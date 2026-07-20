//! Serde wire forms for the E2 (`ShareWitness`) and E4 (`AnchorWitness`) aux-PoW
//! witnesses — the bytes the settlement host writes and the RISC0 guest reads
//! (`env::read`).
//!
//! The witness structs embed Ergo types (`Header`, `ExtensionField`,
//! `BatchMerkleProof`) that do NOT derive `serde`. Rather than mirror every
//! field, the wire form carries each object's **canonical Ergo byte image**
//! (`serialize_header` / `serialize_batch_merkle_proof`) and the guest rebuilds
//! the typed value with the matching decoder (`read_header` /
//! `deserialize_batch_merkle_proof`). Those codecs are the reviewed, oracle-
//! tested Ergo serializers, so the round-trip is faithful — and the guest
//! decoding them pulls no `panic="unwind"` crate (the whole point of the M-E1
//! packaging fix). A malformed wire image fails closed (the guest panics, which
//! aborts the settlement — never forges one).
//!
//! Gated behind `aux-pow` (shares E2/E4's Ergo primitives).

use ergo_primitives::reader::VlqReader;
use ergo_ser::batch_merkle_proof::{deserialize_batch_merkle_proof, serialize_batch_merkle_proof};
use ergo_ser::extension::ExtensionField;
use ergo_ser::header::{read_header, serialize_header};
use serde::{Deserialize, Serialize};

use crate::poseidon::{digest_to_limbs, DIGEST_ELEMS, F};
use crate::settled::SETTLED_DEPTH;
use p3_field::PrimeCharacteristicRing;

use super::anchor::AnchorWitness;
use super::pegin::{DepositProof, PegInBackingWitness};
use super::share::ShareWitness;

/// A `ShareWitness` in wire form: the Ergo candidate header, the MM extension
/// field, and the extension-inclusion proof, each as its canonical byte image.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareWitnessWire {
    pub header_bytes: Vec<u8>,
    pub field_key: [u8; 2],
    pub field_value: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}

impl ShareWitnessWire {
    /// Serialize a typed witness (host side).
    pub fn from_witness(w: &ShareWitness) -> Self {
        let (header_bytes, _) =
            serialize_header(&w.ergo_header).expect("share Ergo header serializes");
        Self {
            header_bytes,
            field_key: w.field.key,
            field_value: w.field.value.clone(),
            proof_bytes: serialize_batch_merkle_proof(&w.proof),
        }
    }

    /// Rebuild the typed witness (guest side). Fails closed on a malformed image.
    pub fn into_witness(self) -> ShareWitness {
        let mut r = VlqReader::new(&self.header_bytes);
        let ergo_header = read_header(&mut r).expect("share header decodes");
        let proof = deserialize_batch_merkle_proof(&self.proof_bytes)
            .expect("share batch-merkle proof decodes");
        ShareWitness {
            ergo_header,
            field: ExtensionField {
                key: self.field_key,
                value: self.field_value,
            },
            proof,
        }
    }
}

/// An `AnchorWitness` in wire form: the parent-linked Ergo header chain
/// (`[ergo_ref, …, H_anchor]`) plus `H_anchor`'s MM commitment field + proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorWitnessWire {
    pub header_bytes: Vec<Vec<u8>>,
    pub anchor_field_key: [u8; 2],
    pub anchor_field_value: Vec<u8>,
    pub anchor_proof_bytes: Vec<u8>,
}

impl AnchorWitnessWire {
    /// Serialize a typed witness (host side).
    pub fn from_witness(w: &AnchorWitness) -> Self {
        let header_bytes = w
            .headers
            .iter()
            .map(|h| serialize_header(h).expect("anchor header serializes").0)
            .collect();
        Self {
            header_bytes,
            anchor_field_key: w.anchor_field.key,
            anchor_field_value: w.anchor_field.value.clone(),
            anchor_proof_bytes: serialize_batch_merkle_proof(&w.anchor_proof),
        }
    }

    /// Rebuild the typed witness (guest side). Fails closed on a malformed image.
    pub fn into_witness(self) -> AnchorWitness {
        let headers = self
            .header_bytes
            .iter()
            .map(|b| {
                let mut r = VlqReader::new(b);
                read_header(&mut r).expect("anchor header decodes")
            })
            .collect();
        let anchor_proof = deserialize_batch_merkle_proof(&self.anchor_proof_bytes)
            .expect("anchor batch-merkle proof decodes");
        AnchorWitness {
            headers,
            anchor_field: ExtensionField {
                key: self.anchor_field_key,
                value: self.anchor_field_value,
            },
            anchor_proof,
        }
    }
}

/// A `DepositProof` in wire form: the deposit tx + its inclusion proof as
/// canonical byte images, and the one-mint-ever path as limb digests.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositProofWire {
    pub tx_bytes: Vec<u8>,
    pub output_index: u16,
    pub tx_merkle_proof_bytes: Vec<u8>,
    pub dep_header_index: usize,
    pub used_path: Vec<[u32; DIGEST_ELEMS]>,
}

/// A `PegInBackingWitness` (F3) in wire form: the parent-linked deposit walk
/// (`[ergo_ref, …, deepest H_dep]`) as header byte images, plus one deposit
/// proof per suffix peg-in.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PegInBackingWitnessWire {
    pub deposit_header_bytes: Vec<Vec<u8>>,
    pub deposits: Vec<DepositProofWire>,
}

impl PegInBackingWitnessWire {
    /// Serialize a typed witness (host side).
    pub fn from_witness(w: &PegInBackingWitness) -> Self {
        let deposit_header_bytes = w
            .deposit_headers
            .iter()
            .map(|h| serialize_header(h).expect("deposit header serializes").0)
            .collect();
        let deposits = w
            .deposits
            .iter()
            .map(|d| DepositProofWire {
                tx_bytes: d.tx_bytes.clone(),
                output_index: d.output_index,
                tx_merkle_proof_bytes: serialize_batch_merkle_proof(&d.tx_merkle_proof),
                dep_header_index: d.dep_header_index,
                used_path: d.used_path.iter().map(digest_to_limbs).collect(),
            })
            .collect();
        Self {
            deposit_header_bytes,
            deposits,
        }
    }

    /// Rebuild the typed witness (guest side). Fails closed on a malformed image.
    pub fn into_witness(self) -> PegInBackingWitness {
        let deposit_headers = self
            .deposit_header_bytes
            .iter()
            .map(|b| {
                let mut r = VlqReader::new(b);
                read_header(&mut r).expect("deposit header decodes")
            })
            .collect();
        let deposits = self
            .deposits
            .into_iter()
            .map(|d| {
                let tx_merkle_proof = deserialize_batch_merkle_proof(&d.tx_merkle_proof_bytes)
                    .expect("deposit tx-Merkle proof decodes");
                assert_eq!(
                    d.used_path.len(),
                    SETTLED_DEPTH,
                    "deposit used_path must be 248 siblings"
                );
                let mut used_path = [[F::ZERO; DIGEST_ELEMS]; SETTLED_DEPTH];
                for (dst, src) in used_path.iter_mut().zip(&d.used_path) {
                    *dst = core::array::from_fn(|i| F::from_u32(src[i]));
                }
                DepositProof {
                    tx_bytes: d.tx_bytes,
                    output_index: d.output_index,
                    tx_merkle_proof,
                    dep_header_index: d.dep_header_index,
                    used_path,
                }
            })
            .collect();
        PegInBackingWitness {
            deposit_headers,
            deposits,
        }
    }
}

// The wire round-trips are tested where their mining/linking helpers live:
// `share.rs::tests::share_wire_roundtrip_still_verifies` and
// `anchor.rs::tests::anchor_wire_roundtrip_still_links`; the F3 backing wire is
// covered by `pegin.rs::tests` via `pegin_backing_wire_roundtrip`.
