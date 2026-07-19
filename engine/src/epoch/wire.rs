//! Serde wire form of the epoch-validity witness — the canonical bytes the
//! settlement host writes and the RISC0 guest reads (`env::read`).
//!
//! Digests travel as 8 canonical `u32` limbs (the guest never (de)serializes a
//! `BabyBear` field element, matching the batch guest's `Vec<[u32; 8]>` inputs).
//! [`EpochWitnessWire::into_witness`] rehydrates the `F`-typed
//! [`super::verify::EpochWitness`] the verifier consumes.

use serde::{Deserialize, Serialize};

use crate::poseidon::{digest_to_limbs, Digest, DIGEST_ELEMS, F};
use crate::settled::SETTLED_DEPTH;
use p3_field::PrimeCharacteristicRing;

use super::types::{PegIn, PegOut, SpendPublics, SuffixBlock};
use super::verify::EpochWitness;

type LimbDigest = [u32; DIGEST_ELEMS];

fn to_d(l: &LimbDigest) -> Digest {
    core::array::from_fn(|i| F::from_u32(l[i]))
}

fn to_l(d: &Digest) -> LimbDigest {
    digest_to_limbs(d)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendWire {
    pub root: LimbDigest,
    pub nf0: LimbDigest,
    pub nf1: LimbDigest,
    pub cm0: LimbDigest,
    pub cm1: LimbDigest,
    pub fee: u64,
}

impl SpendWire {
    fn from_spend(s: &SpendPublics) -> Self {
        Self {
            root: to_l(&s.root),
            nf0: to_l(&s.nf0),
            nf1: to_l(&s.nf1),
            cm0: to_l(&s.cm0),
            cm1: to_l(&s.cm1),
            fee: s.fee,
        }
    }

    fn to_spend(&self) -> SpendPublics {
        SpendPublics {
            root: to_d(&self.root),
            nf0: to_d(&self.nf0),
            nf1: to_d(&self.nf1),
            cm0: to_d(&self.cm0),
            cm1: to_d(&self.cm1),
            fee: self.fee,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PegOutWire {
    pub spend: SpendWire,
    pub amount: u64,
    pub recipient_prop: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PegInWire {
    pub box_id: [u8; 32],
    pub dest_owner: LimbDigest,
    pub amount: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuffixBlockWire {
    pub height: u64,
    pub prev_header_id: [u8; 32],
    pub prev_root: LimbDigest,
    pub state_root: LimbDigest,
    pub timestamp_ms: u64,
    pub sc_nbits: u32,
    pub txs: Vec<SpendWire>,
    pub pegouts: Vec<PegOutWire>,
    pub pegins: Vec<PegInWire>,
    pub miner_owner: LimbDigest,
    pub coinbase_amount: u64,
    pub coinbase_cm: LimbDigest,
    pub coinbase_is_reward: bool,
    pub pot_after: u64,
}

impl SuffixBlockWire {
    fn from_block(b: &SuffixBlock) -> Self {
        Self {
            height: b.height,
            prev_header_id: b.prev_header_id,
            prev_root: to_l(&b.prev_root),
            state_root: to_l(&b.state_root),
            timestamp_ms: b.timestamp_ms,
            sc_nbits: b.sc_nbits,
            txs: b.txs.iter().map(SpendWire::from_spend).collect(),
            pegouts: b
                .pegouts
                .iter()
                .map(|p| PegOutWire {
                    spend: SpendWire::from_spend(&p.spend),
                    amount: p.amount,
                    recipient_prop: p.recipient_prop.clone(),
                })
                .collect(),
            pegins: b
                .pegins
                .iter()
                .map(|p| PegInWire {
                    box_id: p.box_id,
                    dest_owner: to_l(&p.dest_owner),
                    amount: p.amount,
                })
                .collect(),
            miner_owner: to_l(&b.miner_owner),
            coinbase_amount: b.coinbase_amount,
            coinbase_cm: to_l(&b.coinbase_cm),
            coinbase_is_reward: b.coinbase_is_reward,
            pot_after: b.pot_after,
        }
    }

    fn to_block(&self) -> SuffixBlock {
        SuffixBlock {
            height: self.height,
            prev_header_id: self.prev_header_id,
            prev_root: to_d(&self.prev_root),
            state_root: to_d(&self.state_root),
            timestamp_ms: self.timestamp_ms,
            sc_nbits: self.sc_nbits,
            txs: self.txs.iter().map(SpendWire::to_spend).collect(),
            pegouts: self
                .pegouts
                .iter()
                .map(|p| PegOut {
                    spend: p.spend.to_spend(),
                    amount: p.amount,
                    recipient_prop: p.recipient_prop.clone(),
                })
                .collect(),
            pegins: self
                .pegins
                .iter()
                .map(|p| PegIn {
                    box_id: p.box_id,
                    dest_owner: to_d(&p.dest_owner),
                    amount: p.amount,
                })
                .collect(),
            miner_owner: to_d(&self.miner_owner),
            coinbase_amount: self.coinbase_amount,
            coinbase_cm: to_d(&self.coinbase_cm),
            coinbase_is_reward: self.coinbase_is_reward,
            pot_after: self.pot_after,
        }
    }
}

/// The full epoch-validity witness in wire form.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochWitnessWire {
    pub chain_id: u32,
    pub blocks: Vec<SuffixBlockWire>,
    pub frontier_bytes: Vec<u8>,
    pub tip_id_prev: [u8; 32],
    pub pot_before: u64,
    pub shielded_before: u64,
    pub seam_roots: Vec<LimbDigest>,
    pub settled_root_in: LimbDigest,
    /// Flattened 248-sibling paths per peg-out (each `SETTLED_DEPTH` limb-digests).
    pub settled_paths: Vec<Vec<LimbDigest>>,
    pub spend_root_digest: LimbDigest,
    pub ergo_ref_id: [u8; 32],
    pub counter_next: u64,
}

impl EpochWitnessWire {
    /// Serialize an `F`-typed witness to wire form (host side).
    pub fn from_witness(w: &EpochWitness) -> Self {
        Self {
            chain_id: w.chain_id,
            blocks: w.blocks.iter().map(SuffixBlockWire::from_block).collect(),
            frontier_bytes: w.frontier_bytes.clone(),
            tip_id_prev: w.tip_id_prev,
            pot_before: w.pot_before,
            shielded_before: w.shielded_before,
            seam_roots: w.seam_roots.iter().map(to_l).collect(),
            settled_root_in: to_l(&w.settled_root_in),
            settled_paths: w
                .settled_paths
                .iter()
                .map(|p| p.iter().map(to_l).collect())
                .collect(),
            spend_root_digest: to_l(&w.spend_root_digest),
            ergo_ref_id: w.ergo_ref_id,
            counter_next: w.counter_next,
        }
    }

    /// Rehydrate the `F`-typed witness. Panics if any settled path is not exactly
    /// [`SETTLED_DEPTH`] siblings (a malformed witness the guest must reject).
    pub fn into_witness(&self) -> EpochWitness {
        let settled_paths = self
            .settled_paths
            .iter()
            .map(|p| {
                assert_eq!(p.len(), SETTLED_DEPTH, "settled path must be 248 siblings");
                let mut arr = [[F::ZERO; DIGEST_ELEMS]; SETTLED_DEPTH];
                for (dst, src) in arr.iter_mut().zip(p) {
                    *dst = to_d(src);
                }
                arr
            })
            .collect();
        EpochWitness {
            chain_id: self.chain_id,
            blocks: self.blocks.iter().map(SuffixBlockWire::to_block).collect(),
            frontier_bytes: self.frontier_bytes.clone(),
            tip_id_prev: self.tip_id_prev,
            pot_before: self.pot_before,
            shielded_before: self.shielded_before,
            seam_roots: self.seam_roots.iter().map(to_d).collect(),
            settled_root_in: to_d(&self.settled_root_in),
            settled_paths,
            spend_root_digest: to_d(&self.spend_root_digest),
            ergo_ref_id: self.ergo_ref_id,
            counter_next: self.counter_next,
        }
    }
}
