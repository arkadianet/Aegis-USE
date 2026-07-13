//! Node-side shielded-transfer verification (G2-P3 slice S4).
//!
//! Binds a wire [`ShieldedTransfer`] to its embedded `aegis-crypto`
//! [`TransferProof`] and verifies it against a consensus **anchor**
//! tree: the commitment tree as of the parent block. Three checks, in
//! order, before the transfer is allowed to mutate state:
//! 1. the proof deserializes,
//! 2. the proof's output commitments equal the wire note_cm slots (so
//!    the leaves the node will insert are the ones the proof committed
//!    to) and its revealed nullifier extracts equal the wire
//!    nullifiers (so the double-spend check operates on proven values),
//! 3. the Bulletproofs verify against the anchor tree at the consensus
//!    fee (membership + ownership + §3 nullifier relation + range +
//!    fee-constant balance).

use aegis_crypto::note::note_cm_bytes;
use aegis_crypto::spend::{verify_transfer, TransferProof};
use aegis_crypto::tree::AegisTree;
use aegis_spec::Amount;
use ark_serialize::CanonicalDeserialize;

use crate::tx::ShieldedTransfer;

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("transfer proof is malformed")]
    Malformed,
    #[error("proof output commitment {0} does not match the wire note_cm")]
    OutputMismatch(usize),
    #[error("proof nullifiers do not match the wire nullifiers")]
    NullifierMismatch,
    #[error("transfer proof failed verification: {0}")]
    Invalid(String),
}

/// Verify one wire transfer against `anchor` at the consensus `fee`.
pub fn verify_shielded_transfer(
    anchor: &AegisTree,
    tx: &ShieldedTransfer,
    fee: Amount,
) -> Result<(), ProofError> {
    let proof = TransferProof::deserialize_compressed(tx.proof.as_slice())
        .map_err(|_| ProofError::Malformed)?;

    // Bind the wire commitments/nullifiers to the proof's own values.
    for (i, out) in tx.outputs.iter().enumerate() {
        if note_cm_bytes(&proof.output_cms[i]) != out.note_cm {
            return Err(ProofError::OutputMismatch(i));
        }
    }
    if proof.nullifiers() != tx.nullifiers {
        return Err(ProofError::NullifierMismatch);
    }

    verify_transfer(anchor, &proof, fee).map_err(|e| ProofError::Invalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::note::EvenScalar;
    use aegis_crypto::nullifier::OddScalar;
    use aegis_crypto::spend::{
        consensus_note_commitment, consensus_note_tag, prove_transfer, NoteOpening, TransferOutput,
    };
    use aegis_crypto::tree::build_tree;
    use aegis_spec::{EPK_BYTES, NOTE_CT_BYTES, NOTE_OUT_CT_BYTES};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const FEE: u64 = 10; // dev sc_tx_fee

    // ----- helpers -----

    fn opening(value: u64, seed: u64, leaf_index: usize) -> NoteOpening {
        NoteOpening {
            value,
            blinding: EvenScalar::from(seed),
            leaf_index,
            nk: OddScalar::from(seed + 1),
            rho: OddScalar::from(seed + 2),
            r_key: OddScalar::from(seed + 3),
        }
    }

    fn leaf_of(o: &NoteOpening) -> aegis_crypto::generators::EvenPoint {
        consensus_note_commitment(
            o.value,
            consensus_note_tag(o.nk, o.rho, o.r_key),
            o.blinding,
        )
    }

    /// A wire transfer carrying a real proof that spends `inputs`
    /// against `anchor`, paying `total-100` and `100`.
    fn real_transfer(
        anchor: &AegisTree,
        inputs: &[NoteOpening; 2],
        total: u64,
    ) -> ShieldedTransfer {
        let outputs = [
            TransferOutput {
                value: total - FEE - 100,
                tag: EvenScalar::from(0x31u64),
                blinding: EvenScalar::from(0x41u64),
            },
            TransferOutput {
                value: 100,
                tag: EvenScalar::from(0x32u64),
                blinding: EvenScalar::from(0x42u64),
            },
        ];
        let proof = prove_transfer(anchor, inputs, &outputs, FEE, &mut StdRng::seed_from_u64(1))
            .expect("valid transfer proves");
        let mut proof_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes).unwrap();
        let out_wire = |i: usize| crate::tx::ShieldedOutput {
            note_cm: note_cm_bytes(&proof.output_cms[i]),
            epk: [0u8; EPK_BYTES],
            ct: [0u8; NOTE_CT_BYTES],
            out_ct: [0u8; NOTE_OUT_CT_BYTES],
        };
        ShieldedTransfer {
            nullifiers: proof.nullifiers(),
            outputs: [out_wire(0), out_wire(1)],
            proof: proof_bytes,
        }
    }

    fn fixture() -> (AegisTree, ShieldedTransfer) {
        let inputs = [opening(1_000, 0x21, 0), opening(500, 0x22, 1)];
        let leaves = vec![
            leaf_of(&inputs[0]),
            leaf_of(&inputs[1]),
            leaf_of(&opening(0, 0x23, 2)),
        ];
        let anchor = build_tree(&leaves);
        let tx = real_transfer(&anchor, &inputs, 1_500);
        (anchor, tx)
    }

    // ----- happy path -----

    #[test]
    fn valid_transfer_verifies_against_its_anchor() {
        let (anchor, tx) = fixture();
        verify_shielded_transfer(&anchor, &tx, FEE).expect("valid transfer must verify");
    }

    // ----- error paths -----

    #[test]
    fn malformed_proof_bytes_rejected() {
        let (anchor, mut tx) = fixture();
        tx.proof.truncate(tx.proof.len() - 1);
        assert!(matches!(
            verify_shielded_transfer(&anchor, &tx, FEE),
            Err(ProofError::Malformed)
        ));
    }

    #[test]
    fn wire_output_not_matching_proof_rejected() {
        let (anchor, mut tx) = fixture();
        tx.outputs[0].note_cm[0] ^= 0xFF;
        assert!(matches!(
            verify_shielded_transfer(&anchor, &tx, FEE),
            Err(ProofError::OutputMismatch(0))
        ));
    }

    #[test]
    fn wire_nullifier_not_matching_proof_rejected() {
        let (anchor, mut tx) = fixture();
        tx.nullifiers[0][0] ^= 0xFF;
        assert!(matches!(
            verify_shielded_transfer(&anchor, &tx, FEE),
            Err(ProofError::NullifierMismatch)
        ));
    }

    #[test]
    fn wrong_fee_rejected() {
        let (anchor, tx) = fixture();
        assert!(matches!(
            verify_shielded_transfer(&anchor, &tx, FEE + 1),
            Err(ProofError::Invalid(_))
        ));
    }

    #[test]
    fn wrong_anchor_rejected() {
        let (_anchor, tx) = fixture();
        let other = build_tree(&[leaf_of(&opening(1, 0x99, 0))]);
        assert!(matches!(
            verify_shielded_transfer(&other, &tx, FEE),
            Err(ProofError::Invalid(_))
        ));
    }
}
