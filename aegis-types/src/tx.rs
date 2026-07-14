//! ShieldedTransfer wire format (note-protocol.md §6, consensus.md §7).
//!
//! Every transfer is byte-uniform: exactly 2 nullifiers, 2 outputs each
//! carrying (note_cm, epk, ct, out_ct) at fixed sizes, one proof blob.
//! The on-SC fee is NOT a wire field — it is the `sc_tx_fee` consensus
//! constant substituted by the verifier (fee-in-circuit rule, N4).

use aegis_spec::{
    EPK_BYTES, MAX_PROOF_BYTES, NF_BYTES, NOTE_CM_BYTES, NOTE_CT_BYTES, NOTE_OUT_CT_BYTES, TX_ARITY,
};
use ergo_crypto::autolykos::common::blake2b256;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

/// One shielded output: commitment + receiver/sender ciphertext slots,
/// all fixed-size (uniformity rule §6 — presence/length never leaks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldedOutput {
    pub note_cm: [u8; NOTE_CM_BYTES],
    pub epk: [u8; EPK_BYTES],
    pub ct: [u8; NOTE_CT_BYTES],
    pub out_ct: [u8; NOTE_OUT_CT_BYTES],
}

/// Fixed 2-in/2-out shielded transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldedTransfer {
    pub nullifiers: [[u8; NF_BYTES]; TX_ARITY],
    pub outputs: [ShieldedOutput; TX_ARITY],
    pub proof: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum TxDecodeError {
    #[error("tx read failed: {0}")]
    Read(#[from] ReadError),
    #[error("trailing bytes after tx ({0} left)")]
    TrailingBytes(usize),
    #[error("proof too large: {got} > {MAX_PROOF_BYTES}")]
    ProofTooLarge { got: usize },
}

impl ShieldedTransfer {
    /// Canonical serialization — the exact bytes the tx id commits to.
    pub fn bytes(&self) -> Vec<u8> {
        let mut w = VlqWriter::with_capacity(
            TX_ARITY * (NF_BYTES + NOTE_CM_BYTES + EPK_BYTES + NOTE_CT_BYTES + NOTE_OUT_CT_BYTES)
                + self.proof.len()
                + 4,
        );
        for nf in &self.nullifiers {
            w.put_bytes(nf);
        }
        for out in &self.outputs {
            w.put_bytes(&out.note_cm);
            w.put_bytes(&out.epk);
            w.put_bytes(&out.ct);
            w.put_bytes(&out.out_ct);
        }
        w.put_u64(self.proof.len() as u64);
        w.put_bytes(&self.proof);
        w.result()
    }

    /// Tx id: blake2b256 over [`Self::bytes`].
    pub fn id(&self) -> [u8; 32] {
        blake2b256(&self.bytes())
    }

    /// Decode exactly one transfer — trailing bytes are an error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TxDecodeError> {
        let mut r = VlqReader::new(bytes);
        let mut nullifiers = [[0u8; NF_BYTES]; TX_ARITY];
        for nf in &mut nullifiers {
            nf.copy_from_slice(r.get_bytes(NF_BYTES)?);
        }
        let mut outputs = Vec::with_capacity(TX_ARITY);
        for _ in 0..TX_ARITY {
            let mut out = ShieldedOutput {
                note_cm: [0; NOTE_CM_BYTES],
                epk: [0; EPK_BYTES],
                ct: [0; NOTE_CT_BYTES],
                out_ct: [0; NOTE_OUT_CT_BYTES],
            };
            out.note_cm.copy_from_slice(r.get_bytes(NOTE_CM_BYTES)?);
            out.epk.copy_from_slice(r.get_bytes(EPK_BYTES)?);
            out.ct.copy_from_slice(r.get_bytes(NOTE_CT_BYTES)?);
            out.out_ct.copy_from_slice(r.get_bytes(NOTE_OUT_CT_BYTES)?);
            outputs.push(out);
        }
        let proof_len = usize::try_from(r.get_u64()?).unwrap_or(usize::MAX);
        if proof_len > MAX_PROOF_BYTES {
            return Err(TxDecodeError::ProofTooLarge { got: proof_len });
        }
        let proof = r.get_bytes(proof_len)?.to_vec();
        if !r.is_empty() {
            return Err(TxDecodeError::TrailingBytes(r.remaining()));
        }
        let outputs: [ShieldedOutput; TX_ARITY] =
            outputs.try_into().expect("exactly TX_ARITY outputs read");
        Ok(ShieldedTransfer {
            nullifiers,
            outputs,
            proof,
        })
    }
}

/// Test fixtures shared by tx/block test modules here and — via the
/// `testutil` feature — by `aegis-node`'s state/chain/seed/store tests.
/// Gated so it never compiles into a normal build.
#[cfg(any(test, feature = "testutil"))]
pub mod testutil {
    use super::*;
    use aegis_crypto::note::{note_cm_bytes, note_commitment, EvenScalar};

    /// A transfer whose note commitments are VALID curve points (the
    /// state layer strictly decodes them); nullifiers/ciphertexts are
    /// recognizable byte patterns.
    pub fn sample_transfer(seed: u8) -> ShieldedTransfer {
        let out = |b: u8| ShieldedOutput {
            note_cm: note_cm_bytes(&note_commitment(
                u64::from(b),
                EvenScalar::from(u64::from(b) + 1),
                EvenScalar::from(u64::from(b) + 2),
            )),
            epk: [b.wrapping_add(1); EPK_BYTES],
            ct: [b.wrapping_add(2); NOTE_CT_BYTES],
            out_ct: [b.wrapping_add(3); NOTE_OUT_CT_BYTES],
        };
        ShieldedTransfer {
            nullifiers: [[seed; NF_BYTES], [seed.wrapping_add(0x80); NF_BYTES]],
            outputs: [out(seed.wrapping_add(4)), out(seed.wrapping_add(8))],
            proof: vec![seed; 64],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::sample_transfer;
    use super::*;

    // ----- happy path -----

    #[test]
    fn tx_id_changes_when_any_section_changes() {
        let base = sample_transfer(1);
        let mut a = base.clone();
        a.nullifiers[0] = [0xEE; NF_BYTES];
        let mut b = base.clone();
        b.outputs[1].note_cm = [0xEE; NOTE_CM_BYTES];
        let mut c = base.clone();
        c.proof.push(0);
        for v in [a, b, c] {
            assert_ne!(v.id(), base.id());
        }
    }

    // ----- round-trips -----

    #[test]
    fn tx_bytes_roundtrips() {
        let tx = sample_transfer(7);
        assert_eq!(ShieldedTransfer::from_bytes(&tx.bytes()).unwrap(), tx);
    }

    #[test]
    fn tx_with_empty_proof_roundtrips() {
        let mut tx = sample_transfer(7);
        tx.proof.clear();
        assert_eq!(ShieldedTransfer::from_bytes(&tx.bytes()).unwrap(), tx);
    }

    // ----- error paths -----

    #[test]
    fn tx_from_truncated_bytes_errors() {
        let bytes = sample_transfer(3).bytes();
        assert!(ShieldedTransfer::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn tx_with_trailing_garbage_errors() {
        let mut bytes = sample_transfer(3).bytes();
        bytes.push(0);
        assert!(matches!(
            ShieldedTransfer::from_bytes(&bytes),
            Err(TxDecodeError::TrailingBytes(1))
        ));
    }

    #[test]
    fn tx_with_oversized_proof_errors() {
        let mut tx = sample_transfer(3);
        tx.proof = vec![0; MAX_PROOF_BYTES + 1];
        assert!(matches!(
            ShieldedTransfer::from_bytes(&tx.bytes()),
            Err(TxDecodeError::ProofTooLarge { .. })
        ));
    }
}
