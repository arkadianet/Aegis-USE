//! Aegis block header: core fields, canonical bytes, header id.
//!
//! Layout per `consensus.md` §2. The header id is blake2b256 over the
//! canonical (VLQ) serialization of the core fields; the PoW witness
//! is *not* part of the id — the Ergo-side commitment tx authenticates
//! the id, it does not extend it.

use ergo_crypto::autolykos::common::blake2b256;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

/// Aegis core header (consensus.md §2). PoW witness lives beside the
/// header in the block, never inside the id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub prev_id: [u8; 32],
    pub height: u64,
    pub timestamp_ms: u64,
    pub tx_root: [u8; 32],
    pub cm_tree_root: [u8; 32],
    pub nullifier_digest: [u8; 32],
    pub pot_balance: u64,
    pub sc_nbits: u32,
    /// The coinbase note commitment (33-byte compressed point), or the
    /// all-zero sentinel for genesis / no-coinbase blocks (S5b).
    pub reward_claim: [u8; 33],
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderDecodeError {
    #[error("header read failed: {0}")]
    Read(#[from] ReadError),
    #[error("trailing bytes after header ({0} left)")]
    TrailingBytes(usize),
    #[error("sc_nbits does not fit u32: {0}")]
    NbitsOutOfRange(u64),
}

impl Header {
    /// Canonical serialization — the exact bytes the id commits to.
    pub fn bytes(&self) -> Vec<u8> {
        let mut w = VlqWriter::with_capacity(1 + 32 * 4 + 33 + 8 * 3 + 4);
        w.put_u8(self.version);
        w.put_bytes(&self.prev_id);
        w.put_u64(self.height);
        w.put_u64(self.timestamp_ms);
        w.put_bytes(&self.tx_root);
        w.put_bytes(&self.cm_tree_root);
        w.put_bytes(&self.nullifier_digest);
        w.put_u64(self.pot_balance);
        w.put_u64(u64::from(self.sc_nbits));
        w.put_bytes(&self.reward_claim);
        w.result()
    }

    /// Header id: blake2b256 over [`Self::bytes`].
    pub fn id(&self) -> [u8; 32] {
        blake2b256(&self.bytes())
    }

    /// Decode a header from its canonical bytes. The input must contain
    /// exactly one header — trailing bytes are an error (a header is
    /// never a prefix of something else in this protocol).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderDecodeError> {
        let mut r = VlqReader::new(bytes);
        let header = Header {
            version: r.get_u8()?,
            prev_id: read_32(&mut r)?,
            height: r.get_u64()?,
            timestamp_ms: r.get_u64()?,
            tx_root: read_32(&mut r)?,
            cm_tree_root: read_32(&mut r)?,
            nullifier_digest: read_32(&mut r)?,
            pot_balance: r.get_u64()?,
            sc_nbits: {
                let raw = r.get_u64()?;
                u32::try_from(raw).map_err(|_| HeaderDecodeError::NbitsOutOfRange(raw))?
            },
            reward_claim: read_33(&mut r)?,
        };
        if !r.is_empty() {
            return Err(HeaderDecodeError::TrailingBytes(r.remaining()));
        }
        Ok(header)
    }
}

fn read_32(r: &mut VlqReader<'_>) -> Result<[u8; 32], ReadError> {
    let mut out = [0u8; 32];
    out.copy_from_slice(r.get_bytes(32)?);
    Ok(out)
}

fn read_33(r: &mut VlqReader<'_>) -> Result<[u8; 33], ReadError> {
    let mut out = [0u8; 33];
    out.copy_from_slice(r.get_bytes(33)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn sample_header() -> Header {
        Header {
            version: 1,
            prev_id: [0x11; 32],
            height: 42,
            timestamp_ms: 1_760_000_000_123,
            tx_root: [0x22; 32],
            cm_tree_root: [0x33; 32],
            nullifier_digest: [0x44; 32],
            pot_balance: 5_000,
            sc_nbits: 0x0100_0000,
            reward_claim: [0x55; 33],
        }
    }

    // ----- happy path -----

    #[test]
    fn header_id_is_blake2b256_of_bytes() {
        let h = sample_header();
        assert_eq!(
            h.id(),
            ergo_crypto::autolykos::common::blake2b256(&h.bytes())
        );
    }

    #[test]
    fn header_id_changes_when_any_field_changes() {
        let base = sample_header();
        let mut variants = Vec::new();
        for f in 0..10 {
            let mut h = base.clone();
            match f {
                0 => h.version = 2,
                1 => h.prev_id = [0xAA; 32],
                2 => h.height = 43,
                3 => h.timestamp_ms += 1,
                4 => h.tx_root = [0xAB; 32],
                5 => h.cm_tree_root = [0xAC; 32],
                6 => h.nullifier_digest = [0xAD; 32],
                7 => h.pot_balance += 1,
                8 => h.sc_nbits += 1,
                _ => h.reward_claim = [0xAE; 33],
            }
            variants.push(h.id());
        }
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(*v, base.id(), "field {i} did not affect the id");
        }
    }

    // ----- round-trips -----

    #[test]
    fn header_bytes_roundtrips() {
        let h = sample_header();
        let decoded = Header::from_bytes(&h.bytes()).expect("roundtrip decode");
        assert_eq!(decoded, h);
    }

    // ----- error paths -----

    #[test]
    fn header_from_truncated_bytes_errors() {
        let bytes = sample_header().bytes();
        assert!(Header::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn header_from_bytes_with_trailing_garbage_errors() {
        let mut bytes = sample_header().bytes();
        bytes.push(0x00);
        assert!(Header::from_bytes(&bytes).is_err());
    }
}
