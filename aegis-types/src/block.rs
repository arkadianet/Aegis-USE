//! Block = header + body of shielded transfers (consensus.md §2/§7).
//!
//! `tx_root` is the ergo-crypto merkle root over tx ids; the canonical
//! empty body maps to the pinned `EMPTY_TX_ROOT` constant so empty
//! blocks and genesis agree without depending on merkle-of-zero
//! semantics.

use aegis_crypto::mint::MintProof;
use aegis_spec::{MAX_BLOCK_BYTES, MAX_BLOCK_TXS, MAX_PROOF_BYTES};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ergo_crypto::merkle::merkle_tree_root;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::header::{Header, HeaderDecodeError};
use crate::tx::{ShieldedTransfer, TxDecodeError};
use crate::EMPTY_TX_ROOT;

/// Ordered transfers carried by one block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockBody {
    pub transfers: Vec<ShieldedTransfer>,
}

/// Full block: core header + body + optional coinbase mint (S5b).
///
/// `coinbase` is `None` for genesis and no-reward blocks; otherwise it
/// is the `MintProof` binding the coinbase note's value to the public
/// reward. (`MintProof` carries an `R1CSProof`, which is not `Eq`, so
/// `Block` is not `PartialEq`; it was never compared by value.)
#[derive(Debug, Clone)]
pub struct Block {
    pub header: Header,
    pub body: BlockBody,
    pub coinbase: Option<aegis_crypto::mint::MintProof>,
}

#[derive(Debug, thiserror::Error)]
pub enum BodyDecodeError {
    #[error("body read failed: {0}")]
    Read(#[from] ReadError),
    #[error("tx decode failed: {0}")]
    Tx(#[from] TxDecodeError),
    #[error("too many txs: {got} > {MAX_BLOCK_TXS}")]
    TooManyTxs { got: usize },
    #[error("body too large: {got} > {MAX_BLOCK_BYTES} bytes")]
    TooLarge { got: usize },
    #[error("trailing bytes after body ({0} left)")]
    TrailingBytes(usize),
}

impl BlockBody {
    /// Merkle root over tx ids; the pinned constant for an empty body.
    pub fn tx_root(&self) -> [u8; 32] {
        if self.transfers.is_empty() {
            return EMPTY_TX_ROOT;
        }
        let ids: Vec<[u8; 32]> = self.transfers.iter().map(|t| t.id()).collect();
        let refs: Vec<&[u8]> = ids.iter().map(|id| id.as_slice()).collect();
        merkle_tree_root(&refs)
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut w = VlqWriter::with_capacity(64);
        w.put_u64(self.transfers.len() as u64);
        for tx in &self.transfers {
            let tx_bytes = tx.bytes();
            w.put_u64(tx_bytes.len() as u64);
            w.put_bytes(&tx_bytes);
        }
        w.result()
    }

    /// Decode exactly one body, enforcing the consensus caps.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BodyDecodeError> {
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(BodyDecodeError::TooLarge { got: bytes.len() });
        }
        let mut r = VlqReader::new(bytes);
        let count = usize::try_from(r.get_u64()?).unwrap_or(usize::MAX);
        if count > MAX_BLOCK_TXS {
            return Err(BodyDecodeError::TooManyTxs { got: count });
        }
        let mut transfers = Vec::with_capacity(count);
        for _ in 0..count {
            let len = usize::try_from(r.get_u64()?).unwrap_or(usize::MAX);
            let tx_bytes = r.get_bytes(len.min(MAX_BLOCK_BYTES))?;
            transfers.push(ShieldedTransfer::from_bytes(tx_bytes)?);
        }
        if !r.is_empty() {
            return Err(BodyDecodeError::TrailingBytes(r.remaining()));
        }
        Ok(BlockBody { transfers })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlockDecodeError {
    #[error("block read failed: {0}")]
    Read(#[from] ReadError),
    #[error("header decode failed: {0}")]
    Header(#[from] HeaderDecodeError),
    #[error("body decode failed: {0}")]
    Body(#[from] BodyDecodeError),
    #[error("bad coinbase flag {0} (want 0 or 1)")]
    BadCoinbaseFlag(u8),
    #[error("coinbase proof too large: {got} > {MAX_PROOF_BYTES}")]
    CoinbaseTooLarge { got: usize },
    #[error("coinbase decode failed: {0}")]
    Coinbase(ark_serialize::SerializationError),
    #[error("trailing bytes after coinbase proof ({0} left)")]
    CoinbaseTrailingBytes(usize),
    #[error("trailing bytes after block ({0} left)")]
    TrailingBytes(usize),
}

impl Block {
    /// Block id — the header id (the body and coinbase are committed to
    /// through the header's `tx_root` / `reward_claim`).
    pub fn id(&self) -> [u8; 32] {
        self.header.id()
    }

    /// Canonical wire serialization: length-prefixed header bytes,
    /// length-prefixed body bytes, then the optional coinbase mint as a
    /// presence flag + length-prefixed ark-compressed `MintProof` (the
    /// same `CanonicalSerialize` path transfer proofs use on the wire).
    pub fn bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.bytes();
        let body_bytes = self.body.bytes();
        let mut w = VlqWriter::with_capacity(header_bytes.len() + body_bytes.len() + 32);
        w.put_u64(header_bytes.len() as u64);
        w.put_bytes(&header_bytes);
        w.put_u64(body_bytes.len() as u64);
        w.put_bytes(&body_bytes);
        match &self.coinbase {
            None => w.put_u8(0),
            Some(proof) => {
                w.put_u8(1);
                let mut cb = Vec::new();
                proof
                    .serialize_compressed(&mut cb)
                    .expect("MintProof serialization into a Vec is infallible");
                w.put_u64(cb.len() as u64);
                w.put_bytes(&cb);
            }
        }
        w.result()
    }

    /// Decode exactly one block — trailing bytes are an error. The
    /// header/body/coinbase sub-decoders each consume their exact
    /// length-prefixed slice, so every consensus cap (`MAX_BLOCK_TXS`,
    /// `MAX_BLOCK_BYTES`, `MAX_PROOF_BYTES`) is enforced here too.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlockDecodeError> {
        let mut r = VlqReader::new(bytes);
        let header_len = usize::try_from(r.get_u64()?).unwrap_or(usize::MAX);
        let header = Header::from_bytes(r.get_bytes(header_len.min(MAX_BLOCK_BYTES))?)?;
        let body_len = usize::try_from(r.get_u64()?).unwrap_or(usize::MAX);
        let body = BlockBody::from_bytes(r.get_bytes(body_len.min(MAX_BLOCK_BYTES))?)?;
        let coinbase = match r.get_u8()? {
            0 => None,
            1 => {
                let cb_len = usize::try_from(r.get_u64()?).unwrap_or(usize::MAX);
                if cb_len > MAX_PROOF_BYTES {
                    return Err(BlockDecodeError::CoinbaseTooLarge { got: cb_len });
                }
                let mut cb: &[u8] = r.get_bytes(cb_len)?;
                let proof = MintProof::deserialize_compressed(&mut cb)
                    .map_err(BlockDecodeError::Coinbase)?;
                if !cb.is_empty() {
                    return Err(BlockDecodeError::CoinbaseTrailingBytes(cb.len()));
                }
                Some(proof)
            }
            other => return Err(BlockDecodeError::BadCoinbaseFlag(other)),
        };
        if !r.is_empty() {
            return Err(BlockDecodeError::TrailingBytes(r.remaining()));
        }
        Ok(Block {
            header,
            body,
            coinbase,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::testutil::sample_transfer;

    // ----- helpers -----

    fn sample_header() -> Header {
        Header {
            version: 1,
            prev_id: [0x11; 32],
            height: 7,
            timestamp_ms: 1_760_000_000_123,
            tx_root: [0x22; 32],
            cm_tree_root: [0x33; 32],
            nullifier_digest: [0x44; 32],
            pot_balance: 5_000,
            sc_nbits: 0x0100_0000,
            reward_claim: [0x55; 33],
        }
    }

    fn sample_mint_proof() -> MintProof {
        use aegis_crypto::note::EvenScalar;
        use rand::SeedableRng;
        aegis_crypto::mint::prove_mint(
            1_234,
            EvenScalar::from(0x51u64),
            EvenScalar::from(0x61u64),
            &mut rand::rngs::StdRng::seed_from_u64(7),
        )
        .expect("sample mint proves")
    }

    fn sample_block(n_transfers: usize, coinbase: Option<MintProof>) -> Block {
        let transfers = (0..n_transfers)
            .map(|i| sample_transfer(i as u8 + 1))
            .collect();
        Block {
            header: sample_header(),
            body: BlockBody { transfers },
            coinbase,
        }
    }

    /// Structural equality for `Block` (not `PartialEq` — `R1CSProof`
    /// isn't `Eq`): headers and bodies by value, coinbases by their
    /// canonical compressed bytes.
    fn assert_block_eq(a: &Block, b: &Block) {
        assert_eq!(a.header, b.header);
        assert_eq!(a.body, b.body);
        let cb_bytes = |blk: &Block| {
            blk.coinbase.as_ref().map(|p| {
                let mut out = Vec::new();
                p.serialize_compressed(&mut out).unwrap();
                out
            })
        };
        assert_eq!(cb_bytes(a), cb_bytes(b));
    }

    // ----- happy path -----

    #[test]
    fn empty_body_tx_root_is_pinned_constant() {
        assert_eq!(BlockBody::default().tx_root(), EMPTY_TX_ROOT);
    }

    #[test]
    fn tx_root_changes_with_content_and_order() {
        let a = BlockBody {
            transfers: vec![sample_transfer(1), sample_transfer(2)],
        };
        let b = BlockBody {
            transfers: vec![sample_transfer(2), sample_transfer(1)],
        };
        let c = BlockBody {
            transfers: vec![sample_transfer(1)],
        };
        assert_ne!(a.tx_root(), b.tx_root());
        assert_ne!(a.tx_root(), c.tx_root());
        assert_ne!(a.tx_root(), EMPTY_TX_ROOT);
    }

    // ----- round-trips -----

    #[test]
    fn body_bytes_roundtrips() {
        let body = BlockBody {
            transfers: vec![sample_transfer(1), sample_transfer(9)],
        };
        assert_eq!(BlockBody::from_bytes(&body.bytes()).unwrap(), body);
    }

    #[test]
    fn empty_body_bytes_roundtrips() {
        let body = BlockBody::default();
        assert_eq!(BlockBody::from_bytes(&body.bytes()).unwrap(), body);
    }

    #[test]
    fn block_bytes_without_coinbase_roundtrips() {
        for n_transfers in [0usize, 1, 2] {
            let block = sample_block(n_transfers, None);
            let back = Block::from_bytes(&block.bytes()).expect("roundtrip decode");
            assert_block_eq(&block, &back);
            assert!(back.coinbase.is_none());
        }
    }

    #[test]
    fn block_bytes_with_coinbase_roundtrips() {
        for n_transfers in [0usize, 1, 2] {
            let block = sample_block(n_transfers, Some(sample_mint_proof()));
            let back = Block::from_bytes(&block.bytes()).expect("roundtrip decode");
            assert_block_eq(&block, &back);
            // The decoded coinbase must still verify at its minted value.
            aegis_crypto::mint::verify_mint(1_234, back.coinbase.as_ref().unwrap())
                .expect("roundtripped coinbase mint verifies");
        }
    }

    // ----- error paths -----

    #[test]
    fn block_from_truncated_bytes_errors() {
        for coinbase in [None, Some(sample_mint_proof())] {
            let bytes = sample_block(1, coinbase).bytes();
            assert!(Block::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        }
    }

    #[test]
    fn block_with_trailing_garbage_errors() {
        let mut bytes = sample_block(1, Some(sample_mint_proof())).bytes();
        bytes.push(0);
        assert!(matches!(
            Block::from_bytes(&bytes),
            Err(BlockDecodeError::TrailingBytes(1))
        ));
    }

    #[test]
    fn block_with_bad_coinbase_flag_errors() {
        let block = sample_block(0, None);
        let mut bytes = block.bytes();
        // The flag is the last byte of a coinbase-less block.
        *bytes.last_mut().unwrap() = 2;
        assert!(matches!(
            Block::from_bytes(&bytes),
            Err(BlockDecodeError::BadCoinbaseFlag(2))
        ));
    }

    #[test]
    fn block_with_oversized_coinbase_len_errors() {
        // Header + body of a coinbase-less block, then flag=1 with a
        // length above the proof cap.
        let block = sample_block(0, None);
        let mut bytes = block.bytes();
        bytes.pop(); // drop the flag=0 byte
        let mut w = VlqWriter::with_capacity(16);
        w.put_u8(1);
        w.put_u64((MAX_PROOF_BYTES + 1) as u64);
        bytes.extend_from_slice(&w.result());
        assert!(matches!(
            Block::from_bytes(&bytes),
            Err(BlockDecodeError::CoinbaseTooLarge { .. })
        ));
    }

    #[test]
    fn body_with_too_many_txs_errors() {
        // Encode a count above the cap directly (no need to build 129 txs).
        let mut w = VlqWriter::with_capacity(4);
        w.put_u64((MAX_BLOCK_TXS + 1) as u64);
        assert!(matches!(
            BlockBody::from_bytes(&w.result()),
            Err(BodyDecodeError::TooManyTxs { .. })
        ));
    }

    #[test]
    fn body_with_trailing_garbage_errors() {
        let mut bytes = BlockBody::default().bytes();
        bytes.push(0);
        assert!(matches!(
            BlockBody::from_bytes(&bytes),
            Err(BodyDecodeError::TrailingBytes(1))
        ));
    }
}
