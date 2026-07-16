//! Append-only on-disk block + witness logs, and replay-based chain
//! loading (P5, extended for the M6c merge-mining node).
//!
//! Persistence model: the block sequence IS the persisted state. The
//! block log holds the non-genesis blocks (heights 1..) in order, each
//! as a `u32-LE length ‖ Block wire bytes` record in `blocks.log` under
//! the data dir; genesis is always derived from the network. Loading
//! REPLAYS every record through [`Chain::try_extend`] — the exact
//! validation path live blocks take — so the reconstructed state
//! (nullifier set, pot, digest chain, commitment tree) is recomputed
//! and re-verified, never trusted from disk. A corrupt or incompatible
//! log fails loudly.
//!
//! The witness log (`witnesses.log`, same framing) persists each
//! accepted block's [`ShareWitness`] so a restarted merge-mining node
//! can re-prove its own chain's aux-PoW weight into the fork choice
//! ([`crate::node`] resumes by re-verifying every stored witness —
//! weight is never trusted from disk either). A block whose share was
//! only ever observed via the node's own Ergo scan (no witness stored)
//! is recoverable from Ergo itself on the next scan.
//!
//! Crash safety: each append is a single write-then-fsync. A partial
//! trailing record (crash mid-append) is detected on load, warned
//! about, and truncated away — the chain resumes from the last complete
//! record. Anything malformed *before* the tail is an error, not a
//! truncation.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

use aegis_spec::{Network, MAX_BLOCK_BYTES, MAX_PROOF_BYTES};

use crate::auxpow::{ShareWitness, WitnessDecodeError};
use crate::block::{Block, BlockDecodeError};
use crate::chain::{Chain, ExtendError, PowMode, ProofMode};
use crate::seed::MAX_WITNESS_WIRE_BYTES;

/// Block-log file name inside the data dir.
pub const BLOCK_LOG_FILE: &str = "blocks.log";

/// Witness-log file name inside the data dir.
pub const WITNESS_LOG_FILE: &str = "witnesses.log";

/// Bytes of the little-endian record length prefix.
const LEN_PREFIX_BYTES: usize = 4;

/// Upper bound for one block record's declared length: the body
/// consensus cap plus generous header/coinbase framing slack. A larger
/// claim can only be corruption — `Block::from_bytes` would reject it
/// anyway.
const MAX_RECORD_BYTES: usize = MAX_BLOCK_BYTES + MAX_PROOF_BYTES + 1024;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("block log io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("log record at offset {offset} claims {got} bytes (> {cap})")]
    RecordTooLarge {
        offset: usize,
        got: usize,
        cap: usize,
    },
    #[error("block log record at offset {offset} is malformed: {source}")]
    Decode {
        offset: usize,
        source: BlockDecodeError,
    },
    #[error("witness log record at offset {offset} is malformed: {source}")]
    WitnessDecode {
        offset: usize,
        source: WitnessDecodeError,
    },
    #[error("witness does not serialize: {0}")]
    WitnessEncode(ergo_ser::error::WriteError),
    #[error("replay of stored block at height {height} failed: {source}")]
    Replay { height: u64, source: ExtendError },
}

/// Append one `u32-LE length ‖ payload` record to `dir/file`,
/// write-then-fsync.
fn append_record(dir: &Path, file: &str, payload: &[u8]) -> Result<(), StoreError> {
    std::fs::create_dir_all(dir)?;
    let mut record = Vec::with_capacity(LEN_PREFIX_BYTES + payload.len());
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(payload);
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(file))?;
    f.write_all(&record)?;
    f.sync_all()?;
    Ok(())
}

/// Read every complete `(offset, payload)` record from `dir/file`. A
/// missing file yields an empty vec. A partial trailing record (crash
/// artifact) is warned about and truncated away in place; a record
/// claiming more than `cap` bytes is an error (corruption, never a
/// crash tail).
fn read_records(dir: &Path, file: &str, cap: usize) -> Result<Vec<(usize, Vec<u8>)>, StoreError> {
    let path = dir.join(file);
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        if data.len() - offset < LEN_PREFIX_BYTES {
            break; // partial length prefix — crash tail
        }
        let mut len_bytes = [0u8; LEN_PREFIX_BYTES];
        len_bytes.copy_from_slice(&data[offset..offset + LEN_PREFIX_BYTES]);
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > cap {
            return Err(StoreError::RecordTooLarge {
                offset,
                got: len,
                cap,
            });
        }
        let start = offset + LEN_PREFIX_BYTES;
        if data.len() - start < len {
            break; // partial payload — crash tail
        }
        records.push((offset, data[start..start + len].to_vec()));
        offset = start + len;
    }
    if offset < data.len() {
        tracing::warn!(
            file,
            dropped_bytes = data.len() - offset,
            "log ends in a partial record (crash artifact); truncating to last complete record"
        );
        let f = OpenOptions::new().write(true).open(&path)?;
        f.set_len(offset as u64)?;
        f.sync_all()?;
    }
    Ok(records)
}

/// Append one block to the log, write-then-fsync. Call this for every
/// block the chain has ACCEPTED (never for a merely produced one) so
/// the log stays replayable by construction.
pub fn save_block(dir: &Path, block: &Block) -> Result<(), StoreError> {
    append_record(dir, BLOCK_LOG_FILE, &block.bytes())
}

/// Read every complete block record from the data dir's log, in log
/// order. Decode-only — NO replay/validation: [`load_chain`] is the
/// consensus-grade loader; this is for consumers that only index the
/// archive by id (the seed tier serves self-authenticating bytes, so
/// the *fetcher* re-verifies — `seed.rs`). A missing log yields an
/// empty vec. A partial trailing record (crash artifact) is warned
/// about and truncated away; any other malformation is an error.
pub fn read_log(dir: &Path) -> Result<Vec<Block>, StoreError> {
    read_records(dir, BLOCK_LOG_FILE, MAX_RECORD_BYTES)?
        .into_iter()
        .map(|(offset, payload)| {
            Block::from_bytes(&payload).map_err(|source| StoreError::Decode { offset, source })
        })
        .collect()
}

/// Append one accepted block's share witness to the witness log,
/// write-then-fsync. Same discipline as [`save_block`]: only witnesses
/// that VERIFIED (and whose block activated) belong here, so the log
/// re-verifies by construction on resume.
pub fn save_witness(dir: &Path, witness: &ShareWitness) -> Result<(), StoreError> {
    let bytes = witness.bytes().map_err(StoreError::WitnessEncode)?;
    append_record(dir, WITNESS_LOG_FILE, &bytes)
}

/// Read every complete witness record from the data dir's witness log,
/// in log order. Decode-only — the consumer ([`crate::node`]'s resume)
/// re-runs [`ShareWitness::verify`] on every record; aux-PoW weight is
/// never trusted from disk. Missing log = empty vec; crash tail
/// truncated; other malformation errors.
pub fn read_witness_log(dir: &Path) -> Result<Vec<ShareWitness>, StoreError> {
    read_records(dir, WITNESS_LOG_FILE, MAX_WITNESS_WIRE_BYTES)?
        .into_iter()
        .map(|(offset, payload)| {
            ShareWitness::from_bytes(&payload)
                .map_err(|source| StoreError::WitnessDecode { offset, source })
        })
        .collect()
}

/// Rebuild a chain from the data dir by replaying the block log through
/// [`Chain::try_extend`] (each block validated with `now_ms` pinned to
/// its own timestamp, so the deterministic consensus checks all re-run
/// and the future-drift bound is trivially met). A missing or empty log
/// yields a fresh genesis chain. A partial trailing record is truncated
/// away (crash artifact); any other malformation is an error.
pub fn load_chain(
    dir: &Path,
    network: Network,
    pow_mode: PowMode,
    proof_mode: ProofMode,
) -> Result<Chain, StoreError> {
    let mut chain = Chain::new(network, pow_mode, proof_mode);
    for block in read_log(dir)? {
        let (height, ts) = (block.header.height, block.header.timestamp_ms);
        chain
            .try_extend(block, ts)
            .map_err(|source| StoreError::Replay { height, source })?;
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockBody;
    use crate::tx::testutil::sample_transfer;
    use aegis_crypto::note::EvenScalar;
    use aegis_spec::NF_BYTES;

    // ----- helpers -----

    const T_MS: u64 = 15_000;

    fn dev_chain() -> Chain {
        Chain::new(Network::Dev, PowMode::DevStub, ProofMode::DevStub)
    }

    fn load_dev(dir: &Path) -> Result<Chain, StoreError> {
        load_chain(dir, Network::Dev, PowMode::DevStub, ProofMode::DevStub)
    }

    fn transfer_with_nfs(a: u8, b: u8) -> crate::tx::ShieldedTransfer {
        let mut tx = sample_transfer(a);
        tx.nullifiers = [[a; NF_BYTES], [b; NF_BYTES]];
        tx
    }

    /// Extend `chain` by one block (persisted to `dir`): coinbase-minting
    /// when `coinbase`, carrying `transfers` in the body.
    fn grow_and_save(
        chain: &mut Chain,
        dir: &Path,
        coinbase: bool,
        transfers: Vec<crate::tx::ShieldedTransfer>,
    ) {
        let now = chain.tip().timestamp_ms + T_MS;
        let body = BlockBody {
            transfers,
            peg_mints: Vec::new(),
        };
        let block = if coinbase {
            let h = chain.tip().height + 1;
            chain
                .produce_next_with_coinbase(
                    body,
                    now,
                    EvenScalar::from(0xC0u64),
                    EvenScalar::from(h),
                )
                .expect("coinbase block produces")
        } else {
            chain.produce_next(body, now).expect("block produces")
        };
        chain
            .try_extend(block.clone(), now)
            .expect("produced block accepted");
        save_block(dir, &block).expect("block saved");
    }

    /// Assert every observable consensus state field of `b` equals `a`'s.
    fn assert_chain_eq(a: &Chain, b: &Chain) {
        assert_eq!(a.tip().height, b.tip().height, "tip height");
        assert_eq!(a.tip().id(), b.tip().id(), "tip id");
        // ShieldedState is PartialEq over nullifier set, pot, digest,
        // cm_leaves, and cm_root — the whole persisted-state surface.
        assert_eq!(a.state(), b.state(), "shielded state");
        assert_eq!(a.state().nullifier_digest(), b.state().nullifier_digest());
        assert_eq!(a.state().pot(), b.state().pot());
        assert_eq!(a.state().leaf_count(), b.state().leaf_count());
        assert_eq!(a.state().cm_tree_root(), b.state().cm_tree_root());
    }

    // ----- happy path -----

    #[test]
    fn load_from_empty_dir_boots_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let chain = load_dev(dir.path()).unwrap();
        assert_eq!(chain.tip().height, 0);
        assert_eq!(
            chain.tip().id(),
            crate::genesis::genesis_header(Network::Dev).id()
        );
    }

    #[test]
    fn witness_log_missing_file_yields_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_witness_log(dir.path()).unwrap().is_empty());
    }

    // ----- round-trips -----

    #[test]
    fn persisted_chain_replays_to_identical_state() {
        // The restart-fidelity oracle: N blocks (coinbase mints AND fee
        // transfers) into chain A, persisted; load_chain must rebuild a
        // chain B whose tip and full shielded state equal A's.
        let dir = tempfile::tempdir().unwrap();
        let mut a = dev_chain();
        grow_and_save(&mut a, dir.path(), true, vec![]);
        grow_and_save(&mut a, dir.path(), false, vec![transfer_with_nfs(1, 2)]);
        grow_and_save(&mut a, dir.path(), true, vec![transfer_with_nfs(3, 4)]);
        grow_and_save(&mut a, dir.path(), false, vec![]);
        grow_and_save(&mut a, dir.path(), true, vec![]);
        assert_eq!(a.tip().height, 5);
        assert!(a.state().contains(&[1u8; NF_BYTES]));

        let b = load_dev(dir.path()).unwrap();
        assert_chain_eq(&a, &b);
        assert!(b.state().contains(&[1u8; NF_BYTES]));
        assert!(b.state().contains(&[4u8; NF_BYTES]));
    }

    #[test]
    fn witness_log_roundtrips_and_truncates_crash_tail() {
        // Two accepted blocks' witnesses persist and read back
        // byte-identical; a partial trailing record (crash artifact)
        // is truncated away, exactly like the block log.
        let dir = tempfile::tempdir().unwrap();
        let mut chain = dev_chain();
        let mut witnesses = Vec::new();
        for _ in 0..2 {
            let now = chain.tip().timestamp_ms + T_MS;
            let block = chain
                .produce_next(BlockBody::default(), now)
                .expect("block produces");
            chain.try_extend(block.clone(), now).expect("extends");
            let witness = crate::node::grind_dev_witness(&block).expect("dev grind");
            save_witness(dir.path(), &witness).expect("witness saved");
            witnesses.push(witness);
        }
        assert_eq!(read_witness_log(dir.path()).unwrap(), witnesses);

        let path = dir.path().join(WITNESS_LOG_FILE);
        let complete_len = std::fs::metadata(&path).unwrap().len();
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&500u32.to_le_bytes()).unwrap();
        f.write_all(&[0xCD; 7]).unwrap();
        drop(f);
        assert_eq!(read_witness_log(dir.path()).unwrap(), witnesses);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            complete_len,
            "partial tail truncated away"
        );
    }

    #[test]
    fn coinbase_chain_survives_restart_and_keeps_growing() {
        // Restart across a coinbase-bearing chain: leaves and the digest
        // chain must be intact, and the loaded chain must keep extending.
        let dir = tempfile::tempdir().unwrap();
        let mut a = dev_chain();
        for _ in 0..3 {
            grow_and_save(&mut a, dir.path(), true, vec![]);
        }
        assert_eq!(a.state().leaf_count(), 3);

        let mut b = load_dev(dir.path()).unwrap();
        assert_chain_eq(&a, &b);
        grow_and_save(&mut b, dir.path(), true, vec![]);
        assert_eq!(b.tip().height, 4);
        assert_eq!(b.state().leaf_count(), 4);

        // And the extended log replays again (log stays appendable
        // across restarts).
        let c = load_dev(dir.path()).unwrap();
        assert_chain_eq(&b, &c);
    }

    // ----- error paths -----

    #[test]
    fn truncated_trailing_record_is_dropped_and_file_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = dev_chain();
        grow_and_save(&mut a, dir.path(), true, vec![]);
        grow_and_save(&mut a, dir.path(), true, vec![]);
        let path = dir.path().join(BLOCK_LOG_FILE);
        let complete_len = std::fs::metadata(&path).unwrap().len();
        // Simulate a crash mid-append: a full length prefix + partial body.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&1000u32.to_le_bytes()).unwrap();
        f.write_all(&[0xAB; 10]).unwrap();
        drop(f);

        let b = load_dev(dir.path()).unwrap();
        assert_eq!(b.tip().height, 2, "resumes from last complete block");
        assert_chain_eq(&a, &b);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            complete_len,
            "partial tail truncated away"
        );

        // A partial length prefix alone is likewise dropped.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0x01, 0x02]).unwrap();
        drop(f);
        let c = load_dev(dir.path()).unwrap();
        assert_eq!(c.tip().height, 2);
    }

    #[test]
    fn corrupt_mid_log_record_errors() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = dev_chain();
        grow_and_save(&mut a, dir.path(), true, vec![]);
        grow_and_save(&mut a, dir.path(), true, vec![]);
        let path = dir.path().join(BLOCK_LOG_FILE);
        let mut data = std::fs::read(&path).unwrap();
        // Flip a byte inside the FIRST record's payload (past the length
        // prefix and header-length framing) — corruption, not a tail.
        data[LEN_PREFIX_BYTES + 8] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();

        let err = load_dev(dir.path()).unwrap_err();
        assert!(
            matches!(err, StoreError::Decode { .. } | StoreError::Replay { .. }),
            "corruption must fail loudly, got: {err}"
        );
    }

    #[test]
    fn witness_log_corrupt_record_errors() {
        // A complete record whose payload is not a witness must fail
        // loudly (corruption, never silently skipped).
        let dir = tempfile::tempdir().unwrap();
        let mut record = (4u32).to_le_bytes().to_vec();
        record.extend_from_slice(&[0xAB; 4]);
        std::fs::write(dir.path().join(WITNESS_LOG_FILE), &record).unwrap();
        assert!(matches!(
            read_witness_log(dir.path()),
            Err(StoreError::WitnessDecode { offset: 0, .. })
        ));
    }

    #[test]
    fn record_with_absurd_length_errors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(BLOCK_LOG_FILE), u32::MAX.to_le_bytes()).unwrap();
        assert!(matches!(
            load_dev(dir.path()),
            Err(StoreError::RecordTooLarge { offset: 0, .. })
        ));
    }

    #[test]
    fn out_of_order_log_fails_replay() {
        // Persist height-1 then height-2, but swap the records on disk:
        // replay must reject via the same linkage rules live blocks face.
        let dir = tempfile::tempdir().unwrap();
        let mut a = dev_chain();
        grow_and_save(&mut a, dir.path(), true, vec![]);
        grow_and_save(&mut a, dir.path(), true, vec![]);
        let path = dir.path().join(BLOCK_LOG_FILE);
        let data = std::fs::read(&path).unwrap();
        let len0 = u32::from_le_bytes(data[..LEN_PREFIX_BYTES].try_into().unwrap()) as usize;
        let rec0_end = LEN_PREFIX_BYTES + len0;
        let mut swapped = data[rec0_end..].to_vec();
        swapped.extend_from_slice(&data[..rec0_end]);
        std::fs::write(&path, &swapped).unwrap();

        assert!(matches!(
            load_dev(dir.path()),
            Err(StoreError::Replay { height: 2, .. })
        ));
    }
}
