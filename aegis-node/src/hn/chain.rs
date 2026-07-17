//! The hash-native chain facade: a persisted block log over [`HnState`], the
//! mempool (tx admission), local block production, and the wallet-facing
//! [`ChainView`] + submit API. The persistence model mirrors the Curve-Trees
//! node (`store.rs`): **the block sequence IS the persisted state** — an
//! append-only framed log; on restart the log is replayed to rebuild state.
//! Reorg-safety is [`HnState::rollback`] (exact inverse of `apply_block`);
//! this facade exposes the append path a fork-choice driver would call.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aegis_engine::address::Address;
use aegis_engine::merkle::MerklePath;
use aegis_engine::poseidon::hash_id_domain;
use aegis_engine::poseidon::{Digest, DIGEST_ELEMS};
use aegis_hn_wallet::chain::OutputRecord;
use aegis_hn_wallet::{ChainView, SpendCircuit, Tx};

use super::mint::{coinbase_note, MintOut};
use super::state::{digest_to_limbs, limbs_to_digest, HnBlock, HnError, HnState};

const BLOCK_LOG: &str = "hn_blocks.log";
const DOMAIN_BLOCK_ID: u32 = 0x0B10;

/// The node's hash-native chain: state + circuit keys + mempool, persisted to
/// `dir`.
pub struct HnChain {
    state: HnState,
    circuit: SpendCircuit,
    dir: PathBuf,
    mempool: Vec<Tx>,
    mempool_nfs: HashSet<[u32; DIGEST_ELEMS]>,
}

impl HnChain {
    /// A fresh chain persisted under `dir` (creates the dir). `circuit` MUST be
    /// the reproducible published keys (`SpendCircuit::new` — fixed public preprocessed
    /// salt) so the
    /// vk is stable across restarts.
    pub fn create(dir: impl AsRef<Path>, circuit: SpendCircuit) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir.as_ref())?;
        Ok(Self {
            state: HnState::new(),
            circuit,
            dir: dir.as_ref().to_path_buf(),
            mempool: Vec::new(),
            mempool_nfs: HashSet::new(),
        })
    }

    /// Open an existing chain: replay the persisted block log to rebuild state
    /// (the restart path). A partial trailing record (crash mid-append) is
    /// ignored.
    pub fn open(dir: impl AsRef<Path>, circuit: SpendCircuit) -> std::io::Result<Self> {
        let mut chain = Self::create(dir, circuit)?;
        for payload in read_log(&chain.dir.join(BLOCK_LOG))? {
            let Ok(block) = postcard::from_bytes::<HnBlock>(&payload) else {
                break; // corrupt tail
            };
            chain
                .state
                .apply_block(&block, &chain.circuit)
                .expect("a persisted block must re-apply cleanly");
        }
        Ok(chain)
    }

    pub fn height(&self) -> u64 {
        self.state.height()
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    /// The published verifying key (a wallet/light client needs it too).
    pub fn circuit(&self) -> &SpendCircuit {
        &self.circuit
    }

    /// Admit a tx to the mempool: full validation (proof, anchor window, no
    /// nullifier reuse on-chain OR pending, fixed ciphertext sizes). The
    /// pending-nullifier index makes two mempool txs sharing a nullifier
    /// conflict — one is rejected.
    pub fn submit(&mut self, tx: Tx) -> Result<(), HnError> {
        let nfs = self
            .state
            .validate_tx(&tx, &self.circuit, &self.mempool_nfs)?;
        for nf in &nfs {
            self.mempool_nfs
                .insert(core::array::from_fn(|i| nf_limb(nf, i)));
        }
        self.mempool.push(tx);
        Ok(())
    }

    /// Deterministic block id for coinbase uniqueness (height ‖ prev tip root).
    fn block_id(&self) -> [u8; 32] {
        let prev = limbs_to_digest(&self.state.tip_root_limbs());
        hash_id_domain(DOMAIN_BLOCK_ID, self.state.height(), &prev)
    }

    /// Produce and persist one block from the current mempool, minting the
    /// coinbase to `miner` for `coinbase_amount`. Clears the mempool.
    pub fn produce_block(&mut self, miner: &Address, coinbase_amount: u64) -> Result<(), HnError> {
        let block_id = self.block_id();
        let MintOut {
            cm: coinbase_cm,
            ciphertext: coinbase_ct,
        } = coinbase_note(miner, coinbase_amount, &block_id);

        // The block's committed leaves, in consensus order: tx outputs, coinbase.
        let mut cms: Vec<Digest> = Vec::new();
        for tx in &self.mempool {
            cms.push(digest_at_pub(tx, aegis_engine::spend::monolith::PUB_CMO0));
            cms.push(digest_at_pub(tx, aegis_engine::spend::monolith::PUB_CMO1));
        }
        cms.push(coinbase_cm);
        let state_root = self.state.simulate_state_root(&cms);

        let block = HnBlock {
            height: self.state.height(),
            prev_root: self.state.tip_root_limbs(),
            state_root,
            txs: std::mem::take(&mut self.mempool),
            coinbase_cm: digest_to_limbs(&coinbase_cm),
            coinbase_ct,
        };
        self.state.apply_block(&block, &self.circuit)?;
        self.persist(&block);
        self.mempool_nfs.clear();
        Ok(())
    }

    fn persist(&self, block: &HnBlock) {
        let payload = postcard::to_allocvec(block).expect("block serializes");
        append_record(&self.dir.join(BLOCK_LOG), &payload)
            .expect("persisting a block must not fail");
    }
}

fn nf_limb(nf: &Digest, i: usize) -> u32 {
    use p3_field::PrimeField32;
    nf[i].as_canonical_u32()
}

fn digest_at_pub(tx: &Tx, off: usize) -> Digest {
    aegis_hn_wallet::chain::digest_at(&tx.public_values, off)
}

impl ChainView for HnChain {
    fn current_root(&self) -> Digest {
        self.state.current_root()
    }
    fn authentication_path(&self, leaf_index: u64) -> Option<MerklePath> {
        self.state.authentication_path(leaf_index)
    }
    fn nullifier_seen(&self, nf: &Digest) -> bool {
        self.state.nullifier_seen(nf)
    }
    fn outputs_since(&self, cursor: u64) -> Vec<OutputRecord> {
        self.state.outputs_since(cursor)
    }
    fn output_count(&self) -> u64 {
        self.state.output_count()
    }
}

// ---- framed append-only log (mirrors store.rs's `u32-LE len ‖ payload`) ----

fn append_record(path: &Path, payload: &[u8]) -> std::io::Result<()> {
    let mut record = Vec::with_capacity(4 + payload.len());
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(payload);
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(&record)?;
    f.sync_all()
}

fn read_log(path: &Path) -> std::io::Result<Vec<Vec<u8>>> {
    let mut buf = Vec::new();
    match OpenOptions::new().read(true).open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut buf)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= buf.len() {
        let len = u32::from_le_bytes(buf[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + len > buf.len() {
            break; // partial trailing record
        }
        out.push(buf[i..i + len].to_vec());
        i += len;
    }
    Ok(out)
}
