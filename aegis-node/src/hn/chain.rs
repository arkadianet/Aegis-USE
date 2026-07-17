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
use super::state::{digest_to_limbs, limbs_to_digest, AuxAnchor, HnBlock, HnError, HnState};

const BLOCK_LOG: &str = "hn_blocks.log";
const DOMAIN_BLOCK_ID: u32 = 0x0B10;

/// Fixed per-block emission (base units) for the new testnet profile — a flat
/// schedule (documented; a real chain halves). Fees are added on top and go to
/// the miner (no burning).
pub const EMISSION_PER_BLOCK: u64 = 50;

/// The node's hash-native chain: state + circuit keys + mempool + the block
/// log (kept in memory for P2P serving), persisted to `dir`.
pub struct HnChain {
    state: HnState,
    circuit: SpendCircuit,
    dir: PathBuf,
    mempool: Vec<Tx>,
    mempool_nfs: HashSet<[u32; DIGEST_ELEMS]>,
    /// Every applied block (index == height) — served to syncing peers.
    blocks: Vec<HnBlock>,
    params: super::params::HnChainParams,
}

impl HnChain {
    /// A fresh chain persisted under `dir` (creates the dir). `circuit` MUST be
    /// the reproducible published keys (`SpendCircuit::new` — fixed public
    /// preprocessed salt) so the vk is stable across restarts. No genesis
    /// allocation (tests that fund manually); use [`Self::create_with_params`]
    /// for a real chain profile.
    pub fn create(dir: impl AsRef<Path>, circuit: SpendCircuit) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir.as_ref())?;
        Ok(Self {
            state: HnState::new(),
            circuit,
            dir: dir.as_ref().to_path_buf(),
            mempool: Vec::new(),
            mempool_nfs: HashSet::new(),
            blocks: Vec::new(),
            params: super::params::HnChainParams::testnet(),
        })
    }

    /// A fresh chain for a chain profile: applies the genesis allocation
    /// (`params.genesis`) as immediately-spendable faucet notes at height 0.
    pub fn create_with_params(
        dir: impl AsRef<Path>,
        circuit: SpendCircuit,
        params: super::params::HnChainParams,
    ) -> std::io::Result<Self> {
        let mut chain = Self::create(dir, circuit)?;
        let genesis = params.genesis.clone();
        chain.params = params;
        for (addr, amount) in &genesis {
            chain
                .fund(addr, *amount)
                .expect("genesis allocation applies");
        }
        Ok(chain)
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
            chain.blocks.push(block);
        }
        Ok(chain)
    }

    /// The chain's parameters.
    pub fn params(&self) -> &super::params::HnChainParams {
        &self.params
    }

    /// Sync from a peer over HTTP: pull every block the peer has beyond our tip
    /// and ingest it (IBD from genesis if we are empty). Returns the number of
    /// blocks applied. Invalid peer blocks stop the sync (a peer can withhold,
    /// never forge — every block is re-validated by `apply_block`).
    pub fn sync_from(&mut self, peer: &super::http_client::HttpChain) -> usize {
        let mut applied = 0;
        loop {
            let target = peer.peer_block_count();
            if self.block_count() >= target {
                break;
            }
            let batch = peer.fetch_blocks(self.block_count());
            if batch.is_empty() {
                break;
            }
            for block in batch {
                match self.ingest_block(block) {
                    Ok(true) => applied += 1,
                    Ok(false) => {}
                    Err(_) => return applied, // invalid — stop
                }
            }
        }
        applied
    }

    /// The number of blocks (== height) — the sync cursor a peer catches up to.
    pub fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Blocks with height `>= from` — the P2P block feed a syncing peer pulls.
    pub fn blocks_since(&self, from: u64) -> Vec<HnBlock> {
        self.blocks
            .get(from as usize..)
            .map(<[HnBlock]>::to_vec)
            .unwrap_or_default()
    }

    /// Ingest a block received from a peer (P2P / IBD). Fork choice this pass is
    /// **longest-valid-chain by linear extension**: a block is accepted iff it
    /// extends the current tip (`height == self.height` and its `prev_root`
    /// matches, both re-checked by `apply_block`); a stale/duplicate block
    /// (height already reached) is a no-op; anything else is rejected. Deep
    /// reorg / aux-PoW-weight fork choice across competing tips is deferred (see
    /// dev-docs) — for a single-producer testnet with followers this suffices.
    pub fn ingest_block(&mut self, block: HnBlock) -> Result<bool, HnError> {
        if block.height < self.state.height() {
            return Ok(false); // already have it
        }
        self.state.apply_block(&block, &self.circuit)?;
        self.blocks.push(block.clone());
        self.persist(&block);
        // Drop any mempool tx whose nullifier just landed on-chain.
        self.mempool.retain(|tx| {
            let nfs = [
                digest_at_pub(tx, aegis_engine::spend::monolith::PUB_NF0),
                digest_at_pub(tx, aegis_engine::spend::monolith::PUB_NF1),
            ];
            !nfs.iter().any(|nf| self.state.nullifier_seen(nf))
        });
        Ok(true)
    }

    pub fn height(&self) -> u64 {
        self.state.height()
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    /// The pending mempool txs (served for gossip).
    pub fn mempool_txs(&self) -> Vec<Tx> {
        self.mempool.clone()
    }

    /// Pull a peer's mempool and admit each tx locally (tx gossip). Returns how
    /// many were newly admitted; already-known / invalid ones are skipped.
    pub fn pull_mempool(&mut self, peer: &super::http_client::HttpChain) -> usize {
        let mut n = 0;
        for tx in peer.fetch_mempool() {
            if self.submit(tx).is_ok() {
                n += 1;
            }
        }
        n
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

    /// The block reward the miner claims: the fixed emission plus every mempool
    /// tx's fee (fees stop burning — the miner earns them via the coinbase note).
    fn block_reward(&self) -> u64 {
        let fees: u64 = self
            .mempool
            .iter()
            .map(|tx| HnState::tx_fee(tx).unwrap_or(0))
            .sum();
        EMISSION_PER_BLOCK.saturating_add(fees)
    }

    /// Produce a block with an AUTO monotone anchor (`devnet_height = height`).
    /// Local/test path; the deployment uses [`Self::produce_block_anchored`]
    /// with a header fetched from the live devnet.
    pub fn produce_block(&mut self, miner: &Address) -> Result<(), HnError> {
        let id = self.block_id();
        let anchor = AuxAnchor {
            devnet_header_id: id,
            devnet_height: self.state.height(),
        };
        self.produce_block_anchored(miner, anchor)
    }

    /// Produce and persist one block from the current mempool, minting the
    /// coinbase (emission + fees) to `miner`, merge-mined against `anchor`
    /// (a real devnet header for the deployment). Clears the mempool.
    pub fn produce_block_anchored(
        &mut self,
        miner: &Address,
        anchor: AuxAnchor,
    ) -> Result<(), HnError> {
        let coinbase_amount = self.block_reward();
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
            coinbase_is_reward: true,
            anchor,
        };
        self.state.apply_block(&block, &self.circuit)?;
        self.blocks.push(block.clone());
        self.persist(&block);
        self.mempool_nfs.clear();
        Ok(())
    }

    /// Genesis/faucet allocation: a block minting `amount` to `dest` as an
    /// immediately-spendable (non-maturity) note. For chain bootstrap / testnet
    /// funding — a real genesis pins these in the chain-id.
    pub fn fund(&mut self, dest: &Address, amount: u64) -> Result<(), HnError> {
        let block_id = self.block_id();
        let MintOut {
            cm: coinbase_cm,
            ciphertext: coinbase_ct,
        } = coinbase_note(dest, amount, &block_id);
        let state_root = self.state.simulate_state_root(&[coinbase_cm]);
        let block = HnBlock {
            height: self.state.height(),
            prev_root: self.state.tip_root_limbs(),
            state_root,
            txs: vec![],
            coinbase_cm: digest_to_limbs(&coinbase_cm),
            coinbase_ct,
            coinbase_is_reward: false,
            anchor: AuxAnchor::genesis(),
        };
        self.state.apply_block(&block, &self.circuit)?;
        self.blocks.push(block.clone());
        self.persist(&block);
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
    fn tip_height(&self) -> u64 {
        self.state.height()
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
