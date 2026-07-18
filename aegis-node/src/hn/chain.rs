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
use aegis_engine::poseidon::{Digest, DIGEST_ELEMS};
use aegis_hn_wallet::chain::OutputRecord;
use aegis_hn_wallet::{ChainView, SpendCircuit, Tx};

use super::mint::{coinbase_note, MintOut};
use super::params::HnChainParams;
use super::state::{
    block_id, digest_to_limbs, limbs_to_digest, AuxAnchor, HnBlock, HnError, HnState, PegInClaim,
    PegOutTx, Withdrawal,
};

const BLOCK_LOG: &str = "hn_blocks.log";

/// A node-local view of the devnet vault used to admit peg-in claims. The
/// producer queues only claims its own view confirms; a FOLLOWER re-checks
/// every claim in an ingested block against ITS view — a claim not yet
/// confirmed there is a DEFERRAL (sync retries next tick), never a hard
/// reject, which is exactly the anchor-deferral posture for a devnet reorg
/// under the deposit: below the pinned depth nothing mints, and a busy
/// follower simply waits until its own devnet view is deep enough.
pub trait PegInCheck: Send {
    /// Is this exact claim (box id, dest, amount) a vault deposit CONFIRMED at
    /// the required depth in our own devnet view?
    fn confirmed(&self, claim: &PegInClaim) -> bool;
}

/// The node's hash-native chain: state + circuit keys + mempool + the block
/// log (kept in memory for P2P serving), persisted to `dir`.
pub struct HnChain {
    state: HnState,
    circuit: SpendCircuit,
    dir: PathBuf,
    mempool: Vec<Tx>,
    mempool_pegouts: Vec<PegOutTx>,
    /// Confirmed deposits queued for the next produced block.
    pegin_queue: Vec<PegInClaim>,
    /// The devnet-vault view claims are checked against (None = no peg-in
    /// admission; blocks with claims are deferred until a view is set).
    pegin_check: Option<Box<dyn PegInCheck>>,
    mempool_nfs: HashSet<[u32; DIGEST_ELEMS]>,
    /// Every applied block (index == height) — served to syncing peers.
    blocks: Vec<HnBlock>,
}

impl HnChain {
    /// A fresh, EMPTY chain persisted under `dir` (creates the dir) for the
    /// given chain profile — no genesis blocks applied (a follower that IBDs
    /// them from a peer, or a test that applies its own). `circuit` MUST be the
    /// reproducible published keys (`SpendCircuit::new` — fixed public
    /// preprocessed salt) so the vk is stable across restarts.
    pub fn create(
        dir: impl AsRef<Path>,
        circuit: SpendCircuit,
        params: HnChainParams,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir.as_ref())?;
        Ok(Self {
            state: HnState::new(params),
            circuit,
            dir: dir.as_ref().to_path_buf(),
            mempool: Vec::new(),
            mempool_pegouts: Vec::new(),
            pegin_queue: Vec::new(),
            pegin_check: None,
            mempool_nfs: HashSet::new(),
            blocks: Vec::new(),
        })
    }

    /// A fresh chain with the profile's genesis applied: the pinned allocation
    /// (`params.genesis`) minted as immediately-spendable notes at the genesis
    /// heights (the bootstrap node's path).
    pub fn create_genesis(
        dir: impl AsRef<Path>,
        circuit: SpendCircuit,
        params: HnChainParams,
    ) -> std::io::Result<Self> {
        let genesis = params.genesis.clone();
        let mut chain = Self::create(dir, circuit, params)?;
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
    pub fn open(
        dir: impl AsRef<Path>,
        circuit: SpendCircuit,
        params: HnChainParams,
    ) -> std::io::Result<Self> {
        let mut chain = Self::create(dir, circuit, params)?;
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
    pub fn params(&self) -> &HnChainParams {
        self.state.params()
    }

    /// The emission pot's current balance (public security budget).
    pub fn pot(&self) -> u64 {
        self.state.pot()
    }

    /// The shielded pool's total value (public aggregate).
    pub fn shielded_total(&self) -> u64 {
        self.state.shielded_total()
    }

    /// The recorded withdrawals (the settle loop reads these; settleable once
    /// `hn_height + pegout_delay <= tip`).
    pub fn withdrawals(&self) -> Vec<Withdrawal> {
        self.state.withdrawals().to_vec()
    }

    /// Wire the devnet-vault view peg-in claims are admitted against.
    pub fn set_pegin_check(&mut self, check: Box<dyn PegInCheck>) {
        self.pegin_check = Some(check);
    }

    /// Queue a CONFIRMED deposit for the next produced block (producer path;
    /// the claim is still fully re-validated at apply). Skips already-minted
    /// and already-queued box ids.
    pub fn queue_pegin(&mut self, claim: PegInClaim) {
        if self.state.pegin_used(&claim.box_id)
            || self.pegin_queue.iter().any(|c| c.box_id == claim.box_id)
        {
            return;
        }
        if let Some(check) = &self.pegin_check {
            if !check.confirmed(&claim) {
                return;
            }
        }
        self.pegin_queue.push(claim);
    }

    /// Admit a peg-out to the mempool: the inner spend is fully validated
    /// (proof, flat fee, anchor, nullifiers) and the burn commitment must
    /// match the public withdrawal exactly.
    pub fn submit_pegout(&mut self, po: PegOutTx) -> Result<(), HnError> {
        let nfs = self
            .state
            .validate_tx(&po.tx, &self.circuit, &self.mempool_nfs)?;
        let fee = self.state.params().peg_fee(po.amount);
        let burn_value = po.amount.checked_add(fee).ok_or(HnError::BadPegOut)?;
        if po.amount == 0 || po.recipient_prop.is_empty() || po.recipient_prop.len() > 4096 {
            return Err(HnError::BadPegOut);
        }
        let cm0 = digest_at_pub(&po.tx, aegis_engine::spend::monolith::PUB_CMO0);
        if aegis_engine::burn::burn_cm_expected(burn_value, &nfs[0]) != cm0 {
            return Err(HnError::BadPegOut);
        }
        for nf in &nfs {
            self.mempool_nfs
                .insert(core::array::from_fn(|i| nf_limb(nf, i)));
        }
        self.mempool_pegouts.push(po);
        Ok(())
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
        // Peg-in claims must be confirmed in OUR OWN devnet view too. A claim
        // our view has not (yet) confirmed is a DEFERRAL — the sync loop stops
        // and retries next tick — never a hard reject (devnet-reorg posture).
        if !block.pegins.is_empty() {
            match &self.pegin_check {
                None => return Err(HnError::PegInNotConfirmed),
                Some(check) => {
                    for pi in &block.pegins {
                        if !check.confirmed(pi) {
                            return Err(HnError::PegInNotConfirmed);
                        }
                    }
                }
            }
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
        block_id(self.state.height(), &prev)
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
    /// pot-funded coinbase (`min(pot_parent, base + per_tx × txs)`; fees credit
    /// the pot, never the miner directly) to `miner`, merge-mined against
    /// `anchor` (a real devnet header for the deployment). Clears the mempool.
    pub fn produce_block_anchored(
        &mut self,
        miner: &Address,
        anchor: AuxAnchor,
    ) -> Result<(), HnError> {
        let params = self.state.params();
        let n_spends = self.mempool.len() + self.mempool_pegouts.len();
        let coinbase_amount = params.coinbase_amount(self.state.pot(), n_spends);
        let fees = params.flat_fee * n_spends as u64;
        let peg_fees: u64 = self
            .mempool_pegouts
            .iter()
            .map(|po| params.peg_fee(po.amount))
            .chain(self.pegin_queue.iter().map(|pi| params.peg_fee(pi.amount)))
            .sum();
        let pot_after = self.state.pot() + fees + peg_fees - coinbase_amount;
        let block_id = self.block_id();
        let MintOut {
            cm: coinbase_cm,
            ciphertext: coinbase_ct,
        } = coinbase_note(miner, coinbase_amount, &block_id);

        // The block's committed leaves, in consensus order: tx outputs,
        // peg-out outputs, peg-in mints, coinbase.
        let mut cms: Vec<Digest> = Vec::new();
        for tx in self
            .mempool
            .iter()
            .chain(self.mempool_pegouts.iter().map(|p| &p.tx))
        {
            cms.push(digest_at_pub(tx, aegis_engine::spend::monolith::PUB_CMO0));
            cms.push(digest_at_pub(tx, aegis_engine::spend::monolith::PUB_CMO1));
        }
        for pi in &self.pegin_queue {
            let minted = pi.amount - params.peg_fee(pi.amount);
            cms.push(super::mint::pegmint_cm_expected(
                &limbs_to_digest(&pi.dest_owner),
                minted,
                &pi.box_id,
            ));
        }
        cms.push(coinbase_cm);
        let state_root = self.state.simulate_state_root(&cms);

        let block = HnBlock {
            height: self.state.height(),
            prev_root: self.state.tip_root_limbs(),
            state_root,
            txs: std::mem::take(&mut self.mempool),
            pegouts: std::mem::take(&mut self.mempool_pegouts),
            pegins: std::mem::take(&mut self.pegin_queue),
            miner_owner: digest_to_limbs(&miner.owner),
            coinbase_amount,
            coinbase_cm: digest_to_limbs(&coinbase_cm),
            coinbase_ct,
            coinbase_is_reward: true,
            pot_after,
            anchor,
        };
        self.state.apply_block(&block, &self.circuit)?;
        self.blocks.push(block.clone());
        self.persist(&block);
        self.mempool_nfs.clear();
        Ok(())
    }

    /// One pinned genesis-allocation block: mint `amount` to `dest` as an
    /// immediately-spendable note (pot untouched). Only callable through
    /// [`Self::create_genesis`] — `apply_block` rejects any allocation that
    /// deviates from `params.genesis`, so arbitrary funding cannot exist.
    fn fund(&mut self, dest: &Address, amount: u64) -> Result<(), HnError> {
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
            pegouts: vec![],
            pegins: vec![],
            miner_owner: digest_to_limbs(&dest.owner),
            coinbase_amount: amount,
            coinbase_cm: digest_to_limbs(&coinbase_cm),
            coinbase_ct,
            coinbase_is_reward: false,
            pot_after: self.state.pot(),
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
