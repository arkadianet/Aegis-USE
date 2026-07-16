//! Runnable merge-mining node (M6c) — the loop that composes the
//! verified-in-isolation modules into a node that follows, syncs,
//! produces, and serves:
//!
//! - **Boot** — load/replay the on-disk archive (`store.rs` block +
//!   witness logs) through the fork choice: every stored witness is
//!   re-verified ([`ShareWitness::verify`]) and every stored body
//!   re-validated (`Chain::try_extend` via
//!   [`MmForkChoice::ingest_body`]) — the resume IS a self-sync from
//!   the local archive via [`sync_from_seeds`]; nothing on disk is
//!   trusted. Then catch up: [`fresh_sync`] when both an Ergo node and
//!   seeds are configured, the seed schedule alone otherwise.
//! - **Follow + watch** — each tick drives the [`Follower`] (headers
//!   from `--ergo-url`) and the [`AnchorWatch`] (extension scans),
//!   feeding verified shares/bodies/anchors into the [`MmForkChoice`].
//!   On non-dev networks this is the node's only block source (a
//!   consumer node).
//! - **Produce (dev only)** — in `--produce` on `--network dev`, build
//!   a candidate on the canonical tip and grind a **synthetic dev
//!   aux-PoW share** in-process (see below), then feed it through the
//!   exact ingest path a peer's share would take.
//! - **Serve** — `--serve-addr` spawns a [`SeedServer`] over the node's
//!   [`SeedCore`] archive, making this node a body/witness seed peers
//!   can [`fresh_sync`] from.
//!
//! ## The dev producer's synthetic shares — read this
//!
//! The dev network has no real Ergo chain to merge-mine against, so
//! [`grind_dev_witness`] fabricates a SYNTHETIC Ergo header whose
//! extension commits to the Aegis candidate and grinds a real
//! Autolykos-v2 nonce against the (easy) **Aegis** target from the
//! candidate's DAA-pinned `sc_nbits`. The work is real aux-PoW work at
//! dev difficulty; what is bypassed is the real-Ergo-follower C2
//! height window (the [`ShareContext`] is built from the synthetic
//! header's own height). This bypass is gated on `Network::Dev` — the
//! producer refuses to run anywhere else — and no real Ergo block's
//! PoW is ever fabricated (the synthetic header could never pass
//! [`Follower::apply_header`]).
//!
//! ## Honest scope: production merge-mining is an Ergo-side task
//!
//! Real testnet/mainnet merge-mining needs the **Ergo node's candidate
//! builder** to embed the [`aegis_mm_extension_field`] commitment in a
//! real Ergo block's extension and mine it — a change to
//! `arkadianet/ergo` (`ergo-mining`'s extension builder), NOT this
//! repo. M6c delivers (a) the runnable DEV merge-mined chain
//! end-to-end and (b) the consumer/follower/seed/fresh-sync wiring
//! that works on real networks the moment real commitments exist.
//! See `dev-docs/sidechain/architecture.md` §4.
//!
//! Everything fetched or read is DATA, never instructions: witnesses
//! re-verify from presented bytes, bodies self-authenticate, and even
//! the node's own disk archive re-passes full validation on resume.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use aegis_crypto::generators::EvenPoint;
use aegis_crypto::note::EvenScalar;
use aegis_spec::{Network, K_LAG};
use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::autolykos::v2::check_pow_v2;
use ergo_crypto::difficulty::get_target;
use ergo_crypto::merkle::extension_root;
use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{serialize_header_without_pow, Header as ErgoHeader};
use num_bigint::BigUint;

use crate::anchor_watch::fetch_http::{RestBlockConfig, RestBlockError, RestBlockSource};
use crate::anchor_watch::{
    extension_field_proof, settled_is_final, AegisLookup, AegisSource, AnchorWatch,
};
use crate::api::{ApiServer, ApiState, NodeStatus};
use crate::auxpow::{aegis_mm_extension_field, ShareContext, ShareWitness};
use crate::block::{Block, BlockBody};
use crate::chain::{PowMode, ProofMode};
use crate::daa::DaaParams;
use crate::ergo_follow::poll_http::{RestHeaderSource, RestSourceConfig, RestSourceError};
use crate::ergo_follow::Follower;
use crate::fresh_sync::{fresh_sync, sync_from_seeds};
use crate::mempool::{AdmissionView, Mempool};
use crate::mm_forkchoice::{BodyIngest, MmForkChoice, ShareIngest};
use crate::seed::fetch_http::{FetchError, RestAegisSource, SeedClientConfig};
use crate::seed::serve_http::SeedServer;
use crate::seed::{Id, SeedCore, SeedFetch, SeedTips};
use crate::store::{read_log, read_witness_log, save_block, save_witness, StoreError};

/// Fixed dev coinbase reward tag (blinding varies per height so the
/// minted notes are distinct leaves — same values the G1 dev loop used).
const DEV_COINBASE_TAG: u64 = 0xC0FFEE;

/// Grind bound for one dev share: dev difficulty starts at 1 000 and
/// the DAA clamps each step to ×4, so tens of millions of tries is
/// orders of magnitude of headroom before this trips.
const DEV_GRIND_MAX_TRIES: u64 = 50_000_000;

/// SEC1-compressed secp256k1 generator point — a valid public key for
/// the synthetic dev header's Autolykos solution (the v2 hit does not
/// depend on `pk`, but the header must serialize a real point shape).
const DEV_MINER_PK: [u8; 33] = [
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
];

/// Node configuration — the CLI surface (`main.rs` maps `Args` here).
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Which Aegis network's chain to run.
    pub network: Network,
    /// Produce merge-mined blocks. Only honored on [`Network::Dev`]
    /// (see the module doc's honest-scope section).
    pub produce: bool,
    /// Persist blocks + witnesses here and resume from it on boot.
    /// Unset: fully in-memory.
    pub data_dir: Option<PathBuf>,
    /// Ergo node REST base URL for the follower + anchor watcher.
    pub ergo_url: Option<String>,
    /// Ergo height the follower/watcher starts from when empty (the
    /// followed root — e.g. the network's Aegis genesis anchor height).
    pub ergo_start_height: u32,
    /// Seed base URLs for body/witness fetch + fresh sync.
    pub seed_urls: Vec<String>,
    /// Bind address for this node's own seed server (e.g.
    /// `127.0.0.1:8650`, port 0 for an ephemeral port).
    pub serve_addr: Option<String>,
    /// Peg-finality work lead `l_final` (in difficulty units) used for
    /// the per-tick `is_final` telemetry.
    pub l_final: u64,
    /// Bind address for the read-only node API (M3), e.g.
    /// `127.0.0.1:8750`. Unset: no API server.
    pub api_addr: Option<String>,
    /// This node's attester identity (S1b). Set on a federation member to
    /// serve signed tip attestations at `/attest/tip`; `None` on a plain
    /// node. Requires `api_addr` to have any effect.
    pub attester: Option<crate::attest::AttesterContext>,
}

/// Node boot/config failure.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("seed server bind: {0}")]
    Serve(#[from] std::io::Error),
    #[error("ergo header client: {0}")]
    ErgoHeaders(#[from] RestSourceError),
    #[error("ergo block client: {0}")]
    ErgoBlocks(#[from] RestBlockError),
    #[error("seed client: {0}")]
    Seeds(#[from] FetchError),
    #[error("archive resume replay failed: {0}")]
    Resume(String),
}

/// What one [`Node::tick`] did — the loop's telemetry unit. Errors are
/// carried, not thrown: a failed source degrades a tick, it never
/// kills the node (retried next tick).
#[derive(Debug, Default)]
pub struct TickReport {
    /// `(height, id)` of a block produced this tick (dev producer).
    pub produced: Option<(u64, Id)>,
    /// Blocks that joined the validated tree via the seed schedule.
    pub sync_activated: usize,
    /// Anchor-watcher observations this tick (rendered).
    pub watch_events: Vec<String>,
    /// Per-source failures this tick (rendered; all retried later).
    pub errors: Vec<String>,
    /// Canonical tip height after the tick.
    pub canonical_height: u64,
    /// Canonical tip id after the tick.
    pub canonical_tip: Id,
    /// Cumulative real work at the canonical tip.
    pub cumulative_work: BigUint,
    /// §7 hostile-pending weight (shares without validated bodies).
    pub pending_hostile_work: BigUint,
    /// The Ergo follower's best tip height, if following.
    pub ergo_tip_height: Option<u32>,
    /// [`settled_is_final`] verdict for the canonical tip at the
    /// configured `l_final` (always `false` without a caught-up
    /// follower — refuse to judge, never guess).
    pub tip_is_final: bool,
}

/// The composed merge-mining node. Drive it with [`Node::tick`]; all
/// methods are blocking (`main.rs` runs ticks under `spawn_blocking`).
pub struct Node {
    network: Network,
    daa: DaaParams,
    produce_enabled: bool,
    data_dir: Option<PathBuf>,
    l_final: BigUint,
    l_final_units: u64,
    fc: MmForkChoice,
    follower: Follower,
    headers: Option<RestHeaderSource>,
    watch: Option<AnchorWatch<RestBlockSource>>,
    seeds: Option<RestAegisSource>,
    core: Arc<RwLock<SeedCore>>,
    server: Option<SeedServer>,
    /// Read-only API (M3): the shared snapshot the node publishes into
    /// each tick, and the server that serves it. `None` without
    /// `api_addr`.
    api_state: Option<ApiState>,
    api_server: Option<ApiServer>,
    /// Shared mempool (with the API's submit path). `None` without an
    /// API server — there is no other way to submit.
    mempool: Option<Arc<RwLock<Mempool>>>,
    /// Nullifier-set + note-leaf snapshots for the API/admission,
    /// rebuilt only when the tip changes (once per new block).
    nf_snapshot: Arc<BTreeSet<[u8; 32]>>,
    cm_leaves_snapshot: Arc<Vec<EvenPoint>>,
    nf_snapshot_tip: Id,
    /// Block ids already recorded into the core archive (+ disk log).
    recorded_blocks: BTreeSet<Id>,
    /// Ids whose witness is already recorded (+ disk log).
    recorded_witnesses: BTreeSet<Id>,
}

impl Node {
    /// Boot the node: replay the archive, wire the sources, spawn the
    /// seed server, and run one catch-up pass (fresh sync). `now_ms`
    /// is the wall clock (future-drift bound only).
    pub fn boot(config: NodeConfig, now_ms: u64) -> Result<Node, NodeError> {
        let network = config.network;
        // ProofMode: dev accepts stub proofs (the dev loop mints
        // empty-body coinbase blocks); real networks verify every
        // transfer proof.
        let proof_mode = match network {
            Network::Dev => ProofMode::DevStub,
            Network::Test | Network::Main => ProofMode::Real,
        };
        let mut fc = MmForkChoice::new(network, PowMode::DevStub, proof_mode);
        let mut core = SeedCore::new(network);
        let mut recorded_blocks = BTreeSet::new();
        let mut recorded_witnesses = BTreeSet::new();

        if let Some(dir) = &config.data_dir {
            for block in read_log(dir)? {
                recorded_blocks.insert(block.id());
                core.record_canonical(&block);
            }
            for witness in read_witness_log(dir)? {
                match core.record_witness(&witness) {
                    Ok(id) => {
                        recorded_witnesses.insert(id);
                    }
                    Err(e) => return Err(NodeError::Resume(format!("witness log: {e}"))),
                }
            }
            // Resume = self-sync from the local archive: every witness
            // re-verifies, every body re-validates. Weight is never
            // trusted from disk.
            let report = sync_from_seeds(&core, &mut fc, None, network, now_ms)
                .map_err(|e| NodeError::Resume(e.to_string()))?;
            if fc.canonical_tip().height < core.height() {
                tracing::warn!(
                    replayed = fc.canonical_tip().height,
                    stored = core.height(),
                    missing_witnesses = report.missing_witness.len(),
                    "archive resume fell short of the stored height; \
                     the gap re-syncs from seeds / the Ergo scan"
                );
            } else if core.height() > 0 {
                tracing::info!(
                    height = fc.canonical_tip().height,
                    tip = hex::encode(fc.canonical_tip_id()),
                    "resumed merge-mined chain from archive (fully re-verified)"
                );
            }
        }

        let follower = Follower::new(network.params().ergo_mint_confs);
        let (headers, watch) = match &config.ergo_url {
            Some(url) => {
                let headers = RestHeaderSource::new(RestSourceConfig::new(url.clone()))?;
                let blocks = RestBlockSource::new(RestBlockConfig::new(url.clone()))?;
                let watch = AnchorWatch::new(blocks, network, config.ergo_start_height);
                (Some(headers), Some(watch))
            }
            None => (None, None),
        };
        let seeds = if config.seed_urls.is_empty() {
            None
        } else {
            Some(RestAegisSource::new(SeedClientConfig::new(
                config.seed_urls.iter().cloned(),
            ))?)
        };
        let core = Arc::new(RwLock::new(core));
        let server = match &config.serve_addr {
            Some(addr) => Some(SeedServer::spawn(addr, Arc::clone(&core))?),
            None => None,
        };

        let produce_enabled = config.produce && network == Network::Dev;
        if config.produce && network != Network::Dev {
            tracing::warn!(
                "--produce ignored on {}: real-network merge-mining needs the Ergo-side \
                 candidate builder (arkadianet/ergo, ergo-mining) — running as a consumer node",
                network.params().network_name
            );
        }

        let api_addr = config.api_addr.clone();
        let attester = config.attester;
        let mut node = Node {
            network,
            daa: DaaParams::for_network(network),
            produce_enabled,
            data_dir: config.data_dir,
            l_final: BigUint::from(config.l_final),
            l_final_units: config.l_final,
            fc,
            follower,
            headers,
            watch,
            seeds,
            core,
            server,
            api_state: None,
            api_server: None,
            mempool: None,
            nf_snapshot: Arc::new(BTreeSet::new()),
            cm_leaves_snapshot: Arc::new(Vec::new()),
            nf_snapshot_tip: [0u8; 32],
            recorded_blocks,
            recorded_witnesses,
        };
        // Initial catch-up. Failures are logged and retried per tick —
        // an unreachable source must not kill the node.
        for e in node.catch_up(now_ms) {
            tracing::warn!(error = %e, "boot catch-up incomplete; retrying in the loop");
        }
        // Spawn the API (+ its shared mempool) over the caught-up state.
        if let Some(addr) = api_addr {
            node.refresh_snapshots();
            let mempool = Arc::new(RwLock::new(Mempool::new()));
            let mut state = ApiState::new(
                node.build_status(),
                Arc::clone(&node.core),
                Arc::clone(&mempool),
                node.admission_view(),
            );
            if let Some(ctx) = attester {
                state = state.with_attester(ctx);
            }
            let server = ApiServer::spawn(&addr, state.clone())?;
            tracing::info!(addr = %server.local_addr(), "node API serving");
            node.api_state = Some(state);
            node.api_server = Some(server);
            node.mempool = Some(mempool);
        }
        Ok(node)
    }

    /// One loop pass: drive the Ergo follower + anchor watcher, run a
    /// seed-schedule sync, produce (dev), persist, snapshot telemetry.
    pub fn tick(&mut self, now_ms: u64) -> TickReport {
        let mut report = TickReport::default();
        self.drive_watch(now_ms, &mut report);
        self.drive_seed_sync(now_ms, &mut report);
        if self.produce_enabled {
            match self.produce_one(now_ms, &mut report.errors) {
                Ok(produced) => report.produced = Some(produced),
                Err(e) => report.errors.push(e),
            }
        }
        let tip = self.fc.canonical_tip_id();
        report.canonical_height = self.fc.canonical_tip().height;
        report.canonical_tip = tip;
        report.cumulative_work = self
            .fc
            .cumulative_work(&tip)
            .cloned()
            .unwrap_or(BigUint::ZERO);
        report.pending_hostile_work = self.fc.pending_hostile_work();
        report.ergo_tip_height = self.follower.tip_height();
        report.tip_is_final = settled_is_final(&self.fc, &self.follower, &tip, &self.l_final);
        self.publish_status();
        report
    }

    /// Catch up against every configured remote source: the full
    /// [`fresh_sync`] when both Ergo and seeds exist, the Ergo skeleton
    /// alone, or the seed schedule alone. Returns rendered failures
    /// (each retried by later ticks — monotone, never fatal).
    pub fn catch_up(&mut self, now_ms: u64) -> Vec<String> {
        let mut errors = Vec::new();
        match (self.headers.is_some(), self.seeds.is_some()) {
            (true, true) => self.catch_up_fresh_sync(now_ms, &mut errors),
            (true, false) => self.catch_up_ergo_only(now_ms, &mut errors),
            (false, true) => {
                let mut report = TickReport::default();
                self.drive_seed_sync(now_ms, &mut report);
                errors.extend(report.errors);
            }
            (false, false) => {}
        }
        errors
    }

    /// The canonical tip height (fork choice's verdict).
    pub fn canonical_height(&self) -> u64 {
        self.fc.canonical_tip().height
    }

    /// The canonical tip id.
    pub fn canonical_tip_id(&self) -> Id {
        self.fc.canonical_tip_id()
    }

    /// Read access to the fork choice (tests/telemetry).
    pub fn fork_choice(&self) -> &MmForkChoice {
        &self.fc
    }

    /// The seed server's bound address, when serving (useful with
    /// port 0).
    pub fn serve_addr(&self) -> Option<SocketAddr> {
        self.server.as_ref().map(SeedServer::local_addr)
    }

    /// The API server's bound address, when serving (useful with
    /// port 0).
    pub fn api_addr(&self) -> Option<SocketAddr> {
        self.api_server.as_ref().map(ApiServer::local_addr)
    }

    // ----- internals -----

    /// Rebuild the API nullifier + note-leaf snapshots iff the canonical
    /// tip moved. Returns whether the tip changed.
    fn refresh_snapshots(&mut self) -> bool {
        let tip = self.fc.canonical_tip_id();
        if tip == self.nf_snapshot_tip {
            return false;
        }
        let state = self.fc.chain().state();
        self.nf_snapshot = Arc::new(state.nullifiers().clone());
        self.cm_leaves_snapshot = Arc::new(state.cm_leaves().to_vec());
        self.nf_snapshot_tip = tip;
        true
    }

    /// The admission view for the current snapshots (spend anchor leaves
    /// + spent set + consensus fee).
    fn admission_view(&self) -> AdmissionView {
        AdmissionView::new(
            Arc::clone(&self.cm_leaves_snapshot),
            Arc::clone(&self.nf_snapshot),
            self.network.params().sc_tx_fee,
        )
    }

    /// Publish a fresh [`NodeStatus`] snapshot to the API (no-op without
    /// an API server). On a tip change, also refresh the admission view
    /// and evict now-spent mempool transfers.
    fn publish_status(&mut self) {
        if self.api_state.is_none() {
            return;
        }
        if self.refresh_snapshots() {
            if let Some(mempool) = &self.mempool {
                mempool
                    .write()
                    .expect("mempool lock poisoned")
                    .evict_spent(&self.nf_snapshot);
            }
            let view = self.admission_view();
            self.api_state
                .as_ref()
                .expect("checked above")
                .publish_admission(view);
        }
        let status = self.build_status();
        self.api_state
            .as_ref()
            .expect("checked above")
            .publish(status);
    }

    /// Snapshot the current public node state for the API. Reads live
    /// fork-choice/follower state; the nullifier set comes from the
    /// tip-gated [`Self::refresh_nf_snapshot`].
    fn build_status(&self) -> NodeStatus {
        let chain = self.fc.chain();
        let state = chain.state();
        let tip = self.fc.canonical_tip_id();
        let header = self.fc.canonical_tip();
        let (mempool_size, mempool_txs) = match &self.mempool {
            Some(mempool) => {
                let pool = mempool.read().expect("mempool lock poisoned");
                (pool.len(), Arc::new(pool.tx_bytes()))
            }
            None => (0, Arc::new(Vec::new())),
        };
        NodeStatus {
            network_name: self.network.params().network_name,
            canonical_tip: tip,
            canonical_height: header.height,
            tip_timestamp_ms: header.timestamp_ms,
            next_sc_nbits: chain.expected_nbits(),
            median_time_past: chain.median_time_past(),
            cumulative_work: self
                .fc
                .cumulative_work(&tip)
                .cloned()
                .unwrap_or(BigUint::ZERO),
            pending_hostile_work: self.fc.pending_hostile_work(),
            ergo_tip_height: self.follower.tip_height(),
            tip_is_final: settled_is_final(&self.fc, &self.follower, &tip, &self.l_final),
            l_final: self.l_final_units,
            pot: state.pot(),
            nullifier_digest: state.nullifier_digest(),
            cm_tree_root: state.cm_tree_root(),
            leaf_count: state.leaf_count(),
            nullifiers: Arc::clone(&self.nf_snapshot),
            mempool_size,
            mempool_txs,
        }
    }

    /// Full bootstrap: Ergo skeleton to exhaustion + seed schedule +
    /// buffered-commitment retry ([`fresh_sync`]).
    fn catch_up_fresh_sync(&mut self, now_ms: u64, errors: &mut Vec<String>) {
        let seen = {
            let headers = self.headers.as_mut().expect("checked by caller");
            let watch = self.watch.as_mut().expect("headers and watch are paired");
            let seeds = self.seeds.as_ref().expect("checked by caller");
            let tee = TeeSeeds::new(seeds);
            match fresh_sync(
                &mut self.follower,
                headers,
                watch,
                &tee,
                &mut self.fc,
                self.network,
                now_ms,
            ) {
                Ok(report) => tracing::info!(
                    ergo_tip = ?report.ergo_tip_height,
                    activated = report.seed.activated,
                    height = report.canonical_height,
                    tip = hex::encode(report.canonical_tip),
                    "fresh sync complete"
                ),
                Err(e) => errors.push(format!("fresh sync: {e}")),
            }
            tee.into_seen()
        };
        self.persist_witnessed(seen, errors);
    }

    /// Drive the Ergo skeleton to exhaustion with no seeds configured
    /// (bodies resolve against the local archive only).
    fn catch_up_ergo_only(&mut self, now_ms: u64, errors: &mut Vec<String>) {
        loop {
            let tip_before = self.follower.tip_height();
            let headers = self.headers.as_mut().expect("checked by caller");
            let watch = self.watch.as_mut().expect("headers and watch are paired");
            let aegis = LocalFirstAegis {
                core: &self.core,
                seeds: None,
            };
            match watch.drive(&mut self.follower, headers, &aegis, &mut self.fc, now_ms) {
                Ok(events) => {
                    if events.is_empty() && self.follower.tip_height() == tip_before {
                        break; // caught up
                    }
                }
                Err(e) => {
                    errors.push(format!("anchor watch: {e}"));
                    break;
                }
            }
        }
    }

    /// One follower + anchor-watcher pass (a single header batch).
    fn drive_watch(&mut self, now_ms: u64, report: &mut TickReport) {
        if self.headers.is_none() {
            return;
        }
        let headers = self.headers.as_mut().expect("checked above");
        let watch = self.watch.as_mut().expect("headers and watch are paired");
        let aegis = LocalFirstAegis {
            core: &self.core,
            seeds: self.seeds.as_ref(),
        };
        match watch.drive(&mut self.follower, headers, &aegis, &mut self.fc, now_ms) {
            Ok(events) => report
                .watch_events
                .extend(events.iter().map(|e| format!("{e:?}"))),
            Err(e) => report.errors.push(format!("anchor watch: {e}")),
        }
    }

    /// One seed-schedule pass; witnesses that verified are persisted.
    fn drive_seed_sync(&mut self, now_ms: u64, report: &mut TickReport) {
        if self.seeds.is_none() {
            return;
        }
        let seen = {
            let seeds = self.seeds.as_ref().expect("checked above");
            let tee = TeeSeeds::new(seeds);
            match sync_from_seeds(
                &tee,
                &mut self.fc,
                self.follower.tip_height(),
                self.network,
                now_ms,
            ) {
                Ok(r) => {
                    report.sync_activated += r.activated;
                    for (id, why) in &r.rejected {
                        report
                            .errors
                            .push(format!("seed junk for {}: {why}", hex::encode(id)));
                    }
                }
                Err(e) => report.errors.push(format!("seed sync: {e}")),
            }
            tee.into_seen()
        };
        self.persist_witnessed(seen, &mut report.errors);
    }

    /// Dev producer: candidate on the canonical tip → grind a dev
    /// aux-PoW share → verify it with the REAL verifier (never trust
    /// our own grind) → ingest through the exact peer path → persist.
    fn produce_one(&mut self, now_ms: u64, errors: &mut Vec<String>) -> Result<(u64, Id), String> {
        debug_assert_eq!(self.network, Network::Dev, "producer is dev-gated at boot");
        let next_height = self.fc.canonical_tip().height + 1;
        // Drain the mempool: include transfers that RE-verify against the
        // live anchor (authoritative inclusion check). Empty without an
        // API/mempool → coinbase-only block, exactly as before.
        let (transfers, included_ids) = match &self.mempool {
            Some(mempool) => {
                let anchor = self.fc.chain().state().anchor_tree();
                let fee = self.network.params().sc_tx_fee;
                mempool
                    .read()
                    .expect("mempool lock poisoned")
                    .select_for_block(anchor.as_ref(), fee)
            }
            None => (Vec::new(), Vec::new()),
        };
        let candidate = self
            .fc
            .chain()
            .produce_next_with_coinbase(
                BlockBody {
                    transfers,
                    peg_mints: Vec::new(),
                },
                now_ms,
                EvenScalar::from(DEV_COINBASE_TAG),
                EvenScalar::from(next_height),
            )
            .map_err(|e| format!("candidate build: {e}"))?;
        let witness = grind_dev_witness(&candidate)?;
        // Self-check with the verifier a peer runs; the C2 window is the
        // synthetic header's own era (the documented dev bypass).
        let daa_view = self
            .fc
            .daa_view(&candidate.header.prev_id)
            .ok_or("candidate parent is not a validated fork-choice node")?;
        let ctx = ShareContext {
            follower_tip_height: witness.ergo_header.height,
            k_lag: K_LAG,
            daa: &self.daa,
            daa_view: &daa_view,
        };
        let share = witness
            .verify(&ctx)
            .map_err(|e| format!("self-mined share failed verification: {e}"))?;
        let share_ingest = self.fc.ingest_share(&share, now_ms);
        let body_ingest = self.fc.ingest_body(candidate.clone(), now_ms);
        let activated = matches!(share_ingest, ShareIngest::Activated { .. })
            || matches!(body_ingest, BodyIngest::Activated { .. });
        if !activated {
            return Err(format!(
                "self-mined block did not activate: share={share_ingest:?} body={body_ingest:?}"
            ));
        }
        self.persist_one(&candidate, &witness, errors);
        // Drop the transfers this block included from the mempool.
        if let Some(mempool) = &self.mempool {
            if !included_ids.is_empty() {
                mempool
                    .write()
                    .expect("mempool lock poisoned")
                    .remove(&included_ids);
            }
        }
        Ok((candidate.header.height, candidate.id()))
    }

    /// Persist tee'd sync witnesses whose blocks the fork choice
    /// validated (persist-only-accepted, the `store.rs` discipline).
    fn persist_witnessed(&mut self, witnesses: Vec<ShareWitness>, errors: &mut Vec<String>) {
        for witness in witnesses {
            let Ok(block) = Block::from_bytes(&witness.aegis_block_bytes) else {
                continue; // tee'd bytes came from a seed; junk was already reported
            };
            if !self.fc.is_validated(&block.id()) {
                continue;
            }
            self.persist_one(&block, &witness, errors);
        }
    }

    /// Record one accepted (block, witness) pair into the serve-side
    /// archive and, with `--data-dir`, the on-disk logs. Idempotent by
    /// id. Blocks are recorded in acceptance order, which is canonical
    /// order for the linear dev/sync paths this loop drives.
    fn persist_one(&mut self, block: &Block, witness: &ShareWitness, errors: &mut Vec<String>) {
        let id = block.id();
        if self.recorded_blocks.insert(id) {
            self.core
                .write()
                .expect("seed core lock poisoned")
                .record_canonical(block);
            if let Some(dir) = &self.data_dir {
                if let Err(e) = save_block(dir, block) {
                    errors.push(format!("persist block {}: {e}", hex::encode(id)));
                }
            }
        }
        if self.recorded_witnesses.insert(id) {
            if let Err(e) = self
                .core
                .write()
                .expect("seed core lock poisoned")
                .record_witness(witness)
            {
                errors.push(format!("record witness {}: {e}", hex::encode(id)));
            }
            if let Some(dir) = &self.data_dir {
                if let Err(e) = save_witness(dir, witness) {
                    errors.push(format!("persist witness {}: {e}", hex::encode(id)));
                }
            }
        }
    }
}

/// [`AegisSource`] that resolves against the node's own archive first,
/// then the configured seeds — the anchor-watcher's body-resolution
/// order (a commitment to a block we already hold needs no fetch).
struct LocalFirstAegis<'a> {
    core: &'a RwLock<SeedCore>,
    seeds: Option<&'a RestAegisSource>,
}

impl AegisSource for LocalFirstAegis<'_> {
    fn lookup(&self, aegis_id: &Id) -> AegisLookup {
        let local = self
            .core
            .read()
            .expect("seed core lock poisoned")
            .lookup(aegis_id);
        if !matches!(local, AegisLookup::Unknown) {
            return local;
        }
        match self.seeds {
            Some(seeds) => seeds.lookup(aegis_id),
            None => AegisLookup::Unknown,
        }
    }
}

/// [`SeedFetch`]/[`AegisSource`] pass-through that records every
/// witness a sync pass fetched, so the node can persist (and re-serve)
/// exactly what the fork choice verified.
struct TeeSeeds<'a> {
    inner: &'a RestAegisSource,
    seen: RefCell<Vec<ShareWitness>>,
}

impl<'a> TeeSeeds<'a> {
    fn new(inner: &'a RestAegisSource) -> Self {
        TeeSeeds {
            inner,
            seen: RefCell::new(Vec::new()),
        }
    }

    fn into_seen(self) -> Vec<ShareWitness> {
        self.seen.into_inner()
    }
}

impl SeedFetch for TeeSeeds<'_> {
    type Error = FetchError;

    fn tips(&self) -> Result<Vec<SeedTips>, Self::Error> {
        self.inner.tips()
    }

    fn chain_page(&self, from_height: u64, limit: usize) -> Result<Vec<Id>, Self::Error> {
        self.inner.chain_page(from_height, limit)
    }

    fn witness(&self, id: &Id) -> Result<Option<ShareWitness>, Self::Error> {
        let witness = self.inner.witness(id)?;
        if let Some(w) = &witness {
            self.seen.borrow_mut().push(w.clone());
        }
        Ok(witness)
    }

    fn bodies(&self, ids: &[Id]) -> Result<Vec<Option<Block>>, Self::Error> {
        self.inner.bodies(ids)
    }
}

impl AegisSource for TeeSeeds<'_> {
    fn lookup(&self, aegis_id: &Id) -> AegisLookup {
        self.inner.lookup(aegis_id)
    }
}

/// Build the SYNTHETIC Ergo header the dev producer grinds: version 3
/// (Autolykos v2 solution layout), placeholder linkage/roots, and an
/// extension holding exactly the [`aegis_mm_extension_field`]
/// commitment. This is a dev-network stand-in for a real merge-mined
/// Ergo candidate — it can never pass the real Ergo PoW gate
/// ([`Follower::apply_header`]) and is only accepted through the
/// share path at the (easy) Aegis target.
fn synthetic_dev_ergo_header(extension_root_bytes: [u8; 32], block: &Block) -> ErgoHeader {
    // The header's own `n_bits` declares a mainnet-scale (2^100) Ergo
    // difficulty the ground nonce can never clear — the real
    // merge-mining shape (Ergo target ≪ Aegis target): the share
    // clears only the Aegis target, and this header can never pass
    // the real Ergo PoW gate (`Follower::apply_header`).
    let hard_ergo_nbits = ergo_ser::difficulty::encode_compact_bits(&(BigUint::from(1u8) << 100));
    ErgoHeader {
        version: 3,
        parent_id: ModifierId::from_bytes(*b"aegis-dev-synthetic-ergo-parent!"),
        ad_proofs_root: Digest32::ZERO,
        transactions_root: Digest32::ZERO,
        state_root: ADDigest::from_bytes([0u8; 33]),
        timestamp: block.header.timestamp_ms,
        extension_root: Digest32::from_bytes(extension_root_bytes),
        n_bits: hard_ergo_nbits,
        height: u32::try_from(block.header.height).unwrap_or(u32::MAX),
        votes: [0u8; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes(DEV_MINER_PK),
            nonce: [0u8; 8],
        },
    }
}

/// Grind a dev aux-PoW share for `block`: a synthetic Ergo header
/// committing the block id in its extension, with an Autolykos-v2
/// nonce whose hit clears the **Aegis** target from the block's
/// DAA-pinned `sc_nbits`. Real work at dev difficulty; dev-network
/// only (see the module doc). The result is still passed through
/// [`ShareWitness::verify`] by the caller — the grind is never
/// self-trusted. Crate-visible so sibling modules' tests can mint
/// realistic witnesses.
pub(crate) fn grind_dev_witness(block: &Block) -> Result<ShareWitness, String> {
    let field = aegis_mm_extension_field(block.id());
    let pairs: [(&[u8], &[u8]); 1] = [(&field.key[..], &field.value[..])];
    let mut ergo_header = synthetic_dev_ergo_header(extension_root(&pairs), block);
    let msg = blake2b256(
        &serialize_header_without_pow(&ergo_header)
            .map_err(|e| format!("synthetic header serialize: {e}"))?,
    );
    let target = get_target(block.header.sc_nbits);
    if target == BigUint::ZERO {
        return Err(format!(
            "sc_nbits {:#010x} decodes to a zero target",
            block.header.sc_nbits
        ));
    }
    let nonce = (0..DEV_GRIND_MAX_TRIES)
        .map(u64::to_be_bytes)
        .find(|n| check_pow_v2(&msg, n, ergo_header.height, ergo_header.version, &target))
        .ok_or_else(|| {
            format!(
                "no nonce cleared the dev target within {DEV_GRIND_MAX_TRIES} tries \
                 (sc_nbits {:#010x})",
                block.header.sc_nbits
            )
        })?;
    ergo_header.solution = AutolykosSolution::V2 {
        pk: GroupElement::from_bytes(DEV_MINER_PK),
        nonce,
    };
    let proof = extension_field_proof(std::slice::from_ref(&field), 0)
        .ok_or("single-leaf proof must build")?;
    Ok(ShareWitness {
        ergo_header,
        field,
        proof,
        aegis_block_bytes: block.bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;

    // ----- helpers -----

    const T_MS: u64 = 15_000;

    fn dev_block() -> Block {
        let chain = Chain::new(Network::Dev, PowMode::DevStub, ProofMode::DevStub);
        chain
            .produce_next(BlockBody::default(), chain.tip().timestamp_ms + T_MS)
            .expect("block produces")
    }

    // ----- happy path -----

    #[test]
    fn dev_grind_produces_witness_the_real_verifier_accepts() {
        let block = dev_block();
        let witness = grind_dev_witness(&block).expect("dev target grinds");
        let daa = DaaParams::for_network(Network::Dev);
        let ctx = ShareContext {
            follower_tip_height: witness.ergo_header.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[(
                crate::genesis::genesis_header(Network::Dev).timestamp_ms,
                crate::genesis::genesis_header(Network::Dev).sc_nbits,
            )],
        };
        let share = witness.verify(&ctx).expect("ground share verifies");
        assert_eq!(share.aegis_id, block.id());
        assert_eq!(
            share.work,
            ergo_ser::difficulty::decode_compact_bits(block.header.sc_nbits)
        );
        assert_eq!(share.ergo_height, block.header.height as u32);
    }

    #[test]
    fn dev_witness_roundtrips_through_wire_bytes() {
        // The producer's witness must survive the seed/store codec —
        // it is what a second node fetches and what resume replays.
        let block = dev_block();
        let witness = grind_dev_witness(&block).expect("grinds");
        let bytes = witness.bytes().expect("serializes");
        let decoded = ShareWitness::from_bytes(&bytes).expect("decodes");
        assert_eq!(decoded, witness);
    }

    // ----- error paths -----

    #[test]
    fn synthetic_dev_header_never_passes_the_real_ergo_pow_gate() {
        // THE dev-gating invariant: the synthetic header must be
        // rejected by the real follower — dev shares can never leak
        // into a real-network Ergo view.
        let block = dev_block();
        let witness = grind_dev_witness(&block).expect("grinds");
        let mut follower = Follower::new(0);
        assert!(
            follower.apply_header(&witness.ergo_header).is_err(),
            "synthetic dev header must fail real Ergo PoW verification"
        );
    }

    #[test]
    fn local_first_aegis_falls_back_to_unknown_without_seeds() {
        let core = Arc::new(RwLock::new(SeedCore::new(Network::Dev)));
        let src = LocalFirstAegis {
            core: &core,
            seeds: None,
        };
        assert!(matches!(src.lookup(&[0xAB; 32]), AegisLookup::Unknown));

        // Archived body resolves locally.
        let block = dev_block();
        core.write().unwrap().record_canonical(&block);
        assert!(matches!(src.lookup(&block.id()), AegisLookup::Full(_)));
    }
}
