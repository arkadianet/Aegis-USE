//! M3 node API — a read-only HTTP/JSON surface over the running node
//! (`dev-docs/sidechain/node-api.md`) — plus the M5 explorer page. Slice 1
//! (observability + the merge-mining template) and slice 2 (mempool/submit)
//! are built; peg-in wiring (slice 3) is deferred. The **M5 explorer** — a
//! self-contained dashboard served at `/` — renders the public skeleton over
//! these endpoints (blocks, merge-mining status, the transparent pot); never
//! shielded parties or amounts.
//!
//! ## Threading
//!
//! The [`Node`](crate::node::Node) loop is single-threaded (ticks under
//! `spawn_blocking`). Rather than share the whole node across threads,
//! each tick **publishes an immutable [`NodeStatus`] snapshot** into an
//! [`ApiState`]; the API server thread only ever reads that snapshot
//! (plus the already-shared [`SeedCore`] archive for block bodies). So
//! the read path never contends with — and can never mutate — consensus
//! state. A stale-by-one-tick read is the worst case, which is correct
//! for observability.
//!
//! ## Privacy posture (node-api.md §"the privacy wrinkle")
//!
//! Every response is a **public aggregate**: tip/work/height, the
//! nullifier *digest* and count, the note-commitment tree *root* and
//! leaf count, the pot. A nullifier is a public spent-marker, so
//! `GET /nullifier/{hex}` (membership) is safe. No endpoint exposes
//! per-note data, shielded parties, or amounts.
//!
//! The transport is the same deliberately-minimal std-TCP HTTP/1.1 shim
//! as [`crate::seed::serve_http`] (one connection at a time, close after
//! response) — adequate for dev/testnet and loopback tests. The small
//! request-parsing helpers mirror that module; they are duplicated here
//! rather than shared so the proven seed server stays untouched.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use num_bigint::BigUint;

use crate::attest::AttesterContext;
use crate::mempool::{AdmissionView, AdmitError, Admitted, Mempool};
use crate::seed::{Id, SeedCore};
use crate::tx::ShieldedTransfer;

/// An immutable, public snapshot of node state, published once per tick
/// and served verbatim by the API. All fields are public aggregates.
#[derive(Debug)]
pub struct NodeStatus {
    pub network_name: &'static str,
    /// Canonical tip (fork-choice verdict).
    pub canonical_tip: Id,
    pub canonical_height: u64,
    pub tip_timestamp_ms: u64,
    /// Target for the *next* block (DAA), i.e. the `sc_nbits` a miner's
    /// candidate must carry.
    pub next_sc_nbits: u32,
    /// Median-time-past of the tip — the floor for the next timestamp.
    pub median_time_past: u64,
    pub cumulative_work: BigUint,
    /// §7 hostile-pending weight (shares without validated bodies).
    pub pending_hostile_work: BigUint,
    pub ergo_tip_height: Option<u32>,
    pub tip_is_final: bool,
    pub l_final: u64,
    // ----- shielded state aggregates -----
    pub pot: u64,
    pub nullifier_digest: [u8; 32],
    pub cm_tree_root: [u8; 32],
    pub leaf_count: usize,
    /// Spent-nullifier set for membership queries. `Arc` so a tick that
    /// does not change the tip re-publishes without cloning the set.
    pub nullifiers: Arc<BTreeSet<[u8; 32]>>,
    /// Pending transfers admitted to the mempool (slice 2 fills this; 0
    /// until then).
    pub mempool_size: usize,
    /// Wire bytes of the mempool transfers a candidate would include,
    /// in order (slice 2 fills this; empty until then).
    pub mempool_txs: Arc<Vec<Vec<u8>>>,
}

/// Shared handle the API server reads and the node writes. Cheap to
/// clone (all `Arc`).
#[derive(Clone)]
pub struct ApiState {
    status: Arc<RwLock<Arc<NodeStatus>>>,
    core: Arc<RwLock<SeedCore>>,
    /// Pending transfers (shared with the node's producer).
    mempool: Arc<RwLock<Mempool>>,
    /// Admission snapshot (spend anchor + spent set + fee), republished
    /// by the node on each tip change.
    admission: Arc<RwLock<Arc<AdmissionView>>>,
    /// This node's attester identity, if the operator configured one.
    /// `None` on a plain (non-attester) node — `/attest/tip` 404s.
    attester: Option<Arc<AttesterContext>>,
}

impl ApiState {
    /// Create the shared state from an initial snapshot, the node's
    /// archive (block bodies), the shared mempool, and the initial
    /// admission view.
    pub fn new(
        initial: NodeStatus,
        core: Arc<RwLock<SeedCore>>,
        mempool: Arc<RwLock<Mempool>>,
        admission: AdmissionView,
    ) -> Self {
        ApiState {
            status: Arc::new(RwLock::new(Arc::new(initial))),
            core,
            mempool,
            admission: Arc::new(RwLock::new(Arc::new(admission))),
            attester: None,
        }
    }

    /// Attach this node's attester identity, enabling `/attest/tip`.
    pub fn with_attester(mut self, ctx: AttesterContext) -> Self {
        self.attester = Some(Arc::new(ctx));
        self
    }

    /// Replace the published snapshot (called once per tick).
    pub fn publish(&self, status: NodeStatus) {
        *self.status.write().expect("api status lock poisoned") = Arc::new(status);
    }

    /// Replace the admission view (called by the node on a tip change).
    pub fn publish_admission(&self, view: AdmissionView) {
        *self.admission.write().expect("api admission lock poisoned") = Arc::new(view);
    }

    fn snapshot(&self) -> Arc<NodeStatus> {
        Arc::clone(&self.status.read().expect("api status lock poisoned"))
    }

    /// Admit a decoded transfer against the current admission view.
    fn submit(&self, tx: ShieldedTransfer) -> Result<Admitted, AdmitError> {
        let view = Arc::clone(&self.admission.read().expect("api admission lock poisoned"));
        self.mempool
            .write()
            .expect("mempool lock poisoned")
            .admit(tx, &view)
    }

    fn mempool_len(&self) -> usize {
        self.mempool.read().expect("mempool lock poisoned").len()
    }
}

/// Render `status` as the `/tip` document.
fn tip_json(s: &NodeStatus) -> serde_json::Value {
    serde_json::json!({
        "network": s.network_name,
        "height": s.canonical_height,
        "id": hex::encode(s.canonical_tip),
        "timestamp_ms": s.tip_timestamp_ms,
        "cumulative_work": s.cumulative_work.to_string(),
        "is_final": s.tip_is_final,
    })
}

/// Render `status` as the `/state` document (public aggregates only).
fn state_json(s: &NodeStatus) -> serde_json::Value {
    serde_json::json!({
        "height": s.canonical_height,
        "pot": s.pot,
        "nullifier_count": s.nullifiers.len(),
        "nullifier_digest": hex::encode(s.nullifier_digest),
        "cm_tree_root": hex::encode(s.cm_tree_root),
        "leaf_count": s.leaf_count,
    })
}

/// Render `status` as the `/mm/status` document.
fn mm_status_json(s: &NodeStatus) -> serde_json::Value {
    serde_json::json!({
        "canonical_tip": hex::encode(s.canonical_tip),
        "canonical_height": s.canonical_height,
        "cumulative_work": s.cumulative_work.to_string(),
        "pending_hostile_work": s.pending_hostile_work.to_string(),
        "ergo_tip_height": s.ergo_tip_height,
        "tip_is_final": s.tip_is_final,
        "l_final": s.l_final,
    })
}

/// Render the `/mm/commitment` mining template.
///
/// A miner/integration builds the next Aegis candidate from this
/// (adding its own coinbase note), computes the candidate id, and embeds
/// that id as the `AEGIS_MM_KEY` extension commitment — see
/// `dev-docs/sidechain/ergo-integration.md`. The node deliberately does
/// not assemble the candidate itself: that would require the miner's
/// reward key, which a read-only API must not hold.
fn mm_commitment_json(s: &NodeStatus) -> serde_json::Value {
    serde_json::json!({
        "prev_id": hex::encode(s.canonical_tip),
        "height": s.canonical_height + 1,
        "sc_nbits": s.next_sc_nbits,
        "min_timestamp_ms": s.median_time_past + 1,
        "tx_count": s.mempool_txs.len(),
        "txs": s.mempool_txs.iter().map(hex::encode).collect::<Vec<_>>(),
    })
}

pub use serve::ApiServer;

/// The read-only HTTP shim. Mirrors [`crate::seed::serve_http`]'s
/// std-TCP transport; only the routing table differs.
mod serve {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use super::{mm_commitment_json, mm_status_json, state_json, tip_json, ApiState, BTreeSet};
    use crate::block::Block;
    use crate::mempool::AdmitError;
    use crate::seed::Id;
    use crate::tx::ShieldedTransfer;
    use aegis_spec::MAX_PROOF_BYTES;

    const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;
    /// POST body cap: a full transfer wire (proof + fixed fields + slack).
    const MAX_POST_BODY_BYTES: usize = MAX_PROOF_BYTES + 4 * 1024;
    const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

    /// A running API server; shuts down (and joins its thread) on drop.
    #[derive(Debug)]
    pub struct ApiServer {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    impl ApiServer {
        /// Bind `bind_addr` (e.g. `127.0.0.1:0`) and serve `state`.
        pub fn spawn(bind_addr: &str, state: ApiState) -> std::io::Result<Self> {
            let listener = TcpListener::bind(bind_addr)?;
            let addr = listener.local_addr()?;
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let handle = std::thread::spawn(move || {
                for conn in listener.incoming() {
                    if thread_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = conn else { continue };
                    if let Err(e) = handle_connection(stream, &state) {
                        tracing::debug!(error = %e, "api connection failed");
                    }
                }
            });
            Ok(ApiServer {
                addr,
                stop,
                handle: Some(handle),
            })
        }

        /// The bound address (useful with port 0).
        pub fn local_addr(&self) -> SocketAddr {
            self.addr
        }

        /// `http://…` base URL.
        pub fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }
    }

    impl Drop for ApiServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.addr);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn handle_connection(mut stream: TcpStream, state: &ApiState) -> std::io::Result<()> {
        stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
        let (head, rest) = match read_head(&mut stream) {
            Ok(parts) => parts,
            Err(_) => return respond(&mut stream, 400, b"bad request"),
        };
        let Some((method, target, content_length)) = parse_head(&head) else {
            return respond(&mut stream, 400, b"bad request");
        };
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, q),
            None => (target.as_str(), ""),
        };

        // The only mutating route: submit a shielded transfer.
        if method == "POST" && path == "/aegis/v1/tx" {
            return submit_tx(&mut stream, state, content_length, rest);
        }
        if method != "GET" {
            return respond(&mut stream, 405, b"method not allowed");
        }
        let snap = state.snapshot();
        match path {
            // ----- explorer (M5): the node-served public dashboard -----
            "/" | "/explorer" => html(&mut stream, EXPLORER_HTML),
            "/aegis/v1/tip" => json(&mut stream, &tip_json(&snap)),
            "/aegis/v1/state" => json(&mut stream, &state_json(&snap)),
            "/aegis/v1/mm/status" => json(&mut stream, &mm_status_json(&snap)),
            "/aegis/v1/mm/commitment" => json(&mut stream, &mm_commitment_json(&snap)),
            "/aegis/v1/attest/tip" => match &state.attester {
                Some(ctx) => json(
                    &mut stream,
                    &crate::attest::tip_attestation_json(ctx, &snap),
                ),
                None => respond(&mut stream, 404, b"node is not an attester"),
            },
            "/aegis/v1/mempool" => json(
                &mut stream,
                &serde_json::json!({ "size": state.mempool_len() }),
            ),
            "/aegis/v1/blocks" => blocks_list(&mut stream, query, state),
            p if p.starts_with("/aegis/v1/blocks/") => {
                block_detail(&mut stream, &p["/aegis/v1/blocks/".len()..], state)
            }
            p if p.starts_with("/aegis/v1/nullifier/") => nullifier(
                &mut stream,
                &p["/aegis/v1/nullifier/".len()..],
                &snap.nullifiers,
            ),
            p if p.starts_with("/aegis/v1/block/at/") => {
                block_at(&mut stream, &p["/aegis/v1/block/at/".len()..], state)
            }
            p if p.starts_with("/aegis/v1/block/") => {
                block_by_id(&mut stream, &p["/aegis/v1/block/".len()..], state)
            }
            _ => respond(&mut stream, 404, b"not found"),
        }
    }

    /// The self-contained explorer page (inline CSS + vanilla JS; fetches the
    /// `/aegis/v1` endpoints same-origin, so no CORS and no build step).
    const EXPLORER_HTML: &str = include_str!("explorer.html");

    /// Public JSON summary of one decoded block (header aggregates + tx count;
    /// never per-note data). `detail` adds the full header commitment fields.
    fn block_summary(block: &Block, detail: bool) -> serde_json::Value {
        let h = &block.header;
        let mut v = serde_json::json!({
            "height": h.height,
            "id": hex::encode(block.id()),
            "timestamp_ms": h.timestamp_ms,
            "tx_count": block.body.transfers.len(),
            "has_coinbase": block.coinbase.is_some(),
        });
        if detail {
            v["prev_id"] = hex::encode(h.prev_id).into();
            v["tx_root"] = hex::encode(h.tx_root).into();
            v["cm_tree_root"] = hex::encode(h.cm_tree_root).into();
            v["nullifier_digest"] = hex::encode(h.nullifier_digest).into();
            v["pot_balance"] = h.pot_balance.into();
            v["sc_nbits"] = h.sc_nbits.into();
        }
        v
    }

    /// `GET /aegis/v1/blocks?from=&limit=` — recent block summaries, newest
    /// first. Defaults to the latest `limit` (≤ 100, default 20) blocks.
    fn blocks_list(stream: &mut TcpStream, query: &str, state: &ApiState) -> std::io::Result<()> {
        let limit = query_param(query, "limit")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(20)
            .clamp(1, 100);
        let core = state.core.read().expect("seed core lock poisoned");
        let tip = core.height();
        let from = query_param(query, "from")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or_else(|| tip.saturating_sub(limit - 1).max(1));
        let mut blocks: Vec<serde_json::Value> = core
            .chain_page(from, limit as usize)
            .iter()
            .filter_map(|id| core.body_bytes(id))
            .filter_map(|bytes| Block::from_bytes(bytes).ok())
            .map(|block| block_summary(&block, false))
            .collect();
        blocks.reverse(); // newest first
        json(
            stream,
            &serde_json::json!({ "tip_height": tip, "from": from, "blocks": blocks }),
        )
    }

    /// `GET /aegis/v1/blocks/{id}` — full public summary of one block.
    fn block_detail(stream: &mut TcpStream, id_hex: &str, state: &ApiState) -> std::io::Result<()> {
        let Some(id) = parse_id_hex(id_hex) else {
            return respond(stream, 400, b"bad id");
        };
        let core = state.core.read().expect("seed core lock poisoned");
        match core.body_bytes(&id).and_then(|b| Block::from_bytes(b).ok()) {
            Some(block) => json(stream, &block_summary(&block, true)),
            None => respond(stream, 404, b"don't have"),
        }
    }

    fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
        query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v)
    }

    fn nullifier(
        stream: &mut TcpStream,
        hex_str: &str,
        set: &BTreeSet<[u8; 32]>,
    ) -> std::io::Result<()> {
        let Some(nf) = parse_id_hex(hex_str) else {
            return respond(stream, 400, b"bad nullifier");
        };
        json(
            stream,
            &serde_json::json!({ "nullifier": hex::encode(nf), "spent": set.contains(&nf) }),
        )
    }

    fn block_by_id(stream: &mut TcpStream, hex_str: &str, state: &ApiState) -> std::io::Result<()> {
        let Some(id) = parse_id_hex(hex_str) else {
            return respond(stream, 400, b"bad id");
        };
        let core = state.core.read().expect("seed core lock poisoned");
        match core.body_bytes(&id) {
            Some(bytes) => octet(stream, bytes),
            None => respond(stream, 404, b"don't have"),
        }
    }

    fn block_at(stream: &mut TcpStream, height_str: &str, state: &ApiState) -> std::io::Result<()> {
        let Ok(height) = height_str.parse::<u64>() else {
            return respond(stream, 400, b"bad height");
        };
        let core = state.core.read().expect("seed core lock poisoned");
        // chain_page returns canonical ids starting at `height`.
        let Some(id) = core.chain_page(height, 1).first().copied() else {
            return respond(stream, 404, b"no block at height");
        };
        match core.body_bytes(&id) {
            Some(bytes) => octet(stream, bytes),
            None => respond(stream, 404, b"don't have"),
        }
    }

    /// `POST /aegis/v1/tx`: decode a wire [`ShieldedTransfer`] and admit
    /// it to the mempool. Status: 200 (new or idempotent duplicate), 400
    /// (bad wire), 409 (nullifier spent/conflict or no anchor), 422
    /// (invalid proof), 503 (mempool full).
    fn submit_tx(
        stream: &mut TcpStream,
        state: &ApiState,
        content_length: Option<usize>,
        mut body: Vec<u8>,
    ) -> std::io::Result<()> {
        let Some(len) = content_length else {
            return respond(stream, 400, b"missing content-length");
        };
        if len > MAX_POST_BODY_BYTES {
            return respond(stream, 400, b"transfer too large");
        }
        if body.len() < len {
            let mut more = vec![0u8; len - body.len()];
            if stream.read_exact(&mut more).is_err() {
                return respond(stream, 400, b"truncated body");
            }
            body.extend_from_slice(&more);
        }
        let tx = match ShieldedTransfer::from_bytes(&body[..len]) {
            Ok(tx) => tx,
            Err(_) => return respond(stream, 400, b"malformed transfer"),
        };
        match state.submit(tx) {
            Ok(outcome) => {
                let kind = if outcome.is_new() { "new" } else { "duplicate" };
                json(
                    stream,
                    &serde_json::json!({ "admitted": kind, "id": hex::encode(outcome.id()) }),
                )
            }
            Err(e) => {
                let code = match e {
                    AdmitError::Invalid(_) => 422,
                    AdmitError::Full => 503,
                    AdmitError::AlreadySpent | AdmitError::Conflict | AdmitError::NoAnchor => 409,
                };
                respond(stream, code, e.to_string().as_bytes())
            }
        }
    }

    // ----- transport (mirrors seed::serve_http) -----

    /// Read to the end of the request head; returns (head, any body
    /// bytes already read past it).
    fn read_head(stream: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let rest = buf.split_off(pos + 4);
                return Ok((buf, rest));
            }
            if buf.len() > MAX_REQUEST_HEAD_BYTES {
                return Err(std::io::Error::other("request head too large"));
            }
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                return Err(std::io::Error::other("connection closed mid-head"));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn parse_head(head: &[u8]) -> Option<(String, String, Option<usize>)> {
        let head = std::str::from_utf8(head).ok()?;
        let mut lines = head.split("\r\n");
        let mut request_line = lines.next()?.split(' ');
        let method = request_line.next()?.to_string();
        let target = request_line.next()?.to_string();
        let mut content_length = None;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse::<usize>().ok();
                }
            }
        }
        Some((method, target, content_length))
    }

    fn parse_id_hex(s: &str) -> Option<Id> {
        let bytes = hex::decode(s).ok()?;
        bytes.try_into().ok()
    }

    fn json(stream: &mut TcpStream, value: &serde_json::Value) -> std::io::Result<()> {
        write_response(
            stream,
            200,
            "application/json",
            value.to_string().as_bytes(),
        )
    }

    fn octet(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
        write_response(stream, 200, "application/octet-stream", body)
    }

    fn html(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
        write_response(stream, 200, "text/html; charset=utf-8", body.as_bytes())
    }

    fn respond(stream: &mut TcpStream, status: u16, body: &[u8]) -> std::io::Result<()> {
        write_response(stream, status, "text/plain", body)
    }

    fn write_response(
        stream: &mut TcpStream,
        status: u16,
        content_type: &str,
        body: &[u8],
    ) -> std::io::Result<()> {
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            422 => "Unprocessable Entity",
            503 => "Service Unavailable",
            _ => "Error",
        };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len(),
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::SeedCore;
    use aegis_spec::Network;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    // ----- helpers -----

    fn sample_status() -> NodeStatus {
        let mut nfs = BTreeSet::new();
        nfs.insert([0x11; 32]);
        NodeStatus {
            network_name: "aegis-dev",
            canonical_tip: [0xAB; 32],
            canonical_height: 7,
            tip_timestamp_ms: 1_700_000_000_000,
            next_sc_nbits: 0x0203_2400,
            median_time_past: 1_699_999_000_000,
            cumulative_work: BigUint::from(7000u32),
            pending_hostile_work: BigUint::ZERO,
            ergo_tip_height: Some(442_800),
            tip_is_final: false,
            l_final: 4,
            pot: 123,
            nullifier_digest: [0x22; 32],
            cm_tree_root: [0x33; 32],
            leaf_count: 4,
            nullifiers: Arc::new(nfs),
            mempool_size: 0,
            mempool_txs: Arc::new(Vec::new()),
        }
    }

    const FEE: u64 = 10; // dev sc_tx_fee

    fn empty_admission() -> AdmissionView {
        AdmissionView::new(Arc::new(Vec::new()), Arc::new(BTreeSet::new()), FEE)
    }

    fn state() -> ApiState {
        let core = Arc::new(RwLock::new(SeedCore::new(Network::Dev)));
        ApiState::new(
            sample_status(),
            core,
            Arc::new(RwLock::new(Mempool::new())),
            empty_admission(),
        )
    }

    /// A valid wire transfer + an admission view whose anchor it spends.
    fn transfer_scene() -> (ApiState, Vec<u8>) {
        use aegis_crypto::note::{note_cm_bytes, EvenScalar};
        use aegis_crypto::nullifier::OddScalar;
        use aegis_crypto::spend::{
            consensus_note_commitment, consensus_note_tag, prove_transfer, NoteOpening,
            TransferOutput,
        };
        use aegis_crypto::tree::build_tree;
        use aegis_spec::{EPK_BYTES, NOTE_CT_BYTES, NOTE_OUT_CT_BYTES};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let opening = |value: u64, seed: u64, leaf_index: usize| NoteOpening {
            value,
            blinding: EvenScalar::from(seed),
            leaf_index,
            nk: OddScalar::from(seed + 1),
            rho: OddScalar::from(seed + 2),
            r_key: OddScalar::from(seed + 3),
        };
        let leaf = |o: &NoteOpening| {
            consensus_note_commitment(
                o.value,
                consensus_note_tag(o.nk, o.rho, o.r_key),
                o.blinding,
            )
        };
        let inputs = [opening(1_000, 0x21, 0), opening(500, 0x22, 1)];
        let leaves = vec![
            leaf(&inputs[0]),
            leaf(&inputs[1]),
            leaf(&opening(0, 0x23, 2)),
        ];
        let anchor = build_tree(&leaves);
        let outputs = [
            TransferOutput {
                value: 1_500 - FEE - 100,
                tag: EvenScalar::from(0x31u64),
                blinding: EvenScalar::from(0x41u64),
            },
            TransferOutput {
                value: 100,
                tag: EvenScalar::from(0x32u64),
                blinding: EvenScalar::from(0x42u64),
            },
        ];
        let proof = prove_transfer(
            &anchor,
            &inputs,
            &outputs,
            FEE,
            &mut StdRng::seed_from_u64(1),
        )
        .unwrap();
        let mut proof_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes).unwrap();
        let out_wire = |i: usize| crate::tx::ShieldedOutput {
            note_cm: note_cm_bytes(&proof.output_cms[i]),
            epk: [0u8; EPK_BYTES],
            ct: [0u8; NOTE_CT_BYTES],
            out_ct: [0u8; NOTE_OUT_CT_BYTES],
        };
        let tx = ShieldedTransfer {
            nullifiers: proof.nullifiers(),
            outputs: [out_wire(0), out_wire(1)],
            proof: proof_bytes,
        };
        let core = Arc::new(RwLock::new(SeedCore::new(Network::Dev)));
        let admission = AdmissionView::new(Arc::new(leaves), Arc::new(BTreeSet::new()), FEE);
        let state = ApiState::new(
            sample_status(),
            core,
            Arc::new(RwLock::new(Mempool::new())),
            admission,
        );
        (state, tx.bytes())
    }

    /// Issue one GET and return `(status_code, body)`.
    fn get(base: &str, path: &str) -> (u16, String) {
        let addr = base.trim_start_matches("http://");
        let mut s = TcpStream::connect(addr).expect("connect");
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).expect("read");
        let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
        let code = head
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (code, body.to_string())
    }

    /// POST `body` and return `(status_code, response_body)`.
    fn post(base: &str, path: &str, body: &[u8]) -> (u16, String) {
        let addr = base.trim_start_matches("http://");
        let mut s = TcpStream::connect(addr).expect("connect");
        write!(
            s,
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        s.write_all(body).unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).expect("read");
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (head, resp) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
        let code = head
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (code, resp.to_string())
    }

    // ----- happy path -----

    #[test]
    fn tip_endpoint_reports_canonical_tip() {
        let server = ApiServer::spawn("127.0.0.1:0", state()).expect("spawn");
        let (code, body) = get(&server.base_url(), "/aegis/v1/tip");
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["height"], 7);
        assert_eq!(v["id"], hex::encode([0xAB; 32]));
        assert_eq!(v["cumulative_work"], "7000");
        assert_eq!(v["is_final"], false);
    }

    #[test]
    fn attest_tip_serves_a_verifiable_attestation() {
        use aegis_attest::{Attestation, AttesterKey, AttesterSet, PublicKey, Purpose};
        // A 2-of-3 federation; this node holds member #1's key.
        let keys: Vec<AttesterKey> = (1u8..=3)
            .map(|s| AttesterKey::from_secret_bytes(&[s; 32]).unwrap())
            .collect();
        let set = AttesterSet::new(keys.iter().map(|k| k.public()).collect(), 2).unwrap();
        let ctx = crate::attest::AttesterContext::new(keys[0].clone(), set.clone()).unwrap();
        let server = ApiServer::spawn("127.0.0.1:0", state().with_attester(ctx)).expect("spawn");

        let (code, body) = get(&server.base_url(), "/aegis/v1/attest/tip");
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["purpose"], "tip");
        assert_eq!(v["height"], 7);
        assert_eq!(v["k"], 2);
        assert_eq!(v["n"], 3);

        // Reconstruct the attestation and verify it against the federation.
        let payload = hex::decode(v["payload"].as_str().unwrap()).unwrap();
        let signer_bytes: [u8; 33] = hex::decode(v["signer"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sig: [u8; 64] = hex::decode(v["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let att = Attestation {
            signer: PublicKey::from_bytes(&signer_bytes).unwrap(),
            sig,
        };
        assert!(set.verify(Purpose::Tip, &payload, &att));
        // The same signature must not verify a different tip statement.
        assert!(!set.verify(Purpose::Tip, b"some other tip", &att));
    }

    #[test]
    fn attest_tip_404_on_a_non_attester_node() {
        let server = ApiServer::spawn("127.0.0.1:0", state()).expect("spawn");
        let (code, _) = get(&server.base_url(), "/aegis/v1/attest/tip");
        assert_eq!(code, 404);
    }

    #[test]
    fn state_endpoint_reports_public_aggregates_only() {
        let server = ApiServer::spawn("127.0.0.1:0", state()).expect("spawn");
        let (code, body) = get(&server.base_url(), "/aegis/v1/state");
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["pot"], 123);
        assert_eq!(v["nullifier_count"], 1);
        assert_eq!(v["leaf_count"], 4);
        assert_eq!(v["cm_tree_root"], hex::encode([0x33; 32]));
        // No per-note fields leak.
        assert!(v.get("cm_leaves").is_none());
        assert!(v.get("notes").is_none());
    }

    #[test]
    fn mm_commitment_is_a_mining_template_on_the_next_height() {
        let server = ApiServer::spawn("127.0.0.1:0", state()).expect("spawn");
        let (code, body) = get(&server.base_url(), "/aegis/v1/mm/commitment");
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["prev_id"], hex::encode([0xAB; 32]));
        assert_eq!(v["height"], 8); // tip 7 + 1
        assert_eq!(v["sc_nbits"], 0x0203_2400u32);
        assert_eq!(v["min_timestamp_ms"], 1_699_999_000_001u64);
        assert_eq!(v["tx_count"], 0);
    }

    #[test]
    fn mm_status_carries_the_merge_mining_telemetry() {
        let server = ApiServer::spawn("127.0.0.1:0", state()).expect("spawn");
        let (code, body) = get(&server.base_url(), "/aegis/v1/mm/status");
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["ergo_tip_height"], 442_800);
        assert_eq!(v["pending_hostile_work"], "0");
        assert_eq!(v["l_final"], 4);
    }

    #[test]
    fn nullifier_membership_reports_spent_and_unspent() {
        let server = ApiServer::spawn("127.0.0.1:0", state()).expect("spawn");
        let (code, spent) = get(
            &server.base_url(),
            &format!("/aegis/v1/nullifier/{}", hex::encode([0x11; 32])),
        );
        assert_eq!(code, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&spent).unwrap()["spent"],
            true
        );
        let (_, unspent) = get(
            &server.base_url(),
            &format!("/aegis/v1/nullifier/{}", hex::encode([0x99; 32])),
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&unspent).unwrap()["spent"],
            false
        );
    }

    // ----- error paths -----

    #[test]
    fn unknown_route_404s_and_bad_nullifier_400s() {
        let server = ApiServer::spawn("127.0.0.1:0", state()).expect("spawn");
        assert_eq!(get(&server.base_url(), "/aegis/v1/nope").0, 404);
        assert_eq!(get(&server.base_url(), "/aegis/v1/nullifier/zz").0, 400);
        assert_eq!(get(&server.base_url(), "/aegis/v1/block/at/notnum").0, 400);
    }

    // ----- submit (slice 2) -----

    #[test]
    fn submit_admits_a_valid_transfer_and_mempool_reflects_it() {
        let (st, tx_bytes) = transfer_scene();
        let server = ApiServer::spawn("127.0.0.1:0", st).expect("spawn");
        let (code, body) = post(&server.base_url(), "/aegis/v1/tx", &tx_bytes);
        assert_eq!(code, 200, "body={body}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["admitted"],
            "new"
        );
        let (_, mp) = get(&server.base_url(), "/aegis/v1/mempool");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&mp).unwrap()["size"],
            1
        );
    }

    #[test]
    fn submit_double_is_idempotent() {
        let (st, tx_bytes) = transfer_scene();
        let server = ApiServer::spawn("127.0.0.1:0", st).expect("spawn");
        assert_eq!(post(&server.base_url(), "/aegis/v1/tx", &tx_bytes).0, 200);
        let (code, body) = post(&server.base_url(), "/aegis/v1/tx", &tx_bytes);
        assert_eq!(code, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["admitted"],
            "duplicate"
        );
    }

    #[test]
    fn submit_malformed_body_400s_and_invalid_proof_422s() {
        let (st, mut tx_bytes) = transfer_scene();
        let server = ApiServer::spawn("127.0.0.1:0", st).expect("spawn");
        // Garbage bytes fail to decode → 400.
        assert_eq!(post(&server.base_url(), "/aegis/v1/tx", b"not a tx").0, 400);
        // A structurally-decodable transfer with a corrupted proof tail
        // decodes but fails verification → 422.
        let n = tx_bytes.len();
        tx_bytes[n - 1] ^= 0xFF;
        assert_eq!(post(&server.base_url(), "/aegis/v1/tx", &tx_bytes).0, 422);
    }

    #[test]
    fn submit_without_an_anchor_409s() {
        let (st, tx_bytes) = transfer_scene();
        st.publish_admission(empty_admission()); // drop the anchor
        let server = ApiServer::spawn("127.0.0.1:0", st).expect("spawn");
        assert_eq!(post(&server.base_url(), "/aegis/v1/tx", &tx_bytes).0, 409);
    }

    // ----- explorer (M5) -----

    /// An `ApiState` whose archive holds `n` produced dev blocks (heights
    /// 1..=n), plus the block ids in height order.
    fn state_with_blocks(n: usize) -> (ApiState, Vec<[u8; 32]>) {
        use crate::block::BlockBody;
        use crate::chain::{Chain, PowMode, ProofMode};
        let mut chain = Chain::new(Network::Dev, PowMode::DevStub, ProofMode::DevStub);
        let mut core = SeedCore::new(Network::Dev);
        let mut ids = Vec::new();
        for _ in 0..n {
            let ts = chain.tip().timestamp_ms + 15_000;
            let block = chain
                .produce_next(BlockBody::default(), ts)
                .expect("produce");
            chain.try_extend(block.clone(), ts).expect("extend");
            core.record_canonical(&block);
            ids.push(block.id());
        }
        let st = ApiState::new(
            sample_status(),
            Arc::new(RwLock::new(core)),
            Arc::new(RwLock::new(Mempool::new())),
            empty_admission(),
        );
        (st, ids)
    }

    #[test]
    fn blocks_list_returns_recent_blocks_newest_first() {
        let (st, ids) = state_with_blocks(3);
        let server = ApiServer::spawn("127.0.0.1:0", st).expect("spawn");
        let (code, body) = get(&server.base_url(), "/aegis/v1/blocks");
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["tip_height"], 3);
        let blocks = v["blocks"].as_array().unwrap();
        assert_eq!(blocks.len(), 3);
        // Newest first: height 3, then 2, then 1.
        assert_eq!(blocks[0]["height"], 3);
        assert_eq!(blocks[0]["id"], hex::encode(ids[2]));
        assert_eq!(blocks[0]["tx_count"], 0);
        assert_eq!(blocks[2]["height"], 1);
        // Summary carries no per-note data.
        assert!(blocks[0].get("cm_leaves").is_none());
    }

    #[test]
    fn blocks_list_limit_is_honored() {
        let (st, _) = state_with_blocks(5);
        let server = ApiServer::spawn("127.0.0.1:0", st).expect("spawn");
        let (_, body) = get(&server.base_url(), "/aegis/v1/blocks?limit=2");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let blocks = v["blocks"].as_array().unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0]["height"], 5); // the two newest
        assert_eq!(blocks[1]["height"], 4);
    }

    #[test]
    fn block_detail_returns_header_fields() {
        let (st, ids) = state_with_blocks(2);
        let server = ApiServer::spawn("127.0.0.1:0", st).expect("spawn");
        let (code, body) = get(
            &server.base_url(),
            &format!("/aegis/v1/blocks/{}", hex::encode(ids[1])),
        );
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["height"], 2);
        assert_eq!(v["id"], hex::encode(ids[1]));
        assert!(v["prev_id"].is_string());
        assert!(v["cm_tree_root"].is_string());
        // Unknown id → 404.
        assert_eq!(
            get(
                &server.base_url(),
                &format!("/aegis/v1/blocks/{}", hex::encode([0xEE; 32]))
            )
            .0,
            404
        );
    }

    #[test]
    fn explorer_page_is_served_at_root_and_explorer() {
        let server = ApiServer::spawn("127.0.0.1:0", state()).expect("spawn");
        for path in ["/", "/explorer"] {
            let (code, body) = get(&server.base_url(), path);
            assert_eq!(code, 200, "path {path}");
            assert!(
                body.contains("Aegis Explorer"),
                "path {path} served the page"
            );
        }
    }

    #[test]
    fn publish_replaces_the_served_snapshot() {
        let st = state();
        let server = ApiServer::spawn("127.0.0.1:0", st.clone()).expect("spawn");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&get(&server.base_url(), "/aegis/v1/tip").1)
                .unwrap()["height"],
            7
        );
        let mut next = sample_status();
        next.canonical_height = 9;
        st.publish(next);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&get(&server.base_url(), "/aegis/v1/tip").1)
                .unwrap()["height"],
            9
        );
    }
}
