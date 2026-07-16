//! Seed/HTTP body-availability tier (p2p.md §3/§4 — M6b-1).
//!
//! The one job of this layer: **make bytes retrievable by id.** Two
//! content classes, both self-authenticating (p2p.md §1):
//!
//! - **Block bodies** — full [`Block`] wire bytes, authenticated by
//!   recomputing the header id from the served bytes (and the
//!   `tx_root` / `reward_claim` bindings, [`body_self_authenticates`]
//!   — the same checks `MmForkChoice::ingest_body` re-runs).
//! - **Share witnesses** — [`ShareWitness`] wire bytes; the carried
//!   Aegis block must re-hash to the requested id here, and the PoW
//!   claim is only ever admitted through [`ShareWitness::verify`]
//!   at ingestion time.
//!
//! Because every byte is checked against a hash or a PoW threshold the
//! node re-derives itself, **a seed can withhold, never forge**: seeds
//! are a liveness convenience, never a trust root. Weight comes only
//! from verified witnesses, settlement only from the node's own Ergo
//! scan (`anchor_watch`) — nothing here carries a judgment.
//!
//! Three pieces:
//!
//! - [`SeedCore`] — the serve-side archive: canonical bodies indexed
//!   from the `store.rs` block log (the append-only log IS the archive,
//!   p2p.md §6.1) plus a witness map, answering the §4.2 route
//!   semantics (`body`/`witness`/`tips`/`chain`/batched `bodies`).
//!   It implements [`SeedFetch`] (a node can sync from its own or an
//!   in-memory archive) and [`AegisSource`] (the anchor-watcher can
//!   resolve against it).
//! - [`serve_http`] — a deliberately minimal std-TCP HTTP/1.1 shim
//!   exposing a [`SeedCore`] on `/aegis/v1/*`. Read-only, no auth
//!   (public, immutable, content-addressed data); request bytes are
//!   DATA, never instructions — ids parse as hex or the request 400s.
//! - [`fetch_http`] — the client tier: [`fetch_http::RestAegisSource`]
//!   fetches by id from a list of untrusted seeds with per-seed
//!   failover, **verifying self-authentication on every fetch** —
//!   a wrong body is dropped ([`fetch_http::SeedHttpError::NotSelfAuthenticating`]),
//!   never trusted, and the next seed is tried (bodies are
//!   content-addressed; any seed with the bytes works).
//!
//! Retention (p2p.md §6.1): canonical bodies are kept forever (v1, no
//! pruning — fresh-sync replays from genesis); witnesses for ids that
//! never became canonical are dropped once the canonical chain has
//! advanced [`PENDING_WITNESS_RETENTION`] (~240) blocks past their
//! arrival — beyond the undo ring, an unactivated branch is
//! unrecoverable anyway.
//!
//! Wired into the node loop by M6c: [`crate::node`] serves its archive
//! through [`SeedServer`] (`--serve-addr`), records every accepted
//! block + verified witness into its [`SeedCore`], and fetches from
//! peers via [`fetch_http::RestAegisSource`] (`--seed-url`).
//! Push-gossip (`HAVE`/`GET` over TCP) is M6b-2.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use aegis_crypto::note::note_cm_bytes;
use aegis_spec::{Network, MAX_BLOCK_BYTES, MAX_PROOF_BYTES};
use ergo_ser::error::WriteError;

use crate::anchor_watch::{AegisLookup, AegisSource};
use crate::auxpow::{ShareWitness, WitnessDecodeError};
use crate::block::{Block, BlockDecodeError};
use crate::genesis::{genesis_header, EMPTY_REWARD_CLAIM};
use crate::store::{read_log, StoreError};

/// Aegis block id (header id).
pub type Id = [u8; 32];

/// Non-canonical witnesses are dropped once the canonical chain is this
/// many blocks past their arrival (p2p.md §6.1 — the undo-ring horizon:
/// a branch still pending after this is unrecoverable).
pub const PENDING_WITNESS_RETENTION: u64 = 240;

/// Ids answered per `tips` response (`recent`, p2p.md §4.2).
pub const TIPS_RECENT_LEN: usize = 240;

/// Ids per `chain` page (server-side cap).
pub const CHAIN_PAGE_MAX: usize = 512;

/// Ids per batched `POST /aegis/v1/bodies` request.
pub const MAX_BODIES_PER_BATCH: usize = 64;

/// Upper bound for one block's wire bytes: the body consensus cap plus
/// header/coinbase framing slack (the `store.rs` record bound).
pub const MAX_BODY_WIRE_BYTES: usize = MAX_BLOCK_BYTES + MAX_PROOF_BYTES + 1024;

/// Upper bound for one witness's wire bytes: the carried block plus the
/// Ergo header / field / merkle-proof envelope.
pub const MAX_WITNESS_WIRE_BYTES: usize = MAX_BODY_WIRE_BYTES + 4096;

/// Does `block` self-authenticate as the body of `id`? Recomputed
/// header id, `tx_root`, and coinbase `reward_claim` binding — exactly
/// the checks `MmForkChoice::ingest_body` performs before validation
/// (p2p.md §1's table). A mismatch means these BYTES are not the
/// block's body — never a verdict about the id.
pub fn body_self_authenticates(id: &Id, block: &Block) -> bool {
    if block.id() != *id {
        return false;
    }
    if block.header.tx_root != block.body.tx_root() {
        return false;
    }
    match &block.coinbase {
        None => block.header.reward_claim == EMPTY_REWARD_CLAIM,
        Some(proof) => block.header.reward_claim == note_cm_bytes(&proof.cm),
    }
}

/// A seed's claimed canonical tip — an **untrusted download hint**
/// (p2p.md §5): it costs a seed nothing to lie, so this only ever
/// schedules fetches; weight comes solely from verified witnesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedTips {
    /// Claimed canonical tip id.
    pub tip: Id,
    /// Claimed canonical height.
    pub height: u64,
    /// Ordered ids of the last ≤ [`TIPS_RECENT_LEN`] canonical blocks,
    /// oldest first.
    pub recent: Vec<Id>,
}

/// The untrusted download interface fresh-sync drives (p2p.md §5):
/// hints (`tips`/`chain_page`) plus fetch-by-id (`witness`/`bodies`).
///
/// Implementation contract: `witness`/`bodies` MUST only return items
/// whose carried block re-hashes to the requested id (the self-auth
/// drop) — a junk answer is reported as absent/error, never surfaced.
/// The consumer re-verifies everything anyway ([`ShareWitness::verify`]
/// and `ingest_body`'s self-authentication); the contract just keeps
/// junk off the schedule.
pub trait SeedFetch {
    type Error: std::error::Error + 'static;

    /// Every reachable seed's tips claim (≥ 1 entry on success; the §5
    /// cross-check compares them and fetches all claimed branches).
    fn tips(&self) -> Result<Vec<SeedTips>, Self::Error>;

    /// Ordered canonical ids from `from_height` (heights start at 1),
    /// at most `limit`. Empty when past the claimed tip.
    fn chain_page(&self, from_height: u64, limit: usize) -> Result<Vec<Id>, Self::Error>;

    /// The share witness for `id`. `Ok(None)` = no seed has it
    /// (withholding — a liveness fact, never a verdict).
    fn witness(&self, id: &Id) -> Result<Option<ShareWitness>, Self::Error>;

    /// Bodies for `ids`, position-matched; `None` per id no seed
    /// served an authentic body for.
    fn bodies(&self, ids: &[Id]) -> Result<Vec<Option<Block>>, Self::Error>;
}

/// A recorded witness: wire bytes + the canonical height at arrival
/// (the retention clock).
#[derive(Debug, Clone)]
struct StoredWitness {
    bytes: Vec<u8>,
    seen_at_height: u64,
}

/// [`SeedCore::record_witness`] failure — the witness could not be
/// keyed (its id is always RECOMPUTED from the carried block bytes,
/// never caller-claimed).
#[derive(Debug, thiserror::Error)]
pub enum RecordWitnessError {
    #[error("witness block bytes do not decode: {0}")]
    Block(#[from] BlockDecodeError),
    #[error("witness does not serialize: {0}")]
    Encode(WriteError),
}

/// [`SeedCore`]'s [`SeedFetch`] error: its own archived bytes failed to
/// decode — impossible unless the archive is corrupt.
#[derive(Debug, thiserror::Error)]
#[error("seed archive record for {} is corrupt: {detail}", hex::encode(.id))]
pub struct CorruptArchive {
    pub id: Id,
    pub detail: String,
}

/// The serve-side archive: everything a node needs to BE a seed.
///
/// Canonical bodies come from the `store.rs` block log
/// ([`SeedCore::from_store`]) or live acceptance
/// ([`SeedCore::record_canonical`]); witnesses from whoever verified
/// them ([`SeedCore::record_witness`]). All lookups are by id; the
/// canonical order backs only the `tips`/`chain` hints.
#[derive(Debug)]
pub struct SeedCore {
    genesis: Id,
    /// Canonical ids, index `i` ↔ height `i + 1` (genesis is derived
    /// from `aegis-spec`, never served).
    canonical: Vec<Id>,
    /// Block wire bytes by id — content-addressed; reorged-out bodies
    /// are retained too (keep-everything v1, p2p.md §6.1).
    bodies: BTreeMap<Id, Vec<u8>>,
    /// Witness wire bytes by (recomputed) aegis id.
    witnesses: BTreeMap<Id, StoredWitness>,
}

impl SeedCore {
    /// An empty archive for `network` (genesis derived, not stored).
    pub fn new(network: Network) -> Self {
        SeedCore {
            genesis: genesis_header(network).id(),
            canonical: Vec::new(),
            bodies: BTreeMap::new(),
            witnesses: BTreeMap::new(),
        }
    }

    /// Index the `store.rs` block log under `dir` (decode-only — the
    /// log was validated when written, and every *fetcher* re-verifies;
    /// see [`read_log`]).
    pub fn from_store(dir: &Path, network: Network) -> Result<Self, StoreError> {
        let mut core = Self::new(network);
        for block in read_log(dir)? {
            core.record_canonical(&block);
        }
        Ok(core)
    }

    /// Record an ACCEPTED block as canonical at its height. The id is
    /// recomputed, never caller-claimed. Recording at a height at or
    /// below the current tip truncates everything above it first (a
    /// reorg — the displaced bodies stay archived by id). A block more
    /// than one past the tip is archived by id but not placed in the
    /// canonical order (hints degrade; serving by id is unaffected).
    pub fn record_canonical(&mut self, block: &Block) {
        let height = block.header.height;
        if height == 0 {
            return; // genesis is derived from the spec, never recorded
        }
        let id = block.id();
        self.bodies.insert(id, block.bytes());
        let idx = (height - 1) as usize;
        if idx <= self.canonical.len() {
            self.canonical.truncate(idx);
            self.canonical.push(id);
        }
        self.prune_stale_witnesses();
    }

    /// Record a witness, keyed by the RECOMPUTED id of its carried
    /// block. Returns that id.
    pub fn record_witness(&mut self, witness: &ShareWitness) -> Result<Id, RecordWitnessError> {
        let block = Block::from_bytes(&witness.aegis_block_bytes)?;
        let bytes = witness.bytes().map_err(RecordWitnessError::Encode)?;
        let id = block.id();
        self.witnesses.insert(
            id,
            StoredWitness {
                bytes,
                seen_at_height: self.height(),
            },
        );
        Ok(id)
    }

    /// Canonical height (0 = genesis only).
    pub fn height(&self) -> u64 {
        self.canonical.len() as u64
    }

    /// Canonical tip id (genesis when empty).
    pub fn tip_id(&self) -> Id {
        self.canonical.last().copied().unwrap_or(self.genesis)
    }

    /// Archived block wire bytes for `id`, canonical or not.
    pub fn body_bytes(&self, id: &Id) -> Option<&[u8]> {
        self.bodies.get(id).map(Vec::as_slice)
    }

    /// Witness wire bytes for `id`.
    pub fn witness_bytes(&self, id: &Id) -> Option<&[u8]> {
        self.witnesses.get(id).map(|w| w.bytes.as_slice())
    }

    /// The `tips` answer (p2p.md §4.2): tip id + height + the last
    /// ≤ [`TIPS_RECENT_LEN`] canonical ids.
    pub fn tips(&self) -> SeedTips {
        let start = self.canonical.len().saturating_sub(TIPS_RECENT_LEN);
        SeedTips {
            tip: self.tip_id(),
            height: self.height(),
            recent: self.canonical[start..].to_vec(),
        }
    }

    /// Ordered canonical ids from `from_height` (heights start at 1; 0
    /// is treated as 1), at most `limit.min(CHAIN_PAGE_MAX)`.
    pub fn chain_page(&self, from_height: u64, limit: usize) -> Vec<Id> {
        let start = usize::try_from(from_height.max(1) - 1).unwrap_or(usize::MAX);
        if start >= self.canonical.len() {
            return Vec::new();
        }
        let end = start.saturating_add(limit.min(CHAIN_PAGE_MAX));
        self.canonical[start..end.min(self.canonical.len())].to_vec()
    }

    /// Drop witnesses for ids that never became canonical once the
    /// chain is [`PENDING_WITNESS_RETENTION`] past their arrival.
    fn prune_stale_witnesses(&mut self) {
        let tip = self.height();
        let Some(horizon) = tip.checked_sub(PENDING_WITNESS_RETENTION) else {
            return;
        };
        let canonical: BTreeSet<&Id> = self.canonical.iter().collect();
        self.witnesses
            .retain(|id, w| canonical.contains(id) || w.seen_at_height >= horizon);
    }
}

impl SeedFetch for SeedCore {
    type Error = CorruptArchive;

    fn tips(&self) -> Result<Vec<SeedTips>, Self::Error> {
        Ok(vec![SeedCore::tips(self)])
    }

    fn chain_page(&self, from_height: u64, limit: usize) -> Result<Vec<Id>, Self::Error> {
        Ok(SeedCore::chain_page(self, from_height, limit))
    }

    fn witness(&self, id: &Id) -> Result<Option<ShareWitness>, Self::Error> {
        let Some(bytes) = self.witness_bytes(id) else {
            return Ok(None);
        };
        let witness = ShareWitness::from_bytes(bytes).map_err(|e| CorruptArchive {
            id: *id,
            detail: e.to_string(),
        })?;
        Ok(Some(witness))
    }

    fn bodies(&self, ids: &[Id]) -> Result<Vec<Option<Block>>, Self::Error> {
        ids.iter()
            .map(|id| match self.body_bytes(id) {
                None => Ok(None),
                Some(bytes) => Block::from_bytes(bytes)
                    .map(Some)
                    .map_err(|e| CorruptArchive {
                        id: *id,
                        detail: e.to_string(),
                    }),
            })
            .collect()
    }
}

impl AegisSource for SeedCore {
    fn lookup(&self, aegis_id: &Id) -> AegisLookup {
        match self.body_bytes(aegis_id).map(Block::from_bytes) {
            Some(Ok(block)) => AegisLookup::Full(Box::new(block)),
            Some(Err(e)) => {
                tracing::warn!(id = %hex::encode(aegis_id), error = %e, "corrupt seed archive record");
                AegisLookup::Unknown
            }
            None => AegisLookup::Unknown,
        }
    }
}

/// Parse a 64-hex-char block id. `None` on anything else — request
/// content is DATA, never instructions.
fn parse_id_hex(s: &str) -> Option<Id> {
    if s.len() != 64 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// Minimal read-only HTTP/1.1 shim over a [`SeedCore`] — the M6b-1
/// seed server. Deliberately std-only (no server dependency: the
/// workspace's only HTTP dep is a client, and the M3 node API will
/// make its own transport decision); one connection at a time, close
/// after response — adequate for dev-scale seeds and loopback tests,
/// and every route's CORE logic lives in [`SeedCore`], not here.
///
/// Routes (p2p.md §4.2's HTTP mapping):
///
/// - `GET /aegis/v1/body/{id_hex}` → raw [`Block`] wire bytes / 404
/// - `GET /aegis/v1/witness/{id_hex}` → raw [`ShareWitness`] bytes / 404
/// - `GET /aegis/v1/tips` → `{"tip","height","recent":[…]}` (hex ids)
/// - `GET /aegis/v1/chain?from_height=H&tip=…` → `{"from_height","tip","ids":[…]}`
///   (`tip` accepted and ignored in v1 — pages always follow the
///   seed's current canonical order; the response echoes that tip)
/// - `POST /aegis/v1/bodies` (body: concatenated 32-byte ids, ≤
///   [`MAX_BODIES_PER_BATCH`]) → per requested id, in order:
///   `u32-LE len ‖ block bytes` (`len = 0` = don't have)
pub mod serve_http {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, RwLock};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use super::{parse_id_hex, SeedCore, CHAIN_PAGE_MAX, MAX_BODIES_PER_BATCH};

    /// Request head (request line + headers) size cap.
    const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;
    /// POST body cap: a full id batch plus slack.
    const MAX_POST_BODY_BYTES: usize = 32 * MAX_BODIES_PER_BATCH + 1024;
    /// Per-connection socket timeout.
    const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

    /// A running seed server; shuts down (and joins its thread) on drop.
    #[derive(Debug)]
    pub struct SeedServer {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    impl SeedServer {
        /// Bind `bind_addr` (e.g. `127.0.0.1:0`) and serve `core` on a
        /// background thread.
        pub fn spawn(bind_addr: &str, core: Arc<RwLock<SeedCore>>) -> std::io::Result<Self> {
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
                    if let Err(e) = handle_connection(stream, &core) {
                        tracing::debug!(error = %e, "seed connection failed");
                    }
                }
            });
            Ok(SeedServer {
                addr,
                stop,
                handle: Some(handle),
            })
        }

        /// The bound address (useful with port 0).
        pub fn local_addr(&self) -> SocketAddr {
            self.addr
        }

        /// `http://…` base URL for a fetch client.
        pub fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }
    }

    impl Drop for SeedServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            // Wake the blocking accept so the thread observes the flag.
            let _ = TcpStream::connect(self.addr);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    /// One request → one response → close. Everything read is DATA:
    /// malformed requests get a 4xx, never side effects.
    fn handle_connection(
        mut stream: TcpStream,
        core: &Arc<RwLock<SeedCore>>,
    ) -> std::io::Result<()> {
        stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
        let (head, mut rest) = match read_head(&mut stream) {
            Ok(parts) => parts,
            Err(_) => return respond(&mut stream, 400, "text/plain", b"bad request"),
        };
        let Some((method, target, content_length)) = parse_head(&head) else {
            return respond(&mut stream, 400, "text/plain", b"bad request");
        };
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, q),
            None => (target.as_str(), ""),
        };
        let core = core.read().expect("seed core lock poisoned");
        match (method.as_str(), path) {
            ("GET", p) if p.starts_with("/aegis/v1/body/") => {
                serve_item(&mut stream, &p["/aegis/v1/body/".len()..], |id| {
                    core.body_bytes(id).map(<[u8]>::to_vec)
                })
            }
            ("GET", p) if p.starts_with("/aegis/v1/witness/") => {
                serve_item(&mut stream, &p["/aegis/v1/witness/".len()..], |id| {
                    core.witness_bytes(id).map(<[u8]>::to_vec)
                })
            }
            ("GET", "/aegis/v1/tips") => {
                let tips = core.tips();
                let json = serde_json::json!({
                    "tip": hex::encode(tips.tip),
                    "height": tips.height,
                    "recent": tips.recent.iter().map(hex::encode).collect::<Vec<_>>(),
                });
                respond(
                    &mut stream,
                    200,
                    "application/json",
                    json.to_string().as_bytes(),
                )
            }
            ("GET", "/aegis/v1/chain") => {
                let from_height = query_param(query, "from_height")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1);
                let ids = core.chain_page(from_height, CHAIN_PAGE_MAX);
                let json = serde_json::json!({
                    "from_height": from_height,
                    "tip": hex::encode(core.tip_id()),
                    "ids": ids.iter().map(hex::encode).collect::<Vec<_>>(),
                });
                respond(
                    &mut stream,
                    200,
                    "application/json",
                    json.to_string().as_bytes(),
                )
            }
            ("POST", "/aegis/v1/bodies") => {
                let Some(len) = content_length else {
                    return respond(&mut stream, 400, "text/plain", b"missing content-length");
                };
                if len > MAX_POST_BODY_BYTES || len % 32 != 0 || len / 32 > MAX_BODIES_PER_BATCH {
                    return respond(&mut stream, 400, "text/plain", b"bad id batch");
                }
                if rest.len() < len {
                    let mut more = vec![0u8; len - rest.len()];
                    if stream.read_exact(&mut more).is_err() {
                        return respond(&mut stream, 400, "text/plain", b"truncated id batch");
                    }
                    rest.extend_from_slice(&more);
                }
                let mut out = Vec::new();
                for id_bytes in rest[..len].chunks_exact(32) {
                    let id: super::Id = id_bytes.try_into().expect("chunks_exact(32)");
                    match core.body_bytes(&id) {
                        Some(bytes) => {
                            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                            out.extend_from_slice(bytes);
                        }
                        None => out.extend_from_slice(&0u32.to_le_bytes()),
                    }
                }
                respond(&mut stream, 200, "application/octet-stream", &out)
            }
            _ => respond(&mut stream, 404, "text/plain", b"not found"),
        }
    }

    /// Serve one hex-id-addressed item (400 on a malformed id, 404 on
    /// a miss).
    fn serve_item(
        stream: &mut TcpStream,
        id_hex: &str,
        get: impl Fn(&super::Id) -> Option<Vec<u8>>,
    ) -> std::io::Result<()> {
        let Some(id) = parse_id_hex(id_hex) else {
            return respond(stream, 400, "text/plain", b"bad id");
        };
        match get(&id) {
            Some(bytes) => respond(stream, 200, "application/octet-stream", &bytes),
            None => respond(stream, 404, "text/plain", b"don't have"),
        }
    }

    /// Read up to the end of the request head; returns (head bytes,
    /// any body bytes already read past it).
    fn read_head(stream: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        loop {
            if let Some(pos) = find_head_end(&buf) {
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

    fn find_head_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    /// Parse `(method, target, content_length)` from the head. `None`
    /// on anything malformed.
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

    fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
        query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v)
    }

    fn respond(
        stream: &mut TcpStream,
        status: u16,
        content_type: &str,
        body: &[u8],
    ) -> std::io::Result<()> {
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
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

/// Fetch-by-id client over untrusted seeds ([`fetch_http::RestAegisSource`]) —
/// blocking reqwest, same discipline as `ergo_follow::poll_http`:
/// blocking on purpose, plain HTTP, never call from inside an async
/// context.
pub mod fetch_http {
    use std::io::Read as _;
    use std::time::Duration;

    use super::{
        body_self_authenticates, parse_id_hex, Block, Id, SeedFetch, SeedTips, ShareWitness,
        WitnessDecodeError, CHAIN_PAGE_MAX, MAX_BODIES_PER_BATCH, MAX_BODY_WIRE_BYTES,
        MAX_WITNESS_WIRE_BYTES,
    };
    use crate::anchor_watch::{AegisLookup, AegisSource};

    /// Default per-request timeout (connect + response).
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

    /// JSON response cap (`tips`/`chain`): 512 hex ids plus envelope.
    const MAX_JSON_RESPONSE_BYTES: usize = 256 * 1024;

    /// Configuration for [`RestAegisSource`].
    #[derive(Debug, Clone)]
    pub struct SeedClientConfig {
        /// Seed base URLs in preference order, e.g.
        /// `http://seed1.example:8650` (trailing slash tolerated) —
        /// typically `aegis_spec::NetworkParams::seed_urls` plus CLI
        /// `--seed` overrides. Every seed is untrusted (withhold-only).
        pub seed_urls: Vec<String>,
        /// Per-request timeout.
        pub timeout: Duration,
    }

    impl SeedClientConfig {
        /// A config with the default timeout.
        pub fn new<I, S>(seed_urls: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                seed_urls: seed_urls.into_iter().map(Into::into).collect(),
                timeout: DEFAULT_TIMEOUT,
            }
        }
    }

    /// One seed's failure for one request — the failover unit. Split by
    /// retryability like `poll_http::RestSourceError`: transport
    /// failures are worth retrying, junk answers are not (the same
    /// bytes would come back).
    #[derive(Debug, thiserror::Error)]
    pub enum SeedHttpError {
        /// No HTTP response (connect, timeout, mid-body). Retryable.
        #[error("{url}: request failed")]
        Network {
            url: String,
            #[source]
            source: reqwest::Error,
        },
        /// Non-2xx, non-404 status. Retryable.
        #[error("{url}: HTTP status {status}")]
        Status { url: String, status: u16 },
        /// Response exceeded the wire-size cap for its kind. Junk.
        #[error("{url}: response exceeds {cap} bytes")]
        Oversize { url: String, cap: usize },
        /// Response bytes are not decodable as the requested kind. Junk.
        #[error("{url}: response is not decodable: {detail}")]
        Decode { url: String, detail: String },
        /// The served body does not self-authenticate against the
        /// requested id — wrong bytes, NEVER a verdict about the id
        /// (p2p.md §10 #2): dropped, next seed tried.
        #[error("{url}: served body does not self-authenticate against the requested id")]
        NotSelfAuthenticating { url: String },
        /// The served witness carries a block that does not re-hash to
        /// the requested id. Junk, next seed tried.
        #[error("{url}: served witness carries a different aegis block")]
        WitnessIdMismatch { url: String },
    }

    impl SeedHttpError {
        /// Whether retrying the same seed later can plausibly succeed.
        pub fn is_retryable(&self) -> bool {
            matches!(
                self,
                SeedHttpError::Network { .. } | SeedHttpError::Status { .. }
            )
        }
    }

    /// A whole fetch's failure: every configured seed was tried.
    #[derive(Debug, thiserror::Error)]
    pub enum FetchError {
        /// The HTTP client itself could not be built.
        #[error("building blocking HTTP client")]
        Client(#[source] reqwest::Error),
        /// No seed URLs configured.
        #[error("no seeds configured")]
        NoSeeds,
        /// Every seed failed; per-seed reasons attached.
        #[error("all {} seeds failed: {}", .attempts.len(), summarize(.attempts))]
        AllSeedsFailed { attempts: Vec<SeedHttpError> },
        /// Every seed answered, none has the item (withholding or
        /// genuinely absent — a liveness fact, not an error about the
        /// id).
        #[error("no seed has {}", hex::encode(.0))]
        NotFound(Id),
    }

    fn summarize(attempts: &[SeedHttpError]) -> String {
        attempts
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// HTTP fetch-by-id over untrusted seeds, with per-seed failover
    /// and self-authentication on every fetched item. Implements
    /// [`SeedFetch`] (fresh-sync) and [`AegisSource`] (anchor-watcher
    /// resolution — the fetch there is gated by an Ergo-PoW-committed
    /// commitment, the anchored form of witness-first admission).
    #[derive(Debug)]
    pub struct RestAegisSource {
        config: SeedClientConfig,
        client: reqwest::blocking::Client,
    }

    impl RestAegisSource {
        pub fn new(config: SeedClientConfig) -> Result<Self, FetchError> {
            let client = reqwest::blocking::Client::builder()
                .timeout(config.timeout)
                .build()
                .map_err(FetchError::Client)?;
            Ok(Self { config, client })
        }

        /// Fetch + self-authenticate the body for `id`, trying seeds in
        /// order. A non-authenticating answer is dropped and the next
        /// seed is tried; 404 everywhere is [`FetchError::NotFound`].
        pub fn fetch_body(&self, id: &Id) -> Result<Block, FetchError> {
            let mut attempts = Vec::new();
            let mut all_answered_404 = !self.config.seed_urls.is_empty();
            for seed in &self.config.seed_urls {
                let url = format!("{}/aegis/v1/body/{}", base(seed), hex::encode(id));
                match self.get_capped(&url, MAX_BODY_WIRE_BYTES) {
                    Ok(Some(bytes)) => match decode_body_for(id, &url, &bytes) {
                        Ok(block) => return Ok(block),
                        Err(e) => {
                            all_answered_404 = false;
                            attempts.push(e);
                        }
                    },
                    Ok(None) => {} // explicit 404 — DONT_HAVE
                    Err(e) => {
                        all_answered_404 = false;
                        attempts.push(e);
                    }
                }
            }
            Err(self.exhausted(id, all_answered_404, attempts))
        }

        /// Fetch + id-bind the witness for `id`, trying seeds in order.
        pub fn fetch_witness(&self, id: &Id) -> Result<ShareWitness, FetchError> {
            let mut attempts = Vec::new();
            let mut all_answered_404 = !self.config.seed_urls.is_empty();
            for seed in &self.config.seed_urls {
                let url = format!("{}/aegis/v1/witness/{}", base(seed), hex::encode(id));
                match self.get_capped(&url, MAX_WITNESS_WIRE_BYTES) {
                    Ok(Some(bytes)) => match decode_witness_for(id, &url, &bytes) {
                        Ok(witness) => return Ok(witness),
                        Err(e) => {
                            all_answered_404 = false;
                            attempts.push(e);
                        }
                    },
                    Ok(None) => {}
                    Err(e) => {
                        all_answered_404 = false;
                        attempts.push(e);
                    }
                }
            }
            Err(self.exhausted(id, all_answered_404, attempts))
        }

        fn exhausted(
            &self,
            id: &Id,
            all_answered_404: bool,
            attempts: Vec<SeedHttpError>,
        ) -> FetchError {
            if self.config.seed_urls.is_empty() {
                FetchError::NoSeeds
            } else if all_answered_404 && attempts.is_empty() {
                FetchError::NotFound(*id)
            } else {
                FetchError::AllSeedsFailed { attempts }
            }
        }

        /// GET `url`, capping the response at `cap` bytes.
        /// `Ok(None)` = explicit 404 (DONT_HAVE).
        fn get_capped(&self, url: &str, cap: usize) -> Result<Option<Vec<u8>>, SeedHttpError> {
            let response = self
                .client
                .get(url)
                .send()
                .map_err(|e| SeedHttpError::Network {
                    url: url.to_string(),
                    source: e,
                })?;
            self.read_capped(url, cap, response)
        }

        /// POST `body` to `url`, capping the response at `cap` bytes.
        fn post_capped(
            &self,
            url: &str,
            body: Vec<u8>,
            cap: usize,
        ) -> Result<Option<Vec<u8>>, SeedHttpError> {
            let response =
                self.client
                    .post(url)
                    .body(body)
                    .send()
                    .map_err(|e| SeedHttpError::Network {
                        url: url.to_string(),
                        source: e,
                    })?;
            self.read_capped(url, cap, response)
        }

        fn read_capped(
            &self,
            url: &str,
            cap: usize,
            response: reqwest::blocking::Response,
        ) -> Result<Option<Vec<u8>>, SeedHttpError> {
            let status = response.status();
            if status.as_u16() == 404 {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(SeedHttpError::Status {
                    url: url.to_string(),
                    status: status.as_u16(),
                });
            }
            let mut bytes = Vec::new();
            response
                .take(cap as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| SeedHttpError::Decode {
                    url: url.to_string(),
                    detail: format!("reading response: {e}"),
                })?;
            if bytes.len() > cap {
                return Err(SeedHttpError::Oversize {
                    url: url.to_string(),
                    cap,
                });
            }
            Ok(Some(bytes))
        }
    }

    fn base(seed_url: &str) -> &str {
        seed_url.trim_end_matches('/')
    }

    /// Decode + self-authenticate a served body against the requested
    /// id — THE untrusted-seed property: a wrong body is an error about
    /// the bytes/seed, never about the id.
    fn decode_body_for(id: &Id, url: &str, bytes: &[u8]) -> Result<Block, SeedHttpError> {
        let block = Block::from_bytes(bytes).map_err(|e| SeedHttpError::Decode {
            url: url.to_string(),
            detail: e.to_string(),
        })?;
        if !body_self_authenticates(id, &block) {
            return Err(SeedHttpError::NotSelfAuthenticating {
                url: url.to_string(),
            });
        }
        Ok(block)
    }

    /// Decode a served witness and bind it to the requested id (the
    /// carried block must re-hash to `id`; the PoW claim itself is
    /// only admitted through [`ShareWitness::verify`] at ingestion).
    fn decode_witness_for(id: &Id, url: &str, bytes: &[u8]) -> Result<ShareWitness, SeedHttpError> {
        let witness = ShareWitness::from_bytes(bytes).map_err(|e: WitnessDecodeError| {
            SeedHttpError::Decode {
                url: url.to_string(),
                detail: e.to_string(),
            }
        })?;
        let block =
            Block::from_bytes(&witness.aegis_block_bytes).map_err(|e| SeedHttpError::Decode {
                url: url.to_string(),
                detail: format!("witness block bytes: {e}"),
            })?;
        if block.id() != *id {
            return Err(SeedHttpError::WitnessIdMismatch {
                url: url.to_string(),
            });
        }
        Ok(witness)
    }

    /// Parse a `tips` JSON answer.
    fn parse_tips_json(bytes: &[u8]) -> Result<SeedTips, String> {
        let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let tip = v
            .get("tip")
            .and_then(|t| t.as_str())
            .and_then(parse_id_hex)
            .ok_or("missing/invalid tip")?;
        let height = v
            .get("height")
            .and_then(|h| h.as_u64())
            .ok_or("missing/invalid height")?;
        let recent = parse_id_array(v.get("recent").ok_or("missing recent")?)?;
        Ok(SeedTips {
            tip,
            height,
            recent,
        })
    }

    /// Parse a `chain` JSON answer to its id page.
    fn parse_chain_json(bytes: &[u8]) -> Result<Vec<Id>, String> {
        let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        parse_id_array(v.get("ids").ok_or("missing ids")?)
    }

    fn parse_id_array(v: &serde_json::Value) -> Result<Vec<Id>, String> {
        let arr = v.as_array().ok_or("ids is not an array")?;
        if arr.len() > CHAIN_PAGE_MAX {
            return Err(format!("{} ids exceeds the page cap", arr.len()));
        }
        arr.iter()
            .map(|e| {
                e.as_str()
                    .and_then(parse_id_hex)
                    .ok_or_else(|| "invalid id entry".to_string())
            })
            .collect()
    }

    /// Parse a batched-bodies response: `n` frames of
    /// `u32-LE len ‖ bytes` (`len = 0` = don't have), nothing trailing.
    fn parse_bodies_frames(data: &[u8], n: usize) -> Result<Vec<Option<&[u8]>>, String> {
        let mut out = Vec::with_capacity(n);
        let mut offset = 0usize;
        for i in 0..n {
            let Some(len_bytes) = data.get(offset..offset + 4) else {
                return Err(format!("frame {i}: truncated length"));
            };
            let len = u32::from_le_bytes(len_bytes.try_into().expect("4 bytes")) as usize;
            if len > MAX_BODY_WIRE_BYTES {
                return Err(format!("frame {i}: claims {len} bytes"));
            }
            offset += 4;
            let Some(payload) = data.get(offset..offset + len) else {
                return Err(format!("frame {i}: truncated payload"));
            };
            out.push((len > 0).then_some(payload));
            offset += len;
        }
        if offset != data.len() {
            return Err(format!("{} trailing bytes", data.len() - offset));
        }
        Ok(out)
    }

    impl SeedFetch for RestAegisSource {
        type Error = FetchError;

        fn tips(&self) -> Result<Vec<SeedTips>, Self::Error> {
            if self.config.seed_urls.is_empty() {
                return Err(FetchError::NoSeeds);
            }
            let mut out = Vec::new();
            let mut attempts = Vec::new();
            for seed in &self.config.seed_urls {
                let url = format!("{}/aegis/v1/tips", base(seed));
                match self.get_capped(&url, MAX_JSON_RESPONSE_BYTES) {
                    Ok(Some(bytes)) => match parse_tips_json(&bytes) {
                        Ok(tips) => out.push(tips),
                        Err(detail) => attempts.push(SeedHttpError::Decode { url, detail }),
                    },
                    Ok(None) => attempts.push(SeedHttpError::Status { url, status: 404 }),
                    Err(e) => attempts.push(e),
                }
            }
            if out.is_empty() {
                return Err(FetchError::AllSeedsFailed { attempts });
            }
            Ok(out)
        }

        fn chain_page(&self, from_height: u64, limit: usize) -> Result<Vec<Id>, Self::Error> {
            if self.config.seed_urls.is_empty() {
                return Err(FetchError::NoSeeds);
            }
            let mut attempts = Vec::new();
            for seed in &self.config.seed_urls {
                let url = format!("{}/aegis/v1/chain?from_height={from_height}", base(seed));
                match self.get_capped(&url, MAX_JSON_RESPONSE_BYTES) {
                    Ok(Some(bytes)) => match parse_chain_json(&bytes) {
                        Ok(mut ids) => {
                            ids.truncate(limit);
                            return Ok(ids);
                        }
                        Err(detail) => attempts.push(SeedHttpError::Decode { url, detail }),
                    },
                    Ok(None) => attempts.push(SeedHttpError::Status { url, status: 404 }),
                    Err(e) => attempts.push(e),
                }
            }
            Err(FetchError::AllSeedsFailed { attempts })
        }

        fn witness(&self, id: &Id) -> Result<Option<ShareWitness>, Self::Error> {
            match self.fetch_witness(id) {
                Ok(witness) => Ok(Some(witness)),
                Err(FetchError::NotFound(_)) => Ok(None),
                Err(e) => Err(e),
            }
        }

        fn bodies(&self, ids: &[Id]) -> Result<Vec<Option<Block>>, Self::Error> {
            if self.config.seed_urls.is_empty() {
                return Err(FetchError::NoSeeds);
            }
            let mut out: Vec<Option<Block>> = vec![None; ids.len()];
            for (chunk_start, chunk) in ids.chunks(MAX_BODIES_PER_BATCH).enumerate() {
                let offset = chunk_start * MAX_BODIES_PER_BATCH;
                let mut any_answer = false;
                let mut attempts = Vec::new();
                for seed in &self.config.seed_urls {
                    let missing: Vec<usize> = (0..chunk.len())
                        .filter(|i| out[offset + i].is_none())
                        .collect();
                    if missing.is_empty() {
                        break;
                    }
                    let mut request = Vec::with_capacity(missing.len() * 32);
                    for &i in &missing {
                        request.extend_from_slice(&chunk[i]);
                    }
                    let url = format!("{}/aegis/v1/bodies", base(seed));
                    let cap = missing.len() * (4 + MAX_BODY_WIRE_BYTES);
                    let bytes = match self.post_capped(&url, request, cap) {
                        Ok(Some(bytes)) => bytes,
                        Ok(None) => {
                            attempts.push(SeedHttpError::Status { url, status: 404 });
                            continue;
                        }
                        Err(e) => {
                            attempts.push(e);
                            continue;
                        }
                    };
                    let frames = match parse_bodies_frames(&bytes, missing.len()) {
                        Ok(frames) => frames,
                        Err(detail) => {
                            attempts.push(SeedHttpError::Decode { url, detail });
                            continue;
                        }
                    };
                    any_answer = true;
                    for (&i, frame) in missing.iter().zip(frames) {
                        let Some(frame) = frame else { continue };
                        // Per-frame self-auth: a junk entry is dropped
                        // (stays None for another seed), the rest of
                        // the response is still used.
                        if let Ok(block) = decode_body_for(&chunk[i], &url, frame) {
                            out[offset + i] = Some(block);
                        }
                    }
                }
                let chunk_done = (0..chunk.len()).all(|i| out[offset + i].is_some());
                if !any_answer && !chunk_done {
                    return Err(FetchError::AllSeedsFailed { attempts });
                }
            }
            Ok(out)
        }
    }

    impl AegisSource for RestAegisSource {
        /// Resolve by fetching the full body from the seeds; any
        /// failure is `Unknown` — the anchor-watcher buffers and
        /// retries, exactly the monotone no-verdict semantics
        /// availability must have.
        fn lookup(&self, aegis_id: &Id) -> AegisLookup {
            match self.fetch_body(aegis_id) {
                Ok(block) => AegisLookup::Full(Box::new(block)),
                Err(e) => {
                    tracing::debug!(
                        id = %hex::encode(aegis_id),
                        error = %e,
                        "seed body fetch failed; treating as unknown"
                    );
                    AegisLookup::Unknown
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use super::fetch_http::{FetchError, RestAegisSource, SeedClientConfig, SeedHttpError};
    use super::serve_http::SeedServer;
    use super::*;
    use crate::block::BlockBody;
    use crate::chain::{Chain, PowMode, ProofMode};
    use crate::store::save_block;

    // ----- helpers -----

    const T_MS: u64 = 15_000;

    /// Produce `n` empty blocks extending `prefix` (which must itself
    /// extend genesis), `spacing_ms` apart. Returns only the new blocks.
    fn extend_branch(prefix: &[Block], n: usize, spacing_ms: u64) -> Vec<Block> {
        let mut chain = Chain::new(Network::Dev, PowMode::DevStub, ProofMode::DevStub);
        for b in prefix {
            chain
                .try_extend(b.clone(), b.header.timestamp_ms)
                .expect("prefix replays");
        }
        let mut out = Vec::with_capacity(n);
        let mut now = chain.tip().timestamp_ms;
        for _ in 0..n {
            now += spacing_ms;
            let block = chain
                .produce_next(BlockBody::default(), now)
                .expect("empty block produces");
            chain
                .try_extend(block.clone(), now)
                .expect("produced block extends");
            out.push(block);
        }
        out
    }

    fn core_with(blocks: &[Block]) -> SeedCore {
        let mut core = SeedCore::new(Network::Dev);
        for b in blocks {
            core.record_canonical(b);
        }
        core
    }

    /// A structurally valid witness wrapping `block` (unverifiable PoW
    /// — codec/keying tests only; PoW-grade witnesses live in the
    /// fresh-sync integration tests).
    fn stub_witness(block: &Block) -> ShareWitness {
        use crate::auxpow::aegis_mm_extension_field;
        use ergo_ser::batch_merkle_proof::BatchMerkleProof;
        let block_json: ergo_rest_json::types::ScalaFullBlock = serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../test-vectors/testnet/blocks/scala_block_442815.json",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect("vector reads"),
        )
        .expect("vector parses");
        let ergo_header =
            ergo_rest_json::decode_scala_header_struct(&block_json.header).expect("header decodes");
        ShareWitness {
            ergo_header,
            field: aegis_mm_extension_field(block.id()),
            proof: BatchMerkleProof {
                indices: vec![],
                proofs: vec![],
            },
            aegis_block_bytes: block.bytes(),
        }
    }

    /// Spawn a raw junk seed: answers every connection with a canned
    /// HTTP 200 whose body is `payload` — garbage under any id.
    fn spawn_junk_seed(payload: Vec<u8>) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            for conn in listener.incoming().take(16) {
                let Ok(mut stream) = conn else { continue };
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf); // drain the request head
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len(),
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&payload);
            }
        });
        format!("http://{addr}")
    }

    fn client(urls: &[String]) -> RestAegisSource {
        let mut config = SeedClientConfig::new(urls.iter().cloned());
        config.timeout = std::time::Duration::from_secs(5);
        RestAegisSource::new(config).expect("client builds")
    }

    fn serve(core: SeedCore) -> SeedServer {
        SeedServer::spawn("127.0.0.1:0", Arc::new(RwLock::new(core))).expect("server spawns")
    }

    // ----- happy path -----

    #[test]
    fn seed_core_from_store_indexes_the_block_log() {
        let dir = tempfile::tempdir().unwrap();
        let blocks = extend_branch(&[], 3, T_MS);
        for b in &blocks {
            save_block(dir.path(), b).expect("block saves");
        }
        let core = SeedCore::from_store(dir.path(), Network::Dev).expect("archive indexes");
        assert_eq!(core.height(), 3);
        assert_eq!(core.tip_id(), blocks[2].id());
        for b in &blocks {
            assert_eq!(core.body_bytes(&b.id()), Some(b.bytes().as_slice()));
        }
        let tips = core.tips();
        assert_eq!(tips.height, 3);
        assert_eq!(
            tips.recent,
            blocks.iter().map(Block::id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn empty_core_tips_is_genesis() {
        let core = SeedCore::new(Network::Dev);
        let tips = core.tips();
        assert_eq!(tips.tip, genesis_header(Network::Dev).id());
        assert_eq!(tips.height, 0);
        assert!(tips.recent.is_empty());
        assert!(core.chain_page(1, 10).is_empty());
    }

    #[test]
    fn chain_page_paginates_in_order() {
        let blocks = extend_branch(&[], 5, T_MS);
        let core = core_with(&blocks);
        let ids: Vec<Id> = blocks.iter().map(Block::id).collect();
        assert_eq!(core.chain_page(1, 2), ids[..2]);
        assert_eq!(core.chain_page(3, 2), ids[2..4]);
        assert_eq!(core.chain_page(5, 100), ids[4..]);
        assert!(core.chain_page(6, 2).is_empty());
        assert_eq!(core.chain_page(0, 1), ids[..1], "height 0 treated as 1");
    }

    #[test]
    fn record_canonical_reorg_truncates_but_keeps_bodies() {
        let a = extend_branch(&[], 3, T_MS);
        let b = extend_branch(&[a[0].clone()], 2, T_MS + 1_000); // fork at height 1
        let mut core = core_with(&a);
        for blk in &b {
            core.record_canonical(blk);
        }
        assert_eq!(core.height(), 3);
        assert_eq!(core.tip_id(), b[1].id());
        assert_eq!(
            core.chain_page(1, 10),
            vec![a[0].id(), b[0].id(), b[1].id()]
        );
        // Displaced bodies remain fetchable by id (content-addressed).
        assert!(core.body_bytes(&a[1].id()).is_some());
        assert!(core.body_bytes(&a[2].id()).is_some());
    }

    #[test]
    fn record_witness_keys_by_recomputed_id() {
        let blocks = extend_branch(&[], 1, T_MS);
        let mut core = SeedCore::new(Network::Dev);
        let witness = stub_witness(&blocks[0]);
        let id = core.record_witness(&witness).expect("records");
        assert_eq!(id, blocks[0].id(), "id recomputed from carried bytes");
        assert_eq!(
            core.witness_bytes(&id),
            Some(witness.bytes().unwrap().as_slice())
        );
        assert!(core.witness_bytes(&[0xEE; 32]).is_none());
    }

    #[test]
    fn stale_noncanonical_witnesses_pruned_past_retention() {
        // A witness for a block that never becomes canonical is dropped
        // once the canonical chain advances RETENTION past its arrival;
        // canonical blocks' witnesses are kept regardless.
        let n = PENDING_WITNESS_RETENTION as usize + 2;
        let canonical = extend_branch(&[], n, T_MS);
        let orphan = extend_branch(&[], 1, T_MS + 1_000); // never canonical

        let mut core = SeedCore::new(Network::Dev);
        core.record_canonical(&canonical[0]);
        let orphan_id = core.record_witness(&stub_witness(&orphan[0])).unwrap();
        let kept_id = core.record_witness(&stub_witness(&canonical[0])).unwrap();
        for b in &canonical[1..] {
            core.record_canonical(b);
        }
        assert!(
            core.witness_bytes(&orphan_id).is_none(),
            "non-canonical witness dropped past the retention horizon"
        );
        assert!(
            core.witness_bytes(&kept_id).is_some(),
            "canonical block's witness kept"
        );
    }

    // ----- round-trips (loopback HTTP: server shim + client) -----

    #[test]
    fn http_body_roundtrips_and_self_authenticates() {
        let blocks = extend_branch(&[], 2, T_MS);
        let server = serve(core_with(&blocks));
        let client = client(&[server.base_url()]);

        let block = client.fetch_body(&blocks[1].id()).expect("body fetches");
        assert_eq!(block.id(), blocks[1].id());
        assert_eq!(block.bytes(), blocks[1].bytes());

        // As an AegisSource: Full for known, Unknown for missing.
        assert!(matches!(
            client.lookup(&blocks[0].id()),
            AegisLookup::Full(b) if b.id() == blocks[0].id()
        ));
        assert!(matches!(client.lookup(&[0xAB; 32]), AegisLookup::Unknown));
    }

    #[test]
    fn http_witness_roundtrips_with_id_binding() {
        let blocks = extend_branch(&[], 1, T_MS);
        let mut core = core_with(&blocks);
        let witness = stub_witness(&blocks[0]);
        core.record_witness(&witness).unwrap();
        let server = serve(core);
        let client = client(&[server.base_url()]);

        let fetched = client
            .fetch_witness(&blocks[0].id())
            .expect("witness fetches");
        assert_eq!(fetched, witness);
        assert_eq!(
            SeedFetch::witness(&client, &[0xAB; 32]).expect("answered"),
            None,
            "explicit miss is None, not an error"
        );
    }

    #[test]
    fn http_tips_and_chain_roundtrip() {
        let blocks = extend_branch(&[], 4, T_MS);
        let server = serve(core_with(&blocks));
        let client = client(&[server.base_url()]);

        let tips = SeedFetch::tips(&client).expect("tips fetch");
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].tip, blocks[3].id());
        assert_eq!(tips[0].height, 4);
        assert_eq!(
            tips[0].recent,
            blocks.iter().map(Block::id).collect::<Vec<_>>()
        );

        let page = client.chain_page(2, 2).expect("chain page");
        assert_eq!(page, vec![blocks[1].id(), blocks[2].id()]);
    }

    #[test]
    fn http_batched_bodies_roundtrip_with_explicit_misses() {
        let blocks = extend_branch(&[], 3, T_MS);
        let server = serve(core_with(&blocks));
        let client = client(&[server.base_url()]);

        let ids = [blocks[0].id(), [0xCD; 32], blocks[2].id()];
        let got = client.bodies(&ids).expect("batch fetch");
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].as_ref().map(Block::id), Some(blocks[0].id()));
        assert!(got[1].is_none(), "unknown id is an explicit miss");
        assert_eq!(got[2].as_ref().map(Block::id), Some(blocks[2].id()));
    }

    // ----- error paths -----

    #[test]
    fn corrupted_body_is_not_self_authenticating_and_fails_over() {
        // Seed 1 serves garbage under every id (200 OK); seed 2 is
        // honest. The client must drop the junk (self-auth) and fetch
        // from seed 2 — the untrusted-peer property.
        let blocks = extend_branch(&[], 1, T_MS);
        let id = blocks[0].id();

        // Wrong-but-decodable body: a DIFFERENT valid block's bytes.
        let other = extend_branch(&[], 1, T_MS + 1_000);
        assert_ne!(other[0].id(), id);
        let junk_url = spawn_junk_seed(other[0].bytes());

        // Junk alone: typed self-auth failure, id unharmed.
        let junk_only = client(std::slice::from_ref(&junk_url));
        let err = junk_only.fetch_body(&id).unwrap_err();
        match err {
            FetchError::AllSeedsFailed { attempts } => {
                assert!(
                    matches!(attempts[..], [SeedHttpError::NotSelfAuthenticating { .. }]),
                    "{attempts:?}"
                );
                assert!(!attempts[0].is_retryable(), "junk is not retryable");
            }
            other => panic!("expected AllSeedsFailed, got {other:?}"),
        }

        // Junk first, honest second: failover succeeds.
        let honest = serve(core_with(&blocks));
        let both = client(&[junk_url, honest.base_url()]);
        let block = both.fetch_body(&id).expect("failover succeeds");
        assert_eq!(block.id(), id);
    }

    #[test]
    fn undecodable_junk_is_a_decode_error() {
        let junk_url = spawn_junk_seed(vec![0xFF; 64]);
        let client = client(&[junk_url]);
        let err = client.fetch_body(&[0x11; 32]).unwrap_err();
        match err {
            FetchError::AllSeedsFailed { attempts } => {
                assert!(
                    matches!(attempts[..], [SeedHttpError::Decode { .. }]),
                    "{attempts:?}"
                );
            }
            other => panic!("expected AllSeedsFailed, got {other:?}"),
        }
    }

    #[test]
    fn withholding_seed_fails_over_and_all_withhold_is_not_found() {
        let blocks = extend_branch(&[], 1, T_MS);
        let id = blocks[0].id();
        let empty1 = serve(SeedCore::new(Network::Dev)); // withholds (404)
        let full = serve(core_with(&blocks));

        // Withhold → failover: seed 2 serves what seed 1 404s.
        let both = client(&[empty1.base_url(), full.base_url()]);
        assert_eq!(both.fetch_body(&id).expect("failover").id(), id);

        // All withhold: explicit NotFound (liveness fact, not junk).
        let empty2 = serve(SeedCore::new(Network::Dev));
        let starved = client(&[empty1.base_url(), empty2.base_url()]);
        assert!(matches!(
            starved.fetch_body(&id),
            Err(FetchError::NotFound(got)) if got == id
        ));
        assert_eq!(SeedFetch::witness(&starved, &id).unwrap(), None);
        let batch = starved.bodies(&[id]).unwrap();
        assert_eq!(batch.len(), 1);
        assert!(batch[0].is_none());
    }

    #[test]
    fn unreachable_seed_is_a_retryable_network_error() {
        let client = client(&["http://127.0.0.1:9".to_string()]); // discard port
        let err = client.fetch_body(&[0x22; 32]).unwrap_err();
        match err {
            FetchError::AllSeedsFailed { attempts } => {
                assert!(
                    matches!(attempts[..], [SeedHttpError::Network { .. }]),
                    "{attempts:?}"
                );
                assert!(attempts[0].is_retryable());
            }
            other => panic!("expected AllSeedsFailed, got {other:?}"),
        }
    }

    #[test]
    fn no_seeds_configured_errors() {
        let client = client(&[]);
        assert!(matches!(
            client.fetch_body(&[0x33; 32]),
            Err(FetchError::NoSeeds)
        ));
    }

    #[test]
    fn server_rejects_malformed_requests() {
        use std::io::{Read, Write};
        let server = serve(SeedCore::new(Network::Dev));
        let request_status = |raw: &str| -> String {
            let mut stream = std::net::TcpStream::connect(server.local_addr()).expect("connect");
            stream.write_all(raw.as_bytes()).expect("write");
            let mut response = String::new();
            stream.read_to_string(&mut response).expect("read");
            response.lines().next().unwrap_or_default().to_string()
        };
        // Bad id (not 64 hex chars) → 400.
        assert!(
            request_status("GET /aegis/v1/body/zz HTTP/1.1\r\nHost: x\r\n\r\n").contains("400")
        );
        // Unknown route → 404.
        assert!(request_status("GET /aegis/v2/nope HTTP/1.1\r\nHost: x\r\n\r\n").contains("404"));
        // Oversized id batch → 400.
        let oversize = 32 * (MAX_BODIES_PER_BATCH + 1);
        assert!(request_status(&format!(
            "POST /aegis/v1/bodies HTTP/1.1\r\nHost: x\r\nContent-Length: {oversize}\r\n\r\n"
        ))
        .contains("400"));
        // Non-multiple-of-32 batch → 400.
        assert!(request_status(
            "POST /aegis/v1/bodies HTTP/1.1\r\nHost: x\r\nContent-Length: 31\r\n\r\nxxx"
        )
        .contains("400"));
    }

    #[test]
    fn body_self_authentication_catches_tampering() {
        let blocks = extend_branch(&[], 1, T_MS);
        let good = &blocks[0];
        assert!(body_self_authenticates(&good.id(), good));

        // Wrong id.
        assert!(!body_self_authenticates(&[0x99; 32], good));

        // Body swapped under the same header (tx_root mismatch).
        let mut forged = good.clone();
        forged.body = BlockBody {
            transfers: vec![crate::tx::testutil::sample_transfer(7)],
            ..Default::default()
        };
        forged.header = good.header.clone();
        assert!(!body_self_authenticates(&good.id(), &forged));
    }
}
