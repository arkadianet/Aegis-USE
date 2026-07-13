//! Ergo header-follower — the light client that lets aegis-node track
//! the Ergo chain independently (`consensus.md` §1/C2: "light follow,
//! not full Ergo validation").
//!
//! This is **shared infrastructure**:
//!  - the peg-in objectivity work-policy (`g25-pegmint-packaging` §2b)
//!    compares a PegMint proof's total attested work against the
//!    cumulative work of the chain *this* node has independently
//!    followed, taken at the **settled reference**
//!    `H_ref = tip_height − N_mint` ([`Follower::settled_reference`]);
//!  - C2 merge-mining binds each Aegis block to the live Ergo tip.
//!
//! The state machine is a **pure function of the header inputs** — no
//! network I/O lives here (the [`poll`] adapter feeds it) — so it is
//! deterministic and unit-testable. Each ingested header is PoW-gated
//! with the product node's Autolykos verifier
//! ([`ergo_crypto::pow::verify_pow_solution`], confirmed stand-alone by
//! the reuse spike) and contributes per-header work
//! `decode_compact_bits(n_bits)` — the same difficulty `b` the reference
//! PoW check treats as work (`ergo_validation::popow::algos`:
//! `requiredTarget = q / b`). Chain work is the sum of `b`, matching
//! `pegmint::check_objectivity`.
//!
//! ## Honest boundaries (non-goals)
//!  - **Anchoring.** Rejecting a forged *root* is a TOFU concern:
//!    [`Follower::with_root`] pins the expected root id; a bare
//!    [`Follower::new`] trusts the first header it sees as the root.
//!    (The pegmint anchor check is the value-bearing layer above this.)
//!  - **Orphan buffering.** A header whose parent has not yet arrived is
//!    rejected as [`FollowError::UnknownParent`] rather than buffered;
//!    the poller feeds ascending heights so this does not arise on the
//!    happy path.
//!  - **Tie-break.** On exactly-equal cumulative work the incumbent tip
//!    is kept (deterministic); a real PoW-id tie-break is unnecessary at
//!    the `N_mint`-settled depth this component is consulted at.
//!  - **Consumed by the §2b work-policy, but still NOT on a live
//!    consensus path.** `pegmint::comparative_policy` scores a proof
//!    against [`Follower::settled_view`]; `verify_ergo_chain_comparative`
//!    itself remains an unwired lib fn (see the pegmint module banner
//!    for what still blocks wiring). This component does not by itself
//!    make peg-in objective; it is the *reference* the policy consumes.

use std::collections::{HashMap, HashSet};

use ergo_crypto::pow::verify_pow_solution;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::header::{serialize_header, Header as ErgoHeader};
use ergo_validation::popow::max_level_of;
use num_bigint::BigUint;

/// One followed Ergo header, reduced to the consensus metadata the
/// fork-choice and settled-reference logic need (no tx/AD-proof bodies —
/// this is a light follower).
#[derive(Debug, Clone)]
pub struct FollowedHeader {
    /// blake2b256 of the serialized header.
    pub id: [u8; 32],
    /// Parent header id (zero for a genuine genesis).
    pub parent_id: [u8; 32],
    /// Block height.
    pub height: u32,
    /// Per-header difficulty `b = decode_compact_bits(n_bits)` — the
    /// work this header contributes.
    pub work: BigUint,
    /// Cumulative work from the followed root through this header.
    pub cumulative_work: BigUint,
    /// KMZ17 μ-level of the header
    /// ([`ergo_validation::popow::max_level_of`]), recorded at ingest
    /// so the followed chain can be `best_arg`-scored against a
    /// NiPoPoW proof without retaining the full `Header`. Genesis
    /// carries the [`ergo_validation::popow::GENESIS_LEVEL`] sentinel.
    pub level: u32,
}

/// The deterministic comparison point the peg-in work-policy consumes:
/// the followed chain at `tip_height − N_mint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledRef {
    pub id: [u8; 32],
    pub height: u32,
    /// Cumulative followed work up to and including this settled header.
    pub cumulative_work: BigUint,
}

/// The followed best chain truncated to a settled height `h_ref` —
/// the reference the peg-in comparative work-policy (g25 §2b) scores a
/// NiPoPoW proof against. Produced by [`Follower::settled_view`];
/// carries id-membership (for the LCA search) and per-header μ-levels
/// (for [`ergo_validation::popow::best_arg_from_levels`]) so the
/// policy needs no access to the follower's internals.
#[derive(Debug, Clone)]
pub struct SettledView {
    /// Height by id for every best-chain header with `height <= h_ref`.
    heights_by_id: HashMap<[u8; 32], u32>,
    /// `(height, μ-level)` of the same headers, ascending by height.
    levels_asc: Vec<(u32, u32)>,
    /// The settled truncation height this view was taken at.
    pub h_ref: u32,
}

impl SettledView {
    /// Height of `id` on the settled best chain, if present.
    pub fn height_of(&self, id: &[u8; 32]) -> Option<u32> {
        self.heights_by_id.get(id).copied()
    }

    /// μ-levels of the settled best-chain headers strictly above
    /// `height_excl` (the divergent-suffix input to
    /// `best_arg_from_levels`). The follower's root sentinel level
    /// (genesis = `GENESIS_LEVEL`) can only appear here if
    /// `height_excl` is below the root height — which callers exclude
    /// by only passing an LCA height, and an LCA is by construction a
    /// member of this view (so at or above the root).
    pub fn levels_above(&self, height_excl: u32) -> Vec<u32> {
        self.levels_asc
            .iter()
            .filter(|(h, _)| *h > height_excl)
            .map(|(_, l)| *l)
            .collect()
    }

    /// Height of the deepest header in the view — the follower's root.
    /// A view is never empty ([`Follower::settled_view`] always walks
    /// at least the `h_ref` header), so this is total.
    pub fn root_height(&self) -> u32 {
        self.levels_asc.first().map(|(h, _)| *h).unwrap_or(0)
    }

    /// Number of settled headers in the view.
    pub fn len(&self) -> usize {
        self.levels_asc.len()
    }

    /// Whether the view holds no headers.
    pub fn is_empty(&self) -> bool {
        self.levels_asc.is_empty()
    }

    /// TEST-ONLY: fabricate a view from raw `(header_id, height,
    /// μ-level)` rows. The steps-5–9 verifier unit tests need a settled
    /// view whose header commits *synthetic* transactions, which a real
    /// [`Follower`] can never produce (its headers must pass Autolykos
    /// PoW). Never compiled outside `cfg(test)`; production views come
    /// only from [`Follower::settled_view`].
    #[cfg(test)]
    pub(crate) fn fabricate_for_tests(rows: &[([u8; 32], u32, u32)], h_ref: u32) -> Self {
        let mut heights_by_id = HashMap::new();
        let mut levels_asc: Vec<(u32, u32)> = Vec::new();
        for (id, height, level) in rows {
            heights_by_id.insert(*id, *height);
            levels_asc.push((*height, *level));
        }
        levels_asc.sort_unstable_by_key(|(h, _)| *h);
        Self {
            heights_by_id,
            levels_asc,
            h_ref,
        }
    }
}

/// Outcome of ingesting one header, for logging/telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingest {
    /// Established the followed root (first header, or the pinned root).
    Root,
    /// Extended the current best tip in place.
    Extended,
    /// Accepted onto a lighter branch that did not beat the best tip.
    SideBranch,
    /// A heavier branch replaced the tip; `depth` blocks of the previous
    /// best chain were rolled back to the common ancestor.
    Reorg { depth: u32 },
    /// Already-known header id; no change.
    Duplicate,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FollowError {
    #[error("Autolykos PoW verification failed")]
    InvalidPow,
    #[error("header serialization failed")]
    Serialize,
    #[error("first header id does not match the pinned root")]
    RootMismatch,
    #[error("parent header is not in the followed set (orphan)")]
    UnknownParent,
    #[error("height {got} does not follow parent height {expected_parent} + 1")]
    HeightGap { expected_parent: u32, got: u32 },
}

/// The Ergo header-follower state machine.
#[derive(Debug)]
pub struct Follower {
    headers: HashMap<[u8; 32], FollowedHeader>,
    best_tip: Option<[u8; 32]>,
    /// `N_mint` — confirmations that define the settled reference depth.
    n_mint: u64,
    /// Optional pinned root id (TOFU anchor); the first header must match.
    expected_root: Option<[u8; 32]>,
}

impl Follower {
    /// A follower that trusts the first header it sees as the root.
    /// Anchoring against a forged root is left to the caller's TOFU
    /// layer — use [`Follower::with_root`] to pin it here instead.
    pub fn new(n_mint: u64) -> Self {
        Self {
            headers: HashMap::new(),
            best_tip: None,
            n_mint,
            expected_root: None,
        }
    }

    /// A follower pinned to a known root id (rejects any other first
    /// header as [`FollowError::RootMismatch`]).
    pub fn with_root(n_mint: u64, expected_root_id: [u8; 32]) -> Self {
        Self {
            headers: HashMap::new(),
            best_tip: None,
            n_mint,
            expected_root: Some(expected_root_id),
        }
    }

    /// Ingest a full Ergo header: PoW-gate it, then fold it into the
    /// followed chain. The PoW gate runs **first** so an invalid header
    /// never touches the bookkeeping.
    pub fn apply_header(&mut self, h: &ErgoHeader) -> Result<Ingest, FollowError> {
        verify_pow_solution(h).map_err(|_| FollowError::InvalidPow)?;
        let (_bytes, id) = serialize_header(h).map_err(|_| FollowError::Serialize)?;
        let work = decode_compact_bits(h.n_bits);
        let level = max_level_of(h);
        self.apply_verified_header(
            *id.as_bytes(),
            *h.parent_id.as_bytes(),
            h.height,
            work,
            level,
        )
    }

    /// Fold an already-PoW-verified header into the chain: linkage,
    /// cumulative-work, and fork choice. **Private on purpose** — it
    /// bypasses the PoW gate, so exposing it would let a caller fold
    /// attacker-chosen work into a consensus-adjacent structure. The only
    /// entry point is [`Follower::apply_header`] (which PoW-gates first);
    /// the in-file tests reach this core directly as a child module to
    /// exercise the fork-choice bookkeeping against synthetic work.
    fn apply_verified_header(
        &mut self,
        id: [u8; 32],
        parent_id: [u8; 32],
        height: u32,
        work: BigUint,
        level: u32,
    ) -> Result<Ingest, FollowError> {
        if self.headers.contains_key(&id) {
            return Ok(Ingest::Duplicate);
        }

        // Root vs child.
        let cumulative_work = if self.headers.is_empty() {
            if let Some(exp) = self.expected_root {
                if id != exp {
                    return Err(FollowError::RootMismatch);
                }
            }
            work.clone()
        } else {
            let parent = self
                .headers
                .get(&parent_id)
                .ok_or(FollowError::UnknownParent)?;
            if height != parent.height + 1 {
                return Err(FollowError::HeightGap {
                    expected_parent: parent.height,
                    got: height,
                });
            }
            &parent.cumulative_work + &work
        };

        let node = FollowedHeader {
            id,
            parent_id,
            height,
            work,
            cumulative_work: cumulative_work.clone(),
            level,
        };
        self.headers.insert(id, node);

        // Fork choice: heaviest cumulative work wins; ties keep the
        // incumbent.
        match self.best_tip {
            None => {
                self.best_tip = Some(id);
                Ok(Ingest::Root)
            }
            Some(old_tip) => {
                let best_work = &self.headers[&old_tip].cumulative_work;
                if cumulative_work > *best_work {
                    self.best_tip = Some(id);
                    if parent_id == old_tip {
                        Ok(Ingest::Extended)
                    } else {
                        Ok(Ingest::Reorg {
                            depth: self.reorg_depth(old_tip, id),
                        })
                    }
                } else {
                    Ok(Ingest::SideBranch)
                }
            }
        }
    }

    /// Depth (blocks rolled back) of a reorg from `old_tip` to the new
    /// `new_tip`: the number of `old_tip`-chain blocks above the common
    /// ancestor of the two branches.
    fn reorg_depth(&self, old_tip: [u8; 32], new_tip: [u8; 32]) -> u32 {
        let mut new_ancestors: HashSet<[u8; 32]> = HashSet::new();
        let mut cur = Some(new_tip);
        while let Some(id) = cur {
            if !new_ancestors.insert(id) {
                break; // defensive: never loop on a cycle
            }
            cur = self
                .headers
                .get(&id)
                .map(|h| h.parent_id)
                .filter(|p| self.headers.contains_key(p));
        }

        let mut depth = 0;
        let mut node = self.headers.get(&old_tip);
        while let Some(h) = node {
            if new_ancestors.contains(&h.id) {
                break;
            }
            depth += 1;
            node = self.headers.get(&h.parent_id);
        }
        depth
    }

    /// The current best (heaviest-cumulative-work) tip.
    pub fn tip(&self) -> Option<&FollowedHeader> {
        self.best_tip.and_then(|id| self.headers.get(&id))
    }

    /// Height of the current best tip.
    pub fn tip_height(&self) -> Option<u32> {
        self.tip().map(|h| h.height)
    }

    /// Cumulative work of the current best tip.
    pub fn cumulative_work(&self) -> Option<BigUint> {
        self.tip().map(|h| h.cumulative_work.clone())
    }

    /// The settled reference at `tip_height − N_mint` on the best chain —
    /// the deterministic comparison point the peg-in work-policy needs.
    /// `None` until the followed chain is at least `N_mint` deep (or if a
    /// parent link along the way is missing).
    pub fn settled_reference(&self) -> Option<SettledRef> {
        let tip = self.tip()?;
        let target = u64::from(tip.height).checked_sub(self.n_mint)?;
        let mut cur = tip;
        while u64::from(cur.height) > target {
            // Strictly-decreasing height guards termination even on a
            // degenerate self-parenting entry (impossible for real
            // headers — an id is a hash over its parent link).
            let parent = self.headers.get(&cur.parent_id)?;
            if parent.height >= cur.height {
                return None;
            }
            cur = parent;
        }
        Some(SettledRef {
            id: cur.id,
            height: cur.height,
            cumulative_work: cur.cumulative_work.clone(),
        })
    }

    /// The followed **best chain truncated to `h_ref`**, as the
    /// membership + μ-level view the peg-in comparative work-policy
    /// scores against (g25 §2b): every best-chain header with
    /// `height <= h_ref`, from the followed root up.
    ///
    /// Returns `None` if the best tip has not reached `h_ref` (the
    /// follower is not caught up — the §2b.ii bootstrap caveat) or if a
    /// parent link is missing along the walk (defensive; cannot happen
    /// for headers accepted by [`Follower::apply_header`]).
    pub fn settled_view(&self, h_ref: u32) -> Option<SettledView> {
        let tip = self.tip()?;
        if tip.height < h_ref {
            return None;
        }
        // Walk down the best chain to the header at h_ref… (both walks
        // guard termination on strictly-decreasing heights: a
        // self-parenting/cyclic entry is impossible for real headers —
        // an id is a hash over its parent link — but the walk must not
        // hinge on that.)
        let mut cur = tip;
        while cur.height > h_ref {
            let parent = self.headers.get(&cur.parent_id)?;
            if parent.height >= cur.height {
                return None;
            }
            cur = parent;
        }
        if cur.height != h_ref {
            return None; // height gap below h_ref (defensive)
        }
        // …then keep walking to the root, collecting the settled chain.
        let mut heights_by_id = HashMap::new();
        let mut levels_desc: Vec<(u32, u32)> = Vec::new();
        loop {
            heights_by_id.insert(cur.id, cur.height);
            levels_desc.push((cur.height, cur.level));
            match self.headers.get(&cur.parent_id) {
                Some(parent) if parent.height < cur.height => cur = parent,
                // Absent parent = the followed root; a non-decreasing
                // "parent" is treated the same (degenerate input).
                _ => break,
            }
        }
        levels_desc.reverse();
        Some(SettledView {
            heights_by_id,
            levels_asc: levels_desc,
            h_ref,
        })
    }

    /// Number of headers currently tracked (all branches).
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Whether no header has been followed yet.
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

/// Poller adapter — keeps network I/O **out** of the state machine.
///
/// A [`HeaderSource`] yields decoded Ergo headers in ascending height;
/// [`drive`] pulls from it and folds each into the [`Follower`]. This
/// decoupling is what makes the state machine testable without a node.
///
/// ## Live-source status
/// The live transport is [`poll_http::RestHeaderSource`]: a blocking
/// `reqwest` client over the node's `/blocks/chainSlice`, decoding
/// each element via `ergo_rest_json::decode_scala_header_struct` —
/// the decode whose parity is pinned against live-Scala-node JSON by
/// the id/PoW oracle in
/// `ergo-rest-json/tests/headers_json_scala_oracle.rs`. The
/// [`HeaderSource`](poll::HeaderSource) trait stays sync on purpose:
/// the tokio main loop wraps [`drive`](poll::drive) in
/// `spawn_blocking` when it wires the source in (a separate step —
/// nothing here touches the node's runtime). The loop itself remains
/// exercised against an in-memory source that yields real
/// (byte-decoded) headers.
pub mod poll {
    use super::{ErgoHeader, Follower, Ingest};

    /// A source of Ergo headers in ascending height. Implementors own
    /// all I/O; the state machine sees only decoded headers.
    pub trait HeaderSource {
        type Error;
        /// Fetch the next batch of headers at heights `>= from_height`
        /// (possibly empty if the source is caught up).
        fn next_headers(&mut self, from_height: u32) -> Result<Vec<ErgoHeader>, Self::Error>;
    }

    /// An in-memory source over pre-decoded headers — used to exercise
    /// the loop deterministically and to feed headers a live decoder
    /// would produce.
    pub struct VecHeaderSource {
        headers: Vec<ErgoHeader>,
    }

    impl VecHeaderSource {
        pub fn new(headers: Vec<ErgoHeader>) -> Self {
            Self { headers }
        }
    }

    impl HeaderSource for VecHeaderSource {
        type Error = std::convert::Infallible;
        fn next_headers(&mut self, from_height: u32) -> Result<Vec<ErgoHeader>, Self::Error> {
            Ok(self
                .headers
                .iter()
                .filter(|h| h.height >= from_height)
                .cloned()
                .collect())
        }
    }

    /// Pull every currently-available header from `source` and fold it
    /// into `follower`, starting at `from_height`. Returns the ingest
    /// outcomes in order. Errors from the follower (invalid PoW, orphan)
    /// stop the drive and propagate; a source error propagates as-is.
    pub fn drive<S: HeaderSource>(
        follower: &mut Follower,
        source: &mut S,
        from_height: u32,
    ) -> Result<Vec<Ingest>, DriveError<S::Error>> {
        let headers = source
            .next_headers(from_height)
            .map_err(DriveError::Source)?;
        let mut outcomes = Vec::with_capacity(headers.len());
        for h in &headers {
            let outcome = follower.apply_header(h).map_err(DriveError::Follow)?;
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    #[derive(Debug, thiserror::Error)]
    pub enum DriveError<E> {
        #[error("header source error")]
        Source(#[source] E),
        #[error(transparent)]
        Follow(#[from] super::FollowError),
    }
}

/// Live HTTP transport for [`poll::HeaderSource`] — a blocking-reqwest
/// client over the node REST's `GET /blocks/chainSlice`.
///
/// ## `chainSlice` bound semantics (verified live)
/// On the reference node `fromHeight` is **exclusive** and `toHeight`
/// **inclusive**: `fromHeight=100&toHeight=103` returns heights
/// 101..=103 (verified against the live Scala testnet node
/// `arks-testnet-node` 6.0.3 @ 127.0.0.1:9062, 2026-07-13 — the same
/// semantics the committed capture
/// `test-vectors/testnet/nipopow/scala_headers_442813_442815.json`
/// shows: `fromHeight=442812&toHeight=442815` → 442813..=442815).
/// Two further live-verified edge behaviors shape the code:
/// - a `toHeight` past the tip is truncated at the tip;
/// - a request **entirely past the tip is clamped to the tip** — the
///   node returns the current tip header rather than an empty array
///   (`fromHeight=tip+5` → `[tip]`). [`RestHeaderSource`] therefore
///   drops decoded headers below the requested `from_height`; without
///   that filter a caught-up [`poll::drive`] loop would ingest an
///   eternal `Duplicate` instead of ever seeing the empty batch that
///   means "caught up".
///
/// Blocking on purpose: [`poll::HeaderSource`] is sync, and the tokio
/// main loop is expected to wrap [`poll::drive`] in `spawn_blocking`
/// when it wires this in. Do **not** call this source from inside an
/// async context directly — `reqwest::blocking` panics there.
pub mod poll_http {
    use std::time::Duration;

    use ergo_rest_json::decode_scala_header_struct;
    use ergo_rest_json::types::ScalaHeader;

    use super::poll::HeaderSource;
    use super::ErgoHeader;

    /// Default `page_size`: headers fetched per `next_headers` call.
    /// The live node serves ≥1000-header slices in one response, so
    /// this is a politeness/latency trade-off, not a node limit.
    pub const DEFAULT_PAGE_SIZE: u32 = 256;

    /// Default per-request timeout (connect + response).
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

    /// Configuration for [`RestHeaderSource`].
    #[derive(Debug, Clone)]
    pub struct RestSourceConfig {
        /// Node REST base URL, e.g. `http://127.0.0.1:9062` (a trailing
        /// slash is tolerated). Plain HTTP only — the crate links no
        /// TLS backend (the follower talks to a local/LAN node).
        pub base_url: String,
        /// Optional node API key, sent as the `api_key` header.
        /// `GET /blocks/chainSlice` is normally open; this covers
        /// nodes that lock the whole API down.
        pub api_key: Option<String>,
        /// Headers requested per batch (clamped to ≥ 1).
        pub page_size: u32,
        /// Per-request timeout.
        pub timeout: Duration,
    }

    impl RestSourceConfig {
        /// A config with default paging/timeout and no API key.
        pub fn new(base_url: impl Into<String>) -> Self {
            Self {
                base_url: base_url.into(),
                api_key: None,
                page_size: DEFAULT_PAGE_SIZE,
                timeout: DEFAULT_TIMEOUT,
            }
        }
    }

    /// Errors from the REST header source, split by what the caller
    /// may do about them: transport-level failures
    /// ([`RestSourceError::is_retryable`] = `true`) are worth polling
    /// again later; malformed or undecodable node data is not — a
    /// retry would fetch the same bytes.
    #[derive(Debug, thiserror::Error)]
    pub enum RestSourceError {
        /// The HTTP client itself could not be built (TLS/config).
        #[error("building blocking HTTP client")]
        Client(#[source] reqwest::Error),
        /// The request never produced an HTTP response (connect,
        /// timeout, mid-body I/O). Retryable.
        #[error("GET {url} failed")]
        Network {
            url: String,
            #[source]
            source: reqwest::Error,
        },
        /// The node answered with a non-2xx status. Retryable — the
        /// usual causes (node restarting, 503 during sync) are
        /// transient.
        #[error("GET {url}: HTTP status {status}")]
        Status { url: String, status: u16 },
        /// The response body is not a JSON array of header objects.
        /// Not retryable.
        #[error("chainSlice body is not a JSON header array: {detail}")]
        Parse { detail: String },
        /// A header element parsed as JSON but failed the consensus
        /// decode (`decode_scala_header_struct`). Not retryable.
        #[error("header at height {height} failed consensus decode ({kind}): {detail}")]
        Decode {
            height: u32,
            kind: &'static str,
            detail: String,
        },
        /// The slice's heights were not strictly ascending — the node
        /// walks its best chain, so this is a protocol violation, not
        /// a transient. Not retryable.
        #[error("chainSlice heights not strictly ascending: {prev} then {next}")]
        NonAscending { prev: u32, next: u32 },
    }

    impl RestSourceError {
        /// Whether retrying the same request later can plausibly
        /// succeed (transport-level failure) — `false` means the node
        /// returned data we reject, and a retry would refetch it.
        pub fn is_retryable(&self) -> bool {
            matches!(
                self,
                RestSourceError::Network { .. } | RestSourceError::Status { .. }
            )
        }
    }

    /// [`HeaderSource`] over a live node's `GET /blocks/chainSlice`.
    #[derive(Debug)]
    pub struct RestHeaderSource {
        config: RestSourceConfig,
        client: reqwest::blocking::Client,
    }

    impl RestHeaderSource {
        pub fn new(config: RestSourceConfig) -> Result<Self, RestSourceError> {
            let client = reqwest::blocking::Client::builder()
                .timeout(config.timeout)
                .build()
                .map_err(RestSourceError::Client)?;
            Ok(Self { config, client })
        }
    }

    impl HeaderSource for RestHeaderSource {
        type Error = RestSourceError;

        fn next_headers(&mut self, from_height: u32) -> Result<Vec<ErgoHeader>, Self::Error> {
            let (from_excl, to_incl) = slice_bounds(from_height, self.config.page_size);
            let url = format!(
                "{}/blocks/chainSlice?fromHeight={from_excl}&toHeight={to_incl}",
                self.config.base_url.trim_end_matches('/'),
            );
            let mut request = self.client.get(&url);
            if let Some(key) = &self.config.api_key {
                request = request.header("api_key", key);
            }
            let response = request.send().map_err(|e| RestSourceError::Network {
                url: url.clone(),
                source: e,
            })?;
            let status = response.status();
            if !status.is_success() {
                return Err(RestSourceError::Status {
                    url,
                    status: status.as_u16(),
                });
            }
            let body = response
                .text()
                .map_err(|e| RestSourceError::Network { url, source: e })?;
            parse_chain_slice_body(&body, from_height)
        }
    }

    /// `chainSlice` query bounds for a batch of up to `page_size`
    /// headers at heights `>= from_height`: the node treats
    /// `fromHeight` as exclusive and `toHeight` as inclusive (see the
    /// module doc), so ask for `(from_height − 1, from_height − 1 +
    /// page_size]`. `from_height` 0 and 1 coincide (heights start
    /// at 1).
    fn slice_bounds(from_height: u32, page_size: u32) -> (u32, u32) {
        let from_excl = from_height.saturating_sub(1);
        let to_incl = from_excl.saturating_add(page_size.max(1));
        (from_excl, to_incl)
    }

    /// Decode a `chainSlice` response body into ascending
    /// [`ErgoHeader`]s at heights `>= from_height`. Headers below
    /// `from_height` are dropped (the node clamps a beyond-tip request
    /// to its tip instead of returning an empty array — live-verified;
    /// see the module doc), which is what lets a caught-up drive loop
    /// observe an empty batch.
    fn parse_chain_slice_body(
        body: &str,
        from_height: u32,
    ) -> Result<Vec<ErgoHeader>, RestSourceError> {
        let dtos: Vec<ScalaHeader> =
            serde_json::from_str(body).map_err(|e| RestSourceError::Parse {
                detail: e.to_string(),
            })?;
        let mut headers = Vec::with_capacity(dtos.len());
        let mut prev_height: Option<u32> = None;
        for dto in &dtos {
            if dto.height < from_height {
                continue;
            }
            if let Some(prev) = prev_height {
                if dto.height <= prev {
                    return Err(RestSourceError::NonAscending {
                        prev,
                        next: dto.height,
                    });
                }
            }
            prev_height = Some(dto.height);
            let header = decode_scala_header_struct(dto).map_err(|(kind, detail)| {
                RestSourceError::Decode {
                    height: dto.height,
                    kind,
                    detail,
                }
            })?;
            headers.push(header);
        }
        Ok(headers)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::Path;

        // ----- helpers -----

        /// The committed live capture — a verbatim
        /// `GET /blocks/chainSlice?fromHeight=442812&toHeight=442815`
        /// response body (Scala testnet node, heights 442813..=442815),
        /// used here as the HTTP-body fixture.
        fn chain_slice_body() -> String {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("test-vectors/testnet/nipopow/scala_headers_442813_442815.json");
            std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        }

        // ----- happy path -----

        #[test]
        fn chain_slice_capture_decodes_ascending_from_requested_height() {
            // The capture was fromHeight=442812 (exclusive) — the batch
            // a `next_headers(442813)` call requests.
            let headers = parse_chain_slice_body(&chain_slice_body(), 442_813).unwrap();
            let heights: Vec<u32> = headers.iter().map(|h| h.height).collect();
            assert_eq!(heights, vec![442_813, 442_814, 442_815]);
        }

        #[test]
        fn chain_slice_below_from_height_headers_are_dropped() {
            // Simulates the node's beyond-tip clamp: the body holds the
            // tip run, the caller asked from a later height.
            let headers = parse_chain_slice_body(&chain_slice_body(), 442_815).unwrap();
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].height, 442_815);
            let caught_up = parse_chain_slice_body(&chain_slice_body(), 442_816).unwrap();
            assert!(
                caught_up.is_empty(),
                "clamped tip re-serve filters to empty"
            );
        }

        // ----- pagination arithmetic (chainSlice off-by-one) -----

        #[test]
        fn slice_bounds_encode_exclusive_from_inclusive_to() {
            // next_headers(from) must receive heights from..=from+page-1,
            // so the exclusive fromHeight is from-1.
            assert_eq!(slice_bounds(442_813, 3), (442_812, 442_815));
            assert_eq!(slice_bounds(100, 50), (99, 149));
        }

        #[test]
        fn slice_bounds_genesis_and_zero_page_edges_stay_in_range() {
            // Heights start at 1: from_height 0 and 1 both start the
            // slice at exclusive-0.
            assert_eq!(slice_bounds(1, 10), (0, 10));
            assert_eq!(slice_bounds(0, 10), (0, 10));
            // page_size 0 is clamped to 1, never an empty/inverted range.
            assert_eq!(slice_bounds(5, 0), (4, 5));
            // No u32 overflow at the top of the range.
            assert_eq!(slice_bounds(u32::MAX, 10), (u32::MAX - 1, u32::MAX));
        }

        // ----- error paths -----

        #[test]
        fn non_json_body_is_parse_error_not_retryable() {
            let err = parse_chain_slice_body("<html>502 Bad Gateway</html>", 1).unwrap_err();
            assert!(matches!(err, RestSourceError::Parse { .. }), "{err:?}");
            assert!(!err.is_retryable());
        }

        #[test]
        fn corrupt_header_field_is_decode_error_not_retryable() {
            // Truncate the first header's stateRoot to 32 bytes — JSON
            // still parses, the consensus decode must reject it.
            let mut v: Vec<serde_json::Value> = serde_json::from_str(&chain_slice_body()).unwrap();
            let root = v[0]["stateRoot"].as_str().unwrap().to_owned();
            v[0]["stateRoot"] = serde_json::Value::String(root[..64].to_owned());
            let body = serde_json::to_string(&v).unwrap();
            let err = parse_chain_slice_body(&body, 442_813).unwrap_err();
            match &err {
                RestSourceError::Decode { height, .. } => assert_eq!(*height, 442_813),
                other => panic!("expected Decode, got {other:?}"),
            }
            assert!(!err.is_retryable());
        }

        #[test]
        fn non_ascending_heights_are_rejected() {
            let mut v: Vec<serde_json::Value> = serde_json::from_str(&chain_slice_body()).unwrap();
            v.reverse();
            let body = serde_json::to_string(&v).unwrap();
            let err = parse_chain_slice_body(&body, 442_813).unwrap_err();
            assert!(
                matches!(err, RestSourceError::NonAscending { .. }),
                "{err:?}"
            );
            assert!(!err.is_retryable());
        }

        #[test]
        fn network_and_status_errors_are_retryable() {
            // Status is constructible directly; Network carries a real
            // reqwest error, produced here by a connect to a reserved
            // port on localhost via the real client path.
            let status = RestSourceError::Status {
                url: "http://x/blocks/chainSlice".into(),
                status: 503,
            };
            assert!(status.is_retryable());

            let mut source = RestHeaderSource::new(RestSourceConfig {
                base_url: "http://127.0.0.1:9".into(), // discard port — nothing listens
                api_key: None,
                page_size: 4,
                timeout: Duration::from_millis(300),
            })
            .unwrap();
            let err = source.next_headers(1).unwrap_err();
            assert!(matches!(err, RestSourceError::Network { .. }), "{err:?}");
            assert!(err.is_retryable());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::poll::{drive, VecHeaderSource};
    use super::*;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::read_header;
    use std::path::{Path, PathBuf};

    // ----- helpers -----

    fn vectors_dir() -> PathBuf {
        // aegis-node/ -> repo root -> test-vectors/mainnet
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test-vectors/mainnet")
    }

    /// Load a run of REAL mainnet headers (valid PoW, real difficulty)
    /// as decoded `ErgoHeader`s — the oracle for the PoW gate and the
    /// work arithmetic. Each vector's `bytes` field is the consensus
    /// header serialization.
    fn load_real_headers(file: &str) -> Vec<ErgoHeader> {
        let path = vectors_dir().join(file);
        let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {file}: {e}"));
        let vectors: serde_json::Value =
            serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {file}: {e}"));
        vectors
            .as_array()
            .expect("header vectors are a JSON array")
            .iter()
            .map(|v| {
                let hex_bytes = v["bytes"].as_str().expect("bytes field");
                let raw = hex::decode(hex_bytes).expect("hex");
                let mut r = VlqReader::new(&raw);
                read_header(&mut r).expect("real header decodes")
            })
            .collect()
    }

    fn id_of(h: &ErgoHeader) -> [u8; 32] {
        *serialize_header(h).unwrap().1.as_bytes()
    }

    // ----- happy path (real PoW oracle) -----

    #[test]
    fn follows_consecutive_v1_chain_and_sums_real_work() {
        // 10 consecutive mainnet v1 headers (Autolykos v1 PoW).
        let headers = load_real_headers("headers_1_10.json");
        assert_eq!(headers.len(), 10);
        let mut f = Follower::new(3);

        assert_eq!(f.apply_header(&headers[0]).unwrap(), Ingest::Root);
        let mut expected_work = decode_compact_bits(headers[0].n_bits);
        for h in &headers[1..] {
            assert_eq!(f.apply_header(h).unwrap(), Ingest::Extended);
            expected_work += decode_compact_bits(h.n_bits);
        }

        assert_eq!(f.tip_height(), Some(headers[9].height));
        assert_eq!(f.cumulative_work(), Some(expected_work));
        assert_eq!(f.len(), 10);
    }

    #[test]
    fn follows_consecutive_v2_chain_autolykos_v2_pow() {
        // 4 consecutive mainnet v4 headers → Autolykos v2 PoW path.
        let headers = load_real_headers("headers_1761792_1761795_eip37_curated.json");
        assert_eq!(headers.len(), 4);
        let mut f = Follower::new(2);

        assert_eq!(f.apply_header(&headers[0]).unwrap(), Ingest::Root);
        for h in &headers[1..] {
            assert_eq!(f.apply_header(h).unwrap(), Ingest::Extended);
        }
        assert_eq!(f.tip_height(), Some(1761795));
    }

    #[test]
    fn poller_drive_folds_real_headers_through_the_source_seam() {
        let headers = load_real_headers("headers_1_10.json");
        let mut f = Follower::new(3);
        let mut src = VecHeaderSource::new(headers.clone());
        let outcomes = drive(&mut f, &mut src, headers[0].height).unwrap();
        assert_eq!(outcomes.len(), 10);
        assert_eq!(outcomes[0], Ingest::Root);
        assert!(outcomes[1..].iter().all(|o| *o == Ingest::Extended));
        assert_eq!(f.tip_height(), Some(10));
    }

    // ----- settled reference -----

    #[test]
    fn settled_reference_is_tip_minus_n_mint_on_real_chain() {
        let headers = load_real_headers("headers_1_10.json");
        let mut f = Follower::new(3); // N_mint = 3
        for h in &headers {
            f.apply_header(h).unwrap();
        }
        // tip height 10, settle at 10 - 3 = 7.
        let settled = f.settled_reference().expect("chain is deep enough");
        assert_eq!(settled.height, 7);
        assert_eq!(settled.id, id_of(&headers[6])); // heights[6] == height 7
                                                    // cumulative work at height 7 = sum of b over headers 1..=7.
        let expected: BigUint = headers[..7]
            .iter()
            .map(|h| decode_compact_bits(h.n_bits))
            .sum();
        assert_eq!(settled.cumulative_work, expected);
    }

    #[test]
    fn settled_reference_none_until_chain_is_n_mint_deep() {
        let headers = load_real_headers("headers_1_10.json");
        let mut f = Follower::new(100); // deeper than the chain
        for h in &headers {
            f.apply_header(h).unwrap();
        }
        assert_eq!(f.settled_reference(), None);
    }

    // ----- error paths -----

    #[test]
    fn corrupted_pow_solution_is_rejected() {
        use ergo_ser::autolykos::AutolykosSolution;
        let mut headers = load_real_headers("headers_1_10.json");
        // Flip the Autolykos nonce so the PoW no longer solves.
        let bad = &mut headers[0];
        match &mut bad.solution {
            AutolykosSolution::V1 { nonce, .. } | AutolykosSolution::V2 { nonce, .. } => {
                nonce[0] ^= 0xFF;
            }
        }
        let mut f = Follower::new(3);
        assert_eq!(f.apply_header(bad), Err(FollowError::InvalidPow));
        assert!(f.is_empty(), "a rejected header never touches the chain");
    }

    #[test]
    fn header_with_absent_parent_is_orphan_rejected() {
        let headers = load_real_headers("headers_1_10.json");
        let mut f = Follower::new(3);
        f.apply_header(&headers[0]).unwrap(); // root at height 1
                                              // skip height 2, feed height 3: its parent (h2) is unknown.
        assert_eq!(f.apply_header(&headers[2]), Err(FollowError::UnknownParent));
    }

    #[test]
    fn pinned_root_rejects_a_different_first_header() {
        let headers = load_real_headers("headers_1_10.json");
        let mut f = Follower::with_root(3, [0xAB; 32]); // wrong pin
        assert_eq!(f.apply_header(&headers[0]), Err(FollowError::RootMismatch));
    }

    #[test]
    fn pinned_root_accepts_the_matching_first_header() {
        let headers = load_real_headers("headers_1_10.json");
        let root_id = id_of(&headers[0]);
        let mut f = Follower::with_root(3, root_id);
        assert_eq!(f.apply_header(&headers[0]).unwrap(), Ingest::Root);
    }

    // ----- fork choice / reorg (bookkeeping layer) -----
    //
    // Real mainnet vectors are a single linear chain, so the SWITCH path
    // is exercised through `apply_verified_header` with synthetic branch
    // *metadata* (work values, not PoW-bearing bytes). The PoW gate is
    // covered separately above against real headers.

    fn h(id: u8) -> [u8; 32] {
        [id; 32]
    }

    #[test]
    fn heavier_branch_triggers_reorg_with_correct_depth() {
        let mut f = Follower::new(2);
        // root A0 (h1) -> A1 (h2) -> A2 (h3), light per-block work = 1.
        f.apply_verified_header(h(0), [0u8; 32], 1, BigUint::from(1u32), 0)
            .unwrap();
        f.apply_verified_header(h(1), h(0), 2, BigUint::from(1u32), 0)
            .unwrap();
        assert_eq!(
            f.apply_verified_header(h(2), h(1), 3, BigUint::from(1u32), 0)
                .unwrap(),
            Ingest::Extended
        );
        assert_eq!(f.tip_height(), Some(3)); // best = A2, cum work 3

        // Competing branch off A0: B1 (h2) with heavy work, then B2 (h3)
        // heavier still — total beats A2, forcing a 2-block reorg.
        assert_eq!(
            f.apply_verified_header(h(11), h(0), 2, BigUint::from(1u32), 0)
                .unwrap(),
            Ingest::SideBranch // cum 2 < 3, not yet best
        );
        assert_eq!(
            f.apply_verified_header(h(12), h(11), 3, BigUint::from(5u32), 0)
                .unwrap(),
            Ingest::Reorg { depth: 2 } // rolls back A1, A2
        );
        assert_eq!(f.tip().unwrap().id, h(12));
        assert_eq!(f.tip_height(), Some(3));
        assert_eq!(f.cumulative_work(), Some(BigUint::from(7u32))); // 1+1+5
    }

    #[test]
    fn equal_work_keeps_the_incumbent_tip() {
        let mut f = Follower::new(1);
        f.apply_verified_header(h(0), [0u8; 32], 1, BigUint::from(1u32), 0)
            .unwrap();
        f.apply_verified_header(h(1), h(0), 2, BigUint::from(2u32), 0)
            .unwrap();
        let incumbent = f.tip().unwrap().id;
        // A competing height-2 block with identical cumulative work.
        assert_eq!(
            f.apply_verified_header(h(2), h(0), 2, BigUint::from(2u32), 0)
                .unwrap(),
            Ingest::SideBranch
        );
        assert_eq!(f.tip().unwrap().id, incumbent);
    }

    #[test]
    fn duplicate_header_is_idempotent() {
        let headers = load_real_headers("headers_1_10.json");
        let mut f = Follower::new(3);
        f.apply_header(&headers[0]).unwrap();
        assert_eq!(f.apply_header(&headers[0]).unwrap(), Ingest::Duplicate);
        assert_eq!(f.len(), 1);
    }

    // ----- settled view (work-policy reference) -----

    #[test]
    fn real_headers_record_their_popow_levels() {
        use ergo_validation::popow::max_level_of;
        let headers = load_real_headers("headers_1_10.json");
        let mut f = Follower::new(3);
        for h in &headers {
            f.apply_header(h).unwrap();
        }
        for h in &headers {
            let followed = f.headers.get(&id_of(h)).expect("followed");
            assert_eq!(
                followed.level,
                max_level_of(h),
                "h={}: recorded level must equal max_level_of",
                h.height
            );
        }
    }

    #[test]
    fn settled_view_holds_best_chain_up_to_h_ref_only() {
        let headers = load_real_headers("headers_1_10.json");
        let mut f = Follower::new(3);
        for h in &headers {
            f.apply_header(h).unwrap();
        }
        let view = f.settled_view(7).expect("caught up past 7");
        assert_eq!(view.h_ref, 7);
        assert_eq!(view.len(), 7);
        // Heights 1..=7 present with correct heights; 8..=10 absent.
        for h in &headers[..7] {
            assert_eq!(view.height_of(&id_of(h)), Some(h.height));
        }
        for h in &headers[7..] {
            assert_eq!(
                view.height_of(&id_of(h)),
                None,
                "h={} beyond h_ref",
                h.height
            );
        }
    }

    #[test]
    fn settled_view_levels_above_returns_divergent_suffix_levels() {
        use ergo_validation::popow::max_level_of;
        let headers = load_real_headers("headers_1_10.json");
        let mut f = Follower::new(3);
        for h in &headers {
            f.apply_header(h).unwrap();
        }
        let view = f.settled_view(7).expect("caught up");
        // Above height 4 within h_ref=7: exactly heights 5, 6, 7.
        let expected: Vec<u32> = headers[4..7].iter().map(max_level_of).collect();
        assert_eq!(view.levels_above(4), expected);
        // Above h_ref itself: empty.
        assert!(view.levels_above(7).is_empty());
    }

    #[test]
    fn settled_view_none_when_follower_not_caught_up() {
        let headers = load_real_headers("headers_1_10.json");
        let mut f = Follower::new(3);
        for h in &headers[..5] {
            f.apply_header(h).unwrap();
        }
        assert!(f.settled_view(7).is_none(), "tip 5 < h_ref 7");
        assert!(f.settled_view(5).is_some());
    }

    #[test]
    fn settled_view_walks_the_best_branch_after_reorg() {
        // Root (h1) -> A2 (h2, level 9) vs B2+B3 heavier branch
        // (levels 1, 1). After the reorg the settled view at h_ref=2
        // must report B2's level, not A2's.
        let mut f = Follower::new(1);
        f.apply_verified_header(h(0), [0u8; 32], 1, BigUint::from(1u32), 0)
            .unwrap();
        f.apply_verified_header(h(1), h(0), 2, BigUint::from(1u32), 9)
            .unwrap();
        f.apply_verified_header(h(11), h(0), 2, BigUint::from(1u32), 1)
            .unwrap();
        assert_eq!(
            f.apply_verified_header(h(12), h(11), 3, BigUint::from(5u32), 1)
                .unwrap(),
            Ingest::Reorg { depth: 1 }
        );
        let view = f.settled_view(2).expect("best tip at 3 >= 2");
        assert_eq!(view.height_of(&h(11)), Some(2), "B2 on best chain");
        assert_eq!(view.height_of(&h(1)), None, "A2 rolled back");
        assert_eq!(view.levels_above(1), vec![1], "B2's level, not A2's 9");
    }

    #[test]
    fn height_gap_on_verified_child_is_rejected() {
        let mut f = Follower::new(1);
        f.apply_verified_header(h(0), [0u8; 32], 1, BigUint::from(1u32), 0)
            .unwrap();
        // child claims height 5 off a height-1 parent.
        assert_eq!(
            f.apply_verified_header(h(1), h(0), 5, BigUint::from(1u32), 0),
            Err(FollowError::HeightGap {
                expected_parent: 1,
                got: 5
            })
        );
    }
}
