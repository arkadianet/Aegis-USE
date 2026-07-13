//! Ergo anchor-watcher — the glue between the live Ergo chain and the
//! Aegis fork-choice (merge-mining.md §2/§5/§7 — M6a).
//!
//! The pipeline, per followed Ergo block:
//!
//! 1. **Fetch** the block's extension fields ([`BlockSource`]; live
//!    transport [`fetch_http::RestBlockSource`] over
//!    `GET /blocks/{headerId}`, in-memory [`MemoryBlockSource`] for
//!    tests).
//! 2. **Authenticate + extract** ([`extract_commitment`]): the served
//!    field set must re-hash to the header's PoW-committed
//!    `extension_root` — only then is "no [`AEGIS_MM_KEY`] field" a
//!    sound *no-commitment* verdict (a lying REST server cannot hide a
//!    commitment by omitting its field). If the key is present, build
//!    the field's batch-merkle proof — the `(ergo_header, field,
//!    proof)` triple [`crate::auxpow::verify_share`] consumes.
//! 3. **Verify + feed**: resolve the committed Aegis id against an
//!    [`AegisSource`] (in-memory seed for M6a; P2P is M6b), verify the
//!    share with the follower's tip as the C2 height window and the
//!    fork-choice's own DAA view
//!    ([`crate::mm_forkchoice::MmForkChoice::daa_view`]), then
//!    `ingest_share` + `record_anchor` (+ `ingest_body` when the full
//!    block is known).
//! 4. **Finality plumbing** ([`settled_is_final`]): `is_final` judged
//!    at `Follower::settled_reference().height` — the single
//!    caught-up-follower caller contract the M2b review documented.
//!
//! [`AnchorWatch::drive`] composes the whole loop: pull headers from a
//! [`crate::ergo_follow::poll::HeaderSource`], PoW-gate them through
//! the [`Follower`], scan each accepted header. It is a pure function
//! of its sources — deterministic and testable without a node.
//!
//! ## Anchors and best-chain membership
//!
//! Every verified share feeds `ingest_share` (aux-PoW work is work no
//! matter which Ergo branch carried it), but [`MmForkChoice::record_anchor`]
//! is only called for headers on the follower's best chain at scan
//! time (§7 anchors are *Ergo-chain inclusions*, not mere candidates).
//! A deep Ergo reorg can orphan a recorded anchor; `is_final` only
//! consults anchors at or below the settled reference (`N_mint` deep),
//! which is the same reorg-safety margin the peg relies on. Re-checking
//! recorded anchors against the settled chain is deferred to M6b.
//!
//! ## Retry buffers (monotone, height-window bounded)
//!
//! A block-source failure re-buffers the header (`unscanned`); a
//! commitment whose Aegis block or validated parent chain is unknown is
//! buffered (`unresolved`). Both retry on the next drive and expire
//! once the C2 window moves past them (`follower_tip − k_lag`) — a
//! share that old could never verify again, so the buffers self-bound.
//!
//! Everything fetched is DATA, never instructions: fields are
//! authenticated against PoW-committed roots, ids are recomputed, and
//! `verify_share` re-derives every claim from presented bytes.
//!
//! **DO NOT WIRE into `main.rs`'s producer loop yet.** M6a delivers
//! the watcher + the Ergo→share→fork-choice pipeline in isolation; the
//! main-loop integration lands with M6b (P2P body/share gossip), which
//! also replaces the seed [`AegisSource`].

use std::collections::BTreeMap;

use ergo_crypto::merkle::{extension_root, merkle_proof_by_indices};
use ergo_ser::batch_merkle_proof::{BatchMerkleProof, ProofEntry, Side};
use ergo_ser::extension::ExtensionField;
use ergo_ser::header::{serialize_header, Header as ErgoHeader};
use num_bigint::BigUint;

use aegis_spec::{Network, AEGIS_MM_KEY, K_LAG, MM_COMMITMENT_VERSION, MM_FIELD_VALUE_LEN};

use crate::auxpow::{kv_to_leaf, verify_share, ShareContext, ShareError};
use crate::block::Block;
use crate::daa::DaaParams;
use crate::ergo_follow::poll::HeaderSource;
use crate::ergo_follow::{FollowError, Follower, Ingest};
use crate::header::Header as AegisHeader;
use crate::mm_forkchoice::{BodyIngest, MmForkChoice, ShareIngest};

/// Source of an Ergo block's extension fields, by header id. The
/// returned fields are UNTRUSTED data — [`extract_commitment`]
/// authenticates them against the header's PoW-committed
/// `extension_root` before drawing any conclusion from them.
pub trait BlockSource {
    type Error;
    /// The extension key-value fields of the Ergo block `header_id`.
    fn extension_fields(
        &mut self,
        header_id: &[u8; 32],
    ) -> Result<Vec<ExtensionField>, Self::Error>;
}

/// In-memory [`BlockSource`] — deterministic tests and seeding.
#[derive(Debug, Default)]
pub struct MemoryBlockSource {
    fields: BTreeMap<[u8; 32], Vec<ExtensionField>>,
}

/// [`MemoryBlockSource`] miss: no fields recorded for this header id.
#[derive(Debug, thiserror::Error)]
#[error("no extension fields recorded for ergo block {}", hex::encode(.0))]
pub struct MissingBlock(pub [u8; 32]);

impl MemoryBlockSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, header_id: [u8; 32], fields: Vec<ExtensionField>) {
        self.fields.insert(header_id, fields);
    }
}

impl BlockSource for MemoryBlockSource {
    type Error = MissingBlock;
    fn extension_fields(
        &mut self,
        header_id: &[u8; 32],
    ) -> Result<Vec<ExtensionField>, Self::Error> {
        self.fields
            .get(header_id)
            .cloned()
            .ok_or(MissingBlock(*header_id))
    }
}

/// What an [`AegisSource`] knows about a committed Aegis block id.
#[derive(Debug)]
pub enum AegisLookup {
    /// Never heard of it (M6b's P2P will fetch; the watcher buffers).
    Unknown,
    /// Header known, body not yet — enough to verify the share; the
    /// block stays body-pending in the fork-choice (§6).
    HeaderOnly(Box<AegisHeader>),
    /// Full block available.
    Full(Box<Block>),
}

/// Source of Aegis blocks by id. For M6a this is an in-memory seed
/// ([`MemoryAegisSource`]); M6b's P2P store implements the same trait.
pub trait AegisSource {
    fn lookup(&self, aegis_id: &[u8; 32]) -> AegisLookup;
}

/// In-memory [`AegisSource`] — deterministic tests and seeding.
#[derive(Debug, Default)]
pub struct MemoryAegisSource {
    headers: BTreeMap<[u8; 32], AegisHeader>,
    blocks: BTreeMap<[u8; 32], Block>,
}

impl MemoryAegisSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a header (id is recomputed, never caller-claimed).
    pub fn insert_header(&mut self, header: AegisHeader) {
        self.headers.insert(header.id(), header);
    }

    /// Record a full block (id is recomputed, never caller-claimed).
    pub fn insert_block(&mut self, block: Block) {
        self.blocks.insert(block.id(), block);
    }
}

impl AegisSource for MemoryAegisSource {
    fn lookup(&self, aegis_id: &[u8; 32]) -> AegisLookup {
        if let Some(b) = self.blocks.get(aegis_id) {
            return AegisLookup::Full(Box::new(b.clone()));
        }
        if let Some(h) = self.headers.get(aegis_id) {
            return AegisLookup::HeaderOnly(Box::new(h.clone()));
        }
        AegisLookup::Unknown
    }
}

/// A well-formed Aegis commitment extracted from an Ergo block: the
/// claimed field plus its batch-merkle proof against the header's
/// PoW-committed `extension_root` — two of the three
/// [`verify_share`] inputs (the third is the header itself).
#[derive(Debug, Clone)]
pub struct Commitment {
    /// The committed Aegis block id (`field.value[1..]`).
    pub aegis_id: [u8; 32],
    pub field: ExtensionField,
    pub proof: BatchMerkleProof,
}

/// Why an `AEGIS_MM_KEY` field is not a valid commitment. Such a field
/// can genuinely appear on-chain (Ergo does not validate our value
/// format), so this is a per-block observation, never a source error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedReason {
    /// Value is not `MM_FIELD_VALUE_LEN` bytes.
    ValueLen { got: usize },
    /// Version byte is not `MM_COMMITMENT_VERSION` — possibly a later
    /// commitment era this verifier cannot interpret.
    Version { got: u8 },
}

/// Outcome of scanning one authenticated field set.
#[derive(Debug)]
pub enum Extracted {
    /// No `AEGIS_MM_KEY` field — the normal case for most Ergo blocks.
    /// Sound (not absence of evidence): the field set re-hashed to the
    /// PoW-committed root, so nothing was omitted.
    NoCommitment,
    /// `AEGIS_MM_KEY` present but the value is not a commitment.
    Malformed(MalformedReason),
    /// A well-formed commitment, proof built and ready to verify.
    Commitment(Commitment),
}

/// The served field data is inconsistent — impossible for a faithful
/// serve of a real Ergo block, so retrying the same bytes cannot help
/// (the header is kept for rescan in case the *source* heals).
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    /// Fields do not re-hash to the header's PoW-committed
    /// `extension_root`: truncated, reordered, or tampered serve.
    #[error("served extension fields do not hash to the PoW-committed extension_root")]
    RootMismatch { got: [u8; 32], want: [u8; 32] },
    /// More than one `AEGIS_MM_KEY` field — a valid Ergo block carries
    /// at most one field per key (rule 405).
    #[error("{count} AEGIS_MM_KEY fields; a valid Ergo block carries at most one (rule 405)")]
    DuplicateKey { count: usize },
    /// Proof construction failed (defensive; the index is in range by
    /// construction).
    #[error("batch-merkle proof construction failed for field index {idx}")]
    ProofBuild { idx: u32 },
}

/// Batch-merkle proof for `fields[idx]` over the extension tree —
/// exactly the single-leaf reduction [`verify_share`] step 4 replays
/// (and what a merge-miner puts in a
/// [`crate::auxpow::ShareWitness`]). `None` if `idx` is out of range.
pub fn extension_field_proof(fields: &[ExtensionField], idx: u32) -> Option<BatchMerkleProof> {
    let leaves: Vec<Vec<u8>> = fields.iter().map(kv_to_leaf).collect();
    let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    let (indices, raw) = merkle_proof_by_indices(&refs, &[idx])?;
    Some(BatchMerkleProof {
        indices,
        proofs: raw
            .into_iter()
            .map(|e| ProofEntry {
                digest: e.digest,
                side: Side::from_byte(e.side),
            })
            .collect(),
    })
}

/// Authenticate a served field set against `header`'s PoW-committed
/// `extension_root`, then extract the Aegis commitment if one is
/// present (pipeline step 2 — see the module doc).
pub fn extract_commitment(
    header: &ErgoHeader,
    fields: &[ExtensionField],
) -> Result<Extracted, ExtractError> {
    // Root authentication FIRST: every verdict below (including
    // "no commitment") is only sound over the authenticated set.
    let pairs: Vec<(&[u8], &[u8])> = fields.iter().map(|f| (&f.key[..], &f.value[..])).collect();
    let got = extension_root(&pairs);
    let want = *header.extension_root.as_bytes();
    if got != want {
        return Err(ExtractError::RootMismatch { got, want });
    }

    let mut hits = fields
        .iter()
        .enumerate()
        .filter(|(_, f)| f.key == AEGIS_MM_KEY);
    let Some((idx, field)) = hits.next() else {
        return Ok(Extracted::NoCommitment);
    };
    let extra = hits.count();
    if extra > 0 {
        return Err(ExtractError::DuplicateKey { count: extra + 1 });
    }

    if field.value.len() != MM_FIELD_VALUE_LEN {
        return Ok(Extracted::Malformed(MalformedReason::ValueLen {
            got: field.value.len(),
        }));
    }
    if field.value[0] != MM_COMMITMENT_VERSION {
        return Ok(Extracted::Malformed(MalformedReason::Version {
            got: field.value[0],
        }));
    }
    let aegis_id: [u8; 32] = field.value[1..]
        .try_into()
        .expect("MM_FIELD_VALUE_LEN = 1 + 32");
    let idx = idx as u32;
    let proof = extension_field_proof(fields, idx).ok_or(ExtractError::ProofBuild { idx })?;
    Ok(Extracted::Commitment(Commitment {
        aegis_id,
        field: field.clone(),
        proof,
    }))
}

/// Why a found commitment could not be verified yet (buffered for
/// retry on later drives; expires with the C2 height window).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnresolvedReason {
    /// The committed Aegis id is unknown to the [`AegisSource`].
    UnknownAegisBlock,
    /// The Aegis header is known but its parent is not a validated
    /// fork-choice node — the DAA expectation is undecidable.
    ParentNotValidated,
}

/// One observation from a watcher pass — telemetry, not state: every
/// fork-choice effect has already been applied when the event is
/// emitted.
#[derive(Debug)]
pub enum WatchEvent {
    /// Scanned; no Aegis commitment (root-authenticated verdict).
    NoCommitment { ergo_height: u32 },
    /// `AEGIS_MM_KEY` field present but not a valid commitment.
    Malformed {
        ergo_height: u32,
        reason: MalformedReason,
    },
    /// Commitment found but not yet verifiable; buffered for retry.
    Unresolved {
        aegis_id: [u8; 32],
        ergo_height: u32,
        reason: UnresolvedReason,
    },
    /// [`verify_share`] passed; share (and body, when available) fed
    /// to the fork-choice; `anchored` iff the carrying Ergo block was
    /// on the follower's best chain at scan time.
    Verified {
        aegis_id: [u8; 32],
        ergo_height: u32,
        share: ShareIngest,
        body: Option<BodyIngest>,
        anchored: bool,
    },
    /// [`verify_share`] rejected the commitment. Final for the drive
    /// path: the verdict is deterministic in the presented bytes (the
    /// height window only ever moves *away* from an included block).
    Rejected {
        aegis_id: [u8; 32],
        ergo_height: u32,
        error: ShareError,
    },
    /// A buffered item fell below the C2 window (`tip − k_lag`) and
    /// can never verify; dropped. `aegis_id` is `None` for a header
    /// whose fields were never successfully fetched.
    Expired {
        aegis_id: Option<[u8; 32]>,
        ergo_height: u32,
    },
}

/// Scan-path failure (block source / extraction).
#[derive(Debug, thiserror::Error)]
pub enum ScanError<BE> {
    /// The Ergo header does not serialize to an id (defensive — the
    /// follower only accepts serializable headers).
    #[error("ergo header at height {ergo_height} does not serialize")]
    HeaderEncode { ergo_height: u32 },
    /// Block-source failure; the header is buffered for rescan.
    #[error("block source error")]
    Blocks(#[source] BE),
    /// Served data inconsistent with the PoW-committed root; the
    /// header is buffered for rescan (a healed source recovers it).
    #[error("extension extraction at ergo height {ergo_height} failed")]
    Extract {
        ergo_height: u32,
        #[source]
        source: ExtractError,
    },
}

/// [`AnchorWatch::drive`] failure.
#[derive(Debug, thiserror::Error)]
pub enum WatchError<HE, BE> {
    /// Ergo header source (transport) failure.
    #[error("ergo header source error")]
    Headers(#[source] HE),
    /// A header failed the follower's PoW/linkage gate.
    #[error(transparent)]
    Follow(#[from] FollowError),
    /// Scan-path failure (see [`ScanError`]).
    #[error(transparent)]
    Scan(#[from] ScanError<BE>),
}

/// An Ergo header applied to the follower whose extension scan has not
/// succeeded yet.
#[derive(Debug, Clone)]
struct Unscanned {
    header: ErgoHeader,
    on_best_chain: bool,
}

/// A commitment awaiting its Aegis block / validated parent chain.
#[derive(Debug, Clone)]
struct Unresolved {
    ergo_header: ErgoHeader,
    commitment: Commitment,
    on_best_chain: bool,
}

/// Per-pass context shared by the scan/resolve internals.
struct Pass<'a, A> {
    follower_tip_height: u32,
    now_ms: u64,
    aegis: &'a A,
}

/// The Ergo anchor-watcher (module doc for the pipeline).
#[derive(Debug)]
pub struct AnchorWatch<B: BlockSource> {
    blocks: B,
    daa: DaaParams,
    k_lag: u32,
    start_height: u32,
    unscanned: Vec<Unscanned>,
    unresolved: Vec<Unresolved>,
}

impl<B: BlockSource> AnchorWatch<B> {
    /// A watcher over `blocks` for `network`'s Aegis chain.
    /// `start_height` is where [`Self::drive`] begins when the
    /// follower is empty (the followed Ergo root height). The C2
    /// window half-width is [`aegis_spec::K_LAG`].
    pub fn new(blocks: B, network: Network, start_height: u32) -> Self {
        AnchorWatch {
            blocks,
            daa: DaaParams::for_network(network),
            k_lag: K_LAG,
            start_height,
            unscanned: Vec::new(),
            unresolved: Vec::new(),
        }
    }

    /// Buffered (unscanned headers, unresolved commitments) counts.
    pub fn pending_retry(&self) -> (usize, usize) {
        (self.unscanned.len(), self.unresolved.len())
    }

    /// Mutable access to the block source (e.g. reconfigure or, for an
    /// in-memory source, seed blocks between drives).
    pub fn blocks_mut(&mut self) -> &mut B {
        &mut self.blocks
    }

    /// One full watcher pass: retry the buffers, pull new Ergo headers
    /// from `headers`, PoW-gate each through `follower`, scan each
    /// accepted header for an Aegis commitment and feed `fc`.
    ///
    /// Deterministic given its sources. On `Err`, all fork-choice and
    /// buffer effects up to the failure are applied and consistent;
    /// only the returned events of the partial pass are lost (events
    /// are telemetry, never state).
    pub fn drive<H: HeaderSource, A: AegisSource>(
        &mut self,
        follower: &mut Follower,
        headers: &mut H,
        aegis: &A,
        fc: &mut MmForkChoice,
        now_ms: u64,
    ) -> Result<Vec<WatchEvent>, WatchError<H::Error, B::Error>> {
        let mut events = Vec::new();
        if let Some(tip) = follower.tip_height() {
            let pass = Pass {
                follower_tip_height: tip,
                now_ms,
                aegis,
            };
            self.retry_inner(&pass, fc, &mut events)
                .map_err(WatchError::Scan)?;
        }
        let from = follower
            .tip_height()
            .map_or(self.start_height, |h| h.saturating_add(1));
        let batch = headers.next_headers(from).map_err(WatchError::Headers)?;
        for h in &batch {
            let outcome = follower.apply_header(h)?;
            if outcome == Ingest::Duplicate {
                continue; // already scanned when first applied
            }
            let on_best_chain = matches!(
                outcome,
                Ingest::Root | Ingest::Extended | Ingest::Reorg { .. }
            );
            let pass = Pass {
                follower_tip_height: follower
                    .tip_height()
                    .expect("follower has a tip after a successful apply"),
                now_ms,
                aegis,
            };
            self.scan_one(h, on_best_chain, &pass, fc, &mut events)
                .map_err(WatchError::Scan)?;
        }
        Ok(events)
    }

    /// Scan a single Ergo header (already PoW-gated by the caller —
    /// [`Self::drive`] uses the follower's gate) and feed any verified
    /// share into `fc`. `on_best_chain` controls anchor recording
    /// (module doc). Public as the per-header core `drive` composes;
    /// M6b's share gossip feeds candidate headers through
    /// [`crate::auxpow::ShareWitness`] instead.
    pub fn scan_ergo_header<A: AegisSource>(
        &mut self,
        ergo_header: &ErgoHeader,
        on_best_chain: bool,
        follower_tip_height: u32,
        aegis: &A,
        fc: &mut MmForkChoice,
        now_ms: u64,
    ) -> Result<Vec<WatchEvent>, ScanError<B::Error>> {
        let mut events = Vec::new();
        let pass = Pass {
            follower_tip_height,
            now_ms,
            aegis,
        };
        self.scan_one(ergo_header, on_best_chain, &pass, fc, &mut events)?;
        Ok(events)
    }

    /// Retry the buffers only (e.g. after seeding the [`AegisSource`]
    /// with a block the watcher reported [`WatchEvent::Unresolved`]).
    pub fn retry_pending<A: AegisSource>(
        &mut self,
        follower_tip_height: u32,
        aegis: &A,
        fc: &mut MmForkChoice,
        now_ms: u64,
    ) -> Result<Vec<WatchEvent>, ScanError<B::Error>> {
        let mut events = Vec::new();
        let pass = Pass {
            follower_tip_height,
            now_ms,
            aegis,
        };
        self.retry_inner(&pass, fc, &mut events)?;
        Ok(events)
    }

    // ----- internals -----

    /// Fetch + authenticate + extract + resolve for one header.
    /// On fetch/extract failure the header is buffered for rescan.
    fn scan_one<A: AegisSource>(
        &mut self,
        header: &ErgoHeader,
        on_best_chain: bool,
        pass: &Pass<'_, A>,
        fc: &mut MmForkChoice,
        events: &mut Vec<WatchEvent>,
    ) -> Result<(), ScanError<B::Error>> {
        let ergo_height = header.height;
        let (_bytes, id) =
            serialize_header(header).map_err(|_| ScanError::HeaderEncode { ergo_height })?;
        let fields = match self.blocks.extension_fields(id.as_bytes()) {
            Ok(fields) => fields,
            Err(e) => {
                self.unscanned.push(Unscanned {
                    header: header.clone(),
                    on_best_chain,
                });
                return Err(ScanError::Blocks(e));
            }
        };
        match extract_commitment(header, &fields) {
            Err(source) => {
                self.unscanned.push(Unscanned {
                    header: header.clone(),
                    on_best_chain,
                });
                Err(ScanError::Extract {
                    ergo_height,
                    source,
                })
            }
            Ok(Extracted::NoCommitment) => {
                events.push(WatchEvent::NoCommitment { ergo_height });
                Ok(())
            }
            Ok(Extracted::Malformed(reason)) => {
                events.push(WatchEvent::Malformed {
                    ergo_height,
                    reason,
                });
                Ok(())
            }
            Ok(Extracted::Commitment(commitment)) => {
                self.resolve_and_feed(
                    Unresolved {
                        ergo_header: header.clone(),
                        commitment,
                        on_best_chain,
                    },
                    true,
                    pass,
                    fc,
                    events,
                );
                Ok(())
            }
        }
    }

    /// Resolve the committed Aegis id and, if verifiable now, run
    /// [`verify_share`] and feed the fork-choice. Otherwise re-buffer
    /// (`announce` gates the first-time [`WatchEvent::Unresolved`] so
    /// retries stay quiet).
    fn resolve_and_feed<A: AegisSource>(
        &mut self,
        item: Unresolved,
        announce: bool,
        pass: &Pass<'_, A>,
        fc: &mut MmForkChoice,
        events: &mut Vec<WatchEvent>,
    ) {
        let ergo_height = item.ergo_header.height;
        let aegis_id = item.commitment.aegis_id;
        let (aegis_header, block) = match pass.aegis.lookup(&aegis_id) {
            AegisLookup::Unknown => {
                if announce {
                    events.push(WatchEvent::Unresolved {
                        aegis_id,
                        ergo_height,
                        reason: UnresolvedReason::UnknownAegisBlock,
                    });
                }
                self.unresolved.push(item);
                return;
            }
            AegisLookup::HeaderOnly(h) => (*h, None),
            AegisLookup::Full(b) => (b.header.clone(), Some(*b)),
        };
        // DAA expectation from the fork-choice's validated tree — the
        // same view `Chain::try_extend` will enforce on the body.
        let Some(daa_view) = fc.daa_view(&aegis_header.prev_id) else {
            if announce {
                events.push(WatchEvent::Unresolved {
                    aegis_id,
                    ergo_height,
                    reason: UnresolvedReason::ParentNotValidated,
                });
            }
            self.unresolved.push(item);
            return;
        };
        let ctx = ShareContext {
            follower_tip_height: pass.follower_tip_height,
            k_lag: self.k_lag,
            daa: &self.daa,
            daa_view: &daa_view,
        };
        match verify_share(
            &item.ergo_header,
            &item.commitment.field,
            &item.commitment.proof,
            &aegis_header,
            &ctx,
        ) {
            Ok(share) => {
                let share_ingest = fc.ingest_share(&share, pass.now_ms);
                if item.on_best_chain {
                    fc.record_anchor(share.aegis_id, share.ergo_height);
                }
                let body = block.map(|b| fc.ingest_body(b, pass.now_ms));
                events.push(WatchEvent::Verified {
                    aegis_id,
                    ergo_height,
                    share: share_ingest,
                    body,
                    anchored: item.on_best_chain,
                });
            }
            Err(error) => events.push(WatchEvent::Rejected {
                aegis_id,
                ergo_height,
                error,
            }),
        }
    }

    /// Expire below-window buffer entries, then retry the rest.
    fn retry_inner<A: AegisSource>(
        &mut self,
        pass: &Pass<'_, A>,
        fc: &mut MmForkChoice,
        events: &mut Vec<WatchEvent>,
    ) -> Result<(), ScanError<B::Error>> {
        let low = pass.follower_tip_height.saturating_sub(self.k_lag);
        self.unscanned.retain(|u| {
            let keep = u.header.height >= low;
            if !keep {
                events.push(WatchEvent::Expired {
                    aegis_id: None,
                    ergo_height: u.header.height,
                });
            }
            keep
        });
        self.unresolved.retain(|u| {
            let keep = u.ergo_header.height >= low;
            if !keep {
                events.push(WatchEvent::Expired {
                    aegis_id: Some(u.commitment.aegis_id),
                    ergo_height: u.ergo_header.height,
                });
            }
            keep
        });

        let unscanned = std::mem::take(&mut self.unscanned);
        for (i, u) in unscanned.iter().enumerate() {
            if let Err(e) = self.scan_one(&u.header, u.on_best_chain, pass, fc, events) {
                // scan_one re-buffered THIS header; keep the rest too.
                self.unscanned.extend(unscanned[i + 1..].iter().cloned());
                return Err(e);
            }
        }
        let unresolved = std::mem::take(&mut self.unresolved);
        for u in unresolved {
            self.resolve_and_feed(u, false, pass, fc, events);
        }
        Ok(())
    }
}

/// Peg-finality judged at the follower's settled reference — the
/// `is_final` caller contract from the M2b review: shares/anchors and
/// the settled height must come from the SAME caught-up follower.
/// `false` when the follower has no settled reference yet (not
/// `N_mint` deep / not caught up) — refuse to judge rather than guess,
/// the peg's `NotCaughtUp` discipline.
pub fn settled_is_final(
    fc: &MmForkChoice,
    follower: &Follower,
    aegis_id: &[u8; 32],
    l_final: &BigUint,
) -> bool {
    match follower.settled_reference() {
        Some(settled) => fc.is_final(aegis_id, l_final, settled.height),
        None => false,
    }
}

/// Live HTTP transport for [`BlockSource`] — a blocking-reqwest client
/// over the node REST's `GET /blocks/{headerId}` (full block JSON; only
/// the `extension.fields` array is consumed). Same discipline as
/// [`crate::ergo_follow::poll_http`]: blocking on purpose, plain HTTP
/// to a local/LAN node, never call from inside an async context.
pub mod fetch_http {
    use std::time::Duration;

    use ergo_rest_json::types::ScalaExtension;
    use ergo_ser::extension::ExtensionField;

    use super::BlockSource;

    /// Default per-request timeout (connect + response).
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

    /// Configuration for [`RestBlockSource`].
    #[derive(Debug, Clone)]
    pub struct RestBlockConfig {
        /// Node REST base URL, e.g. `http://127.0.0.1:9062` (trailing
        /// slash tolerated). Plain HTTP only — no TLS backend linked.
        pub base_url: String,
        /// Optional node API key, sent as the `api_key` header.
        pub api_key: Option<String>,
        /// Per-request timeout.
        pub timeout: Duration,
    }

    impl RestBlockConfig {
        /// A config with the default timeout and no API key.
        pub fn new(base_url: impl Into<String>) -> Self {
            Self {
                base_url: base_url.into(),
                api_key: None,
                timeout: DEFAULT_TIMEOUT,
            }
        }
    }

    /// Errors from the REST block source, split by retryability —
    /// same taxonomy as
    /// [`crate::ergo_follow::poll_http::RestSourceError`].
    #[derive(Debug, thiserror::Error)]
    pub enum RestBlockError {
        /// The HTTP client itself could not be built.
        #[error("building blocking HTTP client")]
        Client(#[source] reqwest::Error),
        /// No HTTP response (connect, timeout, mid-body). Retryable.
        #[error("GET {url} failed")]
        Network {
            url: String,
            #[source]
            source: reqwest::Error,
        },
        /// Non-2xx status. Retryable — includes 404 for a block whose
        /// sections the node has not stored yet.
        #[error("GET {url}: HTTP status {status}")]
        Status { url: String, status: u16 },
        /// Body is not a JSON object with an `extension.fields` array
        /// of hex pairs. Not retryable.
        #[error("block body is not decodable: {detail}")]
        Parse { detail: String },
        /// A field's key/value hex failed to decode or the key is not
        /// 2 bytes. Not retryable.
        #[error("extension field {index} invalid: {detail}")]
        Field { index: usize, detail: String },
    }

    impl RestBlockError {
        /// Whether retrying the same request later can plausibly
        /// succeed.
        pub fn is_retryable(&self) -> bool {
            matches!(
                self,
                RestBlockError::Network { .. } | RestBlockError::Status { .. }
            )
        }
    }

    /// [`BlockSource`] over a live node's `GET /blocks/{headerId}`.
    #[derive(Debug)]
    pub struct RestBlockSource {
        config: RestBlockConfig,
        client: reqwest::blocking::Client,
    }

    impl RestBlockSource {
        pub fn new(config: RestBlockConfig) -> Result<Self, RestBlockError> {
            let client = reqwest::blocking::Client::builder()
                .timeout(config.timeout)
                .build()
                .map_err(RestBlockError::Client)?;
            Ok(Self { config, client })
        }
    }

    impl BlockSource for RestBlockSource {
        type Error = RestBlockError;

        fn extension_fields(
            &mut self,
            header_id: &[u8; 32],
        ) -> Result<Vec<ExtensionField>, Self::Error> {
            let url = format!(
                "{}/blocks/{}",
                self.config.base_url.trim_end_matches('/'),
                hex::encode(header_id),
            );
            let mut request = self.client.get(&url);
            if let Some(key) = &self.config.api_key {
                request = request.header("api_key", key);
            }
            let response = request.send().map_err(|e| RestBlockError::Network {
                url: url.clone(),
                source: e,
            })?;
            let status = response.status();
            if !status.is_success() {
                return Err(RestBlockError::Status {
                    url,
                    status: status.as_u16(),
                });
            }
            let body = response
                .text()
                .map_err(|e| RestBlockError::Network { url, source: e })?;
            parse_block_extension_fields(&body)
        }
    }

    /// Decode a `GET /blocks/{id}` response body to its extension
    /// fields. The fields are DATA — [`super::extract_commitment`]
    /// authenticates them against the PoW-committed root; no header
    /// cross-check is needed here.
    fn parse_block_extension_fields(body: &str) -> Result<Vec<ExtensionField>, RestBlockError> {
        let v: serde_json::Value =
            serde_json::from_str(body).map_err(|e| RestBlockError::Parse {
                detail: e.to_string(),
            })?;
        let ext = v.get("extension").ok_or_else(|| RestBlockError::Parse {
            detail: "no extension section".to_string(),
        })?;
        let ext: ScalaExtension =
            serde_json::from_value(ext.clone()).map_err(|e| RestBlockError::Parse {
                detail: format!("extension section: {e}"),
            })?;
        let mut fields = Vec::with_capacity(ext.fields.len());
        for (index, kv) in ext.fields.iter().enumerate() {
            let key_raw = hex::decode(&kv[0]).map_err(|e| RestBlockError::Field {
                index,
                detail: format!("key hex: {e}"),
            })?;
            let key: [u8; 2] =
                key_raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| RestBlockError::Field {
                        index,
                        detail: format!("key length {} != 2 bytes", key_raw.len()),
                    })?;
            let value = hex::decode(&kv[1]).map_err(|e| RestBlockError::Field {
                index,
                detail: format!("value hex: {e}"),
            })?;
            fields.push(ExtensionField { key, value });
        }
        Ok(fields)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::Path;

        // ----- helpers -----

        /// The committed real capture — a verbatim `GET /blocks/{id}`
        /// response for testnet block 442815.
        fn block_body() -> String {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("test-vectors/testnet/blocks/scala_block_442815.json");
            std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        }

        // ----- happy path -----

        #[test]
        fn real_block_body_parses_all_extension_fields() {
            let fields = parse_block_extension_fields(&block_body()).unwrap();
            assert_eq!(fields.len(), 14, "pinned capture: 14 interlink fields");
            assert!(fields.iter().all(|f| f.key.len() == 2));
        }

        // ----- error paths -----

        #[test]
        fn non_json_body_is_parse_error_not_retryable() {
            let err = parse_block_extension_fields("<html>502</html>").unwrap_err();
            assert!(matches!(err, RestBlockError::Parse { .. }), "{err:?}");
            assert!(!err.is_retryable());
        }

        #[test]
        fn missing_extension_section_is_parse_error() {
            let err = parse_block_extension_fields("{\"header\":{}}").unwrap_err();
            assert!(matches!(err, RestBlockError::Parse { .. }), "{err:?}");
        }

        #[test]
        fn oversized_field_key_is_field_error_not_retryable() {
            let mut v: serde_json::Value = serde_json::from_str(&block_body()).unwrap();
            v["extension"]["fields"][0][0] = serde_json::Value::String("010203".into());
            let err = parse_block_extension_fields(&v.to_string()).unwrap_err();
            match &err {
                RestBlockError::Field { index, detail } => {
                    assert_eq!(*index, 0);
                    assert!(detail.contains("key length"), "{detail}");
                }
                other => panic!("expected Field, got {other:?}"),
            }
            assert!(!err.is_retryable());
        }

        #[test]
        fn network_and_status_errors_are_retryable() {
            let status = RestBlockError::Status {
                url: "http://x/blocks/aa".into(),
                status: 404,
            };
            assert!(status.is_retryable());

            let mut source = RestBlockSource::new(RestBlockConfig {
                base_url: "http://127.0.0.1:9".into(), // discard port
                api_key: None,
                timeout: Duration::from_millis(300),
            })
            .unwrap();
            let err = source.extension_fields(&[0u8; 32]).unwrap_err();
            assert!(matches!(err, RestBlockError::Network { .. }), "{err:?}");
            assert!(err.is_retryable());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_rest_json::types::ScalaFullBlock;
    use ergo_validation::popow::verify_batch_merkle_proof;

    // ----- helpers -----
    //
    // Extraction unit tests run over REAL testnet block 442815 (the
    // same capture the M2a oracle pins): the extension_root these
    // fields authenticate against was sealed by real PoW. Commitment
    // variants re-root that header's extension over (real fields ‖
    // synthetic field) — structural, clearly labeled.

    fn vector(rel: &str) -> String {
        let path = format!("{}/../test-vectors/{rel}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
    }

    fn real_block_parts() -> (ErgoHeader, Vec<ExtensionField>) {
        let block: ScalaFullBlock =
            serde_json::from_str(&vector("testnet/blocks/scala_block_442815.json"))
                .expect("block JSON parses");
        let header =
            ergo_rest_json::decode_scala_header_struct(&block.header).expect("header decodes");
        let fields = block
            .extension
            .fields
            .iter()
            .map(|kv| ExtensionField {
                key: hex::decode(&kv[0])
                    .expect("key hex")
                    .try_into()
                    .expect("2-byte key"),
                value: hex::decode(&kv[1]).expect("value hex"),
            })
            .collect();
        (header, fields)
    }

    /// Re-root the real header's extension over (real fields ‖ extra).
    fn reroot_with(extra: &[ExtensionField]) -> (ErgoHeader, Vec<ExtensionField>) {
        let (mut header, mut fields) = real_block_parts();
        fields.extend(extra.iter().cloned());
        let pairs: Vec<(&[u8], &[u8])> =
            fields.iter().map(|f| (&f.key[..], &f.value[..])).collect();
        header.extension_root = extension_root(&pairs).into();
        (header, fields)
    }

    // ----- oracle parity (real block) -----

    #[test]
    fn real_block_extracts_no_commitment() {
        // Real testnet block: 14 interlink fields, none AEGIS_MM_KEY —
        // and the no-commitment verdict is root-authenticated against
        // the real PoW-committed extension_root.
        let (header, fields) = real_block_parts();
        assert!(matches!(
            extract_commitment(&header, &fields).unwrap(),
            Extracted::NoCommitment
        ));
    }

    #[test]
    fn real_field_proofs_from_extraction_helper_verify_against_real_root() {
        // The proof builder the watcher uses, driven over every REAL
        // field, must reduce to the real PoW-committed root — the same
        // reduction verify_share step 4 replays.
        let (header, fields) = real_block_parts();
        let root = header.extension_root.as_bytes();
        for idx in 0..fields.len() as u32 {
            let proof = extension_field_proof(&fields, idx).expect("in range");
            assert!(
                verify_batch_merkle_proof(&proof, root),
                "field {idx}: proof must reduce to the PoW-committed root"
            );
        }
        assert!(
            extension_field_proof(&fields, fields.len() as u32).is_none(),
            "out-of-range index yields no proof"
        );
    }

    // ----- error paths -----

    #[test]
    fn omitted_real_field_fails_root_authentication() {
        // A lying source that hides a field (the omission attack) is
        // caught before any verdict: the served set no longer hashes
        // to the PoW-committed root.
        let (header, mut fields) = real_block_parts();
        fields.pop();
        assert!(matches!(
            extract_commitment(&header, &fields),
            Err(ExtractError::RootMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_aegis_key_rejected() {
        // Two AEGIS_MM_KEY fields cannot appear in a valid Ergo block
        // (rule 405) — served data claiming so is rejected even though
        // it root-authenticates.
        let f1 = crate::auxpow::aegis_mm_extension_field([0x11; 32]);
        let f2 = crate::auxpow::aegis_mm_extension_field([0x22; 32]);
        let (header, fields) = reroot_with(&[f1, f2]);
        assert!(matches!(
            extract_commitment(&header, &fields),
            Err(ExtractError::DuplicateKey { count: 2 })
        ));
    }

    #[test]
    fn near_miss_key_is_not_a_commitment() {
        // A key one byte off AEGIS_MM_KEY with a perfectly-shaped value
        // is NOT a commitment (wrong key ignored).
        let mut field = crate::auxpow::aegis_mm_extension_field([0x33; 32]);
        field.key = [0xAE, 0x01];
        let (header, fields) = reroot_with(&[field]);
        assert!(matches!(
            extract_commitment(&header, &fields).unwrap(),
            Extracted::NoCommitment
        ));
    }

    #[test]
    fn short_value_is_malformed_not_a_commitment() {
        let mut field = crate::auxpow::aegis_mm_extension_field([0x44; 32]);
        field.value.pop();
        let (header, fields) = reroot_with(&[field]);
        assert!(matches!(
            extract_commitment(&header, &fields).unwrap(),
            Extracted::Malformed(MalformedReason::ValueLen { got: 32 })
        ));
    }

    #[test]
    fn unknown_version_byte_is_malformed() {
        let mut field = crate::auxpow::aegis_mm_extension_field([0x55; 32]);
        field.value[0] = 0x02;
        let (header, fields) = reroot_with(&[field]);
        assert!(matches!(
            extract_commitment(&header, &fields).unwrap(),
            Extracted::Malformed(MalformedReason::Version { got: 0x02 })
        ));
    }

    // ----- happy path (commitment extraction) -----

    #[test]
    fn well_formed_commitment_extracts_with_verifying_proof() {
        let aegis_id = [0xCD; 32];
        let field = crate::auxpow::aegis_mm_extension_field(aegis_id);
        let (header, fields) = reroot_with(std::slice::from_ref(&field));
        let Extracted::Commitment(c) = extract_commitment(&header, &fields).unwrap() else {
            panic!("expected a commitment");
        };
        assert_eq!(c.aegis_id, aegis_id);
        assert_eq!(c.field, field);
        assert!(verify_batch_merkle_proof(
            &c.proof,
            header.extension_root.as_bytes()
        ));
    }
}
