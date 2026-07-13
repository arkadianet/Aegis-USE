//! Fresh-node sync — bootstrap the merge-mined chain from scratch
//! (architecture.md §5, p2p.md §5 — M6b-1).
//!
//! ## The trust story (who is trusted with what)
//!
//! - **Ergo is the trustless skeleton.** The follower PoW-gates every
//!   Ergo header; the anchor-watcher extracts root-authenticated
//!   `AEGIS_MM_KEY` commitments from settled extensions. Nothing an
//!   Aegis seed says can fake or hide settlement — a fabricated
//!   settled prefix would need fake Ergo anchors, i.e. an Ergo reorg.
//! - **Seeds are liveness-only.** Their `tips`/`chain` answers are a
//!   *download schedule*, never a verdict: it costs a seed nothing to
//!   lie, so a lying seed only wastes bandwidth (p2p.md §10 #7).
//!   Every fetched body self-authenticates; every fetched witness is
//!   re-verified. A seed can withhold, never forge — a withheld item
//!   leaves a block pending/absent (monotone), it never stalls the
//!   node or splits consensus.
//! - **Weight comes only from verified witnesses.** [`ShareWitness::verify`]
//!   re-derives the aux-PoW claim from presented bytes before
//!   `ingest_share`; `MmForkChoice` recomputes cumulative weight
//!   itself. The seed's word is never weight.
//!
//! ## Witness-first admission (p2p.md §6.2 #1)
//!
//! A body is only ingested through a verified witness: the schedule
//! loop fetches the witness for each id FIRST, verifies it, and only
//! then feeds the (witness-carried) block to `ingest_body` — a junk
//! body can never reach the fork-choice's orphan buffer without real
//! aux-PoW behind its id. Ids whose witness no seed serves are
//! reported and skipped, not stashed. (The anchor-watcher's
//! [`AegisSource`] fetches are the anchored form of the same rule:
//! that fetch is gated by an Ergo-PoW-committed commitment.)
//!
//! ## The historical C2 window (replay relaxation — read this)
//!
//! `verify_share`'s C2 height window (`[follower_tip − K_LAG, tip+1]`)
//! is an anti-grinding/stockpiling defense for LIVE tip decisions. A
//! fresh node replaying history necessarily verifies witnesses whose
//! Ergo candidates are far below its (caught-up) follower tip — they
//! could never pass the live window. [`sync_from_seeds`] therefore
//! verifies each witness in an **era-local window**: the context tip
//! is the witness's own claimed Ergo height, clamped to the real
//! follower tip (so future-era claims still fail
//! `HeightOutOfWindow`). What this gives up is only the stockpiling
//! bound for *historical* weight — re-minting history still costs the
//! full real work of the chain (each share must clear the DAA-pinned
//! `sc_nbits` for its exact chain position), and the settled prefix is
//! bounded by the Ergo anchors regardless. Live operation (the M6c
//! loop's anchor-watch path) keeps the strict window.
//!
//! Wired into the node loop by M6c: [`crate::node`] runs [`fresh_sync`]
//! at boot (and [`sync_from_seeds`] per tick, and as the
//! archive-resume replay).

use aegis_spec::{Network, K_LAG};

use crate::anchor_watch::{AegisSource, AnchorWatch, BlockSource, WatchError};
use crate::auxpow::ShareContext;
use crate::block::Block;
use crate::daa::DaaParams;
use crate::ergo_follow::poll::HeaderSource;
use crate::ergo_follow::Follower;
use crate::mm_forkchoice::{BodyIngest, MmForkChoice};
use crate::seed::{Id, SeedFetch};

/// Ids requested per `chain_page` call.
pub const SCHEDULE_PAGE: usize = 256;

/// Hard cap on schedule ids walked per seeds-claim per call — bounds a
/// malicious `tips.height` claim (a later call resumes where fork
/// choice left off; sync is monotone).
pub const MAX_SCHEDULE_IDS: usize = 100_000;

/// What one [`sync_from_seeds`] pass did — telemetry, not state: every
/// fork-choice effect is already applied when this is returned.
#[derive(Debug, Default)]
pub struct SeedSyncReport {
    /// Each seed's claimed `(tip, height)` — the §5 cross-check input.
    pub tips_claims: Vec<(Id, u64)>,
    /// Distinct schedule ids processed this pass.
    pub scheduled: usize,
    /// Blocks that joined the validated tree this pass (including
    /// cascaded orphan activations).
    pub activated: usize,
    /// Schedule ids already validated (skipped).
    pub already_validated: usize,
    /// Ids no seed served a witness for (withheld/absent — the block
    /// stays a non-candidate; monotone, never a stall).
    pub missing_witness: Vec<Id>,
    /// Ids whose parent is not validated (earlier hole in the
    /// schedule); retried by a later pass.
    pub missing_parent: Vec<Id>,
    /// Ids whose witness or body failed verification, with the reason
    /// (junk from a seed — blames the bytes, never the id).
    pub rejected: Vec<(Id, String)>,
    /// Ids carrying (or acquiring) a permanent dead verdict.
    pub dead: Vec<Id>,
}

/// Fetch-and-replay the seeds' claimed canonical chain(s) through the
/// fork choice: for each schedule id — witness first, verify, ingest
/// share, then ingest the witness-carried body. Parent-first schedule
/// order makes one pass sufficient when nothing is withheld; anything
/// missed is reported and picked up by a later pass (monotone).
///
/// `follower_tip_height` should be the caught-up follower's tip
/// (`None` only when no Ergo view exists yet — then the era-local
/// window cannot clamp future-era claims; see the module doc).
pub fn sync_from_seeds<S: SeedFetch>(
    seeds: &S,
    fc: &mut MmForkChoice,
    follower_tip_height: Option<u32>,
    network: Network,
    now_ms: u64,
) -> Result<SeedSyncReport, S::Error> {
    let daa = DaaParams::for_network(network);
    let mut report = SeedSyncReport::default();
    let mut seen: std::collections::BTreeSet<Id> = std::collections::BTreeSet::new();

    for tips in seeds.tips()? {
        report.tips_claims.push((tips.tip, tips.height));
        let mut height = 1u64;
        let mut walked = 0usize;
        while height <= tips.height && walked < MAX_SCHEDULE_IDS {
            let page = seeds.chain_page(height, SCHEDULE_PAGE)?;
            if page.is_empty() {
                break;
            }
            for id in &page {
                walked += 1;
                if !seen.insert(*id) {
                    continue; // already processed this pass
                }
                report.scheduled += 1;
                sync_one(
                    seeds,
                    fc,
                    id,
                    follower_tip_height,
                    &daa,
                    now_ms,
                    &mut report,
                )?;
            }
            height += page.len() as u64;
        }
    }
    Ok(report)
}

/// One schedule id: witness-first fetch → verify → ingest share →
/// ingest the carried body. Every outcome lands in `report`.
fn sync_one<S: SeedFetch>(
    seeds: &S,
    fc: &mut MmForkChoice,
    id: &Id,
    follower_tip_height: Option<u32>,
    daa: &DaaParams,
    now_ms: u64,
    report: &mut SeedSyncReport,
) -> Result<(), S::Error> {
    if fc.is_validated(id) {
        report.already_validated += 1;
        return Ok(());
    }
    if fc.is_dead(id) {
        report.dead.push(*id);
        return Ok(());
    }
    let Some(witness) = seeds.witness(id)? else {
        report.missing_witness.push(*id);
        return Ok(());
    };
    // The witness carries the full block bytes; decode once, both for
    // the parent lookup and (after verification) the body ingest.
    let block = match Block::from_bytes(&witness.aegis_block_bytes) {
        Ok(block) => block,
        Err(e) => {
            report
                .rejected
                .push((*id, format!("witness block bytes: {e}")));
            return Ok(());
        }
    };
    if block.id() != *id {
        report
            .rejected
            .push((*id, "witness carries a different aegis block".to_string()));
        return Ok(());
    }
    let Some(daa_view) = fc.daa_view(&block.header.prev_id) else {
        report.missing_parent.push(*id);
        return Ok(());
    };
    // Era-local C2 window (module doc): the witness verifies against
    // its own Ergo era, clamped so future-era claims still fail.
    let effective_tip = match follower_tip_height {
        Some(tip) => witness.ergo_header.height.min(tip),
        None => witness.ergo_header.height,
    };
    let ctx = ShareContext {
        follower_tip_height: effective_tip,
        k_lag: K_LAG,
        daa,
        daa_view: &daa_view,
    };
    match witness.verify(&ctx) {
        Ok(share) => {
            fc.ingest_share(&share, now_ms);
            match fc.ingest_body(block, now_ms) {
                BodyIngest::Activated { activated } => report.activated += activated,
                BodyIngest::AlreadyValidated => report.already_validated += 1,
                BodyIngest::AwaitingParent | BodyIngest::AwaitingShare => {
                    report.missing_parent.push(*id);
                }
                BodyIngest::Dead => report.dead.push(*id),
                verdict @ (BodyIngest::NotSelfAuthenticating | BodyIngest::RejectedTransient) => {
                    report.rejected.push((*id, format!("{verdict:?}")));
                }
            }
        }
        Err(e) => report.rejected.push((*id, e.to_string())),
    }
    Ok(())
}

/// [`fresh_sync`] failure.
#[derive(Debug, thiserror::Error)]
pub enum FreshSyncError<HE, BE, SE>
where
    HE: std::error::Error + 'static,
    BE: std::error::Error + 'static,
    SE: std::error::Error + 'static,
{
    /// The Ergo skeleton walk failed (header source / follower gate /
    /// extension scan).
    #[error(transparent)]
    Watch(#[from] WatchError<HE, BE>),
    /// The seed download schedule failed (every seed errored — a
    /// partial answer is a report entry, not an error).
    #[error("seed fetch failed")]
    Seeds(#[source] SE),
}

/// What one [`fresh_sync`] pass achieved.
#[derive(Debug)]
pub struct FreshSyncReport {
    /// Follower tip after the Ergo skeleton walk.
    pub ergo_tip_height: Option<u32>,
    /// The seed-schedule pass.
    pub seed: SeedSyncReport,
    /// Canonical tip after the pass (fork choice's verdict, nobody
    /// else's).
    pub canonical_tip: Id,
    /// Canonical height after the pass.
    pub canonical_height: u64,
}

/// [`fresh_sync`]'s result over its three source error types.
pub type FreshSyncResult<HE, BE, SE> = Result<FreshSyncReport, FreshSyncError<HE, BE, SE>>;

/// Bootstrap from genesis (p2p.md §5): (1) walk Ergo through the
/// follower + anchor-watcher — the trustless anchored skeleton; ids it
/// resolves against `seeds` (as [`AegisSource`]) are fetched and fed
/// with Ergo-grade shares + anchors. (2) Walk the seeds' claimed
/// chain(s) — the untrusted download schedule — verifying and
/// replaying witness+body per id through the fork choice.
/// (3) Retry the watcher's buffered commitments, which can now resolve
/// against the blocks step 2 landed.
///
/// One pass over each input; call again (or hand off to the M6c loop)
/// to converge on live data. Everything is monotone: a failed or
/// withheld item degrades nothing, it just stays absent this pass.
pub fn fresh_sync<H, B, S>(
    follower: &mut Follower,
    headers: &mut H,
    watch: &mut AnchorWatch<B>,
    seeds: &S,
    fc: &mut MmForkChoice,
    network: Network,
    now_ms: u64,
) -> FreshSyncResult<H::Error, B::Error, S::Error>
where
    H: HeaderSource,
    B: BlockSource,
    S: SeedFetch + AegisSource,
    H::Error: std::error::Error + 'static,
    B::Error: std::error::Error + 'static,
{
    // 1. Trustless skeleton: drive Ergo headers to exhaustion (an
    //    empty, event-less pass with an unmoved tip = caught up).
    loop {
        let tip_before = follower.tip_height();
        let events = watch.drive(follower, headers, seeds, fc, now_ms)?;
        if follower.tip_height() == tip_before && events.is_empty() {
            break;
        }
    }
    // 2. Untrusted download schedule from the seeds.
    let seed = sync_from_seeds(seeds, fc, follower.tip_height(), network, now_ms)
        .map_err(FreshSyncError::Seeds)?;
    // 3. Buffered commitments can resolve now that bodies landed.
    if let Some(tip) = follower.tip_height() {
        watch
            .retry_pending(tip, seeds, fc, now_ms)
            .map_err(|e| FreshSyncError::Watch(WatchError::Scan(e)))?;
    }
    Ok(FreshSyncReport {
        ergo_tip_height: follower.tip_height(),
        canonical_tip: fc.canonical_tip_id(),
        canonical_height: fc.canonical_tip().height,
        seed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auxpow::{aegis_mm_extension_field, ShareWitness};
    use crate::block::BlockBody;
    use crate::chain::{Chain, PowMode, ProofMode};
    use crate::genesis::genesis_header;
    use crate::seed::SeedCore;
    use ergo_ser::batch_merkle_proof::BatchMerkleProof;

    // ----- helpers -----
    //
    // These unit tests cover schedule/report bookkeeping with cheap
    // (unverifiable) witnesses; PoW-grade witnesses and the full
    // replay-equivalence property live in
    // `tests/fresh_sync_replay_equivalence.rs`.

    const T_MS: u64 = 15_000;
    const NOW: u64 = 1_761_000_000_000;

    fn extend_branch(n: usize) -> Vec<Block> {
        let mut chain = Chain::new(Network::Dev, PowMode::DevStub, ProofMode::DevStub);
        let mut out = Vec::with_capacity(n);
        let mut now = chain.tip().timestamp_ms;
        for _ in 0..n {
            now += T_MS;
            let block = chain
                .produce_next(BlockBody::default(), now)
                .expect("produces");
            chain.try_extend(block.clone(), now).expect("extends");
            out.push(block);
        }
        out
    }

    fn fc_new() -> MmForkChoice {
        MmForkChoice::new(Network::Dev, PowMode::DevStub, ProofMode::DevStub)
    }

    /// A decodable but PoW-unverifiable witness for `block` (empty
    /// proof → `ShareError::ProofShape` at verify time).
    fn junk_witness(block: &Block) -> ShareWitness {
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

    // ----- happy path -----

    #[test]
    fn empty_seed_yields_empty_report() {
        let core = SeedCore::new(Network::Dev);
        let mut fc = fc_new();
        let report = sync_from_seeds(&core, &mut fc, None, Network::Dev, NOW).expect("syncs");
        assert_eq!(report.scheduled, 0);
        assert_eq!(report.activated, 0);
        assert_eq!(
            report.tips_claims,
            vec![(genesis_header(Network::Dev).id(), 0)]
        );
        assert_eq!(fc.canonical_tip().height, 0);
    }

    // ----- error paths -----

    #[test]
    fn witness_first_bodies_without_witnesses_are_never_ingested() {
        // THE witness-first admission property: a seed offering bodies
        // (canonical, well-formed) but NO witnesses gets nothing into
        // the fork choice — not validated, not pending, not stashed.
        let blocks = extend_branch(3);
        let mut core = SeedCore::new(Network::Dev);
        for b in &blocks {
            core.record_canonical(b); // bodies only, no witnesses
        }
        let mut fc = fc_new();
        let report = sync_from_seeds(&core, &mut fc, None, Network::Dev, NOW).expect("syncs");

        assert_eq!(report.scheduled, 3);
        assert_eq!(report.activated, 0);
        assert_eq!(
            report.missing_witness,
            blocks.iter().map(Block::id).collect::<Vec<_>>()
        );
        assert_eq!(fc.canonical_tip().height, 0, "no verified work → no tip");
        for b in &blocks {
            assert!(!fc.is_validated(&b.id()));
            assert!(!fc.is_pending(&b.id()), "no unproven weight either");
        }
    }

    #[test]
    fn unverifiable_witness_is_rejected_without_poisoning_the_id() {
        let blocks = extend_branch(1);
        let mut core = SeedCore::new(Network::Dev);
        core.record_canonical(&blocks[0]);
        core.record_witness(&junk_witness(&blocks[0]))
            .expect("records");
        let mut fc = fc_new();
        let report = sync_from_seeds(&core, &mut fc, None, Network::Dev, NOW).expect("syncs");

        assert_eq!(report.activated, 0);
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].0, blocks[0].id());
        assert!(
            !fc.is_dead(&blocks[0].id()),
            "junk witness blames the bytes, never the id"
        );
        assert!(!fc.is_validated(&blocks[0].id()));
    }

    #[test]
    fn schedule_hole_reports_missing_parent_not_a_stall() {
        // Seed serves witnesses/bodies for heights 2..3 but withholds
        // height 1 entirely: nothing validates (parents unresolvable),
        // the pass completes, and the report says exactly what's
        // missing — monotone, no stall.
        let blocks = extend_branch(3);
        let mut core = SeedCore::new(Network::Dev);
        for b in &blocks {
            core.record_canonical(b); // hints list all 3 heights
        }
        for b in &blocks[1..] {
            core.record_witness(&junk_witness(b)).expect("records");
        }
        // Height 1's witness AND body withheld.
        let mut fc = fc_new();
        let report = sync_from_seeds(&core, &mut fc, None, Network::Dev, NOW).expect("syncs");

        assert_eq!(report.missing_witness, vec![blocks[0].id()]);
        assert_eq!(
            report.missing_parent,
            blocks[1..].iter().map(Block::id).collect::<Vec<_>>(),
            "children of the hole are reported, not stashed as work"
        );
        assert_eq!(fc.canonical_tip().height, 0);
    }
}
