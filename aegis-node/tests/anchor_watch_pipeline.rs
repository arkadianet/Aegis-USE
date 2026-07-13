//! Anchor-watcher pipeline tests (merge-mining.md §2/§5/§7 — M6a):
//! the Ergo→commitment→share→fork-choice glue, driven end-to-end.
//!
//! ## Real-oracle vs structural (honesty)
//!
//! - **Real-oracle**: the `drive` path is exercised over REAL testnet
//!   block 442815 (`test-vectors/testnet/blocks/scala_block_442815.json`,
//!   verbatim node output) — its header passes the follower's full
//!   Autolykos PoW gate, and the extraction verdict ("no commitment")
//!   is authenticated against the real PoW-committed `extension_root`.
//! - **Structural/synthetic**: no real Ergo block carries an
//!   `AEGIS_MM_KEY` field yet, so the commitment path re-roots the real
//!   header's extension over (real fields ‖ commitment) and grinds an
//!   Autolykos nonce against the (easy, dev-genesis) AEGIS target only
//!   — the M2a test discipline. Such headers cannot pass the
//!   follower's Ergo-level PoW gate (their Ergo `n_bits` is real
//!   testnet difficulty), so the synthetic pipeline drives the public
//!   per-header core `scan_ergo_header` directly; the follower
//!   composition is covered by the real-block drive tests. A real
//!   Ergo block's PoW is NEVER fabricated.

use aegis_node::daa::difficulty_to_nbits;
use aegis_node::ergo_follow::poll::VecHeaderSource;
use aegis_node::ergo_follow::Follower;
use aegis_node::{
    aegis_mm_extension_field, genesis_header, settled_is_final, AnchorWatch, Block, BlockBody,
    BodyIngest, Chain, MemoryAegisSource, MemoryBlockSource, MmForkChoice, PowMode, ProofMode,
    ScanError, ShareError, ShareIngest, UnresolvedReason, WatchError, WatchEvent,
};
use aegis_spec::{Network, K_LAG};
use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::autolykos::v2::check_pow_v2;
use ergo_crypto::difficulty::get_target;
use ergo_crypto::merkle::extension_root;
use ergo_rest_json::types::ScalaFullBlock;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::extension::ExtensionField;
use ergo_ser::header::{serialize_header, serialize_header_without_pow, Header as ErgoHeader};
use num_bigint::BigUint;

// ----- helpers -----

/// Pinned capture identity.
const H_REF: u32 = 442_815;

/// Aegis block target spacing (dev network, ms).
const T_MS: u64 = 15_000;

/// Wall clock far past every test Aegis block's timestamp.
const NOW: u64 = 1_761_000_000_000;

fn vector(rel: &str) -> String {
    let path = format!("{}/../test-vectors/{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Real header + verbatim extension fields from the capture.
fn real_block_parts() -> (ErgoHeader, Vec<ExtensionField>) {
    let block: ScalaFullBlock =
        serde_json::from_str(&vector("testnet/blocks/scala_block_442815.json"))
            .expect("block JSON parses");
    let header = ergo_rest_json::decode_scala_header_struct(&block.header).expect("header decodes");
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

fn ergo_id(h: &ErgoHeader) -> [u8; 32] {
    *serialize_header(h).expect("header serializes").1.as_bytes()
}

/// Grind the header's Autolykos v2 nonce until the hit clears the
/// AEGIS target from `nbits` (dev-genesis difficulty 1000 → expected
/// ~1000 tries). Synthetic-share discipline only — never used to fake
/// a real Ergo block's own PoW.
fn grind(eh: &mut ErgoHeader, nbits: u32) {
    let msg = blake2b256(&serialize_header_without_pow(eh).expect("serializes"));
    let target = get_target(nbits);
    let pk = *eh.solution.pk();
    let nonce = (0u64..3_000_000)
        .map(|i| i.to_be_bytes())
        .find(|n| check_pow_v2(&msg, n, eh.height, eh.version, &target))
        .expect("a nonce must clear the dev-difficulty target within 3M tries");
    eh.solution = AutolykosSolution::V2 { pk, nonce };
}

/// Synthetic committed Ergo block: the real header re-rooted over
/// (real fields ‖ AEGIS commitment to `aegis_id`), nonce ground
/// against `mine_nbits` when given.
fn committed_header(
    aegis_id: [u8; 32],
    mine_nbits: Option<u32>,
) -> (ErgoHeader, Vec<ExtensionField>) {
    let (mut eh, mut fields) = real_block_parts();
    fields.push(aegis_mm_extension_field(aegis_id));
    let pairs: Vec<(&[u8], &[u8])> = fields.iter().map(|f| (&f.key[..], &f.value[..])).collect();
    eh.extension_root = extension_root(&pairs).into();
    if let Some(nbits) = mine_nbits {
        grind(&mut eh, nbits);
    }
    (eh, fields)
}

/// Produce `n` empty Aegis blocks extending `prefix` (itself extending
/// genesis), `spacing_ms` apart. Returns only the new blocks.
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

fn fc_new() -> MmForkChoice {
    MmForkChoice::new(Network::Dev, PowMode::DevStub, ProofMode::DevStub)
}

/// Watcher over an in-memory block source pre-seeded with the given
/// (ergo header → fields) entries.
fn watch_with(entries: &[(&ErgoHeader, &[ExtensionField])]) -> AnchorWatch<MemoryBlockSource> {
    let mut source = MemoryBlockSource::new();
    for (h, fields) in entries {
        source.insert(ergo_id(h), fields.to_vec());
    }
    AnchorWatch::new(source, Network::Dev, H_REF)
}

// ----- oracle parity (real block through the full drive path) -----

#[test]
fn drive_follows_real_block_and_reports_no_commitment() {
    // REAL-ORACLE: the real header passes the follower's full Autolykos
    // PoW gate inside `drive`; the served real fields re-hash to the
    // real PoW-committed extension_root; no AEGIS_MM_KEY is present —
    // the watcher yields exactly one root-authenticated NoCommitment.
    let (header, fields) = real_block_parts();
    let mut watch = watch_with(&[(&header, &fields)]);
    let mut follower = Follower::new(0);
    let mut headers = VecHeaderSource::new(vec![header.clone()]);
    let aegis = MemoryAegisSource::new();
    let mut fc = fc_new();

    let events = watch
        .drive(&mut follower, &mut headers, &aegis, &mut fc, NOW)
        .expect("drive succeeds on real data");
    assert!(
        matches!(
            events[..],
            [WatchEvent::NoCommitment { ergo_height: H_REF }]
        ),
        "{events:?}"
    );
    assert_eq!(follower.tip_height(), Some(H_REF));
    assert_eq!(
        fc.canonical_tip_id(),
        genesis_header(Network::Dev).id(),
        "no commitment → fork-choice untouched"
    );

    // Caught up: a second drive sees nothing new.
    let events = watch
        .drive(&mut follower, &mut headers, &aegis, &mut fc, NOW)
        .expect("caught-up drive succeeds");
    assert!(events.is_empty(), "{events:?}");
}

#[test]
fn drive_block_source_failure_buffers_header_and_heals_on_next_drive() {
    // REAL-ORACLE: the header is PoW-gated and applied, but the block
    // source cannot serve its fields — the header is buffered, the
    // drive errors, and a later drive (source healed) completes the
    // scan without refetching headers.
    let (header, fields) = real_block_parts();
    let mut watch = watch_with(&[]); // empty source
    let mut follower = Follower::new(0);
    let mut headers = VecHeaderSource::new(vec![header.clone()]);
    let aegis = MemoryAegisSource::new();
    let mut fc = fc_new();

    let err = watch
        .drive(&mut follower, &mut headers, &aegis, &mut fc, NOW)
        .unwrap_err();
    assert!(
        matches!(err, WatchError::Scan(ScanError::Blocks(_))),
        "{err:?}"
    );
    assert_eq!(follower.tip_height(), Some(H_REF), "header was applied");
    assert_eq!(watch.pending_retry(), (1, 0), "header buffered for rescan");

    // Still failing: a retry against the still-empty source re-buffers
    // and reports the same miss.
    let err = watch
        .retry_pending(H_REF, &aegis, &mut fc, NOW)
        .unwrap_err();
    assert!(matches!(err, ScanError::Blocks(_)), "{err:?}");
    assert_eq!(watch.pending_retry(), (1, 0), "still buffered");

    // Source heals: the next drive rescans the buffered header without
    // refetching it from the header source.
    watch.blocks_mut().insert(ergo_id(&header), fields.clone());
    let events = watch
        .drive(&mut follower, &mut headers, &aegis, &mut fc, NOW)
        .expect("healed drive succeeds");
    assert!(
        matches!(
            events[..],
            [WatchEvent::NoCommitment { ergo_height: H_REF }]
        ),
        "{events:?}"
    );
    assert_eq!(watch.pending_retry(), (0, 0), "buffer drained");
}

// ----- happy path (synthetic commitment pipeline) -----

#[test]
fn commitment_share_body_anchor_and_finality_end_to_end() {
    // SYNTHETIC: one Aegis block committed in a synthetic Ergo header
    // (real header re-rooted, nonce ground against the AEGIS target).
    // The watcher extracts, verifies, ingests share + body, records
    // the anchor, and the block becomes canonical AND peg-final.
    let a1 = extend_branch(&[], 1, T_MS).remove(0);
    let (eh, fields) = committed_header(a1.id(), Some(a1.header.sc_nbits));
    let mut watch = watch_with(&[(&eh, &fields)]);
    let mut aegis = MemoryAegisSource::new();
    aegis.insert_block(a1.clone());
    let mut fc = fc_new();

    let events = watch
        .scan_ergo_header(&eh, true, H_REF, &aegis, &mut fc, NOW)
        .expect("scan succeeds");
    assert!(
        matches!(
            events[..],
            [WatchEvent::Verified {
                ergo_height: H_REF,
                share: ShareIngest::Pending,
                body: Some(BodyIngest::Activated { activated: 1 }),
                anchored: true,
                ..
            }]
        ),
        "{events:?}"
    );
    assert_eq!(fc.canonical_tip_id(), a1.id());

    // Peg finality at the settled Ergo height: W(a1) leads the empty
    // competition by exactly W(a1).
    let w = decode_compact_bits(a1.header.sc_nbits);
    assert!(fc.is_final(&a1.id(), &w, H_REF));
    assert!(!fc.is_final(&a1.id(), &(&w + 1u32), H_REF));

    // settled_is_final plumbing: judged at the REAL follower's settled
    // reference (single caught-up follower contract).
    let (real_header, _) = real_block_parts();
    let mut caught_up = Follower::new(0); // settled ref == tip
    caught_up.apply_header(&real_header).expect("real PoW");
    assert!(settled_is_final(&fc, &caught_up, &a1.id(), &w));

    let mut shallow = Follower::new(1); // root-only chain: no settled ref
    shallow.apply_header(&real_header).expect("real PoW");
    assert!(
        !settled_is_final(&fc, &shallow, &a1.id(), &BigUint::ZERO),
        "no settled reference → refuse to judge"
    );
}

#[test]
fn competing_commitments_resolve_by_cumulative_work() {
    // SYNTHETIC: branch A (1 block) vs branch B (2 blocks), each block
    // committed in its own synthetic Ergo header — the heavier branch
    // wins the canonical tip regardless of scan order.
    let a = extend_branch(&[], 1, T_MS);
    let b = extend_branch(&[], 2, T_MS + 1_000); // distinct ids
    let mut aegis = MemoryAegisSource::new();
    let mut entries = Vec::new();
    for blk in a.iter().chain(b.iter()) {
        aegis.insert_block(blk.clone());
        entries.push(committed_header(blk.id(), Some(blk.header.sc_nbits)));
    }
    let refs: Vec<(&ErgoHeader, &[ExtensionField])> =
        entries.iter().map(|(h, f)| (h, f.as_slice())).collect();
    let mut watch = watch_with(&refs);
    let mut fc = fc_new();

    for (eh, _) in &entries {
        let events = watch
            .scan_ergo_header(eh, true, H_REF, &aegis, &mut fc, NOW)
            .expect("scan succeeds");
        assert!(
            matches!(events[..], [WatchEvent::Verified { .. }]),
            "{events:?}"
        );
    }
    assert_eq!(
        fc.canonical_tip_id(),
        b.last().unwrap().id(),
        "two-block branch outweighs one-block branch"
    );
    assert!(fc.is_validated(&a[0].id()), "lighter branch stays in tree");
    assert_eq!(
        fc.cumulative_work(&fc.canonical_tip_id()).unwrap(),
        &(decode_compact_bits(b[0].header.sc_nbits) * 2u32)
    );
}

#[test]
fn body_missing_share_stays_pending_until_body_arrives() {
    // SYNTHETIC: header-only Aegis source — the share verifies and is
    // ingested (weight known, hostile-counted) but the block is not a
    // fork-choice candidate until its body lands.
    let a1 = extend_branch(&[], 1, T_MS).remove(0);
    let (eh, fields) = committed_header(a1.id(), Some(a1.header.sc_nbits));
    let mut watch = watch_with(&[(&eh, &fields)]);
    let mut aegis = MemoryAegisSource::new();
    aegis.insert_header(a1.header.clone());
    let mut fc = fc_new();

    let events = watch
        .scan_ergo_header(&eh, true, H_REF, &aegis, &mut fc, NOW)
        .expect("scan succeeds");
    assert!(
        matches!(
            events[..],
            [WatchEvent::Verified {
                share: ShareIngest::Pending,
                body: None,
                ..
            }]
        ),
        "{events:?}"
    );
    assert!(fc.is_pending(&a1.id()));
    assert_eq!(
        fc.pending_hostile_work(),
        decode_compact_bits(a1.header.sc_nbits),
        "withheld body's weight counts hostile (§7)"
    );
    assert_eq!(fc.canonical_tip_id(), genesis_header(Network::Dev).id());

    // Body arrives later (M6b gossip path feeds ingest_body directly).
    assert!(matches!(
        fc.ingest_body(a1.clone(), NOW),
        BodyIngest::Activated { activated: 1 }
    ));
    assert_eq!(fc.canonical_tip_id(), a1.id());
}

#[test]
fn unknown_aegis_block_buffers_then_verifies_on_retry() {
    // SYNTHETIC: the commitment references an Aegis block the source
    // has never heard of → buffered; once the source learns it (M6b
    // will fetch via P2P), a retry verifies and feeds it.
    let a1 = extend_branch(&[], 1, T_MS).remove(0);
    let (eh, fields) = committed_header(a1.id(), Some(a1.header.sc_nbits));
    let mut watch = watch_with(&[(&eh, &fields)]);
    let mut aegis = MemoryAegisSource::new();
    let mut fc = fc_new();

    let events = watch
        .scan_ergo_header(&eh, true, H_REF, &aegis, &mut fc, NOW)
        .expect("scan succeeds");
    assert!(
        matches!(
            events[..],
            [WatchEvent::Unresolved {
                ergo_height: H_REF,
                reason: UnresolvedReason::UnknownAegisBlock,
                ..
            }]
        ),
        "{events:?}"
    );
    assert_eq!(watch.pending_retry(), (0, 1));
    assert_eq!(fc.canonical_tip_id(), genesis_header(Network::Dev).id());

    aegis.insert_block(a1.clone());
    let events = watch
        .retry_pending(H_REF, &aegis, &mut fc, NOW)
        .expect("retry succeeds");
    assert!(
        matches!(events[..], [WatchEvent::Verified { anchored: true, .. }]),
        "{events:?}"
    );
    assert_eq!(watch.pending_retry(), (0, 0));
    assert_eq!(fc.canonical_tip_id(), a1.id());
}

#[test]
fn parent_not_validated_buffers_then_cascades_on_retry() {
    // SYNTHETIC: a2's commitment arrives before a1 is validated — the
    // DAA expectation for a2 is undecidable, so it buffers; once a1
    // lands, the retry verifies a2 and the tip cascades.
    let blocks = extend_branch(&[], 2, T_MS);
    let (a1, a2) = (&blocks[0], &blocks[1]);
    let (eh2, fields2) = committed_header(a2.id(), Some(a2.header.sc_nbits));
    let (eh1, fields1) = committed_header(a1.id(), Some(a1.header.sc_nbits));
    let mut watch = watch_with(&[(&eh1, &fields1), (&eh2, &fields2)]);
    let mut aegis = MemoryAegisSource::new();
    aegis.insert_block(a1.clone());
    aegis.insert_block(a2.clone());
    let mut fc = fc_new();

    let events = watch
        .scan_ergo_header(&eh2, true, H_REF, &aegis, &mut fc, NOW)
        .expect("scan succeeds");
    assert!(
        matches!(
            events[..],
            [WatchEvent::Unresolved {
                reason: UnresolvedReason::ParentNotValidated,
                ..
            }]
        ),
        "{events:?}"
    );

    let events = watch
        .scan_ergo_header(&eh1, true, H_REF, &aegis, &mut fc, NOW)
        .expect("scan succeeds");
    assert!(
        matches!(events[..], [WatchEvent::Verified { .. }]),
        "{events:?}"
    );
    assert_eq!(fc.canonical_tip_id(), a1.id());

    let events = watch
        .retry_pending(H_REF, &aegis, &mut fc, NOW)
        .expect("retry succeeds");
    assert!(
        matches!(events[..], [WatchEvent::Verified { .. }]),
        "{events:?}"
    );
    assert_eq!(fc.canonical_tip_id(), a2.id());
    assert_eq!(watch.pending_retry(), (0, 0));
}

// ----- error paths -----

#[test]
fn ungrounded_nonce_rejected_pow_not_cleared() {
    // SYNTHETIC: valid commitment + proof, but the (real, unmined)
    // nonce's hit does not clear the AEGIS target → rejected at step
    // 6; the fork-choice never sees it.
    let a1 = extend_branch(&[], 1, T_MS).remove(0);
    let (eh, fields) = committed_header(a1.id(), None); // no grind
    let mut watch = watch_with(&[(&eh, &fields)]);
    let mut aegis = MemoryAegisSource::new();
    aegis.insert_block(a1.clone());
    let mut fc = fc_new();

    let events = watch
        .scan_ergo_header(&eh, true, H_REF, &aegis, &mut fc, NOW)
        .expect("scan succeeds");
    assert!(
        matches!(
            events[..],
            [WatchEvent::Rejected {
                error: ShareError::PowNotCleared { .. },
                ..
            }]
        ),
        "{events:?}"
    );
    assert_eq!(fc.canonical_tip_id(), genesis_header(Network::Dev).id());
    assert!(!fc.is_pending(&a1.id()));
    assert_eq!(fc.pending_hostile_work(), BigUint::ZERO);
}

#[test]
fn self_declared_easy_nbits_rejected_by_daa_equality() {
    // SYNTHETIC: the Aegis header self-declares difficulty 1 (easier
    // than the DAA-mandated dev minimum 1000); the hit clears its own
    // easy target but the sc_nbits equality rejects it (§3 defense).
    let a1 = extend_branch(&[], 1, T_MS).remove(0);
    let mut easy_header = a1.header.clone();
    easy_header.sc_nbits = difficulty_to_nbits(&BigUint::from(1u8));
    let (eh, fields) = committed_header(easy_header.id(), Some(easy_header.sc_nbits));
    let mut watch = watch_with(&[(&eh, &fields)]);
    let mut aegis = MemoryAegisSource::new();
    aegis.insert_header(easy_header);
    let mut fc = fc_new();

    let events = watch
        .scan_ergo_header(&eh, true, H_REF, &aegis, &mut fc, NOW)
        .expect("scan succeeds");
    assert!(
        matches!(
            events[..],
            [WatchEvent::Rejected {
                error: ShareError::NbitsMismatch { .. },
                ..
            }]
        ),
        "{events:?}"
    );
    assert_eq!(fc.pending_hostile_work(), BigUint::ZERO);
}

#[test]
fn stale_ergo_candidate_rejected_outside_share_window() {
    // SYNTHETIC: the committed Ergo candidate sits below
    // follower_tip − K_LAG — the C2 anti-stockpiling window rejects it.
    let a1 = extend_branch(&[], 1, T_MS).remove(0);
    let (eh, fields) = committed_header(a1.id(), Some(a1.header.sc_nbits));
    let mut watch = watch_with(&[(&eh, &fields)]);
    let mut aegis = MemoryAegisSource::new();
    aegis.insert_block(a1.clone());
    let mut fc = fc_new();

    let far_tip = H_REF + K_LAG + 1;
    let events = watch
        .scan_ergo_header(&eh, true, far_tip, &aegis, &mut fc, NOW)
        .expect("scan succeeds");
    assert!(
        matches!(
            events[..],
            [WatchEvent::Rejected {
                error: ShareError::HeightOutOfWindow { .. },
                ..
            }]
        ),
        "{events:?}"
    );
}

#[test]
fn buffered_commitment_expires_when_window_moves_past_it() {
    // SYNTHETIC: an unresolved commitment whose carrying Ergo block
    // falls below tip − K_LAG can never verify again — pruned.
    let a1 = extend_branch(&[], 1, T_MS).remove(0);
    let (eh, fields) = committed_header(a1.id(), Some(a1.header.sc_nbits));
    let mut watch = watch_with(&[(&eh, &fields)]);
    let aegis = MemoryAegisSource::new(); // never learns the block
    let mut fc = fc_new();

    watch
        .scan_ergo_header(&eh, true, H_REF, &aegis, &mut fc, NOW)
        .expect("scan succeeds");
    assert_eq!(watch.pending_retry(), (0, 1));

    let events = watch
        .retry_pending(H_REF + K_LAG + 1, &aegis, &mut fc, NOW)
        .expect("retry succeeds");
    assert!(
        matches!(
            events[..],
            [WatchEvent::Expired {
                aegis_id: Some(_),
                ergo_height: H_REF,
            }]
        ),
        "{events:?}"
    );
    assert_eq!(watch.pending_retry(), (0, 0));
}
