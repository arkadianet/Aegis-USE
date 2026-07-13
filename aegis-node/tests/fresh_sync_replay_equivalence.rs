//! Fresh-node sync — bootstrap-correctness tests (p2p.md §5 — M6b-1).
//!
//! THE load-bearing property: node A produces N blocks (synthetic
//! aux-PoW shares, M6a discipline) into a fork choice + seed archive;
//! node B, starting empty, fresh-syncs by walking its own Ergo view
//! plus fetching witnesses/bodies from A-as-seed — in memory and over
//! loopback HTTP — and must land on **the same canonical tip, the same
//! validated set, and the same shielded state**.
//!
//! ## Real-oracle vs structural (honesty)
//!
//! The Ergo header base is REAL testnet block 442815 (verbatim node
//! capture); B's follower PoW-gates it for real inside `fresh_sync`.
//! No real Ergo block carries an `AEGIS_MM_KEY` field yet, so witness
//! commitments re-root that header's extension over (real fields ‖
//! commitment) and grind an Autolykos nonce against the (easy,
//! dev-genesis) AEGIS target only — the M2a/M6a synthetic-share
//! discipline. Such headers cannot pass the follower's Ergo-level PoW
//! gate, so the anchored-resolution test drives the public per-header
//! core `scan_ergo_header` directly. A real Ergo block's own PoW is
//! NEVER fabricated.

use std::sync::{Arc, RwLock};

use aegis_node::ergo_follow::poll::VecHeaderSource;
use aegis_node::ergo_follow::Follower;
use aegis_node::seed::fetch_http::{RestAegisSource, SeedClientConfig};
use aegis_node::seed::serve_http::SeedServer;
use aegis_node::{
    aegis_mm_extension_field, extension_field_proof, fresh_sync, sync_from_seeds, AnchorWatch,
    Block, BlockBody, BodyIngest, Chain, MemoryBlockSource, MmForkChoice, PowMode, ProofMode,
    SeedCore, ShareWitness, ValidShare, WatchEvent,
};
use aegis_spec::Network;
use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::autolykos::v2::check_pow_v2;
use ergo_crypto::difficulty::get_target;
use ergo_crypto::merkle::extension_root;
use ergo_rest_json::types::ScalaFullBlock;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::extension::ExtensionField;
use ergo_ser::header::{serialize_header, serialize_header_without_pow, Header as ErgoHeader};

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
/// AEGIS target from `nbits` (dev-genesis difficulty → cheap).
/// Synthetic-share discipline only — never fakes real Ergo PoW.
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

/// A fully verifiable [`ShareWitness`] for `block`: the real Ergo
/// header re-rooted over (real fields ‖ commitment), nonce ground
/// against the block's own DAA-pinned `sc_nbits`.
fn witness_for(block: &Block) -> ShareWitness {
    let (mut eh, mut fields) = real_block_parts();
    let field = aegis_mm_extension_field(block.id());
    fields.push(field.clone());
    let pairs: Vec<(&[u8], &[u8])> = fields.iter().map(|f| (&f.key[..], &f.value[..])).collect();
    eh.extension_root = extension_root(&pairs).into();
    grind(&mut eh, block.header.sc_nbits);
    let proof = extension_field_proof(&fields, (fields.len() - 1) as u32).expect("index in range");
    ShareWitness {
        ergo_header: eh,
        field,
        proof,
        aegis_block_bytes: block.bytes(),
    }
}

/// Produce `n` blocks extending `prefix` (itself extending genesis),
/// `spacing_ms` apart. Returns only the new blocks.
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
            .expect("block produces");
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

/// Node A: `blocks` fed to a fork choice (shares at Ergo height H_REF,
/// like the witnesses claim) and archived — with witnesses — into a
/// seed core. Returns (A's fork choice, A-as-seed).
fn node_a(blocks: &[Block]) -> (MmForkChoice, SeedCore) {
    let mut fc = fc_new();
    let mut core = SeedCore::new(Network::Dev);
    for b in blocks {
        fc.ingest_share(
            &ValidShare {
                aegis_id: b.id(),
                work: decode_compact_bits(b.header.sc_nbits),
                ergo_height: H_REF,
            },
            NOW,
        );
        assert!(matches!(
            fc.ingest_body(b.clone(), NOW),
            BodyIngest::Activated { .. }
        ));
        core.record_canonical(b);
        core.record_witness(&witness_for(b))
            .expect("witness records");
    }
    assert_eq!(fc.canonical_tip_id(), blocks.last().unwrap().id());
    (fc, core)
}

/// Node B's empty Ergo-side machinery: follower + anchor-watch over
/// the REAL capture header (whose fields carry no commitment).
fn node_b_ergo() -> (Follower, VecHeaderSource, AnchorWatch<MemoryBlockSource>) {
    let (header, fields) = real_block_parts();
    let mut blocks = MemoryBlockSource::new();
    blocks.insert(ergo_id(&header), fields);
    let watch = AnchorWatch::new(blocks, Network::Dev, H_REF);
    (Follower::new(0), VecHeaderSource::new(vec![header]), watch)
}

/// Assert node B replayed to exactly node A's chain: same canonical
/// tip, same validated set, same shielded post-state.
fn assert_replay_equivalent(a: &MmForkChoice, b: &MmForkChoice, blocks: &[Block]) {
    assert_eq!(
        b.canonical_tip_id(),
        a.canonical_tip_id(),
        "B's canonical tip must equal A's"
    );
    assert_eq!(b.canonical_tip().height, a.canonical_tip().height);
    for blk in blocks {
        assert!(
            b.is_validated(&blk.id()),
            "block {} must be validated on B",
            blk.header.height
        );
        assert_eq!(
            b.cumulative_work(&blk.id()),
            a.cumulative_work(&blk.id()),
            "same weight accounting at height {}",
            blk.header.height
        );
    }
    assert_eq!(
        b.chain().state(),
        a.chain().state(),
        "replayed shielded state must be identical"
    );
    assert_eq!(b.chain().tip().id(), a.canonical_tip_id());
}

fn http_client(urls: &[String]) -> RestAegisSource {
    let mut config = SeedClientConfig::new(urls.iter().cloned());
    config.timeout = std::time::Duration::from_secs(5);
    RestAegisSource::new(config).expect("client builds")
}

fn serve(core: SeedCore) -> SeedServer {
    SeedServer::spawn("127.0.0.1:0", Arc::new(RwLock::new(core))).expect("server spawns")
}

// ----- happy path (replay equivalence — the load-bearing property) -----

#[test]
fn fresh_sync_replay_equivalence_in_memory() {
    let blocks = extend_branch(&[], 6, T_MS);
    let (fc_a, core) = node_a(&blocks);

    let (mut follower, mut headers, mut watch) = node_b_ergo();
    let mut fc_b = fc_new();
    let report = fresh_sync(
        &mut follower,
        &mut headers,
        &mut watch,
        &core,
        &mut fc_b,
        Network::Dev,
        NOW,
    )
    .expect("fresh sync succeeds");

    assert_eq!(report.ergo_tip_height, Some(H_REF), "real header followed");
    assert_eq!(report.seed.activated, blocks.len());
    assert_eq!(report.seed.tips_claims, vec![(blocks[5].id(), 6)]);
    assert!(report.seed.missing_witness.is_empty());
    assert!(
        report.seed.rejected.is_empty(),
        "{:?}",
        report.seed.rejected
    );
    assert_eq!(report.canonical_tip, fc_a.canonical_tip_id());
    assert_replay_equivalent(&fc_a, &fc_b, &blocks);
}

#[test]
fn fresh_sync_replay_equivalence_over_loopback_http() {
    let blocks = extend_branch(&[], 4, T_MS);
    let (fc_a, core) = node_a(&blocks);
    let server = serve(core);
    let client = http_client(&[server.base_url()]);

    let (mut follower, mut headers, mut watch) = node_b_ergo();
    let mut fc_b = fc_new();
    let report = fresh_sync(
        &mut follower,
        &mut headers,
        &mut watch,
        &client,
        &mut fc_b,
        Network::Dev,
        NOW,
    )
    .expect("fresh sync over HTTP succeeds");

    assert_eq!(report.seed.activated, blocks.len());
    assert_replay_equivalent(&fc_a, &fc_b, &blocks);
}

// ----- error paths (withholding — liveness only, never a stall) -----

#[test]
fn withheld_block_fails_over_to_second_seed_over_http() {
    // Seed 1 withholds block 3 entirely (404 for witness and body);
    // seed 2 archives everything. Fresh sync must reach A's tip by
    // failing over per id — any seed with the bytes works.
    let blocks = extend_branch(&[], 4, T_MS);
    let (fc_a, full_core) = node_a(&blocks);

    let mut partial = SeedCore::new(Network::Dev);
    for (i, b) in blocks.iter().enumerate() {
        partial.record_canonical(b); // hints still list every height
        if i != 2 {
            partial.record_witness(&witness_for(b)).expect("records");
        }
    }

    let seed1 = serve(partial);
    let seed2 = serve(full_core);
    let client = http_client(&[seed1.base_url(), seed2.base_url()]);

    let (mut follower, mut headers, mut watch) = node_b_ergo();
    let mut fc_b = fc_new();
    let report = fresh_sync(
        &mut follower,
        &mut headers,
        &mut watch,
        &client,
        &mut fc_b,
        Network::Dev,
        NOW,
    )
    .expect("fresh sync with failover succeeds");

    assert_eq!(report.seed.activated, blocks.len());
    assert!(
        report.seed.missing_witness.is_empty(),
        "seed 2 covered the hole"
    );
    assert_replay_equivalent(&fc_a, &fc_b, &blocks);
}

#[test]
fn all_seeds_withholding_leaves_suffix_absent_then_heals_monotonically() {
    // Every seed withholds block 3: sync reaches height 2, reports the
    // hole, and NOTHING stalls or poisons. A later pass against a
    // healed seed completes to the tip — availability is a monotone
    // input (merge-mining.md §5).
    let blocks = extend_branch(&[], 4, T_MS);
    let (fc_a, full_core) = node_a(&blocks);

    let mut holed = SeedCore::new(Network::Dev);
    for (i, b) in blocks.iter().enumerate() {
        holed.record_canonical(b);
        if i != 2 {
            holed.record_witness(&witness_for(b)).expect("records");
        }
    }

    let mut fc_b = fc_new();
    let report =
        sync_from_seeds(&holed, &mut fc_b, Some(H_REF), Network::Dev, NOW).expect("first pass");
    assert_eq!(report.missing_witness, vec![blocks[2].id()]);
    assert_eq!(report.missing_parent, vec![blocks[3].id()]);
    assert_eq!(
        fc_b.canonical_tip_id(),
        blocks[1].id(),
        "sync proceeds to the last available block — no stall"
    );
    assert!(
        !fc_b.is_dead(&blocks[2].id()),
        "withholding is never a verdict"
    );

    // Heal: the next pass (any seed with the bytes) completes the chain.
    let report =
        sync_from_seeds(&full_core, &mut fc_b, Some(H_REF), Network::Dev, NOW).expect("heal pass");
    assert_eq!(report.activated, 2, "the hole and its child activate");
    assert_replay_equivalent(&fc_a, &fc_b, &blocks);
}

// ----- oracle parity (anchored skeleton resolves bodies from seeds) -----

#[test]
fn anchored_commitment_resolves_body_from_http_seed() {
    // The anchor-watcher path with the HTTP client as its AegisSource:
    // a committed (synthetic) Ergo header scans, the committed block's
    // body is fetched from the seed by id, the share verifies, and the
    // block lands validated AND anchored. The fetch is witness-first in
    // the anchored sense: it is gated by the Ergo-PoW-committed
    // commitment the watcher just authenticated.
    let blocks = extend_branch(&[], 1, T_MS);
    let (_, core) = node_a(&blocks);
    let server = serve(core);
    let client = http_client(&[server.base_url()]);

    let (mut eh, mut fields) = real_block_parts();
    fields.push(aegis_mm_extension_field(blocks[0].id()));
    let pairs: Vec<(&[u8], &[u8])> = fields.iter().map(|f| (&f.key[..], &f.value[..])).collect();
    eh.extension_root = extension_root(&pairs).into();
    grind(&mut eh, blocks[0].header.sc_nbits);

    let mut source = MemoryBlockSource::new();
    source.insert(ergo_id(&eh), fields);
    let mut watch = AnchorWatch::new(source, Network::Dev, H_REF);
    let mut fc = fc_new();
    let events = watch
        .scan_ergo_header(&eh, true, H_REF, &client, &mut fc, NOW)
        .expect("scan succeeds");
    assert!(
        matches!(
            events[..],
            [WatchEvent::Verified {
                anchored: true,
                body: Some(BodyIngest::Activated { activated: 1 }),
                ..
            }]
        ),
        "{events:?}"
    );
    assert_eq!(fc.canonical_tip_id(), blocks[0].id());
    // Anchored + settled ⇒ peg-final at exactly its own weight lead.
    let w = decode_compact_bits(blocks[0].header.sc_nbits);
    assert!(fc.is_final(&blocks[0].id(), &w, H_REF));
}
