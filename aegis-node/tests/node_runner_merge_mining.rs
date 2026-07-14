//! M6c node-runner integration: a dev node produces blocks through
//! the FULL merge-mining path (grind → `verify_share` → fork choice →
//! persist → serve), restarts from its `--data-dir` and resumes at the
//! same tip, and a second node pointed at it as a seed fresh-syncs to
//! the same tip and keeps following — the M6b-1 replay-equivalence
//! property composed with the real runner.
//!
//! Everything here drives the public [`Node`] API exactly as the
//! binary's loop does (synchronous ticks with an advancing synthetic
//! clock — the binary only adds the tokio timer around them).

use aegis_node::{Node, NodeConfig};
use aegis_spec::Network;
use num_bigint::BigUint;
use std::path::Path;

// ----- helpers -----

/// Dev block target (ms) — ticks advance the synthetic clock by this.
const T_MS: u64 = 15_000;

/// Synthetic wall clock start, far past the dev genesis timestamp
/// (1_760_000_000_000) so MTP/future-drift bounds are trivially met.
const START: u64 = 1_761_000_000_000;

/// Dev genesis difficulty — each dev block's fork-choice weight until
/// the LWMA window fills.
const DEV_DIFFICULTY: u32 = 1_000;

fn producer_config(data_dir: &Path, serve: bool) -> NodeConfig {
    NodeConfig {
        network: Network::Dev,
        produce: true,
        data_dir: Some(data_dir.to_path_buf()),
        ergo_url: None,
        ergo_start_height: 1,
        seed_urls: Vec::new(),
        serve_addr: serve.then(|| "127.0.0.1:0".to_string()),
        api_addr: None,
        attester: None,
        l_final: 0,
    }
}

fn consumer_config(data_dir: &Path, seed_url: String) -> NodeConfig {
    NodeConfig {
        network: Network::Dev,
        produce: false,
        data_dir: Some(data_dir.to_path_buf()),
        ergo_url: None,
        ergo_start_height: 1,
        seed_urls: vec![seed_url],
        serve_addr: None,
        api_addr: None,
        attester: None,
        l_final: 0,
    }
}

/// Tick `node` `n` times, advancing the clock a block target per tick;
/// every tick must be error-free and (for a producer) produce.
fn produce_blocks(node: &mut Node, now: &mut u64, n: usize) {
    for _ in 0..n {
        *now += T_MS;
        let report = node.tick(*now);
        assert!(report.errors.is_empty(), "tick errors: {:?}", report.errors);
        assert!(
            report.produced.is_some(),
            "producer tick must produce a block"
        );
    }
}

// ----- happy path -----

#[test]
fn dev_node_produces_through_full_merge_mining_path_and_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let mut now = START;

    // K blocks through grind → verify_share → fork choice → persist.
    let mut node = Node::boot(producer_config(dir.path(), false), now).expect("boots");
    assert_eq!(node.canonical_height(), 0, "fresh dir starts at genesis");
    produce_blocks(&mut node, &mut now, 5);
    assert_eq!(node.canonical_height(), 5);
    let tip = node.canonical_tip_id();
    // Real aux-PoW weight, not block count: cumulative work is the sum
    // of each block's DAA-pinned difficulty.
    assert_eq!(
        node.fork_choice().cumulative_work(&tip).cloned().unwrap(),
        BigUint::from(DEV_DIFFICULTY) * 5u32,
        "canonical weight = 5 dev-difficulty shares"
    );
    assert_eq!(
        node.fork_choice().pending_hostile_work(),
        BigUint::ZERO,
        "every self-mined share activated"
    );
    let state_before = node.fork_choice().chain().state().clone();
    drop(node);

    // Restart: the archive replays through full verification (witness
    // re-verify + body re-validate) and resumes at the same tip.
    now += T_MS;
    let mut node = Node::boot(producer_config(dir.path(), false), now).expect("reboots");
    assert_eq!(node.canonical_height(), 5, "resumes at the persisted tip");
    assert_eq!(node.canonical_tip_id(), tip, "same tip id after restart");
    assert_eq!(
        node.fork_choice().chain().state(),
        &state_before,
        "replayed shielded state is identical"
    );

    // And keeps producing on top of the resumed tip.
    produce_blocks(&mut node, &mut now, 1);
    assert_eq!(node.canonical_height(), 6);
}

#[test]
fn second_node_fresh_syncs_from_live_producer_and_follows() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let mut now = START;

    // Node A: producing + serving its archive on an ephemeral port.
    let mut a = Node::boot(producer_config(dir_a.path(), true), now).expect("A boots");
    produce_blocks(&mut a, &mut now, 4);
    let a_tip = a.canonical_tip_id();
    let seed_url = format!("http://{}", a.serve_addr().expect("A serves"));

    // Node B: boots against A as its seed — boot's catch-up pass
    // fresh-syncs to A's tip (witness-first: every share re-verified).
    now += 1;
    let mut b = Node::boot(consumer_config(dir_b.path(), seed_url.clone()), now).expect("B boots");
    assert_eq!(b.canonical_height(), 4, "B fresh-synced to A's tip");
    assert_eq!(b.canonical_tip_id(), a_tip);
    assert_eq!(
        b.fork_choice().chain().state(),
        a.fork_choice().chain().state(),
        "replay-equivalent shielded state"
    );

    // A extends; B's next tick picks the new block up from the seed.
    produce_blocks(&mut a, &mut now, 1);
    now += 1;
    let report = b.tick(now);
    assert!(
        report.errors.is_empty(),
        "B tick errors: {:?}",
        report.errors
    );
    assert_eq!(report.sync_activated, 1, "B synced the new block");
    assert_eq!(b.canonical_height(), 5);
    assert_eq!(b.canonical_tip_id(), a.canonical_tip_id());

    // B persisted what it verified: a restart (with A gone) resumes at
    // the synced tip from B's own archive.
    let b_tip = b.canonical_tip_id();
    drop(b);
    drop(a);
    now += T_MS;
    let b2 = Node::boot(consumer_config(dir_b.path(), seed_url), now).expect("B reboots");
    assert_eq!(b2.canonical_height(), 5, "B resumes from its own archive");
    assert_eq!(b2.canonical_tip_id(), b_tip);
}
