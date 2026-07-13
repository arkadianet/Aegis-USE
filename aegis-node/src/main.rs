//! `aegis-node` binary: the merge-mining node loop (M6c).
//!
//! Composes the library's [`aegis_node::node::Node`] runner: boot
//! (archive resume + fresh sync), then a tick loop that follows Ergo
//! (`--ergo-url`), syncs bodies/witnesses from seeds (`--seed-url`),
//! produces merge-mined dev blocks (`--produce`, dev network only),
//! and serves the archive to peers (`--serve-addr`). Blocking work
//! (HTTP polls, share grinding, seed sync) runs under
//! `spawn_blocking`, off the async loop.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aegis_node::node::{Node, NodeConfig};
use aegis_spec::Network;
use clap::Parser;
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "aegis-node", about = "Aegis sidechain merge-mining node")]
struct Args {
    /// Network to run: dev, test, or main.
    #[arg(long, default_value = "dev")]
    network: String,

    /// Produce merge-mined blocks (honored on the dev network only —
    /// real networks need the Ergo-side candidate builder; see
    /// `node.rs`).
    #[arg(long, default_value_t = true)]
    produce: bool,

    /// Stop after this many produced blocks (0 = run until Ctrl-C).
    #[arg(long, default_value_t = 0)]
    max_blocks: u64,

    /// Persist blocks + share witnesses to this directory and resume
    /// from it on boot. Unset: fully in-memory.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Ergo node REST base URL for the follower + anchor watcher
    /// (e.g. http://127.0.0.1:9052). On non-dev networks this is the
    /// node's block source.
    #[arg(long)]
    ergo_url: Option<String>,

    /// Ergo height the follower starts from when empty (the followed
    /// root, e.g. the network's Aegis genesis anchor height).
    #[arg(long, default_value_t = 1)]
    ergo_start_height: u32,

    /// Seed base URL for body/witness fetch + fresh sync (repeatable).
    #[arg(long)]
    seed_url: Vec<String>,

    /// Bind address for this node's own seed server
    /// (e.g. 127.0.0.1:8650; port 0 for ephemeral).
    #[arg(long)]
    serve_addr: Option<String>,

    /// Peg-finality work lead (difficulty units) for the per-tick
    /// `is_final` telemetry.
    #[arg(long, default_value_t = 0)]
    l_final: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_target(false).init();
    let args = Args::parse();

    let network = match args.network.as_str() {
        "dev" => Network::Dev,
        "test" => Network::Test,
        "main" => Network::Main,
        other => return Err(format!("unknown network {other:?} (dev|test|main)").into()),
    };
    let params = network.params();
    let config = NodeConfig {
        network,
        produce: args.produce,
        data_dir: args.data_dir,
        ergo_url: args.ergo_url,
        ergo_start_height: args.ergo_start_height,
        seed_urls: args.seed_url,
        serve_addr: args.serve_addr,
        l_final: args.l_final,
    };
    let producing = config.produce && network == Network::Dev;

    let boot_now = now_ms();
    let node = tokio::task::spawn_blocking(move || Node::boot(config, boot_now)).await??;
    info!(
        network = params.network_name,
        genesis = hex::encode(aegis_node::genesis_header(network).id()),
        tip_height = node.canonical_height(),
        tip = hex::encode(node.canonical_tip_id()),
        serve = ?node.serve_addr(),
        producing,
        target_secs = params.block_target_secs,
        "aegis-node booted (merge-mining loop)"
    );

    // Producers tick at the block target; consumers poll faster so a
    // freshly served block is picked up promptly.
    let tick = if producing {
        Duration::from_secs(params.block_target_secs)
    } else {
        Duration::from_secs(2)
    };

    let mut node = Some(node);
    let mut produced_total = 0u64;
    let mut last_height = u64::MAX;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(tick) => {}
            _ = tokio::signal::ctrl_c() => break,
        }
        let mut n = node
            .take()
            .expect("node is always returned by the tick task");
        let now = now_ms();
        let (n, report) = tokio::task::spawn_blocking(move || {
            let report = n.tick(now);
            (n, report)
        })
        .await?;
        node = Some(n);

        for e in &report.errors {
            warn!(error = %e, "tick error (retried next tick)");
        }
        for ev in &report.watch_events {
            info!(event = %ev, "ergo watch");
        }
        if let Some((height, id)) = report.produced {
            produced_total += 1;
            info!(
                height,
                id = hex::encode(id),
                tip = hex::encode(report.canonical_tip),
                work = %report.cumulative_work,
                pending_hostile = %report.pending_hostile_work,
                ergo_tip = ?report.ergo_tip_height,
                is_final = report.tip_is_final,
                "merge-mined block produced"
            );
        } else if report.canonical_height != last_height || report.sync_activated > 0 {
            info!(
                height = report.canonical_height,
                tip = hex::encode(report.canonical_tip),
                work = %report.cumulative_work,
                synced = report.sync_activated,
                pending_hostile = %report.pending_hostile_work,
                ergo_tip = ?report.ergo_tip_height,
                is_final = report.tip_is_final,
                "chain advanced"
            );
        }
        last_height = report.canonical_height;

        if args.max_blocks != 0 && produced_total >= args.max_blocks {
            break;
        }
    }
    let node = node.expect("node present at shutdown");
    info!(tip = node.canonical_height(), "shutting down");
    Ok(())
}
