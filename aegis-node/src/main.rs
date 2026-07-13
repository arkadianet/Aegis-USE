//! `aegis-node` binary: boots a network's chain from genesis and, in
//! dev mode, produces empty blocks at the 15 s target (G1). P2P, the
//! tx/state layer, and Autolykos witness verification arrive in later
//! slices — this is the walking skeleton the gate asks for.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aegis_crypto::note::EvenScalar;
use aegis_node::{BlockBody, Chain, PowMode, ProofMode};
use aegis_spec::Network;
use clap::Parser;
use tracing::info;

#[derive(Parser)]
#[command(name = "aegis-node", about = "Aegis sidechain node (G1 dev skeleton)")]
struct Args {
    /// Network to run: dev, test, or main.
    #[arg(long, default_value = "dev")]
    network: String,

    /// Produce dev-stub blocks at the block target (dev network only).
    #[arg(long, default_value_t = true)]
    produce: bool,

    /// Stop after this many produced blocks (0 = run until Ctrl-C).
    #[arg(long, default_value_t = 0)]
    max_blocks: u64,

    /// Persist blocks to this directory and resume from it on boot
    /// (P5). Unset: fully in-memory, resets to genesis every restart.
    #[arg(long)]
    data_dir: Option<PathBuf>,
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
    // With --data-dir: replay the on-disk block log through the normal
    // validation path and resume from the persisted tip. Without it the
    // node stays fully in-memory (unchanged no-arg dev boot).
    let mut chain = match &args.data_dir {
        Some(dir) => aegis_node::load_chain(dir, network, PowMode::DevStub, ProofMode::DevStub)?,
        None => Chain::new(network, PowMode::DevStub, ProofMode::DevStub),
    };
    info!(
        network = params.network_name,
        genesis = hex::encode(aegis_node::genesis_header(network).id()),
        tip_height = chain.tip().height,
        tip = hex::encode(chain.tip().id()),
        resumed_from_disk = args.data_dir.is_some() && chain.tip().height > 0,
        target_secs = params.block_target_secs,
        "aegis-node booted"
    );

    if !(args.produce && network == Network::Dev) {
        info!("production disabled (non-dev network or --produce=false); idling until Ctrl-C");
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    let target = Duration::from_secs(params.block_target_secs);
    let mut produced = 0u64;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(target) => {}
            _ = tokio::signal::ctrl_c() => break,
        }
        let now = now_ms();
        // Mint a coinbase note each block (fixed dev reward tag; blinding
        // varied by height so the notes are distinct leaves). Spending a
        // coinbase note is blocked until the nullifier fix (N1) — this
        // enables minting/the first in-band notes only.
        let next_height = chain.tip().height + 1;
        let block = chain
            .produce_next_with_coinbase(
                BlockBody::default(),
                now,
                EvenScalar::from(0xC0FFEEu64),
                EvenScalar::from(next_height),
            )
            .expect("coinbase block must produce");
        let id = block.header.id();
        let (height, nbits, ts) = (
            block.header.height,
            block.header.sc_nbits,
            block.header.timestamp_ms,
        );
        chain
            .try_extend(block.clone(), now)
            .expect("self-produced block must validate");
        // Persist only ACCEPTED blocks so the log replays by construction.
        if let Some(dir) = &args.data_dir {
            aegis_node::save_block(dir, &block)?;
        }
        info!(
            height,
            id = hex::encode(id),
            nbits = format_args!("{nbits:#010x}"),
            ts,
            leaves = chain.state().leaf_count(),
            "block produced"
        );
        produced += 1;
        if args.max_blocks != 0 && produced >= args.max_blocks {
            break;
        }
    }
    info!(tip = chain.tip().height, "shutting down");
    Ok(())
}
