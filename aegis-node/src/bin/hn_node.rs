//! `hn-node` — a hash-native testnet node: serves the wallet HTTP API, opt
//! ionally mines (merge-mined against the STARK devnet) and/or follows a peer
//! (P2P sync + tx gossip). A blocking std-thread loop (no async runtime).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_engine::address::{WalletKeys, HRP_TEST};
use aegis_hn_wallet::SpendCircuit;
use aegis_node::hn::auxpow::fetch_devnet_anchor;
use aegis_node::hn::params::faucet_address_string;
use aegis_node::hn::{HnApiServer, HnApiState, HnChain, HnChainParams, HttpChain, VaultWatch};
use clap::Parser;

#[derive(Parser)]
#[command(name = "hn-node", about = "Aegis hash-native testnet node")]
struct Args {
    /// Persist + resume the block log here.
    #[arg(long)]
    data_dir: PathBuf,
    /// HTTP API bind address (e.g. 127.0.0.1:8750).
    #[arg(long, default_value = "127.0.0.1:8750")]
    bind: String,
    /// Seed the miner/coinbase address derives from.
    #[arg(long, default_value = "hn-node-miner")]
    miner_seed: String,
    /// Apply the genesis allocation on a fresh chain (the bootstrap node).
    #[arg(long, default_value_t = false)]
    genesis: bool,
    /// Produce blocks (merge-mined against the devnet).
    #[arg(long, default_value_t = false)]
    produce: bool,
    /// Peer node URL to sync blocks + gossip mempool from (a follower).
    #[arg(long)]
    peer_url: Option<String>,
    /// STARK devnet REST base URL (merge-mining anchor source).
    #[arg(long, default_value = "http://127.0.0.1:19099")]
    devnet_url: String,
    /// Devnet API key.
    #[arg(long, default_value = "hello")]
    devnet_key: String,
    /// Loop tick (ms).
    #[arg(long, default_value_t = 2000)]
    tick_ms: u64,
    /// PegVault ErgoTree bytes (hex). With --use-token, enables the peg-in
    /// watcher: confirmed vault deposits are minted on the hn chain.
    #[arg(long)]
    vault_tree: Option<String>,
    /// The test-USE token id (hex, 32 bytes) deposits must carry.
    #[arg(long)]
    use_token: Option<String>,
    /// Devnet height the vault watcher starts scanning from.
    #[arg(long, default_value_t = 0)]
    pegin_start: u64,
}

fn main() {
    let args = Args::parse();
    let circuit = SpendCircuit::new();

    let params = HnChainParams::testnet();
    let log_exists = args.data_dir.join("hn_blocks.log").exists();
    let mut chain = if log_exists {
        HnChain::open(&args.data_dir, circuit, params.clone()).expect("open chain")
    } else if args.genesis {
        HnChain::create_genesis(&args.data_dir, circuit, params.clone())
            .expect("create genesis chain")
    } else {
        HnChain::create(&args.data_dir, circuit, params.clone()).expect("create chain")
    };

    // Peg-in watcher: only with BOTH the vault tree and the USE token id.
    let mut watch = match (&args.vault_tree, &args.use_token) {
        (Some(tree_hex), Some(token_hex)) => {
            let tree = hex::decode(tree_hex).expect("--vault-tree is hex");
            let token: [u8; 32] = hex::decode(token_hex)
                .expect("--use-token is hex")
                .try_into()
                .expect("--use-token is 32 bytes");
            let watch = VaultWatch::new(
                args.devnet_url.clone(),
                args.devnet_key.clone(),
                tree,
                token,
                params.pegin_confirmations,
                args.pegin_start,
                params.clone(),
            );
            chain.set_pegin_check(watch.checker());
            Some(watch)
        }
        (None, None) => None,
        _ => panic!("--vault-tree and --use-token must be set together"),
    };

    let miner = WalletKeys::from_seed(args.miner_seed.as_bytes()).address();
    let shared = Arc::new(Mutex::new(chain));
    let server = HnApiServer::spawn(
        &args.bind,
        HnApiState {
            chain: Arc::clone(&shared),
            miner,
        },
    )
    .expect("bind HTTP");

    eprintln!(
        "hn-node: serving {} (data {})",
        server.base_url(),
        args.data_dir.display()
    );
    eprintln!("hn-node: miner {}", miner.encode(HRP_TEST));
    if args.genesis {
        eprintln!("hn-node: genesis faucet {}", faucet_address_string());
    }
    if let Some(p) = &args.peer_url {
        eprintln!("hn-node: following peer {p}");
    }
    if args.produce {
        eprintln!(
            "hn-node: producing (merge-mined vs devnet {})",
            args.devnet_url
        );
    }

    if watch.is_some() {
        eprintln!(
            "hn-node: peg-in watcher on (vault tree {} bytes, from devnet height {})",
            args.vault_tree.as_deref().map(|t| t.len() / 2).unwrap_or(0),
            args.pegin_start
        );
    }

    let peer = args.peer_url.as_deref().map(HttpChain::new);
    let mut last_status = std::time::Instant::now();
    loop {
        // Peg-in: scan the devnet for vault deposits (network I/O — the chain
        // Mutex is NOT held here), then queue confirmed ones for production.
        // Each locked call is `let`-bound / statement-scoped so no guard
        // lives across I/O (see the produce-loop deadlock note below).
        if let Some(w) = watch.as_mut() {
            w.poll();
            if args.produce {
                for c in w.confirmed_claims() {
                    shared.lock().unwrap().queue_pegin(c);
                }
            }
        }
        // Follow: sync blocks + gossip mempool from the peer.
        if let Some(p) = &peer {
            let applied = shared.lock().unwrap().sync_from(p);
            shared.lock().unwrap().pull_mempool(p);
            if applied > 0 {
                eprintln!(
                    "hn-node: synced {applied} block(s); height {}",
                    shared.lock().unwrap().height()
                );
            }
        }
        // Produce: merge-mine against the current devnet header.
        if args.produce {
            match fetch_devnet_anchor(&args.devnet_url, &args.devnet_key) {
                Some(anchor) => {
                    let dh = anchor.devnet_height;
                    // Bind the produce result so the MutexGuard temporary is
                    // dropped at the `;` — an `if let ... {} else {}` on the
                    // lock expression would keep the guard alive through the
                    // `else` arm and self-deadlock the second `lock()` below.
                    let produced = shared
                        .lock()
                        .unwrap()
                        .produce_block_anchored(&miner, anchor);
                    match produced {
                        Err(e) => eprintln!("hn-node: produce error: {e}"),
                        Ok(()) => {
                            let (h, pot) = {
                                let c = shared.lock().unwrap();
                                (c.height(), c.pot())
                            };
                            if last_status.elapsed() > Duration::from_secs(10) {
                                eprintln!("hn-node: height {h} pot {pot} (devnet anchor {dh})");
                                last_status = std::time::Instant::now();
                            }
                        }
                    }
                }
                None => eprintln!("hn-node: devnet unreachable; skipping production this tick"),
            }
        }
        std::thread::sleep(Duration::from_millis(args.tick_ms));
    }
}
