//! `aegis-wallet` CLI.
//!
//! Slice 1: key generation + address derivation (offline). Slice 2 (this
//! change): the node-client plumbing — `scan` (sync the note-commitment
//! tree and the wallet's own notes from the node), `balance` (offline sum
//! of unspent self-notes), and `consolidate` (build + submit a
//! self-transfer that merges two notes). Sending to another party needs
//! note encryption (held), so every note here is self-owned.
//!
//! The wallet file is a small JSON journal (sk + the self-note list). It
//! is **not encrypted at rest yet** — an encrypted keystore is a held
//! slice (`wallet-design.md` §7); until then treat the file like a key.

use std::path::{Path, PathBuf};

use aegis_spec::Network;
use aegis_wallet::{
    consolidate, Address, Diversifier, NodeClient, SelfNote, SpendingKey, TrackedNote, WalletState,
    HRP_MAINNET, HRP_TESTNET,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aegis-wallet",
    about = "Standalone Aegis shielded wallet (slice 2: keys, addresses, scan, self-consolidation)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a fresh wallet file (spending key + empty journal) and
    /// print its first address.
    Init {
        /// Where to write the wallet file.
        #[arg(long, default_value = "wallet.json")]
        wallet: PathBuf,
        /// Network (dev|test|main) — sets the address HRP and default fee.
        #[arg(long, default_value = "test")]
        network: String,
    },
    /// Derive a fresh diversified address from a spending key (32-byte hex).
    Address {
        #[arg(long)]
        sk: String,
    },
    /// Register a self-owned note the wallet created off-chain (e.g. a
    /// coinbase you mined) so `scan` can track it. Value in base units.
    ImportNote {
        #[arg(long, default_value = "wallet.json")]
        wallet: PathBuf,
        #[arg(long)]
        value: u64,
    },
    /// Sync from the node: rebuild the note-commitment tree, resolve the
    /// wallet's notes, and record which are spent. Persists the result.
    Scan {
        #[arg(long, default_value = "wallet.json")]
        wallet: PathBuf,
        #[arg(long)]
        node: String,
    },
    /// Print the local, private balance (sum of confirmed unspent notes)
    /// from the last scan — offline.
    Balance {
        #[arg(long, default_value = "wallet.json")]
        wallet: PathBuf,
    },
    /// Consolidate the two largest self-notes into one change note (plus a
    /// zero reserve) and submit the self-transfer to the node.
    Consolidate {
        #[arg(long, default_value = "wallet.json")]
        wallet: PathBuf,
        #[arg(long)]
        node: String,
        /// Fee override in base units (default: the network `sc_tx_fee`).
        #[arg(long)]
        fee: Option<u64>,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Init { wallet, network } => cmd_init(&wallet, &network),
        Cmd::Address { sk } => cmd_address(&sk),
        Cmd::ImportNote { wallet, value } => cmd_import_note(&wallet, value),
        Cmd::Scan { wallet, node } => cmd_scan(&wallet, &node),
        Cmd::Balance { wallet } => cmd_balance(&wallet),
        Cmd::Consolidate { wallet, node, fee } => cmd_consolidate(&wallet, &node, fee),
    }
}

fn cmd_init(path: &Path, network: &str) -> Result<(), Box<dyn std::error::Error>> {
    let net = parse_network(network)?;
    let mut rng = rand::thread_rng();
    let sk = SpendingKey::random(&mut rng);
    let file = WalletFile::new(sk.clone(), net);
    file.save(path)?;
    let addr = Address::derive(&sk.incoming_viewing_key(), Diversifier::random(&mut rng));
    println!("wrote wallet: {}", path.display());
    println!("address:      {}", addr.encode(hrp_for(net)));
    println!("(the wallet file holds your spending key UNENCRYPTED — guard it like funds)");
    Ok(())
}

fn cmd_address(sk_hex: &str) -> Result<(), Box<dyn std::error::Error>> {
    let sk = SpendingKey::from_bytes(parse_sk(sk_hex)?);
    let mut rng = rand::thread_rng();
    let addr = Address::derive(&sk.incoming_viewing_key(), Diversifier::random(&mut rng));
    println!("{}", addr.encode(HRP_TESTNET));
    Ok(())
}

fn cmd_import_note(path: &Path, value: u64) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = WalletFile::load(path)?;
    let note = file.state.add_note(value);
    file.save(path)?;
    println!("tracked self-note #{} = {} base units", note.index, value);
    println!("run `scan` once it is mined into a block to make it spendable");
    Ok(())
}

fn cmd_scan(path: &Path, node: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = WalletFile::load(path)?;
    let client = NodeClient::new(node)?;
    let report = file.state.scan(&file.sk, &client)?;
    file.save(path)?;
    println!("scanned to height {}", report.target_height);
    println!("leaves:   {}", report.leaf_count);
    println!(
        "resolved: {} of {} notes",
        report.notes_resolved,
        file.state.notes().len()
    );
    println!("spent:    {}", report.notes_spent);
    println!("balance:  {} base units", report.balance);
    Ok(())
}

fn cmd_balance(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = WalletFile::load(path)?;
    println!("{} base units", file.state.balance());
    println!("(as of last scan, height {})", file.state.scanned_height());
    Ok(())
}

fn cmd_consolidate(
    path: &Path,
    node: &str,
    fee: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = WalletFile::load(path)?;
    let client = NodeClient::new(node)?;
    // Refresh first so leaf indices + spent status are current.
    file.state.scan(&file.sk, &client)?;
    let fee = fee.unwrap_or_else(|| file.network.params().sc_tx_fee);

    let mut rng = rand::thread_rng();
    let consolidation = consolidate(&file.sk, &file.state, fee, &mut rng)?;
    let outcome = client.submit(&consolidation.transfer)?;
    consolidation.commit(&mut file.state);
    file.save(path)?;

    println!(
        "submitted transfer {} ({})",
        hex::encode(outcome.id),
        outcome.admitted
    );
    println!(
        "change note #{} = {} base units, reserve #{} = 0",
        consolidation.outputs[0].index,
        consolidation.outputs[0].value,
        consolidation.outputs[1].index,
    );
    println!("nullifiers spent:");
    for nf in &consolidation.nullifiers {
        println!("  {}", hex::encode(nf));
    }
    println!("confirm with: aegis-wallet scan (once mined), or GET /aegis/v1/nullifier/<hex>");
    Ok(())
}

// ----- wallet file (JSON journal; unencrypted — a held slice) -----

/// The persisted wallet: spending key, network, and the self-note journal.
struct WalletFile {
    sk: SpendingKey,
    network: Network,
    state: WalletState,
}

impl WalletFile {
    fn new(sk: SpendingKey, network: Network) -> Self {
        WalletFile {
            sk,
            network,
            state: WalletState::new(),
        }
    }

    fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading wallet {}: {e}", path.display()))?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        let sk = SpendingKey::from_bytes(parse_sk(
            v["sk"].as_str().ok_or("wallet file missing `sk`")?,
        )?);
        let network = parse_network(v["network"].as_str().unwrap_or("test"))?;
        let next_index = v["next_index"].as_u64().unwrap_or(0);
        let scanned_height = v["scanned_height"].as_u64().unwrap_or(0);
        let notes = v["notes"]
            .as_array()
            .map(|arr| arr.iter().map(parse_note).collect::<Result<Vec<_>, _>>())
            .transpose()?
            .unwrap_or_default();
        Ok(WalletFile {
            sk,
            network,
            state: WalletState::from_parts(notes, next_index, scanned_height),
        })
    }

    fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let notes: Vec<serde_json::Value> = self
            .state
            .notes()
            .iter()
            .map(|t| {
                serde_json::json!({
                    "index": t.note.index,
                    "value": t.note.value,
                    "leaf_index": t.leaf_index,
                    "spent": t.spent,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "version": 1,
            "network": network_name(self.network),
            "sk": hex::encode(self.sk.to_bytes()),
            "next_index": self.state.next_index(),
            "scanned_height": self.state.scanned_height(),
            "notes": notes,
        });
        std::fs::write(path, serde_json::to_string_pretty(&doc)?)
            .map_err(|e| format!("writing wallet {}: {e}", path.display()).into())
    }
}

fn parse_note(v: &serde_json::Value) -> Result<TrackedNote, Box<dyn std::error::Error>> {
    let index = v["index"].as_u64().ok_or("note missing `index`")?;
    let value = v["value"].as_u64().ok_or("note missing `value`")?;
    let leaf_index = v["leaf_index"].as_u64().map(|n| n as usize);
    let spent = v["spent"].as_bool().unwrap_or(false);
    Ok(TrackedNote {
        note: SelfNote::new(index, value),
        leaf_index,
        spent,
    })
}

fn parse_sk(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(s.trim()).map_err(|_| "spending key is not hex")?;
    bytes
        .try_into()
        .map_err(|_| "spending key must be 32 bytes (64 hex chars)".into())
}

fn parse_network(s: &str) -> Result<Network, Box<dyn std::error::Error>> {
    match s {
        "dev" => Ok(Network::Dev),
        "test" => Ok(Network::Test),
        "main" => Ok(Network::Main),
        other => Err(format!("unknown network `{other}` (want dev|test|main)").into()),
    }
}

fn network_name(net: Network) -> &'static str {
    match net {
        Network::Dev => "dev",
        Network::Test => "test",
        Network::Main => "main",
    }
}

/// The wallet's own Bech32m address prefix per network (mainnet `use…`,
/// dev/test `tuse…`) — the slice-1 address scheme.
fn hrp_for(net: Network) -> &'static str {
    match net {
        Network::Main => HRP_MAINNET,
        Network::Dev | Network::Test => HRP_TESTNET,
    }
}
