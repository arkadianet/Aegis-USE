//! `aegis-wallet` CLI (M4 slice 1: keys + addresses).
//!
//! Only two commands so far — key generation and address derivation. Sending,
//! scanning, and note encryption arrive in later (freeze-held) slices. The
//! wallet never contacts a node yet.

use aegis_wallet::{Address, Diversifier, SpendingKey, HRP_TESTNET};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aegis-wallet",
    about = "Standalone Aegis shielded wallet (slice 1: keys + addresses)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a fresh spending key and print it with a new address.
    Init,
    /// Derive a fresh diversified address from a spending key (32-byte hex).
    Address {
        #[arg(long)]
        sk: String,
    },
}

fn main() {
    let mut rng = rand::thread_rng();
    match Cli::parse().cmd {
        Cmd::Init => {
            let sk = SpendingKey::random(&mut rng);
            let addr = Address::derive(&sk.incoming_viewing_key(), Diversifier::random(&mut rng));
            println!("spending_key (KEEP SECRET): {}", hex::encode(sk.to_bytes()));
            println!("address:                    {}", addr.encode(HRP_TESTNET));
        }
        Cmd::Address { sk } => {
            let bytes: [u8; 32] = match hex::decode(sk.trim()).ok().and_then(|b| b.try_into().ok())
            {
                Some(b) => b,
                None => {
                    eprintln!("--sk must be 32-byte (64 hex char) spending key");
                    std::process::exit(1);
                }
            };
            let sk = SpendingKey::from_bytes(bytes);
            let addr = Address::derive(&sk.incoming_viewing_key(), Diversifier::random(&mut rng));
            println!("{}", addr.encode(HRP_TESTNET));
        }
    }
}
