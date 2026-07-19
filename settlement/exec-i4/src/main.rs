//! `exec-i4 --dir DIR` — run the batch settlement guest (I4) through the RISC0
//! executor over a dumped artifact set (aegis-recursion
//! `tests/dump_artifacts.rs`) and print the in-guest cycle breakdown + totals.
//! No proving; CPU-only measurement (item 4).

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use methods::{AEGIS_SETTLEMENT_GUEST_ELF, AEGIS_SETTLEMENT_GUEST_ID};
use risc0_zkvm::{default_executor, ExecutorEnv};

#[derive(Parser)]
struct Cli {
    /// Directory holding root.bin + {amounts,recipients,nf0s,cm0s,epoch,counter}.pc
    /// + frontier.bin (from dump_artifacts.rs).
    #[arg(long)]
    dir: PathBuf,
    /// Segment size log2 (proving-side knob; here only affects segment count).
    #[arg(long, default_value_t = 21)]
    segment_po2: u32,
}

fn pc<T: for<'de> serde::Deserialize<'de>>(dir: &std::path::Path, name: &str) -> T {
    let bytes = std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    postcard::from_bytes(&bytes).unwrap_or_else(|e| panic!("decode {name}: {e}"))
}

fn main() {
    let cli = Cli::parse();
    let d = &cli.dir;

    let root: Vec<u8> = std::fs::read(d.join("root.bin")).expect("root.bin");
    let amounts: Vec<u64> = pc(d, "amounts.pc");
    let recipients: Vec<Vec<u8>> = pc(d, "recipients.pc");
    let nf0s: Vec<[u32; 8]> = pc(d, "nf0s.pc");
    let cm0s: Vec<[u32; 8]> = pc(d, "cm0s.pc");
    let frontier: Vec<u8> = std::fs::read(d.join("frontier.bin")).expect("frontier.bin");
    let epoch: Vec<[u32; 8]> = pc(d, "epoch.pc");
    let counter: u64 = pc(d, "counter.pc");

    let n = amounts.len();
    println!(
        "exec-i4: N={n} root {} bytes, image id {}",
        root.len(),
        hex::encode(id_bytes())
    );

    let env = ExecutorEnv::builder()
        .segment_limit_po2(cli.segment_po2)
        .write(&root)
        .unwrap()
        .write(&amounts)
        .unwrap()
        .write(&recipients)
        .unwrap()
        .write(&nf0s)
        .unwrap()
        .write(&cm0s)
        .unwrap()
        .write(&frontier)
        .unwrap()
        .write(&epoch)
        .unwrap()
        .write(&counter)
        .unwrap()
        .build()
        .unwrap();

    let t0 = Instant::now();
    let session = default_executor()
        .execute(env, AEGIS_SETTLEMENT_GUEST_ELF)
        .expect("guest execute");
    let wall = t0.elapsed();
    println!(
        "EXECUTE (no prove): N={n} wall={wall:?} total_user_cycles={} segments={} journal={}B",
        session.cycles(),
        session.segments.len(),
        session.journal.bytes.len(),
    );
}

fn id_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, w) in out
        .chunks_exact_mut(4)
        .zip(AEGIS_SETTLEMENT_GUEST_ID.iter())
    {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    out
}
