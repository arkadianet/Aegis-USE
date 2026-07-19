//! `exec-epoch --dir DIR` — run the FULL aux-PoW epoch-validity guest through
//! the RISC0 executor over a dumped artifact set (aegis-recursion
//! `tests/dump_epoch.rs`) and print the in-guest cycle breakdown + totals. No
//! proving; CPU-only measurement. This is the M-E1 deliverable
//! (`epoch-validity-design.md` §4): the per-block E2 (in-guest aux-PoW
//! share-verify) cost + the per-epoch total vs the ~185 M v6 settlement baseline.
//!
//! The guest reads (in order): root_bytes, EpochWitnessWire, Vec<ShareWitnessWire>
//! (E2), AnchorWitnessWire (E4). It logs `CYCLES <phase>=<n>` per phase; this
//! harness captures the guest stdout and reprints those lines.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use aegis_engine::epoch::aux_wire::{AnchorWitnessWire, ShareWitnessWire};
use aegis_engine::epoch::wire::EpochWitnessWire;
use clap::Parser;
use methods::AEGIS_EPOCH_GUEST_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};

#[derive(Parser)]
struct Cli {
    /// Directory holding root.bin + witness.pc + shares.pc + anchor.pc
    /// (from dump_epoch.rs).
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

/// A thread-safe stdout sink so we can reprint the guest's `CYCLES ...` logs.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);
impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn main() {
    let cli = Cli::parse();
    let d = &cli.dir;

    let root: Vec<u8> = std::fs::read(d.join("root.bin")).expect("root.bin");
    let witness: EpochWitnessWire = pc(d, "witness.pc");
    let shares: Vec<ShareWitnessWire> = pc(d, "shares.pc");
    let anchor: AnchorWitnessWire = pc(d, "anchor.pc");

    let n_blocks = witness.blocks.len();
    let n_withdrawals: usize = witness.blocks.iter().map(|b| b.pegouts.len()).sum();
    println!(
        "exec-epoch: {n_blocks} blocks, {n_withdrawals} withdrawals, root {} bytes, {} shares",
        root.len(),
        shares.len(),
    );

    let sink = Sink::default();
    let env = ExecutorEnv::builder()
        .segment_limit_po2(cli.segment_po2)
        .stdout(sink.clone())
        .write(&root)
        .unwrap()
        .write(&witness)
        .unwrap()
        .write(&shares)
        .unwrap()
        .write(&anchor)
        .unwrap()
        .build()
        .unwrap();

    let t0 = Instant::now();
    let session = default_executor()
        .execute(env, AEGIS_EPOCH_GUEST_ELF)
        .expect("guest execute");
    let wall = t0.elapsed();

    // Reprint the guest's in-guest cycle breakdown.
    let logged = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    println!("---- in-guest cycle breakdown (env::log) ----");
    for line in logged.lines() {
        if line.contains("CYCLES") {
            println!("{line}");
        }
    }
    println!("---------------------------------------------");
    println!(
        "EXECUTE (no prove): wall={wall:?} total_user_cycles={} segments={} journal={}B",
        session.cycles(),
        session.segments.len(),
        session.journal.bytes.len(),
    );
    if n_blocks > 0 {
        println!(
            "per-block (total/{n_blocks}): {} cycles/block (all phases)",
            session.cycles() / n_blocks as u64
        );
    }
}
