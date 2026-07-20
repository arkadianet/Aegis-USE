//! `exec-epoch` — driver for the FULL aux-PoW epoch-validity guest (v7,
//! `AEGISPV1`) over a dumped artifact set (aegis-recursion `tests/dump_epoch.rs`).
//!
//!   exec-epoch image-id                         (print the pinned guest image id)
//!   exec-epoch execute --dir DIR                (RISC0 executor; cycle breakdown)
//!   exec-epoch prove   --dir DIR --out-dir OUT  (REAL succinct prove; write receipt)
//!   exec-epoch verify  --dir OUT               (re-verify a written receipt)
//!
//! `execute` is the M-E1 measurement (no proving; CPU-only). `prove` runs the
//! same statement through a REAL RISC0 succinct prove (no dev-mode) and writes
//! the exact receipt shape the devnet `verifyStark` consumes — bincode
//! `InnerReceipt` + the `AEGISPV1` journal + the image id — the artifacts the v6
//! PegVault predicate accepts. Built with `--features cuda` inside the
//! `~/apps/risc0-cuda` container, the prove runs on the GPU.
//!
//! The guest reads (env::read order): root_bytes, EpochWitnessWire,
//! Vec<ShareWitnessWire> (E2), AnchorWitnessWire (E4). It logs `CYCLES <phase>`
//! per phase; `execute` captures guest stdout and reprints those lines.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use aegis_engine::epoch::aux_wire::{AnchorWitnessWire, ShareWitnessWire};
use aegis_engine::epoch::wire::EpochWitnessWire;
use clap::{Parser, Subcommand};
use methods::{AEGIS_EPOCH_GUEST_ELF, AEGIS_EPOCH_GUEST_ID};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};

#[derive(Parser)]
#[command(
    name = "exec-epoch",
    about = "Aegis epoch-validity guest driver (v7 AEGISPV1)"
)]
struct Cli {
    /// RISC0 segment size log2. Proving-side knob only: changes segment count /
    /// VRAM / wall-clock, never the guest ELF, so the image id is unchanged.
    /// Set programmatically because `RISC0_SEGMENT_PO2` is INERT in risc0 3.0.5.
    #[arg(long, global = true, default_value_t = 21)]
    segment_po2: u32,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the epoch guest image id (pin this into the PegVault).
    ImageId,
    /// Run the guest through the RISC0 executor (no prove); print the in-guest
    /// cycle breakdown + totals.
    Execute {
        #[arg(long)]
        dir: PathBuf,
    },
    /// REAL succinct prove; write receipt_inner.bin / journal.bin / image_id.bin.
    Prove {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Re-verify a written receipt locally.
    Verify {
        #[arg(long)]
        dir: PathBuf,
    },
}

/// The image id as the 32 bytes the PegVault pins and `verifyStark` consumes
/// (LE per u32 word — the encoding the settlement host and ergo-sigma agree on).
fn image_id_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, w) in out.chunks_exact_mut(4).zip(AEGIS_EPOCH_GUEST_ID.iter()) {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn pc<T: for<'de> serde::Deserialize<'de>>(dir: &Path, name: &str) -> T {
    let bytes = std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    postcard::from_bytes(&bytes).unwrap_or_else(|e| panic!("decode {name}: {e}"))
}

/// Load the dumped artifact set and build the guest `ExecutorEnv` in env::read
/// order. Shared by `execute` and `prove`.
fn build_env(dir: &Path, segment_po2: u32, sink: Option<Sink>) -> ExecutorEnv<'static> {
    let root: Vec<u8> = std::fs::read(dir.join("root.bin")).expect("root.bin");
    let witness: EpochWitnessWire = pc(dir, "witness.pc");
    let shares: Vec<ShareWitnessWire> = pc(dir, "shares.pc");
    let anchor: AnchorWitnessWire = pc(dir, "anchor.pc");

    let mut b = ExecutorEnv::builder();
    b.segment_limit_po2(segment_po2);
    if let Some(s) = sink {
        b.stdout(s);
    }
    b.write(&root)
        .unwrap()
        .write(&witness)
        .unwrap()
        .write(&shares)
        .unwrap()
        .write(&anchor)
        .unwrap()
        .build()
        .unwrap()
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

fn describe(dir: &Path) {
    let witness: EpochWitnessWire = pc(dir, "witness.pc");
    let shares: Vec<ShareWitnessWire> = pc(dir, "shares.pc");
    let root: Vec<u8> = std::fs::read(dir.join("root.bin")).expect("root.bin");
    let n_blocks = witness.blocks.len();
    let n_withdrawals: usize = witness.blocks.iter().map(|b| b.pegouts.len()).sum();
    println!(
        "epoch: {n_blocks} blocks, {n_withdrawals} withdrawals, root {} bytes, {} shares",
        root.len(),
        shares.len(),
    );
}

fn execute(dir: &Path, segment_po2: u32) {
    describe(dir);
    let sink = Sink::default();
    let env = build_env(dir, segment_po2, Some(sink.clone()));
    let t0 = Instant::now();
    let session = default_executor()
        .execute(env, AEGIS_EPOCH_GUEST_ELF)
        .expect("guest execute");
    let wall = t0.elapsed();

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
}

fn prove(dir: &Path, out_dir: &Path, segment_po2: u32) {
    assert!(
        std::env::var("RISC0_DEV_MODE").map_or(true, |v| v.is_empty() || v == "0"),
        "dev-mode is banned: unset RISC0_DEV_MODE (real proofs only)"
    );
    describe(dir);
    std::fs::create_dir_all(out_dir).expect("out dir");
    println!("segment_po2={segment_po2} (programmatic; env var is inert in risc0 3.0.5)");

    let env = build_env(dir, segment_po2, None);
    let t0 = Instant::now();
    let prove_info = default_prover()
        .prove_with_opts(env, AEGIS_EPOCH_GUEST_ELF, &ProverOpts::succinct())
        .expect("epoch prove");
    let wall = t0.elapsed();
    let stats = &prove_info.stats;
    println!(
        "PROVED (execute+prove): wall={wall:?} user_cycles={} total_cycles={} segments={}",
        stats.user_cycles, stats.total_cycles, stats.segments
    );

    let receipt = prove_info.receipt;
    receipt
        .verify(AEGIS_EPOCH_GUEST_ID)
        .expect("local receipt verify (real succinct)");

    let inner_bytes = bincode::serialize(&receipt.inner).expect("inner");
    std::fs::write(out_dir.join("receipt_inner.bin"), &inner_bytes).unwrap();
    std::fs::write(out_dir.join("journal.bin"), &receipt.journal.bytes).unwrap();
    std::fs::write(out_dir.join("image_id.bin"), image_id_bytes()).unwrap();
    println!(
        "wrote {} (inner {} KiB, journal {} B, image {})",
        out_dir.display(),
        inner_bytes.len() / 1024,
        receipt.journal.bytes.len(),
        hex::encode(image_id_bytes()),
    );
    // The journal MUST start with the AEGISPV1 tag and carry the fixed 240-byte
    // prefix the PegVault reconstructs (tag 8 + 7*32 roots/ids + counter 8).
    let j = &receipt.journal.bytes;
    assert_eq!(&j[0..8], b"AEGISPV1", "journal tag");
    assert!(j.len() >= 240, "journal shorter than the fixed prefix");
    println!(
        "journal prefix OK (AEGISPV1, {}B); counter_next={}",
        j.len(),
        u64::from_be_bytes(j[232..240].try_into().unwrap()),
    );
}

fn verify(dir: &Path) {
    let inner_bytes = std::fs::read(dir.join("receipt_inner.bin")).expect("inner");
    let journal = std::fs::read(dir.join("journal.bin")).expect("journal");
    let inner: risc0_zkvm::InnerReceipt = bincode::deserialize(&inner_bytes).expect("decode inner");
    let receipt = risc0_zkvm::Receipt::new(inner, journal);
    receipt
        .verify(AEGIS_EPOCH_GUEST_ID)
        .expect("receipt verifies");
    println!("receipt OK for image id {}", hex::encode(image_id_bytes()));
}

fn main() {
    let cli = Cli::parse();
    let po2 = cli.segment_po2;
    match cli.cmd {
        Cmd::ImageId => println!("{}", hex::encode(image_id_bytes())),
        Cmd::Execute { dir } => execute(&dir, po2),
        Cmd::Prove { dir, out_dir } => prove(&dir, &out_dir, po2),
        Cmd::Verify { dir } => verify(&dir),
    }
}
