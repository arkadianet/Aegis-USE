//! `settle` — the settlement prover host.
//!
//!   settle image-id
//!   settle smoke   --out-dir DIR
//!   settle execute            (measurement: cycle breakdown, no prove)
//!   settle prove   --node URL --prev-root HEX32 --prev-height N
//!                  --withdrawal-index I --counter-next N
//!                  --recipient-tree HEX --out-dir DIR
//!   settle verify  --dir DIR
//!
//! `prove` gathers the epoch from a LIVE hn node (blocks + recorded
//! withdrawals over HTTP), rebuilds the consensus leaf sequence exactly as
//! `HnState::apply_block` does, splits it at the vault's last settled height
//! (verified host-side against `prev_root`), and proves Statement 1 with REAL
//! RISC0 (no dev-mode; succinct receipt — the shape the devnet's `verifyStark`
//! consumes: bincode `InnerReceipt` + journal + image id).

use std::path::PathBuf;
use std::time::Instant;

use aegis_engine::poseidon::{digest_to_bytes, Digest, DIGEST_ELEMS};
use aegis_hn_wallet::chain::digest_at;
use aegis_hn_wallet::{ChainView, SpendCircuit, Tx, Wallet};
use aegis_node::hn::mint::{pegmint_cm_expected, pegmint_note};
use aegis_node::hn::state::{digest_to_limbs, limbs_to_digest, HnBlock, PegInClaim, PegOutTx};
use aegis_node::hn::{HnChain, HnChainParams, HttpChain, PegInCheck};
use clap::{Parser, Subcommand};
use methods::{AEGIS_SETTLEMENT_GUEST_ELF, AEGIS_SETTLEMENT_GUEST_ID};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};

#[derive(Parser)]
#[command(name = "settle", about = "Aegis hn settlement prover (Statement 1)")]
struct Cli {
    /// RISC0 segment size limit as log2 cycles. A PROVING-side knob only: it
    /// changes segment count / VRAM / wall-clock, never the guest ELF, so the
    /// image id is unchanged. Set programmatically because the
    /// `RISC0_SEGMENT_PO2` env var is INERT in risc0 3.0.5 (never read by the
    /// executor, so env-var-only runs silently used the default po2 20).
    #[arg(long, global = true, default_value_t = 21)]
    segment_po2: u32,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the guest image id (pin this into the PegVault).
    ImageId,
    /// In-process end-to-end smoke: build a tiny hn chain (two peg-in mints,
    /// then a peg-out burn), prove, verify locally. Writes the same receipt
    /// files as `prove`.
    Smoke {
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Measurement: run the self-contained smoke statement through
    /// the RISC0 *executor* (no proving) and print the guest cycle breakdown
    /// (vk_setup / spend_verify / tree_transition via env::log) plus the total
    /// user-cycle count. Fast (~minutes, CPU-only) — used to measure the
    /// SHA-256 FRI-MMCS swap's effect on `spend_verify` without a 60-min prove.
    Execute,
    /// Prove a recorded withdrawal from a LIVE hn node.
    Prove {
        #[arg(long, default_value = "http://127.0.0.1:8750")]
        node: String,
        /// The root the vault last settled to (its R4), hex 32 bytes.
        #[arg(long)]
        prev_root: String,
        /// The hn height the vault last settled through (inclusive); the
        /// epoch is every block above it. Verified against `--prev-root` by
        /// rebuilding the tree host-side.
        #[arg(long)]
        prev_height: u64,
        #[arg(long, default_value_t = 0)]
        withdrawal_index: usize,
        /// The vault's R5 counter + 1.
        #[arg(long)]
        counter_next: u64,
        /// The recipient's ErgoTree bytes, hex (cross-checked against the
        /// recorded withdrawal; journaled verbatim).
        #[arg(long)]
        recipient_tree: String,
        /// SEAL the epoch at this hn height (inclusive): the epoch is blocks in
        /// `(prev_height, sealed_tip]`, pinned at settle start so the proof is
        /// DETERMINISTIC and does not chase the advancing chain (the earlier
        /// tip-grabbing caused divergent new_roots). Must be `>=` the
        /// withdrawal's height. Omit to seal at the current tip (recorded).
        #[arg(long)]
        sealed_tip: Option<u64>,
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Re-verify a written receipt locally.
    Verify {
        #[arg(long)]
        dir: PathBuf,
    },
}

fn image_id_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, w) in out
        .chunks_exact_mut(4)
        .zip(AEGIS_SETTLEMENT_GUEST_ID.iter())
    {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// The consensus leaf sequence of one block (must mirror
/// `HnState::apply_block` exactly): tx outputs, peg-out outputs, peg-in
/// mints, coinbase.
fn leaves_of_block(block: &HnBlock, params: &HnChainParams) -> Vec<Digest> {
    use aegis_engine::spend::monolith::{PUB_CMO0, PUB_CMO1};
    let mut out = Vec::new();
    for tx in block.txs.iter().chain(block.pegouts.iter().map(|p| &p.tx)) {
        out.push(digest_at(&tx.public_values, PUB_CMO0));
        out.push(digest_at(&tx.public_values, PUB_CMO1));
    }
    for pi in &block.pegins {
        let minted = pi.amount - params.peg_fee(pi.amount);
        out.push(pegmint_cm_expected(
            &limbs_to_digest(&pi.dest_owner),
            minted,
            &pi.box_id,
        ));
    }
    out.push(limbs_to_digest(&block.coinbase_cm));
    out
}

/// Split the chain's full leaf sequence at the vault's settled boundary:
/// pre-epoch = every block at height <= `prev_height`, epoch = the rest.
/// The split is VERIFIED host-side: the pre-epoch tree must rebuild exactly
/// to `prev_root` (the guest re-proves the same fact in-field).
fn split_leaves(
    blocks: &[HnBlock],
    params: &HnChainParams,
    prev_height: u64,
    sealed_tip: u64,
    prev_root: &[u8; 32],
) -> (Vec<Digest>, Vec<Digest>) {
    let pre: Vec<Digest> = blocks
        .iter()
        .filter(|b| b.height <= prev_height)
        .flat_map(|b| leaves_of_block(b, params))
        .collect();
    // SEALED epoch: only blocks in (prev_height, sealed_tip]. Pinning the upper
    // bound makes the proof deterministic regardless of chain advancement.
    let epoch: Vec<Digest> = blocks
        .iter()
        .filter(|b| b.height > prev_height && b.height <= sealed_tip)
        .flat_map(|b| leaves_of_block(b, params))
        .collect();
    let mut tree = aegis_engine::merkle::NoteTree::new();
    for l in &pre {
        tree.append(*l);
    }
    assert_eq!(
        digest_to_bytes(&tree.root()),
        *prev_root,
        "pre-epoch tree (blocks 0..={prev_height}) does not rebuild to --prev-root"
    );
    (pre, epoch)
}

struct ProveInput {
    tx: Tx,
    /// The committed PRE-EPOCH frontier (postcard) — the compact append
    /// boundary, NOT the pre-epoch leaves. Built host-side via
    /// `Frontier::from_leaves(&pre)` (unconstrained O(pre)); the guest advances
    /// it over the epoch in O(epoch).
    frontier_bytes: Vec<u8>,
    epoch_leaves: Vec<[u32; DIGEST_ELEMS]>,
    amount: u64,
    recipient_prop: Vec<u8>,
    counter_next: u64,
}

/// Build the postcard-encoded pre-epoch frontier the guest consumes.
fn frontier_bytes(pre: &[Digest]) -> Vec<u8> {
    let frontier = aegis_engine::merkle::Frontier::from_leaves(pre);
    postcard::to_allocvec(&frontier).expect("frontier serializes")
}

/// Build the guest `ExecutorEnv` for a settlement input (shared by prove and
/// the measurement `execute` path). `segment_po2` is applied HERE, in code:
/// risc0 3.0.5 does not read `RISC0_SEGMENT_PO2` from the environment, so the
/// builder call is the only effective control of segment size.
fn build_env(input: &ProveInput, segment_po2: u32) -> ExecutorEnv<'static> {
    ExecutorEnv::builder()
        .segment_limit_po2(segment_po2)
        .write(&input.tx.proof_bytes)
        .unwrap()
        .write(&input.tx.public_values)
        .unwrap()
        .write(&input.frontier_bytes)
        .unwrap()
        .write(&input.epoch_leaves)
        .unwrap()
        .write(&input.amount)
        .unwrap()
        .write(&input.recipient_prop)
        .unwrap()
        .write(&input.counter_next)
        .unwrap()
        .build()
        .unwrap()
}

/// How many times a failed prove is attempted before giving up. The CUDA
/// prover has shown TRANSIENT single-run faults ("verify segment / proof
/// invalid") that a straight retry of the identical input clears, so one
/// failure is not treated as fatal.
const PROVE_ATTEMPTS: u32 = 3;

/// Run the prover with up to [`PROVE_ATTEMPTS`] attempts, rebuilding the
/// `ExecutorEnv` each time (it is consumed by a prove). Catches both `Err`
/// returns and prover panics — the observed CUDA fault PANICS rather than
/// returning an error — and logs every attempt.
fn prove_with_retry(input: &ProveInput, segment_po2: u32) -> risc0_zkvm::ProveInfo {
    for attempt in 1..=PROVE_ATTEMPTS {
        let t0 = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let env = build_env(input, segment_po2);
            default_prover().prove_with_opts(
                env,
                AEGIS_SETTLEMENT_GUEST_ELF,
                &ProverOpts::succinct(),
            )
        }));
        match result {
            Ok(Ok(info)) => {
                if attempt > 1 {
                    println!("prove attempt {attempt}/{PROVE_ATTEMPTS} succeeded (retry worked)");
                }
                return info;
            }
            Ok(Err(e)) => eprintln!(
                "prove attempt {attempt}/{PROVE_ATTEMPTS} FAILED after {:?}: {e:#}",
                t0.elapsed()
            ),
            Err(panic) => {
                let msg = panic
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| panic.downcast_ref::<&str>().copied())
                    .unwrap_or("<non-string panic>");
                eprintln!(
                    "prove attempt {attempt}/{PROVE_ATTEMPTS} PANICKED after {:?}: {msg}",
                    t0.elapsed()
                );
            }
        }
    }
    panic!("prove failed {PROVE_ATTEMPTS} times — giving up (see attempt logs above)");
}

fn prove_and_write(input: &ProveInput, out_dir: &PathBuf, segment_po2: u32) {
    assert!(
        std::env::var("RISC0_DEV_MODE").map_or(true, |v| v.is_empty() || v == "0"),
        "dev-mode is banned: unset RISC0_DEV_MODE"
    );
    std::fs::create_dir_all(out_dir).expect("out dir");

    println!("segment_po2={segment_po2} (programmatic; env var is inert in risc0 3.0.5)");
    let t0 = Instant::now();
    let prove_info = prove_with_retry(input, segment_po2);
    let wall = t0.elapsed();
    let stats = &prove_info.stats;
    println!(
        "proved (execute+prove): wall={wall:?} user_cycles={} total_cycles={} segments={}",
        stats.user_cycles, stats.total_cycles, stats.segments
    );

    let receipt = prove_info.receipt;
    receipt
        .verify(AEGIS_SETTLEMENT_GUEST_ID)
        .expect("local receipt verify");

    let inner_bytes = bincode::serialize(&receipt.inner).expect("inner");
    std::fs::write(out_dir.join("receipt_inner.bin"), &inner_bytes).unwrap();
    std::fs::write(out_dir.join("journal.bin"), &receipt.journal.bytes).unwrap();
    std::fs::write(out_dir.join("image_id.bin"), image_id_bytes()).unwrap();
    println!(
        "wrote {} (inner {} KiB, journal {} B)",
        out_dir.display(),
        inner_bytes.len() / 1024,
        receipt.journal.bytes.len()
    );
}

fn to_limbs(leaves: &[Digest]) -> Vec<[u32; DIGEST_ELEMS]> {
    leaves.iter().map(digest_to_limbs).collect()
}

/// The smoke's mock devnet-vault view: every claim is confirmed.
struct AlwaysConfirmed;
impl PegInCheck for AlwaysConfirmed {
    fn confirmed(&self, _claim: &PegInClaim) -> bool {
        true
    }
}

/// Measurement helper: build the self-contained smoke settlement
/// statement (a tiny hn chain: two peg-in mints then a peg-out burn) and
/// return the guest `ProveInput` plus the pre/post-epoch roots. Shared by
/// `smoke` (which proves it) and `execute` (which only measures cycles).
fn smoke_input() -> (ProveInput, Digest, Digest) {
    let dir = tempfile::tempdir().unwrap();
    let mut bob = Wallet::from_seed(b"settle-smoke-bob");
    let miner = Wallet::from_seed(b"settle-smoke-miner");
    let bob_addr = bob.address();
    let params = HnChainParams::testnet().with_genesis(vec![], 10_000);
    let flat = params.flat_fee;
    let mut chain = HnChain::create(dir.path(), SpendCircuit::new(), params.clone()).unwrap();
    chain.set_pegin_check(Box::new(AlwaysConfirmed));

    // Two confirmed vault deposits mint Bob two notes (the 2-in burn spend
    // needs both) — the pegmint leaf path is exercised.
    for (amount, box_id) in [(1_000u64, [0x11u8; 32]), (600, [0x22; 32])] {
        let minted = amount - params.peg_fee(amount);
        let mint = pegmint_note(&bob_addr, minted, &box_id);
        chain.queue_pegin(PegInClaim {
            box_id,
            dest_owner: digest_to_limbs(&bob_addr.owner),
            dest_enc_pk: bob_addr.enc_pk,
            amount,
            ciphertext: mint.ciphertext,
        });
    }
    chain.produce_block(&miner.address()).unwrap();
    bob.scan(&chain);

    // Epoch boundary: the vault "deploys" at the post-mint root.
    let prev_root = chain.current_root();
    let prev_height = chain.blocks_since(0).last().expect("mint block").height;

    let withdrawal = 990u64;
    let peg_fee = params.peg_fee(withdrawal);
    let recipient_prop = vec![0xAA; 36];
    let burn_tx = bob
        .burn_spend(&chain, chain.circuit(), withdrawal + peg_fee, flat)
        .expect("burn spend");
    chain
        .submit_pegout(PegOutTx {
            tx: burn_tx,
            amount: withdrawal,
            recipient_prop: recipient_prop.clone(),
        })
        .expect("pegout admitted");
    chain.produce_block(&miner.address()).unwrap();
    let new_root = chain.current_root();

    // The SAME split path as `prove` (seal at the tiny chain's tip).
    let blocks = chain.blocks_since(0);
    let sealed = blocks.iter().map(|b| b.height).max().unwrap_or(prev_height);
    let (pre, epoch) = split_leaves(
        &blocks,
        &params,
        prev_height,
        sealed,
        &digest_to_bytes(&prev_root),
    );
    let po = &blocks
        .iter()
        .find(|b| b.height > prev_height && !b.pegouts.is_empty())
        .expect("pegout block")
        .pegouts[0];

    let input = ProveInput {
        tx: po.tx.clone(),
        frontier_bytes: frontier_bytes(&pre),
        epoch_leaves: to_limbs(&epoch),
        amount: withdrawal,
        recipient_prop,
        counter_next: 1,
    };
    (input, prev_root, new_root)
}

fn main() {
    let cli = Cli::parse();
    let segment_po2 = cli.segment_po2;
    match cli.cmd {
        Cmd::ImageId => println!("{}", hex::encode(image_id_bytes())),
        Cmd::Verify { dir } => {
            // Local sanity: reconstruct a Receipt from inner + journal.
            let inner_bytes = std::fs::read(dir.join("receipt_inner.bin")).expect("inner");
            let journal = std::fs::read(dir.join("journal.bin")).expect("journal");
            let inner: risc0_zkvm::InnerReceipt =
                bincode::deserialize(&inner_bytes).expect("decode inner");
            let receipt = risc0_zkvm::Receipt::new(inner, journal);
            receipt
                .verify(AEGIS_SETTLEMENT_GUEST_ID)
                .expect("receipt verifies");
            println!("receipt OK for image id {}", hex::encode(image_id_bytes()));
        }
        Cmd::Execute => {
            // Measurement: build the self-contained smoke statement
            // and run it through the RISC0 executor (no proving). The guest's
            // env::log lines (CYCLES vk_setup / spend_verify / tree_transition)
            // print during execution; SessionInfo gives the total user cycles.
            let (input, _prev, _new) = smoke_input();
            let env = build_env(&input, segment_po2);
            let t0 = Instant::now();
            let session = default_executor()
                .execute(env, AEGIS_SETTLEMENT_GUEST_ELF)
                .expect("execute");
            let wall = t0.elapsed();
            println!(
                "EXECUTE (no prove): wall={wall:?} total_user_cycles={} segments={}",
                session.cycles(),
                session.segments.len()
            );
        }
        Cmd::Smoke { out_dir } => {
            let t0 = Instant::now();
            let (input, prev_root, new_root) = smoke_input();
            println!("smoke chain built in {:?}", t0.elapsed());
            prove_and_write(&input, &out_dir, segment_po2);

            // The journal must be exactly what the vault reconstructs.
            let journal = std::fs::read(out_dir.join("journal.bin")).unwrap();
            let mut expect = Vec::new();
            expect.extend_from_slice(b"AEGISPO3");
            expect.extend_from_slice(&digest_to_bytes(&prev_root));
            expect.extend_from_slice(&digest_to_bytes(&new_root));
            expect.extend_from_slice(&input.amount.to_be_bytes());
            expect.extend_from_slice(&input.counter_next.to_be_bytes());
            expect.extend_from_slice(&input.recipient_prop);
            assert_eq!(
                journal, expect,
                "journal byte-exact vs vault reconstruction"
            );
            println!("journal byte-exact OK: {}", hex::encode(&journal));
        }
        Cmd::Prove {
            node,
            prev_root,
            prev_height,
            withdrawal_index,
            counter_next,
            recipient_tree,
            sealed_tip,
            out_dir,
        } => {
            let params = HnChainParams::testnet();
            let net = HttpChain::new(&node);
            let blocks = net.fetch_blocks(0);
            assert!(!blocks.is_empty(), "node returned no blocks");
            let ws = net.withdrawals();
            let w = ws
                .get(withdrawal_index)
                .expect("withdrawal index out of range")
                .clone();
            println!(
                "withdrawal[{withdrawal_index}]: amount={} height={} recipient={}B",
                w.amount,
                w.hn_height,
                w.recipient_prop.len()
            );
            let recipient = hex::decode(&recipient_tree).expect("recipient-tree hex");
            assert_eq!(
                recipient, w.recipient_prop,
                "--recipient-tree does not match the recorded withdrawal"
            );
            assert!(
                w.hn_height > prev_height,
                "withdrawal landed at or below --prev-height (already settled?)"
            );

            // Locate the peg-out tx by its nf0 in the block at hn_height.
            use aegis_engine::spend::monolith::PUB_NF0;
            let block = blocks
                .iter()
                .find(|b| b.height == w.hn_height)
                .expect("withdrawal block");
            let po = block
                .pegouts
                .iter()
                .find(|p| digest_to_limbs(&digest_at(&p.tx.public_values, PUB_NF0)) == w.nf0)
                .expect("peg-out tx for withdrawal");

            // Rebuild the full leaf sequence; split at the settled boundary,
            // sealing the epoch's upper bound (deterministic; default = tip).
            let target: [u8; 32] = hex::decode(&prev_root)
                .expect("prev-root hex")
                .try_into()
                .expect("prev-root must be 32 bytes");
            let tip = blocks.iter().map(|b| b.height).max().unwrap_or(prev_height);
            let sealed = sealed_tip.unwrap_or(tip);
            assert!(
                sealed >= w.hn_height && sealed <= tip,
                "--sealed-tip {sealed} must be in [withdrawal height {}, tip {tip}]",
                w.hn_height
            );
            let (pre, epoch) = split_leaves(&blocks, &params, prev_height, sealed, &target);
            println!(
                "epoch: pre-leaves={} epoch-leaves={} sealed_tip={sealed} (deterministic)",
                pre.len(),
                epoch.len()
            );

            let input = ProveInput {
                tx: po.tx.clone(),
                frontier_bytes: frontier_bytes(&pre),
                epoch_leaves: to_limbs(&epoch),
                amount: w.amount,
                recipient_prop: recipient,
                counter_next,
            };
            prove_and_write(&input, &out_dir, segment_po2);
        }
    }
}
