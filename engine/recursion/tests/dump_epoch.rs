//! M-E1 measurement dump (`epoch-validity-design.md` §4): build a REAL small
//! honest epoch — a few suffix reward blocks with a couple of burn-valid
//! withdrawals — aggregate every suffix spend via `layer1_epoch`, and dump the
//! full aux-PoW epoch-validity guest inputs (the SHA-final root, the
//! `EpochWitnessWire`, the per-block share wires for E2, and the anchor wire for
//! E4) for the RISC0 EXECUTE measurement (`settlement/exec-epoch`). The harness
//! natively confirms the statement holds (verify_epoch passes and the digest
//! binds) before dumping.
//!
//! Runs only when `AEGIS_EPOCH_DUMP_DIR` is set. Requires the `aux-pow` feature
//! (mines real shares + builds the anchor chain) + `parallel` + native ISA:
//!
//! `AEGIS_EPOCH_DUMP_DIR=/tmp/ev RUSTFLAGS="-Ctarget-cpu=native" \
//!    cargo test --release --features aux-pow,parallel --test dump_epoch \
//!    -- --ignored --nocapture`

#![cfg(feature = "aux-pow")]

use aegis_engine::burn::{burn_cm_expected, burn_nonces, burn_owner};
use aegis_engine::commit::{note_commitment, owner_key};
use aegis_engine::config::recursion::make_recursion_hiding_config;
use aegis_engine::epoch::aux_wire::{AnchorWitnessWire, ShareWitnessWire};
use aegis_engine::epoch::digest::epoch_spend_root;
use aegis_engine::epoch::header_id::{block_id, header_id};
use aegis_engine::epoch::testgen::{build_anchor_chain, diff1_nbits, mine_diff1_share};
use aegis_engine::epoch::types::{
    coinbase_amount, peg_fee, PegOut, SpendPublics, SuffixBlock, FLAT_FEE, PEGOUT_DELAY,
};
use aegis_engine::epoch::verify::{verify_epoch, EpochError, EpochWitness};
use aegis_engine::epoch::wire::EpochWitnessWire;
use aegis_engine::merkle::{Frontier, NoteTree};
use aegis_engine::mint::coinbase_cm_expected;
use aegis_engine::nullifier::nullifier;
use aegis_engine::poseidon::{Digest, F};
use aegis_engine::settled::{empty_settled_root, SettledSet, SETTLED_DEPTH};
use aegis_engine::spend::batch::{SpendBatchProof, SpendCommonData};
use aegis_engine::spend::monolith::{
    build_spend_trace, InputNote, OutputNote, PUB_CMO0, PUB_CMO1, PUB_NF0, PUB_NF1, PUB_ROOT,
};
use aegis_recursion::digest_agg::{
    aggregate_settlement_sha, layer1_epoch, serialize_root_sha, verify_root_bytes_sha,
};
use aegis_recursion::{AggParams, SpendProofInput};
use p3_field::PrimeCharacteristicRing;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::Path;

const CHAIN_ID: u32 = 0x484E_0005;
const START_HEIGHT: u64 = 100;

fn digest_arr(base: u32) -> Digest {
    core::array::from_fn(|i| F::from_u32(base + i as u32))
}

fn digest_at(pis: &[F], off: usize) -> Digest {
    core::array::from_fn(|i| pis[off + i])
}

fn write_pc<T: serde::Serialize>(dir: &Path, name: &str, v: &T) {
    std::fs::write(dir.join(name), postcard::to_allocvec(v).expect("postcard")).expect("write");
}

/// A real burn-valid peg-out spend whose input notes live in `tree` (the shared
/// pre-epoch tree), so its `PUB_ROOT` is the chain anchor root.
struct BuiltSpend {
    proof: SpendBatchProof,
    common: SpendCommonData,
    pis: Vec<F>,
    amount: u64,
    recipient: Vec<u8>,
}

/// Prepare a spend's two input notes (append their commitments to `tree`) and
/// return the indexed input notes + the withdrawal amount.
fn prepare_inputs(tree: &mut NoteTree, s: u32, amount: u64) -> (InputNote, InputNote, u64) {
    let o = s * 1000;
    let in0 = InputNote {
        value: 1_000_000,
        nk: digest_arr(1 + o),
        rho: digest_arr(50 + o),
        r: digest_arr(90 + o),
        index: 0,
    };
    let in1 = InputNote {
        value: 500,
        nk: digest_arr(200 + o),
        rho: digest_arr(250 + o),
        r: digest_arr(290 + o),
        index: 0,
    };
    let cm0 = note_commitment(in0.value, &owner_key(&in0.nk), &in0.rho, &in0.r);
    let cm1 = note_commitment(in1.value, &owner_key(&in1.nk), &in1.rho, &in1.r);
    let i0 = tree.append(cm0);
    let i1 = tree.append(cm1);
    (
        InputNote { index: i0, ..in0 },
        InputNote { index: i1, ..in1 },
        amount,
    )
}

/// Prove one burn-valid spend against the FINAL shared `tree` (all inputs
/// present → `PUB_ROOT == tree.root()`).
fn prove_burn(tree: &NoteTree, s: u32, in0: InputNote, in1: InputNote, amount: u64) -> BuiltSpend {
    let o = s * 1000;
    let nf0 = nullifier(&in0.nk, &in0.rho);
    let pf = peg_fee(amount);
    let burn_value = amount + pf;
    // D1: the burn nonces bind the withdrawal's (recipient_prop, amount); this
    // suffix peg-out's recipient must match the one the block records below.
    let recipient = vec![0xA0 + s as u8; 33];
    let (brho, br) = burn_nonces(&nf0, &recipient, amount);
    let out0 = OutputNote {
        value: burn_value,
        owner: burn_owner(),
        rho: brho,
        r: br,
    };
    let out1 = OutputNote {
        value: in0.value + in1.value - burn_value - FLAT_FEE,
        owner: digest_arr(600 + o),
        rho: digest_arr(650 + o),
        r: digest_arr(690 + o),
    };
    let (trace, pis) = build_spend_trace(&[in0, in1], tree, &[out0, out1], FLAT_FEE);
    // Sanity: out0 IS the burn note the guest recomputes.
    let cm0 = digest_at(&pis, PUB_CMO0);
    assert_eq!(
        cm0,
        burn_cm_expected(burn_value, &nf0, &recipient, amount),
        "out0 is the burn note"
    );
    let config = make_recursion_hiding_config(
        ChaCha20Rng::seed_from_u64(100 + s as u64),
        ChaCha20Rng::seed_from_u64(200 + s as u64),
    );
    let (proof, common) = aegis_engine::spend::batch::prove_spend_batch(&config, &trace, &pis);
    BuiltSpend {
        proof,
        common,
        pis,
        amount,
        recipient,
    }
}

fn spend_publics(b: &BuiltSpend) -> SpendPublics {
    SpendPublics {
        root: digest_at(&b.pis, PUB_ROOT),
        nf0: digest_at(&b.pis, PUB_NF0),
        nf1: digest_at(&b.pis, PUB_NF1),
        cm0: digest_at(&b.pis, PUB_CMO0),
        cm1: digest_at(&b.pis, PUB_CMO1),
        fee: FLAT_FEE,
    }
}

/// The honest epoch artifact set: the SHA-final aggregation root (real proofs),
/// the guest witness, per-block shares (E2), the anchor (E4), and the honest
/// spend set (for the fabrication test's decoy comparison).
struct HonestEpoch {
    root_bytes: Vec<u8>,
    witness: EpochWitness,
    share_wires: Vec<ShareWitnessWire>,
    anchor_wire: AnchorWitnessWire,
    honest_spends: Vec<SpendPublics>,
    n_withdrawals: usize,
}

/// Build the honest 11-block / 2-withdrawal epoch (the M-E1 statement). Shared by
/// the honest dump and the fabrication dump (which reuses this exact — fully
/// consensus-consistent — suffix, swapping only the aggregation root).
fn build_honest(params: &AggParams) -> HonestEpoch {
    let miner_owner = digest_arr(7);
    let pot_before = 1_000_000u64;
    let shielded_before = 1_000_000_000u64;

    // ---- block 0: two real burn-valid withdrawals against a shared anchor ----
    let mut tree = NoteTree::new();
    let prep: Vec<_> = [(1u32, 5000u64), (2u32, 8000u64)]
        .into_iter()
        .map(|(s, amt)| (s, prepare_inputs(&mut tree, s, amt)))
        .collect();
    let anchor_root = tree.root();
    let pre_frontier = {
        // The frontier over the SAME leaf sequence — its root equals tree.root().
        let mut f = Frontier::new();
        // Re-derive the input commitments in append order.
        for (s, (in0, in1, _)) in &prep {
            let o = s * 1000;
            let _ = f.append(note_commitment(
                in0.value,
                &owner_key(&in0.nk),
                &in0.rho,
                &in0.r,
            ));
            let _ = f.append(note_commitment(
                in1.value,
                &owner_key(&in1.nk),
                &in1.rho,
                &in1.r,
            ));
            let _ = o;
        }
        f
    };
    assert_eq!(
        pre_frontier.root(),
        anchor_root,
        "frontier root == tree root"
    );

    let built: Vec<BuiltSpend> = prep
        .into_iter()
        .map(|(s, (in0, in1, amt))| prove_burn(&tree, s, in0, in1, amt))
        .collect();
    let spends: Vec<SpendPublics> = built.iter().map(spend_publics).collect();

    // ---- aggregate every suffix spend via layer1_epoch → SHA-final root ----
    let leaves: Vec<_> = built
        .iter()
        .map(|b| {
            layer1_epoch(
                params,
                &SpendProofInput {
                    proof: &b.proof,
                    common: &b.common,
                    pis: &b.pis,
                },
                FLAT_FEE,
            )
        })
        .collect();
    let (root, _levels) = aggregate_settlement_sha(params, leaves);
    let root_bytes = serialize_root_sha(&root);
    // The bind: aggregated root digest == epoch_spend_root over the same spends.
    assert_eq!(
        verify_root_bytes_sha(params, &root_bytes)
            .expect("root verifies")
            .as_slice(),
        epoch_spend_root(&spends).as_slice(),
        "layer1_epoch root must equal epoch_spend_root (the guest's bind)"
    );

    // ---- build the suffix: block 0 (2 pegouts) + PEGOUT_DELAY empty blocks ----
    let mut blocks: Vec<SuffixBlock> = Vec::new();
    let mut running = pre_frontier.clone();
    let mut pot = pot_before;
    let mut prev_header_id = [0u8; 32];
    let mut height = START_HEIGHT;

    // block 0
    {
        let prev_root = running.root();
        let pegouts: Vec<PegOut> = built
            .iter()
            .map(|b| PegOut {
                spend: spend_publics(b),
                amount: b.amount,
                recipient_prop: b.recipient.clone(),
            })
            .collect();
        let n_spends = pegouts.len();
        let fees = FLAT_FEE * n_spends as u64;
        let pegout_fees: u64 = pegouts.iter().map(|p| peg_fee(p.amount)).sum();
        let cb = coinbase_amount(pot, n_spends);
        let bid = block_id(height, &prev_root);
        let coinbase_cm = coinbase_cm_expected(&miner_owner, cb, &bid);
        for p in &pegouts {
            let _ = running.append(p.spend.cm0);
            let _ = running.append(p.spend.cm1);
        }
        let _ = running.append(coinbase_cm);
        let state_root = running.root();
        let pot_after = pot + fees + pegout_fees - cb;
        let block = SuffixBlock {
            height,
            prev_header_id,
            prev_root,
            state_root,
            timestamp_ms: 1_760_000_000_000 + height * 15_000,
            sc_nbits: diff1_nbits(),
            txs: vec![],
            pegouts,
            pegins: vec![],
            miner_owner,
            coinbase_amount: cb,
            coinbase_cm,
            coinbase_is_reward: true,
            pot_after,
        };
        prev_header_id = header_id(CHAIN_ID, &block);
        blocks.push(block);
        pot = pot_after;
        height += 1;
    }

    // PEGOUT_DELAY empty maturing blocks
    for _ in 0..PEGOUT_DELAY {
        let prev_root = running.root();
        let cb = coinbase_amount(pot, 0);
        let bid = block_id(height, &prev_root);
        let coinbase_cm = coinbase_cm_expected(&miner_owner, cb, &bid);
        let _ = running.append(coinbase_cm);
        let state_root = running.root();
        let pot_after = pot - cb;
        let block = SuffixBlock {
            height,
            prev_header_id,
            prev_root,
            state_root,
            timestamp_ms: 1_760_000_000_000 + height * 15_000,
            sc_nbits: diff1_nbits(),
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner,
            coinbase_amount: cb,
            coinbase_cm,
            coinbase_is_reward: true,
            pot_after,
        };
        prev_header_id = header_id(CHAIN_ID, &block);
        blocks.push(block);
        pot = pot_after;
        height += 1;
    }

    // ---- E4: anchor chain committing the tip header id ----
    let tip_id = header_id(CHAIN_ID, blocks.last().unwrap());
    let (anchor, ergo_ref_id) = build_anchor_chain(tip_id, 3);

    // ---- honest settled-set paths (E3) ----
    let mut set = SettledSet::new();
    let mut settled_paths: Vec<[Digest; SETTLED_DEPTH]> = Vec::new();
    for b in &blocks {
        for po in &b.pegouts {
            settled_paths.push(set.witness(&po.spend.nf0));
            set.insert(&po.spend.nf0);
        }
    }

    // ---- assemble the witness + native verify ----
    let witness = EpochWitness {
        chain_id: CHAIN_ID,
        blocks: blocks.clone(),
        frontier_bytes: postcard::to_allocvec(&pre_frontier).unwrap(),
        tip_id_prev: [0u8; 32],
        pot_before,
        shielded_before,
        seam_roots: vec![],
        settled_root_in: empty_settled_root(),
        settled_paths,
        spend_root_digest: epoch_spend_root(&spends),
        ergo_ref_id,
        counter_next: built.len() as u64,
    };
    let result = verify_epoch(&witness).expect("the honest epoch must verify natively");
    assert_eq!(result.new_root, blocks.last().unwrap().state_root);
    assert_eq!(result.withdrawals.len(), built.len());

    // ---- mine one aux-PoW share per block (E2) ----
    let share_wires: Vec<ShareWitnessWire> = blocks
        .iter()
        .map(|b| ShareWitnessWire::from_witness(&mine_diff1_share(CHAIN_ID, b)))
        .collect();
    let anchor_wire = AnchorWitnessWire::from_witness(&anchor);

    HonestEpoch {
        root_bytes,
        witness,
        share_wires,
        anchor_wire,
        honest_spends: spends,
        n_withdrawals: built.len(),
    }
}

/// Build a REAL SHA-final aggregation root over a DIFFERENT valid spend set — the
/// "decoy" a settler could genuinely prove (they hold real proofs), which does
/// NOT match the withdrawals recorded in the honest suffix. Returns the root
/// bytes + its surfaced spend digest.
fn build_decoy_root(params: &AggParams) -> (Vec<u8>, Digest) {
    let mut tree = NoteTree::new();
    let prep: Vec<_> = [(3u32, 5001u64), (4u32, 8001u64)]
        .into_iter()
        .map(|(s, amt)| (s, prepare_inputs(&mut tree, s, amt)))
        .collect();
    let built: Vec<BuiltSpend> = prep
        .into_iter()
        .map(|(s, (in0, in1, amt))| prove_burn(&tree, s, in0, in1, amt))
        .collect();
    let spends: Vec<SpendPublics> = built.iter().map(spend_publics).collect();
    let leaves: Vec<_> = built
        .iter()
        .map(|b| {
            layer1_epoch(
                params,
                &SpendProofInput {
                    proof: &b.proof,
                    common: &b.common,
                    pis: &b.pis,
                },
                FLAT_FEE,
            )
        })
        .collect();
    let (root, _) = aggregate_settlement_sha(params, leaves);
    let root_bytes = serialize_root_sha(&root);
    let limbs = verify_root_bytes_sha(params, &root_bytes).expect("decoy root verifies");
    let digest: Digest = core::array::from_fn(|i| limbs[i]);
    assert_eq!(
        digest.as_slice(),
        epoch_spend_root(&spends).as_slice(),
        "decoy root digest == its own spend set"
    );
    (root_bytes, digest)
}

#[test]
#[ignore = "M-E1 dump; run explicitly with AEGIS_EPOCH_DUMP_DIR set"]
fn dump() {
    let Ok(dir) = std::env::var("AEGIS_EPOCH_DUMP_DIR") else {
        eprintln!("AEGIS_EPOCH_DUMP_DIR unset — skipping");
        return;
    };
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let e = build_honest(&AggParams::default());
    let witness_wire = EpochWitnessWire::from_witness(&e.witness);

    // ---- dump guest inputs (env::read order) ----
    std::fs::write(dir.join("root.bin"), &e.root_bytes).unwrap();
    write_pc(dir, "witness.pc", &witness_wire);
    write_pc(dir, "shares.pc", &e.share_wires);
    write_pc(dir, "anchor.pc", &e.anchor_wire);

    println!(
        "[EPOCH-DUMP] {} blocks ({} withdrawals), root {} bytes, {} shares -> {}",
        e.witness.blocks.len(),
        e.n_withdrawals,
        e.root_bytes.len(),
        e.share_wires.len(),
        dir.display()
    );
}

#[test]
#[ignore = "fabrication dump; run explicitly with AEGIS_EPOCH_FAB_DUMP_DIR set"]
fn dump_fabricated() {
    // The fabrication vector, for real: the settler presents a REAL aggregation
    // root — but for a spend set they could actually prove — while the suffix
    // records the withdrawals they WANT (which they cannot prove). Everything in
    // the suffix is consensus-consistent; the ONE thing they cannot forge is a
    // root whose surfaced digest equals the re-derived suffix digest. The guest
    // overwrites `witness.spend_root_digest` with the verified root's digest and
    // then requires the re-derived suffix digest to match — so it dies at the
    // digest bind BEFORE producing any receipt. Dumping the honest (consistent)
    // suffix with a decoy root is the faithful, guest-executable form of this.
    let Ok(dir) = std::env::var("AEGIS_EPOCH_FAB_DUMP_DIR") else {
        eprintln!("AEGIS_EPOCH_FAB_DUMP_DIR unset — skipping");
        return;
    };
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let params = AggParams::default();
    let mut e = build_honest(&params);
    // Dump the honest witness UNCHANGED (the guest overwrites its digest field
    // from the root anyway).
    let witness_wire = EpochWitnessWire::from_witness(&e.witness);

    let (decoy_bytes, decoy_digest) = build_decoy_root(&params);
    let honest_digest = epoch_spend_root(&e.honest_spends);
    assert_ne!(
        decoy_digest, honest_digest,
        "decoy spend set must differ from the honest suffix"
    );
    // The exact fact the guest enforces: bind the decoy digest, the honest suffix
    // re-derivation no longer matches => SpendDigestMismatch (no receipt possible).
    e.witness.spend_root_digest = decoy_digest;
    assert_eq!(
        verify_epoch(&e.witness),
        Err(EpochError::SpendDigestMismatch),
        "a fabricated (mismatched-root) epoch must die at the digest bind"
    );

    // ---- dump the guest inputs: decoy root + honest suffix/shares/anchor ----
    std::fs::write(dir.join("root.bin"), &decoy_bytes).unwrap();
    write_pc(dir, "witness.pc", &witness_wire);
    write_pc(dir, "shares.pc", &e.share_wires);
    write_pc(dir, "anchor.pc", &e.anchor_wire);

    println!(
        "[EPOCH-FAB-DUMP] decoy root {} bytes; the guest MUST die SpendDigestMismatch (no proof) -> {}",
        decoy_bytes.len(),
        dir.display()
    );
}
