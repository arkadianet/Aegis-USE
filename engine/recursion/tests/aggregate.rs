//! Aggregate N REAL monolith spend proofs into ONE root proof, and confirm the
//! root verifies natively + is ~constant size in N (batch independence).
//!
//! Run with the mandated flags (I1 — else ~27x slower):
//!   RUSTFLAGS="-Ctarget-cpu=native" cargo test --release --features parallel -- --nocapture
//! (the crate's [profile.test] is opt-level 3, so plain `cargo test --nocapture`
//! is already optimized; the RUSTFLAGS matter most.)

use std::time::Instant;

use aegis_engine::commit::{note_commitment, owner_key};
use aegis_engine::config::recursion::make_recursion_hiding_config;
use aegis_engine::merkle::NoteTree;
use aegis_engine::poseidon::{Digest, F};
use aegis_engine::spend::batch::{
    prove_spend_batch, verify_spend_batch, SpendBatchProof, SpendCommonData,
};
use aegis_engine::spend::monolith::build_spend_trace;
use aegis_engine::spend::monolith::{InputNote, OutputNote};
use aegis_recursion::{aggregate_spends, proof_bytes, verify_root, AggParams, SpendProofInput};
use p3_field::PrimeCharacteristicRing;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn digest(base: u32) -> Digest {
    core::array::from_fn(|i| F::from_u32(base + i as u32))
}

/// A distinct valid 2-in/2-out spend keyed by `s` (distinct notes => distinct
/// proofs, so the aggregation optimizer cannot collapse the leaves).
fn distinct_spend(s: u32) -> (SpendBatchProof, SpendCommonData, Vec<F>) {
    let o = s * 1000;
    let in0 = InputNote {
        value: 1_000,
        nk: digest(1 + o),
        rho: digest(50 + o),
        r: digest(90 + o),
        index: 0,
    };
    let in1 = InputNote {
        value: 500,
        nk: digest(200 + o),
        rho: digest(250 + o),
        r: digest(290 + o),
        index: 0,
    };
    let mut tree = NoteTree::new();
    let cm0 = note_commitment(in0.value, &owner_key(&in0.nk), &in0.rho, &in0.r);
    let cm1 = note_commitment(in1.value, &owner_key(&in1.nk), &in1.rho, &in1.r);
    let i0 = tree.append(cm0);
    let i1 = tree.append(cm1);
    let in0 = InputNote { index: i0, ..in0 };
    let in1 = InputNote { index: i1, ..in1 };
    let out0 = OutputNote {
        value: 900,
        owner: digest(400 + o),
        rho: digest(450 + o),
        r: digest(490 + o),
    };
    let out1 = OutputNote {
        value: 590,
        owner: digest(600 + o),
        rho: digest(650 + o),
        r: digest(690 + o),
    };
    let (trace, pis) = build_spend_trace(&[in0, in1], &tree, &[out0, out1], 10);

    // A fresh client config per proof (fresh masks/salts): distinct hiding proofs.
    let config = make_recursion_hiding_config(
        ChaCha20Rng::seed_from_u64(100 + s as u64),
        ChaCha20Rng::seed_from_u64(200 + s as u64),
    );
    let (proof, common) = prove_spend_batch(&config, &trace, &pis);
    // Sanity: each client proof verifies natively before it enters the tree.
    verify_spend_batch(&config, &proof, &pis, &common).expect("client proof verifies");
    (proof, common, pis)
}

fn run_and_check(n: usize) -> (usize, u32, std::time::Duration) {
    let params = AggParams::default();
    let spends: Vec<_> = (0..n).map(|i| distinct_spend(i as u32)).collect();
    let inputs: Vec<SpendProofInput> = spends
        .iter()
        .map(|(p, c, pis)| SpendProofInput {
            proof: p,
            common: c,
            pis,
        })
        .collect();

    let t = Instant::now();
    let agg = aggregate_spends(&inputs, &params);
    let elapsed = t.elapsed();

    verify_root(&params, &agg).expect("aggregate root must verify natively");
    let bytes = proof_bytes(&agg);
    eprintln!(
        "[AGG N={n}] end-to-end {elapsed:?} | root {bytes} bytes | {} tree levels (padded to {})",
        agg.levels,
        n.next_power_of_two()
    );
    (bytes, agg.levels, elapsed)
}

// ----- happy path (the measured targets) -----

#[test]
fn aggregate_two_real_spend_proofs_root_verifies() {
    let (bytes, levels, _) = run_and_check(2);
    assert_eq!(levels, 1, "N=2 is a single aggregation level");
    assert!(bytes > 0);
}

#[test]
fn aggregate_four_real_spend_proofs_root_verifies() {
    let (bytes4, levels, _) = run_and_check(4);
    assert_eq!(levels, 2, "N=4 is a two-level tree");
    assert!(bytes4 > 0);
}

// ----- padding (N not a power of two) -----

#[test]
fn aggregate_three_real_spend_proofs_pads_and_verifies() {
    // N=3 pads to 4 (re-recursing a duplicate leaf); the root still verifies.
    let (_bytes, levels, _) = run_and_check(3);
    assert_eq!(levels, 2, "N=3 pads to a two-level tree");
}
