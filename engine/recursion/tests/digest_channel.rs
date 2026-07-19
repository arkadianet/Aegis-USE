//! I4 option-A spike: does an in-circuit-folded digest, re-seeded onto the
//! non-primitive `public_values` channel at every aggregation layer, surface
//! at the ROOT bound to the leaves?
//!
//! Run (mandatory flags, isolated CARGO_TARGET_DIR):
//! `RUSTFLAGS="-Ctarget-cpu=native" cargo test --release --test digest_channel -- --nocapture`

use aegis_engine::commit::{note_commitment, owner_key};
use aegis_engine::config::recursion::make_recursion_hiding_config;
use aegis_engine::merkle::NoteTree;
use aegis_engine::poseidon::{Digest, F};
use aegis_engine::spend::batch::{prove_spend_batch, SpendBatchProof, SpendCommonData};
use aegis_engine::spend::monolith::{build_spend_trace, InputNote, OutputNote};
use aegis_recursion::digest::DIGEST_LIMBS;
use aegis_recursion::digest_agg::{
    agg_pair_digest, aggregate_tree_digest, digest_publics, layer1_digest, sponge_digest, toy_leaf,
    verify_root_digest,
};
use aegis_recursion::{AggParams, SpendProofInput};
use p3_field::PrimeCharacteristicRing;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn seeds(tag: u32) -> Vec<F> {
    (0..4).map(|i| F::from_u32(1000 * tag + i)).collect()
}

// ----- helpers (real spends, mirrors tests/aggregate.rs) -----

fn digest_arr(base: u32) -> Digest {
    core::array::from_fn(|i| F::from_u32(base + i as u32))
}

/// A distinct valid 2-in/2-out spend keyed by `s`.
fn distinct_spend(s: u32) -> (SpendBatchProof, SpendCommonData, Vec<F>) {
    let o = s * 1000;
    let in0 = InputNote {
        value: 1_000,
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
    let mut tree = NoteTree::new();
    let cm0 = note_commitment(in0.value, &owner_key(&in0.nk), &in0.rho, &in0.r);
    let cm1 = note_commitment(in1.value, &owner_key(&in1.nk), &in1.rho, &in1.r);
    let i0 = tree.append(cm0);
    let i1 = tree.append(cm1);
    let in0 = InputNote { index: i0, ..in0 };
    let in1 = InputNote { index: i1, ..in1 };
    let out0 = OutputNote {
        value: 900,
        owner: digest_arr(400 + o),
        rho: digest_arr(450 + o),
        r: digest_arr(490 + o),
    };
    let out1 = OutputNote {
        value: 590,
        owner: digest_arr(600 + o),
        rho: digest_arr(650 + o),
        r: digest_arr(690 + o),
    };
    let (trace, pis) = build_spend_trace(&[in0, in1], &tree, &[out0, out1], 10);
    let config = make_recursion_hiding_config(
        ChaCha20Rng::seed_from_u64(100 + s as u64),
        ChaCha20Rng::seed_from_u64(200 + s as u64),
    );
    let (proof, common) = prove_spend_batch(&config, &trace, &pis);
    (proof, common, pis)
}

// ----- happy path -----

/// 2 leaves -> 1 root (one aggregation level): the root's digest publics must
/// equal H(d_left ‖ d_right) recomputed natively from the leaf seeds alone.
#[test]
fn digest_survives_one_level_and_matches_native_fold() {
    let params = AggParams::default();
    let t0 = std::time::Instant::now();
    let a = toy_leaf(&params, &seeds(1));
    let b = toy_leaf(&params, &seeds(2));
    println!("[DIGEST-SPIKE] 2 toy leaves proved in {:?}", t0.elapsed());

    let d_a = digest_publics(&a.0);
    let d_b = digest_publics(&b.0);
    assert_eq!(d_a.len(), DIGEST_LIMBS);
    assert_eq!(d_a, sponge_digest(&seeds(1)), "leaf digest == H(seeds)");
    assert_eq!(d_b, sponge_digest(&seeds(2)));
    assert_ne!(d_a, d_b);

    let t1 = std::time::Instant::now();
    let root = agg_pair_digest(&params, 1, &a, &b);
    println!("[DIGEST-SPIKE] 1 aggregation level in {:?}", t1.elapsed());

    // Native fold oracle: H(limbs(d_a) ++ limbs(d_b)).
    let mut fold_in = d_a.clone();
    fold_in.extend(d_b.iter().copied());
    let expected = sponge_digest(&fold_in);

    let packing = root.0.table_packing.clone();
    let got = verify_root_digest(&params, &root, packing).expect("root verifies");
    println!("[DIGEST-SPIKE] root digest {:?}", got);
    assert_eq!(got, expected, "root digest == H(d_left ‖ d_right)");
}

/// 4 leaves -> 2 levels: the digest CHAINS (re-seeded each level) and the root
/// carries H(H(d1‖d2) ‖ H(d3‖d4)) — fully determined by the leaf seeds.
#[test]
fn digest_chains_across_two_levels_to_root() {
    let params = AggParams::default();
    let leaves: Vec<_> = (1..=4).map(|t| toy_leaf(&params, &seeds(t))).collect();
    let leaf_digests: Vec<Vec<F>> = leaves.iter().map(|l| digest_publics(&l.0)).collect();

    let t0 = std::time::Instant::now();
    let (root, packing, levels) = aggregate_tree_digest(&params, leaves);
    println!(
        "[DIGEST-SPIKE] 4->1 tree ({levels} levels) in {:?}",
        t0.elapsed()
    );
    assert_eq!(levels, 2);

    let fold = |x: &[F], y: &[F]| {
        let mut v = x.to_vec();
        v.extend_from_slice(y);
        sponge_digest(&v)
    };
    let expected = fold(
        &fold(&leaf_digests[0], &leaf_digests[1]),
        &fold(&leaf_digests[2], &leaf_digests[3]),
    );

    let got = verify_root_digest(&params, &root, packing).expect("root verifies");
    println!("[DIGEST-SPIKE] 2-level root digest {:?}", got);
    assert_eq!(got, expected, "root digest == H(H(d1‖d2) ‖ H(d3‖d4))");
}

/// PRODUCTION SHAPE: 2 REAL client spend proofs -> layer-1 (digest = H(the 44
/// verified client publics)) -> 1 aggregation level. The root digest equals
/// H(H(pis_a) ‖ H(pis_b)) recomputed natively from the client publics alone —
/// i.e. the root is cryptographically bound to the withdrawals' public inputs.
#[test]
fn real_spend_publics_fold_to_root_digest() {
    let params = AggParams::default();
    let (proof_a, common_a, pis_a) = distinct_spend(1);
    let (proof_b, common_b, pis_b) = distinct_spend(2);
    assert_eq!(pis_a.len(), 44, "client spend proof exposes 44 publics");

    let t0 = std::time::Instant::now();
    let a = layer1_digest(
        &params,
        &SpendProofInput {
            proof: &proof_a,
            common: &common_a,
            pis: &pis_a,
        },
    );
    let b = layer1_digest(
        &params,
        &SpendProofInput {
            proof: &proof_b,
            common: &common_b,
            pis: &pis_b,
        },
    );
    println!(
        "[DIGEST-SPIKE] 2 real layer-1(+digest) leaves in {:?}",
        t0.elapsed()
    );

    assert_eq!(
        digest_publics(&a.0),
        sponge_digest(&pis_a),
        "leaf digest == H(client pis)"
    );
    assert_eq!(digest_publics(&b.0), sponge_digest(&pis_b));

    let t1 = std::time::Instant::now();
    let root = agg_pair_digest(&params, 1, &a, &b);
    println!(
        "[DIGEST-SPIKE] real-spend aggregation level in {:?}",
        t1.elapsed()
    );

    let mut fold_in = sponge_digest(&pis_a);
    fold_in.extend(sponge_digest(&pis_b));
    let expected = sponge_digest(&fold_in);

    let packing = root.0.table_packing.clone();
    let got = verify_root_digest(&params, &root, packing).expect("root verifies");
    println!("[DIGEST-SPIKE] real-spend root digest {:?}", got);
    assert_eq!(got, expected, "root digest == H(H(pis_a) ‖ H(pis_b))");
}

// ----- error paths (the bind-checks) -----

/// Changing one leaf's seed changes the root digest (bound, not decorative).
#[test]
fn different_leaf_seed_changes_root_digest() {
    let params = AggParams::default();
    let a = toy_leaf(&params, &seeds(1));
    let b = toy_leaf(&params, &seeds(2));
    let b2 = toy_leaf(&params, &seeds(3));

    let r1 = agg_pair_digest(&params, 1, &a, &b);
    let r2 = agg_pair_digest(&params, 1, &a, &b2);
    assert_ne!(digest_publics(&r1.0), digest_publics(&r2.0));
}

/// Tampering the ROOT's exposed digest publics must fail native verification
/// (the AIR constrains publics == committed trace; verify_batch checks them).
#[test]
fn tampered_root_digest_publics_fail_verification() {
    let params = AggParams::default();
    let a = toy_leaf(&params, &seeds(1));
    let b = toy_leaf(&params, &seeds(2));
    let mut root = agg_pair_digest(&params, 1, &a, &b);

    let entry = root
        .0
        .non_primitives
        .iter_mut()
        .find(|e| e.op_type.as_str() == "aegis/digest")
        .expect("digest entry");
    entry.public_values[0] += F::ONE;

    let packing = root.0.table_packing.clone();
    let res = verify_root_digest(&params, &root, packing);
    assert!(
        res.is_err(),
        "tampered root digest must not verify: {res:?}"
    );
}

/// A leaf cannot lie about its digest: tampering a LEAF's exposed digest
/// publics must make the aggregation layer fail (the parent re-checks them
/// in-circuit against the leaf's committed digest table).
#[test]
fn tampered_leaf_digest_publics_break_aggregation() {
    let params = AggParams::default();
    let a = toy_leaf(&params, &seeds(1));
    let mut b = toy_leaf(&params, &seeds(2));

    let entry =
        b.0.non_primitives
            .iter_mut()
            .find(|e| e.op_type.as_str() == "aegis/digest")
            .expect("digest entry");
    entry.public_values[0] += F::ONE;

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let root = agg_pair_digest(&params, 1, &a, &b);
        let packing = root.0.table_packing.clone();
        verify_root_digest(&params, &root, packing)
    }));
    let bound = match result {
        Err(_) => true,     // prove-time panic (constraints unsatisfied)
        Ok(Err(_)) => true, // or the produced root fails verification
        Ok(Ok(_)) => false, // aggregated + verified a lying leaf: UNSOUND
    };
    assert!(bound, "a tampered leaf digest must not survive aggregation");
}
