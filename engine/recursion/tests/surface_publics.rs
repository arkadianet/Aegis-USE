//! I4 CRUX PROBE — does the aggregate ROOT expose the per-withdrawal publics?
//!
//! The batch-settlement statement (batch-settlement-design.md §1) needs, per
//! aggregated withdrawal, the client spend proof's `(amount, recipient_prop,
//! nf0)` and — for the burn binding (guest-settlement main.rs:89-100) — its
//! `nf0`/`cm0`. In v5 the guest gets these by verifying each spend proof
//! IN-FIELD against externally-supplied `pis` (`verify_with_preprocessed(...,
//! pis, ...)`), which BINDS `pis` to the proof. Recursion replaces the N
//! in-field verifies with ONE root verify — so the root must surface those
//! publics in a form the guest can READ and the verifier CHECKS, else the
//! journal is unbound.
//!
//! This test aggregates two REAL distinct spends and inspects every PLAINTEXT
//! public surface the root batch-stark proof has — `non_primitives[*].
//! public_values`, the only per-instance values `verify_batch` observes
//! (batch_stark_prover.rs `verify`: primitive tables get EMPTY pvs, only
//! non-primitive `entry.public_values` are used; `verify_all_tables` takes NO
//! external publics at all). It asserts the leaf `nf0`/`cm0` octets do NOT
//! appear there. The finding drives the I4 STOP report: the library binds the
//! leaf publics inside layer-1's primitive `Public` table commitment (AIR
//! public-value count 0 → they never propagate up), so the root neither
//! exposes them nor lets the guest check them.
//!
//! Run: RUSTFLAGS="-Ctarget-cpu=native" cargo test --release --features parallel \
//!        --test surface_publics -- --nocapture

use aegis_engine::commit::{note_commitment, owner_key};
use aegis_engine::config::recursion::make_recursion_hiding_config;
use aegis_engine::merkle::NoteTree;
use aegis_engine::poseidon::{Digest, F};
use aegis_engine::spend::batch::{
    prove_spend_batch, verify_spend_batch, SpendBatchProof, SpendCommonData,
};
use aegis_engine::spend::monolith::{
    build_spend_trace, InputNote, OutputNote, N_PUB, PUB_CMO0, PUB_NF0,
};
use aegis_recursion::{aggregate_spends, proof_bytes, verify_root, AggParams, SpendProofInput};
use p3_field::PrimeCharacteristicRing;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn digest(base: u32) -> Digest {
    core::array::from_fn(|i| F::from_u32(base + i as u32))
}

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
    let config = make_recursion_hiding_config(
        ChaCha20Rng::seed_from_u64(100 + s as u64),
        ChaCha20Rng::seed_from_u64(200 + s as u64),
    );
    let (proof, common) = prove_spend_batch(&config, &trace, &pis);
    verify_spend_batch(&config, &proof, &pis, &common).expect("client proof verifies");
    (proof, common, pis)
}

/// Does the 8-element window `needle` (an nf0 or cm0 digest) occur as a
/// contiguous run anywhere in `hay`?
fn contains_window(hay: &[F], needle: &[F]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn root_does_not_expose_per_withdrawal_publics() {
    let params = AggParams::default();
    let spends: Vec<_> = (0..2).map(distinct_spend).collect();
    let inputs: Vec<SpendProofInput> = spends
        .iter()
        .map(|(p, c, pis)| SpendProofInput {
            proof: p,
            common: c,
            pis,
        })
        .collect();

    // The withdrawal-relevant publics the settlement journal + burn binding
    // need, per leaf: nf0 (PUB_NF0..+8) and cm0 (PUB_CMO0..+8).
    let leaf_publics: Vec<(Vec<F>, Vec<F>)> = spends
        .iter()
        .map(|(_, _, pis)| {
            assert_eq!(pis.len(), N_PUB);
            (
                pis[PUB_NF0..PUB_NF0 + 8].to_vec(),
                pis[PUB_CMO0..PUB_CMO0 + 8].to_vec(),
            )
        })
        .collect();

    let agg = aggregate_spends(&inputs, &params);
    verify_root(&params, &agg).expect("root verifies natively");

    // The ONLY plaintext, verifier-observed public surface of the root proof.
    let exposed: Vec<F> = agg
        .root
        .0
        .non_primitives
        .iter()
        .flat_map(|e| e.public_values.iter().copied())
        .collect();

    eprintln!(
        "[I4-PROBE] root {} bytes | {} non-primitive tables | {} total EXPOSED public values",
        proof_bytes(&agg),
        agg.root.0.non_primitives.len(),
        exposed.len(),
    );
    for (i, e) in agg.root.0.non_primitives.iter().enumerate() {
        eprintln!(
            "[I4-PROBE]   non_primitive[{i}] op={:?} public_values.len()={}",
            e.op_type,
            e.public_values.len()
        );
    }

    // If the publics were surfaced for the journal we would see >= 2*(8+8)=32
    // withdrawal field elements recoverable here. Assert instead that NONE of
    // the leaf nf0/cm0 octets are present — the root does not expose them.
    let mut found = 0usize;
    for (li, (nf0, cm0)) in leaf_publics.iter().enumerate() {
        if contains_window(&exposed, nf0) {
            eprintln!("[I4-PROBE]   leaf {li} nf0 FOUND in exposed publics");
            found += 1;
        }
        if contains_window(&exposed, cm0) {
            eprintln!("[I4-PROBE]   leaf {li} cm0 FOUND in exposed publics");
            found += 1;
        }
    }
    eprintln!(
        "[I4-PROBE] leaf nf0/cm0 octets recoverable from root exposed publics: {found} / {}",
        leaf_publics.len() * 2
    );

    assert_eq!(
        found, 0,
        "CRUX: expected the aggregate root to NOT surface any per-withdrawal \
         nf0/cm0 publics (they live in layer-1's primitive Public table, \
         air-public count 0, and never propagate); if this now fails the \
         library gained a surfacing path and the I4 STOP verdict must be \
         revisited"
    );
}
