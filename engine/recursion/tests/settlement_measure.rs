//! I4 end-to-end measurement (item 4): the full settlement pipeline —
//! N real spends → N settlement leaves → aggregation root (digest surfaced) →
//! serialize → `verify_root_bytes` (the guest's exact verify-from-bytes call) →
//! digest-check against `withdrawals_root`. Times the pipeline and reports the
//! root size for N=2 and N=4. The in-guest verify CYCLE cost is measured
//! separately in the RISC0 settlement guest (constant in N; §7 of
//! recursion-feasibility.md).
//!
//! `RUSTFLAGS="-Ctarget-cpu=native" cargo test --release --test settlement_measure -- --nocapture`

use aegis_engine::commit::{note_commitment, owner_key};
use aegis_engine::config::recursion::make_recursion_hiding_config;
use aegis_engine::merkle::NoteTree;
use aegis_engine::poseidon::{Digest, F};
use aegis_engine::settlement_digest::{withdrawals_root, WithdrawalEntry};
use aegis_engine::spend::batch::{prove_spend_batch, SpendBatchProof, SpendCommonData};
use aegis_engine::spend::monolith::{build_spend_trace, InputNote, OutputNote, PUB_CMO0, PUB_NF0};
use aegis_recursion::digest_agg::{
    aggregate_settlement, layer1_settlement, serialize_root, verify_root_bytes,
};
use aegis_recursion::{AggParams, SpendProofInput};
use p3_field::PrimeCharacteristicRing;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

fn digest_arr(base: u32) -> Digest {
    core::array::from_fn(|i| F::from_u32(base + i as u32))
}

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

fn digest_at(pis: &[F], off: usize) -> Digest {
    core::array::from_fn(|i| pis[off + i])
}

fn run(n: u32) {
    let params = AggParams::default();
    let spends: Vec<_> = (1..=n).map(distinct_spend).collect();
    let entries: Vec<WithdrawalEntry> = spends
        .iter()
        .enumerate()
        .map(|(i, (_, _, pis))| WithdrawalEntry {
            amount: 1_000 + i as u64,
            recipient_prop: vec![0xA0 + i as u8; 33],
            nf0: digest_at(pis, PUB_NF0),
            cm0: digest_at(pis, PUB_CMO0),
        })
        .collect();

    let t_leaves = Instant::now();
    let leaves: Vec<_> = spends
        .iter()
        .zip(&entries)
        .map(|((p, c, pis), e)| {
            layer1_settlement(
                &params,
                &SpendProofInput {
                    proof: p,
                    common: c,
                    pis,
                },
                e.amount,
                &e.recipient_prop,
            )
        })
        .collect();
    let leaves_wall = t_leaves.elapsed();

    let t_agg = Instant::now();
    let (root, _packing, levels) = aggregate_settlement(&params, leaves);
    let agg_wall = t_agg.elapsed();

    let bytes = serialize_root(&root);

    let t_verify = Instant::now();
    let got = verify_root_bytes(&params, &bytes).expect("root verifies from bytes");
    let verify_wall = t_verify.elapsed();

    let want = withdrawals_root(&entries);
    assert_eq!(got.as_slice(), want.as_slice(), "root == withdrawals_root");

    println!(
        "[I4-MEASURE] N={n} levels={levels} | leaves {:?} | aggregate {:?} | \
         verify-from-bytes {:?} | root {} bytes | pipeline {:?}",
        leaves_wall,
        agg_wall,
        verify_wall,
        bytes.len(),
        leaves_wall + agg_wall,
    );
}

#[test]
fn measure_n2() {
    run(2);
}

#[test]
fn measure_n4() {
    run(4);
}
