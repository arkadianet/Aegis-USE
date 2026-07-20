//! Dump a fully-valid I4 settlement statement (root proof + guest inputs) to
//! files, for the RISC0 settlement guest EXECUTE measurement (item 4). Uses
//! BURN-VALID spends (out0 == the deterministic burn note) so every guest check
//! passes — root verify, digest bind, burn binding, epoch membership, tree
//! transition. Runs only when `AEGIS_I4_DUMP_DIR` is set.
//!
//! `AEGIS_I4_DUMP_DIR=/tmp/i4 AEGIS_I4_N=2 RUSTFLAGS="-Ctarget-cpu=native" \
//!    cargo test --release --test dump_artifacts -- --nocapture --ignored`

use aegis_engine::burn::{burn_cm_expected, burn_nonces, burn_owner};
use aegis_engine::commit::{note_commitment, owner_key};
use aegis_engine::config::recursion::make_recursion_hiding_config;
use aegis_engine::merkle::{Frontier, NoteTree};
use aegis_engine::nullifier::nullifier;
use aegis_engine::poseidon::{digest_to_limbs, Digest, F};
use aegis_engine::settlement_digest::{withdrawals_root, WithdrawalEntry};
use aegis_engine::spend::batch::{prove_spend_batch, SpendBatchProof, SpendCommonData};
use aegis_engine::spend::monolith::{build_spend_trace, InputNote, OutputNote, PUB_CMO0, PUB_NF0};
use aegis_recursion::digest_agg::{
    aggregate_settlement_sha, layer1_settlement, serialize_root_sha,
};
use aegis_recursion::{AggParams, SpendProofInput};
use p3_field::PrimeCharacteristicRing;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::Path;

fn digest_arr(base: u32) -> Digest {
    core::array::from_fn(|i| F::from_u32(base + i as u32))
}

/// A BURN-VALID 2-in/2-out spend keyed by `s` withdrawing `amount`: out0 is the
/// deterministic burn note for `amount + peg_fee` under the spend's own nf0.
fn burn_valid_spend(s: u32, amount: u64) -> (SpendBatchProof, SpendCommonData, Vec<F>) {
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
    let mut tree = NoteTree::new();
    let cm_in0 = note_commitment(in0.value, &owner_key(&in0.nk), &in0.rho, &in0.r);
    let cm_in1 = note_commitment(in1.value, &owner_key(&in1.nk), &in1.rho, &in1.r);
    let i0 = tree.append(cm_in0);
    let i1 = tree.append(cm_in1);
    let in0 = InputNote { index: i0, ..in0 };
    let in1 = InputNote { index: i1, ..in1 };

    // out0 = the deterministic burn note for (amount + peg_fee) under nf0, bound
    // to the withdrawal's (recipient_prop, amount) — D1. The recipient MUST match
    // the entry `recipient_prop` the caller derives (`0xA0 + (s-1)`), or the
    // guest's burn recomputation from the journaled recipient would mismatch.
    let nf0 = nullifier(&in0.nk, &in0.rho);
    let peg_fee = (amount / 100).max(1);
    let burn_value = amount + peg_fee;
    let recipient = vec![0xA0 + (s - 1) as u8; 33];
    let (brho, br) = burn_nonces(&nf0, &recipient, amount);
    let out0 = OutputNote {
        value: burn_value,
        owner: burn_owner(),
        rho: brho,
        r: br,
    };
    let flat_fee = 10u64;
    let out1 = OutputNote {
        value: in0.value + in1.value - burn_value - flat_fee,
        owner: digest_arr(600 + o),
        rho: digest_arr(650 + o),
        r: digest_arr(690 + o),
    };
    let (trace, pis) = build_spend_trace(&[in0, in1], &tree, &[out0, out1], flat_fee);
    // Sanity: the circuit's cm0 IS the burn note the guest recomputes.
    let cm0: Digest = core::array::from_fn(|i| pis[PUB_CMO0 + i]);
    assert_eq!(
        cm0,
        burn_cm_expected(burn_value, &nf0, &recipient, amount),
        "out0 must be the burn note"
    );

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

fn write_pc<T: serde::Serialize>(dir: &Path, name: &str, v: &T) {
    let bytes = postcard::to_allocvec(v).expect("postcard");
    std::fs::write(dir.join(name), bytes).expect("write");
}

#[test]
#[ignore = "artifact dump; run explicitly with AEGIS_I4_DUMP_DIR set"]
fn dump() {
    let Ok(dir) = std::env::var("AEGIS_I4_DUMP_DIR") else {
        eprintln!("AEGIS_I4_DUMP_DIR unset — skipping");
        return;
    };
    let n: u32 = std::env::var("AEGIS_I4_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let params = AggParams::default();

    let spends: Vec<_> = (1..=n)
        .map(|s| burn_valid_spend(s, 900 + s as u64))
        .collect();
    let entries: Vec<WithdrawalEntry> = spends
        .iter()
        .enumerate()
        .map(|(i, (_, _, pis))| WithdrawalEntry {
            amount: 900 + (i as u64 + 1),
            recipient_prop: vec![0xA0 + i as u8; 33],
            nf0: digest_at(pis, PUB_NF0),
            cm0: digest_at(pis, PUB_CMO0),
        })
        .collect();

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
    let (root, _levels) = aggregate_settlement_sha(&params, leaves);
    let root_bytes = serialize_root_sha(&root);

    // Guest inputs, in env::read order.
    let amounts: Vec<u64> = entries.iter().map(|e| e.amount).collect();
    let recipients: Vec<Vec<u8>> = entries.iter().map(|e| e.recipient_prop.clone()).collect();
    let nf0s: Vec<[u32; 8]> = entries.iter().map(|e| digest_to_limbs(&e.nf0)).collect();
    let cm0s: Vec<[u32; 8]> = entries.iter().map(|e| digest_to_limbs(&e.cm0)).collect();
    // Empty pre-epoch frontier; epoch = the burn commitments (satisfies membership).
    let frontier_bytes = postcard::to_allocvec(&Frontier::from_leaves(&[])).unwrap();
    let epoch_leaves: Vec<[u32; 8]> = cm0s.clone();
    let counter_next: u64 = n as u64;

    std::fs::write(dir.join("root.bin"), &root_bytes).unwrap();
    write_pc(dir, "amounts.pc", &amounts);
    write_pc(dir, "recipients.pc", &recipients);
    write_pc(dir, "nf0s.pc", &nf0s);
    write_pc(dir, "cm0s.pc", &cm0s);
    std::fs::write(dir.join("frontier.bin"), &frontier_bytes).unwrap();
    write_pc(dir, "epoch.pc", &epoch_leaves);
    write_pc(dir, "counter.pc", &counter_next);

    // Cross-check the bind holds natively before we ever run the guest.
    assert_eq!(
        aegis_recursion::digest_agg::verify_root_bytes_sha(&params, &root_bytes)
            .expect("root verifies")
            .as_slice(),
        withdrawals_root(&entries).as_slice(),
    );
    println!(
        "[I4-DUMP] N={n} root {} bytes -> {}",
        root_bytes.len(),
        dir.display()
    );
}
