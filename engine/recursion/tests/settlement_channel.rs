//! I4 settlement statement over the recursion root: does the aggregation tree
//! surface, at the ROOT, the withdrawals-Merkle-root the settlement guest
//! recomputes from the journal — bound to what the spend proofs attested?
//!
//! `RUSTFLAGS="-Ctarget-cpu=native" cargo test --release --test settlement_channel -- --nocapture`

use aegis_engine::commit::{note_commitment, owner_key};
use aegis_engine::config::recursion::make_recursion_hiding_config;
use aegis_engine::merkle::NoteTree;
use aegis_engine::poseidon::{Digest, F};
use aegis_engine::settlement_digest::{
    identity_digest, leaf_digest, withdrawals_root, WithdrawalEntry,
};
use aegis_engine::spend::batch::{prove_spend_batch, SpendBatchProof, SpendCommonData};
use aegis_engine::spend::monolith::{build_spend_trace, InputNote, OutputNote, PUB_CMO0, PUB_NF0};
use aegis_recursion::digest_agg::{
    aggregate_settlement, digest_publics, identity_leaf, layer1_settlement, verify_root_digest,
};
use aegis_recursion::{AggParams, SpendProofInput};
use p3_field::PrimeCharacteristicRing;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// ----- helpers (real spends, mirrors tests/digest_channel.rs) -----

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

fn digest_at(pis: &[F], off: usize) -> Digest {
    core::array::from_fn(|i| pis[off + i])
}

/// The settlement entry the guest would journal for a spend with these publics.
fn entry_for(pis: &[F], amount: u64, recipient: &[u8]) -> WithdrawalEntry {
    WithdrawalEntry {
        amount,
        recipient_prop: recipient.to_vec(),
        nf0: digest_at(pis, PUB_NF0),
        cm0: digest_at(pis, PUB_CMO0),
    }
}

// ----- happy path -----

/// PRODUCTION SHAPE (N=2, no padding): two real spends → settlement leaves →
/// root. Each leaf's exposed digest equals `leaf_digest(entry)`; the root's
/// surfaced digest equals `withdrawals_root([e0, e1])` — the exact value the
/// guest recomputes from the journal. This is the option-A settlement bind.
#[test]
fn root_digest_equals_withdrawals_root_n2() {
    let params = AggParams::default();
    let (pa, ca, pis_a) = distinct_spend(1);
    let (pb, cb, pis_b) = distinct_spend(2);
    let e0 = entry_for(&pis_a, 990, b"\xAArecipient-one");
    let e1 = entry_for(&pis_b, 1_500, b"\xBBrecipient-two-longer");

    let t0 = std::time::Instant::now();
    let la = layer1_settlement(
        &params,
        &SpendProofInput {
            proof: &pa,
            common: &ca,
            pis: &pis_a,
        },
        e0.amount,
        &e0.recipient_prop,
    );
    let lb = layer1_settlement(
        &params,
        &SpendProofInput {
            proof: &pb,
            common: &cb,
            pis: &pis_b,
        },
        e1.amount,
        &e1.recipient_prop,
    );
    println!("[I4] 2 settlement leaves in {:?}", t0.elapsed());

    // Per-leaf schema bind: exposed digest == native leaf_digest(entry).
    assert_eq!(
        digest_publics(&la.0).as_slice(),
        leaf_digest(&e0).as_slice()
    );
    assert_eq!(
        digest_publics(&lb.0).as_slice(),
        leaf_digest(&e1).as_slice()
    );

    let t1 = std::time::Instant::now();
    let (root, packing, levels) = aggregate_settlement(&params, vec![la, lb]);
    println!("[I4] N=2 aggregate ({levels} levels) in {:?}", t1.elapsed());
    assert_eq!(levels, 1);

    let got = verify_root_digest(&params, &root, packing).expect("root verifies");
    let want = withdrawals_root(&[e0.clone(), e1.clone()]);
    assert_eq!(got.as_slice(), want.as_slice(), "root == withdrawals_root");

    // Negative (the guest digest-check binding): any tampered journal entry —
    // wrong amount / recipient / nf0 / reorder — recomputes a different root.
    let bad_amount = withdrawals_root(&[
        WithdrawalEntry {
            amount: e0.amount + 1,
            ..e0.clone()
        },
        e1.clone(),
    ]);
    assert_ne!(
        got.as_slice(),
        bad_amount.as_slice(),
        "wrong amount must fail"
    );
    let bad_recipient = withdrawals_root(&[
        WithdrawalEntry {
            recipient_prop: b"other".to_vec(),
            ..e0.clone()
        },
        e1.clone(),
    ]);
    assert_ne!(
        got.as_slice(),
        bad_recipient.as_slice(),
        "wrong recipient fails"
    );
    let bad_nf0 = withdrawals_root(&[
        WithdrawalEntry {
            nf0: digest_arr(0xDEAD),
            ..e0.clone()
        },
        e1.clone(),
    ]);
    assert_ne!(got.as_slice(), bad_nf0.as_slice(), "wrong nf0 must fail");
    let reordered = withdrawals_root(&[e1, e0]);
    assert_ne!(got.as_slice(), reordered.as_slice(), "reorder must fail");
}

/// PADDING (N=3 → pad to 4): three real spends aggregate with ONE identity
/// padding leaf. The root's digest equals `withdrawals_root([e0,e1,e2])`
/// (which pads with `identity_digest`), and the heterogeneous real+identity
/// pairing at level 1 proves and verifies.
#[test]
fn root_digest_equals_withdrawals_root_n3_padded() {
    let params = AggParams::default();
    let spends: Vec<_> = (3..=5).map(distinct_spend).collect();
    let entries: Vec<WithdrawalEntry> = spends
        .iter()
        .enumerate()
        .map(|(i, (_, _, pis))| entry_for(pis, 100 * (i as u64 + 1), &[0xC0 + i as u8; 8]))
        .collect();

    let t0 = std::time::Instant::now();
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
    println!("[I4] 3 settlement leaves in {:?}", t0.elapsed());

    let t1 = std::time::Instant::now();
    let (root, packing, levels) = aggregate_settlement(&params, leaves);
    println!(
        "[I4] N=3(→4) aggregate ({levels} levels) in {:?}",
        t1.elapsed()
    );
    assert_eq!(levels, 2);

    let got = verify_root_digest(&params, &root, packing).expect("padded root verifies");
    let want = withdrawals_root(&entries);
    assert_eq!(
        got.as_slice(),
        want.as_slice(),
        "padded root == withdrawals_root"
    );
}

// ----- error paths / pins -----

/// A padding leaf carries the pinned identity digest and nothing else — it can
/// never encode a real withdrawal.
#[test]
fn identity_leaf_is_pinned_and_not_a_withdrawal() {
    let params = AggParams::default();
    let id = identity_leaf(&params);
    assert_eq!(
        digest_publics(&id.0).as_slice(),
        identity_digest().as_slice()
    );

    // No real withdrawal tuple hashes to the identity digest.
    let e = WithdrawalEntry {
        amount: 1,
        recipient_prop: vec![0x01],
        nf0: digest_arr(1),
        cm0: digest_arr(9),
    };
    assert_ne!(identity_digest().as_slice(), leaf_digest(&e).as_slice());
}
