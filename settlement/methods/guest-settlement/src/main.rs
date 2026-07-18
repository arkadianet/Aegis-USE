// Statement-1 settlement guest — the trustless peg-out proof.
//
// Proves, for one epoch of the hash-native chain:
//   1. the peg-out SPEND PROOF verifies in-field (hiding monolith 2-in/2-out,
//      BabyBear / Plonky3 uni-STARK) against the vk REBUILT IN-GUEST from the
//      fixed public preprocessed salt (so the vk is pinned by the image id —
//      a malicious prover cannot substitute a different circuit);
//   2. the spend's out0 commitment is the deterministic BURN note for exactly
//      `withdrawal_amount + peg_fee` with nonces derived from the spend's
//      first nullifier (the consensus binding — value provably left the pool
//      for exactly this withdrawal);
//   3. appending the epoch's leaves (which include the burn commitment) to
//      the pre-epoch tree takes prev_root → new_root.
//
// The journal commits EXACTLY the bytes the PegVault contract reconstructs
// from the release transaction:
//   b"AEGISPO3" ‖ prev_root(32) ‖ new_root(32) ‖ amount_be(8) ‖
//   counter_next_be(8) ‖ recipient_prop (variable)
//
// Honest scope (documented): nullifier-freshness and the anchor-root WINDOW
// of the spend are enforced by hn chain consensus, not re-proven here; the
// full epoch-validity proof (every tx + pot arithmetic in-field) is the
// documented follow-up.
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

use aegis_engine::burn::burn_cm_expected;
use aegis_engine::config::{hiding_config_for_verify, make_hiding_config, HidingEngineConfig};
use aegis_engine::merkle::NoteTree;
use aegis_engine::poseidon::{digest_to_bytes, Digest, DIGEST_ELEMS, F};
use aegis_engine::spend::monolith::{SpendAir, N_PUB, N_ROWS, PUB_CMO0, PUB_NF0};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{setup_preprocessed, verify_with_preprocessed, Proof};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

/// The engine wallet's fixed PUBLIC preprocessed salt (`SpendCircuit::new`).
/// Baked into the guest so the verifying key is part of the image id.
const PREPROCESSED_SALT_SEED: u64 = 0x5EED_5A17_0A15_0001;

const JOURNAL_TAG: &[u8; 8] = b"AEGISPO3";

fn limbs_to_digest(l: &[u32; DIGEST_ELEMS]) -> Digest {
    core::array::from_fn(|i| F::from_u32(l[i]))
}

fn digest_at(pis: &[F], off: usize) -> Digest {
    core::array::from_fn(|i| pis[off + i])
}

fn main() {
    // ---- private inputs ----
    let proof_bytes: Vec<u8> = env::read();
    let public_values: Vec<u32> = env::read();
    let pre_leaves: Vec<[u32; DIGEST_ELEMS]> = env::read();
    let epoch_leaves: Vec<[u32; DIGEST_ELEMS]> = env::read();
    let withdrawal_amount: u64 = env::read();
    let recipient_prop: Vec<u8> = env::read();
    let counter_next: u64 = env::read();

    let c0 = env::cycle_count();

    // ---- 1. rebuild the vk from the fixed public salt; verify in-field ----
    let air = SpendAir;
    let degree_bits = N_ROWS.trailing_zeros() as usize;
    let setup_config = make_hiding_config(
        ChaCha20Rng::seed_from_u64(PREPROCESSED_SALT_SEED),
        ChaCha20Rng::seed_from_u64(PREPROCESSED_SALT_SEED ^ 0x9e37_79b9_7f4a_7c15),
    );
    let (_pd, vk) = setup_preprocessed::<HidingEngineConfig, _>(&setup_config, &air, degree_bits)
        .expect("preprocessed vk");
    let c_vk = env::cycle_count();
    env::log(&alloc::format!("CYCLES vk_setup={}", c_vk - c0));

    let verify_config = hiding_config_for_verify();
    let proof: Proof<HidingEngineConfig> =
        postcard::from_bytes(&proof_bytes).expect("spend proof decodes");
    let pis: Vec<F> = public_values.iter().map(|&x| F::from_u32(x)).collect();
    assert_eq!(pis.len(), N_PUB, "public-value shape");
    verify_with_preprocessed(&verify_config, &air, &proof, &pis, Some(&vk))
        .expect("peg-out spend proof must verify in-field");
    let c_verify = env::cycle_count();
    env::log(&alloc::format!("CYCLES spend_verify={}", c_verify - c_vk));

    // ---- 2. the burn binding: out0 == burn note for (amount + fee, nf0) ----
    let peg_fee = (withdrawal_amount / 100).max(1);
    let burn_value = withdrawal_amount
        .checked_add(peg_fee)
        .expect("burn value overflow");
    let nf0 = digest_at(&pis, PUB_NF0);
    let cm0 = digest_at(&pis, PUB_CMO0);
    assert_eq!(
        burn_cm_expected(burn_value, &nf0),
        cm0,
        "out0 must be the deterministic burn note for this withdrawal"
    );

    // ---- 3. tree transition prev_root → new_root over the epoch ----
    let mut tree = NoteTree::new();
    for l in &pre_leaves {
        tree.append(limbs_to_digest(l));
    }
    let prev_root = tree.root();
    let mut burn_in_epoch = false;
    for l in &epoch_leaves {
        let d = limbs_to_digest(l);
        if d == cm0 {
            burn_in_epoch = true;
        }
        tree.append(d);
    }
    assert!(burn_in_epoch, "burn commitment must be an epoch leaf");
    let new_root = tree.root();
    let c_tree = env::cycle_count();
    env::log(&alloc::format!(
        "CYCLES tree_transition={} (pre={} epoch={})",
        c_tree - c_verify,
        pre_leaves.len(),
        epoch_leaves.len()
    ));

    // ---- 4. the journal: exactly what PegVault reconstructs from the tx ----
    let mut journal = Vec::with_capacity(8 + 32 + 32 + 8 + 8 + recipient_prop.len());
    journal.extend_from_slice(JOURNAL_TAG);
    journal.extend_from_slice(&digest_to_bytes(&prev_root));
    journal.extend_from_slice(&digest_to_bytes(&new_root));
    journal.extend_from_slice(&withdrawal_amount.to_be_bytes());
    journal.extend_from_slice(&counter_next.to_be_bytes());
    journal.extend_from_slice(&recipient_prop);
    env::commit_slice(&journal);
}
