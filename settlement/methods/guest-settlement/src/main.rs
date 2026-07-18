// Statement-1 settlement guest — the trustless peg-out proof.
//
// Proves, for one epoch of the hash-native chain:
//   1. the peg-out SPEND PROOF verifies in-field (hiding monolith 2-in/2-out,
//      BabyBear / Plonky3 uni-STARK) against the BAKED vk
//      (`aegis_engine::spend::baked_vk`, ELF constants — so the vk is pinned
//      by the image id; a malicious prover cannot substitute a different
//      circuit. Oracle parity vs `setup_preprocessed` is asserted engine-side);
//   2. the spend's out0 commitment is the deterministic BURN note for exactly
//      `withdrawal_amount + peg_fee` with nonces derived from the spend's
//      first nullifier (the consensus binding — value provably left the pool
//      for exactly this withdrawal);
//   3. advancing the committed PRE-EPOCH FRONTIER (the compact append boundary,
//      authenticated by prev_root: a wrong frontier reproduces a wrong root)
//      over the epoch's leaves (which include the burn commitment) takes
//      prev_root → new_root — O(epoch), independent of chain history.
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
use aegis_engine::config::{hiding_config_for_verify, HidingEngineConfig};
use aegis_engine::merkle::{settle_tree_transition, Frontier};
use aegis_engine::poseidon::{digest_to_bytes, Digest, DIGEST_ELEMS, F};
use aegis_engine::spend::baked_vk::baked_spend_vk;
use aegis_engine::spend::monolith::{SpendAir, N_PUB, PUB_CMO0, PUB_NF0};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{verify_with_preprocessed, Proof};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

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
    // The committed PRE-EPOCH frontier (postcard, like `proof_bytes`): the
    // compact append boundary, NOT the pre-epoch leaves. Its `root()` is bound
    // to the public `prev_root` below, so a wrong boundary cannot pass.
    let frontier_bytes: Vec<u8> = env::read();
    let epoch_leaves: Vec<[u32; DIGEST_ELEMS]> = env::read();
    let withdrawal_amount: u64 = env::read();
    let recipient_prop: Vec<u8> = env::read();
    let counter_next: u64 = env::read();

    let c0 = env::cycle_count();

    // ---- 1. the BAKED vk (ELF constants, pinned by the image id) ----
    // T1.1 vk-bake: `setup_preprocessed` used to run here (66 M cycles under
    // the Poseidon2 MMCS, ~7.5 M under SHA) purely to re-derive a constant.
    // The baked constants are asserted equal to that derivation by the
    // engine-side oracle-parity test (`spend::baked_vk`).
    let air = SpendAir;
    let vk = baked_spend_vk();
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

    // ---- 3. INCREMENTAL transition prev_root → new_root over the epoch ----
    // O(epoch): advance the committed frontier over just the epoch leaves.
    // `prev_root` from the frontier must equal the public root the PegVault
    // binds (checked implicitly — the journal commits this prev_root, and the
    // contract requires it to equal the vault's R4). A wrong frontier yields a
    // wrong prev_root and the release cannot match the vault.
    let frontier: Frontier =
        postcard::from_bytes(&frontier_bytes).expect("pre-epoch frontier decodes");
    let epoch: Vec<Digest> = epoch_leaves.iter().map(limbs_to_digest).collect();
    let burn_in_epoch = epoch.iter().any(|d| *d == cm0);
    assert!(burn_in_epoch, "burn commitment must be an epoch leaf");
    let (prev_root, new_frontier) = settle_tree_transition(&frontier, &epoch);
    let new_root = new_frontier.root();
    let c_tree = env::cycle_count();
    env::log(&alloc::format!(
        "CYCLES tree_transition={} (epoch={})",
        c_tree - c_verify,
        epoch.len()
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
