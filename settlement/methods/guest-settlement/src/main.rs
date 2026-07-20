// Batch Statement-1 settlement guest (I4) — the batch-independent trustless
// peg-out proof over the recursion aggregation ROOT.
//
// Proves, for one epoch of the hash-native chain and its N settled withdrawals:
//   1. the aggregation ROOT proof verifies in-field (ONE verify, constant in N:
//      it recursively attests all N client spend proofs). Its surfaced
//      `aegis/digest` public values are the withdrawals-Merkle-root the tree
//      folded from the per-withdrawal leaf digests
//      (recursion-feasibility.md §11, option A);
//   2. the withdrawals digest recomputed from the §1 JOURNAL entry list
//      (amount ‖ recipient_commit ‖ nf0 ‖ cm0, folded by `withdrawals_root`)
//      EQUALS the root's surfaced digest — the BIND: the journal the vault
//      reconstructs is exactly what the aggregated proofs attested;
//   3. each withdrawal's out0 commitment is the deterministic BURN note for
//      `amount + peg_fee` with nonces from its nullifier AND the JOURNALED
//      `(recipient_prop, amount)` (the D1 recipient binding — a settler
//      journaling any other recipient reproduces a different commitment and the
//      proof fails), its cm0 is an epoch leaf, and all nf0 are pairwise distinct
//      (no burn backs two entries);
//   4. advancing the committed PRE-EPOCH FRONTIER over the epoch's leaves takes
//      prev_root → new_root — O(epoch), once per batch.
//
// The journal commits EXACTLY the bytes the PegVault reconstructs from the
// release transaction (batch-settlement-design.md §1):
//   b"AEGISPB1" ‖ prev_root(32) ‖ new_root(32) ‖ counter_next_be(8) ‖
//   [ amount_be(8) ‖ prop_len_be(8) ‖ recipient_prop ]×N   (output order)
//
// I5 slots (structured here, not yet enforced): epoch-validity (`new_root`
// canonical hn root) and the settled-burn accumulator (settlement-nullifier set
// making each burn settle at most once) add guest checks + a vault register;
// the per-withdrawal tuple and journal layout above are stable across that work.
// Cross-batch anti-replay currently rests on the honest-settler / epoch-
// canonicality assumption (§4) — testnet-acceptable, mainnet-blocking until I5.
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

use aegis_engine::burn::burn_cm_expected;
use aegis_engine::merkle::{settle_tree_transition, Frontier};
use aegis_engine::poseidon::{digest_to_bytes, Digest, DIGEST_ELEMS, F};
use aegis_engine::settlement_digest::{batch_journal, withdrawals_root, WithdrawalEntry};
use aegis_recursion::digest_agg::verify_root_bytes_sha;
use aegis_recursion::AggParams;
use p3_field::PrimeCharacteristicRing;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn limbs_to_digest(l: &[u32; DIGEST_ELEMS]) -> Digest {
    core::array::from_fn(|i| F::from_u32(l[i]))
}

fn main() {
    // ---- private inputs (env::read order; the host writes exactly this) ----
    let root_bytes: Vec<u8> = env::read();
    let amounts: Vec<u64> = env::read();
    let recipients: Vec<Vec<u8>> = env::read();
    let nf0s: Vec<[u32; DIGEST_ELEMS]> = env::read();
    let cm0s: Vec<[u32; DIGEST_ELEMS]> = env::read();
    // The committed PRE-EPOCH frontier (postcard) — the compact append boundary;
    // its root() is bound to `prev_root` (a wrong boundary yields a wrong root).
    let frontier_bytes: Vec<u8> = env::read();
    let epoch_leaves: Vec<[u32; DIGEST_ELEMS]> = env::read();
    let counter_next: u64 = env::read();

    let n = amounts.len();
    assert!(n >= 1, "at least one withdrawal");
    assert_eq!(recipients.len(), n, "recipient count");
    assert_eq!(nf0s.len(), n, "nf0 count");
    assert_eq!(cm0s.len(), n, "cm0 count");

    let c0 = env::cycle_count();

    // ---- 1. verify the aggregation ROOT (ONE verify, constant in N) ----
    // The root's FINAL layer is committed under the SHA-256 config (I5a), so this
    // verify's MMCS/challenger hashing rides the RISC0 SHA accelerator
    // (sys_sha_buffer) — ~4.7x cheaper than software Poseidon2. Reconstructs the
    // poseidon2 + recompose + aegis/digest verifier from the packing carried
    // inside the proof and runs verify_all_tables in-field. The returned limbs are
    // the root's surfaced withdrawals digest (unchanged by the config swap).
    let params = AggParams::default();
    let root_digest =
        verify_root_bytes_sha(&params, &root_bytes).expect("aggregate root must verify");
    let c_verify = env::cycle_count();
    env::log(&alloc::format!("CYCLES root_verify={}", c_verify - c0));

    // ---- 2. THE BIND: journal digest == root's surfaced digest ----
    let entries: Vec<WithdrawalEntry> = (0..n)
        .map(|i| WithdrawalEntry {
            amount: amounts[i],
            recipient_prop: recipients[i].clone(),
            nf0: limbs_to_digest(&nf0s[i]),
            cm0: limbs_to_digest(&cm0s[i]),
        })
        .collect();
    let want = withdrawals_root(&entries);
    assert_eq!(
        root_digest.as_slice(),
        want.as_slice(),
        "journal withdrawals digest must equal the root's surfaced digest"
    );

    // ---- 3. per-withdrawal burn binding + epoch membership + distinctness ----
    let epoch: Vec<Digest> = epoch_leaves.iter().map(limbs_to_digest).collect();
    for e in &entries {
        // fee mirror of HnChainParams::peg_fee (hn/params.rs); keep in lockstep.
        let peg_fee = (e.amount / 100).max(1);
        let burn_value = e.amount.checked_add(peg_fee).expect("burn value overflow");
        // D1: the burn nonces bind the JOURNALED (recipient_prop, amount) too, so
        // a settler journaling any other recipient reproduces a different burn
        // commitment and this equality fails.
        assert_eq!(
            burn_cm_expected(burn_value, &e.nf0, &e.recipient_prop, e.amount),
            e.cm0,
            "out0 must be the deterministic burn note for this withdrawal + recipient"
        );
        assert!(
            epoch.iter().any(|d| *d == e.cm0),
            "burn commitment must be an epoch leaf"
        );
    }
    // Pairwise-distinct nf0 ⇒ distinct burns ⇒ no burn backs two entries.
    for i in 0..n {
        for j in (i + 1)..n {
            assert_ne!(entries[i].nf0, entries[j].nf0, "duplicate nullifier");
        }
    }
    let c_bind = env::cycle_count();
    env::log(&alloc::format!("CYCLES bind={}", c_bind - c_verify));

    // ---- 4. INCREMENTAL transition prev_root → new_root over the epoch ----
    let frontier: Frontier =
        postcard::from_bytes(&frontier_bytes).expect("pre-epoch frontier decodes");
    let (prev_root, new_frontier) = settle_tree_transition(&frontier, &epoch);
    let new_root = new_frontier.root();
    let c_tree = env::cycle_count();
    env::log(&alloc::format!(
        "CYCLES tree_transition={} (epoch={})",
        c_tree - c_bind,
        epoch.len()
    ));

    // ---- 5. commit the §1 batch journal (PegVault reconstructs it verbatim) ----
    let journal = batch_journal(
        &digest_to_bytes(&prev_root),
        &digest_to_bytes(&new_root),
        counter_next,
        &entries,
    );
    env::commit_slice(&journal);
}
