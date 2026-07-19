//! Settlement withdrawals-digest — the native side of the I4 recursion
//! settlement binding (shared by the aggregation circuit's oracle, the
//! settlement host, and the RISC0 settlement guest).
//!
//! # What this binds
//! The recursion aggregation tree folds a per-withdrawal *leaf digest* up to a
//! single ROOT digest, surfaced as the root proof's plaintext `public_values`
//! (the option-A channel — `recursion-feasibility.md` §11). The settlement
//! guest recomputes the SAME root digest from the batch journal's entry list
//! and checks equality: that equality is the bind proving the withdrawals the
//! vault reconstructs are exactly the ones the aggregated proofs attested.
//!
//! # The two hashes, and why parity holds
//! - **`recipient_commit`** — a domain-separated engine sponge over the
//!   recipient's ErgoTree bytes (fixed-width commitment; host and guest both
//!   call it, so parity is by construction).
//! - **[`circuit_sponge`]** — the NATIVE reproduction of the recursion library's
//!   in-circuit `add_hash_slice` (`CircuitBuilder::add_hash_slice`,
//!   Poseidon2-W16, D=4). The leaf/fold digests are produced *in-circuit* by
//!   that gadget; the guest cannot run a circuit, so it must recompute them
//!   natively. For 4-aligned base inputs the circuit gadget equals the standard
//!   overwrite-mode padding-free sponge (proven upstream:
//!   `Plonky3-recursion/circuit/src/ops/hash.rs::test_hash_squeeze`); each
//!   digest limb is re-exposed to the parent circuit as the extension element
//!   `(limb, 0, 0, 0)`, so the base sequence the sponge actually absorbs is each
//!   input value followed by three zeros. [`circuit_sponge`] does exactly that.
//!   The `aegis-recursion` crate asserts `circuit_sponge(x)` equals the circuit
//!   oracle (`digest_channel`/`settlement_channel` parity tests), so the guest's
//!   recomputation is proof-bound.
//!
//! # I5 slots (structured, not built here)
//! [`batch_journal`] emits the §1 layout `AEGISPB1 ‖ prev_root ‖ new_root ‖
//! counter_next ‖ entries`. Epoch-validity (`new_root` canonical) and the
//! settled-burn accumulator ride the same statement in I5 — they add guest
//! checks and journal/vault fields, not a different digest.

use p3_field::PrimeCharacteristicRing;

use crate::poseidon::{hash_domain, permute, Digest, F, WIDTH};

/// Poseidon2-W16 rate in base field elements (the recursion library's
/// `rate_ext = 2` extension elements × D=4 = 8 base lanes).
const SPONGE_RATE: usize = 8;
/// Extension degree the digest limbs are re-exposed under (BabyBear D=4).
const EXT_D: usize = 4;

/// Domain tag for the recipient-proposition commitment folded into a leaf digest.
pub const DOMAIN_SETTLE_RECIPIENT: u32 = 0x0A20;

/// The batch settlement journal tag (`recursion-feasibility.md` §11 /
/// `batch-settlement-design.md` §1, v6 cut).
pub const BATCH_JOURNAL_TAG: &[u8; 8] = b"AEGISPB1";

/// Pinned nothing-up-my-sleeve preimage for the padding identity leaf. A padding
/// slot contributes exactly `circuit_sponge(IDENTITY_PREIMAGE)` — a fixed
/// constant that no real withdrawal tuple can produce (sponge collision
/// resistance), so padding can never smuggle a withdrawal.
pub const IDENTITY_PREIMAGE_TAG: &[u8; 24] = b"aegis-settle-identity-v1";

/// Native reproduction of the recursion circuit's `add_hash_slice`
/// (Poseidon2-W16 overwrite-mode padding-free sponge, `reset = true`) over
/// inputs each re-exposed as the extension element `(v, 0, 0, 0)`.
///
/// The absorbed base sequence is therefore each input value followed by
/// `EXT_D - 1` zeros; it must be padded to a multiple of the rate, which every
/// call site here satisfies (all inputs are 8-limb-aligned).
pub fn circuit_sponge(inputs: &[F]) -> Digest {
    // Repack each input EF element `(v,0,0,0)` to its base coefficients.
    let mut absorbed: Vec<F> = Vec::with_capacity(inputs.len() * EXT_D);
    for &v in inputs {
        absorbed.push(v);
        absorbed.extend_from_slice(&[F::ZERO; EXT_D - 1]);
    }
    debug_assert_eq!(
        absorbed.len() % SPONGE_RATE,
        0,
        "circuit_sponge inputs must be rate-aligned (even count)"
    );

    let mut state = [F::ZERO; WIDTH];
    for chunk in absorbed.chunks(SPONGE_RATE) {
        // Overwrite mode: rate lanes are replaced (not added), capacity carries.
        state[..chunk.len()].copy_from_slice(chunk);
        permute(&mut state);
    }
    state[..8].try_into().expect("8 of 16 lanes")
}

/// The recipient-proposition commitment folded into a leaf digest — a
/// domain-separated engine sponge over the ErgoTree bytes (each byte a field
/// element). Fixed 8-limb output regardless of recipient length.
pub fn recipient_commit(recipient_prop: &[u8]) -> Digest {
    let limbs: Vec<F> = recipient_prop
        .iter()
        .map(|&b| F::from_u32(b as u32))
        .collect();
    hash_domain(DOMAIN_SETTLE_RECIPIENT, &limbs)
}

/// The u64 amount as 8 big-endian byte field elements (matches the leaf circuit
/// exposing 8 amount public inputs, and the §1 journal's `amount_be`).
pub fn amount_limbs(amount: u64) -> [F; 8] {
    let be = amount.to_be_bytes();
    core::array::from_fn(|i| F::from_u32(be[i] as u32))
}

/// One settled withdrawal — the fields the leaf digest binds and the §1 journal
/// carries. `nf0`/`cm0` are the spend proof's public values (bound in-circuit at
/// the leaf); `amount`/`recipient_prop` are the settlement declaration (bound to
/// the proof by the guest's burn check and journaled verbatim).
///
/// I5 note: epoch-validity and the settled-burn accumulator add fields to the
/// *statement*, not to this per-withdrawal tuple — the leaf digest schema is
/// stable across that work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalEntry {
    pub amount: u64,
    pub recipient_prop: Vec<u8>,
    pub nf0: Digest,
    pub cm0: Digest,
}

/// The per-withdrawal leaf digest: `H(amount ‖ recipient_commit ‖ nf0 ‖ cm0)`
/// folded by the circuit sponge — the exact value the leaf circuit exposes.
pub fn leaf_digest(entry: &WithdrawalEntry) -> Digest {
    let mut inputs: Vec<F> = Vec::with_capacity(32);
    inputs.extend_from_slice(&amount_limbs(entry.amount));
    inputs.extend_from_slice(&recipient_commit(&entry.recipient_prop));
    inputs.extend_from_slice(&entry.nf0);
    inputs.extend_from_slice(&entry.cm0);
    circuit_sponge(&inputs)
}

/// The pinned padding-leaf preimage: the identity tag as field elements, padded
/// with zeros to a rate multiple. The aggregation circuit's identity leaf seeds
/// its digest from exactly this, so `identity_leaf.digest == identity_digest()`.
pub fn identity_preimage() -> Vec<F> {
    let mut p: Vec<F> = IDENTITY_PREIMAGE_TAG
        .iter()
        .map(|&b| F::from_u32(b as u32))
        .collect();
    while !p.len().is_multiple_of(8) {
        p.push(F::ZERO);
    }
    p
}

/// The pinned identity digest a padding leaf contributes.
pub fn identity_digest() -> Digest {
    circuit_sponge(&identity_preimage())
}

/// Fold a power-of-two-padded slice of leaf digests into the root digest exactly
/// as the aggregation tree does: `H(left ‖ right)` per node, pairs left to right,
/// bottom to top. Panics if `leaves` is empty.
fn fold_tree(mut leaves: Vec<Digest>) -> Digest {
    assert!(!leaves.is_empty(), "empty withdrawal tree");
    assert!(
        leaves.len().is_power_of_two(),
        "fold_tree expects a power-of-two leaf count"
    );
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            let mut inputs: Vec<F> = Vec::with_capacity(16);
            inputs.extend_from_slice(&pair[0]);
            inputs.extend_from_slice(&pair[1]);
            next.push(circuit_sponge(&inputs));
        }
        leaves = next;
    }
    leaves[0]
}

/// The withdrawals-Merkle-root over the epoch's entries: leaf digests for the
/// `N` real withdrawals, padded to the next power of two with the pinned
/// identity digest. This is the value the guest checks against the root proof's
/// surfaced digest. `N >= 1` required.
pub fn withdrawals_root(entries: &[WithdrawalEntry]) -> Digest {
    assert!(!entries.is_empty(), "at least one withdrawal");
    let padded = entries.len().next_power_of_two();
    let identity = identity_digest();
    let mut leaves: Vec<Digest> = Vec::with_capacity(padded);
    for e in entries {
        leaves.push(leaf_digest(e));
    }
    leaves.resize(padded, identity);
    fold_tree(leaves)
}

/// Build the §1 batch settlement journal committed by the guest and
/// reconstructed by the PegVault contract:
/// `AEGISPB1 ‖ prev_root(32) ‖ new_root(32) ‖ counter_next_be(8) ‖
///  [amount_be(8) ‖ prop_len_be(8) ‖ recipient_prop]×N`, in output order.
pub fn batch_journal(
    prev_root: &[u8; 32],
    new_root: &[u8; 32],
    counter_next: u64,
    entries: &[WithdrawalEntry],
) -> Vec<u8> {
    let mut j = Vec::new();
    j.extend_from_slice(BATCH_JOURNAL_TAG);
    j.extend_from_slice(prev_root);
    j.extend_from_slice(new_root);
    j.extend_from_slice(&counter_next.to_be_bytes());
    for e in entries {
        j.extend_from_slice(&e.amount.to_be_bytes());
        j.extend_from_slice(&(e.recipient_prop.len() as u64).to_be_bytes());
        j.extend_from_slice(&e.recipient_prop);
    }
    j
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn digest_of(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    fn entry(amount: u64, rec: &[u8], nf: u32, cm: u32) -> WithdrawalEntry {
        WithdrawalEntry {
            amount,
            recipient_prop: rec.to_vec(),
            nf0: digest_of(nf),
            cm0: digest_of(cm),
        }
    }

    // ----- happy path -----

    #[test]
    fn circuit_sponge_is_deterministic() {
        let x: Vec<F> = (0..16).map(F::from_u32).collect();
        assert_eq!(circuit_sponge(&x), circuit_sponge(&x));
    }

    #[test]
    fn identity_digest_is_pinned() {
        // Stable across calls and distinct from any small real-tuple leaf.
        assert_eq!(identity_digest(), identity_digest());
        let e = entry(100, b"\xAA\xBB", 1, 2);
        assert_ne!(identity_digest(), leaf_digest(&e));
    }

    #[test]
    fn withdrawals_root_single_pads_with_identity() {
        // N=1 pads to 1 (already a power of two): root == leaf_digest.
        let e = entry(990, b"recipient", 10, 20);
        assert_eq!(withdrawals_root(&[e.clone()]), leaf_digest(&e));
    }

    #[test]
    fn withdrawals_root_three_pads_to_four() {
        let e0 = entry(100, b"a", 1, 2);
        let e1 = entry(200, b"bb", 3, 4);
        let e2 = entry(300, b"ccc", 5, 6);
        let id = identity_digest();
        // Manual tree over [d0, d1, d2, identity].
        let d0 = leaf_digest(&e0);
        let d1 = leaf_digest(&e1);
        let d2 = leaf_digest(&e2);
        let l = circuit_sponge(&[d0.as_slice(), d1.as_slice()].concat());
        let r = circuit_sponge(&[d2.as_slice(), id.as_slice()].concat());
        let expected = circuit_sponge(&[l.as_slice(), r.as_slice()].concat());
        assert_eq!(withdrawals_root(&[e0, e1, e2]), expected);
    }

    // ----- error paths (the guest digest-check binding, natively) -----

    #[test]
    fn changed_amount_changes_root() {
        let a = [entry(100, b"a", 1, 2), entry(200, b"b", 3, 4)];
        let b = [entry(101, b"a", 1, 2), entry(200, b"b", 3, 4)];
        assert_ne!(withdrawals_root(&a), withdrawals_root(&b));
    }

    #[test]
    fn changed_recipient_changes_root() {
        let a = [entry(100, b"aa", 1, 2), entry(200, b"b", 3, 4)];
        let b = [entry(100, b"az", 1, 2), entry(200, b"b", 3, 4)];
        assert_ne!(withdrawals_root(&a), withdrawals_root(&b));
    }

    #[test]
    fn changed_nf0_changes_root() {
        let a = [entry(100, b"a", 1, 2), entry(200, b"b", 3, 4)];
        let b = [entry(100, b"a", 9, 2), entry(200, b"b", 3, 4)];
        assert_ne!(withdrawals_root(&a), withdrawals_root(&b));
    }

    #[test]
    fn reordered_entries_change_root() {
        let a = [entry(100, b"a", 1, 2), entry(200, b"b", 3, 4)];
        let b = [entry(200, b"b", 3, 4), entry(100, b"a", 1, 2)];
        assert_ne!(withdrawals_root(&a), withdrawals_root(&b));
    }

    #[test]
    fn dropped_entry_changes_root() {
        let a = [entry(100, b"a", 1, 2), entry(200, b"b", 3, 4)];
        let b = [entry(100, b"a", 1, 2)];
        assert_ne!(withdrawals_root(&a), withdrawals_root(&b));
    }

    // ----- round-trips -----

    #[test]
    fn batch_journal_layout_roundtrips() {
        let e0 = entry(100, b"\x01\x02\x03", 1, 2);
        let e1 = entry(200, b"\x04", 3, 4);
        let prev = [7u8; 32];
        let new = [9u8; 32];
        let j = batch_journal(&prev, &new, 42, &[e0.clone(), e1.clone()]);
        // tag(8)+prev(32)+new(32)+counter(8) = 80, then two length-prefixed entries.
        assert_eq!(&j[0..8], BATCH_JOURNAL_TAG);
        assert_eq!(&j[8..40], &prev);
        assert_eq!(&j[40..72], &new);
        assert_eq!(&j[72..80], &42u64.to_be_bytes());
        // entry 0: amount(8) len(8) prop(3)
        assert_eq!(&j[80..88], &100u64.to_be_bytes());
        assert_eq!(&j[88..96], &3u64.to_be_bytes());
        assert_eq!(&j[96..99], &[1, 2, 3]);
        // entry 1: amount(8) len(8) prop(1)
        assert_eq!(&j[99..107], &200u64.to_be_bytes());
        assert_eq!(&j[107..115], &1u64.to_be_bytes());
        assert_eq!(&j[115..116], &[4]);
        assert_eq!(j.len(), 116);
    }
}
