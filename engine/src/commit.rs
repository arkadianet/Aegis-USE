//! Note commitment and owner key (hash-native — NO elliptic curve).
//!
//! # Pinned layouts (chain-id-breaking; REVIEW ITEMS)
//! A note is `(value, owner, rho, r)`:
//! - `value`  — the amount, a single BabyBear element constrained to
//!   `< 2^AMOUNT_BITS` (see below).
//! - `owner`  — the recipient's owner key, a digest `owner = H(nk)`. This is the
//!   hash-based replacement for the elliptic-curve `pk = nk·B`; the spender
//!   proves knowledge of the `nk` whose hash is the note's `owner`.
//! - `rho`    — a per-note nonce digest (uniqueness; nullifier input).
//! - `r`      — a blinding digest (hides `value`/`owner` in `cm`).
//!
//! **Commitment:** `cm = H_CM(value ‖ owner ‖ rho ‖ r)` — a domain-separated
//! Poseidon2 sponge (25 field elements → 4 permutations; see
//! [`crate::poseidon`]). `cm` is the leaf inserted into the note accumulator
//! ([`crate::merkle`]).
//!
//! **Owner key:** `owner = H_OWNER(nk)` — one permutation.
//!
//! ## The `AMOUNT_BITS` choice (soundness — REVIEW ITEM)
//! BabyBear is a ~31-bit field, so a single field element cannot hold a full
//! `u64`, and a multi-term balance sum must not wrap the modulus. `value` is
//! therefore pinned to `< 2^28`: with two inputs and (two outputs + fee) the
//! balance equation's largest side is `3·2^28 < 2^30 < p`, so value
//! conservation is a single **overflow-free** field constraint (the spike's
//! model) and each amount range-check is a 28-bit decomposition. A production
//! engine wanting full 64-bit amounts represents `value` as 2–3 limbs with a
//! carrying balance adder — a mechanical, documented extension, deliberately
//! out of this CORE pass.

use p3_field::{PrimeCharacteristicRing, PrimeField32};

use crate::poseidon::{hash_domain, Digest, DIGEST_ELEMS, DOMAIN_COMMITMENT, DOMAIN_OWNER, F};

/// Amount bit-width (see module doc — pinned for overflow-free field balance).
pub const AMOUNT_BITS: usize = 28;
/// Inclusive upper bound on a valid amount: `2^AMOUNT_BITS`.
pub const AMOUNT_BOUND: u64 = 1 << AMOUNT_BITS;

/// A spending/nullifier key `nk`: 8 limbs (~248-bit).
pub type Nk = [F; DIGEST_ELEMS];
/// A per-note nonce `rho`: 8 limbs.
pub type Rho = [F; DIGEST_ELEMS];
/// A blinding factor `r`: 8 limbs.
pub type Blinding = [F; DIGEST_ELEMS];

/// Encode a `u64` amount (`< 2^AMOUNT_BITS`) as a field element.
///
/// # Panics
/// If `value >= 2^AMOUNT_BITS` — an out-of-range amount is a programming error
/// (the circuit also rejects it via the range constraint).
pub fn amount(value: u64) -> F {
    assert!(value < AMOUNT_BOUND, "amount {value} exceeds 2^{AMOUNT_BITS}");
    F::from_u64(value)
}

/// Recover the `u64` amount from its field encoding (canonical representative).
pub fn amount_to_u64(v: F) -> u64 {
    v.as_canonical_u32() as u64
}

/// Owner key `owner = H_OWNER(nk)` — the hash-based public key (no `nk·B`).
pub fn owner_key(nk: &Nk) -> Digest {
    hash_domain(DOMAIN_OWNER, nk)
}

/// The four rate-8 sponge blocks of a note commitment, in absorption order:
/// `[value ‖ 0×7]`, `owner`, `rho`, `r`. Component-aligned (one component per
/// block) so the in-circuit sponge chain ([`crate::spend`]) absorbs exactly one
/// component per row — no component straddles a block boundary.
pub fn commitment_blocks(value: F, owner: &Digest, rho: &Rho, r: &Blinding) -> [[F; DIGEST_ELEMS]; 4] {
    let mut value_block = [F::ZERO; DIGEST_ELEMS];
    value_block[0] = value;
    [value_block, *owner, *rho, *r]
}

/// Note commitment `cm = H_CM(value_block ‖ owner ‖ rho ‖ r)` — a
/// domain-separated Poseidon2 sponge over the four component-aligned blocks
/// (32 field elements → 4 permutations).
pub fn note_commitment(value: F, owner: &Digest, rho: &Rho, r: &Blinding) -> Digest {
    let blocks = commitment_blocks(value, owner, rho, r);
    hash_domain(DOMAIN_COMMITMENT, &blocks.concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn digest(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    fn sample_note() -> (F, Digest, Rho, Blinding) {
        let nk: Nk = digest(1);
        (amount(1_000), owner_key(&nk), digest(50), digest(90))
    }

    // ----- happy path -----

    #[test]
    fn owner_key_is_deterministic_and_binds_nk() {
        let nk: Nk = digest(7);
        assert_eq!(owner_key(&nk), owner_key(&nk));
        let mut nk2 = nk;
        nk2[0] += F::ONE;
        assert_ne!(owner_key(&nk), owner_key(&nk2));
    }

    #[test]
    fn note_commitment_is_deterministic() {
        let (v, owner, rho, r) = sample_note();
        assert_eq!(
            note_commitment(v, &owner, &rho, &r),
            note_commitment(v, &owner, &rho, &r)
        );
    }

    #[test]
    fn note_commitment_changes_when_any_field_changes() {
        let (v, owner, rho, r) = sample_note();
        let base = note_commitment(v, &owner, &rho, &r);
        assert_ne!(base, note_commitment(amount(1_001), &owner, &rho, &r));
        let mut owner2 = owner;
        owner2[0] += F::ONE;
        assert_ne!(base, note_commitment(v, &owner2, &rho, &r));
        let mut rho2 = rho;
        rho2[0] += F::ONE;
        assert_ne!(base, note_commitment(v, &owner, &rho2, &r));
        let mut r2 = r;
        r2[0] += F::ONE;
        assert_ne!(base, note_commitment(v, &owner, &rho, &r2));
    }

    // ----- round-trips -----

    #[test]
    fn amount_roundtrips_through_field() {
        for v in [0u64, 1, 1_000, AMOUNT_BOUND - 1] {
            assert_eq!(amount_to_u64(amount(v)), v);
        }
    }

    // ----- error paths -----

    #[test]
    #[should_panic(expected = "exceeds")]
    fn amount_at_bound_panics() {
        let _ = amount(AMOUNT_BOUND);
    }
}
