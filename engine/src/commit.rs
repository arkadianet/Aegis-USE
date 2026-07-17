//! Note commitment and owner key (hash-native — NO elliptic curve).
//!
//! # Pinned layouts (chain-id-breaking; REVIEW ITEMS)
//! A note is `(value, owner, rho, r)`:
//! - `value`  — a full `u64` amount, represented as **4 little-endian 16-bit
//!   limbs** (see below).
//! - `owner`  — the recipient's owner key, a digest `owner = H(nk)`. This is the
//!   hash-based replacement for the elliptic-curve `pk = nk·B`; the spender
//!   proves knowledge of the `nk` whose hash is the note's `owner`.
//! - `rho`    — a per-note nonce digest (uniqueness; nullifier input).
//! - `r`      — a blinding digest (hides `value`/`owner` in `cm`).
//!
//! **Commitment (v2 layout, domain `0x0A13`):**
//! `cm = H_CM(value_block ‖ owner ‖ rho ‖ r)` — a domain-separated Poseidon2
//! sponge over four component-aligned rate-8 blocks (32 field elements → 4
//! permutations), where `value_block = [v0, v1, v2, v3, 0, 0, 0, 0]` and
//! `value = Σ v_j·2^(16·j)` with each `v_j < 2^16`.
//!
//! **Owner key:** `owner = H_OWNER(nk)` — one permutation.
//!
//! ## Why 4×16-bit limbs (the 64-bit representation — soundness)
//! BabyBear is a ~31-bit field: a single element cannot hold a `u64`, and a
//! multi-term balance sum must not wrap the modulus. The amount is therefore 4
//! LE limbs of 16 bits:
//! - **byte-aligned**: each limb is exactly 2 bytes of the `u64` LE wire the
//!   note ciphertext already carries — the wire↔limb map is trivial and
//!   bijective (no second wire form);
//! - **uniform width**: no special last limb, so the circuit's per-limb range
//!   check and carry chain are uniform (a 3×22/20-bit split saves one carry but
//!   costs an irregular last limb; the total range-bit count is 64 either way);
//! - **small carries**: with 2 inputs vs 3 output-terms per limb, the balance
//!   carries stay in `{-2..1}` (2 bits) — see [`crate::spend::balance_air`].
//!
//! **Canonicity (malleability):** `u64 ↔ limbs` is bijective ON canonical limbs
//! (`v_j < 2^16`). A non-canonical limb (e.g. `[2^16, v1-1, ..]`) would be a
//! second `cm` preimage "for the same value" — so limbs are range-checked
//! in-circuit wherever a note is CREATED (outputs/fee in the spend; coinbase and
//! peg-mint at the node), and wallet-side parsers only ever construct limbs via
//! [`value_limbs`] from a `u64` (bijective by construction). Spent inputs
//! inherit canonicity from their creation-time check through the `cm` binding
//! (the accumulator's note-conservation invariant).

use p3_field::{PrimeCharacteristicRing, PrimeField32};

use crate::poseidon::{hash_domain, Digest, DIGEST_ELEMS, DOMAIN_COMMITMENT, DOMAIN_OWNER, F};

/// Bits per value limb.
pub const LIMB_BITS: usize = 16;
/// Limbs per `u64` amount.
pub const N_LIMBS: usize = 4;
/// Exclusive upper bound of a canonical limb: `2^LIMB_BITS`.
pub const LIMB_BOUND: u64 = 1 << LIMB_BITS;

/// A spending/nullifier key `nk`: 8 limbs (~248-bit).
pub type Nk = [F; DIGEST_ELEMS];
/// A per-note nonce `rho`: 8 limbs.
pub type Rho = [F; DIGEST_ELEMS];
/// A blinding factor `r`: 8 limbs.
pub type Blinding = [F; DIGEST_ELEMS];
/// A 64-bit amount as 4 canonical little-endian 16-bit limbs.
pub type ValueLimbs = [F; N_LIMBS];

/// Encode a `u64` amount as its canonical 4×16-bit LE limbs (bijective).
pub fn value_limbs(value: u64) -> ValueLimbs {
    core::array::from_fn(|j| F::from_u64((value >> (LIMB_BITS * j)) & (LIMB_BOUND - 1)))
}

/// Recover the `u64` from canonical limbs.
///
/// # Panics
/// If any limb is non-canonical (≥ 2^16) — limbs must only ever be built via
/// [`value_limbs`] or validated in-circuit before reaching this.
pub fn limbs_to_u64(limbs: &ValueLimbs) -> u64 {
    limbs.iter().enumerate().fold(0u64, |acc, (j, limb)| {
        let v = limb.as_canonical_u32() as u64;
        assert!(v < LIMB_BOUND, "non-canonical value limb");
        acc | (v << (LIMB_BITS * j))
    })
}

/// Owner key `owner = H_OWNER(nk)` — the hash-based public key (no `nk·B`).
pub fn owner_key(nk: &Nk) -> Digest {
    hash_domain(DOMAIN_OWNER, nk)
}

/// The four rate-8 sponge blocks of a note commitment, in absorption order:
/// `[v0..v3 ‖ 0×4]`, `owner`, `rho`, `r`. Component-aligned (one component per
/// block) so the in-circuit sponge chain ([`crate::spend`]) absorbs exactly one
/// component per row — no component straddles a block boundary.
pub fn commitment_blocks(
    value: u64,
    owner: &Digest,
    rho: &Rho,
    r: &Blinding,
) -> [[F; DIGEST_ELEMS]; 4] {
    let mut value_block = [F::ZERO; DIGEST_ELEMS];
    value_block[..N_LIMBS].copy_from_slice(&value_limbs(value));
    [value_block, *owner, *rho, *r]
}

/// Note commitment `cm = H_CM(value_block ‖ owner ‖ rho ‖ r)` (v2 layout — see
/// module doc).
pub fn note_commitment(value: u64, owner: &Digest, rho: &Rho, r: &Blinding) -> Digest {
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

    fn sample_note() -> (u64, Digest, Rho, Blinding) {
        let nk: Nk = digest(1);
        (1_000, owner_key(&nk), digest(50), digest(90))
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
        assert_ne!(base, note_commitment(1_001, &owner, &rho, &r));
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

    #[test]
    fn full_u64_amounts_commit_distinctly() {
        // The whole point of the limb change: values beyond 2^28 (and up to
        // u64::MAX) are first-class.
        let (_, owner, rho, r) = sample_note();
        let big = note_commitment(u64::MAX, &owner, &rho, &r);
        assert_ne!(big, note_commitment(u64::MAX - 1, &owner, &rho, &r));
        // Limb boundary: 2^16 and 2^32 differ from their neighbors.
        assert_ne!(
            note_commitment(1 << 16, &owner, &rho, &r),
            note_commitment((1 << 16) - 1, &owner, &rho, &r)
        );
        assert_ne!(
            note_commitment(1 << 32, &owner, &rho, &r),
            note_commitment((1 << 32) - 1, &owner, &rho, &r)
        );
    }

    // ----- round-trips -----

    #[test]
    fn value_limbs_roundtrip_and_are_canonical() {
        for v in [0u64, 1, 1_000, 0xFFFF, 0x1_0000, u64::MAX - 1, u64::MAX] {
            let limbs = value_limbs(v);
            for limb in &limbs {
                assert!((limb.as_canonical_u32() as u64) < LIMB_BOUND);
            }
            assert_eq!(limbs_to_u64(&limbs), v);
        }
    }

    // ----- error paths -----

    #[test]
    #[should_panic(expected = "non-canonical")]
    fn non_canonical_limb_panics_on_decode() {
        let mut limbs = value_limbs(5);
        limbs[0] = F::from_u64(LIMB_BOUND); // 2^16: same value, second encoding
        let _ = limbs_to_u64(&limbs);
    }
}
