//! Peg-out BURN note derivation — consensus-shared between wallet (builds the
//! burn output), node (validates it), and settlement guest (proves it).
//!
//! A peg-out spends shielded notes into a note committed to an owner with NO
//! known `nk` preimage (`owner = H(nk)` in the circuit), so no nullifier can
//! ever be derived: the value is provably dead on the hn side, backing the
//! public withdrawal the vault releases on Ergo.
//!
//! # Recipient binding (D1 — security-critical)
//! The nonces derive from the spend's first nullifier — unique forever — AND
//! from the withdrawal's `(recipient_prop, amount)`:
//!
//! ```text
//! bind = H(DOMAIN_BURN_BIND, bytes(recipient_prop) ‖ value_limbs(amount))
//! rho  = H(DOMAIN_BURN_RHO,  nf0 ‖ bind)
//! r    = H(DOMAIN_BURN_R,    nf0 ‖ bind)
//! ```
//!
//! so the burn commitment is only reproducible with the CORRECT recipient and
//! amount. Without this, a permissionless settler could prove a victim's real
//! pending withdrawal with their OWN address as recipient and be paid by the
//! vault (`recipient_prop` is a prover-supplied guest input journaled
//! verbatim); with it, a wrong recipient makes the guest's recomputed burn
//! commitment mismatch the spend's out0 and the settlement proof fails. The
//! same recomputation rejects a mismatched peg-out at node admission and at
//! block validation, so a recorded withdrawal is always bound into its burn.
//!
//! ## Packing injectivity (why these limb widths)
//! `bind`'s preimage packs one BYTE per field element (each `< 2^8`) followed
//! by the amount as the engine's canonical 4×16-bit limbs
//! ([`crate::commit::value_limbs`], each `< 2^16`). Every limb is far below
//! the BabyBear modulus, so limb → element is lossless — 32-bit limbs would
//! NOT be (p ≈ 2^31 < 2^32, two u32s can collide mod p). The sponge binds the
//! total input length ([`hash_domain`]) and the amount occupies a fixed
//! 4-limb suffix, so `recipient_prop.len()` is determined by the length and
//! the `(recipient_prop, amount) → preimage` map is injective. The domain tag
//! separates `bind` from every other sponge use.
//!
//! Validators recompute the exact commitment from public data alone
//! (`nf0` + the public withdrawal record).

use crate::commit::{note_commitment, value_limbs, N_LIMBS};
use crate::poseidon::{hash_domain, Digest, DIGEST_ELEMS, F};
use p3_field::PrimeCharacteristicRing;

const DOMAIN_BURN_OWNER: u32 = 0x0BDE;
const DOMAIN_BURN_RHO: u32 = 0x0BD1;
const DOMAIN_BURN_R: u32 = 0x0BD2;
/// D1 recipient binding `H_p(recipient_prop ‖ amount)` (module doc).
const DOMAIN_BURN_BIND: u32 = 0x0BD3;

/// The burn owner: a nothing-up-my-sleeve digest with no known `nk` preimage.
pub fn burn_owner() -> Digest {
    let tag: Vec<F> = b"aegis-hn-burn-v1"
        .iter()
        .map(|b| F::from_u32(*b as u32))
        .collect();
    hash_domain(DOMAIN_BURN_OWNER, &tag)
}

/// The D1 binding digest of a withdrawal's `(recipient_prop, amount)` —
/// in-field Poseidon2 packing, one byte per element + canonical 16-bit value
/// limbs (injective; see module doc).
pub fn burn_binding(recipient_prop: &[u8], amount: u64) -> Digest {
    let mut input: Vec<F> = Vec::with_capacity(recipient_prop.len() + N_LIMBS);
    input.extend(recipient_prop.iter().map(|&b| F::from_u32(b as u32)));
    input.extend_from_slice(&value_limbs(amount));
    hash_domain(DOMAIN_BURN_BIND, &input)
}

/// The `(rho, r)` of the burn note for a spend whose first nullifier is `nf0`,
/// bound to the withdrawal's `(recipient_prop, amount)` (D1).
pub fn burn_nonces(nf0: &Digest, recipient_prop: &[u8], amount: u64) -> (Digest, Digest) {
    let bind = burn_binding(recipient_prop, amount);
    let mut input = [F::ZERO; 2 * DIGEST_ELEMS];
    input[..DIGEST_ELEMS].copy_from_slice(nf0);
    input[DIGEST_ELEMS..].copy_from_slice(&bind);
    (
        hash_domain(DOMAIN_BURN_RHO, &input),
        hash_domain(DOMAIN_BURN_R, &input),
    )
}

/// The commitment the burn note MUST have (validators and the settlement
/// guest recompute this): value `burn_value` (= amount + peg fee), unspendable
/// owner, nonces bound to `(nf0, recipient_prop, amount)`.
pub fn burn_cm_expected(
    burn_value: u64,
    nf0: &Digest,
    recipient_prop: &[u8],
    amount: u64,
) -> Digest {
    let (rho, r) = burn_nonces(nf0, recipient_prop, amount);
    note_commitment(burn_value, &burn_owner(), &rho, &r)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn nf(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    // ----- happy path -----

    #[test]
    fn burn_cm_is_deterministic_and_nf_bound() {
        let recipient = [0xAA; 36];
        assert_eq!(
            burn_cm_expected(100, &nf(7), &recipient, 99),
            burn_cm_expected(100, &nf(7), &recipient, 99)
        );
        assert_ne!(
            burn_cm_expected(100, &nf(7), &recipient, 99),
            burn_cm_expected(101, &nf(7), &recipient, 99)
        );
        assert_ne!(
            burn_cm_expected(100, &nf(7), &recipient, 99),
            burn_cm_expected(100, &nf(9), &recipient, 99)
        );
    }

    // ----- error paths (the D1 attack surface) -----

    #[test]
    fn burn_cm_wrong_recipient_mismatches() {
        // THE D1 theft vector: a burn created for the victim's recipient must
        // not be reproducible with the attacker's — same nf0, same amounts.
        let victim = vec![0xAA; 36];
        let mut attacker = victim.clone();
        attacker[10] ^= 0x01; // minimal redirect: one bit of the ErgoTree
        assert_ne!(
            burn_cm_expected(100, &nf(7), &victim, 99),
            burn_cm_expected(100, &nf(7), &attacker, 99),
            "a redirected recipient must change the burn commitment"
        );
    }

    #[test]
    fn burn_cm_wrong_withdrawal_amount_mismatches() {
        // Same burn_value, different CLAIMED withdrawal amount → mismatch.
        let recipient = [0xAA; 36];
        assert_ne!(
            burn_cm_expected(100, &nf(7), &recipient, 99),
            burn_cm_expected(100, &nf(7), &recipient, 98)
        );
    }

    #[test]
    fn burn_binding_prop_amount_split_is_unambiguous() {
        // Injectivity at the prop/amount boundary: shifting content between
        // the recipient bytes and the amount limbs must not collide (the
        // sponge's length binding + the fixed 4-limb amount suffix).
        // [1,2,3,4] ‖ limbs(0) packs [1,2,3,4,0,0,0,0]; [1,2] ‖ limbs(3+4·2^16)
        // packs [1,2,3,4,0,0] — same prefix, different lengths.
        let a = burn_binding(&[1, 2, 3, 4], 0);
        let b = burn_binding(&[1, 2], 3 + (4 << 16));
        assert_ne!(a, b, "prop/amount boundary must be length-bound");
    }

    #[test]
    fn burn_binding_empty_prop_still_binds_amount() {
        assert_ne!(burn_binding(&[], 1), burn_binding(&[], 2));
    }
}
