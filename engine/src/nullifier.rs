//! Nullifier `nf = H_NF(nk ‖ rho)` — the N1 scheme re-expressed over BabyBear.
//!
//! # Carry-over and the re-derivation soundness argument (REVIEW ITEM)
//! The reviewed N1 *scheme* — a nullifier that is a pure hash of the note's key
//! material, with no group element, no blinding, and no free component — carries
//! over from the current engine (`aegis-crypto::nullifier::poseidon_nullifier`).
//! Its *soundness in this circuit* must be re-argued, because the input shape
//! changed from the pinned sum `Poseidon(nk + rho)` to the pair `H(nk ‖ rho)`.
//!
//! **The argument.** In the spend circuit the nullifier is bound to the SAME
//! `nk` and `rho` that define the note being spent:
//! - `rho` is an input to the note commitment `cm = H_CM(value ‖ owner ‖ rho ‖ r)`
//!   ([`crate::commit`]), and the circuit proves `cm` is a member of the
//!   accumulator — so `rho` is pinned by the note.
//! - `nk` is pinned by `owner = H_OWNER(nk)`, itself an input to that same `cm`.
//!
//! So both `nk` and `rho` are determined by the (unique) note; the prover has no
//! freedom to present a different `(nk, rho)` and mint a second nullifier for one
//! note. One note ⇒ exactly one `nf`. Unlike the retired `Poseidon(nk + rho)`
//! form, there is no additive re-split (`nk' = nk + δ`, `rho' = rho − δ`) that
//! preserves a sum, because `nf` here is not a function of a sum — but note the
//! collision/preimage security of `H_NF` on the concatenation is exactly what
//! must be reviewed (the one bounded parameter/round-count review item).

use crate::commit::{Nk, Rho};
use crate::poseidon::{hash_domain, Digest, DIGEST_ELEMS, DOMAIN_NULLIFIER};

/// The two rate-8 sponge blocks of a nullifier, in absorption order: `nk`, `rho`.
pub fn nullifier_blocks(nk: &Nk, rho: &Rho) -> [[crate::poseidon::F; DIGEST_ELEMS]; 2] {
    [*nk, *rho]
}

/// Nullifier `nf = H_NF(nk ‖ rho)` (16 field elements → 2 permutations).
pub fn nullifier(nk: &Nk, rho: &Rho) -> Digest {
    hash_domain(DOMAIN_NULLIFIER, &nullifier_blocks(nk, rho).concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    // ----- helpers -----

    fn digest(base: u32) -> Digest {
        core::array::from_fn(|i| crate::poseidon::F::from_u32(base + i as u32))
    }

    // ----- happy path -----

    #[test]
    fn nullifier_is_deterministic() {
        let (nk, rho) = (digest(1), digest(9));
        assert_eq!(nullifier(&nk, &rho), nullifier(&nk, &rho));
    }

    #[test]
    fn nullifier_differs_when_nk_differs() {
        let rho = digest(9);
        let mut nk2 = digest(1);
        nk2[0] += crate::poseidon::F::ONE;
        assert_ne!(nullifier(&digest(1), &rho), nullifier(&nk2, &rho));
    }

    #[test]
    fn nullifier_differs_when_rho_differs() {
        let nk = digest(1);
        let mut rho2 = digest(9);
        rho2[3] += crate::poseidon::F::ONE;
        assert_ne!(nullifier(&nk, &digest(9)), nullifier(&nk, &rho2));
    }

    #[test]
    fn nullifier_is_not_symmetric_in_nk_rho() {
        // H(nk ‖ rho) must differ from H(rho ‖ nk): swapping key and nonce is a
        // different note, not the same nullifier.
        let a = digest(1);
        let b = digest(9);
        assert_ne!(nullifier(&a, &b), nullifier(&b, &a));
    }
}
