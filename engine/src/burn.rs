//! Peg-out BURN note derivation — consensus-shared between wallet (builds the
//! burn output) and node (validates it).
//!
//! A peg-out spends shielded notes into a note committed to an owner with NO
//! known `nk` preimage (`owner = H(nk)` in the circuit), so no nullifier can
//! ever be derived: the value is provably dead on the hn side, backing the
//! public withdrawal the vault releases on Ergo. The nonces derive from the
//! spend's first nullifier — unique forever — so validators recompute the
//! exact commitment from public data alone.

use crate::commit::note_commitment;
use crate::poseidon::{hash_domain, Digest, F};
use p3_field::PrimeCharacteristicRing;

const DOMAIN_BURN_OWNER: u32 = 0x0BDE;
const DOMAIN_BURN_RHO: u32 = 0x0BD1;
const DOMAIN_BURN_R: u32 = 0x0BD2;

/// The burn owner: a nothing-up-my-sleeve digest with no known `nk` preimage.
pub fn burn_owner() -> Digest {
    let tag: Vec<F> = b"aegis-hn-burn-v1"
        .iter()
        .map(|b| F::from_u32(*b as u32))
        .collect();
    hash_domain(DOMAIN_BURN_OWNER, &tag)
}

/// The `(rho, r)` of the burn note for a spend whose first nullifier is `nf0`.
pub fn burn_nonces(nf0: &Digest) -> (Digest, Digest) {
    (
        hash_domain(DOMAIN_BURN_RHO, nf0),
        hash_domain(DOMAIN_BURN_R, nf0),
    )
}

/// The commitment the burn note MUST have (validators recompute this).
pub fn burn_cm_expected(burn_value: u64, nf0: &Digest) -> Digest {
    let (rho, r) = burn_nonces(nf0);
    note_commitment(burn_value, &burn_owner(), &rho, &r)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn burn_cm_is_deterministic_and_nf_bound() {
        let nf: Digest = core::array::from_fn(|i| F::from_u32(7 + i as u32));
        let nf2: Digest = core::array::from_fn(|i| F::from_u32(9 + i as u32));
        assert_eq!(burn_cm_expected(100, &nf), burn_cm_expected(100, &nf));
        assert_ne!(burn_cm_expected(100, &nf), burn_cm_expected(101, &nf));
        assert_ne!(burn_cm_expected(100, &nf), burn_cm_expected(100, &nf2));
    }
}
