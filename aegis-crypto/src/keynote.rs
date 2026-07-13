//! Two-tier key-note binding (G2-P3 slice S2a — native layer).
//!
//! ⚠ **The `nf` half here is SUPERSEDED** — the consensus nullifier is
//! `Poseidon(nk+rho)` (see `crate::nullifier::poseidon_nullifier` and the
//! N1 P0 fix). `tag_and_nullifier` below still returns the retired
//! inverse-tag `Extract((nk+rho)^{-1}·G)` form and must NOT be used for
//! consensus nullifiers; it is kept for reference/vectors. The **tag**
//! derivation remains a freeze-time reference (`note_tag`).
//!
//! A note's **tag** (the §1 `G_PRF` slot) is the x-coordinate of an
//! `E_odd` **key commitment** `C = (nk + rho)·G + r_key·H_odd`. This
//! module derives the `(tag, nf)` pair natively; the in-circuit gadget
//! that proves the linkage without revealing `C` is slice S2b.
//!
//! ## Why the ±C ambiguity is harmless here (S2a resolution, rev 2)
//! A tag is only an x-coordinate, so a prover may witness either of
//! `{C, −C}` (opening to `±(nk + rho)`), deriving `±nullifier_point`.
//! Both x-only quantities are **sign-invariant by construction**: the
//! tag is an x-coordinate, and the consensus nullifier is the Orchard
//! `Extract` (x-coordinate) of the nullifier point — so both sign
//! choices collapse to the same `(tag, nf)` with zero circuit
//! constraints. (An earlier revision canonicalized `C` by `sgn0(y)` and
//! planned an in-circuit parity constraint — superseded: x-extraction
//! achieves the same uniqueness for free.) External review certifies
//! the composed circuit including this argument.

use ark_ec::{AffineRepr, CurveGroup};

use crate::generators::{g_odd_base, h_odd, OddPoint};
use crate::note::EvenScalar;
use crate::nullifier::{nullifier, NullifierError, OddScalar, NF_BYTES};

/// The `E_odd` key commitment `C = (nk + rho)·G + r_key·H_odd`. The
/// identity cannot arise from a hidden `nk + rho` (needs secret `nk`)
/// and is rejected at mint (N12).
pub fn key_commitment(nk: OddScalar, rho: OddScalar, r_key: OddScalar) -> OddPoint {
    (g_odd_base() * (nk + rho) + h_odd() * r_key).into_affine()
}

/// Note tag: the x-coordinate of the key commitment. Lives in `E_odd`'s
/// base field, which is `E_even`'s scalar field — i.e. an
/// [`EvenScalar`], exactly the §1 `G_PRF` slot. Sign-invariant: `±C`
/// share it.
pub fn note_tag(nk: OddScalar, rho: OddScalar, r_key: OddScalar) -> EvenScalar {
    *key_commitment(nk, rho, r_key)
        .x()
        .expect("key commitment is never the identity")
}

/// The `(tag, nf)` pair for a note: the §1 tag slot and its §3
/// consensus nullifier. Both are x-only, so both are independent of
/// which sign representation a prover picks.
pub fn tag_and_nullifier(
    nk: OddScalar,
    rho: OddScalar,
    r_key: OddScalar,
) -> Result<(EvenScalar, [u8; NF_BYTES]), NullifierError> {
    Ok((note_tag(nk, rho, r_key), nullifier(nk, rho)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;

    // ----- helpers -----

    fn odd(hex_be: &str) -> OddScalar {
        OddScalar::from_be_bytes_mod_order(&hex::decode(hex_be).unwrap())
    }

    fn nk() -> OddScalar {
        odd("3333333333333333333333333333333333333333333333333333333333333333")
    }

    fn rho() -> OddScalar {
        odd("4444444444444444444444444444444444444444444444444444444444444444")
    }

    fn r_key() -> OddScalar {
        odd("5555555555555555555555555555555555555555555555555555555555555555")
    }

    // ----- happy path -----

    #[test]
    fn tag_and_nullifier_is_deterministic() {
        let a = tag_and_nullifier(nk(), rho(), r_key()).unwrap();
        let b = tag_and_nullifier(nk(), rho(), r_key()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn key_commitment_is_on_curve_and_hiding_in_r_key() {
        let c = key_commitment(nk(), rho(), r_key());
        assert!(c.is_on_curve());
        assert!(!c.is_zero());
        let c2 = key_commitment(nk(), rho(), r_key() + OddScalar::from(1u64));
        assert_ne!(c, c2, "r_key must blind the key commitment");
    }

    #[test]
    fn distinct_rho_gives_distinct_tag_and_nullifier() {
        // Structural uniqueness (§3): a fresh rho moves both the tag and
        // the nullifier.
        let (t0, nf0) = tag_and_nullifier(nk(), rho(), r_key()).unwrap();
        let (t1, nf1) = tag_and_nullifier(nk(), rho() + OddScalar::from(1u64), r_key()).unwrap();
        assert_ne!(t0, t1);
        assert_ne!(nf0, nf1);
    }

    #[test]
    fn tag_matches_between_helpers() {
        let tag = note_tag(nk(), rho(), r_key());
        let (tag2, _) = tag_and_nullifier(nk(), rho(), r_key()).unwrap();
        assert_eq!(tag, tag2);
    }

    // ----- error paths / adversarial -----

    #[test]
    fn sign_flipped_representation_yields_identical_tag_and_nullifier() {
        // THE ±C soundness test. The negated opening (−nk, −rho, −r_key)
        // builds −C — same x (same tag) — and derives the negated
        // nullifier point. x-extraction must collapse both to the SAME
        // (tag, nf): a note cannot be double-spent under two signs.
        let canonical = tag_and_nullifier(nk(), rho(), r_key()).unwrap();
        let flipped = tag_and_nullifier(-nk(), -rho(), -r_key()).unwrap();
        assert_eq!(
            canonical, flipped,
            "±C representations must collapse to one (tag, nf)"
        );
        // And the underlying points really are distinct (± pair), so
        // the collapse is doing work:
        assert_eq!(
            key_commitment(nk(), rho(), r_key()),
            -key_commitment(-nk(), -rho(), -r_key()),
        );
    }
}
