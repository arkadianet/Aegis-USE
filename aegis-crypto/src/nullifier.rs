//! Nullifier derivation (note-protocol.md §3).
//!
//! **The consensus nullifier is [`poseidon_nullifier`] = `Poseidon(nk+rho)`**
//! (the N1 P0 fix — see `crate::spend` module doc and `crate::poseidon`).
//! It is a field element with no free component, so a note yields exactly
//! one nullifier.
//!
//! ⚠ **SUPERSEDED — do NOT use in consensus:** the inverse-tag functions
//! below ([`nullifier`], [`nullifier_point`], [`extract_x`]) were the
//! earlier `Extract([1/(nk+rho)]·G)` form. That point-exposed-via-commit
//! design carried the P0 malleability (blinding-malleable nullifier ⇒
//! double-spend) and is **retired**. They are retained only for their
//! oracle vectors / historical reference; wiring them into the node
//! would mismatch the circuit and make notes unspendable. Full removal
//! is a tracked DEFERRED follow-up.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};

use crate::generators::{g_odd_base, OddPoint};
use crate::h2c::hash_to_field_one;

/// Scalar field of `E_odd` (secq256k1) — nk/rho domain.
pub type OddScalar = ark_secq256k1::Fr;

/// Consensus nullifier size: one x-coordinate, big-endian.
pub const NF_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum NullifierError {
    /// `nk + rho = 0` has no inverse; unreachable adversarially (needs
    /// secret nk) and rejected at mint (note-protocol.md §3, N12).
    #[error("nk + rho = 0: no nullifier exists for this (nk, rho)")]
    ZeroDenominator,
}

/// ⚠ SUPERSEDED (not consensus — see module doc). The retired
/// inverse-tag nullifier point `(nk + rho)^{-1} · G` (§3).
pub fn nullifier_point(nk: OddScalar, rho: OddScalar) -> Result<OddPoint, NullifierError> {
    let inv = (nk + rho)
        .inverse()
        .ok_or(NullifierError::ZeroDenominator)?;
    Ok((g_odd_base() * inv).into_affine())
}

/// Orchard-style `Extract`: the point's x-coordinate as 32 big-endian
/// bytes. `±point` extract identically (the sign-invariance property).
pub fn extract_x(point: &OddPoint) -> [u8; NF_BYTES] {
    let x = point.x().expect("nullifier point is never the identity");
    let mut out = [0u8; NF_BYTES];
    out.copy_from_slice(&x.into_bigint().to_bytes_be());
    out
}

/// ⚠ SUPERSEDED (not consensus — see module doc, use [`poseidon_nullifier`]).
/// The retired inverse-tag nullifier `Extract((nk + rho)^{-1} · G)` (§3).
pub fn nullifier(nk: OddScalar, rho: OddScalar) -> Result<[u8; NF_BYTES], NullifierError> {
    Ok(extract_x(&nullifier_point(nk, rho)?))
}

/// Transfer rho: outputs seed from a nullifier consumed in the same tx,
/// `H_ρ(dst = "aegis:rho:transfer:v1", msg = consumed nf)` (§3).
pub fn rho_transfer(consumed_nf: &[u8; NF_BYTES]) -> OddScalar {
    hash_to_field_one(b"aegis:rho:transfer:v1", consumed_nf)
}

/// Serialize an odd-field nullifier value to 32 big-endian bytes.
pub fn nf_bytes(nf: OddScalar) -> [u8; NF_BYTES] {
    let mut out = [0u8; NF_BYTES];
    out.copy_from_slice(&nf.into_bigint().to_bytes_be());
    out
}

/// The N1 consensus nullifier: `Poseidon(nk + rho)` (production form).
/// A field element determined entirely by the circuit witness — no
/// group element, no blinding, no free component (the P0 malleability
/// class is structurally impossible). See `crate::poseidon` and
/// `dev-docs/sidechain/n1-nullifier-fix-design.md`.
pub fn poseidon_nullifier(nk: OddScalar, rho: OddScalar) -> [u8; NF_BYTES] {
    nf_bytes(crate::poseidon::hash1(nk + rho))
}

/// PegMint rho: `H_ρ(dst = "aegis:rho:pegmint:v1", msg = ergo boxId)` (§3).
pub fn rho_pegmint(ergo_box_id: &[u8; 32]) -> OddScalar {
    hash_to_field_one(b"aegis:rho:pegmint:v1", ergo_box_id)
}

/// Coinbase rho: msg = 8-byte BE height ‖ network-name UTF-8 (§3).
pub fn rho_coinbase(height: u64, network_name: &str) -> OddScalar {
    let mut msg = Vec::with_capacity(8 + network_name.len());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(network_name.as_bytes());
    hash_to_field_one(b"aegis:rho:coinbase:v1", &msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;

    // ----- helpers -----

    fn scalar(hex_be: &str) -> OddScalar {
        OddScalar::from_be_bytes_mod_order(&hex::decode(hex_be).unwrap())
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../test-vectors/aegis/generators/v1.json")).unwrap()
    }

    fn fixed_nk() -> OddScalar {
        scalar("3333333333333333333333333333333333333333333333333333333333333333")
    }

    fn fixed_rho() -> OddScalar {
        scalar("4444444444444444444444444444444444444444444444444444444444444444")
    }

    // ----- happy path -----

    #[test]
    fn nullifier_same_inputs_is_deterministic() {
        assert_eq!(
            nullifier(fixed_nk(), fixed_rho()).unwrap(),
            nullifier(fixed_nk(), fixed_rho()).unwrap()
        );
    }

    #[test]
    fn nullifier_differs_when_rho_differs() {
        let r2 = fixed_rho() + OddScalar::from(1u64);
        assert_ne!(
            nullifier(fixed_nk(), fixed_rho()).unwrap(),
            nullifier(fixed_nk(), r2).unwrap()
        );
    }

    #[test]
    fn rho_pegmint_differs_per_box_id() {
        assert_ne!(rho_pegmint(&[0xAA; 32]), rho_pegmint(&[0xAB; 32]));
    }

    #[test]
    fn rho_coinbase_differs_per_height_and_network() {
        assert_ne!(rho_coinbase(1, "aegis-dev"), rho_coinbase(2, "aegis-dev"));
        assert_ne!(rho_coinbase(1, "aegis-dev"), rho_coinbase(1, "aegis"));
    }

    // ----- round-trips -----

    #[test]
    fn nullifier_is_sign_invariant() {
        // The load-bearing Extract property: witnessing the negated
        // scalar yields the negated point, but the SAME nullifier — a
        // note cannot produce two nullifiers via the ±C ambiguity.
        let plus = nullifier(fixed_nk(), fixed_rho()).unwrap();
        let minus = nullifier(-fixed_nk(), -fixed_rho()).unwrap();
        assert_ne!(
            nullifier_point(fixed_nk(), fixed_rho()).unwrap(),
            nullifier_point(-fixed_nk(), -fixed_rho()).unwrap(),
            "the points differ (±)"
        );
        assert_eq!(plus, minus, "the extracts must not");
    }

    #[test]
    fn nullifier_is_extract_of_nullifier_point() {
        let point = nullifier_point(fixed_nk(), fixed_rho()).unwrap();
        assert_eq!(
            nullifier(fixed_nk(), fixed_rho()).unwrap(),
            extract_x(&point)
        );
    }

    // ----- error paths -----

    #[test]
    fn nullifier_zero_denominator_errors() {
        let rho = -fixed_nk();
        assert!(matches!(
            nullifier(fixed_nk(), rho),
            Err(NullifierError::ZeroDenominator)
        ));
    }

    // ----- oracle parity -----

    #[test]
    fn nullifier_matches_independent_reference() {
        let v = vectors();
        let nv = &v["nullifier_vector"];
        let nk = scalar(nv["nk"].as_str().unwrap());
        let rho = scalar(nv["rho"].as_str().unwrap());
        let expect_point = OddPoint::new_unchecked(
            ark_secq256k1::Fq::from_be_bytes_mod_order(
                &hex::decode(nv["nf_x"].as_str().unwrap()).unwrap(),
            ),
            ark_secq256k1::Fq::from_be_bytes_mod_order(
                &hex::decode(nv["nf_y"].as_str().unwrap()).unwrap(),
            ),
        );
        assert!(expect_point.is_on_curve());
        assert_eq!(nullifier_point(nk, rho).unwrap(), expect_point);
        // The consensus nullifier is the reference vector's nf_x.
        let expect_x: [u8; NF_BYTES] = hex::decode(nv["nf_x"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(nullifier(nk, rho).unwrap(), expect_x);
    }

    #[test]
    fn rho_derivations_match_independent_reference() {
        let v = vectors();
        let rv = &v["rho_vectors"];
        assert_eq!(
            rho_pegmint(&[0xAA; 32]),
            scalar(rv["pegmint_boxid_aa32"].as_str().unwrap())
        );
        assert_eq!(
            rho_coinbase(1, "aegis-dev"),
            scalar(rv["coinbase_h1_aegis_dev"].as_str().unwrap())
        );
        // Transfer chaining: rho from the reference nullifier's extract.
        let nv = &v["nullifier_vector"];
        let nk = scalar(nv["nk"].as_str().unwrap());
        let rho = scalar(nv["rho"].as_str().unwrap());
        let nf = nullifier(nk, rho).unwrap();
        assert_eq!(
            rho_transfer(&nf),
            scalar(rv["transfer_from_nf_x"].as_str().unwrap())
        );
    }
}
