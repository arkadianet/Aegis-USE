//! Pinned NUMS generators (note-protocol.md §0).
//!
//! Derivation convention (consensus-pinned): each generator is
//! `hash_to_curve(dst = full domain tag, msg = "")` with the RFC 9380
//! SvdW/XMD-SHA-256 pipeline from `h2c`. Any change to seed, tags, map,
//! or this convention is chain-id-breaking. The committed vectors in
//! `test-vectors/aegis/generators/v1.json` come from an independent
//! Python reference implementation — the tests here prove parity.

use std::sync::OnceLock;

use crate::h2c::hash_to_curve;

/// Published nothing-up-my-sleeve seed (note-protocol.md §0).
pub const GEN_SEED: &str = "aegis:gen:v1";

pub type EvenPoint = ark_secp256k1::Affine;
pub type OddPoint = ark_secq256k1::Affine;

macro_rules! even_gen {
    ($(#[$doc:meta])* $fn_name:ident, $static_name:ident, $dst:literal) => {
        $(#[$doc])*
        pub fn $fn_name() -> EvenPoint {
            static $static_name: OnceLock<EvenPoint> = OnceLock::new();
            *$static_name.get_or_init(|| hash_to_curve::<ark_secp256k1::Config>($dst, b""))
        }
    };
}

macro_rules! odd_gen {
    ($(#[$doc:meta])* $fn_name:ident, $static_name:ident, $dst:literal) => {
        $(#[$doc])*
        pub fn $fn_name() -> OddPoint {
            static $static_name: OnceLock<OddPoint> = OnceLock::new();
            *$static_name.get_or_init(|| hash_to_curve::<ark_secq256k1::Config>($dst, b""))
        }
    };
}

even_gen!(
    /// Value slot of the note commitment (§1).
    g_value, G_VALUE, b"aegis:gen:v1:G_value"
);
even_gen!(
    /// Tag slot of the note commitment (§1).
    g_prf, G_PRF, b"aegis:gen:v1:G_PRF"
);
even_gen!(
    /// Blinding base of the note commitment (§1).
    h_even, H_EVEN, b"aegis:gen:v1:H_even"
);
even_gen!(
    /// Provably-unopenable empty-leaf filler (§7, N10).
    empty_leaf, EMPTY_LEAF, b"aegis:empty-leaf:v1"
);
odd_gen!(
    /// Nullifier base point `G` (§3).
    g_odd_base, G_ODD, b"aegis:gen:v1:G"
);
odd_gen!(
    /// Second independent odd-curve base (§0).
    h_odd, H_ODD, b"aegis:gen:v1:H_odd"
);

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;

    // ----- helpers -----

    fn vectors() -> serde_json::Value {
        let raw = include_str!("../../test-vectors/aegis/generators/v1.json");
        serde_json::from_str(raw).expect("valid vectors json")
    }

    fn vector_point(v: &serde_json::Value, name: &str) -> (Vec<u8>, Vec<u8>) {
        let g = v["generators"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["name"] == name)
            .unwrap_or_else(|| panic!("vector {name} missing"));
        (
            hex::decode(g["x"].as_str().unwrap()).unwrap(),
            hex::decode(g["y"].as_str().unwrap()).unwrap(),
        )
    }

    fn assert_even_matches(p: EvenPoint, name: &str) {
        let (x, y) = vector_point(&vectors(), name);
        let expect = EvenPoint::new_unchecked(
            ark_secp256k1::Fq::from_be_bytes_mod_order(&x),
            ark_secp256k1::Fq::from_be_bytes_mod_order(&y),
        );
        assert!(expect.is_on_curve(), "{name} vector not on curve");
        assert_eq!(p, expect, "{name} mismatch vs independent reference");
    }

    fn assert_odd_matches(p: OddPoint, name: &str) {
        let (x, y) = vector_point(&vectors(), name);
        let expect = OddPoint::new_unchecked(
            ark_secq256k1::Fq::from_be_bytes_mod_order(&x),
            ark_secq256k1::Fq::from_be_bytes_mod_order(&y),
        );
        assert!(expect.is_on_curve(), "{name} vector not on curve");
        assert_eq!(p, expect, "{name} mismatch vs independent reference");
    }

    // ----- happy path -----

    #[test]
    fn generators_are_pairwise_distinct_and_nonidentity() {
        let evens = [g_value(), g_prf(), h_even(), empty_leaf()];
        for (i, a) in evens.iter().enumerate() {
            assert!(!a.is_zero());
            for b in &evens[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert!(!g_odd_base().is_zero());
        assert!(!h_odd().is_zero());
        assert_ne!(g_odd_base(), h_odd());
    }

    // ----- oracle parity -----

    #[test]
    fn even_generators_match_independent_reference() {
        assert_even_matches(g_value(), "G_value");
        assert_even_matches(g_prf(), "G_PRF");
        assert_even_matches(h_even(), "H_even");
        assert_even_matches(empty_leaf(), "empty_leaf");
    }

    #[test]
    fn odd_generators_match_independent_reference() {
        assert_odd_matches(g_odd_base(), "G");
        assert_odd_matches(h_odd(), "H_odd");
    }
}
