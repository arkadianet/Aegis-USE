//! Note commitment (note-protocol.md §1):
//! `note_cm = value·G_value + tag·G_PRF + blinding·H_even` on `E_even`.

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::generators::{g_prf, g_value, h_even, EvenPoint};

/// Scalar field of `E_even` (secp256k1) — value/tag/blinding domain.
pub type EvenScalar = ark_secp256k1::Fr;

/// Provisional consensus wire size of a compressed note commitment
/// (ark-canonical compressed; SEC1-vs-ark pinned at freeze, DEFERRED).
pub const NOTE_CM_BYTES: usize = 33;

/// Pedersen note commitment (§1). `value` is USE base units.
pub fn note_commitment(value: u64, tag: EvenScalar, blinding: EvenScalar) -> EvenPoint {
    (g_value() * EvenScalar::from(value) + g_prf() * tag + h_even() * blinding).into_affine()
}

/// Canonical compressed bytes (ark encoding, provisional — see DEFERRED).
pub fn note_cm_bytes(cm: &EvenPoint) -> [u8; NOTE_CM_BYTES] {
    let mut out = [0u8; NOTE_CM_BYTES];
    cm.serialize_compressed(&mut out[..])
        .expect("33-byte buffer fits compressed secp point");
    out
}

/// Strict decode of a wire note commitment; `None` for bytes that are
/// not a canonical compressed curve point.
pub fn note_cm_from_bytes(bytes: &[u8; NOTE_CM_BYTES]) -> Option<EvenPoint> {
    EvenPoint::deserialize_compressed(&bytes[..]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;

    // ----- helpers -----

    fn scalar(hex_be: &str) -> EvenScalar {
        EvenScalar::from_be_bytes_mod_order(&hex::decode(hex_be).unwrap())
    }

    fn fixed_tag() -> EvenScalar {
        scalar("1111111111111111111111111111111111111111111111111111111111111111")
    }

    fn fixed_blinding() -> EvenScalar {
        scalar("2222222222222222222222222222222222222222222222222222222222222222")
    }

    // ----- happy path -----

    #[test]
    fn note_commitment_is_deterministic() {
        let a = note_commitment(1_000, fixed_tag(), fixed_blinding());
        let b = note_commitment(1_000, fixed_tag(), fixed_blinding());
        assert_eq!(a, b);
    }

    #[test]
    fn note_commitment_changes_when_any_input_changes() {
        let base = note_commitment(1_000, fixed_tag(), fixed_blinding());
        assert_ne!(base, note_commitment(1_001, fixed_tag(), fixed_blinding()));
        assert_ne!(
            base,
            note_commitment(1_000, fixed_blinding(), fixed_blinding())
        );
        assert_ne!(base, note_commitment(1_000, fixed_tag(), fixed_tag()));
    }

    #[test]
    fn zero_value_commitment_is_not_identity() {
        // Dummy outputs are zero-value but still hiding (§6).
        let cm = note_commitment(0, fixed_tag(), fixed_blinding());
        assert!(!cm.is_zero());
    }

    // ----- round-trips -----

    #[test]
    fn note_cm_bytes_is_33_bytes_and_roundtrips() {
        let cm = note_commitment(1_000, fixed_tag(), fixed_blinding());
        let bytes = note_cm_bytes(&cm);
        assert_eq!(note_cm_from_bytes(&bytes), Some(cm));
    }

    // ----- error paths -----

    #[test]
    fn note_cm_from_garbage_bytes_is_none() {
        assert_eq!(note_cm_from_bytes(&[0xEE; NOTE_CM_BYTES]), None);
    }

    // ----- oracle parity -----

    #[test]
    fn note_commitment_matches_independent_reference() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../test-vectors/aegis/generators/v1.json"))
                .unwrap();
        let vec = &v["note_cm_vector"];
        assert_eq!(vec["value"].as_u64().unwrap(), 1_000);
        let expect = EvenPoint::new_unchecked(
            ark_secp256k1::Fq::from_be_bytes_mod_order(
                &hex::decode(vec["cm_x"].as_str().unwrap()).unwrap(),
            ),
            ark_secp256k1::Fq::from_be_bytes_mod_order(
                &hex::decode(vec["cm_y"].as_str().unwrap()).unwrap(),
            ),
        );
        assert!(expect.is_on_curve());
        assert_eq!(
            note_commitment(1_000, fixed_tag(), fixed_blinding()),
            expect
        );
    }
}
