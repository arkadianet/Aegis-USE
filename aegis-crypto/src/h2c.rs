//! RFC 9380 hash-to-curve building blocks (note-protocol.md §0).
//!
//! `expand_message_xmd` and `hash_to_field` are implemented here rather
//! than via ark-ff's `DefaultFieldHasher`: ark-ff 0.4.2's `ExpanderXmd`
//! pads with `Z_pad = len_per_base_elem` (48 bytes for 256-bit fields)
//! where RFC 9380 §5.3.1 requires `Z_pad = s_in_bytes` (64 for SHA-256)
//! — a deviation invisible on BLS12-381 (L = 64 there) but wrong for
//! our cycle fields. Both functions are oracle-checked against the
//! official RFC 9380 Appendix K.1 and J.8.1 vectors below.

use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, LegendreSymbol, One, PrimeField, Zero};
use sha2::{Digest, Sha256};

/// RFC 9380 §5.2: bytes per field element for k = 128 and a ≤256-bit
/// prime: L = ceil((256 + 128) / 8).
const L: usize = 48;

/// RFC 9380 §5.3.1 expand_message_xmd with SHA-256.
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    assert!(dst.len() <= 255, "DST longer than 255 bytes");
    assert!(len_in_bytes < (1 << 16), "output length exceeds 2^16 - 1");
    let ell = len_in_bytes.div_ceil(32);
    assert!(ell <= 255, "requested output needs more than 255 blocks");
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    let mut h = Sha256::new();
    h.update([0u8; 64]); // Z_pad = s_in_bytes(SHA-256) = 64
    h.update(msg);
    h.update((len_in_bytes as u16).to_be_bytes());
    h.update([0u8]);
    h.update(&dst_prime);
    let b0 = h.finalize();

    let mut h = Sha256::new();
    h.update(b0);
    h.update([1u8]);
    h.update(&dst_prime);
    let mut bi = h.finalize();

    let mut out = bi.to_vec();
    for i in 2..=ell {
        let xored: Vec<u8> = b0.iter().zip(bi.iter()).map(|(l, r)| l ^ r).collect();
        let mut h = Sha256::new();
        h.update(&xored);
        h.update([i as u8]);
        h.update(&dst_prime);
        bi = h.finalize();
        out.extend_from_slice(&bi);
    }
    out.truncate(len_in_bytes);
    out
}

fn hash_to_field<F: PrimeField>(dst: &[u8], msg: &[u8], count: usize) -> Vec<F> {
    assert!(
        F::MODULUS_BIT_SIZE <= 256,
        "L = 48 is sized for ≤256-bit fields (k = 128)"
    );
    let uniform = expand_message_xmd(msg, dst, count * L);
    (0..count)
        .map(|i| F::from_be_bytes_mod_order(&uniform[i * L..(i + 1) * L]))
        .collect()
}

/// RFC 9380 hash_to_field, XMD/SHA-256, security parameter k = 128:
/// two field elements (the hash_to_curve input pair).
pub fn hash_to_field_two<F: PrimeField>(dst: &[u8], msg: &[u8]) -> [F; 2] {
    let v = hash_to_field(dst, msg, 2);
    [v[0], v[1]]
}

/// RFC 9380 hash_to_field, one element (`H_ρ`-style scalar derivation).
pub fn hash_to_field_one<F: PrimeField>(dst: &[u8], msg: &[u8]) -> F {
    hash_to_field(dst, msg, 1)[0]
}

/// RFC 9380 §5.4.1 sgn0 for prime fields: parity of the canonical repr.
fn sgn0<F: PrimeField>(x: &F) -> bool {
    x.into_bigint().is_odd()
}

/// RFC 9380 is_square: true for 0 and quadratic residues.
fn is_square<F: Field>(x: &F) -> bool {
    x.is_zero() || x.legendre() == LegendreSymbol::QuadraticResidue
}

/// inv0: field inverse extended with inv0(0) = 0 (RFC 9380 §4).
fn inv0<F: Field>(x: F) -> F {
    x.inverse().unwrap_or_else(F::zero)
}

/// Shallue–van de Woestijne map (RFC 9380 §6.6.1) for short-Weierstrass
/// curves; used on secp256k1 and secq256k1 (a=0, b=7, cofactor 1 — the
/// note-protocol.md §0 pinned map: one map for both cycle curves, no
/// isogeny, no cofactor clearing). NOT constant-time — adequate for
/// offline generator derivation; the runtime diversifier map revisits
/// this (DEFERRED.md).
pub struct SvdwMap<C: SWCurveConfig> {
    z: C::BaseField,
    c1: C::BaseField,
    c2: C::BaseField,
    c3: C::BaseField,
    c4: C::BaseField,
}

impl<C: SWCurveConfig> SvdwMap<C>
where
    C::BaseField: PrimeField,
{
    /// g(x) = x³ + A·x + B — the curve's Weierstrass RHS.
    fn g(x: C::BaseField) -> C::BaseField {
        (x.square() + C::COEFF_A) * x + C::COEFF_B
    }

    /// find_z_svdw per RFC 9380 Appendix H.1.
    fn find_z() -> C::BaseField {
        let four = C::BaseField::from(4u64);
        let three = C::BaseField::from(3u64);
        let two = C::BaseField::from(2u64);
        let mut ctr = C::BaseField::one();
        loop {
            for z_cand in [ctr, -ctr] {
                let gz = Self::g(z_cand);
                if gz.is_zero() {
                    continue;
                }
                let h = -(three * z_cand.square() + four * C::COEFF_A) / (four * gz);
                if h.is_zero() || !is_square(&h) {
                    continue;
                }
                if is_square(&gz) || is_square(&Self::g(-z_cand / two)) {
                    return z_cand;
                }
            }
            ctr += C::BaseField::one();
        }
    }

    pub fn new() -> Self {
        let z = Self::find_z();
        let gz = Self::g(z);
        let t = C::BaseField::from(3u64) * z.square() + C::BaseField::from(4u64) * C::COEFF_A;
        let c1 = gz;
        let c2 = -(z / C::BaseField::from(2u64));
        let mut c3 = (-gz * t)
            .sqrt()
            .expect("valid Z guarantees -g(Z)(3Z²+4A) square");
        if sgn0(&c3) {
            c3 = -c3; // RFC: sgn0(c3) MUST be 0
        }
        let c4 = -(C::BaseField::from(4u64) * gz) / t;
        SvdwMap { z, c1, c2, c3, c4 }
    }

    /// Straight-line map_to_curve per RFC 9380 §6.6.1.
    pub fn map_to_curve(&self, u: C::BaseField) -> Affine<C> {
        let one = C::BaseField::one();
        let tv1 = u.square() * self.c1;
        let tv2 = one + tv1;
        let tv1 = one - tv1;
        let tv3 = inv0(tv1 * tv2);
        let tv4 = u * tv1 * tv3 * self.c3;
        let x1 = self.c2 - tv4;
        let x2 = self.c2 + tv4;
        let x3 = (tv2.square() * tv3).square() * self.c4 + self.z;
        let x = if is_square(&Self::g(x1)) {
            x1
        } else if is_square(&Self::g(x2)) {
            x2
        } else {
            x3
        };
        let gx = Self::g(x);
        let mut y = gx.sqrt().expect("SvdW: g(x) square by construction");
        if sgn0(&u) != sgn0(&y) {
            y = -y;
        }
        Affine::<C>::new_unchecked(x, y)
    }
}

impl<C: SWCurveConfig> Default for SvdwMap<C>
where
    C::BaseField: PrimeField,
{
    fn default() -> Self {
        Self::new()
    }
}

/// RFC 9380 hash_to_curve, random-oracle variant: two field elements,
/// two map evaluations, point addition. Both cycle curves are prime
/// order (cofactor 1), so clear_cofactor is the identity.
pub fn hash_to_curve<C: SWCurveConfig>(dst: &[u8], msg: &[u8]) -> Affine<C>
where
    C::BaseField: PrimeField,
{
    let [u0, u1] = hash_to_field_two::<C::BaseField>(dst, msg);
    let map = SvdwMap::<C>::new();
    (map.map_to_curve(u0).into_group() + map.map_to_curve(u1)).into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;

    // ----- helpers -----

    fn fq(hex_be: &str) -> ark_secp256k1::Fq {
        let bytes = hex::decode(hex_be).expect("valid hex");
        ark_secp256k1::Fq::from_be_bytes_mod_order(&bytes)
    }

    /// RFC 9380 J.8.1 suite DST (secp256k1_XMD:SHA-256_SSWU_RO_ vectors —
    /// the hash_to_field u-values are map-agnostic, so they oracle our
    /// XMD + hash_to_field path even though our curve map is SvdW).
    const RFC_DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

    /// RFC 9380 K.1 expander DST.
    const XMD_DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";

    // ----- happy path -----

    #[test]
    fn hash_to_field_one_is_deterministic() {
        let a: ark_secp256k1::Fq = hash_to_field_one(RFC_DST, b"aegis");
        let b: ark_secp256k1::Fq = hash_to_field_one(RFC_DST, b"aegis");
        assert_eq!(a, b);
    }

    #[test]
    fn svdw_secp256k1_maps_field_elements_onto_curve() {
        let map = SvdwMap::<ark_secp256k1::Config>::new();
        for i in 0u64..32 {
            let u = ark_secp256k1::Fq::from(i);
            let p = map.map_to_curve(u);
            assert!(p.is_on_curve(), "u={i} not on curve");
        }
    }

    #[test]
    fn svdw_secq256k1_maps_field_elements_onto_curve() {
        let map = SvdwMap::<ark_secq256k1::Config>::new();
        for i in 0u64..32 {
            let u = ark_secq256k1::Fq::from(i);
            let p = map.map_to_curve(u);
            assert!(p.is_on_curve(), "u={i} not on curve");
        }
    }

    #[test]
    fn hash_to_curve_is_deterministic_and_dst_separated() {
        use ark_ec::AffineRepr;
        let a = hash_to_curve::<ark_secp256k1::Config>(b"aegis:test:v1:A", b"");
        let a2 = hash_to_curve::<ark_secp256k1::Config>(b"aegis:test:v1:A", b"");
        let b = hash_to_curve::<ark_secp256k1::Config>(b"aegis:test:v1:B", b"");
        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert!(a.is_on_curve());
        assert!(!a.is_zero(), "hash_to_curve output must not be identity");
    }

    // ----- oracle parity -----

    #[test]
    fn expand_message_xmd_empty_msg_matches_rfc9380_k1() {
        // Oracle: RFC 9380 Appendix K.1, msg = "", len_in_bytes = 0x20.
        assert_eq!(
            expand_message_xmd(b"", XMD_DST, 0x20),
            hex::decode("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")
                .unwrap()
        );
    }

    #[test]
    fn expand_message_xmd_abc_msg_matches_rfc9380_k1() {
        // Oracle: RFC 9380 Appendix K.1, msg = "abc", len_in_bytes = 0x20.
        assert_eq!(
            expand_message_xmd(b"abc", XMD_DST, 0x20),
            hex::decode("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615")
                .unwrap()
        );
    }

    #[test]
    fn hash_to_field_empty_msg_matches_rfc9380_j881() {
        // Oracle: RFC 9380 Appendix J.8.1, msg = "".
        let [u0, u1] = hash_to_field_two::<ark_secp256k1::Fq>(RFC_DST, b"");
        assert_eq!(
            u0,
            fq("6b0f9910dd2ba71c78f2ee9f04d73b5f4c5f7fc773a701abea1e573cab002fb3")
        );
        assert_eq!(
            u1,
            fq("1ae6c212e08fe1a5937f6202f929a2cc8ef4ee5b9782db68b0d5799fd8f09e16")
        );
    }

    #[test]
    fn hash_to_field_abc_msg_matches_rfc9380_j881() {
        // Oracle: RFC 9380 Appendix J.8.1, msg = "abc".
        let [u0, u1] = hash_to_field_two::<ark_secp256k1::Fq>(RFC_DST, b"abc");
        assert_eq!(
            u0,
            fq("128aab5d3679a1f7601e3bdf94ced1f43e491f544767e18a4873f397b08a2b61")
        );
        assert_eq!(
            u1,
            fq("5897b65da3b595a813d0fdcc75c895dc531be76a03518b044daaa0f2e4689e00")
        );
    }
}
