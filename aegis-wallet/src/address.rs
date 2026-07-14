//! Diversified addresses (M4 slice 1).
//!
//! One `ivk`, many unlinkable addresses. A diversifier `d` (11 random bytes)
//! maps to a base point `g_d = hash_to_curve(d)` on the even curve; the address
//! is `(d, pk_d = ivk·g_d)`. Encoded as **Bech32m** with an Aegis HRP (`use`
//! mainnet / `tuse` testnet). Two addresses from one wallet are unlinkable
//! on-chain (independent `g_d`) but both are scanned by the one `ivk`.
//!
//! The exact encoding is a wallet display concern (not consensus) and
//! v1/provisional.

use aegis_crypto::generators::EvenPoint;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bech32::{FromBase32, ToBase32, Variant};
use rand::RngCore;

use crate::keys::IncomingViewingKey;

const DST_DIVERSIFY: &[u8] = b"aegis:wallet:diversify:v1";
const DIVERSIFIER_LEN: usize = 11;
const PKD_LEN: usize = 33; // compressed even-curve point

/// Bech32m human-readable prefix for a mainnet shielded address.
pub const HRP_MAINNET: &str = "use";
/// Bech32m human-readable prefix for a testnet shielded address.
pub const HRP_TESTNET: &str = "tuse";

/// An 11-byte diversifier — selects one of a wallet's many addresses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Diversifier(pub [u8; DIVERSIFIER_LEN]);

impl Diversifier {
    pub fn random(rng: &mut impl RngCore) -> Self {
        let mut d = [0u8; DIVERSIFIER_LEN];
        rng.fill_bytes(&mut d);
        Diversifier(d)
    }

    /// The diversified base point `g_d = hash_to_curve(d)`.
    fn base(&self) -> EvenPoint {
        aegis_crypto::h2c::hash_to_curve::<ark_secp256k1::Config>(DST_DIVERSIFY, &self.0)
    }
}

/// A shielded address: a diversifier plus the diversified public key `pk_d`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address {
    pub diversifier: Diversifier,
    pub pk_d: EvenPoint,
}

impl Address {
    /// Derive the address for `ivk` at diversifier `d`: `pk_d = ivk·g_d`.
    pub fn derive(ivk: &IncomingViewingKey, d: Diversifier) -> Self {
        let pk_d = (d.base() * ivk.scalar()).into_affine();
        Address {
            diversifier: d,
            pk_d,
        }
    }

    /// Encode as a Bech32m string under `hrp` (`use1…` / `tuse1…`).
    pub fn encode(&self, hrp: &str) -> String {
        let mut payload = self.diversifier.0.to_vec();
        let mut pk = Vec::with_capacity(PKD_LEN);
        self.pk_d
            .serialize_compressed(&mut pk)
            .expect("even-curve point serializes to 33 bytes");
        payload.extend_from_slice(&pk);
        bech32::encode(hrp, payload.to_base32(), Variant::Bech32m).expect("bech32m encodes")
    }

    /// Decode a Bech32m address, returning `(hrp, address)`.
    pub fn decode(s: &str) -> Result<(String, Address), AddressError> {
        let (hrp, data, variant) = bech32::decode(s).map_err(|_| AddressError::Bech32)?;
        if variant != Variant::Bech32m {
            return Err(AddressError::Bech32);
        }
        let bytes = Vec::<u8>::from_base32(&data).map_err(|_| AddressError::Bech32)?;
        if bytes.len() != DIVERSIFIER_LEN + PKD_LEN {
            return Err(AddressError::Length);
        }
        let mut d = [0u8; DIVERSIFIER_LEN];
        d.copy_from_slice(&bytes[..DIVERSIFIER_LEN]);
        let pk_d = EvenPoint::deserialize_compressed(&bytes[DIVERSIFIER_LEN..])
            .map_err(|_| AddressError::Point)?;
        Ok((
            hrp,
            Address {
                diversifier: Diversifier(d),
                pk_d,
            },
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("not a valid bech32m string")]
    Bech32,
    #[error("wrong address payload length")]
    Length,
    #[error("pk_d is not a valid curve point")]
    Point,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;

    fn ivk(seed: u8) -> IncomingViewingKey {
        SpendingKey::from_bytes([seed; 32]).incoming_viewing_key()
    }

    fn diversifier(byte: u8) -> Diversifier {
        Diversifier([byte; DIVERSIFIER_LEN])
    }

    // ----- round-trips -----

    #[test]
    fn address_bech32m_roundtrips() {
        let addr = Address::derive(&ivk(3), diversifier(9));
        let s = addr.encode(HRP_TESTNET);
        assert!(s.starts_with("tuse1"));
        let (hrp, back) = Address::decode(&s).expect("decodes");
        assert_eq!(hrp, HRP_TESTNET);
        assert_eq!(back, addr);
    }

    // ----- unlinkability / determinism -----

    #[test]
    fn distinct_diversifiers_give_distinct_addresses() {
        let k = ivk(3);
        let a = Address::derive(&k, diversifier(1));
        let b = Address::derive(&k, diversifier(2));
        assert_ne!(a.pk_d, b.pk_d, "diversified addresses are unlinkable");
    }

    #[test]
    fn address_derivation_is_deterministic() {
        let a = Address::derive(&ivk(3), diversifier(9));
        let b = Address::derive(&ivk(3), diversifier(9));
        assert_eq!(a, b);
    }

    // ----- error paths -----

    #[test]
    fn decode_rejects_garbage_and_wrong_length() {
        assert!(matches!(
            Address::decode("not-an-address"),
            Err(AddressError::Bech32)
        ));
        // A valid bech32m string but wrong payload length.
        let short = bech32::encode("tuse", [0u8; 8].to_base32(), Variant::Bech32m).unwrap();
        assert!(matches!(Address::decode(&short), Err(AddressError::Length)));
    }
}
