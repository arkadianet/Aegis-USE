//! Payment addresses and wallet key derivation (hash-native engine).
//!
//! # Why the address has TWO components
//! The engine's owner key is a hash, `owner = H(nk)` ([`crate::commit`]) — there
//! is no algebraic public key, so nothing to Diffie–Hellman against on the spend
//! path. The address therefore carries a **separate encryption key**:
//!
//! ```text
//! address = (owner, enc_pk)
//!   owner  : Poseidon2 digest (spend component — binds notes to nk)
//!   enc_pk : X25519 public key (encryption component — note transport)
//! ```
//!
//! A welcome consequence over the old option-a engine (where the address WAS
//! `nk·B`, forcing detection to hold the spend key): here `enc_sk` alone
//! detects+decrypts incoming notes (a viewing capability) while spending still
//! requires `nk` — a real watch-only split, structurally.
//!
//! # Key derivation (one seed → both components)
//! `HKDF-SHA256` (proven crate; mirrors the old keystore's pbkdf2/hkdf pattern)
//! with **independent info domains**, so neither key leaks anything about the
//! other:
//!
//! ```text
//! nk     = limbs(HKDF(seed, info = "aegis:hn:kd:nk:v1",  64 bytes))  (8 BabyBear limbs)
//! enc_sk =        HKDF(seed, info = "aegis:hn:kd:enc:v1", 32 bytes)  (X25519, clamped)
//! ```
//!
//! Each `nk` limb reduces a `u64` block mod p (bias ~2⁻³³ per limb — negligible;
//! noted for review). The seed is the wallet's root secret (the keystore that
//! encrypts it at rest is out of scope this pass).
//!
//! # Wire encoding (versioned, checksummed — repo-consistent Bech32m)
//! `bech32m(hrp, version(1) ‖ owner(32) ‖ enc_pk(32))` with the wallet's Bech32m
//! convention (`aegis-wallet::address`). Bech32m has a strong built-in checksum;
//! the leading version byte (`ADDRESS_V1`) is the PQ/upgrade hinge — a future
//! ML-KEM (or hybrid) encryption component ships as a new version, not a fork of
//! the format.

use bech32::{FromBase32, ToBase32, Variant};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::commit::Nk;
use crate::poseidon::{digest_from_bytes, digest_to_bytes, Digest, DIGEST_ELEMS, F};

/// Address format version (PQ/upgrade hinge — see module doc).
pub const ADDRESS_V1: u8 = 1;
/// Mainnet human-readable part (placeholder until network params freeze).
pub const HRP_MAIN: &str = "aegishn";
/// Testnet human-readable part.
pub const HRP_TEST: &str = "aegishnt";

const KDF_INFO_NK: &[u8] = b"aegis:hn:kd:nk:v1";
const KDF_INFO_ENC: &[u8] = b"aegis:hn:kd:enc:v1";

/// A wallet's secret keys, derived from one seed.
pub struct WalletKeys {
    /// The spend/nullifier key (8 BabyBear limbs).
    pub nk: Nk,
    /// The note-encryption secret (X25519).
    pub enc_sk: StaticSecret,
}

impl WalletKeys {
    /// Derive both keys from the wallet seed (independent HKDF domains).
    pub fn from_seed(seed: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, seed);

        let mut nk_bytes = [0u8; 8 * DIGEST_ELEMS];
        hk.expand(KDF_INFO_NK, &mut nk_bytes)
            .expect("64 bytes is a valid HKDF-SHA256 length");
        let nk: Nk = core::array::from_fn(|i| {
            let block: [u8; 8] = nk_bytes[8 * i..8 * (i + 1)]
                .try_into()
                .expect("8-byte block");
            F::from_u64(u64::from_le_bytes(block))
        });

        let mut sk_bytes = [0u8; 32];
        hk.expand(KDF_INFO_ENC, &mut sk_bytes)
            .expect("32 bytes is a valid HKDF-SHA256 length");
        let enc_sk = StaticSecret::from(sk_bytes); // clamped by the crate

        WalletKeys { nk, enc_sk }
    }

    /// The public payment address for these keys.
    pub fn address(&self) -> Address {
        Address {
            owner: crate::commit::owner_key(&self.nk),
            enc_pk: *PublicKey::from(&self.enc_sk).as_bytes(),
        }
    }
}

use p3_field::PrimeCharacteristicRing;

/// A public payment address: spend component + encryption component.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address {
    /// Spend component: `owner = H(nk)`.
    pub owner: Digest,
    /// Encryption component: X25519 public key.
    pub enc_pk: [u8; 32],
}

/// Address decode errors (strict: anything non-canonical is rejected).
#[derive(Debug, PartialEq, Eq)]
pub enum AddressError {
    /// Not valid Bech32m under the expected HRP.
    Encoding,
    /// Unknown version byte.
    Version(u8),
    /// Wrong payload length for the version.
    Length(usize),
    /// The owner digest bytes are non-canonical field limbs.
    NonCanonicalOwner,
}

impl Address {
    /// Encode as Bech32m under `hrp` (see [`HRP_MAIN`]/[`HRP_TEST`]).
    pub fn encode(&self, hrp: &str) -> String {
        let mut payload = Vec::with_capacity(1 + 32 + 32);
        payload.push(ADDRESS_V1);
        payload.extend_from_slice(&digest_to_bytes(&self.owner));
        payload.extend_from_slice(&self.enc_pk);
        bech32::encode(hrp, payload.to_base32(), Variant::Bech32m).expect("hrp is valid ASCII")
    }

    /// Strict decode: Bech32m checksum, expected `hrp`, known version, exact
    /// length, canonical owner limbs.
    pub fn decode(s: &str, hrp: &str) -> Result<Self, AddressError> {
        let (got_hrp, data, variant) = bech32::decode(s).map_err(|_| AddressError::Encoding)?;
        if got_hrp != hrp || variant != Variant::Bech32m {
            return Err(AddressError::Encoding);
        }
        let payload = Vec::<u8>::from_base32(&data).map_err(|_| AddressError::Encoding)?;
        let (&version, rest) = payload.split_first().ok_or(AddressError::Length(0))?;
        if version != ADDRESS_V1 {
            return Err(AddressError::Version(version));
        }
        if rest.len() != 64 {
            return Err(AddressError::Length(rest.len()));
        }
        let owner_bytes: [u8; 32] = rest[..32].try_into().expect("32-byte owner");
        let owner = digest_from_bytes(&owner_bytes).ok_or(AddressError::NonCanonicalOwner)?;
        let enc_pk: [u8; 32] = rest[32..].try_into().expect("32-byte enc_pk");
        Ok(Address { owner, enc_pk })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn keys() -> WalletKeys {
        WalletKeys::from_seed(b"test-seed-0001")
    }

    // ----- happy path -----

    #[test]
    fn derivation_is_deterministic_and_seed_sensitive() {
        let a = WalletKeys::from_seed(b"seed-a");
        let a2 = WalletKeys::from_seed(b"seed-a");
        let b = WalletKeys::from_seed(b"seed-b");
        assert_eq!(a.nk, a2.nk);
        assert_eq!(a.enc_sk.to_bytes(), a2.enc_sk.to_bytes());
        assert_ne!(a.nk, b.nk);
        assert_ne!(a.enc_sk.to_bytes(), b.enc_sk.to_bytes());
    }

    #[test]
    fn address_components_come_from_independent_domains() {
        // The spend and encryption components are not trivially related.
        let k = keys();
        let addr = k.address();
        assert_ne!(digest_to_bytes(&addr.owner), addr.enc_pk);
    }

    // ----- round-trips -----

    #[test]
    fn address_bech32m_roundtrips() {
        let addr = keys().address();
        let s = addr.encode(HRP_TEST);
        assert!(s.starts_with(HRP_TEST));
        assert_eq!(Address::decode(&s, HRP_TEST), Ok(addr));
    }

    // ----- error paths -----

    #[test]
    fn address_decode_rejects_wrong_hrp_and_corruption() {
        let addr = keys().address();
        let s = addr.encode(HRP_TEST);
        assert_eq!(
            Address::decode(&s, HRP_MAIN),
            Err(AddressError::Encoding),
            "wrong network HRP must not decode"
        );
        // Flip one character (not in the HRP): the Bech32m checksum catches it.
        let mut corrupted = s.clone().into_bytes();
        let i = corrupted.len() - 3;
        corrupted[i] = if corrupted[i] == b'q' { b'p' } else { b'q' };
        let corrupted = String::from_utf8(corrupted).unwrap();
        assert!(Address::decode(&corrupted, HRP_TEST).is_err());
    }

    #[test]
    fn address_decode_rejects_unknown_version() {
        let addr = keys().address();
        let mut payload = vec![99u8];
        payload.extend_from_slice(&digest_to_bytes(&addr.owner));
        payload.extend_from_slice(&addr.enc_pk);
        let s = bech32::encode(HRP_TEST, payload.to_base32(), Variant::Bech32m).unwrap();
        assert_eq!(
            Address::decode(&s, HRP_TEST),
            Err(AddressError::Version(99))
        );
    }
}
