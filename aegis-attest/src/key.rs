//! Attester identity: a secp256k1 keypair whose public half is a 33-byte
//! SEC1-compressed point — exactly an Ergo `GroupElement`, so one key
//! serves both the Aegis-side attestation (this crate) and the Ergo-side
//! `atLeast` peg-out proof (a later slice).

use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// A compressed SEC1 secp256k1 public key (= an Ergo `GroupElement`).
pub const PUBLIC_KEY_BYTES: usize = 33;
/// A raw secp256k1 secret scalar.
pub const SECRET_KEY_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid secp256k1 secret scalar")]
    InvalidSecret,
    #[error("invalid secp256k1 public key (not a valid 33-byte compressed point)")]
    InvalidPublic,
}

/// An attester's public identity — validated compressed SEC1 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct PublicKey([u8; PUBLIC_KEY_BYTES]);

impl PublicKey {
    /// The compressed SEC1 encoding — feed this straight into an Ergo
    /// `GroupElement` / `proveDlog`.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.0
    }

    /// Parse + validate a compressed point. Rejects anything not on-curve.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_BYTES]) -> Result<Self, KeyError> {
        VerifyingKey::from_sec1_bytes(bytes).map_err(|_| KeyError::InvalidPublic)?;
        Ok(PublicKey(*bytes))
    }

    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_sec1_bytes(&self.0).expect("PublicKey holds validated SEC1 bytes")
    }

    /// Verify an ECDSA (SHA-256) signature over `msg` by this key.
    pub(crate) fn verify_message(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(signature) = Signature::from_slice(sig) else {
            return false;
        };
        self.verifying_key().verify(msg, &signature).is_ok()
    }
}

/// An attester's full keypair. The secret half never leaves this type
/// except via [`AttesterKey::secret_bytes`] (guard it like funds); no
/// `Debug` impl, so it can't leak into logs/panics.
#[derive(Clone)]
pub struct AttesterKey {
    signing: SigningKey,
    public: PublicKey,
}

impl AttesterKey {
    /// Generate a fresh keypair from a cryptographic RNG.
    pub fn random(rng: &mut impl k256::elliptic_curve::rand_core::CryptoRngCore) -> Self {
        Self::from_signing(SigningKey::random(rng))
    }

    /// Reconstruct a keypair from its 32-byte secret scalar.
    pub fn from_secret_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> Result<Self, KeyError> {
        let signing = SigningKey::from_slice(bytes).map_err(|_| KeyError::InvalidSecret)?;
        Ok(Self::from_signing(signing))
    }

    fn from_signing(signing: SigningKey) -> Self {
        let ep = signing.verifying_key().to_encoded_point(true);
        let mut bytes = [0u8; PUBLIC_KEY_BYTES];
        bytes.copy_from_slice(ep.as_bytes());
        AttesterKey {
            signing,
            public: PublicKey(bytes),
        }
    }

    /// The 32-byte secret scalar (sensitive).
    pub fn secret_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        self.signing.to_bytes().into()
    }

    /// This attester's public identity.
    pub fn public(&self) -> PublicKey {
        self.public
    }

    /// ECDSA (SHA-256), low-S normalized, over `msg`.
    pub(crate) fn sign_message(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.signing.sign(msg);
        sig.to_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn key(seed: u8) -> AttesterKey {
        AttesterKey::from_secret_bytes(&[seed; 32]).expect("small constant scalar is valid")
    }

    // ----- round-trips -----

    #[test]
    fn secret_bytes_roundtrip() {
        let k = key(7);
        let restored = AttesterKey::from_secret_bytes(&k.secret_bytes()).unwrap();
        assert_eq!(k.public(), restored.public());
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let pk = key(3).public();
        assert_eq!(PublicKey::from_bytes(&pk.to_bytes()).unwrap(), pk);
    }

    #[test]
    fn distinct_secrets_give_distinct_public_keys() {
        assert_ne!(key(1).public(), key(2).public());
    }

    // ----- error paths -----

    #[test]
    fn from_bytes_garbage_public_errors() {
        // 0x02-prefixed but not an x-coordinate on the curve.
        let mut bad = [0u8; PUBLIC_KEY_BYTES];
        bad[0] = 0x02;
        assert!(matches!(
            PublicKey::from_bytes(&bad),
            Err(KeyError::InvalidPublic)
        ));
    }

    #[test]
    fn from_secret_zero_errors() {
        assert!(matches!(
            AttesterKey::from_secret_bytes(&[0u8; 32]),
            Err(KeyError::InvalidSecret)
        ));
    }
}
