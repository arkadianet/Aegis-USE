//! Encrypted keystore — the spending key at rest, sealed under a passphrase.
//!
//! The wallet's spending key is the whole of its authority; storing it as
//! plaintext hex (the slice-1/2 default) means anyone who reads the file
//! owns the funds. This seals it: **PBKDF2-HMAC-SHA256** stretches the
//! passphrase into an **AES-256-GCM** key under a random per-file salt, and
//! the 32-byte secret is AEAD-sealed with a random nonce. A wrong passphrase
//! (or a tampered file) fails the GCM tag and returns `None` — it never
//! yields a wrong key silently.
//!
//! The KDF cost (`iters`) is stored in the blob so a file sealed today still
//! opens after the default is raised. Proven crates only (`pbkdf2`,
//! `aes-gcm`); nothing hand-rolled.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

/// PBKDF2 work factor for newly-sealed keystores (OWASP-2023 floor for
/// PBKDF2-HMAC-SHA256).
pub const DEFAULT_ITERS: u32 = 600_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SECRET_LEN: usize = 32;

/// A passphrase-sealed 32-byte secret. Serialize the fields to persist it;
/// none of them are sensitive on their own (the secret is only recoverable
/// with the passphrase).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Keystore {
    /// PBKDF2 iteration count used to derive this blob's key.
    pub iters: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// AES-256-GCM ciphertext of the secret (`SECRET_LEN` + 16-byte tag).
    pub ct: Vec<u8>,
}

impl Keystore {
    /// Seal `secret` under `passphrase` at the default work factor.
    pub fn seal(secret: &[u8; SECRET_LEN], passphrase: &str, rng: &mut impl RngCore) -> Self {
        Self::seal_with(secret, passphrase, DEFAULT_ITERS, rng)
    }

    /// Seal at an explicit iteration count (tests use a small one; production
    /// goes through [`Keystore::seal`]).
    pub fn seal_with(
        secret: &[u8; SECRET_LEN],
        passphrase: &str,
        iters: u32,
        rng: &mut impl RngCore,
    ) -> Self {
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new(&derive_key(passphrase, &salt, iters).into());
        let ct = cipher
            .encrypt(&nonce.into(), secret.as_slice())
            .expect("AES-256-GCM sealing is infallible for a valid key/nonce");
        Keystore {
            iters,
            salt,
            nonce,
            ct,
        }
    }

    /// Recover the secret with `passphrase`. `None` on a wrong passphrase or
    /// any tampering (GCM tag failure) — never a silently-wrong key.
    pub fn open(&self, passphrase: &str) -> Option<[u8; SECRET_LEN]> {
        let cipher = Aes256Gcm::new(&derive_key(passphrase, &self.salt, self.iters).into());
        let pt = cipher
            .decrypt(&self.nonce.into(), self.ct.as_slice())
            .ok()?;
        pt.try_into().ok()
    }
}

fn derive_key(passphrase: &str, salt: &[u8], iters: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iters, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const ITERS: u32 = 2_000; // fast for tests; production uses DEFAULT_ITERS

    fn rng() -> StdRng {
        StdRng::seed_from_u64(7)
    }

    // ----- round-trips -----

    #[test]
    fn seal_open_roundtrips_the_secret() {
        let secret = [0x42u8; 32];
        let ks = Keystore::seal_with(&secret, "correct horse battery", ITERS, &mut rng());
        assert_eq!(ks.open("correct horse battery"), Some(secret));
    }

    // ----- error paths -----

    #[test]
    fn wrong_passphrase_returns_none() {
        let ks = Keystore::seal_with(&[9u8; 32], "right", ITERS, &mut rng());
        assert_eq!(ks.open("wrong"), None);
    }

    #[test]
    fn tampered_ciphertext_returns_none() {
        let mut ks = Keystore::seal_with(&[1u8; 32], "pw", ITERS, &mut rng());
        ks.ct[0] ^= 0x01;
        assert_eq!(ks.open("pw"), None);
    }

    #[test]
    fn different_files_differ_even_for_the_same_secret() {
        // Fresh salt + nonce per seal ⇒ the blobs are unlinkable on disk.
        let secret = [5u8; 32];
        let a = Keystore::seal_with(&secret, "pw", ITERS, &mut StdRng::seed_from_u64(1));
        let b = Keystore::seal_with(&secret, "pw", ITERS, &mut StdRng::seed_from_u64(2));
        assert_ne!(a.ct, b.ct);
        assert_ne!(a.salt, b.salt);
        // Both still open to the same secret.
        assert_eq!(a.open("pw"), b.open("pw"));
    }

    #[test]
    fn stored_iters_lets_an_old_blob_open_after_a_default_raise() {
        // A blob sealed at one factor opens regardless of DEFAULT_ITERS,
        // because the factor travels with the blob.
        let ks = Keystore::seal_with(&[7u8; 32], "pw", 1_500, &mut rng());
        assert_eq!(ks.iters, 1_500);
        assert_eq!(ks.open("pw"), Some([7u8; 32]));
    }
}
