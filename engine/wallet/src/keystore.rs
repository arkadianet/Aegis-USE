//! Encrypted keystore — the wallet seed at rest, sealed under a passphrase.
//!
//! The seed is the wallet's whole authority (it derives `nk` = spend and
//! `enc_sk` = view via [`aegis_engine::address::WalletKeys`]); storing it as
//! plaintext means anyone who reads the file owns the funds. This seals it,
//! porting the old engine's audited `aegis-wallet::keystore`: **PBKDF2-HMAC-
//! SHA256** stretches the passphrase into an **AES-256-GCM** key under a random
//! per-file salt, and the 32-byte seed is AEAD-sealed with a random nonce. A
//! wrong passphrase (or a tampered file) fails the GCM tag and returns `None` —
//! never a silently-wrong seed. The KDF cost is stored in the blob so a file
//! sealed today still opens after the default is raised. Proven crates only
//! (`pbkdf2`, `aes-gcm`); nothing hand-rolled.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha256;

/// PBKDF2 work factor for newly-sealed keystores (OWASP-2023 floor for
/// PBKDF2-HMAC-SHA256).
pub const DEFAULT_ITERS: u32 = 600_000;
/// Wallet seed length.
pub const SEED_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// A passphrase-sealed 32-byte wallet seed. None of the fields is sensitive on
/// its own — the seed is only recoverable with the passphrase.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Keystore {
    /// PBKDF2 iteration count used to derive this blob's key.
    pub iters: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// AES-256-GCM ciphertext of the seed (`SEED_LEN` + 16-byte tag).
    pub ct: Vec<u8>,
}

impl Keystore {
    /// Seal `seed` under `passphrase` at the default work factor.
    pub fn seal(seed: &[u8; SEED_LEN], passphrase: &str, rng: &mut impl Rng) -> Self {
        Self::seal_with(seed, passphrase, DEFAULT_ITERS, rng)
    }

    /// Seal at an explicit iteration count (tests use a small one).
    pub fn seal_with(
        seed: &[u8; SEED_LEN],
        passphrase: &str,
        iters: u32,
        rng: &mut impl Rng,
    ) -> Self {
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new(&derive_key(passphrase, &salt, iters).into());
        let ct = cipher
            .encrypt(&nonce.into(), seed.as_slice())
            .expect("AES-256-GCM sealing is infallible for a valid key/nonce");
        Keystore {
            iters,
            salt,
            nonce,
            ct,
        }
    }

    /// Recover the seed with `passphrase`. `None` on a wrong passphrase or any
    /// tampering (GCM tag failure) — never a silently-wrong seed.
    pub fn open(&self, passphrase: &str) -> Option<[u8; SEED_LEN]> {
        let cipher = Aes256Gcm::new(&derive_key(passphrase, &self.salt, self.iters).into());
        let pt = cipher
            .decrypt(&self.nonce.into(), self.ct.as_slice())
            .ok()?;
        pt.try_into().ok()
    }
}

/// Generate a fresh random wallet seed from OS entropy.
pub fn generate_seed() -> [u8; SEED_LEN] {
    let mut seed = [0u8; SEED_LEN];
    rand::rng().fill_bytes(&mut seed);
    seed
}

fn derive_key(passphrase: &str, salt: &[u8], iters: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iters, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn small_seal(seed: &[u8; SEED_LEN], pass: &str) -> Keystore {
        Keystore::seal_with(seed, pass, 1_000, &mut rand::rng())
    }

    // ----- round-trips -----

    #[test]
    fn seal_open_roundtrips() {
        let seed = generate_seed();
        let ks = small_seal(&seed, "correct horse");
        assert_eq!(ks.open("correct horse"), Some(seed));
    }

    // ----- error paths -----

    #[test]
    fn wrong_passphrase_returns_none() {
        let ks = small_seal(&generate_seed(), "right");
        assert_eq!(ks.open("wrong"), None);
    }

    #[test]
    fn tampered_ciphertext_returns_none() {
        let mut ks = small_seal(&generate_seed(), "pw");
        let last = ks.ct.len() - 1;
        ks.ct[last] ^= 1;
        assert_eq!(ks.open("pw"), None);
    }
}
