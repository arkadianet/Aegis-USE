//! Wallet key hierarchy (M4 slice 1).
//!
//! Aegis's spend authority is the SCALAR `nk` — the nullifier key the note
//! protocol feeds into `poseidon_nullifier(nk, rho)`. There is no Sapling-style
//! `ak`/`ask` point layer (a correction to the first design sketch). From one
//! root [`SpendingKey`] we derive three capability tiers:
//!
//! - **`nk` (OddScalar) — SPEND.** Whoever holds it can compute nullifiers and
//!   prove ownership. The crown secret; never shared, never inside a viewing key.
//! - **`ivk` (EvenScalar) — INCOMING VIEWING.** Reserved for detecting +
//!   (later) decrypting notes sent to this wallet; CANNOT spend. (Addresses are
//!   `pk = nk·B` under the adopted payment model — see `address.rs`; the
//!   Sapling-style `ivk`-derived address was dropped with option (a). `ivk`
//!   stays for the future encryption/detection layer.)
//! - **`ovk` (32 bytes) — OUTGOING VIEWING.** Lets the sender recover notes it
//!   sent (history + payment disclosure).
//!
//! Each is a domain-separated one-way function of the root, so `ivk`/`ovk` reveal
//! nothing about `nk`. These derivations are WALLET-LOCAL (not consensus) and
//! v1/provisional — pending a ZIP-32-style spec + external review before real
//! value. `nk` itself plugs into the already-consensus `poseidon_nullifier`.

use aegis_crypto::h2c::hash_to_field_one;
use aegis_crypto::note::EvenScalar;
use aegis_crypto::nullifier::OddScalar;
use ergo_crypto::autolykos::common::blake2b256;
use rand::RngCore;

const DST_NK: &[u8] = b"aegis:wallet:nk:v1";
const DST_IVK: &[u8] = b"aegis:wallet:ivk:v1";
const DST_OVK: &[u8] = b"aegis:wallet:ovk:v1";

/// The root wallet secret. Everything derives from this — guard it like funds.
#[derive(Clone)]
pub struct SpendingKey([u8; 32]);

impl SpendingKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SpendingKey(bytes)
    }

    pub fn random(rng: &mut impl RngCore) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        SpendingKey(b)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// The nullifier / **spend** key (crown secret). Feeds the consensus
    /// `poseidon_nullifier(nk, rho)`.
    pub fn nk(&self) -> OddScalar {
        hash_to_field_one::<OddScalar>(DST_NK, &self.0)
    }

    /// The incoming viewing key — the safely-shareable, detect-only key.
    pub fn incoming_viewing_key(&self) -> IncomingViewingKey {
        IncomingViewingKey(hash_to_field_one::<EvenScalar>(DST_IVK, &self.0))
    }

    /// The outgoing viewing key.
    pub fn ovk(&self) -> Ovk {
        let mut pre = Vec::with_capacity(DST_OVK.len() + 32);
        pre.extend_from_slice(DST_OVK);
        pre.extend_from_slice(&self.0);
        Ovk(blake2b256(&pre))
    }
}

/// Incoming viewing key — generates addresses and (later) detects/decrypts
/// incoming notes. Holds only an `EvenScalar`; structurally CANNOT spend
/// (spending needs `nk`, which is not derivable from this).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IncomingViewingKey(EvenScalar);

impl IncomingViewingKey {
    /// The underlying scalar (address derivation: `pk_d = ivk·g_d`).
    pub fn scalar(&self) -> EvenScalar {
        self.0
    }
}

// Redacted so key material is never printed by accident (logs, panics).
impl std::fmt::Debug for IncomingViewingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IncomingViewingKey(<redacted>)")
    }
}

/// Outgoing viewing key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ovk(pub [u8; 32]);

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::nullifier::poseidon_nullifier;

    fn sk(seed: u8) -> SpendingKey {
        SpendingKey::from_bytes([seed; 32])
    }

    // ----- happy path -----

    #[test]
    fn derivation_is_deterministic() {
        let a = sk(7);
        let b = sk(7);
        assert_eq!(a.nk(), b.nk());
        assert_eq!(a.incoming_viewing_key(), b.incoming_viewing_key());
        assert_eq!(a.ovk(), b.ovk());
    }

    #[test]
    fn nk_feeds_the_consensus_nullifier() {
        // The wallet's derived nk is a usable OddScalar for the consensus
        // nullifier — the hierarchy and the note protocol share one nk.
        let nk = sk(1).nk();
        let rho = OddScalar::from(42u64);
        let nf1 = poseidon_nullifier(nk, rho);
        let nf2 = poseidon_nullifier(nk, rho);
        assert_eq!(nf1, nf2, "nullifier is deterministic in (nk, rho)");
    }

    // ----- capability separation -----

    #[test]
    fn distinct_roots_give_distinct_keys() {
        assert_ne!(sk(1).nk(), sk(2).nk());
        assert_ne!(sk(1).incoming_viewing_key(), sk(2).incoming_viewing_key());
        assert_ne!(sk(1).ovk(), sk(2).ovk());
    }

    #[test]
    fn spending_key_roundtrips_its_bytes() {
        let bytes = [0x5Au8; 32];
        assert_eq!(SpendingKey::from_bytes(bytes).to_bytes(), bytes);
    }
}
