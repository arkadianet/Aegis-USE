//! Note encryption: the fixed-size ciphertext that ships beside every on-chain
//! output so the RECIPIENT can find and spend a note sent by a stranger who
//! knows only their address. Ports the old engine's model (aegis-crypto §5:
//! ephemeral-DH → AEAD, aad = cm, nonce 0/single-use key, fixed sizes for §6
//! uniformity) onto the hash-native engine's two-component address.
//!
//! # Mechanism choice (documented decision)
//! **X25519 ECDH + ChaCha20-Poly1305 + HKDF-SHA256** (x25519-dalek /
//! chacha20poly1305 / hkdf — proven crates only). Encryption is OFF-circuit:
//! it is never proven by the spend STARK nor verified by the settlement guest,
//! so the engine's no-elliptic-curve rule — which is about FRI-native
//! *verification* cost — does not apply. A hash-based KEM (ML-KEM) was
//! evaluated and declined this pass: younger crates and ~+1 KB per output for
//! a benefit (PQ confidentiality) that is *privacy*, not funds — a
//! harvest-now-decrypt-later adversary could one day read amounts/memos, but
//! spending still requires the hash-based `nk`. The versioned address format
//! ([`crate::address`]) is the ML-KEM/hybrid upgrade hinge; flagged as a
//! review item.
//!
//! # Scheme (pinned layout — chain-id-breaking)
//! ```text
//! esk     ← 32 fresh CSPRNG bytes            (per-output ephemeral secret)
//! epk     = X25519 basepoint mult of esk
//! shared  = X25519(esk, enc_pk) = X25519(enc_sk, epk)   (reject all-zero)
//! K       = HKDF-SHA256(ikm = shared ‖ epk ‖ enc_pk, info = "aegis:hn:note-enc:v1")
//! ct      = ChaCha20Poly1305(K, nonce = 0, aad = cm_bytes(32), plaintext)
//! plaintext = value(8 LE) ‖ rho(32) ‖ r(32) ‖ memo(32)      (104 bytes)
//! wire    = epk(32) ‖ ct(120)                               (152 bytes/output)
//! ```
//! - The **zero nonce is safe** because `K` is single-use: a fresh `esk` per
//!   output ⇒ a fresh key per ciphertext (same argument as the old engine).
//! - **aad = the output's on-chain `cm`** binds the ciphertext to its output:
//!   a ciphertext replayed beside a different output fails the Poly1305 tag.
//! - `owner` is deliberately NOT in the plaintext: the scanner supplies its
//!   own owner digest when recomputing `cm`, so a decrypted opening can only
//!   ever be accepted for a note the scanner can actually spend.
//!
//! # Scanning / detection
//! For each new output `(cm, ciphertext)` the wallet calls [`try_decrypt`]:
//! wrong-recipient or tampered ciphertexts fail the AEAD cheaply (`None`); on
//! success the opening is parsed **strictly** (canonical limbs, value <
//! canonical limbs; any u64 value) and `cm` is recomputed from the opening + the wallet's OWN
//! `owner` and REQUIRED to equal the on-chain `cm` — an opening that does not
//! reconstruct the on-chain note is rejected (no accepting unspendable
//! garbage, and defense-in-depth beyond the aad binding).
//!
//! # §6 uniformity invariant (carried over, tested)
//! **Every output carries exactly [`NOTE_CT_BYTES`] ciphertext bytes with the
//! same layout, whatever its provenance** — stranger payment, change to self,
//! zero-value dummy. Change/self-sends are encrypted to the sender's own
//! address through the identical path, so ciphertext bytes are
//! indistinguishable across output kinds.
//!
//! # Deferred (follow-ups, mirroring the old engine's N7)
//! The sender-recovery slot (`out_ct`, an OVK-wrapped copy of `K` so a wallet
//! restored from seed can recover notes it *sent*) is not built this pass;
//! adding it is additive (a second fixed-size slot on every output — the
//! uniformity invariant extends to it verbatim).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::address::Address;
use crate::commit::{note_commitment, Blinding, Rho};
use crate::poseidon::{digest_from_bytes, digest_to_bytes, Digest};

/// Ephemeral X25519 public key size.
pub const EPK_BYTES: usize = 32;
/// Fixed memo length carried in every note ciphertext.
pub const MEMO_BYTES: usize = 32;
/// AEAD (Poly1305) tag size.
const TAG_BYTES: usize = 16;
/// Plaintext: value(8) ‖ rho(32) ‖ r(32) ‖ memo(32).
const PLAINTEXT_BYTES: usize = 8 + 32 + 32 + MEMO_BYTES;
/// The fixed on-chain ciphertext size per output: `epk ‖ AEAD(plaintext)`.
/// THE §6 uniformity constant — every output carries exactly this many bytes.
pub const NOTE_CT_BYTES: usize = EPK_BYTES + PLAINTEXT_BYTES + TAG_BYTES;

const _: () = assert!(NOTE_CT_BYTES == 152);

const KDF_INFO: &[u8] = b"aegis:hn:note-enc:v1";

/// The plaintext a recipient recovers: everything needed (with their own `nk`)
/// to recompute `cm`, derive the nullifier, and build the spend witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotePlaintext {
    pub value: u64,
    pub rho: Rho,
    pub r: Blinding,
    pub memo: [u8; MEMO_BYTES],
}

/// Derive the single-use content key from the DH shared secret.
/// `None` if the shared secret is the all-zero point (non-contributory peer
/// key) — encrypting with it would let a malicious "address" force a known key.
fn content_key(shared: &[u8; 32], epk: &[u8; 32], enc_pk: &[u8; 32]) -> Option<Key> {
    if shared.iter().all(|&b| b == 0) {
        return None;
    }
    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(shared);
    ikm[32..64].copy_from_slice(epk);
    ikm[64..].copy_from_slice(enc_pk);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = Key::default();
    hk.expand(KDF_INFO, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    Some(key)
}

fn serialize_plaintext(pt: &NotePlaintext) -> [u8; PLAINTEXT_BYTES] {
    let mut out = [0u8; PLAINTEXT_BYTES];
    out[..8].copy_from_slice(&pt.value.to_le_bytes());
    out[8..40].copy_from_slice(&digest_to_bytes(&pt.rho));
    out[40..72].copy_from_slice(&digest_to_bytes(&pt.r));
    out[72..].copy_from_slice(&pt.memo);
    out
}

/// Strict parse: canonical limbs and in-range value only (a malleable second
/// encoding of an opening, or an out-of-range amount, is rejected).
fn parse_plaintext(bytes: &[u8]) -> Option<NotePlaintext> {
    if bytes.len() != PLAINTEXT_BYTES {
        return None;
    }
    let value = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    let rho = digest_from_bytes(&bytes[8..40].try_into().expect("32 bytes"))?;
    let r = digest_from_bytes(&bytes[40..72].try_into().expect("32 bytes"))?;
    let memo: [u8; MEMO_BYTES] = bytes[72..].try_into().expect("32 bytes");
    Some(NotePlaintext {
        value,
        rho,
        r,
        memo,
    })
}

/// Encrypt a note opening to `address`, bound to the output's on-chain `cm`.
///
/// `esk_bytes` MUST be 32 fresh CSPRNG bytes per output (the caller owns the
/// randomness so tests can be deterministic); [`encrypt_note`] draws them from
/// the OS. Returns `None` only for a non-contributory (all-zero-DH) `enc_pk` —
/// a malformed address that must not be paid.
pub fn encrypt_note_with(
    address: &Address,
    cm: &Digest,
    pt: &NotePlaintext,
    esk_bytes: [u8; 32],
) -> Option<Vec<u8>> {
    let esk = StaticSecret::from(esk_bytes);
    let epk = PublicKey::from(&esk);
    let shared = esk.diffie_hellman(&PublicKey::from(address.enc_pk));
    let key = content_key(shared.as_bytes(), epk.as_bytes(), &address.enc_pk)?;

    let cipher = ChaCha20Poly1305::new(&key);
    let ct = cipher
        .encrypt(
            &Nonce::default(),
            Payload {
                msg: &serialize_plaintext(pt),
                aad: &digest_to_bytes(cm),
            },
        )
        .expect("ChaCha20Poly1305 encryption is infallible for in-memory data");

    let mut wire = Vec::with_capacity(NOTE_CT_BYTES);
    wire.extend_from_slice(epk.as_bytes());
    wire.extend_from_slice(&ct);
    debug_assert_eq!(wire.len(), NOTE_CT_BYTES, "§6 uniformity");
    Some(wire)
}

/// [`encrypt_note_with`] with OS-drawn ephemeral randomness.
pub fn encrypt_note(address: &Address, cm: &Digest, pt: &NotePlaintext) -> Option<Vec<u8>> {
    encrypt_note_with(address, cm, pt, rand::random())
}

/// Trial-decrypt an on-chain output `(cm, ciphertext)` with the wallet's
/// encryption secret and own `owner` digest.
///
/// `None` for: wrong recipient, tampered/replayed ciphertext (AEAD), malformed
/// wire, non-canonical opening, out-of-range value, or an opening that does not
/// recompute the on-chain `cm` for OUR `owner` (unspendable ⇒ not a payment).
pub fn try_decrypt(
    enc_sk: &StaticSecret,
    owner: &Digest,
    cm: &Digest,
    wire: &[u8],
) -> Option<NotePlaintext> {
    if wire.len() != NOTE_CT_BYTES {
        return None;
    }
    let epk_bytes: [u8; 32] = wire[..EPK_BYTES].try_into().expect("32 bytes");
    let epk = PublicKey::from(epk_bytes);
    let shared = enc_sk.diffie_hellman(&epk);
    let our_pk = PublicKey::from(enc_sk);
    let key = content_key(shared.as_bytes(), &epk_bytes, our_pk.as_bytes())?;

    let cipher = ChaCha20Poly1305::new(&key);
    let pt_bytes = cipher
        .decrypt(
            &Nonce::default(),
            Payload {
                msg: &wire[EPK_BYTES..],
                aad: &digest_to_bytes(cm),
            },
        )
        .ok()?;
    let pt = parse_plaintext(&pt_bytes)?;

    // The decisive spendability check: the opening must reconstruct the
    // on-chain note under OUR owner digest.
    let recomputed = note_commitment(pt.value, owner, &pt.rho, &pt.r);
    (recomputed == *cm).then_some(pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::WalletKeys;
    use crate::commit::owner_key;
    use crate::nullifier::nullifier;
    use crate::poseidon::F;
    use p3_field::PrimeCharacteristicRing;

    // ----- helpers -----

    fn digest(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    fn esk(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    fn plaintext(value: u64, base: u32) -> NotePlaintext {
        NotePlaintext {
            value,
            rho: digest(base),
            r: digest(base + 40),
            memo: [0u8; MEMO_BYTES],
        }
    }

    /// A stranger pays `addr` (knowing ONLY the address): builds the output
    /// note and its ciphertext. Returns the on-chain pair `(cm, wire)`.
    fn stranger_pays(addr: &Address, value: u64, base: u32, tag: u8) -> (Digest, Vec<u8>) {
        let pt = plaintext(value, base);
        let cm = note_commitment(pt.value, &addr.owner, &pt.rho, &pt.r);
        let wire = encrypt_note_with(addr, &cm, &pt, esk(tag)).expect("valid address");
        (cm, wire)
    }

    // ----- happy path -----

    #[test]
    fn stranger_payment_is_found_and_spendable() {
        // Sender side: only the encoded address string.
        let recipient = WalletKeys::from_seed(b"recipient-seed");
        let addr_str = recipient.address().encode(crate::address::HRP_TEST);
        let addr = Address::decode(&addr_str, crate::address::HRP_TEST).unwrap();
        let (cm, wire) = stranger_pays(&addr, 1_000, 500, 7);

        // Recipient side: scan finds the payment...
        let owner = owner_key(&recipient.nk);
        let pt = try_decrypt(&recipient.enc_sk, &owner, &cm, &wire)
            .expect("recipient must detect the payment");
        assert_eq!(pt.value, 1_000);

        // ...and the recovered opening + own nk is a complete spend witness:
        // cm reconstructs (checked inside try_decrypt) and the nullifier is
        // derivable — exactly the monolith's InputNote fields.
        let _nf = nullifier(&recipient.nk, &pt.rho);
        assert_eq!(note_commitment(pt.value, &owner, &pt.rho, &pt.r), cm);
    }

    #[test]
    fn scanning_skips_foreign_outputs_cleanly() {
        let recipient = WalletKeys::from_seed(b"recipient-seed");
        let other = WalletKeys::from_seed(b"other-seed");
        let (cm, wire) = stranger_pays(&other.address(), 700, 900, 9);

        let owner = owner_key(&recipient.nk);
        assert_eq!(
            try_decrypt(&recipient.enc_sk, &owner, &cm, &wire),
            None,
            "an output for someone else must trial-decrypt to None"
        );
    }

    // ----- round-trips -----

    #[test]
    fn uniformity_ciphertext_bytes_identical_across_output_kinds() {
        // §6: stranger payment, change-to-self, and zero-value dummy all
        // produce EXACTLY the same ciphertext size (and layout by code path).
        let sender = WalletKeys::from_seed(b"sender-seed");
        let stranger = WalletKeys::from_seed(b"stranger-seed");

        let (_, payment) = stranger_pays(&stranger.address(), 990, 100, 1);
        let (_, change) = stranger_pays(&sender.address(), 10, 200, 2); // to SELF
        let (_, dummy) = stranger_pays(&stranger.address(), 0, 300, 3); // zero-value

        assert_eq!(payment.len(), NOTE_CT_BYTES);
        assert_eq!(change.len(), NOTE_CT_BYTES);
        assert_eq!(dummy.len(), NOTE_CT_BYTES);

        // And the self-send is FOUND by the sender's own scanner (change flow).
        let owner = owner_key(&sender.nk);
        let cm = note_commitment(10, &sender.address().owner, &digest(200), &digest(240));
        assert!(try_decrypt(&sender.enc_sk, &owner, &cm, &change).is_some());
    }

    // ----- error paths -----

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let recipient = WalletKeys::from_seed(b"recipient-seed");
        let (cm, mut wire) = stranger_pays(&recipient.address(), 1_000, 500, 7);
        let owner = owner_key(&recipient.nk);
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        assert_eq!(try_decrypt(&recipient.enc_sk, &owner, &cm, &wire), None);
    }

    #[test]
    fn ciphertext_replayed_on_different_output_is_rejected() {
        // aad binding: the same ciphertext presented beside a different cm
        // fails the tag even for the right recipient.
        let recipient = WalletKeys::from_seed(b"recipient-seed");
        let (_cm, wire) = stranger_pays(&recipient.address(), 1_000, 500, 7);
        let other_cm = digest(9_999);
        let owner = owner_key(&recipient.nk);
        assert_eq!(
            try_decrypt(&recipient.enc_sk, &owner, &other_cm, &wire),
            None
        );
    }

    #[test]
    fn opening_that_does_not_recompute_cm_is_rejected() {
        // Valid AEAD, wrong note: encrypt an opening bound (aad) to cm_b that
        // actually opens cm_a — the recompute check must reject it.
        let recipient = WalletKeys::from_seed(b"recipient-seed");
        let addr = recipient.address();
        let pt_a = plaintext(1_000, 500);
        let cm_b = note_commitment(42, &addr.owner, &digest(800), &digest(840));
        let wire = encrypt_note_with(&addr, &cm_b, &pt_a, esk(7)).unwrap();
        let owner = owner_key(&recipient.nk);
        assert_eq!(
            try_decrypt(&recipient.enc_sk, &owner, &cm_b, &wire),
            None,
            "an opening that cannot reconstruct the on-chain cm is not a payment"
        );
    }

    #[test]
    fn nonconforming_wire_length_is_rejected() {
        let recipient = WalletKeys::from_seed(b"recipient-seed");
        let owner = owner_key(&recipient.nk);
        assert_eq!(
            try_decrypt(&recipient.enc_sk, &owner, &digest(1), &[0u8; 10]),
            None
        );
    }

    #[test]
    fn non_contributory_address_is_refused_at_encrypt() {
        // enc_pk = 0 (a small-order/identity point): DH is all-zero and
        // encrypt must refuse rather than derive a predictable key.
        let mut addr = WalletKeys::from_seed(b"x").address();
        addr.enc_pk = [0u8; 32];
        let pt = plaintext(5, 100);
        let cm = digest(1);
        assert_eq!(encrypt_note_with(&addr, &cm, &pt, esk(1)), None);
    }
}
