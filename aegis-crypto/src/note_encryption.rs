//! Note encryption (note-protocol.md §5): the ciphertext that ships beside
//! every on-chain output so the RECIPIENT (and, via `ovk`, the SENDER) can
//! recover the [`PaymentOpening`] and spend / audit the note. The chain
//! carries these bytes opaquely — encryption is a wallet/transport concern,
//! never consensus — so this module is deliberately key-agnostic (it takes
//! raw `nk`/`ovk`/point material, not wallet types).
//!
//! # Scheme
//!
//! Under the adopted payment model (option a, `payment-primitive-design.md`)
//! a recipient's address IS their spend key as a point `pk = nk·B` on the
//! odd curve. ECDH is therefore keyed on `nk` itself:
//!
//! ```text
//! esk        ← random odd scalar          (per-output ephemeral secret)
//! epk        = esk·B                       (B = tree odd Pedersen base)
//! shared     = esk·pk = nk·epk             (ECDH; recipient recomputes nk·epk)
//! K_enc      = HKDF-SHA256(ikm = shared ‖ epk, info = "aegis:note-enc:ecdh:v1")
//! ct         = ChaCha20Poly1305(K_enc, nonce = 0, aad = note_cm, plaintext)
//! plaintext  = value(8 LE) ‖ blinding(32) ‖ rho(32) ‖ r_key(32) ‖ memo(32)
//! ```
//!
//! `plaintext` is exactly the [`PaymentOpening`] the §1/§3 spend path needs,
//! plus a fixed-size memo. The nonce is a constant zero: safe because `K_enc`
//! is single-use (a fresh `esk` per output ⇒ a fresh key per ciphertext).
//! A wrong `nk` (or a foreign note) derives a different `K_enc`, so the
//! Poly1305 tag fails and trial-decryption cheaply returns `None`.
//!
//! ## Sender recovery (`out_ct`, OVK wrap — N7, Sapling `out_ciphertext`)
//! Every output also carries a fixed-size `out_ct` so the sender can later
//! recover notes it sent (payment disclosure / change), even those encrypted
//! to a stranger's `pk` (which the sender cannot open via `nk`):
//!
//! ```text
//! K_ock  = HKDF-SHA256(ikm = ovk ‖ note_cm ‖ epk, info = "aegis:note-enc:ock:v1")
//! out_ct = ChaCha20Poly1305(K_ock, nonce = 0, aad = note_cm, K_enc ‖ zero-pad(32))
//! ```
//!
//! `out_ct` wraps the 32-byte content key `K_enc` (not `esk`+`pk`, which
//! would need 33-byte points and overflow the 80-byte slot). With `ovk` the
//! sender recomputes `K_ock`, unwraps `K_enc`, and decrypts `ct` — recovering
//! the full opening for ANY output it built. A sender wanting no recovery
//! fills the slot with random bytes; the size never varies (§6 uniformity).
//!
//! ## Capability caveat (option a)
//! Because `pk = nk·B`, recomputing `shared = nk·epk` needs the spend key
//! `nk` — there is no separate incoming-viewing key that detects without
//! spending. Watch-only detection is the accepted cost of option a
//! (`payment-primitive-design.md`); it needs an `nk ↔ ivk` binding that has
//! no cheap algebraic form here.
//!
//! ## Provisional (pin at parameter freeze — DEFERRED.md)
//! AEAD = ChaCha20-Poly1305, KDF = HKDF-SHA256, point encoding = ark
//! compressed. All three are the note-protocol.md §5 provisional choices.

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;

use crate::generators::OddPoint;
use crate::note::{EvenScalar, NOTE_CM_BYTES};
use crate::nullifier::OddScalar;
use crate::payment::{PaymentAddress, PaymentOpening};
use crate::tree::tree_params;

/// Compressed ephemeral-key point size (one odd-curve point).
pub const EPK_BYTES: usize = 33;
/// Fixed memo length carried inside the receiver ciphertext. 32 bytes is
/// what remains of the 152-byte `ct` slot after the 104-byte opening
/// (value ‖ blinding ‖ rho ‖ r_key) and the 16-byte AEAD tag. The
/// note-protocol.md §5 sketch budgeted a 64-byte memo but only ONE
/// 32-byte rerandomizer; the payment opening needs two odd scalars
/// (`rho`, `r_key`), which reclaims 32 bytes from the memo. A 64-byte
/// memo would require bumping `NOTE_CT_BYTES` by 32 (a wire change).
pub const MEMO_BYTES: usize = 32;

/// AEAD authentication-tag length (Poly1305).
const TAG_BYTES: usize = 16;
/// Receiver-ciphertext plaintext: value(8) ‖ blinding(32) ‖ rho(32) ‖
/// r_key(32) ‖ memo(32).
const CT_PLAINTEXT_BYTES: usize = 8 + 32 + 32 + 32 + MEMO_BYTES;
/// Receiver ciphertext size (`ct`) = plaintext + tag. Must equal
/// `aegis_spec::NOTE_CT_BYTES` (asserted wallet-side).
pub const NOTE_CT_BYTES: usize = CT_PLAINTEXT_BYTES + TAG_BYTES;

/// OVK-wrap plaintext: the 32-byte content key, zero-padded to a fixed
/// 64 bytes so `out_ct` fills its whole slot regardless of contents.
const OUT_PLAINTEXT_BYTES: usize = 64;
/// Sender ciphertext size (`out_ct`) = padded plaintext + tag. Must equal
/// `aegis_spec::NOTE_OUT_CT_BYTES` (asserted wallet-side).
pub const NOTE_OUT_CT_BYTES: usize = OUT_PLAINTEXT_BYTES + TAG_BYTES;

// Compile-time layout guards.
const _: () = assert!(NOTE_CT_BYTES == 152);
const _: () = assert!(NOTE_OUT_CT_BYTES == 80);
const _: () = assert!(EPK_BYTES == 33);

/// HKDF `info` domain for the ECDH content key `K_enc`.
const KDF_INFO_ENC: &[u8] = b"aegis:note-enc:ecdh:v1";
/// HKDF `info` domain for the OVK wrap key `K_ock`.
const KDF_INFO_OCK: &[u8] = b"aegis:note-enc:ock:v1";

/// The three fixed-size ciphertext slots that ship beside a `note_cm`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EncryptedNote {
    pub epk: [u8; EPK_BYTES],
    pub ct: [u8; NOTE_CT_BYTES],
    pub out_ct: [u8; NOTE_OUT_CT_BYTES],
}

/// The odd-curve Pedersen base `B` — the base of both `pk = nk·B` and
/// `epk = esk·B`, so `esk·pk = nk·epk`.
fn odd_base() -> OddPoint {
    tree_params().odd_parameters.pc_gens.B
}

/// The single-use zero nonce (safe: `K_enc`/`K_ock` are per-output).
fn zero_nonce() -> Nonce {
    Nonce::from([0u8; 12])
}

fn scalar_to_be32<F: PrimeField>(s: &F) -> [u8; 32] {
    let be = s.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    // These fields are 256-bit, so `be` is 32 bytes; left-pad defensively.
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

fn scalar_from_be32<F: PrimeField>(b: &[u8; 32]) -> F {
    F::from_be_bytes_mod_order(b)
}

fn compress_odd(p: &OddPoint) -> [u8; EPK_BYTES] {
    let mut out = [0u8; EPK_BYTES];
    p.serialize_compressed(&mut out[..])
        .expect("33-byte buffer fits a compressed odd-curve point");
    out
}

/// HKDF-SHA256 to a 32-byte AEAD key from `ikm` under domain `info`.
fn hkdf_key(ikm: &[u8], info: &[u8]) -> Key {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32-byte HKDF output is always valid");
    Key::from(okm)
}

/// Content key `K_enc` from the ECDH shared point and `epk`.
fn content_key(shared: &OddPoint, epk_bytes: &[u8; EPK_BYTES]) -> Key {
    let mut ikm = Vec::with_capacity(EPK_BYTES * 2);
    ikm.extend_from_slice(&compress_odd(shared));
    ikm.extend_from_slice(epk_bytes);
    hkdf_key(&ikm, KDF_INFO_ENC)
}

/// OVK wrap key `K_ock` bound to `ovk`, `note_cm`, and `epk`.
fn ovk_key(ovk: &[u8; 32], note_cm: &[u8; NOTE_CM_BYTES], epk_bytes: &[u8; EPK_BYTES]) -> Key {
    let mut ikm = Vec::with_capacity(32 + NOTE_CM_BYTES + EPK_BYTES);
    ikm.extend_from_slice(ovk);
    ikm.extend_from_slice(note_cm);
    ikm.extend_from_slice(epk_bytes);
    hkdf_key(&ikm, KDF_INFO_OCK)
}

/// Serialize a [`PaymentOpening`] + memo into the fixed AEAD plaintext.
fn pack_ct_plaintext(
    opening: &PaymentOpening,
    memo: &[u8; MEMO_BYTES],
) -> [u8; CT_PLAINTEXT_BYTES] {
    let mut pt = [0u8; CT_PLAINTEXT_BYTES];
    pt[0..8].copy_from_slice(&opening.value.to_le_bytes());
    pt[8..40].copy_from_slice(&scalar_to_be32(&opening.blinding));
    pt[40..72].copy_from_slice(&scalar_to_be32(&opening.rho));
    pt[72..104].copy_from_slice(&scalar_to_be32(&opening.r_key));
    pt[104..136].copy_from_slice(memo);
    pt
}

/// Inverse of [`pack_ct_plaintext`].
fn unpack_ct_plaintext(pt: &[u8]) -> Option<(PaymentOpening, [u8; MEMO_BYTES])> {
    if pt.len() != CT_PLAINTEXT_BYTES {
        return None;
    }
    let value = u64::from_le_bytes(pt[0..8].try_into().ok()?);
    let blinding: EvenScalar = scalar_from_be32(&pt[8..40].try_into().ok()?);
    let rho: OddScalar = scalar_from_be32(&pt[40..72].try_into().ok()?);
    let r_key: OddScalar = scalar_from_be32(&pt[72..104].try_into().ok()?);
    let mut memo = [0u8; MEMO_BYTES];
    memo.copy_from_slice(&pt[104..136]);
    Some((
        PaymentOpening {
            value,
            blinding,
            rho,
            r_key,
        },
        memo,
    ))
}

/// SENDER side: encrypt `opening` (+ `memo`) to the recipient's address
/// `pk`, and OVK-wrap the content key so the sender can recover it later.
///
/// `note_cm` is the output's on-chain commitment bytes; it is bound into
/// both ciphertexts as AEAD associated data (a ciphertext cannot be
/// transplanted onto a different note) and into the OVK key derivation.
pub fn encrypt_note<R: Rng>(
    pk: &PaymentAddress,
    opening: &PaymentOpening,
    memo: &[u8; MEMO_BYTES],
    note_cm: &[u8; NOTE_CM_BYTES],
    ovk: &[u8; 32],
    rng: &mut R,
) -> EncryptedNote {
    let esk = OddScalar::rand(rng);
    let epk = (odd_base() * esk).into_affine();
    let epk_bytes = compress_odd(&epk);
    let shared = (pk.point() * esk).into_affine();

    let k_enc = content_key(&shared, &epk_bytes);
    let ct_vec = ChaCha20Poly1305::new(&k_enc)
        .encrypt(
            &zero_nonce(),
            Payload {
                msg: &pack_ct_plaintext(opening, memo),
                aad: note_cm,
            },
        )
        .expect("ChaCha20Poly1305 encryption is infallible for a valid key");
    let mut ct = [0u8; NOTE_CT_BYTES];
    ct.copy_from_slice(&ct_vec);

    // OVK wrap: seal the content key K_enc (zero-padded to a fixed length).
    let mut out_pt = [0u8; OUT_PLAINTEXT_BYTES];
    out_pt[0..32].copy_from_slice(&k_enc);
    let k_ock = ovk_key(ovk, note_cm, &epk_bytes);
    let out_vec = ChaCha20Poly1305::new(&k_ock)
        .encrypt(
            &zero_nonce(),
            Payload {
                msg: &out_pt,
                aad: note_cm,
            },
        )
        .expect("ChaCha20Poly1305 encryption is infallible for a valid key");
    let mut out_ct = [0u8; NOTE_OUT_CT_BYTES];
    out_ct.copy_from_slice(&out_vec);

    EncryptedNote {
        epk: epk_bytes,
        ct,
        out_ct,
    }
}

/// RECIPIENT side: trial-decrypt `ct` with the spend key `nk`. Returns the
/// recovered opening + memo on a valid Poly1305 tag, else `None` (a foreign
/// note, a wrong `nk`, a non-point `epk`, or tampered bytes).
///
/// The caller MUST still check that the opening reconstructs to the
/// output's `note_cm` before treating the note as spendable — the AEAD
/// authenticates the sender's plaintext, not that it matches the committed
/// leaf. `note_cm` is the AEAD associated data, so a `ct` paired with a
/// different `note_cm` on the wire fails the tag here.
pub fn decrypt_note(
    nk: OddScalar,
    epk: &[u8; EPK_BYTES],
    ct: &[u8; NOTE_CT_BYTES],
    note_cm: &[u8; NOTE_CM_BYTES],
) -> Option<(PaymentOpening, [u8; MEMO_BYTES])> {
    let epk_point = OddPoint::deserialize_compressed(&epk[..]).ok()?;
    let shared = (epk_point * nk).into_affine();
    let k_enc = content_key(&shared, epk);
    let pt = ChaCha20Poly1305::new(&k_enc)
        .decrypt(
            &zero_nonce(),
            Payload {
                msg: ct,
                aad: note_cm,
            },
        )
        .ok()?;
    unpack_ct_plaintext(&pt)
}

/// SENDER side: recover a note the wallet sent, from its `ovk` and the wire
/// slots. Unwraps the content key from `out_ct`, then decrypts `ct`. Returns
/// `None` if the OVK wrap or the content decryption fails (a foreign output,
/// a wrong `ovk`, or tampered bytes).
pub fn recover_sent_note(
    ovk: &[u8; 32],
    note_cm: &[u8; NOTE_CM_BYTES],
    epk: &[u8; EPK_BYTES],
    ct: &[u8; NOTE_CT_BYTES],
    out_ct: &[u8; NOTE_OUT_CT_BYTES],
) -> Option<(PaymentOpening, [u8; MEMO_BYTES])> {
    let k_ock = ovk_key(ovk, note_cm, epk);
    let out_pt = ChaCha20Poly1305::new(&k_ock)
        .decrypt(
            &zero_nonce(),
            Payload {
                msg: out_ct,
                aad: note_cm,
            },
        )
        .ok()?;
    if out_pt.len() != OUT_PLAINTEXT_BYTES {
        return None;
    }
    let mut k_enc_bytes = [0u8; 32];
    k_enc_bytes.copy_from_slice(&out_pt[0..32]);
    let k_enc = Key::from(k_enc_bytes);
    let pt = ChaCha20Poly1305::new(&k_enc)
        .decrypt(
            &zero_nonce(),
            Payload {
                msg: ct,
                aad: note_cm,
            },
        )
        .ok()?;
    unpack_ct_plaintext(&pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::note_cm_bytes;
    use crate::payment::{output_to_address, PaymentAddress};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // ----- helpers -----

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xE0C0DE)
    }

    fn odd(n: u64) -> OddScalar {
        OddScalar::from(n)
    }

    fn even(n: u64) -> EvenScalar {
        EvenScalar::from(n)
    }

    fn recipient_nk() -> OddScalar {
        odd(0xC0FFEE)
    }

    fn memo() -> [u8; MEMO_BYTES] {
        let mut m = [0u8; MEMO_BYTES];
        m[..5].copy_from_slice(b"hello");
        m
    }

    /// Build a real payment output to `pk` and encrypt it; return the
    /// output's note_cm bytes, the opening, and the ciphertext slots.
    fn make_encrypted(
        pk: &PaymentAddress,
        value: u64,
        ovk: &[u8; 32],
        rng: &mut StdRng,
    ) -> ([u8; NOTE_CM_BYTES], PaymentOpening, EncryptedNote) {
        let (out, opening) = output_to_address(pk, value, odd(0x71), odd(0x81), even(0x91));
        let cm = crate::spend::consensus_note_commitment(out.value, out.tag, out.blinding);
        let cm_bytes = note_cm_bytes(&cm);
        let enc = encrypt_note(pk, &opening, &memo(), &cm_bytes, ovk, rng);
        (cm_bytes, opening, enc)
    }

    // ----- happy path -----

    #[test]
    fn recipient_decrypts_to_the_sent_opening() {
        let nk = recipient_nk();
        let pk = PaymentAddress::from_nk(nk);
        let ovk = [0x5Au8; 32];
        let (cm, opening, enc) = make_encrypted(&pk, 1_000, &ovk, &mut rng());

        let (got, got_memo) = decrypt_note(nk, &enc.epk, &enc.ct, &cm).expect("decrypts");
        assert_eq!(got, opening);
        assert_eq!(got_memo, memo());
    }

    #[test]
    fn sender_recovers_via_ovk() {
        let nk = recipient_nk();
        let pk = PaymentAddress::from_nk(nk);
        let ovk = [0x11u8; 32];
        let (cm, opening, enc) = make_encrypted(&pk, 777, &ovk, &mut rng());

        // The sender does NOT know nk, only ovk — still recovers the opening.
        let (got, got_memo) =
            recover_sent_note(&ovk, &cm, &enc.epk, &enc.ct, &enc.out_ct).expect("ovk recovers");
        assert_eq!(got, opening);
        assert_eq!(got_memo, memo());
    }

    #[test]
    fn ciphertext_slots_are_exactly_wire_sized() {
        let pk = PaymentAddress::from_nk(recipient_nk());
        let (_, _, enc) = make_encrypted(&pk, 1, &[0u8; 32], &mut rng());
        assert_eq!(enc.epk.len(), EPK_BYTES);
        assert_eq!(enc.ct.len(), NOTE_CT_BYTES);
        assert_eq!(enc.out_ct.len(), NOTE_OUT_CT_BYTES);
    }

    // ----- round-trips -----

    #[test]
    fn plaintext_pack_unpack_roundtrips() {
        let opening = PaymentOpening {
            value: 42,
            blinding: even(0xABCD),
            rho: odd(0x1234),
            r_key: odd(0x5678),
        };
        let (back, back_memo) = unpack_ct_plaintext(&pack_ct_plaintext(&opening, &memo())).unwrap();
        assert_eq!(back, opening);
        assert_eq!(back_memo, memo());
    }

    // ----- error paths / adversarial -----

    #[test]
    fn wrong_nk_fails_the_tag() {
        let nk = recipient_nk();
        let pk = PaymentAddress::from_nk(nk);
        let (cm, _, enc) = make_encrypted(&pk, 1_000, &[0u8; 32], &mut rng());
        // A foreign wallet's nk derives a different key ⇒ tag fails.
        assert!(decrypt_note(nk + odd(1), &enc.epk, &enc.ct, &cm).is_none());
    }

    #[test]
    fn tampered_ct_fails_the_tag() {
        let nk = recipient_nk();
        let pk = PaymentAddress::from_nk(nk);
        let (cm, _, enc) = make_encrypted(&pk, 1_000, &[0u8; 32], &mut rng());
        let mut bad = enc;
        bad.ct[0] ^= 0x01;
        assert!(decrypt_note(nk, &bad.epk, &bad.ct, &cm).is_none());
    }

    #[test]
    fn tampered_epk_fails_the_tag() {
        let nk = recipient_nk();
        let pk = PaymentAddress::from_nk(nk);
        let (cm, _, enc) = make_encrypted(&pk, 1_000, &[0u8; 32], &mut rng());
        let mut bad = enc;
        // Flip a byte of epk: either it stops being a point, or the shared
        // secret changes — both make decryption fail.
        bad.epk[1] ^= 0x01;
        assert!(decrypt_note(nk, &bad.epk, &bad.ct, &cm).is_none());
    }

    #[test]
    fn ct_bound_to_note_cm_by_aad() {
        let nk = recipient_nk();
        let pk = PaymentAddress::from_nk(nk);
        let (mut cm, _, enc) = make_encrypted(&pk, 1_000, &[0u8; 32], &mut rng());
        // Presenting the ct against a different note_cm fails (AAD binding).
        cm[0] ^= 0x01;
        assert!(decrypt_note(nk, &enc.epk, &enc.ct, &cm).is_none());
    }

    #[test]
    fn wrong_ovk_does_not_recover() {
        let pk = PaymentAddress::from_nk(recipient_nk());
        let ovk = [0x22u8; 32];
        let (cm, _, enc) = make_encrypted(&pk, 500, &ovk, &mut rng());
        let mut wrong = ovk;
        wrong[0] ^= 0x01;
        assert!(recover_sent_note(&wrong, &cm, &enc.epk, &enc.ct, &enc.out_ct).is_none());
    }

    #[test]
    fn garbage_epk_is_rejected_cleanly() {
        // A non-canonical epk must return None, never panic.
        let cm = [0u8; NOTE_CM_BYTES];
        let ct = [0u8; NOTE_CT_BYTES];
        assert!(decrypt_note(recipient_nk(), &[0xFF; EPK_BYTES], &ct, &cm).is_none());
    }
}
