//! Deterministic mint-note derivation for the hash-native pool — coinbase and
//! (INERT) peg-in. Ports the Curve-Trees chain's model: a minted note is
//! DETERMINISTIC from `(destination, amount, unique id)` and domain-separated,
//! so a miner cannot redirect value (the destination is bound into the
//! commitment; the amount is consensus-fixed) and cannot mint twice for one id
//! (the id — coinbase block id / peg-in box id — is on the node's used-set /
//! one-per-block).
//!
//! The nonce `rho` and blinding `r` are derived from the unique id under
//! separate domains, so the recipient — who knows the id (public) and their own
//! keys — recomputes them; a ciphertext to the recipient's address is also
//! attached so the STANDARD wallet scanner finds the note like any output
//! (§6 uniformity: a coinbase output is byte-indistinguishable from a payment).

use aegis_engine::address::Address;
use aegis_engine::commit::note_commitment;
use aegis_engine::note_encryption::{encrypt_note, NotePlaintext, MEMO_BYTES};
use aegis_engine::poseidon::{hash_domain, Digest, F};
use p3_field::PrimeCharacteristicRing;

// Mint domains (distinct from the engine's note domains 0x0A**).
const DOMAIN_MINT_RHO: u32 = 0x0B01;
const DOMAIN_MINT_R: u32 = 0x0B02;

/// A minted output: the leaf commitment + the ciphertext that ships beside it.
pub struct MintOut {
    pub cm: Digest,
    pub ciphertext: Vec<u8>,
}

/// Map a 32-byte unique id to 8 field elements (each 4-byte LE chunk reduced
/// mod p) plus a purpose tag, so coinbase vs peg-in ids never collide.
fn id_field(id: &[u8; 32], purpose: u32) -> [F; 9] {
    let mut out = [F::ZERO; 9];
    for (limb, chunk) in out.iter_mut().zip(id.chunks_exact(4)) {
        *limb = F::from_u32(u32::from_le_bytes(chunk.try_into().expect("4 bytes")));
    }
    out[8] = F::from_u32(purpose);
    out
}

/// Derive the deterministic `(rho, r)` for a mint of purpose `purpose` from its
/// unique id.
fn mint_nonces(id: &[u8; 32], purpose: u32) -> (Digest, Digest) {
    let f = id_field(id, purpose);
    (
        hash_domain(DOMAIN_MINT_RHO, &f),
        hash_domain(DOMAIN_MINT_R, &f),
    )
}

/// Purpose tags separating id namespaces.
pub const PURPOSE_COINBASE: u32 = 1;
pub const PURPOSE_PEGIN: u32 = 2;

/// The coinbase note for `amount` to `dest`, unique per `block_id`. The miner
/// picks `dest` (they earn it) but cannot forge a different note for the same
/// `(dest, amount, block_id)` — the derivation is fixed.
pub fn coinbase_note(dest: &Address, amount: u64, block_id: &[u8; 32]) -> MintOut {
    mint_out(dest, amount, block_id, PURPOSE_COINBASE)
}

/// The commitment a coinbase note MUST have for `(owner, amount, block_id)` —
/// what a validator recomputes from the block's PUBLIC `miner_owner` +
/// `coinbase_amount` to enforce that the shielded coinbase note carries exactly
/// the consensus-determined value to the claimed miner (no over/under-claim,
/// no redirect).
pub fn coinbase_cm_expected(owner: &Digest, amount: u64, block_id: &[u8; 32]) -> Digest {
    let (rho, r) = mint_nonces(block_id, PURPOSE_COINBASE);
    note_commitment(amount, owner, &rho, &r)
}

/// The (INERT) peg-in note for `amount` to `dest`, unique per `box_id`. The
/// derivation exists so the peg-in mint path is defined; enabling it is gated at
/// the node exactly as on `main` (a used-`box_id` set + anchor deferral).
pub fn pegmint_note(dest: &Address, amount: u64, box_id: &[u8; 32]) -> MintOut {
    mint_out(dest, amount, box_id, PURPOSE_PEGIN)
}

fn mint_out(dest: &Address, amount: u64, id: &[u8; 32], purpose: u32) -> MintOut {
    let (rho, r) = mint_nonces(id, purpose);
    let cm = note_commitment(amount, &dest.owner, &rho, &r);
    let pt = NotePlaintext {
        value: amount,
        rho,
        r,
        memo: [0u8; MEMO_BYTES],
    };
    let ciphertext = encrypt_note(dest, &cm, &pt).expect("mint destination is a valid address");
    MintOut { cm, ciphertext }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_engine::address::WalletKeys;

    fn addr(seed: &[u8]) -> Address {
        WalletKeys::from_seed(seed).address()
    }

    #[test]
    fn coinbase_is_deterministic_and_bound_to_dest_amount_id() {
        let a = addr(b"miner");
        let m1 = coinbase_note(&a, 100, &[7u8; 32]);
        let m2 = coinbase_note(&a, 100, &[7u8; 32]);
        assert_eq!(m1.cm, m2.cm, "deterministic");
        assert_ne!(coinbase_note(&a, 100, &[8u8; 32]).cm, m1.cm, "id-bound");
        assert_ne!(coinbase_note(&a, 101, &[7u8; 32]).cm, m1.cm, "amount-bound");
        assert_ne!(
            coinbase_note(&addr(b"other"), 100, &[7u8; 32]).cm,
            m1.cm,
            "dest-bound — a miner cannot redirect"
        );
    }

    #[test]
    fn coinbase_cm_expected_matches_minted_note() {
        let a = addr(b"miner");
        let m = coinbase_note(&a, 42, &[3u8; 32]);
        assert_eq!(
            coinbase_cm_expected(&a.owner, 42, &[3u8; 32]),
            m.cm,
            "a validator recomputes the exact minted commitment"
        );
        assert_ne!(
            coinbase_cm_expected(&a.owner, 43, &[3u8; 32]),
            m.cm,
            "a different claimed amount cannot match the commitment"
        );
    }

    #[test]
    fn coinbase_and_pegin_ids_never_collide() {
        let a = addr(b"x");
        assert_ne!(
            coinbase_note(&a, 5, &[1u8; 32]).cm,
            pegmint_note(&a, 5, &[1u8; 32]).cm,
            "purpose tag separates coinbase from peg-in for the same id"
        );
    }
}
