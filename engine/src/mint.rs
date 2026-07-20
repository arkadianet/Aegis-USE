//! Deterministic mint-note commitment derivation (coinbase + peg-in) — the
//! guest-side mirror of the node's `aegis-node/src/hn/mint.rs`.
//!
//! Epoch-validity (E1, `epoch-validity-design.md` §2.1) requires the settlement
//! guest to **re-derive** an hn block's appended leaves from the block contents
//! rather than trust a settler-supplied leaf list. Two of those leaves — the
//! coinbase note and each peg-in mint note — are consensus formulas over public
//! header/claim fields, not spend-proof outputs. This module provides exactly
//! those formulas so the guest can recompute them.
//!
//! **Parity (REVIEW ITEM, pre-cut lockstep):** the derivations here MUST equal
//! `aegis-node/src/hn/mint.rs` byte-for-byte — same domains, same `id_field`
//! packing, same `note_commitment` — or an honest coinbase/peg-in leaf the node
//! appended would fail the guest's re-derivation. They are transcribed verbatim
//! and pinned by `mint_parity_*` tests; the node/guest consensus-formula lockstep
//! is a flagged item for the E0/E1 cut (D-EV1).

use crate::commit::note_commitment;
use crate::poseidon::{hash_domain, Digest, F};
use p3_field::PrimeCharacteristicRing;

/// Mint nonce domains (distinct from the engine's note domains `0x0A**`);
/// mirror of `aegis-node/src/hn/mint.rs`.
const DOMAIN_MINT_RHO: u32 = 0x0B01;
const DOMAIN_MINT_R: u32 = 0x0B02;

/// Purpose tags separating id namespaces (coinbase block-id vs peg-in box-id).
pub const PURPOSE_COINBASE: u32 = 1;
pub const PURPOSE_PEGIN: u32 = 2;

/// Map a 32-byte unique id to 8 field elements (each 4-byte LE chunk reduced
/// mod p) plus a purpose tag, so coinbase and peg-in ids never collide.
fn id_field(id: &[u8; 32], purpose: u32) -> [F; 9] {
    let mut out = [F::ZERO; 9];
    for (limb, chunk) in out.iter_mut().zip(id.chunks_exact(4)) {
        *limb = F::from_u32(u32::from_le_bytes(chunk.try_into().expect("4 bytes")));
    }
    out[8] = F::from_u32(purpose);
    out
}

/// Derive the deterministic `(rho, r)` for a mint of `purpose` from its id.
fn mint_nonces(id: &[u8; 32], purpose: u32) -> (Digest, Digest) {
    let f = id_field(id, purpose);
    (
        hash_domain(DOMAIN_MINT_RHO, &f),
        hash_domain(DOMAIN_MINT_R, &f),
    )
}

/// The commitment a coinbase note MUST have for `(owner, amount, block_id)`.
pub fn coinbase_cm_expected(owner: &Digest, amount: u64, block_id: &[u8; 32]) -> Digest {
    let (rho, r) = mint_nonces(block_id, PURPOSE_COINBASE);
    note_commitment(amount, owner, &rho, &r)
}

/// The commitment a peg-in mint note MUST have for `(owner, amount, box_id)`.
pub fn pegmint_cm_expected(owner: &Digest, amount: u64, box_id: &[u8; 32]) -> Digest {
    let (rho, r) = mint_nonces(box_id, PURPOSE_PEGIN);
    note_commitment(amount, owner, &rho, &r)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn owner(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    // ----- happy path -----

    #[test]
    fn coinbase_cm_is_deterministic_and_field_bound() {
        let o = owner(10);
        assert_eq!(
            coinbase_cm_expected(&o, 100, &[7u8; 32]),
            coinbase_cm_expected(&o, 100, &[7u8; 32])
        );
        assert_ne!(
            coinbase_cm_expected(&o, 100, &[7u8; 32]),
            coinbase_cm_expected(&o, 101, &[7u8; 32]),
            "amount-bound"
        );
        assert_ne!(
            coinbase_cm_expected(&o, 100, &[7u8; 32]),
            coinbase_cm_expected(&o, 100, &[8u8; 32]),
            "id-bound"
        );
        assert_ne!(
            coinbase_cm_expected(&o, 100, &[7u8; 32]),
            coinbase_cm_expected(&owner(20), 100, &[7u8; 32]),
            "owner-bound"
        );
    }

    // ----- oracle parity -----

    #[test]
    fn coinbase_and_pegin_never_collide_for_same_id() {
        let o = owner(3);
        assert_ne!(
            coinbase_cm_expected(&o, 5, &[1u8; 32]),
            pegmint_cm_expected(&o, 5, &[1u8; 32]),
            "purpose tag separates coinbase from peg-in"
        );
    }
}
