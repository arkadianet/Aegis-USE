//! The hash-native block **header id** — the 32-byte digest the aux-PoW
//! commits (E0, `epoch-validity-design.md` §2.1).
//!
//! Ground truth before E0 (`epoch-validity-design.md` §1): the hn "block id"
//! ([`super::state::block_id`]) committed only `(height, prev_root)` — NOT the
//! block contents — so nothing tied a mined Ergo share to a *particular* hn
//! block, and a fabricated suffix was free. This module defines the object the
//! merge-mining commitment carries and the share verifier binds to: a
//! Poseidon2 digest over **every consensus-relevant header field plus a body
//! commitment**, so one solved Autolykos PoW attests to exactly one hn block.
//!
//! Design choices, matching the reviewed Curve-Trees construction
//! (`aegis-types/src/header.rs` — an id over the canonical fields, PoW witness
//! deliberately EXCLUDED so one share commits one id and a block can be
//! re-mined) and `epoch-validity-design.md` §2.1-E0 / D-EV5:
//!
//! - **Poseidon2, not blake2b** (D-EV5): the hn chain is field-native, so an
//!   in-circuit id recomputation (epoch-validity's E1) is ~1 permutation
//!   instead of a software blake2b. The 8-limb digest packs to the 32 opaque
//!   bytes the Ergo extension field carries (`crate::auxpow` treats the value
//!   as opaque — `merge-mining.md` §2.2).
//! - **`chain_id` bound in** — cross-chain replay protection (a block id can
//!   never be reused on another hn profile).
//! - **Anchor EXCLUDED** — the aux-PoW witness attests the id; the id does not
//!   commit the witness (the reviewed model: one share ⇒ one id, re-mineable).
//! - **Body commitment** — `state_root` commits only the appended output
//!   commitments; a re-miner keeping the same id could otherwise swap a
//!   peg-out's `recipient_prop` (not in `state_root`) and redirect a
//!   withdrawal. The body commitment closes that: it binds every tx, peg-out,
//!   and peg-in by their canonical serialization.

use aegis_engine::poseidon::{digest_to_bytes, hash_domain, Digest, F};
use p3_field::PrimeCharacteristicRing;

use super::state::{HnBlock, PegInClaim, PegOutTx};

/// Poseidon2 domain for the hn header id.
const DOMAIN_HN_HEADER: u32 = 0x0B11;
/// Poseidon2 domain for the hn body commitment.
const DOMAIN_HN_BODY: u32 = 0x0B12;

/// Push a `u64` as four 16-bit BabyBear limbs (little-endian). Each chunk is
/// `< 2^16 < p`, so the encoding is always canonical (no field wraparound
/// hiding a distinct integer).
fn push_u64(out: &mut Vec<F>, v: u64) {
    for i in 0..4 {
        out.push(F::from_u32(((v >> (16 * i)) & 0xFFFF) as u32));
    }
}

/// Push a `u32` as two 16-bit BabyBear limbs (little-endian).
fn push_u32(out: &mut Vec<F>, v: u32) {
    out.push(F::from_u32(v & 0xFFFF));
    out.push(F::from_u32(v >> 16));
}

/// Push a byte slice as 16-bit limbs (two bytes per limb, length-prefixed so a
/// shorter slice can never be a prefix of a longer one under the same hash).
fn push_bytes(out: &mut Vec<F>, bytes: &[u8]) {
    push_u64(out, bytes.len() as u64);
    for chunk in bytes.chunks(2) {
        let lo = chunk[0] as u32;
        let hi = chunk.get(1).copied().unwrap_or(0) as u32;
        out.push(F::from_u32(lo | (hi << 8)));
    }
}

/// Push eight already-canonical BabyBear limbs (a root / owner / cm digest).
fn push_digest_limbs(out: &mut Vec<F>, limbs: &[u32; 8]) {
    for &l in limbs {
        // These come from field elements (< p) by construction; a hostile
        // non-canonical value only changes the hash, never forges a match.
        out.push(F::from_u32(l));
    }
}

/// Commitment over the block body — every tx, peg-out, and peg-in, by their
/// canonical (postcard) serialization. Binds the parts of the block NOT
/// already pinned by `state_root` (peg-out `recipient_prop`, peg-in
/// box-id/dest/amount, ciphertexts) so the id commits the *whole* block.
pub fn hn_body_commitment(
    txs: &[aegis_hn_wallet::Tx],
    pegouts: &[PegOutTx],
    pegins: &[PegInClaim],
) -> Digest {
    // postcard is already the block's persistence codec (chain.rs); reuse it as
    // the canonical byte image of the body.
    let bytes = postcard::to_allocvec(&(txs, pegouts, pegins))
        .expect("block body serializes for the body commitment");
    let mut limbs = Vec::with_capacity(4 + bytes.len() / 2 + 1);
    push_bytes(&mut limbs, &bytes);
    hash_domain(DOMAIN_HN_BODY, &limbs)
}

/// The hn **header id**: a Poseidon2 digest over the canonical header fields —
/// the object the aux-PoW extension commitment carries, packed to 32 bytes.
///
/// `chain_id` is bound in (cross-chain replay protection) and comes from the
/// validator's own params, so both the miner (constructing the commitment) and
/// every validator (recomputing the id from the presented block) derive the
/// same value. The merge-mining anchor is intentionally NOT part of the id.
pub fn hn_header_id(chain_id: u32, block: &HnBlock) -> [u8; 32] {
    let body = hn_body_commitment(&block.txs, &block.pegouts, &block.pegins);
    let body_limbs: [u32; 8] = {
        use p3_field::PrimeField32;
        core::array::from_fn(|i| body[i].as_canonical_u32())
    };

    let mut input: Vec<F> = Vec::with_capacity(72);
    push_u32(&mut input, chain_id);
    push_u64(&mut input, block.height);
    push_bytes(&mut input, &block.prev_header_id);
    push_digest_limbs(&mut input, &block.prev_root);
    push_digest_limbs(&mut input, &block.state_root);
    push_u64(&mut input, block.pot_after);
    push_u32(&mut input, block.sc_nbits);
    push_u64(&mut input, block.timestamp_ms);
    push_digest_limbs(&mut input, &block.miner_owner);
    push_u64(&mut input, block.coinbase_amount);
    push_digest_limbs(&mut input, &block.coinbase_cm);
    input.push(F::from_u32(u32::from(block.coinbase_is_reward)));
    push_digest_limbs(&mut input, &body_limbs);

    digest_to_bytes(&hash_domain(DOMAIN_HN_HEADER, &input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hn::state::AuxAnchor;

    const CHAIN_ID: u32 = 0x484E_0005;

    // ----- helpers -----

    fn base_block() -> HnBlock {
        HnBlock {
            height: 7,
            prev_root: [1u32; 8],
            prev_header_id: [0u8; 32],
            state_root: [2u32; 8],
            timestamp_ms: 1_760_000_000_123,
            sc_nbits: 0x2000_0100,
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: [3u32; 8],
            coinbase_amount: 5,
            coinbase_cm: [4u32; 8],
            coinbase_ct: vec![],
            coinbase_is_reward: true,
            pot_after: 999,
            anchor: AuxAnchor::genesis(),
            aux_pow: None,
        }
    }

    fn a_pegin(box_tag: u8) -> PegInClaim {
        PegInClaim {
            box_id: [box_tag; 32],
            dest_owner: [9u32; 8],
            dest_enc_pk: [0u8; 32],
            amount: 1_000,
            ciphertext: vec![],
        }
    }

    // ----- happy path -----

    #[test]
    fn header_id_changes_when_any_committed_field_changes() {
        let base = base_block();
        let base_id = hn_header_id(CHAIN_ID, &base);
        // chain_id is a committed input (cross-chain replay protection).
        assert_ne!(base_id, hn_header_id(CHAIN_ID + 1, &base));

        let mutators: Vec<fn(&mut HnBlock)> = vec![
            |b| b.height += 1,
            |b| b.prev_root[0] += 1,
            |b| b.prev_header_id[0] ^= 1,
            |b| b.state_root[0] += 1,
            |b| b.timestamp_ms += 1,
            |b| b.sc_nbits += 1,
            |b| b.miner_owner[0] += 1,
            |b| b.coinbase_amount += 1,
            |b| b.coinbase_cm[0] += 1,
            |b| b.pot_after += 1,
            |b| b.coinbase_is_reward = !b.coinbase_is_reward,
        ];
        for (i, m) in mutators.iter().enumerate() {
            let mut v = base.clone();
            m(&mut v);
            assert_ne!(
                hn_header_id(CHAIN_ID, &v),
                base_id,
                "field {i} did not affect the header id"
            );
        }
    }

    #[test]
    fn header_id_ignores_the_anchor() {
        // The aux-PoW witness attests the id; the id must NOT commit the anchor
        // (the reviewed model: one share ⇒ one id, block re-mineable). Two
        // blocks differing only in their anchor share the same header id.
        let mut a = base_block();
        let mut b = base_block();
        a.anchor = AuxAnchor {
            devnet_header_id: [0xAA; 32],
            devnet_height: 10,
        };
        b.anchor = AuxAnchor {
            devnet_header_id: [0xBB; 32],
            devnet_height: 99,
        };
        assert_eq!(hn_header_id(CHAIN_ID, &a), hn_header_id(CHAIN_ID, &b));
    }

    #[test]
    fn header_id_binds_the_body() {
        // A body change NOT reflected in state_root (a different peg-in) must
        // still change the id — otherwise a re-miner could keep the same id and
        // swap the block's bridge effects.
        let base = base_block();
        let mut with_pegin = base_block();
        with_pegin.pegins = vec![a_pegin(0x01)];
        assert_ne!(
            hn_header_id(CHAIN_ID, &with_pegin),
            hn_header_id(CHAIN_ID, &base)
        );

        let mut other_pegin = base_block();
        other_pegin.pegins = vec![a_pegin(0x02)];
        assert_ne!(
            hn_header_id(CHAIN_ID, &with_pegin),
            hn_header_id(CHAIN_ID, &other_pegin),
            "different peg-in box id must give a different header id"
        );
    }

    // ----- round-trips -----

    #[test]
    fn header_id_is_deterministic() {
        let b = base_block();
        assert_eq!(hn_header_id(CHAIN_ID, &b), hn_header_id(CHAIN_ID, &b));
    }
}
