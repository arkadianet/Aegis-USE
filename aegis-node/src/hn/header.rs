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
//! **Node ↔ guest parity (E0/E1 cut, gate 2 of the M-E1 build).** The header id
//! is the object the epoch-validity guest RE-COMPUTES from the presented suffix
//! (`aegis_engine::epoch::header_id::header_id`). If the node and the guest
//! encoded it differently, honest blocks would fail the guest's share-verify /
//! header-chain check. So this module is now a **thin adapter**: it maps a node
//! [`HnBlock`] to the engine's guest-visible [`EngineSuffixBlock`] and calls the
//! engine's field-native `header_id`. The engine is the single source of truth —
//! node-computed and guest-recomputed ids are IDENTICAL by construction (the
//! `node_matches_engine_header_id` parity test is the guard).
//!
//! **Scope of the body commitment (deliberate, reviewed narrowing).** The
//! engine body commitment binds the **bridge-relevant** body the guest can
//! re-derive — every tx's spend public values (`root/nf0/nf1/cm0/cm1/fee`), each
//! peg-out's `amount` + `recipient_prop`, each peg-in's `box_id/dest_owner/
//! amount`, and the coinbase (`miner_owner/coinbase_amount/coinbase_cm/
//! coinbase_is_reward`). It does NOT fold the note **ciphertexts**
//! (`Tx.out_ciphertexts`, `PegInClaim.ciphertext/dest_enc_pk`, `coinbase_ct`) —
//! those are recipient-facing transport, not consensus state, and are size-
//! checked separately. This is a change from E0's original postcard-image body
//! commitment (which folded them opaquely and was NOT guest-recomputable). Every
//! value-relevant field — the nullifiers, output commitments, amounts, and the
//! withdrawal recipient — remains bound.
//!
//! Design choices, matching the reviewed Curve-Trees construction and
//! `epoch-validity-design.md` §2.1-E0 / D-EV5:
//!
//! - **Poseidon2, not blake2b** (D-EV5): the hn chain is field-native, so the
//!   guest's in-circuit / in-zkVM id recomputation is ~1 permutation per field.
//! - **`chain_id` bound in** — cross-chain replay protection.
//! - **Anchor EXCLUDED** — the aux-PoW witness attests the id; the id does not
//!   commit the witness (one share ⇒ one id, block re-mineable).

use aegis_engine::commit::{limbs_to_u64, N_LIMBS};
use aegis_engine::epoch::header_id::header_id as engine_header_id;
use aegis_engine::epoch::types::{
    PegIn as EnginePegIn, PegOut as EnginePegOut, SpendPublics as EngineSpend,
    SuffixBlock as EngineSuffixBlock,
};
use aegis_engine::poseidon::F;
use aegis_engine::spend::monolith::{PUB_CMO0, PUB_CMO1, PUB_FEE, PUB_NF0, PUB_NF1, PUB_ROOT};
use p3_field::PrimeCharacteristicRing;

use aegis_hn_wallet::chain::digest_at;

use super::state::{limbs_to_digest, HnBlock};

/// Read a spend's flat fee from its public-value limbs (`PUB_FEE`, `N_LIMBS`).
fn spend_fee(public_values: &[u32]) -> u64 {
    let limbs: [F; N_LIMBS] = core::array::from_fn(|i| F::from_u32(public_values[PUB_FEE + i]));
    limbs_to_u64(&limbs)
}

/// A monolith spend's public values → the engine's guest-visible `SpendPublics`.
fn engine_spend(public_values: &[u32]) -> EngineSpend {
    EngineSpend {
        root: digest_at(public_values, PUB_ROOT),
        nf0: digest_at(public_values, PUB_NF0),
        nf1: digest_at(public_values, PUB_NF1),
        cm0: digest_at(public_values, PUB_CMO0),
        cm1: digest_at(public_values, PUB_CMO1),
        fee: spend_fee(public_values),
    }
}

/// Map a node [`HnBlock`] to the engine's guest-visible [`EngineSuffixBlock`] —
/// the exact view the epoch-validity guest re-derives the header id from.
fn to_engine_block(block: &HnBlock) -> EngineSuffixBlock {
    EngineSuffixBlock {
        height: block.height,
        prev_header_id: block.prev_header_id,
        prev_root: limbs_to_digest(&block.prev_root),
        state_root: limbs_to_digest(&block.state_root),
        timestamp_ms: block.timestamp_ms,
        sc_nbits: block.sc_nbits,
        txs: block
            .txs
            .iter()
            .map(|t| engine_spend(&t.public_values))
            .collect(),
        pegouts: block
            .pegouts
            .iter()
            .map(|po| EnginePegOut {
                spend: engine_spend(&po.tx.public_values),
                amount: po.amount,
                recipient_prop: po.recipient_prop.clone(),
            })
            .collect(),
        pegins: block
            .pegins
            .iter()
            .map(|pi| EnginePegIn {
                box_id: pi.box_id,
                dest_owner: limbs_to_digest(&pi.dest_owner),
                amount: pi.amount,
            })
            .collect(),
        miner_owner: limbs_to_digest(&block.miner_owner),
        coinbase_amount: block.coinbase_amount,
        coinbase_cm: limbs_to_digest(&block.coinbase_cm),
        coinbase_is_reward: block.coinbase_is_reward,
        pot_after: block.pot_after,
        shielded_after: block.shielded_after,
    }
}

/// The hn **header id**: the engine's field-native Poseidon2 digest over the
/// canonical header fields + the body commitment, packed to 32 bytes. Delegates
/// to `aegis_engine::epoch::header_id::header_id` so the value is byte-identical
/// to what the epoch-validity guest recomputes (the E0/E1 cut gate).
///
/// `chain_id` is bound in (cross-chain replay protection) and comes from the
/// validator's own params, so both the miner (constructing the commitment) and
/// every validator (recomputing the id) derive the same value.
pub fn hn_header_id(chain_id: u32, block: &HnBlock) -> [u8; 32] {
    engine_header_id(chain_id, &to_engine_block(block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hn::state::{AuxAnchor, PegInClaim};

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
            shielded_after: 1234,
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
        // (one share ⇒ one id, block re-mineable). Two blocks differing only in
        // their anchor share the same header id.
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

    // ----- oracle parity (node ↔ engine, the E0/E1 cut gate) -----

    /// The node's `hn_header_id` equals the engine's guest-recomputed
    /// `header_id` for the SAME logical block, built independently on both sides.
    /// This is the load-bearing parity claim: honest blocks the node produces
    /// pass the epoch-validity guest's header-chain + share-verify checks.
    #[test]
    fn node_matches_engine_header_id() {
        use aegis_engine::epoch::header_id::header_id as engine_id;
        use aegis_engine::epoch::types::{
            PegIn as EPegIn, PegOut as EPegOut, SpendPublics as ESpend, SuffixBlock as ESuffixBlock,
        };
        use aegis_engine::poseidon::{Digest, F};
        use aegis_hn_wallet::Tx;

        fn edigest(base: u32) -> Digest {
            core::array::from_fn(|i| F::from_u32(base + i as u32))
        }
        // A full monolith public-value vector (44 limbs) for a spend keyed `base`.
        fn publics(base: u32, fee: u64) -> Vec<u32> {
            let mut pv = vec![0u32; aegis_engine::spend::monolith::N_PUB];
            for (off, b) in [
                (PUB_ROOT, base),
                (PUB_NF0, base + 10),
                (PUB_NF1, base + 20),
                (PUB_CMO0, base + 30),
                (PUB_CMO1, base + 40),
            ] {
                for i in 0..8 {
                    pv[off + i] = b + i as u32;
                }
            }
            // Fee: N_LIMBS little-endian limbs (base 2^16 per `value_limbs`).
            for i in 0..N_LIMBS {
                pv[PUB_FEE + i] = ((fee >> (16 * i)) & 0xFFFF) as u32;
            }
            pv
        }
        fn espend(base: u32, fee: u64) -> ESpend {
            ESpend {
                root: edigest(base),
                nf0: edigest(base + 10),
                nf1: edigest(base + 20),
                cm0: edigest(base + 30),
                cm1: edigest(base + 40),
                fee,
            }
        }

        let fee = 3u64;
        let tx = Tx {
            proof_bytes: vec![],
            public_values: publics(100, fee),
            out_ciphertexts: [vec![0u8; 0], vec![0u8; 0]],
        };
        let pegout_tx = Tx {
            proof_bytes: vec![],
            public_values: publics(500, fee),
            out_ciphertexts: [vec![], vec![]],
        };

        let mut hn = base_block();
        hn.txs = vec![tx];
        hn.pegouts = vec![crate::hn::state::PegOutTx {
            tx: pegout_tx,
            amount: 777,
            recipient_prop: b"\x00\x08\xcd recipient".to_vec(),
        }];
        hn.pegins = vec![a_pegin(0x07)];

        // Build the engine block independently (NOT via the adapter).
        let engine_block = ESuffixBlock {
            height: hn.height,
            prev_header_id: hn.prev_header_id,
            prev_root: edigest_from(&hn.prev_root),
            state_root: edigest_from(&hn.state_root),
            timestamp_ms: hn.timestamp_ms,
            sc_nbits: hn.sc_nbits,
            txs: vec![espend(100, fee)],
            pegouts: vec![EPegOut {
                spend: espend(500, fee),
                amount: 777,
                recipient_prop: b"\x00\x08\xcd recipient".to_vec(),
            }],
            pegins: vec![EPegIn {
                box_id: [0x07; 32],
                dest_owner: edigest_from(&[9u32; 8]),
                amount: 1_000,
            }],
            miner_owner: edigest_from(&hn.miner_owner),
            coinbase_amount: hn.coinbase_amount,
            coinbase_cm: edigest_from(&hn.coinbase_cm),
            coinbase_is_reward: hn.coinbase_is_reward,
            pot_after: hn.pot_after,
            shielded_after: hn.shielded_after,
        };

        assert_eq!(
            hn_header_id(CHAIN_ID, &hn),
            engine_id(CHAIN_ID, &engine_block),
            "node-computed and engine/guest-recomputed header ids must be identical"
        );
    }

    fn edigest_from(limbs: &[u32; 8]) -> aegis_engine::poseidon::Digest {
        core::array::from_fn(|i| aegis_engine::poseidon::F::from_u32(limbs[i]))
    }
}
