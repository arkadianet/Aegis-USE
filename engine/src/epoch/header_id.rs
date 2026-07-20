//! The hn **header id** and **block id**, field-native — the guest-side E1
//! mirror of `aegis-node/src/hn/header.rs` + `hn/state.rs::block_id`.
//!
//! Per D-EV5 the header id is a Poseidon2 digest over the canonical header
//! fields plus a **body commitment** binding every tx / peg-out / peg-in /
//! coinbase, so one solved Autolykos PoW (E2) attests to exactly one hn block.
//!
//! **Difference from E0's shipped `hn/header.rs` (flagged, pre-cut lockstep):**
//! the node's current body commitment folds a `postcard` byte image of node
//! types. That is not guest-recomputable (the guest cannot see those types) and
//! is a byte-sponge, not the "~1 permutation per field" D-EV5 intends. This
//! module folds the body **field-natively** over exactly the bridge-relevant
//! fields the guest re-derives. The node must adopt this same encoding at the
//! E0/E1 cut (D-EV1) — the header id is the object the share commits, so
//! node↔guest MUST agree or honest blocks fail verification. Self-consistent
//! within the guest + e2e today; node parity is the cut gate.

use p3_field::PrimeCharacteristicRing;

use crate::poseidon::{digest_to_bytes, hash_domain, hash_id_domain, Digest, F};
use crate::settlement_digest::recipient_commit;

use super::types::{SpendPublics, SuffixBlock};

/// Poseidon2 domain for the hn header id (matches `hn/header.rs`).
const DOMAIN_HN_HEADER: u32 = 0x0B11;
/// Poseidon2 domain for the field-native body commitment.
const DOMAIN_HN_BODY: u32 = 0x0B12;
/// Poseidon2 domain for the coinbase-uniqueness block id (`hn/state.rs`).
const DOMAIN_BLOCK_ID: u32 = 0x0B10;

fn push_u64(out: &mut Vec<F>, v: u64) {
    for i in 0..4 {
        out.push(F::from_u32(((v >> (16 * i)) & 0xFFFF) as u32));
    }
}

fn push_u32(out: &mut Vec<F>, v: u32) {
    out.push(F::from_u32(v & 0xFFFF));
    out.push(F::from_u32(v >> 16));
}

fn push_digest(out: &mut Vec<F>, d: &Digest) {
    out.extend_from_slice(d);
}

/// A 32-byte id (header id / box id) as 8 canonical LE limbs.
fn push_id_bytes(out: &mut Vec<F>, id: &[u8; 32]) {
    for chunk in id.chunks_exact(4) {
        out.push(F::from_u32(u32::from_le_bytes(
            chunk.try_into().expect("4 bytes"),
        )));
    }
}

fn push_spend(out: &mut Vec<F>, s: &SpendPublics) {
    push_digest(out, &s.root);
    push_digest(out, &s.nf0);
    push_digest(out, &s.nf1);
    push_digest(out, &s.cm0);
    push_digest(out, &s.cm1);
    push_u64(out, s.fee);
}

/// Field-native body commitment: binds every tx, peg-out, peg-in, and the
/// coinbase, length-prefixed so no shorter body is a prefix of a longer one.
pub fn body_commitment(block: &SuffixBlock) -> Digest {
    let mut input: Vec<F> = Vec::new();
    push_u64(&mut input, block.txs.len() as u64);
    for tx in &block.txs {
        push_spend(&mut input, tx);
    }
    push_u64(&mut input, block.pegouts.len() as u64);
    for po in &block.pegouts {
        push_spend(&mut input, &po.spend);
        push_u64(&mut input, po.amount);
        // recipient bound by its fixed-width engine commitment (length-agnostic).
        push_digest(&mut input, &recipient_commit(&po.recipient_prop));
    }
    push_u64(&mut input, block.pegins.len() as u64);
    for pi in &block.pegins {
        push_id_bytes(&mut input, &pi.box_id);
        push_digest(&mut input, &pi.dest_owner);
        push_u64(&mut input, pi.amount);
    }
    push_digest(&mut input, &block.miner_owner);
    push_u64(&mut input, block.coinbase_amount);
    push_digest(&mut input, &block.coinbase_cm);
    input.push(F::from_u32(u32::from(block.coinbase_is_reward)));
    hash_domain(DOMAIN_HN_BODY, &input)
}

/// A header-only preimage: exactly the fields the [`header_id`] hashes, with the
/// body already reduced to its commitment (`body_cm`, an *input* — never
/// recomputed). This is the object F1's authenticated seam walk carries: the
/// witness supplies a `Vec<SeamHeader>` newest-first, and the guest recomputes
/// each id via [`header_id_from_fields`] and checks the hash-linked chain to R7.
///
/// The field *order* the id hashes is fixed by [`header_id`] (see below), NOT by
/// this struct's declaration order — the two must stay in lockstep, which is why
/// [`header_id`] delegates here (one encoding, no drift).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeamHeader {
    pub height: u64,
    pub prev_header_id: [u8; 32],
    pub prev_root: Digest,
    pub state_root: Digest,
    pub timestamp_ms: u64,
    pub sc_nbits: u32,
    pub miner_owner: Digest,
    pub coinbase_amount: u64,
    pub coinbase_cm: Digest,
    pub coinbase_is_reward: bool,
    pub pot_after: u64,
    pub shielded_after: u64,
    /// The block's body commitment ([`body_commitment`]) — a witness input for a
    /// seam header (the seam never consumes the body), recomputed by [`header_id`]
    /// for a full block. A fabricated `body_cm` simply yields a different id and
    /// fails the seam's link check.
    pub body_cm: Digest,
}

/// The hn **header id** over an explicit header preimage — the single canonical
/// field sequence. `chain_id` bound in (cross-chain replay); the merge-mining
/// anchor is intentionally excluded (one share ⇒ one id).
pub fn header_id_from_fields(chain_id: u32, h: &SeamHeader) -> [u8; 32] {
    let mut input: Vec<F> = Vec::with_capacity(64);
    push_u32(&mut input, chain_id);
    push_u64(&mut input, h.height);
    push_id_bytes(&mut input, &h.prev_header_id);
    push_digest(&mut input, &h.prev_root);
    push_digest(&mut input, &h.state_root);
    push_u64(&mut input, h.pot_after);
    push_u64(&mut input, h.shielded_after);
    push_u32(&mut input, h.sc_nbits);
    push_u64(&mut input, h.timestamp_ms);
    push_digest(&mut input, &h.miner_owner);
    push_u64(&mut input, h.coinbase_amount);
    push_digest(&mut input, &h.coinbase_cm);
    input.push(F::from_u32(u32::from(h.coinbase_is_reward)));
    push_digest(&mut input, &h.body_cm);

    digest_to_bytes(&hash_domain(DOMAIN_HN_HEADER, &input))
}

/// A full block's [`SeamHeader`] view — header fields verbatim, body reduced to
/// its [`body_commitment`]. The seam and the block therefore hash IDENTICALLY.
pub fn seam_header_of(block: &SuffixBlock) -> SeamHeader {
    SeamHeader {
        height: block.height,
        prev_header_id: block.prev_header_id,
        prev_root: block.prev_root,
        state_root: block.state_root,
        timestamp_ms: block.timestamp_ms,
        sc_nbits: block.sc_nbits,
        miner_owner: block.miner_owner,
        coinbase_amount: block.coinbase_amount,
        coinbase_cm: block.coinbase_cm,
        coinbase_is_reward: block.coinbase_is_reward,
        pot_after: block.pot_after,
        shielded_after: block.shielded_after,
        body_cm: body_commitment(block),
    }
}

/// The hn **header id** of a full block: Poseidon2 over the canonical header
/// fields + the recomputed body commitment, packed to 32 bytes. Delegates to
/// [`header_id_from_fields`] so a block and its seam preimage never drift.
pub fn header_id(chain_id: u32, block: &SuffixBlock) -> [u8; 32] {
    header_id_from_fields(chain_id, &seam_header_of(block))
}

/// The coinbase-uniqueness block id `H(height ‖ prev_root)` — the id the
/// coinbase note commitment is bound to (`hn/state.rs::block_id`).
pub fn block_id(height: u64, prev_root: &Digest) -> [u8; 32] {
    hash_id_domain(DOMAIN_BLOCK_ID, height, prev_root)
}

#[cfg(test)]
mod tests {
    use super::super::types::{PegIn, PegOut, SpendPublics, FLAT_FEE};
    use super::*;
    use crate::poseidon::F;
    use p3_field::PrimeCharacteristicRing;

    fn digest(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    fn base_block() -> SuffixBlock {
        SuffixBlock {
            height: 7,
            prev_header_id: [0u8; 32],
            prev_root: digest(1),
            state_root: digest(2),
            timestamp_ms: 1_760_000_000_123,
            sc_nbits: 0x2000_0100,
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: digest(3),
            coinbase_amount: 5,
            coinbase_cm: digest(4),
            coinbase_is_reward: true,
            pot_after: 999,
            shielded_after: 1234,
        }
    }

    // ----- happy path -----

    #[test]
    fn header_id_is_deterministic() {
        let b = base_block();
        assert_eq!(header_id(9, &b), header_id(9, &b));
    }

    #[test]
    fn header_id_changes_when_any_committed_field_changes() {
        let base = base_block();
        let id = header_id(9, &base);
        assert_ne!(id, header_id(10, &base), "chain_id bound");
        let mutators: Vec<fn(&mut SuffixBlock)> = vec![
            |b| b.height += 1,
            |b| b.prev_root[0] += F::ONE,
            |b| b.prev_header_id[0] ^= 1,
            |b| b.state_root[0] += F::ONE,
            |b| b.timestamp_ms += 1,
            |b| b.sc_nbits += 1,
            |b| b.miner_owner[0] += F::ONE,
            |b| b.coinbase_amount += 1,
            |b| b.coinbase_cm[0] += F::ONE,
            |b| b.pot_after += 1,
            |b| b.shielded_after += 1,
            |b| b.coinbase_is_reward = !b.coinbase_is_reward,
        ];
        for (i, m) in mutators.iter().enumerate() {
            let mut v = base.clone();
            m(&mut v);
            assert_ne!(header_id(9, &v), id, "field {i} did not affect the id");
        }
    }

    #[test]
    fn header_id_delegates_to_from_fields() {
        // The full-block id and its seam preimage id are identical by
        // construction — this is the "one encoding, no drift" guarantee F1 leans
        // on (a seam header hashes exactly as the block it stands in for).
        let b = base_block();
        assert_eq!(
            header_id(9, &b),
            header_id_from_fields(9, &seam_header_of(&b)),
            "header_id must equal header_id_from_fields ∘ seam_header_of"
        );
    }

    #[test]
    fn header_id_binds_the_body() {
        let base = base_block();
        let mut with_pegin = base_block();
        with_pegin.pegins = vec![PegIn {
            box_id: [1u8; 32],
            dest_owner: digest(9),
            amount: 1000,
        }];
        assert_ne!(header_id(9, &with_pegin), header_id(9, &base));

        // A different peg-out recipient (NOT in state_root) must change the id.
        let mut a = base_block();
        let mut b = base_block();
        let spend = SpendPublics {
            root: digest(50),
            nf0: digest(60),
            nf1: digest(70),
            cm0: digest(80),
            cm1: digest(90),
            fee: FLAT_FEE,
        };
        a.pegouts = vec![PegOut {
            spend: spend.clone(),
            amount: 100,
            recipient_prop: b"\xAA".to_vec(),
        }];
        b.pegouts = vec![PegOut {
            spend,
            amount: 100,
            recipient_prop: b"\xBB".to_vec(),
        }];
        assert_ne!(
            header_id(9, &a),
            header_id(9, &b),
            "peg-out recipient must bind the id"
        );
    }
}
