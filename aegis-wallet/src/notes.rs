//! Self-owned notes (M4 slice 2).
//!
//! Note encryption / trial-decryption is held under the freeze (slice 3),
//! so this slice cannot *detect* notes sent by another party — it tracks
//! only notes the wallet itself created (coinbase / change / self-spends,
//! §4 of `wallet-design.md`). A [`SelfNote`] is therefore fully described
//! by two journalled fields — its `value` and a derivation `index` — from
//! which every hiding secret regenerates deterministically off the
//! wallet's `sk`. That lets the scanner recompute a note's commitment and
//! *recognize* it among the chain's leaves without any ciphertext.
//!
//! The commitment forms are the **circuit-path** ones the spend proof
//! opens ([`consensus_note_commitment`] over the tag
//! [`consensus_note_tag`]) — not the §0 `aegis-tagged` note generators —
//! so a scanned self-note is directly spendable via
//! [`aegis_crypto::spend::prove_transfer`].

use aegis_crypto::generators::EvenPoint;
use aegis_crypto::h2c::hash_to_field_one;
use aegis_crypto::note::{note_cm_bytes, EvenScalar};
use aegis_crypto::note_encryption::{decrypt_note, MEMO_BYTES};
use aegis_crypto::nullifier::{poseidon_nullifier, OddScalar, NF_BYTES};
use aegis_crypto::payment::{recipient_note_opening, PaymentOpening};
use aegis_crypto::spend::{
    consensus_note_commitment, consensus_note_tag, NoteOpening, TransferOutput,
};
use aegis_types::ShieldedOutput;

use crate::keys::SpendingKey;

// Domain separators for the three per-note hiding secrets. Each is an
// independent one-way function of (sk ‖ index); WALLET-LOCAL and
// v1/provisional (same status as the key hierarchy).
const DST_RHO: &[u8] = b"aegis:wallet:note:rho:v1";
const DST_RKEY: &[u8] = b"aegis:wallet:note:rkey:v1";
const DST_BLIND: &[u8] = b"aegis:wallet:note:blind:v1";

/// A self-owned note: its on-chain `value` plus the `index` that
/// regenerates its hiding secrets (`rho`, `r_key`, `blinding`) from `sk`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelfNote {
    /// Derivation index — unique per note created by this wallet.
    pub index: u64,
    /// Note value in USE base units.
    pub value: u64,
}

/// `dst`-domained hash of `sk ‖ index` into field `F`.
fn derive<F: ark_ff::PrimeField>(dst: &[u8], sk: &SpendingKey, index: u64) -> F {
    let mut msg = [0u8; 40];
    msg[..32].copy_from_slice(&sk.to_bytes());
    msg[32..].copy_from_slice(&index.to_le_bytes());
    hash_to_field_one::<F>(dst, &msg)
}

impl SelfNote {
    /// A note at `index` holding `value` base units.
    pub fn new(index: u64, value: u64) -> Self {
        SelfNote { index, value }
    }

    /// Structurally-unique note nonce (§3 rho discipline).
    pub fn rho(&self, sk: &SpendingKey) -> OddScalar {
        derive(DST_RHO, sk, self.index)
    }

    /// Blinding of the key commitment `C`.
    pub fn r_key(&self, sk: &SpendingKey) -> OddScalar {
        derive(DST_RKEY, sk, self.index)
    }

    /// Blinding of the note commitment.
    pub fn blinding(&self, sk: &SpendingKey) -> EvenScalar {
        derive(DST_BLIND, sk, self.index)
    }

    /// The note tag `(C + Δ).x` bound into the commitment's tag slot.
    pub fn tag(&self, sk: &SpendingKey) -> EvenScalar {
        consensus_note_tag(sk.nk(), self.rho(sk), self.r_key(sk))
    }

    /// The circuit-path note commitment — the leaf that appears on-chain
    /// and in the consensus Curve Tree.
    pub fn commitment(&self, sk: &SpendingKey) -> EvenPoint {
        consensus_note_commitment(self.value, self.tag(sk), self.blinding(sk))
    }

    /// The consensus nullifier `Poseidon(nk + rho)` this note reveals
    /// when spent — the marker the wallet watches for on-chain.
    pub fn nullifier(&self, sk: &SpendingKey) -> [u8; NF_BYTES] {
        poseidon_nullifier(sk.nk(), self.rho(sk))
    }

    /// Everything the spend prover needs to consume this note, given its
    /// resolved position in the consensus leaf vector.
    pub fn opening(&self, sk: &SpendingKey, leaf_index: usize) -> NoteOpening {
        NoteOpening {
            value: self.value,
            blinding: self.blinding(sk),
            leaf_index,
            nk: sk.nk(),
            rho: self.rho(sk),
            r_key: self.r_key(sk),
        }
    }

    /// This note as a transfer *output* to create it on-chain (self-pay).
    pub fn output(&self, sk: &SpendingKey) -> TransferOutput {
        TransferOutput {
            value: self.value,
            tag: self.tag(sk),
            blinding: self.blinding(sk),
        }
    }

    /// The [`PaymentOpening`] of this self-note — what a sender would
    /// encrypt into an output's `ct` so a scanner can recover it. Used to
    /// encrypt change-to-self (uniformity: every output carries a real
    /// ciphertext, not zero-fill).
    pub fn payment_opening(&self, sk: &SpendingKey) -> PaymentOpening {
        PaymentOpening {
            value: self.value,
            blinding: self.blinding(sk),
            rho: self.rho(sk),
            r_key: self.r_key(sk),
        }
    }
}

/// A note another party sent to this wallet, recovered by trial-decrypting
/// an on-chain output's `ct` with the wallet's spend key `nk` (§5). Unlike
/// a [`SelfNote`] its secrets are NOT re-derivable from `sk`+index — they
/// arrive inside the ciphertext — so the recovered [`PaymentOpening`] and
/// the discovered `leaf_index` are the note's whole description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedNote {
    /// The opening recovered from the ciphertext (value + hiding secrets).
    pub opening: PaymentOpening,
    /// The fixed-size memo carried alongside the opening.
    pub memo: [u8; MEMO_BYTES],
    /// Position of this note's commitment in the consensus leaf vector.
    pub leaf_index: usize,
    /// Whether the note's nullifier has appeared on-chain (spent).
    pub spent: bool,
}

impl ReceivedNote {
    /// The note's value in USE base units.
    pub fn value(&self) -> u64 {
        self.opening.value
    }

    /// The consensus nullifier this note reveals when spent, under the
    /// receiving wallet's `nk` — the marker the wallet watches for.
    pub fn nullifier(&self, sk: &SpendingKey) -> [u8; NF_BYTES] {
        poseidon_nullifier(sk.nk(), self.opening.rho)
    }

    /// Everything [`aegis_crypto::spend::prove_transfer`] needs to consume
    /// this received note: the opening bound to the wallet's own `nk`.
    pub fn note_opening(&self, sk: &SpendingKey) -> NoteOpening {
        recipient_note_opening(sk.nk(), &self.opening, self.leaf_index)
    }
}

/// Trial-decrypt one on-chain `output` at `leaf_index` with the wallet's
/// `nk`. On a valid AEAD tag, the recovered opening is accepted only if it
/// reconstructs to the output's committed `note_cm` — i.e. the sender built
/// a note actually payable to `nk·B`, not merely a ciphertext this wallet
/// can open. Returns `None` for a foreign note (the common case; the
/// Poly1305 tag fails cheaply) or a ciphertext whose opening does not match
/// its commitment.
pub fn detect_received(
    sk: &SpendingKey,
    output: &ShieldedOutput,
    leaf_index: usize,
) -> Option<ReceivedNote> {
    let (opening, memo) = decrypt_note(sk.nk(), &output.epk, &output.ct, &output.note_cm)?;
    // Bind the opening to the committed leaf: only an opening that
    // reconstructs the on-chain note_cm is a spendable note we own.
    let tag = consensus_note_tag(sk.nk(), opening.rho, opening.r_key);
    let cm = consensus_note_commitment(opening.value, tag, opening.blinding);
    if note_cm_bytes(&cm) != output.note_cm {
        return None;
    }
    Some(ReceivedNote {
        opening,
        memo,
        leaf_index,
        spent: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::note::note_cm_bytes;

    // ----- helpers -----

    fn sk() -> SpendingKey {
        SpendingKey::from_bytes([0x11; 32])
    }

    // ----- happy path -----

    #[test]
    fn secrets_are_deterministic_in_sk_and_index() {
        let n = SelfNote::new(3, 1_000);
        assert_eq!(n.rho(&sk()), n.rho(&sk()));
        assert_eq!(n.r_key(&sk()), n.r_key(&sk()));
        assert_eq!(n.blinding(&sk()), n.blinding(&sk()));
        assert_eq!(n.commitment(&sk()), n.commitment(&sk()));
    }

    #[test]
    fn distinct_indices_give_distinct_secrets_and_commitments() {
        let a = SelfNote::new(1, 1_000);
        let b = SelfNote::new(2, 1_000);
        assert_ne!(a.rho(&sk()), b.rho(&sk()));
        assert_ne!(a.r_key(&sk()), b.r_key(&sk()));
        assert_ne!(a.blinding(&sk()), b.blinding(&sk()));
        assert_ne!(a.commitment(&sk()), b.commitment(&sk()));
        assert_ne!(a.nullifier(&sk()), b.nullifier(&sk()));
    }

    #[test]
    fn distinct_wallets_derive_distinct_notes() {
        let n = SelfNote::new(0, 500);
        let other = SpendingKey::from_bytes([0x22; 32]);
        assert_ne!(n.rho(&sk()), n.rho(&other));
        assert_ne!(n.commitment(&sk()), n.commitment(&other));
        assert_ne!(n.nullifier(&sk()), n.nullifier(&other));
    }

    // ----- round-trips -----

    #[test]
    fn output_commitment_matches_the_notes_leaf() {
        // Creating the note as a transfer output must yield exactly the
        // leaf the scanner will look for (same value/tag/blinding), so a
        // self-paid note is re-recognized on the next scan.
        let n = SelfNote::new(7, 4_242);
        let out = n.output(&sk());
        let out_cm = consensus_note_commitment(out.value, out.tag, out.blinding);
        assert_eq!(note_cm_bytes(&out_cm), note_cm_bytes(&n.commitment(&sk())));
    }

    #[test]
    fn opening_carries_the_leaf_index_and_wallet_nk() {
        let n = SelfNote::new(9, 100);
        let o = n.opening(&sk(), 5);
        assert_eq!(o.leaf_index, 5);
        assert_eq!(o.value, 100);
        assert_eq!(o.nk, sk().nk());
        assert_eq!(o.rho, n.rho(&sk()));
    }
}
