//! Send-to-another-party (M4 slice 3, `wallet-design.md` §5).
//!
//! The primitive slice 2 was missing: a transfer that pays a **stranger**.
//! Slice 2 could only self-transfer (consolidate) because a note's secrets
//! were re-derived from the wallet's own `sk`. Here the wallet builds a
//! note payable to a recipient's address `pk = nk·B`
//! ([`aegis_crypto::payment::output_to_address`]) and ships the opening to
//! them inside an encrypted `ct` ([`aegis_crypto::note_encryption`]), so the
//! recipient can detect and spend it without the sender ever learning `nk`.
//!
//! A payment is the fixed 2-in/2-out shape (§6): two consumed inputs
//! (self-owned or previously-received), and two outputs
//! `[payment-to-recipient, change-to-self]`. Both outputs carry a real
//! ciphertext (the payment encrypted to the recipient's `pk`, the change to
//! the wallet's own `pk`) plus the mandatory OVK wrap — never zero-fill, so
//! outputs stay byte-uniform (§6) and the sender can recover either via
//! `ovk`.
//!
//! Pure, like [`crate::consolidate`]: this builds and returns the transfer;
//! the caller submits it (`client.submit`) and then [`Payment::commit`]s it
//! to wallet state. `pk = nk·B` has no diversified addresses, so change
//! stays an ordinary self-note the next scan re-derives.

use aegis_crypto::generators::EvenPoint;
use aegis_crypto::h2c::hash_to_field_one;
use aegis_crypto::note::{note_cm_bytes, EvenScalar};
use aegis_crypto::note_encryption::{encrypt_note, EncryptedNote, MEMO_BYTES};
use aegis_crypto::nullifier::{rho_transfer, OddScalar, NF_BYTES};
use aegis_crypto::payment::{output_to_address, PaymentOpening};
use aegis_crypto::spend::{prove_transfer, SpendError, TransferProof};
use aegis_types::{ShieldedOutput, ShieldedTransfer};
use ark_serialize::CanonicalSerialize;
use rand::Rng;

use crate::address::Address;
use crate::keys::SpendingKey;
use crate::notes::SelfNote;
use crate::state::{SpentRef, WalletState};

// The wallet's note-encryption ciphertext sizes MUST equal the consensus
// wire sizes, or an assembled transfer would not serialize into the fixed
// `ShieldedOutput` slots. Pinned here so a divergence is a build error.
const _: () = assert!(aegis_spec::EPK_BYTES == aegis_crypto::note_encryption::EPK_BYTES);
const _: () = assert!(aegis_spec::NOTE_CT_BYTES == aegis_crypto::note_encryption::NOTE_CT_BYTES);
const _: () =
    assert!(aegis_spec::NOTE_OUT_CT_BYTES == aegis_crypto::note_encryption::NOTE_OUT_CT_BYTES);

// Domain separators for the payment output's key-commitment blinding and
// note blinding, seeded from the first consumed nullifier (§3 rho chain).
// WALLET-LOCAL and v1/provisional, like the self-note derivations.
const DST_PAY_RKEY: &[u8] = b"aegis:wallet:pay:rkey:v1";
const DST_PAY_BLIND: &[u8] = b"aegis:wallet:pay:blind:v1";

#[derive(Debug, thiserror::Error)]
pub enum PayError {
    #[error("need two spendable notes to build a transfer, have {have}")]
    NotEnoughNotes { have: usize },
    #[error("amount {amount} + fee {fee} overflows u64")]
    AmountOverflow { amount: u64, fee: u64 },
    #[error("inputs total {total} do not cover amount {amount} + fee {fee}")]
    InsufficientFunds { total: u64, amount: u64, fee: u64 },
    #[error("no anchor: the wallet has scanned no leaves to prove against")]
    NoAnchor,
    #[error("spend proof failed: {0}")]
    Spend(#[from] SpendError),
}

/// A built payment: the wire transfer to submit, the change note paid back
/// to the wallet (journal it after submit), the opening of the payment
/// output (the sender's own record of what it sent), the references to mark
/// the two consumed inputs spent, and the revealed nullifiers.
#[derive(Debug, Clone)]
pub struct Payment {
    pub transfer: ShieldedTransfer,
    pub change: SelfNote,
    pub payment_opening: PaymentOpening,
    pub spent_refs: [SpentRef; 2],
    pub nullifiers: [[u8; NF_BYTES]; 2],
}

impl Payment {
    /// Commit this payment to wallet state after the node accepts it:
    /// journal the change note and mark the two consumed inputs spent so
    /// they are not reselected before the next scan confirms them.
    pub fn commit(&self, state: &mut WalletState) {
        state.journal_note(self.change);
        for spent_ref in &self.spent_refs {
            state.mark_spent_input(*spent_ref);
        }
    }
}

/// Build a 2-in/2-out transfer paying `amount` to `recipient`, with the
/// remainder (minus `fee`) returned to the wallet as change. Consumes the
/// wallet's two largest spendable notes (self-owned or received).
///
/// Pure: does **not** mutate `state`. On success the caller submits
/// `payment.transfer` and then [`Payment::commit`]s it.
pub fn pay<R: Rng>(
    sk: &SpendingKey,
    state: &WalletState,
    recipient: Address,
    amount: u64,
    fee: u64,
    rng: &mut R,
) -> Result<Payment, PayError> {
    let inputs = state.spendable_inputs(sk);
    if inputs.len() < 2 {
        return Err(PayError::NotEnoughNotes { have: inputs.len() });
    }
    // Largest two (spendable_inputs sorts by value descending); a
    // zero-value reserve note naturally fills the second slot when the
    // wallet holds a single funded note.
    let mut it = inputs.into_iter();
    let in_0 = it.next().expect("len >= 2");
    let in_1 = it.next().expect("len >= 2");

    let total = in_0.value + in_1.value;
    let required = amount
        .checked_add(fee)
        .ok_or(PayError::AmountOverflow { amount, fee })?;
    let change_value = total
        .checked_sub(required)
        .ok_or(PayError::InsufficientFunds { total, amount, fee })?;

    let anchor = state.anchor_tree().ok_or(PayError::NoAnchor)?;

    // Payment output payable to the recipient. Its secrets seed from the
    // first consumed nullifier (§3 rho discipline: a per-tx-unique nonce),
    // so the same tx never reuses a nonce, and are transmitted to the
    // recipient only inside `ct`.
    let nf0 = in_0.nullifier;
    let rho_p = rho_transfer(&nf0);
    let r_key_p: OddScalar = hash_to_field_one(DST_PAY_RKEY, &nf0);
    let blind_p: EvenScalar = hash_to_field_one(DST_PAY_BLIND, &nf0);
    let recipient_pk = recipient.payment_address();
    let (pay_out, pay_opening) = output_to_address(&recipient_pk, amount, rho_p, r_key_p, blind_p);

    // Change back to self as an ordinary self-note (re-derivable on scan),
    // at the next free derivation index.
    let change = SelfNote::new(state.next_index(), change_value);
    let change_out = change.output(sk);
    let change_opening = change.payment_opening(sk);

    let openings = [in_0.opening, in_1.opening];
    let outputs = [pay_out, change_out];
    let proof = prove_transfer(&anchor, &openings, &outputs, fee, rng)?;

    // Encrypt each output to its recipient: payment → recipient's pk,
    // change → the wallet's own pk. The on-chain note_cm binds each
    // ciphertext (AEAD associated data + OVK key derivation).
    let ovk = sk.ovk().0;
    let own_pk = Address::from_spending_key(sk).payment_address();
    let memo = [0u8; MEMO_BYTES];
    let cm_pay = note_cm_bytes(&proof.output_cms[0]);
    let cm_change = note_cm_bytes(&proof.output_cms[1]);
    let enc_pay = encrypt_note(&recipient_pk, &pay_opening, &memo, &cm_pay, &ovk, rng);
    let enc_change = encrypt_note(&own_pk, &change_opening, &memo, &cm_change, &ovk, rng);

    let transfer = assemble_transfer(&proof, [enc_pay, enc_change]);

    Ok(Payment {
        transfer,
        change,
        payment_opening: pay_opening,
        spent_refs: [in_0.spent_ref, in_1.spent_ref],
        nullifiers: proof.nullifiers(),
    })
}

/// Assemble the wire [`ShieldedTransfer`] from a proof and the two output
/// ciphertexts: revealed nullifiers, output commitments with their
/// `(epk, ct, out_ct)`, and the ark-compressed proof blob.
fn assemble_transfer(proof: &TransferProof, enc: [EncryptedNote; 2]) -> ShieldedTransfer {
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .expect("serializing a proof into a Vec is infallible");
    let out_wire = |cm: &EvenPoint, e: &EncryptedNote| ShieldedOutput {
        note_cm: note_cm_bytes(cm),
        epk: e.epk,
        ct: e.ct,
        out_ct: e.out_ct,
    };
    ShieldedTransfer {
        nullifiers: proof.nullifiers(),
        outputs: [
            out_wire(&proof.output_cms[0], &enc[0]),
            out_wire(&proof.output_cms[1], &enc[1]),
        ],
        proof: proof_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::note_encryption::{decrypt_note, recover_sent_note};
    use aegis_crypto::spend::verify_transfer;
    use aegis_types::ShieldedTransfer as WireTransfer;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const FEE: u64 = 10; // dev-net sc_tx_fee

    // ----- helpers -----

    fn sk_a() -> SpendingKey {
        SpendingKey::from_bytes([0xA1; 32])
    }

    fn sk_b() -> SpendingKey {
        SpendingKey::from_bytes([0xB2; 32])
    }

    fn sk_c() -> SpendingKey {
        SpendingKey::from_bytes([0xC3; 32])
    }

    /// A wallet state whose two self-notes are real leaves in a small tree
    /// (mirrors how a scan leaves the state). Returns the state; the tree
    /// is rebuildable via `anchor_tree`.
    fn funded_wallet(sk: &SpendingKey, values: [u64; 2]) -> WalletState {
        let mut st = WalletState::new();
        let a = st.add_note(values[0]);
        let b = st.add_note(values[1]);
        let extra = SelfNote::new(99, 77).commitment(sk); // unrelated leaf
        let leaves = vec![a.commitment(sk), b.commitment(sk), extra];
        let resolved = [(a.index, 0usize), (b.index, 1usize)];
        st.install_leaves_for_test(leaves, &resolved);
        st
    }

    fn wire_proof(tx: &WireTransfer) -> TransferProof {
        use ark_serialize::CanonicalDeserialize;
        TransferProof::deserialize_compressed(tx.proof.as_slice()).expect("proof roundtrips")
    }

    // ----- happy path -----

    #[test]
    fn pay_builds_a_verifying_transfer_with_correct_change() {
        let st = funded_wallet(&sk_a(), [1_000, 500]);
        let bob = Address::from_spending_key(&sk_b());
        let payment = pay(&sk_a(), &st, bob, 600, FEE, &mut StdRng::seed_from_u64(1)).expect("pay");

        // change = 1500 - 600 - fee.
        assert_eq!(payment.change.value, 1_500 - 600 - FEE);
        // The proof verifies against the same anchor, at the same fee.
        let proof = wire_proof(&payment.transfer);
        verify_transfer(&st.anchor_tree().unwrap(), &proof, FEE).expect("payment verifies");
    }

    #[test]
    fn recipient_decrypts_the_payment_but_a_stranger_cannot() {
        let st = funded_wallet(&sk_a(), [1_000, 500]);
        let bob = Address::from_spending_key(&sk_b());
        let payment = pay(&sk_a(), &st, bob, 600, FEE, &mut StdRng::seed_from_u64(2)).expect("pay");

        let pay_out = &payment.transfer.outputs[0];
        // Bob (the recipient) decrypts the payment ct to the sent opening.
        let (got, _) = decrypt_note(sk_b().nk(), &pay_out.epk, &pay_out.ct, &pay_out.note_cm)
            .expect("recipient decrypts");
        assert_eq!(got, payment.payment_opening);
        assert_eq!(got.value, 600);

        // A foreign wallet (Carol) cannot open it — the tag fails.
        assert!(
            decrypt_note(sk_c().nk(), &pay_out.epk, &pay_out.ct, &pay_out.note_cm).is_none(),
            "a stranger must not decrypt the payment"
        );
    }

    #[test]
    fn sender_recovers_change_via_ovk() {
        let st = funded_wallet(&sk_a(), [1_000, 500]);
        let bob = Address::from_spending_key(&sk_b());
        let payment = pay(&sk_a(), &st, bob, 600, FEE, &mut StdRng::seed_from_u64(3)).expect("pay");

        // The sender recovers BOTH its own outputs via ovk: the change and
        // the payment it sent to Bob.
        let ovk = sk_a().ovk().0;
        let change = &payment.transfer.outputs[1];
        let (rec_change, _) = recover_sent_note(
            &ovk,
            &change.note_cm,
            &change.epk,
            &change.ct,
            &change.out_ct,
        )
        .expect("ovk recovers change");
        assert_eq!(rec_change.value, 1_500 - 600 - FEE);

        let pay_out = &payment.transfer.outputs[0];
        let (rec_pay, _) = recover_sent_note(
            &ovk,
            &pay_out.note_cm,
            &pay_out.epk,
            &pay_out.ct,
            &pay_out.out_ct,
        )
        .expect("ovk recovers the sent payment");
        assert_eq!(rec_pay.value, 600);
    }

    // ----- end-to-end: A pays B, B detects, B spends -----

    #[test]
    fn end_to_end_send_receive_spend() {
        // A pays B (real proof + encrypted outputs).
        let st_a = funded_wallet(&sk_a(), [1_000, 500]);
        let bob_addr = Address::from_spending_key(&sk_b());
        let payment = pay(
            &sk_a(),
            &st_a,
            bob_addr,
            600,
            FEE,
            &mut StdRng::seed_from_u64(4),
        )
        .expect("A pays B");
        let a_proof = wire_proof(&payment.transfer);
        verify_transfer(&st_a.anchor_tree().unwrap(), &a_proof, FEE).expect("A's payment verifies");

        // Simulate the block: A's two outputs append to the tree after A's
        // three original leaves (indices 0,1,2), so payment→3, change→4.
        // B also owns an on-chain zero-reserve note (index in B's journal)
        // to satisfy the 2-in arity — place it at leaf 5.
        let pay_cm = aegis_crypto::note::note_cm_from_bytes(&payment.transfer.outputs[0].note_cm)
            .expect("valid point");
        let change_cm =
            aegis_crypto::note::note_cm_from_bytes(&payment.transfer.outputs[1].note_cm)
                .expect("valid point");
        let a0 = SelfNote::new(0, 1_000).commitment(&sk_a());
        let a1 = SelfNote::new(1, 500).commitment(&sk_a());
        let extra = SelfNote::new(99, 77).commitment(&sk_a());

        // B's on-chain zero-reserve note.
        let mut st_b = WalletState::new();
        let b_reserve = st_b.add_note(0);
        let b_reserve_cm = b_reserve.commitment(&sk_b());

        let leaves = vec![a0, a1, extra, pay_cm, change_cm, b_reserve_cm];

        // B detects the received payment among the block's outputs (the
        // SAME detection routine `scan` uses).
        let received = crate::notes::detect_received(&sk_b(), &payment.transfer.outputs[0], 3)
            .expect("B detects the payment sent to it");
        assert_eq!(received.value(), 600);
        // A foreign output (the change to A) does NOT decrypt for B.
        assert!(
            crate::notes::detect_received(&sk_b(), &payment.transfer.outputs[1], 4).is_none(),
            "B must not detect A's change as a receipt"
        );

        // Install B's view: the leaf vector, B's resolved reserve note, and
        // the detected received note.
        st_b.install_leaves_for_test(leaves, &[(b_reserve.index, 5)]);
        st_b.install_received_for_test(vec![received]);
        assert_eq!(st_b.balance(), 600, "B's spendable balance is the receipt");

        // B spends the received note: pays Carol 200, using [received(600),
        // reserve(0)] as the two inputs. Real proof over the same tree.
        let carol_addr = Address::from_spending_key(&sk_c());
        let b_payment = pay(
            &sk_b(),
            &st_b,
            carol_addr,
            200,
            FEE,
            &mut StdRng::seed_from_u64(5),
        )
        .expect("B spends the received note");
        let b_proof = wire_proof(&b_payment.transfer);
        verify_transfer(&st_b.anchor_tree().unwrap(), &b_proof, FEE)
            .expect("B's onward payment verifies");
        assert_eq!(b_payment.change.value, 600 - 200 - FEE);

        // Carol can open B's payment; B consumed the received note (its
        // nullifier is revealed).
        let c_out = &b_payment.transfer.outputs[0];
        let (carol_got, _) = decrypt_note(sk_c().nk(), &c_out.epk, &c_out.ct, &c_out.note_cm)
            .expect("Carol decrypts");
        assert_eq!(carol_got.value, 200);
        assert!(b_payment.nullifiers.contains(&received.nullifier(&sk_b())));
    }

    // ----- error paths -----

    #[test]
    fn insufficient_funds_refuses() {
        let st = funded_wallet(&sk_a(), [100, 50]);
        let bob = Address::from_spending_key(&sk_b());
        assert!(matches!(
            pay(&sk_a(), &st, bob, 1_000, FEE, &mut StdRng::seed_from_u64(6)),
            Err(PayError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn too_few_notes_refuses() {
        let mut st = WalletState::new();
        let a = st.add_note(1_000);
        st.install_leaves_for_test(vec![a.commitment(&sk_a())], &[(a.index, 0)]);
        let bob = Address::from_spending_key(&sk_b());
        assert!(matches!(
            pay(&sk_a(), &st, bob, 100, FEE, &mut StdRng::seed_from_u64(7)),
            Err(PayError::NotEnoughNotes { have: 1 })
        ));
    }

    #[test]
    fn tampering_the_payment_ct_breaks_detection() {
        let st = funded_wallet(&sk_a(), [1_000, 500]);
        let bob = Address::from_spending_key(&sk_b());
        let mut payment =
            pay(&sk_a(), &st, bob, 600, FEE, &mut StdRng::seed_from_u64(8)).expect("pay");
        payment.transfer.outputs[0].ct[0] ^= 0x01;
        assert!(
            crate::notes::detect_received(&sk_b(), &payment.transfer.outputs[0], 3).is_none(),
            "a tampered ct must not decrypt"
        );
    }
}
