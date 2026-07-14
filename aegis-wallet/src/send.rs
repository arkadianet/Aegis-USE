//! Self-transfer / consolidation (M4 slice 2, `wallet-design.md` §5).
//!
//! The only send this slice can build is a **self-transfer**: consume two
//! of the wallet's own notes and pay the value back to itself as change,
//! minus the flat `sc_tx_fee`. That is the note-consolidation primitive
//! (the "pay 16 with several $1 notes" answer of §5) *and* the way the
//! wallet tops up its zero-value reserve for the fixed 2-in/2-out arity —
//! each consolidation emits `[change, zero]`.
//!
//! Sending to *another party* lives in [`crate::pay`]; everything here
//! stays on self-owned notes, whose secrets the wallet re-derives from
//! `sk` rather than by decryption.
//!
//! Both outputs are nonetheless encrypted to the wallet's *own* address
//! with the same note-encryption primitive `pay` uses, so a self-transfer
//! is byte-indistinguishable from a payment on the wire (§6 uniformity —
//! an observer must not be able to tell a consolidation from a spend). A
//! scan still recognizes these outputs as own notes by commitment, so
//! they are never double-counted as receipts.

use aegis_crypto::generators::EvenPoint;
use aegis_crypto::note::note_cm_bytes;
use aegis_crypto::note_encryption::{encrypt_note, EncryptedNote, MEMO_BYTES};
use aegis_crypto::nullifier::NF_BYTES;
use aegis_crypto::spend::{prove_transfer, SpendError, TransferProof};
use aegis_types::{ShieldedOutput, ShieldedTransfer};
use ark_serialize::CanonicalSerialize;
use rand::Rng;

use crate::address::Address;
use crate::keys::SpendingKey;
use crate::notes::SelfNote;
use crate::state::WalletState;

#[derive(Debug, thiserror::Error)]
pub enum ConsolidateError {
    #[error("need two spendable notes to consolidate, have {have}")]
    NotEnoughNotes { have: usize },
    #[error("inputs total {total} do not cover the fee {fee}")]
    FeeExceedsInputs { total: u64, fee: u64 },
    #[error("no anchor: the wallet has scanned no leaves to prove against")]
    NoAnchor,
    #[error("spend proof failed: {0}")]
    Spend(#[from] SpendError),
}

/// A built self-transfer: the wire transfer to submit, the two output
/// notes it creates (`[change, zero-reserve]`), the derivation indices of
/// the two consumed inputs, and the revealed nullifiers (to confirm the
/// spend landed via `/nullifier/{hex}`).
#[derive(Debug, Clone)]
pub struct Consolidation {
    pub transfer: ShieldedTransfer,
    pub outputs: [SelfNote; 2],
    pub spent_indices: [u64; 2],
    pub nullifiers: [[u8; NF_BYTES]; 2],
}

impl Consolidation {
    /// Commit this consolidation to wallet state after the node accepts
    /// it: journal the two output notes and mark the two inputs spent so
    /// they are not reselected before the next scan confirms them.
    pub fn commit(&self, state: &mut WalletState) {
        for out in &self.outputs {
            state.journal_note(*out);
        }
        for index in &self.spent_indices {
            state.mark_spent(*index);
        }
    }
}

/// Build a 2-in/2-out self-transfer consuming the wallet's two largest
/// spendable notes and paying the balance (minus `fee`) back to itself as
/// change, alongside a fresh zero-value reserve note.
///
/// Pure: does **not** mutate `state`. On success the caller submits the
/// transfer and then [`Consolidation::commit`]s it.
pub fn consolidate<R: Rng>(
    sk: &SpendingKey,
    state: &WalletState,
    fee: u64,
    rng: &mut R,
) -> Result<Consolidation, ConsolidateError> {
    let spendable = state.spendable();
    if spendable.len() < 2 {
        return Err(ConsolidateError::NotEnoughNotes {
            have: spendable.len(),
        });
    }
    let in_0 = spendable[0];
    let in_1 = spendable[1];
    let total = in_0.note.value + in_1.note.value;
    let change_value = total
        .checked_sub(fee)
        .ok_or(ConsolidateError::FeeExceedsInputs { total, fee })?;

    let anchor = state.anchor_tree().ok_or(ConsolidateError::NoAnchor)?;

    // Openings — `is_spendable` guaranteed a resolved leaf index above.
    let inputs = [
        in_0.note
            .opening(sk, in_0.leaf_index.expect("spendable ⇒ resolved")),
        in_1.note
            .opening(sk, in_1.leaf_index.expect("spendable ⇒ resolved")),
    ];

    // Outputs at the next two derivation indices: change, then a
    // zero-value reserve. Indices are fixed now so the built commitments
    // match what a later scan re-derives.
    let base = state.next_index();
    let change = SelfNote::new(base, change_value);
    let reserve = SelfNote::new(base + 1, 0);
    let outputs = [change.output(sk), reserve.output(sk)];

    let proof = prove_transfer(&anchor, &inputs, &outputs, fee, rng)?;

    // Encrypt both outputs to the wallet's own address so the transfer is
    // byte-indistinguishable from a payment (§6 uniformity). Recovery is
    // still by re-derivation on scan; the ciphertext exists only to match
    // a payment's wire shape (and, as a bonus, lets `ovk`/`nk` recover the
    // change if the journal is ever lost).
    let ovk = sk.ovk().0;
    let own_pk = Address::from_spending_key(sk).payment_address();
    let memo = [0u8; MEMO_BYTES];
    let enc = [
        encrypt_note(
            &own_pk,
            &change.payment_opening(sk),
            &memo,
            &note_cm_bytes(&proof.output_cms[0]),
            &ovk,
            rng,
        ),
        encrypt_note(
            &own_pk,
            &reserve.payment_opening(sk),
            &memo,
            &note_cm_bytes(&proof.output_cms[1]),
            &ovk,
            rng,
        ),
    ];
    let transfer = assemble_transfer(&proof, enc);

    Ok(Consolidation {
        transfer,
        outputs: [change, reserve],
        spent_indices: [in_0.note.index, in_1.note.index],
        nullifiers: proof.nullifiers(),
    })
}

/// Assemble the wire [`ShieldedTransfer`] from a proof and the two output
/// ciphertexts: the revealed nullifiers, the output commitments with their
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
    use aegis_crypto::spend::verify_transfer;
    use aegis_types::ShieldedTransfer as WireTransfer;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const FEE: u64 = 10; // dev-net sc_tx_fee

    fn sk() -> SpendingKey {
        SpendingKey::from_bytes([0x44; 32])
    }

    /// A wallet state whose two notes (1000, 500) are real leaves in a
    /// small tree, plus an unrelated third leaf so the tree is not only
    /// ours. Mirrors how a scan would leave the state.
    fn funded_state() -> WalletState {
        let mut st = WalletState::new();
        let a = st.add_note(1_000);
        let b = st.add_note(500);
        // Build the leaf vector the scanner would have produced.
        let extra = SelfNote::new(99, 77).commitment(&sk());
        let leaves = vec![a.commitment(&sk()), b.commitment(&sk()), extra];
        // Reuse scan's resolution by hand: set leaves + indices.
        seed_scanned(&mut st, leaves);
        st
    }

    /// Test shim: install a leaf vector and resolve the journalled notes
    /// against it (what `scan` does, without a node).
    fn seed_scanned(st: &mut WalletState, leaves: Vec<aegis_crypto::generators::EvenPoint>) {
        use aegis_crypto::note::note_cm_bytes;
        let cms: Vec<_> = leaves.iter().map(note_cm_bytes).collect();
        // SAFETY of intent: resolve via the same commitment match scan uses.
        let resolved: Vec<(u64, usize)> = st
            .notes()
            .iter()
            .filter_map(|t| {
                let target = note_cm_bytes(&t.note.commitment(&sk()));
                cms.iter()
                    .position(|c| *c == target)
                    .map(|i| (t.note.index, i))
            })
            .collect();
        st.install_leaves_for_test(leaves, &resolved);
    }

    // ----- happy path -----

    #[test]
    fn consolidate_builds_a_verifying_self_transfer() {
        let st = funded_state();
        let c = consolidate(&sk(), &st, FEE, &mut StdRng::seed_from_u64(1)).expect("consolidate");

        // The change note carries all the value minus the fee; the
        // reserve is zero.
        assert_eq!(c.outputs[0].value, 1_500 - FEE);
        assert_eq!(c.outputs[1].value, 0);
        assert_eq!(c.spent_indices, [0, 1]);

        // The proof verifies against the same anchor, at the same fee.
        let proof = wire_proof(&c.transfer);
        verify_transfer(&st.anchor_tree().unwrap(), &proof, FEE).expect("proof verifies");
    }

    #[test]
    fn wire_outputs_are_the_wallets_own_notes() {
        // The on-wire note_cm must equal the output SelfNote's commitment,
        // so the next scan re-recognizes the change/reserve as ours.
        let st = funded_state();
        let c = consolidate(&sk(), &st, FEE, &mut StdRng::seed_from_u64(2)).unwrap();
        for (i, out) in c.outputs.iter().enumerate() {
            assert_eq!(
                c.transfer.outputs[i].note_cm,
                aegis_crypto::note::note_cm_bytes(&out.commitment(&sk()))
            );
        }
    }

    #[test]
    fn consolidate_outputs_carry_real_ciphertext_not_zero_fill() {
        // §6 uniformity: a self-transfer must look exactly like a payment
        // on the wire — no zero-ciphertext tell that marks it a self-move.
        use aegis_spec::{EPK_BYTES, NOTE_CT_BYTES, NOTE_OUT_CT_BYTES};
        let st = funded_state();
        let c = consolidate(&sk(), &st, FEE, &mut StdRng::seed_from_u64(6)).unwrap();
        for out in &c.transfer.outputs {
            assert_ne!(out.epk, [0u8; EPK_BYTES], "epk must be a real ephemeral");
            assert_ne!(out.ct, [0u8; NOTE_CT_BYTES], "ct must be real ciphertext");
            assert_ne!(out.out_ct, [0u8; NOTE_OUT_CT_BYTES], "out_ct must be real");
        }
    }

    #[test]
    fn consolidate_change_decrypts_to_self() {
        // The change is encrypted to the wallet's own address, so `nk`
        // recovers it (bonus recovery path if the journal is ever lost).
        let st = funded_state();
        let c = consolidate(&sk(), &st, FEE, &mut StdRng::seed_from_u64(7)).unwrap();
        let out = &c.transfer.outputs[0];
        let (opening, _memo) =
            aegis_crypto::note_encryption::decrypt_note(sk().nk(), &out.epk, &out.ct, &out.note_cm)
                .expect("own change decrypts with nk");
        assert_eq!(opening.value, c.outputs[0].value);
    }

    #[test]
    fn revealed_nullifiers_are_the_input_notes_nullifiers() {
        let st = funded_state();
        let c = consolidate(&sk(), &st, FEE, &mut StdRng::seed_from_u64(3)).unwrap();
        let spendable = st.spendable();
        assert_eq!(c.nullifiers[0], spendable[0].note.nullifier(&sk()));
        assert_eq!(c.nullifiers[1], spendable[1].note.nullifier(&sk()));
    }

    #[test]
    fn commit_journals_outputs_and_marks_inputs_spent() {
        let mut st = funded_state();
        assert_eq!(st.balance(), 1_500);
        let c = consolidate(&sk(), &st, FEE, &mut StdRng::seed_from_u64(4)).unwrap();
        c.commit(&mut st);
        // Inputs spent ⇒ removed from balance; outputs journalled but not
        // yet resolved (need a scan) ⇒ do not count yet.
        assert_eq!(st.balance(), 0);
        assert_eq!(st.next_index(), c.outputs[1].index + 1);
    }

    // ----- error paths -----

    #[test]
    fn too_few_notes_refuses() {
        let mut st = WalletState::new();
        let a = st.add_note(1_000);
        seed_scanned(&mut st, vec![a.commitment(&sk())]);
        assert!(matches!(
            consolidate(&sk(), &st, FEE, &mut StdRng::seed_from_u64(5)),
            Err(ConsolidateError::NotEnoughNotes { have: 1 })
        ));
    }

    #[test]
    fn fee_above_inputs_refuses() {
        let st = funded_state();
        assert!(matches!(
            consolidate(&sk(), &st, 10_000, &mut StdRng::seed_from_u64(6)),
            Err(ConsolidateError::FeeExceedsInputs { .. })
        ));
    }

    fn wire_proof(tx: &WireTransfer) -> TransferProof {
        use ark_serialize::CanonicalDeserialize;
        TransferProof::deserialize_compressed(tx.proof.as_slice()).expect("proof roundtrips")
    }
}
