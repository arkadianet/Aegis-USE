//! Address-binding payment notes: a SENDER creates a note that a specific
//! RECIPIENT can later spend, without the sender ever learning the
//! recipient's secret spend key. This is the missing "pay another party"
//! primitive — the pre-existing note construction
//! ([`crate::spend::consensus_note_tag`]) needs the secret `nk` to form a
//! note's tag, so only the key holder could create their own notes
//! (self-notes). See `dev-docs/sidechain/payment-primitive-design.md`.
//!
//! # The construction (why no new circuit gadget is needed)
//!
//! A note's ownership is its **key commitment**
//! `K = (nk + rho)·B + r_key·B_blinding` (odd curve, tree Pedersen bases);
//! its tag is `(K + Δ).x`, and the consensus nullifier is
//! `Poseidon(nk + rho)` (the N1 fix). The spend circuit proves the spender
//! knows the opening `x = nk + rho` of `K` and reveals `Poseidon(x)`.
//!
//! The insight: `K` is **additively homomorphic**. Publish the recipient's
//! spend key as the point `pk = nk·B` (their [`PaymentAddress`]). A sender
//! who knows only `pk` (never `nk`) forms the *same* `K` additively:
//!
//! ```text
//! K = pk + rho·B + r_key·B_blinding = (nk + rho)·B + r_key·B_blinding
//! ```
//!
//! choosing `rho` (per §3 rho-discipline) and `r_key` themselves. The
//! resulting leaf commitment is **byte-identical** to the note the
//! recipient would build from `nk`, so the recipient spends it through the
//! unchanged §3 circuit. Ownership is enforced implicitly: opening `K` to
//! the scalar `x = nk + rho` requires knowing `nk = dlog_B(pk)` — the
//! discrete log the sender does not have. No in-circuit variable-base
//! scalar multiplication, and no change to `prove_transfer` /
//! `verify_transfer`, is required.
//!
//! # What this deliberately does NOT provide (see the design note)
//! - The address key is the **spend** key `nk` (Aegis's designated spend
//!   authority), not a separate incoming-viewing key `ivk`. Binding a note
//!   to `ivk` while keying the nullifier on `nk` needs an in-circuit
//!   `nk ↔ ivk` binding that has no cheap algebraic form here — the
//!   documented blocker. Note-detection can still use a separate `ivk` at
//!   the encryption layer (out of scope for this crate).
//! - Note encryption / transmission of the [`PaymentOpening`] to the
//!   recipient is a wallet/protocol concern, not modelled here.

use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::generators::{EvenPoint, OddPoint};
use crate::note::EvenScalar;
use crate::nullifier::OddScalar;
use crate::spend::{consensus_note_commitment, NoteOpening, TransferOutput};
use crate::tree::tree_params;

/// Compressed wire size of a payment address (one odd-curve point).
pub const PAYMENT_ADDRESS_BYTES: usize = 33;

/// A recipient's public payment address: the point `pk = nk·B`, where `B`
/// is the tree's odd Pedersen base and `nk` the recipient's secret spend
/// key. Publishing `pk` reveals nothing about `nk` (discrete-log hard);
/// holding `nk` is spend authority.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PaymentAddress(OddPoint);

impl PaymentAddress {
    /// Derive the address for spend key `nk`: `pk = nk·B`.
    pub fn from_nk(nk: OddScalar) -> Self {
        let b = tree_params().odd_parameters.pc_gens.B;
        PaymentAddress((b * nk).into_affine())
    }

    /// The underlying public-key point.
    pub fn point(&self) -> OddPoint {
        self.0
    }

    /// Canonical compressed bytes.
    pub fn to_bytes(&self) -> [u8; PAYMENT_ADDRESS_BYTES] {
        let mut out = [0u8; PAYMENT_ADDRESS_BYTES];
        self.0
            .serialize_compressed(&mut out[..])
            .expect("33-byte buffer fits a compressed odd-curve point");
        out
    }

    /// Strict decode; `None` for bytes that are not a canonical compressed
    /// odd-curve point.
    pub fn from_bytes(bytes: &[u8; PAYMENT_ADDRESS_BYTES]) -> Option<Self> {
        OddPoint::deserialize_compressed(&bytes[..])
            .ok()
            .map(PaymentAddress)
    }
}

/// The note-opening a sender transmits to the recipient out-of-band
/// (encrypted; the transport is out of scope). Together with the
/// recipient's own `nk` and the discovered leaf position, it reconstructs
/// the spendable [`NoteOpening`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PaymentOpening {
    pub value: u64,
    pub blinding: EvenScalar,
    pub rho: OddScalar,
    pub r_key: OddScalar,
}

/// The sender-formed key commitment `K = pk + rho·B + r_key·B_blinding`.
/// Equal to [`crate::spend::consensus_key_commitment`]`(nk, rho, r_key)`
/// when `pk = nk·B`, but computed without knowledge of `nk`.
fn sender_key_commitment(addr: &PaymentAddress, rho: OddScalar, r_key: OddScalar) -> OddPoint {
    let pc = &tree_params().odd_parameters.pc_gens;
    (pc.B * rho + pc.B_blinding * r_key + addr.0.into_group()).into_affine()
}

/// The note tag for a key commitment: `(K + Δ).x` (the delta-shifted
/// x-coordinate, matching the select-and-rerandomize leaf layout).
fn tag_of_key_commitment(k: OddPoint) -> EvenScalar {
    let shifted = (k + tree_params().odd_parameters.delta).into_affine();
    *shifted
        .x()
        .expect("delta-shifted key commitment is never the identity")
}

/// SENDER side: build the leaf commitment of a note payable to `addr`,
/// plus the [`PaymentOpening`] to hand the recipient. The sender chooses
/// `rho` (respecting §3 structural uniqueness — e.g. `rho_transfer` of a
/// nullifier consumed in the same tx), `r_key`, and the leaf `blinding`.
///
/// The returned commitment is the ordinary spendable note commitment, so
/// it is added to the consensus tree as a normal leaf.
pub fn sender_build_note(
    addr: &PaymentAddress,
    value: u64,
    rho: OddScalar,
    r_key: OddScalar,
    blinding: EvenScalar,
) -> (EvenPoint, PaymentOpening) {
    let k = sender_key_commitment(addr, rho, r_key);
    let tag = tag_of_key_commitment(k);
    let cm = consensus_note_commitment(value, tag, blinding);
    (
        cm,
        PaymentOpening {
            value,
            blinding,
            rho,
            r_key,
        },
    )
}

/// SENDER side: build a [`TransferOutput`] payable to `addr` (the "pay a
/// recipient" analogue of a raw self-tag output). Returns the output and
/// the opening the recipient needs to later spend it.
pub fn output_to_address(
    addr: &PaymentAddress,
    value: u64,
    rho: OddScalar,
    r_key: OddScalar,
    blinding: EvenScalar,
) -> (TransferOutput, PaymentOpening) {
    let k = sender_key_commitment(addr, rho, r_key);
    let tag = tag_of_key_commitment(k);
    (
        TransferOutput {
            value,
            tag,
            blinding,
        },
        PaymentOpening {
            value,
            blinding,
            rho,
            r_key,
        },
    )
}

/// RECIPIENT side: reconstruct the spendable [`NoteOpening`] from the
/// recipient's secret `nk`, the received [`PaymentOpening`], and the leaf
/// position discovered by scanning. Feeds directly into
/// [`crate::spend::prove_transfer`].
///
/// A party lacking the correct `nk` reconstructs an opening whose derived
/// tag does not match the committed leaf, so `prove_transfer` rejects it
/// with [`crate::spend::SpendError::WrongOpening`] — only the address's
/// key holder can spend.
pub fn recipient_note_opening(
    nk: OddScalar,
    opening: &PaymentOpening,
    leaf_index: usize,
) -> NoteOpening {
    NoteOpening {
        value: opening.value,
        blinding: opening.blinding,
        leaf_index,
        nk,
        rho: opening.rho,
        r_key: opening.r_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nullifier::poseidon_nullifier;
    use crate::spend::{
        consensus_key_commitment, consensus_note_commitment, consensus_note_tag, prove_transfer,
        verify_transfer, SpendError,
    };
    use crate::tree::build_tree;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // ----- helpers -----

    const FEE: u64 = 10;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xA5915)
    }

    fn odd(n: u64) -> OddScalar {
        OddScalar::from(n)
    }

    fn even(n: u64) -> EvenScalar {
        EvenScalar::from(n)
    }

    /// Recipient's secret spend key.
    fn recipient_nk() -> OddScalar {
        odd(0xC0FFEE)
    }

    // ----- happy path -----

    #[test]
    fn sender_note_equals_recipients_reconstruction() {
        // The crux: a sender who knows only pk = nk·B builds the SAME leaf
        // commitment the nk-holder would build. Byte-for-byte.
        let nk = recipient_nk();
        let addr = PaymentAddress::from_nk(nk);
        let (rho, r_key, blinding) = (odd(0x11), odd(0x22), even(0x33));

        let (cm_sender, _) = sender_build_note(&addr, 1_000, rho, r_key, blinding);
        let cm_recipient =
            consensus_note_commitment(1_000, consensus_note_tag(nk, rho, r_key), blinding);
        assert_eq!(cm_sender, cm_recipient);
    }

    #[test]
    fn sender_key_commitment_equals_consensus_form() {
        let nk = recipient_nk();
        let addr = PaymentAddress::from_nk(nk);
        let (rho, r_key) = (odd(0x44), odd(0x55));
        assert_eq!(
            sender_key_commitment(&addr, rho, r_key),
            consensus_key_commitment(nk, rho, r_key),
        );
    }

    // ----- round-trips -----

    #[test]
    fn address_bytes_roundtrip() {
        let addr = PaymentAddress::from_nk(recipient_nk());
        let bytes = addr.to_bytes();
        assert_eq!(PaymentAddress::from_bytes(&bytes), Some(addr));
    }

    #[test]
    fn address_from_garbage_bytes_is_none() {
        assert_eq!(
            PaymentAddress::from_bytes(&[0xEE; PAYMENT_ADDRESS_BYTES]),
            None
        );
    }

    // ----- end-to-end payment -----

    /// Build two notes payable to `addr`, put them in a tree, and hand the
    /// recipient the openings + discovered indices. Returns the tree and
    /// the reconstructed spendable openings.
    fn pay_recipient_two_notes(
        addr: &PaymentAddress,
        nk: OddScalar,
    ) -> (crate::tree::AegisTree, [NoteOpening; 2]) {
        let (cm0, op0) = sender_build_note(addr, 1_000, odd(0x71), odd(0x81), even(0x91));
        let (cm1, op1) = sender_build_note(addr, 500, odd(0x72), odd(0x82), even(0x92));
        // An unrelated leaf so the tree is not only our two notes.
        let (extra, _) = sender_build_note(
            &PaymentAddress::from_nk(odd(0xDEAD)),
            77,
            odd(0x73),
            odd(0x83),
            even(0x93),
        );
        let tree = build_tree(&[cm0, cm1, extra]);
        let openings = [
            recipient_note_opening(nk, &op0, 0),
            recipient_note_opening(nk, &op1, 1),
        ];
        (tree, openings)
    }

    #[test]
    fn recipient_spends_received_payment() {
        // Sender pays the recipient two notes; the recipient reconstructs
        // the openings from nk and spends them through the UNCHANGED §3
        // circuit. This is a real payment: the sender never held nk.
        let nk = recipient_nk();
        let addr = PaymentAddress::from_nk(nk);
        let (tree, inputs) = pay_recipient_two_notes(&addr, nk);

        // The recipient forwards the change to a third party's address.
        let bob = PaymentAddress::from_nk(odd(0xB0B));
        let (out0, _) =
            output_to_address(&bob, 1_500 - FEE - 100, odd(0xA1), odd(0xA2), even(0xA3));
        let (out1, _) = output_to_address(&bob, 100, odd(0xA4), odd(0xA5), even(0xA6));

        let proof =
            prove_transfer(&tree, &inputs, &[out0, out1], FEE, &mut rng()).expect("payment proves");
        verify_transfer(&tree, &proof, FEE).expect("payment verifies");
    }

    #[test]
    fn revealed_nullifiers_are_nk_bound() {
        // The spend reveals Poseidon(nk + rho): keyed on the recipient's
        // secret nk. The sender, lacking nk, cannot compute these — so the
        // sender cannot link the recipient's spend (sender-unlinkability).
        let nk = recipient_nk();
        let addr = PaymentAddress::from_nk(nk);
        let (tree, inputs) = pay_recipient_two_notes(&addr, nk);
        let bob = PaymentAddress::from_nk(odd(0xB0B));
        let (out0, _) =
            output_to_address(&bob, 1_500 - FEE - 100, odd(0xA1), odd(0xA2), even(0xA3));
        let (out1, _) = output_to_address(&bob, 100, odd(0xA4), odd(0xA5), even(0xA6));
        let proof =
            prove_transfer(&tree, &inputs, &[out0, out1], FEE, &mut rng()).expect("payment proves");

        let want = [
            poseidon_nullifier(nk, inputs[0].rho),
            poseidon_nullifier(nk, inputs[1].rho),
        ];
        assert_eq!(proof.nullifiers(), want);
        // A different key would yield different nullifiers — the sender
        // (who knows rho but not nk) cannot reproduce them.
        assert_ne!(
            poseidon_nullifier(nk, inputs[0].rho),
            poseidon_nullifier(nk + odd(1), inputs[0].rho),
        );
    }

    // ----- error paths / adversarial -----

    #[test]
    fn non_recipient_cannot_spend() {
        // An attacker holds the full PaymentOpening (value, blinding, rho,
        // r_key) but NOT nk. Reconstructing with a wrong key yields a tag
        // that does not open the committed leaf — prove_transfer rejects.
        let nk = recipient_nk();
        let addr = PaymentAddress::from_nk(nk);
        let (cm0, op0) = sender_build_note(&addr, 1_000, odd(0x71), odd(0x81), even(0x91));
        let (cm1, op1) = sender_build_note(&addr, 500, odd(0x72), odd(0x82), even(0x92));
        let tree = build_tree(&[cm0, cm1]);

        let wrong_nk = odd(0x1BAD);
        let attacker_inputs = [
            recipient_note_opening(wrong_nk, &op0, 0),
            recipient_note_opening(wrong_nk, &op1, 1),
        ];
        let bob = PaymentAddress::from_nk(odd(0xB0B));
        let (out0, _) =
            output_to_address(&bob, 1_500 - FEE - 100, odd(0xA1), odd(0xA2), even(0xA3));
        let (out1, _) = output_to_address(&bob, 100, odd(0xA4), odd(0xA5), even(0xA6));
        assert!(matches!(
            prove_transfer(&tree, &attacker_inputs, &[out0, out1], FEE, &mut rng()),
            Err(SpendError::WrongOpening(0))
        ));
    }

    #[test]
    fn value_is_conserved() {
        // Anti-inflation: outputs whose values exceed inputs − fee cannot
        // be proven (the in-circuit balance constraint).
        let nk = recipient_nk();
        let addr = PaymentAddress::from_nk(nk);
        let (tree, inputs) = pay_recipient_two_notes(&addr, nk);
        let bob = PaymentAddress::from_nk(odd(0xB0B));
        // Claims to output the full 1500, ignoring the fee — unbalanced.
        let (out0, _) = output_to_address(&bob, 1_400, odd(0xA1), odd(0xA2), even(0xA3));
        let (out1, _) = output_to_address(&bob, 100, odd(0xA4), odd(0xA5), even(0xA6));
        assert!(matches!(
            prove_transfer(&tree, &inputs, &[out0, out1], FEE, &mut rng()),
            Err(SpendError::Unbalanced)
        ));
    }

    #[test]
    fn one_note_yields_exactly_one_nullifier() {
        // Nullifier non-malleability (the N1 failure mode): a received
        // note cannot be made to produce a second, distinct valid
        // nullifier. Two independent proofs of the same notes reveal the
        // SAME nullifiers — there is no free component to vary.
        let nk = recipient_nk();
        let addr = PaymentAddress::from_nk(nk);
        let (tree, inputs) = pay_recipient_two_notes(&addr, nk);
        let bob = PaymentAddress::from_nk(odd(0xB0B));

        let mk_outputs = || {
            let (o0, _) =
                output_to_address(&bob, 1_500 - FEE - 100, odd(0xA1), odd(0xA2), even(0xA3));
            let (o1, _) = output_to_address(&bob, 100, odd(0xA4), odd(0xA5), even(0xA6));
            [o0, o1]
        };

        let p1 = prove_transfer(
            &tree,
            &inputs,
            &mk_outputs(),
            FEE,
            &mut StdRng::seed_from_u64(1),
        )
        .unwrap();
        let p2 = prove_transfer(
            &tree,
            &inputs,
            &mk_outputs(),
            FEE,
            &mut StdRng::seed_from_u64(2),
        )
        .unwrap();
        assert_eq!(
            p1.nullifiers(),
            p2.nullifiers(),
            "a note maps to exactly one nullifier regardless of proof randomness"
        );
    }
}
