//! S1 value-path spend circuit (G2-P3 slice 1; plan
//! `dev-docs/plans/2026-07-12-g2-phase3-spend-circuit.md`).
//!
//! A 2-in/2-out transfer proof over the consensus Curve Tree:
//! - **membership** of each input note (select-and-rerandomize; the
//!   leaf index stays hidden — the anonymity mechanism, §4),
//! - **range**: every output value ∈ [0, 2^64) (B3),
//! - **balance**: `Σ inputs = Σ outputs + fee`, with `fee` substituted
//!   by the *verifier* as a public constant (N4 — a proof built for a
//!   different fee does not verify).
//!
//! # N1: nullifier binding (production fix — P0 malleability CLOSED)
//!
//! The nullifier is `nf = Poseidon(x)` where `x = nk+rho` is opened
//! from the public key commitment `C*` (bound to the note by the S2b
//! tag→`C*` select). It is a **field element** revealed publicly and
//! constrained in the odd CS by `Poseidon(x) == nf` (see `poseidon`).
//! There is no group element, no hiding commitment, and no free/blinding
//! component — so a prover cannot vary the revealed `nf` (the earlier P0:
//! `nf` exposed via `odd.commit`, blinding unconstrained → multiple
//! nullifiers per note). `nf` depends only on the pinned sum `x`, NOT on
//! the `(nk, rho)` split (which `C*` does not pin), so a re-split cannot
//! mint a second nullifier. Single-circuit: no cross-cycle, no aliasing.
//!
//! Uniqueness is definitional (a hash of note-bound inputs), not derived
//! from a chain of assumptions. The one bounded external-review item is
//! the Poseidon-over-`F_p` parameter set (`poseidon` module). Decision +
//! rationale: `dev-docs/sidechain/n1-nullifier-fix-design.md` §0/§0b.
//!
//! ## S2b: tag→C* ownership binding (unchanged)
//! Each input binds its tag slot to a public rerandomized key commitment
//! `C* = C + r_t·H` (one `single_level_select_and_rerandomize` in the
//! even CS at a public index — PRF.md), and the odd CS opens `C*` to the
//! value `x` that feeds `Poseidon(x)` above. The tree's `delta` shift
//! doubles as a sign-breaker at the select level (NUMS `Δ`) — flagged
//! for external review.
//!
//! ## Remaining gaps (typed, deliberate)
//! Dummy-input uniformity (§6) is S3; the node does not yet verify
//! these proofs or compare revealed nullifiers to the wire (S4), so
//! consensus stays on `ProofMode::DevStub`; spend-authorization beyond
//! nk-knowledge (§2 ak-signature) is S6.
//!
//! Commitments on this path are the circuit-compatible forms under the
//! reference-derived tree parameters ([`consensus_note_commitment`],
//! [`consensus_key_commitment`]); the §0 aegis-tagged generators
//! (`note`, `keynote`) remain the specified freeze-time forms
//! (DEFERRED).

use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use ark_std::UniformRand;
use curve_trees_bulletproofs::r1cs::{
    batch_verify, constant, ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof,
    Verifier,
};
use curve_trees_relations::range_proof::range_proof;
use curve_trees_relations::single_level_select_and_rerandomize::single_level_select_and_rerandomize;
use merlin::Transcript;
use rand::Rng;

use crate::generators::{EvenPoint, OddPoint};
use crate::note::EvenScalar;
use crate::nullifier::{nf_bytes, OddScalar, NF_BYTES};
use crate::poseidon;
use crate::tree::{tree_params, AegisPath, AegisTree, TREE_L};

/// Transcript domain for the spend proof (consensus-pinned).
pub const SPEND_DOMAIN: &[u8] = b"aegis:spend:v1";

/// v1 circuit-path note commitment: the vector commitment
/// `commit([value, tag], blinding)` under the tree parameters' even
/// generators — the form the spend circuit opens in-circuit.
pub fn consensus_note_commitment(value: u64, tag: EvenScalar, blinding: EvenScalar) -> EvenPoint {
    tree_params()
        .even_parameters
        .commit(&[EvenScalar::from(value), tag], blinding, 0)
}

/// v1 circuit-path key commitment `C = (nk+rho)·B + r_key·B_blinding`
/// under the tree parameters' odd Pedersen generators (the bases the
/// odd-CS opening uses).
pub fn consensus_key_commitment(nk: OddScalar, rho: OddScalar, r_key: OddScalar) -> OddPoint {
    let pc = &tree_params().odd_parameters.pc_gens;
    (pc.B * (nk + rho) + pc.B_blinding * r_key).into_affine()
}

/// v1 circuit-path note tag: the x-coordinate of the **delta-shifted**
/// key commitment `(C + Δ_odd).x` — the select-and-rerandomize gadget
/// commits children delta-shifted, so the tag slot must too.
pub fn consensus_note_tag(nk: OddScalar, rho: OddScalar, r_key: OddScalar) -> EvenScalar {
    let shifted = (consensus_key_commitment(nk, rho, r_key) + tree_params().odd_parameters.delta)
        .into_affine();
    *shifted
        .x()
        .expect("delta-shifted key commitment is never the identity")
}

/// Everything the prover knows about an input note. The tag is derived
/// ([`consensus_note_tag`]), never stored.
pub struct NoteOpening {
    pub value: u64,
    pub blinding: EvenScalar,
    /// Position of the note commitment in the consensus leaf vector.
    /// Witness-only: never revealed by the proof.
    pub leaf_index: usize,
    /// Nullifier key (§2 split key — only the spender holds it).
    pub nk: OddScalar,
    /// Structurally unique note nonce (§3 rho discipline).
    pub rho: OddScalar,
    /// Blinding of the key commitment.
    pub r_key: OddScalar,
}

impl NoteOpening {
    fn tag(&self) -> EvenScalar {
        consensus_note_tag(self.nk, self.rho, self.r_key)
    }
}

/// A new note to create.
pub struct TransferOutput {
    pub value: u64,
    pub tag: EvenScalar,
    pub blinding: EvenScalar,
}

/// The transfer proof: two Bulletproofs (even/odd transcript halves),
/// the two rerandomized membership paths, the output commitments, and
/// per input the rerandomized key commitment `C*` plus the revealed
/// nullifier point (consensus uses its x-extract, [`Self::nullifiers`]).
#[derive(Clone)]
pub struct TransferProof {
    pub even_proof: R1CSProof<EvenPoint>,
    pub odd_proof: R1CSProof<OddPoint>,
    pub path_0: AegisPath,
    pub path_1: AegisPath,
    pub output_cms: [EvenPoint; 2],
    pub key_cms: [OddPoint; 2],
    pub nfs: [OddScalar; 2],
}

impl TransferProof {
    /// The consensus nullifiers: x-extracts of the revealed points —
    /// what the node compares to the wire `ShieldedTransfer.nullifiers`
    /// (S4). Sign-invariant: `±nf_point` extract identically.
    pub fn nullifiers(&self) -> [[u8; NF_BYTES]; 2] {
        [nf_bytes(self.nfs[0]), nf_bytes(self.nfs[1])]
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpendError {
    #[error("inputs do not cover outputs + fee")]
    Unbalanced,
    #[error("input {0} opening does not match the selected leaf")]
    WrongOpening(usize),
    #[error("nk + rho = 0: no nullifier exists (reject at mint, N12)")]
    ZeroDenominator,
    #[error("r1cs failure: {0}")]
    R1cs(#[from] R1CSError),
}

/// Prove a 2-in/2-out transfer against `tree`. `fee` must equal the
/// consensus `sc_tx_fee` the verifier will substitute.
pub fn prove_transfer<R: Rng>(
    tree: &AegisTree,
    inputs: &[NoteOpening; 2],
    outputs: &[TransferOutput; 2],
    fee: u64,
    rng: &mut R,
) -> Result<TransferProof, SpendError> {
    prove_transfer_inner(tree, inputs, outputs, fee, rng)
}

fn prove_transfer_inner<R: Rng>(
    tree: &AegisTree,
    inputs: &[NoteOpening; 2],
    outputs: &[TransferOutput; 2],
    fee: u64,
    rng: &mut R,
) -> Result<TransferProof, SpendError> {
    // Prover-side sanity; the in-circuit constraint is what binds.
    let in_sum: u128 = inputs.iter().map(|i| u128::from(i.value)).sum();
    let out_sum: u128 = outputs.iter().map(|o| u128::from(o.value)).sum::<u128>() + u128::from(fee);
    if in_sum != out_sum {
        return Err(SpendError::Unbalanced);
    }

    let params = tree_params();
    let mut even_prover: Prover<_, EvenPoint> = Prover::new(
        &params.even_parameters.pc_gens,
        Transcript::new(SPEND_DOMAIN),
    );
    let mut odd_prover: Prover<_, OddPoint> = Prover::new(
        &params.odd_parameters.pc_gens,
        Transcript::new(SPEND_DOMAIN),
    );

    // Outputs: commit + 64-bit range proof on the value slot.
    let mut output_cms = Vec::with_capacity(2);
    let mut out_value_vars = Vec::with_capacity(2);
    for out in outputs {
        let (cm, vars) = even_prover.commit_vec(
            &[EvenScalar::from(out.value), out.tag],
            out.blinding,
            &params.even_parameters.bp_gens,
        );
        range_proof(&mut even_prover, vars[0].into(), Some(out.value), 64)?;
        output_cms.push(cm);
        out_value_vars.push(vars[0]);
    }

    // Inputs: select-and-rerandomize membership, open the rerandomized
    // leaf as a [value, tag] commitment, bind the tag slot to the
    // rerandomized key commitment C*, and prove the nullifier relation.
    let mut paths = Vec::with_capacity(2);
    let mut in_value_vars = Vec::with_capacity(2);
    let mut key_cms = Vec::with_capacity(2);
    let mut nfs = Vec::with_capacity(2);
    for (i, input) in inputs.iter().enumerate() {
        let (path, rerandomization) = tree.select_and_rerandomize_prover_gadget(
            input.leaf_index,
            0,
            &mut even_prover,
            &mut odd_prover,
            params,
            rng,
        );
        let (rerandomized_leaf, vars) = even_prover.commit_vec(
            &[EvenScalar::from(input.value), input.tag()],
            input.blinding + rerandomization,
            &params.even_parameters.bp_gens,
        );
        if path.selected_commitment != rerandomized_leaf {
            return Err(SpendError::WrongOpening(i));
        }

        // Even CS: tag slot == (C + Δ).x, revealed as C* = C + r_t·H
        // (a one-child select at a public index, per PRF.md).
        let x = input.nk + input.rho;
        let c = consensus_key_commitment(input.nk, input.rho, input.r_key);
        let r_t = OddScalar::rand(rng);
        let c_star = (c + params.odd_parameters.pc_gens.B_blinding * r_t).into_affine();
        let c_plus_delta = (c + params.odd_parameters.delta).into_affine();
        single_level_select_and_rerandomize(
            &mut even_prover,
            &params.odd_parameters,
            &c_star,
            vec![vars[1].into()],
            Some(c_plus_delta),
            Some(r_t),
        );

        // Odd CS: open C* → x (= nk+rho), then bind the public
        // nullifier nf = Poseidon(x) — a field element with no free
        // component (N1). x is the value C* pins, so nf binds to the
        // authorized note.
        let (c_star_cm, x_var) = odd_prover.commit(x, input.r_key + r_t);
        debug_assert_eq!(c_star_cm, c_star, "C* must re-open under (x, r_key + r_t)");
        let nf = poseidon::hash1(x);
        let nf_lc = poseidon::hash1_gadget(&mut odd_prover, x_var.into());
        odd_prover.constrain(nf_lc - constant(nf));

        paths.push(path);
        in_value_vars.push(vars[0]);
        key_cms.push(c_star);
        nfs.push(nf);
    }

    // Balance with the fee as a circuit constant (N4).
    let balance: LinearCombination<EvenScalar> =
        out_value_vars[0] + out_value_vars[1] - in_value_vars[0] - in_value_vars[1]
            + constant(EvenScalar::from(fee));
    even_prover.constrain(balance);

    let even_proof = even_prover.prove(&params.even_parameters.bp_gens)?;
    let odd_proof = odd_prover.prove(&params.odd_parameters.bp_gens)?;

    let mut paths = paths.into_iter();
    Ok(TransferProof {
        even_proof,
        odd_proof,
        path_0: paths.next().expect("two paths"),
        path_1: paths.next().expect("two paths"),
        output_cms: output_cms.try_into().expect("two outputs"),
        key_cms: key_cms.try_into().expect("two key commitments"),
        nfs: nfs.try_into().expect("two nullifiers"),
    })
}

/// Verify a transfer against `tree`, substituting the consensus `fee`.
pub fn verify_transfer(
    tree: &AegisTree,
    proof: &TransferProof,
    fee: u64,
) -> Result<(), SpendError> {
    let params = tree_params();

    // Recompute the internal path commitments from the tree root.
    let mut path_0 = proof.path_0.clone();
    tree.select_and_rerandomize_verification_commitments(&mut path_0);
    let mut path_1 = proof.path_1.clone();
    tree.select_and_rerandomize_verification_commitments(&mut path_1);

    // Even half — must mirror the prover's gadget order exactly.
    let mut even_verifier: Verifier<_, EvenPoint> = Verifier::new(Transcript::new(SPEND_DOMAIN));
    let mut out_value_vars = Vec::with_capacity(2);
    for cm in &proof.output_cms {
        let vars = even_verifier.commit_vec(2, *cm);
        range_proof(&mut even_verifier, vars[0].into(), None, 64)?;
        out_value_vars.push(vars[0]);
    }
    let mut in_value_vars = Vec::with_capacity(2);
    for (path, key_cm) in [&path_0, &path_1].into_iter().zip(&proof.key_cms) {
        path.even_verifier_gadget(&mut even_verifier, params, tree);
        let vars = even_verifier.commit_vec(TREE_L, path.get_rerandomized_leaf());
        in_value_vars.push(vars[0]);
        // Tag slot == (C + Δ).x, revealed as the public C*.
        single_level_select_and_rerandomize(
            &mut even_verifier,
            &params.odd_parameters,
            key_cm,
            vec![vars[1].into()],
            None,
            None,
        );
    }
    let balance: LinearCombination<EvenScalar> =
        out_value_vars[0] + out_value_vars[1] - in_value_vars[0] - in_value_vars[1]
            + constant(EvenScalar::from(fee));
    even_verifier.constrain(balance);
    let even_vt = even_verifier.verification_scalars_and_points(&proof.even_proof)?;

    // Odd half — per input: tree gadget, then bind nf = Poseidon(x)
    // where x is opened from the public C*.
    let mut odd_verifier: Verifier<_, OddPoint> = Verifier::new(Transcript::new(SPEND_DOMAIN));
    for ((path, key_cm), nf) in [&path_0, &path_1]
        .into_iter()
        .zip(&proof.key_cms)
        .zip(&proof.nfs)
    {
        path.odd_verifier_gadget(&mut odd_verifier, params, tree);
        let x_var = odd_verifier.commit(*key_cm);
        let nf_lc = poseidon::hash1_gadget(&mut odd_verifier, x_var.into());
        odd_verifier.constrain(nf_lc - constant(*nf));
    }
    let odd_vt = odd_verifier.verification_scalars_and_points(&proof.odd_proof)?;

    batch_verify(
        vec![even_vt],
        &params.even_parameters.pc_gens,
        &params.even_parameters.bp_gens,
    )?;
    batch_verify(
        vec![odd_vt],
        &params.odd_parameters.pc_gens,
        &params.odd_parameters.bp_gens,
    )?;
    Ok(())
}

impl CanonicalSerialize for TransferProof {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.even_proof.serialize_with_mode(&mut writer, compress)?;
        self.odd_proof.serialize_with_mode(&mut writer, compress)?;
        self.path_0.serialize_with_mode(&mut writer, compress)?;
        self.path_1.serialize_with_mode(&mut writer, compress)?;
        self.output_cms[0].serialize_with_mode(&mut writer, compress)?;
        self.output_cms[1].serialize_with_mode(&mut writer, compress)?;
        self.key_cms[0].serialize_with_mode(&mut writer, compress)?;
        self.key_cms[1].serialize_with_mode(&mut writer, compress)?;
        self.nfs[0].serialize_with_mode(&mut writer, compress)?;
        self.nfs[1].serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.even_proof.serialized_size(compress)
            + self.odd_proof.serialized_size(compress)
            + self.path_0.serialized_size(compress)
            + self.path_1.serialized_size(compress)
            + self.output_cms[0].serialized_size(compress)
            + self.output_cms[1].serialized_size(compress)
            + self.key_cms[0].serialized_size(compress)
            + self.key_cms[1].serialized_size(compress)
            + self.nfs[0].serialized_size(compress)
            + self.nfs[1].serialized_size(compress)
    }
}

impl Valid for TransferProof {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for TransferProof {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(Self {
            even_proof: R1CSProof::deserialize_with_mode(&mut reader, compress, validate)?,
            odd_proof: R1CSProof::deserialize_with_mode(&mut reader, compress, validate)?,
            path_0: AegisPath::deserialize_with_mode(&mut reader, compress, validate)?,
            path_1: AegisPath::deserialize_with_mode(&mut reader, compress, validate)?,
            output_cms: [
                EvenPoint::deserialize_with_mode(&mut reader, compress, validate)?,
                EvenPoint::deserialize_with_mode(&mut reader, compress, validate)?,
            ],
            key_cms: [
                OddPoint::deserialize_with_mode(&mut reader, compress, validate)?,
                OddPoint::deserialize_with_mode(&mut reader, compress, validate)?,
            ],
            nfs: [
                OddScalar::deserialize_with_mode(&mut reader, compress, validate)?,
                OddScalar::deserialize_with_mode(&mut reader, compress, validate)?,
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::build_tree;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // ----- helpers -----

    const FEE: u64 = 10; // dev-net sc_tx_fee (0.01 USE)

    fn scalar(n: u64) -> EvenScalar {
        EvenScalar::from(n)
    }

    struct Fixture {
        tree: AegisTree,
        inputs: [NoteOpening; 2],
    }

    fn opening(value: u64, seed: u64, leaf_index: usize) -> NoteOpening {
        NoteOpening {
            value,
            blinding: scalar(seed),
            leaf_index,
            nk: OddScalar::from(seed + 1),
            rho: OddScalar::from(seed + 2),
            r_key: OddScalar::from(seed + 3),
        }
    }

    fn leaf_of(o: &NoteOpening) -> EvenPoint {
        consensus_note_commitment(
            o.value,
            consensus_note_tag(o.nk, o.rho, o.r_key),
            o.blinding,
        )
    }

    /// Two spendable notes (1000 + 500) in a small consensus tree.
    fn fixture() -> Fixture {
        let in_0 = opening(1_000, 0x21, 0);
        let in_1 = opening(500, 0x22, 1);
        // an unrelated note so the tree is not only our inputs
        let extra = opening(77, 0x23, 2);
        let leaves = vec![leaf_of(&in_0), leaf_of(&in_1), leaf_of(&extra)];
        Fixture {
            tree: build_tree(&leaves),
            inputs: [in_0, in_1],
        }
    }

    fn outputs_totalling(total: u64) -> [TransferOutput; 2] {
        [
            TransferOutput {
                value: total - 100,
                tag: scalar(0x31),
                blinding: scalar(0x41),
            },
            TransferOutput {
                value: 100,
                tag: scalar(0x32),
                blinding: scalar(0x42),
            },
        ]
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xAE915)
    }

    fn valid_proof(fx: &Fixture) -> TransferProof {
        prove_transfer(
            &fx.tree,
            &fx.inputs,
            &outputs_totalling(1_500 - FEE),
            FEE,
            &mut rng(),
        )
        .expect("valid transfer must prove")
    }

    // ----- happy path -----

    #[test]
    fn balanced_transfer_proves_and_verifies() {
        let fx = fixture();
        let proof = valid_proof(&fx);
        verify_transfer(&fx.tree, &proof, FEE).expect("valid proof must verify");
    }

    // ----- round-trips -----

    #[test]
    fn transfer_proof_roundtrips_and_fits_wire_budget() {
        let fx = fixture();
        let proof = valid_proof(&fx);
        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        assert!(
            bytes.len() <= aegis_spec_max_proof_bytes(),
            "proof {} bytes exceeds MAX_PROOF_BYTES",
            bytes.len()
        );
        let back = TransferProof::deserialize_compressed(bytes.as_slice()).unwrap();
        verify_transfer(&fx.tree, &back, FEE).expect("roundtripped proof must verify");
    }

    /// Kept in sync with `aegis_spec::MAX_PROOF_BYTES` by value (this
    /// crate does not depend on aegis-spec; the node-side wire test
    /// enforces the real constant).
    fn aegis_spec_max_proof_bytes() -> usize {
        8_192
    }

    // ----- error paths -----

    #[test]
    fn unbalanced_transfer_refuses_to_prove() {
        let fx = fixture();
        let outs = outputs_totalling(1_500); // ignores the fee
        assert!(matches!(
            prove_transfer(&fx.tree, &fx.inputs, &outs, FEE, &mut rng()),
            Err(SpendError::Unbalanced)
        ));
    }

    #[test]
    fn wrong_fee_at_verification_rejects() {
        // The verifier substitutes ITS consensus fee: a proof built for
        // FEE must not verify under FEE+1 (or 0).
        let fx = fixture();
        let proof = valid_proof(&fx);
        assert!(verify_transfer(&fx.tree, &proof, FEE + 1).is_err());
        assert!(verify_transfer(&fx.tree, &proof, 0).is_err());
    }

    #[test]
    fn wrong_tree_at_verification_rejects() {
        let fx = fixture();
        let proof = valid_proof(&fx);
        let other_tree = build_tree(&[consensus_note_commitment(1, scalar(2), scalar(3))]);
        assert!(verify_transfer(&other_tree, &proof, FEE).is_err());
    }

    #[test]
    fn tampered_output_commitment_rejects() {
        let fx = fixture();
        let mut proof = valid_proof(&fx);
        proof.output_cms.swap(0, 1);
        assert!(verify_transfer(&fx.tree, &proof, FEE).is_err());
    }

    #[test]
    fn wrong_opening_refuses_to_prove() {
        let fx = fixture();
        let mut inputs = fx.inputs;
        inputs[0].blinding = scalar(0x99); // no longer opens leaf 0
        assert!(matches!(
            prove_transfer(
                &fx.tree,
                &inputs,
                &outputs_totalling(1_500 - FEE),
                FEE,
                &mut rng()
            ),
            Err(SpendError::WrongOpening(0))
        ));
    }

    #[test]
    fn wrong_nullifier_key_refuses_to_prove() {
        // A different nk derives a different tag, which no longer opens
        // the committed leaf — you cannot spend a note you don't hold
        // the key for.
        let fx = fixture();
        let mut inputs = fx.inputs;
        inputs[0].nk += OddScalar::from(1u64);
        assert!(matches!(
            prove_transfer(
                &fx.tree,
                &inputs,
                &outputs_totalling(1_500 - FEE),
                FEE,
                &mut rng()
            ),
            Err(SpendError::WrongOpening(0))
        ));
    }

    #[test]
    fn revealed_nullifiers_match_native_derivation() {
        let fx = fixture();
        let proof = valid_proof(&fx);
        let want = [
            crate::nullifier::poseidon_nullifier(fx.inputs[0].nk, fx.inputs[0].rho),
            crate::nullifier::poseidon_nullifier(fx.inputs[1].nk, fx.inputs[1].rho),
        ];
        assert_eq!(proof.nullifiers(), want);
    }

    #[test]
    fn tampered_nf_rejected() {
        // nf = Poseidon(x) is fully determined by the witness; altering
        // any revealed nf breaks the in-circuit `Poseidon(x) == nf`
        // constraint (there is no free component to absorb the change).
        let fx = fixture();
        let proof = valid_proof(&fx);
        for i in 0..2 {
            let mut bad = proof.clone();
            bad.nfs[i] += OddScalar::from(1u64);
            assert!(
                verify_transfer(&fx.tree, &bad, FEE).is_err(),
                "altered nf must reject"
            );
        }
    }

    #[test]
    fn tampered_key_commitment_rejects() {
        let fx = fixture();
        let mut proof = valid_proof(&fx);
        proof.key_cms.swap(0, 1);
        assert!(verify_transfer(&fx.tree, &proof, FEE).is_err());
    }
}
