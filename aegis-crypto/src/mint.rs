//! Mint proof (G2-P3 slice S5): a note created with no shielded input,
//! its value slot pinned to a **public** amount `V` (coinbase reward or
//! PegMint amount) so consensus can rule out inflation without learning
//! the owner's key material.
//!
//! The note commitment is the ordinary spendable form
//! `commit([V, tag], blinding)` under the tree parameters
//! ([`consensus_note_commitment`]), so a minted note is a normal leaf
//! the owner later spends through the §3 circuit. The proof is a single
//! even-CS constraint `value_slot − V = 0` with `V` substituted by the
//! verifier — no range proof is needed (`V` is a known public `u64`,
//! and the constraint pins the committed value exactly). Ownership is
//! **not** proven at mint (a garbage tag only costs the miner the
//! ability to spend — no consensus harm); it is established when the
//! note is spent.

use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use curve_trees_bulletproofs::r1cs::{
    batch_verify, constant, ConstraintSystem, Prover, R1CSError, R1CSProof, Verifier,
};
use merlin::Transcript;
use rand::Rng;

use crate::generators::EvenPoint;
use crate::note::EvenScalar;
use crate::spend::consensus_note_commitment;
use crate::tree::tree_params;

/// Transcript domain for the mint proof (consensus-pinned).
pub const MINT_DOMAIN: &[u8] = b"aegis:mint:v1";

/// A mint proof plus the note commitment it attests.
#[derive(Clone, Debug)]
pub struct MintProof {
    pub even_proof: R1CSProof<EvenPoint>,
    pub cm: EvenPoint,
}

#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error("mint r1cs failure: {0}")]
    R1cs(#[from] R1CSError),
}

/// Prove that `cm = commit([value, tag], blinding)` commits to the
/// public `value` in its value slot. `cm` is the returned note's
/// consensus commitment (a normal spendable leaf).
pub fn prove_mint<R: Rng>(
    value: u64,
    tag: EvenScalar,
    blinding: EvenScalar,
    rng: &mut R,
) -> Result<MintProof, MintError> {
    let _ = rng; // deterministic circuit; rng reserved for future blinding
    let params = tree_params();
    let mut prover: Prover<_, EvenPoint> = Prover::new(
        &params.even_parameters.pc_gens,
        Transcript::new(MINT_DOMAIN),
    );
    let (cm, vars) = prover.commit_vec(
        &[EvenScalar::from(value), tag],
        blinding,
        &params.even_parameters.bp_gens,
    );
    // Value slot pinned to the public amount (no inflation).
    prover.constrain(vars[0] - constant(EvenScalar::from(value)));
    let even_proof = prover.prove(&params.even_parameters.bp_gens)?;
    debug_assert_eq!(
        cm,
        consensus_note_commitment(value, tag, blinding),
        "minted cm must equal the spendable note commitment"
    );
    Ok(MintProof { even_proof, cm })
}

/// Verify a mint proof binds `proof.cm`'s value slot to the public
/// `value`.
pub fn verify_mint(value: u64, proof: &MintProof) -> Result<(), MintError> {
    let params = tree_params();
    let mut verifier: Verifier<_, EvenPoint> = Verifier::new(Transcript::new(MINT_DOMAIN));
    let vars = verifier.commit_vec(2, proof.cm);
    verifier.constrain(vars[0] - constant(EvenScalar::from(value)));
    let vt = verifier.verification_scalars_and_points(&proof.even_proof)?;
    batch_verify(
        vec![vt],
        &params.even_parameters.pc_gens,
        &params.even_parameters.bp_gens,
    )?;
    Ok(())
}

impl CanonicalSerialize for MintProof {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.even_proof.serialize_with_mode(&mut writer, compress)?;
        self.cm.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.even_proof.serialized_size(compress) + self.cm.serialized_size(compress)
    }
}

impl Valid for MintProof {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for MintProof {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(Self {
            even_proof: R1CSProof::deserialize_with_mode(&mut reader, compress, validate)?,
            cm: EvenPoint::deserialize_with_mode(&mut reader, compress, validate)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::note_cm_bytes;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x11117)
    }

    fn tag() -> EvenScalar {
        EvenScalar::from(0x51u64)
    }

    fn blinding() -> EvenScalar {
        EvenScalar::from(0x61u64)
    }

    // ----- happy path -----

    #[test]
    fn mint_proves_and_verifies_at_its_value() {
        let proof = prove_mint(1_234, tag(), blinding(), &mut rng()).unwrap();
        verify_mint(1_234, &proof).expect("valid mint verifies");
    }

    #[test]
    fn minted_cm_is_a_spendable_note_commitment() {
        // The minted leaf must be byte-identical to the normal note
        // commitment, so it can be spent through the §3 circuit later.
        let proof = prove_mint(1_234, tag(), blinding(), &mut rng()).unwrap();
        assert_eq!(
            note_cm_bytes(&proof.cm),
            note_cm_bytes(&consensus_note_commitment(1_234, tag(), blinding()))
        );
    }

    #[test]
    fn zero_value_note_mints() {
        // The S3 dummy/reserve zero-notes are minted the same way.
        let proof = prove_mint(0, tag(), blinding(), &mut rng()).unwrap();
        verify_mint(0, &proof).expect("zero-value mint verifies");
    }

    // ----- round-trips -----

    #[test]
    fn mint_proof_roundtrips() {
        let proof = prove_mint(1_234, tag(), blinding(), &mut rng()).unwrap();
        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        let back = MintProof::deserialize_compressed(bytes.as_slice()).unwrap();
        verify_mint(1_234, &back).expect("roundtripped mint verifies");
    }

    // ----- error paths -----

    #[test]
    fn wrong_value_rejected() {
        // A proof built for 1234 must not verify as any other amount —
        // this is the anti-inflation check.
        let proof = prove_mint(1_234, tag(), blinding(), &mut rng()).unwrap();
        assert!(verify_mint(1_235, &proof).is_err());
        assert!(verify_mint(0, &proof).is_err());
    }

    #[test]
    fn tampered_cm_rejected() {
        let mut proof = prove_mint(1_234, tag(), blinding(), &mut rng()).unwrap();
        proof.cm = consensus_note_commitment(1_234, tag(), blinding() + EvenScalar::from(1u64));
        assert!(verify_mint(1_234, &proof).is_err());
    }
}
