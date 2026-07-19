//! The recursion-compatible client spend proof: a **single-instance
//! `p3-batch-stark` proof** of [`SpendAir`] under the Poseidon2 salted-hiding
//! config ([`crate::config::recursion`]).
//!
//! # Why batch-stark and not uni-stark
//! The aggregation pipeline recursively verifies each client proof in-circuit.
//! I1 found the upstream `RecursionInput::UniStark`-over-`HidingFriPcs` entry
//! point broken at Plonky3-recursion `b363397` (a `WitnessConflict` in the
//! witness run: no upstream test exercises the ZK + uni-stark recursion path).
//! The single-instance batch-stark route is the one upstream DOES test for the
//! salted hiding MMCS (`tests/zk_hiding_mmcs.rs`), and it makes every level of
//! the aggregation tree the same proof species (BatchStark), which the
//! aggregation API already assumes. Client cost is a wash vs uni-stark
//! (I1: 37 vs 46 ms; same proof bytes).
//!
//! The spend circuit ([`SpendAir`] + its preprocessed schedule) is UNCHANGED —
//! only the proof-system wrapper differs. See
//! `dev-docs/sidechain/recursion-feasibility.md` §8.4.

use p3_batch_stark::{prove_batch, verify_batch, BatchProof, CommonData, ProverData, StarkInstance};
use p3_matrix::dense::RowMajorMatrix;

use crate::config::recursion::RecursionHidingConfig;
use crate::poseidon::F;
use crate::spend::monolith::SpendAir;

/// The recursion-compatible client spend proof (single-instance batch-stark).
pub type SpendBatchProof = BatchProof<RecursionHidingConfig>;
/// The verifier-shared common data for the single spend instance.
pub type SpendCommonData = CommonData<RecursionHidingConfig>;

/// Prove a spend as a single-instance batch-stark proof. `trace` and `pis` come
/// from [`crate::spend::monolith::build_spend_trace`]. Returns the proof and the
/// verifier-shared [`SpendCommonData`] (preprocessed-schedule commitment +
/// lookups) so a caller can verify without re-deriving it.
pub fn prove_spend_batch(
    config: &RecursionHidingConfig,
    trace: &RowMajorMatrix<F>,
    pis: &[F],
) -> (SpendBatchProof, SpendCommonData) {
    let air = SpendAir;
    let instances = [StarkInstance {
        air: &air,
        trace,
        public_values: pis.to_vec(),
    }];
    let prover_data = ProverData::from_instances(config, &instances);
    let proof = prove_batch(config, &instances, &prover_data);
    (proof, prover_data.common)
}

// NOTE on `common`: the hiding MMCS salts the PREPROCESSED-schedule leaves with
// random salts drawn from the config's salt RNG, so the preprocessed commitment
// is NOT reproducible from the AIR alone — prover and verifier must agree on the
// exact committed value. Here [`prove_spend_batch`] returns the prover's
// [`SpendCommonData`] and it travels with the proof. In production settlement
// (I4) this commitment is vk-pinned — baked into the guest ELF exactly like the
// SHA path's `baked_spend_vk`, so the verifier trusts the baked value, not a
// prover-supplied one (recursion-feasibility.md §7/§4(d)).

/// Verify a client spend batch proof natively.
pub fn verify_spend_batch(
    config: &RecursionHidingConfig,
    proof: &SpendBatchProof,
    pis: &[F],
    common: &SpendCommonData,
) -> Result<(), impl core::fmt::Debug> {
    let air = SpendAir;
    verify_batch(config, &[air], proof, &[pis.to_vec()], common)
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::commit::{note_commitment, owner_key};
    use crate::config::recursion::make_recursion_hiding_config;
    use crate::merkle::NoteTree;
    use crate::poseidon::Digest;
    use crate::spend::monolith::{build_spend_trace, InputNote, OutputNote};

    // ----- helpers -----

    fn digest(base: u32) -> Digest {
        use p3_field::PrimeCharacteristicRing;
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    /// A valid 2-in/2-out spend (mirrors the monolith test scenario).
    fn scenario() -> (NoteTree, [InputNote; 2], [OutputNote; 2], u64) {
        let in0 = InputNote { value: 1_000, nk: digest(1), rho: digest(50), r: digest(90), index: 0 };
        let in1 = InputNote { value: 500, nk: digest(200), rho: digest(250), r: digest(290), index: 0 };
        let mut tree = NoteTree::new();
        let cm0 = note_commitment(in0.value, &owner_key(&in0.nk), &in0.rho, &in0.r);
        let cm1 = note_commitment(in1.value, &owner_key(&in1.nk), &in1.rho, &in1.r);
        let i0 = tree.append(cm0);
        let i1 = tree.append(cm1);
        let in0 = InputNote { index: i0, ..in0 };
        let in1 = InputNote { index: i1, ..in1 };
        let out0 = OutputNote { value: 900, owner: digest(400), rho: digest(450), r: digest(490) };
        let out1 = OutputNote { value: 590, owner: digest(600), rho: digest(650), r: digest(690) };
        (tree, [in0, in1], [out0, out1], 10)
    }

    fn cfg() -> RecursionHidingConfig {
        make_recursion_hiding_config(
            ChaCha20Rng::seed_from_u64(1),
            ChaCha20Rng::seed_from_u64(2),
        )
    }

    // ----- happy path -----

    #[test]
    fn recursion_spend_batch_proof_verifies_natively() {
        let (tree, inputs, outputs, fee) = scenario();
        let (trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let config = cfg();

        let (proof, common) = prove_spend_batch(&config, &trace, &pis);
        verify_spend_batch(&config, &proof, &pis, &common)
            .expect("recursion-config spend proof must verify natively");
    }

    // ----- error paths -----

    #[test]
    fn tampered_public_input_rejects() {
        let (tree, inputs, outputs, fee) = scenario();
        let (trace, mut pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let config = cfg();

        let (proof, common) = prove_spend_batch(&config, &trace, &pis);
        // Flip a public input (e.g. the Merkle root's first limb): must reject.
        use p3_field::PrimeCharacteristicRing;
        pis[0] += F::ONE;
        assert!(
            verify_spend_batch(&config, &proof, &pis, &common).is_err(),
            "a tampered public input must fail verification"
        );
    }
}
