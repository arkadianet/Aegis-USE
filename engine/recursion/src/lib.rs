//! # aegis-recursion — the recursion aggregation pipeline foundation (I3)
//!
//! Aggregates N real monolith spend proofs into ONE fixed-size root proof that
//! verifies natively — the step that makes settlement **batch-independent** (the
//! expensive RISC0 wrap becomes exactly one in-guest verification of the
//! constant-size root, regardless of N). See
//! `dev-docs/sidechain/recursion-feasibility.md`.
//!
//! ## The two stages
//! 1. [`layer1`] — recursively verify ONE client spend proof (aegis-engine's
//!    Poseidon2 salted-hiding single-instance batch-stark proof,
//!    [`aegis_engine::spend::batch`]) inside a circuit, producing a **plain
//!    (non-hiding) batch-stark** layer-1 proof. This is the tested batch-stark
//!    route (upstream's ZK uni-stark recursion is broken — feasibility §8.4).
//! 2. [`aggregate_tree`] — a 2-to-1 binary tree over the layer-1 proofs
//!    (`build_aggregation_layer_circuit` + `prove_aggregation_layer`), each node
//!    verifying its two children in-circuit, up to one root. N is padded to the
//!    next power of two by re-recursing duplicate leaves so every level is a
//!    uniform pair-shape (foundation-level padding; I4 replaces it with
//!    journal-bound identity leaves).
//!
//! [`aggregate_spends`] runs both stages end-to-end.
//!
//! ## Config alignment
//! The client proof is verified in-circuit under the salted Poseidon2 hiding
//! config ([`SaltedZkConfig`], wrapping [`aegis_engine::config::recursion`]); the
//! layer-1 output and every tree node are **plain** batch-stark proofs under
//! [`PlainAggConfig`] (Poseidon2 W16, duplex challenger, non-hiding MMCS —
//! aggregation layers need not re-hide; the spend proofs are already ZK and only
//! their public inputs propagate). The recursive verifier hashes in-circuit with
//! Poseidon2 only, which is exactly why the client reverted off SHA-256 (I2).
//!
//! ## Build flags (mandatory)
//! `RUSTFLAGS="-Ctarget-cpu=native"` + the `parallel` feature (default). Without
//! both, the recursion prover is ~27x slower (I1). See `README.md`.

use std::rc::Rc;
use std::sync::Arc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace, NpoTypeId};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::batch_stark_prover::{poseidon2_air_builders, recompose_air_builders};
use p3_circuit_prover::common::{get_airs_and_degrees_with_prep, NpoPreprocessor};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking,
};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_fri::FriParameters;
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::{
    set_fri_mmcs_private_data, set_hiding_salted_fri_mmcs_private_data, FriProofTargets,
    HidingFriProofTargets, InputProofTargets, MerkleCapTargets, RecExtensionValMmcs,
    RecValHidingMmcs, RecValMmcs, Witness,
};
use p3_recursion::traits::{RecursiveAir, RecursivePcs};
use p3_recursion::verifier::VerificationError;
use p3_recursion::{
    build_aggregation_layer_circuit, prove_aggregation_layer, verify_batch_circuit,
    AggregationPrepCache, BatchOnly, BatchStarkVerifierInputsBuilder, FriRecursionBackend,
    FriRecursionConfig, FriVerifierParams, Poseidon2Config, ProveNextLayerParams, RecursionInput,
    RecursionOutput,
};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val};

use aegis_engine::config::recursion::{
    Compress, Hash, RecursionChallenger, RecursionHidingConfig, RecursionHidingPcs,
    SaltedChallengeMmcs, SaltedValMmcs, CAP_HEIGHT, DIGEST_ELEMS,
};
use aegis_engine::config::{hiding_fri_parameters, EF as Challenge, SALT_ELEMS};
use aegis_engine::poseidon::F;
use aegis_engine::spend::batch::{SpendBatchProof, SpendCommonData};
use aegis_engine::spend::monolith::SpendAir;

/// Challenge-extension degree (BabyBear D=4, the stack's fixed parameter).
const D: usize = 4;
/// The in-circuit Poseidon2 configuration the recursive verifier is wired to.
const P2: Poseidon2Config = Poseidon2Config::BABY_BEAR_D4_W16;

type Dft = Radix2DitParallel<F>;

// ============================ the plain aggregation config ===================
//
// Non-hiding Poseidon2-W16 MMCS + duplex challenger — the species of the layer-1
// output and every tree node. Mirrors the recursion examples' `ConfigWithFriParams`.

type PlainMmcs =
    MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, Hash, Compress, 2, DIGEST_ELEMS>;
type PlainChallengeMmcs = ExtensionMmcs<F, Challenge, PlainMmcs>;
type PlainPcs = p3_fri::TwoAdicFriPcs<F, Dft, PlainMmcs, PlainChallengeMmcs>;
type PlainInner = StarkConfig<PlainPcs, Challenge, RecursionChallenger>;

type PlainRecValMmcs = RecValMmcs<F, DIGEST_ELEMS, Hash, Compress>;
type PlainInputProof = InputProofTargets<F, Challenge, PlainRecValMmcs>;
type PlainInnerFri = FriProofTargets<
    F,
    Challenge,
    RecExtensionValMmcs<F, Challenge, DIGEST_ELEMS, PlainRecValMmcs>,
    PlainInputProof,
    Witness<F>,
>;

/// FRI numbers shared by the layer-1 output and every aggregation layer.
/// Defaults to the engine's exact hiding FRI shape (lb3 / Q67 / pow16 / lfp0 /
/// arity1 / cap3) — the conservative "prove every tree layer at full client-grade
/// parameters" choice (I1 §8.1 measured this at ~2 s/layer, same as relaxed
/// params; the relaxation is an I5 proof-size optimization, not a correctness need).
#[derive(Clone, Copy, Debug)]
pub struct AggParams {
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
    pub num_queries: usize,
    pub commit_pow_bits: usize,
    pub query_pow_bits: usize,
    pub cap_height: usize,
}

impl Default for AggParams {
    fn default() -> Self {
        // Read straight from the engine so a param drift there breaks this crate.
        let p: FriParameters<()> = hiding_fri_parameters(());
        Self {
            log_blowup: p.log_blowup,
            log_final_poly_len: p.log_final_poly_len,
            max_log_arity: p.max_log_arity,
            num_queries: p.num_queries,
            commit_pow_bits: p.commit_proof_of_work_bits,
            query_pow_bits: p.query_proof_of_work_bits,
            cap_height: CAP_HEIGHT,
        }
    }
}

impl AggParams {
    fn fri<M>(&self, mmcs: M) -> FriParameters<M> {
        FriParameters {
            log_blowup: self.log_blowup,
            log_final_poly_len: self.log_final_poly_len,
            max_log_arity: self.max_log_arity,
            num_queries: self.num_queries,
            commit_proof_of_work_bits: self.commit_pow_bits,
            query_proof_of_work_bits: self.query_pow_bits,
            mmcs,
        }
    }

    fn verifier_params(&self) -> FriVerifierParams {
        FriVerifierParams::with_mmcs(
            self.log_blowup,
            self.log_final_poly_len,
            self.commit_pow_bits,
            self.query_pow_bits,
            self.num_queries,
            P2,
        )
    }
}

/// The plain (non-hiding) aggregation config — a `FriRecursionConfig` so its
/// proofs can themselves be recursed by the next tree layer.
#[derive(Clone)]
pub struct PlainAggConfig {
    config: Arc<PlainInner>,
    fri_verifier_params: FriVerifierParams,
}

impl core::ops::Deref for PlainAggConfig {
    type Target = PlainInner;
    fn deref(&self) -> &PlainInner {
        &self.config
    }
}

impl StarkGenericConfig for PlainAggConfig {
    type Challenge = Challenge;
    type Challenger = RecursionChallenger;
    type Pcs = PlainPcs;
    fn pcs(&self) -> &PlainPcs {
        self.config.pcs()
    }
    fn initialise_challenger(&self) -> RecursionChallenger {
        self.config.initialise_challenger()
    }
}

impl FriRecursionConfig for PlainAggConfig
where
    PlainPcs: RecursivePcs<
        PlainAggConfig,
        PlainInputProof,
        PlainInnerFri,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        <PlainPcs as Pcs<Challenge, RecursionChallenger>>::Domain,
    >,
{
    type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;
    type InputProof = PlainInputProof;
    type OpeningProof = PlainInnerFri;
    type RawOpeningProof = <PlainPcs as Pcs<Challenge, RecursionChallenger>>::Proof;
    const DIGEST_ELEMS: usize = DIGEST_ELEMS;

    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Challenge>,
    ) -> Result<(), VerificationError> {
        let perm = default_babybear_poseidon2_16();
        circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
            perm,
        );
        circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
        Ok(())
    }

    fn pcs_verifier_params(
        &self,
    ) -> &<PlainPcs as RecursivePcs<
        PlainAggConfig,
        PlainInputProof,
        PlainInnerFri,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        <PlainPcs as Pcs<Challenge, RecursionChallenger>>::Domain,
    >>::VerifierParams {
        &self.fri_verifier_params
    }

    fn set_fri_private_data(
        runner: &mut CircuitRunner<'_, Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
    ) -> Result<(), &'static str> {
        set_fri_mmcs_private_data::<F, Challenge, PlainChallengeMmcs, PlainMmcs, Hash, Compress, DIGEST_ELEMS>(
            runner, op_ids, opening_proof, P2,
        )
    }
}

/// Build the plain aggregation config at the given [`AggParams`].
pub fn plain_agg_config(p: &AggParams) -> PlainAggConfig {
    let perm = default_babybear_poseidon2_16();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = PlainMmcs::new(hash, compress, p.cap_height);
    let challenge_mmcs = PlainChallengeMmcs::new(val_mmcs.clone());
    let pcs = PlainPcs::new(Dft::default(), val_mmcs, p.fri(challenge_mmcs));
    PlainAggConfig {
        config: Arc::new(PlainInner::new(pcs, RecursionChallenger::new(perm))),
        fri_verifier_params: p.verifier_params(),
    }
}

// ======================= the salted hiding (client) config ===================
//
// Describes how to verify the client's Poseidon2 SALTED HIDING batch-stark spend
// proof in-circuit (layer-1 input). Mirrors i1_monolith's `SaltedZkConfig`.

type RecInputMmcs = RecValHidingMmcs<F, DIGEST_ELEMS, SALT_ELEMS, Hash, Compress, rand_chacha::ChaCha20Rng>;
type SaltedInputProof = InputProofTargets<F, Challenge, RecInputMmcs>;
type SaltedInnerFri = HidingFriProofTargets<
    F,
    Challenge,
    RecExtensionValMmcs<F, Challenge, DIGEST_ELEMS, RecInputMmcs>,
    SaltedInputProof,
    Witness<F>,
>;

/// The `FriRecursionConfig` for the client's salted Poseidon2 hiding proof.
#[derive(Clone)]
pub struct SaltedZkConfig {
    config: Arc<RecursionHidingConfig>,
    fri_verifier_params: FriVerifierParams,
}

impl core::ops::Deref for SaltedZkConfig {
    type Target = RecursionHidingConfig;
    fn deref(&self) -> &RecursionHidingConfig {
        &self.config
    }
}

impl StarkGenericConfig for SaltedZkConfig {
    type Challenge = Challenge;
    type Challenger = RecursionChallenger;
    type Pcs = RecursionHidingPcs;
    fn pcs(&self) -> &RecursionHidingPcs {
        self.config.pcs()
    }
    fn initialise_challenger(&self) -> RecursionChallenger {
        self.config.initialise_challenger()
    }
}

impl FriRecursionConfig for SaltedZkConfig
where
    RecursionHidingPcs: RecursivePcs<
        SaltedZkConfig,
        SaltedInputProof,
        SaltedInnerFri,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        <RecursionHidingPcs as Pcs<Challenge, RecursionChallenger>>::Domain,
    >,
{
    type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;
    type InputProof = SaltedInputProof;
    type OpeningProof = SaltedInnerFri;
    type RawOpeningProof = <RecursionHidingPcs as Pcs<Challenge, RecursionChallenger>>::Proof;
    const DIGEST_ELEMS: usize = DIGEST_ELEMS;

    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Challenge>,
    ) -> Result<(), VerificationError> {
        let perm = default_babybear_poseidon2_16();
        circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
            perm,
        );
        circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
        Ok(())
    }

    fn pcs_verifier_params(
        &self,
    ) -> &<RecursionHidingPcs as RecursivePcs<
        SaltedZkConfig,
        SaltedInputProof,
        SaltedInnerFri,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        <RecursionHidingPcs as Pcs<Challenge, RecursionChallenger>>::Domain,
    >>::VerifierParams {
        &self.fri_verifier_params
    }

    fn set_fri_private_data(
        runner: &mut CircuitRunner<'_, Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
    ) -> Result<(), &'static str> {
        set_hiding_salted_fri_mmcs_private_data::<
            F,
            Challenge,
            SaltedChallengeMmcs,
            SaltedValMmcs,
            DIGEST_ELEMS,
        >(runner, op_ids, opening_proof, P2)
    }
}

/// Build the client-proof verification config. The mask/salt RNG is never drawn
/// from during verification, so a fixed seed is safe (the proof carries its own
/// salts).
pub fn salted_zk_config(p: &AggParams) -> SaltedZkConfig {
    SaltedZkConfig {
        config: Arc::new(aegis_engine::config::recursion::recursion_hiding_config_for_verify()),
        fri_verifier_params: p.verifier_params(),
    }
}

// ================================ the pipeline ===============================

/// One client spend proof + the verifier-shared common data + its public inputs.
pub struct SpendProofInput<'a> {
    pub proof: &'a SpendBatchProof,
    pub common: &'a SpendCommonData,
    pub pis: &'a [F],
}

/// The aggregate produced by the pipeline: the root proof, the table packing it
/// was proved under (needed to reconstruct the verifier), and the tree height.
pub struct Aggregated {
    pub root: RecursionOutput<PlainAggConfig>,
    pub root_packing: TablePacking,
    pub levels: u32,
}

/// Layer-1: recursively verify ONE client spend proof, producing a plain
/// batch-stark proof (a [`RecursionOutput`] ready to feed the aggregation tree).
///
/// `salted_cfg` describes the client proof's in-circuit verification;
/// `outer_cfg`/`params` produce the plain layer-1 output.
pub fn layer1(
    salted_cfg: &SaltedZkConfig,
    outer_cfg: &PlainAggConfig,
    params: &AggParams,
    input: &SpendProofInput<'_>,
) -> RecursionOutput<PlainAggConfig> {
    let air = SpendAir;
    let inner: &RecursionHidingConfig = salted_cfg;
    let pvs = vec![input.pis.to_vec()];
    let air_public_counts = vec![input.pis.len()];

    // --- layer-1 verification circuit (verify the client proof in-circuit) ---
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
    let lookup_gadget = LogUpGadget::new();
    let verifier_inputs = BatchStarkVerifierInputsBuilder::<
        RecursionHidingConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        SaltedInnerFri,
    >::allocate(&mut cb, input.proof, input.common, &air_public_counts);
    let mmcs_op_ids = verify_batch_circuit::<_, _, _, _, _, _, _, 16, 8>(
        inner,
        &[air],
        &mut cb,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &salted_cfg.fri_verifier_params,
        &verifier_inputs.common_data,
        &lookup_gadget,
        P2,
    )
    .expect("build layer-1 batch verification circuit");
    let verification_circuit = cb.build().expect("circuit build");

    let (public_inputs, private_inputs) =
        verifier_inputs.pack_values(&pvs, input.proof, input.common);

    // --- outer prover prep (plain config) ---
    let packing = TablePacking::new(1, 2)
        .with_npo_lanes(NpoTypeId::recompose(), 1)
        .with_fri_params(params.log_final_poly_len, params.log_blowup);
    let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::default()),
    ];
    let mut air_builders = poseidon2_air_builders::<_, D>();
    air_builders.extend(recompose_air_builders(1, false));
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<PlainAggConfig, _, D>(
            &verification_circuit,
            &packing,
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("airs/degrees prep");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + outer_cfg.is_zk()).collect();
    let outer_prover_data =
        p3_batch_stark::ProverData::from_airs_and_degrees(outer_cfg, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(outer_prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(outer_cfg.clone()).with_table_packing(packing);
    prover.register_poseidon2_table::<D>(P2);
    prover.register_recompose_table::<D>(false);

    // --- witness run + outer prove ---
    let mut runner = verification_circuit.runner();
    runner.set_public_inputs(&public_inputs).expect("publics");
    runner.set_private_inputs(&private_inputs).expect("privates");
    set_hiding_salted_fri_mmcs_private_data::<F, Challenge, SaltedChallengeMmcs, SaltedValMmcs, DIGEST_ELEMS>(
        &mut runner,
        &mmcs_op_ids,
        &input.proof.opening_proof,
        P2,
    )
    .expect("MMCS private data");
    let traces = runner.run().expect("witness run");
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("layer-1 outer prove");

    RecursionOutput(proof, Rc::new(circuit_prover_data))
}

/// Aggregate a power-of-two set of layer-1 proofs into ONE root via the 2-to-1
/// binary tree. Every node verifies its two children in-circuit.
///
/// # Panics
/// If `leaves.len()` is not a power of two (use [`aggregate_spends`], which pads).
pub fn aggregate_tree(
    params: &AggParams,
    mut proofs: Vec<RecursionOutput<PlainAggConfig>>,
) -> Aggregated {
    assert!(
        proofs.len().is_power_of_two(),
        "aggregate_tree expects a power-of-two leaf count (got {})",
        proofs.len()
    );
    let backend = FriRecursionBackend::<16, 8, _>::new(P2).for_extension_degree::<D>();
    let mut prep_cache: Option<AggregationPrepCache<PlainAggConfig>> = None;
    let mut level = 0u32;
    let mut root_packing = None;

    while proofs.len() > 1 {
        level += 1;
        let pairs = proofs.len() / 2;
        // Level-1 packs 2 publics / 2 ALU lanes; higher levels use the wider
        // packing the examples measured for the ~fixed-point layers.
        let agg_params = ProveNextLayerParams {
            table_packing: if level == 1 {
                TablePacking::new(2, 2)
            } else {
                TablePacking::new(1, 3)
                    .with_horner_pack_k(4)
                    .with_npo_lanes(NpoTypeId::recompose(), 1)
            }
            .with_fri_params(params.log_final_poly_len, params.log_blowup),
            constraint_profile: ConstraintProfile::Standard,
        };
        let agg_config = plain_agg_config(params);

        let mut next_level = Vec::with_capacity(pairs);
        // Every pair at a level shares the circuit shape: build once, reuse.
        let mut layer_circuit = None;
        for pair_idx in 0..pairs {
            let li = pair_idx * 2;
            let left = proofs[li].into_recursion_input::<BatchOnly>();
            let right = proofs[li + 1].into_recursion_input::<BatchOnly>();

            if layer_circuit.is_none() {
                layer_circuit = Some(
                    build_aggregation_layer_circuit::<PlainAggConfig, _, _, _, D>(
                        &left,
                        &right,
                        &agg_config,
                        &backend,
                    )
                    .unwrap_or_else(|e| panic!("build agg circuit at level {level}: {e:?}")),
                );
            }
            let (verification_circuit, (left_result, right_result)) =
                layer_circuit.as_ref().unwrap();

            let out = prove_aggregation_layer::<PlainAggConfig, _, _, _, D>(
                &left,
                &right,
                left_result,
                right_result,
                verification_circuit,
                &agg_config,
                &backend,
                &agg_params,
                Some(&mut prep_cache),
            )
            .unwrap_or_else(|e| panic!("prove agg at level {level}, pair {pair_idx}: {e:?}"));
            next_level.push(out);
        }
        root_packing = Some(agg_params.table_packing.clone());
        proofs = next_level;
    }
    Aggregated {
        root: proofs.pop().expect("root"),
        root_packing: root_packing.expect("at least one level"),
        levels: level,
    }
}

/// End-to-end: aggregate N real spend proofs into ONE root proof. N is padded to
/// the next power of two by re-recursing duplicate leaves (foundation padding).
pub fn aggregate_spends(inputs: &[SpendProofInput<'_>], params: &AggParams) -> Aggregated {
    assert!(!inputs.is_empty(), "need at least one spend proof");
    let salted_cfg = salted_zk_config(params);
    let outer_cfg = plain_agg_config(params);
    let padded = inputs.len().next_power_of_two();
    let leaves: Vec<RecursionOutput<PlainAggConfig>> = (0..padded)
        .map(|i| layer1(&salted_cfg, &outer_cfg, params, &inputs[i.min(inputs.len() - 1)]))
        .collect();
    aggregate_tree(params, leaves)
}

/// Verify a root proof natively — the same `verify_all_tables` call the
/// settlement guest will make in-zkVM (I4). The verifier's table packing must be
/// the one the root was proved under ([`Aggregated::root_packing`]).
pub fn verify_root(params: &AggParams, agg: &Aggregated) -> Result<(), impl core::fmt::Debug> {
    let agg_config = plain_agg_config(params);
    let mut verifier =
        BatchStarkProver::new(agg_config).with_table_packing(agg.root_packing.clone());
    verifier.register_poseidon2_table::<D>(P2);
    verifier.register_recompose_table::<D>(P2.d() != D);
    verifier.verify_all_tables::<Challenge>(&agg.root.0)
}

/// Serialized size (bytes) of the root proof — the root-size metric.
pub fn proof_bytes(agg: &Aggregated) -> usize {
    postcard::to_allocvec(&agg.root.0).expect("serialize").len()
}
