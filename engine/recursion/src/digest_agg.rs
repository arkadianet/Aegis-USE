//! Digest-carrying aggregation pipeline (I4 option-A spike).
//!
//! Proves the binding channel end-to-end on toy leaves:
//! - [`toy_leaf`]: a circuit-prover proof whose PRIMITIVE public inputs are
//!   `seeds` (not surfaced — exactly the I4 finding) and whose `aegis/digest`
//!   non-primitive entry exposes `H(seeds)` (surfaced + checked).
//! - [`agg_pair_digest`]: one 2-to-1 aggregation layer that verifies two such
//!   proofs in-circuit, reads each child's digest FROM ITS RE-EXPOSED
//!   `public_values` targets (the constrained channel), folds them with the
//!   same in-circuit Poseidon2 sponge, and re-exposes the folded digest on its
//!   own `aegis/digest` entry. Applied recursively this carries a leaf-bound
//!   digest to the root of a tree of any height.
//! - [`verify_root_digest`] / [`digest_publics`]: the native check the
//!   settlement guest would run, plus digest extraction.
//! - [`sponge_digest`]: the independent native recomputation of the identical
//!   sponge (via a witness-only circuit run), used as the test oracle for what
//!   the guest recomputes from the §1 journal entries.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::StarkGenericConfig;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace, NpoTypeId};
use p3_circuit::{Circuit, CircuitBuilder, ExprId, NonPrimitiveOpId};
use p3_circuit_prover::batch_stark_prover::TableProver;
use p3_circuit_prover::batch_stark_prover::{
    poseidon2_air_builders, recompose_air_builders, BatchStarkProof, NUM_PRIMITIVE_TABLES,
};
use p3_circuit_prover::common::{get_airs_and_degrees_with_prep, NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor, Poseidon2Prover,
    RecomposePreprocessor, RecomposeProver, TablePacking,
};
use p3_lookup::logup::LogUpGadget;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::{
    set_fri_mmcs_private_data, set_hiding_salted_fri_mmcs_private_data, MerkleCapTargets,
};
use p3_recursion::verifier::verify_p3_batch_proof_circuit;
use p3_recursion::{verify_batch_circuit, BatchStarkVerifierInputsBuilder, RecursionOutput};

use aegis_engine::config::recursion::{
    Compress, Hash, RecursionHidingConfig, SaltedChallengeMmcs, SaltedValMmcs, DIGEST_ELEMS,
};
use aegis_engine::config::EF as Challenge;
use aegis_engine::poseidon::F;
use aegis_engine::settlement_digest::{amount_limbs, identity_preimage, recipient_commit};
use aegis_engine::spend::monolith::{SpendAir, PUB_CMO0, PUB_CMO1, PUB_NF0, PUB_NF1, PUB_ROOT};

use crate::digest::{
    add_digest_expose, digest_op_type, generate_digest_trace, DigestAirBuilder,
    DigestCircuitPlugin, DigestPreprocessor, DigestProver, DigestTrace, DIGEST_LIMBS,
};
use crate::{
    plain_agg_config, salted_zk_config, sha_final_config, AggParams, PlainAggConfig,
    PlainChallengeMmcs, PlainInnerFri, PlainMmcs, SaltedInnerFri, ShaFinalConfig, SpendProofInput,
    D, P2,
};

// ============================================================================
// shared circuit / prover scaffolding
// ============================================================================

/// Enable every non-primitive op the digest pipeline uses on a builder.
fn prepare_builder(cb: &mut CircuitBuilder<Challenge>) {
    cb.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
    cb.register_npo(DigestCircuitPlugin::new(
        generate_digest_trace::<F, Challenge>,
    ));
}

fn npo_preprocessors() -> Vec<Box<dyn NpoPreprocessor<F>>> {
    vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::default()),
        Box::new(DigestPreprocessor),
    ]
}

fn npo_air_builders() -> Vec<Box<dyn NpoAirBuilder<PlainAggConfig, D>>> {
    let mut builders = poseidon2_air_builders::<_, D>();
    builders.extend(recompose_air_builders(1, false));
    builders.push(Box::new(DigestAirBuilder::<D>));
    builders
}

fn digest_batch_prover(
    cfg: PlainAggConfig,
    packing: TablePacking,
) -> BatchStarkProver<PlainAggConfig> {
    let mut prover = BatchStarkProver::new(cfg).with_table_packing(packing);
    prover.register_poseidon2_table::<D>(P2);
    prover.register_recompose_table::<D>(false);
    prover.register_table_prover(Box::new(DigestProver::<D>));
    prover
}

/// Standalone prover plugins matching a child proof's non-primitive entries,
/// in entry order (required by `verify_p3_batch_proof_circuit`).
fn provers_for(
    proof: &BatchStarkProof<PlainAggConfig>,
) -> Vec<Box<dyn TableProver<PlainAggConfig>>> {
    proof
        .non_primitives
        .iter()
        .map(|entry| -> Box<dyn TableProver<PlainAggConfig>> {
            let s = entry.op_type.as_str();
            if s.starts_with("poseidon2_perm/") {
                Box::new(Poseidon2Prover::new(P2, ConstraintProfile::Standard))
            } else if s == "recompose" {
                Box::new(RecomposeProver::<D>::new(1, false))
            } else if s == "aegis/digest" {
                Box::new(DigestProver::<D>)
            } else {
                panic!("unexpected non-primitive table in child proof: {s}");
            }
        })
        .collect()
}

/// Per-instance public values for a child proof: primitives are externally
/// empty (I4 finding), non-primitive entries carry their `public_values`.
fn table_public_inputs_for(proof: &BatchStarkProof<PlainAggConfig>) -> Vec<Vec<F>> {
    let mut pis: Vec<Vec<F>> = vec![Vec::new(); NUM_PRIMITIVE_TABLES];
    for entry in &proof.non_primitives {
        pis.push(entry.public_values.clone());
    }
    pis
}

/// Instance index of the digest entry within a proof.
fn digest_instance_index(proof: &BatchStarkProof<PlainAggConfig>) -> usize {
    let pos = proof
        .non_primitives
        .iter()
        .position(|e| e.op_type == digest_op_type())
        .expect("child proof carries no aegis/digest entry");
    NUM_PRIMITIVE_TABLES + pos
}

/// Extract the digest entry's plaintext public values from a proof.
pub fn digest_publics(proof: &BatchStarkProof<PlainAggConfig>) -> Vec<F> {
    proof
        .non_primitives
        .iter()
        .find(|e| e.op_type == digest_op_type())
        .expect("proof carries no aegis/digest entry")
        .public_values
        .clone()
}

/// Prove a built circuit under the plain aggregation config with the digest
/// table registered. `set_priv` installs op-specific private data (FRI MMCS
/// openings for aggregation layers; nothing for toy leaves).
fn prove_digest_circuit(
    outer_cfg: &PlainAggConfig,
    circuit: &Circuit<Challenge>,
    packing: TablePacking,
    public_inputs: &[Challenge],
    private_inputs: &[Challenge],
    set_priv: impl FnOnce(&mut p3_circuit::CircuitRunner<'_, Challenge>),
) -> RecursionOutput<PlainAggConfig> {
    let npo_prep = npo_preprocessors();
    let air_builders = npo_air_builders();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<PlainAggConfig, _, D>(
            circuit,
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
    let prover = digest_batch_prover(outer_cfg.clone(), packing);

    let mut runner = circuit.runner();
    runner.set_public_inputs(public_inputs).expect("publics");
    runner.set_private_inputs(private_inputs).expect("privates");
    set_priv(&mut runner);
    let traces = runner.run().expect("witness run");
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove digest circuit");
    RecursionOutput(proof, Rc::new(circuit_prover_data))
}

// ============================================================================
// SHA-256 final-layer proving (I5a) — same digest circuit, SHA-256 output config
// ============================================================================
//
// The final (root) aggregation layer is proved under [`ShaFinalConfig`] so the
// guest verifies it on the RISC0 SHA accelerator. The digest table is
// config-generic (`DigestProver`/`DigestAirBuilder`/`BatchAir` over any `SC`), so
// the `aegis/digest` channel folds and surfaces exactly as under Poseidon2 — only
// the root proof's own commitments/challenger ride SHA. These mirror
// `npo_air_builders`/`digest_batch_prover`/`prove_digest_circuit` at
// `SC = ShaFinalConfig`, and return the bare `BatchStarkProof` (a SHA root is
// never recursed further, so it needs no `CircuitProverData`).

fn npo_air_builders_sha() -> Vec<Box<dyn NpoAirBuilder<ShaFinalConfig, D>>> {
    let mut builders = poseidon2_air_builders::<_, D>();
    builders.extend(recompose_air_builders(1, false));
    builders.push(Box::new(DigestAirBuilder::<D>));
    builders
}

fn digest_batch_prover_sha(
    cfg: ShaFinalConfig,
    packing: TablePacking,
) -> BatchStarkProver<ShaFinalConfig> {
    let mut prover = BatchStarkProver::new(cfg).with_table_packing(packing);
    prover.register_poseidon2_table::<D>(P2);
    prover.register_recompose_table::<D>(false);
    prover.register_table_prover(Box::new(DigestProver::<D>));
    prover
}

fn prove_digest_circuit_sha(
    outer_cfg: &ShaFinalConfig,
    circuit: &Circuit<Challenge>,
    packing: TablePacking,
    public_inputs: &[Challenge],
    private_inputs: &[Challenge],
    set_priv: impl FnOnce(&mut p3_circuit::CircuitRunner<'_, Challenge>),
) -> BatchStarkProof<ShaFinalConfig> {
    let npo_prep = npo_preprocessors();
    let air_builders = npo_air_builders_sha();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ShaFinalConfig, _, D>(
            circuit,
            &packing,
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("airs/degrees prep (sha final)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + outer_cfg.is_zk()).collect();
    let outer_prover_data =
        p3_batch_stark::ProverData::from_airs_and_degrees(outer_cfg, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(outer_prover_data, primitive_columns, non_primitive_columns);
    let prover = digest_batch_prover_sha(outer_cfg.clone(), packing);

    let mut runner = circuit.runner();
    runner.set_public_inputs(public_inputs).expect("publics");
    runner.set_private_inputs(private_inputs).expect("privates");
    set_priv(&mut runner);
    let traces = runner.run().expect("witness run");
    prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove digest circuit (sha final)")
}

// ============================================================================
// toy leaf
// ============================================================================

/// Prove a toy leaf: `seeds` enter as primitive public inputs; the digest
/// entry exposes `H(seeds)` (the in-circuit Poseidon2 sponge, bus-bound).
pub fn toy_leaf(params: &AggParams, seeds: &[F]) -> RecursionOutput<PlainAggConfig> {
    let outer_cfg = plain_agg_config(params);
    let mut cb = CircuitBuilder::new();
    prepare_builder(&mut cb);
    let seed_targets: Vec<ExprId> = seeds.iter().map(|_| cb.public_input()).collect();
    let digest = cb
        .add_hash_slice(&P2, &seed_targets, true)
        .expect("leaf digest hash");
    add_digest_expose(&mut cb, &digest);
    let circuit = cb.build().expect("build toy leaf circuit");

    let packing =
        TablePacking::new(1, 1).with_fri_params(params.log_final_poly_len, params.log_blowup);
    let publics: Vec<Challenge> = seeds.iter().map(|&s| Challenge::from(s)).collect();
    prove_digest_circuit(&outer_cfg, &circuit, packing, &publics, &[], |_| {})
}

// ============================================================================
// real-spend leaf (layer-1 with digest)
// ============================================================================

/// Layer-1 over a REAL client spend proof, with the digest fold: verify the
/// salted-hiding client proof in-circuit and expose `H(pis)` — the Poseidon2
/// sponge over the client's 44 public inputs — on the `aegis/digest` entry.
///
/// This is [`crate::layer1`] plus the option-A binding: the fold's inputs are
/// the SAME `air_public_targets` the in-circuit verifier checks against the
/// client proof, so the exposed digest is bound to what the client attested.
pub fn layer1_digest(
    params: &AggParams,
    input: &SpendProofInput<'_>,
) -> RecursionOutput<PlainAggConfig> {
    let salted_cfg = salted_zk_config(params);
    let outer_cfg = plain_agg_config(params);
    let air = SpendAir;
    let inner: &RecursionHidingConfig = &salted_cfg;
    let pvs = vec![input.pis.to_vec()];
    let air_public_counts = vec![input.pis.len()];

    let mut cb = CircuitBuilder::new();
    prepare_builder(&mut cb);
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

    // The option-A leaf seed: fold the client's verified public inputs.
    let digest = cb
        .add_hash_slice(&P2, &verifier_inputs.air_public_targets[0], true)
        .expect("leaf digest over client publics");
    add_digest_expose(&mut cb, &digest);

    let circuit = cb.build().expect("build layer-1 digest circuit");
    let (publics, privates) = verifier_inputs.pack_values(&pvs, input.proof, input.common);

    let packing = TablePacking::new(1, 2)
        .with_npo_lanes(NpoTypeId::recompose(), 1)
        .with_fri_params(params.log_final_poly_len, params.log_blowup);

    prove_digest_circuit(
        &outer_cfg,
        &circuit,
        packing,
        &publics,
        &privates,
        |runner| {
            set_hiding_salted_fri_mmcs_private_data::<
                F,
                Challenge,
                SaltedChallengeMmcs,
                SaltedValMmcs,
                DIGEST_ELEMS,
            >(runner, &mmcs_op_ids, &input.proof.opening_proof, P2)
            .expect("MMCS private data");
        },
    )
}

// ============================================================================
// aggregation layer with in-circuit digest fold
// ============================================================================

/// One 2-to-1 aggregation layer: verify `left` and `right` in-circuit, fold
/// their re-exposed digests `d = H(d_left ‖ d_right)`, re-expose `d`.
pub fn agg_pair_digest(
    params: &AggParams,
    level: u32,
    left: &RecursionOutput<PlainAggConfig>,
    right: &RecursionOutput<PlainAggConfig>,
) -> RecursionOutput<PlainAggConfig> {
    let b = build_agg_pair(params, level, left, right);
    let agg_config = plain_agg_config(params);
    prove_digest_circuit(
        &agg_config,
        &b.circuit,
        b.packing,
        &b.publics,
        &b.privates,
        |runner| {
            set_child_mmcs(runner, &b.left_ops, left);
            set_child_mmcs(runner, &b.right_ops, right);
        },
    )
}

/// The FINAL (root) aggregation layer, proved under [`ShaFinalConfig`] (I5a):
/// the SAME digest-folding circuit as [`agg_pair_digest`] (children verified
/// in-circuit under Poseidon2, digests folded and re-exposed), but the root
/// proof's own commitments/challenger are SHA-256 — so the settlement guest
/// verifies it on the RISC0 SHA accelerator (~4.7x cheaper, feasibility §7).
/// Returns the bare root proof (a SHA root is never recursed further).
pub fn agg_pair_settlement_sha(
    params: &AggParams,
    level: u32,
    left: &RecursionOutput<PlainAggConfig>,
    right: &RecursionOutput<PlainAggConfig>,
) -> BatchStarkProof<ShaFinalConfig> {
    let b = build_agg_pair(params, level, left, right);
    let sha_config = sha_final_config(params);
    prove_digest_circuit_sha(
        &sha_config,
        &b.circuit,
        b.packing,
        &b.publics,
        &b.privates,
        |runner| {
            set_child_mmcs(runner, &b.left_ops, left);
            set_child_mmcs(runner, &b.right_ops, right);
        },
    )
}

/// A built 2-to-1 digest-folding aggregation circuit, ready to prove under
/// either output config. The circuit — verify both children in-circuit under
/// [`PlainAggConfig`], fold `d = H(d_left ‖ d_right)`, re-expose `d` — is
/// identical regardless of the output config; only the outer `prove_*` differs
/// (Poseidon2 for interior layers, SHA-256 for the final root layer).
struct AggPairCircuit {
    circuit: Circuit<Challenge>,
    publics: Vec<Challenge>,
    privates: Vec<Challenge>,
    left_ops: Vec<NonPrimitiveOpId>,
    right_ops: Vec<NonPrimitiveOpId>,
    packing: TablePacking,
}

/// Install a child proof's Poseidon2 FRI-MMCS openings for the aggregation
/// circuit's in-circuit verify of that child. Identical for interior (Poseidon2)
/// and final (SHA) layers — the child is always a `PlainAggConfig` proof.
fn set_child_mmcs(
    runner: &mut p3_circuit::CircuitRunner<'_, Challenge>,
    op_ids: &[NonPrimitiveOpId],
    child: &RecursionOutput<PlainAggConfig>,
) {
    set_fri_mmcs_private_data::<
        F,
        Challenge,
        PlainChallengeMmcs,
        PlainMmcs,
        Hash,
        Compress,
        DIGEST_ELEMS,
    >(runner, op_ids, &child.0.proof.opening_proof, P2)
    .expect("child MMCS private data");
}

fn build_agg_pair(
    params: &AggParams,
    level: u32,
    left: &RecursionOutput<PlainAggConfig>,
    right: &RecursionOutput<PlainAggConfig>,
) -> AggPairCircuit {
    let agg_config = plain_agg_config(params);
    let lookup_gadget = LogUpGadget::new();

    let mut cb = CircuitBuilder::new();
    prepare_builder(&mut cb);

    let left_provers = provers_for(&left.0);
    let right_provers = provers_for(&right.0);

    let (left_inputs, left_ops) = verify_p3_batch_proof_circuit::<
        PlainAggConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        crate::PlainInputProof,
        PlainInnerFri,
        _,
        _,
        16,
        8,
        { D },
    >(
        &agg_config,
        &mut cb,
        &left.0,
        &agg_config.fri_verifier_params,
        &left.0.stark_common,
        &lookup_gadget,
        P2,
        &left_provers,
    )
    .expect("build left child verifier circuit");

    let (right_inputs, right_ops) = verify_p3_batch_proof_circuit::<
        PlainAggConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        crate::PlainInputProof,
        PlainInnerFri,
        _,
        _,
        16,
        8,
        { D },
    >(
        &agg_config,
        &mut cb,
        &right.0,
        &agg_config.fri_verifier_params,
        &right.0.stark_common,
        &lookup_gadget,
        P2,
        &right_provers,
    )
    .expect("build right child verifier circuit");

    // The crux: the children's digest limbs are available as circuit targets —
    // allocated per `entry.public_values.len()` and CHECKED in-circuit as the
    // child digest AIR's public values. Fold them and re-expose.
    let li = digest_instance_index(&left.0);
    let ri = digest_instance_index(&right.0);
    let mut fold_inputs: Vec<ExprId> = left_inputs.air_public_targets[li].clone();
    fold_inputs.extend(right_inputs.air_public_targets[ri].iter().copied());
    assert_eq!(fold_inputs.len(), 2 * DIGEST_LIMBS);
    let folded = cb
        .add_hash_slice(&P2, &fold_inputs, true)
        .expect("fold digest hash");
    add_digest_expose(&mut cb, &folded);

    let circuit = cb.build().expect("build aggregation circuit");

    // Pack public/private inputs in allocation order (left, then right).
    let left_pis = table_public_inputs_for(&left.0);
    let right_pis = table_public_inputs_for(&right.0);
    let (mut publics, mut privates) =
        left_inputs.pack_values(&left_pis, &left.0.proof, &left.0.stark_common);
    let (rpub, rpriv) = right_inputs.pack_values(&right_pis, &right.0.proof, &right.0.stark_common);
    publics.extend(rpub);
    privates.extend(rpriv);

    let packing = if level == 1 {
        TablePacking::new(2, 2)
    } else {
        TablePacking::new(1, 3)
            .with_horner_pack_k(4)
            .with_npo_lanes(NpoTypeId::recompose(), 1)
    }
    .with_fri_params(params.log_final_poly_len, params.log_blowup);

    AggPairCircuit {
        circuit,
        publics,
        privates,
        left_ops,
        right_ops,
        packing,
    }
}

/// Aggregate a power-of-two set of digest-carrying proofs into one root.
pub fn aggregate_tree_digest(
    params: &AggParams,
    mut proofs: Vec<RecursionOutput<PlainAggConfig>>,
) -> (RecursionOutput<PlainAggConfig>, TablePacking, u32) {
    assert!(proofs.len().is_power_of_two() && !proofs.is_empty());
    let mut level = 0u32;
    let mut packing =
        TablePacking::new(1, 1).with_fri_params(params.log_final_poly_len, params.log_blowup);
    while proofs.len() > 1 {
        level += 1;
        packing = if level == 1 {
            TablePacking::new(2, 2)
        } else {
            TablePacking::new(1, 3)
                .with_horner_pack_k(4)
                .with_npo_lanes(NpoTypeId::recompose(), 1)
        }
        .with_fri_params(params.log_final_poly_len, params.log_blowup);
        let mut next = Vec::with_capacity(proofs.len() / 2);
        for pair in proofs.chunks(2) {
            next.push(agg_pair_digest(params, level, &pair[0], &pair[1]));
        }
        proofs = next;
    }
    (proofs.pop().expect("root"), packing, level)
}

/// Native root verification with the digest table registered — the same call
/// the settlement guest would make in-zkVM. Returns the root's digest limbs.
pub fn verify_root_digest(
    params: &AggParams,
    root: &RecursionOutput<PlainAggConfig>,
    root_packing: TablePacking,
) -> Result<Vec<F>, String> {
    let agg_config = plain_agg_config(params);
    let verifier = digest_batch_prover(agg_config, root_packing);
    verifier
        .verify_all_tables::<Challenge>(&root.0)
        .map_err(|e| format!("{e:?}"))?;
    Ok(digest_publics(&root.0))
}

/// Verify a root proof from its bytes alone — the settlement-guest entry point.
///
/// Takes only the [`BatchStarkProof`] (the guest never sees the prover-side
/// `CircuitProverData`); the table packing rides inside the proof
/// (`proof.table_packing`). Reconstructs the verifier — poseidon2 + recompose +
/// the `aegis/digest` table — runs `verify_all_tables` in-field, and returns the
/// surfaced withdrawals digest limbs. Constant work in N (one root verify).
pub fn verify_root_proof(
    params: &AggParams,
    proof: &BatchStarkProof<PlainAggConfig>,
) -> Result<Vec<F>, String> {
    let agg_config = plain_agg_config(params);
    let verifier = digest_batch_prover(agg_config, proof.table_packing.clone());
    verifier
        .verify_all_tables::<Challenge>(proof)
        .map_err(|e| format!("{e:?}"))?;
    Ok(digest_publics(proof))
}

/// Deserialize a postcard-encoded root proof and verify it — the exact call the
/// RISC0 settlement guest makes (the guest never names a p3 type). Returns the
/// surfaced withdrawals digest limbs.
pub fn verify_root_bytes(params: &AggParams, bytes: &[u8]) -> Result<Vec<F>, String> {
    let proof: BatchStarkProof<PlainAggConfig> =
        postcard::from_bytes(bytes).map_err(|e| format!("root proof decode: {e}"))?;
    verify_root_proof(params, &proof)
}

/// Serialize a root proof for the guest/wire (postcard) — the settlement host's
/// counterpart to [`verify_root_bytes`].
pub fn serialize_root(root: &RecursionOutput<PlainAggConfig>) -> Vec<u8> {
    postcard::to_allocvec(&root.0).expect("serialize root proof")
}

// ---- SHA-256 final-layer verification (I5a) — the settlement-guest path ----

/// Extract the `aegis/digest` entry's plaintext public values from a SHA-final
/// root proof (the surfaced withdrawals digest limbs).
pub fn digest_publics_sha(proof: &BatchStarkProof<ShaFinalConfig>) -> Vec<F> {
    proof
        .non_primitives
        .iter()
        .find(|e| e.op_type == digest_op_type())
        .expect("proof carries no aegis/digest entry")
        .public_values
        .clone()
}

/// Verify a SHA-final root proof and return the surfaced withdrawals digest.
///
/// Reconstructs the SHA verifier — poseidon2 + recompose + the `aegis/digest`
/// table, [`sha_final_config`] with the packing carried inside the proof — and
/// runs `verify_all_tables` in-field. This is the exact op the settlement guest
/// runs in-zkVM, where the SHA-256 MMCS/challenger ride the RISC0 SHA
/// accelerator. Constant work in N (one root verify).
pub fn verify_root_proof_sha(
    params: &AggParams,
    proof: &BatchStarkProof<ShaFinalConfig>,
) -> Result<Vec<F>, String> {
    let sha_config = sha_final_config(params);
    let verifier = digest_batch_prover_sha(sha_config, proof.table_packing.clone());
    verifier
        .verify_all_tables::<Challenge>(proof)
        .map_err(|e| format!("{e:?}"))?;
    Ok(digest_publics_sha(proof))
}

/// Deserialize a postcard-encoded SHA-final root proof and verify it — the exact
/// call the RISC0 settlement guest makes (I5a). Returns the surfaced digest.
pub fn verify_root_bytes_sha(params: &AggParams, bytes: &[u8]) -> Result<Vec<F>, String> {
    let proof: BatchStarkProof<ShaFinalConfig> =
        postcard::from_bytes(bytes).map_err(|e| format!("sha root proof decode: {e}"))?;
    verify_root_proof_sha(params, &proof)
}

/// Serialize a SHA-final root proof for the guest/wire (postcard) — the
/// settlement host's counterpart to [`verify_root_bytes_sha`].
pub fn serialize_root_sha(root: &BatchStarkProof<ShaFinalConfig>) -> Vec<u8> {
    postcard::to_allocvec(root).expect("serialize sha root proof")
}

// ============================================================================
// native digest recomputation (the guest-side oracle)
// ============================================================================

/// Recompute the sponge digest natively via a witness-only circuit run —
/// independent of any proof; this is what the settlement guest recomputes
/// from the §1 journal entries.
pub fn sponge_digest(inputs: &[F]) -> Vec<F> {
    let mut cb = CircuitBuilder::<Challenge>::new();
    prepare_builder(&mut cb);
    let targets: Vec<ExprId> = inputs.iter().map(|_| cb.public_input()).collect();
    let digest = cb.add_hash_slice(&P2, &targets, true).expect("sponge hash");
    add_digest_expose(&mut cb, &digest);
    let circuit = cb.build().expect("build sponge circuit");

    let publics: Vec<Challenge> = inputs.iter().map(|&s| Challenge::from(s)).collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&publics).expect("publics");
    runner.set_private_inputs(&[]).expect("privates");
    let traces = runner.run().expect("witness run");
    let trace = traces
        .non_primitive_traces
        .get(&digest_op_type())
        .expect("digest trace present");
    let t = trace
        .as_any()
        .downcast_ref::<DigestTrace<F>>()
        .expect("digest trace type");
    t.rows[0].limbs.clone()
}

// ============================================================================
// settlement leaf + identity padding + settlement aggregation (the real I4)
// ============================================================================

/// Layer-1 over a REAL client spend proof, exposing the SETTLEMENT leaf digest
/// `d_leaf = H(amount ‖ recipient_commit ‖ nf0 ‖ cm0)`
/// (`aegis_engine::settlement_digest::leaf_digest`).
///
/// `nf0`/`cm0` are the client proof's public values, taken from the verifier's
/// `air_public_targets` — so they are the values THIS proof attested (the
/// option-A bind). `amount`/`recipient_commit` enter as fresh leaf public inputs
/// (the settlement declaration): they are folded into the digest so the root
/// commits to them, and the settlement guest ties `amount` back to the proof via
/// its burn-note check on the same `nf0`/`cm0`.
pub fn layer1_settlement(
    params: &AggParams,
    input: &SpendProofInput<'_>,
    amount: u64,
    recipient_prop: &[u8],
) -> RecursionOutput<PlainAggConfig> {
    let salted_cfg = salted_zk_config(params);
    let outer_cfg = plain_agg_config(params);
    let air = SpendAir;
    let inner: &RecursionHidingConfig = &salted_cfg;
    let pvs = vec![input.pis.to_vec()];
    let air_public_counts = vec![input.pis.len()];

    let mut cb = CircuitBuilder::new();
    prepare_builder(&mut cb);
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

    // Settlement declaration inputs (allocated AFTER the verifier's publics, so
    // they append to the packed public-input vector below).
    let amount_targets: Vec<ExprId> = (0..DIGEST_LIMBS).map(|_| cb.public_input()).collect();
    let recipient_targets: Vec<ExprId> = (0..DIGEST_LIMBS).map(|_| cb.public_input()).collect();

    // Proof-bound nf0/cm0 (the 44 client publics, in monolith layout order).
    let client = &verifier_inputs.air_public_targets[0];
    let nf0_targets = &client[PUB_NF0..PUB_NF0 + DIGEST_LIMBS];
    let cm0_targets = &client[PUB_CMO0..PUB_CMO0 + DIGEST_LIMBS];

    // d_leaf = H(amount ‖ recipient_commit ‖ nf0 ‖ cm0) — same order the guest's
    // `leaf_digest` folds, so the surfaced root binds the journal entries.
    let mut fold_inputs: Vec<ExprId> = Vec::with_capacity(4 * DIGEST_LIMBS);
    fold_inputs.extend_from_slice(&amount_targets);
    fold_inputs.extend_from_slice(&recipient_targets);
    fold_inputs.extend_from_slice(nf0_targets);
    fold_inputs.extend_from_slice(cm0_targets);
    let digest = cb
        .add_hash_slice(&P2, &fold_inputs, true)
        .expect("settlement leaf digest");
    add_digest_expose(&mut cb, &digest);

    let circuit = cb.build().expect("build settlement layer-1 circuit");
    let (mut publics, privates) = verifier_inputs.pack_values(&pvs, input.proof, input.common);
    // Append the settlement declaration values in allocation order.
    publics.extend(amount_limbs(amount).into_iter().map(Challenge::from));
    publics.extend(
        recipient_commit(recipient_prop)
            .into_iter()
            .map(Challenge::from),
    );

    let packing = TablePacking::new(1, 2)
        .with_npo_lanes(NpoTypeId::recompose(), 1)
        .with_fri_params(params.log_final_poly_len, params.log_blowup);

    prove_digest_circuit(
        &outer_cfg,
        &circuit,
        packing,
        &publics,
        &privates,
        |runner| {
            set_hiding_salted_fri_mmcs_private_data::<
                F,
                Challenge,
                SaltedChallengeMmcs,
                SaltedValMmcs,
                DIGEST_ELEMS,
            >(runner, &mmcs_op_ids, &input.proof.opening_proof, P2)
            .expect("MMCS private data");
        },
    )
}

/// Layer-1 over a REAL client spend proof, exposing the EPOCH spend-leaf digest
/// `d_leaf = H(root ‖ nf0 ‖ nf1 ‖ cm0 ‖ cm1 ‖ fee)`
/// (`aegis_engine::epoch::digest::spend_leaf_digest`) — the per-spend leaf the
/// epoch-validity recursion tree folds over EVERY suffix spend (not just the
/// withdrawals). The aggregated root's surfaced digest equals
/// [`aegis_engine::epoch::digest::epoch_spend_root`] over the same spends, which
/// the settlement guest re-derives from the proven suffix and binds against
/// (the anti-fabrication `digest.rs` bind).
///
/// `root/nf0/nf1/cm0/cm1` are the client proof's public values, taken from the
/// verifier's `air_public_targets` (the option-A bind — the five digests the
/// proof attested). `fee` enters as fresh leaf public inputs folded via
/// `amount_limbs`, EXACTLY as `spend_leaf_digest` folds it and exactly as
/// [`layer1_settlement`] folds its `amount` declaration; the settlement guest
/// pins it via `verify_epoch`'s flat-fee check (`s.fee == FLAT_FEE`), so a
/// declared fee cannot diverge from the consensus fee.
pub fn layer1_epoch(
    params: &AggParams,
    input: &SpendProofInput<'_>,
    fee: u64,
) -> RecursionOutput<PlainAggConfig> {
    let salted_cfg = salted_zk_config(params);
    let outer_cfg = plain_agg_config(params);
    let air = SpendAir;
    let inner: &RecursionHidingConfig = &salted_cfg;
    let pvs = vec![input.pis.to_vec()];
    let air_public_counts = vec![input.pis.len()];

    let mut cb = CircuitBuilder::new();
    prepare_builder(&mut cb);
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

    // Fee declaration input (allocated AFTER the verifier's publics, so it
    // appends to the packed public-input vector below).
    let fee_targets: Vec<ExprId> = (0..DIGEST_LIMBS).map(|_| cb.public_input()).collect();

    // Proof-bound root/nf0/nf1/cm0/cm1 (the 44 client publics, monolith layout).
    let client = &verifier_inputs.air_public_targets[0];
    let root_targets = &client[PUB_ROOT..PUB_ROOT + DIGEST_LIMBS];
    let nf0_targets = &client[PUB_NF0..PUB_NF0 + DIGEST_LIMBS];
    let nf1_targets = &client[PUB_NF1..PUB_NF1 + DIGEST_LIMBS];
    let cm0_targets = &client[PUB_CMO0..PUB_CMO0 + DIGEST_LIMBS];
    let cm1_targets = &client[PUB_CMO1..PUB_CMO1 + DIGEST_LIMBS];

    // d_leaf = H(root ‖ nf0 ‖ nf1 ‖ cm0 ‖ cm1 ‖ fee) — the exact order + inputs
    // `spend_leaf_digest` folds, so the surfaced root binds the suffix spends.
    let mut fold_inputs: Vec<ExprId> = Vec::with_capacity(6 * DIGEST_LIMBS);
    fold_inputs.extend_from_slice(root_targets);
    fold_inputs.extend_from_slice(nf0_targets);
    fold_inputs.extend_from_slice(nf1_targets);
    fold_inputs.extend_from_slice(cm0_targets);
    fold_inputs.extend_from_slice(cm1_targets);
    fold_inputs.extend_from_slice(&fee_targets);
    let digest = cb
        .add_hash_slice(&P2, &fold_inputs, true)
        .expect("epoch spend-leaf digest");
    add_digest_expose(&mut cb, &digest);

    let circuit = cb.build().expect("build epoch layer-1 circuit");
    let (mut publics, privates) = verifier_inputs.pack_values(&pvs, input.proof, input.common);
    // Append the fee declaration in allocation order (amount_limbs — the same
    // 8-limb big-endian byte decomposition `spend_leaf_digest` uses).
    publics.extend(amount_limbs(fee).into_iter().map(Challenge::from));

    let packing = TablePacking::new(1, 2)
        .with_npo_lanes(NpoTypeId::recompose(), 1)
        .with_fri_params(params.log_final_poly_len, params.log_blowup);

    prove_digest_circuit(
        &outer_cfg,
        &circuit,
        packing,
        &publics,
        &privates,
        |runner| {
            set_hiding_salted_fri_mmcs_private_data::<
                F,
                Challenge,
                SaltedChallengeMmcs,
                SaltedValMmcs,
                DIGEST_ELEMS,
            >(runner, &mmcs_op_ids, &input.proof.opening_proof, P2)
            .expect("MMCS private data");
        },
    )
}

/// A padding leaf: a toy proof whose digest is the pinned
/// [`aegis_engine::settlement_digest::identity_digest`]. It carries no
/// withdrawal — its digest is a fixed constant no real tuple can produce — so
/// padding a non-power-of-two batch cannot smuggle a withdrawal.
pub fn identity_leaf(params: &AggParams) -> RecursionOutput<PlainAggConfig> {
    toy_leaf(params, &identity_preimage())
}

/// Aggregate `N >= 1` real settlement leaves into ONE root, padding to the next
/// power of two with identity leaves. The root's surfaced digest equals
/// `aegis_engine::settlement_digest::withdrawals_root` over the same entries —
/// the value the settlement guest recomputes and checks.
pub fn aggregate_settlement(
    params: &AggParams,
    mut leaves: Vec<RecursionOutput<PlainAggConfig>>,
) -> (RecursionOutput<PlainAggConfig>, TablePacking, u32) {
    assert!(!leaves.is_empty(), "need at least one settlement leaf");
    let padded = leaves.len().next_power_of_two();
    while leaves.len() < padded {
        leaves.push(identity_leaf(params));
    }
    aggregate_tree_digest(params, leaves)
}

/// Aggregate `N >= 2` real settlement leaves into ONE **SHA-final** root (I5a),
/// padding to the next power of two with identity leaves. Interior layers are
/// Poseidon2 ([`agg_pair_digest`]); the FINAL (root) layer is proved under
/// [`ShaFinalConfig`] ([`agg_pair_settlement_sha`]) so the settlement guest
/// verifies it on the RISC0 SHA accelerator. The digest fold is byte-identical
/// to the Poseidon2 path, so the root's surfaced digest still equals
/// `aegis_engine::settlement_digest::withdrawals_root` over the same entries —
/// the value the guest recomputes and checks. Returns the root proof and the
/// tree height.
///
/// Requires the padded tree to have `>= 2` leaves (one aggregation node): the
/// SHA-final layer is a 2-to-1 node, so a single-withdrawal epoch (no
/// aggregation node) is out of scope for the SHA-final path.
pub fn aggregate_settlement_sha(
    params: &AggParams,
    mut leaves: Vec<RecursionOutput<PlainAggConfig>>,
) -> (BatchStarkProof<ShaFinalConfig>, u32) {
    assert!(!leaves.is_empty(), "need at least one settlement leaf");
    let padded = leaves.len().next_power_of_two();
    while leaves.len() < padded {
        leaves.push(identity_leaf(params));
    }
    assert!(
        leaves.len() >= 2,
        "SHA-final settlement needs >= 2 leaves (one aggregation node)"
    );

    // Interior Poseidon2 layers until exactly two proofs (the root's children)
    // remain; then the final SHA-256 layer over that pair.
    let mut level = 0u32;
    while leaves.len() > 2 {
        level += 1;
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            next.push(agg_pair_digest(params, level, &pair[0], &pair[1]));
        }
        leaves = next;
    }
    level += 1;
    let root = agg_pair_settlement_sha(params, level, &leaves[0], &leaves[1]);
    (root, level)
}
