//! `aegis/digest` — a custom non-primitive table that EXPOSES an in-circuit
//! value as plaintext, verifier-checked `public_values` on the proof (I4
//! option-A spike).
//!
//! ## Why this table exists
//! The I4 finding (recursion-feasibility.md §10): the aggregation root exposes
//! ZERO plaintext public values, so a settlement guest cannot bind which
//! withdrawals were settled. The ONE channel that is both plaintext in the
//! proof AND checked by `verify_all_tables` AND re-exposed as circuit
//! public-input targets when the proof is verified in-circuit at the next
//! layer is a non-primitive table entry's `public_values`
//! (`batch_stark_prover.rs:1794` native; `verifier/batch_stark.rs:315-321`
//! in-circuit). No stock table emits them — this one does.
//!
//! ## The statement this table adds to a proof
//! "The [`DIGEST_LIMBS`] base-field `public_values` of this entry equal the
//! basis coefficients of [`DIGEST_EF`] extension-field circuit witnesses."
//! Soundness chain:
//! 1. the AIR constrains `main[j] == public_values[j]` on the real row
//!    (`is_real` preprocessed flag), so the plaintext publics equal the
//!    committed trace cells;
//! 2. each group of `D` trace cells is a WitnessChecks-bus receive against the
//!    witness index in the committed preprocessed columns, so the trace cells
//!    equal the circuit witness value (LogUp bus balance, mult −1 reader);
//! 3. the circuit witness is the output of whatever in-circuit computation
//!    produced it (here: the Poseidon2 fold over bound values).
//!
//! A prover cannot change the publics without breaking (1), cannot change the
//! trace cells without breaking (2), and cannot change the witness without
//! breaking the circuit that computed it.

use std::any::Any;
use std::fmt;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::builder::{CircuitBuilderError, NpoCircuitPlugin, NpoLoweringContext};
use p3_circuit::ops::{
    ExecutionContext, NonPrimitiveExecutor, NonPrimitivePreprocessedMap, NpoConfig, NpoTypeId, Op,
    OpStateMap, PreprocessedWriter,
};
use p3_circuit::tables::{NonPrimitiveTrace, TraceGeneratorFn, Traces};
use p3_circuit::{CircuitBuilder, CircuitError, ExprId, PreprocessedColumns, WitnessId};
use p3_circuit_prover::batch_stark_prover::{
    BatchTableInstance, DynamicAirEntry, NonPrimitiveTableEntry, TableProver,
};
use p3_circuit_prover::common::{CircuitTableAir, NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{
    Algebra, BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64,
};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SymbolicExpression, SymbolicExpressionExt};
use p3_util::log2_ceil_usize;

use p3_circuit_prover::batch_stark_prover::BatchAir;
use p3_circuit_prover::config::StarkField;

/// Number of extension-field elements in the digest (2 × EF4 over BabyBear
/// = 8 × 31-bit limbs ≈ 248 bits — the Poseidon2-W16 sponge rate).
pub const DIGEST_EF: usize = 2;
/// Circuit extension degree (BabyBear D=4 — the stack's fixed parameter).
pub const DIGEST_D: usize = 4;
/// Number of base-field public values the digest table exposes.
pub const DIGEST_LIMBS: usize = DIGEST_EF * DIGEST_D;
/// Preprocessed columns per row: `[idx_e, mult_e] × DIGEST_EF ++ [is_real]`.
pub const DIGEST_PREP_W: usize = 2 * DIGEST_EF + 1;

/// The table's `NpoTypeId`.
pub fn digest_op_type() -> NpoTypeId {
    NpoTypeId::new("aegis/digest")
}

// ============================================================================
// Circuit side: executor + trace + plugin
// ============================================================================

/// Per-op data captured during circuit execution.
#[derive(Debug, Clone)]
pub struct DigestCircuitRow<BF> {
    /// The `DIGEST_EF` input witness ids (the digest EF elements).
    pub input_wids: Vec<WitnessId>,
    /// The `DIGEST_LIMBS` base-field basis coefficients of those witnesses.
    pub limbs: Vec<BF>,
}

/// Execution state collecting rows across digest ops (the spike uses exactly one).
#[derive(Debug, Default)]
pub struct DigestExecutionState<BF: Send + Sync + fmt::Debug + 'static> {
    pub rows: Vec<DigestCircuitRow<BF>>,
}

/// Executor: reads the digest witnesses, records their base coefficients.
#[derive(Debug, Clone)]
pub struct DigestExecutor {
    op_type: NpoTypeId,
}

impl DigestExecutor {
    pub fn new() -> Self {
        Self {
            op_type: digest_op_type(),
        }
    }
}

impl Default for DigestExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// The concrete circuit field pair of the Aegis stack (the spike is
/// BabyBear/EF4-fixed, like the rest of the pipeline).
type Bf = BabyBear;
type Ef4 = BinomialExtensionField<BabyBear, 4>;

impl NonPrimitiveExecutor<Ef4> for DigestExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, Ef4>,
    ) -> Result<(), CircuitError> {
        if inputs.len() != 1 || inputs[0].len() != DIGEST_EF {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: format!("1 input group with {DIGEST_EF} witnesses"),
                got: inputs.len(),
            });
        }
        if !outputs.is_empty() {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: "no output groups".to_string(),
                got: outputs.len(),
            });
        }

        let input_wids = inputs[0].clone();
        let mut limbs: Vec<Bf> = Vec::with_capacity(DIGEST_LIMBS);
        for &wid in &input_wids {
            let v: Ef4 = ctx.get_witness(wid)?;
            limbs.extend_from_slice(<Ef4 as BasedVectorSpace<Bf>>::as_basis_coefficients_slice(
                &v,
            ));
        }

        let state = ctx.get_op_state_mut::<DigestExecutionState<Bf>>(&self.op_type);
        state.rows.push(DigestCircuitRow { input_wids, limbs });
        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.op_type
    }

    fn preprocess(
        &self,
        inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        preprocessed: &mut dyn PreprocessedWriter<Ef4>,
    ) -> Result<(), CircuitError> {
        // Per row: [idx_e, mult_placeholder] per EF input, then [is_real].
        // The mult placeholders are overwritten with the reader multiplicity
        // (−1) by `DigestPreprocessor`; registering the read here increments
        // the producing table's `ext_reads` so its send multiplicity accounts
        // for this table's receive.
        for &wid in &inputs[0] {
            preprocessed.register_non_primitive_witness_reads(&self.op_type, &[wid])?;
            preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[Ef4::ONE]);
        }
        preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[Ef4::ONE]);
        Ok(())
    }

    fn num_exposed_outputs(&self) -> Option<usize> {
        Some(0)
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<Ef4>> {
        Box::new(self.clone())
    }
}

/// Trace for digest operations (stores BASE-field limb values; boxed as
/// `NonPrimitiveTrace<EF>` like the stock recompose trace).
#[derive(Debug, Clone)]
pub struct DigestTrace<BF> {
    pub rows: Vec<DigestCircuitRow<BF>>,
}

impl<BF: Clone + Send + Sync + fmt::Debug + 'static, CF> NonPrimitiveTrace<CF> for DigestTrace<BF> {
    fn op_type(&self) -> NpoTypeId {
        digest_op_type()
    }

    fn rows(&self) -> usize {
        self.rows.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<CF>> {
        Box::new(self.clone())
    }
}

/// Trace generator: lift the recorded rows out of the execution state.
pub fn generate_digest_trace<BF, EF>(
    op_states: &OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<EF>>>, CircuitError>
where
    BF: Field + Send + Sync + fmt::Debug + 'static,
    EF: Field + ExtensionField<BF>,
{
    let Some(state) = op_states
        .get(&digest_op_type())
        .and_then(|s| s.downcast_ref::<DigestExecutionState<BF>>())
    else {
        return Ok(None);
    };
    if state.rows.is_empty() {
        return Ok(None);
    }
    Ok(Some(Box::new(DigestTrace {
        rows: state.rows.clone(),
    })))
}

/// Circuit-layer plugin. Register with [`CircuitBuilder::register_npo`].
pub struct DigestCircuitPlugin {
    trace_gen: TraceGeneratorFn<Ef4>,
}

impl DigestCircuitPlugin {
    pub fn new(trace_gen: TraceGeneratorFn<Ef4>) -> Self {
        Self { trace_gen }
    }
}

impl fmt::Debug for DigestCircuitPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestCircuitPlugin").finish()
    }
}

/// Marker config payload (required by `NpoCircuitPlugin::config`).
#[derive(Debug, Clone)]
struct DigestConfig;

impl NpoCircuitPlugin<Ef4> for DigestCircuitPlugin {
    fn type_id(&self) -> NpoTypeId {
        digest_op_type()
    }

    fn lower(
        &self,
        data: &p3_circuit::builder::NonPrimitiveOperationData<Ef4>,
        _output_exprs: &[(u32, ExprId)],
        ctx: &mut NpoLoweringContext<'_, Ef4>,
    ) -> Result<Op<Ef4>, CircuitBuilderError> {
        if data.input_exprs.len() != 1 || data.input_exprs[0].len() != DIGEST_EF {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "AegisDigest",
                expected: format!("1 input group with {DIGEST_EF} digest elements"),
                got: data.input_exprs.len(),
            });
        }
        let input_wids: Vec<WitnessId> = data.input_exprs[0]
            .iter()
            .enumerate()
            .map(|(i, &expr)| ctx.resolve_witness_id(expr, || format!("digest element {i}")))
            .collect::<Result<_, _>>()?;

        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: vec![input_wids],
            outputs: vec![],
            executor: Box::new(DigestExecutor::new()),
            op_id: data.op_id,
        })
    }

    fn trace_generator(&self) -> TraceGeneratorFn<Ef4> {
        self.trace_gen
    }

    fn config(&self) -> NpoConfig {
        NpoConfig::new(DigestConfig)
    }
}

/// Push the digest-expose op onto a builder (the two digest EF elements).
pub fn add_digest_expose<EF: Field>(cb: &mut CircuitBuilder<EF>, digest: &[ExprId]) {
    assert_eq!(
        digest.len(),
        DIGEST_EF,
        "digest must be {DIGEST_EF} EF elements"
    );
    let _ = cb.push_non_primitive_op_with_outputs(
        digest_op_type(),
        vec![digest.to_vec()],
        vec![],
        None,
        "aegis_digest_expose",
    );
}

// ============================================================================
// Prover side: AIR + TableProver + preprocessor + air builder
// ============================================================================

/// The digest-expose AIR.
///
/// Main: `DIGEST_LIMBS` columns (basis coefficients of the digest witnesses).
/// Preprocessed: `[idx_e, mult_e] × DIGEST_EF ++ [is_real]`.
/// Public values: `DIGEST_LIMBS` (checked equal to main on the real row).
/// Lookups: one WitnessChecks receive per EF element (mult −1 on real rows).
#[derive(Clone, Debug)]
pub struct DigestAir<F, const D: usize> {
    preprocessed: Vec<F>,
    min_height: usize,
}

impl<F: Field, const D: usize> DigestAir<F, D> {
    pub fn new_with_preprocessed(preprocessed: Vec<F>, min_height: usize) -> Self {
        Self {
            preprocessed,
            min_height,
        }
    }

    /// Build the main trace matrix from recorded rows (one op per row, 1 lane).
    pub fn trace_to_matrix(rows: &[DigestCircuitRow<F>], min_height: usize) -> RowMajorMatrix<F> {
        let mut values = F::zero_vec(rows.len().max(1) * DIGEST_LIMBS);
        for (r, row) in rows.iter().enumerate() {
            values[r * DIGEST_LIMBS..(r + 1) * DIGEST_LIMBS].copy_from_slice(&row.limbs);
        }
        let mut mat = RowMajorMatrix::new(values, DIGEST_LIMBS);
        mat.pad_to_min_power_of_two_height(min_height, F::ZERO);
        mat
    }
}

impl<F: Field, const D: usize> BaseAir<F> for DigestAir<F, D> {
    fn width(&self) -> usize {
        DIGEST_LIMBS
    }

    fn num_public_values(&self) -> usize {
        DIGEST_LIMBS
    }

    fn preprocessed_width(&self) -> usize {
        DIGEST_PREP_W
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut mat =
            RowMajorMatrix::from_flat_padded(self.preprocessed.to_vec(), DIGEST_PREP_W, F::ZERO);
        mat.pad_to_min_power_of_two_height(self.min_height, F::ZERO);
        Some(mat)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB: AirBuilder + InteractionBuilder, const D: usize> Air<AB> for DigestAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.current_slice().to_vec();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice().to_vec();
        let pvs = builder.public_values().to_vec();
        debug_assert_eq!(pvs.len(), DIGEST_LIMBS);

        // WitnessChecks receives: bind each D-limb group to its witness.
        for e in 0..DIGEST_EF {
            let idx: AB::Expr = prep_local[2 * e].into();
            let mult: AB::Expr = prep_local[2 * e + 1].into();
            let mut fields: Vec<AB::Expr> = Vec::with_capacity(1 + D);
            fields.push(idx);
            for j in 0..D {
                fields.push(main_local[e * D + j].into());
            }
            builder.push_interaction("WitnessChecks", fields, Count::bounded(mult, 1));
        }

        // Public-value binding: main == public_values on the real row.
        let is_real: AB::Expr = prep_local[2 * DIGEST_EF].into();
        for j in 0..DIGEST_LIMBS {
            let m: AB::Expr = main_local[j].into();
            let p: AB::Expr = pvs[j].into();
            builder.assert_zero(is_real.clone() * (m - p));
        }
    }
}

impl<SC, const D: usize> BatchAir<SC> for DigestAir<Val<SC>, D>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

/// Table prover plugin for the digest table.
pub struct DigestProver<const D: usize>;

impl<const D: usize> DigestProver<D> {
    fn instance_from_traces<SC, EFT>(
        &self,
        packing: &TablePacking,
        traces: &Traces<EFT>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        let op_type = digest_op_type();
        let trace = traces.non_primitive_traces.get(&op_type)?;
        let t = trace.as_any().downcast_ref::<DigestTrace<Val<SC>>>()?;
        if t.rows.is_empty() {
            return None;
        }
        assert_eq!(
            t.rows.len(),
            1,
            "spike scope: exactly one digest-expose op per circuit"
        );

        let min_height = packing.min_trace_height();

        // Preprocessed indices (mults are overwritten by DigestPreprocessor in
        // the committed columns; zeros here only shape the instance).
        let mut preprocessed = Val::<SC>::zero_vec(t.rows.len() * DIGEST_PREP_W);
        for (r, row) in t.rows.iter().enumerate() {
            for (e, wid) in row.input_wids.iter().enumerate() {
                preprocessed[r * DIGEST_PREP_W + 2 * e] = wid.base_field_index::<Val<SC>, D>();
            }
            preprocessed[r * DIGEST_PREP_W + 2 * DIGEST_EF] = Val::<SC>::ONE;
        }

        let public_values = t.rows[0].limbs.clone();
        let air = DigestAir::<Val<SC>, D>::new_with_preprocessed(preprocessed, min_height);
        let matrix = DigestAir::<Val<SC>, D>::trace_to_matrix(&t.rows, min_height);

        Some(BatchTableInstance {
            op_type,
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values,
            rows: t.rows.len(),
            lanes: 1,
        })
    }
}

impl<SC, const D: usize> TableProver<SC> for DigestProver<D>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        digest_op_type()
    }

    fn lanes(&self) -> usize {
        1
    }

    fn batch_instance_d1(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.instance_from_traces(packing, traces)
    }

    fn batch_instance_d2(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.instance_from_traces(packing, traces)
    }

    fn batch_instance_d4(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.instance_from_traces(packing, traces)
    }

    fn batch_instance_d6(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.instance_from_traces(packing, traces)
    }

    fn batch_instance_d8(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.instance_from_traces(packing, traces)
    }

    fn batch_instance_d5(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<QuinticTrinomialExtensionField<Val<SC>>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.instance_from_traces(packing, traces)
    }

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        _circuit_extension_degree: u32,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        Ok(DynamicAirEntry::new(Box::new(
            DigestAir::<Val<SC>, D>::new_with_preprocessed(Vec::new(), 1),
        )))
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
        _lanes: usize,
        _circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>> {
        Some(DynamicAirEntry::new(Box::new(
            DigestAir::<Val<SC>, D>::new_with_preprocessed(committed_prep, min_height),
        )))
    }
}

/// NpoPreprocessor: convert the EF-recorded preprocessed stream to base field
/// and set the reader multiplicities (−1) on the mult slots.
#[derive(Default, Clone)]
pub struct DigestPreprocessor;

fn digest_preprocess_impl<F, EF, const D: usize>(
    prep: &PreprocessedColumns<EF, D>,
) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>
where
    F: StarkField + PrimeField64,
    EF: Field + ExtensionField<F> + 'static,
{
    let op_type = digest_op_type();
    let ef_data = match prep.non_primitive.get(&op_type) {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(NonPrimitivePreprocessedMap::new()),
    };

    let mut prep_base: Vec<F> = ef_data
        .iter()
        .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
        .collect::<Result<Vec<_>, CircuitError>>()?;

    if !prep_base.len().is_multiple_of(DIGEST_PREP_W) {
        return Err(CircuitError::InvalidPreprocessedValues);
    }

    let neg_one = F::ZERO - F::ONE;
    let num_rows = prep_base.len() / DIGEST_PREP_W;
    for r in 0..num_rows {
        for e in 0..DIGEST_EF {
            // This table is a pure reader of its digest witnesses.
            prep_base[r * DIGEST_PREP_W + 2 * e + 1] = neg_one;
        }
        prep_base[r * DIGEST_PREP_W + 2 * DIGEST_EF] = F::ONE;
    }

    let mut result = NonPrimitivePreprocessedMap::new();
    result.insert(op_type, prep_base);
    Ok(result)
}

impl NpoPreprocessor<BabyBear> for DigestPreprocessor {
    fn preprocess(
        &self,
        _circuit: &dyn Any,
        preprocessed: &mut dyn Any,
    ) -> Result<NonPrimitivePreprocessedMap<BabyBear>, CircuitError> {
        type F = BabyBear;
        if let Some(prep) =
            preprocessed.downcast_mut::<PreprocessedColumns<BinomialExtensionField<F, 4>, 4>>()
        {
            return digest_preprocess_impl::<F, _, 4>(prep);
        }
        if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<F, 1>>() {
            return digest_preprocess_impl::<F, _, 1>(prep);
        }
        Ok(NonPrimitivePreprocessedMap::new())
    }
}

/// NpoAirBuilder: build the digest AIR from committed preprocessed data.
#[derive(Clone)]
pub struct DigestAirBuilder<const D: usize>;

impl<SC, const D: usize> NpoAirBuilder<SC, D> for DigestAirBuilder<D>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn lanes(&self) -> usize {
        1
    }

    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _lanes: usize,
        _constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, D>, usize)> {
        if op_type.as_str() != "aegis/digest" {
            return None;
        }
        let num_ops = prep_base.len() / DIGEST_PREP_W;
        let air = DigestAir::<Val<SC>, D>::new_with_preprocessed(prep_base.to_vec(), min_height);
        let padded_rows = num_ops
            .max(1)
            .next_power_of_two()
            .max(min_height.next_power_of_two());
        let degree = log2_ceil_usize(padded_rows);
        Some((
            CircuitTableAir::Dynamic(DynamicAirEntry::new(Box::new(air))),
            degree,
        ))
    }
}
