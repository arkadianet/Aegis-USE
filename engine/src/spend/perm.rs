//! The Poseidon2-t16 permutation as AIR constraints — the shared gadget the
//! spend circuit is built from.
//!
//! The round structure is authored here (not delegated to a black box) so every
//! constraint is reviewable, but it uses the SAME canonical BabyBear round
//! constants and linear layers as the native permutation
//! ([`crate::poseidon::permute`]) — so native and circuit agree by construction.
//! The column layout is Plonky3's [`Poseidon2Cols`] (one permutation per row):
//! `inputs`, then per full round the committed S-box register + post-layer
//! state, and per partial round the S-box register + post-S-box value.
//!
//! What the permutation constraints enforce, and why it matters: they pin the
//! row's `post` columns to be EXACTLY `Poseidon2(inputs)`. Every higher-level
//! binding (a commitment opening, a nullifier, a Merkle step) is then "this
//! permutation's input/output equals such-and-such", and soundness reduces to
//! Poseidon2's collision/preimage resistance plus the linking constraints. A
//! missing or wrong round constraint would let a prover forge a hash output —
//! i.e. forge a commitment opening or a nullifier — so these are load-bearing.

use core::mem::MaybeUninit;

use p3_air::AirBuilder;
use p3_baby_bear::{
    BabyBear, GenericPoseidon2LinearLayersBabyBear, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, BABYBEAR_POSEIDON2_RC_16_INTERNAL,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{
    generate_trace_rows_for_perm, num_cols, FullRound, PartialRound, Poseidon2Cols, SBox,
};

use crate::poseidon::{
    air_round_constants, permute, Digest, DIGEST_ELEMS, F, HALF_FULL_ROUNDS, PARTIAL_ROUNDS,
    SBOX_DEGREE, SBOX_REGISTERS, WIDTH,
};

/// Number of trace columns for one Poseidon2-t16 permutation.
pub const PERM_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();

/// The concrete per-permutation column struct.
pub type PermCols<T> =
    Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

/// Degree-7 S-box with one committed register (`x^3`): constrains
/// `reg == x^3` and yields `x^7 = (x^3)^2 · x`, keeping the max constraint
/// degree at 3. Omitting the `reg == x^3` check would let the S-box output be
/// arbitrary — a hash forgery — so it is essential.
fn eval_sbox<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    sbox: &SBox<AB::Var, SBOX_DEGREE, SBOX_REGISTERS>,
    x: &mut AB::Expr,
) {
    let committed_x3: AB::Expr = sbox.0[0].into();
    builder.assert_eq(committed_x3.clone(), x.clone().cube());
    *x = committed_x3.square() * x.clone();
}

fn eval_full_round<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    state: &mut [AB::Expr; WIDTH],
    round: &FullRound<AB::Var, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constants: &[BabyBear; WIDTH],
) {
    for (i, s) in state.iter_mut().enumerate() {
        *s = s.clone() + round_constants[i];
        eval_sbox(builder, &round.sbox[i], s);
    }
    GenericPoseidon2LinearLayersBabyBear::external_linear_layer(state);
    for (s, &post) in state.iter_mut().zip(round.post.iter()) {
        builder.assert_eq(s.clone(), post);
        *s = post.into();
    }
}

fn eval_partial_round<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    state: &mut [AB::Expr; WIDTH],
    round: &PartialRound<AB::Var, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constant: BabyBear,
) {
    state[0] = state[0].clone() + round_constant;
    eval_sbox(builder, &round.sbox, &mut state[0]);
    builder.assert_eq(state[0].clone(), round.post_sbox);
    state[0] = round.post_sbox.into();
    GenericPoseidon2LinearLayersBabyBear::internal_linear_layer(state);
}

/// Emit the constraints binding `cols.post(final) == Poseidon2(cols.inputs)`,
/// and return the 16 output-lane expressions (the final post columns) so a
/// caller can link them (e.g. a Merkle step's parent, a squeezed digest).
pub fn eval_permutation<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    cols: &PermCols<AB::Var>,
) -> [AB::Expr; WIDTH] {
    let mut state: [AB::Expr; WIDTH] = cols.inputs.map(|x| x.into());
    GenericPoseidon2LinearLayersBabyBear::external_linear_layer(&mut state);
    for (round, rc) in cols
        .beginning_full_rounds
        .iter()
        .zip(BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL.iter())
    {
        eval_full_round(builder, &mut state, round, rc);
    }
    for (round, &rc) in cols
        .partial_rounds
        .iter()
        .zip(BABYBEAR_POSEIDON2_RC_16_INTERNAL.iter())
    {
        eval_partial_round(builder, &mut state, round, rc);
    }
    for (round, rc) in cols
        .ending_full_rounds
        .iter()
        .zip(BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL.iter())
    {
        eval_full_round(builder, &mut state, round, rc);
    }
    state
}

/// The 8-lane output digest of `Poseidon2(input)` — a native helper mirroring
/// what [`eval_permutation`] exposes as its first 8 output lanes.
pub fn permutation_output(input: &[F; WIDTH]) -> Digest {
    let mut s = *input;
    permute(&mut s);
    s[..DIGEST_ELEMS].try_into().expect("8 of 16")
}

/// The full 16-lane output of `Poseidon2(input)` — used to chain sponge
/// absorptions (the next block adds onto these lanes).
pub fn permutation_output16(input: &[F; WIDTH]) -> [F; WIDTH] {
    let mut s = *input;
    permute(&mut s);
    s
}

/// Fill one permutation's `PERM_COLS` trace columns (`dst`) from the raw input
/// `state`, returning the full 16-lane permutation output. Uses Plonky3's
/// trace generator over the SAME constants as [`eval_permutation`].
pub fn fill_permutation(dst: &mut [F], input: [F; WIDTH]) -> [F; WIDTH] {
    debug_assert_eq!(dst.len(), PERM_COLS);
    let mut buf = [const { MaybeUninit::<F>::uninit() }; PERM_COLS];
    {
        let cols: &mut PermCols<MaybeUninit<F>> = core::borrow::BorrowMut::borrow_mut(&mut buf[..]);
        generate_trace_rows_for_perm::<
            F,
            GenericPoseidon2LinearLayersBabyBear,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(cols, input, air_round_constants());
    }
    for (d, b) in dst.iter_mut().zip(buf.iter()) {
        *d = unsafe { b.assume_init() };
    }
    let mut out = input;
    permute(&mut out);
    out
}
