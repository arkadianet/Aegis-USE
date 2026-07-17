//! The spend circuit — a Plonky3 uni-STARK over BabyBear.
//!
//! Built bottom-up from the [`perm`] Poseidon2 gadget. This module currently
//! lands the plumbing (config + a permutation-binding AIR that verifies) as the
//! validated foundation the full 2-in/2-out spend AIR is assembled on.

pub mod merkle_air;
pub mod nullifier_air;
pub mod perm;

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::poseidon::{F, WIDTH};
use perm::{eval_permutation, fill_permutation, PermCols, PERM_COLS};

/// A minimal AIR that proves, for its first row, that
/// `output == Poseidon2(input)` where `input` (16) and `output` (16) are public
/// values. This exercises the entire prove/verify path (the hand-authored
/// permutation constraints, the config, public-value binding) and is the unit
/// the multi-permutation spend circuit reuses.
#[derive(Debug, Default)]
pub struct PermBindingAir;

impl BaseAir<F> for PermBindingAir {
    fn width(&self) -> usize {
        PERM_COLS
    }
    fn num_public_values(&self) -> usize {
        2 * WIDTH
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for PermBindingAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let cols: &PermCols<AB::Var> = (*local).borrow();

        // The permutation constraints: `post(final) == Poseidon2(inputs)`.
        let output = eval_permutation(builder, cols);

        // Bind the first row's input/output to the public values.
        let pv = builder.public_values().to_vec();
        for i in 0..WIDTH {
            builder
                .when_first_row()
                .assert_eq(cols.inputs[i], pv[i].into());
        }
        for (i, out) in output.into_iter().enumerate() {
            builder
                .when_first_row()
                .assert_eq(out, pv[WIDTH + i].into());
        }
    }
}

/// Build the 2-row trace: the real permutation on `input` in row 0, and a valid
/// (unbound) padding permutation in row 1 so the trace height is a power of two
/// while the permutation constraints hold on every row.
pub fn perm_binding_trace(input: [F; WIDTH]) -> RowMajorMatrix<F> {
    let mut values = vec![F::default(); 2 * PERM_COLS];
    let (row0, row1) = values.split_at_mut(PERM_COLS);
    let _ = fill_permutation(row0, input);
    let _ = fill_permutation(row1, [F::default(); WIDTH]);
    RowMajorMatrix::new(values, PERM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::make_config;
    use p3_field::PrimeCharacteristicRing;
    use p3_uni_stark::{prove, verify};

    // ----- helpers -----

    fn input() -> [F; WIDTH] {
        core::array::from_fn(|i| F::from_u32(1234 + i as u32))
    }

    fn public_io(input: [F; WIDTH]) -> Vec<F> {
        let mut out = input;
        crate::poseidon::permute(&mut out);
        input.iter().chain(out.iter()).copied().collect()
    }

    // ----- happy path -----

    #[test]
    fn perm_binding_proof_verifies() {
        let config = make_config();
        let air = PermBindingAir;
        let inp = input();
        let trace = perm_binding_trace(inp);
        let pis = public_io(inp);
        let proof = prove(&config, &air, trace, &pis);
        assert!(verify(&config, &air, &proof, &pis).is_ok());
    }

    // ----- error paths -----

    #[test]
    fn perm_binding_rejects_tampered_output() {
        let config = make_config();
        let air = PermBindingAir;
        let inp = input();
        let trace = perm_binding_trace(inp);
        let pis = public_io(inp);
        // Prove honestly, then present a tampered public output at verify time.
        let proof = prove(&config, &air, trace, &pis);
        let mut pis_bad = pis.clone();
        pis_bad[WIDTH] += F::ONE; // claim a wrong output digest
        assert!(
            verify(&config, &air, &proof, &pis_bad).is_err(),
            "a public output != Poseidon2(input) must not verify"
        );
    }
}
