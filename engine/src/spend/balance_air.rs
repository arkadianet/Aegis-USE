//! Value conservation + range as AIR constraints — the inflation guard.
//!
//! For a 2-in / 2-out transfer this enforces:
//! - **Conservation**: `in0 + in1 == out0 + out1 + fee`. Because every amount is
//!   `< 2^AMOUNT_BITS` (= 2^28) and there are at most three terms on a side, the
//!   largest side is `< 3·2^28 < 2^30 < p`, so the equation is a single field
//!   constraint that is equivalent to integer equality — **no modular wrap**.
//!   Without it a prover could mint value from nothing (inflation).
//! - **Range**: each freshly-created amount (`out0`, `out1`, `fee`) is bit-
//!   decomposed into `AMOUNT_BITS` booleans that reconstruct it. Without the
//!   range check a "negative" output — a field element ≥ 2^28 that represents a
//!   huge value mod p — could satisfy the linear balance while actually creating
//!   value (a wrap/inflation hole). Inputs are not re-ranged here: an input was
//!   range-checked when it was created as some earlier note's output (this is the
//!   note-conservation invariant the accumulator maintains).
//!
//! Amounts are public here so the guard is directly testable; in the full spend
//! they are private witness bound to the note openings (`cm = H(value‖…)`), which
//! is what ties conservation to the actual notes.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::commit::AMOUNT_BITS;
use crate::poseidon::F;

// Column layout: five amounts, then bit decompositions of the three
// freshly-created amounts (out0, out1, fee).
const IN0: usize = 0;
const IN1: usize = 1;
const OUT0: usize = 2;
const OUT1: usize = 3;
const FEE: usize = 4;
const N_AMOUNTS: usize = 5;
/// Offsets of the three range-checked amounts and their bit blocks.
const RANGED: [usize; 3] = [OUT0, OUT1, FEE];
const BITS_OFF: usize = N_AMOUNTS;
/// Balance-AIR row width: 5 amounts + 3 range-checked × `AMOUNT_BITS` bits.
pub const BAL_ROW_W: usize = N_AMOUNTS + 3 * AMOUNT_BITS;

/// The value-conservation + range AIR (public: `in0,in1,out0,out1,fee`).
#[derive(Debug, Default)]
pub struct BalanceAir;

impl BaseAir<F> for BalanceAir {
    fn width(&self) -> usize {
        BAL_ROW_W
    }
    fn num_public_values(&self) -> usize {
        N_AMOUNTS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for BalanceAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        // Conservation (overflow-free — see module doc).
        let in0: AB::Expr = row[IN0].into();
        let in1: AB::Expr = row[IN1].into();
        let out0: AB::Expr = row[OUT0].into();
        let out1: AB::Expr = row[OUT1].into();
        let fee: AB::Expr = row[FEE].into();
        builder.assert_zero(in0 + in1 - out0 - out1 - fee);

        // Range: each ranged amount == Σ bit_i · 2^i, bits boolean.
        for (k, &amount_col) in RANGED.iter().enumerate() {
            let base = BITS_OFF + k * AMOUNT_BITS;
            let mut acc = AB::Expr::ZERO;
            for i in 0..AMOUNT_BITS {
                let b: AB::Expr = row[base + i].into();
                builder.assert_zero(b.clone() * (b.clone() - AB::Expr::ONE));
                acc += b * AB::Expr::from_u64(1u64 << i);
            }
            builder.assert_eq(row[amount_col], acc);
        }

        // Bind the amounts to the public values (first row).
        let pv = builder.public_values().to_vec();
        for j in 0..N_AMOUNTS {
            builder.when_first_row().assert_eq(row[j], pv[j].into());
        }
    }
}

/// Build a 2-row balance trace from balanced, in-range `u64` amounts, plus the
/// public values `[in0, in1, out0, out1, fee]`.
///
/// # Panics
/// If the amounts are not balanced or any ranged amount is ≥ 2^AMOUNT_BITS
/// (a caller error — the circuit also rejects these).
pub fn balance_trace(
    in0: u64,
    in1: u64,
    out0: u64,
    out1: u64,
    fee: u64,
) -> (RowMajorMatrix<F>, Vec<F>) {
    assert_eq!(in0 + in1, out0 + out1 + fee, "amounts must balance");
    for v in [out0, out1, fee] {
        assert!(v < (1u64 << AMOUNT_BITS), "amount out of range");
    }
    let amounts = [in0, in1, out0, out1, fee];

    let mut one_row = vec![F::default(); BAL_ROW_W];
    for (j, v) in amounts.iter().enumerate() {
        one_row[j] = F::from_u64(*v);
    }
    for (k, &col) in RANGED.iter().enumerate() {
        let v = amounts[col];
        let base = BITS_OFF + k * AMOUNT_BITS;
        for i in 0..AMOUNT_BITS {
            one_row[base + i] = F::from_u64((v >> i) & 1);
        }
    }
    // Two identical valid rows so every row satisfies the constraints.
    let mut values = one_row.clone();
    values.extend_from_slice(&one_row);

    let pis = amounts.iter().map(|v| F::from_u64(*v)).collect();
    (RowMajorMatrix::new(values, BAL_ROW_W), pis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::make_config;
    use p3_uni_stark::{prove, verify};

    // ----- happy path -----

    #[test]
    fn balanced_transfer_verifies() {
        let (trace, pis) = balance_trace(1_000, 500, 900, 590, 10);
        let config = make_config();
        let air = BalanceAir;
        let proof = prove(&config, &air, trace, &pis);
        assert!(verify(&config, &air, &proof, &pis).is_ok());
    }

    // ----- error paths -----

    #[test]
    fn rejects_imbalanced_public_amounts() {
        let (trace, pis) = balance_trace(1_000, 500, 900, 590, 10);
        let config = make_config();
        let air = BalanceAir;
        let proof = prove(&config, &air, trace, &pis);

        // Claim a larger out0 than was actually committed: breaks the binding
        // (and would break conservation) → reject.
        let mut bad = pis.clone();
        bad[OUT0] += F::ONE;
        assert!(
            verify(&config, &air, &proof, &bad).is_err(),
            "an unbalanced/altered output must not verify"
        );
    }

    #[test]
    #[should_panic(expected = "must balance")]
    fn imbalanced_trace_is_rejected_at_construction() {
        // The prover cannot even build an inflating witness.
        let _ = balance_trace(1_000, 500, 900, 600, 10);
    }
}
