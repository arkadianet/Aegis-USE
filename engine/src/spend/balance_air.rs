//! Value conservation + range over FULL 64-bit amounts — the inflation guard.
//!
//! Amounts are 4×16-bit LE limbs ([`crate::commit`]): BabyBear (p ≈ 2^31)
//! cannot hold a `u64`, and a naive `Σ limbs·2^(16j)` recombination would
//! overflow the field — so conservation is proven **limb-wise with an explicit
//! carry chain**, making any modular wrap unsatisfiable.
//!
//! # The carry-chain design (per limb j = 0..3)
//! ```text
//! in0_j + in1_j + c_j  ==  out0_j + out1_j + fee_j + c_{j+1} · 2^16
//! c_0 = 0 (no incoming carry),   c_4 = 0 (no residual carry)
//! ```
//! Telescoping by `Σ_j eq_j · 2^(16j)` gives exactly
//! `in0 + in1 == out0 + out1 + fee` **over the integers** (sums may exceed
//! 2^64 — that is fine, both sides are integers, not u64 registers).
//!
//! **Carry range.** With canonical limbs, the true carries lie in `{-2..1}`
//! (2 input terms vs 3 output terms per limb ⇒ carries can be negative —
//! "borrows"); each internal carry is witnessed as 2 bits, `c = b0 + 2·b1 - 2`.
//!
//! # Constraints, and the attack each one kills
//! - **Limb range** (`b·(b-1)=0` per bit + `limb == Σ b_i·2^i`, 16 bits, on
//!   ALL five values' limbs): without it a "limb" could be any field element —
//!   `out0_0 = p` acts like 0 in the field but denotes a huge u64 when the note
//!   is later decoded/spent (**inflation via non-canonical encoding**), and the
//!   wrap-free-ness of every other equation depends on limbs being small.
//!   Input-limb ranging is defense-in-depth on top of the cm-binding induction
//!   (inputs were range-checked when created).
//! - **Carry booleanity + the pinned `{-2..1}` window**: an unconstrained carry
//!   is a free ±k·2^16 slush fund per limb — a prover could "balance"
//!   `out = in + 2^16` by absorbing the difference into a fake carry
//!   (**inflation via carry overflow**).
//! - **The limb equation itself, wrap-free**: every term is < 2^18 ≪ p
//!   (16-bit limbs, 2-bit carries), so the FIELD equation is equivalent to the
//!   INTEGER equation — no combination of in-range witnesses can exploit mod-p
//!   arithmetic (**the wrap-around attack**: e.g. `out0 = in0 + p` balances a
//!   single-field-element check mod p, but its canonical limbs cannot satisfy
//!   the chain).
//! - **`c_0 = c_4 = 0`** (built-in, not witnessed): a nonzero final carry would
//!   allow the two sides to differ by `k·2^64` (**inflation by 2^64 quanta**).
//!
//! Amounts (incl. fee) are public here so the guard is directly testable; in
//! the monolith they are private witness bound to the note openings.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::commit::{value_limbs, LIMB_BITS, LIMB_BOUND, N_LIMBS};
use crate::poseidon::F;

// Column layout: 5 values × 4 limbs, then 5 × 64 range bits, then 3 internal
// carries × 2 bits.
const N_VALUES: usize = 5; // in0, in1, out0, out1, fee
const LIMBS_OFF: usize = 0;
const BITS_OFF: usize = LIMBS_OFF + N_VALUES * N_LIMBS;
const CARRY_OFF: usize = BITS_OFF + N_VALUES * N_LIMBS * LIMB_BITS;
const N_CARRIES: usize = N_LIMBS - 1; // c_1..c_3; c_0 = c_4 = 0
/// Balance-AIR row width.
pub const BAL_ROW_W: usize = CARRY_OFF + 2 * N_CARRIES;

const IN0: usize = 0;
const IN1: usize = 1;
const OUT0: usize = 2;
const OUT1: usize = 3;
const FEE: usize = 4;

/// The 64-bit value-conservation + range AIR (public: the 20 value limbs).
#[derive(Debug, Default)]
pub struct BalanceAir;

impl BaseAir<F> for BalanceAir {
    fn width(&self) -> usize {
        BAL_ROW_W
    }
    fn num_public_values(&self) -> usize {
        N_VALUES * N_LIMBS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

/// The limb of value `v`, limb index `j`, as a column index.
const fn limb_col(v: usize, j: usize) -> usize {
    LIMBS_OFF + v * N_LIMBS + j
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for BalanceAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        // Range: every limb of every value == its 16-bit decomposition.
        for v in 0..N_VALUES {
            for j in 0..N_LIMBS {
                let base = BITS_OFF + (v * N_LIMBS + j) * LIMB_BITS;
                let mut acc = AB::Expr::ZERO;
                for i in 0..LIMB_BITS {
                    let b: AB::Expr = row[base + i].into();
                    builder.assert_zero(b.clone() * (b.clone() - AB::Expr::ONE));
                    acc += b * AB::Expr::from_u64(1 << i);
                }
                builder.assert_eq(row[limb_col(v, j)], acc);
            }
        }

        // Carries c_1..c_3 ∈ {-2..1} as 2 bits each: c = b0 + 2·b1 - 2.
        let carry = |row: &[AB::Var], k: usize| -> AB::Expr {
            let b0: AB::Expr = row[CARRY_OFF + 2 * k].into();
            let b1: AB::Expr = row[CARRY_OFF + 2 * k + 1].into();
            b0 + b1.double() - AB::Expr::TWO
        };
        for k in 0..N_CARRIES {
            for bit in [row[CARRY_OFF + 2 * k], row[CARRY_OFF + 2 * k + 1]] {
                let b: AB::Expr = bit.into();
                builder.assert_zero(b.clone() * (b - AB::Expr::ONE));
            }
        }

        // Limb-wise conservation with the carry chain (wrap-free: every term
        // < 2^18 ≪ p given the range checks above).
        for j in 0..N_LIMBS {
            let c_in = if j == 0 {
                AB::Expr::ZERO
            } else {
                carry(row, j - 1)
            };
            let c_out = if j == N_LIMBS - 1 {
                AB::Expr::ZERO
            } else {
                carry(row, j)
            };
            let lhs: AB::Expr = row[limb_col(IN0, j)].into() + row[limb_col(IN1, j)].into() + c_in;
            let rhs: AB::Expr = row[limb_col(OUT0, j)].into()
                + row[limb_col(OUT1, j)].into()
                + row[limb_col(FEE, j)].into()
                + c_out * AB::Expr::from_u64(LIMB_BOUND);
            builder.assert_eq(lhs, rhs);
        }

        // Bind the limbs to the public values (first row).
        let pv = builder.public_values().to_vec();
        for (i, p) in pv.iter().enumerate().take(N_VALUES * N_LIMBS) {
            builder
                .when_first_row()
                .assert_eq(row[LIMBS_OFF + i], (*p).into());
        }
    }
}

/// Compute the true carry chain for balanced values; `None` if the values do
/// not balance over the integers (`in0+in1 != out0+out1+fee`).
pub fn compute_carries(vals: [u64; N_VALUES]) -> Option<[i64; N_CARRIES]> {
    let [in0, in1, out0, out1, fee] = vals;
    if (in0 as u128) + (in1 as u128) != (out0 as u128) + (out1 as u128) + (fee as u128) {
        return None;
    }
    let limb = |v: u64, j: usize| ((v >> (LIMB_BITS * j)) & (LIMB_BOUND - 1)) as i64;
    let mut carries = [0i64; N_CARRIES];
    let mut c = 0i64;
    for (j, slot) in carries.iter_mut().enumerate() {
        let diff = limb(in0, j) + limb(in1, j) + c - limb(out0, j) - limb(out1, j) - limb(fee, j);
        debug_assert_eq!(diff % (LIMB_BOUND as i64), 0, "carry chain must divide");
        c = diff / (LIMB_BOUND as i64);
        debug_assert!((-2..=1).contains(&c), "carry out of the pinned window");
        *slot = c;
    }
    Some(carries)
}

/// Build a 2-row balance trace from integer-balanced `u64` amounts, plus the
/// public values (the 20 limbs of `[in0, in1, out0, out1, fee]`).
///
/// # Panics
/// If the amounts do not balance over the integers.
pub fn balance_trace(
    in0: u64,
    in1: u64,
    out0: u64,
    out1: u64,
    fee: u64,
) -> (RowMajorMatrix<F>, Vec<F>) {
    let vals = [in0, in1, out0, out1, fee];
    let carries = compute_carries(vals).expect("amounts must balance");

    let mut one_row = vec![F::default(); BAL_ROW_W];
    for (v, &val) in vals.iter().enumerate() {
        let limbs = value_limbs(val);
        for (j, limb) in limbs.iter().enumerate() {
            one_row[limb_col(v, j)] = *limb;
            let base = BITS_OFF + (v * N_LIMBS + j) * LIMB_BITS;
            let raw = (val >> (LIMB_BITS * j)) & (LIMB_BOUND - 1);
            for i in 0..LIMB_BITS {
                one_row[base + i] = F::from_u64((raw >> i) & 1);
            }
        }
    }
    for (k, &c) in carries.iter().enumerate() {
        let cp = (c + 2) as u64; // {-2..1} -> {0..3}
        one_row[CARRY_OFF + 2 * k] = F::from_u64(cp & 1);
        one_row[CARRY_OFF + 2 * k + 1] = F::from_u64(cp >> 1);
    }

    // Two identical valid rows so every row satisfies the constraints.
    let mut values = one_row.clone();
    values.extend_from_slice(&one_row);

    let pis = vals.iter().flat_map(|&v| value_limbs(v)).collect();
    (RowMajorMatrix::new(values, BAL_ROW_W), pis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::make_config;
    use p3_uni_stark::{prove, verify};

    // ----- helpers -----

    fn prove_verify(vals: [u64; 5]) -> bool {
        let (trace, pis) = balance_trace(vals[0], vals[1], vals[2], vals[3], vals[4]);
        let config = make_config();
        let air = BalanceAir;
        let proof = prove(&config, &air, trace, &pis);
        verify(&config, &air, &proof, &pis).is_ok()
    }

    // ----- happy path -----

    #[test]
    fn balanced_transfer_verifies() {
        assert!(prove_verify([1_000, 500, 900, 590, 10]));
    }

    #[test]
    fn full_u64_amounts_verify() {
        // Sums exceed u64::MAX (integers, not u64 registers) and exercise the
        // whole carry chain, including negative carries at the top limbs.
        assert!(prove_verify([
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX - 10,
            10
        ]));
        assert!(prove_verify([u64::MAX, 0, 1 << 63, (1 << 63) - 1, 0]));
        assert!(prove_verify([0, 0, 0, 0, 0]));
    }

    // ----- error paths -----

    #[test]
    fn rejects_tampered_public_limb() {
        let (trace, pis) = balance_trace(1_000, 500, 900, 590, 10);
        let config = make_config();
        let air = BalanceAir;
        let proof = prove(&config, &air, trace, &pis);

        let mut bad = pis.clone();
        bad[2 * N_LIMBS] += F::ONE; // out0 limb 0: claim a different output
        assert!(
            verify(&config, &air, &proof, &bad).is_err(),
            "an altered output limb must not verify"
        );
    }

    #[test]
    fn wraparound_attack_is_unsatisfiable() {
        // The attack the limb design exists to kill: values that balance MOD p
        // but not over the integers. BabyBear p = 0x78000001;
        // in = [1000, 0]; out0 = 1000 + p balances a naive single-field-element
        // check (1000 ≡ 1000 + p mod p) — the carry chain must reject it.
        let p = 0x7800_0001u64;
        assert!(
            compute_carries([1_000, 0, 1_000 + p, 0, 0]).is_none(),
            "mod-p-balancing values must not admit a carry chain"
        );
        // And 2^64-quantum inflation (would need a nonzero final carry).
        assert!(compute_carries([0, 0, u64::MAX, 1, 0]).is_none());
    }

    #[test]
    #[should_panic(expected = "must balance")]
    fn imbalanced_trace_is_rejected_at_construction() {
        let _ = balance_trace(1_000, 500, 900, 600, 10);
    }

    #[test]
    fn in_circuit_non_canonical_limb_is_rejected() {
        // Adversarial witness: force out0's limb-0 column to 2^16 — a
        // non-canonical encoding that a 16-bit decomposition cannot produce.
        // The range constraint must make the trace unsatisfiable.
        let (mut trace, pis) = balance_trace(1_000, 500, 900, 590, 10);
        trace.values[limb_col(OUT0, 0)] = F::from_u64(LIMB_BOUND);
        trace.values[BAL_ROW_W + limb_col(OUT0, 0)] = F::from_u64(LIMB_BOUND);

        let config = make_config();
        let air = BalanceAir;
        let accepted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let proof = prove(&config, &air, trace, &pis);
            verify(&config, &air, &proof, &pis).is_ok()
        }))
        .unwrap_or(false);
        assert!(!accepted, "a non-canonical limb must be unsatisfiable");
    }
}
