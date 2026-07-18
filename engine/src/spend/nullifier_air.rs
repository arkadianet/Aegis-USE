//! Nullifier derivation as AIR constraints — a fully public-bound, verifying
//! circuit for `nf = H_NF(nk ‖ rho)`.
//!
//! This is the in-circuit face of the N1 nullifier ([`crate::nullifier`]) and
//! demonstrates the **sponge chain** the note-commitment opening uses too (the
//! commitment is the identical construction with four blocks instead of two).
//! It is a 2-permutation add-absorb sponge: block 0 absorbs `nk`, block 1
//! absorbs `rho`, and the squeezed digest is `nf`.
//!
//! # Why this circuit is the anti-double-spend guarantee
//! In the full spend, `nk` and `rho` are the SAME key material that (via
//! `owner = H(nk)` and `cm = H(value‖owner‖rho‖r)`) define the spent note, and
//! the revealed `nf` is checked against the on-chain nullifier set. Because this
//! circuit forces `nf` to be exactly `H_NF(nk‖rho)` — no free component, no
//! blinding — one note yields exactly one `nf`; a second spend of the same note
//! reproduces the same `nf` and is rejected by the set. Here `nk`, `rho`, `nf`
//! are all public so the binding is directly testable; in the spend they are
//! private witness bound to the note.
//!
//! # Constraints, each with its soundness role
//! - **Row 0 input assembly**: `inputs == sponge_init(DOMAIN_NF, len=16)` with
//!   `nk` added on the rate lanes (domain tag in the capacity, length bound).
//!   Fixes the sponge's starting state; a wrong domain/length would let a
//!   nullifier collide across purposes.
//! - **Permutation** per row (`eval_permutation`).
//! - **Absorb chaining** (transition): `next.inputs == cur.output + next.block`
//!   on the rate, `== cur.output` on the capacity — the defining sponge step.
//! - **Public binding**: block 0 `== nk`, block 1 `== rho`, final digest `== nf`.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use super::perm::{eval_permutation, fill_permutation, PermCols, PERM_COLS};
use crate::commit::{Nk, Rho};
use crate::nullifier::nullifier;
use crate::poseidon::{sponge_init, Digest, DIGEST_ELEMS, DOMAIN_NULLIFIER, F, WIDTH};

/// Absorbed-block width (one rate-8 block per row).
const BLOCK_OFF: usize = PERM_COLS;
/// Nullifier-AIR row width.
pub const NF_ROW_W: usize = PERM_COLS + DIGEST_ELEMS;
/// Total absorbed length (`nk‖rho` = 16 elements), bound into the sponge capacity.
const NF_LEN: u32 = (2 * DIGEST_ELEMS) as u32;

/// The nullifier AIR (public: `nk(8) ‖ rho(8) ‖ nf(8)`).
#[derive(Debug, Default)]
pub struct NullifierAir;

impl BaseAir<F> for NullifierAir {
    fn width(&self) -> usize {
        NF_ROW_W
    }
    fn num_public_values(&self) -> usize {
        3 * DIGEST_ELEMS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for NullifierAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();
        let cols: &PermCols<AB::Var> = cur[..PERM_COLS].borrow();
        let pv = builder.public_values().to_vec();

        // Row 0: starting sponge state = init(DOMAIN_NF, len) + nk on the rate.
        for j in 0..DIGEST_ELEMS {
            builder
                .when_first_row()
                .assert_eq(cols.inputs[j], cur[BLOCK_OFF + j].into());
        }
        builder.when_first_row().assert_eq(
            cols.inputs[DIGEST_ELEMS],
            AB::Expr::from_u32(DOMAIN_NULLIFIER),
        );
        for j in (DIGEST_ELEMS + 1)..(WIDTH - 1) {
            builder.when_first_row().assert_zero(cols.inputs[j]);
        }
        builder
            .when_first_row()
            .assert_eq(cols.inputs[WIDTH - 1], AB::Expr::from_u32(NF_LEN));

        let output = eval_permutation(builder, cols);

        // Absorb chaining into the next row.
        let next_cols: &PermCols<AB::Var> = next[..PERM_COLS].borrow();
        for j in 0..DIGEST_ELEMS {
            builder.when_transition().assert_eq(
                next_cols.inputs[j].into(),
                output[j].clone() + next[BLOCK_OFF + j].into(),
            );
        }
        for (inp, out) in next_cols.inputs[DIGEST_ELEMS..]
            .iter()
            .zip(output[DIGEST_ELEMS..].iter())
        {
            builder
                .when_transition()
                .assert_eq((*inp).into(), out.clone());
        }

        // Public binding: block0 == nk, block1 == rho (last row), digest == nf.
        for j in 0..DIGEST_ELEMS {
            builder
                .when_first_row()
                .assert_eq(cur[BLOCK_OFF + j].into(), pv[j].into());
            builder
                .when_last_row()
                .assert_eq(cur[BLOCK_OFF + j].into(), pv[DIGEST_ELEMS + j].into());
        }
        for (j, out) in output.into_iter().take(DIGEST_ELEMS).enumerate() {
            builder
                .when_last_row()
                .assert_eq(out, pv[2 * DIGEST_ELEMS + j].into());
        }
    }
}

/// Build the 2-row nullifier trace and its public values `nk ‖ rho ‖ nf`.
pub fn nullifier_trace(nk: &Nk, rho: &Rho) -> (RowMajorMatrix<F>, Vec<F>) {
    let mut values = vec![F::default(); 2 * NF_ROW_W];

    // Row 0: absorb nk.
    let mut in0 = sponge_init(DOMAIN_NULLIFIER, NF_LEN as usize);
    for j in 0..DIGEST_ELEMS {
        in0[j] += nk[j];
    }
    let out0 = {
        let row = &mut values[..NF_ROW_W];
        let o = fill_permutation(&mut row[..PERM_COLS], in0);
        row[BLOCK_OFF..BLOCK_OFF + DIGEST_ELEMS].copy_from_slice(nk);
        o
    };

    // Row 1: absorb rho.
    let mut in1 = out0;
    for j in 0..DIGEST_ELEMS {
        in1[j] += rho[j];
    }
    let out1 = {
        let row = &mut values[NF_ROW_W..];
        let o = fill_permutation(&mut row[..PERM_COLS], in1);
        row[BLOCK_OFF..BLOCK_OFF + DIGEST_ELEMS].copy_from_slice(rho);
        o
    };

    let nf: Digest = out1[..DIGEST_ELEMS].try_into().expect("8 of 16");
    debug_assert_eq!(nf, nullifier(nk, rho), "circuit nf must equal native nf");

    let pis = nk
        .iter()
        .chain(rho.iter())
        .chain(nf.iter())
        .copied()
        .collect();
    (RowMajorMatrix::new(values, NF_ROW_W), pis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::make_config;
    use p3_uni_stark::{prove, verify};

    // ----- helpers -----

    fn digest(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    // ----- happy path -----

    #[test]
    fn nullifier_proof_verifies() {
        let (nk, rho) = (digest(1), digest(50));
        let (trace, pis) = nullifier_trace(&nk, &rho);
        let config = make_config();
        let air = NullifierAir;
        let proof = prove(&config, &air, trace, &pis);
        assert!(verify(&config, &air, &proof, &pis).is_ok());
    }

    // ----- error paths -----

    #[test]
    fn rejects_tampered_nullifier() {
        let (nk, rho) = (digest(1), digest(50));
        let (trace, pis) = nullifier_trace(&nk, &rho);
        let config = make_config();
        let air = NullifierAir;
        let proof = prove(&config, &air, trace, &pis);

        let mut bad = pis.clone();
        bad[2 * DIGEST_ELEMS] += F::ONE; // claim a wrong nf
        assert!(
            verify(&config, &air, &proof, &bad).is_err(),
            "nf != H_NF(nk‖rho) must not verify"
        );
    }

    #[test]
    fn rejects_tampered_key_material() {
        let (nk, rho) = (digest(1), digest(50));
        let (trace, pis) = nullifier_trace(&nk, &rho);
        let config = make_config();
        let air = NullifierAir;
        let proof = prove(&config, &air, trace, &pis);

        // Present a different nk in the public values while keeping the proof.
        let mut bad = pis.clone();
        bad[0] += F::ONE;
        assert!(
            verify(&config, &air, &proof, &bad).is_err(),
            "the nullifier must be bound to the exact nk"
        );
    }
}
