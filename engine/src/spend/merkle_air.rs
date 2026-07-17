//! Merkle-membership as AIR constraints — the privacy heart of the spend.
//!
//! Proves knowledge of a **private** leaf and a depth-[`DEPTH`] authentication
//! path that folds to a **public** root, without revealing which leaf. This is
//! what lets a spend hide *which* note it consumes (membership-in-a-tree instead
//! of naming the note). It is the direct hash-native replacement for the Curve
//! Tree's membership proof.
//!
//! # Layout
//! One trace row per tree level (level `t` compresses the level-`t` node with its
//! sibling into the level-`t+1` node). The trace is exactly `DEPTH = 32` rows —
//! already a power of two, so there is no padding to gate. Each row is one
//! Poseidon2 compression ([`PermCols`]) plus the extra columns:
//! `child[8]` (the running node entering this level), `sibling[8]`, `bit` (the
//! index bit: 0 ⇒ node is the left child, 1 ⇒ right).
//!
//! # Constraints, and the soundness of each (why omitting it is a hole)
//! - **`bit ∈ {0,1}`** (`bit·(bit−1)=0`). The conditional swap that assembles the
//!   permutation input is linear in `bit`; without booleanity a prover could pick
//!   a non-boolean `bit` and drive the "compression" input to an arbitrary blend
//!   of node/sibling — forging a path. Load-bearing.
//! - **Input assembly** `inputs == swap(child, sibling, bit)`. Binds the
//!   permutation's input to exactly `child‖sibling` (bit 0) or `sibling‖child`
//!   (bit 1). Without it the proven compression would be over unrelated values.
//! - **Permutation** (`eval_permutation`) — the compression itself.
//! - **Chaining** (transition): `next.child == this.output[0..8]`. The parent
//!   computed at level `t` must be the node entering level `t+1`. Without it the
//!   levels are independent and a prover could stitch unrelated compressions.
//! - **Root** (last row): `this.output[0..8] == public root`. Anchors the fold to
//!   the claimed accumulator root.
//!
//! What is intentionally NOT bound here: the leaf to a note opening or a
//! nullifier (added by the full spend circuit) — this is the isolated,
//! separately-tested membership building block.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::merkle::{MerklePath, DEPTH};
use crate::poseidon::{Digest, DIGEST_ELEMS, F};
use super::perm::{eval_permutation, fill_permutation, PermCols, PERM_COLS};

/// Offset of the `child[8]` columns within a membership row.
pub const CHILD_OFF: usize = PERM_COLS;
/// Offset of the `sibling[8]` columns.
pub const SIB_OFF: usize = PERM_COLS + DIGEST_ELEMS;
/// Offset of the `bit` column.
pub const BIT_OFF: usize = PERM_COLS + 2 * DIGEST_ELEMS;
/// Total membership row width.
pub const MEMB_ROW_W: usize = PERM_COLS + 2 * DIGEST_ELEMS + 1;

/// The Merkle-membership AIR (public: the 8-limb root).
#[derive(Debug, Default)]
pub struct MerkleMembershipAir;

impl BaseAir<F> for MerkleMembershipAir {
    fn width(&self) -> usize {
        MEMB_ROW_W
    }
    fn num_public_values(&self) -> usize {
        DIGEST_ELEMS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for MerkleMembershipAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();
        let cols: &PermCols<AB::Var> = cur[..PERM_COLS].borrow();

        // bit ∈ {0,1}
        let bit: AB::Expr = cur[BIT_OFF].into();
        builder.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));

        // Input assembly: conditional swap of child/sibling by `bit`.
        for j in 0..DIGEST_ELEMS {
            let c: AB::Expr = cur[CHILD_OFF + j].into();
            let s: AB::Expr = cur[SIB_OFF + j].into();
            builder.assert_eq(cols.inputs[j], c.clone() + bit.clone() * (s.clone() - c.clone()));
            builder.assert_eq(cols.inputs[j + DIGEST_ELEMS], s.clone() + bit.clone() * (c - s));
        }

        let output = eval_permutation(builder, cols);

        // Chaining: the parent at this level is the child entering the next.
        for j in 0..DIGEST_ELEMS {
            let next_child: AB::Expr = next[CHILD_OFF + j].into();
            builder
                .when_transition()
                .assert_eq(next_child, output[j].clone());
        }

        // Root anchor on the final level.
        let pv = builder.public_values().to_vec();
        for (j, out) in output.into_iter().take(DIGEST_ELEMS).enumerate() {
            builder.when_last_row().assert_eq(out, pv[j].into());
        }
    }
}

/// Build the membership trace for `leaf` with authentication `path`.
pub fn membership_trace(leaf: Digest, path: &MerklePath) -> RowMajorMatrix<F> {
    let mut values = vec![F::default(); DEPTH * MEMB_ROW_W];
    let mut child = leaf;
    let mut idx = path.index;
    for t in 0..DEPTH {
        let row = &mut values[t * MEMB_ROW_W..(t + 1) * MEMB_ROW_W];
        let sib = path.siblings[t];
        let bit = (idx & 1) as u32;
        let mut input = [F::default(); 16];
        if bit == 0 {
            input[..DIGEST_ELEMS].copy_from_slice(&child);
            input[DIGEST_ELEMS..].copy_from_slice(&sib);
        } else {
            input[..DIGEST_ELEMS].copy_from_slice(&sib);
            input[DIGEST_ELEMS..].copy_from_slice(&child);
        }
        let out = fill_permutation(&mut row[..PERM_COLS], input);
        row[CHILD_OFF..CHILD_OFF + DIGEST_ELEMS].copy_from_slice(&child);
        row[SIB_OFF..SIB_OFF + DIGEST_ELEMS].copy_from_slice(&sib);
        row[BIT_OFF] = F::from_u32(bit);
        child = out[..DIGEST_ELEMS].try_into().expect("8 of 16");
        idx >>= 1;
    }
    RowMajorMatrix::new(values, MEMB_ROW_W)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::make_config;
    use crate::merkle::NoteTree;
    use p3_uni_stark::{prove, verify};

    // ----- helpers -----

    fn leaf(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    /// A tree with a few leaves; returns (tree, the leaf we will prove, index).
    fn tree_with_leaf() -> (NoteTree, Digest, u64) {
        let mut t = NoteTree::new();
        for i in 0..6u32 {
            t.append(leaf(1000 + i * 10));
        }
        let target = leaf(1030); // index 3
        (t, target, 3)
    }

    // ----- happy path -----

    #[test]
    fn membership_proof_verifies() {
        let (tree, target, idx) = tree_with_leaf();
        let path = tree.authentication_path(idx);
        let root = tree.root();
        let trace = membership_trace(target, &path);
        let pis = root.to_vec();

        let config = make_config();
        let air = MerkleMembershipAir;
        let proof = prove(&config, &air, trace, &pis);
        assert!(verify(&config, &air, &proof, &pis).is_ok());
    }

    // ----- error paths -----

    #[test]
    fn membership_rejects_wrong_root() {
        let (tree, target, idx) = tree_with_leaf();
        let path = tree.authentication_path(idx);
        let trace = membership_trace(target, &path);
        let pis = tree.root().to_vec();

        let config = make_config();
        let air = MerkleMembershipAir;
        let proof = prove(&config, &air, trace, &pis);

        let mut bad = pis.clone();
        bad[0] += F::ONE; // a different accumulator root
        assert!(
            verify(&config, &air, &proof, &bad).is_err(),
            "membership must not verify against a root the leaf is not under"
        );
    }
}
