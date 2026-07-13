//! Consensus commitment tree — the vendored curve-trees `CurveTree`
//! wrapped behind pinned parameters (consensus.md §5a).
//!
//! v1 parameters: L = 256, M = 1, depth = 4 (capacity 2^32 leaves — the
//! g15 spike configuration). Tree/Pedersen/delta generators are the
//! reference implementation's own deterministic derivation, adopted
//! verbatim so the audited base stays the byte oracle; retagging to
//! `"aegis:bp:v1"` NUMS bases is a freeze-time, chain-id-breaking
//! decision (DEFERRED.md).
//!
//! `from_set` rebuilds the tree from the full leaf set (the reference
//! has no append), so the node recomputes the root per block — O(n)
//! engineering debt tracked in DEFERRED.md, fine at dev scale.

use std::sync::OnceLock;

use curve_trees_relations::curve_tree::{CurveTree, SelRerandParameters};

use crate::generators::EvenPoint;

/// Branching factor (children per branch node).
pub const TREE_L: usize = 256;
/// Batched-membership width (single-path proofs, per the reference Pour).
pub const TREE_M: usize = 1;
/// Tree depth — root parity is even (leaf 0 even → depth 4 even).
pub const TREE_DEPTH: usize = 4;
/// Generator vector length — sized for the depth-4 spend circuits
/// (reference: `1 << 13`); the bp-gens chain is prefix-stable, so tree
/// roots are unchanged versus a shorter vector (pinned root test is the
/// canary).
pub const TREE_GENS_LEN: usize = 1 << 13;

type SecpConfig = ark_secp256k1::Config;
type SecqConfig = ark_secq256k1::Config;

/// The 2-cycle select-and-rerandomize parameter set (reference derivation).
pub type TreeParameters = SelRerandParameters<SecpConfig, SecqConfig>;

/// The consensus Curve Tree at the v1 parameters.
pub type AegisTree = CurveTree<TREE_L, TREE_M, SecpConfig, SecqConfig>;

/// A select-and-rerandomize path through the consensus tree.
pub type AegisPath =
    curve_trees_relations::curve_tree::SelectAndRerandomizePath<TREE_L, SecpConfig, SecqConfig>;

/// Lazily-built consensus tree parameters (deterministic, no rng).
pub fn tree_params() -> &'static TreeParameters {
    static PARAMS: OnceLock<TreeParameters> = OnceLock::new();
    PARAMS.get_or_init(|| TreeParameters::new(TREE_GENS_LEN, TREE_GENS_LEN))
}

/// Build the consensus tree from a non-empty leaf set.
///
/// Panics on an empty set (the reference cannot represent one — the
/// consensus empty-set root is the pinned sentinel constant, guarded by
/// the caller) and beyond capacity.
pub fn build_tree(leaves: &[EvenPoint]) -> AegisTree {
    assert!(
        !leaves.is_empty(),
        "empty set has no Curve Tree root — use the consensus sentinel"
    );
    assert!(
        leaves.len() <= TREE_L.pow(TREE_DEPTH as u32),
        "leaf count exceeds tree capacity"
    );
    CurveTree::from_set(leaves, tree_params(), Some(TREE_DEPTH))
}

/// Root commitment point of a consensus tree (depth-4 ⇒ even curve).
pub fn root_point(tree: &AegisTree) -> EvenPoint {
    match tree {
        CurveTree::Even(node) => node.commitment(0),
        CurveTree::Odd(_) => unreachable!("depth-4 root alternates back to the even curve"),
    }
}

/// Curve Tree root of a non-empty leaf set at the consensus depth.
pub fn tree_root(leaves: &[EvenPoint]) -> EvenPoint {
    root_point(&build_tree(leaves))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::{g_prf, g_value};
    use crate::note::{note_commitment, EvenScalar};
    use ark_ec::AffineRepr;

    // ----- helpers -----

    fn leaf(seed: u64) -> EvenPoint {
        note_commitment(seed, EvenScalar::from(seed + 1), EvenScalar::from(seed + 2))
    }

    // ----- happy path -----

    #[test]
    fn tree_root_is_deterministic() {
        let leaves = [leaf(1), leaf(2), leaf(3)];
        assert_eq!(tree_root(&leaves), tree_root(&leaves));
    }

    #[test]
    fn tree_root_is_order_sensitive() {
        let a = [leaf(1), leaf(2)];
        let b = [leaf(2), leaf(1)];
        assert_ne!(tree_root(&a), tree_root(&b));
    }

    #[test]
    fn tree_root_changes_with_set_content() {
        let base = tree_root(&[leaf(1), leaf(2)]);
        assert_ne!(base, tree_root(&[leaf(1), leaf(3)]));
        assert_ne!(base, tree_root(&[leaf(1)]));
    }

    #[test]
    fn tree_root_is_a_valid_nonidentity_point_distinct_from_leaves() {
        let leaves = [leaf(7)];
        let root = tree_root(&leaves);
        assert!(root.is_on_curve());
        assert!(!root.is_zero());
        assert_ne!(root, leaves[0]);
    }

    // ----- error paths -----

    #[test]
    #[should_panic(expected = "empty set has no Curve Tree root")]
    fn tree_root_of_empty_set_panics() {
        let _ = tree_root(&[]);
    }

    // ----- oracle parity -----

    #[test]
    fn tree_root_matches_pinned_reference_vector() {
        // Oracle: the vendored curve-trees implementation itself
        // (note-protocol.md §8 — no reference node exists; the audited
        // reference is the pinned byte oracle). Captured once from
        // vendor @969e12a with the v1 parameters; any change to tree
        // params, generator derivation, or the vendored tree code that
        // moves this root is chain-id-breaking and must be deliberate.
        let leaves = [
            note_commitment(
                1_000,
                crate::note::EvenScalar::from(0x1111u64),
                crate::note::EvenScalar::from(0x2222u64),
            ),
            g_value(),
            g_prf(),
        ];
        let root = tree_root(&leaves);
        let bytes = crate::note::note_cm_bytes(&root);
        assert_eq!(hex::encode(bytes), PINNED_ROOT_HEX);
    }

    /// Captured from the vendored implementation — see the test comment.
    const PINNED_ROOT_HEX: &str =
        "13f4802ccd69714eec3f2848124b5e58d4252397a2c90bd0c4f69a97e06d193200";
}
