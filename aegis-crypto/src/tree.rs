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
//! has no native append). [`IncrementalCmTree`] adds an append that
//! updates only the root-to-leaf path (O(depth·L) point ops) while
//! producing a root byte-for-byte identical to `from_set` — the node
//! maintains the tree across blocks instead of the old O(n) rebuild.

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

/// An incrementally-maintained consensus commitment tree.
///
/// [`Self::push`] appends one leaf by updating only the root-to-leaf
/// path (O(`TREE_DEPTH` · `TREE_L`) point operations) instead of
/// rebuilding the whole tree from the full leaf vector as [`build_tree`]
/// does (O(n)). This is the operational fix for the per-block O(n)
/// root recompute.
///
/// **Consensus invariant (oracle-tested):** the root after pushing
/// leaves `l_0 … l_{k-1}` in order is byte-for-byte identical to
/// `tree_root(&[l_0, …, l_{k-1}])`. A divergence here would split the
/// chain, so the tests compare against `from_set` exhaustively.
#[derive(Clone)]
pub struct IncrementalCmTree {
    /// `None` until the first leaf (the reference tree cannot represent
    /// the empty set — mirrors [`build_tree`]).
    tree: Option<AegisTree>,
    len: usize,
}

impl IncrementalCmTree {
    /// An empty tree (no leaves, no root).
    pub fn new() -> Self {
        IncrementalCmTree { tree: None, len: 0 }
    }

    /// Rebuild an incremental tree from a full leaf vector (O(n), via
    /// [`build_tree`]). Used on the cold/rollback path where the
    /// incremental state must be restored to an arbitrary prefix.
    pub fn from_leaves(leaves: &[EvenPoint]) -> Self {
        if leaves.is_empty() {
            Self::new()
        } else {
            IncrementalCmTree {
                tree: Some(build_tree(leaves)),
                len: leaves.len(),
            }
        }
    }

    /// Append one leaf, maintaining the depth-`TREE_DEPTH` tree.
    ///
    /// Panics beyond tree capacity (mirrors [`build_tree`]).
    pub fn push(&mut self, leaf: EvenPoint) {
        assert!(
            self.len < TREE_L.pow(TREE_DEPTH as u32),
            "leaf count exceeds tree capacity"
        );
        match &mut self.tree {
            // First leaf: `from_set` builds the pinned single-leaf tree
            // (the audited oracle for n = 1); every later leaf mutates.
            None => self.tree = Some(build_tree(&[leaf])),
            Some(tree) => tree.append(leaf, tree_params()),
        }
        self.len += 1;
    }

    /// Number of leaves appended so far.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no leaves have been appended.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The current root commitment point, or `None` while empty.
    pub fn root(&self) -> Option<EvenPoint> {
        self.tree.as_ref().map(root_point)
    }

    /// The maintained tree for proving/anchoring, or `None` while empty.
    pub fn tree(&self) -> Option<&AegisTree> {
        self.tree.as_ref()
    }
}

impl Default for IncrementalCmTree {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for IncrementalCmTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The tree itself is a large deterministic function of the leaf
        // sequence; only the leaf count is informative here.
        f.debug_struct("IncrementalCmTree")
            .field("len", &self.len)
            .finish()
    }
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

    // ----- incremental append: oracle parity vs `from_set` -----
    //
    // The whole safety case: appending leaves one at a time MUST produce
    // a tree whose root equals `from_set`'s root byte-for-byte, at every
    // count. A single mismatch is a chain split. We test this two ways:
    //   1. at small L (all structural transitions — new sub-nodes at
    //      every level — reachable with a handful of leaves), and
    //   2. at the real consensus L = 256 params (first-node fill,
    //      crossing into the second bottom node, and larger milestones).

    use curve_trees_relations::curve_tree::{CurveTree, SelRerandParameters};

    /// The `Even` root commitment of an arbitrary-`L` tree (all our trees
    /// have even depth ⇒ even root), for byte comparison.
    fn even_root<const L: usize>(tree: &CurveTree<L, TREE_M, SecpConfig, SecqConfig>) -> EvenPoint {
        match tree {
            CurveTree::Even(node) => node.commitment(0),
            CurveTree::Odd(_) => unreachable!("even-depth tree has an even root"),
        }
    }

    /// Compressed bytes of a point (the exact consensus artifact — this
    /// is what feeds the header `cm_tree_root` hash).
    fn root_bytes(p: &EvenPoint) -> Vec<u8> {
        use ark_serialize::CanonicalSerialize;
        let mut b = Vec::new();
        p.serialize_compressed(&mut b).unwrap();
        b
    }

    /// For `n` in `1..=n_max`, assert the incrementally-appended tree's
    /// root equals `from_set`'s root byte-for-byte at branching factor L.
    fn assert_incremental_parity<const L: usize>(
        n_max: usize,
        params: &SelRerandParameters<SecpConfig, SecqConfig>,
    ) {
        let mut leaves: Vec<EvenPoint> = Vec::with_capacity(n_max);
        let mut incremental: Option<CurveTree<L, TREE_M, SecpConfig, SecqConfig>> = None;
        for i in 0..n_max {
            let lf = leaf(i as u64 + 1);
            leaves.push(lf);
            match &mut incremental {
                None => {
                    incremental = Some(CurveTree::<L, TREE_M, _, _>::from_set(
                        &[lf],
                        params,
                        Some(TREE_DEPTH),
                    ))
                }
                Some(t) => t.append(lf, params),
            }
            let inc = incremental.as_ref().unwrap();
            let expected =
                CurveTree::<L, TREE_M, _, _>::from_set(&leaves, params, Some(TREE_DEPTH));
            // Root must match byte-for-byte.
            assert_eq!(
                root_bytes(&even_root(inc)),
                root_bytes(&even_root(&expected)),
                "L={L} n={} root diverged from from_set",
                i + 1
            );
            // Leaf count bookkeeping must match too.
            assert_eq!(inc.num_leaves(), i + 1, "L={L} n={} leaf count", i + 1);
        }
    }

    /// Small-L parameters (cheap; enough generators for width-L commits).
    fn small_params() -> SelRerandParameters<SecpConfig, SecqConfig> {
        SelRerandParameters::new(1 << 8, 1 << 8)
    }

    // ----- happy path (incremental) -----

    #[test]
    fn incremental_root_matches_from_set_l2_full_capacity() {
        // L=2, depth=4 ⇒ capacity 16: exhaustively fills the tree,
        // exercising a new child node at EVERY level (heights 1..4),
        // partial and full nodes, and multi-level carries — cheaply.
        assert_incremental_parity::<2>(16, &small_params());
    }

    #[test]
    fn incremental_root_matches_from_set_l3_partial_and_multilevel() {
        // L=3, depth=4 ⇒ capacity 81: odd branching, several full/partial
        // bottom nodes and a second-level carry (n=9 → new h1 sibling,
        // n=27 → new h2 subtree).
        assert_incremental_parity::<3>(30, &small_params());
    }

    #[test]
    fn incremental_root_matches_from_set_real_params_first_node() {
        // Real consensus L=256 params: empty→1, partial fills within the
        // first bottom node.
        assert_incremental_parity::<TREE_L>(24, tree_params());
    }

    #[test]
    fn incremental_root_matches_from_set_real_params_crosses_bottom_node() {
        // Real L=256: fill the first 256-child bottom node exactly, then
        // cross into a freshly-created second bottom node (n=256, 257…) —
        // the full-node + new-sibling transition on the true params.
        // Sample around the boundary to keep the O(n²) rebuild bounded.
        let params = tree_params();
        let mut leaves: Vec<EvenPoint> = Vec::new();
        let mut incremental: Option<CurveTree<TREE_L, TREE_M, SecpConfig, SecqConfig>> = None;
        // Points at and just past the first full bottom node.
        let checkpoints: std::collections::BTreeSet<usize> =
            [1, 2, 254, 255, 256, 257, 258, 300, 511, 512, 513]
                .into_iter()
                .collect();
        let n_max = 513;
        for i in 0..n_max {
            let lf = leaf(i as u64 + 1);
            leaves.push(lf);
            match &mut incremental {
                None => {
                    incremental = Some(CurveTree::<TREE_L, TREE_M, _, _>::from_set(
                        &[lf],
                        params,
                        Some(TREE_DEPTH),
                    ))
                }
                Some(t) => t.append(lf, params),
            }
            if checkpoints.contains(&(i + 1)) {
                let inc = incremental.as_ref().unwrap();
                let expected =
                    CurveTree::<TREE_L, TREE_M, _, _>::from_set(&leaves, params, Some(TREE_DEPTH));
                assert_eq!(
                    root_bytes(&even_root(inc)),
                    root_bytes(&even_root(&expected)),
                    "L=256 n={} root diverged from from_set",
                    i + 1
                );
            }
        }
    }

    // ----- round-trips (incremental wrapper) -----

    #[test]
    fn incremental_cm_tree_root_matches_tree_root_via_wrapper() {
        // The `IncrementalCmTree` wrapper (real consensus params) must
        // agree with the from-scratch `tree_root` at every height.
        let mut inc = IncrementalCmTree::new();
        assert!(inc.is_empty());
        assert_eq!(inc.root(), None);
        let mut leaves = Vec::new();
        for i in 0..40u64 {
            let lf = leaf(i);
            inc.push(lf);
            leaves.push(lf);
            assert_eq!(inc.len(), leaves.len());
            assert_eq!(
                root_bytes(&inc.root().unwrap()),
                root_bytes(&tree_root(&leaves)),
                "wrapper root diverged at n={}",
                leaves.len()
            );
        }
    }

    #[test]
    fn incremental_from_leaves_equals_pushed_sequence() {
        // Cold rebuild (`from_leaves`, used on rollback) must equal the
        // hot append sequence.
        let leaves: Vec<EvenPoint> = (0..37u64).map(leaf).collect();
        let cold = IncrementalCmTree::from_leaves(&leaves);
        let mut hot = IncrementalCmTree::new();
        for l in &leaves {
            hot.push(*l);
        }
        assert_eq!(cold.len(), hot.len());
        assert_eq!(
            root_bytes(&cold.root().unwrap()),
            root_bytes(&hot.root().unwrap())
        );
        assert_eq!(
            root_bytes(&cold.root().unwrap()),
            root_bytes(&tree_root(&leaves))
        );
    }

    // ----- oracle parity: membership proofs verify against the
    // incrementally-built tree identically to the from_set tree -----

    #[test]
    fn incremental_prover_witness_matches_from_set() {
        // A select-and-rerandomize prover witness (siblings + child
        // commitments along the path — deterministic, no rng) must be
        // identical whether the tree was built by `from_set` or by
        // incremental append, for every leaf index. Identical witnesses
        // ⇒ identical proofs verify.
        use ark_serialize::CanonicalSerialize;
        let params = tree_params();
        let n = 20usize;
        let leaves: Vec<EvenPoint> = (0..n as u64).map(leaf).collect();
        let from_set = build_tree(&leaves);
        let mut inc = IncrementalCmTree::new();
        for l in &leaves {
            inc.push(*l);
        }
        let inc_tree = inc.tree().unwrap();
        for index in 0..n {
            let w_ref = from_set.select_and_rerandomize_prover_witness(index, 0, params);
            let w_inc = inc_tree.select_and_rerandomize_prover_witness(index, 0, params);
            // Compare the serialized path (siblings + child witnesses).
            let ser = |w: &curve_trees_relations::curve_tree_prover::CurveTreeWitnessPath<
                TREE_L,
                SecpConfig,
                SecqConfig,
            >|
             -> (Vec<u8>, Vec<u8>) {
                let mut even = Vec::new();
                for node in &w.even_internal_nodes {
                    for s in node.siblings.iter() {
                        s.serialize_compressed(&mut even).unwrap();
                    }
                    node.child_witness.serialize_compressed(&mut even).unwrap();
                }
                let mut odd = Vec::new();
                for node in &w.odd_internal_nodes {
                    for s in node.siblings.iter() {
                        s.serialize_compressed(&mut odd).unwrap();
                    }
                    node.child_witness.serialize_compressed(&mut odd).unwrap();
                }
                (even, odd)
            };
            assert_eq!(
                ser(&w_ref),
                ser(&w_inc),
                "witness diverged at index {index}"
            );
        }
    }
}
