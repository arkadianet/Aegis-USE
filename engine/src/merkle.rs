//! The Poseidon-Merkle note accumulator (replaces the Curve Tree).
//!
//! A binary Merkle tree of depth 32 (2^32 leaf capacity — the same capacity as
//! the current depth-4, L=256 Curve Tree), whose internal-node hash is the t=16
//! Poseidon2 2-to-1 compression ([`crate::poseidon::compress`]). Membership is a
//! Merkle path; the spend circuit proves a note's `cm` is a member at the tree
//! root ([`crate::spend`]).
//!
//! This is an **incremental, append-only** tree (Zcash/Tornado-style): empty
//! subtrees have precomputed default roots, so the tree behaves as a full
//! depth-32 tree while storing only the O(appended · depth) touched nodes. That
//! is enough to (a) append leaves, (b) track the current root, and (c) produce a
//! membership path for any appended leaf — the operations the accumulator and
//! the circuit need.
//!
//! # Frontier — the O(log n) settlement-transition state ([`Frontier`])
//! [`NoteTree`] holds every touched node (O(appended · depth)); rebuilding it to
//! transition the root therefore costs O(total leaves) — the settlement guest's
//! old `tree_transition` re-walked the ENTIRE pre-epoch history every proof. A
//! [`Frontier`] is the compact append boundary — one left-sibling per level plus
//! the leaf count — sufficient to append new leaves and recompute the root
//! WITHOUT the rest of the tree. Committing the frontier into the state root
//! ([`Frontier::commit`]) authenticates that boundary, so an epoch's appends are
//! proved with O(epoch · depth) compressions instead of O(total). The two agree
//! by construction and are cross-checked against [`NoteTree`] as the oracle.
//!
//! # Pinned constants (REVIEW ITEMS)
//! - `DEPTH = 32`.
//! - `EMPTY_LEAF` = the all-zero digest — a nothing-up-my-sleeve empty-leaf
//!   value; `zeros[level]` is the root of an all-empty subtree of that height.
//!   Level domain-separation of the compression (leaf-vs-node / per-height) is
//!   **not** applied here (the compression matches Plonky3's plain
//!   `TruncatedPermutation`); whether to domain-separate tree levels is a
//!   flagged review item.

use std::collections::HashMap;

use p3_field::PrimeCharacteristicRing;

use crate::poseidon::{compress, hash_domain, Digest, DIGEST_ELEMS, DOMAIN_FRONTIER, F};

/// Tree depth (2^32 leaf capacity).
pub const DEPTH: usize = 32;

/// The empty-leaf digest (nothing-up-my-sleeve; REVIEW ITEM).
pub const EMPTY_LEAF: Digest = [F::ZERO; 8];

/// A membership proof for a leaf: the sibling at each level (bottom→top) and the
/// leaf's index (the path bits `= (index >> level) & 1`; bit 1 ⇒ the node is a
/// right child, so its sibling is on the left).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MerklePath {
    pub siblings: [Digest; DEPTH],
    pub index: u64,
}

/// Precomputed empty-subtree roots: `zeros[0] = EMPTY_LEAF`,
/// `zeros[i+1] = compress(zeros[i], zeros[i])`.
fn zeros() -> &'static [Digest; DEPTH + 1] {
    use std::sync::OnceLock;
    static Z: OnceLock<[Digest; DEPTH + 1]> = OnceLock::new();
    Z.get_or_init(|| {
        let mut z = [EMPTY_LEAF; DEPTH + 1];
        for level in 0..DEPTH {
            z[level + 1] = compress(&z[level], &z[level]);
        }
        z
    })
}

/// An incremental append-only Poseidon-Merkle tree of depth [`DEPTH`].
#[derive(Clone, Debug)]
pub struct NoteTree {
    /// Explicitly-set nodes keyed by `(level, index_within_level)`; absent nodes
    /// take their empty-subtree default from [`zeros`].
    nodes: HashMap<(usize, u64), Digest>,
    /// Number of appended leaves (the index the next leaf will take).
    next_index: u64,
}

impl Default for NoteTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteTree {
    /// A fresh empty tree.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            next_index: 0,
        }
    }

    /// The number of appended leaves.
    pub fn len(&self) -> u64 {
        self.next_index
    }

    /// Whether no leaves have been appended.
    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    fn node(&self, level: usize, index: u64) -> Digest {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or_else(|| zeros()[level])
    }

    /// The current tree root (root of a full depth-[`DEPTH`] tree with empty
    /// subtrees for the unfilled positions).
    pub fn root(&self) -> Digest {
        self.node(DEPTH, 0)
    }

    /// Append `leaf` (a note commitment), returning its leaf index. Recomputes
    /// and stores the path to the root.
    ///
    /// # Panics
    /// If the tree is full (2^32 leaves).
    pub fn append(&mut self, leaf: Digest) -> u64 {
        assert!(self.next_index < (1u64 << DEPTH), "note tree is full");
        let index = self.next_index;
        self.nodes.insert((0, index), leaf);

        let mut idx = index;
        for level in 0..DEPTH {
            let (left, right) = if idx & 1 == 0 {
                (self.node(level, idx), self.node(level, idx ^ 1))
            } else {
                (self.node(level, idx ^ 1), self.node(level, idx))
            };
            let parent = compress(&left, &right);
            idx >>= 1;
            self.nodes.insert((level + 1, idx), parent);
        }
        self.next_index += 1;
        index
    }

    /// The membership path for an appended `index`.
    ///
    /// # Panics
    /// If `index` has not been appended.
    pub fn authentication_path(&self, index: u64) -> MerklePath {
        assert!(index < self.next_index, "leaf {index} not appended");
        let mut siblings = [EMPTY_LEAF; DEPTH];
        let mut idx = index;
        for (level, sib) in siblings.iter_mut().enumerate() {
            *sib = self.node(level, idx ^ 1);
            idx >>= 1;
        }
        MerklePath { siblings, index }
    }
}

/// Recompute a root from a leaf and its membership path — the native mirror of
/// the circuit's Merkle-membership constraint. `index` bit at each level selects
/// whether the running node is the left (bit 0) or right (bit 1) child.
pub fn root_from_path(leaf: &Digest, path: &MerklePath) -> Digest {
    let mut node = *leaf;
    let mut idx = path.index;
    for sib in &path.siblings {
        node = if idx & 1 == 0 {
            compress(&node, sib)
        } else {
            compress(sib, &node)
        };
        idx >>= 1;
    }
    node
}

/// The compact append boundary of the depth-[`DEPTH`] note tree: exactly the
/// state needed to append new leaves and recompute the root without holding the
/// rest of the tree.
///
/// `filled[level]` caches, for each level, the value that will be the LEFT
/// sibling of the next node inserted at that level — i.e. the root of the most
/// recent completed left subtree at that level. Levels the current append path
/// does not descend into a right child of default to the empty-subtree root
/// ([`zeros`]). Together with `leaf_count` this is O([`DEPTH`]) digests, and
/// `root()`/`append()` are the standard Zcash/Tornado incremental-tree
/// recurrences — verified against the full [`NoteTree`] rebuild as the oracle.
///
/// # Soundness
/// The root is a deterministic function of the frontier ([`Frontier::root`]), so
/// committing the frontier ([`Frontier::commit`]) into the state root
/// authenticates the root it produces. A prover who advanced a *wrong* frontier
/// would compute a different, non-matching root — it cannot forge membership.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Frontier {
    /// Per-level left-sibling cache (`filled[level]` defaults to `zeros[level]`).
    filled: [Digest; DEPTH],
    /// Number of appended leaves (the index the next leaf will take).
    leaf_count: u64,
}

impl Default for Frontier {
    fn default() -> Self {
        Self::new()
    }
}

impl Frontier {
    /// A fresh empty frontier — its [`root`](Self::root) is the empty-tree root.
    pub fn new() -> Self {
        Self {
            filled: core::array::from_fn(|level| zeros()[level]),
            leaf_count: 0,
        }
    }

    /// The number of appended leaves.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Whether no leaves have been appended.
    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    /// The current tree root, recomputed from the boundary in [`DEPTH`]
    /// compressions (O(log n), independent of history). Equals
    /// [`NoteTree::root`] for the same leaf sequence.
    pub fn root(&self) -> Digest {
        let mut idx = self.leaf_count;
        let mut node = zeros()[0];
        for level in 0..DEPTH {
            node = if idx & 1 == 1 {
                // Next position is a right child: its left sibling is cached.
                compress(&self.filled[level], &node)
            } else {
                // Next position is a left child: the right subtree is empty.
                compress(&node, &zeros()[level])
            };
            idx >>= 1;
        }
        node
    }

    /// Append `leaf`, advancing the boundary in [`DEPTH`] compressions, and
    /// return the resulting root. Mirrors [`NoteTree::append`]'s root exactly.
    ///
    /// # Panics
    /// If the tree is full (2^[`DEPTH`] leaves).
    pub fn append(&mut self, leaf: Digest) -> Digest {
        assert!(self.leaf_count < (1u64 << DEPTH), "note tree is full");
        let mut idx = self.leaf_count;
        let mut node = leaf;
        for level in 0..DEPTH {
            if idx & 1 == 0 {
                // Left child: this node becomes the future left sibling here.
                self.filled[level] = node;
                node = compress(&node, &zeros()[level]);
            } else {
                // Right child: complete the pair with the cached left sibling.
                node = compress(&self.filled[level], &node);
            }
            idx >>= 1;
        }
        self.leaf_count += 1;
        node
    }

    /// Build a frontier by appending `leaves` in order (native mirror of the
    /// chain accumulating its history into the committed boundary).
    pub fn from_leaves(leaves: &[Digest]) -> Self {
        let mut f = Self::new();
        for leaf in leaves {
            let _ = f.append(*leaf);
        }
        f
    }

    /// Domain-separated Poseidon commitment to the frontier, embedded into the
    /// settlement state root so the append boundary is authenticated:
    /// `H_FRONTIER(leaf_count_lo ‖ leaf_count_hi ‖ filled[0..DEPTH])`.
    ///
    /// Binding `leaf_count` matters: the same `filled` array at a different count
    /// denotes a different tree shape (different root), so both are committed.
    pub fn commit(&self) -> Digest {
        let mut input = Vec::with_capacity(2 + DEPTH * DIGEST_ELEMS);
        input.push(F::from_u64(self.leaf_count & 0xFFFF_FFFF));
        input.push(F::from_u64(self.leaf_count >> 32));
        for node in &self.filled {
            input.extend_from_slice(node);
        }
        hash_domain(DOMAIN_FRONTIER, &input)
    }
}

/// The incremental settlement tree-transition — the O(epoch) replacement for the
/// old O(total) `tree_transition`.
///
/// Given the pre-epoch `frontier` (authenticated by `prev_state_root` via
/// [`Frontier::commit`]) and the epoch's new note commitments in consensus
/// order, advance the boundary over exactly those `N` leaves and return
/// `(prev_root, new_frontier)`. `prev_root` is read from the input frontier (no
/// history walk); `new_frontier.root()` is the post-epoch note-commitment root
/// and `new_frontier.commit()` is what the new state root commits. Cost is
/// `N · DEPTH` compressions — independent of how many leaves preceded the epoch.
pub fn settle_tree_transition(frontier: &Frontier, epoch_leaves: &[Digest]) -> (Digest, Frontier) {
    let prev_root = frontier.root();
    let mut next = frontier.clone();
    for leaf in epoch_leaves {
        let _ = next.append(*leaf);
    }
    (prev_root, next)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn leaf(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    // ----- happy path -----

    #[test]
    fn empty_tree_root_is_the_empty_subtree_root() {
        assert_eq!(NoteTree::new().root(), zeros()[DEPTH]);
    }

    #[test]
    fn append_advances_index_and_changes_root() {
        let mut t = NoteTree::new();
        let r0 = t.root();
        assert_eq!(t.append(leaf(1)), 0);
        assert_eq!(t.append(leaf(2)), 1);
        assert_eq!(t.len(), 2);
        assert_ne!(t.root(), r0);
    }

    // ----- round-trips -----

    #[test]
    fn membership_path_reproduces_root_for_every_leaf() {
        let mut t = NoteTree::new();
        let leaves: Vec<Digest> = (0..5).map(|i| leaf(100 + i * 10)).collect();
        for l in &leaves {
            t.append(*l);
        }
        let root = t.root();
        for (i, l) in leaves.iter().enumerate() {
            let path = t.authentication_path(i as u64);
            assert_eq!(path.index, i as u64);
            assert_eq!(
                root_from_path(l, &path),
                root,
                "path for leaf {i} must recompute the root"
            );
        }
    }

    #[test]
    fn path_depth_is_full_32() {
        let mut t = NoteTree::new();
        t.append(leaf(1));
        assert_eq!(t.authentication_path(0).siblings.len(), 32);
    }

    // ----- error paths -----

    #[test]
    fn wrong_leaf_does_not_reproduce_root() {
        let mut t = NoteTree::new();
        t.append(leaf(1));
        t.append(leaf(2));
        let path = t.authentication_path(0);
        assert_ne!(
            root_from_path(&leaf(999), &path),
            t.root(),
            "a leaf not at this position must not verify"
        );
    }

    #[test]
    fn tampered_sibling_breaks_the_path() {
        let mut t = NoteTree::new();
        t.append(leaf(1));
        t.append(leaf(2));
        let mut path = t.authentication_path(0);
        path.siblings[0][0] += F::ONE;
        assert_ne!(root_from_path(&leaf(1), &path), t.root());
    }

    // ----- oracle parity (Frontier vs full NoteTree rebuild) -----
    //
    // The full NoteTree rebuild is the ORACLE. The incremental Frontier root
    // must byte-match it at every step — a wrong frontier update would let a
    // prover forge membership, so these span the internal-node boundaries where
    // an off-by-one in the recurrence would surface.

    #[test]
    fn frontier_empty_root_matches_notetree() {
        assert_eq!(Frontier::new().root(), NoteTree::new().root());
        assert_eq!(Frontier::new().root(), zeros()[DEPTH]);
    }

    #[test]
    fn frontier_root_matches_notetree_at_every_prefix() {
        // 0..=300 crosses the 1,2,4,8,…,256 power-of-two boundaries.
        let mut tree = NoteTree::new();
        let mut frontier = Frontier::new();
        assert_eq!(frontier.root(), tree.root(), "empty prefix");
        for i in 0..300u32 {
            let l = leaf(1 + i * 7);
            let tree_root = {
                tree.append(l);
                tree.root()
            };
            let append_root = frontier.append(l);
            assert_eq!(
                frontier.leaf_count(),
                tree.len(),
                "leaf counts track at prefix {}",
                i + 1
            );
            assert_eq!(
                append_root,
                tree_root,
                "Frontier::append root diverges from NoteTree at {} leaves",
                i + 1
            );
            assert_eq!(
                frontier.root(),
                tree_root,
                "Frontier::root diverges from NoteTree at {} leaves",
                i + 1
            );
        }
    }

    #[test]
    fn frontier_root_matches_notetree_on_full_subtree_boundaries() {
        // Exactly-full subtrees (K a power of two) are the boundaries where the
        // rightmost path flips at every level at once.
        for k in [1u32, 2, 4, 8, 16, 32, 64, 128, 256, 512] {
            let leaves: Vec<Digest> = (0..k).map(|i| leaf(1000 + i)).collect();
            let mut tree = NoteTree::new();
            for l in &leaves {
                tree.append(*l);
            }
            assert_eq!(
                Frontier::from_leaves(&leaves).root(),
                tree.root(),
                "frontier != full rebuild at K={k}"
            );
        }
    }

    #[test]
    fn settle_transition_empty_epoch_is_identity() {
        let pre: Vec<Digest> = (0..37).map(|i| leaf(500 + i)).collect();
        let frontier = Frontier::from_leaves(&pre);
        let (prev_root, next) = settle_tree_transition(&frontier, &[]);
        assert_eq!(prev_root, frontier.root(), "prev_root is the input root");
        assert_eq!(
            next.root(),
            frontier.root(),
            "empty epoch leaves root fixed"
        );
        assert_eq!(next, frontier, "empty epoch leaves the frontier untouched");
    }

    #[test]
    fn settle_transition_single_leaf_epoch_matches_rebuild() {
        let pre: Vec<Digest> = (0..70).map(leaf).collect();
        let epoch = [leaf(9999)];
        let (prev_root, next) = settle_tree_transition(&Frontier::from_leaves(&pre), &epoch);

        let mut full = NoteTree::new();
        for l in &pre {
            full.append(*l);
        }
        assert_eq!(prev_root, full.root());
        full.append(epoch[0]);
        assert_eq!(next.root(), full.root());
    }

    #[test]
    fn settle_transition_multi_epoch_matches_single_full_rebuild() {
        // Carry ONE persisted frontier across several epochs of varied size —
        // including empty and full-subtree-crossing epochs — and check every
        // boundary root against the single full rebuild of the same sequence.
        let epoch_sizes = [1usize, 0, 7, 64, 1, 100, 0, 128, 33];
        let mut all: Vec<Digest> = Vec::new();
        let mut frontier = Frontier::new();
        let mut base = 0u32;
        for &n in &epoch_sizes {
            let epoch: Vec<Digest> = (0..n as u32).map(|i| leaf(base + i)).collect();
            base += 1000;
            let (prev_root, next) = settle_tree_transition(&frontier, &epoch);

            // prev_root is the root over everything appended so far.
            let mut full_pre = NoteTree::new();
            for l in &all {
                full_pre.append(*l);
            }
            assert_eq!(prev_root, full_pre.root(), "prev_root at epoch size {n}");

            all.extend_from_slice(&epoch);
            let mut full_post = NoteTree::new();
            for l in &all {
                full_post.append(*l);
            }
            assert_eq!(next.root(), full_post.root(), "new_root at epoch size {n}");
            frontier = next;
        }
    }

    #[test]
    fn frontier_commit_is_deterministic() {
        let pre: Vec<Digest> = (0..50).map(leaf).collect();
        assert_eq!(
            Frontier::from_leaves(&pre).commit(),
            Frontier::from_leaves(&pre).commit(),
            "commit is a pure function of the frontier"
        );
    }

    #[test]
    fn frontier_commit_binds_leaf_count() {
        // Same reachable-tree root can never coincide across counts, but even the
        // commitment must separate a boundary from its one-leaf-shorter self.
        let pre: Vec<Digest> = (0..64).map(leaf).collect();
        let a = Frontier::from_leaves(&pre[..63]);
        let b = Frontier::from_leaves(&pre[..64]);
        assert_ne!(a.commit(), b.commit(), "count is bound into the commitment");
    }

    #[test]
    fn frontier_commit_changes_when_history_changes() {
        let a = Frontier::from_leaves(&(0..20).map(leaf).collect::<Vec<_>>());
        let mut leaves: Vec<Digest> = (0..20).map(leaf).collect();
        leaves[19] = leaf(424242); // change the last appended leaf
        let b = Frontier::from_leaves(&leaves);
        assert_ne!(a.root(), b.root(), "different history ⇒ different root");
        assert_ne!(
            a.commit(),
            b.commit(),
            "different history ⇒ different commit"
        );
    }

    #[test]
    fn tampered_frontier_diverges_from_true_root() {
        // A prover who advances a corrupted frontier cannot land on the true
        // root — the forge-membership hole is closed by root determinism.
        let pre: Vec<Digest> = (0..40).map(leaf).collect();
        let mut tampered = Frontier::from_leaves(&pre);
        let true_root = tampered.root();
        tampered.filled[3][0] += F::ONE;
        assert_ne!(
            tampered.append(leaf(7777)),
            {
                let mut honest = Frontier::from_leaves(&pre);
                honest.append(leaf(7777))
            },
            "tampered boundary must not reproduce the honest next root"
        );
        assert_ne!(tampered.root(), true_root);
    }

    // ----- measurement (ignored; the transition-cost collapse) -----

    #[test]
    #[ignore = "measurement — run: cargo test -p aegis-engine measure_transition -- --ignored --nocapture"]
    fn measure_transition_compress_collapse() {
        use std::time::Instant;

        let pre_n = 10_000usize;
        let epoch_n = 200usize;
        let pre: Vec<Digest> = (0..pre_n as u32).map(leaf).collect();
        let epoch: Vec<Digest> = (0..epoch_n as u32).map(|i| leaf(1_000_000 + i)).collect();

        // OLD path: the guest rebuilt pre+epoch from empty every proof (O(total)).
        let t0 = Instant::now();
        let mut full = NoteTree::new();
        for l in &pre {
            full.append(*l);
        }
        let _old_prev = full.root();
        for l in &epoch {
            full.append(*l);
        }
        let old_root = full.root();
        let old_wall = t0.elapsed();

        // NEW path: the pre-epoch frontier is a committed state input (built by
        // the chain, NOT re-walked in the proof); only the epoch advances it.
        let frontier = Frontier::from_leaves(&pre);
        let t1 = Instant::now();
        let (_prev_root, next) = settle_tree_transition(&frontier, &epoch);
        let new_root = next.root();
        let new_wall = t1.elapsed();

        assert_eq!(
            old_root, new_root,
            "incremental root must equal full rebuild"
        );

        // compress() (= one Poseidon2 permutation) is the RISC0 cycle driver of
        // the tree-transition term. NoteTree::append, Frontier::append and
        // Frontier::root each do exactly DEPTH compressions.
        let old_compress = (pre_n + epoch_n) * DEPTH; // rebuild pre + epoch
        let new_compress = (epoch_n + 1) * DEPTH; // epoch appends + one prev-root read
        println!(
            "tree_transition compress calls: OLD={old_compress} NEW={new_compress} \
             ({:.1}x fewer)  wall OLD={old_wall:?} NEW={new_wall:?}",
            old_compress as f64 / new_compress as f64,
        );
    }
}
