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

use crate::poseidon::{compress, Digest, F};

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
}
