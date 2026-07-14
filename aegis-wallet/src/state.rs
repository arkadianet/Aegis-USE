//! Wallet state — reconstructed from the node's blocks (M4 slice 2).
//!
//! The wallet rebuilds the **same** consensus Curve Tree the node does,
//! from the same note-commitment leaves in the same order, so it can
//! produce membership witnesses for its own notes (`wallet-design.md`
//! §4). Slice 2 tracks only SELF-owned notes (see [`crate::notes`]); the
//! journal of `(value, index)` records is the wallet's, and scanning
//! *recognizes* those notes among the chain's leaves by recomputing their
//! commitments — no ciphertext, since note encryption is held (slice 3).
//!
//! ## Leaf order (must match `aegis-node::state::ShieldedState`)
//! Per block, in canonical height order: each transfer's two outputs
//! (in tx-then-slot order), then the block's coinbase note (if any). A
//! divergence here would make every membership witness wrong, so [`scan`]
//! cross-checks its rebuilt root against the node's published
//! `cm_tree_root` and refuses a mismatch.
//!
//! [`scan`]: WalletState::scan

use std::collections::{BTreeSet, HashMap};

use aegis_crypto::generators::EvenPoint;
use aegis_crypto::note::{note_cm_bytes, note_cm_from_bytes, NOTE_CM_BYTES};
use aegis_crypto::nullifier::NF_BYTES;
use aegis_crypto::tree::{build_tree, tree_root, AegisTree};
use aegis_types::Block;
use ergo_crypto::autolykos::common::blake2b256;

use crate::client::{ClientError, NodeClient};
use crate::keys::SpendingKey;
use crate::notes::SelfNote;

// Header commitment-tree-root construction, mirrored from
// `aegis-node::state` (consensus.md §5a) so the wallet can verify its
// rebuild against the node's published `/state` root. Duplicated here
// deliberately — the wallet must not link the node — and pinned against
// the real node in an integration test (a follow-up may promote these to
// a shared crate; see the module doc).
const CM_ROOT_DOMAIN: &[u8] = b"aegis:cm-root:v1";
const EMPTY_TREE_ROOT_PLACEHOLDER: [u8; 32] = *b"aegis/empty-curve-tree-root/v1..";

/// The node's header `cm_tree_root` for a leaf vector: the pinned
/// sentinel while empty, else `blake2b256(domain ‖ compressed root)`.
pub fn node_cm_tree_root(leaves: &[EvenPoint]) -> [u8; 32] {
    if leaves.is_empty() {
        return EMPTY_TREE_ROOT_PLACEHOLDER;
    }
    let root = tree_root(leaves);
    let mut preimage = Vec::with_capacity(CM_ROOT_DOMAIN.len() + NOTE_CM_BYTES);
    preimage.extend_from_slice(CM_ROOT_DOMAIN);
    preimage.extend_from_slice(&note_cm_bytes(&root));
    blake2b256(&preimage)
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("output note commitment in block {height} is not a canonical curve point")]
    InvalidNoteCommitment { height: u64 },
    #[error(
        "rebuilt tree diverges from the node at height {height}: \
         wallet leaf_count {wallet_leaves} vs node {node_leaves}, \
         root match: {root_match}"
    )]
    RootMismatch {
        height: u64,
        wallet_leaves: usize,
        node_leaves: u64,
        root_match: bool,
    },
}

/// A journalled self-note plus what the last scan learned about it.
#[derive(Debug, Clone, Copy)]
pub struct TrackedNote {
    pub note: SelfNote,
    /// Position in the consensus leaf vector, once a scan has found the
    /// note's commitment among the chain's leaves.
    pub leaf_index: Option<usize>,
    /// Whether the note's nullifier has appeared on-chain (spent).
    pub spent: bool,
}

impl TrackedNote {
    /// Confirmed and unspent — i.e. spendable.
    pub fn is_spendable(&self) -> bool {
        self.leaf_index.is_some() && !self.spent
    }
}

/// What one [`WalletState::scan`] learned.
#[derive(Debug, Clone)]
pub struct ScanReport {
    pub target_height: u64,
    pub leaf_count: usize,
    pub notes_resolved: usize,
    pub notes_spent: usize,
    pub balance: u64,
}

/// The wallet's reconstructed view: its note journal plus the leaf vector
/// (hence the anchor tree) from the last scan.
#[derive(Debug, Default)]
pub struct WalletState {
    notes: Vec<TrackedNote>,
    next_index: u64,
    leaves: Vec<EvenPoint>,
    scanned_height: u64,
}

impl WalletState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rehydrate from a persisted journal (the CLI's wallet file). Leaves
    /// are not persisted — they re-derive on the next [`Self::scan`] — but
    /// a note's `leaf_index` is stable once assigned (the Curve Tree only
    /// ever appends), so a persisted position stays valid and offline
    /// [`Self::balance`] is correct between scans.
    pub fn from_parts(notes: Vec<TrackedNote>, next_index: u64, scanned_height: u64) -> Self {
        WalletState {
            notes,
            next_index,
            leaves: Vec::new(),
            scanned_height,
        }
    }

    /// Journal a new self-owned note of `value` base units at the next
    /// free derivation index; returns the [`SelfNote`] created. Used to
    /// record consolidation outputs and to import known self-notes
    /// (coinbase) for tracking.
    pub fn add_note(&mut self, value: u64) -> SelfNote {
        let note = SelfNote::new(self.next_index, value);
        self.next_index += 1;
        self.notes.push(TrackedNote {
            note,
            leaf_index: None,
            spent: false,
        });
        note
    }

    /// Journal a pre-derived self-note (e.g. a transfer output whose
    /// index was fixed when the transfer was built). Advances the next
    /// index past it so future allocations do not collide.
    pub fn journal_note(&mut self, note: SelfNote) {
        self.next_index = self.next_index.max(note.index + 1);
        self.notes.push(TrackedNote {
            note,
            leaf_index: None,
            spent: false,
        });
    }

    /// The next unused derivation index.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// All journalled notes with their last-scan status.
    pub fn notes(&self) -> &[TrackedNote] {
        &self.notes
    }

    /// Height the last successful scan reconstructed to.
    pub fn scanned_height(&self) -> u64 {
        self.scanned_height
    }

    /// Sum of confirmed, unspent notes (the private, local balance).
    pub fn balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|t| t.is_spendable())
            .map(|t| t.note.value)
            .sum()
    }

    /// The anchor Curve Tree over the scanned leaves, or `None` if no
    /// leaves exist yet (nothing to spend against).
    pub fn anchor_tree(&self) -> Option<AegisTree> {
        if self.leaves.is_empty() {
            None
        } else {
            Some(build_tree(&self.leaves))
        }
    }

    /// The scanned leaf vector (read-only).
    pub fn leaves(&self) -> &[EvenPoint] {
        &self.leaves
    }

    /// Spendable notes with their resolved openings, largest value first
    /// (so a zero-value reserve note naturally sorts last as filler).
    pub fn spendable(&self) -> Vec<TrackedNote> {
        let mut v: Vec<TrackedNote> = self
            .notes
            .iter()
            .copied()
            .filter(TrackedNote::is_spendable)
            .collect();
        v.sort_by_key(|t| std::cmp::Reverse(t.note.value));
        v
    }

    /// Locally mark the note at derivation `index` spent (optimistic,
    /// after a submit is accepted) so it is not selected again before the
    /// next scan confirms it.
    pub fn mark_spent(&mut self, index: u64) {
        if let Some(t) = self.notes.iter_mut().find(|t| t.note.index == index) {
            t.spent = true;
        }
    }

    /// Rebuild the note-commitment tree from the node's blocks and update
    /// every tracked note's position + spent status.
    ///
    /// Scans to the node's *current* `/state` height and verifies the
    /// rebuilt root against the node's published `cm_tree_root`; a
    /// mismatch (a leaf-order divergence, or the node advancing mid-scan)
    /// is a hard error rather than silently-wrong witnesses.
    pub fn scan(&mut self, sk: &SpendingKey, client: &NodeClient) -> Result<ScanReport, ScanError> {
        let state = client.state()?;
        let target = state.height;

        let mut leaves: Vec<EvenPoint> = Vec::new();
        let mut nullifiers: BTreeSet<[u8; NF_BYTES]> = BTreeSet::new();
        for height in 1..=target {
            let Some(block) = client.block_at(height)? else {
                continue; // gap below tip — nothing to add
            };
            collect_block(&block, height, &mut leaves, &mut nullifiers)?;
        }

        // Integrity: the wallet's rebuild must match the node's published
        // aggregate exactly, or the witnesses it would produce are wrong.
        let root = node_cm_tree_root(&leaves);
        if leaves.len() as u64 != state.leaf_count || root != state.cm_tree_root {
            return Err(ScanError::RootMismatch {
                height: target,
                wallet_leaves: leaves.len(),
                node_leaves: state.leaf_count,
                root_match: root == state.cm_tree_root,
            });
        }

        // Resolve each note's leaf index by commitment, and its spent
        // status by nullifier membership.
        let index_of: HashMap<[u8; NOTE_CM_BYTES], usize> = leaves
            .iter()
            .enumerate()
            .map(|(i, leaf)| (note_cm_bytes(leaf), i))
            .collect();
        let mut notes_resolved = 0;
        let mut notes_spent = 0;
        for tracked in &mut self.notes {
            tracked.leaf_index = index_of
                .get(&note_cm_bytes(&tracked.note.commitment(sk)))
                .copied();
            if tracked.leaf_index.is_some() {
                notes_resolved += 1;
            }
            tracked.spent = nullifiers.contains(&tracked.note.nullifier(sk));
            if tracked.spent {
                notes_spent += 1;
            }
        }

        self.leaves = leaves;
        self.scanned_height = target;
        Ok(ScanReport {
            target_height: target,
            leaf_count: self.leaves.len(),
            notes_resolved,
            notes_spent,
            balance: self.balance(),
        })
    }
}

/// Append one block's leaves (transfer outputs, then coinbase note) and
/// nullifiers, mirroring `aegis-node::state::ShieldedState::apply_block`.
fn collect_block(
    block: &Block,
    height: u64,
    leaves: &mut Vec<EvenPoint>,
    nullifiers: &mut BTreeSet<[u8; NF_BYTES]>,
) -> Result<(), ScanError> {
    for tx in &block.body.transfers {
        for out in &tx.outputs {
            let point = note_cm_from_bytes(&out.note_cm)
                .ok_or(ScanError::InvalidNoteCommitment { height })?;
            leaves.push(point);
        }
        for nf in &tx.nullifiers {
            nullifiers.insert(*nf);
        }
    }
    if let Some(coinbase) = &block.coinbase {
        leaves.push(coinbase.cm);
    }
    Ok(())
}

#[cfg(test)]
impl WalletState {
    /// Test-only: install a scanned leaf vector and resolve the given
    /// `(note_index, leaf_index)` pairs — what [`Self::scan`] does, but
    /// without a node. Used by `send`'s tests too (crate-visible).
    pub(crate) fn install_leaves_for_test(
        &mut self,
        leaves: Vec<EvenPoint>,
        resolved: &[(u64, usize)],
    ) {
        self.leaves = leaves;
        for (note_index, leaf_index) in resolved {
            if let Some(t) = self.notes.iter_mut().find(|t| t.note.index == *note_index) {
                t.leaf_index = Some(*leaf_index);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn sk() -> SpendingKey {
        SpendingKey::from_bytes([0x33; 32])
    }

    // ----- happy path -----

    #[test]
    fn add_note_allocates_sequential_indices() {
        let mut st = WalletState::new();
        let a = st.add_note(1_000);
        let b = st.add_note(500);
        assert_eq!(a.index, 0);
        assert_eq!(b.index, 1);
        assert_eq!(st.next_index(), 2);
        assert_eq!(st.notes().len(), 2);
    }

    #[test]
    fn balance_counts_only_confirmed_unspent_notes() {
        let mut st = WalletState::new();
        st.add_note(1_000);
        st.add_note(500);
        st.add_note(250);
        // Nothing scanned yet: unresolved ⇒ zero balance.
        assert_eq!(st.balance(), 0);
        // Resolve two, spend one.
        st.notes[0].leaf_index = Some(0);
        st.notes[1].leaf_index = Some(1);
        st.notes[1].spent = true;
        // note 2 stays unresolved.
        assert_eq!(st.balance(), 1_000);
        assert_eq!(st.spendable().len(), 1);
    }

    #[test]
    fn node_cm_tree_root_matches_manual_construction() {
        // Empty ⇒ sentinel; non-empty ⇒ domain-tagged hash of the root.
        assert_eq!(node_cm_tree_root(&[]), EMPTY_TREE_ROOT_PLACEHOLDER);
        let leaves = vec![
            SelfNote::new(0, 1_000).commitment(&sk()),
            SelfNote::new(1, 500).commitment(&sk()),
        ];
        let root = tree_root(&leaves);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(CM_ROOT_DOMAIN);
        preimage.extend_from_slice(&note_cm_bytes(&root));
        assert_eq!(node_cm_tree_root(&leaves), blake2b256(&preimage));
    }

    #[test]
    fn spendable_sorts_largest_first() {
        let mut st = WalletState::new();
        st.add_note(100);
        st.add_note(900);
        st.add_note(0); // zero-reserve
        for (i, t) in st.notes.iter_mut().enumerate() {
            t.leaf_index = Some(i);
        }
        let sp = st.spendable();
        assert_eq!(sp[0].note.value, 900);
        assert_eq!(sp[2].note.value, 0); // filler last
    }

    #[test]
    fn mark_spent_removes_a_note_from_balance() {
        let mut st = WalletState::new();
        let n = st.add_note(1_000);
        st.notes[0].leaf_index = Some(0);
        assert_eq!(st.balance(), 1_000);
        st.mark_spent(n.index);
        assert_eq!(st.balance(), 0);
    }
}
