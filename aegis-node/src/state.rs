//! Versioned shielded state: nullifier set + emission pot (+ commitment
//! tree from Phase 2). Apply/rollback must be EXACT inverses to the
//! full retention depth (consensus.md §5, attack B2).
//!
//! Pinned consensus semantics (consensus.md §5a, added with this
//! module): the nullifier digest is a hash chain
//! `digest' = blake2b256(digest ‖ nf…)` over the block's nullifiers in
//! tx-then-slot order (empty block: unchanged), and the pot updates as
//! fees-credit-then-coinbase-draw so the pot can never go negative.

use std::collections::BTreeSet;

use aegis_crypto::generators::EvenPoint;
use aegis_crypto::note::{note_cm_bytes, note_cm_from_bytes};
use aegis_crypto::payment::pegmint_note;
use aegis_crypto::tree::IncrementalCmTree;
use aegis_spec::{Amount, NetworkParams, NF_BYTES};
use ergo_crypto::autolykos::common::blake2b256;

use crate::genesis::{EMPTY_NULLIFIER_DIGEST, EMPTY_TREE_ROOT_PLACEHOLDER};
use crate::pegmint::{ComparativeAnchor, PegMintError};
use crate::pegmint_steps::{verify_pegmint, PegMintProof, PegMintUsedSet, PegParams};
use crate::tx::ShieldedTransfer;

/// Domain tag for the header's commitment-tree root (consensus.md §5a).
const CM_ROOT_DOMAIN: &[u8] = b"aegis:cm-root:v1";

/// Undo retention depth (consensus.md §5: ≥ 240 = 2×M).
pub const STATE_RETENTION_BLOCKS: usize = 240;

/// Coinbase mode (S5b). `DevStub`: no coinbase note, draw 0, pot only
/// accumulates fees. `Real`: mint a shielded coinbase note (value bound
/// to the public reward by a `MintProof` the chain verifies) and draw
/// that reward from the pot. Minting is sound in isolation; **spending**
/// a coinbase note stays blocked until the nullifier soundness fix (N1,
/// see `spend.rs` P0 note) — so `Real` here enables MINT only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewardMode {
    DevStub,
    Real { coinbase_cm: EvenPoint },
}

/// The coinbase draw for a block with `n_txs` fee-paying transfers,
/// given the pre-block `pot`: credit the fees first, then apply
/// `coinbase_reward`. Single source of truth shared by `apply_block`
/// (state mutation) and the chain (mint-proof verification) so the two
/// never disagree on the amount the coinbase note must commit to.
pub fn expected_coinbase_value(pot: Amount, n_txs: u64, params: &NetworkParams) -> Amount {
    let pot_after_fees = pot.saturating_add(params.sc_tx_fee.saturating_mul(n_txs));
    params.coinbase_reward(pot_after_fees, n_txs)
}

/// The consensus context one block's peg-mints are validated against:
/// the node's independently-followed Ergo settled view (the P1-A
/// `ComparativeAnchor`) and the peg deploy pins ([`PegParams`]). Held by
/// reference — cheap to pass per block, resolved by the node once per
/// tip (the "followed-anchor seam"; the node loop owns resolve-or-defer).
#[derive(Debug, Clone, Copy)]
pub struct PegValidation<'a> {
    pub anchor: &'a ComparativeAnchor,
    pub params: &'a PegParams,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("double spend: nullifier {} already seen", hex::encode(nf))]
    DoubleSpend { nf: [u8; NF_BYTES] },
    #[error("output note commitment in tx {tx_index} is not a canonical curve point")]
    InvalidNoteCommitment { tx_index: usize },
    #[error("block carries peg-mints but no peg-in validation context is configured")]
    PegDisabled,
    #[error("peg-mint {index}: {source}")]
    PegMint { index: usize, source: PegMintError },
    #[error("peg-mint {index}: receipt sc_dest is not a spendable address")]
    PegBadDest { index: usize },
}

/// Everything needed to rewind one block, exactly.
#[derive(Debug)]
pub struct BlockUndo {
    added_nullifiers: Vec<[u8; NF_BYTES]>,
    /// Peg-in receipt boxIds this block inserted into the used-set (I2).
    /// Removed on rollback so apply→rollback→apply is the identity.
    added_box_ids: Vec<[u8; 32]>,
    prev_pot: Amount,
    prev_digest: [u8; 32],
    prev_leaf_count: usize,
    prev_cm_root: [u8; 32],
}

/// In-memory shielded consensus state (persistence: Phase 5).
///
/// Equality is over the logical consensus state (nullifiers, pot,
/// digest, leaves, root). `cm_tree` is a deterministic function of
/// `cm_leaves` (a maintained cache, not independent state), so it is
/// excluded from `PartialEq` — two states with equal `cm_leaves`
/// necessarily have identical trees.
#[derive(Debug, Clone)]
pub struct ShieldedState {
    nullifiers: BTreeSet<[u8; NF_BYTES]>,
    /// Peg-in receipt boxIds already minted against (I2 no-double-mint,
    /// g25 §3). Consensus state: folded into `digest`, rolled back exactly
    /// via [`BlockUndo`], mirroring the nullifier set.
    peg_used: BTreeSet<[u8; 32]>,
    pot: Amount,
    digest: [u8; 32],
    /// Note-commitment leaves in insertion order (source of truth for
    /// equality and for rebuilding `cm_tree` on rollback).
    cm_leaves: Vec<EvenPoint>,
    /// The commitment tree, maintained incrementally across `apply_block`
    /// (append-only) — avoids the O(n) per-block rebuild. Kept in lockstep
    /// with `cm_leaves`; `cm_root` is derived from its root.
    cm_tree: IncrementalCmTree,
    cm_root: [u8; 32],
}

impl PartialEq for ShieldedState {
    fn eq(&self, other: &Self) -> bool {
        self.nullifiers == other.nullifiers
            && self.peg_used == other.peg_used
            && self.pot == other.pot
            && self.digest == other.digest
            && self.cm_leaves == other.cm_leaves
            && self.cm_root == other.cm_root
    }
}

impl Eq for ShieldedState {}

impl ShieldedState {
    pub fn new() -> Self {
        ShieldedState {
            nullifiers: BTreeSet::new(),
            peg_used: BTreeSet::new(),
            pot: 0,
            digest: EMPTY_NULLIFIER_DIGEST,
            cm_leaves: Vec::new(),
            cm_tree: IncrementalCmTree::new(),
            cm_root: EMPTY_TREE_ROOT_PLACEHOLDER,
        }
    }

    pub fn pot(&self) -> Amount {
        self.pot
    }

    pub fn nullifier_digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Header commitment to the Curve Tree (consensus.md §5a): the
    /// pinned sentinel while no leaves exist, else
    /// `blake2b256("aegis:cm-root:v1" ‖ compressed root point)`.
    pub fn cm_tree_root(&self) -> [u8; 32] {
        self.cm_root
    }

    /// Number of note-commitment leaves accumulated so far.
    pub fn leaf_count(&self) -> usize {
        self.cm_leaves.len()
    }

    /// The consensus **anchor** tree for proofs that spend against this
    /// state, or `None` when no notes exist yet (nothing to spend).
    pub fn anchor_tree(&self) -> Option<aegis_crypto::tree::AegisTree> {
        // Clone the incrementally-maintained tree (byte-identical to a
        // fresh `build_tree(&cm_leaves)`, oracle-tested) — no O(n) root
        // recompute.
        self.cm_tree.tree().cloned()
    }

    pub fn contains(&self, nf: &[u8; NF_BYTES]) -> bool {
        self.nullifiers.contains(nf)
    }

    /// The spent-nullifier set (read-only). Used by the node API to
    /// publish a membership snapshot for `GET /nullifier/{hex}`.
    pub fn nullifiers(&self) -> &BTreeSet<[u8; NF_BYTES]> {
        &self.nullifiers
    }

    /// The peg-in used receipt-boxId set (read-only, I2). A boxId here
    /// has already minted its shielded note and can never mint again.
    pub fn peg_used(&self) -> &BTreeSet<[u8; 32]> {
        &self.peg_used
    }

    /// Whether `box_id` has already minted a peg-in note (I2).
    pub fn is_peg_used(&self, box_id: &[u8; 32]) -> bool {
        self.peg_used.contains(box_id)
    }

    /// The note-commitment leaves (read-only). Used to publish a
    /// spend-anchor snapshot for mempool admission.
    pub fn cm_leaves(&self) -> &[EvenPoint] {
        &self.cm_leaves
    }

    /// Recompute `cm_root` from the maintained tree's current root
    /// (O(1) in the leaf count — the tree is kept up to date by
    /// [`Self::apply_block`]).
    fn refresh_cm_root(&mut self) {
        self.cm_root = match self.cm_tree.root() {
            None => EMPTY_TREE_ROOT_PLACEHOLDER,
            Some(root) => {
                let mut preimage = Vec::with_capacity(CM_ROOT_DOMAIN.len() + 33);
                preimage.extend_from_slice(CM_ROOT_DOMAIN);
                preimage.extend_from_slice(&note_cm_bytes(&root));
                blake2b256(&preimage)
            }
        };
    }

    /// Restore `cm_tree` from `cm_leaves` after a truncation (rollback).
    /// O(n), but rollback is the rare reorg path.
    fn rebuild_cm_tree(&mut self) {
        self.cm_tree = IncrementalCmTree::from_leaves(&self.cm_leaves);
    }

    /// Validate and apply one block's transfers and peg-in mints. On
    /// error the state is untouched (all checks run before any mutation —
    /// "verify-valid-or-reject").
    ///
    /// Peg-mints (g25 §3): each proof is verified with [`verify_pegmint`]
    /// against the supplied [`PegValidation`] anchor and the *current*
    /// used-set (the intra-block working set rejects two mints of the
    /// same receipt in one block). Each accepted mint appends a shielded
    /// note leaf whose value is exactly `N` (the verifier-proven public
    /// deposit amount — no inflation) payable to the receipt's `sc_dest`
    /// ([`pegmint_note`]), inserts the receipt boxId into the used-set
    /// (I2), and credits `pot_credit` to the emission pot. Any peg-mint
    /// failure rejects the whole block, state untouched. `peg` may be
    /// `None` only when `peg_mints` is empty.
    ///
    /// Consensus leaf order: transfer outputs, then peg-mint notes, then
    /// the coinbase note (a fixed order both apply and production honour).
    pub fn apply_block(
        &mut self,
        transfers: &[ShieldedTransfer],
        peg_mints: &[PegMintProof],
        params: &NetworkParams,
        reward: RewardMode,
        peg: Option<PegValidation<'_>>,
    ) -> Result<BlockUndo, StateError> {
        // Strict decode of every output note commitment (all checks
        // before any mutation).
        let mut new_leaves: Vec<EvenPoint> = Vec::with_capacity(2 * transfers.len());
        for (tx_index, tx) in transfers.iter().enumerate() {
            for out in &tx.outputs {
                let point = note_cm_from_bytes(&out.note_cm)
                    .ok_or(StateError::InvalidNoteCommitment { tx_index })?;
                new_leaves.push(point);
            }
        }
        // Freshness across the chain AND within the block (tx+slot order).
        let mut block_nfs: Vec<[u8; NF_BYTES]> = Vec::with_capacity(2 * transfers.len());
        let mut seen_in_block: BTreeSet<[u8; NF_BYTES]> = BTreeSet::new();
        for tx in transfers {
            for nf in &tx.nullifiers {
                if self.nullifiers.contains(nf) || !seen_in_block.insert(*nf) {
                    return Err(StateError::DoubleSpend { nf: *nf });
                }
                block_nfs.push(*nf);
            }
        }
        // Peg-mints: verify each against the followed anchor + used-set,
        // deriving the mint effect (leaf, boxId, pot credit). All checks
        // here — still before any mutation.
        let mut peg_leaves: Vec<EvenPoint> = Vec::with_capacity(peg_mints.len());
        let mut peg_box_ids: Vec<[u8; 32]> = Vec::with_capacity(peg_mints.len());
        let mut peg_credit: u128 = 0;
        if !peg_mints.is_empty() {
            let peg = peg.ok_or(StateError::PegDisabled)?;
            // Working used-set = committed set + this block's insertions
            // so far, so a within-block replay of one receipt rejects.
            let mut working = PegMintUsedSet::new();
            for id in &self.peg_used {
                working.insert(*id);
            }
            for (index, proof) in peg_mints.iter().enumerate() {
                let effect = verify_pegmint(proof, peg.anchor, &working, peg.params)
                    .map_err(|source| StateError::PegMint { index, source })?;
                let (leaf, _opening) =
                    pegmint_note(&effect.sc_dest, effect.note_value, &effect.box_id)
                        .ok_or(StateError::PegBadDest { index })?;
                working.insert(effect.box_id);
                peg_leaves.push(leaf);
                peg_box_ids.push(effect.box_id);
                peg_credit = peg_credit.saturating_add(u128::from(effect.pot_credit));
            }
        }
        let undo = BlockUndo {
            added_nullifiers: block_nfs.clone(),
            added_box_ids: peg_box_ids.clone(),
            prev_pot: self.pot,
            prev_digest: self.digest,
            prev_leaf_count: self.cm_leaves.len(),
            prev_cm_root: self.cm_root,
        };
        // Digest chain: fold this block's nullifiers then peg boxIds
        // (empty block, or a block with neither: unchanged — and a
        // transfer-only block folds exactly the pre-peg nullifier chain,
        // so prior pins hold).
        if !block_nfs.is_empty() || !peg_box_ids.is_empty() {
            let mut preimage =
                Vec::with_capacity(32 + NF_BYTES * block_nfs.len() + 32 * peg_box_ids.len());
            preimage.extend_from_slice(&self.digest);
            for nf in &block_nfs {
                preimage.extend_from_slice(nf);
            }
            for id in &peg_box_ids {
                preimage.extend_from_slice(id);
            }
            self.digest = blake2b256(&preimage);
        }
        self.nullifiers.extend(block_nfs.iter().copied());
        self.peg_used.extend(peg_box_ids.iter().copied());
        // Coinbase (S5b): under `Real`, the coinbase note is a real leaf
        // appended AFTER the transfer output and peg-mint leaves (a fixed
        // consensus order), and its value is drawn from the fee-credited
        // pot. (The peg-in fee credit is applied AFTER the coinbase draw,
        // so this block's coinbase cannot spend this block's peg credit.)
        new_leaves.extend(peg_leaves);
        let n_txs = transfers.len() as u64;
        let pot_after_fees = self
            .pot
            .saturating_add(params.sc_tx_fee.saturating_mul(n_txs));
        let coinbase = match reward {
            RewardMode::DevStub => 0,
            RewardMode::Real { coinbase_cm } => {
                new_leaves.push(coinbase_cm);
                expected_coinbase_value(self.pot, n_txs, params)
            }
        };
        // Commitment tree: append this block's leaves (outputs + peg-mint
        // notes + any coinbase note) incrementally, then refresh the root
        // from the maintained tree (no O(n) rebuild).
        if !new_leaves.is_empty() {
            for leaf in &new_leaves {
                self.cm_tree.push(*leaf);
            }
            self.cm_leaves.extend(new_leaves);
            self.refresh_cm_root();
        }
        // Credit fees, draw the coinbase (never below zero), then credit
        // the proven peg-in fees to the pot (I1 emission backing).
        self.pot = (pot_after_fees - coinbase)
            .saturating_add(u64::try_from(peg_credit).unwrap_or(u64::MAX));
        Ok(undo)
    }

    /// Exact inverse of the matching [`Self::apply_block`].
    pub fn rollback(&mut self, undo: BlockUndo) {
        for nf in &undo.added_nullifiers {
            self.nullifiers.remove(nf);
        }
        for id in &undo.added_box_ids {
            self.peg_used.remove(id);
        }
        self.pot = undo.prev_pot;
        self.digest = undo.prev_digest;
        self.cm_leaves.truncate(undo.prev_leaf_count);
        // The vendored tree has no truncate; rebuild from the restored
        // leaf prefix (rare reorg path). `prev_cm_root` is authoritative.
        self.rebuild_cm_tree();
        self.cm_root = undo.prev_cm_root;
    }
}

impl Default for ShieldedState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl ShieldedState {
    /// Test-only: a state pre-seeded with existing note leaves (stands
    /// in for notes minted by PegMint/coinbase, which land in G2.5/S5).
    pub(crate) fn seeded(leaves: Vec<EvenPoint>) -> Self {
        let mut st = ShieldedState::new();
        st.cm_leaves = leaves;
        st.rebuild_cm_tree();
        st.refresh_cm_root();
        st
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::testutil::sample_transfer;
    use aegis_spec::Network;

    // ----- helpers -----

    fn params() -> &'static aegis_spec::NetworkParams {
        Network::Dev.params()
    }

    fn transfer_with_nfs(a: u8, b: u8) -> ShieldedTransfer {
        let mut tx = sample_transfer(a);
        tx.nullifiers = [[a; NF_BYTES], [b; NF_BYTES]];
        tx
    }

    // ----- happy path -----

    #[test]
    fn empty_block_leaves_digest_and_grows_nothing() {
        let mut st = ShieldedState::new();
        let before = (st.pot(), st.nullifier_digest());
        st.apply_block(&[], &[], params(), RewardMode::DevStub, None)
            .unwrap();
        assert_eq!((st.pot(), st.nullifier_digest()), before);
    }

    #[test]
    fn apply_block_credits_fees_and_inserts_nullifiers() {
        let mut st = ShieldedState::new();
        let txs = vec![transfer_with_nfs(1, 2), transfer_with_nfs(3, 4)];
        st.apply_block(&txs, &[], params(), RewardMode::DevStub, None)
            .unwrap();
        assert_eq!(st.pot(), 2 * params().sc_tx_fee);
        for nf in [
            [1u8; NF_BYTES],
            [2u8; NF_BYTES],
            [3u8; NF_BYTES],
            [4u8; NF_BYTES],
        ] {
            assert!(st.contains(&nf));
        }
        assert_ne!(
            st.nullifier_digest(),
            ShieldedState::new().nullifier_digest()
        );
    }

    #[test]
    fn apply_block_with_outputs_updates_cm_root_and_leaf_count() {
        let mut st = ShieldedState::new();
        let sentinel = st.cm_tree_root();
        st.apply_block(
            &[transfer_with_nfs(1, 2)],
            &[],
            params(),
            RewardMode::DevStub,
            None,
        )
        .unwrap();
        assert_eq!(st.leaf_count(), 2);
        assert_ne!(st.cm_tree_root(), sentinel);
        // A second block moves the root again.
        let after_one = st.cm_tree_root();
        st.apply_block(
            &[transfer_with_nfs(3, 4)],
            &[],
            params(),
            RewardMode::DevStub,
            None,
        )
        .unwrap();
        assert_eq!(st.leaf_count(), 4);
        assert_ne!(st.cm_tree_root(), after_one);
    }

    fn coinbase_cm(seed: u64) -> EvenPoint {
        use aegis_crypto::note::EvenScalar;
        aegis_crypto::spend::consensus_note_commitment(
            0,
            EvenScalar::from(seed),
            EvenScalar::from(seed + 1),
        )
    }

    #[test]
    fn real_reward_mints_coinbase_leaf_and_draws_pot() {
        let mut st = ShieldedState::new();
        // Empty Real block: mints one coinbase leaf; pot stays 0 (nothing
        // to draw from an empty pot).
        st.apply_block(
            &[],
            &[],
            params(),
            RewardMode::Real {
                coinbase_cm: coinbase_cm(1),
            },
            None,
        )
        .unwrap();
        assert_eq!(st.leaf_count(), 1);
        assert_eq!(st.pot(), 0);
        // Real block with one transfer: 2 output leaves + 1 coinbase leaf;
        // fees credited then drawn by the coinbase (dev economics ⇒ pot 0).
        st.apply_block(
            &[transfer_with_nfs(1, 2)],
            &[],
            params(),
            RewardMode::Real {
                coinbase_cm: coinbase_cm(2),
            },
            None,
        )
        .unwrap();
        assert_eq!(st.leaf_count(), 1 + 3);
        assert_eq!(st.pot(), 0);
    }

    #[test]
    fn real_reward_rollback_restores_coinbase_leaf_and_pot() {
        let mut st = ShieldedState::new();
        let before = st.clone();
        let undo = st
            .apply_block(
                &[transfer_with_nfs(1, 2)],
                &[],
                params(),
                RewardMode::Real {
                    coinbase_cm: coinbase_cm(9),
                },
                None,
            )
            .unwrap();
        assert_eq!(st.leaf_count(), 3); // 2 outputs + coinbase
        st.rollback(undo);
        assert_eq!(st, before, "coinbase leaf + pot must roll back exactly");
    }

    #[test]
    fn digest_chain_is_order_sensitive_and_deterministic() {
        let mut a = ShieldedState::new();
        let mut b = ShieldedState::new();
        a.apply_block(
            &[transfer_with_nfs(1, 2)],
            &[],
            params(),
            RewardMode::DevStub,
            None,
        )
        .unwrap();
        b.apply_block(
            &[transfer_with_nfs(2, 1)],
            &[],
            params(),
            RewardMode::DevStub,
            None,
        )
        .unwrap();
        assert_ne!(a.nullifier_digest(), b.nullifier_digest());
        let mut a2 = ShieldedState::new();
        a2.apply_block(
            &[transfer_with_nfs(1, 2)],
            &[],
            params(),
            RewardMode::DevStub,
            None,
        )
        .unwrap();
        assert_eq!(a.nullifier_digest(), a2.nullifier_digest());
    }

    // ----- round-trips -----

    #[test]
    fn rollback_restores_state_exactly_over_many_blocks() {
        // Attack B2: tree/nullifier/pot rollback must be exact.
        let mut st = ShieldedState::new();
        let mut undos = Vec::new();
        let mut checkpoints = vec![st.clone()];
        for i in 0..10u8 {
            let txs = vec![transfer_with_nfs(2 * i + 10, 2 * i + 11)];
            undos.push(
                st.apply_block(&txs, &[], params(), RewardMode::DevStub, None)
                    .unwrap(),
            );
            checkpoints.push(st.clone());
        }
        for i in (0..10).rev() {
            st.rollback(undos.pop().unwrap());
            assert_eq!(st, checkpoints[i], "mismatch at height {i}");
        }
        assert!(
            !st.contains(&[10u8; NF_BYTES]),
            "rolled-back nf still present"
        );
    }

    #[test]
    fn multiblock_incremental_cm_root_matches_from_scratch_each_height() {
        // The incrementally-maintained `cm_root` (append-per-block) must
        // equal the from-scratch `tree_root(&all_cm_leaves)` hash at every
        // height, and rollback must retrace the exact root sequence.
        use aegis_crypto::note::{note_cm_bytes, note_cm_from_bytes};
        use aegis_crypto::tree::tree_root;

        let from_scratch_root = |leaves: &[EvenPoint]| -> [u8; 32] {
            if leaves.is_empty() {
                return EMPTY_TREE_ROOT_PLACEHOLDER;
            }
            let root = tree_root(leaves);
            let mut pre = Vec::new();
            pre.extend_from_slice(CM_ROOT_DOMAIN);
            pre.extend_from_slice(&note_cm_bytes(&root));
            blake2b256(&pre)
        };

        let mut st = ShieldedState::new();
        let mut all_leaves: Vec<EvenPoint> = Vec::new();
        let mut undos = Vec::new();
        let mut roots_at_height = vec![st.cm_tree_root()];
        let mut counter: u8 = 0;

        for i in 0..12u8 {
            // Vary the number of fee-paying transfers per block (0..=2).
            let mut txs: Vec<ShieldedTransfer> = Vec::new();
            for _ in 0..=(i % 3) {
                let a = 2 * counter;
                let b = 2 * counter + 1;
                counter += 1;
                txs.push(transfer_with_nfs(a, b));
            }
            let undo = st
                .apply_block(&txs, &[], params(), RewardMode::DevStub, None)
                .unwrap();
            undos.push(undo);

            // Mirror the consensus leaf order (each tx's outputs in order).
            for tx in &txs {
                for out in &tx.outputs {
                    all_leaves.push(note_cm_from_bytes(&out.note_cm).unwrap());
                }
            }
            assert_eq!(st.leaf_count(), all_leaves.len(), "height {}", i + 1);
            assert_eq!(
                st.cm_tree_root(),
                from_scratch_root(&all_leaves),
                "incremental cm_root diverged at height {}",
                i + 1
            );
            roots_at_height.push(st.cm_tree_root());
        }

        // Roll the whole chain back; the root must retrace exactly and the
        // incremental tree must be restored (anchor tree round-trips).
        for i in (0..12).rev() {
            st.rollback(undos.pop().unwrap());
            assert_eq!(
                st.cm_tree_root(),
                roots_at_height[i],
                "rollback root mismatch at height {i}"
            );
            assert_eq!(st.cm_tree_root(), from_scratch_root(st.cm_leaves()));
        }
        assert_eq!(st, ShieldedState::new());
    }

    // ----- error paths -----

    #[test]
    fn double_spend_across_blocks_rejected_and_state_untouched() {
        let mut st = ShieldedState::new();
        st.apply_block(
            &[transfer_with_nfs(1, 2)],
            &[],
            params(),
            RewardMode::DevStub,
            None,
        )
        .unwrap();
        let before = st.clone();
        let err = st
            .apply_block(
                &[transfer_with_nfs(1, 9)],
                &[],
                params(),
                RewardMode::DevStub,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StateError::DoubleSpend { .. }));
        assert_eq!(st, before);
    }

    #[test]
    fn invalid_note_commitment_rejected_and_state_untouched() {
        let mut st = ShieldedState::new();
        let before = st.clone();
        let mut tx = transfer_with_nfs(1, 2);
        tx.outputs[1].note_cm = [0xEE; aegis_spec::NOTE_CM_BYTES];
        let err = st
            .apply_block(&[tx], &[], params(), RewardMode::DevStub, None)
            .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidNoteCommitment { tx_index: 0 }
        ));
        assert_eq!(st, before);
    }

    #[test]
    fn double_spend_within_block_rejected() {
        let mut st = ShieldedState::new();
        // same nf twice inside one block (two txs)
        let err = st
            .apply_block(
                &[transfer_with_nfs(1, 2), transfer_with_nfs(1, 3)],
                &[],
                params(),
                RewardMode::DevStub,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StateError::DoubleSpend { .. }));
        // and within one tx
        let err = st
            .apply_block(
                &[transfer_with_nfs(5, 5)],
                &[],
                params(),
                RewardMode::DevStub,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StateError::DoubleSpend { .. }));
    }

    // ----- peg-in mints -----

    use crate::pegmint_steps::{testutil as peg, verify_pegmint, PegMintUsedSet};

    fn peg_val<'a>(anchor: &'a ComparativeAnchor, pp: &'a PegParams) -> PegValidation<'a> {
        PegValidation { anchor, params: pp }
    }

    /// The canonical effect a proof must apply (used to derive the
    /// expected leaf/boxId/credit independently of the apply path).
    fn effect_of(
        proof: &PegMintProof,
        anchor: &ComparativeAnchor,
        pp: &PegParams,
    ) -> crate::pegmint_steps::PegMintEffect {
        verify_pegmint(proof, anchor, &PegMintUsedSet::new(), pp).expect("valid proof")
    }

    // ----- happy path -----

    #[test]
    fn pegmint_block_mints_note_records_boxid_and_credits_pot() {
        let (proof, anchor, pp) = peg::spendable_case(50_000, 400, 0x11);
        let effect = effect_of(&proof, &anchor, &pp);
        // Value conservation: the minted leaf is exactly the address-bound
        // note for (sc_dest, N, boxId), and N is the proven public amount.
        let expected_leaf = pegmint_note(&effect.sc_dest, effect.note_value, &effect.box_id)
            .unwrap()
            .0;
        assert_eq!(effect.note_value, 50_000);

        let mut st = ShieldedState::new();
        st.apply_block(
            &[],
            &[proof],
            params(),
            RewardMode::DevStub,
            Some(peg_val(&anchor, &pp)),
        )
        .unwrap();

        assert_eq!(st.leaf_count(), 1, "one peg-mint note minted");
        assert_eq!(
            st.cm_leaves()[0],
            expected_leaf,
            "minted the sc_dest-bound note"
        );
        assert!(
            st.is_peg_used(&effect.box_id),
            "receipt boxId recorded (I2)"
        );
        // pot credited by exactly the proven peg fee — no inflation.
        assert_eq!(st.pot(), effect.pot_credit);
        assert_eq!(effect.pot_credit, 400);
    }

    #[test]
    fn pegmint_alongside_transfers_orders_leaves_outputs_then_pegmint() {
        // Consensus leaf order: transfer outputs first, then peg-mint note.
        let (proof, anchor, pp) = peg::spendable_case(12_000, 0, 0x22);
        let effect = effect_of(&proof, &anchor, &pp);
        let expected_leaf = pegmint_note(&effect.sc_dest, effect.note_value, &effect.box_id)
            .unwrap()
            .0;

        let mut st = ShieldedState::new();
        st.apply_block(
            &[transfer_with_nfs(1, 2)],
            &[proof],
            params(),
            RewardMode::DevStub,
            Some(peg_val(&anchor, &pp)),
        )
        .unwrap();
        // 2 transfer outputs, then the peg-mint note (index 2).
        assert_eq!(st.leaf_count(), 3);
        assert_eq!(st.cm_leaves()[2], expected_leaf);
        // Fee-less lock still mints (F2): pot is only the transfer fee.
        assert_eq!(st.pot(), params().sc_tx_fee);
    }

    // ----- round-trips -----

    #[test]
    fn pegmint_apply_rollback_is_exact_identity() {
        let (proof, anchor, pp) = peg::spendable_case(50_000, 400, 0x33);
        let mut st = ShieldedState::new();
        let before = st.clone();
        let undo = st
            .apply_block(
                &[],
                &[proof],
                params(),
                RewardMode::DevStub,
                Some(peg_val(&anchor, &pp)),
            )
            .unwrap();
        assert_eq!(st.leaf_count(), 1);
        st.rollback(undo);
        assert_eq!(
            st, before,
            "peg-mint leaf, used-set, pot and digest roll back exactly"
        );
    }

    // ----- error paths -----

    #[test]
    fn pegmint_without_context_is_rejected_state_clean() {
        let (proof, _anchor, _pp) = peg::spendable_case(50_000, 400, 0x44);
        let mut st = ShieldedState::new();
        let before = st.clone();
        let err = st
            .apply_block(&[], &[proof], params(), RewardMode::DevStub, None)
            .unwrap_err();
        assert!(matches!(err, StateError::PegDisabled));
        assert_eq!(st, before);
    }

    #[test]
    fn tampered_pegmint_rejected_state_clean() {
        // A proof broken at inclusion (trailing bytes on the lock tx) must
        // reject the whole block, leaving state untouched.
        let (mut proof, anchor, pp) = peg::spendable_case(50_000, 400, 0x55);
        proof.lock.tx_bytes.push(0x00);
        let mut st = ShieldedState::new();
        let before = st.clone();
        let err = st
            .apply_block(
                &[],
                &[proof],
                params(),
                RewardMode::DevStub,
                Some(peg_val(&anchor, &pp)),
            )
            .unwrap_err();
        assert!(matches!(err, StateError::PegMint { index: 0, .. }));
        assert_eq!(st, before, "a rejected peg-mint block dirties nothing");
    }

    #[test]
    fn pegmint_bad_sc_dest_rejected_state_clean() {
        // A 33-byte R4 that is NOT a canonical curve point: it verifies
        // (step 7.3 only checks length) yet cannot mint a spendable note.
        let (proof, anchor, pp) = peg::case_with_dest(vec![0xEE; 33], 50_000, 400, 0x99);
        let mut st = ShieldedState::new();
        let before = st.clone();
        let err = st
            .apply_block(
                &[],
                &[proof],
                params(),
                RewardMode::DevStub,
                Some(peg_val(&anchor, &pp)),
            )
            .unwrap_err();
        assert!(matches!(err, StateError::PegBadDest { index: 0 }));
        assert_eq!(st, before);
    }

    #[test]
    fn within_block_replay_of_one_receipt_rejected() {
        // Two mints of the SAME receipt in one block: the second sees the
        // first's boxId in the working used-set → AlreadyMinted (I2).
        let (proof, anchor, pp) = peg::spendable_case(50_000, 400, 0x66);
        let dup = proof.clone();
        let mut st = ShieldedState::new();
        let before = st.clone();
        let err = st
            .apply_block(
                &[],
                &[proof, dup],
                params(),
                RewardMode::DevStub,
                Some(peg_val(&anchor, &pp)),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            StateError::PegMint {
                index: 1,
                source: PegMintError::AlreadyMinted
            }
        ));
        assert_eq!(st, before);
    }

    #[test]
    fn cross_block_replay_of_one_receipt_rejected() {
        // Mint a receipt in block 1; replaying it in block 2 rejects
        // against the committed used-set, block 2 leaving state unchanged.
        let (proof, anchor, pp) = peg::spendable_case(50_000, 400, 0x77);
        let replay = proof.clone();
        let mut st = ShieldedState::new();
        st.apply_block(
            &[],
            &[proof],
            params(),
            RewardMode::DevStub,
            Some(peg_val(&anchor, &pp)),
        )
        .unwrap();
        let after_first = st.clone();
        let err = st
            .apply_block(
                &[],
                &[replay],
                params(),
                RewardMode::DevStub,
                Some(peg_val(&anchor, &pp)),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            StateError::PegMint {
                index: 0,
                source: PegMintError::AlreadyMinted
            }
        ));
        assert_eq!(st, after_first, "the replayed block dirties nothing");
    }

    #[test]
    fn two_distinct_receipts_both_mint() {
        let (p1, a1, pp) = peg::spendable_case(50_000, 400, 0x81);
        let (p2, a2, _) = peg::spendable_case(60_000, 400, 0x82);
        let e1 = effect_of(&p1, &a1, &pp);
        let e2 = effect_of(&p2, &a2, &pp);
        assert_ne!(e1.box_id, e2.box_id, "distinct receipts");
        // Same anchor covers both (both cases settle at h_ref 101 with the
        // same synthetic headers); mint them in one block.
        let mut st = ShieldedState::new();
        st.apply_block(
            &[],
            &[p1],
            params(),
            RewardMode::DevStub,
            Some(peg_val(&a1, &pp)),
        )
        .unwrap();
        st.apply_block(
            &[],
            &[p2],
            params(),
            RewardMode::DevStub,
            Some(peg_val(&a2, &pp)),
        )
        .unwrap();
        assert_eq!(st.leaf_count(), 2);
        assert!(st.is_peg_used(&e1.box_id) && st.is_peg_used(&e2.box_id));
        assert_eq!(st.pot(), e1.pot_credit + e2.pot_credit);
    }
}
