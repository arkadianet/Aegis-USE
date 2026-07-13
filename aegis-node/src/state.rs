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
use aegis_crypto::tree::tree_root;
use aegis_spec::{Amount, NetworkParams, NF_BYTES};
use ergo_crypto::autolykos::common::blake2b256;

use crate::genesis::{EMPTY_NULLIFIER_DIGEST, EMPTY_TREE_ROOT_PLACEHOLDER};
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

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("double spend: nullifier {} already seen", hex::encode(nf))]
    DoubleSpend { nf: [u8; NF_BYTES] },
    #[error("output note commitment in tx {tx_index} is not a canonical curve point")]
    InvalidNoteCommitment { tx_index: usize },
}

/// Everything needed to rewind one block, exactly.
#[derive(Debug)]
pub struct BlockUndo {
    added_nullifiers: Vec<[u8; NF_BYTES]>,
    prev_pot: Amount,
    prev_digest: [u8; 32],
    prev_leaf_count: usize,
    prev_cm_root: [u8; 32],
}

/// In-memory shielded consensus state (persistence: Phase 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldedState {
    nullifiers: BTreeSet<[u8; NF_BYTES]>,
    pot: Amount,
    digest: [u8; 32],
    /// Note-commitment leaves in insertion order; the Curve Tree is
    /// rebuilt from this vector per block (O(n) debt — DEFERRED.md).
    cm_leaves: Vec<EvenPoint>,
    cm_root: [u8; 32],
}

impl ShieldedState {
    pub fn new() -> Self {
        ShieldedState {
            nullifiers: BTreeSet::new(),
            pot: 0,
            digest: EMPTY_NULLIFIER_DIGEST,
            cm_leaves: Vec::new(),
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
        if self.cm_leaves.is_empty() {
            None
        } else {
            Some(aegis_crypto::tree::build_tree(&self.cm_leaves))
        }
    }

    pub fn contains(&self, nf: &[u8; NF_BYTES]) -> bool {
        self.nullifiers.contains(nf)
    }

    /// The spent-nullifier set (read-only). Used by the node API to
    /// publish a membership snapshot for `GET /nullifier/{hex}`.
    pub fn nullifiers(&self) -> &BTreeSet<[u8; NF_BYTES]> {
        &self.nullifiers
    }

    fn recompute_cm_root(&mut self) {
        self.cm_root = if self.cm_leaves.is_empty() {
            EMPTY_TREE_ROOT_PLACEHOLDER
        } else {
            let root = tree_root(&self.cm_leaves);
            let mut preimage = Vec::with_capacity(CM_ROOT_DOMAIN.len() + 33);
            preimage.extend_from_slice(CM_ROOT_DOMAIN);
            preimage.extend_from_slice(&note_cm_bytes(&root));
            blake2b256(&preimage)
        };
    }

    /// Validate and apply one block's transfers. On error the state is
    /// untouched (all checks run before any mutation).
    pub fn apply_block(
        &mut self,
        transfers: &[ShieldedTransfer],
        params: &NetworkParams,
        reward: RewardMode,
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
        let undo = BlockUndo {
            added_nullifiers: block_nfs.clone(),
            prev_pot: self.pot,
            prev_digest: self.digest,
            prev_leaf_count: self.cm_leaves.len(),
            prev_cm_root: self.cm_root,
        };
        // Digest chain (empty block: unchanged).
        if !block_nfs.is_empty() {
            let mut preimage = Vec::with_capacity(32 + NF_BYTES * block_nfs.len());
            preimage.extend_from_slice(&self.digest);
            for nf in &block_nfs {
                preimage.extend_from_slice(nf);
            }
            self.digest = blake2b256(&preimage);
        }
        self.nullifiers.extend(block_nfs.iter().copied());
        // Coinbase (S5b): under `Real`, the coinbase note is a real leaf
        // appended AFTER the transfer output leaves (a fixed consensus
        // order), and its value is drawn from the fee-credited pot.
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
        // Commitment tree: append this block's leaves (outputs + any
        // coinbase note), refresh root.
        if !new_leaves.is_empty() {
            self.cm_leaves.extend(new_leaves);
            self.recompute_cm_root();
        }
        // Credit fees, then draw the coinbase (never below zero).
        self.pot = pot_after_fees - coinbase;
        Ok(undo)
    }

    /// Exact inverse of the matching [`Self::apply_block`].
    pub fn rollback(&mut self, undo: BlockUndo) {
        for nf in &undo.added_nullifiers {
            self.nullifiers.remove(nf);
        }
        self.pot = undo.prev_pot;
        self.digest = undo.prev_digest;
        self.cm_leaves.truncate(undo.prev_leaf_count);
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
        st.recompute_cm_root();
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
        st.apply_block(&[], params(), RewardMode::DevStub).unwrap();
        assert_eq!((st.pot(), st.nullifier_digest()), before);
    }

    #[test]
    fn apply_block_credits_fees_and_inserts_nullifiers() {
        let mut st = ShieldedState::new();
        let txs = vec![transfer_with_nfs(1, 2), transfer_with_nfs(3, 4)];
        st.apply_block(&txs, params(), RewardMode::DevStub).unwrap();
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
        st.apply_block(&[transfer_with_nfs(1, 2)], params(), RewardMode::DevStub)
            .unwrap();
        assert_eq!(st.leaf_count(), 2);
        assert_ne!(st.cm_tree_root(), sentinel);
        // A second block moves the root again.
        let after_one = st.cm_tree_root();
        st.apply_block(&[transfer_with_nfs(3, 4)], params(), RewardMode::DevStub)
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
            params(),
            RewardMode::Real {
                coinbase_cm: coinbase_cm(1),
            },
        )
        .unwrap();
        assert_eq!(st.leaf_count(), 1);
        assert_eq!(st.pot(), 0);
        // Real block with one transfer: 2 output leaves + 1 coinbase leaf;
        // fees credited then drawn by the coinbase (dev economics ⇒ pot 0).
        st.apply_block(
            &[transfer_with_nfs(1, 2)],
            params(),
            RewardMode::Real {
                coinbase_cm: coinbase_cm(2),
            },
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
                params(),
                RewardMode::Real {
                    coinbase_cm: coinbase_cm(9),
                },
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
        a.apply_block(&[transfer_with_nfs(1, 2)], params(), RewardMode::DevStub)
            .unwrap();
        b.apply_block(&[transfer_with_nfs(2, 1)], params(), RewardMode::DevStub)
            .unwrap();
        assert_ne!(a.nullifier_digest(), b.nullifier_digest());
        let mut a2 = ShieldedState::new();
        a2.apply_block(&[transfer_with_nfs(1, 2)], params(), RewardMode::DevStub)
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
            undos.push(st.apply_block(&txs, params(), RewardMode::DevStub).unwrap());
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

    // ----- error paths -----

    #[test]
    fn double_spend_across_blocks_rejected_and_state_untouched() {
        let mut st = ShieldedState::new();
        st.apply_block(&[transfer_with_nfs(1, 2)], params(), RewardMode::DevStub)
            .unwrap();
        let before = st.clone();
        let err = st
            .apply_block(&[transfer_with_nfs(1, 9)], params(), RewardMode::DevStub)
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
            .apply_block(&[tx], params(), RewardMode::DevStub)
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
                params(),
                RewardMode::DevStub,
            )
            .unwrap_err();
        assert!(matches!(err, StateError::DoubleSpend { .. }));
        // and within one tx
        let err = st
            .apply_block(&[transfer_with_nfs(5, 5)], params(), RewardMode::DevStub)
            .unwrap_err();
        assert!(matches!(err, StateError::DoubleSpend { .. }));
    }
}
