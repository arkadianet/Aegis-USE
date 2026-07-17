//! The hash-native shielded-pool consensus state: the Poseidon-Merkle
//! commitment tree, the nullifier set, and the recent-roots acceptance window —
//! with `apply_block`/`rollback` as EXACT inverses (reorg-safe), mirroring the
//! Curve-Trees `ShieldedState` shape (`state.rs`): all validation runs before
//! any mutation ("verify-valid-or-reject"), and a `HnBlockUndo` captures enough
//! prior state that `apply → rollback → apply` is the identity.

use std::collections::{HashSet, VecDeque};

use aegis_engine::merkle::{MerklePath, NoteTree};
use aegis_engine::note_encryption::NOTE_CT_BYTES;
use aegis_engine::poseidon::{Digest, DIGEST_ELEMS, F};
use aegis_engine::spend::monolith::{PUB_NF0, PUB_NF1, PUB_ROOT};
use aegis_hn_wallet::chain::{digest_at, OutputRecord, ROOT_WINDOW};
use aegis_hn_wallet::{ChainView, SpendCircuit};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};

/// Digest ↔ 8 canonical `u32` limbs (the block/header wire form).
pub fn digest_to_limbs(d: &Digest) -> [u32; DIGEST_ELEMS] {
    core::array::from_fn(|i| d[i].as_canonical_u32())
}
pub fn limbs_to_digest(l: &[u32; DIGEST_ELEMS]) -> Digest {
    core::array::from_fn(|i| F::from_u32(l[i]))
}

/// A hash-native block payload: shielded txs + one coinbase mint, with the
/// commitment-tree root committed in the "header" fields (`prev_root` anchors
/// the block; `state_root` is the tip after applying — light state-transition
/// verification is `verify each proof + check the two roots`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HnBlock {
    pub height: u64,
    pub prev_root: [u32; DIGEST_ELEMS],
    pub state_root: [u32; DIGEST_ELEMS],
    pub txs: Vec<aegis_hn_wallet::Tx>,
    pub coinbase_cm: [u32; DIGEST_ELEMS],
    pub coinbase_ct: Vec<u8>,
}

/// Captured prior state for an exact rollback.
pub struct HnBlockUndo {
    prev_leaf_count: usize,
    added_nullifiers: Vec<[u32; DIGEST_ELEMS]>,
    prev_output_count: usize,
    prev_height: u64,
    /// A root evicted from the front of the window when this block's tip root
    /// was pushed (restored on rollback so the window is exact).
    evicted_root: Option<Digest>,
}

/// Why a block (or a single tx, at admission) was rejected.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum HnError {
    #[error("spend proof does not verify")]
    ProofInvalid,
    #[error("anchor root is not in the acceptance window")]
    UnknownRoot,
    #[error("double spend: a nullifier is already spent")]
    DoubleSpend,
    #[error("an output ciphertext is not the fixed size")]
    BadCiphertext,
    #[error("public values have the wrong shape")]
    BadPublicShape,
    #[error("block prev_root does not match the current tip")]
    PrevRootMismatch,
    #[error("block state_root does not match the applied tip")]
    StateRootMismatch,
}

/// The pool state.
pub struct HnState {
    cm_leaves: Vec<Digest>,
    tree: NoteTree,
    nullifiers: HashSet<[u32; DIGEST_ELEMS]>,
    recent_roots: VecDeque<Digest>,
    outputs: Vec<OutputRecord>,
    height: u64,
}

impl Default for HnState {
    fn default() -> Self {
        Self::new()
    }
}

impl HnState {
    pub fn new() -> Self {
        let tree = NoteTree::new();
        let mut recent_roots = VecDeque::new();
        recent_roots.push_back(tree.root());
        Self {
            cm_leaves: Vec::new(),
            tree,
            nullifiers: HashSet::new(),
            recent_roots,
            outputs: Vec::new(),
            height: 0,
        }
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    fn nf_key(nf: &Digest) -> [u32; DIGEST_ELEMS] {
        core::array::from_fn(|i| nf[i].as_canonical_u32())
    }

    fn append_leaf(&mut self, cm: Digest, ciphertext: Vec<u8>) {
        self.cm_leaves.push(cm);
        let leaf_index = self.tree.append(cm);
        self.outputs.push(OutputRecord {
            leaf_index,
            cm,
            ciphertext,
        });
    }

    /// Validate a single tx against the current state + a working nullifier set
    /// (used both at mempool admission and inside block application). Returns
    /// the tx's two nullifiers on success.
    pub fn validate_tx(
        &self,
        tx: &aegis_hn_wallet::Tx,
        circuit: &SpendCircuit,
        pending: &HashSet<[u32; DIGEST_ELEMS]>,
    ) -> Result<[Digest; 2], HnError> {
        if tx.public_values.len() < PUB_NF1 + DIGEST_ELEMS {
            return Err(HnError::BadPublicShape);
        }
        for ct in &tx.out_ciphertexts {
            if ct.len() != NOTE_CT_BYTES {
                return Err(HnError::BadCiphertext);
            }
        }
        if !circuit.verify(&tx.proof_bytes, &tx.public_values) {
            return Err(HnError::ProofInvalid);
        }
        let root = digest_at(&tx.public_values, PUB_ROOT);
        if !self.recent_roots.contains(&root) {
            return Err(HnError::UnknownRoot);
        }
        let nf0 = digest_at(&tx.public_values, PUB_NF0);
        let nf1 = digest_at(&tx.public_values, PUB_NF1);
        for nf in [&nf0, &nf1] {
            let k = Self::nf_key(nf);
            if self.nullifiers.contains(&k) || pending.contains(&k) {
                return Err(HnError::DoubleSpend);
            }
        }
        Ok([nf0, nf1])
    }

    /// Apply one block (validate-then-mutate; the mutation is a no-op on any
    /// error). Consensus leaf order: each tx's two output commitments in tx
    /// order, then the coinbase note (a fixed order production also honours).
    pub fn apply_block(
        &mut self,
        block: &HnBlock,
        circuit: &SpendCircuit,
    ) -> Result<HnBlockUndo, HnError> {
        if limbs_to_digest(&block.prev_root) != self.tree.root() {
            return Err(HnError::PrevRootMismatch);
        }
        // ---- validate everything before mutating ----
        let mut seen: HashSet<[u32; DIGEST_ELEMS]> = HashSet::new();
        let mut all_nfs: Vec<[u32; DIGEST_ELEMS]> = Vec::with_capacity(2 * block.txs.len());
        for tx in &block.txs {
            let nfs = self.validate_tx(tx, circuit, &seen)?;
            for nf in &nfs {
                let k = Self::nf_key(nf);
                seen.insert(k);
                all_nfs.push(k);
            }
        }
        if block.coinbase_ct.len() != NOTE_CT_BYTES {
            return Err(HnError::BadCiphertext);
        }

        let undo = HnBlockUndo {
            prev_leaf_count: self.cm_leaves.len(),
            added_nullifiers: all_nfs.clone(),
            prev_output_count: self.outputs.len(),
            prev_height: self.height,
            evicted_root: None,
        };

        // ---- mutate ----
        for tx in &block.txs {
            let cm0 = digest_at(&tx.public_values, aegis_engine::spend::monolith::PUB_CMO0);
            let cm1 = digest_at(&tx.public_values, aegis_engine::spend::monolith::PUB_CMO1);
            self.append_leaf(cm0, tx.out_ciphertexts[0].clone());
            self.append_leaf(cm1, tx.out_ciphertexts[1].clone());
        }
        self.append_leaf(
            limbs_to_digest(&block.coinbase_cm),
            block.coinbase_ct.clone(),
        );
        for k in &all_nfs {
            self.nullifiers.insert(*k);
        }

        let tip = self.tree.root();
        if digest_to_limbs(&tip) != block.state_root {
            // roll back the leaf appends we just did (validation of the header
            // commitment is part of accept; restore and reject).
            self.cm_leaves.truncate(undo.prev_leaf_count);
            self.tree = rebuild(&self.cm_leaves);
            self.outputs.truncate(undo.prev_output_count);
            for k in &all_nfs {
                self.nullifiers.remove(k);
            }
            return Err(HnError::StateRootMismatch);
        }

        let mut undo = undo;
        if self.recent_roots.len() == ROOT_WINDOW {
            undo.evicted_root = self.recent_roots.pop_front();
        }
        self.recent_roots.push_back(tip);
        self.height += 1;
        Ok(undo)
    }

    /// Exact inverse of [`Self::apply_block`].
    pub fn rollback(&mut self, undo: HnBlockUndo) {
        self.recent_roots.pop_back();
        if let Some(front) = undo.evicted_root {
            self.recent_roots.push_front(front);
        }
        for k in &undo.added_nullifiers {
            self.nullifiers.remove(k);
        }
        self.outputs.truncate(undo.prev_output_count);
        self.cm_leaves.truncate(undo.prev_leaf_count);
        self.tree = rebuild(&self.cm_leaves);
        self.height = undo.prev_height;
    }

    /// Compute a block's `state_root` given the current tip and the block's
    /// txs + coinbase (used by production to fill the header).
    pub fn simulate_state_root(&self, block_cms: &[Digest]) -> [u32; DIGEST_ELEMS] {
        let mut t = self.tree.clone();
        for cm in block_cms {
            t.append(*cm);
        }
        digest_to_limbs(&t.root())
    }

    pub fn tip_root_limbs(&self) -> [u32; DIGEST_ELEMS] {
        digest_to_limbs(&self.tree.root())
    }
}

fn rebuild(leaves: &[Digest]) -> NoteTree {
    let mut t = NoteTree::new();
    for cm in leaves {
        t.append(*cm);
    }
    t
}

impl ChainView for HnState {
    fn current_root(&self) -> Digest {
        self.tree.root()
    }
    fn authentication_path(&self, leaf_index: u64) -> Option<MerklePath> {
        (leaf_index < self.tree.len()).then(|| self.tree.authentication_path(leaf_index))
    }
    fn nullifier_seen(&self, nf: &Digest) -> bool {
        self.nullifiers.contains(&Self::nf_key(nf))
    }
    fn outputs_since(&self, cursor: u64) -> Vec<OutputRecord> {
        self.outputs
            .iter()
            .filter(|o| o.leaf_index >= cursor)
            .cloned()
            .collect()
    }
    fn output_count(&self) -> u64 {
        self.tree.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hn::mint::coinbase_note;
    use aegis_engine::address::WalletKeys;

    /// apply → rollback → apply is the identity (reorg-safety).
    #[test]
    fn apply_rollback_is_exact_inverse() {
        let circuit = SpendCircuit::deterministic(1);
        let miner = WalletKeys::from_seed(b"miner").address();

        let mut st = HnState::new();
        let empty_root = st.tip_root_limbs();

        // A coinbase-only block (no tx proofs needed for this state test).
        let mint = coinbase_note(&miner, 100, &[1u8; 32]);
        let state_root = st.simulate_state_root(&[mint.cm]);
        let block = HnBlock {
            height: 0,
            prev_root: empty_root,
            state_root,
            txs: vec![],
            coinbase_cm: digest_to_limbs(&mint.cm),
            coinbase_ct: mint.ciphertext,
        };

        let undo = st.apply_block(&block, &circuit).unwrap();
        assert_eq!(st.height(), 1);
        assert_ne!(st.tip_root_limbs(), empty_root);

        st.rollback(undo);
        assert_eq!(st.height(), 0, "rollback restores height");
        assert_eq!(
            st.tip_root_limbs(),
            empty_root,
            "rollback restores the tree root exactly"
        );
        assert_eq!(st.output_count(), 0, "rollback truncates the leaves");

        // Re-apply the same block: identity.
        st.apply_block(&block, &circuit).unwrap();
        assert_eq!(st.height(), 1);
        assert_eq!(
            st.tip_root_limbs(),
            digest_to_limbs(&limbs_to_digest(&state_root))
        );
    }

    #[test]
    fn block_with_wrong_prev_root_is_rejected() {
        let circuit = SpendCircuit::deterministic(1);
        let miner = WalletKeys::from_seed(b"m").address();
        let mut st = HnState::new();
        let mint = coinbase_note(&miner, 1, &[9u8; 32]);
        let bad = HnBlock {
            height: 0,
            prev_root: [123u32; DIGEST_ELEMS], // not the current tip
            state_root: [0u32; DIGEST_ELEMS],
            txs: vec![],
            coinbase_cm: digest_to_limbs(&mint.cm),
            coinbase_ct: mint.ciphertext,
        };
        assert!(matches!(
            st.apply_block(&bad, &circuit),
            Err(HnError::PrevRootMismatch)
        ));
    }
}
