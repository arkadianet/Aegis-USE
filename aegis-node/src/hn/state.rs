//! The hash-native shielded-pool consensus state: the Poseidon-Merkle
//! commitment tree, the nullifier set, the recent-roots acceptance window, and
//! the **emission pot** (aegis-spec §11-12) — with `apply_block`/`rollback` as
//! EXACT inverses (reorg-safe), mirroring the Curve-Trees `ShieldedState` shape
//! (`state.rs`): all validation runs before any mutation
//! ("verify-valid-or-reject"), and a `HnBlockUndo` captures enough prior state
//! that `apply → rollback → apply` is the identity.
//!
//! # The pot (public security budget)
//! The pot is a PUBLIC integer balance, header-committed in every block
//! (`HnBlock::pot_after`). Fees flow INTO it (100% — never to the miner
//! directly), the coinbase draws OUT of it:
//! `coinbase = min(pot_parent, base + per_tx × txs)` on the PARENT pot, and
//! `pot_after = pot_parent + fees − coinbase`. Validators recompute both and
//! reject any deviation. The conservation invariant (I1-extended) —
//! `shielded_total + pot` unchanged by every non-genesis block — is enforced in
//! the state transition itself.

use std::collections::{HashSet, VecDeque};

use aegis_engine::commit::{limbs_to_u64, N_LIMBS};
use aegis_engine::merkle::{MerklePath, NoteTree};
use aegis_engine::note_encryption::NOTE_CT_BYTES;
use aegis_engine::poseidon::{hash_id_domain, Digest, DIGEST_ELEMS, F};
use aegis_engine::spend::monolith::{N_PUB, PUB_FEE, PUB_NF0, PUB_NF1, PUB_ROOT};
use aegis_hn_wallet::chain::{digest_at, OutputRecord};
use aegis_hn_wallet::{ChainView, SpendCircuit};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};

use super::mint::coinbase_cm_expected;
use super::params::HnChainParams;

const DOMAIN_BLOCK_ID: u32 = 0x0B10;

/// Deterministic block id (`height ‖ prev tip root`) — the coinbase-uniqueness
/// id every validator recomputes to check the coinbase commitment.
pub fn block_id(height: u64, prev_root: &Digest) -> [u8; 32] {
    hash_id_domain(DOMAIN_BLOCK_ID, height, prev_root)
}

/// The merge-mining anchor: the STARK-devnet Ergo header this hn block is mined
/// against. Merge-mining binds hn liveness to the devnet's Autolykos PoW chain —
/// each hn block references a real, advancing devnet header.
///
/// ⚠ CONSENSUS SURFACE (documented, partially implemented). This pass carries
/// the anchor and enforces MONOTONICITY (the devnet height a block anchors to
/// never goes backwards) + non-empty id, and the deployment's miner only
/// anchors to a header it fetched from the live devnet. The FULL aux-PoW binding
/// — the devnet block's extension Merkle-commits to the hn `state_root`, so one
/// solved Autolykos PoW is bound to exactly one hn block (reusing
/// `crate::auxpow::extension_root` + a `BatchMerkleProof`, verified with
/// `ergo_crypto::autolykos::v2::check_pow_v2`) — is the remaining step. Until it
/// lands, the anchor is a devnet-paced liveness scaffold, not yet PoW-binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxAnchor {
    pub devnet_header_id: [u8; 32],
    pub devnet_height: u64,
}

impl AuxAnchor {
    /// The genesis anchor (before any devnet binding).
    pub fn genesis() -> Self {
        Self {
            devnet_header_id: [0u8; 32],
            devnet_height: 0,
        }
    }
}

/// Digest ↔ 8 canonical `u32` limbs (the block/header wire form).
pub fn digest_to_limbs(d: &Digest) -> [u32; DIGEST_ELEMS] {
    core::array::from_fn(|i| d[i].as_canonical_u32())
}
pub fn limbs_to_digest(l: &[u32; DIGEST_ELEMS]) -> Digest {
    core::array::from_fn(|i| F::from_u32(l[i]))
}

/// A hash-native block payload: shielded txs + one coinbase mint, with the
/// commitment-tree root AND the pot balance committed in the "header" fields.
/// The coinbase is publicly auditable: `miner_owner` + `coinbase_amount` are in
/// the clear, and every validator recomputes the deterministic coinbase
/// commitment from them — the shielded note cannot claim a different value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HnBlock {
    pub height: u64,
    pub prev_root: [u32; DIGEST_ELEMS],
    pub state_root: [u32; DIGEST_ELEMS],
    pub txs: Vec<aegis_hn_wallet::Tx>,
    /// The coinbase destination's spend component (`owner = H(nk)`), public so
    /// validators can recompute the coinbase commitment. The miner reveals
    /// where their reward went — payments stay private; block production does
    /// not.
    pub miner_owner: [u32; DIGEST_ELEMS],
    /// The PUBLIC coinbase amount — consensus-checked against
    /// `min(pot_parent, base + per_tx × txs)` (reward) or the pinned genesis
    /// allocation (non-reward).
    pub coinbase_amount: u64,
    pub coinbase_cm: [u32; DIGEST_ELEMS],
    pub coinbase_ct: Vec<u8>,
    /// `true` for a mined block (pot-funded coinbase, subject to maturity);
    /// `false` for a genesis allocation (pinned in params, immediately
    /// spendable).
    pub coinbase_is_reward: bool,
    /// The pot balance AFTER this block (header-committed; validators recompute
    /// `pot_parent + fees − coinbase` and reject a mismatch).
    pub pot_after: u64,
    /// The merge-mining devnet anchor (monotone across blocks).
    pub anchor: AuxAnchor,
}

/// Captured prior state for an exact rollback.
pub struct HnBlockUndo {
    prev_leaf_count: usize,
    added_nullifiers: Vec<[u32; DIGEST_ELEMS]>,
    prev_output_count: usize,
    prev_height: u64,
    prev_anchor_height: u64,
    prev_pot: u64,
    prev_shielded_total: u64,
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
    #[error("fee does not equal the flat fee (fee variation is a fingerprint)")]
    BadFee,
    #[error("block prev_root does not match the current tip")]
    PrevRootMismatch,
    #[error("merge-mining anchor regressed (devnet height went backwards)")]
    AnchorRegressed,
    #[error("block state_root does not match the applied tip")]
    StateRootMismatch,
    #[error("coinbase amount does not equal min(pot_parent, base + per_tx × txs)")]
    CoinbaseMismatch,
    #[error("coinbase commitment does not match the claimed miner/amount")]
    CoinbaseCmMismatch,
    #[error("committed pot balance does not match pot_parent + fees − coinbase")]
    PotMismatch,
    #[error("block does not match the pinned genesis allocation")]
    BadGenesis,
    #[error("conservation violated: shielded total + pot changed")]
    ConservationViolated,
}

/// The pool state.
pub struct HnState {
    cm_leaves: Vec<Digest>,
    tree: NoteTree,
    nullifiers: HashSet<[u32; DIGEST_ELEMS]>,
    recent_roots: VecDeque<Digest>,
    outputs: Vec<OutputRecord>,
    height: u64,
    /// The devnet height the last block anchored to (monotone).
    anchor_height: u64,
    /// The emission pot (public security budget) — starts at
    /// `params.genesis_pot`, credits fees, funds coinbases.
    pot: u64,
    /// Total value in the shielded pool, tracked from PUBLIC deltas (coinbase
    /// amounts, genesis mints, fees) — the other half of the conservation
    /// invariant. Individual note values stay hidden.
    shielded_total: u64,
    params: HnChainParams,
}

impl HnState {
    pub fn new(params: HnChainParams) -> Self {
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
            anchor_height: 0,
            pot: params.genesis_pot,
            shielded_total: 0,
            params,
        }
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    /// The emission pot's current balance (public).
    pub fn pot(&self) -> u64 {
        self.pot
    }

    /// The shielded pool's total value (public aggregate; per-note values are
    /// hidden).
    pub fn shielded_total(&self) -> u64 {
        self.shielded_total
    }

    pub fn params(&self) -> &HnChainParams {
        &self.params
    }

    fn nf_key(nf: &Digest) -> [u32; DIGEST_ELEMS] {
        core::array::from_fn(|i| nf[i].as_canonical_u32())
    }

    fn append_leaf(&mut self, cm: Digest, ciphertext: Vec<u8>, is_coinbase: bool) {
        self.cm_leaves.push(cm);
        let height = self.height;
        let leaf_index = self.tree.append(cm);
        self.outputs.push(OutputRecord {
            leaf_index,
            cm,
            ciphertext,
            height,
            is_coinbase,
        });
    }

    /// The `u64` fee a tx pays, read from its public fee limbs.
    pub fn tx_fee(tx: &aegis_hn_wallet::Tx) -> Option<u64> {
        if tx.public_values.len() < PUB_FEE + N_LIMBS {
            return None;
        }
        let limbs: [F; N_LIMBS] =
            core::array::from_fn(|i| F::from_u32(tx.public_values[PUB_FEE + i]));
        Some(limbs_to_u64(&limbs))
    }

    /// Validate a single tx against the current state + a working nullifier set
    /// (used both at mempool admission and inside block application). Returns
    /// the tx's two nullifiers on success.
    ///
    /// **Cheap-checks-first (mempool DoS posture)**: shape, §6 ciphertext sizes,
    /// the EXACT flat fee, the anchor window, and the nullifier index are all
    /// checked BEFORE the ~52 ms hiding-proof verify — so spam with a stale
    /// anchor, a reused nullifier, a wrong shape, or a wrong fee is rejected
    /// for nearly free, and only well-formed, fresh, flat-fee txs reach the
    /// expensive verify.
    pub fn validate_tx(
        &self,
        tx: &aegis_hn_wallet::Tx,
        circuit: &SpendCircuit,
        pending: &HashSet<[u32; DIGEST_ELEMS]>,
    ) -> Result<[Digest; 2], HnError> {
        // ---- cheap checks first ----
        if tx.public_values.len() != N_PUB {
            return Err(HnError::BadPublicShape);
        }
        for ct in &tx.out_ciphertexts {
            if ct.len() != NOTE_CT_BYTES {
                return Err(HnError::BadCiphertext);
            }
        }
        // The fee must equal the flat fee EXACTLY — over- OR under-payment is
        // consensus-invalid (a variable fee would fingerprint transactions).
        if Self::tx_fee(tx) != Some(self.params.flat_fee) {
            return Err(HnError::BadFee);
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
        // ---- expensive check last ----
        if !circuit.verify(&tx.proof_bytes, &tx.public_values) {
            return Err(HnError::ProofInvalid);
        }
        Ok([nf0, nf1])
    }

    /// Apply one block: validate EVERYTHING (proofs, coinbase economics, pot
    /// arithmetic, the simulated state root) before any mutation — the state is
    /// untouched on any error. Consensus leaf order: each tx's two output
    /// commitments in tx order, then the coinbase note.
    pub fn apply_block(
        &mut self,
        block: &HnBlock,
        circuit: &SpendCircuit,
    ) -> Result<HnBlockUndo, HnError> {
        if limbs_to_digest(&block.prev_root) != self.tree.root() {
            return Err(HnError::PrevRootMismatch);
        }
        // Merge-mining anchor must never regress (devnet height monotone).
        if block.anchor.devnet_height < self.anchor_height {
            return Err(HnError::AnchorRegressed);
        }
        if block.coinbase_ct.len() != NOTE_CT_BYTES {
            return Err(HnError::BadCiphertext);
        }

        // ---- validate the txs (each pays EXACTLY the flat fee) ----
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
        let fees = self.params.flat_fee * block.txs.len() as u64;

        // ---- coinbase economics + pot arithmetic (all on the PARENT state) ----
        let n_genesis = self.params.genesis.len() as u64;
        let (pot_next, shielded_next) = if block.coinbase_is_reward {
            // Reward blocks only after the pinned genesis prefix.
            if self.height < n_genesis {
                return Err(HnError::BadGenesis);
            }
            let expected = self.params.coinbase_amount(self.pot, block.txs.len());
            if block.coinbase_amount != expected {
                return Err(HnError::CoinbaseMismatch);
            }
            // expected <= pot by construction; fees credit, coinbase draws.
            let pot_next = self.pot + fees - expected;
            if block.pot_after != pot_next {
                return Err(HnError::PotMismatch);
            }
            // Conservation (I1-extended): the pool gains the coinbase and loses
            // the fees; the pot does the exact opposite. Enforced, not assumed.
            let shielded_next = (self.shielded_total + expected)
                .checked_sub(fees)
                .ok_or(HnError::ConservationViolated)?;
            if shielded_next + pot_next != self.shielded_total + self.pot {
                return Err(HnError::ConservationViolated);
            }
            (pot_next, shielded_next)
        } else {
            // A genesis allocation block: only within the pinned prefix, no
            // txs, and (dest, amount) must match the params exactly.
            if self.height >= n_genesis || !block.txs.is_empty() {
                return Err(HnError::BadGenesis);
            }
            let (dest, amount) = &self.params.genesis[self.height as usize];
            if block.miner_owner != digest_to_limbs(&dest.owner) || block.coinbase_amount != *amount
            {
                return Err(HnError::BadGenesis);
            }
            // Genesis issuance: the pool grows by the pinned allocation; the
            // pot is untouched (its genesis value is a separate pinned param).
            if block.pot_after != self.pot {
                return Err(HnError::PotMismatch);
            }
            (self.pot, self.shielded_total + amount)
        };

        // ---- the shielded coinbase note must carry the claimed value ----
        let id = block_id(self.height, &self.tree.root());
        let expected_cm = coinbase_cm_expected(
            &limbs_to_digest(&block.miner_owner),
            block.coinbase_amount,
            &id,
        );
        if digest_to_limbs(&expected_cm) != block.coinbase_cm {
            return Err(HnError::CoinbaseCmMismatch);
        }

        // ---- the committed state root (simulated BEFORE mutating) ----
        let mut cms: Vec<Digest> = Vec::with_capacity(2 * block.txs.len() + 1);
        for tx in &block.txs {
            cms.push(digest_at(
                &tx.public_values,
                aegis_engine::spend::monolith::PUB_CMO0,
            ));
            cms.push(digest_at(
                &tx.public_values,
                aegis_engine::spend::monolith::PUB_CMO1,
            ));
        }
        cms.push(limbs_to_digest(&block.coinbase_cm));
        if self.simulate_state_root(&cms) != block.state_root {
            return Err(HnError::StateRootMismatch);
        }

        // ---- mutate (everything validated) ----
        let mut undo = HnBlockUndo {
            prev_leaf_count: self.cm_leaves.len(),
            added_nullifiers: all_nfs.clone(),
            prev_output_count: self.outputs.len(),
            prev_height: self.height,
            prev_anchor_height: self.anchor_height,
            prev_pot: self.pot,
            prev_shielded_total: self.shielded_total,
            evicted_root: None,
        };
        for tx in &block.txs {
            let cm0 = digest_at(&tx.public_values, aegis_engine::spend::monolith::PUB_CMO0);
            let cm1 = digest_at(&tx.public_values, aegis_engine::spend::monolith::PUB_CMO1);
            self.append_leaf(cm0, tx.out_ciphertexts[0].clone(), false);
            self.append_leaf(cm1, tx.out_ciphertexts[1].clone(), false);
        }
        self.append_leaf(
            limbs_to_digest(&block.coinbase_cm),
            block.coinbase_ct.clone(),
            block.coinbase_is_reward,
        );
        for k in &all_nfs {
            self.nullifiers.insert(*k);
        }
        if self.recent_roots.len() == self.params.root_window {
            undo.evicted_root = self.recent_roots.pop_front();
        }
        self.recent_roots.push_back(self.tree.root());
        self.height += 1;
        self.anchor_height = block.anchor.devnet_height;
        self.pot = pot_next;
        self.shielded_total = shielded_next;
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
        self.anchor_height = undo.prev_anchor_height;
        self.pot = undo.prev_pot;
        self.shielded_total = undo.prev_shielded_total;
    }

    /// Compute a block's `state_root` given the current tip and the block's
    /// txs + coinbase (used by production to fill the header, and by
    /// `apply_block` to validate it before mutating).
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
    fn tip_height(&self) -> u64 {
        self.height
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hn::mint::coinbase_note;
    use aegis_engine::address::{Address, WalletKeys};

    // ----- helpers -----

    fn addr(seed: &[u8]) -> Address {
        WalletKeys::from_seed(seed).address()
    }

    /// Params with no pinned genesis prefix and `pot` in the pot.
    fn params_pot(pot: u64) -> HnChainParams {
        HnChainParams::testnet().with_genesis(vec![], pot)
    }

    /// A consensus-valid empty reward block for the current state.
    fn reward_block(st: &HnState, miner: &Address) -> HnBlock {
        let amount = st.params().coinbase_amount(st.pot(), 0);
        let id = block_id(st.height(), &st.current_root());
        let mint = coinbase_note(miner, amount, &id);
        HnBlock {
            height: st.height(),
            prev_root: st.tip_root_limbs(),
            state_root: st.simulate_state_root(&[mint.cm]),
            txs: vec![],
            miner_owner: digest_to_limbs(&miner.owner),
            coinbase_amount: amount,
            coinbase_cm: digest_to_limbs(&mint.cm),
            coinbase_ct: mint.ciphertext,
            coinbase_is_reward: true,
            pot_after: st.pot() - amount,
            anchor: AuxAnchor::genesis(),
        }
    }

    // ----- happy path -----

    #[test]
    fn empty_reward_block_pays_base_from_pot() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"miner");
        let mut st = HnState::new(params_pot(1_000));
        let block = reward_block(&st, &miner);
        assert_eq!(block.coinbase_amount, 1, "empty block pays the 0.01 base");
        st.apply_block(&block, &circuit).unwrap();
        assert_eq!(st.pot(), 999, "pot decremented by the coinbase");
        assert_eq!(st.shielded_total(), 1, "pool grew by the coinbase");
    }

    #[test]
    fn pot_exhausted_chain_still_advances_with_zero_coinbase() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"m");
        let mut st = HnState::new(params_pot(2));
        // Two blocks drain the pot 2 → 1 → 0; further blocks pay 0 but apply.
        for expect_pot in [1u64, 0, 0, 0] {
            let block = reward_block(&st, &miner);
            st.apply_block(&block, &circuit).unwrap();
            assert_eq!(st.pot(), expect_pot);
        }
        assert_eq!(st.height(), 4, "the chain advances past pot exhaustion");
        assert_eq!(st.shielded_total(), 2, "only the funded coinbases minted");
    }

    // ----- round-trips -----

    /// apply → rollback → apply is the identity (reorg-safety), including the
    /// pot and the shielded total.
    #[test]
    fn apply_rollback_is_exact_inverse_including_pot() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"miner");
        let mut st = HnState::new(params_pot(500));
        let empty_root = st.tip_root_limbs();

        let block = reward_block(&st, &miner);
        let undo = st.apply_block(&block, &circuit).unwrap();
        assert_eq!((st.height(), st.pot(), st.shielded_total()), (1, 499, 1));

        st.rollback(undo);
        assert_eq!(st.height(), 0, "rollback restores height");
        assert_eq!(st.pot(), 500, "rollback restores the pot exactly");
        assert_eq!(st.shielded_total(), 0, "rollback restores the pool total");
        assert_eq!(
            st.tip_root_limbs(),
            empty_root,
            "rollback restores the tree root exactly"
        );
        assert_eq!(st.output_count(), 0, "rollback truncates the leaves");

        // Re-apply the same block: identity.
        st.apply_block(&block, &circuit).unwrap();
        assert_eq!((st.height(), st.pot(), st.shielded_total()), (1, 499, 1));
    }

    // ----- error paths -----

    #[test]
    fn block_with_wrong_prev_root_is_rejected() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"m");
        let mut st = HnState::new(params_pot(10));
        let mut bad = reward_block(&st, &miner);
        bad.prev_root = [123u32; DIGEST_ELEMS];
        assert!(matches!(
            st.apply_block(&bad, &circuit),
            Err(HnError::PrevRootMismatch)
        ));
    }

    #[test]
    fn coinbase_overclaim_is_rejected_even_with_matching_cm() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"greedy");
        let mut st = HnState::new(params_pot(1_000));
        // The miner claims base+1 and builds a fully consistent block for that
        // claim (cm, pot_after, state_root all match the OVER-claim) — the
        // consensus formula itself must reject it.
        let amount = st.params().coinbase_amount(st.pot(), 0) + 1;
        let id = block_id(st.height(), &st.current_root());
        let mint = coinbase_note(&miner, amount, &id);
        let bad = HnBlock {
            height: st.height(),
            prev_root: st.tip_root_limbs(),
            state_root: st.simulate_state_root(&[mint.cm]),
            txs: vec![],
            miner_owner: digest_to_limbs(&miner.owner),
            coinbase_amount: amount,
            coinbase_cm: digest_to_limbs(&mint.cm),
            coinbase_ct: mint.ciphertext,
            coinbase_is_reward: true,
            pot_after: st.pot() - amount,
            anchor: AuxAnchor::genesis(),
        };
        assert!(matches!(
            st.apply_block(&bad, &circuit),
            Err(HnError::CoinbaseMismatch)
        ));
    }

    #[test]
    fn coinbase_overclaim_with_short_pot_is_rejected() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"greedy");
        // Pot holds 0: the consensus coinbase is 0; claiming even the base is
        // an over-claim against an empty pot.
        let mut st = HnState::new(params_pot(0));
        let id = block_id(st.height(), &st.current_root());
        let mint = coinbase_note(&miner, 1, &id);
        let bad = HnBlock {
            height: st.height(),
            prev_root: st.tip_root_limbs(),
            state_root: st.simulate_state_root(&[mint.cm]),
            txs: vec![],
            miner_owner: digest_to_limbs(&miner.owner),
            coinbase_amount: 1,
            coinbase_cm: digest_to_limbs(&mint.cm),
            coinbase_ct: mint.ciphertext,
            coinbase_is_reward: true,
            pot_after: 0,
            anchor: AuxAnchor::genesis(),
        };
        assert!(matches!(
            st.apply_block(&bad, &circuit),
            Err(HnError::CoinbaseMismatch)
        ));
    }

    #[test]
    fn coinbase_underclaim_is_rejected() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"shy");
        let mut st = HnState::new(params_pot(1_000));
        let id = block_id(st.height(), &st.current_root());
        let mint = coinbase_note(&miner, 0, &id);
        let bad = HnBlock {
            height: st.height(),
            prev_root: st.tip_root_limbs(),
            state_root: st.simulate_state_root(&[mint.cm]),
            txs: vec![],
            miner_owner: digest_to_limbs(&miner.owner),
            coinbase_amount: 0,
            coinbase_cm: digest_to_limbs(&mint.cm),
            coinbase_ct: mint.ciphertext,
            coinbase_is_reward: true,
            pot_after: st.pot(),
            anchor: AuxAnchor::genesis(),
        };
        assert!(matches!(
            st.apply_block(&bad, &circuit),
            Err(HnError::CoinbaseMismatch)
        ));
    }

    #[test]
    fn coinbase_note_with_mismatched_amount_is_rejected() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"forger");
        let mut st = HnState::new(params_pot(1_000));
        // Claim the CORRECT public amount, but mint the shielded note for more:
        // the recomputed commitment cannot match.
        let mut bad = reward_block(&st, &miner);
        let id = block_id(st.height(), &st.current_root());
        let forged = coinbase_note(&miner, 1_000_000, &id);
        bad.coinbase_cm = digest_to_limbs(&forged.cm);
        bad.coinbase_ct = forged.ciphertext;
        bad.state_root = st.simulate_state_root(&[forged.cm]);
        assert!(matches!(
            st.apply_block(&bad, &circuit),
            Err(HnError::CoinbaseCmMismatch)
        ));
    }

    #[test]
    fn wrong_pot_after_is_rejected() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"m");
        let mut st = HnState::new(params_pot(1_000));
        let mut bad = reward_block(&st, &miner);
        bad.pot_after += 1;
        assert!(matches!(
            st.apply_block(&bad, &circuit),
            Err(HnError::PotMismatch)
        ));
    }

    #[test]
    fn reward_block_inside_genesis_prefix_is_rejected() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"m");
        let params = HnChainParams::testnet().with_genesis(vec![(addr(b"faucet"), 100)], 50);
        let mut st = HnState::new(params);
        // Height 0 is pinned to the faucet allocation — a reward block there is
        // invalid no matter how well-formed.
        let bad = reward_block(&st, &miner);
        assert!(matches!(
            st.apply_block(&bad, &circuit),
            Err(HnError::BadGenesis)
        ));
    }

    #[test]
    fn genesis_block_deviating_from_pinned_allocation_is_rejected() {
        let circuit = SpendCircuit::new();
        let faucet = addr(b"faucet");
        let thief = addr(b"thief");
        let params = HnChainParams::testnet().with_genesis(vec![(faucet, 100)], 50);
        let mut st = HnState::new(params);
        let id = block_id(0, &st.current_root());

        // Wrong destination.
        let m1 = coinbase_note(&thief, 100, &id);
        let redirect = HnBlock {
            height: 0,
            prev_root: st.tip_root_limbs(),
            state_root: st.simulate_state_root(&[m1.cm]),
            txs: vec![],
            miner_owner: digest_to_limbs(&thief.owner),
            coinbase_amount: 100,
            coinbase_cm: digest_to_limbs(&m1.cm),
            coinbase_ct: m1.ciphertext,
            coinbase_is_reward: false,
            pot_after: 50,
            anchor: AuxAnchor::genesis(),
        };
        assert!(matches!(
            st.apply_block(&redirect, &circuit),
            Err(HnError::BadGenesis)
        ));

        // Wrong amount.
        let m2 = coinbase_note(&faucet, 999, &id);
        let inflated = HnBlock {
            height: 0,
            prev_root: st.tip_root_limbs(),
            state_root: st.simulate_state_root(&[m2.cm]),
            txs: vec![],
            miner_owner: digest_to_limbs(&faucet.owner),
            coinbase_amount: 999,
            coinbase_cm: digest_to_limbs(&m2.cm),
            coinbase_ct: m2.ciphertext,
            coinbase_is_reward: false,
            pot_after: 50,
            anchor: AuxAnchor::genesis(),
        };
        assert!(matches!(
            st.apply_block(&inflated, &circuit),
            Err(HnError::BadGenesis)
        ));

        // The pinned allocation itself applies (pot untouched).
        let m3 = coinbase_note(&faucet, 100, &id);
        let good = HnBlock {
            height: 0,
            prev_root: st.tip_root_limbs(),
            state_root: st.simulate_state_root(&[m3.cm]),
            txs: vec![],
            miner_owner: digest_to_limbs(&faucet.owner),
            coinbase_amount: 100,
            coinbase_cm: digest_to_limbs(&m3.cm),
            coinbase_ct: m3.ciphertext,
            coinbase_is_reward: false,
            pot_after: 50,
            anchor: AuxAnchor::genesis(),
        };
        st.apply_block(&good, &circuit).unwrap();
        assert_eq!(st.pot(), 50, "genesis issuance does not touch the pot");
        assert_eq!(st.shielded_total(), 100);
    }
}
