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

use super::mint::{coinbase_cm_expected, pegmint_cm_expected};
use super::params::HnChainParams;
use crate::daa::next_nbits;
use aegis_engine::burn::burn_cm_expected;

const DOMAIN_BLOCK_ID: u32 = 0x0B10;

/// Deterministic block id (`height ‖ prev tip root`) — the coinbase-uniqueness
/// id every validator recomputes to check the coinbase commitment.
pub fn block_id(height: u64, prev_root: &Digest) -> [u8; 32] {
    hash_id_domain(DOMAIN_BLOCK_ID, height, prev_root)
}

/// The merge-mining anchor: the STARK-devnet Ergo header this hn block is mined
/// against — a LIVENESS reference (monotone devnet height + the header id),
/// paced by the devnet's Autolykos PoW chain.
///
/// The aux-PoW **binding** (E0) lives elsewhere: [`HnBlock::aux_pow`] carries a
/// [`super::auxpow::HnAuxPow`] whose Autolykos v2 solution commits this block's
/// [`hn_header_id`](super::header::hn_header_id) and clears its `sc_nbits`
/// target — one solved PoW bound to exactly one hn block. In Strict mode
/// (`params.require_aux_pow`) `apply_block` enforces it and fork choice weighs
/// the real work; in DevStub the anchor's monotone height is the only devnet
/// check (liveness-only, `epoch-validity-design.md` §6.5). The anchor and the
/// binding are complementary: the anchor says *which* devnet header, the
/// `aux_pow` witness proves that header's work commits this block.
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

/// A peg-in claim: a CONFIRMED devnet vault deposit consensus mints on the hn
/// chain. Everything is public; validators recompute the deterministic mint
/// commitment (`pegmint_cm_expected`) from `(dest_owner, amount − fee,
/// box_id)`, enforce box-id uniqueness (one mint per deposit, ever), and check
/// the deposit against their OWN devnet view at the pinned confirmation depth
/// (chain layer; a not-yet-confirmed claim is DEFERRED, not rejected).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PegInClaim {
    /// The devnet deposit box id (the unique-mint key).
    pub box_id: [u8; 32],
    /// The Aegis destination's spend component (from the deposit's R4).
    pub dest_owner: [u32; DIGEST_ELEMS],
    /// The destination's encryption component (R4 second half).
    pub dest_enc_pk: [u8; 32],
    /// The DEPOSITED amount (base units); the mint is `amount − peg fee`.
    pub amount: u64,
    /// Note ciphertext to the destination (producer-built; size-checked).
    pub ciphertext: Vec<u8>,
}

/// A peg-out: a normal shielded spend whose output 0 is the deterministic
/// BURN note (value = `amount + peg fee`, unspendable owner, nonces derived
/// from the spend's first nullifier), plus the PUBLIC withdrawal it funds.
/// Validators recompute the burn commitment and reject any mismatch — the
/// shielded value provably left the pool for exactly this withdrawal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PegOutTx {
    /// The 2-in/2-out spend (out0 = burn note, out1 = change).
    pub tx: aegis_hn_wallet::Tx,
    /// The USE to release on Ergo.
    pub amount: u64,
    /// The Ergo recipient's ErgoTree (proposition) bytes.
    pub recipient_prop: Vec<u8>,
}

/// A recorded withdrawal awaiting settlement (the epoch's pending set).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Withdrawal {
    /// Unique id = the burning spend's first nullifier.
    pub nf0: [u32; DIGEST_ELEMS],
    pub amount: u64,
    pub recipient_prop: Vec<u8>,
    /// hn height the peg-out landed at (settleable after `pegout_delay`).
    pub hn_height: u64,
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
    /// The parent block's [`hn_header_id`](super::header::hn_header_id) — the
    /// hash-linkage the fork-choice tree follows (E0; the all-zero sentinel at
    /// height 0). Committed by the header id, so a suffix's `prev_header_id`
    /// chain is what epoch-validity (E1) walks. `prev_root` (the parent's
    /// state root) still binds the STATE transition; the two together weld the
    /// header chain to the value-tree chain.
    #[serde(default)]
    pub prev_header_id: [u8; 32],
    pub state_root: [u32; DIGEST_ELEMS],
    /// Wall-clock stamp (ms) — the LWMA difficulty adjustment's solve-time
    /// input, and part of the header id.
    pub timestamp_ms: u64,
    /// The aux-PoW difficulty (compact nbits) this block was mined at.
    /// Consensus-checked against the LWMA expectation; its decoded value is the
    /// block's real-work weight in fork choice (E0).
    pub sc_nbits: u32,
    pub txs: Vec<aegis_hn_wallet::Tx>,
    /// Peg-out spends (each also a full spend proof; leaf order after `txs`).
    pub pegouts: Vec<PegOutTx>,
    /// Confirmed devnet deposits minted in this block (leaf order after
    /// peg-out outputs, before the coinbase).
    pub pegins: Vec<PegInClaim>,
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
    /// The aux-PoW witness ([`super::auxpow::HnAuxPow`] bytes) binding this
    /// block's [`hn_header_id`](super::header::hn_header_id) to real Autolykos
    /// work (E0). `None` in DevStub (the API-anchored devnet); REQUIRED for
    /// reward blocks when `params.require_aux_pow` (Strict). Excluded from the
    /// header id — the aux-PoW attests the id, it does not extend it.
    #[serde(default)]
    pub aux_pow: Option<Vec<u8>>,
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
    added_pegin_box_ids: Vec<[u8; 32]>,
    prev_withdrawal_count: usize,
    /// A root evicted from the front of the window when this block's tip root
    /// was pushed (restored on rollback so the window is exact).
    evicted_root: Option<Digest>,
    /// A `(timestamp, nbits)` pair evicted from the front of the DAA view when
    /// this block's pair was pushed (restored on rollback so the view is exact).
    evicted_daa: Option<(u64, u32)>,
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
    #[error("block sc_nbits does not equal the LWMA difficulty expectation")]
    NbitsMismatch,
    #[error("aux-PoW share is missing or does not bind this block's header id")]
    AuxPowInvalid,
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
    #[error("peg-in claim reuses an already-minted deposit box id")]
    DuplicatePegIn,
    #[error("peg-in claim is malformed (amount, ciphertext, or commitment)")]
    BadPegIn,
    #[error("peg-out burn note does not match the public withdrawal")]
    BadPegOut,
    #[error("peg-in deposit not yet confirmed at the required depth (defer)")]
    PegInNotConfirmed,
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
    /// `(timestamp_ms, sc_nbits)` of the recent chain, oldest first — the LWMA
    /// solve-time view. Capped at `daa_window + 1` entries (all `next_nbits`
    /// ever consults); the same view the share verifier's `sc_nbits` equality
    /// consumes.
    daa_view: VecDeque<(u64, u32)>,
    /// The emission pot (public security budget) — starts at
    /// `params.genesis_pot`, credits fees, funds coinbases.
    pot: u64,
    /// Total value in the shielded pool, tracked from PUBLIC deltas (coinbase
    /// amounts, genesis mints, fees, peg flows) — the other half of the
    /// conservation invariant. Individual note values stay hidden.
    shielded_total: u64,
    /// Devnet deposit box ids already minted (one mint per deposit, ever).
    used_pegins: HashSet<[u8; 32]>,
    /// Recorded withdrawals awaiting settlement (append-only; the VAULT's
    /// root/counter continuity prevents double-settlement on the Ergo side).
    pending_withdrawals: Vec<Withdrawal>,
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
            daa_view: VecDeque::new(),
            pot: params.genesis_pot,
            shielded_total: 0,
            used_pegins: HashSet::new(),
            pending_withdrawals: Vec::new(),
            params,
        }
    }

    /// A deposit box id already minted?
    pub fn pegin_used(&self, box_id: &[u8; 32]) -> bool {
        self.used_pegins.contains(box_id)
    }

    /// The recorded withdrawals (the settle loop reads these).
    pub fn withdrawals(&self) -> &[Withdrawal] {
        &self.pending_withdrawals
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    /// The LWMA difficulty (compact nbits) the NEXT block must declare — the
    /// single spelling shared by production, validation, and the aux-PoW share
    /// verifier (E0). Below `daa_window + 1` blocks this is the floor
    /// (`min_difficulty_nbits`).
    pub fn expected_nbits(&self) -> u32 {
        let view: Vec<(u64, u32)> = self.daa_view.iter().copied().collect();
        next_nbits(&self.params.daa(), &view)
    }

    /// The current DAA solve-time view (oldest first) — what a share verifier
    /// checking a child of this tip needs for the `sc_nbits` equality.
    pub fn daa_view(&self) -> Vec<(u64, u32)> {
        self.daa_view.iter().copied().collect()
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
        // The aux-PoW difficulty is consensus: a miner cannot self-declare an
        // easy (or an inflated-weight) `sc_nbits` — it must equal the LWMA
        // expectation for this chain position (E0; the same defense as the
        // Curve-Trees share verifier's §3 equality).
        if block.sc_nbits != self.expected_nbits() {
            return Err(HnError::NbitsMismatch);
        }
        // Strict aux-PoW binding (E0): a reward (mined) block must carry a
        // witness proving its `hn_header_id` was committed by an Ergo
        // candidate whose Autolykos v2 hit clears `sc_nbits`. Genesis
        // allocations (non-reward, pre-PoW prefix) are exempt. In DevStub
        // (`require_aux_pow == false`) the check is skipped — the API-anchored
        // devnet does not merge-mine yet (liveness-only, §6.5).
        if self.params.require_aux_pow && block.coinbase_is_reward {
            let bytes = block.aux_pow.as_ref().ok_or(HnError::AuxPowInvalid)?;
            let aux =
                super::auxpow::HnAuxPow::from_bytes(bytes).map_err(|_| HnError::AuxPowInvalid)?;
            aux.verify(self.params.chain_id, block)
                .map_err(|_| HnError::AuxPowInvalid)?;
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
        // ---- peg-outs: full spends whose out0 is the bound burn note ----
        let mut pegout_outflow: u64 = 0; // Σ withdrawal amounts (leaves the system)
        let mut pegout_fees: u64 = 0; // Σ peg fees (→ pot)
        let mut burn_total: u64 = 0; // Σ (amount + fee) — dead value in the tree
        for po in &block.pegouts {
            let nfs = self.validate_tx(&po.tx, circuit, &seen)?;
            let fee = self.params.peg_fee(po.amount);
            let burn_value = po.amount.checked_add(fee).ok_or(HnError::BadPegOut)?;
            if po.amount == 0 || po.recipient_prop.is_empty() || po.recipient_prop.len() > 4096 {
                return Err(HnError::BadPegOut);
            }
            // out0 MUST be the deterministic burn note for exactly this
            // withdrawal (value amount+fee, unspendable owner, nf0-derived
            // nonces) — the shielded value provably left for this recipient.
            let cm0 = digest_at(
                &po.tx.public_values,
                aegis_engine::spend::monolith::PUB_CMO0,
            );
            if burn_cm_expected(burn_value, &nfs[0]) != cm0 {
                return Err(HnError::BadPegOut);
            }
            for nf in &nfs {
                let k = Self::nf_key(nf);
                seen.insert(k);
                all_nfs.push(k);
            }
            pegout_outflow += po.amount;
            pegout_fees += fee;
            burn_total += burn_value;
        }
        // ---- peg-ins: confirmed deposits, one mint per box id, ever ----
        let mut pegin_inflow: u64 = 0; // Σ deposited (enters the system)
        let mut pegin_fees: u64 = 0; // Σ peg fees (→ pot)
        let mut pegin_cms: Vec<Digest> = Vec::with_capacity(block.pegins.len());
        {
            let mut in_block: HashSet<[u8; 32]> = HashSet::new();
            for pi in &block.pegins {
                if self.used_pegins.contains(&pi.box_id) || !in_block.insert(pi.box_id) {
                    return Err(HnError::DuplicatePegIn);
                }
                if pi.ciphertext.len() != NOTE_CT_BYTES {
                    return Err(HnError::BadPegIn);
                }
                let fee = self.params.peg_fee(pi.amount);
                let minted = pi
                    .amount
                    .checked_sub(fee)
                    .filter(|m| *m > 0)
                    .ok_or(HnError::BadPegIn)?;
                let cm = pegmint_cm_expected(&limbs_to_digest(&pi.dest_owner), minted, &pi.box_id);
                pegin_cms.push(cm);
                pegin_inflow += pi.amount;
                pegin_fees += fee;
            }
        }
        let fees = self.params.flat_fee * (block.txs.len() + block.pegouts.len()) as u64;

        // ---- coinbase economics + pot arithmetic (all on the PARENT state) ----
        let n_genesis = self.params.genesis.len() as u64;
        let (pot_next, shielded_next) = if block.coinbase_is_reward {
            // Reward blocks only after the pinned genesis prefix.
            if self.height < n_genesis {
                return Err(HnError::BadGenesis);
            }
            let n_spends = block.txs.len() + block.pegouts.len();
            let expected = self.params.coinbase_amount(self.pot, n_spends);
            if block.coinbase_amount != expected {
                return Err(HnError::CoinbaseMismatch);
            }
            // expected <= pot by construction; flat + peg fees credit,
            // coinbase draws.
            let pot_next = self.pot + fees + pegout_fees + pegin_fees - expected;
            if block.pot_after != pot_next {
                return Err(HnError::PotMismatch);
            }
            // Conservation (I1-extended, with bridge flows): the system total
            // (shielded + pot) changes by exactly (peg-in deposits − peg-out
            // withdrawals) — value entering from / leaving to the vault on
            // Ergo. Enforced, not assumed.
            let shielded_next = (self.shielded_total + expected + (pegin_inflow - pegin_fees))
                .checked_sub(fees + burn_total)
                .ok_or(HnError::ConservationViolated)?;
            if shielded_next + pot_next
                != (self.shielded_total + self.pot + pegin_inflow)
                    .checked_sub(pegout_outflow)
                    .ok_or(HnError::ConservationViolated)?
            {
                return Err(HnError::ConservationViolated);
            }
            (pot_next, shielded_next)
        } else {
            // A genesis allocation block: only within the pinned prefix, no
            // txs/pegs, and (dest, amount) must match the params exactly.
            if self.height >= n_genesis
                || !block.txs.is_empty()
                || !block.pegouts.is_empty()
                || !block.pegins.is_empty()
            {
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
        // Consensus leaf order: tx outputs, peg-out outputs, peg-in mints,
        // coinbase.
        let mut cms: Vec<Digest> = Vec::with_capacity(
            2 * (block.txs.len() + block.pegouts.len()) + block.pegins.len() + 1,
        );
        for tx in block.txs.iter().chain(block.pegouts.iter().map(|p| &p.tx)) {
            cms.push(digest_at(
                &tx.public_values,
                aegis_engine::spend::monolith::PUB_CMO0,
            ));
            cms.push(digest_at(
                &tx.public_values,
                aegis_engine::spend::monolith::PUB_CMO1,
            ));
        }
        cms.extend(pegin_cms.iter().copied());
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
            added_pegin_box_ids: block.pegins.iter().map(|p| p.box_id).collect(),
            prev_withdrawal_count: self.pending_withdrawals.len(),
            evicted_root: None,
            evicted_daa: None,
        };
        for tx in block.txs.iter().chain(block.pegouts.iter().map(|p| &p.tx)) {
            let cm0 = digest_at(&tx.public_values, aegis_engine::spend::monolith::PUB_CMO0);
            let cm1 = digest_at(&tx.public_values, aegis_engine::spend::monolith::PUB_CMO1);
            self.append_leaf(cm0, tx.out_ciphertexts[0].clone(), false);
            self.append_leaf(cm1, tx.out_ciphertexts[1].clone(), false);
        }
        for (pi, cm) in block.pegins.iter().zip(pegin_cms.iter()) {
            self.append_leaf(*cm, pi.ciphertext.clone(), false);
        }
        for pi in &block.pegins {
            self.used_pegins.insert(pi.box_id);
        }
        for po in &block.pegouts {
            let nf0 = digest_at(&po.tx.public_values, PUB_NF0);
            self.pending_withdrawals.push(Withdrawal {
                nf0: digest_to_limbs(&nf0),
                amount: po.amount,
                recipient_prop: po.recipient_prop.clone(),
                hn_height: self.height,
            });
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
        // Advance the LWMA solve-time view (cap at window + 1, the most
        // next_nbits ever consults).
        self.daa_view
            .push_back((block.timestamp_ms, block.sc_nbits));
        if self.daa_view.len() > self.params.daa_window + 1 {
            undo.evicted_daa = self.daa_view.pop_front();
        }
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
        self.daa_view.pop_back();
        if let Some(front) = undo.evicted_daa {
            self.daa_view.push_front(front);
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
        for b in &undo.added_pegin_box_ids {
            self.used_pegins.remove(b);
        }
        self.pending_withdrawals
            .truncate(undo.prev_withdrawal_count);
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
            prev_header_id: [0u8; 32],
            state_root: st.simulate_state_root(&[mint.cm]),
            timestamp_ms: 1_760_000_000_000 + st.height() * 15_000,
            sc_nbits: st.expected_nbits(),
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: digest_to_limbs(&miner.owner),
            coinbase_amount: amount,
            coinbase_cm: digest_to_limbs(&mint.cm),
            coinbase_ct: mint.ciphertext,
            coinbase_is_reward: true,
            pot_after: st.pot() - amount,
            anchor: AuxAnchor::genesis(),
            aux_pow: None,
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
            prev_header_id: [0u8; 32],
            state_root: st.simulate_state_root(&[mint.cm]),
            timestamp_ms: 1_760_000_000_000 + st.height() * 15_000,
            sc_nbits: st.expected_nbits(),
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: digest_to_limbs(&miner.owner),
            coinbase_amount: amount,
            coinbase_cm: digest_to_limbs(&mint.cm),
            coinbase_ct: mint.ciphertext,
            coinbase_is_reward: true,
            pot_after: st.pot() - amount,
            anchor: AuxAnchor::genesis(),
            aux_pow: None,
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
            prev_header_id: [0u8; 32],
            state_root: st.simulate_state_root(&[mint.cm]),
            timestamp_ms: 1_760_000_000_000 + st.height() * 15_000,
            sc_nbits: st.expected_nbits(),
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: digest_to_limbs(&miner.owner),
            coinbase_amount: 1,
            coinbase_cm: digest_to_limbs(&mint.cm),
            coinbase_ct: mint.ciphertext,
            coinbase_is_reward: true,
            pot_after: 0,
            anchor: AuxAnchor::genesis(),
            aux_pow: None,
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
            prev_header_id: [0u8; 32],
            state_root: st.simulate_state_root(&[mint.cm]),
            timestamp_ms: 1_760_000_000_000 + st.height() * 15_000,
            sc_nbits: st.expected_nbits(),
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: digest_to_limbs(&miner.owner),
            coinbase_amount: 0,
            coinbase_cm: digest_to_limbs(&mint.cm),
            coinbase_ct: mint.ciphertext,
            coinbase_is_reward: true,
            pot_after: st.pot(),
            anchor: AuxAnchor::genesis(),
            aux_pow: None,
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

    // ----- aux-PoW binding (E0, Strict mode) -----

    fn strict_params(pot: u64) -> HnChainParams {
        HnChainParams::testnet()
            .with_genesis(vec![], pot)
            .with_strict_aux_pow()
    }

    #[test]
    fn strict_reward_block_without_aux_pow_is_rejected() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"miner");
        let mut st = HnState::new(strict_params(1_000));
        let block = reward_block(&st, &miner); // aux_pow: None
        assert!(matches!(
            st.apply_block(&block, &circuit),
            Err(HnError::AuxPowInvalid)
        ));
    }

    #[test]
    fn strict_reward_block_with_valid_aux_pow_applies() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"miner");
        let mut st = HnState::new(strict_params(1_000));
        let mut block = reward_block(&st, &miner);
        // Merge-mine the witness binding this exact block's header id.
        let aux = crate::hn::auxpow::mine_hn_aux_pow(st.params().chain_id, &block);
        block.aux_pow = Some(aux.to_bytes().expect("witness serializes"));
        st.apply_block(&block, &circuit)
            .expect("a block backed by real aux-PoW work applies");
        assert_eq!(st.height(), 1);
    }

    #[test]
    fn strict_reward_block_with_aux_pow_for_a_different_block_is_rejected() {
        let circuit = SpendCircuit::new();
        let miner = addr(b"miner");
        let mut st = HnState::new(strict_params(1_000));
        let block = reward_block(&st, &miner);
        // A witness mined for a DIFFERENT block (tampered state_root): the id
        // it commits will not equal this block's header id.
        let mut other = block.clone();
        other.state_root[0] ^= 1;
        let aux = crate::hn::auxpow::mine_hn_aux_pow(st.params().chain_id, &other);
        let mut bad = block;
        bad.aux_pow = Some(aux.to_bytes().expect("witness serializes"));
        assert!(matches!(
            st.apply_block(&bad, &circuit),
            Err(HnError::AuxPowInvalid)
        ));
    }

    #[test]
    fn strict_genesis_allocation_is_exempt_from_aux_pow() {
        // Genesis (non-reward) blocks are the pre-PoW pinned prefix — Strict
        // mode does not require a witness for them.
        let circuit = SpendCircuit::new();
        let faucet = addr(b"faucet");
        let params = HnChainParams::testnet()
            .with_genesis(vec![(faucet, 100)], 50)
            .with_strict_aux_pow();
        let mut st = HnState::new(params);
        let id = block_id(0, &st.current_root());
        let m = coinbase_note(&faucet, 100, &id);
        let genesis = HnBlock {
            height: 0,
            prev_root: st.tip_root_limbs(),
            prev_header_id: [0u8; 32],
            state_root: st.simulate_state_root(&[m.cm]),
            timestamp_ms: 1_760_000_000_000,
            sc_nbits: st.expected_nbits(),
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: digest_to_limbs(&faucet.owner),
            coinbase_amount: 100,
            coinbase_cm: digest_to_limbs(&m.cm),
            coinbase_ct: m.ciphertext,
            coinbase_is_reward: false,
            pot_after: 50,
            anchor: AuxAnchor::genesis(),
            aux_pow: None,
        };
        st.apply_block(&genesis, &circuit)
            .expect("genesis allocation applies without aux-PoW");
    }

    #[test]
    fn wrong_sc_nbits_is_rejected() {
        // The aux-PoW difficulty is consensus: a self-declared nbits that does
        // not equal the LWMA expectation is invalid (E0).
        let circuit = SpendCircuit::new();
        let miner = addr(b"m");
        let mut st = HnState::new(params_pot(1_000));
        let mut bad = reward_block(&st, &miner);
        bad.sc_nbits = st.expected_nbits().wrapping_add(1);
        assert!(matches!(
            st.apply_block(&bad, &circuit),
            Err(HnError::NbitsMismatch)
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
            prev_header_id: [0u8; 32],
            state_root: st.simulate_state_root(&[m1.cm]),
            timestamp_ms: 1_760_000_000_000 + st.height() * 15_000,
            sc_nbits: st.expected_nbits(),
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: digest_to_limbs(&thief.owner),
            coinbase_amount: 100,
            coinbase_cm: digest_to_limbs(&m1.cm),
            coinbase_ct: m1.ciphertext,
            coinbase_is_reward: false,
            pot_after: 50,
            anchor: AuxAnchor::genesis(),
            aux_pow: None,
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
            prev_header_id: [0u8; 32],
            state_root: st.simulate_state_root(&[m2.cm]),
            timestamp_ms: 1_760_000_000_000 + st.height() * 15_000,
            sc_nbits: st.expected_nbits(),
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: digest_to_limbs(&faucet.owner),
            coinbase_amount: 999,
            coinbase_cm: digest_to_limbs(&m2.cm),
            coinbase_ct: m2.ciphertext,
            coinbase_is_reward: false,
            pot_after: 50,
            anchor: AuxAnchor::genesis(),
            aux_pow: None,
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
            prev_header_id: [0u8; 32],
            state_root: st.simulate_state_root(&[m3.cm]),
            timestamp_ms: 1_760_000_000_000 + st.height() * 15_000,
            sc_nbits: st.expected_nbits(),
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: digest_to_limbs(&faucet.owner),
            coinbase_amount: 100,
            coinbase_cm: digest_to_limbs(&m3.cm),
            coinbase_ct: m3.ciphertext,
            coinbase_is_reward: false,
            pot_after: 50,
            anchor: AuxAnchor::genesis(),
            aux_pow: None,
        };
        st.apply_block(&good, &circuit).unwrap();
        assert_eq!(st.pot(), 50, "genesis issuance does not touch the pot");
        assert_eq!(st.shielded_total(), 100);
    }
}
