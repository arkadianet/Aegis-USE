//! `verify_epoch` — the E1 structural epoch-validity statement (+ E3 chaining).
//!
//! Given the vault's chained state (`prev_root` via the committed frontier,
//! `tip_id_prev` = R7, `settled_root_in` = R6) and a settler-supplied suffix of
//! blocks, prove the suffix is a consensus-valid, real-value hn extension whose
//! appended leaves ARE the epoch — so `new_root` cannot be a fabricated private
//! tree. The soundness chain (design §6):
//!
//! 1. **header-id chain** `T_prev → T_new` (R7) — the suffix extends the exact
//!    sealed tip; no rewrite, ever.
//! 2. **leaves re-derived, not supplied** — each block's appended leaves are
//!    recomputed from its txs (spend outputs `cm0`/`cm1`), peg-out burn notes,
//!    peg-in mints, and coinbase, in the consensus order; the frontier
//!    transition consumes exactly these; `new_root == B_k.state_root`.
//! 3. **the digest bind** — those spend outputs are bound to REAL spend proofs
//!    the recursion tree verified (`digest.rs`); a fabricator cannot inject a
//!    fake note commitment.
//! 4. **anchor-window** — every spend's `PUB_ROOT` is a recent real state-root
//!    of the settled chain, never a private-tree root.
//! 5. **economics replayed** — coinbase amount, pot chain, conservation, burn
//!    binding, peg arithmetic — the value is conserved, not minted.
//! 6. **`pegout_delay`** — a settled burn's block is ≥ `PEGOUT_DELAY` below the
//!    sealed tip, forcing a fabricator to mine a `≥ pegout_delay+1`-block suffix.
//! 7. **E3 replay-close** — each burn's `nf0` is inserted into the settled set,
//!    non-membership proven first (`settled.rs`).
//!
//! Aux-PoW work-pricing (E2, `share.rs`) and canonical-Ergo anchoring (E4,
//! `anchor.rs`) verify the same suffix's blocks and tip; they compose with this
//! statement in the guest but are separated for clarity + cost isolation.

use std::collections::HashSet;

use crate::burn::burn_cm_expected;
use crate::merkle::Frontier;
use crate::mint::{coinbase_cm_expected, pegmint_cm_expected};
use crate::poseidon::{digest_to_limbs, Digest};
use crate::settled::{self, SETTLED_DEPTH};

use super::digest::epoch_spend_root;
use super::header_id::{block_id, header_id};
use super::types::{coinbase_amount, peg_fee, SuffixBlock, FLAT_FEE, PEGOUT_DELAY, ROOT_WINDOW};

/// A settled withdrawal surfaced from the suffix (journal entry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Withdrawal {
    pub amount: u64,
    pub recipient_prop: Vec<u8>,
    pub nf0: Digest,
}

/// The full epoch-validity witness the guest reads.
pub struct EpochWitness {
    pub chain_id: u32,
    /// The suffix `B_1..B_k` (k ≥ 1), in order.
    pub blocks: Vec<SuffixBlock>,
    /// Pre-epoch frontier (postcard) — its `root()` is bound to `prev_root`.
    pub frontier_bytes: Vec<u8>,
    /// Vault R7 (`T_prev`): the previous sealed tip header id.
    pub tip_id_prev: [u8; 32],
    /// Pot balance before the suffix (parent of `B_1`).
    pub pot_before: u64,
    /// Shielded total before the suffix.
    pub shielded_before: u64,
    /// Authenticated recent state-roots preceding the suffix (the anchor-window
    /// seam). Stage-T: supplied + authenticated by the caller via seam blocks
    /// (`anchor_seam`); may be empty (then only in-suffix roots + the pre-suffix
    /// tip anchor spends).
    pub seam_roots: Vec<Digest>,
    /// Vault R6 (`settled_root_in`): the settled-burn set root.
    pub settled_root_in: Digest,
    /// One 248-sibling non-membership witness per peg-out, in suffix order.
    pub settled_paths: Vec<[Digest; SETTLED_DEPTH]>,
    /// The recursion root proof's surfaced spend digest (bound by the guest's
    /// root verify) — checked against the re-derived suffix (`digest.rs`).
    pub spend_root_digest: Digest,
    /// Canonical-Ergo anchor id spliced by the contract (E4); passed through to
    /// the journal. Anchor LINKAGE is verified in `anchor.rs`.
    pub ergo_ref_id: [u8; 32],
    /// Settlement counter (journal `counter_next`).
    pub counter_next: u64,
}

/// The proven epoch-validity result (the vault chains these into R4/R6/R7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochResult {
    pub prev_root: Digest,
    pub new_root: Digest,
    pub settled_root_out: Digest,
    pub tip_id_new: [u8; 32],
    pub pot_after: u64,
    pub shielded_after: u64,
    pub withdrawals: Vec<Withdrawal>,
}

/// Every way a suffix can fail epoch-validity — one variant per soundness check.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EpochError {
    #[error("empty suffix")]
    EmptySuffix,
    #[error("pre-epoch frontier does not decode")]
    FrontierDecode,
    #[error("block[0].prev_root != committed frontier root (prev_root binding)")]
    PrevRootMismatch,
    #[error("block[{i}].prev_header_id does not extend the sealed tip (header chain)")]
    HeaderChainBroken { i: usize },
    #[error("block[{i}].prev_root != parent state_root (value-tree chain broken)")]
    ValueChainBroken { i: usize },
    #[error("block[{i}] is a genesis (non-reward) block — not allowed in a suffix")]
    NonRewardBlock { i: usize },
    #[error("block[{i}] spend #{j} paid fee {got} != FLAT_FEE {want}")]
    BadFee {
        i: usize,
        j: usize,
        got: u64,
        want: u64,
    },
    #[error("block[{i}] spend #{j} anchor root is not a recent real state-root")]
    AnchorOutOfWindow { i: usize, j: usize },
    #[error("block[{i}] peg-out #{j} out0 is not the bound burn note")]
    BadBurnBinding { i: usize, j: usize },
    #[error("block[{i}] peg-out #{j} has amount 0, empty recipient, or recipient > 4096 bytes")]
    BadPegOutBounds { i: usize, j: usize },
    #[error("block[{i}] duplicate nullifier in suffix (double-spend)")]
    DuplicateNullifier { i: usize },
    #[error("block[{i}] coinbase amount {got} != consensus {want}")]
    CoinbaseAmount { i: usize, got: u64, want: u64 },
    #[error("block[{i}] coinbase commitment mismatch")]
    CoinbaseCm { i: usize },
    #[error("block[{i}] pot_after {got} != recomputed {want}")]
    PotMismatch { i: usize, got: u64, want: u64 },
    #[error("block[{i}] conservation violated")]
    ConservationViolated { i: usize },
    #[error("block[{i}] state_root != frontier root after re-derived leaves")]
    StateRootMismatch { i: usize },
    #[error("peg-out #{j} not matured: tip {tip} < height {h} + pegout_delay")]
    NotMatured { j: usize, tip: u64, h: u64 },
    #[error("spend-digest bind failed: re-derived suffix != recursion root digest")]
    SpendDigestMismatch,
    #[error("settled_paths count {got} != {want} (2 per suffix spend — F6c)")]
    SettledPathCount { got: usize, want: usize },
    #[error("spend #{j} nullifier already settled (E3 all-nullifier replay-close, F6c)")]
    AlreadySettled { j: usize },
    #[error("arithmetic overflow in block[{i}]")]
    Overflow { i: usize },
}

/// Verify the suffix and produce the epoch-validity result + the settled set
/// out-root. Pure over the witness — this is exactly what the guest runs.
pub fn verify_epoch(w: &EpochWitness) -> Result<EpochResult, EpochError> {
    if w.blocks.is_empty() {
        return Err(EpochError::EmptySuffix);
    }
    let cid = w.chain_id;

    // ---- frontier / prev_root binding ----
    let frontier: Frontier =
        postcard::from_bytes(&w.frontier_bytes).map_err(|_| EpochError::FrontierDecode)?;
    let prev_root = frontier.root();
    if w.blocks[0].prev_root != prev_root {
        return Err(EpochError::PrevRootMismatch);
    }

    // ---- header-id chain seed ----
    if w.blocks[0].prev_header_id != w.tip_id_prev {
        return Err(EpochError::HeaderChainBroken { i: 0 });
    }

    // Anchor-window: authenticated recent roots (seam + the pre-suffix tip).
    let mut recent_roots: Vec<Digest> = w.seam_roots.clone();
    recent_roots.push(prev_root);

    let mut running = frontier;
    let mut pot = w.pot_before;
    let mut shielded = w.shielded_before;
    let mut seen_nf: HashSet<[u32; 8]> = HashSet::new();
    let mut all_spends = Vec::new();
    let mut withdrawals: Vec<Withdrawal> = Vec::new();
    // (peg-out nf0, its block height) in suffix order — for E3 + maturity.
    let mut pegout_records: Vec<(Digest, u64)> = Vec::new();
    let tip_height = w.blocks.last().expect("non-empty").height;

    for (i, block) in w.blocks.iter().enumerate() {
        if !block.coinbase_is_reward {
            return Err(EpochError::NonRewardBlock { i });
        }
        // Header chain: each block extends its predecessor's id.
        if i > 0 {
            let want = header_id(cid, &w.blocks[i - 1]);
            if block.prev_header_id != want {
                return Err(EpochError::HeaderChainBroken { i });
            }
        }
        // Value-tree chain: prev_root == running frontier root.
        if block.prev_root != running.root() {
            return Err(EpochError::ValueChainBroken { i });
        }

        // Anchor window as of THIS block's parent (roots recorded so far).
        let window_lo = recent_roots.len().saturating_sub(ROOT_WINDOW);
        let window = &recent_roots[window_lo..];

        // ---- per-spend checks (txs then peg-outs) + nullifier distinctness ----
        for (j, s) in block.spends_in_order().enumerate() {
            if s.fee != FLAT_FEE {
                return Err(EpochError::BadFee {
                    i,
                    j,
                    got: s.fee,
                    want: FLAT_FEE,
                });
            }
            if !window.contains(&s.root) {
                return Err(EpochError::AnchorOutOfWindow { i, j });
            }
            for nf in [&s.nf0, &s.nf1] {
                if !seen_nf.insert(digest_to_limbs(nf)) {
                    return Err(EpochError::DuplicateNullifier { i });
                }
            }
            all_spends.push(s.clone());
        }

        // ---- peg-out burn binding + withdrawal record ----
        let mut pegout_outflow: u64 = 0;
        let mut pegout_fees: u64 = 0;
        let mut burn_total: u64 = 0;
        for (j, po) in block.pegouts.iter().enumerate() {
            // F6g: peg-out well-formedness bounds — parity with the node
            // (`aegis-node/src/hn/state.rs:482`). A zero amount, empty
            // recipient proposition, or a recipient over 4096 bytes is
            // consensus-invalid; enforce it in-guest so the guest's accepted
            // set stays a subset of the node's (§4.7).
            if po.amount == 0 || po.recipient_prop.is_empty() || po.recipient_prop.len() > 4096 {
                return Err(EpochError::BadPegOutBounds { i, j });
            }
            let fee = peg_fee(po.amount);
            let burn_value = po
                .amount
                .checked_add(fee)
                .ok_or(EpochError::Overflow { i })?;
            // D1: the burn nonces bind the declared (recipient_prop, amount), so
            // a suffix peg-out whose burn does not reproduce from its recorded
            // recipient fails here — the recipient is welded to the burn note at
            // the settlement layer, independent of the E2 aux-PoW body binding.
            if burn_cm_expected(burn_value, &po.spend.nf0, &po.recipient_prop, po.amount)
                != po.spend.cm0
            {
                return Err(EpochError::BadBurnBinding { i, j });
            }
            pegout_outflow = pegout_outflow
                .checked_add(po.amount)
                .ok_or(EpochError::Overflow { i })?;
            pegout_fees = pegout_fees
                .checked_add(fee)
                .ok_or(EpochError::Overflow { i })?;
            burn_total = burn_total
                .checked_add(burn_value)
                .ok_or(EpochError::Overflow { i })?;
            withdrawals.push(Withdrawal {
                amount: po.amount,
                recipient_prop: po.recipient_prop.clone(),
                nf0: po.spend.nf0,
            });
            pegout_records.push((po.spend.nf0, block.height));
        }

        // ---- peg-in mints ----
        let mut pegin_inflow: u64 = 0;
        let mut pegin_fees: u64 = 0;
        let mut pegin_cms: Vec<Digest> = Vec::with_capacity(block.pegins.len());
        for pi in &block.pegins {
            let fee = peg_fee(pi.amount);
            let minted = pi
                .amount
                .checked_sub(fee)
                .filter(|m| *m > 0)
                .ok_or(EpochError::Overflow { i })?;
            pegin_cms.push(pegmint_cm_expected(&pi.dest_owner, minted, &pi.box_id));
            pegin_inflow = pegin_inflow
                .checked_add(pi.amount)
                .ok_or(EpochError::Overflow { i })?;
            pegin_fees = pegin_fees
                .checked_add(fee)
                .ok_or(EpochError::Overflow { i })?;
        }

        // ---- coinbase economics + pot chain (on the PARENT pot) ----
        let n_spends = block.n_spends();
        let fees = FLAT_FEE.saturating_mul(n_spends as u64);
        let expected_cb = coinbase_amount(pot, n_spends);
        if block.coinbase_amount != expected_cb {
            return Err(EpochError::CoinbaseAmount {
                i,
                got: block.coinbase_amount,
                want: expected_cb,
            });
        }
        let pot_next = pot
            .checked_add(fees)
            .and_then(|v| v.checked_add(pegout_fees))
            .and_then(|v| v.checked_add(pegin_fees))
            .and_then(|v| v.checked_sub(expected_cb))
            .ok_or(EpochError::Overflow { i })?;
        if block.pot_after != pot_next {
            return Err(EpochError::PotMismatch {
                i,
                got: block.pot_after,
                want: pot_next,
            });
        }
        // Conservation (I1-extended): system total changes by pegin − pegout.
        let shielded_next = shielded
            .checked_add(expected_cb)
            .and_then(|v| v.checked_add(pegin_inflow.checked_sub(pegin_fees)?))
            .and_then(|v| v.checked_sub(fees))
            .and_then(|v| v.checked_sub(burn_total))
            .ok_or(EpochError::ConservationViolated { i })?;
        let lhs = shielded_next
            .checked_add(pot_next)
            .ok_or(EpochError::Overflow { i })?;
        let rhs = shielded
            .checked_add(pot)
            .and_then(|v| v.checked_add(pegin_inflow))
            .and_then(|v| v.checked_sub(pegout_outflow))
            .ok_or(EpochError::ConservationViolated { i })?;
        if lhs != rhs {
            return Err(EpochError::ConservationViolated { i });
        }

        // ---- coinbase commitment (bound to block_id = H(height ‖ prev_root)) ----
        let bid = block_id(block.height, &block.prev_root);
        let expected_cm = coinbase_cm_expected(&block.miner_owner, block.coinbase_amount, &bid);
        if expected_cm != block.coinbase_cm {
            return Err(EpochError::CoinbaseCm { i });
        }

        // ---- re-derive appended leaves in consensus order + transition ----
        // Order: tx/peg-out outputs (cm0, cm1), peg-in mints, coinbase.
        for s in block.spends_in_order() {
            let _ = running.append(s.cm0);
            let _ = running.append(s.cm1);
        }
        for cm in &pegin_cms {
            let _ = running.append(*cm);
        }
        let _ = running.append(block.coinbase_cm);

        // The re-derived leaves ARE the epoch: new frontier root must equal the
        // block's committed state_root (welds the value chain to the header id).
        if running.root() != block.state_root {
            return Err(EpochError::StateRootMismatch { i });
        }
        recent_roots.push(block.state_root);
        pot = pot_next;
        shielded = shielded_next;
    }

    let new_root = running.root();
    let tip_id_new = header_id(cid, w.blocks.last().expect("non-empty"));

    // ---- pegout_delay maturity (in-guest) ----
    for (j, (_nf, h)) in pegout_records.iter().enumerate() {
        if tip_height < h.saturating_add(PEGOUT_DELAY) {
            return Err(EpochError::NotMatured {
                j,
                tip: tip_height,
                h: *h,
            });
        }
    }

    // ---- the digest bind: re-derived suffix == recursion root's digest ----
    if all_spends.is_empty() {
        // A suffix with no spends still binds an (empty) statement; but Stage-T
        // settlement requires ≥1 withdrawal, so this cannot be reached via a
        // real settlement — guard anyway.
        return Err(EpochError::SpendDigestMismatch);
    }
    if epoch_spend_root(&all_spends) != w.spend_root_digest {
        return Err(EpochError::SpendDigestMismatch);
    }

    // ---- E3 (F6c): chain the settled set over EVERY nullifier of every spend ----
    // Both `nf0` AND `nf1` of every suffix spend (plain txs and peg-outs) are
    // inserted into R6, non-membership-then-insert, in `all_spends` order (nf0
    // before nf1 per spend). The old burn-`nf0`-only form (design §4.3 F6c) was
    // UNSOUND for real value: an attacker who genuinely owns a note could spend
    // it as a plain tx in settlement N (its nullifier never entered R6), then
    // re-spend it as a peg-out burn in a later fabricated suffix — extracting the
    // note's value twice. Recording the full nullifier set closes that
    // cross-settlement replay. `seen_nf` already proved suffix-internal
    // distinctness, so these inserts never self-collide within the suffix.
    let expected_paths = all_spends
        .len()
        .checked_mul(2)
        .ok_or(EpochError::Overflow { i: 0 })?;
    if w.settled_paths.len() != expected_paths {
        return Err(EpochError::SettledPathCount {
            got: w.settled_paths.len(),
            want: expected_paths,
        });
    }
    let mut settled_root = w.settled_root_in;
    let mut path_iter = w.settled_paths.iter();
    for (j, s) in all_spends.iter().enumerate() {
        for nf in [&s.nf0, &s.nf1] {
            let path = path_iter.next().expect("path count checked above");
            settled_root = settled::verify_insert(&settled_root, nf, path)
                .map_err(|_| EpochError::AlreadySettled { j })?;
        }
    }

    Ok(EpochResult {
        prev_root,
        new_root,
        settled_root_out: settled_root,
        tip_id_new,
        pot_after: pot,
        shielded_after: shielded,
        withdrawals,
    })
}
