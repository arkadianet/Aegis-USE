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
use super::header_id::{block_id, header_id, header_id_from_fields, SeamHeader};
use super::types::{
    coinbase_amount, peg_fee, SuffixBlock, FLAT_FEE, GENESIS_HEADER_ID, PEGOUT_DELAY, ROOT_WINDOW,
    SEAM_LEN,
};

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
    /// F1 authenticated seam: header-only preimages of the pre-suffix chain,
    /// **newest first**. `seam[0]` is the preimage of the sealed tip `T_prev`
    /// (its id == `tip_id_prev`); each `seam[i].prev_header_id` hash-links to
    /// `seam[i+1]`'s id, back `SEAM_LEN` headers or to `GENESIS_HEADER_ID`. Every
    /// window quantity the verifier needs — `recent_roots`, `pot_before`,
    /// `shielded_before`, `height(T_prev)`, the `(ts, nbits)` DAA history — is
    /// **derived** from this authenticated chain, never witnessed directly (the
    /// old raw `seam_roots`/`pot_before`/`shielded_before` fields are deleted).
    pub seam: Vec<SeamHeader>,
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
    #[error("empty seam (need at least seam[0] = the sealed tip preimage)")]
    EmptySeam,
    #[error("seam[0] id != tip_id_prev (R7): the seam is not the sealed tip")]
    SeamTipMismatch,
    #[error("seam[{i}].prev_header_id != id(seam[{next}]) (seam hash-link broken)", next = i + 1)]
    SeamLinkBroken { i: usize },
    #[error("seam[{i}].height != seam[{next}].height + 1 (seam height chain broken)", next = i + 1)]
    SeamHeightBroken { i: usize },
    #[error("seam neither reaches SEAM_LEN nor terminates at GENESIS_HEADER_ID")]
    SeamNotTerminated,
    #[error("block[0].prev_root != seam[0].state_root (seam↔frontier weld broken)")]
    SeamWeldBroken,
    #[error("block[{i}].height is not continuous with the seam/predecessor (F6a)")]
    HeightDiscontinuity { i: usize },
    #[error("block[{i}].timestamp_ms regressed vs its predecessor/seam (F6f)")]
    TimestampRegressed { i: usize },
    #[error("block[{i}].sc_nbits != LWMA/DAA expectation (F2)")]
    NbitsMismatch { i: usize },
    #[error("block[{i}].shielded_after {got} != recomputed {want}")]
    ShieldedMismatch { i: usize, got: u64, want: u64 },
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
    #[error("settled_paths count {got} != peg-out count {want}")]
    SettledPathCount { got: usize, want: usize },
    #[error("peg-out #{j} nf0 already settled (E3 replay-close)")]
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

    // ---- F1: validate the authenticated seam, then DERIVE the window state ----
    // The seam is settler-supplied bytes, but its authenticity reduces to R7 +
    // Poseidon2 collision-resistance + induction over settlements (design §1.2):
    // seam[0] hashes to the vault's sealed tip id, and each link hashes to its
    // successor, so the whole seam IS the previously-verified chain. Everything
    // downstream (anchor window, pot/shielded before, heights, DAA history) is
    // derived from it — nothing is trusted raw.
    if w.seam.is_empty() {
        return Err(EpochError::EmptySeam);
    }
    let tip = &w.seam[0];
    // (1) seam[0] is the sealed tip's preimage: its id == R7.
    if header_id_from_fields(cid, tip) != w.tip_id_prev {
        return Err(EpochError::SeamTipMismatch);
    }
    // (2)+(4) hash-linked walk backwards; heights decrease by exactly 1.
    for i in 0..w.seam.len() - 1 {
        if w.seam[i].prev_header_id != header_id_from_fields(cid, &w.seam[i + 1]) {
            return Err(EpochError::SeamLinkBroken { i });
        }
        if w.seam[i].height != w.seam[i + 1].height + 1 {
            return Err(EpochError::SeamHeightBroken { i });
        }
    }
    // (3) termination: either a full window, or the last (authenticated) link
    // bottoms out at the pinned genesis sentinel (a young chain).
    let reached_genesis = w.seam.last().expect("non-empty").prev_header_id == GENESIS_HEADER_ID;
    if w.seam.len() != SEAM_LEN && !reached_genesis {
        return Err(EpochError::SeamNotTerminated);
    }

    // Derived — never witnessed.
    let pot_before = tip.pot_after;
    let shielded_before = tip.shielded_after;
    let prev_height = tip.height;

    // Anchor window = the seam's state-roots oldest→newest, mirroring the node's
    // `recent_roots` VecDeque EXACTLY (Q-F1). The node seeds the pre-genesis
    // empty-tree root at height 0 and evicts it once ROOT_WINDOW blocks exist, so
    // it is a window member iff the seam reached genesis; prepend it there, then
    // cap to the last ROOT_WINDOW. The window's newest entry is `tip.state_root`.
    let mut recent_roots: Vec<Digest> = w.seam.iter().rev().map(|h| h.state_root).collect();
    if reached_genesis {
        recent_roots.insert(0, Frontier::new().root());
    }
    if recent_roots.len() > ROOT_WINDOW {
        recent_roots.drain(0..recent_roots.len() - ROOT_WINDOW);
    }

    // ---- frontier / prev_root binding + the seam↔frontier weld ----
    let frontier: Frontier =
        postcard::from_bytes(&w.frontier_bytes).map_err(|_| EpochError::FrontierDecode)?;
    let prev_root = frontier.root();
    if w.blocks[0].prev_root != prev_root {
        return Err(EpochError::PrevRootMismatch);
    }
    // Weld the seam to the frontier: block[0]'s parent root is the tip's state
    // root (the newest authenticated anchor). Costs one equality; closes the gap
    // between "frontier root == R4" and "the seam is that same chain".
    if w.blocks[0].prev_root != tip.state_root {
        return Err(EpochError::SeamWeldBroken);
    }

    // ---- header-id chain seed ----
    if w.blocks[0].prev_header_id != w.tip_id_prev {
        return Err(EpochError::HeaderChainBroken { i: 0 });
    }

    // ---- F2: seed the DAA solve-time view from the AUTHENTICATED seam ----
    #[cfg(feature = "aux-pow")]
    let daa_params = crate::epoch::daa::pinned_daa_params();
    #[cfg(feature = "aux-pow")]
    let mut daa_view: Vec<(u64, u32)> = w
        .seam
        .iter()
        .rev()
        .map(|h| (h.timestamp_ms, h.sc_nbits))
        .collect();

    let mut running = frontier;
    let mut pot = pot_before;
    let mut shielded = shielded_before;
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
        // F6a: heights are continuous with the AUTHENTICATED seam tip (block 0)
        // then +1 per block. This anchors `tip_height`/maturity and (with F2) the
        // DAA bootstrap branch to the settled chain's real height — a fabricator
        // can no longer claim `height < 91` to reset difficulty to the floor.
        let want_height = if i == 0 {
            prev_height + 1
        } else {
            w.blocks[i - 1].height + 1
        };
        if block.height != want_height {
            return Err(EpochError::HeightDiscontinuity { i });
        }
        // F6f: timestamps are non-decreasing along the suffix and across the seam
        // boundary (the only in-guest-defensible clock rule; wall-clock/future
        // bounds are subjective). Bounds what free timestamps buy the LWMA (§2.3).
        let prev_ts = if i == 0 {
            tip.timestamp_ms
        } else {
            w.blocks[i - 1].timestamp_ms
        };
        if block.timestamp_ms < prev_ts {
            return Err(EpochError::TimestampRegressed { i });
        }
        // F2: the block's self-declared difficulty must equal the LWMA/DAA
        // expectation over the authenticated history — the fork-point difficulty
        // is inherited, not reset (design §2.2). E2 (`share.rs`) then checks the
        // PoW clears exactly this DAA-constrained target.
        #[cfg(feature = "aux-pow")]
        {
            let expect = crate::epoch::daa::next_nbits(&daa_params, &daa_view);
            if block.sc_nbits != expect {
                return Err(EpochError::NbitsMismatch { i });
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
        // The block's header-committed `shielded_after` (D-F1 §1.3a) must equal
        // the recomputed post-block total — the same equality the node enforces
        // in `apply_block`. Every authenticated header therefore pins the full
        // value state, and the NEXT settlement's seam reads a correct
        // `shielded_before` from `seam[0].shielded_after`.
        if block.shielded_after != shielded_next {
            return Err(EpochError::ShieldedMismatch {
                i,
                got: block.shielded_after,
                want: shielded_next,
            });
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
        // F2: advance the DAA view exactly as `hn/state.rs` maintains `daa_view`
        // (next_nbits only ever consults the last window+1 entries).
        #[cfg(feature = "aux-pow")]
        daa_view.push((block.timestamp_ms, block.sc_nbits));
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

    // ---- E3: chain the settled-burn set over every burn nf0 ----
    if w.settled_paths.len() != pegout_records.len() {
        return Err(EpochError::SettledPathCount {
            got: w.settled_paths.len(),
            want: pegout_records.len(),
        });
    }
    let mut settled_root = w.settled_root_in;
    for (j, ((nf0, _h), path)) in pegout_records.iter().zip(&w.settled_paths).enumerate() {
        settled_root = settled::verify_insert(&settled_root, nf0, path)
            .map_err(|_| EpochError::AlreadySettled { j })?;
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
