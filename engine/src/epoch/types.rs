//! Suffix witness types + Stage-T consensus parameters (E1).
//!
//! These mirror the node's consensus fields (`aegis-node/src/hn/state.rs`
//! `HnBlock`/`PegOutTx`/`PegInClaim` and `hn/params.rs`). The guest holds a
//! settler-supplied suffix and re-derives everything from it — the types carry
//! exactly the fields the re-derivation consumes.
//!
//! **Parity (REVIEW ITEM, pre-cut lockstep — D-EV1/D-EV5):** the constants and
//! the header-id encoding here define the object the aux-PoW share commits and
//! the R7 chain binds. The node must produce header ids under the SAME encoding
//! (this crate is guest-visible; `aegis-node` is not) or an honest block fails
//! the guest's re-derivation. Locking node↔guest parity is the E0/E1 cut gate.

use crate::poseidon::Digest;

// ---- Stage-T consensus parameters (mirror `hn/params.rs`) ----

/// Flat per-tx fee (base units) — every shielded tx and peg-out pays exactly
/// this (`FLAT_FEE`, params.rs).
pub const FLAT_FEE: u64 = 3;
/// Coinbase base draw per block (`COINBASE_BASE`).
pub const COINBASE_BASE: u64 = 1;
/// Coinbase inclusion bonus per included spend (`COINBASE_PER_TX`).
pub const COINBASE_PER_TX: u64 = 1;
/// Peg fee, both directions: percent of the moved amount, min 1 base unit.
pub const PEG_FEE_PERCENT: u64 = 1;
/// Blocks a burn must age before it is settleable (`pegout_delay`, params.rs).
/// The E1 in-guest enforcement of this is what forces a fabricator to mine a
/// `≥ pegout_delay + 1`-block suffix (design §2.1-E1, the §6 security parameter).
pub const PEGOUT_DELAY: u64 = 10;
/// Anchor-window: a spend's `PUB_ROOT` must be one of the last `ROOT_WINDOW`
/// state-roots along the chain (`engine/wallet/src/chain.rs`).
pub const ROOT_WINDOW: usize = 100;

/// Peg fee for `amount`: `PEG_FEE_PERCENT`% of it, at least 1 base unit.
pub fn peg_fee(amount: u64) -> u64 {
    (amount.saturating_mul(PEG_FEE_PERCENT) / 100).max(1)
}

/// The consensus coinbase amount: `min(pot_parent, base + per_tx × n_spends)`,
/// computed on the PARENT pot (this block's fees credit the pot but cannot fund
/// its own coinbase). Mirror of `HnChainParams::coinbase_amount`.
pub fn coinbase_amount(pot_parent: u64, n_spends: usize) -> u64 {
    COINBASE_BASE
        .saturating_add(COINBASE_PER_TX.saturating_mul(n_spends as u64))
        .min(pot_parent)
}

/// The spend-proof public values the monolith `SpendAir` exposes
/// (`PUB_ROOT/NF0/NF1/CMO0/CMO1/FEE`, `spend/monolith.rs`). Surfaced to the
/// guest through the recursion digest channel and bound by `digest.rs`; the
/// guest re-derives leaves (`cm0`/`cm1`) and replays economics from them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendPublics {
    /// The anchor root this spend proved note membership against (`PUB_ROOT`).
    pub root: Digest,
    pub nf0: Digest,
    pub nf1: Digest,
    pub cm0: Digest,
    pub cm1: Digest,
    /// The fee this spend paid (`PUB_FEE`); consensus requires `== FLAT_FEE`.
    pub fee: u64,
}

/// A peg-out: a full spend whose `cm0` is the deterministic burn note, plus the
/// public withdrawal it funds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PegOut {
    pub spend: SpendPublics,
    /// USE released on Ergo.
    pub amount: u64,
    /// The Ergo recipient's ErgoTree (proposition) bytes.
    pub recipient_prop: Vec<u8>,
}

/// A peg-in claim minted in this block (`amount` deposited; mint = `amount −
/// peg_fee`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PegIn {
    pub box_id: [u8; 32],
    pub dest_owner: Digest,
    pub amount: u64,
}

/// One hn block of a settlement suffix — the guest's view. Mirrors `HnBlock`'s
/// consensus-relevant fields; the aux-PoW witness and anchor (E2/E4) travel
/// alongside in [`crate::epoch::EpochWitness`], not here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuffixBlock {
    pub height: u64,
    pub prev_header_id: [u8; 32],
    pub prev_root: Digest,
    pub state_root: Digest,
    pub timestamp_ms: u64,
    pub sc_nbits: u32,
    pub txs: Vec<SpendPublics>,
    pub pegouts: Vec<PegOut>,
    pub pegins: Vec<PegIn>,
    pub miner_owner: Digest,
    pub coinbase_amount: u64,
    pub coinbase_cm: Digest,
    /// Always `true` for a settlement suffix (post-genesis, mined); a genesis
    /// allocation block is never inside a settled suffix.
    pub coinbase_is_reward: bool,
    pub pot_after: u64,
    /// The shielded-pool total AFTER this block (header-committed, D-F1 §1.3a).
    /// A NEW header field: `pot_after` already pinned the pot; this pins the
    /// other half of the conservation invariant so that *any* authenticated
    /// header fixes the full value state. F1's seam derives `shielded_before`
    /// from `seam[0].shielded_after`, making the injected-value bound exact.
    pub shielded_after: u64,
}

impl SuffixBlock {
    /// Every spend in consensus order: plain txs first, then peg-out spends.
    /// This is the order leaves are appended and the order the recursion tree
    /// aggregates the suffix spend proofs.
    pub fn spends_in_order(&self) -> impl Iterator<Item = &SpendPublics> {
        self.txs.iter().chain(self.pegouts.iter().map(|p| &p.spend))
    }

    /// Count of fee-paying spends (txs + peg-outs) — the coinbase bonus base.
    pub fn n_spends(&self) -> usize {
        self.txs.len() + self.pegouts.len()
    }
}
