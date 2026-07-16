//! Real-work fork choice over the validated Aegis block tree
//! (merge-mining.md §5/§6/§7 — M2b).
//!
//! This module turns aux-PoW shares ([`ValidShare`], M2a) plus block
//! bodies into a canonical chain:
//!
//! - **Validated tree.** Every block whose body passed
//!   [`Chain::try_extend`] against its parent's post-state AND whose
//!   work is proven by a verified share is a tree node carrying
//!   `W = W(parent) + decode_compact_bits(sc_nbits)` — real aux-PoW
//!   work, nothing else.
//! - **Pending map (§6).** A share whose block body is not yet
//!   validated contributes *known but inactive* weight. Availability is
//!   a MONOTONE input: "no body yet" is never a verdict, only "not
//!   currently a candidate"; a withheld body delays a branch, it never
//!   stalls the node.
//! - **Canonical tip (§5)** = argmax cumulative `W` over validated
//!   nodes. Ties break objectively: at the fork point, the branch whose
//!   distinguishing block has the earliest Ergo-committed share (lowest
//!   Ergo height across the shares seen for it), then the lex-smaller
//!   block id — order-independent given the same share/body set, so
//!   nodes fed the same inputs in any order converge. (merge-mining.md
//!   §5 previously said "first-seen" for ties; first-seen is subjective
//!   and breaks convergence, so this module implements the objective
//!   rule and the doc was corrected to match.) NOTE (review NIT): the
//!   ONLY residual order-dependence is two nodes holding *different
//!   witness sets* for one block (different `min` Ergo height) — this is
//!   transient and self-heals as Ergo-committed shares are public and
//!   propagate (the peg's `NotCaughtUp` assumption); it can shift a live
//!   tip but NEVER a `is_final` verdict (equal-W ties never finalize).
//! - **Reorg mechanics** reuse [`Chain`] unchanged: the single linear
//!   `Chain` is a *materialization cursor* into the tree — switching
//!   branches rolls back through the undo ring
//!   ([`Chain::rollback_tip`], ≤ [`STATE_RETENTION_BLOCKS`]) and
//!   re-extends along the target path; past the ring it rebuilds from
//!   genesis by replaying stored blocks through `try_extend`, the
//!   exact `store.rs` discipline.
//! - **Dead verdicts (§5).** A body that fails validation on grounds
//!   committed by the block id (header rules, DAA, state transition,
//!   transfer proofs) is PERMANENTLY invalid, along with every
//!   descendant; its share weight never activates and cannot be
//!   resurrected. Failures NOT committed by the id — wall-clock future
//!   drift, body bytes that don't authenticate against the header, a
//!   malleable coinbase `MintProof` (only its `cm` is id-committed via
//!   `reward_claim`) — never poison the id: the body is dropped and a
//!   correct body can still arrive later.
//! - **Peg finality (§7).** [`MmForkChoice::is_final`] gates
//!   irreversible external action: the target's branch weight at the
//!   last Ergo-settled anchor (`W_settled`) must lead the best possible
//!   competitor by `l_final`, where the competitor bound counts the
//!   best validated fork base **plus every pending/unavailable share as
//!   hostile**. A later body reveal was therefore pre-charged and can
//!   never reorg what `is_final` approved.
//!
//! Inputs are DATA, never instructions: shares must come from
//! [`crate::auxpow::verify_share`] (which recomputes everything from
//! presented bytes) and bodies are self-authenticated against their id
//! here before any validation.
//!
//! Wired into the node loop by M6c: [`crate::node`] feeds this module
//! from the anchor watcher, the seed schedule, and the dev producer.
//! It remains a pure, deterministic structure — all I/O lives in its
//! callers.

use std::collections::BTreeMap;

use aegis_crypto::note::note_cm_bytes;
use aegis_spec::Network;
use ergo_ser::difficulty::decode_compact_bits;
use num_bigint::BigUint;

use crate::auxpow::ValidShare;
use crate::block::{Block, BlockBody};
use crate::chain::{Chain, ExtendError, PowMode, ProofMode};
use crate::genesis::{genesis_header, EMPTY_REWARD_CLAIM};
use crate::header::Header;

/// Aegis block id (header id).
type Id = [u8; 32];

/// One validated tree node: the full block (kept for branch replay),
/// linkage, and its real-work weight.
#[derive(Debug)]
struct BlockNode {
    block: Block,
    parent: Id,
    height: u64,
    /// Cumulative real work `W`: parent's `W` +
    /// `decode_compact_bits(sc_nbits)` (merge-mining.md §3/§5).
    cumulative_work: BigUint,
    /// Lowest Ergo height across the verified shares seen for this
    /// block — the objective tie-break key (earliest Ergo-committed
    /// share). Genesis carries 0 but is never a distinguishing block.
    ergo_height: u32,
}

/// A share whose body is not yet validated: weight known, inactive.
#[derive(Debug)]
struct PendingShare {
    work: BigUint,
    ergo_height: u32,
}

/// Outcome of [`MmForkChoice::ingest_share`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareIngest {
    /// Weight recorded; the block is not yet a fork-choice candidate
    /// (body missing, parent missing, or body previously dropped).
    Pending,
    /// The block is already validated (or the share is a duplicate) —
    /// weight counted once, nothing new activated.
    Known,
    /// The id carries a permanent dead verdict; this weight can never
    /// activate.
    Dead,
    /// The share completed a (share, body, parent) triple: `activated`
    /// blocks (it and any waiting descendants) joined the tree.
    Activated { activated: usize },
}

/// Outcome of [`MmForkChoice::ingest_body`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyIngest {
    /// `activated` blocks (this one and any waiting descendants)
    /// joined the validated tree.
    Activated { activated: usize },
    /// Body stashed; its weight is unproven until a share arrives.
    AwaitingShare,
    /// Body + share present, but the parent is not validated yet
    /// (orphan buffer — monotone, activates when the parent lands).
    AwaitingParent,
    /// The block is already in the validated tree.
    AlreadyValidated,
    /// The id (or its parent chain) carries a permanent dead verdict.
    Dead,
    /// The bytes do not authenticate against the block id (`tx_root` /
    /// `reward_claim` mismatch): wrong body, NOT an invalid block —
    /// dropped without poisoning the id.
    NotSelfAuthenticating,
    /// Validation failed on grounds not committed by the id (e.g.
    /// wall-clock future drift, malleable coinbase proof): body
    /// dropped, id stays clean, a correct/later retry can succeed.
    RejectedTransient,
}

/// The validated-block tree + pending weight + finality accounting.
///
/// The embedded [`Chain`] always materializes the path genesis → the
/// current canonical tip (post-state queryable via [`Self::chain`]);
/// during ingestion it temporarily cursors onto side branches to give
/// `try_extend` the right parent post-state, and every public call
/// leaves it back on the canonical branch.
#[derive(Debug)]
pub struct MmForkChoice {
    network: Network,
    pow_mode: PowMode,
    proof_mode: ProofMode,
    /// Materialization cursor: state of the branch `materialized` tips.
    chain: Chain,
    /// Tip currently materialized in `chain`.
    materialized: Id,
    /// Canonical tip per fork choice (== `materialized` between calls).
    canonical: Id,
    genesis: Id,
    nodes: BTreeMap<Id, BlockNode>,
    pending: BTreeMap<Id, PendingShare>,
    /// Self-authenticated bodies waiting for share/parent (orphan
    /// buffer).
    stashed: BTreeMap<Id, Block>,
    /// Permanent dead verdicts: id → reason (§5 dead branch prefix).
    dead: BTreeMap<Id, String>,
    /// Ergo-inclusion anchors: id → lowest Ergo height whose chain
    /// carries this block's commitment (fed by the anchor watcher; the
    /// Ergo-side `check_inclusion` verification is the caller's job).
    anchors: BTreeMap<Id, u32>,
}

impl MmForkChoice {
    /// A fresh tree holding only the network's genesis (weight 0 — a
    /// shared constant offset carries no fork-choice information).
    pub fn new(network: Network, pow_mode: PowMode, proof_mode: ProofMode) -> Self {
        let chain = Chain::new(network, pow_mode, proof_mode);
        let header = genesis_header(network);
        let genesis = header.id();
        let mut nodes = BTreeMap::new();
        nodes.insert(
            genesis,
            BlockNode {
                block: Block {
                    header,
                    body: BlockBody::default(),
                    coinbase: None,
                },
                parent: [0u8; 32],
                height: 0,
                cumulative_work: BigUint::ZERO,
                ergo_height: 0,
            },
        );
        MmForkChoice {
            network,
            pow_mode,
            proof_mode,
            chain,
            materialized: genesis,
            canonical: genesis,
            genesis,
            nodes,
            pending: BTreeMap::new(),
            stashed: BTreeMap::new(),
            dead: BTreeMap::new(),
            anchors: BTreeMap::new(),
        }
    }

    /// Ingest a verified aux-PoW share (MUST come from
    /// [`crate::auxpow::verify_share`]). Monotone: weight for an
    /// unvalidated block only ever accumulates in the pending map; a
    /// duplicate share for a known block is counted once (only its
    /// Ergo height can improve the tie-break key).
    pub fn ingest_share(&mut self, share: &ValidShare, now_ms: u64) -> ShareIngest {
        let id = share.aegis_id;
        if self.dead.contains_key(&id) {
            return ShareIngest::Dead;
        }
        if let Some(node) = self.nodes.get_mut(&id) {
            if share.ergo_height < node.ergo_height {
                node.ergo_height = share.ergo_height;
                // An earlier Ergo-committed share can flip an equal-W tie.
                self.refresh_canonical();
            }
            return ShareIngest::Known;
        }
        let entry = self.pending.entry(id).or_insert_with(|| PendingShare {
            work: share.work.clone(),
            ergo_height: share.ergo_height,
        });
        if share.ergo_height < entry.ergo_height {
            entry.ergo_height = share.ergo_height;
        }
        let activated = self.activate_ready_from(id, now_ms);
        self.refresh_canonical();
        if activated > 0 {
            ShareIngest::Activated { activated }
        } else if self.dead.contains_key(&id) {
            ShareIngest::Dead
        } else {
            ShareIngest::Pending
        }
    }

    /// Ingest a block body (DATA from gossip in M6; fed directly in
    /// tests). The body is self-authenticated against its id, then
    /// validated via [`Chain::try_extend`] once its share and validated
    /// parent are both present; otherwise it waits in the orphan
    /// buffer. `now_ms` is the validator's wall clock (future-drift
    /// bound only — every other check is deterministic).
    pub fn ingest_body(&mut self, block: Block, now_ms: u64) -> BodyIngest {
        let id = block.id();
        if self.nodes.contains_key(&id) {
            return BodyIngest::AlreadyValidated;
        }
        if self.dead.contains_key(&id) {
            return BodyIngest::Dead;
        }
        // Self-authentication (§6: bodies are self-authenticating
        // against the committed id). A mismatch means these BYTES are
        // not the block's body — never a verdict about the block.
        if block.header.tx_root != block.body.tx_root() {
            return BodyIngest::NotSelfAuthenticating;
        }
        let claim_ok = match &block.coinbase {
            None => block.header.reward_claim == EMPTY_REWARD_CLAIM,
            Some(proof) => block.header.reward_claim == note_cm_bytes(&proof.cm),
        };
        if !claim_ok {
            return BodyIngest::NotSelfAuthenticating;
        }
        if self.dead.contains_key(&block.header.prev_id) {
            // Dead branch prefix (§5): descendants of an invalid block
            // are permanently invalid.
            self.mark_dead(id, "descends from a dead block".to_string());
            return BodyIngest::Dead;
        }
        self.stashed.entry(id).or_insert(block);
        let activated = self.activate_ready_from(id, now_ms);
        self.refresh_canonical();
        if activated > 0 {
            BodyIngest::Activated { activated }
        } else if self.dead.contains_key(&id) {
            BodyIngest::Dead
        } else if !self.stashed.contains_key(&id) {
            BodyIngest::RejectedTransient
        } else if self.pending.contains_key(&id) {
            BodyIngest::AwaitingParent
        } else {
            BodyIngest::AwaitingShare
        }
    }

    /// Record that `aegis_id`'s commitment is carried by the Ergo chain
    /// at `ergo_inclusion_height` (an anchor, merge-mining.md §7). The
    /// caller must have verified the inclusion against its own Ergo
    /// follower (`pegmint_steps::check_inclusion` discipline); this
    /// module only does the weight accounting. Keeps the lowest height.
    pub fn record_anchor(&mut self, aegis_id: Id, ergo_inclusion_height: u32) {
        let entry = self
            .anchors
            .entry(aegis_id)
            .or_insert(ergo_inclusion_height);
        if ergo_inclusion_height < *entry {
            *entry = ergo_inclusion_height;
        }
    }

    /// Peg-finality check (merge-mining.md §7, count-pending-hostile).
    ///
    /// `true` iff `aegis_id` is on the canonical branch, inside the
    /// Ergo-settled prefix (at or below the highest canonical anchor
    /// whose inclusion height ≤ `settled_ergo_height`, the follower's
    /// `settled_reference` height), and
    /// `W_settled − W_max_competing ≥ l_final`, where `W_max_competing`
    /// is the heaviest validated node a hostile branch could fork from
    /// (any node not descending through `aegis_id`) **plus every
    /// pending/unavailable share's weight counted as hostile**. A later
    /// reveal of pending weight can therefore never reorg a block this
    /// approved: revealed branches were already charged in full.
    ///
    /// **Caller contract (review P2):** soundness assumes shares and
    /// anchors are fed from a *single caught-up* Ergo follower, so that
    /// `pending` covers ALL Ergo-committed hidden weight at inclusion
    /// height ≤ `settled_ergo_height`. A caller that records an anchor
    /// without first ingesting the shares committed at/below that Ergo
    /// height could get a premature `true` — the same "must be caught up
    /// to judge" precondition the peg's `NotCaughtUp` path enforces. Pass
    /// `settled_ergo_height = Follower::settled_reference().height`.
    pub fn is_final(&self, aegis_id: &Id, l_final: &BigUint, settled_ergo_height: u32) -> bool {
        if !self.nodes.contains_key(aegis_id) {
            return false;
        }
        if !self.is_ancestor_or_eq(aegis_id, &self.canonical) {
            return false;
        }
        // Highest Ergo-settled anchor on the canonical branch.
        let canonical_path = self.path_ids(self.canonical);
        let settled = canonical_path.iter().rev().find(|id| {
            self.anchors
                .get(*id)
                .is_some_and(|h| *h <= settled_ergo_height)
        });
        let Some(settled) = settled else {
            return false; // no Ergo-grade weight at all
        };
        // The target must sit under the settled anchor: its inclusion
        // is then Ergo-grade, not merely Aegis-grade.
        if !self.is_ancestor_or_eq(aegis_id, settled) {
            return false;
        }
        let w_settled = &self.nodes[settled].cumulative_work;
        // Hostile bound: best validated fork base outside the target's
        // subtree (a hidden branch can fork from any validated block
        // below the target, including its own ancestors)...
        let mut hostile = BigUint::ZERO;
        for (id, node) in &self.nodes {
            if !self.is_ancestor_or_eq(aegis_id, id) && node.cumulative_work > hostile {
                hostile = node.cumulative_work.clone();
            }
        }
        // ...plus EVERY pending share counted as the attacker's.
        hostile += self.pending_hostile_work();
        *w_settled >= hostile + l_final
    }

    /// Canonical tip id (heaviest validated real work, §5).
    pub fn canonical_tip_id(&self) -> Id {
        self.canonical
    }

    /// Canonical tip header.
    pub fn canonical_tip(&self) -> &Header {
        &self.nodes[&self.canonical].block.header
    }

    /// The canonical branch's materialized chain (post-state access).
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    /// Cumulative validated work of a tree node.
    pub fn cumulative_work(&self, id: &Id) -> Option<&BigUint> {
        self.nodes.get(id).map(|n| &n.cumulative_work)
    }

    /// `(timestamp_ms, sc_nbits)` of the validated chain genesis →
    /// `tip_id`, oldest first — exactly the [`crate::daa::next_nbits`]
    /// view for a CHILD of `tip_id` (what
    /// [`crate::auxpow::ShareContext::daa_view`] wants when verifying a
    /// share whose Aegis header has `prev_id == tip_id`). `None` when
    /// `tip_id` is not a validated tree node — the share's DAA
    /// expectation is then undecidable until the parent chain lands.
    pub fn daa_view(&self, tip_id: &Id) -> Option<Vec<(u64, u32)>> {
        if !self.nodes.contains_key(tip_id) {
            return None;
        }
        Some(
            self.path_ids(*tip_id)
                .into_iter()
                .map(|id| {
                    let h = &self.nodes[&id].block.header;
                    (h.timestamp_ms, h.sc_nbits)
                })
                .collect(),
        )
    }

    /// Total weight of shares whose blocks are not fork-choice
    /// candidates yet — the §7 hostile-pending term.
    pub fn pending_hostile_work(&self) -> BigUint {
        self.pending
            .values()
            .fold(BigUint::ZERO, |acc, p| acc + &p.work)
    }

    /// Is this block in the validated tree?
    pub fn is_validated(&self, id: &Id) -> bool {
        self.nodes.contains_key(id)
    }

    /// Is this id share-known but not yet validated?
    pub fn is_pending(&self, id: &Id) -> bool {
        self.pending.contains_key(id)
    }

    /// Does this id carry a permanent dead verdict?
    pub fn is_dead(&self, id: &Id) -> bool {
        self.dead.contains_key(id)
    }

    /// The dead verdict's reason, if any.
    pub fn dead_reason(&self, id: &Id) -> Option<&str> {
        self.dead.get(id).map(String::as_str)
    }

    // ----- internals -----

    /// Try to activate `start` and, on success, every stashed
    /// descendant that becomes ready. Returns how many blocks joined
    /// the tree. Leaves the materialization cursor wherever the last
    /// validation put it — callers must `refresh_canonical` after.
    fn activate_ready_from(&mut self, start: Id, now_ms: u64) -> usize {
        let mut activated = 0;
        let mut queue = vec![start];
        while let Some(id) = queue.pop() {
            if !self.try_activate(id, now_ms) {
                continue;
            }
            activated += 1;
            // Children waiting on this parent (deterministic order via
            // the BTreeMap; sibling activations are independent).
            queue.extend(
                self.stashed
                    .iter()
                    .filter(|(_, b)| b.header.prev_id == id)
                    .map(|(child, _)| *child),
            );
        }
        activated
    }

    /// Validate one stashed block against its parent's post-state.
    /// Returns true iff it joined the tree.
    fn try_activate(&mut self, id: Id, now_ms: u64) -> bool {
        let Some(block) = self.stashed.get(&id) else {
            return false;
        };
        let Some(share) = self.pending.get(&id) else {
            return false; // weight unproven — never a candidate
        };
        let parent = block.header.prev_id;
        if !self.nodes.contains_key(&parent) {
            return false; // orphan — waits for the parent
        }
        let ergo_height = share.ergo_height;
        let block = block.clone();
        self.switch_to(parent);
        match self.chain.try_extend(block.clone(), now_ms) {
            Ok(()) => {
                self.materialized = id;
                let work = decode_compact_bits(block.header.sc_nbits);
                let cumulative_work = &self.nodes[&parent].cumulative_work + work;
                let height = block.header.height;
                self.nodes.insert(
                    id,
                    BlockNode {
                        block,
                        parent,
                        height,
                        cumulative_work,
                        ergo_height,
                    },
                );
                self.pending.remove(&id);
                self.stashed.remove(&id);
                true
            }
            Err(err) if verdict_is_permanent(&err) => {
                // Same bytes, same pre-state, same verdict on every
                // node (§5): the block is invalid, forever, and so is
                // every descendant. Its weight never activates.
                self.mark_dead(id, err.to_string());
                false
            }
            Err(_) => {
                // Not committed by the id (wall clock / malleable
                // coinbase proof / wrong bytes): drop the body only —
                // the share stays pending, a good body can still land.
                self.stashed.remove(&id);
                false
            }
        }
    }

    /// Permanently kill `id` and every stashed descendant.
    fn mark_dead(&mut self, id: Id, reason: String) {
        let mut work = vec![(id, reason)];
        while let Some((id, reason)) = work.pop() {
            self.pending.remove(&id);
            self.stashed.remove(&id);
            self.dead.insert(id, reason);
            work.extend(
                self.stashed
                    .iter()
                    .filter(|(_, b)| b.header.prev_id == id)
                    .map(|(child, _)| {
                        (
                            *child,
                            format!("descends from dead block {}", hex::encode(id)),
                        )
                    }),
            );
        }
    }

    /// Re-run fork choice over the validated tree and re-materialize
    /// the winner (§5). Total order: cumulative work, then the
    /// objective tie-break — so the result depends only on the
    /// share/body SET, never on arrival order.
    fn refresh_canonical(&mut self) {
        let mut best = self.genesis;
        for id in self.nodes.keys() {
            if self.preferred(*id, best) {
                best = *id;
            }
        }
        self.canonical = best;
        if self.materialized != best {
            self.switch_to(best);
        }
        debug_assert_eq!(self.chain.tip().id(), self.canonical);
    }

    /// Strict "a beats b" over validated nodes.
    fn preferred(&self, a: Id, b: Id) -> bool {
        use std::cmp::Ordering;
        if a == b {
            return false;
        }
        let (na, nb) = (&self.nodes[&a], &self.nodes[&b]);
        match na.cumulative_work.cmp(&nb.cumulative_work) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => {
                // Equal W (only possible across a fork with work > 0):
                // compare the fork point's distinguishing children by
                // (earliest Ergo-committed share, lex-smaller id).
                let pa = self.path_ids(a);
                let pb = self.path_ids(b);
                let mut i = 0;
                while i < pa.len() && i < pb.len() && pa[i] == pb[i] {
                    i += 1;
                }
                if i == pa.len() {
                    return false; // a is b's ancestor — prefer the deeper b
                }
                if i == pb.len() {
                    return true;
                }
                let (da, db) = (pa[i], pb[i]);
                (self.nodes[&da].ergo_height, da) < (self.nodes[&db].ergo_height, db)
            }
        }
    }

    /// Ids on the path genesis → `id` (inclusive), root first.
    fn path_ids(&self, id: Id) -> Vec<Id> {
        let mut path = vec![id];
        let mut cur = id;
        while let Some(node) = self.nodes.get(&cur) {
            if node.height == 0 {
                break;
            }
            cur = node.parent;
            path.push(cur);
        }
        path.reverse();
        path
    }

    /// Is `a` an ancestor of (or equal to) `d` in the validated tree?
    fn is_ancestor_or_eq(&self, a: &Id, d: &Id) -> bool {
        let target_height = self.nodes[a].height;
        let mut cur = *d;
        loop {
            if cur == *a {
                return true;
            }
            let node = &self.nodes[&cur];
            if node.height <= target_height {
                return false;
            }
            cur = node.parent;
        }
    }

    /// Re-materialize the chain cursor onto `target` (a validated
    /// node): roll back to the fork point through the undo ring, then
    /// re-extend along the target path. If the fork point is beyond
    /// the ring's retention, rebuild from genesis by replaying the
    /// stored blocks — the `store.rs` replay discipline; either way
    /// every block re-passes `try_extend` (pinned to its own timestamp,
    /// exactly like `load_chain`).
    fn switch_to(&mut self, target: Id) {
        if self.materialized == target {
            return;
        }
        let target_path = self.path_ids(target);
        let current_path = self.path_ids(self.materialized);
        let mut fork = 0;
        while fork < target_path.len()
            && fork < current_path.len()
            && target_path[fork] == current_path[fork]
        {
            fork += 1;
        }
        let mut rolled_back = true;
        for _ in fork..current_path.len() {
            if !self.chain.rollback_tip() {
                rolled_back = false;
                break;
            }
        }
        let replay_from = if rolled_back {
            fork
        } else {
            // Fork point deeper than the undo ring: full rebuild.
            self.chain = Chain::new(self.network, self.pow_mode, self.proof_mode);
            1 // skip genesis, which Chain::new already holds
        };
        for id in &target_path[replay_from..] {
            let block = self.nodes[id].block.clone();
            let pinned_now = block.header.timestamp_ms;
            self.chain
                .try_extend(block, pinned_now)
                .expect("re-extending a previously validated branch must succeed");
        }
        self.materialized = target;
    }
}

/// Is this validation failure committed by the block id (permanent —
/// same bytes, same pre-state, same verdict everywhere), or could a
/// different wall clock / different body bytes for the same id succeed
/// (transient — must NOT poison the id)?
fn verdict_is_permanent(err: &ExtendError) -> bool {
    !matches!(
        err,
        // Wall-clock dependent: valid later.
        ExtendError::TimestampTooFarInFuture { .. }
            // Body bytes don't match the id's commitments (pre-checked
            // by self-authentication; defensive here).
            | ExtendError::TxRootMismatch { .. }
            | ExtendError::RewardClaimMismatch
            // Only the coinbase note's cm is id-committed (via
            // reward_claim) — the MintProof itself is malleable, so a
            // failing proof may be a forgery around an honest block.
            | ExtendError::CoinbaseMint(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockBody;
    use crate::state::STATE_RETENTION_BLOCKS;
    use crate::tx::testutil::sample_transfer;
    use aegis_spec::NF_BYTES;

    // ----- helpers -----

    const T_MS: u64 = 15_000;
    /// Wall clock far past every test block's timestamp (dev genesis is
    /// 1_760_000_000_000; the longest test branch spans a few hours).
    const NOW: u64 = 1_761_000_000_000;

    fn fc_new() -> MmForkChoice {
        MmForkChoice::new(Network::Dev, PowMode::DevStub, ProofMode::DevStub)
    }

    fn replay_chain(blocks: &[Block]) -> Chain {
        let mut chain = Chain::new(Network::Dev, PowMode::DevStub, ProofMode::DevStub);
        for b in blocks {
            chain
                .try_extend(b.clone(), b.header.timestamp_ms)
                .expect("test branch block replays");
        }
        chain
    }

    /// Produce `n` empty blocks extending `prefix` (which must itself
    /// extend genesis), `spacing_ms` apart. Returns only the new blocks.
    fn extend_branch(prefix: &[Block], n: usize, spacing_ms: u64) -> Vec<Block> {
        let mut chain = replay_chain(prefix);
        let mut out = Vec::with_capacity(n);
        let mut now = chain.tip().timestamp_ms;
        for _ in 0..n {
            now += spacing_ms;
            let block = chain
                .produce_next(BlockBody::default(), now)
                .expect("empty block produces");
            chain
                .try_extend(block.clone(), now)
                .expect("produced block extends");
            out.push(block);
        }
        out
    }

    fn share_for(block: &Block, ergo_height: u32) -> ValidShare {
        ValidShare {
            aegis_id: block.id(),
            work: decode_compact_bits(block.header.sc_nbits),
            ergo_height,
        }
    }

    /// Ingest share + body for every block, parents first.
    fn feed(fc: &mut MmForkChoice, blocks: &[Block], ergo_height: u32) {
        for b in blocks {
            fc.ingest_share(&share_for(b, ergo_height), NOW);
            fc.ingest_body(b.clone(), NOW);
        }
    }

    fn branch_work(blocks: &[Block]) -> BigUint {
        blocks.iter().fold(BigUint::ZERO, |acc, b| {
            acc + decode_compact_bits(b.header.sc_nbits)
        })
    }

    fn transfer_with_nfs(a: u8, b: u8) -> crate::tx::ShieldedTransfer {
        let mut tx = sample_transfer(a);
        tx.nullifiers = [[a; NF_BYTES], [b; NF_BYTES]];
        tx
    }

    // ----- happy path -----

    #[test]
    fn heavier_short_branch_beats_longer_light_branch() {
        // Real-work fork choice, NOT longest-chain: past the LWMA
        // window, a fast branch's difficulty climbs (x4/step) while a
        // slow branch's craters — so fewer blocks can carry more work.
        let heavy = extend_branch(&[], 96, 1); // 1 ms spacing
        let light = extend_branch(&[], 104, 6 * T_MS); // 6T spacing
        assert!(heavy.len() < light.len());
        assert!(
            branch_work(&heavy) > branch_work(&light),
            "construction: short branch must be heavier ({} vs {})",
            branch_work(&heavy),
            branch_work(&light)
        );

        let mut fc = fc_new();
        feed(&mut fc, &light, 10);
        assert_eq!(fc.canonical_tip_id(), light.last().unwrap().id());
        feed(&mut fc, &heavy, 10);
        assert_eq!(
            fc.canonical_tip_id(),
            heavy.last().unwrap().id(),
            "heavier (shorter) branch must win"
        );
        assert_eq!(fc.canonical_tip().height, heavy.len() as u64);
    }

    #[test]
    fn withheld_body_never_stalls_and_reveal_is_monotone() {
        // Branch A fully available; branch B's shares arrive but its
        // bodies are withheld: B is pending, never canonical, and A
        // keeps extending (no stall). The later reveal activates B and
        // flips the tip — same outcome as if B had never been withheld.
        let a = extend_branch(&[], 3, T_MS);
        let b = extend_branch(&[], 5, T_MS + 1); // distinct ids, same work/blk

        let mut fc = fc_new();
        feed(&mut fc, &a[..2], 10);
        for blk in &b {
            assert_eq!(
                fc.ingest_share(&share_for(blk, 10), NOW),
                ShareIngest::Pending
            );
        }
        // Withheld weight is known but inactive.
        assert_eq!(fc.pending_hostile_work(), branch_work(&b));
        assert_eq!(fc.canonical_tip_id(), a[1].id(), "pending never canonical");

        // The available branch keeps producing — no stall.
        fc.ingest_share(&share_for(&a[2], 10), NOW);
        fc.ingest_body(a[2].clone(), NOW);
        assert_eq!(fc.canonical_tip_id(), a[2].id());

        // Reveal: bodies arrive (children first — orphan buffer), the
        // branch activates and wins on weight.
        for blk in b.iter().rev() {
            fc.ingest_body(blk.clone(), NOW);
        }
        assert_eq!(fc.canonical_tip_id(), b.last().unwrap().id());
        assert_eq!(fc.pending_hostile_work(), BigUint::ZERO);
    }

    #[test]
    fn equal_work_tie_breaks_by_ergo_height_then_id() {
        // Two one-block branches with identical work: the block whose
        // earliest share sits lower on Ergo wins — in either feed order.
        let a = extend_branch(&[], 1, T_MS);
        let b = extend_branch(&[], 1, T_MS + 1_000);
        assert_eq!(branch_work(&a), branch_work(&b));

        for flip in [false, true] {
            let mut fc = fc_new();
            let (first, second) = if flip { (&b, &a) } else { (&a, &b) };
            feed(&mut fc, first, if flip { 5 } else { 10 });
            feed(&mut fc, second, if flip { 10 } else { 5 });
            assert_eq!(
                fc.canonical_tip_id(),
                b[0].id(),
                "ergo-height 5 must beat 10 regardless of order (flip={flip})"
            );
        }

        // Same Ergo height: lex-smaller id wins (vector).
        let expected = a[0].id().min(b[0].id());
        let mut fc = fc_new();
        feed(&mut fc, &a, 7);
        feed(&mut fc, &b, 7);
        assert_eq!(fc.canonical_tip_id(), expected);

        // A later, earlier-Ergo-committed duplicate share flips the tie
        // deterministically (min over the share set, not first-seen).
        let loser = if expected == a[0].id() { &b } else { &a };
        fc.ingest_share(&share_for(&loser[0], 3), NOW);
        assert_eq!(fc.canonical_tip_id(), loser[0].id());
    }

    #[test]
    fn reorg_to_heavier_branch_rolls_state_back_through_undo_ring() {
        // Branch A carries a transfer (nullifiers in state); heavier
        // empty branch B must flip the tip AND rewind A's state.
        let mut chain = replay_chain(&[]);
        let now1 = chain.tip().timestamp_ms + T_MS;
        let a1 = chain
            .produce_next(
                BlockBody {
                    transfers: vec![transfer_with_nfs(1, 2)],
                    ..Default::default()
                },
                now1,
            )
            .unwrap();
        chain.try_extend(a1.clone(), now1).unwrap();
        let a2 = extend_branch(std::slice::from_ref(&a1), 1, T_MS);
        let b = extend_branch(&[], 3, T_MS + 1_000);

        let mut fc = fc_new();
        feed(&mut fc, std::slice::from_ref(&a1), 10);
        feed(&mut fc, &a2, 10);
        assert!(fc.chain().state().contains(&[1u8; NF_BYTES]));
        assert_eq!(fc.canonical_tip().height, 2);

        feed(&mut fc, &b, 10);
        assert_eq!(fc.canonical_tip_id(), b.last().unwrap().id());
        assert_eq!(fc.canonical_tip().height, 3);
        assert!(
            !fc.chain().state().contains(&[1u8; NF_BYTES]),
            "reorg must rewind branch A's nullifiers"
        );
        // A's blocks stay in the tree (its weight remains comparable).
        assert!(fc.is_validated(&a2[0].id()));
    }

    #[test]
    fn deep_reorg_beyond_undo_ring_rebuilds_by_replay() {
        // Fork point (genesis) deeper than STATE_RETENTION_BLOCKS below
        // the tip: rollback_tip runs dry and the switch must rebuild
        // from genesis by replaying stored blocks (store.rs discipline).
        let depth = STATE_RETENTION_BLOCKS + 5;
        let a = extend_branch(&[], depth, T_MS);
        // Faster spacing: distinct ids, and past the LWMA window the
        // longer branch's per-block difficulty rises, keeping it heavier.
        let b = extend_branch(&[], depth + 5, T_MS - 1_000);
        assert!(branch_work(&b) > branch_work(&a));

        let mut fc = fc_new();
        feed(&mut fc, &a, 10);
        assert_eq!(fc.canonical_tip().height, depth as u64);
        // Feed B bodies children-first so activation happens in ONE
        // cascade once the branch root's body lands (orphan buffer at
        // full depth), then the single tip switch crosses the ring.
        for blk in &b {
            fc.ingest_share(&share_for(blk, 10), NOW);
        }
        for blk in b.iter().rev() {
            fc.ingest_body(blk.clone(), NOW);
        }
        assert_eq!(fc.canonical_tip_id(), b.last().unwrap().id());
        assert_eq!(fc.canonical_tip().height, (depth + 5) as u64);
        assert_eq!(fc.chain().tip().id(), b.last().unwrap().id());
    }

    #[test]
    fn daa_view_walks_validated_chain_and_matches_producer_expectation() {
        // The view for a child of the canonical tip must equal the
        // (timestamp, nbits) sequence Chain::expected_nbits consumes —
        // the share verifier and the body validator must agree on the
        // DAA expectation.
        let blocks = extend_branch(&[], 3, T_MS);
        let mut fc = fc_new();
        feed(&mut fc, &blocks, 10);

        let tip_id = fc.canonical_tip_id();
        let view = fc.daa_view(&tip_id).expect("tip is validated");
        let expected: Vec<(u64, u32)> = std::iter::once(&fc.nodes[&fc.genesis].block)
            .chain(blocks.iter())
            .map(|b| (b.header.timestamp_ms, b.header.sc_nbits))
            .collect();
        assert_eq!(view, expected, "genesis-first, oldest first");
        assert_eq!(
            crate::daa::next_nbits(&crate::daa::DaaParams::for_network(Network::Dev), &view),
            fc.chain().expected_nbits(),
            "share-verifier DAA expectation == producer expectation"
        );
        assert_eq!(fc.daa_view(&[0xAB; 32]), None, "unknown id has no view");
    }

    #[test]
    fn orphan_body_waits_then_activates_when_parent_lands() {
        let blocks = extend_branch(&[], 2, T_MS);
        let (parent, child) = (&blocks[0], &blocks[1]);

        let mut fc = fc_new();
        fc.ingest_share(&share_for(child, 10), NOW);
        assert_eq!(
            fc.ingest_body(child.clone(), NOW),
            BodyIngest::AwaitingParent
        );
        assert_eq!(fc.canonical_tip().height, 0);

        fc.ingest_share(&share_for(parent, 10), NOW);
        let out = fc.ingest_body(parent.clone(), NOW);
        assert_eq!(out, BodyIngest::Activated { activated: 2 });
        assert_eq!(fc.canonical_tip_id(), child.id());
    }

    #[test]
    fn pending_hostile_weight_gates_finality() {
        // §7: W_settled must lead the best competitor by l_final with
        // ALL pending weight counted hostile.
        let a = extend_branch(&[], 10, T_MS);
        let mut fc = fc_new();
        feed(&mut fc, &a, 10);
        let x = a[2].id(); // W(x) = 3 blocks
        let w = |i: usize| branch_work(&a[..i]);

        // Anchor at a[7] (8 blocks deep), Ergo-settled.
        fc.record_anchor(a[7].id(), 500);
        // Not final without a settled anchor.
        assert!(!fc.is_final(&x, &BigUint::ZERO, 499));

        // W_settled = W(a..8); hostile base = W(a..2) (x's parent —
        // the best fork base outside x's subtree); no pending yet.
        let lead = w(8) - w(2);
        assert!(fc.is_final(&x, &lead, 500));
        assert!(!fc.is_final(&x, &(&lead + 1u32), 500));

        // A block ABOVE the settled anchor is never final.
        assert!(!fc.is_final(&a[8].id(), &BigUint::ZERO, 500));

        // Hostile branch: shares only (bodies withheld) — its weight
        // must count against finality even though it never activates.
        let b = extend_branch(&[], 5, T_MS + 1_000);
        for blk in &b {
            fc.ingest_share(&share_for(blk, 20), NOW);
        }
        let pending = branch_work(&b);
        assert!(!fc.is_final(&x, &lead, 500), "pending weight is hostile");
        let lead_with_pending = &lead - &pending;
        assert!(fc.is_final(&x, &lead_with_pending, 500));

        // Late reveal: the hidden branch activates but was pre-charged
        // — it cannot reorg the finalized block.
        for blk in b.iter().rev() {
            fc.ingest_body(blk.clone(), NOW);
        }
        assert_eq!(fc.canonical_tip_id(), a.last().unwrap().id());
        assert!(fc.is_validated(&b.last().unwrap().id()));
        assert!(
            fc.is_final(&x, &lead_with_pending, 500),
            "reveal must not un-finalize"
        );

        // Off-canonical block is never final.
        assert!(!fc.is_final(&b[0].id(), &BigUint::ZERO, 500));
    }

    // ----- round-trips -----

    #[test]
    fn different_ingest_orders_converge_to_same_tip() {
        // THE monotone-convergence property: nodes fed the same
        // share/body SET in different orders end at the same canonical
        // tip, the same validated tree, and the same finality verdicts.
        let prefix = extend_branch(&[], 3, T_MS);
        let a = extend_branch(&prefix, 2, T_MS);
        let b = extend_branch(&prefix, 3, T_MS + 1_000);
        let c = extend_branch(&[prefix[0].clone()], 1, T_MS + 2_000);
        let mut all: Vec<Block> = Vec::new();
        all.extend(prefix.iter().cloned());
        all.extend(a.iter().cloned());
        all.extend(b.iter().cloned());
        all.extend(c.iter().cloned());
        // One block's body is withheld everywhere (share only): it must
        // be pending — never canonical — on every node.
        let withheld = extend_branch(
            &prefix
                .iter()
                .chain(b.iter())
                .cloned()
                .collect::<Vec<Block>>(),
            1,
            T_MS,
        );

        #[derive(Clone)]
        enum Ev {
            Share(ValidShare),
            Body(Box<Block>),
        }
        let mut events: Vec<Ev> = Vec::new();
        for blk in &all {
            events.push(Ev::Share(share_for(blk, 10)));
            events.push(Ev::Body(Box::new(blk.clone())));
        }
        events.push(Ev::Share(share_for(&withheld[0], 10)));

        let run = |order: Vec<Ev>| -> MmForkChoice {
            let mut fc = fc_new();
            for ev in order {
                match ev {
                    Ev::Share(s) => {
                        fc.ingest_share(&s, NOW);
                    }
                    Ev::Body(b) => {
                        fc.ingest_body(*b, NOW);
                    }
                }
            }
            fc
        };
        let forward = run(events.clone());
        let reversed = run(events.iter().rev().cloned().collect());
        let interleaved = run({
            // All bodies (children before parents), then all shares.
            let (mut bodies, mut shares): (Vec<Ev>, Vec<Ev>) = (vec![], vec![]);
            for ev in events.iter().rev().cloned() {
                match ev {
                    Ev::Body(_) => bodies.push(ev),
                    Ev::Share(_) => shares.push(ev),
                }
            }
            bodies.into_iter().chain(shares).collect()
        });

        let expected_tip = b.last().unwrap().id(); // heaviest available
        for (name, fc) in [
            ("forward", &forward),
            ("reversed", &reversed),
            ("interleaved", &interleaved),
        ] {
            assert_eq!(fc.canonical_tip_id(), expected_tip, "{name} tip");
            assert_eq!(
                fc.nodes.keys().collect::<Vec<_>>(),
                forward.nodes.keys().collect::<Vec<_>>(),
                "{name} validated set"
            );
            assert_eq!(
                fc.pending.keys().collect::<Vec<_>>(),
                forward.pending.keys().collect::<Vec<_>>(),
                "{name} pending set"
            );
            assert!(fc.is_pending(&withheld[0].id()), "{name} withheld pending");
            assert_eq!(
                fc.pending_hostile_work(),
                branch_work(&withheld),
                "{name} hostile weight"
            );
            assert_eq!(fc.chain().tip().id(), expected_tip, "{name} chain cursor");
        }
    }

    #[test]
    fn duplicate_shares_and_bodies_count_once() {
        let blocks = extend_branch(&[], 2, T_MS);
        let mut fc = fc_new();
        feed(&mut fc, &blocks, 10);
        let w = fc.cumulative_work(&fc.canonical_tip_id()).unwrap().clone();
        assert_eq!(
            fc.ingest_share(&share_for(&blocks[1], 10), NOW),
            ShareIngest::Known
        );
        assert_eq!(
            fc.ingest_body(blocks[1].clone(), NOW),
            BodyIngest::AlreadyValidated
        );
        assert_eq!(fc.cumulative_work(&fc.canonical_tip_id()).unwrap(), &w);
        assert_eq!(fc.pending_hostile_work(), BigUint::ZERO);
    }

    // ----- error paths -----

    #[test]
    fn invalid_body_gets_permanent_dead_verdict_and_weight_never_counts() {
        // A self-authenticating block whose STATE transition is invalid
        // (in-block double spend): permanent dead verdict; its share
        // weight neither activates nor stays hostile-pending, and no
        // later re-ingestion resurrects it.
        let chain = replay_chain(&[]);
        let now = chain.tip().timestamp_ms + T_MS;
        let bad_body = BlockBody {
            transfers: vec![transfer_with_nfs(1, 1)], // nf duplicated
            ..Default::default()
        };
        let mut header = chain
            .produce_next(BlockBody::default(), now)
            .unwrap()
            .header;
        header.tx_root = bad_body.tx_root(); // self-authenticating
        let bad = Block {
            header,
            body: bad_body,
            coinbase: None,
        };

        let mut fc = fc_new();
        assert_eq!(
            fc.ingest_share(&share_for(&bad, 10), NOW),
            ShareIngest::Pending
        );
        assert!(fc.pending_hostile_work() > BigUint::ZERO);
        assert_eq!(fc.ingest_body(bad.clone(), NOW), BodyIngest::Dead);
        assert!(fc.is_dead(&bad.id()));
        assert!(fc.dead_reason(&bad.id()).unwrap().contains("double spend"));
        assert_eq!(
            fc.pending_hostile_work(),
            BigUint::ZERO,
            "dead weight is not hostile-pending either"
        );
        assert_eq!(fc.canonical_tip().height, 0);

        // No resurrection.
        assert_eq!(fc.ingest_share(&share_for(&bad, 5), NOW), ShareIngest::Dead);
        assert_eq!(fc.ingest_body(bad.clone(), NOW), BodyIngest::Dead);
        assert_eq!(fc.pending_hostile_work(), BigUint::ZERO);
    }

    #[test]
    fn descendant_of_dead_block_dies_with_it() {
        // Craft an invalid parent and a structurally fine child linking
        // to it: the child must inherit the dead verdict (dead branch
        // prefix, §5) whether it arrives before or after the verdict.
        let chain = replay_chain(&[]);
        let now = chain.tip().timestamp_ms + T_MS;
        let bad_body = BlockBody {
            transfers: vec![transfer_with_nfs(2, 2)],
            ..Default::default()
        };
        let mut header = chain
            .produce_next(BlockBody::default(), now)
            .unwrap()
            .header;
        header.tx_root = bad_body.tx_root();
        let bad = Block {
            header: header.clone(),
            body: bad_body,
            coinbase: None,
        };
        let child = Block {
            header: Header {
                prev_id: bad.id(),
                height: 2,
                timestamp_ms: header.timestamp_ms + T_MS,
                ..header
            },
            body: BlockBody::default(),
            coinbase: None,
        };
        let mut child_hdr = child.header.clone();
        child_hdr.tx_root = BlockBody::default().tx_root();
        let child = Block {
            header: child_hdr,
            body: BlockBody::default(),
            coinbase: None,
        };

        // Child arrives FIRST (stashed), then the parent goes dead.
        let mut fc = fc_new();
        fc.ingest_share(&share_for(&child, 10), NOW);
        assert_eq!(
            fc.ingest_body(child.clone(), NOW),
            BodyIngest::AwaitingParent
        );
        fc.ingest_share(&share_for(&bad, 10), NOW);
        assert_eq!(fc.ingest_body(bad.clone(), NOW), BodyIngest::Dead);
        assert!(fc.is_dead(&child.id()), "stashed descendant must die too");

        // Child arrives AFTER the verdict.
        let mut fc = fc_new();
        fc.ingest_share(&share_for(&bad, 10), NOW);
        fc.ingest_body(bad, NOW);
        assert_eq!(fc.ingest_body(child.clone(), NOW), BodyIngest::Dead);
        assert!(fc.is_dead(&child.id()));
    }

    #[test]
    fn tampered_body_bytes_do_not_poison_the_id() {
        // Wrong bytes under a real block's id must be rejected WITHOUT
        // a dead verdict — the correct body must still activate.
        let blocks = extend_branch(&[], 1, T_MS);
        let good = &blocks[0];
        let mut forged = good.clone();
        forged.body.transfers = vec![transfer_with_nfs(9, 8)]; // tx_root now wrong
        forged.header = good.header.clone(); // same id

        let mut fc = fc_new();
        fc.ingest_share(&share_for(good, 10), NOW);
        assert_eq!(
            fc.ingest_body(forged, NOW),
            BodyIngest::NotSelfAuthenticating
        );
        assert!(!fc.is_dead(&good.id()));
        assert!(matches!(
            fc.ingest_body(good.clone(), NOW),
            BodyIngest::Activated { .. }
        ));
        assert_eq!(fc.canonical_tip_id(), good.id());
    }

    #[test]
    fn body_without_share_never_activates() {
        // Weight comes ONLY from aux-PoW: an unshared body is stored
        // but is not a fork-choice candidate until its work is proven.
        let blocks = extend_branch(&[], 1, T_MS);
        let mut fc = fc_new();
        assert_eq!(
            fc.ingest_body(blocks[0].clone(), NOW),
            BodyIngest::AwaitingShare
        );
        assert_eq!(fc.canonical_tip().height, 0);
        assert_eq!(
            fc.ingest_share(&share_for(&blocks[0], 10), NOW),
            ShareIngest::Activated { activated: 1 }
        );
        assert_eq!(fc.canonical_tip_id(), blocks[0].id());
    }

    #[test]
    fn far_future_timestamp_is_transient_not_dead() {
        // A block 2 minutes ahead of the local clock fails the drift
        // bound — a wall-clock verdict, not an id-committed one: no
        // dead verdict, and the same body activates once time passes.
        let blocks = extend_branch(&[], 1, T_MS);
        let block = &blocks[0];
        let early_now = block.header.timestamp_ms - 120_000;

        let mut fc = fc_new();
        fc.ingest_share(&share_for(block, 10), early_now);
        assert_eq!(
            fc.ingest_body(block.clone(), early_now),
            BodyIngest::RejectedTransient
        );
        assert!(!fc.is_dead(&block.id()));
        assert!(fc.is_pending(&block.id()), "share must survive the drop");
        assert!(matches!(
            fc.ingest_body(block.clone(), NOW),
            BodyIngest::Activated { .. }
        ));
        assert_eq!(fc.canonical_tip_id(), block.id());
    }
}
