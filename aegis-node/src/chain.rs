//! In-memory block chain: extension rules, shielded state, dev-mode
//! production.
//!
//! Consensus per `consensus.md`: linkage + height (§2), timestamp
//! MTP-11 / +60 s future bound (§4), `sc_nbits` must equal the DAA
//! output (§3), header roots must match the body and post-state (§2/§5a).
//! Two verification gaps stay visible at the type level: PoW witnesses
//! ([`PowMode::DevStub`], lands with the W4 sidecar) and shielded
//! proofs ([`ProofMode::DevStub`], lands with the Phase 3 circuit).

use std::collections::VecDeque;

use aegis_crypto::mint::{prove_mint, verify_mint, MintError};
use aegis_crypto::note::{note_cm_bytes, EvenScalar};
use aegis_spec::Network;
use ark_ec::AffineRepr;
use rand::SeedableRng;

use crate::block::{Block, BlockBody};
use crate::daa::{next_nbits, DaaParams};
use crate::genesis::{genesis_header, EMPTY_REWARD_CLAIM};
use crate::header::Header;
use crate::pegmint::ComparativeAnchor;
use crate::pegmint_steps::{read_pegmint_proof, serialize_pegmint_proof, PegMintProof, PegParams};
use crate::state::{
    expected_coinbase_value, BlockUndo, PegValidation, RewardMode, ShieldedState, StateError,
    STATE_RETENTION_BLOCKS,
};

/// Maximum tolerated future drift of a block timestamp versus the
/// validator's wall clock (consensus.md §4).
pub const MAX_FUTURE_DRIFT_MS: u64 = 60_000;

/// MTP window size (consensus.md §4).
const MTP_WINDOW: usize = 11;

/// PoW verification mode. `DevStub` skips witness verification — the
/// Autolykos commitment path arrives with the MM sidecar (W4). The
/// variant exists so "no PoW check" is a visible configuration, never
/// an implicit default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowMode {
    DevStub,
}

/// Proof verification mode. `DevStub` accepts any proof bytes;
/// `Real` verifies each transfer's `aegis-crypto` proof against the
/// parent-block anchor tree (S4). Typed so "no proof check" is visible
/// configuration (same discipline as [`PowMode`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofMode {
    DevStub,
    Real,
}

/// Why a block was refused as the next one.
#[derive(Debug, thiserror::Error)]
pub enum ExtendError {
    #[error("unsupported header version {0}")]
    UnsupportedVersion(u8),
    #[error("prev_id mismatch: header links {got}, tip is {want}", got = hex::encode(got), want = hex::encode(want))]
    PrevIdMismatch { got: [u8; 32], want: [u8; 32] },
    #[error("height mismatch: got {got}, expected {want}")]
    HeightMismatch { got: u64, want: u64 },
    #[error("timestamp {ts} not strictly after MTP {mtp}")]
    TimestampNotAfterMtp { ts: u64, mtp: u64 },
    #[error("timestamp {ts} more than {MAX_FUTURE_DRIFT_MS}ms ahead of local clock {now}")]
    TimestampTooFarInFuture { ts: u64, now: u64 },
    #[error("sc_nbits {got:#010x} != DAA-expected {want:#010x}")]
    WrongDifficulty { got: u32, want: u32 },
    #[error("tx_root mismatch: header {got}, body {want}", got = hex::encode(got), want = hex::encode(want))]
    TxRootMismatch { got: [u8; 32], want: [u8; 32] },
    #[error("nullifier_digest mismatch: header {got}, state {want}", got = hex::encode(got), want = hex::encode(want))]
    NullifierDigestMismatch { got: [u8; 32], want: [u8; 32] },
    #[error("pot mismatch: header {got}, state {want}")]
    PotMismatch { got: u64, want: u64 },
    #[error("cm_tree_root mismatch: header {got}, state {want}", got = hex::encode(got), want = hex::encode(want))]
    CmTreeRootMismatch { got: [u8; 32], want: [u8; 32] },
    #[error("block has transfers but no notes exist to spend (empty anchor)")]
    NoAnchor,
    #[error("transfer {index}: {source}")]
    Proof {
        index: usize,
        source: crate::proof::ProofError,
    },
    #[error("coinbase mint proof invalid: {0}")]
    CoinbaseMint(#[from] MintError),
    #[error("coinbase note is the identity (unspendable, pot-funded)")]
    ZeroCoinbase,
    #[error("reward_claim mismatch: header does not commit to the block's coinbase")]
    RewardClaimMismatch,
    #[error("peg-mint {index} could not be decoded from the block body")]
    PegMintDecode { index: usize },
    #[error(transparent)]
    State(#[from] StateError),
}

/// The peg-in validation configuration a chain applies to blocks that
/// carry peg-mints: the node's followed Ergo settled view (P1-A) and the
/// peg deploy pins. Absent (`Chain::peg == None`) ⇒ the chain rejects any
/// block that carries peg-mints. The node resolves/refreshes the anchor
/// from its [`crate::ergo_follow::Follower`] as the tip advances (the
/// "followed-anchor seam"); it is owned here so `try_extend`'s signature
/// — called from many sites — stays unchanged.
///
/// ⚠⚠ DO NOT enable peg on a MULTI-NODE network without the anchor-deferral
/// plumbing (peg red-review P1 — load-bearing for soundness). The apply path
/// uses `verify_pegmint` (anchor-supplied), which treats a not-yet-followed
/// inclusion as block-INVALID rather than DEFERRING — so two honest nodes at
/// different Ergo-follow depths would reach DIFFERENT verdicts on the SAME
/// Aegis block = CONSENSUS SPLIT. This is safe today ONLY because `peg == None`
/// (set solely in tests) makes the whole path unreachable on a real node.
/// Before enabling peg anywhere multi-node: resolve the anchor from the node's
/// OWN `Follower` (never from block data) AND defer — not reject — a
/// not-yet-settled mint, against a consensus-agreed anchor.
#[derive(Debug, Clone)]
pub struct PegConfig {
    pub anchor: ComparativeAnchor,
    pub params: PegParams,
}

/// In-memory block chain (linear; fork choice arrives with P2P).
#[derive(Debug)]
pub struct Chain {
    network: Network,
    pow_mode: PowMode,
    proof_mode: ProofMode,
    daa: DaaParams,
    blocks: Vec<Block>,
    state: ShieldedState,
    undo_ring: VecDeque<BlockUndo>,
    /// Peg-in validation config (`None` ⇒ blocks carrying peg-mints are
    /// rejected). Set by the node once it has a followed Ergo view.
    peg: Option<PegConfig>,
}

impl Chain {
    /// A fresh chain holding only the network's genesis block.
    pub fn new(network: Network, pow_mode: PowMode, proof_mode: ProofMode) -> Self {
        let genesis = Block {
            header: genesis_header(network),
            body: BlockBody::default(),
            coinbase: None,
        };
        let daa = DaaParams::for_network(network);
        Chain {
            network,
            pow_mode,
            proof_mode,
            daa,
            blocks: vec![genesis],
            state: ShieldedState::new(),
            undo_ring: VecDeque::new(),
            peg: None,
        }
    }

    /// Test-only: a chain whose genesis already carries `leaves` as
    /// existing notes (standing in for PegMint/coinbase mint output,
    /// which lands in G2.5/S5), with the genesis root fixed to match.
    #[cfg(test)]
    pub(crate) fn new_with_notes(
        network: Network,
        pow_mode: PowMode,
        proof_mode: ProofMode,
        leaves: Vec<aegis_crypto::generators::EvenPoint>,
    ) -> Self {
        let state = ShieldedState::seeded(leaves);
        let mut header = genesis_header(network);
        header.cm_tree_root = state.cm_tree_root();
        let daa = DaaParams::for_network(network);
        Chain {
            network,
            pow_mode,
            proof_mode,
            daa,
            blocks: vec![Block {
                header,
                body: BlockBody::default(),
                coinbase: None,
            }],
            state,
            undo_ring: VecDeque::new(),
            peg: None,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Attach (or replace) the peg-in validation config — the node's
    /// followed Ergo settled view + peg deploy pins. Until set, any block
    /// carrying peg-mints is rejected.
    pub fn set_peg_config(&mut self, config: PegConfig) {
        self.peg = Some(config);
    }

    /// The current peg-in validation config, if any.
    pub fn peg_config(&self) -> Option<&PegConfig> {
        self.peg.as_ref()
    }

    /// Borrow the peg config as a [`PegValidation`] for the apply path.
    fn peg_validation(&self) -> Option<PegValidation<'_>> {
        self.peg.as_ref().map(|c| PegValidation {
            anchor: &c.anchor,
            params: &c.params,
        })
    }

    pub fn tip(&self) -> &Header {
        &self
            .blocks
            .last()
            .expect("chain always holds genesis")
            .header
    }

    pub fn header_at(&self, height: u64) -> Option<&Header> {
        Some(&self.blocks.get(usize::try_from(height).ok()?)?.header)
    }

    /// Current shielded state (read-only view).
    pub fn state(&self) -> &ShieldedState {
        &self.state
    }

    /// Median timestamp of the last [`MTP_WINDOW`] blocks (§4).
    pub fn median_time_past(&self) -> u64 {
        let n = self.blocks.len().min(MTP_WINDOW);
        let mut recent: Vec<u64> = self.blocks[self.blocks.len() - n..]
            .iter()
            .map(|b| b.header.timestamp_ms)
            .collect();
        recent.sort_unstable();
        recent[recent.len() / 2]
    }

    /// DAA-mandated `sc_nbits` for the next block (§3).
    pub fn expected_nbits(&self) -> u32 {
        let view: Vec<(u64, u32)> = self
            .blocks
            .iter()
            .map(|b| (b.header.timestamp_ms, b.header.sc_nbits))
            .collect();
        next_nbits(&self.daa, &view)
    }

    /// Build the next block the way a dev-mode producer would: linked
    /// to the tip, correctly difficulty-stamped, timestamped at the
    /// wall clock but never at/below MTP, with header roots computed by
    /// dry-running `body` against the current state. Fails if the body
    /// is invalid against the state (e.g. a double spend).
    pub fn produce_next(&self, body: BlockBody, now_ms: u64) -> Result<Block, ExtendError> {
        self.produce_inner(
            body,
            now_ms,
            RewardMode::DevStub,
            EMPTY_REWARD_CLAIM,
            None,
            &[],
        )
    }

    /// Produce the next block carrying `peg_mints` (plus `body`'s
    /// transfers): each proof is verified against the chain's peg config
    /// and mints its note, exactly as `try_extend` will re-validate. The
    /// canonical proof bytes are written into the produced body. Fails
    /// (leaving the chain untouched) if any peg-mint is invalid or the
    /// chain has no peg config.
    pub fn produce_next_with_pegmints(
        &self,
        body: BlockBody,
        now_ms: u64,
        peg_mints: &[PegMintProof],
    ) -> Result<Block, ExtendError> {
        self.produce_inner(
            body,
            now_ms,
            RewardMode::DevStub,
            EMPTY_REWARD_CLAIM,
            None,
            peg_mints,
        )
    }

    /// Produce the next block minting a coinbase note (S5b): its value is
    /// `expected_coinbase_value(pot, n_txs)`, committed with the given
    /// `tag`/`blinding`, bound by a `MintProof`. The header's roots and
    /// pot reflect the minted note; `reward_claim` is the note's cm.
    pub fn produce_next_with_coinbase(
        &self,
        body: BlockBody,
        now_ms: u64,
        tag: EvenScalar,
        blinding: EvenScalar,
    ) -> Result<Block, ExtendError> {
        let params = self.network.params();
        let value = expected_coinbase_value(self.state.pot(), body.transfers.len() as u64, params);
        // prove_mint is deterministic (ignores the rng); a fixed rng is
        // fine and keeps production reproducible.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let proof = prove_mint(value, tag, blinding, &mut rng)?;
        let reward_claim = note_cm_bytes(&proof.cm);
        self.produce_inner(
            body,
            now_ms,
            RewardMode::Real {
                coinbase_cm: proof.cm,
            },
            reward_claim,
            Some(proof),
            &[],
        )
    }

    fn produce_inner(
        &self,
        mut body: BlockBody,
        now_ms: u64,
        reward: RewardMode,
        reward_claim: [u8; 33],
        coinbase: Option<aegis_crypto::mint::MintProof>,
        peg_mints: &[PegMintProof],
    ) -> Result<Block, ExtendError> {
        // Attach the canonical peg-mint envelope bytes to the body so the
        // produced block round-trips to exactly what was verified.
        body.peg_mints = peg_mints
            .iter()
            .enumerate()
            .map(|(index, p)| {
                serialize_pegmint_proof(p).map_err(|_| ExtendError::PegMintDecode { index })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut dry = self.state.clone();
        dry.apply_block(
            &body.transfers,
            peg_mints,
            self.network.params(),
            reward,
            self.peg_validation(),
        )?;
        let tip = self.tip();
        let header = Header {
            version: 1,
            prev_id: tip.id(),
            height: tip.height + 1,
            timestamp_ms: now_ms.max(self.median_time_past() + 1),
            tx_root: body.tx_root(),
            cm_tree_root: dry.cm_tree_root(),
            nullifier_digest: dry.nullifier_digest(),
            pot_balance: dry.pot(),
            sc_nbits: self.expected_nbits(),
            reward_claim,
        };
        Ok(Block {
            header,
            body,
            coinbase,
        })
    }

    /// Validate `block` as the next one and append it. `now_ms` is the
    /// validator's wall clock (future-drift bound, §4). On error the
    /// chain and state are unchanged.
    pub fn try_extend(&mut self, block: Block, now_ms: u64) -> Result<(), ExtendError> {
        let header = &block.header;
        if header.version != 1 {
            return Err(ExtendError::UnsupportedVersion(header.version));
        }
        let tip_id = self.tip().id();
        if header.prev_id != tip_id {
            return Err(ExtendError::PrevIdMismatch {
                got: header.prev_id,
                want: tip_id,
            });
        }
        let want_height = self.tip().height + 1;
        if header.height != want_height {
            return Err(ExtendError::HeightMismatch {
                got: header.height,
                want: want_height,
            });
        }
        let mtp = self.median_time_past();
        if header.timestamp_ms <= mtp {
            return Err(ExtendError::TimestampNotAfterMtp {
                ts: header.timestamp_ms,
                mtp,
            });
        }
        if header.timestamp_ms > now_ms + MAX_FUTURE_DRIFT_MS {
            return Err(ExtendError::TimestampTooFarInFuture {
                ts: header.timestamp_ms,
                now: now_ms,
            });
        }
        let want_nbits = self.expected_nbits();
        if header.sc_nbits != want_nbits {
            return Err(ExtendError::WrongDifficulty {
                got: header.sc_nbits,
                want: want_nbits,
            });
        }
        match self.pow_mode {
            PowMode::DevStub => {} // witness verification lands with W4
        }
        let want_tx_root = block.body.tx_root();
        if header.tx_root != want_tx_root {
            return Err(ExtendError::TxRootMismatch {
                got: header.tx_root,
                want: want_tx_root,
            });
        }
        // Shielded proofs verify against the parent-block anchor tree
        // (the current pre-apply state), before any mutation.
        match self.proof_mode {
            ProofMode::DevStub => {}
            ProofMode::Real if !block.body.transfers.is_empty() => {
                let anchor = self.state.anchor_tree().ok_or(ExtendError::NoAnchor)?;
                let fee = self.network.params().sc_tx_fee;
                for (index, tx) in block.body.transfers.iter().enumerate() {
                    crate::proof::verify_shielded_transfer(&anchor, tx, fee)
                        .map_err(|source| ExtendError::Proof { index, source })?;
                }
            }
            ProofMode::Real => {}
        }
        // Coinbase (S5b): a block either carries a mint proof (Real
        // reward) or none (DevStub). Verify the mint binds the expected
        // reward, the coinbase note is not the identity, and the header
        // commits to it — all before any mutation.
        let params = self.network.params();
        let reward = match &block.coinbase {
            None => {
                if block.header.reward_claim != EMPTY_REWARD_CLAIM {
                    return Err(ExtendError::RewardClaimMismatch);
                }
                RewardMode::DevStub
            }
            Some(proof) => {
                let value = expected_coinbase_value(
                    self.state.pot(),
                    block.body.transfers.len() as u64,
                    params,
                );
                verify_mint(value, proof)?;
                if proof.cm.is_zero() {
                    return Err(ExtendError::ZeroCoinbase);
                }
                if block.header.reward_claim != note_cm_bytes(&proof.cm) {
                    return Err(ExtendError::RewardClaimMismatch);
                }
                RewardMode::Real {
                    coinbase_cm: proof.cm,
                }
            }
        };
        // Decode the block's peg-mints from their canonical envelope
        // bytes (before any mutation). A malformed blob rejects the block.
        let mut peg_mints = Vec::with_capacity(block.body.peg_mints.len());
        for (index, bytes) in block.body.peg_mints.iter().enumerate() {
            let proof =
                read_pegmint_proof(bytes).map_err(|_| ExtendError::PegMintDecode { index })?;
            peg_mints.push(proof);
        }
        // State transition — apply, then verify the header committed to
        // exactly this post-state; roll back on any mismatch. Split the
        // borrow so the peg config (`self.peg`) and state (`self.state`)
        // are taken from disjoint fields.
        let peg_val = self.peg.as_ref().map(|c| PegValidation {
            anchor: &c.anchor,
            params: &c.params,
        });
        let undo = self.state.apply_block(
            &block.body.transfers,
            &peg_mints,
            self.network.params(),
            reward,
            peg_val,
        )?;
        let want_digest = self.state.nullifier_digest();
        if header.nullifier_digest != want_digest {
            let got = header.nullifier_digest;
            self.state.rollback(undo);
            return Err(ExtendError::NullifierDigestMismatch {
                got,
                want: want_digest,
            });
        }
        let want_pot = self.state.pot();
        if header.pot_balance != want_pot {
            let got = header.pot_balance;
            self.state.rollback(undo);
            return Err(ExtendError::PotMismatch {
                got,
                want: want_pot,
            });
        }
        let want_cm_root = self.state.cm_tree_root();
        if header.cm_tree_root != want_cm_root {
            let got = header.cm_tree_root;
            self.state.rollback(undo);
            return Err(ExtendError::CmTreeRootMismatch {
                got,
                want: want_cm_root,
            });
        }
        self.blocks.push(block);
        self.undo_ring.push_back(undo);
        if self.undo_ring.len() > STATE_RETENTION_BLOCKS {
            self.undo_ring.pop_front();
        }
        Ok(())
    }

    /// Rewind the tip by one block (fork-choice building block). Returns
    /// false at genesis or past the undo retention depth.
    pub fn rollback_tip(&mut self) -> bool {
        if self.blocks.len() <= 1 {
            return false;
        }
        let Some(undo) = self.undo_ring.pop_back() else {
            return false;
        };
        self.blocks.pop();
        self.state.rollback(undo);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::testutil::sample_transfer;
    use aegis_spec::{Network, NF_BYTES};

    // ----- helpers -----

    const T_MS: u64 = 15_000;

    fn dev_chain() -> Chain {
        Chain::new(Network::Dev, PowMode::DevStub, ProofMode::DevStub)
    }

    fn transfer_with_nfs(a: u8, b: u8) -> crate::tx::ShieldedTransfer {
        let mut tx = sample_transfer(a);
        tx.nullifiers = [[a; NF_BYTES], [b; NF_BYTES]];
        tx
    }

    fn body_with(transfers: Vec<crate::tx::ShieldedTransfer>) -> BlockBody {
        BlockBody {
            transfers,
            peg_mints: Vec::new(),
        }
    }

    /// Extend the chain with `n` produced empty blocks, `spacing_ms`
    /// apart, starting just after genesis time.
    fn grow(chain: &mut Chain, n: usize, spacing_ms: u64) {
        let mut now = chain.tip().timestamp_ms;
        for _ in 0..n {
            now += spacing_ms;
            let block = chain
                .produce_next(BlockBody::default(), now)
                .expect("empty body must produce");
            chain
                .try_extend(block, now)
                .expect("produced block must be accepted");
        }
    }

    // ----- happy path -----

    #[test]
    fn chain_starts_at_genesis() {
        let chain = dev_chain();
        assert_eq!(chain.tip().height, 0);
        assert_eq!(chain.tip().id(), crate::genesis_header(Network::Dev).id());
    }

    #[test]
    fn produced_blocks_extend_the_chain() {
        let mut chain = dev_chain();
        grow(&mut chain, 5, T_MS);
        assert_eq!(chain.tip().height, 5);
        assert_eq!(chain.tip().prev_id, chain.header_at(4).unwrap().id());
    }

    #[test]
    fn produced_timestamp_respects_mtp_when_clock_lags() {
        let mut chain = dev_chain();
        grow(&mut chain, 12, T_MS);
        // Wall clock far behind the chain: production must still emit a
        // timestamp strictly above MTP-11 to be self-consistent.
        let stale_now = chain.header_at(1).unwrap().timestamp_ms;
        let block = chain.produce_next(BlockBody::default(), stale_now).unwrap();
        assert!(block.header.timestamp_ms > chain.median_time_past());
    }

    #[test]
    fn difficulty_reacts_after_window_of_fast_blocks() {
        let mut chain = dev_chain();
        // 91 blocks at half target: once the LWMA window fills, expected
        // difficulty must rise above the genesis minimum.
        grow(&mut chain, 91, T_MS / 2);
        let genesis_nbits = crate::genesis_header(Network::Dev).sc_nbits;
        let next = chain.expected_nbits();
        assert_ne!(next, genesis_nbits);
    }

    #[test]
    fn block_with_transfers_updates_pot_digest_and_cm_root_in_header() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let genesis_digest = chain.tip().nullifier_digest;
        let genesis_cm_root = chain.tip().cm_tree_root;
        let block = chain
            .produce_next(body_with(vec![transfer_with_nfs(1, 2)]), now)
            .unwrap();
        assert_eq!(block.header.pot_balance, Network::Dev.params().sc_tx_fee);
        chain.try_extend(block, now).unwrap();
        assert_eq!(chain.tip().pot_balance, Network::Dev.params().sc_tx_fee);
        assert_ne!(chain.tip().nullifier_digest, genesis_digest);
        assert_ne!(chain.tip().cm_tree_root, genesis_cm_root);
        assert_eq!(chain.state().leaf_count(), 2);
        assert!(chain.state().contains(&[1u8; NF_BYTES]));
    }

    #[test]
    fn empty_blocks_keep_the_sentinel_cm_root() {
        let mut chain = dev_chain();
        let genesis_cm_root = chain.tip().cm_tree_root;
        grow(&mut chain, 3, T_MS);
        assert_eq!(chain.tip().cm_tree_root, genesis_cm_root);
    }

    // ----- round-trips -----

    #[test]
    fn rollback_tip_restores_prior_tip_and_state() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let genesis_digest = chain.tip().nullifier_digest;
        let block = chain
            .produce_next(body_with(vec![transfer_with_nfs(1, 2)]), now)
            .unwrap();
        chain.try_extend(block, now).unwrap();
        assert!(chain.rollback_tip());
        assert_eq!(chain.tip().height, 0);
        assert_eq!(chain.tip().nullifier_digest, genesis_digest);
        assert!(!chain.state().contains(&[1u8; NF_BYTES]));
        assert!(!chain.rollback_tip(), "genesis must not be rollback-able");
    }

    // ----- error paths -----

    #[test]
    fn extend_with_wrong_prev_id_rejected() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain.produce_next(BlockBody::default(), now).unwrap();
        block.header.prev_id = [0xAA; 32];
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::PrevIdMismatch { .. })
        ));
    }

    #[test]
    fn extend_with_wrong_height_rejected() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain.produce_next(BlockBody::default(), now).unwrap();
        block.header.height += 1;
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::HeightMismatch { .. })
        ));
    }

    #[test]
    fn extend_with_timestamp_at_or_below_mtp_rejected() {
        let mut chain = dev_chain();
        grow(&mut chain, 12, T_MS);
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain.produce_next(BlockBody::default(), now).unwrap();
        block.header.timestamp_ms = chain.median_time_past();
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::TimestampNotAfterMtp { .. })
        ));
    }

    #[test]
    fn extend_with_far_future_timestamp_rejected() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain.produce_next(BlockBody::default(), now).unwrap();
        block.header.timestamp_ms = now + MAX_FUTURE_DRIFT_MS + 1;
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::TimestampTooFarInFuture { .. })
        ));
    }

    #[test]
    fn extend_with_wrong_nbits_rejected() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain.produce_next(BlockBody::default(), now).unwrap();
        block.header.sc_nbits += 1;
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::WrongDifficulty { .. })
        ));
    }

    #[test]
    fn extend_with_wrong_version_rejected() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain.produce_next(BlockBody::default(), now).unwrap();
        block.header.version = 2;
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn extend_with_wrong_tx_root_rejected() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain.produce_next(BlockBody::default(), now).unwrap();
        block.header.tx_root = [0xEE; 32];
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::TxRootMismatch { .. })
        ));
    }

    #[test]
    fn extend_with_wrong_pot_or_digest_rejected_and_state_clean() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain
            .produce_next(body_with(vec![transfer_with_nfs(1, 2)]), now)
            .unwrap();
        block.header.pot_balance += 1;
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::PotMismatch { .. })
        ));
        let mut block = chain
            .produce_next(body_with(vec![transfer_with_nfs(1, 2)]), now)
            .unwrap();
        block.header.nullifier_digest = [0xEE; 32];
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::NullifierDigestMismatch { .. })
        ));
        // The rejected blocks must not have dirtied the nullifier set:
        let clean = chain
            .produce_next(body_with(vec![transfer_with_nfs(1, 2)]), now)
            .unwrap();
        chain.try_extend(clean, now).unwrap();
    }

    #[test]
    fn extend_with_wrong_cm_root_rejected_and_state_clean() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain
            .produce_next(body_with(vec![transfer_with_nfs(1, 2)]), now)
            .unwrap();
        block.header.cm_tree_root = [0xEE; 32];
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::CmTreeRootMismatch { .. })
        ));
        // The rejected block must not have left leaves behind:
        assert_eq!(chain.state().leaf_count(), 0);
        let clean = chain
            .produce_next(body_with(vec![transfer_with_nfs(1, 2)]), now)
            .unwrap();
        chain.try_extend(clean, now).unwrap();
        assert_eq!(chain.state().leaf_count(), 2);
    }

    // ----- real proof mode (S4) -----

    fn real_input(value: u64, seed: u64, leaf_index: usize) -> aegis_crypto::spend::NoteOpening {
        use aegis_crypto::note::EvenScalar;
        use aegis_crypto::nullifier::OddScalar;
        aegis_crypto::spend::NoteOpening {
            value,
            blinding: EvenScalar::from(seed),
            leaf_index,
            nk: OddScalar::from(seed + 1),
            rho: OddScalar::from(seed + 2),
            r_key: OddScalar::from(seed + 3),
        }
    }

    fn real_leaf(o: &aegis_crypto::spend::NoteOpening) -> aegis_crypto::generators::EvenPoint {
        aegis_crypto::spend::consensus_note_commitment(
            o.value,
            aegis_crypto::spend::consensus_note_tag(o.nk, o.rho, o.r_key),
            o.blinding,
        )
    }

    /// A wire transfer carrying a real proof spending `inputs` against
    /// `anchor` (1500 in → 1390 + 100 out + 10 fee).
    fn real_transfer_tx(
        anchor: &aegis_crypto::tree::AegisTree,
        inputs: &[aegis_crypto::spend::NoteOpening; 2],
    ) -> crate::tx::ShieldedTransfer {
        use aegis_crypto::note::{note_cm_bytes, EvenScalar};
        use aegis_crypto::spend::{prove_transfer, TransferOutput};
        use aegis_spec::{EPK_BYTES, NOTE_CT_BYTES, NOTE_OUT_CT_BYTES};
        use rand::SeedableRng;
        let outputs = [
            TransferOutput {
                value: 1_390,
                tag: EvenScalar::from(0x31u64),
                blinding: EvenScalar::from(0x41u64),
            },
            TransferOutput {
                value: 100,
                tag: EvenScalar::from(0x32u64),
                blinding: EvenScalar::from(0x42u64),
            },
        ];
        let proof = prove_transfer(
            anchor,
            inputs,
            &outputs,
            Network::Dev.params().sc_tx_fee,
            &mut rand::rngs::StdRng::seed_from_u64(2),
        )
        .expect("valid transfer proves");
        let mut proof_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes).unwrap();
        let out_wire = |i: usize| crate::tx::ShieldedOutput {
            note_cm: note_cm_bytes(&proof.output_cms[i]),
            epk: [0u8; EPK_BYTES],
            ct: [0u8; NOTE_CT_BYTES],
            out_ct: [0u8; NOTE_OUT_CT_BYTES],
        };
        crate::tx::ShieldedTransfer {
            nullifiers: proof.nullifiers(),
            outputs: [out_wire(0), out_wire(1)],
            proof: proof_bytes,
        }
    }

    #[test]
    fn real_mode_accepts_valid_transfer() {
        let inputs = [real_input(1_000, 0x21, 0), real_input(500, 0x22, 1)];
        let leaves = vec![real_leaf(&inputs[0]), real_leaf(&inputs[1])];
        let mut chain = Chain::new_with_notes(
            Network::Dev,
            PowMode::DevStub,
            ProofMode::Real,
            leaves.clone(),
        );
        let anchor = aegis_crypto::tree::build_tree(&leaves);
        let tx = real_transfer_tx(&anchor, &inputs);
        let now = chain.tip().timestamp_ms + T_MS;

        let block = chain
            .produce_next(body_with(vec![tx]), now)
            .expect("produce with real transfer");
        // Valid proof accepted; leaves grow by the two outputs.
        chain
            .try_extend(block, now)
            .expect("valid real transfer accepted");
        assert_eq!(chain.state().leaf_count(), 4);
    }

    #[test]
    fn real_mode_rejects_tampered_nullifier() {
        let inputs = [real_input(1_000, 0x21, 0), real_input(500, 0x22, 1)];
        let leaves = vec![real_leaf(&inputs[0]), real_leaf(&inputs[1])];
        let mut chain = Chain::new_with_notes(
            Network::Dev,
            PowMode::DevStub,
            ProofMode::Real,
            leaves.clone(),
        );
        let anchor = aegis_crypto::tree::build_tree(&leaves);
        let mut tx = real_transfer_tx(&anchor, &inputs);
        tx.nullifiers[0][0] ^= 0xFF; // wire nf no longer matches the proof
        let now = chain.tip().timestamp_ms + T_MS;
        let block = chain
            .produce_next(body_with(vec![tx]), now)
            .expect("produce tampered");
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::Proof { index: 0, .. })
        ));
        // State untouched by the rejected block.
        assert_eq!(chain.state().leaf_count(), 2);
    }

    #[test]
    fn real_mode_transfers_without_notes_have_no_anchor() {
        // A real-mode chain with no seeded notes cannot accept a block
        // that spends (nothing to prove membership against).
        let inputs = [real_input(1_000, 0x21, 0), real_input(500, 0x22, 1)];
        let leaves = vec![real_leaf(&inputs[0]), real_leaf(&inputs[1])];
        let anchor = aegis_crypto::tree::build_tree(&leaves);
        let tx = real_transfer_tx(&anchor, &inputs);
        let mut chain = Chain::new(Network::Dev, PowMode::DevStub, ProofMode::Real);
        let now = chain.tip().timestamp_ms + T_MS;
        // Build the block bytes directly (produce_next would append valid
        // leaves; here we assert the empty-anchor guard specifically).
        let block = Block {
            header: {
                let mut h = chain
                    .produce_next(BlockBody::default(), now)
                    .unwrap()
                    .header;
                h.tx_root = body_with(vec![tx.clone()]).tx_root();
                h
            },
            body: body_with(vec![tx]),
            coinbase: None,
        };
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::NoAnchor)
        ));
    }

    // ----- coinbase mint (S5b) -----

    fn cb_tag() -> aegis_crypto::note::EvenScalar {
        aegis_crypto::note::EvenScalar::from(0xC0u64)
    }

    fn cb_blinding(seed: u64) -> aegis_crypto::note::EvenScalar {
        aegis_crypto::note::EvenScalar::from(0xB1u64 + seed)
    }

    #[test]
    fn coinbase_block_mints_a_note_and_extends() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let block = chain
            .produce_next_with_coinbase(BlockBody::default(), now, cb_tag(), cb_blinding(1))
            .expect("produce coinbase block");
        // header commits to the coinbase note; reward_claim is not the sentinel.
        assert_ne!(
            block.header.reward_claim,
            crate::genesis::EMPTY_REWARD_CLAIM
        );
        chain
            .try_extend(block, now)
            .expect("coinbase block accepted");
        // one coinbase note leaf minted.
        assert_eq!(chain.state().leaf_count(), 1);
    }

    #[test]
    fn coinbase_block_rollback_restores_state() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let block = chain
            .produce_next_with_coinbase(BlockBody::default(), now, cb_tag(), cb_blinding(2))
            .unwrap();
        chain.try_extend(block, now).unwrap();
        assert_eq!(chain.state().leaf_count(), 1);
        assert!(chain.rollback_tip());
        assert_eq!(chain.tip().height, 0);
        assert_eq!(chain.state().leaf_count(), 0);
    }

    #[test]
    fn coinbase_with_wrong_reward_claim_rejected() {
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain
            .produce_next_with_coinbase(BlockBody::default(), now, cb_tag(), cb_blinding(3))
            .unwrap();
        block.header.reward_claim = [0xEE; 33];
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::RewardClaimMismatch)
        ));
        assert_eq!(chain.state().leaf_count(), 0);
    }

    #[test]
    fn no_coinbase_but_nonsentinel_reward_claim_rejected() {
        // A DevStub block may not claim a reward without a mint proof.
        let mut chain = dev_chain();
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain.produce_next(BlockBody::default(), now).unwrap();
        block.header.reward_claim = [0x01; 33];
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::RewardClaimMismatch)
        ));
    }

    #[test]
    fn coinbase_producer_boots_a_chain() {
        // The dev producer path: several coinbase blocks in a row, each
        // minting a note; genesis id + linkage intact.
        let mut chain = dev_chain();
        for h in 1..=4u64 {
            let now = chain.tip().timestamp_ms + T_MS;
            let block = chain
                .produce_next_with_coinbase(BlockBody::default(), now, cb_tag(), cb_blinding(h))
                .unwrap();
            chain.try_extend(block, now).unwrap();
        }
        assert_eq!(chain.tip().height, 4);
        assert_eq!(chain.state().leaf_count(), 4);
    }

    #[test]
    fn double_spend_across_blocks_rejected_by_chain() {
        let mut chain = dev_chain();
        let mut now = chain.tip().timestamp_ms + T_MS;
        let b1 = chain
            .produce_next(body_with(vec![transfer_with_nfs(1, 2)]), now)
            .unwrap();
        chain.try_extend(b1, now).unwrap();
        now += T_MS;
        // produce_next dry-runs state, so building the double spend fails:
        assert!(matches!(
            chain.produce_next(body_with(vec![transfer_with_nfs(1, 9)]), now),
            Err(ExtendError::State(StateError::DoubleSpend { .. }))
        ));
    }

    // ----- peg-in mints (end-to-end through try_extend) -----

    use crate::pegmint_steps::testutil as peg;
    use crate::state::StateError as SErr;

    fn peg_chain(cfg: PegConfig) -> Chain {
        let mut chain = dev_chain();
        chain.set_peg_config(cfg);
        chain
    }

    #[test]
    fn peg_mint_block_extends_chain_and_mints_the_note() {
        let (proof, anchor, pp) = peg::spendable_case(50_000, 400, 0x11);
        let box_id = crate::pegmint_steps::verify_pegmint(
            &proof,
            &anchor,
            &crate::pegmint_steps::PegMintUsedSet::new(),
            &pp,
        )
        .unwrap()
        .box_id;
        let mut chain = peg_chain(PegConfig { anchor, params: pp });
        let now = chain.tip().timestamp_ms + T_MS;
        let block = chain
            .produce_next_with_pegmints(BlockBody::default(), now, &[proof])
            .expect("produce peg-mint block");
        // The produced block carries the canonical proof bytes and its
        // header commits to the minted post-state.
        assert_eq!(block.body.peg_mints.len(), 1);
        chain
            .try_extend(block, now)
            .expect("peg-mint block accepted");
        assert_eq!(chain.tip().height, 1);
        assert_eq!(chain.state().leaf_count(), 1, "one peg-mint note minted");
        assert!(chain.state().is_peg_used(&box_id), "receipt boxId recorded");
        assert_eq!(chain.state().pot(), 400, "proven peg fee credited");
        // Header commits to the peg-mint's effect (post-state roots).
        assert_eq!(chain.tip().pot_balance, 400);
        assert_ne!(
            chain.tip().cm_tree_root,
            crate::genesis_header(Network::Dev).cm_tree_root
        );
    }

    #[test]
    fn peg_mint_block_rolls_back_cleanly() {
        let (proof, anchor, pp) = peg::spendable_case(50_000, 400, 0x22);
        let mut chain = peg_chain(PegConfig { anchor, params: pp });
        let now = chain.tip().timestamp_ms + T_MS;
        let block = chain
            .produce_next_with_pegmints(BlockBody::default(), now, &[proof])
            .unwrap();
        chain.try_extend(block, now).unwrap();
        assert_eq!(chain.state().leaf_count(), 1);
        assert!(chain.rollback_tip());
        assert_eq!(chain.tip().height, 0);
        assert_eq!(chain.state().leaf_count(), 0);
        assert!(chain.state().peg_used().is_empty(), "used-set rolled back");
        assert_eq!(chain.state().pot(), 0);
    }

    #[test]
    fn tampered_peg_mint_block_rejected_state_clean() {
        // Produce a valid peg-mint block, then corrupt the carried proof
        // bytes: it no longer decodes, so try_extend rejects it and the
        // chain state is untouched.
        let (proof, anchor, pp) = peg::spendable_case(50_000, 400, 0x33);
        let mut chain = peg_chain(PegConfig { anchor, params: pp });
        let now = chain.tip().timestamp_ms + T_MS;
        let mut block = chain
            .produce_next_with_pegmints(BlockBody::default(), now, &[proof])
            .unwrap();
        block.body.peg_mints[0].push(0xFF); // trailing byte → decode fails
        assert!(matches!(
            chain.try_extend(block, now),
            Err(ExtendError::PegMintDecode { index: 0 })
        ));
        assert_eq!(chain.tip().height, 0);
        assert_eq!(chain.state().leaf_count(), 0);
        assert!(chain.state().peg_used().is_empty());
    }

    #[test]
    fn replayed_peg_mint_rejected_across_blocks() {
        let (proof, anchor, pp) = peg::spendable_case(50_000, 400, 0x44);
        let replay = proof.clone();
        let mut chain = peg_chain(PegConfig { anchor, params: pp });
        let mut now = chain.tip().timestamp_ms + T_MS;
        let b1 = chain
            .produce_next_with_pegmints(BlockBody::default(), now, &[proof])
            .unwrap();
        chain.try_extend(b1, now).unwrap();
        now += T_MS;
        // produce dry-runs against the committed used-set → AlreadyMinted.
        assert!(matches!(
            chain.produce_next_with_pegmints(BlockBody::default(), now, &[replay]),
            Err(ExtendError::State(SErr::PegMint {
                index: 0,
                source: crate::pegmint::PegMintError::AlreadyMinted
            }))
        ));
        // Chain is unchanged past block 1.
        assert_eq!(chain.tip().height, 1);
        assert_eq!(chain.state().leaf_count(), 1);
    }

    #[test]
    fn peg_mint_block_without_config_is_rejected() {
        // A chain with no peg config rejects any block carrying peg-mints
        // (the bytes are decodable, but there is no anchor to verify them).
        let (proof, anchor, pp) = peg::spendable_case(50_000, 400, 0x55);
        // Build a valid block on a peg-enabled chain…
        let enabled = peg_chain(PegConfig { anchor, params: pp });
        let now = enabled.tip().timestamp_ms + T_MS;
        let block = enabled
            .produce_next_with_pegmints(BlockBody::default(), now, &[proof])
            .unwrap();
        // …then present it to a peg-DISABLED chain.
        let mut disabled = dev_chain();
        assert!(matches!(
            disabled.try_extend(block, now),
            Err(ExtendError::State(SErr::PegDisabled))
        ));
        assert_eq!(disabled.state().leaf_count(), 0);
    }
}
