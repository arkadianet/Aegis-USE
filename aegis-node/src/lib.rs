//! Aegis sidechain node library.
//!
//! Consensus per `dev-docs/sidechain/consensus.md`: header model and
//! id (§2), deterministic genesis (§6), LWMA-90 difficulty (§3).
//! PoW-witness verification, state, P2P, and RPC arrive in later G1/G2
//! slices — this crate starts with the pieces the spec freezes first.
//!
//! Reuses `ergo-primitives` (VLQ writer/reader), `ergo-crypto`
//! (blake2b256), and `ergo-ser` (compact-nbits codecs). Chain
//! parameters come from `aegis-spec`.

pub mod anchor_watch;
pub mod auxpow;
pub mod block;
pub mod chain;
pub mod daa;
pub mod ergo_follow;
pub mod genesis;
pub mod header;
pub mod mm_forkchoice;
pub mod pegmint;
pub mod pegmint_steps;
pub mod proof;
pub mod state;
pub mod store;
pub mod tx;

pub use anchor_watch::{
    extension_field_proof, extract_commitment, settled_is_final, AegisLookup, AegisSource,
    AnchorWatch, BlockSource, Commitment, ExtractError, Extracted, MalformedReason,
    MemoryAegisSource, MemoryBlockSource, ScanError, UnresolvedReason, WatchError, WatchEvent,
};
pub use auxpow::{
    aegis_mm_extension_field, verify_share, ShareContext, ShareError, ShareWitness, ValidShare,
    WitnessDecodeError, WitnessError,
};
pub use block::{Block, BlockBody, BlockDecodeError, BodyDecodeError};
pub use chain::{Chain, ExtendError, PowMode, ProofMode};
pub use daa::{next_nbits, DaaParams};
pub use genesis::genesis_header;
pub use header::{Header, HeaderDecodeError};
pub use mm_forkchoice::{BodyIngest, MmForkChoice, ShareIngest};
pub use proof::{verify_shielded_transfer, ProofError};
pub use state::{BlockUndo, RewardMode, ShieldedState, StateError, STATE_RETENTION_BLOCKS};
pub use store::{load_chain, save_block, StoreError};
pub use tx::{ShieldedOutput, ShieldedTransfer, TxDecodeError};
