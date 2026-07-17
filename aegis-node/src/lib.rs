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
pub mod api;
pub mod attest;
pub mod auxpow;
pub mod chain;
pub mod daa;
pub mod ergo_follow;
pub mod fresh_sync;
pub mod genesis;
pub mod hn;
pub mod mempool;
pub mod mm_forkchoice;
pub mod node;
pub mod pegmint;
pub mod pegmint_steps;
pub mod proof;
pub mod seed;
pub mod state;
pub mod store;

// The pure wire types/codecs now live in `aegis-types`; re-export the
// modules so `crate::block` / `crate::header` / `crate::tx` — used
// throughout the node and its tests — keep resolving unchanged.
pub use aegis_types::{block, header, tx};

pub use anchor_watch::{
    extension_field_proof, extract_commitment, settled_is_final, AegisLookup, AegisSource,
    AnchorWatch, BlockSource, Commitment, ExtractError, Extracted, MalformedReason,
    MemoryAegisSource, MemoryBlockSource, ScanError, UnresolvedReason, WatchError, WatchEvent,
};
pub use api::{ApiServer, ApiState, NodeStatus};
pub use auxpow::{
    aegis_mm_extension_field, verify_share, ShareContext, ShareError, ShareWitness, ValidShare,
    WitnessDecodeError, WitnessError,
};
pub use block::{Block, BlockBody, BlockDecodeError, BodyDecodeError};
pub use chain::{Chain, ExtendError, PegConfig, PowMode, ProofMode};
pub use daa::{next_nbits, DaaParams};
pub use fresh_sync::{
    fresh_sync, sync_from_seeds, FreshSyncError, FreshSyncReport, FreshSyncResult, SeedSyncReport,
};
pub use genesis::genesis_header;
pub use header::{Header, HeaderDecodeError};
pub use mempool::{AdmissionView, AdmitError, Admitted, Mempool};
pub use mm_forkchoice::{BodyIngest, MmForkChoice, ShareIngest};
pub use node::{Node, NodeConfig, NodeError, TickReport};
pub use proof::{verify_shielded_transfer, ProofError};
pub use seed::fetch_http::{RestAegisSource, SeedClientConfig};
pub use seed::serve_http::SeedServer;
pub use seed::{body_self_authenticates, SeedCore, SeedFetch, SeedTips};
pub use state::{
    BlockUndo, PegValidation, RewardMode, ShieldedState, StateError, STATE_RETENTION_BLOCKS,
};
pub use store::{load_chain, read_log, read_witness_log, save_block, save_witness, StoreError};
pub use tx::{ShieldedOutput, ShieldedTransfer, TxDecodeError};
