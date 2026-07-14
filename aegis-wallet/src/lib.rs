//! `aegis-wallet` — the standalone Aegis shielded wallet.
//!
//! **Deliberately not linked into `aegis-node`.** Spending keys must never live
//! in a network-exposed process; the wallet is a client of the node's read-only
//! HTTP API (`dev-docs/sidechain/wallet-design.md`).
//!
//! Slice 1: the key hierarchy ([`keys`]) and diversified addresses
//! ([`address`]). Slice 2 (this change): the node [`client`], self-owned
//! [`notes`], reconstructed [`state`], and self-transfer [`send`] — the
//! plumbing that scans the chain, tracks the wallet's own notes, and
//! consolidates them. Note *encryption* (send-to-another-party) is still
//! held under the freeze; slice 2 stays on self-owned notes the wallet
//! re-derives from `sk`. The key derivations here are wallet-local (not
//! consensus) and v1/provisional.

pub mod address;
pub mod client;
pub mod keys;
pub mod notes;
pub mod send;
pub mod state;

pub use address::{Address, AddressError, Diversifier, HRP_MAINNET, HRP_TESTNET};
pub use client::{
    BlockSummary, BlocksPage, ChainState, ClientError, NodeClient, SubmitOutcome, Tip,
};
pub use keys::{IncomingViewingKey, Ovk, SpendingKey};
pub use notes::SelfNote;
pub use send::{consolidate, ConsolidateError, Consolidation};
pub use state::{ScanError, ScanReport, TrackedNote, WalletState};
