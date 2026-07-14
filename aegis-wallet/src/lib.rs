//! `aegis-wallet` — the standalone Aegis shielded wallet.
//!
//! **Deliberately not linked into `aegis-node`.** Spending keys must never live
//! in a network-exposed process; the wallet is a client of the node's read-only
//! HTTP API (`dev-docs/sidechain/wallet-design.md`).
//!
//! Slice 1 (this crate so far): the key hierarchy ([`keys`]) and diversified
//! addresses ([`address`]). No note encryption, no proving, no network yet —
//! those slices are held under the freeze-hold. The key derivations here are
//! wallet-local (not consensus) and v1/provisional.

pub mod address;
pub mod keys;

pub use address::{Address, AddressError, Diversifier, HRP_MAINNET, HRP_TESTNET};
pub use keys::{IncomingViewingKey, Ovk, SpendingKey};
