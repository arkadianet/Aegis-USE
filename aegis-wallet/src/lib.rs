//! `aegis-wallet` — the standalone Aegis shielded wallet.
//!
//! **Deliberately not linked into `aegis-node`.** Spending keys must never live
//! in a network-exposed process; the wallet is a client of the node's read-only
//! HTTP API (`dev-docs/sidechain/wallet-design.md`).
//!
//! Slice 1: the key hierarchy ([`keys`]) and the address ([`address`]).
//! Slice 2: the node [`client`], self-owned [`notes`], reconstructed
//! [`state`], and self-transfer [`send`]. Slice 3 (this change): note
//! encryption (via [`aegis_crypto::note_encryption`]) and send-to-another
//! party ([`pay`]) — the wallet now builds a note payable to a recipient's
//! address, ships the opening inside an encrypted `ct`, detects notes
//! others sent it by trial-decrypting on-chain outputs during [`state`]
//! scan, and spends them onward. The key derivations here are wallet-local
//! (not consensus) and v1/provisional.

pub mod address;
pub mod client;
pub mod keys;
pub mod keystore;
pub mod notes;
pub mod pay;
pub mod send;
pub mod state;

pub use address::{Address, AddressError, HRP_MAINNET, HRP_TESTNET};
pub use client::{
    BlockSummary, BlocksPage, ChainState, ClientError, NodeClient, SubmitOutcome, Tip,
};
pub use keys::{IncomingViewingKey, Ovk, SpendingKey};
pub use keystore::Keystore;
pub use notes::{detect_received, ReceivedNote, SelfNote};
pub use pay::{pay, PayError, Payment};
pub use send::{consolidate, ConsolidateError, Consolidation};
pub use state::{ScanError, ScanReport, SpendableInput, SpentRef, TrackedNote, WalletState};
