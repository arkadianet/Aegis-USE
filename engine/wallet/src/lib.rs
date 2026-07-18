//! # aegis-hn-wallet — wallet orchestration for the hash-native engine
//!
//! Turns [`aegis_engine`] into something a user (and the e2e test campaign) can
//! drive: a passphrase-sealed [`keystore`], the shared spend [`circuit`] keys,
//! a [`wallet`] (note store + scanner + selection + pay/receive), and the node
//! [`chain`] boundary (`ChainView` + an in-memory node) the aegis-node
//! integration will implement.
//!
//! ## The core flow
//! `recipient address string → select 2 inputs → witnesses at the current root
//! → recipient note + change-to-self (both encrypted, §6 uniformity) → HIDING
//! monolith proof → Tx (proof + public values + 2×152 B ciphertexts) → node
//! accept (verify, anchor-in-window, no-double-spend, append + record)`.
//!
//! The receive path is `scan → trial-decrypt → strict spendability gate →
//! spendable`. See `dev-docs/sidechain/hash-native-spend-circuit.md` (wallet
//! section) for the design, including the root-window and 2-in-shape strategies.

pub mod chain;
pub mod circuit;
pub mod keystore;
pub mod wallet;

pub use chain::{ChainView, InMemoryChain, OutputRecord, SubmitError, Tx};
pub use circuit::{SpendCircuit, SpendVk};
pub use keystore::Keystore;
pub use wallet::{OwnedNote, PayError, ViewingKey, Wallet};
