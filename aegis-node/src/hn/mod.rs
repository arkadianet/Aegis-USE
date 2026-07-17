//! Hash-native shielded pool for aegis-node (feat/hash-native-payment-engine).
//!
//! A self-contained subsystem running the BabyBear/Poseidon2/FRI shielded pool
//! with real persistence and reorg-safe state, driven by `aegis-hn-wallet`
//! transactions. It sits ALONGSIDE the existing Curve-Trees consensus (which
//! stays the working baseline) — the fold into the live mining/P2P/fork-choice
//! pipeline + HTTP surface is the next milestone (see dev-docs integration §).
//!
//! - [`state`]: `HnState` — the Poseidon-Merkle tree, nullifier set, and
//!   recent-roots window, with exact apply/rollback (reorg-safe).
//! - [`mint`]: deterministic coinbase / (INERT) peg-in note derivation.
//! - [`chain`]: `HnChain` — persisted block log + mempool + local block
//!   production + the wallet-facing `ChainView`/submit boundary.

pub mod api;
pub mod chain;
pub mod http_client;
pub mod mint;
pub mod state;

pub use api::{HnApiServer, HnApiState};
pub use chain::HnChain;
pub use http_client::HttpChain;
pub use state::{HnBlock, HnError, HnState};
