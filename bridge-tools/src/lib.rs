//! DEVNET-side tooling for the hash-native trustless bridge: the PegVault
//! ErgoTree (verifyStark release predicate), and transaction assembly for
//! token mint / vault deploy / deposit / release against the STARK devnet.
//! See `Cargo.toml` for why this crate lives outside the workspace.

pub mod devnet;
pub mod hn;
pub mod txbuild;
pub mod vault;
pub mod vault_epoch;
