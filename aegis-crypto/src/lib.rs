//! Aegis note-protocol numeric core (note-protocol.md §0/§1/§3).
//!
//! Charter: field/curve-level primitives only — generators, commitments,
//! nullifiers, and their test vectors. No circuits (Phase 3), no wallet
//! logic, no I/O. Everything consensus-critical here is pinned by
//! committed vectors under `test-vectors/aegis/` produced by an
//! independent reference implementation.

pub mod generators;
pub mod h2c;
pub mod keynote;
pub mod mint;
pub mod note;
pub mod nullifier;
pub mod payment;
pub mod poseidon;
pub mod spend;
pub mod tree;

/// Even-cycle curve (`E_even` = secp256k1): note commitments live here.
pub use ark_secp256k1 as even;
/// Odd-cycle curve (`E_odd` = secq256k1): nullifiers live here.
pub use ark_secq256k1 as odd;
