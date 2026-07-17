//! # aegis-engine — the hash-native private-payment core (Option B)
//!
//! A from-scratch shielded-pool crypto core over **BabyBear + Poseidon2 + FRI**,
//! the crown-jewel rebuild that replaces Aegis's Curve-Trees/Bulletproofs
//! (elliptic-curve) engine. Going fully hash-native removes *all* elliptic-curve
//! arithmetic from the client spend proof, so the proof's verifier is FRI/hash
//! native — the precondition for cheap trustless settlement (a RISC0 guest over
//! the same field re-verifies client proofs with no foreign-curve MSM). See
//! `dev-docs/sidechain/hash-native-engine-design.md`.
//!
//! ## Layers (built bottom-up)
//! - [`poseidon`] — the one hash primitive (Poseidon2-t16 over BabyBear), shared
//!   by native code and the AIR via one pinned constant set.
//! - [`commit`] — note commitment `cm = H(value, owner, rho, r)` and owner key
//!   `owner = H(nk)` (hash-based — NO `nk·B`, no curve).
//! - [`nullifier`] — `nf = H(nk, rho)`, the N1 scheme re-expressed over BabyBear.
//! - [`merkle`] — the depth-32 Poseidon-Merkle note accumulator (append + path),
//!   replacing the Curve Tree.
//! - [`spend`] — the 2-in/2-out spend circuit as a Plonky3 uni-STARK AIR.
//!
//! **Status:** testnet/devnet crypto pending full external review — same gate as
//! the current engine. Not wired into any consensus path.

pub mod address;
pub mod commit;
pub mod config;
pub mod merkle;
pub mod note_encryption;
pub mod nullifier;
pub mod poseidon;
pub mod spend;
