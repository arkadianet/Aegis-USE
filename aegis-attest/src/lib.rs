//! Aegis attester federation — the k-of-n signing substrate (slice S1a,
//! `dev-docs/sidechain/attester-infra.md`).
//!
//! A single majority-honest federation serves two jobs off one secp256k1
//! keypair per attester: (R1) authorize bridge peg-out unlocks, verified in
//! Ergo consensus via native `atLeast(k, …)`; (R2) post the R1-T epoch
//! aggregate. This crate is only the shared *signing* substrate both roles
//! stand on — attester identity, the set + its threshold, and a domain-
//! separated attestation that k-of-n members co-sign.
//!
//! An attester's public key is a 33-byte SEC1-compressed secp256k1 point,
//! which is exactly an Ergo `GroupElement` — so the same key drops into the
//! peg-out vault's `atLeast` sigma proof and signs Aegis-side attestations.
//!
//! Scope guards: NO consensus, NO I/O, NO threshold *decryption* (R2's
//! ElGamal key is separate crypto, deferred). Signatures use `k256` ECDSA;
//! nothing is hand-rolled. Every message is bound to the set (`set_id`) and
//! a `Purpose`, so an attestation can never be replayed against a different
//! set or repurposed.

pub mod attestation;
pub mod key;
pub mod set;

pub use attestation::{Attestation, Purpose};
pub use key::{AttesterKey, KeyError, PublicKey, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES};
pub use set::{AttesterSet, SetError};
