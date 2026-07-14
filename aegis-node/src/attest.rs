//! S1b — the node attestation service (`dev-docs/sidechain/attester-infra.md`).
//!
//! An attester runs a full node and signs *which tip is on its best chain*,
//! so the bridge (and, later, R1-T) can consume a k-of-n attested view. The
//! attestation is **re-signed from the live snapshot on each request** —
//! nothing is stored on-chain, so this is additive and non-consensus. A
//! non-attester node simply has no [`AttesterContext`] and serves 404.
//!
//! The node's public key is a member of the federation's [`AttesterSet`];
//! the same key later co-signs the Ergo `atLeast` peg-out (slice S1c).

use aegis_attest::{Attestation, AttesterKey, AttesterSet, Purpose};

use crate::api::NodeStatus;

/// This node's attester identity: its signing key plus the federation it
/// belongs to. Built only when the operator configures an attester key.
#[derive(Clone)]
pub struct AttesterContext {
    key: AttesterKey,
    set: AttesterSet,
}

#[derive(Debug, thiserror::Error)]
pub enum AttesterConfigError {
    #[error("configured attester key is not a member of the attester set")]
    NotAMember,
}

impl AttesterContext {
    /// Bind a key to a set. Rejects a key that is not a member — a node
    /// whose attestations no one would count is a misconfiguration, not a
    /// silent no-op.
    pub fn new(key: AttesterKey, set: AttesterSet) -> Result<Self, AttesterConfigError> {
        if !set.contains(&key.public()) {
            return Err(AttesterConfigError::NotAMember);
        }
        Ok(AttesterContext { key, set })
    }

    /// The federation this node attests within.
    pub fn set(&self) -> &AttesterSet {
        &self.set
    }

    /// Sign this node's canonical tip.
    pub fn attest_tip(&self, status: &NodeStatus) -> Attestation {
        self.set
            .attest(&self.key, Purpose::Tip, &tip_payload(status))
    }
}

// Redacted: the public key + threshold are safe to print, the signing key
// never is (keeps it out of logs/panics when NodeConfig is `{:?}`-formatted).
impl std::fmt::Debug for AttesterContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttesterContext")
            .field("public", &hex::encode(self.key.public().to_bytes()))
            .field("k", &self.set.k())
            .field("n", &self.set.n())
            .finish_non_exhaustive()
    }
}

/// Canonical payload of a tip attestation:
/// `tip_id ‖ height(LE) ‖ nullifier_digest ‖ cm_tree_root` — the complete
/// committed tip state. A verifier rebuilds these bytes from the same
/// fields and calls `AttesterSet::verify(Purpose::Tip, payload, att)`.
pub fn tip_payload(status: &NodeStatus) -> Vec<u8> {
    let mut p = Vec::with_capacity(32 + 8 + 32 + 32);
    p.extend_from_slice(&status.canonical_tip);
    p.extend_from_slice(&status.canonical_height.to_le_bytes());
    p.extend_from_slice(&status.nullifier_digest);
    p.extend_from_slice(&status.cm_tree_root);
    p
}

/// Render `GET /aegis/v1/attest/tip`: the attested tip fields plus
/// everything a consumer needs to verify — `payload`, `signer`, and
/// `signature` feed straight into `AttesterSet::verify` against the
/// federation identified by `set_id`.
pub fn tip_attestation_json(ctx: &AttesterContext, status: &NodeStatus) -> serde_json::Value {
    let payload = tip_payload(status);
    let att = ctx.attest_tip(status);
    serde_json::json!({
        "purpose": "tip",
        "network": status.network_name,
        "height": status.canonical_height,
        "tip_id": hex::encode(status.canonical_tip),
        "nullifier_digest": hex::encode(status.nullifier_digest),
        "cm_tree_root": hex::encode(status.cm_tree_root),
        "set_id": hex::encode(ctx.set.set_id()),
        "k": ctx.set.k(),
        "n": ctx.set.n(),
        "signer": hex::encode(att.signer.to_bytes()),
        "signature": hex::encode(att.sig),
        "payload": hex::encode(&payload),
    })
}
