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

use aegis_attest::{Attestation, AttesterKey, AttesterSet, KeyError, PublicKey, Purpose, SetError};

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

#[derive(Debug, thiserror::Error)]
pub enum AttesterLoadError {
    #[error("attester key file is not valid JSON: {0}")]
    Json(String),
    #[error("attester key file missing or non-string field `{0}`")]
    Field(&'static str),
    #[error("field `{0}` is not valid fixed-length hex")]
    Hex(&'static str),
    #[error("key: {0}")]
    Key(#[from] KeyError),
    #[error("set: {0}")]
    Set(#[from] SetError),
    #[error(transparent)]
    Config(#[from] AttesterConfigError),
}

/// Load an attester identity from a JSON key file:
/// ```json
/// { "secret": "<32-byte hex>", "members": ["<33-byte hex>", …], "k": <n> }
/// ```
/// `members` is the full federation (including this node's own public key);
/// the loader rejects a `secret` whose public key is not among them.
pub fn load_attester(json: &str) -> Result<AttesterContext, AttesterLoadError> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| AttesterLoadError::Json(e.to_string()))?;

    let secret = decode_hex::<32>(
        v["secret"]
            .as_str()
            .ok_or(AttesterLoadError::Field("secret"))?,
    )
    .ok_or(AttesterLoadError::Hex("secret"))?;
    let key = AttesterKey::from_secret_bytes(&secret)?;

    let raw = v["members"]
        .as_array()
        .ok_or(AttesterLoadError::Field("members"))?;
    let mut members = Vec::with_capacity(raw.len());
    for m in raw {
        let hex = m.as_str().ok_or(AttesterLoadError::Field("members"))?;
        let bytes = decode_hex::<33>(hex).ok_or(AttesterLoadError::Hex("members"))?;
        members.push(PublicKey::from_bytes(&bytes)?);
    }

    let k = v["k"].as_u64().ok_or(AttesterLoadError::Field("k"))? as usize;
    let set = AttesterSet::new(members, k)?;
    Ok(AttesterContext::new(key, set)?)
}

/// Decode a hex string into exactly `N` bytes, or `None`.
fn decode_hex<const N: usize>(h: &str) -> Option<[u8; N]> {
    hex::decode(h).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> AttesterKey {
        AttesterKey::from_secret_bytes(&[seed; 32]).expect("valid scalar")
    }

    /// A key-file JSON for `secret_seed`'s key over the federation
    /// `member_seeds` at threshold `k`.
    fn key_file(secret_seed: u8, member_seeds: &[u8], k: usize) -> String {
        let members: Vec<String> = member_seeds
            .iter()
            .map(|s| hex::encode(key(*s).public().to_bytes()))
            .collect();
        serde_json::json!({
            "secret": hex::encode([secret_seed; 32]),
            "members": members,
            "k": k,
        })
        .to_string()
    }

    #[test]
    fn load_attester_valid_file_builds_context() {
        let ctx = load_attester(&key_file(1, &[1, 2, 3], 2)).expect("loads");
        assert_eq!(ctx.set().k(), 2);
        assert_eq!(ctx.set().n(), 3);
    }

    #[test]
    fn load_attester_rejects_non_member_secret() {
        // Secret for seed 9, but the federation is seeds 1..3.
        let err = load_attester(&key_file(9, &[1, 2, 3], 2)).unwrap_err();
        assert!(matches!(err, AttesterLoadError::Config(_)));
    }

    #[test]
    fn load_attester_rejects_bad_json() {
        assert!(matches!(
            load_attester("not json"),
            Err(AttesterLoadError::Json(_))
        ));
    }

    #[test]
    fn load_attester_rejects_short_secret_hex() {
        let json = serde_json::json!({ "secret": "00", "members": [], "k": 1 }).to_string();
        assert!(matches!(
            load_attester(&json),
            Err(AttesterLoadError::Hex("secret"))
        ));
    }
}
