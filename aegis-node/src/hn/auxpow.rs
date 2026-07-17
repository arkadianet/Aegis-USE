//! Merge-mining: the STARK-devnet anchor the hn miner binds each block to.
//!
//! The Aegis miner solves the devnet's Autolykos PoW; each hn block references
//! the devnet header that PoW produced, so hn liveness is paced by — and
//! (once the full binding lands) secured by — the devnet's proof-of-work chain.
//!
//! This module fetches the current devnet best header via the node's REST API
//! (`GET /info`). It NEVER touches the devnet's code/deployment — API consumer
//! only. The full aux-PoW binding (the devnet block's extension Merkle-commits
//! to the hn `state_root`, verified with `ergo_crypto::autolykos::v2` + a
//! `BatchMerkleProof` — the machinery in `crate::auxpow`) is the documented
//! consensus surface still to close; see [`super::state::AuxAnchor`].

use super::state::AuxAnchor;

/// Fetch the devnet's current best header as an [`AuxAnchor`]. `None` if the
/// devnet is unreachable or the response is missing the expected fields.
pub fn fetch_devnet_anchor(api_url: &str, api_key: &str) -> Option<AuxAnchor> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    let text = client
        .get(format!("{api_url}/info"))
        .header("api_key", api_key)
        .send()
        .ok()?
        .text()
        .ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let id_hex = json.get("bestHeaderId")?.as_str()?;
    let height = json
        .get("fullHeight")
        .and_then(|v| v.as_u64())
        .or_else(|| json.get("headersHeight").and_then(|v| v.as_u64()))?;
    let id: [u8; 32] = hex::decode(id_hex).ok()?.try_into().ok()?;
    Some(AuxAnchor {
        devnet_header_id: id,
        devnet_height: height,
    })
}
