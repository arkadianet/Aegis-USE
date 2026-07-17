//! A REMOTE-wallet `ChainView` over the hn HTTP surface ([`super::api`]). This
//! is what the e2e campaign drives: a wallet holding only its keys + a node URL
//! builds and submits spends without any in-process access to node state.
//!
//! The `ChainView` trait is infallible (it mirrors the in-process view), so
//! network/decoding failures here `expect` — a production client would surface
//! them as errors; the shape is otherwise identical.

use aegis_engine::merkle::MerklePath;
use aegis_engine::poseidon::{digest_from_bytes, digest_to_bytes, Digest};
use aegis_hn_wallet::chain::OutputRecord;
use aegis_hn_wallet::{ChainView, Tx};

/// A wallet-facing HTTP client for an hn node.
pub struct HttpChain {
    base: String,
    client: reqwest::blocking::Client,
}

impl HttpChain {
    pub fn new(base_url: impl Into<String>) -> Self {
        // A per-request timeout so a stalled/unreachable peer surfaces as a
        // failed fetch (empty result) rather than hanging the caller — a
        // follower must not block its produce/serve loop on a dead peer.
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("build reqwest client");
        Self {
            base: base_url.into(),
            client,
        }
    }

    fn get(&self, path: &str) -> Option<String> {
        let resp = self
            .client
            .get(format!("{}{path}", self.base))
            .send()
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.text().ok()
    }

    fn get_hex(&self, path: &str) -> Option<Vec<u8>> {
        hex::decode(self.get(path)?).ok()
    }

    /// Submit a tx to the node's mempool (`POST /hn/v1/tx`). Ok on admission.
    pub fn submit(&self, tx: &Tx) -> Result<(), String> {
        let body = postcard::to_allocvec(tx).expect("tx serializes");
        let resp = self
            .client
            .post(format!("{}/hn/v1/tx", self.base))
            .body(body)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(resp.text().unwrap_or_default())
        }
    }

    /// The peer's block count (== its height) — the sync target.
    pub fn peer_block_count(&self) -> u64 {
        self.get("/hn/v1/blockcount")
            .and_then(|t| t.parse().ok())
            .unwrap_or(0)
    }

    /// Fetch the peer's blocks with height `>= from` (the IBD / gossip pull).
    pub fn fetch_blocks(&self, from: u64) -> Vec<super::state::HnBlock> {
        match self.get_hex(&format!("/hn/v1/blocks?from={from}")) {
            Some(bytes) => postcard::from_bytes(&bytes).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Submit a peg-out (`POST /hn/v1/pegout`).
    pub fn submit_pegout(&self, po: &super::state::PegOutTx) -> Result<(), String> {
        let body = postcard::to_allocvec(po).expect("pegout serializes");
        let resp = self
            .client
            .post(format!("{}/hn/v1/pegout", self.base))
            .body(body)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(resp.text().unwrap_or_default())
        }
    }

    /// The node's recorded withdrawals (`GET /hn/v1/withdrawals`).
    pub fn withdrawals(&self) -> Vec<super::state::Withdrawal> {
        match self.get_hex("/hn/v1/withdrawals") {
            Some(bytes) => postcard::from_bytes(&bytes).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Fetch the peer's mempool (tx gossip pull).
    pub fn fetch_mempool(&self) -> Vec<Tx> {
        match self.get_hex("/hn/v1/mempool") {
            Some(bytes) => postcard::from_bytes(&bytes).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Trigger block production (`POST /hn/v1/mine`) — a dev/test hook.
    pub fn mine(&self) -> Result<(), String> {
        let resp = self
            .client
            .post(format!("{}/hn/v1/mine", self.base))
            .send()
            .map_err(|e| e.to_string())?;
        resp.status()
            .is_success()
            .then_some(())
            .ok_or_else(|| resp.text().unwrap_or_default())
    }
}

impl ChainView for HttpChain {
    fn current_root(&self) -> Digest {
        let bytes: [u8; 32] = self
            .get_hex("/hn/v1/root")
            .expect("root")
            .try_into()
            .expect("32 bytes");
        digest_from_bytes(&bytes).expect("canonical root")
    }
    fn authentication_path(&self, leaf_index: u64) -> Option<MerklePath> {
        let bytes = self.get_hex(&format!("/hn/v1/path/{leaf_index}"))?;
        postcard::from_bytes(&bytes).ok()
    }
    fn nullifier_seen(&self, nf: &Digest) -> bool {
        let hexs = hex::encode(digest_to_bytes(nf));
        self.get(&format!("/hn/v1/nullifier/{hexs}"))
            .map(|t| t == "true")
            .unwrap_or(false)
    }
    fn outputs_since(&self, cursor: u64) -> Vec<OutputRecord> {
        let bytes = self
            .get_hex(&format!("/hn/v1/outputs?from={cursor}"))
            .expect("outputs");
        postcard::from_bytes(&bytes).expect("outputs decode")
    }
    fn output_count(&self) -> u64 {
        self.get("/hn/v1/count")
            .and_then(|t| t.parse().ok())
            .expect("count")
    }
    fn tip_height(&self) -> u64 {
        self.get("/hn/v1/tipheight")
            .and_then(|t| t.parse().ok())
            .expect("tipheight")
    }
}
