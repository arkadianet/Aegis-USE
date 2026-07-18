//! Thin REST client for the STARK devnet (API consumer ONLY — never touches
//! the devnet's code or deployment).

use anyhow::{anyhow, Context, Result};

pub struct Devnet {
    base: String,
    key: String,
    http: reqwest::blocking::Client,
}

impl Devnet {
    pub fn new(base: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            key: key.into(),
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("client"),
        }
    }

    fn get(&self, path: &str) -> Result<serde_json::Value> {
        let r = self
            .http
            .get(format!("{}{path}", self.base))
            .header("api_key", &self.key)
            .send()
            .with_context(|| format!("GET {path}"))?;
        let status = r.status();
        let v: serde_json::Value = r.json().with_context(|| format!("GET {path} json"))?;
        if !status.is_success() {
            return Err(anyhow!("GET {path} -> {status}: {v}"));
        }
        Ok(v)
    }

    fn post(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        let r = self
            .http
            .post(format!("{}{path}", self.base))
            .header("api_key", &self.key)
            .json(&body)
            .send()
            .with_context(|| format!("POST {path}"))?;
        let status = r.status();
        let v: serde_json::Value = r.json().with_context(|| format!("POST {path} json"))?;
        if !status.is_success() {
            return Err(anyhow!("POST {path} -> {status}: {v}"));
        }
        Ok(v)
    }

    pub fn height(&self) -> Result<u64> {
        Ok(self.get("/info")?["fullHeight"].as_u64().unwrap_or(0))
    }

    pub fn wallet_address(&self) -> Result<String> {
        self.get("/wallet/addresses")?[0]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("no wallet address"))
    }

    /// Unspent wallet boxes as raw JSON entries (boxId/value/…).
    pub fn wallet_unspent(&self) -> Result<Vec<serde_json::Value>> {
        let v = self.get("/wallet/boxes/unspent")?;
        Ok(v["items"]
            .as_array()
            .or_else(|| v.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// Fetch one UTXO by box id (full JSON incl. `assets`; the wallet unspent
    /// listing is paged and omits assets on this node).
    pub fn box_by_id(&self, id: &str) -> Result<serde_json::Value> {
        self.get(&format!("/utxo/byId/{id}"))
    }

    /// Pick a pure-ERG wallet box with at least `min_value` nanoErg.
    pub fn pick_erg_box(&self, min_value: u64) -> Result<(String, u64)> {
        for b in self.wallet_unspent()? {
            let value = b["value"].as_u64().unwrap_or(0);
            let has_assets = b["assets"].as_array().is_some_and(|a| !a.is_empty());
            if value >= min_value && !has_assets {
                return Ok((b["boxId"].as_str().unwrap_or_default().to_string(), value));
            }
        }
        Err(anyhow!("no wallet box with >= {min_value} nanoErg"))
    }

    /// Ask the node wallet to sign an unsigned tx (hex wire bytes) — returns
    /// the SIGNED tx wire bytes.
    pub fn sign(&self, unsigned_hex: &str) -> Result<Vec<u8>> {
        let v = self.post(
            "/wallet/transaction/sign",
            serde_json::json!({ "unsignedTx": { "bytes": unsigned_hex } }),
        )?;
        let hex_s = v["transaction"]["bytes"]
            .as_str()
            .ok_or_else(|| anyhow!("sign response missing transaction.bytes: {v}"))?;
        Ok(hex::decode(hex_s)?)
    }

    /// Submit signed tx wire bytes; returns the tx id.
    pub fn submit(&self, tx_bytes: &[u8]) -> Result<String> {
        let v = self.post(
            "/transactions/bytes",
            serde_json::Value::String(hex::encode(tx_bytes)),
        )?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("submit response not a tx id: {v}"))
    }

    /// Block until `predicate` height reached (devnet mines ~1 block/s).
    pub fn wait_height(&self, h: u64) -> Result<()> {
        loop {
            if self.height()? >= h {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
}
