//! Blocking HTTP client for the node's read-only API (M4 slice 2).
//!
//! The wallet is a **client of the node** over its public `/aegis/v1/*`
//! surface (`wallet-design.md` §0) — the only outward contact, and it
//! never carries a secret. Blocking `reqwest` on purpose: the wallet is a
//! one-shot CLI, not an async service, and this mirrors the node's own
//! `ergo_follow`/`seed` blocking transport.
//!
//! Every endpoint response is a *public aggregate* or *self-authenticating
//! block bytes*; nothing here trusts the node with wallet data. Block
//! bytes are decoded locally via [`aegis_types::Block::from_bytes`].

use std::time::Duration;

use aegis_types::{Block, ShieldedTransfer};

/// Default per-request timeout (connect + response).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Node's spent-nullifier size (32-byte extract), re-exported for callers
/// building `/nullifier/{hex}` queries.
pub use aegis_crypto::nullifier::NF_BYTES;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("building blocking HTTP client")]
    Build(#[source] reqwest::Error),
    #[error("GET/POST {url} failed")]
    Network {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{url}: HTTP status {status}")]
    Status { url: String, status: u16 },
    #[error("{url}: response body not understood: {detail}")]
    Decode { url: String, detail: String },
    /// The node rejected a submitted transfer. `code` is the HTTP status
    /// (409 spent/conflict/no-anchor, 422 invalid proof, 503 mempool
    /// full, 400 malformed), `message` the node's plain-text reason.
    #[error("submit rejected ({code}): {message}")]
    Rejected { code: u16, message: String },
}

/// Node chain tip (`GET /tip`).
#[derive(Debug, Clone)]
pub struct Tip {
    pub network: String,
    pub height: u64,
    pub id: [u8; 32],
    pub timestamp_ms: u64,
    /// Cumulative PoW work as a decimal string (the wallet never does
    /// work arithmetic; kept verbatim).
    pub cumulative_work: String,
    pub is_final: bool,
}

/// Public shielded-state aggregates (`GET /state`).
#[derive(Debug, Clone)]
pub struct ChainState {
    pub height: u64,
    pub pot: u64,
    pub nullifier_count: u64,
    pub nullifier_digest: [u8; 32],
    pub cm_tree_root: [u8; 32],
    pub leaf_count: u64,
}

/// One row of the `GET /blocks` summary list.
#[derive(Debug, Clone)]
pub struct BlockSummary {
    pub height: u64,
    pub id: [u8; 32],
    pub timestamp_ms: u64,
    pub tx_count: u64,
    pub has_coinbase: bool,
}

/// A page of block summaries (`GET /blocks?from=&limit=`), newest first.
#[derive(Debug, Clone)]
pub struct BlocksPage {
    pub tip_height: u64,
    pub from: u64,
    pub blocks: Vec<BlockSummary>,
}

/// Outcome of `POST /tx`: the mempool admission verdict and the tx id.
#[derive(Debug, Clone)]
pub struct SubmitOutcome {
    /// `"new"` on first admission, `"duplicate"` if already pending.
    pub admitted: String,
    pub id: [u8; 32],
}

impl SubmitOutcome {
    pub fn is_new(&self) -> bool {
        self.admitted == "new"
    }
}

/// A read-only client bound to one node base URL.
#[derive(Debug, Clone)]
pub struct NodeClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

impl NodeClient {
    /// Bind to `base_url` (e.g. `http://127.0.0.1:9080`) with the default
    /// timeout.
    pub fn new(base_url: impl Into<String>) -> Result<Self, ClientError> {
        Self::with_timeout(base_url, DEFAULT_TIMEOUT)
    }

    /// Bind with an explicit per-request timeout.
    pub fn with_timeout(
        base_url: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let http = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(ClientError::Build)?;
        Ok(NodeClient {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// GET `path`, returning the JSON body or a typed error. `None` maps
    /// a 404 to a value; any other non-2xx is a [`ClientError::Status`].
    fn get_json(&self, path: &str) -> Result<serde_json::Value, ClientError> {
        let url = self.url(path);
        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|source| ClientError::Network {
                url: url.clone(),
                source,
            })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(ClientError::Status {
                url,
                status: status.as_u16(),
            });
        }
        let text = resp.text().map_err(|source| ClientError::Network {
            url: url.clone(),
            source,
        })?;
        serde_json::from_str(&text).map_err(|e| ClientError::Decode {
            url,
            detail: e.to_string(),
        })
    }

    pub fn tip(&self) -> Result<Tip, ClientError> {
        let url = self.url("/aegis/v1/tip");
        let v = self.get_json("/aegis/v1/tip")?;
        Ok(Tip {
            network: str_field(&v, "network", &url)?.to_string(),
            height: u64_field(&v, "height", &url)?,
            id: hash32_field(&v, "id", &url)?,
            timestamp_ms: u64_field(&v, "timestamp_ms", &url)?,
            cumulative_work: str_field(&v, "cumulative_work", &url)?.to_string(),
            is_final: bool_field(&v, "is_final", &url)?,
        })
    }

    pub fn state(&self) -> Result<ChainState, ClientError> {
        let url = self.url("/aegis/v1/state");
        let v = self.get_json("/aegis/v1/state")?;
        Ok(ChainState {
            height: u64_field(&v, "height", &url)?,
            pot: u64_field(&v, "pot", &url)?,
            nullifier_count: u64_field(&v, "nullifier_count", &url)?,
            nullifier_digest: hash32_field(&v, "nullifier_digest", &url)?,
            cm_tree_root: hash32_field(&v, "cm_tree_root", &url)?,
            leaf_count: u64_field(&v, "leaf_count", &url)?,
        })
    }

    /// A page of block summaries starting at height `from`, newest first.
    pub fn blocks(&self, from: u64, limit: u64) -> Result<BlocksPage, ClientError> {
        let path = format!("/aegis/v1/blocks?from={from}&limit={limit}");
        let url = self.url(&path);
        let v = self.get_json(&path)?;
        let rows =
            v.get("blocks")
                .and_then(|b| b.as_array())
                .ok_or_else(|| ClientError::Decode {
                    url: url.clone(),
                    detail: "missing `blocks` array".into(),
                })?;
        let blocks = rows
            .iter()
            .map(|row| {
                Ok(BlockSummary {
                    height: u64_field(row, "height", &url)?,
                    id: hash32_field(row, "id", &url)?,
                    timestamp_ms: u64_field(row, "timestamp_ms", &url)?,
                    tx_count: u64_field(row, "tx_count", &url)?,
                    has_coinbase: bool_field(row, "has_coinbase", &url)?,
                })
            })
            .collect::<Result<Vec<_>, ClientError>>()?;
        Ok(BlocksPage {
            tip_height: u64_field(&v, "tip_height", &url)?,
            from: u64_field(&v, "from", &url)?,
            blocks,
        })
    }

    /// Fetch and decode the full block with id `id`.
    pub fn block(&self, id: &[u8; 32]) -> Result<Block, ClientError> {
        let path = format!("/aegis/v1/block/{}", hex::encode(id));
        self.fetch_block(&path)?.ok_or_else(|| ClientError::Status {
            url: self.url(&path),
            status: 404,
        })
    }

    /// Fetch and decode the canonical block at `height`, or `None` if the
    /// node has none there (past its tip, or a gap).
    pub fn block_at(&self, height: u64) -> Result<Option<Block>, ClientError> {
        let path = format!("/aegis/v1/block/at/{height}");
        self.fetch_block(&path)
    }

    /// GET raw block bytes at `path`; `Ok(None)` on 404, decoded [`Block`]
    /// otherwise.
    fn fetch_block(&self, path: &str) -> Result<Option<Block>, ClientError> {
        let url = self.url(path);
        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|source| ClientError::Network {
                url: url.clone(),
                source,
            })?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(ClientError::Status {
                url,
                status: status.as_u16(),
            });
        }
        let bytes = resp.bytes().map_err(|source| ClientError::Network {
            url: url.clone(),
            source,
        })?;
        Block::from_bytes(&bytes)
            .map(Some)
            .map_err(|e| ClientError::Decode {
                url,
                detail: format!("block decode: {e}"),
            })
    }

    /// Whether nullifier `nf` is recorded spent on-chain (`GET
    /// /nullifier/{hex}`) — the confirm-a-spend query.
    pub fn nullifier(&self, nf: &[u8; NF_BYTES]) -> Result<bool, ClientError> {
        let path = format!("/aegis/v1/nullifier/{}", hex::encode(nf));
        let url = self.url(&path);
        let v = self.get_json(&path)?;
        bool_field(&v, "spent", &url)
    }

    /// Submit a shielded transfer (`POST /tx`). Ok on 200 (new or
    /// duplicate); a non-2xx is a [`ClientError::Rejected`] carrying the
    /// node's status + reason.
    pub fn submit(&self, tx: &ShieldedTransfer) -> Result<SubmitOutcome, ClientError> {
        let url = self.url("/aegis/v1/tx");
        let resp = self
            .http
            .post(&url)
            .body(tx.bytes())
            .send()
            .map_err(|source| ClientError::Network {
                url: url.clone(),
                source,
            })?;
        let status = resp.status();
        let text = resp.text().map_err(|source| ClientError::Network {
            url: url.clone(),
            source,
        })?;
        if !status.is_success() {
            return Err(ClientError::Rejected {
                code: status.as_u16(),
                message: text.trim().to_string(),
            });
        }
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| ClientError::Decode {
                url: url.clone(),
                detail: e.to_string(),
            })?;
        Ok(SubmitOutcome {
            admitted: str_field(&v, "admitted", &url)?.to_string(),
            id: hash32_field(&v, "id", &url)?,
        })
    }
}

// ----- small JSON field extractors (typed errors, no serde derive) -----

fn field<'a>(
    v: &'a serde_json::Value,
    key: &str,
    url: &str,
) -> Result<&'a serde_json::Value, ClientError> {
    v.get(key).ok_or_else(|| ClientError::Decode {
        url: url.to_string(),
        detail: format!("missing field `{key}`"),
    })
}

fn u64_field(v: &serde_json::Value, key: &str, url: &str) -> Result<u64, ClientError> {
    field(v, key, url)?
        .as_u64()
        .ok_or_else(|| ClientError::Decode {
            url: url.to_string(),
            detail: format!("field `{key}` is not a u64"),
        })
}

fn bool_field(v: &serde_json::Value, key: &str, url: &str) -> Result<bool, ClientError> {
    field(v, key, url)?
        .as_bool()
        .ok_or_else(|| ClientError::Decode {
            url: url.to_string(),
            detail: format!("field `{key}` is not a bool"),
        })
}

fn str_field<'a>(v: &'a serde_json::Value, key: &str, url: &str) -> Result<&'a str, ClientError> {
    field(v, key, url)?
        .as_str()
        .ok_or_else(|| ClientError::Decode {
            url: url.to_string(),
            detail: format!("field `{key}` is not a string"),
        })
}

fn hash32_field(v: &serde_json::Value, key: &str, url: &str) -> Result<[u8; 32], ClientError> {
    let s = str_field(v, key, url)?;
    let bytes = hex::decode(s).map_err(|e| ClientError::Decode {
        url: url.to_string(),
        detail: format!("field `{key}` is not hex: {e}"),
    })?;
    bytes.try_into().map_err(|_| ClientError::Decode {
        url: url.to_string(),
        detail: format!("field `{key}` is not 32 bytes"),
    })
}
