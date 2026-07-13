//! LIVE header-feed oracle for `ergo_follow::poll_http::RestHeaderSource`.
//!
//! Drives a [`Follower`] from (tip − 30) to the live Scala testnet
//! node's tip over real `GET /blocks/chainSlice` pages: real header
//! JSON, real Autolykos v2 PoW (`apply_header` gates every header),
//! real pagination (page_size below the span forces multiple pages).
//!
//! ## Skip gate
//! CI has no node: the test first probes `GET /info` on
//! `127.0.0.1:9062` with a short timeout and SKIPs (eprintln + return,
//! reported as `ok`) when unreachable — same spirit as the repo's
//! other live-oracle skips (`[skipped]` in `popow_prove_mainnet.rs`,
//! `[m7-oracle] … skip`). `AEGIS_LIVE_NODE_URL` overrides the node
//! address.

use std::time::Duration;

use aegis_node::ergo_follow::poll::drive;
use aegis_node::ergo_follow::poll_http::{RestHeaderSource, RestSourceConfig};
use aegis_node::ergo_follow::Follower;

// ----- helpers -----

const DEFAULT_NODE_URL: &str = "http://127.0.0.1:9062";

fn node_url() -> String {
    std::env::var("AEGIS_LIVE_NODE_URL").unwrap_or_else(|_| DEFAULT_NODE_URL.into())
}

/// Probe `GET /info`; `Some(headers_height)` iff a node is reachable
/// and answering sanely. Any failure means "skip", not "fail" — the
/// live oracle is opportunistic.
fn probe_headers_height(base_url: &str) -> Option<u32> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;
    let response = client
        .get(format!("{}/info", base_url.trim_end_matches('/')))
        .send()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    // `text()` + serde_json: the crate links reqwest with the
    // `blocking` feature only (no `json`).
    let info: serde_json::Value = serde_json::from_str(&response.text().ok()?).ok()?;
    let height = info.get("headersHeight")?.as_u64()?;
    u32::try_from(height).ok().filter(|h| *h > 100)
}

// ----- oracle parity -----

#[test]
fn live_rest_source_follows_testnet_chain_to_tip() {
    let base_url = node_url();
    let Some(node_tip) = probe_headers_height(&base_url) else {
        eprintln!("[skipped] no live Ergo node at {base_url} — live REST follow oracle not run");
        return;
    };

    const N_MINT: u64 = 10;
    let start = node_tip - 30;
    let mut follower = Follower::new(N_MINT);
    let mut config = RestSourceConfig::new(&base_url);
    // Force real pagination: ≥ 31 headers over ≥ 4 chainSlice pages.
    config.page_size = 8;
    let mut source = RestHeaderSource::new(config).expect("blocking client builds");

    let mut from_height = start;
    let mut followed = 0usize;
    // Bounded loop: each non-empty batch advances the tip, an empty
    // batch means caught up (the source filters the node's beyond-tip
    // clamp down to an empty page). 32 rounds cover the 31-header span
    // plus generous tip advance during the run.
    for _ in 0..32 {
        let outcomes = drive(&mut follower, &mut source, from_height)
            .expect("live headers decode, PoW-verify, and chain");
        if outcomes.is_empty() {
            break;
        }
        followed += outcomes.len();
        from_height = follower.tip_height().expect("non-empty drive set a tip") + 1;
    }

    assert!(followed >= 20, "followed only {followed} headers");
    let tip = follower.tip_height().expect("tip after follow");
    assert!(
        tip >= node_tip,
        "follower tip {tip} below probed tip {node_tip}"
    );

    let settled = follower
        .settled_reference()
        .expect("31+ headers is deeper than N_mint");
    assert_eq!(
        u64::from(settled.height),
        u64::from(tip) - N_MINT,
        "settled reference must sit at tip − N_mint"
    );

    let view = follower
        .settled_view(tip - 10)
        .expect("follower is caught up past tip − 10");
    assert!(!view.is_empty(), "settled view must hold headers");

    eprintln!(
        "[live] followed {followed} headers from {start} to tip {tip}; \
         settled_reference at {} (id {})",
        settled.height,
        hex::encode(settled.id),
    );
}
