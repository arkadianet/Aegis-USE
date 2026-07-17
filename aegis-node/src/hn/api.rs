//! The hash-native wallet-facing HTTP surface: the `ChainView` reads
//! (root / path / outputs / nullifier / count / status) + tx submit + a mine
//! trigger, over the node's minimalist std-`TcpListener` pattern (mirrors
//! `crate::api::serve` — one connection at a time, close after response; no
//! async runtime, no TLS). A REMOTE wallet drives these via [`super::http_client`].
//!
//! Bodies are `postcard` (the on-wire tx/proof format) hex-encoded for the GET
//! responses, matching the wallet types exactly so a client round-trips them
//! with no bespoke schema.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use aegis_engine::address::Address;
use aegis_engine::poseidon::{digest_from_bytes, digest_to_bytes};
use aegis_hn_wallet::{ChainView, Tx};

use super::chain::HnChain;

const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);
/// POST body cap (a hiding proof + fixed fields + slack).
const MAX_BODY: usize = 4 * 1024 * 1024;

/// Shared node handle: the chain behind a mutex + the miner address the `mine`
/// trigger pays the coinbase to.
#[derive(Clone)]
pub struct HnApiState {
    pub chain: Arc<Mutex<HnChain>>,
    pub miner: Address,
}

/// A running hn HTTP server; shuts down (and joins) on drop.
pub struct HnApiServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl HnApiServer {
    pub fn spawn(bind_addr: &str, state: HnApiState) -> std::io::Result<Self> {
        let listener = TcpListener::bind(bind_addr)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let tstop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if tstop.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(stream) = conn {
                    let _ = handle_conn(stream, &state);
                }
            }
        });
        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
        })
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for HnApiServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn respond(s: &mut TcpStream, code: u16, body: &[u8]) -> std::io::Result<()> {
    let reason = if code == 200 { "OK" } else { "ERR" };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body)?;
    s.flush()
}

fn handle_conn(mut s: TcpStream, state: &HnApiState) -> std::io::Result<()> {
    s.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    s.set_write_timeout(Some(SOCKET_TIMEOUT))?;

    // Read headers (until CRLFCRLF), then the body by Content-Length.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let head_end = loop {
        let n = s.read(&mut tmp)?;
        if n == 0 {
            return respond(&mut s, 400, b"bad request");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_crlf2(&buf) {
            break pos;
        }
        if buf.len() > MAX_BODY {
            return respond(&mut s, 413, b"too large");
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let Some(reqline) = lines.next() else {
        return respond(&mut s, 400, b"bad request");
    };
    let mut it = reqline.split_whitespace();
    let (method, target) = match (it.next(), it.next()) {
        (Some(m), Some(t)) => (m, t),
        _ => return respond(&mut s, 400, b"bad request"),
    };
    let content_length: usize = lines
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim().eq_ignore_ascii_case("content-length"))
                .then(|| v.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0);

    if method == "POST" {
        let mut body = buf[head_end + 4..].to_vec();
        while body.len() < content_length {
            let n = s.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(content_length);
        return handle_post(&mut s, state, target, &body);
    }
    handle_get(&mut s, state, target)
}

fn handle_get(s: &mut TcpStream, state: &HnApiState, target: &str) -> std::io::Result<()> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let chain = state.chain.lock().unwrap();
    match path {
        "/hn/v1/status" => {
            let root = hex::encode(digest_to_bytes(&chain.current_root()));
            respond(
                s,
                200,
                format!(
                    "{{\"height\":{},\"count\":{},\"pot\":{},\"root\":\"{root}\"}}",
                    chain.height(),
                    chain.output_count(),
                    chain.pot()
                )
                .as_bytes(),
            )
        }
        // The pinned chain-economic parameters (a remote wallet reads the flat
        // fee + maturity here instead of hardcoding them).
        "/hn/v1/params" => {
            let p = chain.params();
            respond(
                s,
                200,
                format!(
                    "{{\"chain_id\":{},\"flat_fee\":{},\"coinbase_base\":{},\
                     \"coinbase_per_tx\":{},\"coinbase_maturity\":{},\
                     \"root_window\":{},\"genesis_pot\":{}}}",
                    p.chain_id,
                    p.flat_fee,
                    p.coinbase_base,
                    p.coinbase_per_tx,
                    p.coinbase_maturity,
                    p.root_window,
                    p.genesis_pot
                )
                .as_bytes(),
            )
        }
        "/hn/v1/root" => respond(
            s,
            200,
            hex::encode(digest_to_bytes(&chain.current_root())).as_bytes(),
        ),
        "/hn/v1/count" => respond(s, 200, chain.output_count().to_string().as_bytes()),
        "/hn/v1/tipheight" => respond(s, 200, chain.tip_height().to_string().as_bytes()),
        // ----- P2P block feed (a syncing peer pulls blocks from `from`) -----
        "/hn/v1/blockcount" => respond(s, 200, chain.block_count().to_string().as_bytes()),
        "/hn/v1/mempool" => respond(
            s,
            200,
            hex::encode(postcard::to_allocvec(&chain.mempool_txs()).unwrap()).as_bytes(),
        ),
        "/hn/v1/blocks" => {
            let from: u64 = query
                .split_once('=')
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            respond(
                s,
                200,
                hex::encode(postcard::to_allocvec(&chain.blocks_since(from)).unwrap()).as_bytes(),
            )
        }
        "/hn/v1/outputs" => {
            let from: u64 = query
                .split_once('=')
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            let recs = chain.outputs_since(from);
            respond(
                s,
                200,
                hex::encode(postcard::to_allocvec(&recs).unwrap()).as_bytes(),
            )
        }
        p if p.starts_with("/hn/v1/path/") => match p["/hn/v1/path/".len()..].parse::<u64>() {
            Ok(idx) => match chain.authentication_path(idx) {
                Some(path) => respond(
                    s,
                    200,
                    hex::encode(postcard::to_allocvec(&path).unwrap()).as_bytes(),
                ),
                None => respond(s, 404, b"no such leaf"),
            },
            Err(_) => respond(s, 400, b"bad index"),
        },
        p if p.starts_with("/hn/v1/nullifier/") => {
            let hexs = &p["/hn/v1/nullifier/".len()..];
            match hex::decode(hexs).ok().and_then(|b| b.try_into().ok()) {
                Some(bytes) => match digest_from_bytes(&bytes) {
                    Some(nf) => respond(
                        s,
                        200,
                        if chain.nullifier_seen(&nf) {
                            b"true"
                        } else {
                            b"false"
                        },
                    ),
                    None => respond(s, 400, b"non-canonical"),
                },
                None => respond(s, 400, b"bad nullifier"),
            }
        }
        _ => respond(s, 404, b"not found"),
    }
}

fn handle_post(
    s: &mut TcpStream,
    state: &HnApiState,
    target: &str,
    body: &[u8],
) -> std::io::Result<()> {
    match target {
        "/hn/v1/tx" => {
            let Ok(tx) = postcard::from_bytes::<Tx>(body) else {
                return respond(s, 400, b"bad tx");
            };
            let mut chain = state.chain.lock().unwrap();
            match chain.submit(tx) {
                Ok(()) => respond(s, 200, b"ok"),
                Err(e) => respond(s, 409, e.to_string().as_bytes()),
            }
        }
        // Mine one block (test/dev trigger; a real node mines on its own loop).
        "/hn/v1/mine" => {
            let mut chain = state.chain.lock().unwrap();
            match chain.produce_block(&state.miner) {
                Ok(()) => respond(s, 200, b"mined"),
                Err(e) => respond(s, 409, e.to_string().as_bytes()),
            }
        }
        _ => respond(s, 404, b"not found"),
    }
}

fn find_crlf2(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}
