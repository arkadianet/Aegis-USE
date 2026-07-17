//! Devnet vault watcher — the peg-in observation side of the trustless bridge.
//!
//! Polls the STARK devnet's REST API (consumer only, like [`super::auxpow`])
//! and maintains an in-memory map of USE deposits made to the PegVault
//! address: any tx output whose `ergoTree` equals the vault tree, carrying the
//! test-USE token and an `R4` register whose payload is exactly 64 bytes —
//! `sc_dest` = owner digest (32 bytes, canonical LE `u32` limbs, the
//! [`aegis_engine::poseidon::digest_to_bytes`] layout) ‖ enc_pk (32 bytes).
//!
//! Two consumers share the map:
//! - the PRODUCER pulls [`VaultWatch::confirmed_claims`] (deposits at the
//!   pinned depth) and queues them for the next block;
//! - every node's [`super::chain::PegInCheck`] (from [`VaultWatch::checker`])
//!   re-checks claims in INGESTED blocks against its own view — a claim not
//!   yet confirmed locally defers the sync, it never hard-rejects.
//!
//! Real devnet block JSON shape (verified against the live node):
//! `{"header":{"height":N,...},"blockTransactions":{"transactions":[{"outputs":
//! [{"boxId":hex,"ergoTree":hex,"assets":[{"tokenId":hex,"amount":N}],
//! "additionalRegisters":{"R4":"0e40"+128-hex},...}]}]}}`;
//! `GET /blocks/at/{h}` returns a JSON array of header-id hex strings.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aegis_engine::address::Address;
use aegis_engine::poseidon::digest_from_bytes;

use super::chain::PegInCheck;
use super::mint::pegmint_note;
use super::params::HnChainParams;
use super::state::{digest_to_limbs, PegInClaim};

/// Cap on heights scanned per [`VaultWatch::poll`] so a deep start height
/// cannot wedge a node tick; the cursor advances across ticks.
const MAX_HEIGHTS_PER_POLL: u64 = 512;

/// One observed vault deposit.
#[derive(Clone, Debug, PartialEq)]
struct Deposit {
    dest_owner: [u32; 8],
    dest_enc_pk: [u8; 32],
    amount: u64,
    inclusion_height: u64,
}

/// The shared view: deposits + the devnet tip they are judged against.
#[derive(Default)]
struct Inner {
    deposits: HashMap<[u8; 32], Deposit>,
    latest_height: u64,
}

/// Polls the devnet for vault deposits; see the module docs.
pub struct VaultWatch {
    inner: Arc<Mutex<Inner>>,
    client: reqwest::blocking::Client,
    api_url: String,
    api_key: String,
    vault_tree: Vec<u8>,
    use_token_id: [u8; 32],
    confirmations: u64,
    params: HnChainParams,
    /// Next devnet height to scan.
    cursor: u64,
}

impl VaultWatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_url: impl Into<String>,
        api_key: impl Into<String>,
        vault_ergo_tree: Vec<u8>,
        use_token_id: [u8; 32],
        confirmations: u64,
        start_height: u64,
        params: HnChainParams,
    ) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            client,
            api_url: api_url.into(),
            api_key: api_key.into(),
            vault_tree: vault_ergo_tree,
            use_token_id,
            confirmations,
            params,
            cursor: start_height.max(1),
        }
    }

    fn get_json(&self, path: &str) -> Option<serde_json::Value> {
        let text = self
            .client
            .get(format!("{}{path}", self.api_url))
            .header("api_key", self.api_key.clone())
            .send()
            .ok()?
            .text()
            .ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Scan new devnet blocks from the cursor toward the tip (bounded per
    /// call). Network/JSON failures stop the scan; the next poll retries from
    /// the same height. Never panics.
    pub fn poll(&mut self) {
        let Some(info) = self.get_json("/info") else {
            return;
        };
        let Some(tip) = info
            .get("fullHeight")
            .and_then(|v| v.as_u64())
            .or_else(|| info.get("headersHeight").and_then(|v| v.as_u64()))
        else {
            return;
        };
        self.inner.lock().unwrap().latest_height = tip;

        let stop = tip.min(self.cursor + MAX_HEIGHTS_PER_POLL);
        while self.cursor <= stop {
            let h = self.cursor;
            let Some(ids) = self.get_json(&format!("/blocks/at/{h}")) else {
                return; // retry this height next poll
            };
            let Some(ids) = ids.as_array() else {
                return;
            };
            for id in ids {
                let Some(id) = id.as_str() else { continue };
                let Some(block) = self.get_json(&format!("/blocks/{id}")) else {
                    return; // retry this height next poll
                };
                let found = scan_block_json(&block, &self.vault_tree, &self.use_token_id);
                if !found.is_empty() {
                    let mut inner = self.inner.lock().unwrap();
                    for (box_id, dep) in found {
                        inner.deposits.entry(box_id).or_insert(dep);
                    }
                }
            }
            self.cursor += 1;
        }
    }

    /// Deposits at the pinned confirmation depth, as ready-to-queue claims
    /// (the producer path; `HnChain::queue_pegin` dedups already-minted ids).
    pub fn confirmed_claims(&self) -> Vec<PegInClaim> {
        let inner = self.inner.lock().unwrap();
        let mut out = Vec::new();
        for (box_id, dep) in &inner.deposits {
            if inner.latest_height.saturating_sub(dep.inclusion_height) + 1 < self.confirmations {
                continue;
            }
            let fee = self.params.peg_fee(dep.amount);
            let Some(minted) = dep.amount.checked_sub(fee).filter(|m| *m > 0) else {
                continue; // dust deposit: fee swallows it, never mintable
            };
            let owner_bytes = limbs_to_bytes(&dep.dest_owner);
            let Some(owner) = digest_from_bytes(&owner_bytes) else {
                continue;
            };
            let dest = Address {
                owner,
                enc_pk: dep.dest_enc_pk,
            };
            out.push(PegInClaim {
                box_id: *box_id,
                dest_owner: dep.dest_owner,
                dest_enc_pk: dep.dest_enc_pk,
                amount: dep.amount,
                ciphertext: pegmint_note(&dest, minted, box_id).ciphertext,
            });
        }
        out
    }

    /// A shareable [`PegInCheck`] over this watch's view (the follower path).
    pub fn checker(&self) -> Box<dyn PegInCheck> {
        Box::new(Checker {
            inner: Arc::clone(&self.inner),
            confirmations: self.confirmations,
        })
    }
}

struct Checker {
    inner: Arc<Mutex<Inner>>,
    confirmations: u64,
}

impl PegInCheck for Checker {
    fn confirmed(&self, claim: &PegInClaim) -> bool {
        let inner = self.inner.lock().unwrap();
        let Some(dep) = inner.deposits.get(&claim.box_id) else {
            return false;
        };
        dep.dest_owner == claim.dest_owner
            && dep.dest_enc_pk == claim.dest_enc_pk
            && dep.amount == claim.amount
            && inner.latest_height.saturating_sub(dep.inclusion_height) + 1 >= self.confirmations
    }
}

fn limbs_to_bytes(limbs: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(4).zip(limbs.iter()) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// Parse the deposits out of one full-block JSON (see module docs for the
/// verified shape). Returns `(box_id, deposit)` per qualifying output.
fn scan_block_json(
    block: &serde_json::Value,
    vault_tree: &[u8],
    use_token_id: &[u8; 32],
) -> Vec<([u8; 32], Deposit)> {
    let mut out = Vec::new();
    let Some(height) = block
        .get("header")
        .and_then(|h| h.get("height"))
        .and_then(|v| v.as_u64())
    else {
        return out;
    };
    let Some(txs) = block
        .get("blockTransactions")
        .and_then(|bt| bt.get("transactions"))
        .and_then(|t| t.as_array())
    else {
        return out;
    };
    let token_hex = hex::encode(use_token_id);
    for tx in txs {
        let Some(outputs) = tx.get("outputs").and_then(|o| o.as_array()) else {
            continue;
        };
        for o in outputs {
            let Some(tree_hex) = o.get("ergoTree").and_then(|v| v.as_str()) else {
                continue;
            };
            let Ok(tree) = hex::decode(tree_hex) else {
                continue;
            };
            if tree != vault_tree {
                continue;
            }
            // The USE amount carried by this output.
            let Some(amount) = o
                .get("assets")
                .and_then(|a| a.as_array())
                .and_then(|assets| {
                    assets.iter().find_map(|a| {
                        (a.get("tokenId")?.as_str()? == token_hex)
                            .then(|| a.get("amount")?.as_u64())?
                    })
                })
            else {
                continue;
            };
            // R4 = serialized Coll[Byte] constant whose payload is
            // owner(32) ‖ enc_pk(32).
            let Some(r4_hex) = o
                .get("additionalRegisters")
                .and_then(|r| r.get("R4"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let Ok(r4) = hex::decode(r4_hex) else {
                continue;
            };
            let Some(payload) = coll_byte_payload(&r4) else {
                continue;
            };
            if payload.len() != 64 {
                continue;
            }
            let owner_bytes: [u8; 32] = payload[..32].try_into().expect("32 bytes");
            // Reject non-canonical limbs (a second wire form of the same
            // digest would be malleable).
            let Some(owner) = digest_from_bytes(&owner_bytes) else {
                continue;
            };
            let enc_pk: [u8; 32] = payload[32..].try_into().expect("32 bytes");
            let Some(box_id) = o
                .get("boxId")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            else {
                continue;
            };
            out.push((
                box_id,
                Deposit {
                    dest_owner: digest_to_limbs(&owner),
                    dest_enc_pk: enc_pk,
                    amount,
                    inclusion_height: height,
                },
            ));
        }
    }
    out
}

/// Strip the serialized-constant framing of a `Coll[Byte]`: type byte `0x0e`
/// then a VLQ length, returning the payload iff the length matches exactly.
fn coll_byte_payload(bytes: &[u8]) -> Option<&[u8]> {
    let rest = bytes.strip_prefix(&[0x0e])?;
    let (len, consumed) = read_vlq(rest)?;
    let payload = &rest[consumed..];
    (payload.len() as u64 == len).then_some(payload)
}

/// Unsigned VLQ (7-bit groups, high bit = continuation), bounded defensively.
fn read_vlq(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, b) in bytes.iter().enumerate().take(5) {
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_engine::address::WalletKeys;
    use aegis_engine::poseidon::digest_to_bytes;
    use serde_json::json;

    // ----- helpers -----

    const VAULT_TREE: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    const TOKEN: [u8; 32] = [0x42; 32];

    fn dest() -> Address {
        WalletKeys::from_seed(b"pegin-watch-dest").address()
    }

    fn r4_hex(owner_bytes: &[u8; 32], enc_pk: &[u8; 32]) -> String {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(owner_bytes);
        payload.extend_from_slice(enc_pk);
        format!("0e40{}", hex::encode(payload))
    }

    fn block_json(height: u64, outputs: Vec<serde_json::Value>) -> serde_json::Value {
        json!({
            "header": { "height": height },
            "blockTransactions": { "transactions": [ { "outputs": outputs } ] }
        })
    }

    fn deposit_output(box_id: [u8; 32], amount: u64, r4: Option<String>) -> serde_json::Value {
        let mut o = json!({
            "boxId": hex::encode(box_id),
            "ergoTree": hex::encode(VAULT_TREE),
            "assets": [ { "tokenId": hex::encode(TOKEN), "amount": amount } ],
            "additionalRegisters": {},
        });
        if let Some(r4) = r4 {
            o["additionalRegisters"]["R4"] = json!(r4);
        }
        o
    }

    fn watch_with(inner_deposits: Vec<([u8; 32], Deposit)>, latest: u64) -> VaultWatch {
        let w = VaultWatch::new(
            "http://unreachable.invalid",
            "k",
            VAULT_TREE.to_vec(),
            TOKEN,
            10,
            1,
            HnChainParams::testnet(),
        );
        {
            let mut inner = w.inner.lock().unwrap();
            inner.latest_height = latest;
            for (id, d) in inner_deposits {
                inner.deposits.insert(id, d);
            }
        }
        w
    }

    fn dep_at(height: u64, amount: u64) -> Deposit {
        let d = dest();
        Deposit {
            dest_owner: digest_to_limbs(&d.owner),
            dest_enc_pk: d.enc_pk,
            amount,
            inclusion_height: height,
        }
    }

    // ----- happy path -----

    #[test]
    fn scan_block_finds_vault_deposit_with_r4() {
        let d = dest();
        let r4 = r4_hex(&digest_to_bytes(&d.owner), &d.enc_pk);
        let block = block_json(7, vec![deposit_output([1; 32], 10_000, Some(r4))]);
        let found = scan_block_json(&block, &VAULT_TREE, &TOKEN);
        assert_eq!(found.len(), 1);
        let (box_id, dep) = &found[0];
        assert_eq!(*box_id, [1; 32]);
        assert_eq!(dep.dest_owner, digest_to_limbs(&d.owner));
        assert_eq!(dep.dest_enc_pk, d.enc_pk);
        assert_eq!(dep.amount, 10_000);
        assert_eq!(dep.inclusion_height, 7);
    }

    #[test]
    fn confirmed_claims_carry_minted_ciphertext() {
        let w = watch_with(vec![([9; 32], dep_at(5, 10_000))], 14); // depth 10
        let claims = w.confirmed_claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].amount, 10_000);
        // ciphertext binds the MINTED amount (deposit − 1% fee).
        let d = dest();
        let expected = pegmint_note(&d, 10_000 - 100, &[9; 32]).ciphertext;
        assert_eq!(claims[0].ciphertext.len(), expected.len());
    }

    // ----- error paths -----

    #[test]
    fn scan_block_skips_non_deposit_outputs() {
        let d = dest();
        let good_r4 = r4_hex(&digest_to_bytes(&d.owner), &d.enc_pk);

        // Wrong tree.
        let mut o = deposit_output([1; 32], 5_000, Some(good_r4.clone()));
        o["ergoTree"] = json!("aabbccdd");
        assert!(scan_block_json(&block_json(3, vec![o]), &VAULT_TREE, &TOKEN).is_empty());

        // No USE token.
        let mut o = deposit_output([2; 32], 5_000, Some(good_r4.clone()));
        o["assets"] = json!([{ "tokenId": hex::encode([0x01u8; 32]), "amount": 5 }]);
        assert!(scan_block_json(&block_json(3, vec![o]), &VAULT_TREE, &TOKEN).is_empty());

        // Missing R4.
        let o = deposit_output([3; 32], 5_000, None);
        assert!(scan_block_json(&block_json(3, vec![o]), &VAULT_TREE, &TOKEN).is_empty());

        // R4 payload too short (32 bytes, not 64).
        let o = deposit_output(
            [4; 32],
            5_000,
            Some(format!("0e20{}", hex::encode([7u8; 32]))),
        );
        assert!(scan_block_json(&block_json(3, vec![o]), &VAULT_TREE, &TOKEN).is_empty());

        // R4 owner limbs non-canonical (0xFFFFFFFF ≥ p).
        let o = deposit_output([5; 32], 5_000, Some(r4_hex(&[0xFF; 32], &d.enc_pk)));
        assert!(scan_block_json(&block_json(3, vec![o]), &VAULT_TREE, &TOKEN).is_empty());
    }

    #[test]
    fn depth_gate_confirms_exactly_at_threshold() {
        // confirmations = 10; inclusion at 5 → depth = latest − 5 + 1.
        let w = watch_with(vec![([8; 32], dep_at(5, 10_000))], 13); // depth 9
        assert!(w.confirmed_claims().is_empty(), "below threshold");

        let w = watch_with(vec![([8; 32], dep_at(5, 10_000))], 14); // depth 10
        assert_eq!(w.confirmed_claims().len(), 1, "at threshold");
    }

    #[test]
    fn dust_deposit_never_mints() {
        // amount 1: fee = max(1, 1%) = 1 → minted 0 → skipped.
        let w = watch_with(vec![([8; 32], dep_at(5, 1))], 50);
        assert!(w.confirmed_claims().is_empty());
    }

    #[test]
    fn checker_matches_exact_claim_only() {
        let w = watch_with(vec![([8; 32], dep_at(5, 10_000))], 14);
        let check = w.checker();
        let mut claim = w.confirmed_claims().remove(0);
        assert!(check.confirmed(&claim), "exact claim confirms");

        let mut wrong_amount = claim.clone();
        wrong_amount.amount += 1;
        assert!(!check.confirmed(&wrong_amount), "amount mismatch rejects");

        claim.box_id = [9; 32];
        assert!(!check.confirmed(&claim), "unknown box id rejects");

        // Below depth: same claim, shallower view.
        let w2 = watch_with(vec![([8; 32], dep_at(5, 10_000))], 13);
        let claim2 = PegInClaim {
            box_id: [8; 32],
            ..w.confirmed_claims().remove(0)
        };
        assert!(!w2.checker().confirmed(&claim2), "below depth defers");
    }

    // ----- round-trips -----

    #[test]
    fn vlq_framing_roundtrips_typical_lengths() {
        assert_eq!(read_vlq(&[0x40]), Some((64, 1)));
        assert_eq!(read_vlq(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(read_vlq(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), None, "unbounded");
        let payload = [3u8; 64];
        let mut r4 = vec![0x0e, 0x40];
        r4.extend_from_slice(&payload);
        assert_eq!(coll_byte_payload(&r4), Some(&payload[..]));
        // Length/payload mismatch rejected.
        r4.pop();
        assert_eq!(coll_byte_payload(&r4), None);
    }
}
