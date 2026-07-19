//! hn-side drivers for the e2e campaign: sc-dest derivation, wallet
//! scan/pay/peg-out against a node's `/hn/v1/*` surface. Thin glue over
//! `aegis-hn-wallet` + `aegis-node`'s `HttpChain` — no protocol logic here.

use aegis_engine::address::{Address, WalletKeys, HRP_TEST};
use aegis_engine::poseidon::{digest_from_bytes, digest_to_bytes};
use aegis_hn_wallet::{SpendCircuit, Wallet};
use aegis_node::hn::{HttpChain, PegOutTx};
use anyhow::{anyhow, Context, Result};

/// The 64-byte peg-in destination a vault deposit carries in R4:
/// `owner digest bytes(32) ‖ enc_pk(32)`.
pub fn sc_dest(seed: &[u8]) -> [u8; 64] {
    let addr = WalletKeys::from_seed(seed).address();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&digest_to_bytes(&addr.owner));
    out[32..].copy_from_slice(&addr.enc_pk);
    out
}

/// The bech32m address string for a seed (testnet HRP).
pub fn address_string(seed: &[u8]) -> String {
    WalletKeys::from_seed(seed).address().encode(HRP_TEST)
}

/// Parse a 64-byte `owner ‖ enc_pk` hex string back into an [`Address`].
pub fn address_from_dest(hexs: &str) -> Result<Address> {
    let bytes = hex::decode(hexs).context("sc-dest hex")?;
    let raw: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow!("sc-dest must be 64 bytes (owner ‖ enc_pk)"))?;
    let owner_bytes: [u8; 32] = raw[..32].try_into().expect("32");
    let owner = digest_from_bytes(&owner_bytes)
        .ok_or_else(|| anyhow!("owner digest not canonical BabyBear limbs"))?;
    let enc_pk: [u8; 32] = raw[32..].try_into().expect("32");
    Ok(Address { owner, enc_pk })
}

/// Open a wallet on `seed` and scan it to the node's current output cursor.
pub fn scan_wallet(node: &str, seed: &[u8]) -> (Wallet, HttpChain) {
    let chain = HttpChain::new(node);
    let mut wallet = Wallet::from_seed(seed);
    wallet.scan(&chain);
    (wallet, chain)
}

/// Shielded pay: `seed` sends `amount` (flat `fee`) to the 64-byte dest.
/// Returns `(balance_before, balance_after_local)`.
pub fn pay(node: &str, seed: &[u8], dest_hex: &str, amount: u64, fee: u64) -> Result<(u64, u64)> {
    let recipient = address_from_dest(dest_hex)?;
    let (mut wallet, chain) = scan_wallet(node, seed);
    let before = wallet.balance();
    let circuit = SpendCircuit::new();
    let tx = wallet
        .pay(&chain, &circuit, &recipient, amount, fee)
        .map_err(|e| anyhow!("pay failed: {e:?}"))?;
    chain.submit(&tx).map_err(|e| anyhow!("submit: {e}"))?;
    Ok((before, wallet.balance()))
}

/// Peg-out: burn `amount + peg_fee` from `seed`'s notes and submit the public
/// withdrawal for `recipient_prop` (an ErgoTree) to the node.
pub fn pegout(
    node: &str,
    seed: &[u8],
    amount: u64,
    peg_fee: u64,
    flat_fee: u64,
    recipient_prop: Vec<u8>,
) -> Result<u64> {
    let (mut wallet, chain) = scan_wallet(node, seed);
    let before = wallet.balance();
    let circuit = SpendCircuit::new();
    // The burn bakes in (recipient_prop, amount) — D1: only this recipient's
    // settlement can ever claim it.
    let tx = wallet
        .burn_spend(&chain, &circuit, amount, peg_fee, &recipient_prop, flat_fee)
        .map_err(|e| anyhow!("burn_spend failed: {e:?}"))?;
    let po = PegOutTx {
        tx,
        amount,
        recipient_prop,
    };
    chain
        .submit_pegout(&po)
        .map_err(|e| anyhow!("pegout: {e}"))?;
    Ok(before)
}

/// Every output that decrypts to `seed` — `(leaf_index, value)` — plus the
/// unspent balance and spendable-now balance. Detection uses the viewing key
/// (includes already-spent notes; the balances exclude them).
pub fn detect_notes(node: &str, seed: &[u8]) -> (Vec<(u64, u64)>, u64, u64) {
    let (wallet, chain) = scan_wallet(node, seed);
    let notes = wallet
        .viewing_key()
        .detect(&chain, 0)
        .into_iter()
        .map(|(leaf, value, _memo)| (leaf, value))
        .collect();
    let tip = aegis_hn_wallet::ChainView::tip_height(&chain);
    (notes, wallet.balance(), wallet.spendable_balance(tip))
}
