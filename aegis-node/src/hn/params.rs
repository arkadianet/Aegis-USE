//! Chain parameters + genesis for the hash-native testnet profile.
//!
//! A NEW chain id (chain-id-breaking is free pre-launch): the hn profile is
//! entirely separate from the Curve-Trees testnet, which keeps running as-is.
//! Every consensus knob the node enforces is pinned here (not scattered as
//! magic constants) and documented in `dev-docs/sidechain/`.

use aegis_engine::address::{Address, WalletKeys, HRP_TEST};

/// The hn testnet chain id / network magic. Distinct from the Curve-Trees
/// profiles so the two networks can never confuse blocks or peers.
pub const HN_TESTNET_CHAIN_ID: u32 = 0x484E_0001; // "HN" ‖ v1

/// Consensus parameters for an hn chain profile.
#[derive(Clone, Debug)]
pub struct HnChainParams {
    /// Chain id / network magic — bound into the P2P handshake and the block id.
    pub chain_id: u32,
    /// Recent-root acceptance window (a spend anchors to one of the last N roots).
    pub root_window: usize,
    /// Blocks a coinbase note must age before it is spendable.
    pub coinbase_maturity: u64,
    /// Minimum fee (base units) a shielded tx must pay to be admitted.
    pub min_fee: u64,
    /// Flat per-block emission (base units). Fees are added on top, to the miner.
    pub emission_per_block: u64,
    /// Genesis allocation: `(recipient, amount)` faucet notes minted at height 0.
    pub genesis: Vec<(Address, u64)>,
}

/// The seed the genesis faucet's keys derive from — its address funds the e2e
/// campaign. Published (not secret): whoever holds this seed can spend the
/// faucet, so a real launch would use a governance-held key; for the testnet
/// campaign it is intentionally open.
pub const FAUCET_SEED: &[u8] = b"aegis-hn-testnet-faucet-v1";

/// The faucet's public address (base units credited at genesis).
pub fn faucet_address() -> Address {
    WalletKeys::from_seed(FAUCET_SEED).address()
}

/// The faucet's encoded address string (for scripts / the campaign).
pub fn faucet_address_string() -> String {
    faucet_address().encode(HRP_TEST)
}

impl HnChainParams {
    /// The hn testnet parameters (pinned).
    ///
    /// Genesis mints a single large faucet note the campaign draws from. The
    /// emission is a flat 50/block (a real chain halves — documented follow-up);
    /// maturity/window/min-fee match the engine + wallet defaults so a wallet
    /// built against the crate agrees with the chain.
    pub fn testnet() -> Self {
        Self {
            chain_id: HN_TESTNET_CHAIN_ID,
            root_window: aegis_hn_wallet::chain::ROOT_WINDOW,
            coinbase_maturity: aegis_hn_wallet::chain::COINBASE_MATURITY,
            min_fee: crate::hn::state::MIN_FEE,
            emission_per_block: crate::hn::chain::EMISSION_PER_BLOCK,
            genesis: vec![
                (faucet_address(), 500_000_000),
                (faucet_address(), 500_000_000),
            ],
        }
    }
}

impl Default for HnChainParams {
    fn default() -> Self {
        Self::testnet()
    }
}
