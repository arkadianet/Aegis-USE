//! Chain parameters + genesis for the hash-native testnet profile.
//!
//! **Every consensus-economic knob lives HERE** (aegis-spec §11-12): the flat
//! tx fee, the coinbase base/bonus, the coinbase maturity, the genesis pot and
//! allocation, and the root window — a single struct selected by chain profile,
//! documented in `dev-docs/sidechain/`. Nothing economic is a scattered
//! constant elsewhere in the node.
//!
//! # The designed economy (ported from the spec — not the placeholder)
//! - The **emission pot** is a PUBLIC integer balance in chain state,
//!   header-committed. It is the security budget: all tx fees flow INTO it,
//!   every coinbase draws OUT of it. There is no unconditional emission.
//! - The **SC tx fee is flat** ([`FLAT_FEE`] = 0.03 USE), amount-independent
//!   (the standing privacy rule — fee variation is a fingerprint). A tx pays
//!   EXACTLY the flat fee; any other fee is consensus-invalid.
//! - **Coinbase = min(pot_parent, base + per_tx × txs)** — computed on the
//!   PARENT state's pot (no same-block circularity). Per included tx the miner
//!   earns a 0.01 USE inclusion bonus and the pot nets +0.02 USE.
//! - **Conservation (I1-extended)**: shielded total + pot is conserved by every
//!   non-genesis block; the state transition enforces it.

use aegis_engine::address::{Address, WalletKeys, HRP_TEST};

/// The hn testnet chain id / network magic. Distinct from the Curve-Trees
/// profiles so the two networks can never confuse blocks or peers.
/// v3: the trustless-bridge cut (peg-in mints, peg-out burns in the block
/// format) — chain-id-breaking vs the v2 spec-economics testnet.
pub const HN_TESTNET_CHAIN_ID: u32 = 0x484E_0003; // "HN" ‖ v3

/// Base-unit scale: 1 USE = 100 base units ("cents"). All amounts in the
/// engine, wallet, and chain are integer cents.
pub const BASE_UNITS_PER_USE: u64 = 100;

/// The flat shielded-tx fee: 0.03 USE, EXACT (not a floor). Amount-independent
/// by design — a variable fee would fingerprint transactions.
pub const FLAT_FEE: u64 = 3;

/// Coinbase base draw per block: 0.01 USE (paid even for an empty block, while
/// the pot lasts).
pub const COINBASE_BASE: u64 = 1;

/// Coinbase inclusion bonus per tx: 0.01 USE to the miner per included tx.
pub const COINBASE_PER_TX: u64 = 1;

/// The testnet's genesis pot allocation: 10,000 USE of security budget. An
/// empty chain draws ~[`COINBASE_BASE`]/block, so at the testnet's ~2 s cadence
/// this funds mining for weeks; fees top it back up (+0.02 USE net per tx).
pub const TESTNET_GENESIS_POT: u64 = 1_000_000;

/// Consensus parameters for an hn chain profile.
#[derive(Clone, Debug)]
pub struct HnChainParams {
    /// Chain id / network magic — bound into the P2P handshake and the block id.
    pub chain_id: u32,
    /// Recent-root acceptance window (a spend anchors to one of the last N roots).
    pub root_window: usize,
    /// Blocks a coinbase note must age before it is spendable (spec: 120).
    pub coinbase_maturity: u64,
    /// The flat fee (base units) EVERY shielded tx must pay exactly.
    pub flat_fee: u64,
    /// Coinbase base draw (base units) per block.
    pub coinbase_base: u64,
    /// Coinbase inclusion bonus (base units) per included tx.
    pub coinbase_per_tx: u64,
    /// The pot balance the chain starts with (the pinned genesis allocation to
    /// the security budget).
    pub genesis_pot: u64,
    /// Genesis allocation: `(recipient, amount)` faucet notes minted at height 0
    /// — the pinned non-reward blocks; a validator rejects any deviation.
    pub genesis: Vec<(Address, u64)>,
    /// Peg fee, both directions: percent of the moved amount (min 1 base
    /// unit), credited to the POT.
    pub peg_fee_percent: u64,
    /// Devnet confirmations a vault deposit needs before consensus mints it
    /// (the reorg-safety depth; below it a claim is DEFERRED, not rejected).
    pub pegin_confirmations: u64,
    /// hn blocks a recorded withdrawal waits before it is settleable
    /// (T_delay batching: the settle loop only proves withdrawals this deep).
    pub pegout_delay: u64,
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
    /// `root_window`/`coinbase_maturity` reference the wallet crate's constants
    /// (the client-side mirror) so wallet and chain can never drift; the
    /// economic values are the module constants above.
    pub fn testnet() -> Self {
        Self {
            chain_id: HN_TESTNET_CHAIN_ID,
            root_window: aegis_hn_wallet::chain::ROOT_WINDOW,
            coinbase_maturity: aegis_hn_wallet::chain::COINBASE_MATURITY,
            flat_fee: FLAT_FEE,
            coinbase_base: COINBASE_BASE,
            coinbase_per_tx: COINBASE_PER_TX,
            genesis_pot: TESTNET_GENESIS_POT,
            genesis: vec![
                (faucet_address(), 500_000_000),
                (faucet_address(), 500_000_000),
            ],
            peg_fee_percent: 1,
            pegin_confirmations: 10,
            pegout_delay: 10,
        }
    }

    /// The peg fee for moving `amount` across the bridge:
    /// `peg_fee_percent`% of it, at least 1 base unit. Credited to the pot.
    pub fn peg_fee(&self, amount: u64) -> u64 {
        (amount.saturating_mul(self.peg_fee_percent) / 100).max(1)
    }

    /// This profile with a custom genesis allocation + pot (tests / local
    /// profiles; the economics stay pinned).
    pub fn with_genesis(mut self, genesis: Vec<(Address, u64)>, genesis_pot: u64) -> Self {
        self.genesis = genesis;
        self.genesis_pot = genesis_pot;
        self
    }

    /// The consensus coinbase amount for a block with `n_txs` included txs on a
    /// parent state whose pot is `pot_parent`:
    /// `min(pot_parent, base + per_tx × n_txs)`. Computed on the PARENT pot —
    /// this block's fees credit the pot but cannot fund its own coinbase.
    pub fn coinbase_amount(&self, pot_parent: u64, n_txs: usize) -> u64 {
        self.coinbase_base
            .saturating_add(self.coinbase_per_tx.saturating_mul(n_txs as u64))
            .min(pot_parent)
    }
}

impl Default for HnChainParams {
    fn default() -> Self {
        Self::testnet()
    }
}
