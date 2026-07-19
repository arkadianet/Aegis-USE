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

use crate::daa::{difficulty_to_nbits, DaaParams};
use num_bigint::BigUint;

/// hn block-time target (seconds) the LWMA difficulty adjustment aims for.
pub const HN_BLOCK_TARGET_SECS: u64 = 15;

/// hn LWMA window (blocks), matching the Curve-Trees `consensus.md` §3 DAA.
pub const HN_DAA_WINDOW: usize = 90;

/// The hn testnet chain id / network magic. Distinct from the Curve-Trees
/// profiles so the two networks can never confuse blocks or peers.
/// v5: the fast-settlement cut — SHA-256 FRI-Merkle MMCS client proofs
/// (T2.1) + baked settlement vk (T1.1) + rebalanced FRI params (T1.2); the
/// proof format and the settlement image id change, so the chain id breaks.
pub const HN_TESTNET_CHAIN_ID: u32 = 0x484E_0005; // "HN" ‖ v5 (SHA-MMCS fast-settlement cut)

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
    /// Minimum aux-PoW difficulty (compact nbits) — the DAA floor and the
    /// difficulty of the genesis prefix. Devnet mines difficulty-1 from
    /// genesis, so this is the aux-PoW weight of every early block.
    pub min_difficulty_nbits: u32,
    /// LWMA block-time target (seconds) the aux-PoW difficulty aims for.
    pub daa_target_secs: u64,
    /// LWMA window (blocks) — below `window + 1` blocks the chain stays at
    /// `min_difficulty_nbits`.
    pub daa_window: usize,
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
            min_difficulty_nbits: difficulty_to_nbits(&BigUint::from(1u8)),
            daa_target_secs: HN_BLOCK_TARGET_SECS,
            daa_window: HN_DAA_WINDOW,
        }
    }

    /// The LWMA difficulty-adjustment parameters for this profile — the single
    /// spelling shared by block production, block validation, and (E0) the
    /// aux-PoW share verifier's `sc_nbits`-vs-DAA equality; the three must
    /// never diverge.
    pub fn daa(&self) -> DaaParams {
        DaaParams {
            target_secs: self.daa_target_secs,
            window: self.daa_window,
            min_difficulty_nbits: self.min_difficulty_nbits,
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
