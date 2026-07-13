//! Network identity and chain parameters for the Aegis sidechain.
//!
//! Single source of truth for "what does Aegis network X look like":
//! network names, address HRPs, the 15 s block target, fee and
//! emission-box constants, the coinbase reward rule, and the unlock
//! ladder numbers. Values mirror `dev-docs/sidechain/params.md`
//! (design-stage; revisions go through the docs first).
//!
//! Charter: types, constants, constructors only. No validation logic,
//! no I/O, no runtime services (same charter as `ergo-chain-spec`).
//!
//! Amounts are `u64` **base units**: USE has 3 decimals, so
//! `1 USE = 1_000` base units. Fee arithmetic widens to `u128`
//! internally so the full USE emission (10^18 base units) cannot
//! overflow.

/// USE amount in base units (`1 USE = 1_000` base units, 3 decimals).
pub type Amount = u64;

/// USE token decimals on Ergo mainnet (explorer-verified).
pub const USE_DECIMALS: u32 = 3;

/// Base units per whole USE (`10^USE_DECIMALS`).
pub const BASE_UNITS_PER_USE: Amount = 1_000;

/// Mainnet USE (DexyUSD) token id, verified on-chain 2026-07-12
/// (mint tx `adbf3c58…39cd`, inclusion height 1_666_991).
pub const USE_TOKEN_ID_MAINNET: &str =
    "a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669";

/// The three Aegis networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Dev,
    Test,
    Main,
}

impl Network {
    /// Chain parameters for this network (values from `params.md`).
    pub fn params(self) -> &'static NetworkParams {
        match self {
            Network::Dev => &DEV_PARAMS,
            Network::Test => &TEST_PARAMS,
            Network::Main => &MAIN_PARAMS,
        }
    }
}

/// Aegis chain parameters. All amounts in base units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkParams {
    /// Network id string (P2P handshake / config).
    pub network_name: &'static str,
    /// Bech32m human-readable part for payment addresses.
    pub address_hrp: &'static str,
    /// Target seconds between blocks.
    pub block_target_secs: u64,
    /// Flat, amount-independent shielded-transfer fee (standing privacy
    /// rule: on-SC fees are never a function of payment amount).
    pub sc_tx_fee: Amount,
    /// Minimum peg fee either direction (prices receipt spam, not entry).
    pub peg_fee_floor: Amount,
    /// Peg fee rate in basis points, applied to the public peg amount.
    pub peg_fee_rate_bps: u64,
    /// Base per-block coinbase draw from the emission box.
    pub r_target: Amount,
    /// Blocks before a coinbase note becomes spendable.
    pub coinbase_maturity: u64,
    /// SC confirmations required on a burn before exit (`M`).
    pub burn_confs_m: u64,
    /// Ergo depth required on the anchor before exit (`N`).
    pub ergo_anchor_depth_n: u64,
    /// Ergo confirmations on a receipt before PegMint (`N_mint`).
    pub ergo_mint_confs: u64,
    /// Ergo blocks between UnlockIntent and vault payout (`T_delay`).
    pub unlock_delay_ergo_blocks: u64,
    /// Maximum USE the vault may hold until U1-strong (`V_cap`).
    pub vault_cap: Amount,
    /// Genesis note supply — always zero: no premine, every SC USE is
    /// minted against a proven Ergo lock.
    pub genesis_supply: Amount,
    /// Bootstrap seed base URLs for the HTTP body-availability tier
    /// (p2p.md §4.1). NON-consensus: changing this list is a software
    /// update, not a chain break — seeds are a liveness convenience,
    /// never a trust root (every fetched byte self-authenticates).
    /// Empty until operator seeds exist; `--seed` CLI overrides apply.
    pub seed_urls: &'static [&'static str],
}

impl NetworkParams {
    /// Peg fee for public amount `n`: `max(floor, ceil(n × bps / 10_000))`.
    /// Rounds up so the pot is never undercredited by integer division.
    pub fn peg_fee(&self, n: Amount) -> Amount {
        let pct = (u128::from(n) * u128::from(self.peg_fee_rate_bps)).div_ceil(10_000);
        // Full emission (10^18) at 100 bps is 10^16 — far inside u64.
        let pct = Amount::try_from(pct).expect("peg fee exceeds u64 — rate/amount misconfigured");
        pct.max(self.peg_fee_floor)
    }

    /// Coinbase draw for a block: `min(pot, r_target + r_target × txs_included)`.
    /// Base reward plus per-tx inclusion bonus, always capped by the pot
    /// (never mints unbacked USE); saturating so absurd inputs cannot panic.
    pub fn coinbase_reward(&self, pot: Amount, txs_included: u64) -> Amount {
        let bonus = self.r_target.saturating_mul(txs_included);
        self.r_target.saturating_add(bonus).min(pot)
    }
}

/// End-state (mainnet) parameters.
static MAIN_PARAMS: NetworkParams = NetworkParams {
    network_name: "aegis",
    address_hrp: "aegis",
    block_target_secs: 15,
    sc_tx_fee: 30,        // 0.03 USE
    peg_fee_floor: 1_000, // 1 USE
    peg_fee_rate_bps: 100,
    r_target: 10, // 0.01 USE
    coinbase_maturity: 120,
    burn_confs_m: 120,
    ergo_anchor_depth_n: 10,
    ergo_mint_confs: 10,
    unlock_delay_ergo_blocks: 720,
    vault_cap: 1_000_000, // 1000 USE dogfood cap; raise only under U1-strong
    genesis_supply: 0,
    seed_urls: &[],
};

/// Dogfood parameters: same rates as mainnet, lower flat fee and floors
/// (0.01 USE flat, 0.1 USE peg floor).
static DEV_PARAMS: NetworkParams = dogfood_base("aegis-dev", "aegisdev");
static TEST_PARAMS: NetworkParams = dogfood_base("aegis-test", "aegistest");

const fn dogfood_base(network_name: &'static str, address_hrp: &'static str) -> NetworkParams {
    NetworkParams {
        network_name,
        address_hrp,
        block_target_secs: 15,
        sc_tx_fee: 10,
        peg_fee_floor: 100,
        peg_fee_rate_bps: 100,
        r_target: 10,
        coinbase_maturity: 120,
        burn_confs_m: 120,
        ergo_anchor_depth_n: 10,
        ergo_mint_confs: 10,
        unlock_delay_ergo_blocks: 720,
        vault_cap: 1_000_000,
        genesis_supply: 0,
        seed_urls: &[],
    }
}

// ----- Shielded wire-format constants (consensus, provisional sizes) -----
//
// Point encodings are ark-canonical compressed (33 bytes) for now; the
// final wire encoding (SEC1 vs ark) is pinned at parameter freeze
// (DEFERRED.md). Sizes cross-checked by serialization tests in
// aegis-crypto (points) and aegis-node (wire).

/// Consensus nullifier size: the x-coordinate (Orchard-style Extract)
/// of the nullifier point, 32 big-endian bytes — sign-invariant by
/// construction (matches `aegis-crypto` NF_BYTES).
pub const NF_BYTES: usize = 32;
/// Compressed note-commitment point size (matches `aegis-crypto`).
pub const NOTE_CM_BYTES: usize = 33;
/// Compressed ephemeral-key point size (note encryption, §5).
pub const EPK_BYTES: usize = 33;
/// Receiver ciphertext: value(8) + blinding(32) + rerand(32) +
/// memo(64, provisional — note-protocol.md §9) + AEAD tag(16).
pub const NOTE_CT_BYTES: usize = 152;
/// Sender (OVK) ciphertext, Sapling out_ciphertext discipline:
/// esk(32) + pk(32) + AEAD tag(16). Mandatory fixed-size slot (N7).
pub const NOTE_OUT_CT_BYTES: usize = 80;
// ----- Merge-mining commitment constants (merge-mining.md §2.2, §8) -----
//
// The aux-PoW channel: one extension-section field inside the Ergo
// block candidate carries the Aegis block id, so every Autolykos
// attempt over that candidate commits to exactly one Aegis block.
// All three values are chain-id-breaking (frozen at chain-cut).

/// Extension-field key for the Aegis merge-mining commitment:
/// namespace `0xAE`, index 0. Ergo's existing namespaces are `0x00`
/// (system parameters), `0x01` (NiPoPoW interlinks) and `0x02`
/// (validation rules); unknown keys are consensus-legal on Ergo
/// (rules 400/404/405/406 never reject unknown keys).
pub const AEGIS_MM_KEY: [u8; 2] = [0xAE, 0x00];

/// First byte of the commitment field value; a bump starts a new
/// commitment era (old-version fields stop being commitments).
pub const MM_COMMITMENT_VERSION: u8 = 0x01;

/// Commitment field value length: version byte + 32-byte Aegis block
/// id. Must stay ≤ 64 (Ergo rule 404 per-field value cap).
pub const MM_FIELD_VALUE_LEN: usize = 33;

// Compile-time guard: the commitment value must fit Ergo's rule-404
// 64-byte per-field cap (and, a fortiori, the 255-byte wire cap).
const _: () = assert!(MM_FIELD_VALUE_LEN <= 64);

/// C2 share height window (merge-mining.md §2.3 step 2, provisional):
/// a share's Ergo candidate height must lie in
/// `[follower_tip − K_LAG, follower_tip + 1]`. Blocks cheap-height
/// `calc_n` grinding and bounds offline share stockpiling.
pub const K_LAG: u32 = 6;

/// Fixed 2-in/2-out arity (note-protocol.md §6).
pub const TX_ARITY: usize = 2;
/// Hard cap on proof bytes per transfer (spike measured ~3.4–4.0 KB).
pub const MAX_PROOF_BYTES: usize = 8_192;
/// Block limits (consensus.md §7).
pub const MAX_BLOCK_TXS: usize = 128;
pub const MAX_BLOCK_BYTES: usize = 524_288;

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn main_params() -> &'static NetworkParams {
        Network::Main.params()
    }

    fn dev_params() -> &'static NetworkParams {
        Network::Dev.params()
    }

    // ----- happy path -----

    #[test]
    fn wire_constants_match_consensus_doc() {
        assert_eq!(TX_ARITY, 2);
        assert_eq!(MAX_BLOCK_TXS, 128);
        assert_eq!(MAX_BLOCK_BYTES, 524_288);
        // A padded transfer must comfortably fit the per-tx budget implied
        // by consensus.md §7 (~4–5 KiB): 2·nf + 2·(cm+epk+ct+out_ct) + proof.
        let fixed =
            2 * NF_BYTES + 2 * (NOTE_CM_BYTES + EPK_BYTES + NOTE_CT_BYTES + NOTE_OUT_CT_BYTES);
        assert!(fixed + MAX_PROOF_BYTES < MAX_BLOCK_BYTES / MAX_BLOCK_TXS * 3);
    }

    #[test]
    fn block_target_all_networks_is_15s() {
        for net in [Network::Dev, Network::Test, Network::Main] {
            assert_eq!(net.params().block_target_secs, 15);
        }
    }

    #[test]
    fn hrp_per_network_matches_design() {
        assert_eq!(Network::Dev.params().address_hrp, "aegisdev");
        assert_eq!(Network::Test.params().address_hrp, "aegistest");
        assert_eq!(Network::Main.params().address_hrp, "aegis");
    }

    #[test]
    fn network_name_per_network_matches_design() {
        assert_eq!(Network::Dev.params().network_name, "aegis-dev");
        assert_eq!(Network::Test.params().network_name, "aegis-test");
        assert_eq!(Network::Main.params().network_name, "aegis");
    }

    #[test]
    fn genesis_supply_all_networks_is_zero() {
        // No premine: every USE on Aegis is minted against a proven Ergo lock.
        for net in [Network::Dev, Network::Test, Network::Main] {
            assert_eq!(net.params().genesis_supply, 0);
        }
    }

    #[test]
    fn mainnet_fee_constants_match_params_doc() {
        let p = main_params();
        assert_eq!(p.sc_tx_fee, 30); // 0.03 USE flat, amount-independent
        assert_eq!(p.peg_fee_floor, 1_000); // 1 USE
        assert_eq!(p.peg_fee_rate_bps, 100); // 1%
        assert_eq!(p.r_target, 10); // 0.01 USE base block reward
        assert_eq!(p.coinbase_maturity, 120);
    }

    #[test]
    fn dev_dogfood_fee_constants_match_params_doc() {
        let p = dev_params();
        assert_eq!(p.sc_tx_fee, 10); // 0.01 USE dogfood flat fee
        assert_eq!(p.peg_fee_floor, 100); // 0.1 USE dogfood floor
        assert_eq!(p.peg_fee_rate_bps, 100); // same 1% rate as end state
    }

    #[test]
    fn unlock_ladder_constants_match_params_doc() {
        let p = main_params();
        assert_eq!(p.burn_confs_m, 120);
        assert_eq!(p.ergo_anchor_depth_n, 10);
        assert_eq!(p.ergo_mint_confs, 10);
        assert_eq!(p.unlock_delay_ergo_blocks, 720);
        assert_eq!(p.vault_cap, 1_000_000); // 1000 USE dogfood V_cap
    }

    #[test]
    fn peg_fee_small_amount_pays_floor() {
        // 50 USE: 1% = 0.5 USE < 1 USE floor.
        assert_eq!(main_params().peg_fee(50_000), 1_000);
    }

    #[test]
    fn peg_fee_large_amount_pays_one_percent() {
        // 100_000 USE: 1% = 1_000 USE.
        assert_eq!(main_params().peg_fee(100_000_000), 1_000_000);
    }

    #[test]
    fn peg_fee_fractional_unit_rounds_up() {
        // 123.456 USE: 1% = 1.23456 USE -> 1.235 (never undercharge).
        assert_eq!(main_params().peg_fee(123_456), 1_235);
    }

    #[test]
    fn coinbase_reward_empty_block_pays_base() {
        assert_eq!(main_params().coinbase_reward(10_000, 0), 10);
    }

    #[test]
    fn coinbase_reward_five_txs_pays_base_plus_bonus() {
        // 0.01 base + 5 x 0.01 inclusion bonus = 0.06 USE.
        assert_eq!(main_params().coinbase_reward(10_000, 5), 60);
    }

    #[test]
    fn coinbase_reward_pot_short_caps_payout() {
        assert_eq!(main_params().coinbase_reward(15, 5), 15);
    }

    #[test]
    fn coinbase_reward_empty_pot_pays_zero() {
        assert_eq!(main_params().coinbase_reward(0, 7), 0);
    }

    // ----- error paths -----

    #[test]
    fn peg_fee_full_emission_no_overflow() {
        // Entire USE emission (10^18 base units) through the 1% rule.
        assert_eq!(
            main_params().peg_fee(1_000_000_000_000_000_000),
            10_000_000_000_000_000
        );
    }

    #[test]
    fn coinbase_reward_absurd_tx_count_saturates_not_panics() {
        // Bonus arithmetic must saturate (not overflow-panic) and stay
        // capped by the pot even with a nonsense tx count.
        assert_eq!(main_params().coinbase_reward(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(main_params().coinbase_reward(500, u64::MAX), 500);
    }

    #[test]
    fn mm_constants_match_merge_mining_design() {
        // merge-mining.md §8: key namespace 0xAE index 0, value version
        // 0x01, 33-byte value, K_LAG 6 (provisional).
        assert_eq!(AEGIS_MM_KEY, [0xAE, 0x00]);
        assert_eq!(MM_COMMITMENT_VERSION, 0x01);
        assert_eq!(MM_FIELD_VALUE_LEN, 1 + 32);
        assert_eq!(K_LAG, 6);
    }

    #[test]
    fn mm_key_namespace_avoids_ergo_namespaces() {
        // Ergo's occupied extension namespaces (ergo-ser extension.rs
        // module doc): 0x00 params, 0x01 interlinks, 0x02 validation
        // rules. The commitment must not collide.
        assert!(![0x00, 0x01, 0x02].contains(&AEGIS_MM_KEY[0]));
    }

    // ----- oracle parity -----

    #[test]
    fn use_token_id_matches_onchain_mint() {
        // Oracle: mainnet explorer, verified 2026-07-12 — token minted in tx
        // adbf3c5855aa66baf5e45dc192c2bb6dc85f168eafffc9ade7d3fd79137a39cd
        // at inclusion height 1_666_991 (3 decimals, EIP-004).
        assert_eq!(
            USE_TOKEN_ID_MAINNET,
            "a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669"
        );
        assert_eq!(USE_DECIMALS, 3);
        assert_eq!(BASE_UNITS_PER_USE, 1_000);
    }
}
