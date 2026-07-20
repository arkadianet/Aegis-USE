//! F2 — in-guest LWMA difficulty adjustment (the un-discountable work pricer).
//!
//! A **verbatim port** of `aegis-node/src/daa.rs::next_nbits` (LWMA-1, window 90,
//! solve clamp `[1 ms, 6T]`, ×4/÷4 per-step clamp, `min_difficulty_nbits` below
//! `window + 1` history). It is pure over `&[(timestamp_ms, sc_nbits)]`, so it
//! runs unchanged in the RISC0 guest (E2 already links `num_bigint` +
//! `ergo_ser::difficulty` in-guest via `share.rs`).
//!
//! **Why in the guest (design §2.2).** The node enforces `sc_nbits ==
//! expected_nbits()` (`hn/state.rs`), but the bridge must not trust the node.
//! Seeded from F1's authenticated seam `(timestamp, nbits)` history, this lets
//! the settlement guest require every suffix block's `sc_nbits` to equal the DAA
//! expectation — so a fabricator forking at the sealed tip inherits the honest
//! chain's prevailing difficulty exactly and cannot self-declare difficulty-1.
//!
//! **[`PINNED_DAA_PARAMS`] are image constants** matching
//! `HnChainParams::testnet().daa()` = `DaaParams::for_network` EXACTLY; the
//! node↔guest DAA-parity test (`aegis-node`, D-F2 cut gate) is the guard.
//! Gated behind `aux-pow` (it pulls `ergo-ser` + `num-bigint`, exactly like E2).

use ergo_ser::difficulty::{decode_compact_bits, encode_compact_bits};
use num_bigint::BigUint;

use super::types::DAA_WINDOW;

/// LWMA configuration — the guest mirror of `aegis-node`'s `DaaParams`.
#[derive(Debug, Clone)]
pub struct DaaParams {
    pub target_secs: u64,
    pub window: usize,
    pub min_difficulty_nbits: u32,
}

/// The pinned image constants (Stage-T testnet profile). These MUST equal
/// `HnChainParams::testnet().daa()`:
/// - `target_secs = HN_BLOCK_TARGET_SECS = 15`,
/// - `window = HN_DAA_WINDOW = 90`,
/// - `min_difficulty_nbits = difficulty_to_nbits(1)` (the genesis difficulty).
///
/// A function (not a `const`) because the compact-bits encoder is not `const`.
pub fn pinned_daa_params() -> DaaParams {
    DaaParams {
        target_secs: 15,
        window: DAA_WINDOW,
        min_difficulty_nbits: encode_compact_bits(&BigUint::from(1u8)),
    }
}

/// Fixed ceiling for difficulty↔target inversion: `target = C / D`.
fn ceiling() -> BigUint {
    BigUint::from(1u8) << 256
}

/// Next block's compact difficulty from the recent chain view — the byte-exact
/// port of `aegis-node/src/daa.rs::next_nbits`.
///
/// `chain` is `(timestamp_ms, sc_nbits)` pairs, **oldest first**; only the last
/// `window + 1` entries are consulted. LWMA-1: the next target is the window's
/// average target scaled by the linearly weighted mean solve time (weights
/// `1..=window`, newest heaviest). Solve times clamp to `[1 ms, 6×target]`; the
/// result clamps to ×4 / ÷4 of the previous block's difficulty per step.
pub fn next_nbits(params: &DaaParams, chain: &[(u64, u32)]) -> u32 {
    let n = params.window;
    if chain.len() < n + 1 {
        return params.min_difficulty_nbits;
    }
    let view = &chain[chain.len() - (n + 1)..];
    let target_ms = params.target_secs * 1_000;
    let max_solve_ms = 6 * target_ms;

    let mut weighted: u128 = 0;
    let mut target_sum = BigUint::ZERO;
    let c = ceiling();
    for i in 1..=n {
        let solve_ms = view[i]
            .0
            .saturating_sub(view[i - 1].0)
            .clamp(1, max_solve_ms);
        weighted += u128::from(solve_ms) * i as u128;
        let difficulty = decode_compact_bits(view[i].1).max(BigUint::from(1u8));
        target_sum += &c / difficulty;
    }
    let avg_target = target_sum / n;

    let k: u128 = (n as u128 * (n as u128 + 1) / 2) * u128::from(target_ms);
    let next_target = (avg_target * weighted) / k;
    let next_target = next_target.max(BigUint::from(1u8));
    let mut next_difficulty = &c / next_target;

    let prev_difficulty = decode_compact_bits(view[n].1).max(BigUint::from(1u8));
    let hi = &prev_difficulty * 4u32;
    let lo = (&prev_difficulty / 4u32).max(BigUint::from(1u8));
    if next_difficulty > hi {
        next_difficulty = hi;
    } else if next_difficulty < lo {
        next_difficulty = lo;
    }
    encode_compact_bits(&next_difficulty)
}
