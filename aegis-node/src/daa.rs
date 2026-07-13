//! LWMA difficulty adjustment per `consensus.md` §3.
//!
//! LWMA-1 (zawy12) over a 90-block window, 15 s target: the next
//! target is the average target of the window scaled by the linearly
//! weighted mean solve time. Solve times are clamped to `[1, 6T]`
//! before weighting; the resulting target is clamped to ×4 / ÷4 of the
//! previous block's target per step. Below `window + 1` headers the
//! chain stays at the network's minimum difficulty.
//!
//! Works on compact nbits via `ergo_ser::difficulty` (nbits encode a
//! *difficulty*; target ∝ 1/difficulty, so target math uses the
//! decoded values inverted against a fixed ceiling).

use ergo_ser::difficulty::{decode_compact_bits, encode_compact_bits};
use num_bigint::BigUint;

/// LWMA configuration. `window` solve times feed each retarget;
/// below `window + 1` known headers the chain stays at
/// `min_difficulty_nbits`.
#[derive(Debug, Clone)]
pub struct DaaParams {
    pub target_secs: u64,
    pub window: usize,
    pub min_difficulty_nbits: u32,
}

impl DaaParams {
    /// The network's consensus DAA parameters (consensus.md §3):
    /// LWMA-90 at the network's block target, floored at the genesis
    /// difficulty. The single spelling shared by [`crate::chain::Chain`]
    /// (block production/validation) and the anchor-watcher's share
    /// verification ([`crate::auxpow::verify_share`]'s `sc_nbits`
    /// equality) — the two must never diverge.
    pub fn for_network(network: aegis_spec::Network) -> Self {
        DaaParams {
            target_secs: network.params().block_target_secs,
            window: 90,
            min_difficulty_nbits: crate::genesis::genesis_header(network).sc_nbits,
        }
    }
}

/// Encode a difficulty as compact nbits (thin alias kept next to the
/// DAA so callers and tests share one spelling).
pub fn difficulty_to_nbits(difficulty: &BigUint) -> u32 {
    encode_compact_bits(difficulty)
}

/// Fixed ceiling for difficulty↔target inversion: `target = C / D`.
fn ceiling() -> BigUint {
    BigUint::from(1u8) << 256
}

/// Next block's compact difficulty from the recent chain view.
///
/// `chain` is `(timestamp_ms, sc_nbits)` pairs, **oldest first**; only
/// the last `window + 1` entries are consulted. LWMA-1: the next target
/// is the window's average target scaled by the linearly weighted mean
/// solve time (weights 1..=window, newest heaviest). Solve times clamp
/// to `[1 ms, 6×target]`; the result clamps to ×4 / ÷4 of the previous
/// block's difficulty per step (consensus.md §3).
pub fn next_nbits(params: &DaaParams, chain: &[(u64, u32)]) -> u32 {
    let n = params.window;
    if chain.len() < n + 1 {
        return params.min_difficulty_nbits;
    }
    let view = &chain[chain.len() - (n + 1)..];
    let target_ms = params.target_secs * 1_000;
    let max_solve_ms = 6 * target_ms;

    // Weighted solve-time sum over the n intervals, and the average
    // target of the n blocks those intervals produced.
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

    // k = Σ(i) × T — the weighted sum a perfectly on-target chain yields.
    let k: u128 = (n as u128 * (n as u128 + 1) / 2) * u128::from(target_ms);
    let next_target = (avg_target * weighted) / k;
    let next_target = next_target.max(BigUint::from(1u8));
    let mut next_difficulty = &c / next_target;

    // Per-step clamp: at most ×4 / ÷4 versus the previous block.
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

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::difficulty::decode_compact_bits;
    use num_bigint::BigUint;

    // ----- helpers -----

    const T_MS: u64 = 15_000;

    fn params() -> DaaParams {
        DaaParams {
            target_secs: 15,
            window: 90,
            min_difficulty_nbits: difficulty_to_nbits(&BigUint::from(1000u32)),
        }
    }

    fn difficulty_of(nbits: u32) -> BigUint {
        decode_compact_bits(nbits)
    }

    /// Timestamps at a fixed spacing, difficulty constant, oldest first.
    /// Produces `n` (timestamp_ms, nbits) pairs.
    fn uniform_chain(n: usize, spacing_ms: u64, nbits: u32) -> Vec<(u64, u32)> {
        (0..n as u64)
            .map(|i| (1_000_000 + i * spacing_ms, nbits))
            .collect()
    }

    // ----- happy path -----

    #[test]
    fn daa_bootstrap_below_window_returns_min_difficulty() {
        let p = params();
        let chain = uniform_chain(30, T_MS, p.min_difficulty_nbits);
        assert_eq!(next_nbits(&p, &chain), p.min_difficulty_nbits);
    }

    #[test]
    fn daa_on_target_solve_times_keeps_difficulty_steady() {
        let p = params();
        let start = difficulty_of(p.min_difficulty_nbits);
        let chain = uniform_chain(91, T_MS, p.min_difficulty_nbits);
        let next = difficulty_of(next_nbits(&p, &chain));
        // Within 1% of unchanged (integer/weighting rounding only).
        let lo = &start * 99u32 / 100u32;
        let hi = &start * 101u32 / 100u32;
        assert!(
            next >= lo && next <= hi,
            "steady-state drifted: {start} -> {next}"
        );
    }

    #[test]
    fn daa_fast_blocks_raise_difficulty() {
        let p = params();
        let start = difficulty_of(p.min_difficulty_nbits);
        let chain = uniform_chain(91, T_MS / 2, p.min_difficulty_nbits);
        let next = difficulty_of(next_nbits(&p, &chain));
        assert!(next > start, "half-target solves must raise difficulty");
    }

    #[test]
    fn daa_slow_blocks_lower_difficulty() {
        let p = params();
        let start = difficulty_of(p.min_difficulty_nbits);
        let chain = uniform_chain(91, T_MS * 3, p.min_difficulty_nbits);
        let next = difficulty_of(next_nbits(&p, &chain));
        assert!(next < start, "3x-slow solves must lower difficulty");
    }

    // ----- error paths -----

    #[test]
    fn daa_instant_blocks_clamped_to_4x_per_step() {
        let p = params();
        let start = difficulty_of(p.min_difficulty_nbits);
        // All blocks in the same millisecond: solve times clamp to 1 ms,
        // raw LWMA would explode; the ×4 step clamp must bound it.
        let chain: Vec<(u64, u32)> = (0..91)
            .map(|_| (1_000_000, p.min_difficulty_nbits))
            .collect();
        let next = difficulty_of(next_nbits(&p, &chain));
        assert!(next <= &start * 4u32, "step rise must be clamped to 4x");
        assert!(next > start, "clamped rise must still rise");
    }

    #[test]
    fn daa_backwards_timestamps_do_not_panic_and_stay_clamped() {
        let p = params();
        let start = difficulty_of(p.min_difficulty_nbits);
        // Monotonically DECREASING timestamps (hostile input).
        let chain: Vec<(u64, u32)> = (0..91u64)
            .map(|i| (2_000_000_000 - i * 1_000, p.min_difficulty_nbits))
            .collect();
        let next = difficulty_of(next_nbits(&p, &chain));
        assert!(next <= &start * 4u32 && next >= start / 4u32);
    }

    #[test]
    fn daa_very_slow_blocks_clamped_to_quarter_per_step() {
        let p = params();
        let start = difficulty_of(p.min_difficulty_nbits);
        // 100x target spacing: raw LWMA would crater difficulty.
        let chain = uniform_chain(91, T_MS * 100, p.min_difficulty_nbits);
        let next = difficulty_of(next_nbits(&p, &chain));
        assert!(next >= &start / 4u32, "step fall must be clamped to /4");
        assert!(next < start, "clamped fall must still fall");
    }
}
