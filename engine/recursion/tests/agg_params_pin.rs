//! vk-pin: the recursion-aggregation circuit fingerprint the epoch guest bakes.
//!
//! The epoch settlement guest verifies the aggregation root under
//! `AggParams::default()` (baked into its ELF). A drift in those FRI/cap
//! parameters silently changes the recursion tower the guest reconstructs —
//! caught here (a compile-time-pinned constant) AND by the guest image id it
//! changes (`settlement/EPOCH_IMAGE_ID.hex`). See recursion-feasibility.md §4(d).

use aegis_recursion::{AggParams, PINNED_AGG_PARAMS};

#[test]
fn agg_params_default_matches_pin() {
    assert_eq!(
        AggParams::default(),
        PINNED_AGG_PARAMS,
        "recursion aggregation circuit fingerprint drifted from the pin — a \
         config change requires re-pinning EPOCH_IMAGE_ID.hex and the vault"
    );
}
