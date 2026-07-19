//! # Epoch-validity (Stage T) — proving `new_root` is a real merge-mined hn
//! suffix, not a settler-fabricated tree.
//!
//! Discharges the last trustlessness gap (`epoch-validity-design.md`): the v6
//! batch guest trusts the settler's epoch leaves; a malicious settler can mint a
//! private tree of fake notes and settle from nothing. This module makes that
//! **priced** instead of free.
//!
//! Stage-T scope, implemented here (design §"Stage T"):
//! - **E1** structural epoch validity — [`verify::verify_epoch`]: leaves
//!   re-derived from proven suffix blocks (`digest`, the anti-fabrication bind),
//!   header-id chain `T_prev → T_new` (`header_id`, R7), economics replay,
//!   anchor-window, `pegout_delay`.
//! - **E3** basic settled-burn accumulator — [`crate::settled`], chained R6.
//! - **E2** in-guest aux-PoW share verify — `share` (the fabrication pricer).
//! - **E4** canonical-Ergo anchor linkage — `anchor`.
//!
//! The journal is the §2.2 `AEGISPV1` layout; the PegVault reconstructs it
//! byte-exact and chains R4/R6/R7 (`bridge-tools/src/vault.rs`).

pub mod digest;
pub mod header_id;
#[cfg(feature = "aux-pow")]
pub mod share;
pub mod types;
pub mod verify;

pub use types::{PegIn, PegOut, SpendPublics, SuffixBlock};
pub use verify::{verify_epoch, EpochError, EpochResult, EpochWitness, Withdrawal};

use crate::poseidon::digest_to_bytes;

/// The Stage-T epoch-validity journal tag (`epoch-validity-design.md` §2.2 —
/// new image id v7).
pub const EPOCH_JOURNAL_TAG: &[u8; 8] = b"AEGISPV1";

/// Build the §2.2 epoch-validity journal the guest commits and the PegVault
/// reconstructs byte-exact:
/// `AEGISPV1 ‖ prev_root(32) ‖ new_root(32) ‖ settled_root_in(32) ‖
///  settled_root_out(32) ‖ tip_id_prev(32) ‖ tip_id_new(32) ‖ ergo_ref_id(32) ‖
///  counter_next_be(8) ‖ [amount_be(8) ‖ prop_len_be(8) ‖ recipient_prop]×N`.
///
/// All fixed-width fields precede the variable-length entry list (injectivity).
pub fn epoch_journal(
    result: &EpochResult,
    settled_root_in: &crate::poseidon::Digest,
    tip_id_prev: &[u8; 32],
    ergo_ref_id: &[u8; 32],
    counter_next: u64,
) -> Vec<u8> {
    let mut j = Vec::new();
    j.extend_from_slice(EPOCH_JOURNAL_TAG);
    j.extend_from_slice(&digest_to_bytes(&result.prev_root));
    j.extend_from_slice(&digest_to_bytes(&result.new_root));
    j.extend_from_slice(&digest_to_bytes(settled_root_in));
    j.extend_from_slice(&digest_to_bytes(&result.settled_root_out));
    j.extend_from_slice(tip_id_prev);
    j.extend_from_slice(&result.tip_id_new);
    j.extend_from_slice(ergo_ref_id);
    j.extend_from_slice(&counter_next.to_be_bytes());
    for wd in &result.withdrawals {
        j.extend_from_slice(&wd.amount.to_be_bytes());
        j.extend_from_slice(&(wd.recipient_prop.len() as u64).to_be_bytes());
        j.extend_from_slice(&wd.recipient_prop);
    }
    j
}
