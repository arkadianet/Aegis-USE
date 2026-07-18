//! The baked spend-circuit verifying key (the "T1.1 vk-bake" lever from
//! `dev-docs/sidechain/prover-speed-plan.md`).
//!
//! The spend vk is a fixed function of fixed inputs: the [`SpendAir`]
//! preprocessed schedule, the trace degree (`N_ROWS`), the SHA-256 FRI-Merkle
//! MMCS, and the FIXED public preprocessed salt ([`PREPROCESSED_SALT_SEED`]).
//! Rebuilding it in-guest via `setup_preprocessed` costs millions of cycles
//! per settlement proof purely to re-derive a constant. Baking the vk as ELF
//! constants keeps the pin — the constants live in the imaged ELF, so the
//! image id still commits to the exact circuit — and skips the in-guest
//! FFT+commit entirely.
//!
//! Security: neutral. The pin moves from "recompute from the salt" to
//! "hard-coded in the imaged ELF"; a malicious prover still cannot substitute
//! a different circuit without changing the image id. The oracle-parity test
//! below asserts the baked constants equal `setup_preprocessed(..).vk` for the
//! pinned salt, so the bake cannot silently drift from the real derivation.
//!
//! [`SpendAir`]: crate::spend::monolith::SpendAir

use p3_uni_stark::PreprocessedVerifierKey;

use crate::config::{HidingCommitment, HidingEngineConfig};

/// Fixed salt for the PUBLIC preprocessed-schedule commitment. The schedule is
/// public, so a fixed salt leaks nothing; it makes the published vk identical
/// for every party/instance/restart. (The per-proof main-trace masks are the
/// privacy surface and are always fresh OS entropy — see the wallet's
/// `SpendCircuit`.)
pub const PREPROCESSED_SALT_SEED: u64 = 0x5EED_5A17_0A15_0001;

/// XOR-tweak applied to [`PREPROCESSED_SALT_SEED`] for the leaf-salt RNG, so
/// the mask RNG and salt RNG streams are distinct.
pub const PREPROCESSED_SALT_TWEAK: u64 = 0x9e37_79b9_7f4a_7c15;

/// `vk.width`: columns in the preprocessed schedule trace.
pub const SPEND_VK_WIDTH: usize = 7;

/// `vk.degree_bits`: log2 of the committed domain (trace degree + is_zk).
pub const SPEND_VK_DEGREE_BITS: usize = 8;

/// `vk.commitment`: the SHA-256 FRI-Merkle CAP (cap_height = 3 ⇒ 8 digests of
/// 32 bytes) of the preprocessed schedule, committed under the fixed public
/// salt.
pub const SPEND_VK_COMMITMENT: [[u8; 32]; 8] = [
    [
        0xb5, 0xb6, 0x7f, 0xc8, 0x20, 0x91, 0x21, 0x7e, 0x34, 0x0e, 0x49, 0xda, 0xe7, 0xcd, 0x67,
        0x5a, 0xaa, 0x7b, 0x6e, 0x75, 0xcb, 0xbc, 0x68, 0x2c, 0x43, 0xa3, 0x73, 0xcb, 0x1b, 0x4a,
        0x6c, 0x75,
    ],
    [
        0xcf, 0x2d, 0x35, 0xcb, 0xcb, 0xbb, 0xc1, 0xbe, 0xb7, 0xc0, 0x11, 0xad, 0x02, 0x78, 0x25,
        0xca, 0xd5, 0x96, 0xfb, 0xf3, 0xb5, 0x2f, 0x7a, 0xd8, 0x02, 0x30, 0xc6, 0xe9, 0x84, 0x09,
        0xd2, 0x5b,
    ],
    [
        0x45, 0x47, 0x00, 0x09, 0xcb, 0xbc, 0x10, 0x70, 0xe6, 0x10, 0x84, 0x49, 0x23, 0xb7, 0xc0,
        0xa9, 0x6d, 0xef, 0xac, 0xa3, 0x76, 0x90, 0x98, 0x8d, 0x53, 0x58, 0x56, 0x12, 0x2a, 0xeb,
        0x70, 0xf1,
    ],
    [
        0xbf, 0xc1, 0xc8, 0xa0, 0xa6, 0x41, 0x31, 0x75, 0xd2, 0x25, 0x6d, 0x0a, 0xd5, 0xc2, 0x32,
        0x41, 0x04, 0x62, 0x5d, 0x82, 0xd1, 0x7d, 0xbf, 0x36, 0x1e, 0x71, 0xf4, 0x69, 0xec, 0x58,
        0x46, 0x6c,
    ],
    [
        0x1a, 0x6e, 0x3e, 0x9d, 0xab, 0xa3, 0xc7, 0x23, 0x0e, 0x77, 0xfb, 0x34, 0x82, 0xe1, 0x18,
        0xbc, 0xe6, 0xe7, 0x4d, 0x28, 0x53, 0xa7, 0xe5, 0x4b, 0xb4, 0xa3, 0x96, 0x1e, 0xf9, 0xba,
        0x8a, 0xb2,
    ],
    [
        0xe9, 0x76, 0x60, 0xe3, 0xdd, 0x92, 0xca, 0x1f, 0x9b, 0xb1, 0xd1, 0x9b, 0xcd, 0x3a, 0x97,
        0x64, 0x83, 0x79, 0xd2, 0xd8, 0x3e, 0xdf, 0x50, 0xc6, 0x9a, 0x48, 0x39, 0x76, 0xe5, 0x13,
        0x67, 0x33,
    ],
    [
        0x9a, 0xcf, 0x46, 0x53, 0x12, 0xe7, 0xb7, 0x3f, 0x25, 0xe0, 0x42, 0x9b, 0x34, 0x3d, 0x3a,
        0xd2, 0xe3, 0x1b, 0x7e, 0xa1, 0xe2, 0x00, 0x92, 0x11, 0x61, 0xc7, 0x2d, 0x21, 0x4b, 0xfe,
        0x43, 0x4a,
    ],
    [
        0xa6, 0x6a, 0xbe, 0xfa, 0xf3, 0x01, 0x1d, 0x15, 0xef, 0x81, 0x1c, 0x04, 0xc7, 0x2c, 0x44,
        0x28, 0xea, 0x04, 0xb6, 0x07, 0x51, 0x28, 0x40, 0x2a, 0xea, 0x76, 0xdc, 0xcd, 0x71, 0xd5,
        0xa1, 0x8c,
    ],
];

/// The baked spend verifying key — byte-identical to
/// `setup_preprocessed(make_hiding_config(salt, salt ^ tweak), SpendAir,
/// N_ROWS.trailing_zeros()).1` (asserted by the oracle-parity test).
pub fn baked_spend_vk() -> PreprocessedVerifierKey<HidingEngineConfig> {
    PreprocessedVerifierKey {
        width: SPEND_VK_WIDTH,
        degree_bits: SPEND_VK_DEGREE_BITS,
        commitment: HidingCommitment::from(SPEND_VK_COMMITMENT.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use p3_uni_stark::setup_preprocessed;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::config::make_hiding_config;
    use crate::spend::monolith::{SpendAir, N_ROWS};

    // ----- oracle parity -----

    /// The baked constants MUST equal the real `setup_preprocessed` derivation
    /// for the pinned public salt. If the circuit, MMCS, or salt changes, this
    /// fails and the constants must be re-baked (and the settlement image id
    /// re-pinned).
    #[test]
    fn baked_vk_matches_setup_preprocessed_derivation() {
        let setup_config = make_hiding_config(
            ChaCha20Rng::seed_from_u64(PREPROCESSED_SALT_SEED),
            ChaCha20Rng::seed_from_u64(PREPROCESSED_SALT_SEED ^ PREPROCESSED_SALT_TWEAK),
        );
        let degree_bits = N_ROWS.trailing_zeros() as usize;
        let (_pd, vk) =
            setup_preprocessed::<HidingEngineConfig, _>(&setup_config, &SpendAir, degree_bits)
                .expect("spend AIR has a preprocessed schedule");

        let derived: &[[u8; 32]] = vk.commitment.as_ref();
        assert_eq!(
            (vk.width, vk.degree_bits, derived),
            (
                SPEND_VK_WIDTH,
                SPEND_VK_DEGREE_BITS,
                SPEND_VK_COMMITMENT.as_slice()
            ),
            "baked vk drifted from the derivation — re-bake: width={} degree_bits={} commitment={:?}",
            vk.width,
            vk.degree_bits,
            derived
        );
    }
}
