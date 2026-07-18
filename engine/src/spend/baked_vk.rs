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
        0xab, 0x0b, 0x82, 0xe5, 0xad, 0xe0, 0x6f, 0x96, 0x38, 0xbb, 0x6c, 0xe9, 0x84, 0x94, 0x9b,
        0xf1, 0x2e, 0x20, 0xfc, 0x0a, 0xb9, 0x04, 0xec, 0xb7, 0xc9, 0x45, 0xa4, 0x6c, 0xdf, 0xc1,
        0x72, 0xb2,
    ],
    [
        0x0f, 0x5d, 0x3b, 0x93, 0x6f, 0x8a, 0x12, 0x47, 0x5f, 0xbd, 0x53, 0xf7, 0xd1, 0xa2, 0xe8,
        0x29, 0x2e, 0x51, 0xc2, 0x3c, 0x56, 0x47, 0xc6, 0x07, 0x3e, 0xf4, 0x82, 0x71, 0xe6, 0x56,
        0x75, 0xfb,
    ],
    [
        0xbb, 0xa7, 0xe8, 0xa4, 0x2f, 0xe3, 0xcf, 0x8f, 0xf2, 0x88, 0x9a, 0x19, 0x50, 0x59, 0x83,
        0xfd, 0x0f, 0x5b, 0x98, 0x57, 0xd7, 0xe3, 0xf5, 0x49, 0x66, 0xdb, 0xa5, 0x32, 0x09, 0xb0,
        0xfe, 0x02,
    ],
    [
        0x35, 0x44, 0xdd, 0xf6, 0x3c, 0xfa, 0x33, 0xb5, 0x55, 0x3b, 0x60, 0x45, 0x58, 0x52, 0x86,
        0x3c, 0x06, 0x19, 0x6d, 0x7b, 0xc9, 0xec, 0xdc, 0x49, 0x17, 0xef, 0x0d, 0xcc, 0x2b, 0xfc,
        0x8a, 0x66,
    ],
    [
        0x46, 0xfb, 0xe8, 0xb1, 0xed, 0xe3, 0x27, 0x8e, 0x59, 0x4c, 0x30, 0x16, 0x58, 0xc2, 0x2e,
        0x58, 0x60, 0x21, 0x74, 0x42, 0x67, 0xf9, 0x60, 0xf9, 0x63, 0xbc, 0xfd, 0x38, 0x02, 0x4d,
        0xc5, 0x25,
    ],
    [
        0x86, 0xc0, 0xa3, 0xa3, 0x8e, 0x84, 0x8f, 0x0a, 0x0f, 0xff, 0xa0, 0x75, 0xad, 0x87, 0x8a,
        0x45, 0x70, 0x65, 0x53, 0xc4, 0x51, 0x1d, 0x32, 0xc0, 0x9c, 0xf0, 0x30, 0x7b, 0x26, 0xa0,
        0x2f, 0x15,
    ],
    [
        0x3b, 0xa7, 0x7d, 0x4b, 0xaa, 0x45, 0xf7, 0x0d, 0xb4, 0x68, 0x18, 0x6d, 0xfa, 0xbb, 0x05,
        0x85, 0xcc, 0x0e, 0x6f, 0xf7, 0x7c, 0x12, 0xab, 0xe0, 0x1f, 0xf8, 0x2e, 0xf0, 0xe5, 0x68,
        0xf4, 0x90,
    ],
    [
        0x68, 0x20, 0x22, 0xcb, 0x2d, 0xad, 0xd6, 0xb0, 0x4b, 0x4d, 0x2c, 0x62, 0xe1, 0x0e, 0xb6,
        0x49, 0xf0, 0x48, 0x75, 0x8f, 0x2a, 0xb8, 0xdc, 0x91, 0xb3, 0x73, 0xb3, 0x3a, 0x90, 0x1b,
        0x66, 0x3e,
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
