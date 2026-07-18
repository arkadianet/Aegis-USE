//! The proof-system configuration: a uni-STARK over BabyBear with a Poseidon2
//! FRI (the settlement-cheap config the client-cost spike measured).
//!
//! BabyBear + Poseidon2-FRI is deliberate: it is the RISC0 verifier's field, so
//! a settlement RISC0 guest re-verifies these client proofs in-field, with no
//! foreign-curve MSM (`dev-docs/sidechain/hash-native-engine-design.md`).
//!
//! # Security (carried caveat — REVIEW ITEM)
//! Uses `FriParameters::new_benchmark_high_arity` (log_blowup = 1, high-arity
//! FRI), matching the spike. Per `aegis-hashnative-spike/RESULTS.md` these give
//! ~113-bit *conjectured* but only ~58-bit *proven* security; a production
//! deployment raises log_blowup / query count (≈2–3× prove time, larger proof,
//! still sub-second / ~MB). The FRI parameter choice is a flagged review item.

use p3_baby_bear::{default_babybear_poseidon2_16, default_babybear_poseidon2_24, BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::poseidon::F;

/// Degree-4 binomial extension of BabyBear — the challenge field.
pub type EF = BinomialExtensionField<BabyBear, 4>;

type Perm16 = p3_baby_bear::Poseidon2BabyBear<16>;
type Perm24 = p3_baby_bear::Poseidon2BabyBear<24>;

type FieldHash = PaddingFreeSponge<Perm24, 24, 16, 8>;
type Compress = TruncatedPermutation<Perm16, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, FieldHash, Compress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;
type Dft = Radix2DitParallel<F>;
type Pcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type Challenger = DuplexChallenger<F, Perm24, 24, 16>;

/// The concrete STARK config for the engine's spend proofs.
pub type EngineConfig = StarkConfig<Pcs, EF, Challenger>;

/// Build the engine STARK config. Uses the canonical (deterministic) BabyBear
/// Poseidon2 permutations for the FRI Merkle tree and challenger — reproducible
/// across prover/verifier (no rng seed to agree on).
pub fn make_config() -> EngineConfig {
    let perm16 = default_babybear_poseidon2_16();
    let perm24 = default_babybear_poseidon2_24();

    let field_hash = FieldHash::new(perm24.clone());
    let compress = Compress::new(perm16);
    let val_mmcs = ValMmcs::new(field_hash, compress, 3);

    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters::new_benchmark_high_arity(challenge_mmcs);

    let dft = Dft::default();
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm24);

    StarkConfig::new(pcs, challenger)
}

// ===================== the ZERO-KNOWLEDGE (hiding) config =====================
//
// A uni-STARK is NOT hiding by default: FRI query openings are pure functions of
// the witness trace (see the leakage model in
// `dev-docs/sidechain/hash-native-spend-circuit.md` — a constant trace column,
// e.g. the monolith's value bus, is revealed VERBATIM by any single query).
// The hiding config applies the masking construction Plonky3 implements from
// the ZK-STARKs literature (ePrint 2024/1037 §4.2; salted commitments; random
// trace interleaving as in ethSTARK ePrint 2021/582):
//   * `HidingFriPcs`: interleaves the committed trace with an equal number of
//     uniformly random rows (each column polynomial gains `h` random degrees of
//     freedom, so any ≤ h openings off the trace domain are jointly uniform)
//     and appends `NUM_RANDOM_CODEWORDS` random codewords that mask the batched
//     FRI polynomial; quotient chunks are masked by `v_H·t_i` with a
//     Σ-correcting last chunk (2024/1037 §4.2).
//   * `MerkleTreeHidingMmcs`: salts every leaf with `SALT_ELEMS` random field
//     elements, making the Merkle commitment itself hiding (no dictionary
//     attack on low-entropy rows).
//   * `FriParameters::new_benchmark_zk`: log_blowup = 2, 100 queries, 16-bit
//     query PoW — the crate's production-shaped ZK parameter set (conjectured
//     soundness 2·100+16 = 216 bits by the ethSTARK conjecture).
//
// The masking budget: NUM_QUERIES (100) + O(1) out-of-domain points must not
// exceed the number of random rows (= the trace height, ≥ 128 for the spend).
// This inequality is asserted in tests and is a pinned REVIEW ITEM.
//
// ⚠ The mask RNG MUST be cryptographically secure — the masks ARE the privacy.
// Plonky3's own ZK test uses a fixed-seed `SmallRng` (fine for tests, fatal in
// production). We use `ChaCha20Rng` (a CSPRNG) and the client entry point seeds
// it from OS entropy.

/// Random codewords appended per commitment (masks the batched FRI codeword).
/// Matches Plonky3's own ZK test value; adequacy is a REVIEW ITEM.
pub const NUM_RANDOM_CODEWORDS: usize = 4;
/// Salt elements per Merkle leaf (~124 bits of salt over BabyBear).
pub const SALT_ELEMS: usize = 4;

type HidingValMmcs = MerkleTreeHidingMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    FieldHash,
    Compress,
    ChaCha20Rng,
    2,
    8,
    SALT_ELEMS,
>;
type HidingChallengeMmcs = ExtensionMmcs<F, EF, HidingValMmcs>;
type HidingPcs = HidingFriPcs<F, Dft, HidingValMmcs, HidingChallengeMmcs, ChaCha20Rng>;

/// The hiding (zero-knowledge) STARK config for the engine's spend proofs.
pub type HidingEngineConfig = StarkConfig<HidingPcs, EF, Challenger>;

/// The hiding PCS commitment type — the (serde) content of a preprocessed
/// verifying key. Exposed so a settlement verifier can carry the published vk
/// (`PreprocessedVerifierKey { width, degree_bits, commitment }`) across a wire
/// or into a guest, since the vk struct itself is not `Serialize`.
pub type HidingCommitment = <HidingPcs as p3_commit::Pcs<EF, Challenger>>::Commitment;

/// Build the hiding engine config from caller-supplied mask/salt RNGs.
///
/// The RNGs generate the trace/codeword masks and leaf salts — they must be
/// cryptographically secure and freshly seeded for PROVING ([`hiding_config`]).
/// For VERIFYING the RNG is never drawn from (`HidingFriPcs::verify` only
/// merges the random-codeword openings), so a fixed seed is safe
/// ([`hiding_config_for_verify`]).
pub fn make_hiding_config(mask_rng: ChaCha20Rng, salt_rng: ChaCha20Rng) -> HidingEngineConfig {
    let perm16 = default_babybear_poseidon2_16();
    let perm24 = default_babybear_poseidon2_24();

    let field_hash = FieldHash::new(perm24.clone());
    let compress = Compress::new(perm16);
    let val_mmcs = HidingValMmcs::new(field_hash, compress, 3, salt_rng);

    let challenge_mmcs = HidingChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters::new_benchmark_zk(challenge_mmcs);

    let dft = Dft::default();
    let pcs = HidingPcs::new(dft, val_mmcs, fri_params, NUM_RANDOM_CODEWORDS, mask_rng);
    let challenger = Challenger::new(perm24);

    StarkConfig::new(pcs, challenger)
}

/// The PROVER's hiding config: masks and salts seeded from OS entropy (via the
/// OS-seeded thread RNG). **Use this to prove real spends** — the privacy of the
/// witness rests entirely on these masks being unpredictable.
pub fn hiding_config() -> HidingEngineConfig {
    // `make_rng` seeds a fresh `SeedableRng` from OS entropy.
    make_hiding_config(
        rand::make_rng::<ChaCha20Rng>(),
        rand::make_rng::<ChaCha20Rng>(),
    )
}

/// The VERIFIER's hiding config: the RNG is never drawn from during
/// verification, so a fixed seed avoids requiring entropy (e.g. inside the
/// settlement guest).
pub fn hiding_config_for_verify() -> HidingEngineConfig {
    make_hiding_config(ChaCha20Rng::seed_from_u64(0), ChaCha20Rng::seed_from_u64(0))
}
