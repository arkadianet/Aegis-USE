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
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

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
