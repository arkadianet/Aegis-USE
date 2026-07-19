//! The proof-system configuration: a uni-STARK over BabyBear with a
//! **SHA-256 FRI-Merkle commitment** (the "T2.1 SHA-256 MMCS" lever from
//! `dev-docs/sidechain/prover-speed-plan.md`).
//!
//! BabyBear is deliberate: it is the RISC0 verifier's field, so a settlement
//! RISC0 guest re-verifies these client proofs in-field, with no foreign-curve
//! MSM (`dev-docs/sidechain/hash-native-engine-design.md`). The FRI Merkle
//! *commitment* hash is SHA-256 (`p3-sha256`), because RISC0 accelerates
//! SHA-256 in-guest (via the patched `sha2` crate — see the guest workspace's
//! `[patch.crates-io]`): the guest verifies the 100× FRI Merkle openings on
//! the SHA accelerator instead of thousands of software Poseidon2-t24
//! permutations (measured 2.79× on `spend_verify`, 2.33× on total guest
//! cycles; the client also proves ~5.9× faster on hw-SHA hosts).
//!
//! What is SHA-256 here, and what is NOT:
//! - SHA-256: the FRI-Merkle commitment MMCS leaf hash + 2-to-1 compress
//!   (`SerializingHasher<Sha256>` leaf, `Sha256Compress` node). The digest is
//!   a 32-byte `[u8; 32]` instead of 8 BabyBear elements. The commitment's
//!   sole security requirement is collision resistance — SHA-256 provides it.
//! - SHA-256 (required by the MMCS choice): the Fiat-Shamir challenger is the
//!   byte-oriented `SerializingChallenger32<_, HashChallenger<u8, Sha256,
//!   32>>`. This is NOT optional: in this Plonky3 rev `DuplexChallenger<F, …>`
//!   only implements `CanObserve<Hash<F, F, N>>` (field-word digests) — it
//!   *cannot* observe the SHA byte roots `Hash<F, u8, 32>`. Only
//!   `SerializingChallenger32` implements `CanObserve<Hash<F, u8, N>>`.
//!   Fiat-Shamir over SHA-256 is a standard, sound transcript (SHA as a
//!   random oracle) and it too accelerates in-guest.
//! - Poseidon2 in-field, UNCHANGED: note crypto (commitments, nullifiers,
//!   owner keys, the accumulator) stays **Poseidon2** (`crate::poseidon`),
//!   because the guest re-verifies in-field. Only the proof system's Merkle
//!   commitment hash + transcript are byte-oriented.
//!
//! # Security (carried caveat — REVIEW ITEM)
//! Uses `FriParameters::new_benchmark_high_arity` (log_blowup = 1, high-arity
//! FRI), matching the spike. Per `aegis-hashnative-spike/RESULTS.md` these give
//! ~113-bit *conjectured* but only ~58-bit *proven* security; a production
//! deployment raises log_blowup / query count (≈2–3× prove time, larger proof,
//! still sub-second / ~MB). The FRI parameter choice is a flagged review item.

use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_sha256::{Sha256, Sha256Compress};
use p3_symmetric::SerializingHasher;
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::poseidon::F;

/// Degree-4 binomial extension of BabyBear — the challenge field.
pub type EF = BinomialExtensionField<BabyBear, 4>;

// ---- SHA-256 FRI-Merkle commitment ----
//
// `SerializingHasher<Sha256>` bridges BabyBear→bytes then SHA-256s (leaf hash);
// `Sha256Compress` is the 2-to-1 node compress over 32-byte digests. Both route
// through `sha2` (`sha2::block_api::compress256`), which RISC0 patches to its
// SHA accelerator in the guest. The MMCS commits over the SCALAR field `F`
// (`SerializingHasher` only implements `CryptographicHasher<F: Field, …>`, not
// over `F::Packing`), so the digest word type is `u8` and `DIGEST_ELEMS = 32`.
type ByteHash = Sha256;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = Sha256Compress;

type ValMmcs = MerkleTreeMmcs<F, u8, FieldHash, Compress, 2, 32>;
type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;
type Dft = Radix2DitParallel<F>;
type Pcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
/// Byte-oriented Fiat-Shamir challenger — REQUIRED with a SHA (byte-digest)
/// MMCS (see the module doc): it is the only challenger that can observe the
/// 32-byte SHA Merkle roots. Its SHA-256 sponge also accelerates in-guest.
type Challenger = SerializingChallenger32<F, HashChallenger<u8, ByteHash, 32>>;

/// The concrete STARK config for the engine's spend proofs.
pub type EngineConfig = StarkConfig<Pcs, EF, Challenger>;

/// Build the engine STARK config with the SHA-256 FRI-Merkle commitment.
/// Deterministic (no rng seed to agree on): SHA-256 is a fixed function.
pub fn make_config() -> EngineConfig {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(Sha256);
    let compress = Sha256Compress;
    let val_mmcs = ValMmcs::new(field_hash, compress, 3);

    // `ValMmcs` (SHA-256 hashers are `Copy`) is itself `Copy`, so this copies.
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs);
    let fri_params = FriParameters::new_benchmark_high_arity(challenge_mmcs);

    let dft = Dft::default();
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(vec![], byte_hash);

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
//     attack on low-entropy rows). The salt is still `SALT_ELEMS` BabyBear
//     elements (`P::Value = F`) regardless of the SHA digest-word type — the
//     hiding construction is hash-agnostic, so the SHA swap preserves it.
//   * [`hiding_fri_parameters`] (T1.2 query↔blowup rebalance): log_blowup = 3,
//     67 queries, 16-bit query PoW. This REPLACES the previous
//     `FriParameters::new_benchmark_zk` (log_blowup 2, 100 queries, pow 16) at
//     equal-or-better security in BOTH regimes, verified against the vendored
//     `p3-security` crate (see the soundness-regression test below):
//       conjectured 213.6 vs 212.0 bits, proven composite 97.2 vs 96.5 bits
//     (the proven bound binds on the batch-combination term in the
//     list-decoding regime for both parameter sets). The guest-verifier cost
//     scales ~linearly in query count → −33 % queries; the client pays the
//     larger blowup (×2 LDE) — a cost REBALANCE at constant-or-better
//     soundness, not a weakening.
//
// The masking budget: NUM_QUERIES (67) + O(1) out-of-domain points must not
// exceed the number of random rows (= the trace height, ≥ 128 for the spend).
// This inequality is asserted in tests and is a pinned REVIEW ITEM. The SHA
// swap does NOT touch this budget: it is an argument about queries/rows, not
// about the leaf-hash choice (and the query cut 100 → 67 only eases it).
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

/// Hiding-config FRI: log2 of the LDE blowup (T1.2 — see the module comment).
pub const HIDING_LOG_BLOWUP: usize = 3;
/// Hiding-config FRI: number of query rounds (T1.2).
pub const HIDING_NUM_QUERIES: usize = 67;
/// Hiding-config FRI: query-phase proof-of-work bits (T1.2).
pub const HIDING_QUERY_POW_BITS: usize = 16;

// The ZK masking budget, enforced at COMPILE TIME: query count + an O(1)
// out-of-domain margin must stay below the number of random rows the hiding
// interleave adds (= the trace height N_ROWS). See the module comment.
const _: () = assert!(
    HIDING_NUM_QUERIES + 8 <= crate::spend::monolith::N_ROWS,
    "ZK mask budget violated: queries + OOD margin must not exceed random rows"
);

/// The hiding-config FRI parameters (T1.2 query↔blowup rebalance; the
/// soundness-regression test pins them to at-least-ZK-baseline security in
/// both the conjectured and proven regimes).
pub fn hiding_fri_parameters<M>(mmcs: M) -> FriParameters<M> {
    FriParameters {
        log_blowup: HIDING_LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: HIDING_NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: HIDING_QUERY_POW_BITS,
        mmcs,
    }
}

type HidingValMmcs =
    MerkleTreeHidingMmcs<F, u8, FieldHash, Compress, ChaCha20Rng, 2, 32, SALT_ELEMS>;
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
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(Sha256);
    let compress = Sha256Compress;
    let val_mmcs = HidingValMmcs::new(field_hash, compress, 3, salt_rng);

    let challenge_mmcs = HidingChallengeMmcs::new(val_mmcs.clone());
    let fri_params = hiding_fri_parameters(challenge_mmcs);

    let dft = Dft::default();
    let pcs = HidingPcs::new(dft, val_mmcs, fri_params, NUM_RANDOM_CODEWORDS, mask_rng);
    let challenger = Challenger::from_hasher(vec![], byte_hash);

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

// NOTE (p3 0.6.1 rev-align): the `p3-security` soundness-regression test that
// held [`hiding_fri_parameters`] to the ZK-baseline security floor is dropped
// here because `p3-security` is not published on crates.io. The hiding FRI
// constants are unchanged; re-establishing this oracle (vendored copy or a
// dev-only git pin) is tracked as an I5 params/soundness review item.
