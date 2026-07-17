//! Poseidon2 over BabyBear — the single hash primitive of the hash-native
//! engine, and the one shared by BOTH the native code and the in-circuit AIR.
//!
//! # Why one primitive, pinned to Plonky3's canonical constants
//! Every derivation in the engine (note commitment, owner key, nullifier, and
//! the Merkle accumulator) is a Poseidon2 permutation or a sponge/compression
//! built from it. The native functions here and the AIR ([`crate::spend`]) use
//! the *same* round constants (via [`air_round_constants`], built from
//! `try_from_layers` on the canonical BabyBear constant tables), so the value a
//! wallet computes natively and the value the circuit enforces agree **by
//! construction** — there is no second, hand-transcribed parameter set to drift.
//!
//! # Parameters (pinned; matches `aegis-hashnative-spike/RESULTS.md`)
//! Poseidon2, width `t = 16`, `R_F = 8` (4 + 4 external full rounds), `R_P = 13`
//! internal partial rounds, S-box `x^7`, over BabyBear (`p ≈ 2^31`). This is the
//! standard `Poseidon2BabyBear<16>`. A `t = 16` permutation is exactly one
//! 2-to-1 compression of two 8-limb (~248-bit) digests, which is why the Merkle
//! accumulator and Plonky3's own Merkle share the shape.
//!
//! # Sponge / domain separation (pinned layout — REVIEW ITEM)
//! Variable-length hashes use a fixed add-absorb sponge (rate 8, capacity 8):
//! the capacity is seeded with a per-purpose domain tag AND the input length,
//! then the input is absorbed in rate-8 chunks (one permutation each), and the
//! first 8 lanes are squeezed as the digest. Domain tag + length binding is
//! documented as `DOMAIN_*` below and flagged for external review.

use std::sync::OnceLock;

use p3_baby_bear::{
    default_babybear_poseidon2_16, BabyBear, Poseidon2BabyBear,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_16_INTERNAL,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2::ExternalLayerConstants;
use p3_poseidon2_air::RoundConstants;
use p3_symmetric::Permutation;

/// The engine field: BabyBear (the RISC0 verifier's field — settlement-cheap).
pub type F = BabyBear;

/// Permutation width `t`.
pub const WIDTH: usize = 16;
/// Sponge rate `r` (lanes absorbed/squeezed per permutation).
pub const RATE: usize = 8;
/// Sponge capacity `c = t - r` (holds the domain tag + length binding).
pub const CAPACITY: usize = WIDTH - RATE;
/// A digest / tree node / key: 8 BabyBear limbs (~248 bits).
pub const DIGEST_ELEMS: usize = 8;
/// S-box degree (`x^7`).
pub const SBOX_DEGREE: u64 = 7;
/// Optimal committed-register count for the degree-7 S-box in the AIR.
pub const SBOX_REGISTERS: usize = 1;
/// Half of the external full rounds (`R_F / 2 = 4`).
pub const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
/// Internal partial rounds (`R_P = 13`).
pub const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;

/// A 248-bit digest — the note commitment, key, nullifier, and Merkle node type.
pub type Digest = [F; DIGEST_ELEMS];

/// The AIR's concrete `RoundConstants` shape for BabyBear-t16.
pub type AegisRoundConstants = RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

// ----- domain-separation tags (pinned; REVIEW ITEM) -----
// Layout: high byte 0x0A = "Aegis", low byte = purpose. Placed in capacity
// lane `RATE`; the input length is placed in lane `WIDTH - 1`. Changing any of
// these is chain-id-breaking.
/// Owner-key derivation `owner = H(nk)`.
pub const DOMAIN_OWNER: u32 = 0x0A01;
/// Nullifier derivation `nf = H(nk, rho)`.
pub const DOMAIN_NULLIFIER: u32 = 0x0A02;
/// Note-commitment derivation `cm = H(value_limbs, owner, rho, r)`.
/// Bumped 0x0A03 → 0x0A13 when the value block became 4×16-bit limbs
/// (64-bit amounts) — old-layout commitments must not collide with new ones.
pub const DOMAIN_COMMITMENT: u32 = 0x0A13;

/// The canonical BabyBear-t16 permutation (cached).
fn perm16() -> &'static Poseidon2BabyBear<16> {
    static P: OnceLock<Poseidon2BabyBear<16>> = OnceLock::new();
    P.get_or_init(default_babybear_poseidon2_16)
}

/// Native Poseidon2 permutation on a width-16 state (in place).
pub fn permute(state: &mut [F; WIDTH]) {
    perm16().permute_mut(state);
}

/// The AIR round constants, built from the SAME canonical tables the native
/// permutation uses. This is what guarantees native/circuit agreement.
pub fn air_round_constants() -> &'static AegisRoundConstants {
    static RC: OnceLock<AegisRoundConstants> = OnceLock::new();
    RC.get_or_init(|| {
        let external = ExternalLayerConstants::<F, WIDTH>::new(
            BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL.to_vec(),
            BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL.to_vec(),
        );
        RoundConstants::try_from_layers(&external, &BABYBEAR_POSEIDON2_RC_16_INTERNAL)
            .expect("canonical BabyBear-16 constants match the t16/R_F8/R_P13 AIR shape")
    })
}

/// 2-to-1 compression of two digests: `truncate_8(perm(l ‖ r))`.
///
/// This is exactly Plonky3's `TruncatedPermutation<Perm16, 2, 8, 16>` — the
/// note accumulator and Plonky3's own Merkle tree share the shape. It is the
/// internal-node hash of [`crate::merkle`].
pub fn compress(l: &Digest, r: &Digest) -> Digest {
    let mut state = [F::ZERO; WIDTH];
    state[..DIGEST_ELEMS].copy_from_slice(l);
    state[DIGEST_ELEMS..].copy_from_slice(r);
    permute(&mut state);
    state[..DIGEST_ELEMS].try_into().expect("8 of 16 lanes")
}

/// Initial sponge state for `domain`, binding the input `len` (§ module doc).
pub fn sponge_init(domain: u32, len: usize) -> [F; WIDTH] {
    let mut state = [F::ZERO; WIDTH];
    state[RATE] = F::from_u32(domain);
    state[WIDTH - 1] = F::from_u64(len as u64);
    state
}

/// Serialize a digest to 32 bytes: 8 canonical `u32` limbs, little-endian.
pub fn digest_to_bytes(d: &Digest) -> [u8; 32] {
    use p3_field::PrimeField32;
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(4).zip(d.iter()) {
        chunk.copy_from_slice(&limb.as_canonical_u32().to_le_bytes());
    }
    out
}

/// Parse a digest from 32 bytes; `None` if any limb is non-canonical (≥ p).
/// Strictness matters: a non-canonical encoding of the same digest would be a
/// second wire form (malleability), so only the canonical one is accepted.
pub fn digest_from_bytes(bytes: &[u8; 32]) -> Option<Digest> {
    use p3_field::PrimeField32;
    let mut out = [F::ZERO; DIGEST_ELEMS];
    for (limb, chunk) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        let v = u32::from_le_bytes(chunk.try_into().expect("4-byte chunk"));
        if v >= F::ORDER_U32 {
            return None;
        }
        *limb = F::from_u32(v);
    }
    Some(out)
}

/// Hash `(domain, n: u64, limbs)` to 32 bytes — a compact engine-native id
/// (e.g. a block id from height ‖ prev-root limbs).
pub fn hash_id_domain(domain: u32, n: u64, limbs: &[F; DIGEST_ELEMS]) -> [u8; 32] {
    let mut input = [F::ZERO; DIGEST_ELEMS + 2];
    input[0] = F::from_u64(n & 0xFFFF_FFFF);
    input[1] = F::from_u64(n >> 32);
    input[2..].copy_from_slice(limbs);
    digest_to_bytes(&hash_domain(domain, &input))
}

/// Domain-separated fixed-length hash to a digest: add-absorb sponge over
/// rate-8 chunks (one permutation per chunk), squeeze the first 8 lanes.
///
/// Arity is fixed per call site (see [`crate::commit`], [`crate::nullifier`]),
/// so there is no padding ambiguity within a domain; the length is bound into
/// the capacity regardless.
pub fn hash_domain(domain: u32, input: &[F]) -> Digest {
    let mut state = sponge_init(domain, input.len());
    for chunk in input.chunks(RATE) {
        for (lane, &x) in chunk.iter().enumerate() {
            state[lane] += x;
        }
        permute(&mut state);
    }
    state[..DIGEST_ELEMS].try_into().expect("8 of 16 lanes")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn seq(base: u32, n: usize) -> Vec<F> {
        (0..n).map(|i| F::from_u32(base + i as u32)).collect()
    }

    fn digest(base: u32) -> Digest {
        seq(base, DIGEST_ELEMS).try_into().unwrap()
    }

    // ----- happy path -----

    #[test]
    fn permute_is_deterministic() {
        let mut a = [F::from_u32(7); WIDTH];
        let mut b = a;
        permute(&mut a);
        permute(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_domain_differs_per_domain() {
        let input = seq(1, DIGEST_ELEMS);
        assert_ne!(
            hash_domain(DOMAIN_OWNER, &input),
            hash_domain(DOMAIN_NULLIFIER, &input),
            "domain tag must separate otherwise-identical inputs"
        );
    }

    #[test]
    fn hash_domain_differs_per_input() {
        assert_ne!(
            hash_domain(DOMAIN_OWNER, &seq(1, DIGEST_ELEMS)),
            hash_domain(DOMAIN_OWNER, &seq(2, DIGEST_ELEMS)),
        );
    }

    #[test]
    fn compress_differs_when_either_child_changes() {
        let base = compress(&digest(10), &digest(20));
        assert_ne!(base, compress(&digest(11), &digest(20)));
        assert_ne!(base, compress(&digest(10), &digest(21)));
    }

    #[test]
    fn compress_is_not_symmetric() {
        // Order matters — a Merkle path must distinguish left from right.
        assert_ne!(
            compress(&digest(10), &digest(20)),
            compress(&digest(20), &digest(10)),
        );
    }

    // ----- oracle parity -----

    #[test]
    fn permute_matches_plonky3_reference_permutation() {
        // Oracle: the independent Plonky3 `Permutation` impl on the SAME state.
        // (Both are `default_babybear_poseidon2_16`; this pins that our wiring
        // uses the canonical permutation and nothing has been transcribed.)
        let perm = default_babybear_poseidon2_16();
        let mut input = [F::ZERO; WIDTH];
        for (i, x) in input.iter_mut().enumerate() {
            *x = F::from_u32(1000 + i as u32);
        }
        let expected = perm.permute(input);
        let mut got = input;
        permute(&mut got);
        assert_eq!(got, expected);
    }

    #[test]
    fn compress_matches_truncated_permutation_oracle() {
        use p3_symmetric::{PseudoCompressionFunction, TruncatedPermutation};
        let oracle =
            TruncatedPermutation::<_, 2, DIGEST_ELEMS, WIDTH>::new(default_babybear_poseidon2_16());
        let l = digest(100);
        let r = digest(200);
        let expected = oracle.compress([l, r]);
        assert_eq!(compress(&l, &r), expected);
    }
}
