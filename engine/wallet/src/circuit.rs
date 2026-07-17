//! The shared spend-circuit keys: the matched preprocessed
//! `(prover_data, verifying_key)` pair for the 2-in/2-out spend AIR, plus the
//! per-proof proving path.
//!
//! # The RNG split (privacy-critical — see the ZK design in dev-docs)
//! A hiding uni-STARK has TWO randomness surfaces, with OPPOSITE requirements:
//!
//! - The **preprocessed-schedule commitment** (→ the published `vk`) must be
//!   IDENTICAL for every party and across restarts, or a wallet's proof cannot
//!   be verified. The preprocessed trace is the PUBLIC fixed schedule, so its
//!   salt leaks nothing — we commit it under a FIXED internal salt seed
//!   ([`PREPROCESSED_SALT_SEED`]). This is the whole reason the vk is stable.
//!
//! - The **per-proof main-trace masks** (random interleaved rows + codewords +
//!   leaf salts over the SECRET witness) ARE the privacy. They must be FRESH
//!   OS-CSPRNG entropy on every proof; determinism here would reopen the
//!   leakage the ZK milestone closed.
//!
//! These two must never share a seed. This module makes that **structurally
//! impossible**: there is exactly one constructor ([`SpendCircuit::new`]); it
//! takes no seed; setup uses the fixed public salt, and [`SpendCircuit::prove`]
//! draws a fresh OS-seeded hiding config for every proof. There is no
//! `deterministic(seed)` API that could couple them.

use aegis_engine::config::{hiding_config, make_hiding_config, HidingEngineConfig};
use aegis_engine::merkle::MerklePath;
use aegis_engine::poseidon::{Digest, F};
use aegis_engine::spend::monolith::{
    build_spend_trace_with_paths, InputNote, OutputNote, SpendAir, N_PUB, N_ROWS,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_uni_stark::{
    prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed, PreprocessedProverData,
    PreprocessedVerifierKey, Proof,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Fixed salt for the PUBLIC preprocessed-schedule commitment. The schedule is
/// public, so a fixed salt leaks nothing; it makes the published vk identical
/// for every party/instance/restart. Privacy rests solely on the per-proof
/// main-trace masks, which are always fresh OS entropy.
const PREPROCESSED_SALT_SEED: u64 = 0x5EED_5A17_0A15_0001;

/// The verifying-key half, shareable with a node.
pub type SpendVk = PreprocessedVerifierKey<HidingEngineConfig>;

/// Shared proving/verifying keys for the spend circuit.
pub struct SpendCircuit {
    air: SpendAir,
    /// Committed under the FIXED preprocessed salt (paired with `vk`).
    pd: PreprocessedProverData<HidingEngineConfig>,
    /// The stable published verifying key.
    vk: SpendVk,
    /// A reusable config for verification. Verification never draws from the
    /// RNG (mask/salt material travels in the proof), so a fixed seed here is
    /// safe and avoids per-verify entropy — important for a node verifying many
    /// txs.
    verify_config: HidingEngineConfig,
}

impl Default for SpendCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl SpendCircuit {
    /// Build the shared circuit keys. The vk is deterministic (fixed public
    /// preprocessed salt); proofs are non-deterministic (fresh masks per
    /// [`Self::prove`]).
    pub fn new() -> Self {
        let air = SpendAir;
        let degree_bits = N_ROWS.trailing_zeros() as usize;

        // Fixed-salt config used ONLY to commit the public preprocessed
        // schedule → a stable vk. Its mask RNG is irrelevant here (setup
        // commits only the preprocessed trace).
        let setup_config = make_hiding_config(
            ChaCha20Rng::seed_from_u64(PREPROCESSED_SALT_SEED),
            ChaCha20Rng::seed_from_u64(PREPROCESSED_SALT_SEED ^ 0x9e37_79b9_7f4a_7c15),
        );
        let (pd, vk) =
            setup_preprocessed::<HidingEngineConfig, _>(&setup_config, &air, degree_bits)
                .expect("spend AIR has a preprocessed schedule");

        let verify_config =
            make_hiding_config(ChaCha20Rng::seed_from_u64(0), ChaCha20Rng::seed_from_u64(0));

        Self {
            air,
            pd,
            vk,
            verify_config,
        }
    }

    /// The published verifying key (share with the node).
    pub fn vk(&self) -> &SpendVk {
        &self.vk
    }

    /// Produce a HIDING spend proof + its public values (canonical `u32`
    /// limbs), with FRESH OS-seeded masks (the preprocessed half reuses the
    /// stable `pd`, so the vk still verifies). The wallet then attaches the
    /// output ciphertexts to form a `Tx`.
    pub fn prove(
        &self,
        inputs: &[InputNote; 2],
        input_paths: &[MerklePath; 2],
        root: Digest,
        outputs: &[OutputNote; 2],
        fee: u64,
    ) -> (Vec<u8>, Vec<u32>) {
        // Fresh OS entropy for the main-trace masks — the privacy surface.
        let prove_config = hiding_config();
        let (trace, pis) = build_spend_trace_with_paths(inputs, input_paths, root, outputs, fee);
        let proof = prove_with_preprocessed(&prove_config, &self.air, trace, &pis, Some(&self.pd));
        let publics = pis.iter().map(|x| x.as_canonical_u32()).collect();
        (
            postcard::to_allocvec(&proof).expect("proof serializes"),
            publics,
        )
    }

    /// Verify a spend proof against its public values (the node's check).
    pub fn verify(&self, proof_bytes: &[u8], publics: &[u32]) -> bool {
        if publics.len() != N_PUB {
            return false;
        }
        let Ok(proof) = postcard::from_bytes::<Proof<HidingEngineConfig>>(proof_bytes) else {
            return false;
        };
        let pis: Vec<F> = publics.iter().map(|&x| F::from_u32(x)).collect();
        verify_with_preprocessed(&self.verify_config, &self.air, &proof, &pis, Some(&self.vk))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_engine::commit::{note_commitment, owner_key};
    use aegis_engine::merkle::NoteTree;

    fn digest(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    /// A balanced 2-in/2-out spend witness (both inputs in a fresh tree).
    fn sample_spend() -> (
        [InputNote; 2],
        [MerklePath; 2],
        Digest,
        [OutputNote; 2],
        u64,
    ) {
        let nk = digest(1);
        let owner = owner_key(&nk);
        let in0 = InputNote {
            value: 1_000,
            nk,
            rho: digest(50),
            r: digest(90),
            index: 0,
        };
        let in1 = InputNote {
            value: 500,
            nk,
            rho: digest(60),
            r: digest(100),
            index: 1,
        };
        let mut tree = NoteTree::new();
        tree.append(note_commitment(in0.value, &owner, &in0.rho, &in0.r));
        tree.append(note_commitment(in1.value, &owner, &in1.rho, &in1.r));
        let paths = [tree.authentication_path(0), tree.authentication_path(1)];
        let root = tree.root();
        let out0 = OutputNote {
            value: 1_490,
            owner: digest(400),
            rho: digest(450),
            r: digest(490),
        };
        let out1 = OutputNote {
            value: 0,
            owner,
            rho: digest(650),
            r: digest(690),
        };
        ([in0, in1], paths, root, [out0, out1], 10)
    }

    /// The privacy-critical property: the published vk is IDENTICAL across two
    /// independent instances (each instance's vk verifies the OTHER's proof —
    /// only possible if the preprocessed commitment is the same), while two
    /// proofs of the SAME statement from those instances DIFFER (fresh masks).
    #[test]
    fn vk_is_stable_across_instances_and_masks_are_fresh() {
        let a = SpendCircuit::new();
        let b = SpendCircuit::new();
        let (inputs, paths, root, outputs, fee) = sample_spend();

        let (proof_a, pub_a) = a.prove(&inputs, &paths, root, &outputs, fee);
        let (proof_b, pub_b) = b.prove(&inputs, &paths, root, &outputs, fee);

        assert_eq!(pub_a, pub_b, "same public statement");
        assert_ne!(
            proof_a, proof_b,
            "fresh OS masks ⇒ two proofs of one statement must differ"
        );
        // Stable vk: each instance's verifier accepts the other's proof. This
        // is only possible if their published vks (preprocessed commitments)
        // are byte-identical.
        assert!(a.verify(&proof_b, &pub_b), "A's vk verifies B's proof");
        assert!(b.verify(&proof_a, &pub_a), "B's vk verifies A's proof");
    }
}
