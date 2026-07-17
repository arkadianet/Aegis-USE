//! The shared circuit keys: one hiding config + the matched preprocessed
//! `(prover_data, verifying_key)` pair for the 2-in/2-out spend AIR.
//!
//! `setup_preprocessed` commits the PUBLIC schedule (a salted Merkle commitment
//! — transparent, no trusted setup); the resulting `vk` is the published
//! verifying key both the wallet-prover and the node-verifier use, and `pd` is
//! the prover's matched half. In a deployment these are produced once and
//! shipped with the software; here [`SpendCircuit::new`] builds them and both
//! the wallet and the in-memory chain borrow it.

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

/// The verifying-key half, shareable with a node.
pub type SpendVk = PreprocessedVerifierKey<HidingEngineConfig>;

/// Shared proving/verifying keys for the spend circuit.
pub struct SpendCircuit {
    config: HidingEngineConfig,
    air: SpendAir,
    pd: PreprocessedProverData<HidingEngineConfig>,
    vk: SpendVk,
}

impl Default for SpendCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl SpendCircuit {
    /// Build fresh circuit keys (OS-seeded hiding masks).
    pub fn new() -> Self {
        Self::from_config(hiding_config())
    }

    /// Build REPRODUCIBLE circuit keys from a fixed seed — the published vk is
    /// then stable across restarts and identical for every party (a node
    /// reloads the same vk from disk-less reconstruction; the wallet and node
    /// agree). ⚠ REVIEW ITEM: a fixed seed makes the hiding masks deterministic
    /// across instances/restarts, weakening privacy; production must separate
    /// the PUBLIC preprocessed-salt (fixed → stable vk) from FRESH per-proof
    /// main-trace masks (an engine refinement — the two currently share one RNG).
    pub fn deterministic(seed: u64) -> Self {
        Self::from_config(make_hiding_config(
            ChaCha20Rng::seed_from_u64(seed),
            ChaCha20Rng::seed_from_u64(seed ^ 0x9e37_79b9_7f4a_7c15),
        ))
    }

    fn from_config(config: HidingEngineConfig) -> Self {
        let air = SpendAir;
        let degree_bits = N_ROWS.trailing_zeros() as usize;
        let (pd, vk) = setup_preprocessed::<HidingEngineConfig, _>(&config, &air, degree_bits)
            .expect("spend AIR has a preprocessed schedule");
        Self {
            config,
            air,
            pd,
            vk,
        }
    }

    /// The published verifying key (share with the node).
    pub fn vk(&self) -> &SpendVk {
        &self.vk
    }

    /// Produce a HIDING spend proof + its public values (canonical `u32`
    /// limbs). The wallet then attaches the output ciphertexts to form a `Tx`.
    pub fn prove(
        &self,
        inputs: &[InputNote; 2],
        input_paths: &[MerklePath; 2],
        root: Digest,
        outputs: &[OutputNote; 2],
        fee: u64,
    ) -> (Vec<u8>, Vec<u32>) {
        let (trace, pis) = build_spend_trace_with_paths(inputs, input_paths, root, outputs, fee);
        let proof = prove_with_preprocessed(&self.config, &self.air, trace, &pis, Some(&self.pd));
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
        verify_with_preprocessed(&self.config, &self.air, &proof, &pis, Some(&self.vk)).is_ok()
    }
}
