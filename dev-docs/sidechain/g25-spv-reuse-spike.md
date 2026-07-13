# G2.5 — Ergo-SPV-in-consensus reuse spike

**Date:** 2026-07-12 · **Status:** feasibility spike (read-only source audit) · **Question:** is PegMint objectivity "mostly wiring existing Rust verifiers, not new crypto"? **Verdict: YES — the claim holds.** All three verifier layers are clean, standalone, DB-free pure functions/traits over typed inputs. What's missing is *policy + plumbing*, not cryptography.

## Per-component verdict

| Component | Verdict | Crate · path · signature |
|---|---|---|
| **Autolykos v2 PoW** | **REUSABLE-AS-IS** | `ergo_crypto::pow::verify_pow_solution(header: &Header) -> Result<(), PowError>` (recomputes msg = blake2b256(header-without-pow), checks the v2 hit < target from `n_bits`; no state). Difficulty: `ergo_crypto::pow::verify_header_difficulty(header: &Header, epoch_headers: &[Header], config: &DifficultyParams) -> Result<(), DifficultyError>`. Core: `ergo_crypto::autolykos::v2::check_pow_v2(msg,nonce,height,version,target)`. |
| **NiPoPoW (from-genesis PoW-chain validity)** | **REUSABLE-AS-IS** | `ergo_validation::popow::proof::NipopowProofExt::is_valid(&self, chain_config: &DifficultyParams) -> bool` and `is_better_than(&self, that, chain_config) -> bool` (KMZ17 Alg. 4). `is_valid` already composes per-header `verify_pow_solution` + batch-merkle + connections/heights/difficulty. Interlink check: `check_popow_header_interlinks_proof(&PoPowHeader) -> bool`. Inputs are `Header`/`DifficultyParams` only — no DB. |
| **Inclusion proofs** | **REUSABLE-AS-IS** | Batch: `ergo_ser::batch_merkle_proof::{BatchMerkleProof, deserialize_batch_merkle_proof}` + `ergo_validation::popow::merkle::verify_batch_merkle_proof(&proof, expected_root: &[u8;32]) -> bool`. Single tx-in-block: `ergo_crypto::merkle::{merkle_proof_by_index, merkle_proof_verify(&proof, &expected_root) -> bool, transactions_root(tx_ids, witness_ids)}`. `header.transactions_root` is a field (`ergo_ser::header`); block.rs already does `transactions_root(ids) == header.transactions_root` — pure, standalone. |

## Coupling reality check

None of the three touch `StateStore`/DB/async-node context. They are pure functions / a blanket-impl trait over `Header`, `DifficultyParams`, `BatchMerkleProof`, `[u8;32]`. `DifficultyParams::mainnet()` exists (`ergo_crypto::difficulty`). So an `aegis-node` consensus path can call them directly with only `ergo-crypto` + `ergo-validation` + `ergo-ser` as deps. **The "mostly wiring" claim is VALIDATED.**

## Gaps (genuinely missing — all policy/plumbing, none new crypto)

1. **Ergo anchoring.** `NipopowProof::is_valid` proves *internal* PoW-chain validity but does **not** bind to Ergo *mainnet* specifically. Need a pinned Ergo genesis (or a signed checkpoint) header-id constant in `aegis-spec`, and a check that the proof's genesis == that anchor. Without it, an attacker forges a self-consistent low-history chain. (Policy + one constant.)
2. **Absolute suffix-work / acceptance threshold.** `is_better_than` is *relative* (KMZ17); the peg needs an absolute "enough honest work since the anchor" acceptance rule + the `N_mint`-depth check. Policy, layered on the existing comparison.
3. **Box-in-tx re-derivation.** Verifying the DepositReceipt box is output *i* of the receipt tx = deserialize tx (`ergo-ser` has it) → recompute tx-id → check box at index *i* → then tx-in-`txRoot` via `merkle_proof_verify`. Plumbing over existing pieces; no new verifier.
4. **Receipt well-formedness + `boxId` uniqueness (I2).** USE token id, R4 = sc-header-id, guarding-script/template hash, and the used-`boxId` set to stop replay. Pure checks on decoded boxes — Aegis-side logic to author.
5. **Reorg deeper than `N_mint`.** The peg-spv-design top risk (orphaned lock after mint). Pure design/policy — unbuilt.
6. **Packaging.** A single deterministic `verify_pegmint(proof_bytes, expected_template) -> Result<MintedNote, PegError>` that sequences: deserialize headers → `is_valid` + anchor → suffix-work/`N_mint` → tx-in-`txRoot` → box-in-tx → receipt well-formedness → `boxId` uniqueness → emit mint. Objective (pure fn of bytes).

## Rough build order

1. Pin Ergo mainnet anchor (genesis id / checkpoint) + `DifficultyParams::mainnet()` wiring in `aegis-spec`.
2. Header-chain wrapper: `is_valid` + anchor + suffix-work/`N_mint` acceptance.
3. Inclusion glue: tx→`txRoot` (`merkle_proof_verify`), box→tx (re-derive).
4. Receipt well-formedness + `boxId` used-set (I2).
5. Reorg/`N_mint` policy (design first — the graveyard item).
6. Package `verify_pegmint(...)`; oracle-test against real mainnet PegMint fixtures.

**Bottom line:** the cryptographic core is entirely reused; G2.5 is an integration + policy exercise, not a crypto build. The dogfood fallback (operator-mode under `V_cap`) can ship first and swap to `verify_pegmint` behind the same interface.
