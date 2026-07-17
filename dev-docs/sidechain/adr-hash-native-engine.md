# ADR: Aegis goes hash-native (Option B)

**Status:** ACCEPTED 2026-07-17 (operator decision: "let's go full hash native").
**Supersedes** the keep-vs-rebuild fork left open by
`trustless-settlement-design-pass.md`.

## Decision

Aegis's shielded pool is rebuilt **hash-native** — Plonky3 uni-STARK over
BabyBear with Poseidon2 commitments, hash-based keys (`owner = H(nk)`, no
elliptic curve in the note/spend path), and a Poseidon-Merkle note accumulator —
replacing Curve Trees + Bulletproofs over secp/secq. Branch:
`feat/hash-native-payment-engine` (`engine/` nested workspace). The Curve-Trees
engine on `main` remains the working baseline (attester bridge) until the new
engine is integrated and a fresh testnet is cut; no in-place migration.

## Why (the measured evidence — details in `spike-results/`)

Both options were built and measured, not argued:

- **Option A** (`option-a-settlement-curve-trees.md`): a settlement RISC0 guest
  on the audited Curve-Trees engine works, and `batch_verify` amortization is
  real (N=100 = 6.75× N=1; 94% shared MSM base). But the base is a **hard
  floor**: ~14 B cycles/batch of irreducible foreign-curve (secp/secq) MSM —
  GPU-cluster territory per settlement batch, forever.
- **Option B** (`option-b-settlement-hash-native.md`): the full Plonky3
  verifier cross-compiles to riscv32im cleanly (no hand-rolled FRI); in-field
  verify of one 2-in/2-out spend proof is **963 M cycles** (~15× less than A),
  flat/linear in N. Client cost ~251 ms / ~1.33 MB proof at depth 32
  (phone-class, per `hash-native-client-cost-spike.md`).
- **Cost curves cross near N≈115** — unoptimized B ties amortized A at very
  large batches. The decision is the **headroom asymmetry**: A's floor is
  cryptographically irreducible; B's number is a hash circuit with two levers A
  cannot match — the RISC0 Poseidon2 precompile / narrow trace (est.
  0.1–0.3 B/tx) and recursive aggregation (sublinear settlement).

## Price accepted

~1.33 MB client proofs (sidechain bandwidth/throughput; prunable, compressible
later), a ZK wrapper still to build (uni-STARK is not hiding by default), full
external re-review of the new core before real value, and the remaining engine
work (note encryption, wallet, 64-bit amounts, integration, fresh testnet).

## Roadmap (accepted with the decision)

1. **ZK wrapper** — the hiding property itself; first, since it may shape the
   proof format everything downstream consumes.
2. **Note encryption** (hash/KEM DH replacement) → **wallet** over
   `owner = H(nk)` → **64-bit amounts**.
3. **Integration** — swap the engine into aegis-node; **fresh testnet**
   (chain-id-breaking is free).
4. **Trustless peg-out** — `PegVault` ErgoScript on the STARK devnet:
   `verifyStark` + public-input binding (vault NFT, recipient/amount == journal).
5. **Hardening** — production FRI params, Poseidon precompile lever, real
   proving wall-clocks, then external review (the standing value-gate).

Option A's spike is **frozen as the documented fallback**
(`aegis-risc0-guest-spike`, commits `656f7aa`/`2e083c2`).
