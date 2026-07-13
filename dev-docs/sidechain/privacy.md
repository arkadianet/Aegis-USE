# Aegis — privacy specification

**Date:** 2026-07-11  
**Status:** canon  
**Product:** [aegis-spec.md](./aegis-spec.md)

---

## 1. Privacy bar

| Property | On Aegis (between pegs) | On Ergo peg |
|---|---|---|
| Sender | Hidden | Lock tx visible |
| Receiver | Hidden | Unlock tx visible |
| Amount | Hidden | `N` visible |
| Precision | Any multiple of `0.001` USE in commitments | Same domain |

Claim honestly: privacy is **between peg-in and peg-out**. Edges and quiet-chain timing heuristics remain.

## 2. Mechanism — decided (design stage)

**Mandatory global shielded note pool** (not rings, not cleartext SigmaJoin/ZeroJoin).

On-chain: note commitments (Curve Tree) + nullifiers + proofs + ciphertexts.  
Off-chain: note plaintexts in wallets.

| Rejected | Why |
|---|---|
| C0 ZeroJoin/SigmaJoin cleartext amounts | Fails amount-hiding |
| C1 rings as primary | Weak on quiet chains; Monero moving to full-set (FCMP++) |

## 3. Proving engine — decided, provisional

| Choice | Status |
|---|---|
| **Curve Trees + Bulletproofs(+)** | **Chosen** — transparent; Ergo/Monero-adjacent; ~30–40 ms verify (paper figure) fits 15s |
| Halo2 / Orchard | Fallback only |

Scala does **not** verify these proofs. `aegis-node` does (native Rust).

**Engineering reality (2026-07-12 review):** no production Rust stack for this exists. `ergo-curve-trees` (reference dir) is an on-chain ErgoScript *membership* verifier with a TS prover — wrong layer, no amounts/nullifiers. Base = paper authors' research repo; the full note protocol (keys, commitments, nullifiers, encryption) is an unwritten Sapling-scale spec. **Gate G1.5 (proving spike) must pass before node build** — see [engineering.md](./engineering.md) §2b, and the fallback/kill criteria in §6.

## 4. Fees under privacy

On-SC fee = **flat, public, amount-independent**, with uniform (padded) tx shape — a constant leaks zero bits. Never `f(amount)`: a value-correlated fee is a public amount oracle that re-enables peg-edge tracing and taint analysis, and on a quiet chain amounts are the discriminator that stitches everything together. Value-scaled fees live at the **peg edges**, where `N` is public by nature. Rejected alternatives (public `%`, hidden-`%`-paid, `%`-burn): `notes/archive/fee-privacy-alternatives.md`.

## 5. Wallet sync

IVK trial-decrypt of outputs; nullifier set for spent detection. v1 = full node; compact light sync later.

## 5b. Note protocol

The concrete construction — note commitment, key hierarchy (spend/IVK/OVK), nullifier PRF, note encryption, uniform 2-in/2-out tx shape — is specified in [note-protocol.md](./note-protocol.md), grounded in the vendored Curve Trees reference.

## 6. Research trail (archived)

Full decision evidence under `notes/archive/`: `privacy-mechanism-decision.md`, `proving-engine-decision.md`, `full-privacy.md`, `option-c-sigma-native-research.md`. This file is primary.
