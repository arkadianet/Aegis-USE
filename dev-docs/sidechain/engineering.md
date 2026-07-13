# Aegis — engineering reality (scale, reuse, missing specs)

**Date:** 2026-07-12  
**Status:** canon (adversarial review round 2 — scale/feasibility)  
**Role:** what it actually takes to build this. Design says *what*; this file says *how big* and *what is still unspecified*. If this file and a design doc disagree on feasibility/status, this file wins until resolved.

---

## 1. The honest framing

Aegis is **a new blockchain plus a Zcash-class shielded protocol plus a cross-chain peg**, built by one developer with AI assistance. Each of those three is independently a serious project. The design docs are architecturally sound but were written at "component named ⇒ component exists" altitude. This file corrects that.

| Workstream | Closest prior art | Their cost |
|---|---|---|
| Shielded note protocol (W1) | Zcash Sapling spec+impl; Monero FCMP++ (same construction family as ours) | Multi-year, dedicated cryptographers, multiple audits |
| New PoW chain (W2) | Any merge-mined altchain | Months even with heavy reuse |
| Trust-bounded peg (W3) | Rosen, tBTC, drivechains | The graveyard is large |

We are not doing these at their fidelity — dogfood scope + reuse cuts this hard — but the *shape* of the work is theirs.

## 2. Reuse reality check (verified 2026-07-12)

### 2a. This monorepo — real but partial

Workspace has `ergo-primitives/ser/chain-spec/crypto/sigma/validation/wallet/state/p2p/sync/mempool/mining/...`. What transfers:

| Reusable ~as-is | Reusable with surgery | New (no reuse) |
|---|---|---|
| `ergo-ser` VLQ/codec primitives | `ergo-p2p` framing/peering (new magic, new message set for shielded txs) | Aegis header + block format, DAA, fork choice |
| `ergo-crypto` hashes/EC | `ergo-mining` Autolykos plumbing (target logic reusable; template/binding new) | Commitment-tree + nullifier state machine (versioned, reorg-safe) |
| `tracing`/config/db patterns | `ergo-chain-spec` pattern (new `aegis-spec` crate, do not touch mainnet vectors) | All shielded tx validation |
| | `ergo-sync` skeleton | Wallet: keys, scanning, proving |

**Not reusable at all:** `ergo-sigma` / `ergo-validation` / `ergo-state` consensus logic — Aegis blocks contain no ErgoScript and no Ergo state tree. The "reuse ergo-sigma" line in aegis-spec §10 is wrong for the SC ledger (it matters only for peg-side tooling that builds Ergo txs).

### 2b. Proving stack — the load-bearing correction

**`~/coding/reference/ergo-core/ergo-curve-trees` is NOT a basis for Aegis.** Verified: it is an *on-chain ErgoScript verifier* for Curve-Tree **membership** proofs (AUTCT-style) with a **TypeScript** prover. No amounts, no nullifiers, no balance circuit, no Rust library. Wrong layer (Aegis verifies natively in Rust) and wrong scope (membership ≠ payments).

What Aegis W1 actually needs (≈ the Vcash construction from the Curve Trees paper, ePrint 2022/756 — same family Monero chose for FCMP++):

| Piece | Source today |
|---|---|
| Curve Trees select-and-rerandomize + BP circuits (Rust) | Paper authors' research repo — research quality, unaudited, needs vendoring + productionizing. **Cloned 2026-07-12 → `~/coding/reference/crypto/curve-trees/`** (workspace: `bulletproofs` fork + `relations`; `PRF.md` covers nullifier PRF) |
| secp256k1/secq256k1 2-cycle arithmetic | Partially in dalek forks / arkworks; needs selection + review |
| Value commitments, range proofs, balance-with-fee | Standard BP+, but *our integration* into the CT spend circuit is new |
| Nullifier derivation (in-circuit PRF), key hierarchy (spend/IVK/OVK/diversified addrs), note encryption, memo | **Unwritten.** This is a Sapling-spec-sized protocol document that does not exist yet |

**Measured 2026-07-12 (G1.5 spike, PASS — [g15-proving-spike.md](./g15-proving-spike.md)):** on the target 7800X3D, secp-cycle Pour proves in 1.4–2.9 s, verifies in 22–43 ms single / 1.3–3 ms batched, proofs 3.4–4 KB, at set sizes 2^20–2^40. The paper-figure assumptions held; block verification is a non-issue, bandwidth sets the weight limit.

## 3. Missing consensus specs (must exist before `aegis-node` beyond a toy)

> **2026-07-12: written — [consensus.md](./consensus.md)** covers PoW binding (extension-field commitment, verified stock-legal against ported rules 400/405/406), header layout, LWMA-90 DAA, MTP-11 timestamps, fork choice + versioned rollback (≥240 blocks), genesis, and block limits. Remaining from this table: PegMint objectivity (G2.5) and the state-growth policy (tracked below).

| Item | Why it can't be hand-waved |
|---|---|
| **PoW binding** | 15s blocks require: every Autolykos attempt that meets the (lower) SC target is an Aegis block, with the mined message committing to the SC header. The current "sidecar-local packaging, application-layer state box" rule secures *anchors*, not *blocks* — as written, Aegis blocks between Ergo wins have no independent PoW. Decide: (a) Autolykos-with-SC-target + commitment (real MM), or (b) anchors-only + sequencer-style soft blocks (weaker, simpler). This changes the node fundamentally. |
| **Difficulty adjustment** | 15s target with one-laptop→variable hashrate needs a responsive DAA (LWMA-class), not Ergo's epoch scheme. Off-by-design here = chain stalls or block floods. |
| **Reorg semantics for tree + nullifiers** | Commitment tree and nullifier set must roll back exactly (B2). Needs versioned/persistent structures + tests. Known-hard corner. |
| **Block weight / limits** | Proofs are KB-scale; 15s blocks. Set weight units, per-block proof-verify budget (e.g. 40 ms × k), mempool policy. |
| **Timestamp rules, fork-choice tiebreak, genesis format** | Standard but must be written down to be implemented twice (node + tests). |
| **State-growth policy** | Tree storage is cheap (frontier-only for consensus; wallets keep own witnesses), but the **nullifier set grows forever**. Accept for dogfood with metrics; planned post-v1 remedy = **threshold turnstile R1-T** (shielded epoch migrations, attester-aggregated expiry accounting, grace tier — recycles lost USE → pot and archives old nullifier sets; needs S1 + a verifiable-encryption gadget in the circuit). Design: `notes/archive/storage-rent-privacy-tradeoffs.md`. |
| **PegMint objectivity (W3)** | A validator syncing from genesis years later must validate every PegMint identically. "Trusted Ergo node" is not consensus — PegMint must embed a self-contained proof: Ergo header segment (cumulative-difficulty checked) + tx/box inclusion. That is an **Ergo SPV client inside Aegis consensus** + a policy for >`N_mint` Ergo reorgs. Design doc required; security.md A2 updated to match. |

## 4. Fee design under privacy — resolved (2026-07-12, rev 2)

The original end-state (`%`-fee *hidden inside the private spend*, 90/10 split, public pot paying `min(R_target, pot)`) was internally inconsistent: a hidden fee cannot fund a publicly-checkable pot, and a miner cannot spend fee value whose opening nobody can hand them. Alternatives explored and rejected (full trail: `notes/archive/fee-privacy-alternatives.md`):

| Option | Why rejected |
|---|---|
| Public `%`-fee (even bucketed) | Fee = amount oracle; guts "privacy between pegs" and re-enables taint analysis — worst on a quiet chain |
| Hidden `%`-fee paid to miners | Open research: nobody can open/spend sums of others' hidden commitments without threshold committees or encrypted mempools |
| `%`-burn (EIP-1559 style, in-circuit) | Cryptographically clean, but funds zero security — burns the revenue the chain needs |

**Resolution: move value-scaling to the peg edges** — peg amounts are public by nature, and the edge is where vault risk (`V_cap`, `T_delay` exposure) is actually created. On-SC fee is flat/amount-independent with uniform tx shape (standing privacy rule in params.md). This retires the fee-fingerprint problem by construction, keeps the pot a public integer, and removes burn/change-detection constraints from the W1 circuit.

## 5. Workstreams & effort (dogfood scope, AI-assisted, honest)

| # | Workstream | Size | Risk |
|---|---|---|---|
| W1 | Note protocol spec + proving stack (circuits, Rust prover/verifier, vectors) | **Largest — months focused** | Crypto correctness; unaudited base |
| W2 | `aegis-node`: consensus, state, P2P, RPC | Large — weeks-to-months with reuse | Reorg/tree corners |
| W3 | Peg contracts + Ergo SPV coupling + consolidator/watch bots | Medium-large | Classic bridge failure modes (security.md) |
| W4 | `aegis-mm` sidecar + stratum/GPU path; implement `NodeMining::candidate_with_txs` seam in our Rust node — missing from **both** our Scala-parity surface (`ergo-api/src/mining.rs`) and v1 (stub). Scala has it stock (`MiningApiRoute.scala:48`); standalone REST-parity fix, worth a PR regardless of Aegis | Medium (prior art: ergo-stratum-rs) | Binding bugs (D3) |
| W5 | Wallet: keys, scan, prove, UX footguns | Medium | Witness maintenance vs growing tree |
| W6 | Attesters (U1-strong) | Later | Deferred by design |

Serialization: **W1 first as a standalone spike** (no node needed), because it is the only workstream that can invalidate the architecture. If proving is infeasible → fallback per privacy.md (Halo2) or descope. Everything else is deterministic engineering.

**Strategic alternative (decision noted, not taken):** an L1 shielded pool contract on Ergo (ergo-curve-trees direction, EIP-50 arithmetic) would delete W2/W4 entirely — but caps throughput/cost at L1 script limits, likely can't hide amounts practically, and isn't a 15s payment rail. The sidechain remains the goal; this is the documented fallback if W1+W2 prove too heavy solo.

## 6. Kill / descope criteria

- **G1.5 spike fails** (proving > ~10 s or verify > ~200 ms per spend on target hardware, or 2-cycle libs unsound) → switch engine (Halo2) or descope to L1 pool.
- **W3 SPV design exceeds budget** → dogfood peg runs operator-mode (declared, not trust-minimized) with hard caps; do not fake objectivity.
- No mainnet value until security.md gates green — unchanged.
