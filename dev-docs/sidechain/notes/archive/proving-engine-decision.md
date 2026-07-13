# Proving engine choice — Curve Trees + BP vs Halo2

**Date:** 2026-07-11  
**Status:** **LOCKED (provisional)** — Curve Trees + Bulletproofs(+)  
**Depends on:** `privacy-mechanism-decision.md` (global pool)

## Does Scala need to verify this?

**No — not for private SC spends.**

```text
Scala Ergo full node (stock)
  ✓ validates ErgoScript: DepositReceipt, PegVault, SideChainState, fees
  ✓ sees digests / tip commitment the miner posts in SideChainState
  ✗ does NOT sync the privacy SC
  ✗ does NOT verify Curve Tree / Halo2 spend proofs

Rust aegis-node
  ✓ verifies every shielded spend/mint/burn proof
  ✓ maintains commitment tree + nullifier set
```

Unlock on Ergo only checks **ErgoScript rules** + “SC tip / burn inclusion evidence” as the contracts define (hashes, depths) — same ErgoHack pattern. Stock Scala stays stock; **no Scala consensus change** for the proving stack.

(If someday someone wanted Curve Tree verify *inside* ErgoScript on L1, that would be a Scala/node story — **out of scope**. We verify natively on the SC.)

---

## 15s block budget (both engines fit)

Assume dogfood / early rail: tens of private spends per block, not thousands.

| Engine | Single-proof verify (published) | Source |
|---|---|---|
| **Curve Trees / FCMP++-class** | ~**35–40 ms**/input; batch ~**11–18 ms**/proof @ n≈10 | Monero FCMP++ benches; Curve Trees / AUTCT discussions |
| **Halo 2 / Orchard** | ~**30 ms**/tx single-thread; improves with parallel/batch | [ECC Halo explainer](https://electriccoin.co/blog/technical-explainer-halo-on-zcash/); `orchard` Rust crate |
| Vcash paper (CT+BP) | ~**40 ms** membership; ~**80 ms** full tx; batch ≪ | [ePrint 2022/756](https://eprint.iacr.org/2022/756) |

**15s = 15_000 ms.** Even **100 spends × 40 ms = 4 s** serial — fine for v1; batching + threads leave headroom for tree updates and networking.

**Neither engine is the bottleneck for a 15s SC at payment-rail scale.** Choice is about **simplicity / stack fit**, not “can we verify in time.”

---

## Why lock Curve Trees + Bulletproofs(+) for *us*

| Factor | Curve Trees + BP | Halo2 / Orchard |
|---|---|---|
| Verify cost @ 15s | OK (~30–40 ms) | OK (~30 ms) |
| Trusted setup | None | None (Halo2) |
| Curve family | secp/secq cycle — **same neighborhood as Ergo** | Pasta curves (Pallas/Vesta) — new curve stack in our node |
| Ecosystem motion | Monero **FCMP++**, Firo Spark, Vcash paper, [ergo-curve-trees](https://github.com/a-shannon/ergo-curve-trees) | Zcash / Penumbra / Namada (mature, different stack) |
| Rust path | FCMP++/dalek-style work; BP crates exist; we already live in secp256k1 | Excellent `orchard` / `halo2_proofs` crates — but pull a second crypto universe |
| Proof size | ~few KB (Vcash ~4 KB class) | Orchard proofs also KB-scale (not Groth16-tiny) |
| Fit “Ergo sidechain” story | Stronger | “We embedded Zcash” |

**Verdict:** same privacy *shape*, similar verify times → pick the stack that matches **Ergo + Monero’s current direction** and avoids a second curve system day one.

**Halo2 remains the documented fallback** if a CT+BP implementation spike fails soundness/perf/integration — not the default.

---

## What “locked provisional” means

- Specs/plans may say: **global pool, membership via Curve Trees, amounts via Bulletproofs(+)**.  
- First implementation spike builds a **minimal verify path in Rust** (even toy membership) and records real µs on our hardware.  
- Only reopen Halo2 if that spike is a dead end.

---

## Non-goals of this lock

- Not implementing Monero FCMP++ wholesale.  
- Not deploying ergo-curve-trees ErgoScript pipelines on L1.  
- Not requiring Scala upgrades.
