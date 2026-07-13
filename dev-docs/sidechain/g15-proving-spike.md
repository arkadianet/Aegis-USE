# G1.5 proving spike — results (PASS)

**Date:** 2026-07-12  
**Verdict:** **GO** — CT+BP proving stack is comfortably feasible on target hardware; kill criteria (prove ≤ ~10 s, verify ≤ ~200 ms) passed with 3.5×–100× margin.

## What was measured

The paper authors' own `Pour` benchmark (`~/coding/reference/crypto/curve-trees`, `relations/benches/coin.rs`): a full Vcash-style **2-in/2-out spend** — Curve-Tree membership via select-and-rerandomize + Schnorr ownership (rerandomized pk) + value balance — over the **secp256k1/secq256k1 cycle** (ours; pasta also run). Criterion, 50 samples, multi-threaded, `-C target-cpu=native`.

**Hardware:** AMD Ryzen 7 7800X3D (8C/16T, ≤5.05 GHz), 61 GiB RAM, rustc 1.95.0.

## Results (secp256k1/secq256k1)

| Set size | Tree (L, D) | Proof size | Prove | Verify ×1 | Verify ×100 batch |
|---|---|---|---|---|---|
| 2^20 | 1024, 2 | 3,442 B | 1.39 s | 22.4 ms | 133 ms (**1.3 ms/proof**) |
| 2^32 | 256, 4 | 3,970 B | 2.86 s | 42.2 ms | 237 ms (2.4 ms/proof) |
| 2^40 | 1024, 4 | 3,970 B | 2.94 s | 43.3 ms | 301 ms (3.0 ms/proof) |

## Implications for Aegis

- **Block budget is a non-issue:** a 15 s block verifying 100 spends spends ~0.13–0.3 s of one core-set — >97% headroom. Verification will not set the block weight limit; bandwidth/storage will (~4 KB/proof + ciphertexts ⇒ ~4–5 KB/tx).
- **Wallet UX:** ~1.4–2.9 s proving on a desktop is fine; assume 3–10× on weak laptops/phones — still inside tolerable send latency. Single-threaded and low-RAM numbers not yet measured (see caveats).
- **Tree sizing:** with R1-T yearly epochs the per-epoch tree stays small — the 2^32 (L=256, D=4) config is a safe default; 2^20 (D=2) halves proving time if epochs stay under ~1M notes.
- **Batch verification matters:** design block validation around batched verify from day one (per-block batch, not per-tx).

## Caveats (tracked into G1.6 / W1)

1. Pour ≈ but ≠ the final Aegis circuit: fee constraint, nullifier/tag derivation exactly as we spec it, note-encryption checks, and padding to uniform shape will add constraints — expect some slowdown; margin absorbs it.
2. Research-quality, unaudited code (dalek-fork BP + arkworks curves); external review gate before TVL stands (security.md).
3. Multi-threaded prover; measure single-thread + memory footprint during G2 for low-end device targets.
4. R1-T verifiable-encryption gadget (if adopted) not yet in the circuit — bench when designed.

## Gate status

G1.5 **CLOSED — PASS** (2026-07-12). Next per plan: scaffold `aegis-spec` (15 s dev chain params) + G1.6 note-protocol spec, using these numbers as constraints.
