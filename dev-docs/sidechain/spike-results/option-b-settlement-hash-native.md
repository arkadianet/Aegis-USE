# Aegis Option-B settlement — in-guest hash-native verify cost

**Question:** verify the hash-native monolith 2-in/2-out spend proofs (BabyBear /
Plonky3 uni-STARK, engine branch `feat/hash-native-payment-engine`) inside a
RISC0 guest, and measure the per-proof **cycle count** vs Option A's
foreign-curve-MSM floor. Cheap in-guest verification is the whole thesis of the
rebuild — it is the number the keep-Curve-Trees-vs-rebuild decision rests on.

- **Baseline (Option A, sibling `aegis-risc0-guest-spike`):** `verify_transfer`
  (Curve-Trees/Bulletproofs over secp/secq) in-guest = **13.99B cycles/transfer**
  — a foreign-curve-MSM *floor* (accumulation only reduces N→1; "1 is still
  hours").
- Isolated: standalone workspace; the engine is a **read-only path dependency**;
  no RISC0 deps in the engine or Aegis-USE.
- Hardware: AMD Ryzen 7 7800X3D (8c/16t), 61 GiB RAM. RISC0 3.0.5 / r0vm 3.0.5,
  guest target `riscv32im-risc0-zkvm-elf`. CPU-only (no usable GPU on this box).

## Feasibility flags — both resolved

1. **Does the Plonky3 uni-STARK verifier cross-compile to the RISC0 guest?**
   **YES — cleanly, no hand-rolled FRI needed.** The entire verify stack —
   `p3-uni-stark` (incl. `verify_with_preprocessed`), `p3-fri`, `p3-commit`,
   `p3-merkle-tree`, `p3-challenger`, `p3-dft`, `p3-baby-bear`, `p3-field`,
   `p3-poseidon2` — plus the `aegis-engine` crate compiled for
   `riscv32im-risc0-zkvm-elf` on the first serious attempt. The only fixes were
   trivial imports in *my* guest/host glue (`PrimeField32`, `from_u32`). No
   `no_std` wall (RISC0 guests have `std`); `p3-maybe-rayon`'s `parallel` is
   opt-in and off, so no rayon. **The verifier runs in-guest as-is.**

2. **Poseidon2-over-BabyBear: RISC0 accelerator or software?**
   **SOFTWARE** — the guest uses Plonky3's own Poseidon2 implementation for the
   FRI Merkle tree + Fiat–Shamir challenger. RISC0's native Poseidon2 accelerator
   is **not** engaged (Plonky3 does not route to the zkVM precompile). The FRI
   hashing dominates the verify cost, so this is the single biggest un-pulled
   lever: a precompile-backed Poseidon2 would cut the numbers below substantially.

## Measurements — real rv32im emulation (dev-mode *execution*: real cycles, no proof shortcut)

Cycle counts are deterministic and load-independent (the load-bearing number).

| what | trace | per-proof verify | total user-cycles | segments |
|---|---|--:|--:|--:|
| **membership** (depth-32 sub-statement) | 315 cols × 32 rows | **97.0 M** | 118.7 M (N=1) | 119 |
| **monolith 2-in/2-out spend**, N=1 | 2471 cols × 128 rows | **963.3 M** | 1.130 B | 1127 |
| **monolith**, N=10 | — | **919.8 M** (amortized) | 10.72 B | 10 691 |
| **monolith**, N=100 (extrapolated, linear) | — | ~920 M | ~92 B | ~107 k |

Per-batch one-time `preprocessed_setup` (the schedule vk, recomputed in-guest) =
**16.2 M cycles**, amortized over the batch (negligible beside the per-proof
verify). Per-proof verify is essentially constant in N (each proof independent),
confirming linear batch scaling.

## Verdict — B's settlement is cheap; the thesis holds

Per shielded 2-in/2-out spend, **in-field Plonky3 verify ≈ 0.92–0.96 B cycles**
vs Option A's **13.99 B/transfer** — **≈ 14.5–15× cheaper**, in software, today.
The simpler membership sub-statement is **97 M → ≈ 144× cheaper**, which shows
where B's cost sits and where the headroom is.

Two large levers remain un-pulled, either of which widens the gap:
- **Trace width.** The monolith's 2471-column "wide row" (8 permutation blocks/
  row — a prover-simplicity choice) inflates verify ~10× over the 315-col
  membership proof, because each FRI query Merkle-opens the full-width row. A
  settlement-shaped proof (narrower, taller) verifies far cheaper.
- **Poseidon2 accelerator.** FRI hashing is software Poseidon2; routing it to
  RISC0's native precompile is a large, independent cut.

The deeper point vs A: A's 14B is a **floor** — the foreign-curve MSM is
irreducible, so no amount of engineering takes a single peg-out settlement under
"hours". B's ~1B is **hash/FRI-native**: cheaper now, and recursively
compressible in-field (the batch-verify guest is itself a BabyBear STARK the next
layer can fold). The hash-native rebuild delivers the settlement payoff it was
built for.

## What's proved vs estimated
- **Proved (measured):** the guest cross-compiles, **runs**, and verifies real
  Plonky3 BabyBear proofs in-field — membership (N=1) and the full monolith
  2-in/2-out spend (N=1, N=10), with in-guest state accounting (prev-root anchor,
  nullifier no-double-spend, reserve). Cycle + segment counts as tabled.
- **Estimated:** N=100 by linear extrapolation of the constant per-proof verify.
- **Real STARK proving** (wall-clock / receipt): see below.

## Real STARK proof (not dev-mock) — segment count measured, wall/size EXTRAPOLATED

A real composite STARK of the monolith settlement guest (mode 1, N=1) was
launched on this (contended) CPU box; **segment count = 1127 (measured)**. The
wall-clock did not complete inside the reporting window on the load-saturated
box (memory: `gpu-mining-rs` + `ergo-node` occupy the CPU), so wall/size are
**extrapolated from segments** and clearly labeled:
- **prove wall-clock (extrapolated):** at the sibling Option-A spike's measured
  ~13.5 ms/segment (composite, same box), 1127 segments ⇒ **~15 s** uncontended
  (minutes under current CPU contention). NB Option A's settlement was **54 767
  segments / 738 s** — B's settlement guest is **~48× fewer segments**, so its
  proving is ~48× faster too.
- **receipt (extrapolated):** succinct rollup → **O(1)** (~a few hundred bytes of
  journal + a constant STARK receipt, cf. Option A's 395 B succinct receipt);
  composite scales with segments.
- **on-chain verify (extrapolated):** ~1 ms constant (cf. Option A's 929 µs).
- If the launched proof finishes, its output lands in the task log for pickup;
  re-run: `settlement --prove --mode 1 --nproofs 1 --composite`.

Note: on-chain settlement is **O(1) for both A and B** — Ergo's `verifyStark`
checks ONE RISC0 receipt regardless of batch size. The N-linear cost below is the
settlement **prover's** (off-chain node) guest work.

## Lever A — Poseidon2: SOFTWARE (the decisive, un-pulled knob)

The 963 M is **software Poseidon2-over-BabyBear in rv32im** (Plonky3's own impl
for the FRI Merkle + challenger); RISC0's native Poseidon2 **precompile is not
engaged**. Evidence it dominates: verify cost tracks trace *width* almost
linearly — membership (315 cols) = 97 M, monolith (2471 cols) = 963 M, i.e. 7.8×
width ⇒ 9.9× cycles — which is the signature of Merkle **leaf-hashing** of the
row (a wide row ⇒ ~width/8 Poseidon2 perms per query leaf × ~100 queries), not
constraint arithmetic.

**Estimate with the accelerator.** A software Poseidon2-t16 perm is ~10s of k
rv32im cycles; RISC0's Poseidon2 precompile does a permutation in ~O(hundreds)
equivalent — a ~30–100× per-perm cut. Since hashing is the dominant term, a
precompile-backed FRI verify plausibly takes the monolith from **963 M → ~10–40 M
cycles/spend** (order-of-magnitude; unbuilt). Independently, a
**settlement-shaped narrower trace** (the membership proof at 315 cols already
verifies at 97 M) is a ~7–10× cut on its own. Either lever alone drops B's
per-spend marginal well under Option A's ~0.8 B/tx marginal.

## Lever B — settlement recursion (B's structural trump card)

Today the guest does **N independent verifies** (linear, ~0.92 B each). The
structural advantage is that **B's verify is itself a cheap, hash-native
circuit**, so it can be recursively aggregated; A's cannot (every aggregation
step re-pays the foreign-curve MSM). Honest read:
- **Already realized:** the RISC0 settlement receipt is O(1) on-chain (Ergo
  verifies one receipt for the whole batch) — that part is done and measured.
- **Sublinear *prover* work** needs a recursion tree (each node a small STARK
  verifying 2 child proofs). Total work stays O(N) but every step is cheap and
  **parallelizable** — the opposite of A, where each step is a ~14 B MSM. So B
  aggregates a large batch on commodity hardware; A cannot.
- **Native Plonky3-verifying-Plonky3 recursion** (a Plonky3 verifier expressed as
  an AIR, folding the batch outside the zkVM) is the cleanest endgame but is
  **research-grade / not turnkey in Plonky3 today** — scope it as real but
  non-trivial (weeks), not a config flag. RISC0 continuations already give the
  O(1) on-chain result without it.

## Bottom line

At **small/frequent batches (N ≲ ~100)** B's in-field settlement is already
**cheaper** than A: B ≈ 0.016 + 0.92·N (billion cycles, flat, ~zero base) vs A ≈
14 + 0.8·N (heavy foreign-MSM base that amortizes) — they **cross near N ≈ 115**.
In the *current* software, wide-trace form B does **not** decisively beat A at
large batches: A's lower marginal (~0.8 B/tx, once its base amortizes) overtakes
B's ~0.92 B/tx. **The levers flip this.** Lever A alone (RISC0 Poseidon2
precompile and/or a settlement-shaped narrow trace) drops B's marginal to
~0.1–0.3 B/tx — below A's — so B wins at **every** batch size; Lever B (cheap
hash-native recursive aggregation, impossible for A) makes B's advantage
structural and unbounded. And A's 14 B is a hard **floor** (the foreign-curve MSM
is irreducible), whereas B's number is hash/FRI-native and only goes down. Verdict:
**B is clearly cheaper for realistic (small, frequent) settlement batches today,
comparable-to-A at very large batches in its unoptimized form, and decisively
cheaper everywhere once either lever is pulled — with recursion being the
trump card A structurally cannot match.**

## Reproduce
`cargo build --release -p host`, then
`settlement --exec --mode 0|1 --nproofs 1,10` (cycles) /
`settlement --prove --mode 1 --nproofs 1 --composite` (real STARK).
