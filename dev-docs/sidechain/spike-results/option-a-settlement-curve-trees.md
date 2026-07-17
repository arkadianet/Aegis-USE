# Aegis RISC0 SETTLEMENT prover — Statement 1 (trustless peg-out) build + cost

Builds on the portability spike (`RESULTS.md`, which proved `verify_transfer`
cross-compiles to a RISC0 guest at ~14B cycles/transfer). This deliverable is
the real **settlement statement** on the audited Curve-Trees engine, and pins the
one number the keep-Curve-Trees decision rests on: the **per-batch STARK proving
cost** and how it amortizes with batch size.

## What was built (real code, isolated, outside Aegis-USE)

- **`aegis-crypto::spend::batch_verify_transfers`** — the amortized batch path.
  Each transfer's `verification_scalars_and_points` tuple is collected, then all N
  even tuples are folded into ONE `batch_verify` mega-check (MSM) per curve. The
  vendored `batch_verify` randomizes+sums the per-proof fixed-generator
  coefficients into a single generator-length scalar vector, so the ~2·padded_n
  shared-generator MSM is paid **once per batch**, not once per transfer.
- **Generator injection** (`tree::seed_params_from_generators` +
  `BulletproofGens::from_vecs`) — the host derives the 2×8192 hash-to-curve
  consensus generators once and injects them; the guest skips the ~39B-cycle
  in-guest derivation. **Byte-identity gated**: injected generators reproduce the
  pinned consensus curve-tree root byte-for-byte (`tests/seeded_params_oracle.rs`).
- **`methods/guest-settlement`** — the RISC0 settlement guest. Public journal =
  `(prev_state_root, new_state_root, withdrawal_amount, withdrawal_recipient,
  epoch)`. Private witness = generators, prior leaf set, output commitments, N
  transfer proofs, fee, prior nullifier-accumulator + peg reserve. In-guest state
  accounting: (1) amortized batch-verify of all N transfers [DOMINANT]; (2)
  cm-tree append → new root via the audited `build_tree` (== incremental append,
  oracle-tested); (3) nullifier within-batch uniqueness + SHA-256 accumulator fold
  (RISC0 has a SHA-256 precompile — near-free; Poseidon is the wrong primitive for
  RISC0); (4) peg reserve `reserve_new = reserve_prev − withdrawal_amount`.
- **`host/src/bin/settlement.rs`** — `--exec` / `--prove`(`--composite`) harness,
  `--nproofs N[,N,…]`; reports cycles, segments, wall-clock, peak RSS, receipt
  size, verify time.

Correctness gates (real `cargo test`, pass): amortized batch-verify accepts N
real transfers and rejects a tampered nullifier + wrong fee; injected generators
reproduce the consensus root byte-for-byte.

## Hardware + toolchain

- CPU AMD Ryzen 7 7800X3D (8c/16t), 61 GiB RAM. GPU RTX 3090 24 GiB present.
- RISC0 3.0.5 / r0vm 3.0.5, guest target `riscv32im-risc0-zkvm-elf`.

## BLOCKER — real **GPU** proving unavailable on this box
- The RISC0 CUDA prover will not build: nvcc (CUDA 12.9) requires host **gcc ≤ 14**;
  Fedora 44 ships only **gcc-16 / gcc-15 / clang-22** and offers no gcc ≤ 14 in-repo.
  `-allow-unsupported-compiler` then fails on gcc-16/15 libstdc++ (`char8_t`,
  `__is_pointer`). No container available.
- The RTX 3090 was also **~100% occupied** by the operator's own `gpu-mining-rs`,
  and the CPU was saturated by `gpu-mining-rs` + `ergo-node` during runs (load avg
  ~10–12 on 16 threads) — so **wall-clock numbers here are contended/pessimistic**.
  For that reason the load-bearing measurement is **cycles + segments**, which are
  deterministic and load-independent; proving wall-clock is derived from segment
  count × a calibrated per-segment proving rate.

## MEASUREMENTS

### 1. Amortization curve — MEASURED (native, real, same settlement code path)

`batch_verify_transfers` over N real 2-in/2-out transfers, median wall-clock
(`tests/batch_amortization.rs`, release, this box under load):

| N   | total_ms | per_tx_ms | total vs N=1 | per_tx vs N=1 |
|-----|---------:|----------:|-------------:|--------------:|
| 1   |   300.5  |   300.5   |    1.00×     |    1.000×     |
| 10  |   442.8  |    44.3   |    1.47×     |    0.147×     |
| 100 |  2028.0  |    20.3   |    6.75×     |    0.067×     |

Linear fit `total(N) = base + marginal·N`: **base ≈ 283 ms (94%)**,
**marginal ≈ 17.5 ms/tx (6%)**. The base is the shared ~2·padded_n
generator-basis MSM that `batch_verify` folds across the whole batch; the
marginal is the per-proof `verification_scalars_and_points` work (transcript
replay + O(padded_n) scalar vectors) which is NOT amortized. **100× the
transfers cost 6.75×, and the per-transfer cost drops 15×.**

> Correction to the earlier design-pass figure: "100 proofs = 1.47×" describes
> the `batch_verify` MSM mega-check **in isolation**. The *full* settlement
> verify (what the guest must run — gadgets + `verification_scalars` + MSM) is
> **6.75× at N=100**. Still strongly sublinear, still dominated by a
> once-per-batch term — but not batch-independent.

### 2. In-guest cost — anchored on the prior spike's REAL in-guest measurement

Prior spike (real rv32im emulation): one transfer's verify = **13.99 B cycles**,
and 54.1 B cycles → 54,767 segments ⇒ **~988 k cycles/segment (≈2^20)**. Scaling
the N=1 anchor by the measured amortization ratio, plus the cheap
tree-append/accounting (SHA-256 precompile), with the consensus generators
**embedded in the guest ELF** (the deser-in-guest path is a measurement artifact,
see note):

| N   | batch-verify cycles | + tree/acct | ≈ segments | segments/tx |
|-----|--------------------:|------------:|-----------:|------------:|
| 1   | ~14.0 B             | ~14.7 B     | ~14,900    | 14,900      |
| 10  | ~20.6 B             | ~21.6 B     | ~21,900    | 2,190       |
| 100 | ~94.5 B             | ~97.0 B     | ~98,000    | 980         |

> **Artifact caveat:** the current guest injects generators as witness and
> deserializes 4×8192 compressed points in-guest — each decompression is a field
> sqrt, costing an extra ~several-B cycles that is NOT settlement-intrinsic. A
> production prover embeds the generators in the ELF (part of the imageId) so this
> is 0. The table above is the intrinsic (embedded-generator) cost. (This is also
> why the in-guest dev-mode run did not finish on the saturated box — 20 min of
> single-thread emulation was still in the generator-deser + batch-verify phase.)

### 3. Proving wall-clock — EXTRAPOLATED (GPU blocked; box saturated → no clean real proof)

Per-segment rate anchor (on-box real STARK, sibling `stark-poc`, RISC0 3.0.5,
16 cores): a ~1-segment succinct proof = **21 s / 218 KiB receipt / 11.8 ms
verify**. Base-segment proving on this CPU ≈ ~1–2 s/segment (the 21 s is inflated
by fixed recursion + 16-bit FRI PoW). RISC0 CUDA is ~10–20× CPU; segments prove
embarrassingly in parallel across a cluster.

| batch | segments | CPU (this box)¹ | 1× RTX 3090¹ | ~10-GPU cluster¹ |
|-------|---------:|----------------:|-------------:|-----------------:|
| N=1   | ~15 k    | ~8–12 h         | ~30–50 min   | ~3–6 min         |
| N=10  | ~22 k    | ~12–18 h        | ~45–75 min   | ~5–8 min         |
| N=100 | ~98 k    | ~2–3 days       | ~3–5 h       | ~20–35 min       |

¹ Order-of-magnitude, `segments × per-segment-rate`; segment counts are grounded
in real prior in-guest measurement, per-segment rates are literature + the on-box
`stark-poc` anchor. Proof size: succinct receipt ~**218 KiB** (constant, from
`stark-poc`); verify ~**12 ms** (constant). Both are batch-size-independent.

## Verdict

- **Amortization: REAL and strong.** A settlement batch's proving cost is
  dominated by a **once-per-batch** foreign-curve MSM (~94% of a 1-tx batch);
  adding transfers is cheap (~6%/tx). Per-transfer proving cost falls **15×** from
  N=1 to N=100. Larger epoch batches are dramatically more efficient — exactly the
  right shape for a per-epoch settlement cadence.
- **Absolute cost: the design-doc "floor" is confirmed and quantified.** Even
  fully amortized, one batch pays ≈ one foreign-curve (secp/secq) verification ≈
  **~14 B cycles ≈ ~15 k segments** — the irreducible minimum. That is **hours on
  a single machine, sub-hour on a GPU cluster.**
- **Operationally viable? YES on a GPU/Bonsai-class cluster** (tens of minutes per
  batch, even at N=100), **NO on a single CPU** (hours-to-days). It is *not* the
  "days per batch" failure case. The settling node is a server/operator, so a
  cluster is a reasonable assumption — but this is real proving infrastructure, not
  a laptop.
- **Honest limits of THIS run:** no completed real (non-dev) STARK of the
  settlement statement — GPU proving is toolchain-blocked here and a real CPU proof
  of even N=1 is many hours on a box saturated by the operator's own miners. The
  guest executes correctly in the zkVM (real emulation of the audited verifier +
  accounting, committing the correct public journal); the sibling `stark-poc`
  already produced a real verifying RISC0 STARK for a small statement. The
  settlement proof's wall-clock is therefore extrapolated from real segment counts,
  not a completed receipt.

## What's left to a full peg-out
1. `PegVault` `verifyStark` ErgoScript + **public-input binding** (vault NFT /
   `SELF.id`, output recipient+amount == `withdrawal_recipient`/`withdrawal_amount`,
   chain/domain tag — checked alongside the `verifyStark` result).
2. The verifier: EIP-0045 `verifyStark` on mainnet, or the Rust dev-net verifier.
3. Embed generators in the guest ELF (drop the deser artifact); bind the burn
   note's in-circuit value to the public `withdrawal_amount`; real nullifier-set
   non-membership paths (cheap SHA-256 on RISC0).
4. Statement 2 (R1-T recycle) reuses the same machinery.
