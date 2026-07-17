# Aegis trustless-bridge prover — RISC0 validity-rollup feasibility spike

**Question:** can `aegis-crypto`'s `verify_transfer` (arkworks secp/secq +
vendored Curve-Trees/Bulletproofs + merlin) compile and run inside a RISC0
guest (`riscv32im-risc0-zkvm-elf`), so a STARK can prove "our own audited
verifier accepted this batch" (Statement 1)?

Isolated spike; nothing here touches Aegis-USE main. Vendored curve-trees +
aegis-crypto were copied read-only and patched only in the copy.

## Toolchain (already installed)
- `cargo-risczero` 3.0.5, `r0vm` 3.0.5, rustup `risc0` toolchain (rustc
  1.94.1-dev), target `riscv32im-risc0-zkvm-elf` present. NOT a blocker.

## COMPILE — the make-or-break — PASSED
The full real verify path cross-compiles for `riscv32im-risc0-zkvm-elf` under
the `risc0-build` harness (`risc0_build::embed_methods`):
- arkworks `ark-{ec,ff,serialize,std,secp256k1,secq256k1}` 0.4 — OK
- vendored `bulletproofs` 2.0 (dalek-fork R1CS) — OK
- vendored `relations` (curve-trees) — OK
- `merlin` 2 (no_std transcript) — OK
- `aegis-crypto` — OK, calls the REAL `verify_transfer`

### Surgery required (all real, all small)
1. **Strip `parallel` (rayon) + `asm` (x86 ark-ff) features** from the vendored
   crates via `default-features = false`. rayon is NOT on the verify path, so
   this is free. `asm` is x86-only and would not apply to riscv anyway.
   *No code edits — feature flags only.* (Aegis-USE's own `aegis-crypto`
   Cargo.toml pulls these with defaults; a guest build must override.)
2. **getrandom** — two facets, both surmountable:
   - *Build*: two versions resolve — `0.2.17` (ark-std/rand 0.8) and `0.3.4`
     (`risc0-zkvm-platform`). A plain `cargo build --target ...` FAILS
     (`getrandom 0.3.4` has no backend). Building through `embed_methods`
     configures it. => build-path requirement, not a wall.
   - *Runtime*: `bulletproofs::batch_verify` calls `rand::thread_rng()`. RISC0
     **panics by default** on any guest `getrandom()` call. Fix = enable the
     `getrandom` feature on `risc0-zkvm` in the guest (one line). Notably this
     panic fired only at the FINAL `batch_verify` step — i.e. generator setup,
     tree build, and the entire even/odd R1CS verifier all executed first.
3. **32-bit overflow bug in `aegis-crypto`** (genuine finding): `build_tree`
   and `IncrementalCmTree::push` assert `len <= TREE_L.pow(TREE_DEPTH)` =
   `256usize.pow(4)` = 2^32. On the 64-bit host this is fine; in the 32-bit
   guest `usize` is 32-bit and this OVERFLOWS (panic/wrap) -> the guest panicked
   "leaf count exceeds tree capacity" on 3 leaves. One-line fix (compute in
   u64). *This latent bug would bite any 32-bit zkVM guest and is worth fixing
   in main regardless.*

### Not walls (contrary to the naive "no_std" worry)
- `relations` uses `std::` freely (BorrowMut, fmt, ops) — fine, **RISC0 guests
  have `std`**.
- `rand::thread_rng()` in `bulletproofs::batch_verify` compiled and executed —
  RISC0 backs getrandom with a host ecall. (SOUNDNESS NOTE below.)

## RUN — the real verifier executes in-guest — PASSED
The guest gets past `build_tree` into the arkworks/bulletproofs verify and (in
dev-mode execution) runs the real `verify_transfer`.

## COST — per-phase cycle attribution (1 real 2-in/2-out transfer)
Measured via `env::cycle_count()` in the guest (RISC0 3.0.5, dev-mode
*execution* on a 16-core CPU — real emulation, no proof shortcut):

| phase | user cycles | share |
|---|---:|---:|
| deserialize (leaves+proof) | 636,331,297 | 1.2% |
| **gen_params (2×8192 hash-to-curve generators)** | **39,234,613,138** | **72.5%** |
| tree_build (`from_set`, 3 leaves, depth 4) | 246,313,769 | 0.5% |
| **verify_transfer (even+odd R1CS verify + batch)** | **13,990,449,717** | **25.9%** |
| **total user_cycles** | **54,108,176,956** | — |
| total_cycles (padded) | 57,426,837,504 | — |
| **segments (~1M cyc each)** | **54,767** | — |
| journal (public outputs: root‖nf0‖nf1) | 97 B | — |

*Correctness:* the guest ran the REAL `verify_transfer` to completion and it
returned `Ok` in-zkVM (the dev receipt's `journal_bytes=97` and `verify_time`
are dev-mode artifacts — no real STARK was generated: 54,767 segments is
plainly intractable to prove here; the sibling `stark-poc` already pinned the
real 1-segment succinct profile at 218 KiB receipt / ~12 ms verify).

### What the numbers mean
- **~14.0 billion cycles to verify ONE transfer** (even after removing the
  amortizable generator setup). At RISC0's real CPU proving throughput
  (~1 segment per ~1–20 s; `stark-poc` proved its 1-segment sha256 guest in
  ~21 s succinct), 54,767 segments ≈ **hours-to-days of CPU proving for a
  single transfer**; even a 10–30× GPU/Bonsai speedup leaves it at **many
  minutes-to-hours per transfer**. Peak memory: RISC0 keeps a per-segment
  witness; 54k segments prove sequentially/recursively, so wall-time (not
  RAM) is the binding constraint, but a batch's recursion tree is large.
- **Root cause of the explosion:** RISC0 emulates rv32im, so every 256-bit
  arkworks field op is software bigint (dozens of 32-bit instructions), and
  Bulletproofs verify does large multi-scalar mults (thousands of 256-bit
  scalarmuls) over **two** non-native curves (secp/secq) per proof. This is
  the classic "verify a succinct proof inside a general zkVM over a foreign
  field" cost blow-up — there are no RISC0 precompiles for secp/secq arkworks
  arithmetic.

## EXTRAPOLATION to a full Statement-1 batch (N transfers + 1 burn)
- Generator setup (39.2B) is derived once per proof and SHOULD be precomputed
  out entirely (hardcode the consensus params). Removes ~72% of a 1-tx proof.
- Recurring cost is ~**14B cycles per transfer verify** (+ small tree/deser).
  A batch is roughly `≈ 14B × N` cycles:
  - N=10  → ~140B cycles → ~140k segments
  - N=100 → ~1.4T cycles → ~1.4M segments
- On a single CPU this is intractable (days+). Only a large proving cluster
  (Bonsai-scale, continuations + parallel segment proving) makes even a small
  batch finish in the tens-of-minutes-to-hours range — i.e. impractical for a
  per-epoch settlement cadence at these constants.

## SOUNDNESS NOTE (batch_verify randomness)
`batch_verify` draws random combiners via `rand::thread_rng()`. In-guest this
reads host-supplied getrandom (nondeterministic to the guest). For batch
verification this is benign — the proof being verified is a fixed input decided
before the randomness is drawn, so a cheating input still fails w.h.p. But it
does mean the guest execution consumes unconstrained host input; a production
guest should either verify a single proof (no batch randomization needed) or
derive the combiners from the transcript (Fiat-Shamir) rather than the OS RNG,
so the STARK is fully deterministic. Minor, fixable.

## VERDICT

**Portability: TRACTABLE (surprisingly clean).** The make-or-break unknown —
"does the real audited `verify_transfer` (arkworks + curve-trees/bulletproofs
+ merlin) compile and run inside a RISC0 guest?" — is answered **YES**. It
cross-compiles and executes correctly in-zkVM, producing the right public
outputs. The only surgery: two feature flags (`default-features=false` to drop
rayon/asm; `getrandom` on `risc0-zkvm`) and one genuine one-line 32-bit
overflow fix in `aegis-crypto`. No no_std rewrite, no dead-end. RISC0's `std`
support is what makes this easy — a strictly-no_std zkVM (SP1 core, some
others) would be materially harder for `relations`.

**Economics: NOT PRACTICAL as literally specified.** Re-running the full
Bulletproofs verifier in-guest costs **~14 billion cycles per transfer**
(~54B with in-guest setup) = ~54k RISC0 segments for a SINGLE transfer. A
real batch proof is hours-to-days of CPU (minutes-to-hours on a GPU cluster).
The naive validity-rollup that re-verifies each per-transfer STARK-inside-a-
STARK is a **research/heavy-infra problem, not a build**.

**The real finding — it's the wrong statement to prove.** Statement 1 does
NOT require re-verifying the per-transfer Bulletproofs inside the settlement
STARK. Those proofs are already checked natively by the settling node in
milliseconds. The STARK only needs the **aggregate state transition**:
`prev_root → new_root`, value conservation, the burn amount, and nullifier
non-membership (no double-spend). That is Poseidon/Merkle accounting over the
committed state — thousands of times smaller than re-running curve-trees
verify, and it maps onto a zkVM's native field far better.

### Recommended next step
1. **Reframe the guest** to prove the aggregate accounting only (root
   transition + Σvalue + burn + nullifier-set updates over Poseidon), with the
   per-transfer Bulletproofs verified natively off-circuit. Re-measure — this
   is the statement worth benchmarking, and it is plausibly a BUILD.
2. If per-transfer *membership/validity* must also be in-circuit, do NOT do it
   by emulating secp/secq arkworks in rv32im. Options: a custom AIR over the
   settlement relation, a zkVM with secp precompiles / accelerated MSM, or a
   Poseidon-committed re-encoding of the tree so the in-circuit work is over
   the zkVM-native field.
3. Precompute the consensus generators regardless (removes ~72% of any
   in-guest curve-trees cost).
4. Fix the 32-bit `TREE_L.pow(TREE_DEPTH)` overflow in Aegis-USE main (u64
   math) — it is a latent correctness bug on any 32-bit target, independent of
   this spike.

**One-line answer:** the validity-rollup *compiles and runs* — the bridge
prover is not blocked by a porting wall — but re-verifying Bulletproofs
in-zkVM is ~10^4× too costly to be the settlement design. Build the aggregate-
state-transition statement instead; that's where "trustless bridge" becomes a
build rather than a research project.
