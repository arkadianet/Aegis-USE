# aegis-recursion — recursion aggregation pipeline (I3)

Aggregates **N real monolith spend proofs → ONE fixed-size root proof** that
verifies natively. This is the batch-independence layer: it collapses the N
withdrawals of an epoch into a single constant-size proof, so the settlement
RISC0 wrap (I4) verifies exactly one root regardless of N. See
`dev-docs/sidechain/recursion-feasibility.md`.

## Stages
1. **`layer1`** — recursively verify one client spend proof (aegis-engine's
   Poseidon2 salted-hiding single-instance batch-stark proof) in-circuit →
   a plain (non-hiding) batch-stark layer-1 proof.
2. **`aggregate_tree`** — a 2-to-1 binary tree over the layer-1 proofs; each
   node verifies its two children in-circuit, up to one root. N is padded to the
   next power of two by re-recursing duplicate leaves (foundation padding; I4
   replaces it with journal-bound identity leaves).

`aggregate_spends` runs both end-to-end; `verify_root` checks the root natively.

## Build flags — MANDATORY

The recursion prover is **~27× slower** without both of these (I1 measurement:
layer-1 is ~2 s with them, 9.5 s / 55 s without):

```bash
RUSTFLAGS="-Ctarget-cpu=native" cargo test --features parallel -- --nocapture
```

- `--features parallel` (**on by default**) enables `p3-circuit-prover/parallel`
  (rayon). The aggregation-service capacity math must assume the flags actually
  deployed.
- `RUSTFLAGS="-Ctarget-cpu=native"` gives the packed-Poseidon2 AVX-512 path the
  prover leans on.

`[profile.dev]`/`[profile.test]` are pinned to `opt-level = 3` (the FRI/recursion
stack is unusably slow at `opt-level 0`), so a plain `cargo test` is already
optimized — the `RUSTFLAGS` are what matter most.

Build in an **isolated `CARGO_TARGET_DIR`** (the recursion prover's shared
incremental cache clobbers unrelated builds; a killed build corrupts it).

## Dependency posture

The `p3-recursion` / `p3-circuit*` crates are the official but **UNAUDITED**
[Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion) library, pinned
to rev `b363397`. Do-not-use-in-production per its README — inside the same
external crypto-review gate as the rest of the value path. Vendoring the pinned
copy is an I1-tail / I5 policy item. This crate is a **separate nested
workspace**, excluded from the engine workspace so the engine gate never builds
the unaudited library.

## Not in scope here (I4/I5)

Settlement statement over the root + SHA-256 final layer + RISC0 wrap (I4);
epoch-validity carrier + vk-pinning the aggregation circuit fingerprint + testnet
re-cut (I5). This crate stops at "one verifying root from N real proofs".
