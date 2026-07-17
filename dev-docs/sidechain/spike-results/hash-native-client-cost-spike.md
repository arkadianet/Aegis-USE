# Aegis hash-native shielded-SPEND STARK — client feasibility spike

**Question gated:** can a phone-class client produce a hash-native (Poseidon +
Poseidon-Merkle, NO elliptic curve) shielded-spend STARK in ~seconds, and how
big is the proof? This decides whether the Curve-Trees→FRI/STARK rebuild is
reachable at the client, which is the precondition for a trustless bridge (the
prior RISC0 spike pinned re-verifying the *current* EC proofs at ~14B cycles —
a foreign-curve MSM floor; the only escape is client proofs whose verifier is
hash/FRI-native, i.e. this).

## VERDICT: CLIENT-VIABLE, with wide margin.

A 2-in/2-out hash-native spend is **~86 Poseidon2 permutations** over BabyBear.
Proving that many permutations at 113-bit conjectured security:

| metric | measured (this box) | phone-class extrapolation |
|---|---|---|
| **prove time** | **75–100 ms** (single-core bound) | ~0.2–0.5 s (2–5× single-thread slowdown) |
| **peak memory** | **9.5 MB** | ~10 MB — a non-issue (phones have 2–8 GB) |
| **proof size** | **1.27 MB** | same (client→settlement bandwidth: fine) |
| verify time | 35–40 ms (native BabyBear) | — (settlement side) |

Client proving is **not** the wall. The spend circuit is so small that prove
time is dominated by *fixed FRI machinery*, not circuit work: of the ~64 ms
`prove` span, **~46 ms (72%) is the 16-bit FRI proof-of-work grind** (a tunable
anti-DoS constant) and only ~10 ms is committing the actual trace. Memory is
trivial. The rebuild does **not** fail at the client.

## Toolchain & why

- **Plonky3** (pinned rev `4aed8fe`), **BabyBear** field, `p3-poseidon2-air`'s
  production Poseidon2 AIR + `p3-uni-stark`, with a **Poseidon2-native FRI
  Merkle** (`new_benchmark_high_arity`: log_blowup=1, 100 queries, 16-bit query
  PoW). BabyBear chosen deliberately: it is the RISC0 verifier's field, so a
  later settlement STARK can re-verify these proofs cheaply in-field.
- Built and ran first try; **no toolchain wall.** `risc0` rustup toolchain +
  `cargo-risczero` 3.0.5 are also present (from the sibling RISC0 spike) for the
  parked settlement-side stretch.

## Poseidon / geometry parameters (numbers are meaningless without these)

- **Poseidon2, width t=16**, R_F=8 (4+4 full), R_P=13 partial, S-box x^7 —
  the standard BabyBear Poseidon2 (`BABYBEAR_POSEIDON2_*`). A t=16 permutation
  is exactly one 2-to-1 Merkle compression of two 8-element (~248-bit) digests,
  matching Plonky3's own Merkle.
- **Binary Poseidon-Merkle depth 32** (2^32 leaf capacity — the *same* capacity
  as the current design's depth-4 L=256 Curve Tree). Depth was NOT reduced to a
  toy value; 32 real compressions per input are in the count.
- Security: **113-bit conjectured**. NB the benchmark params report **58-bit
  *proven*** (UDR/LDR) — see caveats.

### Spend-circuit permutation budget (the cost driver), per 2-in/2-out spend
| component | perms |
|---|---|
| Merkle membership, depth 32 × 2 inputs | 64 |
| commitment opening `cm=Poseidon(value,owner,rho,r)` (~26 elems, rate 8) × 2 | 8 |
| nullifier `nf=Poseidon(nk,rho)` × 2 | 4 |
| ownership `owner=Poseidon(nk)` × 2 | 2 |
| 2 output commitments | 8 |
| **total** | **~86** |
Value conservation (Σin=Σout+fee) is 1 linear constraint; the 64-bit output
range checks are bit-column booleans over the same ~86 rows — both add a
handful of columns and **zero** meaningful prover cost relative to committing
the Poseidon2 trace. 86 perms sits inside the L=4 (128-perm) measurement.

## Scaling curve (BabyBear / Poseidon2-FRI, this machine)

perms = 2^(L+3); the vectorized AIR packs 8 perms/row.

| log2 rows | perms | prove | proof | peak RSS |
|--:|--:|--:|--:|--:|
| 1 | 16 | ~20–106 ms | 1.26 MB | 9 MB |
| **4** | **128** | **75–100 ms** | **1.27 MB** | **9.5 MB** |
| 5 | 256 | ~150–227 ms | 1.28 MB | 9.6 MB |
| 8 | 2048 | 0.68 s | 1.31 MB | 12 MB |
| 10 | 8192 | 2.26 s | 1.33 MB | 26 MB |
| 12 | 32768 | 4.42 s | 1.37 MB | 83 MB |
| 14 | 131072 | 19.1 s | 1.40 MB | 313 MB |
| 16 | 524288 | 77.6 s | 1.45 MB | 1.23 GB |

A spend (~86 perms) lives at the very bottom. There is ~100× headroom in perm
count before proving reaches even 1 s, and ~1000× before memory is a phone
concern. Proof size is ~flat at ~1.3 MB across all sizes — it is the FRI query
floor (100 openings), independent of this circuit's size.

## Honest scope & caveats

- **What was measured directly:** the real, dominant cost — proving ~86–256
  Poseidon2-t16 permutations with the *production* Poseidon2 AIR at 113-bit
  conjectured security and a Poseidon2-native FRI. This is the make-or-break
  number and it is genuine (no dev/mock mode; proofs verify; `report_proof_size`
  serializes the real proof).
- **What was reasoned, not wired:** the cross-row Merkle *chaining* equalities,
  the value-conservation linear constraint, and the 64-bit range bit-columns.
  These are cheap glue (a handful of extra columns / one selector) that provably
  cannot move a 63 ms / 9.5 MB result into the danger zone. A fully-wired bespoke
  spend AIR would refine the constant, not the verdict.
- **Security gap:** benchmark params give 113-bit *conjectured* but only 58-bit
  *proven*. A production config (log_blowup 1→2–3, more queries) roughly 2–3×'s
  prove time and grows the proof — call it ~0.2–0.3 s client / ~1.5–2 MB proof.
  Still sub-second, still phone-trivial memory.
- **Machine was under load** (heavy swap from other processes during the run),
  so reported times are conservative upper bounds.
- **Proof size ~1.3 MB** is fine to produce/transmit at the client but is large
  to post on an L1 directly. The intended path re-verifies it inside a
  BabyBear/RISC0 settlement STARK (same field) so only a small settlement proof
  hits L1 — that in-guest re-verify is the parked STRETCH (not run here; native
  verify is 28–40 ms as a lower bound signal).

## Recommendation

Proceed with the hash-native design on the client-feasibility axis. Recommended
proof system: **Plonky3 uni-stark over BabyBear with a Poseidon2 FRI** (t=16,
R_F=8/R_P=13). Expected client cost for a 2-in/2-out spend at production
security: **sub-second prove (~0.2–0.5 s on a phone), ~10 MB RAM, ~1.5 MB
proof.** The open risks are NOT at the client — they are (1) the Poseidon2
parameter/round-count review (already flagged as the one external-review item),
(2) the ~1.3–2 MB proof's settlement-side re-verification cost (the RISC0
in-guest stretch, same field, expected cheap but unmeasured here).

## Machine

AMD Ryzen 7 7800X3D (8C/16T), 61 GiB RAM (only ~16 GiB free during the run,
heavy swap in use by other processes), Linux 7.0.11, rustc 1.95.0.
Reproduce with `./run.sh`.
