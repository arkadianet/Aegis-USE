# Recursive aggregation of client spend proofs — feasibility verdict

> **Status: RESEARCH VERDICT (2026-07-19).** Answers the pivotal question: can
> settlement proving be made batch-independent (constant in N withdrawals) and
> cheap enough to also carry epoch-validity? Measured prototype + source audit.
> No production code changed.

## Verdict: **FEASIBLE-SOON** — with one honest reframing and one config change

**Native Plonky3 recursive aggregation of our spend proofs is real, measured,
and cheap.** The official `Plonky3/Plonky3-recursion` library (out-of-tree,
same team) provides exactly the missing piece: a recursive verifier for
`p3-uni-stark` proofs — including **hiding (ZK) proofs**, **preprocessed
columns**, **BabyBear with the D=4 extension we already use**, and
**2-to-1 binary-tree aggregation of N independent proofs into one root proof**.
I built and ran its examples on this machine (Ryzen 7 7800X3D, CPU only):

- recursively verifying a **1.0 MB wide-AIR uni-STARK** (Keccak AIR, 2633 cols
  — a near-perfect proxy for our 2756-col monolith): **1.74 s** (1.82 s with
  ZK mode on) per proof, first layer;
- each **2-to-1 aggregation node: 0.26–0.74 s**, embarrassingly parallel;
- root proof converges to a fixed **~450–475 KB** batch-STARK regardless of N.

Today the same verification costs **~0.30 B RISC0 cycles ≈ ~7 min GPU per
proof** (`batch-settlement-design.md:173,320,350`). Measured gap:
**~200–400× wall-clock per proof, on cheaper hardware.**

**The honest reframing:** no scheme makes *total* work sublinear in N — every
client proof must be verified at least once by someone. What recursion delivers
is (a) the per-proof cost collapses from ~7 min GPU to ~2–4 s CPU,
parallelizable and pipelineable off the critical path, and (b) the expensive
RISC0 GPU wrap becomes **exactly one** in-guest verification of the fixed-size
root proof — **constant in N**. That is the batch-independence that matters:
settlement critical-path cost stops scaling with withdrawals.

**The config change:** the recursive verifier hashes in-circuit with
**Poseidon2 only** — there is no SHA-256 gadget anywhere in the library
(verified by grep over `recursion/src`, `circuit/src`). Our client hiding
config is SHA-256 MMCS + SHA-256 byte challenger (`engine/src/config.rs:66-77`),
chosen for the RISC0 SHA accelerator (`config.rs:11`). Under recursion the
zkVM never verifies client proofs, so that motivation disappears: the client
config must switch to Poseidon2 MMCS + duplex challenger. Chain-id-breaking on
the hn chain → folds into the already-free testnet re-cut.

---

## 1. What exists where (Q1) — cited

### Plonky3 at our rev 4aed8fe: NO in-tree recursion

Checkout: `~/.cargo/git/checkouts/plonky3-7d8a3b21a665a86f/4aed8fe`
(= workspace version **0.6.0**; rev includes PR #1951).

- No recursion crate. The only aggregation-adjacent crate is `p3-batch-stark`
  ("Batched STARK wrapper atop p3-uni-stark that reuses FRI openings across
  instances", `batch-stark/Cargo.toml`) — that is a **joint prover**: it needs
  all witnesses in one place, so it cannot aggregate independently-produced
  client proofs. Not applicable.
- What IS in-tree: recursion-*friendly* affordances the recursion library
  consumes — uniform extension-field challenger notes
  (`challenger/src/lib.rs:128-139`), "Small visibility changes for recursion
  (#1046)" (`uni-stark/CHANGELOG.md:112`), "Small changes for recursive
  lookups (#1229)" (`batch-stark/CHANGELOG.md:113`).

### Plonky3-recursion (github.com/Plonky3/Plonky3-recursion): the missing piece

Audited at commit `b363397` (clone in scratchpad). Explicitly **unaudited /
"do not recommend production use"** (README) — same maturity gate as the rest
of our value-path crypto (external review already mandatory before real use).

- **Recursive uni-stark verifier as a circuit**: `recursion/src/verifier/stark.rs`
  (full FRI verification in-circuit: `recursion/src/pcs/fri/verifier.rs`,
  MMCS paths: `recursion/src/pcs/mmcs.rs`).
- **Preprocessed columns supported**: `verifier/stark.rs:78`
  (`preprocessed_commit: &Option<Comm>`) — our `SpendAir` uses a preprocessed
  schedule (`engine/src/spend/monolith.rs:459-461`), so
  `verify_with_preprocessed` semantics carry over.
- **Hiding proofs supported**: `pcs/mmcs.rs:313-318` — "Optional per-matrix
  salt coefficients for a hiding MMCS … matching the native
  `MerkleTreeHidingMmcs`, which commits `[row | salt]`"; `HidingFriPcs` (ZK
  mode) named in `recursion/src/recursion.rs:293,338`. This is literally our
  PCS type (`engine/src/config.rs:180-186`, `SALT_ELEMS = 4`).
- **Fields**: BabyBear "Fully supported", challenge extension **fixed at D=4**
  (`book/src/user_guide/configuration.md`) — identical to our
  `EF = BinomialExtensionField<BabyBear, 4>` (`engine/src/config.rs:56`).
- **2-to-1 aggregation**: `build_and_prove_aggregation_layer`, binary tree,
  per-level embarrassingly parallel, children may be different AIRs entirely
  (`book/src/user_guide/aggregation.md`). Inner publics propagate to the outer
  circuit (`recursion/src/public_inputs.rs`).
- **Version target**: crates.io **p3 0.6.1** (`Cargo.lock`). Our engine pins
  git 4aed8fe (0.6.0 line + later commits). Same 0.6.x family — an alignment
  bump, not a rewrite (integration item I1 below).
- **In-circuit hash: Poseidon2 only** (`Poseidon2Config::BabyBearD4Width16`
  etc.); no SHA-256 gadget exists.

## 2. Measured cost of native recursion (Q2) — prototype data

Prototype: built the library's examples in an isolated
`CARGO_TARGET_DIR` (scratchpad), ran on the 7800X3D (16 threads, CPU only).
Logs: scratchpad `keccak_bb.log`, `keccak_bb_zk.log`, `agg_bb_4.log`,
`agg_bb_8.log`. Example params: BabyBear, log_blowup 3, query_pow 16,
124-bit conjectured target (→ 36 queries), Poseidon2 in-circuit hash.

| Step | Measured | Notes |
|---|---|---|
| Base Keccak uni-STARK (2633 cols, 24576 rows) prove | 1.52 s | proxy for our monolith (2756 cols) |
| Base proof size | 1,001,470 B | vs our 1.1–1.6 MB spend proof |
| Native (out-of-circuit) verify | 20.5 ms | |
| **Layer-1 recursion prove (verifies the 1.0 MB proof in-circuit)** | **1.74 s** | 1.82 s with `--zk` (hiding) — works |
| Layer-1 circuit build (one-time, cacheable) | 369 ms | |
| Layer-2 / layer-3 recursion prove | 377 / 418 ms | ~475 KB fixed point |
| **2-to-1 aggregation node prove** (two ~466 KB proofs in one circuit) | **257–740 ms** | 7 nodes for 8 leaves; parallel per level |
| Root proof size (any N) | ~450–475 KB | constant |

Scaling to our config: our hiding FRI is lb3 / **Q=67** / pow16
(`engine/src/config.rs:151-155`) vs the example's Q=36; in-circuit work is
roughly linear in queries → estimate **~2.5–4 s per spend-proof layer-1**
(reasoned, not measured). Trace shape (128 rows × 2756 cols,
`monolith.rs:133`) is *smaller* in rows than the proxy.

Per-proof comparison (the order-of-magnitude answer):

- Today, in-zkVM: ~0.30 B cycles ≈ **~7 min GPU** at the measured 32–45
  Mcyc/min (`batch-settlement-design.md:311-320,350`).
- Native recursion: **~2–4 s CPU**, no GPU, no zkVM emulation.
- Gap: **~2 orders of magnitude wall-clock**, ~3+ orders in energy/hardware
  cost. The recursion cost is per-proof (leaves) + per-node (tree), i.e.
  total O(N) with a tiny constant, and each level is parallel.

Cost curve (reasoned from measured points, sequential single-CPU worst case):

| N withdrawals | native aggregation (leaves + tree) | today's in-guest verify |
|---|---|---|
| 1 | ~3 s | ~7 min GPU |
| 4 | ~14 s | ~28 min GPU |
| 16 | ~55 s | ~112 min GPU |
| 64 | ~3.7 min (CPU; ~parallelizable to <1 min) | ~7.5 h GPU |

## 3. The RISC0 wrap is constant in N (Q3)

After aggregation, the settlement guest verifies **one ~450–475 KB
batch-STARK root proof** instead of N × 1.1–1.6 MB uni-STARK proofs. The
wrap's guest work:

- one in-field `p3_batch_stark` verification of the fixed-size root
  (structure fixed by the aggregation circuit, independent of N);
- the burn-binding checks — each client proof's 44 publics
  (`monolith.rs:124`) propagate through the tree via the library's
  public-input mechanism, so the guest re-derives `burn_cm_expected` per
  withdrawal exactly as today (`guest-settlement/src/main.rs:89-100`) —
  O(N) but micro-scale (a few Poseidon2 calls each);
- the frontier transition, unchanged: ~1.1 M cycles/block, per-epoch not
  per-withdrawal (`batch-settlement-design.md:175`).

So settlement cycles ≈ `root_verify + epoch_transition + N·ε` — the N-scaling
term collapses from 0.30 B to ~10^4-cycle scale. **Batch-independence holds.**

The one open cost item: the root proof's MMCS/challenger are Poseidon2, and
RISC0's SHA accelerator no longer applies. Reasoned estimate of software
Poseidon2-BabyBear in-guest for a ~475 KB proof at Q≈36: order 0.2–0.6 B
cycles — i.e. the wrap costs about **one** of today's spend_verifies, once,
regardless of N (**reasoned, not measured — measure first in M1**). Two
mitigations if it comes in high:
- prove the *final* layer under a SHA-256-MMCS `StarkConfig` (the circuit
  tables are ordinary AIRs; `p3-batch-stark::prove` is config-generic — the
  in-circuit hashing stays Poseidon2, but the final proof's own commitments
  ride the guest SHA accelerator, `sys_sha_buffer`). Custom final-prove step
  outside the convenience API.
- RISC0's own accelerated `sys_poseidon2` ecall exists in our platform
  (risc0-zkvm-platform 2.2.2, `src/syscall.rs:474`), but implements RISC0's
  Poseidon2-BabyBear parameterization — matching p3's permutation constants
  is an open compatibility question (do not assume; verify constants before
  counting on it).

## 4. The killer risks, adversarially (Q4)

**(a) "Does recursion exist at our rev?"** Not in-tree — it lives in the
separate official `Plonky3-recursion` repo, which targets crates.io p3
**0.6.1** while we pin git 4aed8fe (0.6.0+). Risk: proof/transcript format
drift between the two 0.6.x points. Mitigation: align both sides on one rev
(engine bump or recursion patch-pin); the engine's oracle-parity and baked-vk
tests will catch transcript drift loudly. Residual risk: LOW, but it is a
*coordination* dependency on an evolving, **unaudited** library — pin a
commit, vendor it, and put it inside the existing external-review gate.

**(b) "Is the recursion circuit so big it beats the savings for realistic N?"**
No — measured. Layer-1 over a 1.0 MB wide-AIR proof is 1.74 s; an aggregation
node is <0.75 s; break-even vs ~7 min GPU per proof is immediate at N=1.
The fixed point (~475 KB, ~0.4 s/layer) proves the overhead does not compound.

**(c) "Does hiding survive recursion?"** Two independent reasons it does:
(i) the library supports verifying hiding proofs in-circuit (salts appended to
leaf preimages, `pcs/mmcs.rs:313-318`) and ZK mode ran clean in the prototype
(`keccak_bb_zk.log`); (ii) even without ZK-mode outer layers, the outer
witness is only the inner *proof bytes and publics* — our spend proofs are
zero-knowledge, so their bytes are simulatable and reveal nothing beyond the
publics the settlement operator already receives today. No privacy regression
in either direction. (Caveat flagged: `recursion.rs:293` requires the same
config *including PCS seed* on both sides for hiding proofs — a wiring detail
to test in M1.)

**(d) "Does the aggregate stay RISC0-verifiable?"** Yes — the root is an
ordinary `p3-batch-stark` proof over BabyBear; the guest links the same p3
crates it links today (it already runs `p3_uni_stark::verify_with_preprocessed`
in-guest, `guest-settlement/src/main.rs:84`). The verify call changes, the
pattern does not. The vk-pinning story carries over: bake the aggregation
circuit's verifying data into the ELF exactly like `baked_spend_vk`
(`main.rs:69-77`) so the image id pins the whole recursion tower.

**(e) "Field/config mismatches?"** Field and extension match exactly
(BabyBear, D=4 — the stack's fixed parameter). The mismatch is the **hash
config**: SHA-256 MMCS/challenger cannot be recursed (no in-circuit SHA
gadget; building one would be months and ~10-100× more in-circuit rows —
this is precisely why every recursion stack uses Poseidon2). Client config
must switch to Poseidon2 hiding MMCS + duplex challenger. Consequences:
  - phone/client prove time changes (SHA-256-with-HW-ext → software
    Poseidon2): current client prove is ~251–754 ms desktop
    (`hash-native-spend-circuit.md:78,208`); Poseidon2-BabyBear commit
    hashing is well within the "seconds" kill-criterion — **measure, expect
    <2× regression** (reasoned, not measured);
  - hn-chain spend verification (aegis-node verifies client proofs natively)
    switches config too — native Poseidon2 verify stays ms-scale;
  - chain-id-breaking → testnet re-cut (already free per project policy);
  - proof bytes stay ~MB-scale (digests shrink 32B→8 field elems; salts grow
    rows slightly) — re-measure `MAX_PROOF_BYTES` headroom.

**(f) "Sequencing/latency trap":** aggregation is pipelined — leaf recursion
(~2–4 s) can run the moment each withdrawal's spend proof arrives, mid-epoch;
only the top ~log2(N) tree levels (~seconds) plus the single wrap sit on the
settlement critical path. No new latency cliff.

## 5. Effort + the concrete path (Q5)

**FEASIBLE-SOON: ~4–8 focused weeks to a testnet-working batch-independent
settlement**, all integration, no new cryptography to invent:

- **I1 (days):** rev alignment — move engine to the p3 release
  Plonky3-recursion pins (or patch-pin recursion to our rev); vendor + pin
  Plonky3-recursion; re-run engine oracle/parity suites.
- **I2 (days):** client config switch SHA-256 → Poseidon2
  (`Poseidon2Config::BabyBearD4Width16` MMCS + duplex challenger, hiding
  variant); re-bake vk; **measure client prove** on desktop + phone-class
  hardware; re-cut testnet.
- **M1 (week 1, the go/no-go measurement):** feed one REAL spend proof
  through `RecursionInput::UniStark` (with `preprocessed_commit`) → layer-1
  proof; measure layer-1 time at Q=67 and **in-guest verify cycles of a root
  proof** (the one materially unmeasured number). Kill-criterion: wrap
  ≤ ~1 B cycles.
- **I3 (1–2 wks):** aggregation service — binary tree over the epoch's spend
  proofs (rayon; embarrassingly parallel per level), publics propagation of
  N×44 values to the root.
- **I4 (1–2 wks):** new settlement guest (root batch-stark verify + N burn
  bindings + frontier transition + N-withdrawal journal) — merges with the
  already-designed batch journal work (`batch-settlement-design.md` §6, whose
  batching rule is needed for *correctness* anyway, §0.1); PegVault batch
  predicate; new image id.
- **I5 (1 wk):** params/soundness review (intermediate-layer relaxation per
  the book's guidance; final layer full-strength), red review, and folding
  the unaudited-library exposure into the existing external crypto-review
  gate.

**Epoch-validity affordability (the trustlessness carry):** with the N-term
gone, the settlement budget is `wrap (~constant) + epoch transition
(1.1 M cyc/block)`. Full epoch-validity then has two viable carriers, both
compatible with this architecture: (i) native AIRs for hn tx/pot validity
aggregated into the same tree (more build, cheapest at scale), or (ii) RISC0
receipt composition — `env::verify` of a per-block validity receipt chained
IVC-style, resolved by the accelerated recursion circuit (weeks-scale,
linear-in-epoch GPU but fully pipelined block-by-block off the critical
path). Decision deferred; the point is the budget now exists.

**Fallback if Plonky3-recursion stalls upstream (not needed on the evidence,
but the honest hedge):** RISC0 proof composition alone — prove each
withdrawal's spend_verify as its own receipt continuously as withdrawals
arrive (0.3 B cycles each, off critical path, parallel), settlement guest
`env::verify`s the N receipts (cheap, accelerated resolve). Total GPU work
stays linear in N (~7 min/withdrawal, priced into the 1% peg fee), but
settlement *latency* becomes ~constant. Weeks of work, zero new deps.
(Reasoned from RISC0 3.x composition docs; not measured here.)

## 6. Measured vs reasoned — the honesty ledger

**Measured (this machine, logs in scratchpad):** everything in the §2 table;
ZK-mode recursion working; root-size fixed point; aggregation-node times;
build times.
**Measured previously (repo docs):** 0.30–0.42 B cycles/spend_verify, GPU
Mcyc/min, client prove times, proof sizes, epoch transition cost.
**Reasoned, NOT measured (ranked by risk):**
1. in-guest verify cost of the Poseidon2-config root proof (~0.2–0.6 B est.)
   — *the* M1 measurement; mitigations exist either way (§3);
2. layer-1 recursion at Q=67 on the real monolith (+preprocessed, hiding
   salts) vs the Q=36 Keccak proxy (~2.5–4 s est.);
3. client prove-time regression under Poseidon2 MMCS (<2× est., phone
   unmeasured);
4. 0.6.x rev-alignment friction;
5. `env::verify` fallback-path costs (risc0 docs, not exercised).

**Bottom line:** the structural trump card is real. Batch-independent,
trustlessness-carrying settlement is achievable with our exact proof system
and field, at the price of one hash-config migration and an integration
against an official-but-unaudited library — not months of research, and not
a different proof system. The phone client keeps its STARK; nothing about
this decision forces a client rewrite.

---
*Sources: Plonky3 checkout `~/.cargo/git/checkouts/plonky3-7d8a3b21a665a86f/4aed8fe`;
Plonky3-recursion @ b363397 (github.com/Plonky3/Plonky3-recursion, book at
plonky3.github.io/Plonky3-recursion); Aegis-USE `engine/src/config.rs`,
`engine/src/spend/monolith.rs`, `settlement/methods/guest-settlement/src/main.rs`,
`dev-docs/sidechain/batch-settlement-design.md`,
`dev-docs/sidechain/hash-native-spend-circuit.md`;
risc0-zkvm-platform-2.2.2 `src/syscall.rs`. Measurement logs:
scratchpad `keccak_bb{,_zk}.log`, `agg_bb_{4,8}.log` (Ryzen 7 7800X3D).*

---

## 7. M1 RESULT (2026-07-19): the RISC0 wrap is MEASURED — verdict GO

> **Status: MEASURED (this machine, Ryzen 7 7800X3D, risc0 3.0.5/r0vm 3.0.5,
> RISC0 executor `execute` — no prove).** This section closes the one
> materially unmeasured number from §6: the in-guest verify cost of the
> Poseidon2-config aggregate root proof. Harness: scratchpad `m1-wrap/`
> (guest+host) + two examples added to the Plonky3-recursion checkout
> (`m1_root_export.rs`, `m1_sha_final.rs`), b363397, crates.io p3 0.6.1.

### The number

Aggregation trees (BabyBear, Poseidon2 W16 MMCS + duplex challenger, spike
params lb3 / Q=36 / query-pow 16 / final-poly 64, non-ZK) built over N dummy
base proofs per the §2 prototype; each ROOT `BatchStarkProof` exported
(postcard), round-tripped into a minimal RISC0 guest that reconstructs the
config and runs `BatchStarkProver::verify_all_tables` in-field:

| N aggregated | root proof bytes | **in-guest root_verify cycles** | guest total¹ |
|---|---|---|---|
| 2 | 305,647 | **220,152,278** | 258.2 M |
| 4 | 324,290 | **227,058,758** | 267.4 M |
| 8 | 324,241 | **227,100,152** | 267.5 M |

¹ total = env::read (33–37 M, serde word-stream of the proof bytes) +
postcard deserialize (3.5–3.7 M) + verify. Segments (po2 20): 261–271.

- **~0.227 B cycles, constant in N.** N=4→N=8 grows by 0.018% — batch
  independence HOLDS (N=2 differs only via its level-1 table packing 2/2 vs
  1/3). This lands at the *bottom* of the §3 reasoned range (0.2–0.6 B) and
  well under the ≤1 B kill-criterion.
- The wrap costs **0.75× of ONE of today's spend_verifies** (0.30 B,
  `batch-settlement-design.md`), once, regardless of N. Today's N=4 in-guest
  cost ≈ 1.2 B; recursion root ≈ 0.227 B (5.3×), N=64 ≈ 19.2 B vs 0.227 B (85×).
- Round-trip risk (§4 serialization/no_std/riscv32) is DEAD: the whole
  `p3-circuit-prover` + p3 0.6.1 stack cross-compiled to riscv32im-risc0 on
  the first attempt (only `env::read_frame` being unstable needed a switch to
  `env::read`), and the host-side deserialize+verify of the exported bytes
  passed before every guest run.

### Where the cycles go (measured, RISC0 pprof on the N=4 run)

Software Poseidon2 IS the dominant term, as §3 suspected: Poseidon2
permutation ≈ **187.7 M cycles cumulative (~82% of verify)** — MerkleTreeMmcs
`verify_batch` 180 M + duplex challenger 13.6 M; next largest: 64-bit
div/rem (`__umoddi3` family, FRI index math) ~29 M (10.7%), FRI folding
arithmetic and batch-verifier logic the small remainder.

### SHA-accelerator mitigation: MEASURED, works, 4.7×

The §3 mitigation (prove the FINAL layer under a SHA-256-MMCS config so the
guest hashes on `sys_sha_buffer`) was built and measured, not just reasoned.
`prove_aggregation_layer_cross` can't be used directly — its `OutSC` bound
requires `FriRecursionConfig` (recursion targets; none exist for SHA) — but
the underlying pieces are config-generic, so the final prove is ~60 lines
against public `p3-circuit-prover` API (`m1_sha_final.rs`): build the last
2-to-1 verifier circuit under the Poseidon2 config, run its traces, then
`get_airs_and_degrees_with_prep::<ShaConfig>` + `ProverData` +
`prove_all_tables` under `StarkConfig<TwoAdicFriPcs<BabyBear, SHA-256 MMCS>,
D4, SerializingChallenger32>` (the engine's own non-hiding config shape).
In-circuit hashing stays Poseidon2; only the root proof's own commitments/
transcript ride SHA.

| final-layer config | root bytes | **in-guest root_verify** | guest total | notes |
|---|---|---|---|---|
| Poseidon2 (native) | 324,290 | **227.1 M** | 267.4 M | 0 accelerator calls |
| SHA-256 final layer | 290,325 | **48.1 M** | 83.6 M | 5,934 Sha2 ecalls (0.5 M cyc); **4.72×** |

Trade: host-side final prove slows 0.7 s → 4.4 s (software SHA hashing in the
prover; once per epoch, off critical path) — irrelevant. With the SHA final
layer the whole wrap (verify + read + deser) is **~84 M cycles ≈ 0.28× of one
spend_verify** — under 2 minutes GPU at measured 45 Mcyc/min, per epoch, for
ANY N.

### Verdict: **GO**

Both §6 risk-ranked unknowns #1 (root verify cost) and the §4(d) round-trip
risk are now measured and green; the recursion integration (I1–I5) is
committed on its merits: settlement critical path becomes
`~0.05–0.23 B cycles + epoch transition + N·ε`, independent of withdrawals.
Residual caveats (unchanged): layer-1 cost at Q=67 on the real monolith
(§6 #2, measure in I2/M1-follow-up), client Poseidon2 prove regression
(§6 #3), 0.6.x rev alignment (I1), unaudited-library exposure (external
review gate). The SHA final layer is now a measured, cheap option for I4 —
recommend adopting it (it also shrinks the proof and keeps the settlement
guest's existing sha2-accelerator patch relevant).

*M1 harness: scratchpad `m1-wrap/` (verify-core + guest + guest-sha + host),
`Plonky3-recursion/recursion/examples/m1_root_export.rs` + `m1_sha_final.rs`
(+ `p3-sha256 = "=0.6.1"` dev-dep), logs `m1-exec-n{2,4,8}.log`,
`m1-exec-n4-sha.log`, profile `m1-n4-profile.pb`. Guest verify =
`BatchStarkProver::verify_all_tables::<BinomialExtensionField<BabyBear,4>>`
with `register_poseidon2_table::<4>(BABY_BEAR_D4_W16)` +
`register_recompose_table::<4>(false)`; config reconstructed in-guest from
constants (no trusted prover-supplied params beyond the proof's own
`table_packing`; production must bake these + the circuit fingerprint into
the ELF, vk-pinning per §4(d)).*

---

## 8. I1 RESULT (2026-07-19): layer-1 on the REAL monolith — MEASURED, estimate confirmed

> **Status: MEASURED (Ryzen 7 7800X3D, 16 threads + AVX-512 via
> `RUSTFLAGS=-Ctarget-cpu=native`, `--features p3-circuit-prover/parallel`,
> matching the M1/§2 methodology).** Closes §6 unknowns #2 (layer-1 at Q=67 on
> the real monolith), #3 (client Poseidon2 prove regression) and #4 (0.6.x rev
> alignment). Harness: `Plonky3-recursion/recursion/examples/i1_monolith.rs`
> over a throwaway copy of the REAL engine (`scratchpad/i1-engine`, the actual
> `SpendAir` + `build_spend_trace` + 2-in/2-out witness from the monolith
> tests) re-pinned to crates.io p3 0.6.1; logs
> `i1-monolith-batch-{run2,par,spikepar,spikenative,enginenative}.log`.

### 8.1 The headline: the real monolith recurses at proxy-consistent cost

One REAL hiding spend proof — 128×2756 monolith + 24-col preprocessed
schedule, under the recursion-required client config (Poseidon2-W16 **salted**
hiding MMCS + duplex challenger) at the engine's exact FRI numbers
(lb3 / **Q=67** / pow16 / cap_height 3 / SALT_ELEMS 4 / 4 random codewords) —
recursively verified in layer-1:

| Layer-1 (per proof, after cacheable setup) | measured |
|---|---|
| **recursive prove (witness run + outer prove)** | **1.8–3.4 s** (steady-state ~2.0–2.1 s) |
| — of which witness run (in-circuit verify execution) | 52–104 ms |
| verification-circuit build (one-time) | 0.42 s (witness_count 995,531) |
| outer prover prep (one-time) | 0.60 s |
| layer-1 proof size (outer at spike params lb3/Q36/lfp6/arity2) | 381,028 B |
| layer-1 native verify | 7.4 ms |

**The §6 #2 estimate (~2.5–4 s) is confirmed — measured 1.8–3.4 s.** The
2756-col / Q=67 / salted / preprocessed monolith costs ~1.2× the Q=36 Keccak
proxy (1.74 s), not a blow-up: the in-circuit content grows (ALU 229 k rows vs
144 k; Poseidon2 32.3 k vs 25.9 k) but pads to the same table heights. The
killer-risk question of §"does the real monolith actually recurse" is closed:
it recurses, verifies natively, and the layer-1 output is an ordinary
batch-STARK ready for the M1-measured aggregation tree + RISC0 wrap.

Outer-parameter sensitivity (same circuit, outer FRI swapped to the engine's
own conservative numbers lb3/Q67/lfp0/arity1/cap3): prove **1.8–2.2 s** —
statistically indistinguishable from the spike-params outer — with proof
806,882 B (vs 381 KB) and native verify 16.8 ms (vs 7.4 ms). I.e. even
proving every tree layer at full client-grade parameters costs ~nothing in
time; the I5 intermediate-layer relaxation buys proof SIZE (and next-layer
in-circuit query count), not prove time. (Without AVX-512/rayon the same
prove is 55 s single-threaded — the recursion prover leans hard on packed
Poseidon2; see 8.4.)

### 8.2 Client prove regression (§6 #3): <2× CONFIRMED on native-ISA builds

Same witness, same machine, same run, p3 0.6.1 (SHA config = the engine's
current production shape; Poseidon2 = the I2 target):

| client hiding prove (2-in/2-out) | 16T + AVX-512 | 16T, no native ISA | 1T, no native ISA | proof bytes |
|---|---|---|---|---|
| SHA-256 MMCS + byte challenger (today) | **34 ms** | 59 ms | 141 ms | 1,206,382 |
| Poseidon2 salted MMCS + duplex (uni-stark) | **46 ms** | 188 ms | 924 ms | 1,234,917 |
| Poseidon2, single-instance **batch**-stark | **37 ms** | 187 ms | 1,017 ms | 1,235,183 |

- With the vector ISA the regression is **~1.1–1.35×** — the "<2×" reasoned
  estimate holds, and absolute cost (~40 ms desktop) is nowhere near the
  seconds-scale kill criterion. Without SIMD the ratio degrades to ~3× (16T)
  / ~6.6× (1T) because software Poseidon2 loses its packing advantage while
  SHA-NI keeps its hardware one — **the phone datapoint (ARMv8 NEON+SHA2 ext)
  remains the open I2 measurement**, expect between the 1.3× and 6.6× ratios,
  i.e. sub-second absolute either way.
- Proof stays ~1.23 MB (digests shrink 32 B→8 elems, salts+random codewords
  grow rows) — `MAX_PROOF_BYTES` headroom unchanged at MB scale.
- Native out-of-circuit verify of the Poseidon2 hiding proof: 22–46 ms.

### 8.3 Rev alignment (§6 #4): the assumption was INVERTED — and it's still cheap

§1/§4(a) assumed crates.io 0.6.1 is *ahead* of our git pin. It is **behind**:
0.6.1 (2026-06-13) = 0.6.0 + one perf PR (#1815); our `4aed8fe` (2026-07-15)
carries ~30 further uni-stark-line PRs incl. the p3-lookup redesign (#1566),
the PeriodicAirBuilder→AirBuilder merge (#1611) and API churn the recursion
library has never seen. So "align both sides" means **step the engine BACK to
the release line**, not forward — and that direction is measured-trivial:

- Whole engine compiles against crates.io `=0.6.1` with **two one-line
  diffs** (`RoundConstants::try_from_layers` → `RoundConstants::new` — the
  former is post-0.6.1; `PartialRound` regains its `WIDTH` generic) plus
  dropping the `p3-security` dev-dep (not published on crates.io — the
  soundness-regression test needs a vendored copy or a git dev-pin) and a
  `#[derive(Clone, Copy)]` on `SpendAir` (batch-stark instances need `Clone`).
- **All 73 engine tests pass at 0.6.1**, including the hiding prove/verify
  and oracle-parity suites.
- Do NOT attempt to forward-port Plonky3-recursion to 4aed8fe in I1 — the
  lookup/AirBuilder churn makes that days-of-porting for zero measurement
  value. Long-term the library will track upstream releases; re-align then.

### 8.4 Upstream gap found (the real integration cost I1 was hunting)

**`RecursionInput::UniStark` over a `HidingFriPcs` proof is broken at
b363397** — `prove_next_layer` dies with
`WitnessConflict { witness_id: 0, existing: 0, new: 1 }` during the witness
run. Bisected: reproduces with a trivial 3-col AddAir, no preprocessed
columns, cap 0 or 3, engine or spike FRI shapes — it is the ZK-uni-stark
recursion path itself, not our AIR. Root cause consistent with test coverage:
**no upstream test exercises ZK + UniStark** (recursive_keccak = non-ZK
uni-stark; every ZK test — `fibonacci_batch_stark_prover_zk`,
`zk_aggregation`, `zk_hiding_mmcs` — goes through batch-stark). Upstream main
== b363397, no fix available.

**Resolution (measured here, recommended for I2–I4): the client proves a
SINGLE-INSTANCE `p3-batch-stark` proof** (`prove_batch` with one
`StarkInstance` — preprocessed schedule handled natively) and layer-1 uses
`BatchStarkVerifierInputsBuilder` + `verify_batch_circuit` — exactly the path
upstream tests for the salted hiding MMCS (`tests/zk_hiding_mmcs.rs`, issue
#440 config). Cost is a wash (37 vs 46 ms client-side; same proof bytes), and
it makes every level of the tree the same proof species (BatchStark), which
the aggregation API already assumes. File the ZK-UniStark bug upstream; do
not block on it.

Two working notes that saved the measurement and belong in I2's build recipe:
- the salted-MMCS recursion targets exist and work end-to-end
  (`RecValHidingMmcs` + `HidingFriProofTargets` +
  `set_hiding_salted_fri_mmcs_private_data`) — §4(c)'s "wiring detail" is
  confirmed wired;
- the prover's performance envelope REQUIRES `--features
  p3-circuit-prover/parallel` **and** `RUSTFLAGS=-Ctarget-cpu=native`:
  without them the same layer-1 prove is 9.5 s (16T, no AVX-512) / 55 s (1T)
  — a 27× spread. Deployment docs must pin the build flags (and the
  aggregation-service capacity math must use the flags actually deployed).

### 8.5 Verdict: GO stands, all four §6 unknowns now measured

| §6 unknown | was | now |
|---|---|---|
| #1 root wrap in-guest | ~0.2–0.6 B est. | **0.227 B / 48 M (SHA final) — §7** |
| #2 layer-1 at Q=67 real monolith | ~2.5–4 s est. | **1.8–3.4 s** |
| #3 client Poseidon2 regression | <2× est. | **~1.3× (AVX-512); 3–6.6× without SIMD; phone TBD (I2)** |
| #4 rev alignment | LOW risk, direction unknown | **engine→0.6.1: 2-line diff, 73/73 tests green** |

The proxy hid one real cost — not in the numbers but in the API: the
ZK-uni-stark entry point is untested upstream and broken; the committed path
routes clients through single-instance batch-stark proofs instead (measured
equal). Remaining open items for the integration: phone-class client prove
(I2), upstream bug report + pin/vendor policy (I1 tail), tower-parameter
policy (I5 — now measured as an optimization, not a correctness need).

*I1 harness: scratchpad `i1-engine/` (engine copy at `=0.6.1`; diffs: config
test module removed with the unpublished `p3-security` dev-dep,
`RoundConstants::new`, `PartialRound<_, WIDTH, _, _>`, `derive(Clone, Copy)`
on `SpendAir`),
`Plonky3-recursion/recursion/examples/i1_monolith.rs` (salted-ZK
`FriRecursionConfig` impl + batch-route layer-1 + AddAir bisection probe;
env knobs `I1_CAP/LFP/ARITY/Q/POW/ITERS/SKIP_SHA/OUTER/MODE_UNISTARK/
MODE_ADDAIR`), logs `i1-monolith-batch-*.log` (run2 = 1T, par = 16T,
spikepar = 16T spike-outer, spikenative/enginenative = 16T+AVX-512).*

---

## 9. I2 RESULT (2026-07-19): phone-class client prove under the recursion config

> **Status: MEASURED x86 ISA brackets (Ryzen 7 7800X3D, p3 0.6.1, same
> `i1_monolith` harness + `I1_CLIENT_ONLY=1` early-exit) → REASONED phone
> estimate.** Closes the one open caveat from §8.2/§6 #3: phones lack AVX-512,
> so does the recursion-required client config (Poseidon2 salted MMCS +
> duplex challenger, batch-stark route, lb3/Q67/pow16) stay phone-viable? No
> real ARM hardware on this box (no qemu-user, no cross-linker; and qemu-user
> soft-emulates both NEON and the SHA2 crypto ext, so its *timing* is
> non-representative) — instead I bracket NEON between MEASURED x86 scalar and
> AVX2 points, exploiting that both proof configs are the same code paths.

### 9.1 The measured x86 ISA sweep (client prove only, min of 5 iters)

The batch-stark route is the **committed client path** (§8.4); SHA-256 is
today's config, measured side-by-side on the same build for a same-ISA ratio.
`-Ctarget-cpu=x86-64-v3` = AVX2/no-AVX512 (8-wide packed BabyBear); default
target = no AVX2 → p3 monty-31 falls to **scalar** packing (p3 ships no SSE
backend); `native` = AVX-512 (16-wide). SHA-256 hashing rides the CPU's
**SHA-NI in every build** — the `sha2` crate runtime-detects it, independent of
`-Ctarget-feature` — so the SHA column isolates the FRI/DFT arithmetic tail.

| config | scalar 1T | scalar 4T | AVX2 1T | AVX2 4T | AVX-512 1T | AVX-512 4T |
|---|---|---|---|---|---|---|
| **Poseidon2 batch-stark (recursion-required)** | 922 ms | 275 ms | **126 ms** | **51 ms** | 117 ms | 46 ms |
| SHA-256 hiding (today) | 144 ms | 61 ms | 70 ms | 30 ms | 67 ms | 26 ms |
| **Poseidon2 / SHA ratio** | 6.4× | 4.5× | **1.80×** | 1.70× | 1.75× | 1.77× |

Two facts fall out that resolve the caveat:

1. **AVX-512 buys essentially nothing over AVX2 for the *client* prove**
   (126→117 ms 1T; 51→46 ms 4T — ~7%). Unlike the *recursion* prover (§8.4,
   27× scalar→AVX512 spread), the client prove over a tiny 128×2756 trace is
   dominated by fixed/serial commit+FRI structure, not by the widest-SIMD
   Poseidon2 inner loop. Width sensitivity is weak once *any* vector unit is
   present.
2. **The 6.6× scalar regression is a red herring for phones.** The scary
   ratio only appears with NO vector unit at all (Poseidon2 goes fully scalar
   while SHA keeps SHA-NI). The instant a vector unit exists — AVX2 *or*
   AVX-512 — the ratio collapses to **~1.7–1.8×**. **A phone always has a
   vector unit (NEON) and hardware SHA2, so it lives in the ~1.8× regime, not
   the 6.4× scalar regime.**

### 9.2 The phone estimate (reasoned from the brackets)

A phone's Poseidon2 hashing uses p3's **NEON** BabyBear backend (128-bit,
4-wide u32) — narrower than AVX2 (8-wide) but far above scalar (1-wide); its
SHA-256 uses the **ARMv8 SHA2 crypto extension** (hardware, SHA-NI-equivalent,
same `sha2`-crate runtime dispatch). So on a phone:

- **Poseidon2 sits between the measured AVX2 and scalar x86 points**, and much
  closer to AVX2: NEON is 4-wide vs AVX2's 8-wide, but §9.1 fact #1 shows this
  workload barely moves with SIMD width above 4 lanes. Estimate NEON ≈
  **1.3–1.8× the AVX2 time** on an equal-speed core → ~165–230 ms 1T,
  ~65–90 ms 4T *if the core matched the 7800X3D*.
- **Core-speed derating:** a flagship phone big core (Apple A-/M-class,
  Cortex-X4) runs ~1.5–2.5× slower than a Zen4 core at this integer/SIMD work;
  mid-range ~3–4×.

Composing (NEON penalty × core derating) on the AVX2 anchor:

| phone class | Poseidon2 batch client prove (est.) | SHA config, same phone (est.) |
|---|---|---|
| flagship, 1 big core | **~0.35–0.6 s** | ~0.15–0.25 s |
| flagship, ~4 cores | **~0.15–0.3 s** | ~0.06–0.12 s |
| mid-range, 1 core | **~0.7–1.2 s** | ~0.3–0.5 s |
| mid-range, ~4 cores | **~0.35–0.6 s** | ~0.15–0.25 s |

The SHA column reproduces the prior hash-native spike's **~0.2–0.5 s phone**
anchor for the OLD config (`hash-native-spend-circuit.md`) — cross-check that
the derating is calibrated right.

### 9.3 Verdict: **PHONE-VIABLE — modest ~1.8–2.5× regression, still sub-second-to-~1s**

The recursion-required Poseidon2 client prove lands at **~0.2–0.6 s on a
flagship (multi-core), ~0.35–1.2 s on a mid-range phone** — comfortably inside
the payment UX bar (sub-second to a second), nowhere near the "many seconds"
kill line. The regression vs today's SHA config is **~1.8× (measured, any
vector ISA)**, widening to perhaps **~2–2.5× on NEON** as Poseidon2 loses a
little width while SHA stays HW-fixed — a real but small UX cost to note, not a
blocker. Proof size grows negligibly (1.206 → 1.235 MB, measured;
`MAX_PROOF_BYTES` headroom unchanged). **The §8.2/§6 #3 caveat is closed: no
mitigation is required for phone viability.** The client keeps its STARK; I2
is just the SHA→Poseidon2 config swap.

**Mitigations, if a target phone ever comes in high (not needed on this
evidence):**
- *Keep client SHA + a translation layer* — rejected: there is no in-circuit
  SHA gadget, so a SHA client proof cannot be recursed without a
  months-of-work SHA-in-circuit build (§4(e)); a "re-prove SHA→Poseidon2"
  translation is just proving twice, strictly worse than proving Poseidon2
  once (the measured Poseidon2 prove is already sub-second).
- *Cheaper client config, re-prove for recursion* — same double-prove
  objection; and the client prove is not the bottleneck (settlement is).
- The genuinely available lever is **thread count**: the 1T→4T speedup is
  ~3.4× (measured), so a phone that dedicates a few big cores to the burst
  gets the multi-core row for free. No code change.

### 9.4 Measured vs reasoned (I2 honesty ledger)

- **Measured (this machine):** all of §9.1 — scalar/AVX2/AVX-512 × 1T/4T for
  both configs, the AVX2≈AVX-512 client-prove finding, the ~1.8× vector-ISA
  ratio, proof sizes.
- **Reasoned, NOT measured:** the phone absolute times (§9.2) — bracketed by
  the measured x86 scalar/AVX2 points plus NEON-width and phone-core-derating
  factors from public ARM microarchitecture characteristics; not run on ARM
  silicon. A true on-device datapoint (an aarch64 build on a real phone/board;
  qemu-user timing is not representative) remains as cheap validation before
  cut, but the bracket is tight and the verdict is not close to the bar.

*I2 harness: same `i1_monolith.rs` + a one-line `I1_CLIENT_ONLY` early-exit
after the batch native verify (skips layer-1 recursion); three release builds
in isolated `CARGO_TARGET_DIR`s — `p3rec-target` (scalar/default),
`p3rec-target-v3` (`-Ctarget-cpu=x86-64-v3`, AVX2), `p3rec-target-native`
(`-Ctarget-cpu=native`, AVX-512); run at `RAYON_NUM_THREADS=1` and `=4`,
`I1_ITERS=5`, min-of-5 reported.*

---

## 10. I4 RESULT (2026-07-19): the settlement statement is BLOCKED — the root does NOT surface per-leaf publics

> **Status: BLOCKED — precise STOP, empirically confirmed (this machine, warm
> I3 `CARGO_TARGET_DIR`, `RUSTFLAGS=-Ctarget-cpu=native` + `parallel`).** I4
> was "turn the I3 aggregation root into an on-chain-verifiable settlement
> proof": surface each withdrawal's `(amount, recipient_prop, nf0)` /
> `(nf0, cm0)` into the root's committed journal so the batch-settlement
> statement (batch-settlement-design.md §1) binds to exactly the aggregated
> withdrawals. **The crux (I4 item 1 — the one §5/task flagged as the possible
> research problem) does not hold with the b363397 library as-is: the aggregate
> root exposes no per-leaf publics, and the proof format offers no external
> public-input check to bind them.** Items 2–4 (SHA-final wrap, RISC0-guest-
> over-root, constant-in-N cost) are UNBLOCKED and already measured GREEN in §7
> — only the *binding* is blocked. Building a guest that emits the §1 journal
> without the binding would be an **unsound** settlement statement (security
> theater), so per the task's explicit instruction I stopped rather than force
> it.

### 10.1 What the settlement statement requires (and why v5 has it, recursion doesn't)

v5's single-withdrawal guest binds the withdrawal to the spend proof by
verifying it **in-field against externally-supplied `pis`**:
`verify_with_preprocessed(config, air, proof, pis, vk)`
(`guest-settlement/src/main.rs:84`) — `pis` is passed in and CHECKED, so
`nf0 = pis[PUB_NF0..]`, `cm0 = pis[PUB_CMO0..]` (`main.rs:94-95`) are provably
the ones this proof attested. The burn binding and journal then read from that
bound `pis`. Recursion's whole point is to replace the N in-field verifies
with ONE root verify — so the root must surface those N×(nf0,cm0,amount,
recipient) in a form the guest can **read** and the verifier **checks**.
It does neither.

### 10.2 The mechanism, cited — three independent walls, one conclusion

1. **`verify_all_tables` takes no external publics.** Signature is
   `verify_all_tables<EF>(&self, proof: &BatchStarkProof<SC>)` — no public-
   value argument (`circuit-prover/src/batch_stark_prover.rs:1284`). The
   internal `verify` (`:1737`) builds `pvs` as `vec![Vec::new(); NUM_PRIMITIVE_
   TABLES]` and only `push`es `entry.public_values` for **non-primitive**
   tables (`:1778-1794`), then calls `p3_batch_stark::verify_batch(config,
   airs, proof, &pvs, common)` (`:1813`). So the primitive `Const/Public/Alu`
   tables are verified with **empty** external public values — nothing to bind
   against. The M1 guest confirms this operationally: it verifies the root with
   `verify_root(&proof)` supplying no publics at all (§7).
2. **Circuit `public_input()` values live in the primitive `Public` table's
   committed trace — not as AIR public values.** The `Public` table is
   `WitnessSendAir`: "The AIR has no constraints" and exposes **no** AIR public
   values (`circuit-prover/src/air/public_air.rs:16,173-196`); the public-input
   VALUES are committed in the main trace and bound only via an internal
   `"WitnessChecks"` bus lookup (`:202-229`). They are never plaintext in the
   proof and never externally checked.
3. **The only propagating/plaintext channel is non-primitive `public_values`,
   and it does not reach the root.** In the aggregation verifier, the child's
   re-exposed air-public counts are `vec![0; NUM_PRIMITIVE_TABLES]` then, per
   non-primitive entry, `entry.public_values.len()`
   (`recursion/src/verifier/batch_stark.rs:313-316`) — i.e. **only** non-
   primitive table `public_values` propagate to the parent, and they land as
   the parent's *primitive* `public_input()`s (count 0 upstream) → they die
   after exactly one level. The 44 client publics enter at layer-1 as the
   verified client instance's air publics → the layer-1 circuit's **primitive**
   `Public` values (`engine/recursion/src/lib.rs:432-436`, `air_public_counts
   = [44]`) → they never propagate even one level. `RecursionOutput::
   into_recursion_input::<BatchOnly>()` hard-codes `table_public_inputs:
   vec![vec![]; num_tables]` (`recursion/src/recursion.rs:132-137`),
   consistent with (2)/(3). The library book agrees: recursion public inputs
   are "the previous proof's commitments, opened values, and challenges"
   (`book/src/user_guide/public_inputs.md:3`) — **not** an inner AIR's
   statement values; there is no surfacing facility (grep of `recursion/`,
   `circuit-prover/` for expose/carry/forward/propagate-public: none).

### 10.3 Empirical confirmation (the incontrovertible nail)

`engine/recursion/tests/surface_publics.rs` (new, committed) aggregates **two
REAL distinct spends** to a root and inspects every plaintext public surface:

```
[I4-PROBE] root 754108 bytes | 2 non-primitive tables | 0 total EXPOSED public values
[I4-PROBE]   non_primitive[0] op=poseidon2_perm/baby_bear_d4_w16 public_values.len()=0
[I4-PROBE]   non_primitive[1] op=recompose                        public_values.len()=0
[I4-PROBE] leaf nf0/cm0 octets recoverable from root exposed publics: 0 / 4
test root_does_not_expose_per_withdrawal_publics ... ok   (9.91s)
```

**The root exposes ZERO plaintext public values.** No `nf0`, no `cm0`, no
`amount` — nothing the §1 journal or the burn binding needs is readable from
or checkable against the root. The withdrawal publics are cryptographically
*bound inside* layer-1's `Public`-table commitment (the tower attests each
client proof is valid) but are **not surfaced**, so a settlement guest cannot
tie the `(amount_i, recipient_i, nf0_i, cm0_i)` it journals to the proofs the
root verified. Recursion-without-surfacing is therefore **strictly weaker than
v5** (it loses even the spend→withdrawal link v5 gets for free), not merely
subject to the already-documented honest-scope caveats (§4 epoch-canonicality,
§7 H1 recipient-binding). This is a **core soundness gap, not a deferrable
stub.**

### 10.4 Options to unblock (ranked — for the orchestrator to choose; each is real work, none is "structure the guest to slot it in")

- **(A) Accumulating-digest carry via a non-primitive `public_values` channel
  (recommended, biggest lift).** Make each aggregation layer compute in-circuit
  a Poseidon2 fold `d_parent = H(d_left ‖ d_right)` of its children's
  withdrawal digests, and route `d_parent` onto a *non-primitive* table's
  `public_values` (the one channel that both propagates one level AND is
  plaintext+observed at the root). At layer-1, seed the leaf digest from the
  44 client publics. The root's non-primitive `public_values` then carry the
  epoch's Merkle-root-of-withdrawals; the guest recomputes it from the
  §1 entry list and checks equality. Requires: (i) a small custom NPO/AIR that
  exposes `public_values` and is threaded through `prove_aggregation_layer`
  at every level (the library today zeroes primitive publics and only carries
  NPO publics one level — this needs the digest to *re-seed* the NPO channel
  each level), and (ii) in-circuit Poseidon2 folding wired into the aggregation
  circuit builder. Substantial work inside the **unaudited** library; weeks-
  scale; must go through the value-gate review.
- **(B) External public-input check in the final verify (smaller, but library
  core).** Add a `verify_all_tables_with_publics(proof, expected_public_inputs)`
  that passes the primitive `Public` table's expected values through to
  `p3_batch_stark::verify_batch`'s `pvs` (today hard-zeroed at
  `batch_stark_prover.rs:1780`) and binds them. Then a dedicated final
  "settlement-wrap" layer exposes the withdrawal digest as its `public_input()`
  and the guest supplies+checks it. Smaller diff, but it modifies the
  circuit-prover's verification core and its soundness (the `WitnessChecks`
  bus semantics for externally-pinned publics) must be reviewed — again inside
  the unaudited library.
- **(C) Abandon in-guest surfacing; bind via a second RISC0 receipt per leaf
  (the §5 fallback, no recursion-lib change).** Keep the root verify for
  batch-independence of *validity*, but bind each withdrawal's publics with a
  cheap per-leaf statement (e.g. the client proof's `pis` committed by a
  tiny per-leaf receipt composed via `env::verify`). Loses part of the
  batch-independence win (O(N) small receipts) but needs zero unaudited-lib
  surgery. Weakest structurally, safest to ship.

### 10.5 What IS green and ready (so I4 is blocked, not worthless)

- The RISC0 wrap over the root is measured and constant in N: **0.227 B cyc
  (Poseidon2) / 48 M cyc (SHA-256 final layer, 4.72×)**, N=2→8 flat (§7). The
  SHA-final integration (item 2) and the guest-over-root (item 3) are proven
  out in the M1 harness (`scratchpad/m1-wrap`, `m1_sha_final.rs`); porting them
  into `settlement/` is mechanical **once the binding channel from 10.4
  exists** — without it they would only reproduce §7.
- The I3 pipeline (`aggregate_spends`/`verify_root`) is unaffected and green;
  the new probe test runs alongside `tests/aggregate.rs`.

**Recommendation: adopt (A) as the I4 design, scoped as its own milestone
inside the value-gate review, before any guest/journal code.** Do not ship a
journal-emitting guest until one of (A)/(B)/(C) binds the per-withdrawal
publics — an unbound §1 journal is not a settlement proof.

*I4 harness: `engine/recursion/tests/surface_publics.rs` (aggregates 2 real
spends, inspects `root.non_primitives[*].public_values`), run in the warm I3
`CARGO_TARGET_DIR` (`scratchpad/i3-target`) with the mandated flags. Source
audit: `circuit-prover/src/batch_stark_prover.rs:1284,1737-1815`,
`circuit-prover/src/air/public_air.rs`,
`recursion/src/verifier/batch_stark.rs:313-321`,
`recursion/src/recursion.rs:128-138,597-646`,
`recursion/src/public_inputs.rs:361-385`,
`book/src/user_guide/public_inputs.md` (Plonky3-recursion @ b363397).*
