# Settlement‑proof speed plan (grounded + tiered)

Goal: cut the Statement‑1 settlement proof wall‑clock (measured **63.5 min on an
RTX 3090**, PO2=19, GPU shared with a 4 GB llama‑server) **without weakening
security**. This is a research/analysis doc — numbers are labelled *grounded*
(from source or a cited formula) vs *estimate* (a reasoned guess). No production
code was changed and no running process was touched.

## 0. What actually costs the cycles (measured + source‑confirmed)

Measured cycle breakdown (from the guest's own `env::log` counters,
`settlement/methods/guest-settlement/src/main.rs`):

| Phase | Cycles | Nature |
|---|---:|---|
| `vk_setup` (in‑guest `setup_preprocessed`) | 66 M | epoch‑independent, avoidable |
| **`spend_verify`** (in‑field Plonky3 FRI verify) | **1.18 B** | **DOMINANT, epoch‑independent** |
| `tree_transition` (incremental frontier) | 496 M | O(epoch), already collapsed |
| Total | ~1.93 B | 1921 segments @ PO2=19 |

The client proof config (source: `engine/src/config.rs`,
`engine/src/spend/monolith.rs`, `engine/src/spend/perm.rs`, Plonky3 rev
`4aed8fe`):

- **Field**: BabyBear + degree‑4 extension for challenges (the RISC0 verifier's
  field — chosen so the guest re‑verifies *in‑field*, no foreign‑curve MSM).
- **Config used at settlement**: the *hiding* config (`hiding_config`) →
  `FriParameters::new_benchmark_zk` = **log_blowup 2, num_queries 100,
  query_pow_bits 16, commit_pow_bits 0, log_final_poly_len 0**
  (grounded: `fri/src/config.rs:132`). Conjectured soundness =
  `log_blowup·num_queries + query_pow_bits = 2·100 + 16 = 216 bits`
  (grounded: `conjectured_soundness_bits`, `fri/src/config.rs:43`).
- **FRI Merkle hashing** (the thing the guest recomputes 100× per proof):
  - leaf hash `FieldHash = PaddingFreeSponge<Poseidon2‑t24, rate 16, out 8>`
  - node compress `TruncatedPermutation<Poseidon2‑t16, 2, 8, 16>`
  - Poseidon2 is **software** in the guest (t=24/t=16, R_F=8, R_P=13/21, x⁷).
    RISC0's Poseidon2 precompile is **ruled out** (t=24 param mismatch — do not
    re‑investigate).

### The cost model (why width and query‑count are the two big knobs)

The monolith main trace is **exactly 2756 columns** (`ROW_W`, verified by
arithmetic: `8 perm‑blocks × 298 PERM_COLS = 2384`, + child/sib/bit/bus(20)/
range‑bits(320)/carries(6)/eneq(8)/inv(1) = **2756**) × **128 rows** (`N_ROWS`,
= `(2·(1+DEPTH)+1)` padded to a power of two, DEPTH=32).

A uni‑STARK FRI verify, per query, hashes the **opened leaf across the full
committed row**. So the dominant term is:

```
leaf_hash_perms ≈ num_queries × ceil(row_width / rate16) × perm24
              ≈ 100 × ceil(2760 / 16) × perm24
              ≈ 100 × 173 × perm24  ≈ 17,300 Poseidon2‑t24 perms
```

plus a Merkle authentication path (log₂(128·blowup4)=9 levels × perm16 × 100 ≈
900 perm16), the FRI fold layers (small), and — importantly — the **OOD
constraint evaluation + DEEP combination**, which is field arithmetic
proportional to **trace width** as well. At an estimated ~40–60k guest cycles
per software perm24, `17,300 × ~50k ≈ 0.87 B`, i.e. the **leaf hashing alone
plausibly accounts for ~60–75 % of the 1.18 B `spend_verify`** (estimate —
the per‑perm cycle figure is not directly measured).

**Two conclusions, both grounded in the structure:**
1. `spend_verify` scales ≈ linearly in `num_queries` → **query reduction is a
   direct multiplier** (Tier 1).
2. `spend_verify`'s dominant term scales ≈ linearly in **committed trace
   width** (leaf hash) *and* in width again (constraint eval) → **narrow trace
   is the biggest single circuit lever** (Tier 2), and **swapping the FRI
   Merkle hash for a RISC0‑accelerated hash** attacks the same term from the
   other side (Tier 2, the sleeper).

---

## Tier 0 — free, zero security impact (do first)

### T0.1 Free the GPU + raise segment PO2 (19 → 21/22)
- **Why it was 19**: forced down because the CUDA prover OOM'd sharing 24 GB
  with a 4 GB llama‑server (per the task facts). PO2=19 → 1921 segments.
- **What PO2 buys**: RISC0 proves each segment then lifts+joins them via
  recursion. Fewer, larger segments = fewer lift/join recursion proofs +
  better GPU NTT occupancy. Segment count ≈ `total_cycles / 2^po2`:
  - PO2 20 → ~960 segments, PO2 21 → ~480, PO2 22 → ~240 (grounded arithmetic).
- **VRAM** (estimate — RISC0 CUDA memory ≈ doubles per PO2): PO2 21 ≈ 8–12 GB,
  PO2 22 ≈ 16–24 GB on a 24 GB 3090. **PO2 21 fits comfortably once the GPU is
  freed; PO2 22 is feasible but tight.** Set via `RISC0_SEGMENT_PO2` /
  `ProverOpts::segment_limit_po2`.
- **Estimated win**: **~1.3–1.6×** wall‑clock (segment proving itself is ~linear
  in cycles regardless of PO2; the saving is recursion overhead + occupancy).
  63.5 min → **~40–48 min**. *Confidence: medium.* Security impact: **none**
  (PO2 does not touch soundness).
- **Effort**: trivial (env var + stop llama‑server during a proof, or pin it to
  CPU). Re‑measure immediately — it recalibrates every downstream estimate.

### T0.2 (conditional) Multi‑GPU segment proving
- RISC0 has an experimental parallel/multi‑GPU default prover
  (`RISC0_PROVER=actor`; source: RISC0 docs). Segments are embarrassingly
  parallel. "A GPU may be free" → **~1.8× with one extra card** (estimate,
  near‑linear in #GPUs minus join overhead). Security impact: **none**.
- **Effort**: low‑moderate (prover selection + memory partitioning). Belongs in
  Tier 0 mechanically but gated on a second card being genuinely free.

---

## Tier 1 — parameter tuning, security‑preserving, small re‑review

### T1.1 Bake the vk commitment instead of rebuilding it in‑guest
- Today the guest runs `setup_preprocessed` every proof (**66 M cycles**) purely
  to pin the vk to the image id. The vk is a fixed function of a fixed public
  salt — you can bake the **vk commitment digest** as a guest constant
  (still pinned by the image id, since the constant lives in the ELF) and skip
  the in‑guest FFT+commit.
- **Win**: ~66 M / 1.93 B ≈ **3.4 %** of total. *Confidence: high.* Security:
  neutral (the pin moves from "recompute" to "hard‑coded in the imaged ELF").
- **Effort**: low. Re‑review: confirm the baked digest equals
  `setup_preprocessed(...).vk.commit` for the pinned salt (one oracle test).

### T1.2 FRI query↔PoW↔blowup rebalance (constant soundness)

The soundness accounting (grounded — `fri/src/config.rs` + the vendored
`p3-security` crate, which implements both regimes: conjectured = ethSTARK
2021/582 / random‑words 2025/2010; proven = round‑by‑round 2024/1553 + LDR
2025/2055):

- **Conjectured**: `bits = log_blowup·Q + query_pow` → each query = `log_blowup`
  bits; each PoW bit = 1 bit.
- **Proven (UDR)**: each query ≈ `log_blowup / 2` bits (unique‑decoding radius).
  Current ZK config → **~216 conjectured / ~116 proven** bits (proven estimate
  from the L/2 rule; the `p3-security` `proven_error_udr` gives the exact
  figure and should be run to confirm).

**Levers, holding security constant:**

- **PoW alone is weak.** Dropping a query costs `log_blowup` conjectured bits (2)
  that PoW must repay 1‑for‑1, and Fiat‑Shamir grinding has a practical ceiling
  ~30 bits (grounded: `p3-security/whir.rs` POW‑ceiling note). From
  `query_pow 16 → ~28` you buy back only ~6 queries (conjectured) / ~12
  (proven). **~6–12 % query cut.** Client grind cost at pow 28 over the
  Poseidon2 challenger ≈ 2²⁸ perms — seconds on the phone, tolerable.
- **Blowup↔query rebalance is the real Tier‑1 knob.** Raising `log_blowup` lets
  you cut queries at constant security, moving cost from the guest‑verifier to
  the client‑prover:
  - proven target ~116 bits: `(log_blowup/2)·Q + pow = 116`
  - blowup 2→**4** (L3), pow 16→24: `1.5·Q + 24 = 116` → **Q ≈ 61** (‑39 %).
  - blowup 2→**8** (L4), pow 16: `2·Q + 16 = 116` → **Q ≈ 50** (‑50 %).
- **Guest win** ≈ proportional to the query cut on the leaf‑hash term
  (~60–75 % of `spend_verify`). Q 100→61 → `spend_verify` ~1.18 B → **~0.88 B**
  (**~1.35×**). *Confidence: medium* (rests on the leaf‑fraction estimate).
- **Client cost**: blowup ×2 (2→4) ≈ **1.5–2×** client prove time and FFT domain
  (phone hiding ~750 ms→4 s budget → +~0.5–1.5 s). Blowup ×4 (2→8) starts to
  bite the phone budget. **Sweet spot: blowup 4, pow 24, Q≈61** — the guest wins
  ~35 %, the phone pays ~1.5–2×, soundness is unchanged (a *rebalance*, not a
  weakening).
- **Security/re‑review**: **small** — same soundness target, re‑run
  `p3-security` to confirm proven+conjectured bits at the new triple, re‑assert
  the ZK mask‑budget inequality (`num_queries + OOD < random_rows`; still
  100‑ish queries, so unchanged). Update the flagged REVIEW ITEM in
  `config.rs`.
- **Effort**: low (a one‑line `FriParameters` change + client grind loop + a
  soundness‑regression test). **This is the highest‑leverage cheap change.**

**Tier‑1 stacked**: ~1.93 B → ~1.5 B cycles (~1.3×), on top of Tier‑0 wall.

---

## Tier 2 — circuit / config rework (re‑audit required)

### T2.1 ⭐ SHA‑256 FRI‑Merkle commitment (the sleeper — highest upside)

**Idea**: the client currently commits its FRI Merkle tree with Poseidon2
(software in the guest). Swap **only the commitment MMCS hash** to SHA‑256, which
RISC0 accelerates natively — the guest then verifies openings via the SHA
accelerator instead of thousands of software perm24.

**Feasibility — confirmed by source:**
- Plonky3 ships `p3-sha256` whose `Sha256` hasher and `Sha256Compress` call
  **`sha2::Sha256` / `sha2::block_api::compress256` directly**
  (`sha256/src/lib.rs`). RISC0 `[patch]`es the `sha2` crate to its accelerator,
  so **both the leaf hash and the 2‑to‑1 node compress accelerate in‑guest**.
- `MerkleTreeMmcs` / `MerkleTreeHidingMmcs` are generic over `(H, C)`; the hiding
  salt path is hash‑agnostic. `SerializingHasher<Sha256>` bridges BabyBear→bytes
  (`symmetric/src/serializing_hasher.rs`). So this is a **client config swap**
  (`ValMmcs`/`HidingValMmcs` type), not a circuit rewrite.
- Keep the **challenger / Fiat‑Shamir** on Poseidon2 (it's a small fixed cost,
  and keeping it in‑field avoids re‑arguing transcript binding). Swap *only* the
  MMCS.

**Security — this is a commitment hash, not note crypto:**
- The FRI Merkle tree's sole requirement is **collision resistance** of a vector
  commitment. SHA‑256 provides it. **Note commitments, nullifiers, owner keys,
  and the accumulator stay Poseidon2 in‑field — untouched, still sound.**
- Re‑audit surface (**small–moderate**): (a) domain/serialization of BabyBear
  limbs→bytes is injective and canonical; (b) the hiding salt still yields a
  hiding commitment with byte leaves; (c) Fiat‑Shamir still binds the SHA
  commitments into the Poseidon2 transcript (it absorbs the 32‑byte roots — fine).

**Win**: this near‑*eliminates* the dominant leaf‑hash term. RISC0 SHA‑256 is a
dedicated accelerator (~hundreds of cycles per 64‑byte block incl. ecall, vs
~40–60k for a software perm24 — a **50–200× per‑hash** ratio; exact cycles/block
**not pinned here — flag as the key uncertainty**). Even at the pessimistic end,
the ~0.8 B leaf‑hash term collapses toward the challenger + constraint‑eval
floor. Realistic: `spend_verify` ~1.18 B → **~0.3–0.5 B** (**~2.5–4×**).
*Confidence: feasibility HIGH, magnitude MEDIUM.*
- **Bonus**: client cost **drops** too (ARM has hardware SHA‑256), so the phone
  budget improves — unusual for a security‑neutral change.
- **Effort**: moderate (client config + regenerate vk/image id + re‑audit).

> **Strategic note**: prototype T2.1 *before* committing to the expensive
> narrow‑trace rewrite (T2.2). If SHA‑MMCS makes the width term cheap enough,
> the narrow‑trace re‑audit may not be worth it. **One measurement decides the
> whole Tier‑2 roadmap.**

### T2.2 Narrow the trace (2756‑wide → tall‑and‑thin)

- Today the monolith is a deliberate **wide row**: 8 Poseidon2 blocks/row so a
  whole note's hashes fit one row and **every intra‑note binding is a same‑row
  column equality — "no bus needed"** (source: `monolith.rs` module doc). That
  design trades width for binding simplicity. Width 2756 is what makes each of
  the 100 query leaf‑hashes cost ~173 perm24.
- **Redesign**: 1 perm block/row, ~8× more rows (~1024 rows). Total cells
  (prover work) ≈ unchanged (8×128 ≈ 1×1024 blocks), but **committed width
  drops ~8×**, cutting both the leaf‑hash term and the width‑proportional
  constraint‑eval term. Merkle path grows only `+log₂(8)=3` levels/query
  (negligible vs 173).
- **Win**: **~2.5–3.5× on `spend_verify`** (the user's "3–10×" is optimistic;
  3–8× on the *hash term* is realistic but the challenger/FRI‑fold floor caps
  the end‑to‑end multiplier). Stacks *partially* with T2.1 (both target leaf
  hashing → shared floor) but **fully** on the constraint‑eval term.
  *Confidence: medium.*
- **Cost — this is the big re‑audit:**
  - The same‑row equalities become **cross‑row bindings** → you must introduce a
    **copy‑constraint / bus** (a logUp or grand‑product permutation argument)
    for every value currently bound by column equality (`nk`, `owner`, `rho`,
    `value`, the cm→leaf hand‑off). New committed columns (the running
    product/multiset) + **new soundness obligations** = a full binding re‑audit,
    exactly the property the current design was built to avoid.
  - **ZK mask budget** must be re‑derived — but this **eases**: the budget is
    `num_queries + O(1) OOD < random_rows = trace_height`; a taller trace has
    *more* random rows, so the inequality is easier (a point in favour).
  - Re‑audit surface: (1) bus soundness (completeness + no cross‑row forgery),
    (2) mask budget at the new height, (3) all adversarial binding tests in
    `monolith.rs` re‑derived for the new layout, (4) native/circuit agreement
    re‑checked.
- **Effort**: high (circuit rewrite + soundness re‑audit + oracle re‑vectoring).

---

## Tier 3 — architecture / parked

- **Multi‑GPU cluster / Bonsai‑style distributed proving**: near‑linear in
  #GPUs beyond a single box. Parked (infra), but the cleanest path past
  single‑GPU limits. (Distinct from T0.2's single‑box multi‑card.)
- **Batch N withdrawals per epoch proof**: `spend_verify` is per‑withdrawal
  (1.18 B each), but `vk_setup` (66 M), tree_transition, and RISC0 fixed/
  continuation overhead amortize across the batch. **Throughput lever, not
  latency** — settle many peg‑outs in one receipt. Modest per‑withdrawal;
  meaningful for a busy epoch.
- **RISC0 version bump beyond 3.0.5**: current line is 3.0.x (latest ~3.0.4/3.0.5
  per crates.io; no dramatically faster major surfaced). **Compat gate**: a
  prover/r0vm bump can change the recursion circuit **control root**, which the
  devnet `verifyStark` verifier pins — a bump requires re‑pinning that control
  root and re‑checking the succinct‑receipt format (`bincode(InnerReceipt)` +
  journal + image id) is still accepted. Monitor the changelog; treat as gated,
  not free.
- **RISC0 `join`/recursion to compress**: *increases* prove time (it's a
  size/verify‑cost lever). **Not a speedup** — noted to rule it out.
- **Keccak instead of SHA for the MMCS**: RISC0 has a keccak circuit too, but
  SHA‑256 is the pervasive native accelerator with lower fixed overhead — prefer
  SHA (T2.1). Keccak only if a byte‑layout reason emerges.

---

## Stacked estimate (honest, with the overlaps counted)

Cycles (epoch‑independent core; grounded arithmetic on estimated fractions):

| After | spend_verify | total cyc | vs 1.93 B |
|---|---:|---:|---:|
| baseline | 1.18 B | 1.93 B | 1.0× |
| +T1.1 vk bake | 1.18 B | 1.86 B | 1.04× |
| +T1.2 query rebalance (Q≈61) | ~0.88 B | ~1.5 B | ~1.3× |
| +T2.1 SHA‑MMCS | ~0.35 B | ~0.9 B | ~2.1× |
| +T2.2 narrow trace | ~0.25 B | ~0.75 B | ~2.6× |

Wall‑clock (cycles × the Tier‑0 PO2/occupancy factor, single GPU):

- 63.5 min → **T0 (free GPU + PO2 21/22): ~40–48 min** (same cycles).
- → **+ Tier 1: ~30–37 min**.
- → **+ T2.1 SHA‑MMCS: ~15–22 min** (the biggest single step).
- → **+ T2.2 narrow trace: ~10–15 min**.
- → **+ Tier 3 multi‑GPU: ~5–8 min** (conditional on hardware).

**Realistic landing: 63.5 min → ~10–15 min single‑GPU (Tiers 0–2), with a path
to ~5–8 min with multi‑GPU.** The wildcard is T2.1: if RISC0's SHA accelerator is
at the cheap end of the cited range, it alone could push single‑GPU under
~12 min and make T2.2 optional.

**Grounded vs guessed**: *Grounded* — the 2756 width, the FRI params + soundness
formulas, the PO2→segment arithmetic, SHA‑MMCS feasibility (source‑confirmed),
the query↔security relationship. *Estimates* — the leaf‑hash fraction of
`spend_verify` (~60–75 %), per‑perm24 guest cycles, RISC0 SHA cycles/block, PO2
VRAM curve, and every wall‑clock number (they inherit the fraction estimates).
The one measurement that would harden everything: instrument a single guest run
to attribute `spend_verify` cycles between leaf‑hashing, path‑compress,
constraint‑eval, and challenger.

## Recommended order

1. **T0.1** free the GPU + PO2 21/22 — zero risk, immediate ~1.4×, **re‑measure**
   (recalibrates all downstream numbers).
2. **T1.1** bake the vk commitment — trivial, ~3 %.
3. **T2.1 SHA‑256 MMCS — prototype early** (out of tier order on purpose): a
   config swap + small re‑audit, highest upside, *lowers* client cost. **Its
   measured guest delta decides whether T2.2 is even needed.**
4. **T1.2** FRI query rebalance (blowup 4 / pow 24 / Q≈61) — one‑line param
   change + client grind + soundness‑regression test; stacks cleanly.
5. **T2.2 narrow trace** — only if 1–4 miss the target; biggest re‑audit
   (cross‑row bus + binding re‑audit + mask‑budget re‑derivation).
6. **Tier 3** multi‑GPU / batching / version bump — infra + gated, parked.

## Security bottom line

Nothing here weakens soundness: Tier 0 and T1.1 are security‑neutral; T1.2 is a
*rebalance* at constant soundness bits (re‑verified against `p3-security`); T2.1
swaps a commitment hash whose only requirement is collision resistance (note
crypto untouched); T2.2 preserves the binding argument but re‑bases it onto a bus
(the real audit cost, and the reason it's last). Both value gates from the
project memory still stand: external crypto review before REAL USE (testnet is
free), and mainnet params fixed at cut.

---

## ADOPTED (2026-07-19) — productionized on `feat/prover-speed-productionize`

The measured levers are now shipped and a fresh **v5** fast chain was cut on them.
This section records what landed vs the plan above.

### Levers adopted

- **T2.1 SHA-256 FRI-Merkle MMCS** (`ef987b6`). The client proof's FRI-Merkle
  commitment hash is SHA-256 (`p3-sha256`: `SerializingHasher<Sha256>` leaf,
  `Sha256Compress` node) for both the base and hiding config; the guest verifies
  the openings on RISC0's SHA accelerator (guest `[patch.crates-io] sha2` →
  `sha2-v0.11.0-risczero.0`). Note crypto (commitments/nullifiers/keys/
  accumulator) stays Poseidon2 in-field, UNCHANGED. The Fiat-Shamir challenger
  necessarily moved to `SerializingChallenger32<_, HashChallenger<u8, Sha256,
  32>>` — the prototype's finding that `DuplexChallenger` cannot observe 32-byte
  SHA roots (required + sound; SHA transcript is a standard random-oracle FS).
  All 72 engine client tests pass.

- **T1.1 vk-bake** (`fb91bea`). The spend vk is baked as ELF constants
  (`aegis_engine::spend::baked_vk`) instead of `setup_preprocessed` in-guest.
  Security-neutral (the pin moves from recompute to hard-coded-in-imaged-ELF);
  held honest by two tests — an engine oracle-parity test (baked == derived vk
  for the pinned salt) and a wallet test (wallet-derived vk == baked settlement
  vk).

- **T1.2 FRI query↔blowup rebalance** (`802529d`). Adopted **log_blowup 3,
  67 queries, 16-bit query PoW** (was blowup 2 / Q100 / pow16), verified at
  **constant-or-better soundness in BOTH regimes** against the vendored
  `p3-security` oracle (dev-dep):

  | params           | conjectured (2025/2010) | proven composite (2024/1553 + 2025/2055) |
  |------------------|------------------------:|------------------------------------------:|
  | lb2 Q100 pow16   | 212.0 bits              | 96.5 bits                                 |
  | **lb3 Q67 pow16**| **213.6 bits**          | **97.2 bits**  ← adopted                  |

  Both regimes improve; the proven bound binds on the batch-combination term in
  the list-decoding regime. A soundness-regression test pins the adopted params
  ≥ the ZK baseline in both regimes; the ZK mask budget
  (`HIDING_NUM_QUERIES + 8 ≤ N_ROWS`) is a compile-time `const _` assertion.

- **T0.1 PO2** — settlement proved on the freed GPU (RTX 3090) via the
  `~/apps/risc0-cuda` container.

- **Independent cross-validation**: a parallel review agent
  (`feat/prover-speed-sha-mmcs`) converged on a **byte-identical baked vk** and
  **identical FRI params** — strong agreement on the two security-sensitive
  numbers.

Deferred as planned: **T2.2 narrow-trace** (not needed — SHA-MMCS already
collapsed the width term) and any soundness-lowering change.

### Measured guest cycles (RISC0 `execute`, smoke statement, epoch = 3)

| phase            | baseline (Poseidon2) | v5 (SHA-MMCS + vk-bake + FRI-rebalance) | ratio     |
|------------------|---------------------:|----------------------------------------:|----------:|
| `vk_setup`       |           65,942,386 |                                     312 | ~baked out|
| **`spend_verify`**|      1,183,174,204 |                             287,574,580 | **4.11×** |
| `tree_transition`|            4,371,282 |                               4,370,660 | 1.0×      |
| **total user cyc**|        1,435,968,320 |                             420,296,792 | **3.42×** |
| segments         |                 1433 |                                     424 | 3.38×     |

The FRI rebalance cut `spend_verify` a further 1.47× beyond the SHA-only
prototype (424M → 288M); vk-bake collapsed `vk_setup` to 312 cycles.

### v5 chain / settlement parameters

- **chain-id** `0x484E_0005` (v5 SHA-MMCS fast-settlement cut).
- **settlement image id** `b8f0b3f91eea737099da13c39e02dd9f8fde068d0b151d77c04b7584c4f7b09f`
  (was v4 `b168fc63…`; the SHA/vk/FRI changes change the guest ELF, pinned in
  `settlement/IMAGE_ID.hex`, reproduced by the container build).

### Confirming round-trip on the v5 fast chain (GPU, real wall-clock)

A full trustless round-trip on the freshly-cut v5 chain
(`~/apps/aegis-testnet-hn`, 2 nodes, merge-mined vs the STARK devnet @19099):

deposit → peg-in mint → shielded hop → peg-out → seal epoch → **GPU settle** →
verify → release accepted by devnet `verifyStark`.

- **Settlement wall-clock: 1175.9 s ≈ 19.6 min** (RTX 3090, `~/apps/risc0-cuda`
  container, real RISC0 succinct prove). **vs the old 63.5 min → 3.24× faster.**
  This run used the RISC0 **default segment PO2** (614 segments); it was NOT the
  PO2=21/22 headline run — with the GPU freed and PO2 raised, the plan's Tier-0
  factor applies on top. Epoch = 278 leaves (pre-leaves 21, sealed_tip 291);
  user_cycles 612,277,489 / total_cycles 643,825,664 (the epoch's O(278)
  `tree_transition` accounts for the delta above the smoke's 420M).
- **Release accepted by the devnet `verifyStark` (0xB9)** — release tx
  `12ff7e2f1f5365fb707e6d1846b21350818c24d5b8434fdfd24a23583744d86a`
  (224 KB chunked proof in the input's context extension); 5000 USE released to
  the recipient. Journal `new_root =
  2af6fd766c64bc765b9ac6584c3d8348da4c7b1e0eebe915dc1230471a909829`.

### v5 deployment (for the record)

- chain-id `0x484E_0005`; image id `b8f0b3f9…c4f7b09f`.
- NFT `0000e30c…305b1a`, USE token `0000e7d8…6a8ebd49`.
- PegVault box `85e48a23…285a4c82` (R4 = deploy-boundary root
  `bdadbf61…47b7600a` at hn height 20; funded 100 000 USE).
- Round-trip flow: peg-in 3 deposits (alice 2×5000, bob 3000) → mints
  (4950/4950/2970) → hop alice→bob 4000 → bob peg-out 5000 (+50 peg fee) →
  settle prev_height 20 / sealed_tip 291.
