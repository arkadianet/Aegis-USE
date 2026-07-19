# RISC0 version bump — decision plan (settlement stack)

Scoped 2026-07-19. READ-ONLY research; no code changed, no builds run (GPU
campaign live). Decision-support for bumping the RISC0 prover under the Aegis
settlement guest, coordinated with the devnet ergo node's `verifyStark`
(EIP-0045) verifier.

## Verdict: NO-GO — defer. Nothing to gain today, and the only meaningful
## target (5.x) is hard-blocked on the verifier side.

Two candidate bumps exist, and both fail the cost/benefit test:

1. **3.0.5 → 3.0.6** (latest stable, released 2026-07-17): **zero performance
   change.** The entire diff is two commits — a cargo-binstall CI bump and
   "Updates for Rust toolchain 1.97.0" (fixes guest builds using the
   `heap-embedded-alloc` feature, which our guest does not use — its features
   are `["std","getrandom"]`, `settlement/methods/guest-settlement/Cargo.toml:16`).
   Control root **verified unchanged** (see §4). A bump would churn lockfiles,
   the container tag, and possibly the pinned image id, for no benefit.
2. **3.0.x → 5.0** (next line; version jumped 3→5): potentially real prover
   speedups (new rv32im-m3 circuit, actor multi-GPU prover, CUDA streams,
   full-GPU `fri_prove`) — but **(a)** it has never shipped stable
   (`5.0.0-rc.1`, 2026-01-15, is still the only cut six months later, with an
   empty release-notes body and no published benchmark numbers), and **(b)**
   the make-or-break condition fails: **no succinct-receipt verifier for the
   5.x circuits exists in zkVerify's `risc0-verifier`** — its newest tag is
   v0.11.0 (2025-09-18, "Add support for v3.0", commit `2462689`) and the repo
   has had **zero commits since**. 5.x replaces the rv32im v2 circuit with m3
   ("Delete v2 code and merge m3 circuit crates", risc0 PR #3600), so
   supporting it in the pure-Rust verifier is a new circuit implementation,
   not just a new control-ID table. Until zkVerify (or someone) ships that,
   the devnet cannot verify 5.x receipts at all.

The real wall-clock lever remains `dev-docs/sidechain/prover-speed-plan.md`
(guest-cycle reduction — the 63.5 min proof is dominated by 1.93 B guest
cycles, which no prover-version bump touches; a prover bump only scales
seconds-per-segment).

**Re-check triggers** (either one reopens this decision):
- risc0 publishes a **stable 5.0.0** (watch
  https://github.com/risc0/risc0/releases / crates.io `risc0-zkvm`
  `max_stable_version`), **with** benchmark numbers vs 3.0.x; and
- zkVerify tags a `risc0-verifier` release whose notes say **v5.0 / m3
  support** (watch https://github.com/zkVerify/risc0-verifier/releases —
  currently dead-stopped at v0.11.0).

Both must hold before the GO plan in §6 is executable.

---

## 1. Current versions (verified on disk 2026-07-19)

### Aegis-USE (prover side)

Source: `/home/rkadias/coding/development/arkadianet/Aegis-USE/settlement/Cargo.lock`
(host) and `settlement/methods/guest-settlement/Cargo.lock` (guest — identical
risc0 resolution):

| crate | version |
|---|---|
| risc0-zkvm | **3.0.5** |
| risc0-build | 3.0.5 |
| risc0-circuit-rv32im | 4.0.4 |
| risc0-circuit-recursion | 4.0.4 |
| risc0-circuit-keccak | 4.0.5 |
| risc0-zkp / risc0-binfmt / risc0-groth16 | 3.0.4 |
| risc0-core | 3.0.1 |
| risc0-sys | 1.5.0 |
| risc0-zkvm-platform / risc0-zkos-v1compat | 2.2.2 |
| bincode (receipt codec) | 1.3.3 |

- Manifests pin `^3.0.5` (`settlement/host/Cargo.toml:8`,
  `settlement/methods/guest-settlement/Cargo.toml:16`,
  `settlement/methods/Cargo.toml:7`).
- rzup toolchain: `r0vm`/`cargo-risczero` **3.0.5**
  (`~/.risc0/extensions/v3.0.5-cargo-risczero-x86_64-unknown-linux-gnu`).
- CUDA container: `localhost/risc0-cuda:3.0.5-cuda12.6`, base
  `nvidia/cuda:12.6.3-devel-ubuntu24.04` + gcc-13, Rust 1.95.0
  (`~/apps/risc0-cuda/Containerfile`). Path-fidelity mounts reproduce the
  host-built guest bit-for-bit — the image id in `settlement/IMAGE_ID.hex`
  (`b8f0b3f9…f7b09f`) depends on those exact paths (see build.sh header).
- Guest sha2 fork: `github.com/risc0/RustCrypto-hashes` tag
  `sha2-v0.11.0-risczero.0` (guest Cargo.toml:37).

### Devnet ergo node (verifier side)

Branch `feat/eip-0045-stark` of `arkadianet/ergo`; deployment
`~/apps/ergo-devnet-stark` (LIVE, mining from genesis — do not touch).

- Dep: `risc0-verifier = { git = "https://github.com/zkVerify/risc0-verifier",
  tag = "v0.11.0", optional = true }` — `ergo-sigma/Cargo.toml:27`, behind the
  `stark-verify` feature (`:33`). Locked to commit `2462689…`
  (root `Cargo.lock`, package `risc0-verifier 0.11.0`).
- Impl: `ergo-sigma/src/evaluator/opcodes/sigma.rs:370-394`
  (`verify_stark_risc0`). The prover-version selector is the opcode's
  `vm_type` arg: **`3 => verify(&v3_0(), vk, proof, journal)`** at
  `sigma.rs:390`; every other value returns `false` (`:391`).
- The PegVault predicate passes `vmType = 3` and the pinned `IMAGE_ID`
  (`bridge-tools/src/vault.rs:20`, doc-comment showing
  `verifyStark(…, IMAGE_ID, 3, [35,16])`).

## 2. Where the control root actually lives

**There is no control-root literal in our code.** The pin is inside zkVerify's
crate: `v3_0()` (`risc0-verifier src/lib.rs:98` → `context/v3.rs`) selects the
circuit tables in `src/circuit/v3_0/recursive/control_id.rs` —
`ALLOWED_CONTROL_IDS` (identity/join/join_povw/lift_rv32im_v2_14..22/… zkr
digests) from which the allowed control root is computed. Cached checkout:
`~/.cargo/git/checkouts/risc0-verifier-2862bc4500b5b8cc/2462689/`.

So "update the control root" concretely means: **bump the `tag =` on
`ergo-sigma/Cargo.toml:27` to a verifier release that ships the new circuit's
control-ID tables, and add the new `vm_type => vX_Y()` arm at
`sigma.rs:387-392`.** Both are verifier-crate-provided; we never hand-enter a
root digest.

## 3. Newest available (crates.io, authoritative, 2026-07-19)

- `risc0-zkvm`: `max_stable_version` **3.0.6** (2026-07-17); `max_version`
  **5.0.0-rc.1** (2026-01-14). Release history: 3.0.5 (2026-02-03), 3.0.4
  (2025-11-24), 3.0.3/3.0.1 (2025-08). There is **no 4.x zkvm line** (4.x is
  the circuit-crate numbering for the 3.x zkvm; `risc0-circuit-recursion`
  latest stable is 4.0.5, 2026-07-17, same-day metadata bump for 3.0.6).
- `zkVerify/risc0-verifier`: tags v0.1.0…**v0.11.0** only. v0.11.0 =
  2025-09-18, "Add support for v3.0 (#17)". Repo commit history ends there.
  Supported prover versions: v1.0, v1.1, v1.2, v2.0, v2.1, v2.2, v2.3, v3.0
  (`src/lib.rs:63-100`). **Nothing for 5.x.** (Not published on crates.io —
  git tags only.)

## 4. Control-root compatibility findings (verified, not guessed)

- **3.0.5 vs 3.0.6: identical control IDs.**
  `risc0/circuit/recursion/src/control_id.rs` is byte-identical at both tags
  (sha256 `6fedf46f…16cb` for both, fetched from raw.githubusercontent.com).
  The v3.0.5→v3.0.6 compare is 2 commits: CI tooling + Rust 1.97.0 toolchain
  updates — no circuit, receipt-format, or prover changes. A 3.0.6-built
  receipt would still verify under the devnet's `v3_0()`. (So a 3.0.6 bump
  needs **no** node-side change — and also delivers no benefit.)
  - Uncertainty flag: the image id would still change if the guest is rebuilt
    with a different toolchain/dep graph (image id = hash of the guest ELF,
    which embeds absolute paths and dep versions). A 3.0.6 bump is
    control-root-safe but NOT image-id-safe → still forces a vault re-pin +
    re-cut. Another reason not to bother.
- **3.0.x vs 5.x: guaranteed incompatible.** 5.0.0-rc.1 ships
  `risc0-circuit-rv32im 5.0.0-rc.1` / `risc0-circuit-recursion 5.0.0-rc.1`;
  the 214-commit v3.0.4…v5.0.0-rc.1 range includes "Initial commit for
  rv32im-m3 circuit (#3430)", "Recursion support for m3 (#3471)", "Delete v2
  code and merge m3 circuit crates (#3600)", "Implement proof of verifiable
  work (PoVW) (#3220)". New circuit ⇒ new zkr set ⇒ new control IDs/root, and
  the verifier needs the m3 verification logic itself.
- **Receipt format under 5.x: UNVERIFIED.** With edition-2024 and the m3
  merge, whether `bincode::deserialize::<InnerReceipt>` of a 5.x receipt is
  wire-compatible is unknown; assume not until tested. (The node bridge at
  `sigma.rs:377` depends on it.)

## 5. Speedup evidence (honest assessment)

- **3.0.5 → 3.0.6: none.** Release note is a single line: "Repair Rust 1.97.0
  guest build with `heap-embedded-alloc` feature." We don't use that feature.
- **3.0.x → 5.x: plausibly significant but UNQUANTIFIED.** Perf-relevant
  commits in the range: actor-based default prover replacing ExternalProver
  (#3486) with multi-GPU job scheduling (#3529), CUDA streams without
  `cudaDeviceSynchronize` (#3531), "Run all of fri_prove on the GPU" (#3542),
  dual-HAL recursion (#3527), and the m3 circuit itself (presumably fewer
  columns/cycles per instruction — no published numbers found). The
  5.0.0-rc.1 release body is EMPTY and the repo CHANGELOG.md is stale (stops
  at v1.2.1); RISC0 has published no 3.x-vs-5.x benchmark. **Do not assume a
  magnitude.** Note: the last risc0 release with *measured* perf claims was
  3.0.1 ("much faster recursion witness generation on GPU", "much faster
  Groth16 on GPU", experimental `RISC0_PROVER=actor`) — we already have all
  of that in 3.0.5.
- Context that caps the upside: our 63.5 min settlement proof is dominated by
  **guest cycle count** (1.93 B cycles, 1921 segments @ PO2=19 —
  `prover-speed-plan.md`). A prover bump improves seconds-per-segment only;
  cutting the in-guest Plonky3 verify cycles (prover-speed-plan tiers) attacks
  the 1.93 B directly and needs no consensus coordination. On a single RTX
  3090, the 5.x multi-GPU actor scheduler adds little.

## 6. The coordinated GO plan (execute ONLY when §0's two triggers hold; GPU idle)

Target = first stable 5.x (call it `5.Y.Z`) + a zkVerify `risc0-verifier`
release supporting it (call it `v0.N` with a `v5_0()`-style selector).

Ordering rule: **prover first, verifier second, cut last** — nothing consensus-
visible changes until step 6.

1. **Freeze baseline.** Record current `settlement/IMAGE_ID.hex`, a known-good
   receipt (`proof_inner.bin`/`journal.bin`/`image_id.bin` style, cf.
   `ergo/ergo-sigma/test-vectors/stark/`), and current proof wall-clock at
   PO2=19 on the 3090. Tag both repos' pre-bump commits.
2. **Aegis-USE prover bump (worktree, not main).**
   - `settlement/{host,methods,methods/guest-settlement}/Cargo.toml`:
     `^3.0.5` → `^5.Y.Z`; refresh both lockfiles.
   - `rzup install` the matching `r0vm`/`cargo-risczero 5.Y.Z` (new
     `~/.risc0/extensions/v5.Y.Z-…`).
   - Check guest sha2 fork tag still applies (risc0 may retag
     `sha2-vX-risczero.N` for the new toolchain) and whether m3 obsoletes the
     patch entirely.
   - Fix host/guest API breakage (edition 2024; prover API around the actor
     prover changed — `ExternalProver` is gone, #3486).
3. **Container rebuild.** New image tag
   `risc0-cuda:5.Y.Z-cudaXX` in `~/apps/risc0-cuda/Containerfile` +
   `build.sh` `IMAGE=`. Verify nvcc/gcc-13 still accepted (5.x added
   `-std=c++17` requirements, #3316; check whether CUDA 12.6 base is still
   supported or ≥12.8 is required). Preserve the path-fidelity mounts
   UNCHANGED (image-id reproducibility contract in build.sh header).
4. **Reproduce + measure off-node.** Build the guest → NEW `IMAGE_ID.hex`
   (expected to change; commit alongside the bump). Prove the standard
   settlement statement; record wall-clock vs step-1 baseline. **If the
   speedup is <~1.5x, abort here and re-evaluate** — the remaining steps carry
   consensus risk for the devnet.
5. **Verifier-side dry run (off-node, no ergo changes yet).** Small harness
   depending on zkVerify `risc0-verifier v0.N`: bincode-deserialize the new
   receipt, `verify(&v5_0(), new_image_id, proof, journal)` must pass, and a
   tampered byte must fail. This proves receipt-format + control-root
   compatibility BEFORE touching the node. If `InnerReceipt` bincode wire
   format changed, the node bridge (`sigma.rs:377`) needs a matching decode —
   scope that here.
6. **Devnet node bump (branch `feat/eip-0045-stark`).**
   - `ergo-sigma/Cargo.toml:27`: tag `v0.11.0` → `v0.N`.
   - `sigma.rs:387-392`: add arm `5 => verify(&v5_0(), …)`. KEEP the `3 =>
     v3_0()` arm during transition so old receipts/vectors still verify;
     drop it only after the re-cut.
   - Refresh oracle vectors: commit a new real receipt triple under
     `ergo-sigma/test-vectors/stark/` produced by the 5.Y.Z prover (oracle
     rule: never self-oracle). Re-run the 8 `verify_stark` feature tests +
     full gate in the ISOLATED target dir
     (`CARGO_TARGET_DIR=~/.cache/ergo-stark-target` — shared-cache
     Payload::Five clobbering, see memory).
   - Re-check `BASE_COST` (`sigma.rs:228-235`, 150_000 JIT calibrated to
     ~11.8 ms v3 verify): re-measure the v5 verify time; if materially
     different, recalibrate (under-cost = DoS).
7. **Redeploy devnet + re-cut.** Stop `~/apps/ergo-devnet-stark` (only when
   its current campaign role allows), rebuild `--release -p ergo-node
   --features stark-verify` in the isolated target dir, redeploy per the
   deployment README. Then the Aegis side: re-assemble the PegVault predicate
   with the NEW `IMAGE_ID` and `vmType = 5` (`bridge-tools/src/vault.rs`),
   fresh vault pin, re-cut the test chain (chain-id-breaking is free on
   testnet per project policy).
8. **End-to-end verify.** Prove one settlement with the new stack → submit the
   verifyStark tx → devnet accepts; tampered proof → rejects. Record final
   numbers.

**Rollback:** every consensus-visible change lands in step 6-7 only. If new
receipts fail on the node: revert the two-file node diff (Cargo.toml tag +
sigma.rs arm), rebuild, redeploy — old chain state is untouched because the
old `3 => v3_0()` arm was kept and the old vault pin was only replaced at the
re-cut. Pre-re-cut, the old prover worktree + container image
(`risc0-cuda:3.0.5-cuda12.6`, still in podman storage) can resume proving
immediately. Post-re-cut, rollback = re-cut again from the step-1 tags
(testnet re-cuts are free).

## 7. Blast radius summary

| Surface | 3.0.6 | 5.x |
|---|---|---|
| Control root / node change | none (verified) | new root; needs zkVerify release that DOES NOT EXIST |
| Image id / vault pin / re-cut | changes anyway (toolchain in ELF) | changes |
| Receipt bincode format | unchanged (no code diff) | UNKNOWN — verify in step 5 |
| Guest/host API | none | breaking (edition 2024, actor prover, m3) |
| Container (CUDA/gcc) | none | possible CUDA/c++17 bumps — check |
| Client Plonky3 side (`engine/`) | untouched | untouched — RISC0 appears only under `settlement/` (workspace grep); the guest re-verifies Plonky3 in-field, no risc0 dep in `engine/` |
| Cost model (`BASE_COST`) | unchanged | re-measure + recalibrate |

## Sources

- crates.io API: `risc0-zkvm` (max_stable 3.0.6 @ 2026-07-17; 5.0.0-rc.1 @
  2026-01-14), `risc0-circuit-recursion` (4.0.5 stable).
- github.com/risc0/risc0 releases API: v3.0.6/v3.0.5/v3.0.1 bodies;
  compare v3.0.5...v3.0.6 (2 commits) and v3.0.4...v5.0.0-rc.1 (214 commits,
  m3/PoVW/actor/CUDA-streams commit titles cited above).
- raw.githubusercontent risc0 `risc0/circuit/recursion/src/control_id.rs`
  @v3.0.5 and @v3.0.6 — identical sha256.
- github.com/zkVerify/risc0-verifier: tags (v0.11.0 newest), commits API
  (last commit 2025-09-18), cached checkout
  `~/.cargo/git/checkouts/risc0-verifier-2862bc4500b5b8cc/2462689/`
  (`src/lib.rs:63-100` selectors, `src/circuit/v3_0/recursive/control_id.rs`).
- Local: Aegis-USE settlement lockfiles/manifests, `~/apps/risc0-cuda/`
  Containerfile+build.sh, `~/.risc0/extensions/`,
  ergo `feat/eip-0045-stark` `ergo-sigma/Cargo.toml` + `sigma.rs`,
  `bridge-tools/src/vault.rs`, `dev-docs/sidechain/prover-speed-plan.md`.
