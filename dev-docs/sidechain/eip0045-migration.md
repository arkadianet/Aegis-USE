# EIP-0045 `verifyStark` migration tracker (5-child → 4-child stock-RISC0 profile)

Status: **PREPARE + TRACK** — the EIP is not activated. Nothing here is cut over yet.
Do **not** modify the opcode, guests, bridge-tools, vault, or the node until item 1
(the Rust node opcode) is ready to cut over with the rest. The four consensus-coupled
parts migrate **together**.

Source of truth for the target interface: the migration brief
(`c9bd4897-AEGISEIP0045MIGRATIONBRIEF.md`). Reference impl: sigmastate PR #1116
(`a-shannon/sigmastate-interpreter@eip-0045-stark-verifier`) — not reachable from this
environment; all target-state claims below are grounded in the brief, all current-state
claims in `file:line` from the live tree.

---

## 0. Which path is live (epoch vs legacy) — RESOLVED: EPOCH (`AEGISPV1`)

The consolidated main runs the **v6/v7 EPOCH** settlement path, not the legacy single
(`AEGISPO3`) path. Evidence:

- Active guest: `settlement/methods/guest-epoch/src/main.rs:1` — "Stage-T epoch-validity
  settlement guest (v7, AEGISPV1)"; journals the exact `AEGISPV1` bytes (line ~18).
- Active journal: `engine/src/epoch/mod.rs:48` `EPOCH_JOURNAL_TAG = b"AEGISPV1"`;
  `epoch_journal()` at `engine/src/epoch/mod.rs:57`.
- Active vault predicate: `bridge-tools/src/vault_epoch.rs` (the R4/R6/R7 register chain +
  E4 anchor splice).
- Active prover/transport: `settlement/exec-epoch/src/main.rs:10-12` — "writes the exact
  receipt shape the devnet `verifyStark` consumes … the artifacts the v6 [path uses]".
- Git history: `8f78e1e merge(v6): land the v6 sidechain … on main`, `668c021 docs(hardening):
  … F1-F3+F6+F5 anti-fabrication CLOSED … cut-safe`.

The legacy path (`vault.rs` `AEGISPO3`, `guest-settlement`, `settlement/host`) still
compiles and is exported (`bridge-tools/src/lib.rs:9 pub mod vault;`), and one vestigial
CLI seam still points at it (see the note below). The migration targets the **EPOCH**
path. The legacy path should be treated as dead and either migrated in lockstep or removed
at the cut; it is not the settlement flow.

> **Loose end (not a migration item, worth fixing at the cut):** the `bridge-tools` CLI
> `Release` subcommand still calls the **legacy** `txbuild::build_release` (single-
> withdrawal, `vault::` / `AEGISPO3`) at `bridge-tools/src/main.rs:377`, while the epoch
> release builder `txbuild::build_release_epoch` (`bridge-tools/src/txbuild.rs:308`) has
> **no CLI caller**. The epoch release tx is currently only reachable programmatically /
> via tests. Wire the CLI to `build_release_epoch` (or delete the legacy `Release` arm) so
> the operator-facing path matches the consolidated design.

---

## 1. SECURITY INVARIANT VERDICT — PegVault root chain: **PASS** (epoch path)

Aegis's replay protection is rollup-style **root chaining**, not "proof valid → pay". The
opcode itself binds no tx/box/nonce (audit finding L-1) — it delegates that to the journal
that the contract reconstructs. So the contract's root chain is the *only* thing preventing
replay/double-withdraw, and it must survive the `ErgoStatementV1` re-framing intact.

**The epoch PegVault enforces both halves of the invariant.** It does so structurally: the
contract never *parses* the journal, it *reconstructs* the only bytes it will accept from
THIS transaction's boxes/context, and `verifyStark`'s byte-exact journal comparison forces
the guest to have committed exactly those bytes (`bridge-tools/src/vault_epoch.rs:42-52`).

Mapping onto the v6 register model — `journal_expr` at `vault_epoch.rs:406-420`:

| invariant half | how it is enforced | citation |
|---|---|---|
| (a) `prev_root == current on-chain settled root` | journal field 2 is `r4_bytes(vault())` = the **spent** vault box's R4. The proof only verifies if its committed `prev_root` equals the input box's R4 = the current settled root. | `vault_epoch.rs:414` (`r4_bytes(vault()) // prev_root`) |
| (b) applying the withdrawal **advances** the root to `new_root` | journal field 3 is `r4_bytes(nv())` = the **successor** vault box's R4. Byte-exact match pins `successor.R4 == new_root`, so the next settlement reads it as ITS `prev_root`. | `vault_epoch.rs:415` (`r4_bytes(nv()) // new_root`) + design note `vault_epoch.rs:42-52` |

The same welding applies to the two auxiliary chains the epoch path adds:

- **Settled-burn set (R6):** `r6_bytes(vault())` = `settled_root_in`, `r6_bytes(nv())` =
  `settled_root_out` (`vault_epoch.rs:416-417`). Prevents re-settling an already-burned
  withdrawal (F6c all-nullifier accumulator).
- **Sealed-tip header id (R7):** `r7_bytes(vault())` = `tip_id_prev`, `r7_bytes(nv())` =
  `tip_id_new` (`vault_epoch.rs:418-419`). Chains the proven hn suffix.
- **Monotone counter (R5):** `nv.R5 == vault.R5 + n` bound both in the journal
  (`counter_next = plus(r5_long(vault()), n_long())`, `vault_epoch.rs:407`) and structurally
  (`vault_epoch.rs:451`), with `1 <= n <= MAX_BATCH` (`vault_epoch.rs:451`, `MAX_BATCH = 16`).
- **NFT singleton chain:** vault and successor each carry exactly `(NFT, 1)` and
  `nv.propositionBytes == vault.propositionBytes` (`vault_epoch.rs:443-449`), so the chain
  cannot fork or escape the predicate.

**Conclusion:** the root chain is present and correct on the live (epoch) path. This is NOT
a replay hole. The migration must **preserve** this reconstruct-and-compare structure — the
same register reads must feed the reconstructed `applicationPayload` after re-framing (see §4).

> For comparison, the legacy `vault.rs` enforces the same shape with a single root chain:
> `journal = TAG ‖ vault.R4 ‖ nv.R4 ‖ …` (`vault.rs:10`, `:202-208`), `nv.R5 == vault.R5 + 1`
> (`vault.rs:234`). Same invariant, one root instead of three. Also a PASS, but not the live path.

---

## 2. Current-vs-target delta — the five coupled changes (mapped to the EPOCH path)

### (1) Rust node opcode `eval_verify_stark` — 5-child → 4-child

- **Now:** `ergo-sigma/src/evaluator/opcodes/sigma.rs:244` `eval_verify_stark(proof_chunks,
  public_inputs, image_id, vm_type, cost_params, cx)` — **5 children**. Script-declared
  cost: `costParams = [Q, D]` drives the AOT charge (`sigma.rs:262-293`); `vmType` selects
  the prover (`sigma.rs:253-261`, `387-392`, only `3 => v3_0` supported). The real verify
  (`verify_stark_risc0`, `sigma.rs:370`) bincode-deserializes an `InnerReceipt`
  (`sigma.rs:377`) and treats `public_inputs` as a **free-form journal** (`Journal::new`,
  `sigma.rs:382`) with no `ErgoStatementV1` framing and no claim==expected check beyond
  RISC0's own imageId binding. Cost is `BASE(150_000) + Q*50 + Q*D*10` (`sigma.rs:231-235`,
  `286-292`) — script-influenced.
- **Target (brief §"Opcode ABI", §"Statement binding", §"Cost"):**
  `verifyStark(proofChunks, applicationPayload, programId, profileId)` — **4 children**. No
  `vmType`, no `costParams` (both collapse into the immutable `profileId`, which owns crypto
  predicate + fixed cost). Host-side: reconstruct `ErgoStatementV1` (§3) from
  `chainDomainId` (authenticated context), `profileId`, `programId`, `contractId =
  BLAKE2b-256(SELF.propositionBytes)`, and `applicationPayload`; require the proof's RISC0
  claim (SHA-256 tagged struct) to equal the reconstructed statement; enforce `programId`
  against the proof's actual imageId. Fixed **prepaid** cost charged fully upfront before any
  proof-sized work; stock profile (BabyBear/Ext4/Poseidon2, `RECURSION_PO2=18`, accepts po2
  15–22). Mirror #1116 `VerifyStark.eval` / `Risc0StockProfileRuntime`.
- **Encoding change:** drop the `vmType`/`costParams` scalars and the `Payload::Five` arm;
  replace free-form `Journal::new(public_inputs)` with the 159-byte-prefixed
  `ErgoStatementV1` reconstruction + claim-equality gate; replace the `InnerReceipt` bincode
  decode with the exact-size raw-seal decoder (§(2)). *(Read-only node repo; do not edit.)*

### (2) bridge-tools / prover proof transport — bincode `InnerReceipt` → raw 222,668-byte seal

- **Now:** the prover serializes the **bincode `InnerReceipt`**:
  `settlement/exec-epoch/src/main.rs:188` `bincode::serialize(&receipt.inner)` →
  `receipt_inner.bin` (`:189`); the legacy prover does the identical thing at
  `settlement/host/src/main.rs:282`. bridge-tools then reads that file and chunks it into the
  context-extension var: `vault_epoch::chunk_proof` (`vault_epoch.rs:508-517`) splits at
  **60,000-byte** boundaries into `Coll[Coll[Byte]]`. The release tx builder calls it at
  `txbuild.rs:326` (epoch) / `txbuild.rs:240` (legacy, via `vault::chunk_proof`).
- **Target (brief §"Proof transport"):** emit the **exact 222,668-byte raw succinct seal**
  (55,667 BabyBear words) in the **four canonical chunks `[65535, 65535, 65535, 26063]`**.
  The bincode wrapper and the generic control-inclusion proof are NOT consensus inputs. Decode
  is exact-size, canonical, fail-closed.
- **Encoding change:** two edits, together —
  1. prover: stop writing `bincode::serialize(&receipt.inner)`; extract and write the raw
     seal bytes (the 55,667-word BabyBear succinct seal) — `exec-epoch/src/main.rs:183-189`.
  2. transport: change `chunk_proof` from `chunks(60_000)` to the fixed
     `[65535, 65535, 65535, 26063]` partition and assert total == 222,668
     (`vault_epoch.rs:508-517`; also `vault.rs` if legacy is kept). The node-side reassembly
     in `eval_verify_stark` (`sigma.rs:326-337`) concatenates chunks in order, so the
     partition is purely a chunking convention — but the decoder now demands the exact size.

### (3) Active guest journal (`guest-epoch`) — commit `ErgoStatementV1`, `AEGISPV1` as payload

- **Now:** `guest-epoch/src/main.rs` builds and commits the **bare `AEGISPV1` journal** via
  `epoch_journal(...)` (`engine/src/epoch/mod.rs:57`), i.e. `env::commit`s the raw
  `AEGISPV1 ‖ prev_root ‖ new_root ‖ settled_root_in ‖ settled_root_out ‖ tip_id_prev ‖
  tip_id_new ‖ ergo_ref_id ‖ counter_next ‖ entries` bytes as the free-form journal. No
  `ErgoStatementV1` framing.
- **Target (brief §migration-item-3):** the guest must commit the **`ErgoStatementV1` bytes**
  as its journal, with the existing `AEGISPV1` journal placed **verbatim as the
  `applicationPayload`** inside the 159-byte-prefixed structure (§3). The guest gains four new
  inputs to build the framing: `chainDomainId`, `profileId`, `programId`, `contractId`.
- **Encoding change:** the guest keeps `epoch_journal(...)` unchanged (it becomes the payload)
  and wraps it: `journal = ErgoStatementV1(tag, 0x01, chainDomainId, profileId, programId,
  contractId, u32le(payload.len), payload=epoch_journal_bytes)`. Because the AEGISPV1 bytes are
  unchanged *content*, all of Aegis's binding (prev_root/new_root/R6/R7/anchor/economics) is
  preserved — only the surrounding frame is new. `contractId = BLAKE2b-256(vault
  propositionBytes)` ties the proof to THIS vault (this is new binding the epoch path did not
  have; it strengthens L-1). Note the guest already pins `AggParams::default()` and the image
  id (`vault_epoch.rs:102-118`); `programId` must equal that pinned image id.

### (4) PegVault contract (`vault_epoch.rs`) — 4-child call, reconstruct `applicationPayload`, PRESERVE root chain

- **Now:** `vault_body` emits the **5-child** `verifyStark` via `Payload::Five(proof_chunks,
  journal_expr, image_id, VM_TYPE_RISC0=3, cost_params=[35,16])` at `vault_epoch.rs:469-478`.
  `journal_expr` (`vault_epoch.rs:406`) reconstructs the bare `AEGISPV1` journal from the box
  registers/context.
- **Target (brief §migration-item-4):** emit the **4-child** `verifyStark(proofChunks,
  applicationPayload, programId, profileId)`. `applicationPayload` = exactly today's
  `journal_expr` output (the reconstructed `AEGISPV1` bytes). `programId` = the pinned image
  id (today's `spec.image_id`, `vault_epoch.rs:129`). `profileId` = the stock profile id
  constant (§(5)). Drop `VM_TYPE_RISC0` and `COST_PARAMS` (`vault_epoch.rs:97-100`). The host
  reconstructs the 159-byte prefix and prepends it; the contract does **not** build the prefix
  (it can't produce `chainDomainId`), it only supplies `applicationPayload` + the two ids.
- **Encoding change:** `Payload::Five(...)` → a 4-arg `verifyStark` payload
  `(proof_chunks, journal_expr(tag), programId=c_bytes(image_id), profileId=c_bytes(STOCK_PROFILE_ID))`.
  **Root chain preserved:** `journal_expr` is unchanged — the same `r4_bytes(vault())` /
  `r4_bytes(nv())` / R6 / R7 register reads (`vault_epoch.rs:414-419`) still feed the payload,
  so the invariant in §1 survives verbatim. This is the load-bearing constraint of the whole
  migration: the payload bytes must not change, or replay protection breaks.
- **Cross-check:** the tree must still fit `MaxPropositionBytes` (< 4096, `vault_epoch.rs:72`).
  Dropping two scalar children (an Int and a Coll[Int]) *shrinks* the tree slightly, so no
  budget risk; re-run `vault_tree_fits_proposition_budget` at the cut.

### (5) Profile wiring — stock `profileId`, po2 15–22, immutable fixed cost

- **Now:** `vmType = 3` + `costParams = [35, 16]` scattered across `vault_epoch.rs:97-100`,
  `vault.rs:49-53`, and node cost constants `sigma.rs:231-235`. The verifier hard-codes the
  RISC0 v3.0 profile (`sigma.rs:390`).
- **Target (brief §"Profile constants"):** a single immutable **stock RISC0 succinct profile
  id** everywhere (risc0-zkp 3.0.4 / risc0-circuit-recursion 4.0.4; BabyBear/Ext4/Poseidon2;
  `RECURSION_PO2=18`, accepts po2 15–22; Q=50; control root
  `a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56`; inner root over 27
  recursion control IDs, 10 terminal IDs; 12,359-op recursion constraint table). Fixed prepaid
  cost owned by the profile.
- **Encoding change:** introduce a `STOCK_PROFILE_ID: [u8; 32]` constant (shared engine/guest/
  vault so they cannot drift, like `EPOCH_JOURNAL_TAG` at `engine/src/epoch/mod.rs:48`); pass
  it as the 4th `verifyStark` child; delete `VM_TYPE_RISC0` / `COST_PARAMS`; on the node,
  replace the `BASE+Q*..+Q*D*..` cost with the profile's immutable fixed charge and gate on
  `profileId` instead of `vmType`.

---

## 3. `ErgoStatementV1` framing mapping (Aegis journal → `applicationPayload`)

The target statement (brief §"Statement binding"). Prefix length arithmetic **confirmed**:

```
26 (tag) + 1 (ver) + 32 (chainDomainId) + 32 (profileId) + 32 (programId)
   + 32 (contractId) + 4 (u32le payload len) = 159 bytes.
```
(26+1=27; +32=59; +32=91; +32=123; +32=155; +4 = **159**.)

Byte layout — Aegis's *current* `AEGISPV1` journal drops in as `applicationPayload` unchanged:

```
ErgoStatementV1
├─ offset   0 ..  26  ASCII "Ergo.VerifyStark.Statement"   (26)  domain tag (host)
├─ offset  26 ..  27  0x01                                 ( 1)  version   (host)
├─ offset  27 ..  59  chainDomainId                        (32)  Ergo genesis/domain (host, authenticated context)
├─ offset  59 ..  91  profileId                            (32)  stock profile id   (host/const)
├─ offset  91 .. 123  programId                            (32)  guest image id, == pinned EPOCH_IMAGE_ID (host, ==RISC0 claim)
├─ offset 123 .. 155  contractId = BLAKE2b-256(SELF.propositionBytes)  (32)  (host, non-spoofable)
├─ offset 155 .. 159  u32le(payload.length)                ( 4)  == len(applicationPayload)
└─ offset 159 ..  N   applicationPayload  ◄── AEGIS'S AEGISPV1 JOURNAL, VERBATIM ─────────┐
                                                                                           │
   applicationPayload (== engine/src/epoch/mod.rs:57 epoch_journal, byte-for-byte):        │
   ┌────────────────────────────────────────────────────────────────────────────────────┐│
   │  "AEGISPV1"            (8)   tag           engine/src/epoch/mod.rs:65                 ││
   │  prev_root            (32)   R4 in         :66   ◄─ ROOT CHAIN (a): == vault.R4       ││
   │  new_root             (32)   R4 out        :67   ◄─ ROOT CHAIN (b): == successor.R4   ││
   │  settled_root_in      (32)   R6 in         :68                                        ││
   │  settled_root_out     (32)   R6 out        :69                                        ││
   │  tip_id_prev          (32)   R7 in         :70                                        ││
   │  tip_id_new           (32)   R7 out        :71                                        ││
   │  ergo_ref_id          (32)   E4 anchor     :72   (CONTEXT.headers(0).id splice)       ││
   │  counter_next_be       (8)   R5+n          :73                                        ││
   │  [ amount_be(8) ‖ prop_len_be(8) ‖ recipient_prop ] × N   entries   :74-78            ││
   └────────────────────────────────────────────────────────────────────────────────────┘│
                                                                                           ┘
```

Key point: **the payload bytes are identical to today's journal.** The guest already
produces them (`epoch_journal`), the contract already reconstructs them (`journal_expr`,
`vault_epoch.rs:406`). Migration only wraps them in the 159-byte prefix on both sides.
Because the payload is unchanged, the §1 root chain (prev_root==R4_in, new_root==R4_out) is
carried through byte-identically — the re-framing cannot silently drop it. The *new* binding
the frame adds — `contractId = BLAKE2b-256(vault propositionBytes)` and host `chainDomainId`
— is strictly additional (it fixes L-1's "opcode binds no box" at the statement level).

---

## 4. Sequencing / boundaries

The four consensus-coupled parts — **(1) node opcode, (3) guest journal, (2) transport,
(4) vault contract** — MUST cut over in the SAME transaction/deploy. A mismatch is
fail-closed but total: if any one side frames differently, `verifyStark` returns `false`
and no withdrawal settles (funds are safe, bridge is stuck).

Ordered checklist for the cut (do NOT start until the EIP finalizes its profile boundary /
activation package — brief §"Boundaries"):

1. [ ] EIP-0045 activation package + stock `profileId` / control-root constants finalized
       upstream (a-shannon). **Blocking dependency — track it.**
2. [ ] Node opcode rewritten to 4-child + `ErgoStatementV1` + raw-seal decoder + fixed cost
       (`ergo` repo, `feat/eip-0045-stark`; separate PR, not this repo). Item (1).
3. [ ] Shared `STOCK_PROFILE_ID` + `ChainDomainId` source constant added (engine). Item (5).
4. [ ] Guest wraps `epoch_journal` in `ErgoStatementV1` (new inputs). Re-pin
       `EPOCH_IMAGE_ID.hex` (image id changes when the guest changes). Item (3).
5. [ ] Prover emits raw 222,668-byte seal; `chunk_proof` → `[65535,65535,65535,26063]`.
       Item (2).
6. [ ] `vault_epoch.rs` → 4-child call; re-derive vault address (tree bytes change → new P2S
       → re-pin `PINNED_VAULT_TREE_BYTES` / `contractId` in the guest, F3). Item (4).
7. [ ] Re-run oracle tests (`tests/epoch_vault_predicate.rs`), size gate
       (`vault_tree_fits_proposition_budget`), full e2e on a fresh devnet chain (chain-id-
       breaking is free on devnet). Only then retire the old-interface devnet.
8. [ ] Wire the CLI `Release` arm to `build_release_epoch` (or delete legacy) — the §0 loose end.

Until then: **the working devnet stays on the 5-child interface.** Do not partially migrate.

---

## 5. Open questions for the EIP author (a-shannon)

1. **`chainDomainId` source & value.** What exactly is the 32-byte `chainDomainId` — Ergo
   mainnet genesis header id? A domain-separation constant? For Aegis it must be a fixed,
   host-supplied, non-spoofable value. What does a **merge-mined sidechain / devnet** supply
   here — the Ergo chain it's anchored to, or its own? This directly affects the E4 anchor
   design (`vault_epoch.rs:54-67`), which already reads `CONTEXT.headers` from the Ergo chain.
2. **`contractId` hash.** Confirm `contractId = BLAKE2b-256(SELF.propositionBytes)` uses the
   *spending* input's propositionBytes (our vault at `INPUTS(0)`), and that a P2S vault tree
   (version-0, sizeless, constants inline — `vault_epoch.rs:484-492`) hashes the bytes the
   contract expects. Any ErgoTree-header normalization before hashing?
3. **Raw seal extraction API.** What is the exact call that yields the 222,668-byte raw
   succinct seal from a risc0 3.0.4 succinct receipt (vs `bincode::serialize(&receipt.inner)`
   today)? Confirm the `[65535,65535,65535,26063]` partition is the canonical one the decoder
   expects and that word-vs-byte ordering matches.
4. **po2 window vs Aegis proving.** Aegis currently proves at a specific PO2 (see the PO2-env
   finding — some runs were PO2=20 not 21). Confirm any AEGISPV1 epoch proof landing in po2
   15–22 with `RECURSION_PO2=18` normal-lift is accepted, and that `AggParams::default()`
   (the recursion tower, `vault_epoch.rs:102-118`) is compatible with the stock profile's
   inner root (27 recursion / 10 terminal control IDs).
5. **~95-bit composed soundness — documented decision input.** The brief states the profile is
   ~95 bits composed (conjectured/model-dependent, below 128). For a real-value bridge this is
   a **risk-acceptance decision**, not a bug — but Aegis should record it and decide whether a
   value cap / additional economic bound is warranted at the mainnet cut. Is a higher-security
   profile on the roadmap, or is 95-bit the intended mainnet floor?
6. **Fixed cost calibration.** The immutable prepaid charge is calibrated by the EIP author
   (~11.8 ms Rust / ~59–65 ms JVM). Our node constant is provisional 150k JIT
   (`sigma.rs:231`, undercharges relative to the brief's earlier "12–30× underpriced" note).
   Publish the final per-profile fixed cost so we replace the `BASE+Q*..` model exactly.
7. **Multi-withdrawal in one statement.** Aegis settles N≤16 withdrawals per epoch release
   (entries list in the payload). The `ErgoStatementV1` `applicationPayload` is opaque/variable
   to the opcode, so this should be fine — confirm there is no implicit payload-size cap in the
   profile beyond the tx/block size limits.

---

## Appendix — file:line index (current tree, for the cut)

| item | file:line |
|---|---|
| node opcode `eval_verify_stark` (5-child) | `ergo` repo `ergo-sigma/src/evaluator/opcodes/sigma.rs:244` |
| node real verify (bincode InnerReceipt) | `…/sigma.rs:370-394` (decode `:377`, journal `:382`, v3_0 `:390`) |
| node cost constants | `…/sigma.rs:231-235`, AOT charge `:286-293` |
| epoch vault predicate, 5-child call | `bridge-tools/src/vault_epoch.rs:469-478` |
| epoch vault journal reconstruction | `bridge-tools/src/vault_epoch.rs:406-420` |
| root chain (a) prev_root == vault.R4 | `bridge-tools/src/vault_epoch.rs:414` |
| root chain (b) new_root == successor.R4 | `bridge-tools/src/vault_epoch.rs:415` |
| R6 / R7 / R5 chains | `bridge-tools/src/vault_epoch.rs:416-419`, `:407`, `:451` |
| vmType / costParams constants | `bridge-tools/src/vault_epoch.rs:97-100` |
| `chunk_proof` (60k chunks) | `bridge-tools/src/vault_epoch.rs:508-517` |
| pinned image id | `bridge-tools/src/vault_epoch.rs:102-118`, `EPOCH_IMAGE_ID.hex` |
| epoch guest (AEGISPV1) | `settlement/methods/guest-epoch/src/main.rs:1-80` |
| epoch journal builder | `engine/src/epoch/mod.rs:48`, `:57-80` |
| prover bincode seal (epoch) | `settlement/exec-epoch/src/main.rs:188-189` |
| prover bincode seal (legacy) | `settlement/host/src/main.rs:282-283` |
| epoch release tx builder | `bridge-tools/src/txbuild.rs:308` |
| CLI Release → legacy builder (loose end) | `bridge-tools/src/main.rs:377` |
| legacy vault (AEGISPO3, comparison) | `bridge-tools/src/vault.rs:47`, `:202-208`, `:234` |
