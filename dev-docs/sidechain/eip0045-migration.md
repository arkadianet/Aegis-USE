# EIP-0045 `verifyStark` migration tracker (5-child → 4-child stock-RISC0 profile)

Status: **PREPARE + TRACK** — the EIP is not activated. Nothing here is cut over yet.
Do **not** modify the opcode, guests, bridge-tools, vault, or the node until item 1
(the Rust node opcode) is ready to cut over with the rest. The four consensus-coupled
parts migrate **together**.

Source of truth for the target interface: **the reference implementation itself**, now
cloned locally and verified — sigmastate @ `9372697` and eips @ `777b9c2`
(a-shannon). The migration brief (`c9bd4897-AEGISEIP0045MIGRATIONBRIEF.md`) is
**secondary**: §6 below verifies every target-state claim against the actual Scala impl,
its byte-pinning KAT tests, and the EIP spec. Where the brief and the reference disagree,
the reference wins and §6 records the correction. All current-state claims are
`file:line` from the live tree; all target-state claims now cite
`sigmastate:<path>:<line>` / `eips:eip-0045.md:<section>`.

> **Verification verdict (see §6): the brief is substantially correct.** Every byte-count,
> endianness, field order, and headline constant it states is confirmed byte-for-byte
> against the KATs. The one material fix a cutover must not miss: the stock **`profileId`
> is `23c4…d383`** (a BLAKE2b-256 digest of the 458-byte profile manifest), which is a
> *different* 32-byte value from the inner control root `a54d…1f56` the brief lists — the
> two are distinct profile constants with distinct roles.

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
  proof-sized work; stock profile (BabyBear/Ext4/Poseidon2, outer/recursion po2 fixed at
  **18**, inner segment/lift po2 **15–22** — see §6 for the two-axis nuance). Mirror the
  reference `VerifyStark.eval` (`sigmastate:data/shared/src/main/scala/sigma/ast/VerifyStark.scala:37-107`)
  / `Risc0RawSealVerifier`. Confirmed 4-child order there: `proofChunks, applicationPayload,
  programId, profileId`; opcode `0xB9`; script version 4 gate; cost added as two upfront
  `FixedCost` charges (`snapshot.dispatchJit` then `active.fixedJit`) **before** any child
  is evaluated (`VerifyStark.scala:52,69`); `contractId = BLAKE2b-256(SELF.propositionBytes)`
  computed host-side (`VerifyStark.scala:95-96`).
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
- **Target (verified against the reference; see §6):** a single immutable **stock RISC0
  succinct profileId** everywhere. **The profileId is
  `23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383`** — the frozen "B3"
  value, computed as `BLAKE2b-256(ASCII("Ergo.StarkProfileId.v1") ‖ 0x00 ‖ u32le(458) ‖
  manifest[458])` (`sigmastate:core/shared/src/main/scala/sigma/stark/profile/Risc0ProfilePackageLoader.scala:178-190`;
  KAT `Risc0ProfilePackageLoaderSpec.scala:170-171`; used as the profileId in the statement
  KAT `ErgoStarkStatementSpec.scala:40-51`). This is the value that goes in the 4th
  `verifyStark` child and at statement offset 59.
  Profile crypto constants (RISC Zero SDK **3.0.5** / risc0-zkp **3.0.4** /
  risc0-circuit-recursion **4.0.4** — `eips:eip-0045/profile-v1/README.md:57-58`;
  BabyBear/Ext4/Poseidon2; outer recursion po2 **18** fixed, inner lift po2 **15–22**;
  Q=**50** FRI queries; **12,359**-op recursion constraint table; **inner control root
  `a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56`** — NOT the profileId;
  it commits to 27 upstream recursion control IDs; **10** pairwise-distinct terminal control
  IDs). Fixed prepaid cost owned by the profile (`dispatchJit + fixedJit`, final numbers
  are EIP blocker **B5** — see §5.6).
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

> **This entire layout is byte-for-byte CONFIRMED against the reference** (see §6). The
> 26-byte tag, the `0x01` version, the field order (chain→profile→program→contract), the
> `u32le` payload-length endianness, and the **159-byte** prefix all match the encoder
> `Risc0ClaimBuilder.encodeStatement` (`sigmastate:core/shared/src/main/scala/sigma/stark/profile/ErgoStarkStatement.scala:195-216`)
> and are pinned by the KAT `ErgoStarkStatementSpec.scala:11-23` (196-byte vector) and the
> offset test `:111-128`. Two facts worth carrying into the guest/opcode work:
>
> 1. **The guest commits the *whole* `ErgoStatementV1` (prefix + payload), not just the
>    payload** (`env::commit_slice(statement)`, `eips:eip-0045.md §5:312-318`). The opcode's
>    expected RISC0 claim is a SHA-256 tagged struct whose journal digest is
>    `SHA-256(ErgoStatementV1 bytes)` (`ErgoStarkStatement.scala:162,184-192`). So "commit
>    the AEGISPV1 bytes as payload" is right, but the guest's `env::commit` target is the
>    full framed statement.
> 2. **There is a hard payload cap: 16,384 bytes** (max statement 16,543), enforced both at
>    profile load and in the opcode (`payload.length > active.maxApplicationPayloadBytes →
>    false`, `VerifyStark.scala:75`; `eips:eip-0045.md:296-297`). Aegis's N≤16 entries fit
>    with wide margin, but the cut must not exceed it (resolves §5.7).

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

## 5. Open questions — resolved against the reference (sigmastate @ 9372697, eips @ 777b9c2)

The local reference resolves most of these outright. **RESOLVED** items are struck with the
answer inline; the two that remain genuinely **OPEN** are the ones a-shannon has not frozen
yet (cost numbers) or that live on the Rust prover side (exact seal-extraction call).

1. ~~**`chainDomainId` source & value.**~~ **RESOLVED.** `chainDomainId` = the raw 32 bytes
   from **Base16-decoding the height-1 genesis `Header.id`** in canonical Ergo byte order —
   not UTF-8 hex, not state digest/AVL root, not network prefix
   (`eips:eip-0045.md §4:246-249`). It is host-derived from the trusted node capability
   (`snapshot.chainDomainId`, `VerifyStark.scala:99`) and scripts MUST NOT override it
   (`eip-0045.md:261-262`). **Per-network**: each chain pins its *own* genesis id; the EIP
   assigns no generic "testnet" id (`eip-0045.md:257-259`). Ergo **mainnet =
   `b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b`** (`eip-0045.md:251-255`;
   this is exactly the `chainDomainId` used in the final-B3 statement KAT
   `ErgoStarkStatementSpec.scala:42`). *For Aegis:* the `verifyStark` box lives on the Ergo
   chain, so `chainDomainId` is the **Ergo network's** genesis id (mainnet value above; on the
   stark devnet, that devnet's own genesis id pinned in its activation package) — **not** a
   sidechain-supplied value. Consistent with the E4 anchor already reading Ergo
   `CONTEXT.headers` (`vault_epoch.rs:54-67`).
2. ~~**`contractId` hash.**~~ **RESOLVED.** `contractId = BLAKE2b-256(SELF.propositionBytes)`
   of the **spending input** (`E.context.SELF.propositionBytes`, `VerifyStark.scala:95-96`;
   `eip-0045.md §5:291`). It hashes the **raw** propositionBytes — no ErgoTree-header
   normalization (`ProfileBlake2b256` is plain BLAKE2b-256; its `abc` vector `bddd813c…` and
   an 85-byte proposition vector are KAT-pinned, `ProfileBlake2b256Spec.scala:52-64`).
   It binds the *contract*, not the box instance — so Aegis's per-box binding (root chain,
   `SELF.id`) must keep living in `applicationPayload`, which it does (`eip-0045.md:299-303`).
3. **(mostly RESOLVED)** **Raw-seal partition & word order — CONFIRMED**; the exact Rust
   extraction call is the only residual. The `[65535,65535,65535,26063]` partition is *the*
   canonical one (`RawSealV1Decoder.CanonicalChunkLengths`, every KAT uses it), total
   **222,668** bytes = **55,667** little-endian u32 words, word 32 = literal outer po2 `18`,
   even words 0..14 = inner control root (Montgomery-decoded, odd padding must be raw 0),
   words 16..31 = claim-digest u16 halfwords (`RawSealV1Decoder.scala:114-190`). What the
   Scala reference does **not** pin is the Rust risc0 3.0.5 API call that yields those 222,668
   bytes from a succinct receipt (replacing `bincode::serialize(&receipt.inner)`); that stays
   a prover-side task, but the *target bytes* are now fully specified.
4. **(mostly RESOLVED)** **po2 window — CONFIRMED 15–22; `AggParams` compat is prover-side.**
   The profile's 8 normal-lift terminal controls carry parameters `15..22` (loader:
   `FirstSegmentPo2=15 + i`, `Risc0ProfilePackageLoader.scala:35,290-297`); real seals verify
   at po2 15 and po2 16 (`Risc0RawSealVerifierE2ESpec.scala:186`, `ArkadiaIndependentRawSealKatSpec.scala:100-101`).
   Soundness is computed "at the largest accepted segment po2 22 and recursion po2 18"
   (`eip-0045-cryptographic-rationale.md:480`). So any AEGISPV1 proof landing in **15–22** is
   accepted, and Aegis's PO2=20/21 runs are inside the window. Whether `AggParams::default()`
   emits a seal in that exact shape is a Rust-prover check, not something the Scala reference
   can settle.
5. **(RESOLVED as documented decision input)** **~95-bit composed soundness.** Confirmed:
   largest accepted segment **95.30 bits**, recursion 99.76, union-bound composition **95.24
   bits**, headline "**about 95 conjectured classical bits** under that specific toy model …
   not a proven lower bound" (`eip-0045-cryptographic-rationale.md:473-489`). The EIP is
   explicit that this is an **interoperability profile, not a 128-bit custody profile**, and
   that "applications securing values that require a stronger target should not infer one from
   the opcode; a hardened future profile would need its own immutable identity…"
   (`rationale:469,504-508`). **No numeric value cap is prescribed** — so Aegis's own
   value-cap / economic-bound decision at the mainnet cut is warranted and is squarely a
   risk-acceptance call, with a hardened profile being explicit future work (a new profileId).
6. **STILL OPEN (EIP blocker B5).** The fixed prepaid charge is `dispatchJit + fixedJit`,
   both added upfront before any heavy child (`eip-0045.md §10:1216-1219`; `VerifyStark.scala:52,69`).
   `fixedJit` is a positive `u32le` inside the exactly-37-byte `CostScheduleFixedV1`
   (`eip-0045.md:619-642`); `dispatchJit` is generation-versioned in the transition manifest.
   **The final numeric values are unresolved — EIP blocker B5** ("Final `dispatchJit`,
   `fixedJit`, schedule bytes, and `scheduleId` from the completed JVM verifier",
   `eip-0045.md:27`). So our provisional `150k` node constant (`sigma.rs:231`) cannot be
   replaced with a final number yet — track B5. Mechanism is now exact; only the constant is
   pending.
7. ~~**Multi-withdrawal / payload-size cap.**~~ **RESOLVED.** There **is** a cap: the stock
   profile's `maxApplicationPayloadBytes = 16,384` (`Risc0ProfilePackageLoader.scala:34,281`),
   enforced in the opcode (`VerifyStark.scala:75`) — max statement 16,543 bytes
   (`eip-0045.md:296-297`). Aegis's N≤16 entries are far under this, so multi-withdrawal in one
   statement is fine, but the builder must guarantee the payload never crosses 16,384 bytes.

---

## 6. Reference-impl verification (sigmastate @ `9372697`, eips @ `777b9c2`)

The migration doc's target-state was grounded only in the human brief because the reference
was unreachable. It is now cloned locally and every target-state claim is checked below
against the **actual Scala impl + its byte-pinning KAT tests + the EIP spec** (ground truth),
not the brief. The KAT tests are the strongest oracle (they hard-code exact bytes).

**Bottom line: the brief is substantially correct.** Only one item is a genuine
*correction* a cutover must not miss (the profileId ≠ inner control root, top of the table);
the rest are CONFIRMED byte-for-byte, plus several previously-open questions now answered.

### 6.1 Corrections (get these wrong and the cut breaks) — sharpest first

| # | Claim in our doc / brief | Reference says | Cite |
|---|---|---|---|
| C1 | Lists control root `a54dc85a…1f56` among profile constants and leaves the 4th-child **`profileId` as an unspecified `STOCK_PROFILE_ID` constant** — the brief's "Profile constants" blurb reads as if `a54dc85a…` is the headline profile identifier. | **`a54dc85a…1f56` is the *inner control root*, not the profileId.** The **profileId** (statement offset 59, the 4th `verifyStark` child) is a **different** 32-byte value: **`23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383`**, the frozen "B3" id = `BLAKE2b-256(ASCII("Ergo.StarkProfileId.v1") ‖ 0x00 ‖ u32le(458) ‖ manifest[458])`. Pinning the wrong one in the child ⇒ profile lookup miss ⇒ `verifyStark` returns false, bridge stuck. | profileId: `Risc0ProfilePackageLoader.scala:178-190,61`; KAT `Risc0ProfilePackageLoaderSpec.scala:170-171,180`; used as profileId in `ErgoStarkStatementSpec.scala:40-51`. inner root: `profile-oracle.tsv:16`, `eips:eip-0045.md:1428-1431` |
| C2 | "`RECURSION_PO2=18`, accepts po2 15–22" (single axis). | Two distinct po2 axes: the **outer recursion po2 is fixed at 18** (raw seal word 32 must equal 18, else reject), while **15–22 is the inner *segment/lift* po2** (the 8 normal-lift terminal controls, parameters 15..22). Not wrong, but conflated — the "18" and the "15–22" are different quantities. | outer: `RawSealV1Decoder.scala:23,154-156`; lift range: `Risc0ProfilePackageLoader.scala:35,290-297`; soundness note `rationale:480` |
| C3 | §2(5) implies the fixed cost is a to-be-published single per-profile number to swap for `BASE+Q*..`. | Cost is **two** upfront `FixedCost` charges: generation-scoped `dispatchJit` **+** per-profile `fixedJit` (37-byte `CostScheduleFixedV1`), both added before any child. The **numbers are unfrozen (EIP blocker B5)** — there is no final constant to adopt yet. | `VerifyStark.scala:52,69`; `eip-0045.md:619-642,1216-1219,27` |

### 6.2 Confirmed byte-for-byte (brief was right)

| Target-state claim | Verdict | Reference (file:line / KAT) |
|---|---|---|
| Opcode is 4-child `verifyStark(proofChunks, applicationPayload, programId, profileId)`, opcode `0xB9`, script v4 gate, no `vmType`/`costParams` | CONFIRMED ✓ | `VerifyStark.scala:26-31,46,110-126`; `eip-0045.md:205-206` |
| `contractId` + `chainDomainId` are host-derived (non-spoofable), only `proofChunks/applicationPayload/programId/profileId` are script children | CONFIRMED ✓ | `VerifyStark.scala:51,71,74,77,95-99`; `eip-0045.md:267-270` |
| Statement tag = `ASCII("Ergo.VerifyStark.Statement")`, **exactly 26 bytes** | CONFIRMED ✓ (KAT hex prefix `4572676f2e566572696679537461726b2e53746174656d656e74` = 26 B) | `ErgoStarkStatement.scala:20`; `ErgoStarkStatementSpec.scala:22,119` |
| Version byte = `0x01` | CONFIRMED ✓ | `ErgoStarkStatement.scala:18,204`; KAT `:120` |
| Field order chain → profile → program → contract | CONFIRMED ✓ | `ErgoStarkStatement.scala:206-209`; offset KAT `:121-124` |
| Payload length = **`u32le`** (little-endian) | CONFIRMED ✓ (len 258 → `02 01 00 00`; 16384 → `00 40 00 00`) | `ErgoStarkStatement.scala:210,274-279`; KAT `:82,125` |
| Prefix total = **159 bytes** (26+1+32+32+32+32+4) | CONFIRMED ✓ (empty-payload statement length = 159) | `ErgoStarkStatement.scala:17`; KAT `:70` |
| BLAKE2b-256 for contractId/profileId; SHA-256 for the RISC0 tagged-struct claim | CONFIRMED ✓ (`ProfileBlake2b256("abc")=bddd813c…`; `ProfileSha256("abc")=ba7816bf…`) | `ProfileBlake2b256Spec` / `ProfileSha256Spec:9-10`; `ErgoStarkStatement.scala:185,222-244` |
| `programId` enforced == proof's actual RISC0 claim/imageId | CONFIRMED ✓ (programId is a `down` child of the ReceiptClaim tagged struct; claim mismatch ⇒ `Left(ClaimMismatch)`) | `ErgoStarkStatement.scala:184-192`; `Risc0RawSealVerifierE2ESpec.scala:189-195` |
| Raw seal total = **222,668 bytes** | CONFIRMED ✓ | `RawSealV1Decoder.scala:21`; manifest requires it `Risc0ProfilePackageLoader.scala:279` |
| BabyBear word count = **55,667** | CONFIRMED ✓ | `RawSealV1Decoder.scala:20` |
| Canonical 4-chunk partition = **`[65535, 65535, 65535, 26063]`** (sum 222,668) | CONFIRMED ✓ | `RawSealV1Decoder.scala:29`; KAT `RawSealV1DecoderSpec.scala:8,18` |
| Word encoding = **little-endian u32**, exact-size, fail-closed decode | CONFIRMED ✓ (wrong length/total/trailing all typed `Left`; word 32 = literal po2 18) | `RawSealV1Decoder.scala:114-190`; KAT `:27-56,128-133` |
| Stock profile = BabyBear / **Ext4** / Poseidon2 | CONFIRMED ✓ (ext degree 4; Poseidon2 cells 24/rate 16/out 8) | `Risc0ProfilePackageLoader.scala:420,423-428` |
| **Q = 50** FRI queries | CONFIRMED ✓ | `Risc0ProfilePackageLoader.scala:431`; `E2ESpec:194` (`FriVerifier.Queries`) |
| **12,359**-op recursion constraint table | CONFIRMED ✓ (`PolyExtOps = 12359`) | `Risc0ProfilePackageLoader.scala:47,448` |
| Inner root over **27** upstream recursion control IDs; **10** terminal control IDs | CONFIRMED ✓ (`ControlCount=10`; "commits to the broader upstream set of 27 recursion") | `Risc0ProfilePackageLoader.scala:31`; `eip-0045.md:504,1465` |
| Versions risc0-zkp **3.0.4** / risc0-circuit-recursion **4.0.4** | CONFIRMED ✓ (+ RISC Zero SDK **3.0.5**) | `eips:eip-0045/profile-v1/README.md:57-58` |
| Inner control root value `a54dc85a…1f56` | CONFIRMED ✓ (as the *inner control root* — see C1) | `profile-oracle.tsv:16`; `eip-0045.md:1428-1431` |
| Guest commits the **`ErgoStatementV1` bytes** (payload framed verbatim inside) | CONFIRMED ✓ (`env::commit_slice(statement)`; journal digest = `SHA-256(statement)`) | `eip-0045.md:312-318`; `ErgoStarkStatement.scala:162,184-185` |
| ~**95-bit** composed soundness (conjectured, below 128) | CONFIRMED ✓ (95.24-bit union-bound composition; "≈95 conjectured classical bits, not a proven bound") | `rationale:473-489` |

### 6.3 Newly-pinned facts the doc did not have

- **Payload cap = 16,384 bytes** (max statement 16,543); enforced at load and in the opcode.
  `Risc0ProfilePackageLoader.scala:34,281`, `VerifyStark.scala:75`, `eip-0045.md:296-297`.
- **The stock profileId value** `23c4…d383` (C1) — Aegis's `STOCK_PROFILE_ID` constant.
- **`chainDomainId` = mainnet genesis id `b0244dfc…175b`** for the Ergo chain (per-network;
  the opcode runs on Ergo, so Aegis uses the Ergo genesis id). `eip-0045.md:246-259`.
- **Cost mechanism** (`dispatchJit + fixedJit`, both upfront; final values blocked on B5).

### 6.4 Unverifiable from the reference (out of scope of the Scala impl)

- The exact **Rust risc0 3.0.5 seal-extraction call** that produces the 222,668 bytes
  (prover-side; the *target bytes* are fully specified, the API is not in the Scala tree).
- Whether Aegis's `AggParams::default()` emits a seal in the accepted shape (Rust prover).
- The **final cost constants** (EIP blocker B5 — not yet frozen upstream).

**Confidence:** high that this doc now matches the reference. Every consensus-critical byte
count, endianness, field order, and headline constant in the brief is confirmed against the
KATs; the single material correction (C1, profileId vs inner control root) and two
sharpenings (C2 po2 axes, C3 cost mechanism) are folded into §2/§3/§5 above.

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
