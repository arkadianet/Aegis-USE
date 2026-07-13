# Aegis merge-mining — Autolykos aux-PoW via the extension section (L1 design)

**Date:** 2026-07-13
**Status:** decided (design stage) — the L1 keystone of
[`architecture.md`](./architecture.md) §4. **This document replaces the
previous marker-lineage design in full** (git history holds it). Where a
decision is deferred it is tagged **DECISION NEEDED** or **v1-accepted**
explicitly.

> **Relation to [`consensus.md`](./consensus.md) §1.** The previous revision
> of this doc claimed to *supersede* consensus.md §1 with a data-transaction
> scheme. That was the error (§1 below). This revision **re-affirms
> consensus.md §1's direction** — commitment inside the mined candidate, own
> easier Aegis target, own DAA (§3), cumulative-real-work fork choice (§5) —
> and upgrades the channel from an `R4` tx output to an **extension-section
> field**, which consensus.md itself listed as the preferred long-term form.
> consensus.md §1's "no candidate API injects custom extension fields" blocker
> is resolved differently now: we *own* a Rust Ergo node
> (`ergo-mining/src/extension_builder.rs` is ours to extend), so the extension
> path no longer requires upstream Scala changes for the first miners. What
> changes vs. consensus.md §1 is spelled out in §2.6.

---

## 1. The error being corrected: fee-purchased inclusion is not merge-mining

The previous design put the Aegis commitment in a **normal Ergo data
transaction** — one output box whose `R4` carried the Aegis block id — that
any miner would include as ordinary fee-paying cargo. Its selling point was
"zero modification to any Ergo node or miner." That selling point is exactly
the flaw:

1. **The PoW never attests to the Aegis block.** The miner hashes
   `msg = blake2b256(bytes_without_pow(ergo_header))`. A confirmed data-tx is
   under `transactions_root`, so yes, the winning hash *transitively* commits
   to it — but the miner did not choose to mine it, does not know it exists,
   and would have produced the identical work without it. The work measures
   Ergo throughput, not Aegis intent. Nothing distinguishes "a miner secured
   this Aegis block" from "someone paid 0.001 ERG to a mempool."
2. **Anyone can submit the tx.** "Weight" was therefore fee-purchased
   inclusion. The design papered over this with a producer-key **lineage**
   (only `PRODUCER_PK` could extend), which made the chain *permissioned* —
   a single-operator sequencer with Ergo as a timestamping service. The
   panel's Fork B fork-choice layer then had to bolt "one counting slot per
   Ergo block, weight = Ergo difficulty" on top as an anti-amplification
   hack, because a fee-slot has no intrinsic work of its own.
3. **It is spoofable at the security level that matters.** An attacker who
   can outbid tx fees (trivial) can populate Ergo with arbitrary competing
   commitments; only the permissioned lineage prevented that, and the lineage
   is precisely what a permissionless chain must not have.

The zero-modification property and the security property are **mutually
exclusive**: PoW cannot attest to data the prover never agreed to hash. Real
merge-mining requires the miner's participation. That adoption cost is
honest and unavoidable (§4, §10), and this doc takes it.

## 2. The fix: true Autolykos aux-PoW via an extension-section commitment

### 2.1 One hash, two targets — the share-chain construction

The Aegis block id goes **inside the Ergo block candidate's extension
section**. The extension's Merkle root (`extension_root`) is one of the
header fields serialized by
`ergo-ser/src/header.rs::write_header_without_pow`, whose output is exactly
the preimage of the PoW message: *"the miner hashes
`msgByHeader = Blake2b256(bytesWithoutPow(header))`"* (module doc, verified —
`ergo-crypto/src/pow.rs::verify_pow_solution:47-50` computes
`msg = blake2b256(serialize_header_without_pow(header))`).

So every single Autolykos attempt over that candidate **already commits to
one specific Aegis block** before the nonce is even tried. The resulting hit
is checked against **two** targets:

- `ergo_target = get_target(ergo_header.n_bits)` — hard. Clears it → a real
  Ergo block (and, incidentally, an on-chain Aegis anchor, §7).
- `aegis_target = get_target(aegis_header.sc_nbits)` — **easier** (larger).
  Clears it → a valid **Aegis block** (a *share*), gossiped on the Aegis
  network with its witness (§2.4), never touching Ergo.

`get_target(nbits) = q / decode_compact_bits(nbits)` with
`q = secp256k1_order()` (`ergo-crypto/src/difficulty.rs:21-28`). Easier =
numerically larger target = smaller decoded difficulty.

**Dual-target soundness (verified in code):** the Autolykos v2 hit is
**target-independent** — `hit_for_v2(msg, nonce, height, n)`
(`ergo-crypto/src/autolykos/v2.rs:12`) takes no target;
`check_pow_v2(msg, nonce, height, version, target)` (`v2.rs:97`) merely
compares that hit against whichever target the caller passes. One solution,
two independent threshold checks, no coupling. The only header-derived
inputs are `height`/`version` via `calc_n` — and the verifier uses the
**Ergo candidate header's own** `height`/`version` (it is re-deriving the
same hit Ergo itself would compute), so there is no ambiguity about which
`n` applies. This is the same construction as Namecoin/Dogecoin aux-PoW:
you **cannot** produce a valid Aegis block without doing real Autolykos work
bound to that exact block.

### 2.2 The commitment field

One extension field (`ergo-ser/src/extension.rs::ExtensionField`,
`key: [u8;2]` = namespace<<8 | index, `value: Vec<u8>`):

| | Pinned value | Constraint it satisfies |
|---|---|---|
| **key** | `AEGIS_MM_KEY = [0xAE, 0x00]` | namespace `0xAE` is unused — existing namespaces are `0x00` params, `0x01` NiPoPoW interlinks, `0x02` validation rules (`extension.rs:9-11`); unknown keys are consensus-legal (rules 400/404/405/406 cap size/duplicates/emptiness but never reject unknown keys — `ergo-validation/src/block.rs::validate_extension_structural:611-657`) |
| **value** | `MM_COMMITMENT_VERSION (1 byte, 0x01)` ‖ `aegis_block_id (32 bytes)` = **33 bytes** | ≤ 64-byte per-field cap, rule 404 (`EXTENSION_FIELD_VALUE_MAX_SIZE = 64`, `block.rs:386`); ≤ 255-byte wire cap (`extension.rs:61`) |

No height, no `prev_id` in the value: the 32-byte id (`Header::id()`,
blake2b256 over the canonical core-header serialization,
`aegis-node/src/header.rs`) already transitively commits `prev_id`,
`height`, `tx_root`, `cm_tree_root`, `nullifier_digest`, `pot_balance`,
`sc_nbits`, and `reward_claim` — the whole block and its ancestry. 33 bytes
is the entire cross-chain surface.

**Ergo consensus itself enforces at most one commitment per header.** Rule
405 rejects any block whose extension carries two fields with the same key
(`block.rs:642-656`). Combined with "only key `AEGIS_MM_KEY` counts" (any
other key is not a commitment, by definition), one Ergo header commits to
**at most one** Aegis block, and the PoW message commits to `extension_root`
which commits to that field. This is load-bearing for §2.5.

### 2.3 The verifier — exact, from existing code

Inputs (the **share witness**, what Aegis gossip carries per block, ~1 KB +
body):

```text
ergo_header_bytes        full Ergo candidate header, incl. AutolykosSolution
extension_field          key AEGIS_MM_KEY, value 0x01 ‖ aegis_id
extension_merkle_proof   BatchMerkleProof: field leaf → header.extension_root
aegis_block_bytes        the full Aegis block
```

Checks, in order (fail-fast; every value re-derived, never trusted):

1. **Parse + solution type.** Decode the Ergo header; require
   `AutolykosSolution::V2` (mainnet is v2 since height 417,792; v1 shares
   are not accepted — one code path, one analysis).
2. **Height window (consensus.md C2, kept).** `ergo_header.height ∈
   [follower.tip_height − K_LAG, follower.tip_height + 1]` against our own
   `ergo_follow::Follower` view, `K_LAG` provisional 6. Blocks grinding a
   low height for a smaller Autolykos `calc_n` element count / per-hash cost
   edge, and bounds offline share stockpiling to a ~K_LAG·2-minute horizon.
3. **PoW message.** `msg = blake2b256(serialize_header_without_pow(h))`
   (`ergo-ser/src/header.rs`; an unserializable header is invalid, mirroring
   `PowError::HeaderEncode`).
4. **Extension inclusion.** Recompute the leaf exactly as
   `ergo_crypto::merkle::extension_root` does (`merkle/mod.rs:348`): leaf =
   `[key.len() as u8 = 2] ‖ key ‖ value` (Scala `Extension.kvToLeaf`), then
   `ergo_validation::popow::merkle::verify_batch_merkle_proof(proof,
   &h.extension_root)` (`popow/merkle.rs:33`) — the same
   leaf-prefix-0x00/internal-0x01 tree as transactions. The leaf bytes are
   built from the *claimed* field, so a proof for a different key/value
   cannot validate.
5. **Field decode.** `field.key == AEGIS_MM_KEY`; `field.value.len() == 33`;
   `field.value[0] == MM_COMMITMENT_VERSION`; `field.value[1..33] ==` the
   **recomputed** `Header::id()` of `aegis_block_bytes` (hash the presented
   bytes; never compare against a carried id).
6. **Aux-PoW threshold.** `aegis_target =
   get_target(aegis_header.sc_nbits)`; require
   `check_pow_v2(&msg, &nonce, h.height, h.version, &aegis_target)`
   (`ergo-crypto/src/autolykos/v2.rs:97`). `sc_nbits` itself is validated
   against `daa.rs::next_nbits` over the block's ancestors (§3) — a miner
   cannot self-declare an easy target.
7. **Body validity.** The Aegis block goes through the same
   `Chain::try_extend` path (`aegis-node/src/chain.rs:276`) every block
   takes: state transition, proofs, coinbase `verify_mint` against
   `reward_claim`, limits.

Steps 1–6 are pure functions over the witness + a recent Ergo header view;
step 7 needs the parent's Aegis state. All primitives exist today; the
verifier is composition, not new crypto.

**When the same solution also clears Ergo's target**, `ergo_header_bytes` is
a real published Ergo header and the witness becomes checkable against
Ergo's settled chain — those blocks are the **anchors** that feed
`W_settled` (§7), verified with exactly the `pegmint_steps::check_inclusion`
discipline (`aegis-node/src/pegmint_steps.rs`) plus a full-extension check:
fetch the block's extension, recompute
`extension_root(&fields)` (`merkle/mod.rs:348`), compare to the settled
header.

### 2.4 What a share is, precisely

A share's Ergo header is (usually) an **unpublished candidate** — it never
appears on Ergo, because its hit missed Ergo's target. That is fine and is
the point: the *work* is real and bound to the Aegis id regardless of
whether Ergo ever sees the header. The witness is self-contained (§2.3
steps 1–6 need no Ergo-chain lookup beyond the C2 height window). Aegis
cadence is therefore decoupled from Ergo's ~2 min: with aux target T_a and
opted-in hashrate H, shares arrive every `q/(T_a·H)` seconds, tuned by the
DAA (§3) — Ergo block arrival does not gate Aegis block production.

### 2.5 One hash → one Aegis block: amplification and equivocation die together

The old design needed an explicit anti-amplification hack ("one counting
slot per Ergo block") and a lineage rule against equivocation. Both are now
**intrinsic**:

- **No amplification.** One Autolykos evaluation produces one hit bound to
  one `msg`; one `msg` commits (via `extension_root` + rule 405 + the
  single-key rule) to at most one Aegis id. Re-binding the same hit to a
  different Aegis block changes the field value → changes the leaf →
  changes `extension_root` → changes `msg` → different hit, i.e. new work.
  Weight is work, one-to-one, with no counting rule needed.
- **No equivocation-for-free.** Two same-height Aegis blocks require two
  independent clearing hits — plain Nakamoto forking at full price, handled
  by fork choice like any fork.
- **Duplicate witnesses are not duplicate blocks.** The Aegis block id is
  the identity; ten distinct witnesses for one id are one block, counted
  once (first valid witness wins, others discarded — no consensus meaning).

### 2.6 Deltas vs. consensus.md §1 (to fold back in a follow-up commit)

Kept: parent→child binding direction (work commits to the SC block — D3),
C2 height pinning, own target/DAA/fork-choice, "every merge-miner runs
`aegis-node`". Changed: (i) channel = extension field, not a
`candidateWithTxs` commitment-tx output — the C1 "exactly one R4 output"
rule is replaced by rule-405 key uniqueness, and the C6 commitment-UTXO
lineage is **deleted** (no UTXO to chain, nothing stalls on an Ergo win);
(ii) witness shrinks from ~1–2 KB (tx + tx-Merkle-path) to ~200–300 B
(field + extension-Merkle-path); (iii) **no `aegis-mm` sidecar required for
the Rust-node solo path** — the builder hook is in-process (§4).

### 2.7 No marker contract — confirmed

With the commitment as pure extension data there is **no box, no ErgoTree,
no `MmMarker.es`, no `PRODUCER_PK`, no `MM_LINEAGE_ORIGIN`, no register
schema**. The `aegis-contracts` crate keeps exactly its six peg contracts.
Nothing about merge-mining touches the UTXO set. (An optional weightless
anchor tx is discussed — and rejected for v1 — in §10.3.)

## 3. Aegis's own difficulty: the share target and DAA

This **reverses** the previous doc's "`sc_nbits` = pinned min constant,
`daa.rs` never consulted, no independent PoW." Aegis has real PoW again, so
it has a real target again:

- **`sc_nbits` is live consensus.** Every Aegis header's `sc_nbits` must
  equal `next_nbits(DaaParams, ancestors)` — LWMA-1 (zawy12) over a
  90-block window as built and tested in `aegis-node/src/daa.rs`: solve
  times clamped to `[1 ms, 6T]`, per-step target clamp ×4/÷4, below
  `window + 1` headers the chain stays at `min_difficulty_nbits`
  (`daa.rs::next_nbits:46`).
- **Target share interval** = `NetworkParams::block_target_secs`
  (`aegis-spec/src/lib.rs`), currently 15 s. **DECISION NEEDED** before
  testnet-MM cut: 15 s is aggressive for early opted-in hashrate; 60 s is
  the candidate fallback. Chain-id-breaking either way (§8), so decide at
  re-cut, not after.
- **Aegis target vs. Ergo target.** Normally
  `aegis_target ≫ ergo_target` (shares much more frequent than Ergo
  blocks). No consensus rule *enforces* this ordering — none is needed and
  none is cleanly checkable (Aegis validation must not depend on Ergo's
  current `n_bits`). If the DAA ever drove Aegis difficulty above Ergo's,
  the only effect is that every share would also be an Ergo block; safety
  is unaffected, cadence degrades, the DAA self-corrects. Stated, not
  legislated.
- **Weight of a block** = `decode_compact_bits(sc_nbits)` (via
  `ergo_ser::difficulty`), i.e. real expected work. Cumulative weight
  `W(b)` = sum over `b` and ancestors — see §5.
- **Bootstrapping** (few miners → lumpy retarget) is a real gap, §10.2.
  consensus.md §3's C7 stands: mainnet `min_difficulty_nbits` must be
  non-trivial at cut time; dev stays trivial. `PowMode::DevStub`
  (`chain.rs`) and the `--network dev` self-paced producer remain the
  dev-network path, untouched.

## 4. Miner integration + incentive

**The adoption surface (honest):** a miner "merge-mines Aegis" iff the
candidate they hash carries the `AEGIS_MM_KEY` field. That requires the
software assembling their candidate to be Aegis-aware. Three tiers:

1. **Our Rust Ergo node, solo (M2a, first).** The candidate's extension is
   assembled in `ergo-mining/src/extension_builder.rs::
   build_candidate_extension_fields` (interlinks always, epoch-boundary
   fields when due). Adding one opt-in field there — value supplied by a
   local `aegis-node` over a small RPC ("current Aegis candidate id") — is
   a contained change in a repo we own. On every Aegis-tip change the
   candidate is rebuilt (the existing candidate-rebuild machinery;
   `candidate_base_cache` keeps this ~16 ms). No external sidecar, no
   Scala dependency. The miner also builds the *Aegis* candidate: sets
   `reward_claim` to their own coinbase note commitment (§ below), so the
   header id they commit is already theirs.
2. **Stock Scala node.** `candidateWithTxs` exists
   (`MiningApiRoute.scala:48`) but injects transactions, not extension
   fields — the extension path needs either a Scala-side patch or an
   external work-provider proxy that post-processes the candidate. Real
   cost, not hidden: this is a v1.x integration project, not a launch
   blocker (launch mines with tier 1). Our own node's
   `/mining/candidateWithTxs` REST-parity gap
   (`ergo-api/src/v1/operator/mining.rs:313`, stubbed) is unchanged as a
   W4 item but is no longer on Aegis's critical path.
3. **Pools.** The pool's candidate builder adds the field; workers need no
   change (they hash whatever `msg` stratum serves). Per-pool integration =
   the long-term hashrate curve (§10.1).

**Incentive — the coinbase goes to the share finder.** Each Aegis block
draws `NetworkParams::coinbase_reward(pot, n_txs)` from the emission pot
(credit-then-draw, consensus.md §5a), minted as a real note bound to the
header's `reward_claim` by `verify_mint`. Because `reward_claim` is inside
the committed id, the reward is bound to the block *before* the work is
done — the miner mines their own payout, exactly like Ergo's own coinbase.
Nothing pays "the producer" anymore; there is no producer. Marginal cost of
merge-mining ≈ 0 (same hashes they were already computing) + integration
effort; revenue = USE coinbase. This is the standard merged-mining
economics that keeps Namecoin at >⅓ of Bitcoin's hashrate.

## 5. Fork choice: heaviest downloaded-and-validated chain of real work

The panel's Fork B permissionless Nakamoto layer is kept — with the weight
input it always wanted:

- **Canonical Aegis** = the leaf with maximal cumulative weight `W(b)` among
  chains **this node has downloaded and validated** end-to-end
  (`Chain::try_extend` per block). `W(b)` = Σ `decode_compact_bits(sc_nbits)`
  over `b` and its ancestors — real aux-PoW work, nothing else. No fee
  slots, no per-Ergo-block counting rule, no Ergo-difficulty proxy: those
  were compensations for weightless commitments and are **gone** (§2.5).
- **Availability is a monotone input, never a verdict.** A block whose
  witness is valid (§2.3 steps 1–6) but whose body this node lacks is
  **pending**: its weight exists but does not activate; the branch is not a
  fork-choice candidate beyond the last validated block. "I don't have it
  yet" can flip to "validated" when bytes arrive (monotone — bodies are
  self-authenticating against the committed id), and can never flip back.
  A withheld body therefore *delays* a branch, it never stalls the node and
  never creates a subjective accept/reject split: the honest chain keeps
  producing and validating shares, and fork-choice follows it. This
  dissolves the old design's stall-on-unavailable rule (§5.3 of the
  previous revision) — that rule existed because skipping a *sequenced
  slot* forked the chain; with weight-based choice there are no slots to
  skip, only branches to (not) prefer.
- **Invalid body = dead branch prefix.** If a body arrives and fails
  `Chain::try_extend`, that block and every descendant is permanently
  invalid (verdict cached by id; deterministic — same bytes, same
  pre-state, same verdict on every node). Its weight never activates. The
  miner burned real work on garbage; no one else is affected.
- **Reorg mechanics** are the existing ones: `Chain::rollback_tip` through
  the 240-block undo ring (consensus.md §5), `store.rs` replay for deeper
  resync. Acceptance-finality declared at retention depth (240) stands.
- **Ties** in cumulative work break first-seen (consensus.md §5 C4,
  unchanged and now actually operative again).

## 6. Data availability by gossip

Bodies (proofs + ciphertexts, KBs each) move on the Aegis P2P network
(gossip + operator seed nodes — the M6 dependency). The DA story under
weight-based fork choice:

- A source can **withhold** (pending weight, liveness) but never **forge**
  (body hashes to the committed id or it is not the body) and never
  **reorder** (order is the chain structure the ids commit).
- **Withholding attack**: attacker mines shares, gossips witnesses but not
  bodies, hoping to later reveal a heavy hidden branch. While hidden, the
  branch is pending everywhere and the honest chain accrues activated
  weight normally — no honest node ever waits on it. The residual risk is
  the **late reveal** (a valid, available, heavier branch appearing deep) —
  which is just a private-mining attack, handled at the only place it can
  be: finality policy, next section.
- Nodes should retain pending witnesses (cheap, ~1 KB) and re-request
  bodies with backoff; a branch pending past ~240 blocks of honest progress
  is unrecoverable anyway (undo ring) and can be discarded.

## 7. Peg finality: `W_settled`, pending-hostile accounting, `L_final`

Peg-out (v1: `V_cap`-bounded attester, [`security.md`](./security.md); the
two-way peg remains unsolved — the vault contract cannot inspect Aegis, so
v1 is one-way-plus-attester, carried over unchanged) must not act on weight
that can evaporate. Three pieces:

- **Anchors.** Shares that also cleared Ergo's target are real Ergo blocks
  whose extensions carry the commitment **on the Ergo chain**. An Aegis
  block committed in an Ergo block ≥ `N_mint` deep on the follower's best
  chain (`Follower::settled_reference`, `aegis-node/src/ergo_follow.rs`) is
  **Ergo-settled**. Reversing it requires reorging Ergo past `N_mint` —
  Ergo's full security budget, not Aegis's.
- **`W_settled(b)`** = cumulative Aegis weight of branch `b` up to its
  highest Ergo-settled block. Weight above the last anchor is real but
  Aegis-grade; weight below it is Ergo-grade.
- **The attester rule.** Act on a peg-out at Aegis block `x` only when
  `W_settled(canonical) − W_max_competing ≥ L_final`, where
  `W_max_competing` counts every known competing branch **including
  pending/unavailable weight as hostile** (valid witnesses whose bodies we
  lack are assumed to be an attacker's hidden branch). A late reveal can
  therefore never reorg attested state: its weight was already counted
  against us before we acted. `L_final` (work units) is a new spec
  constant — provisional intuition "≥ 30 blocks at current difficulty",
  **DECISION NEEDED** with the cadence decision (§3), since its wall-clock
  meaning scales with the share interval and opted-in hashrate.

Full-node fork choice stays pure heaviest-validated (§5); anchors and
`L_final` gate only *irreversible external actions* (peg-out attestation,
and merchants are pointed at the same rule). An anchored-prefix no-reorg
checkpoint rule for all nodes was considered and **rejected for v1**: both
sides of a fork can anchor, so it buys little beyond `W_settled` and risks
wedging fork choice on Ergo-inclusion timing.

## 8. New / changed `aegis-spec` constants (all chain-id-breaking)

Per network in `aegis-spec/src/lib.rs::NetworkParams`, frozen at chain-cut
(testnet → mainnet is a re-cut, architecture.md §9):

| Constant | Type | Meaning |
|---|---|---|
| `AEGIS_MM_KEY` | `[u8; 2] = [0xAE, 0x00]` | extension field key (namespace `0xAE`, index 0) |
| `MM_COMMITMENT_VERSION` | `u8 = 0x01` | first byte of the field value; bump = new commitment era |
| `AEGIS_GENESIS_ID` | 32 bytes | pinned genesis (current dogfood cut: `e369d3c9…`) — the chain the key commits to |
| `min_difficulty_nbits` | `u32` | initial + floor Aegis difficulty (C7: non-trivial on mainnet) |
| `block_target_secs` | `u64` | DAA share-interval target (15 s vs 60 s — **DECISION NEEDED**, §3) |
| `K_LAG` | `u32 = 6` (provisional) | C2 Ergo-height window for share candidates |
| `L_FINAL` | `u128` (work units) | peg-out attestation lead (§7 — **DECISION NEEDED**) |
| `ERGO_ANCHOR` | 32-byte header id + height | pinned Ergo root for `Follower::with_root` |
| `ergo_mint_confs` (`N_mint`) | exists | unchanged; now also the anchor settling depth |

**Deleted** (from the superseded design; never shipped, nothing to
migrate): `MM_MARKER_TREE`, `MM_PRODUCER_PK`, `MM_CHAIN_TAG`,
`MM_LINEAGE_ORIGIN`, and the `sc_nbits == min` constant-equality rule.

## 9. Reuse ledger + staged build plan

**Reused as-is** (no new cryptography anywhere in this design):

| Piece | Where | Role here |
|---|---|---|
| `serialize_header_without_pow` | `ergo-ser/src/header.rs` | PoW message preimage |
| `check_pow_v2` / `hit_for_v2` | `ergo-crypto/src/autolykos/v2.rs` | the aux-PoW threshold check |
| `get_target`, `decode_compact_bits` | `ergo-crypto/src/difficulty.rs`, `ergo-ser` | nbits ↔ target ↔ weight |
| `extension_root`, `verify_batch_merkle_proof` | `ergo-crypto/src/merkle/mod.rs:348`, `ergo-validation/src/popow/merkle.rs:33` | field-inclusion proof |
| `ExtensionField`/`read_extension` | `ergo-ser/src/extension.rs` | field wire format |
| `Follower` (headers, settled view) | `aegis-node/src/ergo_follow.rs` | C2 window + anchor settling |
| `pegmint_steps::check_inclusion` discipline | `aegis-node/src/pegmint_steps.rs` | anchor verification in settled Ergo blocks |
| `next_nbits` (LWMA) | `aegis-node/src/daa.rs` | live again as consensus (§3) |
| `Chain::try_extend`, undo ring, `store.rs` replay | `aegis-node` | body validation + reorg |
| `build_candidate_extension_fields` | `ergo-mining/src/extension_builder.rs` (ergo repo) | the solo-miner injection point |

**Build plan:**

- **M2a — extension-commit builder + aux-PoW verifier.** Ergo-repo side:
  opt-in `AEGIS_MM_KEY` field in `extension_builder` fed by a local Aegis
  candidate endpoint (config-gated; off by default). Aegis side:
  `mm_verify.rs` implementing §2.3 steps 1–6 as a pure function;
  share-witness codec. Tests: witness round-trip; oracle vectors — a real
  testnet Ergo header whose extension carries the field, hit checked
  against both targets from mainnet-grade `check_pow_v2` vectors; wrong-key
  / wrong-value / forged-proof / oversized-value (rule 404) / duplicate-key
  (rule 405) rejection vectors; C2 window edges.
- **M2b — share ingestion + fork choice.** Witness pool; pending/active
  weight bookkeeping; `W(b)` fork choice over validated leaves; dead-id
  cache; anchor detection via the follower + `check_inclusion`;
  `W_settled` computation. Tests: amplification attempt (two ids, one
  hash — must be unconstructible), duplicate-witness dedup, pending→active
  activation, invalid-body branch death, deep-reorg refold vs the undo
  ring, first-seen tie.
- **M6 — gossip.** Bodies + witnesses on Aegis P2P, seeds, re-request/
  backoff, pending-hostile input to the attester. (Unchanged dependency;
  now also carries witnesses.)

## 10. Honest gaps

1. **Opted-in hashrate is the security budget.** Aux-PoW security equals
   the Ergo hashrate that *actually embeds the commitment* — not Ergo's
   total. Same as Namecoin/Dogecoin. At launch this is ~zero: tier-1 solo
   miners on our Rust node, then pools (§4). Until adoption, Aegis-grade
   reorg protection is weak and everything leans on §7's Ergo-settled
   anchors + `L_final` + pending-hostile accounting for anything
   irreversible. There is no clever fix; there is only adoption, and the
   coinbase is the adoption incentive. Stated as the #1 risk.
2. **Cadence/DAA bootstrapping.** One miner joining/leaving is a step
   function in hashrate; LWMA handles it better than epochs (why it was
   chosen) but early cadence will be lumpy, and a hashrate collapse
   stretches block times until the ×4-per-step clamp walks difficulty
   down. `block_target_secs` and `min_difficulty_nbits` must be re-picked
   at MM-testnet cut with measured hashrate. **DECISION NEEDED** (§3, §8).
3. **Pre-adoption liveness aid — decided: none.** A permissionless data-tx
   /anchor-box path could let anyone checkpoint Aegis ids on Ergo before
   miners adopt. Rejected for v1: it would be weightless by construction
   (weight comes ONLY from aux-PoW), so it secures nothing, and its only
   real function — discovery — is already served by Ergo-settled anchors
   once even one miner mines (and by seed nodes before that). Reconsider
   only if M6 discovery proves inadequate. Keeping it out keeps "the only
   way to extend Aegis is work" exactly true.
4. **Two-way peg unsolved** (unchanged): the Ergo-side contract cannot
   observe Aegis, so v1 peg-out = one-way / `V_cap`-bounded attester per
   `security.md`; `M`/`T_delay` protect the vault independently of
   everything in this doc.
5. **Scala-node miner path** (§4 tier 2) is unbuilt and needs either an
   upstream patch or a candidate-proxy; until then merge-mining is
   Rust-node-only. Accepted for v1.
6. **`L_final` calibration** requires observed hashrate distribution;
   provisional value is a placeholder (§7).

## 11. Self-adversarial pass

| # | Attack | Verdict | Killed by |
|---|---|---|---|
| 1 | **Spoof a commitment without work** — hand-craft a witness for an Aegis block with a fabricated Ergo header | Rejected | §2.3 step 6: `check_pow_v2` over `msg = blake2b256(bytes_without_pow)` must clear `aegis_target`; the header being unpublished doesn't matter, the *hit* is the credential. No hit, no block. Fee-paying data-txs carry zero weight by construction (§10.3) |
| 2 | **Double-commit: two Aegis blocks under one Ergo hash** | Impossible | One key counts (`AEGIS_MM_KEY`); rule 405 forbids duplicate keys inside one extension (`block.rs:642`); the value holds exactly one 33-byte entry (rule 404 caps 64 B; verifier requires len == 33); `msg` commits `extension_root`. A second id ⇒ different `msg` ⇒ the old hit is void — that's new work, not amplification (§2.5) |
| 3 | **Fake extension proof** — valid PoW header, Merkle proof binding a different field | Rejected | §2.3 step 4: the leaf is rebuilt from the claimed key‖value (`kvToLeaf`) and reduced against the header's own `extension_root` via `verify_batch_merkle_proof`; a proof over other bytes cannot reach the committed root (blake2b256 collision resistance) |
| 4 | **Low-hashrate reorg** — rent hash exceeding the opted-in set, rewrite recent Aegis | Works above honest share-rate; bounded | Honest answer: yes, until adoption (§10.1). Damage is bounded to reversible state: peg-out and merchant acceptance gate on `W_settled` lead ≥ `L_final` with pending-hostile counting (§7); rewriting below an Ergo-settled anchor needs a > `N_mint` Ergo reorg (Ergo's budget) |
| 5 | **Withhold a body** — gossip witnesses, hide bodies, reveal a heavy branch late | Never a stall; reveal pre-charged | Pending weight never activates for fork choice (§5) — honest chain proceeds; the attester already counted the hidden branch as hostile before acting (§7), so the reveal reorgs nothing attested. Residual: unattested recent state reorgs — ordinary Nakamoto risk priced in real work |
| 6 | **Ergo reorg** | Contained by depth | Shares don't live on Ergo — an Ergo reorg does not touch Aegis fork choice at all (improvement over the old design, where Aegis history *was* Ergo tx history). Only anchors move: ≤ `N_mint` deep, anchors were never settled (no `W_settled` impact); > `N_mint`, `W_settled` recedes and the attester's lead requirement re-arms — peg assumptions break with Ergo's, jointly with PegMint by shared `N_mint` |
| 7 | **Selfish share-mining** — withhold valid shares, release to orphan honest work | Standard selfish mining | Same γ/α analysis as any Nakamoto chain; no new lever (a withheld share earns nothing until published, coinbase included — `reward_claim` matures per consensus.md §5). Lumpier at low hashrate; folded into §10.1's honest risk and `L_final` margin |
| 8 | **Cheap-height grinding** — mine shares at a low Ergo height for a smaller `calc_n` table / cost edge, or stockpile offline | Rejected | C2 window (§2.3 step 2): candidate height within `[tip − K_LAG, tip + 1]` of the verifier's own `Follower` view bounds both the `n`-table choice and the stockpile horizon |
| 9 | **Self-declared easy target** — set `sc_nbits` soft so your shares clear trivially | Rejected | `sc_nbits` is consensus-checked against `next_nbits(daa)` over ancestors (§3); a wrong value fails header validation in `Chain::try_extend` regardless of PoW |
| 10 | **Replay a witness for a block already on-chain / duplicate weight** | No-op | Block id = identity; a second witness for a known id is discarded (§2.5); weight counted once per block per branch |
