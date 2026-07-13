# Aegis merge-mining — the commitment scheme (L1 design)

**Date:** 2026-07-13
**Status:** decided (design stage) — the L1 keystone of
[`architecture.md`](./architecture.md) §4. This doc pins the v1 scheme end to
end: what is committed, how the commitment appears on Ergo, how a node finds
and verifies it, and the consensus rule that makes the committed sequence *be*
the Aegis chain. Where a decision is deferred it is tagged **DECISION NEEDED**
or **v1-accepted** explicitly.

> **Supersedes [`consensus.md`](./consensus.md) §1 for v1.** §1's
> `candidateWithTxs` scheme binds Aegis blocks to *unpublished Ergo
> candidates* and gives Aegis its own (easier) PoW target, its own DAA (§3)
> and its own cumulative-work fork choice (§5). That is a *higher-cadence*
> design that requires an `aegis-mm` sidecar on every miner and
> `candidateWithTxs` REST parity on our Rust node (still a W4 gap). The
> scheme here is the architecture.md §4 path instead: the commitment is a
> **confirmed, ordinary Ergo transaction**, requiring **zero modification to
> any Ergo node or miner**, at the cost of Aegis cadence = Ergo cadence.
> Consequences for consensus.md §3 (DAA) and §5 (fork choice) are spelled out
> in §7 below; amending consensus.md is a follow-up commit, deliberately not
> folded into this doc. The §1 share-based scheme remains the documented v2
> cadence upgrade.

---

## 1. The commitment: the Aegis block id (32 bytes)

An Aegis block commits to Ergo exactly one value: its **block id**.

`Block::id()` (`aegis-node/src/block.rs`) delegates to `Header::id()`
(`aegis-node/src/header.rs`): **blake2b256 over the canonical VLQ
serialization of the core header fields** (`Header::bytes()`): `version`,
`prev_id`, `height`, `timestamp_ms`, `tx_root`, `cm_tree_root`,
`nullifier_digest`, `pot_balance`, `sc_nbits`, `reward_claim`.

That single hash transitively commits the whole block:

- the **body** via `tx_root` (`BlockBody::tx_root()` — merkle root over
  transfer ids, `EMPTY_TX_ROOT` for an empty body);
- the **coinbase** via `reward_claim` (the 33-byte coinbase note commitment,
  or the all-zero sentinel — consensus.md §5a);
- the **parent** via `prev_id`, so committing a tip transitively commits its
  whole ancestry;
- the **post-state** via `cm_tree_root` / `nullifier_digest` / `pot_balance`.

So a 32-byte register value on Ergo is a full binding commitment to one Aegis
block and its history. Nothing else needs to cross the boundary.

## 2. The commitment marker on Ergo — the crux

### 2.1 Pinned scheme: a marker box on a self-spending lineage

The commitment rides as one output box of an **ordinary Ergo transaction**:

**Marker ErgoTree.** A new seventh contract, `contracts/es/MmMarker.es`,
compiled and byte-pinned exactly like the six peg contracts (the
`aegis-contracts` crate: deploy-constant injection into `fromBase64("")`
placeholders, pinned `ergo-compiler`, blake2b256 script-hash pins):

```ergoscript
{
  // CHAIN_TAG: injected per-network 32-byte constant = the Aegis genesis id.
  // Referenced so it cannot be optimized out of the tree bytes; it exists
  // only to make the compiled tree unique per network (cheap scan filter +
  // cross-network domain separation).
  val chainTag = CHAIN_TAG
  sigmaProp(chainTag.size == 32) && proveDlog(PRODUCER_PK)
}
```

(The exact source shape is an M2a implementation detail — what is **pinned as
consensus** is the compiled tree *bytes*, `MM_MARKER_TREE` in `aegis-spec`,
not the source. The two requirements on the source: the per-network
`CHAIN_TAG` constant must survive into the tree bytes, and the spend
condition must be `proveDlog(PRODUCER_PK)` — see "why guarded" below.)

**Register layout** (strict; all four present, R8/R9 absent):

| Register | Type | Content |
|---|---|---|
| `R4` | `Coll[Byte]`, exactly 32 | Aegis block id (`Header::id()`) |
| `R5` | `Long`, `1 ..= i64::MAX` | Aegis height |
| `R6` | `Coll[Byte]`, exactly 32 | `prev_id` of the committed block (chain-linking; redundant with the body but lets a watcher check linkage **before** fetching the body) |
| `R7` | `Coll[Byte]`, exactly 1 | commitment version byte, `0x01` (`MM_COMMITMENT_VERSION`) |

A box that matches `MM_MARKER_TREE` but violates any row above is
**malformed** and is treated as carrying no commitment (never an error that
stalls anything — see §5).

**The lineage rule (authentication + total order).** Marker boxes are
trivially forgeable — anyone can create a box with any tree and any
registers. What cannot be forged is a **spend**. So the marker validity rule
is:

> A marker box **counts** iff its creating transaction **spends the current
> lineage tip** — the previous counting marker box — and it is the **first**
> `MM_MARKER_TREE` output of that transaction. The lineage starts at a
> per-network pinned outpoint `MM_LINEAGE_ORIGIN` (a marker box the operator
> creates at chain-cut, carrying `R4 = AEGIS_GENESIS_ID, R5 = 0,
> R6 = 0x00…00`; its content is informational — genesis is a spec constant,
> not a committed block).

This is consensus.md §1's C6 commitment-UTXO idea promoted from an
operational trick to **the** authentication mechanism, and it buys four
properties at once:

1. **Spoof-proof.** An attacker cannot spend the lineage tip (it is guarded
   by `proveDlog(PRODUCER_PK)`), so no attacker-created box ever counts. This
   is why the marker is **not** a pure anyone-can-spend data box: the box
   doubles as the lineage tip, and an anyone-can-spend tip could be spent (=
   hijacked or burned) by anyone.
2. **Total order for free.** Each counting marker spends the previous one;
   Ergo's single-spend rule makes the sequence a chain with no ties, no
   sibling ambiguity, no "two commitments for the same slot". Ordering needs
   no `(height, tx_index, output_index)` tie-break — the spend graph *is* the
   order (Ergo orders dependent txs within a block, so even two lineage steps
   inside one Ergo block are unambiguous).
3. **Cheap discovery.** The watcher tracks exactly one live outpoint (the
   current lineage tip box id) and looks for its spend; the
   `propositionBytes == MM_MARKER_TREE` byte-compare over block outputs is
   the scan filter that finds it.
4. **Self-funding.** The ERG in the tip rolls forward into the next tip; the
   operator tops up the float with an extra input when needed. Nothing is
   burned; min-box value (~0.001 ERG conventionally) is paid once.

**Cost of the lineage rule (stated, not hidden):** commitment production is
**permissioned** — only the holder of `PRODUCER_PK` can extend Aegis. In v1
this changes nothing real (there is a single operator/producer anyway, and
the operator is already trusted for *liveness* — never for safety). It is
also the load-bearing answer to the committed-but-unavailable-body attack in
§5.3. Opening production to multiple/permissionless producers is a v2
consensus design with a genuine data-availability problem — see §9.

### 2.2 The rejected alternative: the block-extension field

Ergo's header extension (2-byte key → 32-byte value) would carry the same 32
bytes with a ~100 B witness and no box dust. It was verified
stock-consensus-legal (consensus.md §1, deferred note: ported rules
400/405/406 cap size/duplicates but never reject unknown keys) — **but no
candidate API on either the Scala or our Rust node lets a client inject a
custom extension key today**, so it needs node changes on both
implementations plus miner cooperation. The data-box path needs *nothing*:
any stock Scala or Rust node relays the marker tx like any fee-paying tx.
Extension-field commitment stays the v2 optimization, alongside the
`candidateWithTxs` cadence upgrade.

## 3. Miner inclusion + incentive

The Aegis node (M2a builder) constructs the marker tx — inputs: the current
lineage tip (+ optionally a float top-up box), outputs: the new marker box,
change, and a normal miner-fee output — signs it with the producer key, and
submits it through the **stock `POST /transactions`** REST endpoint of any
Ergo node it is pointed at. That is the entire Ergo-side surface.

- **Why an Ergo miner includes it:** the tx fee. To a miner it is an
  ordinary fee-paying transaction; the miner neither knows nor cares that
  Aegis exists. **No node fork, no miner-software change, no sidecar on the
  miner** — this is the property the whole v1 design is built around.
- **Why the Aegis producer bothers:** the **Aegis coinbase**. Each committed
  block draws `NetworkParams::coinbase_reward(pot, n_txs)` from the emission
  pot (fee credit-then-draw, consensus.md §5a), minted as a real coinbase
  note bound to the header's `reward_claim` by the mint proof
  (`verify_mint`). The producer owns that note. The producer's cost per
  block ≈ one Ergo tx fee; the reward is denominated in USE from the pot
  (peg fees + sc tx fees), so production is economically self-sustaining
  once the chain carries traffic — and in v1 is simply an operator duty.
- **The Ergo miner gets no Aegis reward.** Deliberate: rewarding the
  includer would require identifying them and would buy nothing — inclusion
  is already purchased by the fee.

**Producer loop (v1 policy, not consensus):** build Aegis block `h+1` on the
producer's own tip `h`, submit the marker tx, wait for it to confirm, repeat.
One commitment in flight at a time — a replacement would double-spend the
lineage tip and mempools keep first-seen, so replacement is not reliable and
is not attempted. The producer does **not** wait `N_mint` between blocks
(that would make cadence 10× worse): it chains optimistically at ~1 block per
Ergo block and re-commits from the fork point if Ergo reorgs its recent
markers away. Settlement depth gates *other nodes'* acceptance, not the
producer's own progress.

## 4. The watcher (extends the follower)

Today `ergo_follow.rs` reads **headers only**: `Follower::apply_header`
PoW-gates every header via `ergo_crypto::pow::verify_pow_solution`, keeps
heaviest-cumulative-work fork choice, and exposes the settled reference
(`Follower::settled_reference`, `tip − N_mint`) and `Follower::settled_view`.
The live transport is `poll_http::RestHeaderSource` over
`GET /blocks/chainSlice`. All of that stays exactly as is — it remains the
PoW spine and the *single* Ergo fork-choice authority in the process.

The watcher (M2b, `aegis-node/src/mm_watch.rs`) adds a second consumer of the
same followed chain:

**New data needed: full blocks, not headers.** For each best-chain Ergo
block at settled depth the watcher fetches the block's transactions
(`GET /blocks/{headerId}/transactions` — a new `BlockSource` trait + REST
impl, the exact sibling of `poll::HeaderSource` / `poll_http::
RestHeaderSource`, same blocking/`spawn_blocking` discipline). Headers-only
is not enough: markers live in tx outputs. This is the honest bandwidth cost
of the scheme (Ergo blocks are typically tens of KB; cap 8 MB), and it is
v1-accepted; a compact-proof sync path exists below.

**Per-block verification, three layers:**

- **(a) Inclusion — reuses `pegmint_steps` verbatim.** Every observed
  lineage-step tx is authenticated by exactly the discipline of
  `pegmint_steps::check_inclusion` (`aegis-node/src/pegmint_steps.rs`),
  steps (1)–(6): header id **re-derived** from carried header bytes via
  `serialize_header` (never trusted); membership of that id at its own
  height in the follower's settled best chain (step (2) — here via the
  follower directly rather than a `SettledView` snapshot); tx decoded by
  `read_transaction` with trailing-byte rejection; leaf recomputed as
  `tx_leaf_digest(transaction_id(tx))` — never read from the proof; and the
  single-leaf `BatchMerkleProof` reduced against the carried header's
  `transactions_root` by `ergo_validation::popow::merkle::
  verify_batch_merkle_proof`. When the watcher scans a full block it can
  equivalently recompute the whole `transactions_root` (leaf rules per the
  block version: tx ids, then witness ids for v2+ — the `block_leaves` /
  `witness_id` construction already exercised in `pegmint_steps` tests) and
  compare it to the PoW-verified header; the single-leaf `TxInclusion` form
  is what a seed/peer hands a syncing node so it need not fetch whole Ergo
  blocks. Both reduce to the same root check.
- **(b) PoW** — already done: only headers accepted by
  `Follower::apply_header` (hence Autolykos-verified) are ever consulted;
  the watcher never looks at a block whose header the follower rejected.
- **(c) Marker well-formedness** — `propositionBytes == MM_MARKER_TREE`,
  strict R4–R7 layout per §2.1, lineage-tip spend check. Malformed ⇒ no
  commitment (never an error).

**Soundness vs. completeness (why a lying REST node can only stall).** The
consensus object is the *lineage*, and each step both spends the previous box
and is inclusion-proven in a settled PoW-valid block. A malicious block
source can therefore **withhold** the next lineage step — the watcher simply
does not advance (liveness; refetch from another node) — but can never
**forge** one: a fabricated spend fails (a), a spend on a stale branch fails
the settled-membership check, and fabricating PoW fails (b). Withholding a
*non-lineage* tx is irrelevant to consensus. There is no scan-completeness
requirement on which two honest nodes could disagree — both follow the same
spend chain. (Recomputing the full tx root when scanning full blocks detects
withholding immediately and is worth doing, but it is an integrity check,
not a soundness dependency.)

**Output.** The watcher maintains a `CommitLog`: the ordered lineage steps
`(aegis_id, aegis_height, prev_id, ergo_height, ergo_header_id)` on the
settled best chain. On `Ingest::Reorg { depth }` from the follower it rolls
back entries above the fork point and rescans the new branch —
deterministic, exactly mirroring the follower.

**Composition with the peg-in watcher.** One process, one `Follower`, one
Ergo REST upstream, three consumers: (i) header fork-choice + settled
reference (exists), (ii) the marker watcher (new), (iii) PegMint proof
verification (`verify_pegmint_full`), which already consumes
`Follower::settled_view`. All three share `N_mint`
(`aegis_spec::NetworkParams::ergo_mint_confs`), so "settled" means one thing
process-wide. The marker watcher and the peg verifier share the inclusion
primitives; nothing is duplicated.

## 5. The consensus rule + fork choice

> **Canonical Aegis = the result of folding the valid commitment lineage
> found in Ergo's heaviest chain, truncated to settled depth
> (`tip − N_mint`), starting from the pinned Aegis genesis.**

Aegis keeps **no independent fork choice**. `ergo_follow`'s
heaviest-cumulative-work rule over PoW-verified Ergo headers *is* the Aegis
fork choice; the lineage merely reads it out. This replaces consensus.md §5's
cumulative-SC-work rule (and its C4 first-seen tie-break) for merge-mined
networks: ties cannot arise, because the lineage admits no siblings.

### 5.1 The fold

State: `(tip_id, tip_height)`, starting `(AEGIS_GENESIS_ID, 0)`. For each
lineage step `M` in order:

1. **Linkage check (registers only, body not needed):**
   `M.R6 == tip_id && M.R5 == tip_height + 1`. If not — the step is
   **dead**: permanently skipped, the fold state does not change, but the
   **lineage still advances** (the step's marker box is the next lineage
   tip). A dead step burns a lineage slot and nothing else — this makes the
   scheme robust to producer bugs without letting them wedge the chain.
2. **Body validation:** fetch the block bytes whose `Header::id() == M.R4`
   (self-authenticating: hash and compare) and run them through the same
   `Chain::try_extend` path live blocks take (the replay-and-verify
   discipline `store.rs` already implements). Three outcomes:
   - **valid** → accept; `(tip_id, tip_height) := (M.R4, M.R5)`.
   - **invalid** → the step is **dead** (see 5.2).
   - **unavailable** → **stall** (see 5.3).

Gaps are trivial: an Ergo block containing no lineage step contributes no
Aegis block. Aegis cadence is "whenever a commitment lands", full stop.

Two Aegis blocks in one Ergo block: two consecutive lineage steps in one
block (the second marker tx spends the first's output in the same Ergo
block). Both count, in lineage order; their heights must chain `h+1, h+2` or
the second is dead by linkage. No tie-break rule is needed anywhere in this
design — single-spend forbids siblings.

### 5.2 Committed-but-**invalid** body: the commitment is dead, the chain does not halt

Pinned rule: **a lineage step whose body is available but fails
`Chain::try_extend` validation is permanently dead.** The fold skips it and
waits for the next step whose `R6` matches the *unchanged* tip. Nodes cache
dead ids (id → verdict) so bodies are not re-fetched or re-validated.

Why this is safe to decide locally (the subtle part): the verdict is
**objective and deterministic**. The body either blake2b256-hashes to the
committed id or it is not the committed body at all; and
`Chain::try_extend` against the fold's current state is a pure function —
every honest node holding the same bytes reaches the same verdict
(consistency-not-soundness caveats of the crypto aside, the *function* is
deterministic). There is no first-seen, no timeout, no clock in the verdict,
hence no way for two honest nodes to split on it.

Why "dead", not "halt": halting would price chain-death at one Ergo tx fee
plus a garbage body — and even restricted to the producer (lineage), a
producer *bug* that commits an invalid block must not be fatal; the producer
just fixes the bug and re-commits a valid block on the same parent. And why
"dead", not "pretend it never happened and allow the same id to be
re-committed": an id, once judged invalid, is invalid forever (determinism);
allowing re-commitment of the same id buys nothing and invites verdict-cache
inconsistencies.

One consequence to state plainly: **a committed id is a commitment, not a
guarantee** — Ergo's PoW orders commitments, it does not validate Aegis
bodies. Depth in Ergo says "this is the canonical *attempt* sequence";
validity is still judged by every Aegis node itself. That division is
exactly the SPV-style trust model the architecture already claims (§5:
"discovery + ordering + fork-choice = trustless via Ergo").

### 5.3 Committed-but-**unavailable** body: stall, never skip

Pinned rule: **a node that cannot obtain the body for a linkage-valid
lineage step stops advancing at that point.** It does not skip, ever.

Skipping on unavailability would be a *subjective* verdict — node A holds the
body and accepts, node B timed out and skipped — a permanent fork from a
liveness condition. Unavailability must therefore degrade to liveness only:
sync waits, retries seeds/peers, and any single honest holder of the bytes
unwedges everyone (the body is self-authenticating against `M.R4`).

The attack this exposes: commit `R4 = random 32 bytes` with correct linkage —
no body will ever exist, and everyone stalls forever. **The lineage rule of
§2.1 is the answer:** only the producer can create a counting step, so only
the producer can wedge the chain this way — and a producer that wedges the
chain is indistinguishable from a producer that stops producing, a liveness
failure v1 already accepts from its sole operator (the operator is trusted
for liveness, never for safety — peg-out remains protected by `M`/`T_delay`
independently). **v1-accepted under the single-producer assumption**; a
permissionless-producer v2 must solve this for real (§9 — it is *the*
open problem of the scheme).

### 5.4 Ergo reorgs

Commitments live in Ergo blocks, so they reorg with Ergo, and canonical
Aegis re-derives deterministically from the new heaviest chain:

- **Depth ≤ `N_mint`:** invisible. The fold only reads the settled prefix
  (`Follower::settled_reference`), so ordinary Ergo churn never touches
  Aegis state. The producer re-submits any of its marker txs that fell out
  (they are ordinary txs and usually just re-confirm on the new branch —
  unless the new branch already spent the lineage differently, which only
  the producer itself could have caused).
- **Depth > `N_mint`:** Aegis reorgs. The watcher rolls `CommitLog` back to
  the fork point and refolds; the node rolls Aegis state back with
  `Chain::rollback_tip` through the undo ring (240 blocks, consensus.md §5)
  and re-extends along the new committed sequence. Deeper than the ring →
  resync from snapshot/genesis (already the documented rule). Rewriting
  settled Aegis history therefore costs **a real > `N_mint`-deep Ergo PoW
  reorg** — Aegis inherits Ergo's full security budget here, which is the
  entire point of merge-mining. (The same event also breaks peg-in
  assumptions node-wide; `N_mint` is shared with PegMint by design, so the
  two subsystems fail and recover together, not separately.)

## 6. Body availability boundary

Restated cleanly, because every security claim above leans on it:

- **Trustless via Ergo:** discovery, ordering, fork choice, and the
  *identity* of every canonical Aegis block (its 32-byte id sequence). A
  fresh node needs only `aegis-spec` constants + an Ergo connection
  (architecture.md §5).
- **Liveness via the Aegis side:** the block *bodies* (proofs, ciphertexts —
  KBs each) are served by the producer/seed in v1 and P2P gossip at M6/L2.
  A body source can **withhold** but never **forge** (hash-checked against
  the committed id) and never **reorder** (order is Ergo's). Body
  unavailability stalls sync; it never changes what the chain *is*.

## 7. Interaction with existing pieces

- **Peg-in watcher:** shared infra, one follower — see §4. No change to
  `pegmint.rs`/`pegmint_steps.rs` semantics; the marker watcher is a second
  consumer, not a second Ergo client. (`ergo_follow.rs`'s module doc already
  calls itself "shared infrastructure" for exactly this reason.)
- **Difficulty / DAA / the 15 s target:** under this scheme Aegis has **no
  independent PoW**, so difficulty is meaningless on merge-mined networks.
  Pinned: on `aegis-test`/`aegis` (MM networks), `sc_nbits` **must equal**
  the network's `min_difficulty_nbits` constant in every header (a
  constant-equality consensus check; `daa.rs::next_nbits` is never
  consulted), and block cadence is *whatever Ergo confirms* (~2 min
  average, variable; finality for other nodes lags a further `N_mint` ≈ 20
  min). The `sc_nbits` header field is **kept** (dropping it is a gratuitous
  chain-id break and a header-codec change; a pinned constant is free). The
  15 s `block_target_secs` and the LWMA DAA remain exactly what they are
  today in practice: the **dev-network** self-paced producer's pacing
  (`PowMode::DevStub` in `chain.rs`, the `--network dev` loop in `main.rs`).
  consensus.md §3 and params.md must be amended to scope the DAA to dev
  (follow-up; **DECISION NEEDED** only on whether `aegis-test` retains a
  dev-style fallback pacer for local testing, which would be config, not
  consensus).
- **Timestamps:** MTP-11 still applies (producer-set timestamps stay
  monotonic-ish for wallet UX). The 60 s future-drift check
  (`MAX_FUTURE_DRIFT_MS`, `chain.rs`) applies at *live* acceptance;
  for commitment-settled blocks replayed during sync it is **waived**
  (`store.rs` replay already cannot honestly apply it; Ergo's own timestamp
  rules bound the committed sequence transitively). This waiver is a
  consensus rule and goes into the consensus.md amendment.
- **Coinbase reward:** goes to the **Aegis producer** (the coinbase note is
  minted to a producer-chosen key, bound via `reward_claim`), not to the
  Ergo miner who mined the commitment — §3. With v1's single producer,
  "who gets it" has one answer; a multi-producer v2 re-opens it together
  with the §9 items.

## 8. New `aegis-spec` constants (all chain-id-breaking)

Joining `ergo_mint_confs` (= `N_mint`, already present) in
`aegis-spec/src/lib.rs`, per network, frozen at chain-cut (a testnet →
mainnet re-cut re-pins all of them — architecture.md §9 already declares
the commitment-marker chain-id-breaking):

| Constant | Type | Meaning |
|---|---|---|
| `MM_MARKER_TREE` | `&[u8]` (pinned bytes) | compiled `MmMarker.es` ErgoTree with `CHAIN_TAG`/`PRODUCER_PK` injected — the scan filter and box-validity pin |
| `MM_PRODUCER_PK` | 33 bytes | the lineage spend key (inside the tree; pinned separately for tooling) |
| `MM_CHAIN_TAG` | 32 bytes | `= AEGIS_GENESIS_ID` (domain separation inside the tree) |
| `MM_LINEAGE_ORIGIN` | 32 bytes (box id) | the pinned first lineage outpoint (§2.1) |
| `MM_COMMITMENT_VERSION` | `u8 = 0x01` | the R7 byte; bump = new marker era (paired with a spec release) |
| `ERGO_ANCHOR` | 32 bytes (header id) + height | the pinned Ergo root the follower starts from (`Follower::with_root`) — already planned by architecture.md §5, becomes load-bearing here |

`Network::params()` grows these alongside the existing peg pins; like
`PegParams`, values for testnet come from the deployed artifacts at M2a
time (the `aegis-contracts` oracle-test pattern pins them byte-for-byte).

## 9. Honest gaps, open questions, staged build plan

**Gaps / open questions (unresolved, stated plainly):**

1. **Permissionless producers (v2).** The lineage rule makes v1 production
   single-keyed. Opening it re-introduces: the unavailable-body wedge
   (§5.3) — the classic sidechain data-availability problem — plus
   commitment ordering among competing producers and coinbase assignment.
   Candidate directions (N-of-M lineage keys; open markers + on-Ergo
   proposer auction; availability attestations; skip-after-Ergo-depth with
   its fork risk) all need a real design pass. **DECISION NEEDED before any
   multi-producer milestone; nothing in v1 forecloses any of them** (a new
   marker era via `MM_COMMITMENT_VERSION` + re-cut covers even radical
   changes on testnet).
2. **Producer-key loss / lineage termination.** If `PRODUCER_PK` is lost, or
   the tip is ever spent by a tx with no marker output, the lineage — and
   the chain — terminates; recovery is a chain re-cut (cheap on testnet,
   catastrophic on mainnet). Mitigations to decide at mainnet-cut time:
   key ceremony, or a marker script with a timelocked recovery path to a
   successor key (**DECISION NEEDED**, mainnet gate).
3. **Miner censorship economics.** Fee-bumping is the only lever; a
   miner-majority policy of dropping `MM_MARKER_TREE` outputs halts Aegis
   (liveness only). v1-accepted; the extension-field/candidateWithTxs v2
   channels are also the long-term hedge here.
4. **consensus.md / params.md amendments** (§1 supersession scoping, §3 DAA
   scoped to dev, §5 fork-choice replacement, timestamp waiver) —
   follow-up doc commit, deliberately excluded from this one.
5. **Bandwidth posture of full-block watching** on mainnet Ergo — fine on
   paper (tens of KB typical), unmeasured by us. Measure during M2b;
   the compact `TxInclusion` sync path (§4a) is the fallback.

**Staged build plan:**

- **M2a — commitment-tx builder + submitter.** `MmMarker.es` +
  `aegis-contracts` pins (tree bytes, script hash, register schema
  round-trip); `mm_commit.rs`: lineage wallet (track tip outpoint, build
  spend, sign, `POST /transactions`, confirm-or-retry); `aegis-spec`
  constants for dev/test. Deliverable: real marker lineage on Ergo testnet
  committing dev-produced Aegis blocks. Tests: tree-byte oracle vs deployed
  box (the `test-vectors/testnet/` pattern), register layout round-trip,
  lineage-chaining across a simulated Ergo win, one-in-flight policy.
- **M2b — watcher.** `BlockSource` + REST impl; marker extraction +
  strict-parse; lineage tracking; `CommitLog` with reorg rollback wired to
  `Ingest::Reorg`; inclusion verification reusing the `check_inclusion`
  primitives. Deliverable: a node that, given only spec constants + an Ergo
  node, prints the canonical Aegis id sequence. Tests: spoofed marker
  ignored, withheld-tx refetch (root mismatch), reorg rescan determinism,
  malformed-register vectors, settled-depth gating; oracle: the real M2a
  testnet lineage.
- **M2c — consensus rule.** The §5 fold; dead-id cache; body fetch
  (seed URL) + `Chain::try_extend` replay; stall-on-unavailable;
  `sc_nbits`-constant check + timestamp waiver on MM networks; switch
  test-network block acceptance from "produced locally" to
  "committed + settled". Deliverable: fresh-node sync from genesis via Ergo
  (architecture.md §5 made real). Tests: skip-invalid vs stall-unavailable
  split, deep-reorg refold against the undo ring, replay/equivocation
  vectors, end-to-end sync against the live testnet lineage.

## 10. Self-adversarial pass

| # | Attack | Verdict | Killed by |
|---|---|---|---|
| 1 | **Spoof a marker box** (correct tree + registers, attacker-funded, R6 = current tip) | Dead | Lineage rule: the creating tx does not spend the producer-guarded lineage tip; watcher never counts it (§2.1) |
| 2 | **Commit an invalid body** (garbage that hashes to the committed id) | Dead, chain continues | §5.2 skip rule: verdict objective (`Chain::try_extend` deterministic vs fixed pre-state); step dead, tip unchanged. Only the producer can even create the step |
| 3 | **Commit an unavailable body** (`R4` = random) | Stall, not fork | §5.3: only the producer can (lineage); equivalent to the producer halting — v1-accepted under the single-operator liveness assumption; **the** open problem for permissionless v2 (§9.1) |
| 4 | **Censor commitments** (miners refuse marker txs) | Halt, never unsafe | Nothing to kill it: liveness-only by construction (no commitment ⇒ no block ⇒ no state change; peg-out safety rests on `M`/`T_delay`, not SC liveness). v1-accepted (§9.3) |
| 5 | **Commit two competing Aegis blocks at one height** (producer equivocation) | Impossible on one Ergo chain | Ergo single-spend: both steps would spend the same lineage tip; at most one confirms. Across Ergo forks, the settled-prefix rule picks exactly one (§5.4) |
| 6 | **Replay an old commitment at a new position** | Dead | Fold linkage: `R6 ≠ current tip` / `R5 ≠ tip+1` (§5.1); and a replayed *tx* is unconfirmable anyway (its input is long spent) |
| 7 | **Reorg Ergo > `N_mint` to rewrite Aegis history** | Works iff you can reorg Ergo | Inherited security — the attack *is* a deep Ergo PoW reorg (Aegis adds no cheaper path); Aegis refolds deterministically, undo ring to 240, resync beyond. Accepted: identical to the assumption the peg already makes (§5.4) |
| 8 | **Forge PoW-less inclusion** (lying REST node fabricates a lineage-step tx or its host block) | Rejected | `Follower::apply_header`'s Autolykos gate + settled-membership + the `check_inclusion` merkle reduction against the PoW-committed `transactions_root` (§4). A lying source can only withhold (liveness) |
| 9 | **Withhold the next lineage step** (lying block source) | Stall + detect | No skip decision exists to poison (§4 soundness/completeness); full-root recompute flags the source, watcher refetches elsewhere |
