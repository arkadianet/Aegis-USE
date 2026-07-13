# M3 — node API + mempool (design)

> Turns the running merge-mining node (M6c) into an **inspectable, usable** node:
> an HTTP/RPC API to submit a shielded transfer and query state, a mempool to
> accept and order pending transfers, and the peg verifier wired into the chain.
> This is a *design* — build it (design → adversarial review → build) when
> capacity allows. Unaudited/testnet posture unchanged.

## Goal & non-goals

**Goal:** a client can submit a `ShieldedTransfer`, have it enter a mempool, be
ordered into a produced block, and query chain/state/peg/merge-mining status.
Plus the small **merge-mining commitment endpoint** the Ergo-side integration
needs (`ergo-integration.md`).

**Non-goal (this milestone):** privacy-preserving *transaction relay* across the
P2P network (the Dandelion-shaped origin-hiding problem, flagged out-of-scope in
`p2p.md`). M3's mempool is **node-local** first; multi-node encrypted tx relay is
its own later item. Say this loudly so a single-node API isn't mistaken for
network-private submission.

## The privacy wrinkle to get right

A mempool on a private chain leaks *metadata* even though contents are shielded:
- **Timing/origin:** the node that first sees a tx, and *when*, links a submitter
  to a (still-shielded) transfer. Single-node v1 = the submitter trusts their own
  node (fine). Multi-node relay must not let the first-hop peer learn the origin
  → deferred (Dandelion++/stem-fluff), explicitly.
- **Ordering:** every transfer is byte-identical (2-in/2-out, uniform fee), so
  ordering leaks only *count and timing*, not amounts/parties — good. Keep fee
  uniform (no fee-priority ordering, which would leak a preference signal); order
  by arrival or randomize within a block.
- **Mempool inspection:** the API must **not** expose the pending set to third
  parties in a way that de-anonymises timing. A public `/mempool` count is fine;
  dumping pending nullifiers/commitments with timestamps is a metadata leak —
  gate it or omit it.

## API surface (HTTP/JSON, versioned `/aegis/v1/...`)

Reuse the seed server's transport (M6b-1 `serve_http`) or the M3 API server —
one decision at build time (recommend one shared server; the seed routes and API
routes coexist). All read routes public; submit is the only mutating route.

**Submit / mempool**
- `POST /aegis/v1/tx` — body = a `ShieldedTransfer` wire blob. Validates
  (`proof.rs` wire↔proof bind + `verify_shielded_transfer` against the current
  tip anchor) and admits to the mempool, or returns the typed rejection. Idempotent
  on the transfer's nullifiers (double-submit = no-op).
- `GET /aegis/v1/mempool` — count + aggregate only (no per-tx metadata dump).

**Chain / state (read)**
- `GET /aegis/v1/tip` — canonical tip id, height, cumulative work, `is_final`
  horizon.
- `GET /aegis/v1/block/{id}` and `/block/at/{height}` — block bodies (already
  content-addressed; overlaps the seed `/body` route — unify).
- `GET /aegis/v1/state` — nullifier-set size, note-commitment tree root, emission
  pot, digest — the *public* aggregates, never per-note data.
- `GET /aegis/v1/nullifier/{hex}` — spent? (public; a nullifier is a public
  spent-marker). Useful for wallets to confirm a spend landed.

**Peg (transparent side — safe to expose fully)**
- `GET /aegis/v1/peg` — vault balance, `V_CAP`, pending peg-ins/outs, used-set
  size. The peg is transparent by design (`architecture.md §7`).

**Merge-mining**
- `GET /aegis/v1/mm/commitment` — the current Aegis block **commitment**
  (`aegis_id` of the candidate on the canonical tip) — the endpoint the Ergo-side
  candidate-builder polls (`ergo-integration.md`). Cheap, cache-until-tip-changes.
- `GET /aegis/v1/mm/status` — followed Ergo tip, settled height, pending-hostile
  weight, share ingest rate — the observability the M6c logs currently hold.

## Mempool

A `Mempool` structure holding admitted `ShieldedTransfer`s:
- **Admission:** wire-decode → `proof.rs` bind → `verify_shielded_transfer`
  against the **current canonical tip's anchor** (the cm-tree the transfer proves
  membership in). Reject on: bad proof, nullifier already spent (`ShieldedState`
  nullifier set) OR already in the mempool (intra-mempool double-spend), oversize,
  wrong fee.
- **Reorg handling:** on a fork-choice tip change (M2b), transfers whose anchor is
  no longer canonical must be **re-validated** against the new tip (their
  membership proof may no longer hold) — evict the now-invalid, keep the rest.
  This mirrors the mempool tip-revalidation the Ergo node already does.
- **Ordering into a block:** the producer (M6c dev path, and real producers) pulls
  up to `MAX_BLOCK_TXS` transfers, checks pairwise nullifier-disjointness (no two
  in one block spend the same note), and includes them. Uniform fee ⇒ no priority
  ordering; arrival-order or shuffle. The coinbase is added as today.
- **Eviction:** on inclusion, on nullifier-conflict after a reorg, and a size/age
  cap.

## Wiring the peg verifier into the chain (the "DO-NOT-WIRE" removal)

`pegmint`/`pegmint_steps` (peg-in) are verified pure fns behind a DO-NOT-WIRE
banner. M3 (or a dedicated slice) connects them: a confirmed Ergo consolidation
(`verify_pegmint_full` against the follower's `ComparativeAnchor` /
`settled_view`) → a `PegMintEffect` → the chain **mints the note** (reusing the
coinbase mint machinery, `RewardMode`/S5b) + credits the pot + inserts the
receipt boxId into the used-set. Gate this behind the same value posture: **no
real value** until the external reviews land; on testnet it's the tUSE stand-in.
This is peg-in going live end-to-end (the last unwired peg piece); keep it a
reviewed slice of its own given it's the value path.

## Build order (M3 slices, each design→review→build)

1. **Read-only API** (tip/state/peg/mm status + the `mm/commitment` endpoint —
   unblocks the Ergo integration) — smallest, no mutation, safe first.
2. **Mempool + submit** (admission, reorg-revalidation, ordering into the
   producer) — the shielded-tx lifecycle.
3. **Peg-in wiring** (`verify_pegmint_full` → mint) — a reviewed value-path slice.
4. *(later)* multi-node encrypted tx relay (Dandelion-shaped) — its own privacy
   design.

Slice 1 is the quickest win and directly enables real merge-mining (the Ergo
candidate-builder needs `mm/commitment`). Recommend it first.
