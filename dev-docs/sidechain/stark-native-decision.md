# STARK-native architecture decision (OPEN — spike-gated)

> **Status: OPEN. Decision is gated on a bounded spike (below).** Until it reports
> and the operator decides, the Curve Trees core stays the working prototype and
> **the crypto core is frozen from *freezing*** — see the freeze-hold. This doc is
> the auditable record of what we're deciding, how we measure it, and how we keep
> the proven work clean while we do.

## The decision

Whether to keep the current **Curve Trees + Bulletproofs** private-transaction
core, or pivot toward a **STARK-native private state machine** whose root-to-root
transition Ergo verifies via **EIP-0045**, making USE settlement
*cryptographically enforced* rather than *attester-trusted + `V_cap`-bounded*.

This is not being decided now. It is being **measured** now.

## Why this is worth a spike (the load-bearing reason)

Seven limitations of the current core were raised (lifetime, O(n) rebuild, fixed
2-in/2-out, hand-composed relations, no PQ, no trust-minimized settlement, limited
aggregation). Most are real but addressable within Curve Trees. **The one that
changes the *product* rather than the *scaling curve* is settlement:**

> Aux-PoW gives Aegis objective ordering and fork choice. It does **not** prove to
> an Ergo contract that Aegis conserved USE supply, admitted only valid deposits,
> prevented double-spends, or finalized a valid burn. Peg-out therefore still rests
> on `SideChainState` + attesters + `V_cap` (the "two-way peg is unsolved" wall
> recorded throughout `peg.md` / `g25-pegmint-packaging.md`).

A STARK Ergo can verify converts the peg from *trusted+capped* to *enforced*.
Curve Trees + aux-PoW structurally cannot reach that. **That is the reason to
look — everything else is secondary.**

**The contingency the argument hangs on:** EIP-0045 is an *unmerged proposal*
(ergoplatform/eips PR #103). Its on-chain verification cost and proof size are
unmeasured. If verifying a transition proof is unaffordable on Ergo, the settlement
argument collapses back to attesters and the pivot loses its main reason. **So the
spike measures EIP-0045 economics first, before any private-state-machine
internals.**

## The spike — four questions, in priority order

Build **one bounded** STARK-native prototype. Not a product, not a migration — a
measurement rig that answers, with numbers:

1. **EIP-0045 on Ergo** — proof size on-chain + verification cost (ergo-tree cost
   units / would-it-fit-in-a-block) per state transition. *Measure first; the whole
   thesis depends on it.*
2. **Client-side proving** — wall-clock + peak memory to prove one transition on
   **phone/browser-class hardware**, not a server. (A mass-market payment system
   lives or dies here; a Bulletproof is comparatively light, a STARK often is not.)
3. **One bounded transition, end-to-end** — a single proof over: note membership +
   nullifier freshness + value conservation + deposit provenance + PegBurn validity
   + reserve/liability conservation, with the **exact EIP-0045 public inputs**.
4. **Operator-blindness** — can the prover be fully client-side so the sequencer
   never sees plaintext? (Required for the privacy model to survive the pivot.)

## Kill criteria (pre-committed, so a "promising" spike can't bias the decision)

Write the thresholds **before** running, and honor them:

- **EIP-0045 verify cost** above a per-transition ceiling that fits a real Ergo
  block → **do not pivot** (settlement benefit is unrealizable; #6 dies).
- **Client proving** above ~N seconds / M GB on mid-range phone hardware → **do not
  pivot to a client-proving model** (mass-market UX regresses vs today).
- zkVM/toolchain not production-auditable (unstable, unaudited, single-vendor lock)
  → **do not pivot yet** (soundness surface moved, not reduced).

(Operator sets N, M, and the cost ceiling before the spike runs. A spike that
merely "looks promising" is not a pass.)

## Handling — how we do this without making a mess

**Principle: the spike measures; it does not refactor.** The Aegis-USE `main`
branch does not change during the spike **except this and other docs.**

### Isolation

- The spike lives in a **separate sibling repo**, `aegis-stark-spike/` (own git,
  own `Cargo.lock`, own build dir `~/.cache/cargo-target-aegis-stark-spike`).
- **Rationale:** a zkVM dependency (RISC Zero / SP1 / Cairo) drags a large tree.
  Keeping it in a separate repo means it **never enters Aegis-USE's dependency
  graph or `Cargo.lock`**, the spike stays genuinely disposable, and it's forced to
  be self-contained. If it needs Aegis structs it **copies** the minimal state
  model — we're testing a *different* representation anyway.
- **Not pushed to GitHub** until the operator decides (outward-facing; local only).

### Freeze-hold (the guardrail)

Until the spike reports and the operator decides, **do not**:

- commit any **chain-id-breaking param** (share interval, `L_final`, `V_CAP`,
  mainnet constants) or do the **testnet→mainnet re-cut**;
- mark `aegis-spec` / `note-protocol` as **frozen**;
- **harden or optimize the Curve Trees crypto** — in particular *do not* build the
  deferred incremental-tree append/witness-update. It's the single biggest piece of
  new crypto-layer engineering left, and it's exactly what a pivot throws away.
  Building it now is the mess we're avoiding.

### What is safe to keep building in parallel (none touch the proving layer)

- **M3** API + mempool (submit / query / the `mm/commitment` endpoint) — safe.
- **M5** indexer + explorer — safe.
- **Ergo-side candidate-builder integration** (`ergo-integration.md`) — safe;
  it's about Ergo extensions, orthogonal to the private layer.
- **M4 wallet**: the **key-hierarchy / address / scan-orchestration design** is safe
  to spec; **hold** building note-encryption and any *proving-facing* wallet code
  (both change under a pivot).

## Blast radius — what a pivot would actually touch

This is the reassurance that the mess is bounded. A pivot replaces the **proving
layer only** — one crate plus one vendored dep — and it's the *least-frozen, most
in-flux* part of the system (N1 just closed; encryption is unbuilt).

**Survives a pivot unchanged (proving-independent):**
- The entire consensus + networking layer: aux-PoW verifier (`auxpow.rs`),
  fork-choice (`mm_forkchoice.rs`), Ergo follower (`ergo_follow.rs`), anchor-watcher
  (`anchor_watch.rs`), seed + fresh-sync (`seed.rs`, `fresh_sync.rs`), node loop
  (`node.rs`).
- Peg **plumbing**: `aegis-contracts`, peg-in inclusion/objectivity
  (`pegmint.rs`, `pegmint_steps.rs`), the deposit/receipt/vault machinery.
- `store.rs` persistence/replay, `Chain` materialization, DAA/difficulty.
- Note-protocol *semantics*, key-hierarchy *design*, wire-uniformity principle.
- All test vectors and the `dev-docs/sidechain` corpus.

**Replaced by a pivot (the bounded cost):**
- `aegis-crypto` Curve Trees circuits: `spend.rs`, `mint.rs`, `tree.rs`, the
  Poseidon nullifier gadget / N1 work; the 2-in/2-out R1CS + cross-cycle gadgets.
- The vendored `curve-trees` dependency.
- `ProofMode::Real` Bulletproofs verification in the node.

**Redesigned either way (already in-flux):**
- `ShieldedState` representation (leaf vector → sparse STARK state roots).
- Note encryption/transport (unbuilt; a pivot may bring a PQ KEM).
- Peg-**out** validity: attester/`V_cap` → EIP-0045 proof verification — *this is
  the #6 win.*

## Don't miss the hybrid

The decision is **not** binary. The load-bearing benefit (#6, enforced settlement)
might be reachable by adding an EIP-0045 **settlement/burn proof on top of the
existing Curve Trees private layer** — getting trust-minimized peg-out **without
rewriting the private-tx crypto at all.** The spike should explicitly test whether
the settlement proof can be **decoupled** from the private-tx proof. If it can,
"hybrid" may dominate: highest-value point captured, lowest work, private layer
untouched. Treat Curve-Trees / hybrid / STARK-native as a **spectrum**, not two
camps.

## Exit

The spike returns the four numbers + a written recommendation. Then the operator
decides:

- **STAY** → archive the spike, drop its dep tree, resume the freeze path, and
  *then* build the deferred incremental-append (safe again once we're committed).
- **HYBRID** → keep the Curve Trees private layer; add the EIP-0045 settlement
  proof at the peg-out boundary only. A *contained* addition, not a rewrite.
- **PIVOT** → write a migration plan against the blast-radius inventory above. The
  pivot is a **fresh crypto core slotted under the surviving consensus/peg/network
  layers** — not a system rewrite.

Curve Trees remains an excellent prototype and a source of privacy-protocol
lessons regardless of outcome. The point of this gate is to **not harden an
architecture we might replace** — and to keep every proven, battle-tested layer
untouched while we find out.
