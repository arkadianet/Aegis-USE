# Hybrid STARK — settlement statement + build plan

> The hybrid keeps **Curve Trees for private payments** (client-side, small
> statements — where it wins) and uses a **STARK only for server-side settlement**
> (big aggregate statements — where STARK wins): the *trustless bridge* and the
> *trustless R1-T recycle*. This doc pins the **statement** — exactly what the
> proof proves and what Ergo verifies — because that interface is what every
> downstream piece (prover, verifier, peg contract) targets, and it's fixable now,
> zkVM-agnostic, ahead of any tool choice. It is the foundation, not the build.

## Why settlement is the right STARK job

Settlement is one big proof over a whole epoch/batch of aggregate state — exactly
the shape STARK is efficient at, and it's produced **once, server-side, by the
settling node**, never on a user's phone. So it sidesteps the client-side proving
cost that keeps payments on Curve Trees. One proof, verified by Ergo, replaces a
trusted attester.

## Statement 1 — trustless withdrawal (peg-out)

**Claim (what the STARK proves):** starting from a committed Aegis state, a batch
of activity produces a new committed state in which a specific withdrawal is valid
— value is conserved, the withdrawn amount was genuinely burned on the Aegis side,
and nothing was double-spent — *without revealing the shielded details*.

- **Public inputs (what Ergo sees + verifies via `verifyStark`):**
  - `prev_state_root` — the Aegis state (note-commitment tree **frontier
    commitment** + nullifier-set accumulator + peg reserve) the batch starts
    from. See *Incremental tree transition* below: the state root commits the
    O(log n) append **frontier**, not just the note-commitment root, so the
    transition need never re-walk history.
  - `new_state_root` — the state after the batch.
  - `withdrawal_amount`, `withdrawal_recipient` — the USE to release on Ergo.
  - `epoch` / `height` binding — anti-replay / freshness.
- **Private witness (hidden in the proof):** the batch's shielded transfers,
  the burn note openings, the membership paths — none revealed.
- **What Ergo does with it:** the `PegVault` contract calls `verifyStark(proof,
  publicInputs, imageId, vmType, costParams)` and, only if it returns true **and**
  the public inputs are bound to this transaction (below), releases
  `withdrawal_amount` to `withdrawal_recipient`. No attester, no `V_cap`.

## Incremental tree transition — O(epoch), not O(history)

The single tree-transition term of Statement 1 — "appending the epoch's leaves
takes `prev_root → new_root`" — was the cost that grew with chain history
**forever**: the guest rebuilt the whole note-commitment tree over `pre + epoch`
leaves (`~4.5M cycles/block` of history swept, dominating any long-epoch proof).
It is now O(epoch), independent of `pre`.

**The frontier.** An append-only Merkle tree has a compact boundary — one
left-sibling digest per level plus the leaf count (`DEPTH+1` = 33 digests for the
depth-32 tree) — that is sufficient to (a) recompute the current root and (b)
append new leaves. This is [`aegis_engine::merkle::Frontier`] (the standard
Zcash/Tornado incremental-tree recurrence, sharing `zeros[]` and the Poseidon2
`compress` of the accumulator). The hn chain state maintains this frontier as it
accumulates leaves; **the state root commits `Frontier::commit()` =
`H_FRONTIER(leaf_count ‖ filled[0..DEPTH])`** (domain `0x0A04`), so the boundary
is authenticated. Because `root()` is a deterministic function of the frontier,
committing the frontier authenticates the root it produces — a prover cannot
substitute a boundary that yields a different root.

**The reworked transition statement.** Given the committed `prev` frontier (bound
by `prev_state_root`) and the epoch's `N` new note commitments, the guest:

1. reads `prev_root = prev.root()` — 32 compressions, no history walk;
2. advances the frontier over exactly the `N` epoch leaves
   (`settle_tree_transition`) → `new` frontier — `N · DEPTH` compressions;
3. `new_root = new.root()`, and `new_state_root` commits `new.commit()`.

Total tree-transition work: `(N+1) · DEPTH` Poseidon2 compressions — a function of
the **epoch** size only. The guest no longer receives `pre_leaves` at all. The
spend-verification term (per-tx in-field STARK verify) is unchanged; only this
transition term changes.

**Correctness anchor (oracle parity).** The incremental `new_root` byte-matches
the old full-rebuild root — the full `NoteTree` rebuild is the oracle, and
`engine/src/merkle.rs` cross-checks the frontier against it at every prefix
`0..=300` (all power-of-two boundaries), on exactly-full subtrees
(`K ∈ {1,2,…,512}`), across multi-epoch sequences (empty / single-leaf /
subtree-crossing epochs carried through one persisted frontier), and confirms a
tampered boundary cannot reproduce the honest root (the forge-membership guard).

**Measured collapse** (`measure_transition_compress_collapse`, pre=10000 /
epoch=200): tree-transition compressions **326,400 → 6,432 (50.7× fewer)**; native
wall 335 ms → 6.1 ms. In guest cycles that turns the transition term from the
~O(pre) history sweep the campaign flagged (a ~9B-cycle term at realistic pre)
into ~O(epoch) — well under 1B — leaving the in-field spend verify (~1.045B) as
the floor. **Chain-id-breaking:** the state root now commits the frontier and the
image id changes; deploy needs a fresh testnet cut (a separate milestone).

## Statement 2 — trustless R1-T recycle

Folds the storage-rent sweep into the same machinery so it needs no attester
threshold-decryption:

- **Claim:** for a sealing epoch, `expired = public_epoch_total − Σ(migrated)`,
  and `expired` is swept to the emission box — proven in-circuit, so the aggregate
  lost value is computed by the proof, not decrypted by a committee.
- **Public inputs:** `epoch`, `public_epoch_total`, `swept_amount` (= expired),
  the sealed-epoch root, the new emission-pot commitment.
- **Private witness:** the individual migration values (hidden; only their sum
  enters the public `expired`).

This is the direct upgrade of R1-T from "attesters decrypt the aggregate" to "the
proof computes the aggregate" — individual amounts never revealed, no trust.

## The public-input binding (the footgun, from EIP-0045)

`verifyStark` is a *pure* check — it proves the proof is valid for those public
inputs, but it does **not** know they authorize *this* Ergo transaction. The peg
contract MUST bind them, or a valid proof from the mempool can be replayed onto a
different withdrawal. `PegVault` binds: the vault singleton NFT / `SELF.id`, the
output recipient + amount == `withdrawal_recipient`/`withdrawal_amount`, and a
chain/domain tag — all checked in ErgoScript alongside the `verifyStark` result.
(Same discipline the EIP spells out; it's settlement-critical.)

## Prover / verifier interface

- **Prover:** a zkVM guest program (RISC0/SP1/Valida) — or a custom AIR — that
  emits a proof for the statement above. Runs server-side on the settling node.
  *Profile caveat:* EIP-0045 requires an Ext16/Poseidon1 profile that stock zkVMs
  don't emit by default (see `stark-native-decision.md` Q1) — so a *mainnet*
  prover needs that profile; a *dev-net* prototype can use a stock profile with a
  matching self-run verifier.
- **Verifier:** EIP-0045 `verifyStark` on mainnet Ergo (unshipped — see the EIP
  track), or our own verifier in the Rust node for a self-run dev net.

## Build plan (bounded — settlement only, not a private-layer rewrite)

1. ✅ **This statement** — the fixed interface. Done here.
2. **Pick a zkVM + write the guest program** for Statement 1 (withdrawal). Real
   code; server-side proving.
3. **Measure** — proving time/memory (server, fine), proof size, verify cost — the
   spike's Q2/Q3 against a concrete statement. Kill-criteria as before.
4. **`PegVault` `verifyStark` path** — the ErgoScript that calls the verifier and
   binds the public inputs (design → contract).
5. **Verifier** — EIP-0045 when it ships, or a Rust dev-net verifier to prototype
   the whole loop end-to-end ahead of mainnet.
6. **Statement 2 (R1-T)** — once withdrawal settlement works, extend the same
   machinery to the recycle sweep.

## Honest status + gating

**Incremental tree transition: DONE (engine), pending testnet cut.** The O(epoch)
frontier transition above is built, tested (oracle-parity vs full rebuild), and
measured in `engine/src/merkle.rs` — `Frontier` + `settle_tree_transition`. It is
the *Incremental / checkpointed state transition* item from the hardening roadmap
(`HARDENING.md` Tier 2). It is chain-id-breaking (new state-root layout + image
id), so it lands only at a fresh testnet cut; the guest/host swap (drop
`pre_leaves`, pass the committed frontier) is the remaining wiring at cut time.

Step 1 (this) is free and done. Steps 2–3 are a real but *bounded* effort (one
guest program + benchmarks) and can start whenever there's appetite for the
toolchain. Steps 4–6 depend on either EIP-0045 shipping or a self-run dev-net
verifier. None of it blocks — or is blocked by — the Curve Trees core build; the
private-payment layer is untouched. This is the seam that lets "trust a committee"
become "verify the proof" later without redesign.
