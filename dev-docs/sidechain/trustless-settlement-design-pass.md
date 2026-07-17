# Trustless settlement — design pass (2026-07-17)

**Status:** design analysis, no code. Follows the RISC0 feasibility spike
(`aegis-risc0-guest-spike`) which proved the verifier *ports* to a RISC0 guest
but the naive "re-verify every transfer in the STARK" costs ~14B cycles/transfer
(~10⁴× too expensive). This pass maps *why cheap-and-sound is hard* and the only
real leads — so we don't burn effort on approaches that can't work.

## The claim we must prove, and what makes it hard

Statement 1 (peg-out) needs the STARK to prove, from public `(prev_root,
new_root, withdrawal_amount, recipient)`: the batch is valid — **no inflation, no
double-spend, inputs are real, spender authorized** — without revealing shielded
data. The settling node is **untrusted** (it produces the proof), so anything the
proof does NOT enforce is a hole a malicious node can drive value through.

Two properties are the cost drivers, and each fights a different constraint:

1. **Inputs are real + values conserve.** In the current design the cm accumulator
   is **Curve Trees** (elliptic-curve, over the secp/secq 2-cycle) and note values
   live in **Pedersen** commitments. Proving membership + conservation means
   elliptic-curve arithmetic over a *non-native* field inside RISC0's rv32 machine
   = software bigint = the measured blow-up. Range proofs (values ≥ 0) are
   Bulletproofs — same non-native cost.
2. **Spender authorized / correct nullifier.** This part is *cheap* — the nullifier
   is `Poseidon(nk, rho)`, and RISC0 has a Poseidon accelerator. Not the problem.

So the expensive, irreducible part is **re-establishing that each spent note is a
real, unspent, value-correct note** — which today is exactly what the client's
Curve-Trees/Bulletproofs proof establishes, in a form that is brutal to re-verify
in a general zkVM.

## Approaches considered — and why the easy ones fail

- **(A) Add a Poseidon-Merkle accumulator beside Curve Trees; prove membership +
  conservation over Poseidon (cheap).** *Fails.* Conservation needs the note
  *values*; Poseidon commitments aren't homomorphic, so the STARK needs the
  **openings** — which are the note owners' private witness, NOT held by the
  settling node (the whole point of the client zk proof is that the node never
  learns them). The node cannot supply what it does not have without breaking
  privacy. Pedersen commitments *are* homomorphic (conservation = one EC point
  check, no openings) — but that check is non-native EC = back to expensive.
- **(B) Prove only the aggregate totals, verify transfers off-circuit.** *Not
  trustless.* "Off-circuit" = the untrusted node checks them and Ergo trusts that.
  A malicious node includes a fake input and the totals still add up → inflation.
- **(C) Optimistic / fraud-proof settlement.** Sound, but a *different* trust model
  (challenge period + a watchtower), not the STARK-trustless the task wants.

The common wall: **you cannot cheaply re-establish, to an untrusted verifier, what
a Curve-Trees/Bulletproofs proof establishes — because that proof is the expensive
kind and its witness is private.** This is a real tension the "Curve Trees for
payments, STARK for settlement" split did not anticipate: the settlement statement
is *not* a clean zkVM-native aggregate; it inherits the client crypto's cost.

## The real leads (all frontier — validate before building)

1. **Native-cycle aggregation + a single RISC0 wrapper.** Aggregate the batch's
   per-transfer Curve-Trees proofs *over their own secp/secq cycle* (native EC,
   cheap), producing ONE aggregate proof, then wrap that single verification in
   one RISC0 STARK (the expensive non-native step, but paid **once per batch**, not
   per transfer). A 100-tx batch → ~1× the wrapper cost, not 100×. **Open
   question:** Curve-Trees/Bulletproofs are IPA-based, NOT natively foldable like
   Nova/R1CS — is there an aggregation scheme for *these specific* proofs over the
   cycle, and what does the final wrapper actually cost? This is the highest-value
   thing to validate next.
2. **Swap the client proof system for a recursion/zkVM-friendly one** (so
   settlement aggregation is cheap by construction). Cost: heavier *client-side*
   proving — trades away the phone-friendly reason Curve Trees was chosen. A real
   architectural pivot, not a settlement add-on.
3. **A settlement-specific accumulator maintained in-consensus** whose *validity*
   is proven incrementally as blocks are made (IVC), so settlement just references
   it. Still pays the per-transfer re-proof cost somewhere; only helps if combined
   with (1) or (2).

## Honest conclusion

Trustless settlement is not a coding task blocked on plumbing — it's an open
crypto-architecture problem, because the current privacy layer's proofs don't
cheaply re-verify to an untrusted party. Lead (1) is the most promising path that
*keeps the client unchanged*; it is frontier and needs a concrete feasibility
check (can these proofs be aggregated over the cycle, and what's the one-time
wrapper cost) before any build. There is no cheap-and-sound shortcut that reuses
the existing proofs as-is — the earlier "aggregate is STARK-friendly" hope does
not survive contact with the fact that the aggregate still has to re-establish
per-note validity.

## Synthesis with parallel research (2026-07-17) — the argument is now airtight

A second independent research pass reached the same verdict (Lead 1 is not a sound
foundation; the ecosystem pivoted to recursion-friendly proving from day one).
Combining both, the argument sharpens to a **floor**, and the distinction that
matters is aggregation vs accumulation:

- **Aggregation** (Bulletproofs `batch_verify`): **[MEASURED 2026-07-17, refined by
  the Option-A settlement build — supersedes the accumulation spike's headline.]**
  Two things amortize differently. The combined-MSM *point count* is near-flat: the
  ~16k-point generator MSM is shared, so 100 proofs' MSM is only ~1.47× one proof's
  (this was the spike's "1.47×"). BUT the *full* settlement verify the RISC0 guest
  runs also derives each proof's `verification_scalars_and_points` (~79 pts +
  scalars/proof), which does NOT amortize. Measured full-verify:
  **`283 ms shared base (94%) + 17.5 ms/tx marginal (6%)` → 6.75× at N=100** (per-tx
  cost drops 15×). **Strongly sublinear — the right shape for per-epoch batching —
  but NOT batch-independent.** So it is a constant-heavy base + a small linear tail,
  not free amortization; the earlier "batch-independent" was the MSM point-count
  alone, not the work the guest actually does.
- **Accumulation** (Halo/IPA-style): defers to ONE final MSM of size independent of
  N. This DOES amortize N → 1. **But that one MSM is still over secp/secq**, i.e.
  still non-native in RISC0 ≈ the ~14B-cycle (hours) foreign verification.

**The floor (the real wall):** any bridge Ergo checks via `verifyStark` (RISC0)
needs the *final* proof RISC0-native. As long as that proof is over our secp/secq
curves, verifying it costs **≥ one foreign-curve MSM ≈ ~14B cycles ≈ hours** —
irreducible. Accumulation reduces N → 1; it cannot get below 1, and 1 is hours.
**The only way under the floor is a proof whose verifier is RISC0-native (hash/FRI)
— which means changing the client proof system.** That is why every modern private
rollup (Aztec/UltraHonk, Mina/Pickles, Nova/IVC, Plonky-family) uses a
recursion-friendly system from the start rather than wrapping a foreign verifier.

## The pivot is a privacy-LAYER rebuild, not a settlement add-on
"Change the prover" understates it. Aegis's spend proof, note commitments,
nullifier scheme (the reviewed N1 work), and the Curve-Trees accumulator are ALL
Curve-Trees/Bulletproofs over secp/secq. A hash-native pivot **rebuilds the entire
shielded core** — the largest and most-audited component — and discards much of
that audited work. So this is a project-defining decision, not an increment.

- **Pivot target (if taken):** a **FRI/STARK-native** system (Plonky3, or a
  RISC0-guest note circuit) — NOT KZG/Halo2, which reintroduces a trusted setup
  that Curve Trees was chosen to avoid. FRI keeps no-trusted-setup AND is native to
  the RISC0 verifier, so settlement aggregation is then cheap by construction.
- **Client cost of the pivot:** client proving rises from Curve Trees' ~2.9 s to
  ~5–20 s (STARK/Plonky-class) — a real regression, the price of native recursion.

## The honest landscape of Ergo-verifiable bridge trust models
Ranked by how cheaply Ergo can verify them (the thing that actually gates us):
1. **Attester k-of-n** — Ergo verifies sigs via native `atLeast(proveDlog)`. Cheap,
   ships now, majority-honest. (Current: S1c/S1d.)
2. **SPV / aux-PoW** — Ergo verifies Autolykos work + Merkle inclusion (hash-native,
   cheap). PoW-majority trust; proves ORDERING, not monetary validity — complements
   the attester, doesn't replace it.
3. **Optimistic / fraud-proof** — awkward fit: the fraud proof itself would need
   Ergo-side foreign-curve verification (the same floor), so it doesn't cleanly
   dodge the wall.
4. **Full STARK validity (trustless)** — requires the privacy-layer rebuild above.

## Recommendation (ADR)
**Do not pursue trustless by wrapping the current Curve-Trees/Bulletproofs verifier
in RISC0** — the foreign-MSM floor (~hours per batch, at best, via accumulation)
makes it an unsound production foundation, and accumulation can't get under it.
Realistic paths: (a) keep the **trust-minimized bridge** (attester, optionally
hardened with SPV) shipping now, which preserves the audited privacy layer; and
(b) treat **full trustless as a deliberate future** that commits to rebuilding the
shielded core in a FRI/STARK-native system. That rebuild is the real cost of
trustless — it should be a separate, eyes-open decision, not an assumed increment.
The prover architecture, not the settlement layer, is the component that must
change if trustless is the long-term goal.
