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

## Recommended next step
A focused feasibility check on Lead (1): does a native-cycle aggregation of N
Curve-Trees transfer proofs into one exist/compose, and what is the single RISC0
wrapper's real cost? That number decides whether trustless-with-today's-privacy is
reachable, or whether it forces Lead (2) (a client-crypto pivot). Everything
downstream (the `verifyStark` peg contract, wiring) is unchanged and waits on it.
