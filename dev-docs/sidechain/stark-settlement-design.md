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
  - `prev_state_root` — the Aegis state (note-commitment root + nullifier-set
    accumulator + peg reserve) the batch starts from.
  - `new_state_root` — the state after the batch.
  - `withdrawal_amount`, `withdrawal_recipient` — the USE to release on Ergo.
  - `epoch` / `height` binding — anti-replay / freshness.
- **Private witness (hidden in the proof):** the batch's shielded transfers,
  the burn note openings, the membership paths — none revealed.
- **What Ergo does with it:** the `PegVault` contract calls `verifyStark(proof,
  publicInputs, imageId, vmType, costParams)` and, only if it returns true **and**
  the public inputs are bound to this transaction (below), releases
  `withdrawal_amount` to `withdrawal_recipient`. No attester, no `V_cap`.

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

Step 1 (this) is free and done. Steps 2–3 are a real but *bounded* effort (one
guest program + benchmarks) and can start whenever there's appetite for the
toolchain. Steps 4–6 depend on either EIP-0045 shipping or a self-run dev-net
verifier. None of it blocks — or is blocked by — the Curve Trees core build; the
private-payment layer is untouched. This is the seam that lets "trust a committee"
become "verify the proof" later without redesign.
