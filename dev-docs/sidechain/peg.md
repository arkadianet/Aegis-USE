# Aegis — Ergo peg specification

**Date:** 2026-07-11  
**Status:** canon  
**Params:** [params.md](./params.md) · **Security:** [security.md](./security.md) · **Gaps:** [contracts/GAPS.md](./contracts/GAPS.md)

---

## 1. Stance

Ergo mainnet peg = **compose existing patterns**. Novelty stays on Aegis (shielded notes), not a clever new vault race.

| Pattern source | Take |
|---|---|
| Rosen Lock/Commitment/Event | Multi-box deposit events; observe → act elsewhere |
| Mixers | Parallel user boxes; stealth ideas for `sc_dest` |
| Dexy / AgeUSD bank NFT | Singleton vault; separate helper contracts |
| ErgoHack SideChainState / DoubleUnlock | Tip digest + burn-once |
| TokenJay pain | **Never** race one bank UTXO for deposits |

**Do not:** use AgeUSD/Dexy **bank** as the deposit input. Do not require Rosen **guards** as mint authority long-term (watcher Mode B = broadcast helper only).

### Concurrent deposits (Alice + Bob)

Same Ergo block: each creates own **DepositReceipt** (no PegVault spend) → each is consolidated into the vault independently (permissionless, incentive-aligned) → each mints after `N_mint` Ergo confs **on its consolidation** (the commit-point — see §3.1). Vault contention only on exits / merge, not on peg-in, and consolidation is per-receipt so concurrent deposits never race one box.

## 2. Ergo boxes

| Contract | Role | Pattern |
|---|---|---|
| **DepositReceipt** | Many parallel boxes: `N` USE + `R4 = sc_dest` | Rosen / mixer many-box |
| **PegVault** | Singleton NFT; pooled reserves; exits | Dexy bank NFT |
| **SideChainState** | Miner-updated Aegis tip digest | ErgoHack |
| **UnlockIntent** | Claim marker: binds `(burn_id, N, tip refs, claimant)`, starts `T_delay` clock — **spec TBD** (register map, spam control) | New — see GAPS |
| **FeePot** | Buffer for peg-in fee outputs; consolidator merges into PegVault — **backs the SC emission box** | Dexy multi-contract |
| **DoubleRedeem** | Burn id used once | ErgoHack |

DepositReceipt / PegVault / UnlockIntent / FeePot / consolidator have **no upstream counterpart** — authored fresh; requirements in [contracts/GAPS.md](./contracts/GAPS.md).

Upstream ErgoHack Unlock is **ERG-centric** — adapt carefully; do not cargo-cult per-user lock boxes. ErgoScript spend rights are per-box proposition, not “matching amount.”

## 3. Peg-in

```text
User: create DepositReceipt (N USE + R4=sc_dest) + peg-in fee output
      (does NOT spend PegVault — Alice+Bob same block OK)
Consolidate: anyone (usually the depositor) merges the receipt → PegVault
             — this CONSUMES the receipt box and is the mint COMMIT-POINT
Aegis: after N_mint Ergo confs on the CONSOLIDATION, PegMint the note to
       sc_dest (read from the consumed receipt); mark boxId used
```

- Principal `N` 1:1; fee **on top**, value-scaled (end: `max(1, 1%×N)` — see params.md; `N` is public here, so `%` leaks nothing).  
- R4 immutable while locked.  
- **No god-mint** — see [security.md](./security.md) M1.

### 3.1 Mint commit-point = consolidation (the refund↔mint interlock — RESOLVED 2026-07-12)

**Problem (adversarial review):** if the SC mints against the *lock* (as an earlier draft did), the DepositReceipt lingers as a live, refundable box *after* the note is minted, until a lazy permissionless consolidation runs. A depositor could front-run consolidation and refund the receipt **after already being minted** → keep the note **and** reclaim `N` → inflation.

**Resolution — the SC mints against the CONSOLIDATION, not the lock.** The receipt box has exactly **one terminal spend**: (a) *consolidate into PegVault* (this is what **enables** the mint; the receipt is consumed) **XOR** (b) *refund* (only possible while the box still exists, i.e. never consolidated). They are mutually exclusive because both spend the one box.

- **minted ⟹ consolidated ⟹ box gone ⟹ cannot refund.**
- **refunded ⟹ not consolidated ⟹ never minted.**

The double-claim window is gone: there is no "after-mint, before-consumption" state, because consolidation *is* both the consumption and the mint trigger. Why the other options were rejected: (a-naive) "credit the vault directly at lock" reintroduces the forbidden vault-contention on concurrent deposits (§1, TokenJay); (b) "refund gated on a non-inclusion proof" needs a circular two-way cross-chain dependency (Ergo refund reads SC used-set *and* SC mint reads Ergo refund state). Consolidation-as-commit-point needs neither — mutual exclusion is by box-spend, and the SC only reads Ergo (one direction, the objectivity engine it already runs).

**Who/when:** consolidation is permissionless and **incentive-aligned** — the depositor drives their own peg-in to completion (they want the note), so consolidation is prompt rather than a lazy afterthought. If nobody consolidates, no note is minted and the depositor refunds after timeout.

**aegis-node obligation (the load-bearing change, pass-3):** `verify_pegmint` must prove the **consolidation tx** (the receipt spent into the vault, `sc_dest`/`N` read from the consumed receipt as a spent input), NOT the lock tx; the used-set keys on the receipt `boxId` (unchanged). This refines `g25-pegmint-packaging.md` steps 5–9 to target the consolidation event — flagged for that doc.

**Residual (v1, honest):** once a receipt is consolidated the depositor cannot refund, so if the SC never mints against a valid consolidation (chain down / censored), the depositor's value sits **safely in the vault** (I1 holds, over-reserved — no theft/inflation) but they hold no note until the mint proof is submitted. This is a liveness/UX edge, not a security hole; recovery = anyone submitting the (deterministic) mint proof for the confirmed consolidation. No new trust assumption beyond the existing objectivity/`V_cap` model; **this bug is closed in v1 without needing U1-strong attesters.**

### Fee layout (preferred = A)

Same Ergo tx: output0 = receipt `N` USE + R4; output1 = `peg_in_fee` USE **at the FeePot script address** (anyone may later sweep/merge fee boxes into the pot singleton — TBD confirm). Avoid locking `N+fee` in one box unless carefully tested.

## 4. Peg-out (unsecured fungible)

```text
Note holder: PegBurn N on Aegis
→ Ergo UnlockIntent (burn id, N, tip refs)
→ wait T_delay (+ M Aegis confs, N Ergo depth, attest if U1-strong)
→ PegVault pays claimant N − peg_out_fee USE (fee-worth stays in vault, credited to SC emission box at burn)
→ DoubleRedeem records burn id
```

Exit rights follow **who holds notes now**, not who deposited. Never: “any burn spends Alice’s still-earmarked box.”

### Failures / refunds

| Case | Handling |
|---|---|
| Receipt never minted | Ergo refund on receipt after timeout (GAPS) |
| Double PegMint | Rejected — `boxId` used-set |
| Double redeem | DoubleRedeem |
| Lost mnemonic | Unrecoverable |

### Should-fix soon

**Receipt tokens / update counter** so unlocks need not all race the hot `SideChainState` tip box (see GAPS).

## 5. Register map (receipt)

| Field | Content |
|---|---|
| tokens | USE amount `N` |
| R4 | `sc_dest` payload (`Coll[Byte]`) — immutable while locked |
| R5 | Optional memo |
| R6 | Peg version / network id |

Register maps for **UnlockIntent** and **DoubleRedeem** are unwritten — tracked in [contracts/GAPS.md](./contracts/GAPS.md).

## 6. Economic invariant

```text
spendable_reserve = PegVault.USE + Σ(unmerged receipts.USE) + Σ(unmerged FeePot.USE)
spendable_reserve ≥ Σ(unspent note values) + emission_box_balance + pending_burns_accounting
```

Peg fees **back the SC emission box** (pot credits are minted against them at PegMint/PegBurn — see [aegis-spec.md](./aegis-spec.md) §11), so FeePot counts toward reserve and the pot counts as a liability. Ops: metric + halt peg-out RPC if broken.

## 7. Unlock / tip policy

Miner-posted `SideChainState` alone is **not** enough for serious TVL.  
**U1-dogfood:** `V_cap` + `T_delay` + honest UI.  
**U1-strong:** k-of-n attesters (preferred) and/or extension commit.  
Full text: [security.md](./security.md).

## 8. Implementation gate

No public vault until [GAPS.md](./contracts/GAPS.md) must-fix is green + USE token id checks + rent endowment (`R_rent`).
