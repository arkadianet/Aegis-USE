# Aegis — design mitigations (adversarial follow-up)

**Date:** 2026-07-11  
**Status:** **LOCKED for v1 design** (closes “can we mitigate at design stage?”)  
**Inputs:** `adversarial-review.md`, `trust-threat-model.md`  
**Rule:** Prefer mitigations that are enforceable in specs/contracts/process — not vibes.

---

## Principle

Split mitigations by phase:

| Phase | Allowed residual risk |
|---|---|
| **Dogfood** | Solo MM, tiny vault, operator-known set |
| **Public testnet** | Same rules as mainnet-dust; watchers optional |
| **Mainnet dust** | Caps + full mint/unlock rules below |
| **Serious TVL** | Requires **U1-strong** (not only U1-dogfood) |

---

## M1 — PegMint provenance (kills A2, helps A1/A3)

### Locked

1. **No admin / god mint.** No operator key that can create notes without an Ergo receipt.  
2. **PegMint inputs:** serialized DepositReceipt box (id, tokens, R4, proposition hash) + proof of **≥ `N_mint` Ergo confirmations** (provisional: same family as unlock `N`, default **10**).  
3. **Used-set key = Ergo `boxId`.** Duplicate PegMint ⇒ invalid Aegis block.  
4. **R4 binding:** note commitment(s) must encrypt to receipt `R4`; script forbids R4 mutation on receipt.  
5. **Ergo view:** dogfood may use a local Ergo node; the *consensus rule* is still “bytes match a confirmed box,” not “watcher said so.”

### Mode B (watcher)

Allowed **only** as a *broadcast helper* that submits an otherwise-valid PegMint. Watcher **must not** be able to mint without the receipt proof body. If impl ships a shortcut, it is a **release blocker**.

### Status

| Adv | Mitigation | Phase |
|---|---|---|
| A2 | M1 | all |
| A1 | M1 used-set + confs | all |
| A3 | M1 R4 bind | all |

---

## M2 — Reserve accounting (kills A4 / I1 drift)

### Locked

```text
spendable_reserve = PegVault.USE + Σ(unmerged DepositReceipt.USE)
spendable_reserve >= Σ(unspent note values) + pending_burns_accounting
```

- PegMint may occur **before** merge **iff** the receipt still counts in `spendable_reserve`.  
- Node rejects tips that break the invariant when fully auditable (vault + receipt set + note supply commitments).  
- **FeePot is separate** — never counted as user principal (E4).

### Ops

Continuous check in `aegis-node` (metric + halt peg-out RPC if broken).

### Status

| Adv | Mitigation | Phase |
|---|---|---|
| A4 | M2 | all |
| E4 | separate FeePot | all |

---

## M3 — Peg-out / lying tip (kills C1 — layered)

This is the hard one. Design locks a **ladder**, not a single fantasy.

### U1-dogfood (required before any vault USE > dust)

1. **Vault TVL cap** in PegVault script (or spend path): e.g. max `V_cap` USE total (param; dogfood start **100–1000 USE**).  
2. **Long exits:** `M` SC confs + `N` Ergo depth (already in params); do not lower for convenience.  
3. **Unlock delay:** after UnlockIntent, wait `T_delay` Ergo blocks (provisional **720** ≈ 1 day @ 2m) before vault pays — time for operators/watchers to halt if tip looks wrong.  
4. **Explicit UI trust copy:** “Exits trust Aegis MM anchors; not Ergo-majority SC validation.”  
5. **Known-MM dogfood:** document operator set; no marketing as trust-minimized bridge.

### U1-strong (required before raising `V_cap` / serious TVL)

Pick **at least one** primary (design preference order):

| Option | Idea | Pros | Cons |
|---|---|---|---|
| **S1 — Attested tip (k-of-n)** | Unlock needs k signatures from Aegis full-node attesters that digest D is on their best chain | Implementable without Scala consensus change | Federation trust |
| **S2 — Extension commit** | Winning Ergo block commits Aegis header hash in extension; script checks linkage | Stronger binding miner↔tip | Template/API work; still not full verify |
| **S3 — Fraud window** | Bonded tip poster; anyone submits fraud proof on Ergo within window | Trust-minimizing direction | Hard ErgoScript; research |
| **S4 — Burn accumulator in state** | SideChainState carries burn-set root; unlock = Merkle proof of burn | Stops random claims; **does not alone stop lying root** | Must pair with S1/S2/S3 |

**Locked preference:** ship **U1-dogfood** now; implement **S1 (k-of-n attestations)** as first U1-strong path; keep S2 as parallel spike; S3 research later.

**S1 detail (design):**

- Attester set in SideChainState or separate AttestRegistry box (NFT).  
- Threshold `k` (e.g. 2-of-3 dogfood → 3-of-5 testnet).  
- Attestation signs `(network_id, aegis_height, tip_digest, burn_id, N)`.  
- Unlock script: vault pay only if valid threshold sigs + DoubleRedeem fresh + delay elapsed.  
- Attesters run `aegis-node`; **not** the same as vault custodian (they cannot spend vault alone).

### Status

| Adv | Mitigation | Phase |
|---|---|---|
| C1 | U1-dogfood | dogfood/dust |
| C1 | U1-strong S1 | before serious TVL |
| C2 | DoubleRedeem (already) | all |
| C3 | pooled vault only (already) | all |
| C4 | delay + multi-MM + attesters | testnet+ |
| C5 | single N binding in script | all |

---

## M4 — Aegis ledger soundness (B1–B3)

### Locked

1. Consensus verifies **membership + range + balance + nullifier** for every spend; no “trust mempool.”  
2. Nullifiers are **forever** on a given fork; reorgs drop the fork’s spends with the blocks.  
3. Peg-out only after `M` confs on the **canonical** chain wallet sees from ≥1 honest peer policy (multi-peer later).  
4. Crypto: CT+BP constructions from literature; **no custom proving system**; external review before raising `V_cap`.

### Status

| Adv | Mitigation | Phase |
|---|---|---|
| B1–B3 | M4 | all |
| B6 | multi-peer + compare tip to attested digest on withdraw | testnet+ |

---

## M5 — Contracts / rent / token id (E1–E3)

### Locked

1. **No public vault** until `GAPS.md` must-fix is green.  
2. **USE token id** hardcoded from `params.md`; reject others.  
3. **Rent endowment:** SideChainState + PegVault + FeePot + DoubleRedeem carry ≥ `R_rent` ERG (param TBD) + top-up runbook.  
4. Upstream Unlock **not** copied for USE exits; new vault spend paths only.

### Status

| Adv | Mitigation | Phase |
|---|---|---|
| E1 | GAPS gate | before dust vault |
| E2 | rent endowment | before dust vault |
| E3 | hardcoded token id | all |

---

## M6 — Privacy expectations (B5)

### Locked (product honesty)

- Privacy claim = **between peg-in and peg-out** on Aegis.  
- Peg edges public; quiet-chain heuristics acknowledged.  
- Optional wallet “wait / split” UX later — not consensus.

---

## M7 — Wallet footguns (F1–F3)

### Locked

- Refuse wrong HRP network; refuse Ergo `9…` on Aegis send.  
- IVK export requires typed warning.  
- Peg-out UI shows delay `T_delay` and attester policy when S1 active.

---

## Parameter additions (`params.md` to absorb)

| Key | Provisional dogfood | Notes |
|---|---|---|
| `N_mint` | 10 | Ergo confs before PegMint |
| `V_cap` | 1000 USE | Vault hard cap until U1-strong |
| `T_delay` | 720 Ergo blocks | Unlock delay |
| `attest_k` / `attest_n` | 2 / 3 | When S1 enabled |
| `R_rent` | TBD | Min ERG on critical boxes |

---

## What we deliberately still accept (dogfood)

- Solo / tiny MM (D1/D4)  
- No drivechain security  
- Full-node wallet only  
- Attesters = federation **until** S2/S3  

Accepting these in a README is part of the mitigation (no false advertising).

---

## Updated release gates

| Gate | Requirement |
|---|---|
| Scaffold | Design package + this doc |
| Dogfood vault | M1–M2, M4, M5, **U1-dogfood** (cap + delay + copy) |
| Raise `V_cap` | **U1-strong S1** (or S2) live + crypto review + GAPS audit |
| “Trust-minimized bridge” marketing | S3 or equivalent — **not claimed in v1** |

---

## Self-check

- [x] Every **Critical** in adversarial review has a design mitigator  
- [x] C1 has dogfood path **and** strong path (not hand-waved)  
- [x] No god-mint  
- [x] Invariant explicit  
- [x] Honest about federation for exits until stronger commit
