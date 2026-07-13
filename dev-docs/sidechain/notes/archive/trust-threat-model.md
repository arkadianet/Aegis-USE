# Aegis — trust & threat model (v1)

**Date:** 2026-07-11  
**Status:** design freeze for dogfood bar; **not** mainnet-value bar  
**Pairs with:** `adversarial-review.md`

## 1. What we are optimizing for

| Phase | Bar |
|---|---|
| **Dogfood / public testnet** | Honest majority of *Aegis MM hashrate*; honest Ergo contracts; users who wait `M`+`N` |
| **Mainnet dust experiment** | Same + audited ErgoScript + no known inflation bugs |
| **Serious TVL** | Needs upgrades called out in adversarial review (not claimed today) |

**Explicit non-claim:** Aegis is **not** a drivechain. Ergo full nodes do not validate Aegis history. Peg security ≠ “Ergo majority must steal.”

---

## 2. Actors & trust

| Actor | Trusted for | Not trusted for |
|---|---|---|
| **User wallet** | Own keys, correct fee/amount in proofs | Other users’ privacy; miner honesty |
| **Aegis full node** (honest) | Verify CT+BP, nullifiers, tree, consensus rules | Ergo consensus |
| **MM miner + `aegis-mm`** | Producing SC blocks + posting `SideChainState` when they win Ergo | Honesty if they dominate MM hashrate |
| **Scala / Ergo full node** | ErgoScript peg + state box rules; Autolykos validity | Aegis tx validity; “correct” SC tip content |
| **Peg watcher** (if any) | Convenience (broadcast PegMint) | Must not be *required* for safety if mint is proof-based |
| **Ergo majority hashrate** | Not forking Ergo / censoring forever | May ignore Aegis entirely |

---

## 3. Trust boundaries (diagram)

```text
                    ┌──────────────────────────────────────┐
                    │         Ergo mainnet (Scala OK)      │
                    │  DepositReceipt · PegVault · Fee ·   │
                    │  SideChainState · DoubleRedeem       │
                    │  Trust: ErgoScript + Ergo PoW        │
                    └───────────────┬──────────────────────┘
                                    │ anchors (miner-posted digest)
                                    │ unlock proofs (hashes / inclusion
                                    │ as scripts allow — NOT full SC verify)
                    ┌───────────────▼──────────────────────┐
                    │              Aegis SC                │
                    │  notes · nullifiers · CT+BP verify   │
                    │  Trust: Aegis consensus + MM hashrate│
                    └──────────────────────────────────────┘
```

**Scala guarantees:** “This Ergo tx follows the peg scripts.”  
**Scala does not guarantee:** “This digest is the honest Aegis tip” or “this burn corresponds to a valid private history.”

**Aegis nodes guarantee (among honest peers):** “Shielded rules held; no double-nullifier.”  
**Aegis does not guarantee:** Peg vault solvency if Ergo contracts are wrong or unlock proofs are under-specified.

---

## 4. Critical invariants

### I1 — Reserve (economic)

```text
PegVault USE  ≥  sum(unspent Aegis note values)
  ± in-flight receipts not yet merged
  ± fee pot accounting (fees are not user principal)
```

Broken ⇒ insolvency / bank run on exits.

### I2 — No double mint

Each DepositReceipt id mints **once** on Aegis.

### I3 — No double redeem

Each PegBurn / burn id unlocks **once** on Ergo.

### I4 — No note inflation on Aegis

ShieldedTransfer conserves value (+ fees to pot/miner only from inputs). PegMint only from proven receipts. Coinbase only from pot.

### I5 — Destination binding

PegMint note(s) encrypt only to receipt `R4 = sc_dest`.

---

## 5. PegMint authority (locked preference)

| Mode | Trust | v1 stance |
|---|---|---|
| **A. Permissionless PegMint** with receipt proof + confs | Anyone can mint; safety in proofs + used-set | **Target** |
| **B. Federated watcher** must sign mint | Watcher liveness + honesty | Dogfood **fallback only** if A slips schedule |

Adversarial review assumes **A** unless noted.

---

## 6. What unlock proofs must check (ErgoScript)

Minimum honest design (detail in contract impl):

1. Burn / nullifier artifact committed on Aegis and present under **anchored** tip digest in `SideChainState` (or receipt-token trail — preferred later).  
2. Value `N` and USE token id.  
3. Burn id fresh in DoubleRedeem.  
4. Depth / height rules (`N` Ergo after anchor; `M` implied by tip age policy).  
5. Pay claimant from **PegVault**, not from a foreign user’s still-earmarked box.

**Gap to close in contracts:** exact inclusion format (header chain vs AVL vs digest list). Wrong format ⇒ fake unlocks or bricked exits. Tracked in `GAPS.md` + adversarial §U*.

---

## 7. Merge-mining trust

| Event | Who decides “truth” |
|---|---|
| Aegis block validity | Aegis peers verifying proofs |
| Which Aegis tip Ergo “recognizes” for unlock | **U1-dogfood:** miner digest + delay + `V_cap`. **U1-strong:** k-of-n attesters (S1) and/or extension commit (S2) — see `design-mitigations.md` |
| User payment finality on Aegis | Aegis confs (no Ergo wait) |
| Peg-out finality | Aegis confs **and** Ergo delay/depth **and** (dogfood cap \| strong attest) |

If unlock only trusts miner digest **without** U1-dogfood/U1-strong controls, **lying tip + vault drain** remains critical. Design forbids shipping vault value without those controls.
---

## 8. Privacy threat model (on Aegis)

| Adversary | Goal | Mitigation |
|---|---|---|
| Global passive ledger observer | Learn from/to/amount | Shielded pool (CT+BP) |
| Peg observer | Link Ergo identity ↔ SC activity | Unavoidable at peg edge; diversify addresses; delay |
| Network observer | Link IPs to txs | Tor/VPN out of band; not consensus |
| Malicious light server | Lie about notes | v1 = full node; light later needs fraud/compare |
| Timing on quiet chain | Heuristic link peg-in → spend | Weak early; grows with set — accept for dogfood |

---

## 9. Availability

| Failure | Effect | Mitigation |
|---|---|---|
| No MM | Aegis stalls; peg-outs stuck | Solo MM dogfood; tips/pot incentive |
| Ergo congested / rent | State/vault boxes at risk | Rent reserve policy (ops) |
| Watcher down (mode B) | Mints stall | Prefer mode A |
| User loses seed | Funds gone | Wallet warnings |

---

## 10. Trust summary (one paragraph)

Users trust **Aegis consensus + their wallet** for private balances and transfers. They trust **ErgoScript peg contracts + Ergo PoW** for custody of USE. They **do not** get Ergo-majority validation of Aegis history. Peg-out safety is only as strong as (unlock script soundness) ∧ (anchor / inclusion rules) ∧ (MM honesty assumptions for tip posting). That is enough for an experiment; it is **not** enough to market as “as safe as holding USE in a singleton vault with no SC.”
