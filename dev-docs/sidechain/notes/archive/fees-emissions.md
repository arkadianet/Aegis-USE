# Fee & emissions design — privacy cash SC

**Status:** provisional freeze (end-deployment targets set; dogfood may use lower)  
**Invariant:** never mint unbacked USE. All miner subsidies come from real USE paid as fees.

## Goals

1. **Everyday SC use stays OK** — coffee-scale pays aren’t killed by fees.  
2. **Large transfers pay more** — value moved ↔ fee (with a floor for spam).  
3. **Privacy costs at the bridge** — entering the private rail is deliberately not free.  
4. **Worth MM’ing** — pot-funded block rewards + tx tips.  
5. **Scales with use** — more peg/tx volume → healthier pot; idle → subsidy → 0.

## Three fee streams

```text
  SC payment txs ──► miner tip (most) + pot skim
  Peg in / out   ──► emissions pot (100%)
                         │
                         ▼ per SC block: min(R_target, pot) → MM miner
```

| Stream | Role |
|---|---|
| **A. SC tx fee** | Spam resistance + pay for inclusion; scales with transfer size |
| **B. Peg fee** | “Pay for privacy” entry/exit; funds emissions pot |
| **C. Storage rent (later)** | Long-term box hygiene |

Principal peg remains **1:1**. Fees are **on top**, always shown in UI.

---

## A — SC transaction fees

### End-deployment rule (recommended)

```text
fee = max( floor, rate * amount_sent )
```

| Param | End target | Notes |
|---|---|---|
| `tx_fee_floor` | **`0.03` USE** (~3¢) | Spam floor; coffee still fine |
| `tx_fee_rate` | **`0.001` (0.1%)** | Scales with value |
| `tx_fee_per_weight` | TBD | Extra for heavy mix proofs |
| `tx_fee_to_miner` | **90%** | |
| `tx_fee_to_pot` | **10%** | |

**Examples (1 USE ≈ $1):**

| Send | Floor | 0.1% | **Fee charged** |
|---|---|---|---|
| Coffee `5.6` | 0.03 | 0.0056 | **`0.03`** (floor wins) |
| `50` USE | 0.03 | 0.05 | **`0.05`** |
| Car `300` USE | 0.03 | 0.30 | **`0.30`** |
| `3000` USE | 0.03 | 3.0 | **`3.0`** |

So yes: **% scaling is the right idea**, with a **3¢ floor** so dust txs aren’t free.

Flat-only 3¢ undercharges whales; pure 0.1% undercharges (and under-deters) tiny spam. Hybrid fixes both.

### Privacy warning → resolved under full privacy

With **hidden amounts**, `%` fees are computed by the prover inside the spend. Verifiers check fee policy without learning `amount`. Any leftover **public** miner fee must be fixed/bucketed only.

See `full-privacy.md`.

---

## B — Peg / bridge fees (“pay for privacy”)

Entering the private rail should hurt a little. **10 USE peg-in** is reasonable for end deployment.

| Param | End target | Notes |
|---|---|---|
| `peg_in_fee` | **`10` USE** | Pay to enter privacy rail; fills pot fast |
| `peg_out_fee` | **`1` USE** | Exit isn’t free; still << entry so people aren’t trapped |
| Destination | Emissions pot on SC | 100% |

UI: “Bridge **100 USE** + **10 USE** privacy fee.” Vault reserves **100** only.

### Why not 1 USE entry

Works for onboarding experiments; weak “pay for privacy” signal and slow pot fill. Keep **10** as end target; dogfood can start at 1.

### Sustainability sketch (end targets)

At `R_target = 0.01` USE/block ≈ **57.6 USE/day** full subsidy:

- One peg-in at **10 USE** fee ≈ **~4 hours** of full block subsidy  
- ~6 peg-ins/day sustain continuous full `R_target` (before tx skim / peg-outs)  

Much healthier than 1 USE entry (~58 peg-ins/day).

---

## C — Emissions pot → per-block reward

```text
R_target = 0.01 USE          # ~1¢ / 15s block when pot healthy
R_paid   = min(R_target, pot_balance)
```

No unbacked USE. Empty pot ⇒ tips only.

Optional later: raise `R_target` with EMA(peg volume). v1 keeps fixed target + pot cap.

---

## What miners earn

| Source | When |
|---|---|
| SC tx tips (90%) | Scales with payment size + count |
| Pot block reward | While pot > 0 (bridge-funded) |
| Ergo rewards | Unchanged when they win Ergo |
| Anchor tx fee on Ergo | When posting `SideChainState` |

---

## Explicit non-goals

- Unbacked USE inflation  
- Speculative gas token  
- Cleartext fee that leaks private send amounts  
- Guaranteed subsidy with no bridge usage  

---

## Param freeze

| Key | Dogfood OK | End deployment |
|---|---|---|
| `tx_fee_floor_use` | `0.01`–`0.03` | **`0.03`** |
| `tx_fee_rate` | `0` until private fee path | **`0.001` (0.1%)** |
| `tx_fee_miner_share` | `0.90` | `0.90` |
| `tx_fee_pot_share` | `0.10` | `0.10` |
| `peg_in_fee_use` | `1.0` | **`10`** |
| `peg_out_fee_use` | `0.1` | **`1`** |
| `block_reward_target_use` | `0.01` | `0.01` |
| `block_reward_source` | pot only | pot only |
| `fee_fingerprint_mitigation` | required before enabling `%` | required |
