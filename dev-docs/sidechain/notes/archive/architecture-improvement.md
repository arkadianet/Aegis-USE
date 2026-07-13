# Peg + SC architecture improvement

**Date:** 2026-07-11  
**Stance:** Prefer **existing Ergo patterns**; novelty is the **fully private USE sidechain**, not a new mainnet vault style.

## Verdict

| Layer | Approach |
|---|---|
| Ergo mainnet peg | **Existing** — compose Rosen + ErgoHack + Dexy/AgeUSD patterns |
| Privacy SC ledger | **Novel product** — shielded USE notes + MM + fee pot (no twin deployed) |

Do **not** invent a clever new singleton race for deposits. Do **not** federate mint long-term like Rosen guards unless we explicitly want that trust model for v0.

## Improved Ergo-side shape (concrete)

```text
[1] DepositReceipt script   (many boxes, parallel)     ← Rosen event / Mixer many-box
[2] PegVault singleton NFT  (one live box)             ← Dexy/AgeUSD bank / ErgoHack state
[3] SideChainState singleton NFT                       ← ErgoHack SideChainState.es
[4] FeePot / Emissions singleton (optional separate)   ← Dexy multi-contract style
[5] DoubleRedeem prevention box/NFT                    ← ErgoHack DoubleUnlockPrevention
```

### Deposit (no vault contention)

1. User tx creates **DepositReceipt**: USE `N` + `R4 = sc_dest` + fee output.  
2. Does **not** spend PegVault. Alice and Bob same block = fine (Rosen-like).  
3. SC (permissionless with proof): after confs, mint shielded notes to `sc_dest`, mark receipt id used.  
4. Later consolidator: spend receipts → add USE into PegVault (batch OK).

### Withdraw

1. User burns shielded value `N` on SC.  
2. After SC confs + Ergo anchor: spend **PegVault** → pay claimant `N` USE + vault' with less USE.  
3. DoubleRedeem records burn id (ErgoHack pattern).

### SideChainState

Keep ErgoHack miner-updated singleton. **Add receipt tokens** (their own TODO) so unlocks don’t all dataInput the hot tip box.

## What we take from `/reference`

| Source | Take |
|---|---|
| `ergo-ecosystem/rosen-bridge/contract/.../Lock.es`, `Commitment.es`, `EventTrigger.es` | Multi-box events; observe deposit → act elsewhere |
| `ergo-apps/mixers/` | Parallel user boxes; stealth addressing ideas for `sc_dest` |
| `ergo-apps/protocols/Dexy/`, `sigma-usd/` | Singleton bank NFT; separate helper contracts |
| ErgoHack (in `dev-docs/.../upstream-ergohack`) | SC state + unlock proof skeleton |
| `ergoscript-contracts-rs` | Author/test harness for our scripts |

## Explicitly not copying

| Source | Avoid for peg-in |
|---|---|
| AgeUSD/Dexy bank as the **deposit** input | Everyone races one UTXO (TokenJay pain) |
| Rosen **guards** as required mint authority | Optional v0 federated mint only; target = proof-based mint on SC |

## Novelty (worth doing)

1. **Fully private USE rail** (hide from/to/amount) pegged 1:1 to mainnet USE.  
2. **MM privacy cash** funded by peg fees → pot → per-block USE rewards.  
3. Permissionless **receipt → shielded mint** (Rosen flow without guard custody of mint).

## Non-novelty (keep boring)

- Singleton vault, receipt boxes, SideChainState, double-redeem, Autolykos MM sidecar.

## Doc updates

- Peg-entry CRITICAL + protocol table already point here.  
- Spec decision: **receipt-first deposits; vault for reserve/exits only.**
