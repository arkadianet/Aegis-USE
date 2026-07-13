# Aegis — design index

**Date:** 2026-07-11  
**Status:** Design index **superseded as primary** by [README.md](./README.md) (consolidated canon). This file kept until archive.

Read this first; drill into notes for detail.

---

## One-liner

**Aegis** — merge-mined Ergo sidechain for private **USE** payments: global shielded note pool (Curve Trees + Bulletproofs), ~15s blocks, 1:1 peg via ErgoScript receipts/vault. Addresses `aegis1…`. Crates `aegis-spec` / `aegis-node` / `aegis-mm`. Stock Scala OK for mainnet.

---

## Locked decisions

| Topic | Decision | Doc |
|---|---|---|
| **Chain name** | **Aegis** | this index, `params.md` |
| Asset | USE only (3 decimals, `0.001`) | `params.md` |
| SigUSD / other stables | Out of scope | spec |
| Privacy shape | Mandatory **global shielded pool** | `privacy-mechanism-decision.md` |
| Proving engine | **Curve Trees + BP(+)**; Halo2 fallback | `proving-engine-decision.md` |
| Rings / ZeroJoin cleartext | Rejected | same |
| Addresses | Bech32m `aegisdev1…` / `aegis…`; not Ergo `9…` | `ledger-wallet-addresses.md` |
| Wallet | Notes + IVK sync; mnemonic | same |
| Note flow | Mint / transfer / burn | `note-lifecycle.md` |
| Peg | DepositReceipt (parallel) + PegVault + SideChainState + DoubleRedeem | `architecture-improvement.md`, `peg-entry-ergoscript.md` |
| Unlock | Unsecured fungible (note holder exits) | peg notes |
| Fees / emissions | Peg 10/1 USE; SC `max(0.03,0.1%)`; pot → `min(0.01,pot)`/block; no unbacked USE | `fees-emissions.md` |
| Scala role | Peg + mining API + SideChainState only; **no** SC proof verify | `proving-engine-decision.md` |
| MM | Sidecar; Autolykos; SC pay in USE | `mm-commit.md`, `sc-node-consensus.md` |
| Trust / threats | Dogfood bar; Scala ≠ SC verify | `trust-threat-model.md` |
| Adversarial review | Peg-out tip lie = top risk | `adversarial-review.md` |
| **Design mitigations** | M1–M7, U1-dogfood / U1-strong S1 | `design-mitigations.md` |
| Layout | **`aegis-spec` / `aegis-node` / `aegis-mm`** | `layout.md` |
| Block time | ~15s | `params.md` |
| Confs | M=120 SC, N=10 Ergo (provisional) | `params.md` |

---

## Doc map

| Path | Role |
|---|---|
| `specs/2026-07-11-privacy-mm-sidechain-design.md` | Master product spec |
| `plans/2026-07-11-private-use-cash-sidechain.md` | Impl plan |
| `sidechain/params.md` | Frozen numbers |
| `sidechain/contracts/GAPS.md` | ErgoScript gaps |
| `sidechain/notes/design-mitigations.md` | Locked mitigations for red-team findings |
| `sidechain/notes/trust-threat-model.md` | Trust boundaries, invariants |
| `sidechain/notes/adversarial-review.md` | Red-team attacks + TVL blockers |
| `sidechain/notes/ledger-wallet-addresses.md` | **Addresses, keys, wallet, ledger state** |
| `sidechain/notes/note-lifecycle.md` | Mint / spend / burn |
| `sidechain/notes/sc-node-consensus.md` | Node, P2P, MM, genesis |
| `sidechain/notes/privacy-mechanism-decision.md` | Global pool lock |
| `sidechain/notes/proving-engine-decision.md` | CT+BP lock |
| `sidechain/notes/full-privacy.md` | Privacy bar |
| `sidechain/notes/architecture-improvement.md` | Peg pattern composition |
| `sidechain/notes/fees-emissions.md` | Fee math |
| `sidechain/notes/mm-commit.md` | MM encoding spike |
| `sidechain/notes/layout.md` | Crate layout |

---

## Still provisional (OK to implement around)

- Testnet USE token id  
- Exact Bech32 payload bytes / diversifier  
- Exact proof wire format  
- Dogfood fee discounts  
- Fine-tune `M,N` after timing experience  
- Unlock inclusion crypto (beyond “miner digest”) — **U1-dogfood now; U1-strong before serious TVL** (`design-mitigations.md`)

These do **not** reopen the product shape.

---

## Review ask

Approve design package including **trust-threat-model** + **adversarial-review**. Scaffold OK for dogfood; mainnet value blocked on adversarial must-fix list.
