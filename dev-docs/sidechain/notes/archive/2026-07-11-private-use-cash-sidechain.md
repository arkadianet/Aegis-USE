# Private USE Cash Sidechain — Implementation Plan

> **For agentic workers:** Prefer phase execution. Spec + design index: `dev-docs/sidechain/DESIGN-INDEX.md`.

**Design status (2026-07-11):** Package complete — ledger/addresses/wallet/lifecycle/node docs written. **Do not scaffold until user says go.**

**Goal:** **Aegis** — merge-mined Ergo sidechain = private USE payment rail (global shielded note pool, Curve Trees + BP, ~15s blocks), dogfoodable with solo MM.

**Architecture:** Stock Ergo holds USE + peg vaults + `SideChainState`. Rust **`aegis-node`** runs the Aegis ledger (`aegis-spec`, `aegis-mm`). Wallet (notes + `aegis…` addresses).

## Global Constraints

- Asset: **USE only** (3 decimals, any multiple of `0.001`).  
- Privacy: **mandatory global shielded pool** — not fixed mix denominations, not rings.  
- Addresses: Bech32m `aegisdev1…` / `aegis…` (see `notes/ledger-wallet-addresses.md`).  
- Unlock: **unsecured** fungible.  
- SC block time: **~15s**.  
- No Scala consensus PR for v1 (Scala does not verify SC proofs).  
- Working docs under **`dev-docs/`** (gitignored). Public commits only when asked.  
- Author: **arkadianet**. Never overwrite `.env`.

## Subsystem map

| ID | Subsystem | Doc / phase |
|---|---|---|
| A | Params | `params.md` — done |
| B | Mainnet peg contracts | GAPS + peg notes |
| C | SC chain-spec / 15s / genesis | Task 3+ ; `sc-node-consensus.md` |
| D | Shielded pool (CT+BP) | `privacy-mechanism-decision.md`, `proving-engine-decision.md` |
| E | MM sidecar | `mm-commit.md` |
| F | Wallet / addresses | `ledger-wallet-addresses.md`, `note-lifecycle.md` |

## Crate sketch

```text
aegis-spec/     # params, genesis, address HRPs, note policy
aegis-node/     # binary
aegis-mm/       # MM sidecar
dev-docs/sidechain/contracts/  # ErgoScript until sibling repo
```

## Phase gates

| Gate | Requirement |
|---|---|
| G0 | Design package + params + gaps + layout — **ready for user review** |
| G1 | SC node boots on 15s spec |
| G2 | Shielded path only for user value; MM produces SC blocks |
| G3 | Testnet USE peg round-trip once |
| G4 | Wallet polish after G3 |

## Immediate next (human)

1. Review **`dev-docs/sidechain/DESIGN-INDEX.md`** + three new notes.  
2. On approval, start **Task 3** scaffold (`aegis-spec` + 15s test).  
3. Do **not** start code before that approval.

## Out of scope

- SigUSD / second stables  
- Scala first-class MM PR (optional later)  
- Matrix on SC / private DEX  
- Mainnet funds beyond dust experiments  

## Historical tasks (Phase 0)

Tasks 0–2 (params, GAPS, layout) were completed earlier in this worktree. See gitignored docs history / DESIGN-INDEX for current truth. Older checkbox steps mentioning fixed note ladders are **obsolete**.
