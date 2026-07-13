# Doc consolidation status

**Date:** 2026-07-11  
**Policy:** New canon is primary. Legacy moved to `notes/archive/`.

## New canon

| New | Replaces |
|---|---|
| `README.md` | `DESIGN-INDEX.md` |
| `aegis-spec.md` | greenfield spec + ledger/wallet/lifecycle/node/fees/layout/mm-commit |
| `peg.md` | architecture-improvement + peg-entry |
| `privacy.md` | privacy-mechanism + proving-engine + full-privacy (research archived) |
| `security.md` | trust-threat + design-mitigations |
| `security-appendix.md` | adversarial-review (full catalog kept live) |
| `params.md` | numbers (+ fee gates from fees-emissions) |
| `../plans/aegis-impl.md` | `../plans/2026-07-11-private-use-cash-sidechain.md` |

## Still live (not archived)

- `contracts/GAPS.md`
- Canon files listed above

Upstream ErgoHack clone moved to `~/coding/reference/ergo-ecosystem/ergohack-sidechain/` (2026-07-12).

## Verification checklist

- [x] Chain name Aegis + HRPs + crate names  
- [x] USE-only, 3 decimals, token id  
- [x] Global pool + CT+BP  
- [x] Receipt + vault peg + unsecured exit  
- [x] U1-dogfood / U1-strong + no god-mint  
- [x] Fees / emissions + dogfood table (fee model revised in round 3 — edge-`%` + flat SC)  
- [x] Scala does not verify SC proofs  
- [x] MM commit provisional rule + Hybrid B layout  
- [x] UnlockIntent, R_rent, pending_burns, AttestRegistry, unlock must-check  
- [x] Solo MM ~1 Ergo block/day exit latency noted  
- [x] Operator checklist + protocol pattern map  
- [x] Legacy archived under `notes/archive/`  

**If conflict:** `params.md` → `security.md` → `engineering.md` (feasibility) → `aegis-spec.md`.

## Round 2 (2026-07-12) — audit + adversarial scale review

- On-chain verification of USE token facts; emission recorded in base units.  
- `upstream-ergohack/` moved to `~/coding/reference/ergo-ecosystem/ergohack-sidechain/`.  
- GAPS widened: new-contract table (DepositReceipt/PegVault/UnlockIntent/FeePot/DoubleRedeem/consolidator); contracts authored **fresh**, upstream reference-only.  
- New canon: `engineering.md` — reuse matrix, missing consensus specs, W1 proving-stack correction (`ergo-curve-trees` ≠ payment stack), workstreams, kill criteria.  
- Fee contradiction resolved: v1 = public fixed/bucketed fee; hidden `%`-fee research-gated.  
- Plan resequenced: **G1.5 proving spike before any node code**.

## Round 3 (2026-07-12) — fee redesign + design-stage stance

- **Nothing is frozen**: "locked/frozen" language replaced with "decided (design stage)" across docs; README states the stance.  
- **Fee redesign**: value-scaled `%` moved to peg edges (`N` public anyway; where vault risk is created); on-SC fee flat + amount-independent + uniform tx shape = **standing privacy rule** (replaces `fee_fingerprint_mitigation` gate). Rejected alternatives recorded in `notes/archive/fee-privacy-alternatives.md` (public `%` = amount oracle; hidden-`%`-paid = open research; `%`-burn = funds no security).  
- aegis-spec §12 clarified: system paths are **native Rust consensus rules — no ErgoScript interpreter on Aegis**; ErgoScript lives on the Ergo peg side only.

## Round 4 (2026-07-12) — peg rate final + emission box mechanics

- Peg fees set to **1% each way** (operator decision — premium pricing); SC tx flat `0.03`; block reward `min(0.01, pot)`.  
- **SC tx fees → emission box 100%** (operator decision); miner income = block reward only. 90/10 split removed.  
- **Emission box specified** (aegis-spec §11): public integer balance in SC state, header-committed; peg fees back it (credits minted at PegMint / retained at PegBurn); coinbase draws on parent balance; I1 extended (FeePot = reserve, pot = liability).  
- **Inclusion bonus decided**: coinbase = `min(pot, 0.01 + 0.01 × txs_included)` — per tx: 1¢ to includer, pot nets +2¢ (β = ⅓); kills empty-block free-riding while staying pot-funded.
