# Aegis — security (trust, adversarial, mitigations)

**Date:** 2026-07-11  
**Status:** canon (merges trust-threat-model + adversarial-review + design-mitigations)  
**Params:** [params.md](./params.md)

---

## 1. Security bar by phase

| Phase | Bar |
|---|---|
| Dogfood / testnet | U1-dogfood + M1–M5 |
| Mainnet dust | Same + GAPS green + `V_cap` |
| Serious TVL | **U1-strong** + crypto review + audit |
| “Trust-minimized bridge” marketing | Not claimed in v1 |

**Non-claim:** Not a drivechain. Ergo nodes do not validate Aegis history.

## 2. What Scala guarantees vs does not

| | |
|---|---|
| **Does** | ErgoScript peg/state validity; Autolykos Ergo blocks |
| **Does not** | Aegis shielded tx validity; honesty of miner-posted tip digest; note non-inflation |

## 3. Actors

| Actor | Trusted for | Not for |
|---|---|---|
| User wallet | Own keys | Others’ privacy |
| Honest `aegis-node` | CT+BP, nullifiers, rules | Ergo consensus |
| MM + `aegis-mm` | Blocks + state updates when they win Ergo | Honesty if they dominate MM |
| Attesters (U1-strong) | Tip/burn attestations | Vault custody alone |
| Scala Ergo | Peg scripts | Aegis execution |

## 4. Invariants

- **I1 Reserve:** `vault + unmerged receipts + unmerged fee boxes ≥ unspent notes + emission_box + pending_burns_accounting` — peg fees back the SC emission box, so FeePot is reserve and the pot is a liability.  
- **I2** No double mint (`boxId` used-set).  
- **I3** No double redeem (DoubleRedeem).  
- **I4** No note inflation.  
- **I5** PegMint binds to receipt R4.

## 5. Top adversarial findings → mitigations

| ID | Attack | Mitigation |
|---|---|---|
| **C1** | Lying `SideChainState` tip → fake burn → drain vault | **U1-dogfood:** `V_cap` + `T_delay` + UI honesty. **U1-strong:** k-of-n attesters (S1) before raising cap; S2 extension spike |
| **A2** | Mint without real lock | **M1** no god-mint; proven receipt + `N_mint` confs |
| **A1** | Double mint | Used-set by `boxId` |
| **A3** | R4 malleation | Immutable R4 + bind mint |
| **A4** | Notes without vault reserve | **M2** spendable_reserve |
| **B1–B3** | Proof/nullifier bugs | Full consensus verify; literature crypto; review before TVL |
| **E1** | Broken Unlock copy | GAPS gate; new vault paths only |
| **E2** | Rent kills state/vault | Rent endowment + top-up |
| **B5** | Quiet-chain linking | Product honesty (M6) |

Full catalog: [security-appendix.md](./security-appendix.md).

**Mitigation ids (legend):** M1 PegMint provenance (§7) · M2 reserve accounting (I1) · **M3 = the U1 unlock ladder (§6)** · M4 ledger soundness (B1–B3) · M5 contracts/rent/token-id gate · M6 privacy honesty · M7 wallet footguns (§7b). Numbering from archived `notes/archive/design-mitigations.md`; gates that say "M1–M2, M4–M5, U1-dogfood" cover all of M1–M7 (M3 ≡ U1, M6–M7 are copy/UX requirements).

## 6. U1 unlock ladder (detail)

### Dogfood (required for any vault value)

1. Vault hard cap `V_cap` (params: 1000 USE).  
2. `M` + `N` confs; do not weaken casually.  
3. UnlockIntent → wait `T_delay` (720 Ergo blocks ≈ 1 day) before pay.  
4. UI: exits trust Aegis MM anchors, not Ergo-majority SC validation.  
5. Known-MM dogfood; no “trustless bridge” marketing.  
6. **Solo MM reality:** SideChainState advances on Ergo wins (~1 Ergo block/day solo) ⇒ peg exits stay Ergo-paced until more MM joins. User pays on Aegis do not wait on Ergo.

**`V_cap` ↔ hashrate coupling:** SC hashrate defends between-peg finality, not the vault — but reorg-assisted attacks get cheaper as MM participation falls. Raise `V_cap` only when (a) U1-strong is live **and** (b) out-mining the participating MM set for `M` (120 blocks ≈ 30 min) is expensive relative to `V_cap` (track participation as % of Ergo hashrate).

### Strong (required to raise `V_cap`)

> **Retirement note (2026-07-17, operator decision):** S1 (k-of-n attesters)
> was built (S1a–S1d), red-reviewed SOUND, and then **RETIRED from `main`** —
> the bridge is the trustless verifyStark settlement design
> ([stark-settlement-design.md](./stark-settlement-design.md)); the committee
> machinery is preserved at git tag `attester-bridge-final`. S1 below is
> historical.

**S1 (preferred):** k-of-n attesters sign `(network_id, aegis_height, tip_digest, burn_id, N)`; unlock requires threshold + DoubleRedeem + delay. Attester set lives in SideChainState or an **AttestRegistry** NFT box. Threshold progression: dogfood **2/3** → testnet **3/5** (params start at 2/3). Attesters run `aegis-node`; **≠** sole vault spenders.

**S2:** Ergo extension commits Aegis header (parallel spike).  
**S3:** Fraud window / bonds — research.  
**S4:** Burn Merkle root in state — pairs with S1/S2; alone insufficient.

### Unlock ErgoScript must-check (minimum)

1. Burn / nullifier under **anchored** tip digest (or later receipt-token trail).  
2. Payout = `N − peg_out_fee` + USE token id (fee-worth stays in vault, mirrored as SC pot credit).  
3. Burn id fresh in DoubleRedeem.  
4. Depth / height (`N` Ergo after anchor; `M` via tip-age policy).  
5. Pay claimant from **PegVault** only — never a foreign still-earmarked box.

## 7. PegMint rules (M1)

No admin mint. PegMint carries confirmed receipt bytes; used-set = `boxId`; R4 binding.  
**Watcher (Mode B):** may only *broadcast* an otherwise-valid PegMint. Shortcut mint without receipt proof body = **release blocker**.  
**Objectivity:** "trusted Ergo node" is not consensus — a from-genesis validator must check every PegMint identically, so PegMint must ultimately embed a self-contained Ergo proof (header segment + inclusion; SPV-in-consensus, [engineering.md](./engineering.md) §3). Dogfood may run declared operator-mode under caps; do not market it as objective.

## 7b. Wallet footguns (M7)

Refuse wrong HRP / Ergo `9…` on Aegis send. IVK export requires typed warning. Peg-out UI shows `T_delay` and attester policy when S1 active.

## 8. Release gates

| Gate | Requirement |
|---|---|
| Scaffold | Design canon readable |
| Dogfood vault | M1–M2, M4–M5, U1-dogfood |
| Raise `V_cap` | U1-strong S1 or S2 + reviews |
| Trust-minimized marketing | S3-class — **not v1** |

## 9. Accept for dogfood (explicit)

Solo MM; quiet-chain heuristics; full-node wallet; federation for exits until S2/S3.

## 10. Full adversarial catalog

See [security-appendix.md](./security-appendix.md) (archived attack-by-attack tables). Top findings remain in §5.
