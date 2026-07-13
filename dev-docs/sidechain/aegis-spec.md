# Aegis — product & ledger specification

**Date:** 2026-07-11  
**Status:** canon (consolidates prior greenfield spec + ledger/wallet/node notes)  
**Author:** arkadianet  
**Numbers:** [params.md](./params.md) · **Peg:** [peg.md](./peg.md) · **Privacy:** [privacy.md](./privacy.md) · **Security:** [security.md](./security.md)

---

## 1. One-liner

**Aegis** is a merge-mined Ergo **sidechain** for **fully private USE payments**: hide sender, receiver, and amount on-chain; ~**15s** blocks; 1:1 peg to mainnet USE. Addresses `aegis1…`. Asset: **USE only**. Stock Scala Ergo OK for mainnet peg/mining API.

Not a DEX, not Matrix, not a general DeFi L2.

## 2. Why it exists

| On Aegis | Not on Aegis |
|---|---|
| Private USE notes + sends | Mint USE vs ERG (Dexy mainnet) |
| ~15s private payments | AMM / orderbook / user dApps |
| Peg in/out to mainnet USE | SigUSD or other stables |

USE stays mintable on Dexy — seeds the private rail.

```text
Ergo mainnet                         Aegis
┌─────────────────────────┐          ┌──────────────────────────────┐
│ USE bank (Dexy)         │  peg     │ Own blocks / P2P             │
│ PegVault + receipts     │◄────────►│ Shielded USE notes           │
│ SideChainState          │          │ CT+BP spends                 │
└─────────────────────────┘          └──────────────────────────────┘
```

## 3. Goals / non-goals

**Goals:** private USE rail; full child ledger; fully reserved peg; unsecured fungible exits; fee pot → MM rewards; Rust `aegis-node` + `aegis-mm`; dogfood with small MM.

**Non-goals:** SigUSD; Dexy-on-SC; private DEX; arbitrary user contracts; ERG as primary private asset; Matrix/Braid/Pioneer; Scala consensus upgrade; drivechain-grade “Ergo majority must steal.”

## 4. Decided (design stage — revisable, summary)

| Topic | Decision |
|---|---|
| Name | **Aegis** (shield); HRP `aegis` / `aegisdev` / `aegistest` |
| Asset | USE only, 3 decimals, any multiple of `0.001` |
| Privacy | Mandatory **global shielded pool**; Curve Trees + Bulletproofs(+) |
| Peg | Parallel **DepositReceipt** + **PegVault**; unsecured exit |
| Crates | `aegis-spec`, `aegis-node`, `aegis-mm` |
| Scala | Peg ErgoScript + mining API only — **no** Aegis proof verify |
| Emission | No unbacked USE; fees → pot → `min(pot, 0.01 + 0.01×txs)` / block |

## 5. User journey

1. Wallet mnemonic → `aegisdev1…` payment addresses.  
2. Mint USE on Ergo if needed.  
3. Peg in: lock `N` USE (+ fee), `R4 = sc_dest` → shielded note(s).  
4. Send privately to `aegis…` (~15s).  
5. Balance = decrypted notes (IVK), not explorer.  
6. Peg out: burn → after confs/delay → USE to an **Ergo** address.

Detail: §7–8 and [peg.md](./peg.md).

## 6. Amounts

Same value domain as mainnet USE (`0.001`). On Aegis, amounts live in **commitments** (hidden). Peg edge shows `N` publicly.

## 7. Keys, addresses, wallet

### Keys

```text
mnemonic → spending_key → IVK / OVK / payment_address(es)
```

| Key | Role | Share? |
|---|---|---|
| Spending | Spend / burn | Never |
| IVK | Sync balance | Watch-only only |
| Payment address | Receive | Yes |

### Addresses

| Network | HRP | Example |
|---|---|---|
| Dev | `aegisdev` | `aegisdev1q…` |
| Test | `aegistest` | `aegistest1q…` |
| Main | `aegis` | `aegis1q…` |

Bech32m. Not Ergo `9…`. Peg `R4` = address **payload bytes**, not the Bech32 string. Default: new diversified address per receive/peg-in.

### Wallet v1 must

Create/restore; show USE balance; receive/send; peg-in helper; peg-out guide; refuse wrong HRP / Ergo addresses on Aegis send. Light sync = later.

## 8. Note lifecycle (summary)

```text
DepositReceipt → PegMint → note(s)
ShieldedTransfer (private pay)
PegBurn → UnlockIntent → (delay) → PegVault pays Ergo claimant
```

Invariant:

```text
spendable_reserve = vault + unmerged receipts
  ≥ unspent notes + pending_burns_accounting
```

(See [security.md](./security.md), [peg.md](./peg.md).)

## 9. Ledger & transactions

**No transparent user USE UTXOs.** State: headers, Curve Tree, nullifier set, system boxes.

Block header (logical): `prev_hash`, height, time, merkle(txs), `cm_tree_root`, nullifier digest, MM/aux link, miner claim.

| Tx kind | Effect |
|---|---|
| `ShieldedTransfer` | Spend → outputs + fee; proofs + nullifiers |
| `PegMint` | Mint from proven receipt to `sc_dest` |
| `PegBurn` | Nullify value `N` for exit |
| `Coinbase` | Pot → miner (`min(pot, R_target + R_target × txs_included)`) |

Block target ~15s; linear chain; fork choice = heaviest/most-work MM chain. User pays on Aegis do **not** wait for Ergo.  
Unwritten consensus specs (PoW binding, DAA, reorg semantics for tree/nullifiers, weights, timestamps) are enumerated in [engineering.md](./engineering.md) §3 — required before `aegis-node` beyond a toy.

### Validation pipeline (per block)

1. Header / MM linkage.  
2. Merkle txs.  
3. Per-tx: type checks + native CT+BP verify.  
4. Nullifiers fresh.  
5. Update commitment tree; commit roots.  
6. System box transitions (pot → miner).  
7. Economic checks expressible in consensus.

### P2P / RPC (v1 sketch)

Devnet seeds; gossip headers/blocks/txs. RPC families: balance/notes, new address, transfer, broadcast, sync info; peg helpers optional.

## 10. Node architecture & MM

```text
Autolykos ─► aegis-mm ─► Ergo (/mining/candidate, /mining/solution)
                │              + SideChainState update on Ergo win
                └─► aegis-node (P2P, mempool, verify CT+BP)
```

| Binary | Role |
|---|---|
| `aegis-node` | Consensus, tree, nullifiers, RPC |
| `aegis-mm` | Bind Ergo work ↔ Aegis templates |
| Wallet | Keys + prove (CLI first) |

### Merge-mine commit — decided (2026-07-12, supersedes the provisional rule)

**Commitment transaction via stock `POST /mining/candidateWithTxs`** — the sidecar includes a tx carrying the Aegis header id (ideally the `SideChainState` update tx itself, unifying MM commitment and anchor); every Autolykos attempt on the candidate commits to exactly one Aegis block via `txRoot`. **Scala miners work today with no PR** (the channel kushti's `sigmachains.md` designates for MM sidechains); our Rust node needs the `candidate_with_txs` seam (W4). Full spec + PoW witness format: [consensus.md](./consensus.md) §1. Remaining open: combined-work byte layout for GPU/stratum pools.

### Layout (Hybrid B)

Dedicated **`aegis-*`** crates in this monorepo; reuse is real but partial — ser/crypto ~as-is, p2p/mining/sync with surgery, consensus/state all new; **not** ergo-sigma for the SC ledger (no ErgoScript in Aegis blocks). Full matrix: [engineering.md](./engineering.md) §2a.  
**Reject:** folding Aegis into default `ergo-node` `Network::` (misconfig with mainnet).  
**Reject for day one:** pure sibling repo (slower dogfood).  
Do **not** change mainnet/testnet vectors in `ergo-chain-spec` when scaffolding.

Genesis: empty tree/nullifiers; no user premine; network id `aegis-dev` / `aegis-test` / `aegis`.

### Operator checklist (dogfood)

1. Ergo node (Scala OK) with mining API.  
2. `aegis-node`.  
3. `aegis-mm` → both.  
4. Autolykos miner → sidecar.  
5. Wallet vs SC RPC; Ergo wallet for USE peg.

## 11. Fees & emissions

Never mint unbacked USE.

**Principle (2026-07-12 redesign):** value-scaled fees at the **peg edges** (where `N` is public by nature — also where vault risk is created); **flat, amount-independent** fees inside the pool (an amount-correlated on-SC fee is a public amount oracle that re-enables peg-edge tracing). Rationale + rejected alternatives: [engineering.md](./engineering.md) §4, `notes/archive/fee-privacy-alternatives.md`.

| Stream | Current design (provisional) | Destination |
|---|---|---|
| SC tx | Flat **0.03**, public, uniform tx shape — never `f(amount)` | Emission box (100%) |
| Peg-in | `max(1, 1% × N)` | Pot |
| Peg-out | `max(1, 1% × N)` (symmetric — see params.md) | Pot |
| Block | `min(pot, 0.01 + 0.01 × txs_included)` | MM miner |

Examples (1 USE ≈ $1): every SC payment — coffee or 100k — pays **0.03**; peg-in `100` → **1**; peg-in `30_000` → **300**; peg-out `100_000` → **1_000**; one `~2.9k` round-trip/day ≈ full subsidy. Round trip `2%` — premium pricing, amortized over the whole holding period. Whales pay proportionally where their amount is already public; inside the pool everyone looks identical.  
At `R_target = 0.01`/block ≈ **57.6 USE/day** full subsidy ≈ `5.8k` USE/day one-way bridge flow at `1%`.  
Optional later: `R_target` scales with EMA(peg volume); v1 = fixed target + pot.

### Dogfood fee OK (vs end)

| Key | Dogfood OK | End |
|---|---|---|
| SC flat fee | `0.01` | `0.03` |
| peg-in | `max(0.1, 1%×N)` | `max(1, 1%×N)` |
| peg-out | `max(0.1, 1%×N)` | `max(1, 1%×N)` |
| SC fee destination | 100% emission box | 100% emission box |

### Emission box mechanics

The emission box (pot) is **SC system state**: a public integer balance committed in each header — not a spendable UTXO, and never a hidden commitment (the coinbase rule must stay publicly checkable).

| Flow | Rule | Backing |
|---|---|---|
| SC tx fee `0.03` | Credited at block apply | Value moves from note supply to pot; SC supply unchanged |
| Peg-in fee `1%×N` | Credited at **PegMint**, proven from the same Ergo tx as the receipt | Fee USE locked on Ergo alongside principal |
| Peg-out fee `1%×N` | At **PegBurn**: burn `N` ⇒ exit claim `N − fee`, fee → pot | Vault retains the fee-worth it never pays out |
| Coinbase | Pays `min(pot_parent, R_target + R_target × txs_included)` — base + inclusion bonus, computed on the **parent** state's balance (no same-block circularity); paid as an ordinary shielded note to the miner's configured `reward_address` (template-built by their own node, so the plaintext is theirs); wallet scan picks it up like any payment. Unspendable for `coinbase_maturity` (120) blocks so a reorged coinbase can't poison downstream spends | Pot decrement |

Every pot credit is matched 1:1 by USE locked/retained on Ergo or moved within SC supply — the pot is always fully backed; reserve invariant I1 includes the pot term (see [security.md](./security.md) §4, [peg.md](./peg.md) §6).

**Inclusion bonus (decided 2026-07-12; guards against empty-block free-riding):** with fees 100%→pot and a content-independent reward, a decentralized miner's dominant strategy is header-only blocks (verify cost + orphan risk, pot growth shared with everyone — Bitcoin pools mined empty even *with* direct fees). Fix, in round units:

```text
coinbase = min(pot, 0.01 + 0.01 × txs_included)
```

Per included tx: fee `0.03` → pot; miner draws `0.01`; pot nets `+0.02` (β = ⅓). Empty block still pays the `0.01` base. Always pot-funded (never unbacked), single public payout path, one tunable constant. Solo-MM dogfood works either way; this makes decentralized MM incentive-compatible from day one.

**`txs_included` is defined narrowly (C5):** it counts **only fee-paying ShieldedTransfers** (each contributing `0.03` to the pot). Coinbase, PegMint, and PegBurn do **not** count toward the bonus — they pay no SC flat fee, so counting them would let the pot pay a bonus it wasn't funded for. This preserves the invariant "**every counted tx pays ≥ `sc_tx_fee` into the pot**," which is what makes β = ⅓ pot-positive; any future tx type must satisfy it to be countable. (The self-dealing drain is separately impossible: a padded self-tx pays 0.03 to claim 0.01, a net loss.)

**Empty-block base is not guaranteed when the pot is thin (C8, accepted):** `min(pot, …)` pays `< 0.01` whenever `pot < 0.01` — i.e. early life and after depletion, exactly when the anti-free-ride incentive is weakest. This is economic, not a solvency break (never pays unbacked USE). Dogfood mitigates via a funded operator; a small seeded `pot` floor at genesis is an option if empty-block behavior bites in practice (tracked, DEFERRED.md).

**Security-budget reality (MM economics):** 57.6 USE/day is a cap, not a floor — pot starts at 0. Per Ergo-block-equivalent (8 SC blocks) a full pot adds ≤ 0.08 USE on top of ~3 ERG re-emission + fees + rent: a ~1–3% margin bump for near-zero marginal cost. MM participation is therefore gated by **integration friction** (pool/stratum sidecar must be zero-risk to Ergo income — W4), not reward size (cf. Namecoin >60%, RSK 40–60% of parent hashrate on modest rewards). SC hashrate defends between-peg payment finality and liveness only; the vault is defended by the U1 ladder by design. Consequence: **`V_cap` scales with MM participation share** (cost to out-mine participants for `M` = 120 blocks ≈ 30 min), not with pot revenue.

## 12. System "contracts" on Aegis — native rules, not ErgoScript

There is **no script interpreter on Aegis**. System paths (fee pot, peg mint/burn gates) are native consensus rules in Rust over system boxes; ErgoScript lives only on the **Ergo side** of the peg. Rationale: transparent script boxes would fragment the uniform anonymity set (the Zcash transparent-pool failure), and a script interpreter is a large consensus surface with zero product need — user value = shielded notes only. No user-deployed DeFi as product.

**No storage rent on Aegis (decided 2026-07-12).** Infeasible: rent needs visibility (which notes are old/unspent — hidden by design) and confiscation (spending needs the owner's nullifier key — impossible by design). Also pointless: the commitment tree is append-only and the nullifier set only grows — rent could reclaim nothing. Uniform tx shape means every tx adds a *constant* amount of state, so the flat fee is an exact prepaid perpetual-storage charge. Residual: nullifier-set growth is unbounded and lost notes strand vault USE (over-backing — safe direction). **Planned post-v1 remedy: threshold turnstile (R1-T)** — shielded epoch migrations whose values are threshold-decrypted *only in aggregate* by the U1-strong attesters; expired = public epoch total − aggregate → emission box; old nullifier sets archived. Cadence: **1y epoch + 1y transparent grace ⇒ sweep at ~2y untouched** ("privacy decays before money") — Aegis is a chain for **use, not storage**: small rolling ledger (~2y nullifier window), fast recycling; deadline-free cold storage = peg out to L1. Requires S1 live; v1 ships without it. Full ladder + design: `notes/archive/storage-rent-privacy-tradeoffs.md`. Ergo-side rent still applies **to our peg boxes** (E2, `R_rent`).

## 13. Wallet notes (extra)

OVK optional (see sent). Note plaintext: value, pk, blinding/`rcm`, memo. Diversifiers secp256k1-family (exact encoding open).  
Footguns: wrong HRP; Ergo `9…` on Aegis send; peg without confs; lose mnemonic = lose money; IVK export = privacy loss (typed warning).

## 14. Deployment phases

0. Design freeze.  
1. ErgoScript lab.  
2. `aegis-node` + MM + wallet CLI (scaffold: `aegis-spec` 15s test first).  
3. Public testnet E2E.  
4. Optional Scala MM PR.  
5. Mainnet dust under [security.md](./security.md).

## 15. Open encoding knobs

Bech32 payload; proof wire; MM combined-work bytes; tune fees/`M,N` after dogfood.

## 16. References

ErgoHack (`~/coding/reference/ergo-ecosystem/ergohack-sidechain/`); Dexy/USE; Curve Trees ePrint 2022/756 (Vcash construction = our shape); `ergo-curve-trees` (L1 membership verifier — *not* a payment stack, see [engineering.md](./engineering.md) §2b). Archived research under `notes/archive/`.
