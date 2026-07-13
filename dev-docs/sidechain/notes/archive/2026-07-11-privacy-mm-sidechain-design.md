# Private USD Payment Sidechain — Greenfield Design

**Date:** 2026-07-11  
**Status:** **superseded as primary** by `dev-docs/sidechain/README.md` (consolidated Aegis canon). Kept until archive.  
**Author:** arkadianet  
**Workspace:** `arkadianet/ergo` (Rust Ergo node)  
**Location:** `dev-docs/specs/` (gitignored working spec)

## 1. One-liner

A **merge-mined Ergo sidechain** named **Aegis** for **fully private USE payments** (hide sender, receiver, amount on SC), ~**15s** blocks, 1:1 peg to mainnet USE (`0.001` value domain). Addresses `aegis1…`. **Asset: USE only.** Stock Scala OK for v1.

**Not** a private DEX / general DeFi L2 in v1. **Is** a full sidechain whose job is: *send dollars privately and quickly*.

## 2. Product vision — what is the sidechain *for*?

| On the sidechain (v1) | Not on the sidechain (v1) |
|---|---|
| Hold **USE** as private notes | Mint/redeem USE vs ERG (stays on Dexy mainnet bank) |
| Send dollars privately (~15s) | Spectrum-style AMM / orderbook DEX |
| Mix to grow anonymity set | Arbitrary user-deployed DeFi |
| Peg in/out to mainnet **USE** | Pioneer / Braid / Matrix-on-SC; other stables |

**Why USE only:** Dexy/USE stays mintable against the bank/oracle path, so the private rail can always be seeded. No second stable in scope.

Mental model:

```text
Ergo mainnet                         Privacy SC (this work)
┌─────────────────────────┐          ┌──────────────────────────────┐
│ USE bank (Dexy USD)     │  peg     │ Own blocks / UTXO / P2P      │
│ Peg vault (USE)         │◄────────►│ Native money = private USE   │
│ Oracles, LP, mint       │          │ Fully shielded sends         │
└─────────────────────────┘          └──────────────────────────────┘
```

Users mint **USE on mainnet**, then peg into the SC for private sends.

## 3. Goals / non-goals

### Goals

- Private, fast **USE** transfers on a child ledger.
- Full child ledger (consensus, state, history) — not a mainnet mixer.
- Fully reserved **USE** peg (lock on Ergo ↔ credit on SC), amounts match `0.001` USE.  
- Unsecured fungible unlock.  
- Fee model: cheap SC txs + peg fees funding pot-backed block rewards.  
- Rust SC node + stock Scala Ergo + MM sidecar.  
- Dogfood with solo/small MM hashrate.

### Non-goals

- **SigUSD / any second stable** — out of scope entirely.  
- Reimplementing Dexy bank on the SC.  
- Private DEX / general smart-contract marketplace.  
- User-deployed arbitrary contracts as a supported product surface.  
- ERG as the private asset.  
- Matrix on SC; Braid; ASIC Pioneer PoW.  
- Full Orchard feature-clone (privacy bar via smallest viable shielded-note design).  
- Scala consensus upgrade / mandatory node upgrade.

## 4. Decisions locked

| Topic | Decision |
|---|---|
| Asset | **USE** (Dexy USD) **only** — no SigUSD |
| Chain name | **Aegis** — private USE rail; HRP `aegis` / `aegisdev` |
| SC purpose | Private dollar **payment rail** |
| Consensus | Merge-mined with Ergo; linear chain; **~15s** blocks |
| Privacy | **Mandatory global shielded note pool** on SC (hide from/to/amount). Peg on Ergo public. Decision: `notes/privacy-mechanism-decision.md` |
| Peg | 1:1 USE; **DepositReceipt boxes (parallel)** + **PegVault singleton** for reserves/exits; unsecured exit = burn notes → claim from vault; see `architecture-improvement.md` |
| Smart contracts (v1) | **System contracts only** (peg, pools, fees) — see §8 |
| Scala | Stock Ergo + sidecar; MM PR later optional |
| Emission | **No unbacked USE.** Peg fees (+ tx skim) → emissions pot → per-block miner reward; see `notes/fees-emissions.md` |

## 5. Amounts — match USE (domain), hide on SC (presentation)

Mainnet USE is **3 decimals**. The SC uses the **same value domain** (`0.001` steps, any size). User balances on SC are **shielded notes**, not cleartext UTXO amounts.

| Surface | Rule |
|---|---|
| On-SC send / hold | Any multiple of `0.001` USE **inside** commitments; not visible on explorer |
| Peg in / peg out | 1:1 with mainnet; **N is public on Ergo** |
| Coffee `5.600` USE | One private spend (+ private change) |

### Peg edge

- Fully reserved lock N ↔ shielded value N.  
- Privacy product = SC life between peg-in and peg-out.  
- Ergo peg txs remain public by nature.

## 6. What users can do (v1 UX)

1. Create SC wallet (mnemonic) → `aegisdev1…` payment addresses.  
2. Mint USE on mainnet if needed.  
3. Peg in: lock N USE (+ fee) with `R4=sc_dest` → shielded note(s) value N.  
4. Private send on SC (~15s): to `aegis…`, hide from/to/amount.  
5. Balance = synced notes (IVK), not explorer.  
6. Peg out: burn notes → claim N USE on Ergo to a normal Ergo address.

Canonical: `notes/ledger-wallet-addresses.md`, `notes/note-lifecycle.md`.

## 7. Architecture (unchanged shape)

```text
Autolykos miner ──► MM sidecar ──► Ergo mainnet (Scala-majority OK)
                         │
                         └──► Privacy SC node (Rust; USE notes v1)
```

- Mainnet: **USE** PegVault + DepositReceipts + `SideChainState` (miner-updated).  
- SC: 15s MM chain; note pools; system scripts only for user value path.  
- Scala full nodes: validate peg/state txs only; do not sync SC.

Anchors still Ergo-paced (`proveDlog(minerPk)`); solo ~1 Ergo block/day ⇒ slow peg exits until more MM joins. SC payments between users do **not** wait on Ergo.

## 8. Smart contracts — honest scope

The SC **has** a Sigma contractual layer (same family as Ergo). **v1 product policy** restricts what counts as valid user value:

| Contract class | v1 |
|---|---|
| Peg vault + mint/burn/unlock (**USE**; **pooled** reserves) | **Yes** — required |
| Emissions pot + per-block reward script | **Yes** — required |
| Shielded/confidential note spend + mint/burn (full privacy) | **Yes** — required |
| Fee sinks / rent top-up helpers | **Yes** |
| Stealth / double-unlock helpers | **Yes** |
| User-deployed arbitrary ErgoScript dApps | **No** (consensus or policy reject as user-value holders) |
| DEX / AMM / lending | **No** |
| Stablecoin bank / oracle on SC | **No** — mainnet only |

So: **programmable under the hood for system scripts**; **not** “deploy any contract / run a private DEX” as a v1 promise.

### Later (explicitly out of product scope unless reopened)

- Controlled contract allowlist experiments.  
- Private note↔note swap protocol.  
- Other assets (including SigUSD) — **not planned**.  
- Transparent “contract zone.”

## 9. Privacy model

Canonical: `notes/privacy-mechanism-decision.md`, `notes/proving-engine-decision.md`, `notes/full-privacy.md`, `notes/ledger-wallet-addresses.md`.

- **Mandatory global shielded note pool** (not rings, not cleartext SigmaJoin).  
- Addresses: Bech32m **`aegis…`** (not Ergo `9…`).  
- Hide sender, receiver, amount on SC; peg edge on Ergo still reveals `N`.  
- Proving: **Curve Trees + Bulletproofs(+)**.  
- Scala full nodes do **not** verify SC shielded proofs — only ErgoScript peg/state.  
- `%` fees inside private spend; public fee leg fixed/bucketed only.  
- ErgoScript = peg + system boxes; not user balances.

## 10. Incentives, rent, security

### Fees & emissions (canonical: `dev-docs/sidechain/notes/fees-emissions.md`)

| Stream | Provisional | Destination |
|---|---|---|
| SC tx | `max(0.03, 0.1% × amount)` inside **private** spend; public fee leg fixed/bucketed only; 90/10 | Miner tip / pot |
| Peg-in | **`10` USE** end target (dogfood may use `1`) | Emissions pot |
| Peg-out | **`1` USE** end target | Emissions pot |
| Block reward | `min(0.01 USE, pot)` | SC MM miner |

Never inflate USE. Empty pot ⇒ no subsidy (tips only).

### Other

- Mainnet rent on `SideChainState` + vaults must be survivable.  
- SC tip security ≈ MM hashrate; anchor finality ≈ Ergo.  
- Unlock: SC confs **and** Ergo depth after anchor.  
- Drivechain-level “need Ergo majority to steal” deferred.  
- **Trust / adversarial / mitigations:** `trust-threat-model.md`, `adversarial-review.md`, **`design-mitigations.md`** (U1-dogfood cap+delay; U1-strong k-of-n attestations before raising `V_cap`).

## 11. Deployment phases

0. Design freeze (this package) + USE token id + `(M,N)`.  
1. Contracts lab on Ergo testnet (**USE** peg only).  
2. Rust SC + local MM + wallet CLI.  
3. Public testnet: private USE sends + peg E2E.  
4. Optional Scala MM PR.  
5. Careful mainnet experiment (USE).

## 12. Open knobs (encoding / tuning only)

1. `(M, N)` confirmation policy after dogfood timing.  
2. AuxPoW / MM commit encoding.  
3. Final `peg_in_fee` / `peg_out_fee` / `R_target`.  
4. Bech32 payload / diversifier bit layout.  
5. Proof wire format (CT+BP).  
6. Optional: `R_target` scales with EMA(peg volume).

## 13. References

- **Design index:** `dev-docs/sidechain/DESIGN-INDEX.md`  
- Ledger / addresses / wallet: `dev-docs/sidechain/notes/ledger-wallet-addresses.md`  
- Note lifecycle: `dev-docs/sidechain/notes/note-lifecycle.md`  
- SC node / MM: `dev-docs/sidechain/notes/sc-node-consensus.md`  
- Architecture improvement: `dev-docs/sidechain/notes/architecture-improvement.md`  
- Peg entry (ErgoScript): `dev-docs/sidechain/notes/peg-entry-ergoscript.md`  
- Fee & emissions: `dev-docs/sidechain/notes/fees-emissions.md`  
- Full privacy / mechanism / engine: `notes/full-privacy.md`, `privacy-mechanism-decision.md`, `proving-engine-decision.md`  
- ErgoHack sidechain: https://github.com/ross-weir/ergohack-sidechain  
- USE / Dexy: https://docs.ergoplatform.com/uses/use_stablecoin/ · https://github.com/kushti/dexy-stable · local `reference/ergo-apps/protocols/Dexy/`  
- Curve Trees: https://eprint.iacr.org/2022/756 · https://github.com/a-shannon/ergo-curve-trees  
- ZeroJoin / SigmaJoin: historical only (superseded)  
- Sigma Chains: https://docs.ergoplatform.com/uses/sidechains/sigma-chains/  
- Matrix (L1 parallel): https://docs.ergoplatform.com/uses/sidechains/subblocks/  

## 14. Spec self-review

- [x] Vision = private **USE-only** payment rail  
- [x] **Full privacy on SC** + global pool + CT+BP  
- [x] **Addresses / wallet / ledger** specified  
- [x] Note lifecycle mint/spend/burn  
- [x] SC node + MM + Scala boundary clear  
- [x] Peg = receipts + vault  
- [x] No SigUSD  
- [x] Amounts = USE domain (`0.001`)  
- [x] System contracts only for user-value policy  

---

**Review ask:** Approve design package via `DESIGN-INDEX.md`. Then Task 3 scaffold on explicit go.
