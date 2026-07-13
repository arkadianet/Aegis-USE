# Aegis — red adversarial review

**Date:** 2026-07-11  
**Role:** attack the design as written (not the author’s intent)  
**Inputs:** DESIGN-INDEX, peg notes, privacy/engine locks, `trust-threat-model.md`, GAPS  
**Verdict up front:** **Ship dogfood / testnet** under **U1-dogfood** mitigations. **Serious TVL** needs **U1-strong** (attested tip or better). Design mitigations locked in `design-mitigations.md`.

Severity: **C**ritical / **H**igh / **M**edium / **L**ow · Status updated after design mitigations.

---

## Mitigation map (design stage — see `design-mitigations.md`)

| Adv | Design mitigation | Dogfood | Serious TVL |
|---|---|---|---|
| A1 double mint | M1 used-set + `N_mint` | required | required |
| A2 mint w/o lock | M1 no god-mint | required | required |
| A3 R4 malleation | M1 R4 bind | required | required |
| A4 reserve drift | M2 spendable_reserve | required | required |
| B1–B3 crypto/nullifier | M4 | required | + external review |
| B5 quiet linkability | M6 honesty | accept | accept |
| C1 lying tip | **U1-dogfood** cap+delay+copy | required | **U1-strong S1/S2** |
| C2 double redeem | DoubleRedeem | required | required |
| C3 wrong box | pooled vault only | required | required |
| E1 GAPS | M5 gate | before vault | + audit |
| E2 rent | M5 endowment | before vault | required |

---

1. **Unlock ↔ miner-posted tip is the load-bearing risk.** If ErgoScript accepts “burn under whatever digest the miner posted” without a challengeable Aegis light-client proof, a corrupt MM+Ergo winner can steal vault USE or brick exits.  
2. **Permissionless PegMint is underspecified for forged receipts** — must bind to real Ergo boxes with confs; any shortcut “API mint” is fatal.  
3. **Quiet-chain privacy is weaker than marketing** — pool helps, peg edges + timing still link.  
4. **Insolvency paths** if receipt merge / fee pot / vault accounting drift from note supply.  
5. **ErgoScript GAPS** — design assumes contracts that do not exist yet; upstream Unlock is ERG-shaped and dangerous if cargo-culted.

---

## A — Peg-in / PegMint

### A1. Double mint from one receipt — **C** · open

**Attack:** Mint twice for same DepositReceipt (race two PegMints, rewind SC, buggy used-set).  
**Impact:** Note inflation ⇒ vault insolvency.  
**Mitigate:** Consensus used-set keyed by Ergo `boxId`; reject duplicates; test reorgs of Ergo view vs SC mint timing (don’t mint on 0-conf).  
**Dogfood:** Accept only with ≥N Ergo confs before mint + invariant monitor.

### A2. Mint without real lock — **C** · open

**Attack:** Forge PegMint proof / corrupt watcher (mode B) credits notes with no USE in receipt/vault.  
**Mitigate:** Mode A only: verify receipt bytes against Ergo (SPV/header + tx inclusion or trusted Ergo node with attestation policy documented). No “admin mint.”  
**Dogfood:** Single operator Ergo node is fine if **code path cannot mint without box bytes**; never ship a god-key.

### A3. Wrong `sc_dest` / malleated R4 — **H** · open

**Attack:** Replace destination so Alice’s deposit mints to Attacker.  
**Mitigate:** R4 immutable in receipt script; PegMint binds commitment to R4 hash from proven box.  
**Dogfood:** Contract must-fix before any public deposit UI.

### A4. Receipt never merged, vault empty, notes exist — **H** · open

**Attack / bug:** Notes minted from receipt but consolidator never moves USE into PegVault; exits fail or race incomplete vault.  
**Mitigate:** Either mint only after merge, **or** treat unmerged receipts as still-spendable reserve in invariant (vault + outstanding receipts ≥ notes). Prefer explicit accounting in node + docs.  
**Dogfood:** Monitor invariant I1 continuously.

### A5. Grief peg-in with dust / fee grief — **L** · accept

Spam receipts. Fees + dust limits.

---

## B — Private ledger (Aegis)

### B1. Fake spend proof / soundness bug — **C** · open (crypto)

**Attack:** Break CT+BP / Curve Tree integration ⇒ inflate or steal notes.  
**Mitigate:** Don’t roll custom crypto; follow audited constructions; consensus tests; optional Halo2 fallback if CT path fails review.  
**Dogfood:** Tiny TVL until external review of *our* glue code.

### B2. Nullifier reuse / reset on fork — **C** · open

**Attack:** Reorg drops nullifier; double-spend.  
**Mitigate:** Fork choice + nullifier set tied to canonical chain; no “prune nullifiers” without epoch design.  
**Dogfood:** Simple linear chain, long finality before peg-out (`M`).

### B3. Missing range proof ⇒ negative / overflow — **C** · open

**Attack:** Classic CT footgun.  
**Mitigate:** BP range on all outputs; balance equation in verify.

### B4. Fee bypass / public fee leaks amount — **M** · mitigate

**Attack:** Skip private fee; or public fee = f(amount).  
**Mitigate:** Fee in proof; public leg fixed/bucketed only (already in fees doc).

### B5. Quiet-chain linkability — **M** · accept-for-dogfood

**Attack:** Peg-in N then soon peg-out N; or sole activity heuristics.  
**Mitigate:** UX delays optional; honesty in docs (“privacy between pegs”).  
**Not a consensus bug.**

### B6. Malicious full node / eclipse — **H** · open

**Attack:** Feed wallet false roots; trap peg-out.  
**Mitigate:** Multi-peer; checkpoint digests; compare Ergo `SideChainState` vs local tip policy for withdrawals.

---

## C — Peg-out / vault

### C1. Fake burn unlock (lying tip) — **C** · open

**Attack:** MM miner posts `SideChainState` digest for a fraudulent Aegis fork that “contains” a burn; unlock drains PegVault; honest chain ignored.  
**Impact:** Steal locked USE.  
**Mitigate (pick ≥1 before TVL):**  
- Stronger inclusion: NiPoPoW / header MM commit in Ergo extension + script checks  
- Fraud proof / challenge window before unlock  
- Federation / delay + watchtowers for v0  
- Hard cap vault TVL  
**Dogfood:** Accept with **dust vault caps** + operator-known MM set.

### C2. Replay burn / double redeem — **C** · open

**Attack:** Same burn unlocks twice.  
**Mitigate:** DoubleRedeem NFT/id set (ErgoHack); consensus tests.

### C3. Unlock steals from wrong accounting — **C** · open if per-user boxes return

**Attack:** Cargo-cult Unlock pays from Alice’s receipt with Bob’s burn.  
**Mitigate:** Pooled vault only; never long-lived per-user claim boxes (already forbidden in GAPS).

### C4. Brick exits (censorship of unlock / tip) — **H** · accept-for-dogfood

**Attack:** Miners refuse to post honest tip or censor unlock txs.  
**Mitigate:** Multiple MM; escape hatch research later; social liveness.

### C5. Amount mismatch burn N vs claim N — **H** · open

**Attack:** Burn 1, claim 100 via script bug.  
**Mitigate:** Single `N` binding in script + burn artifact.

---

## D — Merge mining / consensus

### D1. 51% Aegis MM reorg — **H** · accept-for-dogfood

**Attack:** Reorg private history; confuse wallets; attack burns in flight.  
**Mitigate:** Large `M`; withdraw only after deep anchors; hashrate diversity.

### D2. Ergo winner posts stale/wrong digest without stealing — **M** · accept

Griefing unlocks / UX. Same mitigations as C1/C4.

### D3. Sidecar binds wrong work — **M** · open

**Attack:** Miner thinks they’re securing tip H but publishes H′.  
**Mitigate:** Explicit tests for sidecar commit layout (`mm-commit.md`).

### D4. Solo MM centralization — **H** · accept-for-dogfood

Early network = one laptop. Document; don’t pretend otherwise.

---

## E — Contracts / Ergo ops

### E1. Upstream Unlock TODOs shipped as-is — **C** · open

**Attack:** Any of GAPS must-fix list.  
**Mitigate:** No mainnet vault until GAPS green + audit.

### E2. Storage rent kills SideChainState / vault — **H** · open

**Attack:** Neglect rent ⇒ box/status lost ⇒ peg frozen or steal paths.  
**Mitigate:** Rent endowment; monitoring; top-up bot.

### E3. Token id confusion (DexyGold etc.) — **H** · mitigate

**Mitigate:** Hard-code mainnet USE id from `params.md`; reject others.

### E4. Fee pot / principal co-mingling bug — **M** · open

**Attack:** Fees counted as vault principal or vice versa ⇒ invariant lie.  
**Mitigate:** Separate FeePot box; clear accounting.

---

## F — Wallet / UX adversaries

### F1. Address HRP confusion (`aegis` vs `aegisdev`) — **M** · mitigate

Wrong network send. Wallet hard-fail.

### F2. Paste Ergo `9…` into Aegis send — **M** · mitigate

Already required reject.

### F3. Phishing viewing key — **H** · mitigate

IVK leak ⇒ full history/balance. Label “read-only key = privacy loss.”

### F4. Prove on compromised host — **C** · accept (user endpoint)

Same as any wallet; seed = money.

---

## G — Economic / incentive

### G1. Empty pot ⇒ no MM — **M** · accept

Design already allows subsidy → 0. Risk: death spiral if no peg volume.  
**Mitigate:** Dogfood funded MM; bootstrap peg fees.

### G2. Miner extracts only tips, ignores privacy relay — **L** · accept

Standard.

### G3. Overpriced peg-in chills anonymity set — **L** · accept

Privacy vs fee tradeoff; dogfood lower fees OK.

---

## What Scala *actually* stops

| Attack | Stopped by stock Scala? |
|---|---|
| Invalid ErgoScript peg spend | Yes |
| Invalid Autolykos Ergo block | Yes |
| Invalid Aegis shielded spend | **No** |
| Lying `SideChainState` digest | **No** (if script allows miner update) |
| Note inflation on Aegis | **No** |

Anyone selling “Scala secures the sidechain” is wrong. Scala secures **the peg contracts’ rules**, not Aegis execution.

---

## Must-fix before mainnet value (gate)

| ID | Item |
|---|---|
| G-C1 | Unlock inclusion story that doesn’t reduce to “trust MM tip” **or** hard TVL cap + warning |
| G-A2 | PegMint only from proven Ergo receipts (no admin mint) |
| G-A1/I1 | Used-set + continuous reserve invariant |
| G-E1 | GAPS must-fix list green + review |
| G-B1 | Crypto glue review (even informal external) |
| G-E2 | Rent survival plan |

---

## Acceptable for dogfood (explicit)

- Solo / tiny MM set  
- Quiet-chain privacy heuristics  
- Full-node wallet only  
- Provisional `M,N` and fees  
- Mode B watcher **only** if Mode A mint proofs delayed — and watcher key is **not** vault spend key  

---

## Red-team conclusion

The architecture is **coherent** and matches known patterns (receipts + vault + shielded pool + MM sidecar). The **red** items are concentrated in **peg-out verification** and **mint provenance** — classic sidechain failure modes — not in the choice of `aegis` branding or 15s blocks.

**Recommendation:** Proceed to scaffold + contracts lab; treat adversarial **C1/A2/E1** as release blockers for anything beyond dust; update UI/docs to state the trust model in one screen (“Ergo holds USE; Aegis MM secures private history; unlock trusts anchor rules”).
