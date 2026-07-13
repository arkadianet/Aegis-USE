# Peg entry on Ergo mainnet (ErgoScript)

**Status:** design freeze for register layout — contracts not implemented yet  
**Asset:** USE `a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669` (3 decimals)

## Are we covered?

| Piece | Status |
|---|---|
| Idea: lock USE on Ergo → mint shielded note on SC | Spec / full-privacy |
| Upstream ErgoHack `Unlock.es` | **ERG** lock/unlock skeleton only — not USE, no SC destination |
| USE token in vault | In `GAPS.md` — **must implement** |
| **SC recipient in lock box** | **This doc** — was underspecified; now frozen |
| Working compiled contracts | **Not yet** (Phase 3) |

So: **path is clear and ErgoScript-capable; not “done in code.”**

## How assignment works (ErgoScript-friendly)

Ergo boxes have **registers R4–R9**. Peg-in lock box stores the SC destination in a register. Off-chain (SC node / peg watcher) reads the confirmed lock and mints a shielded note to that destination.

```text
Wallet                         Ergo mainnet                      Privacy SC
  │                                 │                                 │
  │ create one-time SC recv         │                                 │
  │ build tx:                       │                                 │
  │  - USE amount N → peg script    │                                 │
  │  - USE fee → fee path           │                                 │
  │  - R4 = sc_dest (bytes)         │                                 │
  ├────────────────────────────────►│ lock box lives                  │
  │                                 │                                 │
  │                                 │  (after confs)                  │
  │                                 │  watcher sees box               │
  │                                 ├────────────────────────────────►│ mint note
  │                                 │                                 │  value N
  │                                 │                                 │  to sc_dest
```

ErgoScript does **not** need to understand shielded crypto. It only:

1. Holds USE (token id + amount).  
2. Stores `sc_dest` immutably (or under controlled update rules).  
3. Releases USE only under unlock rules (SC proof + confs) / refund rules.

Minting to the correct user is an **SC-side** rule: “if mainnet lock L with R4=D and amount N is proven, may create shielded note (N, D) once.”

## Provisional lock-box register map

| Register | Type | Content |
|---|---|---|
| tokens(0) | USE | Amount `N` (principal only; fee separate) |
| **R4** | `Coll[Byte]` | **`sc_dest`** — shielded payment address / note pubkey bytes (format TBD with proving stack) |
| R5 | `Coll[Byte]` | Optional memo (payment id); may be empty |
| R6 | `Byte` / enum | Peg version / network id (dev vs main) |
| R7+ | — | Reserved (fee receipt ref, etc.) |

**Invariant:** while principal is locked, **R4 must not change** (successor output must copy R4, or spend paths don’t allow rewrite).

## Fee on entry

Per `fees-emissions.md`: peg-in fee (end: **10 USE**) is **extra**, not taken from `N`.

Options (pick in contract impl):

- **A (preferred):** same tx — output0 = lock `N` USE under peg script + R4; output1 = `peg_in_fee` USE to fee/pot bridge box.  
- **B:** lock `N+fee` and script splits — easier to mess up 1:1; avoid unless careful.

## What upstream gives us vs what we add

Upstream `MainChain/Unlock.es` today:

- Locks **ERG** value.  
- R4/R5 used for **unlock flow** state (sidechain hash / height) — different lifecycle.  
- No USE token checks.  
- No `sc_dest` for mint assignment.

We will **adapt or replace** with a USE **pooled vault** + peg-in receipt path that:

1. Credits USE into the shared vault (principal `N`).  
2. Carries `sc_dest` for one-time mint assignment (receipt / deposit box registers).  
3. Unlocks only by paying **from the vault** to a claimant who proves SC burn of value `N` (unsecured, fungible).  
4. Refund path for failed/incomplete peg-in before mint (GAPS).  
5. Does **not** verify shielded proofs on Ergo — only SC tip / burn inclusion for unlock.  
6. **Never** allows “spend Alice’s deposit box with Bob’s unrelated burn proof.”

## CRITICAL: ErgoScript spend rules + who can exit

### ErgoScript reminder

A box is only spent if **that box’s** `propositionBytes` are satisfied in the tx that consumes it. Nobody “inherits” spend rights from a matching amount alone unless **we write the script that way**.

Upstream ErgoHack `Unlock.es` is closer to: start unlock against a **specific** mainchain lock box while proving a **specific** SC box (token amount ≤ lock) sits in the SC UTXO tree, and record that SC `boxId` in double-unlock prevention — not a free-floating “any 100 burn.” It still has the open TODO about whether a foreign SC balance can be aimed at someone else’s lock (secured vs unsecured). Treat that as research when porting; don’t cargo-cult the theft one-liner.

### What we want economically (pooled rail)

Deposits fund a **shared reserve**. Shielded notes are **fungible liabilities**. Exit rights follow **who holds notes now**, not who originally pegged in.

```text
Alice pegs in 100 USE ──► vault += 100
                       ──► Alice gets shielded notes (100)

Alice pays Carol 100 privately on SC
  (Alice may never touch mainnet again — that's fine)

Carol burns 100 on SC ──► proves burn ──► vault pays Carol 100 USE on Ergo
                       ──► vault -= 100
```

So it is **wrong** to say “Alice’s notes sit untouched until Alice withdraws.” Alice may spend on-SC forever; **Carol** (or Dave, …) is the one who later withdraws that value to mainnet. The vault doesn’t care who deposited; it cares that outstanding notes still equal reserves and that each burn is only redeemed once.

### Target mainnet shape

| Piece | Role | Pattern source |
|---|---|---|
| **DepositReceipt** (many) | Parallel peg-ins: USE `N` + `R4=sc_dest`; no vault race | Rosen events / ErgoMixer many boxes |
| **PegVault** (singleton NFT) | Pooled reserves; spent on exits (+ batched receipt merges) | Dexy/AgeUSD bank NFT |
| **SideChainState** (singleton NFT) | Anchored SC tip for unlock proofs | ErgoHack |
| **DoubleRedeem** | Burn/receipt id used once | ErgoHack |
| **FeePot** (singleton, optional split) | Peg fees → emissions | Dexy multi-contract |

Canonical improvement write-up: `notes/architecture-improvement.md`.

### Patterns

| Pattern | Verdict |
|---|---|
| Pooled vault; any note holder can exit by burning | **Required** for private fungible cash |
| Script that lets an unrelated proof drain a still-earmarked per-user deposit box | **Bug** — avoid by not keeping long-lived per-user claim boxes |
| Secured “only original Ergo locker may unlock” as default | Breaks Carol’s exit after Alice paid her |

### Invariant

```text
USE in peg vault on Ergo  >=  sum(unspent shielded note values on SC)
```

(Modulo in-flight pegs and fee pots.)

## Concrete Ergo protocols to copy patterns from

There is **no** deployed “private USE sidechain peg” twin. We **compose** patterns from these:

| Protocol | What to copy | What not to copy for peg-in |
|---|---|---|
| **[ErgoHack sidechain](https://github.com/ross-weir/ergohack-sidechain)** (`SideChainState.es`, `Unlock.es`) | Closest peg design: singleton SC state NFT; lock/unlock with SC proofs; double-unlock prevention | Still ERG-centric; incomplete TODOs |
| **[Rosen Bridge](https://docs.ergoplatform.com/eco/rosen/watcher/)** | **Many parallel event/commitment boxes**; watchers observe deposits; mint/burn on target after consensus — solves “two deposits same time” | Federated guards (heavier trust than we want long-term) |
| **[ErgoMixer / ErgoMix](https://docs.ergoplatform.com/eco/ergomixer/)** | **Many parallel deposit/half-mix boxes**; users don’t serialize on one UTXO | Mixing, not a bridge vault |
| **[AgeUSD / SigmaUSD](https://github.com/emurgo/age-usd)** + [bank v2 sketch](https://gist.github.com/kushti/3f34ed7d70cc6919c29f5bc65772b02e) | Singleton **bank** NFT; mint tx also emits a **receipt** output | Bank itself is a concurrency bottleneck (TokenJay: rebuild tx if bank moved) |
| **[Dexy bank](https://github.com/kushti/dexy-stable)** | Singleton bank NFT + **separate** mint helper contracts (free mint / arbitrage mint) | Same singleton contention on bank updates |
| **[Singletons docs](https://docs.ergoplatform.com/dev/tokens/singletons/)** | Canonical NFT account-box pattern | — |

### Mapping to us

| Our piece | Closest existing pattern |
|---|---|
| Peg-in receipt (per user, parallel) | Rosen event boxes / ErgoMixer many boxes / AgeUSD receipt output |
| Pooled vault (singleton) | AgeUSD/Dexy bank NFT / ErgoHack SideChainState NFT |
| Credit on other ledger | Rosen watchers→mint (we mint on SC from Ergo receipt proof) |
| Exit without stealing | ErgoHack unlock + double-unlock id (adapt to vault pay-out) |

**Practical takeaway:** use **Rosen/Mixer-style many receipts for deposits** + **AgeUSD/Dexy/ErgoHack-style singleton for the reserve vault**. Multiple contracts is normal on Ergo.

## Concurrent deposits (Alice + Bob same block)

**Problem if every deposit spends the vault:** only one tx can spend that UTXO unless they’re carefully chained. Two people clicking “deposit” at once → one fails (same pain as AgeUSD bank).

**What we do instead:**

```text
Alice deposit → creates Alice RECEIPT box (100 USE + her sc_dest)   ← does NOT need vault
Bob deposit   → creates Bob RECEIPT box (100 USE + his sc_dest)     ← parallel OK

SC sees two different box ids → mints Alice’s notes + Bob’s notes

Later (bot/miner): merge receipts into singleton VAULT (piggy bank)
```

- Alice is guaranteed her SC credit because mint keys off **her receipt box id + R4**, not “whoever won the vault race.”  
- 0-conf: each receipt is its own box; they don’t collide.  
- Vault singleton is for **pooled reserves / withdrawals**, not for serializing every peg-in.

### How Alice gets her 100 on the SC

1. Her deposit tx creates **receipt A** with `R4 = Alice_dest`, `100 USE`.  
2. After enough Ergo confs, SC accepts proof of receipt A.  
3. SC mints shielded notes to `Alice_dest` for 100, marks receipt A as used (no double mint).  
4. Bob’s receipt B is unrelated → his 100 goes to him.

Same block on Ergo is fine: two receipts, two mints.
## Implementation checklist (Phase 3)

- [ ] Write `contracts/MainChain/UsePegLock.es` (name TBD) with register map above  
- [ ] Compile + golden vectors  
- [ ] SC mint rule: prove Ergo box → create note `(N, R4)` once  
- [ ] Wallet: build lock tx with embedded one-time `sc_dest`  
- [ ] Update `GAPS.md` checkboxes as done  

## Related docs

- `full-privacy.md` — note model + wallet sync  
- `fees-emissions.md` — peg fees  
- `contracts/GAPS.md` — upstream TODOs  
- Upstream: `upstream-ergohack/contracts/MainChain/Unlock.es`  
