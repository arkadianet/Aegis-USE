# Note lifecycle — mint, spend, burn

**Date:** 2026-07-11  
**Status:** design freeze (v1)  
**Pairs with:** `ledger-wallet-addresses.md`, peg notes, `privacy-mechanism-decision.md`

---

## Overview

```text
Ergo                Privacy SC                         Ergo
────                ──────────                         ────
DepositReceipt ──► PegMint ──► note(s) for Alice
                      │
                      ▼
              ShieldedTransfer (Alice → Carol)
                      │
                      ▼
Alice or Carol ──► PegBurn ──► unlock from PegVault ──► USE to claimant
```

Invariant (economic):

```text
USE in PegVault (≥) sum of unspent shielded note values
  (modulo in-flight mints/burns and fee pot)
```

---

## 1. Peg-in → PegMint

### User

1. Wallet creates/shows payment address `aegis…` (or dedicated peg address).  
2. On Ergo: lock `N` USE in **DepositReceipt** + pay peg-in fee; `R4 = sc_dest` payload.  
3. Wait Ergo confirmations (policy TBD; provisional: same family as unlock `N`).

### Network

4. Peg watcher (or any prover) submits **`PegMint`** on SC proving:  
   - receipt box id / contents (USE `N`, `sc_dest`, token id)  
   - not already minted (receipt id in used-set)  
5. Consensus: append note commitment(s) value `N` encrypted to `sc_dest`; mark receipt used.

### Wallet

6. Sync / trial-decrypt → Alice’s balance += `N`.

**Public:** Ergo shows `N`. **Private:** who holds the note after mint (only `sc_dest` holder).

---

## 2. ShieldedTransfer (private pay)

### User

1. Pick notes totaling ≥ `amount + fee`.  
2. Build outputs: payment note to Bob’s `aegis…`, change to self, fee per policy.  
3. Prove (Curve Trees membership + BP balance/range + auth).  
4. Broadcast tx.

### Chain

5. Verify proof; check nullifiers fresh; append nullifiers; append new commitments; update tree root.

### Wallets

6. Alice: notes spent (nullifiers match).  
7. Bob: decrypts new note → balance up.  
8. Observers: see a valid private tx, not parties/amounts.

---

## 3. Peg-out → PegBurn → Ergo unlock

### User (note holder — may be Carol after Alice paid her)

1. Choose notes value `N` (+ peg-out fee path as designed).  
2. **`PegBurn`** on SC: nullify notes; attach burn id / value proof for Ergo.  
3. Wait **`M` SC confirmations** (~120 ≈ 30 min).  
4. After miner anchors tip in **SideChainState**, wait **`N` Ergo depth** (~10).  
5. On Ergo: spend **PegVault** with burn proof + double-redeem check → USE `N` to claimant’s **Ergo** address.

**Unsecured fungible:** vault does not care who originally deposited — only that burn of `N` is fresh.

---

## 4. Fees in the lifecycle

| Moment | Fee |
|---|---|
| Peg-in | `10` USE (end) → emissions pot (Ergo side / bridge) |
| ShieldedTransfer | `max(0.03, 0.1%×amt)` inside proof |
| Peg-out | `1` USE (end) → pot |
| Each SC block | `min(0.01, pot)` → miner |

---

## 5. Failure / refund paths

| Case | Handling |
|---|---|
| Receipt never minted | Ergo refund path on receipt script (GAPS) after timeout |
| PegMint double | Rejected — receipt id used once |
| PegBurn double redeem | DoubleRedeem / burn id on Ergo |
| User loses mnemonic | Notes unrecoverable (same as any shielded coin) |

---

## 6. What explorers show

| Surface | Visible |
|---|---|
| Ergo peg tx | Addresses, `N` USE, fee |
| SC shielded tx | Proof OK, nullifiers, new commitments, ciphertexts |
| SC PegMint | Linkage to receipt id (mint is somewhat linkable to peg-in — expected) |
| SC PegBurn | Burn value may be revealed to Ergo unlock (public `N` on exit) — expected |

Privacy product = **life between peg-in and peg-out**, not the bridge edges.
