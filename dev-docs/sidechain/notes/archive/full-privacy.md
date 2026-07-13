# Full privacy on SC — what changes

**Decision:** On the sidechain, transfers are **fully private by default**: hide **sender, receiver, and amount**. Peg edge on Ergo stays public (lock/unlock N USE).

## Privacy bar

| Property | On SC (between peg-in and peg-out) | On Ergo peg |
|---|---|---|
| Sender | Hidden | Lock tx visible |
| Receiver | Hidden | Unlock tx visible |
| Amount | Hidden | Lock/unlock amount visible |
| Precision | Any multiple of `0.001` USE (commitments, not cleartext boxes) | Same `0.001` |

“Match USE” = **value domain** (3 decimals, any size). It does **not** mean cleartext UTXO amounts like mainnet.

## What was wrong before

Stealth + mix with **visible amounts** = partial privacy (link-breaking only). That is **not** full privacy. `%` tx fees in cleartext would also leak size.

## What must change

### 1. Value representation

- **Replace** cleartext USE boxes as the user balance model.  
- **Use** shielded / confidential **notes**: value in a commitment (e.g. Pedersen), spend via nullifier + proof (balance, range, ownership).  
- Consensus: only shielded notes (+ allowlisted system boxes: peg, pot, fees) hold user value.

### 2. Crypto path — **LOCKED: global shielded note pool**

**Canonical decision:** `notes/privacy-mechanism-decision.md` (2026-07-11).

| Choice | Status |
|---|---|
| **Global shielded pool** (commitments + nullifiers + spend proofs; full anonymity set) | **LOCKED** |
| C1 rings + CT | Rejected as primary (Monero moving to FCMP++; weak on quiet chains) |
| C0 ZeroJoin / SigmaJoin cleartext amounts | Rejected |

**Proving engine:** **LOCKED provisional** — Curve Trees + Bulletproofs(+); Halo2 fallback. See `notes/proving-engine-decision.md`.

**Requirement:** hide amount + parties for default pays. Stock ErgoScript balances alone are **insufficient**.

### 3. Fees

- **`fee = max(0.03, 0.1% × amount)`** is fine **inside** the private spend (prover knows amount; verifiers don’t learn it from a cleartext fee).  
- Any **public** fee leg (if needed for miners) must be **fixed or coarse-bucketed**, not exact `%`.  
- Bridge fees (`10` / `1` USE) stay public on Ergo / peg — expected.

### 4. Peg

- Unchanged economically: lock N → mint shielded note value N; burn note → unlock N.  
- Mint/burn proofs must show value N **without** leaving a cleartext SC trail of intermediate spends.  
- Mainnet still shows N.

### 5. Wallet / UX

- Balance is sum of **notes** the wallet can decrypt/detect (view keys / trial decryption), not explorer box amounts.  
- Coffee `5.600` USE = one private spend (change note back to self). No cleartext “bag of bills” required.  
- Light client / sync story required (can't skim transparent UTXO set for balances).

### 6. Impl plan impact

- Harder than stealth-only. Phase 2 starts with a **proving/note spike**, not “port SigmaJoin boxes.”  
- `notes/sigmajoin-on-sc.md` demoted to historical — see this doc.  
- Schedule: peg + node boot can proceed; **private spend circuit is on the critical path** before calling it a privacy chain.

## Wallet balance UX (after peg-in 100 USE)

User locks **100 USE** on Ergo → SC mints a **shielded note** value 100 encrypted to their keys. Explorer does **not** show “address X has 100.”

### How the wallet knows the balance

It does **not** need a global “account balance” table. It keeps a local note set:

1. **Detect** notes it can open (trial-decrypt / view-key scan of shielded outputs).  
2. **Sum** unspent notes it owns.  
3. **Mark spent** when it sees nullifiers it created (or that match spends it made).

So after deposit: wallet shows **100 USE** once it has synced far enough to decrypt the mint note. After sending `5.6`, it shows remaining notes (e.g. change `94.4` + any others).

### Do you scan the “entire ledger”?

You scan **shielded outputs** (and nullifiers), not every mainnet-style UTXO interpretation of every stranger’s money. Others’ notes stay opaque; you only open yours.

| Mode | What you download | Who uses it |
|---|---|---|
| Full node | All blocks | Power users |
| Light client | Compact shielded outputs / tags | Phones — **standard** |

You still need *some* chain data over time (or a trusted/light server). You do **not** recompute the whole world state to learn your balance.

### Has this been solved?

**Yes, in production:**

| Chain | Mechanism |
|---|---|
| **Zcash** (Sapling/Orchard) | Incoming viewing key + trial decryption; **lightwalletd** / compact blocks so phones don’t store full chain |
| **Monero** | View key scans for outputs to your stealth addresses; wallets sync continuously |
| **Aztec / other L2 shielded** | Similar note + nullifier model with client sync |

Not magically “zero sync” — solved as **view-key / trial-decrypt + light clients**.

### What we must build for this SC

- Note encryption to user keys (and optional **incoming viewing key** for watch-only).  
- Wallet DB of notes + nullifiers.  
- Sync protocol: full node and later **compact light sync** (Zcash-style).  
- Peg mint must emit a note the depositor’s wallet can detect — **destination embedded in Ergo lock R4** (see `peg-entry-ergoscript.md`).

### UX sketch

```text
[ Peg in 100 USE on Ergo ]
        ↓
Wallet sync… finds note #1 (100 USE)
Balance: 100.000 USE
        ↓
Send 5.600 USE (private) → change note 94.400
Balance: 94.400 USE
```

User never “looks up an address on an explorer” for SC balance. Explorer shows shielded activity blobs, not dollar balances per person.


## Non-goal clarification

Earlier “no Zcash-style pool” meant “don’t boil the ocean first.” **Full privacy is in-scope** via a **mandatory global shielded note pool** — see `privacy-mechanism-decision.md`. Proving engine (Curve Trees+BP vs Halo2) is the remaining spike, not “rings vs pool.”
