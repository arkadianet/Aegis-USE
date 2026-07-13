# Aegis ledger, addresses & wallets

**Date:** 2026-07-11  
**Status:** design freeze (v1)  
**Chain:** **Aegis** · networks `aegis-dev` / `aegis-test` / `aegis`  
**Depends on:** `privacy-mechanism-decision.md`, `proving-engine-decision.md`, `params.md`

**Aegis** = private USE payment sidechain. Users are **shielded**; the name is the divine shield (Greek). Address HRP matches the chain.

This is the “what is the sidechain *as a product*” doc: not just merge-mining, but **ledger + who you pay + how a wallet works**.

---

## 1. Mental model (non-crypto)

| Ergo mainnet | **Aegis** |
|---|---|
| Boxes with visible ERG/tokens | **Notes** you can’t see on an explorer |
| Address ≈ who can spend a box | **Payment address** ≈ who can decrypt/receive a note |
| Balance = sum of boxes at address | Balance = sum of **notes your wallet can open** |
| Explorer shows amounts | Explorer shows activity blobs, not “Alice has 94 USE” |

You still have something that *looks* like an address (string you paste to get paid). Under the hood it is **not** an Ergo P2PK.

---

## 2. Key hierarchy (v1)

One wallet seed → one account (multi-account later).

```text
mnemonic (BIP-39)
    │
    ▼
spending_key          # can spend notes (never leave device)
    │
    ├── incoming_viewing_key (IVK)   # scan chain; see incoming notes + amounts
    ├── outgoing_viewing_key (OVK)   # optional; see what you sent
    └── payment_address(es)          # what you give people / put in peg R4
```

| Key | Can do | Share? |
|---|---|---|
| Spending key | Spend, prove, burn | Never |
| IVK | Rebuild balance; watch-only | Trusted auditor / own phone sync |
| OVK | Prove “I sent X to Y” if needed | Rarely |
| Payment address | Receive | Yes — public |

**Curve / encoding:** secp256k1-family secrets aligned with Ergo + Curve Trees path; exact diversifier scheme fixed in proving spike (Sapling-like diversifiers are the UX template).

---

## 3. What does an “address” look like?

### Payment address (SC)

Human string, **Bech32m**, network-tagged:

| Network | HRP (locked) | Example shape |
|---|---|---|
| Dev / dogfood | `aegisdev` | `aegisdev1q…` |
| Public test | `aegistest` | `aegistest1q…` |
| Mainnet (later) | `aegis` | `aegis1q…` |

**Name:** Chain + HRP = **Aegis** — Greek divine shield (protection / shielding). Private dollars, shielded users. Spelled `aegis`, not “ageis”.

**Payload (logical):** diversifier + transmission/receive public key (+ version byte).  
**Not** an Ergo tree bytes address. Wallets must refuse to paste Ergo `9…` addresses into SC “send” (and vice versa for peg-out claim address).

**Reuse:** allowed but discouraged for privacy; wallet default = **new diversified address per receive / per peg-in**. Same IVK still finds all of them.

### Ergo addresses (unchanged)

Peg-in spends USE from a normal Ergo wallet. Peg-out **claim** pays USE to a normal Ergo P2PK / contract you specify in the unlock tx — **not** a `aegis…` string.

### What goes in peg `R4 = sc_dest`

Raw **payment address payload** (versioned bytes), not the Bech32 string. SC mint encrypts the new note to that address. See `peg-entry-ergoscript.md`.

---

## 4. Notes (the real balance unit)

A **note** is private money:

| Field (plaintext, wallet-only) | Meaning |
|---|---|
| `value` | USE base units (`0.001` = 1) |
| `address / pk` | Who can spend |
| `rcm` / blinding | Commitment randomness |
| `memo` | Optional short memo (encrypted) |

**On chain:** only `note_commitment`, later `nullifier` when spent, plus ciphertext for the recipient.

Wallet balance:

```text
balance = sum(value of notes I can decrypt ∧ nullifier not yet on chain)
```

---

## 5. Ledger state (what full nodes store)

```text
Consensus state
├── headers / block index
├── commitment accumulator (Curve Tree) root + structure
├── nullifier set (append-only)
├── system boxes (fee pot, peg mint/burn gates) — ErgoScript/Sigma OK
└── (optional) compact block cache for light sync
```

**There is no transparent UTXO set of user USE.** User value only via the shielded pool.

### Block shape (logical)

```text
Block {
  header: prev_hash, height, timestamp, merkle_root(txs),
          cm_tree_root, nullifier_set_root (or append digest),
          mm / aux link to Ergo work (sidecar),
          miner_pk / reward claim
  txs: [ Tx... ]
}
```

### Transaction kinds (v1)

| Kind | Who creates | Effect |
|---|---|---|
| `ShieldedTransfer` | User wallet | Spend note(s) → new note(s) + fee; nullifiers + proofs |
| `PegMint` | Peg watcher / permissionless with receipt proof | Add commitment(s) for value `N` to `sc_dest` |
| `PegBurn` | User wallet | Nullify note(s) value `N`; emit burn receipt for Ergo unlock |
| `Coinbase` / pot pay | Miner | `min(R_target, pot)` → miner’s shielded note or system→miner path |

Exact wire codecs: proving spike + `aegis-spec`.

---

## 6. Wallet product (v1 scope)

### Must

- Create/restore from mnemonic  
- Show **USE balance** (synced notes)  
- Generate payment addresses (`aegis…`)  
- **Send** private USE (amount + `aegis…` dest)  
- **Peg-in helper:** show `sc_dest` bytes / QR for Ergo deposit UI  
- **Peg-out:** burn → guide Ergo claim  
- Sync from full node (v1); compact light sync = v1.1  

### Must not (v1)

- Transparent SC “checking account”  
- Arbitrary dApp / DEX  
- Multi-asset  

### UX sketch

```text
Balance: 94.400 USE          [sync ●]

[ Receive ]  → shows aegisdev1q…  (+ “use for peg-in”)
[ Send ]     → to: aegis…  amount: 5.600
[ Peg out ]  → amount → Ergo address 9…
```

User never “looks up box on explorer” for SC balance.

---

## 7. Sync modes

| Mode | Downloads | Who |
|---|---|---|
| Full node | All blocks + tree + nullifiers | Operators, power users |
| Light (later) | Compact outputs + nullifier tags; trial-decrypt | Phones |

IVK required for trial decryption. Same pattern as Zcash lightwalletd / Penumbra.

---

## 8. Fee display

Inside private spend: wallet computes `max(0.03, 0.1% × amount)` and proves it.  
UI: “Fee ≈ 0.03 USE” before confirm. Public miner fee leg (if any) fixed/bucketed only.

---

## 9. Security / UX footguns (document in wallet)

1. Sending to wrong network HRP (`aegis` vs `aegisdev`).  
2. Pasting Ergo address into SC send.  
3. Peg-in without waiting for Ergo confs → mint delay.  
4. Peg-out needs SC confs `M` + Ergo depth `N` (`params.md`).  
5. Backup mnemonic = backup money (notes aren’t on a recoverable “account server”).

---

## 10. Open encoding knobs (don’t block product design)

- Exact Bech32 payload layout / version byte  
- Diversifier bit length  
- Ciphertext AEAD choice  
- Whether miner reward is a shielded note or a short system→shield path  

Frozen later in `aegis-spec` constants — **UX and roles above are locked**.
