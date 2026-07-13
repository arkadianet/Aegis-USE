# Decision: how the SC hides money

**Date:** 2026-07-11  
**Status:** **LOCKED** (architecture)  
**Author:** arkadianet  
**Supersedes:** open “C1 vs global pool” in `option-c-sigma-native-research.md`

## Decision

**User value on the privacy SC is a mandatory global shielded note pool.**

```text
On-chain (public):   note commitments in an accumulator + nullifier set + proofs
Off-chain (private): note plaintexts (amount, keys, memo) held by wallets
```

- Hide **sender, receiver, amount** for default SC pays.  
- Anonymity set = **all notes in the pool** (grows with every mint/spend), not a per-tx ring of decoys.  
- **C1 rings are not the target.** Stock ZeroJoin/SigmaJoin (C0) remains rejected.  
- ErgoScript remains for **mainnet peg + SC system boxes only**, not for cleartext user balances.

**Proving engine:** **LOCKED provisional** — **Curve Trees + Bulletproofs(+)**; Halo2 fallback. See `notes/proving-engine-decision.md`.

| Rank | Engine | Status |
|---|---|---|
| **1** | **Curve Trees + Bulletproofs(+)** | **Chosen** — Ergo-adjacent curves, FCMP++/Vcash direction, ~30–40 ms verify (fits 15s) |
| 2 | Halo 2 / Orchard-style | Fallback only |
| — | C1 rings + CT | Rejected as primary |

---

## What “global pool” means (concrete)

Same shape as Zcash Sapling/Orchard, Penumbra, Namada MASP:

| Object | On chain? | Role |
|---|---|---|
| **Note** (amount, spend key, diversifier, …) | No | Wallet-local |
| **Note commitment** | Yes (in tree) | Opaque leaf |
| **Nullifier** | Yes (set) | One-time spend tag |
| **Spend proof** | Yes (in tx) | “I own some unspent note; amounts balance; auth OK” — without saying which |
| **Output proof / new commitments** | Yes | Create change / payment notes |
| **Encrypted note payload** | Yes (ciphertext) | Receiver (and view keys) can decrypt |

**Peg:**

- Peg-in: Ergo receipt with public `N` → SC **mints** note commitment(s) value `N` to `sc_dest`.  
- Peg-out: burn note(s) value `N` (nullify + proof) → Ergo vault pays `N`.  
- Mid-life SC transfers never show cleartext USE amounts.

---

## Research evidence (why not C1)

### 1. New privacy systems converge on note pools

| System | Model | Source |
|---|---|---|
| **Zcash** Sapling / Orchard | Global shielded pool + nullifiers | Zcash protocol |
| **Penumbra** | Multi-asset shielded pool (Sapling-derived) | [notes/nullifiers/trees](https://protocol.penumbra.zone/main/concepts/notes_nullifiers_trees.html) |
| **Namada** | Unified MASP across assets | Namada specs / blog |
| **Vcash** (paper system) | Curve Trees + BP, full anonymity set, ~4KB tx | [ePrint 2022/756](https://eprint.iacr.org/2022/756) |
| **Firo** Lelantus Spark | Moving Spark sets → Curve Trees for full membership | Firo research notes |

None of the modern “private payment rail” designs start with fixed-size rings as the end state.

### 2. Monero is *leaving* rings for a global set

Monero’s **FCMP++** replaces “1-of-16 ring” with a proof of membership in **all** outputs (~150M+), built on **Curve Trees**, now in stressnet / integration (2025–2026). That is the ring-coin ecosystem admitting: **rings are not the long-term bar**.

We should not ship a greenfield SC on the model Monero is actively replacing.

### 3. Ring privacy fails hardest on quiet chains

Documented issues:

- Decoy-selection bugs (e.g. “10-block decoy”) collapsing effective anonymity ([Monero #8872](https://github.com/monero-project/monero/issues/8872); [arXiv:2408.05332](https://arxiv.org/abs/2408.05332)).  
- Statistical decoy heuristics; effective ring size &lt; nominal.  
- Early / low-volume networks → few good decoys → worse than advertised.

Our SC starts **quiet** (dogfood MM). Rings would be weakest exactly when we need them most. A global pool is thin at first too, but **every** mint helps the same set, and there is no decoy-policy footgun.

### 4. Ergo-native “C” alone cannot meet the bar

| Ergo stack piece | Gives |
|---|---|
| ProveDlog / ProveDHTuple / ZeroJoin / SigmaJoin | Link-breaking; **amounts public** |
| Stealth | Receiver privacy (partial) |
| Bulletproofs (WIP on Ergo) | Amount range — needed either way |
| Curve Trees on Ergo ([a-shannon](https://github.com/a-shannon/ergo-curve-trees)) | **Membership** half of a global pool |

So “explore C” concludes: **reuse Sigma where it fits (ownership leaves, system scripts); implement pool membership + CT as first-class SC consensus crypto** — preferably Curve-Tree-shaped, not Sapling-or-bust day one.

---

## Efficiency & bloat (honest budgets)

Private money is **not** free. It is also **not** “multi-MB per coffee” if we stay minimal.

### Typical sizes (order of magnitude from literature / production)

| Design | Approx spend tx / proof size | Notes |
|---|---|---|
| Zcash Sapling | ~2–3 KB | Trusted setup (legacy) |
| Vcash (Curve Trees paper) | ~**4 KB** tx; membership ~2.9 KB @ 2^40; verify ~40–80 ms (batch better) | Transparent |
| Monero rings (today) | Often **larger** (ring + BP) | Decoy lists on-chain |
| Cleartext Ergo tx | Hundreds of bytes | Not private |

**SC block growth drivers:**

1. **Proof bytes per spend** (dominant) — budget target: **≤ 8 KB** proof payload per private spend for v1 (tune after engine pick).  
2. **Nullifier set** — one hash/tag per spent note, forever (or with a documented pruning/epoch policy later).  
3. **Commitment accumulator** — root is tiny; tree stored by full nodes (like any UTXO set).  
4. **Ciphertexts** — encrypted note payloads (~hundreds of bytes each).

**Not** storing cleartext balances for every user. Explorers see blobs + nullifiers, not dollar ledgers.

### Efficiency rules for *our* SC (locked policy)

- Verify proofs in **native Rust** at block validation — do **not** run Curve Tree / BP verify as multi-tx ErgoScript JIT pipelines on the SC (that L1 trick is for mainnet cost models; we control SC consensus).  
- Mandatory shielded path for user value (no transparent USE UX that shrinks the set).  
- System boxes (fee pot, peg mint/burn gates) may be clear / scripted.  
- Light clients: compact note + nullifier sync (Zcash/Penumbra pattern) — required before “phone wallet,” not before node boot.

### Will it “massively bloat”?

| Scenario | Expectation |
|---|---|
| Dogfood (tens–hundreds txs/day) | Negligible disk vs any Ergo node |
| Busy payment rail (thousands txs/day × ~4–8 KB) | Grows like any shielded chain — **linear in tx count**, manageable with pruning of old bodies if headers+nullifiers+tree retained |
| Worst mistake | Cleartext “mix boxes” × denominations × remixes — UTXO spam **and** weak privacy |

Global pool is the *cleaner* state model: one tree + one nullifier set, not a growing soup of half-mix UTXOs.

---

## ErgoScript — final wording

| Surface | Language / crypto |
|---|---|
| Ergo mainnet peg (receipt, vault, SideChainState, fee pot, double-redeem) | **ErgoScript** |
| SC system contracts (emissions pot, peg mint/burn authorization) | ErgoScript / Sigma OK |
| SC **user money** | **Shielded notes** + consensus proof verify — **not** transparent ErgoScript balances |

We are an **Ergo-family sidechain with a shielded cash layer**, not “ErgoMixer on a fast chain.”

---

## What stays open (next design, still no scaffold required)

1. **Exact proving stack:** Curve Trees+BP vs Halo2 — spike S2 with byte/µs table.  
2. **Note plaintext format** + viewing keys.  
3. **Tree parameters** (arity, curves: align with secp256k1/secq if Ergo-adjacent).  
4. **`(M,N)` peg confs** (already provisional in params).  
5. Nullifier pruning / archival policy.

---

## Doc updates triggered by this lock

- `full-privacy.md` — crypto path → global pool locked  
- `option-c-sigma-native-research.md` — status → concluded; C1 rejected as primary  
- Spec one-liner privacy row — point here  

---

## Self-review

- [x] Architecture locked (global pool), engine open  
- [x] Evidence from other coins + papers cited  
- [x] Rings rejected with reasons that fit *our* quiet SC  
- [x] Bloat discussed with numeric order-of-magnitude, not vibes  
- [x] ErgoScript role clarified  

**Review ask:** Confirm this lock. Then next design doc = note lifecycle (mint/spend/burn) under global pool — still before Task 3 scaffold.
