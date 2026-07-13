# Contract gaps — USE private cash peg

**Upstream:** `~/coding/reference/ergo-ecosystem/ergohack-sidechain/` (clone of ross-weir/ergohack-sidechain)  
**Target asset:** USE (**3** decimals on mainnet), not sERG/ERG value peg as primary  
**Unlock model:** unsecured only (v1)

## Authoring stance — write fresh, upstream is reference-only (decided)

Aegis contracts are **authored from scratch** against `peg.md`; the ErgoHack contracts are
a *pattern reference*, never a code base to patch. Reasons: upstream is ERG/sERG-centric,
ships `fromBase64("") // todo` placeholders in the unlock path, uses a different unlock
model, and lacks `sc_dest`, fee separation, vault pooling, `V_cap`/`T_delay`. Adapting it
line-by-line risks inheriting exactly the bugs the security docs warn about (E1).
The "must-fix" table below is therefore a **requirements checklist** for the fresh
contracts, keyed to where upstream fell short.

## Contract home

Keep authored ErgoScript under `dev-docs/sidechain/contracts/` until first testnet deploy, then promote to a sibling repo (e.g. `arkadianet/aegis-contracts`) for versioning. Do **not** commit contract deploy keys.

## Inventory (upstream)

| Path | Role |
|---|---|
| `contracts/MainChain/SideChainState.es` | Miner-updated SC tip on Ergo |
| `contracts/MainChain/Unlock.es` | Lock / unlock ERG (adapt → USE) |
| `contracts/SideChain/Unlock.es` | Mint path on SC |
| `contracts/SideChain/UnlockComplete.es` | Complete SC-side unlock |
| `contracts/DoubleUnlockPrevention.es` | Double-spend peg prevention |
| `contracts/relay/*` | BTC relay — **out of scope** |

## Must-fix before testnet value (USE)

| Item | Upstream TODO | USE adaptation |
|---|---|---|
| Inject double-unlock NFT ids | Unlock.es both chains | Same |
| Validate `SideChainState` dataInput | MainChain Unlock | Same |
| Refund path on incomplete unlock | MainChain + SideChain UnlockComplete | Same — needed for UX |
| Digest slice `0..32` vs `1..33` | MainChain Unlock | Resolve with AVL digest tests |
| Sidechain box script bytes (not `false`) | MainChain Unlock L78 | Note script template hash |
| Token id + amount checks | was sERG / ERG value | **USE token id** + any multiple of 0.001 USE (match mainnet) |
| **SC destination in lock box (R4)** | **missing upstream** | See [peg.md](../peg.md) — required for mint assignment |
| Inject UnlockComplete proposition | SideChain Unlock | Same |

## New contracts — no upstream counterpart (must-write, gate items)

These hold the money. The vault gate ("GAPS green") includes **all** of the below —
upstream adaptation alone does not clear it.

| Contract | Must enforce | Open spec items |
|---|---|---|
| **DepositReceipt** | R4 (`sc_dest`) immutable while locked; spendable only by (a) consolidator merge into PegVault or (b) depositor **refund after timeout** if never minted | Timeout height source; refund proves "never minted" how? (likely: refund allowed unconditionally after timeout — SC side must then reject late PegMint of refunded boxes) |
| **PegVault** | Singleton NFT; pays claimant only via valid unlock (anchored burn + DoubleRedeem fresh + `T_delay` elapsed since UnlockIntent); total USE ≤ `V_cap`; never pays from a foreign box | Exact anchor check (tip digest vs later receipt-token trail) |
| **UnlockIntent** | Anyone may post for a real burn; binds `(burn_id, N, tip refs, claimant)`; starts `T_delay` clock; one intent per burn id | Register map; bond/spam control; cancellation on fraud-halt |
| **FeePot** | Buffer for peg-in fee outputs; merged into PegVault by consolidator; **backs the SC emission box** (pot credits minted against proven fee events — I1 counts FeePot as reserve, pot as liability) | Fee delivery: preferred = peg-in tx pays fee output **directly to FeePot script address**, anyone may sweep/merge (TBD confirm); Ergo-reorg policy for pot credits |
| **DoubleRedeem** | Burn id recorded exactly once; checked by every vault payout | Storage format (AVL tree vs token-per-burn), rent behavior |
| **Consolidator path** | Receipt merge into PegVault preserves I1 at every step (no window where notes exist and value is in neither vault nor receipts); respects `V_cap` | Who runs it (anyone / operator bot); batch rules |

## Should-fix soon (not blocking dry-run)

| Item | Notes |
|---|---|
| Receipt tokens / update counter | BIP-300-ish; helps unlock without racing live state box |
| Chain digest transition validation | Hard with rollbacks; document threat if deferred |
| Many SC blocks per Ergo block | Already allowed if height+1 only; MM tip advances locally |

## Explicitly keep / drop

| Item | Decision |
|---|---|
| Per-user lock + unsecured “any burn spends any matching box” | **Forbidden** — theft |
| Secured (depositor-sig) unlock as default | **Drop for v1** — breaks fungible private transfers |
| BTC relay TODOs | **Out of scope** |
| ERG-as-primary peg | **Out of scope** — USE primary |

## Adaptation sketch (MainChain USE peg)

- **Pooled vault** holds all principal USE (not long-lived per-user boxes stealable by foreign burns).  
- Peg-in carries `sc_dest` (R4) for mint assignment, then credits vault.  
- Peg fee paid separately (not haircutting `N`).  
- SC mints shielded note `(N, sc_dest)` once.  
- Unlock: burn notes on SC → claim **from vault** (unsecured fungible).  

Canonical write-up: **`../peg.md`** (and archived `notes/archive/peg-entry-ergoscript.md`).

**Mainnet USE token id (recorded in params.md, verified on-chain):**
`a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669`

## Next contract task

Author USE peg contracts fresh per `peg.md` (upstream reference-only); do not ship on mainnet value until **both** the must-fix table and the new-contracts table are green.
