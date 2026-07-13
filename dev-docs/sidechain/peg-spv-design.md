# Aegis — peg + Ergo-SPV-in-consensus (G2.5 design DRAFT)

**Date:** 2026-07-12
**Status:** DRAFT for operator review — not canon. Flags mark unresolved points.
**Reads:** [peg.md](./peg.md) · [contracts/GAPS.md](./contracts/GAPS.md) · [engineering.md](./engineering.md) §3 · [security.md](./security.md) (A2, I1, U1) · [aegis-spec.md](./aegis-spec.md) §11 · [params.md](./params.md)
**Role:** turns engineering §3's "PegMint must embed a self-contained Ergo proof" requirement into a concrete verification design, and pins the peg-in/peg-out flows to named boxes. Consensus numbers (`M/N/N_mint/T_delay/V_cap`) are frozen in params.md; this doc must not contradict them.

---

## 0. The objectivity problem (why this doc exists)

"Trusted Ergo node" is **not** consensus (security §7, A2). A validator syncing Aegis from genesis years later must accept exactly the PegMints every other validator accepts, without querying a live Ergo node it has to trust. So each PegMint must carry a **self-contained proof** that the referenced Ergo lock really happened and had enough work on top of it — an **Ergo SPV client running inside Aegis consensus**, in Rust.

### 0a. Reuse finding (materially changes the effort estimate)

The monorepo already verifies Ergo natively, so the SPV client is mostly *wiring*, not new crypto:

| Need | Existing Rust |
|---|---|
| Autolykos v2 PoW check | `ergo-crypto/src/{pow.rs, autolykos/}` |
| Difficulty / `nBits` decode + cumulative work | `ergo-crypto/src/difficulty.rs` |
| Ergo header validation | `ergo-validation/src/header.rs` |
| **NiPoPoW proof verify** (succinct cumulative-work proof) | `ergo-validation/src/popow/proof.rs` |
| Tx-inclusion (txRoot) | `ergo-ser/src/batch_merkle_proof.rs` |
| AVL / box-set proofs | `ergo-crypto/src/merkle`, `ergo-ser` AVL support |

⚠ **Verify before relying:** confirm each of the above is (a) consensus-faithful to mainnet and (b) usable as a *library* from `aegis-node` without dragging in full `ergo-state`. The reuse claim is the load-bearing assumption of this whole design's feasibility — spike it first (see build order).

---

## 1. Ergo-SPV-in-consensus for PegMint

### 1a. What a PegMint proof embeds

```text
PegMint {
  receipt_box_bytes         // the DepositReceipt: N USE + R4=sc_dest (+R5/R6)
  box_inclusion_proof       // receipt_box ∈ tx  (or ∈ Ergo UTXO/tx output set)
  tx_inclusion_proof        // tx ∈ header.txRoot  (BatchMerkleProof)
  anchor_header             // the Ergo header whose block contains the receipt
  work_proof                // NiPoPoW proof (preferred) OR header segment:
                            //   genesis/checkpoint → anchor_header, + N_mint headers on top
}
```

### 1b. Verification steps Aegis consensus runs (all in-Rust, deterministic)

1. **Pinned origin.** `anchor` chain roots at a consensus-pinned Ergo **genesis hash** (or a signed checkpoint — see §1d). Hard-coded in `aegis-spec`, chain-id-breaking to change.
2. **PoW on every header** in the work proof: `autolykos_verify(h)` and `nBits` matches the DAA-implied difficulty (reuse `ergo-crypto`).
3. **Cumulative work.** The proof establishes total work from origin to `anchor` ≥ the threshold the pinned honest-Ergo-hashrate estimate implies (NiPoPoW gives this succinctly without every header). ⚠ Pin the NiPoPoW security params (m, k) — DEFERRED to spike.
4. **Depth `N_mint`.** ≥ `N_mint` (params: 10) valid Ergo headers extend `anchor` within the proof — the lock is buried.
5. **Inclusion.** `tx ∈ anchor.txRoot` (BatchMerkleProof) and `receipt_box ∈ tx`.
6. **Receipt well-formedness.** token id == `USE_TOKEN_ID` (params), `N` a multiple of `0.001` USE, `R4 = sc_dest` present, script hash == the pinned DepositReceipt template (M1/A3).
7. **Uniqueness (I2/A1).** `receipt.boxId` ∉ Aegis nullifier-analogue **PegMint used-set** (consensus state, versioned like the nullifier set).
8. On success: mint one shielded note `(N, sc_dest)` (a normal PegMint output note, `rho = H_ρ(boxId)` per note-protocol §3), insert `boxId` into the used-set, credit the pot by the proven peg-in fee event (§3).

Steps 2–5 are pure functions of the proof bytes → **objective**: any validator recomputes the same accept/reject.

### 1c. Ergo reorgs deeper than `N_mint` — THE hard risk

If an Ergo reorg **deeper than `N_mint`** orphans a receipt *after* Aegis minted against it, the lock no longer exists on Ergo but the shielded notes do → **I1 reserve break** (unbacked USE). Aegis cannot un-mint (notes may already be spent/shielded). Options, none free:

| Option | Cost |
|---|---|
| **(A) Large `N_mint`** so a deeper reorg is economically absurd | Slower peg-in; `N_mint`=10 (~20 min) is dogfood-thin — flag for raise before value |
| **(B) Checkpoint/attester finality gate** — a PegMint only finalizes once an attester quorum (S1) or a signed Ergo checkpoint confirms the anchor at depth `D_final ≫ N_mint` | Adds the S1 trust the peg was trying to avoid; but bounded and declared |
| **(C) Accept as known dogfood risk under `V_cap`** — bounded loss ≤ `V_cap` (1000 USE); the honest recovery is operator socialization | Only tolerable at dogfood scale |

**DRAFT recommendation:** dogfood = (C) under `V_cap`, with (A) `N_mint` raised meaningfully before any non-dust value, migrating to (B) with S1. Reconcile `N_mint` (params, currently 10) with whatever (A) needs — **do not silently diverge from params.md; propose the change there.**

### 1d. Genesis vs checkpoint origin

Verifying cumulative work from the *real* Ergo genesis is heavy even with NiPoPoW. Pragmatic: pin a recent **signed Ergo checkpoint** (height + header hash) as origin. This trades a one-time trust-on-first-use (matches how every SPV client bootstraps) for far cheaper proofs. ⚠ Decide genesis-vs-checkpoint; if checkpoint, it is a governance artifact and must be documented as such (a mild objectivity caveat, honestly disclosed).

---

## 2. Peg-in / peg-out flows (named boxes)

### 2a. Peg-in (Ergo lock → Aegis PegMint)

```text
1. User (Ergo tx): output0 = DepositReceipt { N USE, R4=sc_dest, R6=peg-ver }
                   output1 = peg_in_fee USE → FeePot script addr        (fee ON TOP, not haircut)
                   (does NOT spend PegVault — Alice+Bob same block OK, peg.md §1)
2. Wait N_mint Ergo confs.
3. Any party builds a PegMint (§1a) and submits to Aegis (watcher Mode B = broadcast only, no mint authority).
4. Aegis consensus verifies (§1b) → mints note (N, sc_dest), records boxId used, credits pot by proven fee.
5. Later: consolidator merges DepositReceipt + FeePot boxes → PegVault (I1 preserved every step).
```

Fresh contracts touched: **DepositReceipt**, **FeePot**, **PegVault**, **consolidator** (GAPS new-contracts table).

### 2b. Peg-out (Aegis burn → Ergo unlock)

```text
1. Note holder: PegBurn N on Aegis (a shielded spend whose output is a "burn" — reveals N publicly, per peg.md §4;
   nullifiers spent, no new note of value N). Produces burn_id.
2. Ergo tx: post UnlockIntent { burn_id, N, tip refs, claimant }  → starts T_delay clock (720 Ergo blocks ≈ 1d).
3. Wait: M Aegis confs after burn (120) + N Ergo depth after anchor (10) + T_delay; attest if U1-strong.
4. PegVault pays claimant N − peg_out_fee USE; fee-worth stays in vault, mirrored as SC pot credit at burn.
5. DoubleRedeem records burn_id (spent once; I3).
```

Fresh contracts: **UnlockIntent**, **PegVault**, **DoubleRedeem**. Exit rights follow *who holds notes now*, never who deposited (peg.md §4 — the "any burn spends Alice's box" theft is forbidden, GAPS).

⚠ **Direction asymmetry (important).** Peg-*in* objectivity is Ergo-SPV-**in-Aegis** (this doc's §1). Peg-*out* validity is the reverse: the **Ergo** UnlockIntent/PegVault contracts must be convinced a real Aegis burn occurred — that is the **SideChainState tip digest** (miner-posted, ErgoHack pattern) or attester quorum (S1), verified in *ErgoScript*, not Rust. The Ergo side cannot run the Aegis shielded verifier. This is exactly the C1 "lying tip" surface → **U1 ladder governs it** (V_cap + T_delay dogfood; attesters strong). Keep the two directions conceptually separate.

---

## 3. Economic invariant (I1) and pot crediting

```text
spendable_reserve = PegVault.USE + Σ(unmerged DepositReceipt.USE) + Σ(unmerged FeePot.USE)
spendable_reserve ≥ Σ(unspent note values) + emission_pot_balance + pending_burns_accounting
```

- Peg-edge `%` fees (params: `max(1 USE, 1%×N)` each way; dogfood `max(0.1,1%×N)`) land in **FeePot** on peg-in and are retained in **PegVault** on peg-out. Both **back the SC emission pot**: the pot is credited (as a public integer in SC state) *against proven fee events*, so FeePot/retained-fee count as reserve and the pot counts as a liability (peg.md §6, security I1).
- ⚠ **Pot-credit ↔ Ergo-reorg coupling.** A pot credit minted from a peg-in fee that later reorgs away is the same I1 problem as §1c — the pot credit must ride the same `N_mint`/finality gate as the mint. Bind pot crediting to PegMint finalization, not to first-sight of the fee box.
- Ops: expose I1 as a metric; **halt peg-out RPC if `spendable_reserve` < liabilities** (peg.md §6).

## 4. Dogfood-mode fallback (declared, NOT trust-minimized)

If the full §1 SPV-in-consensus exceeds budget (engineering §6 kill criterion: "W3 SPV design exceeds budget → operator-mode with hard caps; do not fake objectivity"):

- **Operator-mode PegMint:** an operator key signs PegMints after observing `N_mint` confs on its own Ergo node. Aegis consensus checks the operator signature instead of the §1 work proof.
- **Hard caps:** `V_cap` (1000 USE) bounds total exposure; keep `M/N/N_mint/T_delay` as-is.
- **Honesty (security §1 non-claim):** this is **declared operator custody**, explicitly *not objective*, *not a trust-minimized bridge*, *not a drivechain*. Wallet/UI must say so (M6/M7). It is a stepping stone; the §1 client replaces it before value scales.
- Migration path: operator-mode and §1-mode share the *same* PegMint output/used-set semantics — only the authorization check differs — so swapping in the work proof later is a localized change, not a redesign.

## 5. Open questions / risks (for external review + operator)

1. **Ergo reorg > `N_mint`** (§1c) — the unavoidable objectivity/liveness tradeoff. Biggest risk; pick (A)/(B)/(C) mix and reconcile `N_mint` with params.
2. **Reuse feasibility** (§0a) — is the monorepo's PoW/NiPoPoW/inclusion code usable stand-alone and consensus-faithful from `aegis-node`? Spike gates everything.
3. **NiPoPoW parameters (m, k)** and genesis-vs-checkpoint origin (§1d) — security/size tradeoff, unpinned.
4. **PegMint used-set growth** — grows forever like the nullifier set; same R1-T-style remedy question (engineering §3 state-growth).
5. **Peg-out tip trust (C1)** — the SideChainState digest is miner-posted and *not* objective; the whole peg-out direction leans on U1. Chain-digest transition validation "hard with rollbacks" is still open (GAPS should-fix).
6. **Fresh contract specs** — UnlockIntent register map, DepositReceipt refund-after-timeout vs late-PegMint rejection, DoubleRedeem storage (AVL vs token-per-burn), `R_rent` endowment — all GAPS open items, unchanged by this doc.
7. **PegBurn shape** — how a burn is expressed in the uniform 2-in/2-out shielded tx (note-protocol §6) without leaking beyond the public `N` it must reveal — needs a note-protocol cross-check.

## 6. Rough build order

1. **SPV-reuse spike** — prove `aegis-node` can call the monorepo Autolykos + NiPoPoW + BatchMerkleProof verifiers stand-alone on real mainnet headers/inclusion (§0a). Kill/redesign gate.
2. **PegMint verifier** (`aegis-crypto`/`aegis-node`): the §1b function over a `PegMintProof` type, vectored against real Ergo mainnet blocks (oracle = mainnet bytes).
3. **Used-set + pot-credit consensus state** — versioned, reorg-safe, wired into block apply/rollback (mirrors the nullifier-set machinery already built in P2).
4. **Fresh ErgoScript contracts** per GAPS (DepositReceipt → FeePot → PegVault → UnlockIntent → DoubleRedeem → consolidator), authored fresh, on **testnet**, alongside a Scala node.
5. **operator-mode first** (§4) end-to-end on testnet to exercise flows; swap in the §1 verifier behind it.
6. **U1-dogfood** peg-out with `V_cap` + `T_delay`; S1 attesters only when raising the cap.

---
*Draft. Everything under ⚠ is unconfirmed and awaits operator/reviewer decision; nothing here overrides params.md or security.md.*
