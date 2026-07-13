# Option C research — Sigma-native notes

**Date:** 2026-07-11  
**Status:** **concluded** — see `privacy-mechanism-decision.md`  
**Question:** Can we meet the full-privacy bar using Ergo’s Σ-protocol / ErgoScript stack alone?

## Verdict (final)

| Claim | Finding |
|---|---|
| Stock ZeroJoin / SigmaJoin | **Fails** — amounts public |
| Pure ErgoTree Sigma = Sapling | **No** |
| C1 rings as primary design | **Rejected** — industry (incl. Monero FCMP++) moving to full-set membership; weak on quiet SCs |
| Global shielded pool | **LOCKED** as architecture |
| Sigma / ErgoScript role | Peg + system boxes; ownership leaves may compose inside proofs |
| Curve Trees | **Preferred membership engine candidate** (with Bulletproofs for amounts) |

---

## What “C” means

Compose privacy from **Σ-protocols and Ergo-native crypto** so user value is notes/boxes spent under proofs, without importing Sapling/Orchard circuits as the primary design.

That is different from:

- **A** — commitment tree + nullifiers + spend/output **circuit** (Zcash-like).  
- **B** — confidential amounts + **ring** decoys (Monero-like).

C can **borrow pieces** of B (rings, Pedersen) while staying “native” to how Ergo already thinks about proofs.

---

## What Ergo already has (grounded)

### Production / documented (link-breaking, not amount-hiding)

| Primitive | Role | Sources |
|---|---|---|
| `ProveDlog` / `ProveDHTuple` | Ownership / DH stealth without revealing key | ErgoDocs Σ-protocols; this repo’s `ergo-sigma` / wallet prover |
| ZeroJoin | Non-custodial mix via DH + rings | [ZeroJoin](https://docs.ergoplatform.com/dev/crypto/zerojoin/) |
| SigmaJoin | Non-interactive / outsourceable mix boxes | [SigmaJoin](https://docs.ergoplatform.com/eco/sigmajoin/) |
| Stealth / covert addresses | Hide receiver (one-time keys) | ErgoMixer docs; forum stealth threads |

**Critical design choice in ZeroJoin / SigmaJoin:** mix **fixed-denomination cleartext boxes**. Amounts are visible so they can skip heavy range proofs. That is **partial privacy** (breaks graph links), not our full bar.

### Research / WIP (amount-hiding pieces)

| Item | Status | Relevance |
|---|---|---|
| Bulletproof range-proof pattern | Docs **WIP**; sigmastate [PR #1079](https://github.com/ergoplatform/sigmastate-interpreter/pull/1079) open (tests toward BP verify) | Needed for Pedersen CT |
| Temporal Stealth Note Protocol (TSNP) | Forum design — **Sigma-native** bearer notes, DH redeem | Hides **redeemer link**; amounts / denoms still public pool boxes |
| `ergoscript-contracts-rs` privacy sketches | Educational stubs (ring+nullifier, “CT” with simplified hashes) | **Not** a production CT implementation — treat as pattern names only |
| EIP-0045 native STARK verify | Proposal for Ergo L1 | Path to circuit privacy *on mainnet*; our SC can add consensus opcodes without waiting on Scala majority — but that’s still “foreign prover,” closer to A |
| **[ergo-curve-trees](https://github.com/a-shannon/ergo-curve-trees)** (A. Shannon) | Testnet demo: on-chain Curve Tree membership verify (Ergo 6.0 / EIP-0050) | **High research value** for C2 — private set membership without trusted setup; see § Curve Trees below |

---

## Mapping C to our privacy bar

| Property | Stock C (ZeroJoin/SigmaJoin/stealth) | C-extended (what a serious spike must build) |
|---|---|---|
| Hide sender | Partial (mix / rings) | Rings **or** global nullifiers + membership |
| Hide receiver | Yes (stealth / encrypted dest) | Same + note encryption / view keys |
| Hide amount | **No** | Pedersen commitments + **range proofs** (Bulletproofs-class) + balance equation |
| Arbitrary `0.001` USE | Only via many cleartext bills or leak | Homomorphic CT (any size in commitment) |
| Peg mint/burn of public `N` | Easy (clear boxes) | Open `N` at peg edge only; SC life stays committed |
| Anonymity set | Pool of same-denom boxes | Rings (local) **or** note tree (global → needs membership ZK ≈ A) |

**Hard stop:** without amount-hiding crypto, C cannot satisfy `full-privacy.md`. Fixed denoms were already rejected as the product model.

---

## Three honest C variants

### C0 — Stock mixer notes (reject for product)

Consensus-enforced SigmaJoin/ZeroJoin + stealth. Cleartext amounts.  
**Privacy:** link-breaking only.  
**Effort:** lowest, vibecode-reachable.  
**Decision:** **out** relative to the locked bar.

### C1 — Sigma ownership + confidential amounts (rings)

- Value = Pedersen commitment (not box `value` / token amount in clear).  
- Spend = Σ ownership (dlog / DHT / OR-ring) + Bulletproof range + input−output balance.  
- Anonymity set = **ring size** (pick decoys from recent notes).  

**Privacy:** ≈ Monero-class (option **B** with ErgoScript-shaped ownership).  
**Design fit:** still Ergo-family; no Sapling circuit, but **Bulletproofs are not** classic `ProveDlog` leaves — they are an extra verifier in consensus.  
**Gaps:** decoy selection, fee leakage, scanning model, ring growth vs SC throughput.

### C2 — Sigma + note commitment tree (Sapling-shaped, Sigma-branded)

- Global Merkle/MMR **or Curve Tree** of note commitments.  
- Spend proves membership + nullifier + balance **in ZK**.  

Succinct membership-in-tree is **not** something stock Σ AND/OR compositions do well. Paths:

- huge proofs, or  
- a circuit/STARK (classic **A**), or  
- **Curve Trees + Bulletproofs** (transparent accumulator; see below) — still a proving stack, but Ergo-adjacent and no trusted setup, or  
- EIP-0045-style native verify.

**Privacy:** best (global set).  
**Honesty:** without Curve Trees / circuits this is **A**. With Curve Trees it is **C2 ≈ A-class privacy, different accumulator**.

---

## Curve Trees ([ergo-curve-trees](https://github.com/a-shannon/ergo-curve-trees)) — value for us?

**What it is:** ErgoScript + off-chain TS prover for [Curve Trees](https://eprint.iacr.org/2022/756) — transparent ZK set-membership (hide *which* leaf; root public). Testnet deploy/spend claimed; needs Ergo **6.0.3+** / treeVersion 3 / EIP-0050 `UnsignedBigInt`. Companion write-up: [a-shannon/ergo-research](https://github.com/a-shannon/ergo-research) (pipelining / cost analysis for L1).

**What it gives our bar:**

| Need | Covered by curve-trees alone? |
|---|---|
| Hide which note you spend (global set) | **Yes** — core purpose |
| Hide amount | **No** — still need Pedersen CT + range proofs |
| Hide receiver / note plaintext | **No** — wallet encryption / view keys separate |
| Double-spend (nullifiers) | **No** — compose separately |
| Peg vault ErgoScript | Unrelated |

So: **valuable research input for C2 membership**, not a drop-in private USE wallet.

**Value judgment:**

| Use | Verdict |
|---|---|
| Study / spike reference for “global anonymity without Sapling SNARK” | **Yes — high** |
| Day-one dependency for SC payments | **No** — research/demo; L1 cost story involves heavy JIT / pipelining in the paper |
| Mainnet peg contracts | Weak fit today (6.0 + cost); peg stays boring ErgoScript anyway |
| **Our SC consensus** | Stronger fit: we can verify Curve Tree (or simpler Merkle+circuit) in **native Rust** at block validate time, avoiding ErgoScript JIT hell |

**How it changes A vs C:** Curve Trees make “C2” less hand-wavy — membership ZK without trusted setup is a real Ergo-ecosystem path. It does **not** remove the need for amount-hiding. Full rail ≈ **membership (Curve Tree or Sapling tree) + CT/range + nullifier + note encrypt**. That package is still **A-class privacy**; Curve Trees are a candidate *engine* for the membership half, not a reason to settle for C0/C1 if we want global sets.

---

## Why C is still worth exploring (for us)

1. **Ownership / stealth / DH** are already in this monorepo’s prover path — reuse beats relearning.  
2. A **SC we control** can add Bulletproof (or similar) verify **without** waiting for Ergo mainnet hard fork — C1 is more reachable here than as an L1 EIP.  
3. Peg edge already reveals `N`; the hard part is **SC life**. C1 can hide SC amounts while peg stays boring ErgoScript.  
4. If C1 spike fails cost/complexity, we **graduate to A** with clear evidence — not vibes.  
5. Ecosystem story: “privacy cash on Sigma” is stronger than “we bolted Orchard onto Autolykos” *if* C1 hits the bar.

---

## What would falsify C

Stop exploring C and lock A if a spike shows any of:

1. Bulletproof (or equivalent) verify is too heavy for ~15s SC blocks at target throughput.  
2. No sound balance + range design without a general circuit.  
3. Ring anonymity is unacceptable vs global note pool for a payment rail.  
4. Wallet sync / view-key story collapses without Sapling-style note plaintexts + nullifier set.

---

## Spike plan (research → decide)

Keep this **off consensus-critical path** of peg contracts / node boot.

| Step | Work | Done when |
|---|---|---|
| S0 | Written (this doc) | ✓ |
| S1 | Inventory: what `ergo-sigma` can prove today vs needs new verify opcode | Table of leaf types + cost |
| S2 | Minimal CT toy: Pedersen commit `v`, prove `v ∈ [0, 2^n)`, balance two commits (off-chain + verify stub) | Pass/fail + µs/bytes |
| S3 | Add Σ spend: proveDlog on note key **or** small OR-ring (size 8–16) over decoys | Same metrics + anonymity notes |
| S4 | Peg interface sketch: mint opens `N` → commit; burn opens `N` from commit for vault claim | No cleartext mid-life |
| S5 | Decision memo: **C1** / **hybrid C1→A** / **A** | Update `full-privacy.md` |

Suggested spike home later: `aegis-spec` tests or a throwaway `dev-docs/sidechain/spikes/c-ct/` — not mainnet contracts.

---

## Relation to A / B (after research)

```text
C0 stock mixer ──────────► REJECT (no amount hide)

C1 Sigma + BP/CT + rings ─► real candidate (= B-shaped privacy, Ergo ownership)
         │
         └─ if membership-in-tree required ─► becomes A

A shielded pool ──────────► best global anonymity; heavier build
B Monero-like ────────────► same privacy class as C1; less Ergo-native story
```

---

## References

- `notes/full-privacy.md` — product bar  
- ErgoDocs: ZeroJoin, SigmaJoin, Σ-protocols, Bulletproof pattern (WIP)  
- sigmastate-interpreter PR #1079 (Bulletproofs tests)  
- TSNP forum spec (Sigma-native notes, amounts public)  
- Local: `reference/ergo-tooling/ergoscript-contracts-rs/src/contracts/privacy.rs` (stubs only)  
- This monorepo: `ergo-sigma` DHT/DLog verify; `ergo-wallet` proving for ProveDlog/ProveDHTuple

## Open question for product owner

For the payment rail, is **ring-sized** anonymity (C1) acceptable if amounts are hidden, or do we require a **global** note pool (A / C2)? That single answer dominates the C vs A decision after S2–S3.
