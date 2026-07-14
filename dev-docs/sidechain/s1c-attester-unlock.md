# S1c — k-of-n attester authority for the peg (closes C1)

**Status:** design + compiled prototype for review (2026-07-15, branch
`design/s1c-attester-unlock`). **HOLD:** no merge / no redeploy without
operator sign-off. Builds on the S1a/S1b attester substrate
(`attester-infra.md`).

## What C1 is, and why this closes it

The peg-out vault (`PegVault.es`) faithfully enforces the *ceremony* — a
matching `UnlockIntent`, `T_delay`, `DoubleRedeem` freshness, a capped and
fee-pinned payout from the singleton — but it does **not** prove the Aegis
burn was real. Burn authenticity flows from the `SideChainState` box: a
payout's `UnlockIntent` proves `burn_id → N` membership in that box's
append-only burn tree. So *whoever can advance `SideChainState` decides
which burns are real.*

In v1 that authority is a **single key** (`proveDlog(TIP_PK)`, the miner-tip
key). One compromised or malicious key can insert a fake burn and drain up
to `V_cap`. That is C1.

**S1c swaps that single key for the k-of-n attester federation:**

```
  proveDlog(TIP_PK)
→ atLeast(ATTEST_K, Coll(proveDlog(ATTESTER_PK_1), …, proveDlog(ATTESTER_PK_N)))
```

Now advancing the tip — including inserting a burn — requires **k of n
attesters to co-sign the update transaction**. A fake burn requires **k
colluding attesters** instead of one key. That is the U1-strong upgrade
DESIGN.md §C1 / line 141 calls for: *"replace `proveDlog(TIP_PK)` in
SideChainState with the k-of-n predicate — the transition-constrained tree
stays as-is."*

## Blast radius: one contract

Only `SideChainState.es` changes. **`PegVault.es`, `UnlockIntent.es`,
`DepositReceipt.es`, `FeePot.es`, `DoubleRedeem.es` are untouched** — they
already bind to the `SideChainState` singleton by NFT (pass 3), so hardening
*who may advance it* propagates to every payout for free. Every other
security predicate in `SideChainState` (append-only tree transition, strict
height monotonicity, rate limit, no-USE / `tokens.size == 1`, fee-siphon
guard) is preserved verbatim; only the authorizing sigma proposition
changes.

## What k-of-n does and does not buy

- **Does:** a burn is now authorized by ≥k attesters, not one key.
  `< k` malicious attesters cannot forge a burn. A forged burn still needs
  ≥k colluders and still leaves a permanent, attributable on-chain insert
  record (fraud evidence). Bounded by `V_cap` + `T_delay` as before.
- **Does not:** it does **not** verify the Aegis tip commitment `R5`
  (still unverified data) or make the peg *trustless* — it makes it a
  **majority-honest federation** (U1-strong) instead of a single point of
  trust. Full trust-minimization is the SPV / STARK-settlement end-state
  (S2 / `stark-settlement-design.md`), not this slice.

## Deploy constants

`SideChainState` gains `ATTESTER_PK_1..N` (33-byte compressed points, the
same secp256k1 keys the S1a federation uses) and an inlined `ATTEST_K`
threshold, replacing `TIP_PK`. The **canonical source is authored 2-of-3**
(the dogfood default in `design-mitigations.md`: `attest_k/n = 2/3`). A
different `(k, n)` re-authors `ATTEST_K` + the `ATTESTER_PK_i` list + the
`atLeast` `Coll` — a small mechanical per-deploy edit; testnet's 3-of-5 adds
two more pubkey placeholders. (An n-agnostic single-`Coll[GroupElement]`
injection was considered and rejected: textual `fromBase64` injection yields
`Coll[Byte]`, and reconstructing `Coll[GroupElement]` in-script is more
surface than explicit `decodePoint` placeholders for no security gain.)

The on-chain set is **fixed at deploy**. Rotation (add/remove/replace an
attester) is **S1d** — an `AttestRegistry` NFT box spent under the current
set's `atLeast`. Until S1d, rotation = redeploy.

## Redeploy is chain-id-breaking (for the peg deployment)

Changing `SideChainState.es` changes its compiled tree → a new script
address → a **new `SideChainState` singleton must be minted and the peg
re-provisioned** (new vault/receipt/intent hashes cascade through the
injected constants). This is a peg-deployment re-cut, free on testnet. The
Aegis *chain* genesis is unaffected — this is Ergo-side contract state, not
Aegis consensus.

## Compile / parity status

- The modified `SideChainState.es` **compiles** under the pinned
  `ergo-compiler` (tree v3); placeholder-form size moves **209 → 225 B**
  (+16 B for the 3-way `atLeast` vs one `proveDlog`; updated in the
  structure-regression test). A test also injects a **real 2-of-3
  federation** (keys from `aegis-attest`) and confirms `decodePoint` accepts
  them and the tree bakes them in.
- **Before redeploy (post-sign-off):** (1) wire real attester-pubkey
  injection through `ScriptConstants` (done in this branch:
  `attester_pks`), (2) regenerate the peg parity vectors against a fresh
  testnet `SideChainState`, (3) an external review pass on the new
  authority predicate (the sum-accounting + tree-transition review carries
  over unchanged; only the sigma proposition is new).

## Red-team review (2026-07-15) — VERDICT: SOUND

An adversarial review verified against ground truth (the consensus
interpreter's `at_least_reduce`, not the diff's own comments) and found
**no contract bug**:

- `atLeast(2, Coll(dlog1..3))` genuinely reduces to a `Cthreshold{k:2}` that
  requires ≥2 of 3 — confirmed in `ergo-sigma`.
- The non-authority predicates are **byte-identical** to `main` (comment-
  stripped diff) — zero regression.
- Single spend path, no alternate tip-advance; the payout side still binds
  the singleton by NFT (`UnlockIntent` untouched is sufficient).
- Injection order + the 209→225 pin are correct; trust-model claims honest.

### Deploy-ceremony gates (the ErgoScript cannot enforce these — the deploy MUST)

- **D1 — threshold bound.** `atLeast` treats `k ≤ 0` as *trivially true*
  (anyone spends) and `k > n` as *unsatisfiable* (box bricked). `ATTEST_K`
  is inlined at `2` here (safe), but any re-author MUST assert
  `1 ≤ ATTEST_K ≤ n`, and for real security `k ≥ ⌊n/2⌋+1`.
- **D2 — distinct keys.** `atLeast` does not dedup; a duplicated key lets one
  secret fill multiple slots and collapse the threshold. **Now enforced in
  the harness** (`side_chain_state` returns `DuplicateAttesterKey`; tested),
  but the deploy must still inject keys that are on-curve *and*
  independently held.
- **D3 — regenerate parity vectors.** The 225-byte pin is a self-measurement;
  `SideChainState` has no on-chain oracle until deployed. Regenerate peg
  parity vectors against a fresh testnet `SideChainState` before value.

### Tracked (do not lose)

- **P2-b:** `UnlockIntent.es` lines 28–29 still say the burn set is
  "TIP_PK-posted"; after S1c it is k-of-n-posted. The **file** stays
  untouched on purpose (editing changes its tree hash — chain-id-breaking);
  sweep the comment at the next `UnlockIntent` re-cut.

## Gate

The red-team review stands in for design sign-off (operator delegated it).
The **value gate is unchanged**: external-cryptographer sign-off before any
real USE, and the deploy prerequisites above (real-key injection, fresh
testnet `SideChainState` + parity vectors) before any redeploy. Testnet
re-cut is free.
