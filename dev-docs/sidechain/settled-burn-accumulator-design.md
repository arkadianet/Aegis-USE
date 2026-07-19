# Settled-burn accumulator — idempotent settlement, closing the double-pay vector (design)

> **Status: DESIGN FOR REVIEW — not implemented.** Discharges the HARDENING
> Tier-3 "settlement epoch-canonicality / double-pay" item's **replay vector**
> (`HARDENING.md:63–74`), red-review 2026-07-19, option (a). Folds into the
> SAME v6 cut as D1 recipient-binding + batch settlement
> (`batch-settlement-design.md` §8) — one chain-id-breaking cut, not three.
> **Scope honesty up front:** this closes double-pay-by-replay *fully* and
> settlement-layer nullifier freshness as a bonus; it does **not** close the
> separate anchor-window honest-scope item (§7.3) — the bridge stays
> "trustless modulo fabricated-anchor spends" until epoch-validity.

## 0. The vulnerability being closed (recap, with code)

The settlement guest proves a burn commitment is a leaf of the epoch
`(prev_root, new_root]` (`settlement/methods/guest-settlement/src/main.rs:111–112`)
and that advancing the authenticated frontier over the supplied epoch leaves
takes `prev_root → new_root` (`:113–114`, `engine/src/merkle.rs:307–314`).
**Nothing proves `new_root` is the canonical hn chain's root** — epoch leaves
are settler-supplied (`main.rs:62`), and epoch canonicality is documented
honest scope (`main.rs:23–26`, `batch-settlement-design.md` §7).

Attack (red-review, logged `HARDENING.md:63–74` and
`batch-settlement-design.md:270–290`): a malicious permissionless settler

1. takes an **already-settled** burn's spend proof + public values (nothing
   on-chain or in-guest consumes a spend proof — the hn chain records the
   withdrawal once, but the proof bytes are reusable);
2. builds a **non-canonical epoch**: the leaf list is just `[cm0]` (or any
   list containing it) appended to the *current* authenticated frontier —
   the frontier chained in the vault's R4 accepts any leaves;
3. proves a second settlement: spend proof verifies (`main.rs:84–85`), burn
   binding holds (`:96–100`, `engine/src/burn.rs:37–40` — deterministic in
   `(value, nf0)`), the re-appended `cm0` is an epoch leaf (`:111–112`),
   journal committed (`:122–130`);
4. the PegVault (`bridge-tools/src/vault.rs:219–267`) reconstructs the same
   journal from the release tx — `prev_root` from `vault.R4`, `new_root`
   from the successor's R4, which the settler *sets* — and `verifyStark`
   passes byte-exact.

Result: the vault releases USE **twice for one burn**. D1 recipient-binding
forces payment to the original recipient, so it is not theft-to-attacker —
it is **peg inflation / vault drain**. Pre-existing in v5; independent of
batching.

## 1. The fix in one paragraph

The vault carries a second chained register, **R6 = the root of the
settled-burn nullifier set** — a sparse Merkle set over each settled
withdrawal's `nf0` (the spend's first nullifier, `pis[PUB_NF0..]`,
`engine/src/spend/monolith.rs:114`; already the withdrawal's consensus
identity, `aegis-node/src/hn/state.rs:109–116, 576–580`). Each settlement's
guest proves, for every withdrawal in the batch: `nf0 ∉ set(R6_in)`, then
inserts it, and commits `R6_out` in the journal. The contract binds `R6_in`
to the spent vault's R6 and `R6_out` to the successor's R6 exactly the way
it already binds `prev_root`/`new_root` to R4 — by *reconstructing* the
journal from the tx. Settlement becomes **idempotent per burn**: a burn can
be settled at most once, ever, regardless of epoch canonicality. The
non-canonical replay dies because a re-appended burn leaf carries the *same*
`nf0` (`burn.rs:29–40` derives the burn nonces from `nf0`; the nullifier is
deterministic per note), which is already in the set.

## 2. Decision A — accumulator structure

### Recommended: **fixed-depth-248 Poseidon2 sparse Merkle set (SMT), full-width key**

- **Key** = the 248-bit canonical bit-decomposition of `nf0` (8 BabyBear
  limbs, each < 2³¹ — `engine/src/poseidon.rs:41–61`; bit `k` = bit
  `k mod 31` of limb `k / 31`'s canonical `u32`, LSB-first — pin the order
  in code + test vector). **No truncation, no extra hashing** — no
  key-collision argument to audit at all (two distinct `nf0`s occupy two
  distinct SMT positions, unconditionally).
- **Leaves**: `EMPTY = [F::ZERO; 8]` (matches the note tree's
  nothing-up-my-sleeve empty leaf, `merkle.rs:45–46`), `OCCUPIED = [F::ONE;
  8]` (pinned marker; the key already *is* the nullifier, so storing `nf0`
  in the leaf is redundant — review item Q2).
- **Internal node** = the existing t=16 Poseidon2 2-to-1 `compress`
  (`poseidon.rs:114–119`) — the same permutation the note tree and frontier
  already use in-guest; nothing new in the trusted hash set.
- **Empty-set root**: `zeros_settled[248]` computed by the `zeros()`
  recurrence pattern (`merkle.rs:59–69`) — a pinned genesis constant.
- **Non-membership + insert in one witness**: 248 siblings; verify the path
  with leaf `EMPTY` reproduces the running root (proves absence), then
  recompute the *same path* with leaf `OCCUPIED` (the insert). **496
  compressions per `nf0`**, always — depth is fixed, so **guest cost is
  O(1) per settled burn for the life of the chain**. Insertion order does
  not affect the final root (distinct keys, deterministic structure) — the
  set root is a canonical function of the set contents.
- **Placement**: new module `engine/src/settled.rs` (reusing
  `compress`/`zeros` idioms from `merkle.rs`; the existing `NoteTree`/
  `Frontier` are append-only positional trees and are NOT reusable as-is
  for a keyed set — this is deliberately separate, small, oracle-tested
  code).

### Rejected alternatives

| option | guest cost / nf0 | why not |
|---|---|---|
| **(b) hash-chain of settled nf0, guest re-scans for absence** (the §6-H2 shape, `batch-settlement-design.md:373–379`) | O(total ever settled) — ~1 hash per historical entry, *per entry per settlement* | Unbounded growth over chain life; at 10⁵ settled burns a single insert costs more than the SMT forever will. Also makes proving-witness size O(history). Dead on arrival for a forever-set. |
| **(a2) indexed / sorted Merkle tree (Aztec-style: sorted linked-list leaves, non-membership = one "low leaf" range proof)** | ~3 × depth-32 paths ≈ 100–130 compressions (~4× cheaper than SMT-248) | Real, but buys a 4× saving on a term that is already ~5% of a spend-verify (§4) at the price of: low-leaf/next-pointer bookkeeping in guest + host, an insertion-order-dependent root, range-comparison logic over field limbs, and a materially larger audit surface. Keep as the escape hatch if measurement (Q5) says the SMT term hurts. |
| **(c) RSA / group accumulator** | small | New cryptographic assumption (groups of unknown order), out-of-field bignum arithmetic in a BabyBear/RISC0 guest, trusted or class-group setup. Violates the "proven primitives only" bar for zero benefit here. |
| **SMT with truncated key (e.g. depth 64/128 over `H(nf0)`)** | 128–256 compressions | Depth 64 is unsafe: a targeted second-preimage on a *known pending* withdrawal's key (nf0 is public in the hn chain once recorded, `state.rs:576–580`) is ~2⁶⁴ Poseidon evaluations and permanently **strands** the victim's withdrawal (its key can never be inserted). Depth ~124 (4 limbs) is safe (~2¹²⁴ targeted) and halves cost — but adds a truncation argument for a term that doesn't need shrinking. Note as the first optimization if ever needed (Q5). |

**Growth over chain life:** on-chain, R6 is 32 bytes forever. Host-side, the
SMT stores O(settled × 248) digests — at 10⁶ settled withdrawals that is
~8 GB *worst case* naïve, or ~250 MB with standard branch-sharing/pruned
storage; either way an operator-side artifact, rebuildable from the vault's
release history (every `nf0` is recoverable from the hn chain's withdrawal
records and from release-tx journals). No consensus-side growth at all.

## 3. Guest statement additions (v6 guest, extends the batch guest of `batch-settlement-design.md` §2)

### New inputs

```rust
// ---- additional private inputs (env::read order, after batch inputs) ----
settled_root_in: [u32; DIGEST_ELEMS],      // must reproduce vault.R6 (journal-bound)
settled_paths:   Vec<[[u32; DIGEST_ELEMS]; 248]>,  // one 248-sibling witness per entry,
                                                   // valid at its sequential insert point
```

`settled_root_in` enters exactly as `prev_root` does: it is not "checked
against" anything in-guest — it is **committed in the journal**, and the
contract reconstructs the journal with `vault.R6` in that slot, so a wrong
`R6_in` can never match the spendable vault (the same mechanism as
`main.rs:104–107`'s prev_root comment).

### New per-entry check (i = 1..=N, inserted after the burn-binding check §2.3)

```
root_0 = settled_root_in
for i in 1..=N:
    nf0_i = pis_i[PUB_NF0..]                       // monolith.rs:114
    assert smt_root(key=bits248(nf0_i), leaf=EMPTY,    siblings=paths[i]) == root_{i-1}
    root_i = smt_root(key=bits248(nf0_i), leaf=OCCUPIED, siblings=paths[i])
settled_root_out = root_N
```

Sequential chaining means later witnesses are generated against the
intermediate set states — the host inserts in entry order and emits each
witness at its insert point (§5). The guest needs no ordering rule for the
nullifiers themselves (final root is order-independent); entry order is
already canonicalized by the batch design (§4 determinism rule) and the
journal binds it.

### Journal layout (v6, supersedes `batch-settlement-design.md` §1 layout)

```
b"AEGISPB1"                                     8
prev_root                                      32
new_root                                       32
settled_root_in                                32   NEW — binds vault.R6
settled_root_out                               32   NEW — binds successor.R6
counter_next_be                                 8
entry[1..=N]  (amount_be(8) ‖ prop_len_be(8) ‖ recipient_prop)   unchanged
```

All new fields are fixed-width and precede the variable-length entry list —
the injectivity argument of §1 (Option L) is unchanged. Mirror change in the
native reference `journal_bytes` (`vault.rs:310–326`).

### Cost

One insert = 496 compressions. Calibrating from the measured transition term
(~1.1 M cycles per block ≈ 32–64 compressions per block ⇒ **~20–35 K
cycles/compress** in the RISC0 guest — Q5 pins this by measurement):

| term | cycles | vs baseline |
|---|---|---|
| per-entry SMT non-membership + insert | ~10–17 M | **~3–6 %** of the ~0.3 B post-T1.2 spend_verify |
| N=16 batch total SMT term | ~160–270 M | ~3–5 % of the ~5.3 B batch total (16 × 0.3 B + 0.5 B transition) |
| witness input bytes | 248 × 32 B ≈ 7.9 KB/entry (~127 KB at N=16) | private input only — nothing on-chain |

The term is flat in set size forever (fixed depth). If measurement says it
matters, the depth-124 keyed variant halves it and the indexed tree quarters
it (§2) — both deliberately deferred.

## 4. Decision B — the contract-side check (minimal, and why it is sufficient)

**The only PegVault change is in the journal reconstruction plus one deploy
register.** No new predicate conjuncts.

`journal_expr` (`vault.rs:202–215`) gains two reads, exactly parallel to the
existing `r4_bytes` helper (`vault.rs:146–155`):

```
journal = TAG_PB1 ++ vault.R4 ++ nv.R4
       ++ vault.R6[Coll[Byte]].get          // settled_root_in   — NEW
       ++ nv.R6[Coll[Byte]].get             // settled_root_out  — NEW
       ++ longToByteArray(vault.R5 + n)
       ++ entries
```

That is one new `r6_bytes(bx)` combinator (`ExtractRegisterAs reg_id 6` +
`OptionGet` — the `r4_bytes` pattern verbatim) and two `Append` nodes:
**~30–40 bytes of tree**, on top of the batch predicate's ~800–1000 B, far
under the 4096-B `MaxPropositionBytes` budget (`vault.rs:39`). R6 is
currently unused anywhere in the vault, txbuild, settlement, or hn state
(verified by search — only R4/R5 are read: `vault.rs:146–166`,
`txbuild.rs:269`).

**Why "journal binding only" is sufficient (the R4 argument, verbatim):**

- *Soundness lives in the guest.* The RISC0 claim binds the journal digest;
  `verifyStark` compares the reconstructed journal **byte-exact** against
  the receipt's committed journal
  (`ergo/ergo-sigma/src/evaluator/opcodes/sigma.rs:382`); the image id
  pinned in the tree (`vault.rs:64–65`) pins *which program* produced it.
  So a passing release **is** a guest execution that proved
  `settled_root_out = insert(settled_root_in, {nf_1..nf_N})` with every
  `nf_i` proven absent from `settled_root_in`.
- *The contract only chains the state.* `settled_root_in` in the journal is
  built from `vault.R6` — the register of the box actually being spent,
  which must carry the singleton NFT (`vault.rs:15, 30–34`), so it is the
  authentic current set. `settled_root_out` is built from the successor's
  R6, and the successor is forced to be a same-script NFT-carrying vault —
  so the *next* settlement's `R6_in` is this settlement's proven `R6_out`.
  This is precisely how R4's `prev_root → new_root` chain already works
  (`vault.rs:26–31`); R6 rides the identical trust chain.
- *Malleability:* a wrong-length or absent `nv.R6` changes (or aborts, via
  `OptionGet`) the reconstruction → byte mismatch → `false`. The guest
  commits exactly 32 bytes at a fixed offset; there is no parse ambiguity.

No explicit `nv.R6 == <journal slice>` conjunct is needed for the same
reason none exists for `nv.R4` today: the journal is *built from* the
successor's register, and equality with the proof's journal is the check.

## 5. Host / tooling deltas (non-consensus, listed for completeness)

- `settle prove` (`settlement/host/src/main.rs:63–90, 455–510`): read the
  vault's R6 alongside `--prev-root`/`--counter-next`; maintain a persisted
  host-side SMT of all settled `nf0` (rebuildable from the hn chain's
  withdrawal records + on-chain release journals); pre-check every batch
  entry for membership (fail fast *before* a GPU run — a doomed proof is
  the expensive failure mode); generate the 248-sibling witness per entry
  at its sequential insert point; pass `settled_root_in` + paths to the
  guest.
- `build_release` (`bridge-tools/src/txbuild.rs:226–289`): successor
  candidate registers grow from `[coll_byte_reg(new_root),
  long_reg(counter+1)]` (`txbuild.rs:269`) to also set
  `R6 = coll_byte_reg(settled_root_out)` from the prove output.
- `bridge-tools` deploy: mint/deploy sets `R6 = empty-set root` (§6).

## 6. Genesis / migration — one v6 cut (confirmed)

- R6 starts as the **pinned empty-set root** (`zeros_settled[248]`,
  a compile-time constant with an oracle test), set at vault deploy.
- Chain-id-breaking pieces — new journal tag `AEGISPB1` + new layout, new
  guest → **new image id v6**, new vault tree → new P2S address + fresh NFT
  — are the *same* artifacts the batch cut already replaces
  (`batch-settlement-design.md` §8 steps 1–2). D1's burn-derivation change
  re-cuts the hn testnet anyway (§8 step 5). **All three (D1 + batching +
  settled-set) fold into one cut.** Confirmed: nothing here forces a
  second cut; the settled set adds zero hn-consensus changes (recording in
  `state.rs` is untouched — the set lives in the vault + guest only).
- No live migration concern: fresh testnet cut carries no pending
  withdrawals (same posture as batch §8 step 6).

## 7. Does this close it? — the rigorous argument

### 7.1 Claim: **at most one release per `nf0`, ever** (double-pay closed)

Invariants:

- **(I1) Singleton state.** The settled set root is readable only from the
  NFT-carrying vault box: the predicate anchors on `INPUTS(0)` and requires
  its `tokens(0)` to be the unique NFT (`vault.rs:14–15, 220–226`); deposit
  boxes at the vault address cannot stand in (`vault.rs:30–34`). The NFT is
  minted once at deploy.
- **(I2) Guest soundness.** A passing `verifyStark` under image id v6 is a
  faithful execution of the v6 guest (RISC0 STARK soundness + byte-exact
  journal check, sigma.rs:382 + image-id pinning, `vault.rs:64–65`), which
  proved: every `nf_i ∉ set(R6_in)` and `R6_out = set(R6_in) ∪ {nf_1..nf_N}`
  — under Poseidon2 collision resistance (a false non-membership requires a
  compress collision on the path; the same assumption the note tree's
  soundness already rests on, `merkle.rs:188–193`).
- **(I3) Contract chaining.** Every spend of the vault binds
  `R6_in = spent vault's R6` and forces the successor to carry the proven
  `R6_out` (§4).

Induction over the vault's release chain from genesis: `set(R6)` after
release *k* is exactly the set of all `nf0` released in releases 1..k
(base: pinned empty root; step: I2 + I3). Any release attempting an
already-released `nf0` needs a non-membership proof for a member —
unprovable by I2. **Every replay shape is the same `nf0`:**

- *Non-canonical epoch re-appending a settled burn leaf* (the red-review
  vector): the burn commitment is deterministic in `(value, nf0)`
  (`burn.rs:37–40`), so the re-appended leaf's settlement still presents
  `nf0` from the reused spend proof's public values → member → dead.
- *A different spend proof re-burning the same note* (even a fresh, valid
  proof on a non-canonical branch): the nullifier is deterministic per
  note+key, so `nf0` is identical → dead. (This is settlement-layer
  **nullifier freshness for peg-outs** — one of the three inherited
  honest-scope items of batch §7 — closed for free.)
- *Intra-batch duplicate:* the second sequential insert finds `OCCUPIED` →
  guest aborts (§8 reconciles this with batch §2.6).
- *Cross-reorg replay:* if hn reorgs and the same burn is re-recorded on the
  new branch after already being settled, the second settlement is dead —
  the set is deliberately *not* reorg-aware; "paid once" is final.

Races and forgeries:

- *Two settlements racing from the same `R6_in`:* the vault is a UTXO
  singleton — exactly one spend of the box confirms; the loser's proof is
  bound to a `prev_root`/`R6_in` pair no spendable box carries anymore.
  Same serialization R4 already provides (`batch-settlement-design.md`
  §4 primary anti-replay).
- *Forged `R6_in`:* impossible — it is read from `INPUTS(0)`'s register
  under I1, not from prover input. The guest's `settled_root_in` private
  input is only *bound*, via the journal, to that register (§3).
- *Successor omitting / garbling R6:* `OptionGet` aborts or bytes mismatch
  (§4). *Set deletion:* the guest computes insert-only; no journal with a
  shrunk set can be produced by the v6 image.
- *Old v5 receipts:* different journal shape and different image id — the
  v6 tree rejects them structurally.

### 7.2 Therefore

The HARDENING Tier-3 **double-pay / peg-inflation vector as scoped**
("re-append an already-settled burn + reuse its spend proof",
`HARDENING.md:63–74`) is **closed, fully**, with no residual path within
that vector. Not narrowed — closed.

### 7.3 Residuals, stated honestly (what this does NOT close)

1. **Fabricated-anchor mint (the anchor-window honest-scope item) — OPEN,
   and it shares the same root cause.** The guest never compares the spend's
   `PUB_ROOT` against anything (`monolith.rs:112, 359` bind it in-circuit;
   the guest ignores it — documented honest scope, `main.rs:23–26`, batch
   §7). A malicious settler who is already willing to build a non-canonical
   epoch does not need to replay a settled burn at all: they can build a
   **private tree of self-minted notes**, produce a *valid* spend proof
   against that fake anchor with a **fresh** nullifier, append its burn
   commitment in their non-canonical epoch, and mint a release from
   nothing (bounded only by the vault's balance). The settled set does not
   and cannot block this — the `nf0` is genuinely new.
   **Consequence for review:** HARDENING's phrasing that option (a)
   "closes it without full epoch-validity" is correct for the *replay*
   vector but must not be over-read: after this ships, the bridge is
   trustless against **replay** but still trusts settlers not to
   **fabricate** — the honest-settler assumption narrows, it does not
   vanish. Full closure needs epoch-validity (every epoch leaf arises from
   a consensus-valid hn tx), because even binding `PUB_ROOT` to the vault's
   root history would not help while malicious epochs can poison the note
   tree with fake commitments that later become anchorable. Recommend the
   HARDENING entry be split into "replay (closed by this design)" and
   "fabrication (open; epoch-validity)" so the residual stays visible.
2. **Incomplete-batch griefing / stranding (batch §0.1, §6, D5) —
   unchanged** by this design as specced. But see §8: the set is the
   missing ingredient for a *clean* fix, flagged as Q4.
3. **Deep-hn-reorg-after-release (O5) — unchanged**, with one improvement:
   the set now also prevents double-*pay* across reorg replays (§7.1); the
   remaining exposure is "vault paid for a burn the canonical chain later
   dropped", mitigated by `pegout_delay` as today.
4. **Assumptions:** Poseidon2 collision resistance (pre-existing),
   RISC0/STARK soundness at the configured ~113-bit conjectured level
   (pre-existing Tier-3 item), devnet `verifyStark` byte-exact journal
   semantics (sigma.rs:370–390).

## 8. Interaction with batching (reconciliation)

- **Batch insertion:** N sequential inserts into one set transition,
  `R6_in → R6_out`, one journal — §3. No per-withdrawal on-chain state.
- **Batch §2.6 (pairwise-distinct `nf0`) is now redundant as a soundness
  requirement** — an intra-batch duplicate fails the second insert's
  non-membership check (§7.1). Recommendation: **drop the O(N²) guest check;
  keep a host-side duplicate pre-check** (the useful failure mode is
  refusing to *start* a doomed GPU run, which an in-guest check never
  provides). Batch §7's "no duplicate within a batch" clause re-anchors on
  the set.
- **Register collision with batch §6-H2:** the H2 recovery sketch wanted
  `R6 = SHA-chain of journals`. The settled set takes R6; H2 — if ever
  built — moves to R7. But H2's *motivation* (recovering stranded
  withdrawals) is better served by the set itself, see Q4.
- **Journal/entry ordering rules** of batch §4 are unchanged; the set adds
  no ordering constraint (order-independent root, §2).

## 9. Test plan sketch (for the implementation PR)

- `engine/src/settled.rs` unit tier (same-file `mod tests`, section
  dividers per convention): empty-root constant oracle-pinned; insert →
  membership; non-membership witness verifies pre-insert and fails
  post-insert; order-independence (`insert(a,b) == insert(b,a)` root);
  key-bit decomposition test vector (pinned bytes); tampered-sibling and
  wrong-leaf error paths; oracle parity vs a naive full-map reference
  implementation across power-of-two boundary key patterns.
- Guest tier: duplicate-in-batch rejected via the set (with §2.6 removed);
  replay-across-settlements rejected (settle, then re-prove same burn on a
  synthetic non-canonical epoch — **the red-review attack as a regression
  test**, this is the headline test); fresh-burn accepted; journal
  byte-exactness vs extended `journal_bytes`.
- `vault_predicate.rs` (both tiers, incl. real-receipt oracle): R6 absent
  in successor → reject; R6 wrong bytes → reject; R6_in mismatching
  vault.R6 (tampered journal) → reject; happy path chains R6 across two
  consecutive releases.
- e2e devnet: settle a withdrawal, then run the replay attack end-to-end
  and watch the release tx fail script validation; plus the two-release
  R6-chaining flow.

## 10. Open questions / decisions for review

- **Q1 — accumulator confirm:** depth-248 full-key Poseidon2 SMT (§2) vs
  the indexed-tree escape hatch. Recommendation: SMT; revisit only on Q5
  numbers.
- **Q2 — OCCUPIED leaf value:** `[F::ONE; 8]` marker vs storing `nf0`
  itself. Marker is smaller/simpler and sufficient (key = position = nf0);
  confirm no future use case wants the value materialized in-tree.
- **Q3 — journal field order:** settled roots placed after `new_root`,
  before `counter_next` (§3). Any preference for grouping with counter?
  Cosmetic; pin one.
- **Q4 — seize the bigger simplification now or later?** With the set,
  release no longer *needs* the "burn ∈ this epoch's leaves" watermark rule
  at all: a supplemental (or replacement) statement "burn cm has a valid
  depth-32 membership path to the current R4 root **and** nf0 ∉ set" is
  idempotent, kills the batch-§0.1 stranding problem *and* the D5 griefing
  residual, and retires the completeness policy. It is a larger guest
  redesign (host must serve full-tree paths, `merkle.rs:148–157`) and does
  not change the §7.3 fabrication residual. Recommendation: **not in this
  cut** — ship the minimal set first; log Q4 as the successor to D5/H2.
- **Q5 — measure before pinning:** per-compress guest cycles (§3's 20–35 K
  band) and the N=16 end-to-end batch cost with the SMT term, on the
  devnet, before the cut — same gate as batch D2's `MAX_BATCH`
  measurement; fold into the same session.
- **Q6 — domain/constant hygiene:** new pinned constants (`zeros_settled`
  table, OCCUPIED marker, key-bit order) join the poseidon domain review
  list (`poseidon.rs:25`, external-review brief) as flagged review items.
- **Q7 — HARDENING split:** rewrite the Tier-3 entry into closed-replay /
  open-fabrication halves per §7.3 when this lands, so the residual
  honest-settler trust stays on the mainnet-blocking list.
