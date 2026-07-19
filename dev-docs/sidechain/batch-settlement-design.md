# Batch settlement — N withdrawals, one proof, one release tx (design)

> **Status: DESIGN FOR REVIEW — not implemented.** Extends the live v5
> single-withdrawal settlement (`stark-settlement-design.md`, image id v5
> `b8f0b3f9…`, commit `5cb7441`). Chain-id-breaking (new journal tag, new
> image id, new vault predicate) → folds into a fresh cut (§8).

## 0. What exists today (the baseline being extended)

One settlement proof settles exactly ONE withdrawal:

- **Guest** (`settlement/methods/guest-settlement/src/main.rs`): verifies ONE
  in-field spend proof against the baked vk (:74–87), checks its `out0` is the
  deterministic burn note for `amount + fee` keyed by the spend's first
  nullifier (:89–100, `engine/src/burn.rs:37`), requires the burn commitment
  to be an epoch leaf (:111–112), advances the committed pre-epoch frontier
  over the epoch (:108–114), and commits the journal
  `b"AEGISPO3" ‖ prev_root ‖ new_root ‖ amount_be(8) ‖ counter_next_be(8) ‖
  recipient_prop` (:123–130).
- **PegVault** (`bridge-tools/src/vault.rs:199–267`): hand-assembled ErgoTree
  that RECONSTRUCTS that exact journal from the spending tx — prev root from
  `vault.R4`, new root from `OUTPUTS(0).R4`, amount from
  `OUTPUTS(1).tokens(0)._2`, counter from `vault.R5 + 1`, recipient from
  `OUTPUTS(1).propositionBytes` — and calls `verifyStark` (0xB9) on it.
  Structure pinned: `OUTPUTS.size == 3` (successor, recipient, fee),
  fee output token-free (:238–241).
- **Release tx** (`bridge-tools/src/txbuild.rs:226–289`): vault box +
  chunked ~218 KiB succinct receipt in context-extension var 0
  (`vault.rs:295–306`, 60 KB chunks under Scala's u16 `Coll` length cap).
- **hn recording** (`aegis-node/src/hn/state.rs`): a peg-out is a full spend
  whose `out0` is the bound burn note (:407–432); consensus records
  `Withdrawal { nf0, amount, recipient_prop, hn_height }` append-only
  (:107–116, :574–580); "the VAULT's R5/R4 decides which are settled"
  (:240–242). Settleable after `pegout_delay` (10 blocks,
  `hn/params.rs:80,120`).
- **verifyStark semantics** (devnet node,
  `ergo/ergo-sigma/src/evaluator/opcodes/sigma.rs:244–362, 370–390`): the
  `publicInputs` argument IS the RISC0 journal, compared **byte-exact**
  (`Journal::new(public_inputs.to_vec())`) against the receipt's committed
  journal digest. AOT cost from `costParams [queries=35, merkle_depth=16]`.

### 0.1 A correctness defect batching fixes (not just amortization)

The single-withdrawal flow **cannot settle two withdrawals recorded in the
same hn block** — and more generally strands any withdrawal skipped by an
earlier settlement:

- The guest requires the burn commitment to be a leaf of the epoch
  `(prev_height, sealed_tip]` (guest :111–112).
- The host requires `w.hn_height > prev_height` and
  `sealed_tip >= w.hn_height` (`settlement/host/src/main.rs:469–472,
  494–497`), and epochs are whole blocks (`split_leaves`, :137–166).
- So after settling withdrawal A at block `h`, any withdrawal B also at block
  `h` (or below `sealed_tip`) has `hn_height <= prev_height` forever:
  **no epoch window can ever contain its burn leaf again. B is permanently
  unreleasable.** `block.pegouts` is a `Vec` — multiple peg-outs per block are
  consensus-legal today (`hn/state.rs:138, 407`).

Batch settlement therefore adopts the rule: **a settlement settles ALL
recorded withdrawals in its sealed window** (§6). Batching is the fix, not an
optimization bolted on.

## 1. Batch commitment / journal binding (the crux)

### Decision: the journal carries the withdrawal list **verbatim** (Option L)

There is **no hash to reconcile**. The current design's strength is that the
journal is compared *byte-exact* by `verifyStark` (sigma.rs:382) and the
contract *builds* the only acceptable journal from the tx. That mechanism
generalizes directly: the batch journal contains the ordered entry list
itself, and the contract folds the tx's recipient outputs into the same
bytes. Binding is byte-equality of an injectively-encoded list — the simplest
possible security argument, zero new primitives on either side.

**Journal layout (exact bytes, guest-committed and contract-reconstructed):**

```
b"AEGISPB1"                                     8   batch tag (v6 cut)
prev_root                                      32
new_root                                       32
counter_next_be                                 8   = R5_in + N  (u64 BE)
entry[1..=N], in output order 1..N:
    amount_be                                   8   (u64 BE, USE base units)
    prop_len_be                                 8   (u64 BE = len(recipient_prop))
    recipient_prop                        variable  (ErgoTree bytes, 1..=4096)
```

- **Injectivity:** all non-list fields are fixed-width; each entry is
  `fixed(16) ‖ length-prefixed bytes`. A byte string parses as exactly one
  `(prev_root, new_root, counter_next, [(amount_i, prop_i)])` — no
  concatenation ambiguity between a long `prop_i` and the next entry's
  `amount`. (`prop_len` is 8 bytes because ErgoScript's only int→bytes
  primitive in the hand-assembled tree is `longToByteArray` 0x7A;
  `prop.size` upcasts via 0x7E.)
- **N is bound twice:** implicitly by byte-exact equality of the entry list,
  and explicitly by `counter_next = R5 + N` (the contract computes `N =
  OUTPUTS.size − 2` from the tx). No separate `count` field needed.
- **No `total_withdrawn` field:** unnecessary. Each output's amount is bound
  individually (it *enters the journal from* `tokens(0)._2`), and Ergo token
  conservation routes the remainder to the successor — the current predicate
  already relies on exactly this (it never checks the successor's USE
  balance; with all other outputs pinned, conservation pins it). Same
  argument holds for N outputs.

### Rejected alternative (Option H): `withdrawals_root = H(list)` in the journal

Journal carries `SHA256(entry list) ‖ total ‖ count`; contract rebuilds the
list bytes from outputs and hashes them. If hashing were needed, **SHA-256 is
the only sane pick** — the guest gets it ~free (RISC0 SHA accelerator, the
same lever as the T2.1 MMCS swap, commit `ef987b6`), and the devnet contract
side has `CalcSha256` — whereas blake2b would be software-slow in the guest.
But Option H is strictly worse here: the contract must *still* fold over all
N outputs to rebuild the list before hashing (no on-chain work saved), and it
adds a hash-collision assumption to the binding argument. Journal size is not
a real constraint that would motivate it: at `MAX_BATCH = 16` with ~100-byte
recipients the journal is < 2.5 KiB — noise next to the ~218 KiB proof, and
`verifyStark` charges journal bytes via its existing byte-ingestion cost
(sigma.rs:348). **Adopt Option L; keep H in reserve only if some future
constraint caps journal size.**

## 2. Batched Statement-1 guest

### Inputs

```rust
// ---- private inputs (env::read order) ----
entries:        Vec<BatchEntry>,       // N >= 1, in journal/output order
frontier_bytes: Vec<u8>,               // committed PRE-EPOCH frontier (unchanged)
epoch_leaves:   Vec<[u32; DIGEST_ELEMS]>,  // unchanged
counter_next:   u64,                   // = R5_in + N

struct BatchEntry {
    proof_bytes:    Vec<u8>,           // one 2-in/2-out hiding spend proof
    public_values:  Vec<u32>,          // its N_PUB public values
    amount:         u64,
    recipient_prop: Vec<u8>,
}
```

### Per-entry checks (i = 1..=N) — each is today's single-withdrawal check

1. `pis_i.len() == N_PUB`; `verify_with_preprocessed(&air, proof_i, pis_i,
   baked_vk)` — the same baked-vk in-field verify as guest :74–87. **This is
   the term that scales: ~N × spend_verify.** The vk setup stays baked
   (constant, once).
2. `fee_i = (amount_i / 100).max(1)` (must stay the mirror of
   `HnChainParams::peg_fee`, `hn/params.rs:126–128`);
   `burn_value_i = amount_i.checked_add(fee_i)`.
3. `burn_cm_expected(burn_value_i, nf0_i) == cm0_i` where
   `nf0_i = pis_i[PUB_NF0..]`, `cm0_i = pis_i[PUB_CMO0..]`
   (`engine/src/burn.rs:37–40`; offsets `engine/src/spend/monolith.rs:112–124`).
4. `cm0_i` is an epoch leaf (as guest :111–112; N linear scans of the epoch
   vec is fine at N ≤ 16 — or one pass with a sorted index if it ever matters).

### Batch-level checks

5. `N >= 1`.
6. **All `nf0_i` pairwise distinct.** This is the in-circuit
   no-duplicate-release rule: distinct nullifiers ⇒ distinct burn notes
   (burn nonces are `H(domain, nf0)`, `burn.rs:29–34`, collision-resistant)
   ⇒ each journal entry consumes a *different* burn. Without it, one real
   burn could back two identical entries paying twice. O(N²) limb compare.
7. One `settle_tree_transition(frontier, epoch)` → `(prev_root,
   new_frontier)`; `new_root = new_frontier.root()` — **once per batch**,
   unchanged from guest :102–114.
8. Commit the §1 journal.

### What scales, what doesn't

| term | today (v5) | batched |
|---|---|---|
| vk setup (baked) | ~0 (constants) | ~0, ×1 |
| spend_verify | ~0.42 B cycles measured post-T2.1 (`ef987b6`), est. ~0.28–0.30 B post-T1.2 (`802529d`) | **× N** |
| burn binding + distinctness | ~0 | ~0 (×N + N²/2 compares) |
| tree_transition | ~1.1 M cycles/block (≈0.5 B at the measured 447-block epoch) | × 1 per batch |
| journal commit | ~0 | ~0 (few KiB SHA via accelerator) |

## 3. PegVault predicate (v6)

### ErgoScript-equivalent (hand-assembled, as today)

```scala
val vault = INPUTS(0)
val nv    = OUTPUTS(0)
val n     = OUTPUTS.size - 2                       // recipients 1 .. n
val recs  = OUTPUTS.slice(1, OUTPUTS.size - 1)

val entries = recs.fold(Coll[Byte](), { (acc: Coll[Byte], b: Box) =>
  acc ++ longToByteArray(b.tokens(0)._2)           // amount_be(8)
      ++ longToByteArray(b.propositionBytes.size.toLong)  // prop_len_be(8)
      ++ b.propositionBytes })

val journal = TAG_PB1 ++ vault.R4[Coll[Byte]].get ++ nv.R4[Coll[Byte]].get
           ++ longToByteArray(vault.R5[Long].get + n.toLong)
           ++ entries

sigmaProp(
  vault.tokens(0) == (NFT, 1L) && nv.tokens(0) == (NFT, 1L) &&
  nv.propositionBytes == vault.propositionBytes &&
  nv.R5[Long].get == vault.R5[Long].get + n.toLong &&
  n >= 1 && n <= MAX_BATCH &&
  recs.forall { (b: Box) => b.tokens.size == 1 && b.tokens(0)._1 == USE } &&
  OUTPUTS(OUTPUTS.size - 1).tokens.size == 0 &&    // fee box, token-free
  verifyStark(getVar[Coll[Coll[Byte]]](0).get, journal, IMAGE_ID_V6,
              3, Coll(35, 16))
)
```

Deltas vs `vault_body` (`vault.rs:219–267`): `OUTPUTS.size == 3` →
`3 <= OUTPUTS.size <= MAX_BATCH + 2`; the single `rec()` amount/recipient
reads become the fold; `R5 + 1` → `R5 + n`; recipient token check moves into
a `forall` (which also pins `tokens.size == 1` per recipient — today's single
recipient doesn't need it because `OUTPUTS.size==3` + conservation pins
everything; with N outputs, pinning each box to exactly the USE token keeps
any co-spent deposit-box tokens flowing to the successor only).

Note the successor's USE balance still needs **no explicit check**: every
non-successor output's tokens are fully pinned (recipients: exactly
`(USE, amount_i)` — amount read *into* the journal; fee box: token-free), so
conservation forces `successor_USE = vault_USE + co-spent-deposit_USE − Σ
amount_i`. Same mechanism as today (txbuild.rs:255–268 constructs it; the
predicate never reads it).

### Hand-assembly feasibility (this was checked, not assumed)

The devnet node's evaluator and `ergo-ser` support everything needed:
`Fold` 0xB0 (`ergo-ser/src/opcode/types.rs:343`; evaluated at
`ergo-sigma/src/evaluator/dispatch.rs:966`), `ForAll` 0xAF (types.rs:342),
`Slice` 0xB4 (:347), `FuncValue` 0xD9 / `ValUse` (:419, :75), `Upcast` 0x7E
(:294). Cost: the current tree deliberately has **zero binding-id
semantics** (`vault.rs:36–39`); the batch tree needs two single-argument
lambdas (fold op over `(acc, Box)` tuple + forall predicate). That is a real
step up in hand-assembly risk — mitigated by the existing two-tier test
pattern (`bridge-tools/tests/vault_predicate.rs`: predicate tampering matrix
+ real-receipt oracle tier), which must grow batch cases (§9).

Alternative if lambdas are deemed too risky: unroll to a fixed `MAX_BATCH`
with `ByIndex`+default per slot — no lambdas, but ~K× the AST and ugly
absent-slot encoding. **Recommend the fold**; the evaluator's Fold is
consensus-tested on the devnet and the oracle test tier catches binding-id
mistakes byte-exactly. (Decision point D6.)

Tree size: current body ~600 B of a 4096-B `MaxPropositionBytes` budget
(`vault.rs:39`); the fold/forall machinery adds an estimated ~200–400 B.
Comfortable.

### Ergo tx constraints (N outputs, big proof)

- The ~218 KiB receipt already rides the live devnet release tx in context
  var 0 (4 × 60 KB chunks, `vault.rs:295–306`). Batching does not grow it.
- Each extra recipient output adds ~(box header + tree + one token) ≈
  60–150 B; at N=16 that's ~2 KiB — noise.
- The binding constraint is **script execution cost**: the fold + forall are
  O(N) with per-`Append` costs, and `verifyStark`'s AOT + byte-ingestion cost
  dominates anyway. A batch that proves fine but overflows the tx cost budget
  at release time is *recoverable* (nothing settled) but wastes a GPU run —
  so `MAX_BATCH` is pinned in the contract AND enforced by the host before
  proving. **Propose `MAX_BATCH = 16`, to be confirmed by measuring an N=16
  release on the devnet before the cut** (decision D2).

## 4. Counter / anti-replay / reorg semantics

- **Primary anti-replay: the R4 root chain, exactly as today.** The journal
  binds `prev_root == vault.R4`; a successful release moves R4 to
  `new_root`. Re-broadcasting the same release fails (the vault box is
  spent); re-proving the same batch fails (`prev_root` no longer matches R4).
  `new_root != prev_root` always: every epoch block appends ≥ 1 leaf (the
  coinbase, host `leaves_of_block` :129), and Poseidon2 root collision
  resistance does the rest.
- **Cross-batch double-release is structural.** Settled windows chain:
  batch k proves the transition over `(watermark_k, sealed_k]` where the
  frontier's `leaf_count` (the watermark) is authenticated by `prev_root`
  (a forged frontier reproducing R4's root is a Poseidon2 collision — the
  engine's forge-membership guard covers this, `engine/src/merkle.rs`
  oracle tests). A burn leaf lies below exactly one watermark boundary, so it
  can be inside at most one settled window, ever. Within a window, §2 check 6
  (distinct `nf0`) prevents duplication. **No released-set accumulator is
  needed on-chain.**
- **R5: cumulative withdrawal count — `R5' = R5 + N`** (decision D4,
  recommended over a `+1` batch index). It costs the same one addition,
  makes `counter_next` double as the explicit N binding in the journal, and
  gives ops/explorers a monotone "withdrawals settled" figure. It remains
  belt-and-braces — soundness rests on R4.
- **hn reorg semantics (unchanged by batching):** withdrawals are settleable
  only after `pegout_delay` (10 hn blocks, params.rs:120); the host should
  additionally refuse `sealed_tip > hn_tip − pegout_delay` so the sealed
  epoch sits behind merge-mined finality. A deeper hn reorg after a release
  leaves the vault's R4 committing a root off the canonical hn chain —
  a **pre-existing** exposure of the R4-chaining design (the vault cannot
  "re-org"); recovery is operational (devnet redeploy). Flagged as O5, out
  of scope here.
- **Determinism:** the sealed epoch (`--sealed-tip`, host :83–89) pins the
  leaf set; the batch adds one rule: entries are ordered by
  `(hn_height, intra-block peg-out index)` — canonical, so two settlers
  proving the same window produce byte-identical journals.

## 5. Amortization — honest numbers

Measured baseline: v4 real settlement `~1.75 B` cycles (spend_verify
`1.182 B` + tree_transition `~0.5 B` over a 447-block epoch), real GPU
wall **63.5 min** at 2.013 B cycles, PO2 19, contended 3090 (≈ 32 Mcyc/min).
v5 (SHA-MMCS `ef987b6` + FRI rebalance `802529d` + baked vk `fb91bea`):
spend_verify measured 1.183 B → **424 M** (2.79×) pre-T1.2, est.
~**0.3 B** post-T1.2; tree_transition unchanged (in-field Poseidon2). With
PO2 21 programmatic (`43148a0`) + a free GPU, the prover-speed plan's
grounded estimate is ~1.3–1.6× wall on same cycles (≈ 45 Mcyc/min).

**Model:** `cycles(N, B) ≈ N × 0.30 B (spend_verify) + B × 1.1 M
(transition) + ~0.02 B (fixed)`.

**The honest accounting: prove-cycles do NOT amortize much.** Sequential
settlements partition the same block window, so Σ of their transition terms
≈ one batch transition; spend_verify is ×N either way. What actually
amortizes ×(N−1):

1. the RISC0 **succinct-wrap** (lift/join + compression to the ~218 KiB
   receipt) — per-proof constant, minutes each;
2. the **release tx + confirmation round-trip** — sequential settlements are
   *inherently serial*: prove k+1 needs the confirmed R4/R5 of release k
   (host takes `--prev-root/--counter-next` from the vault, :67–77);
3. the **on-chain footprint**: one ~220 KiB tx + one `verifyStark` execution
   instead of N of each (N=10: ~2.2 MB → ~220 KiB);
4. one GPU job spin-up / operator loop instead of N.

**Worked example — N = 10 withdrawals over a ~450-block unsettled window
(3090, PO2 21, free GPU):**

| | batched | 10 × sequential |
|---|---|---|
| prove cycles | ~3.5 B (10×0.3 + 0.5 + fixed) | ~3.7 B total (same terms + 10× fixed) |
| GPU jobs / succinct wraps | 1 | 10 |
| prove wall | ~75–85 min | Σ ≈ 90–110 min *but serialized with…* |
| release txs + confirmations | 1 | 10, each gating the next prove |
| end-to-end (prove→funds) | **~1.5 h** | **~4–6 h** (10 × (prove slice + wrap + release + confirm)) |
| on-chain bytes / verifyStark | ~220 KiB / 1 | ~2.2 MB / 10 |
| same-block withdrawals | settles them | **impossible** (§0.1) |

Marginal cost of one more withdrawal in a batch ≈ 0.3 B cycles ≈ **~7 min
GPU** vs a full separate settlement cycle (~20 min prove + wrap + release +
confirm). The win grows with N and is unbounded for same-block withdrawals,
which sequential settlement cannot do at all.

## 6. Completeness policy, and the griefing residual

Because a settlement's window permanently retires every leaf below its
watermark (§4), the settler MUST include **every** recorded withdrawal with
`watermark < hn_height <= sealed_tip` in the batch — the host derives this
set from the node's `withdrawals()` list (`hn/state.rs:273`) and refuses to
prove otherwise. Omission doesn't threaten funds-safety of others; it
permanently strands the omitted withdrawal (liveness harm).

**Residual (flagged, not solved here):** settlement is permissionless — a
*malicious* settler can race an incomplete batch to strand a targeted
withdrawal. The contract cannot check completeness (it would need hn block
structure on-chain). Two mitigations, decision D5:

- **Accept for now (recommended for this cut):** devnet/testnet posture; the
  honest-settler policy plus monitoring. Same trust class as today's
  documented honest-scope items (§7).
- **H2 (sketch, future): release-history recovery.** Add `R6 = running
  SHA-256 chain of batch journals` (`R6' = SHA256(R6 ‖ journal)`). A
  supplemental "recovery" statement can then release a stranded burn by
  proving: burn leaf ∈ tree at R4 (below the watermark) AND ∉ any entry of
  any prior batch — the prover feeds all prior batch journals, the guest
  re-hashes the chain to match R6 and scans for absence. O(total history)
  guest work, 32 bytes on-chain. Clean, but real machinery; defer unless the
  griefing vector matters before the epoch-validity follow-up.

## 7. Security argument (batch binding) + inherited honest scope

**No alter:** each output's `(amount, script)` enters the reconstructed
journal *from the tx itself*; `verifyStark` compares journals byte-exact
(sigma.rs:382); the RISC0 claim binds the journal digest. Changing any
output changes the reconstruction → `false`.
**No add / no drop:** the outputs between successor and fee ARE the entry
list — an extra, missing, or reordered recipient output changes the bytes.
`counter_next = R5 + (OUTPUTS.size − 2)` pins N a second time.
**No ambiguity:** §1 encoding is injective (fixed-width fields +
length-prefixed props).
**No duplicate within a batch:** pairwise-distinct `nf0` ⇒ distinct burns
(§2.6). **No replay across batches:** R4 root chaining + frontier
authentication (§4). **Vault preservation:** NFT/script/size guards carry
over verbatim; conservation routes all unpinned USE to the successor (§3).

**Inherited honest scope — unchanged by batching** (guest :23–26): the
spend's anchor-root window (`PUB_ROOT` is not checked against the frontier
chain in-guest), nullifier freshness, and epoch canonicality (nothing proves
`new_root` is the *canonical* hn chain's root) remain enforced by hn
consensus + the honest-settler assumption until the full epoch-validity
proof. Batching neither widens nor narrows these.

**H1 — a real gap worth fixing in this same cut (recommended, decision
D1):** the burn note binds `(amount + fee, nf0)` but **not the recipient**
(`burn.rs:29–40`); `recipient_prop` is a prover-supplied guest input
journaled verbatim (guest :64, :129). A malicious *permissionless* settler
can therefore prove a victim's real pending burn with `recipient_prop =
attacker` and be paid by the vault — today, single or batched. Fix: derive
the burn nonces from the recipient too, e.g.
`rho = H(DOMAIN_BURN_RHO, nf0 ‖ H_p(recipient_prop ‖ amount_be))` (`H_p` =
in-field Poseidon2 packing of the bytes), wallet + node validators + guest
all recompute it (validators already hold `recipient_prop` in `PegOutTx`,
`state.rs:98–105`). Costs a few permutations everywhere; **hn
consensus-breaking**, but this cut is already chain-id-breaking, so folding
it in is nearly free now and expensive later.

## 8. Migration (chain-id-breaking → fresh cut)

1. New journal tag `AEGISPB1`; guest reworked per §2 → **new image id (v6)**;
   pin via `settle image-id` + container reproduction (the `5cb7441`
   procedure).
2. New vault tree per §3 (`vault.rs`: `journal_expr` → fold form,
   `vault_body` size/forall changes, `MAX_BATCH`) → new P2S address; fresh
   vault NFT + deploy on the devnet (testnet chain-id-breaking = free).
3. `build_release` takes `&[(amount, recipient_tree)]` and emits
   `successor ‖ rec_1..rec_N ‖ fee` (txbuild.rs:226–289).
4. Host: `settle prove` drops `--withdrawal-index` for
   `--all-pending` (default; explicit `--sealed-tip` retained), enforces
   completeness (§6) + `sealed_tip <= tip − pegout_delay`, orders entries
   canonically (§4).
5. hn node: **no consensus change for the minimal design** (recording is
   untouched) — unless H1 is adopted (recommended), which changes the burn
   derivation in wallet + node + engine and forces the full hn testnet
   re-cut anyway planned for cuts.
6. Old pending withdrawals at cut time: none carry over (fresh testnet cut);
   for any future *live* migration this design is not sufficient (old-vault
   drain path would be needed) — out of scope for testnet.

## 9. Test plan sketch (for the implementation PR)

- Guest unit tier: N=1 parity with today's journal (modulo tag), N=3 happy
  path, duplicate-`nf0` rejected, one-bad-spend-proof rejects the whole
  batch, burn-not-in-epoch rejected, journal byte-exactness vs a Rust
  `journal_bytes_batch` reference.
- `vault_predicate.rs` extensions (both tiers, incl. real-receipt oracle):
  N=1 and N=3 accepted; add/drop/reorder/alter an output → rejected;
  `R5 + wrong-N` rejected; recipient with extra token rejected; fee box with
  token rejected; `MAX_BATCH+1` rejected; fold/lambda binding-id oracle
  parity (serialize → devnet node evaluator).
- e2e on the devnet: two withdrawals in ONE hn block settled by one release
  (the §0.1 case that is impossible today).

## 10. Decisions needed from the orchestrator

- **D1 (security, recommended YES):** fold H1 burn-recipient binding into
  this cut (§7) — it is what makes *permissionless* settlement
  non-thieving; without it batching inherits a real recipient-swap hole.
- **D2:** `MAX_BATCH` value — proposed 16 pending a devnet cost measurement
  of an N=16 release (§3).
- **D3:** confirm Option L (verbatim list journal) over Option H
  (SHA-256 root) (§1).
- **D4:** R5 semantics — cumulative count `+= N` (recommended) vs batch
  index `+= 1` (§4).
- **D5:** accept the incomplete-batch griefing residual for now vs build the
  R6/H2 recovery machinery in this cut (§6; recommend accept + defer).
- **D6:** fold/FuncValue in the hand-assembled tree (recommended) vs
  unrolled fixed-slot predicate (§3).
- **O5 (noted, out of scope):** deep-hn-reorg-after-release recovery story
  for the vault's R4 (pre-existing).
