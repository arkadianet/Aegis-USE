# Epoch-validity F1–F3 — closing the anti-fabrication gaps (design + security analysis)

> **Status: SECURITY DESIGN FOR OPERATOR REVIEW — not implemented.** Closes the
> three MAINNET-BLOCKING findings of the v6 red review
> (`v6-red-review-findings.md` F1/F2/F3) so the bridge *actually* prices
> fabrication at the SPV ceiling instead of relying on the honest-settler
> assumption. Written against branch `feat/v6-vkpin-e2e` (62d5ae5): the code
> cited is `engine/src/epoch/*` + `settlement/methods/guest-epoch/src/main.rs`
> + `bridge-tools/src/vault_epoch.rs` + `aegis-node/src/{daa.rs, hn/*}`.
> Companion: `epoch-validity-design.md` (the E0–E4 architecture this repairs),
> `merge-mining.md`, `settled-burn-accumulator-design.md`, `peg-spv-design.md`.
>
> The review deliverable is §5–§7: the fabrication-cost theorem, the full
> witness-surface hunt (seven residual findings F6a–F6g, three of which — F6a,
> F6b, F6c — are soundness-critical and F6a/F6b MUST ship with F2), and the
> honest merge-mining-floor analysis (the key result: E4 + aux-PoW raises the
> fabrication floor from Aegis-hashrate to **Ergo-hashrate**).

## 0. Ground truth: the measured baseline and the exact holes

The Stage-T epoch guest is real and measured: **417 M cycles** for an 11-block
epoch (root-verify 101.4 M; E1+E3 59.3 M ≈ 5.4 M/block; E2 share-verify
179.5 M ≈ 16.3 M/block; E4 anchor 0.53 M) — `epoch-validity-design.md` §4.1.
The vault chains R4 (state root), R6 (settled-burn set), R7 (sealed tip header
id) and reconstructs the `AEGISPV1` journal byte-exact
(`bridge-tools/src/vault_epoch.rs:26–52`). The holes, verified in code:

- **F1** — `engine/src/epoch/verify.rs:167` copies settler-supplied
  `w.seam_roots` into `recent_roots` with no authentication; the doc-comment's
  `anchor_seam` mechanism (verify.rs:64–68) does not exist anywhere in the
  tree (grep confirms: the only occurrences are the comment itself).
  `pot_before` / `shielded_before` (verify.rs:61–63) are likewise raw witness.
  A settler puts a private-tree root in `seam_roots`; every fake spend then
  passes `AnchorOutOfWindow` (verify.rs:210–212); conservation replay
  (verify.rs:301–318) starts from attacker-chosen `pot_before/shielded_before`
  so it constrains nothing. **Unbounded value injection.**
- **F2** — `engine/src/epoch/share.rs:147–159` checks the Autolykos hit
  against `get_target(sc_nbits)` where `sc_nbits` is **the block's own
  self-declared field**. The node enforces `sc_nbits == expected_nbits()`
  (`aegis-node/src/hn/state.rs:443`) but the bridge must not trust the node
  (design §3 — the hn network is trusted for liveness only). A fabricator
  sets `sc_nbits` = difficulty-1 in every fake block and "mines" the suffix
  on a laptop at mainnet. **Work-pricing defeated.**
- **F3** — `verify.rs:261–275` re-derives peg-in mint commitments from
  settler-declared `(box_id, dest_owner, amount)` with no proof any such Ergo
  deposit exists. E4 anchors only the hn tip id. **Unbacked mints** — and
  (new finding F6e, §4) there is not even an in-suffix `box_id` dedup, so one
  imaginary deposit can be minted in every block of the suffix.

One structural fact the fixes lean on everywhere: the hn **header id**
(`engine/src/epoch/header_id.rs:96–116`) is a Poseidon2 digest committing
`chain_id, height, prev_header_id, prev_root, state_root, pot_after,
sc_nbits, timestamp_ms, miner_owner, coinbase_amount, coinbase_cm,
coinbase_is_reward, body_commitment`. Everything F1/F2 need — past state
roots, the pot, the difficulty history, heights, timestamps — is **already
committed by the id chain the vault already pins (R7)**. The fixes are
therefore mostly "make the guest open those commitments" rather than new
cryptography.

---

## 1. F1 — authenticated seam: the header-preimage walk

### 1.1 Mechanism

Replace the free-form `seam_roots: Vec<Digest>` with an **authenticated seam
header chain**:

```
pub struct SeamHeader {            // header-only preimage, no body
    height: u64,
    prev_header_id: [u8; 32],
    prev_root: Digest,
    state_root: Digest,
    timestamp_ms: u64,
    sc_nbits: u32,
    miner_owner: Digest,
    coinbase_amount: u64,
    coinbase_cm: Digest,
    coinbase_is_reward: bool,
    pot_after: u64,
    shielded_after: u64,           // NEW header field — see §1.3
    body_cm: Digest,               // witness input, not recomputed
}
```

plus a header-only id function `header_id_from_fields(chain_id, &SeamHeader)`
that hashes exactly the same field sequence as `header_id`
(header_id.rs:100–115) but takes `body_cm` as an input instead of calling
`body_commitment(block)`. (The current `header_id` becomes
`header_id_from_fields(cid, fields, body_commitment(block))` — one function,
one encoding, no drift.)

The witness supplies `seam: Vec<SeamHeader>`, **newest first**, where
`seam[0]` is the preimage of the sealed tip `T_prev` itself. The guest checks:

1. `header_id_from_fields(cid, seam[0]) == tip_id_prev` (the vault's R7);
2. for each `i`: `seam[i].prev_header_id == header_id_from_fields(cid, seam[i+1])`
   — a hash-linked walk backwards;
3. the walk length is `SEAM_LEN = max(ROOT_WINDOW, DAA_WINDOW + 1) = 100`
   headers (`ROOT_WINDOW = 100`, `engine/src/epoch/types.rs:33`;
   `HN_DAA_WINDOW = 90`, `aegis-node/src/hn/params.rs:31`), **or** terminates
   at the pinned genesis header id (`GENESIS_HEADER_ID`, a new guest
   constant pinned at the cut — the early-chain base case);
4. heights decrease by exactly 1 along the walk (parity with the node's
   by-height chain structure).

Then, **derived — never supplied**:

- `recent_roots` = the seam headers' `state_root`s (oldest→newest) — the
  authenticated anchor window replacing verify.rs:167. Window semantics must
  mirror the node's `recent_roots: VecDeque` (`hn/state.rs:256, 405,
  665–668`): the last `ROOT_WINDOW` roots *including* the tip root. A
  node↔guest window parity test is a cut gate (same discipline as the
  header-id parity test, `hn/header.rs`).
- `pot_before = seam[0].pot_after`, `shielded_before = seam[0].shielded_after`
  — the witness fields `pot_before`/`shielded_before` are **deleted**.
- `height(T_prev) = seam[0].height` — consumed by F6a (§4.1) and F2.
- the `(timestamp_ms, sc_nbits)` pairs of the last 91 pre-suffix blocks —
  consumed by F2 (§2).
- additionally require `w.blocks[0].prev_root == seam[0].state_root` (today
  only `frontier.root()` binds it via vault R4; this welds the seam to the
  frontier explicitly and costs one equality).

### 1.2 Why this is sound (the induction, and why it is NOT circular)

The obvious worry: the seam headers are settler-supplied bytes — what stops a
fabricator supplying fake seam preimages? Answer: **R7 + Poseidon2 collision
resistance + induction over settlements.**

- Base case: at deploy, R7 is pinned to the hn cut's genesis header id
  (design §2.2), and the guest pins `GENESIS_HEADER_ID`.
- Inductive step: settlement *N* proved its suffix `B'_1..B'_m` satisfies the
  full statement (header-chain from the previous R7, E2 PoW at DAA-enforced
  difficulty per §2, economics replay) and the vault wrote
  `R7 := id(B'_m)`. Settlement *N+1*'s seam walk produces preimages whose ids
  hash-chain to that exact R7. Under Poseidon2 collision resistance each id
  has a unique preimage the prover can exhibit, so the seam headers **are**
  (field-for-field) the very blocks settlement *N* (and earlier settlements,
  if the walk crosses a settlement boundary — it may, and that's fine)
  already verified. Their `state_root`s, `pot_after`, `sc_nbits`,
  `timestamp_ms`, `height` therefore carry the full weight of the previous
  settlements' verification.

No step consults the thing being established (the current suffix's validity),
so there is no circularity: authenticity of the seam reduces to authenticity
of R7, which reduces to the previous settlement's proof, down to the pinned
genesis. The one honest caveat: this authenticates the **vault-canonical**
chain, not the network-canonical one — which is exactly the design's stated
model (§2 "vault-canonical PoW suffix"); a divergence is the priced attack of
§5, not a soundness hole.

`body_cm` being witness-supplied is safe: nothing in the seam consumes the
body; the header fields the seam serves (roots, pot, nbits, timestamps,
heights) are all directly hashed. A fabricated `body_cm` for a real header
simply fails check 1/2 (different id).

### 1.3 Binding `shielded_before`: add `shielded_after` to the header (recommended)

`pot_after` is already a header field; `shielded_total` is node state
(`hn/state.rs:555–559`) but **not** header-committed. Two options:

- **(a) RECOMMENDED — add `shielded_after` to the hn header** at the E0/E1
  cut (the cut is already chain-id-breaking for the header-id encoding,
  types.rs:8–12 "pre-cut lockstep"). Cost: 4 limbs in the id preimage
  (~nothing). Benefit: *any* authenticated header pins the full value state;
  light clients and future audits get it for free; the guest derivation in
  §1.1 stays uniform (everything comes from `seam[0]`).
- **(b) fallback — vault-register chaining**: append `pot_after(8B) ‖
  shielded_after(8B)` to the journal and chain them through a widened R7 (or
  a new register), the `r6_bytes` pattern verbatim. Works without touching
  the header, but couples the value state to the vault instead of the chain
  and adds journal/contract surface. Use only if the header change is vetoed.

With (a), conservation replay (verify.rs:301–318) finally has an
authenticated starting point: the injected-value bound of §5 becomes exact.
Node-side, `apply_block` must also *enforce* `block.shielded_after ==
recomputed` (it already recomputes `shielded_next`; today the value lives
only in state).

### 1.4 Where proven, and cost

| piece | where | mechanism |
|---|---|---|
| seam header ids chain to R7 | guest | Poseidon2 walk (§1.1 checks 1–2) |
| R7 is the previous sealed tip | vault | journal splice + register chaining (`vault_epoch.rs:47–52`) |
| seam fields = previously-verified blocks' fields | induction | §1.2 |
| anchor window / pot / shielded / heights / DAA history | guest | derived from seam, not witnessed |

Cost: header-only id ≈ input of ~63–67 limbs → ~9–10 Poseidon2 permutations
(t=16, rate 8) ≈ 200–350 K cycles/header at the measured in-guest 20–35 K
cycles/compression calibration (`settled-burn-accumulator-design.md` §3).
**100 headers ≈ 20–35 M cycles per settlement, constant** (not per-block).
≈ +5–8 % of the 417 M baseline. Near genesis the walk is shorter and cheaper.

---

## 2. F2 — in-guest LWMA, with authenticated fork-point difficulty

### 2.1 Mechanism

Port `aegis-node/src/daa.rs::next_nbits` (LWMA-1, window 90, solve clamp
`[1 ms, 6T]`, ×4/÷4 per-step clamp, `min_difficulty_nbits` below
`window + 1` history) into the engine as a pure guest-visible function —
it already is pure over `&[(u64, u32)]` and `num_bigint` cross-compiles to
the RISC0 target (E2 already links `num_bigint` in-guest via
`decode_compact_bits`, share.rs:161).

Guest algorithm, replacing the "trust `block.sc_nbits`" hole:

1. Initialize `daa_view` with the seam's 91 `(timestamp_ms, sc_nbits)` pairs,
   oldest first (from §1 — authenticated). If the walk hit genesis with
   fewer than 91 headers, the view is short.
2. For each suffix block `B_i` (in order):
   `expect = next_nbits(PINNED_DAA_PARAMS, &daa_view)`;
   require `B_i.sc_nbits == expect` (new `EpochError::NbitsMismatch`);
   then push `(B_i.timestamp_ms, B_i.sc_nbits)` and pop the front beyond
   `window + 1` — exactly the node's `daa_view` maintenance
   (`hn/state.rs:671–673`).
3. E2's `verify_share(&share, &hid, B_i.sc_nbits)` is unchanged — its target
   is now DAA-constrained instead of self-declared.

`PINNED_DAA_PARAMS` (`target_secs`, `window = 90`, `min_difficulty_nbits`)
are **image constants**, mirroring `DaaParams::for_network`
(`daa.rs:34–41`); per-network images already differ (chain-id, journal tag),
so this adds no new coupling. The bootstrap branch (`chain.len() < n + 1 →
min_difficulty_nbits`, daa.rs:64–66) is reproduced by the seam-length rule:
short view ⟺ suffix starts within the first 91 blocks of the chain — and
that equivalence is only sound because heights are authenticated (F6a, §4.1;
without it a fabricator *claims* height 5 and gets difficulty-1 at mainnet —
the bootstrap rule is the single cheapest difficulty-reset lever, which is
why F6a is part of F2, not a nice-to-have).

Sliding-window implementation note: `next_nbits` naively does 90 256-bit
divisions per call. Keep `target_sum` and the weighted solve sum incremental
(add newest / subtract oldest, reweight = subtract plain sum) → ~2 divisions
per block after the first call. This is an optimization, not a soundness
item; even the naive form fits the budget (§2.4).

### 2.2 The fork-point difficulty is authenticated, not declared — precisely

The task flags the crux: "the starting difficulty at the fork point must
itself be authenticated or the fabricator just resets it." §1.2's induction
is the answer, stated for nbits specifically:

- `B_1`'s expected nbits is a function of the seam's 91 `(ts, nbits)` pairs.
- Those pairs are fields of preimages of the R7-chained ids (CR argument).
- Each of those blocks had **its** nbits DAA-checked (this same rule) in the
  settlement that sealed it, and its PoW checked against that nbits (E2),
  back to the pinned genesis whose `min_difficulty_nbits` is the DAA floor.

So a fabricator forking at the sealed tip **inherits the honest chain's
prevailing difficulty exactly**, with no declared quantity anywhere in the
chain of custody. There is no circularity: settlement *N+1*'s DAA check
consumes only settlement ≤ *N* facts plus the pinned genesis.

### 2.3 Adversarial timestamp analysis (how fast can difficulty be walked down?)

In-guest we cannot check wall-clock ("the future-time rule is subjective").
A fabricator controls fake-suffix timestamps freely, subject to: solve-time
clamp `[1 ms, 6T]`, LWMA weighting, ×4/÷4 step clamp, and (F6f, §4) in-guest
non-decreasing timestamps. Quantified:

- Fastest ride-down: claim every solve took the max `6T`. One such interval
  at newest weight (90) moves the weighted mean by ≈ `+(6T−T)·90 / 4095T` ≈
  +11 % → target +11 % → difficulty ≈ −10 % **per fake block**, window
  inertia dominating (the ÷4 step clamp never binds on this path).
- Therefore during the first ~7 fake blocks difficulty stays ≥ 50 % of the
  fork-point difficulty `D`; an 11-block fake suffix (`pegout_delay + 1`,
  types.rs:30) costs ≥ ≈ `8.2 × D` of expected work even on the maximal
  ride-down (Σ 0.9^i, i=0..10), i.e. **the same order as mining 11 honest
  blocks**. Walking difficulty down to ε before mining the cheap suffix
  costs ≈ `D · Σ 0.9^i ≈ 10 D` — *more* than just mining the suffix at `D`.
  Conclusion: LWMA + the seam makes difficulty-reset strictly unprofitable;
  the fabrication price is `Θ(k·D)` with `k = pegout_delay + 1`.
- Residual (inherent to every SPV construction): a *patient* attacker who
  lets real time pass while privately mining can honestly claim long solve
  times; over ≥ 90 fake blocks (≥ several windows) they reach difficulty
  ≈ `D/6` steady-state (mean solve 6T ⇒ target ×6). Mining 90+ blocks at
  decaying difficulty costs ≈ `10 D` up front — the reset is never free, it
  is *prepaid*. Optional hardening (D-EV4 extended): require the suffix's
  Ergo-candidate heights (E2 witness, PoW-committed) to be non-decreasing
  and end within `K` of `height(H_anchor)` — this binds claimed hn time to
  Ergo's consensus-validated clock and caps the patient-attacker window at
  the anchor's age. Recommended at Stage-M parameterization; not required
  for the Θ(k·D) bound.

### 2.4 Where proven, and cost

| piece | where |
|---|---|
| `sc_nbits == LWMA expectation`, per suffix block | guest (new check) |
| DAA history authenticity | guest seam walk (§1) + induction |
| PoW clears that nbits | guest E2 `verify_share` (unchanged) |
| DAA params | pinned in the image |

Cost: initial window build ≈ 90 BigUint divisions (2^256/D) ≈ 1–5 M cycles;
incremental per block ≈ 0.05–0.2 M. **Total ≈ +2–7 M per settlement**
(≈ +1 % of baseline). Naive (no sliding window): ≈ +10–50 M — still fine at
Stage T; the sliding form matters for Stage-M IVC (per-block ≈ 0.1 M is
noise against E2's 16.3 M/block).

---

## 3. F3 — peg-in backing proven against the E4-anchored canonical Ergo chain

### 3.1 Mechanism (tx-Merkle inclusion + one-mint-ever accumulator)

For every `PegIn {box_id, dest_owner, amount}` in the suffix
(verify.rs:261–275), the witness adds a **deposit proof**:

```
DepositProof {
    tx_bytes:        Vec<u8>,          // full serialized Ergo transaction
    output_index:    u16,              // which output is the deposit box
    tx_merkle_proof: BatchMerkleProof, // txid ∈ H_dep.transactions_root
    dep_header_path: (position in the extended E4 ancestor walk, see below)
    used_path:       [Digest; 248],    // one-mint-ever SMT non-membership+insert
}
```

Guest checks, per deposit (all pure over presented bytes — the same posture
as E2):

1. **Canonical containment.** `H_dep` (the Ergo header whose block carries
   the deposit) lies on the E4 ancestor walk: extend
   `anchor.rs::verify_anchor_linkage`'s parent-linked chain from `ergo_ref`
   so it passes through both `H_anchor` **and** every `H_dep`, i.e. one
   shared walk, deposits identified by index into it. Canonicality is
   inherited from `ergo_ref = CONTEXT.headers(j).id` — the contract-spliced
   canonical view (anchor.rs:1–24). No PoW verification needed, same as E4.
2. **Confirmation depth.** `depth(H_dep under ergo_ref) ≥
   PEGIN_CONFIRMATIONS` (mirror of `HnChainParams::pegin_confirmations`,
   params.rs:86 — pinned in the image). This is the Ergo-reorg-safety
   parameter: a mint is only provable once the deposit is buried at least as
   deep as consensus requires.
3. **Tx inclusion.** `txid = blake2b256(tx_bytes)`; verify
   `tx_merkle_proof` binds `txid` to `H_dep.transactions_root`. Per the
   established oracle finding (tx tree = concatenated txids ++ witness-ids;
   the Scala `/proofFor` trap): the guest **recomputes and binds the leaf
   itself** — never accepts a supplied leaf digest — and pins the leaf
   position to the txid half of the tree.
4. **Deposit well-formedness.** Parse `tx_bytes` (ergo-ser), take
   `outputs[output_index]`; require: `ergoTree == PINNED_VAULT_TREE_BYTES`
   (image constant — the vault address is what makes a box a deposit,
   `pegin_watch.rs:1–10`), USE token id == pinned, token amount ==
   `pi.amount`, `R4` = 64-byte `sc_dest` whose owner half decodes to
   `pi.dest_owner` (the `digest_to_bytes` layout, pegin_watch.rs:6–8).
5. **Box id.** Recompute `box_id = blake2b256(serialized output ‖ txid ‖
   output_index)` (Ergo box-id rule, via ergo-ser) and require
   `== pi.box_id` — this is what welds the mint commitment
   `pegmint_cm_expected(dest_owner, minted, box_id)` (verify.rs:268) to the
   real deposit.
6. **One mint per deposit, ever.**
   a. **in-suffix dedup** (F6e): a `HashSet<[u8;32]>` over the suffix's
      `box_id`s — mirror of the node's `in_block.insert` + `used_pegins`
      (`hn/state.rs:513`), currently missing in the guest entirely;
   b. **cross-settlement**: insert `key = hash_domain(DOMAIN_PEGIN_USED,
      box_id limbs)` into the **R6 settled SMT** with non-membership-first
      semantics — the exact `settled::verify_insert` machinery
      (`engine/src/settled.rs`, 248-bit key, 496 compressions), sharing the
      register: burn-nf0 keys and pegin-box keys are domain-separated by the
      key derivation, so one accumulator serves both. (Alternative: a
      separate R8 SMT — cleaner audit story, +32 B register, +journal
      fields. Either is sound; sharing R6 is recommended for register
      economy, with the domain-separation constant pinned and documented.)

Note the predicate proved is deliberately **existence + uniqueness**, not
unspentness: deposits at the vault address are later consolidated by release
txs (`vault.rs:30–34` — every vault-address box is spendable only inside a
release), so "unspent at height h" is the wrong invariant; "minted at most
once, ever" (6b) is the right one and is exactly the node's `used_pegins`
rule lifted into the proof.

### 3.2 Why tx-Merkle inclusion, not an AVL/UTXO-set proof

The alternative — prove the box in the AVL-tree `stateRoot` of an anchored
header — was considered and rejected: (i) it proves the wrong predicate
(unspentness-at-height; see above); (ii) it drags the AVL verifier into the
guest (heavier, blake2b-dense, and a codebase with a known upstream panic
history) for no security gain; (iii) `transactions_root` inclusion is the
already-oracle-tested machinery (`ergo-ser/batch_merkle_proof`, reused by
E2/E4 in-guest today, `peg-spv-design.md` §0a). Depth ≥ `PEGIN_CONFIRMATIONS`
+ one-mint-ever gives strictly the guarantees the node's own peg-in consensus
gives (`pegin_watch.rs` + `state.rs:507–528`), now bridge-grade.

### 3.3 The old-deposit depth problem (flagged honestly)

The shared ancestor walk is linear: cost ≈ 20–25 K cycles/Ergo header (2–3
blake2b compressions at the measured ~7.6 K/compression). A deposit minted
promptly sits O(`pegin_confirmations` + settlement lag) below `ergo_ref` —
cheap. But nothing forces settlement promptness: a suffix settled a week
late on a 2-min-block anchor chain implies a ~5,000-header walk ≈ ~125 M
cycles. Mitigations, in preference order: (i) settle promptly (operational);
(ii) cap `DEPOSIT_MAX_DEPTH` in the image and let the (rare) deep case fall
back to waiting for the next settlement — **rejected**: it can wedge a mint
permanently; (iii) accept the linear cost at Stage T (devnet walks are
short) and move the walk to the Stage-M carrier where it amortizes; (iv) the
NiPoPoW-interlink skip-walk as a future optimization (Ergo headers commit
interlinks in the extension) — real complexity, only if (iii) measures badly.
**Recommendation: (i)+(iii), measure, revisit.** Open question Q-F3.

### 3.4 Where proven, and cost

| piece | where |
|---|---|
| deposit exists in a canonical-Ergo block | guest (tx-Merkle + shared ancestor walk) + vault (`ergo_ref` splice) + Ergo consensus (canonicality of `CONTEXT.headers`) |
| deposit buried ≥ `PEGIN_CONFIRMATIONS` | guest (walk depth) |
| deposit shape / token / destination | guest (parse + pinned vault tree bytes) |
| mint amount arithmetic | guest (existing verify.rs:261–275 replay) |
| one mint ever | guest SMT vs R6 + vault register chaining |

Cost per deposit: txid blake2b of tx bytes (~5–20 compressions) + tx-Merkle
path (~10–30 compressions) + box-id blake2b ≈ **0.3–0.6 M cycles**, plus the
**SMT insert ≈ 10–17 M cycles (dominant)**, plus the walk increment (shared,
§3.3). Devnet epochs with a handful of peg-ins: +10–40 M total. Busy epochs:
the SMT insert belongs in the same native Poseidon2 AIR as the E3
generalization (design §2.1-E3 — the recursion tree already registers a
Poseidon2 table); the blake2b pieces join the E2 blake2b AIR at Stage M.

---

## 4. The residual-vector hunt — F6a–F6g, and the full witness surface

Adversarial pass over **every** input the settler controls
(`EpochWitness`/`EpochWitnessWire`, wire.rs:168–182; `ShareWitness`,
share.rs:50–54; `AnchorWitness`, anchor.rs:39–46; `root_bytes`,
guest main.rs:37). Seven residual findings F1–F3 do not cover (F6a–F6g);
three are soundness-critical (F6a, F6b — companions to F2, MUST ship with it;
F6c — required for the tight value bound of §5). F6e/F6f are folded into the
F3/F2 fixes above and restated here for the surface audit; F6d/F6g are
node-parity hardening.

### 4.1 F6a — suffix heights are UNCONSTRAINED (critical; F2 is unsound without it)

`verify_epoch` never checks height continuity: `block.height` (settler-set)
feeds the pegout-maturity check (verify.rs:352–360, both `tip_height` and
`h` attacker-chosen), the coinbase `block_id` (verify.rs:321), and — fatally
once F2 lands — the DAA bootstrap rule (§2.1: claim `height < 91` ⇒
`min_difficulty_nbits` ⇒ mainnet fabrication at difficulty-1 again, F2
defeated end-to-end). The header id commits `height`
(header_id.rs:103) but a fabricator mines fake blocks with any heights they
like, so commitment ≠ constraint.

**Fix (ships WITH F2):** `blocks[0].height == seam[0].height + 1` (seam
authenticated, §1.1) and `blocks[i].height == blocks[i-1].height + 1`
(new `EpochError::HeightDiscontinuity`). With this, `tip_height`, maturity,
and the bootstrap branch are all anchored to the settled chain's real
height. Cost: k integer compares — free.

### 4.2 F6b — in-guest share amplification: one PoW solve → k fake blocks (critical; divides the F2 price by k)

The node kills amplification with rule 405 — extension **key uniqueness**
inside one candidate (`merge-mining.md` §2.5, §11.2, enforced at
`block.rs:642` node-side). The guest does not: `verify_share` checks *one*
batch-Merkle inclusion of *one* `AEGIS_MM_KEY` leaf (share.rs:117–131). A
fabricator builds **one** Ergo candidate whose extension tree contains k
leaves `0xAE00 → id(B_1) … id(B_k)` (the Merkle tree happily commits
duplicate keys — uniqueness is a Scala-consensus rule for *canonical*
blocks, and shares are self-built candidates, not canonical blocks), solves
its PoW **once**, and presents the same solved header with k different
inclusion proofs as k "distinct" shares. `verify_share` passes k times.
Fabrication cost drops from `k·D` to `D` — an 11× discount at
`pegout_delay = 10`.

**Fix (ships WITH F2):** enforce in-guest that all k shares' PoW messages
are pairwise distinct: `msg_i = blake2b256(bytes_without_pow(share_i))` is
already computed inside `verify_share` (share.rs:113–115) — surface it and
collect into a `HashSet`, reject duplicates (`EpochError::SharedPowMessage`).
Distinct `msg` ⟺ distinct solve (re-binding a hit to a different message
voids it — §2.5's own argument), so one-solve-per-block is restored without
porting the key-uniqueness rule (which would require the full extension
contents in-guest). Honest chains trivially satisfy it (the node builds one
candidate per hn block). Cost: k 32-byte set inserts — free.

*(Checked and not a hole: cross-settlement share replay — old shares commit
old ids which cannot chain from the current R7; share reuse within a
settlement for the same block is idempotent; a share witness for block
`B_i` cannot serve `B_j` since the committed id is recomputed per block,
guest main.rs:87–91.)*

### 4.3 F6c — cross-settlement replay of a non-burn nullifier (critical for the tight value bound)

Known in the design (E3, `epoch-validity-design.md` §2.1-E3) but **not
implemented**: the guest inserts only *burn* `nf0`s into R6
(verify.rs:373–384 iterates `pegout_records`, which are peg-out `nf0`s only).
Within a suffix, `seen_nf` (verify.rs:213–217) catches re-use of *both* `nf0`
and `nf1` of *every* spend, so intra-suffix double-spends die. But **across
settlements** only burn `nf0`s are remembered. So an attacker who genuinely
owns note X can:

1. in settlement *N*, spend X in a plain (non-burn) tx — its nullifier `nf(X)`
   is *not* inserted into R6;
2. in a later fabricated suffix (settlement *N+1*), spend X **again** as a
   peg-out burn — anchored to an authenticated root (X really existed, so F1
   is satisfied), `nf(X)` fresh to *this* suffix's `seen_nf`, and absent from
   R6 → E3 passes → the vault pays for a note already consumed.

This is a **double-spend of a real, backed note**, so it does not mint
unbacked value out of nothing — but it lets the attacker extract a note's
value *twice*, which breaks the §5 bound "V ≤ the attacker's real holdings
double-spent **once**". It must be closed for the value bound to be tight.

**Fix:** the design's E3-generalization — insert **every** nullifier of
**every** suffix spend (`nf0` and `nf1`, txs and peg-outs) into the R6 SMT,
non-membership-then-insert, not just burn `nf0`s. Change verify.rs:373–384 to
walk `all_spends` (both nullifiers) instead of `pegout_records`. Cost: 2 SMT
inserts per suffix spend (496 compressions each) — fine in-guest for ≤~16
spends/epoch, and the Stage-M native Poseidon2 AIR (design §2.1-E3) for busy
epochs. This is the same carrier decision the design already booked; F6c just
records that Stage-T ships the burn-`nf0`-only *subset*, which is **not
sound for real value** and must be upgraded to the full set before mainnet.

### 4.4 F6d — coinbase maturity is not enforced in-guest (minor; not a drain)

The node ages a coinbase note `coinbase_maturity = 120` blocks before it is
spendable (params.rs:68). The guest re-derives the coinbase leaf and appends
it (verify.rs:336) but never forbids a *later* suffix block from anchoring a
spend to a root containing an immature coinbase. Impact is bounded to
consensus-faithfulness, not value: the coinbase amount is
`min(pot_parent, base + per_tx·n)` replayed against the **authenticated**
pot (F1), so a prematurely-spent coinbase moves only the miner's own, real,
already-counted reward — it injects nothing. Classified minor; close for node
parity by carrying the block heights (F6a) and requiring
`spend_height ≥ mint_height + coinbase_maturity` if/when the guest tracks
per-leaf provenance (it does not today; deferred with a noted residual).

### 4.5 F6e — no in-suffix peg-in `box_id` dedup (folded into F3)

Restated for the surface audit: today the guest re-mints from
`(box_id, dest_owner, amount)` with **no** dedup at all (verify.rs:261–275),
so even without F3's backing proof a single imaginary `box_id` mints in
*every* block of the suffix. The node prevents this with
`in_block.insert(box_id)` + the `used_pegins` set (state.rs:513). F3 §3.1
step 6 closes both halves (in-suffix `HashSet` + cross-settlement R6/R8 SMT);
listed here so the audit shows it accounted for.

### 4.6 F6f — claimed suffix timestamps are unconstrained (folded into F2)

Restated: `block.timestamp_ms` feeds the LWMA (post-F2) and is settler-chosen.
The only in-guest defensible rule is **monotonic non-decreasing** timestamps
along the suffix and across the seam boundary
(`seam[0].timestamp_ms ≤ blocks[0].timestamp_ms ≤ …`); wall-clock/future-time
bounds are subjective and cannot be proven in a closed verifier. §2.3
quantifies what a fabricator buys with free timestamps under the LWMA clamps
(answer: a *prepaid*, never free, difficulty ride-down) and the optional
Ergo-height binding (D-EV4) that caps it. The monotonicity check is a new
`EpochError::TimestampRegressed`; cost is `k` compares.

### 4.7 F6g — peg-out well-formedness bounds not enforced in-guest (minor)

The node rejects `amount == 0`, empty `recipient_prop`, and
`recipient_prop.len() > 4096` (state.rs:482). The guest checks none of these.
Not a drain: the burn commitment binds `(recipient_prop, amount)` (D1,
verify.rs:235) and the vault contract folds the **actual** recipient output's
`propositionBytes` and token amount into the byte-exact journal
(`vault_epoch.rs:390–402`), so a malformed or redirected recipient fails
`verifyStark` reconstruction. Still worth the three compares for node parity
and to keep the guest's accepted-set ⊆ the node's; classified minor.

### 4.8 Full witness-surface sign-off

Every settler-controlled input to the guest, and what authenticates it
**after** F1–F3 + F6a–F6c ship:

| witness field (source) | authenticated by |
|---|---|
| `frontier_bytes` (wire.rs:171) | `frontier.root() == prev_root` == vault **R4** (journal-bound); both ends of the append chain pinned (`new_root == B_k.state_root`, header-committed → E2 work) |
| `blocks[*]` header fields (wire.rs:77–92) | header-id chain to **R7** (§1) + **E2** aux-PoW at **F2** DAA difficulty; heights continuous (**F6a**); timestamps monotone (**F6f**) |
| `blocks[*]` bodies (txs/pegouts/pegins/coinbase) | folded into each header id via `body_commitment` (header_id.rs:67–91) → bound by E2 work; spends additionally digest-bound to the recursion root (digest.rs) |
| `seam` (replaces `seam_roots`) | **F1** hash-walk to **R7**, induction to pinned genesis |
| `pot_before`/`shielded_before` | **deleted** — derived from authenticated `seam[0]` (**F1** §1.3) |
| `tip_id_prev` (wire.rs:172) | journal-bound to vault **R7** |
| `settled_root_in` (wire.rs:180) | journal-bound to vault **R6**; `settled_root_out` → successor R6; SMT transition self-authenticating |
| `settled_paths` (wire.rs:178) | validated by `settled::verify_insert` (non-membership then insert); wrong path ⇒ wrong root ⇒ journal mismatch |
| `spend_root_digest` (wire.rs:179) | **overwritten** in-guest by the verified recursion root (main.rs:55–58) — never trusted from the wire |
| `ergo_ref_id` (wire.rs:181) | contract-spliced from `CONTEXT.headers(j).id` (Ergo consensus canonical); **E4** links the suffix tip under it |
| `counter_next` (wire.rs:181) | contract-reconstructed `vault.R5 + n` (`vault_epoch.rs`); guest value must match byte-exact |
| `ShareWitness` (share.rs:50) | pure over presented Ergo bytes; id **recomputed** by the guest, PoW self-verifying; **F6b** forces one solve per block |
| `AnchorWitness` (anchor.rs:39) | header ids recomputed (blake2b); ref pinned to `ergo_ref_id`; **F5** depth (open param) |
| **peg-in `DepositProof`** (new, **F3**) | tx-Merkle to an ancestor of `ergo_ref`, depth ≥ `PEGIN_CONFIRMATIONS`, box-id recomputed, one-mint-ever SMT |
| `root_bytes` (main.rs:37) | the recursion root proof; `verify_root_bytes_sha` verifies it and its `AggParams` are pinned |

**Verdict of the hunt:** after F1–F3 + F6a–F6c, every witness field is either
(i) proof-bound (recursion root / share PoW / SMT), (ii) R4/R5/R6/R7-register
chained (induction backbone), or (iii) Ergo-anchored (`CONTEXT.headers`). No
unauthenticated quantity remains that a fabricator can move to inject or
double-count value. F6d/F6e-residual/F6g are node-parity items that do not
affect the value bound; F5 (E4 depth) and D-EV4 (Ergo-height timestamp bind)
are **parameters** that set *how expensive*, analyzed next.

---

## 5. The fabrication-cost theorem — is fabrication fully priced?

**Setup.** After F1–F3 + F6a–F6c, a release paying withdrawal-value `V` is
accepted only if it presents a suffix `S = B_1..B_k` with:

- (S1) `B_1` chains from the vault's sealed tip **R7** and each `B_{i+1}` from
  `B_i` (header-id chain, §1) — *no rewrite below the settled watermark, ever*
  (R4/R6/R7 induction);
- (S2) `k ≥ pegout_delay + 1 = 11` (in-guest maturity, verify.rs:352–360 with
  authenticated `tip_height`/`height`, F6a);
- (S3) every `B_i` carries a **distinct** Autolykos v2 solution (F6b) clearing
  the **DAA-expected** target (F2) whose fork-point difficulty `D` is the
  authenticated prevailing difficulty (§2.2);
- (S4) every burned note is a real spend (digest bind) anchored to an
  **authenticated** recent root of the vault-canonical chain (F1) — never a
  private tree;
- (S5) every nullifier is fresh vs the entire settled history (E3-generalized,
  F6c) and the suffix (`seen_nf`);
- (S6) every peg-in mint is backed by a real, ≥`PEGIN_CONFIRMATIONS`-buried
  Ergo deposit (F3), minted at most once ever;
- (S7) the suffix **tip** is committed in a canonical Ergo header buried
  ≥ `A_min` (E4 + F5).

**Where can value `V` come from?** Every leaf of the value tree is re-derived
(verify.rs:327–342) from exactly three sources, each now bounded:

1. **spend outputs** — conserve value (a spend's `cm0+cm1` re-hide its inputs
   minus fee); by S4 the inputs trace to authenticated roots, i.e. to value
   already in the authenticated shielded supply. *Injects nothing.*
2. **coinbase** — `min(pot_parent, base + per_tx·n)` ≈ a few base units/block,
   replayed against the **authenticated** pot (F1). To accumulate `V` this way
   needs ≈ `V / COINBASE_BASE` blocks of real PoW — for any meaningful `V`,
   astronomically more than `V`. *Priced far above `V`.*
3. **peg-in mint** — by S6 requires a real Ergo deposit of `V` locked on the
   canonical chain. *That is not fabrication; it is using the bridge (cost `V`
   of real value, redeemable).*

So the vault only ever pays out **real, backed** value. Unbacked minting is
**closed** (was the design's headline free attack, §0). What remains is a
**double-spend**: the attacker owns a real backed note of value `V`, and gets
it withdrawn on a **vault-canonical suffix that diverges from the
network-canonical chain**, keeping the note on the network side. By S1+S5 they
cannot settle two conflicting suffixes from one R7 (the nullifier lands in R6
on the first, and R7 advances), so the double-spend is: *present the vault a
real-work suffix the honest network does not have, win the settlement race.*

**Cost of one fabricated withdrawal of value `V`:**

```
Cost(V)  =  k · E[work per block at difficulty D]        (S2 + S3, k = 11)
          + 1 canonical Ergo block committing the fake tip (S7, E4)
          + winning the settlement race vs honest settlers
   with   V ≤ (attacker's real backed holdings, double-spent once)   (S4 + S5)
```

- The first term is **`Θ(k · D)`** of real Autolykos work — F2 + F6a + F6b
  make it un-discountable: the difficulty is inherited (not reset — §2.2), the
  ride-down is prepaid not free (§2.3), and each block needs its own solve
  (F6b). Lower bound `≈ 8–10 · D` even on the maximal LWMA ride-down.
- The second term is one **canonical Ergo block** — see §6; on mainnet this is
  the dominant, hashrate-scale, and *public* cost.
- `V` is **bounded by real holdings** and each holding double-spends **once**
  (S5/F6c). There is no path to `V` unbounded by the vault balance — the §0
  drain is gone.

**Is there a cheaper path?** The witness-surface sign-off (§4.8) rules out any
unauthenticated shortcut; the three value sources above are exhaustive
(verify.rs:327–342 appends exactly spends, peg-in mints, coinbase). The only
levers left to a fabricator — private-tree anchor (F1), difficulty reset
(F2/F6a), share amplification (F6b), replay (F6c/E3), unbacked peg-in (F3) —
are each closed. **Conclusion: fabrication is fully priced at the SPV ceiling
— real majority-scale work + a public Ergo-anchored act + a race — with no
cheaper path, and the payout is bounded by the attacker's own backed value.**
This is exactly the ceiling §0.2 of the parent design argues is the maximum a
closed verifier can reach.

---

## 6. Merge-mining raises the floor from Aegis-hashrate to Ergo-hashrate

This is the most important *positive* result, and it materially strengthens
the weakest residual (`epoch-validity-design.md` §6 residual 1: "early
opted-in hashrate is ~zero → early price is ~zero").

**The two terms have different hashrate scales.** Decompose Cost(V):

- **`k · D` (the suffix work).** `D` is the **Aegis** DAA difficulty, which
  tracks the hashrate that *opts into* aux-PoW (`merge-mining.md` §10.1). This
  is a share target — deliberately **easier** than an Ergo block target (the
  share-chain construction, `merge-mining.md` §2.1). Early adoption ⇒ `D`
  small ⇒ this term is **weak** (the honest #1 risk). Aux-PoW hashrate, not
  Ergo hashrate.
- **The E4 Ergo anchor (S7).** To satisfy E4 the fabricator must get **their
  fake tip id** committed into a **canonical Ergo header** (`H_anchor`, linked
  under `ergo_ref = CONTEXT.headers`). Critically: an honest Aegis-aware Ergo
  miner commits **their own node's** hn tip (`merge-mining.md` §4) — a
  *different* id from the attacker's fake tip. So the attacker **cannot
  free-ride** an honest Ergo block; they must **mine their own Ergo block**
  carrying their fake commitment and get it into the canonical Ergo chain.
  That costs **one full canonical Ergo block = Ergo-hashrate** — orders of
  magnitude above a young sidechain's own `D`.

**So E4 is not just "an extra check" — it re-bases the fabrication floor from
Aegis-hashrate to Ergo-hashrate.** For any sidechain younger/smaller than
Ergo (all of them, for a long time), the **Ergo-block term dominates** and is
the true security floor. This is the merge-mining dividend the task asks
about, and it is real:

- It **directly patches** the parent design's residual 1: even at *zero*
  opted-in Aegis hashrate, fabrication still costs a canonical Ergo block per
  attempt, because E4's commitment must ride real Ergo PoW.
- It is **public and watchable**: the fake hn tip appears *in a canonical Ergo
  block* before the release can confirm — watchtowers and the honest settler
  see the equivocating commitment on Ergo and can react (freeze/challenge)
  within the `pegout_delay` + anchor-window.

**Conditions for the Ergo-floor to actually hold (⇒ recommendations):**

1. **E4 must be mandatory and TIP-binding on mainnet.** It is today behind the
   `aux-pow` cargo feature and binds the tip (`anchored_hn_id =
   header_id(…, blocks.last())`, guest main.rs:98) — good, but the mainnet
   image **must** be built with the feature and E4 non-optional. A `require_e4`
   image constant, asserted unconditionally, is the gate.
2. **F5 must be closed: `A_min ≥ 1` (recommend several).** The red review's F5
   (`epoch-validity-design.md` §"F5", guest main.rs:99 ignores depth) means
   the fake tip need only appear in the last-10 window at depth 0. Depth 0
   still requires *one* Ergo block (the floor holds), but sets the floor at a
   *single, reorg-able* Ergo block. Setting `A_min` to a few Ergo blocks
   raises the cost to `A_min` buried Ergo blocks and defeats a private
   single-block Ergo equivocation that the attacker reorgs away after release.
   **F5 should ship with this work**, not be deferred — it is what converts
   "one Ergo block" into "`A_min` Ergo blocks of *settled* work".
3. **`ergo_ref` freshness** (`epoch-validity-design.md` Q-EV2): the last-10
   window must still contain `ergo_ref` at release-validation time; bind the
   oldest of the ten and re-prove if missed.

**Residual ceiling (honest):** an attacker with **Ergo majority hashrate** can
still mine the anchor and reorg — but that is **Ergo's own security budget**
(the same assumption PegMint already makes for `N_mint`, `peg-spv-design.md`
§1c), astronomically above a young Aegis chain's. That is the true, and
correct, floor: *fabrication costs an Ergo-scale reorg.* No closed verifier can
do better; merge-mining lets Aegis **inherit Ergo's** floor instead of living
on its own.

**One caveat to flag for review:** this argument assumes the attacker cannot
obtain a *natural* canonical Ergo block that commits a hn tip they can pass off
as their fake suffix's tip. Since the committed id is a Poseidon2 digest over
the full hn header incl. body (header_id.rs), and the honest tip's body differs
from the fake suffix's, the ids differ and the pass-off is infeasible under
Poseidon2 CR. Worth an explicit adversarial pass at implementation (does *any*
honestly-committed id ever coincide with a fabricator-reachable tip? — no, by
CR + `chain_id` binding, but assert it in the F5/E4 test suite).

---

## 7. Cost verdict and Stage-M implications

**Added cycles vs the measured 417 M baseline (11-block epoch, in-guest):**

| fix | carrier | cost / 11-block epoch | fraction of 417 M |
|---|---|---|---|
| F1 authenticated seam (≤100 header-only ids) | in-guest, **constant** | +20–35 M | +5–8 % |
| F2 in-guest LWMA (sliding window) | in-guest | +2–7 M | +1 % |
| F3 peg-in backing (few deposits: tx-Merkle + box-id + SMT) | in-guest | +10–40 M | +2–10 % |
| F6a heights / F6f timestamps / F6g bounds | in-guest | ~0 (integer compares) | noise |
| F6b share-msg dedup | in-guest | ~0 (k set inserts) | noise |
| F6c all-nullifier SMT (2 inserts/spend vs burns only) | in-guest (Stage-T) / **AIR (Stage-M)** | +10–17 M per extra spend | data-dependent |
| **F1+F2+F3 + F6 (light epoch, ~2 peg-ins, ~4 spends)** | in-guest | **≈ +80–140 M → ~0.5–0.56 B total** | +19–33 % |

**Stage-T (short devnet epochs): tractable in-guest.** The whole sound guest at
~0.5 B cycles for an 11-block epoch is ~2.6× the ~185 M-class settlement
baseline and well within a devnet execute/prove — the same envelope the parent
design already accepted for the 417 M unsound version. Nothing here forces a
new carrier at Stage-T; F1's seam is a *constant* ~30 M adder (not per-block),
which is the cheap surprise.

**Stage-M (production-length epochs): the fixes do not change the carrier
decision, they slot into the AIRs already planned.**

- E2 at 16.3 M/block remains the dominant term → **per-block IVC** stays the
  Stage-M carrier (design D-EV2), unchanged.
- F1 seam is **constant per settlement** (~30 M), amortized to noise over a
  240-block epoch — it does **not** grow with epoch length. Free win.
- F2 sliding-window LWMA is ~0.1 M/block — noise inside the IVC loop.
- F3's Ergo-ancestor walk is **linear in Ergo depth** (the honest §3.3
  old-deposit problem) — the one term that can grow; mitigation is operational
  promptness + moving the walk into the Stage-M carrier (Q-F3).
- F6c's all-nullifier SMT (2 inserts/spend) is **dead in-guest for busy
  epochs** and belongs in the **same native Poseidon2 AIR** the design already
  books for the E3 generalization (§2.1-E3) — no new circuit, just the carrier
  it was always going to need.

**Net:** the sound guest is **Stage-T-tractable today** and **Stage-M-feasible
with the carriers already chosen** — F1–F3 add one constant seam term, a
noise-level DAA term, a linear-in-depth peg-in walk (the one thing to measure),
and fold their SMT/blake2b costs into the E3-AIR / E2-blake2b-AIR endgames the
design had already scheduled. No new cryptographic primitive is introduced by
F1/F2/F3 themselves; the only genuinely new circuit remains the Stage-M
blake2b AIR (E2 endgame), unchanged by this work.

---

## 8. Decisions needed / open questions (this work)

- **D-F1 (recommended: yes).** Add `shielded_after` as an hn header field at
  the E0/E1 cut (§1.3 option a) rather than vault-register chaining it — the
  cut is already chain-id-breaking, and it makes *every* authenticated header
  pin the full value state. Node `apply_block` must then enforce it.
- **D-F2.** Confirm `PINNED_DAA_PARAMS` (`target_secs`, `window = 90`,
  `min_difficulty_nbits`) as image constants matching `DaaParams::for_network`
  exactly; add a node↔guest DAA-parity test as a cut gate (same discipline as
  the header-id parity test).
- **D-F3 (recommended: share R6, domain-separated).** Peg-in one-mint-ever set
  shares the R6 SMT with burn nullifiers via a pinned domain-separation
  constant, vs a separate R8 SMT (cleaner audit, +register/+journal). Decide at
  implementation; both sound.
- **D-F5 (recommended: close it WITH this work).** Set `A_min ≥ 1` (several)
  and make E4 mandatory + tip-binding on the mainnet image — this is what
  secures the §6 Ergo-hashrate floor; deferring it leaves the floor at a single
  reorg-able Ergo block.
- **F6c carrier (recommended: Stage-T in-guest subset is UNSOUND for value).**
  Ship the full all-nullifier set before mainnet; the burn-`nf0`-only form is a
  testnet-only approximation and must be labelled as such.
- **Q-F1.** Node↔guest **anchor-window** parity: the guest's derived
  `recent_roots` must match the node's `VecDeque` semantics (last `ROOT_WINDOW`
  incl. tip; eviction at `hn/state.rs:665–668`) exactly — needs its own parity
  test.
- **Q-F3 (measure).** The Ergo-ancestor-walk depth for realistically-timed
  settlements on the live devnet cadence — if deep walks are common, prioritize
  the NiPoPoW-interlink skip-walk (§3.3 option iv) at Stage-M.
- **Q-F6b.** Confirm no honest chain ever produces two suffix blocks whose
  `bytes_without_pow(share)` collide (they cannot — distinct hn ids ⇒ distinct
  extension_root ⇒ distinct msg; assert in the test suite alongside the
  amplification regression).
- **Regression headline (both suites).** The §0 fabrication attack, end to end:
  build a private tree, a difficulty-1 fake suffix, an amplified single-solve
  share set, a re-spent note, and an unbacked peg-in — and watch each die at its
  named check (F1 `AnchorOutOfWindow`, F2 `NbitsMismatch`, F6a
  `HeightDiscontinuity`, F6b `SharedPowMessage`, F6c `AlreadySettled`, F3
  deposit-inclusion). This is the acceptance test for "fabrication is priced."