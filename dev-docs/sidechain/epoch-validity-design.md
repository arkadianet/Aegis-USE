# Epoch-validity — proving `new_root` is the canonical merge-mined hn state (design)

> **Status: DESIGN FOR REVIEW — not implemented.** Discharges the HARDENING
> Tier-3 double-pay entry's **fabrication vector** (`HARDENING.md:63–74`, the
> half the settled-burn accumulator explicitly does NOT close —
> `settled-burn-accumulator-design.md` §7.3 item 1). This is the last
> conceptual gap: after it, the bridge's honest label changes from
> "trustless modulo epoch canonicality" to **"trustless at the SPV ceiling"**
> — a precise, priced, non-zero residual, stated in §6. Companion designs it
> composes with: `batch-settlement-design.md` (v6 batch guest + journal),
> `settled-burn-accumulator-design.md` (replay closure, R6),
> `recursion-feasibility.md` (the budget that makes this affordable),
> `merge-mining.md` (the aux-PoW construction it consumes).

## 0. The gap, precisely (recap with code)

The settlement guest proves: the peg-out spend proof verifies against the
baked vk, its `out0` is the bound burn note, the burn commitment is a leaf of
the settler-supplied epoch, and advancing the authenticated frontier over
those leaves takes `prev_root → new_root`
(`settlement/methods/guest-settlement/src/main.rs:54–131`). The epoch leaves
are **settler-supplied private input** (`main.rs:62`); nothing anywhere
proves they are the leaves the real hn chain appended
(documented honest scope, `main.rs:23–26`; host-side `split_leaves` verifies
the split against the node's own view, `settlement/host/src/main.rs:137–166`
— but the host is the untrusted settler).

So a malicious permissionless settler fabricates an epoch: append leaves of
their own invention — in particular, mint fake notes into a **private tree**
(a non-canonical branch only they know), produce a *valid* spend proof
against that fake anchor with a **fresh** nullifier (the settled-burn
accumulator cannot catch it — the `nf0` is genuinely new,
`settled-burn-accumulator-design.md` §7.3), burn one, settle. The PegVault
reconstructs the journal from the tx — `new_root` comes from the successor's
R4, **which the settler sets** (`bridge-tools/src/vault.rs:10–31`) — and
`verifyStark` passes. The vault pays for a burn that never happened on the
real chain: **peg inflation, bounded only by the vault balance.**

Two facts frame the fix:

1. **The R4 chain already prevents history rewrite.** Every settlement must
   take the vault's current R4 as `prev_root` (`vault.rs:26–31`), so a
   fabricated epoch cannot rewrite anything below the settled watermark — it
   can only append a **fake suffix** on top of the last settled state. The
   whole problem is: *nothing prices the suffix.* Today a fake suffix is
   free.
2. **"Canonical" has a hard ceiling for a closed verifier.** No proof
   checkable by a contract (or a zkVM guest) can establish that a presented
   chain is THE canonical chain, because canonicality is a statement about
   the *absence* of a heavier competing branch — unknowable without
   observing the network. Every PoW bridge ever built (SPV, NiPoPoW,
   zk-light-clients) tops out at: *the presented chain carries real,
   consensus-valid work, and reversing the anchored prefix costs a real
   reorg.* Epoch-validity can reach exactly that ceiling and no higher.
   The design below is honest about this: fabrication goes from **free** to
   **priced in aux-PoW work + canonical-Ergo inclusion** — closed as an
   economics-free attack, narrowed (not closed) as a majority-hashrate
   attack. §6 quantifies the residual.

## 1. Ground truth today: what the merge-mining anchor actually is (code)

This matters because epoch-validity **consumes** the aux-PoW binding as its
raw material, and on the hn chain that binding **does not exist yet**:

- **hn chain (the chain the bridge settles):** `AuxAnchor` is a
  `(devnet_header_id, devnet_height)` pair fetched from the devnet's
  `GET /info` (`aegis-node/src/hn/auxpow.rs:18–41` — "API consumer only").
  Consensus enforces only **monotone height + shape**
  (`hn/state.rs:384–386`); the module doc says it outright: *"the anchor is
  a devnet-paced liveness scaffold, not yet PoW-binding"*
  (`hn/state.rs:47–55`). The binding direction is also backwards for our
  purpose: the hn block references a devnet header; nothing makes devnet
  PoW attest to the hn block. Fork choice is linear-extension only
  (`hn/chain.rs:231–238`), and the hn "block id" commits only
  `(height, prev_root)` (`hn/state.rs:35–41`) — NOT the block contents.
- **Curve-Trees chain (the retired payments track):** the full construction
  exists, reviewed and live — extension-field commitment
  (`aegis-node/src/auxpow.rs:58–79`, `AEGIS_MM_KEY`, rule-404/405
  discipline), the fail-fast share verifier re-deriving everything from
  presented bytes (`auxpow.rs:16–23`, merge-mining.md §2.3 steps 1–6 +
  DAA equality), and weight fork choice with pending-hostile `is_final`
  (`aegis-node/src/mm_forkchoice.rs:1–63`). Oracle-tested against a real
  PoW-committed extension (`aegis-node/tests/auxpow_real_extension_oracle.rs`).

**Dependency verdict (asked explicitly in the task):** epoch-validity is NOT
a superset of the Tier-1 "full aux-PoW commitment" — it **strictly depends
on it**. The commitment (hn header id inside the mined Ergo/devnet
candidate's extension, `merge-mining.md` §2.2) is the object the proof
verifies; without it there is no PoW statement to prove. It also depends on
a real hn **header id** (one that commits the whole block) existing, which
the commitment work must define anyway. It does NOT subsume
aux-PoW-weight fork choice (that remains the live node's job); it subsumes
only fork choice's *bridge-safety* role, for the vault-canonical chain
specifically. **Sequencing: the Tier-1 hn aux-PoW port (call it E0) ships
first or in the same chain-id-breaking cut** — it is a port of existing,
reviewed M2a/M2b code, not new design.

## 2. The mechanism — "vault-canonical PoW suffix" (hybrid, recommended)

One sentence: **the vault chains the sealed hn tip's header id (new
register), and each settlement proves that the new sealed tip extends the
previous one by a consensus-valid, aux-PoW-carrying hn block suffix whose
appended leaves are exactly the epoch — with canonical-Ergo anchoring
enforced by the contract through `CONTEXT.headers`.** Fabricating an epoch
then requires mining it for real.

### 2.1 Components

**E0 — hn aux-PoW foundation (Tier-1 prereq, chain-side, no proof work).**
Port the merge-mining construction to the hn chain:

- Define the hn **header id**: a Poseidon2 digest (NOT blake2b — see cost
  note below) over the canonical header fields: `chain_id, height,
  prev_header_id, state_root, leaves_root, nullifiers_root_delta or nf list
  commitment, pot_after, sc_nbits, miner_owner, coinbase_amount,
  coinbase_cm, body_commitment`. The 8-limb digest packs to the 32-byte id
  the extension field carries (`aegis_mm_extension_field`,
  `aegis-node/src/auxpow.rs:58–66` — the Ergo side treats it as opaque
  bytes). Choosing Poseidon2 makes every in-circuit id recomputation ~1
  permutation instead of a software blake2b; the only blake2b the proof
  ever touches is Ergo's own PoW/header material, which is unavoidable.
- `sc_nbits` + LWMA DAA live on hn (`daa.rs` port), share witness +
  `verify_share` port, weight fork choice port (M2b). All existing code.
- Consensus: an hn block is valid only with a verified share binding its
  header id (replacing the monotonicity-only `AnchorRegressed` check,
  `hn/state.rs:384–386`).

**E1 — structural epoch validity in-proof.** The settlement statement gains:
given the previous sealed tip header id `T_prev` (journal-bound to the new
vault register, exactly the R4/R6 pattern) and the presented suffix of
blocks `B_1..B_k`:

- header ids chain: `B_1.prev_header_id = T_prev`, each `B_{i+1}` links
  `B_i`; `T_new` = id of `B_k` — committed in the journal, contract binds
  it to the successor's register.
- each block's **leaves are re-derived, not supplied**: tx output cms from
  the (recursion-verified, see below) spend publics, peg-in mints via
  `pegmint_cm_expected`, coinbase via `coinbase_cm_expected` with the
  consensus amount `min(pot_parent, base + per_tx × n)`, in the exact
  consensus order (`hn/state.rs:530–544`); the frontier transition then
  consumes exactly these leaves — the epoch IS the suffix's output, by
  construction, and `new_root` must equal `B_k.state_root`.
- consensus arithmetic replayed: pot chain (`pot_after = pot_parent + fees
  − coinbase`, `hn/state.rs:460–492`), conservation (I1-extended), peg-out
  burn binding per block (`burn_cm_expected`, already in the guest),
  peg-in fee/mint arithmetic, genesis-prefix rules.
- **every spend proof in the suffix verifies** — not just the burns'. This
  is where recursion pays: all suffix txs' proofs enter the SAME
  aggregation tree the batch design already builds for the withdrawals'
  spends (`recursion-feasibility.md` §5 carrier (i)); the guest's one root
  verify then attests all of them, constant-cost (measured §7: 48.1–227.1 M
  cycles, flat N=2→8).
- anchor-window discipline in-proof: each spend's `PUB_ROOT` must be one of
  the last `ROOT_WINDOW` (= 100, `engine/wallet/src/chain.rs:28`)
  state-roots along the chain. In-suffix roots the guest has; for the seam
  (the first ≤100 blocks of the suffix) the prover supplies the previous
  ≤100 headers, authenticated by walking `prev_header_id` back from
  `T_prev` — ~1 Poseidon2 permutation per header. This **closes §7.3's
  fabricated-anchor item within the vault-canonical model**: a spend can no
  longer anchor to a private tree, only to real roots of the chain the
  vault has settled.
- **`pegout_delay` enforced in-guest**: a burn at suffix height `h` is
  settleable only if `sealed_tip ≥ h + pegout_delay` (10,
  `hn/params.rs:120`). Today this is host-side only (`batch-settlement-
  design.md` §4) — moving it in-proof is what forces a fabricator to mine
  a ≥ `pegout_delay + 1`-block suffix rather than a 1-block one. It is the
  security parameter of §6; cheap to raise.

**E2 — aux-PoW verification per suffix block (the fabrication pricer).**
For each `B_i`, verify the share witness (merge-mining.md §2.3 steps 1–6):
Ergo candidate header decodes, `msg = blake2b256(bytes_without_pow)`,
extension-Merkle inclusion of `0x01 ‖ id(B_i)` under the candidate's
`extension_root`, `sc_nbits` equals the DAA expectation over the suffix's
own ancestors, and `check_pow_v2(msg, nonce, height, version,
target(sc_nbits))` (`ergo-crypto/src/autolykos/v2.rs:97–108`). This is a
pure function over presented bytes — it ports to a guest directly. Cost is
THE dominant new term; carriers and numbers in §4.

**E3 — nullifier freshness across settlements (accumulator
generalization).** Structural validity alone checks double-spends only
*within* the suffix (in-guest hash set — cheap). Across settlements, a note
below the watermark can be re-spent in a later fake... no — in a later
*valid* suffix its nullifier is deterministic, so the fix is set-membership,
and the settled-burn accumulator almost provides it: burn `nf0`s are
inserted into the R6 SMT. The hole: a 2-in spend re-using an already-spent
note as its **second** input (`nf1` never enters a burn-`nf0`-only set).
Fix: **insert every nullifier of every suffix spend** (both `nf`s, all txs,
not just burns) into the R6 SMT, non-membership-then-insert as designed
(`settled-burn-accumulator-design.md` §3). This makes the vault-canonical
chain double-spend-free end to end. Cost forces a carrier decision (§4):
496 compressions × 2 per tx is fine for ≤16 burns in-guest but dead for
busy epochs — it belongs in a native Poseidon2 AIR inside the recursion
tree (the tree already registers a Poseidon2 table —
`recursion-feasibility.md` §7 harness note).

**E4 — canonical-Ergo anchor binding (the on-chain lever; the task's point
4, and yes, it is the key lever).** The PegVault sits ON the chain hn is
merge-mined against — so the vault's own execution context IS a canonical
view of the anchor chain:

- The contract splices `ergo_ref = CONTEXT.headers(j).id` (a recent
  canonical header, last-10 window — supported by the devnet evaluator:
  `ergo-sigma/src/evaluator/types.rs:253–255`, SHeader at `:469`) into the
  reconstructed journal. Byte-exact `verifyStark` then forces the guest to
  have committed that exact id.
- The guest proves: some devnet/Ergo header `H_anchor` extension-commits
  `id(B_a)` for a suffix block `B_a` (extension-Merkle inclusion, the
  §2.3-step-4 check), and `H_anchor` is an **ancestor of `ergo_ref`** by
  hash-linkage: recompute each header's id (blake2b256 of header bytes)
  and follow `parent_id` from `ergo_ref` back to `H_anchor`. **No PoW
  verification needed for this chain** — canonicality of `ergo_ref` is
  supplied by Ergo consensus itself via `CONTEXT.headers`; linkage costs
  ~2–3 blake2b compressions (~30–60 K cycles, reasoned) per header, ~2–4 M
  cycles at 72-deep. This is the cheap trick the whole hybrid rests on:
  *the contract contributes the one fact a proof cannot — a canonical
  chain view — and the proof contributes everything the contract cannot.*
- Policy knob `A_min`: the anchored block `B_a` must satisfy
  `height(B_a) ≥ sealed_tip − A_slack` (anchor near the tip) and
  `depth(H_anchor under ergo_ref) ≥ A_min` (anchor settled). What it buys:
  a fabricated suffix must additionally get its fake tip committed **into
  the canonical Ergo chain** — which only a miner of a real Ergo block can
  do (extension contents are the miner's choice; honest Aegis-aware miners
  commit their own node's tip, `merge-mining.md` §4). On mainnet that is a
  full Ergo block's hashrate per attempt, and it is *public* — watchtowers
  see a fake tip anchored on Ergo before the release can confirm. What it
  does NOT buy: on the difficulty-1 STARK devnet, Ergo blocks are free, so
  E4 is mechanism-demonstration only there (stated in §6).
- Liveness cost: honest anchors arrive only when opted-in miners win Ergo
  blocks — early-adoption cadence is lumpy (`merge-mining.md` §10.1), so
  `A_min`/`A_slack` must be generous at first or E4 gated per network.
  Operational wrinkle: `ergo_ref` must still be in the last-10 window when
  the release tx validates → bind the oldest of the ten and re-prove
  (cheap: re-run guest + wrap, ~minutes) if the window is missed.

### 2.2 Journal and vault deltas (sketch)

Extends the v6 batch+accumulator journal
(`settled-burn-accumulator-design.md` §3) — all fixed-width, prepended
before the entry list, injectivity argument unchanged:

```
b"AEGISPV1"                          8   (new tag, new image id)
prev_root / new_root                64   (unchanged)
settled_root_in / settled_root_out  64   (R6 — now ALL suffix nullifiers)
tip_id_prev / tip_id_new            64   NEW — binds vault R7 / successor R7
ergo_ref_id                         32   NEW — contract splices CONTEXT.headers(j).id
counter_next_be                      8
entry[1..=N]                        var  (unchanged)
```

Vault: one new chained register **R7 = sealed tip header id** (the
`r6_bytes` pattern verbatim, ~30–40 B of tree — budget fine at ~1 KB of
4096, `vault.rs:39`) plus the `CONTEXT.headers(j).id` splice (SHeader
property access exists in the evaluator; the exact opcode path is a
hand-assembly item for the two-tier oracle test discipline,
`bridge-tools/tests/vault_predicate.rs`). Deploy pins `tip_id_prev` genesis
= the hn cut's genesis header id.

## 3. What is proven where (the division of labor)

| layer | establishes | mechanism |
|---|---|---|
| **recursion tree** (native, CPU, off critical path) | every suffix spend proof is valid; (E3) the nullifier-SMT transition over all suffix nfs; (endgame E2) blake2b/Autolykos work | leaf recursion ~2 s/proof + 2-to-1 tree (`recursion-feasibility.md` §2/§8), publics propagate to root |
| **settlement guest** (RISC0, the wrap) | one root-proof verify attests the tree; header-id chaining `T_prev → T_new`; leaves re-derived = frontier input; pot/conservation/coinbase/peg arithmetic; anchor-window + `pegout_delay`; (E2 interim) per-block share verify; (E4) `H_anchor → ergo_ref` linkage | extends the v6 batch guest; journal §2.2 |
| **PegVault** (on-chain) | journal byte-exact vs receipt (`verifyStark`, image-id pinned); R4/R6/R7 state chaining (the induction backbone); `ergo_ref` IS canonical (CONTEXT.headers); output/amount/recipient binding | reconstruction, no parsing — `vault.rs:24–34` mechanism unchanged |
| **merge-mining / Ergo consensus** | real work exists behind each share; one header commits ≤1 hn id (rule 405); canonical Ergo view; anchor settledness | `merge-mining.md` §2, `auxpow.rs` |
| **hn node consensus** (NOT trusted by the bridge after this ships) | live-network fork choice, DA, mempool policy — liveness only | `mm_forkchoice.rs` port |

The trust statement after E0–E4: a release is valid only if the paid burns
sit on a consensus-valid, double-spend-free, real-work hn chain suffix
extending the vault's entire settled history, whose tip a canonical Ergo
block has committed. The hn *network* is no longer trusted for bridge
**safety** at all — only for liveness.

## 4. Cost against the recursion-era budget (the affordability question)

Baseline (measured, `recursion-feasibility.md` §7): settlement guest total
**83.6 M cycles** (SHA final layer; 267.4 M with the Poseidon2 final) —
constant in N — plus the frontier transition 1.1 M/block (240-block hourly
epoch at the 15 s target: 264 M; the measured 447-block epoch: ~0.5 B).
That is the "~185 M-class constant + per-block transition" budget this must
fit.

New terms, per 240-block epoch, honest measured/reasoned split:

| term | carrier | cost | status |
|---|---|---|---|
| E1 structural replay (cm recomputation ~10–40 Poseidon2/block, id chain ~1 perm/block, u64 arithmetic, seam headers) | in-guest | ~0.5–2 M cyc/block → **0.12–0.5 B/epoch** | reasoned from the 20–35 K/compress calibration (`settled-burn-accumulator-design.md` §3) |
| E1 all-tx spend verification | recursion tree | ~2–4 s CPU/tx off-path; root verify **flat** (measured N≤8; publics ingestion grows mildly with total tx count — measure at N~10²) | measured/§8 |
| E2 aux-PoW, software in-guest | in-guest | ~2,150 blake2b compressions/header (structure read from `v2.rs:29–66` + `M_BYTES=8192`: 33 hashes × ~8.2 KB) × ~5–15 K cyc/compress (**unmeasured**) ≈ **11–32 M/block → 2.6–7.7 B/epoch ≈ 1–2.9 h GPU** | reasoned — the make-or-break measurement |
| E2 per-block IVC (`env::verify` chain) | RISC0 composition | same cycles, paid continuously as blocks arrive; at 15 s blocks needs ~0.7–2 Mcyc/s sustained ≈ **1–3 dedicated 3090s**; at 60 s blocks ≈ a fraction of one GPU. Critical-path addition ≈ one assumption resolve (~constant) | reasoned from risc0 composition docs; not exercised |
| E2 endgame: blake2b AIR in the tree | native AIR | ~516 K compressions/epoch — seconds-to-minutes CPU at measured prover throughput, embarrassingly chunkable; **build cost: a new 64-bit ARX AIR (p3-blake3 is the template) + the guest-side digest-list binding — weeks + review** | reasoned |
| E3 nullifier SMT, all nfs | in-guest: ~25 M/tx — **dead** for busy epochs; native Poseidon2 AIR: 992 compressions/tx — trivial (the tree already registers a Poseidon2 table) | AIR carrier required | reasoned |
| E4 anchor linkage | in-guest | ~30–60 K cyc/Ergo header × depth ≤ ~72 ≈ **2–4 M/epoch** — noise | reasoned |
| E4 contract side | on-chain | one CONTEXT.headers read + journal splice; ~tens of bytes of tree | verified feasible (evaluator has SHeader + 0xCB blake2b if ever needed) |

**Reading of the table:** E1 + E3(AIR) + E4 together cost roughly *one more
epoch-transition term* — comfortably inside budget, and off the wrap's
constant path. **E2 is the honest hard cost.** Software-in-guest per-epoch
is 1–3 h GPU (viable only as a separate pipelined receipt, ugly); per-block
IVC makes it a continuous background load priced like a second settler GPU;
the blake2b AIR makes it near-free at scale but is the one genuinely new
build. Block time is a first-class lever here: at the 60 s candidate
(`merge-mining.md` §3 DECISION NEEDED) every E2 carrier gets 4× cheaper.

**Cost decision (recommended):** ship E2 first as **per-block IVC** (zero
new cryptography, all pieces exist, pipelined off the critical path), with
the blake2b AIR as the planned scale optimization. Gate: measure blake2b
cycles/compression in-guest before pinning (M-E1 measurement, same
discipline as M1/Q5).

## 5. Interactions (asked explicitly)

- **Incremental frontier:** unchanged and load-bearing — `prev_root →
  new_root` stays the value-tree transition; E1 only replaces *where the
  leaves come from* (derived from proven blocks instead of settler input).
  `new_root == B_k.state_root` welds the frontier chain to the header
  chain.
- **Settled-burn accumulator:** strictly complementary, and E3 *generalizes*
  it (all suffix nullifiers, not just burn `nf0`s). Its replay closure
  (§7.1 induction) is untouched; its §7.3 fabrication residual is what this
  design addresses; its Q4 option (drop the watermark rule for
  membership-path release) remains compatible but is still deferred.
- **Aux-PoW commitment (Tier-1):** hard dependency (§1). Epoch-validity
  consumes it; it does not replace weight fork choice node-side.
- **Batching/D1/v6 cut:** the guest here extends the v6 batch guest; the E0
  chain-side changes (header id, share consensus) are hn-chain-id-breaking.
  **Recommend folding E0 into the same v6 re-cut** (already breaking for
  D1 + recursion's Poseidon2 client config) even if the epoch-validity
  guest (new tag `AEGISPV1`, image id v7) trails — otherwise a second hn
  re-cut later. Decision D-EV1.

## 6. Security argument — what closes, what is priced, what remains

**Claim (after E0–E4):** any accepted release's burns lie on a suffix
`S = B_1..B_k` such that: (i) S is hn-consensus-valid (structure, spends,
economics, double-spend-free vs the entire settled history — E1+E3);
(ii) every `B_i` carries real Autolykos work at the DAA-enforced difficulty
(E2 — the DAA equality means a fabricator inherits the honest chain's
difficulty at the fork point, and the LWMA ×4/÷4 clamps prevent walking it
down quickly); (iii) S extends the vault's full settled history (R4/R6/R7
induction — no rewrite, ever); (iv) `k ≥ pegout_delay + 1` for any paid
burn (in-guest); (v) S's tip region is committed in the canonical Ergo
chain (E4).

**Fabrication is therefore no longer an attack, it is an economics:** the
cheapest fake-suffix double-pay costs
`(pegout_delay + 1) × E[work per hn block]` of real Autolykos hashing
(≈ 11 blocks × share-interval × opted-in hashrate, at current parameters)
**plus** one canonical Ergo block committing the fake tip (mainnet: a full
Ergo block's hashrate; also a public, watchable act) **plus** winning the
settlement race against honest settlers. This is exactly SPV-bridge
security — the ceiling argued in §0.2. Levers that scale the price:
`pegout_delay` (linear), `A_min`/anchor count, a per-settlement release cap
(the `V_cap` idea from the attester era, reusable here as
defense-in-depth), and above all merge-mining adoption
(`merge-mining.md` §10.1 — the honest #1 risk carries over verbatim).

**Residuals, stated honestly (what this does NOT close):**

1. **Majority/private-mining fabrication** at the price above. Early
   opted-in hashrate is ~zero → early price is ~zero-plus-one-Ergo-block.
   Not closable by any proof; only by adoption + parameters + caps.
2. **Post-attack wedge:** a successful fake suffix makes the
   vault-canonical chain diverge from the network-canonical one — every
   subsequent honest settlement fails (R4/R7 mismatch). The attack is
   self-outing but the peg wedges; recovery is operational (the O5
   deep-reorg-after-release class, `batch-settlement-design.md` §4 —
   unchanged, now also the fabrication-aftermath story).
3. **Deep Ergo reorg** around `ergo_ref`/`H_anchor` or `> N_mint` under
   peg-ins: pre-existing, Ergo's security budget (merge-mining.md §11.6).
4. **Liveness residuals:** incomplete-batch griefing (D5), settler
   availability, body withholding (a settler needs the suffix bodies to
   prove — withholding delays settlement, never forges it). All
   liveness-not-safety, unchanged.
5. **Devnet toothlessness:** at difficulty 1, E2's work-pricing and E4's
   Ergo-block cost are both ~free — the devnet demonstrates the mechanism,
   the security statement is mainnet-parameter-conditional.
6. **Assumption set (unchanged additions in bold):** RISC0/STARK soundness
   (~113-bit conjectured, Tier-3), Poseidon2 CR, **blake2b CR + Autolykos
   v2 soundness**, unaudited Plonky3-recursion (existing external-review
   gate), `verifyStark` byte-exact semantics, **Ergo `CONTEXT.headers`
   canonicality**.
7. **Open detail — share-stockpiling window:** node-side C2
   (`ergo_height ∈ [tip − K_LAG, tip + 1]`) is subjective and cannot be
   proven in-guest. Proposed objective substitute: suffix blocks' Ergo
   candidate heights must be non-decreasing and end within `K` of
   `height(H_anchor)`; this bounds stockpiling against the anchored
   timeline instead of a node's view. Needs a short adversarial pass
   (decision D-EV4).

## 7. Verdict: FEASIBLE-SOON, staged — with one honest reframing

The reframing first: this does **not** produce "genuinely, not
modulo-something, trustless." It produces the *maximum a closed verifier
can have* — trustless **modulo a priced, public, majority-hashrate attack**
(the same modulo Bitcoin SPV lives with), instead of modulo an unpriced,
invisible, free one. That is the correct target; anything claiming more
would be wrong.

**Stage T — testnet mechanism-complete (~5–8 weeks, mostly ports and guest
work, no new cryptography):**

- E0 port of M2a/M2b to hn (header id, extension commit, share verify, DAA,
  weight fork choice): 2–3 wks — existing reviewed code
  (`auxpow.rs`/`mm_forkchoice.rs`), the main work is the hn header/id
  definition and the consensus wiring. Fold into the v6 re-cut (D-EV1).
- E1 structural guest (extends the I4 batch guest) + R7 + journal +
  `pegout_delay` in-guest + seam headers: 1.5–2.5 wks.
- E2 interim carrier: software share-verify — in-guest for short devnet
  epochs, or per-block IVC if the M-E1 blake2b measurement says in-guest
  hurts: 1–2 wks.
- E4 contract splice + guest linkage + oracle tests: 1 wk.
- Red review + regression suite (the fabrication attack of §0 as the
  headline e2e test — build the private tree, prove, watch it die at four
  distinct checks).

**Stage M — mainnet-grade (adds ~4–8 weeks, the two real builds):**

- E3 nullifier-SMT generalization as a native Poseidon2 AIR in the tree:
  1–2 wks (small AIR, existing primitive).
- E2 endgame: blake2b AIR + Autolykos glue (digest-list binding to the
  guest): 3–6 wks + review — the only genuinely new circuit in the whole
  design. Skippable as long as the IVC carrier's GPU cost is acceptable.
- Parameter work: `pegout_delay`, `A_min`, block time (60 s materially
  cheapens everything here), release caps — with the DAA/adoption data.

**Cheapest sound testnet approximation vs the full version:** Stage T *is*
the sound approximation — every check present, work-pricing real but
devnet-cheap; nothing in it is throwaway. The unsound shortcuts (prove
structure without PoW; sample the suffix; trust the host's `split_leaves`)
are rejected — each leaves fabrication free and would have to be ripped
out.

## 8. Decisions needed / open questions

- **D-EV1:** fold E0 (hn header id + share consensus) into the v6 re-cut
  now, guest (v7 image, `AEGISPV1`) trailing? **Recommend yes** — avoids a
  third hn re-cut.
- **D-EV2:** E2 carrier order — per-block IVC first, blake2b AIR as scale
  work (**recommended**), vs AIR-first. Gate on M-E1 (blake2b
  cycles/compression in-guest) + a GPU-throughput check of the IVC loop at
  the chosen block time.
- **D-EV3:** E4 at Stage T (recommended — the contract splice is cheap and
  the mechanism needs devnet soak) vs deferring to mainnet params.
- **D-EV4:** the objective stockpiling rule (§6.7) — needs its own short
  adversarial pass.
- **D-EV5:** hn header id hash = Poseidon2 (recommended, §2.1-E0) — confirm
  no Ergo-side tooling assumes blake2b of the committed 32 bytes (it
  shouldn't; the field is opaque, `merge-mining.md` §2.2).
- **Q-EV1:** root-verify publics ingestion at realistic suffix tx counts
  (N ~ 10²–10³) — measured flat only to N=8; measure before pinning
  MAX_EPOCH_TXS.
- **Q-EV2:** does `ergo_ref`'s last-10 window force re-proves often at
  devnet cadence? Measure on the live devnet; if so, bind depth-9 and/or
  add a node-side "hold release until ref settles" policy.
- **Q-EV3:** whether E3's all-nullifier SMT should instead live in hn
  consensus itself (nullifier-set root as a header field) — same work,
  different home; consensus-side makes light clients stronger, guest-side
  keeps hn consensus untouched. Leaning guest-side for this cut.
