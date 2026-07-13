# G2.5 — PegMint verifier packaging (`verify_pegmint`)

**Date:** 2026-07-12 · **Status:** steps 1–4 BUILT (`aegis-node::pegmint`, `verify_ergo_chain`) — PoW+NiPoPoW reused (confirmed stand-alone), anchor+depth+absolute-work objectivity policy unit-tested, testnet anchor pinned from the live node; steps 5–9 (tx/box/receipt/used-set) + a real full-proof e2e vector are the follow-on (see DEFERRED; the exact steps 5–9 proof schema is DESIGNED in §5, unbuilt). Design below unchanged. · **Depends:** [g25-spv-reuse-spike.md](./g25-spv-reuse-spike.md) (verifiers confirmed reusable-as-is), [peg-spv-design.md](./peg-spv-design.md) §1 (objectivity + flows). **Role:** turn the reuse spike's confirmed pieces into ONE deterministic, objective consensus function. Consensus numbers (`N_mint=10`, `V_cap=1000 USE`, `USE_TOKEN_ID_MAINNET`) are frozen in params.md/aegis-spec — this doc must not diverge; where it wants a change it says so.

---

## 1. `verify_pegmint` — the objective mint verifier

Signature (lives in a new `aegis-peg` crate or `aegis-node::peg`; deps = `ergo-crypto` + `ergo-validation` + `ergo-ser` + `aegis-spec` + `aegis-crypto`):

```rust
pub fn verify_pegmint(
    proof: &PegMintProof,          // parsed once from wire bytes; see §1a
    used_set: &PegMintUsedSet,     // consensus state (versioned like the nullifier set)
    params: &NetworkParams,        // N_mint, USE_TOKEN_ID, peg fee rule, ...
    anchor: &ErgoAnchor,           // pinned mainnet origin constant (aegis-spec)
) -> Result<PegMintEffect, PegMintError>;

pub struct PegMintEffect {         // what consensus applies on Ok
    pub note_value: u64,           // N (base units) — public, becomes the minted note's value
    pub sc_dest: [u8; 33],         // R4 receiver address core
    pub box_id: [u8; 32],          // inserted into used_set (I2)
    pub pot_credit: u64,           // proven peg-in fee → emission pot (§3)
    pub rho_seed: [u8; 32],        // = box_id; note rho = rho_pegmint(box_id) (aegis-crypto)
}
```

**`PegMintProof` (parsed, not trusted):** `{ work: NipopowProof | HeaderSegment, anchor_header: Header, tx_bytes: Vec<u8>, box_index: u16, tx_inclusion: BatchMerkleProof }`. `PegMintError` is a typed enum, one variant per step below — a validator rejects on the first failure; every step is a pure function of `proof`+`params`+`anchor` ⇒ **objective** (all validators recompute identical accept/reject).

### 1a. Steps (each names the reused verifier)

| # | Step | Input → output | Reused fn / check |
|---|---|---|---|
| 0 | **Parse** | bytes → `PegMintProof` | `ergo-ser` deserialize (headers, tx, batch-merkle); reject trailing/oversize |
| 1 | **PoW on every header** | each `Header` in `work` | `ergo_crypto::pow::verify_pow_solution(h)` + `verify_header_difficulty(h, epoch, DifficultyParams::mainnet())` |
| 2 | **Chain validity** | `work` (NiPoPoW) | `NipopowProofExt::is_valid(&self, &DifficultyParams::mainnet())` (composes PoW + interlinks + heights) |
| 3 | **Ergo-mainnet anchoring** | `work.genesis_id` vs `anchor` | equality check against the pinned `ErgoAnchor` constant (§2) — **without this a forged low-history chain passes** |
| 4 | **Objectivity: depth + superchain work vs followed chain** | `work`, `anchor_header`, node's followed-Ergo view | ≥ `N_mint`(=10) dense headers extend `anchor_header`; **superchain score (`best_arg`) ∧ `!node_ref.is_better_than(proof)` at `H_ref = tip−N_mint`** — see the §2b REDESIGN (supersedes the static suffix-floor the shipped code uses) |
| 5 | **Consolidation + lock txs in blocks** | lock `tx_bytes`+`tx_inclusion`, consolidation `tx_bytes`+`tx_inclusion`, header `txRoot`(s) | for each: recompute tx-id (`ergo-ser`) → `verify_batch_merkle_proof(&incl, &header.transactions_root)`. The **consolidation** tx (receipt spent → PegVault) is the mint commit-point (peg.md §3.1); the **lock** tx supplies the receipt box content |
| 6 | **Receipt box + its consumption** | lock tx output `box_index`, consolidation tx inputs | receipt BOX = lock tx output `box_index`; its `box.id()` MUST equal an **input** the consolidation tx spends into the vault (proves consumption = the single-spend commit-point). Ergo tx inputs carry only boxIds, so *content* comes from the creating lock tx, *consumption* from the consolidation tx |
| 7 | **Receipt well-formedness** | the receipt box (step 6) | token id == `USE_TOKEN_ID_MAINNET`; `N` a multiple of `10^-3` USE and > 0; `R4` = 33-byte `sc_dest` present; guarding-script hash == pinned DepositReceipt template (M1/A3) |
| 8 | **`boxId` uniqueness (I2)** | receipt `box.id()`, `used_set` | `box_id ∉ used_set` (else replay) — keyed on the **receipt** boxId (the consumed input) |
| 9 | **Emit** | — | `PegMintEffect { N, sc_dest, box_id, pot_credit = peg_fee(N), rho_seed = box_id }` |

Steps 1–6 are pure over the proof bytes; 7 pure over params; 8 over versioned consensus state. Nothing queries a live node.

> **Consolidation is the mint commit-point (peg.md §3.1 — Fork A + review 2026-07-12).** The mint binds to the *consolidation* event, not the lock: the proof shows the receipt boxId is consumed into the PegVault, so by Ergo single-spend a consolidated receipt can never also be refunded — this closes the refund↔mint double-claim. Because Ergo tx inputs carry only boxIds (not registers/tokens), reading the receipt's `sc_dest`/`N`/template requires the receipt **box** from the lock tx output, cross-checked by boxId to the consolidation tx's spent input — hence **two** inclusion proofs (lock-output supplies content; consolidation-input is the commit-point). The step-4 `N_mint` depth check applies to the **consolidation** (the lock is necessarily older). **Binding rule (review P1-A, enforced by the `ComparativeAnchor` return type): BOTH inclusion headers must resolve through `ComparativeAnchor.settled_view` (height ≤ `H_ref`) — never against the proof's suffix or tip, which are not membership-checked.** The exact two-inclusion proof schema is **§5**.

## 2. Ergo-mainnet anchor (the one new constant)

`is_valid` proves *internal* PoW-chain validity, not *which* chain — so pin an origin in `aegis-spec`:

```rust
pub struct ErgoAnchor { pub header_id: [u8; 32], pub height: u64, pub cumulative_work_floor: u128 }
pub const ERGO_MAINNET_ANCHOR: ErgoAnchor = /* chain-id-breaking; §2a */;
```

**Genesis vs checkpoint (decision needed, peg-spv-design §1d):** a *signed recent checkpoint* (height + header id) is far cheaper to prove-work-from than real genesis and matches how every SPV client bootstraps (trust-on-first-use). Recommend **checkpoint for v1**, disclosed as a governance artifact (mild, honest objectivity caveat). If chosen, `cumulative_work_floor` guards against a shorter forged suffix. Changing the anchor is chain-id-breaking.

## 2b. Objectivity work-policy — REDESIGN (supersedes the static suffix-floor)

**Why:** adversarial review of `aegis-node::pegmint` (`885b985`) found the shipped step-4 policy is a **FIX-BEFORE-WIRING inflation risk**: (i) it sums work over only the ~k-block *suffix* (`check_objectivity` folds `suffix_nbits`), but a NiPoPoW proof's *prefix superblocks* attest exponentially more; and (ii) it compares one proof to a *static* `work_floor`, whereas NiPoPoW security is *comparative* — a patient/rented attacker can build a valid-but-weaker chain from the real pinned anchor (genuine PoW, valid difficulty, far less total work than mainnet) and clear a static floor. A constant cannot track Ergo's ever-growing real work. The corrected policy has three parts.

**(1) Right quantity — the superchain measure, not the suffix.** The proof's attested work is the KMZ17 best-argument `best_arg(diversity(prefix), m)` over the **prefix superblocks** (`ergo_validation::popow::algos::best_arg`, already what `is_better_than` uses internally) — *not* `Σ suffix n_bits`. Replace `check_objectivity`'s suffix fold with the prefix superchain score. (The suffix's only job stays step-4a: `N_mint` depth of dense headers past the anchored tip.)

**(2) Right reference — the node's independently-followed Ergo chain, not a constant.** The aegis-node **light-follows Ergo headers** (consensus.md §1 / C2), so it holds its *own* view of the best Ergo chain. The objective test is **comparative against that view**: a PegMint proof is accepted only if it is **at-least-as-good as the node's own followed chain at the settled reference height** — i.e. `!node_ref.is_better_than(proof, diff)` where `node_ref` is the NiPoPoW proof the node derives from *its own* followed headers. This is exactly NiPoPoW's `is_better_than` (already reused, spike-confirmed), now applied against a real, growing reference instead of a static number. An attacker's weaker-but-valid chain loses the comparison to the honest chain the node has actually seen.

> **Implementation status (2026-07-13) — POLICY IMPLEMENTED, with one design refinement found at build time.** The follower state machine (`aegis-node::ergo_follow::Follower`) now also records each header's KMZ17 μ-level at ingest and exposes `settled_view(h_ref) -> Option<SettledView>` (best-chain id-membership + μ-levels truncated to `H_ref`; `None` when not caught up). The policy is `aegis-node::pegmint::verify_ergo_chain_comparative` → `comparative_policy` → `check_comparative_objectivity`.
>
> **The refinement — membership, not a score comparison (dense reference).** Building the literal `best_arg`-vs-`best_arg` comparison exposed an asymmetry: an honest proof's settled portion is its SPARSE superblock prefix (the dense suffix lies above `H_ref`), while the node's reference is DENSE — a dense-vs-sparse `best_arg` comparison inflates the node side (level-0 counts the whole segment) and **rejects honest proofs** whose prefix is legitimately empty near `H_ref`. KMZ17's `is_better_than` is only meaningful between two prover-constructed sparse chains. For a dense, gap-free reference (the follower enforces parent-linked consecutive heights) the comparative question **evaluates exactly**: an honest proof of the real chain has *every* settled header on the followed best chain (membership); a valid-but-weaker fork has a first settled off-chain header (reject `DivergesFromFollowedChain`); a fork below `H_ref` is a reorg deeper than `N_mint` = out-of-model per §2b.i, and rejecting an out-of-model heavier unknown fork can only refuse mints, never inflate. Headers below the follower's root (checkpoint-rooted) are skipped and at least one settled header must overlap (`NoCommonAncestor` otherwise) — the §2b.ii caveat. The `best_arg_from_levels` entry point (added to `ergo-validation::popow`, score-identical refactor) is **reserved for a future sparse-reference bootstrap mode**, where both sides are sparse and the KMZ17 score comparison is the right tool.
>
> **Adversarial review (2026-07-13): SOUND-WITH-FIXES — both P1s applied (commit a15d604).** The membership evaluation is correct but **scoped to the settled prefix**; two contracts are now pinned in code:
>
> **(P1-A) The suffix is NOT objectified — steps 5–9 must bind inclusion at ≤ `H_ref`.** The proof's dense suffix (the k headers above `H_ref`, up to its attacker-chosen tip) is only PoW/interlink-checked, never membership-checked. Attack that motivated the fix: extend the real chain privately by `N_mint` valid headers → `H_ref` lands on the real chain (membership passes) → plant a fake consolidation in the private suffix → if step 5 binds inclusion to the proof tip, unbacked USE mints. Fix: the comparative path now returns `ComparativeAnchor { h_ref, settled_view }` — the membership-checked region ONLY (no `tip_id`, no suffix anything) — so steps 5–9 structurally cannot bind above `H_ref`; a fake tx would have to sit in a real settled block the attacker can't forge. Corollary stated honestly: **peg-in security above `H_ref` remains the `N_mint`-deep-PoW / `V_cap` assumption (§2b.i/§4)** — the followed chain objectifies the prefix, it does not remove that assumption.
>
> **(P1-B) `NotCaughtUp` = DEFERRAL, never block-invalid.** The membership question has a time-invariant answer once `H_ref` is buried (§2b.i model), so the canonical consensus verdict is *comparative-once-caught-up*: a lagging validator waits and re-evaluates (like any syncing node); a from-genesis re-syncer follows Ergo forward and reproduces identical verdicts. This makes the verdict a deterministic function of the proof for every honest validator, resolving the §2b(3) requirement. The static-floor path is explicitly **non-canonical** bootstrap-only.
>
> (P2: the below-root skip's reliance on `is_valid`+anchor — checkpoint trust, not the follower — is now documented at the code site.)
>
> What remains before wiring: (a) the **live header feed** — JSON→`Header` decode EXISTS (`ergo_rest_json::decode_header_json`, live-Scala id/PoW-oracle-tested); only the HTTP transport choice is open; (b) steps 5–9, which MUST consume `ComparativeAnchor.settled_view` per P1-A. **Full-proof e2e: CLOSED (2026-07-13, cbf8092)** — JSON→binary NiPoPoW decode (`decode_nipopow_proof_json`, byte-identity-oracled vs the Scala wire fixture) + a verbatim continuous testnet proof (tip 442825) run end-to-end through every `is_valid` sub-check, the static path, a tamper-negative, AND the comparative path with a real dense checkpoint-rooted follower (P1-A/P1-B contracts pinned on live data). The static-`work_floor` entry point remains ONLY as the non-canonical §2b.ii bootstrap fallback.

**(3) Determinism.** The result must be a deterministic function of `(proof, node's followed-Ergo state)` so honest validators agree. Near the head two nodes may hold different tips → **pin the reference at a settled height `H_ref = proof.tip_height − N_mint`** (already `≥ N_mint` deep, past normal reorg depth), and derive `node_ref` from the node's followed headers truncated to `H_ref`. At settled depth all honest followers share identical headers, and `is_better_than` is level-coarse (compares superchain scores), so sub-`N_mint` tip jitter cannot flip accept/reject. Reject if the node has not yet followed Ergo to `H_ref` (it must catch up before it can objectively judge — see the bootstrap caveat).

Net `check_objectivity` becomes: anchor-equality (unchanged §2) ∧ `N_mint`-depth (unchanged) ∧ **superchain-score ∧ `!node_ref.is_better_than(proof)` at `H_ref`** — replacing the static `work_floor`.

### 2b.i Reorg deeper than `N_mint`
Unchanged from §4 and now consistent with the followed-chain reference: if Ergo reorgs past `N_mint` after a mint, the node's followed reference itself moves, so the mint can strand → **(C) bounded loss ≤ `V_cap` for dogfood + the params.md `N_mint` reconciliation before non-dust value, → (B) attester finality with S1.** The comparative reference does *not* remove this — it is the same objectivity/liveness tradeoff; flagged, not silently diverged (`N_mint` stays 10 in code, read from `params`).

### 2b.ii Cold-validator bootstrap — the honest caveat (NOT full objectivity)
A **from-genesis cold-sync validator with no followed Ergo state cannot apply (2)** — it has no independent reference yet. So there is a bounded bootstrap assumption: until a fresh node has independently followed Ergo past the heights of the PegMints it must validate, it falls back to the pinned checkpoint's `cumulative_work_floor` (§2) as a *static lower bound* — the weaker, checkpoint-trusting mode — and converges to full comparative objectivity as it follows Ergo forward from the checkpoint. This is trust-on-first-use at the checkpoint (same class as every SPV bootstrap, and as the anchor decision in §2/§8.1), **not** a claim of unconditional objectivity. State it plainly: *objective for a caught-up follower; checkpoint-bounded during bootstrap.*

### 2b.iii Residual external item (now precise)
After this redesign the accept/reject is an **objective function of the proof + the node's settled Ergo view** — no arbitrary constant. With the membership evaluation (implementation note above), the caught-up path has **no `m` and no margin at all** — the remaining external sign-off narrows to: (a) `N_mint` vs the §2b.i out-of-model reorg depth (the membership rule *rejects* any settled fork, so `N_mint` must exceed plausible honest reorgs — same params.md reconciliation as §4); (b) the bootstrap **checkpoint `cumulative_work_floor`** value + its governance disclosure; (c) `m` only if/when the future sparse-reference bootstrap mode is built. That is a bounded parameter review, not "invent an absolute work threshold."

## 3. PegMint → shielded note + pot (reuse the sound mint)

- **Note:** `PegMintEffect.note_value` is the *public* locked amount `N`, so the minted note reuses the already-sound **`aegis-crypto::mint`** path: `verify_mint(N, &mint_proof)` binds the note's value slot to `N` (no inflation — S5a, independently reviewed). The block carries this MintProof exactly like the coinbase mint (S5b), appended as a tree leaf; `rho = rho_pegmint(box_id)` (aegis-crypto, §3 base case) ties uniqueness to the globally-unique Ergo `boxId`. **The PegMint mint side is therefore already-built machinery — only the `verify_pegmint` gate is new.**
- **Pot:** credit `pot_credit = peg_fee(N)` (params: `max(1 USE, 1%×N)`; dogfood `max(0.1,1%×N)`) as a public integer, backing I1 reserve. **Bind the pot credit to PegMint finalization, not first-sight** (same reorg gate as the mint — §4).
- **State:** `used_set` + pot credit are versioned per block and roll back exactly, mirroring the nullifier-set/pot machinery already built (P2/S5b) — reuse `BlockUndo`-style snapshots.

## 4. Reorg deeper than `N_mint` — policy (the graveyard risk)

An Ergo reorg deeper than `N_mint` that orphans a receipt *after* Aegis minted = unbacked USE = **I1 break Aegis cannot un-mint** (notes may be spent/shielded). `N_mint=10` (~20 min) is **dogfood-thin**. Options (peg-spv-design §1c): (A) raise `N_mint`; (B) attester/checkpoint finality at `D_final ≫ N_mint`; (C) accept bounded loss ≤ `V_cap`.

**Recommendation (dogfood):** **(C) under `V_cap`=1000 USE** now — bounded, operator-socialized recovery — **plus a params.md reconciliation to raise `N_mint`** before any non-dust value, migrating to **(B)** once S1 attesters exist. **This needs an explicit params.md change proposal; do NOT silently diverge** — `N_mint` stays 10 in code until params.md is updated, and `verify_pegmint` reads it from `params` so the bump is a one-line param change, not a code change.

## 5. Steps 5–9 — PegMintProof schema (two-inclusion binding)

**Date:** 2026-07-13 · **Status:** DESIGN (docs only, unbuilt) — the exact wire schema + verifier expansion for §1a steps 5–9, consuming the P1-A `ComparativeAnchor` contract from §2b. **Contract:** the whole of steps 5–9 is a pure function of `(PegMintProof bytes, ComparativeAnchor, params, used_set)` — no node queries, no clock, no re-execution of ErgoScript. Every named type/fn below is the real one in the repo (file:line cited), per the §1a table discipline.

### 5.1 Wire struct

```rust
/// One "tx T is in settled block B" claim. The FULL header is carried
/// because `SettledView` (aegis-node/src/ergo_follow.rs:92) holds only
/// id/height/μ-level — it has no `transactions_root`. The header's id
/// is RE-DERIVED by the verifier (`serialize_header`,
/// ergo-ser/src/header.rs:189) and membership-checked against
/// `ComparativeAnchor.settled_view`; since the id is Blake2b256 of the
/// full serialized header, membership-by-id commits `transactions_root`
/// (and everything else in the header) — that is why carrying the
/// header and checking only id-membership is sufficient binding.
/// There are NO free-standing `claimed_id`/`claimed_height` fields:
/// both are derived from `header`, leaving no smuggleable wire surface.
pub struct TxInclusion {
    pub header: Header,          // ergo-ser/src/header.rs:22 (read_header :142)
    pub tx_bytes: Vec<u8>,       // full signed tx wire bytes → read_transaction
                                 //   (ergo-ser/src/transaction.rs:180)
    pub proof: BatchMerkleProof, // ergo-ser/src/batch_merkle_proof.rs:84
                                 //   (read_batch_merkle_proof :173)
}

pub struct PegMintProof {
    /// Steps 1–4 (existing): NiPoPoW chain part, verified by
    /// `verify_ergo_chain_comparative` → `ComparativeAnchor`.
    pub work: NipopowProof,          // ergo-ser/src/popow_proof.rs
    /// Step 5a/6a: the LOCK tx — supplies the receipt box CONTENT
    /// (sc_dest, N, script) as its output `receipt_output_index`.
    pub lock: TxInclusion,
    pub receipt_output_index: u16,   // index into lock tx output_candidates
    /// Step 5b/6b: the CONSOLIDATION tx — the mint commit-point
    /// (peg.md §3.1); supplies the receipt's CONSUMPTION as its input
    /// `receipt_input_index` (Ergo tx inputs carry only boxIds —
    /// ergo-ser/src/input.rs:412: `Input { box_id: Digest32, .. }`).
    pub consolidation: TxInclusion,
    pub receipt_input_index: u16,    // index into consolidation tx inputs
}
```

Envelope codec (aegis side, `aegis-peg`/`aegis-node::peg`): fields VLQ-length-prefixed in the order above, no optional fields, **trailing bytes = reject** (per step 0). Parsing is deterministic, so the accept/reject verdict is a function of the raw bytes.

Both `TxInclusion.header`s may be the **same block** (lock and consolidation chained in one block is legal Ergo); the two headers are then byte-identical — allowed, no dedupe machinery.

### 5.2 Verifier expansion — steps 5a/5b (tx-in-settled-block)

For each of `lock` and `consolidation` (roles differ only in the error tag):

1. **Header id (derived, never trusted):** `hid = serialize_header(&incl.header)?.1` (ergo-ser/src/header.rs:189, returns `(bytes, ModifierId)`).
2. **Settled membership (P1-A binding):** `anchor.settled_view.height_of(hid.as_bytes()) == Some(incl.header.height)` (`SettledView::height_of`, aegis-node/src/ergo_follow.rs:103) — else `InclusionNotSettled { role, height }`. The view contains ONLY best-chain headers with `height ≤ h_ref`, so this single check enforces both "on the followed chain" and "≤ `h_ref`"; nothing in the proof's suffix/tip is ever consulted.
3. **Tx decode:** `tx = read_transaction(&mut VlqReader::new(&incl.tx_bytes))` (ergo-ser/src/transaction.rs:180); reject trailing bytes.
4. **Tx id:** `txid = transaction_id(&tx)?` (ergo-ser/src/transaction.rs:273) = `Blake2b256(bytes_to_sign(tx))`.
5. **Leaf digest (recomputed, never read from the proof):** `leaf = blake2b256(0x00 ‖ txid)` — the scorex leaf rule (`leaf_hash`, ergo-crypto/src/merkle/mod.rs:7; currently private — **implementation note:** expose it as e.g. `pub fn tx_leaf_digest(txid) -> [u8;32]`, a one-liner). Require `incl.proof.indices.len() == 1 && incl.proof.indices[0].1 == leaf` — else `MalformedInclusionProof { role }`. The `BatchMerkleProof.indices` digests are attacker-supplied wire data; **binding the leaf to the recomputed tx id is the load-bearing line** — `verify_batch_merkle_proof` alone only proves *some* leaves reduce to the root. (The leaf *index* value is left unconstrained: the reduction binds position, and Ergo forbids duplicate txs in a block anyway.)
6. **Merkle check:** `verify_batch_merkle_proof(&incl.proof, &incl.header.transactions_root)` (ergo-validation/src/popow/merkle.rs:33 — the same fn the §1a table names) — else `TxNotInBlock { role }`.

**Witness-leaf non-confusion:** block-v2+ `transactions_root` trees append 31-byte *witness ids* as extra leaves (ergo-crypto/src/merkle/mod.rs:98–111). Our leaf preimage is the 32-byte tx id, hashed by the verifier itself — a witness leaf (31-byte preimage) can never equal it without a Blake2b256 collision, so a witness leaf cannot be passed off as a tx.

**`N_mint` depth is measured on the consolidation's inclusion header, and needs no separate check:** `h_ref = proof.tip_height − N_mint` (§2b(3)), and step 2 forces `consolidation.header.height ≤ h_ref`, hence `tip_height − consolidation_height ≥ N_mint` — the consolidation is at least `N_mint` deep in the proof's own chain, and at least `N_mint`-settled on the *followed* chain (the follower must be caught up to `h_ref` to produce the view at all, P1-B). The lock is bound by the same rule; no lock-before-consolidation ordering check is needed — Ergo consensus already forbids spending a box before it exists, and both txs are proven on the real settled chain.

### 5.3 Step 6a — receipt box reconstruction (content from the lock tx)

1. `candidate = lock_tx.output_candidates.get(receipt_output_index)` — else `OutputIndexOutOfRange` (`ErgoBoxCandidate`, ergo-ser/src/ergo_box.rs:30: `value`, `creation_height`, `tokens: Vec<Token>` (token.rs:11: `token_id`, `amount: u64`), `additional_registers: AdditionalRegisters`, plus raw `ergo_tree_bytes()`/`register_bytes()` accessors :198/:208).
2. `receipt = ErgoBox { candidate, transaction_id: lock_txid, index: receipt_output_index }` (ergo-ser/src/ergo_box.rs:218).
3. `receipt_box_id = receipt.box_id()?` (ergo-ser/src/ergo_box.rs:232) = `Blake2b256(serialize_ergo_box)` — candidate body ‖ 32-byte tx id ‖ VLQ-u16 index. Everything the mint reads (boxId, sc_dest, N, script) is therefore committed by `lock_txid`, which is committed by the settled header via step 5a.

**Round-trip fidelity note (oracle-test it):** tx-wire outputs are *token-table-indexed* (`read_ergo_box_candidate_indexed`, ergo_box.rs:366) while `box_id` hashes the *standalone* form (full token ids). The candidate preserves raw `ergo_tree_bytes`/`register_bytes`, so re-serialization is byte-faithful — but the test plan (§5.8) pins `receipt.box_id()` against the node-reported boxId of a real output precisely because this is a parity surface.

### 5.4 Step 6b — consumption + the merge-vs-refund discriminator (the soundness point)

**Consumption:** `consolidation_tx.inputs.get(receipt_input_index)` — else `InputIndexOutOfRange`; require `.box_id == receipt_box_id` (`Input`, ergo-ser/src/input.rs:412) — else `ReceiptNotConsumed`. This is the peg.md §3.1 commit-point: the receipt boxId is spent, so by Ergo single-spend it can never also be refunded *afterwards*.

**But consumption alone is NOT enough — the receipt script admits TWO spend paths** (`DepositReceipt.es`, post-F1 merge/refund split):

```
sigmaProp(mintable && mergedIntoVault) || (sigmaProp(isUseReceipt && timedOut) && depositor)
```

A **refund** spend (`isUseReceipt && timedOut && depositor`, DepositReceipt.es:49–51) also consumes the boxId. If the verifier accepted mere consumption, a depositor could refund after timeout and then submit the refund tx itself as a "consolidation" → get `N` back on Ergo **and** mint `N` on Aegis. So *receipt-script-enforcement does not suffice*; the verifier must decide, from the tx alone, **which branch ran**. The discriminator is the receipt's own merge predicate, mirrored exactly (`mergedIntoVault`, `DepositReceipt.es:40–43`):

> require `consolidation_tx.output_candidates[0].tokens` non-empty **and** `output_candidates[0].tokens[0].token_id == params.peg_vault_nft` — else `NotConsolidatedIntoVault`.

**Why this predicate is sound (necessity and sufficiency):**

- **Necessary:** a genuine refund tx cannot satisfy it. `PEG_VAULT_NFT` is a singleton: Ergo's token-minting rule (new token id = the minting tx's *first input boxId*, preimage-resistant) means the NFT can never be re-minted, and token conservation means an output carrying it requires an input carrying it — i.e. the real PegVault box is spent in the same tx. A depositor "refunding" into a tx shaped like that isn't refunding (see next point).
- **Sufficient:** if `OUTPUTS(0)` carries the genuine vault NFT in a consensus-valid tx in a settled block, the PegVault input's script ran. Its two paths: **PAYOUT is impossible here** — payout requires `receiptSum == 0` (`PegVault.es:109`) and `receiptSum` counts every input whose `blake2b256(propositionBytes) == RECEIPT_SCRIPT_HASH` (`PegVault.es:81–85`), which includes this receipt because step 7 pins the receipt's tree to that same template hash. So **TOP-UP ran**, and top-up enforces `vaultOutUSE == vaultInUSE + receiptSum + feeSum` (`PegVault.es:140–143`) — the vault provably absorbed this receipt's `N`. Even the corner case "depositor signs a timed-out receipt into a vault-topped tx" (both script branches true) is a *merge*: the vault accounting took the USE; the depositor got nothing back; minting is correct.
- **What we rely on (stated honestly):** the SC does **not** re-execute ErgoScript. Soundness rests on (i) the tx being consensus-valid in a *settled real block* (steps 5a/5b — an attacker cannot get an invalid tx into one), (ii) Ergo's token-mint/conservation rules, and (iii) the deployed `DepositReceipt.es` / `PegVault.es` being byte-identical to the pinned templates (step 7 hash pin; chain-id-breaking constants). The `PegVault.es` top-up accounting itself is the pass-2-reviewed siphon fix (contracts/DESIGN.md) — its correctness is a standing dependency of this step.

### 5.5 Steps 7–9 — well-formedness, replay, emit

**Step 7 (pure over the reconstructed receipt candidate + lock tx + params):**

1. **Script pin:** `blake2b256(candidate.ergo_tree_bytes()) == params.deposit_receipt_script_hash` — else `WrongReceiptScript`. (`propositionBytes` in ErgoScript *is* the serialized-ErgoTree bytes; same preimage the vault hashes at `PegVault.es:82`.) This pin is load-bearing twice: it is what makes §5.4's `receiptSum` argument include this box, and it stops a *fake-receipt* box (attacker script) whose USE the vault's accounting would NOT absorb (its script hash ≠ `RECEIPT_SCRIPT_HASH` → contributes 0 to `receiptSum` → its USE is routable back to the attacker) from minting.
2. **Token:** `candidate.tokens` non-empty; `tokens[0].token_id == params.use_token_id` (mainnet `a55b…2669`, params.md) — else `WrongToken`; `N = tokens[0].amount`; `N > 0` — else `ZeroAmount`. (`N` is integer base units = automatically a multiple of `0.001` USE, params.md decimals = 3. Optional sanity `N ≤ V_cap`: a consolidation pushing the vault past `V_cap` cannot be on-chain anyway, `PegVault.es:76`.)
3. **sc_dest:** `candidate.additional_registers.get(RegisterId::R4)` (ergo-ser/src/register.rs:64/:14) must be a `Coll[Byte]` constant whose payload is **exactly 33 bytes** → `sc_dest: [u8; 33]` (the §1 `PegMintEffect` shape) — else `BadScDest`.
4. **Peg-in fee (makes §1's "proven peg-in fee" true):** sum the USE amounts of lock-tx outputs whose `blake2b256(ergo_tree_bytes()) == params.fee_pot_script_hash`; `pot_credit = min(Σ fee paid, peg_fee(N))`, **never reject on a shortfall.** `peg_fee(N) = max(fee_floor, N·fee_bps / 10000)` with the *same integer arithmetic* as `PegVault.es:113–114` (dogfood floor `100` base units, mainnet `1000`; `N ≤ V_cap` bounds the multiply — use checked ops anyway). *Decision `min()` — ADOPTED per adversarial review F2 (2026-07-13), reversing the earlier pinned reject-if-missing.* Verified argument: **the fee is emission-pot credit, NOT I1 reserve backing** — the minted note's `N` is backed by the full `N` the vault absorbs (`receiptSum`, `PegVault.es:140–143`), independent of the fee (a *separate* FeePot output, also absorbed as `feeSum`). So `min()` under-credits *emission* by a `V_cap`-bounded amount (a tuning concern; deliberate underpayment only shrinks the miner subsidy, never inflates or steals) — whereas reject-if-missing converted a recoverable UX error into **total principal loss a permissionless consolidator can trigger on a victim** (F1). Never stranding principal outweighs keeping §3's emission literally frozen. **This is an emission-POLICY choice — `min()` is the safer engineering default adopted here; the emission owner signs the final rule at wiring (external-sign-off bucket).** Consequence: the fee-less-lock case no longer traps — a fee-less receipt still mints (0 pot credit), so nothing consolidatable is unmintable for the fee reason; the residual R4-shape trap is closed contract-side (see (5)).

**Step 8 (replay, I2):** `receipt_box_id ∉ used_set` — else `AlreadyMinted`. Keyed on the **receipt** boxId (the consumed input), exactly as §1a; insertion happens on block-apply with the versioned rollback of §3.

**Step 9 (emit, unchanged from §1/§3):**

```rust
PegMintEffect {
    note_value: N,
    sc_dest,                       // [u8; 33] from R4
    box_id: receipt_box_id,        // → used_set
    pot_credit: min(fee_paid, peg_fee(N)),  // step 7.4 (min(), never rejects)
    rho_seed: receipt_box_id,      // note rho = rho_pegmint(box_id)
}
```

### 5.6 Size / DoS bounds (checked at step 0, before any hashing)

| Field | Bound | Rationale |
|---|---|---|
| whole `PegMintProof` | `MAX_PEGMINT_PROOF_BYTES = 2 MiB` | envelope cap; everything below nests inside |
| `work` (NiPoPoW) | `MAX_NIPOPOW_PROOF_BYTES = 1 MiB` | measure against the real e2e vector (tip 442825) before freezing; `m`/`k` bound header count |
| each `header` | `4096 B` | real headers ~200–300 B; slack for `unparsed_bytes` future versions |
| each `tx_bytes` | `MAX_PEG_TX_BYTES = 1 MiB` | lock/consolidation txs are few KB; cap ≪ Ergo max block size. **Reject-valid note:** a legit consolidation above the cap can never mint (funds stranded in the vault) — consolidators must stay under it; the cap is a consensus param in `aegis-spec`, not a tunable |
| each `proof.indices` | exactly `1` | single-leaf claims only |
| each `proof.proofs` | `≤ 64` entries | tree depth for ≤ 2^64 leaves; real blocks ≤ ~2^20 txs → ≤ 21 |
| `receipt_output_index` / `receipt_input_index` | `u16`, bounds-checked vs the parsed tx | tx wire counts are u16 (transaction.rs:56–70) |

Verification cost is O(proof bytes) hashing + O(1) `settled_view` lookups; no attacker-scalable allocation beyond the caps. Fail-fast in step order; first error wins (deterministic error, not just deterministic accept/reject).

### 5.7 Error taxonomy (extends `PegMintError`, aegis-node/src/pegmint.rs:96)

```rust
pub enum InclusionRole { Lock, Consolidation }

// new variants (one per rejectable condition; step order = check order)
Oversize { field: &'static str, len: usize, max: usize },   // step 0
MalformedProof { field: &'static str },                     // step 0 (parse / trailing bytes)
InclusionNotSettled { role: InclusionRole, height: u32 },   // 5a/5b.2 (P1-A)
MalformedInclusionProof { role: InclusionRole },            // 5a/5b.5 (leaf ≠ recomputed txid leaf)
TxNotInBlock { role: InclusionRole },                       // 5a/5b.6
OutputIndexOutOfRange { got: u16, len: usize },             // 6a
InputIndexOutOfRange { got: u16, len: usize },              // 6b
ReceiptNotConsumed,                                         // 6b (boxId mismatch)
NotConsolidatedIntoVault,                                   // 6b (refund-shaped / no vault NFT at OUTPUTS(0))
WrongReceiptScript,                                         // 7.1
WrongToken,                                                 // 7.2
ZeroAmount,                                                 // 7.2
BadScDest,                                                  // 7.3
// (no fee-shortfall error — step 7.4 uses min(), never rejects; F2)
AlreadyMinted,                                              // 8 (I2)
```

`NotCaughtUp` keeps its P1-B deferral semantics (never block-invalid); every variant above IS a rejection verdict.

### 5.8 Test plan sketch (oracle discipline)

- **Vectors = real testnet lock + consolidation txs.** Testnet has no USE (params.md: `use_token_id_testnet` TBD) — issue the params.md `lab_stand_in` (3-decimal token), deploy `DepositReceipt.es`/`PegVault.es` with stand-in ids injected (a distinct chain id by construction — §5.9(3)), run a real lock → consolidation on testnet, and capture header bytes + tx bytes + merkle proof **from the Scala node REST** (`:9052`) under `test-vectors/` — expected ids/roots/proofs from the node, never `expected = my_fn(input)` (CLAUDE.md oracle rule).
- **Parity pins:** `receipt.box_id()` vs the node/explorer-reported boxId of the real lock output (the §5.3 round-trip surface); recomputed `txid` + leaf vs the node's tx-inclusion proof; `verify_batch_merkle_proof` vs the node's `transactions_root`.
- **Per-step tamper-negatives** (`mod tests` divider discipline): flip one byte in each wire field → the step's exact error; refund fixture (a *second* receipt spent via the refund path on testnet) presented as consolidation → `NotConsolidatedIntoVault`; replay → `AlreadyMinted`; view truncated below the inclusion height → `InclusionNotSettled` (the P1-A suffix-smuggle test); wrong output/input index; foreign lock tx paired with the real consolidation → `ReceiptNotConsumed`; receipt-lookalike with a different script → `WrongReceiptScript`; **fee-less lock still mints** (pot_credit 0, no rejection — F2); **wrong-length-R4 receipt** rejected two ways — verifier `BadScDest` (step 7.3) AND, contract-side, it is un-consolidatable so the trap never arises (F1: `DepositReceipt.es` merge requires `mintable`, exercised by a compile+spend fixture).
- **e2e:** extend `aegis-node/tests/pegmint_real_proof_e2e.rs` — full `PegMintProof` through steps 1–9 against a real dense checkpoint-rooted `Follower`.

### 5.9 Assumptions / residuals (honest)

1. **Reorg > `N_mint` unchanged** (§2b.i/§4): a settled-then-orphaned consolidation still strands a mint; bounded by `V_cap` + the params.md `N_mint` reconciliation. This schema neither worsens nor fixes it.
2. **Nothing above `h_ref` is objectified** (P1-A corollary restated): both inclusions bind at ≤ `h_ref`; peg-in security above `h_ref` remains the `N_mint`-deep-PoW / `V_cap` assumption.
3. **Template/constant pins are chain-id-breaking:** `deposit_receipt_script_hash`, `fee_pot_script_hash`, `peg_vault_nft`, `use_token_id` join the §2 anchor as frozen `aegis-spec` deploy constants; the testnet stand-ins define a separate chain id.
4. **No ErgoScript re-execution:** §5.4 soundness rests on Ergo consensus validity of settled txs + the pass-2 `PegVault.es` top-up accounting (its adversarial re-review is still flagged in contracts/DESIGN.md — a vault accounting bug would propagate here).
5. **Consolidate-then-unmintable loss-trap — CLOSED (review F1, 2026-07-13).** *General root cause:* consolidation is permissionless and consolidated ⟹ unrefundable (§3.1), so **any** receipt that is consolidatable-but-not-step-7-mintable is permanent principal loss a griefer can spring by front-running consolidation. The design's `DepositReceipt.es` merge/refund split closes the class: the **merge path now requires `mintable`** (`isUseReceipt && R4.size == 33`) — a strict SUPERSET of the verifier's step-7 well-formedness — so a non-mintable receipt **cannot be consolidated at all**; and the **refund path stays lenient** (`isUseReceipt && timedOut && depositor`), so a malformed receipt is always reclaimable by its depositor (mint-or-refund always terminates, no stranding). The fee instance additionally dissolved under the §5.5 `min()` decision (fee-less still mints). **Standing INVARIANT (chain-id-breaking): `DepositReceipt.es` merge-`mintable` must remain ⊇ `verify_pegmint` step 7 — any future step-7 tightening requires a matching contract tightening.**
6. **Checkpoint-rooted follower floor:** an inclusion below the follower's root height gets `height_of = None` → reject. The followed root must predate the first supported lock (true for any launch-time checkpoint; matters only if the root is ever re-pinned forward).
7. **used-set growth** unchanged (§8.5).
8. **Liveness residual from peg.md §3.1 unchanged:** consolidated-but-never-proven receipt = funds safe (over-reserved) in the vault; anyone can later submit this deterministic proof.

### 5.10 Self-adversarial pass (schema vs its own checks)

| # | Attack | Verdict | Killed by |
|---|---|---|---|
| 1 | **Fake consolidation shape** — craft a syntactically valid consolidation tx that was never on Ergo (or sits only in the proof's private suffix) | ✗ dead | 5b.2: `settled_view.height_of(hid) == Some(height)` — the tx must live in a real, membership-checked block ≤ `h_ref`; the suffix is structurally unreachable (P1-A type) |
| 2 | **Refund-path spend presented as the consolidation** — depositor refunds after timeout, submits the refund tx as proof (consumption is real!) | ✗ dead | 6b discriminator: refund tx has no vault NFT at `OUTPUTS(0)` (`DepositReceipt.es:40–43` mirrored) → `NotConsolidatedIntoVault`. If the depositor *does* shape it with the vault NFT, the vault's top-up (`PegVault.es:140–143`) absorbs the USE — it *became* a merge and no refund was received |
| 3 | **Two mints, one receipt** — replay the same proof, or re-wrap the same consolidation with a different `receipt_input_index`/second proof | ✗ dead | step 8: used-set keys on `receipt_box_id`; any proof for the same receipt carries the same boxId. Distinct receipts in one consolidation each mint once, correctly (vault absorbed Σ) |
| 4 | **Vault-lookalike output** — mint a token with id == `PEG_VAULT_NFT`, or put a lookalike NFT at `OUTPUTS(0)` | ✗ dead | Ergo token-mint rule: a new token's id = the minting tx's first-input boxId (Blake2b256 preimage-resistant — cannot be targeted); conservation forces the genuine singleton input. Relies on tx consensus-validity in a settled block (§5.9(4)) |
| 5 | **Inclusion-header smuggling above `h_ref`** — extend the real chain privately by `N_mint` valid headers, plant the tx there (the original P1-A attack) | ✗ dead | 5b.2 again: `settled_view` contains no height > `h_ref`; `height_of` → `None` → `InclusionNotSettled`. The `N_mint` depth guarantee (§5.2) is exactly `h_ref = tip − N_mint` |
| 6 | **Tx malleability / boxId instability** — remalleate spending proofs or context so the "same" tx yields a different id or content | ✗ dead | `transaction_id = Blake2b256(bytes_to_sign)` (transaction.rs:273) commits inputs' boxIds, data inputs, context extensions, and all output candidates (proof bytes are zero-length in the preimage, so proof malleation cannot change anything the verifier reads); `box_id` commits `(candidate, txid, index)` (ergo_box.rs:232) |
| 7 | **Mismatched pairing** — real lock A + real consolidation of receipt B; or wrong `receipt_output_index` into a multi-output lock | ✗ dead | 6b: `consolidation.inputs[j].box_id == receipt.box_id()` — the boxId equality binds the exact `(lock tx, output index)` to the exact consumed input; identical-looking sibling outputs still differ in the serialized `index` |
| 8 | **Fake-receipt consolidation** — lock USE under an attacker script (spendable back to self), consolidate it alongside the vault, mint against it | ✗ dead | 7.1 script pin (`WrongReceiptScript`). Adversarial detail: the vault would *not* have absorbed that box's USE anyway (`receiptSum` counts only `RECEIPT_SCRIPT_HASH` inputs, `PegVault.es:81–85`) — the pin is what keeps §5.4's sufficiency argument airtight |
| 9 | **Witness-leaf confusion** — pass a v2 witness leaf (31-byte preimage) off as a tx-id leaf | ✗ dead | 5a/5b.5: the leaf digest is recomputed from the parsed tx's id (32-byte preimage), never read from the wire; length-distinct preimages can't collide without breaking Blake2b256 |
| 10 | **Payout-smuggle** — consume the receipt inside a vault *payout* tx (vault NFT at `OUTPUTS(0)` is present!) and mint | ✗ dead (on-chain) | such a tx is not consensus-valid: payout requires `receiptSum == 0` (`PegVault.es:109`), so it can never appear in a settled block; step 5b makes unincludable txs unprovable |



## 6. Build order (integration, since crypto is reuse)

1. `aegis-spec`: pin `ERGO_MAINNET_ANCHOR` (checkpoint) + wire `DifficultyParams::mainnet()`.
2. `PegMintProof` type + `ergo-ser` parse (wire schema: §5.1); oracle-test parse against real mainnet block/tx/inclusion bytes.
3. `verify_pegmint` steps 1–8 (steps 5–9 expansion: §5.2–§5.5), each unit-tested; **oracle = real Ergo mainnet PegMint fixtures** (mainnet bytes, per CLAUDE.md oracle rule) — a real receipt verifies, a tampered one at each step rejects.
4. `used_set` + pot-credit consensus state, versioned into block apply/rollback (mirror nullifier-set).
5. Wire PegMint into the block/`try_extend` path: a block's PegMints each `verify_pegmint` → apply `PegMintEffect` (mint note via existing MintProof machinery, insert boxId, credit pot).
6. Reorg/`N_mint` policy §4 + the params.md reconciliation proposal.

## 7. Dogfood fallback (declared, NOT objective — security §1 non-claim)

If step-3/4 work-proof budget slips: **operator-mode** — an operator key signs PegMints after `N_mint` confs on its own Ergo node; consensus checks the signature *instead of* steps 1–4 (steps 5–9 identical). Bounded by `V_cap`. **Explicitly declared operator custody, not a trust-minimized bridge** (M6/M7 wallet warning). Migration is localized: operator-mode and `verify_pegmint` share the *same* `PegMintEffect`/used-set/mint semantics — only the authorization check (steps 1–4 vs signature) differs.

## 8. Open questions (external review + operator)

1. **Anchor: genesis vs signed checkpoint** (§2) — recommend checkpoint; needs operator sign-off as a disclosed governance artifact.
2. **Objectivity work-policy** — REDESIGNED in §2b (superchain measure + comparison vs the node's followed chain, not a static floor). Residual external item narrowed to `m` / the `is_better_than` margin / the bootstrap checkpoint floor (§2b.iii) — a bounded param review, no longer "invent a threshold".
3. **Reorg > `N_mint`** (§4) — the objectivity/liveness tradeoff; the params.md `N_mint` reconciliation is a live decision.
4. **DepositReceipt template hash** (step 7) — depends on the fresh contract authoring (GAPS); the pinned template is chain-id-breaking.
5. **used-set unbounded growth** — same forever-growth question as the nullifier set (R1-T-style remedy, engineering §3).
6. **PegBurn shape** (peg-out direction) — out of scope here; note-protocol §6 cross-check pending (peg-spv-design §5.7).

---
*Design; the cryptographic verifiers are reused (spike-confirmed). Everything here is integration + policy. Nothing overrides params.md/security.md; §2 anchor and §4 `N_mint` are the two items requiring an explicit params/governance decision.*
