# Aegis — deferred / open register (living)

**Role:** the single ledger of everything consciously postponed — designed-but-waiting features, open parameters, engineering debt, research. Each row names its source doc (authoritative for detail) and the **trigger** that reopens it. Add here whenever a doc says "deferred / later / TBD / research"; remove when shipped or rejected.

## Designed, waiting on prerequisites

| Item | Source | Trigger / when |
|---|---|---|
| **R1-T threshold turnstile** (recycle lost USE → pot, archive old nullifier sets; 1y epoch + 1y grace) | `notes/archive/storage-rent-privacy-tradeoffs.md`, aegis-spec §12 | S1 attesters live **and** (nullifier growth measured painful **or** stranded value material). Adds verifiable-encryption gadget to circuit (bench first) |
| **Extension-field MM commitment** (~100 B witness vs ~1–2 KB; no wallet dust) | consensus.md §1 (verified stock-legal, rules 400/405/406) | v2; needs candidate-builder support in both nodes; only worth it if witness size ever matters |
| **EMA-scaled `R_target`** (convert pot overflow → hashrate instead of runway) | params.md, aegis-spec §11 | Pot persistently overflows at dogfood volumes |
| **S2 — Ergo extension anchor** (parallel spike to attesters) | security.md §6 | U1-strong hardening round |
| **S3 — fraud window / bonds**; **S4 — burn Merkle root in state** | security.md §6 | Research; S3-class required before any "trust-minimized" marketing |
| **Receipt tokens / update counter** (unlocks stop racing the hot SideChainState box) | peg.md §4 should-fix, GAPS | Before real exit volume; not blocking dry-run |
| **Light wallet sync** (compact blocks / out-of-band paths) | aegis-spec §7 | Post-G4; full-node wallet accepted for dogfood |

## Open parameters (TBD)

| Param | Source | Blocking |
|---|---|---|
| `R_rent` (ERG endowment on peg boxes + top-up bot sizing) | params.md, E2 | Before any public vault (M5 gate) |
| Min dust / note minimum | params.md | G1.6 note-protocol spec |
| Testnet USE token id (or lab stand-in issuance) | params.md | G3 testnet round-trip |
| Padding arity (fixed 2-in/2-out v1) + `EMPTY_TREE_ROOT` | note-protocol.md §6/§7 | Freeze at G1.6→G2 boundary; 2→4 arity bench-driven |
| Diversified addresses; `r_sk=0`?; memo size; dummy-note construction; exact AEAD/KDF/hash-to-curve primitives | note-protocol.md §9 | Pin at note-protocol freeze (before G2 circuit) |
| Inclusion-bonus β (set ⅓ = 1¢/tx) | aegis-spec §11 | Revisit with dogfood mempool data |
| Attester threshold progression (2/3 → 3/5) | params.md, security.md S1 | When S1 goes live on testnet |
| Combined-work byte layout for GPU/stratum pools | aegis-spec §10, W4 | Before third-party miners (prior art: ergo-stratum-rs) |
| Ergo-reorg policy for pot credits (> `N_mint` reorgs) | GAPS FeePot row, engineering §3 | G2.5 SPV design |

## Engineering debt

| Item | Source | Trigger |
|---|---|---|
| **`NodeMining::candidate_with_txs` seam** — scoped 2026-07-12 (branch `feat/candidate-with-txs`, uncommitted): NOT a REST seam — the Rust node builds candidates from an async cache with **no forced-tx path**; needs `forced_txs` in `ergo-mining/candidate.rs` (pin after emission tx, before user txs, rebuild fee tx — mirror the storage-rent pinning), a synchronous build entrypoint bypassing the cache, a `MiningRequest::GetCandidateWithTxs` bridge variant, both API routes, and (follow-up) `ProofOfUpcomingTransactions` for the membership `proof`. Request body = JSON array of ErgoTransaction (no fee/cost). | consensus.md §1, W4 | ~1–2 day consensus task; **needs a live Scala node for `candidateWithTxs` parity diffing** — do alongside testnet Scala-node bring-up |
| Ergo-SPV-in-consensus is **mostly wiring, not new crypto** — the monorepo already has Rust Autolykos + `ergo-validation/src/popow/proof.rs` (NiPoPoW) + `batch_merkle_proof.rs`; a from-genesis validator can skip Ergo headers via NiPoPoW | `peg-spv-design.md` (draft), engineering §3 | G2.5 — spike the stand-alone reuse first |
| Wallet zero-note reserve (S3 dummy mechanics: keep ≥1 owned zero-value note so 1-real-input transfers can pad to the uniform 2-in shape; each transfer regenerates one) | note-protocol §6, P3 S6 | Wallet build (P4/S6) |
| **PegMint/coinbase must mint a paired zero-note** with a wallet's first value note (S3 consequence: a wallet holding exactly one note cannot transact) | note-protocol §6, peg.md | G2.5 PegMint spec / S5 coinbase |
| Per-tx proof verification is NOT yet batched across a block (S4 verifies each transfer's two BPs separately; consensus.md §7's 0.4 s budget assumed per-block batch_verify) — collect VerificationTuples across all txs and batch once per curve | aegis-node proof.rs/chain.rs | Before testnet load; the tuples API already supports it |
| `produce_next` does not pre-verify proofs in `ProofMode::Real` (a producer can build a block its own `try_extend` rejects); dev producer uses empty bodies so latent — add a self-check when the mempool lands | aegis-node chain.rs | P5 mempool |
| Wire redundancy: `note_cm`/nullifiers appear both as wire fields and inside proof bytes (~130 B/tx); S4 binds them by equality — dedupe at parameter freeze if tx size matters | aegis-node tx.rs/proof.rs | Parameter freeze |
| Single-thread + memory-footprint proving bench (low-end devices) | g15-proving-spike.md caveats | During G2 |
| Batched proof verification wired into block pipeline (not per-tx) | consensus.md §7, spike | G2 node build |
| External review of W1 crypto glue (unaudited research base) | engineering §2b, security gates | Before any TVL beyond dust |
| PegMint objectivity: Ergo-SPV-in-consensus design | engineering §3, security §7 | G2.5 (dogfood may run declared operator-mode under caps) |
| Chain digest transition validation (hard with rollbacks) | GAPS should-fix | Document threat if still deferred at G3 |
| Final wire point encoding: ark-canonical compressed (33 B, current) vs SEC1 | consensus.md §5a, G2-P1 | Parameter freeze; chain-id-breaking |
| Memo size (drives `NOTE_CT_BYTES = 152` provisional) | aegis-spec consts, note-protocol §9 | Wallet UX (P4) |
| ~~`reward_claim` 32→33~~ **DONE S5b**: resized; genesis id now `e369d3c9…0cbeb495` (chain-id-breaking, applied) | header.rs | — |
| ~~`RewardMode::DevStub` retire~~ **DONE S5b**: `Real { coinbase_cm }` mints a coinbase note (MintProof-bound value, appended-last leaf, exact rollback). Residuals below | state.rs, consensus.md §5a | — |
| Coinbase note **wire serialization** — `Block.coinbase` is in-memory only (`Block` has no wire codec yet, only `BlockBody`) | block.rs | With block serialization (P5) |
| **Skip the 0-value coinbase leaf** (S5b review L1): a block whose reward is 0 (idle chain, empty pot) still mints a value-0 note, so `cm_leaves` grows every block regardless of activity — compounds the O(n) per-block tree rebuild. Fix: when `expected_coinbase_value == 0`, emit `coinbase = None` (sentinel reward_claim, no leaf, no draw) on BOTH produce and verify. Small consensus-behavior change → own reviewed slice. | state.rs/chain.rs, S5b review | Before a long-running/idle testnet |
| S5b review verdict (2026-07-12): mint-side wiring **SOUND** — no inflation/theft/panic/produce-verify-divergence across 7 categories. Value conservation holds by construction (draw == bound note value); x=0-off-curve secures the reward_claim sentinel. Residuals = L1 (above), L2 (negligible 0-value tag guard), L3 (golden id vector — **DONE**, `dev_genesis_id_is_pinned`) | — | — |
| Coinbase note **maturity** (120-block spend delay, C3) not enforced — a spend-side rule, moot while spending is blocked (N1) | consensus.md §5, params.md | With spend enablement (post-N1) |
| Coinbase **spending** blocked until nullifier fix (N1); coinbase notes are minted now but not yet spendable | spend.rs P0, n1-nullifier-fix-design.md | N1 |
| Constant-time SvdW / diversifier map (current map is variable-time, fine offline) | aegis-crypto h2c.rs, note-protocol §0 | Before runtime wallet-side `G_d` derivation (P4) |
| Key hierarchy (§2 sk→ak/nk/ivk/ovk) implementation | note-protocol §2 | P3/P4 — spend-auth mechanism fixed by circuit design first |
| Incremental Curve Tree append (state rebuilds O(n) from full leaf vector per block; reference has no append) | consensus.md §5a, aegis-crypto tree.rs | Testnet volume / block-apply time noticeable — before G3 |
| Tree/BP generator retagging to `"aegis:bp:v1:<i>"` NUMS bases (v1 uses reference derivation verbatim: PedersenGens::default + BulletproofGens chain + tai delta) | consensus.md §5a, note-protocol §0 | Parameter freeze; chain-id-breaking |
| ~~`TREE_GENS_LEN` sizing~~ **RESOLVED P3-S1**: `1<<13` (reference sizing for depth-4 circuits; roots unchanged — prefix chain) | aegis-crypto tree.rs | — |
| §0 aegis-tagged note Pedersen (`note::note_commitment`) vs circuit-path `consensus_note_commitment` (vector commit under tree params) — two commitment forms until freeze | aegis-crypto spend.rs, consensus.md §5a | Parameter freeze; pick one, chain-id-breaking |

## Adversarial-review fixes (g16-adversarial-review.md, 2026-07-12) — before G2 unless noted

| Item | Sev | Trigger |
|---|---|---|
| ~~D-A spend model~~ **RESOLVED** → Orchard-discipline nullifier (note-protocol §3) | — | External crypto review of exact algebraic form still gates TVL |
| ~~D-B/N2 leaf-index~~ **FIXED** → hidden (note-protocol §4) | — | Confirm in circuit design |
| ~~N1 nullifier collision~~ **RESOLVED** → `rho = consumed nf` = structural uniqueness | — | — |
| ~~N11 secret-index caveat~~ **RESOLVED** → structural rho removes the fragile select | — | — |
| **C1 single-commitment binding** (multi-R4 candidate = D3) | High | Before G2 MM path |
**All spec revisions applied 2026-07-12** (note-protocol / consensus / aegis-spec; full map in g16-adversarial-review.md triage). Remaining threads:

| Item | Sev | Trigger |
|---|---|---|
| Composed-circuit soundness certification | gate (TVL) | External crypto reviewer *checks* the now-fully-specified spec (nullifier form §3, generators §0 both pinned) — not an open design item |
| N6 coinbase-note mixing limit; N8 on-SC PegBurn value; N12 sk+H(tx)=0 wallet reject; C8 seeded pot floor | Low | Document / accept; revisit if they bite |
| `k_lag` (C2), retention-vs-maturity numbers (C3), seeded-pot-floor size (C8) | tuning | Set with dogfood data |

## Adversarial-review findings (2026-07-12, spend.rs/proof.rs) → external-review brief

| Finding | Sev | Status / trigger |
|---|---|---|
| **Nullifier point malleable** — exposed via hiding Pedersen commit, blinding free ⇒ unlimited nullifiers/note ⇒ double-spend | **P0 soundness** | **BLOCKS `ProofMode::Real`**; fix = plan slice N1 (bind `nf=x_inv·G` via in-circuit fixed-base mult) before S5b |
| Identity nullifier point panics `extract_x` | DoS | **FIXED `c8798f4`** (reject up front) |
| Spend inputs are NOT range-proved — soundness rests on every leaf being ≤2^64 at creation | Medium (load-bearing invariant) | Satisfied today: transfer outputs are range-proved and `mint` pins value to a `u64`; **keep it true for every future mint** (PegMint) and state it in the review brief |
| Ownership binding rests on `delta ⊥ {B, B_blinding}` (NUMS, inherited from curve-trees) — now load-bearing for spend authority via the tag→C* "delta as sign-breaker" argument | Low (assumption) | Put in the external-review brief explicitly |
| Wire `epk`/`ct`/`out_ct` unbound to the proof (only `note_cm` is) — a relayer can swap ciphertexts (griefing/receiver-detection), not inflation | Low | §5 OVK/note-encryption binding (P4/S6) |
| Mint (S5a) is **sound** (2nd review, 2026-07-12) — no inflation, value pinned to a public `u64`, minted cm == spendable leaf, transcript matched, identity-DoS fix confirmed complete. Residual: (a) S5b should reject `cm.is_zero()` coinbase notes (unspendable, pot-funded); (b) the no-range-proof safety is load-bearing on `value: u64` — a future field-valued mint needs a 64-bit range proof | Low | S5b / any new mint path |

## N1 nullifier — CLOSED, residuals

| Item | Status / trigger |
|---|---|
| **N1 P0 (nullifier malleability) — CLOSED** `fe6f205`: `nf = Poseidon(nk+rho)`, reviewed MERGE-clean, gate green | done |
| Poseidon-over-`F_p` parameter/round-count sign-off (t=3,R_F=8,R_P=56,α=5) | **external review** (in `external-review-brief.md`) — before TVL |
| Delete the SUPERSEDED inverse-tag code (`nullifier::{nullifier,nullifier_point,extract_x}`, `keynote::{tag_and_nullifier,note_tag}`) + their orphaned tests + the `nullifier_vector` oracle entry — currently marked SUPERSEDED (footgun mitigated, not removed) | Cleanup pass (ripples into test-vectors) |
| Stale "point/inverse-tag nullifier" wording in `TransferProof`/`nullifiers()` doc comments (now Poseidon) | With the deletion pass |
| Enable `ProofMode::Real` end-to-end | After Poseidon-param + delta-NUMS external sign-offs |

## G2.5 PegMint — built vs follow-on

| Item | Status / trigger |
|---|---|
| **Ergo-SPV objectivity steps 1–4 — BUILT** (`aegis-node::pegmint::verify_ergo_chain`): reuses `is_valid` (PoW+interlinks) + `verify_pow_solution`, adds anchor-equality + `N_mint` depth + absolute suffix-work; policy unit-tested; testnet anchor `5b1827ca…` pinned from live node | done |
| **Absolute suffix-work threshold** (`ErgoAnchor::work_floor`) — Aegis-authored policy; `is_valid`/`is_better_than` are only RELATIVE | **external sign-off** before value |
| **e2e `verify_ergo_chain` against a real full NiPoPoW proof — CLOSED (2026-07-13, cbf8092).** `aegis-node/tests/pegmint_real_proof_e2e.rs` runs the VERBATIM Scala-testnet `GET /nipopow/proof/6/10` capture (`test-vectors/testnet/nipopow/proof_m6_k10.json`, tip 442825, continuous=true — the route serves continuous unconditionally) through every `is_valid` sub-check individually (ALL PASS), the static path (ACCEPT vs pinned testnet anchor), a tamper-negative, AND the comparative path with a real dense checkpoint-rooted follower (ACCEPT; P1-A tip-not-in-view + P1-B deferral pinned). JSON→binary decode = `ergo_rest_json::decode_scala_nipopow_proof`/`decode_nipopow_proof_json`, byte-identity-oracled vs the Scala wire fixture. Cross-check nit: Rust node's served genesis `size` 283 vs Scala 284 (derived field, decoders ignore) — REST-parity nit only. | CLOSED |
| **PegMint steps 5–9** (tx-in-block, box-in-tx, receipt well-formedness, `boxId` used-set, emit `PegMintEffect`) — the mint side reuses S5a `MintProof` + `rho_pegmint` | Next G2.5 slice |
| `ErgoAnchor` + `ergo_*_anchor()` should move from `aegis-node::pegmint` to `aegis-spec` (consensus surface) + a real mainnet anchor | Parameter freeze; chain-id-breaking |
| `ergo_testnet_anchor().work_floor = 1` is a placeholder | Set with the absolute-work sign-off |

## G2.5 PegMint objectivity engine (`10d1f6e`) — review residuals

| Item | Sev | Trigger |
|---|---|---|
| **Objectivity WORK-POLICY — IMPLEMENTED + ADVERSARIALLY REVIEWED (2026-07-13, aa335a1 + review fixes a15d604; verdict SOUND-WITH-FIXES, both P1s applied): `pegmint::verify_ergo_chain_comparative` → `ComparativeAnchor`.** Build-time refinement (g25 §2b note): dense-vs-sparse `best_arg` comparison INVALID (rejects honest empty-prefix proofs) → **settled-membership** is the exact evaluation for the dense gap-free follower. Review pinned two contracts: **(P1-A)** the suffix above `H_ref` is NOT objectified — the accepted result now exposes ONLY `{h_ref, settled_view}` (no suffix `tip_id`), and steps 5–9 MUST bind both inclusion headers through the settled view; peg-in security above `H_ref` stays the `N_mint`-PoW/`V_cap` assumption. **(P1-B)** `NotCaughtUp` = deferral (wait + re-evaluate), never block-invalid — canonical verdict is comparative-once-caught-up, time-invariant, re-syncer-reproducible; static floor = explicitly NON-CANONICAL bootstrap. (P2 sub-root trust documented at code site.) Tested vs real mainnet headers incl. the P1-A contract pin. REMAINING before value: live feed transport, steps 5–9 (must consume `settled_view`), §2b.iii param sign-off (`N_mint` reorg margin + bootstrap floor). Full-proof e2e CLOSED 2026-07-13 (cbf8092) — both paths exercised on a real proof. | done (reviewed + e2e) | steps 5–9 + external param sign-off |
| **Ergo header-follower — STATE MACHINE BUILT (`aegis-node::ergo_follow::Follower`, 2026-07-12).** Pure, deterministic, PoW-gated (`verify_pow_solution`, stand-alone) fork-choice over Ergo headers: per-header work `decode_compact_bits(n_bits)`, heaviest-cumulative-work tip, reorg switch, and the settled-reference accessor `settled_reference() -> Option<SettledRef>` (id + height + cumulative_work at `tip−N_mint`) that §2b consumes. Tested vs REAL mainnet vectors — consecutive v1 chain (`headers_1_10`, Autolykos-v1 PoW) + consecutive v2 chain (`headers_1761792_1761795`, Autolykos-v2 PoW) + reorg-depth + settled-ref. Poller decoupled behind a `HeaderSource` trait (`poll::drive` + in-memory `VecHeaderSource`, exercised). **LIVE-FEED GAP (honest):** no pure-Rust REST source — the Ergo node returns headers as JSON but `ergo-ser` exposes only a *bytes* decoder (`read_header`); the repo's own vectors are produced via a Scala re-serializer (`extract_headers_batch.sh`). A live follower needs a JSON→`Header` decoder in `ergo-ser` (shared with C2 merge-mining) — the documented next step. NOT wired to pegmint/consensus yet. | state machine done | JSON→Header decoder (or P2P header source) for live follow |
| **Follower `headers` map is unbounded** (review 2026-07-12) — `ergo_follow::Follower` keeps every header of every branch forever; a long-running live follower grows without bound and never prunes below the settled reference. Not a soundness issue (fork-choice/settled-ref stay correct), a memory residual. Fix: prune branches/headers below `tip − N_mint − reorg_margin` once settled. | Med (memory) | Before long-running live follow |
| **`apply_verified_header` hardened to private** (review 2026-07-12) — it bypasses the PoW gate, so it was made non-`pub` (the fork had exposed it); tests reach it as a child module. No open item; noted so a future re-export is a deliberate, gated decision. | done | — |
| Pin `diff: DifficultyParams` per-network (not caller-chosen — a wrong/permissive config weakens the difficulty check) | Med | With the work-policy fix |
| Assert `genesis.height == anchor.height` (defense-in-depth; currently relies on `is_valid`/heights) | Low | With the fix |
| Full-NiPoPoW-proof e2e test through `verify_ergo_chain` — **CLOSED (2026-07-13, cbf8092; see the e2e row above)**: JSON→binary decode built + real continuous proof vector committed + both paths exercised | CLOSED | — |
| Move `ErgoAnchor`/`diff` to `aegis-spec` + a real MAINNET anchor (testnet `5b1827ca…` pinned) | — | Parameter freeze |
| PegMint steps 5–9 — mint side reuses S5a. **Refined (peg.md §3.1, 2026-07-12): binds the CONSOLIDATION tx (receipt spent → PegVault = the single-spend commit-point), NOT the lock. Receipt content read from the lock-tx output box, cross-checked by boxId to the consolidation tx's spent input → TWO inclusion proofs; `N_mint` depth on the consolidation. Exact two-inclusion schema = pass-3 design point.** | — | Peg-in completion |

## Peg-out ErgoScript contracts (W3 — pass 1 done, under review)

| Item | Sev | Trigger |
|---|---|---|
| **Contracts pass 1 (2026-07-12):** `contracts/DESIGN.md` + `{PegVault,DepositReceipt,DoubleRedeem}.es` — all COMPILE (repo Rust ErgoScript compiler, tree v3). Gitignored (mirror-persisted, not committed). | — | — |
| ~~**MUST-FIX before ANY value — receipt-USE SIPHON**~~ **✅ RESOLVED (pass 2, in current `PegVault.es`; reviewed):** fixed exactly as prescribed — PegVault sums the USE of all consumed receipt inputs (pinned by `RECEIPT_SCRIPT_HASH`) and requires `vaultOut == vaultIn + receiptSum + feeSum`. The eager-ValDef testnet redeploy (`f2b8d9d6…` @443688) exercised this sum-accounting live. *(Original finding: DepositReceipt merge only checked OUTPUTS(0)=vault + PegVault only `vaultOut ≥ vaultIn` → conservation routed receipt USE to an attacker output.)* | ~~theft/I1~~ **fixed** | ~~Pass 2~~ done |
| Zero-fee peg-out revenue leak (review): `payoutOk` allows `paidOut==n` → the peg-out fee backing the emission box can be skipped (revenue only, no principal loss) — add a fee-floor | low | Pass 2 |
| ~~Refund-before-mint race~~ **pass 2 added `R8 ≥ creation+N_mint+margin` — but the pass-2 review found this ENABLES a WORSE bug (below)** | — | — |
| ~~**MUST-RESOLVE before ANY value — refund↔mint DOUBLE-CLAIM**~~ **✅ RESOLVED in design (peg.md §3.1, "consolidation is the mint commit-point"; adversarially reviewed):** the SC mints against the **consolidation** tx (which *consumes* the receipt box), not the lock — so by Ergo single-spend a consolidated receipt can never also be refunded (minted ⟹ consolidated ⟹ box gone ⟹ un-refundable; refunded ⟹ never consolidated ⟹ never minted). Closes the double-claim with no `V_cap`-strong attester. *(Original finding: refund-floor forced MINT-then-refund ordering; a depositor could front-run the permissionless consolidation → refund after being minted → keep the note AND reclaim USE → inflation.)* | ~~inflation~~ **fixed** | ~~design task~~ done |
| Extra-token siphon (#3, low/defense-in-depth): add `vaultOut.tokens.size==2` | low | Pass 2 |
| ~~Positional/index attacks (#2)~~ **REFUTED as theft** (review): identity is correctly NFT/script-hash-pinned; reordering fails validation = liveness/griefing not theft. Subsumed by the #1 fix. | — | — |
| DoubleRedeem.es reviewed **SOUND** (insert-once via NFT conservation; no stale-tree/skip bypass) | — | — |
| Deploy correctness (review): inject the `fromBase64("")` placeholders (USE id, vault/DoubleRedeem NFTs, intent hash); create DoubleRedeem R4 AvlTree with the insert flag — else unspendable (griefing, not theft) | deploy | Testnet deploy |
| **v1-acceptable under `V_cap` (NOT bugs, deferred by design):** C1 burn authenticity rests on the trusted miner-posted SideChainState tip (needs U1-strong attesters/SPV for trust-min); I2 no-double-mint + refund-never-minted interlock are cross-chain (aegis-node used-set must reject minting a refunded/redeemed boxId); I1 global reserve is an ops metric + per-tx preservation, not a single-box invariant | design | U1-strong / SPV before value beyond `V_cap` |
| **Pass 2 contracts:** `UnlockIntent.es`, `FeePot.es`, Consolidator path (+ the sum-accounting fix) + GAPS must-fix adaptations (SideChainState dataInput validation, AVL digest slice 0..32 vs 1..33, double-unlock NFT ids, `sc_dest` R4 mint assignment) | — | Peg-out completion |

## Research (no design commitment)

| Item | Source | Note |
|---|---|---|
| Hidden `%`-fee with pot accounting | engineering §4, `notes/archive/fee-privacy-alternatives.md` | Likely never worth it — edge-`%` + flat interior achieves the goal |
| Private fee markets / encrypted mempools | fee-privacy-alternatives | Only relevant if fee visibility to miners ever becomes a leak that matters |
| L1 shielded-pool descope | engineering §5 | Standing fallback if the chain proves too heavy solo |

## Standing non-claims

- "Trust-minimized bridge" — not claimable in v1 (security.md §1); needs S3-class.
- Wallet warnings for R1-T transparency/sweep deadlines (M7 extension) — required **with** R1-T, not before.
