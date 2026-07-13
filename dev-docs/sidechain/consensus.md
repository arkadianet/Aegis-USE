# Aegis — consensus specification (draft for G1)

**Date:** 2026-07-12  
**Status:** decided (design stage) — the specs engineering.md §3 required before `aegis-node`. Numbers here are implementation targets; `params.md` wins on conflict.

---

## 1. PoW binding — decided

**Every Autolykos v2 attempt that meets the (easier) SC target is an Aegis block**, provided the attempted Ergo work commits to the Aegis header. Binding direction is parent→child (the work commits to the SC block), because the reverse (SC header quoting the Ergo msg) lets one solution back arbitrarily many SC blocks — attack D3.

**Commitment channel (v1): a commitment transaction via `POST /mining/candidateWithTxs`** — the channel Ergo's design already provides for merge-mined sidechains (kushti, `sigmachains.md`: *"current node API would be enough… a merge mining client would use `/mining/candidateWithTxs` to include sidechain block data into mainchain transactions"*; mechanism in the ErgoHack whitepaper §2). The sidecar builds a tx whose output carries the 32-byte Aegis header id (`R4`) — **ideally the `SideChainState` update tx itself**, so when the miner also wins Ergo, the same tx lands on-chain and doubles as the anchor. The candidate's `txRoot` commits to the tx, so every hash attempt commits to exactly one Aegis block.

**Miner compatibility (verified 2026-07-12):**

| Node serving the miner | Status |
|---|---|
| Stock Scala | **Works today** — `candidateWithTxs` in `MiningApiRoute.scala:48`; no Scala PR needed |
| Our Rust `ergo-node` | **REST-parity gap**: the Scala-compat `/mining/*` module serves only candidate/solution/rewardAddress/rewardPublicKey (`ergo-api/src/mining.rs`); v1-native route exists but is stubbed (`v1/operator/mining.rs:305`). One `NodeMining::candidate_with_txs` seam feeds both surfaces — W4 item, and a parity fix worth landing regardless of Aegis |

Per SC tip change (~15 s) the sidecar re-posts `candidateWithTxs` with the rebuilt commitment tx (new `R4`); at most one such tx ever confirms per Ergo block, and only when the miner wins — where its fee buys the anchor anyway.

**Commitment-UTXO lineage (C6 — avoids the on-win stall).** The sidecar must **not** re-spend one fixed wallet input each round: winning an Ergo block consumes it, invalidating every subsequent candidate until re-chained → Aegis production stalls exactly at a solo operator's win. Instead the sidecar maintains a **dedicated single-purpose commitment UTXO** and, on each rebuild, spends the *current* commitment box to a *new* one (self-chain), so the lineage survives an Ergo win by simply continuing from the win's output box. Only the latest is ever posted; superseded ones never broadcast (no mempool conflict).

**Who runs and stores what** ("Scala can merge-mine" = the miner's *Ergo* node may be Scala — every merge-miner still runs `aegis-node`, Namecoin-style):

| Process | Runs where | Holds | Sees of the other chain |
|---|---|---|---|
| Ergo node (Scala or ours) | every miner + operator | Ergo chain, peg contracts | one 32-byte register value in an ordinary tx |
| `aegis-node` (only impl) | every miner, operator, full-wallet users — own P2P network | full Aegis ledger: blocks, tree, nullifiers, pot | Ergo headers/receipts it needs for PegMint (G2.5) |
| `aegis-mm` sidecar | every miner | nothing (stateless glue) | both APIs |

**Aegis PoW witness** (carried by the SC block, since sub-Ergo-target candidates never appear on Ergo):

```text
ergo_candidate_header_bytes   (the unpublished candidate, full)
commitment_tx_bytes            (tx whose output R4 = sc_header_id)
tx_merkle_path                 (tx id → candidate txRoot)
autolykos_solution             (n, pk, w, d as applicable to v2)
```

Validity (revised per review C1/C2): `autolykos_verify(candidate, solution)` meets `sc_nbits` **and**:

1. **Exactly one commitment per candidate (C1 — closes the D3 re-opening).** The candidate must carry **exactly one** `R4`-bearing output at the designated commitment-contract address, and that `R4` must equal this block's header id. One solution then backs exactly one Aegis block; a candidate with zero or ≥2 commitment outputs is an invalid witness. (Without this, one candidate could carry many `R4`s → one solution backing N equivocating same-height blocks.)
2. **Candidate height pinned to the live Ergo tip (C2).** The candidate header `height` must lie in `[ergo_tip − k_lag, ergo_tip + 1]` (`k_lag` provisional 6), so an attacker cannot choose a low height for the smallest Autolykos-v2 element count and a per-hash cost edge over honest MM. `aegis-node` follows Ergo header height for this (light follow, not full Ergo validation).

**Deferred alternative (v2 optimization):** an extension-field commitment (2-byte key → 32-byte id) gives a ~100 B witness instead of ~1–2 KB and needs no wallet dust. Verified stock-consensus-legal (ported rules 400/405/406 cap size/duplicates but never reject unknown keys) — but no candidate API on either node injects custom extension fields today, so it would need node changes on both sides. Not v1.

## 2. Header (logical layout, v1)

| Field | Size | Notes |
|---|---|---|
| `version` | 1 | starts at 1 |
| `prev_id` | 32 | Blake2b-256 of parent core header |
| `height` | 8 | u64 |
| `timestamp_ms` | 8 | u64, rules §4 |
| `tx_root` | 32 | Merkle root of tx ids |
| `cm_tree_root` | 32 | Curve Tree root after applying this block |
| `nullifier_digest` | 32 | digest of nullifier set after this block |
| `pot_balance` | 8 | emission box, base units, after this block |
| `sc_nbits` | 4 | compact difficulty (reuse ergo-primitives encoding) |
| `reward_claim` | 33 | coinbase note commitment (compressed point), or all-zero sentinel for genesis/no-coinbase (S5b) |

**Header id** = Blake2b-256 over the serialized core fields (PoW witness excluded — it authenticates the id via the extension field, it is not part of it). Serialization via `ergo-ser` primitives.

## 3. Difficulty (DAA)

**LWMA** (zawy12 LWMA-1) over a window of **N = 90** blocks, target 15 s:

- next_target ∝ weighted mean of last-90 solve times (weights 1..90, newest heaviest)
- per-recalc clamp: target may move at most **×4 / ÷4** per window-slide step
- solve times clamped to `[-6×T, 6×T]` before weighting (timestamp-game damping)
- genesis + first 90 blocks: fixed `min_difficulty` per network. **`aegis` mainnet `min_difficulty` must be non-trivial (C7)** — set from an estimate of available honest MM hashrate, so an attacker can't cheaply pre-mine a long alternate genesis-anchored chain during the bootstrap window; optionally pin a signed checkpoint over the first window. `aegis-dev` stays trivially low.

Chosen over Ergo's epoch scheme because SC hashrate will be tiny and lumpy (one miner joining/leaving is a step function); LWMA re-targets every block.

## 4. Timestamps

- strictly greater than **median of last 11** block timestamps (MTP-11)
- at most **60 s** in the future of validator wall clock
- solve-time clamps in the DAA absorb residual gaming

## 5. Fork choice & reorg semantics

- **Most cumulative SC work** wins (sum of per-block difficulty). **Ties (common — equal-length forks get identical LWMA difficulty) break by first-seen only (C4)**, NOT by header id: a header-id tiebreak includes miner-grindable fields (`reward_claim` blinding, `timestamp`), letting a miner grind to win contested tips and farm the coinbase. First-seen is per-node and ungrindable; a node never re-orgs across an exact work tie.
- Commitment tree, nullifier set, pot, and peg bookkeeping are **versioned per block**; rollback must restore all four exactly (attack B2). Retention window: **≥ 240 blocks** (2×M) of undo data; deeper reorgs require resync from a snapshot.
- No finality gadget in v1. Exit safety does not depend on SC finality — that is `M`/`T_delay`'s job.
- **User-facing finality (C3).** Node rollback is clean to the full retention depth (240), but *off-chain acceptance* (goods shipped, USE released) is only as safe as the depth an actor waits. So a coinbase note matures at 120 but is reorg-eligible to 240; **on-SC finality for acceptance is declared at the retention depth (240 ≈ 60 min), not at coinbase maturity (120).** Peg-out is separately protected by `M` + `T_delay`. Wallets/merchants must not treat 120-deep as final for irreversible off-chain action.

### 5a. State digests & pot update (pinned with G2-P1 code)

- **Nullifier digest** is a hash chain, not a set digest:
  `digest_h = blake2b256(digest_{h-1} ‖ nf_0 ‖ nf_1 ‖ …)` over the block's
  nullifiers in tx-then-slot order; an empty block leaves it unchanged;
  genesis value is the pinned `EMPTY_NULLIFIER_DIGEST` constant. A chain
  digest commits to insertion history — equivalent to a set commitment for
  consensus (deterministic given blocks) and O(1) to maintain/roll back.
- **Pot update order (per block):** `pot += n_txs × sc_tx_fee` (credit
  first), then `coinbase = coinbase_reward(pot, n_txs)` is drawn. Credit-
  then-draw means the pot can never go negative and a block's own fees can
  fund its inclusion bonus.
- **Coinbase note (pinned with G2-P3 S5b).** A block either carries a
  coinbase `MintProof` (`RewardMode::Real`) or none (`RewardMode::DevStub`,
  draw 0). Under `Real`: the reward is
  `expected_coinbase_value(pre_pot, n_txs) = coinbase_reward(pre_pot + n_txs×sc_tx_fee, n_txs)`
  (single source of truth shared by validation and state), the coinbase
  **note** is minted as a real leaf appended **after** the transfer output
  leaves (fixed order), its value bound to the public reward by the mint
  proof (`verify_mint(reward, proof)`; no inflation), and the header's
  `reward_claim` (now a **33-byte** compressed cm) must equal the coinbase
  note's commitment. A `cm == identity` coinbase is rejected (unspendable,
  pot-funded). No-coinbase blocks must carry the all-zero `reward_claim`
  sentinel. Rollback restores the coinbase leaf + pot exactly (the leaf
  count snapshot already covers it). **Chain-id-breaking:** `reward_claim`
  32→33 changed the genesis id to
  `e369d3c93e403ba39cde560d115f8eb4664f8b10ae8a80a05a1d76730cbeb495`.
  **Spending** a coinbase note is blocked until the nullifier fix (N1);
  coinbase **maturity** (120-block spend delay, C3) is a spend-side rule,
  deferred with spending. Coinbase wire serialization lands with block
  serialization (P5) — `Block.coinbase` is in-memory for now.
- **Wire encodings (provisional until parameter freeze):** nullifiers are
  **32-byte big-endian x-coordinates** (Orchard-style `Extract` — see
  note-protocol §3; sign-invariant, so no canonical-encoding rule is
  needed); note commitments travel as 33-byte ark-canonical compressed
  points; `tx_root` of an empty body is the pinned `EMPTY_TX_ROOT`
  constant, else the ergo-crypto merkle root over tx ids; ct/out_ct sizes
  are the aegis-spec constants (152/80, provisional pending memo size).
- **Commitment-tree root (pinned with G2-P2).** Tree parameters:
  **L = 256, M = 1, depth = 4** (capacity 2^32 leaves — the g15 spike
  config; a depth-4 root is an even-curve point). Every block's output
  `note_cm`s are strictly decoded and appended as leaves in tx-then-slot
  order; the header commits
  `cm_tree_root = blake2b256("aegis:cm-root:v1" ‖ compressed root point)`.
  The **empty leaf set maps to the pinned sentinel constant** (the
  reference tree cannot represent an empty set), so genesis is unchanged.
  Tree/Pedersen/delta generators are the vendored reference's own
  deterministic derivation (`PedersenGens::default`, `BulletproofGens`
  chain, `delta = try-and-increment("curve_trees_delta")`), adopted
  verbatim so the audited base stays the byte oracle; retagging to
  `"aegis:bp:v1"` NUMS bases is a freeze-time, chain-id-breaking decision
  (DEFERRED). The tree is rebuilt from the full leaf vector per block —
  O(n) engineering debt (DEFERRED: incremental append).
- **Spend proof (G2-P3, S1+S2 done).** `aegis-crypto::spend` proves
  2-in/2-out transfers over the consensus tree: hidden-index membership +
  64-bit output ranges + balance with **fee as a verifier-substituted
  constant** + **the §3 nullifier relation in-circuit** — each input's
  tag slot binds to a public rerandomized key commitment `C*`
  (single-level select-and-rerandomize at a public index), and the odd
  half opens `C*` → `x` and the revealed nullifier point (randomness-zero
  commitment) → `x_inv` with `x·x_inv = 1`. Consensus nullifiers = the
  x-extracts of the revealed points. Transcript domain `"aegis:spend:v1"`,
  gens length `1<<13`, proof fits `MAX_PROOF_BYTES`. Circuit-path
  commitments (note/key/tag/nf) use the tree parameters' generators;
  **tags are delta-shifted: `tag = (C + Δ_odd).x`**; unification with the
  §0 aegis-tagged forms happens at freeze (DEFERRED). **Node verification
  (S4, done):** `ProofMode::Real` in `try_extend` verifies every transfer
  against the **parent-block anchor tree** before state mutation —
  deserialize, bind wire↔proof (output commitments == note_cm slots,
  x-extract nullifiers == wire nullifiers), then the Bulletproofs at the
  consensus fee; a block spending with no notes yet in the tree is
  `NoAnchor`. **Dummy inputs (§6, S3 decision):** a "dummy" is a
  self-owned zero-value note (a real tree member, value constrained 0) —
  no circuit or consensus change, uniformity is maximal, complexity is
  wallet-side (maintain a zero-note reserve). **Remaining gaps:** the
  dev producer still runs `DevStub` until an in-band mint (PegMint
  G2.5 / coinbase S5) can create the first notes; §2 spend-auth
  signature (S6). **⚠ `ProofMode::Real` is NOT yet sound** — adversarial
  review (2026-07-12) found the S2b nullifier point is malleable (hiding
  commit leaves the blinding free ⇒ unlimited nullifiers per note); the
  fix (bind `nf = x_inv·G` in-circuit) is plan slice N1 and gates any
  real deployment. A separate identity-nullifier DoS was fixed
  (`c8798f4`).

## 6. Genesis

Deterministic, no premine:

```text
version=1, prev_id=0x00…00, height=0, timestamp_ms=fixed per network,
tx_root=H(empty), cm_tree_root=EMPTY_TREE_ROOT (from crypto params, G1.6),
nullifier_digest=H(empty), pot_balance=0, sc_nbits=min_difficulty(network)
```

`EMPTY_TREE_ROOT` is the only crypto-dependent constant; G1 boots with a placeholder pinned by test, replaced when G1.6 fixes the tree parameters (L=256, D=4 default per the spike).

## 7. Block limits

- `max_block_bytes = 524_288` (512 KiB ≈ ~100 padded shielded txs at ~4–5 KiB)
- `max_block_txs = 128` (verify budget: ~128 × ~3 ms batched ≈ 0.4 s ≪ 15 s)
- mempool min relay fee = `sc_tx_fee` exactly (flat; no fee market in v1 — first-seen, FIFO)

## 8. Out of scope here

PegMint objectivity (Ergo-SPV-in-consensus) is its own design at **G2.5**; until then dev-chain PegMint is stubbed behind operator mode. Note protocol (commitments, nullifiers, encryption, padding) is **G1.6**.
