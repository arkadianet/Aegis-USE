# Hash-native spend circuit — engine core status & the monolith assembly

**Branch:** `feat/hash-native-payment-engine`. **Crate:** `engine/` (isolated
nested workspace over Plonky3 rev `4aed8fe`, BabyBear + Poseidon2 FRI — the exact
toolchain the client-cost spike measured). Testnet/devnet crypto pending full
external review, same gate as the current engine; nothing here touches `main`.

This is the crown-jewel rebuild's CORE. It pins every layout and demonstrates
every spend constraint class as a **verifying, sound** circuit. It does NOT yet
ship the single monolithic 2-in/2-out proof — that assembly is specified below.

## Pinned layouts (all chain-id-breaking; all REVIEW ITEMS)

- **Field / hash.** BabyBear (`p ≈ 2^31`), Poseidon2 `t=16`, `R_F=8` (4+4),
  `R_P=13`, S-box `x^7` — the canonical `Poseidon2BabyBear<16>`. The native
  permutation and the in-circuit AIR use the **same** constant tables (via
  `RoundConstants::try_from_layers` and the public `BABYBEAR_POSEIDON2_RC_16_*`
  arrays), so native and circuit agree by construction — no second, hand-copied
  parameter set to drift. Oracle-checked against Plonky3's own `Permutation` and
  `TruncatedPermutation`.
- **Digest = 8 limbs** (~248-bit): the note commitment, key, nullifier, and
  Merkle-node type.
- **Sponge.** Add-absorb, rate 8 / capacity 8; the capacity is seeded with a
  per-purpose domain tag (`DOMAIN_OWNER=0x0A01`, `DOMAIN_NULLIFIER=0x0A02`,
  `DOMAIN_COMMITMENT=0x0A03`) and the input length; input absorbed in
  component-aligned rate-8 blocks (one permutation each), first 8 lanes squeezed.
- **owner** `= H_OWNER(nk)` — `nk` is 8 limbs → 1 permutation. Hash-based key: no
  `nk·B`, no curve.
- **nf** `= H_NF(nk ‖ rho)` — 2 blocks → 2 permutations. The N1 scheme carried
  over, re-expressed over BabyBear (soundness re-argued below).
- **cm** `= H_CM(value_block ‖ owner ‖ rho ‖ r)` — 4 component-aligned blocks
  (`value_block = [v0..v3, 0×4]` — the amount's 4 LE 16-bit limbs — `owner`,
  `rho`, `r`) → 4 permutations. Commitment domain `0x0A13` (bumped from `0x0A03`
  when the value block became limbed).
- **Accumulator.** Binary Poseidon-Merkle, depth 32 (2^32 leaves), internal node
  `= truncate_8(perm(left ‖ right))` — matches Plonky3's own Merkle shape.
  Incremental/append-only with empty-subtree defaults. `EMPTY_LEAF = 0×8`.
- **value = full u64 as 4×16-bit LE limbs.** A single BabyBear element cannot
  hold a `u64`, and a naive limb recombination would wrap `p`. 16-bit limbs are
  byte-aligned to the ciphertext's `u64` LE wire (bijective, no second wire
  form), uniform (no special last limb), and keep balance carries in a 2-bit
  window. Conservation is limb-wise with an explicit signed carry chain
  (`in0_j + in1_j + c_j == out0_j + out1_j + fee_j + c_{j+1}·2^16`,
  `c_0 = c_4 = 0`, carries ∈ {-2..1} as 2 bits) — telescopes to integer
  equality; every term < 2^18 ≪ p so the field equations ARE the integer
  equations (mod-p wrap unsatisfiable). ALL five values' limbs are 16-bit
  range-checked in-circuit (outputs/fee mandatorily — they are created here;
  inputs as defense-in-depth on the cm-binding induction). Per-constraint
  attack notes in `balance_air.rs`.

This reproduces the spike's ~86-permutation budget exactly: `2·(1 owner + 4 cm +
2 nf + 32 merkle) + 2·(4 out cm) = 86`.

## What verifies today (real proofs, with negative tests)

| circuit | statement | negatives |
|---|---|---|
| `PermBindingAir` | `out == Poseidon2(in)` (public I/O) | tampered output rejected |
| `MerkleMembershipAir` | private leaf + depth-32 path folds to public root | wrong root rejected |
| `NullifierAir` | `nf == H_NF(nk‖rho)` (public `nk,rho,nf`) | tampered `nf`, tampered `nk` rejected |
| `BalanceAir` | limbed u64 `Σin==Σout+fee` (carry chain) + 16-bit limb ranges | imbalance/wrap-mod-p/non-canonical-limb rejected; inflating witness unbuildable |

**Measured** (depth-32 membership, this machine, `new_benchmark_high_arity`
FRI): prove **~115 ms**, verify **~5 ms**, proof **~0.19 MB**, 315 columns × 32
rows. Comfortably inside the spike's phone-class envelope.

Each constraint's soundness role ("why omitting it is an inflation/theft/
double-spend hole") is documented at its site: the S-box `reg==x^3` (else hash
forgery), the Merkle `bit∈{0,1}` (else path forgery via a non-boolean blend), the
sponge absorb-chaining (the defining sponge step), the overflow-free balance, and
the output range (else a field-wrap "negative" output inflates).

## The monolith — BUILT (`engine/src/spend/monolith.rs`, verifying)

A single uni-STARK proves a 2-in/2-out spend binding all sub-statements behind
one public root, with a **private** shared witness (no public `cm`, no leaf
index — so which notes were spent is hidden). **Measured** (depth 32, this
machine): prove **~251 ms**, verify **~41 ms**, proof **~1.33 MB**; 128 rows ×
2471 cols; 41 public values (`root ‖ nf0 ‖ nf1 ‖ cm_out0 ‖ cm_out1 ‖ fee`). This
matches the spike's ~1.3 MB / sub-second prediction.

**Layout — the "wide row".** Rather than a general microcode bus, each row
carries 8 always-valid Poseidon2 blocks, so a whole note's hashes (owner 1 + cm 4
+ nf 2) sit in one row and **every intra-note binding is a same-row column
equality**. Only the `cm → Merkle-leaf` hand-off and the Merkle chain cross rows
(adjacent next-row links); the five transfer amounts ride a 5-column constant
"value bus". A 7-flag **preprocessed** schedule (committed, transcript-bound —
trusted, not prover-controlled) marks each row's role:
`hash(in0) · merkle(in0)×32 · hash(in1) · merkle(in1)×32 · output · pad…`.

**Per-value binding (what forces each shared value to be one element):**
- `nk`: the owner hash (B0) and nullifier hash (B5) absorb the SAME columns
  (`B5.in == B0.in`) ⇒ the key proving ownership is the key deriving the nf.
- `owner`: cm absorbs `B0.out` (`B2.in − B1.out == B0.out`) ⇒ committed owner is
  exactly `H(nk)` — theft-resistance.
- `rho`: cm's and nf's rho are constrained equal (`B3.in − B2.out == B6.in −
  B5.out`) ⇒ the nf is built from the note's own rho.
- `cm`: opening output `B4.out` is handed to the first Merkle `child`
  (`cm_to_leaf`) ⇒ the note in the tree is the note opened; `cm` never public.
- `value`: cm's value block binds to the bus, which feeds conservation.
- `root`: each chain's last output binds to the one public root.
- `nf0 ≠ nf1`: a one-hot limb selector + inverse witness forbids the two inputs
  being the same note *inside* one proof (double-spend); the cross-tx case is the
  consensus nullifier set's.

**Adversarial tests (each REJECTED by the real verifier, release-mode):**
ownership key mismatch, committed-owner ≠ `H(nk)`, nullifier from a foreign rho,
membership of a different leaf (witness substitution), value inflation, wrong
root at verify; same-note double-spend is unbuildable; and a structural check
that no input `cm` / leaf index appears in the public values.

### The re-derivation soundness argument (nullifier — REVIEW ITEM)
The N1 property "one note ⇒ one nullifier" holds because in the monolith `nf`'s
inputs are the bus `nk` and `rho`, and both are pinned by the note: `rho` is a
`cm` input and `cm`'s membership is proven; `nk` is pinned by `owner = H(nk)`,
itself a `cm` input. So the prover cannot present a different `(nk,rho)` for a
given note. Unlike the retired `Poseidon(nk+rho)` there is no additive re-split.
What still needs review: the collision/preimage security of `H_NF` on the
concatenation (the bounded Poseidon2 parameter/round-count review item).

## Honest soundness gaps / external-review items
1. **Poseidon2 parameters** (`t=16, R_F=8, R_P=13, x^7`) — the round-count vs
   algebraic-attack review; carried from the spike as the one bounded item.
2. **FRI security** — `new_benchmark_high_arity` is ~113-bit *conjectured* /
   ~58-bit *proven*; production raises log_blowup / queries (still sub-second /
   ~MB). A parameter choice, not a design flaw.
3. **Domain-separation scheme** — the `DOMAIN_*` tags + length binding, and the
   choice NOT to domain-separate Merkle levels (leaf-vs-node / per-height).
4. ~~`AMOUNT_BITS=28`~~ **RESOLVED: full u64 amounts** (4×16-bit limbs + signed
   carry chain; see the balance section). Residual review: the carry-window
   argument ({-2..1}) and the input-limb-induction note.
5. **`EMPTY_LEAF`** nothing-up-my-sleeve value.
6. **Zero-knowledge — NOW IMPLEMENTED (hiding config).** See the dedicated
   section below. Residual: the hiding is *conjectured* (statistical, standard
   ZK-STARK model) and the masking-budget inequality is a pinned constraint.
7. **Monolith soundness items:** (a) the `nf0 ≠ nf1` one-hot/inverse in-circuit
   guard is best-effort — the authoritative double-spend defense is the consensus
   nullifier set (cross-tx); (b) the fixed transaction shape is exactly 2-in/2-out
   (dummy zero-value notes pad smaller transfers — the standard shielded-pool
   approach, but the padding/uniformity story wants review); (c) fee is a public
   input and is not itself range-checked here (assumed set by an honest wallet /
   bounded at consensus).

## Zero-knowledge (hiding) — leakage model + fix (`engine/src/config.rs`)

A uni-STARK is a **sound but not hiding** argument: for a *privacy* chain the
hiding is the product, not hardening. This is now addressed by a hiding config.

### Leakage model — what a PLAIN uni-STARK proof reveals (our config: rev
`4aed8fe`, BabyBear, Poseidon2 FRI, `TwoAdicFriPcs`, **no PCS blinding**)
The proof carries, for each of `k = 100` FRI query points, the **opened LDE rows**
of the committed trace (main + quotient) plus a few out-of-domain (OOD)
evaluations. These openings are **deterministic functions of the witness trace**:
- **Concrete total leak:** a *constant* trace column has a constant LDE, so it is
  revealed **verbatim by any single query**. The monolith's **value bus is
  constant across all 128 rows** ⇒ the transfer amounts leak directly. Low-degree
  columns leak similarly.
- **General recovery:** the trace polynomials have degree `< N = 128`; `k = 100`
  openings over a rate-1/2 code, plus the OOD point and the quotient relations,
  over-determine them — an adversary reconstructs the witness columns (`nk`,
  `rho`, values, the Merkle path) and thus **which note was spent**.
- **Verdict:** leakage is effectively **total** for a privacy adversary. A
  non-hiding spend proof is NOT private — even though the *public values* hide the
  note, the *proof body* does not. (This is empirically confirmed: the non-hiding
  proof is byte-deterministic in the witness — `hiding_is_randomized…` test.)

### The fix — Plonky3's ZK-STARK masking (no hand-rolled crypto)
Our rev ships the standard construction; we turn it on (`HidingEngineConfig`):
- **Random trace interleaving** (ethSTARK, [ePrint 2021/582]): `HidingFriPcs`
  interleaves the committed matrix with an equal number of **uniformly random
  rows** and adds `NUM_RANDOM_CODEWORDS` random columns, giving each column
  polynomial ~`h` random degrees of freedom.
- **Random-codeword + quotient masking** ([ePrint 2024/1037] §4.2): the batched
  FRI codeword is blinded by appended random codewords (their openings travel
  beside the proof, hidden from the verifier's statement); quotient chunks are
  masked by `v_H·t_i` with a Σ-correcting last chunk.
- **Salted Merkle leaves** (`MerkleTreeHidingMmcs`, `SALT_ELEMS = 4`): each leaf
  is salted, so the commitment itself is hiding (no dictionary attack on
  low-entropy rows).
- **`FriParameters::new_benchmark_zk`**: `log_blowup = 2`, 100 queries, 16-bit
  query PoW (conjectured soundness `2·100 + 16 = 216` bits, ethSTARK conjecture).
- Masks + salts from a **CSPRNG (ChaCha20)**, OS-seeded at the client
  (`hiding_config()`). **The masks ARE the privacy** — a weak/predictable seed
  breaks hiding entirely.

### Why the k queries reveal nothing (the argument, not vibes)
Masking budget: `k` queries + O(1) OOD points must be **≤ the number of random
rows** added (= the trace height `h = 128`). The interleaved random rows give each
committed column `h` independent uniform coefficients off the constraint-enforced
trace domain; any ≤ `h` evaluations *off* that domain are a full-rank linear image
of ≥ that many independent uniform masks, hence **jointly uniform and
statistically independent of the witness**. `100 + few < 128` ⇒ satisfied, so the
queried openings are uniform regardless of the witness. Verification still passes
because the masks live off the enforced domain and the codeword masks integrate to
zero via the Σ-correction — they cancel in the constraint/FRI relations.

### Adversarial verification (tests, all green)
- `hiding_spend_verifies` — a hiding 2-in/2-out proof verifies (fixed-seed
  verifier vk = the settlement-guest path).
- `hiding_is_randomized_same_statement_differs` — same witness + same public
  values, two mask seeds ⇒ **different proofs and openings**; the non-hiding
  config is **byte-identical** (deterministic). This is the observable signature
  that the masking injects real, witness-independent randomness.

### Cost (measured, this machine)
| | non-hiding | **hiding** |
|---|--:|--:|
| client prove | 251 ms | **754 ms** (~3×, from log_blowup 1→2) |
| verify (native) | 41 ms | **52 ms** |
| proof size | 1.33 MB | **1.46 MB** (+10%) |
| settlement guest (RISC0, in-field) | 963 M cycles | **1.045 B cycles** (+8.5%) |

Phone-class prove extrapolation ~**1.5–4 s** — **above** the ~1 s target; the
narrow-trace lever (the same one that cheapens settlement) is the mitigation and
is the recommended next optimization. The settlement guest verifies the hiding
proof in-field at **+8.5%** (measured: `aegis-settlement-guest-spike` mode 2,
1209 vs 1127 segments) — privacy costs settlement almost nothing; the 963 M path
is not broken, it is superseded by a 1.045 B hiding path.

### Residual ZK review items
- Hiding is **conjectured** (statistical, standard ZK-STARK model), not proven.
- The masking-budget inequality (`queries + OOD ≤ random rows`) is **tight-ish**
  and pinned — a larger circuit / more queries needs more random rows.
- `NUM_RANDOM_CODEWORDS = 4`, `SALT_ELEMS = 4` adequacy.
- The mask CSPRNG **must** be OS-seeded in production; `hiding_config_for_verify`
  uses a fixed seed but is verify-only (the RNG is never drawn from in verify).
- The preprocessed vk is a **salted commitment to the PUBLIC schedule**, published
  once and used by both prover and verifier (a matched `(pd, vk)` pair).

[ePrint 2021/582]: https://eprint.iacr.org/2021/582
[ePrint 2024/1037]: https://eprint.iacr.org/2024/1037

## Address + note encryption (send-to-a-stranger) — `engine/src/{address,note_encryption}.rs`

**Mechanism decision: X25519 ECDH + ChaCha20-Poly1305 + HKDF-SHA256** (proven
crates: x25519-dalek, chacha20poly1305, hkdf, sha2). Rationale: encryption is
**off-circuit** — never proven by the spend STARK nor verified by the settlement
guest — so the engine's no-EC rule (about FRI-native *verification* cost) does
not apply; the dalek/RustCrypto stack is battle-tested and ciphertexts are small.
ML-KEM (option b) declined this pass: younger crates, ~+1 KB/output, and its
benefit (PQ confidentiality) protects *privacy*, not funds — an HNDL adversary
could someday read amounts/memos but spending still requires the hash-based
`nk`. The **versioned address** is the ML-KEM/hybrid upgrade hinge (REVIEW).

**Address (two components — a capability upgrade over the old engine):**
`owner = H(nk)` has no algebraic pk, so the address carries a separate
encryption key: `bech32m(hrp, version(1) ‖ owner(32) ‖ enc_pk(32))` (Bech32m =
the wallet's existing convention; strong checksum; strict decode: known version,
exact length, canonical limbs). Keys derive from ONE seed via HKDF-SHA256 with
independent info domains (`aegis:hn:kd:nk:v1`, `aegis:hn:kd:enc:v1`).
Consequence: `enc_sk` alone detects+decrypts (a viewing capability), `nk` spends
— the watch-only split the option-a engine documented as impossible.

**Ciphertext (pinned; 152 bytes per output, chain-id-breaking):**
`epk(32) ‖ ChaCha20Poly1305(K, nonce=0, aad=cm_bytes, value(8) ‖ rho(32) ‖ r(32) ‖ memo(32))`
with `K = HKDF-SHA256(shared ‖ epk ‖ enc_pk, info="aegis:hn:note-enc:v1")`,
all-zero DH rejected (non-contributory address). Zero nonce is safe: fresh esk
per output ⇒ single-use key. `aad = cm` binds the ciphertext to its output.

**Scanning:** trial-decrypt each new output; AEAD failure = not ours (cheap);
on success parse STRICTLY (canonical digest limbs; the value is a full u64 —
its 4×16 limb encoding is bijective by construction) and REQUIRE the
opening to recompute the on-chain `cm` under our OWN `owner` — unspendable
garbage is rejected. The recovered `(value, rho, r)` + `nk` is exactly the
monolith's `InputNote` witness.

**§6 uniformity invariant (carried, tested):** every output carries exactly
`NOTE_CT_BYTES = 152` ciphertext bytes via the identical code path — stranger
payment, change-to-self, zero-value dummy are byte-length-indistinguishable
(and change is found by the sender's own scanner).

**Deferred:** the sender-recovery slot (`out_ct`, OVK wrap of `K` — the old
engine's N7) — an additive second fixed slot, uniformity extends verbatim;
memo semantics; keystore-at-rest for the seed.

## Wallet orchestration — `engine/wallet` (`aegis-hn-wallet`)

The layer that turns the engine into something a user (and the e2e campaign)
drives. Crate layout: `keystore` (seed at rest), `circuit` (shared spend
proving/verifying keys), `wallet` (note store + scanner + selection + pay),
`chain` (the node boundary + an in-memory node).

- **Keystore**: the old engine's audited pattern ported verbatim —
  PBKDF2-HMAC-SHA256 (600k iters, cost stored in-blob) → AES-256-GCM over the
  32-byte seed, random per-file salt + nonce; wrong passphrase/tamper ⇒ `None`,
  never a silently-wrong seed. Proven crates only. The seed derives `nk` +
  `enc_sk` via the existing HKDF domains.
- **Watch-only split**: `ViewingKey = (enc_sk, owner)` detects + decrypts
  incoming notes; it holds no `nk`, so no nullifier or spend witness can be
  derived from it — spend authority is absent at the TYPE level.
- **Note store + scanner**: owned notes = decrypted openings + leaf index + cm
  + spent flag; incremental cursor (`outputs_since`); idempotent rescans (dedup
  by leaf index); spent-state refresh from the chain's nullifier set (catches
  spends by other instances of the same seed).
- **Selection (deterministic, documented)**: the two highest-value unspent
  notes, tie-broken by leaf index. The fixed 2-in shape means one spend
  consumes exactly two notes; zero/dust change notes organically serve as the
  second ("dummy") input later. Outputs are always exactly two (payment +
  change-to-self, change may be 0) — §6 uniformity holds by construction.
  Follow-ups: multi-tx consolidation; an in-circuit dummy-input flag.
- **Tx object**: `{ proof_bytes (hiding monolith), public_values (44 u32
  limbs), out_ciphertexts ([2 × 152 B]) }` — exactly what a node consumes.
- **Node boundary (`ChainView`)**: `current_root`, `authentication_path`,
  `nullifier_seen`, `outputs_since`, `output_count`. The in-memory chain and
  the coming aegis-node integration share this trait; the node accept path is
  `verify proof → anchor-root in window → no double-spend → append outputs +
  record nullifiers` (`InMemoryChain::submit`).
- **Root management (honest strategy)**: the tree advances between path fetch
  and node processing, so wallets always fetch a FRESH path at the current
  root and prove against that anchor; the node accepts any of the last
  `ROOT_WINDOW = 100` roots (Zcash-anchor style sliding window); staler
  anchors ⇒ re-fetch + re-prove. The engine's
  `build_spend_trace_with_paths(inputs, paths, root, …)` is the wallet-side
  entry (no whole-tree access needed).
- **e2e rehearsal (passing)**: three wallets, address-string-only payments
  A→B→C→A on the in-memory chain with real hiding proofs; change found by the
  senders' own scans; balances reconcile exactly (fees burn); a stale wallet
  instance's double-spend AND a replayed tx are rejected by the nullifier set;
  the watch-only key sees B's payments (800 + faucet 50) but cannot spend.

Deferred: keystore file format/serde + CLI, out_ct sender recovery, note-store
persistence, fee-to-miner accounting (fees burn in the rehearsal), in-circuit
dummy-input flag.

## aegis-node integration (single node, local) — `aegis-node/src/hn/`

The sidechain itself runs hash-native. A self-contained subsystem in aegis-node,
ALONGSIDE the existing Curve-Trees consensus (which stays the baseline); path
deps into the isolated `engine/` workspace pull Plonky3 into the node for
in-field proof verification (~52 ms/proof native).

- **`hn::state` (`HnState`)** mirrors the Curve-Trees `ShieldedState`: the
  Poseidon-Merkle tree + `cm_leaves` (for rebuild), the nullifier set, and the
  recent-roots window (`ROOT_WINDOW=100`). `apply_block`/`rollback` are EXACT
  inverses (validate-then-mutate; `HnBlockUndo` captures leaf count, added
  nullifiers, output count, height, and any evicted window root) — reorg-safe,
  tested `apply→rollback→apply = identity`.
- **Reorg strategy (documented)**: rollback truncates `cm_leaves` and rebuilds
  the tree from the prefix (the tree has no truncate — the rare reorg path is
  O(n), exactly the Curve-Trees choice); nullifiers/outputs/window roll back
  from the undo. The block header commits both `prev_root` (anchor) and
  `state_root` (tip after applying), so a light client verifies a state
  transition as *verify each proof + check the two roots*.
- **Tx validation (mempool AND block, `validate_tx`)**: verify the hiding proof
  against the published `SpendVk`; anchor root ∈ window; both nullifiers unseen
  on-chain OR pending (the mempool's pending-nullifier index rejects
  conflicting txs); exactly 2×152 B ciphertexts (§6 at consensus); canonical
  public-values shape. **Mempool DoS posture (honest)**: admission costs one
  ~52 ms proof verify — cheap for block validation, but a spam vector at scale;
  the standard defenses (a proof-carrying fee bond checked before verify, per-
  peer rate limits, verify-after-cheap-checks ordering) are a flagged follow-up.
- **Mint derivation (`hn::mint`)**: coinbase / (INERT) peg-in notes are
  DETERMINISTIC from `(dest, amount, unique id)`, domain-separated (`rho`/`r`
  from the id under distinct domains; a purpose tag separates coinbase from
  peg-in) — a miner cannot redirect value (dest is bound into `cm`) or double-
  mint (id on a used-set / one-per-block). A ciphertext is attached so the
  standard wallet scanner finds a mint like any output (§6 uniformity). Peg-in
  stays INERT (as on `main`) but its derivation exists.
- **Node boundary (`hn::chain::HnChain`)**: implements the wallet's `ChainView`
  (current_root / authentication_path / nullifier_seen / outputs_since /
  output_count) + `submit` (mempool) + `produce_block` (local production) over a
  **persisted block log** (`hn_blocks.log`, framed `len‖postcard(block)` — "the
  block sequence IS the state", mirroring `store.rs`). Restart = `open()` replays
  the log to rebuild state.
- **Published vk stability**: node + wallet share reproducible circuit keys
  (`SpendCircuit::deterministic(seed)`) so the vk survives restarts. ⚠ REVIEW:
  a fixed seed makes the hiding masks deterministic across instances — production
  must split the public preprocessed-salt (fixed → stable vk) from fresh per-
  proof masks (a coupled-RNG engine refinement).
- **Real-node e2e (passing)**: `aegis-node/tests/hn_e2e.rs` — coinbase/faucet
  mint → A pays B by address → B finds+spends → double-spend from a stale
  instance rejected at the REAL mempool → node restart (reload from disk) →
  wallet rescan recovers the exact balance → the reopened node accepts a fresh
  spend (stable vk). Balances reconcile exactly (fees burn).

### Primary-consensus promotion (economics, hardening, remote wallet)

- **RNG split (privacy must-fix)**: the deterministic-keys shortcut for a stable
  vk was replaced by a structural split — a FIXED internal salt for the PUBLIC
  preprocessed commitment (→ vk stable across instances/restarts) + FRESH OS
  masks per proof (the privacy). One constructor `SpendCircuit::new()`, no seed
  arg. Tested: two instances' vks cross-verify each other's proofs (⇒ identical)
  while two proofs of one statement differ (⇒ fresh masks).
- **Emission + fee-to-miner**: `produce_block` mints coinbase =
  `EMISSION_PER_BLOCK` (flat 50, documented; a real chain halves) + all mempool
  fees; fees go to the miner via the deterministic coinbase note (no burning).
  `fund()` is a genesis/faucet allocation (immediately spendable);
  `HnBlock.coinbase_is_reward` distinguishes mined vs genesis.
- **Coinbase maturity**: `OutputRecord` carries `height` + `is_coinbase`; the
  wallet won't select an immature coinbase note (`COINBASE_MATURITY`);
  `spendable_balance(tip)` excludes them. (A consensus-enforced maturity over
  HIDDEN inputs is a documented hard problem — wallet-side for now.)
- **Mempool hardening**: `validate_tx` is cheap-checks-first — shape, §6
  ciphertext sizes, the `MIN_FEE` floor (from public fee limbs), the anchor
  window, and the nullifier index all BEFORE the ~52 ms proof verify.
- **HTTP surface + remote wallet**: `hn::api::HnApiServer` exposes the
  `ChainView` reads (GET) + tx submit / mine (POST) on the node's minimalist
  std-`TcpListener` pattern; `hn::http_client::HttpChain` (reqwest blocking) is a
  remote `ChainView` a wallet drives with only its keys + a node URL. **Promoted
  e2e** (`hn_http_e2e.rs`): a REMOTE wallet over HTTP does the full flow
  (scan → pay by address → submit+mine → double-spend rejected → restart → rescan
  → fresh spend), plus the in-process e2e's emission/fee/maturity checks.

## Networked testnet cut (multi-node, merge-mined)

The hash-native subsystem now runs as a **networked, multi-node, merge-mined
testnet** (`hn_node` binary + `~/apps/aegis-testnet-hn/`).

- **Chain params, pinned (not scattered constants).** `hn::params::HnChainParams`
  centralizes the profile; `HnChainParams::testnet()` fixes: chain id
  `0x484E0001`, `ROOT_WINDOW` 100, coinbase maturity 5, `MIN_FEE` 1, emission 50
  (+fees), and the genesis allocation (2 × 500,000,000 to the faucet). The faucet
  key derives from the PUBLIC seed `aegis-hn-testnet-faucet-v1`
  (`hn::params::faucet_address()`) — anyone with the seed can spend it; it exists
  only to fund the e2e campaign. The old Curve-Trees testnet profile is untouched
  and still builds/runs.
- **P2P: HTTP block feed + mempool gossip (IBD from genesis).** The node's
  `ChainView` HTTP surface gained a peer feed: `GET /hn/v1/{blockcount,blocks?from=,
  mempool}` serve postcard-framed `Vec<HnBlock>` / `Vec<Tx>`. A follower's
  `HnChain::sync_from(peer)` pulls blocks `>= block_count` and applies them by
  **linear-extension fork-choice** (`ingest_block`: accept only a block that
  extends the local tip, dropping any landed mempool txs); `pull_mempool(peer)`
  gossips unconfirmed txs. IBD from genesis = `sync_from` starting at count 0.
- **Aux-PoW / hn-header binding (consensus surface — honest status).** Each
  `HnBlock` carries an `AuxAnchor { devnet_header_id, devnet_height }`; the miner
  fetches the devnet's current best header (`hn::auxpow::fetch_devnet_anchor`,
  `GET /info`, 5 s timeout) and `apply_block` enforces the anchor height is
  **monotone** (`HnError::AnchorRegressed` otherwise), so hn liveness is **paced
  by the devnet's Autolykos PoW chain**. The FULL binding — the devnet block's
  extension Merkle-commits to the hn `state_root` so one solved PoW binds exactly
  one hn block (reusing `crate::auxpow::extension_root` + a `BatchMerkleProof`,
  verified via `ergo_crypto::autolykos::v2::check_pow_v2`) — is the remaining
  consensus step; until it lands the anchor is a devnet-paced scaffold, not yet
  PoW-binding. Aux-PoW-weight reorg is likewise deferred (single-producer +
  followers only need linear extension).
- **Node loop (`hn_node`).** A blocking std-thread loop (no async runtime):
  resume-or-genesis from the persisted block log, spawn the HTTP server, then
  each tick optionally `sync_from`/`pull_mempool` a peer and optionally
  `produce_block_anchored` against the live devnet header. Concurrency note: the
  chain lives behind a single `Mutex`; the loop binds each locked call to a
  temporary that drops at the statement `;` — an `if let … {} else {}` over the
  lock expression would hold the guard across the `else` arm and self-deadlock the
  server thread, so produce results are `let`-bound before the follow-up
  `lock()`. The peer `HttpChain` client carries a 10 s request timeout so a dead
  peer surfaces as an empty fetch rather than hanging the loop.
- **Deployment (`~/apps/aegis-testnet-hn/`, separate from `~/apps/aegis-testnet`).**
  `start.sh` boots node A (`:8750`, genesis + producer, merge-mined vs the devnet)
  then node B (`:8751`, follower syncing A over the HTTP feed); `status.sh`
  prints both heights+roots, `stop.sh` tears down. README documents topology,
  the pinned param table, the faucet, and the aux-PoW deferral.
- **Multi-node e2e** (`hn_multinode_e2e.rs`, in-process 2-node) + a live
  networked run: two nodes IBD-converge on identical roots, advance together
  (~1 block / 2 s tick), a faucet spend submitted to the follower propagates to
  the producer and is mined, the recipient finds it via BOTH nodes, a double
  spend is rejected on both, and a restarted follower replays its log and
  re-syncs to the same root.

**Deferred (explicitly NEXT):** the full aux-PoW commitment (extension-Merkle
binding of the devnet PoW to the hn `state_root`) + aux-PoW-weight reorg;
per-peer unverified-tx rate limiting; consensus-enforced coinbase maturity over
hidden inputs; peg-in enablement; folding hn into the main Curve-Trees node's
libp2p gossip layer (the hn testnet runs its own HTTP-feed P2P for now).

## Next (in order)
1. ~~Wallet~~ DONE (see the wallet section above). ~~Node integration (single,
   local)~~ DONE (see the aegis-node integration section).
2. Sender-recovery slot (`out_ct`, N7 analog) + memo semantics.
3. Peg contract wiring on the settlement guest; narrow-trace optimization
   (client prove < 1 s AND cheaper settlement).
4. Generalizing the fixed 2-in/2-out shape.
5. A fresh testnet on the new engine (chain-id-breaking is free).
