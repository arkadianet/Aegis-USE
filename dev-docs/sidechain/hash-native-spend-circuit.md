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
  (`value_block = [value,0×7]`, `owner`, `rho`, `r`) → 4 permutations.
- **Accumulator.** Binary Poseidon-Merkle, depth 32 (2^32 leaves), internal node
  `= truncate_8(perm(left ‖ right))` — matches Plonky3's own Merkle shape.
  Incremental/append-only with empty-subtree defaults. `EMPTY_LEAF = 0×8`.
- **value / AMOUNT_BITS = 28.** A single BabyBear element cannot hold a `u64`, and
  a multi-term balance sum must not wrap `p`. Amounts are pinned `< 2^28` so
  `Σin == Σout + fee` is a single overflow-free field constraint (largest side
  `3·2^28 < 2^30 < p`) and each range-check is a 28-bit decomposition. Full 64-bit
  amounts ⇒ 2–3 limbs + a carrying balance adder (mechanical, deferred).

This reproduces the spike's ~86-permutation budget exactly: `2·(1 owner + 4 cm +
2 nf + 32 merkle) + 2·(4 out cm) = 86`.

## What verifies today (real proofs, with negative tests)

| circuit | statement | negatives |
|---|---|---|
| `PermBindingAir` | `out == Poseidon2(in)` (public I/O) | tampered output rejected |
| `MerkleMembershipAir` | private leaf + depth-32 path folds to public root | wrong root rejected |
| `NullifierAir` | `nf == H_NF(nk‖rho)` (public `nk,rho,nf`) | tampered `nf`, tampered `nk` rejected |
| `BalanceAir` | `Σin==Σout+fee` + 28-bit output range | imbalance rejected; inflating witness unbuildable |

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
4. **`AMOUNT_BITS=28`** vs a full 64-bit amount (limbs + carrying adder).
5. **`EMPTY_LEAF`** nothing-up-my-sleeve value.
6. **Zero-knowledge.** uni-STARK proofs are not ZK by default; keeping secrets
   out of the public inputs is necessary but the hiding wrapper (`is_zk`, or a
   recursive ZK layer) is a separate, later axis. Until then a proof is *sound*
   but not *hiding*: a witness-carrying proof could leak note data even though
   the public values do not — the ZK wrapper is required before real value.
7. **Monolith soundness items:** (a) the `nf0 ≠ nf1` one-hot/inverse in-circuit
   guard is best-effort — the authoritative double-spend defense is the consensus
   nullifier set (cross-tx); (b) the fixed transaction shape is exactly 2-in/2-out
   (dummy zero-value notes pad smaller transfers — the standard shielded-pool
   approach, but the padding/uniformity story wants review); (c) fee is a public
   input and is not itself range-checked here (assumed set by an honest wallet /
   bounded at consensus).

## Next (in order)
1. Note encryption (hash/KEM-based DH replacement) — deferred this pass.
2. Address/wallet over `owner = H(nk)`.
3. Settlement: the RISC0 guest re-verifying these BabyBear client proofs in-field
   (the whole reason for the hash-native rebuild), + the peg contract wiring.
4. A ZK wrapper (hiding), and generalizing the fixed 2-in/2-out shape.
5. A fresh testnet on the new engine (chain-id-breaking is free).
