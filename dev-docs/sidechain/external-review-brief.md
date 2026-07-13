# Aegis shielded-transfer circuit — external cryptographer review brief

**Purpose:** self-contained brief to certify the *composed* 2-in/2-out shielded-transfer circuit before any real value (the pre-TVL gate, security.md). Written for a reviewer who has NOT read the codebase. Nothing here is claimed "certified" — the asks are in §4.

**Status of the code reviewed:** `aegis-crypto` (spend/mint/nullifier/keynote/generators/tree/h2c) on `feat/privacy-use-cash-sc` tip `7c8fcd7`, PLUS the N1 Poseidon nullifier fix on branch `worktree-agent-a9620eb22f94d1269` (2 commits, not yet merged — the version this brief describes). In-house adversarial review has run per-slice; this is the residual expert scope.

---

## 1. System + threat model (one page)

- **Chain:** a merge-mined Ergo sidechain for private USE payments. Global mandatory shielded pool; **no transparent lane**. A note is a commitment; spent notes are marked by a **nullifier** in a consensus set.
- **Proving stack:** Curve Trees (select-and-rerandomize) + Bulletproofs over the **secp256k1/secq256k1 2-cycle** (`E_even`=secp, `E_odd`=secq; each curve's scalar field is the other's base field — `F_p` = secp base = secq scalar; `F_n` = secp scalar = secq base). Vendored research code (dalek-fork bulletproofs r1cs + arkworks curves), pinned, **unaudited**.
- **Transfer shape:** fixed **2 inputs / 2 outputs** (Zcash "pour" arity), byte-uniform (metadata privacy). Dummies are self-owned zero-value notes (real members), so the circuit is always 2 real spends — no dummy branch.
- **Consensus must guarantee:** (a) **no inflation** — Σ input value = Σ output value + public fee; (b) **no double-spend** — one note ⟹ exactly one nullifier; (c) **unlinkability** — nothing public lets an observer correlate a wallet's spends; (d) **hiding** — amount, sender, receiver, and which leaf is spent are all hidden.
- **The prover controls:** all witnesses (keys, blindings, note openings, leaf indices, the tree path randomization). The verifier substitutes only public constants: the per-network **fee**, the tree **root**, and the revealed **nullifiers** and **output commitments**. **Any prover degree of freedom that reaches a consensus-stored value (a nullifier, an output commitment/value) is a potential break** — that is exactly the class of the resolved P0 (§2 nullifier).

---

## 2. The composed circuit, statement by statement

Two linked provers share a transcript: the **even CS** (native field `F_n`, operates on odd-curve point coordinates) and the **odd CS** (native field `F_p`, where key scalars `x=nk+rho` live). Per input, the gadgets interleave; the verifier mirrors the exact order (transcript domain `"aegis:spend:v1"`).

### 2.0 Generators (the DL-independence base) — `generators.rs`, note-protocol §0
All generators derived `hash_to_curve(DST = domain tag, msg = "")` via **RFC 9380 SvdW / XMD-SHA-256** (our own XMD impl — ark-ff 0.4.2's `DefaultFieldHasher` is RFC-non-compliant on ≤256-bit fields), vectored against RFC J.8.1/K.1 + an independent Python reimpl. Set: `{G_value, G_PRF, H_even}` (even), `{G, H_odd}` (odd), plus the tree's Pedersen bases `{B, B_blinding}` and the tree `delta` (Δ). **The entire soundness rests on these having no known DL relations (NUMS).** Inflation-binding of the note commitment, value/tag slot separation, and the ownership argument (§2.2) all reduce to this.

### 2.1 Membership — `spend.rs` select-and-rerandomize
Each input note is proved in the commitment tree via curve-trees select-and-rerandomize; **leaf index HIDDEN** (this is the anonymity mechanism). Tree params L=256, M=1, depth=4. Standard curve-trees; no known issue in-house.

### 2.2 Ownership / tag→C* binding — `spend.rs` (single_level_select_and_rerandomize) — **LOAD-BEARING, please certify**
The note's tag slot equals `(C + Δ).x`, where `C = x·B + r·B_blinding` is the key commitment and `x = nk+rho`. Ownership is bound by a public-index select-and-rerandomize revealing `C* = C + r_t·H`. **The "delta-as-sign-breaker" argument:** `tag = (C+Δ).x` admits `C+Δ ∈ {Q, −Q}`; the `+Q` branch forces `x = nk+rho`, and the `−Q` branch would require expressing `−2Δ` in the `{B, B_blinding}` basis — infeasible iff **Δ's discrete log w.r.t. `B` and `B_blinding` is unknown (NUMS)**. This is inherited from curve-trees but is now *load-bearing for spend authority*. **Ask: certify this sign-breaker argument and the Δ-NUMS assumption.**

### 2.3 Nullifier — the resolved P0 — `poseidon.rs` + `spend.rs:262–266` — **please certify the fix + params**
**Original bug (fixed):** `nf` was exposed as `odd.commit(x_inv, β)` — a Pedersen commitment whose blinding `β` was left unconstrained (only the value `x_inv` was bound via `x·x_inv=1`). A prover chose any `β`, producing `nf' = x_inv·B + β·B_blinding`; the constraint still held but `extract_x(nf')` varied ⇒ **unlimited valid nullifiers per note ⇒ double-spend/inflation** (was executably demonstrated). Root cause: a consensus identifier contained prover entropy.

**Adopted fix:** `nf = Poseidon(x)`, a **field element** over `F_p`, with `x = nk+rho` the SAME committed value the ownership path pins (`x_var` from `C*`'s opening at `spend.rs:262`, fed directly into `hash1_gadget` at :265, constrained `== public nf` at :266). Properties:
- **No free component** — `nf` is a fully-determined circuit output; there is no group element and no blinding to vary. The P0 class is *structurally* impossible (uniqueness is definitional, not derived).
- **Binds to the note via the pinned sum `x`, NOT `(nk,rho)` individually.** `C*` pins only `x = nk+rho`; hashing `(nk,rho)` separately would let a prover re-split `x` into a different `(nk',rho')` and mint a second nullifier per note — so the input is `x`, not the split. (This correction was made during the build.)
- **Single-circuit** (odd CS, `F_p`): no cross-cycle scalar transport, no `x`-vs-`x+p` aliasing (both reps scalar-reduce identically; and here it is a field hash, not a scalar-mult).
- **Unlinkability** holds because Poseidon is non-linear (no `nk·G` term to factor out — contrast the additive form rejected below).

**Gadget (`poseidon.rs`):** width `t=3` (rate 2 + capacity 1), state `[x, DOMAIN, 0]` with domain tag `"aegis:nf"` in the capacity slot, output `state[0]`. S-box `x^5` (`ALPHA=5`, `gcd(5, p−1)=1` verified ⇒ permutation). `R_F=8` (4 before / 4 after), `R_P=56`. Round constants + MDS from the standard Grain-LFSR generator (`ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds`) **for this exact field `F_p`**. One `permute` drives both the native oracle (`hash1`) and the gadget (`hash1_gadget`), so they compute the identical function by construction; params pinned by a golden test (chain-id-breaking to change). The partial-round lanes are collapsed to a fresh variable each round (`acc·1=v`) to avoid a `2^R_P`-term LC blowup — values unchanged.
**Ask: certify the Poseidon-over-`F_p` parameter/round-count choice — is `R_F=8, R_P=56` an adequate security margin against algebraic (Gröbner/interpolation) attacks for this 256-bit prime and `t=3, α=5`?** This is the single bounded external item.

### 2.4 Balance + range — `spend.rs`
- **Balance:** `Σ value_in = Σ value_out + fee`, with **`fee` a verifier-substituted public constant** (not a witness) — a witnessed fee could be signed negative to mint. Verified.
- **Range:** each **output** value ∈ [0, 2^64) (64-bit range proof). Confirmed both outputs covered; the value slot (not the tag slot) is the one range-proved.

### 2.5 Input-range invariant — **LOAD-BEARING, please certify**
Spend **inputs are NOT range-proved** in the circuit. Soundness relies on the invariant that **every leaf was ≤ 2^64 at creation**: outputs are range-proved (§2.4), and every mint (§2.6) pins the value to a Rust `u64`. With ≤2 inputs, `Σ < 2^65 ≪ field`, so no wrap-around. **Ask: certify this whole-system invariant (that no note with value ≥ 2^64 can ever enter the tree).**

### 2.6 Mint + coinbase — `mint.rs`
A note minted with no shielded input (PegMint / coinbase) carries a `MintProof` pinning its value slot to a **public** amount `V` via one even-CS constraint `value_slot − V = 0` (verifier substitutes `V`; no range proof needed — `V` is a `u64`, so the committed value is `< 2^64`). The minted commitment is byte-identical to a spendable note. Coinbase **value conservation** holds by construction: the amount drawn from the emission pot equals the value the `MintProof` binds. (In-house reviewed sound.)

---

## 3. Assumptions catalog

| Assumption | Where it's load-bearing |
|---|---|
| Discrete log hard on secp256k1 / secq256k1 | everything |
| NUMS / no-DL-relations among `{G_value, G_PRF, H_even, G, H_odd, B, B_blinding, Δ}` | note-commitment binding (inflation), value/tag separation, **ownership sign-breaker (§2.2)** |
| Poseidon `(t=3, R_F=8, R_P=56, α=5)` over `F_p` is a secure sponge/PRF | **nullifier uniqueness + unlinkability (§2.3)** |
| Bulletproofs / R1CS knowledge-soundness (vendored dalek-fork + arkworks, **unaudited**, pinned) | all proofs |
| RFC 9380 generator derivation reproducible + structure-free | generator NUMS (§2.0) |
| Every tree leaf has value < 2^64 (system invariant, not a per-proof check) | **balance no-wrap (§2.5)** |

---

## 4. Highest-priority questions for the reviewer

1. **Poseidon params (§2.3):** are `R_F=8, R_P=56, t=3, α=5` an adequate margin for a 256-bit prime `F_p` against Gröbner-basis / interpolation / GCD algebraic attacks? Recommend a conservative round count if not.
2. **Ownership sign-breaker (§2.2):** is the `tag=(C+Δ).x` → `x=nk+rho` binding sound, given it rests entirely on `Δ` being NUMS relative to `{B, B_blinding}`? Any `−Q`-branch or torsion/identity edge?
3. **Composed cross-terms:** across membership + ownership + nullifier + balance + range in the shared transcript — any cross-statement malleability or witness that satisfies two sub-relations with inconsistent values (the classic "∃ an x" vs "∃ the same x" trap)? Note the nullifier now shares `x_var` with the ownership opening by construction (`spend.rs:262/265`) — please confirm that binding.
4. **Input-range invariant (§2.5):** is relying on creation-time range-bounding (rather than per-spend range proofs) sound for the 2-in balance statement?
5. **Transcript / Fiat-Shamir:** are all public points/values absorbed identically on both prover and verifier sides (no grinding surface), given the even/odd interleaving?

---

## 5. Already checked in-house (do not redo)

- **The P0 nullifier malleability** was found by adversarial review, executably demonstrated, and is the subject of the §2.3 fix.
- **Additive nullifier `nk·G₁+rho·G₂` REJECTED** — privacy-broken (linear ⇒ `nf_X−nf_Y=(rho_X−rho_Y)·G₂` lets an observer factor out the per-wallet `nk·G₁` and link spends). This is *why* the fix is a non-linear hash, not an additive form.
- **Mint proof (§2.6) and coinbase value-conservation** — independently reviewed, no inflation/theft/panic.
- **An alternative fix (P-REL: prove `nf=x_inv·G` via an in-circuit point relation)** was designed and built to a partial; sound but rests on a larger assumption chain (same-witness binding + Pedersen binding + DL + EC exceptional-case hardening) — retained as a documented fallback. Poseidon was chosen for its *definitional* (vs derived) uniqueness. See `n1-nullifier-fix-design.md`.
- **RFC 9380 generators** vectored against official + independent references.
- The g16 3-lens adversarial review (2026-07-12, 20 findings) and its resolutions predate this brief; `g16-adversarial-review.md` has the trail.
