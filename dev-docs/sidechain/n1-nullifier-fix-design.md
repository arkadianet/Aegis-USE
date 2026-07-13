# N1 — nullifier soundness fix: design

**Date:** 2026-07-12 · **Status:** design (implementation is a focused, adversarially-reviewed build) · **Blocks:** `ProofMode::Real` (any sound value transfer). Does NOT block testnet *mechanics* (see §6).

---

## STATUS: ✅ CLOSED (2026-07-12) — Poseidon fix built, adversarially reviewed MERGE-clean, merged to `feat/privacy-use-cash-sc` (`fe6f205`).
`nf = Poseidon(nk+rho)`; malleability structurally gone; note-binding confirmed (same `x_var` feeds ownership + hash). Full gate green (299). Remaining: one bounded external item (Poseidon-`F_p` param sign-off, in `external-review-brief.md`); dead inverse-tag code marked SUPERSEDED (full deletion = DEFERRED). P-REL (§0a) retained as documented fallback. `ProofMode::Real` may be enabled after the param + delta-NUMS external sign-offs.

## 0. DECISION (2026-07-12, after 3 design forks + 2 adversarial reviews) — N1 IS IN-HOUSE BUILDABLE

The FCMP++-class cross-cycle framing (§4/§6b below) is **avoidable**. Verified facts driving the decision:

- **No downstream point-dependency** (checked in code): `NF_BYTES=32`, the spent-set is `BTreeSet<[u8;32]>`, the wire carries 32 bytes, and `rho_transfer` already *hashes* the nf bytes. So the nullifier can be any 32-byte value — a point is not required.
- **Unlinkability requires non-linearity** (linkability review). Three families:
  - **Inverse-tag (current, non-linear):** the malleability came only from *exposing it via a hiding commit*; the math is fine.
  - **Additive Pedersen `nk·G₁+rho·G₂` (Option A): REJECTED — privacy-broken.** `rho` is public, `nk` is per-wallet, so `nf_X−nf_Y=(rho_X−rho_Y)·G₂` lets an observer factor out `nk·G₁` and link a user's spends (meet-in-the-middle over the public rho set). Linearity is fatal.
  - **Non-linear hash `nf=H(nk,rho)` (Poseidon, Option B):** unlinkable (no factor-out), single-field.

**Two viable, sound, in-house paths:**

| Path | Spec change | Privacy re-analysis | New primitive | Load-bearing review item |
|---|---|---|---|---|
| **P-REL — point-relation inverse-tag** (§0a) | **none** | **none** (keeps §3 form) | two windowed scalar-mults (fork `lookup`) | DL-independence of `{B,B_blinding}` (inherited) + EC edge-cases |
| **HASH — Poseidon over F_p** (§0b) | §3 nullifier form | yes (confirm unlinkable — mirrors Orchard) | in-circuit Poseidon | Poseidon-over-F_p **parameter selection** (bounded, standard, not zero external input) |

**⚠ RECOMMENDATION UPDATED (P-REL adversarial review, 2026-07-12) → now leaning HASH/Poseidon.** The review corrected a real error and it moves the call:

- **P-REL uniqueness is COMPUTATIONAL (≡ discrete-log hardness), NOT "structurally impossible"** as an earlier draft of this section wrongly claimed. In the prime-order group `B_blinding = λ·B`, so the point relation is *one* congruence, not two — the "matching components ⇒ `x_inv·x=1`" argument is INVALID. Correct argument: two distinct nullifiers for one note ⟹ recover `λ = dlog_B(B_blinding)`, i.e. **double-spend ⟺ break DL.** Sound, but computational, and the reduction MUST be written correctly (it was botched once) and externally certified.
- **P-REL also carries a real EC exceptional-case hazard** (`incomplete_curve_addition` mis-computes on x-collisions/identity; the vendored `todo hs=0`): a prover steering the windowed-mult accumulator through a degenerate point could forge `nf`. Known Zcash/arkworks VBSM pattern — bounded, but delicate; needs complete/checked addition at danger points + fuzzing.
- **Poseidon gives UNCONDITIONAL/structural uniqueness** (nf = a function of note-bound inputs, zero output witness-freedom; only needs collision-resistance for cross-note forgery, no DL) **and has NO EC-edge hazard.** Its cost is the §3 spec change + a bounded, standard Poseidon-over-F_p parameter sign-off.
- **Both paths need a bounded external sign-off** (P-REL: certify the DL reduction; HASH: certify the Poseidon params) — neither is literally zero external input, but both are far smaller than the FCMP++ cross-cycle build.

**DECISION (operator + 2 external cryptographer reads + 3 fork analyses, 2026-07-12): BUILD BOTH; Poseidon is the PRODUCTION path, P-REL is the parallel research artifact/fallback.**

The deciding argument (external review): *how many lemmas must hold before consensus safety follows?*
- **Poseidon:** "Poseidon behaves as specified." The invariant *one note ⟹ one nullifier* is **definitional** — no other witness variable can touch `nf`. One whiteboard; any future auditor gets it in minutes.
- **P-REL:** same-witness-binding + PoK extraction + Pedersen binding + DL + EC arithmetic + edge-case correctness + implementation fidelity. Each reasonable; together a large proof obligation. Elegant, preserves external semantics, no spec change — but soundness is *derived*, not definitional.

For a protocol that will secure real value and outlive its authors, fewer assumptions = less long-term risk → **Poseidon ships.** P-REL is built in parallel (isolated worktree) as a comparison/fallback and a literature-worthy artifact; if Poseidon's parameter review ever stalls, P-REL is the ready backup. Option A dead.

**Spec-history note to preserve when Poseidon lands (per external review — stops a future dev "optimizing" back to the broken point form):** *"Earlier drafts represented the nullifier as an elliptic-curve point from the inverse relation. Implementation review found that publishing a commitment-derived point admitted witness malleability via an unconstrained blinding factor. After evaluating a proof-preserving repair (P-REL) and a hash-based redesign, the protocol adopts a deterministic Poseidon nullifier: it achieves the consensus invariant — a unique deterministic identifier per spend — with fewer cryptographic assumptions and substantially simpler verification."*

**Build note (both):** the vendored proving stack is the **dalek-fork bulletproofs r1cs** (its own `ConstraintSystem`), NOT arkworks r1cs-std — so ark-crypto-primitives' Poseidon *gadget* will not plug in; the S-box (`x^5`)+MDS+round-constants must be built against the vendored CS, with params from a documented generator for the odd scalar field `F_p` and TDD'd against an out-of-circuit Poseidon oracle with committed vectors. That gadget cost is the one thing that could narrow Poseidon's simplicity lead — measure it early.

### 0a. P-REL construction — reviewed SOUND-WITH-CAVEATS
Single circuit (even CS). With `C* = x·B + s'·B_blinding` public from S2b, prove `x_inv·C* = B + s·B_blinding` (two fixed-base mults) plus `nf = x_inv·B`. Under DL-hardness this makes `nf` unique (a second nullifier ⟹ recovering `dlog_B(B_blinding)`). Cross-cycle avoided; canonicity dissolves (both integer reps give the same point). ~2–3× per-input constraints, proof `<MAX_PROOF_BYTES`, prove ~5–9 s.

**THE make-or-break, flagged independently by the review fork AND an external cryptographer's read (2026-07-12): witness-equality of `x_inv`.** The security rests on the *same* `x_inv` being used in BOTH mults (`nf = x_inv·B` and `x_inv·C*`). The first attack any reviewer writes: use `x_1_inv` to satisfy `nf = x_1_inv·B` but a different `x_2_inv` inside `x_2_inv·C* = B + s·B_blinding`. If manufacturable, the bug survives. Proving "there exists **the same** x_inv" (not merely "there exists an x_inv") is a classic subtle-bug site. The build MUST use one shared set of allocated bit-variables across both mults, and the formal proof-of-knowledge must certify the single-witness binding. Plus the EC exceptional-case hazard (§0 above). Source: `n1-crosscycle-tractability.md`. External-review scope = the witness-binding PoK + the DL reduction + EC edges.

### 0b. HASH construction (fallback)
`nf = Poseidon(nk, rho)` in the odd CS, revealed + constrained `circuit_nf == public_nf`. Non-linear ⇒ unlinkable; single-field ⇒ no cross-cycle. Needs an in-circuit Poseidon gadget (ark-crypto-primitives base) + a conservative F_p parameter set with a short parameter review. Source: `n1-redesign-hash-nullifier.md` Option B (that doc's Option A #1 ranking is SUPERSEDED — Option A is rejected).

---


## 1. The bug (recap, executably proven)

`spend.rs` exposes the nullifier point via `odd.commit(x_inv, β)` — a *hiding* Pedersen commitment `x_inv·B + β·B_blinding`. The circuit constrains only the value component `x_inv` (via `x·x_inv = 1`); `β` is free. A prover picks any `β`, computes `nf_point = x_inv·B + β·B_blinding` (forward, no discrete log needed), and gets a valid proof whose `extract_x(nf_point)` depends on `β` → **unlimited distinct valid nullifiers for one note → double-spend / inflation.** Proven by `spend.rs::p0_nullifier_malleability_is_executable` (two proofs, one note, two nullifiers). The paper's "treat `t` as a commitment *with randomness zero*" (PRF.md) is a *requirement the circuit must enforce* — it currently does not.

## 2. What "fixed" means

The consensus nullifier must be a **deterministic** group element `nf = x_inv·G` with **no free component** — i.e. `nf` bound to `x_inv` by an explicit scalar-multiplication relation, `nf` exposed as a **public input** (not a `commit`), with `x_inv` the *same* value the `x·x_inv = 1` inverse constraint uses.

Regression targets already committed: un-`#[ignore]` `nonzero_nf_blinding_is_rejected`; delete `p0_nullifier_malleability_is_executable` (it must stop verifying).

## 3. The crux — this is an irreducibly cross-cycle relation

The nullifier scalar `x_inv = 1/(nk+rho)` lives in **`F_p`** (E_odd scalar field). A point `x_inv·B` therefore lives on **E_odd** (only E_odd has scalar field `F_p`), whose coordinates are in **`F_n`** (E_odd base field = E_even scalar field). Consequences, all forced by the 2-cycle:

- **`x·x_inv = 1`** is a multiplication in `F_p` ⇒ must run in the **odd CS** (native field `F_p`). This is where `x` is available (opening `C*`).
- **`nf = x_inv·B`** produces an E_odd point whose coordinates are `F_n` elements ⇒ the scalar-mult must run in the **even CS** (native field `F_n`), exactly like `single_level_select_and_rerandomize`/`re_randomize` operate on odd points inside the even prover.

So the inverse constraint and the scalar-mult are in **different circuits over different fields**, and they must agree on the *same* `x_inv`. That cross-cycle scalar equality — not the scalar-mult itself — is the hard, soundness-critical core. (This is the same class of problem FCMP++ solves for Monero; it is characteristic of the CT+BP construction, not a mistake in ours.)

## 4. Construction

**(a) Odd CS (F_p), per input — unchanged except the nf exposure:**
- open `C* → x_var` (value `nk+rho`); allocate `x_inv_var`; constrain `x_var·x_inv_var = 1`. Keep.
- **Remove** `odd.commit(x_inv, 0)`. `x_inv` is bound here as `x_inv_var`.

**(b) Even CS (F_n), per input — the new gadget:**
- Bit-decompose `x_inv` into `L` boolean variables `b_0..b_{L-1}` (`is_bit` each, `lookup.rs`).
- Fixed-base windowed mult: accumulate `Σ b_i·2^i · B` using precomputed window tables of multiples of the odd base `B` (adapt `build_tables`/the accumulation loop in `rerandomize.rs`, but starting from identity — a pure scalar-mult, not `commitment + r·H`; handle the identity/first-window edge like `re_randomize`'s `i==1` branch and its `todo hs=0`).
- Constrain the accumulated point equals the **public** `nf_point` (checked curve addition to the public coords, as `re_randomize` does against `x_tilde,y_tilde`).

**(c) Cross-cycle scalar equality — the soundness-critical link:**
- The even-CS bits reconstruct `S = Σ b_i·2^i`. This is computed **mod `F_n`**, but `x_inv ∈ F_p` and **`p > n`** (secp256k1: `p = 2^256−2^32−977`, `n < p`). So an `F_n` reconstruction aliases: bit-patterns for `x_inv` and (if `x_inv < p−n`) `x_inv + n` reconstruct to the same `F_n` element but are different `F_p` scalars → different `nf`. **A range/canonicity proof that the bits represent the canonical `x_inv < n`-… actually `< p` with a unique representative — is REQUIRED**, or the fix is still malleable. Bind the reconstructed `S` to the odd-CS `x_inv_var`: the standard technique is to commit `x_inv` once and open it in both circuits with a range proof pinning it `< min(p,n)` (FCMP++ pattern). **This is the step that most needs an external cryptographer.**

## 5. Why not shortcuts (rejected)

- *Force `β=0` on the commit* — impossible from the verifier side (Pedersen hides the blinding by design).
- *Reveal `x_inv` and let consensus compute `nf`* — `x_inv` reveals `nk` (rho is public for transfers) ⇒ catastrophic key leak.
- *Hash nullifier `H(x)`* — no in-circuit hash gadget exists; changes the pinned §3 form; still needs `x` bound.
- *Reuse `re_randomize` directly* — its scalar is a raw internal witness, not a constrainable `Variable` (verified). Forking it to expose the reconstructed-bits LC is viable and is folded into §4(b)/(c); log any vendored patch in `PROVENANCE.md`.

## 6. Scope reframe — N1 blocks *value*, not testnet *mechanics*

N1's failure mode is value theft (double-spend). For **mechanical** bring-up — node runs, produces blocks, MM sidecar, peg plumbing, bridge round-trip **with no real value** — the nullifier soundness is irrelevant. So S5b/coinbase, testnet, and the Scala-node bridge work can proceed **in parallel** with N1, provided a hard rule holds: **no real USE value on the chain until N1 lands AND the composed circuit passes external review.** Track this as the top TVL gate (security.md).

## 6b. Empirical confirmation (fork spike, 2026-07-12) — N1 is not a fork task

A dedicated build fork traced the circuit and vendored primitives and **correctly declined to build** (committed nothing; a plausible-but-unverified gadget on inflation-critical code is the S2b trap). What it pinned:

- **Aliasing window is real and large:** `p − n` is exactly **129 bits** (verified). So the F_n reconstruction of an F_p scalar aliases across a ~2^129 window — the canonicity proof `S < n` in §4(c) is mandatory, not belt-and-suspenders. Its completeness cost is ~2^−127 (negligible).
- **The vendored primitives do not compose for this:** `lookup` (lookup.rs:87) takes a **raw `index: Option<usize>`, not external constrainable bit variables**, and `re_randomize` decomposes its scalar internally — so neither can tie the mult's scalar to the odd-CS `x_inv`. A **fork of `lookup`/the windowed accumulation to expose the bit LC** is required (log the vendored patch in `PROVENANCE.md`), plus the identity/edge handling the vendored code flags `todo`.
- **The fallback "standalone scalar-mult increment" also cannot be safely landed** short of the cross-proof binding: rejecting the `s+n` alias needs both the canonicity range-proof AND the cross-cycle scalar equality, neither establishable by functional tests.
- **Verdict: N1 is an FCMP++-class cross-cycle engagement for an external cryptographer**, now specified to implementable detail with the numbers pinned. The three remaining pieces are exactly §4(a) even-CS mult with constrainable bits, §4(b/c) canonicity `S<n`, and the genuinely hard §4(c) cross-proof `x_inv` equality. Do not attempt as a single unreviewed pass.

## 7. Test plan

- Standalone gadget: `nf = s·B` verifies for honest `s`; rejects a wrong public `nf`; the aliased scalar `s+n` (if `< p`) is REJECTED by the canonicity proof (the soundness test — a functional test alone does NOT prove this).
- Integration: un-ignore `nonzero_nf_blinding_is_rejected`; `p0_nullifier_malleability_is_executable` must stop verifying (delete); all existing spend tests still green; proof size still `< MAX_PROOF_BYTES` (the scalar-mult adds ~L·const constraints — bench).
- External review of §4(c) before any TVL.
