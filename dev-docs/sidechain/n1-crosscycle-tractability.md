# N1 — cross-cycle tractability: is the nullifier fix an in-house build?

**Date:** 2026-07-12 · **Verdict:** **LANDABLE IN-HOUSE** (bounded build + mandatory adversarial/external review of the EC gadgets) — **the FCMP++-class cross-cycle scalar-equality step is AVOIDABLE.** This revises `n1-nullifier-fix-design.md` §4(c)/§6b, which routed N1 to an external cryptographer on the premise that a cross-*circuit* secret-scalar equality is unavoidable. It is not.

## 0. The key finding (read this first)

`n1-nullifier-fix-design.md` frames the fix as: odd CS proves `x·x_inv=1` (field `F_p`), even CS proves `nf = x_inv·B` (odd point, coords `F_n`), and the two circuits must be bound to the *same* secret `x_inv` — a cross-proof secret-scalar equality (the FCMP++/Eagen-divisor-flavored hard part), plus a canonicity range-proof to kill the `p−n = 129-bit` aliasing.

**Both of those hard parts dissolve if the inverse relation is proven as a POINT relation inside the even CS, so the whole nullifier binding lives in ONE circuit and the shared scalar is shared trivially (same bit variables).** Concretely, replace `x·x_inv=1` (a field relation, wrong circuit) with `x_inv · C* = B + s·B_blinding` (a point relation, native to the even CS), where `C*` is the already-public rerandomized key commitment. No second circuit, no cross-proof binding, no canonicity proof needed.

## 1. Cross-proof scalar equality — AVOIDED, not solved

The directive asks which technique binds the even-CS mult scalar to the odd-CS `x_inv`. Answer: **don't**. Survey:

- **(a) FCMP++ / Eagen divisors** — the efficient way to prove a discrete-log/scalar-mult relation in one curve's circuit. Real, but: research-grade to implement soundly, Monero's reference is C++/complex, and it is *overkill* here — we have g15 proving-headroom to spend on a naive-but-auditable gadget. **Not needed.**
- **(b) commit `x_inv` once, open in both circuits + range proof** (the design §4c sketch) — this is the genuinely subtle path: a *hidden* secret bit-vector equal across two independent Bulletproofs needs a cross-proof commitment opening. Avoidable, so drop it.
- **(c) THE ADOPTED PATH — inverse-as-point-relation, single even CS.** Everything the nullifier needs is expressible over odd-curve points, whose coords are `F_n` = the even-CS native field. No cross-cycle anything.

### The construction (all in the even CS, per input)

`C* = x·B + r'·B_blinding` is already public (S2b `key_cms`); `B, B_blinding` are the odd `pc_gens` (NUMS, DL-independent — the assumption curve-trees already makes). Reveal the nullifier point `nf`. Then:

1. Bit-decompose `x_inv` into `L=256` bits `b_i` (`is_bit` each). **These bits are the only "x_inv" — shared by both mults below because they are the same circuit variables.**
2. **Mult A (fixed base `B`):** windowed `nf_calc = Σ b_i 2^i · B`; constrain `nf_calc == nf` (public). Tables of multiples of `B` are setup constants.
3. **Mult B (base `C*`, public-per-instance):** windowed `P = Σ b_i 2^i · C*`; constrain `P == B + s·B_blinding` for a witnessed `s` — i.e. `re_randomize(commitment=B, randomness=s, H=B_blinding, tilde=P)`. Tables of multiples of `C*` are computed per-proof from the public `C*` by *both* prover and verifier (native EC, outside R1CS).
4. Drop the odd-CS `commit(x,·)` / `commit(x_inv,0)` / `multiply` entirely. (The odd CS is still used for tree membership, unchanged.)

### Why it is sound (the algebra to be reviewed)

Mult B forces `x_inv·C* = B + s·B_blinding`. Expand `C*`: `x_inv·x·B + x_inv·r'·B_blinding = B + s·B_blinding`. DL-independence of `{B, B_blinding}` ⇒ **`x_inv·x ≡ 1 (mod p)`** and `x_inv·r' = s`. Mult A gives `nf = x_inv·B`. Together: `nf = (1/x)·B` — exactly the §3 inverse-tag nullifier, with **no free component** (nf is the deterministic output of Mult A over public/witnessed data; there is no Pedersen commit and hence no blinding `β` to vary). The old malleability is *structurally gone*: there is nothing to hide `β` in.

### Why the aliasing (canonicity) concern dissolves

The 129-bit `p−n` aliasing in the design doc was specific to *reconstructing `S = Σ b_i 2^i` as an `F_n` field element and equating it to `x_inv`*. Here `x_inv`'s bits only ever drive EC mults over the order-`p` group. Any two integer representatives of the same residue (`x_inv` vs `x_inv+p`) yield the **identical point** in both Mult A and Mult B → the **same** `nf`, still one nullifier per note. Aliasing is **harmless**, not a vuln. No canonicity range-proof required. (`L=256` suffices to represent every `x_inv ∈ [0,p)`.)

### No new privacy surface

`nf` and `C*` are already public in S2b; `s`, the `x_inv` bits, and the mult intermediates are witnesses. The construction reveals **nothing new** — so no privacy-review delta beyond the existing composed-circuit review.

## 2. The scalar-mult gadgets — BOUNDED-BUILD

- **Fixed-base windowed mult (Mult A, base `B`):** fork the vendored `lookup` (`lookup.rs:87`) + the `re_randomize` accumulation loop (`rerandomize.rs`) to (i) accept `x_inv`'s bits as the window indices via *constrainable* bit LCs rather than a raw `Option<usize>`, and (ii) start from identity (pure `s·B`, not `commitment + r·H`). All curve-add primitives exist (`curve.rs`: `incomplete_curve_addition`, `checked_curve_addition`). ~`L/3 ≈ 86` windows × (1 `lookup` + 1 checked/incomplete add). Est. ~2–4k constraints.
- **Per-instance-base windowed mult (Mult B, base `C*`):** identical gadget; the only change is the table values are public inputs recomputed from `C*` each proof (verifier recomputes → no trust). Same ~2–4k constraints. `re_randomize(B, s, B_blinding, P)` for the final constraint is vendored as-is.
- **`re_randomize` is a fork-able base, not a rewrite** — the accumulation + checked-addition skeleton is exactly reused; the only surgery is exposing the scalar as constrainable bits.

## 3. Canonicity — NOT NEEDED (in this construction)

Dissolved (see §1). It *would* be the "easy part" (a 256-bit `is_bit` + a `< p` comparison ≈ 256–512 constraints) only under the field-reconstruction approach, which we are not using. Skip it.

## 4. Tractability verdict (per sub-piece)

| Sub-piece | Verdict |
|---|---|
| Cross-proof scalar equality | **AVOIDED** (reformulated away — no cross-circuit binding exists) |
| Fixed-base mult (Mult A) | **BOUNDED-BUILD** + adversarial review |
| Per-instance-base mult (Mult B) | **BOUNDED-BUILD** + adversarial review |
| `x_inv·C* = B + s·B_blinding` algebra / DL-independence argument | **BOUNDED**, but **NEEDS-EXTERNAL-REVIEW** before TVL (short, clean argument) |
| EC-gadget exceptional cases (incomplete-add x-collisions; the vendored `todo hs=0`) | **BOUNDED-BUILD**, **the delicate part → NEEDS-ADVERSARIAL-REVIEW** (known pattern: Zcash/arkworks VBSM gadgets; not research) |
| Canonicity range-proof | **NOT NEEDED** |

**Overall: LANDABLE IN-HOUSE with the adversarial-review discipline already in use, then external sign-off before TVL** (the same gate the whole composed circuit needs — N1 is *not* a special research blocker beyond it). The prior "external cryptographer / FCMP++-class research" verdict was correct *for the field-reconstruction framing* and is superseded by the point-relation framing.

**Honesty flags (I reasoned on paper, built nothing):** two things MUST be adversarially verified and cannot be trusted on a functional pass — (i) the `{B,B_blinding}` DL-independence step that turns the point equation into `x·x_inv=1 ∧ δ=0`; (ii) the windowed-mult exceptional-case handling. If review finds the incomplete-addition edge cases intractable to make sound cheaply, complete/twisted-Edwards-style addition or a random-offset accumulator is the fallback (more constraints, still bounded).

## 5. No-malleability test strategy (verifiable, not just functional)

1. **`nonzero_nf_blinding_is_rejected` becomes structural** — there is no `commit`, so no `β` to inject; the old malicious prover hook can't even construct a divergent `nf`. Assert: any `nf ≠ Mult-A output` fails.
2. **Direct forge:** post-hoc set `nf' = nf + β·B_blinding` on a valid proof; verifier's Mult-A constraint (`nf_calc == nf'`) fails. Assert reject.
3. **Wrong-`Q`/`δ≠0`:** feed a `C*`-inconsistent witness so `x_inv·C*` has a nonzero `B`-and-`B_blinding` cross-term; Mult B (`== B + s·B_blinding`) fails. Assert reject.
4. **No-inverse (`x=0`):** `C*` opening with `x=0` ⇒ `x_inv·C*` can't equal `B` ⇒ reject.
5. **Aliasing is harmless (positive test):** `x_inv` vs `x_inv+p` bits both verify and produce the **identical** `nf` — assert equality (documents no double-nullifier).
6. **Exceptional-case fuzz:** random `x_inv`/`C*` including scalars that drive the accumulator through identity/doubling points; assert soundness (reject wrong `nf`) and completeness (honest proofs verify).
7. **Delete `p0_nullifier_malleability_is_executable`** — it must stop verifying; keep a inverted-assertion version as a regression guard.

## 6. Proof-cost impact (rough)

Per input adds ~2 windowed mults (~4–8k constraints) + one `re_randomize` (already ~few-k). Roughly **2–3× the current per-input constraint count**, × 2 inputs. Bulletproofs proof **size** grows only `~2·log2(constraints)` ⇒ stays KB-scale, comfortably `< MAX_PROOF_BYTES`. Prove **time** grows ~linearly ⇒ estimate ~2–3× the current ~1.5–3 s → ~5–9 s single-thread; batched verify still ms-scale. Within the g15 headroom. Bench during the build.

## 7. Recommended build order

1. Fork `lookup` + accumulation into a `scalar_mul.rs` gadget exposing constrainable bits; **standalone test** `s·B == public P`, incl. exceptional-case fuzz. (The soundness test here is real: reject wrong `P`.)
2. Add the per-instance-base variant (tables from public `C*`).
3. Wire into `spend.rs`: drop the odd-CS nf commit; add Mult A (`nf`), Mult B (`x_inv·C* == B + s·B_blinding` via `re_randomize`); share the `x_inv` bits.
4. Flip the regression tests (§5); full gate; bench.
5. Adversarial-review fork on the composed gadget (DL-independence argument + exceptional cases) → then external sign-off before TVL.
