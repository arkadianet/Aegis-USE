> **⚠ SUPERSEDED RANKING (2026-07-12): Option A (additive Pedersen) is REJECTED — privacy-broken (linkable via public rho; see `n1-nullifier-fix-design.md` §0). Only Option B (non-linear Poseidon hash) survives from this doc. The overall N1 decision + the leading P-REL alternative live in `n1-nullifier-fix-design.md` §0.**

# N1 redesign — a single-field nullifier that kills the malleability class

**Date:** 2026-07-12 · **Status:** design/feasibility (fork spike) · **Verdict:** a single-field-element nullifier **eliminates the cross-cycle problem structurally** and is **verifiably soundable in-house**. Recommend redesigning §3 rather than pursuing the FCMP++-class cross-cycle fix.

## 0. Why the current form is hard (recap)

`nf = (1/(nk+rho))·G` is a **point on E_odd (secq)**, coords in **F_n**. The inverse `x·x_inv=1` is F_p (odd CS), but the point `x_inv·G` has F_n coords → its scalar-mult must run in the even CS (F_n), needing an FCMP++-class cross-proof scalar equality + a canonicity proof over a **129-bit** aliasing window (`p−n`, verified). And it's exposed via a hiding `commit`, leaving the blinding free → the P0. Two hard problems: cross-cycle, and the free component.

## 1. The field fact that unlocks everything

The spend proof's **odd prover runs over F_p** (secq's scalar field). **secp (E_even) point coordinates are in F_p == the odd-CS field.** So *secp* curve operations — additions, fixed-base mults, x-coordinate extraction — are **native in the odd CS, single field, no cross-cycle**. (Verified: `p`,`n` both 256-bit, `n<p`; `build_tables<C:AffineRepr>` / `re_randomize<P:SWCurveConfig>` are curve-generic.)

Also: the nullifier must **hide nk** (revealing `x_inv=1/(nk+rho)` directly leaks `nk = 1/x_inv − rho`, since `rho` is public). So the nullifier must be a one-way function of `nk` — a hash or a DL-hiding — computed in-circuit and revealed as a **fully-constrained field element** (no group element exposed via `commit`, so no free component).

## 2. Two single-field constructions (both kill the P0)

Both compute `nk = x − rho` in-circuit (`x` from the existing `C*` opening = `nk+rho`; `rho` public = consumed nf / mint context), then produce `nf ∈ F_p`, reveal it, and constrain `circuit_nf == public_nf`. **No point is exposed via a hiding commit; `nf` is a determined field element ⇒ the malleability class is structurally impossible, not patched.**

### Option A — Pedersen-hash on secp, in the odd CS (RECOMMENDED)
`nf = Extract( nk·G₁ + rho·G₂ )` where `G₁,G₂` are NUMS **secp** points, the mults/addition run in the **odd CS (F_p)** via the **already-audited** `curve.rs` (checked/incomplete addition) + the `lookup`/`rerandomize` fixed-base-mult machinery, and `Extract = x-coord ∈ F_p`.
- **Single field, no aliasing:** everything is F_p; the scalar `nk ∈ F_p` bit-decomposes and reconstructs *exactly* in F_p (`Σ bᵢ2ⁱ = nk_var`, a clean checkable constraint). The 129-bit canonicity nightmare **does not arise** — it was purely an artifact of crossing F_p↔F_n.
- **Reuses audited primitives;** the only genuinely new gadget is a **constrainable-scalar fixed-base mult** (fork `lookup` to expose its bit LC so it can be tied to `nk_var` — the same lookup-fork N1 identified, but now *without* cross-cycle or canonicity, so it's bounded and testable).
- **Security assumption = discrete log**, already relied on everywhere in this circuit. No new cryptanalytic surface.

### Option B — Algebraic hash (Poseidon/Rescue) over F_p
`nf = H(nk, rho)` with `H` a ZK-friendly permutation over F_p (S-box `x⁵` + MDS), computed in the odd CS purely with `multiply`/`constrain` (no group ops, no scalar-mult, no lookup-fork).
- **Cleanest circuit;** but adds a hash gadget **and** requires Poseidon **parameters for F_p** (round constants, MDS, round counts vs algebraic attacks) — standard reference generation exists, and `ark-crypto-primitives 0.4` (already a vendored dep) gives a native Poseidon for the test-vector **oracle**, but the parameter choice is the one review-sensitive piece.

## 3. Soundness (both forms)
- **Determinism** ✓ (deterministic function of fixed `nk,rho`).
- **Binding to the spending key** ✓ — `nk` is derived from `C*` (`nk = x − rho`), the *same* key the tag/ownership path (`C*`) authorizes; a wrong `nk` fails the existing membership/tag binding. This is stronger than today: nf can't be produced without opening `C*`.
- **Unlinkability** ✓ — Pedersen: recovering `nk` from `Extract` is DL-hard; Poseidon: preimage-resistant.
- **Uniqueness** ✓ — unchanged `rho` discipline (`rho = consumed nf`); works because **nf is now an F_p field element and `rho ∈ F_p`**, so the chain is type-consistent (mint `rho` already hashes into F_p).
- **No new attack:** Pedersen `Extract` (x-coord) has a ±P collision, but for a *fixed* note `(nk,rho)` are constrained so the point and its x are fixed — one nf. No malleability: nf is fully determined, and the concrete guard test (below) proves it.

## 4. Spec blast radius — small, localized
- **Changes:** note-protocol **§3** (nullifier form: inverse-tag point → single-field hash), plus test vectors. `aegis-crypto::nullifier` (native derivation + oracle) and `spend.rs` odd-CS block.
- **Unchanged:** key hierarchy **§2** (`nk` still the nullifier key), the tag/ownership `C*` binding, the `rho` chaining rule, S4 node verification, and the **wire format** — the nullifier is still a **32-byte field element** (same width as today's `extract_x`), so `proof.nullifiers() == wire` and the double-spend set need no structural change.

## 5. Verifiability in-house — YES
- **Gadget correctness:** TDD against a native reference (Pedersen: reuse `curve.rs` math / ark; Poseidon: ark-crypto-primitives) — byte-exact test vectors.
- **The no-malleability test (the one that matters):** build a valid proof; assert that replacing the revealed `nf` with **any** other value makes `verify` fail (nf is circuit-determined; there is no free component to exploit). Plus: two proofs for one note ⇒ **identical** nf; the current `p0_nullifier_malleability_is_executable` must become impossible to construct.
- **External cryptographer:** **not required for Option A** (DL-only, reused audited curve math + a bounded, testable mult gadget). **Option B** wants a small, *standard* sign-off on the Poseidon-over-F_p parameters — far smaller than the research-grade cross-cycle construction.

## 6. Recommendation (ranked)
1. **Option A — Pedersen-hash on secp in the odd CS.** Strictly simpler than the cross-cycle fix, reuses audited primitives, DL-only, single-field (no aliasing/canonicity, no cross-proof equality). Structurally kills the P0. **Do this.**
2. **Option B — Poseidon/Rescue over F_p.** Cleanest circuit, no scalar-mult; cost is a new hash gadget + parameter sign-off.
3. **Keep inverse-tag + cross-cycle fix.** FCMP++-class, external-cryptographer research build. **Reject** — the hardness was self-inflicted by putting the nullifier on the wrong curve.

## 7. Open items / honest caveats
- Validate that instantiating `build_tables`/the fixed-base mult for **secp points inside the odd prover** composes with the existing even(tree)/odd(C*) prover split (structurally native — secp coords ∈ F_p — but an implementation-validation step, not a soundness risk). The vendored mult flags an identity/`hs=0` edge `todo` — handle + test.
- Pick `G₁,G₂` as vectored NUMS secp generators (reuse the §0 hash-to-curve discipline).
- One doc consequence: this **retires** the "external cryptographer certifies the composed inverse-tag circuit" TVL gate and replaces it with a much smaller in-house-verifiable claim (Option A) — a net de-risk for the whole project.
