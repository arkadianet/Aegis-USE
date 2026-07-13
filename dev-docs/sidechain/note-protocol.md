# Aegis — note protocol specification (G1.6)

**Date:** 2026-07-12  
**Status:** spec fully pinned post-review (2026-07-12, [g16-adversarial-review.md](./g16-adversarial-review.md)). All 20 findings addressed: spend model + exact nullifier form (§3), generators via RFC 9380 SvdW (§0), leaf-index hidden (§4), fee-in-circuit (§4), dummies (§6), OVK slot (§5), diversified addresses (§2). **No open design forks.** The single remaining gate before TVL is an external cryptographer *certifying the composed circuit's soundness* — a check of a finished spec, not a design task. Grounded in `~/coding/reference/crypto/curve-trees/` (membership/range + inverse-tag nullifier) + Zcash Sapling/Orchard (structural-uniqueness discipline) + RFC 9380 (generators); consensus numbers in `params.md`.

**Reading order:** [privacy.md](./privacy.md) (what) → this (how the note works) → [consensus.md](./consensus.md) (how blocks carry it). Open items feed [DEFERRED.md](./DEFERRED.md).

---

## 0. Curve setting

Curve Trees run on the **secp256k1 / secq256k1 2-cycle** (`E_even = secp256k1`, `E_odd = secq256k1`; each curve's scalar field is the other's base field). Commitments alternate curves up the tree; the spike measured this cycle (g15-proving-spike.md).

**Generators (N3 — load-bearing, not a footnote).** Every soundness property reduces to the generators `G, H_odd, G_value, G_PRF, H_even` (and the Bulletproofs vector bases) having **no known discrete-log relations** (NUMS/nothing-up-my-sleeve): Pedersen *binding* of `note_cm` prevents opening a note to a larger value (**this is what stops inflation**); `G_value ⊥ G_PRF` keeps the value and tag slots from trading off (so the 64-bit range proof, which covers only the value slot, actually binds value); `G ⊥ H_odd` gives nullifier determinism.

**Pinned derivation — RFC 9380 hash-to-curve, SvdW map, both curves.** Each generator = `hash_to_curve(seed ‖ domain_tag)` using the RFC 9380 **Shallue–van de Woestijne (SvdW)** map with the **XMD expander over SHA-256**. Chosen over SSWU-with-isogeny because SvdW works **directly** on the `a=0` short-Weierstrass form of *both* secp256k1 and secq256k1 — one map, no per-curve isogeny to derive/vector (and secq256k1 has no standardized SSWU suite). Both curves are prime-order (cofactor 1) so no cofactor clearing is needed. Constant-time, so the same primitive also serves the diversifier→`G_d` map (§2). Rejected: try-and-increment (`affine_from_bytes_tai` — the reference's method; adequate for offline public generators but *not* constant-time, and non-standard so harder to reproduce/audit); Elligator 2 (needs an order-2 point — absent on these prime-order curves).

- **Seed:** published nothing-up-my-sleeve string `"aegis:gen:v1"`; **per-generator domain tags** `"aegis:gen:v1:G_value"`, `":G_PRF"`, `":H_even"`, `":G"`, `":H_odd"`; Bulletproofs base vectors `"aegis:bp:v1:<i>"`.
- **Vectors:** the seed, the SvdW map, and every derived generator point are emitted under `test-vectors/aegis/generators/` (§8) so third parties reproduce them with a stock RFC 9380 library and confirm no hidden structure — this is what makes "no trusted setup" *checkable*, not asserted.
- **Derivation convention (pinned, G2-P1):** each generator is `hash_to_curve(DST = the full domain tag, msg = "")` — domain separation rides the RFC 9380 DST, not the message. Committed vectors: `test-vectors/aegis/generators/v1.json`, produced by the independent pure-Python reference (`test-vectors/aegis/tools/aegis_h2c_reference.py`, self-checked against RFC 9380 K.1/J.8.1) — the Rust implementation must reproduce them. Implementation note: ark-ff 0.4.2's `DefaultFieldHasher` deviates from RFC 9380 (Z_pad = L instead of 64 for SHA-256), so `aegis-crypto` carries its own vectored XMD/hash_to_field.
- **Reviewer check (bounded):** confirm the secq256k1 SvdW instantiation hits none of the map's exceptional inputs (map to identity/low order) — benign under cofactor 1, but verify not assume. Any change to seed/tags/map is chain-id-breaking.

## 1. What a note is

A note (the reference's "coin") is an on-chain **commitment** on `E_even` to `(value, tag)`:

```text
note_cm = value·G_value + tag·G_PRF + blinding·H_even      (permissible point; x-coord is the tree leaf)
```

- `value` — USE in base units (`u64`; 3 decimals). Range-proved to 64 bits (§4).
- `tag` — the x-coordinate of the receiver's rerandomized public key, homomorphically bound to the minting tx (§3). Ties the note to exactly one spending key without revealing it.
- `blinding` — hiding randomness.

On-chain the note is only `note_cm`; the opening `(value, tag-derivation data, blinding)` lives in the owner's wallet, delivered via the ciphertext (§5).

## 2. Key hierarchy

Derive Sapling-style from a 32-byte seed (BIP-39 mnemonic → seed; account/diversifier tree TBD):

```text
mnemonic ──► seed ──► sk  (root spend key; NEVER shared)
                        ├─► ak   spend-authorizing key   (signs; the address core)
                        ├─► nk   nullifier key           (derives nf — §3; only the spender holds it)
                        ├─► IVK = KDF(ak, nk)             incoming viewing — trial-decrypt, detect receipts (watch-only)
                        └─► OVK                            outgoing viewing — recover own sends (optional)
```

Sapling/Orchard split: `nk` distinct from `ak` so the nullifier (§3) is uncomputable by anyone but the spender, and IVK-detection is separable from spend authority. `pk_commitment` (the on-chain address core) commits to `ak`.

**Diversified addresses (N9 — v1, resolves the aegis-spec §7 "new address per receive" promise).** One `sk` yields unboundedly many unlinkable receiving addresses (Sapling-style): a **diversifier** `d` (random 11-byte index) maps via a group hash to a base point `G_d`, and the address is `(d, pk_d = ivk·G_d)`. Different `d` → on-chain-unlinkable addresses under DDH, all spendable by the one `sk`, all detected by the one IVK. The wallet issues a fresh `d` per receive/peg-in. This is a v1 requirement (not deferred): without it, address reuse links a receiver's payments sender-side and makes a single IVK leak unlink the whole history.

- **Spend** requires `sk` (derive nullifier, sign). **IVK** = watch-only (balance + history, no spend — the "read-only = privacy loss" footgun, M7). **OVK** lets a sender re-derive what they sent (memo recovery); omittable.
- Open: whether `r_sk` can be 0 (reference flags it); diversified-address derivation so each receive uses a fresh unlinkable address off one `sk`.

## 3. Nullifier (spend tag) — double-spend prevention

> **PRODUCTION FORM (N1, adopted 2026-07-12): `nf = Poseidon(x)`, `x = nk + rho`** — a field element over the odd scalar field `F_p`, revealed and constrained `Poseidon(x) == nf` in the odd CS; `x` is the sum opened from the note-bound key commitment `C*`. **Uniqueness is definitional:** `nf` is a hash of note-bound inputs with no group element, no hiding commitment, and no free/blinding component, so a note yields exactly one nullifier. It binds the *sum* `x` (not the `(nk,rho)` split, which `C*` does not pin), so a re-split cannot mint a second nullifier. Single-circuit — no cross-cycle, no aliasing. Params: `crate::poseidon` (t=3, R_F=8, R_P=56, α=5, Grain-LFSR over `F_p`); the parameter security margin is the one bounded **external-review** item. Adversarially reviewed in-house (MERGE-clean); code `aegis-crypto::{poseidon, nullifier::poseidon_nullifier, spend}`; decision `n1-nullifier-fix-design.md` §0.
>
> **Spec-history (do not "optimize" back):** earlier drafts represented the nullifier as an elliptic-curve point derived from the inverse relation `[1/(nk+rho)]·G`. Implementation review found that publishing a commitment-derived point admitted **witness malleability via an unconstrained blinding factor** (a prover could produce unlimited nullifiers for one note ⇒ double-spend). After evaluating a proof-preserving repair (P-REL, kept as a documented fallback in `n1-nullifier-fix-design.md` §0a) and this hash redesign, the protocol adopts the deterministic Poseidon nullifier — it achieves the consensus invariant (a unique deterministic identifier per spend) with fewer cryptographic assumptions and substantially simpler verification.

**⚠ The inverse-tag model below is the SUPERSEDED historical design** (retained for provenance of the D-A reasoning; the production form is the box above).

**Model (specified 2026-07-12, D-A; soundness of the *composed circuit* still gated on external review).** Neither reference verbatim: `coin.rs`'s revealed-rerandomized-pk + Schnorr is not adopted (weaker anonymity; as implemented not even a complete double-spend mechanism — fresh rerandomization each spend, nothing deterministic to check). We keep `coin.rs`'s **Curve Tree select-and-rerandomize membership + range proof** (the paper's audited core) and adopt the **curve-trees paper's inverse-tag nullifier** (ePrint 2022/756, native to the CT+BP algebraic setting — one inversion constraint) with **Orchard's structural-uniqueness discipline** grafted on. This is a fully-pinned construction, not a sketch:

1. **Split key hierarchy.** `sk → nk` (nullifier key), separate from spend-auth (`ak`) and viewing keys (`ivk`, `ovk`). The nullifier derives from `nk`, so only the spender computes it, the **sender never can**, and receipt-detection (IVK) stays cleanly separated from spend.

2. **Exact nullifier form:**
   ```text
   nf = [ 1 / (nk + rho) ] · G          (mod the E_odd scalar field; G the §0 base point)
   ```
   proven in-circuit by one inversion constraint: introduce witness `w`, constrain `(nk + rho)·w = 1` and `nf = w·G`. Cheap (no bit-hash). `nk + rho = 0` is impossible to hit adversarially (needs secret `nk`) and rejected at mint (N12).

3. **`rho` — structurally unique, with a defined base case (no unbounded recursion):**
   - **Transferred notes** (ShieldedTransfer output *j*): `rho_j = input_j.nf` — the nullifier consumed in the same tx. Input nullifiers are unique (nullifier set), so output `rho`s are unique by construction. Dummy inputs supply fresh, non-aliasing nullifiers (N5) as `rho` seeds even in a 1-real-input tx.
   - **Minted notes** (no shielded input to consume) seed `rho` from a globally-unique public mint context, terminating the recursion:
     - **PegMint:** `rho = H_ρ("aegis:rho:pegmint:v1" ‖ ergo_boxId)` — the Ergo `boxId` is globally unique and already in the used-set (I2).
     - **Coinbase:** `rho = H_ρ("aegis:rho:coinbase:v1" ‖ block_height ‖ network_id)` — unique per block.
   - `H_ρ` = the §0 XMD/SHA-256 expander into the E_odd scalar field.

Properties: `nf` is deterministic per note (replay → same `nf`, rejected by the consensus **nullifier set**, aegis-spec §9 step 4), unlinkable to the leaf or the key, uncomputable by the sender, and unique by construction across transferred *and* minted notes. No transparent "spent" flag exists.

**Nullifier is x-only — `nf = Extract((nk+rho)^{-1}·G)` (S2a rev 2, 2026-07-12 — resolves the tag=x-coord ±C ambiguity).** The tag is only the x-coordinate of the key commitment `C`, so a prover may witness either of `{C, −C}` (opening to `±(nk+rho)`), deriving `±nullifier_point` — a two-nullifiers-per-note double-spend vector if the nullifier were a full point. Resolution: **the consensus nullifier is the x-coordinate (Orchard's `Extract` discipline) of the nullifier point, 32 big-endian bytes** — `±point` extract identically, so both sign choices collapse to one `(tag, nf)` **by construction, at zero circuit cost**. The circuit reveals the full point (needed to open it as a randomness-zero commitment); consensus and the wire carry only the extract, and the node checks `Extract(revealed point) == wire nf`. Transfer-rho chaining is pinned as `rho_j = H_ρ("aegis:rho:transfer:v1" ‖ consumed nf)` (the 32-byte extract). A first-revision `sgn0(y)`-canonicalization of `C` (with a planned in-circuit parity constraint, ~255 mul constraints) is superseded — x-extraction achieves the same uniqueness for free and matches the Orchard precedent already adopted for `rho`. Implemented + adversarially sign-flip-tested natively in `aegis-crypto::{nullifier, keynote}`; the composed-circuit certification below still covers the argument.

**What review still owns (bounded, not open-ended):** not "design a nullifier" — that's done above — but *certify the composed circuit's soundness*: that inverse-tag + membership + range + public-fee balance + dummy handling glue with no cross-term leakage or malleability, that the `rho` recursion is well-founded (it is — every chain terminates at a mint base case), and that the inversion form has no soundness edge in the E_odd field. Historically this composition step is where shielded-pool bugs live (Zcash BCTV14 2018), so it gets an expert check before TVL — a *check of a finished spec*, not an unresolved fork.

> **Provenance:** the inverse-tag form is the curve-trees paper's own anonymous-payment construction (published analysis), so the primitive is not invented here. Its residual weakness — nonce uniqueness only *probabilistic* and sender-grindable (faerie-gold) — is closed by Orchard's deployed, audited `rho = consumed nf` trick plus the mint base cases above. Membership/range oracle vs `coin.rs` still stands (§8); the nullifier is vectored against this spec + an independent reimpl (coin.rs has no nullifier to vector against).

## 4. Transaction balance & range

A ShieldedTransfer with inputs `{note_i}` and outputs `{note_j}` proves, all in one Bulletproof over the CT circuit:

1. **Membership:** each input note is in the commitment tree (select-and-rerandomize; **leaf index HIDDEN** — that hiding is the anonymity mechanism; value/key hidden). ⚠ Corrected from an earlier "leaf index public" error (review N2/D-B). The reference's public-index *soundness caveat* applies to the second-level key-commitment select (N11), a distinct sub-step — spec separately.
2. **Ownership:** prover knows the spend authority for each input and derives its nullifier from `nk` (§3).
3. **Balance (N4):** `Σ value_in = Σ value_out + fee`. **`fee` is a circuit *constant*, not a committed/witnessed variable** — the verifier substitutes the public `sc_tx_fee` (a per-network consensus constant, aegis-spec params) directly into the constraint. A witnessed fee would let a prover pass a negative fee and mint `fee` per tx; a hardcoded constant cannot be signed away. The block-level tie to the emission box is a separate consensus check: **`Σ (fees of all ShieldedTransfers in block) = pot credit for the block`** (aegis-spec §11 emission-box mechanics) — a mismatch at the shielded↔pot boundary is an inflation path, so it is validated explicitly, not assumed.
4. **Range:** every output `value_j ∈ [0, 2^64)` (64-bit range proof), so no negative/overflow inflation (attack B3). With ≤2 inputs, `Σ < 2^65 ≪` the ~256-bit scalar field — no wrap-around.
5. **Nullifiers:** one `nf` per input (§3), each fresh vs the consensus nullifier set.

Outputs carry new `note_cm` + ciphertext. Proof size / timing per the spike (~4 KB, ~1.5–3 s prove, ~1–3 ms batched verify at the chosen tree depth).

## 5. Note encryption (receiver delivery)

Each output ships a ciphertext so only the receiver (and, via OVK, the sender) can open it:

```text
ephemeral: esk random; epk = esk·G_dh
shared    = KDF( DH(esk, recipient_pk) ‖ epk )
plaintext = (value, blinding, pk_rerandomization, memo)     # exactly what §1/§3 opening needs
ct        = AEAD_encrypt(shared, plaintext)                 # ChaCha20-Poly1305 (proven AEAD)
```

- Recipient scans with **IVK**: for each output, DH with `epk`, trial-decrypt; success = "mine" (aegis-spec §5). Wrong notes fail the AEAD tag cheaply.
- `memo` fixed-size (padded) so its presence/length leaks nothing.
- **OVK wrap is mandatory and fixed-size (N7).** Every output — real *and* dummy — carries a second `out_ct` slot of identical size (Sapling `out_ciphertext` discipline). A sender who doesn't want recovery fills it with random bytes. Making it *optional* would byte-distinguish outputs and fingerprint the sender's wallet, defeating §6 uniformity; so it is always present, never a variable-length tell.
- Wire, identical for every output: `(epk, ct, out_ct)` beside each `note_cm`.

## 6. Uniform transaction shape (metadata privacy)

Standing privacy rule (params.md) needs same-looking txs. **v1 fixed shape: exactly 2 inputs, 2 outputs** (Zcash-Sapling "pour" arity — also the spike's benchmark):

- Fewer real inputs → pad with **dummy inputs**. Fewer real outputs → pad with 0-value outputs to the sender.
- **Dummy realization (S3 decision, 2026-07-12): a dummy input is a self-owned zero-value note.** In curve-trees, membership is anchored to the public root *inside* the gadget structure (unlike Sapling's witnessed Merkle path), so conditional/gated membership is expensive and adds review surface. Instead a "dummy" is a real tree member the wallet owns with value constrained to 0: the circuit is unchanged (always 2 real memberships + ownership + nullifier), uniformity is maximal (dummies are cryptographically identical to real spends because they *are* real spends), and the only new work is wallet-side — maintain a small reserve of owned zero-notes (each transfer's 2 outputs can regenerate one). Bootstrapping a fresh wallet's first zero-note comes from PegMint/coinbase (mint side). This resolves g16 N5 with **zero consensus/circuit cost**; the in-circuit `is_real`-flag and disjunction alternatives are rejected as costlier. The still-referenced rules below (value==0, fresh non-aliasing nf) are then automatic: a zero-note has its own key material and its own nullifier.
- **Dummy-input rules (N5) — SUPERSEDED wording, kept for the trail.** The rules below were drafted for non-member dummies; under the S3 zero-note realization every rule holds *automatically*, so there is no separate dummy branch to enforce:
  - ~~`value == 0` circuit constraint on non-membership-proved dummies~~ → a zero-note's value **is** 0 inside its ordinary membership-proved commitment; inflation is blocked by the same balance+range constraints as any spend.
  - ~~fresh per-tx `nk`/`rho` for a synthetic dummy `nf`~~ → a zero-note has its **own genuine key material and nullifier** (unique, non-aliasing, inserted/checked like any nf), and seeds output `rho` via the normal §3 chain. Nothing synthetic exists to leak arity.
  - ~~uniform real/dummy branch with a zero-value witness~~ → there is **no branch**: the circuit always proves 2 real memberships + ownership + nullifiers. Uniformity is by identity, not by construction.
  - **New obligation this creates (wallet/mint, not circuit): the zero-note reserve.** A wallet must own ≥1 unspent zero-note to pad a 1-real-input spend; each transfer can regenerate one as an output, and **PegMint/coinbase must mint a paired zero-note alongside a wallet's first value note** (else a fresh wallet with exactly one note cannot transact) — spec this in peg.md/G2.5 (DEFERRED).
- Every ShieldedTransfer is byte-identical: 2 nullifiers, 2 output `note_cm`, 2 `(epk, ct, out_ct)`, one public fee, one proof. Amount, sender, receiver, and real-vs-dummy count all hidden.
- Consequence: consolidating >2 notes or paying >2 recipients = multiple txs (acceptable; flat fee each). Larger fixed arities (2→4) are a tunable knob — bench before changing (proof cost scales with arity).

## 7. Genesis / empty-tree constant

`EMPTY_TREE_ROOT` is a **sentinel constant for the empty leaf set** (pinned in `aegis-node` genesis): the reference Curve Tree cannot represent an empty set, so consensus maps "no leaves yet" to the sentinel and real CT roots exist only from the first leaf (G2-P2 decision — this keeps the genesis id stable and needs no empty-tree construction).

**Empty/unused child slots (N10 — resolved stronger than drafted).** The reference encodes an absent child as x-coordinate **0** in the parent's vector commitment, and **x = 0 is not on `y² = x³ + 7` over either cycle field (7 is a quadratic non-residue mod p and mod n — verified 2026-07-12)**: the filler is unopenable in the strongest sense — the point does not exist, so no `(value, tag, blinding)` opening can ever be presented and the in-circuit on-curve check rejects any attempt to select an empty slot. This supersedes the earlier plan to fill slots with a NUMS point (tag `"aegis:empty-leaf:v1"` — that generator remains derived and vectored, but is not load-bearing for v1). Flagged for the external reviewer alongside the composed-circuit check. v1 adopts the reference convention unchanged; any deviation is chain-id-breaking.

## 8. Test-vector obligations (oracle discipline)

> **Oracle split (resolved with D-A):** `coin.rs` emits no nullifier, so it is the oracle **only** for Curve Tree membership + range-proof bytes. The §3 nullifier is vectored against the chosen Orchard-style construction's own spec + an independent reimplementation, and gated on external crypto review — not against `coin.rs`.

Consensus-critical byte formats need external oracles (CLAUDE.md rule), but Aegis has **no reference node** — so the oracle is the **vendored reference implementation itself**, pinned:

- Membership + range-proof bytes cross-checked against `curve-trees` `coin.rs` outputs for fixed seeds → vectors under `test-vectors/aegis/`.
- Nullifier bytes vectored against the §3 Orchard-style construction's own spec + an independent reimplementation (not `coin.rs`, which has no nullifier).
- Generator derivation (§0) vectored from the published seed + hash-to-curve so third parties reproduce every generator.
- This is consistency-with-the-audited-construction, not self-oracle; it is the strongest available until external review (security gate before TVL).

## 9. Open items (→ DEFERRED.md)

| Item | Note |
|---|---|
| Exact nullifier algebraic form (§3) | Inversion vs Orchard additive; **external crypto review** owns this |
| Memo size | Fixed length — pick after wallet UX |
| Fixed arity 2-in/2-out vs 2→4 | Bench-driven; privacy vs proof cost |
| R1-T verifiable-encryption gadget | Only if threshold turnstile adopted (post-v1) |
| AEAD / KDF / hash-to-curve exact primitives | ChaCha20-Poly1305 / HKDF-SHA256 / RFC 9380 SSWU provisional; pin at freeze |

*Resolved since draft:* nullifier collision (N1, §3 `rho`), leaf-index (N2, §4), generators (N3, §0), fee-in-circuit (N4, §4), dummy notes (N5, §6), OVK slot (N7, §5), diversified addresses (N9, §2), empty-slot filler (N10, §7), secret-index caveat (N11, §3).
