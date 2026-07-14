# Payment primitive: address-binding notes (first pass)

**Status:** first pass, NOT production-sound; awaiting adversarial review.
**Crate:** `aegis-crypto` (module `payment`).
**Branch:** `feat/payment-primitive`.

## 0. Problem

Today a note's ownership binds the **secret** spend key `nk`. The note tag is
`consensus_note_tag(nk, rho, r_key) = (K + Δ).x` where
`K = (nk + rho)·B + r_key·B_blinding` on the odd curve (`spend.rs`,
`keynote.rs`). Forming the tag requires `nk`, so only the key holder can create
their own notes — **self-notes only**. There is no address / `pk_d` / recipient
concept in `aegis-crypto`. Real payments (sender creates a note a *different*
party can spend) cannot be expressed.

Requirement: a note must bind the recipient's **public** address value (which
the sender knows), the spend circuit must prove the spender knows the secret
behind that address, the nullifier must stay unforgeable + unlinkable (the N1
property), and the sender must never learn the spend secret.

## 1. Construction (what is implemented)

The key commitment `K` is an **additively homomorphic** Pedersen commitment.
Publish the recipient's spend key as a **point**:

```
PaymentAddress:  pk = nk·B          (odd curve, B = tree odd Pedersen base)
```

A sender who knows only `pk` (never `nk`) forms the *same* `K` additively,
choosing `rho` (per §3 rho-discipline) and `r_key`:

```
K = pk + rho·B + r_key·B_blinding
  = (nk + rho)·B + r_key·B_blinding          (because pk = nk·B)
tag = (K + Δ).x
cm  = commit([value, tag], blinding)         (the ordinary spendable leaf)
```

The resulting leaf commitment is **byte-identical** to the note the `nk`-holder
would build (test `sender_note_equals_recipients_reconstruction`). The recipient
receives the opening `(value, blinding, rho, r_key)` out-of-band, adds their own
`nk`, and spends the note through the **unchanged** §3 circuit
(`prove_transfer` / `verify_transfer`) — no new circuit gadget.

API (`payment.rs`):
- `PaymentAddress::from_nk(nk) -> pk = nk·B`; `to_bytes`/`from_bytes` (33 B).
- `sender_build_note(addr, value, rho, r_key, blinding) -> (cm, PaymentOpening)`.
- `output_to_address(addr, …) -> (TransferOutput, PaymentOpening)` — the "pay a
  recipient" analogue of a raw self-tag output.
- `recipient_note_opening(nk, opening, leaf_index) -> NoteOpening` — feeds
  straight into `prove_transfer`.

**Wire format:** unchanged. The leaf is the same `commit([value, tag], blinding)`
(33-byte cm), the proof is the same `TransferProof`, the nullifier is the same
`Poseidon(nk+rho)`. Only note *construction* moves off `nk`. Not chain-breaking.

## 2. Soundness argument

Let `pk = nk·B` be the recipient address; `B`, `B_blinding` the tree's odd
Pedersen bases (independent NUMS generators).

**No theft (only the `nk`-holder can spend).** To spend, the circuit requires
the prover to open `K` to the scalar `x = nk + rho` in the odd CS
(`odd_prover.commit(x, r_key+r_t)` must equal the leaf-bound `C*`; `spend.rs`).
Pedersen commitments are binding: given `K = x·B + r·B_blinding`, the pair
`(x, r)` is unique, so the only opening is `x = nk + rho`. Producing the scalar
`x` requires `nk = dlog_B(pk)`, which the discrete-log assumption denies to
anyone but the recipient. The sender knows `rho, r_key, pk` but not `nk`, so the
sender cannot open `K` either → the sender cannot spend the note it created.
Adversarial test `non_recipient_cannot_spend`: a party with the full opening but
a wrong `nk` derives a tag that does not match the committed leaf →
`SpendError::WrongOpening`.

**No inflation.** Value conservation is entirely in the reused circuit: the
in-circuit balance constraint `Σin = Σout + fee` with the fee substituted by the
verifier (N4). Construction does not touch it. Test `value_is_conserved`.

**Nullifier unforgeable + unlinkable + non-malleable (N1 preserved).** The
nullifier is `Poseidon(x)`, `x = nk + rho`, exactly as in the audited N1 fix —
a field element with no free/blinding component, pinned by `K` which is pinned
by the leaf tag. The construction changes *who computes the tag*, not the tag's
algebraic form, so the N1 argument (including the `Δ` sign-breaker) carries over
verbatim. A note yields exactly one nullifier regardless of proof randomness
(test `one_note_yields_exactly_one_nullifier`); altering a revealed nf rejects
(pre-existing `tampered_nf_rejected`).

**Sender-unlinkability (a bonus vs. a naive design).** Because the nullifier is
keyed on `nk` and the sender lacks `nk`, the sender **cannot** compute the
recipient's future nullifier and therefore cannot link the note commitment to
its later spend (test `revealed_nullifiers_are_nk_bound`).

## 3. Why no in-circuit scalar-mult gadget was needed

The brief anticipated an in-circuit variable-base scalar-mult gadget proving
`pk_d = ivk·g_d`. That is the Sapling approach and would be necessary if the
note bound a point on a *different* key than the one the nullifier/opening uses.
Here the recipient's public key is folded **additively** into the same
Pedersen key commitment the circuit already opens, so the discrete-log knowledge
("prove you know the secret behind the address") is discharged by the existing
"open `K` to `x`" step for free. The vendored `re_randomize` fixed-base
scalar-mult gadget (`vendor/curve-trees/relations/src/rerandomize.rs`) *is*
available and *is* the tool the Sapling-faithful variant would use — see §4.

## 4. What this does NOT do (deliberate first-pass scope / blockers)

1. **Address key = spend key, not a viewing key.** The address is `nk·B`, so it
   binds the **spend** key `nk` (Aegis's designated spend authority; `keys.rs`
   states "spend authority is the SCALAR `nk`"), not the incoming-viewing key
   `ivk`. The brief's literal target is `pk_d = ivk·g_d` with the nullifier
   keyed on a *separate* `nk`. Achieving that soundly requires an **in-circuit
   `nk ↔ ivk` binding**: with the address bound to `ivk` but the nullifier keyed
   on an independent `nk`, nothing forces the spender to use the "right" `nk`, so
   they could reveal multiple valid nullifiers for one note → double-spend (the
   N1 malleability class returns). The current KDF derives `nk` and `ivk` as
   independent hashes of `sk` with no algebraic relation, so binding them
   in-circuit means either proving the hash preimage `sk` in-circuit or
   redesigning the key hierarchy — **N1-scale work**, and the reason this pass
   collapses address-key and nullifier-key into the single secret `nk`.
   Consequence: you cannot hand out an address-deriving + detecting capability
   that *cannot* spend. Note-detection can still use a separate `ivk` at the
   encryption layer; that is a wallet concern, not modelled here.

2. **No in-circuit diversified addresses.** One `nk` → one address point `nk·B`.
   On-chain unlinkability across notes to the same address still holds (each
   leaf's tag is randomized by per-note `rho` and `r_key`, and `pk` itself never
   appears on chain), so this is weaker than Sapling diversification only in the
   sense that the *address string* is reused between a sender and receiver.
   Diversified `g_d` (a per-address base) would need the variable-base scalar
   mult of §3 to remain hidden — deferred.

3. **Note encryption / opening transport is out of scope.** The recipient must
   receive `(value, blinding, rho, r_key)`; the encrypted-note channel and the
   `ivk`-based trial-decryption are wallet/protocol layers.

4. **`rho` discipline is the caller's responsibility.** Soundness of the
   nullifier's structural uniqueness (§3) requires the sender pick `rho` per the
   rho-discipline (e.g. `rho_transfer(consumed_nf)`); the module does not
   enforce it.

## 5. Points a cryptographer must check

- The binding claim in §2 ("opening `K` to `x` requires `dlog_B(pk)`") rests on
  Pedersen binding of `K` under independent `B`, `B_blinding` AND on the leaf
  tag pinning `K` up to the `±/Δ` ambiguity handled by the existing N1 argument.
  Confirm the additive re-derivation of `K` introduces no new representation of
  the tag that opens to a different `x` (I believe it does not — `K` is
  identical to the self-note `K` — but this composes with the unreviewed N1
  `Δ` sign-breaker).
- Whether collapsing address-key and nullifier-key into `nk` is acceptable for
  the intended threat model, or whether the viewing/spend separation (blocker
  #1) is a hard requirement — in which case this pass is a stepping stone, not
  the final primitive.
- `rho`/`r_key` reuse across two notes to the same address produces two leaves
  with the same tag; confirm the protocol's rho-discipline precludes it.
