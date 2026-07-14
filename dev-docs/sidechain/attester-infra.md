# Attester infrastructure (U1-strong S1 + R1-T threshold decrypt)

**Status:** implementable spec (2026-07-15). Supersedes the S1 sketch in
`notes/archive/design-mitigations.md` §S1 with a buildable design + slice
plan. Prereq for both the **bridge peg-out** (U1-strong, C1 "before serious
TVL") and **R1-T storage-rent recycle** (aggregate decryption). Neither the
set nor the key exists in code yet — this is greenfield.

> **Value gate:** the threshold-decryption key + the R1-T verifiable-
> encryption gadget are crown-jewel crypto → external cryptographer review
> before real USE. Testnet is free (chain-id-breaking re-cut allowed).

## 1. Why one set, two roles

A single **k-of-n attester federation** (majority-honest; staked/slashable
is future) serves two jobs. Same membership, two *independent* crypto keys:

| Role | Job | Crypto | Verified where |
|---|---|---|---|
| **R1 — bridge unlock (S1)** | Attest that a peg-out's burn is on the attesters' best Aegis chain, so Ergo will pay the vault | **k-of-n signatures** on secp256k1 | **Ergo consensus**, via native `atLeast` |
| **R2 — R1-T aggregate** | Decrypt *only the sum* of an epoch's hidden migration values, so expired USE can be swept | **k-of-n threshold decryption** (exponential ElGamal) | Aegis consensus reads the signed posted aggregate |

Attesters are **not** the vault custodian (they cannot spend the vault
alone) and run `aegis-node` (they have an independent view of the canonical
tip). Trust assumption: `< k` are malicious/colluding.

**Failure modes are all safe-direction.** Quorum down ⇒ bridge unlocks
stall (value sits over-reserved in the vault, I1 holds) and R1-T sweeps
don't happen (lost USE strands longer — the R0 status quo). Nothing becomes
unsound; liveness degrades.

## 2. Identity & keys

Each attester holds **one secp256k1 keypair**: secret scalar `sk`, public
point `pk` (33-byte SEC1-compressed). That 33-byte point **is** an Ergo
`GroupElement`, so the *same* `pk`:

- drops into the Ergo peg-out vault as `proveDlog(pk)` inside
  `atLeast(k, Coll(proveDlog(pk_1), …, proveDlog(pk_n)))` — **Ergo verifies
  k-of-n in consensus for free**, no custom signature-verification script;
- signs the Aegis-side standalone `Attestation` (ECDSA, deterministic
  RFC-6979, low-S) over a domain-separated message — used for gossip,
  audit, the S2 extension-commit path, and R2's aggregate posting.

The threshold-decryption key (R2) is a **separate** joint key over the same
member set (see §5), because homomorphic threshold decryption ≠ signing.

## 3. The attestation primitive (Role R1 substrate — SLICE S1a, this build)

`aegis-attest` crate:

- `AttesterKey` — secp256k1 keypair; `AttesterId` = `blake2b(pk)[..16]` or
  the compressed `pk` itself (canonical, ordering-stable).
- `AttesterSet { members: Vec<pk>, k: usize }` — sorted-unique members, a
  threshold `k`, a canonical `set_id` (hash of ordered members ‖ k) so a
  signature can't be replayed against a different set.
- `Attestation { signer: pk, sig }` — an ECDSA signature over
  `H("aegis:attest:v1" ‖ set_id ‖ purpose_tag ‖ payload)`. `purpose_tag`
  separates unlock attestations from R1-T aggregate posts from tip
  attestations, so one can never be replayed as another.
- `sign(key, set, purpose, payload) -> Attestation`
- `verify(set, purpose, payload, att) -> bool` (member + valid sig)
- `verify_threshold(set, purpose, payload, atts) -> bool` — **k distinct
  members** each with a valid signature (dedupe by signer; reject
  non-members and duplicates).

Proven crate only (`k256` ECDSA); no hand-rolled signatures.

## 4. Bridge wiring (Role R1 — slices S1b–S1d, follow-on)

- **S1b** — `aegis-node` attestation service: on a schedule / on demand,
  sign the node's best-chain tip digest `(digest D, height, epoch)` and
  serve/gossip it (`/aegis/v1/attest/tip`). An unlock attestation signs the
  unlock intent (burn id, claimant, amount, D).
- **S1c** — Ergo `PegVault.es`: replace the U1-dogfood custodian condition
  with `atLeast(k, Coll(proveDlog(pk_i)))` over the registered set, ANDed
  with the existing `DoubleRedeem`-fresh + `T_delay`-elapsed + burn-binding
  conditions. Peg-out = attesters co-sign the unlock tx.
- **S1d** — registry box: an `AttestRegistry` singleton-NFT box on Ergo
  carrying the current `{pks, k}`; rotation = spend it under the current
  set's `atLeast`. Aegis mirrors the registry for its own checks.

Params: `attest_k / attest_n` = **2/3 dogfood → 3/5 testnet**
(`design-mitigations.md`). Pin per-network in `params.md` at each cut.

## 5. R1-T wiring (Role R2 — deferred, crown-jewel)

- **R2 key** — a k-of-n **threshold exponential-ElGamal** key over the same
  members. Generation: **DKG** (n-party, no trusted dealer) preferred;
  trusted-dealer acceptable for dogfood. *DECISION DEFERRED* (needs the
  external review that gates real value anyway).
- **Verifiable-encryption gadget** — each migration proves in-circuit that
  its ciphertext encrypts the same value its note commits to. Additively
  homomorphic ⇒ the epoch aggregate = product of ciphertexts; k-of-n
  decrypt the aggregate via small-range discrete log. This is the R1-T
  circuit line item (bench first; `g15-proving-spike.md` §4).
- **Aggregate posting** — attesters `verify_threshold`-sign the decrypted
  epoch sum (purpose_tag = `r1t-aggregate`); Aegis consensus sweeps
  `expired = epoch_total − sum` → emission box.

Full R1-T epoch machinery (per-epoch trees + nullifier archival + sweep) is
its own consensus track (`storage-rent-privacy-tradeoffs.md`), chain-id-
breaking, buildable on this substrate once R2 exists.

## 6. Slice plan

| Slice | Deliverable | Blocked on | Chain-id-breaking |
|---|---|---|---|
| **S1a** | `aegis-attest` substrate: keys + set + attestation + k-of-n verify | — (**this build**) | no |
| S1b | node attestation service + `/attest/tip` | S1a | no (additive API) |
| S1c | `PegVault.es` `atLeast` k-of-n unlock | S1a + contract review | Ergo-contract redeploy |
| S1d | `AttestRegistry` NFT box + rotation | S1c | Ergo-contract |
| R2-key | threshold ElGamal key + DKG | S1a + **external review** | no |
| R2-gadget | in-circuit verifiable encryption | R2-key + review + bench | (circuit) |
| R1-T | epoch machinery + aggregate sweep | R2-* | **yes** (Aegis consensus) |
