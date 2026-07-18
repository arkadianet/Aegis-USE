# M4 — wallet + keys (design)

> **⚠️ LEGACY design (Curve-Trees era).** The STARK/PQ pivot this doc anticipated
> *happened*: Aegis is hash-native ([ADR](./adr-hash-native-engine.md)) and the
> live wallet is **`aegis-hn-wallet`** (`engine/wallet` — keystore, scanner, tx
> building, built and integrated), not the `aegis-wallet` crate described here.
> The key-hierarchy / address / scan *concepts* below still inform it; the
> proving-facing details are superseded.

> The **send / receive / verify-a-payment** layer — the actual point of a private
> payment chain. This is a *design*; the key-hierarchy / address / scan
> *orchestration* is buildable under the freeze-hold, but note-encryption and the
> proving-facing code are **held** (they may change under a STARK/PQ pivot — see
> `stark-native-decision.md`). Build it in slices when the freeze lifts.

## 0. Architecture decision: a standalone `aegis-wallet`, not in the node

The wallet is a **separate crate + binary (`aegis-wallet`)**, never linked into
`aegis-node`. Non-negotiable reason:

> **Spending keys must never live in a network-exposed process.** The node runs
> P2P, mining, and a public HTTP API. If the wallet's keys sit in that process, a
> node compromise is a *funds* compromise. Keys, note-scanning, transaction
> building, and proving all live in the wallet process; the node never sees a
> secret.

This is the mature-design consensus (Zcash/Zebra keep the wallet out of the full
node; Bitcoin Core moved the wallet to a separate process). It also buys:

- **Proving isolation** — heavy Bulletproofs proving stays off the node's hot path.
- **Deployment flexibility** — wallet on a laptop, node on a server; many wallets
  against one node; a future *light* wallet that scans a served ciphertext feed
  without running a full node.

**The seam is the node's read-only HTTP API — which already exists (M3/M5):**

| wallet needs | node endpoint |
|---|---|
| scan for incoming notes + rebuild the note-commitment tree | `GET /aegis/v1/blocks` + `GET /aegis/v1/block/{id}` (raw block bytes → decode transfers → outputs' `(epk, ct, note_cm)`) |
| sync status / tip | `GET /aegis/v1/tip`, `/state` |
| confirm a spend landed | `GET /aegis/v1/nullifier/{hex}` |
| send | `POST /aegis/v1/tx` |

So the wallet is a **client of the node**, reachable over that API. Shared code
lives in `aegis-crypto` (note commitments, nullifiers, key math, the spend/mint
proofs) + `aegis-spec` (constants, wire formats) — both crates the node already
uses, so no duplication and no fork of logic.

```
aegis-wallet (bin)  ──HTTP──▶  aegis-node  (/aegis/v1/*)
     │ depends on
     ├── aegis-crypto   (keys, notes, nullifiers, proving)
     └── aegis-spec     (constants, wire formats)
```

*Note-availability caveat (honest):* to scan, the wallet downloads every output
ciphertext — which on a private chain is the wallet protocol anyway (Zcash/Monero
prove this is fine; the design's "privacy chains are DA-friendly" principle). A
later **compact-block / ciphertext-feed** endpoint is an optimization, not a
prerequisite; v1 scans full blocks via `/block/{id}`.

## 1. Key hierarchy (Aegis-shaped, over our cycle curves)  *(built — slice 1)*

> Corrected from the first sketch: Aegis's spend authority is the **scalar `nk`**
> the note protocol already uses in `poseidon_nullifier(nk, rho)` — there is **no
> Sapling `ak`/`ask` point layer** (spending is a proof of knowledge of `nk`, not
> a separate spend-auth signature). So the hierarchy is simpler and `nk`-centric.

One **spending key** `sk` (a 32-byte root) derives three domain-separated,
one-way capability tiers (`aegis-wallet::keys`):

- **`nk` (OddScalar) — SPEND.** `nk = hash_to_field_one("aegis:wallet:nk:v1", sk)`.
  Whoever holds it can compute nullifiers and prove ownership — the crown secret,
  never shared, never inside a viewing key. It *is* the note protocol's `nk`: one
  scheme, not two.
- **`ivk` (EvenScalar) — INCOMING VIEWING.** `ivk = hash_to_field_one(
  "aegis:wallet:ivk:v1", sk)`. Detects + (later) decrypts notes *received*, and
  generates addresses; **cannot spend**. Safe to share for watch-only access.
- **`ovk` (32 bytes) — OUTGOING VIEWING.** `blake2b256("aegis:wallet:ovk:v1"‖sk)`.
  Lets the *sender* recover the notes it sent (history + disclosure).

`ivk`/`ovk` are independent one-way functions of `sk`, so they reveal nothing
about `nk`. Note there is an inherent Aegis property: *detecting your own spends*
means recognizing your nullifiers, which needs `nk` = spend authority — so a
view key that sees your spends is a spend key. The safely-shareable key is
therefore `ivk` (incoming-only). These derivations are **wallet-local** (not
consensus) and **v1/provisional** pending a ZIP-32-style spec + external review.

## 2. Diversified addresses

A wallet has one `ivk` but **many unlinkable addresses**. A **diversifier** `d`
(random 11 bytes) maps to a diversified base `g_d = DiversifyHash(d)`; the address
is `(d, pk_d = ivk·g_d)`. Encoding: a Bech32m string with an Aegis HRP
(`use1…` / testnet `tuse1…`), payload `d ‖ pk_d`. Two addresses from the same
wallet are unlinkable on-chain (different `g_d`), but both are scanned by the one
`ivk`. Change goes to an internal diversified address.

## 3. Note encryption & scanning  *(freeze-held: KEM may become PQ)*

Each transfer output already carries `(epk, ct, out_ct)` on the wire (see
`tx.rs::ShieldedOutput`). Sending to `(d, pk_d)`:

1. sample `esk`, `epk = esk·g_d`; shared secret `s = esk·pk_d` (recipient recovers
   it as `ivk·epk`); derive a symmetric key `KDF(s, epk)`.
2. `ct = ChaCha20-Poly1305(key, note-plaintext)` — plaintext = `(d, value,
   rho/rseed, memo)`. `out_ct` is encrypted under a key derived from `ovk` so the
   *sender* can recover the same note later.

**Scanning (IVK scan):** for every output the wallet sees, compute `s = ivk·epk`,
derive the key, trial-decrypt `ct`; success ⇒ an incoming note. Trial-decryption
per output is the standard cost and is why the wallet downloads everything.

> **PQ hook (from the STARK discussion):** this KEM is ECDH-style ⇒ **not**
> post-quantum. Keep the note-encryption layer **modular** behind a KEM interface
> so a PQ-KEM swap (if the chain goes PQ) touches only this module. This is a
> reason encryption is held under the freeze — it's the layer most likely to
> change.

## 4. Wallet state

Reconstructed from the node's blocks, persisted locally (encrypted at rest):

- **note-commitment tree** — the wallet rebuilds the *same* Curve Tree the node
  does (from the note_cm leaves it scans), so it can produce membership witnesses.
- **my unspent notes** — `(note, position, witness)`; witnesses updated as new
  leaves append.
- **my nullifiers** — to detect when my notes get spent (mark spent when the
  nullifier appears on-chain).
- **address book / diversifier index**, and a **zero-note reserve** (the S3 dummy
  path: self-owned value-0 notes for the fixed 2-in/2-out arity, topped up by
  self-spends).

## 5. Sending (2-in/2-out)

1. select input notes covering `value + fee` (top up with a zero-note if only one
   real input — the S3 reserve);
2. build outputs `[payment, change]`, encrypt each to its recipient (§3);
3. generate the spend proof (`aegis-crypto::spend::prove_transfer`) against the
   current anchor from `/state`;
4. assemble the wire `ShieldedTransfer`, `POST /aegis/v1/tx`;
5. confirm via `/nullifier/{hex}` once mined.

The "pay 16 with several $1 notes" case (raised early): fixed arity ⇒ the wallet
**chains** transfers (consolidate small notes first), or it's the motivating case
for the variable-arity the STARK direction would enable — noted, not solved here.

## 6. Verify a payment  *(the headline UX — "how do I verify they got it?")*

Three tiers, by who's asking:

- **Recipient** confirms receipt: their `ivk` scan surfaces the note ⇒ they *see*
  the 10 USE arrived, no interaction with the sender needed.
- **Sender** proves they paid: using `ovk` they recover the output note and reveal
  a **payment disclosure** — `(recipient address, value, the note opening, and the
  tx/nullifier locating it on-chain)` — which a third party checks against the
  public `note_cm` on-chain. Proves "I paid *this* amount to *this* address,"
  without exposing the sender's other notes or spend key.
- **Auditor** (optional): give a `ivk`/`ovk` (view-only) for full incoming/outgoing
  history without spend authority.

## 7. `aegis-wallet` CLI (shape)

```
aegis-wallet init                 # generate sk, print a shielded address
aegis-wallet address [--new]      # a fresh diversified address
aegis-wallet scan  --node URL     # sync: pull blocks, IVK-scan, update tree/notes
aegis-wallet balance              # sum of unspent notes (local, private)
aegis-wallet send --to <addr> --value <n> --node URL
aegis-wallet verify-received <note-ref>       # recipient-side confirmation
aegis-wallet disclose <tx>        # emit a payment disclosure (sender side)
```

Keys in an encrypted keystore; `--node` is the only outward contact, and it's the
public read-only API — the node never receives a secret.

## 8. Build slices (when the freeze lifts)

1. ✅ **DONE — Keys + addresses.** `aegis-wallet` crate + CLI; `sk`→`nk/ivk/ovk`
   (§1); diversified Bech32m addresses (`use1…`/`tuse1…`); redacted key Debug.
   Standalone binary, no node contact. Built on reviewed `aegis-crypto` h2c
   primitives; 8 tests; freeze-hold-safe + hybrid-independent.
2. **Node client + scanning-orchestration** (fetch blocks, rebuild the tree,
   track notes) — the plumbing; the *decrypt* step stubs until slice 3.
3. **Note encryption / IVK decrypt** (held — modular KEM).
4. **Send** (build + prove + submit) — held (proving-facing).
5. **Verify / disclose** (held — depends on 3–4).

Slice 1 (and the client plumbing of 2) is buildable under the freeze **and is
independent of the hybrid decision** — the key/address layer is the same whether
the private core stays Curve Trees or pivots. Encryption + proving (3–5) wait on
the freeze / the STARK call.
