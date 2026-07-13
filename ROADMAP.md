# Aegis roadmap

From today (a reviewed consensus + crypto core) to a **complete, merge-mined,
private-USE sidechain** — and, separately, to *real value* (an audit gate that is
deliberately kept off the critical path).

See [`dev-docs/sidechain/architecture.md`](dev-docs/sidechain/architecture.md)
for the system map this roadmap sequences, and
[`dev-docs/sidechain/DEFERRED.md`](dev-docs/sidechain/DEFERRED.md) for the
living open-items register.

> ⚠️ **Unaudited, testnet-only, no real value.** Every milestone below builds
> and runs on **testnet**. Real USE moves only after the **value gate** (below)
> — an external-review track that is *not* a build milestone.

---

## Where we are

**Done — L0 consensus + crypto core (built + adversarially reviewed):**
shielded crypto (nullifier soundness closed), the peg-in verifier (objectivity +
receipt binding, green on real testnet chain data), the six peg-out contracts
(reviewed, deployed + fixed on testnet, now a first-class compiled+hash-pinned
crate), block/chain/state, difficulty, and crash-safe persistence — extracted
into this repo, git-depending the Ergo crates at a pinned tag.

**Today the binary is a dev block-producer, not a networked node** — no P2P, no
API. The milestones below build the operational chain around the proven core.

---

## Milestones

Sizes are rough; each ships testable and gets reviewed.

### M0 — Contracts first-class ✅ DONE
`aegis-contracts` crate: the six `.es` compiled via the pinned `ergo-compiler`,
tree-hashes pinned as tested constants, **oracle-verified byte-for-byte against
the live testnet deployment**. *(small)*

### M1 — Testnet re-provision *(next)*
Mint **100,000,000 tUSE** (10¹¹ base units, 3 decimals), redeploy fresh peg
contracts using M0's compile-and-pin tooling (so deployed hashes provably match
the pinned constants), and record a distribution-ready testnet supply. *(small)*

### M2 — Merge-mining *(the keystone)*
Bind Aegis blocks to Ergo's proof-of-work — the feature that makes this a real
merge-mined sidechain, and simultaneously its **security, block-ordering,
fork-choice, and fresh-node sync** (architecture §4/§5). Staged:
- **M2a** commitment-tx builder + submitter (Aegis → a stock Ergo `/transactions`
  call, so *any* Scala **or** Rust node can mine it with zero modification).
- **M2b** extend the follower to **watch Ergo for the commitment** and verify its
  inclusion — reusing the peg-in inclusion machinery already built.
- **M2c** the consensus rule: *canonical Aegis = the chain Ergo's PoW committed
  to*, ≥ `N_mint` deep. *(large)*

### M3 — Node shell (API + mempool + wiring)
Turn the producer into an inspectable node: an HTTP/RPC API (submit a shielded
tx, query chain/state/peg), a mempool to accept + order transfers, the follower
running continuously in the main loop, and the peg verifier wired to `Chain`.
*(medium)*

### M4 — Wallet + keys
Make *send / receive / verify a payment* real: the split key hierarchy
(`ak`/`nk`/`ivk`/`ovk`), note encryption (ChaCha20-Poly1305), incoming-viewing-key
scanning, diversified addresses, and payment disclosures (architecture §6). This
is what lets a recipient confirm "I received 10 USE" and a sender prove it.
*(medium-large)*

### M5 — Indexer + explorer
A **peg + activity + merge-mining dashboard** — the only things a private chain
can publicly show (blocks, tx counts, merge-mining proofs, the transparent peg /
pool size), never shielded parties or amounts (architecture §7). *(medium)*

### M6 — P2P
Multi-node body distribution + seed discovery. **Lighter than a normal chain's
P2P**: Ergo already provides discovery/ordering/fork-choice, so this is a
body-availability layer keyed by Ergo-committed hashes, with untrusted peers
(verify each body against its committed hash; a bad peer can withhold, never
forge). v1 can start with a seed/snapshot server and add gossip later. *(medium)*

### M7 — Mainnet hardening
Light-wallet sync, operator tooling, the storage-rent turnstile (R1-T), receipt
tokens, and the **testnet → mainnet re-cut** (new genesis + Ergo anchor + `USE`
token constants — a re-cut, not a migration; architecture §9). *(ongoing)*

---

## The value gate (cross-cutting — gates *real value*, not milestones)

Independent of the milestones, **no real USE moves** until an external-review
track completes. These are calendar/human-gated, not code:

- **Composed-circuit soundness** — external cryptographer certifies the 2-in/2-out
  shielded-transfer circuit (`external-review-brief.md`).
- **Poseidon-over-F_p parameters** — round counts / constants sign-off.
- **`delta ⊥ {B, B_blinding}` (NUMS)** ownership-binding assumption.
- **Peg-in objectivity margins** — the absolute-work floor + `N_mint` reorg margin.
- **Peg-out C1** — move off the v1 `V_cap`-bounded trusted attester to U1-strong
  attesters or SPV-in-consensus.

A **functionally complete testnet chain (M0–M6) is reachable without any of
these** — which is the point: build and prove the whole thing on testnet, get it
audited, *then* flip mainnet. Compilation and green tests prove consistency, not
soundness.

---

## Naming

The asset **is `USE`** — 1:1 backed and redeemable, the *same value* as mainnet
USE, just shielded (Lightning-BTC-is-still-BTC). On **testnet** the stand-in is
**`tUSE`**. **"Aegis"** is the chain/protocol; **"Aegis-USE"** is this repo. In
prose, disambiguate as *"shielded USE"* / *"private USE"* — never a separate
token brand, which would break the 1:1 fungibility premise.
