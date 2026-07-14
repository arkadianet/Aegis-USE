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

> 🧊 **FREEZE-HOLD (active).** A [STARK-native architecture decision](dev-docs/sidechain/stark-native-decision.md)
> is **OPEN** and gated on a bounded spike. Until it reports and the operator
> decides: **do not** commit chain-id-breaking params (share interval, `L_final`,
> `V_CAP`, mainnet constants), **do not** do the testnet→mainnet re-cut, **do not**
> freeze `aegis-spec`/`note-protocol`, and **do not** harden the Curve Trees crypto
> (esp. the deferred incremental-tree append — a pivot may discard it). Safe to keep
> building in parallel: M3 (API/mempool), M5 (explorer), the ergo-side integration,
> and the *non-proving* parts of M4 (key hierarchy / addresses / scan design).

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

### M1 — Testnet re-provision ✅ DONE
Minted **100,000,000 tUSE** (10¹¹ base units, 3 decimals), redeployed fresh peg
contracts via M0's compile-and-pin tooling (deployed hashes provably match the
pinned constants — the crate was the *pre-deploy* oracle). Vectors +
distribution-ready supply in `test-vectors/testnet/peg-v3/`.

### M2 — Merge-mining ✅ DONE (dev) — the keystone
Binds Aegis blocks to Ergo's proof-of-work: security, block-ordering,
fork-choice, and fresh-node sync, all at once (architecture §4/§5). **Corrected
mid-design** from a weak data-transaction commitment to **true Autolykos
aux-PoW**: the Aegis block id rides in the Ergo block *extension* (which
Autolykos hashes over), so one hash secures both chains and an Aegis block is a
"share" clearing Aegis's easier target — real, unspoofable work. **Permissionless**
(anyone mines) via a Nakamoto fork-choice over available+valid blocks; the
data-availability wedge dissolves (a withheld body is pending weight, never a
stall). Built + adversarially reviewed, each stage having found and fixed a real
consensus bug:
- **M2a** aux-PoW share verifier (extension commitment, dual-threshold PoW) —
  reviewed, real-Ergo-block oracle; closed an empty-Merkle-proof forgery hole.
- **M2b** real-work fork-choice tree — **adversarially reviewed SOUND**; closed a
  subjective tie-break (would split consensus) and a block-poisoning attack.
- **M6a** Ergo anchor-watcher (extension scan → verify → fork-choice) — real-block
  oracle; root-authenticates served fields so a lying node is caught.
- **M6b-1** seed/HTTP body layer + fresh-node sync — replay-equivalence proven
  over real HTTP (a fresh node reaches the same tip).
- **M6c** runnable node loop — **proof of life:** produces merge-mined blocks with
  climbing real work, persists, and restart-resumes from a re-verified archive.

*Remaining for **real** (non-dev) merge-mining:* the **Ergo-side candidate-builder
task** — patch the Ergo node (`arkadianet/ergo`, `ergo-mining`) to embed the
`AEGIS_MM_KEY` commitment in the extension of the candidates it hands miners
([`ergo-integration.md`](dev-docs/sidechain/ergo-integration.md)). The consumer
half (follower / anchor-watcher / seed / fresh-sync) is network-ready today. Also
**M6b-2** push-gossip (removes seeds from the liveness path). *(large — done)*

### M3 — Node shell (API + mempool + wiring)
Turn the producer into an inspectable node: an HTTP/RPC API (submit a shielded
tx, query chain/state/peg), a mempool to accept + order transfers, the follower
running continuously in the main loop, and the peg verifier wired to `Chain`.
*(medium)*

### M4 — Wallet + keys *(designed — [`wallet-design.md`](dev-docs/sidechain/wallet-design.md))*
Make *send / receive / verify a payment* real: the split key hierarchy
(`ak`/`nk`/`ivk`/`ovk`), note encryption (ChaCha20-Poly1305), incoming-viewing-key
scanning, diversified addresses, and payment disclosures (architecture §6). This
is what lets a recipient confirm "I received 10 USE" and a sender prove it.
**Architecture decided: a standalone `aegis-wallet` binary, never linked into the
node** (spending keys must never sit in a network-exposed process); it's a client
of the node's read-only HTTP API (the M3/M5 seam). Slice 1 (keys + diversified
addresses) is freeze-hold-safe and hybrid-independent; note-encryption + proving
(slices 3–5) are held. *(medium-large)*

### M5 — Indexer + explorer ✅ DONE
A **peg + activity + merge-mining dashboard** — the only things a private chain
can publicly show (blocks, tx counts, merge-mining status, the transparent
pot/pool), never shielded parties or amounts (architecture §7). Built as a
**self-contained page the node serves at `/`** (inline CSS + vanilla JS, fetched
same-origin — no CORS, no build step) over new read-only endpoints
`GET /aegis/v1/blocks?from=&limit=` (recent block summaries, newest-first) and
`/aegis/v1/blocks/{id}` (full public header). Proof-of-life: a dev node with
`--api-addr` serves the dashboard + block list/detail of real mined blocks.
Public aggregates only. *(medium — done)*

### M6 — P2P *(partly done — landed with M2)*
Multi-node body distribution + seed discovery. **Lighter than a normal chain's
P2P**: Ergo already provides discovery/ordering/fork-choice, so this is a
body-availability layer keyed by self-authenticating hashes, untrusted peers (a
bad peer can withhold, never forge). **Done:** the design (`p2p.md`), the
seed/HTTP body tier + fresh-sync (M6b-1), and the anchor-watcher (M6a). **Remaining
(M6b-2):** push-gossip (`HAVE`/`GET`/peer scoring) so seeds leave the liveness
path, and a real multi-node testnet run. *(medium — seed tier done, gossip next)*

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
