# Aegis-USE

**Private payments in USE, secured by Ergo.**

Aegis is a **sidechain** for the Ergo blockchain that lets you hold and send
**USE** privately — the amount, the sender, and the receiver are all hidden,
and every transaction looks identical on the network. It's the same idea as
Zcash's shielded pool, but the money is USE and the security comes from Ergo's
mining.

> ## ⚠️ Unaudited — testnet only — NO REAL VALUE
> This is **pre-audit research software.** The privacy math and several
> parameters have **not** been reviewed by an external cryptographer. A green
> test suite proves the code is *self-consistent*, **not** that it's *sound*.
> **Do not put real USE — or any real value — on any Aegis chain** until the
> reviews in [`dev-docs/sidechain/DEFERRED.md`](dev-docs/sidechain/DEFERRED.md)
> are done. See the [roadmap](ROADMAP.md) value-gate.

---

## How it works, in plain terms

**The peg (1:1 backing).** You lock real USE on Ergo; an equal amount appears on
Aegis as private "notes." You can always redeem a note back for real USE on
Ergo. Aegis-USE **is** USE — same value, just private — the way Lightning BTC is
still BTC. Nothing is minted out of thin air; all USE on Aegis is backed by USE
locked on Ergo.

**Private money = notes, not balances.** On Aegis there are no visible account
balances. Money exists as sealed **notes** (cryptographic commitments). Everyone
can see that *a* note exists; nobody can see its amount or owner. Spending a note
produces a zero-knowledge proof that says "I own a valid note, the money adds up,
and here is its one-time spend-marker" — without revealing *which* note. That
spend-marker (a *nullifier*) stops double-spends while keeping you anonymous.

**Sending, receiving, and verifying a payment.** When you send 10 USE, you create
a note for the recipient and **encrypt its contents to them**; only they can
open it. Their wallet **scans** the chain with their *viewing key* and finds it —
"you received 10 USE." To prove a payment to a third party (a merchant, an
auditor), you hand them a **payment disclosure** for that one note. The key idea:
**on a private chain, verification is key-gated, not public** — only the parties,
or whoever they choose to show, can confirm a payment. That's the feature.

**Merge-mined by Ergo.** Aegis has no separate miners. Every Aegis block's hash
is committed inside an Ergo block, so **Ergo's proof-of-work secures Aegis for
free** — and any Ergo miner (Scala or Rust node) can merge-mine it with no
software changes. This same commitment is how a fresh node discovers and syncs
the real chain: it scans Ergo for the commitments, which *define* the canonical
Aegis chain, so it can't be fooled by a fake one.

For the full picture — the components, the merge-mining data flow, the key
hierarchy, what an explorer can show — read
**[`dev-docs/sidechain/architecture.md`](dev-docs/sidechain/architecture.md)**.

## Who this is for

- **Researchers / cryptographers** — the shielded-transfer circuit and its
  soundness arguments (`dev-docs/sidechain/`, `external-review-brief.md`); the
  review-gate items are the point.
- **Ergo / Rust builders** — a real, reviewed sidechain core to extend
  (node, wallet, explorer, merge-mining); see the [roadmap](ROADMAP.md).
- **The curious** — start with this README, then `architecture.md`.

## What exists today (honest status)

The **consensus + crypto core is built and adversarially reviewed** — the private
money, the peg-in verifier, the peg-out contracts (live + fixed on testnet). What
is **not built yet**: the networking, the node API, the mempool, the wallet, and
the explorer. The binary today is a **dev block-producer** (it makes blocks and
persists them) — *not yet* a networked, usable node. The [roadmap](ROADMAP.md)
lays out the path from here.

## Layout

| Crate / dir | Role |
|---|---|
| `aegis-spec` | Network identity + chain parameters (constants, no logic) |
| `aegis-crypto` | The shielded-value crypto: notes, the nullifier, the spend/mint circuits |
| `aegis-node` | Block / chain / state, the Ergo follower, the peg verifier, persistence |
| `contracts` (`aegis-contracts`) | The six peg-out ErgoScript contracts, compiled + hash-pinned + tested against the live deployment |
| `vendor/curve-trees` | Vendored Curve Trees / Bulletproofs proving stack (pinned) |
| `dev-docs/sidechain` | Full protocol design, security analysis, the open-items register |

Ergo consensus primitives (serialization, PoW, NiPoPoW, REST-JSON decode) are
**git dependencies on [`arkadianet/ergo`](https://github.com/arkadianet/ergo)**
pinned to a release tag, so Aegis stays byte-compatible with the Ergo reference
node without forking it.

## Build

```sh
cargo build --workspace         # first build pulls the pinned ergo crates
cargo test  --workspace         # oracle tests run against committed real-chain vectors
```

Rust toolchain is pinned in `rust-toolchain.toml`. On low-memory machines,
`cargo build -j4` avoids OOM during the proving-stack compile.

## Docs

- **[ROADMAP.md](ROADMAP.md)** — milestones from here to a complete sidechain.
- **[dev-docs/sidechain/architecture.md](dev-docs/sidechain/architecture.md)** —
  the system map (read this second).
- `dev-docs/sidechain/{consensus,note-protocol,peg,security}.md` — depth.
- `dev-docs/sidechain/DEFERRED.md` — the living open-items / review-gate register.

---
🤖 Scaffolding + docs generated with [Claude Code](https://claude.com/claude-code)
