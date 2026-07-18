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

**Hash-native crypto (Plonky3 / BabyBear / Poseidon2).** The shielded pool is a
uni-STARK over the BabyBear field with Poseidon2 commitments and hash-based keys
(`owner = H(nk)`, no elliptic curve in the note/spend path) over a Poseidon-Merkle
note accumulator. This is a deliberate choice: because a client spend proof's
verifier is FRI/hash-native, a settlement STARK can re-verify it cheaply, in-field
— which is what makes the **trustless peg bridge** below possible. It replaces the
earlier Curve-Trees + Bulletproofs engine (see the
[ADR](dev-docs/sidechain/adr-hash-native-engine.md)).

**Trustless peg bridge — proven.** Redeeming a note back to real USE on Ergo needs
no trusted committee. A settlement proof is verified *on Ergo itself* by the
`verifyStark` opcode (EIP-0045, `0xB9`), and the `PegVault` ErgoScript releases the
locked USE only against a valid proof whose public journal binds the recipient and
amount. The **first fully trustless round-trip completed 2026-07-19** on the STARK
devnet — release tx
`01cba5ace7d9aeb2f4a8e9bec9e277db5dfbe3f977a8a5d2573fdb31169831d6`, accepted by the
devnet.

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

The hash-native private-payment engine is **built, integrated, and demonstrated
end-to-end** — including the first trustless peg round-trip. The remaining work is
hardening and the external-review value-gate, not core construction. Status:

| Area | State |
|---|---|
| Hash-native engine (Poseidon2/Merkle/nullifier AIRs, spend circuit) | Built, adversarially tested (`engine/`) |
| Zero-knowledge (hiding) spend proofs | Built — hiding wrapper + split hiding RNG |
| 64-bit amounts, note encryption, payment addresses (send-to-a-stranger) | Built |
| Wallet (`aegis-hn-wallet`: keystore, scanner, tx building) | Built |
| Node (`aegis-node`): hash-native shielded pool, HTTP API, mempool, emission/fees | Built — persisted, reorg-safe |
| Networked merge-mined testnet | Cut (multi-node) |
| Incremental O(epoch) settlement transition (v4) | Built |
| Trustless `verifyStark` peg bridge (peg-in + peg-out consensus, `PegVault`, settlement guest/prover) | **Round-trip proven on devnet (2026-07-19)** |
| Rigorous e2e campaign, prover-speed optimization, remaining [HARDENING](dev-docs/sidechain/HARDENING.md) tiers | Next |
| External crypto review (the real-value gate) | Not started — **do not put real value on any Aegis chain** |

The trustless bridge activates on mainnet only once EIP-0045 `verifyStark` ships
upstream; it runs on the STARK devnet today. The [roadmap](ROADMAP.md) and
[HARDENING.md](dev-docs/sidechain/HARDENING.md) lay out the path from here.

## Layout

| Crate / dir | Role |
|---|---|
| `engine/` (`aegis-engine`) | **The live hash-native engine** — Poseidon2/Merkle/nullifier AIRs, the ZK spend circuit, note encryption (nested workspace over Plonky3/BabyBear) |
| `engine/wallet` (`aegis-hn-wallet`) | Hash-native wallet: keystore, chain scanner, tx building |
| `aegis-node` | Block / chain / state, the hash-native shielded pool (`hn/`), Ergo follower, peg consensus, HTTP API, persistence |
| `settlement/` | Settlement prover (RISC0 guest + host) — the peg-out STARK re-verified on Ergo |
| `bridge-tools/` | Devnet `verifyStark` bridge tooling: `PegVault` ErgoTree (`0xB9`), deposit / release-tx assembly |
| `contracts` (`aegis-contracts`) | The peg ErgoScript contracts, compiled + hash-pinned + tested against the live deployment |
| `aegis-spec` / `aegis-types` | Network identity + chain parameters; shared domain types |
| `aegis-crypto`, `aegis-wallet`, `vendor/curve-trees` | **Legacy — the prior Curve-Trees + Bulletproofs engine, superseded by the hash-native engine per the [ADR](dev-docs/sidechain/adr-hash-native-engine.md).** Retained (the old testnet still references it); not the live path. |
| `dev-docs/sidechain` | Full protocol design, the ADR, security analysis, HARDENING checklist, open-items register |

> The hash-native crates in `engine/` (and `settlement/`, `bridge-tools/`) are
> **separate nested workspaces**, excluded from the root workspace so their
> Plonky3 / RISC0 / devnet-ergo dependency graphs don't perturb the main crates.
> Build each with its own `CARGO_TARGET_DIR`.

Ergo consensus primitives (serialization, PoW, NiPoPoW, REST-JSON decode) are
**git dependencies on [`arkadianet/ergo`](https://github.com/arkadianet/ergo)**
pinned to a release tag, so Aegis stays byte-compatible with the Ergo reference
node without forking it.

## Build

```sh
# Root workspace (node, wallet, contracts, spec/types):
cargo build --workspace         # first build pulls the pinned ergo crates
cargo test  --workspace         # oracle tests run against committed real-chain vectors

# Hash-native engine (nested workspace — use an isolated target dir):
CARGO_TARGET_DIR=~/.cache/cargo-target-aegis-engine cargo test --workspace --manifest-path engine/Cargo.toml
```

`settlement/` (RISC0) and `bridge-tools/` are further nested workspaces that
path-depend on a sibling `ergo` checkout carrying the devnet `verifyStark` opcode;
build them with their own `CARGO_TARGET_DIR` per their manifest headers.

Rust toolchain is pinned in `rust-toolchain.toml`. On low-memory machines,
`cargo build -j4` avoids OOM during the proving-stack compile.

## Docs

Read in this order for the full arc — design → decision → evidence → circuit →
integration → hardening → the round-trip:

- **[dev-docs/sidechain/README.md](dev-docs/sidechain/README.md)** — the doc index.
- **[adr-hash-native-engine.md](dev-docs/sidechain/adr-hash-native-engine.md)** —
  the ADR: why Aegis went hash-native (Option B), with the measured spike evidence.
- **[spike-results/](dev-docs/sidechain/spike-results/)** — the A-vs-B settlement
  cost measurements the ADR rests on.
- **[hash-native-engine-design.md](dev-docs/sidechain/hash-native-engine-design.md)**
  / **[hash-native-spend-circuit.md](dev-docs/sidechain/hash-native-spend-circuit.md)**
  — the live engine + spend circuit.
- **[stark-settlement-design.md](dev-docs/sidechain/stark-settlement-design.md)** /
  **[stark-devnet-integration.md](dev-docs/sidechain/stark-devnet-integration.md)**
  — the trustless bridge and its devnet integration.
- **[HARDENING.md](dev-docs/sidechain/HARDENING.md)** — the consolidated
  post-campaign roadmap and the real-value review-gate.
- **[architecture.md](dev-docs/sidechain/architecture.md)** — the system map.
- **[ROADMAP.md](ROADMAP.md)** / **[DEFERRED.md](dev-docs/sidechain/DEFERRED.md)** —
  milestones and the living open-items register.
