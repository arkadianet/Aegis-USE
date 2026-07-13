# Aegis-USE

A merge-mined **Ergo sidechain for fully private USE payments** — a shielded
pool (Curve Trees + Bulletproofs over the secp256k1 / secq256k1 cycle) with a
1:1 peg to USE locked on the Ergo main chain. Amounts, senders, and receivers
are hidden; every transaction has an identical shape.

> ## ⚠️ Unaudited — testnet only — NO REAL VALUE
>
> This is **pre-audit research software**. The shielded-value soundness
> (nullifier construction, the composed spend circuit) and several bounded
> parameters (Poseidon-over-F_p constants, the peg-in objectivity work-policy
> margins) **have not yet been reviewed by an external cryptographer**.
> Compilation and a green test suite prove consistency, **not** soundness.
>
> **Do not put real USE — or any real value — on any Aegis chain** until the
> external review sign-offs listed in `dev-docs/sidechain/DEFERRED.md` are
> complete. The peg-out path additionally carries a declared, `V_cap`-bounded
> trusted-attester assumption in v1 (see `dev-docs/sidechain/contracts/DESIGN.md`).

## Layout

| Crate | Role |
|---|---|
| `aegis-spec` | Network identity + chain parameters (types, constants — no logic) |
| `aegis-crypto` | The shielded-value crypto: generators, note commitments, the Poseidon nullifier, the Curve-Trees spend/mint circuits |
| `aegis-node` | The node: block/chain/state, the Ergo header-follower, the peg-in objectivity + receipt verifier, on-disk persistence |
| `vendor/curve-trees` | Vendored Curve Trees / Bulletproofs proving stack (pinned; see `PROVENANCE.md`) |

Consensus primitives (serialization, PoW, NiPoPoW, REST-JSON decode) are
consumed as **git dependencies on [`arkadianet/ergo`](https://github.com/arkadianet/ergo)**
pinned to a release tag (`Cargo.toml` → `[workspace.dependencies]`), so this
repo stays byte-compatible with the Ergo reference node without forking it.

## Build

```sh
cargo build --workspace         # pulls the pinned ergo crates on first build
cargo test  --workspace         # oracle tests run against committed real-chain vectors
```

Rust toolchain is pinned in `rust-toolchain.toml`.

## Design docs

`dev-docs/sidechain/` — the full protocol design, security analysis, peg
design, and the deferred/open register. **Start with
[`architecture.md`](dev-docs/sidechain/architecture.md)** (the system map: what
exists vs. what's next, how merge-mining / sync / privacy work), then
`consensus.md` and `note-protocol.md` for depth.

---
🤖 Scaffolding generated with [Claude Code](https://claude.com/claude-code)
