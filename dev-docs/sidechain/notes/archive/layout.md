# Layout choice — Aegis vs this monorepo

**Decision (Phase 0):** **Hybrid B** — dedicated **`aegis-*`** workspace crates; shared ergo crypto/ser/sigma/p2p. Do **not** fold Aegis into default `ergo-node` without hard separation.

## Why not “just Network::Aegis in ergo-node”

- Privacy consensus (notes-only) diverges hard from Ergo mainnet validation.
- Misconfig risk: operator points at Aegis genesis with mainnet keys/peers.
- Mainnet `ChainSpec::mainnet()` / testnet must stay byte-locked and boring.

## Chosen shape

```text
arkadianet/ergo (this worktree)
├── ergo-sigma, ergo-ser, ergo-p2p, ergo-mining, …  # reuse
├── aegis-spec/     # NEW crate: 15s params, genesis, note policy constants
├── aegis-node/     # NEW binary: boots only aegis-dev
└── aegis-mm/       # NEW binary: MM sidecar (Phase 2)

dev-docs/sidechain/contracts/   # ErgoScript until sibling contracts repo
```

Optional later: extract `aegis-*` to sibling git repo if the fork grows unwieldy; keep crates path-compatible.

## Rejected for v1

| Option | Why not |
|---|---|
| A — only `Network` variant inside existing `ergo-node` | Too easy to confuse with Ergo; validation soup |
| Pure sibling repo from day one | Slower dogfood of shared crate fixes; revisit if needed |

## Implication for Task 3

First code: scaffold `aegis-spec` + failing test for 15s block interval; wire a minimal `aegis-node` that depends on it. Touch `ergo-chain-spec` only if extracting shared helpers — **do not** change mainnet/testnet vectors.
