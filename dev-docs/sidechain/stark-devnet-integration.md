# STARK devnet ↔ Aegis integration (scout, 2026-07-17)

The trustless-bridge end-state runs on an Ergo L1 that can verify a STARK in
consensus. That L1 now exists as a **private, isolated Ergo devnet** built
from the Rust node's `feat/eip-0045-stark` branch (`--features stark-verify`,
so opcode `0xB9 verifyStark` does real RISC0 verification). Deployment:
`~/apps/ergo-devnet-stark/` (API `127.0.0.1:19099`, key `hello`). This note
records what it takes to run Aegis against it — scouted, not yet wired.

## State of the devnet (verified)
- **Live and advancing** under a difficulty-1 external miner: height passed
  **37k** on first check, `mining: True`, `peersCount: 0` (isolated — unique
  P2P magic `[7,7,7,7]` + empty seeds; can't even handshake a public peer).
- **Funding is already available.** 37k blocks ≫ the 720-block
  `miner_reward_delay`, so mature spendable coinbase exists — the
  verifyStark-box funding tax is effectively paid.

## Aegis → devnet is CONFIG, not code
Aegis's follower/anchor already takes an `ergo_url` ("Ergo node REST base URL
for the follower + anchor watcher") and consumes exactly one Ergo endpoint,
`/blocks`, which the devnet serves on the standard API. So pointing Aegis at
the STARK L1 is:
- `ergo_url = "http://127.0.0.1:19099"` + an `ergo_start_height`;
- Aegis's pegmint **anchor set to the devnet's genesis** (it reuses testnet
  genesis, so the testnet `ErgoAnchor` applies).
No follower rework.

## The one real code gap — the trustless `SideChainState`
The M4 trustless authority is the STARK analogue of S1c: a `SideChainState`
whose tip-update authority is `verifyStark(...) == true` instead of
`atLeast(k, …)`. That **cannot be written in ErgoScript today** — the
`ergo-compiler` frontend has no `verifyStark`, so the guard would need a
hand-built raw ErgoTree, OR `verifyStark` added to the compiler. Adding it to
the compiler frontend is the highest-leverage unblock and is **ergo branch-
session territory**, not an Aegis-USE build.

## Practical path to a live trustless peg-out on the devnet
1. Point Aegis's follower at the devnet (config, above).
2. Deploy the peg contracts on the devnet (real constants; the mature
   coinbase funds the vault + a `verifyStark`-guarded test box).
3. Build the verifyStark tx (chunked ~218 KiB proof in the input's context
   extension) and `POST /transactions` — mempool admission runs full script
   reduction, so accept-valid / reject-tampered needs no mined block. Prove
   BOTH directions on the feature-on binary (a wrong chunk split silently
   yields `false`, so tampered→reject alone is not sufficient).
4. Express the trustless `SideChainState` (blocked on the compiler gap above)
   and advance the tip with a real proof = M4, end to end.

Everything through step 3 is unblocked now; step 4 waits on the compiler.
Real *trustless settlement* (vs the trivial-statement mechanism demo) still
needs the deferred Aegis-validity STARK AIR — the real settlement statement.
