# Aegis — mechanics testnet bring-up runbook

**Date:** 2026-07-12 · **Status:** runbook (mechanics only — NO real value) · **Scope:** exercise node/block/MM/bridge *plumbing*, never sound value transfer.

> **MILESTONES 1–2 LIVE (2026-07-13).** aegis-node (release, `--network dev`, no ports bound — P5 unbuilt so log-only observability) runs detached at `~/apps/aegis-testnet/` alongside the Scala testnet node @9062 (syncing, ~443k). Verified: 15.007s cadence, `leaves == height` every block (coinbase note minted per block), zero errors, ~7.5 MB RSS, clean SIGINT shutdown; restart resets to genesis `e369d3c9…` height 1 — the EXPECTED P5 no-persistence gap, not a bug. Ops: pidfile `~/apps/aegis-testnet/aegis.pid` (use `pgrep -x aegis-node`, not `$!` which captures the wrapper shell), log `aegis.log` (run-1 archive `aegis.run1.log`), health one-liner: `ps -p $(cat ~/apps/aegis-testnet/aegis.pid) -o pid,rss,etime --no-headers && tail -1 ~/apps/aegis-testnet/aegis.log`. Failure signal = any panic/ERROR line or a stalled tail. NOTE (N1 banner below is historical): N1 is CLOSED (Poseidon, fe6f205) — the no-real-value rule now rests on the pending EXTERNAL reviews (Poseidon params, delta-NUMS, composed circuit), not an open P0. Next: milestone 3 (real MM) blocked on aegis-mm + candidate seam; milestone 4 on P5.

> **HARD NO-VALUE RULE.** The nullifier P0 (N1) means shielded spends are **not sound** (a prover can forge unlimited nullifiers → double-spend). **No real USE touches any Aegis chain until N1 lands AND the composed circuit passes external review.** Everything below is plumbing validation with zero/stub value.

## 0. Reality check — what actually exists today

| Piece | State |
|---|---|
| `aegis-node` dev producer | **Works** — boots genesis, produces a coinbase-minting block every 15 s |
| Coinbase note minting (S5b) | **Works** — sound `MintProof`, one note/leaf per block |
| Shielded spend verification | **Built but UNSOUND** (N1) — `ProofMode::DevStub` only; never enable `Real` for value |
| Persistence / P2P / sync / mempool | **NOT built** (Phase 5) — chain is **in-memory, single-node** |
| `aegis-mm` sidecar (real PoW/MM) | **NOT built** — `PowMode::DevStub` only |
| `candidate_with_txs` seam (MM binding) | **NOT built** — scoped on branch `feat/candidate-with-txs`; needs a live Scala node for parity diffing |
| Peg / PegMint | **NOT built** — G2.5 (`verify_pegmint`); SPV verifiers confirmed reusable |
| Scala Ergo testnet node | **Deployable now** — `~/apps/ergo-node-scala/testnet/` |

Consequence: a "testnet" today is **one `aegis-node` producing a coinbase-minting chain in memory**, plus a **Scala Ergo testnet node standing by** as the environment the MM/bridge seams will be built against. They are **not yet wired together** (that's `aegis-mm` + `candidate_with_txs`).

## 1. Topology (solo-operator, mechanics)

Maps to consensus.md §1's process table. Target end-state (most not yet wired):

```
[aegis-node]  full Aegis ledger; produces 15s blocks, mints coinbase notes   ← works (in-mem)
[aegis-mm]    stateless sidecar: builds commitment tx, drives PoW             ← UNBUILT
[ergo-node]   Scala testnet node; serves candidateWithTxs, holds peg contracts ← deployable now
```

For **this** bring-up: run `aegis-node` (produces) + the Scala node (idle standby). The sidecar/binding is the next build, not a run step.

Network choice: the producer runs **only on `dev`** (`main.rs` gates `produce` to `Network::Dev`; `test`/`main` idle). Use `--network dev`. A dedicated `test` network with production needs a small `main.rs` change (out of scope here) — dev is the correct mechanics target now.

## 2. Bring-up steps

**A. Build + run aegis-node (works today):**
```bash
cd /home/rkadias/coding/development/arkadianet/ergo/.worktrees/privacy-use-cash-sc
export CARGO_TARGET_DIR=~/.cache/cargo-target-aegis
cargo build -p aegis-node                              # binary: $CARGO_TARGET_DIR/debug/aegis-node
$CARGO_TARGET_DIR/debug/aegis-node --network dev       # runs until Ctrl-C, 1 block/15s
# smoke test (2 blocks then exit):
$CARGO_TARGET_DIR/debug/aegis-node --network dev --max-blocks 2
```
Expect: `aegis-node booted genesis=e369d3c9…`, then `block produced height=1 … leaves=1`, `height=2 … leaves=2`. `leaves` incrementing = coinbase notes minting. CLI flags: `--network dev|test|main`, `--produce` (default true, dev only), `--max-blocks N` (0 = forever).

**B. Stand up the Scala Ergo testnet node (deployable now):**
```bash
cd ~/apps/ergo-node-scala/testnet
./start-ergo.sh --background        # java -jar ergo-6.0.3.jar --testnet -c ergo.conf
# API: 127.0.0.1:9062  (P2P 9020)   [NOTE: not 9053 — that was a stale figure]
# API is apiKey-protected (apiKeyHash set in ergo.conf); pass `api_key: <secret>` header for protected routes
curl -s 127.0.0.1:9062/info | head        # confirm it's syncing testnet
./stop-ergo.sh                             # to stop
```
Confirm `candidateWithTxs` exists on the stock node (it does — `MiningApiRoute`): `POST 127.0.0.1:9062/mining/candidateWithTxs` with a JSON array of transactions (auth required).

**C. Wire MM binding — NOT YET POSSIBLE.** Requires: (1) the `candidate_with_txs` seam on our Rust node *if* using ours (branch `feat/candidate-with-txs`, ~1–2 day consensus task — the running Scala node above is exactly the parity-diff oracle it needs), and (2) the `aegis-mm` sidecar (unbuilt) to build the commitment tx + drive Autolykos, replacing `PowMode::DevStub`. Until both exist, aegis blocks are dev-stub-PoW only.

## 3. What works vs what's stubbed (honest gating)

- ✅ **Block production + coinbase minting** — real, in-memory.
- ✅ **State machine** — nullifier set, pot, commitment tree, exact 240-block rollback (unit-tested; no live reorg driver yet).
- ⛔ **Multi-node / sync** — no P2P or persistence (Phase 5); a second `aegis-node` **cannot** sync yet.
- ⛔ **Real PoW / merge-mining** — needs `aegis-mm` + `candidate_with_txs`.
- ⛔ **Peg round-trip** — needs G2.5 `verify_pegmint` (crypto verifiers confirmed reusable; integration+policy remain).
- ⛔ **Shielded spending** — blocked by N1; `ProofMode` stays `DevStub`.

## 4. No-value guardrails

- Never set `ProofMode::Real` on a chain anyone treats as holding value (spends are forgeable until N1).
- Never peg real USE; peg round-trips use stub/zero value only.
- Legitimate mechanics testing: block cadence/DAA under variable timing, coinbase mint + pot accounting, reorg/rollback correctness, (once built) MM commitment plumbing, and peg round-trip with zero-value receipts.

## 5. Prerequisites / gaps checklist

- [ ] `aegis-mm` sidecar (commitment tx + Autolykos drive) — **unbuilt**
- [ ] `candidate_with_txs` seam (branch `feat/candidate-with-txs`) — **scoped, unbuilt**; do alongside the running Scala node
- [ ] aegis-node **persistence + P2P + sync** (Phase 5) — **unbuilt**; blocks any multi-node testnet
- [ ] G2.5 `verify_pegmint` + peg contracts — **unbuilt** (SPV verifiers reusable)
- [ ] N1 nullifier fix + external review — **blocks value** (not mechanics)

**Suggested first milestone (achievable now):** `aegis-node --network dev` runs a stable coinbase-minting chain for N blocks while the Scala testnet node syncs alongside — the two-process environment in which the `candidate_with_txs` parity work and `aegis-mm` build then proceed. **Second milestone (needs Phase 5):** a second `aegis-node` syncs the first's chain over P2P.
