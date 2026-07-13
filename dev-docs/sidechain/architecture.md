# Aegis architecture & roadmap

> **Read this first.** It maps the whole system — what a complete Aegis node
> needs, what exists today, how merge-mining / sync / privacy actually work,
> and the build order. Deep detail lives in the per-topic docs it links.
>
> ⚠️ **Unaudited, testnet-only, no real value** (see [README](../../README.md),
> [DEFERRED.md](./DEFERRED.md)). Compilation + green tests prove *consistency*,
> not soundness.

---

## 1. What Aegis is

A **merge-mined Ergo sidechain for fully private USE payments.** USE is locked
1:1 on Ergo; an equal amount exists on Aegis as **shielded notes** (Curve Trees
+ Bulletproofs over the secp256k1 / secq256k1 cycle). Amounts, senders, and
receivers are hidden; every transaction is byte-identical in shape (2-in/2-out,
[`note-protocol.md`](./note-protocol.md) §6).

Aegis inherits Ergo's proof-of-work: it adds no new trust root for security,
only for (v1) peg-out attestation (`V_cap`-bounded — [`security.md`](./security.md)).

**Pinned facts** (`aegis-spec`): USE has 3 decimals (1 USE = 1000 base units);
`TX_ARITY = 2`; note wire = `2·nf(32) + 2·(cm(33) + epk(33) + ct(152) + out_ct(80))
+ fee + proof(≤8192)`; `MAX_BLOCK_TXS = 128`, `MAX_BLOCK_BYTES = 512 KiB`;
genesis supply = 0 on every network (all USE enters via the peg).

---

## 2. The layer model — what exists vs. what's needed

| Layer | Responsibility | State | Where |
|---|---|---|---|
| **L0 Consensus core** | block / chain / state / difficulty, shielded crypto, peg verifiers | ✅ **built + adversarially reviewed** | `aegis-crypto`, `aegis-node/{block,chain,state,daa,genesis}.rs` |
| **L1 Merge-mining bind** | make Ergo PoW secure & order Aegis blocks | ❌ not built — **the keystone** (§4) | — |
| **L2 Networking (P2P)** | nodes gossip blocks / txs / find peers | ❌ | — |
| **L3 Mempool + node API** | accept pending txs, submit/query over RPC/HTTP | ❌ | — |
| **L4 Wallet + keys** | send/receive, scan for your notes (§6) | ⚙️ **designed, not built** | `note-protocol.md` §4/§5; wire bytes reserved in `aegis-spec` |
| **L5 Indexer + explorer** | track commitments/nullifiers/peg, display (§7) | ❌ | — |

**L0 is the hard, dangerous part and it is done** — the nullifier soundness
(N1), the peg-in objectivity policy, the peg-out theft surface all went through
build → adversarial review → fix. Everything above L0 is substantial but is
*known engineering with no unsolved problems*.

### What the binary does *today* (be precise)

`aegis-node` is **not yet an operational networked node.** The binary
(`main.rs`) only: in `--network dev`, produces blocks at a 15 s target with real
coinbase mints, and (with `--data-dir`) persists each block to an append-only
log and resumes from it on restart. **It binds no ports** — no P2P, no API. The
follower, the peg verifier, and the crypto are complete *libraries* that are not
yet wired into a running, networked node. The real testnet transactions we
posted were the **Ergo-side peg contracts** (real), not Aegis blocks over a
network.

---

## 3. Component map (L0, what's actually in `aegis-node/src`)

- `block.rs` / `chain.rs` / `state.rs` — the ledger: `Block` (+ wire codec),
  `Chain` (produce/extend/rollback, 240-block undo ring), `ShieldedState`
  (nullifier set, emission pot, hash-chained digest, note-commitment tree).
- `daa.rs` / `genesis.rs` / `header.rs` — difficulty (LWMA), per-network
  deterministic genesis, header model.
- `store.rs` — block-log persistence (replay-and-verify on load; §5).
- `ergo_follow.rs` — the Ergo **header-follower** (PoW-gated fork-choice,
  settled reference, live REST source in `poll_http`). Reads *headers* only.
- `pegmint.rs` / `pegmint_steps.rs` — the **peg-in verifier**: objectivity
  (steps 1–4, comparative NiPoPoW membership) + receipt binding (steps 5–9).
  Pure library fns behind a `DO-NOT-WIRE` banner — proven correct, not yet
  connected to `Chain`.
- `proof.rs` / `tx.rs` — shielded-transfer wire ↔ proof binding.
- `aegis-crypto` — generators, note commitments, the Poseidon nullifier, the
  Curve-Trees spend/mint circuits (the shielded-value engine).
- `contracts/` (the `aegis-contracts` workspace crate) — the six peg-out
  ErgoScript contracts as first-class build artifacts: authoritative `.es`
  sources under `contracts/es/`, deploy-constant injection, compilation via
  the pinned `ergo-compiler`, and blake2b256 script-hash pins, oracle-tested
  byte-for-byte against the trees deployed on Ergo testnet
  (`test-vectors/testnet/peg-v2/`). Design docs stay in
  `dev-docs/sidechain/contracts/` (DESIGN.md / GAPS.md).

---

## 4. Merge-mining — the keystone (L1)

Merge-mining is simultaneously Aegis's **security**, **block ordering**, **fork
choice**, and **sync/discovery**. Building it unlocks all four.
Full design: [`merge-mining.md`](./merge-mining.md) — **which supersedes the data-tx sketch below**: the commitment now rides in the Ergo block's *extension section* (real Autolykos aux-PoW; the data-tx path is spoofable fee-purchased inclusion, not work). On any conflict, `merge-mining.md` wins.

### Data flow

```
Aegis node                         Ergo network (any Scala OR Rust node)
──────────                         ────────────────────────────────────
build Aegis block candidate
  → commitment C = hash(block)
  → build a normal Ergo tx whose
    data output carries C  ───────► submit via stock /transactions REST
                                    miner includes it in the block it mines
                                    Ergo PoW is found  →  PoW now covers C
watch Ergo, find the C-tx  ◄─────── (reuses the peg-in inclusion machinery)
  verify: Ergo header PoW valid
          ∧ block hashes to C
  → accept the Aegis block
```

### Why "easy for Scala **and** Rust nodes"

The commitment rides in a **normal Ergo transaction** (a data output), submitted
through the standard REST endpoint every Ergo node already exposes. **No miner
software change, no node fork** — the miner includes it like any fee-paying tx
(incentive = tx fee + Aegis coinbase reward). (Alternative: the block extension
section — lighter on-chain but needs miner cooperation; the data-tx path is the
zero-modification default. Scoped in `consensus.md` §1 + the `candidate_with_txs`
notes.)

### What building L1 requires

1. Commitment-tx **builder + submitter** (Aegis → Ergo).
2. Ergo **box/tx watching** — today the follower reads only headers; L1 needs it
   to find the commitment tx and verify its inclusion. **This reuses the exact
   inclusion-proof code already built for peg-in** (`pegmint_steps`).
3. The Aegis **consensus rule**: a block is canonical iff its commitment sits in
   an Ergo block with valid PoW, ≥ `N_mint` deep. Fork choice becomes
   *"follow the Aegis chain Ergo's PoW committed to."*

---

## 5. How a fresh node finds & syncs the chain

Because Aegis is merge-mined, **Ergo is the discovery layer** — a fresh node
needs almost no bundled trust.

1. **Ships only** `aegis-spec` constants: the Aegis genesis id, the pinned Ergo
   anchor, and the commitment-marker (the fixed pattern identifying Aegis
   commitment-txs on Ergo).
2. **Syncs Ergo** (headers, or a NiPoPoW bootstrap — the follower does this).
3. **Scans Ergo's heaviest chain for the marker** → the ordered list of Aegis
   block *hashes*, each backed by Ergo PoW. **This is discovery + ordering +
   fork-choice in one step**: there is no "which Aegis chain is real?" — the real
   one is *defined* as the one Ergo committed to. A fake Aegis chain has no Ergo
   PoW behind it and is rejected outright.
4. **Fetches the block bodies** for those hashes and replays them through the
   same `Chain::try_extend` path live blocks take (`store.rs` already does this
   replay-and-verify), rebuilding shielded state from genesis.

**The honest gap — body availability.** Ergo gives you the verifiable *hash
list* (32 B each); the large *bodies* (proofs, ciphertexts) live on the Aegis
network. So a fresh node still needs somewhere to download bodies from:
- **v1 practical:** a bootstrap seed / signed snapshot — every body verified
  against its Ergo-committed hash on arrival, so a lying seed can *withhold* but
  never *forge*.
- **eventual:** P2P gossip (L2); peers are a convenience, never a trust root.

**Trust model:** discovery + ordering + fork-choice = *trustless via Ergo*; body
availability = a *liveness/plumbing* concern, not a security one.

---

## 6. Privacy model — keys, sending, and "did they get it?"

**Designed (Zcash-Sapling/Orchard-style), not yet built** — the wire *reserves*
`epk`/`ct`/`out_ct`; `aegis-crypto` has no encryption/scanning code yet. This is
the L4 wallet work. From [`note-protocol.md`](./note-protocol.md) §4/§5:

One secret `sk` derives a **split key hierarchy**:
- `ak` — spend authority
- `nk` — **nullifier key** (only the owner can compute a note's spend-marker; the
  *sender never can*)
- **`ivk`** — incoming viewing key: **watch-only** — detect + decrypt notes sent
  *to* you, no spend power
- `ovk` — outgoing viewing key: lets the *sender* re-derive what they sent
- **Diversified addresses** (N9): one `sk` → unboundedly many unlinkable
  receive addresses.

**Sending 10 USE:** you create an output note `(value = 10, → their address)`,
**encrypt its opening to the recipient** via ephemeral Diffie-Hellman
(ChaCha20-Poly1305, provisional), and publish `(commitment, epk, ct)`. The
commitment is public; the contents are sealed.

**"How do I verify they got it?"** — verification on a private chain is
**key-gated, not public**:
- **The recipient** scans every new output, trial-decrypting with their `ivk`;
  the AEAD tag rejects others cheaply, yours succeeds → "received 10 USE."
- **You (sender)** retain proof via `ovk` (re-derive what you sent).
- **To a third party** (merchant, auditor): produce a **payment disclosure** —
  reveal that specific note's opening, proving on-chain commitment X decrypts to
  "10 USE → their address." Selective, holder-controlled.

The mental shift from a transparent chain: on Ergo anyone verifies any payment
via an explorer; on Aegis, only the parties — or whoever they hand a viewing key
/ disclosure to — can. **That is the feature, not a gap.**

---

## 7. What an explorer can (and cannot) show

For a private chain the explorer shows the **public skeleton**, never contents:
- ✅ blocks, times, heights, **merge-mining proofs** (which Ergo block secured
  each Aegis block)
- ✅ per-block tx *count*; nullifiers (spent-markers) + note-commitments
  (created-markers) as **opaque** entries
- ✅ **the peg is fully transparent**: PegVault balance on Ergo, total
  shielded-pool size, peg-in/out events, fees
- ❌ who sent what to whom, or any shielded amount

Effectively a **peg + activity + merge-mining dashboard** (like a Zcash
explorer: pool size and tx counts, never shielded parties/amounts).

---

## 8. Roadmap — the build order

1. **Contracts first-class** — ✅ DONE (2026-07-13): the `aegis-contracts`
   crate (`contracts/`) builds the `.es` against the git-dep'd `ergo-compiler`
   and pins tree sizes + blake2b256 script hashes, with on-chain parity tests
   against the deployed testnet trees (`test-vectors/testnet/peg-v2/`).
2. **Merge-mining (L1)** — the keystone (§4). Reuses the peg-in inclusion code.
   Unlocks security, ordering, fork-choice, **and** fresh-node sync (§5) at once.
3. **Node API + mempool (L3)** — accept/order shielded transfers; submit/query
   over RPC/HTTP. *Makes it usable and inspectable.* Wire the follower to run
   continuously and connect the peg verifier to `Chain`.
4. **Wallet + keys (L4)** — the `ivk`/`ovk` hierarchy, note encryption, IVK
   scanning, diversified addresses. *Makes "send / receive / verify 10 USE"
   real.*
5. **Indexer + explorer (L5)** — the §7 dashboard.
6. **P2P (L2)** — multi-node body gossip + seed discovery.

Threaded throughout, gating **any real value**: the external cryptographer
sign-offs in [`DEFERRED.md`](./DEFERRED.md) (Poseidon-F_p params, the composed
circuit, the peg-in work-policy margins) + moving peg-out off the v1
`V_cap`-bounded trusted attester.

---

## 9. Testnet → mainnet is a re-cut, not a migration

The Ergo anchor, the commitment-marker, the USE token id, and the genesis are
**chain-id-breaking constants** pinned per-network in `aegis-spec`. Testnet and
mainnet Aegis are therefore **different chains by construction** — a mainnet node
rejects testnet commitments and vice-versa. "Going to mainnet" is not a data
migration; it is cutting a **new genesis + anchor + constant set** (the pattern
already exists — genesis has been re-cut before when constants changed). No
testnet state carries over; the peg simply re-anchors to mainnet USE.
