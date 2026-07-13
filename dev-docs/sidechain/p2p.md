# Aegis P2P — the body-availability layer (L2 design)

**Date:** 2026-07-13
**Status:** decided (design stage) — the M6 dependency of
[`merge-mining.md`](./merge-mining.md) §6/§9, layer **L2** of
[`architecture.md`](./architecture.md) §2. Docs only; no code in this
commit. Where a decision is deferred it is tagged **DECISION NEEDED** or
**v1-accepted** explicitly.

> **Scope.** This doc designs how nodes obtain **block bodies** and
> **share witnesses** so the chain is live and permissionless. It does
> NOT design mempool transaction relay — pending-transfer gossip is an
> L3 concern with its own (privacy-sensitive, Dandelion-shaped)
> considerations and gets its own doc when L3 is cut. It also does not
> revisit fork choice or finality: those are decided in
> merge-mining.md §5/§7 and built in `aegis-node/src/mm_forkchoice.rs`.

---

## 1. The defining property: this is not a consensus network

A normal chain's P2P must deliver discovery, ordering, fork-choice
inputs, and data — and defend all four against Byzantine peers. Aegis
outsources the hard three to Ergo:

- **Ordering + weight** come from aux-PoW share witnesses
  (merge-mining.md §2), each self-contained and verifiable against the
  node's own Ergo header view (`ergo_follow::Follower`). No peer can
  forge weight; weight is work.
- **Settlement** comes from anchors — commitments carried by settled
  Ergo blocks, read from the node's own Ergo connection (the
  anchor-watcher, §7). No Aegis peer is in that loop at all.
- **Chain identity** is pinned in `aegis-spec` (genesis id, `ERGO_ANCHOR`,
  `AEGIS_MM_KEY`) — a fresh node cannot be handed the wrong chain,
  only a lighter fork of the right one, which fork choice rejects on
  weight.

What remains for the P2P layer is exactly one job: **make bytes
retrievable by id.** Two content classes, both self-authenticating:

| Item | Size | Authenticates by |
|---|---|---|
| **Block body** (full `Block` wire: header ‖ body ‖ coinbase, `block.rs::Block::bytes`) | ≤ ~520 KiB (`MAX_BLOCK_BYTES = 524_288` on the body + header + coinbase ≤ `MAX_PROOF_BYTES`) | recomputed `Header::id()` == requested id, then `header.tx_root == body.tx_root()` and `reward_claim` ↔ coinbase binding — exactly the checks `MmForkChoice::ingest_body` already performs (`BodyIngest::NotSelfAuthenticating` on mismatch) |
| **Share witness** (`auxpow::ShareWitness` wire: ergo header ‖ extension field ‖ Merkle proof — codec exists, `ShareWitness::{bytes,from_bytes}`) | ≤ ~1 KiB | `ShareWitness::verify(&ShareContext)` — pure aux-PoW re-verification against the node's own follower tip + DAA view; no peer trust anywhere |

Because every byte is checked against a hash (or a PoW threshold) the
node already knows or re-derives, **a peer can withhold, never forge**
(architecture.md §5). Availability is a monotone input to fork choice,
never a verdict (merge-mining.md §5): a missing body delays a branch,
it never stalls the node or splits consensus. So the threat model is
purely liveness + resource exhaustion, and the right prior art is not
Tendermint-style consensus gossip but **content distribution**:

- **Ethereum devp2p `eth` wire protocol** — the closest structural
  analog: headers-first sync, then `GetBlockBodies(hashes)` from
  untrusted peers, bodies verified against the header's roots. Aegis's
  witness stream plays the role of the header chain.
- **Bitcoin** — headers-first (BIP 130 `sendheaders`) + `inv`/`getdata`
  block relay and BIP 152 compact blocks: announce cheap identifiers,
  fetch bodies on demand, never push large payloads unsolicited.
- **BitTorrent (BEP 3)** — fetch-by-hash from an untrusted swarm;
  per-piece hash checks make peer honesty irrelevant to integrity.
- **IPFS bitswap 1.2** — content-addressed block exchange with
  want-lists and explicit `HAVE`/`DONT_HAVE` responses — the direct
  model for §4's inventory messages.
- **libp2p gossipsub v1.1** — mesh pubsub with peer scoring; the
  benchmark for what a *full* gossip dependency buys (and §3 argues we
  don't need most of it).

## 2. What actually has to move, and how much

Traffic envelope (per `aegis-spec` caps, both candidate cadences from
merge-mining.md §3's open decision):

| Cadence | Blocks/day | Worst-case bodies/day (all full, 512 KiB) | Realistic early (near-empty bodies, coinbase ≤ 8 KiB) |
|---|---|---|---|
| 60 s | 1,440 | ~720 MiB | ~15 MiB |
| 15 s | 5,760 | ~2.8 GiB | ~60 MiB |

Witnesses are noise next to that (≤ ~1 KiB × block count). Even the
worst case is a few hundred GB/year — trivially archivable by a seed,
comfortably servable over plain HTTP. There is no bandwidth argument
for a sophisticated transport at any scale Aegis will see before it
has a reason to re-decide (§9).

**Who needs what, when:**

- **A synced node at the tip** needs new witnesses promptly (they drive
  fork choice and the miner's parent selection) and new bodies soon
  after (to activate weight and extend validated state).
- **A fresh node** needs *every canonical body from genesis* — replay
  through `Chain::try_extend` is the only way to rebuild shielded state
  (architecture.md §5; `store.rs` already replays-and-verifies).
- **The attester / merchants** need witnesses even for branches they'd
  never follow: pending-hostile accounting (merge-mining.md §7) counts
  every known competing witness against acting.

## 3. Transport — the decision

Three candidates were weighed:

| | (a) rust-libp2p (gossipsub + Kademlia + Noise) | (b) minimal custom TCP protocol | (c) seed/HTTP-first |
|---|---|---|---|
| Dependency weight | very heavy: rust-libp2p pulls a large transitive tree (yamux, noise, QUIC stacks, prost, …) into a repo whose posture is minimal roots of trust and few, proven deps | zero new deps of substance (tokio + the existing `ergo-primitives` VLQ codec) | zero-to-one dep (an HTTP client; the node will grow one for L3 anyway) |
| Dev time | medium — batteries included, but gossipsub topics, peer scoring config, and DHT bootstrap are real integration surface with real tuning failure modes (ETH2 spent years tuning gossipsub scoring) | medium — a framed request/response + announce protocol is a few hundred lines, but *we* own connection management, backoff, and peer bookkeeping | small — a fetch loop with retry/multi-source is days, and it is the *same code fresh-sync needs regardless* |
| Fit to the trust model | poor fit: Noise-encrypted authenticated channels, message signing, and score-based mesh defense solve integrity/identity problems that **self-authenticating content already solves for free**. We'd carry the cost of guarantees we don't consume | good fit: the protocol can be honest about trusting nothing — every payload hash-checked, every peer disposable | perfect fit for integrity (a lying seed can only withhold), poor fit for decentralization (liveness leans on named operators) |
| NAT / discovery at dev scale | overkill (DHT + AutoNAT + relays for a network of, initially, single-digit nodes) | manual peer lists + outbound-only works fine at dev scale; NAT traversal deferred | non-issue: outbound HTTPS |
| Future decentralization | the strongest end-state if Aegis grows to hundreds of untrusted, NATed nodes | adequate to tens of nodes with peer-exchange; DHT-scale discovery would be new work | none by itself — it is a bootstrapping tier, not an end-state |

**Decision: (c) → (b) staged; (a) only on demonstrated need.**

- **v1 (M6b-1, launch-critical): seed/HTTP-first.** Nodes fetch bodies
  and witnesses by id over HTTPS from a small set of operator seeds
  pinned per-network in `aegis-spec`. This is the minimum that makes
  fresh-sync and tip-following real, and every line of it (fetch by id,
  verify, `ingest_*`, retry elsewhere) remains load-bearing under every
  later transport.
- **v1.x (M6b-2): minimal custom TCP gossip** — the §4 message set over
  length-prefixed frames. This removes the seeds from the *liveness*
  path (any node can serve any node) at the cost of a few hundred lines
  we fully own — consistent with the repo's minimal-roots-of-trust
  posture and with the fact that we need none of libp2p's channel
  guarantees.
- **libp2p is a re-decision point, not a plan** (§9): adopt gossipsub +
  Kademlia only if the network outgrows manual-peer-list scale (roughly:
  >~50 independent node operators, NAT-heavy topology, or observed
  eclipse pressure). The §4 message semantics are transport-agnostic by
  construction so the migration cost is the transport shim, not the
  protocol.

Why not libp2p from day one, despite ETH2/Filecoin/Polkadot precedent:
those networks *are* consensus-gossip networks — validator messages are
unforgeable only via signatures and timely only via mesh tuning, so
they consume exactly the guarantees libp2p sells. Aegis consumes none
of them: content is hash-gated, ordering is Ergo's, and timeliness
requirements are soft (a late body delays weight activation, nothing
else). Buying the heaviest dependency in the tree for guarantees the
design explicitly does not need would invert the repo's engineering
posture. And why not (b) immediately, skipping (c): the HTTP tier is
not throwaway — seeds remain the archival/bootstrap tier (§6) and the
fresh-sync path under every future transport, and shipping it first
makes the testnet live weeks earlier with the identical verification
core.

## 4. Protocol

### 4.1 Identity, discovery, bootstrap

- **Network identity:** every session opens with the pair
  `(genesis_id, AEGIS_MM_KEY)` — chain-id-breaking constants from
  `aegis-spec` (merge-mining.md §8). Mismatch ⇒ disconnect. Testnet and
  mainnet are different chains by construction (architecture.md §9);
  the P2P inherits that for free.
- **Bootstrap:** a per-network `SEED_URLS: &[&str]` list in
  `aegis-spec::NetworkParams` (new constant, non-consensus — changing
  it is a software update, not a chain break), plus `--seed` /
  `--peer` CLI overrides. **v1-accepted:** operator-run seeds; DNS
  seeds (Bitcoin-style `A`-record crawlers) are deferred to M6b-3 —
  they matter only when the peer set is large enough that a static
  list goes stale, and they add an operational surface (a DNS zone)
  with no payoff at dev scale.
- **Peer exchange (M6b-2):** a minimal `GET_PEERS` → `PEERS(addr...)`
  pair, Bitcoin `getaddr`/`addr` shaped, capped and rate-limited.
  Learned addresses are hints, never trust.

### 4.2 Messages (transport-agnostic semantics)

Wire framing for M6b-2: length-prefixed frames over TCP, `u8` message
tag + VLQ-encoded payload via the existing `ergo_primitives`
writer/reader (the same codec discipline every Aegis wire format
already uses). The HTTP tier (M6b-1) exposes the same semantics as
routes.

| Message | Payload | Semantics |
|---|---|---|
| `HELLO` | `protocol_version, genesis_id(32), best_tip_id(32), best_height, listen_addr?` | session open; wrong `genesis_id` or unknown major version ⇒ drop |
| `HAVE` | `kind (body\|witness), id(32) × n` (n capped, e.g. 64) | announce availability near the tip. **This is the measurability primitive:** a peer that announced `HAVE(id)` and then stalls or `DONT_HAVE`s the `GET` is *observably* withholding — logged and scored per-peer (§6), even though it is never consensus-actionable (merge-mining.md §6: availability is monotone input, not verdict) |
| `GET` | `kind, id(32) × n` (n small, e.g. 16) | request by id; multi-source by design — any peer with the bytes can answer, ids are the only coordinates |
| `BODY` | full `Block::bytes()` | answer to `GET body`. Unsolicited `BODY` frames are dropped unread past the frame header (§6) |
| `WITNESS` | `ShareWitness::bytes()` | answer to `GET witness`, and the one payload that IS pushed unsolicited at the tip (≤ ~1 KiB, PoW-gated by verification — cheap to check, expensive to mint) |
| `DONT_HAVE` | `kind, id(32)` | explicit miss (bitswap 1.2's lesson: an explicit negative beats a timeout for source selection) |
| `GET_PEERS` / `PEERS` | — / `addr × n` | M6b-2 peer exchange |

HTTP mapping (M6b-1, seeds): `GET /aegis/v1/body/{id_hex}`,
`GET /aegis/v1/witness/{id_hex}`, `GET /aegis/v1/tips` (the seed's
canonical tip id + height + the ordered id list of the last ~240),
`GET /aegis/v1/chain?from_height=H&tip={id_hex}` (ordered canonical id
page for fresh-sync — **untrusted hints**, see §5), plus a batched
`POST /aegis/v1/bodies` (ids in, concatenated length-prefixed bodies
out) so fresh-sync isn't one round-trip per block.

**Gossip discipline near the tip (M6b-2):** on activating a new block
(or verifying a new witness), send `HAVE`/unsolicited `WITNESS` to all
connected peers; peers `GET` what they lack. Bodies are never pushed
unsolicited — announce-then-fetch, Bitcoin `inv`/`getdata` style, so a
peer's inbound body bandwidth is always something it asked for.

### 4.3 What flows: bodies always; witnesses gossiped, not Ergo-derived

**Decision: witnesses are first-class gossip payloads.** The tempting
alternative — "witnesses can be re-derived from Ergo by any node
running the anchor-watcher, so don't gossip them" — is **wrong for the
majority of shares** and the design must say so plainly: a share's
Ergo header is usually an *unpublished candidate* that missed Ergo's
target and never appears on the Ergo network (merge-mining.md §2.4).
Nobody can re-derive those bytes from anywhere; the witness held by
the finder (and whoever it gossiped to) is the only copy of the proof
that the work happened. No witness circulating ⇒ the block has no
weight on any other node ⇒ it may as well not exist.

Only the **anchored subset** — shares that also cleared Ergo's target —
is Ergo-recoverable: the header is on-chain, and the extension field +
Merkle proof can be rebuilt from the settled Ergo block. That subset is
the anchor-watcher's domain (§7) and doubles as a witness *recovery*
path for anchored blocks, but it is a sparse skeleton (one anchor per
Ergo block at best), not the share stream. So:

- **Gossiped:** all witnesses (tip gossip + fetch-by-id), all bodies
  (fetch-by-id after announce).
- **Ergo-sourced (not P2P):** anchor facts (`record_anchor`) and, as a
  fallback, reconstructed witnesses for anchored ids.

## 5. Fresh-node sync

Per architecture.md §5, with the merge-mining.md realities folded in:

1. Ship `aegis-spec` (genesis id, `ERGO_ANCHOR`, `AEGIS_MM_KEY`,
   `SEED_URLS`). Sync Ergo headers via the follower.
2. **Anchored skeleton from Ergo (trustless):** the anchor-watcher
   scans settled Ergo extensions for `AEGIS_MM_KEY` → the ordered set
   of anchored Aegis ids, each Ergo-grade. This is discovery the P2P
   layer cannot be lied to about.
3. **Candidate chain from seeds/peers (hints):** fetch `/tips` and
   `/chain` pages → an ordered id list claiming to be canonical. This
   list is **untrusted**: it costs the seed nothing to lie. It is only
   a download schedule.
4. **Fetch witnesses + bodies by id** (batched, multi-source), feed
   `ShareWitness::verify` → `ingest_share` and `ingest_body` in
   parent-first order. Every body self-authenticates; every witness
   carries its own PoW; `MmForkChoice` recomputes cumulative weight
   itself. A seed that served a lighter side chain merely wasted the
   node's bandwidth — the moment heavier witnesses arrive from anyone,
   fork choice reorgs onto them, and step 2's anchored skeleton bounds
   how wrong the settled prefix can be (a fake settled prefix would
   need fake Ergo anchors ⇒ an Ergo reorg).
5. Cross-check tips across ≥2 seeds + any peers before declaring
   synced; disagreement ⇒ fetch both branches and let weight decide.

Note what is absent: no snapshot trust, no checkpoint file, no signed
chain summaries. The only sync shortcut ever worth adding is a
shielded-state snapshot keyed to an anchored block id, and that is
explicitly out of scope for v1 (replay from genesis is fast at v1
volumes; `store.rs` replay-and-verify already exists).

## 6. Retention, replication, anti-DoS

### 6.1 Retention

- **Canonical bodies: keep everything, v1.** No pruning. Fresh-sync
  requires every canonical body from genesis (§2), the volume is
  bounded (§2's table), and `store.rs`'s append-only log already *is*
  the archive — a node serves `GET body` straight from it. Pruning is
  a non-goal until volume says otherwise.
- **Non-canonical / pending:** per merge-mining.md §6 — a branch still
  pending after ~240 blocks of settled canonical progress is beyond the
  undo ring and unrecoverable; drop its bodies and witnesses. Pending
  *witnesses* (~1 KiB) are retained up to that horizon with re-request
  backoff for their bodies.
- **The Q3 risk — "bodies lost forever" (Fork C):** if every copy of a
  canonical body vanishes, no fresh node can ever validate past it —
  the ids survive on Ergo, the chain's *meaning* doesn't. Mitigation is
  a **replication policy, stated as operations, not consensus**:
  (i) ≥ 2 operator seeds on disjoint infrastructure, each archiving
  the full canonical log; (ii) every full node is a mirror by default
  (no pruning + serves `GET body`); (iii) seed operators keep offline
  log backups (`store.rs` log files are rsyncable flat files);
  (iv) the block producer (miner) MUST persist its own blocks before
  announcing — the finder is always the first archive. Residual risk
  is honest-gap #4 in §9.

### 6.2 Anti-DoS

The asymmetry to defend: a body is up to ~520 KiB, junk is free to
generate, and `MmForkChoice`'s `stashed` orphan buffer is (correctly,
at the consensus layer) unbounded. The P2P layer is the bounding wall:

1. **Witness-first admission — the PoW ticket.** Never `GET` (or accept)
   a body for an id lacking a locally verified witness, except ids on
   the §5 fresh-sync schedule (which are fetched witness-before-body
   anyway). A witness costs real Autolykos work above `aegis_target` to
   mint and ~a hash + a Merkle check to verify: the attacker pays, we
   don't. Junk bodies therefore never reach `ingest_body` at all; the
   `stashed` map's population is bounded by the number of PoW-backed
   pending ids.
2. **Witness flood is self-bounding.** `verify_share`'s C2 window
   rejects anything outside `[follower_tip − K_LAG, tip + 1]`
   (`ShareError::HeightOutOfWindow`), so a flooder must mint *fresh*
   work at chain difficulty inside a ~K_LAG·2-min horizon — the flood
   rate is capped by the attacker's hashrate, which honest fork choice
   would rather they spent mining. Failed verifications score against
   the peer (below).
3. **Frame hygiene:** hard caps on frame size (body frames ≤
   `MAX_BLOCK_BYTES` + header/coinbase slack — the `Block::from_bytes`
   caps then re-enforce), `HAVE`/`GET` batch sizes, and in-flight
   `GET`s per peer. Unsolicited `BODY` frames dropped at the tag byte.
4. **Per-peer scoring + rate limits:** token-bucket on bytes served and
   on `GET`s answered; a misbehavior score fed by: failed witness
   verification, `NotSelfAuthenticating` bodies, `HAVE`-then-stall
   (§4.2's measurability), frame violations. Score past threshold ⇒
   disconnect + temp-ban the address. Deliberately Bitcoin-simple; no
   gossipsub-style mesh scoring is warranted at this scale.
5. **Distinguish wrong-body from bad-block (already built):**
   `BodyIngest::NotSelfAuthenticating` and `RejectedTransient` blame
   the *bytes/peer*, never the id — a malicious peer cannot poison an
   honest id by serving garbage for it; the node re-requests from the
   next source. Only `Chain::try_extend` failure on authenticated
   bytes kills a branch, deterministically, on every node alike.
6. **Seed-side:** plain HTTP semantics mean commodity defenses (CDN,
   rate limiting) apply; seeds serve immutable content-addressed bytes,
   the single easiest workload to cache.

## 7. The split: P2P vs anchor-watcher vs fork-choice

One consumer, two feeders, no overlap:

```
Aegis P2P (M6b)                      Anchor-watcher (M6a)
  bodies + witnesses by id             own Ergo follower / REST
  from UNTRUSTED peers/seeds           scans settled extensions for
       │                               AEGIS_MM_KEY; check_inclusion
       │ ShareWitness::verify(ctx)     discipline (pegmint_steps)
       │  └→ ValidShare                     │
       ▼                                    ▼
  MmForkChoice::ingest_share    MmForkChoice::record_anchor(id, ergo_h)
  MmForkChoice::ingest_body     (+ reconstructed witnesses for anchored
       │                          ids as a recovery path, §4.3)
       ▼
  canonical tip / W(b) / W_settled / pending-hostile  →  chain, miner,
                                                         attester
```

- **P2P feeds `ingest_body` and (via `verify_share`) `ingest_share`.**
  It carries bytes; it never carries judgments. Everything it delivers
  is re-verified locally before touching fork choice.
- **The anchor-watcher feeds `record_anchor`.** It is Ergo-sourced end
  to end — it works with zero Aegis peers, which is exactly why eclipse
  attacks on the Aegis P2P cannot fake or hide settlement (§10).
- **Fork choice consumes both and owns every consensus decision.** The
  P2P layer holds no chain state beyond "which ids do I have bytes
  for" and per-peer bookkeeping. It can be restarted, replaced, or
  eclipsed without corrupting consensus — only liveness degrades.

## 8. Staged build plan

| Stage | Contents | Status gate |
|---|---|---|
| **M6b-1 — seed/HTTP body-fetch + fresh-sync** (**launch-critical**) | seed server mode in `aegis-node` (serve `body`/`witness`/`tips`/`chain` from the store); fetch client with multi-seed retry/backoff; the §5 fresh-sync loop wired to `ingest_share`/`ingest_body`; `SEED_URLS` in `aegis-spec`; miner persist-before-announce | a wiped node reaches the live tip from `aegis-spec` constants + running seeds, end to end |
| **M6b-2 — peer gossip** (**launch-window**: required before calling the testnet permissionless in practice, not required for first blocks) | TCP framing; `HELLO/HAVE/GET/BODY/WITNESS/DONT_HAVE`; announce-then-fetch at the tip; witness-first admission; per-peer scoring/limits; `GET_PEERS` exchange; config peer lists | two non-seed nodes keep each other at the tip with all seeds stopped |
| **M6b-3 — discovery hardening** (**later, on demonstrated need**) | DNS seeds; outbound-diversity / eclipse hardening; NAT traversal; **the libp2p re-decision** (§3) if operator count outgrows peer lists | revisit when >~50 independent operators or observed eclipse pressure |

Launch-critical is deliberately only M6b-1: with seeds up, the chain
is live, minable, and syncable; M6b-2 removes the seeds from the
liveness path; M6b-3 is insurance against success.

## 9. Honest gaps / v1 simplifications

1. **Seed trust for liveness (not safety).** Until M6b-2 lands, all
   body distribution flows through operator seeds — withholdable,
   DoS-able, censorable. Never forgeable (every byte hash-checked),
   and never able to fake weight or settlement. Accepted for v1 with
   eyes open; it mirrors architecture.md §5's "seeds are a convenience,
   never a trust root".
2. **Eclipse resistance deferred.** v1 peer selection is static lists +
   exchange hints; a resourced attacker can monopolize a node's Aegis
   connections. §10 #3 bounds the damage (the Ergo side-channel), but
   real outbound-diversity work is M6b-3.
3. **No light-client DA.** Bodies are fetched whole; no erasure coding,
   no DA sampling, no partial-body proofs. Every Aegis node is a full
   node. Right-sized: blocks cap at ~512 KiB and privacy already
   requires full scanning of outputs (note-protocol.md §5).
4. **Replication is policy, not protocol.** §6.1's mirror rules are
   operational commitments; nothing in-protocol *proves* a body is
   archived somewhere (no proof-of-retrievability). The residual Q3
   risk stands until the node count makes it statistical.
5. **No transport encryption/authentication in v1.** Content integrity
   never needed it; body/witness bytes are public data (ciphertexts
   within are already end-to-end encrypted at the note layer). Cost: an
   on-path observer learns you run an Aegis node, and an active MITM
   can act as a withholding "peer" (= liveness, handled by scoring +
   multi-source). HTTPS on seeds is free and used; peer-link Noise can
   ride in with M6b-3/libp2p if warranted.
6. **Mempool tx relay unscoped here** (see the scope note up top) — the
   privacy-relevant gossip problem (who originated a transfer) is L3's,
   and conflating it with body availability would smuggle a hard
   problem into an easy layer.

## 10. Self-adversarial pass

| # | Attack | Verdict | Killed / bounded by |
|---|---|---|---|
| 1 | **Withhold bodies** — announce `HAVE`, serve nothing (or gossip witnesses, hide bodies for a later heavy reveal) | Liveness annoyance; never a stall, reveal pre-charged | Pending weight never activates (merge-mining.md §5) — honest chain proceeds; `HAVE`-then-stall is measured per-peer (§4.2) → deprioritize + refetch from any other source (multi-source by id); the attester already counted the hidden branch as hostile before acting (§7 of merge-mining.md) |
| 2 | **Serve a wrong body** for a real id | Rejected, id unharmed | `ingest_body` self-authentication (`tx_root`/`reward_claim`) ⇒ `NotSelfAuthenticating`: bytes blamed, peer scored, id stays clean, re-request elsewhere. Poisoning an id via garbage bytes is impossible by construction |
| 3 | **Eclipse a node's Aegis connections** | Degraded tip-freshness; settlement view intact; attester fails safe | The anchor-watcher rides the node's own **Ergo** connection — an Aegis-P2P eclipser can neither hide nor fake anchored commitments without an Ergo-level attack. Eclipsed node sees anchored ids it can't fetch bodies for ⇒ they stay pending ⇒ pending-hostile accounting makes the attester **refuse to attest** (stall, not theft). Real outbound-diversity hardening deferred (§9 #2) |
| 4 | **Flood junk bodies** | Dropped at the door | Announce-then-fetch: unsolicited `BODY` frames dropped unread; `GET`s are only issued witness-first (§6.2 #1), so a 520 KiB payload is only ever accepted against a PoW-backed id; frame caps + token buckets bound the rest |
| 5 | **Flood junk witnesses** | Rate-capped by attacker hashrate | Each witness must clear `aegis_target` inside the C2 window — minting spam costs real fresh Autolykos work at chain difficulty; verification is ~a hash + Merkle check; failures score the peer toward a ban |
| 6 | **DoS the seeds** (M6b-1 era) | Liveness-only outage | ≥2 seeds on disjoint infra + CDN-able immutable content; synced nodes keep producing/validating via their own miners and (post-M6b-2) each other; consensus state and Ergo settlement untouched |
| 7 | **Poison fresh-sync** — seed serves a valid-format but non-canonical chain | Wasted bandwidth only | The id schedule is a hint (§5): weight comes solely from verified witnesses, settlement solely from the node's own Ergo scan; heavier honest witnesses from any source trigger the reorg; a fabricated settled prefix needs fake Ergo anchors ⇒ an Ergo reorg |
| 8 | **Grief with transiently-invalid variants** (e.g. malleated coinbase proof bytes for a real id) | Retry succeeds, id clean | `BodyIngest::RejectedTransient` is explicitly non-poisoning (built and tested in `mm_forkchoice.rs`): bytes dropped, peer scored, correct bytes from another source validate normally |
| 9 | **Stale-`HAVE` source-selection abuse** — advertise everything, answer `DONT_HAVE` | Self-defeating | Explicit `DONT_HAVE` (bitswap-style) feeds the same per-peer score as stalling; the peer just documents its own uselessness faster |
