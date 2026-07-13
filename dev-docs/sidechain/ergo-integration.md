# Ergo-side integration — enabling real merge-mining

> The Aegis node is a complete merge-mining consumer today (follower →
> anchor-watcher → share verifier → fork-choice → seed/sync, all built + reviewed;
> the dev network merge-mines end-to-end with in-process share grinding). What is
> **not** in this repo, by design, is the piece that makes *real* Ergo miners
> produce Aegis shares: the Ergo node must embed the Aegis commitment in the
> block candidates it hands miners, **before** they hash. This doc specs that
> task. It is a change to **`arkadianet/ergo`**, not to Aegis-USE.

## Why it's needed

Real Autolykos aux-PoW (`merge-mining.md`) requires the Aegis block id to sit in
the Ergo block **extension**, because the extension's Merkle root
(`extension_root`) is inside the bytes Autolykos hashes. Only then does one hash
attest to a specific Aegis block. A miner therefore must have the commitment in
the candidate *at build time*. Ergo's node builds those candidates — so the node
is where the commitment must be injected. There is no way to do this from the
Aegis side alone (a transaction included after the fact is *not* covered by the
PoW — that was the rejected weak design).

## The change (minimal, opt-in, non-consensus)

**Where:** `arkadianet/ergo`, `ergo-mining` — the candidate/extension builder
(`extension_builder.rs::build_candidate_extension_fields`, the fn that assembles
the extension key-values for a block candidate).

**What:** when merge-mining is enabled (a new opt-in node config, **off by
default** so ordinary Ergo nodes are unaffected), add one extension field to the
candidate:

| field | value |
|---|---|
| key `[0xAE, 0x00]` (`AEGIS_MM_KEY`) | `0x01 ‖ <32-byte Aegis block id>` (33 bytes; `MM_COMMITMENT_VERSION = 0x01`) |

Rules to respect (all already-enforced Ergo consensus, verified): rule 404
(value ≤ 64 B — 33 fits), rule 405 (no duplicate keys — inject exactly one), and
unknown keys are consensus-legal (rules 400/405/406 do not reject them), so this
does **not** fork Ergo — a candidate carrying the field is a valid Ergo block
whether or not anyone else understands it.

**Where the id comes from:** a running `aegis-node` produces the current Aegis
block candidate on its canonical tip and exposes its id. The cleanest coupling is
a thin local hook: at Ergo-candidate-build time the Ergo node asks the co-located
aegis-node "current Aegis commitment?" over a loopback call (aegis-node exposes
it via the M3 API once that lands; until then a minimal endpoint). Keep it
**optional and non-blocking** — if the aegis-node is unreachable, the Ergo node
builds a normal candidate (no Aegis field), i.e. merge-mining degrades to "not
this block," never to an Ergo stall.

## The full real-network loop, once this lands

1. Ergo node (merge-mining enabled) asks aegis-node for the current Aegis
   commitment → embeds `AEGIS_MM_KEY` in the candidate extension.
2. Miner hashes the candidate (unchanged mining). The Autolykos solution is
   checked against Ergo's target *and* — by the aegis-node — against Aegis's
   easier target.
3. If it clears Aegis's target, it's a valid Aegis **share**; if it also clears
   Ergo's, it's an Ergo block too. Either way the commitment is now under real
   PoW.
4. The aegis-node's **anchor-watcher (M6a, already built)** sees the Ergo block's
   extension, runs `verify_share`, and feeds the fork-choice. For shares that
   clear only Aegis's target (never became Ergo blocks), the witness is gossiped
   on the Aegis P2P (they're not on Ergo — see `p2p.md`).

Everything from step 4 on is done. Steps 1–3 are this task.

## Scope, incentive, adoption

- **Incentive:** the share finder mines the Aegis coinbase note to their own key
  (`reward_claim`), so producing shares pays in USE. The extension field is free
  (no tx, no fee). No change to Ergo's economics.
- **Reference integration:** the Rust Ergo node's own candidate-builder (you run
  it) — the simplest place to land the opt-in hook and dogfood real testnet
  merge-mining without any third party.
- **Wider adoption:** each pool that wants to merge-mine Aegis integrates the same
  hook. Security = the Ergo hashrate that opts in (the inherent Namecoin
  property), starting near-zero and growing with adoption; the on-Ergo anchored
  commitments + `W_settled` finality bound the risk while participation is low.
- **Deliberately NOT here:** this is a `arkadianet/ergo` PR (opt-in, minimal, one
  extension field + a local hook). It is not attempted from Aegis-USE, and
  `--produce` on non-dev networks is refused until it exists.

## Suggested build steps (for the ergo-side PR)

1. Config flag `merge_mining.aegis = { enabled, commitment_url }` (default off).
2. In `build_candidate_extension_fields`, when enabled, fetch the commitment (thin
   loopback call, short timeout, failure ⇒ omit the field) and add the
   `AEGIS_MM_KEY` field. Respect rule 404/405.
3. A test: a candidate built with the hook carries exactly one `AEGIS_MM_KEY`
   field of 33 bytes; disabled ⇒ no field; unreachable source ⇒ no field, normal
   candidate.
4. Dogfood: run the Rust Ergo testnet node with the hook + a co-located
   `aegis-node --network test`, and confirm the aegis-node's anchor-watcher
   ingests real shares (the first *real* Autolykos-secured Aegis blocks).
