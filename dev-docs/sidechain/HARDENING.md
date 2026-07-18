# Aegis hardening & roadmap checklist

Living tracker of the honest deferrals accumulated across the hash-native build.
Ordered by what each item protects. Nothing here blocks the devnet/testnet
demonstration; the crypto-maturity tier gates **real value** only.

> Sequencing: bridge finale → rigorous e2e campaign (which *surfaces* more items —
> that's its job) → this list, **consensus soundness first**, scaling second,
> crypto-maturity + external review last (the value gate).

## Tier 1 — consensus soundness (do not ship real value without)

- [ ] **Full aux-PoW commitment.** Bind the merge-mined Ergo PoW to the hn
      `state_root` via an extension-Merkle commitment, so a solution is provably
      *for this Aegis state*. (Currently the hn header carries the roots but the
      aux-PoW→state binding is deferred.)
- [ ] **Aux-PoW-weight fork choice.** Replace the current linear-extension fork
      choice with PoW-weight accumulation, so reorgs follow real work. This is the
      single biggest open consensus item.
- [ ] **Consensus-enforced maturity over hidden inputs.** Coinbase (and settler-
      reward) maturity is wallet-side today; enforcing it in consensus when the
      inputs are *shielded* is a genuinely hard problem — needs design, not just
      code.
- [ ] **Peg-in reorg deferral.** Depth threshold exists; harden the
      devnet-reorg-under-deposit path (deferral + re-org rollback of an
      in-flight mint).

## Tier 2 — performance & scaling (makes settlement cheap/quick)

- [ ] **Incremental / checkpointed state transition.** Kills the per-block sweep
      term (~4.5M cycles/block) that dominates a long-epoch settlement proof — the
      chain maintains running checkpoints so settlement stops re-walking history.
      *Promoted to a settler-economics prerequisite:* the difference between a
      45-min hourly job and a minutes-class one.
- [ ] **Narrow-trace rework.** ~3–10× off the per-tx verify term, and pushes phone
      proving back under ~1s (currently extrapolates to ~1.5–4s post-ZK). Same
      lever that cheapens settlement.
- [x] ~~**Poseidon2 precompile / accelerator** in the settlement guest~~ — **RULED
      OUT 2026-07-19 (feasibility spike, source-grounded).** RISC0's Poseidon2 ecall
      exists but is a **different function**: t=24 / R_P=21 / RISC0-proprietary
      constants+MDS, vs our client's Plonky3 t=16 / R_P=13. Cryptographically
      distinct — cannot verify our hashes. Using it would require re-basing the
      client's entire Poseidon2 (→ note-commitment + nullifier crypto) on RISC0's
      t=24 instance: chain-id-breaking, review-gated, not offered by Plonky3. Bad
      trade for a settlement-only win. **→ narrow-trace is THE settlement lever.**
      Only precompile-compatible route = make the CLIENT proof RISC0-native
      recursion format (architecture swap, parked — see below).
- [ ] **Productionize GPU proving.** The `~/apps/risc0-cuda` container becomes the
      standard settler path (host gcc-16 vs CUDA toolchain worked around via an
      Ubuntu-LTS build container; image-id pin-matched).

## Tier 3 — cryptographic maturity (the real-value gate)

- [ ] **FRI parameters to production.** Currently ~113-bit *conjectured*; raise
      queries / log-blowup for mainnet margin.
- [ ] **R1-T threshold turnstile.** Bounds unbounded nullifier-set growth (the
      "storage rent" analog) and recycles stranded USE → pot. Hash-native upgrade:
      Statement 2 computes `expired = epoch_total − Σ(migrated)` *in-proof* (no
      attester decryption). Test on compressed epochs.
- [ ] **External crypto review.** Standing value-gate. A fresh shielded core gets
      outside eyes before it holds any real USE. Everything ships testnet/devnet
      until then.

## Tier 4 — network & DoS

- [ ] **Per-peer unverified-tx rate limiting** + a fee-bond checked *before* the
      ~52ms proof verify (cheap-checks-first ordering is done; the bond isn't).
- [ ] **libp2p gossip.** Replace the current HTTP-feed P2P + linear-extension sync
      with real gossip for a multi-operator network.

## Open tuning question — block time

Settlement sweep cost scales with **blocks covered = interval / block_time**, not
wall-clock. So block time trades payment-confirmation UX against settlement-proof
cost, and is also bounded by merge-mining cadence (Aegis blocks derive from Ergo
aux-PoW solutions).

| block time | blocks / hourly epoch | sweep cycles (~4.5M/blk) |
|---|--:|--:|
| 2s (current testnet) | 1,800 | ~8.1B |
| **15s (spec target)** | 240 | ~1.08B |
| 30s | 120 | ~0.54B |
| 60s | 60 | ~0.27B |

**Decision:** target **15s**, but treat as *measured, not assumed* — re-run the
cost model after the incremental-transition optimization lands and confirm 15s
sits in the sweet spot (snappy payments + minutes-class settlement), adjusting
only if the data says otherwise. Note the incremental transition largely removes
the sweep term, which *decouples* block-time choice from settlement cost.

## Settler economics (design pinned; implement post-bridge, with R1-T pot work)

Settlement is a **permissionless singleton GPU job** (~5–10¢ real cost/run;
ordinary nodes never prove; miners unaffected; a missing settler delays
withdrawals — liveness, never safety). Reward is **Aegis-side from the pot**: the
settler binds their own Aegis address as a **public journal field** (`settler_dest`
— proof-bound, so unstealable), and consensus mints
`min(pot, S_base + S_per_wd × withdrawals)` to it on observing the L1-accepted
settlement, via the same deterministic publicly-audited pattern as the coinbase.
`S_base` only when ≥1 withdrawal (no empty-settlement farming). Funded by the
1%/way peg fees → pot. Start `S_base = 0.25 USE`, `S_per_wd = 0.05 USE` (tunable).
