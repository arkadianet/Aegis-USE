# Aegis hardening & roadmap checklist

Living tracker of the honest deferrals accumulated across the hash-native build.
Ordered by what each item protects. Nothing here blocks the devnet/testnet
demonstration; the crypto-maturity tier gates **real value** only.

> Sequencing: bridge finale → rigorous e2e campaign (which *surfaces* more items —
> that's its job) → this list, **consensus soundness first**, scaling second,
> crypto-maturity + external review last (the value gate).

> **Milestone reached — first trustless round-trip (2026-07-19).** The bridge
> finale landed: a full hash-native peg round-trip completed trustlessly on the
> STARK devnet — `verifyStark` (EIP-0045 opcode `0xB9`) verified the settlement
> proof on-chain and the `PegVault` released against it. Release tx
> `01cba5ace7d9aeb2f4a8e9bec9e277db5dfbe3f977a8a5d2573fdb31169831d6` was accepted
> by the devnet. Next in sequence: the rigorous e2e campaign, which will surface
> more items into the tiers below.

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

- [x] ~~**Incremental / checkpointed state transition.**~~ **DONE (v4 cut,
      `676664a`/`092fc87`).** The note-tree maintains an O(epoch) running frontier
      so settlement no longer re-walks history — kills the per-block sweep term
      (~4.5M cycles/block) that dominated a long-epoch settlement proof, turning a
      45-min hourly job into a minutes-class one. This also *decouples* block-time
      choice from settlement cost (see the block-time table below).
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

- [x] ~~**Epoch-validity fabrication gaps F1-F3.**~~ **CLOSED + RED-REVIEWED CUT-SAFE
      (2026-07-20, on main via the v6 merge).** The whole anti-fabrication surface is now
      priced in-guest (design + security analysis: `epoch-validity-f1-f3-design.md`; the
      whole-surface hunt expanded the original F1-F3 to 8 fixes): **F1** authenticated seam
      (header-id hash-walk back to vault R7, induction to pinned genesis; `recent_roots`/
      `pot_before`/`shielded_before` DERIVED not witnessed; `shielded_after` added as a
      header field) → private-tree injection dies `SeamTipMismatch`/`AnchorOutOfWindow`;
      **F2** in-guest LWMA DAA seeded from the authenticated seam, byte-identical port of the
      node's `next_nbits` → difficulty-1 mining dies `NbitsMismatch`; **F6a** height
      continuity (closes F2's bootstrap lever); **F6b** distinct-PoW-message dedup, wired
      into the LIVE guest → share amplification dies `SharedPowMessage`; **F6c** full
      all-nullifier R6 accumulator (nf0+nf1, every spend) → cross-settlement replay dies
      `AlreadySettled`; **F3** peg-in backing (tx-Merkle inclusion + box-id recompute +
      one-mint-ever SMT vs the E4-anchored Ergo chain) → unbacked mints die; **F5** anchor
      burial ≥ `A_MIN` + mandatory `REQUIRE_E4` → secures the Ergo-hashrate fabrication
      floor. Node↔guest oracle-parity gates (header-id, DAA, recent-roots window) pass;
      full workspace green (engine default+aux-pow, node 285, guest ELF cross-compile).
      **HEADLINE:** merge-mining re-bases the fabrication floor from Aegis-hashrate to
      ERGO-hashrate (a fake tip must ride a self-mined canonical Ergo block). Remaining are
      cut-time / mainnet-gate items only, all fail-closed: (i) pin `PINNED_VAULT_TREE_BYTES`
      / `PINNED_USE_TOKEN_ID` / final `A_MIN` (`TODO(cut)`); (ii) host-side F3 backing-witness
      generation (`dump_epoch`/`exec-epoch`/`settlement/host`); (iii) MAINNET-gate liveness
      check — confirm dummy `nf1`s are always distinct across spends (F6c rejects honest
      settlements otherwise; fails closed, never under-pays); (iv) non-aux-pow images skip
      backing/DAA but are gated shut by `REQUIRE_E4` on the mainnet image (documented, no
      mainnet exposure). F4 (spend-fee bind) folded; superseded double-pay entry below.
- [ ] ~~**Settlement epoch-canonicality / double-pay (red-review 2026-07-19).**~~ Superseded
      by the F1-F3 entry above — epoch-validity IS the fix, but incomplete per F1-F3. Original:
      the settlement guest proves a burn is a leaf of `(prev_root, new_root]` but
      NOT that `new_root` is the *canonical* hn chain root. A malicious permissionless
      settler can build a non-canonical epoch re-appending an already-settled burn +
      reuse its spend proof → **double-pay / peg-inflation** (pays the original
      recipient, so not theft, but releases 2× USE for one burn → drains the vault).
      Pre-existing in v5; NOT introduced by batching/D1. This is what makes the bridge
      "trustless *modulo epoch canonicality*", not fully trustless. FIX (one of):
      (a) **settled-burn accumulator** (settlement-nullifier set in the vault R6 —
      idempotent-per-burn, cheaper, closes it without full epoch-validity), or
      (b) full **epoch-validity proof**. Testnet-acceptable (honest settler);
      mainnet-blocking. Likely the top post-batching security priority.
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
