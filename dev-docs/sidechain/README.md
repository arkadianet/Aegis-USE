# Aegis design docs

**Status:** Aegis is a **hash-native private sidechain** (Plonky3 / BabyBear /
Poseidon2) with a **trustless `verifyStark` peg bridge**. The engine, ZK spend
proofs, note encryption, wallet, and node are **built and integrated**; a
networked merge-mined testnet is cut; and the **first fully trustless peg
round-trip completed 2026-07-19** on the STARK devnet (release tx
`01cba5ace7d9aeb2f4a8e9bec9e277db5dfbe3f977a8a5d2573fdb31169831d6`, accepted).
What remains: the rigorous e2e campaign, prover-speed optimization, the
[HARDENING.md](./HARDENING.md) tiers, and the external-review value-gate before
any real value.  
**Archive:** Superseded notes live under [`notes/archive/`](./notes/archive/) — do not use as primary.

> **Engine (2026-07-17 ADR, ACCEPTED):** the shielded pool is **hash-native**
> (Plonky3 uni-STARK over BabyBear, Poseidon2 commitments, `owner = H(nk)`,
> Poseidon-Merkle accumulator), **superseding** the Curve-Trees + Bulletproofs
> engine. Rationale + measured A-vs-B evidence:
> [adr-hash-native-engine.md](./adr-hash-native-engine.md) and
> [spike-results/](./spike-results/). The Curve-Trees engine (`aegis-crypto`,
> `vendor/curve-trees`, `aegis-wallet`) is retained as the prior baseline but is
> **not the live path**; docs that describe it are legacy context.

> **Bridge (trustless):** the Aegis bridge is the **trustless verifyStark
> settlement design** —
> [stark-settlement-design.md](./stark-settlement-design.md),
> [stark-devnet-integration.md](./stark-devnet-integration.md). A settlement STARK
> is verified *on Ergo* by `verifyStark` (EIP-0045, `0xB9`) and `PegVault` releases
> against it — **round-trip proven on devnet (2026-07-19)**. The k-of-n
> **attester committee bridge (S1a–S1d) is RETIRED**: the `aegis-attest` crate,
> the node attestation service, `AttestRegistry.es`, and the committee authority
> in `SideChainState.es` were removed from `main` and are preserved at git tag
> `attester-bridge-final` (its design docs `attester-infra.md` /
> `s1c-attester-unlock.md` live there too). Mainnet activation awaits upstream
> EIP-0045 (ergoplatform/eips#103, sigmastate-interpreter#1116). Older docs that
> describe attester/`V_cap` peg-out mechanics are historical context, not the
> current plan.

## The live architecture (read in this order)

| Doc | Contents |
|---|---|
| **[adr-hash-native-engine.md](./adr-hash-native-engine.md)** | The decision: Aegis goes hash-native (Option B), superseding Curve-Trees — with the price accepted and the roadmap |
| **[spike-results/](./spike-results/)** | The measured A-vs-B settlement-cost evidence the ADR rests on |
| **[hash-native-engine-design.md](./hash-native-engine-design.md)** | The live engine: Poseidon2/commitment/nullifier/Merkle, the STARK AIRs |
| **[hash-native-spend-circuit.md](./hash-native-spend-circuit.md)** | The 2-in/2-out ZK spend circuit (hiding, value-conservation, range, membership) |
| **[stark-settlement-design.md](./stark-settlement-design.md)** | Trustless peg-out: the settlement statement + incremental O(epoch) transition |
| **[stark-devnet-integration.md](./stark-devnet-integration.md)** | `verifyStark` (`0xB9`) on the devnet, `PegVault`, the proven round-trip |
| **[HARDENING.md](./HARDENING.md)** | Consolidated post-campaign roadmap; tiers; the real-value review-gate |

## Foundational specs (protocol depth)

| Doc | Contents |
|---|---|
| **[aegis-spec.md](./aegis-spec.md)** | Product, ledger, addresses, wallet, fees, node/MM, crates |
| **[params.md](./params.md)** | Working numbers only (design stage) |
| **[peg.md](./peg.md)** | Ergo peg contracts, mint/burn, unlock |
| **[peg-spv-design.md](./peg-spv-design.md)** | G2.5 draft: Ergo-SPV-in-consensus objectivity + peg-in/out flows (draft, not canon) |
| **[g25-spv-reuse-spike.md](./g25-spv-reuse-spike.md)** | G2.5 feasibility spike: Autolykos/NiPoPoW/inclusion verifiers reusable-as-is (SPV = wiring, not new crypto) |
| **[g25-pegmint-packaging.md](./g25-pegmint-packaging.md)** | G2.5 `verify_pegmint` deterministic objectivity sequence + reorg policy (mint side reuses S5a) |
| **[testnet-bringup-runbook.md](./testnet-bringup-runbook.md)** | No-value mechanics-testnet bring-up (aegis-node + Scala node @9062 + aegis-mm); honest unbuilt/blocking list |
| **[privacy.md](./privacy.md)** | Shielded pool + proving engine |
| **[note-protocol.md](./note-protocol.md)** | Note structure, keys, nullifiers, encryption, tx shape (G1.6 — **revision needed**) |
| **[n1-nullifier-fix-design.md](./n1-nullifier-fix-design.md)** | P0 nullifier-malleability: decision (Poseidon ships) + P-REL fallback |
| **[external-review-brief.md](./external-review-brief.md)** | Self-contained brief for the external cryptographer (composed circuit + the 5 sign-off questions) |
| **[g16-adversarial-review.md](./g16-adversarial-review.md)** | 3-lens red-team of note-protocol + consensus (2026-07-12); decisions + fix triage |
| **[security.md](./security.md)** | Trust model, mitigations, unlock ladder |
| **[security-appendix.md](./security-appendix.md)** | Full adversarial attack catalog |
| **[engineering.md](./engineering.md)** | Scale/feasibility: reuse matrix, missing specs, workstreams, kill criteria |
| **[g15-proving-spike.md](./g15-proving-spike.md)** | G1.5 spike results — **PASS** (measured prove/verify on target hardware) |
| **[consensus.md](./consensus.md)** | Consensus spec: PoW binding (extension-field commit), header, DAA, fork choice, genesis, limits |
| **[contracts/GAPS.md](./contracts/GAPS.md)** | ErgoScript requirements (fresh-authored; upstream reference-only) |
| **[DEFERRED.md](./DEFERRED.md)** | Living register of deferred features, open params, debt, research — with revisit triggers |
| **[../plans/aegis-impl.md](../plans/aegis-impl.md)** | Implementation plan / gates (G1.5 proving spike first) |

## One-liner

**Aegis** — merge-mined Ergo sidechain for private **USE** payments (`aegis1…` addresses). Global shielded note pool, **hash-native** (Plonky3 uni-STARK / BabyBear / Poseidon2-Merkle). 1:1 peg with a **trustless `verifyStark` bridge** (settlement STARK verified on Ergo → `PegVault` release). Live crates: `aegis-engine` (`engine/`) / `aegis-hn-wallet` / `aegis-node`; legacy Curve-Trees engine retained but not the live path.

## Conflict resolution

`params.md` wins for numbers; `security.md` for trust/TVL gates; `engineering.md` for feasibility/status; then `aegis-spec.md`.
