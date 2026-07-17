# Aegis design docs

**Status:** Consolidated primary docs (2026-07-11; fee redesign 2026-07-12).  
**Stage: design — nothing is frozen.** "Decided" means current-best-reasoning, revisable until scaffold; revisions go through these docs so the trail stays coherent.  
**Archive:** Superseded notes live under [`notes/archive/`](./notes/archive/) — do not use as primary.

> **Bridge status (2026-07-17, operator decision):** the Aegis bridge is the
> **trustless verifyStark settlement design** —
> [stark-settlement-design.md](./stark-settlement-design.md). The k-of-n
> **attester committee bridge (S1a–S1d) is RETIRED**: the `aegis-attest` crate,
> the node attestation service, `AttestRegistry.es`, and the committee authority
> in `SideChainState.es` were removed from `main` and are preserved at git tag
> `attester-bridge-final` (its design docs `attester-infra.md` /
> `s1c-attester-unlock.md` live there too). `SideChainState.es` keeps its
> transition-constrained shape with a placeholder authority slot where the
> verifyStark predicate plugs in. Mainnet activation of the trustless bridge
> awaits upstream EIP-0045 (ergoplatform/eips#103, sigmastate-interpreter#1116).
> Older docs below that describe attester/`V_cap` peg-out mechanics are
> historical context, not the current plan.

## Start here

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

**Aegis** — merge-mined Ergo sidechain for private **USE** payments (`aegis1…` addresses). Global shielded note pool (Curve Trees + Bulletproofs). 1:1 peg via ErgoScript receipts + vault. Crates: `aegis-spec` / `aegis-node` / `aegis-mm`.

## Conflict resolution

`params.md` wins for numbers; `security.md` for trust/TVL gates; `engineering.md` for feasibility/status; then `aegis-spec.md`.
