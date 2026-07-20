# v6 red-review findings (2026-07-20)

Adversarial red-review of the complete converged+validated v6 (branch
`feat/v6-vkpin-e2e`). **Verdict: FINDINGS — safe to cut the testnet as an
honest-settler / pre-value demonstrator, but the anti-fabrication mechanism has
real gaps vs its own design. F1–F3 are MAINNET-BLOCKING and MUST be closed
before any real value.** The docs previously implied these checks were present;
they are DEFERRED. Corrects the "Stage-T = every check present / fabrication
priced / trustless at the SPV ceiling" claim — that is the design *intent*, not
the current implementation.

## Testnet-cut safety (attacked, all BLOCKED)
- Recipient-swap theft (D1): burn_cm binds recipient+amount, proof-bound through
  recursion, welded in verify_epoch — blocked at every entry point.
- Double-pay replay: R6 settled-set non-membership+insert, vault-chained — blocked.
- Vault value-leak (N outputs): conservation + per-recipient USE-token pinning +
  token-free fee box — blocked.
- Guest/config swap: EPOCH_IMAGE_ID pinned + AggParams pin; no E2-off release path
  against the deployed (aux-pow) predicate — blocked.
- Consensus split (E0): node DAA + Strict aux-PoW + real-work fork choice.
- Digest add/drop/reorder/alter: order/count-sensitive root, real in-circuit spend
  verify, native↔circuit parity — blocked.

## MAINNET-BLOCKING findings (the anti-fabrication is NOT yet sound)
- **F1 — anchor-window seam roots UNAUTHENTICATED (peg-inflation / vault-drain).**
  `engine/src/epoch/verify.rs:167` copies settler-supplied `w.seam_roots` into
  `recent_roots` with NO header-walk back from `T_prev`. The doc comment
  (verify.rs:64-68) claims `anchor_seam` authentication — NO SUCH CODE; field is
  `vec![]` everywhere. + `pot_before`/`shielded_before` are unauthenticated
  witness (mod.rs:53), so conservation can't catch the injection. A settler names
  a fake private-tree root as a seam → unbounded fake-value extraction.
  FIX: authenticate seam roots by walking R7 back; bind pot/shielded into the
  R-register chain.
- **F2 — E2 share verify does NOT enforce DAA (defeats work-pricing).**
  `engine/src/epoch/share.rs:147-159` checks PoW vs the block's SELF-DECLARED
  `sc_nbits`, never vs the DAA expectation (guest doesn't constrain it; node does,
  but design §3 doesn't trust the node for bridge safety). Fabricator sets
  difficulty-1 → mines the fake suffix trivially at mainnet. FIX: recompute LWMA
  in-guest over the suffix + authenticated fork-point difficulty.
- **F3 — peg-in backing NOT verified in-guest (inflation).**
  `verify.rs:261-268` re-derives peg-in mints with no proof the Ergo deposit
  exists; E4 anchors only the tip. Fabricated suffix mints unbacked peg-ins.
  FIX: prove peg-in deposits against the anchored Ergo state.

## Minor / hardening
- **F4 — spend fee declared, not proof-bound.** `layer1_epoch` folds a declared
  `fee` (digest_agg.rs:862,890), not the proof's `PUB_FEE`. Release amount is
  still bound via burn_cm; only internal pot/coinbase accounting affected. Close
  the bind.
- **F5 — E4 anchor depth ignored** (guest-epoch main.rs:99); no A_min/A_slack.
  Mainnet param work.

## Pre-real-value gate (updated)
F1, F2, F3 (close the fabrication pricing) + F4/F5 + Stage-M (per-block IVC for E2
at long epochs, both-nf accumulator AIR, blake2b AIR) + the standing external
crypto review. Testnet cut is pre-value and does not require these.
