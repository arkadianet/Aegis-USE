# Storage rent on Aegis — privacy cost ladder (2026-07-12)

**Status:** decision record (research option, not adopted). Outcome: R0 in aegis-spec §12; state-growth item in engineering.md §3.

Rent needs three hidden things: identify old unspent value, know its amount, seize it. Options by privacy cost:

| Opt | Design | Leak | Verdict |
|---|---|---|---|
| R0 | No rent (current) | none | **Adopted v1.** Lost notes strand USE in vault forever = permanent over-backing (safe direction of I1); only cost is foregone pot revenue + dead capital. Note asymmetry: on Ergo L1 lost USE *does* recycle via rent after 4y (miners collect abandoned boxes incl. tokens); on Aegis R0, never |
| R3 | Age-priced peg-out | holding duration at exit | Useless — lost notes never exit; reclaims nothing |
| R2 | In-circuit note expiry, no recycling | ~1 bit/spend ("not expired") | Enforcement without reclaim (expired amounts stay unknowable) — converts lost-by-accident into lost-by-rule with zero benefit. Strictly worse than R0 |
| **R1** | **Epoch turnstile**: per-epoch tree+nullifier set; live notes must migrate before epoch close via **public (bucketed) value** migration txs (Zcash Sprout→Sapling pattern). Expired value = public inflows − public outflows → swept to emission box. Also archives old nullifier sets (solves the real unbounded-state problem) | (1) periodic value census (bucketed); (2) cohort/timing linkage; (3) **kills mattress cash** — miss the window ⇒ confiscation by rule (inheritance/cold-storage hazard); (4) anonymity set partitions per epoch | **Minimal viable rent.** Deferred — layerable later by consensus upgrade without redesign |
| R4 | Transparent amounts | everything | = rejected C0; not an option |

## R1-T — threshold turnstile (PREFERRED end-state, 2026-07-12 rev)

Key fact: total pool value is always public (all inflows/outflows public; transfers conserve). So expired value = epoch_total − migrated_total; the only hidden number is the migrated aggregate. Reveal it **in aggregate via the U1-strong attesters** instead of per-tx:

- Migrations = ordinary shielded self-spends into the new epoch tree (amounts hidden from everyone).
- Each carries a verifiable encryption of its value under the attesters' **threshold** key (circuit proves ciphertext = commitment; additively homomorphic, e.g. exponential ElGamal — epoch aggregate decrypted via small-range DL).
- k-of-n attesters decrypt **only the sum**, post it signed (same trust machinery as unlock attestations) → `expired = epoch_total − sum` swept to emission box; old epoch's nullifier set archived (kills the unbounded-state problem).
- Privacy cost collapses to: k-of-n collusion could decrypt individual migration *values* (not identities), once per epoch. No census, no buckets.
- **Grace tier ("privacy decays before money"):** after the migration window, un-migrated notes remain claimable via public-value late-migration (reveal amount, keep identity); final sweep only after epoch + grace.
- **Cadence (operator decision 2026-07-12): 1y epoch + 1y grace ⇒ sweep at ~2y untouched.** Deliberately shorter than Ergo L1's 4y rent: Aegis is **a chain for use, not storage** — the design goal is a small rolling ledger (~2y of nullifier state) + fast recycling of lost USE into the emission box; deadline-free cold storage = peg out to L1 (the permanent escape hatch). Live wallets auto-migrate in background (0.03 fee); migration waves add cover traffic. **Wallet requirement when R1-T ships:** loud, escalating warnings as notes approach transparency (year 1) and sweep (year 2) — extends M7 footgun list.
- Failure mode: attester quorum unavailable ⇒ degrade to R0 (value strands; nothing unsound).
- Cost: verifiable-encryption gadget in the spend/migration circuit (W1 line item); per-epoch anonymity-set cohorts; soft liveness expectation.

**Sequencing:** post-v1 consensus upgrade — requires S1 attesters live + epoch machinery. v1 ships R0; adopt R1-T when (a) S1 is live and (b) either nullifier-set growth is a measured problem or stranded value is material. The census turnstile (plain R1) is superseded by R1-T.
