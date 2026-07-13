# Fee design under privacy — alternatives considered (2026-07-12)

**Status:** decision record (archive). Outcome lives in `params.md` (standing rule) + `aegis-spec.md` §11 + `engineering.md` §4.

## The goal tension

Value-scaled fees ("moving 100k should pay more than a coffee") vs amount confidentiality — on this chain, amount hiding is the keystone property: peg edges are public, so any per-tx amount signal re-links peg-in → internal activity → peg-out, and on a quiet chain amounts are the discriminator that defeats the pool.

## Options

### 1. Public `%`-fee (incl. bucketed) — REJECTED

Fee = `0.1% × amount` published per tx is an amount oracle to ~1 USE resolution. Buckets leak the bucket. Guts "privacy between pegs" (the product claim) and re-enables taint analysis. Worst on a quiet chain, where the anonymity set is small.

### 2. Hidden `%`-fee paid to miners — REJECTED (open research)

Fee must be hidden from *everyone* incl. block producer (miner-visible fee = miner-visible amount). But then:
- Miner cannot spend a reward note built from others' hidden commitments (no value/blinding opening available; block producer unknown at tx-construction time, so no encryption target).
- Public payout rules (`min(R_target, pot)`, 90/10 split) cannot be verified against hidden sums.
- Any public per-tx handle that permits aggregate opening also permits per-tx brute force (fees are low-entropy).
- Escape hatches = threshold committee decrypting epoch aggregates (adds federation trust *for privacy*) or encrypted mempools (research). Zcash/Monero/MW all have public fees for exactly these reasons.

### 3. `%`-burn, EIP-1559 style — REJECTED (economics)

Enforce `burn ≥ rate × payment` in-circuit; commitment never opened by anyone. Cryptographically clean (perfect privacy, consensus-enforced, change-exemption provable via same-spending-key derivation in-circuit; burned SC supply leaves the Ergo vault over-collateralized — safe direction for I1). **But it funds zero security** — destroys the revenue the (tiny) MM security budget needs, and the vault surplus is stranded/unmeasurable. Also drags extra constraints into the W1 circuit. Fairness without funding = wrong trade here.

Note-system pathology recorded for posterity: naive `%`-fees charge on **notes touched, not value transferred** (coffee from a single 100k note → 100 USE fee; self-consolidation taxed). Fix exists (change-exemption via in-circuit key-ownership proof) but is moot given the outcome.

### 4. Value-scaling at the peg edges — ADOPTED

Peg amounts `N` are public by nature; the edge is where vault risk (`V_cap`, `T_delay` exposure) is created. So: symmetric `%` both directions (params.md is authoritative for the rate; floor sized to spam cost, not revenue: a large floor is a regressive participation tax that chills the anonymity set), all to pot → miners. Rate history: 0.1% (assistant, anonymity-set-first) → 0.25% (0.5% round trip ≈ one DEX swap, mid-market vs privacy comps: relayers/coinjoin ~0.3%+, mixers 1–3%) → **1% (operator decision 2026-07-12: premium pricing, "users will pay for privacy"; 2% round trip = mixer-tier but non-custodial; tune down after dogfood if elasticity bites)**. On-SC fee = flat, public, amount-independent, uniform (padded) tx shape — a constant leaks zero bits. Whale pays proportionally where the amount is already visible; inside the pool everyone is identical. Retires `fee_fingerprint_mitigation` by construction; fixes the old flat 10-USE peg-in being regressive.
