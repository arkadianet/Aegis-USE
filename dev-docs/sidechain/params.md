# Aegis — working params (design stage)

**Date:** 2026-07-11 (rev: chain name **Aegis**)  
**Worktree:** `.worktrees/privacy-use-cash-sc` · branch `feat/privacy-use-cash-sc`  
**Canon docs:** [README.md](./README.md) (`aegis-spec`, `peg`, `privacy`, `security`). This file = **numbers only**.  
**Archived research:** `notes/archive/` (do not treat as primary).

## Network / brand

| Key | Value |
|---|---|
| `chain_name` | **Aegis** |
| `network_name` (dev) | `aegis-dev` |
| `network_name` (test) | `aegis-test` |
| `network_name` (main) | `aegis` |
| `sc_block_target` | `15s` |
| `asset` | USE (Dexy USD) **only** |
| Address HRP | `aegisdev` / `aegistest` / `aegis` |

## USE token (mainnet explorer)

| Key | Value | Source |
|---|---|---|
| `name` | USE | Explorer |
| `description` | USE (DexyUSD) | Explorer |
| `type` | EIP-004 | Explorer |
| `decimals` | **3** | Explorer |
| `atomic_unit` | `0.001` USE = `1` base unit | `10^-decimals` |
| `emission_amount` | `1_000_000_000_000_000_000` **base units** (= `10^15` USE at 3 decimals; explorer UI shows the USE figure) | On-chain (verified 2026-07-12) |
| `mint_block` | `1666991` | On-chain (verified 2026-07-12) |
| `mint_tx` | `adbf3c5855aa66baf5e45dc192c2bb6dc85f168eafffc9ade7d3fd79137a39cd` | Explorer |
| `use_token_id_mainnet` | `a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669` | Explorer / operator |
| `use_token_id_testnet` | **TBD / unknown** | Not confirmed |
| `lab_stand_in` | Prefer mainnet-id mirroring on private/regtest; else issue **3-decimal** testnet token | Operator-controlled |

**Do not** hard-code DexyGold as USE.

## Amounts — match USE (no fixed face-value ladder)

| Rule | Value |
|---|---|
| On-SC transfers | Any multiple of **`0.001` USE** (same as mainnet) |
| Peg in (lock → mint) | Same: any multiple of `0.001` USE, 1:1 |
| Peg out (burn → unlock) | Same: any multiple of `0.001` USE, 1:1 |
| Min dust | TBD (at least 1 base unit; may set higher for fees) |

Coffee `5.600` USE = one payment of `5600` base units (or whatever split the wallet chooses). No forced `0.1` / `1` / `10` notes.

**Privacy note:** On-SC balances are fully private — see [privacy.md](./privacy.md). Peg amounts on Ergo remain public.

## Fees & emissions

**Invariant:** never mint unbacked USE. Miner subsidies come only from fees. Detail: [aegis-spec.md](./aegis-spec.md) §11.

| Stream | Current design (provisional — tune after dogfood) | Goes to |
|---|---|---|
| SC tx fee | **Flat `0.03` USE** — public, amount-independent by standing rule (below) | **Emission box 100%** — miner income is the block reward only (operator decision 2026-07-12) |
| Peg-in fee | `max(1 USE, 1% × N)` — value-scaled where `N` is already public; floor ≈ spam cost only, never a participation tax | Emissions pot |
| Peg-out fee | `max(1 USE, 1% × N)` — symmetric. Round trip `2%`: deliberately premium ("users will pay for privacy" — operator decision 2026-07-12); mixer-tier pricing but non-custodial; amortizes over holding time. Tune **down** after dogfood if elasticity bites | Emissions pot |
| Per SC block | `min(pot, 0.01 + 0.01 × txs_included)` to miner — 1¢ base + 1¢ inclusion bonus per tx (pot nets +2¢/tx) | Scales with bridge + on-chain use |

| Rule / open | Value |
|---|---|
| **Amount-independence (standing privacy rule)** | On-SC fees are never a function of payment amount, and tx shape is uniform (padded arity) — a value-correlated fee is a public amount oracle (re-enables peg-edge tracing/taint analysis). Value-scaling lives at the peg edges only. Replaces the old `fee_fingerprint_mitigation` gate. Rationale: [engineering.md](./engineering.md) §4 |
| `tx_fee_per_weight` | Dropped in favor of uniform tx shape; revisit only if shape classes are ever introduced |
| Dogfood peg-in / peg-out / SC flat | `max(0.1, 1%×N)` / `max(0.1, 1%×N)` / `0.01` — same rate as end so dogfood exercises the real fee math |
| Rate ↔ security note | Fees above miner payout accumulate as pot **runway**; if pot persistently overflows, the lever that converts revenue → security is EMA-scaled `R_target`, not more rate |
| `R_target` EMA(peg volume) | Optional later; v1 fixed |

## Unlock confirmations (provisional)

| Key | Value | Rough wall time |
|---|---|---|
| `M` (SC confs after burn) | `120` | ~30 min @ 15s |
| `N` (Ergo depth after anchor) | `10` | ~20 min @ 2m Ergo blocks |
| `N_mint` (Ergo confs before PegMint) | `10` | same family as `N` |
| `T_delay` (Ergo blocks after UnlockIntent) | `720` | ~1 day — tip-lie watch window |
| `V_cap` (PegVault max USE) | `1000` | raise only after U1-strong (attested tip) |
| `attest_k` / `attest_n` | `2` / `3` | unlock attestations when S1 enabled |
| `R_rent` | **TBD** | Min ERG endowment on SideChainState / PegVault / FeePot / DoubleRedeem |
| `coinbase_maturity` | `120` SC blocks | ~30 min (= `M`); reorged coinbase must not poison downstream spends |

See [security.md](./security.md) (U1 ladder).

## Sanity

- [x] SC + peg precision = mainnet USE (`0.001`)  
- [x] Coffee `5.600` USE is a normal amount, not a note puzzle  
- [x] Mainnet USE token id recorded  
- [x] Decimals = **3** from explorer  
- [ ] Testnet USE token id (if any) confirmed  
- [x] Fee / emissions model in [aegis-spec.md](./aegis-spec.md) / params  
- [ ] Peg fee & `R_target` tuned after dogfood  
