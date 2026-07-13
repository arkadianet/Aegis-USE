# Aegis peg-in v2 — PegVault eager-ValDef FIX verified on testnet

Captured 2026-07-13 from the Scala testnet node (`127.0.0.1:9062`, appVersion
6.0.3, network `testnet`). This ceremony re-proves, on the public Ergo testnet
with zero real value, that the PegVault eager-ValDef bug found in the first
deployment (`test-vectors/testnet/peg/README.md`) is FIXED: a **clean
consolidation with a DepositReceipt (carrying a `Coll[Byte]` memo at R5) at
`INPUTS(1)`** — the exact shape the node previously rejected with
`sigma.exceptions.InvalidType: Cannot getReg[Long](5)` — was **accepted and
confirmed**.

## The fix (before → after)

**Before:** `PegVault.es` bound the whole payout predicate as a top-level
`val payoutOk = { … val n = intent.R5[Long].get … }`. Nodes in a top-level
`val`'s rhs are first-built in the sigma compiler's GLOBAL scope; `n` is used
twice (fee + expectedPaid), so CSE hoisted `INPUTS(1).R5[Long].get` into an
**eager top-level ValDef** evaluated on EVERY vault spend — and the typed read
THROWS (InvalidType, before `.get`) when `INPUTS(1)` is a receipt with a
`Coll[Byte]` memo at R5. Receipts could never sit at `INPUTS(1)` on a top-up
(liveness bug only; the sum-accounting is index-agnostic, no theft).

**After:** both path bodies moved SYNTACTICALLY inside the
`if (isPayout) { … } else { … }` branches (`val pathOk = if …`). Branch
operands are lazy compiler scopes, so multi-use nodes built there hoist to
ValDefs INSIDE the branch: the payout-register reads (`R4`/`R5`/`R6`,
`OUTPUTS(1)`/`OUTPUTS(2)`) now evaluate only on the payout path. Every
security predicate (pass-2 sum-accounting, fee pinning, `tokens.size == 2`,
V_cap, T_delay from `creationInfo`, DoubleRedeem binding) is verbatim-preserved.

Verified two ways before broadcast, then by the chain:
1. Repo interpreter (`ergo-sigma`) over synthetic contexts: OLD tree reproduces
   the exact `InvalidType` on the receipt-at-INPUTS(1) top-up; NEW tree yields
   `TrivialProp(true)` there, `false` on a siphoning top-up, `true` on a happy
   payout, `false` on a pre-T_delay payout.
2. Repo `ergo-compiler` recompiles all 6 contracts (tree v3, Testnet):
   `DepositReceipt.es 138B · DoubleRedeem.es 79B · FeePot.es 74B ·
   PegVault.es 590B (was 596B) · SideChainState.es 209B · UnlockIntent.es 159B`.
3. The testnet consolidation below — the only oracle that catches this class.

## Identifiers

| What | Value |
|---|---|
| tUSE token id (reused from v1 ceremony) | `006a33af9b295c830b1fe19422ede003da35a1c3a5f6ac56618e99ef2eaa2bab` |
| **PegVault v2 singleton NFT id (fresh)** | `014b21beea1dbfc55837bd3fef92cb5e2ec57b8c4b5529c6dd731a0071db6ed4` |
| Fixed PegVault tree | `peg_vault_tree.hex` (**796 B** injected; canonical placeholder form 590 B) |
| Fixed PegVault P2S (testnet) | `3njX1QAFZjzvesxB13yw1MpAwq3RUAuqiERjrsK2LuUrg4uWhfuYXA9P8EpsRCMu9LDtSGPMk6KcCGDzPdt6UG857qmUMQKS78eV3u9cpwDDZtem3juGga6qEa7gvQxeamaG7orJ24G1tGHwg9DbBqXwUXm5xSuMhGRjUCJmuzXVawKkAfMwvVMGS6oQizjkju1UL1Azgz13itimcd6mGs19TkSVPchtEL9vyxuHEVhaKi4JdKNWsL5yi25cKoVyTT7HwWCDtYckKnCfKEo2Wf1uPu1TdjC7nyzx5TibZpm88yDMiVvkcn4mKGJcSYS27yxdWopEK8gBzPzocuvA1dY8gXmhQPp3X45zMjQJLjrQZSpwPgU3c19R9XhCKsg99pg7XukCG54c4Cm2E9btrRdc9NrBK4exfySH8fSaYWDagC2Ns6pPk9XtGerfWWTJD7v5Yk6oxW4sF53iEjjHi2ZkPrdxsCkn7V71pyDNJAYr3YL9wqDueQ9RpfSd12NMM3fZ4FpwbfJKa8quHVt5zmCK8eNypAJe8khTFn45Nc9zR5ihcRRSJyfLdvk2C5wToYP6jBi2D1bJRDbfqxEWAdmWJNg83NAFhV6X6YZbWnuxiAMRzSahjpZDzgfG4TwsXxFWWd1pwNafeB5oiJeuSCgQR5dp5avE6RFzPbHySXb6kmKjZvbdf5VscUj8h7FkzKVpAnEMkuYcEDN7YSZ7VoptUz1tmF16H1DREwZnjUrVeM4ZfLZW68crsKiPvCZTgHXQenLVDoaUxfMyyoSxFWbHhB2j7mp5RYDEfPf7RwtVST6sJJXC7d3LDTiNkkXt8X72FUaQiuDimERG3zpReHnjwvWCzfBPzkmLV2rKnsfqPR4iZeAt2hQshkzvNdQXdoHZe5zWSKXTXwBjfhPRvGjcksSPbmGYr3dxnnbFVXG4VBuMcWrBi9KMpeg4ap9HidmnEo4enCaUBAr2TTvW1xovUVBr8i26tcFyk1dSMkv1BfGysvjaEtdfgshG14ckhXKpRFqWwjoQrdYGysK3SCrJw5Uib2CBH9hmQAoF55EXxujwXj43JSbx3cXXiqLuqJS5vd` |
| DepositReceipt v2 tree (embeds the v2 vault NFT) | `deposit_receipt_tree.hex` (200 B) |
| blake2b256(receipt tree) = RECEIPT_SCRIPT_HASH | `3c9d5dd0376806ce559051cb70922ac519c979d65eea1375c26ef1a891916fb8` |
| DepositReceipt v2 P2S (testnet) | `4ftaxv5T31S2QUUiV15qA13B71LskmFXhghGJxD26A4qU1marXrvMTdBr5Hz8SvPUB5snomNo5Lv5CiWcm9uFcn6qAjEiM8XDXMMSo1WEoP25uWsXQUgRaPigPXp4ofWUP2TxgwJSRn9FYp6UBy3cTEGiAMLypqUkRTN5zr2WiWjuZwAHuuM1GPJT7baPH7wf8N1ytRvTHAF6wefeuAVB5rWVzVhat96XMrYV5xivmEoXkr723DBM1RmKmhuVS6Fipbp1Xk9dxRubUaGSDQK2T4p` |
| Depositor key (R7) | wallet P2PK `3WywEV3keFs3zpXTHx9wbAxjQcWdBU9yCWud4CmEuqsDPXpwgj7M` |
| sc_dest (R4) | secp256k1 G compressed `0279be66…f81798` (33 B) |
| R5 memo (the poison the old tree threw on) | `Coll[Byte]` `"aegis-testnet-lock-v2-memo-proves-eager-valdef-fix"` |

Dummy injections unchanged from v1 (top-up-only vault; payout ceremony not
deployed here): `DOUBLE_REDEEM_NFT = blake2b256("aegis-testnet-dummy-doubleredeem-nft")`,
`UNLOCK_INTENT_SCRIPT_HASH = blake2b256("aegis-testnet-dummy-unlockintent")`,
`FEE_POT_SCRIPT_HASH = blake2b256("aegis-testnet-dummy-feepot")`. Exact
injected sources: `*.injected.es`. Compiler: repo `ergo-compiler`,
`compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet)`; node
`/script/addressToTree` round-trips both addresses to these exact tree bytes.

## Transactions (ceremony order, all confirmed)

| # | txid | file | inclusion height |
|---|---|---|---|
| 1 mint v2 vault NFT | `f77231cda557fbd97a31769162d608a72dff384786d2047c7f5009c4de26b679` | `mint_vault_nft_tx.json` | 443678 |
| 2 vault deploy (NFT + 1.000 tUSE) | `2f027c8f42ca99192f4228a4d47ec3f8e8a6d062b0e5f6e27433e9b77aec1fff` | `vault_deploy_tx.json` | 443682 |
| 3 LOCK (100.000 tUSE, **R5 = Coll[Byte] memo**) | `6f01460cab876ad5a3e579f54ef44cd882e4c1e5c00a63ced2f0e3f4bba35e58` | `lock_tx.json` | 443685 |
| 4 **CONSOLIDATION, receipt at INPUTS(1)** | `f2b8d9d682c4e48cde8d2ec11264b6ec783c62edfa3325ab22b9f12c8e994c14` | `consolidation_tx.json` (+ `consolidation_tx_as_broadcast.json`) | 443688 |

Tx 4 is the headline: `INPUTS(0)` = vault
`c061945c6284a40f40dee1163e8aea66ea83ae9ea9454dcc10727792f010a6e4`,
`INPUTS(1)` = receipt
`78f2e0e4935412c98055aeeb012b95460ca9e25776c4ce6ecc9398815c6cde1a`
(memo at R5), both spent with empty `proofBytes`. Output vault'
`21e98eee1c6b279b6def05ee92dcb618141c6466369b89976a290d494ed326ae`
holds NFT + **101,000 tUSE** (1,000 + 100,000 — `topUpOk` sum-accounting
exact). The identical shape against the OLD tree was rejected by this same
node with `InvalidType: Cannot getReg[Long](5)`; against the fixed tree it was
accepted at mempool script verification and confirmed at height 443688.

The v1 vectors in `test-vectors/testnet/peg/` are unchanged and remain the
repro of the bug (as-compiled behavior of the pre-fix tree).
