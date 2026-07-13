# Aegis peg-in — first real testnet deployment vectors

Captured 2026-07-13 from the Scala testnet node (`127.0.0.1:9062`, appVersion
6.0.3, network `testnet`, genesis `5b1827ca…`). All transactions below are
confirmed on the public Ergo testnet; zero real value. These are the real
lock/consolidation vectors for the steps-5–9 peg verifier.

## Identifiers

| What | Value |
|---|---|
| tUSE token id (stand-in USE) | `006a33af9b295c830b1fe19422ede003da35a1c3a5f6ac56618e99ef2eaa2bab` |
| tUSE supply / decimals | 1,000,000 base units / 3 ("tUSE-aegis-test") |
| PegVault singleton NFT id | `006ad21fd48bc6676dab0e7b32df80b0d29119912bf9e9022f60eed844067307` |
| DepositReceipt P2S (testnet) | `4ftaxv5T31S2QUUiV15qA13B71LskmFXhghGJxD26A4qU1marXrvMTdBr5Hz8SvPUB5snokg2d5GRKvZJCNWtt5reMJKoKELrH6GPnvdiTRCU7ytSh3yH21PjAMGPmcG2rhcyaudHrvZHCB7ddVY9kJuDDU9X8g1M5QiBgv3zy8ZFkcPuMCXDegZM1pgzmyFR6EtSXDn6pYHbJ5v6CdNnkCxmTkZXbXMyJSvN5AvGcYenHqLLBbh7gT3v7TcN5LcosVmbP1X7a3NSEmig4yfN8MQ` |
| DepositReceipt tree | `deposit_receipt_tree.hex` (200 B) |
| blake2b256(receipt tree) = RECEIPT_SCRIPT_HASH | `312466e0ed5660f4e36b182b6e754dd6db3f68edc000baf8a7512eab5a17f804` |
| PegVault P2S (testnet) | see `peg_vault_tree.hex` (802 B tree; address = base58(0x13‖tree‖cs4)) |
| Depositor key (R7) | wallet P2PK `3WywEV3keFs3zpXTHx9wbAxjQcWdBU9yCWud4CmEuqsDPXpwgj7M` (`03b648cf…07fd`) |
| sc_dest (R4, both locks) | secp256k1 G compressed `0279be66…f81798` (33 B) |

PegVault dummy injections (top-up-only vault; payout path unusable by design
here): `DOUBLE_REDEEM_NFT = blake2b256("aegis-testnet-dummy-doubleredeem-nft")`,
`UNLOCK_INTENT_SCRIPT_HASH = blake2b256("aegis-testnet-dummy-unlockintent")`,
`FEE_POT_SCRIPT_HASH = blake2b256("aegis-testnet-dummy-feepot")`. Exact
injected sources: `*.injected.es`. Compiler: repo `ergo-compiler`,
`compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet)`; node
`/script/addressToTree` round-trips both addresses to these exact tree bytes.

## Transactions (in ceremony order, all confirmed)

| # | txid | file | inclusion height |
|---|---|---|---|
| 1 mint tUSE | `036514b1dc7196ebb1ef420b3381ed2b155d572b9bee82ef15a1062064df3544` | `mint_tuse_tx.json` | 443392 |
| 2 mint vault NFT | `3df04ae00ede293c44daf741f1969707a51a5f4ddc61cc9a68e083a9aa9294cc` | `mint_vault_nft_tx.json` | 443392 |
| 3 LOCK #1 (100.000 tUSE) | `bc7245647bee2f242b118dae0094f594692afb7d7333967bf8d62884a07790eb` | `lock1_tx.json` | 443396 |
| 4 vault deploy (NFT + 1.000 tUSE) | `9657e510fa8a4ce44c63434d2824a3093520fab568871bce306e33ef975d51b9` | `vault_deploy_tx.json` | 443398 |
| 5 LOCK #2 (100.000 tUSE, R5=Long) | `527f29307372c64ea418a5eed87db4135ea906a012586f9fac100482c9555da8` | `lock2_tx.json` | 443404 |
| 6 CONSOLIDATION (both receipts → vault) | `81015c1be5e50f3a4ac34f733b9bf70ba84488ca04a7c5e2f4b068e7fe8eaa93` | `consolidation_tx.json` (+ `consolidation_tx_as_broadcast.json`) | 443406 |

Key boxes: receipt1 `b7fde121261d67cf8522013f2c8e131a5e41ae902132d52273331f9c73756d13`
(R8 refund height 443534), receipt2 `798959c00442fc6338fa661489298f383da4dadd556cb5501869d600c2a2200a`
(R8 443543), vault `139bda398e74c2f34c6542d2a38a24969afe1a20f08ba4a0b4c326054995c7de`,
vault' `c0580ca1439f4a4a45aab85e53edbacc10a8bfdbfab65f2f3bc7bf4b5743181e`
(NFT + 201,000 tUSE = 1,000 + 2×100,000; `topUpOk` sum-accounting exercised
with TWO receipts in one tx). Script inputs spend with empty `proofBytes`.

## ⚠ Finding: eager `intent.R5[Long].get` constrains INPUTS(1) on EVERY vault spend

First consolidation attempt (vault + receipt1 only) was REJECTED by the node:

    Scripts of all transaction inputs should pass verification. …: #0 =>
    Failure(sigma.exceptions.InvalidType: Cannot getReg[Long](5): invalid type
    of value TestValue(Coll(97,101,103,105,115,…)) at id=5)

Cause: in `PegVault.es`, `val payoutOk = { … val n = intent.R5[Long].get … }`
is used twice, so the compiler hoists `INPUTS(1).R5[Long].get` (and
`INPUTS(1)` itself) into eager top-level ValDefs — evaluated on BOTH paths.
Consequence: the vault is spendable only when `INPUTS(1)` exists and carries
`R5: Long`. A DepositReceipt with a `Coll[Byte]` memo in R5 (receipt1 here)
can never sit at INPUTS(1); a top-up needs an R5:Long box there (receipt2) with
other receipts at index ≥ 2. Contract-side fix candidates: gate the register
reads inside the `if (isPayout)` branch via `noExtension`-style laziness, or
read `R5[Long]` with `.getOrElse`-shaped guards. Not fixed here — vectors
capture the as-compiled behavior.
