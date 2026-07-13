# Aegis peg-in v3 — M1 testnet re-provision, aegis-contracts as deploy oracle

Captured 2026-07-13 from the Scala testnet node (`127.0.0.1:9062`, appVersion
6.0.3, network `testnet`). Zero real value. This ceremony re-provisions the
testnet peg from scratch — a LARGE fresh tUSE supply (100M) plus fresh
contracts — and, unlike peg/peg-v2, the expected trees/hashes/addresses were
computed BEFORE deployment from the `aegis-contracts` crate
(`deposit_receipt` / `peg_vault` under the v3 `ScriptConstants`). The deployed
artifacts then had to reproduce them bit-exact.

## Parity result (crate-computed vs deployed): ALL MATCH

| Check | Result |
|---|---|
| `/script/addressToTree`(crate receipt P2S) == crate receipt tree (pre-deploy) | MATCH |
| `/script/addressToTree`(crate vault P2S) == crate vault tree (pre-deploy) | MATCH |
| deployed vault box ergoTree (443909, and vault' 443911 from `/utxo/byId`) == crate `peg_vault` tree | MATCH |
| deployed receipt box ergoTree (443910) == crate `deposit_receipt` tree | MATCH |
| blake2b256(deployed vault tree) == crate `script_hash` `c750024e…` | MATCH |
| blake2b256(deployed receipt tree) == crate `script_hash` `446d147f…` | MATCH |

This proves the M0 tooling (`contracts/` crate: authoritative `es/` sources +
textual injection + pinned `ergo-compiler`, tree v3) reproduces a NEW
deployment, not just the historical peg-v2 bytes. The receipt-at-`INPUTS(1)`
consolidation (the eager-ValDef fix shape) succeeded again.

## Identifiers

| What | Value |
|---|---|
| **tUSE v3 token id (fresh)** | `01f4e85f5214bd29aae27dc9e0bfed2a934d5783fbee04224a30c8379583da28` |
| tUSE v3 supply / decimals / name | 100,000,000,000 base units (= 100,000,000 tUSE) / 3 / "tUSE" |
| **PegVault v3 singleton NFT id (fresh)** | `01f7c2fb58c0053a57f9051f1a40514bd0ff38a2de1243266ac5d7273f3ef16c` |
| PegVault v3 tree | `peg_vault_tree.hex` (796 B) |
| blake2b256(vault tree) | `c750024ed155e6b5695b63eef6f1560aac05f1b6c3eba4d3505de03203f3ee2b` |
| PegVault v3 P2S (testnet) | `3njX1QAFmEMJZ9q1L8KX1EFrNfSXJKo7BHo5KXH63t3kKxt5qS1pU7YkGEAZQD3nS7aRty54PNtdUyWjdbxwZXvQmFKBesBj6fPNFRLr3n48ExsVPvfzHfBppQ5ojcVyu1Yb5RLSV2QjDga7yMpYaof2MHdUmALw4caMb48XJYuV9p7fmjv2ZwViR7T2MiaSkzo9gRXftGqeREaFQRvNffzyWZGArZUKhaUEVwzZ6XLifpgrarDbAaaGWsRgyHDDyJ28ZRaq2MnsCjrUoBFjDqWzCRRim62ag2KmzuGWR5GwKtUxNk6BPLXawtukwKvqxV4k1huThKJGvxJKakbR1sKJQnxmi2RJfH8SziifBYR1nvJTVs9WxsrrjVLzcL7XUrQePfVnQ6b3ojjQMqus5RKhJ7UksvEFvRms4FDVhXz2kBtWYKrpNzjuVVszTqZszcdhe36JijkWb195mjsJEB2vg2gBxsBuFSuX188v2USPASwcrnZb7cxP6LMbHqsVBbSRUAuphcNviveuuMhwiJHPAZT4maNbbCTyQGnaZJLVg2Xh4uWdsibNDCYwUfRKDwDwvAD6tkfHWYeoDHb4cooY2Po1focqvkxRfRqfzsUN2k85RTU47VyBw5KgfXPN7geKsjWzNfga1ixk8FTrq2J256S6DLf5vVGvQaUxfQLtREu8q22ZP3k6h5LjTYKVnwpBFUtX2W69c33HH88S5MWNytBKnmPAjvLnTdytzxv7aFdF8bZgDQVsviAW5wHw31w3hGZ2ZynLtRg6cSLNWrm3PcZkTS6YQAeAuC6Dd8z2K5TQbtQYRBPcTCvfq1ewm5pJQWRVa6C5ZgcuJMUjc1QN63FhbRmznSHC4mtDUeF3tPWE7zt9EwyyDbgVwdyqSHvNBTHh2rCQNdqveWhUnGExjPk7AjTLfx1LfVqvGzRA5BnZGk88HurGfrCXtxdwigN5E2BNyfNuoqJNRp282XzPibfoNsG9BFcHM9eudvHHGLV9SJe3x1FVp4cQY1cCfxyvEVkmoNsTwbLVNg9X9R2kfnZKHma682no35MuDJAGFdBvV28CryDG4Q8bZgHvrRvCeF` |
| DepositReceipt v3 tree (embeds v3 tUSE + vault NFT) | `deposit_receipt_tree.hex` (200 B) |
| blake2b256(receipt tree) = `RECEIPT_SCRIPT_HASH` | `446d147f29faeae4251dd9fff5505842c30c095c4a1ea178681ff4399f88676e` |
| DepositReceipt v3 P2S (testnet) | `4ftaxv5T31S2QZmCaoW65yLAfDXHFzhxnj3ML7y2p5biixwTExttE1sSActbuG9XFyJFvNGQmwJdUryxZ2eNzwHH281dDPuweco3pTgkL7U2giVUbuNjXMBnBARDwdEkkva2VjXvuPwasPzpSohcmkYnR5YKXufS26n4EdmrAechTK37vhV195EZQZMcZwko5v5JtKcJTYCHpPahH4xCHfqw1PwdaQJhAPCRSHTp85iHv9uCbb1mhuTsVsTokQgyiBbr9dskntNedPYYKXv8gSCJ` |
| Depositor key (R7) | wallet P2PK `3WywEV3keFs3zpXTHx9wbAxjQcWdBU9yCWud4CmEuqsDPXpwgj7M` (`03b648cf…07fd`) |
| sc_dest (R4) | secp256k1 G compressed `0279be66…f81798` (33 B) |
| R5 memo (`Coll[Byte]`) | `"aegis-testnet-lock-v3-m1-reprovision"` |
| R6 / R8 | Int 3 (version) / Int 444200 (refund height) |

## Deploy constants (`aegis_contracts::ScriptConstants`, tree v3, Testnet)

Mirrors the peg-v2 ceremony: real ids, DERIVED receipt hash, dummy pins for
the not-yet-deployed payout siblings (top-up-only vault):

```text
use_token_id              = 01f4e85f5214bd29aae27dc9e0bfed2a934d5783fbee04224a30c8379583da28
peg_vault_nft             = 01f7c2fb58c0053a57f9051f1a40514bd0ff38a2de1243266ac5d7273f3ef16c
receipt_script_hash       = 446d147f…676e  (derived: deposit_receipt(consts).script_hash)
double_redeem_nft         = blake2b256("aegis-testnet-dummy-doubleredeem-nft")
unlock_intent_script_hash = blake2b256("aegis-testnet-dummy-unlockintent")
fee_pot_script_hash       = blake2b256("aegis-testnet-dummy-feepot")
```

Exact injected sources: `*.injected.es` (recompile to the same bytes —
cross-checked at ceremony time). Compiler: repo `ergo-compiler`,
`compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet)`.

## Transactions (ceremony order, all confirmed)

| # | txid | file | inclusion height |
|---|---|---|---|
| 1 mint tUSE v3 (100M, dec 3) | `ebff9434a1380648ec922ae5fe8a40c8ce82783a02c1c3a15fc67fb5ab5001de` | `mint_tuse_tx.json` | 443905 |
| 2 mint v3 vault NFT | `ce3a795603e301aaa6b2c22da6c835f94ea96fb0e35e7af3777ed515771b8370` | `mint_vault_nft_tx.json` | 443906 |
| 3 vault deploy (NFT + 1,000 tUSE base units) | `a8fbeb21986d1be7195fbf1cafe45bfe9d340f8db61c5a4dfa441827abd92a95` | `vault_deploy_tx.json` | 443909 |
| 4 LOCK (999,000 base units, R5 = Coll[Byte] memo) | `32bdefe80abc680896e8bee727f3b4e4b9e318db6b51afd07b5521e8797b5674` | `lock_tx.json` | 443910 |
| 5 CONSOLIDATION, receipt at INPUTS(1) | `d71ff5e8752a9926f095a9c5f1ca2df4a53b534bab27ee056d2bc0a74658ad1e` | `consolidation_tx.json` (+ `consolidation_tx_as_broadcast.json`) | 443911 |

Tx 5: `INPUTS(0)` = vault
`5c59def7ed6d4d9db840557b90025b7370358f1abc23cbc02b5572010afcf93b`,
`INPUTS(1)` = receipt
`9d4910797dd34f30750b96bac8cd974b565468d09730a4381e27c3b2fd029421`
(memo at R5), both spent with empty `proofBytes`. Output vault'
`000fdd5ecb69d278412fb327c50c802a91472ca98cc33ccecf7770dca3b00795` holds
NFT + **1,000,000 tUSE base units** (1,000 + 999,000) — `topUpOk`
sum-accounting exact AND `underCap` at the exact `V_CAP = 1000000L` boundary
(`vaultOutUSE <= V_CAP` proven inclusive on-chain).

NB the lock was sized to 999,000 base units (999 tUSE) deliberately:
`PegVault.es` pins `V_CAP = 1000000L` BASE UNITS, so this is the largest lock
whose consolidation the deployed vault can accept. The remaining v3 supply
(99,999,000,000 base units) stays in the wallet for future ceremonies.
