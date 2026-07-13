# SC node, consensus & P2P (v1 sketch)

**Date:** 2026-07-11  
**Status:** design freeze (shape); codecs TBD in `aegis-spec`  
**Binaries:** `aegis-node`, `aegis-mm` (sidecar)

---

## 1. What “fully working sidechain” means (v1)

A dogfoodable network where:

1. Nodes sync a **linear chain** (~15s blocks) via P2P.  
2. Miners (via MM sidecar) produce blocks and earn USE from pot/tips.  
3. Wallets send **ShieldedTransfer** and sync balances.  
4. PegMint / PegBurn talk to Ergo peg contracts.  
5. Stock Scala Ergo is **not** an SC peer — only peg + `SideChainState`.

---

## 2. Components

```text
┌─────────────────┐     P2P      ┌─────────────────┐
│ aegis-node      │◄────────────►│ aegis-node      │
│ (full)          │              │                 │
└────────┬────────┘              └────────┬────────┘
         │ RPC/wallet                      │
         ▼                                 │
┌─────────────────┐                        │
│ wallet (lib/CLI)│                        │
└─────────────────┘                        │
         ▲                                 │
         │ templates                       │
┌────────┴────────┐    Ergo /mining/*     ┌┴────────────────┐
│ aegis-mm        │◄─────────────────────►│ Scala (or Rust) │
│ sidecar         │                        │ Ergo node       │
└─────────────────┘                        └─────────────────┘
```

| Process | Role |
|---|---|
| `aegis-node` | Consensus, mempool, tree, nullifiers, RPC |
| `aegis-mm` | Bind Ergo Autolykos work ↔ SC block template |
| Wallet | Keys, prove, sync (library + CLI first; GUI later) |
| Ergo node | Mainnet only; peg boxes; mining API |

---

## 3. Consensus (v1)

| Item | Choice |
|---|---|
| Structure | Single linear chain (no complex sharding) |
| Block time | ~**15s** target (`params.md`) |
| PoW | **Merge-mined** with Ergo Autolykos via sidecar (ErgoHack-style) |
| Finality for peg | SC confs `M` + Ergo anchor depth `N` |
| Fork choice | Heaviest / most-work MM chain (exact rule in chain-spec) |

SC does **not** wait for Ergo between user payments — only peg edges care about anchors.

---

## 4. Validation pipeline (per block)

1. Header linkage / MM proof as specified.  
2. Merkle txs.  
3. For each tx: type-specific checks + **native** proof verify (Curve Trees + BP).  
4. Nullifiers unique vs set.  
5. Update commitment tree; commit new roots in header.  
6. Apply system box transitions (pot → miner reward).  
7. Economic invariant checks that are consensus-expressible (no silent inflation of notes without mint).

---

## 5. P2P (v1 minimal)

- Devnet peer list / seed config in node toml.  
- Gossip: headers, blocks, txs (inventory + getdata pattern — reuse ergo-p2p ideas where possible).  
- No requirement to speak Ergo P2P wire for SC objects.

---

## 6. RPC (wallet-facing, sketch)

| Method family | Purpose |
|---|---|
| `get_balance` / note list | After sync with IVK or full wallet |
| `get_new_address` | Diversified `aegis…` |
| `transfer` | Build+prove ShieldedTransfer (or return unsigned proof inputs) |
| `peg_mint_status` / watch receipt | Optional helper |
| `broadcast` | Submit tx |
| `sync_info` / compact blocks | Light path later |

Exact JSON schema in impl; not frozen here.

---

## 7. Genesis

- Empty commitment tree.  
- Empty nullifier set.  
- System: fee pot = 0; peg mint authority / verifier keys as constants.  
- Chain id / network magic = `aegis-dev` (test/main: `aegis-test` / `aegis`).  
- No premine of user USE (all value from peg-ins).

---

## 8. Operator checklist (dogfood)

1. Run Ergo node (Scala OK) with mining API.  
2. Run `aegis-node`.  
3. Run `aegis-mm` pointing at both.  
4. Autolykos miner → sidecar.  
5. Wallet against SC RPC; Ergo wallet for USE peg.

---

## 9. Explicitly deferred

- Lightwalletd-class hosted sync  
- Mobile proving  
- Multiple SC assets  
- Drivechain-grade theft resistance vs Ergo majority  
- Scala-native SC client
