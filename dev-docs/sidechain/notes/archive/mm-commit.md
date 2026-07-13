# MM commit encoding (spike)

**Goal:** Solo / pool MM without a Scala consensus PR.

## Stock Ergo surfaces

- `GET /mining/candidate` → Autolykos work message (header material, `msg`, etc.)
- `POST /mining/solution` → submit Ergo block
- SC node exposes analogous candidate/solution (aegis-node)

## Sidecar responsibilities

1. Poll Ergo candidate + SC candidate.
2. Bind SC tip commitment into miner-visible bytes **without** requiring every Ergo full node to understand SC:
   - **v1 preferred:** commitment carried in sidecar-local work packaging; Ergo block itself unchanged; SC progress posted later as **`SideChainState` tx** when this miner wins Ergo (ErgoHack model).
   - **v1 optional stronger:** put SC header hash in Ergo **extension** key-value if miner template API allows extension injection without fork — verify against Scala `/mining/candidate` fields before relying on it.
3. On SC PoW success → submit SC block.
4. On Ergo PoW success → submit Ergo block + build `SideChainState` spend with current SC digests.

## Security note

Until extension commitment is verified end-to-end, SC tip integrity ≈ MM hashrate; Ergo only finalizes **whatever digest the winning miner posts** in the state box. Aligns with design § security bar (not drivechain).

## Open for Task 6

- Exact byte layout of “combined work” for GPU/stratum proxies.
- Whether Autolykos `msg` can commit to SC hash without breaking Ergo validity (must remain consensus-valid Ergo header).

**Provisional rule:** Ergo header stays valid under stock rules; SC commit is **application-layer** via state box (+ optional extension if proven safe).
