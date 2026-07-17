# Hash-native private-payment engine — architecture design

**Status:** design, no code (branch `feat/hash-native-payment-engine`). This is
the crown-jewel rebuild: replace Aegis's Curve-Trees/Bulletproofs shielded pool
with a **hash-native, recursion-friendly, no-trusted-setup** one, so a trustless
bridge becomes reachable. It's a from-scratch privacy core, not a bolt-on —
treated as a multi-phase effort gated on an early make-or-break measurement.

## Why (the one-paragraph justification)
`trustless-settlement-design-pass.md` established the wall: any bridge Ergo checks
via `verifyStark` (RISC0) pays ≥ one foreign-curve MSM (~14B cycles / hours) as
long as the client proof is over secp/secq — accumulation reduces N→1 but 1 is
still hours. The ONLY way under the floor is a client proof whose verifier is
RISC0-native (hash/FRI). So the prover architecture must change; this doc pins to
what.

## Proof-system choice — FRI/STARK-native (BabyBear), NOT KZG
- **Pick: a STARK over BabyBear** (the RISC0 verifier's field) — via **Plonky3**
  (mature, FRI, Polygon) as the primary candidate, or a hand-written AIR as the
  efficiency fallback.
- **Why FRI, not KZG/Halo2:** KZG needs a trusted setup — the exact thing Curve
  Trees was chosen to avoid; a shielded-money chain should not reintroduce it. FRI
  is transparent (hash-only).
- **Why BabyBear-aligned:** settlement verifies the batch's client proofs. If they
  share RISC0's field, the settlement RISC0 guest verifies them **cheaply and
  hash-natively** — no foreign-curve MSM anywhere. The whole stack collapses to one
  field.
- **Consequence to accept:** STARK proofs are larger (~tens–hundreds of KB vs
  Curve Trees' ~4 KB) and client proving is heavier (target ~seconds; measure).

## The engine (what each piece becomes)
| Piece | Today (Curve Trees) | Rebuilt (hash-native) |
|---|---|---|
| Note commitment | Pedersen (EC point) | `Poseidon(value, owner, rho, r)` |
| Owner key / address | `pk = nk·B` (EC) | `pk = Poseidon(nk)` (hash — NO elliptic curve) |
| cm accumulator | Curve Tree (EC, depth 4) | **Poseidon-Merkle tree** (membership = a Merkle path) |
| Nullifier | `Poseidon(nk, rho)` | **unchanged** — already hash-native ✓ |
| Spend proof | Bulletproofs R1CS over the 2-cycle | **STARK/AIR**: membership + openings + nullifier + range + balance |
| Note encryption | ECDH (secp) + ChaCha20-Poly1305 | hash/KEM-based DH replacement (design item) |

Going fully hash-native (hash-based keys, no `nk·B`) is deliberate: it removes
**all** elliptic-curve arithmetic from the client proof, which is what makes the
STARK cheap. The payment address model (option-a `pk = nk·B`) and the ECDH note
encryption are re-derived on hashes.

## The spend circuit (2-in / 2-out), all STARK-cheap
For each input: Merkle-path membership of its `cm` in the tree at `prev_root`;
`cm == Poseidon(value, owner, rho, r)` (opening); `nullifier == Poseidon(nk, rho)`
revealed + non-member of the nullifier accumulator; `owner == Poseidon(nk)`
(ownership). Plus: value conservation `Σin == Σout + fee`; 64-bit range on outputs
(bit-decomposition / lookups — cheap in FRI); output `cm`s well-formed. Every gate
is Poseidon/Merkle/arithmetic — native to the field.

## Settlement (why the rebuild unlocks trustless)
Client emits a per-transfer STARK (BabyBear). The settling node runs a **RISC0
guest** that verifies the batch's STARKs (cheap — same field) and accounts the
state transition `prev_root → new_root` + the withdrawal, emitting the peg-out
STARK that Ergo's `verifyStark` checks. No foreign-curve verification anywhere →
under the floor. (Statement-1/2 of `stark-settlement-design.md` become tractable.)

## What carries over vs rebuilds (honest)
- **Rebuilds (crown jewel):** note commitment, keys/address, cm accumulator, spend
  proof, note encryption, the mint/coinbase/pegmint leaf derivations. The reviewed
  N1 nullifier *scheme* (Poseidon(nk,rho)) carries; its *soundness in the new
  circuit* must be re-argued + re-reviewed.
- **Survives (mostly):** the node (consensus, mempool, fork-choice, merge-mining,
  peg-in wiring, attester bridge), the wallet scaffolding, the wire/block formats
  (with new proof/commitment sizes), the explorer. They consume the crypto through
  interfaces; the interfaces change shape, the systems around them largely don't.

## THE make-or-break (de-risk first, before building anything)
**Can a phone-class client produce a hash-native shielded-spend STARK cheaply
enough (target ~seconds), and how big is the proof?** If STARK spend proving is
minutes or the proof is megabytes, the rebuild fails at the client and the answer
is a different system — so this is measured BEFORE the full build, exactly as the
RISC0 verifier-port was de-risked first.

## Phased plan
1. **This design** — pin the stack.
2. **Client-cost spike (make-or-break):** a minimal Poseidon-Merkle-membership +
   nullifier + balance spend proof in Plonky3/STARK; measure prove time, memory,
   proof size on commodity hardware. Kill-criteria: if client proving ≫ seconds or
   proof ≫ ~1 MB, reconsider the system.
3. **Full engine** — commitment/keys/tree/nullifier/spend circuit + wallet.
4. **Settlement** — RISC0 aggregator + `PegVault verifyStark` contract + wiring.
5. **Migration** — a FRESH testnet on the new engine (testnet chain-id-breaking is
   free); no in-place migration of the old Curve-Trees pool.

## Gates
This is a fresh crypto core → full external review before real value, same as the
current engine. Everything here is testnet/devnet until then. The rebuild does NOT
touch `main`'s working engine until it's a proven, reviewed replacement.
