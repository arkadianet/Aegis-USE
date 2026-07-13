# Aegis — G1.6 / consensus adversarial review (2026-07-12)

**Method:** three independent red-team agents (crypto soundness, privacy/deanon, consensus/economics), each grounding claims in the vendored reference (`~/coding/reference/crypto/curve-trees/`) and the specs. Cross-checked and deduped here; the main session verified the load-bearing factual claims (spend-model, leaf-index) directly against `coin.rs`. Two lenses **independently converged** on the nullifier-collision bug (C1/P F4) — highest-confidence finding.

**Verdict:** note-protocol.md and consensus.md §1 need revision before any G2 circuit code. No finding is fatal to the architecture; all are fixable in spec. The two that gate everything: the **spend-model fork** (which construction) and the **leaf-index anonymity** correction.

---

## Decisions required (not yet made)

> **RESOLVED 2026-07-12** (note-protocol.md §3, pending external crypto review of the exact algebraic form): adopt **neither reference verbatim** — keep `coin.rs`'s CT membership + range proofs; use an **Orchard-discipline nullifier** (split `nk` key; per-note `rho = consumed input nf` → structural uniqueness; cheap algebraic `nf`). This resolves D-A and dissolves **N1** (collision, now structurally impossible) and **N11** (secret-index caveat gone). D-B fixed in §4 wording. Below is the original finding, kept for the record.

**D-A. Spend model.** The reference offers TWO, and the draft conflated them:
- **PRF.md** — inverse-tag nullifier `nf = (sk+H(tx))⁻¹·G`, revealed in-circuit; fully hides the spender. A *sketch* with hand-flagged soundness caveats.
- **`coin.rs`** — reveals the rerandomized public key + Schnorr signature (`Pour.pk0/pk1` public; `Schnorr::verify`, and even that is `// todo`, line 571). No nullifier. This is the code that actually exists.

The draft's §3 uses PRF.md but §8 claims `coin.rs` as the byte-oracle — impossible. **Must pick one and re-ground.** PRF.md's model is more private but unaudited-sketch; coin.rs is real code but leaks the (rerandomized) key and isn't a nullifier system. This is the single biggest open question and likely needs the external crypto reviewer (security gate) to weigh in.

**D-B. Leaf-index anonymity.** §4 says "leaf index **public**" — for note membership this is catastrophic (select-and-rerandomize exists to *hide* which leaf; public index ⇒ the whole spend graph reconstructs by following leaf refs, anonymity set → 1). Fix: note membership leaf index **HIDDEN**. Caveat: PRF.md flags a soundness issue with a *secret* index on the second-level key-commitment select — so "hidden note leaf" vs "public key-select index" are two different sub-steps that must be specified separately.

---

## Findings — note protocol (crypto ⊕ privacy)

| # | Sev | Finding | Fix |
|---|---|---|---|
| N1 | **High** (2 lenses) | **Nullifier collision.** `nf` depends only on `(sk, H(tx))` — no per-output term. Two outputs of one tx to the same key (ordinary pay+change, or §6 pad-to-sender) → identical `nf` → second note permanently unspendable; weaponizable (pay a victim twice to one address, one note dead). | Bind `nf` to a per-output-unique preimage (output index / the note's own value-commitment), specified normatively; ensure the nonce doesn't re-correlate `nf` with leaf position |
| N2 | **Critical (wording)** | **§4 "leaf index public"** ⇒ full spend-graph reconstruction (D-B). | "leaf HIDDEN" for note membership; specify key-select index separately |
| N3 | **High** | **Generators unpinned.** All soundness (Pedersen binding = no inflation; `G_value ⊥ G_PRF` = range proof covers value; `G ⊥ H_odd` = nf determinism) rests on NUMS independence of the 5 generators. §9 defers hash-to-curve as a "UX footnote" — it's the load-bearing assumption for "no trusted setup." | Pin RO hash-to-curve, per-generator domain separation, nothing-up-my-sleeve seed; vector it; state inflation-resistance depends on it |
| N4 | **High** | **Fee not in the balance circuit.** `coin.rs` balance has no fee term. If Aegis admits `fee` as a committed variable, a negative fee mints. Also no stated `Σ block fees = pot delta` invariant at the shielded↔pot boundary. | Fee = public constant `= sc_tx_fee`, folded as a constant; add block-level `Σfee = pot delta` consensus check |
| N5 | **High** | **Dummy notes underspecified.** If a dummy input's value isn't circuit-constrained to 0 → inflate by V. If a dummy's `nf` isn't inserted → spend a real note in the dummy slot twice. And a canonical dummy has a **known constant nf** → observers count real-input arity, breaking uniform-shape (privacy). | Constrain dummy `value == 0`; insert/check ALL nullifiers; dummy `nf` fresh-per-tx and non-aliasing; prove circuit uniform across membership-present/absent |
| N6 | Med | **Coinbase notes don't mix.** Public coinbase value + (base 0.01 < fee 0.03) forces long all-coinbase consolidation chains whose amounts are all publicly known until first mixing with outside funds; on a quiet chain that's the whole miner subtree, value-labelled and tied to `reward_address`. | Accept as disclosed miner-privacy limit, or raise base ≥ fee so a single coinbase note is independently spendable; document |
| N7 | Med | **OVK optionality leaks.** Optional OVK-wrap ⇒ outputs-with-OVK byte-distinguishable ⇒ fingerprints sender/wallet. | Mandatory fixed-size OVK slot on every output incl. dummies (Sapling `out_ciphertext` discipline) |
| N8 | Med | **On-SC tx-type/value surfacing.** PegMint/PegBurn/Coinbase are publicly-typed on Aegis; PegBurn discloses a specific note's value N on-SC (not just at the Ergo edge). | Document honestly; consider whether burn value can be range-bucketed |
| N9 | Med | **Diversified-address contradiction.** aegis-spec §7 promises "new diversified address per receive"; note-protocol §2/§9 leaves derivation TBD. Without it, one IVK leak unlinks the receiver's entire history. | Specify diversified derivation before v1, or downgrade the §7 claim |
| N10 | Med | **Empty tree/slot filler.** §7 pins the root but not what fills unused leaves; an openable filler point = mint-from-padding. | Unopenable/zero point, documented + vectored |
| N11 | Med | **PRF secret-index caveat dropped.** PRF.md flags the key-commitment second-level rerandomize as a possible soundness issue; §4 doesn't address it (relates D-B). | Specify public-index for that select; prove it binds `nf` to the spent leaf |
| N12 | Low | **`sk+H(tx)=0`** non-invertible → unspendable note. Negligible, self-DoS only. | Reject at wallet mint; note in spec |

**Verified sound:** `nf` determinism / no double-nf-per-note (conditional on N3); attacker can't force a victim's `nf` (needs their `sk` or a 256-bit preimage); 64-bit range vs field = no overflow with 2 inputs; 0-value *output* padding is properly hidden (leak is input/nullifier-side); flat-fee amount-independence genuinely protects internal volume (pot deltas reveal count, never amount); DH-KEM key-privacy and memo padding showed no oracle.

---

## Findings — consensus / economics

| # | Sev | Finding | Fix |
|---|---|---|---|
| C1 | **High** | **Multi-commitment candidate reopens D3.** Witness rule only checks `solution` meets `sc_nbits` AND *a* tx output's `R4 == sc_header_id`. One candidate can carry many R4 outputs → one solution → N equivocating same-height Aegis blocks. §1's "commits to exactly one block" is false. | Require exactly one R4-bearing output per candidate, or bind the SC block to the whole `txRoot`/candidate |
| C2 | **High** | **Attacker-chosen candidate height → smallest Autolykos-v2 N.** Witness never pins candidate `height`/`prev` to the live Ergo tip; low height ⇒ least memory-hard variant ⇒ per-hash cost edge over honest MM mining the real tip. Directly erodes the `V_cap`↔hashrate coupling. | Constrain candidate height (and prev) to the current Ergo epoch in the witness rule |
| C3 | Med-High | **M=120 finality < 240 retention.** Maturity = ½·retention: a coinbase note / burn treated as final at M=120 is reorg-eligible to depth 240; node rollback is clean but off-chain acceptance (goods, USE) isn't. §5's poison-safety claim is imprecise. | State user-facing finality at retention depth, or set retention = maturity, or bound finality < maturity |
| C4 | Med | **Grindable tie-break.** Equal-length forks get identical LWMA difficulty ⇒ exact ties (common on per-block retarget); tie → lower header id, which includes miner-grindable `reward_claim`/`timestamp`. Selfish-mining edge on contested tips. | Tie-break on a non-grindable value (first-seen only, or PoW-derived) |
| C5 | Med | **`txs_included` undefined.** β=⅓ pot-safety holds only if every counted tx pays ≥0.03 to the pot. Coinbase/peg txs pay no SC fee; if they count, accounting drifts / a future <0.01-fee type reopens drain. (Self-dealing drain itself is correctly defended: fee 0.03 > bonus 0.01.) | Define `txs_included = fee-paying ShieldedTransfers only`; enforce |
| C6 | Med (liveness) | **Commitment-tx UTXO stall.** Sidecar re-spends one wallet input each 15s; winning an Ergo block consumes it → subsequent candidates invalid → Aegis production halts until re-chained to the change output. Bites exactly on a solo operator's Ergo win. | Spec change-output chaining / dedicated commitment-UTXO lineage |
| C7 | Low | **Bootstrap deep-chain window.** First 90 blocks at fixed `min_difficulty`; if mainnet sets it as low as dev, cheap alternate genesis-anchored chain. | Non-trivial mainnet `min_difficulty` and/or first-window checkpoint |
| C8 | Low | **Empty-block base not guaranteed.** `min(pot, …)` pays <0.01 when pot <0.01 — the anti-free-ride incentive vanishes exactly when the pot is depleted/early. | Accept (economic, not solvency), or seed a small pot floor |

**Verified sound / not new:** pot over-credit on PegMint+Ergo-reorg = existing C1/A2 mint-backing risk, not a new pot-term gap (note + credit unback together); SC reorg covered by versioned rollback of all four structures; self-dealing pot drain defended by fee > bonus; LWMA timestamp gaming damped by MTP-11 + 60s-future + [−6T,6T] clamp.

---

## Triage → action

**Spec revision complete 2026-07-12** — all findings addressed in the docs (below). No open design forks remain; the one item that still *gates TVL* is external crypto review of the §3 nullifier's exact algebraic form.

| Finding | Resolution | Where |
|---|---|---|
| D-A spend model | Orchard-discipline nullifier (neither reference verbatim) | note-protocol §3 |
| D-B/N2 leaf-index | Hidden (was wrongly "public") | note-protocol §4 |
| N1 nullifier collision | `rho = consumed input nf` → structural uniqueness | note-protocol §3, §6 |
| N3 generators | RFC 9380 hash-to-curve, NUMS seed, domain-sep, vectored | note-protocol §0 |
| N4 fee-in-circuit | Fee = circuit constant + block `Σfee = pot credit` check | note-protocol §4 |
| N5 dummy notes | `value==0` constrained, all nf inserted, fresh non-aliasing dummy nf | note-protocol §6 |
| N7 OVK | Mandatory fixed-size `out_ct` slot on every output | note-protocol §5 |
| N9 diversified addr | Sapling diversified addresses, v1 requirement | note-protocol §2 |
| N10 empty filler | Unopenable NUMS point for empty leaves | note-protocol §7 |
| N11 secret-index caveat | Dissolved by structural `rho` | note-protocol §3 |
| C1 single-commitment | Exactly one `R4` output per candidate | consensus §1 |
| C2 height pin | Candidate height ∈ [tip−k, tip+1] | consensus §1 |
| C3 finality depth | Acceptance finality = retention depth (240), not maturity | consensus §5 |
| C4 tie-break | First-seen only (not grindable header id) | consensus §5 |
| C5 `txs_included` | Fee-paying ShieldedTransfers only | aegis-spec §11 |
| C6 commitment-UTXO | Dedicated self-chaining commitment box | consensus §1 |
| C7 bootstrap difficulty | Non-trivial mainnet `min_difficulty` + optional checkpoint | consensus §3 |
| N6, N8, N12, C8 | Documented / accepted | note-protocol / aegis-spec |

**Still gates TVL (not v1-blocking):** external crypto reviewer owns the exact §3 nullifier form + generator/NUMS review; the pre-TVL crypto-glue review already in security.md covers it.
