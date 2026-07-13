{
  // Aegis PegVault — singleton pooled USE reserve; the only box that pays
  // peg-out claimants. Two spend paths: PAYOUT (peg-out) and TOP-UP
  // (consolidator merges receipts / fee-pot into the vault). Authored fresh
  // (Dexy/AgeUSD bank-NFT pattern; never race a per-user box).
  //
  // tokens[0] = (vault NFT, 1)         singleton identity
  // tokens[1] = (USE id, vaultUSE)     the reserve
  //
  // Boxes by convention:
  //   INPUTS(0)  = SELF (vault)         OUTPUTS(0) = vault'
  //   PAYOUT:  INPUTS(1) = UnlockIntent (consumed),
  //            OUTPUTS(1) = DoubleRedeem' (burn id inserted),
  //            OUTPUTS(2) = claimant payout.
  //
  // ── SECURITY (pass 2) ────────────────────────────────────────────────
  // FIXES the pass-1 CRITICAL receipt-USE siphon. Root cause: the vault
  // never accounted for DepositReceipt / FeePot USE consumed in the same tx,
  // so any tx spending a receipt could route its USE to an attacker output
  // (token conservation) while the vault's own checks passed. Per-receipt
  // checks CANNOT compose (a receipt only sees "OUTPUTS(0) is the vault", not
  // by how much the vault grew), so the VAULT does the accounting:
  //   * TOP-UP: `vaultOut == vaultIn + Σ(receipt USE) + Σ(feePot USE)` — the
  //     vault must absorb EXACTLY every consumed receipt/fee (diverting any →
  //     vaultOut too low → fail). Closes the siphon in consolidation txs.
  //   * PAYOUT: `receiptSum == 0 && feeSum == 0` — a payout may not smuggle
  //     receipts/fee to siphon them. Closes it in payout txs.
  // Also (defense-in-depth from review): the fee is now PINNED (no zero-fee
  // leak), `vaultOut.tokens.size == 2` (no extra-token siphon), and T_delay
  // starts from the intent box's own creation height (unspoofable, not a
  // prover register).
  //
  // ⚠⚠ C1 — BURN AUTHENTICITY IS NOT PROVEN ON-CHAIN IN v1. The UnlockIntent
  // asserts a burn happened under the miner-posted SideChainState tip; this
  // contract enforces the CEREMONY (matching intent, T_delay, DoubleRedeem,
  // capped/fee-pinned payout from the singleton), NOT that the burn is real.
  // Under U1-dogfood that is bounded only by V_cap + T_delay. Do NOT deploy
  // value beyond V_cap on this form; trust-minimization needs U1-strong
  // (k-of-n attesters) or SPV-in-consensus. See DESIGN.md §C1.
  //
  // ⚠ deploy-time injections: USE_TOKEN_ID, VAULT_NFT, DOUBLE_REDEEM_NFT,
  //   UNLOCK_INTENT_SCRIPT_HASH, RECEIPT_SCRIPT_HASH, FEE_POT_SCRIPT_HASH.
  // ⚠ FEE_FLOOR/FEE_BPS are the mainnet peg-fee params (params.md); a
  //   different network re-inlines them. `n ≤ V_cap` bounds `n·bps` (no
  //   overflow at v1 scale); revisit for large V_cap.

  val USE_TOKEN_ID = fromBase64("AGozr5spXIMLH+GUIu3gA9o1ocOl9qxWYY6Z7y6qK6s=")               // todo a55b…2669
  val VAULT_NFT = fromBase64("AGrSH9SLxmdtqw57Mt+AsNKRGZEr+ekCL2Du2EQGcwc=")                  // todo vault singleton NFT
  val DOUBLE_REDEEM_NFT = fromBase64("R9TsS/+OxnQJvAjCCwv9AyGU9vxFL4UpjX7vtEjGvBQ=")          // todo DoubleRedeem NFT
  val UNLOCK_INTENT_SCRIPT_HASH = fromBase64("ZYBSnfw2wDLTs8caB5PWXRFnSanKSarWBbOxru10mwM=")  // todo blake2b256(UnlockIntent propBytes)
  val RECEIPT_SCRIPT_HASH = fromBase64("MSRm4O1WYPTjaxgrbnVN1ts/aO3AALr4p1Euq1oX+AQ=")        // todo blake2b256(DepositReceipt propBytes)
  val FEE_POT_SCRIPT_HASH = fromBase64("oJBY7J999sTnnI3AdkD/Lj7Hh0V3u0HOCwsj0O2KMU0=")        // todo blake2b256(FeePot propBytes)

  val V_CAP = 1000000L        // 1000 USE (base units)
  val T_DELAY = 720           // Ergo blocks
  val FEE_FLOOR = 1000L       // 1 USE (mainnet peg_fee_floor)
  val FEE_BPS = 100L          // 1% (mainnet peg_fee_rate_bps)

  val vaultOut = OUTPUTS(0)

  // --- invariants common to both paths ---
  val nftPreserved =
    SELF.tokens.size >= 2 &&
    SELF.tokens(0)._1 == VAULT_NFT &&
    SELF.tokens(0)._2 == 1L &&
    SELF.tokens(1)._1 == USE_TOKEN_ID &&
    vaultOut.tokens.size == 2 &&              // exactly NFT + USE (no extra-token siphon)
    vaultOut.tokens(0)._1 == VAULT_NFT &&
    vaultOut.tokens(0)._2 == 1L &&
    vaultOut.tokens(1)._1 == USE_TOKEN_ID &&
    vaultOut.propositionBytes == SELF.propositionBytes &&
    vaultOut.value == SELF.value

  val vaultInUSE = SELF.tokens(1)._2
  val vaultOutUSE = vaultOut.tokens(1)._2
  val underCap = vaultOutUSE <= V_CAP

  // Σ USE of consumed DepositReceipt / FeePot inputs — the vault MUST absorb
  // exactly this (fixes the siphon). Guard tokens.size so a receipt-scripted
  // but token-empty grief box contributes 0 rather than throwing.
  val receiptSum = INPUTS.fold(0L, { (acc: Long, b: Box) =>
    if (blake2b256(b.propositionBytes) == RECEIPT_SCRIPT_HASH && b.tokens.size > 0)
      acc + b.tokens(0)._2
    else acc
  })
  val feeSum = INPUTS.fold(0L, { (acc: Long, b: Box) =>
    if (blake2b256(b.propositionBytes) == FEE_POT_SCRIPT_HASH && b.tokens.size > 0)
      acc + b.tokens(0)._2
    else acc
  })

  // --- PAYOUT path: an UnlockIntent is being consumed as INPUTS(1) ---
  val isPayout =
    INPUTS.size > 1 &&
    blake2b256(INPUTS(1).propositionBytes) == UNLOCK_INTENT_SCRIPT_HASH

  val payoutOk = {
    val intent = INPUTS(1)
    val burnId = intent.R4[Coll[Byte]].get      // Aegis burn id
    val n = intent.R5[Long].get                 // burned amount N (USE base units)
    val claimant = intent.R6[Coll[Byte]].get    // claimant script bytes

    // T_delay is measured from the intent BOX's creation height — unspoofable
    // (a prover-set register could be backdated to shortcut the delay).
    val startHeight = intent.creationInfo._1
    val delayElapsed = HEIGHT >= startHeight + T_DELAY

    // A payout must not smuggle receipts/fee in to siphon them.
    val noConsolidation = receiptSum == 0L && feeSum == 0L

    // Pin the fee exactly (closes the zero-fee revenue leak): the claimant
    // receives N − fee, fee = max(floor, bps·N/10000) and stays in the vault.
    val bpsFee = n * FEE_BPS / 10000L
    val fee = if (bpsFee > FEE_FLOOR) bpsFee else FEE_FLOOR
    val expectedPaid = n - fee

    val paidOut = vaultInUSE - vaultOutUSE       // USE leaving the vault
    val feePinned = paidOut == expectedPaid && paidOut > 0L

    val claimantBox = OUTPUTS(2)
    val claimantGets =
      claimantBox.propositionBytes == claimant &&
      claimantBox.tokens.size > 0 &&
      claimantBox.tokens(0)._1 == USE_TOKEN_ID &&
      claimantBox.tokens(0)._2 == paidOut

    // DoubleRedeem must record THIS burn id in the same tx (its own contract
    // enforces insert-once; we bind the id so a payout can't cite a stale one).
    val drOut = OUTPUTS(1)
    val doubleRedeemBinds =
      drOut.tokens.size > 0 &&
      drOut.tokens(0)._1 == DOUBLE_REDEEM_NFT &&
      drOut.R5[Coll[Byte]].get == burnId

    delayElapsed && noConsolidation && feePinned && claimantGets && doubleRedeemBinds
  }

  // --- TOP-UP path (consolidator): vault absorbs EXACTLY the consumed
  // receipts + fee-pot USE, nothing diverted, no intent consumed. ---
  val topUpOk =
    !isPayout &&
    (receiptSum + feeSum) > 0L &&
    vaultOutUSE == vaultInUSE + receiptSum + feeSum

  sigmaProp(nftPreserved && underCap && (if (isPayout) payoutOk else topUpOk))
}
