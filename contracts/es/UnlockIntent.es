{
  // Aegis UnlockIntent — posted (by anyone) to claim a peg-out for an Aegis
  // burn. Binds (burn_id, N, claimant); PegVault measures T_delay from THIS
  // box's creation height (unspoofable) and pays `claimant` exactly N − fee.
  //
  // R4 = burn_id (Coll[Byte])   R5 = N (Long)   R6 = claimant script (Coll[Byte])
  //
  // ── SECURITY ─────────────────────────────────────────────────────────
  // Anti-grief: this intent is spendable ONLY in the vault-payout structure —
  // INPUTS(0) is the singleton PegVault and SELF is INPUTS(1). The vault then
  // binds the payout to SELF's burn_id / N / claimant and updates DoubleRedeem.
  // Consequence: even an *anyone*-triggered spend pays the box's own R6
  // claimant (someone paying out your burn to you is harmless), and the intent
  // cannot be consumed/burned outside a real payout (no griefing the claimant).
  // Double-posting two intents for one burn id is harmless — DoubleRedeem's
  // insert-once lets only ONE payout for a burn id succeed (I3).
  //
  // Burn authenticity (pass 3): the payout tx must carry the CURRENT
  // SideChainState singleton as dataInputs(0) and prove (AVL lookup, proof in
  // THIS input's context extension, getVar(0)) that its burn tree records
  // (burn_id → longToByteArray(N)) — i.e. the burn EXISTS in the miner-posted
  // burn set AND the amount matches. dataInputs must be unspent ⇒ only the
  // live tip box qualifies (no stale-tip replay). The tree is insert-only and
  // transition-constrained on the SideChainState side, so membership can only
  // GROW — a burn once posted stays provable at payout time (T_delay later),
  // and a recorded burn's N is immutable (re-insert of the key fails there).
  //
  // ⚠ C1: this upgrades "burn asserted from thin air" to "burn present in the
  //   TIP_PK-posted append-only burn set" — the burn set itself is still
  //   TRUSTED from the miner-tip key in v1 (bounded by V_cap + T_delay), NOT
  //   proven. See DESIGN §C1.
  // ⚠ Spam/bond control (a locked bond refunded on valid payout, slashed on a
  //   fraud-halt cancellation) is DEFERRED to a later pass; v1 relies on the
  //   fee + honest posting.
  // ⚠ inject VAULT_NFT, SIDECHAIN_STATE_NFT.

  val VAULT_NFT = fromBase64("")            // todo vault singleton NFT id
  val SIDECHAIN_STATE_NFT = fromBase64("")  // todo state singleton NFT id

  val wellFormed =
    SELF.R4[Coll[Byte]].isDefined &&
    SELF.R5[Long].isDefined &&
    SELF.R6[Coll[Byte]].isDefined

  // Must be spent as INPUTS(1) alongside the singleton PegVault at INPUTS(0).
  val payoutContext =
    INPUTS.size > 1 &&
    INPUTS(0).tokens.size > 0 &&
    INPUTS(0).tokens(0)._1 == VAULT_NFT &&
    INPUTS(1).id == SELF.id

  // Burn recorded in the live SideChainState burn tree, amount-bound.
  val tipBox = CONTEXT.dataInputs(0)
  val tipIsCurrentSingleton =
    tipBox.tokens.size == 1 &&
    tipBox.tokens(0)._1 == SIDECHAIN_STATE_NFT
  val lookupProof = getVar[Coll[Byte]](0).get
  val burnRecorded =
    tipBox.R6[AvlTree].get.get(SELF.R4[Coll[Byte]].get, lookupProof).get ==
      longToByteArray(SELF.R5[Long].get)

  sigmaProp(wellFormed && payoutContext && tipIsCurrentSingleton && burnRecorded)
}
