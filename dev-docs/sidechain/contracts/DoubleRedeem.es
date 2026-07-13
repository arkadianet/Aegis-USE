{
  // Aegis DoubleRedeem — burn-once ledger (I3).
  // Holds an AvlTree of consumed Aegis burn ids; a PegVault payout must
  // update this box in the same tx, inserting the burn id it pays out.
  // insert() FAILS if the key already exists → a burn id can be redeemed
  // at most once. Authored fresh; pattern from ErgoHack
  // DoubleUnlockPrevention (reference only).
  //
  // tokens[0] = singleton contract NFT (identity; never leaves this box)
  // R4        = AvlTree of used burn ids
  //
  // convention: OUTPUTS(0) = PegVault', OUTPUTS(1) = this box updated.

  val selfTree = SELF.R4[AvlTree].get
  val selfOutput = OUTPUTS(1)

  // The burn id being consumed this tx (also bound by PegVault to the
  // UnlockIntent's burn_id — this contract only guarantees uniqueness).
  val burnId = selfOutput.R5[Coll[Byte]].get

  val proof = getVar[Coll[Byte]](0).get
  val insertOps: Coll[(Coll[Byte], Coll[Byte])] = Coll((burnId, burnId))

  // insert returns None if `burnId` is already present ⇒ .get fails ⇒
  // sigmaProp(false path). This is the double-redeem block.
  val expectedTree = selfTree.insert(insertOps, proof).get

  val validTransition =
    selfOutput.value == SELF.value &&
    selfOutput.tokens == SELF.tokens &&
    selfOutput.propositionBytes == SELF.propositionBytes &&
    selfOutput.R4[AvlTree].get == expectedTree

  sigmaProp(validTransition)
}
