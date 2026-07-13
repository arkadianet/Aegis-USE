{
  // Aegis FeePot — a peg-in fee output (USE) buffering toward the SC emission
  // box. A peg-in tx pays its fee directly to this script address; anyone may
  // later sweep the box into the singleton PegVault, which accounts for its
  // USE (`feeSum`, the pass-2 sum-accounting) and credits the reserve.
  //
  // I1 role: unmerged FeePot USE counts as reserve (the emission "pot" is the
  // matching liability). Merging preserves value — the vault absorbs exactly
  // this box's USE.
  //
  // tokens[0] = (USE id, fee)
  //
  // ── SECURITY ─────────────────────────────────────────────────────────
  // Only spendable by merging into the vault: OUTPUTS(0) must carry the vault
  // singleton NFT, which (NFT conservation) forces the PegVault to be a spent
  // input → its script runs → `feeSum` requires this box's USE to land in the
  // vault, undivertible. No signature (permissionless sweep).
  //
  // ⚠ inject USE_TOKEN_ID, PEG_VAULT_NFT.

  val USE_TOKEN_ID = fromBase64("")   // todo inject a55b…2669
  val PEG_VAULT_NFT = fromBase64("")  // todo inject vault singleton NFT id

  val wellFormed =
    SELF.tokens.size > 0 &&
    SELF.tokens(0)._1 == USE_TOKEN_ID

  val mergedIntoVault =
    OUTPUTS(0).tokens.size > 0 &&
    OUTPUTS(0).tokens(0)._1 == PEG_VAULT_NFT

  sigmaProp(wellFormed && mergedIntoVault)
}
