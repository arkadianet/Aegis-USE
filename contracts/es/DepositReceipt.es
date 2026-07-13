{
  // Aegis DepositReceipt — a peg-in lock box (many parallel; no PegVault
  // contention). Holds N USE + R4=sc_dest (immutable while locked). The SC
  // mints a note to sc_dest after N_mint Ergo confs (aegis-node; I2/I5 SC
  // side). Spendable two ways:
  //   (a) CONSOLIDATOR MERGE — absorbed into the singleton PegVault;
  //   (b) REFUND — after a timeout, back to the depositor.
  //
  // tokens[0] = (USE id, N)
  // R4 = sc_dest (Coll[Byte]) — immutable while locked
  // R5 = memo (optional)   R6 = version/network id
  // R7 = depositor key (SigmaProp)   R8 = refund timeout height (Int)
  //
  // ⚠ deploy-time injections (fromBase64("") placeholders below):
  //   USE_TOKEN_ID, PEG_VAULT_NFT.
  // ⚠ cross-chain interlock (NOT enforceable here): the SC used-set MUST
  //   reject a late PegMint against a receipt already spent via refund.
  //   Otherwise a depositor could refund AND have minted. Enforced SC side.

  val USE_TOKEN_ID = fromBase64("")   // todo inject a55b…2669
  val PEG_VAULT_NFT = fromBase64("")  // todo inject vault singleton NFT id

  // N_mint (Ergo confs before the SC mints) + a margin; the refund cannot be
  // valid before creation + N_MINT + REFUND_MARGIN, so a depositor can't win a
  // refund-before-mint race by setting R8 too small. Defense-in-depth only —
  // the authoritative interlock is the SC used-set (I2), which must also
  // reject a late PegMint against a refunded boxId.
  val N_MINT = 10
  val REFUND_MARGIN = 30

  val timeout = SELF.R8[Int].get
  val depositor = SELF.R7[SigmaProp].get

  // Path (a): merge into the vault. OUTPUTS(0) must be the PegVault
  // (identified by its singleton NFT); the vault side sums this box's USE into
  // the vault (`receiptSum`, pass-2 siphon fix) and enforces ≤ V_cap. R4
  // immutability is moot (box consumed). NB the vault NFT is a singleton, so
  // OUTPUTS(0) carrying it forces the vault to be a spent input → its script
  // runs → this receipt's USE is accounted, never divertible.
  val vaultOut = OUTPUTS(0)
  val mergedIntoVault =
    vaultOut.tokens.size > 0 &&
    vaultOut.tokens(0)._1 == PEG_VAULT_NFT

  // Path (b): refund to the depositor, but only after `R8` AND only if `R8`
  // was set at least N_MINT+margin past this box's creation (else no refund —
  // funds await the mint/consolidation). SELF.creationInfo._1 = inclusion
  // height, unspoofable.
  val timedOut =
    HEIGHT >= timeout &&
    timeout >= SELF.creationInfo._1 + N_MINT + REFUND_MARGIN

  // Is this a USE receipt at all (a real box carrying the locked USE)? The
  // REFUND path uses only this lenient gate so a depositor can ALWAYS reclaim
  // their principal — even if they fat-fingered R4 at lock time.
  val isUseReceipt =
    SELF.tokens.size > 0 &&
    SELF.tokens(0)._1 == USE_TOKEN_ID &&
    SELF.R4[Coll[Byte]].isDefined

  // MINTABLE — the strict precondition the MERGE path additionally requires,
  // kept a SUPERSET of aegis-node `verify_pegmint` step 7 (review F1,
  // 2026-07-13): sc_dest is exactly a 33-byte compressed point. Because
  // consolidation is permissionless AND consolidated ⟹ unrefundable
  // (peg.md §3.1), a receipt that the SC could never mint (wrong-length R4)
  // MUST NOT be consolidatable — else anyone could front-run consolidation to
  // strand a victim's N (consolidatable-but-unmintable = permanent loss).
  // Gating merge on `mintable` closes that trap: a non-mintable receipt can
  // only leave via refund. INVARIANT: if verify_pegmint step 7 ever tightens,
  // this predicate must tighten to match (chain-id-breaking).
  val mintable =
    isUseReceipt &&
    SELF.R4[Coll[Byte]].get.size == 33

  // Merge path: no signature (anyone may consolidate a MINTABLE receipt into
  // the vault). Refund path: after timeout, the depositor signs — available
  // for ANY USE receipt, so principal is never stranded (mint-or-refund
  // always terminates).
  sigmaProp(mintable && mergedIntoVault) ||
    (sigmaProp(isUseReceipt && timedOut) && depositor)
}
