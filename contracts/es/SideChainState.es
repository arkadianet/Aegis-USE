{
  // Aegis SideChainState — the singleton tip-digest box on Ergo (pass 3).
  // Holds the miner-posted Aegis chain-tip commitment AND the authenticated
  // burn set (an insert-only AvlTree of every Aegis PegBurn), which the
  // UnlockIntent payout path reads (as a dataInput) as the burn-authenticity
  // source. Authored fresh; pattern from ErgoHack SideChainState
  // (reference only — upstream left the digest transition unvalidated,
  // `successor.R7.isDefined` + TODO; here the tree transition IS validated).
  //
  // tokens[0] = (SIDECHAIN_STATE_NFT, 1)  singleton identity (minted once at
  //             deploy; token ids are first-input box ids — unforgeable)
  // R4 = Long       Aegis sidechain height h (strictly increasing; jumps
  //                 allowed — many Aegis blocks per Ergo block)
  // R5 = Coll[Byte] Aegis tip commitment at h (32-byte block id / state
  //                 digest) — DATA, not verified on-chain (see C1 below)
  // R6 = AvlTree    burn tree: key = burn_id (32 bytes), value =
  //                 longToByteArray(N) (8 bytes, burned USE base units).
  //                 Genesis = empty tree, keyLength 32, valueLength Some(8),
  //                 enabledOperations = INSERT ONLY.
  // R7 = Int        Ergo height of the last update (rate limit)
  //
  // Update tx convention: INPUTS(i) = SELF, OUTPUTS(0) = successor.
  // Context extension (on SELF's input):
  //   getVar[Coll[(Coll[Byte], Coll[Byte])]](0) = new burn insert ops
  //     (absent ⇒ no burns this update; tree must be UNCHANGED)
  //   getVar[Coll[Byte]](1) = AVL insert proof (required iff var 0 present)
  //
  // ── THE DIGEST-SWAP DEFENSE (the load-bearing predicate) ────────────────
  // The successor's tree is TRANSITION-CONSTRAINED, not merely present:
  //     successor.R6 == SELF.R6.insert(ops, proof).get      (ops posted)
  //     successor.R6 == SELF.R6                             (no ops)
  // `insert` verifies the proof against the OLD digest and returns the NEW
  // tree; `.get` fails if any key already exists or the proof is invalid.
  // Consequence: every digest this box can ever hold is an insert-descendant
  // of the genesis empty tree — the updater (even holding TIP_PK) CANNOT
  //   * swap in a fresh/foreign tree (it is not the insert-image of SELF.R6),
  //   * delete or mutate a recorded burn (insert-only; re-inserting an
  //     existing burn_id fails ⇒ a burn's N is immutable once posted),
  //   * change tree params/flags (AvlTree == compares digest AND keyLength/
  //     valueLength/enabledOperations; both branches pin them to SELF's).
  // History is append-only: a fake burn is possible only via TIP_PK (C1) and
  // leaves a permanent, attributable on-chain insert record (fraud evidence).
  // NB `==` on AvlTree compares whole authenticated-tree values — no manual
  // digest byte-slicing anywhere (sidesteps the 0..32 vs 1..33 question).
  //
  // ── SECURITY ─────────────────────────────────────────────────────────────
  // * Stale-tip replay: impossible — readers take this box as a dataInput and
  //   dataInputs must be UNSPENT; only the current successor carries the NFT.
  // * Height rollback: successor.R4 > SELF.R4 (strict). An Aegis reorg below
  //   the posted tip therefore CANNOT be represented — v1 policy: post burns
  //   only at ≥ M_conf Aegis depth; an inserted-then-rolled-back burn is a
  //   C1 fraud event (halt). See DESIGN.md GAP-3.
  // * Fee siphon: successor.value >= SELF.value — updates cannot bleed the
  //   box's ERG endowment for tx fees; the updater funds fees externally.
  // * Rate limit: successor.R7 == HEIGHT && HEIGHT > SELF.R7 — at most one
  //   update per Ergo block (bounds tip churn for dataInput readers).
  // * PegVault interaction: this box is neither receipt- nor feepot-scripted
  //   and holds no USE (successor.tokens.size == 1), so it contributes 0 to
  //   the vault's pass-2 sum-accounting and cannot perturb it.
  //
  // ⚠⚠ C1 — v1 TRUST STATEMENT (verbatim-honest): the updater is a DECLARED
  //   TRUSTED KEY (TIP_PK, the miner-tip key). Burn authenticity is trusted
  //   from that key, bounded only by V_cap + T_delay. R5 (tip commitment) is
  //   unverified data. This contract makes the trusted key APPEND-ONLY and
  //   AUDITABLE — it does NOT make peg-out trust-minimized. Do NOT deploy
  //   value beyond V_cap; trust-minimization needs U1-strong (k-of-n
  //   attesters) or SPV-in-consensus. See DESIGN.md §C1.
  // ⚠ deploy-time injections: SIDECHAIN_STATE_NFT, TIP_PK (33-byte
  //   compressed EC point).

  val SIDECHAIN_STATE_NFT = fromBase64("")        // todo state singleton NFT id
  val TIP_PK = decodePoint(fromBase64(""))        // todo miner-tip pubkey (C1)

  val successor = OUTPUTS(0)

  // Singleton + script + endowment preserved; exactly the NFT (no USE, no
  // extra tokens — keeps this box invisible to PegVault sum-accounting).
  val structural =
    SELF.tokens.size == 1 &&
    SELF.tokens(0)._1 == SIDECHAIN_STATE_NFT &&
    successor.tokens.size == 1 &&
    successor.tokens(0)._1 == SIDECHAIN_STATE_NFT &&
    successor.tokens(0)._2 == 1L &&
    successor.propositionBytes == SELF.propositionBytes &&
    successor.value >= SELF.value

  // Aegis height strictly increases (jumps allowed: many Aegis blocks per
  // Ergo block); tip commitment is a 32-byte digest; ≤ 1 update / Ergo block.
  val heightAdvances = successor.R4[Long].get > SELF.R4[Long].get
  val tipWellFormed = successor.R5[Coll[Byte]].get.size == 32
  val rateLimited =
    successor.R7[Int].get == HEIGHT &&
    HEIGHT > SELF.R7[Int].get

  // Burn-tree transition (see DIGEST-SWAP DEFENSE above).
  val oldTree = SELF.R6[AvlTree].get
  val newTree = successor.R6[AvlTree].get
  val burnOps = getVar[Coll[(Coll[Byte], Coll[Byte])]](0)
  val treeTransition =
    if (burnOps.isDefined) {
      val proof = getVar[Coll[Byte]](1).get
      newTree == oldTree.insert(burnOps.get, proof).get
    } else {
      newTree == oldTree
    }

  proveDlog(TIP_PK) &&
    sigmaProp(structural && heightAdvances && tipWellFormed && rateLimited && treeTransition)
}
