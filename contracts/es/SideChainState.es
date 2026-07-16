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
  // of the genesis empty tree — the updater (even a k-of-n attester quorum)
  // CANNOT
  //   * swap in a fresh/foreign tree (it is not the insert-image of SELF.R6),
  //   * delete or mutate a recorded burn (insert-only; re-inserting an
  //     existing burn_id fails ⇒ a burn's N is immutable once posted),
  //   * change tree params/flags (AvlTree == compares digest AND keyLength/
  //     valueLength/enabledOperations; both branches pin them to SELF's).
  // History is append-only: a fake burn is possible only via a k-of-n
  // attester quorum (C1) and leaves a permanent, attributable on-chain
  // insert record (fraud evidence).
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
  // ── C1 — U1-STRONG (k-of-n attesters, ROTATABLE via S1d) ───────────────
  //   Tip updates (INCLUDING every burn insert) are authorized by a k-of-n
  //   ATTESTER FEDERATION, not a single key. A fake burn now requires k
  //   colluding attesters instead of one compromised tip key, and still
  //   leaves a permanent, attributable append-only insert record (fraud
  //   evidence). Burn authenticity is therefore majority-honest-trusted,
  //   bounded by V_cap + T_delay. R5 (tip commitment) remains unverified
  //   DATA — k-of-n does NOT make peg-out trustless; full trust-minimization
  //   needs SPV-in-consensus / STARK settlement (S2). See attester-infra.md
  //   §S1c/§S1d + DESIGN.md §C1.
  //
  //   S1d: the federation is no longer INLINED here. It is read from the
  //   AttestRegistry singleton box (pinned by ATTEST_REGISTRY_NFT) provided as
  //   dataInputs(0): R4 = Coll[GroupElement] members, R5 = Int threshold k.
  //   The authority is `atLeast(k, members.map(proveDlog))` built from THOSE
  //   registers — so ROTATING the registry (add/remove/replace an attester)
  //   changes who may advance the tip with NO SideChainState redeploy. The
  //   AttestRegistry contract constrains every set it can hold to
  //   1 <= k <= n <= 255 and distinct members, so the atLeast built here can
  //   never degenerate (k<=0 ⇒ anyone-spends; k>n / n>255 ⇒ brick).
  //
  //   SOUNDNESS of the dataInput read: `registryValid` (dataInputs(0) carries
  //   the real ATTEST_REGISTRY_NFT — an UNFORGEABLE singleton) is ANDed into
  //   the sigmaProp below. A spoofed dataInput fails registryValid, so even
  //   though its attacker-chosen R4/R5 could satisfy the atLeast, the ANDed
  //   sigmaProp(false) rejects the spend; the ONLY way to pass is to reference
  //   the genuine registry, whose members/k are the real ones. dataInputs must
  //   be UNSPENT ⇒ only the LIVE registry box qualifies (no stale-set replay).
  // ⚠ deploy-time injections: SIDECHAIN_STATE_NFT, ATTEST_REGISTRY_NFT (the
  //   AttestRegistry singleton NFT id). The set + threshold are NOT injected
  //   here anymore — they live in the registry box's registers.

  val SIDECHAIN_STATE_NFT = fromBase64("")   // todo state singleton NFT id
  val ATTEST_REGISTRY_NFT = fromBase64("")   // todo attest-registry singleton NFT id

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

  // U1-strong authority (S1d, rotatable): read the CURRENT federation from the
  // AttestRegistry singleton (dataInputs(0), pinned by its NFT) and require
  // its k-of-n to co-sign. `registryValid` is ANDed into the sigmaProp so a
  // spoofed dataInput cannot inject attacker keys (see SOUNDNESS note above).
  // The transition constraints are ANDed on too, so ≥k signatures are
  // NECESSARY but not sufficient — a signed update still has to be a valid
  // append-only advance.
  val registry = CONTEXT.dataInputs(0)
  val registryValid =
    registry.tokens.size == 1 &&
    registry.tokens(0)._1 == ATTEST_REGISTRY_NFT
  val attesterPks = registry.R4[Coll[GroupElement]].get
  val attestK = registry.R5[Int].get

  atLeast(attestK, attesterPks.map({ (pk: GroupElement) => proveDlog(pk) })) &&
    sigmaProp(
      registryValid &&
      structural && heightAdvances && tipWellFormed && rateLimited && treeTransition
    )
}
