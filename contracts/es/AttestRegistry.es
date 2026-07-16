{
  // Aegis AttestRegistry — the singleton-NFT box that holds the CURRENT
  // k-of-n attester federation, so the set can be ROTATED (add/remove/replace
  // an attester, or change k) WITHOUT redeploying SideChainState. SideChainState
  // reads this box as a dataInput and builds its tip-advance authority
  // `atLeast(k, pks.map(proveDlog))` from these registers (S1d). Authored fresh
  // for S1d (attester-infra.md §S1d); the singleton-transition pattern mirrors
  // SideChainState's tree-transition discipline.
  //
  // tokens[0] = (ATTEST_REGISTRY_NFT, 1)  singleton identity (minted once at
  //             deploy; token id = first-input box id — unforgeable)
  // R4 = Coll[GroupElement]  the ordered attester pubkeys (the CURRENT
  //             federation; n = R4.size, each a 33-byte SEC1 point)
  // R5 = Int    the threshold k
  //
  // ── DEPLOY / ROTATION CEREMONY GATES (the script CANNOT see these — the mint
  //   and every rotation MUST get them right; S1d red-review P2) ──
  //   * MINT SUPPLY == 1. SideChainState's dataInput-spoofing defense rests on
  //     this NFT being a true singleton (EIP-4). NEVER mint supply > 1 — with
  //     supply > 1 an attacker box could carry a unit + attacker-chosen R4/R5.
  //   * Members on-curve, non-identity, and INDEPENDENTLY held (distinct OWNERS,
  //     not merely distinct bytes) — the in-script `distinct` is byte-only.
  //   * Pick k >= floor(n/2)+1; avoid k == n (one lost key then deadlocks BOTH
  //     the tip and rotation). The script only enforces 1 <= k <= n <= 255.
  //
  // Update tx convention: INPUTS(i) = SELF, OUTPUTS(0) = successor.
  //
  // ── THE ONLY SPEND PATH IS ROTATION ─────────────────────────────────────
  // This box may be spent ONLY to replace it with a successor carrying a new
  // {pks, k}, authorized by the CURRENT set's own quorum:
  //     atLeast(k, R4.map(proveDlog))          // the SITTING quorum signs
  // i.e. a rotation is a k-of-n co-signed transaction over the CURRENT
  // members — the sitting quorum authorizes its own change. The successor is
  // structurally CONSTRAINED (below), so ≥k signatures are NECESSARY but not
  // sufficient: a signed rotation still has to produce a WELL-FORMED successor.
  //
  // ── SUCCESSOR CONSTRAINTS (what a rotation may NOT do) ───────────────────
  // * Singleton preserved: successor carries exactly the SAME NFT (tokens.size
  //   == 1, tokens(0) == (ATTEST_REGISTRY_NFT, 1)) — the federation identity
  //   cannot be split, burned, or forked.
  // * Script preserved: successor.propositionBytes == SELF.propositionBytes —
  //   the rotation rules are immutable (no swap to a laxer registry script).
  // * Endowment preserved: successor.value >= SELF.value — a rotation cannot
  //   bleed the box's ERG for fees; the rotator funds fees externally.
  // * Sane threshold + set — enforced IN-SCRIPT on the NEW registers, because
  //   the interpreter's atLeast has three catastrophic degenerate cases and
  //   SideChainState's authority is BUILT from these exact registers:
  //     - k <= 0   ⇒ atLeast is TRIVIALLY TRUE ⇒ ANYONE could then advance the
  //                  tip (and rotate again) — an irreversible hijack. Blocked:
  //                  newK >= 1.
  //     - k > n    ⇒ atLeast is UNSATISFIABLE ⇒ tip + registry both BRICK
  //                  (permanent halt). Blocked: newK <= n.
  //     - n > 255  ⇒ atLeast throws (MaxChildrenCountForAtLeastOp) ⇒ tip eval
  //                  ERRORS ⇒ brick. Blocked: n <= 255.
  //   So every registry this box can ever become carries 1 <= k <= n <= 255.
  // * Distinct members — a duplicated key lets ONE secret fill multiple atLeast
  //   slots and collapse the effective threshold (k colluders → fewer). The
  //   interpreter's atLeast does NOT dedup, so we reject duplicates here
  //   (O(n^2) pairwise; n is tiny). NB this is defense-in-depth: a rotation
  //   already needs the CURRENT honest quorum to co-sign, and a set's members
  //   must additionally be INDEPENDENTLY HELD (on-curve + distinct-owner) —
  //   independent custody is a ceremony gate the script cannot see (see the
  //   AttestRegistry ceremony gates in s1d docs, mirroring S1c D2).
  //
  // ── WHO CAN ROTATE / HIJACK (honest trust statement) ────────────────────
  // Rotation power == the current k-of-n. If ≥k CURRENT attesters collude they
  // can seize the federation (rotate to keys they control) — but that is the
  // SAME C1 trust boundary that already lets ≥k colluders forge a burn via
  // SideChainState; S1d adds NO new hijack surface beyond C1. A malformed
  // successor cannot BRICK the registry: the successor register reads
  // (R4/R5[..].get) and the guards below are evaluated when SPENDING SELF, so
  // a bad successor makes the ROTATION TX fail and SELF stays live (unspent) —
  // the old federation simply persists. The residual governance foot-gun
  // (a valid rotation to k == n, then a lost key ⇒ neither tip nor registry
  // can advance) is a ceremony concern: pick k = majority, not unanimity.

  val ATTEST_REGISTRY_NFT = fromBase64("")   // todo registry singleton NFT id

  val currentPks = SELF.R4[Coll[GroupElement]].get
  val k = SELF.R5[Int].get

  val successor = OUTPUTS(0)
  val newPks = successor.R4[Coll[GroupElement]].get
  val newK = successor.R5[Int].get
  val n = newPks.size

  // Singleton identity + script + endowment preserved across the rotation.
  val structural =
    SELF.tokens.size == 1 &&
    SELF.tokens(0)._1 == ATTEST_REGISTRY_NFT &&
    successor.tokens.size == 1 &&
    successor.tokens(0)._1 == ATTEST_REGISTRY_NFT &&
    successor.tokens(0)._2 == 1L &&
    successor.propositionBytes == SELF.propositionBytes &&
    successor.value >= SELF.value

  // Sane new federation: 1 <= k <= n <= 255 (each bound blocks a distinct
  // atLeast degenerate case — see SUCCESSOR CONSTRAINTS above).
  val boundOk =
    n >= 1 &&
    n <= 255 &&
    newK >= 1 &&
    newK <= n

  // Distinct members: no key equals any other (pairwise; the interpreter's
  // atLeast has no dedup, so a repeat would collapse the threshold).
  val idx = newPks.indices
  val distinct = idx.forall({ (i: Int) =>
    idx.forall({ (j: Int) => (i == j) || (newPks(i) != newPks(j)) })
  })

  // Authority: the CURRENT set's k-of-n co-sign the rotation; ANDed with the
  // successor constraints so a signed rotation must still be well-formed.
  atLeast(k, currentPks.map({ (pk: GroupElement) => proveDlog(pk) })) &&
    sigmaProp(structural && boundOk && distinct)
}
