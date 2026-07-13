//! Ergo-SPV peg-in objectivity engine (G2.5 — steps 1–4 of
//! `dev-docs/sidechain/g25-pegmint-packaging.md`).
//!
//! A validator syncing from genesis years later must accept/reject each
//! PegMint identically, so this is a **pure function of the proof
//! bytes**: it reuses the product node's Autolykos-v2 PoW + NiPoPoW
//! verifiers (confirmed stand-alone by the reuse spike), checks the
//! proof chains to a **pinned Ergo anchor** (without which a forged
//! low-history chain would pass), is at least `N_mint` deep, and carries
//! at least an absolute suffix-work floor. The tx/box/receipt/used-set
//! steps (5–9) are the documented follow-on.
//!
//! ⚠⚠ **DO NOT WIRE THIS TO REAL VALUE YET.** The §2b comparative
//! work-policy is IMPLEMENTED and adversarially reviewed
//! (2026-07-13, SOUND-WITH-FIXES; both P1 fixes applied):
//! [`verify_ergo_chain_comparative`] — the proof's settled portion
//! must lie on the Ergo chain this node independently follows (see
//! [`check_comparative_objectivity`] for why a dense reference makes
//! membership the exact evaluation of NiPoPoW's comparative model).
//! Review-pinned contracts: **(P1-A)** the membership check objectifies
//! ONLY the settled prefix ≤ `H_ref`; the suffix up to the
//! attacker-chosen tip is merely PoW-valid, so the accepted result
//! ([`ComparativeAnchor`]) exposes ONLY the settled view and steps 5–9
//! MUST bind tx-inclusion through it — peg-in security above `H_ref`
//! remains the `N_mint`-deep-PoW / `V_cap` assumption of §2b.i/§4.
//! **(P1-B)** the canonical consensus verdict is
//! comparative-once-caught-up; [`PegMintError::NotCaughtUp`] is a
//! deferral ("wait and re-evaluate"), never a block-invalid verdict,
//! which makes the verdict a time-invariant function of the proof for
//! every honest validator including from-genesis re-syncers.
//! What still blocks value: (a) steps 5–9 (consolidation-tx / receipt /
//! used-set — peg.md §3.1 two-inclusion binding) are BUILT + adversarially
//! reviewed SOUND (2026-07-13) as a pure verifier in
//! [`crate::pegmint_steps`] (g25 §5), with the steps-1–4↔5–9 binding made
//! STRUCTURAL via [`crate::pegmint_steps::verify_pegmint_full`] (derives the
//! anchor from `proof.work` internally — review P2) — but NOT wired into
//! consensus; (b) the follower's LIVE header feed exists
//! ([`crate::ergo_follow::poll_http`]) but is not driven by the main loop;
//! (c) external sign-off on `N_mint`/§2b.i reorg margin + the §2b.ii
//! bootstrap floor + the §5.5 `min()` emission-policy rule (which also owns
//! reconciling the two peg-fee formulas — `PegParams::peg_fee` floor-div vs
//! `aegis-spec` ceil-div, review NIT, inert under `min()`). (Full-proof e2e: CLOSED — both entry points
//! are exercised end-to-end on a real continuous testnet proof in
//! `aegis-node/tests/pegmint_real_proof_e2e.rs`, every `is_valid`
//! sub-check asserted.) [`verify_ergo_chain`] (static `work_floor`)
//! remains ONLY as the explicitly NON-CANONICAL §2b.ii cold-validator
//! bootstrap fallback.
//!
//! Smaller items: pin `diff: DifficultyParams` per-network (not
//! caller-chosen), assert `genesis.height == anchor.height`
//! (defense-in-depth), and move the anchor/`diff` to `aegis-spec`. Full
//! detail in g25-pegmint-packaging §2/§2b + DEFERRED. Until then these
//! are standalone unwired lib fns.

use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::popow_proof::NipopowProof;
use ergo_validation::popow::proof::NipopowProofExt;
use num_bigint::BigUint;

/// Difficulty parameters consumed by the reused PoW/NiPoPoW verifiers.
pub use ergo_crypto::difficulty::DifficultyParams;

/// A pinned Ergo origin the proof must chain to. Changing it is
/// chain-id-breaking.
#[derive(Debug, Clone)]
pub struct ErgoAnchor {
    /// Header id (blake2b256 of the serialized header) of the pinned
    /// origin block.
    pub header_id: [u8; 32],
    /// Height of the pinned origin.
    pub height: u32,
    /// Absolute suffix-work floor — the Aegis-authored objectivity
    /// policy knob (external-review item).
    pub work_floor: BigUint,
}

/// Ergo **testnet** genesis (height 1), verified live from the node
/// 2026-07-12 (`127.0.0.1:9052 /blocks/at/1`). The `work_floor` is a
/// placeholder policy value — testnet difficulty is trivial; the real
/// floor needs external sign-off before value.
pub fn ergo_testnet_anchor() -> ErgoAnchor {
    let mut header_id = [0u8; 32];
    header_id.copy_from_slice(
        &hex::decode("5b1827ca092b599eafbaf339d2acf2445bc5216ec2e022d9c001a6fff660cad9")
            .expect("valid hex"),
    );
    ErgoAnchor {
        header_id,
        height: 1,
        work_floor: BigUint::from(1u32),
    }
}

/// The accepted objectivity result — feeds the remaining PegMint steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredTip {
    pub tip_id: [u8; 32],
    pub tip_height: u32,
    pub suffix_work: BigUint,
}

/// Which of the two tx-inclusion claims a steps-5–9 error refers to
/// (g25 §5.7): the LOCK tx supplies the receipt box content, the
/// CONSOLIDATION tx is the mint commit-point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InclusionRole {
    Lock,
    Consolidation,
}

#[derive(Debug, thiserror::Error)]
pub enum PegMintError {
    #[error("Ergo chain proof invalid (PoW/interlinks/heights)")]
    InvalidChain,
    #[error("proof is not a continuous chain")]
    NotContinuous,
    #[error("empty proof")]
    EmptyProof,
    #[error("proof does not chain to the pinned Ergo anchor")]
    WrongAnchor,
    #[error("anchored tip only {got} deep, need >= {need}")]
    InsufficientDepth { got: u64, need: u64 },
    #[error("suffix work below the objectivity floor")]
    InsufficientWork,
    #[error("header serialization failed")]
    Serialize,
    #[error("follower has not caught up to the settled reference height {h_ref}")]
    NotCaughtUp { h_ref: u32 },
    #[error("proof shares no settled header with the followed chain")]
    NoCommonAncestor,
    #[error("proof's settled header at height {height} is not on the followed chain")]
    DivergesFromFollowedChain { height: u32 },
    // ----- steps 5–9 (g25 §5.7; step order = check order) -----
    #[error("proof field {field} oversize: {len} bytes (max {max})")]
    Oversize {
        field: &'static str,
        len: usize,
        max: usize,
    },
    #[error("malformed proof field {field}")]
    MalformedProof { field: &'static str },
    #[error("{role:?} inclusion header (height {height}) is not in the settled view (P1-A)")]
    InclusionNotSettled { role: InclusionRole, height: u32 },
    #[error("{role:?} inclusion proof leaf does not bind the recomputed tx id")]
    MalformedInclusionProof { role: InclusionRole },
    #[error("{role:?} tx is not in the carried header's transactions root")]
    TxNotInBlock { role: InclusionRole },
    #[error("receipt output index {got} out of range (lock tx has {len} outputs)")]
    OutputIndexOutOfRange { got: u16, len: usize },
    #[error("receipt input index {got} out of range (consolidation tx has {len} inputs)")]
    InputIndexOutOfRange { got: u16, len: usize },
    #[error("consolidation tx does not spend the receipt box id")]
    ReceiptNotConsumed,
    #[error("consolidation tx OUTPUTS(0) does not carry the peg-vault NFT (refund-shaped)")]
    NotConsolidatedIntoVault,
    #[error("receipt box script does not match the pinned DepositReceipt template")]
    WrongReceiptScript,
    #[error("receipt box does not carry the USE token at tokens(0)")]
    WrongToken,
    #[error("receipt box locks a zero USE amount")]
    ZeroAmount,
    #[error("receipt R4 is not a 33-byte Coll[Byte] sc_dest")]
    BadScDest,
    #[error("receipt box id already minted (I2 replay)")]
    AlreadyMinted,
}

/// The consensus **objectivity policy** (steps 3–4) over primitive
/// inputs — the genesis header id, the tip height, and the dense
/// suffix's per-header `n_bits`. Pure and unit-testable without real
/// PoW: returns the cumulative suffix work on success.
fn check_objectivity(
    genesis_id: [u8; 32],
    tip_height: u32,
    suffix_nbits: &[u32],
    anchor: &ErgoAnchor,
    n_mint: u64,
) -> Result<BigUint, PegMintError> {
    check_anchored_depth(genesis_id, tip_height, anchor, n_mint)?;
    // (4b) absolute suffix work (the policy layered on the reused
    // *relative* NiPoPoW comparison — external sign-off).
    let work = suffix_nbits
        .iter()
        .map(|nbits| decode_compact_bits(*nbits))
        .fold(BigUint::from(0u32), |acc, w| acc + w);
    if work < anchor.work_floor {
        return Err(PegMintError::InsufficientWork);
    }
    Ok(work)
}

/// Steps 3 + 4a, shared by both work-policies (static bootstrap floor
/// and §2b comparative): pinned-anchor equality and `N_mint` depth.
fn check_anchored_depth(
    genesis_id: [u8; 32],
    tip_height: u32,
    anchor: &ErgoAnchor,
    n_mint: u64,
) -> Result<(), PegMintError> {
    // (3) anchoring: the proof's genesis must be the pinned origin.
    if genesis_id != anchor.header_id {
        return Err(PegMintError::WrongAnchor);
    }
    // (4a) depth: the tip must be at least `N_mint` beyond the anchor.
    let depth = u64::from(tip_height.saturating_sub(anchor.height));
    if depth < n_mint {
        return Err(PegMintError::InsufficientDepth {
            got: depth,
            need: n_mint,
        });
    }
    Ok(())
}

fn header_id(h: &Header) -> Result<[u8; 32], PegMintError> {
    let (_bytes, id) = serialize_header(h).map_err(|_| PegMintError::Serialize)?;
    Ok(*id.as_bytes())
}

/// Verify the Ergo-header-chain objectivity of a PegMint proof
/// (steps 1–4 of the design). On success the remaining steps
/// (tx/box/receipt/used-set) run against [`AnchoredTip`].
pub fn verify_ergo_chain(
    proof: &NipopowProof,
    anchor: &ErgoAnchor,
    diff: &DifficultyParams,
    n_mint: u64,
) -> Result<AnchoredTip, PegMintError> {
    // (1)+(2) REUSED: Autolykos-v2 PoW per header + NiPoPoW validity
    // (interlinks, heights) — `is_valid` composes both. No node state.
    if !proof.is_valid(diff) {
        return Err(PegMintError::InvalidChain);
    }
    if !proof.continuous {
        return Err(PegMintError::NotContinuous);
    }
    // Extract the primitives the objectivity policy needs.
    let chain = proof.headers_chain();
    let genesis = chain.first().ok_or(PegMintError::EmptyProof)?;
    let tip = chain.last().ok_or(PegMintError::EmptyProof)?;
    let k = (proof.k as usize).min(chain.len());
    let suffix_nbits: Vec<u32> = chain[chain.len() - k..].iter().map(|h| h.n_bits).collect();
    let work = check_objectivity(
        header_id(genesis)?,
        tip.height,
        &suffix_nbits,
        anchor,
        n_mint,
    )?;
    Ok(AnchoredTip {
        tip_id: header_id(tip)?,
        tip_height: tip.height,
        suffix_work: work,
    })
}

/// §2b comparative work-policy, **evaluated exactly against the dense
/// followed chain**: every settled proof header (height ≤ the view's
/// `h_ref`) at or above the follower's root must be a member of the
/// followed best chain.
///
/// Why membership and not a `best_arg` score comparison: the reference
/// here is DENSE (the follower keeps every best-chain header, gap-free
/// by construction), while a proof's settled portion is its SPARSE
/// superblock prefix — KMZ17's score comparison (`is_better_than`) is
/// only meaningful between two prover-constructed sparse chains, and
/// scoring dense-vs-sparse would reject honest proofs whose prefix is
/// legitimately empty near `h_ref`. With a dense reference the
/// comparative question degenerates to exact membership:
///  - an honest proof of the real chain has every settled header on
///    the followed chain → accept;
///  - a valid-but-weaker fork diverges at some settled height → its
///    first divergent settled header is off-chain → reject. A fork
///    below the settled height is a reorg deeper than `N_mint`, which
///    §2b.i places out of model. Rejecting an (out-of-model) heavier
///    unknown fork can only refuse mints, never inflate.
///
/// Headers below the follower's root (checkpoint-rooted follower)
/// cannot be corroborated and are skipped — the §2b.ii bootstrap
/// caveat; at least one settled proof header must overlap the view or
/// the proof is not comparable ([`PegMintError::NoCommonAncestor`]).
/// A `best_arg`-vs-`best_arg` comparison (via
/// `ergo_validation::popow::best_arg_from_levels` over the follower's
/// recorded μ-levels) is reserved for a future SPARSE-reference
/// bootstrap mode.
pub fn check_comparative_objectivity(
    settled_chain: &[Header],
    view: &crate::ergo_follow::SettledView,
) -> Result<(), PegMintError> {
    let root = view.root_height();
    let mut corroborated = 0usize;
    for h in settled_chain {
        if h.height < root {
            // Below the followed root: not corroboratable by
            // membership. LOAD-BEARING TRUST NOTE (review P2): the
            // integrity of these skipped headers rests entirely on
            // `is_valid` (strict-monotone heights + interlink
            // connections + per-header PoW) chaining them to the
            // pinned anchor — i.e. the §2b.ii checkpoint trust, NOT
            // the follower. A genesis-rooted follower skips nothing.
            continue;
        }
        match view.height_of(&header_id(h)?) {
            Some(view_height) if view_height == h.height => corroborated += 1,
            // Same id at a different height is impossible (the id
            // commits to the height); either way the header is not on
            // the followed best chain at its claimed height.
            _ => {
                return Err(PegMintError::DivergesFromFollowedChain { height: h.height });
            }
        }
    }
    if corroborated == 0 {
        return Err(PegMintError::NoCommonAncestor);
    }
    Ok(())
}

/// Accepted §2b comparative result — **deliberately exposes ONLY the
/// membership-checked settled region** (review 2026-07-13 P1-A). The
/// proof's dense suffix above `h_ref` — up to its attacker-chosen tip —
/// is PoW/interlink-checked by `is_valid` but NEVER membership-checked,
/// so nothing about it (no `tip_id`, no suffix work) appears here:
/// steps 5–9 MUST resolve the consolidation tx's inclusion header
/// through [`ComparativeAnchor::settled_view`] (height ≤ `h_ref`), else
/// an attacker who privately extends the real chain by `N_mint` valid
/// headers could plant a fake consolidation in the un-objectified
/// suffix and mint unbacked USE. Binding inclusion at ≤ `h_ref` kills
/// that: the fake tx would have to sit in a real settled block the
/// attacker cannot forge.
#[derive(Debug, Clone)]
pub struct ComparativeAnchor {
    /// The settled reference height `proof.tip_height − N_mint`.
    pub h_ref: u32,
    /// The followed best chain truncated to `h_ref` — the ONLY headers
    /// steps 5–9 may verify tx-inclusion against.
    pub settled_view: crate::ergo_follow::SettledView,
}

/// The §2b policy over a validated proof chain: compute the settled
/// reference `H_ref = tip_height − N_mint`, take the follower's view
/// there, and require the proof's settled portion to lie on the
/// followed chain. Returns the membership-checked settled region for
/// the step 5–9 follow-on.
///
/// [`PegMintError::NotCaughtUp`] is a **deferral signal, not a
/// rejection verdict** (review 2026-07-13 P1-B): the membership
/// question "is this settled header on the real Ergo chain ≤ H_ref?"
/// has a time-invariant answer once `H_ref` is buried (§2b.i model),
/// so the canonical verdict is defined *once caught up* and is then
/// identical for every honest validator — including a from-genesis
/// re-syncer, which follows Ergo forward and reproduces the same
/// verdicts. Consensus wiring MUST treat `NotCaughtUp` as "wait and
/// re-evaluate", never as "invalid block".
///
/// Split out of [`verify_ergo_chain_comparative`] so the policy is
/// testable with real header chains without constructing a full
/// `is_valid`-passing `NipopowProof`.
pub fn comparative_policy(
    chain: &[Header],
    n_mint: u64,
    follower: &crate::ergo_follow::Follower,
) -> Result<ComparativeAnchor, PegMintError> {
    let tip = chain.last().ok_or(PegMintError::EmptyProof)?;
    let h_ref64 =
        u64::from(tip.height)
            .checked_sub(n_mint)
            .ok_or(PegMintError::InsufficientDepth {
                got: u64::from(tip.height),
                need: n_mint,
            })?;
    // h_ref64 <= tip.height (a u32), so the narrowing is lossless.
    let h_ref = h_ref64 as u32;
    let view = follower
        .settled_view(h_ref)
        .ok_or(PegMintError::NotCaughtUp { h_ref })?;
    let settled: Vec<Header> = chain
        .iter()
        .filter(|h| h.height <= h_ref)
        .cloned()
        .collect();
    check_comparative_objectivity(&settled, &view)?;
    Ok(ComparativeAnchor {
        h_ref,
        settled_view: view,
    })
}

/// [`verify_ergo_chain`] with the §2b comparative work-policy in place
/// of the static bootstrap `work_floor`: steps (1)+(2) reused verifiers,
/// (3) anchor equality, (4a) `N_mint` depth, then (4b′) the settled
/// portion of the proof must lie on the Ergo chain this node has
/// independently followed. Returns [`ComparativeAnchor`] — the settled,
/// membership-checked region ONLY (no suffix tip; see the P1-A note on
/// the type). The static-floor entry point is the explicitly
/// NON-CANONICAL §2b.ii bootstrap fallback; the canonical verdict is
/// this function's, evaluated once the follower is caught up
/// (`NotCaughtUp` = defer, see [`comparative_policy`]).
pub fn verify_ergo_chain_comparative(
    proof: &NipopowProof,
    anchor: &ErgoAnchor,
    diff: &DifficultyParams,
    n_mint: u64,
    follower: &crate::ergo_follow::Follower,
) -> Result<ComparativeAnchor, PegMintError> {
    if !proof.is_valid(diff) {
        return Err(PegMintError::InvalidChain);
    }
    if !proof.continuous {
        return Err(PegMintError::NotContinuous);
    }
    let chain = proof.headers_chain();
    let genesis = chain.first().ok_or(PegMintError::EmptyProof)?;
    let tip = chain.last().ok_or(PegMintError::EmptyProof)?;
    check_anchored_depth(header_id(genesis)?, tip.height, anchor, n_mint)?;
    comparative_policy(&chain, n_mint, follower)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn anchor_with(id: [u8; 32], height: u32, floor: u32) -> ErgoAnchor {
        ErgoAnchor {
            header_id: id,
            height,
            work_floor: BigUint::from(floor),
        }
    }

    // A real testnet nBits (difficulty 1 era) — decodes to a positive
    // work value; used to exercise the work-sum arithmetic.
    const NBITS: u32 = 0x1a01_765e;

    // ----- happy path -----

    #[test]
    fn objectivity_accepts_anchored_deep_worked_chain() {
        let anchor = anchor_with([0xAB; 32], 1, 1);
        let work = check_objectivity([0xAB; 32], 11, &[NBITS, NBITS], &anchor, 10)
            .expect("anchored, 10 deep, work present");
        // suffix work = 2 × decode(NBITS).
        assert_eq!(work, decode_compact_bits(NBITS) * BigUint::from(2u32));
    }

    #[test]
    fn testnet_anchor_is_the_verified_genesis_id() {
        let a = ergo_testnet_anchor();
        assert_eq!(
            hex::encode(a.header_id),
            "5b1827ca092b599eafbaf339d2acf2445bc5216ec2e022d9c001a6fff660cad9"
        );
        assert_eq!(a.height, 1);
    }

    // ----- error paths -----

    #[test]
    fn wrong_genesis_id_rejected_as_wrong_anchor() {
        let anchor = anchor_with([0xAB; 32], 1, 1);
        assert!(matches!(
            check_objectivity([0xCD; 32], 100, &[NBITS], &anchor, 10),
            Err(PegMintError::WrongAnchor)
        ));
    }

    #[test]
    fn shallow_tip_rejected_as_insufficient_depth() {
        let anchor = anchor_with([0xAB; 32], 1, 1);
        // tip height 5, anchor 1 → depth 4 < N_mint 10.
        assert!(matches!(
            check_objectivity([0xAB; 32], 5, &[NBITS], &anchor, 10),
            Err(PegMintError::InsufficientDepth { got: 4, need: 10 })
        ));
    }

    #[test]
    fn suffix_work_below_floor_rejected() {
        // Floor above what two headers supply.
        let floor = decode_compact_bits(NBITS) * BigUint::from(100u32);
        let anchor = ErgoAnchor {
            header_id: [0xAB; 32],
            height: 1,
            work_floor: floor,
        };
        assert!(matches!(
            check_objectivity([0xAB; 32], 100, &[NBITS, NBITS], &anchor, 10),
            Err(PegMintError::InsufficientWork)
        ));
    }

    #[test]
    fn empty_suffix_has_zero_work_and_fails_a_positive_floor() {
        let anchor = anchor_with([0xAB; 32], 1, 1);
        assert!(matches!(
            check_objectivity([0xAB; 32], 100, &[], &anchor, 10),
            Err(PegMintError::InsufficientWork)
        ));
    }

    // ----- comparative policy (§2b, dense-reference membership) -----

    use crate::ergo_follow::Follower;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::read_header;

    /// Real consecutive mainnet headers 1..=10 (valid PoW) — the same
    /// oracle vector the follower suite uses.
    fn real_headers() -> Vec<Header> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test-vectors/mainnet/headers_1_10.json");
        let data = std::fs::read_to_string(&path).expect("read header vectors");
        let vectors: serde_json::Value = serde_json::from_str(&data).expect("parse");
        vectors
            .as_array()
            .expect("array")
            .iter()
            .map(|v| {
                let raw = hex::decode(v["bytes"].as_str().expect("bytes")).expect("hex");
                let mut r = VlqReader::new(&raw);
                read_header(&mut r).expect("real header decodes")
            })
            .collect()
    }

    fn followed(headers: &[Header]) -> Follower {
        let mut f = Follower::new(3);
        for h in headers {
            f.apply_header(h).expect("real header follows");
        }
        f
    }

    #[test]
    fn comparative_full_membership_chain_accepts_and_returns_settled_region() {
        let headers = real_headers();
        let follower = followed(&headers);
        // Proof chain = the exact followed chain; n_mint 3 → h_ref 7,
        // settled = heights 1..=7, all on the followed chain.
        let anchor = comparative_policy(&headers, 3, &follower).expect("honest chain accepts");
        // P1-A contract: the result exposes ONLY the settled region —
        // h_ref and a view covering exactly heights 1..=7. Nothing
        // above h_ref (the suffix) is exposed or queryable.
        assert_eq!(anchor.h_ref, 7);
        assert_eq!(anchor.settled_view.len(), 7);
        let (_bytes, tip_id) = serialize_header(&headers[9]).unwrap();
        assert_eq!(
            anchor.settled_view.height_of(tip_id.as_bytes()),
            None,
            "the proof tip (height 10) must NOT be in the settled view"
        );
        let (_bytes, h7_id) = serialize_header(&headers[6]).unwrap();
        assert_eq!(anchor.settled_view.height_of(h7_id.as_bytes()), Some(7));
    }

    #[test]
    fn comparative_sparse_settled_prefix_accepts() {
        // An honest NiPoPoW prefix is SPARSE: only superblock heights
        // survive below h_ref. Membership must accept sparse subsets —
        // including a prefix that stops well short of h_ref (the case
        // a dense-vs-sparse score comparison would wrongly reject).
        let headers = real_headers();
        let follower = followed(&headers);
        let view = follower.settled_view(7).expect("caught up");
        let sparse: Vec<Header> = [0usize, 2, 4, 6] // heights 1, 3, 5, 7
            .iter()
            .map(|&i| headers[i].clone())
            .collect();
        assert!(check_comparative_objectivity(&sparse, &view).is_ok());
        let short_prefix: Vec<Header> = headers[..4].to_vec(); // 1..=4 only
        assert!(check_comparative_objectivity(&short_prefix, &view).is_ok());
    }

    #[test]
    fn comparative_tampered_settled_header_rejects_as_divergent() {
        // A valid-but-weaker fork's first settled off-chain header must
        // reject. Tampering a real header (timestamp) changes its id →
        // not on the followed chain at height 5.
        let headers = real_headers();
        let follower = followed(&headers);
        let view = follower.settled_view(7).expect("caught up");
        let mut chain: Vec<Header> = headers[..4].to_vec();
        let mut forged = headers[4].clone();
        forged.timestamp += 1;
        chain.push(forged);
        assert!(matches!(
            check_comparative_objectivity(&chain, &view),
            Err(PegMintError::DivergesFromFollowedChain { height: 5 })
        ));
    }

    #[test]
    fn comparative_no_settled_overlap_rejects_as_no_common_ancestor() {
        // Follower rooted at height 2 (checkpoint-style root): a proof
        // whose settled portion is entirely below the root cannot be
        // corroborated at all → not comparable.
        let headers = real_headers();
        let follower = followed(&headers[1..]); // root = height 2
        let view = follower.settled_view(7).expect("caught up");
        let below_root: Vec<Header> = headers[..1].to_vec(); // height 1 only
        assert!(matches!(
            check_comparative_objectivity(&below_root, &view),
            Err(PegMintError::NoCommonAncestor)
        ));
    }

    #[test]
    fn comparative_policy_not_caught_up_rejects() {
        let headers = real_headers();
        let follower = followed(&headers[..5]); // tip 5 < h_ref 7
        assert!(matches!(
            comparative_policy(&headers, 3, &follower),
            Err(PegMintError::NotCaughtUp { h_ref: 7 })
        ));
    }

    #[test]
    fn comparative_policy_tip_shallower_than_n_mint_rejects() {
        let headers = real_headers();
        let follower = followed(&headers);
        assert!(matches!(
            comparative_policy(&headers[..2], 10, &follower),
            Err(PegMintError::InsufficientDepth { got: 2, need: 10 })
        ));
    }
}
