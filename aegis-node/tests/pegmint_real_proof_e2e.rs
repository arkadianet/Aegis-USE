//! Peg-in objectivity engine e2e against a COMPLETE real NiPoPoW proof
//! — closes the DEFERRED "no full-proof e2e vector exercises `is_valid`
//! + policy end-to-end" row of `g25-pegmint-packaging.md`.
//!
//! ## Vectors (all VERBATIM node output, nothing hand-edited)
//!
//! - `test-vectors/testnet/nipopow/proof_m6_k10.json` — the full
//!   `GET /nipopow/proof/6/10` response from the Scala testnet node
//!   (`arks-testnet-node` 6.0.3, `127.0.0.1:9062`), captured
//!   2026-07-13. Proof shape: 171-entry prefix (heights 1..=442813),
//!   `suffixHead` at 442816, 9-header `suffixTail` 442817..=442825
//!   (tip 442825), `continuous = true` — the route always serves
//!   continuous proofs (`NipopowApiRoute.scala:69-90` passes
//!   `continuous = true` unconditionally), which is exactly the form
//!   [`aegis_node::pegmint::verify_ergo_chain`] requires. The Rust
//!   node's response (`ergo-rust-testnet-0.5.1`, `:9052`, same tip)
//!   was captured as a cross-check and is semantically identical
//!   except one derived JSON field: the genesis header's `size`
//!   (Scala 284 vs Rust 283; the decoder ignores `size` and
//!   recomputes ids from bytes, so the divergence cannot affect this
//!   suite — tracked as a REST-parity nit, not consensus).
//! - `test-vectors/testnet/nipopow/scala_headers_442813_442815.json`
//!   — `GET /blocks/chainSlice?fromHeight=442812&toHeight=442815`
//!   from the same Scala node, same capture: the dense 3-header run
//!   from the proof's last prefix superblock (442813) up to
//!   `H_ref = tip − N_mint = 442815`, feeding the comparative-path
//!   follower.
//!
//! Anti-fabrication oracle: every header id is
//! `blake2b256(serialize_header(...))` and every non-genesis header
//! must satisfy its own Autolykos equation, so the vectors cannot be
//! forged or drift silently — `is_valid` / `Follower::apply_header`
//! re-derive everything from raw bytes.

use aegis_node::ergo_follow::Follower;
use aegis_node::pegmint::{
    ergo_testnet_anchor, verify_ergo_chain, verify_ergo_chain_comparative, DifficultyParams,
    PegMintError,
};
use ergo_rest_json::types::ScalaHeader;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::popow_proof::NipopowProof;
use ergo_validation::popow::proof::NipopowProofExt;

// ----- helpers -----

/// The captured proof's tip (last suffix-tail header) height/id, as
/// served by the node — pinned so a silently re-captured vector fails
/// loudly instead of shifting every assertion.
const TIP_HEIGHT: u32 = 442_825;
const TIP_ID: &str = "161f82e20d2d18b29c63fa4c3d9b91189155361f9b2c63fdec80b10ef559ebea";
/// Last prefix superblock — root of the comparative follower run.
const PREFIX_TIP_HEIGHT: u32 = 442_813;
/// `H_ref = TIP_HEIGHT − N_MINT` for the comparative path.
const N_MINT: u64 = 10;
const H_REF: u32 = 442_815;

fn vector_path(name: &str) -> String {
    format!(
        "{}/../test-vectors/testnet/nipopow/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn real_proof() -> NipopowProof {
    let path = vector_path("proof_m6_k10.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    ergo_rest_json::decode_nipopow_proof_json(&raw).expect("captured Scala proof JSON decodes")
}

/// The dense follower run 442813..=442815, decoded from the verbatim
/// chainSlice capture.
fn dense_run() -> Vec<Header> {
    let path = vector_path("scala_headers_442813_442815.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let dtos: Vec<ScalaHeader> = serde_json::from_str(&raw).expect("chainSlice array parses");
    dtos.iter()
        .map(|dto| {
            ergo_rest_json::decode_scala_header_struct(dto).expect("captured header decodes")
        })
        .collect()
}

fn id_of(h: &Header) -> [u8; 32] {
    let (_bytes, id) = serialize_header(h).expect("real header serializes");
    *id.as_bytes()
}

// ----- oracle parity -----

/// A REAL, complete proof from the REAL node must pass the reused
/// verifier stack. Each `is_valid` sub-check is asserted individually
/// so a failure names the diverging predicate, not just "invalid".
#[test]
fn real_testnet_proof_passes_every_is_valid_subcheck() {
    let proof = real_proof();
    let diff = DifficultyParams::testnet();
    assert_eq!((proof.m, proof.k), (6, 10));
    assert!(
        proof.continuous,
        "route serves continuous proofs (NipopowApiRoute passes continuous = true)"
    );
    assert!(proof.all_headers_serializable(), "serializability pre-gate");
    assert!(proof.has_valid_heights(), "strictly increasing heights");
    assert!(
        proof.has_valid_connections(&diff),
        "interlink/parent connectivity"
    );
    assert!(
        proof.has_valid_proofs(),
        "interlinks batch Merkle proofs vs extension roots"
    );
    assert!(
        proof.has_valid_difficulty_headers(&diff),
        "continuous-proof difficulty-recalculation headers present"
    );
    assert!(proof.has_valid_per_header_pow(), "Autolykos PoW per header");
    assert!(proof.is_valid(&diff));
}

/// The proof's shape must match what was live at capture time — the
/// tip pins the vector, and the chain must start at the pinned
/// testnet anchor (genesis 5b1827ca…, height 1).
#[test]
fn real_testnet_proof_shape_matches_capture() {
    let proof = real_proof();
    let chain = proof.headers_chain();
    let genesis = chain.first().expect("non-empty");
    let tip = chain.last().expect("non-empty");
    assert_eq!(genesis.height, 1);
    assert_eq!(id_of(genesis), ergo_testnet_anchor().header_id);
    assert_eq!(tip.height, TIP_HEIGHT);
    assert_eq!(hex::encode(id_of(tip)), TIP_ID);
    assert_eq!(
        proof.prefix.last().expect("non-empty prefix").header.height,
        PREFIX_TIP_HEIGHT
    );
}

// ----- static-floor path (§2b.ii bootstrap fallback) -----

/// Full-proof e2e through the static-floor entry point: the real
/// proof must verify, anchor to the pinned testnet genesis, clear
/// `N_mint = 10` depth (tip is ~442k deep), and clear the placeholder
/// work floor. This is the DEFERRED "complete real `is_valid`-passing
/// proof through `verify_ergo_chain`" row.
#[test]
fn verify_ergo_chain_accepts_real_testnet_proof() {
    let proof = real_proof();
    let tip = verify_ergo_chain(
        &proof,
        &ergo_testnet_anchor(),
        &DifficultyParams::testnet(),
        N_MINT,
    )
    .expect("real proof against the pinned testnet anchor accepts");
    assert_eq!(tip.tip_height, TIP_HEIGHT);
    assert_eq!(hex::encode(tip.tip_id), TIP_ID);
    assert!(
        tip.suffix_work > num_bigint::BigUint::from(0u32),
        "k-suffix must carry positive cumulative work"
    );
}

// ----- error paths -----

/// Tampering one field of one suffix header (timestamp of the tip)
/// invalidates its PoW/id, so `is_valid` must go false and the engine
/// must reject with `InvalidChain`.
#[test]
fn tampered_suffix_header_rejected_as_invalid_chain() {
    let mut proof = real_proof();
    proof
        .suffix_tail
        .last_mut()
        .expect("non-empty suffix tail")
        .timestamp += 1;
    let diff = DifficultyParams::testnet();
    assert!(!proof.is_valid(&diff), "tampered proof must fail is_valid");
    assert!(matches!(
        verify_ergo_chain(&proof, &ergo_testnet_anchor(), &diff, N_MINT),
        Err(PegMintError::InvalidChain)
    ));
}

// ----- comparative path (§2b canonical policy) -----

/// End-to-end §2b: a follower checkpoint-rooted at the proof's last
/// prefix superblock (442813) and fed the real dense run up to
/// `H_ref = 442815` corroborates the proof's settled portion, so
/// `verify_ergo_chain_comparative` accepts and returns the settled
/// region only (P1-A contract: the proof tip is NOT in the view).
#[test]
fn verify_ergo_chain_comparative_accepts_with_real_dense_follower() {
    let proof = real_proof();
    let headers = dense_run();
    assert_eq!(
        headers.iter().map(|h| h.height).collect::<Vec<_>>(),
        vec![442_813, 442_814, 442_815],
        "dense run covers [prefix superblock ..= H_ref]"
    );
    // Bind the two independent captures together: the follower root
    // must BE the proof's last prefix superblock header.
    let root_id = id_of(&proof.prefix.last().expect("non-empty prefix").header);
    assert_eq!(root_id, id_of(&headers[0]));

    let mut follower = Follower::with_root(N_MINT, root_id);
    for h in &headers {
        follower
            .apply_header(h)
            .expect("real testnet header follows");
    }
    assert_eq!(follower.tip_height(), Some(H_REF));

    let anchor = verify_ergo_chain_comparative(
        &proof,
        &ergo_testnet_anchor(),
        &DifficultyParams::testnet(),
        N_MINT,
        &follower,
    )
    .expect("settled prefix lies on the followed chain");
    assert_eq!(anchor.h_ref, H_REF);
    assert_eq!(anchor.settled_view.len(), headers.len());
    // The corroborated superblock is in the settled view…
    assert_eq!(
        anchor.settled_view.height_of(&root_id),
        Some(PREFIX_TIP_HEIGHT)
    );
    // …and the P1-A contract holds: the proof's (attacker-choosable)
    // tip is NOT part of the objectified settled region.
    let tip_id = id_of(proof.suffix_tail.last().expect("non-empty suffix tail"));
    assert_eq!(hex::encode(tip_id), TIP_ID);
    assert_eq!(anchor.settled_view.height_of(&tip_id), None);
}

/// The deferral contract (P1-B): with the follower short of `H_ref`
/// the comparative path must return `NotCaughtUp` — a "wait and
/// re-evaluate" signal — never a block-invalid verdict.
#[test]
fn verify_ergo_chain_comparative_not_caught_up_defers() {
    let proof = real_proof();
    let headers = dense_run();
    let root_id = id_of(&headers[0]);
    let mut follower = Follower::with_root(N_MINT, root_id);
    for h in &headers[..2] {
        follower
            .apply_header(h)
            .expect("real testnet header follows");
    }
    assert!(matches!(
        verify_ergo_chain_comparative(
            &proof,
            &ergo_testnet_anchor(),
            &DifficultyParams::testnet(),
            N_MINT,
            &follower,
        ),
        Err(PegMintError::NotCaughtUp { h_ref: H_REF })
    ));
}
