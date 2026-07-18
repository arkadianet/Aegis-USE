//! PegVault predicate — local adversarial suite against the ergo-sigma
//! evaluator (the SAME code the devnet runs at spend time).
//!
//! Two tiers (crate features):
//! - DEFAULT (stub verifier): a well-formed `verifyStark` reduces to `true`
//!   (M1 stub), so every outcome below isolates the TX-BINDING checks — the
//!   EIP-0045 footgun surface. Happy path TRUE; every tampering FALSE.
//! - `--features real-verify`: REAL RISC0 verification of the pinned oracle
//!   receipt through the exact release shape (proof chunked into
//!   context-extension var 0), with the FULL vault predicate. The oracle
//!   journal (67 bytes) is split across a fabricated tx context — tag,
//!   vault.R4, successor.R4, recipient token amount, counter+1, recipient
//!   propositionBytes — so the journal the CONTRACT reconstructs from the tx
//!   equals `journal.bin` byte-for-byte. The receipt verifying TRUE through
//!   that path is the oracle proof that the contract's journal derivation is
//!   byte-exact; each single tampering then flips it FALSE.

#[cfg(not(feature = "real-verify"))]
use bridge_tools::vault::journal_bytes;
use bridge_tools::vault::{chunk_proof, vault_body, vault_tree_bytes, VaultSpec, JOURNAL_TAG};
use ergo_ser::register::RegisterValue;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};
use ergo_sigma::evaluator::{reduce_expr, EvalBox, ReductionContext};

// ----- helpers -----

const NFT: [u8; 32] = [0xA0; 32];
const USE: [u8; 32] = [0x05; 32];
const IMG: [u8; 32] = [0x1D; 32];

fn spec() -> VaultSpec {
    VaultSpec {
        nft_id: NFT,
        use_id: USE,
        image_id: IMG,
        tag: JOURNAL_TAG,
    }
}

fn coll_byte_reg(bytes: &[u8]) -> RegisterValue {
    RegisterValue {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        value: SigmaValue::Coll(CollValue::Bytes(bytes.to_vec())),
    }
}
fn long_reg(v: i64) -> RegisterValue {
    RegisterValue {
        tpe: SigmaType::SLong,
        value: SigmaValue::Long(v),
    }
}

fn mk_box(
    script: Vec<u8>,
    tokens: Vec<([u8; 32], u64)>,
    r4: Option<RegisterValue>,
    r5: Option<RegisterValue>,
) -> EvalBox {
    let mut b = EvalBox::simple(1, script);
    b.value = 1_000_000_000;
    b.tokens = tokens;
    b.registers[0] = r4;
    b.registers[1] = r5;
    b
}

/// A release-tx shape. Roots are variable-length on purpose: the contract
/// binds R4 as raw `Coll[Byte]` (whatever length the guest committed), which
/// lets the real-verify tier split the fixed oracle journal across them.
struct Scenario {
    vault_script: Vec<u8>,
    prev_root: Vec<u8>,
    new_root: Vec<u8>,
    counter: i64,
    amount: u64,
    recipient_script: Vec<u8>,
    use_in_vault: u64,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            vault_script: vault_tree_bytes(&spec()),
            prev_root: vec![0xAA; 32],
            new_root: vec![0xBB; 32],
            counter: 7,
            amount: 990,
            recipient_script: vec![0x00, 0x08, 0xCD, 0x02, 0x79],
            use_in_vault: 1_000_000,
        }
    }
}

/// Build the release tx context for a scenario and reduce the FULL predicate.
fn run_with(
    spec: &VaultSpec,
    s: &Scenario,
    proof: &[u8],
    mutate: impl FnOnce(&mut Vec<EvalBox>),
) -> bool {
    let vault_in = mk_box(
        s.vault_script.clone(),
        vec![(NFT, 1), (USE, s.use_in_vault)],
        Some(coll_byte_reg(&s.prev_root)),
        Some(long_reg(s.counter)),
    );
    let successor = mk_box(
        s.vault_script.clone(),
        vec![(NFT, 1), (USE, s.use_in_vault.saturating_sub(s.amount))],
        Some(coll_byte_reg(&s.new_root)),
        Some(long_reg(s.counter + 1)),
    );
    let recipient = mk_box(
        s.recipient_script.clone(),
        vec![(USE, s.amount)],
        None,
        None,
    );
    let fee = mk_box(vec![0x01], vec![], None, None);

    let mut outputs = vec![successor, recipient, fee];
    mutate(&mut outputs);
    let inputs = vec![vault_in];

    let mut ctx = ReductionContext::minimal(500_000, 1);
    ctx.inputs = &inputs;
    ctx.outputs = &outputs;
    ctx.self_box = Some(&inputs[0]);
    let (tpe, val) = chunk_proof(proof);
    ctx.extension.insert(0u8, (tpe, val));

    match reduce_expr(&vault_body(spec), &ctx, &[]) {
        Ok(SigmaBoolean::TrivialProp(b)) => b,
        Ok(other) => panic!("unexpected sigma reduction: {other:?}"),
        Err(_) => false, // an eval error can never authorize a spend
    }
}

#[cfg(not(feature = "real-verify"))]
fn run(s: &Scenario, proof: &[u8], mutate: impl FnOnce(&mut Vec<EvalBox>)) -> bool {
    run_with(&spec(), s, proof, mutate)
}

// =====================================================================
// Tier 1 (default features): STUB verifier — a well-formed verifyStark is
// `true`, so these outcomes isolate the TX-BINDING checks.
// =====================================================================

#[cfg(not(feature = "real-verify"))]
mod binding {
    use super::*;

    // ----- happy path -----

    #[test]
    fn wellformed_release_is_accepted() {
        assert!(run(&Scenario::default(), b"stub-proof", |_| {}));
    }

    // ----- error paths (each single tampering flips the predicate) -----

    #[test]
    fn amount_binding_is_journal_carried_not_structural() {
        // Deliberate design pin: the recipient amount has NO structural check —
        // it is bound solely through the reconstructed journal, which only the
        // REAL verifier enforces (see real_verify::wrong_amount_rejected and
        // devnet adversarial (a)). Under the stub the tampering must therefore
        // still evaluate TRUE; if this ever flips, a structural amount check
        // was added and the journal layout docs need updating.
        let s = Scenario::default();
        assert!(run(&s, b"p", |outs| {
            outs[1].tokens[0].1 += 1;
        }));
    }

    #[test]
    fn successor_missing_nft_rejected() {
        let s = Scenario::default();
        assert!(!run(&s, b"p", |outs| {
            outs[0].tokens.remove(0);
        }));
    }

    #[test]
    fn successor_script_swap_rejected() {
        let s = Scenario::default();
        assert!(!run(&s, b"p", |outs| {
            outs[0].script_bytes = vec![0xDE, 0xAD];
        }));
    }

    #[test]
    fn counter_not_incremented_rejected() {
        let s = Scenario::default();
        assert!(!run(&s, b"p", |outs| {
            outs[0].registers[1] = Some(long_reg(s.counter)); // stale counter
        }));
    }

    #[test]
    fn extra_output_rejected() {
        let s = Scenario::default();
        assert!(!run(&s, b"p", |outs| {
            outs.push(mk_box(vec![0x01], vec![], None, None));
        }));
    }

    #[test]
    fn fee_output_with_tokens_rejected() {
        // Sneaking USE into the fee slot would break conservation accounting.
        let s = Scenario::default();
        assert!(!run(&s, b"p", |outs| {
            outs[2].tokens = vec![(USE, 5)];
        }));
    }

    #[test]
    fn wrong_use_token_to_recipient_rejected() {
        let s = Scenario::default();
        assert!(!run(&s, b"p", |outs| {
            outs[1].tokens[0].0 = [0x77; 32]; // not the USE id
        }));
    }

    #[test]
    fn missing_proof_var_rejected() {
        // No context-extension var 0 → OptionGet fails → eval error → reject.
        let s = Scenario::default();
        let vault_in = mk_box(
            s.vault_script.clone(),
            vec![(NFT, 1), (USE, s.use_in_vault)],
            Some(coll_byte_reg(&s.prev_root)),
            Some(long_reg(s.counter)),
        );
        let inputs = vec![vault_in];
        let outputs = vec![
            mk_box(
                s.vault_script.clone(),
                vec![(NFT, 1), (USE, s.use_in_vault - s.amount)],
                Some(coll_byte_reg(&s.new_root)),
                Some(long_reg(s.counter + 1)),
            ),
            mk_box(
                s.recipient_script.clone(),
                vec![(USE, s.amount)],
                None,
                None,
            ),
            mk_box(vec![0x01], vec![], None, None),
        ];
        let mut ctx = ReductionContext::minimal(500_000, 1);
        ctx.inputs = &inputs;
        ctx.outputs = &outputs;
        ctx.self_box = Some(&inputs[0]);
        assert!(reduce_expr(&vault_body(&spec()), &ctx, &[]).is_err());
    }

    #[test]
    fn journal_reconstruction_matches_reference_layout() {
        // The contract-side journal expression and the host-side
        // `journal_bytes` (what the settlement guest commits) must agree.
        let s = Scenario::default();
        let expected = journal_bytes(
            &JOURNAL_TAG,
            &s.prev_root.clone().try_into().unwrap(),
            &s.new_root.clone().try_into().unwrap(),
            s.amount as i64,
            s.counter + 1,
            &s.recipient_script,
        );
        assert_eq!(expected.len(), 88 + s.recipient_script.len());
        // (Byte-level equality of the EXPR against this layout is exercised
        // by the real-verify tier below and the devnet e2e.)
    }
}

// =====================================================================
// Tier 2 (--features real-verify): REAL RISC0 verification of the pinned
// oracle receipt through the FULL predicate. The 67-byte oracle journal is
// split across a fabricated tx context so the contract-reconstructed journal
// equals journal.bin exactly:
//
//   [0..8)   tag                (VaultSpec.tag)
//   [8..24)  vault.R4           (prev "root" — raw Coll[Byte], length-free)
//   [24..40) successor.R4       (new "root")
//   [40..48) rec.tokens(0)._2   (big-endian i64 — positive by inspection)
//   [48..56) vault.R5 + 1       (big-endian i64 — positive by inspection)
//   [56..67) rec.propositionBytes
// =====================================================================

#[cfg(feature = "real-verify")]
mod real_verify {
    use super::*;

    const PROOF: &[u8] =
        include_bytes!("../../../../../ergo/ergo-sigma/test-vectors/stark/proof_inner.bin");
    const JOURNAL: &[u8] =
        include_bytes!("../../../../../ergo/ergo-sigma/test-vectors/stark/journal.bin");
    const IMAGE_ID: &[u8] =
        include_bytes!("../../../../../ergo/ergo-sigma/test-vectors/stark/image_id.bin");

    /// The vault spec + scenario whose tx-derived journal == `journal.bin`.
    fn oracle_scenario() -> (VaultSpec, Scenario) {
        assert_eq!(JOURNAL.len(), 67, "oracle journal layout drifted");
        let tag: [u8; 8] = JOURNAL[0..8].try_into().unwrap();
        let prev_root = JOURNAL[8..24].to_vec();
        let new_root = JOURNAL[24..40].to_vec();
        let amount = u64::from_be_bytes(JOURNAL[40..48].try_into().unwrap());
        let epoch = i64::from_be_bytes(JOURNAL[48..56].try_into().unwrap());
        let recipient_script = JOURNAL[56..].to_vec();
        assert!(amount <= i64::MAX as u64, "amount window must be positive");
        assert!(epoch > i64::MIN, "epoch window must not underflow");

        // Sanity: reassembling the split IS the oracle journal, byte-exact.
        let mut reassembled = tag.to_vec();
        reassembled.extend_from_slice(&prev_root);
        reassembled.extend_from_slice(&new_root);
        reassembled.extend_from_slice(&amount.to_be_bytes());
        reassembled.extend_from_slice(&epoch.to_be_bytes());
        reassembled.extend_from_slice(&recipient_script);
        assert_eq!(reassembled, JOURNAL);

        let spec = VaultSpec {
            nft_id: NFT,
            use_id: USE,
            image_id: IMAGE_ID.try_into().expect("32-byte image id"),
            tag,
        };
        let s = Scenario {
            vault_script: vault_tree_bytes(&spec),
            prev_root,
            new_root,
            counter: epoch - 1,
            amount,
            recipient_script,
            use_in_vault: amount,
        };
        (spec, s)
    }

    // ----- happy path -----

    #[test]
    fn real_receipt_through_full_predicate_verifies() {
        // ORACLE: the receipt only verifies against journal.bin, so TRUE here
        // proves the contract's tx-derived journal is byte-exact.
        let (spec, s) = oracle_scenario();
        assert!(run_with(&spec, &s, PROOF, |_| {}));
    }

    // ----- error paths (each single tampering flips the predicate) -----

    #[test]
    fn wrong_amount_rejected() {
        let (spec, s) = oracle_scenario();
        assert!(!run_with(&spec, &s, PROOF, |outs| {
            outs[1].tokens[0].1 += 1; // journal amount window changes
        }));
    }

    #[test]
    fn wrong_recipient_rejected() {
        let (spec, s) = oracle_scenario();
        assert!(!run_with(&spec, &s, PROOF, |outs| {
            outs[1].script_bytes[0] ^= 0xFF; // journal recipient tail changes
        }));
    }

    #[test]
    fn wrong_new_root_rejected() {
        let (spec, s) = oracle_scenario();
        let mut bad = s.new_root.clone();
        bad[0] ^= 0xFF;
        assert!(!run_with(&spec, &s, PROOF, move |outs| {
            outs[0].registers[0] = Some(coll_byte_reg(&bad));
        }));
    }

    #[test]
    fn counter_not_incremented_rejected() {
        let (spec, s) = oracle_scenario();
        let stale = s.counter;
        assert!(!run_with(&spec, &s, PROOF, move |outs| {
            outs[0].registers[1] = Some(long_reg(stale)); // successor R5 stale
        }));
    }

    #[test]
    fn successor_missing_nft_rejected() {
        let (spec, s) = oracle_scenario();
        assert!(!run_with(&spec, &s, PROOF, |outs| {
            outs[0].tokens.remove(0);
        }));
    }

    #[test]
    fn tampered_proof_chunk_rejected() {
        let (spec, s) = oracle_scenario();
        let mut bad = PROOF.to_vec();
        let mid = bad.len() / 2;
        bad[mid] ^= 0xFF;
        assert!(!run_with(&spec, &s, &bad, |_| {}));
    }

    #[test]
    fn wrong_image_id_rejected() {
        // Same context, same proof, vault pinned to a different guest.
        let (mut spec, mut s) = oracle_scenario();
        spec.image_id[0] ^= 0xFF;
        s.vault_script = vault_tree_bytes(&spec);
        assert!(!run_with(&spec, &s, PROOF, |_| {}));
    }
}
