//! The DEFERRED GATE, closed: `verifyStark` returns TRUE for a REAL AEGISPV1
//! epoch-validity receipt through the v6 PegVault epoch predicate
//! (`vault_epoch`), evaluated by the real ergo-sigma interpreter (the oracle
//! tier the devnet runs at spend time).
//!
//! `tests/epoch_vault_predicate.rs::real_verify` could only exercise the REJECT
//! half (a 67-byte single-withdrawal receipt vs a >=240-byte AEGISPV1
//! reconstruction). This test consumes a real epoch receipt (GPU-proved by
//! `settlement/exec-epoch prove`, from the `aegis-recursion/tests/dump_epoch.rs`
//! honest 11-block / 2-withdrawal epoch) and drives the whole loop:
//!
//!   1. reconstruct the AEGISPV1 journal from the release tx (R4/R6/R7 endpoints
//!      + the CONTEXT.headers anchor splice + recipient entries) and assert it is
//!      BYTE-EXACT the receipt's committed journal — the anchor/register binding;
//!   2. run the FULL vault predicate with the real receipt in the context
//!      extension and `spec.image_id` = the pinned epoch guest id => TRUE
//!      (verifyStark verifies the receipt under the image id AND matches the
//!      reconstructed journal). THIS is the gate the vault agent deferred.
//!   3. a TAMPERED receipt (flipped byte) and a MISMATCHED journal (bumped
//!      recipient amount) both => FALSE.
//!
//! Runs only with `--features real-verify` AND `AEGIS_EPOCH_RECEIPT_DIR` set to
//! the `prove` out-dir (receipt_inner.bin / journal.bin / image_id.bin);
//! otherwise it skips (no vendored multi-MB epoch receipt in-tree).

#![cfg(feature = "real-verify")]

use bridge_tools::vault_epoch::{
    chunk_proof, journal_expr, pinned_epoch_image_id, vault_body, vault_tree_bytes, VaultSpec,
    ANCHOR_HEADER_INDEX, JOURNAL_TAG,
};
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::register::RegisterValue;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};
use ergo_sigma::evaluator::{reduce_expr, EvalBox, EvalHeader, ReductionContext};

// ----- fixtures -----

const NFT: [u8; 32] = [0xA0; 32];
const USE: [u8; 32] = [0x05; 32];

/// The parsed fixed-layout AEGISPV1 journal (`epoch_journal`, §2.2):
/// tag(8) ‖ prev(32) ‖ new(32) ‖ settled_in(32) ‖ settled_out(32) ‖
/// tip_prev(32) ‖ tip_new(32) ‖ ergo_ref(32) ‖ counter_next_be(8) ‖ entries.
struct Journal {
    prev_root: [u8; 32],
    new_root: [u8; 32],
    settled_in: [u8; 32],
    settled_out: [u8; 32],
    tip_prev: [u8; 32],
    tip_new: [u8; 32],
    ergo_ref: [u8; 32],
    counter_next: u64,
    withdrawals: Vec<(u64, Vec<u8>)>, // (amount, recipient_prop) in journal order
}

fn take32(j: &[u8], off: usize) -> [u8; 32] {
    j[off..off + 32].try_into().unwrap()
}

impl Journal {
    fn parse(j: &[u8]) -> Self {
        assert_eq!(&j[0..8], &JOURNAL_TAG, "AEGISPV1 tag");
        assert!(j.len() >= 240, "journal shorter than fixed prefix");
        let counter_next = u64::from_be_bytes(j[232..240].try_into().unwrap());
        let mut withdrawals = Vec::new();
        let mut p = 240;
        while p < j.len() {
            let amount = u64::from_be_bytes(j[p..p + 8].try_into().unwrap());
            let plen = u64::from_be_bytes(j[p + 8..p + 16].try_into().unwrap()) as usize;
            let prop = j[p + 16..p + 16 + plen].to_vec();
            withdrawals.push((amount, prop));
            p += 16 + plen;
        }
        assert_eq!(p, j.len(), "entries consumed the whole journal");
        Self {
            prev_root: take32(j, 8),
            new_root: take32(j, 40),
            settled_in: take32(j, 72),
            settled_out: take32(j, 104),
            tip_prev: take32(j, 136),
            tip_new: take32(j, 168),
            ergo_ref: take32(j, 200),
            counter_next,
            withdrawals,
        }
    }

    fn n(&self) -> usize {
        self.withdrawals.len()
    }
    fn total_out(&self) -> u64 {
        self.withdrawals.iter().map(|(a, _)| a).sum()
    }
    fn counter_prev(&self) -> i64 {
        self.counter_next as i64 - self.n() as i64
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
    regs: [Option<RegisterValue>; 4],
) -> EvalBox {
    let mut b = EvalBox::simple(1, script);
    b.value = 1_000_000_000;
    b.tokens = tokens;
    let [r4, r5, r6, r7] = regs;
    b.registers[0] = r4;
    b.registers[1] = r5;
    b.registers[2] = r6;
    b.registers[3] = r7;
    b
}

fn header_with_id(id: [u8; 32]) -> EvalHeader {
    EvalHeader {
        id,
        version: 2,
        parent_id: [0; 32],
        ad_proofs_root: [0; 32],
        state_root: [0; 33],
        transactions_root: [0; 32],
        timestamp: 0,
        n_bits: 0x0100_0000,
        height: 1,
        extension_root: [0; 32],
        miner_pk: [0x02; 33],
        pow_onetime_pk: [0x03; 33],
        pow_nonce: [0; 8],
        pow_distance: num_bigint::BigInt::from(0),
        votes: [0, 0, 0],
        unparsed_bytes: Vec::new(),
    }
}

/// A recent-header window with `anchor` at the pinned slot.
fn window(anchor: [u8; 32]) -> Vec<EvalHeader> {
    let mut w = vec![header_with_id([0x01; 32]); 3];
    w[ANCHOR_HEADER_INDEX as usize] = header_with_id(anchor);
    w
}

fn spec() -> VaultSpec {
    VaultSpec {
        nft_id: NFT,
        use_id: USE,
        image_id: pinned_epoch_image_id(),
        tag: JOURNAL_TAG,
    }
}

fn vault_in(j: &Journal, script: &[u8]) -> EvalBox {
    mk_box(
        script.to_vec(),
        vec![(NFT, 1), (USE, j.total_out() + 1_000_000)],
        [
            Some(coll_byte_reg(&j.prev_root)),
            Some(long_reg(j.counter_prev())),
            Some(coll_byte_reg(&j.settled_in)),
            Some(coll_byte_reg(&j.tip_prev)),
        ],
    )
}

fn successor(j: &Journal, script: &[u8]) -> EvalBox {
    mk_box(
        script.to_vec(),
        vec![(NFT, 1), (USE, 1_000_000)],
        [
            Some(coll_byte_reg(&j.new_root)),
            Some(long_reg(j.counter_next as i64)),
            Some(coll_byte_reg(&j.settled_out)),
            Some(coll_byte_reg(&j.tip_new)),
        ],
    )
}

/// `[successor, rec_1..rec_n, fee]` — the release-tx outputs.
fn outputs_of(j: &Journal, spec: &VaultSpec) -> Vec<EvalBox> {
    let script = vault_tree_bytes(spec);
    let mut outs = vec![successor(j, &script)];
    for (amount, prop) in &j.withdrawals {
        outs.push(mk_box(
            prop.clone(),
            vec![(USE, *amount)],
            [None, None, None, None],
        ));
    }
    outs.push(mk_box(vec![0x01], vec![], [None, None, None, None])); // fee box
    outs
}

/// Reduce the FULL vault predicate with the real receipt in the extension var
/// and a header window whose anchor slot = the journal's ergo_ref.
fn run_full(
    j: &Journal,
    spec: &VaultSpec,
    proof: &[u8],
    mutate: impl FnOnce(&mut Vec<EvalBox>),
) -> bool {
    let script = vault_tree_bytes(spec);
    let inputs = vec![vault_in(j, &script)];
    let mut outputs = outputs_of(j, spec);
    mutate(&mut outputs);
    let headers = window(j.ergo_ref);

    let mut ctx = ReductionContext::minimal(20_000_000, 1);
    ctx.inputs = &inputs;
    ctx.outputs = &outputs;
    ctx.self_box = Some(&inputs[0]);
    ctx.last_headers = &headers;
    let (tpe, val) = chunk_proof(proof);
    ctx.extension.insert(0u8, (tpe, val));

    match reduce_expr(&vault_body(spec), &ctx, &[]) {
        Ok(SigmaBoolean::TrivialProp(b)) => b,
        Ok(_) => panic!("unexpected non-trivial sigma reduction"),
        Err(_) => false,
    }
}

fn load() -> Option<(Journal, Vec<u8>, [u8; 32])> {
    let dir = std::env::var("AEGIS_EPOCH_RECEIPT_DIR").ok()?;
    let dir = std::path::Path::new(&dir);
    let journal_bytes = std::fs::read(dir.join("journal.bin")).expect("journal.bin");
    let proof = std::fs::read(dir.join("receipt_inner.bin")).expect("receipt_inner.bin");
    let img: [u8; 32] = std::fs::read(dir.join("image_id.bin"))
        .expect("image_id.bin")
        .try_into()
        .expect("image_id is 32 bytes");
    Some((Journal::parse(&journal_bytes), proof, img))
}

fn c_bytes(b: &[u8]) -> Expr {
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        val: SigmaValue::Coll(CollValue::Bytes(b.to_vec())),
    }
}
fn eq(a: Expr, b: Expr) -> Expr {
    Expr::Op(IrNode {
        opcode: 0x93,
        payload: Payload::Two(Box::new(a), Box::new(b)),
    })
}

// ----- happy path: the deferred gate -----

#[test]
fn real_epoch_receipt_reconstructs_and_verifies_true() {
    let Some((j, proof, img)) = load() else {
        eprintln!("AEGIS_EPOCH_RECEIPT_DIR unset — skipping real-receipt gate");
        return;
    };
    // The pinned vault image id MUST equal the receipt's image id, else no real
    // receipt could ever release (image-id / journal drift = the STOP condition).
    assert_eq!(
        img,
        pinned_epoch_image_id(),
        "receipt image_id.bin != settlement/EPOCH_IMAGE_ID.hex (re-pin needed)"
    );
    let s = spec();
    let journal_bytes = {
        // rebuild the exact committed bytes from the parsed struct for the probe
        let mut jb = Vec::new();
        jb.extend_from_slice(&JOURNAL_TAG);
        jb.extend_from_slice(&j.prev_root);
        jb.extend_from_slice(&j.new_root);
        jb.extend_from_slice(&j.settled_in);
        jb.extend_from_slice(&j.settled_out);
        jb.extend_from_slice(&j.tip_prev);
        jb.extend_from_slice(&j.tip_new);
        jb.extend_from_slice(&j.ergo_ref);
        jb.extend_from_slice(&j.counter_next.to_be_bytes());
        for (a, p) in &j.withdrawals {
            jb.extend_from_slice(&a.to_be_bytes());
            jb.extend_from_slice(&(p.len() as u64).to_be_bytes());
            jb.extend_from_slice(p);
        }
        jb
    };

    // 1. reconstruction is byte-exact vs the committed journal (anchor splice +
    //    R4/R6/R7 endpoints + entries), via the real evaluator.
    {
        let script = vault_tree_bytes(&s);
        let inputs = vec![vault_in(&j, &script)];
        let outputs = outputs_of(&j, &s);
        let headers = window(j.ergo_ref);
        let mut ctx = ReductionContext::minimal(20_000_000, 1);
        ctx.inputs = &inputs;
        ctx.outputs = &outputs;
        ctx.self_box = Some(&inputs[0]);
        ctx.last_headers = &headers;
        let probe = eq(journal_expr(&s.tag), c_bytes(&journal_bytes));
        assert!(
            matches!(
                reduce_expr(&probe, &ctx, &[]),
                Ok(SigmaBoolean::TrivialProp(true))
            ),
            "reconstructed journal must be byte-exact the receipt's committed journal"
        );
    }

    // 2. THE DEFERRED GATE: full predicate + real receipt => verifyStark TRUE.
    assert!(
        run_full(&j, &s, &proof, |_| {}),
        "verifyStark must return TRUE for the real AEGISPV1 epoch receipt"
    );
}

// ----- error paths -----

#[test]
fn tampered_real_receipt_verifies_false() {
    let Some((j, mut proof, _img)) = load() else {
        eprintln!("AEGIS_EPOCH_RECEIPT_DIR unset — skipping");
        return;
    };
    // Flip a byte deep in the receipt (past any length prefix) — the RISC0
    // verify must fail => FALSE, never a spend.
    let mid = proof.len() / 2;
    proof[mid] ^= 0xFF;
    assert!(
        !run_full(&j, &spec(), &proof, |_| {}),
        "a tampered receipt must NOT verify"
    );
}

#[test]
fn mismatched_journal_amount_verifies_false() {
    let Some((j, proof, _img)) = load() else {
        eprintln!("AEGIS_EPOCH_RECEIPT_DIR unset — skipping");
        return;
    };
    // Bump a recipient's amount: the reconstructed journal no longer matches the
    // committed one => verifyStark's byte-exact journal check FALSE (with the
    // REAL, otherwise-valid receipt — isolates the journal binding).
    assert!(
        !run_full(&j, &spec(), &proof, |outs| {
            outs[1].tokens[0].1 += 1;
        }),
        "a journal-mismatched (amount-bumped) release must NOT verify"
    );
}
