//! Epoch-validity PegVault predicate (`vault_epoch`) — adversarial suite
//! against the ergo-sigma evaluator (the SAME code the devnet runs at spend
//! time), grown from `tests/vault_predicate.rs`.
//!
//! Three surfaces:
//!
//! - `reconstruct` (DEFAULT, the load-bearing one): runs the FULL journal
//!   reconstruction — including the E4 `CONTEXT.headers(ANCHOR).id` anchor
//!   splice — through the real evaluator and asserts it equals the engine's
//!   `AEGISPV1` journal (`aegis_engine::epoch::epoch_journal`) BYTE-EXACT.
//!   Every field tamper (a withdrawal, R4/R6/R7 endpoints, the anchor id, the
//!   counter, add/drop/reorder outputs, wrong anchor slot, empty window) flips
//!   it. This is the direct confirmation of the design's "verify the splice
//!   against the evaluator" crux (§E4): the evaluator CAN bind
//!   `CONTEXT.headers` into the journal the way it binds R4.
//!
//! - `binding` (DEFAULT, stub verifyStark): a well-formed `verifyStark` reduces
//!   to `true`, so these outcomes isolate the STRUCTURAL bindings (NFT
//!   singleton, counter advance, `MAX_BATCH` bounds, fee-box token-free,
//!   recipient USE-only). Journal-CONTENT bindings (amount, roots, anchor) are
//!   journal-carried — proven byte-exact by `reconstruct`, not structural.
//!
//! - `real_verify` (`--features real-verify`): confirms the epoch tree's
//!   `verifyStark` opcode PATH is wired and rejects a journal-mismatched
//!   receipt. A verifyStark-TRUE for a real `AEGISPV1` receipt needs a pinned
//!   ≥240-byte epoch receipt (the vk-pinning follow-up); no such vector exists
//!   yet, so the pinned 67-byte single-withdrawal receipt can only exercise the
//!   reject path here (its journal can never equal a ≥240-byte reconstruction).

use aegis_engine::epoch::{epoch_journal, EpochResult, Withdrawal};
use aegis_engine::poseidon::{digest_from_bytes, digest_to_bytes, Digest};
use bridge_tools::vault_epoch::{
    chunk_proof, journal_expr, vault_body, vault_tree_bytes, VaultSpec, ANCHOR_HEADER_INDEX,
    JOURNAL_TAG,
};
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::register::RegisterValue;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};
use ergo_sigma::evaluator::{reduce_expr, EvalBox, EvalHeader, ReductionContext};

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

/// A canonical BabyBear digest whose serialized bytes are stable (every 4th
/// byte zeroed keeps each u32 limb < the field order).
fn dg(seed: u8) -> Digest {
    let mut b = [0u8; 32];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = if i % 4 == 3 {
            0
        } else {
            seed.wrapping_add(i as u8)
        };
    }
    digest_from_bytes(&b).expect("canonical digest")
}

/// A raw 32-byte id (tip / anchor) — not a field digest, used verbatim.
fn id32(seed: u8) -> [u8; 32] {
    [seed; 32]
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

/// A box with the four chained registers R4..R7 (index 0..3).
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

/// A recent-header window with `id32(seed)` at slot 0 (the anchor slot) — the
/// evaluator returns `ctx.last_headers` verbatim for `CONTEXT.headers`.
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

/// One withdrawal: `amount` USE to `recipient_prop`.
#[derive(Clone)]
struct Wd {
    amount: u64,
    recipient_prop: Vec<u8>,
}

/// A full epoch-release shape. `prev/new/settled_*` are canonical digests;
/// `tip_*` / `ergo_ref` are raw 32-byte ids.
struct EpochScn {
    prev_root: Digest,
    new_root: Digest,
    settled_in: Digest,
    settled_out: Digest,
    tip_prev: [u8; 32],
    tip_new: [u8; 32],
    ergo_ref: [u8; 32],
    counter_prev: i64,
    withdrawals: Vec<Wd>,
    use_in_vault: u64,
}

impl EpochScn {
    fn default_with(n: usize) -> Self {
        let withdrawals = (0..n)
            .map(|i| Wd {
                amount: 100 + i as u64,
                // distinct, distinct-length recipient scripts
                recipient_prop: vec![0x00, 0x08, 0xCD, 0x02, 0x79 ^ i as u8, i as u8],
            })
            .collect();
        Self {
            prev_root: dg(0x11),
            new_root: dg(0x22),
            settled_in: dg(0x33),
            settled_out: dg(0x44),
            tip_prev: id32(0x55),
            tip_new: id32(0x66),
            ergo_ref: id32(0x77),
            counter_prev: 7,
            withdrawals,
            use_in_vault: 1_000_000,
        }
    }

    fn n(&self) -> usize {
        self.withdrawals.len()
    }
    fn total_out(&self) -> u64 {
        self.withdrawals.iter().map(|w| w.amount).sum()
    }
    fn counter_next(&self) -> i64 {
        self.counter_prev + self.n() as i64
    }

    /// The engine's byte-exact `AEGISPV1` journal for this shape (the oracle).
    fn expected_journal(&self) -> Vec<u8> {
        let wds = self
            .withdrawals
            .iter()
            .map(|w| Withdrawal {
                amount: w.amount,
                recipient_prop: w.recipient_prop.clone(),
                nf0: self.prev_root, // unused by the journal
            })
            .collect();
        let result = EpochResult {
            prev_root: self.prev_root,
            new_root: self.new_root,
            settled_root_out: self.settled_out,
            tip_id_new: self.tip_new,
            pot_after: 0,
            shielded_after: 0,
            withdrawals: wds,
        };
        epoch_journal(
            &result,
            &self.settled_in,
            &self.tip_prev,
            &self.ergo_ref,
            self.counter_next() as u64,
        )
    }

    fn vault_in(&self, script: &[u8]) -> EvalBox {
        mk_box(
            script.to_vec(),
            vec![(NFT, 1), (USE, self.use_in_vault)],
            [
                Some(coll_byte_reg(&digest_to_bytes(&self.prev_root))),
                Some(long_reg(self.counter_prev)),
                Some(coll_byte_reg(&digest_to_bytes(&self.settled_in))),
                Some(coll_byte_reg(&self.tip_prev)),
            ],
        )
    }

    fn successor(&self, script: &[u8]) -> EvalBox {
        mk_box(
            script.to_vec(),
            vec![
                (NFT, 1),
                (USE, self.use_in_vault.saturating_sub(self.total_out())),
            ],
            [
                Some(coll_byte_reg(&digest_to_bytes(&self.new_root))),
                Some(long_reg(self.counter_next())),
                Some(coll_byte_reg(&digest_to_bytes(&self.settled_out))),
                Some(coll_byte_reg(&self.tip_new)),
            ],
        )
    }

    fn recipients(&self) -> Vec<EvalBox> {
        self.withdrawals
            .iter()
            .map(|w| {
                mk_box(
                    w.recipient_prop.clone(),
                    vec![(USE, w.amount)],
                    [None, None, None, None],
                )
            })
            .collect()
    }
}

/// Build the release-tx outputs `[successor, rec_1..rec_n, fee]`.
fn outputs_of(spec: &VaultSpec, s: &EpochScn) -> Vec<EvalBox> {
    let script = vault_tree_bytes(spec);
    let mut outs = vec![s.successor(&script)];
    outs.extend(s.recipients());
    outs.push(mk_box(vec![0x01], vec![], [None, None, None, None]));
    outs
}

// ----- expr combinators reused from the module surface -----

fn op(opcode: u8, payload: Payload) -> Expr {
    Expr::Op(IrNode { opcode, payload })
}
fn c_bytes(b: &[u8]) -> Expr {
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        val: SigmaValue::Coll(CollValue::Bytes(b.to_vec())),
    }
}
fn eq(a: Expr, b: Expr) -> Expr {
    op(0x93, Payload::Two(Box::new(a), Box::new(b)))
}

/// Reduce `journal_expr == expected` through the real evaluator with a given
/// header window + output mutation. `true` iff the tx-derived journal is
/// byte-exact.
fn reconstructs_to(
    spec: &VaultSpec,
    s: &EpochScn,
    expected: &[u8],
    headers: &[EvalHeader],
    mutate: impl FnOnce(&mut Vec<EvalBox>),
) -> Result<bool, ()> {
    let script = vault_tree_bytes(spec);
    let inputs = vec![s.vault_in(&script)];
    let mut outputs = outputs_of(spec, s);
    mutate(&mut outputs);

    let mut ctx = ReductionContext::minimal(2_000_000, 1);
    ctx.inputs = &inputs;
    ctx.outputs = &outputs;
    ctx.self_box = Some(&inputs[0]);
    ctx.last_headers = headers;

    let probe = eq(journal_expr(&spec.tag), c_bytes(expected));
    match reduce_expr(&probe, &ctx, &[]) {
        Ok(SigmaBoolean::TrivialProp(b)) => Ok(b),
        Ok(_) => Ok(false),
        Err(_) => Err(()),
    }
}

fn window(anchor: [u8; 32]) -> Vec<EvalHeader> {
    // A 3-slot window; the anchor lives at ANCHOR_HEADER_INDEX (0), the rest
    // carry unrelated ids.
    let mut w = vec![header_with_id([0x01; 32]); 3];
    w[ANCHOR_HEADER_INDEX as usize] = header_with_id(anchor);
    w
}

/// Full-predicate reduction (stub or real verifyStark), with a proof var and a
/// header window whose anchor slot = `s.ergo_ref`.
fn run_full(
    spec: &VaultSpec,
    s: &EpochScn,
    proof: &[u8],
    mutate: impl FnOnce(&mut Vec<EvalBox>),
) -> bool {
    let script = vault_tree_bytes(spec);
    let inputs = vec![s.vault_in(&script)];
    let mut outputs = outputs_of(spec, s);
    mutate(&mut outputs);
    let headers = window(s.ergo_ref);

    let mut ctx = ReductionContext::minimal(2_000_000, 1);
    ctx.inputs = &inputs;
    ctx.outputs = &outputs;
    ctx.self_box = Some(&inputs[0]);
    ctx.last_headers = &headers;
    let (tpe, val) = chunk_proof(proof);
    ctx.extension.insert(0u8, (tpe, val));

    match reduce_expr(&vault_body(spec), &ctx, &[]) {
        Ok(SigmaBoolean::TrivialProp(b)) => b,
        Ok(_) => panic!("unexpected sigma reduction"),
        Err(_) => false,
    }
}

// =====================================================================
// reconstruct: the E4 splice + full journal, byte-exact, real evaluator.
// =====================================================================

mod reconstruct {
    use super::*;

    // ----- happy path -----

    #[test]
    fn journal_reconstructs_byte_exact_with_anchor_splice() {
        // The load-bearing assertion: the evaluator reads CONTEXT.headers(0).id,
        // splices it into the journal, and the whole thing equals the engine's
        // AEGISPV1 bytes — for N = 1..=3.
        for n in 1..=3 {
            let s = EpochScn::default_with(n);
            let expected = s.expected_journal();
            let ok = reconstructs_to(&spec(), &s, &expected, &window(s.ergo_ref), |_| {})
                .expect("reduces");
            assert!(ok, "N={n} journal must reconstruct byte-exact");
        }
    }

    #[test]
    fn vault_tree_fits_proposition_budget() {
        // The hand-assembled body must stay under MaxPropositionBytes (4096).
        let bytes = vault_tree_bytes(&spec());
        println!("epoch vault tree size = {} bytes", bytes.len());
        assert!(
            bytes.len() < 4096,
            "epoch vault tree {} >= 4096",
            bytes.len()
        );
    }

    #[test]
    fn expected_journal_has_the_242plus_byte_fixed_prefix() {
        // 8 tag + 7*32 fixed roots/ids + 8 counter = 240, then entries.
        let s = EpochScn::default_with(1);
        let j = s.expected_journal();
        let entry0 = 8 + 8 + s.withdrawals[0].recipient_prop.len();
        assert_eq!(j.len(), 240 + entry0);
        assert_eq!(&j[0..8], &JOURNAL_TAG);
    }

    // ----- error paths: every journal field tamper flips reconstruction -----

    #[test]
    fn tampered_withdrawal_amount_rejected() {
        let s = EpochScn::default_with(2);
        let expected = s.expected_journal();
        let ok = reconstructs_to(&spec(), &s, &expected, &window(s.ergo_ref), |outs| {
            outs[1].tokens[0].1 += 1; // recipient 1's amount enters the journal
        })
        .expect("reduces");
        assert!(!ok);
    }

    #[test]
    fn tampered_recipient_prop_rejected() {
        let s = EpochScn::default_with(2);
        let expected = s.expected_journal();
        let ok = reconstructs_to(&spec(), &s, &expected, &window(s.ergo_ref), |outs| {
            outs[2].script_bytes[0] ^= 0xFF;
        })
        .expect("reduces");
        assert!(!ok);
    }

    #[test]
    fn tampered_new_root_r4_rejected() {
        let s = EpochScn::default_with(1);
        let expected = s.expected_journal();
        let ok = reconstructs_to(&spec(), &s, &expected, &window(s.ergo_ref), |outs| {
            outs[0].registers[0] = Some(coll_byte_reg(&digest_to_bytes(&dg(0x99))));
        })
        .expect("reduces");
        assert!(!ok);
    }

    #[test]
    fn tampered_settled_out_r6_rejected() {
        let s = EpochScn::default_with(1);
        let expected = s.expected_journal();
        let ok = reconstructs_to(&spec(), &s, &expected, &window(s.ergo_ref), |outs| {
            outs[0].registers[2] = Some(coll_byte_reg(&digest_to_bytes(&dg(0x9A))));
        })
        .expect("reduces");
        assert!(!ok);
    }

    #[test]
    fn tampered_tip_new_r7_rejected() {
        let s = EpochScn::default_with(1);
        let expected = s.expected_journal();
        let ok = reconstructs_to(&spec(), &s, &expected, &window(s.ergo_ref), |outs| {
            outs[0].registers[3] = Some(coll_byte_reg(&id32(0x9B)));
        })
        .expect("reduces");
        assert!(!ok);
    }

    #[test]
    fn tampered_anchor_id_rejected() {
        // THE splice test: a different header id at the anchor slot => the
        // spliced ergo_ref no longer matches the guest-committed journal.
        let s = EpochScn::default_with(1);
        let expected = s.expected_journal();
        let ok =
            reconstructs_to(&spec(), &s, &expected, &window(id32(0xDE)), |_| {}).expect("reduces");
        assert!(!ok);
    }

    #[test]
    fn wrong_anchor_slot_rejected() {
        // ergo_ref present, but at slot 1 (not the pinned ANCHOR_HEADER_INDEX);
        // slot 0 carries an unrelated id => reject. Confirms the contract binds
        // the SPECIFIC slot.
        let s = EpochScn::default_with(1);
        let expected = s.expected_journal();
        let mut w = window(id32(0xDE)); // slot 0 = unrelated
        w[1] = header_with_id(s.ergo_ref);
        let ok = reconstructs_to(&spec(), &s, &expected, &w, |_| {}).expect("reduces");
        assert!(!ok);
    }

    #[test]
    fn empty_header_window_errors_not_authorizes() {
        // No headers => ByIndex(0) fails => eval error, never a spend.
        let s = EpochScn::default_with(1);
        let expected = s.expected_journal();
        assert!(reconstructs_to(&spec(), &s, &expected, &[], |_| {}).is_err());
    }

    #[test]
    fn tampered_counter_rejected() {
        // counter_next = vault.R5 + n; shifting the input R5 shifts the journal.
        let s = EpochScn::default_with(1);
        let expected = s.expected_journal();
        let script = vault_tree_bytes(&spec());
        let mut vin = s.vault_in(&script);
        vin.registers[1] = Some(long_reg(s.counter_prev + 1));
        let inputs = vec![vin];
        let outputs = outputs_of(&spec(), &s);
        let headers = window(s.ergo_ref);
        let mut ctx = ReductionContext::minimal(2_000_000, 1);
        ctx.inputs = &inputs;
        ctx.outputs = &outputs;
        ctx.self_box = Some(&inputs[0]);
        ctx.last_headers = &headers;
        let probe = eq(journal_expr(&spec().tag), c_bytes(&expected));
        let ok = matches!(
            reduce_expr(&probe, &ctx, &[]),
            Ok(SigmaBoolean::TrivialProp(true))
        );
        assert!(!ok);
    }

    #[test]
    fn dropped_output_rejected() {
        let s = EpochScn::default_with(2);
        let expected = s.expected_journal();
        let ok = reconstructs_to(&spec(), &s, &expected, &window(s.ergo_ref), |outs| {
            outs.remove(1); // drop a recipient => n and entries change
        })
        .expect("reduces");
        assert!(!ok);
    }

    #[test]
    fn added_output_rejected() {
        let s = EpochScn::default_with(2);
        let expected = s.expected_journal();
        let ok = reconstructs_to(&spec(), &s, &expected, &window(s.ergo_ref), |outs| {
            let extra = mk_box(
                vec![0x00, 0x08, 0xCD, 0x02],
                vec![(USE, 5)],
                [None, None, None, None],
            );
            outs.insert(2, extra);
        })
        .expect("reduces");
        assert!(!ok);
    }

    #[test]
    fn reordered_outputs_rejected() {
        let s = EpochScn::default_with(2);
        let expected = s.expected_journal();
        let ok = reconstructs_to(&spec(), &s, &expected, &window(s.ergo_ref), |outs| {
            outs.swap(1, 2); // distinct amounts => entry order changes
        })
        .expect("reduces");
        assert!(!ok);
    }
}

// =====================================================================
// binding: stub verifyStark => structural bindings only.
// =====================================================================

#[cfg(not(feature = "real-verify"))]
mod binding {
    use super::*;
    use bridge_tools::vault_epoch::MAX_BATCH;

    // ----- happy path -----

    #[test]
    fn wellformed_release_is_accepted() {
        assert!(run_full(
            &spec(),
            &EpochScn::default_with(2),
            b"stub",
            |_| {}
        ));
    }

    // ----- error paths -----

    #[test]
    fn amount_is_journal_carried_not_structural() {
        // Design pin (mirrors the batch predicate): the amount has NO structural
        // check — bound solely through the journal (proven byte-exact by
        // `reconstruct::tampered_withdrawal_amount_rejected`). Under the stub it
        // must stay TRUE; if this flips, a structural amount check crept in.
        assert!(run_full(
            &spec(),
            &EpochScn::default_with(2),
            b"stub",
            |outs| {
                outs[1].tokens[0].1 += 1;
            }
        ));
    }

    #[test]
    fn successor_missing_nft_rejected() {
        assert!(!run_full(
            &spec(),
            &EpochScn::default_with(2),
            b"stub",
            |outs| {
                outs[0].tokens.remove(0);
            }
        ));
    }

    #[test]
    fn successor_script_swap_rejected() {
        assert!(!run_full(
            &spec(),
            &EpochScn::default_with(2),
            b"stub",
            |outs| {
                outs[0].script_bytes = vec![0xDE, 0xAD];
            }
        ));
    }

    #[test]
    fn counter_not_incremented_rejected() {
        let s = EpochScn::default_with(2);
        let stale = s.counter_prev; // successor R5 must be counter_prev + n
        assert!(!run_full(&spec(), &s, b"stub", move |outs| {
            outs[0].registers[1] = Some(long_reg(stale));
        }));
    }

    #[test]
    fn fee_output_with_tokens_rejected() {
        let s = EpochScn::default_with(2);
        assert!(!run_full(&spec(), &s, b"stub", |outs| {
            let last = outs.len() - 1;
            outs[last].tokens = vec![(USE, 5)];
        }));
    }

    #[test]
    fn wrong_use_token_to_recipient_rejected() {
        assert!(!run_full(
            &spec(),
            &EpochScn::default_with(2),
            b"stub",
            |outs| {
                outs[1].tokens[0].0 = [0x77; 32];
            }
        ));
    }

    #[test]
    fn recipient_with_extra_token_rejected() {
        assert!(!run_full(
            &spec(),
            &EpochScn::default_with(2),
            b"stub",
            |outs| {
                outs[1].tokens.push(([0x99; 32], 1)); // tokens.size != 1
            }
        ));
    }

    #[test]
    fn zero_withdrawals_rejected() {
        // OUTPUTS = [successor, fee] => n = 0 => n >= 1 fails.
        let s = EpochScn::default_with(2);
        assert!(!run_full(&spec(), &s, b"stub", |outs| {
            outs.truncate(1); // drop recipients + fee
            outs.push(mk_box(vec![0x01], vec![], [None, None, None, None]));
        }));
    }

    #[test]
    fn over_max_batch_rejected() {
        // MAX_BATCH + 1 recipients => n > MAX_BATCH.
        let s = EpochScn::default_with(MAX_BATCH as usize + 1);
        assert!(!run_full(&spec(), &s, b"stub", |_| {}));
    }

    #[test]
    fn max_batch_boundary_accepted() {
        let s = EpochScn::default_with(MAX_BATCH as usize);
        assert!(run_full(&spec(), &s, b"stub", |_| {}));
    }

    #[test]
    fn missing_proof_var_rejected() {
        // No context-extension var 0 => OptionGet fails => eval error => reject.
        let s = EpochScn::default_with(2);
        let script = vault_tree_bytes(&spec());
        let inputs = vec![s.vault_in(&script)];
        let outputs = outputs_of(&spec(), &s);
        let headers = window(s.ergo_ref);
        let mut ctx = ReductionContext::minimal(2_000_000, 1);
        ctx.inputs = &inputs;
        ctx.outputs = &outputs;
        ctx.self_box = Some(&inputs[0]);
        ctx.last_headers = &headers;
        assert!(reduce_expr(&vault_body(&spec()), &ctx, &[]).is_err());
    }
}

// =====================================================================
// real_verify: the verifyStark opcode PATH is wired and journal-binding.
// =====================================================================

#[cfg(feature = "real-verify")]
mod real_verify {
    use super::*;

    const PROOF: &[u8] =
        include_bytes!("../../../../../ergo/ergo-sigma/test-vectors/stark/proof_inner.bin");

    #[test]
    fn epoch_tree_rejects_journal_mismatched_receipt() {
        // The pinned receipt commits a 67-byte journal; the epoch predicate
        // reconstructs a >=240-byte AEGISPV1 journal, so verifyStark's
        // byte-exact comparison must FALSE. This proves the 0xB9 opcode is
        // wired into the epoch tree AND that it binds the (larger) journal —
        // the reject half of the oracle. A TRUE path needs a pinned AEGISPV1
        // receipt (the vk-pinning follow-up); no such vector exists yet.
        let s = EpochScn::default_with(1);
        assert!(!run_full(&spec(), &s, PROOF, |_| {}));
    }
}
