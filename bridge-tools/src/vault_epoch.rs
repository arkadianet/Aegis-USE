//! The epoch-validity PegVault ErgoTree, hand-assembled (the ErgoScript
//! compiler has no `verifyStark`; opcode 0xB9 is devnet-only EIP-0045). v6
//! EPOCH form: one release settles N withdrawals (1 <= N <= [`MAX_BATCH`])
//! against a proven, aux-PoW-carrying hn suffix — the `AEGISPV1` journal
//! (`epoch-validity-design.md` §2.2, `engine/src/epoch/mod.rs`).
//!
//! This is the [`crate::vault`] batch predicate grown with the epoch-validity
//! fields: it chains three registers (R4 state root, R6 settled-burn set, R7
//! sealed-tip header id) instead of one, and — the genuinely new machinery —
//! splices a canonical Ergo header id read from `CONTEXT.headers` into the
//! reconstructed journal (design §E4, "the on-chain lever").
//!
//! # Predicate (anchored on `INPUTS(0)`)
//!
//! ```text
//! val vault = INPUTS(0)                     // the NFT-carrying vault box
//! val nv    = OUTPUTS(0)                    // successor vault
//! val n     = OUTPUTS.size - 2              // recipients 1 .. n
//! val recs  = OUTPUTS.slice(1, OUTPUTS.size - 1)
//! val entries = recs.fold(Coll[Byte](), { (t: (Coll[Byte], Box)) =>
//!   t._1 ++ longToByteArray(t._2.tokens(0)._2)                // amount_be(8)
//!       ++ longToByteArray(t._2.propositionBytes.size.toLong) // prop_len_be(8)
//!       ++ t._2.propositionBytes })
//! journal = TAG
//!         ++ vault.R4 ++ nv.R4                    // prev_root / new_root
//!         ++ vault.R6 ++ nv.R6                    // settled_root_in / _out
//!         ++ vault.R7 ++ nv.R7                    // tip_id_prev / tip_id_new
//!         ++ CONTEXT.headers(ANCHOR).id           // ergo_ref_id (E4 splice)
//!         ++ longToByteArray(vault.R5 + n.toLong) // counter_next
//!         ++ entries
//! sigmaProp(
//!   vault.tokens(0) == (NFT, 1) && nv.tokens(0) == (NFT, 1) &&
//!   nv.propositionBytes == vault.propositionBytes &&
//!   nv.R5 == vault.R5 + n.toLong &&
//!   n >= 1 && n <= MAX_BATCH &&
//!   recs.forall { (b: Box) => b.tokens.size == 1 && b.tokens(0)._1 == USE } &&
//!   OUTPUTS(OUTPUTS.size - 1).tokens.size == 0 &&             // fee box
//!   verifyStark(getVar[Coll[Coll[Byte]]](0).get, journal, IMAGE_ID, 3, [35,16])
//! )
//! ```
//!
//! ## Why the register reads ARE the successor-chain checks
//!
//! The contract does not PARSE the journal — it RECONSTRUCTS the only bytes it
//! will accept from THIS transaction, then `verifyStark`'s byte-exact journal
//! comparison forces the guest to have committed exactly those bytes. So
//! reading `nv.R4` / `nv.R6` / `nv.R7` INTO the reconstructed journal already
//! pins `successor.R4 == new_root`, `successor.R6 == settled_root_out`,
//! `successor.R7 == tip_id_new` — the induction backbone (design §3 "R4/R6/R7
//! state chaining"), with no separate equality op, exactly as R4 chains in the
//! batch predicate. The NEXT settlement reads these same successor registers as
//! ITS `prev_root` / `settled_root_in` / `tip_id_prev`, welding the chain.
//!
//! ## The E4 anchor splice (the on-chain lever, and the new/risky part)
//!
//! `ergo_ref_id` is the one fact no proof can supply: a canonical Ergo chain
//! view. The vault sits ON the chain hn is merge-mined against, so its own
//! execution context carries it. The contract reads `CONTEXT.headers(ANCHOR).id`
//! — a header from the last-10 window Ergo consensus itself vouches for — and
//! splices it into the journal; the guest must have committed that exact id
//! (and proved `H_anchor -> ergo_ref` linkage in-proof, design §E4). The
//! evaluator supports the read: `CONTEXT.headers` = `PropertyCall(101, 2)` ->
//! `Coll[Header]`, `ByIndex` -> `Header`, `Header.id` = `PropertyCall(104, 1)`
//! -> the 32-byte `Coll[Byte]` (devnet `ergo-sigma` evaluator; oracle-tested in
//! `tests/epoch_vault_predicate.rs`). We bind [`ANCHOR_HEADER_INDEX`] = the
//! OLDEST of the window (design §E4: maximal slack before `ergo_ref` slides out
//! of the last-10 window and a re-prove is forced).
//!
//! Layout choices mirror [`crate::vault`]: version-0 sizeless header, constants
//! inline, no ValDef/BlockValue bindings; the only binding ids are the two
//! lambda parameters (fold id 1, forall id 2). Body must stay < 4096 bytes
//! (`MaxPropositionBytes`); the epoch fields + anchor splice add ~a few hundred
//! bytes over the batch tree (size-pinned by `vault_tree_fits_proposition_budget`).

use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaValue};

/// The epoch-validity journal domain tag (`AEGISPV1`) — the engine-shared
/// constant, so guest and contract cannot drift.
pub const JOURNAL_TAG: [u8; 8] = *aegis_engine::epoch::EPOCH_JOURNAL_TAG;

/// Maximum withdrawals settled by one release (Stage-T in-guest bound, design
/// §E3: "fine for ≤16 burns in-guest"). Bounds N a second time on-chain.
pub const MAX_BATCH: i32 = 16;

/// Which `CONTEXT.headers` slot the contract splices as `ergo_ref`. Index 0 is
/// the OLDEST of the up-to-10 recent-header window (design §E4: bind the oldest
/// so the window has maximal slack before the ref slides out and forces a
/// re-prove). Deploy-time note: confirm the node presents `CONTEXT.headers`
/// oldest-first at the target height before pinning.
pub const ANCHOR_HEADER_INDEX: i32 = 0;

/// verifyStark vmType for a RISC0 succinct receipt (matches the devnet's
/// oracle tests).
pub const VM_TYPE_RISC0: i32 = 3;

/// verifyStark costParams `[queries, merkle_depth]` (devnet oracle values).
pub const COST_PARAMS: [i32; 2] = [35, 16];

/// The epoch-validity guest's pinned RISC0 image id, hex, container-reproduced
/// (`settlement/EPOCH_IMAGE_ID.hex`, built under `~/apps/risc0-cuda` with
/// `AEGIS_EPOCH_AUXPOW=1`). This is the load-bearing vk-pin: `verifyStark` only
/// releases funds for a receipt of THIS program, whose ELF bakes the epoch
/// statement AND `AggParams::default()` (the recursion aggregation tower,
/// recursion-feasibility.md §4(d)) — so a swapped guest or a drifted aggregation
/// config cannot produce an accepted receipt. The hex file is the single source
/// of truth; a re-pin (config drift / guest change) is one edit there + a re-cut.
pub const EPOCH_IMAGE_ID_HEX: &str = include_str!("../../settlement/EPOCH_IMAGE_ID.hex");

/// Decode [`EPOCH_IMAGE_ID_HEX`] into the 32-byte image id the PegVault pins.
pub fn pinned_epoch_image_id() -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(EPOCH_IMAGE_ID_HEX.trim(), &mut out)
        .expect("EPOCH_IMAGE_ID.hex must be exactly 32-byte hex");
    out
}

/// Everything the vault tree is pinned to at build time.
#[derive(Clone, Debug)]
pub struct VaultSpec {
    /// The vault singleton NFT token id.
    pub nft_id: [u8; 32],
    /// The bridged USE token id.
    pub use_id: [u8; 32],
    /// The epoch-validity guest's RISC0 image id (pins WHICH program's proofs
    /// release funds — the v7 `AEGISPV1` image).
    pub image_id: [u8; 32],
    /// Journal domain tag (production: [`JOURNAL_TAG`]; the oracle-tier tests
    /// pin the tag their reconstructed journal carries).
    pub tag: [u8; 8],
}

// ---- tiny AST combinators (mirror crate::vault) ----

fn op(opcode: u8, payload: Payload) -> Expr {
    Expr::Op(IrNode { opcode, payload })
}
fn one(opcode: u8, a: Expr) -> Expr {
    op(opcode, Payload::One(Box::new(a)))
}
fn two(opcode: u8, a: Expr, b: Expr) -> Expr {
    op(opcode, Payload::Two(Box::new(a), Box::new(b)))
}
fn three(opcode: u8, a: Expr, b: Expr, c: Expr) -> Expr {
    op(
        opcode,
        Payload::Three(Box::new(a), Box::new(b), Box::new(c)),
    )
}

fn c_bytes(b: &[u8]) -> Expr {
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        val: SigmaValue::Coll(CollValue::Bytes(b.to_vec())),
    }
}
fn c_int(v: i32) -> Expr {
    Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(v),
    }
}
fn c_long(v: i64) -> Expr {
    Expr::Const {
        tpe: SigmaType::SLong,
        val: SigmaValue::Long(v),
    }
}

fn inputs() -> Expr {
    op(0xA4, Payload::Zero)
}
fn outputs() -> Expr {
    op(0xA5, Payload::Zero)
}
/// `CONTEXT` — the context global (obj of the SContext property calls).
fn context() -> Expr {
    op(0xFE, Payload::Zero)
}
/// `coll(idx_expr)` — ByIndex, no default, expression index.
fn at_expr(coll: Expr, idx: Expr) -> Expr {
    op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(coll),
            index: Box::new(idx),
            default: None,
        },
    )
}
/// `coll(i)` — ByIndex, no default, literal index.
fn at(coll: Expr, i: i32) -> Expr {
    at_expr(coll, c_int(i))
}
fn opt_get(a: Expr) -> Expr {
    one(0xE4, a)
}
/// A no-arg `PropertyCall` (opcode 0xDB): `obj.<method>` for `(type_id,
/// method_id)`. The devnet evaluator routes 0xDB through the same no-arg method
/// table as 0xDC MethodCall (`property_call.rs`).
fn property_call(type_id: u8, method_id: u8, obj: Expr) -> Expr {
    op(
        0xDB,
        Payload::MethodCall {
            type_id,
            method_id,
            obj: Box::new(obj),
            args: vec![],
            type_args: vec![],
        },
    )
}
/// `CONTEXT.headers` — SContext(101).headers(2) -> `Coll[Header]`.
fn ctx_headers() -> Expr {
    property_call(101, 2, context())
}
/// `header.id` — SHeader(104).id(1) -> `Coll[Byte]` (32 bytes).
fn header_id(hdr: Expr) -> Expr {
    property_call(104, 1, hdr)
}
/// `CONTEXT.headers(ANCHOR_HEADER_INDEX).id` — the E4 canonical-Ergo anchor
/// splice (design §E4). Yields the 32-byte `ergo_ref_id` the journal binds.
fn ergo_ref() -> Expr {
    header_id(at(ctx_headers(), ANCHOR_HEADER_INDEX))
}
/// `box.tokens` — ExtractRegisterAs R2 as Coll[(Coll[Byte], Long)], unwrapped.
fn tokens_of(bx: Expr) -> Expr {
    opt_get(op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(bx),
            reg_id: 2,
            tpe: SigmaType::SColl(Box::new(SigmaType::STuple(vec![
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaType::SLong,
            ]))),
        },
    ))
}
fn select(tuple: Expr, idx_1based: u8) -> Expr {
    op(
        0x8C,
        Payload::SelectField {
            input: Box::new(tuple),
            field_idx: idx_1based,
        },
    )
}
/// `box.R<reg>[Coll[Byte]].get` — the chained root/set/tip registers all read
/// as raw byte strings (R4 state root, R6 settled set, R7 sealed-tip id).
fn reg_bytes(bx: Expr, reg_id: u8) -> Expr {
    opt_get(op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(bx),
            reg_id,
            tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        },
    ))
}
fn r4_bytes(bx: Expr) -> Expr {
    reg_bytes(bx, 4)
}
fn r6_bytes(bx: Expr) -> Expr {
    reg_bytes(bx, 6)
}
fn r7_bytes(bx: Expr) -> Expr {
    reg_bytes(bx, 7)
}
/// `box.R5[Long].get`
fn r5_long(bx: Expr) -> Expr {
    opt_get(op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(bx),
            reg_id: 5,
            tpe: SigmaType::SLong,
        },
    ))
}
fn prop_bytes(bx: Expr) -> Expr {
    one(0xC2, bx)
}
fn size_of(coll: Expr) -> Expr {
    one(0xB1, coll)
}
fn eq(a: Expr, b: Expr) -> Expr {
    two(0x93, a, b)
}
fn and(a: Expr, b: Expr) -> Expr {
    two(0xED, a, b) // BinAnd (lazy)
}
fn plus(a: Expr, b: Expr) -> Expr {
    two(0x9A, a, b)
}
fn minus(a: Expr, b: Expr) -> Expr {
    two(0x99, a, b)
}
fn ge(a: Expr, b: Expr) -> Expr {
    two(0x92, a, b)
}
fn le(a: Expr, b: Expr) -> Expr {
    two(0x90, a, b)
}
fn append(a: Expr, b: Expr) -> Expr {
    two(0xB3, a, b)
}
/// Left-fold `append` over a non-empty list of byte-collection exprs.
fn concat(parts: Vec<Expr>) -> Expr {
    let mut it = parts.into_iter();
    let mut acc = it.next().expect("at least one part");
    for p in it {
        acc = append(acc, p);
    }
    acc
}
fn long_to_bytes(a: Expr) -> Expr {
    one(0x7A, a)
}
/// `expr.toLong` — Upcast Int -> Long.
fn upcast_long(a: Expr) -> Expr {
    op(
        0x7E,
        Payload::NumericCast {
            input: Box::new(a),
            tpe: SigmaType::SLong,
        },
    )
}
/// A unary lambda `{ (arg: tpe) => body }` (the evaluator rejects any other
/// arity at eval time; Scala closures are always unary).
fn func1(arg_id: u32, tpe: SigmaType, body: Expr) -> Expr {
    op(
        0xD9,
        Payload::FuncValue {
            args: vec![(arg_id, Some(tpe))],
            body: Box::new(body),
        },
    )
}
fn val_use(id: u32) -> Expr {
    op(0x72, Payload::ValUse { id })
}

fn vault() -> Expr {
    at(inputs(), 0)
}
fn nv() -> Expr {
    at(outputs(), 0)
}
/// `n = OUTPUTS.size - 2` (Int) — the batch size the tx claims.
fn n_int() -> Expr {
    minus(size_of(outputs()), c_int(2))
}
/// `n.toLong`.
fn n_long() -> Expr {
    upcast_long(n_int())
}
/// `OUTPUTS.slice(1, OUTPUTS.size - 1)` — the recipient outputs.
fn recs() -> Expr {
    three(
        0xB4,
        outputs(),
        c_int(1),
        minus(size_of(outputs()), c_int(1)),
    )
}
/// `OUTPUTS(OUTPUTS.size - 1)` — the fee box (always last).
fn fee_box() -> Expr {
    at_expr(outputs(), minus(size_of(outputs()), c_int(1)))
}

/// Fold-lambda binding id: the `(acc: Coll[Byte], b: Box)` tuple parameter.
const FOLD_ARG: u32 = 1;
/// ForAll-lambda binding id: the recipient `Box` parameter.
const FORALL_ARG: u32 = 2;

/// The ordered entry-list bytes, rebuilt from the recipient outputs:
/// `recs.fold(Coll[Byte](), (t) => t._1 ++ amount_be(8) ++ prop_len_be(8) ++
/// prop)` — byte-exact against the `for wd in withdrawals` loop in
/// [`aegis_engine::epoch::epoch_journal`].
fn entries_expr() -> Expr {
    let acc = || select(val_use(FOLD_ARG), 1);
    let bx = || select(val_use(FOLD_ARG), 2);
    let amount = select(at(tokens_of(bx()), 0), 2);
    let prop_len = upcast_long(size_of(prop_bytes(bx())));
    let body = concat(vec![
        acc(),
        long_to_bytes(amount),
        long_to_bytes(prop_len),
        prop_bytes(bx()),
    ]);
    let tuple_tpe = SigmaType::STuple(vec![
        SigmaType::SColl(Box::new(SigmaType::SByte)),
        SigmaType::SBox,
    ]);
    three(0xB0, recs(), c_bytes(&[]), func1(FOLD_ARG, tuple_tpe, body))
}

/// The `AEGISPV1` journal, reconstructed from the spending transaction —
/// byte-exact against [`aegis_engine::epoch::epoch_journal`] (§2.2):
/// `TAG ‖ prev_root ‖ new_root ‖ settled_root_in ‖ settled_root_out ‖
///  tip_id_prev ‖ tip_id_new ‖ ergo_ref_id ‖ counter_next_be ‖ entries`.
pub fn journal_expr(tag: &[u8; 8]) -> Expr {
    let counter_next = plus(r5_long(vault()), n_long());
    concat(vec![
        c_bytes(tag),
        r4_bytes(vault()), // prev_root
        r4_bytes(nv()),    // new_root
        r6_bytes(vault()), // settled_root_in
        r6_bytes(nv()),    // settled_root_out
        r7_bytes(vault()), // tip_id_prev
        r7_bytes(nv()),    // tip_id_new
        ergo_ref(),        // ergo_ref_id (E4 CONTEXT.headers splice)
        long_to_bytes(counter_next),
        entries_expr(),
    ])
}

/// The full release predicate body (a Boolean expression; the tree root wraps
/// it in BoolToSigmaProp).
pub fn vault_body(spec: &VaultSpec) -> Expr {
    let nft = |bx: Expr| {
        let t0 = at(tokens_of(bx), 0);
        and(
            eq(select(t0.clone(), 1), c_bytes(&spec.nft_id)),
            eq(select(t0, 2), c_long(1)),
        )
    };
    // Each recipient carries EXACTLY one token, the USE id (`tokens.size == 1`
    // keeps any co-spent deposit-box tokens flowing to the successor only); the
    // AMOUNT is bound through the journal, not structurally.
    let rec_ok = {
        let b = || val_use(FORALL_ARG);
        let body = and(
            eq(size_of(tokens_of(b())), c_int(1)),
            eq(select(at(tokens_of(b()), 0), 1), c_bytes(&spec.use_id)),
        );
        two(0xAF, recs(), func1(FORALL_ARG, SigmaType::SBox, body))
    };
    let bindings = and(
        and(
            and(
                and(nft(vault()), nft(nv())),
                eq(prop_bytes(nv()), prop_bytes(vault())),
            ),
            and(
                eq(r5_long(nv()), plus(r5_long(vault()), n_long())),
                and(ge(n_int(), c_int(1)), le(n_int(), c_int(MAX_BATCH))),
            ),
        ),
        and(rec_ok, eq(size_of(tokens_of(fee_box())), c_int(0))),
    );
    let proof_chunks = opt_get(op(
        0xE3,
        Payload::GetVar {
            var_id: 0,
            tpe: SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte)))),
        },
    ));
    let cost_params = Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SInt)),
        val: SigmaValue::Coll(CollValue::Values(
            COST_PARAMS.iter().map(|v| SigmaValue::Int(*v)).collect(),
        )),
    };
    let verify = op(
        0xB9,
        Payload::Five(
            Box::new(proof_chunks),
            Box::new(journal_expr(&spec.tag)),
            Box::new(c_bytes(&spec.image_id)),
            Box::new(c_int(VM_TYPE_RISC0)),
            Box::new(cost_params),
        ),
    );
    and(bindings, verify)
}

/// The vault ErgoTree: version-0 sizeless header, constants inline,
/// `sigmaProp(body)` root.
pub fn vault_tree(spec: &VaultSpec) -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: one(0xD1, vault_body(spec)), // BoolToSigmaProp
    }
}

/// Serialized vault tree bytes (what deposits pay to, what the box carries).
pub fn vault_tree_bytes(spec: &VaultSpec) -> Vec<u8> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::ergo_tree::write_ergo_tree(&mut w, &vault_tree(spec)).expect("vault tree serializes");
    w.result()
}

/// The vault P2S address on `network`.
pub fn vault_address(spec: &VaultSpec, network: ergo_ser::address::NetworkPrefix) -> String {
    ergo_ser::address::encode_p2s(network, &vault_tree_bytes(spec))
}

/// Chunk a serialized receipt for the context-extension `Coll[Coll[Byte]]`
/// var (mirrors the devnet oracle's chunking).
pub fn chunk_proof(proof: &[u8]) -> (SigmaType, SigmaValue) {
    let chunks: Vec<SigmaValue> = proof
        .chunks(60_000)
        .map(|c| SigmaValue::Coll(CollValue::Bytes(c.to_vec())))
        .collect();
    (
        SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte)))),
        SigmaValue::Coll(CollValue::Values(chunks)),
    )
}
