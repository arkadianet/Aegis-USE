//! The PegVault ErgoTree, hand-assembled (the ErgoScript compiler has no
//! `verifyStark`; opcode 0xB9 is devnet-only EIP-0045).
//!
//! # Predicate (anchored on `INPUTS(0)`)
//!
//! ```text
//! val vault = INPUTS(0)          // the NFT-carrying vault box
//! val nv    = OUTPUTS(0)         // successor vault
//! val rec   = OUTPUTS(1)         // withdrawal recipient
//! journal = TAG ++ vault.R4 ++ nv.R4
//!         ++ longToByteArray(rec.tokens(0)._2)
//!         ++ longToByteArray(vault.R5 + 1)
//!         ++ rec.propositionBytes
//! sigmaProp(
//!   vault.tokens(0) == (NFT, 1) && nv.tokens(0) == (NFT, 1) &&
//!   nv.propositionBytes == vault.propositionBytes &&
//!   nv.R5 == vault.R5 + 1 &&
//!   rec.tokens(0)._1 == USE &&
//!   OUTPUTS.size == 3 && OUTPUTS(2).tokens.size == 0 &&
//!   verifyStark(getVar[Coll[Coll[Byte]]](0).get, journal, IMAGE_ID, 3, [35,16])
//! )
//! ```
//!
//! The binding kills the EIP-0045 footgun (`stark-settlement-design.md` §"the
//! public-input binding"): the contract does not PARSE a journal — it
//! RECONSTRUCTS the only journal it will accept from THIS transaction's data
//! (prev root from the vault being spent, new root from the successor, amount
//! from the actual recipient output, epoch = counter+1, recipient = the actual
//! output script). A valid proof can therefore never be replayed onto a
//! different withdrawal, and replaying the same release fails because the
//! successor's R4/R5 have advanced. Every box at the vault address (the main
//! NFT box AND deposit boxes) is spendable only inside a tx whose `INPUTS(0)`
//! is the NFT vault and whose shape satisfies the release rules — deposit
//! consolidation for free.
//!
//! Layout choices: version-0 sizeless header, constants inline (no
//! segregation), no ValDef/BlockValue bindings — every subexpression is
//! inlined, trading ~a hundred bytes for zero binding-id semantics to get
//! wrong. Body must stay < 4096 bytes (`MaxPropositionBytes`); it is ~600.

use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaValue};

/// The production journal domain tag (chain id v3 cut).
pub const JOURNAL_TAG: [u8; 8] = *b"AEGISPO3";

/// verifyStark vmType for a RISC0 succinct receipt (matches the devnet's
/// oracle tests).
pub const VM_TYPE_RISC0: i32 = 3;

/// verifyStark costParams `[queries, merkle_depth]` (devnet oracle values).
pub const COST_PARAMS: [i32; 2] = [35, 16];

/// Everything the vault tree is pinned to at build time.
#[derive(Clone, Debug)]
pub struct VaultSpec {
    /// The vault singleton NFT token id.
    pub nft_id: [u8; 32],
    /// The bridged USE token id.
    pub use_id: [u8; 32],
    /// The settlement guest's RISC0 image id (pins WHICH program's proofs
    /// release funds).
    pub image_id: [u8; 32],
    /// Journal domain tag (production: [`JOURNAL_TAG`]; the stub-tier tests
    /// pin a different tag to match the oracle journal).
    pub tag: [u8; 8],
}

// ---- tiny AST combinators ----

fn op(opcode: u8, payload: Payload) -> Expr {
    Expr::Op(IrNode { opcode, payload })
}
fn one(opcode: u8, a: Expr) -> Expr {
    op(opcode, Payload::One(Box::new(a)))
}
fn two(opcode: u8, a: Expr, b: Expr) -> Expr {
    op(opcode, Payload::Two(Box::new(a), Box::new(b)))
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
/// `coll(i)` — ByIndex, no default.
fn at(coll: Expr, i: i32) -> Expr {
    op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(coll),
            index: Box::new(c_int(i)),
            default: None,
        },
    )
}
fn opt_get(a: Expr) -> Expr {
    one(0xE4, a)
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
/// `box.R4[Coll[Byte]].get`
fn r4_bytes(bx: Expr) -> Expr {
    opt_get(op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(bx),
            reg_id: 4,
            tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        },
    ))
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
fn append(a: Expr, b: Expr) -> Expr {
    two(0xB3, a, b)
}
fn long_to_bytes(a: Expr) -> Expr {
    one(0x7A, a)
}

fn vault() -> Expr {
    at(inputs(), 0)
}
fn nv() -> Expr {
    at(outputs(), 0)
}
fn rec() -> Expr {
    at(outputs(), 1)
}

/// `TAG ++ vault.R4 ++ nv.R4 ++ long(rec.tokens(0)._2) ++ long(vault.R5+1)
///  ++ rec.propositionBytes` — the ONLY journal this vault accepts, derived
/// from the spending transaction itself.
pub fn journal_expr(tag: &[u8; 8]) -> Expr {
    let amount = select(at(tokens_of(rec()), 0), 2);
    let epoch = plus(r5_long(vault()), c_long(1));
    append(
        append(
            append(
                append(append(c_bytes(tag), r4_bytes(vault())), r4_bytes(nv())),
                long_to_bytes(amount),
            ),
            long_to_bytes(epoch),
        ),
        prop_bytes(rec()),
    )
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
    let bindings = and(
        and(
            and(
                and(nft(vault()), nft(nv())),
                eq(prop_bytes(nv()), prop_bytes(vault())),
            ),
            and(
                eq(r5_long(nv()), plus(r5_long(vault()), c_long(1))),
                eq(select(at(tokens_of(rec()), 0), 1), c_bytes(&spec.use_id)),
            ),
        ),
        and(
            eq(size_of(outputs()), c_int(3)),
            eq(size_of(tokens_of(at(outputs(), 2))), c_int(0)),
        ),
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
        .chunks(120 * 1024)
        .map(|c| SigmaValue::Coll(CollValue::Bytes(c.to_vec())))
        .collect();
    (
        SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte)))),
        SigmaValue::Coll(CollValue::Values(chunks)),
    )
}

/// The journal bytes the settlement guest must commit for a release —
/// byte-identical to what the contract reconstructs from the tx.
pub fn journal_bytes(
    tag: &[u8; 8],
    prev_root: &[u8; 32],
    new_root: &[u8; 32],
    amount: i64,
    epoch: i64,
    recipient_prop: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(88 + recipient_prop.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(prev_root);
    out.extend_from_slice(new_root);
    out.extend_from_slice(&amount.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(recipient_prop);
    out
}
