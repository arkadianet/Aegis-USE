//! F3 — peg-in backing proven against the E4-anchored canonical Ergo chain.
//!
//! The v6 guest re-derived peg-in mint commitments from settler-declared
//! `(box_id, dest_owner, amount)` with **no** proof any such Ergo deposit exists
//! (verify.rs peg-in region) — unbacked mints, and not even an in-suffix
//! `box_id` dedup, so one imaginary deposit could mint in every suffix block.
//! This module closes that (`epoch-validity-f1-f3-design.md` §3): every suffix
//! peg-in must exhibit a **deposit proof** that the guest checks against the
//! same canonical `ergo_ref` the anchor (E4) is spliced from.
//!
//! Per peg-in, the guest proves EXISTENCE + UNIQUENESS (not unspentness — vault
//! boxes are consolidated by release txs, so "unspent at height h" is the wrong
//! invariant; "minted at most once, ever" is the right one, §3.2):
//!
//! 1. **Canonical containment + confirmation depth** — `H_dep` lies on a
//!    parent-linked ancestor walk rooted at `ergo_ref` ([`super::anchor::verify_ancestor_walk`]),
//!    at index (= depth) ≥ [`DepositParams::pegin_confirmations`].
//! 2. **Tx inclusion** — the deposit tx's id (RECOMPUTED as
//!    `blake2b256(bytes_to_sign(tx))`, the real Ergo rule — NOT `blake2b256`
//!    of the signed bytes) is bound to `H_dep.transactions_root` via a batch-
//!    Merkle proof whose leaf the guest recomputes itself
//!    (`tx_leaf_digest = blake2b256(0x00 ‖ txid)`) and pins to the proven leaf —
//!    never trusting a supplied leaf (the Scala `/proofFor` witness-leaf trap).
//! 3. **Deposit well-formedness** — `outputs[output_index]` has the pinned vault
//!    `ergoTree`, carries the pinned USE token in amount `pi.amount`, and its
//!    `R4` = `owner(32) ‖ enc_pk(32)` whose owner half decodes to `pi.dest_owner`.
//! 4. **Box id** — `box_id = blake2b256(serialized output ‖ txid ‖ index)`
//!    (the Ergo box-id rule) equals `pi.box_id`, welding the mint commitment
//!    `pegmint_cm_expected(dest_owner, minted, box_id)` (verify.rs) to the real
//!    deposit.
//! 5. **One mint ever** — (a) an in-suffix `HashSet<box_id>` (F6e), (b) a
//!    cross-settlement insert of `hash_domain(DOMAIN_PEGIN_USED, box_id)` into
//!    the R6 settled SMT ([`crate::settled`]), non-membership-then-insert,
//!    domain-separated from the nullifier keys (D-F3).
//!
//! Gated behind `aux-pow` (shares E2/E4's Ergo primitives + the vendored
//! batch-Merkle verifier).

use std::collections::HashSet;

use ergo_crypto::merkle::tx_leaf_digest;
use ergo_primitives::reader::VlqReader;
use ergo_ser::batch_merkle_proof::BatchMerkleProof;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header as ErgoHeader;
use ergo_ser::register::RegisterId;
use ergo_ser::sigma_value::{CollValue, SigmaValue};
use ergo_ser::transaction::{read_transaction, transaction_id};

use crate::poseidon::{digest_to_bytes, Digest};
use crate::settled::{self, pegin_used_key, SETTLED_DEPTH};

use super::anchor::{verify_ancestor_walk, AnchorError};
use super::batch_merkle::verify_batch_merkle_proof;
use super::types::{PegIn, SuffixBlock};

/// Confirmations a vault deposit needs before consensus mints it — the
/// Ergo-reorg-safety depth (mirror of `HnChainParams::pegin_confirmations`,
/// `aegis-node/src/hn/params.rs`, testnet value 10). Pinned image constant.
pub const PEGIN_CONFIRMATIONS: usize = 10;

/// The R4 `sc_dest` payload width: `owner(32) ‖ enc_pk(32)` (mirror of the
/// node's `pegin_watch.rs` deposit shape).
const SC_DEST_LEN: usize = 64;

/// Pinned deposit-recognition parameters. `vault_tree_bytes` (the vault
/// address's `ergoTree`) and `use_token_id` are **deployment-specific** — they
/// are derived from the deployed `VaultSpec` (`bridge-tools/src/vault_epoch.rs`)
/// and MUST be pinned into the guest image at the cut, exactly like the vault
/// address the node's `VaultWatch` is configured with. They are inputs here
/// (not settler-controlled witness) so a fabricator cannot redefine what counts
/// as a deposit.
#[derive(Clone, Debug)]
pub struct DepositParams {
    /// Canonical `ergoTree` bytes of the vault address (what makes a box a deposit).
    pub vault_tree_bytes: Vec<u8>,
    /// The USE token id carried by a deposit.
    pub use_token_id: [u8; 32],
    /// Confirmation depth (defaults to [`PEGIN_CONFIRMATIONS`]).
    pub pegin_confirmations: usize,
}

/// A single peg-in's deposit proof (witness input, one per suffix peg-in in
/// suffix order).
#[derive(Clone, Debug)]
pub struct DepositProof {
    /// Full serialized (signed) Ergo transaction that created the deposit box.
    pub tx_bytes: Vec<u8>,
    /// Which output of that tx is the deposit box.
    pub output_index: u16,
    /// Batch-Merkle proof binding the tx id to `H_dep.transactions_root`.
    pub tx_merkle_proof: BatchMerkleProof,
    /// Index of `H_dep` in [`PegInBackingWitness::deposit_headers`] (= its depth
    /// below `ergo_ref`).
    pub dep_header_index: usize,
    /// One-mint-ever SMT non-membership-then-insert path for this deposit.
    pub used_path: [Digest; SETTLED_DEPTH],
}

/// The F3 witness: one shared parent-linked deposit walk rooted at `ergo_ref`
/// plus one [`DepositProof`] per suffix peg-in (suffix order).
#[derive(Clone, Debug)]
pub struct PegInBackingWitness {
    /// `[ergo_ref, …, deepest H_dep]` — canonical-Ergo ancestor walk. Rooted at
    /// the contract-spliced `ergo_ref`; deposits index into it.
    pub deposit_headers: Vec<ErgoHeader>,
    /// One deposit proof per suffix peg-in, in suffix order.
    pub deposits: Vec<DepositProof>,
}

/// Every way a peg-in backing proof can fail.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PegInError {
    #[error("deposit-proof count {got} != suffix peg-in count {want}")]
    DepositCountMismatch { got: usize, want: usize },
    #[error("deposit walk linkage: {0}")]
    WalkLinkage(#[from] AnchorError),
    #[error("peg-in #{i}: box id {0} duplicated in-suffix (one mint per deposit)", box_hex(.box_id))]
    DuplicateInSuffix { i: usize, box_id: [u8; 32] },
    #[error("peg-in #{i}: dep_header_index {index} out of walk range {len}")]
    HeaderIndexOob { i: usize, index: usize, len: usize },
    #[error("peg-in #{i}: deposit buried at depth {depth} < pegin_confirmations {need}")]
    InsufficientConfirmations { i: usize, depth: usize, need: usize },
    #[error("peg-in #{i}: deposit tx bytes do not decode ({err})")]
    TxDecode { i: usize, err: String },
    #[error("peg-in #{i}: deposit tx has trailing bytes")]
    TxTrailing { i: usize },
    #[error("peg-in #{i}: deposit tx id does not encode ({err})")]
    TxIdEncode { i: usize, err: String },
    #[error("peg-in #{i}: tx-Merkle proof must prove exactly one leaf (got {got})")]
    ProofShape { i: usize, got: usize },
    #[error("peg-in #{i}: tx-Merkle proof leaf != recomputed tx-id leaf")]
    ProofLeafMismatch { i: usize },
    #[error("peg-in #{i}: tx-Merkle proof does not reduce to H_dep.transactions_root")]
    ProofInvalid { i: usize },
    #[error("peg-in #{i}: output_index {index} out of range {len}")]
    OutputIndexOob { i: usize, index: usize, len: usize },
    #[error("peg-in #{i}: deposit output ergoTree != pinned vault tree")]
    WrongVaultTree { i: usize },
    #[error("peg-in #{i}: deposit output has no USE token in amount pi.amount")]
    WrongUseToken { i: usize },
    #[error("peg-in #{i}: deposit output R4 is not a 64-byte sc_dest Coll[Byte]")]
    BadR4 { i: usize },
    #[error("peg-in #{i}: deposit R4 owner != pi.dest_owner")]
    DestOwnerMismatch { i: usize },
    #[error("peg-in #{i}: box id does not encode ({err})")]
    BoxIdEncode { i: usize, err: String },
    #[error("peg-in #{i}: recomputed box id != pi.box_id")]
    BoxIdMismatch { i: usize },
    #[error("peg-in #{i}: deposit already minted (R6 non-membership failed)")]
    AlreadyMinted { i: usize },
}

fn box_hex(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Verify every suffix peg-in is backed by a real, buried, well-formed Ergo
/// deposit minted at most once ever, and fold the one-mint-ever keys into R6.
///
/// `settled_root_in` is R6 AFTER the F6c nullifier inserts (verify.rs); the
/// returned root additionally folds one `pegin_used_key(box_id)` per peg-in, in
/// suffix order — the host must generate `used_path`s against a set seeded with
/// exactly those nullifiers, then the peg-in keys, in the same order.
pub fn verify_pegin_backing(
    blocks: &[SuffixBlock],
    wit: &PegInBackingWitness,
    ergo_ref_id: &[u8; 32],
    settled_root_in: Digest,
    params: &DepositParams,
) -> Result<Digest, PegInError> {
    // Suffix peg-ins in order (txs/pegouts carry none; peg-ins are per block).
    let pegins: Vec<&PegIn> = blocks.iter().flat_map(|b| b.pegins.iter()).collect();

    if wit.deposits.len() != pegins.len() {
        return Err(PegInError::DepositCountMismatch {
            got: wit.deposits.len(),
            want: pegins.len(),
        });
    }
    if pegins.is_empty() {
        // No peg-ins ⇒ no deposit walk required; R6 unchanged.
        return Ok(settled_root_in);
    }

    // The shared deposit walk is canonical iff rooted at `ergo_ref` and
    // parent-linked (canonicality inherited from `ergo_ref = CONTEXT.headers`).
    verify_ancestor_walk(&wit.deposit_headers, ergo_ref_id)?;

    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut settled_root = settled_root_in;

    for (i, (pi, dp)) in pegins.iter().zip(&wit.deposits).enumerate() {
        // (5a) in-suffix dedup — one imaginary box id cannot mint every block.
        if !seen.insert(pi.box_id) {
            return Err(PegInError::DuplicateInSuffix {
                i,
                box_id: pi.box_id,
            });
        }

        verify_one_deposit(i, pi, dp, &wit.deposit_headers, params)?;

        // (5b) cross-settlement one-mint-ever: insert the domain-separated key.
        let key = pegin_used_key(&pi.box_id);
        settled_root = settled::verify_insert(&settled_root, &key, &dp.used_path)
            .map_err(|_| PegInError::AlreadyMinted { i })?;
    }

    Ok(settled_root)
}

/// Existence + shape + box-id checks for one deposit (steps 1–4).
fn verify_one_deposit(
    i: usize,
    pi: &PegIn,
    dp: &DepositProof,
    headers: &[ErgoHeader],
    params: &DepositParams,
) -> Result<(), PegInError> {
    // (1) canonical containment + confirmation depth. `headers` is already
    // verified as a parent-linked walk rooted at ergo_ref, so index == depth.
    let h_dep = headers
        .get(dp.dep_header_index)
        .ok_or(PegInError::HeaderIndexOob {
            i,
            index: dp.dep_header_index,
            len: headers.len(),
        })?;
    if dp.dep_header_index < params.pegin_confirmations {
        return Err(PegInError::InsufficientConfirmations {
            i,
            depth: dp.dep_header_index,
            need: params.pegin_confirmations,
        });
    }

    // (2) tx inclusion. RECOMPUTE the tx id (real Ergo rule) and RECOMPUTE the
    // leaf digest — never trust the supplied leaf (the /proofFor witness-leaf
    // trap). Binding the recomputed 33-byte-preimage txid leaf also pins the
    // proof to the txid half of the (txids ++ witness-ids) tree: a witness-id
    // leaf has a different preimage length and cannot reproduce it.
    let mut r = VlqReader::new(&dp.tx_bytes);
    let tx = read_transaction(&mut r).map_err(|e| PegInError::TxDecode {
        i,
        err: e.to_string(),
    })?;
    if !r.is_empty() {
        return Err(PegInError::TxTrailing { i });
    }
    let txid = transaction_id(&tx).map_err(|e| PegInError::TxIdEncode {
        i,
        err: e.to_string(),
    })?;
    let txid_bytes = *txid.as_bytes();
    let leaf = tx_leaf_digest(&txid_bytes);
    if dp.tx_merkle_proof.indices.len() != 1 {
        return Err(PegInError::ProofShape {
            i,
            got: dp.tx_merkle_proof.indices.len(),
        });
    }
    if dp.tx_merkle_proof.indices[0].1 != leaf {
        return Err(PegInError::ProofLeafMismatch { i });
    }
    if !verify_batch_merkle_proof(&dp.tx_merkle_proof, h_dep.transactions_root.as_bytes()) {
        return Err(PegInError::ProofInvalid { i });
    }

    // (3) deposit well-formedness.
    let out =
        tx.output_candidates
            .get(dp.output_index as usize)
            .ok_or(PegInError::OutputIndexOob {
                i,
                index: dp.output_index as usize,
                len: tx.output_candidates.len(),
            })?;
    if out.ergo_tree_bytes() != params.vault_tree_bytes.as_slice() {
        return Err(PegInError::WrongVaultTree { i });
    }
    // The USE token in the exact deposited amount must be present.
    let has_use = out
        .tokens
        .iter()
        .any(|t| t.token_id.as_bytes() == &params.use_token_id && t.amount == pi.amount);
    if !has_use {
        return Err(PegInError::WrongUseToken { i });
    }
    // R4 = sc_dest = owner(32) ‖ enc_pk(32); owner half must decode to pi.dest_owner.
    let reg = out
        .additional_registers
        .get(RegisterId::R4)
        .ok_or(PegInError::BadR4 { i })?;
    let payload = match &reg.value {
        SigmaValue::Coll(CollValue::Bytes(b)) if b.len() == SC_DEST_LEN => b,
        _ => return Err(PegInError::BadR4 { i }),
    };
    if payload[..32] != digest_to_bytes(&pi.dest_owner) {
        return Err(PegInError::DestOwnerMismatch { i });
    }

    // (4) box id welds the mint commitment to the real deposit.
    let ebox = ErgoBox {
        candidate: out.clone(),
        transaction_id: txid,
        index: dp.output_index,
    };
    let box_id = ebox.box_id().map_err(|e| PegInError::BoxIdEncode {
        i,
        err: e.to_string(),
    })?;
    if box_id.as_bytes() != &pi.box_id {
        return Err(PegInError::BoxIdMismatch { i });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::F;
    use crate::settled::{empty_settled_root, SettledSet};
    use ergo_crypto::merkle::{merkle_proof_by_indices, merkle_tree_root};
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::batch_merkle_proof::{ProofEntry, Side};
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_ser::token::{Token, TokenId};
    use ergo_ser::transaction::{write_transaction, Transaction};
    use p3_field::PrimeCharacteristicRing;

    // ----- helpers -----

    const USE_TOKEN: [u8; 32] = [0x77; 32];
    const CONFIRMATIONS: usize = 3;

    fn owner_digest(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    /// A minimal valid size-delimited ErgoTree (`sigmaProp(true)`), used as the
    /// stand-in vault tree — its serialized bytes are the pinned `vault_tree_bytes`.
    fn a_tree(marker: bool) -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(marker)),
            },
        }
    }

    fn tree_bytes(tree: &ErgoTree) -> Vec<u8> {
        let mut w = VlqWriter::new();
        ergo_ser::ergo_tree::write_ergo_tree(&mut w, tree).unwrap();
        w.result()
    }

    fn sc_dest_r4(owner: &Digest, enc_pk: [u8; 32]) -> AdditionalRegisters {
        let mut payload = Vec::with_capacity(SC_DEST_LEN);
        payload.extend_from_slice(&digest_to_bytes(owner));
        payload.extend_from_slice(&enc_pk);
        AdditionalRegisters {
            registers: vec![RegisterValue {
                tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
                value: SigmaValue::Coll(CollValue::Bytes(payload)),
            }],
        }
    }

    /// A deposit output box carrying the vault tree, USE token, and sc_dest R4.
    fn deposit_candidate(
        tree: &ErgoTree,
        amount: u64,
        owner: &Digest,
        token_id: [u8; 32],
    ) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            1_000_000,
            tree.clone(),
            100,
            vec![Token {
                token_id: TokenId::from_bytes(token_id),
                amount,
            }],
            sc_dest_r4(owner, [0x55; 32]),
        )
        .unwrap()
    }

    fn a_tx(output: ErgoBoxCandidate) -> Transaction {
        Transaction {
            inputs: vec![Input {
                box_id: Digest32::from_bytes([0x01; 32]),
                spending_proof: SpendingProof::new(vec![0xAB, 0xCD], ContextExtension::empty())
                    .unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![output],
        }
    }

    fn tx_bytes_of(tx: &Transaction) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_transaction(&mut w, tx).unwrap();
        w.result()
    }

    fn a_header() -> ErgoHeader {
        let path = format!(
            "{}/../test-vectors/testnet/blocks/scala_block_442815.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&path).unwrap();
        let sblock: ergo_rest_json::types::ScalaFullBlock = serde_json::from_str(&raw).unwrap();
        ergo_rest_json::decode_scala_header_struct(&sblock.header).unwrap()
    }

    /// A batch-Merkle proof for the tx-id leaf against a two-leaf
    /// `[txid, witness_id]` transactions tree (the concatenated layout).
    fn tx_inclusion(txid: &[u8; 32], witness_id: &[u8; 31]) -> (BatchMerkleProof, [u8; 32]) {
        let leaves: Vec<&[u8]> = vec![&txid[..], &witness_id[..]];
        let root = merkle_tree_root(&leaves);
        let (indices, raw) = merkle_proof_by_indices(&leaves, &[0]).unwrap();
        let proof = BatchMerkleProof {
            indices,
            proofs: raw
                .into_iter()
                .map(|e| ProofEntry {
                    digest: e.digest,
                    side: Side::from_byte(e.side),
                })
                .collect(),
        };
        (proof, root)
    }

    /// Parent-linked deposit walk `[ergo_ref, …, h_dep]` with `h_dep` at index
    /// `depth`. Returns `(headers, ergo_ref_id)`.
    fn deposit_walk(h_dep: ErgoHeader, depth: usize) -> (Vec<ErgoHeader>, [u8; 32]) {
        let mut headers = vec![h_dep];
        for k in 0..depth {
            let child_id = super::super::anchor::ergo_header_id(&headers[0]).unwrap();
            let mut parent = a_header();
            parent.parent_id = ModifierId::from(child_id);
            parent.height = 2000 + k as u32;
            headers.insert(0, parent);
        }
        let ergo_ref = super::super::anchor::ergo_header_id(&headers[0]).unwrap();
        (headers, ergo_ref)
    }

    /// Assemble a single-peg-in backing witness for a well-formed deposit at
    /// `depth`, returning `(pi, witness, ergo_ref, params, box_id)`.
    fn build_backed_pegin(
        amount: u64,
        owner: Digest,
        depth: usize,
    ) -> (
        PegIn,
        PegInBackingWitness,
        [u8; 32],
        DepositParams,
        [u8; 32],
    ) {
        let tree = a_tree(true);
        let vault_bytes = tree_bytes(&tree);
        let candidate = deposit_candidate(&tree, amount, &owner, USE_TOKEN);
        let tx = a_tx(candidate.clone());
        let tx_bytes = tx_bytes_of(&tx);
        let txid = transaction_id(&tx).unwrap();
        let box_id = *ErgoBox {
            candidate,
            transaction_id: txid,
            index: 0,
        }
        .box_id()
        .unwrap()
        .as_bytes();

        let (proof, tx_root) = tx_inclusion(txid.as_bytes(), &[0x22; 31]);
        let mut h_dep = a_header();
        h_dep.transactions_root = Digest32::from_bytes(tx_root);
        let (headers, ergo_ref) = deposit_walk(h_dep, depth);

        // Honest one-mint-ever path against an empty set (no prior settled keys).
        let mut set = SettledSet::new();
        let key = pegin_used_key(&box_id);
        let used_path = set.witness(&key);
        set.insert(&key);

        let pi = PegIn {
            box_id,
            dest_owner: owner,
            amount,
        };
        let wit = PegInBackingWitness {
            deposit_headers: headers,
            deposits: vec![DepositProof {
                tx_bytes,
                output_index: 0,
                tx_merkle_proof: proof,
                dep_header_index: depth,
                used_path,
            }],
        };
        let params = DepositParams {
            vault_tree_bytes: vault_bytes,
            use_token_id: USE_TOKEN,
            pegin_confirmations: CONFIRMATIONS,
        };
        (pi, wit, ergo_ref, params, box_id)
    }

    fn one_block(pi: PegIn) -> Vec<SuffixBlock> {
        vec![SuffixBlock {
            height: 1,
            prev_header_id: [0; 32],
            prev_root: [F::ZERO; 8],
            state_root: [F::ZERO; 8],
            timestamp_ms: 0,
            sc_nbits: 0,
            txs: vec![],
            pegouts: vec![],
            pegins: vec![pi],
            miner_owner: [F::ZERO; 8],
            coinbase_amount: 0,
            coinbase_cm: [F::ZERO; 8],
            coinbase_is_reward: true,
            pot_after: 0,
            shielded_after: 0,
        }]
    }

    // ----- happy path -----

    #[test]
    fn a_real_backed_deposit_mints() {
        let owner = owner_digest(500);
        let (pi, wit, ergo_ref, params, box_id) = build_backed_pegin(2000, owner, CONFIRMATIONS);
        let blocks = one_block(pi);
        let root = verify_pegin_backing(&blocks, &wit, &ergo_ref, empty_settled_root(), &params)
            .expect("a real, buried, well-formed deposit mints");
        // R6 advanced by exactly the peg-in key.
        let mut set = SettledSet::new();
        set.insert(&pegin_used_key(&box_id));
        assert_eq!(root, set.root());
    }

    #[test]
    fn no_pegins_leaves_r6_unchanged() {
        let wit = PegInBackingWitness {
            deposit_headers: vec![],
            deposits: vec![],
        };
        let blocks = vec![SuffixBlock {
            pegins: vec![],
            ..one_block(PegIn {
                box_id: [0; 32],
                dest_owner: owner_digest(1),
                amount: 1,
            })
            .pop()
            .unwrap()
        }];
        let r = verify_pegin_backing(
            &blocks,
            &wit,
            &[0; 32],
            empty_settled_root(),
            &DepositParams {
                vault_tree_bytes: vec![],
                use_token_id: USE_TOKEN,
                pegin_confirmations: CONFIRMATIONS,
            },
        )
        .expect("a suffix with no peg-ins never touches R6");
        assert_eq!(r, empty_settled_root());
    }

    // ----- error paths: the fabrication vectors -----

    #[test]
    fn an_unbacked_pegin_dies_at_tx_inclusion() {
        // No real deposit: the tx is not provably in any canonical block —
        // model it as an inclusion proof that does not reduce to H_dep's
        // transactions_root (a corrupted sibling), leaving the walk intact so
        // the failure is the tx-inclusion check, not the linkage.
        let owner = owner_digest(1);
        let (pi, mut wit, ergo_ref, params, _) = build_backed_pegin(2000, owner, CONFIRMATIONS);
        // The txid leaf still recomputes (leaf binding passes), but the path no
        // longer reduces to the anchored transactions_root.
        wit.deposits[0].tx_merkle_proof.proofs[0].digest = Some([0xAB; 32]);
        let blocks = one_block(pi);
        assert_eq!(
            verify_pegin_backing(&blocks, &wit, &ergo_ref, empty_settled_root(), &params),
            Err(PegInError::ProofInvalid { i: 0 }),
            "an unbacked peg-in has no tx included in the anchored canonical chain"
        );
    }

    #[test]
    fn a_witness_leaf_proof_is_rejected() {
        // The Scala /proofFor trap: a proof whose leaf is the WITNESS-id leaf
        // (not the txid leaf) cannot satisfy the recomputed-txid-leaf binding.
        let owner = owner_digest(2);
        let (pi, mut wit, ergo_ref, params, _) = build_backed_pegin(2000, owner, CONFIRMATIONS);
        // Replace the proof with one proving the witness-id leaf (index 1).
        let tx = {
            let mut r = VlqReader::new(&wit.deposits[0].tx_bytes);
            read_transaction(&mut r).unwrap()
        };
        let txid = *transaction_id(&tx).unwrap().as_bytes();
        let witness_id = [0x22u8; 31];
        let leaves: Vec<&[u8]> = vec![&txid[..], &witness_id[..]];
        let (indices, raw) = merkle_proof_by_indices(&leaves, &[1]).unwrap();
        wit.deposits[0].tx_merkle_proof = BatchMerkleProof {
            indices,
            proofs: raw
                .into_iter()
                .map(|e| ProofEntry {
                    digest: e.digest,
                    side: Side::from_byte(e.side),
                })
                .collect(),
        };
        let blocks = one_block(pi);
        assert_eq!(
            verify_pegin_backing(&blocks, &wit, &ergo_ref, empty_settled_root(), &params),
            Err(PegInError::ProofLeafMismatch { i: 0 }),
            "a witness-leaf proof cannot pass the recomputed txid-leaf binding"
        );
    }

    #[test]
    fn a_shallow_deposit_dies_at_confirmation_depth() {
        let owner = owner_digest(3);
        // Buried only CONFIRMATIONS-1 deep.
        let (pi, wit, ergo_ref, params, _) = build_backed_pegin(2000, owner, CONFIRMATIONS - 1);
        let blocks = one_block(pi);
        assert_eq!(
            verify_pegin_backing(&blocks, &wit, &ergo_ref, empty_settled_root(), &params),
            Err(PegInError::InsufficientConfirmations {
                i: 0,
                depth: CONFIRMATIONS - 1,
                need: CONFIRMATIONS
            }),
        );
    }

    #[test]
    fn wrong_vault_tree_dies() {
        let owner = owner_digest(4);
        let (pi, wit, ergo_ref, mut params, _) = build_backed_pegin(2000, owner, CONFIRMATIONS);
        params.vault_tree_bytes = tree_bytes(&a_tree(false)); // a different tree
        let blocks = one_block(pi);
        assert_eq!(
            verify_pegin_backing(&blocks, &wit, &ergo_ref, empty_settled_root(), &params),
            Err(PegInError::WrongVaultTree { i: 0 }),
        );
    }

    #[test]
    fn wrong_use_token_dies() {
        let owner = owner_digest(5);
        let (pi, wit, ergo_ref, mut params, _) = build_backed_pegin(2000, owner, CONFIRMATIONS);
        params.use_token_id = [0x99; 32]; // not the deposit's token
        let blocks = one_block(pi);
        assert_eq!(
            verify_pegin_backing(&blocks, &wit, &ergo_ref, empty_settled_root(), &params),
            Err(PegInError::WrongUseToken { i: 0 }),
        );
    }

    #[test]
    fn wrong_amount_dies_at_use_token() {
        let owner = owner_digest(6);
        let (mut pi, wit, ergo_ref, params, _) = build_backed_pegin(2000, owner, CONFIRMATIONS);
        pi.amount = 2001; // deposit carries 2000
        let blocks = one_block(pi);
        assert_eq!(
            verify_pegin_backing(&blocks, &wit, &ergo_ref, empty_settled_root(), &params),
            Err(PegInError::WrongUseToken { i: 0 }),
        );
    }

    #[test]
    fn wrong_dest_owner_dies() {
        let owner = owner_digest(7);
        let (mut pi, wit, ergo_ref, params, _) = build_backed_pegin(2000, owner, CONFIRMATIONS);
        pi.dest_owner = owner_digest(999); // not the R4 owner
                                           // Recompute box_id would also change, but dest_owner is checked before
                                           // box_id, so this fires at DestOwnerMismatch.
        let blocks = one_block(pi);
        assert_eq!(
            verify_pegin_backing(&blocks, &wit, &ergo_ref, empty_settled_root(), &params),
            Err(PegInError::DestOwnerMismatch { i: 0 }),
        );
    }

    #[test]
    fn wrong_box_id_dies() {
        let owner = owner_digest(8);
        let (mut pi, wit, ergo_ref, params, _) = build_backed_pegin(2000, owner, CONFIRMATIONS);
        pi.box_id = [0xEE; 32]; // an imaginary box id
        let blocks = one_block(pi);
        assert_eq!(
            verify_pegin_backing(&blocks, &wit, &ergo_ref, empty_settled_root(), &params),
            Err(PegInError::BoxIdMismatch { i: 0 }),
        );
    }

    #[test]
    fn one_imaginary_box_id_minted_every_block_dies_at_in_suffix_dedup() {
        // F6e: the same box id in two suffix blocks is rejected in-suffix.
        let owner = owner_digest(9);
        let (pi, wit1, ergo_ref, params, _) = build_backed_pegin(2000, owner, CONFIRMATIONS);
        let mut blocks = one_block(pi.clone());
        blocks.push(blocks[0].clone()); // second block re-mints the same box id
                                        // Provide two deposit proofs (count must match) — reuse the same one.
        let mut wit = wit1;
        wit.deposits.push(wit.deposits[0].clone());
        assert_eq!(
            verify_pegin_backing(&blocks, &wit, &ergo_ref, empty_settled_root(), &params),
            Err(PegInError::DuplicateInSuffix {
                i: 1,
                box_id: pi.box_id
            }),
        );
    }

    #[test]
    fn re_minting_an_already_settled_deposit_dies_at_r6() {
        // Cross-settlement one-mint-ever: the deposit's key is already in R6.
        let owner = owner_digest(10);
        let (pi, mut wit, ergo_ref, params, box_id) =
            build_backed_pegin(2000, owner, CONFIRMATIONS);

        // R6 already contains this deposit's key (minted in a prior settlement).
        let mut set = SettledSet::new();
        let key = pegin_used_key(&box_id);
        set.insert(&key);
        let root_in = set.root();
        // The presented non-membership path is now a MEMBER path.
        wit.deposits[0].used_path = set.witness(&key);

        let blocks = one_block(pi);
        assert_eq!(
            verify_pegin_backing(&blocks, &wit, &ergo_ref, root_in, &params),
            Err(PegInError::AlreadyMinted { i: 0 }),
            "a deposit minted in a prior settlement cannot be minted again"
        );
    }

    #[test]
    fn deposit_count_mismatch_dies() {
        let owner = owner_digest(11);
        let (pi, mut wit, ergo_ref, params, _) = build_backed_pegin(2000, owner, CONFIRMATIONS);
        wit.deposits.clear(); // zero proofs for one peg-in
        let blocks = one_block(pi);
        assert_eq!(
            verify_pegin_backing(&blocks, &wit, &ergo_ref, empty_settled_root(), &params),
            Err(PegInError::DepositCountMismatch { got: 0, want: 1 }),
        );
    }

    // ----- round-trips -----

    #[test]
    fn pegin_backing_wire_roundtrip() {
        // The guest reads the wire form; an honest backing must still verify
        // after from_witness → postcard → into_witness.
        use super::super::aux_wire::PegInBackingWitnessWire;
        let owner = owner_digest(321);
        let (pi, wit, ergo_ref, params, box_id) = build_backed_pegin(2000, owner, CONFIRMATIONS);

        let wire = PegInBackingWitnessWire::from_witness(&wit);
        let bytes = postcard::to_allocvec(&wire).expect("wire serializes");
        let back: PegInBackingWitnessWire =
            postcard::from_bytes(&bytes).expect("wire deserializes");
        let wit2 = back.into_witness();

        let blocks = one_block(pi);
        let root = verify_pegin_backing(&blocks, &wit2, &ergo_ref, empty_settled_root(), &params)
            .expect("round-tripped backing still mints");
        let mut set = SettledSet::new();
        set.insert(&pegin_used_key(&box_id));
        assert_eq!(root, set.root());
    }

    // ----- oracle parity: the Ergo box-id rule on real mainnet bytes -----

    #[test]
    fn box_id_matches_ergo_oracle_block_700000() {
        // The box-id weld (step 4) must be byte-exact with Ergo's own rule.
        // Oracle: tx cba71e32… from mainnet block 700000, with explorer-known
        // tx id and output box ids (the exact vector `ergo-ser` pins). Derived
        // from real Ergo bytes — never a self-oracle.
        let tx_hex = "02ff30511557bab24769274ad8b31be7bfb791608c695b70950957ed655f630def38dcf11cccad217fd3120f2abcc0b706e2916630a1f266bfba18a47f849f1dcce0b4c00ab4a52f5d888d42014ac9b98349f210b2ad827ebcbf0028b111fcc692be6be99cd29bde11fd10435df815163ba8b3227c834af042686238ce430d0d57d5ae3b908655ddc769a1ea95ee76d97adce01a2333c56905af3d13ca2262f3d2fbbd8757cfe40687e1ff59569b1e5d8b55a1b00001c57f8a9938e16575413ae6fa00eb45686e8e4158a6dd2b20904e078f4b675743018c27dd9d8a35aac1e3167d58858c0a8b4059b277da790552e37eba22df9b903503c0843d100504000400050004000e20011d3364de07e5a26f0c4eef0852cddb387039a921b7154ef3cab22c6eda887fd803d601b2a5730000d602e4c6a70407d603b2db6501fe730100ea02d1ededededed93e4c672010407720293e4c67201050ec5720391e4c672010605730293c27201c2a793db63087201db6308a7938cb2db63087203730300017304cd7202dedc2a01000103070331b99a9fcc7bceb0a238446cdab944402dd4b2e79f9dcab898ec3b46aea285c80e20c57f8a9938e16575413ae6fa00eb45686e8e4158a6dd2b20904e078f4b675743058ec7faaa02e091431005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304dedc2a0000a0a489ce210008cd0333920f80ca39477cb57ccdff9847ed6cbd46cf2c7237b6b085979622349910e9dedc2a0000";
        let tx_bytes = hex::decode(tx_hex).unwrap();
        let mut r = VlqReader::new(&tx_bytes);
        let tx = read_transaction(&mut r).unwrap();
        assert!(r.is_empty());
        let txid = transaction_id(&tx).unwrap();
        assert_eq!(
            hex::encode(txid.as_bytes()),
            "cba71e328904bfc47b02b4b573fa654ad53db2df19e24a76edbbf3c929336c06"
        );
        let expected = [
            "aa61e97c00978fab96e905d76d13c1e8b1f95812837bb56f90adf1ffcbd63d4f",
            "e2fd3036020836e40d1fb22095fd632eb4a9386c3063db7aa51bb64817a11414",
            "e6eca48a4ac4608fc6ac6abd4668561416e2533348b4e2927058e0b8b8141477",
        ];
        for (idx, want) in expected.iter().enumerate() {
            let ebox = ErgoBox {
                candidate: tx.output_candidates[idx].clone(),
                transaction_id: txid,
                index: idx as u16,
            };
            assert_eq!(hex::encode(ebox.box_id().unwrap().as_bytes()), *want);
        }
    }
}
