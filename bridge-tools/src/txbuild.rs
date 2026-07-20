//! Devnet transaction assembly: EIP-4 mints, vault deploy, deposits, and the
//! verifyStark release tx (script-only spend, proof chunked into the context
//! extension). Wallet-signed txs go unsigned-bytes → `/wallet/transaction/sign`
//! → `/transactions/bytes`; the release needs no signature at all.

use anyhow::{anyhow, Context, Result};
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, DataInput, Input, SpendingProof, UnsignedInput};
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaValue};
use ergo_ser::token::{Token, TokenId};
use ergo_ser::transaction::{
    transaction_id, write_transaction, write_unsigned_transaction, Transaction, UnsignedTransaction,
};

/// Standard miner-fee proposition (mainnet/testnet-identical; oracle-pinned in
/// ergo-api).
pub const FEE_TREE_HEX: &str = "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304";

/// Standard fee (nanoErg) — generous for a difficulty-1 devnet.
pub const FEE_NANOERG: u64 = 1_000_000;

/// Min ERG we put on token-carrying boxes.
pub const BOX_ERG: u64 = 100_000_000; // 0.1 ERG

pub fn tree_of(bytes: &[u8]) -> Result<ergo_ser::ergo_tree::ErgoTree> {
    let mut r = VlqReader::new(bytes);
    read_ergo_tree(&mut r).map_err(|e| anyhow!("parse ergo tree: {e:?}"))
}

pub fn candidate(
    value: u64,
    tree_bytes: &[u8],
    height: u32,
    tokens: Vec<Token>,
    registers: Vec<RegisterValue>,
) -> Result<ErgoBoxCandidate> {
    ErgoBoxCandidate::new(
        value,
        tree_of(tree_bytes)?,
        height,
        tokens,
        AdditionalRegisters { registers },
    )
    .map_err(|e| anyhow!("candidate: {e:?}"))
}

pub fn fee_candidate(height: u32) -> Result<ErgoBoxCandidate> {
    candidate(
        FEE_NANOERG,
        &hex::decode(FEE_TREE_HEX).expect("fee tree hex"),
        height,
        vec![],
        vec![],
    )
}

pub fn coll_byte_reg(bytes: &[u8]) -> RegisterValue {
    RegisterValue {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        value: SigmaValue::Coll(CollValue::Bytes(bytes.to_vec())),
    }
}

pub fn long_reg(v: i64) -> RegisterValue {
    RegisterValue {
        tpe: SigmaType::SLong,
        value: SigmaValue::Long(v),
    }
}

pub fn unsigned_hex(tx: &UnsignedTransaction) -> Result<String> {
    let mut w = VlqWriter::new();
    write_unsigned_transaction(&mut w, tx).map_err(|e| anyhow!("ser unsigned: {e:?}"))?;
    Ok(hex::encode(w.result()))
}

pub fn signed_bytes(tx: &Transaction) -> Result<Vec<u8>> {
    let mut w = VlqWriter::new();
    write_transaction(&mut w, tx).map_err(|e| anyhow!("ser signed: {e:?}"))?;
    Ok(w.result())
}

fn digest32(hex_s: &str) -> Result<Digest32> {
    let b: [u8; 32] = hex::decode(hex_s)
        .context("hex")?
        .try_into()
        .map_err(|_| anyhow!("need 32 bytes"))?;
    Ok(Digest32::from_bytes(b))
}

/// Compute the box id of output `index` of a SIGNED tx.
pub fn output_box_id(tx_bytes: &[u8], index: u16) -> Result<String> {
    let mut r = VlqReader::new(tx_bytes);
    let tx = ergo_ser::transaction::read_transaction(&mut r)
        .map_err(|e| anyhow!("parse signed tx: {e:?}"))?;
    let txid: ModifierId = transaction_id(&tx).map_err(|e| anyhow!("txid: {e:?}"))?;
    let eb = ErgoBox {
        candidate: tx
            .output_candidates
            .get(index as usize)
            .cloned()
            .ok_or_else(|| anyhow!("no output {index}"))?,
        transaction_id: txid,
        index,
    };
    Ok(hex::encode(
        eb.box_id().map_err(|e| anyhow!("{e:?}"))?.as_bytes(),
    ))
}

/// The EIP-4 token metadata for a mint.
pub struct MintSpec {
    pub supply: u64,
    pub name: String,
    pub description: String,
    pub decimals: u8,
}

/// An EIP-4 mint of `spec.supply` units to `dest_tree`, spending the pure-ERG
/// wallet box `(input_id, input_value)`. Token id = the input box id.
pub fn build_mint(
    input_id: &str,
    input_value: u64,
    dest_tree: &[u8],
    spec: &MintSpec,
    height: u32,
) -> Result<(UnsignedTransaction, String)> {
    let token_id = TokenId::from_bytes(*digest32(input_id)?.as_bytes());
    let token_out = candidate(
        input_value - FEE_NANOERG,
        dest_tree,
        height,
        vec![Token {
            token_id,
            amount: spec.supply,
        }],
        vec![
            coll_byte_reg(spec.name.as_bytes()),
            coll_byte_reg(spec.description.as_bytes()),
            coll_byte_reg(spec.decimals.to_string().as_bytes()),
        ],
    )?;
    let tx = UnsignedTransaction {
        inputs: vec![UnsignedInput {
            box_id: digest32(input_id)?,
            extension: ContextExtension::empty(),
        }],
        data_inputs: vec![],
        output_candidates: vec![token_out, fee_candidate(height)?],
    };
    Ok((tx, input_id.to_string()))
}

/// Inputs spec for a wallet-signed transfer: `(box_id, value, tokens)`.
pub struct InBox {
    pub id: String,
    pub value: u64,
    pub tokens: Vec<Token>,
}

/// Build a wallet-signed tx that sends `send_tokens` + `send_value` to
/// `dest_tree` with `dest_registers`, returning all remaining ERG/tokens to
/// `change_tree`.
#[allow(clippy::too_many_arguments)]
pub fn build_send(
    ins: Vec<InBox>,
    dest_tree: &[u8],
    dest_registers: Vec<RegisterValue>,
    send_value: u64,
    send_tokens: Vec<Token>,
    change_tree: &[u8],
    height: u32,
) -> Result<UnsignedTransaction> {
    let total_in: u64 = ins.iter().map(|i| i.value).sum();
    let change_value = total_in
        .checked_sub(send_value + FEE_NANOERG)
        .ok_or_else(|| anyhow!("insufficient ERG"))?;
    // Change tokens = inputs − sent, per token id.
    let mut change: Vec<Token> = vec![];
    for i in &ins {
        for t in &i.tokens {
            match change.iter_mut().find(|c| c.token_id == t.token_id) {
                Some(c) => c.amount += t.amount,
                None => change.push(t.clone()),
            }
        }
    }
    for s in &send_tokens {
        let c = change
            .iter_mut()
            .find(|c| c.token_id == s.token_id)
            .ok_or_else(|| anyhow!("sending a token not present in inputs"))?;
        c.amount = c
            .amount
            .checked_sub(s.amount)
            .ok_or_else(|| anyhow!("insufficient token balance"))?;
    }
    change.retain(|c| c.amount > 0);

    let dest = candidate(send_value, dest_tree, height, send_tokens, dest_registers)?;
    let chg = candidate(change_value, change_tree, height, change, vec![])?;
    Ok(UnsignedTransaction {
        inputs: ins
            .into_iter()
            .map(|i| {
                Ok(UnsignedInput {
                    box_id: digest32(&i.id)?,
                    extension: ContextExtension::empty(),
                })
            })
            .collect::<Result<_>>()?,
        data_inputs: vec![],
        output_candidates: vec![dest, chg, fee_candidate(height)?],
    })
}

/// The release tx: spend the vault box (script-only — empty proof, proof
/// chunks in context-extension var 0) into successor + recipient + fee.
#[allow(clippy::too_many_arguments)]
pub fn build_release(
    vault_box_id: &str,
    vault_value: u64,
    vault_tokens: Vec<Token>, // [(NFT,1),(USE,N)]
    vault_tree: &[u8],
    prev_root: &[u8; 32],
    new_root: &[u8; 32],
    counter: i64,
    use_id: [u8; 32],
    amount: u64,
    recipient_tree: &[u8],
    receipt: &[u8],
    height: u32,
) -> Result<Transaction> {
    let (var_tpe, var_val) = crate::vault::chunk_proof(receipt);
    let mut ext = ContextExtension::empty();
    ext.values.insert(0u8, (var_tpe, var_val));

    let use_in = vault_tokens
        .iter()
        .find(|t| *t.token_id.as_bytes() == use_id)
        .map(|t| t.amount)
        .ok_or_else(|| anyhow!("vault box carries no USE"))?;
    let nft = vault_tokens
        .iter()
        .find(|t| *t.token_id.as_bytes() != use_id)
        .cloned()
        .ok_or_else(|| anyhow!("vault box carries no NFT"))?;

    let successor = candidate(
        vault_value - FEE_NANOERG - BOX_ERG,
        vault_tree,
        height,
        vec![
            nft,
            Token {
                token_id: TokenId::from_bytes(use_id),
                amount: use_in
                    .checked_sub(amount)
                    .ok_or_else(|| anyhow!("vault underfunded for the withdrawal"))?,
            },
        ],
        vec![coll_byte_reg(new_root), long_reg(counter + 1)],
    )?;
    let _ = prev_root; // (bound in the journal by the guest; kept for the caller's clarity)
    let recipient = candidate(
        BOX_ERG,
        recipient_tree,
        height,
        vec![Token {
            token_id: TokenId::from_bytes(use_id),
            amount,
        }],
        vec![],
    )?;
    Ok(Transaction {
        inputs: vec![Input {
            box_id: digest32(vault_box_id)?,
            spending_proof: SpendingProof::new(vec![], ext).map_err(|e| anyhow!("{e:?}"))?,
        }],
        data_inputs: vec![],
        output_candidates: vec![successor, recipient, fee_candidate(height)?],
    })
}

/// One settled withdrawal in an epoch release: `amount` USE to `recipient_tree`.
pub struct EpochWithdrawal {
    pub amount: u64,
    pub recipient_tree: Vec<u8>,
}

/// The epoch-validity release tx (`vault_epoch` predicate): spend the vault box
/// (script-only — empty proof, proof chunks in context-extension var 0) into a
/// successor carrying the advanced R4/R5/R6/R7, N recipient outputs, and the
/// fee box (always last). The `AEGISPV1` journal the guest committed is
/// reconstructed by the contract from exactly this shape (design §2.2).
///
/// The E4 `ergo_ref` anchor is NOT a tx element: the contract splices it from
/// `CONTEXT.headers` at validation time, so the caller's job is only to have
/// the release land in a block whose recent-header window carries the anchor
/// the receipt committed (operational; see `vault_epoch::ANCHOR_HEADER_INDEX`).
#[allow(clippy::too_many_arguments)]
pub fn build_release_epoch(
    vault_box_id: &str,
    vault_value: u64,
    vault_tokens: Vec<Token>, // [(NFT,1),(USE,N)]
    vault_tree: &[u8],
    new_root: &[u8; 32],
    settled_root_out: &[u8; 32],
    tip_id_new: &[u8; 32],
    counter_prev: i64, // vault R5; successor R5 = counter_prev + n
    use_id: [u8; 32],
    withdrawals: &[EpochWithdrawal],
    receipt: &[u8],
    height: u32,
) -> Result<Transaction> {
    let n = withdrawals.len();
    if n == 0 {
        return Err(anyhow!("epoch release needs >= 1 withdrawal"));
    }
    let (var_tpe, var_val) = crate::vault_epoch::chunk_proof(receipt);
    let mut ext = ContextExtension::empty();
    ext.values.insert(0u8, (var_tpe, var_val));

    let use_in = vault_tokens
        .iter()
        .find(|t| *t.token_id.as_bytes() == use_id)
        .map(|t| t.amount)
        .ok_or_else(|| anyhow!("vault box carries no USE"))?;
    let nft = vault_tokens
        .iter()
        .find(|t| *t.token_id.as_bytes() != use_id)
        .cloned()
        .ok_or_else(|| anyhow!("vault box carries no NFT"))?;

    let total_out: u64 = withdrawals.iter().map(|w| w.amount).sum();
    let successor = candidate(
        vault_value - FEE_NANOERG - BOX_ERG * (n as u64),
        vault_tree,
        height,
        vec![
            nft,
            Token {
                token_id: TokenId::from_bytes(use_id),
                amount: use_in
                    .checked_sub(total_out)
                    .ok_or_else(|| anyhow!("vault underfunded for the batch"))?,
            },
        ],
        vec![
            coll_byte_reg(new_root),           // R4
            long_reg(counter_prev + n as i64), // R5
            coll_byte_reg(settled_root_out),   // R6
            coll_byte_reg(tip_id_new),         // R7
        ],
    )?;

    let mut outputs = vec![successor];
    for w in withdrawals {
        outputs.push(candidate(
            BOX_ERG,
            &w.recipient_tree,
            height,
            vec![Token {
                token_id: TokenId::from_bytes(use_id),
                amount: w.amount,
            }],
            vec![],
        )?);
    }
    outputs.push(fee_candidate(height)?);

    Ok(Transaction {
        inputs: vec![Input {
            box_id: digest32(vault_box_id)?,
            spending_proof: SpendingProof::new(vec![], ext).map_err(|e| anyhow!("{e:?}"))?,
        }],
        data_inputs: vec![],
        output_candidates: outputs,
    })
}

/// Data-input free re-export so main.rs needn't import ergo-ser directly.
pub fn no_data_inputs() -> Vec<DataInput> {
    vec![]
}
