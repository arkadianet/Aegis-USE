//! PegMint steps 5–9 — the tx/box/receipt/used-set half of the peg-in
//! verifier (`dev-docs/sidechain/g25-pegmint-packaging.md` §5, built to
//! the adversarially-reviewed schema of 2026-07-13).
//!
//! ⚠⚠ **DO NOT WIRE THIS TO REAL VALUE YET.** This module is a PURE
//! verifier: no node/network I/O, no clock, no ErgoScript re-execution,
//! no consensus wiring (the used-set/pot consensus state and the
//! block-apply path are a separate reviewed step). The whole of steps
//! 5–9 is a deterministic function of
//! `(PegMintProof, ComparativeAnchor, used_set, params)`.
//!
//! Review-pinned contracts enforced here:
//!
//! - **(P1-A binding, §5.2.2)** BOTH tx-inclusion headers resolve
//!   through [`ComparativeAnchor::settled_view`] — the header id is
//!   RE-DERIVED from the carried header bytes (`serialize_header`) and
//!   membership-checked at its own height; nothing above `h_ref` (the
//!   proof's un-objectified suffix) is ever consulted, so a privately
//!   mined suffix cannot host a fake consolidation.
//! - **(Leaf binding, §5.2.5)** the batch-merkle leaf digest is
//!   recomputed as `Blake2b256(0x00 ‖ transaction_id(tx))` from the
//!   parsed tx — never read from the attacker-supplied proof — and the
//!   proof reduces to the CARRIED header's `transactions_root` (which
//!   the membership-checked header id commits).
//! - **(Merge-vs-refund discriminator, §5.4)** consumption of the
//!   receipt boxId alone is NOT sufficient (the receipt script also has
//!   a refund path): the consolidation tx's `OUTPUTS(0)` must carry the
//!   singleton peg-vault NFT at `tokens(0)`, mirroring the
//!   `mergedIntoVault` predicate of `DepositReceipt.es`.
//! - **(Fee = `min()`, §5.5/F2)** the peg-in fee is emission-pot
//!   credit, not I1 backing: `pot_credit = min(Σ fee-pot USE,
//!   peg_fee(N))` and a fee-less lock still mints (pot credit 0) —
//!   there is deliberately NO fee-shortfall rejection.
//! - **(DoS, §5.6)** size caps are enforced before any hashing;
//!   amount sums use widened/checked arithmetic. Fail-fast in step
//!   order, so the ERROR (not just accept/reject) is deterministic.
//!
//! Standing invariant (§5.9(5), chain-id-breaking): the deployed
//! `DepositReceipt.es` merge path's `mintable` predicate must remain a
//! SUPERSET of step 7 here — any step-7 tightening requires a matching
//! contract tightening, else a consolidatable-but-unmintable receipt
//! becomes permanent principal loss.
//!
//! [`PegParams`] pins (`use_token_id`, `peg_vault_nft`, script hashes)
//! are chain-id-breaking deploy constants; like the §2 anchor they
//! belong in `aegis-spec` at wiring time (values are still TBD —
//! params.md testnet stand-ins).

use std::collections::BTreeSet;

use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::merkle::tx_leaf_digest;
use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::batch_merkle_proof::{
    deserialize_batch_merkle_proof, serialize_batch_merkle_proof, BatchMerkleProof,
};
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::{read_header, serialize_header, Header};
use ergo_ser::popow_proof::{read_nipopow_proof, serialize_nipopow_proof, NipopowProof};
use ergo_ser::register::RegisterId;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaValue};
use ergo_ser::transaction::{read_transaction, transaction_id, Transaction};
use ergo_validation::popow::merkle::verify_batch_merkle_proof;

use crate::pegmint::{
    verify_ergo_chain_comparative, ComparativeAnchor, DifficultyParams, ErgoAnchor, InclusionRole,
    PegMintError,
};

// ----- §5.6 size / DoS bounds (consensus params in aegis-spec at wiring) -----

/// Envelope cap on a whole serialized [`PegMintProof`]. Single source
/// of truth in `aegis-spec` (the block codec caps each carried proof to
/// the same value).
pub use aegis_spec::MAX_PEGMINT_PROOF_BYTES;
/// Cap on the serialized NiPoPoW chain part (real continuous testnet
/// proof at tip 442825 measures ~90 KiB — see the e2e assertion).
pub const MAX_NIPOPOW_PROOF_BYTES: usize = 1024 * 1024;
/// Cap on one serialized inclusion header (real headers ~200–300 B).
pub const MAX_PEG_HEADER_BYTES: usize = 4096;
/// Cap on one inclusion tx's wire bytes. **Reject-valid note (§5.6):**
/// a legit consolidation above this cap can never mint (funds stay
/// safe-but-stranded in the vault), so consolidators must stay under
/// it; consensus param, not a tunable.
pub const MAX_PEG_TX_BYTES: usize = 1024 * 1024;
/// Cap on batch-merkle sibling entries (tree depth; real blocks ≤ ~2^20
/// txs → ≤ 21 levels).
pub const MAX_PEG_MERKLE_PROOF_ENTRIES: usize = 64;
/// Serialized batch-proof blob cap implied by "exactly 1 index +
/// ≤ 64 proof entries": `8 + 36 + 64×33`.
pub const MAX_PEG_MERKLE_PROOF_BYTES: usize = 8 + 36 + MAX_PEG_MERKLE_PROOF_ENTRIES * 33;

// ----- wire structs (§5.1) -----

/// One "tx T is in settled block B" claim. The FULL header is carried
/// because `SettledView` holds only id/height/μ-level — it has no
/// `transactions_root`. The header's id is re-derived by the verifier
/// and membership-checked against the settled view; since the id is
/// Blake2b256 of the full serialized header, membership-by-id commits
/// `transactions_root` (and everything else in the header). There are
/// NO free-standing `claimed_id`/`claimed_height` fields: both derive
/// from `header`, leaving no smuggleable wire surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInclusion {
    /// The block header the tx claims inclusion in.
    pub header: Header,
    /// Full signed tx wire bytes (decoded by the verifier via
    /// `read_transaction`; trailing bytes rejected).
    pub tx_bytes: Vec<u8>,
    /// Single-leaf batch merkle proof against `header.transactions_root`.
    pub proof: BatchMerkleProof,
}

/// The full peg-in mint proof (§5.1). `work` carries the steps-1–4
/// chain part; steps 5–9 ([`verify_pegmint`]) consume the
/// [`ComparativeAnchor`] the caller obtained by running
/// [`crate::pegmint::verify_ergo_chain_comparative`] **on this same
/// `work`** — that caller contract is what makes the two halves one
/// deterministic verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PegMintProof {
    /// Steps 1–4: NiPoPoW chain proof (verified separately, see above).
    pub work: NipopowProof,
    /// Step 5a/6a: the LOCK tx — supplies the receipt box CONTENT
    /// (sc_dest, N, script) as its output `receipt_output_index`.
    pub lock: TxInclusion,
    /// Index into the lock tx's `output_candidates`.
    pub receipt_output_index: u16,
    /// Step 5b/6b: the CONSOLIDATION tx — the mint commit-point
    /// (peg.md §3.1); spends the receipt at input
    /// `receipt_input_index` (Ergo tx inputs carry only boxIds).
    pub consolidation: TxInclusion,
    /// Index into the consolidation tx's `inputs`.
    pub receipt_input_index: u16,
}

// ----- params / state / effect (§1, §5.5) -----

/// Peg-in deploy pins + fee rule. Every field is chain-id-breaking
/// (§5.9(3)); frozen `aegis-spec` constants at wiring time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PegParams {
    /// USE token id the receipt must carry at `tokens(0)`.
    pub use_token_id: [u8; 32],
    /// Singleton PegVault NFT — the §5.4 merge-vs-refund discriminator.
    pub peg_vault_nft: [u8; 32],
    /// `blake2b256(serialized ErgoTree)` of the pinned
    /// `DepositReceipt.es` template (step 7.1; same preimage the vault
    /// hashes for `receiptSum`).
    pub deposit_receipt_script_hash: [u8; 32],
    /// `blake2b256(serialized ErgoTree)` of the pinned `FeePot.es`
    /// template (step 7.4 fee summing).
    pub fee_pot_script_hash: [u8; 32],
    /// Minimum peg fee in USE base units.
    pub peg_fee_floor: u64,
    /// Peg fee rate in basis points.
    pub peg_fee_rate_bps: u64,
}

impl PegParams {
    /// Peg fee for public amount `n`, with the SAME integer arithmetic
    /// as `PegVault.es` (`bpsFee = n * FEE_BPS / 10000L`, i.e. floor
    /// division, then `max(floor, bpsFee)`). Deliberately NOT
    /// `aegis_spec::NetworkParams::peg_fee`, which rounds UP — §5.5
    /// pins the vault's floor arithmetic for the verifier so the two
    /// ends of the peg agree on one number. Widened to `u128` so the
    /// multiply cannot overflow for any `u64` input.
    pub fn peg_fee(&self, n: u64) -> u64 {
        let bps = u128::from(n) * u128::from(self.peg_fee_rate_bps) / 10_000;
        // `V_cap`-scale inputs are far inside u64; saturate (still
        // deterministic) rather than panic on absurd configs.
        let bps = u64::try_from(bps).unwrap_or(u64::MAX);
        bps.max(self.peg_fee_floor)
    }
}

/// I2 replay state: receipt boxIds already minted against. Later a
/// versioned consensus set (rolled back like the nullifier set, §3);
/// here a minimal pure-value newtype so the verifier stays unwired.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PegMintUsedSet(BTreeSet<[u8; 32]>);

impl PegMintUsedSet {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `box_id` has already minted.
    pub fn contains(&self, box_id: &[u8; 32]) -> bool {
        self.0.contains(box_id)
    }

    /// Record a minted receipt boxId; `false` if already present.
    pub fn insert(&mut self, box_id: [u8; 32]) -> bool {
        self.0.insert(box_id)
    }

    /// Number of recorded boxIds.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no boxIds are recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What consensus applies on `Ok` (§1). `note_value` feeds the
/// already-reviewed public-value mint (`aegis-crypto::verify_mint`);
/// `box_id` is inserted into the used set; `rho_seed = box_id` ties
/// note uniqueness to the globally-unique Ergo boxId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PegMintEffect {
    /// `N` — the public locked amount in USE base units.
    pub note_value: u64,
    /// R4 receiver address core (33 bytes).
    pub sc_dest: [u8; 33],
    /// The consumed receipt boxId (used-set key, I2).
    pub box_id: [u8; 32],
    /// Proven peg-in fee credited to the emission pot
    /// (`min(paid, peg_fee(N))` — §5.5/F2, never a rejection).
    pub pot_credit: u64,
    /// Note `rho = rho_pegmint(box_id)` seed; equals `box_id`.
    pub rho_seed: [u8; 32],
}

// ----- envelope codec (§5.1 wire; §5.6 caps enforced at parse) -----

fn role_fields(role: InclusionRole) -> (&'static str, &'static str, &'static str) {
    match role {
        InclusionRole::Lock => ("lock.header", "lock.tx_bytes", "lock.proof"),
        InclusionRole::Consolidation => (
            "consolidation.header",
            "consolidation.tx_bytes",
            "consolidation.proof",
        ),
    }
}

fn read_blob<'a>(
    r: &mut VlqReader<'a>,
    field: &'static str,
    max: usize,
) -> Result<&'a [u8], PegMintError> {
    let len = r
        .get_u32_exact()
        .map_err(|_| PegMintError::MalformedProof { field })? as usize;
    if len > max {
        return Err(PegMintError::Oversize { field, len, max });
    }
    r.get_bytes(len)
        .map_err(|_| PegMintError::MalformedProof { field })
}

fn read_tx_inclusion(r: &mut VlqReader, role: InclusionRole) -> Result<TxInclusion, PegMintError> {
    let (hf, tf, pf) = role_fields(role);
    let header_bytes = read_blob(r, hf, MAX_PEG_HEADER_BYTES)?;
    let mut hr = VlqReader::new(header_bytes);
    let header = read_header(&mut hr).map_err(|_| PegMintError::MalformedProof { field: hf })?;
    if !hr.is_empty() {
        return Err(PegMintError::MalformedProof { field: hf });
    }
    let tx_bytes = read_blob(r, tf, MAX_PEG_TX_BYTES)?.to_vec();
    let proof_bytes = read_blob(r, pf, MAX_PEG_MERKLE_PROOF_BYTES)?;
    let proof = deserialize_batch_merkle_proof(proof_bytes)
        .map_err(|_| PegMintError::MalformedProof { field: pf })?;
    if proof.indices.len() != 1 {
        return Err(PegMintError::MalformedProof { field: pf });
    }
    if proof.proofs.len() > MAX_PEG_MERKLE_PROOF_ENTRIES {
        return Err(PegMintError::Oversize {
            field: pf,
            len: proof.proofs.len(),
            max: MAX_PEG_MERKLE_PROOF_ENTRIES,
        });
    }
    Ok(TxInclusion {
        header,
        tx_bytes,
        proof,
    })
}

/// Parse a [`PegMintProof`] from envelope wire bytes: VLQ-`u32`
/// length-prefixed blobs in §5.1 field order, `u16` indices, no
/// optional fields; trailing bytes and every §5.6 cap violation
/// reject BEFORE any hashing. Deterministic parse ⇒ the accept/reject
/// verdict (and error) is a function of the raw bytes.
pub fn read_pegmint_proof(bytes: &[u8]) -> Result<PegMintProof, PegMintError> {
    if bytes.len() > MAX_PEGMINT_PROOF_BYTES {
        return Err(PegMintError::Oversize {
            field: "proof",
            len: bytes.len(),
            max: MAX_PEGMINT_PROOF_BYTES,
        });
    }
    let mut r = VlqReader::new(bytes);
    let work_bytes = read_blob(&mut r, "work", MAX_NIPOPOW_PROOF_BYTES)?;
    let mut wr = VlqReader::new(work_bytes);
    let work =
        read_nipopow_proof(&mut wr).map_err(|_| PegMintError::MalformedProof { field: "work" })?;
    if !wr.is_empty() {
        return Err(PegMintError::MalformedProof { field: "work" });
    }
    let lock = read_tx_inclusion(&mut r, InclusionRole::Lock)?;
    let receipt_output_index = r.get_u16().map_err(|_| PegMintError::MalformedProof {
        field: "receipt_output_index",
    })?;
    let consolidation = read_tx_inclusion(&mut r, InclusionRole::Consolidation)?;
    let receipt_input_index = r.get_u16().map_err(|_| PegMintError::MalformedProof {
        field: "receipt_input_index",
    })?;
    if !r.is_empty() {
        return Err(PegMintError::MalformedProof {
            field: "trailing bytes",
        });
    }
    Ok(PegMintProof {
        work,
        lock,
        receipt_output_index,
        consolidation,
        receipt_input_index,
    })
}

fn write_blob(
    w: &mut VlqWriter,
    field: &'static str,
    max: usize,
    bytes: &[u8],
) -> Result<(), PegMintError> {
    if bytes.len() > max {
        return Err(PegMintError::Oversize {
            field,
            len: bytes.len(),
            max,
        });
    }
    w.put_u32(bytes.len() as u32);
    w.put_bytes(bytes);
    Ok(())
}

fn write_tx_inclusion(
    w: &mut VlqWriter,
    incl: &TxInclusion,
    role: InclusionRole,
) -> Result<(), PegMintError> {
    let (hf, tf, pf) = role_fields(role);
    let (header_bytes, _id) =
        serialize_header(&incl.header).map_err(|_| PegMintError::Serialize)?;
    write_blob(w, hf, MAX_PEG_HEADER_BYTES, &header_bytes)?;
    write_blob(w, tf, MAX_PEG_TX_BYTES, &incl.tx_bytes)?;
    let proof_bytes = serialize_batch_merkle_proof(&incl.proof);
    write_blob(w, pf, MAX_PEG_MERKLE_PROOF_BYTES, &proof_bytes)
}

/// Serialize a [`PegMintProof`] to the envelope wire form read by
/// [`read_pegmint_proof`]. Enforces the same §5.6 caps so an oversize
/// proof cannot even be emitted.
pub fn serialize_pegmint_proof(proof: &PegMintProof) -> Result<Vec<u8>, PegMintError> {
    let mut w = VlqWriter::new();
    let work_bytes = serialize_nipopow_proof(&proof.work).map_err(|_| PegMintError::Serialize)?;
    write_blob(&mut w, "work", MAX_NIPOPOW_PROOF_BYTES, &work_bytes)?;
    write_tx_inclusion(&mut w, &proof.lock, InclusionRole::Lock)?;
    w.put_u16(proof.receipt_output_index);
    write_tx_inclusion(&mut w, &proof.consolidation, InclusionRole::Consolidation)?;
    w.put_u16(proof.receipt_input_index);
    let out = w.result();
    if out.len() > MAX_PEGMINT_PROOF_BYTES {
        return Err(PegMintError::Oversize {
            field: "proof",
            len: out.len(),
            max: MAX_PEGMINT_PROOF_BYTES,
        });
    }
    Ok(out)
}

// ----- verifier: steps 0 + 5a/5b (§5.2) -----

/// §5.6 struct-level bounds, re-checked here so a directly-constructed
/// (non-wire) proof is bounded before any hashing, exactly like a
/// parsed one.
fn check_bounds(proof: &PegMintProof) -> Result<(), PegMintError> {
    for (incl, role) in [
        (&proof.lock, InclusionRole::Lock),
        (&proof.consolidation, InclusionRole::Consolidation),
    ] {
        let (_hf, tf, pf) = role_fields(role);
        if incl.tx_bytes.len() > MAX_PEG_TX_BYTES {
            return Err(PegMintError::Oversize {
                field: tf,
                len: incl.tx_bytes.len(),
                max: MAX_PEG_TX_BYTES,
            });
        }
        if incl.proof.proofs.len() > MAX_PEG_MERKLE_PROOF_ENTRIES {
            return Err(PegMintError::Oversize {
                field: pf,
                len: incl.proof.proofs.len(),
                max: MAX_PEG_MERKLE_PROOF_ENTRIES,
            });
        }
    }
    Ok(())
}

/// Steps 5a/5b for one inclusion claim (§5.2). Returns the decoded tx
/// and its recomputed 32-byte id.
///
/// Ordering is the schema's: (1) header id derived from the carried
/// header — never trusted; (2) settled membership at the header's own
/// height (P1-A: the view holds ONLY best-chain headers ≤ `h_ref`, so
/// one lookup enforces both "on the followed chain" and "settled");
/// (3) tx decode (trailing bytes reject); (4) tx id; (5) leaf digest
/// recomputed and REQUIRED to equal the proof's single claimed leaf —
/// the load-bearing line, since `verify_batch_merkle_proof` alone only
/// proves *some* leaves reduce to the root; (6) merkle reduction
/// against the carried header's `transactions_root`.
fn check_inclusion(
    incl: &TxInclusion,
    role: InclusionRole,
    view: &crate::ergo_follow::SettledView,
) -> Result<(Transaction, [u8; 32]), PegMintError> {
    let (hf, tf, _pf) = role_fields(role);
    // (1) header id: derived, never trusted.
    let (header_bytes, hid) =
        serialize_header(&incl.header).map_err(|_| PegMintError::Serialize)?;
    if header_bytes.len() > MAX_PEG_HEADER_BYTES {
        return Err(PegMintError::Oversize {
            field: hf,
            len: header_bytes.len(),
            max: MAX_PEG_HEADER_BYTES,
        });
    }
    // (2) settled membership (P1-A binding).
    if view.height_of(hid.as_bytes()) != Some(incl.header.height) {
        return Err(PegMintError::InclusionNotSettled {
            role,
            height: incl.header.height,
        });
    }
    // (3) tx decode; trailing bytes reject.
    let mut tr = VlqReader::new(&incl.tx_bytes);
    let tx = read_transaction(&mut tr).map_err(|_| PegMintError::MalformedProof { field: tf })?;
    if !tr.is_empty() {
        return Err(PegMintError::MalformedProof { field: tf });
    }
    // (4) tx id = Blake2b256(bytes_to_sign(tx)).
    let txid = transaction_id(&tx).map_err(|_| PegMintError::Serialize)?;
    let txid = *txid.as_bytes();
    // (5) leaf digest recomputed from the parsed tx — never read from
    // the wire — and bound to the proof's single claimed leaf. (A v2+
    // witness leaf has a 31-byte preimage, so it can never equal this
    // 32-byte-preimage digest without a Blake2b256 collision.)
    let leaf = tx_leaf_digest(&txid);
    if incl.proof.indices.len() != 1 || incl.proof.indices[0].1 != leaf {
        return Err(PegMintError::MalformedInclusionProof { role });
    }
    // (6) merkle reduction against the carried (membership-checked)
    // header's transactions_root.
    if !verify_batch_merkle_proof(&incl.proof, incl.header.transactions_root.as_bytes()) {
        return Err(PegMintError::TxNotInBlock { role });
    }
    Ok((tx, txid))
}

// ----- verifier: steps 6–9 (§5.3–§5.5) -----

/// Steps 6a/6b/7/8/9 over the two decoded txs (§5.3–§5.5). Pure over
/// `(txs, indices, used_set, params)` — no view access, callable only
/// after both inclusions settled.
fn receipt_steps(
    lock_tx: &Transaction,
    lock_txid: [u8; 32],
    receipt_output_index: u16,
    consolidation_tx: &Transaction,
    receipt_input_index: u16,
    used_set: &PegMintUsedSet,
    params: &PegParams,
) -> Result<PegMintEffect, PegMintError> {
    // 6a: receipt box reconstruction — content from the lock tx,
    // identity from (candidate, lock_txid, index).
    let candidate = lock_tx
        .output_candidates
        .get(usize::from(receipt_output_index))
        .ok_or(PegMintError::OutputIndexOutOfRange {
            got: receipt_output_index,
            len: lock_tx.output_candidates.len(),
        })?;
    let receipt = ErgoBox {
        candidate: candidate.clone(),
        transaction_id: ModifierId::from_bytes(lock_txid),
        index: receipt_output_index,
    };
    let receipt_box_id = *receipt
        .box_id()
        .map_err(|_| PegMintError::Serialize)?
        .as_bytes();

    // 6b: consumption — the consolidation tx must spend exactly this
    // boxId (peg.md §3.1 commit-point; Ergo single-spend then forbids a
    // later refund).
    let spent = consolidation_tx
        .inputs
        .get(usize::from(receipt_input_index))
        .ok_or(PegMintError::InputIndexOutOfRange {
            got: receipt_input_index,
            len: consolidation_tx.inputs.len(),
        })?;
    if *spent.box_id.as_bytes() != receipt_box_id {
        return Err(PegMintError::ReceiptNotConsumed);
    }
    // 6b: merge-vs-refund discriminator (§5.4) — consumption alone is
    // NOT enough: a timed-out refund also consumes the boxId. Mirror
    // the receipt's own `mergedIntoVault` predicate: OUTPUTS(0) carries
    // the singleton vault NFT at tokens(0), which (token conservation +
    // the mint rule) forces the genuine PegVault to be a spent input,
    // so its top-up accounting absorbed this receipt's USE.
    let vault_nft_at_out0 = consolidation_tx
        .output_candidates
        .first()
        .and_then(|out| out.tokens.first())
        .is_some_and(|t| *t.token_id.as_bytes() == params.peg_vault_nft);
    if !vault_nft_at_out0 {
        return Err(PegMintError::NotConsolidatedIntoVault);
    }

    // 7.1: script pin — load-bearing twice (§5.5): it makes the vault's
    // `receiptSum` argument include this box, and blocks fake-receipt
    // boxes whose USE the vault would not absorb.
    if blake2b256(candidate.ergo_tree_bytes()) != params.deposit_receipt_script_hash {
        return Err(PegMintError::WrongReceiptScript);
    }
    // 7.2: USE token at tokens(0), N > 0.
    let token = candidate.tokens.first().ok_or(PegMintError::WrongToken)?;
    if *token.token_id.as_bytes() != params.use_token_id {
        return Err(PegMintError::WrongToken);
    }
    let note_value = token.amount;
    if note_value == 0 {
        return Err(PegMintError::ZeroAmount);
    }
    // 7.3: sc_dest — R4 must be a Coll[Byte] constant of exactly 33 bytes.
    let sc_dest = match candidate.additional_registers.get(RegisterId::R4) {
        Some(rv) if rv.tpe == SigmaType::SColl(Box::new(SigmaType::SByte)) => match &rv.value {
            SigmaValue::Coll(CollValue::Bytes(b)) if b.len() == 33 => {
                let mut dest = [0u8; 33];
                dest.copy_from_slice(b);
                dest
            }
            _ => return Err(PegMintError::BadScDest),
        },
        _ => return Err(PegMintError::BadScDest),
    };
    // 7.4: peg-in fee — `min()`, NEVER reject on shortfall (F2): the
    // fee is emission-pot credit, not I1 backing; rejecting would let a
    // permissionless consolidator convert a fee-less lock into total
    // principal loss. Sum widened to u128 (255 tokens × u64 amounts per
    // output cannot overflow it).
    let mut fee_paid: u128 = 0;
    for out in &lock_tx.output_candidates {
        if blake2b256(out.ergo_tree_bytes()) == params.fee_pot_script_hash {
            for t in &out.tokens {
                if *t.token_id.as_bytes() == params.use_token_id {
                    fee_paid += u128::from(t.amount);
                }
            }
        }
    }
    let pot_credit = fee_paid.min(u128::from(params.peg_fee(note_value))) as u64;

    // 8: replay (I2), keyed on the consumed receipt boxId.
    if used_set.contains(&receipt_box_id) {
        return Err(PegMintError::AlreadyMinted);
    }

    // 9: emit.
    Ok(PegMintEffect {
        note_value,
        sc_dest,
        box_id: receipt_box_id,
        pot_credit,
        rho_seed: receipt_box_id,
    })
}

// ----- verifier: composition (§5) -----

/// Steps 5–9 of `verify_pegmint` (g25 §1a/§5), composed on top of the
/// steps-1–4 result.
///
/// **Caller contract:** `anchor` MUST be the [`ComparativeAnchor`]
/// returned by [`crate::pegmint::verify_ergo_chain_comparative`] for
/// `proof.work` — that call is steps 1–4 (PoW, NiPoPoW validity,
/// pinned-anchor equality, `N_mint` depth + followed-chain membership)
/// and its P1-A return type is what structurally prevents binding
/// inclusion above `h_ref`. This function never reads `proof.work`.
///
/// Pure: no node queries, no clock, no ErgoScript re-execution. Errors
/// are rejection verdicts; only the steps-1–4 `NotCaughtUp` (raised by
/// the caller's chain verification, not here) is a deferral.
pub fn verify_pegmint(
    proof: &PegMintProof,
    anchor: &ComparativeAnchor,
    used_set: &PegMintUsedSet,
    params: &PegParams,
) -> Result<PegMintEffect, PegMintError> {
    // Step 0 (residual): struct-level §5.6 bounds before any hashing.
    check_bounds(proof)?;
    // Steps 5a/6a-content + 5b: both inclusions must resolve through
    // the settled view (P1-A) — lock first, then consolidation (§5.2
    // check order; first error wins).
    let (lock_tx, lock_txid) =
        check_inclusion(&proof.lock, InclusionRole::Lock, &anchor.settled_view)?;
    let (consolidation_tx, _cons_txid) = check_inclusion(
        &proof.consolidation,
        InclusionRole::Consolidation,
        &anchor.settled_view,
    )?;
    // Steps 6–9.
    receipt_steps(
        &lock_tx,
        lock_txid,
        proof.receipt_output_index,
        &consolidation_tx,
        proof.receipt_input_index,
        used_set,
        params,
    )
}

/// The **whole** PegMint verifier, steps 1–9, with the steps-1–4 ↔
/// steps-5–9 binding made STRUCTURAL (review 2026-07-13 P2): it derives
/// the [`ComparativeAnchor`] from **`proof.work`** itself via
/// [`verify_ergo_chain_comparative`], then runs steps 5–9 against that
/// anchor — so a caller cannot pair a valid anchor with a foreign
/// chain's txs. This is the entry point a consensus integrator should
/// use; [`verify_pegmint`] (anchor supplied) stays for callers that
/// have already run steps 1–4 and for step-isolated testing.
///
/// `NotCaughtUp` from the steps-1–4 stage is a **deferral** (§2b.ii):
/// the follower must catch up to `H_ref` before an objective verdict
/// exists — the caller re-evaluates, never treats it as block-invalid.
#[allow(clippy::too_many_arguments)]
pub fn verify_pegmint_full(
    proof: &PegMintProof,
    ergo_anchor: &ErgoAnchor,
    diff: &DifficultyParams,
    n_mint: u64,
    follower: &crate::ergo_follow::Follower,
    used_set: &PegMintUsedSet,
    params: &PegParams,
) -> Result<PegMintEffect, PegMintError> {
    // Steps 1–4: bound to THIS proof's chain, yielding the settled,
    // membership-checked reference (P1-A). `proof.work` is now read.
    let anchor = verify_ergo_chain_comparative(&proof.work, ergo_anchor, diff, n_mint, follower)?;
    // Steps 5–9 against exactly that anchor.
    verify_pegmint(proof, &anchor, used_set, params)
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Shared builders for peg-mint proofs/anchors, reused by the
    //! state- and chain-layer apply tests (crate-internal).
    use super::*;
    use crate::ergo_follow::{Follower, SettledView};
    use crate::pegmint::comparative_policy;
    use ergo_crypto::merkle::merkle_proof_by_indices;
    use ergo_primitives::digest::{ADDigest, Digest32};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::batch_merkle_proof::{ProofEntry, Side};
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_ser::token::{Token, TokenId};
    use ergo_ser::transaction::write_transaction;

    // ----- helpers -----

    // == real-vector loaders (mainnet blocks 1..=10: real headers with
    // real PoW, and each block's single real tx with the node-reported
    // id — the oracle for txid / leaf / root parity) ==

    pub(crate) fn vectors_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test-vectors")
    }

    pub(crate) fn real_headers() -> Vec<Header> {
        let data = std::fs::read_to_string(vectors_dir().join("mainnet/headers_1_10.json"))
            .expect("read header vectors");
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

    /// `(node_reported_id_hex, wire_bytes)` for the single tx of each
    /// mainnet block 1..=10, in height order (asserted in the vector).
    pub(crate) fn real_txs() -> Vec<(String, Vec<u8>)> {
        let data = std::fs::read_to_string(vectors_dir().join("mainnet/transactions_1_10.json"))
            .expect("read tx vectors");
        let vectors: serde_json::Value = serde_json::from_str(&data).expect("parse");
        vectors
            .as_array()
            .expect("array")
            .iter()
            .enumerate()
            .map(|(i, v)| {
                assert_eq!(
                    v["height"].as_u64().expect("height"),
                    (i + 1) as u64,
                    "vector must be one tx per block, height-ordered"
                );
                (
                    v["id"].as_str().expect("id").to_string(),
                    hex::decode(v["bytes"].as_str().expect("bytes")).expect("hex"),
                )
            })
            .collect()
    }

    /// A real `ComparativeAnchor` produced by the ACTUAL steps-1–4
    /// policy over the ACTUAL follower: mainnet headers 1..=10 followed
    /// with `n_mint = 3` → `h_ref = 7`.
    pub(crate) fn real_anchor() -> ComparativeAnchor {
        let headers = real_headers();
        let mut f = Follower::new(3);
        for h in &headers {
            f.apply_header(h).expect("real header follows");
        }
        comparative_policy(&headers, 3, &f).expect("honest chain accepts")
    }

    /// Real inclusion claim for mainnet block `height`'s single tx:
    /// carried header from the vector, tx wire bytes from the vector,
    /// and the batch proof extracted from the block's real one-leaf tx
    /// tree (v1 blocks: leaves = tx ids only). The root is oracled
    /// against the PoW-committed `transactions_root` in
    /// `real_tx_root_matches_pow_committed_header`.
    pub(crate) fn real_inclusion(height: usize) -> TxInclusion {
        let headers = real_headers();
        let txs = real_txs();
        let (_id, tx_bytes) = &txs[height - 1];
        let mut r = VlqReader::new(tx_bytes);
        let tx = read_transaction(&mut r).expect("real tx decodes");
        let txid = *transaction_id(&tx).expect("txid").as_bytes();
        TxInclusion {
            header: headers[height - 1].clone(),
            tx_bytes: tx_bytes.clone(),
            proof: batch_proof_over(&[txid.to_vec()], 0),
        }
    }

    /// The real continuous testnet NiPoPoW proof (tip 442825) — carried
    /// as `PegMintProof.work` by composed tests. `verify_pegmint` never
    /// reads it (steps 1–4 are the caller's), but the wire struct is
    /// §5.1-complete.
    pub(crate) fn real_work() -> NipopowProof {
        let raw = std::fs::read_to_string(vectors_dir().join("testnet/nipopow/proof_m6_k10.json"))
            .expect("read nipopow vector");
        ergo_rest_json::decode_nipopow_proof_json(&raw).expect("captured proof decodes")
    }

    // == synthetic lock/consolidation machinery. The txs are built with
    // the REAL ergo-ser types and the tx id / box id / merkle root are
    // COMPUTED by the same algorithms the oracle-parity tests pin
    // against real mainnet data — structural tests, not self-oracles
    // (no `expected = my_fn(input)` assertion appears; expectations are
    // behavioral: accept/reject + effect arithmetic). ==

    pub(crate) const USE_ID: [u8; 32] = [0xAA; 32];
    pub(crate) const VAULT_NFT: [u8; 32] = [0xBB; 32];
    pub(crate) const N_LOCK: u64 = 50_000;
    pub(crate) const FEE_PAID: u64 = 400;

    /// Distinct minimal sigma-prop trees: `(has_size, value)` vary the
    /// serialized bytes, so script hashes differ per role.
    pub(crate) fn sigma_tree(has_size: bool, value: bool) -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(value)),
            },
        }
    }

    pub(crate) fn receipt_tree() -> ErgoTree {
        sigma_tree(true, true)
    }

    pub(crate) fn fee_pot_tree() -> ErgoTree {
        sigma_tree(false, true)
    }

    pub(crate) fn other_tree() -> ErgoTree {
        sigma_tree(true, false)
    }

    pub(crate) fn tree_hash(tree: &ErgoTree) -> [u8; 32] {
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, tree).expect("tree serializes");
        blake2b256(&w.result())
    }

    pub(crate) fn peg_params() -> PegParams {
        PegParams {
            use_token_id: USE_ID,
            peg_vault_nft: VAULT_NFT,
            deposit_receipt_script_hash: tree_hash(&receipt_tree()),
            fee_pot_script_hash: tree_hash(&fee_pot_tree()),
            peg_fee_floor: 100,
            peg_fee_rate_bps: 100,
        }
    }

    pub(crate) fn use_tokens(n: u64) -> Vec<Token> {
        vec![Token {
            token_id: TokenId::from_bytes(USE_ID),
            amount: n,
        }]
    }

    pub(crate) fn vault_out_tokens() -> Vec<Token> {
        vec![
            Token {
                token_id: TokenId::from_bytes(VAULT_NFT),
                amount: 1,
            },
            Token {
                token_id: TokenId::from_bytes(USE_ID),
                amount: N_LOCK,
            },
        ]
    }

    pub(crate) fn r4_coll_bytes(payload: Vec<u8>) -> AdditionalRegisters {
        AdditionalRegisters {
            registers: vec![RegisterValue {
                tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
                value: SigmaValue::Coll(CollValue::Bytes(payload)),
            }],
        }
    }

    pub(crate) fn dest33() -> Vec<u8> {
        vec![0x07; 33]
    }

    pub(crate) fn candidate(
        tree: ErgoTree,
        tokens: Vec<Token>,
        regs: AdditionalRegisters,
    ) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(1_000_000_000, tree, 100, tokens, regs).expect("candidate builds")
    }

    pub(crate) fn dummy_input(fill: u8) -> Input {
        Input {
            box_id: Digest32::from_bytes([fill; 32]),
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty())
                .expect("empty proof"),
        }
    }

    /// Lock tx: output 0 = receipt (USE `n`, R4 = `regs`), output 1 =
    /// fee-pot output carrying `fee` USE (omitted when `fee == 0`),
    /// output 2 = unrelated change.
    pub(crate) fn make_lock(n: u64, fee: u64, regs: AdditionalRegisters) -> Transaction {
        let mut outputs = vec![candidate(receipt_tree(), use_tokens(n), regs)];
        if fee > 0 {
            outputs.push(candidate(
                fee_pot_tree(),
                use_tokens(fee),
                AdditionalRegisters::empty(),
            ));
        }
        outputs.push(candidate(
            other_tree(),
            vec![],
            AdditionalRegisters::empty(),
        ));
        Transaction {
            inputs: vec![dummy_input(0x11)],
            data_inputs: vec![],
            output_candidates: outputs,
        }
    }

    /// Consolidation tx: spends `spent_box_id` at input 0 (plus a vault
    /// input at 1), OUTPUTS(0) carries `out0_tokens`.
    pub(crate) fn make_cons(spent_box_id: [u8; 32], out0_tokens: Vec<Token>) -> Transaction {
        Transaction {
            inputs: vec![
                Input {
                    box_id: Digest32::from_bytes(spent_box_id),
                    spending_proof: SpendingProof::new(vec![], ContextExtension::empty())
                        .expect("empty proof"),
                },
                dummy_input(0x77),
            ],
            data_inputs: vec![],
            output_candidates: vec![candidate(
                other_tree(),
                out0_tokens,
                AdditionalRegisters::empty(),
            )],
        }
    }

    pub(crate) fn wire(tx: &Transaction) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_transaction(&mut w, tx).expect("tx serializes");
        w.result()
    }

    pub(crate) fn txid_of(tx: &Transaction) -> [u8; 32] {
        *transaction_id(tx).expect("txid").as_bytes()
    }

    /// Receipt boxId of `lock`'s output `index`.
    pub(crate) fn receipt_id(lock: &Transaction, index: u16) -> [u8; 32] {
        let receipt = ErgoBox {
            candidate: lock.output_candidates[usize::from(index)].clone(),
            transaction_id: ModifierId::from_bytes(txid_of(lock)),
            index,
        };
        *receipt.box_id().expect("box id").as_bytes()
    }

    /// v2+ witness leaf: `blake2b256(concat input proofs)[1..]` (31 B).
    pub(crate) fn witness_id(tx: &Transaction) -> Vec<u8> {
        let mut all = Vec::new();
        for i in &tx.inputs {
            all.extend_from_slice(&i.spending_proof.proof);
        }
        blake2b256(&all)[1..].to_vec()
    }

    /// Block leaves under the v2+ rule: tx ids then witness ids.
    pub(crate) fn block_leaves(txs: &[&Transaction]) -> Vec<Vec<u8>> {
        let mut leaves: Vec<Vec<u8>> = txs.iter().map(|t| txid_of(t).to_vec()).collect();
        leaves.extend(txs.iter().map(|t| witness_id(t)));
        leaves
    }

    /// Real prove-side extraction (`merkle_proof_by_indices`) → wire
    /// `BatchMerkleProof` for leaf `i`.
    pub(crate) fn batch_proof_over(leaves: &[Vec<u8>], i: u32) -> BatchMerkleProof {
        let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let (indices, proofs) = merkle_proof_by_indices(&refs, &[i]).expect("index in range");
        BatchMerkleProof {
            indices,
            proofs: proofs
                .into_iter()
                .map(|e| ProofEntry {
                    digest: e.digest,
                    side: Side::from_byte(e.side),
                })
                .collect(),
        }
    }

    /// Synthetic v2 header committing `txs` (fixed shape apart from
    /// height + tx root; PoW is fake — the settled view is fabricated,
    /// which is exactly why the fabricator is cfg(test)-only).
    pub(crate) fn synth_header(height: u32, txs: &[&Transaction]) -> Header {
        let leaves = block_leaves(txs);
        let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let root = ergo_crypto::merkle::merkle_tree_root(&refs);
        Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0x01; 32]),
            ad_proofs_root: Digest32::from_bytes([0x02; 32]),
            transactions_root: Digest32::from_bytes(root),
            state_root: ADDigest::from_bytes([0x04; 33]),
            timestamp: 1_700_000_000_000 + u64::from(height),
            extension_root: Digest32::from_bytes([0x05; 32]),
            n_bits: 0x1a01_7660,
            height,
            votes: [0x00; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0xAA; 8],
            },
        }
    }

    pub(crate) fn inclusion_in(txs: &[&Transaction], i: usize, header: &Header) -> TxInclusion {
        TxInclusion {
            header: header.clone(),
            tx_bytes: wire(txs[i]),
            proof: batch_proof_over(&block_leaves(txs), i as u32),
        }
    }

    pub(crate) fn header_id(h: &Header) -> [u8; 32] {
        let (_bytes, id) = serialize_header(h).expect("header serializes");
        *id.as_bytes()
    }

    pub(crate) fn anchor_over(headers: &[&Header], h_ref: u32) -> ComparativeAnchor {
        let rows: Vec<([u8; 32], u32, u32)> = headers
            .iter()
            .map(|h| (header_id(h), h.height, 0))
            .collect();
        ComparativeAnchor {
            h_ref,
            settled_view: SettledView::fabricate_for_tests(&rows, h_ref),
        }
    }

    /// Baseline valid scenario: lock in block 100, consolidation in
    /// block 101, both settled (`h_ref = 101`), N = 50_000 USE base
    /// units, 400 base units paid to the fee pot.
    pub(crate) fn happy() -> (PegMintProof, ComparativeAnchor, PegParams) {
        let lock = make_lock(N_LOCK, FEE_PAID, r4_coll_bytes(dest33()));
        let cons = make_cons(receipt_id(&lock, 0), vault_out_tokens());
        let lock_header = synth_header(100, &[&lock]);
        let cons_header = synth_header(101, &[&cons]);
        let proof = PegMintProof {
            work: real_work(),
            lock: inclusion_in(&[&lock], 0, &lock_header),
            receipt_output_index: 0,
            consolidation: inclusion_in(&[&cons], 0, &cons_header),
            receipt_input_index: 0,
        };
        let anchor = anchor_over(&[&lock_header, &cons_header], 101);
        (proof, anchor, peg_params())
    }

    /// A real, spendable receiver address core (a canonical odd-curve
    /// `PaymentAddress`) — unlike `happy`'s `dest33()` sentinel, this
    /// passes the state apply path's `pegmint_note` derivation, which
    /// requires `sc_dest` to be a real curve point.
    pub(crate) fn spendable_dest() -> Vec<u8> {
        aegis_crypto::payment::PaymentAddress::from_nk(aegis_crypto::nullifier::OddScalar::from(
            0x9E57u64,
        ))
        .to_bytes()
        .to_vec()
    }

    /// [`happy`] with a real spendable `sc_dest`, so the minted note is
    /// one the recipient could later spend. `n`/`fee` and a `box_seed`
    /// (varies the receipt boxId, for distinct-receipt tests) are
    /// parameters; the returned anchor settles both inclusion headers.
    pub(crate) fn spendable_case(
        n: u64,
        fee: u64,
        box_seed: u8,
    ) -> (PegMintProof, ComparativeAnchor, PegParams) {
        case_with_dest(spendable_dest(), n, fee, box_seed)
    }

    /// [`spendable_case`] with a caller-chosen R4 `sc_dest` payload — used
    /// to exercise the non-curve-point (unspendable) reject path.
    pub(crate) fn case_with_dest(
        dest: Vec<u8>,
        n: u64,
        fee: u64,
        box_seed: u8,
    ) -> (PegMintProof, ComparativeAnchor, PegParams) {
        let mut lock = make_lock(n, fee, r4_coll_bytes(dest));
        // Vary an unrelated input's boxId so distinct cases yield distinct
        // receipt boxIds (the receipt boxId hashes the lock tx id).
        lock.inputs[0].box_id = ergo_primitives::digest::Digest32::from_bytes([box_seed; 32]);
        let cons = make_cons(receipt_id(&lock, 0), vault_out_tokens());
        let lock_header = synth_header(100, &[&lock]);
        let cons_header = synth_header(101, &[&cons]);
        let proof = PegMintProof {
            work: real_work(),
            lock: inclusion_in(&[&lock], 0, &lock_header),
            receipt_output_index: 0,
            consolidation: inclusion_in(&[&cons], 0, &cons_header),
            receipt_input_index: 0,
        };
        let anchor = anchor_over(&[&lock_header, &cons_header], 101);
        (proof, anchor, peg_params())
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use crate::ergo_follow::SettledView;
    use ergo_ser::batch_merkle_proof::{ProofEntry, Side};
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    use ergo_ser::token::{Token, TokenId};

    // ----- happy path -----

    #[test]
    fn pegmint_happy_path_emits_full_effect() {
        let (proof, anchor, params) = happy();
        let lock = make_lock(N_LOCK, FEE_PAID, r4_coll_bytes(dest33()));
        let expected_box_id = receipt_id(&lock, 0);
        let effect = verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params)
            .expect("valid proof mints");
        assert_eq!(effect.note_value, N_LOCK);
        assert_eq!(effect.sc_dest, [0x07; 33]);
        assert_eq!(effect.box_id, expected_box_id);
        assert_eq!(effect.rho_seed, effect.box_id, "rho seeds from the boxId");
        // peg_fee(50_000) = max(100, 500) = 500; paid 400 → min = 400.
        assert_eq!(effect.pot_credit, FEE_PAID);
    }

    #[test]
    fn pegmint_fee_overpay_pot_capped_at_peg_fee() {
        let lock = make_lock(N_LOCK, 10_000, r4_coll_bytes(dest33()));
        let cons = make_cons(receipt_id(&lock, 0), vault_out_tokens());
        let lh = synth_header(100, &[&lock]);
        let ch = synth_header(101, &[&cons]);
        let proof = PegMintProof {
            work: real_work(),
            lock: inclusion_in(&[&lock], 0, &lh),
            receipt_output_index: 0,
            consolidation: inclusion_in(&[&cons], 0, &ch),
            receipt_input_index: 0,
        };
        let anchor = anchor_over(&[&lh, &ch], 101);
        let effect =
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &peg_params()).expect("mints");
        // peg_fee(50_000) = 500 caps the credit.
        assert_eq!(effect.pot_credit, 500);
    }

    #[test]
    fn pegmint_fee_less_lock_still_mints_zero_pot() {
        // F2: fee shortfall is NEVER a rejection — a fee-less lock
        // mints with pot_credit 0.
        let lock = make_lock(N_LOCK, 0, r4_coll_bytes(dest33()));
        let cons = make_cons(receipt_id(&lock, 0), vault_out_tokens());
        let lh = synth_header(100, &[&lock]);
        let ch = synth_header(101, &[&cons]);
        let proof = PegMintProof {
            work: real_work(),
            lock: inclusion_in(&[&lock], 0, &lh),
            receipt_output_index: 0,
            consolidation: inclusion_in(&[&cons], 0, &ch),
            receipt_input_index: 0,
        };
        let anchor = anchor_over(&[&lh, &ch], 101);
        let effect =
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &peg_params()).expect("mints");
        assert_eq!(effect.pot_credit, 0);
        assert_eq!(effect.note_value, N_LOCK);
    }

    #[test]
    fn pegmint_same_block_lock_and_consolidation_accepts() {
        // §5.1: lock and consolidation chained in ONE block is legal —
        // the two carried headers are byte-identical.
        let lock = make_lock(N_LOCK, FEE_PAID, r4_coll_bytes(dest33()));
        let cons = make_cons(receipt_id(&lock, 0), vault_out_tokens());
        let header = synth_header(100, &[&lock, &cons]);
        let proof = PegMintProof {
            work: real_work(),
            lock: inclusion_in(&[&lock, &cons], 0, &header),
            receipt_output_index: 0,
            consolidation: inclusion_in(&[&lock, &cons], 1, &header),
            receipt_input_index: 0,
        };
        let anchor = anchor_over(&[&header], 100);
        let effect =
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &peg_params()).expect("mints");
        assert_eq!(effect.note_value, N_LOCK);
    }

    #[test]
    fn peg_fee_uses_vault_floor_division() {
        // §5.5 pins PegVault.es arithmetic: n·bps/10000 FLOOR-divided,
        // then max(floor, ·). 123_456 · 100 / 10_000 = 1234 (the
        // aegis-spec NetworkParams::peg_fee would give 1235 — that
        // rounds UP by design for peg-out pricing; the verifier must
        // match the vault).
        let p = peg_params();
        assert_eq!(p.peg_fee(123_456), 1_234);
        assert_eq!(p.peg_fee(50), 100, "floor applies");
        assert_eq!(p.peg_fee(100_000), 1_000);
    }

    // ----- round-trips -----

    #[test]
    fn pegmint_proof_wire_roundtrips() {
        let (proof, _anchor, _params) = happy();
        let bytes = serialize_pegmint_proof(&proof).expect("serializes");
        assert!(bytes.len() <= MAX_PEGMINT_PROOF_BYTES);
        let parsed = read_pegmint_proof(&bytes).expect("parses");
        assert_eq!(parsed, proof);
    }

    #[test]
    fn envelope_trailing_byte_rejects() {
        let (proof, _anchor, _params) = happy();
        let mut bytes = serialize_pegmint_proof(&proof).expect("serializes");
        bytes.push(0x00);
        assert!(matches!(
            read_pegmint_proof(&bytes),
            Err(PegMintError::MalformedProof {
                field: "trailing bytes"
            })
        ));
    }

    #[test]
    fn oversize_tx_bytes_rejected_on_write_and_verify() {
        let (mut proof, anchor, params) = happy();
        proof.lock.tx_bytes = vec![0u8; MAX_PEG_TX_BYTES + 1];
        assert!(matches!(
            serialize_pegmint_proof(&proof),
            Err(PegMintError::Oversize {
                field: "lock.tx_bytes",
                ..
            })
        ));
        // §5.6: the cap fires BEFORE any hashing on the verify side too.
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::Oversize {
                field: "lock.tx_bytes",
                ..
            })
        ));
    }

    // ----- error paths (§5.10 attack table) -----

    #[test]
    fn suffix_smuggle_consolidation_above_h_ref_rejects() {
        // Attack 5 (the P1-A original): consolidation planted in a
        // block above h_ref — the settled view simply does not contain
        // its header.
        let (proof, _anchor, params) = happy();
        // Rebuild the anchor WITHOUT the consolidation header (h_ref
        // stops at the lock's height).
        let truncated = anchor_over(&[&proof.lock.header], 100);
        assert!(matches!(
            verify_pegmint(&proof, &truncated, &PegMintUsedSet::new(), &params),
            Err(PegMintError::InclusionNotSettled {
                role: InclusionRole::Consolidation,
                height: 101
            })
        ));
    }

    #[test]
    fn unknown_lock_header_rejects() {
        // Attack 1: a header never on the followed chain.
        let (proof, _anchor, params) = happy();
        let empty = anchor_over(&[], 200);
        assert!(matches!(
            verify_pegmint(&proof, &empty, &PegMintUsedSet::new(), &params),
            Err(PegMintError::InclusionNotSettled {
                role: InclusionRole::Lock,
                height: 100
            })
        ));
    }

    #[test]
    fn settled_view_height_mismatch_rejects() {
        // Defense-in-depth: the id must be settled AT the carried
        // header's own height (`height_of(id) == Some(header.height)`).
        let (proof, _anchor, params) = happy();
        let rows = [
            (header_id(&proof.lock.header), 99u32, 0u32), // wrong height
            (header_id(&proof.consolidation.header), 101, 0),
        ];
        let anchor = ComparativeAnchor {
            h_ref: 101,
            settled_view: SettledView::fabricate_for_tests(&rows, 101),
        };
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::InclusionNotSettled {
                role: InclusionRole::Lock,
                ..
            })
        ));
    }

    #[test]
    fn refund_shaped_consolidation_rejects() {
        // Attack 2: a refund spend consumes the boxId but its
        // OUTPUTS(0) has no vault NFT at tokens(0). Three shapes: USE
        // where the NFT should be; token-less OUTPUTS(0); NFT present
        // but not FIRST.
        let lock = make_lock(N_LOCK, FEE_PAID, r4_coll_bytes(dest33()));
        let rid = receipt_id(&lock, 0);
        let lh = synth_header(100, &[&lock]);
        for out0 in [
            use_tokens(N_LOCK),
            vec![],
            vec![
                Token {
                    token_id: TokenId::from_bytes(USE_ID),
                    amount: N_LOCK,
                },
                Token {
                    token_id: TokenId::from_bytes(VAULT_NFT),
                    amount: 1,
                },
            ],
        ] {
            let cons = make_cons(rid, out0);
            let ch = synth_header(101, &[&cons]);
            let proof = PegMintProof {
                work: real_work(),
                lock: inclusion_in(&[&lock], 0, &lh),
                receipt_output_index: 0,
                consolidation: inclusion_in(&[&cons], 0, &ch),
                receipt_input_index: 0,
            };
            let anchor = anchor_over(&[&lh, &ch], 101);
            assert!(matches!(
                verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &peg_params()),
                Err(PegMintError::NotConsolidatedIntoVault)
            ));
        }
    }

    #[test]
    fn replayed_receipt_rejects_as_already_minted() {
        // Attack 3 (I2): same receipt boxId cannot mint twice.
        let (proof, anchor, params) = happy();
        let mut used = PegMintUsedSet::new();
        let effect = verify_pegmint(&proof, &anchor, &used, &params).expect("first mint");
        assert!(used.insert(effect.box_id));
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &used, &params),
            Err(PegMintError::AlreadyMinted)
        ));
    }

    #[test]
    fn output_index_out_of_range_rejects() {
        let (mut proof, anchor, params) = happy();
        proof.receipt_output_index = 7;
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::OutputIndexOutOfRange { got: 7, len: 3 })
        ));
    }

    #[test]
    fn input_index_out_of_range_rejects() {
        let (mut proof, anchor, params) = happy();
        proof.receipt_input_index = 9;
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::InputIndexOutOfRange { got: 9, len: 2 })
        ));
    }

    #[test]
    fn mismatched_lock_consolidation_pairing_rejects() {
        // Attack 7: point receipt_output_index at a DIFFERENT real
        // output of the same lock (the fee-pot output) — its boxId is
        // not what the consolidation spends.
        let (mut proof, anchor, params) = happy();
        proof.receipt_output_index = 1;
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::ReceiptNotConsumed)
        ));
        // And a consolidation of a foreign receipt (different lock).
        let lock_b = make_lock(N_LOCK + 1, FEE_PAID, r4_coll_bytes(dest33()));
        let cons = make_cons(receipt_id(&lock_b, 0), vault_out_tokens());
        let lock_a = make_lock(N_LOCK, FEE_PAID, r4_coll_bytes(dest33()));
        let lh = synth_header(100, &[&lock_a]);
        let ch = synth_header(101, &[&cons]);
        let proof = PegMintProof {
            work: real_work(),
            lock: inclusion_in(&[&lock_a], 0, &lh),
            receipt_output_index: 0,
            consolidation: inclusion_in(&[&cons], 0, &ch),
            receipt_input_index: 0,
        };
        let anchor = anchor_over(&[&lh, &ch], 101);
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::ReceiptNotConsumed)
        ));
    }

    #[test]
    fn fake_receipt_script_rejects() {
        // Attack 8: a receipt-lookalike under an attacker script.
        let mut lock = make_lock(N_LOCK, FEE_PAID, r4_coll_bytes(dest33()));
        lock.output_candidates[0] =
            candidate(other_tree(), use_tokens(N_LOCK), r4_coll_bytes(dest33()));
        let cons = make_cons(receipt_id(&lock, 0), vault_out_tokens());
        let lh = synth_header(100, &[&lock]);
        let ch = synth_header(101, &[&cons]);
        let proof = PegMintProof {
            work: real_work(),
            lock: inclusion_in(&[&lock], 0, &lh),
            receipt_output_index: 0,
            consolidation: inclusion_in(&[&cons], 0, &ch),
            receipt_input_index: 0,
        };
        let anchor = anchor_over(&[&lh, &ch], 101);
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &peg_params()),
            Err(PegMintError::WrongReceiptScript)
        ));
    }

    fn proof_with_receipt(
        tokens: Vec<Token>,
        regs: AdditionalRegisters,
    ) -> (PegMintProof, ComparativeAnchor) {
        let mut lock = make_lock(N_LOCK, FEE_PAID, r4_coll_bytes(dest33()));
        lock.output_candidates[0] = candidate(receipt_tree(), tokens, regs);
        let cons = make_cons(receipt_id(&lock, 0), vault_out_tokens());
        let lh = synth_header(100, &[&lock]);
        let ch = synth_header(101, &[&cons]);
        let proof = PegMintProof {
            work: real_work(),
            lock: inclusion_in(&[&lock], 0, &lh),
            receipt_output_index: 0,
            consolidation: inclusion_in(&[&cons], 0, &ch),
            receipt_input_index: 0,
        };
        let anchor = anchor_over(&[&lh, &ch], 101);
        (proof, anchor)
    }

    #[test]
    fn wrong_token_rejects() {
        for tokens in [
            vec![Token {
                token_id: TokenId::from_bytes([0xCC; 32]),
                amount: N_LOCK,
            }],
            vec![],
        ] {
            let (proof, anchor) = proof_with_receipt(tokens, r4_coll_bytes(dest33()));
            assert!(matches!(
                verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &peg_params()),
                Err(PegMintError::WrongToken)
            ));
        }
    }

    #[test]
    fn zero_amount_rejects() {
        let (proof, anchor) = proof_with_receipt(use_tokens(0), r4_coll_bytes(dest33()));
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &peg_params()),
            Err(PegMintError::ZeroAmount)
        ));
    }

    #[test]
    fn bad_sc_dest_rejects() {
        // Wrong length (32), missing R4, and non-Coll[Byte] R4.
        let cases = [
            r4_coll_bytes(vec![0x07; 32]),
            AdditionalRegisters::empty(),
            AdditionalRegisters {
                registers: vec![RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(33),
                }],
            },
        ];
        for regs in cases {
            let (proof, anchor) = proof_with_receipt(use_tokens(N_LOCK), regs);
            assert!(matches!(
                verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &peg_params()),
                Err(PegMintError::BadScDest)
            ));
        }
    }

    #[test]
    fn tampered_tx_bytes_trailing_rejects() {
        let (mut proof, anchor, params) = happy();
        proof.lock.tx_bytes.push(0x00);
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::MalformedProof {
                field: "lock.tx_bytes"
            })
        ));
    }

    #[test]
    fn leaf_binding_rejects_substituted_tx() {
        // Attack 6 (contract 2): swap in a DIFFERENT decodable tx while
        // keeping the original merkle proof — the recomputed txid no
        // longer matches the proof's claimed leaf.
        let (mut proof, anchor, params) = happy();
        let alt = make_lock(N_LOCK + 1, FEE_PAID, r4_coll_bytes(dest33()));
        proof.lock.tx_bytes = wire(&alt);
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::MalformedInclusionProof {
                role: InclusionRole::Lock
            })
        ));
    }

    #[test]
    fn wire_supplied_leaf_must_be_hashed_txid_not_raw() {
        // Attack 9 family: the leaf digest is RECOMPUTED — a proof
        // claiming the raw (unhashed) txid as its leaf digest rejects,
        // as would any witness-leaf digest (31-byte preimage).
        let (mut proof, anchor, params) = happy();
        let mut r = VlqReader::new(&proof.lock.tx_bytes);
        let tx = read_transaction(&mut r).unwrap();
        proof.lock.proof.indices[0].1 = txid_of(&tx); // unhashed
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::MalformedInclusionProof {
                role: InclusionRole::Lock
            })
        ));
    }

    #[test]
    fn two_leaf_indices_reject() {
        let (mut proof, anchor, params) = happy();
        let extra = proof.lock.proof.indices[0];
        proof.lock.proof.indices.push(extra);
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::MalformedInclusionProof {
                role: InclusionRole::Lock
            })
        ));
    }

    #[test]
    fn tampered_merkle_sibling_rejects() {
        let (mut proof, anchor, params) = happy();
        // The synthetic lock block has 2 leaves (txid + witness id), so
        // the single-leaf proof carries a real sibling digest.
        let entry = proof
            .lock
            .proof
            .proofs
            .first_mut()
            .expect("sibling entry present");
        let mut d = entry.digest.expect("real sibling");
        d[0] ^= 0x01;
        entry.digest = Some(d);
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::TxNotInBlock {
                role: InclusionRole::Lock
            })
        ));
    }

    #[test]
    fn oversize_merkle_proof_entries_reject() {
        let (mut proof, anchor, params) = happy();
        proof.consolidation.proof.proofs = vec![
            ProofEntry {
                digest: Some([0x01; 32]),
                side: Side::Left,
            };
            MAX_PEG_MERKLE_PROOF_ENTRIES + 1
        ];
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &params),
            Err(PegMintError::Oversize {
                field: "consolidation.proof",
                ..
            })
        ));
    }

    #[test]
    fn first_error_wins_check_order_is_deterministic() {
        // A proof broken at BOTH step 5 (lock leaf) and step 7 (wrong
        // token) must surface the step-5 error.
        let (mut proof, anchor) = proof_with_receipt(vec![], r4_coll_bytes(dest33())); // WrongToken later
        let alt = make_lock(N_LOCK + 2, FEE_PAID, r4_coll_bytes(dest33()));
        proof.lock.tx_bytes = wire(&alt); // leaf mismatch first
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &peg_params()),
            Err(PegMintError::MalformedInclusionProof {
                role: InclusionRole::Lock
            })
        ));
    }

    // ----- oracle parity -----

    #[test]
    fn real_mainnet_txids_match_node_reported() {
        // Oracle: node-reported tx ids for mainnet blocks 1..=10 —
        // recomputing them from raw wire bytes must agree.
        for (id_hex, bytes) in real_txs() {
            let mut r = VlqReader::new(&bytes);
            let tx = read_transaction(&mut r).expect("real tx decodes");
            assert!(r.is_empty());
            assert_eq!(hex::encode(txid_of(&tx)), id_hex);
        }
    }

    #[test]
    fn real_mainnet_tx_root_matches_pow_committed_header() {
        // Oracle: the PoW-committed transactions_root of each real v1
        // header equals the merkle root over its (single) real tx id —
        // pins the leaf rule + reduction this verifier relies on.
        let headers = real_headers();
        let txs = real_txs();
        for (h, (_id, bytes)) in headers.iter().zip(&txs) {
            assert_eq!(h.version, 1, "v1 blocks: tx-id leaves only");
            let mut r = VlqReader::new(bytes);
            let tx = read_transaction(&mut r).expect("decodes");
            let txid = txid_of(&tx);
            let root = ergo_crypto::merkle::merkle_tree_root(&[&txid[..]]);
            assert_eq!(&root, h.transactions_root.as_bytes());
        }
    }

    #[test]
    fn node_proof_for_tx_leaf_preimage_is_the_txid() {
        // Oracle: the Scala node's own `/blocks/{id}/proofFor/{txId}`
        // for mainnet block 1 — its `leafData` (the leaf PREIMAGE) is
        // exactly the tx id, which is the §5.2.5 binding this verifier
        // recomputes (`blake2b256(0x00 ‖ txid)`).
        let txs = real_txs();
        let path = vectors_dir().join(format!("mainnet/proof_for_tx/h1_{}.json", txs[0].0));
        let raw = std::fs::read_to_string(&path).expect("read node proofFor vector");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("parse");
        assert_eq!(v["leafData"].as_str().expect("leafData"), txs[0].0);
    }

    #[test]
    fn real_inclusion_settles_through_real_follower() {
        // Fully real steps-5 path: real mainnet header (real PoW,
        // followed by the REAL Follower), real tx bytes, real one-leaf
        // tree, through the REAL comparative-policy anchor (h_ref 7).
        let anchor = real_anchor();
        assert_eq!(anchor.h_ref, 7);
        let incl = real_inclusion(5);
        let (tx, txid) = check_inclusion(&incl, InclusionRole::Lock, &anchor.settled_view)
            .expect("real inclusion verifies");
        assert_eq!(hex::encode(txid), real_txs()[4].0);
        assert!(!tx.output_candidates.is_empty());
    }

    #[test]
    fn real_inclusion_above_h_ref_rejects() {
        // P1-A on real data: block 8 is above h_ref = 7 → not settled.
        let anchor = real_anchor();
        let incl = real_inclusion(8);
        assert!(matches!(
            check_inclusion(&incl, InclusionRole::Consolidation, &anchor.settled_view),
            Err(PegMintError::InclusionNotSettled {
                role: InclusionRole::Consolidation,
                height: 8
            })
        ));
    }

    #[test]
    fn real_pair_composes_to_receipt_not_consumed() {
        // Full verify_pegmint over ONLY real mainnet data: block 5's tx
        // as both lock and consolidation. Reaching ReceiptNotConsumed
        // proves steps 0, 5a, 5b and 6a all passed on real bytes (the
        // tx does not spend its own output, so 6b correctly rejects).
        let anchor = real_anchor();
        let incl = real_inclusion(5);
        let proof = PegMintProof {
            work: real_work(),
            lock: incl.clone(),
            receipt_output_index: 0,
            consolidation: incl,
            receipt_input_index: 0,
        };
        assert!(matches!(
            verify_pegmint(&proof, &anchor, &PegMintUsedSet::new(), &peg_params()),
            Err(PegMintError::ReceiptNotConsumed)
        ));
    }
}
