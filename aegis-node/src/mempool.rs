//! M3 slice 2 — the shielded-transfer mempool.
//!
//! Admission is **authoritative at the boundary**: a transfer is only
//! accepted if its Bulletproofs proof verifies against the current tip
//! anchor at the consensus fee ([`verify_shielded_transfer`]) and none
//! of its nullifiers are already spent on-chain or pending in the pool.
//! So the API rejects an invalid proof up front, regardless of a
//! producer's proof mode. Inclusion re-verifies against the live anchor
//! ([`Mempool::select_for_block`]) — the authoritative check — so a tip
//! change between admission and production can only drop a transfer,
//! never let a stale one through.
//!
//! Pool invariant: no two pending transfers share a nullifier (admission
//! rejects conflicts), so any subset selected for a block already has
//! pairwise-disjoint nullifiers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use aegis_crypto::generators::EvenPoint;
use aegis_crypto::tree::{build_tree, AegisTree};
use aegis_spec::{Amount, NF_BYTES};
use ergo_crypto::autolykos::common::blake2b256;

use crate::proof::{verify_shielded_transfer, ProofError};
use crate::seed::Id;
use crate::tx::ShieldedTransfer;

/// Max pending transfers held at once.
pub const MAX_MEMPOOL_TXS: usize = 1024;
/// Max transfers a single produced block includes.
pub const MAX_BLOCK_TRANSFERS: usize = 64;

/// A consistent snapshot of chain state for admission: the spend-anchor
/// leaves, the spent-nullifier set, and the consensus fee. Published by
/// the node on each tip change; cheap to clone (all `Arc`).
#[derive(Clone)]
pub struct AdmissionView {
    leaves: Arc<Vec<EvenPoint>>,
    spent: Arc<BTreeSet<[u8; NF_BYTES]>>,
    fee: Amount,
}

impl AdmissionView {
    pub fn new(
        leaves: Arc<Vec<EvenPoint>>,
        spent: Arc<BTreeSet<[u8; NF_BYTES]>>,
        fee: Amount,
    ) -> Self {
        AdmissionView { leaves, spent, fee }
    }

    /// The spend anchor for this view, or `None` when no notes exist yet.
    fn anchor(&self) -> Option<AegisTree> {
        if self.leaves.is_empty() {
            None
        } else {
            Some(build_tree(&self.leaves))
        }
    }
}

/// Why a transfer was not admitted.
#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    #[error("mempool full ({MAX_MEMPOOL_TXS})")]
    Full,
    #[error("a nullifier is already spent on-chain")]
    AlreadySpent,
    #[error("a nullifier conflicts with a pending transfer")]
    Conflict,
    #[error("no spendable notes yet (empty anchor)")]
    NoAnchor,
    #[error("proof invalid: {0}")]
    Invalid(#[from] ProofError),
}

/// Outcome of a successful admission.
#[derive(Debug, PartialEq, Eq)]
pub enum Admitted {
    /// Newly admitted; the transfer id.
    New(Id),
    /// Already in the pool (idempotent double-submit); the transfer id.
    Duplicate(Id),
}

impl Admitted {
    pub fn id(&self) -> Id {
        match self {
            Admitted::New(id) | Admitted::Duplicate(id) => *id,
        }
    }

    pub fn is_new(&self) -> bool {
        matches!(self, Admitted::New(_))
    }
}

/// Pending shielded transfers, keyed by transfer id
/// (`blake2b256(bytes)`), with a nullifier index for conflict checks.
#[derive(Debug, Default)]
pub struct Mempool {
    by_id: BTreeMap<Id, ShieldedTransfer>,
    nullifiers: BTreeSet<[u8; NF_BYTES]>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool::default()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Validate and admit `tx` against `view`. Double-submit of an
    /// identical transfer is a no-op ([`Admitted::Duplicate`]).
    pub fn admit(
        &mut self,
        tx: ShieldedTransfer,
        view: &AdmissionView,
    ) -> Result<Admitted, AdmitError> {
        let id = tx_id(&tx);
        if self.by_id.contains_key(&id) {
            return Ok(Admitted::Duplicate(id));
        }
        if self.by_id.len() >= MAX_MEMPOOL_TXS {
            return Err(AdmitError::Full);
        }
        for nf in &tx.nullifiers {
            if view.spent.contains(nf) {
                return Err(AdmitError::AlreadySpent);
            }
            if self.nullifiers.contains(nf) {
                return Err(AdmitError::Conflict);
            }
        }
        let anchor = view.anchor().ok_or(AdmitError::NoAnchor)?;
        verify_shielded_transfer(&anchor, &tx, view.fee)?;
        for nf in &tx.nullifiers {
            self.nullifiers.insert(*nf);
        }
        self.by_id.insert(id, tx);
        Ok(Admitted::New(id))
    }

    /// Wire bytes of every pending transfer (for the `/mm/commitment`
    /// template), in id order.
    pub fn tx_bytes(&self) -> Vec<Vec<u8>> {
        self.by_id.values().map(ShieldedTransfer::bytes).collect()
    }

    /// Select up to [`MAX_BLOCK_TRANSFERS`] transfers that RE-verify
    /// against the live `anchor` (the authoritative inclusion check).
    /// Returns the transfers and their ids (to [`Self::remove`] once the
    /// block is accepted). No anchor ⇒ nothing spendable ⇒ empty.
    pub fn select_for_block(
        &self,
        anchor: Option<&AegisTree>,
        fee: Amount,
    ) -> (Vec<ShieldedTransfer>, Vec<Id>) {
        let Some(anchor) = anchor else {
            return (Vec::new(), Vec::new());
        };
        let mut txs = Vec::new();
        let mut ids = Vec::new();
        for (id, tx) in &self.by_id {
            if txs.len() >= MAX_BLOCK_TRANSFERS {
                break;
            }
            if verify_shielded_transfer(anchor, tx, fee).is_ok() {
                txs.push(tx.clone());
                ids.push(*id);
            }
        }
        (txs, ids)
    }

    /// Drop included transfers and release their nullifiers.
    pub fn remove(&mut self, ids: &[Id]) {
        for id in ids {
            if let Some(tx) = self.by_id.remove(id) {
                for nf in &tx.nullifiers {
                    self.nullifiers.remove(nf);
                }
            }
        }
    }

    /// Evict every pending transfer any of whose nullifiers are now
    /// spent on-chain (called on a tip change / reorg).
    pub fn evict_spent(&mut self, spent: &BTreeSet<[u8; NF_BYTES]>) {
        let doomed: Vec<Id> = self
            .by_id
            .iter()
            .filter(|(_, tx)| tx.nullifiers.iter().any(|nf| spent.contains(nf)))
            .map(|(id, _)| *id)
            .collect();
        self.remove(&doomed);
    }
}

/// Transfer id = `blake2b256` of its canonical wire bytes (includes the
/// proof, so it is a stable content address).
fn tx_id(tx: &ShieldedTransfer) -> Id {
    blake2b256(&tx.bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::note::{note_cm_bytes, EvenScalar};
    use aegis_crypto::nullifier::OddScalar;
    use aegis_crypto::spend::{
        consensus_note_commitment, consensus_note_tag, prove_transfer, NoteOpening, TransferOutput,
    };
    use aegis_spec::{EPK_BYTES, NOTE_CT_BYTES, NOTE_OUT_CT_BYTES};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const FEE: u64 = 10;

    // ----- helpers -----

    fn opening(value: u64, seed: u64, leaf_index: usize) -> NoteOpening {
        NoteOpening {
            value,
            blinding: EvenScalar::from(seed),
            leaf_index,
            nk: OddScalar::from(seed + 1),
            rho: OddScalar::from(seed + 2),
            r_key: OddScalar::from(seed + 3),
        }
    }

    fn leaf_of(o: &NoteOpening) -> EvenPoint {
        consensus_note_commitment(
            o.value,
            consensus_note_tag(o.nk, o.rho, o.r_key),
            o.blinding,
        )
    }

    /// A pair of spendable input notes + the leaves they live in.
    fn scene(seed: u64) -> (Vec<EvenPoint>, [NoteOpening; 2]) {
        let inputs = [opening(1_000, seed, 0), opening(500, seed + 10, 1)];
        let leaves = vec![
            leaf_of(&inputs[0]),
            leaf_of(&inputs[1]),
            leaf_of(&opening(0, seed + 20, 2)),
        ];
        (leaves, inputs)
    }

    fn transfer(anchor: &AegisTree, inputs: &[NoteOpening; 2], out_tag: u64) -> ShieldedTransfer {
        let outputs = [
            TransferOutput {
                value: 1_500 - FEE - 100,
                tag: EvenScalar::from(out_tag),
                blinding: EvenScalar::from(out_tag + 1),
            },
            TransferOutput {
                value: 100,
                tag: EvenScalar::from(out_tag + 2),
                blinding: EvenScalar::from(out_tag + 3),
            },
        ];
        let proof = prove_transfer(anchor, inputs, &outputs, FEE, &mut StdRng::seed_from_u64(1))
            .expect("valid transfer proves");
        let mut proof_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes).unwrap();
        let out_wire = |i: usize| crate::tx::ShieldedOutput {
            note_cm: note_cm_bytes(&proof.output_cms[i]),
            epk: [0u8; EPK_BYTES],
            ct: [0u8; NOTE_CT_BYTES],
            out_ct: [0u8; NOTE_OUT_CT_BYTES],
        };
        ShieldedTransfer {
            nullifiers: proof.nullifiers(),
            outputs: [out_wire(0), out_wire(1)],
            proof: proof_bytes,
        }
    }

    fn view(leaves: &[EvenPoint], spent: BTreeSet<[u8; NF_BYTES]>) -> AdmissionView {
        AdmissionView::new(Arc::new(leaves.to_vec()), Arc::new(spent), FEE)
    }

    // ----- happy path -----

    #[test]
    fn admits_a_valid_transfer() {
        let (leaves, inputs) = scene(0x21);
        let anchor = build_tree(&leaves);
        let tx = transfer(&anchor, &inputs, 0x31);
        let mut mp = Mempool::new();
        let outcome = mp
            .admit(tx, &view(&leaves, BTreeSet::new()))
            .expect("admits");
        assert!(outcome.is_new());
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn double_submit_is_an_idempotent_noop() {
        let (leaves, inputs) = scene(0x21);
        let anchor = build_tree(&leaves);
        let tx = transfer(&anchor, &inputs, 0x31);
        let mut mp = Mempool::new();
        let v = view(&leaves, BTreeSet::new());
        let first = mp.admit(tx.clone(), &v).expect("admits");
        let again = mp.admit(tx, &v).expect("re-admits");
        assert!(first.is_new());
        assert!(!again.is_new());
        assert_eq!(first.id(), again.id());
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn selects_admitted_transfer_for_a_block_then_removes_it() {
        let (leaves, inputs) = scene(0x21);
        let anchor = build_tree(&leaves);
        let tx = transfer(&anchor, &inputs, 0x31);
        let mut mp = Mempool::new();
        mp.admit(tx, &view(&leaves, BTreeSet::new())).unwrap();
        let (txs, ids) = mp.select_for_block(Some(&anchor), FEE);
        assert_eq!(txs.len(), 1);
        mp.remove(&ids);
        assert!(mp.is_empty());
    }

    // ----- error paths -----

    #[test]
    fn rejects_an_invalid_proof_at_admission() {
        let (leaves, inputs) = scene(0x21);
        let anchor = build_tree(&leaves);
        let mut tx = transfer(&anchor, &inputs, 0x31);
        tx.proof.truncate(tx.proof.len() - 1); // corrupt the proof
        let mut mp = Mempool::new();
        assert!(matches!(
            mp.admit(tx, &view(&leaves, BTreeSet::new())),
            Err(AdmitError::Invalid(_))
        ));
        assert!(mp.is_empty());
    }

    #[test]
    fn rejects_a_spent_nullifier() {
        let (leaves, inputs) = scene(0x21);
        let anchor = build_tree(&leaves);
        let tx = transfer(&anchor, &inputs, 0x31);
        let spent: BTreeSet<_> = [tx.nullifiers[0]].into_iter().collect();
        let mut mp = Mempool::new();
        assert!(matches!(
            mp.admit(tx, &view(&leaves, spent)),
            Err(AdmitError::AlreadySpent)
        ));
    }

    #[test]
    fn evicts_a_transfer_whose_nullifier_gets_spent() {
        let (leaves, inputs) = scene(0x21);
        let anchor = build_tree(&leaves);
        let tx = transfer(&anchor, &inputs, 0x31);
        let nf0 = tx.nullifiers[0];
        let mut mp = Mempool::new();
        mp.admit(tx, &view(&leaves, BTreeSet::new())).unwrap();
        assert_eq!(mp.len(), 1);
        mp.evict_spent(&[nf0].into_iter().collect());
        assert!(mp.is_empty());
    }

    #[test]
    fn no_anchor_when_no_notes_exist() {
        let (leaves, inputs) = scene(0x21);
        let anchor = build_tree(&leaves);
        let tx = transfer(&anchor, &inputs, 0x31);
        let mut mp = Mempool::new();
        let empty = view(&[], BTreeSet::new());
        assert!(matches!(mp.admit(tx, &empty), Err(AdmitError::NoAnchor)));
    }
}
