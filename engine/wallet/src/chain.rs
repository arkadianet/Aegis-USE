//! The node boundary: the read interface a wallet consumes to build a spend
//! (root / paths / nullifier / scan-feed queries), the on-chain transaction
//! object, and an in-memory node implementing the accept path. The real
//! aegis-node integration (next milestone) implements [`ChainView`] and mirrors
//! [`InMemoryChain::submit`]; the in-memory chain and the real node share this
//! trait so the multi-wallet e2e is a faithful rehearsal.
//!
//! # Root management (the honest strategy — pin-to-recent-root + window)
//! A spend proves membership at a specific accumulator root. Between the wallet
//! fetching a path and the node processing the tx, the tree may advance (other
//! txs append leaves), changing the right-frontier siblings of existing paths.
//! So a wallet always fetches a FRESH path at the current root and proves
//! against THAT root; the node accepts a tx whose public root is any of the last
//! [`ROOT_WINDOW`] roots (a sliding acceptance window, cf. Zcash anchors). Stale
//! anchors outside the window are rejected — the wallet re-fetches and re-proves.

use std::collections::{HashSet, VecDeque};

use aegis_engine::merkle::{MerklePath, NoteTree};
use aegis_engine::note_encryption::NOTE_CT_BYTES;
use aegis_engine::poseidon::{Digest, DIGEST_ELEMS, F};
use aegis_engine::spend::monolith::{PUB_CMO0, PUB_CMO1, PUB_NF0, PUB_NF1, PUB_ROOT};
use p3_field::PrimeCharacteristicRing;

use crate::circuit::SpendCircuit;

/// How many recent accumulator roots the node accepts a spend against.
pub const ROOT_WINDOW: usize = 100;

/// Blocks a coinbase note must age before it is spendable (a wallet-side policy
/// — a well-behaved wallet won't select an immature coinbase note; a fully
/// consensus-enforced maturity over HIDDEN inputs is a documented hard problem,
/// deferred). The aegis-spec value (120); the node's chain params reference this
/// constant so wallet and chain can never drift.
pub const COINBASE_MATURITY: u64 = 120;

/// An on-chain shielded transaction: the hiding spend proof, its public values
/// (canonical `u32` limbs), and the two fixed-size output ciphertexts (§6
/// uniformity — always exactly two, always [`NOTE_CT_BYTES`] each).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Tx {
    pub proof_bytes: Vec<u8>,
    pub public_values: Vec<u32>,
    pub out_ciphertexts: [Vec<u8>; 2],
}

/// A committed output as the scan feed surfaces it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OutputRecord {
    /// The leaf index of this output's commitment in the accumulator.
    pub leaf_index: u64,
    pub cm: Digest,
    pub ciphertext: Vec<u8>,
    /// Block height at which this output was committed.
    pub height: u64,
    /// Whether this output is a coinbase note (subject to maturity).
    pub is_coinbase: bool,
}

/// Why the node rejected a submission.
#[derive(Debug, PartialEq, Eq)]
pub enum SubmitError {
    ProofInvalid,
    UnknownRoot,
    DoubleSpend,
    BadCiphertext,
    BadPublicShape,
}

/// Read a digest from a public-value slice at byte offset `off` (8 limbs).
pub fn digest_at(publics: &[u32], off: usize) -> Digest {
    core::array::from_fn(|i| F::from_u32(publics[off + i]))
}

/// The read boundary a wallet uses to build spends and scan for payments.
pub trait ChainView {
    /// The current accumulator root (the anchor a fresh spend proves against).
    fn current_root(&self) -> Digest;
    /// The membership path for `leaf_index` at the current root, if it exists.
    fn authentication_path(&self, leaf_index: u64) -> Option<MerklePath>;
    /// Whether a nullifier has been spent (double-spend / spent-state tracking).
    fn nullifier_seen(&self, nf: &Digest) -> bool;
    /// New committed outputs with `leaf_index >= cursor` (the scan feed).
    fn outputs_since(&self, cursor: u64) -> Vec<OutputRecord>;
    /// Total committed outputs = the next leaf index = a scan-cursor target.
    fn output_count(&self) -> u64;
    /// The current chain tip height (for coinbase-maturity checks).
    fn tip_height(&self) -> u64;
}

/// An in-memory chain: the accumulator, the nullifier set, the recent-root
/// window, and the committed outputs. Implements the node's accept path
/// ([`Self::submit`]) and the [`ChainView`] read boundary.
pub struct InMemoryChain {
    tree: NoteTree,
    nullifiers: HashSet<[u32; DIGEST_ELEMS]>,
    recent_roots: VecDeque<Digest>,
    outputs: Vec<OutputRecord>,
    height: u64,
}

impl Default for InMemoryChain {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryChain {
    pub fn new() -> Self {
        let tree = NoteTree::new();
        let mut recent_roots = VecDeque::new();
        recent_roots.push_back(tree.root());
        Self {
            tree,
            nullifiers: HashSet::new(),
            recent_roots,
            outputs: Vec::new(),
            height: 0,
        }
    }

    fn push_root(&mut self) {
        if self.recent_roots.len() == ROOT_WINDOW {
            self.recent_roots.pop_front();
        }
        self.recent_roots.push_back(self.tree.root());
    }

    /// Append one output commitment with its ciphertext (a coinbase/faucet or
    /// the accept path). Returns the leaf index. Advances the root window.
    pub fn append_output(&mut self, cm: Digest, ciphertext: Vec<u8>) -> u64 {
        let height = self.height;
        let leaf_index = self.tree.append(cm);
        self.outputs.push(OutputRecord {
            leaf_index,
            cm,
            ciphertext,
            height,
            is_coinbase: false,
        });
        self.push_root();
        self.height += 1;
        leaf_index
    }

    fn root_in_window(&self, root: &Digest) -> bool {
        self.recent_roots.contains(root)
    }

    fn key(nf: &Digest) -> [u32; DIGEST_ELEMS] {
        use p3_field::PrimeField32;
        core::array::from_fn(|i| nf[i].as_canonical_u32())
    }

    /// The node's accept path for a submitted [`Tx`]: verify the hiding proof,
    /// check the anchor root is recent, reject double-spends, then append the
    /// two output commitments and record the two nullifiers atomically.
    pub fn submit(&mut self, tx: &Tx, circuit: &SpendCircuit) -> Result<(), SubmitError> {
        if tx.public_values.len() < PUB_CMO1 + DIGEST_ELEMS {
            return Err(SubmitError::BadPublicShape);
        }
        for ct in &tx.out_ciphertexts {
            if ct.len() != NOTE_CT_BYTES {
                return Err(SubmitError::BadCiphertext);
            }
        }
        if !circuit.verify(&tx.proof_bytes, &tx.public_values) {
            return Err(SubmitError::ProofInvalid);
        }
        let root = digest_at(&tx.public_values, PUB_ROOT);
        if !self.root_in_window(&root) {
            return Err(SubmitError::UnknownRoot);
        }
        let nf0 = digest_at(&tx.public_values, PUB_NF0);
        let nf1 = digest_at(&tx.public_values, PUB_NF1);
        // (the circuit already enforces nf0 != nf1)
        if self.nullifier_seen(&nf0) || self.nullifier_seen(&nf1) {
            return Err(SubmitError::DoubleSpend);
        }

        // Accept: record nullifiers, append the two output commitments.
        self.nullifiers.insert(Self::key(&nf0));
        self.nullifiers.insert(Self::key(&nf1));
        let cm0 = digest_at(&tx.public_values, PUB_CMO0);
        let cm1 = digest_at(&tx.public_values, PUB_CMO1);
        self.append_output(cm0, tx.out_ciphertexts[0].clone());
        self.append_output(cm1, tx.out_ciphertexts[1].clone());
        Ok(())
    }
}

impl ChainView for InMemoryChain {
    fn current_root(&self) -> Digest {
        self.tree.root()
    }
    fn authentication_path(&self, leaf_index: u64) -> Option<MerklePath> {
        (leaf_index < self.tree.len()).then(|| self.tree.authentication_path(leaf_index))
    }
    fn nullifier_seen(&self, nf: &Digest) -> bool {
        self.nullifiers.contains(&Self::key(nf))
    }
    fn outputs_since(&self, cursor: u64) -> Vec<OutputRecord> {
        self.outputs
            .iter()
            .filter(|o| o.leaf_index >= cursor)
            .cloned()
            .collect()
    }
    fn output_count(&self) -> u64 {
        self.tree.len()
    }
    fn tip_height(&self) -> u64 {
        self.height
    }
}
