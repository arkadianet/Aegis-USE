//! The wallet: keys, note store + scanner, selection, and the pay/receive flow.

use aegis_engine::address::{Address, WalletKeys};
use aegis_engine::commit::{note_commitment, owner_key, Blinding, Rho};
use aegis_engine::merkle::MerklePath;
use aegis_engine::note_encryption::{encrypt_note, try_decrypt, NotePlaintext, MEMO_BYTES};
use aegis_engine::nullifier::nullifier;
use aegis_engine::poseidon::{Digest, F};
use aegis_engine::spend::monolith::{InputNote, OutputNote};
use p3_field::PrimeCharacteristicRing;
use rand::Rng;
use x25519_dalek::StaticSecret;

use crate::chain::{ChainView, OutputRecord, Tx};
use crate::circuit::SpendCircuit;

/// A note the wallet owns: the decrypted opening + its accumulator position and
/// spent state.
#[derive(Clone, Debug)]
pub struct OwnedNote {
    pub value: u64,
    pub rho: Rho,
    pub r: Blinding,
    pub memo: [u8; MEMO_BYTES],
    pub leaf_index: u64,
    pub cm: Digest,
    pub spent: bool,
}

/// A watch-only viewing key: detects + decrypts incoming notes but holds no
/// `nk`, so it can NEVER derive a nullifier or a spend witness.
pub struct ViewingKey {
    enc_sk: StaticSecret,
    owner: Digest,
}

impl ViewingKey {
    /// Detect payments in the scan feed. Returns `(leaf_index, value, memo)`
    /// for every output that decrypts to us — visibility, not spendability.
    pub fn detect(
        &self,
        chain: &impl ChainView,
        from_cursor: u64,
    ) -> Vec<(u64, u64, [u8; MEMO_BYTES])> {
        chain
            .outputs_since(from_cursor)
            .into_iter()
            .filter_map(|o| {
                try_decrypt(&self.enc_sk, &self.owner, &o.cm, &o.ciphertext)
                    .map(|pt| (o.leaf_index, pt.value, pt.memo))
            })
            .collect()
    }
}

/// Errors from the pay flow.
#[derive(Debug, PartialEq, Eq)]
pub enum PayError {
    /// Fewer than two spendable notes, or the two largest do not cover
    /// `amount + fee` (the 2-in shape caps a single spend to two notes).
    InsufficientFunds,
    /// A selected note has no membership path at the current root (stale store).
    MissingPath,
    /// The recipient address's encryption key is non-contributory.
    BadRecipient,
}

/// A wallet over one seed.
pub struct Wallet {
    keys: WalletKeys,
    owner: Digest,
    address: Address,
    notes: Vec<OwnedNote>,
    scan_cursor: u64,
}

impl Wallet {
    /// Open a wallet from its seed (derives spend + view keys).
    pub fn from_seed(seed: &[u8]) -> Self {
        let keys = WalletKeys::from_seed(seed);
        let owner = owner_key(&keys.nk);
        let address = keys.address();
        Wallet {
            keys,
            owner,
            address,
            notes: Vec::new(),
            scan_cursor: 0,
        }
    }

    /// The public payment address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// The encoded address string a stranger pays to.
    pub fn address_string(&self, hrp: &str) -> String {
        self.address.encode(hrp)
    }

    /// Export a watch-only viewing key (detect + decrypt, never spend).
    pub fn viewing_key(&self) -> ViewingKey {
        ViewingKey {
            enc_sk: StaticSecret::from(self.keys.enc_sk.to_bytes()),
            owner: self.owner,
        }
    }

    /// Scan new outputs (idempotent): trial-decrypt, apply the strict
    /// spendability gate, record owned notes by leaf index (dedup), then refresh
    /// spent-state from the chain's nullifier set.
    pub fn scan(&mut self, chain: &impl ChainView) {
        for OutputRecord {
            leaf_index,
            cm,
            ciphertext,
        } in chain.outputs_since(self.scan_cursor)
        {
            if self.notes.iter().any(|n| n.leaf_index == leaf_index) {
                continue; // idempotent rescan
            }
            if let Some(pt) = try_decrypt(&self.keys.enc_sk, &self.owner, &cm, &ciphertext) {
                self.notes.push(OwnedNote {
                    value: pt.value,
                    rho: pt.rho,
                    r: pt.r,
                    memo: pt.memo,
                    leaf_index,
                    cm,
                    spent: false,
                });
            }
        }
        self.scan_cursor = chain.output_count();
        self.refresh_spent(chain);
    }

    /// Mark any owned note whose nullifier is on-chain as spent (catches spends
    /// made from another wallet instance / a stale copy of this store).
    fn refresh_spent(&mut self, chain: &impl ChainView) {
        for n in self.notes.iter_mut().filter(|n| !n.spent) {
            let nf = nullifier(&self.keys.nk, &n.rho);
            if chain.nullifier_seen(&nf) {
                n.spent = true;
            }
        }
    }

    /// Total spendable balance (owned ∩ unspent).
    pub fn balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| !n.spent)
            .map(|n| n.value)
            .sum()
    }

    /// Deterministic 2-note selection: the two highest-value unspent notes,
    /// ordered `(value desc, leaf_index asc)`. The fixed 2-in shape means a
    /// single spend consumes exactly two notes, so it can spend at most the sum
    /// of the two largest; multi-note consolidation (fold N notes → 1 over
    /// several txs) and a circuit dummy-input flag (spend a single note) are the
    /// documented follow-ups.
    fn select(&self, need: u64) -> Result<[OwnedNote; 2], PayError> {
        let mut unspent: Vec<&OwnedNote> = self.notes.iter().filter(|n| !n.spent).collect();
        unspent.sort_by(|a, b| b.value.cmp(&a.value).then(a.leaf_index.cmp(&b.leaf_index)));
        match unspent.as_slice() {
            [a, b, ..] if a.value + b.value >= need => Ok([(*a).clone(), (*b).clone()]),
            _ => Err(PayError::InsufficientFunds),
        }
    }

    /// Build a shielded payment to `recipient` of `amount` (with `fee`): select
    /// two inputs, derive witnesses at the current root, build the recipient
    /// note + change-to-self (both encrypted, §6 uniformity), and produce the
    /// hiding spend proof. Marks the inputs spent locally on success.
    pub fn pay(
        &mut self,
        chain: &impl ChainView,
        circuit: &SpendCircuit,
        recipient: &Address,
        amount: u64,
        fee: u64,
    ) -> Result<Tx, PayError> {
        let need = amount + fee;
        let sel = self.select(need)?;

        let root = chain.current_root();
        let paths: [MerklePath; 2] = [
            chain
                .authentication_path(sel[0].leaf_index)
                .ok_or(PayError::MissingPath)?,
            chain
                .authentication_path(sel[1].leaf_index)
                .ok_or(PayError::MissingPath)?,
        ];
        let inputs: [InputNote; 2] = core::array::from_fn(|i| InputNote {
            value: sel[i].value,
            nk: self.keys.nk,
            rho: sel[i].rho,
            r: sel[i].r,
            index: sel[i].leaf_index,
        });

        let total_in = sel[0].value + sel[1].value;
        let change = total_in - need;

        // Output 0 = recipient note; output 1 = change to self. Fresh nonces.
        let (rho_pay, r_pay) = (random_digest(), random_digest());
        let (rho_chg, r_chg) = (random_digest(), random_digest());
        let outputs: [OutputNote; 2] = [
            OutputNote {
                value: amount,
                owner: recipient.owner,
                rho: rho_pay,
                r: r_pay,
            },
            OutputNote {
                value: change,
                owner: self.owner,
                rho: rho_chg,
                r: r_chg,
            },
        ];

        // The proof (public cm_out0/1 = these two commitments).
        let (proof_bytes, publics) = circuit.prove(&inputs, &paths, root, &outputs, fee);

        // Encrypt each output to its recipient, bound to its on-chain cm.
        let cm_pay = note_commitment(amount, &recipient.owner, &rho_pay, &r_pay);
        let cm_chg = note_commitment(change, &self.owner, &rho_chg, &r_chg);
        let pt_pay = NotePlaintext {
            value: amount,
            rho: rho_pay,
            r: r_pay,
            memo: [0u8; MEMO_BYTES],
        };
        let pt_chg = NotePlaintext {
            value: change,
            rho: rho_chg,
            r: r_chg,
            memo: [0u8; MEMO_BYTES],
        };
        let ct_pay = encrypt_note(recipient, &cm_pay, &pt_pay).ok_or(PayError::BadRecipient)?;
        let ct_chg =
            encrypt_note(&self.address, &cm_chg, &pt_chg).expect("own address is contributory");

        // Mark inputs spent locally (defensive; the chain's nullifier set is
        // authoritative and will confirm on the next scan).
        for s in &sel {
            if let Some(n) = self.notes.iter_mut().find(|n| n.leaf_index == s.leaf_index) {
                n.spent = true;
            }
        }

        Ok(Tx {
            proof_bytes,
            public_values: publics,
            out_ciphertexts: [ct_pay, ct_chg],
        })
    }
}

/// A fresh random digest (per-note nonce / blinding), from OS entropy.
fn random_digest() -> Digest {
    let mut rng = rand::rng();
    core::array::from_fn(|_| F::from_u32(rng.next_u32()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_engine::poseidon::DIGEST_ELEMS;

    #[test]
    fn balance_counts_only_unspent() {
        let mut w = Wallet::from_seed(b"w");
        w.notes.push(OwnedNote {
            value: 100,
            rho: [F::ZERO; DIGEST_ELEMS],
            r: [F::ZERO; DIGEST_ELEMS],
            memo: [0; MEMO_BYTES],
            leaf_index: 0,
            cm: [F::ZERO; DIGEST_ELEMS],
            spent: false,
        });
        w.notes.push(OwnedNote {
            value: 50,
            rho: [F::ZERO; DIGEST_ELEMS],
            r: [F::ZERO; DIGEST_ELEMS],
            memo: [0; MEMO_BYTES],
            leaf_index: 1,
            cm: [F::ZERO; DIGEST_ELEMS],
            spent: true,
        });
        assert_eq!(w.balance(), 100);
    }

    #[test]
    fn select_needs_two_notes_and_picks_largest() {
        let mut w = Wallet::from_seed(b"w");
        assert!(matches!(w.select(10), Err(PayError::InsufficientFunds)));
        for (i, v) in [30u64, 100, 70].into_iter().enumerate() {
            w.notes.push(OwnedNote {
                value: v,
                rho: [F::ZERO; DIGEST_ELEMS],
                r: [F::ZERO; DIGEST_ELEMS],
                memo: [0; MEMO_BYTES],
                leaf_index: i as u64,
                cm: [F::ZERO; DIGEST_ELEMS],
                spent: false,
            });
        }
        let sel = w.select(150).unwrap();
        assert_eq!([sel[0].value, sel[1].value], [100, 70]); // two largest
        assert!(matches!(w.select(171), Err(PayError::InsufficientFunds))); // 100+70 < 171
    }
}
