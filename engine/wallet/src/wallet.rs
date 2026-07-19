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

use crate::chain::{ChainView, OutputRecord, Tx, COINBASE_MATURITY};
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
    /// Block height at which this note was committed (for coinbase maturity).
    pub mined_height: u64,
    /// Coinbase notes are unspendable until [`COINBASE_MATURITY`] blocks pass.
    pub is_coinbase: bool,
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
    /// The fixed 2-in shape needs two spendable notes and the wallet holds
    /// fewer. Distinct from [`PayError::InsufficientFunds`] so a single-note
    /// wallet with ample balance gets an actionable error: it needs a second
    /// on-chain note — a received note or a self-owned zero-value dummy
    /// (note-protocol §6 / S3) — before it can spend at all.
    NotEnoughNotes { have: usize },
    /// The two selected notes do not cover `amount + fee` (the 2-in shape
    /// caps a single spend to the sum of the two largest notes).
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
            height,
            is_coinbase,
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
                    mined_height: height,
                    is_coinbase,
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

    /// Total owned unspent value (some may be immature coinbase — see
    /// [`Self::spendable_balance`]).
    pub fn balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| !n.spent)
            .map(|n| n.value)
            .sum()
    }

    /// Whether an unspent note is spendable NOW at `tip_height` (a coinbase note
    /// must be at least [`COINBASE_MATURITY`] blocks old).
    fn is_spendable(&self, n: &OwnedNote, tip_height: u64) -> bool {
        !n.spent
            && (!n.is_coinbase || tip_height.saturating_sub(n.mined_height) >= COINBASE_MATURITY)
    }

    /// Value spendable NOW (excludes immature coinbase notes).
    pub fn spendable_balance(&self, tip_height: u64) -> u64 {
        self.notes
            .iter()
            .filter(|n| self.is_spendable(n, tip_height))
            .map(|n| n.value)
            .sum()
    }

    /// Deterministic 2-note selection, ordered `(value desc, leaf_index asc)`:
    ///
    /// - If the LARGEST note alone covers `need`, pad the second slot with the
    ///   SMALLEST spendable note — the self-owned zero-value dummy of
    ///   note-protocol §6 / S3 when the wallet holds one (zero/dust change
    ///   notes fill this role organically). Padding instead of burning the
    ///   second-largest note preserves the wallet's funded notes, so a single
    ///   real note stays spendable as long as any dummy exists.
    /// - Otherwise the two largest; the fixed 2-in shape caps one spend at
    ///   their sum. Multi-note consolidation and an in-circuit dummy-input
    ///   flag (spend with NO second on-chain note) are the documented
    ///   follow-ups.
    fn select(&self, need: u64, tip_height: u64) -> Result<[OwnedNote; 2], PayError> {
        let mut unspent: Vec<&OwnedNote> = self
            .notes
            .iter()
            .filter(|n| self.is_spendable(n, tip_height))
            .collect();
        unspent.sort_by(|a, b| b.value.cmp(&a.value).then(a.leaf_index.cmp(&b.leaf_index)));
        match unspent.as_slice() {
            [] | [_] => Err(PayError::NotEnoughNotes {
                have: unspent.len(),
            }),
            [a, .., z] if a.value >= need => Ok([(*a).clone(), (*z).clone()]),
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
        let sel = self.select(need, chain.tip_height())?;

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

impl Wallet {
    /// Build a peg-out BURN spend: out0 is the deterministic burn note of
    /// `withdrawal_amount + peg_fee` (owner/nonces per [`aegis_engine::burn`],
    /// derived from this spend's first nullifier AND bound to
    /// `(recipient_prop, withdrawal_amount)` — the D1 recipient binding),
    /// out1 is change to self. The caller wraps the returned `Tx` with the
    /// public withdrawal record for the SAME `(amount, recipient_prop)`; the
    /// chain validates the burn commitment against it, so a mismatched record
    /// (or a settler proving a different recipient) is rejected. Marks the
    /// inputs spent locally on success.
    pub fn burn_spend(
        &mut self,
        chain: &impl ChainView,
        circuit: &SpendCircuit,
        withdrawal_amount: u64,
        peg_fee: u64,
        recipient_prop: &[u8],
        fee: u64,
    ) -> Result<Tx, PayError> {
        use aegis_engine::burn::{burn_nonces, burn_owner};

        let burn_value = withdrawal_amount
            .checked_add(peg_fee)
            .ok_or(PayError::InsufficientFunds)?;
        let need = burn_value
            .checked_add(fee)
            .ok_or(PayError::InsufficientFunds)?;
        let sel = self.select(need, chain.tip_height())?;
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
        // The burn nonces derive from nf0 = nullifier(nk, rho of input 0) —
        // known before proving, unique forever — bound to the intended
        // (recipient, amount) so no other recipient can claim this burn (D1).
        let nf0 = nullifier(&self.keys.nk, &sel[0].rho);
        let (rho_burn, r_burn) = burn_nonces(&nf0, recipient_prop, withdrawal_amount);
        let owner_burn = burn_owner();

        let change = sel[0].value + sel[1].value - need;
        let (rho_chg, r_chg) = (random_digest(), random_digest());
        let outputs: [OutputNote; 2] = [
            OutputNote {
                value: burn_value,
                owner: owner_burn,
                rho: rho_burn,
                r: r_burn,
            },
            OutputNote {
                value: change,
                owner: self.owner,
                rho: rho_chg,
                r: r_chg,
            },
        ];
        let (proof_bytes, publics) = circuit.prove(&inputs, &paths, root, &outputs, fee);

        // §6 uniformity: both output slots carry a fixed-size ciphertext. The
        // burn note has no recipient; encrypt its opening to SELF (bound to
        // the burn cm, so our own scanner rejects it as not-ours).
        let cm_burn = note_commitment(burn_value, &owner_burn, &rho_burn, &r_burn);
        let cm_chg = note_commitment(change, &self.owner, &rho_chg, &r_chg);
        let pt_burn = NotePlaintext {
            value: burn_value,
            rho: rho_burn,
            r: r_burn,
            memo: [0u8; MEMO_BYTES],
        };
        let pt_chg = NotePlaintext {
            value: change,
            rho: rho_chg,
            r: r_chg,
            memo: [0u8; MEMO_BYTES],
        };
        let ct_burn =
            encrypt_note(&self.address, &cm_burn, &pt_burn).expect("own address is contributory");
        let ct_chg =
            encrypt_note(&self.address, &cm_chg, &pt_chg).expect("own address is contributory");

        for s in &sel {
            if let Some(n) = self.notes.iter_mut().find(|n| n.leaf_index == s.leaf_index) {
                n.spent = true;
            }
        }
        Ok(Tx {
            proof_bytes,
            public_values: publics,
            out_ciphertexts: [ct_burn, ct_chg],
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
            mined_height: 0,
            is_coinbase: false,
        });
        w.notes.push(OwnedNote {
            value: 50,
            rho: [F::ZERO; DIGEST_ELEMS],
            r: [F::ZERO; DIGEST_ELEMS],
            memo: [0; MEMO_BYTES],
            leaf_index: 1,
            cm: [F::ZERO; DIGEST_ELEMS],
            spent: true,
            mined_height: 0,
            is_coinbase: false,
        });
        assert_eq!(w.balance(), 100);
    }

    fn wallet_with_notes(values: &[u64]) -> Wallet {
        let mut w = Wallet::from_seed(b"w");
        for (i, v) in values.iter().enumerate() {
            w.notes.push(OwnedNote {
                value: *v,
                rho: [F::ZERO; DIGEST_ELEMS],
                r: [F::ZERO; DIGEST_ELEMS],
                memo: [0; MEMO_BYTES],
                leaf_index: i as u64,
                cm: [F::ZERO; DIGEST_ELEMS],
                spent: false,
                mined_height: 0,
                is_coinbase: false,
            });
        }
        w
    }

    #[test]
    fn select_needs_two_notes_and_picks_largest() {
        let w = wallet_with_notes(&[30, 100, 70]);
        let sel = w.select(150, 0).unwrap();
        assert_eq!([sel[0].value, sel[1].value], [100, 70]); // two largest
        assert!(matches!(w.select(171, 0), Err(PayError::InsufficientFunds))); // 100+70 < 171
    }

    #[test]
    fn select_zero_or_one_note_reports_not_enough_notes() {
        // The campaign UX bug: a single note with ample balance surfaced as
        // "InsufficientFunds". It must be the actionable NotEnoughNotes.
        let w = wallet_with_notes(&[]);
        assert!(matches!(
            w.select(10, 0),
            Err(PayError::NotEnoughNotes { have: 0 })
        ));
        let w = wallet_with_notes(&[5_000]);
        assert!(matches!(
            w.select(10, 0),
            Err(PayError::NotEnoughNotes { have: 1 })
        ));
    }

    #[test]
    fn select_covering_largest_pads_with_smallest_dummy() {
        // S3 dummy mechanics: the largest note covers the spend, so the second
        // slot is padded with the SMALLEST note (the zero-value dummy),
        // preserving the funded 70-note.
        let w = wallet_with_notes(&[70, 100, 0]);
        let sel = w.select(90, 0).unwrap();
        assert_eq!([sel[0].value, sel[1].value], [100, 0]);
    }

    #[test]
    fn select_single_funded_note_plus_zero_dummy_spends() {
        // A wallet holding ONE funded note + a zero-value dummy can spend the
        // funded note — the single-real-note case the fixed 2-in shape
        // otherwise blocks.
        let w = wallet_with_notes(&[5_000, 0]);
        let sel = w.select(3_000, 0).unwrap();
        assert_eq!([sel[0].value, sel[1].value], [5_000, 0]);
    }
}
