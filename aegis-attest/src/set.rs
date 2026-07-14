//! The k-of-n attester federation: a canonical member set + threshold, and
//! the sign / verify / threshold-verify operations over it.

use sha2::{Digest, Sha256};

use crate::attestation::{message, Attestation, Purpose};
use crate::key::{AttesterKey, PublicKey};

/// Domain tag for the `set_id` commitment.
const SET_DOMAIN: &[u8] = b"aegis:attest:set:v1";

#[derive(Debug, thiserror::Error)]
pub enum SetError {
    #[error("attester set is empty")]
    Empty,
    #[error("threshold k={k} must be in 1..=n where n={n}")]
    BadThreshold { k: usize, n: usize },
    #[error("duplicate attester public key in the set")]
    DuplicateMember,
}

/// A k-of-n attester federation: a sorted, duplicate-free set of member
/// public keys and a threshold `k`. Canonicalized on construction so its
/// [`set_id`](AttesterSet::set_id) is independent of input order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AttesterSet {
    members: Vec<PublicKey>, // sorted ascending, unique
    k: usize,
}

impl AttesterSet {
    /// Build a set from members + threshold. Members are sorted and checked
    /// for duplicates; `k` must be in `1..=n`.
    pub fn new(mut members: Vec<PublicKey>, k: usize) -> Result<Self, SetError> {
        if members.is_empty() {
            return Err(SetError::Empty);
        }
        let n0 = members.len();
        members.sort();
        members.dedup();
        if members.len() != n0 {
            return Err(SetError::DuplicateMember);
        }
        let n = members.len();
        if k < 1 || k > n {
            return Err(SetError::BadThreshold { k, n });
        }
        Ok(AttesterSet { members, k })
    }

    pub fn members(&self) -> &[PublicKey] {
        &self.members
    }

    pub fn k(&self) -> usize {
        self.k
    }

    pub fn n(&self) -> usize {
        self.members.len()
    }

    pub fn contains(&self, pk: &PublicKey) -> bool {
        self.members.binary_search(pk).is_ok()
    }

    /// Canonical set identifier bound into every signed message, so an
    /// attestation for one set can never be replayed against another — a
    /// different member list OR a different threshold yields a different id.
    pub fn set_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(SET_DOMAIN);
        h.update((self.k as u32).to_le_bytes());
        h.update((self.n() as u32).to_le_bytes());
        for pk in &self.members {
            h.update(pk.to_bytes());
        }
        h.finalize().into()
    }

    /// Sign a `(purpose, payload)` statement as `key`. Producing a signature
    /// does not require membership; [`verify`](AttesterSet::verify) enforces
    /// it, so a stray signature from a non-member is simply never counted.
    pub fn attest(&self, key: &AttesterKey, purpose: Purpose, payload: &[u8]) -> Attestation {
        Attestation {
            signer: key.public(),
            sig: key.sign_message(&message(&self.set_id(), purpose, payload)),
        }
    }

    /// A single attestation is valid iff its signer is a member and the
    /// signature verifies over this exact `(set, purpose, payload)`.
    pub fn verify(&self, purpose: Purpose, payload: &[u8], att: &Attestation) -> bool {
        self.contains(&att.signer)
            && att
                .signer
                .verify_message(&message(&self.set_id(), purpose, payload), &att.sig)
    }

    /// The threshold check: at least `k` **distinct** members each supply a
    /// valid signature over the same statement. Duplicate signers count
    /// once; non-members and bad signatures are ignored.
    pub fn verify_threshold(&self, purpose: Purpose, payload: &[u8], atts: &[Attestation]) -> bool {
        let msg = message(&self.set_id(), purpose, payload);
        let mut seen: Vec<PublicKey> = Vec::with_capacity(self.k);
        for att in atts {
            if self.contains(&att.signer)
                && !seen.contains(&att.signer)
                && att.signer.verify_message(&msg, &att.sig)
            {
                seen.push(att.signer);
                if seen.len() >= self.k {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn key(seed: u8) -> AttesterKey {
        AttesterKey::from_secret_bytes(&[seed; 32]).expect("small constant scalar is valid")
    }

    /// A `k`-of-`n` set over deterministic keys with seeds `1..=n`.
    fn set_of(n: u8, k: usize) -> AttesterSet {
        let members = (1..=n).map(|s| key(s).public()).collect();
        AttesterSet::new(members, k).expect("valid set")
    }

    const PAYLOAD: &[u8] = b"digest-D:height=42:epoch=0";

    // ----- happy path -----

    #[test]
    fn single_member_attestation_verifies() {
        let set = set_of(3, 2);
        let att = set.attest(&key(1), Purpose::Tip, PAYLOAD);
        assert!(set.verify(Purpose::Tip, PAYLOAD, &att));
    }

    #[test]
    fn threshold_met_with_exactly_k_verifies() {
        let set = set_of(5, 3);
        let atts: Vec<_> = [1u8, 2, 3]
            .iter()
            .map(|s| set.attest(&key(*s), Purpose::Unlock, PAYLOAD))
            .collect();
        assert!(set.verify_threshold(Purpose::Unlock, PAYLOAD, &atts));
    }

    #[test]
    fn set_id_is_order_independent() {
        let a =
            AttesterSet::new(vec![key(1).public(), key(2).public(), key(3).public()], 2).unwrap();
        let b =
            AttesterSet::new(vec![key(3).public(), key(1).public(), key(2).public()], 2).unwrap();
        assert_eq!(a.set_id(), b.set_id());
    }

    // ----- error paths / negative -----

    #[test]
    fn threshold_below_k_fails() {
        let set = set_of(5, 3);
        let atts: Vec<_> = [1u8, 2]
            .iter()
            .map(|s| set.attest(&key(*s), Purpose::Unlock, PAYLOAD))
            .collect();
        assert!(!set.verify_threshold(Purpose::Unlock, PAYLOAD, &atts));
    }

    #[test]
    fn duplicate_signer_counts_once() {
        let set = set_of(5, 3);
        // Three attestations but only two distinct signers → below k=3.
        let a1 = set.attest(&key(1), Purpose::Unlock, PAYLOAD);
        let a2 = set.attest(&key(2), Purpose::Unlock, PAYLOAD);
        let atts = vec![a1, a2, a1];
        assert!(!set.verify_threshold(Purpose::Unlock, PAYLOAD, &atts));
    }

    #[test]
    fn non_member_signature_is_ignored() {
        let set = set_of(3, 2);
        let outsider = key(99); // not in seeds 1..=3
        let a1 = set.attest(&key(1), Purpose::Unlock, PAYLOAD);
        let a_out = set.attest(&outsider, Purpose::Unlock, PAYLOAD);
        // One real member + one outsider < k=2.
        assert!(!set.verify_threshold(Purpose::Unlock, PAYLOAD, &[a1, a_out]));
        assert!(!set.verify(Purpose::Unlock, PAYLOAD, &a_out));
    }

    #[test]
    fn wrong_purpose_rejected() {
        let set = set_of(3, 2);
        let att = set.attest(&key(1), Purpose::Tip, PAYLOAD);
        assert!(!set.verify(Purpose::Unlock, PAYLOAD, &att));
    }

    #[test]
    fn wrong_payload_rejected() {
        let set = set_of(3, 2);
        let att = set.attest(&key(1), Purpose::Tip, PAYLOAD);
        assert!(!set.verify(Purpose::Tip, b"a different tip", &att));
    }

    #[test]
    fn attestation_from_a_different_set_rejected() {
        // Same members, different threshold ⇒ different set_id ⇒ the
        // signature must not carry over.
        let set_k2 = set_of(3, 2);
        let set_k3 = set_of(3, 3);
        let att = set_k2.attest(&key(1), Purpose::Tip, PAYLOAD);
        assert!(set_k2.verify(Purpose::Tip, PAYLOAD, &att));
        assert!(!set_k3.verify(Purpose::Tip, PAYLOAD, &att));
    }

    #[test]
    fn tampered_signature_rejected() {
        let set = set_of(3, 2);
        let mut att = set.attest(&key(1), Purpose::Tip, PAYLOAD);
        att.sig[0] ^= 0x01;
        assert!(!set.verify(Purpose::Tip, PAYLOAD, &att));
    }

    #[test]
    fn new_empty_set_errors() {
        assert!(matches!(AttesterSet::new(vec![], 1), Err(SetError::Empty)));
    }

    #[test]
    fn new_zero_threshold_errors() {
        let members = vec![key(1).public()];
        assert!(matches!(
            AttesterSet::new(members, 0),
            Err(SetError::BadThreshold { k: 0, n: 1 })
        ));
    }

    #[test]
    fn new_threshold_exceeds_n_errors() {
        let members = vec![key(1).public(), key(2).public()];
        assert!(matches!(
            AttesterSet::new(members, 3),
            Err(SetError::BadThreshold { k: 3, n: 2 })
        ));
    }

    #[test]
    fn new_duplicate_member_errors() {
        let members = vec![key(1).public(), key(1).public()];
        assert!(matches!(
            AttesterSet::new(members, 1),
            Err(SetError::DuplicateMember)
        ));
    }

    #[test]
    fn random_keypair_signs_and_verifies() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(1);
        let members: Vec<_> = (0..3).map(|_| AttesterKey::random(&mut rng)).collect();
        let signer = members[0].clone();
        let set = AttesterSet::new(members.iter().map(|k| k.public()).collect(), 2).unwrap();
        let att = set.attest(&signer, Purpose::Tip, PAYLOAD);
        assert!(set.verify(Purpose::Tip, PAYLOAD, &att));
    }
}
