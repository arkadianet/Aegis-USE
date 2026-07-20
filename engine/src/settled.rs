//! The settled-burn nullifier accumulator (E3, Stage-T basic form) — a
//! fixed-depth-248 Poseidon2 sparse Merkle set (SMT) over settled `nf0`s.
//!
//! Per `settled-burn-accumulator-design.md` §2: the vault carries a chained
//! register **R6 = the root of this set**. Each settlement's guest proves, for
//! every withdrawal, `nf0 ∉ set(R6_in)`, inserts it, and commits `R6_out` — so a
//! burn can be settled **at most once, ever**, closing the double-pay-by-replay
//! vector independently of epoch canonicality. Epoch-validity (E1) closes
//! *fabrication*; this closes *replay*; they are complementary.
//!
//! ## Structure (design §2, "recommended")
//! - **Key** = the 248-bit canonical bit-decomposition of `nf0` (8 BabyBear
//!   limbs, each `< 2^31`; bit `k` = bit `k mod 31` of limb `k / 31`, LSB-first).
//!   Full width — no truncation, no key-collision argument (distinct `nf0` ⇒
//!   distinct SMT position, unconditionally).
//! - **Leaves**: `EMPTY = [0; 8]`, `OCCUPIED = [1; 8]` (the key already *is* the
//!   nullifier, so the marker suffices).
//! - **Internal node** = the engine's t=16 Poseidon2 2-to-1 [`compress`] — the
//!   same permutation the note tree and frontier already use in-guest.
//! - **Empty-set root** = `zeros_settled[248]`, a pinned genesis constant.
//! - **Non-membership + insert in one witness**: 248 siblings; verify the path
//!   with leaf `EMPTY` reproduces the running root (proves absence), then
//!   recompute the same path with leaf `OCCUPIED` (the insert). 496 compressions
//!   per `nf0`, always — O(1) per settled burn for the life of the chain.
//!
//! Stage-M generalizes this to *all* suffix nullifiers (both `nf`s of every tx)
//! via a native Poseidon2 AIR in the recursion tree (design §E3 endgame); this
//! module is the Stage-T in-guest basic form (burn `nf0`s only).

use std::sync::OnceLock;

use p3_field::PrimeCharacteristicRing;

use crate::poseidon::{compress, hash_domain, Digest, DIGEST_ELEMS, F};

/// Fixed SMT depth: 8 limbs × 31 canonical bits = 248-bit key.
pub const SETTLED_DEPTH: usize = 248;
/// Canonical bits per BabyBear limb (`p < 2^31`).
const BITS_PER_LIMB: usize = 31;

/// Domain-separation tag for the peg-in one-mint-ever keys living in the SAME
/// R6 SMT as the burn/spend nullifiers (D-F3, `epoch-validity-f1-f3-design.md`
/// §3.1 step 6b). A settled nullifier is inserted under its raw digest (itself a
/// `DOMAIN_NULLIFIER`-tagged Poseidon2 output); a used peg-in is inserted under
/// [`pegin_used_key`] = `hash_domain(DOMAIN_PEGIN_USED, box_id_limbs)`. The two
/// key families are therefore Poseidon2-domain-separated: a collision between a
/// nullifier key and a peg-in key would require a `DOMAIN_NULLIFIER` output to
/// equal a `DOMAIN_PEGIN_USED` output (a ~2^124 birthday event), and the peg-in
/// side is not attacker-grindable — `box_id` must be a real, buried Ergo deposit
/// (F3). One accumulator thus safely serves both one-spend-ever and
/// one-mint-ever. Pinned; changing it is chain-id-breaking.
pub const DOMAIN_PEGIN_USED: u32 = 0x0A05;

/// The R6 SMT key digest for a used peg-in deposit `box_id` (the 32-byte Ergo
/// box id). Maps the box id into the digest space via a domain-separated
/// Poseidon2 sponge over its eight canonical little-endian `u32` limbs, so the
/// peg-in key namespace never overlaps the nullifier namespace ([`DOMAIN_PEGIN_USED`]).
///
/// The resulting digest is fed to [`verify_insert`] exactly like a nullifier —
/// its 248-bit [`key_bits`] decomposition is the SMT position. Pinned by
/// [`tests::pegin_used_key_is_domain_separated`].
pub fn pegin_used_key(box_id: &[u8; 32]) -> Digest {
    let mut limbs = [F::ZERO; DIGEST_ELEMS];
    for (limb, chunk) in limbs.iter_mut().zip(box_id.chunks_exact(4)) {
        *limb = F::from_u32(u32::from_le_bytes(chunk.try_into().expect("4-byte chunk")));
    }
    hash_domain(DOMAIN_PEGIN_USED, &limbs)
}

/// The empty-position leaf.
pub const EMPTY: Digest = [F::ZERO; DIGEST_ELEMS];

/// The occupied-position marker leaf (`[1; 8]`).
pub fn occupied() -> Digest {
    [F::ONE; DIGEST_ELEMS]
}

/// `zeros_settled[level]` = root of an all-empty subtree of height `level`;
/// `zeros_settled[0] = EMPTY`, `zeros_settled[i+1] = compress(z[i], z[i])`.
fn zeros_settled() -> &'static [Digest; SETTLED_DEPTH + 1] {
    static Z: OnceLock<[Digest; SETTLED_DEPTH + 1]> = OnceLock::new();
    Z.get_or_init(|| {
        let mut z = [EMPTY; SETTLED_DEPTH + 1];
        for level in 0..SETTLED_DEPTH {
            z[level + 1] = compress(&z[level], &z[level]);
        }
        z
    })
}

/// The pinned empty-set root (`zeros_settled[248]`) — R6's deploy value.
pub fn empty_settled_root() -> Digest {
    zeros_settled()[SETTLED_DEPTH]
}

/// The 248-bit SMT key of an `nf0`, LSB-first: bit `k` = bit `k mod 31` of the
/// canonical `u32` of limb `k / 31`. Pinned by [`tests::key_bits_pinned_vector`].
pub fn key_bits(nf0: &Digest) -> [bool; SETTLED_DEPTH] {
    use p3_field::PrimeField32;
    let limbs: [u32; DIGEST_ELEMS] = core::array::from_fn(|i| nf0[i].as_canonical_u32());
    core::array::from_fn(|k| {
        let limb = limbs[k / BITS_PER_LIMB];
        (limb >> (k % BITS_PER_LIMB)) & 1 == 1
    })
}

/// Recompute the SMT root along `key`'s path with a chosen `leaf`, given the
/// 248 sibling digests (bottom→top). `key[level] == false` ⇒ the running node is
/// the LEFT child at that level. Mirrors [`crate::merkle::root_from_path`].
pub fn smt_root_with_leaf(
    key: &[bool; SETTLED_DEPTH],
    leaf: Digest,
    siblings: &[Digest; SETTLED_DEPTH],
) -> Digest {
    let mut node = leaf;
    for level in 0..SETTLED_DEPTH {
        node = if key[level] {
            compress(&siblings[level], &node)
        } else {
            compress(&node, &siblings[level])
        };
    }
    node
}

/// Non-membership-then-insert error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SettledError {
    #[error("nf0 already settled (non-membership path does not reproduce R6_in)")]
    AlreadySettled,
}

/// Prove `nf0 ∉ set(root_in)` with `siblings` and return the post-insert root.
///
/// The witness is valid iff replaying `key`'s path with an `EMPTY` leaf
/// reproduces `root_in` (absence); the returned root replays the SAME path with
/// the `OCCUPIED` leaf (the insert). A settler presenting a member gets
/// [`SettledError::AlreadySettled`] — the exact replay-close.
pub fn verify_insert(
    root_in: &Digest,
    nf0: &Digest,
    siblings: &[Digest; SETTLED_DEPTH],
) -> Result<Digest, SettledError> {
    let key = key_bits(nf0);
    if &smt_root_with_leaf(&key, EMPTY, siblings) != root_in {
        return Err(SettledError::AlreadySettled);
    }
    Ok(smt_root_with_leaf(&key, occupied(), siblings))
}

/// A host-side settled-burn set — stores inserted keys and generates the
/// 248-sibling non-membership witness per key at its insert point. Non-consensus
/// (tooling only): the guest is served witnesses, it never holds the set.
#[derive(Clone, Debug, Default)]
pub struct SettledSet {
    keys: Vec<[bool; SETTLED_DEPTH]>,
}

impl SettledSet {
    /// A fresh empty set (root = [`empty_settled_root`]).
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Whether `nf0` is already in the set.
    pub fn contains(&self, nf0: &Digest) -> bool {
        let k = key_bits(nf0);
        self.keys.contains(&k)
    }

    /// The current set root.
    pub fn root(&self) -> Digest {
        self.subtree_root(&self.keys.iter().collect::<Vec<_>>(), SETTLED_DEPTH)
    }

    /// Root of the height-`level` subtree containing exactly `occ` keys (already
    /// filtered to this node's prefix). Empty ⇒ the pinned zeros constant.
    fn subtree_root(&self, occ: &[&[bool; SETTLED_DEPTH]], level: usize) -> Digest {
        if occ.is_empty() {
            return zeros_settled()[level];
        }
        if level == 0 {
            return occupied();
        }
        let bit = level - 1;
        let zero: Vec<&[bool; SETTLED_DEPTH]> = occ.iter().copied().filter(|k| !k[bit]).collect();
        let one: Vec<&[bool; SETTLED_DEPTH]> = occ.iter().copied().filter(|k| k[bit]).collect();
        compress(
            &self.subtree_root(&zero, level - 1),
            &self.subtree_root(&one, level - 1),
        )
    }

    /// The 248-sibling non-membership witness for `nf0` against the CURRENT set.
    pub fn witness(&self, nf0: &Digest) -> [Digest; SETTLED_DEPTH] {
        let key = key_bits(nf0);
        core::array::from_fn(|level| {
            // Sibling at `level`: keys sharing `key`'s bits above `level`, with
            // bit[level] flipped.
            let sib: Vec<&[bool; SETTLED_DEPTH]> = self
                .keys
                .iter()
                .filter(|k| {
                    k[level] != key[level] && (level + 1..SETTLED_DEPTH).all(|b| k[b] == key[b])
                })
                .collect();
            self.subtree_root(&sib, level)
        })
    }

    /// Insert `nf0` (idempotent on the key set).
    pub fn insert(&mut self, nf0: &Digest) {
        let k = key_bits(nf0);
        if !self.keys.contains(&k) {
            self.keys.push(k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn nf(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base.wrapping_mul(7).wrapping_add(i as u32 * 101) + 1))
    }

    // ----- happy path -----

    #[test]
    fn empty_root_is_pinned_and_stable() {
        assert_eq!(empty_settled_root(), empty_settled_root());
        assert_eq!(SettledSet::new().root(), empty_settled_root());
    }

    #[test]
    fn insert_then_membership_and_nonmembership() {
        let mut set = SettledSet::new();
        let a = nf(1);
        // Fresh burn: non-membership witness reproduces the empty root, insert ok.
        let w = set.witness(&a);
        let root_out = verify_insert(&empty_settled_root(), &a, &w).expect("fresh nf0 inserts");
        set.insert(&a);
        assert_eq!(
            set.root(),
            root_out,
            "guest insert root matches host set root"
        );
    }

    #[test]
    fn chained_inserts_track_the_set_root() {
        let mut set = SettledSet::new();
        let mut root = empty_settled_root();
        for i in 0..6u32 {
            let a = nf(i);
            let w = set.witness(&a);
            root = verify_insert(&root, &a, &w).expect("distinct nf0 inserts");
            set.insert(&a);
            assert_eq!(set.root(), root);
        }
    }

    // ----- error paths (the replay-close) -----

    #[test]
    fn already_settled_nf0_is_rejected() {
        let mut set = SettledSet::new();
        let a = nf(42);
        let w0 = set.witness(&a);
        let root1 = verify_insert(&empty_settled_root(), &a, &w0).unwrap();
        set.insert(&a);
        // Re-presenting the same burn against the post-insert root: the
        // non-membership path can no longer reproduce root1 → rejected.
        let w1 = set.witness(&a);
        assert_eq!(
            verify_insert(&root1, &a, &w1),
            Err(SettledError::AlreadySettled),
            "a settled nf0 cannot be settled twice"
        );
    }

    // ----- round-trips / order independence -----

    #[test]
    fn set_root_is_order_independent() {
        let mut a = SettledSet::new();
        let mut b = SettledSet::new();
        let xs = [nf(3), nf(9), nf(17), nf(25)];
        for x in &xs {
            a.insert(x);
        }
        for x in xs.iter().rev() {
            b.insert(x);
        }
        assert_eq!(
            a.root(),
            b.root(),
            "root is a function of the set, not order"
        );
    }

    // ----- peg-in one-mint-ever (domain-separated R6 sharing) -----

    #[test]
    fn pegin_used_key_is_deterministic_and_box_id_bound() {
        assert_eq!(pegin_used_key(&[7u8; 32]), pegin_used_key(&[7u8; 32]));
        let mut other = [7u8; 32];
        other[0] = 8;
        assert_ne!(
            pegin_used_key(&[7u8; 32]),
            pegin_used_key(&other),
            "distinct box ids must map to distinct keys"
        );
    }

    #[test]
    fn pegin_used_key_is_domain_separated_from_a_raw_nullifier() {
        // A nullifier whose limbs are numerically the box-id limbs must NOT
        // land at the same R6 position as the peg-in key for that box id — the
        // domain tag is the separation. (This is the one-sided separation the
        // shared-R6 decision D-F3 relies on.)
        let box_id = [0x11u8; 32];
        let raw_nf: Digest = core::array::from_fn(|i| {
            F::from_u32(u32::from_le_bytes(
                box_id[i * 4..i * 4 + 4].try_into().unwrap(),
            ))
        });
        assert_ne!(
            key_bits(&raw_nf),
            key_bits(&pegin_used_key(&box_id)),
            "peg-in key must be domain-separated from the same-limbs nullifier"
        );
    }

    #[test]
    fn a_used_pegin_cannot_be_minted_twice_across_settlements() {
        // One-mint-ever: insert a peg-in box id into R6, then a second insert of
        // the same box id against the post-insert root is rejected (member).
        let mut set = SettledSet::new();
        let key = pegin_used_key(&[0xABu8; 32]);
        let w0 = set.witness(&key);
        let root1 = verify_insert(&empty_settled_root(), &key, &w0).expect("fresh mint inserts");
        set.insert(&key);
        let w1 = set.witness(&key);
        assert_eq!(
            verify_insert(&root1, &key, &w1),
            Err(SettledError::AlreadySettled),
            "a peg-in deposit can be minted at most once, ever"
        );
    }

    #[test]
    fn nullifiers_and_pegins_coexist_in_one_r6() {
        // Both key families insert into the SAME set without interfering.
        let mut set = SettledSet::new();
        let mut root = empty_settled_root();
        let nf_a = nf(1);
        let nf_b = nf(2);
        let pk_a = pegin_used_key(&[1u8; 32]);
        let pk_b = pegin_used_key(&[2u8; 32]);
        for key in [nf_a, nf_b, pk_a, pk_b] {
            let w = set.witness(&key);
            root = verify_insert(&root, &key, &w).expect("distinct keys insert");
            set.insert(&key);
        }
        assert_ne!(root, empty_settled_root());
    }

    // ----- oracle parity -----

    #[test]
    fn key_bits_pinned_vector() {
        // nf0 = limbs [1, 2, 4, 0, ...]: bit0 of limb0 set (k=0), bit1 of limb1
        // set (k = 31 + 1 = 32), bit2 of limb2 set (k = 62 + 2 = 64).
        let mut d = EMPTY;
        d[0] = F::from_u32(1);
        d[1] = F::from_u32(2);
        d[2] = F::from_u32(4);
        let bits = key_bits(&d);
        assert!(bits[0]);
        assert!(bits[32]);
        assert!(bits[64]);
        let set: usize = bits.iter().filter(|b| **b).count();
        assert_eq!(set, 3, "exactly three bits set");
    }

    #[test]
    fn nonmembership_against_naive_map_reference() {
        // Oracle: a naive full-key membership map must agree with the SMT witness
        // path across an insert boundary.
        let mut set = SettledSet::new();
        let members = [nf(100), nf(200), nf(300)];
        for m in &members {
            set.insert(m);
        }
        let root = set.root();
        // A non-member verifies non-membership; a member does not.
        let outsider = nf(999);
        assert!(!set.contains(&outsider));
        assert!(verify_insert(&root, &outsider, &set.witness(&outsider)).is_ok());
        for m in &members {
            assert!(set.contains(m));
            assert_eq!(
                verify_insert(&root, m, &set.witness(m)),
                Err(SettledError::AlreadySettled),
            );
        }
    }
}
