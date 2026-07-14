//! Deterministic genesis headers per `consensus.md` §6.
//!
//! No premine: zero pot, empty roots. `EMPTY_TREE_ROOT` is a
//! domain-separated placeholder pinned by test until G1.6 fixes the
//! Curve Tree parameters and supplies the real empty-tree root.

use aegis_spec::Network;

use crate::header::Header;

/// Placeholder Curve Tree empty root — a readable 32-byte tag, NOT a
/// real tree root. Replaced at G1.6 (chain-id-breaking; the pinning
/// test makes that deliberate).
pub const EMPTY_TREE_ROOT_PLACEHOLDER: [u8; 32] = *b"aegis/empty-curve-tree-root/v1..";

/// Placeholder digests for the empty tx set / nullifier set at genesis.
/// `EMPTY_TX_ROOT` is defined in `aegis-types` (the block codec needs it)
/// and re-exported here so `crate::genesis::EMPTY_TX_ROOT` is unchanged.
pub use aegis_types::EMPTY_TX_ROOT;
pub const EMPTY_NULLIFIER_DIGEST: [u8; 32] = *b"aegis/empty-nullifier-set/v1....";

/// Header `reward_claim` sentinel for genesis and any no-coinbase block
/// (all zero — not a valid compressed point, so never a real note; S5b).
pub const EMPTY_REWARD_CLAIM: [u8; 33] = [0u8; 33];

/// Provisional minimum difficulty encoded as compact nbits (difficulty
/// 1000 — trivial, dev-grade; mainnet value is a launch-time decision,
/// tracked in DEFERRED.md).
pub const MIN_DIFFICULTY: u64 = 1_000;

/// Arbitrary frozen genesis timestamps; distinct per network so genesis
/// ids differ. The wall-clock meaning is irrelevant — determinism is
/// the requirement.
fn genesis_timestamp_ms(network: Network) -> u64 {
    match network {
        Network::Dev => 1_760_000_000_000,
        Network::Test => 1_760_000_000_001,
        Network::Main => 1_760_000_000_002,
    }
}

/// Deterministic genesis header (consensus.md §6). No premine: zero
/// pot, zero supply, empty roots.
pub fn genesis_header(network: Network) -> Header {
    Header {
        version: 1,
        prev_id: [0u8; 32],
        height: 0,
        timestamp_ms: genesis_timestamp_ms(network),
        tx_root: EMPTY_TX_ROOT,
        cm_tree_root: EMPTY_TREE_ROOT_PLACEHOLDER,
        nullifier_digest: EMPTY_NULLIFIER_DIGEST,
        pot_balance: 0,
        sc_nbits: ergo_ser::difficulty::encode_compact_bits(&num_bigint::BigUint::from(
            MIN_DIFFICULTY,
        )),
        reward_claim: EMPTY_REWARD_CLAIM,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_spec::Network;

    // ----- happy path -----

    #[test]
    fn genesis_height_zero_prev_zero_pot_zero() {
        for net in [Network::Dev, Network::Test, Network::Main] {
            let g = genesis_header(net);
            assert_eq!(g.height, 0);
            assert_eq!(g.prev_id, [0u8; 32]);
            assert_eq!(g.pot_balance, 0);
            assert_eq!(g.version, 1);
        }
    }

    #[test]
    fn genesis_is_deterministic() {
        assert_eq!(genesis_header(Network::Dev), genesis_header(Network::Dev));
        assert_eq!(
            genesis_header(Network::Dev).id(),
            genesis_header(Network::Dev).id()
        );
    }

    #[test]
    fn genesis_ids_differ_per_network() {
        let dev = genesis_header(Network::Dev).id();
        let test = genesis_header(Network::Test).id();
        let main = genesis_header(Network::Main).id();
        assert_ne!(dev, test);
        assert_ne!(dev, main);
        assert_ne!(test, main);
    }

    #[test]
    fn dev_genesis_id_is_pinned() {
        // Golden regression vector (S5b review L3): the dev genesis id
        // folds in the 33-byte `reward_claim` sentinel. A change here is
        // chain-id-breaking and must be deliberate — this catches
        // accidental drift in any core header field or constant.
        assert_eq!(
            hex::encode(genesis_header(Network::Dev).id()),
            "e369d3c93e403ba39cde560d115f8eb4664f8b10ae8a80a05a1d76730cbeb495"
        );
    }

    #[test]
    fn genesis_uses_placeholder_empty_tree_root() {
        // Pinned until G1.6 supplies the real Curve Tree empty root; a
        // change here is a chain-id-breaking event and must be deliberate.
        assert_eq!(
            genesis_header(Network::Dev).cm_tree_root,
            EMPTY_TREE_ROOT_PLACEHOLDER
        );
    }
}
