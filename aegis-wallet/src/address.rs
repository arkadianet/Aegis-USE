//! Wallet address (M4 — reconciled to the payment primitive, option a).
//!
//! The address is the recipient's spend key as a public point,
//! `pk = nk·B` ([`aegis_crypto::payment::PaymentAddress`]) — the value a sender
//! folds additively into a note so that only the `nk`-holder can spend it (see
//! `dev-docs/sidechain/payment-primitive-design.md`). Revealing `pk` leaks
//! nothing (recovering `nk` is the discrete log).
//!
//! **One address per wallet.** The `pk = nk·B` construction has no diversified
//! addresses — that was the accepted cost of option (a) (reusing the audited
//! spend circuit with no new gadget). On-chain notes to this address are still
//! mutually unlinkable (per-note `rho`/`r_key` randomize the commitment), but
//! the address itself is reused across recipients. Address-level unlinkability
//! (Monero-style subaddresses / a viewing-key layer) is future work.
//!
//! Encoded as Bech32m with an Aegis HRP (`use` mainnet / `tuse` testnet). The
//! encoding is a wallet display concern (not consensus) and v1/provisional.

use aegis_crypto::payment::{PaymentAddress, PAYMENT_ADDRESS_BYTES};
use bech32::{FromBase32, ToBase32, Variant};

use crate::keys::SpendingKey;

/// Bech32m human-readable prefix for a mainnet shielded address.
pub const HRP_MAINNET: &str = "use";
/// Bech32m human-readable prefix for a testnet shielded address.
pub const HRP_TESTNET: &str = "tuse";

/// A wallet address: `pk = nk·B`, Bech32m-encoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address(PaymentAddress);

impl Address {
    /// The wallet's address, derived from its spend key: `pk = nk·B`.
    pub fn from_spending_key(sk: &SpendingKey) -> Self {
        Address(PaymentAddress::from_nk(sk.nk()))
    }

    /// The underlying payment address (the value a sender folds into a note).
    pub fn payment_address(&self) -> PaymentAddress {
        self.0
    }

    /// Encode as a Bech32m string under `hrp` (`use1…` / `tuse1…`).
    pub fn encode(&self, hrp: &str) -> String {
        bech32::encode(hrp, self.0.to_bytes().to_base32(), Variant::Bech32m)
            .expect("bech32m encodes")
    }

    /// Decode a Bech32m address, returning `(hrp, address)`.
    pub fn decode(s: &str) -> Result<(String, Address), AddressError> {
        let (hrp, data, variant) = bech32::decode(s).map_err(|_| AddressError::Bech32)?;
        if variant != Variant::Bech32m {
            return Err(AddressError::Bech32);
        }
        let bytes = Vec::<u8>::from_base32(&data).map_err(|_| AddressError::Bech32)?;
        let arr: [u8; PAYMENT_ADDRESS_BYTES] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| AddressError::Length)?;
        let pk = PaymentAddress::from_bytes(&arr).ok_or(AddressError::Point)?;
        Ok((hrp, Address(pk)))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("not a valid bech32m string")]
    Bech32,
    #[error("wrong address payload length")]
    Length,
    #[error("not a valid curve point")]
    Point,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(seed: u8) -> Address {
        Address::from_spending_key(&SpendingKey::from_bytes([seed; 32]))
    }

    // ----- round-trips -----

    #[test]
    fn address_bech32m_roundtrips() {
        let a = addr(3);
        let s = a.encode(HRP_TESTNET);
        assert!(s.starts_with("tuse1"));
        let (hrp, back) = Address::decode(&s).expect("decodes");
        assert_eq!(hrp, HRP_TESTNET);
        assert_eq!(back, a);
    }

    // ----- determinism / distinctness -----

    #[test]
    fn address_is_deterministic_in_the_spending_key() {
        assert_eq!(addr(7), addr(7));
    }

    #[test]
    fn distinct_wallets_have_distinct_addresses() {
        assert_ne!(addr(1), addr(2));
    }

    #[test]
    fn address_matches_pk_equals_nk_times_b() {
        // The address point IS the payment primitive's pk = nk·B.
        let sk = SpendingKey::from_bytes([9u8; 32]);
        assert_eq!(
            addr(9).payment_address(),
            aegis_crypto::payment::PaymentAddress::from_nk(sk.nk())
        );
    }

    // ----- error paths -----

    #[test]
    fn decode_rejects_garbage_and_wrong_length() {
        assert!(matches!(
            Address::decode("not-an-address"),
            Err(AddressError::Bech32)
        ));
        // Valid bech32m but wrong payload length.
        let short = bech32::encode("tuse", [0u8; 8].to_base32(), Variant::Bech32m).unwrap();
        assert!(matches!(Address::decode(&short), Err(AddressError::Length)));
    }
}
