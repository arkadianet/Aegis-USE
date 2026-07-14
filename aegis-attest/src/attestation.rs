//! The attestation: one member's signature over a `(set, purpose, payload)`
//! statement. Both the set (`set_id`) and the `Purpose` are bound into the
//! signed bytes, so a signature can never be replayed against a different
//! federation nor repurposed (e.g. a tip attestation reused to authorize an
//! unlock).

use crate::key::PublicKey;

/// Domain tag prefixed to every signed message.
pub(crate) const DOMAIN: &[u8] = b"aegis:attest:v1";

/// What an attestation authorizes. The tag is mixed into the signed message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Purpose {
    /// The signer's canonical best-chain tip (payload = digest ‖ height ‖ epoch).
    Tip,
    /// A bridge peg-out unlock (payload = burn id ‖ claimant ‖ amount ‖ tip digest).
    Unlock,
    /// An R1-T epoch aggregate (payload = epoch ‖ decrypted sum).
    R1tAggregate,
}

impl Purpose {
    fn tag(self) -> &'static [u8] {
        match self {
            Purpose::Tip => b"tip",
            Purpose::Unlock => b"unlock",
            Purpose::R1tAggregate => b"r1t-aggregate",
        }
    }
}

/// One member's signature over a statement. `sig` is a compact (r‖s) ECDSA
/// signature; `signer` identifies which member produced it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attestation {
    pub signer: PublicKey,
    pub sig: [u8; 64],
}

/// The exact bytes an attestation signs:
/// `DOMAIN ‖ set_id ‖ len(tag) ‖ tag ‖ len(payload) ‖ payload`.
/// `DOMAIN` and `set_id` are fixed-length; `tag`/`payload` are length-
/// prefixed, so no two distinct inputs share an encoding.
pub(crate) fn message(set_id: &[u8; 32], purpose: Purpose, payload: &[u8]) -> Vec<u8> {
    let tag = purpose.tag();
    let mut m = Vec::with_capacity(DOMAIN.len() + 32 + 8 + tag.len() + payload.len());
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(set_id);
    m.extend_from_slice(&(tag.len() as u32).to_le_bytes());
    m.extend_from_slice(tag);
    m.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    m.extend_from_slice(payload);
    m
}
