//! `aegis-types` — the Aegis wire types and their canonical codecs.
//!
//! Pure serialization: the header, the fixed 2-in/2-out
//! [`tx::ShieldedTransfer`], and the [`block::Block`] that wraps them.
//! No I/O, no runtime services, no consensus *logic* — just the byte
//! formats and their decoders (the same charter as `aegis-spec`, one
//! level up: `aegis-spec` owns the constants, this crate owns the
//! structures built from them).
//!
//! Split out of `aegis-node` so a client — notably the standalone
//! `aegis-wallet` — can decode blocks and build transfers **without
//! linking the node** (its P2P/mempool/mining/HTTP-server stack, and the
//! spending-key exposure that a network process implies). `aegis-node`
//! re-exports every type here, so its public API and internal paths are
//! unchanged.

pub mod block;
pub mod header;
pub mod tx;

pub use block::{Block, BlockBody, BlockDecodeError, BodyDecodeError};
pub use header::{Header, HeaderDecodeError};
pub use tx::{ShieldedOutput, ShieldedTransfer, TxDecodeError};

/// Pinned empty-tx-set merkle root (consensus.md §6): the canonical
/// digest an empty [`block::BlockBody`] maps to, so empty blocks and
/// genesis agree without depending on merkle-of-zero semantics. Lives
/// here (not in `aegis-node::genesis`) because [`block::BlockBody`]'s
/// codec needs it; `aegis-node::genesis` re-exports it.
pub const EMPTY_TX_ROOT: [u8; 32] = *b"aegis/empty-tx-root/v1..........";
