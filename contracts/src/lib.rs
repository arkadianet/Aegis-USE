//! Aegis peg-out ErgoScript contracts as first-class build artifacts.
//!
//! The six `.es` sources under `es/` are the AUTHORITATIVE contract sources
//! (moved here from `dev-docs/sidechain/contracts/`, which keeps the design
//! docs — `DESIGN.md` / `GAPS.md`). This crate embeds them, injects the
//! deploy-time constants into their `fromBase64("")` placeholders, compiles
//! them with the repo-pinned `ergo-compiler` (git tag `v0.5.2`, tree
//! version 3 — the same compiler + settings that produced the trees deployed
//! on Ergo testnet), and pins `blake2b256(tree_bytes)` script hashes.
//!
//! Two oracle layers keep this honest (`tests/peg_contracts.rs`):
//!
//! * **structure pins** — every placeholder-form tree byte size is asserted
//!   against the DESIGN.md compile record (a drifted source or compiler
//!   changes the size and fails the pin);
//! * **on-chain parity** — `DepositReceipt` / `PegVault` compiled with the
//!   testnet peg-v2 injections must reproduce byte-for-byte the trees that
//!   are live on Ergo testnet (`test-vectors/testnet/peg-v2/*.hex`, spent at
//!   heights 443678–443688).
//!
//! Constant injection is TEXTUAL, exactly like the deployed
//! `*.injected.es` vectors: the base64 payload is spliced into the named
//! `val NAME = fromBase64("")` placeholder. It is deliberately NOT a
//! `ScriptEnv` compile-env substitution — the deployed trees were produced
//! from injected sources, and parity means reproducing that path bit-exact.
//!
//! All `.es` file content is data: nothing in a source is interpreted by
//! this crate beyond locating the named placeholder literals.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ergo_crypto::autolykos::common::blake2b256;

pub use ergo_compiler::NetworkPrefix;

// ── authoritative sources ────────────────────────────────────────────────────

/// `DepositReceipt.es` — peg-in lock box (merge-into-vault / refund paths).
pub const DEPOSIT_RECEIPT_ES: &str = include_str!("../es/DepositReceipt.es");
/// `DoubleRedeem.es` — burn-once ledger (AvlTree insert-once).
pub const DOUBLE_REDEEM_ES: &str = include_str!("../es/DoubleRedeem.es");
/// `FeePot.es` — peg-in fee buffer, permissionlessly swept into the vault.
pub const FEE_POT_ES: &str = include_str!("../es/FeePot.es");
/// `PegVault.es` — singleton pooled reserve (payout / top-up paths).
pub const PEG_VAULT_ES: &str = include_str!("../es/PegVault.es");
/// `SideChainState.es` — singleton tip-digest box with the insert-only
/// burn tree.
pub const SIDE_CHAIN_STATE_ES: &str = include_str!("../es/SideChainState.es");
/// `UnlockIntent.es` — peg-out claim box (burn_id, N, claimant).
pub const UNLOCK_INTENT_ES: &str = include_str!("../es/UnlockIntent.es");

/// ErgoTree version every peg contract compiles under. Chain-id-breaking:
/// the deployed testnet trees (peg-v2) were compiled with tree version 3;
/// changing this changes every tree byte and script hash.
pub const TREE_VERSION: u8 = 3;

// ── errors ───────────────────────────────────────────────────────────────────

/// Failures surfaced by this crate. Injection errors mean the caller's
/// constants don't fit the source (or the source lost its placeholder —
/// a drift the tests also catch); compile errors carry the pinned
/// `ergo-compiler` diagnosis.
#[derive(Debug, thiserror::Error)]
pub enum ContractsError {
    /// The named `val NAME = fromBase64("")` placeholder was not found in
    /// the contract source.
    #[error("{contract}: no `val {name} = fromBase64(\"\")` placeholder in source")]
    MissingPlaceholder {
        /// Contract file stem, e.g. `"PegVault"`.
        contract: &'static str,
        /// Placeholder `val` name, e.g. `"USE_TOKEN_ID"`.
        name: &'static str,
    },
    /// A deploy constant required by this call was not set in
    /// [`ScriptConstants`].
    #[error("{contract}: required deploy constant `{name}` is not set")]
    MissingConstant {
        /// What was being assembled, e.g. `"PegMintPins"`.
        contract: &'static str,
        /// The unset [`ScriptConstants`] field.
        name: &'static str,
    },
    /// `ergo_compiler::compile` rejected the (injected) source.
    #[error("{contract}: ErgoScript compile failed")]
    Compile {
        /// Contract file stem.
        contract: &'static str,
        /// The compiler's own error.
        #[source]
        source: ergo_compiler::CompileError,
    },
}

// ── deploy constants ─────────────────────────────────────────────────────────

/// Deploy-time constant injections for the peg contract family. `None`
/// leaves the corresponding `fromBase64("")` placeholder EMPTY (the
/// canonical placeholder form pinned by the structure-regression tests);
/// [`ScriptConstants::placeholder`] is the all-`None` env.
///
/// Field → placeholder mapping (a field is only read by the contracts that
/// declare the placeholder):
///
/// | field | placeholder | contracts |
/// |---|---|---|
/// | `use_token_id` | `USE_TOKEN_ID` | DepositReceipt, FeePot, PegVault |
/// | `peg_vault_nft` | `PEG_VAULT_NFT` / `VAULT_NFT` | DepositReceipt, FeePot, PegVault, UnlockIntent |
/// | `double_redeem_nft` | `DOUBLE_REDEEM_NFT` | PegVault |
/// | `unlock_intent_script_hash` | `UNLOCK_INTENT_SCRIPT_HASH` | PegVault |
/// | `receipt_script_hash` | `RECEIPT_SCRIPT_HASH` | PegVault |
/// | `fee_pot_script_hash` | `FEE_POT_SCRIPT_HASH` | PegVault |
/// | `sidechain_state_nft` | `SIDECHAIN_STATE_NFT` | SideChainState, UnlockIntent |
/// | `tip_pk` | `TIP_PK` (33-byte compressed point) | SideChainState |
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptConstants {
    /// USE token id (`tokens(0)._1` of receipts / `tokens(1)._1` of the vault).
    pub use_token_id: Option<[u8; 32]>,
    /// Singleton PegVault NFT id.
    pub peg_vault_nft: Option<[u8; 32]>,
    /// Singleton DoubleRedeem NFT id.
    pub double_redeem_nft: Option<[u8; 32]>,
    /// `blake2b256(UnlockIntent tree bytes)`.
    pub unlock_intent_script_hash: Option<[u8; 32]>,
    /// `blake2b256(DepositReceipt tree bytes)`.
    pub receipt_script_hash: Option<[u8; 32]>,
    /// `blake2b256(FeePot tree bytes)`.
    pub fee_pot_script_hash: Option<[u8; 32]>,
    /// Singleton SideChainState NFT id.
    pub sidechain_state_nft: Option<[u8; 32]>,
    /// Miner-tip pubkey (33-byte SEC1-compressed point) — the v1 C1
    /// trusted key.
    pub tip_pk: Option<[u8; 33]>,
}

impl ScriptConstants {
    /// The all-empty placeholder env: every `fromBase64("")` stays empty.
    /// Compiling under it yields the canonical placeholder trees whose byte
    /// sizes DESIGN.md records (138/79/74/590/209/159).
    pub fn placeholder() -> Self {
        Self::default()
    }

    /// Fill the three sibling-script-hash fields the vault pins
    /// (`RECEIPT_SCRIPT_HASH`, `FEE_POT_SCRIPT_HASH`,
    /// `UNLOCK_INTENT_SCRIPT_HASH`) by compiling those contracts under the
    /// CURRENT constants. Call once the id fields (`use_token_id`,
    /// `peg_vault_nft`, `sidechain_state_nft`) are set, then compile the
    /// vault — this encodes the deploy dependency order (siblings first,
    /// vault last).
    pub fn derive_sibling_hashes(mut self, network: NetworkPrefix) -> Result<Self, ContractsError> {
        self.receipt_script_hash = Some(deposit_receipt(&self, network)?.script_hash);
        self.fee_pot_script_hash = Some(fee_pot(&self, network)?.script_hash);
        self.unlock_intent_script_hash = Some(unlock_intent(&self, network)?.script_hash);
        Ok(self)
    }
}

// ── compiled artifact ────────────────────────────────────────────────────────

/// A compiled peg contract: the canonical tree wire bytes, their
/// `blake2b256` script hash (the pin `PegVault.es` and `PegParams` match
/// on), and the P2S address for the compile network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledContract {
    /// Canonical ErgoTree wire bytes (`ergo_compiler::CompileResult::tree_bytes`).
    pub tree_bytes: Vec<u8>,
    /// `blake2b256(tree_bytes)` — the same preimage the vault hashes for
    /// `receiptSum`/`feeSum` and `verify_pegmint` step 7.1 checks.
    pub script_hash: [u8; 32],
    /// Pay-to-Script address of `tree_bytes` on the compile network.
    pub p2s_address: String,
}

fn compile_es(
    contract: &'static str,
    src: &str,
    network: NetworkPrefix,
) -> Result<CompiledContract, ContractsError> {
    let result =
        ergo_compiler::compile(&ergo_compiler::ScriptEnv::new(), src, TREE_VERSION, network)
            .map_err(|source| ContractsError::Compile { contract, source })?;
    let script_hash = blake2b256(&result.tree_bytes);
    Ok(CompiledContract {
        tree_bytes: result.tree_bytes,
        script_hash,
        p2s_address: result.p2s_address,
    })
}

/// `Option<[u8; N]>` → `Option<&[u8]>` for [`inject`] (arrays don't
/// `Deref` to slices, so `Option::as_deref` doesn't apply).
fn opt_slice<const N: usize>(bytes: &Option<[u8; N]>) -> Option<&[u8]> {
    bytes.as_ref().map(|b| b.as_slice())
}

/// Splice `bytes` (base64-encoded) into the `val {name} = … fromBase64("")`
/// placeholder of `src`. `None` leaves the placeholder empty (placeholder
/// form). The placeholder must sit on the `val`'s own line — matching the
/// exact shape of every injectable constant in `es/` and of the deployed
/// `*.injected.es` vectors.
fn inject(
    src: String,
    contract: &'static str,
    name: &'static str,
    bytes: Option<&[u8]>,
) -> Result<String, ContractsError> {
    let Some(bytes) = bytes else {
        return Ok(src);
    };
    let missing = ContractsError::MissingPlaceholder { contract, name };
    let marker = format!("val {name} = ");
    let Some(val_at) = src.find(&marker) else {
        return Err(missing);
    };
    let line_end = src[val_at..]
        .find('\n')
        .map_or(src.len(), |offset| val_at + offset);
    const PLACEHOLDER: &str = "fromBase64(\"\")";
    let Some(ph_offset) = src[val_at..line_end].find(PLACEHOLDER) else {
        return Err(missing);
    };
    // Insertion point: just after `fromBase64("`.
    let insert_at = val_at + ph_offset + PLACEHOLDER.len() - "\")".len();
    let mut out = String::with_capacity(src.len() + 44);
    out.push_str(&src[..insert_at]);
    out.push_str(&BASE64.encode(bytes));
    out.push_str(&src[insert_at..]);
    Ok(out)
}

// ── per-contract compile fns ─────────────────────────────────────────────────

/// Compile `DepositReceipt.es`. Injections: `use_token_id`, `peg_vault_nft`.
pub fn deposit_receipt(
    consts: &ScriptConstants,
    network: NetworkPrefix,
) -> Result<CompiledContract, ContractsError> {
    const NAME: &str = "DepositReceipt";
    let src = DEPOSIT_RECEIPT_ES.to_owned();
    let src = inject(src, NAME, "USE_TOKEN_ID", opt_slice(&consts.use_token_id))?;
    let src = inject(src, NAME, "PEG_VAULT_NFT", opt_slice(&consts.peg_vault_nft))?;
    compile_es(NAME, &src, network)
}

/// Compile `DoubleRedeem.es`. No deploy injections (its singleton NFT is a
/// box property, not a script constant).
pub fn double_redeem(network: NetworkPrefix) -> Result<CompiledContract, ContractsError> {
    compile_es("DoubleRedeem", DOUBLE_REDEEM_ES, network)
}

/// Compile `FeePot.es`. Injections: `use_token_id`, `peg_vault_nft`.
pub fn fee_pot(
    consts: &ScriptConstants,
    network: NetworkPrefix,
) -> Result<CompiledContract, ContractsError> {
    const NAME: &str = "FeePot";
    let src = FEE_POT_ES.to_owned();
    let src = inject(src, NAME, "USE_TOKEN_ID", opt_slice(&consts.use_token_id))?;
    let src = inject(src, NAME, "PEG_VAULT_NFT", opt_slice(&consts.peg_vault_nft))?;
    compile_es(NAME, &src, network)
}

/// Compile `PegVault.es`. Injections: `use_token_id`, `peg_vault_nft` (as
/// `VAULT_NFT`), `double_redeem_nft`, `unlock_intent_script_hash`,
/// `receipt_script_hash`, `fee_pot_script_hash` — see
/// [`ScriptConstants::derive_sibling_hashes`] for the hash fields.
pub fn peg_vault(
    consts: &ScriptConstants,
    network: NetworkPrefix,
) -> Result<CompiledContract, ContractsError> {
    const NAME: &str = "PegVault";
    let src = PEG_VAULT_ES.to_owned();
    let src = inject(src, NAME, "USE_TOKEN_ID", opt_slice(&consts.use_token_id))?;
    let src = inject(src, NAME, "VAULT_NFT", opt_slice(&consts.peg_vault_nft))?;
    let src = inject(
        src,
        NAME,
        "DOUBLE_REDEEM_NFT",
        opt_slice(&consts.double_redeem_nft),
    )?;
    let src = inject(
        src,
        NAME,
        "UNLOCK_INTENT_SCRIPT_HASH",
        opt_slice(&consts.unlock_intent_script_hash),
    )?;
    let src = inject(
        src,
        NAME,
        "RECEIPT_SCRIPT_HASH",
        opt_slice(&consts.receipt_script_hash),
    )?;
    let src = inject(
        src,
        NAME,
        "FEE_POT_SCRIPT_HASH",
        opt_slice(&consts.fee_pot_script_hash),
    )?;
    compile_es(NAME, &src, network)
}

/// Compile `SideChainState.es`. Injections: `sidechain_state_nft`, `tip_pk`.
pub fn side_chain_state(
    consts: &ScriptConstants,
    network: NetworkPrefix,
) -> Result<CompiledContract, ContractsError> {
    const NAME: &str = "SideChainState";
    let src = SIDE_CHAIN_STATE_ES.to_owned();
    let src = inject(
        src,
        NAME,
        "SIDECHAIN_STATE_NFT",
        opt_slice(&consts.sidechain_state_nft),
    )?;
    let src = inject(src, NAME, "TIP_PK", opt_slice(&consts.tip_pk))?;
    compile_es(NAME, &src, network)
}

/// Compile `UnlockIntent.es`. Injections: `peg_vault_nft` (as `VAULT_NFT`),
/// `sidechain_state_nft`.
pub fn unlock_intent(
    consts: &ScriptConstants,
    network: NetworkPrefix,
) -> Result<CompiledContract, ContractsError> {
    const NAME: &str = "UnlockIntent";
    let src = UNLOCK_INTENT_ES.to_owned();
    let src = inject(src, NAME, "VAULT_NFT", opt_slice(&consts.peg_vault_nft))?;
    let src = inject(
        src,
        NAME,
        "SIDECHAIN_STATE_NFT",
        opt_slice(&consts.sidechain_state_nft),
    )?;
    compile_es(NAME, &src, network)
}

// ── PegParams sourcing ───────────────────────────────────────────────────────

/// The four peg-in deploy pins in exactly the shape `aegis-node`'s
/// `PegParams` needs (`pegmint_steps.rs`): field names match one-for-one,
/// so wiring is `PegParams { use_token_id: pins.use_token_id, … }` plus the
/// two fee params. Produced from COMPILED trees — the script hashes can no
/// longer be hand-copied constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PegMintPins {
    /// USE token id the receipt must carry at `tokens(0)`.
    pub use_token_id: [u8; 32],
    /// Singleton PegVault NFT — the merge-vs-refund discriminator.
    pub peg_vault_nft: [u8; 32],
    /// `blake2b256(tree_bytes)` of the injected `DepositReceipt.es`.
    pub deposit_receipt_script_hash: [u8; 32],
    /// `blake2b256(tree_bytes)` of the injected `FeePot.es`.
    pub fee_pot_script_hash: [u8; 32],
}

/// Compile `DepositReceipt.es` + `FeePot.es` under `consts` and assemble
/// the `PegParams`-shaped pins. Requires `use_token_id` and `peg_vault_nft`
/// to be set — placeholder script hashes in a verifier would be a foot-gun,
/// so this REFUSES the placeholder env rather than silently pinning it.
pub fn peg_mint_pins(
    consts: &ScriptConstants,
    network: NetworkPrefix,
) -> Result<PegMintPins, ContractsError> {
    const NAME: &str = "PegMintPins";
    let use_token_id = consts.use_token_id.ok_or(ContractsError::MissingConstant {
        contract: NAME,
        name: "use_token_id",
    })?;
    let peg_vault_nft = consts
        .peg_vault_nft
        .ok_or(ContractsError::MissingConstant {
            contract: NAME,
            name: "peg_vault_nft",
        })?;
    Ok(PegMintPins {
        use_token_id,
        peg_vault_nft,
        deposit_receipt_script_hash: deposit_receipt(consts, network)?.script_hash,
        fee_pot_script_hash: fee_pot(consts, network)?.script_hash,
    })
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    // ----- happy path -----

    #[test]
    fn inject_splices_base64_into_named_placeholder() {
        let src = "val USE_TOKEN_ID = fromBase64(\"\")   // todo\n".to_owned();
        let out = inject(src, "T", "USE_TOKEN_ID", Some(&[0u8; 3])).unwrap();
        assert_eq!(out, "val USE_TOKEN_ID = fromBase64(\"AAAA\")   // todo\n");
    }

    #[test]
    fn inject_none_returns_source_unchanged() {
        let src = "val X = fromBase64(\"\")\n".to_owned();
        let out = inject(src.clone(), "T", "X", None).unwrap();
        assert_eq!(out, src);
    }

    #[test]
    fn inject_handles_wrapped_placeholder() {
        // TIP_PK's shape: the placeholder sits inside decodePoint(...).
        let src = "val TIP_PK = decodePoint(fromBase64(\"\"))\n".to_owned();
        let out = inject(src, "T", "TIP_PK", Some(&[1u8])).unwrap();
        assert_eq!(out, "val TIP_PK = decodePoint(fromBase64(\"AQ==\"))\n");
    }

    // ----- round-trips -----

    // ----- error paths -----

    #[test]
    fn inject_unknown_name_errors() {
        let src = "val X = fromBase64(\"\")\n".to_owned();
        let err = inject(src, "T", "Y", Some(&[0u8; 32])).unwrap_err();
        assert!(matches!(
            err,
            ContractsError::MissingPlaceholder {
                contract: "T",
                name: "Y"
            }
        ));
    }

    #[test]
    fn inject_already_filled_placeholder_errors() {
        // A filled placeholder is no longer `fromBase64("")` — injecting
        // the same name twice must fail, not double-splice.
        let src = "val X = fromBase64(\"\")\n".to_owned();
        let once = inject(src, "T", "X", Some(&[0u8; 32])).unwrap();
        let err = inject(once, "T", "X", Some(&[0u8; 32])).unwrap_err();
        assert!(matches!(
            err,
            ContractsError::MissingPlaceholder {
                contract: "T",
                name: "X"
            }
        ));
    }

    #[test]
    fn inject_placeholder_on_other_line_errors() {
        // The placeholder must be on the named val's OWN line.
        let src = "val X = 1\nval Y = fromBase64(\"\")\n".to_owned();
        let err = inject(src, "T", "X", Some(&[0u8; 32])).unwrap_err();
        assert!(matches!(
            err,
            ContractsError::MissingPlaceholder {
                contract: "T",
                name: "X"
            }
        ));
    }

    // ----- oracle parity -----
    // (tree-byte / script-hash oracles live in tests/peg_contracts.rs.)
}
