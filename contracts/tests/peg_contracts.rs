//! Oracle tests for the compiled peg contracts.
//!
//! Two layers, per the crate contract:
//!
//! * **structure pins** — placeholder-form tree byte sizes vs the DESIGN.md
//!   compile record (`dev-docs/sidechain/contracts/DESIGN.md`, pass 3 + the
//!   F1/eager-ValDef fixes). A mismatch is a REAL FINDING (source drift or
//!   compiler change) — investigate, never just update the number.
//! * **on-chain parity** — `DepositReceipt` / `PegVault` under the testnet
//!   peg-v2 injections must reproduce BYTE-FOR-BYTE the trees deployed and
//!   spent on Ergo testnet (`test-vectors/testnet/peg-v2/`, consolidation
//!   confirmed at height 443688). Expected bytes/hashes/addresses come from
//!   the captured vectors + README — never from this crate's own output.

use aegis_contracts::{
    deposit_receipt, double_redeem, fee_pot, peg_mint_pins, peg_vault, side_chain_state,
    unlock_intent, ContractsError, NetworkPrefix, ScriptConstants,
};
use ergo_crypto::autolykos::common::blake2b256;

// ----- helpers -----

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-vectors/testnet/peg-v2"
);

/// tUSE token id minted for the testnet ceremonies (peg-v2 README).
const TUSE_TOKEN_ID: &str = "006a33af9b295c830b1fe19422ede003da35a1c3a5f6ac56618e99ef2eaa2bab";
/// PegVault v2 singleton NFT id (peg-v2 README).
const VAULT_NFT_V2: &str = "014b21beea1dbfc55837bd3fef92cb5e2ec57b8c4b5529c6dd731a0071db6ed4";
/// `RECEIPT_SCRIPT_HASH` recorded in the peg-v2 README =
/// blake2b256(deployed DepositReceipt v2 tree).
const RECEIPT_SCRIPT_HASH_V2: &str =
    "3c9d5dd0376806ce559051cb70922ac519c979d65eea1375c26ef1a891916fb8";
/// DepositReceipt v2 P2S address (testnet, peg-v2 README).
const RECEIPT_P2S_V2: &str = "4ftaxv5T31S2QUUiV15qA13B71LskmFXhghGJxD26A4qU1marXrvMTdBr5Hz8SvPUB5snomNo5Lv5CiWcm9uFcn6qAjEiM8XDXMMSo1WEoP25uWsXQUgRaPigPXp4ofWUP2TxgwJSRn9FYp6UBy3cTEGiAMLypqUkRTN5zr2WiWjuZwAHuuM1GPJT7baPH7wf8N1ytRvTHAF6wefeuAVB5rWVzVhat96XMrYV5xivmEoXkr723DBM1RmKmhuVS6Fipbp1Xk9dxRubUaGSDQK2T4p";

fn hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("test constant hex");
    v.try_into().expect("32 bytes")
}

/// Read a captured tree-bytes vector (`*.hex`, single hex line).
fn vector_tree(name: &str) -> Vec<u8> {
    let path = format!("{VECTORS}/{name}");
    let hex_text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    hex::decode(hex_text.trim()).unwrap_or_else(|e| panic!("decode {path}: {e}"))
}

/// Read a captured injected source (`*.injected.es`).
fn vector_source(name: &str) -> String {
    let path = format!("{VECTORS}/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// The exact deploy constants of the testnet peg-v2 ceremony: real tUSE +
/// v2 vault NFT; DoubleRedeem/UnlockIntent/FeePot pins were DUMMY values
/// (top-up-only vault — the payout ceremony was not deployed), derived as
/// blake2b256 of fixed strings (peg-v2 README). `RECEIPT_SCRIPT_HASH` is
/// the README-recorded deployed value, NOT derived from this crate.
fn testnet_v2_constants() -> ScriptConstants {
    ScriptConstants {
        use_token_id: Some(hex32(TUSE_TOKEN_ID)),
        peg_vault_nft: Some(hex32(VAULT_NFT_V2)),
        double_redeem_nft: Some(blake2b256(b"aegis-testnet-dummy-doubleredeem-nft")),
        unlock_intent_script_hash: Some(blake2b256(b"aegis-testnet-dummy-unlockintent")),
        receipt_script_hash: Some(hex32(RECEIPT_SCRIPT_HASH_V2)),
        fee_pot_script_hash: Some(blake2b256(b"aegis-testnet-dummy-feepot")),
        sidechain_state_nft: None,
        tip_pk: None,
    }
}

// ----- happy path -----

/// Structure pin: placeholder-form tree sizes vs the DESIGN.md record.
/// `DepositReceipt 138 · DoubleRedeem 79 · FeePot 74 · PegVault 590 ·
/// SideChainState 209 · UnlockIntent 159` (post F1 + eager-ValDef fixes).
#[test]
fn placeholder_trees_match_design_size_record() {
    let consts = ScriptConstants::placeholder();
    let net = NetworkPrefix::Testnet;
    let sizes = [
        (
            "DepositReceipt",
            deposit_receipt(&consts, net).unwrap().tree_bytes.len(),
            138,
        ),
        (
            "DoubleRedeem",
            double_redeem(net).unwrap().tree_bytes.len(),
            79,
        ),
        (
            "FeePot",
            fee_pot(&consts, net).unwrap().tree_bytes.len(),
            74,
        ),
        (
            "PegVault",
            peg_vault(&consts, net).unwrap().tree_bytes.len(),
            590,
        ),
        (
            "SideChainState",
            side_chain_state(&consts, net).unwrap().tree_bytes.len(),
            209,
        ),
        (
            "UnlockIntent",
            unlock_intent(&consts, net).unwrap().tree_bytes.len(),
            159,
        ),
    ];
    for (name, got, expected) in sizes {
        assert_eq!(
            got, expected,
            "{name} placeholder tree is {got} B, DESIGN.md records {expected} B — \
             source drift or compiler change; investigate, do NOT just update the pin"
        );
    }
}

/// A placeholder constant stays a placeholder: injecting only some
/// constants still compiles (the others remain empty colls).
#[test]
fn partial_injection_compiles() {
    let consts = ScriptConstants {
        use_token_id: Some(hex32(TUSE_TOKEN_ID)),
        ..ScriptConstants::placeholder()
    };
    let c = fee_pot(&consts, NetworkPrefix::Testnet).unwrap();
    assert!(!c.tree_bytes.is_empty());
}

/// `derive_sibling_hashes` fills exactly the three vault-pinned hash
/// fields, and its receipt hash equals the README-recorded deployed value.
#[test]
fn derive_sibling_hashes_reproduces_deployed_receipt_hash() {
    let consts = ScriptConstants {
        use_token_id: Some(hex32(TUSE_TOKEN_ID)),
        peg_vault_nft: Some(hex32(VAULT_NFT_V2)),
        ..ScriptConstants::placeholder()
    }
    .derive_sibling_hashes(NetworkPrefix::Testnet)
    .unwrap();
    assert_eq!(
        consts.receipt_script_hash,
        Some(hex32(RECEIPT_SCRIPT_HASH_V2)),
        "derived RECEIPT_SCRIPT_HASH != deployed peg-v2 value"
    );
    assert!(consts.fee_pot_script_hash.is_some());
    assert!(consts.unlock_intent_script_hash.is_some());
}

// ----- round-trips -----

// ----- error paths -----

#[test]
fn peg_mint_pins_placeholder_env_errors() {
    let err = peg_mint_pins(&ScriptConstants::placeholder(), NetworkPrefix::Testnet).unwrap_err();
    assert!(matches!(
        err,
        ContractsError::MissingConstant {
            name: "use_token_id",
            ..
        }
    ));
}

#[test]
fn peg_mint_pins_missing_vault_nft_errors() {
    let consts = ScriptConstants {
        use_token_id: Some(hex32(TUSE_TOKEN_ID)),
        ..ScriptConstants::placeholder()
    };
    let err = peg_mint_pins(&consts, NetworkPrefix::Testnet).unwrap_err();
    assert!(matches!(
        err,
        ContractsError::MissingConstant {
            name: "peg_vault_nft",
            ..
        }
    ));
}

// ----- oracle parity -----

/// THE on-chain oracle: `DepositReceipt.es` with the testnet peg-v2
/// injections must reproduce the DEPLOYED tree byte-for-byte (200 B,
/// `deposit_receipt_tree.hex` — the script of the box consolidated at
/// height 443688), its README-recorded script hash, and its P2S address.
#[test]
fn deposit_receipt_testnet_injection_matches_deployed_tree() {
    let c = deposit_receipt(&testnet_v2_constants(), NetworkPrefix::Testnet).unwrap();
    let deployed = vector_tree("deposit_receipt_tree.hex");
    assert_eq!(deployed.len(), 200, "vector file drifted");
    assert_eq!(
        c.tree_bytes, deployed,
        "compiled DepositReceipt tree != tree deployed on Ergo testnet"
    );
    assert_eq!(
        c.script_hash,
        hex32(RECEIPT_SCRIPT_HASH_V2),
        "script hash != README RECEIPT_SCRIPT_HASH"
    );
    assert_eq!(
        c.p2s_address, RECEIPT_P2S_V2,
        "P2S address != README record"
    );
}

/// THE on-chain oracle: `PegVault.es` with the testnet peg-v2 injections
/// must reproduce the DEPLOYED vault tree byte-for-byte (796 B,
/// `peg_vault_tree.hex` — the post-eager-ValDef-fix tree that accepted the
/// receipt-at-INPUTS(1) consolidation, txid `f2b8d9d6…` @ 443688).
#[test]
fn peg_vault_testnet_injection_matches_deployed_tree() {
    let c = peg_vault(&testnet_v2_constants(), NetworkPrefix::Testnet).unwrap();
    let deployed = vector_tree("peg_vault_tree.hex");
    assert_eq!(deployed.len(), 796, "vector file drifted");
    assert_eq!(
        c.tree_bytes, deployed,
        "compiled PegVault tree != tree deployed on Ergo testnet"
    );
}

/// Cross-check: the captured injected sources (`*.injected.es`, exactly
/// what was compiled at deploy time) compile to the same deployed trees —
/// proving this crate's placeholder INJECTION path is byte-equivalent to
/// the ceremony's hand-injected sources.
#[test]
fn captured_injected_sources_compile_to_deployed_trees() {
    for (src_name, tree_name) in [
        ("DepositReceipt.injected.es", "deposit_receipt_tree.hex"),
        ("PegVault.injected.es", "peg_vault_tree.hex"),
    ] {
        let src = vector_source(src_name);
        let r = ergo_compiler::compile(
            &ergo_compiler::ScriptEnv::new(),
            &src,
            aegis_contracts::TREE_VERSION,
            NetworkPrefix::Testnet,
        )
        .unwrap_or_else(|e| panic!("compile {src_name}: {e}"));
        assert_eq!(
            r.tree_bytes,
            vector_tree(tree_name),
            "{src_name} does not reproduce {tree_name}"
        );
    }
}

/// `PegMintPins` (the `PegParams`-shaped accessor) pins the deployed
/// testnet receipt hash — the values `aegis-node` would consume.
#[test]
fn peg_mint_pins_match_testnet_v2_deployment() {
    let pins = peg_mint_pins(&testnet_v2_constants(), NetworkPrefix::Testnet).unwrap();
    assert_eq!(pins.use_token_id, hex32(TUSE_TOKEN_ID));
    assert_eq!(pins.peg_vault_nft, hex32(VAULT_NFT_V2));
    assert_eq!(
        pins.deposit_receipt_script_hash,
        hex32(RECEIPT_SCRIPT_HASH_V2),
        "pins receipt hash != deployed peg-v2 value"
    );
    // FeePot was never deployed on testnet (dummy pin in the ceremony);
    // its hash is asserted self-consistent with a direct compile only.
    assert_eq!(
        pins.fee_pot_script_hash,
        fee_pot(&testnet_v2_constants(), NetworkPrefix::Testnet)
            .unwrap()
            .script_hash
    );
}
