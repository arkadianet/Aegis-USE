//! bridge-tools CLI — drive the devnet side of the trustless bridge.

use anyhow::{anyhow, Context, Result};
use bridge_tools::devnet::Devnet;
use bridge_tools::txbuild::{self, InBox};
use bridge_tools::vault::{self, VaultSpec, JOURNAL_TAG};
use clap::{Parser, Subcommand};
use ergo_ser::address::NetworkPrefix;
use ergo_ser::token::{Token, TokenId};

#[derive(Parser)]
#[command(
    name = "bridge-tools",
    about = "Aegis hash-native bridge devnet tooling"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:19099")]
    api: String,
    #[arg(long, default_value = "hello")]
    key: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// EIP-4 mint of a new token to the wallet's own address.
    MintToken {
        #[arg(long)]
        supply: u64,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long, default_value_t = 0)]
        decimals: u8,
    },
    /// Print the vault ErgoTree hex + P2S address for the pinned ids.
    VaultAddress {
        #[arg(long)]
        nft: String,
        #[arg(long)]
        use_token: String,
        #[arg(long)]
        image_id: String,
    },
    /// Create + fund the vault box (NFT + USE + ERG, R4=root, R5=0).
    DeployVault {
        #[arg(long)]
        nft: String,
        #[arg(long)]
        use_token: String,
        #[arg(long)]
        image_id: String,
        #[arg(long)]
        use_amount: u64,
        #[arg(long, default_value_t = 10_000_000_000)]
        erg: u64,
        /// Initial hn state root (hex 32B) the vault starts from.
        #[arg(long)]
        r4_root: String,
        /// Box id currently holding the NFT.
        #[arg(long)]
        nft_box: String,
        /// Box id currently holding the USE supply.
        #[arg(long)]
        use_box: String,
    },
    /// Deposit USE to the vault address with R4 = sc_dest (peg-in).
    Deposit {
        #[arg(long)]
        vault_tree: String,
        #[arg(long)]
        use_token: String,
        #[arg(long)]
        amount: u64,
        /// hn destination: hex of owner digest bytes(32) ‖ enc_pk(32).
        #[arg(long)]
        sc_dest: String,
        /// Box id holding the sender's USE.
        #[arg(long)]
        use_box: String,
    },
    /// Print the hn peg-in destination (owner ‖ enc_pk hex) + address for a seed.
    ScDest {
        #[arg(long)]
        seed: String,
    },
    /// Scan an hn wallet: every detected note + balances.
    HnScan {
        #[arg(long)]
        seed: String,
        #[arg(long, default_value = "http://127.0.0.1:8750")]
        node: String,
    },
    /// Shielded hn payment from --seed to --to (64-byte dest hex).
    HnPay {
        #[arg(long)]
        seed: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        /// The consensus flat fee (exact, not a floor).
        #[arg(long, default_value_t = 3)]
        fee: u64,
        #[arg(long, default_value = "http://127.0.0.1:8750")]
        node: String,
    },
    /// hn peg-out: burn amount + peg fee, record the public withdrawal.
    HnPegout {
        #[arg(long)]
        seed: String,
        #[arg(long)]
        amount: u64,
        /// The peg fee (1% of amount, min 1 — must match consensus exactly).
        #[arg(long)]
        peg_fee: u64,
        #[arg(long, default_value_t = 3)]
        flat_fee: u64,
        /// The devnet recipient's ErgoTree bytes (hex).
        #[arg(long)]
        recipient_tree: String,
        #[arg(long, default_value = "http://127.0.0.1:8751")]
        node: String,
    },
    /// Assemble (and optionally submit) the verifyStark release tx.
    Release {
        #[arg(long)]
        vault_box: String,
        #[arg(long)]
        vault_value: u64,
        #[arg(long)]
        vault_tree: String,
        #[arg(long)]
        nft: String,
        #[arg(long)]
        nft_amount: u64,
        #[arg(long)]
        use_token: String,
        #[arg(long)]
        use_amount_in_vault: u64,
        #[arg(long)]
        prev_root: String,
        #[arg(long)]
        new_root: String,
        #[arg(long)]
        counter: i64,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        recipient_tree: String,
        #[arg(long)]
        receipt: std::path::PathBuf,
        #[arg(long, default_value_t = false)]
        submit: bool,
        #[arg(long, default_value = "release-tx.hex")]
        out: std::path::PathBuf,
    },
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)
        .context("hex")?
        .try_into()
        .map_err(|_| anyhow!("need 32 bytes"))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let dev = Devnet::new(&args.api, &args.key);
    match args.cmd {
        Cmd::MintToken {
            supply,
            name,
            description,
            decimals,
        } => {
            let height = dev.height()? as u32;
            let addr = dev.wallet_address()?;
            let tree =
                ergo_ser::address::decode_address_to_tree_bytes(&addr, NetworkPrefix::Testnet)?;
            let (input_id, input_value) = dev.pick_erg_box(1_000_000_000)?;
            let (utx, token_id) = txbuild::build_mint(
                &input_id,
                input_value,
                &tree,
                &txbuild::MintSpec {
                    supply,
                    name,
                    description,
                    decimals,
                },
                height,
            )?;
            let signed = dev.sign(&txbuild::unsigned_hex(&utx)?)?;
            let box_id = txbuild::output_box_id(&signed, 0)?;
            let txid = dev.submit(&signed)?;
            println!("token_id={token_id}");
            println!("token_box={box_id}");
            println!("tx_id={txid}");
        }
        Cmd::VaultAddress {
            nft,
            use_token,
            image_id,
        } => {
            let spec = VaultSpec {
                nft_id: hex32(&nft)?,
                use_id: hex32(&use_token)?,
                image_id: hex32(&image_id)?,
                tag: JOURNAL_TAG,
            };
            println!("tree={}", hex::encode(vault::vault_tree_bytes(&spec)));
            println!(
                "address={}",
                vault::vault_address(&spec, NetworkPrefix::Testnet)
            );
        }
        Cmd::DeployVault {
            nft,
            use_token,
            image_id,
            use_amount,
            erg,
            r4_root,
            nft_box,
            use_box,
        } => {
            let spec = VaultSpec {
                nft_id: hex32(&nft)?,
                use_id: hex32(&use_token)?,
                image_id: hex32(&image_id)?,
                tag: JOURNAL_TAG,
            };
            let tree = vault::vault_tree_bytes(&spec);
            let height = dev.height()? as u32;
            let addr = dev.wallet_address()?;
            let change =
                ergo_ser::address::decode_address_to_tree_bytes(&addr, NetworkPrefix::Testnet)?;
            // Spend the NFT box + USE box (wallet-held) into the vault.
            let ins = collect_boxes(&dev, &[&nft_box, &use_box])?;
            let utx = txbuild::build_send(
                ins,
                &tree,
                vec![
                    txbuild::coll_byte_reg(&hex::decode(&r4_root)?),
                    txbuild::long_reg(0),
                ],
                erg,
                vec![
                    Token {
                        token_id: TokenId::from_bytes(hex32(&nft)?),
                        amount: 1,
                    },
                    Token {
                        token_id: TokenId::from_bytes(hex32(&use_token)?),
                        amount: use_amount,
                    },
                ],
                &change,
                height,
            )?;
            let signed = dev.sign(&txbuild::unsigned_hex(&utx)?)?;
            let box_id = txbuild::output_box_id(&signed, 0)?;
            let txid = dev.submit(&signed)?;
            println!(
                "vault_address={}",
                vault::vault_address(&spec, NetworkPrefix::Testnet)
            );
            println!("vault_box={box_id}");
            println!("tx_id={txid}");
        }
        Cmd::Deposit {
            vault_tree,
            use_token,
            amount,
            sc_dest,
            use_box,
        } => {
            let height = dev.height()? as u32;
            let addr = dev.wallet_address()?;
            let change =
                ergo_ser::address::decode_address_to_tree_bytes(&addr, NetworkPrefix::Testnet)?;
            let dest = hex::decode(&sc_dest)?;
            if dest.len() != 64 {
                return Err(anyhow!("sc-dest must be 64 bytes (owner ‖ enc_pk)"));
            }
            let ins = collect_boxes(&dev, &[&use_box])?;
            let utx = txbuild::build_send(
                ins,
                &hex::decode(&vault_tree)?,
                vec![txbuild::coll_byte_reg(&dest)],
                txbuild::BOX_ERG,
                vec![Token {
                    token_id: TokenId::from_bytes(hex32(&use_token)?),
                    amount,
                }],
                &change,
                height,
            )?;
            let signed = dev.sign(&txbuild::unsigned_hex(&utx)?)?;
            let box_id = txbuild::output_box_id(&signed, 0)?;
            let txid = dev.submit(&signed)?;
            let h = dev.height()?;
            println!("deposit_box={box_id}");
            println!("tx_id={txid}");
            println!("submitted_at_height={h}");
        }
        Cmd::ScDest { seed } => {
            let dest = bridge_tools::hn::sc_dest(seed.as_bytes());
            println!("sc_dest={}", hex::encode(dest));
            println!(
                "address={}",
                bridge_tools::hn::address_string(seed.as_bytes())
            );
        }
        Cmd::HnScan { seed, node } => {
            let (notes, balance, spendable) =
                bridge_tools::hn::detect_notes(&node, seed.as_bytes());
            for (leaf, value) in &notes {
                println!("note leaf={leaf} value={value}");
            }
            println!("balance={balance}");
            println!("spendable={spendable}");
        }
        Cmd::HnPay {
            seed,
            to,
            amount,
            fee,
            node,
        } => {
            let (before, after) = bridge_tools::hn::pay(&node, seed.as_bytes(), &to, amount, fee)?;
            println!("submitted amount={amount} fee={fee}");
            println!("balance_before={before}");
            println!("balance_after_local={after}");
        }
        Cmd::HnPegout {
            seed,
            amount,
            peg_fee,
            flat_fee,
            recipient_tree,
            node,
        } => {
            let before = bridge_tools::hn::pegout(
                &node,
                seed.as_bytes(),
                amount,
                peg_fee,
                flat_fee,
                hex::decode(&recipient_tree)?,
            )?;
            println!("submitted pegout amount={amount} peg_fee={peg_fee} flat_fee={flat_fee}");
            println!("balance_before={before}");
        }
        Cmd::Release {
            vault_box,
            vault_value,
            vault_tree,
            nft,
            nft_amount,
            use_token,
            use_amount_in_vault,
            prev_root,
            new_root,
            counter,
            amount,
            recipient_tree,
            receipt,
            submit,
            out,
        } => {
            let receipt_bytes = std::fs::read(&receipt).context("read receipt")?;
            let height = dev.height()? as u32;
            let tx = txbuild::build_release(
                &vault_box,
                vault_value,
                vec![
                    Token {
                        token_id: TokenId::from_bytes(hex32(&nft)?),
                        amount: nft_amount,
                    },
                    Token {
                        token_id: TokenId::from_bytes(hex32(&use_token)?),
                        amount: use_amount_in_vault,
                    },
                ],
                &hex::decode(&vault_tree)?,
                &hex32(&prev_root)?,
                &hex32(&new_root)?,
                counter,
                hex32(&use_token)?,
                amount,
                &hex::decode(&recipient_tree)?,
                &receipt_bytes,
                height,
            )?;
            let bytes = txbuild::signed_bytes(&tx)?;
            std::fs::write(&out, hex::encode(&bytes))?;
            println!("release_tx_bytes={} ({} bytes)", out.display(), bytes.len());
            if submit {
                let txid = dev.submit(&bytes)?;
                println!("tx_id={txid}");
            }
        }
    }
    Ok(())
}

/// Load `(value, tokens)` for box ids from the UTXO set (`/utxo/byId` —
/// the wallet unspent listing is paged and omits `assets` on this node).
fn collect_boxes(dev: &Devnet, ids: &[&str]) -> Result<Vec<InBox>> {
    let mut out = Vec::new();
    for id in ids {
        let b = dev.box_by_id(id)?;
        let tokens = b["assets"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|t| {
                        Ok(Token {
                            token_id: TokenId::from_bytes(
                                hex::decode(t["tokenId"].as_str().unwrap_or_default())?
                                    .try_into()
                                    .map_err(|_| anyhow!("token id"))?,
                            ),
                            amount: t["amount"].as_u64().unwrap_or(0),
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        out.push(InBox {
            id: (*id).to_string(),
            value: b["value"].as_u64().unwrap_or(0),
            tokens,
        });
    }
    Ok(out)
}
