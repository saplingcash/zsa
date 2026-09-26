//! `zsa`: OrchardZSA twins of Sapling (sapling.cash) coins. Test networks only.
//!
//! A coin directory (`assets/<coin>/`) holds:
//!   coin.json       the input (name, Solana cluster + mint, decimals, note)
//!   bundle.json     Cachet v1 metadata bundle (exact bytes; written by `describe`)
//!   envelope.txt    Cachet v1 envelope = the ZIP 227 asset_desc (exact bytes; written by `describe`)
//!   issuer.txt      the published issuer key, hex of [0x00] || ik
//!   issuances.txt   txids of the twin's issuances, one per line

mod address;
mod audit;
mod check;
mod issue;
mod keys;
mod metadata;
mod rpc;
mod scan;
mod solana;
mod vectors;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zsa", version, about = "OrchardZSA twins of Sapling (sapling.cash) coins. Test networks only.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build the Cachet v1 bundle and envelope from coin.json, and print the asset identifiers.
    Describe { coin_dir: PathBuf },
    /// Create a test issuer key (a BIP-39 phrase) in a file under .private/ or outside the repo.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the issuer (hex of [0x00] || ik) for a key file.
    Issuer {
        #[arg(long)]
        key: PathBuf,
    },
    /// Issue units of the coin's twin on a ZSA test node (to account 1 of the same test wallet).
    Issue {
        coin_dir: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        amount: u64,
        /// The Solana burn this issuance answers (base58 signature); adds the burn citation.
        #[arg(long)]
        burn_sig: Option<String>,
        #[arg(long, default_value = rpc::DEFAULT_NODE)]
        node: String,
    },
    /// Apply docs/RULES.md to the whole registry: scan the chain, classify every issuance by a listed
    /// issuer, compare each twin's supply with the node's record.
    Audit {
        #[arg(long, default_value = "qedit-zsa-test")]
        network: String,
        /// The directory holding registry/ and assets/ (default: the current directory).
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// Override the network's RPC URL from registry/issuers.json (e.g. a local node).
        #[arg(long)]
        node: Option<String>,
    },
    /// Issue deliberately bad twin issuances on a LOCAL ZSA node and check audit's verdict on each.
    LocalVectors {
        #[arg(long, default_value = "http://127.0.0.1:38232")]
        node: String,
    },
    /// Check a twin from public data only: metadata, issuer, signatures, asset, node supply.
    Check {
        coin_dir: PathBuf,
        /// Issuance txids to check (default: the coin's issuances.txt).
        #[arg(long)]
        txid: Vec<String>,
        #[arg(long, default_value = rpc::DEFAULT_NODE)]
        node: String,
    },
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

fn read_text(path: &Path) -> Result<String, String> {
    String::from_utf8(read(path)?).map_err(|_| format!("{} is not UTF-8", path.display()))
}

fn published(dir: &Path) -> Result<(String, Vec<u8>, String), String> {
    let envelope = read_text(&dir.join("envelope.txt"))?;
    let bundle = read(&dir.join("bundle.json"))?;
    let issuer = read_text(&dir.join("issuer.txt"))?.trim().to_lowercase();
    Ok((envelope, bundle, issuer))
}

fn run(cli: Cli) -> Result<bool, String> {
    match cli.cmd {
        Cmd::Describe { coin_dir } => {
            let spec: metadata::CoinSpec = serde_json::from_slice(&read(&coin_dir.join("coin.json"))?)
                .map_err(|e| format!("coin.json: {e}"))?;
            let bundle = spec.bundle().map_err(|p| p.join("; "))?;
            let bytes = metadata::bundle_bytes(&bundle);
            let envelope = metadata::envelope_for(&bundle)?;
            fs::write(coin_dir.join("bundle.json"), &bytes).map_err(|e| e.to_string())?;
            fs::write(coin_dir.join("envelope.txt"), &envelope).map_err(|e| e.to_string())?;
            println!("bundle sha256      {}", metadata::sha256_hex(&bytes));
            println!("asset_desc         {envelope}");
            println!("asset_desc_hash    {}", hex::encode(metadata::asset_desc_hash(envelope.as_bytes())));
            if let Ok(issuer) = read_text(&coin_dir.join("issuer.txt")) {
                let ik = hex::decode(issuer.trim())
                    .ok()
                    .and_then(|b| orchard::issuance::auth::IssueValidatingKey::decode(&b).ok())
                    .ok_or("issuer.txt does not decode")?;
                let hash = metadata::asset_desc_hash(envelope.as_bytes());
                let asset = orchard::note::AssetBase::custom(&orchard::note::AssetId::new_v0(&ik, &hash));
                println!("issuer             {}", issuer.trim());
                println!("asset base         {}", hex::encode(asset.to_bytes()));
            }
            Ok(true)
        }
        Cmd::Keygen { out } => {
            let issuer = keys::keygen(&out)?;
            println!("key written to {} (never commit it)", out.display());
            println!("issuer {issuer}");
            Ok(true)
        }
        Cmd::Issuer { key } => {
            println!("{}", keys::issuer_hex(&keys::issuance_key(&keys::read_phrase(&key)?)?));
            Ok(true)
        }
        Cmd::Issue { coin_dir, key, amount, burn_sig, node } => {
            let (envelope, bundle, issuer) = published(&coin_dir)?;
            metadata::verify_published(&envelope, &bundle).map_err(|p| p.join("; "))?;
            let key_issuer = keys::issuer_hex(&keys::issuance_key(&keys::read_phrase(&key)?)?);
            if key_issuer != issuer {
                return Err(format!("the key's issuer {key_issuer} is not the published issuer.txt {issuer}"));
            }
            let info = rpc::Node::new(&node).chain_info()?;
            println!("node {node}: chain {}, height {}", info.chain, info.blocks);
            let citation = burn_sig.map(|s| scan::Citation::for_burn(&s, amount)).transpose()?;
            let issued = issue::issue(&key, &envelope, amount, citation, &node)?;
            let mut list = read_text(&coin_dir.join("issuances.txt")).unwrap_or_default();
            list.push_str(&format!("{}\n", issued.txid));
            fs::write(coin_dir.join("issuances.txt"), list).map_err(|e| e.to_string())?;
            println!("issued {amount} units: txid {} at height {}", issued.txid, issued.height);
            println!("asset base {}", issued.asset_base_hex);
            println!("recipient (raw Orchard address) {}", issued.recipient_hex);
            println!("first issuance: {}", issued.first_issuance);
            Ok(true)
        }
        Cmd::Audit { network, root, node } => {
            let report = audit::audit(&root, &network, node.as_deref(), false);
            for (ok, line) in &report.lines {
                println!("{} {line}", if *ok { "OK  " } else { "FAIL" });
            }
            println!("{}", if report.passed() { "RESULT: OK" } else { "RESULT: FAIL" });
            Ok(report.passed())
        }
        Cmd::LocalVectors { node } => vectors::run(&node),
        Cmd::Check { coin_dir, txid, node } => {
            let (envelope, bundle, issuer) = published(&coin_dir)?;
            let txids = if txid.is_empty() {
                read_text(&coin_dir.join("issuances.txt"))?
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(String::from)
                    .collect()
            } else {
                txid
            };
            let node = rpc::Node::new(&node);
            println!("checking {} against {} ({} issuance(s))", coin_dir.display(), node.url(), txids.len());
            let report = check::check(&envelope, &bundle, &issuer, &txids, &node);
            for (ok, line) in &report.lines {
                println!("{} {line}", if *ok { "OK  " } else { "FAIL" });
            }
            println!("{}", if report.passed() { "RESULT: OK" } else { "RESULT: FAIL" });
            Ok(report.passed())
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
