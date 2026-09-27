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
mod frost;
mod frost_selftest;
mod holder;
mod inspect;
mod issue;
mod keys;
mod metadata;
mod pages;
mod rpc;
mod scan;
mod serve;
mod signer;
mod solana;
mod threshold;
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
    /// Print a test wallet's unified address (test network, Orchard receiver) for a key file.
    Address {
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value_t = 0)]
        account: u32,
    },
    /// The issuer service: watch Solana for burns of every burn twin and issue each twin once.
    Serve {
        /// A single issuer key (a BIP-39 phrase file).
        #[arg(long)]
        key: Option<PathBuf>,
        /// A FROST group's public key package: issue with threshold signatures instead of a key.
        #[arg(long)]
        group: Option<PathBuf>,
        /// The group's signers (host:port), with --group.
        #[arg(long, value_delimiter = ',')]
        signers: Vec<String>,
        /// Signatures needed, with --group.
        #[arg(long, default_value_t = 2)]
        threshold: usize,
        #[arg(long, default_value = "qedit-zsa-test")]
        network: String,
        /// The directory holding registry/ and assets/.
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// State file (kept out of version control).
        #[arg(long, default_value = ".private/serve-state.json")]
        state: PathBuf,
        /// Override the network's RPC URL from registry/issuers.json (e.g. a local node).
        #[arg(long)]
        node: Option<String>,
        /// Seconds between passes.
        #[arg(long, default_value_t = 15)]
        interval: u64,
        /// One pass, then exit.
        #[arg(long)]
        once: bool,
    },
    /// The holder's side of a twin: balances, sending on to a fresh address, burning on Zcash.
    Holder {
        #[command(subcommand)]
        cmd: HolderCmd,
        /// The holder's test key file (a BIP-39 phrase).
        #[arg(long, global = true)]
        key: Option<PathBuf>,
        /// Wallet state (SQLite; kept out of version control).
        #[arg(long, global = true, default_value = ".private/holder-wallet.sqlite")]
        wallet_db: PathBuf,
        #[arg(long, global = true, default_value = rpc::DEFAULT_NODE)]
        node: String,
    },
    /// Generate a static HTML page per twin (and an index) from an audit run.
    Pages {
        #[arg(long, default_value = "site")]
        out: PathBuf,
        #[arg(long, default_value = "qedit-zsa-test")]
        network: String,
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        node: Option<String>,
    },
    /// Print what anyone can read from the chain about a transaction, and what stays hidden.
    Inspect {
        txid: String,
        #[arg(long, default_value = rpc::DEFAULT_NODE)]
        node: String,
    },
    /// A threshold signer of the issuer key: key generation, and the signing server.
    Signer {
        #[command(subcommand)]
        cmd: SignerCmd,
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
    /// On a LOCAL ZSA node only: issue under a 2-of-3 FROST group key and check what the node accepts.
    FrostSelftest {
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

#[derive(Subcommand)]
enum SignerCmd {
    /// One participant's part of the distributed key generation (run one process per participant).
    Dkg {
        #[arg(long)]
        id: u16,
        #[arg(long, default_value_t = 3)]
        n: u16,
        #[arg(long, default_value_t = 2)]
        t: u16,
        /// Directory the participants exchange packages through.
        #[arg(long)]
        exchange: PathBuf,
        /// Where this participant's key share is written (keep it private).
        #[arg(long)]
        share: PathBuf,
        /// Where the group's public key package is written.
        #[arg(long)]
        group: PathBuf,
    },
    /// Serve signature shares for issuances that pass this signer's own checks.
    Serve {
        #[arg(long)]
        share: PathBuf,
        #[arg(long)]
        group: PathBuf,
        /// host:port to listen on (keep it on a private interface).
        #[arg(long)]
        listen: String,
        #[arg(long, default_value = "qedit-zsa-test")]
        network: String,
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        node: Option<String>,
    },
}

#[derive(Subcommand)]
enum HolderCmd {
    /// The wallet's two addresses and its balance of a twin at each.
    Balance { coin_dir: PathBuf },
    /// Send units of a twin from account 0 (the memo's address) to account 1 (a fresh address).
    Send {
        coin_dir: PathBuf,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 0)]
        from: usize,
        #[arg(long, default_value_t = 1)]
        to: usize,
    },
    /// Burn units of a twin on Zcash (ZIP 226).
    Burn {
        coin_dir: PathBuf,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 1)]
        from: usize,
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
        Cmd::Address { key, account } => {
            let addr = issue::test_address(&keys::read_phrase(&key)?, account)?;
            println!("{}", address::encode_orchard(addr.to_raw_address_bytes())?);
            Ok(true)
        }
        Cmd::Serve { key, group, signers, threshold, network, root, state, node, interval, once } => {
            serve::run(&serve::Options {
                root,
                network,
                key,
                group,
                signers,
                threshold,
                state,
                node,
                interval: std::time::Duration::from_secs(interval),
                once,
            })?;
            Ok(true)
        }
        Cmd::Holder { cmd, key, wallet_db, node } => {
            let key = key.ok_or("--key <holder key file> is required")?;
            let mut w = holder::HolderWallet::open(&key, &wallet_db, &node)?;
            let show = |w: &mut holder::HolderWallet, asset| -> Result<(), String> {
                for a in 0..2 {
                    println!("account {a}  {}  balance {}", w.address(a)?, w.balance(a, asset));
                }
                Ok(())
            };
            match cmd {
                HolderCmd::Balance { coin_dir } => show(&mut w, holder::asset_of(&coin_dir)?)?,
                HolderCmd::Send { coin_dir, amount, from, to } => {
                    let asset = holder::asset_of(&coin_dir)?;
                    if from > 1 || to > 1 || from == to {
                        return Err("accounts are 0 and 1, and must differ".into());
                    }
                    let txid = w.send(from, to, amount, asset)?;
                    println!("sent {amount} units from account {from} to account {to}: tx {txid}");
                    show(&mut w, asset)?;
                }
                HolderCmd::Burn { coin_dir, amount, from } => {
                    let asset = holder::asset_of(&coin_dir)?;
                    if from > 1 {
                        return Err("accounts are 0 and 1".into());
                    }
                    let txid = w.burn(from, amount, asset)?;
                    println!("burned {amount} units on Zcash from account {from}: tx {txid}");
                    show(&mut w, asset)?;
                }
            }
            Ok(true)
        }
        Cmd::Pages { out, network, root, node } => {
            let result = audit::audit(&root, &network, node.as_deref(), false);
            for f in pages::write(&root, &result, &out)? {
                println!("{}", out.join(f).display());
            }
            println!("audit: {}", if result.report.passed() { "OK" } else { "FAIL" });
            Ok(true)
        }
        Cmd::Signer { cmd } => {
            match cmd {
                SignerCmd::Dkg { id, n, t, exchange, share, group } => {
                    let issuer = signer::dkg(id, n, t, &exchange, &share, &group)?;
                    println!("participant {id}: key share written to {}; group issuer {issuer}", share.display());
                }
                SignerCmd::Serve { share, group, listen, network, root, node } => {
                    signer::serve(&signer::ServeOptions { share, group, listen, root, network, node })?;
                }
            }
            Ok(true)
        }
        Cmd::Inspect { txid, node } => {
            for line in inspect::inspect(&txid, &rpc::Node::new(&node))? {
                println!("{line}");
            }
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
            let report = audit::audit(&root, &network, node.as_deref(), false).report;
            for (ok, line) in &report.lines {
                println!("{} {line}", if *ok { "OK  " } else { "FAIL" });
            }
            println!("{}", if report.passed() { "RESULT: OK" } else { "RESULT: FAIL" });
            Ok(report.passed())
        }
        Cmd::LocalVectors { node } => vectors::run(&node),
        Cmd::FrostSelftest { node } => frost_selftest::run(&node),
        Cmd::Check { coin_dir, txid, node } => {
            let (envelope, bundle, issuer) = published(&coin_dir)?;
            let txids = if txid.is_empty() {
                let list = coin_dir.join("issuances.txt");
                if !list.exists() {
                    return Err(format!(
                        "{} has no issuances.txt: a burn twin's issuances are found by scanning the chain. \
                         Run `zsa audit` for all of them, or pass each txid with --txid",
                        coin_dir.display()
                    ));
                }
                read_text(&list)?
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
