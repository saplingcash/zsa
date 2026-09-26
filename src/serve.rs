//! `serve`: the issuer service. Watches Solana for finalized burns of every `burn` twin's mint and
//! issues each burn's twin once, on the ZSA network, citing the burn (docs/RULES.md §2.7).
//!
//! Idempotent by construction:
//! - a burn is answered at most once: burns already cited on chain by this issuer are found by
//!   scanning the chain, and every issuance is written to the state file (with its raw bytes)
//!   before it is submitted;
//! - after a restart, an issuance in the state file that is not on chain yet is re-submitted byte
//!   for byte, never rebuilt, so one burn can never be answered twice;
//! - a burn that fails the rules (no memo, wrong mint, bad address, ...) is recorded as skipped,
//!   with the reason, and not retried.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use crate::audit::{self, IssuerEntry, IssuersFile, TwinsFile};
use crate::issue::{self, BuildOptions};
use crate::metadata::TwinOf;
use crate::rpc::Node;
use crate::scan::{self, Citation};
use crate::solana::{self, SolanaRpc};
use crate::keys;

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// The chain was scanned for this issuer's citations up to this height.
    scanned_to: u64,
    /// Burn signatures already answered on chain.
    answered: HashSet<String>,
    /// Issuances built and submitted by this service, by burn signature.
    issued: BTreeMap<String, Issued>,
    /// Burns that fail the rules, by signature, with the reason.
    skipped: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Issued {
    txid: String,
    raw: String,
    amount: u64,
    to: String,
}

impl State {
    fn load(path: &Path) -> Result<Self, String> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Write to a temporary file and rename, so a crash never leaves a half-written state.
    fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let tmp = path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(self).expect("state serializes");
        {
            use std::io::Write;
            let mut f = fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
            f.write_all(&bytes).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
        }
        fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// Solana mainnet-beta's genesis hash: refused.
const SOLANA_MAINNET_GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

pub struct Options {
    pub root: PathBuf,
    pub network: String,
    /// A single issuer key (a BIP-39 phrase file) ...
    pub key: Option<PathBuf>,
    /// ... or a FROST group: its public key package, the signers' addresses, and the threshold.
    pub group: Option<PathBuf>,
    pub signers: Vec<String>,
    pub threshold: usize,
    pub state: PathBuf,
    pub node: Option<String>,
    pub interval: Duration,
    pub once: bool,
}

/// Who signs issuances: one key held by the service, or a threshold group of separate signers.
enum Authority {
    Key(String),
    Group {
        pkp: crate::frost::PublicKeyPackage,
        ik: orchard::issuance::auth::IssueValidatingKey<orchard::issuance::auth::ZSASchnorr>,
        signers: Vec<String>,
        threshold: usize,
    },
}

struct BurnTwin {
    label: String,
    envelope: String,
    twin_of: TwinOf,
    rpc: SolanaRpc,
}

pub fn run(opts: &Options) -> Result<(), String> {
    let issuers: IssuersFile = audit::read_json(&opts.root.join("registry/issuers.json"))?;
    let twins_file: TwinsFile = audit::read_json(&opts.root.join("registry/twins.json"))?;
    let network = issuers
        .networks
        .get(&opts.network)
        .ok_or_else(|| format!("network {} is not in registry/issuers.json", opts.network))?;
    let node_url = opts.node.clone().unwrap_or_else(|| network.rpc.clone());
    let node = Node::new(&node_url);
    if node.block_hash(0)? != network.genesis {
        return Err(format!("node {node_url} is not {} (genesis differs)", opts.network));
    }

    let (authority, issuer) = match (&opts.key, &opts.group) {
        (Some(k), None) => {
            let phrase = keys::read_phrase(k)?;
            let issuer = keys::issuer_hex(&keys::issuance_key(&phrase)?);
            (Authority::Key(phrase), issuer)
        }
        (None, Some(g)) => {
            let pkp = crate::signer::read_group(g)?;
            let ik = crate::threshold::issuer_from_xonly(&crate::frost::group_xonly(&pkp)?)?;
            let issuer = hex::encode(ik.encode());
            if opts.threshold == 0 || opts.signers.len() < opts.threshold {
                return Err(format!("{} signer(s) given for a threshold of {}", opts.signers.len(), opts.threshold));
            }
            (Authority::Group { pkp, ik, signers: opts.signers.clone(), threshold: opts.threshold }, issuer)
        }
        _ => return Err("give either --key or --group with --signers".into()),
    };
    let listed: HashMap<String, &IssuerEntry> = issuers
        .issuers
        .iter()
        .filter(|i| i.network == opts.network)
        .map(|i| (i.issuer.to_lowercase(), i))
        .collect();
    let entry = listed.get(&issuer).ok_or_else(|| format!("the key's issuer {issuer} is not listed for {}", opts.network))?;
    if entry.valid_until.is_some() {
        return Err("the key's validity range is closed; it must not issue".into());
    }

    let mut twins = Vec::new();
    for t in twins_file.twins.iter().filter(|t| t.kind == "burn") {
        let dir = t.dir.as_deref().ok_or("a burn twin without dir")?;
        let (label, _asset, _, twin_of) = audit::twin_with_metadata(&opts.root, dir, &listed, &opts.network)?;
        // Only this issuer's twins: another issuer's twin is a different asset.
        let twin_issuer = fs::read_to_string(opts.root.join(dir).join("issuer.txt")).map_err(|e| e.to_string())?;
        if twin_issuer.trim().to_lowercase() != issuer {
            continue;
        }
        let url = network
            .solana_rpc
            .get(&twin_of.cluster)
            .ok_or_else(|| format!("{label}: no Solana RPC for cluster {}", twin_of.cluster))?;
        let rpc = SolanaRpc::new(url);
        if rpc.genesis_hash()? == SOLANA_MAINNET_GENESIS {
            return Err(format!("{label}: the Solana RPC {url} is mainnet; test networks only"));
        }
        let envelope = fs::read_to_string(opts.root.join(dir).join("envelope.txt")).map_err(|e| e.to_string())?;
        twins.push(BurnTwin { label, envelope, twin_of, rpc });
    }
    if twins.is_empty() {
        return Err(format!("no burn twin of issuer {issuer} in registry/twins.json"));
    }
    println!("issuer {issuer} on {} ({node_url}); watching:", opts.network);
    for t in &twins {
        println!("  {}: Solana {} mint {}", t.label, t.twin_of.cluster, t.twin_of.mint);
    }

    let mut state = State::load(&opts.state)?;
    if state.scanned_to < entry.valid_from {
        state.scanned_to = entry.valid_from.saturating_sub(1);
    }
    loop {
        if let Err(e) = pass(&mut state, &opts.state, &node, &node_url, &authority, &issuer, &twins) {
            eprintln!("pass failed (will retry): {e}");
        }
        if opts.once {
            return Ok(());
        }
        std::thread::sleep(opts.interval);
    }
}

fn pass(
    state: &mut State,
    state_path: &Path,
    node: &Node,
    node_url: &str,
    authority: &Authority,
    issuer: &str,
    twins: &[BurnTwin],
) -> Result<(), String> {
    // 1. What this issuer has already answered on chain. (A fresh chain at genesis has no Orchard
    //    tree yet, so no anchor: produce one empty block first.)
    if node.block_count()? == 0 {
        issue::empty_block(node_url)?;
    }
    let tip = node.block_count()?;
    for height in state.scanned_to + 1..=tip {
        for (_, tx) in scan::issuances_in_block(&node.raw_block(height)?)? {
            if hex::encode(tx.issue_bundle().expect("filtered").ik().encode()) != issuer {
                continue;
            }
            for c in scan::null_data_outputs(&tx).into_iter().flatten().filter_map(|d| Citation::decode(&d)) {
                state.answered.insert(c.signature_b58());
            }
        }
        state.scanned_to = height;
    }
    state.save(state_path)?;

    // 2. Issuances submitted earlier but not on chain yet: re-submit the same bytes.
    let pending: Vec<(String, String)> = state
        .issued
        .iter()
        .filter(|(sig, _)| !state.answered.contains(*sig))
        .map(|(sig, i)| (sig.clone(), i.raw.clone()))
        .collect();
    for (sig, raw) in pending {
        let bytes = hex::decode(&raw).map_err(|e| e.to_string())?;
        let tx = Transaction::read(bytes.as_slice(), BranchId::Nu6).map_err(|e| e.to_string())?;
        match issue::submit(node_url, tx) {
            Ok(h) => println!("re-submitted the issuance for burn {sig} at height {h}"),
            Err(e) => eprintln!("re-submitting the issuance for burn {sig}: {e}"),
        }
    }

    // 3. New burns, oldest first.
    for t in twins {
        let mut sigs = t.rpc.signatures_for(&t.twin_of.mint, None, 100)?;
        sigs.reverse();
        for (sig, succeeded) in sigs {
            if state.answered.contains(&sig) || state.issued.contains_key(&sig) || state.skipped.contains_key(&sig) {
                continue;
            }
            if !succeeded {
                state.skipped.insert(sig, "the transaction failed on Solana".into());
                continue;
            }
            let Some(tx) = t.rpc.transaction(&sig)? else { continue };
            let burn = match solana::parse_burn(&sig, &tx, Some(&t.twin_of.mint)) {
                Ok(b) => b,
                Err(reason) => {
                    println!("{}: not a twin burn, skipped: {sig} ({reason})", t.label);
                    state.skipped.insert(sig, reason);
                    state.save(state_path)?;
                    continue;
                }
            };
            let Some(recipient) = Option::from(orchard::Address::from_raw_address_bytes(&burn.orchard_receiver)) else {
                state.skipped.insert(sig, "the memo's Orchard receiver is not a valid address".into());
                state.save(state_path)?;
                continue;
            };
            let citation = Citation::for_burn(&sig, burn.amount)?;
            let opts = BuildOptions { citation: Some(citation), ..Default::default() };
            let tx = match authority {
                Authority::Key(phrase) => issue::build(phrase, &t.envelope, burn.amount, recipient, &opts, node)?.0,
                Authority::Group { pkp, ik, signers, threshold } => {
                    let u = crate::threshold::build_unsigned(ik, &t.envelope, burn.amount, recipient, &opts, node)?;
                    let mut raw = Vec::new();
                    u.tx.write(&mut raw).map_err(|e| e.to_string())?;
                    println!("{}: burn {sig}: asking {} signers ({threshold} needed)", t.label, signers.len());
                    match crate::signer::request_signature(signers, pkp, *threshold, &hex::encode(&raw), &u.sighash) {
                        Ok(sig64) => {
                            let tx = crate::threshold::attach(u.tx, &sig64)?;
                            crate::threshold::verify_issuance_signature(&tx)?;
                            tx
                        }
                        Err(e) => {
                            // Not recorded: the burn is tried again on the next pass.
                            println!("{}: burn {sig}: {e}", t.label);
                            continue;
                        }
                    }
                }
            };
            let txid = tx.txid().to_string();
            let mut raw = Vec::new();
            tx.write(&mut raw).map_err(|e| e.to_string())?;
            // Stored before it is submitted: a crash after this line re-submits these exact bytes.
            state.issued.insert(
                sig.clone(),
                Issued { txid: txid.clone(), raw: hex::encode(&raw), amount: burn.amount, to: burn.zcash_address.clone() },
            );
            state.save(state_path)?;
            println!("{}: burn {sig} ({} base units) -> issuing twin tx {txid} to {}", t.label, burn.amount, burn.zcash_address);
            match issue::submit(node_url, tx) {
                Ok(h) => println!("{}: twin issued at height {h}: {txid}", t.label),
                Err(e) => eprintln!("{}: submitting {txid}: {e} (will re-submit)", t.label),
            }
        }
    }
    state.save(state_path)
}
