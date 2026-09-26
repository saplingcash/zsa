//! `audit`: apply docs/RULES.md to the whole registry, from the chain alone.
//!
//! Scans every block of the network from the earliest `valid_from` of a listed issuer to the tip,
//! classifies every issuance signed by a listed issuer, and checks each twin's supply against the
//! node's own record. Issuances by keys that are not listed are other people's and are ignored.
//! For burn twins, every cited burn is fetched from Solana (finalized) and checked (RULES §2).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use orchard::issuance::auth::IssueValidatingKey;
use orchard::note::{AssetBase, AssetId};
use serde::Deserialize;
use zcash_primitives::transaction::Transaction;

use crate::check::Report;
use crate::metadata::{self, TwinOf};
use crate::solana::{self, SolanaRpc};
use crate::rpc::Node;
use crate::scan::{self, Citation};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuersFile {
    pub v: u32,
    pub networks: BTreeMap<String, Network>,
    pub issuers: Vec<IssuerEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[allow(dead_code)] // descriptive only
    pub description: String,
    pub rpc: String,
    pub genesis: String,
    /// Solana RPC per cluster (e.g. "devnet"), for the burn twins' Solana-side checks.
    #[serde(default)]
    pub solana_rpc: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerEntry {
    pub issuer: String,
    pub network: String,
    pub valid_from: u64,
    pub valid_until: Option<u64>,
    #[allow(dead_code)] // descriptive only
    pub note: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwinsFile {
    pub v: u32,
    pub twins: Vec<TwinEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwinEntry {
    pub kind: String,
    /// `burn` and `direct-test`: the directory with the published metadata.
    pub dir: Option<String>,
    /// `undisclosed-test`: the asset base (hex) and the issuer; no metadata is published.
    pub asset: Option<String>,
    pub issuer: Option<String>,
    #[allow(dead_code)] // descriptive only
    pub note: String,
}

#[derive(Debug, Clone, PartialEq)]
enum Status {
    /// Valid; the string says what backs it (the Solana burn, or a direct test issuance).
    Valid(String),
    Unbacked(String),
    Duplicate,
    Malformed(String),
}

struct Seen {
    height: u64,
    txid: String,
    amount: u64,
    status: Status,
}

struct Twin {
    entry: TwinEntry,
    twin_of: Option<TwinOf>,
    label: String,
    asset_hex: String,
    seen: Vec<Seen>,
}

/// What one issuance transaction says, if it has the shape a twin issuance must have.
struct Shape {
    asset: AssetBase,
    amount: u64,
    finalized: bool,
    citation: Option<Citation>,
    recipient: [u8; 43],
}

pub(crate) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// RULES §2.3–2.7 on one transaction (everything that does not need the registry or history).
fn shape(tx: &Transaction) -> Result<Shape, String> {
    let bundle = tx.issue_bundle().ok_or("no issuance bundle")?;
    if tx.transparent_bundle().is_some_and(|b| !b.vin.is_empty()) {
        return Err("has transparent inputs".into());
    }
    let sighash: [u8; 32] = *tx.txid().as_ref();
    bundle
        .ik()
        .verify(&sighash, bundle.authorization().signature().sig())
        .map_err(|_| "issuance signature does not verify over the txid digest")?;
    if bundle.actions().len() != 1 {
        return Err(format!("{} issue actions (exactly 1 expected)", bundle.actions().len()));
    }
    let action = bundle.actions().first();
    let asset = AssetBase::custom(&AssetId::new_v0(bundle.ik(), action.asset_desc_hash()));
    let value_notes: Vec<_> = action.notes().iter().filter(|n| n.value().inner() > 0).collect();
    if value_notes.len() != 1 {
        return Err(format!("{} value notes (exactly 1 expected)", value_notes.len()));
    }
    let mut citation = None;
    for data in scan::null_data_outputs(tx) {
        match data.as_deref().and_then(Citation::decode) {
            Some(c) if citation.is_none() => citation = Some(c),
            Some(_) => return Err("more than one burn citation".into()),
            None => return Err("an OP_RETURN output that is not a burn citation".into()),
        }
    }
    Ok(Shape {
        asset,
        amount: value_notes[0].value().inner(),
        finalized: action.is_finalized(),
        citation,
        recipient: value_notes[0].recipient().to_raw_address_bytes(),
    })
}

/// RULES §2 against Solana: the cited burn exists (finalized), burns this twin's mint, exactly the
/// cited amount, carries one sapling-twin memo, and the issued note goes to the memo's address.
fn check_burn(c: &Citation, s: &Shape, twin: &TwinOf, rpc: &SolanaRpc) -> Status {
    let sig = c.signature_b58();
    let tx = match rpc.transaction(&sig) {
        Ok(Some(tx)) => tx,
        Ok(None) => return Status::Unbacked(format!("burn {sig} not found (or not finalized) on Solana {}", twin.cluster)),
        Err(e) => return Status::Unbacked(format!("burn {sig}: {e}")),
    };
    let burn = match solana::parse_burn(&sig, &tx, Some(&twin.mint)) {
        Ok(b) => b,
        Err(e) => return Status::Unbacked(format!("burn {sig}: {e}")),
    };
    if burn.amount != c.amount {
        return Status::Unbacked(format!("burn {sig} burned {} but the citation says {}", burn.amount, c.amount));
    }
    if burn.orchard_receiver != s.recipient {
        return Status::Unbacked(format!("burn {sig}: the issued note does not go to the memo's address"));
    }
    Status::Valid(format!("burn {sig} on Solana {}, slot {}, to {}", twin.cluster, burn.slot, burn.zcash_address))
}

/// `skip_solana`: do not fetch burns from Solana (local test vectors; the lines say so).
pub fn audit(root: &Path, network_name: &str, node_override: Option<&str>, skip_solana: bool) -> Report {
    let mut r = Report::new();
    let loaded = (|| -> Result<(IssuersFile, TwinsFile), String> {
        Ok((read_json(&root.join("registry/issuers.json"))?, read_json(&root.join("registry/twins.json"))?))
    })();
    let (issuers, twins_file) = match loaded {
        Ok(x) => x,
        Err(e) => {
            r.fail(e);
            return r;
        }
    };
    if issuers.v != 1 || twins_file.v != 1 {
        r.fail("registry files must be version 1");
        return r;
    }
    let Some(network) = issuers.networks.get(network_name) else {
        r.fail(format!("network {network_name} is not in registry/issuers.json"));
        return r;
    };
    let node = Node::new(node_override.unwrap_or(&network.rpc));

    // The network, by its genesis hash.
    match node.block_hash(0) {
        Ok(h) if h == network.genesis => r.ok(format!("network {network_name}: genesis {h} matches ({})", node.url())),
        Ok(h) => {
            r.fail(format!("node {} has genesis {h}, not {network_name}'s {} (a reset, or another network)", node.url(), network.genesis));
            return r;
        }
        Err(e) => {
            r.fail(e);
            return r;
        }
    }

    // Listed issuers for this network.
    let listed: HashMap<String, &IssuerEntry> = issuers
        .issuers
        .iter()
        .filter(|i| i.network == network_name)
        .map(|i| (i.issuer.to_lowercase(), i))
        .collect();
    if listed.is_empty() {
        r.fail("no issuer is listed for this network");
        return r;
    }

    // Twins: metadata, issuer, asset.
    let mut twins: Vec<Twin> = Vec::new();
    for entry in &twins_file.twins {
        let resolved = match (entry.kind.as_str(), &entry.dir, &entry.asset, &entry.issuer) {
            ("burn" | "direct-test", Some(dir), None, None) => {
                twin_with_metadata(root, dir, &listed, network_name).map(|(l, a, w, t)| (l, a, w, Some(t)))
            }
            ("undisclosed-test", None, Some(asset), Some(issuer)) => {
                let issuer = issuer.to_lowercase();
                if !listed.contains_key(&issuer) {
                    Err(format!("undisclosed asset {asset}: issuer {issuer} is not listed for {network_name}"))
                } else if asset.len() != 64 || hex::decode(asset).is_err() {
                    Err(format!("undisclosed asset {asset}: not a 32-byte hex asset base"))
                } else {
                    Ok((format!("undisclosed test asset {}", &asset[..16]), asset.to_lowercase(), "listed by asset id only; description not published".to_string(), None))
                }
            }
            (kind, ..) => Err(format!("twins.json: an entry of kind {kind} has the wrong fields")),
        };
        let (label, asset_hex, what, twin_of) = match resolved {
            Ok(x) => x,
            Err(e) => {
                r.fail(e);
                continue;
            }
        };
        if twins.iter().any(|t| t.asset_hex == asset_hex) {
            r.fail(format!("{label}: the same asset is listed twice"));
            continue;
        }
        r.ok(format!("{label} ({}): {what}; asset {asset_hex}", entry.kind));
        if entry.kind == "burn" && !skip_solana {
            let cluster = twin_of.as_ref().map(|t| t.cluster.as_str()).unwrap_or("");
            if !network.solana_rpc.contains_key(cluster) {
                r.fail(format!("{label}: no Solana RPC for cluster {cluster} in registry/issuers.json"));
                continue;
            }
        }
        twins.push(Twin { entry: entry.clone(), twin_of, label, asset_hex, seen: Vec::new() });
    }
    let by_asset: HashMap<String, usize> = twins.iter().enumerate().map(|(i, t)| (t.asset_hex.clone(), i)).collect();

    // Scan.
    let from = listed.values().map(|i| i.valid_from).min().unwrap_or(1).max(1);
    let tip = match node.block_count() {
        Ok(t) => t,
        Err(e) => {
            r.fail(e);
            return r;
        }
    };
    let mut cited: HashSet<[u8; 64]> = HashSet::new();
    let (mut ours, mut others) = (0usize, 0usize);
    for height in from..=tip {
        if (height - from) % 200 == 0 {
            eprintln!("scanning {height}..{tip}");
        }
        let raw = match node.raw_block(height) {
            Ok(b) => b,
            Err(e) => {
                r.fail(e);
                return r;
            }
        };
        let found = match scan::issuances_in_block(&raw) {
            Ok(f) => f,
            Err(e) => {
                r.fail(format!("block {height}: {e}"));
                return r;
            }
        };
        for (_, tx) in found {
            let txid = tx.txid().to_string();
            let issuer = hex::encode(tx.issue_bundle().expect("filtered").ik().encode());
            let Some(entry) = listed.get(&issuer) else {
                others += 1;
                continue;
            };
            ours += 1;
            let in_range = height >= entry.valid_from && entry.valid_until.is_none_or(|u| height <= u);
            let s = match shape(&tx) {
                Ok(s) => s,
                Err(e) => {
                    r.fail(format!("tx {txid} (height {height}) by a listed issuer is malformed: {e}"));
                    continue;
                }
            };
            let asset_hex = hex::encode(s.asset.to_bytes());
            let Some(&ti) = by_asset.get(&asset_hex) else {
                r.fail(format!("tx {txid} (height {height}): listed issuer issued {} units of an UNKNOWN asset {asset_hex}", s.amount));
                continue;
            };
            let twin = &mut twins[ti];
            let status = if !in_range {
                Status::Malformed(format!("issued at height {height}, outside the key's validity range"))
            } else if s.finalized {
                Status::Malformed("finalized (twins stay open)".into())
            } else if twin.entry.kind != "burn" {
                match s.citation {
                    None => Status::Valid("direct test issuance".into()),
                    Some(_) => Status::Malformed("a test twin carries a burn citation".into()),
                }
            } else {
                match s.citation {
                    None => Status::Unbacked("no burn citation".into()),
                    Some(c) if c.amount != s.amount => {
                        Status::Unbacked(format!("citation amount {} but {} issued", c.amount, s.amount))
                    }
                    Some(c) => {
                        // Only a burn that checks out on Solana is answered; the first such issuance wins.
                        let backed = if skip_solana {
                            Status::Valid("Solana side not checked".into())
                        } else {
                            let twin_of = twin.twin_of.as_ref().expect("burn twins have metadata");
                            let rpc = SolanaRpc::new(&network.solana_rpc[&twin_of.cluster]);
                            check_burn(&c, &s, twin_of, &rpc)
                        };
                        match backed {
                            Status::Valid(_) if !cited.insert(c.burn_signature) => Status::Duplicate,
                            other => other,
                        }
                    }
                }
            };
            twin.seen.push(Seen { height, txid, amount: s.amount, status });
        }
    }
    r.ok(format!(
        "scanned blocks {from}..={tip}: {ours} issuance(s) by listed issuers, {others} by other keys (ignored)"
    ));

    // Per twin.
    for t in &twins {
        let total: u64 = t.seen.iter().map(|s| s.amount).sum();
        let valid: u64 = t.seen.iter().filter(|s| matches!(s.status, Status::Valid(_))).map(|s| s.amount).sum();
        for s in &t.seen {
            let line = format!("{}: tx {} (height {}) {} units", t.label, s.txid, s.height, s.amount);
            match &s.status {
                Status::Valid(why) => r.ok(format!("{line}: valid ({why})")),
                Status::Unbacked(why) => r.fail(format!("{line}: UNBACKED ({why})")),
                Status::Duplicate => r.fail(format!("{line}: DUPLICATE (cites a burn already answered)")),
                Status::Malformed(why) => r.fail(format!("{line}: MALFORMED ({why})")),
            }
        }
        match node.asset_state(&t.asset_hex) {
            Ok(Some(st)) => {
                r.expect(
                    st.amount == total,
                    format!("{}: node supply {} = all issuances found by the scan", t.label, st.amount),
                    format!("{}: node supply {} but the scan found {total} (scan incomplete?)", t.label, st.amount),
                );
                r.expect(
                    st.amount == valid,
                    format!("{}: supply {} is all valid issuances", t.label, st.amount),
                    format!("{}: supply {} but only {valid} is valid", t.label, st.amount),
                );
                r.expect(!st.is_finalized, format!("{}: not finalized", t.label), format!("{}: FINALIZED", t.label));
            }
            Ok(None) if t.seen.is_empty() => r.ok(format!("{}: not issued yet", t.label)),
            Ok(None) => r.fail(format!("{}: the scan found issuances but the node has no record", t.label)),
            Err(e) => r.fail(format!("{}: {e}", t.label)),
        }
    }
    r
}

/// A `burn` or `direct-test` twin: verify its published metadata and derive its asset.
pub(crate) fn twin_with_metadata(
    root: &Path,
    dir_name: &str,
    listed: &HashMap<String, &IssuerEntry>,
    network_name: &str,
) -> Result<(String, String, String, TwinOf), String> {
    let dir = root.join(dir_name);
    let read = |f: &str| fs::read(dir.join(f)).map_err(|e| format!("{dir_name}/{f}: {e}"));
    let envelope = String::from_utf8(read("envelope.txt")?).map_err(|_| format!("{dir_name}: envelope is not UTF-8"))?;
    let bundle = read("bundle.json")?;
    let issuer = String::from_utf8(read("issuer.txt")?).map_err(|_| "issuer.txt")?.trim().to_lowercase();
    let twin_of = metadata::verify_published(&envelope, &bundle)
        .map_err(|p| format!("{dir_name}: metadata: {}", p.join("; ")))?;
    if !listed.contains_key(&issuer) {
        return Err(format!("{dir_name}: issuer {issuer} is not listed for {network_name}"));
    }
    let ik = hex::decode(&issuer)
        .ok()
        .and_then(|b| IssueValidatingKey::decode(&b).ok())
        .ok_or_else(|| format!("{dir_name}: issuer does not decode"))?;
    let asset = AssetBase::custom(&AssetId::new_v0(&ik, &metadata::asset_desc_hash(envelope.as_bytes())));
    Ok((dir_name.to_string(), hex::encode(asset.to_bytes()), "metadata verifies".to_string(), twin_of))
}
