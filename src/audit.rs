//! `audit`: apply docs/RULES.md to the whole registry, from the chain alone.
//!
//! Scans every block of the network from the earliest `valid_from` of a listed issuer to the tip,
//! classifies every issuance signed by a listed issuer, counts every ZIP 226 burn of a twin, and
//! checks each twin's supply against the node's own record. Issuances by keys that are not listed
//! are other people's and are ignored. For burn twins, every cited burn is fetched from Solana
//! (finalized) and checked (RULES §2).
//!
//! The result is both a report (one line per finding) and structured findings, which `pages` uses.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use orchard::issuance::auth::IssueValidatingKey;
use orchard::note::{AssetBase, AssetId};
use serde::Deserialize;
use zcash_primitives::transaction::Transaction;

use crate::check::Report;
use crate::metadata::{self, TwinOf};
use crate::rpc::Node;
use crate::scan::{self, Citation};
use crate::solana::{self, Burn, SolanaRpc};

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
    /// A transaction link on a public explorer, with `{txid}` (optional; used by `pages`).
    #[serde(default)]
    pub explorer_tx: Option<String>,
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

/// How audit classified one issuance.
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    /// Valid; the string says what backs it (the Solana burn, or a direct test issuance).
    Valid(String),
    Unbacked(String),
    Duplicate,
    Malformed(String),
}

#[derive(Debug, Clone)]
pub struct IssuanceFinding {
    pub height: u64,
    pub txid: String,
    pub amount: u64,
    pub status: Status,
    /// The Solana burn behind it, when it checked out.
    pub solana_burn: Option<Burn>,
}

#[derive(Debug, Clone)]
pub struct BurnFinding {
    pub height: u64,
    pub txid: String,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct TwinFindings {
    pub label: String,
    pub kind: String,
    pub dir: Option<String>,
    pub asset_hex: String,
    pub issuer: String,
    pub twin_of: Option<TwinOf>,
    pub issuances: Vec<IssuanceFinding>,
    pub burns: Vec<BurnFinding>,
    pub node_supply: Option<u64>,
    pub node_finalized: Option<bool>,
    /// Every check for this twin passed.
    pub ok: bool,
}

pub struct AuditResult {
    pub report: Report,
    pub network: String,
    pub explorer_tx: Option<String>,
    pub node: String,
    pub scanned: Option<(u64, u64)>,
    pub twins: Vec<TwinFindings>,
}

/// What one issuance transaction says, if it has the shape a twin issuance must have.
pub(crate) struct Shape {
    pub asset: AssetBase,
    pub amount: u64,
    pub finalized: bool,
    pub citation: Option<Citation>,
    pub recipient: [u8; 43],
}

pub(crate) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// RULES §2.3–2.7 on one transaction (everything that does not need the registry or history).
fn shape(tx: &Transaction) -> Result<Shape, String> {
    let s = shape_unsigned(tx)?;
    let bundle = tx.issue_bundle().ok_or("no issuance bundle")?;
    let sighash: [u8; 32] = *tx.txid().as_ref();
    bundle
        .ik()
        .verify(&sighash, bundle.authorization().signature().sig())
        .map_err(|_| "issuance signature does not verify over the txid digest")?;
    Ok(s)
}

/// RULES §2.3–2.7 except the issuance signature: what a threshold signer checks before signing.
pub(crate) fn shape_unsigned(tx: &Transaction) -> Result<Shape, String> {
    let bundle = tx.issue_bundle().ok_or("no issuance bundle")?;
    if tx.transparent_bundle().is_some_and(|b| !b.vin.is_empty()) {
        return Err("has transparent inputs".into());
    }
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

/// RULES §2.8: the cited burn exists (finalized), burns this twin's mint, exactly the cited amount,
/// carries one sapling-twin memo, and the issued note goes to the memo's address.
pub(crate) fn check_burn(c: &Citation, s: &Shape, twin: &TwinOf, rpc: &SolanaRpc) -> Result<Burn, String> {
    let sig = c.signature_b58();
    let tx = match rpc.transaction(&sig) {
        Ok(Some(tx)) => tx,
        Ok(None) => return Err(format!("burn {sig} not found (or not finalized) on Solana {}", twin.cluster)),
        Err(e) => return Err(format!("burn {sig}: {e}")),
    };
    let burn = solana::parse_burn(&sig, &tx, Some(&twin.mint)).map_err(|e| format!("burn {sig}: {e}"))?;
    if burn.amount != c.amount {
        return Err(format!("burn {sig} burned {} but the citation says {}", burn.amount, c.amount));
    }
    if burn.orchard_receiver != s.recipient {
        return Err(format!("burn {sig}: the issued note does not go to the memo's address"));
    }
    Ok(burn)
}

/// `skip_solana`: do not fetch burns from Solana (local test vectors; the lines say so).
pub fn audit(root: &Path, network_name: &str, node_override: Option<&str>, skip_solana: bool) -> AuditResult {
    let mut out = AuditResult {
        report: Report::new(),
        network: network_name.to_string(),
        explorer_tx: None,
        node: String::new(),
        scanned: None,
        twins: Vec::new(),
    };
    run(&mut out, root, network_name, node_override, skip_solana);
    out
}

fn run(out: &mut AuditResult, root: &Path, network_name: &str, node_override: Option<&str>, skip_solana: bool) {
    let r = &mut out.report;
    let loaded = (|| -> Result<(IssuersFile, TwinsFile), String> {
        Ok((read_json(&root.join("registry/issuers.json"))?, read_json(&root.join("registry/twins.json"))?))
    })();
    let (issuers, twins_file) = match loaded {
        Ok(x) => x,
        Err(e) => return r.fail(e),
    };
    if issuers.v != 1 || twins_file.v != 1 {
        return r.fail("registry files must be version 1");
    }
    let Some(network) = issuers.networks.get(network_name) else {
        return r.fail(format!("network {network_name} is not in registry/issuers.json"));
    };
    let node = Node::new(node_override.unwrap_or(&network.rpc));
    out.node = node.url().to_string();
    out.explorer_tx = network.explorer_tx.clone();

    // The network, by its genesis hash.
    match node.block_hash(0) {
        Ok(h) if h == network.genesis => r.ok(format!("network {network_name}: genesis {h} matches ({})", node.url())),
        Ok(h) => {
            return r.fail(format!(
                "node {} has genesis {h}, not {network_name}'s {} (a reset, or another network)",
                node.url(),
                network.genesis
            ))
        }
        Err(e) => return r.fail(e),
    }

    // Listed issuers for this network.
    let listed: HashMap<String, &IssuerEntry> = issuers
        .issuers
        .iter()
        .filter(|i| i.network == network_name)
        .map(|i| (i.issuer.to_lowercase(), i))
        .collect();
    if listed.is_empty() {
        return r.fail("no issuer is listed for this network");
    }

    // Twins: metadata, issuer, asset.
    let twins = &mut out.twins;
    for entry in &twins_file.twins {
        let resolved = match (entry.kind.as_str(), &entry.dir, &entry.asset, &entry.issuer) {
            ("burn" | "direct-test", Some(dir), None, None) => twin_with_metadata(root, dir, &listed, network_name)
                .map(|(l, a, w, t)| (l, a, w, Some(t), read_issuer(root, dir))),
            ("undisclosed-test", None, Some(asset), Some(issuer)) => {
                let issuer = issuer.to_lowercase();
                if !listed.contains_key(&issuer) {
                    Err(format!("undisclosed asset {asset}: issuer {issuer} is not listed for {network_name}"))
                } else if asset.len() != 64 || hex::decode(asset).is_err() {
                    Err(format!("undisclosed asset {asset}: not a 32-byte hex asset base"))
                } else {
                    Ok((
                        format!("undisclosed test asset {}", &asset[..16]),
                        asset.to_lowercase(),
                        "listed by asset id only; description not published".to_string(),
                        None,
                        issuer,
                    ))
                }
            }
            (kind, ..) => Err(format!("twins.json: an entry of kind {kind} has the wrong fields")),
        };
        let (label, asset_hex, what, twin_of, issuer) = match resolved {
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
        if entry.kind == "burn" && !skip_solana {
            let cluster = twin_of.as_ref().map(|t| t.cluster.as_str()).unwrap_or("");
            if !network.solana_rpc.contains_key(cluster) {
                r.fail(format!("{label}: no Solana RPC for cluster {cluster} in registry/issuers.json"));
                continue;
            }
        }
        r.ok(format!("{label} ({}): {what}; asset {asset_hex}", entry.kind));
        twins.push(TwinFindings {
            label,
            kind: entry.kind.clone(),
            dir: entry.dir.clone(),
            asset_hex,
            issuer,
            twin_of,
            issuances: Vec::new(),
            burns: Vec::new(),
            node_supply: None,
            node_finalized: None,
            ok: true,
        });
    }
    let by_asset: HashMap<String, usize> = twins.iter().enumerate().map(|(i, t)| (t.asset_hex.clone(), i)).collect();

    // Scan: issuances by listed issuers, and burns of listed twins (by anyone).
    let from = listed.values().map(|i| i.valid_from).min().unwrap_or(1).max(1);
    let tip = match node.block_count() {
        Ok(t) => t,
        Err(e) => return r.fail(e),
    };
    let mut cited: HashSet<[u8; 64]> = HashSet::new();
    let (mut ours, mut others, mut burns_seen) = (0usize, 0usize, 0usize);
    for height in from..=tip {
        if (height - from) % 200 == 0 {
            eprintln!("scanning {height}..{tip}");
        }
        let all = match node.raw_block(height).and_then(|raw| scan::transactions_in_block(&raw)) {
            Ok(all) => all,
            Err(e) => return r.fail(format!("block {height}: {e}")),
        };
        for (_, tx) in all {
            let txid = tx.txid().to_string();
            // ZIP 226 burns (public: asset and amount). Anyone may burn a twin they hold.
            for (asset, amount) in scan::zsa_burns(&tx) {
                if let Some(&ti) = by_asset.get(&hex::encode(asset.to_bytes())) {
                    burns_seen += 1;
                    twins[ti].burns.push(BurnFinding { height, txid: txid.clone(), amount });
                }
            }
            let Some(bundle) = tx.issue_bundle() else { continue };
            let issuer = hex::encode(bundle.ik().encode());
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
                r.fail(format!(
                    "tx {txid} (height {height}): listed issuer issued {} units of an UNKNOWN asset {asset_hex}",
                    s.amount
                ));
                continue;
            };
            let twin = &mut twins[ti];
            let mut solana_burn = None;
            let status = if !in_range {
                Status::Malformed(format!("issued at height {height}, outside the key's validity range"))
            } else if s.finalized {
                Status::Malformed("finalized (twins stay open)".into())
            } else if twin.kind != "burn" {
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
                            Ok(None)
                        } else {
                            let twin_of = twin.twin_of.as_ref().expect("burn twins have metadata");
                            let rpc = SolanaRpc::new(&network.solana_rpc[&twin_of.cluster]);
                            check_burn(&c, &s, twin_of, &rpc).map(Some)
                        };
                        match backed {
                            Err(why) => Status::Unbacked(why),
                            Ok(_) if !cited.insert(c.burn_signature) => Status::Duplicate,
                            Ok(None) => Status::Valid("Solana side not checked".into()),
                            Ok(Some(b)) => {
                                let why = format!(
                                    "burn {} on Solana {}, slot {}, to {}",
                                    b.signature,
                                    twin.twin_of.as_ref().map(|t| t.cluster.as_str()).unwrap_or(""),
                                    b.slot,
                                    b.zcash_address
                                );
                                solana_burn = Some(b);
                                Status::Valid(why)
                            }
                        }
                    }
                }
            };
            twin.issuances.push(IssuanceFinding { height, txid, amount: s.amount, status, solana_burn });
        }
    }
    out.scanned = Some((from, tip));
    r.ok(format!(
        "scanned blocks {from}..={tip}: {ours} issuance(s) by listed issuers, {others} by other keys (ignored), {burns_seen} burn(s) of listed twins"
    ));

    // Per twin.
    for t in twins.iter_mut() {
        let before = r.lines.len();
        let issued: u64 = t.issuances.iter().map(|s| s.amount).sum();
        let valid: u64 = t.issuances.iter().filter(|s| matches!(s.status, Status::Valid(_))).map(|s| s.amount).sum();
        let burned: u64 = t.burns.iter().map(|b| b.amount).sum();
        for s in &t.issuances {
            let line = format!("{}: tx {} (height {}) {} units", t.label, s.txid, s.height, s.amount);
            match &s.status {
                Status::Valid(why) => r.ok(format!("{line}: valid ({why})")),
                Status::Unbacked(why) => r.fail(format!("{line}: UNBACKED ({why})")),
                Status::Duplicate => r.fail(format!("{line}: DUPLICATE (cites a burn already answered)")),
                Status::Malformed(why) => r.fail(format!("{line}: MALFORMED ({why})")),
            }
        }
        for b in &t.burns {
            r.ok(format!("{}: burned on Zcash in tx {} (height {}): {} units", t.label, b.txid, b.height, b.amount));
        }
        if burned > valid {
            r.fail(format!(
                "{}: {burned} units burned on Zcash but only {valid} validly issued (burns cannot make other units valid)",
                t.label
            ));
        }
        match node.asset_state(&t.asset_hex) {
            Ok(Some(st)) => {
                t.node_supply = Some(st.amount);
                t.node_finalized = Some(st.is_finalized);
                r.expect(
                    issued.checked_sub(burned) == Some(st.amount),
                    format!("{}: node supply {} = issued {issued} - burned {burned}, all found by the scan", t.label, st.amount),
                    format!("{}: node supply {} but the scan found issued {issued} - burned {burned} (scan incomplete?)", t.label, st.amount),
                );
                r.expect(
                    valid.checked_sub(burned) == Some(st.amount),
                    format!("{}: supply {} is valid issuances {valid} - burned {burned}", t.label, st.amount),
                    format!("{}: supply {} but valid issuances {valid} - burned {burned} differ", t.label, st.amount),
                );
                r.expect(!st.is_finalized, format!("{}: not finalized", t.label), format!("{}: FINALIZED", t.label));
            }
            Ok(None) if t.issuances.is_empty() => r.ok(format!("{}: not issued yet", t.label)),
            Ok(None) => r.fail(format!("{}: the scan found issuances but the node has no record", t.label)),
            Err(e) => r.fail(format!("{}: {e}", t.label)),
        }
        t.ok = r.lines[before..].iter().all(|(ok, _)| *ok);
    }
}

fn read_issuer(root: &Path, dir: &str) -> String {
    fs::read_to_string(root.join(dir).join("issuer.txt")).map(|s| s.trim().to_lowercase()).unwrap_or_default()
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
