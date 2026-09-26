//! Threshold signers for the issuer key: distributed key generation between separate processes, and
//! a signer server that checks every issuance on its own before contributing a signature share.
//!
//! Key generation (`zsa signer dkg`): each participant runs the three FROST DKG rounds as its own
//! process, exchanging packages through a directory. Each ends with only its own key share. The
//! round-2 packages are secret to their recipient: here they are files on one machine; in a real
//! deployment they travel over authenticated, confidential channels between separate machines.
//!
//! Signing (`zsa signer serve`): the issuer service (the coordinator) sends the complete issuance
//! transaction, with its issuance signature left empty. Before committing to a signing session the
//! signer checks, independently of the coordinator:
//! - the issuer is this group's key, and the transaction has the shape of a twin issuance (RULES §2);
//! - the asset is a listed burn twin of this issuer;
//! - the cited burn checks out on Solana (mint, amount, memo, recipient: RULES §2.8);
//! - no issuance by this issuer on chain already cites that burn.
//!
//! It then signs only the sighash it recomputed from the transaction (with no transparent inputs,
//! the txid digest). Nonces are used once and dropped.
//!
//! Wire format: one JSON object per line over TCP, one request per connection.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use crate::audit::{self, IssuerEntry, IssuersFile, TwinsFile};
use crate::frost::{self, Identifier, KeyPackage, PublicKeyPackage, SigningNonces};
use crate::metadata::TwinOf;
use crate::rpc::Node;
use crate::scan::{self, Citation};
use crate::solana::SolanaRpc;

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn wait_for(paths: &[PathBuf], timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    while !paths.iter().all(|p| p.exists()) {
        if start.elapsed() > timeout {
            let missing: Vec<_> = paths.iter().filter(|p| !p.exists()).map(|p| p.display().to_string()).collect();
            return Err(format!("timed out waiting for {missing:?}"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    std::thread::sleep(Duration::from_millis(200)); // let a writer finish
    Ok(())
}

/// One participant's part of the distributed key generation.
pub fn dkg(id: u16, n: u16, t: u16, exchange: &Path, share_out: &Path, group_out: &Path) -> Result<String, String> {
    let me = frost::identifier(id)?;
    let r1_dir = exchange.join("round1");
    let r2_dir = exchange.join("round2");
    fs::create_dir_all(&r1_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&r2_dir).map_err(|e| e.to_string())?;

    let (r1_secret, r1_pkg) = frost::dkg::part1(me, n, t)?;
    fs::write(r1_dir.join(id.to_string()), r1_pkg.serialize().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let others: Vec<u16> = (1..=n).filter(|j| *j != id).collect();
    wait_for(&others.iter().map(|j| r1_dir.join(j.to_string())).collect::<Vec<_>>(), Duration::from_secs(300))?;
    let mut r1 = BTreeMap::new();
    for j in &others {
        let bytes = fs::read(r1_dir.join(j.to_string())).map_err(|e| e.to_string())?;
        r1.insert(frost::identifier(*j)?, frost::dkg::Round1Package::deserialize(&bytes).map_err(|e| e.to_string())?);
    }

    let (r2_secret, outgoing) = frost::dkg::part2(r1_secret, &r1)?;
    for j in &others {
        let pkg = &outgoing[&frost::identifier(*j)?];
        write_private(&r2_dir.join(format!("{id}-to-{j}")), &pkg.serialize().map_err(|e| e.to_string())?)?;
    }
    wait_for(&others.iter().map(|j| r2_dir.join(format!("{j}-to-{id}"))).collect::<Vec<_>>(), Duration::from_secs(300))?;
    let mut for_me = BTreeMap::new();
    for j in &others {
        let bytes = fs::read(r2_dir.join(format!("{j}-to-{id}"))).map_err(|e| e.to_string())?;
        for_me.insert(frost::identifier(*j)?, frost::dkg::Round2Package::deserialize(&bytes).map_err(|e| e.to_string())?);
    }

    let (key, pkp) = frost::dkg::part3(&r2_secret, &r1, &for_me)?;
    write_private(share_out, &key.serialize().map_err(|e| e.to_string())?)?;
    fs::write(group_out, pkp.serialize().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let issuer = crate::threshold::issuer_from_xonly(&frost::group_xonly(&pkp)?)?;
    Ok(hex::encode(issuer.encode()))
}

pub fn read_group(path: &Path) -> Result<PublicKeyPackage, String> {
    PublicKeyPackage::deserialize(&fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?).map_err(|e| e.to_string())
}

fn read_share(path: &Path) -> Result<KeyPackage, String> {
    KeyPackage::deserialize(&fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?).map_err(|e| e.to_string())
}

/// What a signer knows: its share, the group, the registry's burn twins of this issuer, the chain.
struct Signer {
    key: KeyPackage,
    issuer: String,
    node: Node,
    twins: HashMap<String, (String, TwinOf, SolanaRpc)>,
    valid_from: u64,
    scanned_to: u64,
    answered: HashSet<String>,
    sessions: HashMap<String, (Instant, [u8; 32], SigningNonces)>,
}

impl Signer {
    fn refresh_answered(&mut self) -> Result<(), String> {
        let tip = self.node.block_count()?;
        let from = self.scanned_to.max(self.valid_from.saturating_sub(1)) + 1;
        for height in from..=tip {
            for (_, tx) in scan::issuances_in_block(&self.node.raw_block(height)?)? {
                if hex::encode(tx.issue_bundle().expect("filtered").ik().encode()) != self.issuer {
                    continue;
                }
                for c in scan::null_data_outputs(&tx).into_iter().flatten().filter_map(|d| Citation::decode(&d)) {
                    self.answered.insert(c.signature_b58());
                }
            }
            self.scanned_to = height;
        }
        Ok(())
    }

    /// The independent checks, then the sighash to sign.
    fn check(&mut self, tx_hex: &str) -> Result<([u8; 32], String), String> {
        let bytes = hex::decode(tx_hex).map_err(|_| "tx is not hex")?;
        let tx = Transaction::read(bytes.as_slice(), BranchId::Nu6).map_err(|e| format!("tx does not parse: {e}"))?;
        let bundle = tx.issue_bundle().ok_or("no issuance bundle")?;
        if hex::encode(bundle.ik().encode()) != self.issuer {
            return Err("the issuer is not this group's key".into());
        }
        let s = audit::shape_unsigned(&tx)?;
        if s.finalized {
            return Err("finalized".into());
        }
        let asset_hex = hex::encode(s.asset.to_bytes());
        let (label, twin_of, rpc) = self.twins.get(&asset_hex).ok_or("not a listed burn twin of this issuer")?;
        let c = s.citation.ok_or("no burn citation")?;
        if c.amount != s.amount {
            return Err(format!("citation amount {} but {} issued", c.amount, s.amount));
        }
        let burn = audit::check_burn(&c, &s, twin_of, rpc)?;
        let label = label.clone();
        self.refresh_answered()?;
        if self.answered.contains(&burn.signature) {
            return Err(format!("burn {} is already answered on chain", burn.signature));
        }
        Ok((*tx.txid().as_ref(), format!("{label}: burn {} of {} units to {}", burn.signature, burn.amount, burn.zcash_address)))
    }

    fn handle(&mut self, req: &Value) -> Value {
        self.sessions.retain(|_, (t, _, _)| t.elapsed() < Duration::from_secs(300));
        let session = req.get("session").and_then(Value::as_str).unwrap_or("").to_string();
        match req.get("op").and_then(Value::as_str) {
            Some("commit") => {
                let tx = req.get("tx").and_then(Value::as_str).unwrap_or("");
                match self.check(tx) {
                    Ok((sighash, what)) => {
                        let (nonces, commitments) = frost::commit(&self.key);
                        self.sessions.insert(session.clone(), (Instant::now(), sighash, nonces));
                        eprintln!("signer {:?}: agreed to sign session {session}: {what}", self.key.identifier());
                        match commitments.serialize() {
                            Ok(c) => json!({"ok": true, "id": hex::encode(self.key.identifier().serialize()), "commitments": hex::encode(c)}),
                            Err(e) => json!({"ok": false, "error": e.to_string()}),
                        }
                    }
                    Err(e) => {
                        eprintln!("signer {:?}: REFUSED session {session}: {e}", self.key.identifier());
                        json!({"ok": false, "error": e})
                    }
                }
            }
            Some("sign") => {
                let Some((_, sighash, nonces)) = self.sessions.remove(&session) else {
                    return json!({"ok": false, "error": "unknown or expired session"});
                };
                let package = match req
                    .get("package")
                    .and_then(Value::as_str)
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| frost::SigningPackage::deserialize(&b).ok())
                {
                    Some(p) => p,
                    None => return json!({"ok": false, "error": "bad signing package"}),
                };
                if package.message() != &sighash[..] {
                    return json!({"ok": false, "error": "the signing package's message is not the checked transaction's sighash"});
                }
                match frost::sign_share(&package, &nonces, &self.key, false).and_then(|s| Ok(hex::encode(s.serialize()))) {
                    Ok(share) => {
                        eprintln!("signer {:?}: signed session {session}", self.key.identifier());
                        json!({"ok": true, "share": share})
                    }
                    Err(e) => json!({"ok": false, "error": e}),
                }
            }
            _ => json!({"ok": false, "error": "unknown op"}),
        }
    }
}

pub struct ServeOptions {
    pub share: PathBuf,
    pub group: PathBuf,
    pub listen: String,
    pub root: PathBuf,
    pub network: String,
    pub node: Option<String>,
}

pub fn serve(o: &ServeOptions) -> Result<(), String> {
    let key = read_share(&o.share)?;
    let pkp = read_group(&o.group)?;
    if key.verifying_key() != pkp.verifying_key() {
        return Err("the share does not belong to this group".into());
    }
    let issuer = hex::encode(crate::threshold::issuer_from_xonly(&frost::group_xonly(&pkp)?)?.encode());
    let issuers: IssuersFile = audit::read_json(&o.root.join("registry/issuers.json"))?;
    let twins_file: TwinsFile = audit::read_json(&o.root.join("registry/twins.json"))?;
    let network = issuers.networks.get(&o.network).ok_or("network not in the registry")?;
    let node = Node::new(o.node.as_deref().unwrap_or(&network.rpc));
    if node.block_hash(0)? != network.genesis {
        return Err("the node is not on this network (genesis differs)".into());
    }
    let listed: HashMap<String, &IssuerEntry> =
        issuers.issuers.iter().filter(|i| i.network == o.network).map(|i| (i.issuer.to_lowercase(), i)).collect();
    let entry = listed.get(&issuer).ok_or_else(|| format!("this group's issuer {issuer} is not listed"))?;
    let mut twins = HashMap::new();
    for t in twins_file.twins.iter().filter(|t| t.kind == "burn") {
        let dir = t.dir.as_deref().ok_or("burn twin without dir")?;
        let (label, asset, _, twin_of) = audit::twin_with_metadata(&o.root, dir, &listed, &o.network)?;
        let twin_issuer = fs::read_to_string(o.root.join(dir).join("issuer.txt")).map_err(|e| e.to_string())?;
        if twin_issuer.trim().to_lowercase() != issuer {
            continue;
        }
        let url = network.solana_rpc.get(&twin_of.cluster).ok_or("no Solana RPC for the twin's cluster")?;
        twins.insert(asset, (label, twin_of, SolanaRpc::new(url)));
    }
    let mut signer = Signer {
        key,
        issuer: issuer.clone(),
        node,
        twins,
        valid_from: entry.valid_from,
        scanned_to: 0,
        answered: HashSet::new(),
        sessions: HashMap::new(),
    };
    let listener = TcpListener::bind(&o.listen).map_err(|e| format!("{}: {e}", o.listen))?;
    eprintln!(
        "signer {:?} of group {issuer} listening on {} ({} burn twin(s))",
        signer.key.identifier(),
        o.listen,
        signer.twins.len()
    );
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line).is_err() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(req) => signer.handle(&req),
            Err(e) => json!({"ok": false, "error": format!("bad request: {e}")}),
        };
        let _ = writeln!(stream, "{resp}");
    }
    Ok(())
}

fn call(addr: &str, req: &Value, timeout: Duration) -> Result<Value, String> {
    let sock = addr.parse().map_err(|e| format!("{addr}: {e}"))?;
    let mut s = TcpStream::connect_timeout(&sock, Duration::from_secs(3)).map_err(|e| format!("{addr}: {e}"))?;
    s.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    writeln!(s, "{req}").map_err(|e| format!("{addr}: {e}"))?;
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).map_err(|e| format!("{addr}: {e}"))?;
    serde_json::from_str(&line).map_err(|e| format!("{addr}: bad response: {e}"))
}

/// The coordinator's side: ask every signer, use the first `t` that agree, aggregate.
/// Returns the 64-byte signature, or an error saying why no signature could be made.
pub fn request_signature(
    signers: &[String],
    pkp: &PublicKeyPackage,
    t: usize,
    tx_hex: &str,
    sighash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let session = hex::encode(rand::random::<[u8; 16]>());
    let mut agreed: Vec<(String, Identifier, frost::SigningCommitments)> = Vec::new();
    let mut refusals = Vec::new();
    for addr in signers {
        let resp = call(addr, &json!({"op": "commit", "session": session, "tx": tx_hex}), Duration::from_secs(120));
        match resp {
            Ok(v) if v.get("ok") == Some(&json!(true)) => {
                let id = v.get("id").and_then(Value::as_str).and_then(|h| hex::decode(h).ok()).and_then(|b| Identifier::deserialize(&b).ok());
                let c = v
                    .get("commitments")
                    .and_then(Value::as_str)
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| frost::SigningCommitments::deserialize(&b).ok());
                match (id, c) {
                    (Some(id), Some(c)) => agreed.push((addr.clone(), id, c)),
                    _ => refusals.push(format!("{addr}: malformed response")),
                }
            }
            Ok(v) => refusals.push(format!("{addr}: refused: {}", v.get("error").and_then(Value::as_str).unwrap_or("?"))),
            Err(e) => refusals.push(format!("{addr}: unreachable ({e})")),
        }
    }
    if agreed.len() < t {
        return Err(format!(
            "only {} of {} signers agreed to sign; {t} needed; nothing issued [{}]",
            agreed.len(),
            signers.len(),
            refusals.join("; ")
        ));
    }
    agreed.truncate(t);
    let commitments: BTreeMap<_, _> = agreed.iter().map(|(_, id, c)| (*id, c.clone())).collect();
    let package = frost::signing_package(commitments, sighash);
    let package_hex = hex::encode(package.serialize().map_err(|e| e.to_string())?);
    let mut shares = BTreeMap::new();
    for (addr, id, _) in &agreed {
        let v = call(addr, &json!({"op": "sign", "session": session, "package": package_hex}), Duration::from_secs(60))?;
        let share = v
            .get("share")
            .and_then(Value::as_str)
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| frost::SignatureShare::deserialize(&b).ok())
            .ok_or_else(|| format!("{addr}: no signature share ({})", v.get("error").and_then(Value::as_str).unwrap_or("?")))?;
        shares.insert(*id, share);
    }
    frost::aggregate(&package, &shares, pkp, false)
}
