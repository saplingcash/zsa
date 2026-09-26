//! `local-vectors`: issue deliberately bad twin issuances on a LOCAL ZSA node, run `audit` on a
//! throwaway registry, and check that every case gets exactly the verdict docs/RULES.md predicts.
//!
//! Refuses any node that is not on localhost: these issuances must never reach a shared network.
//! Keys are generated in memory and discarded; the registry lives in a temporary directory.

use std::fs;
use std::path::{Path, PathBuf};

use bip0039::{Count, Mnemonic};

use crate::issue::{self, BuildOptions};
use crate::rpc::Node;
use crate::scan::Citation;
use crate::{audit, keys, metadata};

struct Coin {
    dir: String,
    envelope: String,
}

/// Write a local twin's metadata (localnet cluster, a made-up mint) under `root/assets/<slug>`.
fn coin(root: &Path, slug: &str, n: u8, issuer: &str) -> Result<Coin, String> {
    let spec = metadata::CoinSpec {
        name: format!("Local {slug} (no value)"),
        cluster: "localnet".into(),
        mint: metadata::base58_encode(&[n; 32]),
        decimals: 6,
        note: "Local test vector. No value.".into(),
    };
    let bundle = spec.bundle().map_err(|p| p.join("; "))?;
    let envelope = metadata::envelope_for(&bundle)?;
    let dir = format!("assets/{slug}");
    let abs = root.join(&dir);
    fs::create_dir_all(&abs).map_err(|e| e.to_string())?;
    fs::write(abs.join("bundle.json"), metadata::bundle_bytes(&bundle)).map_err(|e| e.to_string())?;
    fs::write(abs.join("envelope.txt"), &envelope).map_err(|e| e.to_string())?;
    fs::write(abs.join("issuer.txt"), issuer).map_err(|e| e.to_string())?;
    Ok(Coin { dir, envelope })
}

fn new_phrase() -> String {
    Mnemonic::<bip0039::English>::generate(Count::Words24).phrase().to_string()
}

fn sig(n: u8) -> String {
    metadata::base58_encode(&[n; 64])
}

struct Case {
    name: &'static str,
    txid: String,
    height: u32,
    /// Substring the audit line for this transaction must contain; `None`: no line may mention it.
    expect: Option<&'static str>,
}

pub fn run(node_url: &str) -> Result<bool, String> {
    let local = ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"];
    if !local.iter().any(|p| node_url.starts_with(p)) {
        return Err(format!("refusing {node_url}: local-vectors only runs against a node on localhost"));
    }
    let node = Node::new(node_url);
    if node.block_count()? == 0 {
        issue::empty_block(node_url)?;
    }

    let root: PathBuf = std::env::temp_dir().join(format!("zsa-vectors-{:016x}", rand::random::<u64>()));
    let result = run_in(&root, node_url, &node);
    let _ = fs::remove_dir_all(&root);
    result
}

fn run_in(root: &Path, node_url: &str, node: &Node) -> Result<bool, String> {
    let k1 = new_phrase();
    let k2 = new_phrase();
    let issuer1 = keys::issuer_hex(&keys::issuance_key(&k1)?);
    let recipient = issue::test_address(&k1, 1)?;

    let burn = coin(root, "burn-twin", 1, &issuer1)?;
    let test = coin(root, "test-twin", 2, &issuer1)?;
    let unlisted = coin(root, "unlisted", 3, &issuer1)?;
    let forged = coin(root, "forged", 4, &issuer1)?;
    // Change one byte of the forged coin's bundle after its envelope was sealed.
    let forged_bundle = root.join(&forged.dir).join("bundle.json");
    let text = fs::read_to_string(&forged_bundle).map_err(|e| e.to_string())?;
    fs::write(&forged_bundle, text.replacen("No value.", "No value!", 1)).map_err(|e| e.to_string())?;

    let other_coin = coin(root, "other-key", 5, &keys::issuer_hex(&keys::issuance_key(&k2)?))?;

    let mut cases: Vec<Case> = Vec::new();
    let go = |cases: &mut Vec<Case>,
              name: &'static str,
                  phrase: &str,
                  envelope: &str,
                  amount: u64,
                  opts: BuildOptions,
                  expect: Option<&'static str>|
     -> Result<(), String> {
        let (tx, _, _) = issue::build(phrase, envelope, amount, recipient, &opts, node)?;
        let txid = tx.txid().to_string();
        let height = issue::submit(node_url, tx)?;
        eprintln!("issued {name}: {txid} at height {height}");
        cases.push(Case { name, txid, height, expect });
        Ok(())
    };
    let cite = |n: u8, amount: u64| Citation::for_burn(&sig(n), amount);

    go(&mut cases, "valid burn issuance", &k1, &burn.envelope, 100,
       BuildOptions { citation: Some(cite(1, 100)?), ..Default::default() }, Some(": valid (Solana side not checked)"))?;
    go(&mut cases, "same burn cited again", &k1, &burn.envelope, 100,
       BuildOptions { citation: Some(cite(1, 100)?), ..Default::default() }, Some("DUPLICATE"))?;
    go(&mut cases, "burn twin without a citation", &k1, &burn.envelope, 7,
       BuildOptions::default(), Some("UNBACKED (no burn citation)"))?;
    go(&mut cases, "citation amount differs", &k1, &burn.envelope, 60,
       BuildOptions { citation: Some(cite(2, 50)?), allow_citation_mismatch: true, ..Default::default() },
       Some("UNBACKED (citation amount 50 but 60 issued)"))?;
    go(&mut cases, "test twin with a citation", &k1, &test.envelope, 5,
       BuildOptions { citation: Some(cite(3, 5)?), ..Default::default() },
       Some("MALFORMED (a test twin carries a burn citation)"))?;
    go(&mut cases, "asset not in the registry", &k1, &unlisted.envelope, 9, BuildOptions::default(), Some("UNKNOWN asset"))?;
    go(&mut cases, "issuance by a key that is not listed", &k2, &other_coin.envelope, 11, BuildOptions::default(), None)?;
    go(&mut cases, "finalized", &k1, &test.envelope, 3,
       BuildOptions { finalize: true, ..Default::default() }, Some("MALFORMED (finalized"))?;
    let last_in_range = cases.last().map(|c| c.height).unwrap_or(1);
    go(&mut cases, "after the key's range closed", &k1, &burn.envelope, 4,
       BuildOptions { citation: Some(cite(4, 4)?), ..Default::default() }, Some("outside the key's validity range"))?;

    // The registry, written after the fact: issuer 1 valid up to `last_in_range`.
    let genesis = node.block_hash(0)?;
    let reg = root.join("registry");
    fs::create_dir_all(&reg).map_err(|e| e.to_string())?;
    let issuers = serde_json::json!({
        "v": 1,
        "networks": { "local": { "description": "local ZSA node (test vectors)", "rpc": node_url, "genesis": genesis } },
        "issuers": [ { "issuer": issuer1, "network": "local", "valid_from": 1, "valid_until": last_in_range, "note": "vector key" } ]
    });
    let twins = serde_json::json!({
        "v": 1,
        "twins": [
            { "kind": "burn", "dir": burn.dir, "note": "vector" },
            { "kind": "direct-test", "dir": test.dir, "note": "vector" },
            { "kind": "direct-test", "dir": forged.dir, "note": "vector" }
        ]
    });
    fs::write(reg.join("issuers.json"), serde_json::to_vec_pretty(&issuers).unwrap()).map_err(|e| e.to_string())?;
    fs::write(reg.join("twins.json"), serde_json::to_vec_pretty(&twins).unwrap()).map_err(|e| e.to_string())?;

    let report = audit::audit(root, "local", None, true).report;
    println!("--- audit of the local vectors ---");
    for (ok, line) in &report.lines {
        println!("{} {line}", if *ok { "OK  " } else { "FAIL" });
    }
    println!("--- expectations ---");

    let mut all_met = true;
    let mut check = |met: bool, what: String| {
        all_met &= met;
        println!("{} {what}", if met { "MET   " } else { "NOT MET" });
    };
    for c in &cases {
        let lines: Vec<&(bool, String)> = report.lines.iter().filter(|(_, l)| l.contains(&c.txid)).collect();
        match c.expect {
            Some(want) => check(
                lines.len() == 1 && lines[0].1.contains(want) && lines[0].0 == want.starts_with(": valid"),
                format!("{} (height {}): \"{want}\"", c.name, c.height),
            ),
            None => check(lines.is_empty(), format!("{} (height {}): ignored", c.name, c.height)),
        }
    }
    let has = |ok: bool, needle: &str| report.lines.iter().any(|(o, l)| *o == ok && l.contains(needle));
    check(has(false, &format!("{}: metadata: bundle bytes do not hash", forged.dir)), "forged metadata is refused".into());
    check(has(false, &format!("{}: supply 271 but valid issuances 100 - burned 0 differ", burn.dir)), "burn twin: supply 271, only 100 valid".into());
    check(has(false, &format!("{}: FINALIZED", test.dir)), "test twin: finalized is a failure".into());
    check(has(true, "1 by other keys"), "the unlisted key's issuance is counted as someone else's".into());
    check(!report.passed(), "audit result is FAIL".into());

    // Every FAIL line must be one of the expected ones.
    let known: Vec<&str> = cases.iter().map(|c| c.txid.as_str()).collect();
    let unexpected: Vec<&String> = report
        .lines
        .iter()
        .filter(|(ok, l)| {
            !ok && !known.iter().any(|t| l.contains(t))
                && !l.starts_with(&format!("{}: metadata", forged.dir))
                && !l.contains("valid issuances 100 - burned 0 differ")
                && !l.contains(&format!("{}: supply 8 but valid issuances 0 - burned 0 differ", test.dir))
                && !l.contains(&format!("{}: FINALIZED", test.dir))
        })
        .map(|(_, l)| l)
        .collect();
    check(unexpected.is_empty(), format!("no unexpected failures {unexpected:?}"));

    println!("{}", if all_met { "VECTORS: ALL MET" } else { "VECTORS: NOT ALL MET" });
    Ok(all_met)
}
