//! `pages`: a static HTML page per twin, plus an index, generated from an audit run.
//!
//! Every page shows: the asset, its supply, every issuance with the Solana burn behind it, every
//! burn on Zcash, the audit result, the published metadata, the trust model, and that this runs
//! on test networks and has no value. The pages are self-contained (no scripts, no external requests).

use std::fs;
use std::path::Path;

use crate::audit::{AuditResult, Status, TwinFindings};

const CSS: &str = r#"
:root { --bg:#fbfbf8; --fg:#1d1f23; --muted:#5f6670; --line:#dcdcd4; --ok:#1f7a45; --bad:#b3261e; --warn-bg:#fff3cd; --warn-fg:#5c4400; --code:#f1f1ec; }
@media (prefers-color-scheme: dark) { :root { --bg:#16181c; --fg:#e6e6e1; --muted:#9aa1ab; --line:#30343b; --ok:#5fc48a; --bad:#ff8a80; --warn-bg:#3a2f0b; --warn-fg:#ffe08a; --code:#1f2228; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width:1100px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:1.6rem; margin:.2em 0 .1em; } h2 { font-size:1.15rem; margin:2em 0 .6em; border-bottom:1px solid var(--line); padding-bottom:.3em; }
.banner { background:var(--warn-bg); color:var(--warn-fg); padding:10px 14px; border-radius:6px; font-weight:600; }
.muted { color:var(--muted); }
.ok { color:var(--ok); font-weight:700; } .bad { color:var(--bad); font-weight:700; }
code, .hash { font-family:ui-monospace, "DejaVu Sans Mono", Menlo, Consolas, monospace; font-size:.86em; word-break:break-all; }
pre { background:var(--code); padding:12px; border-radius:6px; overflow-x:auto; white-space:pre-wrap; word-break:break-all; font-size:.84em; }
table { width:100%; border-collapse:collapse; font-size:.92em; } th, td { text-align:left; vertical-align:top; padding:6px 8px; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:600; } dl { display:grid; grid-template-columns:max-content 1fr; gap:4px 16px; } dt { color:var(--muted); } dd { margin:0; }
a { color:inherit; } ul { padding-left:1.2em; }
"#;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn units(amount: u64, decimals: Option<u8>) -> String {
    match decimals {
        Some(d) if d > 0 => {
            let p = 10u64.pow(d as u32);
            let frac = format!("{:0width$}", amount % p, width = d as usize);
            let frac = frac.trim_end_matches('0');
            if frac.is_empty() { format!("{}", amount / p) } else { format!("{}.{frac}", amount / p) }
        }
        _ => amount.to_string(),
    }
}

fn tx_link(txid: &str, explorer: Option<&str>) -> String {
    match explorer {
        Some(t) => format!("<a class=\"hash\" href=\"{}\">{}</a>", esc(&t.replace("{txid}", txid)), esc(txid)),
        None => format!("<span class=\"hash\">{}</span>", esc(txid)),
    }
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>{}</title>\n<style>{CSS}</style></head>\n<body><main>\n{body}\n</main></body></html>\n",
        esc(title)
    )
}

const BANNER: &str = "<p class=\"banner\">Test networks only (Solana devnet and QEDIT's ZSA test network). No value. Never pay for it.</p>";

const TRUST: &str = "<h2>Trust model</h2>\n<ul>\n\
<li><strong>The issuer is trusted.</strong> It holds the issuance key, so it could issue without a burn, or refuse to issue.</li>\n\
<li><strong>Anyone can check.</strong> <code>zsa audit</code> recomputes everything on this page from the two chains and the published metadata, with no key and no account.</li>\n\
<li><strong>Issuance is public</strong> (ZIP 227): the first recipient address and the amount are visible on Zcash. Once the holder sends the twin on to a fresh address, the asset, the amount and the parties are shielded.</li>\n\
<li><strong>Burns on Zcash are public</strong> (ZIP 226): the asset and the amount, not who burned.</li>\n\
<li><strong>One-way.</strong> Burning a twin on Zcash releases nothing on Solana.</li>\n</ul>";

fn status_cell(s: &Status) -> String {
    match s {
        Status::Valid(_) => "<span class=\"ok\">valid</span>".into(),
        Status::Unbacked(why) => format!("<span class=\"bad\">unbacked</span><br><span class=\"muted\">{}</span>", esc(why)),
        Status::Duplicate => "<span class=\"bad\">duplicate</span>".into(),
        Status::Malformed(why) => format!("<span class=\"bad\">malformed</span><br><span class=\"muted\">{}</span>", esc(why)),
    }
}

fn file_name(t: &TwinFindings) -> String {
    match &t.dir {
        Some(d) => format!("{}.html", d.rsplit('/').next().unwrap_or(d)),
        None => format!("asset-{}.html", &t.asset_hex[..16]),
    }
}

fn twin_page(root: &Path, t: &TwinFindings, a: &AuditResult) -> String {
    let explorer = a.explorer_tx.as_deref();
    let (envelope, bundle) = match &t.dir {
        Some(d) => (
            fs::read_to_string(root.join(d).join("envelope.txt")).unwrap_or_default(),
            fs::read_to_string(root.join(d).join("bundle.json")).unwrap_or_default(),
        ),
        None => (String::new(), String::new()),
    };
    let name = serde_json::from_str::<serde_json::Value>(&bundle)
        .ok()
        .and_then(|b| b.get("name").and_then(|n| n.as_str()).map(String::from))
        .unwrap_or_else(|| t.label.clone());
    let decimals = t.twin_of.as_ref().map(|o| o.decimals);
    let issued: u64 = t.issuances.iter().map(|i| i.amount).sum();
    let burned: u64 = t.burns.iter().map(|b| b.amount).sum();

    let mut b = String::new();
    b.push_str(BANNER);
    b.push_str(&format!("\n<h1>{}</h1>\n<p class=\"muted\">OrchardZSA twin ({} kind) of a coin on Sapling (sapling.cash)</p>\n", esc(&name), esc(&t.kind)));
    b.push_str(&format!(
        "<p>Audit: {} <span class=\"muted\">(network {}, blocks {}, generated by <code>zsa pages</code>)</span></p>\n",
        if t.ok { "<span class=\"ok\">OK</span>" } else { "<span class=\"bad\">FAIL</span>" },
        esc(&a.network),
        a.scanned.map(|(f, to)| format!("{f}..={to}")).unwrap_or_default()
    ));

    b.push_str("<h2>Asset</h2>\n<dl>\n");
    b.push_str(&format!("<dt>Asset base</dt><dd class=\"hash\">{}</dd>\n", esc(&t.asset_hex)));
    b.push_str(&format!("<dt>Issuer</dt><dd class=\"hash\">{}</dd>\n", esc(&t.issuer)));
    if let Some(o) = &t.twin_of {
        let mint = format!("https://explorer.solana.com/address/{}?cluster={}", o.mint, o.cluster);
        b.push_str(&format!(
            "<dt>Solana coin</dt><dd><a class=\"hash\" href=\"{}\">{}</a> <span class=\"muted\">({}, {} decimals)</span></dd>\n",
            esc(&mint), esc(&o.mint), esc(&o.cluster), o.decimals
        ));
    }
    b.push_str("</dl>\n");

    b.push_str("<h2>Supply</h2>\n<dl>\n");
    b.push_str(&format!("<dt>Issued</dt><dd>{} <span class=\"muted\">({issued} base units)</span></dd>\n", units(issued, decimals)));
    b.push_str(&format!("<dt>Burned on Zcash</dt><dd>{} <span class=\"muted\">({burned} base units)</span></dd>\n", units(burned, decimals)));
    match t.node_supply {
        Some(s) => b.push_str(&format!(
            "<dt>Supply (node record)</dt><dd>{} <span class=\"muted\">({s} base units; finalized: {})</span></dd>\n",
            units(s, decimals),
            t.node_finalized.unwrap_or(false)
        )),
        None => b.push_str("<dt>Supply (node record)</dt><dd class=\"muted\">none</dd>\n"),
    }
    b.push_str("</dl>\n");

    b.push_str("<h2>Issuances</h2>\n");
    if t.issuances.is_empty() {
        b.push_str("<p class=\"muted\">None yet.</p>\n");
    } else {
        b.push_str("<table><tr><th>Height</th><th>Zcash transaction</th><th>Amount</th><th>Status</th><th>Backed by</th></tr>\n");
        for i in &t.issuances {
            let backed = match (&i.solana_burn, &i.status) {
                (Some(burn), _) => {
                    let cluster = t.twin_of.as_ref().map(|o| o.cluster.as_str()).unwrap_or("devnet");
                    format!(
                        "burn <a class=\"hash\" href=\"https://explorer.solana.com/tx/{s}?cluster={c}\">{s}</a> <span class=\"muted\">(Solana {c}, slot {slot})</span><br>to <span class=\"hash\">{to}</span>",
                        s = esc(&burn.signature), c = esc(cluster), slot = burn.slot, to = esc(&burn.zcash_address)
                    )
                }
                (None, Status::Valid(why)) => esc(why),
                _ => String::new(),
            };
            b.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{backed}</td></tr>\n",
                i.height,
                tx_link(&i.txid, explorer),
                units(i.amount, decimals),
                status_cell(&i.status)
            ));
        }
        b.push_str("</table>\n");
    }

    b.push_str("<h2>Burns on Zcash (ZIP 226)</h2>\n");
    if t.burns.is_empty() {
        b.push_str("<p class=\"muted\">None.</p>\n");
    } else {
        b.push_str("<table><tr><th>Height</th><th>Zcash transaction</th><th>Amount</th></tr>\n");
        for x in &t.burns {
            b.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n", x.height, tx_link(&x.txid, explorer), units(x.amount, decimals)));
        }
        b.push_str("</table>\n");
    }

    b.push_str("<h2>Published metadata (Cachet v1)</h2>\n");
    if t.dir.is_some() {
        b.push_str("<p class=\"muted\">The envelope is the ZIP 227 asset description; its hash is part of the asset id. The bundle's SHA-256 is in the envelope.</p>\n");
        b.push_str(&format!("<p>Envelope (exact bytes)</p><pre>{}</pre>\n", esc(&envelope)));
        b.push_str(&format!("<p>Bundle (exact bytes, wrapped for reading)</p><pre>{}</pre>\n", esc(&bundle)));
    } else {
        b.push_str("<p class=\"muted\">Listed by asset id only: a test asset issued while testing the tools. Its description is not published.</p>\n");
    }

    b.push_str(TRUST);
    b.push_str("\n<h2>Check it yourself</h2>\n<pre>git clone https://github.com/saplingcash/zsa &amp;&amp; cd zsa\nsh scripts/cargo-wsl.sh build --release --locked\n$HOME/zsa/target/release/zsa audit</pre>\n");
    b.push_str("<p class=\"muted\"><a href=\"index.html\">All twins</a> · https://github.com/saplingcash/zsa · Apache-2.0</p>");
    page(&name, &b)
}

pub fn write(root: &Path, a: &AuditResult, out: &Path) -> Result<Vec<String>, String> {
    fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut written = Vec::new();
    let mut rows = String::new();
    for t in &a.twins {
        let file = file_name(t);
        fs::write(out.join(&file), twin_page(root, t, a)).map_err(|e| e.to_string())?;
        let issued: u64 = t.issuances.iter().map(|i| i.amount).sum();
        let burned: u64 = t.burns.iter().map(|b| b.amount).sum();
        let decimals = t.twin_of.as_ref().map(|o| o.decimals);
        rows.push_str(&format!(
            "<tr><td><a href=\"{f}\">{l}</a></td><td>{k}</td><td>{s}</td><td>{i}</td><td>{bu}</td><td>{st}</td></tr>\n",
            f = esc(&file),
            l = esc(&t.label),
            k = esc(&t.kind),
            s = t.node_supply.map(|s| units(s, decimals)).unwrap_or_else(|| "none".into()),
            i = t.issuances.len().to_string() + " (" + &units(issued, decimals) + ")",
            bu = t.burns.len().to_string() + " (" + &units(burned, decimals) + ")",
            st = if t.ok { "<span class=\"ok\">OK</span>" } else { "<span class=\"bad\">FAIL</span>" }
        ));
        written.push(file);
    }
    let overall = a.report.passed();
    let body = format!(
        "{BANNER}\n<h1>OrchardZSA twins of Sapling (sapling.cash) coins</h1>\n<p>Audit: {} <span class=\"muted\">(network {}, blocks {})</span></p>\n<table><tr><th>Twin</th><th>Kind</th><th>Supply</th><th>Issuances</th><th>Burns on Zcash</th><th>Audit</th></tr>\n{rows}</table>\n{TRUST}\n<p class=\"muted\">https://github.com/saplingcash/zsa · Apache-2.0</p>",
        if overall { "<span class=\"ok\">OK</span>" } else { "<span class=\"bad\">FAIL</span>" },
        esc(&a.network),
        a.scanned.map(|(f, to)| format!("{f}..={to}")).unwrap_or_default()
    );
    fs::write(out.join("index.html"), page("OrchardZSA twins of Sapling (sapling.cash) coins", &body)).map_err(|e| e.to_string())?;
    written.insert(0, "index.html".into());
    Ok(written)
}
