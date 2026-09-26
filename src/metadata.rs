//! Twin metadata: Cachet's metadata format v1, unchanged, plus the `solana-twin` line.
//!
//! Format: <https://github.com/cachet-zec/cachet/blob/main/packages/registry-spec/README.md> (MIT).
//! Written independently from that specification; see docs/METADATA.md.
//!
//! - The **bundle** is the JSON serialization (serde_json, no whitespace) of Cachet's
//!   `MetadataBundle`, fields in the order `v, name, description, image_data_uri, external_url`,
//!   absent optional fields omitted.
//! - The **envelope** `{"v":1,"name":"…","sha256":"<hex sha-256 of the bundle bytes>"}` is the
//!   ZIP 227 `asset_desc`, so its hash is part of the asset id.
//! - The bundle's description starts with `solana-twin:1:<cluster>:<mint>:<decimals>`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_NAME_BYTES: usize = 120;
pub const MAX_DESCRIPTION_BYTES: usize = 4096;
pub const MAX_ASSET_DESC_BYTES: usize = 512;
pub const TWIN_TAG: &str = "solana-twin:1:";
/// Test networks only: mainnet is refused until ZSAs are active on Zcash mainnet.
pub const ALLOWED_CLUSTERS: [&str; 2] = ["devnet", "localnet"];
pub const NO_VALUE_SUFFIX: &str = "(no value)";
pub const MAX_DECIMALS: u8 = 18;

/// The input a coin's metadata is built from (`assets/<coin>/coin.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoinSpec {
    pub name: String,
    pub cluster: String,
    pub mint: String,
    pub decimals: u8,
    /// Free text after the twin line: what this is, the trust model, where to check.
    pub note: String,
}

/// Cachet's metadata bundle v1 (field order matters: it is the byte order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub v: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_data_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_url: Option<String>,
}

/// Cachet's on-chain description envelope v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u32,
    pub name: String,
    pub sha256: String,
}

/// The Solana coin a twin stands for, as read from its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwinOf {
    pub cluster: String,
    pub mint: String,
    pub decimals: u8,
}

pub fn explorer_url(cluster: &str, mint: &str) -> String {
    match cluster {
        "localnet" => format!(
            "https://explorer.solana.com/address/{mint}?cluster=custom&customUrl=http%3A%2F%2F127.0.0.1%3A8899"
        ),
        other => format!("https://explorer.solana.com/address/{mint}?cluster={other}"),
    }
}

pub fn twin_line(cluster: &str, mint: &str, decimals: u8) -> String {
    format!("{TWIN_TAG}{cluster}:{mint}:{decimals}")
}

impl CoinSpec {
    pub fn bundle(&self) -> Result<Bundle, Vec<String>> {
        let bundle = Bundle {
            v: 1,
            name: self.name.clone(),
            description: Some(format!(
                "{}\n\n{}",
                twin_line(&self.cluster, &self.mint, self.decimals),
                self.note
            )),
            image_data_uri: None,
            external_url: Some(explorer_url(&self.cluster, &self.mint)),
        };
        check_bundle(&bundle).map(|_| bundle)
    }
}

pub fn bundle_bytes(bundle: &Bundle) -> Vec<u8> {
    serde_json::to_vec(bundle).expect("bundle serialization cannot fail")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The envelope text (the ZIP 227 `asset_desc`) for a bundle.
pub fn envelope_for(bundle: &Bundle) -> Result<String, String> {
    let text = serde_json::to_string(&Envelope {
        v: 1,
        name: bundle.name.clone(),
        sha256: sha256_hex(&bundle_bytes(bundle)),
    })
    .expect("envelope serialization cannot fail");
    if text.len() > MAX_ASSET_DESC_BYTES {
        return Err(format!("envelope is {} bytes, over {MAX_ASSET_DESC_BYTES}", text.len()));
    }
    Ok(text)
}

/// BLAKE2b-256 with personalization "ZSA-AssetDescCRH" (ZIP 227), computed here directly.
/// `check` compares it with QEDIT's `orchard::issuance::compute_asset_desc_hash`.
pub fn asset_desc_hash(asset_desc: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZSA-AssetDescCRH")
        .hash(asset_desc);
    hash.as_bytes().try_into().expect("32 bytes")
}

/// Our twin rules on a bundle (on top of Cachet's own limits).
fn check_bundle(bundle: &Bundle) -> Result<TwinOf, Vec<String>> {
    let mut problems = Vec::new();
    if bundle.v != 1 {
        problems.push(format!("bundle version {} (expected 1)", bundle.v));
    }
    if bundle.name.trim().is_empty() || bundle.name.len() > MAX_NAME_BYTES {
        problems.push(format!("name must be 1..={MAX_NAME_BYTES} bytes"));
    }
    if bundle.image_data_uri.is_some() {
        problems.push("images are not used by twins yet".into());
    }
    let description = bundle.description.as_deref().unwrap_or("");
    if description.len() > MAX_DESCRIPTION_BYTES {
        problems.push(format!("description over {MAX_DESCRIPTION_BYTES} bytes"));
    }
    let first_line = description.lines().next().unwrap_or("");
    let twin = parse_twin_line(first_line);
    match &twin {
        Err(e) => problems.push(e.clone()),
        Ok(t) => {
            if t.cluster != "mainnet" && !bundle.name.ends_with(NO_VALUE_SUFFIX) {
                problems.push(format!("a test-network twin's name must end with \"{NO_VALUE_SUFFIX}\""));
            }
            let expected = explorer_url(&t.cluster, &t.mint);
            if bundle.external_url.as_deref() != Some(expected.as_str()) {
                problems.push(format!("external_url must be {expected}"));
            }
        }
    }
    if problems.is_empty() { Ok(twin.expect("checked")) } else { Err(problems) }
}

pub fn parse_twin_line(line: &str) -> Result<TwinOf, String> {
    let rest = line
        .strip_prefix(TWIN_TAG)
        .ok_or_else(|| format!("description must start with \"{TWIN_TAG}\""))?;
    let parts: Vec<&str> = rest.split(':').collect();
    let [cluster, mint, decimals] = parts[..] else {
        return Err("twin line must be solana-twin:1:<cluster>:<mint>:<decimals>".into());
    };
    if !ALLOWED_CLUSTERS.contains(&cluster) {
        return Err(format!("cluster \"{cluster}\" is not allowed (test networks only: {ALLOWED_CLUSTERS:?})"));
    }
    match base58_decode(mint) {
        Some(bytes) if bytes.len() == 32 && base58_encode(&bytes) == mint => {}
        _ => return Err(format!("mint \"{mint}\" is not a canonical base58 32-byte address")),
    }
    let parsed: Option<u8> = decimals.parse().ok();
    let decimals_value = parsed
        .filter(|d| *d <= MAX_DECIMALS && decimals == d.to_string())
        .ok_or_else(|| format!("decimals \"{decimals}\" must be 0..={MAX_DECIMALS}, no leading zeros"))?;
    Ok(TwinOf { cluster: cluster.into(), mint: mint.into(), decimals: decimals_value })
}

/// Verify a published (envelope, bundle bytes) pair: Cachet's verification rule, strict
/// canonical bytes on both, and the twin rules. Returns the Solana coin it is a twin of.
pub fn verify_published(envelope_text: &str, bundle: &[u8]) -> Result<TwinOf, Vec<String>> {
    let envelope: Envelope = serde_json::from_str(envelope_text)
        .map_err(|e| vec![format!("envelope does not parse as Cachet v1: {e}")])?;
    let mut problems = Vec::new();
    if serde_json::to_string(&envelope).ok().as_deref() != Some(envelope_text) {
        problems.push("envelope is not in canonical form".into());
    }
    if envelope.v != 1 || envelope.sha256.len() != 64 {
        problems.push("envelope must be v1 with a 64-hex-digit sha256".into());
    }
    if envelope_text.len() > MAX_ASSET_DESC_BYTES {
        problems.push(format!("envelope over {MAX_ASSET_DESC_BYTES} bytes"));
    }
    if sha256_hex(bundle) != envelope.sha256 {
        problems.push("bundle bytes do not hash to the envelope's sha256".into());
    }
    let parsed: Bundle = match serde_json::from_slice(bundle) {
        Ok(b) => b,
        Err(e) => {
            problems.push(format!("bundle does not parse as Cachet v1: {e}"));
            return Err(problems);
        }
    };
    if bundle_bytes(&parsed) != bundle {
        problems.push("bundle is not in canonical form".into());
    }
    if parsed.name != envelope.name {
        problems.push("bundle name differs from envelope name".into());
    }
    match check_bundle(&parsed) {
        Ok(twin) if problems.is_empty() => Ok(twin),
        Ok(_) => Err(problems),
        Err(mut more) => {
            problems.append(&mut more);
            Err(problems)
        }
    }
}

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = B58.iter().position(|&b| b == c)? as u32;
        for byte in bytes.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut out = vec![0u8; zeros];
    out.extend(bytes.into_iter().skip_while(|&b| b == 0));
    Some(out)
}

pub fn base58_encode(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    std::iter::repeat_n('1', zeros)
        .chain(digits.iter().rev().map(|&d| B58[d as usize] as char))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // An arbitrary valid 32-byte address (the System Program is all zeros: 32 x '1').
    const MINT: &str = "11111111111111111111111111111111";

    fn spec() -> CoinSpec {
        CoinSpec {
            name: "Test coin (no value)".into(),
            cluster: "devnet".into(),
            mint: MINT.into(),
            decimals: 6,
            note: "Test network only.".into(),
        }
    }

    fn published() -> (String, Vec<u8>) {
        let bundle = spec().bundle().unwrap();
        (envelope_for(&bundle).unwrap(), bundle_bytes(&bundle))
    }

    #[test]
    fn bytes_match_cachet_serialization_exactly() {
        let bundle = spec().bundle().unwrap();
        let bytes = String::from_utf8(bundle_bytes(&bundle)).unwrap();
        assert_eq!(
            bytes,
            "{\"v\":1,\"name\":\"Test coin (no value)\",\"description\":\"solana-twin:1:devnet:11111111111111111111111111111111:6\\n\\nTest network only.\",\"external_url\":\"https://explorer.solana.com/address/11111111111111111111111111111111?cluster=devnet\"}"
        );
        let envelope = envelope_for(&bundle).unwrap();
        assert_eq!(envelope, format!("{{\"v\":1,\"name\":\"Test coin (no value)\",\"sha256\":\"{}\"}}", sha256_hex(bytes.as_bytes())));
    }

    #[test]
    fn published_pair_verifies() {
        let (envelope, bundle) = published();
        let twin = verify_published(&envelope, &bundle).unwrap();
        assert_eq!(twin, TwinOf { cluster: "devnet".into(), mint: MINT.into(), decimals: 6 });
    }

    #[test]
    fn tampered_bundle_fails() {
        let (envelope, bundle) = published();
        let tampered = String::from_utf8(bundle).unwrap().replace("devnet:1111", "devnet:2111");
        let err = verify_published(&envelope, tampered.as_bytes()).unwrap_err();
        assert!(err.iter().any(|e| e.contains("do not hash")), "{err:?}");
    }

    #[test]
    fn non_canonical_forms_fail() {
        let (envelope, bundle) = published();
        let spaced = envelope.replace(",\"name\"", ", \"name\"");
        assert!(verify_published(&spaced, &bundle).unwrap_err().iter().any(|e| e.contains("canonical")));
    }

    #[test]
    fn mainnet_and_bad_fields_are_refused() {
        let mut s = spec();
        s.cluster = "mainnet".into();
        assert!(s.bundle().unwrap_err().iter().any(|e| e.contains("not allowed")));
        let mut s = spec();
        s.name = "Real coin".into();
        assert!(s.bundle().unwrap_err().iter().any(|e| e.contains("no value")));
        let mut s = spec();
        s.mint = "0OIl".into();
        assert!(s.bundle().is_err());
        assert!(parse_twin_line("solana-twin:1:devnet:11111111111111111111111111111111:06").is_err());
    }

    #[test]
    fn external_url_must_name_the_same_mint() {
        let mut bundle = spec().bundle().unwrap();
        bundle.external_url = Some(explorer_url("devnet", "So11111111111111111111111111111111111111112"));
        let envelope = envelope_for(&bundle).unwrap();
        let err = verify_published(&envelope, &bundle_bytes(&bundle)).unwrap_err();
        assert!(err.iter().any(|e| e.contains("external_url")), "{err:?}");
    }

    #[test]
    fn base58_round_trips() {
        for s in [MINT, "So11111111111111111111111111111111111111112", "B8uJKxx4NR4tzr9UsR3szNqZR7JEaw6JRATeTZuhJ6ry"] {
            let bytes = base58_decode(s).unwrap();
            assert_eq!(bytes.len(), 32, "{s}");
            assert_eq!(base58_encode(&bytes), s);
        }
    }

    #[test]
    fn desc_hash_matches_orchard() {
        let (envelope, _) = published();
        let ours = asset_desc_hash(envelope.as_bytes());
        let theirs = orchard::issuance::compute_asset_desc_hash(
            &nonempty::NonEmpty::from_slice(envelope.as_bytes()).unwrap(),
        );
        assert_eq!(ours, theirs);
    }
}
