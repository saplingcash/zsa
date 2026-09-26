//! The issuer's test key: a BIP-39 phrase kept in a file outside version control.
//!
//! The issuance key is derived the way QEDIT's zcash_tx_tool derives it (ZIP 32 path
//! m_Issuance / 227' / coin_type' / 0', coin type 1 for test networks), so the tool's wallet and
//! this CLI agree on the issuer.

use std::fs;
use std::path::{Path, PathBuf};

use bip0039::{Count, Mnemonic};
use orchard::issuance::auth::{IssueAuthKey, IssueValidatingKey, ZSASchnorr};
use zcash_protocol::constants::regtest::COIN_TYPE;

pub fn read_phrase(path: &Path) -> Result<String, String> {
    let phrase = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let phrase = phrase.trim().to_string();
    Mnemonic::<bip0039::English>::from_phrase(phrase.as_str()).map_err(|e| format!("not a BIP-39 phrase: {e}"))?;
    Ok(phrase)
}

pub fn issuance_key(phrase: &str) -> Result<IssueAuthKey<ZSASchnorr>, String> {
    let seed = Mnemonic::<bip0039::English>::from_phrase(phrase)
        .map_err(|e| format!("not a BIP-39 phrase: {e}"))?
        .to_seed("");
    IssueAuthKey::from_zip32_seed(&seed, COIN_TYPE, 0).map_err(|e| format!("deriving the issuance key: {e}"))
}

/// The issuer as it appears on chain: `[0x00] || ik` (0x00 = BIP-340), hex.
pub fn issuer_hex(isk: &IssueAuthKey<ZSASchnorr>) -> String {
    hex::encode(IssueValidatingKey::from(isk).encode())
}

/// Refuse to write a key anywhere git could pick it up: only under `.private/` or outside the repo.
fn safe_key_path(path: &Path) -> Result<PathBuf, String> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    let abs = fs::canonicalize(parent).map_err(|e| e.to_string())?.join(path.file_name().ok_or("no file name")?);
    let repo = fs::canonicalize(env!("CARGO_MANIFEST_DIR")).map_err(|e| e.to_string())?;
    if abs.starts_with(&repo) && !abs.starts_with(repo.join(".private")) {
        return Err(format!("refusing to write a key inside the repository outside .private/: {}", abs.display()));
    }
    Ok(abs)
}

pub fn keygen(out: &Path) -> Result<String, String> {
    let path = safe_key_path(out)?;
    if path.exists() {
        return Err(format!("{} exists; not overwriting a key", path.display()));
    }
    let mnemonic = Mnemonic::<bip0039::English>::generate(Count::Words24);
    fs::write(&path, format!("{}\n", mnemonic.phrase())).map_err(|e| format!("writing {}: {e}", path.display()))?;
    issuance_key(mnemonic.phrase()).map(|isk| issuer_hex(&isk))
}
