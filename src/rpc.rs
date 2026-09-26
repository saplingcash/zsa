//! A small read-only JSON-RPC client for a ZSA Zebra node (what `check` needs).

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// QEDIT's public ZSA test network node.
pub const DEFAULT_NODE: &str = "https://rpc.test-zsa.org:443";

pub struct Node {
    url: String,
    http: reqwest::blocking::Client,
}

#[derive(Debug, Deserialize)]
pub struct RawTx {
    pub hex: String,
    pub height: Option<i64>,
    pub confirmations: Option<i64>,
}

/// `getassetstate` (QEDIT's Zebra): the node's record of an asset.
#[derive(Debug, Deserialize)]
pub struct AssetState {
    pub amount: u64,
    pub is_finalized: bool,
}

#[derive(Debug, Deserialize)]
pub struct ChainInfo {
    pub chain: String,
    pub blocks: u64,
}

impl Node {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("http client"),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, String> {
        let body = json!({"jsonrpc": "1.0", "id": "saplingcash-zsa", "method": method, "params": params});
        let resp: Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .map_err(|e| format!("{method}: {e}"))?
            .json()
            .map_err(|e| format!("{method}: bad response: {e}"))?;
        if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
            return Err(format!("{method}: {}", err.get("message").and_then(Value::as_str).unwrap_or("error")));
        }
        serde_json::from_value(resp.get("result").cloned().unwrap_or(Value::Null))
            .map_err(|e| format!("{method}: unexpected result: {e}"))
    }

    pub fn chain_info(&self) -> Result<ChainInfo, String> {
        self.call("getblockchaininfo", json!([]))
    }

    pub fn raw_tx(&self, txid: &str) -> Result<RawTx, String> {
        self.call("getrawtransaction", json!([txid, 1]))
    }

    pub fn block_count(&self) -> Result<u64, String> {
        self.call("getblockcount", json!([]))
    }

    pub fn block_hash(&self, height: u64) -> Result<String, String> {
        self.call("getblockhash", json!([height]))
    }

    pub fn raw_block(&self, height: u64) -> Result<Vec<u8>, String> {
        let hex: String = self.call("getblock", json!([height.to_string(), 0]))?;
        hex::decode(hex).map_err(|e| format!("getblock {height}: {e}"))
    }

    /// The Orchard note commitment tree root after `height` (an anchor for a new transaction).
    pub fn orchard_root(&self, height: u64) -> Result<[u8; 32], String> {
        let state: Value = self.call("z_gettreestate", json!([height.to_string()]))?;
        let root = state
            .pointer("/orchard/commitments/finalRoot")
            .and_then(Value::as_str)
            .ok_or("z_gettreestate: no orchard finalRoot")?;
        hex::decode(root)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| "z_gettreestate: bad orchard finalRoot".to_string())
    }

    /// `Ok(None)` when the node has no record of the asset.
    pub fn asset_state(&self, asset_base_hex: &str) -> Result<Option<AssetState>, String> {
        match self.call::<AssetState>("getassetstate", json!([asset_base_hex])) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.to_lowercase().contains("not found") => Ok(None),
            Err(e) => Err(e),
        }
    }
}
