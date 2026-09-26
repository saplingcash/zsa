//! The Solana side of a burn twin: read a finalized transaction and check it is a twin burn
//! (docs/RULES.md §2, "against Solana").

use serde_json::{Value, json};

pub const MEMO_PREFIX: &str = "sapling-twin:1:";
const TOKEN_PROGRAMS: [&str; 2] = ["spl-token", "spl-token-2022"];

/// A burn that asks for a twin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Burn {
    pub signature: String,
    pub slot: u64,
    pub mint: String,
    pub amount: u64,
    pub zcash_address: String,
    pub orchard_receiver: [u8; 43],
}

pub struct SolanaRpc {
    url: String,
    http: reqwest::blocking::Client,
}

impl SolanaRpc {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("http client"),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
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
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    /// The genesis hash, to tell clusters apart.
    pub fn genesis_hash(&self) -> Result<String, String> {
        self.call("getGenesisHash", json!([]))?
            .as_str()
            .map(String::from)
            .ok_or_else(|| "getGenesisHash: no result".into())
    }

    /// A finalized transaction, parsed; `None` if not found (or not finalized yet).
    pub fn transaction(&self, signature: &str) -> Result<Option<Value>, String> {
        let tx = self.call(
            "getTransaction",
            json!([signature, {"encoding": "jsonParsed", "commitment": "finalized", "maxSupportedTransactionVersion": 0}]),
        )?;
        Ok((!tx.is_null()).then_some(tx))
    }

    /// Finalized signatures touching `address`, newest first, down to (not including) `until`.
    pub fn signatures_for(&self, address: &str, until: Option<&str>, limit: u32) -> Result<Vec<(String, bool)>, String> {
        let mut opts = json!({"commitment": "finalized", "limit": limit});
        if let Some(u) = until {
            opts["until"] = json!(u);
        }
        let list = self.call("getSignaturesForAddress", json!([address, opts]))?;
        Ok(list
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| Some((e.get("signature")?.as_str()?.to_string(), e.get("err").is_some_and(Value::is_null))))
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// All instructions of a parsed transaction: top level and inner (CPI).
fn instructions(tx: &Value) -> Vec<&Value> {
    let mut all: Vec<&Value> = tx
        .pointer("/transaction/message/instructions")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    if let Some(inner) = tx.pointer("/meta/innerInstructions").and_then(Value::as_array) {
        for group in inner {
            if let Some(list) = group.get("instructions").and_then(Value::as_array) {
                all.extend(list.iter());
            }
        }
    }
    all
}

/// Check a parsed, finalized transaction against the Solana-side rules and return the burn.
/// `expected_mint`: the twin's mint, when known.
pub fn parse_burn(signature: &str, tx: &Value, expected_mint: Option<&str>) -> Result<Burn, String> {
    if !tx.pointer("/meta/err").is_some_and(Value::is_null) {
        return Err("the transaction failed on Solana".into());
    }
    let listed_sig = tx.pointer("/transaction/signatures/0").and_then(Value::as_str);
    if listed_sig != Some(signature) {
        return Err("the transaction's signature is not the one cited".into());
    }
    let ins = instructions(tx);

    let burns: Vec<&Value> = ins
        .iter()
        .copied()
        .filter(|i| {
            i.get("program").and_then(Value::as_str).is_some_and(|p| TOKEN_PROGRAMS.contains(&p))
                && i.pointer("/parsed/type").and_then(Value::as_str).is_some_and(|t| t == "burn" || t == "burnChecked")
        })
        .collect();
    if burns.len() != 1 {
        return Err(format!("{} token burns (exactly 1 expected)", burns.len()));
    }
    let info = burns[0].pointer("/parsed/info").ok_or("burn without info")?;
    let mint = info.get("mint").and_then(Value::as_str).ok_or("burn without a mint")?.to_string();
    let amount_str = info
        .get("amount")
        .and_then(Value::as_str)
        .or_else(|| info.pointer("/tokenAmount/amount").and_then(Value::as_str))
        .ok_or("burn without an amount")?;
    let amount: u64 = amount_str.parse().map_err(|_| format!("burn amount {amount_str} is not a u64"))?;
    if amount == 0 {
        return Err("burn of zero".into());
    }
    if let Some(m) = expected_mint {
        if mint != m {
            return Err(format!("burns mint {mint}, not the twin's mint {m}"));
        }
    }

    let memos: Vec<&str> = ins
        .iter()
        .filter(|i| i.get("program").and_then(Value::as_str) == Some("spl-memo"))
        .filter_map(|i| i.get("parsed").and_then(Value::as_str))
        .filter(|m| m.starts_with(MEMO_PREFIX))
        .collect();
    if memos.len() != 1 {
        return Err(format!("{} sapling-twin memos (exactly 1 expected)", memos.len()));
    }
    let zcash_address = memos[0][MEMO_PREFIX.len()..].to_string();
    let orchard_receiver = crate::address::orchard_receiver(&zcash_address)?;
    let slot = tx.get("slot").and_then(Value::as_u64).unwrap_or(0);
    Ok(Burn { signature: signature.to_string(), slot, mint, amount, zcash_address, orchard_receiver })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real Solana devnet transactions (getTransaction, jsonParsed, finalized).
    const VALID: &str = include_str!("../tests/fixtures/solana/valid-burn.json");
    const NO_MEMO: &str = include_str!("../tests/fixtures/solana/no-memo.json");
    const OTHER_MINT: &str = include_str!("../tests/fixtures/solana/other-mint.json");
    const MINT: &str = "25PVFmBUJzvuCWeni4fgE15pQhTNEwMLyakK3aWN97q4";
    const HOLDER: &str = "utest1ytaymgygt6suas43ay6wfnuree5te8v7ex64ayy9p74t8jcdj0wzf2736602t9yf05apdu7pjn9hav2tfs5maasgvhngnze5zyqj7pyk";

    fn tx(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    fn sig(v: &Value) -> String {
        v.pointer("/transaction/signatures/0").unwrap().as_str().unwrap().to_string()
    }

    fn memo_instruction(v: &Value) -> Value {
        instructions(v)
            .into_iter()
            .find(|i| i.get("program").and_then(Value::as_str) == Some("spl-memo"))
            .unwrap()
            .clone()
    }

    #[test]
    fn a_real_twin_burn_parses() {
        let v = tx(VALID);
        let b = parse_burn(&sig(&v), &v, Some(MINT)).unwrap();
        assert_eq!(b.mint, MINT);
        assert_eq!(b.amount, 25_000_000);
        assert_eq!(b.zcash_address, HOLDER);
        assert_eq!(b.orchard_receiver, crate::address::orchard_receiver(HOLDER).unwrap());
    }

    #[test]
    fn a_burn_without_memo_is_refused() {
        let v = tx(NO_MEMO);
        let e = parse_burn(&sig(&v), &v, Some(MINT)).unwrap_err();
        assert!(e.contains("0 sapling-twin memos"), "{e}");
    }

    #[test]
    fn a_burn_of_another_mint_is_refused() {
        let v = tx(OTHER_MINT);
        let e = parse_burn(&sig(&v), &v, Some(MINT)).unwrap_err();
        assert!(e.contains("not the twin's mint"), "{e}");
    }

    #[test]
    fn edited_copies_are_refused() {
        let base = tx(VALID);
        let s = sig(&base);

        assert!(parse_burn(&sig(&tx(NO_MEMO)), &base, Some(MINT)).unwrap_err().contains("not the one cited"));

        let mut failed = base.clone();
        failed["meta"]["err"] = serde_json::json!({"InstructionError": [0, "Custom"]});
        assert!(parse_burn(&s, &failed, Some(MINT)).unwrap_err().contains("failed"));

        let mut two_memos = base.clone();
        let memo = memo_instruction(&base);
        two_memos["transaction"]["message"]["instructions"].as_array_mut().unwrap().push(memo);
        assert!(parse_burn(&s, &two_memos, Some(MINT)).unwrap_err().contains("2 sapling-twin memos"));

        let mut two_burns = base.clone();
        let burn = instructions(&base)
            .into_iter()
            .find(|i| i.pointer("/parsed/type").and_then(Value::as_str) == Some("burnChecked"))
            .unwrap()
            .clone();
        two_burns["transaction"]["message"]["instructions"].as_array_mut().unwrap().push(burn);
        assert!(parse_burn(&s, &two_burns, Some(MINT)).unwrap_err().contains("2 token burns"));

        let mut mainnet = base.clone();
        let main_ua = zcash_address::unified::Encoding::encode(
            &<zcash_address::unified::Address as zcash_address::unified::Encoding>::try_from_items(vec![
                zcash_address::unified::Receiver::Orchard([7u8; 43]),
            ])
            .unwrap(),
            &zcash_protocol::consensus::NetworkType::Main,
        );
        for i in mainnet["transaction"]["message"]["instructions"].as_array_mut().unwrap() {
            if i.get("program").and_then(Value::as_str) == Some("spl-memo") {
                i["parsed"] = Value::String(format!("{MEMO_PREFIX}{main_ua}"));
            }
        }
        assert!(parse_burn(&s, &mainnet, Some(MINT)).unwrap_err().contains("mainnet"));
    }
}
