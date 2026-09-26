//! The holder's side of a twin: balances, sending a twin on to a fresh shielded address, and
//! burning twin units on Zcash (ZIP 226).
//!
//! The wallet (note tracking, witnesses, transfer and burn building) is QEDIT's zcash_tx_tool,
//! used as a library; this module chooses the addresses, checks balances before building, and
//! reports what happened. A test wallet's accounts come from one BIP-39 phrase (ZIP 32, coin type 1):
//! account 0 is the address a burn memo names, account 1 is the fresh address a twin moves on to.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use orchard::keys::Scope;
use orchard::note::AssetBase;
use orchard::Address;
use zcash_tx_tool::components::db;
use zcash_tx_tool::components::rpc_client::reqwest::ReqwestRpcClient;
use zcash_tx_tool::components::transactions::{
    create_burn_transaction, create_transfer_transaction, mine, sync_from_height,
};
use zcash_tx_tool::components::wallet::Wallet;

use crate::{address, keys, metadata};

pub struct HolderWallet {
    conn: diesel::SqliteConnection,
    wallet: Wallet,
    rpc: ReqwestRpcClient,
    /// Account 0: the address a burn memo names. Account 1: the fresh address.
    pub accounts: [Address; 2],
}

/// Run library code that reports failure by panicking; turn a panic into an error.
fn guarded<T>(what: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|p| {
        let msg = p
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown error".into());
        format!("{what}: {msg}")
    })
}

/// The asset base of a twin, from its published issuer and envelope.
pub fn asset_of(coin_dir: &Path) -> Result<AssetBase, String> {
    let read = |f: &str| std::fs::read_to_string(coin_dir.join(f)).map_err(|e| format!("{}: {e}", coin_dir.join(f).display()));
    let envelope = read("envelope.txt")?;
    let issuer = read("issuer.txt")?.trim().to_lowercase();
    let ik = hex::decode(&issuer)
        .ok()
        .and_then(|b| orchard::issuance::auth::IssueValidatingKey::decode(&b).ok())
        .ok_or("issuer.txt does not decode")?;
    Ok(AssetBase::custom(&orchard::note::AssetId::new_v0(&ik, &metadata::asset_desc_hash(envelope.as_bytes()))))
}

impl HolderWallet {
    /// Open (or create) the wallet state and sync it with the node.
    pub fn open(key: &Path, wallet_db: &Path, node_url: &str) -> Result<Self, String> {
        Self::open_with_phrase(&keys::read_phrase(key)?, wallet_db, node_url)
    }

    /// As `open`, with the phrase itself (the local test vectors keep their keys in memory).
    pub fn open_with_phrase(phrase: &str, wallet_db: &Path, node_url: &str) -> Result<Self, String> {
        if let Some(dir) = wallet_db.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let db_path = wallet_db.to_string_lossy().to_string();
        let mut conn = guarded("opening the wallet database", || db::establish_connection(&db_path))?;
        let mut wallet = Wallet::new(&mut conn, phrase);
        let accounts = [wallet.address_for_account(0, Scope::External), wallet.address_for_account(1, Scope::External)];
        let mut rpc = ReqwestRpcClient::new(node_url.to_string());
        eprintln!("syncing the wallet with {node_url} ...");
        guarded("syncing", || sync_from_height(&mut conn, 1, &mut wallet, &mut rpc))?;
        Ok(Self { conn, wallet, rpc, accounts })
    }

    pub fn address(&self, account: usize) -> Result<String, String> {
        address::encode_orchard(self.accounts[account].to_raw_address_bytes())
    }

    pub fn balance(&mut self, account: usize, asset: AssetBase) -> u64 {
        self.wallet.balance(&mut self.conn, self.accounts[account], asset)
    }

    /// Send `amount` units of `asset` from account `from` to account `to`. Returns the txid.
    pub fn send(&mut self, from: usize, to: usize, amount: u64, asset: AssetBase) -> Result<String, String> {
        let have = self.balance(from, asset);
        if amount == 0 || amount > have {
            return Err(format!("cannot send {amount}: account {from} holds {have}"));
        }
        let (sender, recipient) = (self.accounts[from], self.accounts[to]);
        let tx = guarded("building the transfer", || {
            create_transfer_transaction(&mut self.conn, sender, recipient, amount, asset, &self.rpc, &mut self.wallet)
        })?;
        let txid = tx.txid().to_string();
        guarded("submitting", || mine(&mut self.conn, &mut self.wallet, &mut self.rpc, vec![tx]))?
            .map_err(|e| format!("submitting: {e}"))?;
        Ok(txid)
    }

    /// Burn `amount` units of `asset` held by account `from` (ZIP 226). Returns the txid.
    pub fn burn(&mut self, from: usize, amount: u64, asset: AssetBase) -> Result<String, String> {
        let have = self.balance(from, asset);
        if amount == 0 || amount > have {
            return Err(format!("cannot burn {amount}: account {from} holds {have}"));
        }
        let arsonist = self.accounts[from];
        let tx = guarded("building the burn", || {
            create_burn_transaction(&mut self.conn, arsonist, amount, asset, &self.rpc, &mut self.wallet)
        })?;
        let txid = tx.txid().to_string();
        guarded("submitting", || mine(&mut self.conn, &mut self.wallet, &mut self.rpc, vec![tx]))?
            .map_err(|e| format!("submitting: {e}"))?;
        Ok(txid)
    }
}
