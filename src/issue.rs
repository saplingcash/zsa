//! Build and submit a twin issuance.
//!
//! The transaction is built here with librustzcash's builder (QEDIT's ZSA branch):
//! - one issue action for the twin, one value note (plus the reference note on first issuance);
//! - one zero-value Orchard output in ZEC, because an OrchardZSA bundle with at least one action is
//!   needed to derive the issued notes' rho (as QEDIT's zcash_tx_tool does);
//! - for a burn twin, one OP_RETURN output with the burn citation (docs/RULES.md §2.7);
//! - no transparent inputs; the fee rule is the test network's zero-fee non-standard rule.
//!
//! The anchor comes from the node (`z_gettreestate`). The block carrying the transaction is
//! assembled and submitted by zcash_tx_tool's `mine_block` (QEDIT; MIT per its README).

use std::path::Path;

use bip0039::Mnemonic;
use orchard::issuance::IssueInfo;
use orchard::issuance::auth::IssueValidatingKey;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{AssetBase, AssetId};
use orchard::value::NoteValue;
use orchard::{Address, Anchor};
use rand::rngs::OsRng;
use zcash_primitives::transaction::Transaction;
use zcash_primitives::transaction::builder::{BuildConfig, Builder};
use zcash_primitives::transaction::fees::zip317::{FeeError, FeeRule};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::{BlockHeight, REGTEST_NETWORK};
use zcash_protocol::constants::regtest::COIN_TYPE;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::builder::TransparentSigningSet;
use zcash_tx_tool::components::rpc_client::reqwest::ReqwestRpcClient;
use zcash_tx_tool::components::transactions::mine_block;
use zip32::AccountId;

use crate::keys;
use crate::rpc::Node;
use crate::scan::Citation;

pub struct Issued {
    pub txid: String,
    pub height: u32,
    pub asset_base_hex: String,
    pub recipient_hex: String,
    pub first_issuance: bool,
}

/// A test wallet's Orchard address (account `account`, external, index 0), from the key phrase.
pub fn test_address(phrase: &str, account: u32) -> Result<Address, String> {
    let seed = Mnemonic::<bip0039::English>::from_phrase(phrase).map_err(|e| e.to_string())?.to_seed("");
    let sk = SpendingKey::from_zip32_seed(&seed, COIN_TYPE, AccountId::try_from(account).map_err(|_| "account")?)
        .map_err(|_| "deriving the spending key".to_string())?;
    Ok(FullViewingKey::from(&sk).address_at(0u32, Scope::External))
}

/// What goes into an issuance besides the asset and the amount.
#[derive(Debug, Clone, Copy, Default)]
pub struct BuildOptions {
    /// The burn citation (docs/RULES.md §2.7).
    pub citation: Option<Citation>,
    /// Set the finalize flag. Twins never do; the local test vectors use it.
    pub finalize: bool,
    /// Allow a citation whose amount differs from the issued amount. Local test vectors only.
    pub allow_citation_mismatch: bool,
}

pub fn build(
    phrase: &str,
    asset_desc: &str,
    amount: u64,
    recipient: Address,
    opts: &BuildOptions,
    node: &Node,
) -> Result<(Transaction, AssetBase, bool), String> {
    if amount == 0 {
        return Err("amount must be above zero".into());
    }
    if let Some(c) = opts.citation {
        if c.amount != amount && !opts.allow_citation_mismatch {
            return Err(format!("citation amount {} differs from the amount {amount}", c.amount));
        }
    }
    let isk = keys::issuance_key(phrase)?;
    let desc_hash = crate::metadata::asset_desc_hash(asset_desc.as_bytes());
    let asset = AssetBase::custom(&AssetId::new_v0(&IssueValidatingKey::from(&isk), &desc_hash));
    let first = node.asset_state(&hex::encode(asset.to_bytes()))?.is_none();

    let tip = node.block_count()?;
    let root = node.orchard_root(tip)?;
    let anchor = Option::from(Anchor::from_bytes(root)).ok_or("the node's Orchard root is not a valid anchor")?;
    let target = BlockHeight::from_u32(u32::try_from(tip + 1).map_err(|_| "height")?);

    let mut b = Builder::new(
        REGTEST_NETWORK,
        target,
        BuildConfig::Standard { sapling_anchor: None, orchard_anchor: Some(anchor) },
    );
    b.init_issuance_bundle::<FeeError>(
        isk,
        desc_hash,
        Some(IssueInfo { recipient, value: NoteValue::from_raw(amount) }),
        first,
    )
    .map_err(|e| format!("issuance bundle: {e:?}"))?;
    if opts.finalize {
        b.finalize_asset::<FeeError>(&desc_hash).map_err(|e| format!("finalize: {e:?}"))?;
    }
    let own = test_address(phrase, 0)?;
    let ovk = {
        let seed = Mnemonic::<bip0039::English>::from_phrase(phrase).map_err(|e| e.to_string())?.to_seed("");
        let sk = SpendingKey::from_zip32_seed(&seed, COIN_TYPE, AccountId::ZERO).map_err(|_| "spending key")?;
        FullViewingKey::from(&sk).to_ovk(Scope::External)
    };
    b.add_orchard_output::<FeeError>(Some(ovk), own, Zatoshis::ZERO, AssetBase::zatoshi(), MemoBytes::empty())
        .map_err(|e| format!("orchard output: {e:?}"))?;
    if let Some(c) = opts.citation {
        b.add_transparent_null_data_output::<FeeError>(&c.encode())
            .map_err(|e| format!("citation output: {e:?}"))?;
    }

    let prover = LocalTxProver::with_default_location()
        .ok_or("Sapling proving parameters not found in ~/.zcash-params (see README.md)")?;
    let fee_rule = FeeRule::non_standard(Zatoshis::ZERO, 20, 150, 34, 0).ok_or("the zero-fee rule")?;
    let tx = b
        .build(
            &TransparentSigningSet::new(),
            &[],
            &[],
            OsRng,
            &prover,
            &prover,
            &fee_rule,
            |a| first && *a == asset,
        )
        .map_err(|e| format!("building: {e:?}"))?
        .into_transaction();
    Ok((tx, asset, first))
}

pub fn issue(
    phrase_file: &Path,
    asset_desc: &str,
    amount: u64,
    citation: Option<Citation>,
    node_url: &str,
) -> Result<Issued, String> {
    let phrase = keys::read_phrase(phrase_file)?;
    let node = Node::new(node_url);
    // Test issuances go to account 1 of the same test wallet. (A burn twin goes to the burn memo's address.)
    let recipient = test_address(&phrase, 1)?;
    let opts = BuildOptions { citation, ..Default::default() };
    let (tx, asset, first) = build(&phrase, asset_desc, amount, recipient, &opts, &node)?;
    let txid = tx.txid().to_string();
    let height = submit(node_url, tx)?;
    Ok(Issued {
        txid,
        height,
        asset_base_hex: hex::encode(asset.to_bytes()),
        recipient_hex: hex::encode(recipient.to_raw_address_bytes()),
        first_issuance: first,
    })
}

/// Put a transaction in a new block on a ZSA test node (anyone may produce blocks there).
pub fn submit(node_url: &str, tx: Transaction) -> Result<u32, String> {
    let mut rpc = ReqwestRpcClient::new(node_url.to_string());
    let (height, _) = mine_block(&mut rpc, vec![tx]).map_err(|e| format!("submitting the block: {e}"))?;
    Ok(height)
}

/// Produce an empty block (a fresh local node starts at genesis, before the Orchard tree exists).
pub fn empty_block(node_url: &str) -> Result<u32, String> {
    let mut rpc = ReqwestRpcClient::new(node_url.to_string());
    let (height, _) = mine_block(&mut rpc, vec![]).map_err(|e| format!("submitting an empty block: {e}"))?;
    Ok(height)
}
