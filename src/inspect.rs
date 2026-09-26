//! `inspect`: print what anyone can read from the chain about a transaction, and what stays hidden.
//!
//! An issuance (ZIP 227) is transparent: issuer, asset, recipient and amount are public. A transfer
//! of a twin is an OrchardZSA bundle: an observer sees nullifiers, note commitments and encrypted
//! notes, but not the asset, the amounts or the parties. A burn (ZIP 226) publishes the asset and the
//! amount burned, not who burned it.

use orchard::note::{AssetBase, AssetId};
use zcash_primitives::transaction::{OrchardBundle, Transaction};
use zcash_protocol::consensus::BranchId;

use crate::address;
use crate::rpc::Node;
use crate::scan::{self, Citation};

pub fn inspect(txid: &str, node: &Node) -> Result<Vec<String>, String> {
    let raw = node.raw_tx(txid)?;
    let bytes = hex::decode(&raw.hex).map_err(|e| e.to_string())?;
    let tx = Transaction::read(bytes.as_slice(), BranchId::Nu6).map_err(|e| format!("does not parse: {e}"))?;
    let mut out = vec![format!(
        "tx {txid} (height {})",
        raw.height.map_or("unmined".into(), |h| h.to_string())
    )];

    if let Some(t) = tx.transparent_bundle() {
        out.push(format!("transparent: {} input(s), {} output(s)", t.vin.len(), t.vout.len()));
        for data in scan::null_data_outputs(&tx).into_iter().flatten() {
            match Citation::decode(&data) {
                Some(c) => out.push(format!("  public: burn citation, Solana signature {}, amount {}", c.signature_b58(), c.amount)),
                None => out.push(format!("  public: OP_RETURN data, {} bytes", data.len())),
            }
        }
    }

    if let Some(bundle) = tx.issue_bundle() {
        out.push(format!("issuance (ZIP 227, transparent): issuer {}", hex::encode(bundle.ik().encode())));
        for action in bundle.actions().iter() {
            let asset = AssetBase::custom(&AssetId::new_v0(bundle.ik(), action.asset_desc_hash()));
            out.push(format!("  public: asset {} (finalized: {})", hex::encode(asset.to_bytes()), action.is_finalized()));
            for note in action.notes() {
                let to = address::encode_orchard(note.recipient().to_raw_address_bytes())?;
                if note.value().inner() == 0 {
                    out.push("  public: the zero-value reference note (first issuance)".into());
                } else {
                    out.push(format!("  public: {} units to {to}", note.value().inner()));
                }
            }
        }
    }

    match tx.orchard_bundle() {
        Some(OrchardBundle::OrchardZSA(b)) => {
            out.push(format!("OrchardZSA bundle: {} action(s)", b.actions().len()));
            out.push("  public: one nullifier and one note commitment per action".into());
            out.push("  hidden: for every action, the asset, the amount, the sender and the recipient".into());
            out.push(format!("  public: ZEC value balance {} zatoshi", i64::from(*b.value_balance())));
            for (asset, amount) in b.burn() {
                out.push(format!(
                    "  public: burn (ZIP 226) of {} units of asset {}",
                    amount.inner(),
                    hex::encode(asset.to_bytes())
                ));
            }
        }
        Some(OrchardBundle::OrchardVanilla(b)) => {
            out.push(format!("Orchard bundle: {} action(s); amounts and parties hidden", b.actions().len()));
        }
        None => {}
    }
    Ok(out)
}
