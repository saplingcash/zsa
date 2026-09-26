//! `check`: re-derive a twin's issuance from public data only (the chain and the published
//! metadata), with no key and no database.
//!
//! What it establishes, in order:
//!  1. the published metadata is a valid Cachet v1 envelope + bundle, and names a Solana test mint;
//!  2. the asset description hash (BLAKE2b-256 "ZSA-AssetDescCRH"), computed here and by QEDIT's
//!     orchard crate, agree;
//!  3. the transaction fetched from the node has the requested txid (recomputed locally);
//!  4. its issuance bundle is signed by the published issuer key, and the BIP-340 signature verifies
//!     over the transaction's sighash (recomputed locally);
//!  5. it issues this description's asset: AssetBase = GroupHash(issuer, description hash), every
//!     note of the action is that asset, and the amount is reported;
//!  6. the node's own asset record (`getassetstate`) agrees with the supply seen.
//!
//! Limits: the asset base and the sighash use QEDIT's crates (not an independent implementation);
//! the supply comparison covers the issuances given (`audit` scans the whole chain).

use orchard::issuance::{IssueBundle, Signed, verify_issue_bundle};
use orchard::note::{AssetBase, AssetId};
use zcash_primitives::transaction::{OrchardBundle, Transaction};
use zcash_protocol::consensus::BranchId;

use crate::metadata;
use crate::rpc::Node;

pub struct Report {
    pub lines: Vec<(bool, String)>,
}

impl Report {
    pub fn new() -> Self {
        Self { lines: Vec::new() }
    }
    pub(crate) fn ok(&mut self, msg: impl Into<String>) {
        self.lines.push((true, msg.into()));
    }
    pub(crate) fn fail(&mut self, msg: impl Into<String>) {
        self.lines.push((false, msg.into()));
    }
    pub(crate) fn expect(&mut self, cond: bool, ok: impl Into<String>, fail: impl Into<String>) -> bool {
        if cond { self.ok(ok) } else { self.fail(fail) }
        cond
    }
    pub fn passed(&self) -> bool {
        self.lines.iter().all(|(ok, _)| *ok)
    }
}

pub fn check(envelope: &str, bundle: &[u8], issuer_hex: &str, txids: &[String], node: &Node) -> Report {
    let mut r = Report::new();

    // 1. metadata
    match metadata::verify_published(envelope, bundle) {
        Ok(t) => r.ok(format!(
            "metadata: Cachet v1 envelope and bundle verify; twin of Solana {} mint {} ({} decimals)",
            t.cluster, t.mint, t.decimals
        )),
        Err(problems) => {
            for p in problems {
                r.fail(format!("metadata: {p}"));
            }
            return r;
        }
    }

    // 2. description hash, two ways
    let ours = metadata::asset_desc_hash(envelope.as_bytes());
    let theirs = orchard::issuance::compute_asset_desc_hash(
        &nonempty::NonEmpty::from_slice(envelope.as_bytes()).expect("non-empty"),
    );
    if !r.expect(
        ours == theirs,
        format!("asset description hash {} (computed here and by orchard: equal)", hex::encode(ours)),
        "asset description hash: our BLAKE2b and orchard's disagree",
    ) {
        return r;
    }

    let issuer = match hex::decode(issuer_hex)
        .ok()
        .and_then(|b| orchard::issuance::auth::IssueValidatingKey::decode(&b).ok())
    {
        Some(ik) => ik,
        None => {
            r.fail(format!("published issuer key {issuer_hex} does not decode"));
            return r;
        }
    };
    let asset = AssetBase::custom(&AssetId::new_v0(&issuer, &ours));
    let asset_hex = hex::encode(asset.to_bytes());
    r.ok(format!("asset base {asset_hex} (from the published issuer and the description hash)"));

    let mut supply_seen: u64 = 0;
    let mut finalized_seen = false;
    for txid in txids {
        match check_issuance(&mut r, txid, &issuer_hex.to_lowercase(), &ours, asset, node) {
            Some((amount, finalized)) => {
                supply_seen = supply_seen.saturating_add(amount);
                finalized_seen |= finalized;
            }
            None => return r,
        }
    }

    // 6. the node's record
    match node.asset_state(&asset_hex) {
        Ok(Some(state)) => {
            r.expect(
                state.amount == supply_seen,
                format!("node asset record: supply {} = issued in the checked transactions", state.amount),
                format!(
                    "node asset record: supply {} but the checked transactions issue {supply_seen} (other issuances exist; list them all)",
                    state.amount
                ),
            );
            r.expect(
                state.is_finalized == finalized_seen,
                format!("node asset record: finalized = {}", state.is_finalized),
                format!("node asset record: finalized = {}, transactions say {finalized_seen}", state.is_finalized),
            );
        }
        Ok(None) => r.fail("node has no record of this asset"),
        Err(e) => r.fail(format!("node asset record: {e}")),
    }
    r
}

fn check_issuance(
    r: &mut Report,
    txid: &str,
    issuer_hex: &str,
    desc_hash: &[u8; 32],
    asset: AssetBase,
    node: &Node,
) -> Option<(u64, bool)> {
    // 3. fetch and recompute the txid
    let raw = match node.raw_tx(txid) {
        Ok(raw) => raw,
        Err(e) => {
            r.fail(format!("tx {txid}: {e}"));
            return None;
        }
    };
    let bytes = hex::decode(&raw.hex).ok()?;
    let tx = match Transaction::read(bytes.as_slice(), BranchId::Nu6) {
        Ok(tx) => tx,
        Err(e) => {
            r.fail(format!("tx {txid}: does not parse: {e}"));
            return None;
        }
    };
    if !r.expect(
        tx.txid().to_string() == txid,
        format!(
            "tx {txid}: txid recomputed from its bytes; height {}, {} confirmations",
            raw.height.map_or("?".into(), |h| h.to_string()),
            raw.confirmations.map_or("?".into(), |c| c.to_string())
        ),
        format!("tx {txid}: bytes hash to {}", tx.txid()),
    ) {
        return None;
    }

    // 4. issuer and signature
    let Some(bundle) = tx.issue_bundle() else {
        r.fail(format!("tx {txid}: no issuance bundle"));
        return None;
    };
    let bundle: &IssueBundle<Signed> = bundle;
    let tx_issuer = hex::encode(bundle.ik().encode());
    if !r.expect(
        tx_issuer == issuer_hex,
        format!("tx {txid}: issuer {tx_issuer} is the published issuer"),
        format!("tx {txid}: issuer {tx_issuer} is NOT the published issuer {issuer_hex}"),
    ) {
        return None;
    }
    // ZIP 244: with no transparent inputs, the shielded signature digest equals the txid digest.
    // (librustzcash cannot recompute a sighash over an already-authorized transaction's transparent
    // inputs without their spent outputs; twin issuances have none, so anything else is refused.)
    let has_transparent_inputs = tx.transparent_bundle().is_some_and(|b| !b.vin.is_empty());
    if !r.expect(
        !has_transparent_inputs,
        format!("tx {txid}: no transparent inputs, so the shielded sighash is the txid digest (ZIP 244)"),
        format!("tx {txid}: has transparent inputs; this checker only handles issuances without them"),
    ) {
        return None;
    }
    let sighash: [u8; 32] = *tx.txid().as_ref();
    let sig_ok = bundle.ik().verify(&sighash, bundle.authorization().signature().sig()).is_ok();
    if !r.expect(
        sig_ok,
        format!("tx {txid}: BIP-340 issuance signature verifies over the recomputed sighash"),
        format!("tx {txid}: issuance signature does NOT verify"),
    ) {
        return None;
    }

    // 5. the action for this description
    let Some(action) = bundle.get_action_by_desc_hash(desc_hash) else {
        r.fail(format!("tx {txid}: issues nothing under this description"));
        return None;
    };
    let mut amount: u64 = 0;
    for note in action.notes() {
        if note.asset() != asset {
            r.fail(format!("tx {txid}: a note of the action is not this asset"));
            return None;
        }
        let Some(sum) = amount.checked_add(note.value().inner()) else {
            r.fail(format!("tx {txid}: value overflow"));
            return None;
        };
        amount = sum;
    }
    let first = action.get_reference_note().is_some();
    if first {
        // Full consensus checks for a first issuance (reference note, rho derivation, signature).
        let first_nf = match tx.orchard_bundle() {
            Some(OrchardBundle::OrchardZSA(b)) => b.actions().first().nullifier().to_owned(),
            Some(OrchardBundle::OrchardVanilla(b)) => b.actions().first().nullifier().to_owned(),
            None => {
                r.fail(format!("tx {txid}: no Orchard bundle to derive issued notes' rho from"));
                return None;
            }
        };
        let full = verify_issue_bundle(bundle, sighash, |_| None, &first_nf);
        if !r.expect(
            full.is_ok(),
            format!("tx {txid}: orchard's verify_issue_bundle accepts it as a first issuance (reference note present)"),
            format!("tx {txid}: verify_issue_bundle: {:?}", full.err()),
        ) {
            return None;
        }
    }
    let finalized = action.is_finalized();
    let value_notes = action.notes().iter().filter(|n| n.value().inner() > 0).count();
    r.ok(format!(
        "tx {txid}: issues {} units of this asset in {} note(s){}; finalized: {finalized}",
        amount,
        value_notes,
        if first { " plus the zero-value reference note (first issuance)" } else { "" }
    ));
    Some((amount, finalized))
}
