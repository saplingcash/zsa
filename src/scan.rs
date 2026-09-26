//! Reading the chain: every issuance in a block, and the burn citation (docs/RULES.md §2.7).

use std::io::Cursor;

use zcash_encoding::CompactSize;
use zcash_primitives::block::BlockHeader;
use orchard::note::AssetBase;
use zcash_primitives::transaction::{OrchardBundle, Transaction};
use zcash_protocol::consensus::BranchId;

pub const CITATION_TAG: &[u8; 4] = b"SPLT";
pub const CITATION_VERSION: u8 = 1;
pub const CITATION_LEN: usize = 4 + 1 + 64 + 8;

/// A burn citation: the Solana burn an issuance answers (its full signature), and for how much.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Citation {
    pub burn_signature: [u8; 64],
    pub amount: u64,
}

impl Citation {
    /// From a Solana transaction signature (base58, 64 bytes) and the burned amount.
    pub fn for_burn(signature_b58: &str, amount: u64) -> Result<Self, String> {
        let sig: [u8; 64] = crate::metadata::base58_decode(signature_b58)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| format!("{signature_b58} is not a 64-byte base58 Solana signature"))?;
        Ok(Self { burn_signature: sig, amount })
    }

    /// The cited Solana signature, base58.
    pub fn signature_b58(&self) -> String {
        crate::metadata::base58_encode(&self.burn_signature)
    }

    pub fn encode(&self) -> [u8; CITATION_LEN] {
        let mut out = [0u8; CITATION_LEN];
        out[..4].copy_from_slice(CITATION_TAG);
        out[4] = CITATION_VERSION;
        out[5..69].copy_from_slice(&self.burn_signature);
        out[69..].copy_from_slice(&self.amount.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != CITATION_LEN || &data[..4] != CITATION_TAG || data[4] != CITATION_VERSION {
            return None;
        }
        Some(Self {
            burn_signature: data[5..69].try_into().ok()?,
            amount: u64::from_le_bytes(data[69..].try_into().ok()?),
        })
    }
}

/// The data of every OP_RETURN output (`OP_RETURN <one push>`); `None` for an OP_RETURN script that
/// is not exactly one push.
pub fn null_data_outputs(tx: &Transaction) -> Vec<Option<Vec<u8>>> {
    let Some(bundle) = tx.transparent_bundle() else { return Vec::new() };
    bundle
        .vout
        .iter()
        .map(|out| out.script_pubkey().0.0.clone())
        .filter(|s| s.first() == Some(&0x6a))
        .map(|s| parse_single_push(&s[1..]))
        .collect()
}

fn parse_single_push(rest: &[u8]) -> Option<Vec<u8>> {
    let (&op, body) = rest.split_first()?;
    let (len, data) = match op {
        1..=75 => (op as usize, body),
        0x4c => (*body.first()? as usize, &body[1..]),
        _ => return None,
    };
    (data.len() == len).then(|| data.to_vec())
}

/// Every transaction of a raw block, with its position.
pub fn transactions_in_block(raw: &[u8]) -> Result<Vec<(usize, Transaction)>, String> {
    let mut r = Cursor::new(raw);
    BlockHeader::read(&mut r).map_err(|e| format!("block header: {e}"))?;
    let n = CompactSize::read(&mut r).map_err(|e| format!("tx count: {e}"))?;
    let mut all = Vec::new();
    for i in 0..n as usize {
        all.push((i, Transaction::read(&mut r, BranchId::Nu6).map_err(|e| format!("tx {i}: {e}"))?));
    }
    if r.position() as usize != raw.len() {
        return Err("trailing bytes after the last transaction".into());
    }
    Ok(all)
}

/// Every transaction of a raw block that carries an issuance bundle, with its position.
pub fn issuances_in_block(raw: &[u8]) -> Result<Vec<(usize, Transaction)>, String> {
    Ok(transactions_in_block(raw)?.into_iter().filter(|(_, tx)| tx.issue_bundle().is_some()).collect())
}

/// The ZIP 226 burns of a transaction: public (asset base, amount) pairs.
pub fn zsa_burns(tx: &Transaction) -> Vec<(AssetBase, u64)> {
    match tx.orchard_bundle() {
        Some(OrchardBundle::OrchardZSA(b)) => b.burn().iter().map(|(a, v)| (*a, v.inner())).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn citation_round_trips_and_rejects_others() {
        let sig = crate::metadata::base58_encode(&[7u8; 64]);
        let c = Citation::for_burn(&sig, 1_000_000).unwrap();
        let bytes = c.encode();
        assert_eq!(bytes.len(), 77);
        assert!(bytes.len() <= 80, "OP_RETURN relay limit");
        assert_eq!(c.signature_b58(), sig);
        assert_eq!(&bytes[..5], b"SPLT\x01");
        assert_eq!(Citation::decode(&bytes), Some(c));
        let mut wrong = bytes;
        wrong[4] = 2;
        assert_eq!(Citation::decode(&wrong), None);
        assert_eq!(Citation::decode(&bytes[..76]), None);
        assert!(Citation::for_burn("11111111111111111111111111111111", 1).is_err());
    }

    #[test]
    fn single_push_parsing() {
        assert_eq!(parse_single_push(&[3, 1, 2, 3]), Some(vec![1, 2, 3]));
        assert_eq!(parse_single_push(&[0x4c, 2, 9, 9]), Some(vec![9, 9]));
        assert_eq!(parse_single_push(&[3, 1, 2]), None);
        assert_eq!(parse_single_push(&[3, 1, 2, 3, 4]), None);
        assert_eq!(parse_single_push(&[]), None);
    }
}
