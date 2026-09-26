//! Reading the chain: every issuance in a block, and the burn citation (docs/RULES.md §2.7).

use std::io::Cursor;

use sha2::{Digest, Sha256};
use zcash_encoding::CompactSize;
use zcash_primitives::block::BlockHeader;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

pub const CITATION_TAG: &[u8; 4] = b"SPLT";
pub const CITATION_VERSION: u8 = 1;
pub const CITATION_LEN: usize = 4 + 1 + 32 + 8;

/// A burn citation: which Solana burn an issuance answers, and for how much.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Citation {
    pub burn_sig_sha256: [u8; 32],
    pub amount: u64,
}

impl Citation {
    /// From a Solana transaction signature (base58, 64 bytes) and the burned amount.
    pub fn for_burn(signature_b58: &str, amount: u64) -> Result<Self, String> {
        let sig = crate::metadata::base58_decode(signature_b58)
            .filter(|b| b.len() == 64)
            .ok_or_else(|| format!("{signature_b58} is not a 64-byte base58 Solana signature"))?;
        Ok(Self { burn_sig_sha256: Sha256::digest(&sig).into(), amount })
    }

    pub fn encode(&self) -> [u8; CITATION_LEN] {
        let mut out = [0u8; CITATION_LEN];
        out[..4].copy_from_slice(CITATION_TAG);
        out[4] = CITATION_VERSION;
        out[5..37].copy_from_slice(&self.burn_sig_sha256);
        out[37..].copy_from_slice(&self.amount.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != CITATION_LEN || &data[..4] != CITATION_TAG || data[4] != CITATION_VERSION {
            return None;
        }
        Some(Self {
            burn_sig_sha256: data[5..37].try_into().ok()?,
            amount: u64::from_le_bytes(data[37..].try_into().ok()?),
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

/// Every transaction of a raw block that carries an issuance bundle, with its position.
pub fn issuances_in_block(raw: &[u8]) -> Result<Vec<(usize, Transaction)>, String> {
    let mut r = Cursor::new(raw);
    BlockHeader::read(&mut r).map_err(|e| format!("block header: {e}"))?;
    let n = CompactSize::read(&mut r).map_err(|e| format!("tx count: {e}"))?;
    let mut found = Vec::new();
    for i in 0..n as usize {
        let tx = Transaction::read(&mut r, BranchId::Nu6).map_err(|e| format!("tx {i}: {e}"))?;
        if tx.issue_bundle().is_some() {
            found.push((i, tx));
        }
    }
    if r.position() as usize != raw.len() {
        return Err("trailing bytes after the last transaction".into());
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn citation_round_trips_and_rejects_others() {
        let sig = crate::metadata::base58_encode(&[7u8; 64]);
        let c = Citation::for_burn(&sig, 1_000_000).unwrap();
        let bytes = c.encode();
        assert_eq!(bytes.len(), 45);
        assert_eq!(&bytes[..5], b"SPLT\x01");
        assert_eq!(Citation::decode(&bytes), Some(c));
        let mut wrong = bytes;
        wrong[4] = 2;
        assert_eq!(Citation::decode(&wrong), None);
        assert_eq!(Citation::decode(&bytes[..44]), None);
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
