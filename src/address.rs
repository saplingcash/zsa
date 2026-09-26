//! Zcash unified addresses (ZIP 316) with an Orchard receiver: what a burn memo names.

use zcash_address::unified::{self, Container, Encoding};
use zcash_protocol::consensus::NetworkType;

/// The Orchard receiver (43 raw bytes) of a unified address for a test network.
pub fn orchard_receiver(ua: &str) -> Result<[u8; 43], String> {
    let (net, addr) = unified::Address::decode(ua).map_err(|e| format!("not a unified address: {e}"))?;
    if !matches!(net, NetworkType::Test | NetworkType::Regtest) {
        return Err("a mainnet address; test networks only".into());
    }
    addr.items()
        .into_iter()
        .find_map(|r| match r {
            unified::Receiver::Orchard(bytes) => Some(bytes),
            _ => None,
        })
        .ok_or_else(|| "the unified address has no Orchard receiver".to_string())
}

/// A unified address (test network) with only this Orchard receiver.
pub fn encode_orchard(receiver: [u8; 43]) -> Result<String, String> {
    unified::Address::try_from_items(vec![unified::Receiver::Orchard(receiver)])
        .map(|a| a.encode(&NetworkType::Test))
        .map_err(|e| format!("encoding: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_refusals() {
        let ua = encode_orchard([7u8; 43]).unwrap();
        assert!(ua.starts_with("utest1"), "{ua}");
        assert_eq!(orchard_receiver(&ua).unwrap(), [7u8; 43]);
        let main = unified::Address::try_from_items(vec![unified::Receiver::Orchard([7u8; 43])])
            .unwrap()
            .encode(&NetworkType::Main);
        assert!(orchard_receiver(&main).unwrap_err().contains("mainnet"));
        assert!(orchard_receiver("not-an-address").is_err());
    }
}
