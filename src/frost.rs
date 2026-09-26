//! FROST(secp256k1, SHA-256) with BIP-340 signatures (the Zcash Foundation's `frost-secp256k1-tr`),
//! used untweaked: an aggregate signature is a plain BIP-340 signature under the x-only group key,
//! which is what ZIP 227's `issueAuthSig` is.

use std::collections::BTreeMap;

use frost_secp256k1_tr as frost;
use rand::rngs::OsRng;

pub use frost::keys::{KeyPackage, PublicKeyPackage};
pub use frost::Identifier;

/// The x-only group key (32 bytes): the issuer key `ik`.
pub fn group_xonly(pkp: &PublicKeyPackage) -> Result<[u8; 32], String> {
    let vk = pkp.verifying_key().serialize().map_err(|e| e.to_string())?;
    vk[vk.len() - 32..].try_into().map_err(|_| "unexpected key length".to_string())
}

pub fn identifier(i: u16) -> Result<Identifier, String> {
    Identifier::try_from(i).map_err(|e| e.to_string())
}

/// Distributed key generation among `n` participants with threshold `t`, all three rounds run in
/// this process. Used by the local self-test; the signer processes run the same rounds separately.
pub fn dkg_in_process(n: u16, t: u16) -> Result<(BTreeMap<Identifier, KeyPackage>, PublicKeyPackage), String> {
    let ids: Vec<Identifier> = (1..=n).map(identifier).collect::<Result<_, _>>()?;
    let mut r1_secret = BTreeMap::new();
    let mut r1 = BTreeMap::new();
    for id in &ids {
        let (s, p) = frost::keys::dkg::part1(*id, n, t, OsRng).map_err(|e| e.to_string())?;
        r1_secret.insert(*id, s);
        r1.insert(*id, p);
    }
    let others = |id: &Identifier| -> BTreeMap<Identifier, _> {
        r1.iter().filter(|(k, _)| *k != id).map(|(k, v)| (*k, v.clone())).collect()
    };
    let mut r2_secret = BTreeMap::new();
    let mut r2_for: BTreeMap<Identifier, BTreeMap<Identifier, _>> = BTreeMap::new();
    for id in &ids {
        let (s, out) = frost::keys::dkg::part2(r1_secret.remove(id).expect("round 1"), &others(id)).map_err(|e| e.to_string())?;
        r2_secret.insert(*id, s);
        for (to, pkg) in out {
            r2_for.entry(to).or_default().insert(*id, pkg);
        }
    }
    let mut keys = BTreeMap::new();
    let mut pkp = None;
    for id in &ids {
        let (kp, p) = frost::keys::dkg::part3(&r2_secret[id], &others(id), &r2_for[id]).map_err(|e| e.to_string())?;
        keys.insert(*id, kp);
        pkp = Some(p);
    }
    Ok((keys, pkp.expect("n >= 1")))
}

/// Round 1 for one signer: fresh nonces and their public commitments.
pub fn commit(key: &KeyPackage) -> (frost::round1::SigningNonces, frost::round1::SigningCommitments) {
    frost::round1::commit(key.signing_share(), &mut OsRng)
}

pub type SigningCommitments = frost::round1::SigningCommitments;
pub type SigningNonces = frost::round1::SigningNonces;
pub type SigningPackage = frost::SigningPackage;
pub type SignatureShare = frost::round2::SignatureShare;

pub fn signing_package(commitments: BTreeMap<Identifier, SigningCommitments>, message: &[u8]) -> SigningPackage {
    frost::SigningPackage::new(commitments, message)
}

/// Round 2 for one signer. `tweak` is only for demonstrating that a Taproot-tweaked signature is
/// refused; issuance never uses it.
pub fn sign_share(package: &SigningPackage, nonces: &SigningNonces, key: &KeyPackage, tweak: bool) -> Result<SignatureShare, String> {
    if tweak {
        frost::round2::sign_with_tweak(package, nonces, key, None)
    } else {
        frost::round2::sign(package, nonces, key)
    }
    .map_err(|e| e.to_string())
}

/// The coordinator's last step: check every share and aggregate them into a 64-byte signature.
pub fn aggregate(
    package: &SigningPackage,
    shares: &BTreeMap<Identifier, SignatureShare>,
    pkp: &PublicKeyPackage,
    tweak: bool,
) -> Result<Vec<u8>, String> {
    if tweak {
        frost::aggregate_with_tweak(package, shares, pkp, None)
    } else {
        frost::aggregate(package, shares, pkp)
    }
    .map_err(|e| e.to_string())?
    .serialize()
    .map_err(|e| e.to_string())
}

/// All of signing in one process (the local self-test): commitments, shares, aggregate.
pub fn sign_in_process(
    keys: &BTreeMap<Identifier, KeyPackage>,
    signers: &[Identifier],
    pkp: &PublicKeyPackage,
    message: &[u8],
    tweak: bool,
) -> Result<Vec<u8>, String> {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in signers {
        let (n, c) = commit(&keys[id]);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let package = signing_package(commitments, message);
    let mut shares = BTreeMap::new();
    for id in signers {
        shares.insert(*id, sign_share(&package, &nonces[id], &keys[id], tweak)?);
    }
    aggregate(&package, &shares, pkp, tweak)
}

/// Distributed key generation, one participant at a time (each signer process runs its own part).
pub mod dkg {
    use super::*;

    pub type Round1Secret = frost::keys::dkg::round1::SecretPackage;
    pub type Round1Package = frost::keys::dkg::round1::Package;
    pub type Round2Secret = frost::keys::dkg::round2::SecretPackage;
    pub type Round2Package = frost::keys::dkg::round2::Package;

    pub fn part1(id: Identifier, n: u16, t: u16) -> Result<(Round1Secret, Round1Package), String> {
        frost::keys::dkg::part1(id, n, t, OsRng).map_err(|e| e.to_string())
    }

    pub fn part2(
        secret: Round1Secret,
        others: &BTreeMap<Identifier, Round1Package>,
    ) -> Result<(Round2Secret, BTreeMap<Identifier, Round2Package>), String> {
        frost::keys::dkg::part2(secret, others).map_err(|e| e.to_string())
    }

    pub fn part3(
        secret: &Round2Secret,
        others_r1: &BTreeMap<Identifier, Round1Package>,
        for_me: &BTreeMap<Identifier, Round2Package>,
    ) -> Result<(KeyPackage, PublicKeyPackage), String> {
        frost::keys::dkg::part3(secret, others_r1, for_me).map_err(|e| e.to_string())
    }
}
