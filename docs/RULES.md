# Rules: what counts as a twin issuance (v1)

Words used below:

- **Issuer:** a key listed in [`registry/issuers.json`](../registry/issuers.json).
- **Twin:** an asset listed in [`registry/twins.json`](../registry/twins.json).
- **Network:** a ZSA test network named in `registry/issuers.json`, identified by its genesis block
  hash.

`zsa audit` implements §1–§3, on Zcash and, for burn twins, against Solana.

## 1. The registry

- **`issuers.json`** lists each issuer key (`[0x00] || ik`, hex) with:
  - the network it issues on;
  - `valid_from`: the first height at which it may issue;
  - `valid_until`: the last such height, or `null`.

  A key is rotated by closing its range and adding a new key. It is never edited in place.
- **`twins.json`** lists each twin with its kind:
  - `burn`: issued only against burns on Solana. Its metadata is in `assets/<coin>/`.
  - `direct-test`: issued directly as a test, not against burns. Its metadata is in `assets/<coin>/`
    and says so.
  - `undisclosed-test`: a test asset issued while testing the tools, listed by its asset id only. Its
    description is not published, and it is never used for a coin.

The registry is the issuer's public commitment. Every change to it is visible in this repository's
history.

## 2. A valid twin issuance

A Zcash transaction is a **valid twin issuance** only if all of these hold:

1. **It is mined on the network.** The network is checked by its genesis hash, so a reset network is
   not confused with the old one.
2. **Its issuer is listed.** The issuance bundle's issuer is a listed key, valid at the transaction's
   height.
3. **It has no transparent inputs.** Its shielded sighash is therefore its txid digest (ZIP 244), and
   the BIP-340 issuance signature verifies over it.
4. **It issues exactly one listed twin.** It has exactly one issue action, for the asset of a listed
   twin. The asset is derived from the issuer and the twin's `envelope.txt`, whose metadata verifies
   ([METADATA.md](METADATA.md)).
5. **It has exactly one value note.** The action has one note with a value above zero. On the first
   issuance of the asset, it also has the zero-value reference note ZIP 227 requires.
6. **It is not finalized.** Twins follow burns, so their supply stays open.
7. **Burn twins only: it carries exactly one burn citation.** This is a zero-value `OP_RETURN` output
   of 77 bytes, inside the 80-byte relay limit:

   | Bytes | Field |
   |---|---|
   | 0–3 | `SPLT` (protocol tag) |
   | 4 | version `1` |
   | 5–68 | the Solana burn transaction's signature (64 raw bytes) |
   | 69–76 | the amount, u64 little-endian; must equal the value note's amount |

   The citation sits in the same transaction the issuer signs, so it is covered by the issuance
   signature. ZIP 227 issued notes have no memo field.
8. **Burn twins only: the cited burn checks out against Solana.** The checks run on the burn
   transaction the citation names, read at `finalized` commitment from the cluster's RPC in
   `registry/issuers.json`:
   - it exists and succeeded;
   - it has exactly one token burn (`burn` or `burnChecked`, top-level or inner), of this twin's mint;
   - it burns exactly the cited amount, in base units;
   - it carries exactly one memo `sapling-twin:1:<address>`, where `<address>` is a test-network
     unified address (ZIP 316) with an Orchard receiver;
   - the value note's recipient is that Orchard receiver.
9. **First valid citation wins.** It is the first transaction, in chain order (height, then position
   in the block), that satisfies 1–8 for that burn. Later ones are **duplicates**.

## 3. What `audit` reports

`audit` scans every block of the network, from the earliest `valid_from` of any listed issuer to the
tip. It collects every issuance signed by a listed issuer, and every ZIP 226 burn of a listed twin,
by anyone (a burn publishes the asset and the amount, not who burned).

**Per twin:**

- `burn` twins:
  - every issuance is valid, or it is reported as:
    - **unbacked**: no citation, its amount differs, or the burn does not check out against Solana;
    - **duplicate**;
    - **malformed**;
  - **the invariant:** supply on the node = the sum of valid issuances − the sum of burns on Zcash;
  - burns on Zcash of more than the sum of valid issuances are a failure: a burn cannot make other
    units valid.
- `direct-test` and `undisclosed-test` twins: the issuances and burns are listed and summed; issued −
  burned must equal the node's supply. The Solana rules do not apply.

**Across twins:**

- any issuance by a listed issuer of an asset **not** in `twins.json` is a failure (**unknown asset**);
- any finalized twin is a failure.

The result is OK only if nothing above failed.

## 4. What the rules cannot do

- **Stop the issuer.** The rules make a bad issuance visible, in one run, to anyone. They cannot stop
  it: whoever can sign for the issuer key can issue. With a threshold issuer (§6), that takes a
  threshold of the signers, not one key holder.
- **Return a burn that does not ask correctly.** A burn with no memo, two memos, an address that is
  not a test-network unified address with an Orchard receiver, or another coin's mint is never
  answered. The coins stay burned.
- **Protect privacy at issuance.** ZIP 227 issuance is transparent. The recipient address and the
  amount are public. Privacy starts when the holder sends the twin on to a fresh address: an
  OrchardZSA transfer hides the asset, the amounts and the parties.
- **Work across a test-network reset.** A reset erases the Zcash side. The same key and description
  give the same asset id on a new network, and burns on Solana still stand. So after a reset, twins can
  be re-issued from the burns and checked again from scratch.

## 5. The issuer service

`zsa serve` answers burns automatically:

- It watches the Solana cluster of every `burn` twin for finalized transactions touching the twin's
  mint.
- It checks each one with the same code `audit` uses (§2.8), and issues the twin once, citing the
  burn, to the memo's address.
- A transaction that is not a valid twin burn is recorded as skipped, with the reason, and not retried.

**Answering at most once:**

- The burns already cited by the issuer are found by scanning the chain, so a lost state file never
  causes a second answer.
- Every issuance is written to the state file, with its raw bytes, before it is submitted.
- After a restart, an issuance that is not on chain yet is re-submitted byte for byte, never rebuilt.

## 6. A threshold issuer

An issuer key can be a FROST group key (RFC 9591, the ciphersuite FROST(secp256k1, SHA-256) with
BIP-340 signatures). The listed key is the group's x-only public key, `[0x00] || ik`, like any other
issuer key. On chain, a threshold issuance is an ordinary ZIP 227 issuance: one BIP-340 signature
under `ik`. The rules in §1–§5 apply unchanged, and `audit` does not need to know which kind of
issuer signed.

- **Key generation.** `zsa signer dkg` is one participant's part of FROST's distributed key
  generation. Each participant ends with its own key share and the group's public key package. The
  full issuance key `isk` is never formed, by anyone.
- **Signing.** `zsa signer serve` holds one key share. The issuer service (`zsa serve --group`)
  holds no key. It builds the issuance, asks the signers, and needs `t` of the `n` signers to agree.
  It then aggregates their shares into the signature and checks it before submitting.
- **Each signer checks the issuance on its own** before it commits to a signing session:
  - the transaction's issuer is the group key;
  - its shape is a twin issuance (§2);
  - the twin is a listed `burn` twin of this group;
  - the cited burn is a valid twin burn on Solana (§2.8), for the cited amount, to the recipient in
    its memo;
  - the burn has not already been answered on chain.

  In the signing round it signs only the sighash of the transaction it checked. Each nonce is used
  once, and a session expires after 300 seconds.
- **Fewer than `t` signers** means no signature and no issuance. The burn stays unanswered and is
  tried again on the next pass.
- **Untweaked keys only.** A Taproot-tweaked FROST signature (BIP-341) is not valid under `ik`, and the
  node refuses it.

**Limits of the implementation here:**

- The signers talk to the service over plain TCP, one JSON line per request. Run them on a private
  network.
- The DKG exchanges its packages through a shared directory. That suits processes on one machine. The
  second-round packages are secret: between machines, they need authenticated, confidential channels.
- The demo runs all signers on one machine. Separate machines, operators and RPC endpoints are what
  make the signers independent in practice.
