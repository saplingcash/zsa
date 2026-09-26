# Metadata

Twins use **Cachet's metadata format v1**, unchanged. The link to the Solana coin is carried inside
fields that format already has.

## Why Cachet v1

We compared the two openly licensed metadata formats used on the ZSA test network:

| | Cachet v1 | ZecBit ZMD-1 |
|---|---|---|
| Spec | [`packages/registry-spec/README.md`](https://github.com/cachet-zec/cachet/blob/main/packages/registry-spec/README.md) | [`SPEC.md`](https://github.com/Zecbit-nft/zmd1/blob/main/SPEC.md) |
| License | MIT | MIT |
| Built for | any asset: name, supply, description, image | NFT items: a collection slug, an item index, media, a creator signature |
| On-chain `asset_desc` | JSON envelope `{"v":1,"name":"…","sha256":"<bundle hash>"}` | `zmd1\|<collection>\|<index>[\|<cid>\|<hash>]` |
| Bundle binding | SHA-256 of the bundle's exact bytes | BLAKE2b-256 of the JCS-canonical manifest |
| Mutability | immutable (the bundle hash is in the asset id) | minimal form mutable, full form immutable |

The comparison used Cachet at commit `0ba8969` and ZMD-1 at commit `97f56da`.

1. **It fits a coin.** A Sapling coin is one fungible asset. ZMD-1 describes numbered items of a
   collection, so it would make every twin "item 0 of a collection of one".
2. **It is immutable.** The bundle hash sits inside `asset_desc`, which sits inside the asset id, which
   the ZIP 227 issuance signature covers. The metadata cannot change after the first issuance.
3. **It is readable by existing tools.** Per Cachet's spec, any Cachet registry resolves a description
   without an account, by checking that it hashes to the on-chain value.
4. **It is short and fully specified.** The bundle's exact bytes are the serde_json serialization of a
   fixed struct.

ZMD-1 is carefully specified too, and it is the right fit for NFTs.

## How a twin uses it

**The envelope** is the ZIP 227 `asset_desc`, hashed into the asset id. It is exactly Cachet's:

```json
{"v":1,"name":"Sapling testnet demo coin 1 (no value)","sha256":"<hex sha-256 of the bundle bytes>"}
```

**The bundle** has exactly Cachet's fields, in Cachet's field order, serialized as Cachet serializes it
(serde_json, no whitespace):

```json
{"v":1,"name":"Sapling testnet demo coin 1 (no value)","description":"solana-twin:1:devnet:<mint base58>:6\n\n<free text>","external_url":"https://explorer.solana.com/address/<mint base58>?cluster=devnet"}
```

**The Solana link** is the bundle description's **first line**:

```
solana-twin:1:<cluster>:<mint base58>:<decimals>
```

- `cluster` is `devnet` or `localnet`. `mainnet` is refused by the tools until ZSAs are active on Zcash
  mainnet.
- The mint is base58, as Solana writes it.
- `decimals` is the coin's decimals. One twin unit equals one base unit of the coin, so no rounding
  ever happens.

**How the binding holds:**

- The first line is inside the bundle.
- The bundle's hash is inside the envelope.
- The envelope's hash is inside the asset id.

So the mint is bound to the asset by the issuance signature itself. A different mint is a different
asset.

**What the tools require**, on top of Cachet's own verification rule:

- the description's first line parses exactly as above;
- the cluster is allowed;
- a test-network twin's name ends in "(no value)";
- `external_url` names the same mint;
- both files are in canonical form: re-serializing them gives the same bytes.

**Byte-exactness.** Field order is `v, name, description, image_data_uri, external_url`, and absent
fields are omitted. The implementation (`src/metadata.rs`) is written independently from Cachet's
specification. Its tests pin the exact bytes.

**Images** are not used by twins yet. Cachet's limits: png, jpeg, webp or gif, at most 256,000 bytes
as a data URI, no SVG.
