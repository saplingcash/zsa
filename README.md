# saplingcash/zsa

Twins of Sapling (sapling.cash) coins as Zcash Shielded Assets: OrchardZSA assets
([ZIP 226](https://zips.z.cash/zip-0226) / [ZIP 227](https://zips.z.cash/zip-0227)). A twin is issued
one-way when its coin is burned on Solana. Anyone can check every issued unit from public data.

> **Test networks only.** Zcash Shielded Assets are not active on Zcash mainnet. Everything here runs
> on QEDIT's public ZSA test network (or a local ZSA node) and on Solana devnet. Test-network assets
> have **no value**. Never pay for them.

## What is here

The `zsa` command-line tool:

| Command | What it does |
|---|---|
| `describe <coin-dir>` | Builds a twin's metadata from `coin.json`, and prints its asset identifiers. The metadata is a Cachet v1 bundle and envelope; see [docs/METADATA.md](docs/METADATA.md). |
| `keygen`, `issuer` | Creates a test issuer key (a BIP-39 phrase), and prints its public issuer key. |
| `issue <coin-dir>` | Builds and submits an issuance on a ZSA test node, optionally with a burn citation. |
| `check <coin-dir>` | Re-derives a twin's issuances from public data only: the metadata, the asset id, the transactions, the issuer's signature and the node's supply record. |
| `audit` | Applies [docs/RULES.md](docs/RULES.md) to every twin in `registry/`, by scanning the chain. |

The published twins are in `assets/`, and the listed issuer keys are in `registry/`.

## Trust model

- **The issuer is trusted.** It holds the issuance key, so it could issue without a burn, or refuse to
  issue.
- **`check` and `audit` make that visible.** Anyone can run them, with no key, no account and no
  database.
- **ZIP 227 issuance is public.** The first recipient address and the amount are visible on Zcash.
  Privacy starts when the holder moves the twin on to a fresh address.
- **One-way.** Burning a twin on Zcash releases nothing on Solana.

## Check it yourself

You need Linux (or WSL), Rust, a C compiler and OpenSSL headers. You also need the Sapling proving
parameters in `~/.zcash-params`: `sapling-spend.params` and `sapling-output.params` from
https://download.z.cash/downloads/. Their SHA-256 values are in `.github/workflows/public-check.yml`.

```
sh scripts/cargo-wsl.sh build --release --locked
$HOME/zsa/target/release/zsa check assets/demo-coin-1
$HOME/zsa/target/release/zsa audit
```

**`check`** prints one line per step:

1. The metadata is a canonical Cachet v1 pair and names a Solana test mint.
2. The ZIP 227 description hash is computed twice, with `blake2b_simd` directly and with orchard's
   `compute_asset_desc_hash`, and the two agree.
3. The asset base is derived from the published issuer.
4. Each transaction's bytes hash to its txid.
5. The issuer is the published one.
6. The BIP-340 issuance signature verifies over the sighash. Twin issuances have no transparent
   inputs, so the sighash equals the txid digest (ZIP 244).
7. A first issuance passes orchard's `verify_issue_bundle`.
8. The node's `getassetstate` record matches.

**`audit`** does the following:

- scans every block from the earliest listed issuer height to the tip;
- classifies each issuance by a listed issuer: valid, unbacked, duplicate, malformed, or unknown asset;
- compares each twin's supply with the node's record.

**Limits:**

- The asset base, note parsing and the signature scheme come from QEDIT's crates. The tools are not an
  independent implementation of the protocol.
- They trust the node to serve the chain.
- The Solana-side checks of the rules (RULES.md §2, "against Solana") are not implemented in this
  version.

## Layout

```
src/                     the `zsa` tool (Rust)
assets/<coin>/           a twin's metadata, issuer and issuance txids
registry/                listed issuer keys (with validity heights) and twins
docs/RULES.md            what counts as a valid twin issuance
docs/METADATA.md         the metadata format (Cachet v1) and the Solana link
solana/                  Solana devnet helpers (test mints); devnet/localnet only
scripts/cargo-wsl.sh     build with the output on the Linux filesystem
scripts/public_check.py  leak guard, run in CI and in the git hooks
tests/                   tests for the leak guard
```

To turn on the git hooks after cloning:

```
git config core.hooksPath .githooks
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

By Sapling (sapling.cash). Not affiliated with QEDIT, Electric Coin Co., the Zcash Foundation, Shielded
Labs or Cachet.
