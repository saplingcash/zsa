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
| `address` | Prints a test wallet's unified address (test network, Orchard receiver): the address a burn memo names. |
| `serve` | The issuer service: watches Solana for burns of every burn twin and issues each twin once, citing the burn ([RULES.md §5](docs/RULES.md)). It holds the issuer key (`--key`), or asks threshold signers (`--group`, `--signers`, `--threshold`). |
| `signer dkg`, `signer serve` | A threshold signer of a FROST group issuer key: one participant's part of the key generation, and a signing server that checks each issuance on its own before signing ([RULES.md §6](docs/RULES.md)). |
| `issue <coin-dir>` | Builds and submits an issuance on a ZSA test node, optionally with a burn citation. |
| `holder balance / send / burn` | The holder's side: a test wallet's balance of a twin, sending it on to a fresh address, and burning part of it on Zcash (ZIP 226). |
| `inspect <txid>` | Prints what anyone can read from the chain about a transaction, and what stays hidden. |
| `pages` | Generates a static HTML page per twin (and an index) from an audit run. |
| `check <coin-dir>` | Re-derives a twin's issuances from public data only: the metadata, the asset id, the transactions, the issuer's signature and the node's supply record. |
| `audit` | Applies [docs/RULES.md](docs/RULES.md) to every twin in `registry/`, by scanning the chain. |
| `frost-selftest` | On a **local** ZSA node: issues under a 2-of-3 FROST group key, and checks what the node accepts and refuses. |
| `local-vectors` | Issues deliberately bad twin issuances on a **local** ZSA node, runs `audit` on a throwaway registry, and checks each verdict. It refuses any node that is not on localhost. |

The published twins are in `assets/`, and the listed issuer keys are in `registry/`.

## Trust model

- **The issuer is trusted.** Whoever can sign for the issuer key could issue without a burn, or refuse
  to issue. With a single key, that is its holder. With a threshold issuer, it takes `t` of the `n`
  signers: no one holds the whole key.
  Demo coin 3's issuer is a 2-of-3 FROST group key.
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
- counts every ZIP 226 burn of a twin, by anyone;
- compares each twin's supply with the node's record: supply = issued − burned, and for a burn twin,
  valid issuances − burned.

**What is public, and when.** Measured on QEDIT's ZSA test network with `zsa inspect`:

| Step | Public on chain | Hidden |
|---|---|---|
| Issuance (ZIP 227) | the issuer, the asset, the amount, the recipient address, the burn citation | nothing |
| Holder sends the twin on to a fresh address (OrchardZSA transfer) | one nullifier and one note commitment per action | the asset, the amounts, the sender, the recipient |
| Burn on Zcash (ZIP 226) | the asset and the amount burned | who burned it; the rest of the transaction |

The issued notes are public, but their nullifiers need the holder's key, so the transfer that spends
them cannot be linked to the issuance from the chain alone (timing aside). Explorers may show less
than is public: the issuance details are in the raw transaction, which `zsa inspect` decodes.

**Burn to twin, on Solana devnet and the ZSA test network.** The burn and the issuance need the
holder's devnet test keys and the issuer's key, which never leave the machines that hold them (the
burn script reads a devnet payer key and the coin's mint key from local key files). The last step,
`audit`, needs no key and can be run by anyone:

```
# the holder's Zcash address (a test wallet)
$HOME/zsa/target/release/zsa address --key <holder key file>

# burn 25 tokens of demo coin 2 on devnet, with the memo sapling-twin:1:<that address>
node solana/burn-for-twin.mjs demo-coin-2 25 utest1...

# the issuer service answers the burn with the twin, then anyone can check both chains
$HOME/zsa/target/release/zsa serve --key <issuer key file> --once
$HOME/zsa/target/release/zsa audit
```

`audit` then shows the issuance as valid, backed by that burn: the signature, the slot and the
address.

**The holder's side**, with the holder's test key (account 0 is the address the burn memo named,
account 1 a fresh address of the same wallet):

```
$HOME/zsa/target/release/zsa holder balance assets/demo-coin-2 --key <holder key file>
$HOME/zsa/target/release/zsa holder send assets/demo-coin-2 --amount 10000000 --key <holder key file>
$HOME/zsa/target/release/zsa holder burn assets/demo-coin-2 --amount 3000000 --key <holder key file>
$HOME/zsa/target/release/zsa inspect <txid>
```

**Threshold issuer (2-of-3 FROST).** Demo coin 3 is issued under a FROST group key. Three signer
processes each hold a key share, and the service holds no key:

```
# key generation: one process per participant, each writes its own share
zsa signer dkg --id 1 --n 3 --t 2 --exchange <dir> --share <share file> --group <group file>
#   (the same with --id 2 and --id 3)

# each signer, with its own share
zsa signer serve --share <share file> --group <group file> --listen 127.0.0.1:39301

# the service asks the signers; 2 of the 3 must agree
zsa serve --group <group file> --signers 127.0.0.1:39301,127.0.0.1:39302,127.0.0.1:39303 --threshold 2
```

With one signer offline, the other two sign and the twin is issued. With only one signer online,
there is no signature and nothing is issued; the burn waits until a second signer is back. On chain,
the signature is one ordinary BIP-340 signature, so `check` and `audit` work as for any issuer. What
each signer checks, and the limits of this setup, are in [RULES.md §6](docs/RULES.md).

**A page per twin:** `zsa pages --out site` writes `site/index.html` and one page per twin: the asset,
its supply, every issuance with the Solana burn behind it, every burn on Zcash, the audit result, the
published metadata and the trust model. The pages are published at https://saplingcash.github.io/zsa/:
`.github/workflows/pages.yml` runs the audit and regenerates them on every change to `main` and once a
day.

**Test vectors.** These run against a local ZSA node: QEDIT's Zebra in Docker (rootless works),
regtest with ZSA active from height 1, RPC on `127.0.0.1:38232` only, and a fresh chain on every start.

```
sh scripts/local-node.sh build      # clones QEDIT's Zebra at the pinned commit and builds the image
sh scripts/local-node.sh start
$HOME/zsa/target/release/zsa local-vectors
sh scripts/local-node.sh stop
```

The vectors cover:

- a valid burn issuance;
- the same burn cited twice;
- a burn twin with no citation;
- a citation whose amount differs;
- a test twin carrying a citation;
- an asset not in the registry;
- an issuance by a key that is not listed (ignored);
- a finalized twin;
- an issuance after the key's range closed;
- forged metadata;
- a burn on Zcash of more than was validly issued (flagged: a burn cannot make other units valid);
- a burn on Zcash of an asset that is not a twin (not counted).

Each must get exactly the verdict docs/RULES.md predicts, with no other failure.

**Limits:**

- The asset base, note parsing and the signature scheme come from QEDIT's crates. The tools are not an
  independent implementation of the protocol.
- They trust the node to serve the chain.
- The Solana-side checks read the cited burn from the cluster's public RPC, at `finalized`
  commitment. They trust that RPC to serve the chain.

## Layout

```
src/                     the `zsa` tool (Rust)
assets/<coin>/           a twin's metadata, issuer and issuance txids
registry/                listed issuer keys (with validity heights) and twins
docs/RULES.md            what counts as a valid twin issuance
docs/METADATA.md         the metadata format (Cachet v1) and the Solana link
solana/                  Solana devnet helpers (test mints, burns for a twin); devnet/localnet only
scripts/cargo-wsl.sh     build with the output on the Linux filesystem
scripts/local-node.sh    a local ZSA node (QEDIT's Zebra) in Docker, for the test vectors
scripts/public_check.py  leak guard, run in CI and in the git hooks
tests/                   tests for the leak guard; tests/fixtures: real devnet transactions for the Solana checks
```

To turn on the git hooks after cloning:

```
git config core.hooksPath .githooks
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

By Sapling (sapling.cash). Not affiliated with QEDIT, Electric Coin Co., the Zcash Foundation, Shielded
Labs or Cachet.
