# Changelog

Notable changes to `zsa`, the registry and the published twins. Versions follow
[Semantic Versioning](https://semver.org/); while the version is 0.x, the command line, the registry
format and the rules can change between minor versions.

Everything here runs on test networks only: QEDIT's public ZSA test network (or a local ZSA node) and
Solana devnet. Test-network assets have no value.

## [Unreleased]

### Changed

- README: a quickstart from a clean Debian or Ubuntu machine to `zsa audit`. The Sapling proving
  parameters are only needed to build issuances, not for `check`, `audit`, `inspect` or `pages`.
- `check` on a burn twin with no `issuances.txt` says to run `audit` or to pass `--txid`, instead of
  a bare file error.

### Tests

- Unit tests for the threshold issuer that need no node: FROST signatures verify under the issuer key;
  tweaked, foreign, altered and wrong-message signatures do not; one signer cannot sign; DKG through a
  directory; a signer signs only the checked sighash, once, and drops expired sessions.

## [0.1.0]

The first tagged version.

### Twins, metadata and registry

- `describe`: a twin's Cachet v1 bundle and envelope from its `coin.json`, and its asset identifiers
  (the ZIP 227 description hash and the asset base).
- `registry/issuers.json`: issuer keys (`[0x00] || ik`) per network, each with `valid_from` and
  `valid_until` heights. A network is identified by its genesis block hash.
- `registry/twins.json`: twins by kind (`burn`, `direct-test`, `undisclosed-test`).
- Demo coins 1, 2 and 3 (no value), with test mints on Solana devnet. Demo coin 3 is issued under a
  2-of-3 FROST group key (issuer 2).

### Issuance

- `keygen`, `issuer`, `address`, and `issue` with an optional burn citation. The citation is a 77-byte
  `OP_RETURN` in the issuance transaction: `SPLT`, version 1, the 64-byte Solana signature, and the
  amount (u64 little-endian).
- `serve`: the issuer service. It answers each valid Solana burn of a burn twin once, to the memo's
  address. Each issuance is written to the state file before it is submitted, and re-submitted byte for
  byte after a restart.
- Threshold issuer: FROST(secp256k1, SHA-256) with BIP-340 signatures, untweaked, as the ZIP 227
  issuer key.
  - `signer dkg`: one participant's part of the distributed key generation.
  - `signer serve`: checks each issuance on its own before it signs.
  - `serve --group --signers --threshold`: the service holds no key and asks the signers.
  - `frost-selftest`, on a local node.

### Checking

- `check`: one twin from public data. It checks:
  - the metadata, and the ZIP 227 description hash, computed twice (directly and with orchard);
  - the asset id;
  - each transaction's bytes and the issuer;
  - the BIP-340 issuance signature over the sighash;
  - the node's supply record.
- `audit`: applies docs/RULES.md to every twin. It:
  - scans the chain from the earliest issuer height;
  - classifies each issuance as valid, unbacked, duplicate, malformed or an unknown asset;
  - checks each cited burn on Solana at `finalized` commitment;
  - counts every ZIP 226 burn of a twin;
  - compares supply (issued − burned) with the node's record.
- `pages`: a static page per twin and an index, generated from an audit run.
- `inspect`: what the chain shows about a transaction, and what stays hidden.
- `local-vectors`: deliberately bad issuances and burns on a local ZSA node, each with the verdict
  docs/RULES.md predicts.

### Holder side

- `holder balance`, `holder send` (to a fresh address of the same wallet) and `holder burn` (ZIP 226).

### Solana and tooling

- Solana devnet helpers: `solana/create-test-mint.mjs` and `solana/burn-for-twin.mjs`.
- Solana RPC calls retry on HTTP 429.
- `scripts/local-node.sh`: QEDIT's Zebra (`zsa1`, 8c9c93fd) in Docker, regtest with NU7 active from
  height 1.
- `scripts/cargo-wsl.sh`: builds from a Windows-drive checkout with the build output on the Linux
  filesystem.
- `scripts/public_check.py`: a check for files that must not be published. It runs in CI and in the
  git hooks.

[Unreleased]: https://github.com/saplingcash/zsa/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saplingcash/zsa/releases/tag/v0.1.0
