// Create a Solana DEVNET test coin shaped like a pump.fun coin: a Token-2022 mint, 6 decimals,
// a fixed supply of 1,000,000,000 tokens minted to the payer, then the mint authority revoked.
//
// Devnet or a local validator ONLY: any other RPC URL is refused.
// Keys live in ../.private/keys (gitignored); nothing secret is printed.
//
// usage: node create-test-mint.mjs <coin-slug> [rpc-url]
//   e.g. node create-test-mint.mjs demo-coin-1

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Connection, Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  AuthorityType,
  createMint,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  setAuthority,
  getMint,
} from "@solana/spl-token";

const DECIMALS = 6;
const SUPPLY = 1_000_000_000n * 10n ** BigInt(DECIMALS);
const ALLOWED_RPC = [/^https:\/\/api\.devnet\.solana\.com\/?$/, /^http:\/\/(127\.0\.0\.1|localhost):\d+\/?$/];

const here = path.dirname(fileURLToPath(import.meta.url));
const keysDir = path.join(here, "..", ".private", "keys");

function loadOrCreate(file) {
  if (fs.existsSync(file)) {
    return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(file, "utf8"))));
  }
  const kp = Keypair.generate();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(Array.from(kp.secretKey)), { mode: 0o600 });
  return kp;
}

async function main() {
  const [slug, rpcArg] = process.argv.slice(2);
  if (!slug || !/^[a-z0-9-]{1,40}$/.test(slug)) throw new Error("usage: create-test-mint.mjs <coin-slug> [rpc-url]");
  const rpc = rpcArg ?? "https://api.devnet.solana.com";
  if (!ALLOWED_RPC.some((rx) => rx.test(rpc))) throw new Error(`refusing RPC ${rpc}: devnet or localhost only`);
  const conn = new Connection(rpc, "confirmed");

  const genesis = await conn.getGenesisHash();
  // devnet's genesis hash; a local validator has its own. Mainnet's is refused outright.
  if (genesis === "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d") throw new Error("mainnet genesis: refused");

  const payer = loadOrCreate(path.join(keysDir, "devnet-payer.json"));
  const mintKp = loadOrCreate(path.join(keysDir, `${slug}-mint.json`));
  console.log(`payer ${payer.publicKey.toBase58()}`);
  console.log(`mint  ${mintKp.publicKey.toBase58()}`);

  const existing = await conn.getAccountInfo(mintKp.publicKey);
  if (existing) {
    const m = await getMint(conn, mintKp.publicKey, "confirmed", TOKEN_2022_PROGRAM_ID);
    console.log(`mint exists: supply ${m.supply} decimals ${m.decimals} mintAuthority ${m.mintAuthority?.toBase58() ?? "none"}`);
    return;
  }

  let balance = await conn.getBalance(payer.publicKey);
  if (balance < 0.05 * LAMPORTS_PER_SOL) {
    console.log("requesting a devnet airdrop of 1 SOL ...");
    const sig = await conn.requestAirdrop(payer.publicKey, LAMPORTS_PER_SOL);
    await conn.confirmTransaction(sig, "confirmed");
    balance = await conn.getBalance(payer.publicKey);
  }
  console.log(`payer balance ${balance / LAMPORTS_PER_SOL} SOL (devnet)`);

  await createMint(conn, payer, payer.publicKey, null, DECIMALS, mintKp, { commitment: "confirmed" }, TOKEN_2022_PROGRAM_ID);
  const ata = await getOrCreateAssociatedTokenAccount(conn, payer, mintKp.publicKey, payer.publicKey, false, "confirmed", undefined, TOKEN_2022_PROGRAM_ID);
  const mintSig = await mintTo(conn, payer, mintKp.publicKey, ata.address, payer, SUPPLY, [], { commitment: "confirmed" }, TOKEN_2022_PROGRAM_ID);
  const revokeSig = await setAuthority(conn, payer, mintKp.publicKey, payer, AuthorityType.MintTokens, null, [], { commitment: "confirmed" }, TOKEN_2022_PROGRAM_ID);

  const m = await getMint(conn, mintKp.publicKey, "confirmed", TOKEN_2022_PROGRAM_ID);
  console.log(`created: supply ${m.supply} decimals ${m.decimals} mintAuthority ${m.mintAuthority?.toBase58() ?? "none"}`);
  console.log(`mintTo ${mintSig}`);
  console.log(`revoke ${revokeSig}`);
}

main().catch((e) => {
  console.error(String(e?.message ?? e));
  process.exit(1);
});
