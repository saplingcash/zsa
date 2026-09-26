// Burn a Solana DEVNET test coin for its OrchardZSA twin: one transaction with a Token-2022
// burnChecked from the payer's token account and a memo "sapling-twin:1:<zcash unified address>".
//
// Devnet or a local validator ONLY: any other RPC URL, and mainnet's genesis, are refused.
// The payer key lives in ../.private/keys (gitignored); nothing secret is printed.
//
// usage: node burn-for-twin.mjs <coin-slug> <amount in tokens> <zcash unified address> [--no-memo]
//   e.g. node burn-for-twin.mjs demo-coin-2 25 utest1...
//   --no-memo  burn without the memo (a burn that asks for nothing; used to test the checks)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  createBurnCheckedInstruction,
  getAssociatedTokenAddressSync,
  getMint,
} from "@solana/spl-token";

const MEMO_PROGRAM = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const ALLOWED_RPC = [/^https:\/\/api\.devnet\.solana\.com\/?$/, /^http:\/\/(127\.0\.0\.1|localhost):\d+\/?$/];
const MAINNET_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

const here = path.dirname(fileURLToPath(import.meta.url));
const keysDir = path.join(here, "..", ".private", "keys");
const loadKeypair = (f) => Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(f, "utf8"))));

async function main() {
  const args = process.argv.slice(2);
  const noMemo = args.includes("--no-memo");
  const [slug, amountArg, zcashAddress] = args.filter((a) => !a.startsWith("--"));
  if (!slug || !amountArg || (!zcashAddress && !noMemo)) {
    throw new Error("usage: burn-for-twin.mjs <coin-slug> <amount in tokens> <zcash unified address> [--no-memo]");
  }
  if (zcashAddress && !/^u(test|regtest)1[02-9ac-hj-np-z]+$/.test(zcashAddress)) {
    throw new Error("the Zcash address must be a test-network unified address (utest1... or uregtest1...)");
  }
  const rpc = process.env.SOLANA_RPC ?? "https://api.devnet.solana.com";
  if (!ALLOWED_RPC.some((rx) => rx.test(rpc))) throw new Error(`refusing RPC ${rpc}: devnet or localhost only`);
  const conn = new Connection(rpc, "confirmed");
  if ((await conn.getGenesisHash()) === MAINNET_GENESIS) throw new Error("mainnet genesis: refused");

  const payer = loadKeypair(path.join(keysDir, "devnet-payer.json"));
  const mint = loadKeypair(path.join(keysDir, `${slug}-mint.json`)).publicKey;
  const info = await getMint(conn, mint, "confirmed", TOKEN_2022_PROGRAM_ID);
  const [whole, frac = ""] = amountArg.split(".");
  if (!/^\d+$/.test(whole) || !/^\d*$/.test(frac) || frac.length > info.decimals) throw new Error(`bad amount ${amountArg}`);
  const amount = BigInt(whole) * 10n ** BigInt(info.decimals) + BigInt(frac.padEnd(info.decimals, "0") || "0");
  if (amount <= 0n) throw new Error("amount must be above zero");

  const ata = getAssociatedTokenAddressSync(mint, payer.publicKey, false, TOKEN_2022_PROGRAM_ID);
  const tx = new Transaction().add(
    createBurnCheckedInstruction(ata, mint, payer.publicKey, amount, info.decimals, [], TOKEN_2022_PROGRAM_ID),
  );
  if (!noMemo) {
    tx.add(new TransactionInstruction({ programId: MEMO_PROGRAM, keys: [], data: Buffer.from(`sapling-twin:1:${zcashAddress}`, "utf8") }));
  }
  const sig = await sendAndConfirmTransaction(conn, tx, [payer], { commitment: "finalized" });
  console.log(`burned ${amountArg} (${amount} base units) of ${mint.toBase58()}`);
  console.log(`memo ${noMemo ? "(none)" : `sapling-twin:1:${zcashAddress}`}`);
  console.log(`signature ${sig}`);
  console.log(`https://explorer.solana.com/tx/${sig}?cluster=devnet`);
}

main().catch((e) => {
  console.error(String(e?.message ?? e));
  process.exit(1);
});
