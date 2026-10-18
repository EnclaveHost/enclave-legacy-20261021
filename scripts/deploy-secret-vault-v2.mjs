#!/usr/bin/env node
// Deploy EnclaveSecretVaultV2 (docs/security/secret-custody-v2-spec.md §1).
//
//   NETWORK=base  HOST_OWNERSHIP=0x… DEPLOYER_PRIVATE_KEY=0x… node scripts/deploy-secret-vault-v2.mjs --dry-run      compile + print the plan
//   NETWORK=base  HOST_OWNERSHIP=0x… DEPLOYER_PRIVATE_KEY=0x… node scripts/deploy-secret-vault-v2.mjs                 deploy (asks first)
//   NETWORK=local RPC_URL=http://127.0.0.1:8545 BOOK=0x… ENCLAVE_OWNER=0x… HOST_OWNERSHIP=0x… DEPLOYER_PRIVATE_KEY=0x… node scripts/deploy-secret-vault-v2.mjs --yes
//
// The vault has NO owner, NO admin and NO proxy: the deployer key holds no power over it after the deployment transaction.
// Constructor (book, enclaveOwner, hostOwnership):
//   - book: used once at construction to pin the ledger and SessionVault factory
//     (Base: 0xab214342d5A490150A4A977063A2f88E21F80907);
//   - enclaveOwner: the accepted owning wallet that identifies the Enclave seat
//     (Base: 0x0b2d009c0c9Af05b12100D77F3c815fea822eE61, the governance Trezor).
//   - hostOwnership: deployed EnclaveHostOwnership, pinning the host registry and accepted owners.
//
// NOT done here, printed at the end for governance (the book owner, a Trezor) to sign: book.set("secretVaultV2", <vault>).
// Until that transaction, nothing in the platform (site, CLI, relay) uses the vault unless configured by hand.
//
// Compiled with solc-js 0.8.35, optimizer runs 200, viaIR (the Foundry suite compiles the same source the same way).
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import solc from "solc";
import { createPublicClient, createWalletClient, http, getAddress, isAddress, encodeFunctionData, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base, baseSepolia, foundry } from "viem/chains";

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..");
export const EIP170 = 24576;
export const NETWORKS = {
  base: { chain: base, rpc: "https://mainnet.base.org", book: "0xab214342d5A490150A4A977063A2f88E21F80907",
          enclaveOwner: "0x0b2d009c0c9Af05b12100D77F3c815fea822eE61", explorer: "https://basescan.org" },
  "base-sepolia": { chain: baseSepolia, rpc: "https://sepolia.base.org", book: null, enclaveOwner: null, explorer: "https://sepolia.basescan.org" },
  local: { chain: foundry, rpc: "http://127.0.0.1:8545", book: null, enclaveOwner: null },
};
export const BOOK_KEY = "secretVaultV2";
const die = (m) => { const e = new Error(m); e.fatal = true; throw e; };

export const compileSecretVaultV2 = () => compileContract("EnclaveSecretVaultV2");
export const compileHostOwnership = () => compileContract("EnclaveHostOwnership");
function compileContract(name) {
  const out = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity",
    sources: { [name+".sol"]: { content: fs.readFileSync(path.join(REPO,"contracts",name+".sol"), "utf8") } },
    settings: { viaIR: true, optimizer: { enabled: true, runs: 200 }, outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } } } })));
  const errs = (out.errors || []).filter((e) => e.severity === "error");
  if (errs.length) die("solc:\n" + errs.map((e) => e.formattedMessage).join("\n"));
  const c = out.contracts[name+".sol"][name];
  const size = c.evm.deployedBytecode.object.length / 2;
  if (size > EIP170) die(`${name} is ${size} bytes, over EIP-170`);
  return { abi: c.abi, bytecode: "0x" + c.evm.bytecode.object, size };
}

// a public RPC can answer the receipt before it serves the new code (10-14, v1: "book returned no data"), so retry reads
async function readBack(pc, address, abi, functionName) {
  for (let i = 0; i < 20; i++) {
    const v = await pc.readContract({ address, abi, functionName }).catch(() => null);
    if (v) return v;
    await new Promise((r) => setTimeout(r, 1500));
  }
  return null;
}

export async function deploySecretVaultV2({ rpc, chain, privateKey, book, enclaveOwner, hostOwnership, log = console.log, dryRun = false, confirm = async () => true }) {
  if (!isAddress(book || "")) die("BOOK (the address book) is required for this network");
  if (!isAddress(enclaveOwner || "")) die("ENCLAVE_OWNER (the Enclave seat's accepted owning wallet) is required for this network");
  if (!isAddress(hostOwnership || "") || /^0x0{40}$/i.test(hostOwnership)) die("HOST_OWNERSHIP (the deployed host ownership contract) is required");
  const art = compileSecretVaultV2();
  log(`EnclaveSecretVaultV2: ${art.size} bytes runtime (EIP-170: ${EIP170}); constructor(book = ${getAddress(book)}, enclaveOwner = ${getAddress(enclaveOwner)}, hostOwnership = ${getAddress(hostOwnership)})`);
  if (dryRun) { log("dry run: nothing sent"); return null; }
  const account = privateKeyToAccount(privateKey);
  const pc = createPublicClient({ chain, transport: http(rpc) });
  const wc = createWalletClient({ chain, account, transport: http(rpc) });
  if ((await pc.getChainId()) !== chain.id) die(`the RPC is not chain ${chain.id}`);
  if ((await pc.getCode({ address: book })) === undefined) die(`no contract at the book address ${book}`);
  const bookABI = [{type:"function",name:"addr",stateMutability:"view",inputs:[{type:"bytes32"}],outputs:[{type:"address"}]}];
  const pinNames = {deploymentLedger:"deployments",sessionVaultFactory:"sessionVaultFactory"};
  const pins = Object.fromEntries(await Promise.all(Object.entries(pinNames).map(async([getter,key])=>
    [getter,getAddress(await pc.readContract({address:book,abi:bookABI,functionName:"addr",args:[stringToHex(key,{size:32})]}))])));
  log(`immutable release authorities: ${JSON.stringify(pins)}`);
  if (!(await confirm(`deploy from ${account.address} on chain ${chain.id}?`))) die("aborted");
  const hash = await wc.deployContract({ abi: art.abi, bytecode: art.bytecode, args: [book, enclaveOwner, hostOwnership] });
  const r = await pc.waitForTransactionReceipt({ hash });
  if (r.status !== "success" || !r.contractAddress) die(`deployment reverted: ${hash}`);
  const vault = getAddress(r.contractAddress);
  // verify what is on chain: the book it reads and the Enclave wallet it names (the deployer holds nothing: there is nothing TO hold)
  const gotBook = await readBack(pc, vault, art.abi, "book");
  if (!gotBook) die(`deployed ${vault} (tx ${hash}) but no RPC answered book() yet: verify it by hand`);
  if (getAddress(gotBook) !== getAddress(book)) die(`the vault reads book ${gotBook}, not ${book}`);
  const gotOwner = await readBack(pc, vault, art.abi, "enclaveOwner");
  if (!gotOwner) die(`deployed ${vault} (tx ${hash}) but no RPC answered enclaveOwner() yet: verify it by hand`);
  if (getAddress(gotOwner) !== getAddress(enclaveOwner)) die(`the vault names enclaveOwner ${gotOwner}, not ${enclaveOwner}`);
  const gotOwnership = await readBack(pc, vault, art.abi, "hostOwnership");
  if (!gotOwnership || getAddress(gotOwnership) !== getAddress(hostOwnership)) die("hostOwnership read-back mismatch");
  for (const [getter, expected] of Object.entries(pins)) {
    const actual = await readBack(pc, vault, art.abi, getter);
    if (!actual || getAddress(actual) !== expected) die(`${getter} read-back mismatch; do not activate this vault`);
  }
  log(`deployed ${vault} (tx ${hash}, block ${r.blockNumber})`);
  const setData = encodeFunctionData({ abi: [{ type: "function", name: "set", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [] }],
                                      functionName: "set", args: [stringToHex(BOOK_KEY, { size: 32 }), vault] });
  log(`\nGOVERNANCE STEP (not sent): the book owner signs\n  to:   ${getAddress(book)}\n  data: ${setData}\n  (EnclaveAddressBook.set("${BOOK_KEY}", ${vault}))`);
  return { vault, hash, setData };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const net = NETWORKS[process.env.NETWORK || ""] || die(`NETWORK must be one of ${Object.keys(NETWORKS).join(", ")}`);
  const rl = process.argv.includes("--yes") ? null : readline.createInterface({ input, output });
  try {
    await deploySecretVaultV2({ rpc: process.env.RPC_URL || net.rpc, chain: net.chain,
      privateKey: process.env.DEPLOYER_PRIVATE_KEY || (process.argv.includes("--dry-run") ? "0x" + "11".repeat(32) : die("DEPLOYER_PRIVATE_KEY is required")),
      hostOwnership: process.env.HOST_OWNERSHIP, book: process.env.BOOK || net.book, enclaveOwner: process.env.ENCLAVE_OWNER || net.enclaveOwner, dryRun: process.argv.includes("--dry-run"),
      confirm: async (q) => (rl ? /^y(es)?$/i.test(await rl.question(q + " [y/N] ")) : true) });
  } catch (e) { console.error(`deploy-secret-vault-v2: ${e.message}`); process.exitCode = 1; }
  finally { rl?.close(); }
}
