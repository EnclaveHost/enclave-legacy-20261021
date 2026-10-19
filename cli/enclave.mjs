#!/usr/bin/env node
// enclave — the Enclave platform CLI. One file, wallet-native; your wallet is your account.
//
// Every command maps 1:1 onto the public HTTP API (https://api.enclave.host/v1)
// and the on-chain contracts on Base — the CLI holds the pieces, it owns
// nothing: auth is a SIWE signature, payment is your USDC, deployments are
// EnclaveDeployments work items your key created. Run any command with -x to see
// the exact API traffic and transactions, ready to replay with curl.
//
//   enclave key new | import         bring a wallet (or ENCLAVE_KEY env)
//   enclave login                    or sign in with your Enclave account (passkey)
//   enclave deploy hello-world:1 --fund 2  create + fund + wait until live
//   enclave ls | status | logs -f    watch it run
//   enclave attest [<id>]            verify the enclave BEFORE you send data  [--expect HEX[,HEX]] [--min-tcb JSON]  (exit 0 verified, 3 limited, 1 not)
//   enclave publish app.wasm --slug hello-world   pin to IPFS + cut a catalog version
//
// State lives in ~/.config/enclave/ (key: chmod 600; cached bearer tokens).
// Nothing else touches your machine; the key never leaves it — API calls sign
// a one-time SIWE challenge, transactions are signed locally and broadcast to
// your own --rpc.
//
// Passkey accounts (no wallet): `enclave login` runs the platform's device
// flow — approve the shown link from any browser where your passkey works,
// and this terminal holds an account session. That session reads your
// account-provisioned/credit deployments and balances (ls, whoami, account);
// it cannot sign transactions or wallet-gated reads, which stay key-only.
//
// Env:  ENCLAVE_KEY       hex private key (overrides the key file)
//       ENCLAVE_API_BASE  gateway or a specific enclave origin (--base)
//       ENCLAVE_RPC       Base JSON-RPC url, or several comma-separated (--rpc)
//       ENCLAVE_VISIBLE_WAIT  seconds deploy waits for a new record to reach every reader (default 60)
//       ENCLAVE_SESSION   an exported session (enclave session new --env): the session-aware commands act through it
//       ENCLAVE_SESSION_DIR  where session keys live (default ~/.config/enclave/sessions)
import {catalogAdmissionNotice} from "../site/js/core/catalog-policy.js";
import fs from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import rlSync from "node:readline";
import { stdin, stdout, stderr, argv, env, exit } from "node:process";
import { createPublicClient, createWalletClient, http as viemHttp, fallback,
         parseEther, formatUnits, encodeFunctionData, getAddress,
         keccak256, toHex } from "viem";
import { base } from "viem/chains";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";

import {directUploadHeaders} from "../sdk/storage/upload-auth.mjs";
import {loadContractPins} from "../network/contract-pins.mjs";

const VERSION = "1.6.0";

// ---- platform constants -----------------------------------------------------
// Addresses are Base mainnet (chain 8453), kept in lockstep with
// enclaves/cpu/config.yml and site/index.html by
// scripts/sync-contract-addresses.sh — same values, one authority.
const DEFAULTS = {
  apiBase: "https://api.enclave.host",
  chainId: 8453,
  rpcs: ["https://base-rpc.publicnode.com", "https://base.drpc.org",
         "https://1rpc.io/base", "https://mainnet.base.org"],
  DEPLOYMENTS_ADDRESS: "0xF9e71385C5cB49844F2457ba6567De0742f8B89a",
  APP_CATALOG_ADDRESS: "0x18419CA2b502D423A8de6269AEeE171a378626e3",   // the address book's appCatalog (read 2026-09-26; 0xAc5270… is a RETIRED catalog): a FALLBACK only, see resolveAddressBook
  REGISTRY_ADDRESS: "0x868eB7fc5B5A84B2FF082eafc9bf40b7AAc5CCAC",
  ADDRESS_BOOK_ADDRESS: "0xab214342d5A490150A4A977063A2f88E21F80907",     // EnclaveAddressBook; written by scripts/deploy-address-book.mjs — when set, the CLI resolves the addresses above from it at start ("" = baked only)
  USDC_ADDRESS: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  // SessionVault v2 factory (contracts/deployments/ledger-15d-base.json): `session delegate` asks the book's
  // "sessionVaultFactory" first and uses this only while the book names none (unset at the 2026-10-07 cutover)
  SESSION_VAULT_FACTORY_ADDRESS: "0x1F5c887c0cDF491b16AB6c449abAfDF9B2ec9C9C",
  ipfsUpload: env.ENCLAVE_IPFS_UPLOAD || "https://ipfs.enclave.host/add-wasm",
  ipfsJsonUpload: env.ENCLAVE_IPFS_JSON_UPLOAD || "https://ipfs.enclave.host/add-json",
  appDomain: "app.enclave.host",
};

// App-config ceilings. INLINE_MAX is the catalog's on-chain limit on the
// version's `config` field — a hard contract constant, not a policy dial. Above
// it the config is pinned to IPFS and the version carries the CID instead
// (catalog rev 7, publishVersionCfg), which is what CONFIG_MAX_BYTES bounds:
// the runner refuses anything larger at launch, and the pin gateway at upload.
// Keep all three in lockstep — wasm_manager CONFIG_MAX_BYTES, the gateway's
// MAX_CONFIG_BYTES, and this.
const CONFIG_INLINE_MAX = 4096;
const CONFIG_MAX_BYTES  = 1024 * 1024;
// The keys read straight off the CHAIN RECORD by readers with no CID to fetch
// yet. When the config moves to a CID these stay behind in the inline field:
// wasi/threads/set/gpuOptional/cpuFallback place the deployment AND size it (a
// runner picks a box, and the share floor it must clear, before it fetches
// anything), and _media is the catalog grid's tile art. They
// stay in the PINNED config too, so the delivered ENCLAVE_CONFIG remains the
// whole document — the manifest is a projection, not a split. Derived, never
// hand-written: publish stamps wasi/threads/set from the binary's own exports.
// Mirrors ROUTING_KEYS in site/js/core/chain.js — keep them in lockstep.
const ROUTING_KEYS = ["wasi", "threads", "set", "mem64", "gpuOptional", "cpuFallback", "volumes", "_media"];

// Minimal ABIs — mirror contracts/*.abi.json (checked in, re-emitted by the
// deploy scripts); embedded so the installed binary is self-contained.
// Deployment struct, schema rev 2. Rev-1 contracts carry a removed sshPubKey
// string after ports (in the struct and in create); depAbi() sniffs which
// shape the live ledger speaks, the same way catRev() sniffs the catalog.
const DEPLOYMENT_TUPLE = [
  { name: "id", type: "bytes32" }, { name: "owner", type: "address" },
  { name: "appRef", type: "string" }, { name: "ports", type: "string" },
  { name: "configCid", type: "string" },
  { name: "gpuMilli", type: "uint16" }, { name: "cpuMilli", type: "uint16" },
  { name: "appPort", type: "uint32" }, { name: "isPublic", type: "bool" },
  { name: "active", type: "bool" }, { name: "createdAt", type: "uint64" },
  { name: "rate", type: "uint256" }, { name: "balance6", type: "uint256" },
  { name: "spent6", type: "uint256" }, { name: "runner", type: "bytes32" },
  { name: "runnerOperator", type: "address" }, { name: "leaseUntil", type: "uint64" },
];
const DEPLOYMENT_TUPLE_V1 = [
  ...DEPLOYMENT_TUPLE.slice(0, 4), { name: "sshPubKey", type: "string" }, ...DEPLOYMENT_TUPLE.slice(4),
];
const depsAbiFor = (tuple, rev) => [
  { type: "function", name: "create", stateMutability: "nonpayable",
    inputs: [{ name: "appRef", type: "string" }, { name: "gpuMilli", type: "uint16" },
             { name: "cpuMilli", type: "uint16" }, { name: "appPort", type: "uint32" },
             { name: "ports", type: "string" }, { name: "isPublic", type: "bool" },
             ...(rev >= 2 ? [] : [{ name: "sshPubKey", type: "string" }]),
             { name: "configCid", type: "string" },
             // rev-4 ledgers: the publisher-fee snapshot (recipient wallet +
             // the version's per-second fee, folded into the record's rate)
             ...(rev >= 4 ? [{ name: "feeRecipient", type: "address" }, { name: "feePerSec6", type: "uint256" }] : []),
             // rev-8 ledgers: the owner's per-second spend ceiling. Required —
             // there is no platform price to fall back on; each enclave posts
             // its own and this bounds which of them may claim the work
             ...(rev >= 8 ? [{ name: "maxRate6", type: "uint256" }] : [])],
    outputs: [{ type: "bytes32" }] },
  // rev-4 ledgers only: the fee snapshot back out (0x0/0 = no fee)
  { type: "function", name: "feeOf", stateMutability: "view",
    inputs: [{ name: "id", type: "bytes32" }],
    outputs: [{ name: "recipient", type: "address" }, { name: "feePerSec6", type: "uint256" }] },
  { type: "function", name: "fundWithAuthorization", stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "bytes32" }, { name: "from", type: "address" },
             { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" },
             { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
             { name: "signature", type: "bytes" }], outputs: [] },
  { type: "function", name: "fundEth", stateMutability: "payable",
    inputs: [{ name: "id", type: "bytes32" }], outputs: [] },
  { type: "function", name: "setActive", stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "bytes32" }, { name: "active", type: "bool" }], outputs: [] },
  // rev-3 ledgers only (deploymentsSchema >= 3): the owner's version change
  { type: "function", name: "setAppRef", stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "bytes32" }, { name: "appRef", type: "string" }], outputs: [] },
  // rev-9 ledgers only (deploymentsSchema >= 9): how far the serving enclave
  // has PROVEN it was actually running the app. The runner meter never pays
  // past this, so it is also the honest answer to "am I getting what I paid
  // for" — and unlike an uptime badge, nobody can self-report it.
  { type: "function", name: "provenUntil", stateMutability: "view",
    inputs: [{ type: "bytes32" }], outputs: [{ type: "uint64" }] },
  { type: "function", name: "proofRequired", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  // rev-6 ledgers only (deploymentsSchema >= 6): the owner's share resize —
  // re-buys the two shares in place, rate recalculated at current list prices
  { type: "function", name: "setShares", stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "bytes32" }, { name: "gpuMilli", type: "uint16" },
             { name: "cpuMilli", type: "uint16" }], outputs: [] },
  // self-delegatecall batcher: setAppRef + setShares ride one signature
  { type: "function", name: "multicall", stateMutability: "nonpayable",
    inputs: [{ name: "calls", type: "bytes[]" }], outputs: [{ type: "bytes[]" }] },
  // the owner's envelope rewrite (all revs; rev < 5 caps the field at 100 bytes)
  { type: "function", name: "setConfig", stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "bytes32" }, { name: "configCid", type: "string" }], outputs: [] },
  // rev-8 ledgers only: the owner's spend ceiling — which enclaves may run
  // this deployment (including after its host dies), and at what price
  { type: "function", name: "setMaxRate", stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "bytes32" }, { name: "maxRate6", type: "uint256" }], outputs: [] },
  { type: "function", name: "capOf", stateMutability: "view",
    inputs: [{ name: "id", type: "bytes32" }], outputs: [{ name: "maxRate6", type: "uint256" }] },
  // rev-10 ledgers only (deploymentsSchema >= 10): cancel and take back the
  // unused runtime the ledger still HOLDS. refundableOf is the exact payout,
  // not an estimate — see the contract's note on why a view can be exact here.
  { type: "function", name: "refund", stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "bytes32" }], outputs: [] },
  { type: "function", name: "refundableOf", stateMutability: "view",
    inputs: [{ name: "id", type: "bytes32" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "ownerEscrow6", stateMutability: "view",
    inputs: [{ type: "bytes32" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "earnOf", stateMutability: "view",
    inputs: [{ type: "bytes32" }],
    outputs: [{ name: "runnerRate6", type: "uint256" }, { name: "escrow6", type: "uint256" }, { name: "creditedUntil", type: "uint64" }] },
  // rev-11 ledgers only: hand the record — control, never money — to another
  // wallet. The ledger refuses it while any of the owner's own refundable
  // backing is still held ("refund first"); cmdTransfer chains the refund.
  { type: "function", name: "transferDeployment", stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "bytes32" }, { name: "to", type: "address" }], outputs: [] },
  { type: "function", name: "get", stateMutability: "view",
    inputs: [{ name: "id", type: "bytes32" }],
    outputs: [{ type: "tuple", components: tuple }] },
  { type: "function", name: "getPage", stateMutability: "view",
    inputs: [{ name: "start", type: "uint256" }, { name: "n", type: "uint256" }],
    outputs: [{ type: "tuple[]", components: tuple }] },
  { type: "function", name: "count", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "secondsFundable", stateMutability: "view",
    inputs: [{ name: "id", type: "bytes32" }], outputs: [{ type: "uint256" }] },
  { type: "event", name: "Created",
    inputs: [{ name: "id", type: "bytes32", indexed: true }, { name: "owner", type: "address", indexed: true },
             { name: "appRef", type: "string" }, { name: "gpuMilli", type: "uint16" },
             { name: "cpuMilli", type: "uint16" }, { name: "rate", type: "uint256" }] },
];
// Only a REVERT means "the marker getter isn't there" = a genuinely old
// contract. Anything else (transport trouble, or "returned no data" - an RPC
// that has no code for the address yet, seen live right after a cutover) is
// UNKNOWN: falling back silently decodes the live contract with the wrong
// schema and rev-gates every feature off. Same rule as the site's sniffs.
const isRevertErr = (e) => /revert/i.test(String((e && (e.shortMessage || e.message)) || ""));
// sniff once per run which shape the live contract speaks (mirrors catRev)
let _depAbi = null;
async function depAbi() {
  if (_depAbi) return _depAbi;
  let rev = 2;
  try { rev = Number(await read(DEFAULTS.DEPLOYMENTS_ADDRESS,
    [{ type: "function", name: "deploymentsSchema", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] }],
    "deploymentsSchema", [])) || 2; }
  catch (e) { if (!isRevertErr(e)) throw e; rev = 1; }   // pre-getter contract: the call reverts
  _depAbi = { rev, abi: depsAbiFor(rev >= 2 ? DEPLOYMENT_TUPLE : DEPLOYMENT_TUPLE_V1, rev) };
  return _depAbi;
}
// keccak256("Created(bytes32,address,string,uint16,uint16,uint256)") — same
// constant the deploy console uses to pull the minted id out of the receipt.
const DEP_CREATED_TOPIC = "0x3b201eb11e77934b296f908775fc0a82679683fd83a1232579f1014bcf7d3239";
const APP_TUPLE = [
  { name: "appId", type: "bytes32" }, { name: "publisher", type: "address" },
  { name: "slug", type: "string" }, { name: "name", type: "string" },
  { name: "description", type: "string" }, { name: "versionCount", type: "uint32" },
  { name: "createdAt", type: "uint64" }, { name: "updatedAt", type: "uint64" },
  { name: "active", type: "bool" },
];
// catalog schema rev 4: VERSION carries `config` (default/template
// ENCLAVE_CONFIG JSON, appended last; immutable + approval-covered).
// Rev sniffed via catalogSchema(): absent = rev 2; rev 3 = the retired
// app-level-config layout whose versions are config-LESS.
const VERSION_TUPLE = [
  { name: "cid", type: "string" }, { name: "version", type: "string" },
  { name: "vramMb", type: "uint32" }, { name: "gpuGflops", type: "uint32" },
  { name: "memMb", type: "uint32" }, { name: "cpuGflops", type: "uint32" },
  { name: "createdAt", type: "uint64" }, { name: "verified", type: "bool" },
  { name: "yanked", type: "bool" }, { name: "ports", type: "string" },
  { name: "approval", type: "uint8" },
];
const VERSION_TUPLE_V3 = [...VERSION_TUPLE, { name: "config", type: "string" }];
const CATALOG_ABI = [
  { type: "function", name: "appCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "getAppsPage", stateMutability: "view",
    inputs: [{ name: "start", type: "uint256" }, { name: "n", type: "uint256" }],
    outputs: [{ type: "tuple[]", components: APP_TUPLE }] },
  { type: "function", name: "getVersionsPage", stateMutability: "view",
    inputs: [{ name: "appId", type: "bytes32" }, { name: "start", type: "uint256" }, { name: "n", type: "uint256" }],
    outputs: [{ type: "tuple[]", components: VERSION_TUPLE }] },
  { type: "function", name: "numVersions", stateMutability: "view",
    inputs: [{ name: "appId", type: "bytes32" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "appIdOf", stateMutability: "pure",
    inputs: [{ name: "publisher", type: "address" }, { name: "slug", type: "string" }],
    outputs: [{ type: "bytes32" }] },
  { type: "function", name: "cidStatus", stateMutability: "view",
    inputs: [{ name: "cid", type: "string" }],
    outputs: [{ name: "listed", type: "bool" }, { name: "appId", type: "bytes32" },
              { name: "index", type: "uint256" }, { name: "approval", type: "uint8" },
              { name: "yanked", type: "bool" }, { name: "appActive", type: "bool" },
              { name: "res", type: "uint32[4]" }] },
  { type: "function", name: "publishVersion", stateMutability: "nonpayable",
    inputs: [{ name: "slug", type: "string" }, { name: "name", type: "string" },
             { name: "description", type: "string" }, { name: "version", type: "string" },
             { name: "cid", type: "string" }, { name: "res", type: "uint32[4]" },
             { name: "ports", type: "string" }],
    outputs: [{ type: "bytes32" }, { type: "uint256" }] },
  // rev-3/4 overload (viem resolves by arg count) + the schema marker
  { type: "function", name: "publishVersion", stateMutability: "nonpayable",
    inputs: [{ name: "slug", type: "string" }, { name: "name", type: "string" },
             { name: "description", type: "string" }, { name: "version", type: "string" },
             { name: "cid", type: "string" }, { name: "res", type: "uint32[4]" },
             { name: "ports", type: "string" }, { name: "config", type: "string" }],
    outputs: [{ type: "bytes32" }, { type: "uint256" }] },
  // rev-5 overload: the version's publisher fee (USDC 6dp per second,
  // immutable + approval-covered like config and ports; 0 = free)
  { type: "function", name: "publishVersion", stateMutability: "nonpayable",
    inputs: [{ name: "slug", type: "string" }, { name: "name", type: "string" },
             { name: "description", type: "string" }, { name: "version", type: "string" },
             { name: "cid", type: "string" }, { name: "res", type: "uint32[4]" },
             { name: "ports", type: "string" }, { name: "config", type: "string" },
             { name: "feePerSec6", type: "uint256" }],
    outputs: [{ type: "bytes32" }, { type: "uint256" }] },
  // rev-7: a version whose config lives at a CID. `config` here is the ROUTING
  // MANIFEST (wasi/threads/set/gpuOptional — what a runner reads off the chain
  // before it can fetch anything), and configCid names the real config.
  { type: "function", name: "publishVersionCfg", stateMutability: "nonpayable",
    inputs: [{ name: "slug", type: "string" }, { name: "name", type: "string" },
             { name: "description", type: "string" }, { name: "version", type: "string" },
             { name: "cid", type: "string" }, { name: "res", type: "uint32[4]" },
             { name: "ports", type: "string" }, { name: "config", type: "string" },
             { name: "configCid", type: "string" }, { name: "feePerSec6", type: "uint256" }],
    outputs: [{ type: "bytes32" }, { type: "uint256" }] },
  // rev-5 surface (side mapping, so version tuples decode on every rev)
  { type: "function", name: "versionFee", stateMutability: "view",
    inputs: [{ name: "appId", type: "bytes32" }, { name: "index", type: "uint256" }],
    outputs: [{ type: "uint256" }] },
  // rev-7 surface (side mapping too): "" = the inline config IS the config
  { type: "function", name: "versionConfigCid", stateMutability: "view",
    inputs: [{ name: "appId", type: "bytes32" }, { name: "index", type: "uint256" }],
    outputs: [{ type: "string" }] },
  { type: "function", name: "maxFeePerSec6", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "catalogSchema", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
];
// VersionApprovalSet(bytes32 indexed appId, uint256 indexed index, uint8 status):
// emitted inside the publish tx itself when the catalog auto-approves an
// owner publish (rev 9) — the receipt is the authority on whether review is done
const APPROVAL_SET_TOPIC = keccak256(toHex("VersionApprovalSet(bytes32,uint256,uint8)"));
// per-version publisher fee: 0 for every pre-rev-5 catalog (no getter there)
async function versionFee6(appId, index) {
  if ((await catRev()) < 5) return 0n;
  return await read(DEFAULTS.APP_CATALOG_ADDRESS, CATALOG_ABI, "versionFee", [appId, BigInt(index)]);
}
// getVersionsPage can't overload by outputs, so rev-3 reads swap the tuple shape
const CATALOG_ABI_V3 = CATALOG_ABI.map((f) =>
  f.name === "getVersionsPage" ? { ...f, outputs: [{ type: "tuple[]", components: VERSION_TUPLE_V3 }] } : f);
let _catRev = null;
async function catRev() {
  if (_catRev) return _catRev;
  try { _catRev = Number(await read(DEFAULTS.APP_CATALOG_ADDRESS, CATALOG_ABI, "catalogSchema", [])) || 2; }
  catch (e) { if (!isRevertErr(e)) throw e; _catRev = 2; }   // revert = pre-marker catalog; else unknown, don't cache
  return _catRev;
}
// one versions read for all revisions: only rev-4 versions carry config
// (rev 3 = the retired app-level layout; its versions decode as rev 2)
async function readVersions(appId, count) {
  const abi = (await catRev()) >= 4 ? CATALOG_ABI_V3 : CATALOG_ABI;
  const versions = await read(DEFAULTS.APP_CATALOG_ADDRESS, abi, "getVersionsPage",
                              [appId, 0n, BigInt(Math.max(1, Number(count)))]);
  return versions.map((v) => ({ config: "", ...v }));
}
const ERC20_ABI = [
  { type: "function", name: "balanceOf", stateMutability: "view",
    inputs: [{ name: "a", type: "address" }], outputs: [{ type: "uint256" }] },
];
const APPROVAL_WORD = ["pending", "approved", "rejected"];

// ---- global flags + config ---------------------------------------------------
// Parsed once, up front; command args are whatever remains.
const opt = { json: false, trace: false, base: null, rpc: null, yes: false,
              unsigned: false, signer: null, from: null, contractPins: null,
              // --wallet: act with the wallet key even when a session is active (see "sessions" below)
              wallet: false,
              // `enclave attest` (verifier/metal-box.mjs, this repository's own verifier): --expect pins the launch measurement(s)
              // that must run (without it the relay operator's allowlist is used and the verdict is at best "limited");
              // --min-tcb overrides the published TCB floor; --collateral-dir reads AMD collateral from disk instead of AMD KDS.
              expect: null, minTcb: null, collateralDir: null };
const args = [];
{
  const a = argv.slice(2);
  for (let i = 0; i < a.length; i++) {
    if (a[i] === "--json") opt.json = true;
    else if (a[i] === "-x" || a[i] === "--trace") opt.trace = true;
    else if (a[i] === "--yes" || a[i] === "-y") opt.yes = true;
    else if (a[i] === "--base") opt.base = a[++i];
    else if (a[i] === "--rpc") opt.rpc = a[++i];
    else if (a[i] === "--contract-pins") {
      if (!a[i + 1] || a[i + 1].startsWith("--")) throw new Error("--contract-pins needs a JSON file");
      opt.contractPins = a[++i];
    }
    // ---- signing somewhere other than this machine ----------------------
    // The CLI's own key is a hot key in a file. These two let it drive a
    // wallet that is not: --unsigned prints the transaction for you to sign
    // wherever you like (a browser wallet with a Ledger behind it, a Safe, an
    // air-gapped box), and --signer hands it to a local JSON-RPC signer —
    // Frame, Clef — that talks to the hardware wallet itself. Neither can be a
    // bundled Ledger transport: this CLI ships as ONE esbuild'd file and
    // node-hid is a native module with per-platform binaries.
    else if (a[i] === "--unsigned") opt.unsigned = true;
    else if (a[i] === "--signer") opt.signer = a[++i];
    else if (a[i] === "--from") opt.from = a[++i];
    else if (a[i] === "--wallet") opt.wallet = true;
    else if (a[i] === "--expect") opt.expect = a[++i];                  // the launch measurement(s) you expect, 96 hex each, comma-separated
    else if (a[i] === "--min-tcb") opt.minTcb = a[++i];                 // JSON TCB floor per product line (default: the verifier's published floors)
    else if (a[i] === "--collateral-dir") opt.collateralDir = a[++i];   // AMD collateral from a directory (amd/<product>-cert_chain.pem, amd/<product>-crl.der, vcek/<product>-<chip>-<tcb>.der) instead of KDS
    else args.push(a[i]);
  }
}
// Both the gateway and a bare enclave serve the same /v1 paths (and
// /availability at the root), so the base is always an origin; a pasted
// ".../v1" is normalized away.
const API_BASE = (opt.base || env.ENCLAVE_API_BASE || DEFAULTS.apiBase).replace(/\/+$/, "").replace(/\/v1$/, "");
// --rpc/ENCLAVE_RPC may name several, comma-separated (tried in order, like the defaults)
const RPCS = (opt.rpc || env.ENCLAVE_RPC)
  ? String(opt.rpc || env.ENCLAVE_RPC).split(",").map((s) => s.trim()).filter(Boolean) : DEFAULTS.rpcs;
const CONF_DIR = path.join(env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "enclave");
// session keys (`enclave session …`): one 0600 file each, beside the wallet key
const SESSION_DIR = path.resolve(env.ENCLAVE_SESSION_DIR || path.join(CONF_DIR, "sessions"));

const say = (...s) => console.log(...s);
const die = (msg, code = 1) => { stderr.write("error: " + msg + "\n"); exit(code); };
const trace = (...s) => { if (opt.trace) stderr.write("x " + s.join(" ") + "\n"); };
const jout = (o) => say(JSON.stringify(o, (_k, v) => typeof v === "bigint" ? v.toString() : v, 2));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Explicit operator/user trust pins take precedence over mutable discovery. A
// missing, malformed or disabled binding never falls back to the address book.
let CONTRACT_PINS = null;
let CHAIN_ONLY = false;
function configureContractPins() {
  CONTRACT_PINS = loadContractPins({ ...env,
    ENCLAVE_CONTRACT_PINS_FILE: opt.contractPins || env.ENCLAVE_CONTRACT_PINS_FILE });
  if (!CONTRACT_PINS) return;
  for (const [key, name] of Object.entries({ deployments: "DEPLOYMENTS_ADDRESS",
    registry: "REGISTRY_ADDRESS", appCatalog: "APP_CATALOG_ADDRESS",
    sessionVaultFactory: "SESSION_VAULT_FACTORY_ADDRESS" })) DEFAULTS[name] = CONTRACT_PINS[key];
  trace("using explicit contract pins; address-book discovery disabled");
}
function pinnedContract(name, override) {
  const a = CONTRACT_PINS[name];
  if (!a || /^0x0{40}$/i.test(a)) throw new Error(`contract pins disable ${name}`);
  if (override && getAddress(override) !== getAddress(a))
    throw new Error(`${name} override conflicts with the explicit contract pin`);
  return getAddress(a);
}
let _pinnedSessionFactoryCheck;
async function assertPinnedSessionFactory() {
  if (!CONTRACT_PINS) return;
  if (!_pinnedSessionFactoryCheck) _pinnedSessionFactoryCheck = (async () => {
    const factory = pinnedContract("sessionVaultFactory");
    const abi = [{ type: "function", name: "authorityPins", stateMutability: "view", inputs: [],
      outputs: [{ type: "address" }, { type: "address" }, { type: "address" }] }];
    let result;
    try { result = await read(factory, abi, "authorityPins"); }
    catch { throw new Error("the pinned session factory must expose fixed authorityPins; legacy mutable-book factories are not supported in pinned mode"); }
    const [ledger, catalog, authority] = result;
    if (getAddress(ledger) !== pinnedContract("deployments") || getAddress(catalog) !== pinnedContract("appCatalog")
      || /^0x0{40}$/i.test(authority)) throw new Error("session factory authorityPins do not match the explicit contract pins");
    return factory;
  })();
  return _pinnedSessionFactoryCheck;
}

// flag parser for the per-command remainder
function flags(rest, { bool = [], val = [] } = {}) {
  const out = { _: [] };
  for (let i = 0; i < rest.length; i++) {
    const f = rest[i];
    if (bool.includes(f)) out[f.replace(/^--?/, "")] = true;
    else if (val.includes(f)) {
      if (i + 1 >= rest.length) throw new Error(`${f} needs a value`);
      out[f.replace(/^--?/, "")] = rest[++i];
    }
    else if (f.startsWith("-") && f !== "-") throw new Error(`unknown flag ${f} (see: enclave help)`);
    else out._.push(f);
  }
  return out;
}
// a referral code (relay/referrals.mjs REFERRAL_RE): attribution only
const REFERRAL_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const numFlag = (v, name) => {
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) throw new Error(`${name} must be a non-negative number, got "${v}"`);
  return n;
};

// ---- key management -----------------------------------------------------------
const KEY_FILE = path.join(CONF_DIR, "key");
/* --signer / --unsigned mean the private key is somewhere this process cannot
   reach, so there is nothing to load — but the rest of the CLI still needs to
   know WHICH address it is acting as (ownership gates, `?owner=` reads, the
   from field of the transaction it prints). This stands in for the account:
   same `.address`, and the two signing methods throw something that names the
   real problem instead of "cannot read properties of undefined".
   MESSAGE signing genuinely cannot be delegated this way — `enclave login`
   (SIWE), uploads and encrypted-volume unlocks need a signature over a string,
   which Frame/Clef will do but an unsigned run cannot represent at all. */
const externalAccount = (address) => ({
  address: getAddress(address),
  _external: true,
  signMessage: async () => { throw new Error(EXTERNAL_SIGN_HINT); },
  signTypedData: async () => { throw new Error(EXTERNAL_SIGN_HINT); },
});
const EXTERNAL_SIGN_HINT =
  "this command needs a SIGNED MESSAGE, not a transaction, so --unsigned cannot express it. "
  + "Use --signer <url> (Frame/Clef sign messages too), or run it with a local key";
function loadKey({ required = true } = {}) {
  // an address is enough when something else holds the key
  if (opt.unsigned || opt.signer) {
    if (opt.from) {
      if (!/^0x[0-9a-fA-F]{40}$/.test(opt.from)) throw new Error(`--from is not a 0x…40-hex address: ${opt.from}`);
      return externalAccount(opt.from);
    }
    // Asked for rather than discovered: a signer may hold several accounts, and
    // every ownership gate in this CLI keys on the address — guessing one would
    // silently act as the wrong wallet, which is the failure that cost a
    // payout-wallet declaration on 2026-08-09.
    if (required) throw new Error(`--${opt.unsigned ? "unsigned" : "signer"} needs --from 0x… — the wallet this is for`);
    return null;
  }
  let pk = (env.ENCLAVE_KEY || "").trim();
  if (!pk && fs.existsSync(KEY_FILE)) pk = fs.readFileSync(KEY_FILE, "utf8").trim();
  if (!pk) {
    if (required) throw new Error("no wallet key. Run `enclave key new` (or `enclave key import`, or set ENCLAVE_KEY)"
      + (accountToken({ required: false })
         ? " — your `enclave login` account session can't sign transactions or wallet-gated reads"
         : ""));
    return null;
  }
  if (!pk.startsWith("0x")) pk = "0x" + pk;
  if (!/^0x[0-9a-fA-F]{64}$/.test(pk)) throw new Error("the configured key is not a 32-byte hex private key");
  return privateKeyToAccount(pk);
}
function saveKey(pk) {
  fs.mkdirSync(CONF_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(KEY_FILE, pk + "\n", { mode: 0o600 });
  // writeFileSync's mode is ignored when the file already exists, so an
  // overwrite (e.g. key new --force over a loose-permissioned file) would keep
  // the old perms — chmod explicitly to re-tighten to 0600 every time.
  try { fs.chmodSync(KEY_FILE, 0o600); } catch {}
}
// hidden prompt (mirrors scripts/login.mjs) — keys and passphrases never echo
function promptSecret(query) {
  return new Promise((resolve) => {
    if (!stdin.isTTY) { // piped: read all of stdin
      let buf = ""; stdin.setEncoding("utf8");
      stdin.on("data", (d) => buf += d);
      stdin.on("end", () => resolve(buf.trim()));
      return;
    }
    const rl = rlSync.createInterface({ input: stdin, output: stdout, terminal: true });
    rl._writeToOutput = (s) => { if (!rl._muted) stdout.write(s); };
    rl.question(query, (ans) => { rl.close(); stdout.write("\n"); resolve(ans.trim()); });
    rl.on("close", () => resolve(""));
    rl._muted = true;
  });
}
async function confirm(what) {
  if (opt.yes) return true;
  // Non-interactive (piped/cron) WITHOUT --yes: refuse rather than auto-proceed.
  // These prompts guard spending/teardown; silently answering "yes" for a pipe
  // is how a cron job drains a wallet. --yes is the explicit opt-in.
  if (!stdin.isTTY || !stdout.isTTY)
    throw new Error(`refusing to proceed without a confirmation in a non-interactive session; re-run with --yes to approve (${what})`);
  const rl = rlSync.createInterface({ input: stdin, output: stdout });
  const ans = await new Promise((r) => rl.question(what + " [y/N] ", (a) => { rl.close(); r(a.trim()); }));
  return /^y(es)?$/i.test(ans);
}

// ---- chain clients -------------------------------------------------------------
let _pub = null, _wallet = null;
function pub() {
  if (!_pub) _pub = createPublicClient({ chain: base, transport: fallback(RPCS.map((u) => viemHttp(u))) });
  return _pub;
}
function wallet(account) {
  if (_wallet) return _wallet;
  // With --signer the key lives in Frame/Clef/a node, so the account is just an
  // ADDRESS and viem sends eth_sendTransaction to that endpoint — which is
  // where the hardware-wallet prompt comes from. Without it, the local account
  // signs and we broadcast through the normal RPC pool.
  _wallet = opt.signer
    ? createWalletClient({ account: getAddress(account.address), chain: base, transport: viemHttp(opt.signer) })
    : createWalletClient({ account, chain: base, transport: fallback(RPCS.map((u) => viemHttp(u))) });
  return _wallet;
}
// One client PER configured RPC, no fallback and no retries: the
// read-after-write wait in deploy needs each reader's own answer, where pub()
// reports whichever one responds first.
let _pubEach = null;
function pubEach() {
  if (!_pubEach) _pubEach = RPCS.map((u) =>
    ({ host: (() => { try { return new URL(u).host; } catch { return "rpc"; } })(),   // host only: a url can carry an API key
       c: createPublicClient({ chain: base, transport: viemHttp(u, { retryCount: 0, timeout: 5_000 }) }) }));
  return _pubEach;
}
const read = (address, abi, functionName, a = []) =>
  pub().readContract({ address, abi, functionName, args: a });
/* Print the transaction and STOP. Stopping is the honest part: a flow like
   deploy is create-then-fund, and the second call needs the first one's logs,
   so pretending to continue would emit a transaction built on state that does
   not exist yet. Same contract as the MCP tools, which hand back unsigned
   transactions to be signed and sent IN ORDER — this is that surface, in the
   terminal. Re-run the command once the printed one has mined. */
function emitUnsigned({ account, to, data, value, label }) {
  const tx = { chainId: DEFAULTS.chainId, from: account?.address || opt.from || null,
               to: getAddress(to), data, value: "0x" + BigInt(value || 0).toString(16) };
  if (opt.json) { jout({ unsigned: tx, label }); exit(0); }
  say(`\n${label} — UNSIGNED. Sign and send this, then re-run if the command has more steps.\n`);
  kv([["chainId", String(tx.chainId)], ...(tx.from ? [["from", tx.from]] : []),
      ["to", tx.to], ["value", tx.value === "0x0" ? "0" : tx.value], ["data", tx.data]]);
  exit(0);
}
async function sendTx(account, { address, abi, functionName, args: a, value }) {
  // before the --unsigned branch below, so an unsigned transaction for someone else to sign is guarded too (enclave-b4)
  if (String(address).toLowerCase() === String(DEFAULTS.APP_CATALOG_ADDRESS).toLowerCase()) catalogWriteAllowed();
  const name = { [DEFAULTS.DEPLOYMENTS_ADDRESS]: "EnclaveDeployments",
                 [DEFAULTS.APP_CATALOG_ADDRESS]: "EnclaveAppCatalog" }[address] || address;
  trace(`tx ${name}.${functionName}(${a.map(fmtArg).join(", ")})${value ? ` value=${formatUnits(value, 18)} ETH` : ""}`);
  if (opt.unsigned) return emitUnsigned({ account, to: address,
    data: encodeFunctionData({ abi, functionName, args: a }), value,
    label: `${name}.${functionName}` });
  const hash = await wallet(account).writeContract({ address, abi, functionName, args: a, ...(value ? { value } : {}) });
  trace(`tx sent ${hash}, waiting for receipt`);
  const rcpt = await pub().waitForTransactionReceipt({ hash });
  if (rcpt.status !== "success") throw new Error(`transaction reverted: ${hash}`);
  return rcpt;
}
const fmtArg = (v) => typeof v === "string" && v.length > 48 ? JSON.stringify(v.slice(0, 45) + "…")
  : JSON.stringify(v, (_k, x) => typeof x === "bigint" ? x.toString() : x);

// ---- HTTP client (SIWE auth, token cache, -x tracing) ---------------------------
const TOK_FILE = path.join(CONF_DIR, "tokens.json");
function tokenCache() { try { return JSON.parse(fs.readFileSync(TOK_FILE, "utf8")); } catch { return {}; } }
function tokenPut(k, v) {
  const t = tokenCache(); if (v) t[k] = v; else delete t[k];
  fs.mkdirSync(CONF_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(TOK_FILE, JSON.stringify(t, null, 2) + "\n", { mode: 0o600 });
}
const jwtExp = (tok) => { // exp claim if the token parses as a JWT; 0 = unknown
  try { return (JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString()).exp || 0) * 1000; }
  catch { return 0; }
};
const jwtClaims = (tok) => { try { return JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString()); } catch { return {}; } };

// ---- account sessions (`enclave login`) -----------------------------------------
// The platform's OTHER auth domain: relay-minted acct_* session JWTs from a
// passkey (or SIWE) Enclave ACCOUNT. They gate /v1/account/* and /v1/billing/*
// (profile, orders, credit, the account-deployments join) and are obtained by
// approving a device-flow link in a browser — this terminal never runs
// WebAuthn itself. They can't sign transactions or enclave-private reads;
// those stay wallet-key-only by trust-domain design.
const ACCT_TOKEN_KEY = () => `${API_BASE}|account`;
function accountToken({ required = true } = {}) {
  const t = tokenCache()[ACCT_TOKEN_KEY()];
  if (t && jwtExp(t) - Date.now() > 60_000) return t;
  if (!required) return null;
  throw new Error(t ? "your account session has expired; sign in again: enclave login"
                    : "not signed in; run `enclave login` (Enclave account/passkey) or set up a wallet key (enclave key new)");
}

// The login message comes from the SERVER and we sign it with the user's key —
// with no prompt, unlike a browser wallet, so nobody is reading it. That makes
// it blind signing unless we check it first. The same key also authorizes
// `enclave-upload:…`, `enclave-secrets:put:…` (a secrets WRITE) and the
// encrypted-volume message whose signature IS the volume key; a relay that
// returned one of those strings here would get it signed and handed straight
// back. So: the message must be a SIWE login, for THIS wallet, at THIS host,
// on THIS chain — and every line must belong to the SIWE grammar, which is
// what stops anything else riding along inside it.
const SIWE_FIELD_RE = /^(URI|Version|Chain ID|Nonce|Issued At|Expiration Time|Not Before|Request ID|Resources): ?(.*)$/;
export function assertSiweLogin(message, address, apiBase) {
  const bad = (why) => { throw new Error(
    `refusing to sign: the server's login challenge is not a SIWE message for this wallet (${why}). ` +
    `Nothing was signed. If ${apiBase} is not the endpoint you meant, pass --base.`); };
  if (typeof message !== "string" || message.length > 4096) bad("not a string, or absurdly long");
  const L = message.split("\n");
  const host = (() => { try { return new URL(apiBase).host; } catch { return ""; } })();
  // The SIWE domain is the SITE (enclave.host); the API host is a sibling
  // (api.enclave.host). Accept either direction of that relationship, and skip
  // the comparison entirely for a loopback base — pointing the CLI at a local
  // relay is a deliberate act, and a false refusal there helps nobody. The
  // checks that actually stop a cross-protocol smuggle are the grammar, the
  // address and the chain, all of which still apply.
  const related = (a, b) => a === b || a.endsWith("." + b) || b.endsWith("." + a);
  const localish = /^(localhost|127\.|\[?::1|0\.0\.0\.0)/.test(host);
  const m0 = /^(\S+) wants you to sign in with your Ethereum account:$/.exec(L[0] || "");
  if (!m0) bad("first line is not the SIWE preamble");
  if (host && !localish && !related(m0[1].split(":")[0], host.split(":")[0]))
    bad(`it names domain ${m0[1]}, but we are talking to ${host}`);
  if ((L[1] || "").toLowerCase() !== address.toLowerCase()) bad("it asks a different address to sign");
  if (L[2] !== "") bad("malformed header");
  // optional one-line statement, then a blank line, then only SIWE fields
  // EIP-4361: the statement is OPTIONAL, and when it is absent so is the blank
  // line after it — fields follow the address directly. Tell the two apart by
  // whether line 3 already parses as a field.
  let i = 3;
  if (L[i] !== undefined && L[i] !== "" && !SIWE_FIELD_RE.test(L[i])) {
    i++; if (L[i] !== "") bad("statement is not a single line"); i++;
  }
  const seen = {};
  for (; i < L.length; i++) {
    if (L[i] === "" && i === L.length - 1) continue;              // trailing newline
    if (/^- \S+$/.test(L[i]) && seen["Resources"]) continue;      // resource list entries
    const f = SIWE_FIELD_RE.exec(L[i]);
    if (!f) bad(`line ${i + 1} is not a SIWE field: ${JSON.stringify(L[i].slice(0, 60))}`);
    seen[f[1]] = f[2];
  }
  if (!seen["Nonce"]) bad("no Nonce");
  if (seen["Version"] !== "1") bad("not SIWE version 1");
  if (host && !localish && seen["URI"] && !related(new URL(seen["URI"]).host.split(":")[0], host.split(":")[0]))
    bad(`URI points at ${seen["URI"]}`);
  if (seen["Chain ID"] !== String(DEFAULTS.chainId)) bad(`chain ${seen["Chain ID"]}, expected ${DEFAULTS.chainId}`);
  if (seen["Expiration Time"] && Date.parse(seen["Expiration Time"]) <= Date.now()) bad("already expired");
  return message;
}

async function bearer(account) {
  const key = `${API_BASE}|${account.address.toLowerCase()}`;
  const hit = tokenCache()[key];
  if (hit && jwtExp(hit) - Date.now() > 60_000) return hit;
  trace(`curl -s '${API_BASE}/v1/auth/nonce?address=${account.address}'`);
  const nonce = await fetch(`${API_BASE}/v1/auth/nonce?address=${account.address}`).then((r) => r.json());
  if (!nonce.message) throw new Error(`auth nonce failed: ${JSON.stringify(nonce)}`);
  assertSiweLogin(nonce.message, account.address, API_BASE);
  const signature = await account.signMessage({ message: nonce.message });
  trace(`curl -sX POST ${API_BASE}/v1/auth/login -d '{"message":…,"signature":…}'`);
  const login = await fetch(`${API_BASE}/v1/auth/login`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ message: nonce.message, signature }),
  }).then((r) => r.json());
  if (!login.token) throw new Error(`login failed: ${JSON.stringify(login)}`);
  tokenPut(key, login.token);
  return login.token;
}
// api("GET", "/v1/deployments", { auth: account }) -> parsed JSON; throws on HTTP
// error. auth: a wallet account object (SIWE session, auto-minted) or the
// string "account" (the stored `enclave login` session token).
async function api(method, p, { body, auth, ok404, text } = {}) {
  if (CHAIN_ONLY) throw new Error("--chain-only does not contact an Enclave control API");
  const url = API_BASE + p;
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (auth === "account") headers.authorization = "Bearer " + accountToken();
  else if (auth) headers.authorization = "Bearer " + await bearer(auth);
  trace(`curl -s${method === "GET" ? "" : "X " + method} '${url}'`
        + (auth ? " -H 'authorization: Bearer …'" : "")
        + (body !== undefined ? ` -d '${JSON.stringify(body)}'` : ""));
  let r = await fetch(url, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  if (r.status === 401 && auth === "account") {
    // account sessions can't be re-minted without a fresh browser approval
    tokenPut(ACCT_TOKEN_KEY(), "");
    throw new Error("the API rejected your account session; sign in again: enclave login");
  }
  if (r.status === 401 && auth) { // stale cached token: re-login once
    tokenPut(`${API_BASE}|${auth.address.toLowerCase()}`, "");
    headers.authorization = "Bearer " + await bearer(auth);
    r = await fetch(url, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  }
  if (r.status === 404 && ok404) return null;
  const raw = await r.text();
  if (!r.ok) {
    let d; try { d = JSON.parse(raw); } catch { d = {}; }
    throw new Error(`${method} ${p} -> ${r.status}: ${d.detail || d.error || raw.slice(0, 300)}`);
  }
  if (text) return raw;
  try { return JSON.parse(raw); } catch { return { raw }; }
}

// ---- formatting ------------------------------------------------------------------
const isB32 = (s) => /^0x[0-9a-fA-F]{64}$/.test(s);
const short = (id) => isB32(id) ? id.slice(0, 10) + "…" : id;
const usd6 = (v) => "$" + (Number(v) / 1e6).toFixed(2);
function dur(sec) {
  sec = Math.max(0, Math.floor(Number(sec)));
  if (sec < 90) return sec + "s";
  if (sec < 5400) return Math.round(sec / 60) + "m";
  if (sec < 172800) return (sec / 3600).toFixed(1) + "h";
  return Math.round(sec / 86400) + "d";
}
function table(rows, cols) { // cols: [{ h, k | f }]
  if (!rows.length) return say("(none)");
  const cells = rows.map((r) => cols.map((c) => String((c.f ? c.f(r) : r[c.k]) ?? "")));
  const w = cols.map((c, i) => Math.max(c.h.length, ...cells.map((r) => r[i].length)));
  say(cols.map((c, i) => c.h.padEnd(w[i])).join("  ").trimEnd());
  for (const r of cells) say(r.map((v, i) => v.padEnd(w[i])).join("  ").trimEnd());
}
function kv(pairs) {
  const w = Math.max(...pairs.filter((p) => p).map(([k]) => k.length));
  for (const p of pairs) if (p && p[1] !== undefined && p[1] !== null && p[1] !== "")
    say(`${p[0].padEnd(w)}  ${p[1]}`);
}

// The app URL rule, same as the console: via the gateway each deployment is its
// own origin <first-8-hex>.app.enclave.host; direct-to-enclave it's <origin>/x/<id>.
const appLabel = (id) => isB32(id) ? id.slice(2, 10).toLowerCase() : String(id).replace(/^dep_/, "");
const appUrl = (id) => /(^|\/\/)api\.(enclave|nan)\.host/i.test(API_BASE)
  ? `https://${appLabel(id)}.${DEFAULTS.appDomain}` : `${API_BASE}/x/${id}`;

// ---- id + app-ref resolution --------------------------------------------------
// Accepts a full bytes32 id, a legacy dep_… id, or a unique 0x-hex prefix
// (>= 8 chars) which is resolved against the on-chain ledger.
async function resolveId(input, account) {
  if (isB32(input) || /^dep_[a-z0-9]+$/i.test(input)) return input;
  const hex = input.replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{8,63}$/.test(hex)) throw new Error(`"${input}" is not a deployment id (bytes32, 0x-prefix of one, or dep_…)`);
  const mine = await chainDeployments(account?.address);
  const hit = mine.filter((d) => d.id.slice(2).startsWith(hex));
  if (hit.length === 1) return hit[0].id;
  const all = await chainDeployments(null);
  const hits = all.filter((d) => d.id.slice(2).startsWith(hex));
  if (hits.length === 1) return hits[0].id;
  throw new Error(hits.length ? `id prefix ${input} is ambiguous (${hits.length} matches)` : `no deployment matches id prefix ${input}`);
}
let _pageCache = null;
async function chainDeployments(owner) { // owner=null -> all
  if (!_pageCache) {
    _pageCache = [];
    for (let start = 0; ; start += 100) {
      const page = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "getPage", [BigInt(start), 100n]);
      _pageCache.push(...page);
      if (page.length < 100) break;
    }
  }
  return owner ? _pageCache.filter((d) => d.owner.toLowerCase() === owner.toLowerCase()) : _pageCache;
}

// [publisher/]slug[:version] -> { ref: catalog://<appId>/<idx>, ver, app } with
// an exact immutable version. Default selection prefers approved releases;
// an explicit version leaves admission to each host. The ref names the
// on-chain VERSION RECORD — the authority for the wasm, config, and ports the
// publisher recorded. CIDs are refused: a CID names bytes, not a version
// (several versions can share bytes and differ entirely in approved config).
// An explicit version selects the immutable release regardless of catalog moderation.
// Hosts enforce their owning wallets' admission policy; the CLI reports status.
async function resolveAppRef(input) {
  if (/^ipfs:\/\//i.test(input) || /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|baf[a-z0-9]{20,})$/.test(input))
    throw new Error(`CIDs can't deploy: a CID names bytes, not a version. Deploy a [publisher/]slug:version from the catalog (enclave apps)`);
  const m = input.match(/^(?:([0-9a-zA-Z.]+|0x[0-9a-fA-F]{40})\/)?([a-z0-9][a-z0-9-]*)(?::(.+))?$/);
  if (!m) throw new Error(`"${input}" is not an app reference ([publisher/]slug[:version])`);
  const [, pubFilter, slug, verLabel] = m;
  let apps = (await catalogApps()).filter((a) => a.slug === slug && (verLabel !== undefined || a.active));
  if (pubFilter) apps = apps.filter((a) => a.publisher.toLowerCase() === pubFilter.toLowerCase());
  if (!apps.length) throw new Error(`no active catalog app with slug "${slug}"${pubFilter ? ` by ${pubFilter}` : ""}`);
  if (apps.length > 1 && !pubFilter)
    throw new Error(`slug "${slug}" is published by ${apps.length} publishers; disambiguate as <publisher>/${slug}`);
  const app = apps[0];
  const versions = await readVersions(app.appId, app.versionCount);
  let vi;
  if (verLabel !== undefined) {
    vi = versions.findIndex((v) => v.version === verLabel);
    if (vi < 0) throw new Error(`app "${slug}" has no version labeled "${verLabel}"`);
  } else {
    vi = versions.findLastIndex((v) => !v.yanked && Number(v.approval) === 1);
    if (vi < 0) throw new Error(`app "${slug}" has no approved version yet`);
  }
  const ver = versions[vi];
  return { ref: `catalog://${app.appId}/${vi}`, ver, app, notice: catalogAdmissionNotice(app, ver) };
}
let _appsCache = null;
async function catalogApps() {
  if (_appsCache) return _appsCache;
  _appsCache = [];
  for (let start = 0; ; start += 50) {
    const page = await read(DEFAULTS.APP_CATALOG_ADDRESS, CATALOG_ABI, "getAppsPage", [BigInt(start), 50n]);
    _appsCache.push(...page);
    if (page.length < 50) break;
  }
  return _appsCache;
}

// Minimum shares for an app's specs on the fleet's hardware — the runner's own
// formula (spec / server spec, larger of the memory and compute axes, ceil to
// the percent grain), computed against /v1/pricing's node + card numbers.
function minShares(ver, pricing) {
  const node = pricing?.node || {}, card = pricing?.card || {};
  const axis = (need, have) => need > 0 && have > 0 ? need / have : 0;
  const cpuOf = (mb, gf) => Math.max(axis(Number(mb), (node.ramGb || 0) * 1024),
                                     axis(Number(gf), node.gflops || 0));
  const cpu = cpuOf(ver.memMb, ver.cpuGflops);
  const gpu = Math.max(axis(Number(ver.vramMb), (card.vramGb || 0) * 1024),
                       axis(Number(ver.gpuGflops), (card.tflops || 0) * 1000));
  let gpuOptional = false, fb = null;
  try {
    const o = JSON.parse(ver.config || "{}");
    gpuOptional = o.gpuOptional === true;
    if (o.cpuFallback && !Array.isArray(o.cpuFallback) && typeof o.cpuFallback === "object") fb = o.cpuFallback;
  } catch {}
  const grain = (x) => Math.min(1000, Math.ceil(x * 100) * 10); // whole percents, in milli
  // TWO node floors on a version that sized both placements: beside a card the
  // weights are in the tenant's VRAM slice, on cores they are in node RAM and
  // every matmul is the node's work. Which one applies is decided by the DIAL,
  // by the caller - the runner does the same (cpuFloorFor), and a CLI floor
  // below the runner's creates a deployment that box refuses to claim.
  // Clamped up, like the runner's: this key may only ever raise a coreless
  // floor. Absent = the two are equal and nothing changes.
  const cpuNoGpu = fb ? Math.max(cpu, cpuOf(fb.memMb || 0, fb.cpuGflops || 0)) : cpu;
  return { gpuMilli: gpuOptional ? 0 : grain(gpu),
           cpuMilli: Math.max(10, grain(cpu)),
           cpuMilliNoGpu: Math.max(10, grain(cpuNoGpu)) };
}
// The node floor for what this deployment BUYS: a 0% card dial is the coreless
// placement, and a bought card can still fall back to cores, so the dial is
// the only thing that distinguishes them ahead of a claim.
const cpuFloorOf = (mins, gpuMilli) => gpuMilli > 0 ? mins.cpuMilli : mins.cpuMilliNoGpu;
// Changing the version or shares of a LEASED deployment is judged by ONE box:
// the enclave holding the lease restarts the app in place and checks the new
// version against its own card and node (supervisor minSharesOf). /v1/pricing
// describes the fleet's best box, which on a mixed fleet is a different machine
// - so re-point minShares at the lease holder's own numbers, per axis it
// reports (a CPU-only box reports no card; those axes keep the pricing values).
// No live lease, no fleet view, or an unknown runner: pricing stands, since any
// box could claim the record next.
async function hostPricing(d, pricing) {
  const runner = String(d?.runner || "").toLowerCase();
  const none = { pricing, host: null, hostAsk: null, hostFree: false };
  if (!/^0x[0-9a-f]{64}$/.test(runner) || /^0x0+$/.test(runner)) return none;
  if (!(Number(d.leaseUntil) * 1000 > Date.now())) return none;
  const rows = await api("GET", "/enclaves").then((j) => j?.enclaves || []).catch(() => []);
  const row = rows.find((e) => String(e?.id || "").toLowerCase() === runner);
  const a = row?.availability;
  if (!a) return none;
  const pick = (v, fallback) => (Number(v) > 0 ? Number(v) : fallback);
  const owner = String(d?.owner || "").toLowerCase();
  return {
    host: row.name || "the enclave holding the lease",
    // FREE SELF-HOSTING (ledger rev 12): this box waives its whole charge when
    // its DECLARED payout wallet owns the deployment - EnclaveDeployments
    // ._hostRate, which _resizeRate goes through too. Callers gate it on the
    // ledger rev; without it a self-hosted record (correctly empty balance) is
    // priced at the box's ask and refused as unfunded. The row's top-level
    // field only: the relay projects that from the on-chain registry entry,
    // where the ledger reads it too. The copy inside /availability is the box
    // talking, and a box must not be able to quote itself free.
    hostFree: /^0x[0-9a-f]{40}$/.test(owner) && !/^0x0+$/.test(owner)
              && String(row.payoutWallet || "").toLowerCase() === owner,
    // its posted price (rev-8 ledgers): a resize re-buys from THIS box
    hostAsk: { name: row.name, cpu6: Number(a.askCpuPricePerSec6) || 0, gpu6: Number(a.askGpuPricePerSec6) || 0 },
    pricing: { ...pricing,
      node: { ...(pricing?.node || {}), ramGb: pick(a.nodeRamGb, pricing?.node?.ramGb),
              gflops: pick(a.nodeGflops, pricing?.node?.gflops), vcpus: pick(a.nodeVcpus, pricing?.node?.vcpus) },
      card: { ...(pricing?.card || {}), vramGb: pick(a.cardVramGb, pricing?.card?.vramGb),
              tflops: pick(a.cardTflops, pricing?.card?.tflops) } },
  };
}

// What a whole node / whole card costs per second right now, and who says so.
// Rev-8 ledgers carry no platform price: every enclave posts its own, so a NEW
// deployment is priced at the cheapest live one (the box it will land on), and
// a change to an existing one is priced at its lease holder (`at`, from
// hostPricing) — that is the box actually selling it the slice.
async function livePrices6(at) {
  const { rev } = await depAbi();
  if (rev < 8) {
    const U = (name) => [{ type: "function", name, stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] }];
    const [gpu6, cpu6] = await Promise.all([
      read(DEFAULTS.DEPLOYMENTS_ADDRESS, U("pricePerSec6"), "pricePerSec6"),
      read(DEFAULTS.DEPLOYMENTS_ADDRESS, U("cpuPricePerSec6"), "cpuPricePerSec6"),
    ]);
    return { gpu6, cpu6, who: "the platform list price" };
  }
  if (at && at.cpu6 > 0)
    return { gpu6: BigInt(at.gpu6), cpu6: BigInt(at.cpu6),
             who: at.name ? `${at.name}'s posted price` : "the serving enclave's posted price" };
  const av = await api("GET", "/availability").catch(() => null);
  const cpu = Number(av?.cheapestCpuPricePerSec6) || 0, gpu = Number(av?.cheapestGpuPricePerSec6) || 0;
  if (!cpu) throw new Error("no live enclave is posting a price right now, so this can't be priced - try again shortly");
  return { gpu6: BigInt(gpu), cpu6: BigInt(cpu), who: "the cheapest live enclave" };
}
const rate6Of = (p, gpuMilli, cpuMilli) => (p.gpu6 * BigInt(gpuMilli) + p.cpu6 * BigInt(cpuMilli) + 999n) / 1000n;
// $/hour <-> USDC 6dp per second (the ledger's unit for caps and rates)
const perSec6FromHour = (usdPerHour) => BigInt(Math.round(Number(usdPerHour) * 1e6 / 3600));

// ---- funding (EIP-3009 receiveWithAuthorization -> EnclaveDeployments) ---------------
// `retry` (deploy's read-after-write retry) wraps the SEND, never the signing:
// a second send carries the same authorization and its one EIP-3009 nonce, so
// at most one of the two can ever move money.
async function fundUsdc(account, id, amountUsd, { retry = (send) => send() } = {}) {
  // Funding is billed in whole cents (contract balances are 6dp USDC). Reject
  // sub-cent amounts rather than silently rounding them to nothing / to a cent.
  const cents = amountUsd * 100;
  if (amountUsd > 0 && amountUsd < 0.01)
    throw new Error(`minimum USDC funding is $0.01 (got $${amountUsd}); amounts are billed in whole cents`);
  if (amountUsd > 0 && Math.abs(cents - Math.round(cents)) > 1e-9)
    throw new Error(`USDC funding is billed in whole cents: $${amountUsd} isn't a whole number of cents (nearest is $${(Math.round(cents) / 100).toFixed(2)})`);
  const value = BigInt(Math.round(cents)) * 10000n;             // whole cents -> 6dp
  const bal = await read(DEFAULTS.USDC_ADDRESS, ERC20_ABI, "balanceOf", [account.address]);
  if (bal < value) throw new Error(`wallet holds ${usd6(bal)} USDC on Base, needs ${usd6(value)}; fund ${account.address}`);
  // The EIP-712 domain is PINNED, never taken from the API: a forged domain
  // could coax a valid ReceiveWithAuthorization signature over a different
  // token/chain/contract. Base USDC (Circle native) domain = {"USD Coin","2"}.
  const domain = { name: "USD Coin", version: "2", chainId: DEFAULTS.chainId,
                   verifyingContract: DEFAULTS.USDC_ADDRESS };
  // authorization nonce: first 16 bytes = the deployment id's first 16 bytes
  // (the contract requires it), last 16 random so top-ups never collide
  const nonce = id.slice(0, 34) + crypto.randomBytes(16).toString("hex");
  const validBefore = BigInt(Math.floor(Date.now() / 1000) + 3600);
  const message = { from: account.address, to: DEFAULTS.DEPLOYMENTS_ADDRESS,
                    value, validAfter: 0n, validBefore, nonce };
  trace(`sign EIP-712 ReceiveWithAuthorization value=${usd6(value)} nonce=${nonce.slice(0, 20)}…`);
  const signature = await account.signTypedData({
    domain, primaryType: "ReceiveWithAuthorization",
    types: { ReceiveWithAuthorization: [
      { name: "from", type: "address" }, { name: "to", type: "address" },
      { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" },
      { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] },
    message,
  });
  const { abi } = await depAbi();
  await retry(() => sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi,
    functionName: "fundWithAuthorization",
    args: [id, account.address, value, 0n, validBefore, nonce, signature] }));
  return value;
}

// ---- read-after-write: a mined create is not yet a record every reader sees ----
// Base RPCs are load-balanced pools, so the node that handed back the create's
// receipt need not be the one the next call lands on, and the relay reads the
// ledger through an RPC of its own. Seen live 2026-09-26: seconds after create
// mined, fund's gas estimate reverted "unknown" (the ledger's
// require(_exists[id])) and the relay's secrets gate answered 404 for the id.
// So deploy waits until every reader sees the record before it stages or
// spends anything on it, and gives each step ONE retry for the lag that can
// still slip past. The poll and retry pauses scale with the bound.
const VISIBLE_WAIT_MS = (Number(env.ENCLAVE_VISIBLE_WAIT) > 0 ? Number(env.ENCLAVE_VISIBLE_WAIT) : 60) * 1000;
const VISIBLE_POLL_MS = Math.min(2000, Math.max(20, VISIBLE_WAIT_MS / 30));
const LAG_PAUSE_MS = Math.min(3000, Math.max(20, VISIBLE_WAIT_MS / 20));
// the lag signatures: the ledger's "unknown" on a node without the record,
// and the relay's owner gate finding no such id in its ledger view
const isUnknownRevert = (e) => !!(e?.walk?.((x) => x?.reason === "unknown"))
  || /(reverted with the following reason:|execution reverted:?)\s*unknown\b/i.test(String(e?.shortMessage || e?.message || ""));
const isRelay404 = (e) => /-> 404: not_found\b/.test(String(e?.message || ""));
// get(id) as EVERY configured RPC answers it; null = that RPC couldn't be
// asked (transport trouble abstains - it can neither confirm nor deny)
async function ledgerViews(id) {
  const { abi } = await depAbi();
  return Promise.all(pubEach().map(({ c }) =>
    c.readContract({ address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi, functionName: "get", args: [id] }).catch(() => null)));
}
// Until every RPC that answers returns the record with its owner (and at
// least one does), and - with secrets to stage - the relay's tokenless record
// read, which answers from the same ledger cache its secrets gate checks, has
// it too (404 = not yet; any other failure = this API can't say, and the
// secrets step's own retry covers it). -> { views } | { lagging: "who" }
async function waitVisible(id, owner, { relay }) {
  const deadline = Date.now() + VISIBLE_WAIT_MS;
  let relayOk = !relay, waited = false;
  for (;;) {
    const [views, relayNow] = await Promise.all([ledgerViews(id),
      relayOk || api("GET", `/v1/deployments/${id}`, { ok404: true }).then(Boolean, () => true)]);
    relayOk = relayNow;
    const behind = pubEach().filter((_r, i) => views[i] && views[i].owner.toLowerCase() !== owner.toLowerCase()).map((r) => r.host);
    if (!relayOk) behind.push(`the relay (${API_BASE})`);
    if (views.some(Boolean) && !behind.length) return { views };
    if (Date.now() >= deadline)
      return { lagging: views.some(Boolean) ? `${behind.join(" and ")} still can't see it` : "no RPC answered" };
    if (!waited) { waited = true; say("waiting for the new record to reach every RPC" + (relay ? " and the relay" : "") + "…"); }
    await sleep(VISIBLE_POLL_MS);
  }
}

// ---- attestation verification (the real thing, run locally, with this repository's own verifier) ---------------------
// verifier/metal-box.mjs through verifier/consumer.mjs (bundled by cli/build.mjs): the box is challenged with OUR fresh nonce
// through the relay, the report must be AMD-signed (VCEK -> the pinned AMD root), meet the TCB floor and bind the box's
// transport key with that nonce, and its launch measurement must be one we expect: --expect, or - labelled, never a pass -
// the relay operator's allowlist. Nothing here trusts the relay's or the box's word for any of it.
async function verifyBox(name) {
  let C;
  try { C = await import("../verifier/consumer.mjs"); }
  catch (e) { throw new Error(`the Enclave verifier is not part of this install (${e.message}); reinstall the CLI`); }
  let expected = null;
  if (opt.expect) {
    const ms = String(opt.expect).split(",").map((m) => m.trim().toLowerCase()).filter(Boolean);
    if (!ms.length || !ms.every((m) => /^[0-9a-f]{96}$/.test(m))) throw new Error("--expect takes launch measurements, 96 hex characters each, comma-separated");
    expected = { measurements: ms, source: "--expect" };
  }
  let minTcb;
  if (opt.minTcb) { try { minTcb = JSON.parse(opt.minTcb); } catch { throw new Error("--min-tcb must be JSON like {\"Turin\":{\"fmc\":1,\"bootloader\":3,\"tee\":2,\"snp\":5,\"microcode\":117}}"); } }
  let collateral = null;
  if (opt.collateralDir) { const { fileCollateral } = await import("../verifier/collateral.mjs"); collateral = fileCollateral(path.resolve(opt.collateralDir)); }
  trace(`verify box ${name}: fresh attestation over our nonce through ${API_BASE}, AMD collateral from ${collateral ? opt.collateralDir : "AMD KDS"}, measurement from ${expected ? "--expect" : "the relay operator's allowlist (limited)"}`);
  return C.verifyMetalBox({ apiBase: new URL(API_BASE).origin, name, expected, minTcb, collateral });
}
// the box a deployment runs on, from its attestation pointer (".../t/<box>/..."); null when it is not an attested SNP box
const boxOfEndpoint = (ep) => { try { return (new URL(ep).pathname.match(/^\/t\/([A-Za-z0-9_-]{1,64})\//) || [])[1] || null; } catch { return null; } };
function printBoxVerdict(r) {
  kv([["box", r.subject?.name], ["verifier", "enclave (verifier/metal-box.mjs)"], ["  status", r.status],
      ["  measurement", r.measurement], ["  expected", r.expected ? `${r.expected.source}: ${r.expected.measurements.length} value(s)` : null],
      ["  product", r.product], ["  transport key", r.transportKeySha256 ? `sha256:${r.transportKeySha256}` : null],
      ["  nonce", r.nonce ? `${r.nonce.slice(0, 16)}… (ours, fresh)` : null],
      ["  failed", (r.failedChecks || []).join(", ") || "-"], ["  omitted", (r.omissions || []).join(", ") || "-"]]);
  if (r.channel) say(`  channel     ${r.channel}`);
  const last = (r.reasons || []).at(-1);
  say(r.status === "verified" ? "verdict     PASS: a genuine, fresh AMD SEV-SNP report from this box, at a measurement you expect"
    : r.status === "limited" ? `verdict     LIMITED: every check passed, but ${(r.omissions || []).join(", ")} was not independently judged${r.omissions?.includes("expected-measurement-operator-stated") ? " (pin the measurement with --expect)" : ""}; not a pass`
    : `verdict     ${String(r.status).toUpperCase()}: do not send data${last ? ` (${last})` : ""}`);
}
const attestExit = (status) => (status === "verified" ? 0 : status === "limited" ? 3 : 1);
async function attestDeployment(account, id) {
  // Keyless works: the endpoint is public. The OWNER's session adds one thing —
  // the GPU report is regenerated fresh over OUR nonce — so only authenticate
  // and send a challenge when our key actually owns the deployment; anyone
  // else gets the enclave's cached report (the server would ignore their nonce
  // anyway, and an ignored challenge prints as a scary false "nonce mismatch").
  let asOwner = false;
  if (account && isB32(id)) {
    const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "get", [id]).catch(() => null);
    asOwner = !!d && d.owner.toLowerCase() === account.address.toLowerCase();
  } else if (account) asOwner = true;   // legacy dep_… id: no chain row to compare against
  const nonce = asOwner ? crypto.randomBytes(32).toString("hex") : null;
  let att;
  try { att = await api("GET", `/v1/deployments/${id}/attestation${nonce ? `?nonce=${nonce}` : ""}`, asOwner ? { auth: account } : {}); }
  catch (e) {
    // a Shield (Hyper-V partition) host carries its evidence in the app's own TLS, not an SNP report this command verifies
    if (/shield_tls_only/.test(e.message)) return { att: null, nonce, box: null, unsupported: "this deployment runs on an Enclave Shield host (a Hyper-V partition): its evidence travels in the app's own TLS and is host-attested, not an AMD SEV-SNP report; `enclave attest` verifies SEV-SNP boxes only" };
    throw e;
  }
  const box = boxOfEndpoint(att.verification?.attestationEndpoint);
  if (!box) return { att, nonce, box: null, unsupported: `the deployment's host is not an attested SEV-SNP box (${att.verification?.attestationEndpoint || "no attestation pointer"})` };
  return { att, nonce, box, result: await verifyBox(box) };
}
// ---- commands ---------------------------------------------------------------------
// `enclave login`: sign in with an Enclave ACCOUNT (passkey/SIWE) through the
// platform's device flow — the same /v1/account/device/* endpoints behind the
// site's "Use your phone" sign-in. This terminal starts a request and shows a
// link + code; the user approves it in any browser where their passkey works.
// The link/QR carries only the CODE — claiming the session additionally needs
// the SECRET, which never leaves this process, so a shoulder-surfed code can
// never hand this terminal's session to someone else (worst case a stranger
// signs US into THEIR account; the approve page carries warning copy).
async function cmdLogin(rest) {
  const f = flags(rest, { bool: ["--print"] });
  const cur = accountToken({ required: false });
  if (cur) say(`already signed in as ${jwtClaims(cur).sub || "?"}; approving again replaces that session`);
  const start = await api("POST", "/v1/account/device/start", { body: {} });
  if (!start.code || !start.secret) throw new Error(`device flow unavailable: ${JSON.stringify(start).slice(0, 200)}`);
  const link = start.link || `https://enclave.host/link?code=${start.code}`;
  const pretty = start.code.length === 8 ? start.code.slice(0, 4) + "-" + start.code.slice(4) : start.code;
  say(`Open this link on your phone or in any browser where you can sign in to Enclave:`);
  say(``);
  say(`    ${link}`);
  say(``);
  say(`(or open ${link.split("?")[0]} and enter the code ${pretty})`);
  say(`Only approve a request you started yourself. Waiting for approval…`);
  const deadline = Date.parse(start.expiresAt) || Date.now() + 3 * 60_000;
  for (;;) {
    await sleep(Math.max(250, (Number(start.interval) || 3) * 1000));
    if (Date.now() > deadline) throw new Error("the sign-in request expired before it was approved; run `enclave login` again");
    // 404 = the code is gone (expired/claimed elsewhere); other errors are
    // transient network blips — keep polling until the deadline says stop
    const r = await api("POST", "/v1/account/device/claim",
      { body: { code: start.code, secret: start.secret }, ok404: true }).catch(() => undefined);
    if (r === null) throw new Error("the sign-in request expired; run `enclave login` again");
    if (r === undefined || r.status === "pending") continue;
    if (r.status === "denied") throw new Error("the request was denied from the approving device");
    if (r.status === "ok" && r.token) {
      tokenPut(ACCT_TOKEN_KEY(), r.token);
      if (opt.json) return jout({ accountId: r.accountId, method: r.method, expiresAt: r.expiresAt,
                                  ...(f.print ? { token: r.token } : {}) });
      say(`signed in as ${r.accountId} (session until ${r.expiresAt})`);
      say(`try: enclave whoami · enclave ls · enclave account`);
      if (f.print) say(r.token);   // --print: the raw bearer, for curl/scripts against /v1/account/* + /v1/billing/*
      return;
    }
    throw new Error(`unexpected claim answer: ${JSON.stringify(r).slice(0, 200)}`);
  }
}

async function cmdLogout() {
  const had = !!tokenCache()[ACCT_TOKEN_KEY()];
  tokenPut(ACCT_TOKEN_KEY(), "");
  say(had ? "signed out (the local session token is discarded; the session also expires server-side on its own)"
          : "no account session to discard");
}

async function cmdKey(rest) {
  const sub = rest[0];
  if (sub === "new") {
    const f = flags(rest.slice(1), { bool: ["--force"] });
    if (fs.existsSync(KEY_FILE) && !f.force)
      throw new Error(`${KEY_FILE} already exists; pass --force to overwrite it (this abandons the old address!)`);
    const pk = generatePrivateKey();
    saveKey(pk);
    const a = privateKeyToAccount(pk);
    if (opt.json) return jout({ address: a.address, keyFile: KEY_FILE });
    say(a.address);
    say(`key saved to ${KEY_FILE} (0600). Fund this address with USDC on Base (chain 8453)`);
    say(`plus a little ETH for transaction gas, then: enclave deploy <app> --fund 5`);
  } else if (sub === "import") {
    const pk0 = await promptSecret("private key (hidden): ");
    let pk = pk0.startsWith("0x") ? pk0 : "0x" + pk0;
    if (!/^0x[0-9a-fA-F]{64}$/.test(pk)) throw new Error("that is not a 32-byte hex private key");
    saveKey(pk);
    const a = privateKeyToAccount(pk);
    if (opt.json) return jout({ address: a.address, keyFile: KEY_FILE });
    say(a.address);
    say(`key saved to ${KEY_FILE} (0600)`);
  } else throw new Error("usage: enclave key new [--force] | enclave key import");
}

async function cmdWhoami() {
  const account = loadKey({ required: false });
  const acctTok = accountToken({ required: false });
  if (!account && !acctTok)
    throw new Error("no wallet key and no account session. Run `enclave key new` (wallet) or `enclave login` (Enclave account/passkey)");
  const out = {}, rows = [];
  if (account) {
    const [eth, usdc] = await Promise.all([
      pub().getBalance({ address: account.address }),
      read(DEFAULTS.USDC_ADDRESS, ERC20_ABI, "balanceOf", [account.address]),
    ]);
    let running = null;
    try {
      const ls = await api("GET", "/v1/deployments", { auth: account });
      running = (ls.data || []).filter((d) => d.status === "running").length;
    } catch {} // API being down shouldn't hide your own balances
    Object.assign(out, { address: account.address, ethWei: eth, usdc6: usdc, running, keyFile: env.ENCLAVE_KEY ? "(env)" : KEY_FILE });
    rows.push(["address", account.address],
      ["usdc", usd6(usdc) + " (Base)"],
      ["eth", formatUnits(eth, 18).replace(/(\.\d{6})\d+$/, "$1") + " (gas)"],
      ["running", running === null ? "(api unreachable)" : String(running)],
      ["key", env.ENCLAVE_KEY ? "ENCLAVE_KEY env" : KEY_FILE]);
  }
  if (acctTok) {
    const c = jwtClaims(acctTok);
    const until = c.exp ? new Date(c.exp * 1000).toISOString() : null;
    out.account = { accountId: c.sub, method: c.amr, expiresAt: until };
    rows.push(["account", `${c.sub} (${c.amr || "?"} session${until ? ` until ${until.slice(0, 10)}` : ""})`]);
    // credit balance is a nicety: no vault key / vaults dark / API down must
    // not break whoami
    try {
      const v = await api("GET", "/v1/billing/vault", { auth: "account" });
      out.account.creditUsd = v.balanceUsd;
      rows.push(["credit", `$${v.balanceUsd} (account credit)`]);
    } catch {}
  }
  if (opt.json) return jout(out);
  kv(rows);
}

async function cmdLs() {
  const account = loadKey({ required: false });
  const acctTok = accountToken({ required: false });
  if (!account && !acctTok)
    throw new Error("no wallet key and no account session. Run `enclave key new` (wallet) or `enclave login` (Enclave account/passkey)");
  const [apiList, mine, acctList] = await Promise.all([
    account ? api("GET", "/v1/deployments", { auth: account }).then((r) => r.data || []).catch(() => []) : [],
    account ? chainDeployments(account.address).catch(() => []) : [],
    // the account join: order-provisioned + credit-vault-owned deployments,
    // served in the same view shape as the enclave rows
    acctTok ? api("GET", "/v1/billing/deployments", { auth: "account" }).then((r) => r.deployments || []).catch(() => []) : [],
  ]);
  const seen = new Set(apiList.map((d) => String(d.id).toLowerCase()));
  const rows = apiList.map((d) => ({
    id: d.id, app: d.image?.reference || "", status: d.status,
    shares: `${d.resources?.gpuShare ? Math.round(d.resources.gpuShare * 100) + "% gpu " : ""}${Math.round((d.resources?.cpuShare || 0) * 100)}% cpu`,
    left: d.timeRemainingSec != null ? dur(d.timeRemainingSec) : "",
    url: d.status === "running" ? appUrl(d.id) : "",
  }));
  for (const d of acctList) {
    const id = d.deploymentId || d.id;
    if (!id || seen.has(String(id).toLowerCase())) continue;
    seen.add(String(id).toLowerCase());
    rows.push({ id, app: d.image?.reference || "", status: d.status || "unknown",
      shares: `${d.resources?.gpuShare ? Math.round(d.resources.gpuShare * 100) + "% gpu " : ""}${Math.round((d.resources?.cpuShare || 0) * 100)}% cpu`,
      left: d.timeRemainingSec != null ? dur(d.timeRemainingSec) : "",
      url: d.status === "running" ? appUrl(id) : "",
      via: d.viaVault ? "credit" : "order" });
  }
  // queue items the fleet hasn't picked up (or that ran dry) exist only on-chain
  for (const d of mine) {
    if (seen.has(d.id.toLowerCase())) continue;
    if (!d.active) continue;
    const leased = Number(d.leaseUntil) * 1000 > Date.now();
    const fundable = d.rate > 0n ? Number(d.balance6 / d.rate) : 0;
    rows.push({ id: d.id, app: d.appRef, status: leased ? "claimed" : (fundable >= 1 ? "queued" : "unfunded"),
                shares: `${d.gpuMilli ? (Number(d.gpuMilli) / 10) + "% gpu " : ""}${Number(d.cpuMilli) / 10}% cpu`,
                left: dur(fundable), url: "" });
  }
  if (opt.json) return jout({ deployments: rows });
  table(rows, [{ h: "id", f: (r) => short(r.id) }, { h: "app", f: (r) => r.app.length > 40 ? r.app.slice(0, 37) + "…" : r.app },
               { h: "status", k: "status" }, { h: "shares", k: "shares" },
               { h: "funded", k: "left" }, { h: "url", k: "url" }]);
}

async function cmdStatus(rest) {
  // keyless works: the ledger row is public, and public deployments answer the
  // API read unauthenticated (account-session users get their status this way
  // too — enclave-private reads stay wallet-gated by trust-domain design)
  const account = loadKey({ required: false });
  if (!rest[0]) throw new Error("usage: enclave status <id>");
  const id = await resolveId(rest[0], account);
  const rec = account
    ? await api("GET", `/v1/deployments/${id}`, { auth: account, ok404: true })
    : await api("GET", `/v1/deployments/${id}`, { ok404: true }).catch(() => null);
  let chainRec = null, cap6 = 0n;
  if (isB32(id)) try { chainRec = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "get", [id]); } catch {}
  if (chainRec && (await depAbi()).rev >= 8)
    try { cap6 = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "capOf", [id]); } catch {}
  let proven = null, proofReq = false;
  if (chainRec && (await depAbi()).rev >= 9) try {
    proven = Number(await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "provenUntil", [id]));
    proofReq = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "proofRequired", []);
  } catch {}
  if (!rec && !chainRec) throw new Error(`no deployment ${rest[0]} (not on any live enclave, not on the ledger)`);
  if (opt.json) return jout({ api: rec, chain: chainRec, ...(cap6 > 0n ? { maxRate6: String(cap6) } : {}),
    ...(proven != null ? { proofOfTime: { provenUntil: proven, required: proofReq } } : {}) });
  const leased = chainRec && Number(chainRec.leaseUntil) * 1000 > Date.now();
  // queued vs unfunded is the contract's claimable() boundary (balance6 >= rate):
  // below it no enclave will ever claim, so "queued" would be a lie
  // ... unless an enclave hosts this owner for FREE (ledger rev 12): its price
  // there is zero, so there is no balance to be short of. The relay's row
  // carries that verdict; the arithmetic above cannot see it, because an
  // unclaimed record still carries its worst-case ceiling as `rate`.
  const claimable = !!(rec && rec.hostedFree) || (chainRec && chainRec.balance6 >= chainRec.rate);
  kv([
    ["id", id],
    ["app", rec?.image?.reference || chainRec?.appRef],
    ["status", rec?.status || (chainRec ? (!chainRec.active ? "stopped" : leased ? "claimed (no live enclave record yet)" : claimable ? "queued: waiting for an enclave to claim" : "unfunded: spent its funding; a top-up re-queues it (enclave fund)") : null)],
    ["visibility", (rec ? rec.public : chainRec?.isPublic) ? "public" : "private (owner only: bearer here, wallet sign-in in a browser)"],
    rec?.resources ? ["shares", `gpu ${Math.round((rec.resources.gpuShare || 0) * 100)}% · cpu ${Math.round((rec.resources.cpuShare || 0) * 100)}%`]
                   : chainRec ? ["shares", `gpu ${Number(chainRec.gpuMilli) / 10}% · cpu ${Number(chainRec.cpuMilli) / 10}%`] : null,
    chainRec ? ["rate", `${usd6(chainRec.rate)}/s (${usd6(chainRec.rate * 3600n)}/h)`
      + (leased ? " at its current enclave" : cap6 > 0n ? " (its ceiling; no enclave is serving it)" : "")] : rec ? ["rate", `$${rec.ratePerSecondUsdc}/s`] : null,
    cap6 > 0n ? ["rate cap", `${usd6(cap6 * 3600n)}/h - only enclaves at or under this can run it (enclave rate-cap)`] : null,
    // a lowered cap that has stopped the app: the runner says so on the record
    rec?.rateCapBlocked ? ["! cap", rec.rateCapBlocked] : null,
    chainRec ? ["balance", `${usd6(chainRec.balance6)} on-chain (${dur(chainRec.rate > 0n ? Number(chainRec.balance6 / chainRec.rate) : 0)})`] : null,
    rec?.timeRemainingSec != null ? ["remaining", dur(rec.timeRemainingSec)] : null,
    leased ? ["lease", `until ${new Date(Number(chainRec.leaseUntil) * 1000).toISOString()} (runner ${short(chainRec.runner)}, operator ${chainRec.runnerOperator})`] : null,
    // Proof of time: the gap between what you are paying for and what the host
    // has proven it delivered. Healthy is a few minutes (one proof interval);
    // a large or growing gap means the host stopped proving it is serving, and
    // from the ledger's rev 9 on, it stops being paid for that time too.
    ...(leased && proven != null ? (() => {
      const now = Math.floor(Date.now() / 1000);
      const gap = Math.max(0, Math.min(now, Number(chainRec.leaseUntil)) - proven);
      return [["proven", proven
        ? `service proven through ${new Date(proven * 1000).toISOString()}`
          + (gap > 0 ? ` — ${dur(gap)} of this lease is UNPROVEN` : " — fully covered")
          + (proofReq ? "" : " (the ledger is still in its proof grace window: held time is paid for now)")
        : "nothing proven on this lease yet"]];
    })() : []),
    ["url", appUrl(id)],
    // the deployment's dedicated IPv6: declared tcp/udp ports served on it at
    // their real port numbers; with egress on it's the outbound address too
    rec?.network?.address ? ["ip6", rec.network.address
      + (rec.network.tcp || rec.network.udp ? "" : rec.network.egress ? " (egress only)" : "")] : null,
    rec?.network?.tcp ? ["tcp", JSON.stringify(rec.network.tcp)] : null,
    rec?.network?.udp ? ["udp", JSON.stringify(rec.network.udp)] : null,
  ]);
}

async function cmdLogs(rest) {
  const account = loadKey();
  const f = flags(rest, { bool: ["-f", "--follow"], val: ["--tail"] });
  if (!f._[0]) throw new Error("usage: enclave logs <id> [-f] [--tail N]");
  const id = await resolveId(f._[0], account);
  const tail = Math.min(2000, parseInt(f.tail || "200", 10) || 200);
  const follow = f.f || f.follow;
  let last = "";
  for (;;) {
    const text = await api("GET", `/v1/deployments/${id}/logs?tail=${follow ? 2000 : tail}`, { auth: account, text: true });
    if (text !== last) {
      // print only what's new when the previous fetch is a prefix; else reprint
      stdout.write(text.startsWith(last) ? text.slice(last.length) : text);
      last = text;
    }
    if (!follow) break;
    await sleep(2000);
  }
}

async function cmdFund(rest) {
  // with a session: deploy.fund, paid out of the session budget (USDC only), on a deployment the vault holds or
  // (delegated) the owner's wallet holds; the escrowed share is credited to whoever holds the record
  const sess = await sessionForCommand();
  const account = sess ? null : loadKey();
  const f = flags(rest, { val: ["--usdc", "--eth"] });
  if (!f._[0] || (!f.usdc && !f.eth)) throw new Error("usage: enclave fund <id> --usdc 5 | --eth 0.002");
  if (sess && f.eth) throw new Error("a session funds in USDC out of its budget: use --usdc <usd> (or --wallet to fund with ETH from your wallet)");
  if (sess) await sessionRequire(sess, "deploy.fund");
  const id = await resolveId(f._[0], account ?? sessionAccount(sess));
  if (!isB32(id)) throw new Error("only on-chain deployments (bytes32 ids) are fundable by transaction");
  const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "get", [id]);
  if (d.owner === "0x0000000000000000000000000000000000000000") throw new Error(`no deployment ${short(id)} on the ledger`);
  // the ledger funds only an ACTIVE record (_requireActive): a stopped or refunded one would revert "inactive" after the
  // signature and the gas estimate, so say what brings it back instead of sending that (enclave-b4)
  if (!d.active) throw new Error(`${short(id)} is inactive (stopped or cancelled), and the ledger funds only an active record: `
    + `its owner runs \`enclave resume ${short(id)}\` first, then funds it`);
  const held = sess ? await sessionHolder(sess, d, id, "deploy.fund") : null;
  if (held === "wallet") await sessionWalletFund(sess, d, id);
  if (f.usdc) {
    const amt = numFlag(f.usdc, "--usdc");
    if (!(await confirm(`fund ${short(id)} with ${usd6(BigInt(Math.round(amt * 1e6)))} USDC (buys ~${dur(d.rate > 0n ? amt * 1e6 / Number(d.rate) : 0)})${sess ? " out of the session budget" : ""}`
                      + `${held === "wallet" ? ` (its unspent escrow refunds to the owner's wallet ${await sessionOwner(sess)})` : ""}?`)))
      return say("aborted");
    if (sess) await sessionCall(sess, "deploy.fund", { id, amount6: sessionUsd6(amt, "--usdc") });
    else await fundUsdc(account, id, amt);
  } else {
    const amt = numFlag(f.eth, "--eth");
    if (!(await confirm(`fund ${short(id)} with ${amt} ETH (credited at the Chainlink ETH/USD rate)?`))) return say("aborted");
    await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi: (await depAbi()).abi,
      functionName: "fundEth", args: [id], value: parseEther(String(amt)) });
  }
  const fresh = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "get", [id]);
  if (opt.json) return jout({ id, balance6: fresh.balance6, fundableSec: fresh.rate > 0n ? Number(fresh.balance6 / fresh.rate) : 0 });
  say(`balance ${usd6(fresh.balance6)}: ${dur(fresh.rate > 0n ? Number(fresh.balance6 / fresh.rate) : 0)} of runtime at ${usd6(fresh.rate * 3600n)}/h`);
}

async function cmdAttest(rest) {
  if (!rest[0]) {
    // no id: every attested SEV-SNP box the relay holds (the boxes tenant apps run on)
    const rows = ((await api("GET", "/enclaves").catch(() => null))?.enclaves || []).filter((e) => e.mode === "snp" && e.name);
    if (!rows.length) { if (opt.json) return jout({ boxes: [] }); say("no attested SEV-SNP box is attached right now"); exit(1); }
    const results = [];
    for (const e of rows) results.push(await verifyBox(e.name));
    // the exit code follows the verdict in both output modes (0 verified, 3 limited, 1 anything else): a script that only
    // reads the code can never take a refusal for a pass
    if (opt.json) jout({ boxes: results.map(({ document, ...r }) => r) }); else for (const r of results) printBoxVerdict(r);
    exit(Math.max(...results.map((r) => attestExit(r.status))));
    return;
  }
  // No wallet needed: attestation is a READER's tool (an app's users verify the
  // enclave before sending it data, and they don't own the deployment). A key,
  // when one is configured, only upgrades the GPU report to a fresh challenge
  // signed over our own nonce.
  const account = loadKey({ required: false });
  const id = await resolveId(rest[0], account);
  const { att, nonce, box, result, unsupported } = await attestDeployment(account, id);
  if (unsupported) {
    if (opt.json) jout({ id, status: "unsupported", reason: unsupported }); else { kv([["deployment", id]]); say(`verdict     UNSUPPORTED: ${unsupported}`); }
    exit(1); return;
  }
  // The GPU CC report must be signed over the SAME nonce we sent, or its
  // freshness is unproven (a replayed report would still "have a nonce").
  const gpuNonce = att.gpu ? String(att.gpu.nonce || "").toLowerCase().replace(/^0x/, "") : "";
  const gpuNonceOk = !!nonce && !!gpuNonce && gpuNonce === nonce.toLowerCase();
  if (opt.json) { const { document, ...r } = result; jout({ id, box, ...r, gpu: att.gpu ? { ccMode: att.gpu.ccMode ?? null, fresh: gpuNonceOk, report: !!att.gpu.report } : null }); exit(attestExit(result.status)); return; }
  kv([["deployment", id], att.app?.digest ? ["app digest", att.app.digest] : null]);
  printBoxVerdict(result);
  if (att.gpu) say(`gpu         CC report ${att.gpu.report ? "present" : "absent"}${att.gpu.ccMode ? `, ccMode=${att.gpu.ccMode}` : ""}`
    + (gpuNonceOk ? `, fresh (signed over our nonce)`
     : nonce      ? `, freshness NOT verified (${att.gpu.nonce ? "nonce mismatch" : "no nonce returned"})`
                  : `, enclave-chosen nonce (an owner key buys a challenge over your own nonce)`));
  exit(attestExit(result.status));
}


async function cmdStop(rest) {
  // with a session: deploy.setActive(false) on a deployment the vault holds, or (delegated) the owner's wallet holds
  const sess = await sessionForCommand();
  const account = sess ? null : loadKey();
  if (!rest[0]) throw new Error("usage: enclave stop <id>");
  if (sess) await sessionRequire(sess, "deploy.setActive");
  const id = await resolveId(rest[0], account ?? sessionAccount(sess));
  if (!(await confirm(`stop ${short(id)}? (suspends the app and takes it off the queue; the remaining balance stays on the deployment - \`enclave resume\` re-queues it)`))) return say("aborted");
  if (sess) return stopViaSession(sess, id);
  let sent = null;   // the setActive(false) THIS run confirmed: { tx, block }
  if (isB32(id)) {
    // take the work item off the queue first so no enclave re-claims it…
    const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "get", [id]).catch(() => null);
    if (d && d.active && d.owner.toLowerCase() === account.address.toLowerCase()) {
      const rcpt = await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi: (await depAbi()).abi,
        functionName: "setActive", args: [id, false] });
      sent = { tx: rcpt.transactionHash, block: rcpt.blockNumber };
      // The stop is DONE here: the record is off the queue, and its runner ends the app on its next ledger pass. Said
      // now, before the teardown below, so a failure there can never read as the stop having failed (enclave-87: a
      // login refusal printed as the only line after setActive 0xded9430d had landed).
      if (!opt.json) say(`stopped on-chain: setActive(false) tx ${sent.tx} confirmed in block ${sent.block} - the deployment is off the queue`);
    }
  }
  // …then tear down the running instance (the runner also notices ActiveSet on
  // its next sweep; DELETE just makes it immediate). Once this run's on-chain stop
  // has landed, a teardown failure (a refused login, the API down) is a WARNING:
  // the stop stands and exits 0. With nothing sent, the teardown IS the command.
  let r = null, teardownError = null;
  try { r = await api("DELETE", `/v1/deployments/${id}`, { auth: account, ok404: true }); }
  catch (e) { if (!sent) throw e; teardownError = e.message; }
  if (opt.json) return jout({ ...(r || { id, status: "stopped", note: teardownError ? "ledger item deactivated; the immediate teardown failed (teardown)" : "ledger item deactivated; no live enclave record" }),
                              ...(sent ? { setActive: sent } : {}), ...(teardownError ? { teardown: { ok: false, error: teardownError } } : {}) });
  if (teardownError) {
    stderr.write(`warning: the immediate teardown failed: ${teardownError}\n`
      + `warning: the stop itself succeeded (tx ${sent.tx}); the runner ends the app on its next ledger pass\n`);
    return;
  }
  say(r ? `${r.status}${r.ranSeconds ? ` after ${dur(r.ranSeconds)}` : ""}${r.note ? ` (${r.note})` : ""}`
        : "deactivated on-chain; no enclave was serving it");
}

// Restart in place: the enclave stops the app instance and relaunches it on
// the same version, lease and balance - a pure API action (no wallet tx; SIWE
// auth only). The remedy for a wedged instance the crash detector can't see:
// the process answers, it just can't do its job (e.g. it booted before its
// model volume finished mounting and can never load the model).
async function cmdRestart(rest) {
  const account = loadKey();
  if (!rest[0]) throw new Error("usage: enclave restart <id>");
  const id = await resolveId(rest[0], account);
  const r = await api("POST", `/v1/deployments/${id}/restart`, { auth: account });
  if (opt.json) return jout(r);
  say(`${r.status}${r.note ? ` (${r.note})` : ""}`);
}

// Move a running deployment to another enclave. There is no on-chain "move":
// EnclaveDeployments.release is RUNNER-only (an owner cannot evict a host), so
// this is release-then-re-claim. The owner-authenticated DELETE asks the box
// holding the lease to hand it back — which refunds the unused lease tail to
// the deployment's balance and returns the record to the open queue, still
// active and funded — and the claim hint then gives the chosen box first crack.
//
// Placement is a STEER, not a lock: nothing on chain reserves a deployment for
// an enclave. What makes it land is timing — the hinted box evaluates at once
// while the rest of the fleet only looks on its next sweep (~60s). We poll the
// ledger and report where it ACTUALLY went, because losing the race is a
// normal outcome and silently implying success would be a lie.
async function cmdMove(rest) {
  const account = loadKey();
  if (!rest[0] || !rest[1]) throw new Error("usage: enclave move <id> <enclave>   (enclave = a name from `enclave availability`)");
  const id = await resolveId(rest[0], account);
  if (!isB32(id)) throw new Error("only on-chain deployments (bytes32 ids) hold a lease that can be moved");
  const target = String(rest[1]).trim().toLowerCase();
  const { abi } = await depAbi();
  const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "get", [id]);
  if (!d || d.owner === "0x0000000000000000000000000000000000000000") throw new Error(`no deployment ${short(id)} on the ledger`);
  if (d.owner.toLowerCase() !== account.address.toLowerCase()) throw new Error(`${short(id)} is owned by ${d.owner}, not this key`);
  const fleet = await api("GET", "/enclaves").catch(() => null);
  const rows = (fleet && fleet.enclaves) || [];
  const dest = rows.find((e) => String(e.name || "").toLowerCase() === target);
  if (!dest) throw new Error(`no live enclave named "${rest[1]}" (see \`enclave availability\`)`);
  if (String(dest.id || "").toLowerCase() === String(d.runner || "").toLowerCase())
    return say(`${short(id)} already runs on ${dest.name}`);
  const from = rows.find((e) => String(e.id || "").toLowerCase() === String(d.runner || "").toLowerCase());
  const leased = Number(d.leaseUntil) * 1000 > Date.now();
  if (!leased) say(`${short(id)} holds no live lease right now - this just hints ${dest.name} to claim it`);
  else if (!(await confirm(`move ${short(id)} off ${from ? from.name : "its current enclave"} to ${dest.name}? (the app stops and relaunches there; unused lease time is refunded, then re-bought at ${dest.name}'s price)`)))
    return say("aborted");
  const oldRunner = String(d.runner || "").toLowerCase();
  const ZERO = "0x" + "0".repeat(64);
  const leaseGone = async () => {
    const cur = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "get", [id]).catch(() => null);
    const r = String((cur && cur.runner) || "").toLowerCase();
    return !cur || !r || r === ZERO || !(Number(cur.leaseUntil) * 1000 > Date.now());
  };
  if (leased) {
    // evacuate=1: the source also stands down from re-claiming for a short
    // window. Without it the box that just released still has the app staged
    // and its own sweep re-takes the work within seconds - the move looks like
    // it worked and nothing moved (observed 2026-07-27).
    const rel = await api("DELETE", `/v1/deployments/${id}?evacuate=1`, { auth: account });
    say(`lease released - unused time refunded to the balance`
        + (rel && rel.standDownSec ? `; ${from ? from.name : "the source"} stands down for ${rel.standDownSec}s` : ""));
    // the release is a TRANSACTION: hinting before it is mined makes the
    // destination attempt a claim that reverts "leased", which then puts THAT
    // box into its own provisioning backoff and locks out the good retry
    let cleared = false;
    for (let i = 0; i < 30 && !cleared; i++) { await new Promise((r) => setTimeout(r, 2000)); cleared = await leaseGone(); }
    if (!cleared) throw new Error("the lease is still live on-chain 60s after the release - nothing moved and nothing was lost; try again shortly");
  }
  let landed = null, lastReason = "";
  for (let i = 0; i < 45 && !landed; i++) {
    if (i % 3 === 0) {
      const h = await api("POST", "/v1/claim-hint", { body: { id, enclave: dest.name } }).catch(() => null);
      if (h && h.accepted === false && h.reason && h.reason !== lastReason) {
        lastReason = h.reason;
        say(`${dest.name} declines: ${h.reason}`);
      }
    }
    await new Promise((r) => setTimeout(r, 2000));
    const cur = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "get", [id]).catch(() => null);
    const runner = String((cur && cur.runner) || "").toLowerCase();
    if (cur && runner && runner !== ZERO && Number(cur.leaseUntil) * 1000 > Date.now() && runner !== oldRunner)
      landed = cur;
  }
  const where = landed ? (rows.find((e) => String(e.id || "").toLowerCase() === String(landed.runner).toLowerCase()) || {}).name : null;
  if (opt.json) return jout({ id, target: dest.name, moved: !!landed, runner: landed ? landed.runner : null, enclave: where || null });
  if (!landed)
    say(`no enclave has claimed it yet - the record is funded and queued, so the fleet's sweep picks it up within a minute (watch: enclave status ${short(id)})`);
  else if (where && where.toLowerCase() === target)
    say(`running on ${where} now`);
  else
    say(`claimed by ${where || "another enclave"}, not ${dest.name} - placement is a steer, not a lock; run the move again to retry`);
}

// The owner's hourly spend ceiling (ledger rev 8). Prices differ per enclave —
// each one posts its own — so this is the line that decides which of them may
// run the deployment, including when its current host dies and the work goes
// back on the queue. Raising it opens up dearer hardware; lowering it below
// what the app currently costs lets the paid lease finish and then stops it,
// which is deliberate (a ceiling that can't stop spending isn't one) and
// confirmed in words before the signature.
async function cmdRateCap(rest) {
  // with a session: deploy.setMaxRate on a deployment the vault holds or (delegated) the owner's wallet holds;
  // on a PRODUCTION one (every wallet-held record) a session may only lower the cap
  const sess = await sessionForCommand();
  const account = sess ? null : loadKey();
  if (!rest[0]) throw new Error("usage: enclave rate-cap <id> [<usd/hour>]   (no amount = show the current cap)");
  if (sess && rest[1] !== undefined) await sessionRequire(sess, "deploy.setMaxRate");
  const id = await resolveId(rest[0], account ?? sessionAccount(sess));
  if (!isB32(id)) throw new Error("only on-chain deployments (bytes32 ids) carry a rate cap");
  const { rev, abi } = await depAbi();
  if (rev < 8) throw new Error("the live ledger predates rate caps (deploymentsSchema < 8)");
  const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "get", [id]);
  if (rest[1] !== undefined && (!d || d.owner === "0x0000000000000000000000000000000000000000")) throw new Error(`no deployment ${short(id)} on the ledger`);
  const cap6 = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "capOf", [id]);
  const leased = Number(d.leaseUntil) * 1000 > Date.now();
  if (rest[1] === undefined) {
    if (opt.json) return jout({ id, maxRate6: String(cap6), maxRatePerHour: Number(cap6) * 3600 / 1e6,
      ratePerSec6: String(d.rate), ratePerHour: Number(d.rate) * 3600 / 1e6, leased });
    say(`cap  ${cap6 > 0n ? usd6(cap6 * 3600n) + "/h" : "none (grandfathered record)"}`);
    say(`rate ${usd6(BigInt(d.rate) * 3600n)}/h${leased ? " (what its current enclave charges)" : " (no enclave is serving it; the ceiling stands in)"}`);
    return;
  }
  const next6 = perSec6FromHour(numFlag(rest[1], "<usd/hour>"));
  if (!(next6 > 0n)) throw new Error("the cap must be a positive $/hour amount");
  const fee6 = rev >= 4 ? (await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "feeOf", [id]))[1] : 0n;
  if (next6 <= fee6)
    throw new Error(`the cap must exceed this app's publisher fee (${usd6(fee6 * 3600n)}/h)`);
  if (sess) {
    const held = await sessionHolder(sess, d, id, "deploy.setMaxRate");
    // the vault's rule: a raised production cap would let a host a stolen key's holder runs claim at that price and earn the escrow
    if (next6 > cap6 && (held === "wallet" || (await sessionHeldEnv(sess, id)) === sess.S.ENVIRONMENTS.prod))
      throw new Error(`a session may only LOWER a production deployment's rate cap (${short(id)}: ${usd6(cap6 * 3600n)}/h now`
        + `${held === "wallet" ? ", held by the owner's wallet" : ""}); raising it is the owner's call: enclave rate-cap ${short(id)} ${rest[1]} --wallet`);
    if (next6 < 2n * fee6)
      throw new Error(`a session's cap must be at least twice this app's publisher fee (${usd6(2n * fee6 * 3600n)}/h)`);
  }
  if (leased && next6 < BigInt(d.rate)) {
    say(`! ${usd6(next6 * 3600n)}/h is BELOW what this deployment pays now (${usd6(BigInt(d.rate) * 3600n)}/h).`);
    say(`  The lease you already paid for runs to ${new Date(Number(d.leaseUntil) * 1000).toLocaleString()}, then the app STOPS:`);
    say(`  no renewal and no re-claim until a cheaper enclave exists or you raise the cap again.`);
  }
  if (!(await confirm(`set ${short(id)}'s rate cap to ${usd6(next6 * 3600n)}/h${sess ? ` through session ${short(sess.sid)}` : ""}?`))) return say("aborted");
  if (sess) await sessionCall(sess, "deploy.setMaxRate", { id, maxRate6: next6 });
  else await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi, functionName: "setMaxRate", args: [id, next6] });
  say(`cap set to ${usd6(next6 * 3600n)}/h`);
  if (!leased) say("takes effect on the next claim (an enclave dearer than the cap can't take it)");
}

// Cancel a deployment and take the unused runtime back to the owner's wallet
// (rev-10 ledgers). What comes back is what the ledger still HOLDS for the
// record — the runner escrow — not the sticker price: the publisher's cut and
// the platform's remainder were forwarded to their wallets at funding time and
// no contract can claw them back. So this prints the real number from
// refundableOf and the shortfall against the balance, rather than implying the
// balance is what lands. Refunding mid-lease is allowed and pays what the lease
// cannot still claim; the reserved tail comes back once the runner releases.
async function cmdRefund(rest) {
  // with a session: deploy.refund on a deployment the vault holds (paid to the vault: the owner's free balance
  // there, never the session's budget) or (delegated) the owner's wallet holds (paid to that wallet)
  const sess = await sessionForCommand();
  const account = sess ? null : loadKey();
  if (!rest[0]) throw new Error("usage: enclave refund <id>");
  if (sess) await sessionRequire(sess, "deploy.refund");
  const id = await resolveId(rest[0], account ?? sessionAccount(sess));
  if (!isB32(id)) throw new Error("only on-chain deployments (bytes32 ids) can be refunded");
  const { rev, abi } = await depAbi();
  if (rev < 10) throw new Error("the live ledger predates refunds (deploymentsSchema < 10)");
  const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "get", [id]);
  if (!d || d.owner === "0x0000000000000000000000000000000000000000") throw new Error(`no deployment ${short(id)} on the ledger`);
  let to = account?.address;
  if (sess) to = (await sessionHolder(sess, d, id, "deploy.refund")) === "wallet" ? await sessionOwner(sess) : sess.vault;
  else if (d.owner.toLowerCase() !== account.address.toLowerCase()) throw new Error(`${short(id)} is owned by ${d.owner}, not this key`);
  const amount6 = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "refundableOf", [id]);
  const leased = Number(d.leaseUntil) * 1000 > Date.now();
  const fundable = d.rate > 0n ? Number(d.balance6 / d.rate) : 0;
  if (!(amount6 > 0n)) {
    if (leased) throw new Error(`nothing refundable yet: every dollar this record still holds is reserved for the lease running to ${new Date(Number(d.leaseUntil) * 1000).toLocaleString()}. Retry once it ends.`);
    throw new Error(`nothing to refund on ${short(id)} (it has already spent or refunded everything it held)`);
  }
  const toWhom = !sess ? to : to === sess.vault ? `${to} (the session's vault: the owner's free balance there, not this session's budget)`
                                                : `${to} (the owner's wallet)`;
  say(`refundable  ${usd6(amount6)}  ->  ${toWhom}`);
  say(`balance     ${usd6(d.balance6)} (${dur(fundable)} of runtime at ${usd6(d.rate * 3600n)}/h)`);
  if (d.balance6 > amount6) {
    say(`! ${usd6(d.balance6 - amount6)} of that balance is NOT refundable: the publisher fee and the platform's`);
    say(`  share left for their wallets when you funded. Only the host's escrow is still held here.`);
  }
  if (leased)
    say(`! a lease runs to ${new Date(Number(d.leaseUntil) * 1000).toLocaleString()}; its unearned seconds stay reserved for the host and become refundable after it releases (run this again then).`);
  if (!(await confirm(`refund ${usd6(amount6)} and CANCEL ${short(id)}? (the app stops and the record is deactivated)`))) return say("aborted");
  if (sess) {
    // the immediate teardown (DELETE) is an owner-login API call a session can't make yet; the runner's ledger pass ends it
    const rcpt = await sessionTx(sess, "deploy.refund", { id });
    if (opt.json) return jout({ id, refunded6: String(amount6), refunded: Number(amount6) / 1e6, to, tx: rcpt.transactionHash,
                                note: "the runner ends the app on its next ledger pass" });
    say(`refunded ${usd6(amount6)} to ${toWhom}; ${short(id)} is cancelled (tx ${rcpt.transactionHash}); its runner ends the app on its next ledger pass`);
    return say(`\`enclave resume ${short(id)}\` re-activates it if you change your mind; it runs again once it holds a balance (\`enclave fund ${short(id)} --usdc 5\`)`);
  }
  await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi, functionName: "refund", args: [id] });
  // the ledger deactivates the record; tear the live instance down immediately
  // rather than waiting for the runner's next ActiveSet sweep
  const r = await api("DELETE", `/v1/deployments/${id}`, { auth: account, ok404: true }).catch(() => null);
  if (opt.json) return jout({ id, refunded6: String(amount6), refunded: Number(amount6) / 1e6, to: account.address, teardown: r || null });
  say(`refunded ${usd6(amount6)} to ${account.address}; ${short(id)} is cancelled`);
  // a refund CANCELS the record, and the ledger funds only an ACTIVE one (_requireActive): `fund` alone reverts
  // "inactive" here. `resume` (setActive(true)) re-activates it; a balance is then a separate fund.
  say(`\`enclave resume ${short(id)}\` re-activates it if you change your mind; it runs again once it holds a balance (\`enclave fund ${short(id)} --usdc 5\`)`);
}

// Hand a deployment to another wallet (rev-11 ledgers). A transfer moves
// CONTROL and never money: the ledger refuses it ("refund first") while it
// still holds any of this wallet's refundable backing, so this command chains
// the refund - your money comes back to YOUR wallet, then the (empty) record
// changes hands. One-shot on-chain - no accept step, and no way back except
// the new owner transferring it again - so the FULL destination address is
// shown before anything is signed. Staged secrets and custom domains stay
// with the record (they are the record's, not the wallet's).
async function cmdTransfer(rest) {
  const account = loadKey();
  if (!rest[0] || !rest[1]) throw new Error("usage: enclave transfer <id> <0xaddress>");
  const id = await resolveId(rest[0], account);
  if (!isB32(id)) throw new Error("only on-chain deployments (bytes32 ids) can be transferred");
  let to; try { to = getAddress(rest[1]); } catch { throw new Error(`"${rest[1]}" is not an Ethereum address`); }
  const { rev, abi } = await depAbi();
  if (rev < 11) throw new Error("the live ledger predates deployment transfers (deploymentsSchema < 11)");
  const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "get", [id]);
  if (!d || d.owner === "0x0000000000000000000000000000000000000000") throw new Error(`no deployment ${short(id)} on the ledger`);
  if (d.owner.toLowerCase() !== account.address.toLowerCase()) throw new Error(`${short(id)} is owned by ${d.owner}, not this key`);
  if (to.toLowerCase() === account.address.toLowerCase()) throw new Error(`${to} already owns ${short(id)}`);
  // the ledger's gate: any of the owner's own backing still held = no transfer
  const [ownerEsc6, earn] = await Promise.all([
    read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "ownerEscrow6", [id]),
    read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "earnOf", [id]),
  ]);
  const blocked = ownerEsc6 > 0n && earn[1] > 0n;
  const leased = Number(d.leaseUntil) * 1000 > Date.now();
  say(`deployment  ${short(id)}`);
  say(`owner       ${account.address}  ->  ${to}`);
  say(`! staged secrets and custom domains stay with the deployment; rotate any`);
  say(`  credentials in them that the new owner must not hold.`);
  if (!blocked) {
    if (!(await confirm(`transfer ${short(id)} to ${to}? (one-shot: only the new owner could ever transfer it back)`))) return say("aborted");
    await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi, functionName: "transferDeployment", args: [id, to] });
    if (opt.json) return jout({ id, from: account.address, to });
    return say(`${short(id)} now belongs to ${to}`);
  }
  const refundable6 = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "refundableOf", [id]);
  if (!(refundable6 > 0n))
    // the mid-lease window: the free part is home but the tail is reserved
    // for the host and would free to the NEW owner - the ledger refuses that
    throw new Error(`your remaining escrow is reserved for the running lease (to ${new Date(Number(d.leaseUntil) * 1000).toLocaleString()}). `
      + `\`enclave stop ${short(id)}\` (the host releases within ~a minute), \`enclave refund\` to collect it, then transfer.`);
  say(`! the ledger holds ${usd6(refundable6)} of your money and refuses to transfer it`);
  say(`  with the record - it comes back to THIS wallet first, then the record`);
  say(`  (with zero balance${leased ? ", once the lease winds down" : ""}) hands over. Two transactions.`);
  if (leased)
    say(`! a lease runs to ${new Date(Number(d.leaseUntil) * 1000).toLocaleString()}; if part of your escrow stays reserved for it,`);
  if (leased)
    say(`  the transfer step will be refused until the host releases - run this again then.`);
  if (!(await confirm(`refund ${usd6(refundable6)} to ${account.address}, then transfer ${short(id)} to ${to}?`))) return say("aborted");
  await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi, functionName: "refund", args: [id] });
  say(`refunded ${usd6(refundable6)} to ${account.address}`);
  const [esc2, earn2] = await Promise.all([
    read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "ownerEscrow6", [id]),
    read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "earnOf", [id]),
  ]);
  if (esc2 > 0n && earn2[1] > 0n)
    throw new Error(`${usd6(esc2 < earn2[1] ? esc2 : earn2[1])} stays reserved for the running lease; `
      + `once the host releases, \`enclave refund ${short(id)}\` collects it and the transfer will go through.`);
  await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi, functionName: "transferDeployment", args: [id, to] });
  if (opt.json) return jout({ id, from: account.address, to, refunded6: String(refundable6) });
  say(`${short(id)} now belongs to ${to} (your ${usd6(refundable6)} stayed with you)`);
}

// The other half of stop: setActive(true) re-queues the work item (its balance
// never left the record), then one claim-hint nudges the fleet so the relaunch
// doesn't wait for the next sweep. The app relaunches FRESH from its published
// version - suspend/resume preserves money, not memory.
async function cmdResume(rest) {
  // with a session: deploy.setActive(true) on a deployment the vault holds, or (delegated) the owner's wallet holds
  const sess = await sessionForCommand();
  const account = sess ? null : loadKey();
  if (!rest[0]) throw new Error("usage: enclave resume <id>");
  if (sess) await sessionRequire(sess, "deploy.setActive");
  const id = await resolveId(rest[0], account ?? sessionAccount(sess));
  if (!isB32(id)) throw new Error("only on-chain deployments (bytes32 ids) can be resumed");
  const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "get", [id]);
  if (!d || d.owner === "0x0000000000000000000000000000000000000000") throw new Error(`no deployment ${short(id)} on the ledger`);
  if (sess) await sessionHolder(sess, d, id, "deploy.setActive");
  else if (d.owner.toLowerCase() !== account.address.toLowerCase()) throw new Error(`${short(id)} is owned by ${d.owner}, not this key`);
  const fundable = d.rate > 0n ? Number(d.balance6 / d.rate) : 0;
  if (!(await confirm(`resume ${short(id)}? (re-queues it; the remaining ${usd6(d.balance6)} buys ${dur(fundable)} at ${usd6(d.rate * 3600n)}/h once it runs)`))) return say("aborted");
  if (d.active) say("already active on the ledger; nudging the fleet");
  else if (sess) await sessionCall(sess, "deploy.setActive", { id, active: true });
  else await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi: (await depAbi()).abi,
    functionName: "setActive", args: [id, true] });
  // force: resume is the one hint that may override the ex-runner's
  // provision-failure cooldown (the owner explicitly asked for a retry NOW)
  const h = await api("POST", "/v1/claim-hint", { body: { id, force: true } }).catch(() => null);
  if (opt.json) return jout({ id, active: true, fundableSec: fundable, hint: h });
  if (fundable < 1)
    say(`re-queued, but UNFUNDED: ${usd6(d.balance6)} buys under a second at ${usd6(d.rate * 3600n)}/h - \`enclave fund ${short(id)} --usdc 5\` un-sticks it`);
  else if (h && h.accepted === false && h.reason)
    say(`re-queued; claim-hint declined: ${h.reason} (the sweep may still claim it)`);
  else
    say(`re-queued with ${dur(fundable)} of runtime - an enclave claims it shortly (watch: enclave status ${short(id)})`);
}

// Switch a deployment to an explicit version of ITS app (setAppRef) —
// the upgrade path: paid time and any live lease stay on the record, so a new
// release never costs a second buy-in; the current runner restarts the app in
// place on the new version. On a rev-6 ledger --gpu/--cpu additionally RE-BUY
// the deployment's shares in place (setShares, batched with the version
// change into ONE multicall transaction): the rate is recalculated at the
// current list prices — a resize is a new purchase decision, exactly like
// create — and a live lease's unserved tail settles at the old rate before
// re-burning at the new one, so nothing is ever re-priced retroactively.
// `enclave resize` is the version-less spelling of the same flow. The same
// pre-flight resource and fee gates run BEFORE the wallet signature, including
// the new version's minimum shares against the shares the
// record will carry (a record no runner accepts would leave the app dark on
// a still-billing lease).
async function cmdUpgrade(rest, { resize = false } = {}) {
  const f = flags(rest, { val: ["--gpu", "--cpu"] });
  rest = f._;
  // with a session: deploy.setAppRef (upgrade: staging deployments the vault holds) or deploy.setShares (resize:
  // those, and the production ones the vault or, delegated, the owner's wallet holds)
  const sess = await sessionForCommand();
  const account = sess ? null : loadKey();
  if (!rest[0]) throw new Error(resize
    ? "usage: enclave resize <id> [--gpu 0..1] [--cpu 0..1]  (fractions of one card/node; the rate is recalculated at current prices)"
    : "usage: enclave upgrade <id> [<version>] [--gpu 0..1] [--cpu 0..1]  (default: the app's latest approved version)");
  const id = await resolveId(rest[0], account ?? sessionAccount(sess));
  if (!isB32(id)) throw new Error("only on-chain deployments (bytes32 ids) can change versions or shares");
  const { rev, abi } = await depAbi();
  if (rev < 3) throw new Error("the live EnclaveDeployments contract predates version changes (deploymentsSchema < 3); until the ledger upgrade, deploy the new version fresh and stop the old one");
  const wantShares = f.gpu !== undefined || f.cpu !== undefined;
  if (resize && !wantShares) throw new Error("nothing to change: pass --gpu and/or --cpu (fractions of one card/node, e.g. --gpu 0.5)");
  // one session operation per change: the vault has no multicall for a session
  if (sess && !resize && wantShares)
    throw new Error(`a session changes the version and the shares in two operations: enclave upgrade ${rest[0]}${rest[1] !== undefined ? " " + rest[1] : ""}, then enclave resize ${rest[0]} --gpu … --cpu …`);
  if (wantShares && rev < 6)
    throw new Error("the live EnclaveDeployments contract predates share resizes (deploymentsSchema < 6); until the ledger upgrade, deploy at the new dials fresh and stop this one");
  const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "get", [id]);
  if (!d || d.owner === "0x0000000000000000000000000000000000000000") throw new Error(`no deployment ${short(id)} on the ledger`);
  if (sess) {
    // who holds it first: a version change on a record the WALLET holds is refused whatever the grant says
    await sessionHolder(sess, d, id, resize ? "deploy.setShares" : "deploy.setAppRef");
    await sessionRequire(sess, resize ? "deploy.setShares" : "deploy.setAppRef");
  } else if (d.owner.toLowerCase() !== account.address.toLowerCase()) throw new Error(`${short(id)} is owned by ${d.owner}, not this key`);
  const m = /^catalog:\/\/(0x[0-9a-fA-F]{64})\/(\d{1,9})$/.exec(d.appRef || "");
  if (!m) throw new Error(`${short(id)} references "${d.appRef}" - only catalog-versioned deployments can switch versions or shares`);
  const appId = m[1], curIdx = Number(m[2]);
  const app = (await catalogApps()).find((a) => a.appId.toLowerCase() === appId.toLowerCase());
  if (!app) throw new Error(`the catalog has no app ${appId} (delisted?)`);
  const versions = await readVersions(app.appId, app.versionCount);
  let vi;
  if (rest[1] !== undefined) {
    vi = versions.findIndex((v) => v.version === rest[1]);
    if (vi < 0) throw new Error(`app "${app.slug}" has no version labeled "${rest[1]}"`);
  } else if (resize) {
    vi = curIdx;   // a pure resize stays on the version the record already runs
    if (!versions[vi]) throw new Error(`${short(id)} references version index ${vi}, which the catalog doesn't list`);
  } else {
    vi = versions.findLastIndex((v) => !v.yanked && Number(v.approval) === 1);
    if (vi < 0) throw new Error(`app "${app.slug}" has no approved version`);
  }
  const ver = versions[vi];
  if (vi === curIdx && !wantShares) return say(`${short(id)} already runs ${app.slug}:${ver.version} (version index ${vi}); nothing to do`);
  const notice = catalogAdmissionNotice(app, ver);
  if (notice) say(`! ${notice}`);
  // the record's shares (bought at create, or re-bought here) must cover the
  // version's minimums ON THE BOX THAT WILL APPLY THE CHANGE — its lease holder
  // while it has one, the fleet's otherwise; a record that box won't accept
  // would leave the app dark on a still-billing lease
  let pricing = null;
  try { pricing = await api("GET", "/v1/pricing"); } catch {}
  let host = null, hostAsk = null, hostFree = false;
  ({ pricing, host, hostAsk, hostFree } = await hostPricing(d, pricing));
  const where = host ? `on ${host}` : "on the fleet's hardware";
  const mins = minShares(ver, pricing);
  let gpuMilli = f.gpu !== undefined ? Math.round(numFlag(f.gpu, "--gpu") * 1000) : Number(d.gpuMilli);
  let cpuMilli = f.cpu !== undefined ? Math.round(numFlag(f.cpu, "--cpu") * 1000) : Number(d.cpuMilli);
  if (gpuMilli > 1000 || cpuMilli > 1000) throw new Error("--gpu/--cpu are fractions of one card/node (0..1)");
  if (cpuMilli < 1) cpuMilli = 10;
  // pre-13 setShares reverts on a GPU share under the CPU one, so round the
  // card up there; rev 13+ buys exactly the two shares that were asked for
  if (rev < 13 && gpuMilli > 0 && gpuMilli < cpuMilli) gpuMilli = cpuMilli;
  const needCpu = cpuFloorOf(mins, gpuMilli);
  if (gpuMilli < mins.gpuMilli || cpuMilli < needCpu) {
    const dial = `--gpu ${mins.gpuMilli / 1000} --cpu ${needCpu / 1000}`;
    if (wantShares)
      throw new Error(`those dials are below ${app.slug}:${ver.version}'s minimums ${where} - it needs at least ${dial}`
        + (needCpu > mins.cpuMilli ? ` (without a card its weights live in node RAM: ${mins.cpuMilli / 10}% CPU would do beside one)` : ""));
    throw new Error(`${app.slug}:${ver.version} needs at least gpu ${mins.gpuMilli / 10}% / cpu ${needCpu / 10}% ${where}, `
                  + `but ${short(id)} bought gpu ${Number(d.gpuMilli) / 10}% / cpu ${Number(d.cpuMilli) / 10}% - `
                  + (rev >= 6
                     ? `resize it in place (the rate is recalculated at current prices): enclave upgrade ${rest[0]}${rest[1] !== undefined ? " " + rest[1] : ""} ${dial}`
                     : `this ledger's shares are immutable - deploy it fresh instead: enclave deploy ${app.slug}:${ver.version} --fund 5`));
  }
  const resized = wantShares && (gpuMilli !== Number(d.gpuMilli) || cpuMilli !== Number(d.cpuMilli));
  // the publisher-fee snapshot IS still immutable: a version asking MORE than
  // the deployment snapshotted at create could never pay its publisher, so
  // every runner refuses the switch - fail here with words
  const newFee = await versionFee6(app.appId, vi);
  if (newFee > 0n) {
    const [snapTo, snapFee] = rev >= 4
      ? await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "feeOf", [id])
      : ["0x0000000000000000000000000000000000000000", 0n];
    if (snapFee < newFee || snapTo.toLowerCase() !== app.publisher.toLowerCase())
      throw new Error(`${app.slug}:${ver.version} charges a ${usd6(newFee * 3600n)}/h publisher fee, above the ${usd6(snapFee * 3600n)}/h `
                    + `this deployment snapshotted at create - the fee snapshot is immutable; `
                    + `deploy it fresh instead: enclave deploy ${app.slug}:${ver.version} --fund 5`);
  }
  const from = versions[curIdx] ? `${app.slug}:${versions[curIdx].version}` : d.appRef;
  const leased = Number(d.leaseUntil) * 1000 > Date.now();
  let newRate = d.rate, shareNote = "";
  if (resized) {
    // price the new dials exactly as the ledger will — at the SERVING
    // enclave's posted price (rev 8) or the platform list price (older), plus
    // the record's immutable fee snapshot — and enforce the platform's cap
    const [prices, maxGpu] = await Promise.all([
      livePrices6(hostAsk),
      read(DEFAULTS.DEPLOYMENTS_ADDRESS,
           [{ type: "function", name: "maxGpuMilli", stateMutability: "view", inputs: [], outputs: [{ type: "uint16" }] }],
           "maxGpuMilli").then(Number).catch(() => 1000),
    ]);
    if (gpuMilli > maxGpu)
      throw new Error(`--gpu ${gpuMilli / 10}% is over the platform's per-deployment GPU cap of ${maxGpu / 10}% of a card - lower --gpu`);
    const snapFee6 = rev >= 4 ? (await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "feeOf", [id]))[1] : 0n;
    // free self-hosting (rev 12): the serving box charges its own payout wallet
    // nothing, so the re-buy costs the publisher fee and nothing else - see
    // hostPricing. The fee is never waived; it is the publisher's money.
    const freeHere = rev >= 12 && hostFree;
    newRate = (freeHere ? 0n : rate6Of(prices, gpuMilli, cpuMilli)) + snapFee6;
    if (rev >= 8) {
      // a resize BUYS time, so the ceiling applies: the contract reverts
      // "over rate cap" above it
      const cap6 = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "capOf", [id]).catch(() => 0n);
      if (cap6 > 0n && newRate > cap6)
        throw new Error(`those dials cost ${usd6(newRate * 3600n)}/h at ${prices.who}, above this deployment's rate cap of `
                      + `${usd6(cap6 * 3600n)}/h - raise it first: enclave rate-cap ${id.slice(0, 10)} ${(Number(newRate) * 3600 / 1e6).toFixed(2)}`);
    }
    // Fail closed while the tx is still unsent: a runner that predates the
    // audit's share watch would keep serving the OLD slice while the ledger
    // bills the NEW rate — refuse unless every live runner re-slices. Only an
    // unreachable aggregate falls through, with a loud warning (the --config
    // rule).
    try {
      const av = await api("GET", "/availability");
      if (av && av.aggregate && av.shareResize !== true)
        throw new Error("the live fleet doesn't apply share resizes to running deployments yet (availability.shareResize is not true) - the billing would change while the served slice didn't. Retry after the fleet updates.");
    } catch (e) {
      if (/doesn't apply share resizes/.test(e.message)) throw e;
      say("! couldn't read fleet availability to confirm resize support; if a runner predates it, the new rate applies but the slice only changes at the next re-claim");
    }
    // a resize mid-lease settles the lease tail at the old rate and re-burns
    // it at the new one; the contract refuses ("unfunded at the new rate") if
    // that can't buy even one second - fail with words before the signature
    if (leased) {
      const tail = BigInt(Math.max(0, Number(d.leaseUntil) - Math.floor(Date.now() / 1000)));
      if (d.balance6 + tail * d.rate < newRate)
        throw new Error(`the remaining balance can't fund even one second at the new rate (${usd6(newRate * 3600n)}/h) - top it up first, then resize`);
    }
    shareNote = ` at gpu ${Number(d.gpuMilli) / 10}%->${gpuMilli / 10}% / cpu ${Number(d.cpuMilli) / 10}%->${cpuMilli / 10}% `
              + `(rate ${usd6(d.rate * 3600n)}/h -> ${usd6(newRate * 3600n)}/h`
              + (newRate > 0n ? `, balance buys ≈ ${dur(Number(d.balance6) / Number(newRate))})`
                              : `, and ${host || "your own enclave"} hosts this owner for free - no balance needed)`);
  }
  const doing = vi !== curIdx
    ? `switch ${short(id)} from ${from} to ${app.slug}:${ver.version}${shareNote}`
    : `resize ${short(id)} (${app.slug}:${ver.version})${shareNote}`;
  if (!(await confirm(`${doing}? (paid time carries over`
                    + `${leased ? "; the runner restarts the app in place within ~a minute" : ""})`))) return say("aborted");
  const appRef = `catalog://${app.appId}/${vi}`;
  if (sess) {
    if (resize && !resized) return say(`${short(id)} already has those shares; nothing to do`);
    if (!resize) sessionRequireApp(sess, app.appId, "deploy.setAppRef", app.slug);
    if (resized) await sessionCall(sess, "deploy.setShares", { id, gpuMilli, cpuMilli });
    else await sessionCall(sess, "deploy.setAppRef", { id, appRef });
  } else if (vi !== curIdx && resized) {
    // one signature: the contract's self-delegatecall batcher applies both
    await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi, functionName: "multicall",
      args: [[encodeFunctionData({ abi, functionName: "setAppRef", args: [id, appRef] }),
              encodeFunctionData({ abi, functionName: "setShares", args: [id, gpuMilli, cpuMilli] })]] });
  } else if (resized) {
    await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi,
      functionName: "setShares", args: [id, gpuMilli, cpuMilli] });
  } else {
    await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi,
      functionName: "setAppRef", args: [id, appRef] });
  }
  // nudge the fleet: relaunches queued/suspended work promptly (a running
  // instance is restarted by its own runner's next ledger pass)
  const h = await api("POST", "/v1/claim-hint", { body: { id } }).catch(() => null);
  if (opt.json) return jout({ id, appRef, version: ver.version,
    ...(resized ? { gpuMilli, cpuMilli, ratePerSec6: newRate.toString() } : {}), hint: h });
  say(`${vi !== curIdx ? `switched to ${app.slug}:${ver.version}` : "resized"}${resized ? ` at gpu ${gpuMilli / 10}% / cpu ${cpuMilli / 10}% (${usd6(newRate * 3600n)}/h)` : ""}${leased
    ? " - the runner restarts the app in place within a minute (paid time and the endpoint carry over)"
    : " - it launches when claimed"}; watch: enclave status ${short(id)}`);
}

// The hosts an --isolation deployment can land on: what THEY advertise decides how its config gets in (not the fleet's
// aggregate, which leaves isolation hosts out). -> true when any of them advertises `key` true.
const isoTakesConfig = (hosts, key) => hosts.some((h) => h && h.availability && h.availability[key] === true);
const isoHostNames = (hosts) => hosts.map((h) => h.name || h.id).join(", ");

async function cmdDeploy(rest) {
  // with a session: deploy.create through the vault, which holds the record (--env staging|prod)
  CHAIN_ONLY = rest.includes("--chain-only");
  if (CHAIN_ONLY && sessionConfigured() && !walletChosen())
    throw new Error("--chain-only uses direct wallet transactions; pass --wallet explicitly when a session is active");
  const sess = CHAIN_ONLY ? null : await sessionForCommand();
  const account = sess ? null : loadKey();
  const f = flags(rest, {
    val: ["--gpu", "--cpu", "--fund", "--fund-eth", "--port", "--ports", "--config-cid", "--waf", "--config",
          "--secrets", "--secrets-file", "--max-rate", "--isolation", ...(sess ? ["--env"] : [])],
    bool: ["--private", "--public", "--no-wait", "--gpu-optional", "--chain-only"],
  });
  if (!f._[0]) throw new Error("usage: enclave deploy <app> [--gpu 0..1] [--cpu 0..1] --fund <usd> [flags]");
  if (CHAIN_ONLY) {
    if (!CONTRACT_PINS) throw new Error("--chain-only requires --contract-pins (or ENCLAVE_CONTRACT_PINS_FILE)");
    if (f.cpu === undefined || f.gpu === undefined || f["max-rate"] === undefined)
      throw new Error("--chain-only requires explicit --cpu, --gpu and --max-rate; no API supplies hardware or price estimates");
    if (!(numFlag(f.cpu, "--cpu") > 0)) throw new Error("--chain-only requires --cpu greater than zero");
    if (f.secrets !== undefined || f["secrets-file"] !== undefined)
      throw new Error("--chain-only cannot stage relay-held secrets; configure owner-authorized custody separately before funding a secret-dependent deployment");
    f["no-wait"] = true;
    say("chain-only: hosts decide admission; this submits your resource request and spend ceiling without API discovery or a readiness claim");
  }
  if (sess) await sessionDeployPreflight(sess, f);
  const { ref, ver, app, notice } = await resolveAppRef(sess ? sessionAppInput(sess, f._[0]) : f._[0]);
  if (sess) sessionRequireApp(sess, app.appId, "deploy.create", app.slug);
  if (notice) say(`! ${notice}`);

  // WASIp3 apps (the version config's `wasi: "0.3"`, stamped from the binary
  // at publish): only p3-capable runners claim them. Fleet-AND true = every
  // box serves it, deploy normally. Otherwise: at least one capable box =
  // canary, warn and proceed (the ledger is an open queue; incapable boxes
  // refuse the claim and `enclave move <id> <box>` hints placement). No
  // capable box anywhere = the deployment would sit Queued forever with its
  // funding unrecoverable - fail with words before any wallet step.
  let verWasi3 = false;
  try { verWasi3 = JSON.parse(ver?.config || "{}").wasi === "0.3"; } catch {}
  if (verWasi3 && !CHAIN_ONLY) {
    let av = null; try { av = await api("GET", "/availability"); } catch {}
    if (!(av && av.aggregate && av.p3 === true)) {
      const rows = await api("GET", "/enclaves").then((j) => j?.enclaves || []).catch(() => []);
      const capable = rows.filter((e) => e?.availability?.p3 === true).map((e) => e.name).filter(Boolean);
      if (!capable.length)
        throw new Error(`${app.slug}:${ver.version} is a WASIp3 app and no live enclave serves p3 yet - it would sit Queued forever. Retry after the fleet updates.`);
      say(`! WASIp3 canary: not every runner serves p3 yet - only ${capable.join(", ")} will claim this; \`enclave move <id> ${capable[0]}\` hints placement if it stays Queued`);
    }
  }

  // shares: fractions of one GPU card / one node (1 = the whole thing). When
  // omitted, use the app's minimum on the fleet's hardware (same formula the
  // runners enforce) so `enclave deploy hello-world:1 --fund 2` just works.
  let pricing = null;
  try { pricing = await api("GET", "/v1/pricing"); } catch {}
  const mins = ver ? minShares(ver, pricing) : { gpuMilli: 0, cpuMilli: 50, cpuMilliNoGpu: 50 };
  let gpuMilli = f.gpu !== undefined ? Math.round(numFlag(f.gpu, "--gpu") * 1000) : mins.gpuMilli;
  // the node default follows the card dial: buy no card and this is a coreless
  // placement, which on a cpuFallback version is the larger floor
  let cpuMilli = f.cpu !== undefined ? Math.round(numFlag(f.cpu, "--cpu") * 1000)
                                     : Math.max(cpuFloorOf(mins, gpuMilli), 10);
  if (gpuMilli > 1000 || cpuMilli > 1000) throw new Error("--gpu/--cpu are fractions of one card/node (0..1)");
  if (cpuMilli < 1) cpuMilli = 10;
  // ditto on create: the lift survives only as pre-13 ledger compatibility, so
  // `--gpu 0.05 --cpu 0.5` buys a sliver of card beside half a node on rev 13+
  if ((await depAbi()).rev < 13 && gpuMilli > 0 && gpuMilli < cpuMilli) gpuMilli = cpuMilli;
  if (f.gpu === undefined && f.cpu === undefined && ver)
    trace(`shares from app specs: gpu ${gpuMilli / 10}% cpu ${cpuMilli / 10}% (override with --gpu/--cpu)`);

  const portsCsv = f.ports !== undefined ? f.ports : (ver?.ports || "");
  const httpEntry = portsCsv.split(",").map((s) => s.trim()).find((s) => /^http:/i.test(s));
  const appPort = f.port !== undefined ? parseInt(f.port, 10)
    : httpEntry ? parseInt(httpEntry.split(":")[1], 10) : 8080;
  const isPublic = f.private ? false : true;
  // configCid as a CID is RETIRED: the appRef names the catalog version RECORD
  // and the enclave applies that version's config (approved with it) straight
  // from the chain. The create() field carries only the deployment-options
  // ENVELOPE — {"waf":{…}} (per-IP rate limit + request filter) and
  // {"config":{…}} (an inline app-config override for THIS deployment);
  // anything else is refused at claim.
  if (f["config-cid"])
    throw new Error("--config-cid is retired: a CID names bytes nobody validated. The version's approved config applies automatically; to run THIS deployment on a different config pass it inline: --config '{\"key\":\"value\"}'. (For the per-IP rate limit / request filter, use --waf.)");
  // --waf '{"rps":10,"burst":40,"maxConcurrent":10,"maxBodyMb":40,…}' — the
  // waf OBJECT; --config '{…}' — the app-config override OBJECT (the envelope
  // wrapper is added here). Shape-checked locally; the runner's claim gate is
  // the real validator and refuses unknown keys.
  const envParts = {};
  if (f.waf !== undefined) {
    let w; try { w = JSON.parse(f.waf); } catch (e) { throw new Error("--waf must be a JSON object, e.g. --waf '{\"rps\":10}': " + e.message); }
    if (!w || Array.isArray(w) || typeof w !== "object" || !Object.keys(w).length)
      throw new Error("--waf must be a non-empty JSON object, e.g. --waf '{\"rps\":10,\"blockScanners\":true}'");
    envParts.waf = w;
    say(`protection: ${JSON.stringify({ waf: w })} (per requester IP, enforced by the enclave's proxy; needs a fleet that supports the options envelope)`);
  }
  // --isolation <backend>: the deployment REQUIRES a per-app isolation tier (`{"isolation":{"require":…}}`, the same
  // envelope namespace an owner's setConfig adds later). Set AT CREATION, so there is no window in which a runner
  // without that tier can claim it: every other runner refuses the namespace. Refused unless some live host
  // advertises that backend, because nothing else would ever claim it.
  let isoBackend = null, isoHosts = [];
  if (f.isolation !== undefined) {
    isoBackend = String(f.isolation).trim();
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(isoBackend)) throw new Error("--isolation takes a backend name, e.g. --isolation snp-guest-per-app");
    let hosts = [];
    if (!CHAIN_ONLY) try { hosts = ((await api("GET", "/enclaves")).enclaves || []).filter((e) => e && e.availability && e.availability.isolation === isoBackend); }
    catch (e) { throw new Error(`couldn't read the fleet to confirm a ${isoBackend} host: ${e.message}`); }
    if (!CHAIN_ONLY && !hosts.length) throw new Error(`no live host advertises the ${isoBackend} tier; a deployment requiring it would never be claimed`);
    isoHosts = hosts;
    envParts.isolation = { require: isoBackend };
    say(`isolation: REQUIRES ${isoBackend} (${CHAIN_ONLY ? "host availability not queried" : "hosts: " + hosts.map((h) => h.name || h.id).join(", ")}); every other runner refuses it`);
  }
  if (f.config !== undefined) {
    let c; try { c = JSON.parse(f.config); } catch (e) { throw new Error("--config must be a JSON object, e.g. --config '{\"api_key\":\"…\"}': " + e.message); }
    if (!c || Array.isArray(c) || typeof c !== "object")
      throw new Error("--config must be a JSON object — it replaces the version's config as this deployment's ENCLAVE_CONFIG (--config '{}' = explicitly empty)");
    envParts.config = c;
    // Fail closed while the tx is still unsent: a runner that predates the
    // `config` namespace refuses the claim, so the deployment would sit
    // Queued until the owner notices and rewrites the envelope (`enclave
    // config clear`) — refuse here instead. Only an unreachable aggregate
    // falls through (same information the --waf path has always had), with a
    // loud warning.
    // An isolation tier is not in the fleet-wide AND (its host advertises configOverride:false on purpose: it takes
    // config only through the attested release), so the gate that matters there is the release, stated instead.
    if (CHAIN_ONLY) say("config: the owner-authored override is on chain; a host must support and enforce it to claim");
    else if (isoBackend) say(isoTakesConfig(isoHosts, "configOverride")
      ? `config: the ${isoBackend} host(s) take a per-deployment config themselves (availability.configOverride: ${isoHostNames(isoHosts)})`
      : `config: delivered only INTO the ${isoBackend} guest, through the attested release; the deployment stays Queued until the relay lists it for the release and its host has opted in`);
    else try {
      const av = await api("GET", "/availability");
      if (av && av.aggregate && av.configOverride !== true)
        throw new Error("the live fleet doesn't support per-deployment config overrides yet (availability.configOverride is not true) — a deployment carrying one would never be claimed. Drop --config or retry after the fleet updates.");
    } catch (e) {
      if (/doesn't support per-deployment config/.test(e.message)) throw e;
      say("! couldn't read fleet availability to confirm config-override support; if a runner predates it, this deployment will sit Queued unclaimed");
    }
    say("config override: this deployment runs on YOUR config (the version's config stays the default for every other deployment)");
  } else if (ver && ver.config) say("the version's approved config applies (from its on-chain record; override with --config '{…}')");
  // --gpu-optional: this deployment PREFERS a card but will run on cores
  // rather than queue for one. Only meaningful with a bought GPU share - the
  // runner refuses it otherwise rather than accept a no-op - and fleet-AND
  // gated for the same reason --config is: a runner predating the `gpu`
  // namespace refuses the WHOLE envelope, leaving the deployment unclaimable
  // on that box.
  if (f["gpu-optional"]) {
    if (!(gpuMilli > 0))
      throw new Error("--gpu-optional applies only when you buy a GPU share (--gpu 0.2); with no slice there is no card requirement to soften and the deployment already runs anywhere");
    envParts.gpu = { optional: true };
    try {
      const av = await api("GET", "/availability");
      if (av && av.aggregate && av.gpuOptional !== true)
        throw new Error("the live fleet doesn't understand gpu.optional yet (availability.gpuOptional is not true) — a runner predating it refuses the whole envelope, so this deployment would never be claimed. Drop --gpu-optional or retry after the fleet updates.");
    } catch (e) {
      if (/doesn't understand gpu.optional/.test(e.message)) throw e;
      say("! couldn't read fleet availability to confirm gpu.optional support; if a runner predates it, this deployment will sit Queued unclaimed");
    }
    say("gpu: PREFERRED, not required — a GPU enclave claims it first; if every card is busy a CPU-only enclave runs it on cores and the ledger bills only the CPU share there");
    // ...but only if it bought enough NODE to hold the app there. On a version
    // that sized the coreless case, a CPU dial that clears the card-case floor
    // and not that one leaves --gpu-optional inert: every CPU box refuses the
    // claim, and the record queues for a card exactly as it would without the
    // flag. Say it here, where it can still be changed, rather than leaving it
    // to be discovered as a deployment that never leaves the queue.
    if (mins.cpuMilliNoGpu > cpuMilli)
      say(`! --gpu-optional will not fire at --cpu ${cpuMilli / 1000}: without a card this app's weights live in node RAM, so a CPU-only enclave needs --cpu ${mins.cpuMilliNoGpu / 1000} (${mins.cpuMilliNoGpu / 10}% of a node) and will refuse the claim below that. Raise --cpu to buy the fallback, or leave it and this stays GPU-only.`);
  }
  let envelope = Object.keys(envParts).length ? JSON.stringify(envParts) : "";
  if (Buffer.byteLength(envelope) > 4096 && envParts.config) {
    if (CHAIN_ONLY) throw new Error("--chain-only currently requires an inline config envelope of at most 4096 bytes; no implicit upload service is used");
    const body = JSON.stringify(envParts.config);
    if (Buffer.byteLength(body) > CONFIG_MAX_BYTES)
      throw new Error(`the config is ${Buffer.byteLength(body)} bytes; enclaves refuse anything over ${CONFIG_MAX_BYTES} at launch`);
    // A pinned config is claimable where the hosts that will RUN it take one. For an isolation tier those are its own
    // hosts, never the fleet-wide aggregate, which leaves them out (enclave-b4's review of 864be4e5): a host that takes
    // config itself (availability.configOverride) must also take it pinned (configCidOverride); a tier that takes it only
    // through the attested release gets the CID resolved there (relay: resolveConfigCid).
    // PER HOST (enclave-b4's review of 8774b4e7): a host takes a pinned config itself (configCidOverride), or takes
    // config only through the release (configOverride not true), or takes it only inline. Claimable when ANY host of the
    // tier can take it, so a tier mixing kinds is judged by the hosts that can.
    if (isoBackend) {
      const pinnedSelf = isoHosts.filter((h) => h?.availability?.configCidOverride === true);
      const viaRelease = isoHosts.filter((h) => h?.availability?.configOverride !== true);
      if (!pinnedSelf.length && !viaRelease.length)
        throw new Error(`the ${isoBackend} host(s) take a config only inline (availability.configCidOverride is not true), and this one must be pinned (the envelope would be ${Buffer.byteLength(envelope)} bytes, over 4096); trim the config`);
      if (pinnedSelf.length) say(`config: pinned; ${isoHostNames(pinnedSelf)} take(s) a pinned config (availability.configCidOverride)`);
      if (viaRelease.length) say(`config: pinned; on ${isoHostNames(viaRelease)} it reaches the ${isoBackend} guest only through the attested release, which resolves its CID`);
    } else {
      const av = await api("GET", "/availability");
      if (!av?.configCidOverride)
        throw new Error("the live fleet does not support pinned config overrides; trim the config or update the fleet");
    }
    const manifest = {};
    if (envParts.config.volumes !== undefined) manifest.volumes = envParts.config.volumes;
    const cid = await pinJson(sess ?? account, Buffer.from(body, "utf8"));
    say(`config pinned at ${cid}; its volume list stays in the routing manifest`);
    envParts.configCid = cid;
    if (Object.keys(manifest).length) envParts.config = manifest; else delete envParts.config;
    envelope = JSON.stringify(envParts);
  }
  if (Buffer.byteLength(envelope) > 4096)
    throw new Error(`the options envelope (waf + config) is ${Buffer.byteLength(envelope)} bytes; runners refuse envelopes over 4096 bytes — trim the config override`);
  // --secrets '{"K":"V"}' / --secrets-file .env: PRIVATE env vars, staged on the
  // relay between create and the first claim so the app has them at first boot.
  // Deliberately NOT part of the on-chain envelope — the whole point is that
  // they never touch the public ledger. Parsed (and any file read) BEFORE any
  // transaction so a typo dies with $0 spent.
  let secretsSet = null;
  if (f.secrets !== undefined || f["secrets-file"] !== undefined) {
    let fromJson = {};
    if (f.secrets !== undefined) {
      try { fromJson = JSON.parse(f.secrets); } catch (e) { throw new Error("--secrets must be a JSON object of NAME: value: " + e.message); }
      if (!fromJson || Array.isArray(fromJson) || typeof fromJson !== "object" || Object.values(fromJson).some((v) => typeof v !== "string"))
        throw new Error('--secrets must be a JSON object of string values, e.g. --secrets \'{"S3_SECRET_KEY":"…"}\'');
    }
    secretsSet = { ...secretsKv([], f["secrets-file"]), ...fromJson };
    if (!Object.keys(secretsSet).length) throw new Error("--secrets/--secrets-file named no secrets");
    say(`secrets: ${Object.keys(secretsSet).length} value${Object.keys(secretsSet).length === 1 ? "" : "s"} will be staged on the relay (private; injected as env vars by the enclave, never on-chain)`);
  }

  // price it before asking for money (the same formula the claim will apply)
  const [prices, maxGpuMilli] = await Promise.all([
    CHAIN_ONLY ? null : livePrices6(),
    // operator-set per-deployment GPU-share cap; contracts predating it have
    // no getter (the read reverts) -> 1000 = a whole card, i.e. uncapped
    read(DEFAULTS.DEPLOYMENTS_ADDRESS,
         [{ type: "function", name: "maxGpuMilli", stateMutability: "view", inputs: [], outputs: [{ type: "uint16" }] }],
         "maxGpuMilli").then(Number).catch(() => 1000),
  ]);
  // create() refuses gpuMilli over the cap - fail with words, not a revert.
  // Deployer-facing copy: most users deploying an app didn't publish it, so
  // "stays publishable" means nothing to them - just say it can't run here.
  if (gpuMilli > maxGpuMilli)
    throw new Error(mins.gpuMilli > maxGpuMilli
      ? `${f._[0]} needs at least a ${mins.gpuMilli / 10}% GPU share, but the platform currently caps deployments at ${maxGpuMilli / 10}% of a card - it can't be deployed right now`
      : `--gpu ${gpuMilli / 10}% is over the platform's per-deployment GPU cap of ${maxGpuMilli / 10}% of a card - lower --gpu`);
  // The version's publisher fee is snapshotted INTO the record by create():
  // read it fresh from the catalog (fail closed - a deployment that
  // under-declares it is a record no runner will ever claim, its funding
  // unrecoverable, exactly like under-provisioned shares) and refuse
  // ledgers that predate the fee surface.
  const fee6 = ver ? await versionFee6(app.appId, Number(ref.split("/").pop())) : 0n;
  const { rev: depRev, abi: depsAbi } = await depAbi();
  if (fee6 > 0n && depRev < 4)
    throw new Error(`${f._[0]} charges a publisher fee, which the live EnclaveDeployments contract predates (deploymentsSchema < 4) - it can't be deployed until the ledger upgrade`);
  // the ledger's own bound on create()'s options field: rev <= 4 contracts cap
  // it at 100 bytes (CID-sized) and revert "configCid length" on more - the tx
  // would never mine, so refuse with words before any signature
  if (envParts.config && depRev < 5)
    throw new Error("the live EnclaveDeployments contract predates per-deployment config overrides (deploymentsSchema < 5): its create() caps the options field at 100 bytes - drop --config until the rev-5 ledger upgrade");
  const envCap = depRev >= 5 ? 4096 : 100;
  if (Buffer.byteLength(envelope) > envCap)
    throw new Error(`the options envelope is ${Buffer.byteLength(envelope)} bytes but this ledger caps the field at ${envCap} bytes (create() reverts "configCid length") - trim the ${envParts.config ? "config override" : "protection rules"}`);
  if (CHAIN_ONLY && depRev < 8) throw new Error("--chain-only requires a ledger with owner spend ceilings (schema 8 or newer)");
  const rate = CHAIN_ONLY ? perSec6FromHour(numFlag(f["max-rate"], "--max-rate"))
    : rate6Of(prices, gpuMilli, cpuMilli) + fee6;
  if (fee6 > 0n)
    say(`publisher fee: ${usd6(fee6 * 3600n)}/h, paid straight to ${app.publisher} out of each funding (included in the rate below)`);
  // The spend ceiling (rev-8 ledgers). Default: exactly what we just quoted —
  // the cheapest live enclave — so nothing dearer can ever pick this up. A
  // roomier --max-rate keeps failover options open on a mixed-price fleet, at
  // the cost of possibly paying more after a host dies.
  let maxRate6 = 0n;
  if (depRev >= 8) {
    maxRate6 = f["max-rate"] !== undefined ? perSec6FromHour(numFlag(f["max-rate"], "--max-rate")) : rate;
    if (maxRate6 <= fee6)
      throw new Error(`--max-rate must be above the app's publisher fee (${usd6(fee6 * 3600n)}/h)`);
    if (maxRate6 < rate)
      throw new Error(`--max-rate ${usd6(maxRate6 * 3600n)}/h is below what ${prices.who} charges for these shares `
                    + `(${usd6(rate * 3600n)}/h) - no enclave could claim it`);
    say(`rate cap: ${usd6(maxRate6 * 3600n)}/h - enclaves dearer than this can't run it, now or after a failover `
      + `(change it later: enclave rate-cap <id> <usd/hour>)`);
  } else if (f["max-rate"] !== undefined) {
    throw new Error("the live ledger predates rate caps (deploymentsSchema < 8) - drop --max-rate");
  }
  const fundUsd = f.fund !== undefined ? numFlag(f.fund, "--fund") : 0;
  const fundEth = f["fund-eth"] !== undefined ? numFlag(f["fund-eth"], "--fund-eth") : 0;
  if (!fundUsd && !fundEth)
    throw new Error(`nothing to fund it with: add --fund <usd> (rate is ${usd6(rate * 3600n)}/h; runners skip unfunded work)`);
  if (sess) return deployViaSession(sess, { f, ref, gpuMilli, cpuMilli, appPort, portsCsv, isPublic, envelope, maxRate6, fundUsd, rate });
  const eth = await pub().getBalance({ address: account.address });
  if (eth === 0n) throw new Error(`${account.address} has no Base ETH for transaction gas; bridge a little first`);
  const buys = fundUsd ? dur(fundUsd * 1e6 / Number(rate)) : `(ETH at the live rate)`;
  if (!(await confirm(`deploy ${f._[0]}: gpu ${gpuMilli / 10}% cpu ${cpuMilli / 10}% ${CHAIN_ONLY ? "capped at" : "at"} ${usd6(rate * 3600n)}/h, `
                    + `fund ${fundUsd ? "$" + fundUsd.toFixed(2) : fundEth + " ETH"} ≈ ${buys}?`))) return say("aborted");

  // 1. create — the id is minted on-chain, read back from the Created event
  // (rev-1 contracts take a now-removed sshPubKey string before configCid;
  // rev-4 ones take the publisher-fee snapshot after it)
  const rcpt = await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi: depsAbi,
    functionName: "create",
    args: [ref, gpuMilli, cpuMilli, appPort, portsCsv, isPublic, ...(depRev >= 2 ? [] : [""]), envelope,
           ...(depRev >= 4 ? [fee6 > 0n ? app.publisher : "0x0000000000000000000000000000000000000000", fee6] : []),
           ...(depRev >= 8 ? [maxRate6] : [])] });
  const log = (rcpt.logs || []).find((l) => l.topics?.[0] === DEP_CREATED_TOPIC
    && l.address.toLowerCase() === DEFAULTS.DEPLOYMENTS_ADDRESS.toLowerCase());
  if (!log) throw new Error("create succeeded but no Created event in the receipt; inspect tx " + rcpt.transactionHash);
  const id = log.topics[1];
  say(`created ${id}`);
  // Echo back the asset the user actually chose (don't flip ETH -> USDC).
  const fundHint = `enclave fund ${id} ${fundUsd ? `--usdc ${fundUsd}` : `--eth ${fundEth}`}`;

  // 1a. read-after-write: nothing below runs until every reader sees the record
  const seen = await waitVisible(id, account.address, { relay: !!secretsSet });
  if (!seen.views)
    throw new Error(`created ${id}, but after ${VISIBLE_WAIT_MS / 1000}s ${seen.lagging}, so nothing was staged or funded. `
      + `The deployment exists on-chain, NOT funded (runners skip it). Once it shows up, `
      + (secretsSet ? `stage its secrets (enclave secrets set ${id} KEY=VALUE…), then ` : "") + `fund it: ${fundHint}`);

  // 1b. stage secrets BEFORE funding: claims only chase funded work, so the
  // values are on the relay before any runner can launch the app. A store
  // failure must not strand the created record — warn and keep going (the
  // owner re-runs `enclave secrets set` and restarts).
  if (secretsSet) {
    try {
      const put = () => secretsCall(account, id, JSON.stringify({ set: secretsSet }));
      const r = await put().catch(async (e) => {
        if (!isRelay404(e)) throw e;
        say("! the relay doesn't see the deployment yet; retrying the secrets once");
        await sleep(LAG_PAUSE_MS);
        return put();
      });
      say(`secrets staged (rev ${r.rev}): ${r.names.join(", ")}`);
      await secretsFleetWarn();
    } catch (e) {
      say(`! secrets NOT stored (${e.message}) — the app launches without them; retry with: enclave secrets set ${id} … --restart`);
    }
  }

  // 2. fund (separate tx — the deployment already exists; if this fails it's inert, not lost).
  // One retry if the node that estimated it still had no record; before it,
  // the balance is re-read, so money that already arrived is never sent twice.
  const bal0 = seen.views.reduce((m, d) => (d && d.balance6 > m ? d.balance6 : m), 0n);
  const retry = (send) => send().catch(async (e) => {
    if (!isUnknownRevert(e)) throw e;
    say("! the funding estimate ran on a node that doesn't see the deployment yet; retrying once");
    await sleep(LAG_PAUSE_MS);
    if ((await ledgerViews(id)).some((d) => d && d.balance6 > bal0)) return say("the deployment's balance already moved; not sending again");
    return send();
  });
  try {
    if (fundUsd) await fundUsdc(account, id, fundUsd, { retry });
    else { const { abi } = await depAbi();
      await retry(() => sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi,
        functionName: "fundEth", args: [id], value: parseEther(String(fundEth)) })); }
  } catch (e) {
    throw new Error(`created but NOT funded (${e.message}); top up later: ${fundHint}`);
  }
  say(`funded ${fundUsd ? "$" + fundUsd.toFixed(2) : fundEth + " ETH"}`);
  if (CHAIN_ONLY) {
    if (opt.json) return jout({ id, status: "funded", ledger: DEFAULTS.DEPLOYMENTS_ADDRESS, readinessVerified: false });
    return say(`submitted to ledger ${DEFAULTS.DEPLOYMENTS_ADDRESS}; verify the serving host and its signed route before sending application data`);
  }

  // 3. nudge the fleet (advisory; the ~60s sweep would find it anyway)
  try {
    const h = await api("POST", "/v1/claim-hint", { body: { id } });
    if (h.accepted === false && h.reason) say(`claim-hint declined: ${h.reason} (the sweep may still claim it)`);
  } catch {}

  if (f["no-wait"]) return say(opt.json ? JSON.stringify({ id, url: appUrl(id) }) : `not waiting; check: enclave status ${id}`);

  // 4. wait: ledger lease first, then the runner's own status
  say("waiting for an enclave to claim…");
  let claimed = null;
  for (let i = 0; i < 90 && !claimed; i++) {
    await sleep(2000);
    const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "get", [id]).catch(() => null);
    if (d && !/^0x0+$/.test(d.runner) && Number(d.leaseUntil) * 1000 > Date.now()) claimed = d;
  }
  if (!claimed) throw new Error(`no enclave claimed it yet (still queued; funded work is retried every sweep); watch: enclave status ${id}`);
  say(`claimed by ${short(claimed.runner)} (operator ${claimed.runnerOperator})`);
  const done = { running: 1, failed: 1, terminated: 1, expired: 1 };
  let rec = null;
  for (let i = 0; i < 180; i++) {
    rec = await api("GET", `/v1/deployments/${id}`, { auth: account, ok404: true });
    if (rec && done[rec.status]) break;
    await sleep(2500);
  }
  if (!rec || rec.status !== "running")
    throw new Error(`deployment is "${rec?.status || "unknown"}"; logs: enclave logs ${id}`);
  if (opt.json) return jout({ id, status: rec.status, url: appUrl(id) });
  say(`running at ${appUrl(id)}`);
  say(`verify before sending data: enclave attest ${id}`);
}

// Which wasi world contract does a component target? Same classifier as the
// runner (wasm_manager._component_contract) and the upload gateway — the
// EXPORT decides, in the order `wasmtime serve` tries instantiation. Mixed
// 0.2/0.3 IMPORTS are normal (rustc's wasm32-wasip3 std still imports WASIp2
// APIs), so only the top-level export section (id 11) is read: section walk,
// then a scan for length-prefixed `wasi:` names inside that one payload.
// wasm64 detection: does this CORE module (layer 0) declare a 64-bit linear
// memory? Reads the memory section (id 5) — the first memory's limits flags
// carry the memory64 bit (0x04). Structural, not a byte scan (there is no
// import string to key on). Lockstep with wasm_manager._module_mem64, the
// launch authority; components and anything unparseable return false.
function moduleMem64(bytes) {
  if (bytes.length < 8 || bytes.readUInt32LE(0) !== 0x6d736100 || (bytes[6] | (bytes[7] << 8)) !== 0) return false;
  const uleb = (buf, i) => {
    let r = 0, s = 0;
    for (;;) {
      const b = buf[i++];
      if (b === undefined) throw new Error("truncated uleb128");
      r += (b & 0x7f) * 2 ** s;
      if (!(b & 0x80)) return [r, i];
      s += 7;
      if (s > 35) throw new Error("uleb128 too long");
    }
  };
  try {
    for (let i = 8; i < bytes.length; ) {
      const sid = bytes[i];
      const [size, j] = uleb(bytes, i + 1);
      if (sid === 5) {                    // memory section
        const [count, k] = uleb(bytes, j);
        if (count === 0) return false;
        const [flags] = uleb(bytes, k);
        return (flags & 0x04) !== 0;      // limits flag bit 2: 64-bit index
      }
      i = j + size;
    }
  } catch { return false; }
  return false;
}

// wasm64 COMPONENT detection: a component (layer 1) whose first memory-bearing
// core module (section id 1) declares a 64-bit memory — a wasip2 app that can
// address more than 4 GiB. Lockstep with wasm_manager._component_mem64 (the
// launch authority) and the gateway's component_mem64.
function componentMem64(bytes) {
  if (bytes.length < 8 || bytes.readUInt32LE(0) !== 0x6d736100 || (bytes[6] | (bytes[7] << 8)) !== 1) return false;
  const uleb = (buf, i) => {
    let r = 0, s = 0;
    for (;;) {
      const b = buf[i++];
      if (b === undefined) throw new Error("truncated uleb128");
      r += (b & 0x7f) * 2 ** s;
      if (!(b & 0x80)) return [r, i];
      s += 7;
      if (s > 35) throw new Error("uleb128 too long");
    }
  };
  const hasMemory = (m) => {
    if (m.length < 8) return false;
    for (let i = 8; i < m.length; ) {
      const sid = m[i];
      const [size, j] = uleb(m, i + 1);
      if (sid === 5) { const [count] = uleb(m, j); return count > 0; }
      i = j + size;
    }
    return false;
  };
  try {
    for (let i = 8; i < bytes.length; ) {
      const sid = bytes[i];
      const [size, j] = uleb(bytes, i + 1);
      const inner = bytes.subarray(j, j + size);
      if (sid === 1) {                    // core module: any 64-bit memory decides
        if (hasMemory(inner) && moduleMem64(inner)) return true;
      } else if (sid === 4) {             // nested component (a wasm64 app ships composed under a wasm32 proxy)
        if (componentMem64(Buffer.from(inner))) return true;
      }
      i = j + size;
    }
  } catch { return false; }
  return false;
}

function componentContract(bytes) {
  const none = { wasi: null, world: null };
  if (bytes.length < 8 || bytes.readUInt32LE(0) !== 0x6d736100 || (bytes[6] | (bytes[7] << 8)) !== 1) return none;
  const uleb = (buf, i) => {   // -> [value, nextIndex]; throws on malformed
    let r = 0, s = 0;
    for (;;) {
      const b = buf[i++];
      if (b === undefined) throw new Error("truncated uleb128");
      r += (b & 0x7f) * 2 ** s;
      if (!(b & 0x80)) return [r, i];
      s += 7;
      if (s > 35) throw new Error("uleb128 too long");
    }
  };
  const exports = new Set();
  try {
    for (let i = 8; i < bytes.length; ) {
      const sid = bytes[i];
      const [size, j] = uleb(bytes, i + 1);
      if (sid === 11) {
        const payload = bytes.subarray(j, j + size);
        for (let p = 0; (p = payload.indexOf("wasi:", p)) !== -1; p++) {
          for (let back = 1; back <= 5 && p - back >= 0; back++) {
            let ln, q;
            try { [ln, q] = uleb(payload, p - back); } catch { continue; }
            if (q !== p || p + ln > payload.length) continue;
            const s = payload.subarray(p, p + ln).toString("latin1");
            if (/^[A-Za-z0-9:/@.+-]+$/.test(s)) exports.add(s);
            break;
          }
        }
      }
      i = j + size;
    }
  } catch { return none; }
  for (const [prefix, ver] of [["wasi:http/handler@0.3.", "0.3"], ["wasi:http/incoming-handler@0.2.", "0.2"],
                               ["wasi:cli/run@0.3.", "0.3"], ["wasi:cli/run@0.2.", "0.2"]]) {
    const hit = [...exports].filter((e) => e.startsWith(prefix)).sort();
    if (hit.length) return { wasi: ver, world: hit[0] };
  }
  return none;
}

// Pin bytes through the validating gateway. Every pin route is WALLET-AUTHORIZED
// (it closes the open-pin storage DoS): sign enclave-upload:<sha256>:<expiry>,
// trade the signature at the API for a one-time token bound to those exact
// bytes, then upload carrying it. The token also spends against a per-wallet
// daily byte budget, which is what actually bounds the pin surface.
// `account` may be a session (sessionForCommand): its key signs the token request
// itself (Authorization: EnclaveSession, scope api.upload) and the token is the
// session OWNER's, so the pin spends the owner's daily byte budget.
async function pinBytes(account, bytes, url, contentType, label) {
  const hash = crypto.createHash("sha256").update(bytes).digest("hex");
  const expiry = Math.floor(Date.now() / 1000) + 300;
  let headers;
  if (env.ENCLAVE_IPFS_WALLET_AUDIENCE) {
    if (account?.kind === "session") throw new Error("Direct uploads currently require an EOA wallet; platform sessions still need the legacy issuer");
    headers = await directUploadHeaders({audience:env.ENCLAVE_IPFS_WALLET_AUDIENCE,url,address:account.address,bytes,signMessage:args=>account.signMessage(args)});
  } else {
    const tok = account?.kind === "session" ? await sessionUploadToken(account, hash, expiry)
                                            : await walletUploadToken(account, hash, expiry);
    if (!tok || !tok.token) throw new Error("upload authorization failed");
    headers = {"x-upload-address":tok.address,"x-upload-expiry":String(expiry),"x-upload-token":tok.token};
  }
  trace(`POST ${url} (${label}, wallet authorization)`);
  const up = await fetch(url, { method: "POST", body: bytes, headers: { "content-type": contentType, ...headers } });
  const body = await up.text();
  if (!up.ok) throw new Error(`IPFS upload failed (${up.status}): ${body.slice(0, 200)}`);
  const cid = JSON.parse(body).cid;
  if (!cid) throw new Error("IPFS upload returned no CID");
  return cid;
}
async function walletUploadToken(account, hash, expiry) {
  const signature = await account.signMessage({ message: `enclave-upload:${hash}:${expiry}` });
  return api("POST", "/v1/apps/upload-token", { body: { hash, expiry, signature } });
}

// An app config, for a version that keeps it at a CID rather than inline. The
// gateway re-parses the JSON and caps the size; the enclave re-fetches and
// hash-verifies against this CID, so a bad pin fails at publish rather than
// becoming a version that cannot launch.
const pinJson = (account, buf) =>
  pinBytes(account, buf, DEFAULTS.ipfsJsonUpload, "application/json", "config.json");

async function cmdPublish(rest) {
  catalogWriteAllowed();   // before anything is pinned: the version would go to a catalog this CLI cannot vouch for
  // with a session: the publisher is the session's VAULT (app.publish, named apps only)
  const sess = await sessionForCommand();
  const account = sess ? null : loadKey();
  const f = flags(rest, { val: ["--slug", "--name", "--desc", "--version", "--mem", "--cpu-gflops",
                                "--vram", "--gpu-gflops", "--ports", "--config", "--fee",
                                "--nogpu-mem", "--nogpu-cpu-gflops"],
                       bool: ["--gpu-optional"] });
  const file = f._[0];
  if (!file || !f.slug) throw new Error("usage: enclave publish <app.wasm> --slug <slug> [--name --desc --version --mem MB --cpu-gflops N --vram MB --gpu-gflops N --nogpu-mem MB --nogpu-cpu-gflops N --ports CSV --config JSON --fee $/hr]");
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(f.slug)) throw new Error("slug: lowercase letters, digits, hyphens (max 40)");
  if (sess) {
    await sessionRequire(sess, "app.publish", "api.upload");
    sessionRequireApp(sess, await read(DEFAULTS.APP_CATALOG_ADDRESS, CATALOG_ABI, "appIdOf", [sess.vault, f.slug]),
                      "app.publish", f.slug);
  }
  const publisher = sess ? sess.vault : account.address;
  // --config = the app's default/template ENCLAVE_CONFIG (deploy consoles pre-fill from it)
  // --gpu-optional rides IN that config as `gpuOptional: true`: the publisher
  // declaring that --vram/--gpu-gflops describe what this app WOULD use, not
  // what it needs to start. Runners then set no GPU floor for it (minSharesOf)
  // and CPU-only enclaves may serve it; the declared axes stay the recommended
  // slice for a deployer who wants the card. It lives in the version config
  // rather than a new on-chain column because config is already immutable per
  // version, approved with it, and already the place platform-meaningful keys
  // live (`volumes`) - no catalog redeploy, and it ships the day it is pushed.
  const nogpuMem = Number(f["nogpu-mem"] || 0), nogpuGflops = Number(f["nogpu-cpu-gflops"] || 0);
  if (f.config || f["gpu-optional"] || nogpuMem > 0 || nogpuGflops > 0){
    const raw = f.config || "{}";
    if (Buffer.byteLength(raw) > CONFIG_MAX_BYTES)
      throw new Error(`--config too long (≤ ${CONFIG_MAX_BYTES} bytes)`);
    let o; try { o = JSON.parse(raw); } catch (e) { throw new Error("--config isn't valid JSON: " + e.message); }
    if (!o || Array.isArray(o) || typeof o !== "object") throw new Error("--config must be a JSON object");
    if (f["gpu-optional"]){
      if (!(Number(f.vram) > 0 || Number(f["gpu-gflops"]) > 0))
        throw new Error("--gpu-optional describes GPU specs as desired rather than required, so it needs --vram and/or --gpu-gflops (without them this app already asks for no card)");
      o.gpuOptional = true;
      f.config = JSON.stringify(o);
      say("gpu-optional: --vram/--gpu-gflops publish as DESIRED - runners set no GPU floor, CPU-only enclaves may serve it, and the declared slice is what a deployer buys to get the card");
    }
    // --nogpu-mem / --nogpu-cpu-gflops ride in the same config as
    // `cpuFallback`, and they answer the question --gpu-optional opens: the
    // four on-chain axes are ONE set, so --mem/--cpu-gflops describe this app
    // beside the card it asked for - the guest's own memory, with the weights
    // resident in its VRAM slice. Serve the same app on cores and those
    // weights are in node RAM beside the guest and every matmul is the node's
    // work, which is a bigger node slice by a long way. Without this the
    // coreless placement is sized off the card-case figure and the app dies at
    // weight-load on a share nobody could have known was too small.
    if (nogpuMem > 0 || nogpuGflops > 0){
      if (!f["gpu-optional"] && !(o.gpuOptional === true))
        throw new Error("--nogpu-mem/--nogpu-cpu-gflops size this app for a box with NO card, which only happens when the card is optional - publish with --gpu-optional too (or drop them: a CPU-only app's --mem/--cpu-gflops already describe that case)");
      if (nogpuMem < 0 || nogpuMem > 1048576) throw new Error("--nogpu-mem must be 0..1048576 MB");
      if (nogpuGflops < 0 || nogpuGflops > 10000000) throw new Error("--nogpu-cpu-gflops must be 0..10000000");
      o.cpuFallback = {};
      if (nogpuMem > 0) o.cpuFallback.memMb = Math.round(nogpuMem);
      if (nogpuGflops > 0) o.cpuFallback.cpuGflops = Math.round(nogpuGflops);
      f.config = JSON.stringify(o);
      say(`cpu-fallback: on an enclave with no card this app is sized at ${nogpuMem > 0 ? nogpuMem + " MB RAM" : ""}`
        + `${nogpuMem > 0 && nogpuGflops > 0 ? " / " : ""}${nogpuGflops > 0 ? nogpuGflops + " GFLOPS CPU" : ""}`
        + ` instead of --mem/--cpu-gflops. A deployment dialled for the card case is refused by CPU-only boxes rather than served too small - it keeps running wherever a card is.`);
    }
  }
  const bytes = fs.readFileSync(file);
  // same gate the IPFS gateway and runners apply: a wasi:http *component* —
  // with the one core-module carve-out: wasm64 (a 64-bit linear memory, the
  // >4 GiB guests), which runs in PORT mode under `wasmtime run`
  if (bytes.length < 8 || bytes.readUInt32LE(0) !== 0x6d736100)
    throw new Error(`${file} is not a wasm binary (bad magic)`);
  const layer = bytes[6] | (bytes[7] << 8);
  const needsMem64 = layer === 1 && componentMem64(bytes);
  if (layer === 0) throw new Error(`${file} is a core wasm module, not a component; build for wasm32-wasip2 (cargo component / componentize), wasm32-wasip3 (see the develop guide's WASIp3 chapter), or — for a guest that needs more than 4 GiB — a memory64 COMPONENT with wasm/Dockerfile.wasm64p2-build`);
  if (layer !== 0 && layer !== 1) throw new Error(`${file} has unrecognized wasm layer ${layer} (expected a component)`);
  if (needsMem64)
    say("detected a memory64 component: a wasip2 app that addresses more than 4 GiB — only mem64-capable enclaves will claim it, and its memory ceiling is the deployment's full RAM slice instead of the 4 GiB wasm32 clamp");
  // world contract, read from the binary (never asked of the publisher): a
  // wasip3 component publishes `wasi: "0.3"` in its version config so runners
  // route claims to p3-capable boxes; the runner re-classifies the bytes at
  // launch, so this stamp is routing, not trust. wasip2 versions are stamped
  // too — explicit beats implied — and an unclassifiable export section
  // publishes without the key, exactly like every pre-p3 version.
  const contract = componentContract(bytes);
  if (contract.wasi) say(`detected ${contract.wasi === "0.3" ? "WASIp3" : "WASIp2"} component (exports ${contract.world})`);
  else say("could not classify the component's wasi world from its exports; publishing without a wasi tag (runners will classify at launch)");
  // cooperative threads (🧵): a coop-linked guest's core module imports
  // `[thread-new-indirect-v0]` and siblings — length-prefixed names sitting
  // verbatim in the binary, so the same raw-scan doctrine as the world scan.
  // Stamped as `threads: true` so runners route claims to thread-capable
  // boxes; the runner re-classifies the bytes at launch (routing, not trust).
  const needsThreads = bytes.includes("[thread-");
  if (needsThreads) say("detected cooperative threads (\u{1F9F5}): only thread-capable enclaves will claim it");
  // shared-everything threads (⚡): set-componentize wires the spawn canon
  // under `[set-spawn-indirect]` — same raw-scan doctrine. Stamped `set: true`
  // so runners route claims to SET-capable boxes. Independent of `threads`.
  const needsSet = bytes.includes("[set-spawn-indirect]");
  if (needsSet) say("detected shared-everything threads (\u{26A1}): only SET-capable enclaves will claim it");

  // version defaults to the next integer for your app (labels are free-form, matched exactly on deploy)
  let version = f.version;
  const appId = await read(DEFAULTS.APP_CATALOG_ADDRESS, CATALOG_ABI, "appIdOf", [publisher, f.slug]);
  const existing = Number(await read(DEFAULTS.APP_CATALOG_ADDRESS, CATALOG_ABI, "numVersions", [appId]).catch(() => 0n));
  if (!version) version = String(existing + 1);

  const res = [Math.round(numFlag(f.vram, "--vram") ?? 0), Math.round(numFlag(f["gpu-gflops"], "--gpu-gflops") ?? 0),
               Math.round(numFlag(f.mem, "--mem") ?? 256), Math.round(numFlag(f["cpu-gflops"], "--cpu-gflops") ?? 10)];

  // --fee = YOUR hourly fee in USD, stored on-chain as USDC 6dp per SECOND.
  // Deployers' fundings pay it straight to your publisher wallet, pro-rata;
  // immutable per version and covered by the owner's approval, like ports.
  const feeUsdHr = numFlag(f.fee, "--fee") ?? 0;
  if (feeUsdHr < 0) throw new Error("--fee can't be negative");
  const feePerSec6 = BigInt(Math.round(feeUsdHr * 1e6 / 3600));
  if (sess && feePerSec6 > 0n)
    throw new Error("a session publishes free versions only (the vault refuses a publisher fee in v1); drop --fee, or publish with --wallet");
  if (feePerSec6 > 0n) {
    if ((await catRev()) < 5)
      throw new Error("--fee needs the rev-5 catalog (this one predates publisher fees) - publish free, or wait for the catalog upgrade");
    const max = await read(DEFAULTS.APP_CATALOG_ADDRESS, CATALOG_ABI, "maxFeePerSec6", []);
    if (feePerSec6 > max)
      throw new Error(`--fee ${feeUsdHr} is over the platform's cap of ${usd6(max * 3600n)}/h - lower it`);
  }
  if (!(await confirm(`publish ${file} (${(bytes.length / 1048576).toFixed(1)} MB) as ${f.slug}:${version} `
                    + `res=[vram ${res[0]}MB, gpu ${res[1]}Gf, mem ${res[2]}MB, cpu ${res[3]}Gf]`
                    + (feePerSec6 > 0n ? ` fee=${usd6(feePerSec6 * 3600n)}/h to ${account.address}` : "") + `?`))) return say("aborted");

  // 1. pin to IPFS. The gateway requires a WALLET-AUTHORIZED token (closes the
  //    open-pin storage DoS): sign enclave-upload:<sha256>:<expiry>, trade it at
  //    the API for a one-time token, then upload the bytes carrying it.
  const cid = await pinBytes(sess ?? account, bytes, DEFAULTS.ipfsUpload, "application/wasm", file);
  say(`pinned ipfs://${cid}`);

  // 2. cut the catalog version (publisher = your address; appId = keccak(publisher, slug))
  // --config rides rev-4 catalogs as the version's default/template ENCLAVE_CONFIG
  const rev = await catRev();
  if (f.config && rev < 4) throw new Error("--config needs the rev-4 catalog (this one doesn't store per-version configs)");
  // stamp the detected world contract into the version config (rev-4+: config
  // is immutable per version and approval-covered, the same envelope pattern
  // as gpuOptional/_media — no catalog schema change). A publisher-supplied
  // `wasi` never survives: the binary is the authority.
  if ((contract.wasi || needsThreads || needsMem64) && rev >= 4) {
    let cfgObj; try { cfgObj = JSON.parse(f.config || "{}"); } catch { cfgObj = {}; }
    if (contract.wasi) {
      if (cfgObj.wasi !== undefined && cfgObj.wasi !== contract.wasi)
        say(`--config declared wasi ${JSON.stringify(cfgObj.wasi)} but the binary exports ${contract.world}; using the binary's answer`);
      cfgObj.wasi = contract.wasi;
    }
    // threads: binary is the authority in BOTH directions — set when the
    // marker is present, dropped when it isn't (an over-declared `threads`
    // would route claims to thread boxes for nothing).
    if (needsThreads) cfgObj.threads = true;
    else if (cfgObj.threads !== undefined) {
      say("--config declared threads but the binary carries no [thread- imports; dropping the key");
      delete cfgObj.threads;
    }
    // set: same binary-authoritative BOTH directions as threads.
    if (needsSet) cfgObj.set = true;
    else if (cfgObj.set !== undefined) {
      say("--config declared set but the binary carries no [set-spawn-indirect] import; dropping the key");
      delete cfgObj.set;
    }
    // mem64: same binary-authoritative BOTH directions — an over-declared
    // `mem64` would route claims to mem64 boxes for nothing, and a missing
    // one would let a wasm64 module land on an engine that cannot parse it.
    if (needsMem64) cfgObj.mem64 = true;
    else if (cfgObj.mem64 !== undefined) {
      say("--config declared mem64 but the binary's memory section is not 64-bit; dropping the key");
      delete cfgObj.mem64;
    }
    f.config = JSON.stringify(cfgObj);
    if (Buffer.byteLength(f.config) > CONFIG_MAX_BYTES)
      throw new Error(`--config too long after the wasi stamp (≤ ${CONFIG_MAX_BYTES} bytes)`);
  }
  // A config past the on-chain ceiling rides a CID instead (catalog rev 7). The
  // chain record then keeps only the ROUTING MANIFEST — the handful of keys a
  // runner needs before it can fetch anything — and the pinned JSON is what the
  // guest receives as ENCLAVE_CONFIG.
  let configCid = "";
  const cfgBytes = Buffer.byteLength(f.config || "");
  if (cfgBytes > CONFIG_INLINE_MAX) {
    if (rev < 7) throw new Error(
      `--config is ${cfgBytes} bytes; this catalog (rev ${rev}) stores configs inline and caps them at ${CONFIG_INLINE_MAX}. `
      + `A rev-7 catalog keeps large configs at a CID.`);
    // what stays on-chain: only the derived routing keys, never the body.
    // Derived and size-checked BEFORE the pin — pinning is irreversible and
    // spends the publisher's daily byte budget, so a manifest that would revert
    // publishVersionCfg has to fail here rather than after.
    const cfgBuf = Buffer.from(f.config, "utf8");
    const full = JSON.parse(f.config);
    const manifest = {};
    for (const k of ROUTING_KEYS) if (full[k] !== undefined) manifest[k] = full[k];
    const onchain = Object.keys(manifest).length ? JSON.stringify(manifest) : "";
    if (Buffer.byteLength(onchain) > CONFIG_INLINE_MAX) throw new Error(
      `the on-chain routing manifest (${ROUTING_KEYS.join(", ")}) is ${Buffer.byteLength(onchain)} bytes, `
      + `over the ${CONFIG_INLINE_MAX}-byte record limit - shorten \`volumes\` or \`_media\``);
    configCid = await pinJson(sess ?? account, cfgBuf);
    say(`pinned config ipfs://${configCid} (${cfgBytes} bytes)`);
    f.config = onchain;
  }
  const args = [f.slug, f.name || f.slug, f.desc || "", version, cid, res, f.ports || ""];
  if (rev >= 3) args.push(f.config || "");   // rev 3+ take the 8-arg form (rev 3 stores it app-level; we always pass "")
  if (configCid) args.push(configCid);       // rev 7 publishVersionCfg: the config's CID sits between config and fee
  if (rev >= 5) args.push(feePerSec6);       // rev 5+ take the 9-arg form (the version's publisher fee; 0 = free)
  // a session's vault builds the catalog call itself (publishVersion, or publishVersionCfg with a configCid; fee 0)
  const rcpt = sess
    ? await sessionTx(sess, "app.publish", { slug: f.slug, name: f.name || f.slug, description: f.desc || "", version, cid,
                                             res, ports: f.ports || "", config: f.config || "", configCid })
    : await sendTx(account, { address: DEFAULTS.APP_CATALOG_ADDRESS, abi: CATALOG_ABI,
    functionName: configCid ? "publishVersionCfg" : "publishVersion", args });
  // rev 9: the catalog owner's own publishes are approved ON PUBLISH (the
  // publish signature is the approval signature). The receipt says which way
  // it went — the contract emits the VersionApprovalSet it minted — so read
  // that instead of assuming Pending or racing a fresh eth_call.
  const approvedNow = (rcpt.logs || []).some((l) =>
    l.topics?.[0] === APPROVAL_SET_TOPIC && BigInt(l.data) === 1n);
  if (opt.json) return jout({ slug: f.slug, version, cid, appId, tx: rcpt.transactionHash,
                              approval: approvedNow ? "approved" : "pending" });
  say(`published ${f.slug}:${version} (tx ${rcpt.transactionHash})`);
  if (approvedNow) {
    say(`approved on publish (catalog-owner releases skip review). Deploy it:`);
    say(`  enclave deploy ${f.slug}:${version} --fund 2`);
    return;
  }
  say(`approval is pending. Each host decides whether to run this release. For owner-only access:`);
  say(`  enclave deploy ${f.slug}:${version} --private --fund 2`);
  say(`for public access on a host that accepts this release:`);
  say(`  enclave deploy ${f.slug}:${version} --fund 2`);
}

async function cmdApps(rest) {
  const q = (rest[0] || "").toLowerCase();
  let apps = await catalogApps();
  if (q) apps = apps.filter((a) => (a.slug + " " + a.name + " " + a.description).toLowerCase().includes(q));
  const rows = [];
  for (const a of apps.slice(0, 50)) {
    const versions = a.versionCount ? await readVersions(a.appId, a.versionCount) : [];
    const latest = [...versions].reverse().find((v) => !v.yanked);
    rows.push({ slug: a.slug, name: a.name, publisher: a.publisher.slice(0, 10) + "…",
                version: latest ? latest.version : "-",
                approval: latest ? APPROVAL_WORD[Number(latest.approval)] : "",
                active: a.active ? "" : "inactive",
                versions, app: a });
  }
  if (opt.json) return jout({ apps: rows.map(({ app, versions, ...r }) => ({ ...r, appId: app.appId,
    versions: versions.map((v) => ({ version: v.version, cid: v.cid, approval: APPROVAL_WORD[Number(v.approval)], yanked: v.yanked })) })) });
  table(rows, [{ h: "app", f: (r) => r.slug + ":" + r.version }, { h: "name", k: "name" },
               { h: "publisher", k: "publisher" }, { h: "approval", k: "approval" }, { h: "", k: "active" }]);
  if (apps.length > 50) say(`(+${apps.length - 50} more; narrow with: enclave apps <query>)`);
}

async function cmdPricing() {
  const p = await api("GET", "/v1/pricing");
  if (opt.json) return jout(p);
  kv([
    p.card ? ["gpu card", `${usd6(BigInt(Math.round((p.card.wholeCardPerSecondUsdc || 0) * 1e6)) * 3600n)}/h whole card (${p.card.vramGb} GB, ${p.card.tflops} TFLOPS${p.card.count ? `, ${p.card.count} cards` : ""})`] : null,
    p.node ? ["cpu node", `${usd6(BigInt(Math.round((p.node.wholeNodePerSecondUsdc || 0) * 1e6)) * 3600n)}/h whole node (${p.node.vcpus} vcpus, ${p.node.ramGb} GB)`] : null,
    ["granularity", p.computeGranularity
      ? `${p.computeGranularity.step || 1}% share steps${p.computeGranularity.minPercent ? `, min ${p.computeGranularity.minPercent}%` : ""}`
      : "1% shares"],
    ["billing", `per ${p.billingIncrementSeconds || 1}s, on-chain balance`],
    p.ethUsd ? ["eth quote", `$${p.ethUsd} (Chainlink, for --fund-eth)`] : null,
    ["contract", p.deploymentsContract], ["chain", String(p.chainId)],
  ]);
  for (const ex of p.examples || []) {
    if (ex.gpuShare === undefined) { say(`  e.g. ${ex.description || JSON.stringify(ex)}`); continue; }
    say(`  e.g. --gpu ${ex.gpuShare} --cpu ${ex.cpuShare}  ->  $${ex.ratePerHourUsdc}/h`
      + (ex.vramGb ? `  (${ex.vramGb} GB vram, ${ex.vcpus} vcpus, ${ex.ramGb} GB ram)` : ""));
  }
}

async function cmdAvailability() {
  const a = await api("GET", "/availability");
  if (opt.json) return jout(a);
  if (a.aggregate) {
    kv([["fleet", `${a.enclaves} live enclave(s)`],
        ["best gpu slice", a.gpuShareFree != null ? Math.round(a.gpuShareFree * 100) + "% of a card" : "none"],
        ["best cpu pool", a.cpuShareFree != null ? Math.round(a.cpuShareFree * 100) + "% of a node" : "none"],
        a.gpuEnclaveCpuShareFree != null ? ["gpu-node cpu", Math.round(a.gpuEnclaveCpuShareFree * 100) + "% (rides with gpu work)"] : null]);
  } else {
    kv([["enclave", a.type || (a.gpu ? "gpu" : "cpu")],
        ["gpu free", a.gpu ? `${Math.round((a.gpuShareFree || 0) * 100)}% (${a.vramFreeGb ?? "?"} GB vram)` : "no gpu"],
        ["cpu free", `${Math.round((a.cpuShareFree || 0) * 100)}% (${a.vcpusFree ?? "?"} vcpus, ${a.ramGbFree ?? "?"} GB)`],
        ["updated", a.updatedAt]]);
  }
}

async function cmdGpu() {
  const g = await api("GET", "/v1/gpu").catch((e) => {
    if (/404/.test(e.message)) return null;
    throw e;
  });
  if (!g) return say("this enclave has no GPU (CPU-only); try --base against the GPU enclave, or `enclave availability`");
  if (opt.json) return jout(g);
  const c = g.capacity || {};
  kv([["role", g.role], ["mps", g.mpsActive ? "active" : "off"],
      c.gpuShareFree != null ? ["gpu free", `${Math.round(c.gpuShareFree * 100)}%${c.vramFreeGb != null ? ` (${c.vramFreeGb} GB vram, ${c.smFree ?? "?"} SMs)` : ""}`] : null,
      ["sm total", g.smTotal != null ? String(g.smTotal) : undefined],
      ["tenants", String((g.tenants || []).length)]]);
  for (const t of g.tenants || []) say(`  ${t.pct}% ${t.status}${t.smGranted ? ` (${t.smGranted} SMs)` : ""}`);
}

async function cmdAccount() {
  const account = loadKey({ required: false });
  const acctTok = accountToken({ required: false });
  if (!account && !acctTok)
    throw new Error("no wallet key and no account session. Run `enclave key new` (wallet) or `enclave login` (Enclave account/passkey)");
  const out = {}, rows = [];
  if (account) {
    const a = await api("GET", "/v1/account", { auth: account });
    out.wallet = a;
    rows.push(["address", a.address], ["chain", String(a.chainId)],
      ["forwarder", a.payment?.forwarder], ["usdc", a.payment?.usdc],
      ["assets", (a.payment?.assets || []).join(", ")],
      ["running", String(a.deployments?.running ?? 0)],
      ["total", String(a.deployments?.total ?? 0)],
      ["funded time", dur(a.deployments?.totalTimeRemainingSec || 0)]);
  }
  if (acctTok) {
    const me = await api("GET", "/v1/account/me", { auth: "account" });
    out.account = me;
    rows.push(["account", me.accountId],
      ["sign-in", `${me.passkeys?.length || 0} passkey(s)`
        + (me.wallets?.length ? `, wallets ${me.wallets.join(", ")}` : "")],
      ["since", me.createdAt]);
    // credit + the account's deployments ride along when the relay serves them
    try {
      const v = await api("GET", "/v1/billing/vault", { auth: "account" });
      out.account.credit = { balanceUsd: v.balanceUsd, capUsd: v.capUsd, vault: v.address };
      rows.push(["credit", `$${v.balanceUsd} of $${v.capUsd} (vault ${v.address})`]);
    } catch (e) {
      if (/no_vault_key|409/.test(e.message)) rows.push(["credit", "none (add a passkey on enclave.host to use credit)"]);
    }
    try {
      const d = await api("GET", "/v1/billing/deployments", { auth: "account" });
      out.account.deployments = (d.deployments || []).length;
      rows.push(["deployments", String((d.deployments || []).length) + " via this account (enclave ls)"]);
    } catch {}
  }
  if (opt.json) return jout(out.wallet && !out.account ? out.wallet : out);
  kv(rows);
}

// ---- per-deployment secrets ---------------------------------------------------
// Env-var-shaped private values (S3 keys, API tokens) stored on the API RELAY,
// never on the public chain: the enclave holding the deployment's lease pulls
// the current set at every app start and injects each entry as a guest env
// var (same visibility class as ENCLAVE_CONFIG — the app can read them, and
// an app that prints them puts them in its own owner-readable log). Owner ops
// are single-use personal_sign signatures over canonical strings (no session;
// the relay checks the signer against the deployment's ON-CHAIN owner):
//   put: enclave-secrets:put:<id>:<expiry>:<sha256hex(payload)>
//        payload = the EXACT JSON string sent as body.payload ({set?,del?,clear?})
//   get: enclave-secrets:get:<id>:<expiry>
// A running app picks changes up on its next start; --restart applies now.
const secretsPutMsg = (id, expiry, payload) =>
  `enclave-secrets:put:${id}:${expiry}:${crypto.createHash("sha256").update(payload, "utf8").digest("hex")}`;
const secretsGetMsg = (id, expiry) => `enclave-secrets:get:${id}:${expiry}`;
async function secretsCall(account, id, payload) {           // payload null = read-back
  const expiry = Math.floor(Date.now() / 1000) + 300;
  const message = payload == null ? secretsGetMsg(id, expiry) : secretsPutMsg(id, expiry, payload);
  const signature = await account.signMessage({ message });
  return api("POST", `/v1/secrets/${id}${payload == null ? "/get" : ""}`,
             { body: payload == null ? { expiry, signature } : { payload, expiry, signature } });
}
// KEY=VALUE args + optional .env file (# comments, blank lines, `export ` prefix).
// dotenv-style quoting: KEY="value" / KEY='value' strip one layer of matched
// quotes ('single' literal, "double" unescapes \" and \\); bare values pass
// through. `secrets ls --show` prints the same canonical quoted form, so its
// output is valid input here. The quotes are a client convention - the relay
// stores the unquoted value.
const secretsUnq = (v) => {
  const dq = /^"([\s\S]*)"$/.exec(v); if (dq) return dq[1].replace(/\\(["\\])/g, "$1");
  const sq = /^'([\s\S]*)'$/.exec(v); if (sq) return sq[1];
  return v;
};
const secretsQuo = (v) => '"' + String(v).replace(/(["\\])/g, "\\$1") + '"';
function secretsKv(pairs, file) {
  const set = {};
  const add = (line, from) => {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!m) throw new Error(`${from}: "${line.length > 40 ? line.slice(0, 37) + "…" : line}" is not KEY=VALUE`);
    set[m[1]] = secretsUnq(m[2]);
  };
  for (const p of pairs) add(p, "argument");
  if (file) {
    for (let line of fs.readFileSync(file, "utf8").split("\n")) {
      line = line.trim().replace(/^export\s+/, "");
      if (!line || line.startsWith("#")) continue;
      add(line, file);
    }
  }
  return set;
}
// after a successful store, one advisory availability probe: the relay accepted
// the secrets, but only an up-to-date FLEET injects them (fleet-AND flag)
async function secretsFleetWarn() {
  try {
    const av = await api("GET", "/availability");
    if (av && av.aggregate && av.secrets !== true)
      say("! stored on the relay, but the live fleet doesn't inject secrets yet (availability.secrets is not true) — they apply once the fleet updates");
  } catch {}
}
async function cmdSecrets(rest) {
  const sub = rest.shift();
  const usage = "usage: enclave secrets set <id> KEY=VALUE… [--file .env] [--restart]\n"
              + "     | enclave secrets ls <id> [--show]\n"
              + "     | enclave secrets rm <id> KEY… [--restart]\n"
              + "     | enclave secrets clear <id> [--restart]";
  if (!["set", "ls", "list", "rm", "clear"].includes(sub || "")) throw new Error(usage);
  const f = flags(rest, { bool: ["--show", "--restart"], val: ["--file"] });
  if (!f._[0]) throw new Error(usage);
  const account = loadKey();
  const id = await resolveId(f._[0], account);
  if (!isB32(id)) throw new Error("secrets need an on-chain deployment (bytes32 id)");
  const kvArgs = f._.slice(1);

  let r;
  if (sub === "set") {
    const set = secretsKv(kvArgs, f.file);
    if (!Object.keys(set).length) throw new Error("nothing to set: pass KEY=VALUE arguments and/or --file .env");
    r = await secretsCall(account, id, JSON.stringify({ set }));
    say(`stored ${Object.keys(set).length} secret${Object.keys(set).length === 1 ? "" : "s"} (rev ${r.rev}): ${r.names.join(", ")}`);
    await secretsFleetWarn();
  } else if (sub === "rm") {
    if (!kvArgs.length) throw new Error("usage: enclave secrets rm <id> KEY [KEY…]");
    r = await secretsCall(account, id, JSON.stringify({ del: kvArgs }));
    say(r.names.length ? `removed; ${r.names.length} left (rev ${r.rev}): ${r.names.join(", ")}` : "removed; no secrets left");
  } else if (sub === "clear") {
    if (!(await confirm(`clear ALL secrets on ${short(id)}?`))) return say("aborted");
    r = await secretsCall(account, id, JSON.stringify({ clear: true }));
    say("cleared");
  } else {                                                   // ls
    r = await secretsCall(account, id, null);
    if (opt.json) return jout(f.show ? r : { ...r, env: undefined });
    if (!r.names.length) return say(`no secrets stored for ${short(id)} (set some: enclave secrets set ${short(id)} KEY=VALUE)`);
    say(`rev ${r.rev} · ${r.updatedAt || ""}`.trim());
    for (const n of r.names) say(f.show ? `${n}=${secretsQuo(r.env[n])}` : `${n}  (${Buffer.byteLength(r.env[n], "utf8")} bytes; --show to reveal)`);
    return;
  }
  if (opt.json) return jout(r);
  if (f.restart) {
    const rr = await api("POST", `/v1/deployments/${id}/restart`, { auth: account })
      .catch((e) => ({ error: e.message }));
    say(rr.error ? `restart failed: ${rr.error} (a queued/stopped app applies them when it next starts)`
                 : "restarted — the app now runs with the new secrets");
  } else if (sub !== "clear") {
    say("a running app applies them on its next start: enclave restart " + short(id));
  }
}

// ---- secret custody (cli/custody.mjs; docs/security/secret-custody.md): the CLI's own helpers, handed in ----------
async function cmdCustodyHere(rest) {
  // loaded on use: the custody code imports ../custody (and viem from the repo root), which a bare `cli/` install lacks
  const { cmdCustody } = await import("./custody.mjs");
  return cmdCustody(rest, {
    flags, loadKey, resolveId, say, jout, short, api, sendTx, secretsKv, env, json: !!opt.json, chainId: DEFAULTS.chainId,
    warn: (m) => console.error(m),
    readFile: (p) => fs.readFileSync(p, "utf8"),
    pubEachClients: () => pubEach().map((x) => x.c),
    vaultAddress: async () => {
      if (CONTRACT_PINS) throw new Error("pinned contract mode supports custody v2; use --v2 with an explicitly pinned vault");
      if (env.ENCLAVE_SECRET_VAULT) return getAddress(env.ENCLAVE_SECRET_VAULT);
      const book = env.ENCLAVE_ADDRESS_BOOK !== undefined ? env.ENCLAVE_ADDRESS_BOOK : DEFAULTS.ADDRESS_BOOK_ADDRESS;
      const a = book ? await bookEntry(book, "secretVault") : null;
      if (!a) throw new Error('no EnclaveSecretVault: the address book names no "secretVault" yet (set ENCLAVE_SECRET_VAULT to use one)');
      return a;
    },
    vaultV2Address: async () => {
      if (CONTRACT_PINS) return pinnedContract("secretVaultV2", env.ENCLAVE_SECRET_VAULT_V2);
      if (env.ENCLAVE_SECRET_VAULT_V2) return getAddress(env.ENCLAVE_SECRET_VAULT_V2);
      const book = env.ENCLAVE_ADDRESS_BOOK !== undefined ? env.ENCLAVE_ADDRESS_BOOK : DEFAULTS.ADDRESS_BOOK_ADDRESS;
      const a = book ? await bookEntry(book, "secretVaultV2") : null;
      return a || getAddress("0xE48699B8401564aaCe7A814AE4569b67a3F7eEF5");   // deployed 2026-10-14 (contracts/deployments/secret-vault-v2-base.json)
    },
    relayRead: (id) => secretsCall(loadKey(), id, null),
    relayClear: (id) => secretsCall(loadKey(), id, JSON.stringify({ clear: true })),
  });
}

// ---- per-deployment options envelope: the owner's config/waf EDIT path --------
// The envelope (create()'s configCid field: {"waf":{…},"config":{…}}) is
// MUTABLE via EnclaveDeployments.setConfig - one owner tx rewrites it, and a
// fleet advertising configEdit re-applies it to the LIVE app within ~a minute
// (waf swaps in place; a config change restarts the app on the new
// ENCLAVE_CONFIG - same lease, balance and endpoint). `set` PRESERVES the
// namespace you didn't pass, so editing the config never silently wipes the
// waf and vice versa; `clear config` falls the app back to the version's
// approval-covered config.
async function cmdConfig(rest) {
  const sub = rest.shift();
  const usage = "usage: enclave config show <id>\n"
              + "     | enclave config set <id> '<json>' | --file app-config.json  [--waf '<json>']\n"
              + "     | enclave config clear <id> [config|waf|all]      (default config: the app falls back to the version's config)";
  if (!["show", "get", "set", "clear"].includes(sub || "")) throw new Error(usage);
  const f = flags(rest, { val: ["--file", "--waf"] });
  if (!f._[0]) throw new Error(usage);
  // with a session: set/clear are deploy.setConfig on a STAGING deployment the vault holds (show needs no key);
  // one the owner's WALLET holds is production to a session, so it is refused before anything else
  const sess = await sessionForCommand();
  const account = sess ? null : loadKey();
  const id = await resolveId(f._[0], account ?? sessionAccount(sess));
  if (!isB32(id)) throw new Error("only on-chain deployments (bytes32 ids) carry an options envelope");
  const { rev, abi } = await depAbi();
  const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "get", [id]);
  if (!d || d.owner === "0x0000000000000000000000000000000000000000") throw new Error(`no deployment ${short(id)} on the ledger`);
  // the current envelope; a legacy/unparseable string reads as empty (setConfig
  // replaces it wholesale, which is also how such a string gets healed)
  const raw = String(d.configCid || "").trim();
  let cur = {};
  if (raw.startsWith("{")) { try { cur = JSON.parse(raw); } catch {} }
  if (!cur || Array.isArray(cur) || typeof cur !== "object") cur = {};

  if (sub === "show" || sub === "get") {
    // the effective ENCLAVE_CONFIG: the deployment's override, else the
    // version's approved config (read from its catalog record)
    let verCfg = null;
    const m = /^catalog:\/\/(0x[0-9a-fA-F]{64})\/(\d{1,9})$/.exec(d.appRef || "");
    if (m) { try { verCfg = ((await readVersions(m[1], Number(m[2]) + 1))[Number(m[2])] || {}).config || ""; } catch {} }
    if (opt.json) return jout({ id, envelope: raw, waf: cur.waf ?? null,
      config: "config" in cur ? cur.config : null, configCid: cur.configCid ?? null, versionConfig: verCfg });
    say(`deployment ${short(id)} options envelope (${Buffer.byteLength(raw)} bytes of ${rev >= 5 ? 4096 : 100})`);
    say(cur.waf ? `waf: ${JSON.stringify(cur.waf)}` : "waf: (none)");
    // a pinned override: the inline field beside it is only the routing manifest,
    // so printing it as "the config" would misreport what the app receives
    if (cur.configCid) {
      say(`config: pinned at ipfs://${cur.configCid}   <- per-deployment override: this deployment's ENCLAVE_CONFIG (too large for the envelope)`);
      say(`        routing manifest on-chain: ${"config" in cur ? JSON.stringify(cur.config) : "(none)"}`);
    }
    else if ("config" in cur) say(`config: ${JSON.stringify(cur.config)}   <- per-deployment override: this deployment's ENCLAVE_CONFIG`);
    else if (verCfg) say(`config: the version's applies (no override): ${verCfg.length > 200 ? verCfg.slice(0, 197) + "…" : verCfg}`);
    else say(`config: (none - ${m ? "this version publishes no config and" : ""} no override is set)`);
    return;
  }

  if (sess) {
    await sessionHolder(sess, d, id, "deploy.setConfig");
    await sessionRequire(sess, "deploy.setConfig");
  } else if (d.owner.toLowerCase() !== account.address.toLowerCase())
    throw new Error(`${short(id)} is owned by ${d.owner}, not this key`);
  const next = { ...cur };
  if (sub === "set") {
    const cfgArg = f._[1] !== undefined ? f._[1] : (f.file !== undefined ? fs.readFileSync(f.file, "utf8") : undefined);
    if (cfgArg === undefined && f.waf === undefined)
      throw new Error("nothing to set: pass the app-config JSON (positional or --file) and/or --waf '<json>'\n" + usage);
    if (cfgArg !== undefined) {
      let c; try { c = JSON.parse(cfgArg); } catch (e) { throw new Error("the app config must be a JSON object, e.g. '{\"api_key\":\"…\"}': " + e.message); }
      if (!c || Array.isArray(c) || typeof c !== "object")
        throw new Error("the app config must be a JSON object - it replaces the version's config as this deployment's ENCLAVE_CONFIG ('{}' = explicitly empty)");
      if ("_media" in c) throw new Error("config._media is reserved for the catalog's store media and never reaches an app - remove it");
      next.config = c;
      // A replacement must not retain the old pinned body: the runner gives
      // that CID precedence over inline config, and a large edit must re-pin.
      delete next.configCid;
    }
    if (f.waf !== undefined) {
      let w; try { w = JSON.parse(f.waf); } catch (e) { throw new Error("--waf must be a JSON object, e.g. --waf '{\"rps\":10}': " + e.message); }
      if (!w || Array.isArray(w) || typeof w !== "object") throw new Error("--waf must be a JSON object ('{}' removes the waf)");
      if (Object.keys(w).length) next.waf = w; else delete next.waf;
    }
  } else {                                                   // clear
    const what = (f._[1] || "config").toLowerCase();
    if (!["config", "waf", "all"].includes(what)) throw new Error(usage);
    if (what !== "waf") { delete next.config; delete next.configCid; }
    if (what !== "config") delete next.waf;
  }
  let envelope = Object.keys(next).length ? JSON.stringify(next) : "";
  const cap = rev >= 5 ? 4096 : 100;
  if (envelope === raw) return say("nothing to change - the envelope already reads exactly that");
  // Too big to sit in the ledger's one options field: pin the body and keep the
  // reference plus the routing manifest on-chain (DEP_MANIFEST_KEYS in
  // supervisor.js — `volumes` is what a runner reads off a DEPLOYMENT's config
  // to place it). Same projection rule as a version's split: the routing keys
  // stay in the PINNED document too, so the delivered ENCLAVE_CONFIG is still
  // the whole thing. Pin BEFORE signing — an envelope naming a CID nobody
  // pinned claims fine and then fails every launch on the fetch.
  if (Buffer.byteLength(envelope) > cap && rev >= 5 && next.config && !next.configCid) {
    const body = JSON.stringify(next.config);
    if (Buffer.byteLength(body) > CONFIG_MAX_BYTES)
      throw new Error(`the config is ${Buffer.byteLength(body)} bytes; enclaves refuse anything over ${CONFIG_MAX_BYTES} at launch`);
    let av = null; try { av = await api("GET", "/availability"); } catch {}
    if (av && av.aggregate && av.configCidOverride !== true)
      throw new Error("this config needs to be pinned off-chain to fit the ledger's options field, but the live fleet doesn't support pinned overrides yet "
                    + "(availability.configCidOverride is not true) - the deployment would be unclaimable at its next claim. Trim the config, or wait for the fleet to update");
    const manifest = {};
    if (next.config.volumes !== undefined) manifest.volumes = next.config.volumes;
    say(`config is ${Buffer.byteLength(body)} bytes - too big for the envelope; pinning it and keeping the reference on-chain`);
    const cid = await pinJson(sess ?? account, Buffer.from(body, "utf8"));
    say(`  pinned ${cid}`);
    next.configCid = cid;
    if (Object.keys(manifest).length) next.config = manifest; else delete next.config;
    envelope = JSON.stringify(next);
    // content addressing makes a re-pin of unchanged bytes reproduce the same
    // CID, so this catches "set the same large config twice" after the pin
    if (envelope === raw) return say("nothing to change - the envelope already reads exactly that");
  }
  if (Buffer.byteLength(envelope) > cap)
    throw new Error(rev >= 5
      ? `the options envelope is ${Buffer.byteLength(envelope)} bytes; the ledger caps it at 4096 - `
        + `even with the config pinned off-chain, the routing manifest and protection settings must fit. Trim the volumes list`
      : `this ledger (deploymentsSchema ${rev}) caps the envelope at 100 bytes (got ${Buffer.byteLength(envelope)}) - config overrides need the rev-5 ledger`);
  // the deploy --config fail-closed rule: a `config` namespace no runner
  // accepts makes the deployment unclaimable at its NEXT claim; configEdit
  // only decides whether a LIVE app applies the edit in place or later
  let av = null; try { av = await api("GET", "/availability"); } catch {}
  if ("config" in next && !("config" in cur)) {
    if (av && av.aggregate && av.configOverride !== true)
      throw new Error("the live fleet doesn't support per-deployment config overrides yet (availability.configOverride is not true) - the deployment would be unclaimable at its next relaunch");
    if (!av || !av.aggregate) say("! couldn't read fleet availability to confirm config-override support; if a runner predates it, the next claim would refuse this deployment");
  }
  const leased = Number(d.leaseUntil) * 1000 > Date.now();
  const liveEdit = !!(av && av.aggregate && av.configEdit === true);
  const when = leased
    ? (liveEdit ? "the runner re-applies it in place within ~a minute; a config change restarts the app, waf changes apply live"
                : "the live fleet predates in-place envelope edits - it applies at the app's next relaunch or claim")
    : "it applies when the deployment is next claimed";
  if (!(await confirm(`rewrite the options envelope of ${short(id)}? (${envelope ? Buffer.byteLength(envelope) + " bytes" : "empty"}; ${when})`))) return say("aborted");
  if (sess) await sessionCall(sess, "deploy.setConfig", { id, configCid: envelope });
  else await sendTx(account, { address: DEFAULTS.DEPLOYMENTS_ADDRESS, abi, functionName: "setConfig", args: [id, envelope] });
  if (opt.json) return jout({ id, envelope, applies: leased ? (liveEdit ? "in_place" : "next_relaunch") : "next_claim" });
  say(`envelope updated - ${when}; watch: enclave status ${short(id)}`);
}

// ---- sessions: act through an owner-approved session key (docs/design/sessions.md §8.2) ----
// A session is a P-256 key that the owner's wallet approved ONCE, under a policy
// the owner's SessionVault enforces on-chain: which actions, which apps, which
// environments, how much money, until when. The key signs every operation and
// the sessions relayer submits it, reimbursed out of the session budget by a fee
// the key itself signed. The key lives in SESSION_DIR (one 0600 file each) or,
// for agents that keep secrets in the environment, in ENCLAVE_SESSION.
//
// With a session available, publish / deploy / fund / upgrade / resize /
// config set|clear / stop / resume / rate-cap / refund act THROUGH it. A refusal
// (budget, policy, expiry) is reported with its code and the next step, and the
// command stops: it never falls back to the wallet key. --wallet (or --unsigned /
// --signer, which name a wallet) is the explicit way back to the wallet paths.
// They act on the deployments the session's vault holds and, once the owner has
// let the vault act for its wallet (`enclave session delegate`), on the ones the
// owner's WALLET holds - as production: fund, resize, rate-cap (lower only),
// stop, resume, refund (to the wallet); never upgrade or config (sessionHolder).
const SESSION_POLL_MS = 3000;
let _sessionsSdk = null;
async function sessionsSdk() {
  if (_sessionsSdk) return _sessionsSdk;
  try { _sessionsSdk = await import("../sdk/sessions/dist/node.mjs"); }
  catch (e) { throw new Error(`this build of the CLI can't load the sessions SDK (${e.message}); install from a full checkout (cli/install.sh), or pass --wallet`); }
  return _sessionsSdk;
}
const sessionEnvString = () => (env.ENCLAVE_SESSION || "").trim();
// cheap, SDK-free: is there a session this command should act through?
function sessionConfigured() {
  if (sessionEnvString()) return true;
  try { return fs.readFileSync(path.join(SESSION_DIR, "active"), "utf8").trim() !== ""; } catch { return false; }
}
const walletChosen = () => opt.wallet || opt.unsigned || !!opt.signer;
async function sessionStore() { return new (await sessionsSdk()).FileStore(SESSION_DIR); }
const explicitRpc = () => !!(opt.rpc || env.ENCLAVE_RPC);
const sessionAccount = (s) => ({ address: s.vault });
const sessionNotHeld = (s, owner) => `this session's vault ${s.vault}${owner ? ` nor its owner's wallet ${owner}` : ""} `
  + `(a session acts only on deployments its vault holds${owner ? ", or, once the owner allows it, the ones the owner's wallet holds" : ""}; `
  + `use --wallet for your own)`;

// The wallet that owns the session's vault: the vault's own word (immutable), else what the record says.
async function sessionOwner(s) {
  if (s.ownerWallet) return s.ownerWallet;
  try { s.ownerWallet = getAddress(await read(s.vault, s.S.sessionVaultAbi, "owner")); }
  catch (e) { if (!s.owner) throw e; s.ownerWallet = getAddress(s.owner); }
  return s.ownerWallet;
}
// Records the owner's WALLET holds (ledger rev 15d + SessionVault v2): once the owner has let its vault act
// for it (`enclave session delegate`, one wallet transaction), a session reaches them too, and to a session
// they are always PRODUCTION: how they run (fund, resize, lower the cap, stop/resume, refund to the wallet),
// never what they run (setAppRef/setConfig stay the wallet's). Returns "vault" or "wallet", or throws the
// refusal with its next step BEFORE any prompt; the vault re-checks all of it on-chain.
const SESSION_PROD_ONLY = { "deploy.setAppRef": "version", "deploy.setConfig": "config" };
async function sessionHolder(s, d, id, action) {
  const holder = String(d.owner).toLowerCase();
  if (holder === s.vault.toLowerCase()) return "vault";
  const owner = await sessionOwner(s);
  if (holder !== owner.toLowerCase()) throw new Error(`${short(id)} is owned by ${d.owner}, not ${sessionNotHeld(s, owner)}`);
  if (SESSION_PROD_ONLY[action])
    throw new Error(`${short(id)} is held by the owner's wallet ${owner}, so to a session it is a PRODUCTION app: a session can't change `
      + `what a production app runs (its ${SESSION_PROD_ONLY[action]}); the owner does it with --wallet`);
  const st = s.state ?? await sessionRequire(s, action);
  if ((Number(st.envs) & s.S.ENVIRONMENTS.prod) === 0)
    throw sessionRefusal(s, action, "env", `${short(id)} is held by the owner's wallet ${owner}, which makes it production, and this session acts only in staging`);
  let dg = null;
  try { dg = await s.S.delegationStatus(pub(), DEFAULTS.DEPLOYMENTS_ADDRESS, owner, s.vault); }
  catch (e) { trace(`delegation read: ${String(e?.shortMessage || e?.message || e).split("\n")[0]} (the vault decides)`); }
  if (dg && !dg.supported)
    throw new Error(`${short(id)} is held by the owner's wallet ${owner}, and the ledger ${DEFAULTS.DEPLOYMENTS_ADDRESS}`
      + `${BOOK.why ? ` (a baked address: the address book was not read, ${BOOK.why})` : ""} predates delegation `
      + `(no setDelegate): no session reaches the deployments a wallet holds there; the owner acts with --wallet`);
  if (dg && !dg.granted)
    throw sessionRefusal(s, action, "delegation", `${short(id)} is held by the owner's wallet ${owner}, and the owner has not let this `
      + `session's vault ${s.vault} act on the deployments the wallet holds`);
  return "wallet";
}
// A session funding a record the WALLET holds: anyone can transfer a record INTO the wallet, so its publisher
// fee was never vetted by this grant. A paid one needs the catalog's own fee for its version, its app NAMED in
// the grant ("*" never covers it) and a fee within the grant's hourly ceiling (what the vault enforces).
async function sessionWalletFund(s, d, id) {
  const { rev, abi } = await depAbi();
  const [feeTo, fee6] = rev >= 4 ? await read(DEFAULTS.DEPLOYMENTS_ADDRESS, abi, "feeOf", [id]) : [null, 0n];
  if (!(fee6 > 0n)) return;
  const m = /^catalog:\/\/(0x[0-9a-fA-F]{64})\/(\d{1,9})$/.exec(d.appRef || "");
  const app = m && (await catalogApps()).find((a) => a.appId.toLowerCase() === m[1].toLowerCase());
  if (!app || app.publisher.toLowerCase() !== String(feeTo).toLowerCase() || (await versionFee6(app.appId, Number(m[2]))) !== fee6)
    throw new Error(`${short(id)} (held by the owner's wallet) carries a ${usd6(fee6 * 3600n)}/h publisher fee that is not its catalog `
      + `version's own: a session never funds it; the owner funds it with --wallet`);
  const st = s.state ?? await sessionRequire(s, "deploy.fund");
  if (!st.apps.some((a) => a.toLowerCase() === app.appId.toLowerCase()))
    throw sessionRefusal(s, "deploy.fund", "app", `"${app.slug}" charges a ${usd6(fee6 * 3600n)}/h publisher fee and this session's grant `
      + `does not name it ("*" never covers a paid app the wallet holds)`, { slug: app.slug });
  if (fee6 * 3600n > BigInt(st.maxAppFeeHour6))
    throw sessionRefusal(s, "deploy.fund", "app", `"${app.slug}" charges a ${usd6(fee6 * 3600n)}/h publisher fee, above this session's `
      + `${usd6(st.maxAppFeeHour6)}/h ceiling`, { slug: app.slug });
}
// the environment a vault-held record is adopted in (1 staging, 2 prod, 0 = unadopted: the vault refuses it)
const sessionHeldEnv = async (s, id) => Number((await read(s.vault, s.S.sessionVaultAbi, "held", [id]))[0]);

// A stored record by its full id, or a unique prefix of its id or key hash.
// pending: true = only keys still waiting for a signature, false = only open ones.
async function findSessionRecord(store, q, { pending } = {}) {
  const all = (await store.list()).filter((r) => pending === undefined || !r.handle === pending);
  const lc = String(q).toLowerCase();
  let hits = all.filter((r) => r.id.toLowerCase() === lc);
  if (!hits.length && lc.length >= 6)
    hits = all.filter((r) => r.id.toLowerCase().startsWith(lc)
                          || (lc.startsWith("0x") && lc.length >= 10 && String(r.keyHash).toLowerCase().startsWith(lc)));
  if (hits.length === 1) return store.load(hits[0].id);    // load() re-checks the 0600 mode
  const kind = pending === true ? "pending " : pending === false ? "open " : "";
  throw new Error(hits.length ? `"${q}" matches ${hits.length} sessions; give more of the id (enclave session list)`
                              : `no ${kind}session "${q}" in ${store.dir} (enclave session list)`);
}

// The session to act through: ENCLAVE_SESSION first (an explicit choice), else
// the named or active key in SESSION_DIR. -> { kind: "session", S, rec, session, … }
async function loadSession(idArg) {
  const S = await sessionsSdk();
  let rec = null, from = "file", store = null;
  const fromEnv = sessionEnvString();
  if (fromEnv) {
    const r = S.importSessionString(fromEnv);
    if (!idArg || r.id.toLowerCase().startsWith(String(idArg).toLowerCase())) { rec = r; from = "env"; }
  }
  if (!rec) {
    store = await sessionStore();
    const id = idArg ?? store.activeId();
    if (!id) throw new Error("no active session: open one (enclave session new), pick a stored one (enclave session use <sid>), or set ENCLAVE_SESSION");
    try { rec = await findSessionRecord(store, id); }
    catch (e) {
      if (idArg) throw e;
      throw new Error(`the active session ${short(id)} has no key file in ${store.dir}: pick another (enclave session use <sid>), `
        + `or pass --wallet to use your wallet key (${e.message})`);
    }
  }
  if (!rec.handle) throw new Error(`session ${rec.id} is still waiting for the owner's signature: enclave session resume-wait ${rec.id}`);
  // the chain is read where the user points the CLI (--rpc/ENCLAVE_RPC), else where the session was opened
  const rpc = explicitRpc() ? RPCS[0] : rec.handle.rpc;
  const session = await S.sessionFromRecord({ ...rec, handle: { ...rec.handle, rpc } });
  return { kind: "session", S, rec, from, store, session, sid: rec.handle.sid, vault: rec.handle.vault,
           owner: rec.handle.owner, label: rec.label, chainId: rec.chainId };
}

// For the session-aware commands: the session to act through, or null for the wallet path.
async function sessionForCommand() {
  if (walletChosen() || !sessionConfigured()) return null;
  const s = await loadSession();
  if (CONTRACT_PINS) {
    const factory = await assertPinnedSessionFactory();
    const actual = await read(s.vault, [{ type: "function", name: "factory", stateMutability: "view",
      inputs: [], outputs: [{ type: "address" }] }], "factory");
    if (s.chainId !== DEFAULTS.chainId || getAddress(actual) !== factory)
      throw new Error("active session is not on the pinned chain and session factory; explicitly migrate or use --wallet");
  }
  // the ledger and catalog reads go through this CLI's RPCs: they must be on the session's chain
  if (s.chainId !== DEFAULTS.chainId && !explicitRpc())
    throw new Error(`the active session lives on chain ${s.chainId}, but this CLI reads Base (${DEFAULTS.chainId}); point it at that chain `
      + `with --rpc/ENCLAVE_RPC (and ENCLAVE_ADDRESS_BOOK), or pass --wallet to use your wallet key`);
  stderr.write(`session: acting through ${short(s.sid)}${s.label ? ` "${s.label}"` : ""} (vault ${s.vault}); --wallet uses your wallet key instead\n`);
  return s;
}

// The refusal, its code, and what to do next. Never a silent wallet fallback.
function sessionHint(s, action, e, ctx = {}) {
  const S = s.S, d = e.detail || {};
  let next, message = e.message;
  switch (e.code) {
    case "budget": {
      const gap = typeof d.need === "bigint" && typeof d.have === "bigint" && d.need > d.have ? d.need - d.have : 1_000_000n;
      if (typeof d.need === "bigint" && typeof d.have === "bigint")
        message = `this needs ${S.fmtUsd(d.need)} (amount + relay fee) and the session has ${S.fmtUsd(d.have)} left`;
      next = `the owner can add budget: enclave session top-up-link --amount ${Math.max(1, Math.ceil(Number(gap) / 1e6))} (prints the link to send them)`;
      break;
    }
    case "period":
      if (typeof d.need === "bigint" && typeof d.left === "bigint")
        message = `this needs ${S.fmtUsd(d.need)} and ${S.fmtUsd(d.left)} of this period's limit is left`;
      next = `this period's spending limit is used up${typeof d.left === "bigint" ? ` (${S.fmtUsd(d.left)} left)` : ""}: wait for the next period `
           + `(enclave session status shows when it resets), or ask the owner for a session with a higher limit`;
      break;
    case "rate": next = "this session used its operations for this period: wait for the next one (enclave session status shows when)"; break;
    case "expired": next = "this session has expired: open a new session (enclave session new --preset <preset> --app <slug>)"; break;
    case "not_live": next = "this session has ended (signed out, or revoked by the owner): open a new session (enclave session new …)"; break;
    case "not_allowed": next = `ask the owner for a session with ${action} (enclave session new prints the link to send them), or have the owner run this with --wallet`; break;
    case "env":
      next = `ask the owner for a session with ${action} in that environment. A session acts on deployments its vault holds, in the `
           + `environments it was granted, and (once the owner allows it) on the ones the owner's wallet holds, which are always production; `
           + `what a PRODUCTION deployment runs changes only through the owner (--wallet, or Promote on enclave.host)`;
      break;
    case "app": next = `ask the owner for a session that names ${ctx.slug ? `this app (--app ${ctx.slug})` : "this app"}; publishing needs the app named, "*" never covers it`; break;
    case "fee": next = "the relay's fee is above this session's per-operation cap right now; retry shortly"; break;
    case "price":
      next = ({ LeaseUnsettled: "a host still holds this deployment's lease: stop it, wait for the host to release it, then retry",
                FundRateTooLow: "this deployment's current price wouldn't buy runtime from a top-up: wait for its lease to end (or stop and resume it), then retry" })[d.error]
           || "that price is outside what this session may pay or set (its rate-cap ceiling, or a production cap it may only lower); the owner acts with --wallet";
      break;
    case "delegation":
      next = "this deployment is held by the owner's WALLET: sessions reach it only once the owner lets them, with one wallet "
           + "transaction: the owner runs `enclave session delegate` (or enclave.host → Sessions → Apps your wallet owns → Grant); "
           + "until then the owner acts with --wallet";
      break;
    case "nonce": next = "another operation of this session landed first; retry"; break;
    case "relay": next = "the sessions relay did not complete it; retry, and check enclave session status"; break;
  }
  return `session ${short(s.sid)} refused ${action}: ${e.code}: ${message}` + (next ? `\nnext: ${next}` : "");
}
const sessionRefusal = (s, action, code, message, ctx) => new Error(sessionHint(s, action, new s.S.SessionError(code, message), ctx));

// Fail BEFORE any preflight or prompt when the session can't do this at all
// (the vault re-checks everything; this only makes the refusal early and clear).
async function sessionRequire(s, ...actions) {
  const st = await s.session.status();
  s.state = st;
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (!st.live) {
    const expired = Number(st.state) === 1 && st.expiresAt < now;
    throw sessionRefusal(s, actions[0], expired ? "expired" : "not_live", expired ? "this session has expired" : "this session has ended");
  }
  for (const a of actions)
    if (((st.actions >> BigInt(s.S.ACTIONS[a])) & 1n) === 0n) throw sessionRefusal(s, a, "not_allowed", `this session may not ${a}`);
  return st;
}
// on-chain app ids the session names (a slug is the VAULT's app of that slug); "*" covers all but publishing
function sessionRequireApp(s, appId, action, slug) {
  const st = s.state;
  if (!st) return;
  if (action !== "app.publish" && st.anyApp) return;
  if (st.apps.some((a) => a.toLowerCase() === String(appId).toLowerCase())) return;
  throw sessionRefusal(s, action, "app", `${slug ? `"${slug}" (${short(appId)})` : short(appId)} is not one of this session's apps`, { slug });
}
// a bare slug the session names means the VAULT's app of that slug (several publishers can share a slug)
function sessionAppInput(s, input) {
  const m = /^([a-z0-9][a-z0-9-]*)(:.+)?$/.exec(input);
  const named = (s.rec.grant?.apps || []).filter((a) => a !== "*");
  return m && named.includes(m[1]) ? `${s.vault}/${input}` : input;
}

async function sessionCall(s, action, args) {
  trace(`session ${short(s.sid)} ${action} ${fmtArg(args)}`);
  let out;
  try { out = await s.session.call(action, args); }
  catch (e) { if (e instanceof s.S.SessionError) throw new Error(sessionHint(s, action, e)); throw e; }
  trace(`session op mined ${out.txHash} (relay fee ${s.S.fmtUsd(out.fee)})`);
  return out;
}
// the receipt of a session operation, for callers that read its logs/block like a sendTx receipt
async function sessionTx(s, action, args) {
  const out = await sessionCall(s, action, args);
  const rcpt = await pub().getTransactionReceipt({ hash: out.txHash });
  return Object.assign(rcpt, { sessionResult: out.result, sessionFee: out.fee });
}
// USD -> USDC 6dp, in whole cents like fundUsdc (sub-cent amounts are refused, not rounded away)
function sessionUsd6(usd, flag) {
  const cents = usd * 100;
  if (usd > 0 && usd < 0.01) throw new Error(`${flag}: the minimum is $0.01 (got $${usd}); amounts are whole cents`);
  if (Math.abs(cents - Math.round(cents)) > 1e-9) throw new Error(`${flag}: $${usd} isn't a whole number of cents`);
  return BigInt(Math.round(cents)) * 10000n;
}

// The token request is signed by the session key over the exact body bytes sent.
async function sessionUploadToken(s, hash, expiry) {
  const p = "/v1/apps/upload-token";
  const body = JSON.stringify({ hash, expiry });
  const authorization = await s.session.apiAuthorization("POST", API_BASE + p, body);
  trace(`curl -sX POST '${API_BASE}${p}' -H 'authorization: EnclaveSession …' -d '${body}'`);
  const r = await fetch(API_BASE + p, { method: "POST", headers: { "content-type": "application/json", authorization }, body });
  const raw = await r.text();
  let j = {}; try { j = JSON.parse(raw); } catch {}
  if (!r.ok) {
    if (j.error === "not_allowed") throw sessionRefusal(s, "api.upload", "not_allowed", j.message || "this session lacks api.upload");
    if (j.error === "session_ended") throw sessionRefusal(s, "api.upload", "not_live", j.message || "this session has ended");
    throw new Error(`POST ${p} -> ${r.status}: ${j.message || j.error || raw.slice(0, 300)}`);
  }
  return j;
}

async function sessionDeployPreflight(s, f) {
  if (f["fund-eth"] !== undefined) throw new Error("a session funds in USDC out of its budget: use --fund <usd> (or --wallet to fund with ETH)");
  if (f.secrets !== undefined || f["secrets-file"] !== undefined)
    throw new Error("secrets are the owner's alone (a session can neither set nor read them): deploy without --secrets, "
      + "then the owner runs `enclave secrets set <id> KEY=VALUE --wallet`");
  const envName = f.env ?? "staging";
  if (!(envName in s.S.ENVIRONMENTS)) throw new Error(`--env takes ${Object.keys(s.S.ENVIRONMENTS).join(" or ")}, got "${envName}"`);
  f.env = envName;
  const st = await sessionRequire(s, "deploy.create");
  if ((st.envs & s.S.ENVIRONMENTS[envName]) === 0)
    throw sessionRefusal(s, "deploy.create", "env", `this session may not create ${envName} deployments`);
}

// create + fund in ONE session operation (the vault funds from the session budget)
async function deployViaSession(s, { f, ref, gpuMilli, cpuMilli, appPort, portsCsv, isPublic, envelope, maxRate6, fundUsd, rate }) {
  const fund6 = sessionUsd6(fundUsd, "--fund");
  const left = s.state ? s.S.fmtUsd(s.state.balance6) : "?";
  if (!(await confirm(`deploy ${f._[0]} to ${f.env} through session ${short(s.sid)}: gpu ${gpuMilli / 10}% cpu ${cpuMilli / 10}% at `
                    + `${usd6(rate * 3600n)}/h, fund ${usd6(fund6)} out of the session budget (${left} left) ≈ ${dur(Number(fund6) / Number(rate))}?`)))
    return say("aborted");
  const out = await sessionCall(s, "deploy.create", { appRef: ref, gpuMilli, cpuMilli, appPort, ports: portsCsv, isPublic,
    configCid: envelope, maxRate6, env: f.env, fund6 });
  const id = "0x" + out.result.slice(2, 66);
  say(`created ${id} (${f.env}, held by vault ${s.vault}; tx ${out.txHash})`);
  say(`funded ${usd6(fund6)} out of the session budget (relay fee ${s.S.fmtUsd(out.fee)})`);
  try {
    const h = await api("POST", "/v1/claim-hint", { body: { id } });
    if (h.accepted === false && h.reason) say(`claim-hint declined: ${h.reason} (the sweep may still claim it)`);
  } catch {}
  if (f["no-wait"]) return say(opt.json ? JSON.stringify({ id, url: appUrl(id) }) : `not waiting; check: enclave status ${id}`);
  say("waiting for an enclave to claim…");
  let claimed = null;
  for (let i = 0; i < 90 && !claimed; i++) {
    await sleep(2000);
    const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "get", [id]).catch(() => null);
    if (d && !/^0x0+$/.test(d.runner) && Number(d.leaseUntil) * 1000 > Date.now()) claimed = d;
  }
  if (!claimed) throw new Error(`no enclave claimed it yet (still queued; funded work is retried every sweep); watch: enclave status ${id}`);
  say(`claimed by ${short(claimed.runner)} (operator ${claimed.runnerOperator})`);
  // the tokenless record read: owner-only reads need the owner's login, which a session does not mint yet
  const done = { running: 1, failed: 1, terminated: 1, expired: 1 };
  let rec = null;
  for (let i = 0; i < 180; i++) {
    rec = await api("GET", `/v1/deployments/${id}`, { ok404: true }).catch(() => null);
    if (rec && done[rec.status]) break;
    await sleep(2500);
  }
  if (!rec || rec.status !== "running") throw new Error(`deployment is "${rec?.status || "unknown"}"; logs: enclave logs ${id} --wallet (owner)`);
  if (opt.json) return jout({ id, status: rec.status, url: appUrl(id) });
  say(`running at ${appUrl(id)}`);
  say(`verify before sending data: enclave attest ${id}`);
}

async function stopViaSession(s, id) {
  if (!isB32(id)) throw new Error("only on-chain deployments (bytes32 ids) can be stopped through a session");
  const d = await read(DEFAULTS.DEPLOYMENTS_ADDRESS, (await depAbi()).abi, "get", [id]);
  if (!d || d.owner === "0x0000000000000000000000000000000000000000") throw new Error(`no deployment ${short(id)} on the ledger`);
  await sessionHolder(s, d, id, "deploy.setActive");
  if (!d.active) return opt.json ? jout({ id, status: "stopped", note: "already inactive on the ledger" }) : say("already inactive on the ledger");
  const rcpt = await sessionTx(s, "deploy.setActive", { id, active: false });
  // the immediate teardown (DELETE) is an owner-login API call a session can't make yet; the runner's ledger pass ends it
  if (opt.json) return jout({ id, status: "stopped", setActive: { tx: rcpt.transactionHash, block: rcpt.blockNumber },
                              note: "the runner ends the app on its next ledger pass" });
  say(`stopped on-chain: setActive(false) tx ${rcpt.transactionHash} confirmed in block ${rcpt.blockNumber} - the deployment is off the queue; `
    + `its runner ends the app on its next ledger pass`);
}

// ---- `enclave session …` -----------------------------------------------------------
const SESSION_USAGE = `usage: enclave session new --preset <preset> [--app <slug>[,<slug>…]] [--budget <usd>] [--days <n>] [--label <text>]
                           [--owner 0x…] [--env] [--no-wait] [--wait-minutes 30]
     | enclave session resume-wait <id> [--env] [--wait-minutes 30]
     | enclave session status [<sid>]
     | enclave session list
     | enclave session use <sid>
     | enclave session terminate [<sid>]
     | enclave session top-up-link --amount <usd> [<sid>]
     | enclave session delegate [--revoke] [--status [--owner 0x…]]   (the OWNER, with the wallet)`;

async function cmdSession(rest) {
  const sub = rest.shift();
  if (sub === "new") return sessionNew(rest);
  if (sub === "resume-wait") return sessionResumeWait(rest);
  if (sub === "status") return sessionStatus(rest);
  if (sub === "list" || sub === "ls") return sessionList(rest);
  if (sub === "use") return sessionUse(rest);
  if (sub === "terminate" || sub === "end") return sessionTerminate(rest);
  if (sub === "top-up-link") return sessionTopUpLink(rest);
  if (sub === "delegate") return sessionDelegate(rest);
  throw new Error(SESSION_USAGE);
}

async function sessionNew(rest) {
  const f = flags(rest, { val: ["--preset", "--app", "--budget", "--days", "--label", "--owner", "--wait-minutes"],
                          bool: ["--env", "--no-wait"] });
  if (f._.length) throw new Error(`unexpected argument "${f._[0]}"\n${SESSION_USAGE}`);
  const S = await sessionsSdk();
  if (!f.preset) throw new Error(`name a preset: --preset ${Object.keys(S.PRESETS).join(" | ")}`);
  if (!S.PRESETS[f.preset]) throw new Error(`unknown preset "${f.preset}" (${Object.keys(S.PRESETS).join(", ")})`);
  if (f.owner !== undefined && !/^0x[0-9a-fA-F]{40}$/.test(f.owner)) throw new Error(`--owner is not a 0x…40-hex address: ${f.owner}`);
  const policy = {};
  if (f.app !== undefined) policy.apps = String(f.app).split(",").map((a) => a.trim()).filter(Boolean);
  if (f.budget !== undefined) policy.budget = BigInt(Math.round(numFlag(f.budget, "--budget") * 1e6));
  if (f.days !== undefined) {
    const days = numFlag(f.days, "--days");
    if (!(days > 0)) throw new Error("--days must be above 0");
    policy.expiresIn = Math.round(days * 86400);
  }
  const label = f.label ?? "enclave CLI";
  // the owner's page and the relay must agree on the chain: ask the relay which one it serves
  const cfg = await new S.RelayClient(API_BASE).config();
  const site = String(cfg.site || "https://enclave.host").replace(/\/+$/, "");
  // validate the policy BEFORE a key exists, so a bad flag leaves nothing behind
  S.buildGrant({ preset: f.preset, label, sessionKey: S.ZERO_HASH, policy });
  const store = await sessionStore();
  const { signer, record } = await S.newSessionKey(store, { relay: API_BASE, chainId: cfg.chainId, label, extractable: true });
  const grant = S.buildGrant({ preset: f.preset, label, sessionKey: signer.keyHash, policy });
  const pending = { ...record, grant, ...(f.owner ? { wantOwner: getAddress(f.owner) } : {}), ...(cfg.rpc ? { rpc: cfg.rpc } : {}) };
  await store.save(pending);
  const link = S.grantLink(site, { v: 1, chainId: cfg.chainId, relay: API_BASE, x: record.x, y: record.y, grant,
                                   ...(f.owner ? { owner: getAddress(f.owner) } : {}) });
  const code = S.checkCode(signer.keyHash);
  // --env/--json: stdout carries only the machine output, so the human text goes to stderr
  const info = (f.env || opt.json) ? (t) => stderr.write(t + "\n") : say;
  const { lines, warnings } = S.describeGrant(grant);
  info(`session request "${label}" (preset ${f.preset}, chain ${cfg.chainId})`);
  for (const l of lines) info(`  ${l}`);
  for (const w of warnings) info(`  ! ${w}`);
  info("");
  info(`check code: ${code}`);
  info("");
  info(`The OWNER opens this link and signs with their wallet${f.owner ? ` (${getAddress(f.owner)} only)` : ""}:`);
  info(`  ${link}`);
  info("");
  info(`Before signing, the owner checks that the page shows check code ${code}, and on a hardware wallet that the`);
  info(`first 8 hex characters of "sessionKey" read ${signer.keyHash.slice(2, 10)} (0x${signer.keyHash.slice(2, 10)}…).`);
  if (opt.json && f["no-wait"]) jout({ pending: pending.id, keyHash: signer.keyHash, checkCode: code, link, summary: lines, warnings });
  if (f["no-wait"]) {
    info(`not waiting. Once the owner has signed: enclave session resume-wait ${pending.id}${f.env ? " --env" : ""}`);
    return;
  }
  return sessionWait(S, store, pending, f);
}

async function sessionResumeWait(rest) {
  const f = flags(rest, { val: ["--wait-minutes", "--owner"], bool: ["--env"] });
  if (!f._[0]) throw new Error("usage: enclave session resume-wait <id> [--env]   (the pending id `enclave session new` printed; see enclave session list)");
  if (f.owner !== undefined && !/^0x[0-9a-fA-F]{40}$/.test(f.owner)) throw new Error(`--owner is not a 0x…40-hex address: ${f.owner}`);
  const S = await sessionsSdk();
  const store = await sessionStore();
  const rec = await findSessionRecord(store, f._[0], { pending: true });
  if (!rec.grant) throw new Error(`${rec.id} carries no grant (not made by \`enclave session new\`); start again with enclave session new`);
  if (f.owner) rec.wantOwner = getAddress(f.owner);
  return sessionWait(S, store, rec, f);
}

// Poll the relay's index for a session opened with THIS key, then verify it on-chain before storing it.
async function sessionWait(S, store, rec, f) {
  const info = (f.env || opt.json) ? (t) => stderr.write(t + "\n") : say;
  const minutes = f["wait-minutes"] !== undefined ? numFlag(f["wait-minutes"], "--wait-minutes") : 30;
  const deadline = Date.now() + minutes * 60_000;
  const relay = new S.RelayClient(rec.relay);
  const rpc = explicitRpc() ? RPCS[0] : rec.rpc;
  const pc = S.chainClient(rec.chainId, rpc);
  const ignored = new Set();
  let lastErr = null;
  info(`waiting for the owner's signature (checking every ${SESSION_POLL_MS / 1000}s for up to ${minutes} min; ctrl-c is safe: `
     + `enclave session resume-wait ${rec.id}${f.env ? " --env" : ""})`);
  for (;;) {
    const found = [];
    try {
      const { sessions = [] } = await relay.request("GET", `/by-key/${rec.keyHash}`);
      for (const c of sessions) {
        if (c.ended || ignored.has(c.sid)) continue;
        // the grant THIS key asked for, opened at that vault (sid commits to vault, key and grant nonce)
        if (String(c.sid).toLowerCase() !== S.sessionIdOf(c.vault, rec.grant.sessionKey, rec.grant.grantNonce).toLowerCase()) continue;
        const st = await S.readSession(pc, c.vault, c.sid);
        if (String(st.keyHash).toLowerCase() !== rec.keyHash.toLowerCase() || !st.live) continue;
        // the owner as the vault itself says, never the relay's word
        const owner = getAddress(await pc.readContract({ address: c.vault, abi: S.sessionVaultAbi, functionName: "owner" }));
        if (rec.wantOwner && owner !== getAddress(rec.wantOwner)) {
          ignored.add(c.sid);
          info(`! ignoring a session for this key opened by ${owner}, not ${rec.wantOwner}`);
          continue;
        }
        found.push({ sid: c.sid, vault: getAddress(c.vault), owner, st });
      }
      lastErr = null;
    } catch (e) {
      // a relay or RPC hiccup is not an answer: keep polling, say why only if it never clears
      lastErr = String(e?.shortMessage || e?.message || e).split("\n")[0];
      trace(`by-key poll: ${lastErr}`);
      found.length = 0;
    }
    if (found.length > 1)
      throw new Error(`this key was approved by several wallets (${found.map((x) => x.owner).join(", ")}); `
        + `pick yours: enclave session resume-wait ${rec.id} --owner 0x…`);
    if (found.length === 1) return sessionOpened(S, store, rec, found[0], f, info);
    if (Date.now() >= deadline)
      throw new Error(`no session opened with this key within ${minutes} min${lastErr ? ` (last poll failed: ${lastErr})` : ""}. `
        + `Once the owner has signed: enclave session resume-wait ${rec.id}${f.env ? " --env" : ""}`);
    await sleep(SESSION_POLL_MS);
  }
}

async function sessionOpened(S, store, rec, hit, f, info) {
  const { wantOwner: _w, rpc, ...plain } = rec;
  const open = await S.completeSession(store, plain, { vault: hit.vault, owner: hit.owner, grant: rec.grant,
    ...(rpc || explicitRpc() ? { rpc: rpc || RPCS[0] } : {}) });
  const left = Number(hit.st.expiresAt) - Math.floor(Date.now() / 1000);
  info(`session open: ${open.id}`);
  info(`  owner   ${hit.owner}`);
  info(`  vault   ${hit.vault}`);
  info(`  budget  ${S.fmtUsd(hit.st.balance6)}, expires in ${dur(left)}`);
  if (f.env) {
    const exported = S.exportSessionString(open);
    await store.remove(open.id);
    info("the key is NOT stored on disk: keep the line below as a secret (it is the session key)");
    say(`export ENCLAVE_SESSION=${exported}`);
    return;
  }
  store.setActive(open.id);
  if (opt.json) return jout({ sid: open.id, vault: hit.vault, owner: hit.owner, label: open.label, expiresAt: hit.st.expiresAt,
                              balance6: hit.st.balance6, file: path.join(store.dir, `${open.id}.json`), active: true });
  say(`stored ${path.join(store.dir, `${open.id}.json`)} (0600) as the ACTIVE session: publish/deploy/fund/upgrade/resize/config/stop/resume/rate-cap/refund act through it`);
  say(`see it: enclave session status · sign out (refunds the owner): enclave session terminate`);
}

const SESSION_STATE = ["none", "live", "ended"];
function sessionActions(S, mask) {
  return Object.entries(S.ACTIONS).filter(([, bit]) => ((BigInt(mask) >> BigInt(bit)) & 1n) === 1n).map(([n]) => n);
}

async function sessionStatus(rest) {
  const f = flags(rest, {});
  const s = await loadSession(f._[0]);
  const S = s.S;
  const st = await s.session.status();
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = Number(st.expiresAt) - now;
  const state = st.live ? "live"
    : Number(st.state) === 1 && expiresIn < 0 ? "expired"
    : Number(st.state) === 1 ? "revoked" : SESSION_STATE[Number(st.state)] || String(st.state);
  const periodEnds = Number(st.periodStart) + Number(st.period);
  const fresh = now >= periodEnds;
  const periodSpent = fresh ? 0n : st.periodSpent6, periodOps = fresh ? 0 : Number(st.periodOps);
  const actions = sessionActions(S, st.actions);
  const envs = Object.entries(S.ENVIRONMENTS).filter(([, b]) => (Number(st.envs) & b) !== 0).map(([n]) => n);
  const apps = st.anyApp ? ["*", ...((s.rec.grant?.apps || []).filter((a) => a !== "*"))]
    : (s.rec.grant?.apps?.length ? s.rec.grant.apps : st.apps.map((a) => short(a)));
  const active = s.from === "env" ? "ENCLAVE_SESSION" : (s.store?.activeId() === s.rec.id ? "active" : "stored");
  if (opt.json) return jout({ sid: s.sid, state, live: st.live, source: active, owner: s.owner, vault: s.vault, label: s.label,
    balance6: st.balance6, spent6: st.spent6, periodSpent6: periodSpent, perPeriod6: st.perPeriod6, periodEndsAt: fresh ? null : periodEnds,
    periodOps, opsPerPeriod: st.opsPerPeriod, maxFee6: st.maxFee6, expiresAt: st.expiresAt, actions, environments: envs, apps });
  const until = new Date(Number(st.expiresAt) * 1000).toISOString().replace(/\.\d+Z$/, "Z");
  kv([
    ["session", `${s.sid}  (${active})`],
    ["state", state],
    ["label", s.label || "(none)"],
    ["owner", s.owner || "(unknown)"],
    ["vault", s.vault],
    ["balance", `${S.fmtUsd(st.balance6)} left, ${S.fmtUsd(st.spent6)} spent`],
    ["this period", `${S.fmtUsd(periodSpent)} of ${S.fmtUsd(st.perPeriod6)}`
      + (Number(st.opsPerPeriod) ? `, ${periodOps} of ${st.opsPerPeriod} operations` : `, ${periodOps} operations`)
      + (fresh ? ` (a fresh ${dur(Number(st.period))} period starts with the next operation)` : ` (resets in ${dur(periodEnds - now)})`)],
    ["relay fee cap", `${S.fmtUsd(st.maxFee6)} per operation`],
    ["expires", expiresIn >= 0 ? `in ${dur(expiresIn)} (${until})` : `${dur(-expiresIn)} ago (${until})`],
    ["actions", actions.join(", ") || "(none)"],
    ["environments", envs.join(", ") || "(none)"],
    ["apps", apps.join(", ") || "(none)"],
  ]);
  if (!st.live) say(state === "expired" ? "this session has expired: open a new one (enclave session new …)"
                                        : "this session has ended: open a new one (enclave session new …)");
}

async function sessionList(rest) {
  flags(rest, {});
  const S = await sessionsSdk();
  const rows = [];
  const fromEnv = sessionEnvString();
  if (fromEnv) {
    try { const r = S.importSessionString(fromEnv); rows.push({ ...r, _where: "ENCLAVE_SESSION" }); }
    catch (e) { rows.push({ id: "(ENCLAVE_SESSION)", label: `unreadable: ${e.message}`, _where: "ENCLAVE_SESSION" }); }
  }
  const store = await sessionStore();
  const active = store.activeId();
  for (const r of await store.list()) rows.push({ ...r, _where: r.id === active ? "active" : "" });
  const now = Math.floor(Date.now() / 1000);
  if (opt.json) return jout(rows.map((r) => ({ id: r.id, state: r.handle ? "open" : "pending", label: r.label, vault: r.handle?.vault ?? null,
    owner: r.handle?.owner ?? null, expiresAt: r.grant?.expiresAt ?? null, where: r._where || "stored" })));
  table(rows, [
    { h: "", f: (r) => r._where === "active" ? "*" : r._where === "ENCLAVE_SESSION" ? "env" : "" },
    { h: "id", f: (r) => r.handle ? short(r.id) : r.id },
    { h: "state", f: (r) => !r.handle ? "pending (enclave session resume-wait)" : r.grant && Number(r.grant.expiresAt) < now ? "expired" : "open" },
    { h: "label", k: "label" },
    { h: "owner", f: (r) => r.handle?.owner || "" },
    { h: "expires", f: (r) => r.grant ? (Number(r.grant.expiresAt) >= now ? `in ${dur(Number(r.grant.expiresAt) - now)}` : `${dur(now - Number(r.grant.expiresAt))} ago`) : "" },
  ]);
  if (rows.length) say(`(* = active; live state and balance: enclave session status <id>)`);
}

async function sessionUse(rest) {
  const f = flags(rest, {});
  if (!f._[0]) throw new Error("usage: enclave session use <sid>   (see enclave session list)");
  const store = await sessionStore();
  const rec = await findSessionRecord(store, f._[0], { pending: false });
  store.setActive(rec.id);
  if (sessionEnvString()) stderr.write("note: ENCLAVE_SESSION is set and takes precedence over the active stored session\n");
  say(`active session: ${rec.id}${rec.label ? ` "${rec.label}"` : ""} (vault ${rec.handle.vault})`);
}

async function sessionTerminate(rest) {
  const f = flags(rest, {});
  const s = await loadSession(f._[0]);
  const S = s.S;
  const st = await s.session.status();
  const forget = async () => {
    if (s.from !== "file") return "unset ENCLAVE_SESSION: the key it holds is now useless";
    await s.store.remove(s.rec.id);
    if (s.store.activeId() === s.rec.id) s.store.setActive(null);
    return `deleted the key ${path.join(s.store.dir, `${s.rec.id}.json`)}`;
  };
  if (!st.live) {
    const open = Number(st.state) === 1, expired = open && Number(st.expiresAt) < Math.floor(Date.now() / 1000);
    const note = expired ? `it expired${st.balance6 > 0n ? `; the relay's keeper closes it and refunds the owner its ${S.fmtUsd(st.balance6)}` : ""}`
               : open ? "the owner revoked it (its budget is already back in the owner's vault)"
               : "it has already ended";
    const gone = await forget();
    if (opt.json) return jout({ sid: s.sid, ended: true, refund6: 0n, note });
    say(`session ${short(s.sid)}: ${note}; ${gone}`);
    return;
  }
  if (!(await confirm(`sign out session ${short(s.sid)}${s.label ? ` "${s.label}"` : ""}? Its remaining ${S.fmtUsd(st.balance6)} `
                    + `returns to the owner ${s.owner || ""} and the key stops working for good`)))
    return say("aborted");
  let out;
  try { out = await s.session.terminate(); }
  catch (e) { if (e instanceof S.SessionError) throw new Error(sessionHint(s, "terminate", e)); throw e; }
  const gone = await forget();
  if (opt.json) return jout({ sid: s.sid, ended: true, refund6: out.refund6, txHash: out.txHash });
  say(`signed out: refund ${S.fmtUsd(out.refund6)} to ${s.owner || "the owner"} (tx ${out.txHash})`);
  say(gone);
}

async function sessionTopUpLink(rest) {
  const f = flags(rest, { val: ["--amount"] });
  if (f.amount === undefined) throw new Error("usage: enclave session top-up-link --amount <usd> [<sid>]");
  const amount6 = sessionUsd6(numFlag(f.amount, "--amount"), "--amount");
  if (amount6 === 0n) throw new Error("--amount must be above 0");
  const s = await loadSession(f._[0]);
  let site = "https://enclave.host";
  try { site = String((await s.session.relay.config()).site || site).replace(/\/+$/, ""); } catch {}
  const link = `${site}/sessions#topup=${s.vault}:${s.sid}:${amount6}`;
  if (opt.json) return jout({ link, vault: s.vault, sid: s.sid, amount6 });
  say(`Send this to the owner${s.owner ? ` (${s.owner})` : ""}: they open it and sign ONE USDC authorization adding ${usd6(amount6)} to this session.`);
  say(`  ${link}`);
}

// ---- `enclave session delegate`: the OWNER lets its session vault act for its wallet ------------------
// One wallet transaction to the ledger (rev 15d): setDelegate(vault, true). From then on the owner's sessions
// that cover production reach the deployments the WALLET holds - fund, resize, lower the cap, stop/resume,
// refund (to the wallet); never the version or config, never a transfer - until --revoke takes it back from
// every session at once. The ledger is the address book's "deployments" (the one the vault resolves on every
// call), never a baked address; the vault is factory.vaultFor(owner), a CREATE2 address, so the grant may
// precede the vault itself. Signed like every other wallet transaction here (the key, --signer, --unsigned),
// never relayed. --status needs no key: it reads the ledger's storage, else asks the sessions relay.
const BOOK_ENTRY_ABI = [{ type: "function", name: "addr", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "address" }] }];
async function bookEntry(book, name) {
  const a = await read(book, BOOK_ENTRY_ABI, "addr", [toHex(name, { size: 32 })]);
  return /^0x0{40}$/i.test(a) ? null : getAddress(a);
}
async function delegationTarget(S, owner) {
  const book = CONTRACT_PINS ? null : env.ENCLAVE_ADDRESS_BOOK !== undefined ? env.ENCLAVE_ADDRESS_BOOK : DEFAULTS.ADDRESS_BOOK_ADDRESS;
  if (!book && !CONTRACT_PINS) throw new Error(`the delegation lives on the ledger the on-chain address book names, and ENCLAVE_ADDRESS_BOOK="" switches the book off`);
  const ledger = CONTRACT_PINS ? pinnedContract("deployments") : await bookEntry(book, "deployments");
  if (!ledger) throw new Error(`the address book ${book} names no "deployments" ledger`);
  const factory = CONTRACT_PINS ? pinnedContract("sessionVaultFactory")
    : (await bookEntry(book, S.BOOK_KEY_FACTORY)) ?? DEFAULTS.SESSION_VAULT_FACTORY_ADDRESS;
  if (CONTRACT_PINS) await assertPinnedSessionFactory();
  let vault;
  try { vault = getAddress(await S.vaultAddress(pub(), factory, owner)); }
  catch (e) { throw new Error(`can't read the session vault factory ${factory} (${String(e?.shortMessage || e?.message || e).split("\n")[0]})`); }
  const code = await pub().getCode({ address: vault });
  const deployed = !!code && code !== "0x";
  // a deployed vault answers for its owner itself: anything else is not this wallet's vault
  if (deployed && getAddress(await read(vault, S.sessionVaultAbi, "owner")) !== owner)
    throw new Error(`the factory ${factory} names vault ${vault} for ${owner}, but that vault belongs to someone else`);
  return { book, ledger, factory, vault, deployed };
}

async function sessionDelegate(rest) {
  const f = flags(rest, { val: ["--owner"], bool: ["--revoke", "--status"] });
  if (f._.length) throw new Error(`unexpected argument "${f._[0]}"\n${SESSION_USAGE}`);
  if (f.revoke && f.status) throw new Error("--status only reads; drop --revoke");
  if (f.owner !== undefined && !/^0x[0-9a-fA-F]{40}$/.test(f.owner)) throw new Error(`--owner is not a 0x…40-hex address: ${f.owner}`);
  if (f.owner !== undefined && !f.status)
    throw new Error("--owner goes with --status: a grant or revoke is the owner's own wallet transaction (its key, --signer or --unsigned with --from)");
  const S = await sessionsSdk();
  if (f.status) return sessionDelegateStatus(S, f);
  const account = loadKey();
  const owner = getAddress(account.address);
  const allowed = !f.revoke;
  const t = await delegationTarget(S, owner);
  DEFAULTS.DEPLOYMENTS_ADDRESS = t.ledger;   // `session` skips the start-up book read; this names the ledger in -x and --unsigned
  const st = await S.delegationStatus(pub(), t.ledger, owner, t.vault);
  if (!st.supported)
    throw new Error(`the ledger ${t.ledger} (the address book's "deployments") predates delegation: it has no setDelegate, `
      + `so no session reaches the deployments a wallet holds there`);
  await warnSessionVault(owner, t.vault);
  if (st.granted === allowed) {
    if (opt.json) return jout({ owner, vault: t.vault, ledger: t.ledger, granted: allowed, changed: false });
    return say(allowed ? `already granted: sessions of vault ${t.vault} act on the deployments ${owner} holds (revoke: enclave session delegate --revoke)`
                       : `nothing to revoke: vault ${t.vault} does not act for ${owner} on ledger ${t.ledger}`);
  }
  if (!opt.json) {
    say(`owner   ${owner}`);
    say(`vault   ${t.vault}${t.deployed ? "" : "  (not deployed yet: it is created with the first session you approve)"}`);
    say(`ledger  ${t.ledger}  (the address book's deployments)`);
    say(allowed
      ? "Your sessions that cover production could then fund, resize, lower the rate cap of, stop, resume and refund (to this wallet)\n"
        + "the deployments this wallet holds, without a wallet prompt each time. They can never change the version or config\n"
        + "such a deployment runs, raise its rate cap, or move it out of the wallet."
      : "Every session of that vault loses the deployments this wallet holds at once; the sessions themselves stay live.");
  }
  if (!(await confirm(allowed ? `let vault ${t.vault} act on the deployments ${owner} holds? (one wallet transaction: setDelegate(vault, true))`
                              : `take that back from vault ${t.vault}? (one wallet transaction: setDelegate(vault, false))`)))
    return say("aborted");
  const rcpt = await sendTx(account, { address: t.ledger, abi: S.ledgerDelegateAbi, functionName: "setDelegate", args: [t.vault, allowed] });
  // the sessions relay (and its RPC) must see it before a session relies on it: wait until the chain reads it back
  let seen = false;
  for (let i = 0; i < 20 && !seen; i++) {
    const now = await S.delegationStatus(pub(), t.ledger, owner, t.vault).catch(() => null);
    seen = !!now && now.granted === allowed;
    if (!seen) await sleep(1500);
  }
  if (opt.json) return jout({ owner, vault: t.vault, ledger: t.ledger, granted: allowed, changed: true,
                              tx: rcpt.transactionHash, block: rcpt.blockNumber, readBack: seen });
  say(`${allowed ? "granted" : "revoked"}: setDelegate(${t.vault}, ${allowed}) tx ${rcpt.transactionHash} confirmed in block ${rcpt.blockNumber}`);
  if (!seen) say("! the RPC does not read it back yet; a session call in the next few seconds may still be refused (retry it)");
  say(allowed ? "sessions covering production now act on the deployments this wallet holds (see: enclave session delegate --status)"
              : "sessions act only on the deployments their vault holds again");
}

// supported/granted for --owner, else this wallet, else the active session's owner
async function sessionDelegateStatus(S, f) {
  let owner = f.owner ? getAddress(f.owner) : null;
  if (!owner) { const k = loadKey({ required: false }); if (k) owner = getAddress(k.address); }
  if (!owner && sessionConfigured()) owner = await sessionOwner(await loadSession());
  if (!owner) throw new Error("whose delegation? pass --owner 0x… (or run it with the owner's wallet key, or with a session active)");
  let r, why = null;
  try {
    const t = await delegationTarget(S, owner);
    r = { owner, vault: t.vault, deployed: t.deployed, ledger: t.ledger, ...(await S.delegationStatus(pub(), t.ledger, owner, t.vault)), source: "chain" };
  } catch (e) {
    // the chain read failed: the sessions relay answers the same question (GET /v1/sessions/owner/<addr>)
    why = String(e?.shortMessage || e?.message || e).split("\n")[0];
    trace(`delegation read from the chain failed (${why}); asking the sessions relay`);
    let o;
    try { o = await new S.RelayClient(API_BASE).request("GET", `/owner/${owner}`); }
    catch (e2) { throw new Error(`can't read the delegation: the chain read failed (${why}) and so did the sessions relay (${e2.message})`); }
    r = { owner, vault: getAddress(o.vault), deployed: !!o.deployed, ledger: o.delegation?.ledger ?? null,
          supported: !!o.delegation?.supported, granted: !!o.delegation?.granted, source: "relay" };
  }
  if (opt.json) return jout(r);
  kv([
    ["owner", r.owner],
    ["vault", r.vault + (r.deployed ? "" : "  (not deployed yet: created with the first session the owner approves)")],
    ["ledger", r.ledger || "(unknown)"],
    ["supported", r.supported ? "yes" : "no: this ledger predates delegation (no setDelegate)"],
    ["granted", r.granted ? "yes: sessions covering production act on the deployments this wallet holds" : "no"],
    ...(r.source === "relay" ? [["source", `the sessions relay (the chain read failed: ${why})`]] : []),
  ]);
  if (r.supported && !r.granted) say("grant it (the owner, with the wallet; one transaction): enclave session delegate");
  if (r.granted) say("take it back (the owner, with the wallet): enclave session delegate --revoke");
}

// a session opened at another vault (an older factory) is not covered by this grant: say so
async function warnSessionVault(owner, vault) {
  if (!sessionConfigured()) return;
  try {
    const s = await loadSession();
    if ((await sessionOwner(s)) === owner && getAddress(s.vault) !== vault)
      stderr.write(`warning: the active session ${short(s.sid)} lives in vault ${s.vault}, not ${vault} (an older vault factory): `
        + `this grant does not reach it\n`);
  } catch (e) { trace(`active session: ${e.message}`); }
}

// ---- encrypted volumes: wallet key derivation + credentials envelope ----------
// BYTE-EXACT contract shared with scripts/enclave-encvol.sh and the
// encrypted-volumes app's JS, pinned by test/encvol-e2e.py stage 3:
//   password/salt = sha256_hex( sig + "\n" + "enclave-encvol-v1:password"/":salt" )
//   envelope      = "encv1:" + base64( iv[16] || AES-256-CTR(encKey, iv, credsJSON) || HMAC-SHA256(macKey, iv||ct)[32] )
//   encKey/macKey = sha256( sig + "\n" + "enclave-encvol-v1:creds-enc"/":creds-mac" )
// The envelope rides the PUBLIC App Config as "credsEnvelope"; it is exactly
// as sensitive as the volume itself (the same wallet guards both).
const encvolMessage = (keyId) =>
  `Enclave encrypted volume key v1\nvolume: ${keyId}\n\nSigning derives this volume's encryption key. Only sign in apps you trust with its contents.`;
const encvolSha = (s) => crypto.createHash("sha256").update(s).digest();

// --sig passes a personal_sign from any wallet through; otherwise the CLI
// wallet signs the canonical message itself (viem signs deterministically -
// RFC 6979 - so the same key always derives the same volume key).
async function encvolSig(f) {
  let sig = (f.sig || env.ENCVOL_WALLET_SIG || "").trim().toLowerCase();
  if (!sig) {
    const keyId = f["key-id"];
    if (!keyId) throw new Error("need --key-id <keyId> (sign with the CLI wallet) or --sig 0x… (a personal_sign made anywhere else)");
    sig = (await loadKey().signMessage({ message: encvolMessage(keyId) })).toLowerCase();
  }
  if (!/^0x[0-9a-f]{130}$/.test(sig)) throw new Error("signature must be 65-byte ECDSA hex (0x + 130 hex chars)");
  return sig;
}

async function cmdEncvol(rest) {
  const sub = rest.shift();
  const f = flags(rest, { val: ["--key-id", "--sig", "--access-key", "--secret-key", "--session-token"] });
  if (sub === "message") {
    const keyId = f["key-id"] || f._[0];
    if (!keyId) throw new Error("usage: enclave encvol message <keyId>");
    return say(encvolMessage(keyId));
  }
  if (sub === "derive") {
    const sig = await encvolSig(f);
    const password = encvolSha(sig + "\nenclave-encvol-v1:password").toString("hex");
    const salt = encvolSha(sig + "\nenclave-encvol-v1:salt").toString("hex");
    if (opt.json) return jout({ sig, password, salt });
    say(`export ENCVOL_PASSWORD=${password}`);
    say(`export ENCVOL_SALT=${salt}`);
    stderr.write("These decrypt the volume - treat them like the data itself.\n");
    return;
  }
  if (sub === "seal-creds") {
    const sig = await encvolSig(f);
    const accessKeyId = f["access-key"] || env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = f["secret-key"] || env.AWS_SECRET_ACCESS_KEY;
    const sessionToken = f["session-token"] || env.AWS_SESSION_TOKEN;
    if (!accessKeyId || !secretAccessKey)
      throw new Error("seal-creds needs --access-key + --secret-key (or AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY in the environment)");
    // ENCVOL_SEAL_IV: test hook so the pinned e2e vector is reproducible.
    const ivHex = (env.ENCVOL_SEAL_IV || "").trim();
    if (ivHex && !/^[0-9a-f]{32}$/.test(ivHex)) throw new Error("ENCVOL_SEAL_IV must be 32 lowercase hex chars");
    const iv = ivHex ? Buffer.from(ivHex, "hex") : crypto.randomBytes(16);
    const pt = JSON.stringify(sessionToken
      ? { accessKeyId, secretAccessKey, sessionToken }
      : { accessKeyId, secretAccessKey });
    const cipher = crypto.createCipheriv("aes-256-ctr", encvolSha(sig + "\nenclave-encvol-v1:creds-enc"), iv);
    const ivct = Buffer.concat([iv, cipher.update(pt, "utf8"), cipher.final()]);
    const tag = crypto.createHmac("sha256", encvolSha(sig + "\nenclave-encvol-v1:creds-mac")).update(ivct).digest();
    const envelope = "encv1:" + Buffer.concat([ivct, tag]).toString("base64");
    if (opt.json) return jout({ envelope });
    say(envelope);
    stderr.write(`\nSealed. Add "credsEnvelope" to the volume's encVolumes entry in the (public)
App Config - it is ciphertext under the SAME wallet that guards the volume:

      "unlock": "wallet",
      "credsEnvelope": "${envelope}"

One signature in the app then derives the crypt key AND opens these
credentials - no S3 fields to enter, after any restart.\n`);
    return;
  }
  throw new Error("usage: enclave encvol <message|derive|seal-creds> [--key-id K | --sig 0x…] …");
}

// ---- help + dispatch ---------------------------------------------------------------
const HELP = `enclave ${VERSION} · confidential compute from your terminal (https://enclave.host)

usage: enclave <command> [args]  [--json] [-x] [-y|--yes] [--base URL] [--rpc URL]
                                 [--unsigned --from 0x…] [--signer URL --from 0x…]

identity
  key new [--force]          generate a wallet key -> ${KEY_FILE}
  key import                 import a private key (hidden prompt / stdin pipe)
  login [--print]            sign in with your Enclave account (passkey) instead:
                             approve a link from your phone or any signed-in
                             browser; --print echoes the API bearer for scripts
  logout                     discard the account session token
  whoami                     wallet balances and/or account session + credit

deployments
  deploy <app> --fund <usd>  create + fund + wait until live; prints the URL
    --chain-only             submit directly to pinned contracts without an API;
                             requires --contract-pins, --cpu, --gpu, --max-rate.
                             Wallet-only, inline config, no relay-held secrets;
                             returns after funding without claiming readiness.
         [--gpu 0..1] [--cpu 0..1]      shares of one card / one node (default: app minimums)
         [--fund-eth <eth>] [--private] [--port N] [--ports CSV] [--no-wait]
         [--max-rate <usd/hour>]        hourly spend ceiling (default: what the cheapest live
                                        enclave charges for these shares). Only enclaves at or
                                        under it can run the app, now or after a failover
         [--waf '{"rps":10,"burst":40,"maxConcurrent":10,"maxBodyMb":40,"blockScanners":true}']
                                        per-IP rate limit + request filter, enforced in-enclave
         [--config '{"api_key":"…"}']   app-config override for THIS deployment: replaces the
                                        version's config as its ENCLAVE_CONFIG ('{}' = empty;
                                        the catalog default and other deployments are untouched)
         [--secrets '{"NAME":"value"}'] [--secrets-file .env]
                                        PRIVATE env vars staged on the relay (never on-chain):
                                        the enclave injects them into the app at every start
         [--isolation <backend>]        REQUIRE a per-app isolation tier (e.g. snp-guest-per-app),
                                        set at creation so no other runner can ever claim it
  secrets set <id> KEY=VALUE… [--file .env] [--restart]
                             store/update private env vars for a deployment (S3
                             keys etc): relay-stored, encrypted at rest, injected
                             by the lease-holding enclave; a wallet signature per
                             change, checked against the on-chain owner
  secrets ls <id> [--show]   list them (values masked without --show)
  secrets rm <id> KEY…       remove some; "secrets clear <id>" removes all
                             (--restart on any of these applies changes now)
  config show <id>           the deployment's options envelope: its waf and its
                             app-config override (or the version config that applies)
  config set <id> '<json>' [--file app-config.json] [--waf '<json>']
                             rewrite the envelope (one owner tx): the JSON becomes
                             this deployment's ENCLAVE_CONFIG; each namespace you
                             don't pass is preserved. The runner re-applies it in
                             place: waf live, config via an in-place app restart
  config clear <id> [config|waf|all]   drop the override (default config: the app
                             falls back to the version's approved config)
  ls                         your deployments: live, queued and unfunded
  status <id>                one deployment: state, lease, balance, URL
  logs <id> [-f] [--tail N]  the app's stdout/stderr (-f polls)
  fund <id> --usdc 5|--eth 0.002   top up runtime by the second
  attest [<id>]              fetch attestation + verify it LOCALLY (no key needed); nonzero exit on FAIL
  restart <id>               stop + relaunch the app in place (same version,
                             endpoint and balance; app state is ephemeral) - the
                             fix for a wedged instance, no wallet tx needed
  stop <id>                  suspend: setActive(false) on-chain + DELETE the instance
                             (the remaining balance stays on the deployment)
  resume <id>                setActive(true): re-queue a stopped deployment; it
                             relaunches from its remaining balance
  publish ... [--gpu-optional]
                             publish --vram/--gpu-gflops as DESIRED, not required:
                             runners set no GPU floor, CPU-only enclaves may serve
                             the app, and the declared slice is what a deployer
                             buys to actually get the card
  deploy ... [--gpu-optional]
                             this deployment PREFERS a card (needs --gpu): a GPU
                             enclave claims it first, but a CPU-only one runs it
                             on cores rather than let it queue - and bills only
                             the CPU share there
  move <id> <enclave>        run it on a different enclave: the current host hands
                             the lease back (unused time is refunded) and the box
                             you name claims it. Same URL, version and balance -
                             a steer, not a lock; prints where it actually landed
  upgrade <id> [<version>] [--gpu 0..1] [--cpu 0..1]
                             switch to another approved version of the same app
                             (default: its latest); paid time carries over - the
                             runner restarts the app in place on the new version.
                             --gpu/--cpu re-buy the shares in the same transaction
                             (rate recalculated at current prices; rev-6 ledgers)
  resize <id> --gpu 0..1 --cpu 0..1
                             re-buy the shares without changing versions; the
                             rate is recalculated and a live lease settles at
                             the old rate before re-burning at the new one
  rate-cap <id> [<usd/hour>]  show or move the hourly spend ceiling. Enclaves
                             price their own hardware, so this decides which of
                             them may run the app - including where it fails
                             over to if its host dies. Below the running rate
                             stops it at the end of the paid lease
  refund <id>                cancel and send the unused runtime back to your
                             wallet, then stop the app. What returns is what the
                             ledger still HOLDS - the host's escrow, ~80% of
                             unspent time - not the sticker price: the publisher
                             fee and the platform share went to their wallets
                             when you funded. Prints the exact amount first
                             (aliases: cancel; rev-10 ledgers)
  transfer <id> <0xaddr>     hand the deployment to another wallet. Control
                             moves, money never does: the ledger refuses the
                             transfer while it still holds your refundable
                             escrow, so this refunds you first (two txs), then
                             hands over the record. One-shot - no accept step,
                             so check the address. Secrets and domains stay
                             with the record (rev-11 ledgers)

catalog
  publish <app.wasm> --slug S [--version V --name N --desc D --config JSON]
          [--mem MB --cpu-gflops N --vram MB --gpu-gflops N --ports CSV]
          [--fee $/hr]        your hourly fee, paid straight to your wallet out
                             of deployers' fundings (capped on-chain; immutable
                             per version and covered by approval, like ports)
  apps [query]               browse/search the on-chain catalog

sessions (an agent acts under a budget and policy its owner approved once - no wallet key here)
  session new --preset staging-publish --app <slug>[,<slug>…] [--budget <usd>] [--days N]
              [--label TEXT] [--owner 0x…] [--env] [--no-wait] [--wait-minutes 30]
                             make a session key and print, in plain words, what it may
                             do, a check code and a link. The OWNER opens the link and
                             signs once with their wallet (on a hardware wallet the first
                             8 hex characters of "sessionKey" match the check code). Waits
                             for that signature, then stores the key (0600, in
                             ${SESSION_DIR}) as the active session;
                             --env prints \`export ENCLAVE_SESSION=…\` instead (no file)
                             presets: staging-publish (named apps, staging only, $5/day),
                             auth-only (status reads, no money), browser
  session resume-wait <id> [--env]
                             keep waiting for the owner's signature (after --no-wait/ctrl-c)
  session status [<sid>]     live/ended, owner, vault, balance and spend, this period's
                             spend vs its limit, operations, expiry, actions, environments
  session list | use <sid>   the stored sessions; pick the active one
  session terminate [<sid>]  sign out: the unspent budget returns to the owner and the
                             key file is deleted
  session top-up-link --amount <usd>
                             a link for the owner: one signature adds budget
  session delegate [--revoke] [--status [--owner 0x…]]
                             the OWNER, with the wallet: one ledger transaction
                             (setDelegate) lets your session vault act on the
                             deployments your WALLET holds. Sessions covering prod may
                             then fund, resize, lower the rate cap of, stop, resume and
                             refund them (to the wallet) - never upgrade or config them,
                             never move them. --revoke takes it back from every session
                             at once; --status shows supported/granted (no key needed)
  With a session active (or ENCLAVE_SESSION set), these act THROUGH it instead of the
  wallet: publish (app.publish; the publisher is the session's vault), deploy (--env
  staging|prod, default staging; --fund comes out of the session budget), fund --usdc,
  upgrade, resize, config set|clear, stop, resume, rate-cap, refund. They reach the
  deployments the session's vault holds and, once the owner ran \`session delegate\`,
  the ones the owner's wallet holds: production to a session (rate-cap may only
  lower; upgrade and config are refused). A refusal (budget, policy, expiry) prints
  its code and the next step - it never falls back to the wallet key. Secrets,
  transfers and production promotion stay with the owner's wallet. --wallet uses the
  wallet key for one command.

encrypted volumes (rclone-crypt over S3; push data with scripts/enclave-encvol.sh)
  encvol message <keyId>     print the canonical message a wallet signs for a volume key
  encvol derive     --key-id K | --sig 0x…   volume password/salt, signed by the CLI
                             wallet (deterministic) or derived from a given signature
  encvol seal-creds --key-id K | --sig 0x…  [--access-key A --secret-key S]
                             encrypt S3 credentials (default: AWS_* env) under the wallet
                             key -> a "credsEnvelope" for the PUBLIC App Config; the app
                             then unlocks with one signature, nothing typed

sell hosting (run an enclave on your own TEE hardware — metal/PROTOCOL.md)
  host init [--name N] [--payout 0x…] [--cpus N --mem MiB]
            [--price-cpu USD/hr] [--gpu N --price-gpu USD/hr]
            [--eab-kid K --eab-hmac H] [--referral CODE]
                             scaffold metal/config.json: mints the box's operator
                             key INTO that file (gitignored; the printed address
                             derives from it — nothing external to trust) and
                             defaults payout to THIS CLI wallet
  host build [--repo PATH]   build the measured guest image from a checkout
                             (unprivileged; the first run pulls the pinned
                             images, so give it a while)
  host run [--config PATH]   launch the enclave in the foreground (ctrl-c stops)
  host install               run it under systemd instead: writes a user unit
                             pointing at THIS checkout, enables it at boot and
                             keeps it running after logout
  host check                 is the guest answering, and is its attestation real
                             hardware or dev mode
  host fund [--eth 0.002] [--address 0x…]
                             gas the operator from your CLI wallet, one signed
                             transfer: it pays the box's register/heartbeat/claim
                             transaction fees — it is not a payment to anyone
  host status                gas left · listed/serving · accrued USDC earnings
  host referral [CODE]       report this machine's referral code (default: the one
                             host init saved; also ENCLAVE_REFERRAL), signed by its
                             operator key; needs the name registered on chain
  host declare-payout [--url https://…]
                             publish THIS wallet as the box's payout wallet, so
                             deployments you own run there for nothing (a paid
                             app's publisher fee still applies). Must be sent
                             from that wallet — the box cannot declare it
  host clear-payout          withdraw the declaration again

platform
  pricing | availability | gpu | account

<app>  is  [publisher/]slug[:version] from the on-chain catalog (CIDs can't
       deploy: a CID names bytes, not a version; config differs per version)
<id>   is  the bytes32 deployment id (0x…), any unique 0x-prefix of it, or a legacy dep_… id

Signing without a key on this machine (hardware wallets, Safes, air-gapped):
  --unsigned --from 0x…      print the transaction {chainId,to,data,value} and
                             stop, instead of sending it. Sign it wherever the
                             key lives - a browser wallet with a Ledger behind
                             it, a Safe, a cold box. Multi-step commands print
                             the FIRST transaction; re-run once it has mined.
                             Same shape the MCP build_* tools return.
  --signer URL --from 0x…    send eth_sendTransaction to a local signer that
                             holds the key - Frame (http://127.0.0.1:1248) or
                             Clef - which drives the Ledger/Trezor itself and
                             pops the approval. Reads still use --rpc.
  Both need --from: a signer may hold several accounts, and every ownership
  gate here keys on the address, so guessing would act as the wrong wallet.
  Message-signing commands (login, upload, encvol) need --signer; --unsigned
  cannot represent a signature over a string.

Global: --json machine output · -x print every REST call + transaction ·
--base/--rpc (ENCLAVE_API_BASE/ENCLAVE_RPC) target an enclave or your own RPC ·
--contract-pins FILE (ENCLAVE_CONTRACT_PINS_FILE) fixes contract addresses from
the host pin-document format and disables mutable address-book discovery.
Invalid pins refuse; zero optional bindings disable that feature. Pins select
contracts, not their internal governance or an independent API operator.
ENCLAVE_KEY overrides the key file · --wallet acts with the wallet key even when a
session is active (ENCLAVE_SESSION / ENCLAVE_SESSION_DIR). Auth is SIWE (wallet) or an Enclave account
session (enclave login); keys never leave this machine. Account sessions read
account-provisioned/credit deployments (ls, whoami, account) but can't sign
transactions - deploying and funding by credit stays on enclave.host for now.`;

// ---- host: sell hosting on your own TEE hardware (metal/) ---------------------
// Seller onboarding without the sharp edges: `init` mints the operator key
// INTO the (gitignored) metal config and prints the address it derives —
// nothing to trust, you can re-derive it from the file; `fund` gases that
// operator FROM THE CLI WALLET in one signed transfer instead of a hand-typed
// send to a pasted address; `status` reads back gas / serving / earnings.
// The ETH is a GAS TANK for the box's register/heartbeat/claim transactions,
// not a payment; earnings sweep to payoutAddress (default: this CLI wallet).
async function cmdHost(rest) {
  const sub = rest.shift();
  const f = flags(rest, { val: ["--config", "--name", "--payout", "--eth", "--address", "--mode", "--cpus", "--mem", "--eab-kid", "--eab-hmac", "--price-cpu", "--price-gpu", "--gpu", "--repo", "--supervisor", "--wasm", "--kernel", "--url", "--referral"] });
  const cfgPath = f.config || path.join("metal", "config.json");
  const readCfg = () => { try { return JSON.parse(fs.readFileSync(cfgPath, "utf8")); } catch { return null; } };
  const operatorOf = (cfg) => {
    if (!cfg || !cfg.registryKey) return null;
    const pk = cfg.registryKey.startsWith("0x") ? cfg.registryKey : "0x" + cfg.registryKey;
    return privateKeyToAccount(pk).address;
  };

  if (sub === "init") {
    let cfg = readCfg();
    const fresh = !cfg;
    if (fresh) {
      if (!fs.existsSync(path.dirname(cfgPath)))
        throw new Error(`${path.dirname(cfgPath)}/ not found. Run this from a checkout of the enclave repo `
          + `(git clone https://github.com/EnclaveHost/enclave) or pass --config <path>`);
      cfg = { mode: f.mode || "snp", name: f.name || "metal0",
              cpus: parseInt(f.cpus || "8", 10), memMiB: parseInt(f.mem || "8192", 10),
              relayUrl: "wss://api.enclave.host/v1/fleet-tunnel", tunnelToken: "" };
    } else if (f.name) cfg.name = f.name;
    if (!cfg.publicUrl) cfg.publicUrl = `https://api.enclave.host/t/${cfg.name || "metal0"}`;
    const minted = !cfg.registryKey;
    if (minted) cfg.registryKey = generatePrivateKey();
    // optional bring-your-own ZeroSSL EAB (free account): the box then mints
    // app certs via ZeroSSL first, dodging Let's Encrypt's per-domain weekly cap
    if (!!f["eab-kid"] !== !!f["eab-hmac"]) throw new Error("--eab-kid and --eab-hmac go together (ZeroSSL dashboard - Developer - EAB credentials)");
    if (f["eab-kid"]) { cfg.acmeEabKid = f["eab-kid"]; cfg.acmeEabHmac = f["eab-hmac"]; }
    // what this box CHARGES: USD/hour for a FULL node / FULL card. It then
    // refuses work paying less. A GPU ask needs a GPU enclave (--gpu, or a
    // build that passes a card through) — pricing a card you can't sell would
    // advertise capacity that can never be claimed.
    const price = (k) => { if (f[k] == null) return null;
      const v = Number(f[k]);
      if (!Number.isFinite(v) || v < 0) throw new Error(`--${k} must be a USD-per-hour number (e.g. --${k} 2.50)`);
      return v; };
    const pCpu = price("price-cpu"), pGpu = price("price-gpu");
    if (pCpu != null) cfg.priceCpuUsdHr = pCpu;
    if (pGpu != null) {
      if (!(f.gpu || cfg.gpuCount > 0)) throw new Error("--price-gpu needs a GPU enclave (pass --gpu, or drop the flag: a CPU-only box sells no GPU shares)");
      cfg.priceGpuUsdHr = pGpu;
    }
    if (f.gpu) { cfg.gpuCount = Math.max(1, parseInt(f.gpu, 10) || 1);
      if (cfg.priceGpuUsdHr == null) say("note: GPU enclave with no --price-gpu — its GPU shares sell at the on-chain list price"); }
    // the referral code this machine was set up with (attribution only): kept here, said by the guest when it attaches
    // (x-metal-referral) and reported now by `enclave host referral` once the name is registered
    const referral = f.referral ?? env.ENCLAVE_REFERRAL;
    if (referral != null && String(referral).trim() !== "") {
      if (!REFERRAL_RE.test(String(referral).trim())) throw new Error("--referral: a referral code is 1-64 letters, digits, '.', '_' or '-'");
      cfg.referral = String(referral).trim();
    }
    if (f.payout) cfg.payoutAddress = f.payout;
    else if (!cfg.payoutAddress) {
      const acct = loadKey({ required: false });
      if (acct) cfg.payoutAddress = acct.address;      // the seller's own wallet — earnings come HERE
    }
    fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
    try { fs.chmodSync(cfgPath, 0o600); } catch {}
    const op = operatorOf(cfg);
    say(`${cfgPath} ${fresh ? "created" : "updated"}${minted ? " · operator key MINTED (it stays in this file; keep it out of git — metal/config.json is gitignored in the repo)" : ""}`);
    const askRow = (label, v, unit) => [label, v != null ? `$${Number(v).toFixed(2)} / ${unit}   (this box refuses work paying less)` : `list price (on-chain) — set with --price-${label.startsWith("cpu") ? "cpu" : "gpu"}`];
    kv([["operator", `${op}   (this box's on-chain identity; needs a little Base ETH for gas)`],
        ["payout", cfg.payoutAddress ? `${cfg.payoutAddress}   (your USDC earnings sweep here)` : "(unset — set one before earning: enclave host init --payout 0x…)"],
        ...(cfg.referral ? [["referral", `${cfg.referral}   (reported for this machine: enclave host referral, once it is registered)`]] : []),
        askRow("cpu ask", cfg.priceCpuUsdHr, "full node-hour"),
        ...(cfg.gpuCount > 0 ? [askRow("gpu ask", cfg.priceGpuUsdHr, "full card-hour")] : []),
        ["endpoint", cfg.publicUrl]]);
    say(`next:
  enclave host fund --eth 0.002              gas the operator from this CLI wallet
  enclave host declare-payout                publish your payout wallet on-chain, so your
                                             OWN apps run on this box for free (optional)
  node metal/build-image.mjs                 reproducible guest image
  sudo bash metal/host-setup.sh              one-time /dev/sev perms
  node metal/enclave-metal.mjs --config ${cfgPath}    (or metal/systemd/)
the box hides itself until its registration confirms, then appears as serving.`);
    return;
  }

  if (sub === "referral") {
    // Report this machine's referral code (attribution only; relay/referrals.mjs): the operator key in the config signs
    // "enclave-referral:<name>:<code>", and the relay records it only when that key is the name's REGISTERED owner.
    const cfg = readCfg();
    if (!cfg || !cfg.registryKey) throw new Error(`no host config with an operator key at ${cfgPath}: run \`enclave host init\` first`);
    const code = String(f._[0] ?? f.referral ?? env.ENCLAVE_REFERRAL ?? cfg.referral ?? "").trim();
    if (!code) throw new Error("no referral code: enclave host referral <code> (or set one with enclave host init --referral <code>)");
    if (!REFERRAL_RE.test(code)) throw new Error("a referral code is 1-64 letters, digits, '.', '_' or '-'");
    if (cfg.referral !== code) { cfg.referral = code; fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 }); }
    const name = cfg.name || "metal0";
    const pk = cfg.registryKey.startsWith("0x") ? cfg.registryKey : "0x" + cfg.registryKey;
    const signature = await privateKeyToAccount(pk).signMessage({ message: `enclave-referral:${name}:${code}` });
    const r = await fetch(API_BASE + "/v1/referrals/host", { method: "POST", headers: { "content-type": "application/json" },
                                                             body: JSON.stringify({ name, code, signature }) });
    const d = await r.json().catch(() => ({}));
    if (r.status === 409) { say(`${name} is not registered on chain yet: the code is saved in ${cfgPath}; run this again once it is`); return; }
    if (!r.ok) throw new Error(`the relay refused it (${r.status}): ${d.message || d.error || "no reason given"}`);
    if (opt.json) return console.log(JSON.stringify({ name, code, outcome: d.outcome }));
    say(d.outcome === "kept-first" ? `${name} already has an earlier referral code; ${code} is recorded beside it`
                                   : `${name}: referral code ${code} recorded`);
    return;
  }

  if (sub === "fund") {
    const to = f.address || operatorOf(readCfg());
    if (!to) throw new Error(`nothing to fund: pass --address 0x…, or run \`enclave host init\` first (looked in ${cfgPath})`);
    if (!/^0x[0-9a-fA-F]{40}$/.test(to)) throw new Error(`operator address is not a 0x…40-hex EOA: ${to}`);
    const ethAmt = f.eth || "0.002";
    const value = BigInt(Math.round(Number(ethAmt) * 1e18));
    if (!(value > 0n)) throw new Error("--eth must be a positive ETH amount");
    const account = loadKey();
    const bal = await pub().getBalance({ address: account.address });
    if (bal < value) throw new Error(`your CLI wallet ${account.address} holds ${formatUnits(bal, 18)} ETH on Base — less than ${ethAmt}. Bridge/buy Base ETH first.`);
    say(`gassing operator ${to} with ${ethAmt} ETH from ${account.address}`);
    say(`(a gas tank for its register/heartbeat/claim transactions — not a payment; earnings never touch this key)`);
    if (opt.unsigned) emitUnsigned({ account, to, data: "0x", value, label: "ETH transfer" });
    const hash = await wallet(account).sendTransaction({ to, value });
    trace(`tx sent ${hash}, waiting for receipt`);
    const rcpt = await pub().waitForTransactionReceipt({ hash });
    if (rcpt.status !== "success") throw new Error(`transfer reverted: ${hash}`);
    say(`✓ funded (tx ${hash})`);
    kv([["operator balance", `${formatUnits(await pub().getBalance({ address: to }), 18)} ETH`]]);
    say("the enclave registers itself on its next attempt and then shows as serving (enclave host status)");
    return;
  }

  // `enclave host declare-payout` — the one transaction that makes this box
  // host YOUR OWN apps for free (ledger rev 12). EnclaveRegistry.setPayoutWallet
  // takes no address: it records msg.sender, so the declaration can only ever
  // come from the wallet being named. That is what stops any operator from
  // naming a stranger and hosting their deployment for free out of reach of its
  // rate cap — and it is why the box's own operator key cannot send this. It
  // goes from THIS CLI wallet, which is the wallet your deployments come from.
  if (sub === "declare-payout" || sub === "clear-payout") {
    const cfg = readCfg();
    const url = f.url || (cfg && cfg.publicUrl);
    if (!url) throw new Error("no enclave endpoint: pass --url https://…, or run `enclave host init` first");
    const account = loadKey();
    const id = keccak256(toHex(String(url).replace(/\/+$/, "")));   // EnclaveRegistry.idOf(endpoint)
    const abi = [{ type: "function", name: "setPayoutWallet", stateMutability: "nonpayable",
                   inputs: [{ name: "id", type: "bytes32" }], outputs: [] },
                 { type: "function", name: "clearPayoutWallet", stateMutability: "nonpayable",
                   inputs: [{ name: "id", type: "bytes32" }], outputs: [] }];
    const clearing = sub === "clear-payout";
    // Preflight: on a pre-schema-4 registry neither function exists, and the
    // tx would revert with nothing to explain why. Say it before spending gas.
    const regRev = await read(DEFAULTS.REGISTRY_ADDRESS,
      [{ type: "function", name: "registrySchema", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] }],
      "registrySchema").then(Number).catch((e) => { if (!isRevertErr(e)) throw e; return 1; });
    if (regRev < 4)
      throw new Error(`the registry at ${DEFAULTS.REGISTRY_ADDRESS} is schema ${regRev}; declaring a payout wallet `
        + `needs schema 4. This platform has not deployed it yet - until then every deployment is charged, `
        + `including your own on your own box.`);
    say(clearing
      ? `withdrawing ${account.address} as the payout wallet of ${url}`
      : `declaring ${account.address} as the payout wallet of ${url}`);
    if (!clearing)
      say("(from then on, deployments owned by this wallet run on that box for free — the publisher fee of a paid app still applies)");
    const rcpt = await sendTx(account, { address: DEFAULTS.REGISTRY_ADDRESS, abi,
      functionName: clearing ? "clearPayoutWallet" : "setPayoutWallet", args: [id] });
    say(`✓ ${clearing ? "cleared" : "declared"} (tx ${rcpt.transactionHash})`);
    if (!clearing) say("check it landed: enclave host status");
    return;
  }

  if (sub === "status") {
    const cfg = readCfg();
    const name = f.name || (cfg && cfg.name) || "metal0";
    const op = f.address || operatorOf(cfg);
    const rows = [["name", name], ["operator", op || "(no config/key found — pass --address or --config)"]];
    if (op) rows.push(["gas", `${formatUnits(await pub().getBalance({ address: op }), 18)} ETH`]);
    try {
      const list = await api("GET", "/enclaves");
      const row = (list.enclaves || []).find((e) => (e.name || "") === name);
      rows.push(["listed", row ? "yes" : "no (tunnel down, or not attached to this relay)"]);
      if (row) rows.push(["serving", row.serving === true ? "yes (registered + claiming)"
        : "no — " + (row.availability && row.availability.claimEnabled === false
            ? "not registered yet (needs selling config + a gassed operator)" : "not claiming")]);
      // The on-chain declaration, which is what the ledger actually prices
      // against — NOT metal/config.json's payoutAddress, which only says where
      // this box sweeps its earnings. They are usually the same wallet and a
      // seller assumes they are, so show the chain's answer plainly.
      if (row) rows.push(["payout wallet", row.payoutWallet && !/^0x0+$/.test(row.payoutWallet)
        ? `${row.payoutWallet}   (its own deployments run here free)`
        : "(undeclared — this box charges even its owner; fix with `enclave host declare-payout`)"]);
    } catch (e) { rows.push(["listed", `unknown (${e.message})`]); }
    if (op) {
      try {
        const { rev } = await depAbi();
        if (rev >= 7) {
          const earned = await read(DEFAULTS.DEPLOYMENTS_ADDRESS,
            [{ type: "function", name: "earned6", stateMutability: "view",
               inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] }], "earned6", [op]);
          rows.push(["earned", `$${(Number(earned) / 1e6).toFixed(2)} accrued on the ledger (auto-swept to payoutAddress)`]);
        } else rows.push(["earned", "n/a — the live ledger predates runner payout (schema < 7)"]);
      } catch {}
    }
    kv(rows);
    return;
  }

  // ---- the rest of the quickstart, as commands instead of pasted shell ----
  // These need the repo (the guest image is built from it), so they resolve
  // metal/ from the cwd or --repo and say so plainly when it isn't there.
  const metalDir = () => {
    const root = f.repo || process.cwd();
    const d = path.join(root, "metal");
    if (!fs.existsSync(path.join(d, "build-image.mjs")))
      throw new Error(`no metal/ here. Run this from a checkout of the enclave repo `
        + `(git clone https://github.com/EnclaveHost/enclave), or pass --repo <path>`);
    return { root, dir: d };
  };
  const runNode = (root, args, label) => {
    say(`$ node ${args.join(" ")}`);
    const r = spawnSync(process.execPath, args, { cwd: root, stdio: "inherit" });
    if (r.status !== 0) throw new Error(`${label} exited ${r.status ?? r.signal}`);
  };

  if (sub === "build") {
    const { root } = metalDir();
    say("building the measured guest image (unprivileged; the first run pulls images and takes a while)");
    const args = ["metal/build-image.mjs"];
    for (const k of ["supervisor", "wasm", "kernel"]) if (f[k]) args.push("--" + k, f[k]);
    runNode(root, args, "build-image");
    say(`next: enclave host run --config ${cfgPath}   (or: enclave host install)`);
    return;
  }

  if (sub === "run") {
    const { root } = metalDir();
    if (!fs.existsSync(path.join(root, "metal", "dist", "initramfs.cpio.gz")))
      throw new Error("no built image (metal/dist). Run `enclave host build` first.");
    say(`launching ${cfgPath} in the foreground (ctrl-c stops it; \`enclave host install\` runs it under systemd)`);
    runNode(root, ["metal/enclave-metal.mjs", "--config", cfgPath], "enclave-metal");
    return;
  }

  if (sub === "install") {
    const { root } = metalDir();
    if (process.platform !== "linux") throw new Error("systemd install is Linux-only; use `enclave host run` elsewhere");
    const unitDir = path.join(os.homedir(), ".config", "systemd", "user");
    fs.mkdirSync(unitDir, { recursive: true });
    // Generate the unit from THIS checkout's real paths. The shipped template
    // hardcodes one developer's directory, which silently fails for everyone
    // else; the absolute node path keeps it working without a login shell.
    const unit = `[Unit]
Description=Enclave Metal - self-hosted confidential-VM enclave
After=network-online.target

[Service]
Type=simple
WorkingDirectory=${root}
ExecStart=${process.execPath} ${path.join(root, "metal", "enclave-metal.mjs")} --config ${path.resolve(cfgPath)}
Restart=always
RestartSec=3
LimitMEMLOCK=infinity

[Install]
WantedBy=default.target
`;
    const unitPath = path.join(unitDir, "enclave-metal.service");
    fs.writeFileSync(unitPath, unit);
    say(`wrote ${unitPath}`);
    for (const args of [["--user", "daemon-reload"], ["--user", "enable", "--now", "enclave-metal"]]) {
      const r = spawnSync("systemctl", args, { stdio: "inherit" });
      if (r.status !== 0) throw new Error(`systemctl ${args.join(" ")} failed (${r.status ?? r.signal})`);
    }
    // survive logout / start at boot - without this the box stops selling the
    // moment the operator's session ends
    spawnSync("loginctl", ["enable-linger", os.userInfo().username], { stdio: "ignore" });
    say("✓ running under systemd (enabled at boot, lingering)");
    say(`logs:   journalctl --user -u enclave-metal -f
health: enclave host check
stop:   systemctl --user disable --now enclave-metal`);
    return;
  }

  if (sub === "check") {
    const cfg = readCfg() || {};
    const hp = (cfg.hostfwd || []).find((h) => Number(h.guest) === 8080);
    const rows = [];
    const probe = async (url, opts) => {
      try {
        const r = await fetch(url, { signal: AbortSignal.timeout(5000), ...(opts || {}) });
        return { ok: r.ok, status: r.status, body: await r.text() };
      } catch (e) { return { err: e.cause?.code || e.message }; }
    };
    if (hp) {
      const h = await probe(`http://127.0.0.1:${hp.host}/v1/health`);
      rows.push(["supervisor", h.err ? `unreachable (${h.err}) - is the guest up? journalctl --user -u enclave-metal`
        : h.ok ? "ok" : `HTTP ${h.status}`]);
    } else rows.push(["supervisor", "(no hostfwd for guest 8080 in the config - probe it over the tunnel instead)"]);
    const a = await probe(`https://api.enclave.host/t/${cfg.name || "metal0"}/v1/attestation`);
    if (a.err) rows.push(["attestation", `not reachable through the relay (${a.err})`]);
    else {
      // the supervisor wraps the RAD: enclave.attestationDocument.format
      let fmt = ""; try { const j = JSON.parse(a.body); fmt = j?.enclave?.attestationDocument?.format || j?.format || ""; } catch {}
      rows.push(["attestation", fmt ? `${fmt}${/dev-unattested/.test(fmt) ? "  (DEV MODE - not attested; set mode snp|tdx to sell)" : "  (hardware-attested)"}`
        : `HTTP ${a.status}`]);
    }
    kv(rows);
    say("verify the launch measurement independently: node metal/verify.mjs --url https://api.enclave.host/t/" + (cfg.name || "metal0"));
    return;
  }

  throw new Error("usage: enclave host init | build | run | install | check | fund | status | declare-payout | clear-payout");
}

const COMMANDS = {
  key: cmdKey, login: cmdLogin, logout: cmdLogout,
  whoami: cmdWhoami, deploy: cmdDeploy, ls: cmdLs, list: cmdLs,
  status: cmdStatus, logs: cmdLogs, fund: cmdFund, attest: cmdAttest,
  restart: cmdRestart, stop: cmdStop, suspend: cmdStop, resume: cmdResume, move: cmdMove,
  upgrade: cmdUpgrade, "set-version": cmdUpgrade,
  resize: (rest) => cmdUpgrade(rest, { resize: true }),
  "rate-cap": cmdRateCap, cap: cmdRateCap,
  refund: cmdRefund, cancel: cmdRefund, transfer: cmdTransfer,
  secrets: cmdSecrets, config: cmdConfig, custody: cmdCustodyHere,
  publish: cmdPublish, apps: cmdApps,
  pricing: cmdPricing, availability: cmdAvailability, gpu: cmdGpu, account: cmdAccount,
  encvol: cmdEncvol, host: cmdHost, session: cmdSession,
};

// Resolve the platform's contract addresses from the on-chain address book
// before dispatch (one eth_call, hard 4s cap; baked DEFAULTS on any failure so
// offline use and tests never block; ENCLAVE_ADDRESS_BOOK="" opts out).
// A baked address can be a RETIRED contract that still answers (the catalog's
// was, until 2026-09-26: a publish would have gone to a dead catalog, and a
// deploy would have read versions and fees from it). So an unread book is said
// on stderr, not only under --trace, and a catalog WRITE is refused unless the
// catalog address came from the book or the book was switched off on purpose.
const BOOK = { wanted: false, catalogFromBook: false, why: "" };
function catalogWriteAllowed() {
  if (!BOOK.wanted || BOOK.catalogFromBook) return;
  throw new Error(`refusing to write to the app catalog: the on-chain address book was not read (${BOOK.why}), so this CLI `
    + `cannot tell which catalog is live, and its baked address may be a retired one. Retry, or set ENCLAVE_ADDRESS_BOOK="" `
    + `to use the baked addresses on purpose.`);
}
async function resolveAddressBook() {
  if (CONTRACT_PINS) return;
  const book = env.ENCLAVE_ADDRESS_BOOK !== undefined ? env.ENCLAVE_ADDRESS_BOOK : DEFAULTS.ADDRESS_BOOK_ADDRESS;
  if (!book) return;
  BOOK.wanted = true;
  try {
    const abi = [{ type: "function", name: "all", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32[]" }, { type: "address[]" }] }];
    const [keys, values] = await Promise.race([
      pub().readContract({ address: book, abi, functionName: "all" }),
      sleep(4000).then(() => { throw new Error("timeout"); }),
    ]);
    const map = { registry: "REGISTRY_ADDRESS", deployments: "DEPLOYMENTS_ADDRESS",
                  appCatalog: "APP_CATALOG_ADDRESS", enclavePay: "FORWARDER_ADDRESS" };
    keys.forEach((kh, i) => {
      let k = ""; for (let b = 2; b < kh.length; b += 2) { const c = parseInt(kh.slice(b, b + 2), 16); if (!c) break; k += String.fromCharCode(c); }
      const name = map[k], v = values[i];
      if (name && DEFAULTS[name] !== undefined && !/^0x0{40}$/i.test(v)) {
        DEFAULTS[name] = v;
        if (name === "APP_CATALOG_ADDRESS") BOOK.catalogFromBook = true;
      }
    });
    if (!BOOK.catalogFromBook) BOOK.why = "it names no appCatalog";
    trace("address book " + book + " resolved");
  } catch (e) { BOOK.why = String(e?.shortMessage || e?.message || e).split("\n")[0]; }
  if (!BOOK.catalogFromBook)
    stderr.write(`warning: the on-chain address book ${book} was not read (${BOOK.why}); this CLI is using its baked `
      + `contract addresses, which can be out of date. Catalog writes are refused; set ENCLAVE_ADDRESS_BOOK="" to use the `
      + `baked addresses on purpose.\n`);
}

const cmd = args.shift();
if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") { say(HELP); exit(0); }
if (cmd === "version" || cmd === "--version") { say(VERSION); exit(0); }
if (!COMMANDS[cmd]) die(`unknown command "${cmd}"; run: enclave help`);
// `key new`/`key import` are purely local and `login`/`logout` touch only the
// API, so skip the address-book resolve — no reason to make them wait on an RPC.
// `session …` reads only the sessions relay and the session's own vault (`session delegate` reads the book itself).
const OFFLINE = cmd === "key" || cmd === "login" || cmd === "logout" || cmd === "session";
try {
  configureContractPins();
  if (cmd === "deploy" && args.includes("--chain-only") && !CONTRACT_PINS)
    throw new Error("--chain-only requires --contract-pins (or ENCLAVE_CONTRACT_PINS_FILE)");
  if (!OFFLINE) await resolveAddressBook();
  await COMMANDS[cmd](args);
} catch (e) {
  die(e?.message || String(e));
}
