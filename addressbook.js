// addressbook.js — the supervisor's contract-address root. Exports LIVE
// BINDINGS for the platform's contract addresses, seeded from the baked env
// (the measured enclave config) and — when ADDRESS_BOOK_ADDRESS is set —
// overridden from the on-chain EnclaveAddressBook at boot and re-polled, so
// a contract redeploy reaches running enclaves with ONE owner transaction
// instead of a release + dashboard update.
//
// Trust note (this is deliberate, documented policy): the book's owner is the
// platform governance key. With a book configured, WHICH contracts this
// enclave talks to is governed by that key at runtime; the measurement pins
// this code and the book's address, not the addresses inside it.
//
// import { APP_CATALOG_ADDRESS } from "./addressbook.js" — the value updates
// in place when the book changes (ES live bindings); process.env.* is kept in
// step for any child/tooling that reads env.

import { createPublicClient, http, fallback, getAddress } from "viem";
import { base } from "viem/chains";
import {loadContractPins} from './windows/node/host-admission.bundle.mjs';

export const CONTRACT_PINS=loadContractPins();

export let REGISTRY_ADDRESS      = process.env.REGISTRY_ADDRESS || "";
export let DEPLOYMENTS_ADDRESS   = process.env.DEPLOYMENTS_ADDRESS || "";
export let APP_CATALOG_ADDRESS   = process.env.APP_CATALOG_ADDRESS || "";
export let FORWARDER_ADDRESS     = process.env.FORWARDER_ADDRESS || "";
export let PROOF_OF_TIME_ADDRESS = process.env.PROOF_OF_TIME_ADDRESS || "";

const BOOK = (process.env.ADDRESS_BOOK_ADDRESS || "").trim();
const POLL_SEC = parseInt(process.env.ADDRESS_BOOK_POLL_SEC || "", 10) || 300;

const ABI = [{ type: "function", name: "all", stateMutability: "view", inputs: [],
               outputs: [{ type: "bytes32[]" }, { type: "address[]" }] }];
// book key (ascii bytes32) -> [env name, setter for the live binding]
const KEYS = {
  registry:     ["REGISTRY_ADDRESS",      (v) => { REGISTRY_ADDRESS = v; }],
  deployments:  ["DEPLOYMENTS_ADDRESS",   (v) => { DEPLOYMENTS_ADDRESS = v; }],
  appCatalog:   ["APP_CATALOG_ADDRESS",   (v) => { APP_CATALOG_ADDRESS = v; }],
  enclavePay:   ["FORWARDER_ADDRESS",     (v) => { FORWARDER_ADDRESS = v; }],
  proofOfTime:  ["PROOF_OF_TIME_ADDRESS", (v) => { PROOF_OF_TIME_ADDRESS = v; }],
};
const current = () => ({ registry: REGISTRY_ADDRESS, deployments: DEPLOYMENTS_ADDRESS,
  appCatalog: APP_CATALOG_ADDRESS, enclavePay: FORWARDER_ADDRESS,
  proofOfTime: PROOF_OF_TIME_ADDRESS });

// Pin at process start. A book owner cannot redirect an explicitly pinned host,
// even while the book is unavailable, cleared or publishing different addresses.
if(CONTRACT_PINS)for(const [name,[env,set]] of Object.entries(KEYS)){
  const address=CONTRACT_PINS[name];set(address);process.env[env]=address;
}

let client = null;
async function readBook() {
  // same multi-provider pool as supervisor.js RPC_POOL: the address book is
  // the root of contract resolution — a throttled single RPC must not pin the
  // fleet to stale addresses or block boot
  if (!client) client = createPublicClient({ chain: base,
    transport: fallback([...new Set([process.env.BASE_RPC || "https://mainnet.base.org",
      "https://base-rpc.publicnode.com", "https://base.drpc.org",
      "https://1rpc.io/base", "https://mainnet.base.org"])].map((u) => http(u, { retryCount: 2, retryDelay: 500 }))) });
  const [keysHex, values] = await client.readContract({ address: getAddress(BOOK), abi: ABI, functionName: "all" });
  const changed = [];
  keysHex.forEach((kh, i) => {
    let key = "";
    for (let b = 2; b < kh.length; b += 2) { const c = parseInt(kh.slice(b, b + 2), 16); if (!c) break; key += String.fromCharCode(c); }
    const ent = KEYS[key]; if (!ent) return;
    const v = getAddress(values[i]);
    if (/^0x0{40}$/i.test(v.slice(0))) return;               // zero = retired; keep the baked value
    const cur = current()[key] || "";
    if (cur.toLowerCase() === v.toLowerCase()) return;
    ent[1](v); process.env[ent[0]] = v;
    changed.push(`${ent[0]} ${cur || "(unset)"} -> ${v}`);
  });
  return changed;
}

/// Boot: block on one read (with the baked env as the fallback on failure),
/// then poll. Call this BEFORE anything derives state from the addresses.
export async function initAddressBook(log = console) {
  if(CONTRACT_PINS){log.log('[addressbook] immutable host contract pins active; book polling disabled');return false;}
  if (!BOOK) return false;
  try {
    const changed = await readBook();
    log.log(`[addressbook] resolved from ${BOOK}${changed.length ? " · " + changed.join(" · ") : " (matches baked env)"}`);
  } catch (e) {
    log.warn(`[addressbook] boot read failed (keeping the baked env): ${e.shortMessage || e.message}`);
  }
  const t = setInterval(async () => {
    try {
      const changed = await readBook();
      for (const c of changed) log.log(`[addressbook] ${c}`);
    } catch (e) { /* transient RPC trouble; next poll retries */ }
  }, POLL_SEC * 1000);
  if (t.unref) t.unref();
  return true;
}
