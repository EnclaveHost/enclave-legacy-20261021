/* ============================================================
   Base chain access - hand-rolled ABI codec (verified vs viem),
   a rotating pool of public RPCs for reads, and the
   EnclaveDeployments / EnclaveAppCatalog contract surface.
   No web3 library loads on the site.
   ============================================================ */
import { APP_CATALOG_ADDRESS, DEPLOYMENTS_ADDRESS, FEATURED_ADDRESS, REVIEWS_ADDRESS, HOST_REVIEWS_ADDRESS, APP_CATALOG_CHAIN, APP_CATALOG_RPCS } from "./config.js";
import { EnclaveError, Enclave } from "./api.js";
import { wait } from "./util.js";
import { fleetPrice } from "./pricing.js";

/* ---- word-level encoders ---- */
export const pad32 = (h) => h.replace(/^0x/, "").toLowerCase().padStart(64, "0");
export const encAddr = (a) => pad32(a.replace(/^0x/, ""));
export const encUint = (n) => pad32(BigInt(n).toString(16));
export const encBytes32 = (h) => { const x = h.replace(/^0x/, "").toLowerCase(); if (x.length !== 64) throw new EnclaveError("bad payment reference", 0); return x; };
// dynamic `bytes` tail: length word, then the data right-padded to a 32-byte boundary
export const encBytesTail = (hex) => { const x = hex.replace(/^0x/, "").toLowerCase(); return encUint(x.length / 2) + x.padEnd(Math.ceil(x.length / 64) * 64, "0"); };
export const randHex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), b => b.toString(16).padStart(2, "0")).join("");
// USDC has 6 decimals, but we FUND in whole cents (0.01 USDC granularity): a
// sub-cent amount encodes as a tiny raw value that wallets render as "0 USDC"
// (and buys no meaningful runtime), so round to cents. NaN-safe (empty field -> 0).
export const usdc6 = (amt) => BigInt(Math.round((parseFloat(amt) || 0) * 100)) * 10000n;
export const hexBig = (h) => (!h || h === "0x") ? 0n : BigInt(h);

/* ---- EnclaveDeployments: on-chain work items (contracts/DEPLOYMENTS.md) ----
   create() from the deployer's wallet (they own the record), fund it
   (EIP-3009 USDC or ETH), and enclaves claim + serve it under expiring
   leases - so a deployment outlives any single enclave, its update, or
   its crash. */
export const DEP_SEL = { create:"36aaac4b",   // rev >= 8: (..., feeRecipient, feePerSec6, maxRate6) - the spend ceiling
                         createV4:"e99c6ae0", // rev 4-7: (..., configCid, feeRecipient, feePerSec6) - the publisher-fee snapshot
                         createV3:"11835efe", // rev 2-3: no fee args
                         createV1:"1a8e502a", // rev 1: extra sshPubKey string before configCid
                         fund:"e46bbc9e", fundAuth:"209c0069", fundEth:"9f33dca0", get:"8eaa6ac0",
                         price:"1e897c58", cpuPrice:"3f6195cc", setActive:"6485d678", setAppRef:"4d506615", maxGpuMilli:"4c8c5963",
                         feeOf:"430062bd", maxFeePerSec6:"95b957d7",
                         setShares:"00bc2be4",  // rev >= 6: owner share resize, re-priced at the serving enclave
                         setConfig:"df6e40ba",  // owner rewrite of the options envelope (waf + config namespaces)
                         setMaxRate:"2d3e461f", // rev >= 8: move the hourly spend ceiling (which enclaves may run it)
                         capOf:"6cc6a48c",      // rev >= 8: read that ceiling (0 = a grandfathered, uncapped import)
                         refund:"7249fbb6",     // rev >= 10: cancel + return the unused runtime the ledger still HOLDS
                         refundableOf:"bfa34835", // rev >= 10: exactly what refund() pays (not an estimate)
                         ownerEscrow6:"0711f45b", // rev >= 10: the owner-contributed escrow (the refund cap; also half the transfer gate)
                         earnOf:"a4a3e7a4",     // rev >= 7: (runnerRate6, escrow6, creditedUntil) - escrow6 is the other half of the transfer gate
                         transferDeployment:"dd68b480", // rev >= 11: hand the record (control, never money) to another wallet, one-shot; reverts "refund first" while owner escrow is held
                         multicall:"ac9650d8", // self-delegatecall batcher: setAppRef + setShares ride one signature
                         deploymentsSchema:"5d1b72b6" };  // shape-revision marker (reverts on rev-1 contracts;
                                                         // rev 3 = rev-2 struct + setAppRef version changes;
                                                         // rev 4 = same struct + the publisher-fee surface;
                                                         // rev 6 = same struct + the setShares resize surface;
                                                         // rev 8 = same struct, NO platform price (each enclave
                                                         // posts its own) + the per-deployment rate cap)
export const DEP_CREATED_TOPIC = "0x3b201eb11e77934b296f908775fc0a82679683fd83a1232579f1014bcf7d3239"; // Created(bytes32,address,string,uint16,uint16,uint256)
export const DEP_SCHEMA = [   // mirrors EnclaveDeployments.Deployment field order exactly (schema rev 2)
  {k:"id",t:"bytes32"},{k:"owner",t:"addr"},{k:"appRef",t:"str"},{k:"ports",t:"str"},
  {k:"configCid",t:"str"},{k:"gpuMilli",t:"uint"},{k:"cpuMilli",t:"uint"},
  {k:"appPort",t:"uint"},{k:"isPublic",t:"bool"},{k:"active",t:"bool"},{k:"createdAt",t:"uint"},
  {k:"rate",t:"uint"},{k:"balance6",t:"uint"},{k:"spent6",t:"uint"},
  {k:"runner",t:"bytes32"},{k:"runnerOperator",t:"addr"},{k:"leaseUntil",t:"uint"},
];
// rev 1 carried an sshPubKey string (the removed owner-access channel); the
// slot survives here only to read rev-1 contracts and is dropped on decode.
export const DEP_SCHEMA_V1 = [...DEP_SCHEMA.slice(0, 4), {k:"sshPubKey",t:"str"}, ...DEP_SCHEMA.slice(4)];
// Which struct/create shape the (book-resolved) deployments contract speaks:
// one cached eth_call to deploymentsSchema(); rev-1 contracts revert -> 1.
//
// Only a REVERT may take that fallback: the getters never legitimately return
// empty (emptyRetry rotates the pool and throws), so a transport failure is
// UNKNOWN, and caching a legacy rev off one poisons the whole session — the
// live ledger decodes with the wrong schema and every rev-gated feature
// vanishes. Seen live on the catalog sniff right after the rev-8 cutover
// (fresh address + lagging public RPCs -> "rev 2" -> publishes refused).
// Callers already handle throws: the uncached path (depCall/ethCall) throws
// on the same RPC trouble today.
const isRevertErr = (e) => /revert/i.test((e && e.message) || "");
let _depRev = null;
export async function depSchemaRev(){
  if (_depRev) return _depRev;
  try { const r = await depCall("0x" + DEP_SEL.deploymentsSchema); _depRev = Number(hexBig(r)) || 1; }
  catch(e){ if (!isRevertErr(e)) throw e; _depRev = 1; }
  return _depRev;
}

/* ---- EnclaveAppCatalog ---- */
export const CAT_SEL = {
  getApp:"42c71f1d", appCount:"b55ca2c3", getAppsPage:"a0483de1", getVersionsPage:"2eb7c1f0", owner:"8da5cb5b",
  publishVersion:"47910c23",   // rev >= 5: publishVersion(...,uint32[4] res,string ports,string config,uint256 feePerSec6)
  publishVersionV4:"ffd9de8f", // rev-4 catalogs: same without the fee arg (kept until the cutover)
  publishVersionV2:"adbf439a", // rev-2 catalogs: same without the config arg (kept until the cutover)
  versionFee:"82869209",       // rev >= 5: the per-version publisher fee (side mapping - tuples decode on every rev)
  publishVersionCfg:"7e2b4404",// rev >= 7: ...,string ports,string config,string configCid,uint256 feePerSec6 — `config` is the routing manifest here, configCid names the real one
  versionConfigCid:"637d5777", // rev >= 7: where a version's config lives ("" = it is inline in `config`, as on every earlier rev)
  versionConfigCids:"5ea1708a",// rev >= 7: all of one app's config CIDs at once, index-aligned with getVersionsPage
  maxFeePerSec6:"95b957d7",    // rev >= 5: publish-time cap on that fee
  catalogSchema:"18cccf57",    // struct-schema revision marker: 5 = rev-4 tuples + the publisher-fee
                               // surface; 4 = Version carries config; 3 = the short-lived
                               // app-level-config layout (versions config-LESS); missing = 2
  setActive:"9e4b5d56", yankVersion:"345c52dc", setVerified:"4ca171e5",
  setApproval:"a67613fa",
  grantCid:"353aa20f",         // grantCid(string,bytes32) - owner-only anti-squat remedy:
                               // authorizes ONE other app to list an already-claimed CID
};
// Version.approval: the owner's deploy-gating ruling (unlike `verified`, a curation signal)
export const APPROVAL = { pending:0, approved:1, rejected:2 };
// `config` is the catalog's INLINE ceiling — a hard on-chain constant
// (MAX_CONFIG), not a dial. `configMax` is what a config may total once it
// stops riding the record: past the inline limit the publish path pins the JSON
// and the version stores its CID instead (rev 7), so this is the pin gateway's
// and the runner's shared ceiling rather than the chain's.
export const CAT_MAX = { slug:40, name:80, desc:500, version:32, cid:100, mb:1048576, gflops:10000000,
                         config:4096, configMax:1048576 };
// The keys read straight off the CHAIN RECORD, by readers that have no CID to
// fetch yet or no business fetching one. When a config moves to a CID these
// stay behind in the inline field as the on-chain manifest; everything else
// moves. Derived at publish, never hand-typed.
//   wasi/threads/set/gpuOptional - a runner PLACES a deployment on these before
//     it fetches anything; lose them and a p3/threaded/GPU-optional app routes
//     to a box that cannot run it.
//   volumes - the same, for attested model volumes: volumeGate refuses a box
//     that doesn't carry the named volume, and a box that claims one it lacks
//     can only claim-fail-release in a loop.
//   _media - the catalog grid reads tile art from the record while rendering
//     hundreds of versions; lose it and every large-config app loses its
//     artwork, or the grid starts doing an IPFS fetch per tile.
// They stay in the PINNED config too (the app ignores keys it doesn't know), so
// the delivered ENCLAVE_CONFIG is still the complete document the publisher
// wrote — the manifest is a projection, not a split.
export const ROUTING_KEYS = ["wasi", "threads", "set", "mem64", "gpuOptional", "cpuFallback", "volumes", "_media"];
export const APP_SCHEMA = [
  {k:"appId",t:"bytes32"},{k:"publisher",t:"addr"},{k:"slug",t:"str"},{k:"name",t:"str"},
  {k:"description",t:"str"},{k:"versionCount",t:"uint"},{k:"createdAt",t:"uint"},{k:"updatedAt",t:"uint"},{k:"active",t:"bool"},
];
export const VER_SCHEMA = [
  {k:"cid",t:"str"},{k:"version",t:"str"},{k:"vramMb",t:"uint"},{k:"gpuGflops",t:"uint"},{k:"memMb",t:"uint"},{k:"cpuGflops",t:"uint"},{k:"createdAt",t:"uint"},{k:"verified",t:"bool"},{k:"yanked",t:"bool"},{k:"ports",t:"str"},{k:"approval",t:"uint"},
  {k:"config",t:"str"},   // default/template ENCLAVE_CONFIG JSON - IMMUTABLE, covered by the version's approval (schema rev 3; appended last).
                          // rev 7: when versionConfigCid() is non-empty this is the ROUTING MANIFEST instead, and the fetched CID is the app's config.
];

export function catConfigured(){ return APP_CATALOG_ADDRESS && !/^0x0+$/i.test(APP_CATALOG_ADDRESS); }
export function catExplorer(){ return APP_CATALOG_CHAIN === 84532 ? "https://sepolia.basescan.org" : "https://basescan.org"; }

/* ---- EnclaveFeatured: the store's featured slot, sold by per-view bid ----
   Campaigns escrow USDC per appId; readers rank the standing bids (highest
   funded bid whose app is approved + listed wins - the RANKING lives here on
   the read side by design, see the contract header). Selectors from
   site/js/gen/contract-artifacts.js (viem-derived). */
export const FEAT_SEL = {
  campaignCount:"7274e30d", getCampaignsPage:"8f5825d8", getCampaign:"cabe0452",
  featuredSchema:"ac580698", maxBidPerView6:"37ab19a0",
  place:"22525b0e", fund:"e46bbc9e", fundAuth:"209c0069",   // fund/fundAuth are signature-identical to the deployments pair
  withdraw:"040cf020", setActive:"6485d678", settle:"79f48d4c",
};
export const CAMPAIGN_SCHEMA = [   // mirrors EnclaveFeatured.Campaign field order exactly (featuredSchema 1)
  {k:"appId",t:"bytes32"},{k:"advertiser",t:"addr"},{k:"bidPerView6",t:"uint"},
  {k:"balance6",t:"uint"},{k:"spent6",t:"uint"},{k:"createdAt",t:"uint"},{k:"active",t:"bool"},
];
export function featConfigured(){ return FEATURED_ADDRESS && !/^0x0+$/i.test(FEATURED_ADDRESS); }
export async function featCall(data){
  return (await baseRpc("eth_call", [{ to: FEATURED_ADDRESS, data }, "latest"], { emptyRetry: true })) || "0x";
}
export async function featGetCampaigns(){
  const n = Number(hexBig(await featCall("0x" + FEAT_SEL.campaignCount)));
  const out = []; const PAGE = 100;
  for (let s = 0; s < n; s += PAGE)
    out.push(...decodeStructArray(await featCall(encCall(FEAT_SEL.getCampaignsPage, [{t:"uint",v:s},{t:"uint",v:PAGE}])), CAMPAIGN_SCHEMA));
  return out;
}
export async function featMaxBid(){ return hexBig(await featCall("0x" + FEAT_SEL.maxBidPerView6)); }

/* ---- EnclaveReviews: 1-5 stars + comments, gated on a funded deployment ----
   The contract checks the receipt itself (it reads EnclaveDeployments), so
   the site's job is only to FIND the caller's qualifying deployment and hand
   its id to post(). Selectors from site/js/gen/contract-artifacts.js. */
export const REV_SEL = {
  post:"131c2e70", setHidden:"4431f07c", canReview:"efc9ce6a",
  reviewCount:"2891e4ce", getReviewsPage:"0f9f0a97", getReview:"df46153a",
  tallyOf:"b4a6def1", talliesOf:"e6f706f7", reviewsSchema:"7e9ca439",
  owner:"8da5cb5b", MAX_BODY:"f77b4942",
  ledger:"56397c35",             // the ledger it checks receipts against NOW (resolved through the address book)
  ledgerFallback:"7e1ffc65", setLedgerFallback:"7da3ffcb", book:"05a8da72",
};
export const REVIEW_SCHEMA = [   // mirrors EnclaveReviews.Review field order exactly (reviewsSchema 1)
  {k:"reviewer",t:"addr"},{k:"stars",t:"uint"},{k:"hidden",t:"bool"},
  {k:"createdAt",t:"uint"},{k:"updatedAt",t:"uint"},{k:"deployment",t:"bytes32"},{k:"body",t:"str"},
];
export const REVIEW_MAX_BODY = 2000;   // the contract's cap; the form counts against it before the wallet opens
export function revConfigured(){ return REVIEWS_ADDRESS && !/^0x0+$/i.test(REVIEWS_ADDRESS); }
export async function revCall(data){
  return (await baseRpc("eth_call", [{ to: REVIEWS_ADDRESS, data }, "latest"], { emptyRetry: true })) || "0x";
}
// decode talliesOf's (uint32[] counts, uint32[] sums) back onto the appIds we
// asked about - two parallel arrays, so the pairing is positional
export function decodeTallies(hex, appIds){
  const buf = (hex || "").replace(/^0x/, "");
  if (buf.length < 128) return [];
  const ru = (o) => Number(BigInt("0x" + buf.slice(o * 2, o * 2 + 64)));
  const cOff = ru(0), sOff = ru(32);
  const n = Math.min(ru(cOff), ru(sOff), appIds.length);
  const out = [];
  for (let i = 0; i < n; i++) out.push({ appId: appIds[i], count: ru(cOff + 32 + i * 32), sum: ru(sOff + 32 + i * 32) });
  return out;
}
// every visible rating for a set of apps in ONE call - the store grid's read
// (returns [{appId, count, sum}], count 0 = unrated)
export async function revTallies(appIds){
  if (!appIds.length) return [];
  return decodeTallies(await revCall(encCall(REV_SEL.talliesOf, [{ t:"bytes32[]", v: appIds }])), appIds);
}
// one app's reviews, every page (an app with thousands of them is a good
// problem; the list view pages client-side)
export async function revGetReviews(appId){
  const n = Number(hexBig(await revCall(encCall(REV_SEL.reviewCount, [{ t:"bytes32", v: appId }]))));
  const out = []; const PAGE = 50;
  for (let s = 0; s < n; s += PAGE)
    out.push(...decodeStructArray(await revCall(encCall(REV_SEL.getReviewsPage,
      [{ t:"bytes32", v: appId }, { t:"uint", v: s }, { t:"uint", v: PAGE }])), REVIEW_SCHEMA));
  return out;
}
// does the contract accept this (app, deployment, wallet) triple? Asked BEFORE
// the wallet signature, so a refusal is a sentence and not a reverted tx.
export async function revCanReview(appId, deploymentId, who){
  const r = await revCall(encCall(REV_SEL.canReview,
    [{ t:"bytes32", v: appId }, { t:"bytes32", v: deploymentId }, { t:"addr", v: who }]));
  return hexBig(r) === 1n;
}
/* ---- EnclaveHostReviews: the same shape, subject = an ENCLAVE ----
   Ratings for the boxes that RUN apps. Identical function signatures to
   EnclaveReviews (so the selectors and the Review decoder are shared - only
   the target address differs), plus hasReviewed: a wallet that already rated
   a host may edit without a fresh receipt, because `runner` names the CURRENT
   lease holder and yours moves. */
export const HREV_SEL = { ...REV_SEL, hasReviewed: "a20daec2", hostReviewsSchema: "63d14beb" };
export function hrevConfigured(){ return HOST_REVIEWS_ADDRESS && !/^0x0+$/i.test(HOST_REVIEWS_ADDRESS); }
export async function hrevCall(data){
  return (await baseRpc("eth_call", [{ to: HOST_REVIEWS_ADDRESS, data }, "latest"], { emptyRetry: true })) || "0x";
}
// every live box's rating in ONE call - the fleet panel's read
export async function hrevTallies(enclaveIds){
  if (!enclaveIds.length || !hrevConfigured()) return [];
  const rows = decodeTallies(await hrevCall(encCall(HREV_SEL.talliesOf, [{ t:"bytes32[]", v: enclaveIds }])), enclaveIds);
  return rows.map((r) => ({ enclaveId: r.appId, count: r.count, sum: r.sum }));
}
export async function hrevGetReviews(enclaveId){
  const n = Number(hexBig(await hrevCall(encCall(HREV_SEL.reviewCount, [{ t:"bytes32", v: enclaveId }]))));
  const out = []; const PAGE = 50;
  for (let s2 = 0; s2 < n; s2 += PAGE)
    out.push(...decodeStructArray(await hrevCall(encCall(HREV_SEL.getReviewsPage,
      [{ t:"bytes32", v: enclaveId }, { t:"uint", v: s2 }, { t:"uint", v: PAGE }])), REVIEW_SCHEMA));
  return out;
}
// asked BEFORE the wallet signature, so a refusal is a sentence not a revert
export async function hrevCanReview(enclaveId, deploymentId, who){
  const r = await hrevCall(encCall(HREV_SEL.canReview,
    [{ t:"bytes32", v: enclaveId }, { t:"bytes32", v: deploymentId || "0x" + "0".repeat(64) }, { t:"addr", v: who }]));
  return hexBig(r) === 1n;
}
export async function hrevMine(enclaveId, who){
  return decodeStruct(await hrevCall(encCall(HREV_SEL.getReview,
    [{ t:"bytes32", v: enclaveId }, { t:"addr", v: who }])), REVIEW_SCHEMA);
}

export async function revOwner(){ const r = await revCall("0x" + REV_SEL.owner); return "0x" + (r || "").replace(/^0x/, "").slice(24).padStart(40, "0"); }

/* ---- read side: JSON-RPC against a POOL of public Base RPCs ----
   Rotates to the next endpoint on transport errors and rate limits; a
   contract REVERT is deterministic and thrown immediately (retrying it 8x
   would just burn the pool). One short breather between rounds.
   opts.emptyRetry: rate-limited public RPCs sometimes answer eth_call with
   200 + result:"0x" instead of an error (seen live - it once poisoned the
   relay's schema sniff, and the addressbook guards against it too). Our
   contract getters never legitimately return "0x" (a missing getter is a
   REVERT), so under the flag an empty result rotates like any transport
   error; if every endpoint agrees it throws, and callers keep their
   error paths instead of caching a zero. */
let _rpcIdx = 0;
export async function baseRpc(method, params, opts){
  let lastErr = null;
  for (let attempt = 0; attempt < APP_CATALOG_RPCS.length * 2; attempt++){
    const url = APP_CATALOG_RPCS[_rpcIdx % APP_CATALOG_RPCS.length];
    try {
      const r = await fetch(url, { method:"POST", headers:{ "content-type":"application/json" },
        body: JSON.stringify({ jsonrpc:"2.0", id:1, method, params }),
        signal: AbortSignal.timeout(8000) });   // fail fast and rotate; a hung RPC must not freeze flows
      if (!r.ok) throw new EnclaveError("HTTP " + r.status, r.status);
      const j = await r.json();
      if (j.error){
        if (/revert/i.test(j.error.message || "")) throw { fatal: true, err: new EnclaveError(j.error.message, 0) };
        throw new EnclaveError(j.error.message || "rpc error", 0);
      }
      if (opts && opts.emptyRetry && (j.result == null || j.result === "0x" || j.result === ""))
        throw new EnclaveError("empty eth_call result", 0);
      return j.result;                       // null is a valid result (e.g. pending receipt)
    } catch(e){
      if (e && e.fatal) throw e.err;
      lastErr = (e instanceof EnclaveError) ? e : new EnclaveError(e.message || String(e), 0);
      _rpcIdx++;
      if (attempt === APP_CATALOG_RPCS.length - 1) await wait(700);
    }
  }
  throw lastErr || new EnclaveError("all Base RPC endpoints failed", 0);
}
export async function ethCall(data){
  return (await baseRpc("eth_call", [{ to: APP_CATALOG_ADDRESS, data }, "latest"], { emptyRetry: true })) || "0x";
}
export async function depCall(data, block = "latest"){
  return (await baseRpc("eth_call", [{ to: DEPLOYMENTS_ADDRESS, data }, block], { emptyRetry: true })) || "0x";
}
// EnclaveDeployments.get(id) -> one Deployment struct (see DEP_SCHEMA). The tuple
// contains dynamic strings, so the return is offset-prefixed like a dynamic type.
export async function depGet(id, block = "latest"){
  const schema = (await depSchemaRev()) >= 2 ? DEP_SCHEMA : DEP_SCHEMA_V1;
  const obj = decodeStruct(await depCall("0x" + DEP_SEL.get + pad32(id.replace(/^0x/, "")), block), schema);
  return obj && Number(obj.createdAt) ? obj : null;           // a never-created id decodes to an all-zero record
}
// Lease expiry uses the chain's clock, not the browser's. Pin the deployment
// read to that same block so RPC rotation cannot mix times and lease states.
export async function depSnapshot(id){
  const block = await baseRpc("eth_getBlockByNumber", ["latest", false]);
  if (!/^0x[0-9a-f]+$/i.test(block?.number || "")
    || !/^0x[0-9a-f]+$/i.test(block?.timestamp || "")
    || !Number.isSafeInteger(Number(block.timestamp)) || Number(block.timestamp) <= 0)
    throw new EnclaveError("Unable to verify the current lease time. Try again.", 0);
  const d = await depGet(id, block.number);
  return d ? { ...d, blockNumber: Number(block.number), blockTimestamp: Number(block.timestamp) } : null;
}
// The live full-card / full-node per-second prices (6dp USDC), read once and
// cached: EVERY money estimate must come from these, never from client
// constants (and the create's ceil-to-1-micro-USDC floor makes small
// deployments cost more than the linear formula suggests).
//
// Rev 8 moved pricing OFF the contract: each enclave posts its own in its
// registry entry and charges it when it claims, so the number a new deployment
// will pay is the CHEAPEST live enclave's — read from /availability, which
// pricing.js has already adopted. Older ledgers keep the two global getters.
let _prices6 = null;
export async function depPrices6(){
  if (_prices6) return _prices6;
  if ((await depSchemaRev()) >= 8) {
    const p = fleetPrice();
    _prices6 = { gpu: BigInt(Math.round(p.full * 1e6)), cpu: BigInt(Math.round(p.node * 1e6)), live: p.live };
    if (!p.live) _prices6 = null;          // fallback constants: don't cache, retry after /availability lands
    return _prices6 || { gpu: BigInt(Math.round(p.full * 1e6)), cpu: BigInt(Math.round(p.node * 1e6)), live: false };
  }
  const [p, c] = await Promise.all([
    depCall("0x" + DEP_SEL.price), depCall("0x" + DEP_SEL.cpuPrice)]);
  _prices6 = { gpu: BigInt(p || "0x0"), cpu: BigInt(c || "0x0"), live: true };
  return _prices6;
}
// A deployment's spend ceiling (rev >= 8; 0 on older ledgers and on imported
// records that were never given one). USDC 6dp per second, like every rate.
export async function depCapOf(id){
  if ((await depSchemaRev()) < 8) return 0n;
  try { return hexBig(await depCall("0x" + DEP_SEL.capOf + pad32(id.replace(/^0x/, "")))); }
  catch { return 0n; }
}
// What cancelling a deployment would pay its owner right now (rev >= 10; USDC
// 6dp). This is the HELD escrow that no lease can still claim — NOT the
// deployment's balance: the publisher fee and the platform share were forwarded
// to their wallets when the deployment was funded, so a refund can never return
// them. Always render this number rather than balance6 next to a refund action.
// 0 on older ledgers, so the UI simply never offers the action there.
export async function depRefundableOf(id){
  if ((await depSchemaRev()) < 10) return 0n;
  try { return hexBig(await depCall("0x" + DEP_SEL.refundableOf + pad32(id.replace(/^0x/, "")))); }
  catch { return 0n; }
}
// The operator-set per-deployment GPU-share cap (milli of one card), read once
// and cached like the prices. create() refuses gpuMilli above it, so every
// deploy path checks BEFORE the wallet signature. Contracts predating the cap
// have no getter (the call reverts / returns empty) -> 1000 = a whole card,
// i.e. uncapped. NOTE: 0 is a real value (GPU creates paused), hence != null.
let _maxGpu = null;
export async function depMaxGpuMilli(){
  if (_maxGpu != null) return _maxGpu;
  try { const r = await depCall("0x" + DEP_SEL.maxGpuMilli); _maxGpu = (!r || r === "0x") ? 1000 : Number(hexBig(r)); }
  // revert = no getter = pre-cap contract = genuinely uncapped. Transport
  // trouble must not cache "uncapped": the check exists to refuse BEFORE the
  // wallet signature, and a poisoned 1000 waves through a create the chain
  // then rejects as a gas-estimation hang (same rule as the schema sniffs).
  catch(e){ if (!isRevertErr(e)) throw e; _maxGpu = 1000; }
  return _maxGpu;
}
// The contract's exact per-second rate (6dp USDC) for two share dials in
// 1/1000ths - mirrors create()'s ceil math so estimates match on-chain.
// NOTE: platform shares only - a paid app's publisher fee (catVersionFee)
// is added ON TOP by create(), so money displays must add it themselves.
export const rate6Of = (pr, gpuMilli, cpuMilli) =>
  (pr.gpu * BigInt(gpuMilli) + pr.cpu * BigInt(cpuMilli) + 999n) / 1000n;
export async function depRate6(gpuMilli, cpuMilli){
  return rate6Of(await depPrices6(), gpuMilli, cpuMilli);
}
// The deployment's publisher-fee snapshot (rev >= 4 ledgers; earlier ones
// structurally have none). Returns { recipient, feePerSec6 } - feePerSec6 is
// INSIDE the record's rate, not on top of it.
export async function depFeeOf(id){
  if ((await depSchemaRev()) < 4) return { recipient: null, feePerSec6: 0n };
  const hex = (await depCall("0x" + DEP_SEL.feeOf + pad32(id.replace(/^0x/, "")))).replace(/^0x/, "");
  if (hex.length < 128) return { recipient: null, feePerSec6: 0n };
  return { recipient: "0x" + hex.slice(24, 64), feePerSec6: BigInt("0x" + hex.slice(64, 128)) };
}

/* ---- minimal ABI codec (generic encode + struct-array decode), verified vs viem ---- */
export function encStr(s){
  const b = new TextEncoder().encode(s); let h = "";
  for (const x of b) h += x.toString(16).padStart(2, "0");
  return { body: encUint(b.length) + h.padEnd(Math.ceil(h.length / 64) * 64, "0"), words: 1 + Math.ceil(b.length / 32) };
}
// args: [{t:'str'|'uint'|'bool'|'addr'|'bytes32'|'bytes32[]'|'addr[]'|'bytes[]', v}]; head (offsets/inline) then dynamic tails.
export function encCall(selector, args){
  let off = args.length * 32; const heads = [], bodies = [];
  for (const a of args){
    if (a.t === "str"){ const e = encStr(a.v); heads.push(encUint(off)); off += e.words * 32; bodies.push(e.body); }
    else if (a.t === "bytes32[]" || a.t === "addr[]"){
      const items = a.v.map(x => pad32(String(x).replace(/^0x/, "")));
      heads.push(encUint(off)); off += (1 + items.length) * 32;
      bodies.push(encUint(items.length) + items.join(""));
    }
    else if (a.t === "bytes[]"){
      // dynamic array of dynamic bytes (multicall's calldata list): length,
      // then per-item offsets relative to the array body, then each item as
      // len + right-padded data - verified against viem in test/
      const items = a.v.map(x => { const h = String(x).replace(/^0x/, "");
        return encUint(h.length / 2) + h.padEnd(Math.ceil(h.length / 64) * 64, "0"); });
      let ioff = items.length * 32; const iheads = [];
      for (const it of items){ iheads.push(encUint(ioff)); ioff += it.length / 2; }
      heads.push(encUint(off)); off += 32 + ioff;
      bodies.push(encUint(items.length) + iheads.join("") + items.join(""));
    }
    else if (a.t === "uint") heads.push(encUint(a.v));
    else if (a.t === "bool") heads.push(encUint(a.v ? 1 : 0));
    else heads.push(pad32(a.v.replace(/^0x/, "")));   // addr | bytes32
  }
  return "0x" + selector + heads.join("") + bodies.join("");
}
export function hexToUtf8(h){ const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16); return new TextDecoder().decode(b); }
// decode ONE returned struct (a getter's `T memory`): the return is
// offset-prefixed like any dynamic type, then the tuple's own head. Field
// offsets inside a tuple are relative to the TUPLE's start, so a schema that
// stops short of a contract's appended fields still decodes correctly.
export function decodeStruct(hex, schema){
  const buf = (hex || "").replace(/^0x/, "");
  if (buf.length < 64) return null;
  const ru = (o) => BigInt("0x" + buf.slice(o * 2, o * 2 + 64));
  const ts = Number(ru(0));                                    // offset to the tuple head
  const obj = {};
  schema.forEach((f, fi) => {
    const w = ts + fi * 32;
    if (f.t === "str"){ const so = ts + Number(ru(w)); const len = Number(ru(so)); obj[f.k] = hexToUtf8(buf.slice((so + 32) * 2, (so + 32) * 2 + len * 2)); }
    else if (f.t === "uint") obj[f.k] = Number(ru(w));
    else if (f.t === "addr") obj[f.k] = "0x" + buf.slice(w * 2 + 24, w * 2 + 64);
    else if (f.t === "bool") obj[f.k] = ru(w) !== 0n;
    else obj[f.k] = "0x" + buf.slice(w * 2, w * 2 + 64);       // bytes32
  });
  return obj;
}
// decode a bare top-level `string` return (offset word, then length + bytes)
export function decodeString(hex){
  const buf = (hex || "").replace(/^0x/, "");
  if (buf.length < 128) return "";                             // no offset+length pair: treat as empty
  const ru = (o) => Number(BigInt("0x" + buf.slice(o * 2, o * 2 + 64)));
  const so = ru(0), len = ru(so);
  return len ? hexToUtf8(buf.slice((so + 32) * 2, (so + 32) * 2 + len * 2)) : "";
}
// decode a bare top-level `string[]`
export function decodeStringArray(hex){
  const buf = (hex || "").replace(/^0x/, "");
  if (buf.length < 128) return [];
  const ru = (o) => Number(BigInt("0x" + buf.slice(o * 2, o * 2 + 64)));
  const arrOff = ru(0), len = ru(arrOff), elems = arrOff + 32, out = [];
  for (let k = 0; k < len; k++){
    const so = elems + ru(elems + k * 32), n = ru(so);
    out.push(n ? hexToUtf8(buf.slice((so + 32) * 2, (so + 32) * 2 + n * 2)) : "");
  }
  return out;
}
// decode a dynamic T[] where T is a tuple of str|uint|bool|addr|bytes32 fields (per `schema`).
export function decodeStructArray(hex, schema){
  const buf = (hex || "").replace(/^0x/, "");
  if (buf.length < 64) return [];
  const ru   = (o) => BigInt("0x" + buf.slice(o * 2, o * 2 + 64));
  const radd = (o) => "0x" + buf.slice(o * 2 + 24, o * 2 + 64);
  const rb32 = (o) => "0x" + buf.slice(o * 2, o * 2 + 64);
  const rstr = (o) => { const len = Number(ru(o)); const s = (o + 32) * 2; return hexToUtf8(buf.slice(s, s + len * 2)); };
  const arrOff = Number(ru(0)), len = Number(ru(arrOff)), elems = arrOff + 32, out = [];
  // a struct with no dynamic members (no strings) encodes its array elements
  // INLINE - no per-element offset table (EnclaveFeatured.Campaign); dynamic
  // structs (catalog App/Version, Deployment) go through the offset words
  const isStatic = !schema.some(f => f.t === "str");
  for (let k = 0; k < len; k++){
    const ts = isStatic ? elems + k * schema.length * 32 : elems + Number(ru(elems + k * 32)), obj = {};
    schema.forEach((f, fi) => {
      const w = ts + fi * 32;
      if (f.t === "str") obj[f.k] = rstr(ts + Number(ru(w)));
      else if (f.t === "uint") obj[f.k] = Number(ru(w));
      else if (f.t === "addr") obj[f.k] = radd(w);
      else if (f.t === "bool") obj[f.k] = ru(w) !== 0n;
      else if (f.t === "bytes32") obj[f.k] = rb32(w);
    });
    out.push(obj);
  }
  return out;
}

/* ---- catalog reads ---- */
export async function appCount(){ return Number(hexBig(await ethCall("0x" + CAT_SEL.appCount))); }
/* Catalog struct-schema revision: rev 4 Version tuples carry `config`; a
   catalog without the marker getter (reverts) is rev 2; rev 3 (the retired
   app-level-config layout, live at 0xa036d5e8… on 2026-07-08) has config-LESS
   versions - decoding them with the rev-4 schema reads past the tuple and
   yields garbage "config" strings (seen live). Sniffed once per page load. */
export const VER_SCHEMA_V2 = VER_SCHEMA.filter(f => f.k !== "config");
let _catRev = null;
export async function catSchemaRev(){
  if (_catRev) return _catRev;
  try { _catRev = Number(hexBig(await ethCall("0x" + CAT_SEL.catalogSchema))) || 2; }
  // revert = the marker getter isn't there = a genuine rev-2 catalog. Anything
  // else is transport trouble and must PROPAGATE, not cache: one failed read
  // here once made a freshly cut-over catalog look rev 2 for the whole
  // session (config publishes refused, fees read 0, configs dropped from the
  // version decode) - see depSchemaRev's note.
  catch(e){ if (!isRevertErr(e)) throw e; _catRev = 2; }
  return _catRev;
}
// Per-version publisher fee (USDC 6dp per SECOND), rev-5 catalogs only. The
// fee lives in a side mapping (so Version tuples decode unchanged on every
// rev); pre-rev-5 catalogs structurally have no fees -> 0n without a call.
// Cached per record: fees are immutable once published. Throws on RPC
// trouble - deploy flows treat "can't know the fee" as a refusal, not a 0.
const _verFee = {};
export async function catVersionFee(appId, index){
  const key = appId + "/" + index;
  if (_verFee[key] != null) return _verFee[key];
  if ((await catSchemaRev()) < 5) return (_verFee[key] = 0n);
  const r = await ethCall(encCall(CAT_SEL.versionFee, [{ t:"bytes32", v:appId }, { t:"uint", v:index }]));
  return (_verFee[key] = hexBig(r));
}
// Where a version's config actually lives (rev-7 catalogs only): "" means it
// is inline in the version's `config` field, as on every earlier rev; a CID
// means `config` is the on-chain manifest and the real one is at that CID.
// Side mapping, so Version tuples decode unchanged either way.
//
// Read ONE VERSION AT A TIME, on the deploy path only. The catalog grid must
// never call this per tile: it renders hundreds of versions, and the two things
// it needs off a record — tile art (_media) and the routing keys — are exactly
// what the manifest keeps on-chain for this reason. Cached per record: a
// version's config reference is immutable once published.
const _verCfgCid = {};
export async function catVersionConfigCid(appId, index){
  const key = appId + "/" + index;
  if (_verCfgCid[key] != null) return _verCfgCid[key];
  if ((await catSchemaRev()) < 7) return (_verCfgCid[key] = "");
  const r = await ethCall(encCall(CAT_SEL.versionConfigCid, [{ t:"bytes32", v:appId }, { t:"uint", v:index }]));
  return (_verCfgCid[key] = decodeString(r));
}
// The catalog's publish-time cap on that fee (rev >= 5; earlier catalogs
// take no fee at all, surfaced as 0).
export async function catMaxFeePerSec6(){
  if ((await catSchemaRev()) < 5) return 0n;
  return hexBig(await ethCall("0x" + CAT_SEL.maxFeePerSec6));
}
export async function catGetApp(appId){
  return decodeStruct(await ethCall(encCall(CAT_SEL.getApp, [{t:"bytes32",v:appId}])), APP_SCHEMA);
}
export async function catGetAppsPage(start, n){
  return decodeStructArray(await ethCall(encCall(CAT_SEL.getAppsPage, [{t:"uint",v:start},{t:"uint",v:n}])), APP_SCHEMA);
}
// A deployment may reference a version newer than the cached app listing.
// Read that exact record without depending on the listing's versionCount.
export async function catGetVersion(appId, index){
  const rev = await catSchemaRev();
  const versions = decodeStructArray(await ethCall(encCall(CAT_SEL.getVersionsPage,
    [{ t: "bytes32", v: appId }, { t: "uint", v: index }, { t: "uint", v: 1 }])), rev >= 4 ? VER_SCHEMA : VER_SCHEMA_V2);
  if (versions.length !== 1) throw new EnclaveError("The deployed app version is unavailable from the catalog.", 0);
  if (rev < 4) versions[0].config = "";
  return versions[0];
}
export async function catGetVersions(appId, count){
  const rev = await catSchemaRev();
  const schema = rev >= 4 ? VER_SCHEMA : VER_SCHEMA_V2;
  const vs = []; const PAGE = 50;
  for (let s = 0; s < count; s += PAGE)
    vs.push(...decodeStructArray(await ethCall(encCall(CAT_SEL.getVersionsPage, [{t:"bytes32",v:appId},{t:"uint",v:s},{t:"uint",v:PAGE}])), schema));
  if (rev < 4) for (const v of vs) v.config = "";
  // rev 7: where each version's config lives. ONE call for the whole history
  // (the side mapping is invisible to the tuple decoder, and a per-version read
  // would be an eth_call per tile). "" = inline, which is every version on
  // every earlier rev — so the field is simply absent below rev 7 and every
  // existing reader is unaffected.
  if (rev >= 7 && vs.length){
    try {
      const cids = decodeStringArray(await ethCall(encCall(CAT_SEL.versionConfigCids, [{t:"bytes32",v:appId}])));
      vs.forEach((v, i) => { v.configCid = cids[i] || ""; });
    } catch(e){ /* leave configCid unset: readers fall back to the inline field */ }
  }
  return vs;
}
export async function catOwner(){ const r = await ethCall("0x" + CAT_SEL.owner); return "0x" + (r || "").replace(/^0x/, "").slice(24).padStart(40, "0"); }

/* Wait for a receipt, and tell a DROPPED transaction from a slow one.
   Only ONE node can answer that: the one the wallet submitted through. A
   pending tx lives in THAT node's mempool and gossips to independent nodes on
   its own schedule, so "a public RPC has not heard of it" is not evidence of
   anything — least of all within a few seconds, and least of all from a
   ROTATING pool where each check may land on a different node. An earlier
   version of this asked exactly that question and aborted healthy migrations
   on the answer, while claiming nothing had been sent. Absence of evidence
   from a node that never accepted the transaction is not evidence of absence. */
export async function waitReceipt(hash, tries){
  tries = tries || 45;
  const DROP_AFTER = 20;            // ~40s: long enough that a live tx is in its own node's pool
  let seen = false;
  for (let i = 0; i < tries; i++){
    let rec = null;
    try { rec = await baseRpc("eth_getTransactionReceipt", [hash]); } catch(e){}
    if (rec){ if (hexBig(rec.status) === 0n) throw new EnclaveError("transaction reverted", 0); return rec; }
    if (!seen && i >= DROP_AFTER){
      // Ask the SUBMITTING provider. No provider (or an errored one) means we
      // cannot know, and we keep waiting rather than guess.
      let known = null;
      try {
        if (Enclave.provider)
          known = await Enclave.provider.request({ method: "eth_getTransactionByHash", params: [hash] });
      } catch(e){ known = undefined; }          // undefined = unknowable, not absent
      if (known) seen = true;
      else if (known === null && Enclave.provider)
        throw new EnclaveError("your wallet's RPC does not have this transaction " + Math.round(DROP_AFTER * 2) + "s after signing it: "
          + "it returned a hash but never relayed it. Check the wallet's own activity log for the reason — "
          + "\"FAILED_WOULD_REVERT\" there means the transaction would have reverted (usually an under-provisioned "
          + "gas limit, not an oversized batch), which MetaMask cancels before broadcast. "
          + "Confirm on the explorer before retrying — if it is genuinely absent, nothing was spent.", 0);
    }
    await new Promise(res => setTimeout(res, 2000));
  }
  throw new EnclaveError("timed out waiting for confirmation (it may still land; hit refresh shortly)", 0);
}
