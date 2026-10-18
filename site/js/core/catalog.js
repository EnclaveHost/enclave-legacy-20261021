import {directUploadHeaders} from "./upload-auth.js";
/* ============================================================
   App store · on-chain catalog (EnclaveAppCatalog on Base) + IPFS CIDs
   Apps are versioned: keyed by keccak256(publisher, slug), each with an
   append-only list of releases (own CID, label, verified/yank flags).
   Browsing reads the contract via a public RPC eth_call (no wallet).

   This module is the shared READ side + the friendly-ref caches:
   the Apps page renders from it, and the Deploy page resolves
   slug:version references and pre-flights the deploy gate with it.
   Load progress is announced with `enclave:catalog` events (detail.type:
   loading | loaded | error) - pages render, this module doesn't.
   ============================================================ */
import { APP_CATALOG_ADDRESS, IPFS_IMG_GATEWAY, IPFS_JSON_UPLOAD_URL, IPFS_WALLET_AUDIENCE } from "./config.js";
import { catConfigured, appCount, catGetAppsPage, catGetVersions, catOwner, APPROVAL, CAT_MAX } from "./chain.js";
import { lsGet, lsSet, emit, on, esc } from "./util.js";
import { minPctsOf } from "./pricing.js";
import { Enclave, EnclaveError } from "./api.js";
import { connectWallet, personalSign } from "./wallet.js";

/* `filter` is the store tab. It opens on "featured": the approved list with the
   standing campaigns (or the editorial pick) lifted to the front, NOT a
   featured-only view. "approved" is the same list without that head group. */
export const STORE = { apps:[], byId:{}, sel:{}, owner:null, filter:"featured", loaded:false, loading:false, at:0 };

// firewall entry: http (default web app) | http:N | tcp:N | udp:N, N in 1-49999 (labels; <1024 always remapped)
// (1080/8080/8090/8091 are infra-reserved; the enclave enforces the same rules server-side)
export const FW_ENTRY_RE = /^(http|http:\d{1,5}|tcp:\d{1,5}|udp:\d{1,5})$/;
const FW_RESERVED = [1080, 8080, 8090, 8091];
export function validPortsCsv(s){
  const parts = String(s || "").split(",").map(x => x.trim().toLowerCase()).filter(Boolean);
  for (const p of parts){
    if (!FW_ENTRY_RE.test(p)) return "bad port spec '" + p + "' (use http[:N], tcp:N, udp:N)";
    const n = p.includes(":") ? +p.split(":")[1] : 0;
    if (n && (n < 1 || n > 49999 || FW_RESERVED.includes(n))) return "port " + n + " not allowed (1-49999, excluding " + FW_RESERVED.join("/") + ")";
  }
  return null;
}

// The last good catalog is cached in localStorage (stale-while-revalidate):
// paint it instantly, refresh behind it, and a failed refresh keeps the page
// usable instead of replacing it with an error wall.
// Bumped whenever a cached version object gains a field the UI now depends on.
// A cache written by an OLDER site build is not merely stale, it is missing
// that field — and the site deploys independently of the catalog contract, so
// the address in the key does not change when the site does. Rev 7 is the live
// example: without `configCid`, a large-config version reads as though its
// config were the small on-chain routing manifest, and the dashboard's Config
// tab would offer that manifest as the app's config for the user to "override".
const CAT_CACHE_V = 2;
export function catCacheGet(){
  try { const c = JSON.parse(lsGet("enclave_catalog_" + APP_CATALOG_ADDRESS) || "null");
        return (c && c.v === CAT_CACHE_V && Array.isArray(c.apps)) ? c : null; } catch(e){ return null; }
}
export function catCacheSet(apps){ lsSet("enclave_catalog_" + APP_CATALOG_ADDRESS, JSON.stringify({ v: CAT_CACHE_V, at: Date.now(), apps })); }

// A loaded store older than this re-reads (in the background, behind the
// current paint) on the next loadCatalog() - i.e. the next page boot. The
// session can't get stuck on one bad read: a store that loaded empty or
// stale heals on the next visit to the Apps page instead of holding
// until a hard refresh.
const FRESH_MS = 120000;
/* The owner read gates ALL moderation UI: approve/reject/verify and the
   Pending/Rejected/Delisted queues key off STORE.owner, and "owner unknown"
   renders identically to "not the owner". A swallowed one-shot failure
   therefore stripped the owner's controls for the whole page view with no
   error and no retry - and the burst right after a publish (receipt polling +
   the catalog reload) is exactly when the public-RPC pool rate-limits, so it
   read as "I can't approve apps" moments after a successful publish. Retry
   with backoff until it lands; the emit re-renders whichever view is up. */
let _ownerBusy = false, _ownerWait = 4000;
function loadOwner(){
  if (_ownerBusy || STORE.owner !== null) return;
  _ownerBusy = true;
  catOwner().then(o => {
    STORE.owner = o.toLowerCase(); _ownerBusy = false; _ownerWait = 4000;
    emit("enclave:catalog", { type: "loaded" });
  }).catch(() => {
    setTimeout(() => { _ownerBusy = false; loadOwner(); }, _ownerWait);
    _ownerWait = Math.min(_ownerWait * 2, 60000);
  });
}
/* ---- confirmed writes the read side hasn't caught up to ----
   A moderation transaction (approve / reject / verify / yank / delist) is
   SETTLED the moment its receipt lands: the chain holds the new state. What
   the UI shows next used to be a different question, and often the wrong one.
   The post-tx re-read goes to the rotating pool of public Base RPCs at exactly
   the moment our own receipt polling has been bursting against them, so it
   either fails outright ("catalog refresh failed - showing the last good
   read", the store keeping its PRE-approval paint) or lands on a replica that
   hasn't indexed the block yet and faithfully repaints the old ruling. Either
   way the owner approved a version and watched nothing happen until a manual
   page refresh minutes later.

   So a write whose receipt has landed is recorded here and re-applied over
   every catalog read until a FRESH read agrees with it (the replicas caught
   up - drop it) or it ages out. The receipt is the authority; a lagging
   replica is not evidence against it. Persisted, because the page refresh
   that used to be the workaround must not be the thing that loses the state.
   A read showing a THIRD value (neither ours nor what we overwrote) means the
   chain moved on without us - someone else's later write - and retires the
   entry too; the TTL is only the backstop under that. */
const WRITE_TTL = 900000;                  // 15 min: far past replica lag, far short of a real divergence
const WRITE_KEY = "enclave_catalog_writes_" + APP_CATALOG_ADDRESS;
let WRITES = null;
function writesLoad(){
  if (WRITES) return WRITES;
  WRITES = {};
  let dropped = false;
  try {
    const o = JSON.parse(lsGet(WRITE_KEY) || "{}"), now = Date.now();
    for (const k in o){
      if (o[k] && now - (o[k].at || 0) < WRITE_TTL) WRITES[k] = o[k];
      else dropped = true;
    }
  } catch(e){ WRITES = {}; dropped = true; }
  if (dropped) writesSave();               // expired entries leave for good, not just for this page
  return WRITES;
}
function writesSave(){ lsSet(WRITE_KEY, JSON.stringify(WRITES || {})); }
/* Re-apply the live writes over an apps[] (in place). `fresh` marks a read
   straight off the chain: only THAT can retire an entry, by agreeing with it
   (or by having moved past it). A cached/already-patched paint agrees with
   itself, so retiring on one would hand the next lagging replica the old
   value back. */
export function applyCatalogWrites(apps, fresh){
  const w = writesLoad(), now = Date.now();
  let changed = false;
  for (const k in w){
    const e = w[k];
    if (now - (e.at || 0) >= WRITE_TTL){ delete w[k]; changed = true; continue; }
    const app = (apps || []).find(a => a.appId === e.appId);
    // an app (or version) this read doesn't carry yet - nothing to write over,
    // and nothing to conclude either: hold the entry until a read shows it
    const tgt = !app ? null : (e.idx == null ? app : app.versions[e.idx]);
    if (!tgt) continue;
    // the read caught up, or it moved somewhere neither we nor the value we
    // overwrote put it (a later write from another tab/wallet) - either way
    // the chain is authoritative again and this entry stops speaking for it
    if (fresh && (tgt[e.field] === e.value || ("was" in e && tgt[e.field] !== e.was))){ delete w[k]; changed = true; }
    else tgt[e.field] = e.value;
  }
  if (changed) writesSave();
  return apps;
}
/* Record a confirmed write and show it at once: the store is patched in place,
   re-cached and announced, so the badge and the Pending/Approved queues move
   on the RECEIPT rather than on the next catalog read that happens to land. */
export function noteCatalogWrite(appId, idx, field, value){
  const w = writesLoad();
  const app = STORE.apps.find(a => a.appId === appId);
  const tgt = !app ? null : (idx == null ? app : app.versions[idx]);
  w[appId + "|" + (idx == null ? "app" : idx) + "|" + field] =
    { appId, idx: idx == null ? null : idx, field, value, at: Date.now(),
      ...(tgt && tgt[field] !== value ? { was: tgt[field] } : {}) };   // what a read still showing this hasn't seen yet
  writesSave();
  applyCatalogWrites(STORE.apps, false);
  if (STORE.loaded) catCacheSet(STORE.apps);
  emit("enclave:catalog", { type: "loaded" });
}
/* Resolves true when a fresh chain read landed. opts.quiet marks a read whose
   failure is not load-bearing (the caller has already painted a confirmed
   write): the error still emits, flagged, so pages can skip the alarm. */
export async function loadCatalog(force, opts){
  if (!catConfigured()){ STORE.loaded = true; emit("enclave:catalog", { type: "loaded" }); return true; }
  // the owner read rides every boot until it lands - ABOVE the freshness
  // early-return, so one rate-limited miss can't leave badges/official
  // fallbacks ownerless for as long as the catalog stays fresh
  if (STORE.owner === null) loadOwner();
  if (STORE.loading || (STORE.loaded && !force && Date.now() - STORE.at < FRESH_MS)) return false;
  STORE.loading = true;
  if (!STORE.loaded){
    const cached = catCacheGet();
    if (cached){
      applyCatalogWrites(cached.apps, false);
      STORE.apps = cached.apps; STORE.byId = {}; cached.apps.forEach(a => STORE.byId[a.appId] = a);
      STORE.loaded = true; STORE.at = cached.at || 0;
      emit("enclave:catalog", { type: "loaded", stale: true });
    } else emit("enclave:catalog", { type: "loading" });
  }
  try {
    const n = await appCount();
    const apps = []; const PAGE = 50;
    for (let s = 0; s < n; s += PAGE) apps.push(...await catGetAppsPage(s, PAGE));
    await Promise.all(apps.map(async a => { a.versions = await catGetVersions(a.appId, a.versionCount); }));
    applyCatalogWrites(apps, true);            // a confirmed ruling outranks a lagging replica
    STORE.apps = apps; STORE.byId = {}; apps.forEach(a => STORE.byId[a.appId] = a);
    STORE.loaded = true; STORE.at = Date.now();
    catCacheSet(apps);
  } catch(e){
    emit("enclave:catalog", { type: "error", message: e.message || String(e), quiet: !!(opts && opts.quiet) });
    STORE.loading = false; return false;
  }
  STORE.loading = false; emit("enclave:catalog", { type: "loaded" });
  return true;
}

/* ---- version selection helpers ---- */
// Yanked and rejected releases are the publisher's cleanup and the owner's
// moderation surface, not the store's: normal browsers never see them (the
// enclave refuses to deploy them anyway - resolveAppRef below). The app's
// publisher and the catalog owner see everything, since these states are
// exactly what they act on (yank/approve/reject buttons).
export const appPrivileged = (app) => {
  const me = (Enclave.address || "").toLowerCase();
  return !!me && (app.publisher.toLowerCase() === me || me === STORE.owner);
};
export const verVisible = (app, v) => appPrivileged(app) || (!v.yanked && v.approval !== APPROVAL.rejected);
// indices into app.versions the viewer may see - callers keep the REAL index
// (catalog:// refs and card-action idx are positions in the on-chain list)
export const visibleVerIdxs = (app) =>
  app.versions.reduce((idxs, v, i) => (verVisible(app, v) && idxs.push(i), idxs), []);
export function defaultIdx(app){         // newest visible non-yanked release, else newest visible; -1 = none to show
  const vs = app.versions;
  for (let i = vs.length - 1; i >= 0; i--) if (!vs[i].yanked && verVisible(app, vs[i])) return i;
  for (let i = vs.length - 1; i >= 0; i--) if (verVisible(app, vs[i])) return i;
  return -1;
}
export function selIdx(app){
  const s = STORE.sel[app.appId];
  return (s != null && s >= 0 && s < app.versions.length && verVisible(app, app.versions[s])) ? s : defaultIdx(app);
}
// platform-published apps: publisher wallet == the catalog contract deployer
export const appOfficial = (app) => !!(STORE.owner && app.publisher.toLowerCase() === STORE.owner);
// the Verified filter means "owner-endorsed": an explicit setVerified flag, or official
// (owner-published is implicit endorsement - none of the platform apps carry the flag)
export const appVerified = (app) => { const i = defaultIdx(app); return i >= 0 && (app.versions[i].verified || appOfficial(app)); };

/* ---- app media (tile thumbnail + detail-page banner) ----
   Media CIDs ride inside the version's config JSON under a reserved `_media`
   key ({ thumbnail, banner }). This keeps the EnclaveAppCatalog contract
   unchanged - the trade-off (accepted) is that media is per-version, immutable,
   and re-reviewed on change, exactly like the rest of a version's config. The
   runner delivers the whole config as ENCLAVE_CONFIG, so an app just sees an
   extra `_media` key it ignores; the dashboard's Config tab strips it from its view. */
export const MEDIA_KEY = "_media";
const cleanCid = (c) => (typeof c === "string" && /^[a-zA-Z0-9]{10,100}$/.test(c.trim())) ? c.trim() : "";
// Gateway URL for a media CID. SVG media carries a flag in _media because it
// only renders in image contexts under an exact image/svg+xml content-type,
// which the Kubo gateway derives from the ?filename extension; bare raster
// CIDs content-sniff fine without it.
export const mediaUrl = (cid, svg) => IPFS_IMG_GATEWAY + encodeURIComponent(cid) + (svg ? "?filename=i.svg" : "");
export function mediaOf(version){
  if (!version || !version.config) return {};
  try {
    const m = JSON.parse(version.config)[MEDIA_KEY];
    if (m && typeof m === "object" && !Array.isArray(m))
      return { thumbnail: cleanCid(m.thumbnail), banner: cleanCid(m.banner),
               thumbnailSvg: !!m.thumbnailSvg, bannerSvg: !!m.bannerSvg };
  } catch(e){}
  return {};
}
// media of an app's DEFAULT (displayed) version - what the tile + detail show
export function appMedia(app){ const i = app && app.versions ? defaultIdx(app) : -1; return i >= 0 ? mediaOf(app.versions[i]) : {}; }
// drop the reserved `_media` key from a config string (for the deploy preview /
// the publish "add version" prefill - media is edited via its own pickers)
export function stripMedia(configStr){
  if (!configStr) return "";
  try {
    const o = JSON.parse(configStr);
    if (o && typeof o === "object" && MEDIA_KEY in o){ delete o[MEDIA_KEY]; return Object.keys(o).length ? JSON.stringify(o) : ""; }
  } catch(e){}
  return configStr;
}
// fold thumbnail/banner CIDs into a config string for publishing (JSON string,
// or "" when there's neither config nor media). thumbnailSvg/bannerSvg mark
// SVG media (the /add-image gateway's verdict) so renderers can request the
// svg content-type - see mediaUrl.
export function withMedia(configStr, thumbnail, banner, thumbnailSvg, bannerSvg){
  let o = {};
  if (configStr){ try { const p = JSON.parse(configStr); if (p && typeof p === "object" && !Array.isArray(p)) o = p; } catch(e){} }
  const m = {};
  if (cleanCid(thumbnail)){ m.thumbnail = thumbnail.trim(); if (thumbnailSvg) m.thumbnailSvg = true; }
  if (cleanCid(banner)){ m.banner = banner.trim(); if (bannerSvg) m.bannerSvg = true; }
  if (Object.keys(m).length) o[MEDIA_KEY] = m; else delete o[MEDIA_KEY];
  return Object.keys(o).length ? JSON.stringify(o) : "";
}

/* Resolve what the user typed into an `image.reference` the enclave understands.
   Humans type "[publisher/]slug:version"; we look it up in the on-chain catalog
   and hand the enclave `catalog://<appId>/<versionIndex>` — the on-chain RECORD
   of that version. The record (not the deployer) carries everything approval
   covered: wasm CID, config, ports, specs. CIDs are NOT app references - a CID
   names bytes, and several versions (with different approved configs) can share
   bytes. Returns {reference, label?, error?, pending?}. */
export const catalogRef = (appId, index) => "catalog://" + appId + "/" + index;
export const parseCatalogRef = (ref) => {
  const m = /^catalog:\/\/(0x[0-9a-fA-F]{64})\/(\d{1,9})$/.exec(String(ref || "").trim());
  return m ? { appId: m[1], index: +m[2] } : null;
};
export const REF_CACHE = {};    // friendly "slug:version" -> "catalog://<appId>/<idx>" (filled by Use-in-Deploy + lookups)
export const PORTS_CACHE = {};  // friendly "slug:version" -> that version's firewall CSV (defaults the deploy)
export const SPECS_CACHE = {};  // friendly "slug:version" -> the version's RAW specs {vramMb,gpuGflops,memMb,cpuGflops}.
                                // Raw on purpose: dial floors are minPctsOf(spec) AT READ TIME, so they always
                                // divide by the currently adopted fleet hardware - caching computed percents
                                // froze them against whatever spec was live at first resolve (the 91%-vs-92%
                                // unclaimable-deployment bug of 2026-07-14)
// `volumes` rides along with the hardware numbers because it is the same KIND
// of requirement: a model volume is attached to a box, not fetched, so which
// boxes can host this version depends on it exactly as it depends on the card.
// It comes off the version's approved config (a deployment's own config
// override - the dashboard's Models tab - replaces it for that deployment).
export const specOf = (v) => ({ vramMb: Number(v && v.vramMb) || 0, gpuGflops: Number(v && v.gpuGflops) || 0,
                                memMb: Number(v && v.memMb) || 0, cpuGflops: Number(v && v.cpuGflops) || 0,
                                volumes: volumesOfConfig(v && v.config),
                                gpuOptional: gpuOptionalOfConfig(v && v.config),
                                cpuFallback: cpuFallbackOfConfig(v && v.config) });
/* The publisher's declaration that this version's GPU axes are DESIRED, not
   required: the app starts without a card and would use one if given it. Read
   from the version config, like `volumes` — immutable per version, approved
   with it, and the only place that knows the difference (on-chain the axes are
   just numbers). An unparseable config declares nothing, which leaves the
   specs required: the runner computes the same, and a console floor below the
   runner's would sell a deployment nobody can claim. */
export function gpuOptionalOfConfig(cfg){
  if (!cfg) return false;
  try {
    const o = typeof cfg === "string" ? JSON.parse(cfg) : cfg;
    return !!(o && o.gpuOptional === true);
  } catch { return false; }
}
/* What the app needs from a NODE when it runs WITHOUT a card, for a version
   whose publisher sized that case: {memMb, cpuGflops}, from the version config
   beside `gpuOptional`. The four on-chain axes are ONE set and on a soft-GPU
   app they describe the card case - the guest's own memory, with the weights
   resident in its VRAM slice. On cores those weights move into node RAM beside
   it and the matmuls become the node's work, so the CPU floor is a different
   number; nothing in the record can say that, which is why this key exists.
   Mirrors the runner's cpuFallbackOfConfig exactly, bounds included: a console
   floor BELOW the runner's sells a deployment that box will not claim. */
export function cpuFallbackOfConfig(cfg){
  if (!cfg) return null;
  let f;
  try {
    const o = typeof cfg === "string" ? JSON.parse(cfg) : cfg;
    f = o && o.cpuFallback;
  } catch { return null; }       // unparseable declares nothing; the on-chain axes hold, as they do today
  if (!f || Array.isArray(f) || typeof f !== "object") return null;
  const num = (x, max) => { const n = Number(x); return Number.isFinite(n) && n >= 0 && n <= max ? n : 0; };
  const memMb = num(f.memMb, 1048576), cpuGflops = num(f.cpuGflops, 10000000);
  return (memMb || cpuGflops) ? { memMb, cpuGflops } : null;
}
export function volumesOfConfig(cfg){
  if (!cfg) return [];
  try {
    const o = typeof cfg === "string" ? JSON.parse(cfg) : cfg;
    return Array.isArray(o && o.volumes) ? [...new Set(o.volumes.map(String).filter(Boolean))] : [];
  } catch { return []; }        // an unparseable config constrains nothing; the runner still gates the claim
}
export const CONFIG_CACHE = {}; // friendly "slug:version" -> that VERSION's default/template config JSON (pre-fills the deploy form)
export const CONFIG_CID_CACHE = {}; // friendly "slug:version" -> the CID that config lives at ("" = it is inline, and CONFIG_CACHE already has it)
/* friendly "slug:version" -> the version's INLINE on-chain field, verbatim.
   Below rev 7 that IS the config; from rev 7 a large-config version keeps only
   the routing manifest there. Either way it is the one place the placement keys
   (wasi/threads/set/volumes/gpuOptional) are guaranteed to be readable WITHOUT
   a network fetch — so every gate that decides which box can run this app reads
   THIS, never CONFIG_CACHE. CONFIG_CACHE answers a different question ("what
   will the app receive"), and for a CID version it is empty until a fetch
   lands, which would silently turn a hard placement refusal into a pass. */
export const MANIFEST_CACHE = {};

/* A rev-7 version keeps its config at an IPFS CID; this reads it for DISPLAY
   (the dashboard's Config tab prefill and its override diff). Display only — nothing
   here is a trust boundary: the enclave re-fetches the same CID and verifies
   the content hashes back to it before any of it reaches a guest, so the worst
   a lying gateway does to this path is show the operator the wrong text.
   Returns null when unreadable, which callers render as empty rather than
   wrong. Cached by CID: it is content-addressed, so it can never go stale. */
const _cfgCidCache = {};
export async function fetchConfigCid(cid){
  if (cid in _cfgCidCache) return _cfgCidCache[cid];
  let out = null;
  try {
    // A cached immutable gateway response may predate its CORS repair. Fetch
    // fresh headers once per page; successful content remains memoized by CID.
    const r = await fetch(IPFS_IMG_GATEWAY + encodeURIComponent(cid), { cache: "reload", signal: AbortSignal.timeout(15000) });
    if (r.ok) {
      const text = await r.text();
      JSON.parse(text);                     // must parse, or it is not a config
      out = text;
    }
  } catch(e){ out = null; }
  // only a SUCCESS is memoized: content addressing makes a hit permanently
  // valid, but a gateway hiccup is transient and caching it would kill the
  // prefill for the rest of the page session
  if (out !== null) _cfgCidCache[cid] = out;
  return out;
}
/* Wallet-authorize a pin: sign enclave-upload:<sha256(bytes)>:<expiry>, trade it
   at the API for a one-time HMAC token bound to exactly these bytes. Shared by
   the wasm upload, the images, and both config pins (a publisher's version
   config and a deployer's per-deployment override). */
export async function signedUploadToken(bytes){
  if (!Enclave.address){ try { await connectWallet(); } catch(_){} }
  if (!Enclave.address || !Enclave.provider) throw new EnclaveError("Connect your wallet to upload; your signature authorizes the pin.", 0);
  const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(b => b.toString(16).padStart(2, "0")).join("");
  const expiry = Math.floor(Date.now() / 1000) + 300;
  try {
    const signature = await personalSign(`enclave-upload:${hash}:${expiry}`);
    const r = await fetch(Enclave.base + "/apps/upload-token", { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ hash, expiry, signature }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.token) throw new EnclaveError("upload authorization failed: " + (j.message || j.error || ("HTTP " + r.status)), 0);
    return { token: j.token, address: j.address, expiry };
  } catch(err){
    if (err && (err.code === 4001 || /reject|denied|declin|cancell/i.test(err.message || ""))) throw new EnclaveError("upload canceled: you declined the wallet signature.", 0);
    throw (err instanceof EnclaveError) ? err : new EnclaveError("upload authorization failed: " + (err.message || err), 0);
  }
}

export async function signedUploadHeaders(bytes,url){
  if (!IPFS_WALLET_AUDIENCE) {
    const {token,address,expiry}=await signedUploadToken(bytes);
    return {"x-upload-address":address,"x-upload-expiry":String(expiry),"x-upload-token":token};
  }
  if (!Enclave.address) await connectWallet();
  if (!Enclave.address || !Enclave.provider) throw new EnclaveError("Connect your wallet to authorize the upload.",0);
  return directUploadHeaders({audience:IPFS_WALLET_AUDIENCE,url,address:Enclave.address,bytes,signMessage:({message})=>personalSign(message)});
}

/* Pin a config too large to sit on-chain. Wallet-signed like the wasm and the
   images — the gateway re-parses the JSON, caps the size and pins; the CID then
   goes into a VERSION RECORD (catalog rev 7, immutable and approval-covered) or
   into a DEPLOYMENT's options envelope (the same split, deployment side).
   Enclaves re-fetch and hash-verify either one, so this pin is AVAILABILITY,
   never trust: a gateway that served different bytes would fail the check, not
   change what runs. */
export async function putConfig(text){
  if (!IPFS_JSON_UPLOAD_URL) throw new EnclaveError("Large configs aren’t configured here (no config pin gateway).", 0);
  const buf = new TextEncoder().encode(text);
  if (buf.byteLength > CAT_MAX.configMax)
    throw new EnclaveError("config too long (≤ " + CAT_MAX.configMax + " bytes)", 0);
  const headers = await signedUploadHeaders(buf, IPFS_JSON_UPLOAD_URL);
  const r = await fetch(IPFS_JSON_UPLOAD_URL, { method: "POST", headers: {
    "content-type": "application/json",
    ...headers,
  }, body: buf });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.cid) throw new EnclaveError("config pin rejected: " + (j.error || ("HTTP " + r.status)), 0);
  return j.cid;
}

export function looksFriendly(s){ return s.includes(":") && !s.startsWith("ipfs://"); }
/* opts.allowPending: admit a version still AWAITING approval — the dev-mode
   path (PRIVATE deployments on a fleet advertising devDeploy; the caller owns
   both checks). Pending resolutions NEVER enter REF_CACHE: the cache hit path
   skips the approval gate, so caching one would let a later PUBLIC deploy of
   the same input slip through unexamined. Rejected/yanked stay refused. */
export function resolveAppRef(input, opts = {}){
  input = (input || "").trim();
  if (!input) return { reference: "", error: "Pick an app: slug:version from the Apps catalog." };
  if (input.startsWith("ipfs://") || /^(baf[a-z0-9]{10,}|Qm[1-9A-HJ-NP-Za-km-z]{20,})$/.test(input))
    return { reference: input, error: "CIDs can’t deploy - a CID names bytes, not a version (several versions can share bytes and differ in approved config). Deploy a slug:version from the Apps catalog." };
  if (!looksFriendly(input)) return { reference: input, error: "Not a slug:version reference. Deploys come from the on-chain catalog - pick an app on the Apps page." };
  // The cache is only the PRE-LOAD fast path (a "Use in Deploy" stash resolving
  // before the catalog read lands). Once the catalog is loaded, always resolve
  // fresh: the stash writer (apps.js useInDeploy) caches whatever version the
  // user clicked — a publisher's own PENDING one included — and the approval
  // gate below must re-run against the caller's current opts, not be
  // short-circuited by a cache entry that never saw it.
  if (REF_CACHE[input] && !STORE.loaded) return { reference: REF_CACHE[input], label: input };
  let pub = null, rest = input;
  const slash = input.indexOf("/");
  if (slash >= 0){ pub = input.slice(0, slash).trim().toLowerCase(); rest = input.slice(slash + 1); }
  const colon = rest.lastIndexOf(":");
  const slug = rest.slice(0, colon).trim(), version = rest.slice(colon + 1).trim();
  if (!STORE.loaded) return { reference: input, label: input, pending: true };   // catalog not read yet
  let apps = (STORE.apps || []).filter(a => a.slug === slug && a.active);
  if (pub) apps = apps.filter(a => a.publisher.toLowerCase() === pub);
  if (!apps.length) return { reference: input, label: input, error: "No catalog app '" + slug + "'" + (pub ? " by " + pub : "") + "." };
  if (apps.length > 1) return { reference: input, label: input, error: "Several publishers have '" + slug + "'; qualify it: <publisher>/" + slug + ":" + version };
  const vi = apps[0].versions.findIndex(x => x.version === version && !x.yanked);
  const v = vi >= 0 ? apps[0].versions[vi] : null;
  if (!v) return { reference: input, label: input, error: "'" + slug + "' has no live version '" + version + "'." };
  if (v.approval !== APPROVAL.approved && (v.approval === APPROVAL.rejected || !opts.allowPending))
    return { reference: input, label: input, error: "'" + slug + ":" + version + "' " + (v.approval === APPROVAL.rejected
      ? "was rejected by the catalog owner; the enclave refuses to deploy it."
      : "isn’t approved yet by the catalog owner; the enclave only runs it PRIVATE (owner-only access) for testing - switch Access to Private.") };
  const awaiting = v.approval !== APPROVAL.approved;   // pending, admitted by allowPending
  if (!awaiting) REF_CACHE[input] = catalogRef(apps[0].appId, vi);
  PORTS_CACHE[input] = v.ports || "";
  SPECS_CACHE[input] = specOf(v);         // raw specs; floors are computed at read time
  // The version's default config template (store media stripped: _media never
  // reaches an app, and an override built from this prefill must not carry it).
  // On a rev-7 version `v.config` is only the on-chain manifest, so the real
  // config is fetched from its CID — otherwise a config editor would prefill
  // the manifest and treat the user's first keystroke as an override against
  // the wrong baseline. Best effort: a gateway that won't answer leaves the
  // box empty rather than wrong, and the ENCLAVE_CONFIG the app receives is
  // resolved in-enclave regardless of what this display path managed to read.
  MANIFEST_CACHE[input] = v.config || "";
  CONFIG_CACHE[input] = stripMedia(v.config || "");
  // On a rev-7 version the line above cached only the ON-CHAIN MANIFEST. The
  // real config is at a CID and reading it is a network fetch, so it is not
  // done here (this resolver is synchronous and called from render paths):
  // CONFIG_CID_CACHE records where to get it; a consumer that shows the
  // config fetches it from there. Until then the box shows the manifest-stripped empty
  // string rather than the manifest itself, which would read as the app's
  // config and make the user's first keystroke an override against a baseline
  // that was never the config.
  CONFIG_CID_CACHE[input] = v.configCid || "";
  if (v.configCid) CONFIG_CACHE[input] = "";
  return { reference: catalogRef(apps[0].appId, vi), label: input, mins: minPctsOf(SPECS_CACHE[input]),
           ...(awaiting ? { awaitingApproval: true } : {}) };
}

// A mid-session address-book change (js/core/addressbook.js emits
// `enclave:addresses` when APP_CATALOG_ADDRESS et al. are repointed on-chain)
// leaves our loaded catalog reading the OLD contract. Re-read against the new
// address so pages repaint - loadCatalog emits `enclave:catalog` on completion,
// which is exactly the repaint signal the Apps page already listens for.
on("enclave:addresses", ({ changed }) => {
  if (changed && changed.indexOf("APP_CATALOG_ADDRESS") !== -1){
    STORE.loaded = false; STORE.loading = false; STORE.owner = null;
    loadCatalog(true);
  }
});

// deployment rows resolve their catalog://<appId>/<idx> reference to the app
// record - from the live STORE or the localStorage catalog cache (either may
// be populated first, depending on which page the visitor landed on).
function appOfRef(cr){
  const lists = [];
  if (Array.isArray(STORE.apps) && STORE.apps.length) lists.push(STORE.apps);
  try {
    const raw = lsGet("enclave_catalog_" + APP_CATALOG_ADDRESS);
    if (raw){ const j = JSON.parse(raw); if (j && Array.isArray(j.apps)) lists.push(j.apps); }
  } catch(e){}
  for (const apps of lists) for (const a of apps)
    if (a && a.appId === cr.appId) return { app: a, v: (a.versions || [])[cr.index] || null };
  return null;
}
// the human app name (slug:version) for a deployment row. Legacy ipfs:// rows
// return null (the caller falls back to the truncated reference): a CID can
// belong to several versions with different approved configs - naming one
// would be a guess.
export function slugOfRef(ref){
  const cr = parseCatalogRef(ref);
  const hit = cr && appOfRef(cr);
  if (!hit) return null;
  return hit.app.slug + (hit.v && hit.v.version != null ? ":" + hit.v.version : "#" + cr.index);
}
// Resolve the exact deployed version from the same live/persisted catalog as
// its name and artwork. Unknown versions must not look like zero requirements.
export function specOfRef(ref){
  const cr = parseCatalogRef(ref);
  const hit = cr && appOfRef(cr);
  return hit?.v ? specOf(hit.v) : null;
}
// the publisher wallet behind a catalog:// reference - the payee a paid app's
// fee snapshot must name (create() copies it; runners verify it at claim)
export function publisherOfRef(ref){
  const cr = parseCatalogRef(ref);
  const hit = cr && appOfRef(cr);
  return hit ? hit.app.publisher : null;
}

/* ---- generated stand-in art ----
   For apps that ship no thumbnail (store tiles AND dashboard rows): an accent
   from the site palette keyed off `key`, the enclave corner brackets, and the
   app's initial. Inline SVG data URI - nothing to fetch, can never 404; the
   same key always yields the same art, so a deployment's chip matches its
   store tile. */
const ART_ACCENTS = ["#2fe6a8", "#8fa2ff", "#ff914d", "#57d7ff", "#c08aff", "#e66bd2"];
export function placeholderArt(key, initial){
  key = String(key || "?");
  let h = 5381; for (let i = 0; i < key.length; i++) h = ((h * 33) ^ key.charCodeAt(i)) >>> 0;
  const c = ART_ACCENTS[h % ART_ACCENTS.length];
  const ch = esc(String(initial || "?").trim().charAt(0).toUpperCase() || "?");
  const svg =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 180">'
    + '<rect width="320" height="180" fill="#0b0f16"/>'
    + '<circle cx="160" cy="90" r="115" fill="' + c + '" opacity=".05"/>'
    + '<circle cx="160" cy="90" r="62" fill="' + c + '" opacity=".07"/>'
    + '<path d="M26 42v-18h18M294 42v-18h-18M26 138v18h18M294 138v18h-18" stroke="' + c + '" stroke-width="2" fill="none" opacity=".55"/>'
    + '<text x="160" y="92" text-anchor="middle" dominant-baseline="central" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="64" font-weight="600" fill="' + c + '" opacity=".9">' + ch + '</text>'
    + '</svg>';
  return "url('data:image/svg+xml," + encodeURIComponent(svg) + "')";
}
// CSS background-image for a deployment row's app chip: the referenced
// version's real thumbnail when the catalog knows it, else placeholder art
// keyed by the appId (so it matches the store tile). `label` seeds the art
// for legacy ipfs:// rows the catalog can't name.
export function artOfRef(ref, label){
  const cr = parseCatalogRef(ref);
  const hit = cr && appOfRef(cr);
  const m = hit && hit.v ? mediaOf(hit.v) : {};
  if (m.thumbnail) return "url('" + mediaUrl(m.thumbnail, m.thumbnailSvg) + "')";
  const name = (hit && (hit.app.name || hit.app.slug)) || String(label || "?");
  return placeholderArt((cr && cr.appId) || ref || label, name);
}
