import {catalogStatus} from "../../js/core/catalog-policy.js";
/* ============================================================
   <c-deployments> - the "My Apps" panel: the signed-in
   customer's deployments, each with status, spend, its app origin,
   its dedicated IPv6 (when the deployment declares tcp/udp
   ports), in-browser attestation verification, and suspend/resume
   (on-chain rows; the balance stays on the record across a
   suspend - legacy dep_ rows terminate instead).
   ONE panel for both kinds of customer: wallet rows come from the
   ledger/enclave list and act via wallet txs; passkey/card account
   rows come from the relay's account-scoped join (their credit
   vault owns them on-chain) and money/control ops are passkey-
   signed vault operations instead - same rows, same controls.
   Polls while signed in; follows `enclave:wallet` address edges
   (async session restore, account switches), `enclave:account`
   sign-in/out edges and `enclave:auth` sign-in edges.
   ============================================================ */
import { EnclaveElement, register } from "../../js/lib/enclave-element.js";
import "../volume-picker/volume-picker.js";   // the Models tab's checklist
import { $$, esc, hlJson, fmtDur, statusCls, copyText, showToast, lsGet, lsSet } from "../../js/core/util.js";
import { APP_DOMAIN, DEPLOYMENTS_ADDRESS } from "../../js/core/config.js";
import { Enclave } from "../../js/core/api.js";
import { openStateOf, probeAppTls } from "../../js/core/app-tls.js";
import { pad32, encUint, encCall, hexBig, DEP_SEL, depPrices6, rate6Of, depMaxGpuMilli, depGet, depSchemaRev, depFeeOf, depCapOf, depRefundableOf, depCall, catVersionFee, catGetVersion, waitReceipt } from "../../js/core/chain.js";
import { authenticate, asHostOwner, connectWallet, refreshWallet, saveSession, ensureBaseChain, sendTx as walletSendTx, personalSign } from "../../js/core/wallet.js";
// Every ledger call this panel sends goes through here. A row the wallet's SessionVault holds is acted on by this
// browser's session (no wallet prompt; a prod version/config change becomes the owner's Promote signature); every
// other row - and every other contract - sends the same wallet transaction as before (js/core/sessions.js ledgerSend).
const sendTx = (to, data, value, gas) => String(to).toLowerCase() === String(DEPLOYMENTS_ADDRESS).toLowerCase()
  ? import("../../js/core/sessions.js").then((S) => S.ledgerSend(data, () => walletSendTx(to, data, value, gas)))
  : walletSendTx(to, data, value, gas);
import { slugOfRef, artOfRef, loadCatalog, parseCatalogRef, catalogRef, specOf, specOfRef, STORE, fetchConfigCid, stripMedia, putConfig } from "../../js/core/catalog.js";
import { appShares } from "../../js/core/app-resources.js";
import { cpuPoolBadge, gpuPoolBadge } from "../../js/core/pool-badges.js";
import { shareEditor } from "../../js/core/share-editor.js";
import { resourceOverview } from "../../js/core/resource-overview.js";
import { vspecOf, boxOfEndpoint, verifyBoxInBrowser, verdictBadge, verificationHtml, boxModeOf, boxRowOf, verifyAppInBrowser } from "../../js/core/verify.js";
import { runlog, paintLine, retryOfferOf } from "../../js/core/runlog.js";
import { payForRuntime } from "../../js/core/fund.js";
import { moveLeaseLive, prepareDeploymentMove } from "../../js/core/deployment-move.js";
import { isolationOptions, withIsolationRequirements, hostMeetsTeeRequirements, hostsTakeConfig } from "../../js/core/isolation-options.js";
import { placementMessage, pinnedHost, withPlacementPin } from "../../js/core/placement-options.js";
import { resizeAfterStop } from "../../js/core/share-resize.js";
import { depSnapshot } from "../../js/core/chain.js";
import { custodyAvailable, custodyStatus, saveToCustody, rulesFromPredictionPreview } from "../../js/core/custody.js";
import { BUCKETS, bucketOf, countBuckets } from "../../js/core/deploy-status.js";
import { LastGood, listIdentity, failureReason, asOf } from "../../js/core/list-state.js";
import { shareRates, minPctsOf, cpuFloorFor, cardServesApp, adoptServerSpec, leaseHostOf, moveTargetsFor, gpuUpgradeForMove, gpuDowngradeForMove, enclavePriceOf, hostChargeWaived, sharesLegalOn, liftSharesForLedger } from "../../js/core/pricing.js";

// Keep search and the card title on the same resolved app identity.
function deploymentTitle(d) {
  return (d.app && d.app.slug ? d.app.slug + ":" + d.app.version : null)
    || (d.image && d.image.reference ? slugOfRef(d.image.reference) || shortImg(d.image.reference) : null);
}

// The app's reachable URL. Through the gateway each deployment gets its OWN
// origin: a per-deployment subdomain (<id>.app.enclave.host, the base36 part of
// the deployment id; the "dep_" is dropped as redundant in this namespace), so
// an app can't touch the frontend's origin or another tenant's. Talking to an
// enclave directly falls back to the /x/<id> path. The deployment's own
// network.endpoint (the enclave's hostname) is only a last resort; it's the
// right value for attestation/registry, not for how the user reaches the app.
export function appEndpoint(d){
  if (!d || !d.id) return (d && d.network && d.network.endpoint) || "";
  const root = Enclave.base.replace(/\/v1\/?$/, "");
  if (/(^|\/\/)api\.(enclave|nan)\.host/i.test(root))
    return "https://" + appLabel(d.id) + "." + APP_DOMAIN;
  return root + "/x/" + d.id;                              // direct-to-enclave override
}
// Subdomain label for a deployment id. On-chain ids are bytes32: the label is
// the FIRST 8 HEX CHARS (32 bits - collisions are fantasy at any realistic
// deployment count; enclaves resolve the prefix to the unique match, and any
// longer prefix keeps working too). Legacy dep_ ids keep their base36 label.
export function appLabel(id){
  return /^0x[0-9a-f]{64}$/i.test(id) ? id.slice(2, 10).toLowerCase() : id.replace(/^dep_/, "");
}
// appEndpoint can derive from server-supplied fields (network.endpoint), so an
// endpoint may only become a navigable href if it is https: or a relative URL;
// anything else (javascript:, data:, …) is dropped so a hostile API can't smuggle
// a scheme into the "open ↗" link. "" means "not safe to link" (caller omits it).
function safeHref(u){
  const s = String(u || "");
  if (/^https:\/\//i.test(s)) return s;                 // absolute enclave/app origin
  if (/^\/(?!\/)/.test(s) || /^\.{1,2}\//.test(s)) return s;   // root- or dot-relative path
  return "";
}

/* The lock closes only after a successful browser HTTPS probe. */
const LOCK_OPEN = '<svg class="enc-lock" viewBox="0 0 24 24" width="11" height="11" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M9 11V7a3.5 3.5 0 0 1 6.9-.9"/></svg>';
const LOCK_SHUT = '<svg class="enc-lock" viewBox="0 0 24 24" width="11" height="11" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M9 11V7a3.5 3.5 0 0 1 7 0v4"/></svg>';
function openCtl(d, ep, tls){
  const href = safeHref(ep);
  if (!(d && (d.status || "") === "running" && href)) return "";
  /* PRIVATE rows are offered too. They were suppressed entirely while a private
     app had no browser-reachable form at all; now they carry an app-zone
     certificate like any other and answer a navigation with a wallet sign-in,
     so the only difference left is WHERE the link points: /authorize trades
     this wallet's session for an app-origin cookie first, because a top-level
     navigation cannot carry a bearer. */
  const to = d.public ? esc(href) + "/" : "authorize?d=" + esc(encodeURIComponent(d.id));
  /* WHAT THE PADLOCK MEANS, and only that: this browser completed the handshake and the origin
     answered. It is not a claim about where the private key is held. A certificate that chains to a
     public CA says nothing about key custody, and on a consumer node the app-zone key lives in the
     host process (that box publishes appTls.keyIn itself) - so a tooltip asserting "issued inside
     the enclave" was telling the reader something the evidence does not support. */
  if (tls?.href === href && openStateOf(tls) === "ok") {
    const why = d.public
      ? 'title="TLS verified by this browser: the certificate chains and the app answered"'
      : 'title="private - opens through your session, or after a wallet sign-in, which authorizes no transaction"';
    return '<a class="enc-open" data-tls="' + esc(d.id) + '" href="' + to + '" target="_blank" rel="noopener" aria-label="Open app (new tab)' + (d.public ? " - TLS verified by this browser" : " - opens through your session or a wallet sign-in") + '" ' + why + '>' + LOCK_SHUT + ' open ↗</a>';
  }
  /* The link still opens. The old control disabled itself and blamed the certificate; the honest
     version offers the app and says exactly what is and is not known. */
  return '<a class="enc-open enc-open-unknown" data-tls="' + esc(d.id) + '" href="' + to + '" target="_blank" rel="noopener"'
    + ' aria-label="Open app (new tab) - this browser got no answer from a readiness check"'
    + ' title="no answer to a readiness check from this browser. That can be an app that does not serve its root path, a network problem, or a certificate that is not ready - this page cannot tell them apart, so it does not guess. The link still opens.">'
    + LOCK_OPEN + ' open ↗</a>';
}

// Per-row SECRETS section (wallet-owned on-chain rows): rendered PERMANENTLY
// as its locked bar - id + the Unlock control - with the editor body absent
// until a reveal signature succeeds (_secretsWire). Values only ever exist in
// the DOM while unlocked; every repaint guard keys on .enc-sec-body so the
// poll never wipes an open editor and never stalls on the always-present bar.
// While the reveal signature is still PENDING the body is hidden, so that
// window pins repaints via [data-busy] on the section instead (_panelPinned) -
// a wallet prompt easily outlives a 10s poll tick.
function secretsSection(id){
  const label = appLabel(id);
  return '<div class="enc-sec" data-id="' + esc(id) + '">'
    +   '<div class="enc-sec-body" id="esBody' + label + '" hidden>'
    +     '<label for="esTa' + label + '">Private env vars, one KEY="value" per line (quotes optional; inside double quotes, escape &quot; and \\ with a backslash) - stored on the relay, never on-chain; the enclave injects them when the app starts</label>'
    +     '<textarea class="es-ta" id="esTa' + label + '" rows="5" spellcheck="false" autocomplete="off" placeholder="S3_ACCESS_KEY_ID=&quot;…&quot;&#10;S3_SECRET_ACCESS_KEY=&quot;…&quot;"></textarea>'
    +     '<span class="enc-sec-acts">'
    +       '<button class="btn btn-sm es-save" type="button" title="One wallet signature stores the textarea as this deployment’s complete secret set">Save</button>'
    +       '<button class="btn btn-sm es-custody" type="button" hidden title="Encrypts the textarea IN THIS BROWSER to independent custodians and stores it on Base: the relay no longer holds or sees the values, and only this app, attested in hardware, can open them. One wallet transaction; replaces the whole set">Save to custody</button>'
    +     '</span>'
    +   '</div>'
    +   '<div class="term enc-sec-status" role="status" aria-live="polite"></div>'
    + '</div>';
}

/* ---- per-row "Get the app" section ----
   A published version may name installable MOBILE builds in its on-chain
   config under "_mobile" ({android: <apk url>, ios: <store url>}) - the
   verify-first shell (enclave-apps/mobile-shell) wrapping this app, which
   checks the enclave's attestation ON THE PHONE before the app loads. The
   config is publisher-authored, so a link only renders from an allowlist of
   store/release hosts: the dashboard must never become an arbitrary-binary
   delivery vector. Grow the list deliberately, never to "any https". */
const MOBILE_KEY = "_mobile";
const MOBILE_HOSTS = /^https:\/\/(github\.com\/[^?#\s]+\/releases\/download\/|play\.google\.com\/|apps\.apple\.com\/|testflight\.apple\.com\/)/i;
export function mobileLinksOf(ref){
  try {
    const cr = parseCatalogRef(ref);
    const app = cr && STORE.byId[cr.appId];
    const ver = app && app.versions ? app.versions[cr.index] : null;
    const m = ver ? (JSON.parse(ver.config || "{}") || {})[MOBILE_KEY] : null;
    if (!m || typeof m !== "object") return null;
    const pick = (u) => (typeof u === "string" && MOBILE_HOSTS.test(u) && safeHref(u)) || "";
    const android = pick(m.android), ios = pick(m.ios);
    return android || ios ? { android, ios } : null;
  } catch { return null; }
}
// The GENERIC shell: one signed APK any *.app.enclave.host deployment can
// pair into via the deep link this section mints (the shell stores the
// target, verifies its attestation on the phone, then loads it). Rows whose
// version publishes dedicated builds (_mobile) offer those instead.
const GENERIC_APK = "https://github.com/EnclaveHost/enclave-apps/releases/download/mobile-enclave/enclave.apk";

// PREPACKAGED per-deployment APKs: CI snapshots the app's whole UI off its
// live origin into a signed APK pre-linked to that deployment (zero
// downloads at open; only API calls touch the network), and commits the
// list of built labels to mobile-index.json. Rows on that list offer the
// direct install; the CI cron re-snapshots them. A row not yet on the list
// falls back to the pairing flow below - dispatching the mobile-shell
// workflow with the deployment id is what adds it.
const DEP_APK_BASE = "https://github.com/EnclaveHost/enclave-apps/releases/download/mobile-dep-";
const DEP_INDEX_URL = "https://raw.githubusercontent.com/EnclaveHost/enclave-apps/main/mobile-index.json";
let DEP_APKS = null;    // Set of 8-hex labels once the index answers
fetch(DEP_INDEX_URL)
  .then((r) => (r.ok ? r.json() : null))
  .then((j) => { DEP_APKS = new Set(((j && j.deployments) || []).map(String)); })
  .catch(() => { DEP_APKS = new Set(); });
export function mobilePairLink(d, ep){
  try {
    const host = new URL(String(ep)).host;
    if (!/^[0-9a-z-]+\.app\.enclave\.host$/i.test(host)) return "";   // custom domains pair via a branded build instead
    const name = (d.app && d.app.slug) || appLabel(d.id);
    return "enclave://open?u=" + encodeURIComponent("https://" + host)
         + "&d=" + encodeURIComponent(d.id) + "&n=" + encodeURIComponent(name);
  } catch { return ""; }
}
// What this row can offer a phone, in order of preference; null = no button.
function mobileOffer(d, ep){
  const links = mobileLinksOf(d.image && d.image.reference);
  if (links) return { kind: "links", links };
  if (!(d.public && (d.status || "") === "running")) return null;
  const label = appLabel(d.id);
  if (DEP_APKS && DEP_APKS.has(label))
    return { kind: "apk", url: DEP_APK_BASE + label + "/" + label + ".apk" };
  const pair = mobilePairLink(d, ep);
  return pair ? { kind: "pair", pair } : null;
}
const IOS_NOTE = "iPhone: open the app in Safari, then Share → Add to Home Screen.";
function mobileDialogBody(offer, name){
  if (offer.kind === "links") {
    return (offer.links.android
        ? '<div class="em-dl"><a class="btn btn-primary" href="' + esc(offer.links.android) + '" target="_blank" rel="noopener">Android · APK ↓</a></div>'
        : '')
      + (offer.links.ios
        ? '<div class="em-dl"><a class="btn btn-primary" href="' + esc(offer.links.ios) + '" target="_blank" rel="noopener">iPhone ↗</a></div>'
        : '<p class="qd-sub">' + IOS_NOTE + '</p>')
      + '<p class="qd-sub">Android asks you to allow installs from your browser the first time.</p>';
  }
  if (offer.kind === "apk") {
    return '<div class="em-dl"><a class="btn btn-primary" href="' + esc(offer.url) + '" target="_blank" rel="noopener">Android · install ' + esc(name) + ' ↓</a></div>'
      + '<p class="qd-sub">The app’s UI ships inside the APK: it opens instantly, works offline, and only its API calls reach the enclave. It is rebuilt automatically when the app updates. Android asks you to allow installs from your browser the first time.</p>'
      + '<p class="qd-sub">' + IOS_NOTE + '</p>';
  }
  return '<div class="em-dl"><a class="btn btn-primary" href="' + esc(GENERIC_APK) + '" target="_blank" rel="noopener">1 · Get the Enclave app ↓</a></div>'
    + '<div class="em-dl"><a class="btn" href="' + esc(offer.pair) + '">2 · Open this app in it</a>'
    + '<button class="btn em-copy" type="button" data-copy="' + esc(offer.pair) + '" title="Copy the pairing link (e.g. to send it to your phone)">copy link</button></div>'
    + '<p class="qd-sub">Do both steps ON YOUR PHONE (this page works there too). The link pairs the installed Enclave app to this deployment. ' + IOS_NOTE + '</p>';
}

// Per-row Domains: attach a hostname you own and the app serves on it, with a
// certificate minted inside the enclave. Collapsed to a bar until opened -
// listing needs a wallet signature (the relay proves ownership against the
// ledger), so nothing is fetched until the customer asks for it.
function domainsSection(id){
  const label = appLabel(id);
  return '<div class="enc-dom" data-id="' + esc(id) + '">'
    +   '<div class="enc-dom-body" id="edBody' + label + '" hidden>'
    +     '<div class="ed-list"></div>'
    +     '<div class="ed-add">'
    +       '<label class="sr-only" for="edIn' + label + '">Hostname to attach</label>'
    +       '<input class="ed-in" id="edIn' + label + '" type="text" inputmode="url" spellcheck="false" autocomplete="off" placeholder="shop.example.com">'
    +       '<button class="btn btn-sm btn-primary ed-add-btn" type="button" title="One wallet signature attaches this hostname">Attach</button>'
    +     '</div>'
    +   '</div>'
    +   '<div class="term enc-dom-status" role="status" aria-live="polite"></div>'
    + '</div>';
}

// One attached domain: its state, the records to create, and what to fix.
// Every status carries an action — a customer looking at this should never
// have to guess what the platform is waiting for.
const DOM_STATE = {
  pending_dns: { cls: "warn",  dot: "◌", text: "waiting for DNS" },
  verified:    { cls: "info",  dot: "◍", text: "verified · certificate on the way" },
  active:      { cls: "ok",    dot: "●", text: "live" },
  failed:      { cls: "warn",  dot: "○", text: "not verified" },
};
function domainRow(d){
  const s = DOM_STATE[d.status] || DOM_STATE.failed;
  const rec = (r, hint) => '<div class="ed-rec">'
    + '<span class="ed-rt">' + esc(r.type) + '</span>'
    + '<code class="ed-rn" title="record name">' + esc(r.name) + '</code>'
    + '<code class="ed-rv" title="record value">' + esc(r.value) + '</code>'
    + '<button class="btn btn-sm ed-copy" type="button" data-copy="' + esc(r.value) + '" title="Copy the value">copy</button>'
    + (hint ? '<span class="ed-hint">' + esc(hint) + '</span>' : '')
    + '</div>';
  const live = d.status === "active";
  return '<div class="ed-row" data-host="' + esc(d.hostname) + '">'
    + '<div class="ed-head">'
    +   '<span class="ed-dot ' + s.cls + '" aria-hidden="true">' + s.dot + '</span>'
    +   (live ? '<a class="ed-host" href="https://' + esc(d.hostname) + '/" target="_blank" rel="noopener">' + esc(d.hostname) + ' ↗</a>'
            : '<span class="ed-host">' + esc(d.hostname) + '</span>')
    +   '<span class="ed-state ' + s.cls + '">' + esc(s.text) + '</span>'
    +   '<span class="ed-acts">'
    +     (live ? '' : '<button class="btn btn-sm ed-check" type="button" title="Check the DNS records now (they are re-checked automatically every few minutes)">check now</button>')
    +     '<button class="btn btn-sm ed-del" type="button" title="Detach this hostname: routing stops and the certificate is dropped">detach</button>'
    +   '</span>'
    + '</div>'
    // Records stay visible while live: people move DNS providers, and the
    // delegation CNAME must survive the move or renewal quietly stops working.
    + '<div class="ed-recs">'
    +   rec(d.records.routing, d.hostname.split(".").length <= 2 ? "apex: use CNAME flattening, or A/AAAA to our edge" : "")
    +   rec(d.records.challenge, "proves you own the name")
    +   rec(d.records.acme, "keeps the certificate renewing — leave it in place")
    + '</div>'
    + (d.lastError ? '<div class="ed-err warn">⚠ ' + esc(d.lastError) + '</div>' : '')
    + (d.caaWarning ? '<div class="ed-err warn">⚠ ' + esc(d.caaWarning) + '</div>' : '')
    + (d.certificate && d.certificate.error
        ? '<div class="ed-err warn">⚠ certificate: ' + esc(d.certificate.error) + '</div>' : '')
    + (live && d.certificate && d.certificate.ca
        ? '<div class="ed-err dimln">// certificate issued by ' + esc(d.certificate.ca) + ', minted inside the enclave</div>' : '')
    + '</div>';
}

function shortImg(s){ if (!s) return ""; return s.length > 44 ? s.slice(0, 42) + "…" : s; }
// Status buckets for the filter bar: BUCKETS/bucketOf/countBuckets live in
// js/core/deploy-status.js (tested there). Unknown statuses land in "ended".
const FILTER_KEY = "enclave_dash_filters";
// Decline reasons that no amount of waiting resolves (mirrors the enclave's
// claim-gauntlet wording; deploy.js's watchClaimAndRun keys on the same set)
const WHY_TERMINAL = /below the app|minimum shares|yanked|not .{0,12}approved|rejected|delisted|unlisted|configcid|retired|deactivated/i;
// Who can act on a row: "wallet" rows are owned by the connected wallet
// (on-chain txs + enclave-session reads); "vault" rows are owned by the
// account's credit vault (money/control ops are passkey-signed through the
// relay); "order" rows are legacy provisioner-owned (read-only here).
function ctlOf(d){ return d && d.viaVault ? "vault" : (d && d.orderId ? "order" : "wallet"); }
/* ---- saved config VARIATIONS: named app-config documents, THIS BROWSER only ----
   A variation is a config the owner wants to come back to (a tuning they A/B,
   a seasonal setting) - it never rides the chain until Applied, so it lives in
   localStorage, keyed by the APP (appId): every deployment of the same app,
   whatever its version, offers the same shelf. Compact strings, newest first,
   save-over-same-name replaces, capped so one enthusiastic app can't grow the
   key unboundedly. */
const VAR_KEY = "enclave_cfg_variations";
function varStore(){ try { const v = JSON.parse(lsGet(VAR_KEY) || "{}"); return (v && typeof v === "object" && !Array.isArray(v)) ? v : {}; } catch(e){ return {}; } }
function varsFor(app){ const l = varStore()[app]; return Array.isArray(l) ? l.filter(x => x && typeof x.n === "string" && typeof x.c === "string") : []; }
function varPut(app, name, json){
  const s = varStore();
  const list = varsFor(app).filter(x => x.n !== name);
  list.unshift({ n: name, c: json, at: Date.now() });
  s[app] = list.slice(0, 20);
  lsSet(VAR_KEY, JSON.stringify(s));
}
function varDrop(app, name){
  const s = varStore();
  s[app] = varsFor(app).filter(x => x.n !== name);
  if (!s[app].length) delete s[app];
  lsSet(VAR_KEY, JSON.stringify(s));
}
/* ---- the per-deployment config override, planned against the ledger ----
   The keys the enclave reads off a deployment's config to PLACE it, and so
   the only ones that stay inline when the body moves to a CID. Lockstep with
   DEP_MANIFEST_KEYS in supervisor.js - shorter than the catalog's
   ROUTING_KEYS, because wasi/threads/set/mem64 describe the BINARY (read off
   the version, unchangeable by an override) and gpuOptional has its own
   namespace. A key added here that the runner doesn't know is refused
   outright, so the two lists must move together. */
const MANIFEST_KEYS = ["volumes"];
// Sizing a split envelope before the pin: a CIDv1 base32 is 59 chars, and
// this is only for the meta line and the fits/doesn't decision - the commit
// re-measures the REAL envelope once the CID is known and refuses there
// rather than signing something the ledger would reject.
const CID_SIZE_HINT = "b".repeat(62);
const bytesOf = (s) => new TextEncoder().encode(s).length;
// the `volumes` key of a config object: the model volumes it mounts (deduped, as strings)
const volumesOf = (o) => (o && Array.isArray(o.volumes)) ? [...new Set(o.volumes.map(String))] : [];
/* What a candidate config object MEANS against the ledger - the one truth
   Apply acts on, shared by the Config and Models panels (ctx = _cfgRead's).
   verdictOf(o): { same } nothing to do · { clear } drops the override (o IS
   the stock config) · { set, mode:"inline", envelope, bytes } · { set,
   mode:"split", body, cfg, bytes } (pin the body, keep the routing manifest
   on-chain) · { err }. The envelope's other namespaces (waf, network, gpu)
   ride every result verbatim. */
function cfgPlan(ctx){
  const { raw, cur, curBase, cap, stockC, hasOv, ovCid, ovLost, o0, splitOk } = ctx;
  const manifestOf = (o) => { const m = {}; for (const k of MANIFEST_KEYS) if (o[k] !== undefined) m[k] = o[k]; return m; };
  const splitEnvelope = (o, cid) => {
    const m = manifestOf(o);
    return JSON.stringify({ ...curBase, configCid: cid, ...(Object.keys(m).length ? { config: m } : {}) });
  };
  const clearEnvelope = () => {
    const next = { ...cur }; delete next.config; delete next.configCid;
    return Object.keys(next).length ? JSON.stringify(next) : "";
  };
  const verdictOf = (o) => {
    const mine = JSON.stringify(o);
    if (stockC !== null && mine === stockC) return hasOv ? { clear: true } : { same: true };
    // No new envelope or pin is needed for the body already stored here.
    if (ovCid && !ovLost && mine === JSON.stringify(o0)) return { same: true };
    // INLINE while the whole document fits the ledger's one options field
    const inlineEnv = JSON.stringify({ ...curBase, config: o });
    const inlineBytes = bytesOf(inlineEnv);
    if (inlineBytes <= cap){
      if (inlineEnv === raw) return { same: true };
      return { set: true, envelope: inlineEnv, bytes: inlineBytes, mode: "inline" };
    }
    // ...otherwise SPLIT: pin the body, keep the routing manifest on-chain
    // Fleet support gates INTRODUCING the configCid namespace. An existing
    // pinned override already needs it, so replacing its body adds no new
    // runner requirement (the relay's build_set_config uses the same rule).
    // Keep it editable when a partial host makes the fleet aggregate false.
    if (!splitOk && !ovCid) return { err: "this config is " + bytesOf(mine) + " bytes and the ledger's options field caps at " + cap
      + " - the live fleet can’t serve a config pinned off-chain yet, so for now only a smaller document can override this version. Try again after the fleet updates" };
    const preview = splitEnvelope(o, CID_SIZE_HINT);
    const previewBytes = bytesOf(preview);
    if (previewBytes > cap) return { err: "even split, the envelope would be " + previewBytes + " bytes; the ledger caps it at " + cap
      + " - the routing manifest (" + MANIFEST_KEYS.join(", ") + ") plus this deployment’s protection settings don’t leave room for the reference. Trim the volumes list" };
    return { set: true, bytes: previewBytes, mode: "split", body: mine, cfg: o };
  };
  return { verdictOf, clearEnvelope, splitEnvelope };
}
// a running row's allocation, "21% [tee cpu]": each pool's share beside the pill Live enclaves names that pool
// with (core/pool-badges.js). The pill starts plain and takes its colour once the serving box's /enclaves row is read.
function encTier(d){
  if (d.status !== "running") return "";
  const parts = appShares(d);
  if (!parts.length) return "Resources";
  return parts.map(s => esc(s.pct) + ' <span class="enc-pool" data-pool="' + s.pool + '"' + (d.enclave ? ' data-box="' + esc(d.enclave) + '"' : '')
    + '><span class="ap-badge">' + s.pool + '</span></span>').join(" · ");
}
class Deployments extends EnclaveElement {
  static templateUrl = new URL("./deployments.html", import.meta.url);

  renderedCallback() {
    if (this._wired) return;
    this._wired = true;
    this._page = 0;                            // current deployments page (5 per page)
    this._logPolls = {};                       // open Output panels' log timers, by id
    this._strips = new Map();                  // live-deploy strips, keyed by run record
    this.querySelector(".enc-refresh").addEventListener("click", () => this.refresh({ spinner: true }));
    // status filter: a single-select seg + search, the store toolbar's
    // grammar (persisted; a legacy stored checkbox-set falls back to All)
    let saved = null; try { saved = JSON.parse(lsGet(FILTER_KEY) || "null"); } catch (e) {}
    this._filter = (typeof saved === "string" && ("all" === saved || BUCKETS.indexOf(saved) !== -1)) ? saved : "all";
    $$(".enc-segs button", this).forEach(b => {
      b.classList.toggle("on", b.dataset.bucket === this._filter);
      b.setAttribute("aria-pressed", String(b.dataset.bucket === this._filter));
      b.addEventListener("click", () => {
        this._filter = b.dataset.bucket;
        lsSet(FILTER_KEY, JSON.stringify(this._filter));
        $$(".enc-segs button", this).forEach(x => { x.classList.toggle("on", x === b); x.setAttribute("aria-pressed", String(x === b)); });
        this._page = 0;                        // a new filter starts at the first page
        this._renderRows(this._list || []);
      });
    });
    const q = this.querySelector(".enc-search");
    if (q) q.addEventListener("input", () => { this._q = q.value.trim().toLowerCase(); this._page = 0; this._renderRows(this._list || []); });
    // run-log ACTION lines - today "[↻] Retry payment", painted into a run's
    // narrative when a deploy's funding failed. ONE delegated handler for every
    // painter: a live strip has no row to hang a listener on (an unfunded
    // deployment has no row at all), and a row's Output panel is rebuilt on
    // each open, so the click is caught at the component instead.
    this.addEventListener("click", (e) => {
      const b = e.target && e.target.closest && e.target.closest(".ln-act");
      if (!b || b.disabled || !this.contains(b) || b.dataset.kind !== "fund") return;
      b.disabled = true;          // an offer is spent once taken; a retry that fails paints a fresh one
      const id = b.dataset.id, usd = parseFloat(b.dataset.usd);
      // no amount recorded (see _output): hand off to the row's Top up, which asks for one
      if (!(usd > 0)) {
        const fb = this.querySelector('.enc-fundbtn[data-id="' + id + '"]');
        if (fb){ fb.click(); fb.scrollIntoView({ block: "nearest" }); }
        return;
      }
      import("../../js/pages/deploy.js")
        .then(m => m.retryFunding(id, usd, b.dataset.asset, runlog.runFor(id)))
        .catch(() => { b.disabled = false; });
    });
    // document-level listeners must be removable: the soft-nav router mounts a
    // fresh instance per visit, and detached ones must not keep refreshing.
    // A sign-in mid-view (the lazy log/attestation unlock) must NOT clobber
    // the open panel the user just unlocked - skip the repaint, the poll
    // catches up once the panel closes.
    this._onAuth = (e) => {
      if (Enclave.address && this._panelPinned()) return;
      this.refresh({ spinner: !!(e.detail && e.detail.spinner) });
    };
    document.addEventListener("enclave:auth", this._onAuth);
    // the wallet session restores ASYNC after a hard reload (provider
    // discovery can take seconds), so the panel mounts and paints the connect
    // wall FIRST - and an address-only session (the lazy-SIWE norm) never
    // fires enclave:auth. Follow the wallet edges instead: whenever the
    // effective address differs from what the last paint used (restore,
    // connect, account switch, disconnect), re-list.
    this._onWallet = () => { if (Enclave.address !== this._paintedFor) this.refresh(); };
    document.addEventListener("enclave:wallet", this._onWallet);
    // passkey/card sign-in and sign-out edges: the same rule as the wallet edge
    this._onAcct = () => { if (Enclave.accountAuthed() !== this._paintedAcct) this.refresh(); };
    document.addEventListener("enclave:account", this._onAcct);
    // a wallet session starting or ending changes what the list shows (the hosts' live view rides it): same rule
    this._onSess = () => { if (Enclave.sessionMayServe() !== this._paintedSess && !this._panelPinned()) this.refresh(); };
    document.addEventListener("enclave:session", this._onSess);
    this._onLog = (e) => this._onRunlog(e.detail || {});
    document.addEventListener("enclave:runlog", this._onLog);
    // deploys in flight (soft-nav away and back): rejoin every live run.
    // After a HARD reload none are live - but some may sit interrupted in the
    // persisted log (the refresh killed their deploy flows mid-stream); hand
    // them ALL to deploy.js to re-read the ledger and keep narrating, each
    // into its own run (a fleet resumes as a fleet).
    runlog.live().forEach(r => this._strip(r));
    const cuts = runlog.interrupted();
    if (cuts.length) import("../../js/pages/deploy.js")
      .then(m => cuts.forEach(r => m.resumeDeployWatch(r))).catch(() => {});
    // rows show their app's cover art, resolved from the catalog - kick the
    // read here too (no-op when loaded; the localStorage copy paints first)
    // and repaint once the live catalog lands, unless a panel is open (same
    // clobber rule as _onAuth; the regular poll catches up after it closes).
    loadCatalog();
    this._onCat = () => {
      if (this._panelPinned()) return;
      if (this._list) this._renderRows(this._list);
    };
    document.addEventListener("enclave:catalog", this._onCat);
    this.refresh();
  }
  disconnectedCallback() {
    super.disconnectedCallback();
    this._stopPoll();
    Object.keys(this._logPolls || {}).forEach(id => this._stopLogPoll(id));
    if (this._onAuth) document.removeEventListener("enclave:auth", this._onAuth);
    if (this._onWallet) document.removeEventListener("enclave:wallet", this._onWallet);
    if (this._onAcct) document.removeEventListener("enclave:account", this._onAcct);
    if (this._onSess) document.removeEventListener("enclave:session", this._onSess);
    if (this._onLog) document.removeEventListener("enclave:runlog", this._onLog);
    if (this._onCat) document.removeEventListener("enclave:catalog", this._onCat);
    this._wired = false; this._onAuth = null; this._onWallet = null; this._onAcct = null; this._onSess = null; this._onLog = null; this._onCat = null;
  }

  /* ---- live-deploy strips: one per run streaming with no row to live in ---- */
  _strip(run, create) {
    let s = this._strips.get(run);
    if (s || create === false) return s || null;
    const wrap = this.querySelector(".enc-lives"); if (!wrap) return null;
    s = document.createElement("div");
    s.className = "enc-live";
    s.innerHTML = '<div class="enc-live-bar"><span class="elb-k">deploying</span><span class="enc-live-lbl"></span><button class="enc-live-x" type="button" title="dismiss" aria-label="Dismiss">✕</button></div>'
      + '<div class="term enc-live-out" role="status" aria-live="polite"></div>';
    s.querySelector(".enc-live-lbl").textContent = run.id || run.label || "";
    s.querySelector(".enc-live-x").addEventListener("click", () => { this._strips.delete(run); s.remove(); });
    const out = s.querySelector(".enc-live-out");
    run.lines.forEach(l => paintLine(out, l[0], l[1], null, l[2]));   // rejoined/resumed runs replay their history (l[2] = an action line's descriptor)
    wrap.appendChild(s);
    this._strips.set(run, s);
    return s;
  }
  /* a strip yields to its row the moment one exists (the row's Output panel
     carries the history from there); an UNCLAIMED deployment has no row (rows
     come from the enclave API), so its strip stays until claimed or dismissed */
  _retireStrip(run) {
    const s = this._strips.get(run);
    if (s && run.done && run.id && this.querySelector('.enc-outbtn[data-id="' + run.id + '"]')) {
      this._strips.delete(run); s.remove();
    }
  }
  _onRunlog(d) {
    if (d.type === "start") this._strip(d.run);
    else if (d.type === "id") {
      const s = this._strip(d.run, false);
      const lbl = s && s.querySelector(".enc-live-lbl"); if (lbl) lbl.textContent = d.run.id;
    }
    else if (d.type === "line") {
      const s = this._strip(d.run, false);               // a dismissed strip stays dismissed
      if (s) paintLine(s.querySelector(".enc-live-out"), d.cls, d.txt, null, d.act);
      // a row's open Output panel for this deployment follows the narrative too
      if (d.run.id) { const nar = this._openNar(d.run.id); if (nar) paintLine(nar.box, d.cls, d.txt, nar.scroller, d.act); }
    }
    else if (d.type === "end") this._retireStrip(d.run);
    else if (d.type === "clear") {                        // sign-out purged the run log
      this._strips.forEach((s) => s.remove());
      this._strips.clear();
    }
  }
  _openNar(id) {
    const row = this.querySelector('.enc-out[data-id="' + id + '"]:not([hidden])');
    if (!row) return null;
    return { box: row.querySelector(".enc-out-nar"), scroller: row.querySelector(".enc-out-term") };
  }

  async refresh(opts) {
    opts = opts || {};
    const body = this.querySelector(".enc-body");
    if (!body) return;
    this._paintedFor = Enclave.address;             // what this paint reflects (see _onWallet)
    this._paintedAcct = Enclave.accountAuthed();    // …and the account edge (_onAcct)
    this._paintedSess = Enclave.sessionMayServe();  // …and the wallet-session edge (_onSess)
    const hideBar = () => { const tb = this.querySelector(".enc-toolbar"); if (tb) tb.hidden = true; };
    if (!Enclave.address && !this._paintedAcct){
      this._stopPoll(); hideBar(); this._sessionNote();
      const pager = this.querySelector(".enc-pager"); if (pager){ pager.hidden = true; pager.innerHTML = ""; }
      body.innerHTML = '<div class="enc-empty">Sign in (above) to see your enclaves.</div>'; return;
    }
    // NO sign-in wall: a connected wallet is enough - the list is public
    // ledger data, scoped by address (api.js adds ?owner= when tokenless);
    // a session only enriches rows with the enclaves' live view
    // whose list this paint is: rows are never shown to another wallet/account
    const who = listIdentity(Enclave.address, this._paintedAcct, Enclave.accountId);
    if (!this._good) this._good = new LastGood();
    if (this._rowsFor !== who){ this._rowsFor = null; this._list = []; body.innerHTML = ""; }   // another identity's rows never linger through a load
    if (!body.querySelector(".enc-row") || opts.spinner) body.innerHTML = '<div class="loading" role="status">loading your enclaves…</div>';
    try {
      // fire-and-forget: the row art and the mobile section resolve versions
      // through the catalog STORE; a cold cache fills while the first paint
      // proceeds and the poll repaints with it (loadCatalog self-dedupes)
      loadCatalog().catch(() => null);
      const list = [];
      if (Enclave.address){
        const res = await Enclave.listDeployments();
        list.push(...(Array.isArray(res) ? res : ((res && (res.deployments || res.items || res.data)) || [])));
        // rows the wallet's SessionVault holds (sessions): the same panel, acted on through the session
        try {
          const seen = new Set(list.map((d) => String(d.id).toLowerCase()));
          for (const d of await (await import("../../js/core/sessions.js")).vaultRows())
            if (d.id && !seen.has(String(d.id).toLowerCase())) list.push(d);
        } catch(e){ /* sessions off or unreachable: wallet rows still serve */ }
      }
      // passkey/card accounts: rows owned by the account's credit vault (plus
      // legacy provisioned orders) via the relay's account-scoped ledger join -
      // the SAME row shape, so both kinds of customer share this panel
      if (this._paintedAcct){
        try {
          const seen = new Set(list.map((d) => String(d.id).toLowerCase()));
          for (const d of (await Enclave.accountDeployments()).deployments || []){
            if (!d.id) d.id = d.deploymentId;
            if (d.id && !seen.has(String(d.id).toLowerCase())) list.push(d);
          }
        } catch(e){ if (!Enclave.address) throw e; }   // wallet rows still serve
      }
      const tb = this.querySelector(".enc-toolbar"); if (tb) tb.hidden = false;   // refresh + Deploy CTA live here now
      this._good.ok(who, list);
      this._loadNote(null);
      this._sessionNote();
      this._rowsFor = who;
      this._renderRows(list, opts.highlight);
      this._startPoll();
    } catch(e){
      // an expired/refused session isn't a wall anymore: drop the token and
      // re-list scoped by the connected address (the public ledger view) -
      // but VISIBLY (the bar below), never silently: the fallback hides
      // runner-held truth, and the owner must know signing in restores it
      if (e.status === 401 && Enclave.token){ Enclave.token = null; Enclave.tokenBase = null; saveSession(); refreshWallet(); this._sessDropped = true; return this.refresh(opts); }
      this._listFailed(who, e);
      this._startPoll();   // keep retrying: the next good read clears the failure
    }
  }

  /* ---- a failed read is not an empty list (see js/core/list-state.js).
     Same identity with a good read behind it: those rows again, marked stale
     with their time. Otherwise: an error state, counters unknown ("–", never
     0), and none of anyone else's rows. Either way a Retry, plus the poll. ---- */
  _listFailed(who, e) {
    const body = this.querySelector(".enc-body"); if (!body) return;
    const v = this._good.failed(who, e);
    const tb = this.querySelector(".enc-toolbar"); if (tb) tb.hidden = false;   // refresh + Deploy CTA stay reachable
    if (v.kind === "stale"){
      if (this._rowsFor !== who || !body.querySelector(".enc-row")){ this._rowsFor = who; this._renderRows(v.rows); }
      this._loadNote(v);
      return;
    }
    this._list = []; this._rowsFor = null;
    this._loadNote(null);
    $$(".enc-segs button", this).forEach(b => { const n = b.querySelector("b"); if (n) n.textContent = "–"; b.classList.add("zero"); b.title = "not loaded"; });
    const pager = this.querySelector(".enc-pager"); if (pager){ pager.hidden = true; pager.innerHTML = ""; }
    body.innerHTML = '<div class="enc-empty enc-loaderr" role="alert" title="' + esc(e && e.message || String(e)) + '">'
      + 'Couldn’t load your apps: ' + esc(failureReason(e)) + '. This is a failed read, not an empty list. Retrying every 10 s. '
      + '<button type="button" class="btn btn-sm enc-retry">Retry now</button></div>';
    body.querySelector(".enc-retry").addEventListener("click", () => this.refresh({ spinner: true }));
  }
  _loadNote(v) {
    let el = this.querySelector(".enc-loadnote");
    if (!v){ if (el) el.remove(); return; }
    const body = this.querySelector(".enc-body"); if (!body) return;
    if (!el){
      el = document.createElement("div");
      el.className = "enc-sessnote enc-loadnote";
      el.setAttribute("role", "status");
      body.before(el);
    }
    el.title = (v.error && v.error.message) || "";
    el.innerHTML = '⚠ Couldn’t refresh: ' + esc(failureReason(v.error)) + '. Showing your apps as of ' + esc(asOf(v.at))
      + '; statuses may have changed since. Retrying every 10 s. <button type="button" class="btn btn-sm enc-retry">Retry now</button>';
    el.querySelector(".enc-retry").addEventListener("click", () => this.refresh({ spinner: true }));
  }

  /* ---- a dropped session must be VISIBLE. Every fleet update reboots the
     enclaves, which mints fresh in-enclave session keys (ramdisk-backed by
     design) and 401s every stored token; the refresh path above then falls
     back to the public ledger view. Right call - never wall the list - but
     the fallback hides what only the enclaves' view carries: a failed app's
     status and error. The owner sees a bare "queued", no error, and nothing
     suggesting sign-in would change that (found live 2026-08-06: a failed
     deployment read as "queued" through two fleet updates). This bar is the
     missing signal, and it offers the fix. ---- */
  _sessionNote() {
    let el = this.querySelector(".enc-sessnote");
    if (!(this._sessDropped && Enclave.address && !Enclave.token && !Enclave.sessionMayServe())){ if (el) el.remove(); return; }
    if (el) return;
    const body = this.querySelector(".enc-body"); if (!body) return;
    el = document.createElement("div");
    el.className = "enc-sessnote";
    el.setAttribute("role", "status");
    el.innerHTML = '⚠ Signed out by a fleet update. Rows show only public ledger status: a failed app reads as "queued" and its error stays hidden until you sign back in. '
      + '<button type="button" class="btn btn-sm es-signin">Sign in</button>';
    el.querySelector(".es-signin").addEventListener("click", async (e) => {
      const b = e.currentTarget; b.disabled = true; b.textContent = "signing in…";
      try { await authenticate(); this._sessDropped = false; this.refresh(); }
      catch(err){ showToast(err.message || String(err)); b.disabled = false; b.textContent = "Sign in"; }
    });
    body.before(el);
  }

  async _shares(id, btn) {
    const listed = (this._list || []).find(row => row.id === id);
    if (!listed) return;
    if (btn.dataset.editable === 'true' && listed.status === 'running') return this._upgrade(id, btn, 'shares');
    const box = btn.closest('.enc-row').querySelector('.enc-shares');
    if (box.dataset.busy) return;
    if (!box.hidden) { box.hidden = true; box.innerHTML = ''; btn.setAttribute('aria-expanded', 'false'); return; }
    box.hidden = false; btn.setAttribute('aria-expanded', 'true');
    box.innerHTML = '<p class="enc-shares-note">Reading app requirements and host capacity…</p>';
    try {
      const [d, fleet] = await Promise.all([
        /^0x[0-9a-f]{64}$/i.test(id) ? depGet(id) : Promise.resolve(listed),
        Enclave.getEnclaves().catch(() => null),
      ]);
      const ref = d.appRef || listed.image?.reference || (listed.app?.appId != null && listed.app?.index != null ? catalogRef(listed.app.appId, listed.app.index) : '');
      const cr = parseCatalogRef(ref);
      const spec = cr ? specOf(await catGetVersion(cr.appId, cr.index)) : specOfRef(ref);
      if (box.hidden || !box.isConnected) return;
      box.replaceChildren(this._resourceOverview(id, btn, { spec, fleet, configCid: d.configCid,
        unresolvedHost: listed.status === 'running' }));
      if (btn.dataset.editable === 'true') await this._resourceBudget(id, box);
    } catch (e) {
      if (!box.hidden && box.isConnected) box.innerHTML = '<p class="enc-shares-note">Could not load requirements. Close and reopen Resources to retry.</p>';
    }
  }

  async _resourceBudget(id, box) {
    // A price ceiling is meaningful before placement; unlike a host share it
    // must remain editable while an app is queued or stopped.
    let rev, cap, fee, availability;
    try { [rev, cap, fee, availability] = await Promise.all([depSchemaRev(), depCapOf(id), depFeeOf(id), Enclave.getAvailability()]); }
    catch { return; }
    if (box.hidden || !box.isConnected || rev < 8) return;
    const budget = document.createElement('div'); budget.className = 'enc-resource-overview enc-resource-budget';
    const inputId = 'resourceBudget' + appLabel(id);
    budget.innerHTML = '<h3>Price limit</h3><p class="enc-resource-note enc-resource-context">The maximum hourly price for the next host. A host above this limit cannot start the app.</p>'
      + '<label for="' + inputId + '">Rate cap ($/hour)</label><div class="enc-resource-budget-input"><input id="' + inputId + '" type="number" min="0" step="0.01" value="' + (Number(cap) * 3600 / 1e6).toFixed(2) + '">'
      + '<button class="btn btn-sm" type="button" disabled>Save price limit</button></div><p class="enc-resource-note" role="status"></p>';
    box.append(budget);
    const input = budget.querySelector('input'), button = budget.querySelector('button'), status = budget.querySelector('[role="status"]');
    const value = () => { const n = Number(input.value); return Number.isFinite(n) && n > 0 ? BigInt(Math.round(n * 1e6 / 3600)) : 0n; };
    if (availability?.rateCap !== true) { input.disabled = true; status.textContent = 'The fleet cannot edit this price limit right now.'; return; }
    input.addEventListener('input', () => { button.disabled = value() <= fee.feePerSec6 || value() === cap; });
    button.addEventListener('click', async () => {
      const next = value(); if (box.dataset.busy || next <= fee.feePerSec6 || next === cap) return;
      box.dataset.busy = 'true'; button.disabled = input.disabled = true;
      const via = ctlOf((this._list || []).find(d => d.id === id)) === 'vault';
      try {
        if (await depCapOf(id) !== cap) throw Error('The price limit changed elsewhere. Reopen Resources to refresh it.');
        status.textContent = 'Confirm the price limit in your ' + (via ? 'passkey prompt.' : 'wallet.');
        if (via) await (await import('../../js/core/vault.js')).vaultOp('control', { id, action: 'maxrate', maxRate6: Number(next) });
        else {
          if (!Enclave.provider) await connectWallet();
          await ensureBaseChain();
          await waitReceipt(await sendTx(DEPLOYMENTS_ADDRESS, encCall(DEP_SEL.setMaxRate, [{ t: 'bytes32', v: id }, { t: 'uint', v: next }])));
        }
        cap = next; status.textContent = 'Price limit saved.';
      } catch (e) { status.textContent = e.message || String(e); }
      finally { delete box.dataset.busy; input.disabled = false; button.disabled = value() === cap; if (!via) refreshWallet(); }
    });
  }

  _resourceOverview(id, btn, options) {
    return resourceOverview({ ...options, editable: btn.dataset.editable === 'true', onChooseHost: async name => {
      const row = btn.closest('.enc-row'), pin = row.querySelector('.enc-movebtn');
      if (!pin) return;
      const box = row.querySelector('.enc-shares');
      if (box.dataset.busy) return;
      box.hidden = true; box.innerHTML = ''; btn.setAttribute('aria-expanded', 'false');
      const move = row.querySelector('.enc-move');
      if (move.hidden) await this._move(id, pin);
      const select = move.querySelector('select');
      if (name && select && [...select.options].some(option => option.value === name && !option.disabled)) {
        select.value = name; select.dispatchEvent(new Event('change', { bubbles: true }));
      }
      pin.focus(); move.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    } });
  }

  _renderRows(list, highlight) {
    const body = this.querySelector(".enc-body");
    list = (list || []).slice().sort((a, b) => String(b.createdAt || "").localeCompare(String(a.createdAt || "")));
    this._list = list;
    const counts = countBuckets(list);
    $$(".enc-segs button", this).forEach(b => { const n = b.querySelector("b"); if (n) n.textContent = String(counts[b.dataset.bucket] || 0); b.classList.toggle("zero", !(counts[b.dataset.bucket] > 0)); b.title = ""; });
    let shown = this._filter === "all" ? list.slice() : list.filter(d => bucketOf(d.status) === this._filter);
    if (this._q) shown = shown.filter(d =>
      [d.id, deploymentTitle(d), d.image && d.image.reference, d.status, d.enclave]
        .filter(Boolean).join(" ").toLowerCase().includes(this._q));
    const pager = this.querySelector(".enc-pager");
    const clearPager = () => { if (pager){ pager.hidden = true; pager.innerHTML = ""; } };
    if (!list.length){ body.innerHTML = '<div class="enc-empty">No apps yet. <a href="apps">Deploy one →</a></div>'; clearPager(); return; }
    if (!shown.length){ body.innerHTML = '<div class="enc-empty">Nothing here - pick another status tab or clear the search.</div>'; clearPager(); return; }
    // paginate: 5 rows per page (the list grows unbounded; keep the panel short).
    // The page persists across the 10s poll; a just-deployed (highlighted) row
    // pulls the view to whichever page it lands on; clamp when the list shrinks.
    const PER_PAGE = 5;
    const pages = Math.max(1, Math.ceil(shown.length / PER_PAGE));
    if (highlight){ const hi = shown.findIndex(d => d.id === highlight); if (hi >= 0) this._page = Math.floor(hi / PER_PAGE); }
    if (this._page >= pages) this._page = pages - 1;
    if (!(this._page >= 0)) this._page = 0;
    const pageRows = shown.slice(this._page * PER_PAGE, this._page * PER_PAGE + PER_PAGE);
    body.innerHTML = pageRows.map(d => {
      const ep = appEndpoint(d), st = d.status || "–";
      // vault rows speak in dollars (account customers never see token names);
      // wallet rows keep the explicit USDC wording. Paid AND spent: both row
      // sources (supervisor live view, relay ledger view) carry spentUsdc.
      const ctl = ctlOf(d);
      const bud = (d.paidUsdc != null)
        ? ((ctl === "wallet" ? esc(d.paidUsdc) + " USDC paid" : "$" + esc(d.paidUsdc) + " paid")
           + (d.spentUsdc != null ? " · " + (ctl === "wallet" ? esc(d.spentUsdc) : "$" + esc(d.spentUsdc)) + " spent" : "")
           + (d.timeRemainingSec > 0 ? " · " + esc(fmtDur(d.timeRemainingSec)) + " left" : "")
           + (d.paused ? " · ⏸ time frozen (" + esc(d.pauseReason || "outage") + ", resumes when service is restored)" : ""))
        : "–";
      const onchain = /^0x[0-9a-f]{64}$/i.test(d.id || "");
      // on-chain rows without a live runner stay actionable: queued/claimed
      // work can be topped up, and awaiting_payment/unfunded are Top up's
      // whole point (unfunded = drained; a top-up is what un-sticks it).
      // "expired" is the ex-runner's word for that same drained state (its
      // record shadows the ledger's "unfunded" while signed in): the record
      // is still active on the ledger, so it takes top-ups and the claim
      // sweep re-adopts it the moment the balance covers the rate again.
      // "failed" is the same shape with a different cause: the runner kept
      // the record as the owner's evidence of WHY (crash loop, provision
      // failure) and handed the lease back, but the ledger row stays active
      // with its balance - and failed is claim-terminal, so the fleet
      // re-adopts once the cause is fixed. The FIX lives in these controls
      // (switch Version, Top up, edit Secrets, Resume's claim-hint nudge),
      // so hiding them on failure would lock the owner out of the recovery.
      const live = ["running", "provisioning", "queued", "pending", "claiming", "claimed", "awaiting_payment", "unfunded"].indexOf(st) !== -1
        || (onchain && (st === "expired" || st === "failed"));
      // on-chain rows are WORK ITEMS: setActive(false) suspends (the remaining
      // balance stays on the record) and setActive(true) re-queues it, so a
      // stopped/terminated on-chain row is resumable, not gone. "stopped" is
      // the ledger's word for it; "terminated" is the ex-runner's own record
      // of the same suspend (it shadows the ledger row while signed in).
      // "expired" resumes too - watchdog/consolidation expiries keep a spendable
      // balance and only need the re-queue nudge (_resume skips the setActive
      // tx when the ledger record never went inactive; a drained one gets told
      // to Top up instead of a relaunch promise that can't happen).
      // "failed" resumes the same way expired does: its ledger record never
      // went inactive, so _resume skips the setActive signature and the
      // claim-hint nudge alone re-queues it (typically after a Version
      // switch fixed what made it fail).
      // Legacy dep_ instances have no ledger record to reactivate: theirs
      // stays Terminate, and ended legacy rows offer nothing.
      const resumable = onchain && (st === "stopped" || st === "terminated" || st === "expired" || st === "failed");
      // the row's app identity, shared by the cover-art chip and the meta line
      const appLbl = deploymentTitle(d);
      const shareText = encTier(d);
      const art = artOfRef(d.image && d.image.reference, appLbl || d.id);
      // the card leads with the APP, not the raw id: the bytes32 becomes a
      // compact copy chip (full value in data-copy/title), stated once per card
      const idShort = (d.id || "").length > 20 ? d.id.slice(0, 10) + "…" + d.id.slice(-4) : (d.id || "–");
      // runway gauge: measures TIME LEFT against a fixed 48h horizon, NOT
      // spent/paid - a long-lived topped-up row has spent≈paid forever, which
      // would pin a spend-ratio bar at empty beside a healthy "14h left".
      // Floor at 2% so a nearly-drained row still shows a sliver; amber under
      // 6h (the bar length itself is the non-color cue, text has the number).
      const RUNWAY_FULL = 172800, RUNWAY_LOW = 21600;
      const runwaySec = live && d.timeRemainingSec > 0 ? d.timeRemainingSec : null;
      const runwayPct = runwaySec != null ? Math.max(2, Math.min(100, Math.round(100 * runwaySec / RUNWAY_FULL))) : null;
      return '<div class="enc-row' + (highlight && d.id === highlight ? " enc-new" : "") + '">' +
        '<div class="enc-main">' +
          '<span class="enc-thumb" style="background-image:' + art + '" aria-hidden="true"></span>' +
          '<span class="enc-title">' + esc(appLbl || idShort) + '</span>' +
          '<span class="ap-badge ' + statusCls(st) + '">' + esc(st) + '</span>' +
          '<span class="ap-badge ' + (d.public ? 'ep-public' : 'ep-private') + '" title="' + (d.public ? 'anyone can reach the app endpoint' : 'only your wallet token can reach the app') + '">' + (d.public ? 'public' : 'private') + '</span>' +
          '<span class="ap-badge info ep-waf" data-wafb="' + esc(d.id) + '" hidden>protected</span>' +
          '<span class="ap-badge ep-cfg" data-cfgb="' + esc(d.id) + '" hidden>custom config</span>' +
          '<button class="enc-id" data-copy="' + esc(d.id) + '" title="' + esc(d.id) + '" aria-label="copy deployment id">' + esc(idShort) + ' ⧉</button>' +
          '<span class="enc-br" aria-hidden="true"></span>' +
          (shareText || d.enclave ? '<span class="enc-meta">' + (shareText ? '<span class="enc-allocation">' + shareText + '</span>' : '')
            // which box serves it (relay stamps `enclave` on live-hosted and
            // lease-held rows alike; absent while queued/stopped - nothing runs it)
            + (d.enclave ? (shareText ? ' · ' : '') + '<span class="dim enc-host" title="the enclave this app runs on">on ' + esc(d.enclave) + '</span>' : '') + '</span>' : '') +
          '<span class="enc-spend">' + bud + '</span>' +
          (runwayPct != null ? '<span class="enc-meter' + (runwaySec < RUNWAY_LOW ? ' low' : '') + '" title="' + esc(fmtDur(runwaySec)) + ' of paid runtime left · full bar = 48h" aria-hidden="true"><b style="width:' + runwayPct + '%"></b></span>' : '') +
          // the acts row holds only IMMEDIATE actions; everything that opens a
          // panel lives in the tab strip below (develop-page tab idiom)
          '<span class="enc-acts">' +
            (st === "running" && ctl === "wallet" ? '<button class="btn btn-sm enc-restart" data-id="' + esc(d.id) + '" title="Stop and relaunch the app in place - same version, endpoint and balance; app state is ephemeral. The fix for a wedged instance (e.g. a model that never loaded at boot)">Restart</button>' : '') +
            (resumable && ctl !== "order" ? '<button class="btn btn-sm ok enc-resume" data-id="' + esc(d.id) + '" title="Put it back on the queue - an enclave re-claims it and the app relaunches fresh from its published version, spending the remaining balance">Resume</button>' : '') +
            (live && ctl !== "order" ? (onchain
              ? '<button class="btn btn-sm warn enc-kill" data-id="' + esc(d.id) + '" title="Stop the app and take it off the queue. The remaining balance stays on the deployment - Resume restarts it any time">Suspend</button>'
              : '<button class="btn btn-sm danger enc-kill" data-id="' + esc(d.id) + '">Terminate</button>') : '') +
            // Cancel is the one-way door Suspend is not: it ENDS the deployment
            // and sends its unused runtime back. Offered on stopped rows too -
            // suspend-then-cancel is the ordinary path. The dialog quotes the
            // real payout from the ledger before anything is signed, because it
            // is not the balance (see _refund).
            (onchain && (live || resumable) && ctl !== "order" ? '<button class="btn btn-sm danger enc-refund" data-id="' + esc(d.id) + '" title="End this deployment and send its unused runtime back' + (ctl === "vault" ? ' to your credit balance' : ' to your wallet') + '. You get back what the contract still holds for it, which is less than the balance - the exact amount is shown before you confirm">Cancel</button>' : '') +
          '</span>' +
        '</div>' +
        ((st === "failed" || st === "expired") && d.error ? '<div class="enc-err" title="why this deployment ' + esc(st) + '">⚠ ' + esc(d.error) + '</div>' : '') +
        // a version change the runner could not apply yet (unapproved/oversized
        // target, catalog unreachable): the OLD version keeps serving; say why
        (d.versionChange && d.versionChange.error ? '<div class="enc-err" title="the requested version change has not applied - the previous version keeps serving; the runner retries automatically">⚠ version change pending: ' + esc(d.versionChange.error) + '</div>' : '') +
        (st === "queued" ? '<div class="enc-why" data-why="' + esc(d.id) + '" role="status" aria-live="polite" hidden></div>' : '') +
        (ep ? '<div class="enc-eprow"><button class="enc-ep" data-ep="' + esc(ep) + '">' + esc(ep) + ' ⧉</button>'
              + openCtl(d, ep, this._tls && this._tls.get(d.id)) + '</div>' : '') +
        // panel tabs (develop-page idiom): each button toggles its panel below;
        // aria-expanded doubles as the active-tab style hook. Transfer lives
        // here - it opens a panel and does not belong beside Cancel.
        '<div class="enc-tabs" role="group" aria-label="deployment panels">' +
          '<button class="btn btn-sm enc-outbtn" data-id="' + esc(d.id) + '" aria-expanded="false">Output</button>' +
          (live && ctl !== "order" ? '<button class="btn btn-sm enc-fundbtn" data-id="' + esc(d.id) + '" aria-expanded="false" title="' + (ctl === "vault" ? 'Add runtime from your credit balance - one passkey tap' : 'Add runtime - a gas-free USDC signature credits the deployment’s on-chain balance') + '">Top up</button>' : '') +
          (onchain && (live || resumable) && ctl !== "order" ? '<button class="btn btn-sm enc-upgbtn" data-id="' + esc(d.id) + '" aria-expanded="false" title="Switch to another approved version of this app - paid time carries over; the app restarts in place on the new version">Version</button>' : '') +
          '<button class="btn btn-sm enc-sharesbtn" data-id="' + esc(d.id) + '" data-editable="' + (onchain && (live || resumable) && ctl !== "order") + '" aria-expanded="false" title="App requirements, host capacity, and running allocation">Resources</button>' +
          (onchain && (live || resumable) && ctl !== "order" ? '<button class="btn btn-sm enc-cfgbtn" data-id="' + esc(d.id) + '" aria-expanded="false" title="This deployment’s app config (its ENCLAVE_CONFIG): edit it, save named variations, or reset to the version’s stock config - the catalog default and every other deployment stay untouched">Config</button>' : '') +
          (onchain && (live || resumable) && ctl !== "order" ? '<button class="btn btn-sm enc-modbtn" data-id="' + esc(d.id) + '" aria-expanded="false" title="The model volumes this app mounts: attested read-only weights the fleet carries, picked by name - a change relaunches the app in place on the new set; the catalog and every other deployment stay untouched">Models</button>' : '') +
          (onchain && (live || resumable) && ctl !== "order" ? '<button class="btn btn-sm enc-wafbtn" data-id="' + esc(d.id) + '" aria-expanded="false" title="Per-IP rate limit + request filter, enforced inside the enclave at the app’s front door - add, tune or remove it any time; a running app picks the change up live">Protect</button>' : '') +
          (onchain && (live || resumable) && ctl !== "order" ? '<button class="btn btn-sm enc-netbtn" data-id="' + esc(d.id) + '" aria-expanded="false" title="This app’s network: its routes, providers and settings. TLS ends in the app guest.">Network</button>' : '') +
          '<button class="btn btn-sm enc-movebtn" data-id="' + esc(d.id) + '" aria-expanded="false" title="Choose a preferred host for this app, or resume an ended app on a selected host. Same URL, version and balance">Pin</button>' +
          '<button class="btn btn-sm enc-verify" data-id="' + esc(d.id) + '" aria-expanded="false">Verify</button>' +
          (mobileOffer(d, ep) ? '<button class="btn btn-sm enc-mobbtn" data-id="' + esc(d.id) + '" aria-expanded="false" title="Install this app on a phone - the mobile build verifies the enclave on the device before the app loads">Downloads</button>' : '') +
          // secrets/domains are tabs like every other panel; their toggle
          // buttons live HERE, the sections below hold only body + status
          // (the wire helpers resolve the toggle at row level)
          (onchain && (live || resumable) && ctl === "wallet" ? '<button class="btn btn-sm es-toggle" aria-controls="esBody' + appLabel(d.id) + '" aria-expanded="false" title="Private env vars for this app (S3 keys, API tokens): stored on the relay - never on the public chain - and injected at app start by the enclave holding its lease. One wallet signature reveals them for editing">Secrets</button>' : '') +
          (onchain && (live || resumable) && ctl === "wallet" ? '<button class="btn btn-sm ed-toggle" aria-controls="edBody' + appLabel(d.id) + '" aria-expanded="false" title="Serve this app on a domain you own, with a certificate minted inside the enclave">Domains</button>' : '') +
          // wallet rows only: a vault-owned record's on-chain owner IS the
          // vault contract - handing it to an outside wallet would tear it
          // out of the vault's accounting (a vault feature if ever wanted)
          (onchain && (live || resumable) && ctl === "wallet" ? '<button class="btn btn-sm enc-xferbtn" data-id="' + esc(d.id) + '" aria-expanded="false" title="Hand this deployment to another wallet. Control moves, money never does: any refundable escrow returns to YOUR wallet first (the ledger refuses to transfer it), then the record - with its staged secrets and custom domains - changes hands. One-shot, no way back from this wallet">Transfer</button>' : '') +
        '</div>' +
        '<div class="enc-fund" hidden></div>' +
        '<div class="enc-upg" hidden></div>' +
        '<div class="enc-shares" hidden></div>' +
        '<div class="enc-move" hidden></div>' +
        '<div class="enc-waf" hidden></div>' +
        '<div class="enc-net" hidden></div>' +
        '<div class="enc-cfg" hidden></div>' +
        '<div class="enc-mod" hidden></div>' +
        '<div class="enc-mob" hidden></div>' +
        '<div class="enc-xfer" hidden></div>' +
        (onchain && (live || resumable) && ctl === "wallet" ? secretsSection(d.id) : '') +
        (onchain && (live || resumable) && ctl === "wallet" ? domainsSection(d.id) : '') +
        '<div class="enc-out" data-id="' + esc(d.id) + '" hidden></div>' +
        '<div class="enc-att" hidden></div>' +
      '</div>';
    }).join("");
    $$(".enc-id", body).forEach(b => b.addEventListener("click", () => copyText(b.dataset.copy)));
    $$(".enc-ep", body).forEach(b => b.addEventListener("click", () => copyText(b.dataset.ep)));
    // STRICT tabs: opening one panel first closes any open sibling - via the
    // open tab's own click path (capture phase runs before the open handler),
    // so each panel keeps its own close semantics. Re-entry is safe: the
    // synthetic click hits a button whose aria-expanded is "true", which the
    // opening-only selector below ignores.
    $$(".enc-tabs", body).forEach(strip => strip.addEventListener("click", (e) => {
      const b = e.target.closest('button[aria-expanded="false"]');
      if (!b) return;
      $$('button[aria-expanded="true"]', strip).forEach(o => { if (o !== b) o.click(); });
    }, true));
    $$(".enc-outbtn", body).forEach(b => b.addEventListener("click", () => this._output(b.dataset.id, b)));
    $$(".enc-fundbtn", body).forEach(b => b.addEventListener("click", () => this._fund(b.dataset.id, b)));
    $$(".enc-upgbtn", body).forEach(b => b.addEventListener("click", () => this._upgrade(b.dataset.id, b)));
    $$(".enc-sharesbtn", body).forEach(b => b.addEventListener("click", () => this._shares(b.dataset.id, b)));
    $$(".enc-movebtn", body).forEach(b => b.addEventListener("click", () => this._move(b.dataset.id, b)));
    $$(".enc-wafbtn", body).forEach(b => b.addEventListener("click", () => this._waf(b.dataset.id, b)));
    $$(".enc-cfgbtn", body).forEach(b => b.addEventListener("click", () => this._configPanel(b.dataset.id, b)));
    $$(".enc-modbtn", body).forEach(b => b.addEventListener("click", () => this._models(b.dataset.id, b)));
    $$(".enc-netbtn", body).forEach(b => b.addEventListener("click", () => this._network(b.dataset.id, b)));
    $$(".enc-xferbtn", body).forEach(b => b.addEventListener("click", () => this._transfer(b.dataset.id, b)));
    $$(".enc-sec[data-id]", body).forEach(el => this._secretsWire(el));
    $$(".enc-dom[data-id]", body).forEach(el => this._domainsWire(el));
    $$(".enc-mobbtn", body).forEach(b => b.addEventListener("click", () => this._mobile(b.dataset.id, b)));
    $$(".enc-verify", body).forEach(b => b.addEventListener("click", () => this._verify(b.dataset.id, b)));
    // each allocation's pool pill, coloured as Live enclaves colours the serving box's pool
    $$(".enc-pool[data-box]", body).forEach(el => boxRowOf(el.dataset.box).then((row) => {
      const html = row && (el.dataset.pool === "gpu" ? gpuPoolBadge(row) : cpuPoolBadge(row));
      if (html && el.isConnected) el.innerHTML = html;
    }).catch(() => {}));
    $$(".enc-kill", body).forEach(b => b.addEventListener("click", () => this._kill(b.dataset.id, b)));
    $$(".enc-refund", body).forEach(b => b.addEventListener("click", () => this._refund(b.dataset.id, b)));
    $$(".enc-resume", body).forEach(b => b.addEventListener("click", () => this._resume(b.dataset.id, b)));
    $$(".enc-restart", body).forEach(b => b.addEventListener("click", () => this._restart(b.dataset.id, b)));
    this._fillWhy();               // cached decline reasons repaint instantly with the rows
    this._probeWhy(pageRows);      // then refresh them (throttled per row)
    this._probeTls(pageRows);      // TLS-gate the Open controls (throttled per row)
    this._probeEnv(pageRows);      // WAF badges from the cached options envelope
    this._renderPager(pages, shown.length, PER_PAGE);
    // finished runs' strips yield to their rows the moment those render
    [...this._strips.keys()].forEach(r => this._retireStrip(r));
    // a just-deployed row opens its Output panel so the narrative continues in place
    if (highlight) {
      const b = body.querySelector('.enc-outbtn[data-id="' + highlight + '"]');
      if (b && runlog.runFor(highlight)) this._output(highlight, b);
    }
  }

  /* ---- queued rows: WHY is the fleet not taking this? ----
     "queued" only says no runner holds a lease - the ledger can't say why.
     /v1/claim-hint runs the enclaves' exact claim gauntlet and returns the
     decline reason, so the row can distinguish "waiting on capacity" from
     TERMINAL states (below the app's minimum shares, unapproved version,
     retired configCid) where no amount of waiting ever starts the app and
     the only exit is suspend + redeploy (created shares are immutable).
     Without this, a permanently unclaimable deployment is indistinguishable
     from a patient one - it took chain forensics to tell them apart once
     (2026-07-14, 0xf3d976a0…). Probes are throttled hard: current page only,
     30s per row - the enclave's hint bucket is per-source-IP and the relay
     pools every browser behind its one IP. ---- */
  async _probeWhy(rows) {
    this._why = this._why || new Map();
    for (const d of rows) {
      if ((d.status || "") !== "queued" || !/^0x[0-9a-f]{64}$/i.test(d.id || "")) continue;
      const c = this._why.get(d.id);
      if (c && Date.now() - c.at < 30_000) continue;
      this._why.set(d.id, { ...(c || {}), at: Date.now() });   // stamp before the await: overlapping polls must not double-probe
      try {
        const r = await fetch(Enclave.base + "/claim-hint", { method: "POST",
          headers: { "content-type": "application/json" }, body: JSON.stringify({ id: d.id }) });
        const h = await r.json();
        if (h && h.accepted === false && h.reason)
          this._why.set(d.id, { at: Date.now(), reason: h.reason, terminal: WHY_TERMINAL.test(h.reason) });
        else if (h && h.accepted === true)
          this._why.set(d.id, { at: Date.now(), reason: "", terminal: false });   // being claimed - clear the line
      } catch(e){}   // 429 / network: keep what we knew, retry next cycle
    }
    this._fillWhy();
  }
  _fillWhy() {
    if (!this._why) return;
    $$(".enc-why", this).forEach(el => {
      const c = this._why.get(el.dataset.why);
      if (!c || !c.reason){ el.hidden = true; el.innerHTML = ""; el.classList.remove("enc-err"); return; }
      el.classList.toggle("enc-err", !!c.terminal);
      el.innerHTML = c.terminal
        ? "⚠ won’t start by waiting - the fleet refuses this work: " + esc(c.reason)
          + " (check the app’s minimum resources in Resources)"
        : '<span class="dim">fleet: ' + esc(c.reason) + " - retrying automatically</span>";
      el.hidden = false;
    });
  }

  /* ---- per-row envelope badges: what does the options envelope carry?
     The `waf` namespace supplies the protection badge. The list rows (supervisor live view /
     relay ledger view) don't carry the envelope, so visible on-chain rows get
     ONE cached ledger read each - an envelope only changes via an owner tx, so
     the cache lives until a panel rewrites it (which flips its badge in
     place). ---- */
  async _probeEnv(rows) {
    this._env = this._env || new Map();
    for (const d of rows) {
      const id = d.id;
      if (!/^0x[0-9a-f]{64}$/i.test(id || "")) continue;
      const c = this._env.get(id);
      if (c) { this._envPaint(id); continue; }
      this._env.set(id, { waf: false, summary: "" });   // stamp before the await: overlapping polls must not double-read
      try {
        const dd = await depGet(id);
        this._envLearn(id, dd && dd.configCid);
      } catch (e) { this._env.delete(id); }             // unread: a later repaint retries
    }
  }
  /* parse an envelope string into the cache + repaint that row's badges -
     shared by the probe, each panel's open (fresh read) and its apply
     (optimistic), so the badges always say what the ledger says */
  _envLearn(id, envelope) {
    this._env = this._env || new Map();
    let w = null, o = null;
    const raw = String(envelope || "").trim();
    if (raw.startsWith("{")) { try { const p = JSON.parse(raw); if (p && typeof p === "object" && !Array.isArray(p)) o = p; } catch (e) {} }
    if (o && o.waf && typeof o.waf === "object" && !Array.isArray(o.waf)) w = o.waf;
    const summary = w ? [
      w.rps != null ? w.rps + " r/s per IP" : null,
      w.burst != null ? "burst " + w.burst : null,
      w.maxConcurrent != null ? w.maxConcurrent + " in flight/IP" : null,
      w.maxBodyMb != null ? "max body " + w.maxBodyMb + " MB" : null,
      w.blockScanners ? "scanner paths blocked" : null,
    ].filter(Boolean).join(" \u00b7 ") : "";
    // `config` present at all = an override (even {} - explicitly empty is a
    // choice, and the badge is how the owner remembers having made it)
    this._env.set(id, { waf: !!w, summary, cfg: !!(o && "config" in o) });
    this._envPaint(id);
  }
  _envPaint(id) {
    const c = this._env && this._env.get(id);
    if (!c) return;
    const b = this.querySelector('.ep-waf[data-wafb="' + id + '"]');
    if (b) {
      b.hidden = !c.waf;
      if (c.waf) b.title = "Protection is on: " + c.summary + " - the Protect button tunes or removes it";
    }
    const k = this.querySelector('.ep-cfg[data-cfgb="' + id + '"]');
    if (k) {
      k.hidden = !c.cfg;
      if (c.cfg) k.title = "This deployment runs its own app config, not the version’s stock one - the Config button shows, edits or resets it";
    }
  }

  async _probeTls(rows) {
    this._tls = this._tls || new Map();
    // Probe rows independently: one unanswered app must not delay every other lock.
    await Promise.all(rows.map(async d => {
      if ((d.status || "") !== "running") { this._tls.delete(d.id); return; }
      const href = safeHref(appEndpoint(d));
      if (!/^https:\/\//i.test(href)) return;
      const c = this._tls.get(d.id);
      if (c?.href === href && (c.pending || Date.now() - c.at < (c.state === "ok" ? 300_000 : 8_000))) return;
      const pending = { state: c?.href === href ? c.state : "noanswer", href, pending: true, at: Date.now() };
      this._tls.set(d.id, pending);
      try {
        const result = await probeAppTls(href);
        // A newer endpoint or stopped row invalidates an older in-flight result.
        if (this._tls.get(d.id) === pending)
          this._tls.set(d.id, { ...result, href, at: Date.now() });
      } catch (e) {
        if (this._tls.get(d.id) === pending)
          this._tls.set(d.id, { state: "noanswer", href, at: Date.now(), error: e?.name || "Error" });
      }
      this._fillTls();
    }));
  }
  /* swap Open controls in place when a probe verdict differs from what's
     rendered - the 10s poll skips repaints while a panel is open, and the
     first probe usually lands between two paints */
  _fillTls() {
    if (!this._tls) return;
    $$("[data-tls]", this).forEach(el => {
      const c = this._tls.get(el.dataset.tls);
      // both verdicts render an <a> now, so the tag no longer identifies the state: the
      // unknown one carries enc-open-unknown, and that is what a repaint compares.
      const d = (this._list || []).find(x => x.id === el.dataset.tls);
      const ok = !!(d && c?.href === safeHref(appEndpoint(d)) && c.state === "ok");
      if (ok === !el.classList.contains("enc-open-unknown")) return;
      const html = d ? openCtl(d, appEndpoint(d), c) : "";
      if (html) el.outerHTML = html;
    });
  }

  /* ---- pager: prev · "x–y of N" · next. Hidden for a single page. ---- */
  _renderPager(pages, total, per) {
    const pager = this.querySelector(".enc-pager"); if (!pager) return;
    if (pages <= 1){ pager.hidden = true; pager.innerHTML = ""; return; }
    const p = this._page, first = p * per + 1, last = Math.min(total, (p + 1) * per);
    pager.hidden = false;
    pager.innerHTML =
      '<button class="btn btn-sm enc-pg" data-pg="prev" type="button"' + (p <= 0 ? " disabled" : "") + '>← prev</button>' +
      '<span class="enc-pg-info">' + first + '–' + last + ' of ' + total + ' · page ' + (p + 1) + ' of ' + pages + '</span>' +
      '<button class="btn btn-sm enc-pg" data-pg="next" type="button"' + (p >= pages - 1 ? " disabled" : "") + '>next →</button>';
    $$(".enc-pg", pager).forEach(b => b.addEventListener("click", () => {
      this._page += b.dataset.pg === "next" ? 1 : -1;
      this._renderRows(this._list || []);
      const top = this.querySelector(".enc-body");
      if (top) top.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }));
  }

  /* ---- per-row Top up: extend a deployment's runtime in place. One amount,
     the runtime it adds at this deployment's own rate, one gas-free USDC
     signature (EIP-3009 -> fundWithAuthorization; same flow as deploying). ---- */
  _fund(id, btn) {
    const row = btn.closest(".enc-row"), box = row && row.querySelector(".enc-fund"); if (!box) return;
    if (!box.hidden){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); return; }
    btn.setAttribute("aria-expanded", "true");
    const d = (this._list || []).find(x => x.id === id) || {};
    const via = ctlOf(d) === "vault";   // credit-vault row: passkey-signed, spends account credit
    const r = d.resources || {};
    const gpuPct = Math.round((r.gpuShare || 0) * 100), cpuPct = Math.round((r.cpuShare != null ? r.cpuShare : (r.share || 0)) * 100);
    // the deployment's own burn rate: the API's live number (the on-chain
    // snapshot) when present; else the CONTRACT's prices; constants only
    // until that read lands
    let rate = parseFloat(d.ratePerSecondUsdc) || shareRates(gpuPct, cpuPct).rate;
    if (!parseFloat(d.ratePerSecondUsdc))
      depPrices6().then(pr => { rate = Number(rate6Of(pr, gpuPct * 10, cpuPct * 10)) / 1e6; if (box.isConnected && !box.hidden) upd(); }).catch(() => {});
    box.hidden = false;
    box.innerHTML = '<div class="ap-attbar">top up · ' + esc(id) + '</div>'
      + '<div class="enc-fund-body">'
      +   '<label for="efAmt">Add runtime (' + (via ? 'USD' : 'USDC') + ')</label>'
      +   '<input class="ef-amt" id="efAmt" type="number" value="5" min="0.01" step="any" inputmode="decimal" />'
      +   '<span class="ef-est"></span>'
      +   '<button class="btn btn-sm btn-primary ef-go" type="button">' + (via ? 'Confirm with passkey' : 'Sign &amp; pay') + '</button>'
      + '</div>'
      + '<div class="term enc-fund-status" role="status" aria-live="polite"></div>';
    const amt = box.querySelector(".ef-amt"), est = box.querySelector(".ef-est");
    const go = box.querySelector(".ef-go"), st = box.querySelector(".enc-fund-status");
    const paint = (cls, txt) => paintLine(st, cls, txt);
    // a drained row (expired on the runner's record, unfunded on the ledger's)
    // has no runner watching its balance: funding is what re-queues it, and one
    // claim-hint makes the fleet's re-claim prompt instead of next-sweep
    const revive = ["expired", "unfunded"].indexOf(d.status || "") !== -1;
    const nudge = () => { if (revive) fetch(Enclave.base + "/claim-hint", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ id }) }).catch(() => {}); };
    const okTail = revive ? " · re-queued: the fleet re-claims it and the app relaunches within a minute"
                          : " · the enclave picks up the new balance within a minute";
    const upd = () => {
      const usd = parseFloat(amt.value) || 0;
      est.textContent = (rate > 0 && usd > 0) ? "adds ≈ " + fmtDur(usd / rate) : "";
      go.disabled = !(usd >= 0.01);
    };
    amt.addEventListener("input", upd); upd();
    go.addEventListener("click", async () => {
      const usd = parseFloat(amt.value) || 0; if (!(usd >= 0.01)) return;
      go.disabled = true; st.innerHTML = "";
      if (via){
        // credit path: the vault owns this deployment on-chain; one passkey
        // tap signs fundDeployment and the balance moves credit -> deployment
        try {
          paint("info", "[*] confirm with your passkey…");
          const { vaultOp } = await import("../../js/core/vault.js");
          await vaultOp("fund", { id, amountUsd: usd });
          nudge();
          paint("ok", "[✓] topped up from your credit" + (rate > 0 ? " - +" + fmtDur(usd / rate) + " of runtime" : "") + okTail);
          showToast("topped up " + id.slice(0, 10) + "… with $" + usd.toFixed(2));
          setTimeout(() => { if (box.isConnected && !box.hidden){ box.hidden = true; box.innerHTML = ""; } this.refresh(); }, 3500);
        } catch(e){ paint("warn", "[x] " + (e.message || String(e))); }
        finally { go.disabled = false; }
        return;
      }
      try {
        // no SIWE: the EIP-3009 authorization IS the proof of key ownership
        if (!Enclave.provider){ paint("info", "[*] connecting wallet…"); await connectWallet(); }
        await ensureBaseChain();
        let pricing = null;
        try { pricing = await (await fetch(Enclave.base + "/pricing", { signal: AbortSignal.timeout(8000) })).json(); } catch(e){}
        await payForRuntime({
          contract: DEPLOYMENTS_ADDRESS, deploymentRef: id,
          usdcDomain: pricing && pricing.usdcDomain, usdc: (pricing && pricing.usdc) || "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          ethUsd: pricing && pricing.ethUsd,
        }, usd, "USDC", paint);
        nudge();
        paint("ok", "[✓] topped up" + (rate > 0 ? " - +" + fmtDur(usd / rate) + " of runtime" : "") + okTail);
        showToast("topped up " + id.slice(0, 10) + "… with $" + usd.toFixed(2));
        setTimeout(() => { if (box.isConnected && !box.hidden){ box.hidden = true; box.innerHTML = ""; } this.refresh(); }, 3500);
      } catch(e){
        const rejected = (e && e.code === 4001) || /reject|denied|declin|cancell/i.test(e && e.message || "");
        paint("warn", rejected ? "[x] rejected in wallet - nothing was paid" : "[x] " + (e.message || String(e)));
      } finally { go.disabled = false; refreshWallet(); }
    });
  }

  /* Version and Shares have separate panels and transactions. Shared ledger,
     pricing and minimum checks keep their validation consistent. Shares pins
     the CURRENT version; opening it must never propose an upgrade/downgrade. */
  async _upgrade(id, btn, panel = "version") {
    const sharesOnly = panel === "shares";
    const title = sharesOnly ? "resources" : "change version";
    const row = btn.closest(".enc-row"), box = row && row.querySelector(sharesOnly ? ".enc-shares" : ".enc-upg"); if (!box) return;
    if (box.dataset.busy) return;
    if (!box.hidden){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); return; }
    btn.setAttribute("aria-expanded", "true");
    box.hidden = false;
    box.innerHTML = '<div class="ap-attbar">' + title + ' · ' + esc(id) + '</div>'
      + '<div class="term enc-upg-status" role="status" aria-live="polite"><span class="ln dimln">// reading the ledger + catalog…</span></div>';
    let d = null, rev = 1, avail = null, fleet = null;
    try {
      [rev, d] = await Promise.all([depSchemaRev(), depGet(id)]);
      await loadCatalog();
      // adopt the fleet's live hardware for the minimum-share floors (the
      // deploy dials' rule: a stale spec must over-ask, never under-sell an
      // unclaimable switch); the pre-fetch fallback constants already over-ask.
      // The per-enclave table rides along: a leased deployment is sized on the
      // box that HOLDS the lease, not on the aggregate (see hw below).
      [avail, fleet] = await Promise.all([
        Enclave.getAvailability().then(a => { adoptServerSpec(a); return a; }).catch(() => null),
        Enclave.getEnclaves().catch(() => null),
      ]);
    } catch(e){ d = null; }
    if (box.hidden || !box.isConnected) return;             // closed while loading
    const fail = (msg) => { box.querySelector(".enc-upg-status").innerHTML = ""; paintLine(box.querySelector(".enc-upg-status"), "warn", msg); };
    if (!d) return fail("[x] couldn’t read this deployment from the ledger - try again shortly");
    const cr = parseCatalogRef(d.appRef);
    if (!cr) return fail("[x] this deployment doesn’t reference a catalog version (" + (d.appRef || "no appRef") + ") - only catalog deployments can switch versions");
    const app = STORE.byId[cr.appId] || (sharesOnly ? { slug: 'app', versions: [] } : null);
    if (!app || !app.versions) return fail("[x] the catalog doesn’t list this deployment’s app (delisted?) - nothing to switch to");
    let currentVersion = null;
    if (sharesOnly) {
      try { currentVersion = await catGetVersion(cr.appId, cr.index); }
      catch (e) { return fail("[x] Could not read this app’s requirements. Close and reopen Resources to retry."); }
      if (box.hidden || !box.isConnected) return;
    }
    const versions = sharesOnly ? [{ v: currentVersion, i: cr.index }] : app.versions.map((v, i) => ({ v, i }));
    if (rev < 3)
      return fail("[!] the live ledger contract predates version changes - the Version control activates with the next contract upgrade. Until then: deploy the new version fresh, then suspend this one (its balance stays on the record).");
    // The deployment's publisher-fee snapshot is immutable:
    // a candidate version asking MORE than the snapshot could never pay its
    // publisher, so every runner would refuse the switch - list it disabled,
    // exactly like a share misfit. Fail closed on unreadable fees: offering a
    // switch runners refuse would leave the app dark. (Pre-fee ledger/catalog
    // revs read as all-zero without extra RPC - nothing disables today.)
    let snapFee = 0n; const verFees = {};
    try {
      snapFee = (await depFeeOf(id)).feePerSec6;
      await Promise.all(versions.map(async ({ v, i }) => {
        verFees[i] = await catVersionFee(cr.appId, i);
      }));
    } catch(e){ return fail("[x] couldn’t read the publisher fees involved - try again shortly"); }
    // Shares uses the stop/release/reclaim lifecycle on every backend. Save
    // shares with suspension atomically; never leave a failed resize stopped
    // with the old allocation or pretend the existing VM resized live.
    const restartResize = sharesOnly;
    let resizable = sharesOnly && rev >= 6, prices = null, maxGpu = 1000;
    let resizeReason = rev < 6 ? "This ledger does not support changing shares." : "";
    if (resizable){
      try { [prices, maxGpu] = await Promise.all([depPrices6(), depMaxGpuMilli()]); }
      catch(e){ resizable = false; resizeReason = "Current prices could not be loaded. Close and reopen Resources to retry."; }
    }
    // The owner's hourly ceiling (rev 8). Editable here whenever every live
    // runner honors it — the fleet-AND flag, same rule as the resize dials:
    // against an older runner a lowered cap would just look like a renewal
    // that mysteriously stopped.
    const capEditable = sharesOnly && rev >= 8 && avail?.rateCap === true;
    let cap6 = 0n;
    if (rev >= 8){ try { cap6 = await depCapOf(id); } catch(e){} }
    // WHOSE HARDWARE the floors divide by. A live lease pins it: the enclave
    // holding it restarts the app in place and checks the new version against
    // its OWN card and node, so that box - not the fleet - decides what this
    // deployment can switch to. The adopted aggregate is deliberately the
    // SMALLEST box on every axis (right for a deploy that could land anywhere,
    // wrong here): it told a 1%-CPU row leased by a 64 GB box that its app
    // needs 17%, the same 512 MB measured against a 3 GB node, and disabled
    // every newer version behind a resize it doesn't need. Unleased rows keep
    // the aggregate - any box may claim them next, so over-asking is right.
    const hw = leaseHostOf(d, fleet);          // null = size on the aggregate
    if (sharesOnly && (!hw || d.active === false || ![hw.row.availability.nodeRamGb, hw.row.availability.nodeGflops, ...(hw.row.availability.gpu ? [hw.row.availability.cardVramGb, hw.row.availability.cardTflops] : [])].every(x => Number.isFinite(Number(x)) && Number(x) > 0))) {
      box.replaceChildren(this._resourceOverview(id, btn, { spec: specOf(currentVersion), fleet,
        configCid: d.configCid, unresolvedHost: d.active !== false }));
      if (btn.dataset.editable === 'true') await this._resourceBudget(id, box);
      return;
    }
    // FREE SELF-HOSTING (ledger rev 12). The same box decides the PRICE of the
    // change, and it charges this owner nothing when its declared payout wallet
    // is the deployment's owner - _resizeRate goes through the very _hostRate
    // that claim() does, so a resize re-buys the bigger slice at zero. Priced
    // any other way, a self-hosted record refuses its own owner: its correct
    // state is an empty balance, and the box's posted price then reads as "the
    // remaining balance can't fund even one second at the new rate" for a
    // transaction the ledger accepts (2026-08-11, risc-box on kryptos).
    // Only the LEASE HOLDER's waiver counts, exactly as on-chain: an unleased
    // record is re-priced at whichever box claims it next.
    const freeHere = rev >= 12 && !!hw && hostChargeWaived(hw.row, d.owner);
    const bought = { gpuMilli: Number(d.gpuMilli) || 0, cpuMilli: Number(d.cpuMilli) || 0 };
    /* WHICH node floor a candidate version has to clear here. On a cpuFallback
       version the card case and the coreless case are different numbers, and
       the lease holder decides which applies: this tenant's weights are in a
       VRAM slice only if it bought a card, the box HAS one, and that card can
       hold the version being switched to. Anything else and they are in node
       RAM, where the fallback figure is the floor - the runner's version-change
       gate sizes against where the tenant is ACTUALLY running for exactly this
       reason, and a console floor below the runner's would offer a switch that
       gets the deployment EVICTED rather than merely refused.
       Version changes retain the normal minimum for stopped/queued apps.
       The Shares editor also enforces the CPU-only floor before the next
       launch, so its sliders cannot save an under-sized CPU-only allocation.
       `gpuMilli` is a parameter because a running app's dials can change the
       answer while you type: dial the card to 0 and it becomes CPU-only.
       `cardServesApp` is the shared mirror of the runner's gpuRouting, shielded
       card and all - a card too small for the app routes the work to cores,
       unless it is shielded, where offload is per-matmul and too-big is merely
       slower. Reading that wrong locks the panel: metal0 posts 214.7 TFLOPS
       against eyesoff-ai's declared 320, so a plain ratio calls its shielded
       card unusable and demands the coreless floor for a deployment the runner
       serves on that very card at the card-case one. */
    const hostAvail = (hw && hw.row && hw.row.availability) || null;
    const cpuNeedOf = (r, gpuMilli = bought.gpuMilli) => sharesOnly
      ? cpuFloorFor(r.mins, gpuMilli > 0 && (!hw || cardServesApp(hostAvail, r.mins)) ? 1 : 0)
      : !hw || d.active === false ? r.mins.cpuPct : cpuFloorFor(r.mins,
        gpuMilli > 0 && cardServesApp(hostAvail, r.mins) ? 1 : 0);
    const rows = versions
      .map(({ v, i }) => ({ v, i, mins: minPctsOf(specOf(v), hw && hw.spec) }))
      .map(r => ({ ...r,
        shareFit: r.mins.gpuPct * 10 <= bought.gpuMilli && cpuNeedOf(r) * 10 <= bought.cpuMilli,
        feeFit: (verFees[r.i] || 0n) <= snapFee }))
      .map(r => ({ ...r, fits: (r.shareFit || resizable) && r.feeFit }))
      .reverse();
    const others = rows.filter(r => r.i !== cr.index);
    // Version may suggest a newer fitting release. Shares always keeps the
    // current release, even when an upgrade is available.
    const newer = others.find(r => r.fits && r.i > cr.index && !catalogStatus(app, r.v));
    const cur = rows.find(r => r.i === cr.index);
    const pick = sharesOnly ? null : newer || ((cur && cur.fits) ? null : others.find(r => r.fits && !catalogStatus(app, r.v))) || null;
    if (!sharesOnly && !others.length)
      return fail("// " + app.slug + " has no other version yet");
    const selId = (sharesOnly ? "esShares" : "euSel") + appLabel(id);
    box.innerHTML = '<div class="ap-attbar">' + title + ' · ' + esc(id) + '</div>'
      + (sharesOnly && resizeReason ? '<p class="enc-shares-note" role="status">' + esc(resizeReason) + '</p>' : '')
      + '<div class="' + (sharesOnly ? 'enc-share-content' : 'enc-upg-body') + '">'
      + (sharesOnly ? '' : '<label for="' + selId + '">Switch ' + esc(app.slug) + ' to</label>'
      +   '<select class="eu-sel" id="' + selId + '">'
      +     rows.map(r => '<option value="' + r.i + '"' + (((r.i === cr.index && !resizable) || !r.fits) ? " disabled" : "") + (pick && r.i === pick.i ? " selected" : (!pick && r.i === cr.index ? " selected" : "")) + '>'
      +       esc(app.slug + ":" + r.v.version)
      +       (catalogStatus(app, r.v) ? " · " + esc(catalogStatus(app, r.v)) : "")
      +       (r.i === cr.index ? " · current" : "")
      +       (!r.shareFit && r.i !== cr.index ? " · needs ≥ " + (r.mins.gpuPct ? r.mins.gpuPct + "% GPU / " : "") + cpuNeedOf(r) + "% CPU"
                                                 + (hw ? " on " + hw.name : "") : "")
      +       (r.shareFit && !r.feeFit && r.i !== cr.index ? " · charges $" + (Number(verFees[r.i]) * 3600 / 1e6).toFixed(2) + "/hr publisher fee (above this deployment’s snapshot)" : "")
      +     '</option>').join("")
      +   '</select><p class="enc-shares-note">Each host decides which releases it accepts. Catalog status does not guarantee a host will run the selected release.</p>')
      +   (sharesOnly ? '' : '<button class="btn btn-sm btn-primary eu-go" type="button">Change version</button>')
      + '</div>'
      + (capEditable
         ? '<div class="enc-upg-body eu-cap-row">'
         +   '<label for="' + selId + 'r">Rate cap $/hr</label>'
         +   '<input id="' + selId + 'r" class="eu-cap" type="number" min="0" step="0.01" value="' + (Number(cap6) * 3600 / 1e6).toFixed(2) + '">'
         +   '<button class="btn btn-sm eu-cap-go" type="button">Set cap</button>'
         + '</div>'
         : '')
      + '<div class="term enc-upg-status" role="status" aria-live="polite"></div>'
      + (sharesOnly ? '<div class="enc-share-actions"><button class="btn btn-sm eu-cancel" type="button">Cancel</button><button class="btn btn-sm btn-primary eu-go" type="button">Save</button></div>' : '');
    const sel = sharesOnly ? { value: String(cr.index) } : box.querySelector(".eu-sel");
    const go = box.querySelector(".eu-go"), st = box.querySelector(".enc-upg-status");
    const editor = sharesOnly && cur ? shareEditor({ id: selId, spec: specOf(cur.v), mins: cur.mins,
      allocation: bought, maxGpu, rev, cpuMinimum: gpu => cpuNeedOf(cur, gpu), editable: resizable,
      hostName: hw?.name, hardware: { ...hw.spec, ...(hw.row.availability.gpu !== true ? { cardVramGb: 0, cardTflops: 0 } : {}) },
      onCompareHosts: () => box.querySelector('.enc-resource-overview').scrollIntoView({ block: 'start', behavior: 'smooth' }), onChange: () => upd() }) : null;
    if (editor) {
      box.querySelector('.enc-share-content').append(editor.element);
      box.append(this._resourceOverview(id, btn, { spec: specOf(cur.v), fleet, configCid: d.configCid, currentHost: hw }));
    }
    box.querySelector('.eu-cancel')?.addEventListener('click', () => {
      if (box.dataset.busy) return;
      box.hidden = true; box.innerHTML = ''; btn.setAttribute('aria-expanded', 'false'); btn.focus();
    });
    const paint = (cls, txt) => paintLine(st, cls, txt);
    const intro = () => {
      if (sharesOnly) {
        if (resizable) paint("info", restartResize
          ? d.active === false
            ? "Save the allocation and re-queue the stopped app. Its URL and balance stay the same."
            : "Save the new shares and stop in one confirmation, then confirm re-queue after the old lease clears. URL and balance stay the same; in-memory state resets."
          : "The host applies the new allocation and may restart the app. Its URL and balance stay the same; in-memory state may reset.");
        if (cur) paint("dimln", "Minimum: " + (editor ? editor.cpuMinimum() : Math.max(1, cpuNeedOf(cur, dials().gpuMilli))) + "% CPU"
          + (cur.mins.gpuPct ? " · " + cur.mins.gpuPct + "% GPU" : "") + (hw ? " on " + hw.name : ""));
        if (restartResize && resizable) paint("dimln", "Pricing is an estimate. The new instance must fit an eligible host and your hourly rate cap.");
        return;
      }
      if (sharesOnly && resizable && restartResize)
        paint("info", "// resizing stops this instance, waits for its lease to be released, then starts a fresh instance with the new shares. The URL and balance carry over; in-memory state is lost. Wallet confirmations are required for suspension and the resize/restart.");
      else if (!sharesOnly || resizable) paint("info", "// paid time carries over: the runner restarts the app in place (~a minute); the endpoint and balance don’t change, app state is ephemeral");
      if (restartResize && resizable) paint("dimln", "// pricing below is an estimate at the current host’s rates; the fresh instance must fit an eligible host and your rate cap");
      if (resizable && freeHere)
        paint("dimln", "// the dials re-buy this deployment’s shares in the same transaction - " + hw.name
          + " pays out to this deployment’s owner, so the bigger slice is re-bought at $0.00/h too"
          + (snapFee > 0n ? " (the app’s publisher fee is never waived)" : " and no balance is needed"));
      else if (resizable)
        paint("dimln", "// the dials re-buy this deployment’s shares in the same transaction - the hourly rate is recalculated at "
          + (rev >= 8 ? (hw ? hw.name + "’s posted price" : "the price of whichever enclave claims it") : "the CURRENT list prices")
          + ", and a live lease settles at the old rate first");
      if (sharesOnly && cap6 > 0n)
        paint("dimln", "// rate cap $" + (Number(cap6) * 3600 / 1e6).toFixed(2) + "/h: enclaves dearer than this can’t run this deployment - "
          + "it is also what decides where the app goes if its enclave dies"
          + (capEditable ? "" : " (this fleet can’t change it yet)"));
      if (hw)
        paint("dimln", "// minimum shares are measured on " + hw.name + " (" + hw.spec.nodeRamGb + " GB / " + hw.spec.nodeVcpus + " vCPU node"
          + (bought.gpuMilli ? ", " + hw.spec.cardVramGb + " GB card" : "") + "), the enclave holding this deployment’s lease - it restarts the app in place and checks the new version against its own hardware");
      if (!sharesOnly && others.some(r => !r.shareFit))
        paint("dimln", "// disabled entries need more than this deployment’s " + (bought.gpuMilli ? (bought.gpuMilli / 10) + "% GPU / " : "") + (bought.cpuMilli / 10) + "% CPU - " + "adjust the allocation in Resources before switching to one of those versions");
      if (!sharesOnly && others.some(r => r.shareFit && !r.feeFit))
        paint("dimln", "// entries charging a higher publisher fee than this deployment snapshotted at create need a fresh deploy - the fee snapshot is immutable");
    };
    const dials = () => editor ? editor.values() : { ...bought };
    // the rate this size would run at, priced at the box that will serve it:
    // its lease holder's posted price (rev 8), else the fleet/list price - and
    // zero for the host half when that box hosts this owner for free, leaving
    // the publisher fee, which no waiver ever touches
    const rateOf = t => (freeHere ? 0n : rate6Of(hw && hw.price
      ? { gpu: BigInt(Math.round(hw.price.full * 1e6)), cpu: BigInt(Math.round(hw.price.node * 1e6)) }
      : prices, t.gpuMilli, t.cpuMilli)) + snapFee;
    // Sliders enforce resource floors; Save also validates pricing, capacity
    // and ledger rules, both while editing and immediately before signing.
    const problem = (r, t, resized) => {
      if (!editor) return "";
      if (editor.problem()) return editor.problem();
      if (t.gpuMilli < 0 || t.cpuMilli < 0) return "// shares can’t be negative";
      const ver = app.slug + ":" + r.v.version;
      if (t.gpuMilli < r.mins.gpuPct * 10)
        return "// " + ver + " needs at least " + r.mins.gpuPct + "% GPU" + (hw ? " on " + hw.name : "");
      const cNeed = cpuNeedOf(r, t.gpuMilli);
      if (t.cpuMilli < Math.max(10, cNeed * 10))
        return "// " + ver + " needs at least " + Math.max(1, cNeed) + "% CPU" + (hw ? " on " + hw.name : "")
             + (cNeed > r.mins.cpuPct ? " without a card (its weights live in node RAM there)" : "");
      if (t.cpuMilli > 1000) return "// the CPU share can’t be more than 100% of the node";
      if (t.gpuMilli > maxGpu) return "// GPU over the platform’s per-deployment cap of " + (maxGpu / 10) + "%";
      // The two dials are independent from ledger rev 13 on. Older ledgers
      // revert setShares outright, so keep saying so there rather than letting
      // the click burn gas on a bare "gpuShare < cpuShare".
      if (!sharesLegalOn(t.gpuMilli / 10, t.cpuMilli / 10, rev))
        return "// this ledger (deploymentsSchema " + rev + ") still needs GPU ≥ CPU - raise GPU to "
          + (t.cpuMilli / 10) + "% or more, or lower CPU (the rev-13 ledger drops the rule)";
      if (!resized) return "";
      const newRate = rateOf(t);
      if (cap6 > 0n && newRate > cap6)
        return "// that size costs more than this deployment’s rate cap of $" + (Number(cap6) * 3600 / 1e6).toFixed(2)
          + "/h - raise the rate cap, then save";
      if (Number(d.leaseUntil) * 1000 > Date.now()){
        const tail = Math.max(0, Number(d.leaseUntil) - Math.floor(Date.now() / 1000));
        if (BigInt(Number(d.balance6 || 0)) + BigInt(tail) * BigInt(Math.round(Number(d.rate) || 0)) < newRate)
          return "// the remaining balance can’t fund even one second at the new rate - top it up first";
      }
      return "";
    };
    const upd = () => {
      if (box.dataset.busy) return;
      const r = rows.find(x => String(x.i) === sel.value);
      st.innerHTML = ""; intro();
      if (!r || !r.fits){ go.disabled = true; return; }
      if (resizable && editor){
        const t = dials();
        const resized = t.gpuMilli !== bought.gpuMilli || t.cpuMilli !== bought.cpuMilli;
        const verChange = r.i !== cr.index;
        go.textContent = 'Save';
        go.disabled = !verChange && !resized && !(restartResize && d.active === false);
        const bad = problem(r, t, resized);
        if (bad){ go.disabled = true; paint("warn", bad); return; }
        if (resized){
          const newRate = rateOf(t), oldRate = Math.round(Number(d.rate) || 0), bal = Number(d.balance6 || 0);
          paint("dimln", "// rate $" + (oldRate * 3600 / 1e6).toFixed(2)
            + "/h -> $" + (Number(newRate) * 3600 / 1e6).toFixed(2) + "/h"
            + (freeHere ? " - you host it on " + hw.name + ", which charges its own payout wallet nothing"
                        : hw ? " at " + hw.name + "’s price" : "")
            + (bal > 0 && Number(newRate) > 0 ? " · remaining balance buys ≈ " + fmtDur(bal / Number(newRate)) : ""));
        }
      } else {
        go.disabled = r.i === cr.index || !r.fits;
      }
    };
    if (!sharesOnly) sel.addEventListener("change", upd);
    upd();
    go.addEventListener("click", async () => {
      if (box.dataset.busy) return;
      const r = rows.find(x => String(x.i) === sel.value);
      if (!r || !r.fits || (sharesOnly && !resizable)) return;
      const t = dials();
      const resized = resizable && (t.gpuMilli !== bought.gpuMilli || t.cpuMilli !== bought.cpuMilli);
      const verChange = !sharesOnly && r.i !== cr.index;
      if (!verChange && !resized && !(restartResize && d.active === false)) return;
      // Recheck the complete draft before asking for a signature.
      if (resizable && editor){
        const bad = problem(r, t, resized);
        if (bad){ st.innerHTML = ""; intro(); paint("warn", bad); return; }
      }
      const locked = [...row.querySelectorAll(".enc-tabs button"), ...box.querySelectorAll("input, select, button")].map(el => [el, el.disabled]);
      go.disabled = true;
      let saved = false;
      const via = ctlOf((this._list || []).find(x => x.id === id)) === "vault";
      const doneWord = verChange ? "switched to " + app.slug + ":" + r.v.version + (resized ? " at " + (t.gpuMilli / 10) + "% GPU / " + (t.cpuMilli / 10) + "% CPU" : "")
                                 : "resized to " + (t.gpuMilli / 10) + "% GPU / " + (t.cpuMilli / 10) + "% CPU";
      try {
        box.dataset.busy = "true";
        locked.forEach(([el]) => { el.disabled = true; });
        if (sharesOnly) {
          const latest = await depGet(id), current = leaseHostOf(latest, fleet);
          if (latest.active === false || !current || current.row.id !== hw.row.id)
            throw new Error('The app’s host changed. Reopen Resources to size its current allocation.');
        }
        if (restartResize && (resized || d.active === false)) {
          if (!via && !Enclave.provider) await connectWallet();
          if (!via) await ensureBaseChain();
          const walletTx = async data => { const hash = await sendTx(DEPLOYMENTS_ADDRESS, data); await waitReceipt(hash); };
          const activeCall = active => encCall(DEP_SEL.setActive, [{ t: "bytes32", v: id }, { t: "bool", v: active }]);
          const sharesCall = encCall(DEP_SEL.setShares, [{ t: "bytes32", v: id }, { t: "uint", v: t.gpuMilli }, { t: "uint", v: t.cpuMilli }]);
          const vault = via ? (await import("../../js/core/vault.js")).vaultOp : null;
          const result = await resizeAfterStop({
            expected: d, target: t, read: () => depSnapshot(id),
            saved: ({ active }) => {
              // Keep the same panel retryable after cancellation/RPC trouble.
              // The chain already retains these shares across reloads.
              Object.assign(bought, t); Object.assign(d, t, { active });
            },
            resume: () => via ? vault("control", { id, action: "resume" }) : walletTx(activeCall(true)),
            progress: message => paint("info", message),
            apply: async ({ active }) => {
              if (via) {
                await vault("control", { id, action: "resize", gpuMilli: t.gpuMilli, cpuMilli: t.cpuMilli, active });
              } else {
                await walletTx(encCall(DEP_SEL.multicall, [{ t: "bytes[]", v: [sharesCall, activeCall(active)] }]));
              }
            },
          });
          saved = true;
          if (result.resumed) {
            fetch(Enclave.base + "/claim-hint", { method: "POST", headers: { "content-type": "application/json" },
              body: JSON.stringify({ id, force: true }) }).catch(() => {});
          }
          if (this._why) this._why.delete(id);
          paint("ok", "[✓] " + doneWord + (result.resumed ? " — queued for a fresh instance at the new size" : " — saved; use Resume when you are ready to start it"));
          showToast(doneWord);
          setTimeout(() => { if (box.isConnected){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); } this.refresh(); }, 3500);
          return;
        }
        if (via){
          // credit-vault row: the vault owns the deployment on-chain, so the
          // change is a passkey-signed controlDeployment op via the relay
          paint("info", "[*] confirm the change with your passkey…");
          const { vaultOp } = await import("../../js/core/vault.js");
          await vaultOp("control", resized
            ? { id, action: "resize", gpuMilli: t.gpuMilli, cpuMilli: t.cpuMilli, ...(verChange ? { ref: catalogRef(cr.appId, r.i) } : {}) }
            : { id, action: "version", ref: catalogRef(cr.appId, r.i) });
        } else {
          // no SIWE: setAppRef/setShares are owner-gated on-chain - a connected
          // wallet is all this needs; Version and Shares each send their own action
          if (!Enclave.provider){ paint("info", "[*] connecting wallet…"); await connectWallet(); }
          await ensureBaseChain();
          paint("info", "[*] confirm the transaction in your wallet…");
          const calls = [];
          if (verChange) calls.push(encCall(DEP_SEL.setAppRef, [{ t: "bytes32", v: id }, { t: "str", v: catalogRef(cr.appId, r.i) }]));
          if (resized) calls.push(encCall(DEP_SEL.setShares, [{ t: "bytes32", v: id }, { t: "uint", v: t.gpuMilli }, { t: "uint", v: t.cpuMilli }]));
          const th = await sendTx(DEPLOYMENTS_ADDRESS,
            calls.length > 1 ? encCall(DEP_SEL.multicall, [{ t: "bytes[]", v: calls }]) : calls[0]);
          paint("dimln", "  ↳ sent " + th + " · waiting for confirmation…");
          await waitReceipt(th);
        }
        saved = true;
        if (this._why) this._why.delete(id);   // a pre-change decline reason must not outlive the switch
        // nudge the fleet: makes queued/suspended rows relaunch promptly (a
        // running one is restarted by its own runner's next ledger pass)
        fetch(Enclave.base + "/claim-hint", { method: "POST",
          headers: { "content-type": "application/json" }, body: JSON.stringify({ id }) }).catch(() => {});
        paint("ok", "[✓] " + doneWord + " - the runner applies it within a minute; paid time and the endpoint carry over");
        showToast(doneWord.replace(/^switched/, "switched " + id.slice(0, 10) + "…").replace(/^resized/, "resized " + id.slice(0, 10) + "…"));
        setTimeout(() => { if (box.isConnected && !box.hidden){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); } this.refresh(); }, 3500);
      } catch(e){
        const rejected = (e && e.code === 4001) || /reject|denied|declin|cancell/i.test(e && e.message || "");
        paint("warn", restartResize ? "[x] " + (e.message || String(e))
          : rejected ? (via ? "[x] cancelled - nothing changed" : "[x] rejected in wallet - nothing changed") : "[x] " + (e.message || String(e)));
        go.disabled = false;
      } finally { delete box.dataset.busy; locked.forEach(([el, disabled]) => { el.disabled = disabled; }); if (saved) go.disabled = true; if (!via) refreshWallet(); }
    });
    // ---- the hourly ceiling: which enclaves may run this deployment --------
    // Enclaves price their own hardware, so this line decides where the work
    // can go - including when its host dies and the lease reopens. Below the
    // running rate it becomes a stop: the paid lease finishes and nothing
    // renews or re-claims it, which the button says out loud before signing.
    const capGo = box.querySelector(".eu-cap-go"), capIn = box.querySelector(".eu-cap");
    if (capGo && capIn){
      const leased = Number(d.leaseUntil) * 1000 > Date.now();
      const capOf = () => BigInt(Math.round((parseFloat(capIn.value) || 0) * 1e6 / 3600));
      capGo.disabled = true;
      capIn.addEventListener("input", () => { const n = capOf(); capGo.disabled = !(n > snapFee) || n === cap6; });
      capGo.addEventListener("click", async () => {
        const next6 = capOf();
        if (!(next6 > snapFee))
          return paint("warn", "// the cap must be above the app’s publisher fee ($" + (Number(snapFee) * 3600 / 1e6).toFixed(2) + "/hr)");
        const runRate = BigInt(Math.round(Number(d.rate) || 0));
        if (leased && next6 < runRate
            && !confirm("$" + (Number(next6) * 3600 / 1e6).toFixed(2) + "/hr is below what this deployment pays now ($"
                        + (Number(runRate) * 3600 / 1e6).toFixed(2) + "/hr).\n\nThe lease you already paid for runs to "
                        + new Date(Number(d.leaseUntil) * 1000).toLocaleString()
                        + ", then the app STOPS: no renewal and no re-claim until a cheaper enclave exists or you raise the cap.\n\nSet it anyway?"))
          return;
        capGo.disabled = true;
        const viaVault = ctlOf((this._list || []).find(x => x.id === id)) === "vault";
        try {
          if (viaVault){
            paint("info", "[*] confirm the change with your passkey…");
            const { vaultOp } = await import("../../js/core/vault.js");
            await vaultOp("control", { id, action: "maxrate", maxRate6: Number(next6) });
          } else {
            if (!Enclave.provider){ paint("info", "[*] connecting wallet…"); await connectWallet(); }
            await ensureBaseChain();
            paint("info", "[*] confirm the transaction in your wallet…");
            const th = await sendTx(DEPLOYMENTS_ADDRESS,
              encCall(DEP_SEL.setMaxRate, [{ t: "bytes32", v: id }, { t: "uint", v: next6 }]));
            paint("dimln", "  ↳ sent " + th + " · waiting for confirmation…");
            await waitReceipt(th);
          }
          cap6 = next6;
          paint("ok", "[✓] rate cap now $" + (Number(next6) * 3600 / 1e6).toFixed(2) + "/hr"
            + (leased && next6 < runRate ? " - the app stops when the current lease ends" : " - enclaves dearer than this can’t run it"));
          showToast("rate cap set for " + id.slice(0, 10) + "…");
          this.refresh();
        } catch(e){
          const rejected = (e && e.code === 4001) || /reject|denied|declin|cancell/i.test(e && e.message || "");
          paint("warn", rejected ? "[x] cancelled - the cap is unchanged" : "[x] " + (e.message || String(e)));
          capGo.disabled = false;
        } finally { if (!viaVault) refreshWallet(); }
      });
    }
  }

  /* ---- per-row Protect: the deployment's options envelope, WAF namespace.
     Deployments that skipped Protection at create gain it here - one owner
     setConfig tx rewrites the envelope (the `config` namespace, if any, is
     PRESERVED verbatim), and a fleet advertising configEdit swaps the waf on
     the LIVE app within ~a minute, no restart. Fails closed like the deploy
     form: the editor only arms when every live runner enforces the envelope
     (aggregate waf:true) - a mixed fleet would strand the deployment on a
     runner that refuses it at its next claim. ---- */
  async _waf(id, btn) {
    const row = btn.closest(".enc-row"), box = row && row.querySelector(".enc-waf"); if (!box) return;
    if (!box.hidden){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); return; }
    btn.setAttribute("aria-expanded", "true");
    box.hidden = false;
    box.innerHTML = '<div class="ap-attbar">protection · ' + esc(id) + '</div>'
      + '<div class="term enc-waf-status" role="status" aria-live="polite"><span class="ln dimln">// reading the ledger + fleet…</span></div>';
    let d = null, rev = 1, avail = null;
    try { [rev, d] = await Promise.all([depSchemaRev(), depGet(id)]); } catch(e){ d = null; }
    try { avail = await Enclave.getAvailability(); } catch(e){}
    if (box.hidden || !box.isConnected) return;              // closed while loading
    const fail = (msg) => { box.querySelector(".enc-waf-status").innerHTML = ""; paintLine(box.querySelector(".enc-waf-status"), "warn", msg); };
    if (!d) return fail("[x] couldn’t read this deployment from the ledger - try again shortly");
    if (avail && avail.waf !== true)
      return fail("[!] the live fleet doesn’t enforce the protection envelope yet - enabling it now could strand this deployment on its next claim; try again after the fleet updates");
    // the current envelope: waf + config namespaces; anything unparseable
    // reads as empty (setConfig replaces it wholesale, which also heals it)
    const raw = String(d.configCid || "").trim();
    this._envLearn(id, raw);                       // freshest ledger truth: sync the row badge
    let cur = {};
    if (raw.startsWith("{")) { try { cur = JSON.parse(raw); } catch(e){} }
    if (!cur || Array.isArray(cur) || typeof cur !== "object") cur = {};
    const w0 = (cur.waf && typeof cur.waf === "object" && !Array.isArray(cur.waf)) ? cur.waf : null;
    const fid = "ew" + appLabel(id);
    box.innerHTML = '<div class="ap-attbar">protection · ' + esc(id) + '</div>'
      + '<div class="enc-waf-body">'
      +   '<label class="ew-on"><input type="checkbox" class="ew-en" id="' + fid + 'e"' + (w0 ? " checked" : "") + '> Protection on</label>'
      +   '<label for="' + fid + 'r">Rate/IP <abbr title="sustained requests per second each client IP may make; steadier traffic above it is dropped at the enclave’s front door with 429">?</abbr></label>'
      +   '<input id="' + fid + 'r" class="ew-rps" type="number" min="0.1" max="10000" step="0.1" value="' + esc(String(w0 && w0.rps != null ? w0.rps : 10)) + '"> r/s'
      +   '<label for="' + fid + 'b">Burst</label>'
      +   '<input id="' + fid + 'b" class="ew-burst" type="number" min="1" max="100000" step="1" value="' + esc(String(w0 && w0.burst != null ? w0.burst : "")) + '" placeholder="auto">'
      +   '<label for="' + fid + 'c">In flight/IP <abbr title="how many requests one client IP may have OPEN at once; the limit that bites a streaming app, where a single answer holds its connection for as long as it takes to write. Empty = unlimited">?</abbr></label>'
      +   '<input id="' + fid + 'c" class="ew-conc" type="number" min="1" max="10000" step="1" value="' + esc(String(w0 && w0.maxConcurrent != null ? w0.maxConcurrent : "")) + '" placeholder="off">'
      +   '<label for="' + fid + 'm">Max body</label>'
      +   '<input id="' + fid + 'm" class="ew-body" type="number" min="0" max="1024" step="0.1" value="' + esc(String(w0 && w0.maxBodyMb != null ? w0.maxBodyMb : "")) + '" placeholder="off"> MB'
      +   '<label class="ew-scanlbl"><input type="checkbox" class="ew-scan"' + (w0 && w0.blockScanners ? " checked" : "") + '> Block scanner paths <abbr title="drop obvious probe paths (/wp-admin, /.env, .php…) before they reach the app">?</abbr></label>'
      +   '<button class="btn btn-sm btn-primary ew-go" type="button">Apply</button>'
      + '</div>'
      + '<div class="term enc-waf-status" role="status" aria-live="polite"></div>';
    const st = box.querySelector(".enc-waf-status"), go = box.querySelector(".ew-go");
    const en = box.querySelector(".ew-en"), rIn = box.querySelector(".ew-rps"),
          bIn = box.querySelector(".ew-burst"), cIn = box.querySelector(".ew-conc"),
          mIn = box.querySelector(".ew-body"), sc = box.querySelector(".ew-scan");
    const paint = (cls, txt) => paintLine(st, cls, txt);
    const liveEdit = !!(avail && avail.configEdit === true);
    const applyWord = liveEdit ? "a running app picks it up live within ~a minute (no restart)"
                               : "it applies at the app’s next relaunch or claim";
    const intro = () => {
      st.innerHTML = "";
      paint("info", w0 ? "// tuning the existing protection - " + applyWord
                       : "// this deployment launched without protection; enabling it needs one owner signature - " + applyWord);
      if ("config" in cur) paint("dimln", "// the deployment’s app-config override is preserved untouched");
    };
    // mirror the deploy form's clamps; burst empty = auto (4s of the rate)
    const spec = () => {
      const num = (el, lo, hi, dflt) => { const v = parseFloat(el && el.value); return Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : dflt; };
      const w = { rps: num(rIn, 0.1, 10000, 10) };
      const burst = parseFloat(bIn && bIn.value);
      w.burst = Number.isFinite(burst) ? Math.round(Math.min(100000, Math.max(1, burst))) : Math.max(5, Math.ceil(w.rps * 4));
      const conc = parseFloat(cIn && cIn.value);
      if (Number.isFinite(conc)) w.maxConcurrent = Math.round(Math.min(10000, Math.max(1, conc)));
      const body = num(mIn, 0, 1024, 0);
      if (body > 0) w.maxBodyMb = body;
      if (sc && sc.checked) w.blockScanners = true;
      return w;
    };
    const sync = () => { const on = en.checked; [rIn, bIn, cIn, mIn, sc].forEach(el => { if (el) el.disabled = !on; });
      const next = { ...cur }; if (en.checked) next.waf = spec(); else delete next.waf;
      const env = Object.keys(next).length ? JSON.stringify(next) : "";
      go.disabled = env === raw;
      go.textContent = !en.checked && w0 ? "Remove protection" : w0 ? "Apply changes" : "Enable protection";
    };
    [en, rIn, bIn, cIn, mIn, sc].forEach(el => el && el.addEventListener("input", sync));
    intro(); sync();
    go.addEventListener("click", async () => {
      const next = { ...cur };
      if (en.checked) next.waf = spec(); else delete next.waf;
      const envelope = Object.keys(next).length ? JSON.stringify(next) : "";
      if (envelope === raw) return;
      const cap = rev >= 5 ? 4096 : 100;
      if (new TextEncoder().encode(envelope).length > cap)
        return paint("warn", "[x] the options envelope (protection + config override) is over this ledger’s " + cap + "-byte cap - trim the config override first");
      go.disabled = true;
      const via = ctlOf((this._list || []).find(x => x.id === id)) === "vault";
      const doneWord = en.checked ? (w0 ? "protection updated" : "protection enabled") : "protection removed";
      try {
        if (via){
          // credit-vault row: the vault owns the deployment - one
          // passkey-signed controlDeployment(setConfig) op via the relay
          paint("info", "[*] confirm with your passkey…");
          const { vaultOp } = await import("../../js/core/vault.js");
          await vaultOp("control", { id, action: "options", envelope });
        } else {
          // setConfig is owner-gated on-chain - a connected wallet is all
          // this needs; the envelope rides one transaction
          if (!Enclave.provider){ paint("info", "[*] connecting wallet…"); await connectWallet(); }
          await ensureBaseChain();
          paint("info", "[*] confirm the transaction in your wallet…");
          const th = await sendTx(DEPLOYMENTS_ADDRESS,
            encCall(DEP_SEL.setConfig, [{ t: "bytes32", v: id }, { t: "str", v: envelope }]));
          paint("dimln", "  ↳ sent " + th + " · waiting for confirmation…");
          await waitReceipt(th);
        }
        paint("ok", "[✓] " + doneWord + " - " + applyWord);
        showToast(doneWord + " on " + id.slice(0, 10) + "…");
        this._envLearn(id, envelope);          // the row badge reflects the new envelope immediately
        setTimeout(() => { if (box.isConnected && !box.hidden){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); } }, 3500);
      } catch(e){
        const rejected = (e && e.code === 4001) || /reject|denied|declin|cancell/i.test(e && e.message || "");
        paint("warn", rejected ? (via ? "[x] cancelled - nothing changed" : "[x] rejected in wallet - nothing changed") : "[x] " + (e.message || String(e)));
        go.disabled = false;
      } finally { if (!via) refreshWallet(); }
    });
  }

  // The Enclave network does not expose the retired per-connection traffic feed.
  async _traffic(id, host) {
    if (host) host.innerHTML = '<div class="ap-attbar">traffic</div><p class="en-intro dim">Traffic is carried by the Enclave network. Per-connection traffic reports are unavailable.</p>';
  }

  async _network(id, btn) {
    const row = btn.closest(".enc-row"), box = row && row.querySelector(".enc-net"); if (!box) return;
    if (!box.hidden) {box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); return;}
    btn.setAttribute("aria-expanded", "true"); box.hidden = false;
    box.innerHTML = '<div class="ap-attbar">Network</div><div class="term enc-net-status" role="status" aria-live="polite"></div>';
    const status = box.querySelector(".enc-net-status"), d = (this._list || []).find(x => x.id === id);
    // the Enclave network (docs/design/enclave-network.md): status, privacy, and the owner-signed mode setting
    try { const m = await import("../../js/core/enclave-network.js"); await m.renderEnclaveNetwork(box, id, {viaVault: ctlOf(d) === "vault", owner: d?.owner}); }
    catch (e) { paintLine(status, "warn", "Network settings unavailable: " + e.message); }
  }

  /* ---- the deployment's config, as the ledger + catalog see it ----
     ONE read shared by the Config and Models panels. The catalog version's
     config is the DEFAULT (stock); the envelope's `config` namespace is a
     per-deployment OVERRIDE that replaces it as this one deployment's
     ENCLAVE_CONFIG, volumes key included. The catalog entry and every other
     deployment stay untouched. One owner setConfig tx rewrites the envelope
     (waf/network namespaces PRESERVED verbatim); a fleet advertising
     configEdit restarts the app in place on the new config within ~a minute.
     An override is stored one of two ways, and the panels hide the
     difference: INLINE (`config` is the whole document) or SPLIT (`configCid`
     holds it and `config` is only the routing manifest - the deployment-side
     mirror of catalog rev 7). The split exists because the whole envelope
     shares one 4096-byte ledger field with waf/network, so an app whose
     config is bigger than that has no override without it.
     Fails closed like the deploy gates: CREATING an override needs the fleet
     aggregate's configOverride flag, or every host that could claim THIS
     deployment taking it (hostsTakeConfig: an isolation host takes it through
     the attested release) - a runner that predates the namespace refuses the
     whole envelope, stranding the deployment Queued at its next claim;
     dropping one is always safe. Returns { err } when nothing can be
     edited, else the context cfgPlan() and the panels build on. ---- */
  async _cfgRead(id, { allowReadOnly = false } = {}) {
    let d = null, rev = 1, avail = null, fleet = null;
    try { [rev, d] = await Promise.all([depSchemaRev(), depGet(id)]); await loadCatalog(); } catch(e){ d = null; }
    [avail, fleet] = await Promise.all([Enclave.getAvailability().catch(() => null), Enclave.getEnclaves().catch(() => null)]);
    if (!d) return { err: "[x] couldn’t read this deployment from the ledger - try again shortly" };
    // the current envelope; anything unparseable reads as empty (setConfig
    // replaces it wholesale, which is also how such a string gets healed)
    const raw = String(d.configCid || "").trim();
    this._envLearn(id, raw);                       // freshest ledger truth: sync the row badge
    let cur = {};
    if (raw.startsWith("{")) { try { cur = JSON.parse(raw); } catch(e){} }
    if (!cur || Array.isArray(cur) || typeof cur !== "object") cur = {};
    const ovCid = typeof cur.configCid === "string" ? cur.configCid : "";
    const hasOv = "config" in cur || !!ovCid;
    let o0 = null, ovLost = false;    // the override's FULL config; ovLost = stored at a CID this gateway won't serve
    if (ovCid){
      const body = await fetchConfigCid(ovCid);
      if (body === null) ovLost = true;
      else { try { o0 = JSON.parse(body); } catch(e){ o0 = {}; } }
      if (!o0 || Array.isArray(o0) || typeof o0 !== "object") o0 = ovLost ? null : {};
    } else if (hasOv){
      o0 = (cur.config && typeof cur.config === "object" && !Array.isArray(cur.config)) ? cur.config : {};
    }
    let editBlocked = null;
    if (rev < 5 && !hasOv)
      editBlocked = "The current ledger does not support changing this deployment’s models.";
    else if ((!avail || avail.configOverride !== true) && !hostsTakeConfig(fleet, raw) && !hasOv)
      editBlocked = "Changing models is unavailable because fleet support is missing or could not be verified.";
    if (editBlocked && !allowReadOnly) return { err: editBlocked };
    // The STOCK config: the catalog version this deployment references. On a
    // rev-7 catalog a large config lives at a CID (the record's inline field is
    // only the routing manifest) - fetch it for display and the diff baseline;
    // the enclave resolves and hash-verifies the same CID itself, so a silent
    // gateway costs a panel its prefill, never the app a correct config.
    const cr = parseCatalogRef(d.appRef);
    const app = cr && STORE.byId[cr.appId];
    const ver = app && app.versions ? app.versions[cr.index] : null;
    let stock = null;               // JSON string ("" = the version publishes none); null = unreadable
    if (ver){
      if (ver.configCid){ const real = await fetchConfigCid(ver.configCid); stock = real === null ? null : stripMedia(real); }
      else stock = stripMedia(ver.config || "");
    }
    const compact = (x) => { try { return x ? JSON.stringify(JSON.parse(x)) : ""; } catch(e){ return (x || "").trim(); } };
    const stockC = stock === null ? null : compact(stock);
    const cap = rev >= 5 ? 4096 : 100;
    const liveEdit = !!(avail && avail.configEdit === true);
    const leased = Number(d.leaseUntil) * 1000 > Date.now();
    const applyWord = leased
      ? (liveEdit ? "the enclave restarts the app in place on it within ~a minute (same URL, same balance)"
                  : "it applies at the app’s next relaunch or claim")
      : "it applies when the deployment is next claimed";
    const curBase = { ...cur }; delete curBase.config; delete curBase.configCid;   // the envelope's OTHER namespaces, carried verbatim
    return { d, rev, avail, raw, cur, curBase, ovCid, hasOv, o0, ovLost, cr, ver, stock, stockC, cap, editBlocked,
             splitOk: !!(avail && avail.configCidOverride === true) || hostsTakeConfig(fleet, raw, "configCidOverride"), applyWord };
  }
  /* one owner setConfig tx (vault rows: the same passkey-signed control op as
     Protect/Network) rewriting the envelope - shared by the Config and Models
     panels. ui: { box, btn, st (the panel's term), lock(), unlock() }. Resolves
     true when the ledger took it (the panel closes itself after a beat). */
  async _cfgSubmit(id, ctx, ui, envelope, doneWord) {
    ui.lock();
    const paint = (cls, txt) => paintLine(ui.st, cls, txt);
    const via = ctlOf((this._list || []).find(x => x.id === id)) === "vault";
    try {
      if (via){
        paint("info", "[*] confirm with your passkey…");
        const { vaultOp } = await import("../../js/core/vault.js");
        await vaultOp("control", { id, action: "options", envelope });
      } else {
        if (!Enclave.provider){ paint("info", "[*] connecting wallet…"); await connectWallet(); }
        await ensureBaseChain();
        paint("info", "[*] confirm the transaction in your wallet…");
        const th = await sendTx(DEPLOYMENTS_ADDRESS,
          encCall(DEP_SEL.setConfig, [{ t: "bytes32", v: id }, { t: "str", v: envelope }]));
        paint("dimln", "  ↳ sent " + th + " · waiting for confirmation…");
        await waitReceipt(th);
      }
      paint("ok", "[✓] " + doneWord + " - " + ctx.applyWord);
      showToast(doneWord + " on " + id.slice(0, 10) + "…");
      this._envLearn(id, envelope);          // the row badge reflects the new envelope immediately
      setTimeout(() => { if (ui.box.isConnected && !ui.box.hidden){ ui.box.hidden = true; ui.box.innerHTML = ""; ui.btn.setAttribute("aria-expanded", "false"); } }, 3500);
      return true;
    } catch(e){
      const rejected = (e && e.code === 4001) || /reject|denied|declin|cancell/i.test(e && e.message || "");
      paint("warn", rejected ? (via ? "[x] cancelled - nothing changed" : "[x] rejected in wallet - nothing changed") : "[x] " + (e.message || String(e)));
      ui.unlock();
      return false;
    } finally { if (!via) refreshWallet(); }
  }
  /* act on a cfgPlan verdict: clear the override, sign an inline envelope, or
     pin the body first and sign the split one. words: { set, setPinned,
     clear } name each outcome in the done-line. */
  async _cfgCommit(id, ctx, ui, v, words) {
    const plan = cfgPlan(ctx);
    if (v.clear) return this._cfgSubmit(id, ctx, ui, plan.clearEnvelope(), words.clear);
    if (!v.set) return false;
    if (v.mode !== "split") return this._cfgSubmit(id, ctx, ui, v.envelope, words.set);
    // SPLIT: pin the body FIRST, then sign the reference. Order matters - a
    // signed envelope naming a CID nobody pinned is a deployment that claims
    // fine and then fails every launch on the fetch, so the pin must succeed
    // before anything reaches the ledger. The reverse (a pin nobody
    // references) costs a pinned document and nothing else.
    const paint = (cls, txt) => paintLine(ui.st, cls, txt);
    ui.lock();
    let cid;
    try {
      paint("info", "[*] pinning the config… (your wallet signs the upload, not a transaction)");
      cid = await putConfig(v.body);
      paint("dimln", "  ↳ pinned " + cid);
    } catch(e){
      paint("warn", "[x] " + (e.message || String(e)) + " - nothing was signed, the deployment is untouched");
      ui.unlock();
      return false;
    }
    // the size preview used a stand-in CID; this is the string that gets signed
    const envelope = plan.splitEnvelope(v.cfg, cid);
    if (bytesOf(envelope) > ctx.cap){
      paint("warn", "[x] the envelope came to " + bytesOf(envelope) + " bytes with the real CID; the ledger caps it at " + ctx.cap
        + " - nothing was signed. Trim the volumes list and try again");
      ui.unlock();
      return false;
    }
    return this._cfgSubmit(id, ctx, ui, envelope, words.setPinned);
  }

  /* ---- per-row Config: the deployment's app config (ENCLAVE_CONFIG) ----
     The editor over _cfgRead's context: one honest textarea (the config is
     arbitrary publisher JSON, so no form can know its fields), a live meta
     line (verdict + envelope bytes), Apply/Reset through _cfgCommit, and the
     variations shelf. Reset drops the override: the app falls back to the
     version's approval-covered config, resolved fresh by the runner - so it
     works even when this page can't read the stock text. Variations are
     named documents saved in THIS BROWSER (localStorage, one shelf per app) -
     nothing touches the chain until Apply. ---- */
  async _configPanel(id, btn) {
    const row = btn.closest(".enc-row"), box = row && row.querySelector(".enc-cfg"); if (!box) return;
    if (!box.hidden){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); return; }
    btn.setAttribute("aria-expanded", "true");
    box.hidden = false;
    const bar = '<div class="ap-attbar">app config · ' + esc(id) + '</div>';
    box.innerHTML = bar + '<div class="term enc-cfg-status" role="status" aria-live="polite"><span class="ln dimln">// reading the ledger + catalog…</span></div>';
    const ctx = await this._cfgRead(id);
    if (box.hidden || !box.isConnected) return;              // closed while loading
    const fail = (msg) => { box.querySelector(".enc-cfg-status").innerHTML = ""; paintLine(box.querySelector(".enc-cfg-status"), "warn", msg); };
    if (ctx.err) return fail(ctx.err);
    const { d, cur, ovCid, hasOv, o0, ovLost, cr, stock, cap, avail } = ctx;
    const plan = cfgPlan(ctx);
    const pretty = (x) => { try { return x ? JSON.stringify(JSON.parse(x), null, 2) : ""; } catch(e){ return x || ""; } };
    const varKey = cr ? cr.appId : (d.appRef || id);         // one shelf per APP: every deployment/version of it
    const fid = "ec" + appLabel(id);
    box.innerHTML = bar
      + '<div class="enc-cfg-body">'
      +   '<p class="en-intro">The JSON this app receives as <b>ENCLAVE_CONFIG</b>. Editing it here sets an override for <b>this deployment only</b> - '
      +     'the version’s stock config in the catalog and every other deployment stay untouched. Its <b>volumes</b> key names the model volumes the app mounts (the Models tab edits that key as a checklist). '
      +     'A config too large for the ledger’s options field is pinned off-chain automatically, with the reference and the volumes list kept on-chain.</p>'
      +   '<textarea class="ec-ta" id="' + fid + 't" rows="10" spellcheck="false" autocomplete="off" aria-label="app config JSON"></textarea>'
      +   '<div class="ec-meta" id="' + fid + 'm" role="status" aria-live="polite"></div>'
      +   '<div class="ec-acts">'
      +     '<button class="btn btn-sm btn-primary ec-go" type="button">Apply</button>'
      +     '<button class="btn btn-sm ec-reset" type="button" title="Drop the override: the app falls back to the version’s stock config">Reset to stock</button>'
      +   '</div>'
      +   '<div class="ec-vars">'
      +     '<label for="' + fid + 'v">Variations</label>'
      +     '<select class="ec-sel" id="' + fid + 'v" aria-label="saved config variations"></select>'
      +     '<button class="btn btn-sm ec-load" type="button" title="Load the selected variation into the editor - nothing changes on-chain until Apply">Load</button>'
      +     '<button class="btn btn-sm ec-drop" type="button" title="Forget the selected variation (this browser only)">Delete</button>'
      +     '<input class="ec-name" id="' + fid + 'n" type="text" maxlength="40" placeholder="name this config…" autocomplete="off" aria-label="variation name">'
      +     '<button class="btn btn-sm ec-save" type="button" title="Save the editor’s JSON as a named variation in this browser - load it back here, or on any other deployment of this app">Save</button>'
      +   '</div>'
      + '</div>'
      + '<div class="term enc-cfg-status" role="status" aria-live="polite"></div>';
    const st = box.querySelector(".enc-cfg-status"), go = box.querySelector(".ec-go"), reset = box.querySelector(".ec-reset");
    const ta = box.querySelector(".ec-ta"), meta = box.querySelector(".ec-meta"),
          sel = box.querySelector(".ec-sel"), name = box.querySelector(".ec-name"),
          load = box.querySelector(".ec-load"), drop = box.querySelector(".ec-drop"), save = box.querySelector(".ec-save");
    const paint = (cls, txt) => paintLine(st, cls, txt);
    ta.value = ovLost ? "" : (hasOv ? pretty(JSON.stringify(o0)) : (stock ? pretty(stock) : ""));
    paint("info", ovLost ? "// this deployment runs an OVERRIDE pinned off-chain, and this gateway won’t serve it right now - the enclave fetches and hash-verifies the same CID itself, so the app is unaffected. Reset to stock still works; typing here REPLACES the override"
                         : (hasOv ? "// this deployment runs an OVERRIDE (shown above) - the version’s stock config is not in effect"
                        : (stock ? "// showing the version’s stock config - edit it to create an override for this deployment"
                                 : (stock === "" ? "// this version publishes no config - anything you type becomes this deployment’s override"
                                                 : "// couldn’t read the version’s stock config right now - an override can still be set, and Reset works regardless (the runner resolves stock itself)"))));
    if (ovCid && !ovLost) paint("dimln", "// its config is pinned off-chain (" + esc(ovCid.slice(0, 12)) + "…) because it doesn’t fit the ledger’s options field; the reference is what’s on-chain");
    if ("waf" in cur) paint("dimln", "// the deployment’s protection settings are preserved untouched");
    if (cur.network) paint("dimln", "// its network options are preserved");
    if (!avail) paint("dimln", "// couldn’t read fleet availability to confirm override support - if a runner predates it, the next claim would refuse this deployment");
    // what the textarea MEANS against the ledger - the one truth Apply acts on
    const verdict = () => {
      const t = ta.value.trim();
      if (!t) return { empty: true };
      let o; try { o = JSON.parse(t); } catch(e){ return { err: "not valid JSON: " + e.message }; }
      if (!o || Array.isArray(o) || typeof o !== "object") return { err: "the config must be a JSON object, e.g. {\"api_key\":\"…\"} - {} is an explicitly empty config" };
      if ("_media" in o) return { err: "config._media is reserved for the catalog’s store media and never reaches an app - remove it" };
      return plan.verdictOf(o);
    };
    const sync = () => {
      const v = verdict();
      meta.classList.toggle("warn", !!v.err);
      if (v.err) meta.textContent = "[!] " + v.err;
      else if (v.empty) meta.textContent = hasOv ? "the editor is empty - Reset to stock drops the override, or type {} for an explicitly empty config"
                                                 : "type a JSON object to set an override for this deployment";
      else if (v.same) meta.textContent = hasOv ? "unchanged from the override on the ledger" : "this is the version’s stock config - edit it to create an override";
      else if (v.clear) meta.textContent = "matches the stock config - applying removes the override";
      // The split is the panel's own decision, not the owner's, so it says so
      // rather than silently changing where their config lives: the byte count
      // stops being the thing to manage and the pin becomes visible instead.
      else if (v.mode === "split") meta.textContent = bytesOf(v.body) + " bytes - too big for the ledger’s options field, so Apply pins the config "
        + "and puts the reference on-chain with the routing manifest (" + MANIFEST_KEYS.join(", ") + "). Envelope: ~" + v.bytes + " of " + cap + " bytes";
      else meta.textContent = v.bytes + " of " + cap + " envelope bytes";
      go.disabled = !(v.set || v.clear);
      go.textContent = v.clear ? "Remove override" : hasOv ? "Update override" : "Set override";
      reset.disabled = !hasOv;
    };
    ta.addEventListener("input", sync);
    const ui = { box, btn, st, lock: () => { go.disabled = true; reset.disabled = true; }, unlock: sync };
    const setWord = hasOv ? "config override updated" : "config override set";
    go.addEventListener("click", () => this._cfgCommit(id, ctx, ui, verdict(),
      { set: setWord, setPinned: setWord + " (pinned)", clear: "config override removed (back to stock)" }));
    reset.addEventListener("click", () => {
      if (!hasOv) return;
      this._cfgSubmit(id, ctx, ui, plan.clearEnvelope(), "config override removed (back to stock)");
    });
    // ---- the variations shelf ----
    const paintVars = () => {
      const list = varsFor(varKey);
      sel.innerHTML = '<option value="">' + (list.length ? "saved for this app…" : "none saved yet") + '</option>'
        + list.map(x => '<option value="' + esc(x.n) + '">' + esc(x.n) + '</option>').join("");
      load.disabled = drop.disabled = !sel.value;
    };
    sel.addEventListener("change", () => { load.disabled = drop.disabled = !sel.value; });
    load.addEventListener("click", () => {
      const v = varsFor(varKey).find(x => x.n === sel.value); if (!v) return;
      ta.value = pretty(v.c); sync();
      paint("dimln", "// loaded “" + v.n + "” into the editor - Apply makes it this deployment’s config");
    });
    drop.addEventListener("click", () => {
      const n = sel.value; if (!n) return;
      varDrop(varKey, n); paintVars();
      showToast("forgot “" + n + "”");
    });
    save.addEventListener("click", () => {
      const n = (name.value || "").trim();
      if (!n){ meta.classList.add("warn"); meta.textContent = "[!] name the variation first"; name.focus(); return; }
      const t = ta.value.trim();
      let o; try { o = t ? JSON.parse(t) : undefined; } catch(e){ o = undefined; }
      if (!o || Array.isArray(o) || typeof o !== "object"){ meta.classList.add("warn"); meta.textContent = "[!] the editor must hold a JSON object to save as a variation"; return; }
      varPut(varKey, n, JSON.stringify(o));
      paintVars(); sel.value = n; load.disabled = drop.disabled = false;
      name.value = "";
      showToast("saved “" + n + "” in this browser");
      sync();
    });
    paintVars(); sync();
  }

  /* ---- per-row Models: the model volumes this deployment mounts ----
     The fleet's attested read-only weights (Modelwrap volumes, mounted at
     /models/<name>) are named by the app config's `volumes` key. This panel
     is that key as a checklist: every volume a live enclave advertises (union
     across the fleet, each tagged with where it lives), the ones this
     deployment mounts ticked. Apply writes the deployment's config override
     through the same path as the Config tab - the config the deployment runs
     today (its override, else the version's stock config) with only `volumes`
     replaced - so the rest of the app's config is carried verbatim, a
     document too large for the ledger's field is pinned off-chain with the
     volumes list kept on-chain (the runner places on that manifest without a
     fetch), and ticking back the stock set drops the override. Placement
     follows the ticks: a volume lives on the boxes that attached it, so a
     running app whose new set its box lacks relaunches on a box that has it
     at its next claim - the panel says so before anything is signed. ---- */
  async _models(id, btn) {
    const row = btn.closest(".enc-row"), box = row && row.querySelector(".enc-mod"); if (!box) return;
    if (!box.hidden){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); return; }
    btn.setAttribute("aria-expanded", "true");
    box.hidden = false;
    const bar = '<div class="ap-attbar">models · ' + esc(id) + '</div>';
    box.innerHTML = bar + '<div class="term enc-mod-status" role="status" aria-live="polite"><span class="ln dimln">// reading the ledger + fleet…</span></div>';
    const [ctx, fleet] = await Promise.all([this._cfgRead(id, { allowReadOnly: true }), Enclave.getEnclaves().catch(() => null)]);
    if (box.hidden || !box.isConnected) return;              // closed while loading
    const fail = (msg) => { const x = box.querySelector(".enc-mod-status"); x.innerHTML = ""; paintLine(x, "warn", msg); };
    if (ctx.err) return fail(ctx.err);
    const { cur, hasOv, ovLost, o0, stock, cap } = ctx;
    // the config the ticks edit: the override where one exists, the version's
    // stock config otherwise - the WHOLE document, because the override that
    // rides out replaces the app's config, not just its volumes key
    let base = null;
    if (hasOv && ovLost)
      return fail("[!] this deployment runs a config override pinned off-chain, and this gateway won’t serve it right now - the enclave fetches and hash-verifies the same CID itself, so the app is unaffected. Try again once the gateway answers, or reset the override from the Config tab");
    if (hasOv) base = o0 || {};
    else {
      if (stock === null) return fail("[x] couldn’t read the version’s config right now - the volumes list is one key of it, so it can’t be edited without the rest; try again shortly");
      try { base = stock ? JSON.parse(stock) : {}; } catch(e){ base = {}; }
    }
    if (!base || Array.isArray(base) || typeof base !== "object") base = {};
    const nowVols = volumesOf(base);          // what the app mounts today
    let stockVols = [];
    try { stockVols = volumesOf(stock ? JSON.parse(stock) : {}); } catch(e){}
    // the fleet's volumes (Modelwrap): union across serving enclaves, each
    // tagged with which boxes carry it - a one-box volume pins the deployment
    // to that box, and the picker says so
    const byName = new Map();
    for (const e of (fleet || [])){
      if (!e || e.serving === false || e.relay === true) continue;
      for (const v of ((e.availability && e.availability.volumes) || [])){
        if (!v || !v.name) continue;
        const c = byName.get(v.name) || { name: v.name, bytes: 0, onnx: false, gguf: false, sd: false, count: 0, hosts: [] };
        c.bytes = Math.max(c.bytes, v.bytes || 0); c.onnx = c.onnx || !!v.onnx; c.gguf = c.gguf || !!v.gguf; c.sd = c.sd || !!v.sd; c.count++;
        c.hosts.push(e.name || String(e.endpoint || "").replace(/^[a-z]+:\/\//, "").split(".")[0]);
        byName.set(v.name, c);
      }
    }
    // a volume the config names that no live box carries is listed anyway,
    // ticked and flagged: a name nobody serves is a deployment nobody claims,
    // and unticking it here is the way out
    for (const n of nowVols) if (!byName.has(n)) byName.set(n, { name: n, bytes: 0, count: 0, hosts: [], missing: true });
    const vols = [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
    const selected = new Set(nowVols);
    const lr = (this._list || []).find(x => x.id === id);
    const here = (lr && lr.enclave) || "";       // the box serving it right now (absent while queued/stopped)
    // Reading a model selection does not require permission to write a new
    // config. Show the resolved selection even when no host can edit it.
    if (ctx.editBlocked) {
      box.innerHTML = bar + '<div class="enc-mod-body"><h3>Selected models</h3>'
        + (nowVols.length ? '<ul>' + nowVols.map(n => '<li><b>' + esc(n) + '</b> · '
          + (byName.get(n).missing ? 'not on any live enclave' : 'available on ' + byName.get(n).hosts.map(esc).join(', '))
          + '</li>').join('') + '</ul>' : '<p>No model volumes selected.</p>')
        + '<p class="en-intro dim">' + esc(ctx.editBlocked) + ' You can still view the selection here.</p></div>';
      return;
    }
    box.innerHTML = bar
      + '<div class="enc-mod-body">'
      +   '<p class="en-intro">The model volumes this app mounts at <b>/models/&lt;name&gt;</b>: attested read-only weights an enclave carries, named by the <b>volumes</b> key of the app’s config. '
      +     'Tick what <b>this deployment</b> should mount. Applying writes the list into this deployment’s own config (the config it runs today, with only the volumes changed) - '
      +     'the version in the catalog and every other deployment stay untouched.</p>'
      +   (vols.length ? '<c-volume-picker></c-volume-picker>'
                       : '<p class="en-intro dim">No live enclave is carrying a model volume right now, and this deployment names none - there is nothing to pick from yet.</p>')
      +   '<div class="ec-meta em-meta" role="status" aria-live="polite"></div>'
      +   '<div class="ec-acts"><button class="btn btn-sm btn-primary em-go" type="button">Apply</button></div>'
      + '</div>'
      + '<div class="term enc-mod-status" role="status" aria-live="polite"></div>';
    const st = box.querySelector(".enc-mod-status"), go = box.querySelector(".em-go"), meta = box.querySelector(".em-meta");
    const picker = box.querySelector("c-volume-picker");
    if (picker){ picker.selected = selected; picker.volumes = vols; }
    const paint = (cls, txt) => paintLine(st, cls, txt);
    const plan = cfgPlan(ctx);
    paint("info", hasOv
      ? "// this deployment runs its own config override - the ticks edit its volumes list; the rest of the override is carried verbatim"
      : "// this deployment mounts the version’s stock volumes" + (stockVols.length ? " (" + stockVols.join(", ") + ")" : " (none)") + " - a change creates a config override for this deployment only");
    if (here) paint("dimln", "// running on " + here + " - a volume it doesn’t carry moves the app to a box that does, on its next claim");
    paint("dimln", "// a volume only one enclave carries pins this deployment to that box");
    const missing0 = nowVols.filter(n => byName.get(n).missing);
    if (missing0.length) paint("warn", "[!] " + missing0.join(", ") + ": no live enclave carries " + (missing0.length === 1 ? "it" : "these") + " right now - the fleet can’t place this deployment until one does, or until it’s unticked");
    if ("waf" in cur) paint("dimln", "// the deployment’s protection settings are preserved untouched");
    if (cur.network) paint("dimln", "// its network options are preserved");
    // the config that rides out: today's document with the ticks as its
    // `volumes` key - the ones it already names first (in their order), new
    // ticks after in list order; no ticks = no key
    const nextObj = () => {
      const o = { ...base };
      const keep = nowVols.filter(n => selected.has(n));
      const names = keep.concat(vols.map(v => v.name).filter(n => selected.has(n) && keep.indexOf(n) === -1));
      if (names.length) o.volumes = names; else delete o.volumes;
      return o;
    };
    const verdict = () => plan.verdictOf(nextObj());
    const sync = () => {
      const v = verdict();
      const names = volumesOf(nextObj());
      meta.classList.toggle("warn", !!v.err);
      const list = names.length ? names.join(", ") : "no model volumes";
      // the box serving it now lacks a tick: say the app will move, before the signature
      // (a volume NO box carries is the warn line's business, not this note's)
      const away = here ? names.filter(n => !byName.get(n).missing && (byName.get(n).hosts || []).indexOf(here) === -1) : [];
      const moveNote = away.length ? " · " + here + " doesn’t carry " + away.join(", ") + ": the app relaunches on a box that does" : "";
      if (v.err) meta.textContent = "[!] " + v.err;
      else if (v.same) meta.textContent = list + " - unchanged";
      else if (v.clear) meta.textContent = list + " - the version’s stock set: applying removes this deployment’s config override" + moveNote;
      else if (v.mode === "split") meta.textContent = list + " · the config is too big for the ledger’s field, so Apply pins it off-chain and keeps the volumes list on-chain (~" + v.bytes + " of " + cap + " envelope bytes)" + moveNote;
      else meta.textContent = list + " · " + v.bytes + " of " + cap + " envelope bytes" + moveNote;
      go.disabled = !(v.set || v.clear);
      go.textContent = v.clear ? "Remove override" : "Apply";
    };
    if (picker) picker.addEventListener("change", sync);
    const ui = { box, btn, st, lock: () => { go.disabled = true; }, unlock: sync };
    go.addEventListener("click", () => {
      const names = volumesOf(nextObj());
      const word = names.length ? "model volumes set to " + names.join(", ") : "model volumes cleared";
      this._cfgCommit(id, ctx, ui, verdict(), { set: word, setPinned: word + " (config pinned)", clear: word + " (override removed, back to stock)" });
    });
    sync();
  }

  /* ---- per-row Secrets section: private env vars, relay-stored ----
     S3 keys and API tokens live on the RELAY (encrypted at rest), never on the
     public chain; the enclave holding the lease injects them as env vars at
     every app start. No session: each owner op is one single-use personal_sign
     over a canonical string the relay checks against the on-chain owner -
       get:  enclave-secrets:get:<id>:<expiry>
       put:  enclave-secrets:put:<id>:<expiry>:<sha256hex(payload)>
     The bar renders permanently (secretsSection); this wires its Unlock/Lock
     control. Reveal-first on purpose: Save REPLACES the whole set, and saving
     blind over unseen keys is how secrets get wiped by accident, so the editor
     only exists after a reveal signature has shown what's stored. ---- */
  _secretsWire(box) {
    const id = box.dataset.id;
    const row = box.closest(".enc-row") || box;
    const ta = box.querySelector(".es-ta"), toggle = row.querySelector(".es-toggle"),
          body_ = box.querySelector(".enc-sec-body"), save = box.querySelector(".es-save"),
          cust = box.querySelector(".es-custody"), st = box.querySelector(".enc-sec-status");
    if (!id || !ta || !toggle || !body_ || !save || !st) return;
    const paint = (cls, txt) => paintLine(st, cls, txt);
    // dotenv-style value quoting, both directions: the reveal renders every
    // value as KEY="…" (with " and \ escaped), and the parser strips one layer
    // of matched quotes ('single' = literal, "double" = \" \\ unescape). Bare
    // KEY=value still works; the quotes are a client convention only - the
    // relay stores the unquoted value.
    const quo = (v) => '"' + String(v).replace(/(["\\])/g, "\\$1") + '"';
    const unq = (v) => {
      const dq = /^"([\s\S]*)"$/.exec(v); if (dq) return dq[1].replace(/\\(["\\])/g, "$1");
      const sq = /^'([\s\S]*)'$/.exec(v); if (sq) return sq[1];
      return v;
    };
    const sha256hex = async (s) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))]
      .map(b => b.toString(16).padStart(2, "0")).join("");
    const sign = async (message) => {
      if (!Enclave.provider){ paint("info", "[*] connecting wallet…"); await connectWallet(); }
      return personalSign(message);
    };
    const call = async (path, body) => {
      const r = await fetch(Enclave.base + path, { method: "POST",
        headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.message || j.error || ("HTTP " + r.status));
      return j;
    };
    let hadKeys = 0, armedClear = false, custodyHeld = false, admitted = null;
    // the textarea as an env map (both Save paths); throws naming the first bad line
    const parseSet = () => {
      const set = {};
      for (let line of ta.value.split("\n")) {
        line = line.trim();
        if (!line || line.startsWith("#")) continue;
        const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
        if (!m) throw new Error('"' + (line.length > 40 ? line.slice(0, 37) + "…" : line) + '" is not KEY=value');
        if (/^ENCLAVE_/i.test(m[1])) throw new Error(m[1] + ": the ENCLAVE_ prefix is reserved for platform variables");
        set[m[1]] = unq(m[2]);
      }
      return set;
    };
    // One control, two states. Unlock: sign the get, fill the editor, show the
    // body. Lock: wipe the values and collapse back to the bare bar (what's
    // stored is untouched; nothing is sent).
    toggle.addEventListener("click", async () => {
      if (toggle.dataset.open) {
        ta.value = "";
        body_.hidden = true;
        delete toggle.dataset.open;
        toggle.title = "One wallet signature reveals this deployment’s stored secrets for editing";
        toggle.setAttribute("aria-expanded", "false");
        armedClear = false; save.textContent = "Save";
        st.innerHTML = "";
        return;
      }
      toggle.disabled = true;
      box.dataset.busy = "1";   // pin repaints for the wallet wait - the body is still hidden (see _panelPinned)
      try {
        // custody (docs/security/secret-custody.md): a custody-held set is readable by NOBODY here - not the relay,
        // not this page - so there is nothing to reveal; the editor opens empty and saves a complete new set
        custodyHeld = false;
        if (custodyAvailable()) {
          let cs = null;
          try { cs = await custodyStatus(id); }
          catch(e){ paint("dimln", "// the custody vault could not be read just now (" + (e.message || e) + ")"); }
          if (cs) {
            custodyHeld = true; hadKeys = 0;
            ta.value = "";
            save.hidden = true; cust.hidden = false;
            body_.hidden = false;
            toggle.dataset.open = "1";
            toggle.setAttribute("aria-expanded", "true");
            toggle.disabled = false;
            ta.focus();
            paint("ok", "[✓] custody-held · rev " + cs.secretRev + (cs.threshold ? " · " + cs.threshold + " of " + cs.custodians.length + " custodians" : "")
              + (cs.paused ? " · PAUSED" : "") + " - the values are encrypted to the custodians and cannot be shown here; enter the complete set to replace it");
            return;
          }
          save.hidden = false; cust.hidden = false;
        }
        paint("info", "[*] one signature reveals this deployment’s stored secrets…");
        const expiry = Math.floor(Date.now() / 1000) + 300;
        const signature = await sign("enclave-secrets:get:" + id + ":" + expiry);
        const r = await call("/secrets/" + id + "/get", { expiry, signature });
        hadKeys = r.names.length;
        ta.value = r.names.map(n => n + "=" + quo(r.env[n])).join("\n");
        body_.hidden = false;
        toggle.dataset.open = "1";
        toggle.title = "Hide the revealed values (what’s stored is untouched)";
        toggle.setAttribute("aria-expanded", "true");
        toggle.disabled = false;
        ta.focus();
        paint("ok", r.names.length
          ? "[✓] rev " + r.rev + " · " + r.names.length + " secret" + (r.names.length === 1 ? "" : "s") + " - edit below, then Save (replaces the whole set)"
          : "[✓] nothing stored yet - add KEY=value lines below, then Save");
        // fleet advisory - the relay stores regardless; injection needs the fleet
        try {
          const a = await Enclave.getAvailability();
          if (a && a.aggregate && a.secrets !== true)
            paint("dimln", "// heads-up: the live fleet doesn’t inject secrets yet - values you store apply once it updates");
        } catch(e){}
      } catch(e){
        paint("warn", "[x] " + (e.message || String(e)));
        toggle.disabled = false;
      } finally { delete box.dataset.busy; }   // on success the visible body takes over the pin
    });
    save.addEventListener("click", async () => {
      let set;
      try { set = parseSet(); } catch(e){ return paint("warn", "[x] " + e.message); }
      if (!Object.keys(set).length && hadKeys && !armedClear) {
        armedClear = true; save.textContent = "Really clear all?";
        return paint("warn", "[!] the textarea is empty - Save again to remove all " + hadKeys + " stored secret" + (hadKeys === 1 ? "" : "s"));
      }
      save.disabled = true;
      try {
        paint("info", "[*] one signature stores the set…");
        const payload = JSON.stringify({ clear: true, ...(Object.keys(set).length ? { set } : {}) });
        const expiry = Math.floor(Date.now() / 1000) + 300;
        const signature = await sign("enclave-secrets:put:" + id + ":" + expiry + ":" + await sha256hex(payload));
        const r = await call("/secrets/" + id, { payload, expiry, signature });
        hadKeys = r.names.length; armedClear = false; save.textContent = "Save";
        const running = ((this._list || []).find(x => x.id === id) || {}).status === "running";
        paint("ok", "[✓] stored rev " + r.rev + (r.names.length ? " · " + r.names.join(", ") : " · empty")
          + (running ? " - Restart applies it to the running app" : " - the app picks it up when it starts"));
        showToast("secrets updated for " + id.slice(0, 10) + "…");
      } catch(e){
        const rejected = (e && e.code === 4001) || /reject|denied|declin|cancell/i.test(e && e.message || "");
        paint("warn", rejected ? "[x] rejected in wallet - nothing changed" : "[x] " + (e.message || String(e)));
      } finally { save.disabled = false; }
    });
    // Save to custody: encrypt in this browser, one wallet transaction to the vault; then, for a set the relay held,
    // delete the relay's copy (only once the relay itself reports the deployment custody-held)
    if (cust) cust.addEventListener("click", async () => {
      let env;
      try { env = parseSet(); } catch(e){ return paint("warn", "[x] " + e.message); }
      if (!Object.keys(env).length) return paint("warn", "[x] custody stores a complete set: add KEY=value lines (to remove every value use: enclave custody set with a new set, or clear the policy with the CLI)");
      cust.disabled = true; save.disabled = true;
      try {
        // a FIRST custody policy admits which code may receive the values: the relay's public prediction is SHOWN, and
        // only a second click admits it (it decides who gets the secrets, so it is never taken silently)
        if (!custodyHeld && !admitted) {
          const pr = await fetch(Enclave.base + "/expected-guest?id=" + encodeURIComponent(id));
          if (!pr.ok) throw new Error("no public prediction of this deployment's guest (set its rules with the CLI: enclave custody set --rules)");
          const rules = await rulesFromPredictionPreview(await pr.json());
          admitted = rules; cust.textContent = "Admit and save";
          return paint("warn", "[!] the values will only be released to app " + rules.appId.slice(0, 16) + "… running in: "
            + rules.images.map((im) => "measurement " + im.measurement.slice(0, 16) + "… / runtime " + im.runtimeId.slice(0, 12) + "…").join("; ")
            + " - as the relay predicts them. Check them, then click Admit and save.");
        }
        if (!Enclave.provider){ paint("info", "[*] connecting wallet…"); await connectWallet(); }
        const r = await saveToCustody({ id, env, admittedRules: admitted, sendTx: (to, data) => walletSendTx(to, data), waitReceipt,
                                        onStep: (m) => paint("info", "[*] " + m) });
        admitted = null; cust.textContent = "Save to custody";
        let note = "";
        if (hadKeys) {
          const ex = await call("/secrets/exists", { id }).catch(() => null);
          if (ex && ex.custody === true) {
            const payload = '{"clear":true}', expiry = Math.floor(Date.now() / 1000) + 300;
            const signature = await sign("enclave-secrets:put:" + id + ":" + expiry + ":" + await sha256hex(payload));
            await call("/secrets/" + id, { payload, expiry, signature });
            note = " · the relay's old copy is deleted - rotate those credentials at their issuers: the relay could read them";
          } else note = " · the relay still holds its old copy (it is not custody-aware yet); clear it later";
        }
        custodyHeld = true; hadKeys = 0; ta.value = ""; save.hidden = true;
        paint("ok", "[✓] custody rev " + r.secretRev + " · " + r.threshold + " of " + r.custodians.length + " custodians" + note
          + " - Restart applies it to the running app");
        showToast("secrets moved to custody for " + id.slice(0, 10) + "…");
      } catch(e){
        const rejected = (e && e.code === 4001) || /reject|denied|declin|cancell/i.test(e && e.message || "");
        paint("warn", rejected ? "[x] rejected in wallet - nothing changed" : "[x] " + (e.message || String(e)));
      } finally { cust.disabled = false; save.disabled = false; }
    });
  }

  /* ---- per-row Domains: attach a hostname you own ------------------------
     Four signed calls (list/add/verify/delete), each an EIP-191 personal_sign
     the relay checks against the deployment's on-chain owner - the secrets
     convention, same shapes:
       list:   enclave-domains:list:<id>:<expiry>
       add:    enclave-domains:add:<id>:<expiry>:<hostname>
       verify: enclave-domains:verify:<id>:<expiry>:<hostname>
       delete: enclave-domains:del:<id>:<expiry>:<hostname>
     The hostname in a signed message is the NORMALIZED one, so the client
     normalizes before signing and the relay re-normalizes before checking -
     "EXAMPLE.com " must not produce a signature over a string no record will
     ever match again.
     While the panel is open it re-lists every 30s WITHOUT a signature prompt,
     reusing the one the customer already gave until it expires - watching
     pending_dns become live is the whole point of the panel, and a wallet
     popup every 30s is not a feature anyone would use. The relay exempts the
     LIST read from its single-use rule for exactly this (mutations stay
     single-use, so every one of those drops the cached signature). */
  _domainsWire(box) {
    const id = box.dataset.id;
    const toggle = (box.closest(".enc-row") || box).querySelector(".ed-toggle"), body_ = box.querySelector(".enc-dom-body"),
          list = box.querySelector(".ed-list"), input = box.querySelector(".ed-in"),
          add = box.querySelector(".ed-add-btn"), st = box.querySelector(".enc-dom-status");
    if (!id || !toggle || !body_ || !list || !input || !add || !st) return;
    const paint = (cls, txt) => paintLine(st, cls, txt);
    const sign = async (message) => {
      if (!Enclave.provider){ paint("info", "[*] connecting wallet…"); await connectWallet(); }
      return personalSign(message);
    };
    const call = async (path, body) => {
      const r = await fetch(Enclave.base + path, { method: "POST",
        headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.message || j.error || ("HTTP " + r.status));
      return j;
    };
    // Same normalization the relay applies, so what gets signed is what gets
    // stored. Deliberately lenient about what it ACCEPTS (a pasted URL, a
    // trailing dot) and strict about what it EMITS.
    const norm = (s) => String(s || "").trim().toLowerCase()
      .replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.+$/, "");
    let timer = null, listSig = null;   // { expiry, signature } reused by the poll

    const render = (r) => {
      const rows = r.domains || [];
      list.innerHTML = rows.length ? rows.map(domainRow).join("")
        : '<div class="ed-empty">No domains attached. Add one below and this app will serve it '
          + 'on your own name, with a certificate minted inside the enclave.</div>';
      $$(".ed-copy", list).forEach(b => b.addEventListener("click", () => copyText(b.dataset.copy)));
      $$(".ed-check", list).forEach(b => b.addEventListener("click", () =>
        act("verify", b.closest(".ed-row").dataset.host, b)));
      $$(".ed-del", list).forEach(b => b.addEventListener("click", () =>
        act("delete", b.closest(".ed-row").dataset.host, b)));
      const pending = rows.filter(d => d.status !== "active").length;
      if (rows.length) paint("dimln", "// " + rows.length + " of " + r.limit + " attached"
        + (pending ? " · " + pending + " waiting on DNS or a certificate - re-checked automatically" : " · all live"));
      else st.innerHTML = "";
    };

    const refresh = async ({ interactive = true } = {}) => {
      const now = Math.floor(Date.now() / 1000);
      if (!listSig || listSig.expiry <= now + 10) {
        if (!interactive) return;                       // poll: never prompt, just wait for the next user action
        const expiry = now + 300;
        listSig = { expiry, signature: await sign("enclave-domains:list:" + id + ":" + expiry) };
      }
      render(await call("/domains/" + id + "/list", listSig));
    };

    // add/verify/delete: one signature each, then re-list. The re-list needs a
    // FRESH signature (the relay makes every owner signature single-use), so
    // the cached one is dropped whenever a mutation lands.
    const act = async (kind, hostname, btn) => {
      const host = norm(hostname);
      if (!host) return paint("warn", "[x] enter a hostname");
      if (btn) btn.disabled = true;
      try {
        const expiry = Math.floor(Date.now() / 1000) + 300;
        const msg = { add: "enclave-domains:add:", verify: "enclave-domains:verify:", delete: "enclave-domains:del:" }[kind]
                  + id + ":" + expiry + ":" + host;
        paint("info", "[*] one signature " + { add: "attaches", verify: "re-checks", delete: "detaches" }[kind] + " " + host + "…");
        const signature = await sign(msg);
        const path = "/domains/" + id + (kind === "add" ? "" : "/" + kind);
        const r = await call(path, { hostname: host, expiry, signature });
        listSig = null;
        if (kind === "delete") {
          paint("ok", "[✓] " + host + " detached - remove its DNS records at your provider too");
          showToast(host + " detached");
        } else if (r.status === "active" || r.status === "verified") {
          paint("ok", "[✓] " + host + " verified" + (r.status === "active" ? " and live" : " - the certificate is being minted, usually within a minute"));
        } else {
          paint("warn", "[!] " + host + " attached · " + (r.lastError || "create the DNS records below; we re-check every few minutes"));
        }
        if (kind === "add") input.value = "";
        await refresh();
        // fleet advisory, exactly like secrets: the relay stores regardless,
        // but serving the name needs runners that know the feature
        try {
          const a = await Enclave.getAvailability();
          if (a && a.aggregate && a.customDomains !== true)
            paint("dimln", "// heads-up: the live fleet doesn’t serve custom domains yet - this one starts working once it updates");
        } catch(e){}
      } catch(e){
        const rejected = (e && e.code === 4001) || /reject|denied|declin|cancell/i.test(e && e.message || "");
        paint("warn", rejected ? "[x] rejected in wallet - nothing changed" : "[x] " + (e.message || String(e)));
      } finally { if (btn) btn.disabled = false; }
    };

    toggle.addEventListener("click", async () => {
      if (toggle.dataset.open) {
        body_.hidden = true; delete toggle.dataset.open;
        toggle.setAttribute("aria-expanded", "false");
        st.innerHTML = ""; list.innerHTML = ""; listSig = null;
        clearInterval(timer); timer = null;
        return;
      }
      toggle.disabled = true;
      box.dataset.busy = "1";   // same repaint pin as secrets: hidden body + pending wallet prompt
      try {
        paint("info", "[*] one signature lists this deployment’s domains…");
        await refresh();
        body_.hidden = false;
        toggle.dataset.open = "1";
        toggle.setAttribute("aria-expanded", "true");
        // While it's open, keep the statuses moving on their own - the whole
        // point of the panel is watching pending_dns become live.
        clearInterval(timer);
        timer = setInterval(() => refresh({ interactive: false }).catch(() => {}), 30000);
      } catch(e){
        paint("warn", "[x] " + (e.message || String(e)));
      } finally { toggle.disabled = false; delete box.dataset.busy; }
    });
    add.addEventListener("click", () => act("add", input.value, add));
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); act("add", input.value, add); } });
  }

  /* ---- per-row Output panel: recorded deploy narrative + live app logs ---- */
  _output(id, btn) {
    const row = btn.closest(".enc-row"), box = row && row.querySelector(".enc-out"); if (!box) return;
    if (!box.hidden) { box.hidden = true; box.innerHTML = ""; this._stopLogPoll(id); btn.setAttribute("aria-expanded", "false"); return; }
    box.hidden = false;
    btn.setAttribute("aria-expanded", "true");
    // logs are NOT a live region: each poll replaces them wholesale (a live region would re-announce all 200 lines every 5s)
    box.innerHTML = '<div class="ap-attbar">output · ' + esc(id) + '</div>'
      + '<div class="term enc-out-term">'
      +   '<div class="enc-out-info"></div>'
      +   '<div class="enc-out-nar"></div>'
      +   '<div class="enc-out-logs" role="log" aria-live="off" aria-label="Deployment logs" tabindex="0"><span class="ln dimln">// fetching app logs…</span></div>'
      + '</div>';
    const nar = box.querySelector(".enc-out-nar"), scroller = box.querySelector(".enc-out-term");
    // lead with the OUTSIDE view - the app's reachable endpoints - because the
    // logs below speak in enclave-internal bind ports that match nothing out here
    const info = box.querySelector(".enc-out-info");
    const d = (this._list || []).find(x => x.id === id);
    if (info && d){
      const ep = appEndpoint(d);
      if (ep) paintLine(info, "ok", "→ reachable at " + ep + (d.public ? "" : "   (private · opens after a wallet sign-in)"), scroller);
      const net = d.network || {};
      const tcp = (net.tcp && net.tcp.ports) || [], udp = (net.udp && net.udp.ports) || [];
      if (net.address)
        paintLine(info, "info", "→ dedicated IPv6 [" + net.address + "]"
          + (tcp.length ? " · tcp " + tcp.join(",") : "") + (udp.length ? " · udp " + udp.join(",") : "")
          + ((tcp.length || udp.length) ? "   (served at these real port numbers)" : "   (outbound egress address - no inbound ports declared)"), scroller);
      paintLine(info, "dimln", "// any 127.0.0.1:<port> below is the app's internal bind inside the enclave - from outside, use the endpoints above", scroller);
    }
    const run = runlog.runFor(id);
    if (run) {
      paintLine(nar, "dimln", "// deploy narrative · " + run.label + " (recorded in this browser)", scroller);
      run.lines.forEach(l => paintLine(nar, l[0], l[1], scroller, l[2]));
      // A narrative that ends in a payment that never happened gets the offer
      // to finish it, even when the record carries no descriptor of its own
      // (retryOfferOf re-derives one). Gated on the LEDGER still showing
      // nothing paid, never on the story alone: a deployment funded since must
      // not be asked to pay twice.
      const offer = retryOfferOf(run, id);
      if (offer && ["awaiting_payment", "unfunded"].indexOf(d && d.status) !== -1)
        paintLine(nar, "act", offer.usd ? "[↻] Retry payment · $" + offer.usd + " USDC" : "[↻] Retry payment",
                  scroller, offer);
    }
    if (ctlOf(d) !== "wallet") this._noteLogs(box);
    else if (this._hostAuthed(id)) this._startLogs(id, box);
    else this._lockedLogs(id, box);
  }
  /* vault-owned rows: the enclaves' log read rides the in-enclave WALLET
     session (the credit vault is the on-chain owner, and only IT could prove
     ownership - ERC-1271 session support is tracked follow-up work). Honest
     note instead of an unlock that could never succeed. */
  _noteLogs(box) {
    const el = box.querySelector(".enc-out-logs"); if (!el) return;
    el.innerHTML = '<span class="ln dimln">// app logs for credit-run deployments are coming soon - today the log channel rides an in-enclave wallet session. The endpoints above are live now.</span>';
  }
  _startLogs(id, box) {
    this._fetchLogs(id, box);
    this._stopLogPoll(id);
    this._logPolls[id] = setInterval(() => {
      if (box.hidden || !box.isConnected) { this._stopLogPoll(id); return; }
      this._fetchLogs(id, box);
    }, 5000);
  }
  /* logs are the one genuinely PRIVATE read on this panel (an app's stdout
     routinely carries secrets). The wallet session reads them with no prompt;
     this unlock is the fallback for no session, or a host that hasn't learned
     sessions yet: prove key ownership to THAT box once - a gas-free
     signature - right where it's needed, and only on a click */
  _lockedLogs(id, box) {
    const el = box.querySelector(".enc-out-logs"); if (!el) return;
    el.innerHTML = '<span class="ln dimln">// ' + (this._sessionTried(id)
        ? "this deployment's host doesn't take your session yet - one gas-free signature proves this wallet owns it there (lasts a week)"
        : "app logs are owner-private - one gas-free signature proves this wallet owns this deployment (lasts a week)") + '</span>'
      + '<button class="wp-mini enc-unlock" type="button">unlock logs</button>';
    el.querySelector(".enc-unlock").addEventListener("click", async () => {
      try { await this._hostSignIn(id); if (!box.hidden && box.isConnected) this._startLogs(id, box); }
      catch(e){ showToast(e.message || String(e)); }
    });
  }
  _stopLogPoll(id) {
    if (this._logPolls && this._logPolls[id]) { clearInterval(this._logPolls[id]); delete this._logPolls[id]; }
  }
  async _fetchLogs(id, box) {
    const el = box.querySelector(".enc-out-logs"), scroller = box.querySelector(".enc-out-term");
    if (!el) return;
    try {
      // never a wallet prompt from a poll: no session or token the host takes = the unlock button
      const text = await this._asHost(id, (h) => Enclave.logs(id, { tail: 200 }, h), { prompt: false });
      if (box.hidden || !el.isConnected) return;
      const lines = String(text == null ? "" : text).split("\n");
      while (lines.length && lines[lines.length - 1] === "") lines.pop();
      // wholesale replace each poll; keep the reader's place unless they're tailing
      const follow = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 48;
      const keep = scroller.scrollTop;
      el.innerHTML = '<span class="ln dimln">// app logs (stdout/stderr from the enclave · tail 200 · refreshes while open)</span>';
      if (!lines.length) el.insertAdjacentHTML("beforeend", '<span class="ln dimln">// (no output yet)</span>');
      for (const ln of lines) {
        const s = document.createElement("span");
        // enclave-internal noise (loopback/wildcard binds) reads dim; real app output full-strength
        s.className = "ln " + (/127\.0\.0\.1|0\.0\.0\.0/.test(ln) ? "dimln" : "logln");
        s.textContent = ln; el.appendChild(s);
      }
      scroller.scrollTop = follow ? scroller.scrollHeight : keep;
    } catch (e) {
      if (e && e.status === 401) { this._stopLogPoll(id); if (el.isConnected && !box.hidden) this._lockedLogs(id, box); return; }
      if (el.isConnected && !box.hidden)
        el.innerHTML = '<span class="ln warn">// logs unavailable: ' + esc(e.message || String(e)) + '</span>';
    }
  }

  async _verify(id, btn) {
    const row = btn.closest(".enc-row"), box = row && row.querySelector(".enc-att"); if (!box) return;
    if (!box.hidden){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); return; }
    box.hidden = false;
    btn.setAttribute("aria-expanded", "true");
    // Checks that need no session, for every account (wallet, card credit, order):
    //   - an app's OWN isolated VM, from public evidence: an Enclave Shield partition, or a public deployment's own SEV-SNP
    //     guest or phone protected VM (both read from the app's public address, so a private deployment cannot take these);
    //   - a private deployment on a phone, or a private card deployment on a confidential server: the host itself, with a
    //     note saying plainly that it is the host and why.
    const dep = (this._list || []).find(x => x.id === id);
    const mode = dep && dep.enclave && /^0x[0-9a-f]{64}$/i.test(id) ? await boxModeOf(dep.enclave).catch(() => null) : null;
    if (mode === "hv-node" || ((mode === "snp" || mode === "avf") && dep.public)) return this._attestApp(id, box, dep.enclave, mode);
    if (mode === "avf") return this._attestHost(id, box, dep.enclave, mode,
      "This checks the phone itself. Checking this app's own protected VM in your browser reads the app's public address, which a private deployment does not have; the relay checks the app's VM when it starts.");
    if (mode === "snp" && ctlOf(dep) !== "wallet") return this._attestHost(id, box, dep.enclave, mode,
      "This checks the confidential server. Checking this app's own SEV-SNP guest in your browser reads the app's public address, which a private deployment does not have.");
    if (ctlOf((this._list || []).find(x => x.id === id)) !== "wallet"){
      // vault/order rows reach here only when no attached host holds the deployment (every attached kind of host is
      // checked above without a session); the session-based attestation read below is a wallet's
      box.innerHTML = '<div class="ap-attbar">attestation · ' + esc(id) + '</div>'
        + '<div class="term"><span class="ln dimln">// no attached host is running this deployment right now, so there is nothing to verify yet. Once a host claims it, Verify checks that host (and, on a confidential server or an Enclave Shield host, this app’s own VM) in your browser.</span></div>';
      return;
    }
    if (!this._hostAuthed(id)) return this._lockedAttest(id, box);
    this._attest(id, box);
  }
  /* the attestation read rides the owner's session (or the host's own sign-in); unlock it in place */
  _lockedAttest(id, box) {
    box.innerHTML = '<div class="ap-attbar">attestation · ' + esc(id) + '</div>'
      + '<div class="term"><span class="ln dimln">// ' + (this._sessionTried(id)
          ? "this deployment's host doesn't take your session yet - one gas-free signature unlocks its attestation reads (lasts a week)"
          : "attestation reads ride the owner session - one gas-free signature unlocks them (lasts a week)") + '</span>'
      + '<button class="wp-mini enc-unlock" type="button">unlock &amp; verify</button></div>';
    box.querySelector(".enc-unlock").addEventListener("click", async () => {
      try { await this._hostSignIn(id); if (!box.hidden && box.isConnected) this._attest(id, box); }
      catch(e){ showToast(e.message || String(e)); }
    });
  }
  /* One app's own VM, verified in this browser (core/verify.js verifyAppInBrowser). Enclave Shield: the host's TPM-quoted boot
     with a credential this page mints, then this app's partition report under that boot's VSM identity key. Confidential
     server: the server's AMD report, then this app's own SEV-SNP guest report from its public address, on the same chip.
     Both over fresh nonces this page draws. */
  async _attestApp(id, box, name, mode) {
    const what = mode === "snp" ? "the server, then this app\u2019s own SEV-SNP guest" : mode === "avf" ? "the phone, then this app\u2019s own protected VM" : "the host, then this app\u2019s partition";
    box.innerHTML = '<div class="ap-attbar">attestation · ' + esc(id) + '<span class="enc-vbadge">⏳ verifying ' + what + ', in your browser…</span></div>'
      + '<div class="enc-shield-v"></div>';
    const badge = box.querySelector(".enc-vbadge"), out = box.querySelector(".enc-shield-v");
    try {
      const r = await verifyAppInBrowser(name, id, { mode });
      if (box.hidden || !box.isConnected) return;
      const b = verdictBadge(r);
      badge.className = "enc-vbadge " + b.cls; badge.textContent = b.text; badge.title = b.title;
      out.innerHTML = verificationHtml(name, r);
    } catch (e) { if (!box.hidden && box.isConnected){ badge.className = "enc-vbadge bad"; badge.textContent = "✗ could not verify: " + (e.message || e); } }
  }
  /* The HOST this deployment runs on, verified in this browser from public evidence (no session), with a note saying plainly
     that it is the host and not the app's own VM. */
  async _attestHost(id, box, name, mode, note) {
    box.innerHTML = '<div class="ap-attbar">attestation · ' + esc(id) + '<span class="enc-vbadge">⏳ verifying the host, in your browser…</span></div>'
      + '<div class="term"><span class="ln dimln">// ' + esc(note) + '</span></div><div class="enc-shield-v"></div>';
    const badge = box.querySelector(".enc-vbadge"), out = box.querySelector(".enc-shield-v");
    try {
      const r = await verifyBoxInBrowser(name, { mode });
      if (box.hidden || !box.isConnected) return;
      const b = verdictBadge(r);
      badge.className = "enc-vbadge " + b.cls; badge.textContent = b.text; badge.title = b.title;
      out.innerHTML = verificationHtml(name, r);
    } catch (e) { if (!box.hidden && box.isConnected){ badge.className = "enc-vbadge bad"; badge.textContent = "✗ could not verify: " + (e.message || e); } }
  }
  async _attest(id, box) {
    box.innerHTML = '<div class="ap-attbar">attestation · ' + esc(id)
      + '<span class="enc-vbadge">⏳ verifying in your browser…</span></div>'
      + '<pre class="ap-attpre">fetching…</pre>';
    const badge = box.querySelector(".enc-vbadge");
    try {
      const att = await this._asHost(id, (h) => Enclave.attestation(id, h), { prompt: false });
      const pre = box.querySelector(".ap-attpre"); if (pre) pre.innerHTML = hlJson(att);
      const vspec = vspecOf(att);
      if (!vspec){ if (badge) badge.textContent = ""; return; }
      // the badge is computed HERE, in the customer's browser, with the repository's own verifier: the box this deployment
      // runs on is challenged with this page's nonce (core/verify.js); the API's verification.selfCheck is never the verdict.
      const boxName = boxOfEndpoint(vspec.attestationEndpoint);
      if (!boxName){ if (badge){ badge.className = "enc-vbadge bad"; badge.textContent = "· not an SEV-SNP box: nothing to verify in the browser"; } return; }
      try {
        const r = await verifyBoxInBrowser(boxName);
        if (!badge || box.hidden) return;
        const b = verdictBadge(r);
        badge.className = "enc-vbadge " + b.cls; badge.textContent = b.text; badge.title = b.title;
      } catch(e){ if (badge && !box.hidden){ badge.className = "enc-vbadge bad"; badge.textContent = "✗ could not verify: " + (e.message || e); } }
    }
    catch(e){
      if (e && e.status === 401) { if (!box.hidden && box.isConnected) this._lockedAttest(id, box); return; }
      const pre = box.querySelector(".ap-attpre"); if (pre) pre.textContent = e.message; if (badge) badge.textContent = "";
    }
  }

  async _kill(id, btn) {
    const onchain = /^0x[0-9a-f]{64}$/i.test(id);
    if (btn){ btn.disabled = true; btn.textContent = onchain ? "suspending…" : "terminating…"; }
    if (ctlOf((this._list || []).find(x => x.id === id)) === "vault"){
      // vault-owned row: setActive(false) goes through the vault contract,
      // passkey-signed - the runner's owner-stop watcher sees the ledger flip
      // and tears the app down within a minute (same suspend semantics)
      try {
        const { vaultOp } = await import("../../js/core/vault.js");
        await vaultOp("control", { id, action: "suspend" });
        showToast("suspended " + id.slice(0, 10) + "… - the remaining balance stays on it; Resume restarts it any time");
        setTimeout(() => this.refresh(), 900);
      } catch(e){ showToast(e.message || String(e)); if (btn){ btn.disabled = false; btn.textContent = "Suspend"; } }
      return;
    }
    try {
      // On-chain deployments (bytes32 ids) are WORK ITEMS: the enclave DELETE
      // only releases the current lease - any enclave would re-claim while the
      // record stays active and funded. A real stop is the owner's
      // setActive(false) on the ledger (one wallet tx), then the enclave release.
      // The remaining balance stays on the record and setActive(true) re-queues
      // it, so for on-chain rows this is a SUSPEND, not an end.
      if (onchain){
        showToast("confirm setActive(false) in your wallet - this suspends the app and takes it off the queue");
        await ensureBaseChain();
        const th = await sendTx(DEPLOYMENTS_ADDRESS, "0x" + DEP_SEL.setActive + pad32(id.replace(/^0x/, "")) + encUint(0));
        await waitReceipt(th);
      }
      const r = await this._asHost(id, (h) => Enclave.terminateDeployment(id, h)).catch(e => {
        // the enclave's owner-stop watcher may already have torn it down
        if (onchain) return null;
        throw e;
      });
      showToast(onchain
        ? "suspended " + id.slice(0, 10) + "… - the remaining balance stays on it; Resume restarts it any time"
        : (r && r.status === "terminated" ? "terminated " : "terminating ") + id);
      setTimeout(() => this.refresh(), 900);
    }
    catch(e){ showToast(e.message); if (btn){ btn.disabled = false; btn.textContent = onchain ? "Suspend" : "Terminate"; } }
  }

  /* Cancel a deployment and send its unused runtime back (ledger rev 10).

     The whole point of this handler is to be honest about the number. What the
     contract can return is what it still HOLDS for the record - the host's
     escrow - and NOT the balance on the row: the publisher fee and the platform
     share were forwarded to their wallets the moment the deployment was funded,
     and no contract can pull them back. So the quote comes from refundableOf()
     (which is exact, not an estimate) and the dialog names the shortfall
     explicitly rather than letting the balance imply the payout.

     Unlike Suspend this is one-way: the ledger zeroes the balance and
     deactivates the record. Re-funding it later is possible but buys new time
     at the price of the day, so the confirm has to read like an ending. */
  async _refund(id, btn){
    const row = (this._list || []).find(x => x.id === id);
    const vault = ctlOf(row) === "vault";
    const where = vault ? "your credit balance" : "your wallet";
    const orig = btn ? btn.textContent : "Cancel";
    if (btn){ btn.disabled = true; btn.textContent = "checking…"; }
    try {
      if ((await depSchemaRev()) < 10) throw new Error("this ledger predates refunds - suspend it instead, or contact support");
      const [amount6, d] = await Promise.all([depRefundableOf(id), depGet(id)]);
      const bal6 = d ? BigInt(d.balance6 || 0) : 0n;
      const leased = d && Number(d.leaseUntil) * 1000 > Date.now();
      if (!(amount6 > 0n)){
        if (leased)
          throw new Error("nothing refundable yet - everything still held is reserved for the running lease. Suspend it and try again once the host hands the lease back.");
        // Nothing to send back, but the owner still asked to END it. Refusing here
        // left a queued record active (zero-escrow and ETH fundings hold nothing
        // refundable from day one), so Cancel could never take it off the queue.
        // The ledger's refund() reverts on amount=0; the stop is setActive(false).
        if (btn){ btn.disabled = false; btn.textContent = orig; }
        if (!d || !d.active){ showToast("already stopped - there is nothing left on " + id.slice(0, 10) + "… to refund"); setTimeout(() => this.refresh(), 900); return; }
        if (!confirm("Nothing to refund on " + id.slice(0, 10) + "… - the contract holds nothing for it that it can send back.\n\n"
                   + "Stop it and take it off the queue anyway?")) return;
        return this._kill(id, null);
      }
      const usd = (v) => "$" + (Number(v) / 1e6).toFixed(2);
      const lines = ["Cancel " + id.slice(0, 10) + "… and send " + usd(amount6) + " back to " + where + "?", ""];
      if (bal6 > amount6)
        lines.push("Its balance is " + usd(bal6) + ", but " + usd(bal6 - amount6) + " of that cannot be returned: the "
                 + "publisher fee and the platform share went to their wallets when you funded it. " + usd(amount6)
                 + " is what the contract still holds, and it is exactly what you will receive.", "");
      if (leased)
        lines.push("A lease is running. Its unearned time stays reserved for the host and becomes refundable once "
                 + "the host hands the lease back - cancel again then to collect the rest.", "");
      lines.push("The app stops and the deployment ends. This cannot be undone.");
      if (!confirm(lines.join("\n"))){ if (btn){ btn.disabled = false; btn.textContent = orig; } return; }

      if (btn) btn.textContent = "cancelling…";
      if (vault){
        // vault-owned row: the vault contract IS the record's on-chain owner, so
        // the refund lands in the holder's credit balance (passkey-signed)
        const { vaultOp } = await import("../../js/core/vault.js");
        await vaultOp("control", { id, action: "cancel" });
      } else {
        showToast("confirm the refund in your wallet - " + usd(amount6) + " comes back and the deployment ends");
        await ensureBaseChain();
        await waitReceipt(await sendTx(DEPLOYMENTS_ADDRESS, "0x" + DEP_SEL.refund + pad32(id.replace(/^0x/, ""))));
      }
      // the ledger already deactivated it; tear the instance down now rather
      // than waiting for the runner's next owner-stop sweep
      await this._asHost(id, (h) => Enclave.terminateDeployment(id, h)).catch(() => null);
      showToast("cancelled " + id.slice(0, 10) + "… - " + usd(amount6) + " returned to " + where);
      setTimeout(() => this.refresh(), 900);
    }
    catch(e){ showToast(e.message || String(e)); if (btn){ btn.disabled = false; btn.textContent = orig; } }
  }

  /* Hand the record to another wallet (rev-11 ledgers). A transfer moves
     CONTROL and never money: the ledger reverts "refund first" while it still
     holds any of this wallet's refundable backing, so the panel reads the
     gate (min(ownerEscrow6, escrow6)) and either transfers directly, chains
     Cancel + transfer (your money back to YOUR wallet, then the empty record
     hands over), or - while a lease reserves part of the escrow for the host -
     points at Suspend first. ONE-SHOT on-chain: no accept step, so the
     destination address is the whole risk - pasted in full, validated, and
     restated in the confirm. Staged secrets and custom domains stay with the
     record. Wallet rows only - a vault-owned record's on-chain owner IS the
     vault contract (see the render gate). */
  async _transfer(id, btn){
    const row = btn.closest(".enc-row"), box = row && row.querySelector(".enc-xfer"); if (!box) return;
    if (!box.hidden){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); return; }
    btn.setAttribute("aria-expanded", "true");
    box.hidden = false;
    box.innerHTML = '<div class="ap-attbar">transfer · ' + esc(id) + '</div>'
      + '<div class="term enc-xfer-status" role="status" aria-live="polite"><span class="ln dimln">// reading the ledger…</span></div>';
    const b32 = pad32(id.replace(/^0x/, ""));
    let rev = 1, d = null, amount6 = 0n, ownerEsc6 = 0n, escrow6 = 0n;
    try {
      [rev, d, amount6] = await Promise.all([depSchemaRev(), depGet(id), depRefundableOf(id)]);
      if (rev >= 11) {
        const [oe, earn] = await Promise.all([depCall("0x" + DEP_SEL.ownerEscrow6 + b32), depCall("0x" + DEP_SEL.earnOf + b32)]);
        ownerEsc6 = hexBig(oe);
        escrow6 = hexBig("0x" + earn.replace(/^0x/, "").slice(64, 128));   // (rate6, escrow6, creditedUntil)
      }
    } catch(e){}
    if (box.hidden || !box.isConnected) return;               // closed while loading
    const fail = (msg) => { const st = box.querySelector(".enc-xfer-status"); st.innerHTML = ""; paintLine(st, "warn", msg); };
    if (rev < 11) return fail("[x] the live ledger predates deployment transfers (deploymentsSchema < 11)");
    if (!d) return fail("[x] couldn’t read this deployment from the ledger - try again shortly");
    const usd = (v) => "$" + (Number(v) / 1e6).toFixed(2);
    const blocked = ownerEsc6 > 0n && escrow6 > 0n;           // the ledger's own gate
    const leased = Number(d.leaseUntil) * 1000 > Date.now();
    if (blocked && !(amount6 > 0n))
      // the mid-lease window: refundable reads zero while the host's reserve
      // is still escrowed - nothing to chain, the owner must wind down first
      return fail("[x] your remaining escrow is reserved for the running lease. Suspend the app (the host releases within ~a minute), Cancel to collect it, then transfer.");
    const chain = blocked;                                    // Cancel rides in front of the transfer
    const fid = "ex" + appLabel(id);
    box.innerHTML = '<div class="ap-attbar">transfer · ' + esc(id) + '</div>'
      + '<div class="enc-xfer-body">'
      +   '<label for="' + fid + 'a">New owner</label>'
      +   '<input id="' + fid + 'a" class="ex-addr" type="text" spellcheck="false" autocomplete="off" placeholder="0x…" size="46">'
      +   '<button class="btn btn-sm btn-primary ex-go" type="button" disabled>' + (chain ? "Refund & transfer" : "Transfer") + '</button>'
      + '</div>'
      + '<div class="term enc-xfer-status" role="status" aria-live="polite"></div>';
    const st = box.querySelector(".enc-xfer-status"), go = box.querySelector(".ex-go"), aIn = box.querySelector(".ex-addr");
    const paint = (cls, txt) => paintLine(st, cls, txt);
    const intro = () => {
      st.innerHTML = "";
      paint("info", "// a transfer moves control, never money: the record hands over"
                  + (chain ? " AFTER " + usd(amount6) + " of your refundable escrow returns to this wallet (two signatures; the app stops - the new owner funds it)"
                           : " with zero of your funds in it")
                  + "; staged secrets and custom domains go with the record");
      if (chain && leased)
        paint("dimln", "// a lease is running: if part of your escrow stays reserved for the host, the transfer step waits until the host releases - reopen this panel then");
      paint("dimln", "// one-shot: there is no accept step, and only the new owner could ever transfer it back");
    };
    const sync = () => { go.disabled = !/^0x[0-9a-fA-F]{40}$/.test((aIn.value || "").trim()); };
    aIn.addEventListener("input", sync);
    intro(); sync();
    go.addEventListener("click", async () => {
      const to = (aIn.value || "").trim();
      if (!/^0x[0-9a-fA-F]{40}$/.test(to)) return paint("warn", "[x] not an Ethereum address (0x + 40 hex characters)");
      if (to.toLowerCase() === String(Enclave.address || "").toLowerCase()) return paint("warn", "[x] that address already owns this deployment");
      if (/^0x0{40}$/i.test(to)) return paint("warn", "[x] the zero address");
      const lines = ["Transfer " + id.slice(0, 10) + "… to", "", to, "",
                     (chain ? usd(amount6) + " comes back to your wallet first, then this wallet loses every right to the record"
                            : "This wallet loses every right to the record") + " - control, secrets, domains. Your money never goes to the new owner. There is no way back from here. Continue?"];
      if (!confirm(lines.join("\n"))) return;
      go.disabled = true; aIn.disabled = true;
      try {
        await ensureBaseChain();
        if (chain){
          paint("info", "[*] 1/2 confirm the refund in your wallet - " + usd(amount6) + " comes back to you…");
          await waitReceipt(await sendTx(DEPLOYMENTS_ADDRESS, "0x" + DEP_SEL.refund + b32));
          paint("ok", "[✓] refunded " + usd(amount6) + " to your wallet");
        }
        paint("info", "[*] " + (chain ? "2/2 " : "") + "confirm the transfer in your wallet…");
        await waitReceipt(await sendTx(DEPLOYMENTS_ADDRESS, "0x" + DEP_SEL.transferDeployment + b32 + pad32(to)));
        paint("ok", "[✓] transferred to " + to);
        showToast("transferred " + id.slice(0, 10) + "… - it now belongs to " + to.slice(0, 10) + "… and will leave this list");
        setTimeout(() => this.refresh(), 1200);
      } catch(e){
        const m = String(e && e.message || e);
        paint("warn", /refund first/.test(m)
          ? "[x] part of your escrow is still reserved for the running lease - Suspend the app, Cancel once the host releases, then transfer"
          : "[x] " + m);
        go.disabled = false; aIn.disabled = false;
      }
    });
  }

  /* Which box HOSTS this deployment, and whether an owner call there can run
     without asking the wallet.

     The wallet session covers every box: each host verifies it against the
     chain itself, so logs, attestation, Restart, Move and private apps need no
     sign-in of their own. The per-host SIWE token is the fallback for a box
     that hasn't learned sessions yet (or no session at all): every enclave
     signs those with its own in-enclave key and verifies only its own kid, so
     the token minted at the relay's sticky box is rejected everywhere else - a
     deployment hosted anywhere else answered "Missing or invalid session" on
     Restart, logs, attestation and Move alike (2026-07-27). One signature per
     such box, cached per box across reloads, asked once. */
  _hostOf(id) {
    const d = (this._list || []).find(x => x.id === id);
    return String((d && d.enclave) || "").trim();
  }
  _hostAuthed(id) {
    const host = this._hostOf(id);
    // A generic token says nothing about this host. Unlock must use the
    // same scope as the read, including when no fleet-default host is serving.
    return (host ? Enclave.authedFor(host) : Enclave.authed()) || Enclave.sessionMayServe(host);
  }
  /* a session exists in this browser, and this host answered it with 401: the copy says so */
  _sessionTried(id) {
    return !!Enclave.address && Enclave._siweHosts.has(Enclave._hostKey(this._hostOf(id)));
  }
  /* the explicit fallback, behind an unlock click: the per-host sign-in for this deployment's box */
  async _hostSignIn(id) {
    const host = this._hostOf(id);
    await authenticate(host ? { enclave: host } : undefined);
    return host;
  }

  /* Run an owner call against the box HOSTING this deployment: the wallet
     session when that box takes it; otherwise (and only then) the per-host
     sign-in, once (wallet.js asHostOwner). A cached per-host token the box no
     longer honours - minted elsewhere before the sign-in pin existed, or when
     the pin fell back - is dropped by _req on its 401, so the same retry
     re-mints against the right enclave instead of "Missing or invalid session"
     forever. `prompt: false` (polls, panels opened without a click on an
     unlock) hands the 401 back instead of asking the wallet. */
  async _asHost(id, call, opts) {
    return asHostOwner(this._hostOf(id), call, opts);
  }

  /* ---- choose placement for a deployment in any state.

     A lease can only be handed back by the box holding it
     (EnclaveDeployments.release is runner-only - the owner has no on-chain
     authority to evict), so a move is two steps: the owner asks the CURRENT
     runner to release, which refunds the unused lease tail to the deployment's
     balance and puts the record back in the open queue still active and
     funded; then the chosen box gets a claim hint and first crack at it.

     The relay saves the owner's preferred host and tries it first whenever
     the app is queued. The ledger envelope enforces pins without fallback. A preference
     stays saved even when a fallback holds the lease.

     Cost: the app stops and relaunches, so this is the same interruption as
     Restart plus a claim. No time is lost - release refunds, claim re-burns. ---- */
  async _move(id, btn) {
    const row = btn.closest(".enc-row"), box = row && row.querySelector(".enc-move"); if (!box) return;
    if (!box.hidden){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); return; }
    btn.setAttribute("aria-expanded", "true");
    box.hidden = false;
    box.innerHTML = '<div class="ap-attbar">pin · ' + esc(id) + '</div>'
      + '<div class="term enc-move-status" role="status" aria-live="polite"><span class="ln dimln">// reading the ledger + fleet…</span></div>';
    const stEl = () => box.querySelector(".enc-move-status");
    const fail = (msg) => { const s = stEl(); if (s){ s.innerHTML = ""; paintLine(s, "warn", msg); } };
    if (!/^0x[0-9a-f]{64}$/i.test(id))
      return fail("This legacy instance has no ledger deployment to pin. Deploy its app version on the host you want.");
    const controller = ctlOf((this._list || []).find(x => x.id === id));
    if (controller === "order")
      return fail("This payment order is still being provisioned. Pin becomes actionable once its deployment is created.");
    let d = null, fleet = null, rev = 1, placement = null;
    try {
      [d, fleet, rev, placement] = await Promise.all([depGet(id), Enclave.getEnclaves().catch(() => null), depSchemaRev().catch(() => 1), Enclave.getPlacement(id)]);
      await loadCatalog();
      await Enclave.getAvailability().then(a => adoptServerSpec(a)).catch(() => null);
    } catch(e){ d = null; }
    if (box.hidden || !box.isConnected) return;             // closed while loading
    if (!d) return fail("[x] couldn’t read this deployment from the ledger - try again shortly");
    if (!fleet) return fail("[x] couldn’t read the fleet list - try again shortly");
    let isolation;
    try { isolation = isolationOptions(d.configCid); }
    catch (e) { return fail("[x] Cannot safely edit deployment options: " + e.message); }
    const currentRunner = moveLeaseLive(d) ? d.runner : "";
    const here = currentRunner ? leaseHostOf(d, fleet) : null;
    // The app's own requirements decide where it can go. A catalog deployment
    // carries its version's spec (hardware + model volumes); the deployment's
    // own config overrides the volume list (the row's Models tab edits it).
    const cr = parseCatalogRef(d.appRef);
    const ver = cr ? await catGetVersion(cr.appId, cr.index).catch(() => null) : null;
    if (!ver) return fail("[x] the catalog doesn’t list this deployment’s version - a move re-claims the record, and only a listed version can be re-claimed");
    const baseSpec = specOf(ver);
    const spec = { ...baseSpec, ...(isolation.envelope.config ? { volumes: isolation.envelope.config.volumes || [] } : {}) };
    // the DEPLOYMENT's own softening (its options envelope), distinct from the
    // publisher's in specOf: an envelope speaks for the owner's dial only
    const depSoftGpu = (() => {
      try { const o = JSON.parse(String(d.configCid || "") || "{}"); return o && o.gpu && o.gpu.optional === true; }
      catch { return false; }
    })();
    const targets = moveTargetsFor({ ...spec, depGpuOptional: depSoftGpu, gpuMilli: Number(d.gpuMilli) || 0 }, fleet, currentRunner);
    if (here && !targets.some(t => t.name === here.name))
      targets.unshift({ ...here, current: true });
    if (placement?.hostId && !targets.some(t => String(t.row.id).toLowerCase() === placement.hostId)) {
      const row = fleet.find(h => String(h.id).toLowerCase() === placement.hostId)
        || { id: placement.hostId, availability: { isolation: placement.isolation } };
      targets.push({ name: placement.name, row, unavailable: true });
    }
    const initialHost = placement?.configured
      ? (placement.hostId ? targets.find(t => String(t.row.id).toLowerCase() === placement.hostId)?.name || placement.name || '' : '')
      : here?.name || '';
    const selId = "mvSel" + appLabel(id);
    box.innerHTML = '<div class="ap-attbar">pin · ' + esc(id) + '</div>'
      + '<div class="enc-pin-form">'
      + '<fieldset class="enc-pin-requirements"><legend>Hardware requirements</legend>'
      + '<label><input type="checkbox" class="mv-tee-cpu"' + (isolation.cpuTee ? ' checked' : '') + '> Require TEE CPU</label>'
      + '<label><input type="checkbox" class="mv-tee-gpu"' + (isolation.gpuTee ? ' checked' : '') + '> Require TEE GPU</label>'
      + '</fieldset>'
      + '<p class="enc-pin-help">Unchecked allows either supported isolation implementation. TEE GPU requires confidential GPU hardware; masked GPU offload does not qualify.</p>'
      + '<div class="enc-pin-placement"><div class="enc-pin-host"><label for="' + selId + '">Host</label>'
      + '<select class="eu-sel" id="' + selId + '"></select></div><button class="btn btn-sm btn-primary mv-go">Apply</button></div>'
      + '<label><input type="checkbox" class="mv-fallback"' + (placement?.allowFallback !== false ? ' checked' : '') + '> Allow Fallback</label>'
      + '<p class="enc-pin-help">' + (currentRunner ? 'Changing hosts restarts the app. Keeping this host leaves it running. ' : !d.active ? 'Applying placement resumes the app. ' : '')
      + 'Auto uses the cheapest eligible hosts. A selected host stays pinned; Allow Fallback lets another eligible host run the app when that host cannot. Without fallback, the app waits. Your rate cap in Resources still applies.</p>'
      + '<div class="enc-pin-notice" role="status" aria-live="polite"></div>'
      + '<div class="enc-upg-body mv-upg" hidden></div>'
      + '<div class="term enc-move-status" role="status" aria-live="polite"></div></div>';
    const sel = box.querySelector("#" + selId), go = box.querySelector(".mv-go");
    const cpu = box.querySelector(".mv-tee-cpu"), gpu = box.querySelector(".mv-tee-gpu");
    const notice = box.querySelector(".enc-pin-notice");
    const fallback = box.querySelector(".mv-fallback");
    box._placement = placement;
    box._placementTargets = targets;
    let initialized = false;
    const syncRequirements = () => {
      const choice = { cpuTee: cpu.checked, gpuTee: gpu.checked };
      box._isolationChoice = { ...choice, original: JSON.stringify(d.configCid || "") };
      const selected = initialized ? sel.value : initialHost;
      initialized = true;
      const eligible = targets.filter(t => hostMeetsTeeRequirements(t.row, choice));
      sel.innerHTML = '<option value="">Auto — cheapest eligible host</option>'
        + eligible.map(t => '<option value="' + esc(t.name) + '">' + esc(t.name) + (t.current ? ' · current host' : t.unavailable ? ' · currently unavailable' : t.queued ? ' · currently full' : '') + '</option>').join('');
      sel.value = eligible.some(t => t.name === selected) ? selected : "";
      notice.textContent = eligible.length ? '' : gpu.checked
        ? 'No eligible TEE GPU host is currently available. This requirement will keep the app queued.'
        : 'No host currently meets these hardware requirements.';
    };
    cpu.addEventListener("change", () => { syncRequirements(); syncUpg(); });
    gpu.addEventListener("change", () => { syncRequirements(); syncUpg(); });
    syncRequirements();
    const s = stEl();
    const upgWrap = box.querySelector(".mv-upg");
    const bought = { gpuMilli: Number(d.gpuMilli) || 0, cpuMilli: Number(d.cpuMilli) || 0 };
    const syncUpg = () => {
      fallback.disabled = !sel.value;
      const t = targets.find((x) => x.name === sel.value && !x.unavailable && !x.current);
      go.textContent = "Apply";
      const vv = { ...spec, depGpuOptional: depSoftGpu };
      // the upgrade buys the slice the version declares; a pre-13 ledger still
      // rounds it up to the CPU share, because its setShares would revert
      const up0 = t ? gpuUpgradeForMove(vv, t, bought.gpuMilli, bought.cpuMilli) : null;
      const up = up0 ? liftSharesForLedger(up0, rev) : null;
      const down = t && !up ? gpuDowngradeForMove(vv, t, bought.gpuMilli, bought.cpuMilli) : null;
      const act = up || down;
      box._moveUpgrade = act ? { ...act, target: t, dir: up ? "up" : "down" } : null;
      if (!upgWrap) return;
      upgWrap.hidden = !act;
      if (!act) return;
      const price = enclavePriceOf(t.row);
      const nowPct = Math.max(1, Math.round(bought.cpuMilli / 10));
      const cur = shareRates(Math.round(bought.gpuMilli / 10), nowPct, t.spec, price).rate;
      const next = shareRates(act.gpuPct, act.cpuPct, t.spec, price).rate;
      upgWrap.innerHTML = '<label style="display:flex;gap:.5em;align-items:baseline;">'
        + '<input type="checkbox" class="mv-upg-on" checked /> '
        + (up
            ? '<span>buy ' + up.gpuPct + '% GPU on ' + esc(t.name) + ' so it uses the card'
              + ' <span class="dim">(' + up.cpuPct + '% CPU · $' + (next * 3600).toFixed(2) + '/hr, was $' + (cur * 3600).toFixed(2)
              + '/hr on cores) — one confirmation before pinning</span></span>'
            : '<span>drop the ' + Math.round(bought.gpuMilli / 10) + '% GPU share — ' + esc(t.name) + ' has no card'
              + ' <span class="dim">(keeps ' + act.cpuPct + '% CPU. The ledger already stops charging for a card this box'
              + ' does not have; dropping it stops the record asking every future claim for GPU hardware)'
              + ' — one confirmation before pinning</span></span>')
        + '</label>';
    };
    sel.addEventListener("change", syncUpg);
    syncUpg();
    go.addEventListener("click", () => this._doMove(id, sel.value, box, go, here && here.name));
  }

  /* the move itself: release on the current runner, then hint the target until
     the ledger shows a lease somewhere. Every step reports what the chain says,
     because a steer that lost its race is a normal outcome, not an error. */
  async _doMove(id, target, box, go, fromName) {
    const s = box.querySelector(".enc-move-status");
    const controller = ctlOf((this._list || []).find(x => x.id === id));
    const via = controller === "vault";
    const label = go.textContent;
    const vault = via ? (await import("../../js/core/vault.js")).vaultOp : null;
    const walletActive = async active => {
      if (!Enclave.provider) await connectWallet();
      await ensureBaseChain();
      await waitReceipt(await sendTx(DEPLOYMENTS_ADDRESS,
        encCall(DEP_SEL.setActive, [{ t: "bytes32", v: id }, { t: "bool", v: active }])));
    };
    go.disabled = true; go.textContent = "Applying…";
    const choice = box._isolationChoice;
    const placementTarget = (box._placementTargets || []).find(t => t.name === target);
    const hostId = target ? String(placementTarget?.row?.id || '').toLowerCase() : '';
    const allowFallback = !target || box.querySelector('.mv-fallback')?.checked !== false;
    if (box._placementTargets && target && !/^0x[0-9a-f]{64}$/.test(hostId)) {
      paintLine(s, 'warn', '[x] Reopen Pin to refresh the selected host.');
      go.disabled = false; go.textContent = label; return;
    }
    if (choice) {
      try {
        const fresh = await depGet(id);
        const old = isolationOptions(fresh.configCid);
        const initial = isolationOptions(JSON.parse(choice.original));
        if (JSON.stringify(old.envelope.isolation) !== JSON.stringify(initial.envelope.isolation))
          throw new Error("The hardware requirements changed elsewhere. Reopen Pin before applying.");
        if (box._placementTargets && pinnedHost(fresh.configCid) !== pinnedHost(JSON.parse(choice.original)))
          throw new Error("The placement policy changed elsewhere. Reopen Pin before applying.");
        const cap = (await depSchemaRev()) >= 5 ? 4096 : 100;
        let envelope = withIsolationRequirements(fresh.configCid, choice, cap);
        if (box._placementTargets) envelope = withPlacementPin(envelope, hostId, allowFallback, cap);
        if (envelope !== String(fresh.configCid || "")) {
          paintLine(s, "info", "Confirm the placement and hardware requirements in your wallet.");
          if (via) await vault("control", { id, action: "options", envelope });
          else {
            if (!Enclave.provider) await connectWallet();
            await ensureBaseChain();
            await waitReceipt(await sendTx(DEPLOYMENTS_ADDRESS,
              encCall(DEP_SEL.setConfig, [{ t: "bytes32", v: id }, { t: "str", v: envelope }])));
          }
          this._envLearn(id, envelope);
          choice.original = JSON.stringify(envelope);
        }
      } catch(e) {
        paintLine(s, "warn", "[x] " + e.message);
        go.disabled = false; go.textContent = label;
        return;
      }
    }
    if (box._placementTargets) {
      try {
        if (!box._placement?.configured || box._placement.hostId !== hostId || (box._placement.allowFallback !== false) !== allowFallback) {
          const body = { hostId, allowFallback };
          if (!via) {
            if (!Enclave.provider) await connectWallet();
            body.expiry = Math.floor(Date.now() / 1000) + 300;
            body.nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
            paintLine(s, 'info', 'Confirm the placement preference in your wallet.');
            body.signature = await personalSign(placementMessage(DEPLOYMENTS_ADDRESS.toLowerCase(), id.toLowerCase(), hostId, body.expiry, body.nonce, allowFallback));
          }
          box._placement = await Enclave.savePlacement(id, body, via);
          paintLine(s, 'ok', hostId ? 'Host pin saved: ' + target + (allowFallback ? '. Other eligible hosts can serve as fallbacks.' : '. Fallback is off; the app will wait for this host.') : 'Auto placement saved.');
        }
      } catch (e) {
        paintLine(s, 'warn', '[x] Placement was not saved: ' + e.message);
        go.disabled = false; go.textContent = label;
        return;
      }
    }
    // Re-buy the card BEFORE handing the lease back, so the destination claims
    // the record already sized for its GPU and provisions once. Resizing after
    // the move would land it on cores first and restart it again to add the
    // card — two interruptions for one intent. A resize refused here (rate cap,
    // an older fleet) aborts the move with the app still running where it is.
    const upg = box._moveUpgrade;
    const wantUpg = upg && box.querySelector(".mv-upg-on")?.checked;
    if (wantUpg) {
      try {
        paintLine(s, "info", upg.dir === "down"
          ? `[*] dropping the GPU share for ${upg.target.name} (setShares)…`
          : `[*] buying ${upg.gpuPct}% GPU on ${upg.target.name} (setShares)…`);
        if (via) await vault("control", { id, action: "resize", gpuMilli: upg.gpuPct * 10, cpuMilli: upg.cpuPct * 10 });
        else {
          if (!Enclave.provider) await connectWallet();
          await ensureBaseChain();
          const th = await sendTx(DEPLOYMENTS_ADDRESS,
            encCall(DEP_SEL.setShares, [{ t: "bytes32", v: id }, { t: "uint", v: upg.gpuPct * 10 }, { t: "uint", v: upg.cpuPct * 10 }]));
          paintLine(s, "dimln", "    ↳ sent " + th + " · waiting for confirmation…");
          await waitReceipt(th);
        }
        paintLine(s, "dimln", `    shares are now ${upg.gpuPct}% GPU / ${upg.cpuPct}% CPU`);
      } catch(e){
        paintLine(s, "warn", "[x] the resize did not go through: " + (e.message || e));
        paintLine(s, "dimln", "    the share change did not complete; check Resources before retrying the pin");
        go.disabled = false; go.textContent = label;
        return;
      }
    }
    let prepared;
    try {
      prepared = await prepareDeploymentMove({
        read: () => depGet(id), connected: () => box.isConnected,
        keepRunner: target ? String(placementTarget?.row?.id || '') : '',
        progress: message => paintLine(s, "info", "[*] " + message),
        resume: () => via ? vault("control", { id, action: "resume" }) : walletActive(true),
        release: async d => {
          if (via) {
            // The vault controls the ledger through a passkey, not a wallet
            // session at the runner. Suspend, wait for release, then resume.
            await vault("control", { id, action: "suspend" });
            return;
          }
          const fleet = await Enclave.getEnclaves();
          const host = leaseHostOf(d, fleet);
          if (!host?.name) throw Error("The lease holder is offline. Retry when its lease expires.");
          // the session where that box takes it, else its own sign-in (once)
          await asHostOwner(host.name, (h) => Enclave.terminateDeployment(id, h, !!target));
        },
      });
      this._why?.delete(id);
    } catch (e) {
      paintLine(s, "warn", "[x] Pin did not finish: " + (e.message || e));
      go.disabled = false; go.textContent = label;
      setTimeout(() => this.refresh(), 1200);
      return;
    }
    const ZERO = "0x" + "0".repeat(64);
    let landed = moveLeaseLive(prepared) ? prepared : null, lastReason = "";
    for (let i = 0; i < 60 && !landed; i++){
      if (!box.isConnected) return;
      // Re-hint while we wait: the first hint can beat the release being
      // visible to the fleet's load-balanced RPC node and get declined, and a
      // funded record with no hint sits until someone's 60s sweep finds it.
      if (i % 4 === 0){
        try {
          const h = await Enclave.claimHint(id, target, { strategy: target ? "preferred" : "cheapest" });
          if (h && h.accepted === false && h.reason && h.reason !== lastReason){
            lastReason = h.reason;
            paintLine(s, "warn", "[!] " + (target || "the fleet") + " declines: " + h.reason);
          }
        } catch(e){}
      }
      await new Promise(r => setTimeout(r, 2000));
      let d = null; try { d = await depGet(id); } catch(e){}
      const runner = String((d && d.runner) || "").toLowerCase();
      if (d && runner && runner !== ZERO && Number(d.leaseUntil) * 1000 > Date.now()) landed = d;
    }
    if (!landed){
      paintLine(s, "warn", "[!] no enclave has claimed it yet");
      paintLine(s, "dimln", "    the app remains queued. It still needs an eligible host with capacity and funding or free hosting.");
    } else {
      const fleet = await Enclave.getEnclaves().catch(() => null);
      const now = leaseHostOf(landed, fleet);
      const where = (now && now.name) || "another enclave";
      if (!target || where.toLowerCase() === String(target).toLowerCase())
        paintLine(s, "ok", "[✓] running on " + where + " now");
      else {
        paintLine(s, "ok", "[✓] running on fallback host " + where);
        paintLine(s, "dimln", "    " + target + " remains the preferred host for future placement.");
      }
    }
    go.disabled = false; go.textContent = label;
    setTimeout(() => this.refresh(), 1200);
  }

  /* ---- restart a running deployment in place: stop the app instance and
     relaunch it on the same version, lease and balance (no wallet tx - the
     enclave API does it under the owner session). The remedy for a wedged
     instance the crash detector can't see: the process answers, it just
     can't do its job - e.g. a tenant that booted before its model volume
     finished mounting and so can never load the model. App state is
     ephemeral by design, so a restart never loses anything but the wedge. ---- */
  async _restart(id, btn) {
    if (btn){ btn.disabled = true; btn.textContent = "restarting…"; }
    try {
      // owner-private action: rides the wallet session; the host's own sign-in only where it needs one
      await this._asHost(id, (h) => Enclave.restartDeployment(id, h));
      showToast("restarted " + id.slice(0, 10) + "… - relaunching in place, back within a minute");
      setTimeout(() => this.refresh(), 1200);
    }
    catch(e){ showToast(e.message || String(e)); }
    finally { if (btn){ btn.disabled = false; btn.textContent = "Restart"; } }
  }

  /* ---- resume a suspended on-chain deployment: setActive(true) re-queues
     the work item (the balance never left it), then one claim-hint nudges the
     fleet so the relaunch doesn't wait for the next sweep - the ex-runner
     itself may re-adopt (terminated is CLAIM_TERMINAL). The app relaunches
     FRESH from its published version: suspend/resume preserves money, not
     memory (app state is ephemeral by design). An "expired" row's record
     usually never went inactive (expiry is the runner's word for a spent
     lease, not a ledger flip), so the ledger read below skips the no-op
     signature and the nudge alone re-queues it. ---- */
  async _resume(id, btn) {
    if (btn){ btn.disabled = true; btn.textContent = "resuming…"; }
    const via = ctlOf((this._list || []).find(x => x.id === id)) === "vault";
    try {
      // the same read that decides whether setActive is needed also carries
      // the balance, so the toast can send a drained owner to Top up instead
      // of promising a relaunch no enclave would claim
      let dep = null;
      try { dep = await depGet(id); } catch(e){}
      if (!dep || !dep.active){
        if (via){
          // vault-owned row: setActive(true) through the vault, passkey-signed
          const { vaultOp } = await import("../../js/core/vault.js");
          await vaultOp("control", { id, action: "resume" });
        } else {
          showToast("confirm setActive(true) in your wallet - this re-queues the app; billing resumes once it runs");
          await ensureBaseChain();
          const th = await sendTx(DEPLOYMENTS_ADDRESS, "0x" + DEP_SEL.setActive + pad32(id.replace(/^0x/, "")) + encUint(1));
          await waitReceipt(th);
        }
      }
      if (this._why) this._why.delete(id);   // a pre-suspend decline reason must not outlive the resume
      // the nudge's answer carries WHY when every enclave declines (capacity,
      // missing model volume, …) - surface it behind the optimistic toast, or
      // a Resume the fleet can't honor reads as a button that does nothing.
      // force: Resume is the ONE hint allowed to override a failed row's
      // ex-runner provision cooldown (the automatic hints - the why-probe,
      // the funding nudges - must not, or a crash-looping app never rests)
      fetch(Enclave.base + "/claim-hint", { method: "POST",
        headers: { "content-type": "application/json" }, body: JSON.stringify({ id, force: true }) })
        .then(r => r.json())
        .then(h => { if (h && h.accepted === false && h.reason) showToast("the fleet declined the resume nudge: " + h.reason); })
        .catch(() => {});
      // the contract's claimable() boundary: below it no enclave ever claims —
      // EXCEPT a box that hosts this owner for free (ledger rev 12), where the
      // price is zero and there is no balance to be short of. The relay row
      // carries that verdict (hostedFree); trust it over the arithmetic, which
      // compares against the record's worst-case ceiling until a host prices it.
      const free = !!(this._list || []).find(x => String(x.id) === String(id) && x.hostedFree);
      const drained = !free && dep && !(dep.balance6 >= dep.rate);
      showToast(drained
        ? "re-queued " + id.slice(0, 10) + "… - but its balance is spent, so no enclave will claim it: Top up to relaunch"
        : "resumed " + id.slice(0, 10) + "… - re-queued; an enclave picks it up shortly");
      setTimeout(() => this.refresh(), 900);
    }
    catch(e){ showToast(e.message); if (btn){ btn.disabled = false; btn.textContent = "Resume"; } }
  }

  /* ---- "Downloads": a tab panel like the others (was a popup). Content is
     three short branches (dedicated builds / prepackaged APK / generic-shell
     pairing); the panel is inside the component, so it is listed in the
     poll's open-panel guard. */
  _mobile(id, btn) {
    const row = btn.closest(".enc-row"), box = row && row.querySelector(".enc-mob"); if (!box) return;
    if (!box.hidden){ box.hidden = true; box.innerHTML = ""; btn.setAttribute("aria-expanded", "false"); return; }
    const d = (this._list || []).find((x) => String(x.id) === String(id));
    if (!d) return;
    const offer = mobileOffer(d, appEndpoint(d));
    if (!offer) return;
    // same identity the card title uses, minus the version: slug via the
    // catalog ref when d.app is absent, the 8-hex label only as a last resort
    const name = (d.app && d.app.slug)
      || String(slugOfRef(d.image && d.image.reference) || "").split(/[:#]/)[0]
      || appLabel(d.id);
    box.innerHTML =
      '<div class="enc-mob-body">' +
        '<p class="enc-mob-lead">Run ' + esc(name) + ' on a phone. The download below is the app’s mobile build: it re-checks the enclave’s attestation on the device before anything loads, so the phone trusts the enclave itself, not this site.</p>' +
        mobileDialogBody(offer, name) +
      '</div>';
    box.hidden = false; btn.setAttribute("aria-expanded", "true");
    const copy = box.querySelector(".em-copy");
    if (copy) copy.addEventListener("click", () => copyText(copy.dataset.copy));
  }

  /* One answer to "is the user mid-something in a row?" for EVERY repaint
     path (auth edge, catalog land, the 10s poll): any open in-row panel, or a
     signed reveal still waiting on its wallet prompt. The second clause
     exists because secrets/domains are reveal-first - their bodies stay
     hidden until the signature lands - so the open-body check alone has a
     gap exactly as wide as the wallet interaction, and a repaint through it
     rebuilds the row and strands the reveal in detached DOM (the dropdown
     "closes" under the wallet popup). The poll catches up once it clears. */
  _panelPinned() {
    return !!this.querySelector(".enc-att:not([hidden]), .enc-out:not([hidden]), .enc-fund:not([hidden]), .enc-upg:not([hidden]), .enc-shares:not([hidden]), .enc-move:not([hidden]), .enc-waf:not([hidden]), .enc-net:not([hidden]), .enc-cfg:not([hidden]), .enc-mod:not([hidden]), .enc-mob:not([hidden]), .enc-sec-body:not([hidden]), .enc-dom-body:not([hidden]), .enc-sec[data-busy], .enc-dom[data-busy]");
  }
  _startPoll() {
    if (this._poll) return;
    this._poll = setInterval(() => {
      if (!Enclave.address && !Enclave.accountAuthed()){ this._stopPoll(); return; }
      if (this._panelPinned()) return;
      this.refresh();
    }, 10000);
  }
  _stopPoll() { if (this._poll){ clearInterval(this._poll); this._poll = null; } }
}
register("c-deployments", Deployments);
