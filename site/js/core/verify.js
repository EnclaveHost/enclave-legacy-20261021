/* ============================================================
   Live in-browser enclave verification with THIS repository's
   own verifier (verifier/web, bundled to /vendor/enclave-verifier.js
   by scripts/build-vendor.mjs and served same-origin). Shared core
   for the Overview attest widget (<c-live-verify>), each host row of
   the Live enclaves list (<c-fleet-list>) and the Dashboard's
   per-deployment badge.

   What runs in the browser (verifier/metal-box.mjs has the rules):
   the attached SEV-SNP box is challenged with a nonce THIS page
   draws (through the relay, which forwards it over the box's tunnel
   and hands back the box's own document); the report must be
   AMD-signed (VCEK -> the AMD root pinned in the bundle, collateral
   through the relay's KDS mirror: bytes only), meet the published TCB
   floor, refuse debug/migration, and bind the box's transport key
   together with OUR nonce. The launch measurement is compared with
   the relay operator's allowlist - which is the operator's word, so
   the best result here is "limited" with that reason, never a
   silent green. Nothing on this path is a third party's.
   ============================================================ */
import { esc } from "./util.js";

// Same-origin, version-pinned (sha256 in verifier/web/dist/MANIFEST.json). Deliberately not a CDN import: a third party
// that could serve this file could report anything it liked.
export const LV_VERIFIER_URL = "/vendor/enclave-verifier.js";
export const API_ORIGIN = "https://api.enclave.host";

// verification pointers: new shape (verification) with fallback to the pre-selfCheck field name (verify)
export const vspecOf = (att) => (att && (att.verification || att.verify)) || null;

// the box a deployment runs on, from its attestation pointer (https://api.enclave.host/t/<box>/...)
export const boxOfEndpoint = (ep) => { try { return (new URL(ep).pathname.match(/^\/t\/([A-Za-z0-9_-]{1,64})\//) || [])[1] || null; } catch (e) { return null; } };

// the checks the verdict reports (verifier/snp.mjs), in the order a reader follows the chain, with what each one means
export const CHECK_ORDER = ["report shape", "product line", "chain", "crl", "vcek identity", "signature", "tcb policy", "guest policy", "vmpl", "binding", "measurement"];
export const CHECK_LABELS = {
  "report shape": "well-formed AMD SEV-SNP attestation report",
  "product line": "product line named by the report and confirmed by its chain",
  "chain":        "VCEK → ASK → AMD root of trust (the ARK pinned in this page's verifier)",
  "crl":          "AMD revocation list checked (no revoked certificate in the chain)",
  "vcek identity":"the VCEK belongs to this chip at this TCB",
  "signature":    "the report is signed by that VCEK",
  "tcb policy":   "firmware TCB at or above the published floor",
  "guest policy": "guest policy forbids debug and migration",
  "vmpl":         "report produced at VMPL 0",
  "binding":      "report binds the box's transport key and this page's fresh nonce",
  "measurement":  "launch measurement is on the expected list",
};
export const OMISSION_LABELS = {
  "expected-measurement-operator-stated": "the expected measurement comes from the relay operator's own allowlist, not an independent reproduction",
  "tcb-floor-unjudged": "no TCB floor is published for this product line",
  "freshness-unbound": "no fresh nonce was bound",
};

// Which verifier answers for a box: the relay's verdict on how it attached (row.mode), never the box's own word.
//   snp      an AMD SEV-SNP guest: its AMD-signed report (verifyMetalBoxWeb)
//   avf      a phone's protected VM: its Android attestation chain to Google's root (verifyPvmHostWeb)
//   hv-node  an Enclave Shield host: its TPM-quoted boot, with a credential THIS page mints (verifyShieldHostWeb)
const VERIFIERS = { snp: "verifyMetalBoxWeb", avf: "verifyPvmHostWeb", "hv-node": "verifyShieldHostWeb" };
export const TIER_NAMES = { snp: "AMD SEV-SNP", avf: "phone pVM", "hv-node": "Enclave Shield", vbs: "Windows VBS" };
// what each check looks at, in a phrase for the "check it yourself" line
export const EVIDENCE_OF = { snp: "its AMD SEV-SNP report", avf: "its protected VM's Android attestation", "hv-node": "its TPM-attested boot" };

// one run per box at a time; a finished result is reused for 60 s (every run draws a new nonce, so this only spares the box)
const _cache = new Map();   // name -> { at, promise }
export function verifyBoxInBrowser(name, { apiOrigin = API_ORIGIN, mode = "snp" } = {}) {
  const hit = _cache.get(name);
  if (hit && (Date.now() - hit.at < 60_000 || !hit.done)) return hit.promise;
  const entry = { at: Date.now(), done: false };
  entry.promise = (async () => {
    const mod = await import(LV_VERIFIER_URL), fn = VERIFIERS[mode];
    if (!fn || typeof mod[fn] !== "function") throw new Error("this page's verifier cannot check a " + (TIER_NAMES[mode] || mode || "unattested") + " box");
    return mod[fn]({ apiBase: apiOrigin, name });
  })().finally(() => { entry.done = true; entry.at = Date.now(); });
  entry.promise.catch(() => _cache.delete(name));
  _cache.set(name, entry);
  return entry.promise;
}

// ONE app's own isolated VM, verified in this browser:
//   hv-node  its Enclave Shield partition (verifier/web shield-app.mjs): the host's TPM-quoted boot first, with a credential
//            this page mints, then the app guest's report under that boot's VSM identity key, over a fresh nonce.
//   snp      its own SEV-SNP guest (verifier/web snp-app.mjs): the server's AMD report first, then the app guest's, fetched
//            from the app's own origin over a fresh nonce, bound to the key its TLS certificate carries, on the same chip.
//   avf      its own protected VM on a phone (verifier/web pvm-app.mjs): the phone's host VM first, then the app VM's evidence
//            from the app's own origin over a fresh nonce, bound to its TLS key, and the VM proven the phone's (sibling key).
// One run per deployment at a time; a result is reused for 60 s (the relay allows one report per app every 30 s).
const APP_VERIFIERS = { "hv-node": ["verifyShieldAppWeb", "an Enclave Shield app"], snp: ["verifySnpAppWeb", "an app on a confidential server"],
                        avf: ["verifyPvmAppWeb", "an app on a phone host"] };
export const appVerifiable = (mode) => !!APP_VERIFIERS[mode];
const _appCache = new Map();   // deployment id -> { at, promise }
export function verifyAppInBrowser(name, deployment, { apiOrigin = API_ORIGIN, mode = "hv-node" } = {}) {
  const key = String(deployment).toLowerCase(), hit = _appCache.get(key);
  if (hit && (Date.now() - hit.at < 60_000 || !hit.done)) return hit.promise;
  const entry = { at: Date.now(), done: false };
  entry.promise = (async () => {
    const mod = await import(LV_VERIFIER_URL), [fn, what] = APP_VERIFIERS[mode] || [];
    if (!fn || typeof mod[fn] !== "function") throw new Error("this page's verifier cannot check " + (what || "this kind of app") + " yet");
    return mod[fn]({ apiBase: apiOrigin, name, deployment: key });
  })().finally(() => { entry.done = true; entry.at = Date.now(); });
  entry.promise.catch(() => _appCache.delete(key));
  _appCache.set(key, entry);
  return entry.promise;
}
// the public apps a box serves now (the relay's ledger view): [{ id, appRef }]
export async function appsOnBox(name, { apiOrigin = API_ORIGIN } = {}) {
  const r = await fetch(apiOrigin + "/v1/enclaves/" + encodeURIComponent(name) + "/apps", { credentials: "omit" });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.message || ("GET apps -> " + r.status));
  return Array.isArray(j.apps) ? j.apps : [];
}
// a box's /enclaves row as the relay holds it (its tier as verified at attach is row.mode), read once a minute
let _rows = { at: 0, map: null };
export async function boxRowOf(name, { apiOrigin = API_ORIGIN } = {}) {
  if (!_rows.map || Date.now() - _rows.at > 60_000) {
    const rows = await liveBoxes({ apiOrigin });
    _rows = { at: Date.now(), map: new Map(rows.map((e) => [e.name, e])) };
  }
  return _rows.map.get(name) || null;
}
export const boxModeOf = async (name, opts) => ((await boxRowOf(name, opts)) || {}).mode || null;

// every named box the relay holds right now, the ones this page can challenge first
export async function liveBoxes({ apiOrigin = API_ORIGIN } = {}) {
  const r = await fetch(apiOrigin + "/enclaves", { credentials: "omit" });
  if (!r.ok) throw new Error("GET /enclaves -> " + r.status);
  const rows = ((await r.json()).enclaves || []).filter((e) => e && e.name);
  return rows.filter(boxVerifiable).concat(rows.filter((e) => !boxVerifiable(e)));
}

// a one-line summary of a verdict for a badge: { cls: ok|warn|bad, text, title }
// A box or app that was only busy (the relay's 503 busy, a node's 429) is not a verdict: the page says so and when to retry.
export const isBusy = (r) => !!r && r.status === "error"
  && /HTTP (503|429)\b.*(busy|moments ago|in flight|other evidence|retry)/i.test(String((r.reasons || []).at(-1) || ""));
export function verdictBadge(r) {
  if (!r) return { cls: "bad", text: "✗ not verified", title: "" };
  if (isBusy(r)) return { cls: "", text: "· busy right now; try again shortly (not a verdict)", title: String((r.reasons || []).at(-1)) };
  // a verdict that carries its own summary and omission labels (pVM, Enclave Shield) speaks for itself
  if (r.summary && (r.status === "verified" || r.status === "limited")) return { cls: r.status === "verified" ? "ok" : "warn",
    text: r.status === "verified" ? "✓ verified in your browser" : "◐ genuine and fresh (verified in your browser, with limits)",
    title: r.summary + ((r.omissions || []).length ? " Not judged independently: " + r.omissions.map((o) => (r.omissionLabels || {})[o] || o).join("; ") : "") };
  if (r.status === "verified") return { cls: "ok", text: "✓ verified in your browser", title: "AMD SEV-SNP report verified here: chain to AMD's root, TCB floor, fresh nonce binding, and an expected measurement." };
  if (r.status === "limited") return { cls: "warn", text: "◐ genuine and fresh (measurement: operator-stated)",
    title: "Verified in your browser: a genuine AMD SEV-SNP report, fresh for this page's nonce. Not judged independently: "
      + (r.omissions || []).map((o) => OMISSION_LABELS[o] || o).join("; ") + "." };
  const last = (r.reasons || []).at(-1) || r.status;
  return { cls: "bad", text: "✗ not verified: " + String(last).replace(/^(REJECT|UNSUPPORTED|OMITTED)[^:]*:\s*/, ""), title: (r.reasons || []).join("\n") };
}

// Whether THIS page can challenge a box itself: the attested tiers the relay's fresh route and verifier/web cover.
// Any other box gets an honest "not here" with what the relay checked instead.
export const boxVerifiable = (row) => !!(row && row.name && VERIFIERS[row.mode]);
export function unverifiableReason(row) {
  const m = row && row.mode;
  if (m === "vbs") return "a Windows VBS enclave host. The relay verifies its enclave report when it attaches; this page cannot run that check yet.";
  return "a host that attached without hardware evidence the relay verified (a token or operator attach), so there is nothing for this page to challenge.";
}

// One verdict, compact (the lv-* classes, styled in components/live-verify/live-verify.css): a one-line verdict and a count,
// with the summary, every check, what was not judged and the evidence behind "Show the checks". Shared by <c-live-verify>,
// each <c-fleet-list> host row and the Dashboard's Shield badge. An SEV-SNP verdict is first put in the shape the pVM and
// Shield verifiers already return (their own checks, labels, omissions, summary and facts).
function asGeneric(name, r) {
  if (Array.isArray(r.checkOrder)) return r;
  return { ...r, checkOrder: CHECK_ORDER, checkLabels: CHECK_LABELS, omissionLabels: OMISSION_LABELS,
    summary: r.status === "verified" ? name + " presented a genuine, fresh AMD SEV-SNP report at an expected measurement."
      : r.status === "limited" ? name + "'s report verifies to AMD's root for this page's nonce; its measurement matches the operator's list, which this page cannot reproduce on its own." : "",
    facts: [["box", name], r.measurement && ["measurement", r.measurement], r.product && ["product", "AMD EPYC " + r.product],
      r.transportKeySha256 && ["transport key", "sha256:" + r.transportKeySha256], r.nonce && ["nonce", r.nonce.slice(0, 32) + "… (drawn by this page)"],
      r.expected && ["expected from", r.expected.source]].filter(Boolean) };
}
export function verificationHtml(name, r) {
  const g = asGeneric(name, r), labels = g.checkLabels || {}, omit = g.omissionLabels || {};
  const li = (cls, st, txt) => '<li class="' + cls + '"><span class="st">' + st + "</span><span>" + esc(txt) + "</span></li>";
  const order = g.checkOrder || [], checks = g.checks || {};
  const passed = order.filter((k) => checks[k] === true).length, failed = order.find((k) => checks[k] === false);
  const limits = (g.omissions || []).length;
  const reason = String((g.reasons || []).at(-1) || "verification incomplete").replace(/^(REJECT|UNSUPPORTED|OMITTED)[^:]*:\s*/, "");
  const short = (t) => (t.length > 160 ? t.slice(0, 157) + "…" : t);
  const [cls, head] = isBusy(g) ? ["", "Busy right now; try again shortly (not a verdict)"]
    : g.status === "verified" ? ["ok", "✓ Verified"] : g.status === "limited" ? ["warn", "◐ Genuine and fresh"]
    : ["bad", "✗ Not verified: " + short(failed ? (labels[failed] || failed) + " failed" : reason.replace(/^.*?HTTP \d{3}:\s*/, ""))];
  const count = isBusy(g) ? "" : passed + " of " + order.length + " checks passed" + (limits ? " · " + limits + " not judged independently" : "");
  const steps = order.map((k) => checks[k] === true ? li("ok", "✓", labels[k] || k) : checks[k] === false ? li("bad", "✗", labels[k] || k) : li("", "·", labels[k] || k))
    .concat((g.omissions || []).map((o) => li("warn", "◐", "not judged independently: " + (omit[o] || o)))).join("");
  const facts = (Array.isArray(g.facts) ? g.facts : []).filter((f) => Array.isArray(f) && f.length === 2)
    .map(([k, v]) => '<span><b>' + esc(k) + '</b> ' + esc(v) + "</span>").join("");
  return '<div class="lv-verdict ' + cls + '" role="status">' + esc(head) + ' <span class="lv-of">' + esc(name) + "</span></div>"
    + (count ? '<div class="lv-count">' + esc(count) + "</div>" : "")
    + (order.length ? '<details class="lv-more"><summary>Show the checks</summary>'
      + (g.summary ? '<p class="lv-sum">' + esc(g.summary) + "</p>" : "")
      + (g.status !== "verified" && g.status !== "limited" && !isBusy(g) ? '<p class="lv-sum bad">' + esc(reason) + "</p>" : "")
      + '<ul class="lv-steps">' + steps + "</ul>" + (facts ? '<div class="lv-meta">' + facts + "</div>" : "") + "</details>" : "");
}

