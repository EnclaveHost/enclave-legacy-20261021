// windows/node/domains.mjs -- the hostnames a customer attached to a deployment this box runs.
//
// WHAT THIS IS FOR. An owner can point their own domain at a deployment: they attach it on the
// dashboard, prove the DNS, and the relay's domain store records it. From then on the app should
// answer on that name with a certificate a browser trusts. The circuit's ingress worker
// maps its SNI to the deployment. The lease holder learns the attached names here
// so it can obtain and serve the corresponding certificates.
//
// AUTHENTICATION, and why this box can do it at all. relay/domains.js handleFetch takes two
// factors and opens on EITHER: a fleet HMAC over "<id>:<endpoint>:<ts>", or a personal_sign over
// the same tuple by the operator key that REGISTERED this endpoint on chain. Byte for byte the
// secrets fetch (see secrets.mjs for why this box must never hold the fleet key - that key family
// also authorizes _acme-challenge pushes for every hostname on the platform). We send the operator
// factor only. What SCOPES the answer is the ledger: the relay serves a deployment only while its
// live lease `runner` equals keccak256(endpoint), so `endpoint` must be the exact string this box
// registered.
//
// FAILURE BEHAVIOUR IS THE INTERESTING PART, and it is mirrored from the platform runner
// (supervisor.js fetchDepDomains) because getting it wrong takes a paying customer's site down:
//
//   * 503 (a relay without the feature) and 404 (the deployment is not on its ledger view) are
//     AUTHORITATIVE "no custom domains". They clear the list.
//   * anything else - a timeout, a 5xx, a wire error - KEEPS THE LAST KNOWN LIST. A relay blip
//     must not withdraw a live customer's certificate or stop their app answering on their name.
//     This is the opposite of the secrets fetch, where a refusal throws, and deliberately so:
//     there, launching without secrets is a silent misconfiguration; here, forgetting a hostname
//     is an outage on a name the customer owns.
//
// The ISSUANCE REPORT rides along on the next fetch: the box says what happened to each name it
// tried, and the relay shows it to the customer. It is the only way somebody learns that a CA
// refused their domain, so a report that fails to send is retried rather than dropped.

import { ownerHost } from "../../sdk/bootstrap/package.mjs";

const FETCH_SKEW_SEC = 300;          // relay/domains.js FETCH_SKEW_SEC
const TIMEOUT_MS = 5000;
// relay/domains.js's own hostname filter, re-checked here rather than trusted: this list decides
// which names this box will ask a CA to certify and will answer TLS for, and the relay is not the
// authority for what this box does with its own key.
// A dot is required, and so is the entry being a STRING. Both were found by the test rather than
// by reading: `String(42)` is "42" and `String(null)` is "null", and both sail through a character
// class - so a relay answering with a number would have this box ask a CA to certify "42". The dot
// is not pedantry either: no public CA will issue for a single-label name, so accepting one only
// buys a failed order and a report the customer cannot act on.
const HOST_RE = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const MAX_HOSTS = 64;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * The custom hostnames attached to one deployment, with the platform's failure semantics.
 *
 * `previous` is what this box last knew, and it is what comes back when the relay cannot be
 * reached - the caller passes its own record rather than this module keeping a cache, so there is
 * exactly one copy of the truth and it lives with the lease.
 *
 * `report` is an array of {hostname, ...status} to deliver; the caller clears what was delivered
 * on a successful fetch (`delivered` in the result says which).
 */
export async function fetchDomains({ id, endpoint, sign, base = "https://api.enclave.host",
                                     previous = [], report = [], log = () => {} }) {
  const idL = String(id || "").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(idL)) throw new Error(`domains: "${id}" is not a bytes32 deployment id`);
  // Stripped BEFORE signing: the relay strips the endpoint it verifies and builds its message from
  // the stripped form, so signing the unstripped spelling recovers the right key over the wrong
  // message and returns 403 wrong_operator - a refusal that reads like a stolen key.
  const ep = String(endpoint || "").replace(/\/+$/, "");
  if (!/^https?:\/\//.test(ep)) throw new Error("domains: endpoint must be this box's registered http(s) origin");
  if (typeof sign !== "function") throw new Error("domains: no operator sign function was passed");
  const api = String(base || "").trim().replace(/\/+$/, "");
  const keep = (why) => ({ hosts: [...previous], delivered: [], source: "kept", why });
  if (!api) return { hosts: [], delivered: [], source: "off" };

  let last = "";
  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt) await sleep(1000);
    const ts = Math.floor(Date.now() / 1000);
    const message = `enclave-domains-fetch:${idL}:${ep}:${ts}`;
    let opSig;
    try { opSig = String(await sign(message) || ""); }
    catch (e) { return keep(`the operator key would not sign the fetch: ${e.message}`); }
    if (!/^0x[0-9a-fA-F]{130}$/.test(opSig)) return keep("sign() did not return a 65-byte personal_sign hex");

    let r;
    try {
      r = await fetch(`${api}/v1/domains/fetch`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: idL, endpoint: ep, ts, opSig, ...(report.length ? { report } : {}) }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (e) { last = e.message; continue; }

    // AUTHORITATIVE none. Not an outage: a relay without the feature, or a deployment it does not
    // see, both mean this box should stop answering for names it may once have had.
    if (r.status === 503 || r.status === 404) return { hosts: [], delivered: [], source: "none" };
    if (r.status === 401 || r.status === 403) {
      // A wrong key or a wrong clock does not fix itself in a second, and retrying only burns the
      // relay's bucket. Keep what we had and say which, because both are fixed on THIS machine.
      let why = `HTTP ${r.status}`;
      try { const b = await r.json(); if (b?.message) why = b.message; } catch {}
      return keep(why + (r.status === 401 ? " (a clock more than 5 minutes out will do this)" : ""));
    }
    if (!r.ok) { last = `HTTP ${r.status}`; continue; }

    let b;
    try { b = await r.json(); } catch (e) { last = `unreadable answer: ${e.message}`; continue; }
    const seen = new Set();
    const hosts = (Array.isArray(b.domains) ? b.domains : [])
      .filter((h) => typeof h === "string")
      .map((h) => h.toLowerCase().replace(/\.+$/, ""))
      .filter((h) => HOST_RE.test(h) && !seen.has(h) && (seen.add(h), true))
      .slice(0, MAX_HOSTS);
    if (hosts.length !== (Array.isArray(b.domains) ? b.domains.length : 0))
      log(`domains: ${idL.slice(0, 10)} the relay listed ${(b.domains || []).length} name(s), ${hosts.length} usable`);
    return { hosts, delivered: report.map((x) => x.hostname), source: "relay" };
  }
  return keep(last || "the relay did not answer");
}

// ---- owner-committed names (an owner-committed startup package; no relay domain map) ---------------------------------
//
// The LEGACY path above is unchanged and is still what a legacy envelope uses: the relay's list, on the relay's word.
// A deployment started from an owner-committed package (shield-startup.mjs) takes its names from that package and from
// nowhere else, and a listed name is the OWNER'S CLAIM, not proof of control (network/owner-names.mjs, whose rules these
// are). A name is served only while a proof stands that whoever controls its DNS agrees: a WebPKI certificate for the
// name, chaining to the public roots, presented by THIS deployment's partition on exactly the TLS key the manager's
// readiness judge bound (proveNameControl). A CA issued it only after DNS validation. Proofs lapse after
// NAME_PROOF_TTL_MS and are re-made, never extended; a failed proof drops the name at once.
//
//   startup   the verified startup record (host.mjs rec.startup): its `names` are the package's, its `sha256` the package
//   prove     async (name) -> proof ({ name, notBefore, notAfter, ... }) or throws: the caller's real handshake through its
//             own forward path (host.mjs uses network/owner-names.mjs proveNameControl over the partition splice)
//   proofs    Map name -> proof, the caller's previous proofs FOR THIS PACKAGE (a new package starts empty)
// -> { hosts, proofs, refused: [{ hostname, why }], source: "owner-package" }
export const OWNER_NAME_PROOF_TTL_MS = 5 * 60_000;
export async function ownerCommittedDomains({ startup, prove, proofs = new Map(), now = Date.now, log = () => {} }) {
  if (!startup || !/^[0-9a-f]{64}$/.test(String(startup.sha256 || ""))) throw new Error("domains: owner names need a verified startup package");
  if (typeof prove !== "function") throw new Error("domains: owner names need a name-control prover");
  const names = (Array.isArray(startup.names) ? startup.names : []).filter((h) => typeof h === "string" && HOST_RE.test(h) && ownerHost(h)).slice(0, MAX_HOSTS);
  const next = new Map(), refused = [];
  for (const h of names) {
    const old = proofs.get(h), t = now();
    if (old && old.provedAt + OWNER_NAME_PROOF_TTL_MS > t && old.notAfter > t) { next.set(h, old); continue; }
    try {
      const p = await prove(h);
      if (!p || p.name !== h || !(p.notAfter > now())) throw new Error("the proof is not for this name now");
      next.set(h, { ...p, provedAt: now() });
    } catch (e) { refused.push({ hostname: h, why: String(e.message || e).slice(0, 200) }); }
  }
  if (refused.length) log(`domains: owner-committed name(s) not proven: ${refused.map((r) => `${r.hostname} (${r.why})`).join("; ")}`);
  return { hosts: [...next.keys()], proofs: next, refused, source: "owner-package" };
}
