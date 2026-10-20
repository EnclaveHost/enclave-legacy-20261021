// The custody v2 daemon's HTTP surface (custody/v2/daemon.mjs serves exactly this handler; the tunnel agent forwards the
// relay's /t/<name>/... here, or the operator's own ingress does). Extracted from daemon.mjs unchanged - the same routes,
// order, rate limit, 256 KiB body bound and error mapping - so tests drive the real router over real HTTP. One change: the
// client key is the TCP peer, not a client-chosen x-forwarded-for (see clientKeyFor).
//
// Added: the Shield host-session routes (custody/v2/shield-evidence.mjs, shield-operator.mjs), ONLY when the custodian has
// the measured Shield adapter installed; without it they are exactly an unknown route (404). Their bounds:
//   .../challenge  the ordinary 256 KiB body bound;
//   .../attest     the measured limits.maxAttestBytes (it carries the host's raw TCG boot log), refused by Content-Length
//                  before anything is read and counted while streaming; at most limits.maxConcurrentAttests read or
//                  verified at once (503 before reading); the whole body within attestReadMs (408 after).
import net from "node:net";
import { Refusal } from "./custodian.mjs";
import { rateLimiter } from "../custodian.mjs";
import { SHIELD_ROUTE_PREFIX } from "./shield-operator.mjs";

export const MAX_BODY = 262144;
export const MAX_TRUSTED_PROXIES = 4;

// THE CLIENT KEY (rate limit, and the release-challenge count per client). By default the TCP peer, never a header: a
// client chooses its own x-forwarded-for. Every custodian connection arrives from the host's forwarder (the QEMU port
// forward's 10.0.2.2 in direct mode, the in-guest tunnel agent's 127.0.0.1), so the default is ONE bucket shared by all
// clients. An image measured with trustedProxies (build: --trusted-proxy) reads x-forwarded-for ONLY from those peers,
// and then only its RIGHTMOST entry: the address that proxy itself saw (Caddy's reverse_proxy sets it). A trusted
// proxy chooses buckets, which is availability only; the host can deny service anyway.
const PRIVATE_V4 = [[127, 0, 0, 0, 8], [10, 0, 0, 0, 8], [172, 16, 0, 0, 12], [192, 168, 0, 0, 16]];
const normalizeIp = (a) => String(a || "").toLowerCase().replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/, "");
function privateLiteral(ip) {
  if (net.isIPv4(ip)) {
    const n = ip.split(".").reduce((x, o) => x * 256 + Number(o), 0);
    return PRIVATE_V4.some(([a, b, c, d, bits]) => { const base = ((a * 256 + b) * 256 + c) * 256 + d, size = 2 ** (32 - bits); return n >= base && n < base + size; });
  }
  if (!net.isIPv6(ip)) return false;
  if (ip === "::1") return true;
  const first = parseInt(ip.split(":")[0] || "0", 16);
  return (first & 0xfe00) === 0xfc00;                                            // fc00::/7, unique local
}
/** -> the normalized list (throws): 0..4 distinct loopback or private IP literals; no hostnames, ranges or public addresses. */
export function validateTrustedProxies(list) {
  if (!Array.isArray(list) || list.length > MAX_TRUSTED_PROXIES) throw new Error(`trusted proxies: at most ${MAX_TRUSTED_PROXIES} IP literals`);
  const out = list.map((x) => {
    const ip = normalizeIp(x);
    if (typeof x !== "string" || !net.isIP(ip)) throw new Error(`trusted proxies: ${JSON.stringify(x)} is not an IP literal`);
    if (!privateLiteral(ip)) throw new Error(`trusted proxies: ${ip} is not a loopback or private address (the host's own forwarder)`);
    return ip;
  });
  if (new Set(out).size !== out.length) throw new Error("trusted proxies: repeated address");
  return out;
}
export function clientKeyFor(trustedProxies = []) {
  const trusted = new Set(validateTrustedProxies(trustedProxies));
  return (req) => {
    const peer = normalizeIp(req.socket.remoteAddress) || "-";
    if (!trusted.has(peer)) return peer.slice(0, 64);
    const last = normalizeIp(String(req.headers["x-forwarded-for"] || "").split(",").pop().trim());
    return net.isIP(last) ? last : peer.slice(0, 64);
  };
}
export const ATTEST_READ_MS = 60_000;

const json = (res, code, body, headers = {}) => { res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store", ...headers }); res.end(JSON.stringify(body)); };

// -> Buffer, or null after answering 413 (or 408 past `deadlineMs`; the rest of the body is discarded and the connection
// closed). Settles on every outcome - end, error, the deadline, or the client going away mid-body - so a caller's
// concurrency slot is always given back.
function readBody(req, res, cap, deadlineMs = 0) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0, settled = false, timer = null;
    const settle = (fn, v) => { if (!settled) { settled = true; if (timer) clearTimeout(timer); fn(v); } };
    if (deadlineMs > 0) timer = setTimeout(() => {
      if (settled) return;
      chunks.length = 0;
      json(res, 408, { error: "too_slow", message: "The body did not arrive in time." }, { connection: "close" });
      settle(resolve, null);
    }, deadlineMs);
    req.on("data", (ch) => {
      if (settled) return;
      n += ch.length;
      if (n > cap) { chunks.length = 0; json(res, 413, { error: "too_large", message: "Body too large." }, { connection: "close" }); settle(resolve, null); return; }
      chunks.push(ch);
    });
    req.on("end", () => settle(resolve, Buffer.concat(chunks)));
    req.on("error", (e) => settle(reject, e));
    req.on("close", () => settle(reject, new Error("the request ended before its body")));
  });
}

/**
 * createCustodyRouter({ custodian, member, runIndependent, servedCommittee, policyMode, chainId, vault, rate, attestReadMs, trustedProxies })
 *   custodian       createCustodianV2(...) (its shieldChallenge / shieldAttest / shieldLimits exist only with the adapter)
 *   member          createMember(...)
 *   runIndependent  createIndependentService(...)
 *   servedCommittee () -> committee id | null
 *   attestReadMs    the whole Shield attest body must arrive within this (default 60 s): a client trickling bytes holds a
 *                   concurrency slot for at most this long, not for Node's 300 s request timeout
 *   trustedProxies  MEASURED.trustedProxies (default none): the peers whose x-forwarded-for names the client (clientKeyFor)
 * -> async (req, res)
 */
export function createCustodyRouter({ custodian, member, runIndependent, servedCommittee, policyMode = null, chainId, vault, rate = rateLimiter(), attestReadMs = ATTEST_READ_MS, trustedProxies = [] }) {
  const clientOf = clientKeyFor(trustedProxies);
  const shieldOn = typeof custodian.shieldChallenge === "function" && typeof custodian.shieldAttest === "function";
  const limits = shieldOn ? custodian.shieldLimits : null;
  if (shieldOn && !(limits && Number.isSafeInteger(limits.maxAttestBytes) && Number.isSafeInteger(limits.maxConcurrentAttests)))
    throw new Error("custody router: the Shield adapter carries no measured limits");
  let attesting = 0;

  async function shieldRoute(res, route, body) {
    try { return json(res, 200, await (route === "challenge" ? custodian.shieldChallenge(body) : custodian.shieldAttest(body))); }
    catch (e) {
      if (e instanceof Refusal) throw e;
      const status = Number.isInteger(e?.status) && e.status >= 400 && e.status < 600 ? e.status : 422;
      return json(res, status, { error: "shield_session", message: String(e?.message || e).slice(0, 300) });
    }
  }

  return async (req, res) => {
    const u = new URL(req.url, "http://x");
    const client = clientOf(req);
    let held = false;
    try {
      if (req.method === "GET" && (u.pathname === "/health" || u.pathname === "/")) return json(res, 200, { ok: true, role: "custodian-v2" });
      if (req.method === "GET" && u.pathname === "/v2/custody/info") return json(res, 200, { ...member.info(servedCommittee()), chainId, vault,
                                                                                         independentAdmission: policyMode || null,
        ...(shieldOn ? { shieldRecipients: { tier: "hv-node/T0-hv", hostExcluded: false, party: custodian.encKeyHex, path: SHIELD_ROUTE_PREFIX } } : {}) });
      if (req.method !== "POST") return json(res, 405, { error: "method_not_allowed", message: "POST only." });
      if (!rate(client)) return json(res, 429, { error: "rate_limited", message: "Too many requests; retry shortly." });
      const attest = shieldOn && u.pathname === `${SHIELD_ROUTE_PREFIX}/attest`;
      let cap = MAX_BODY;
      if (attest) {
        cap = limits.maxAttestBytes;
        const declared = req.headers["content-length"];
        if (declared !== undefined && !(Number(declared) <= cap)) return json(res, 413, { error: "too_large", message: "Body too large." }, { connection: "close" });
        if (attesting >= limits.maxConcurrentAttests) return json(res, 503, { error: "busy", message: "Too many Shield host attestations in progress; retry shortly." }, { connection: "close" });
        attesting++; held = true;
      }
      const raw = await readBody(req, res, cap, attest ? attestReadMs : 0);
      if (raw === null) return;
      let body; try { body = JSON.parse(raw.toString("utf8") || "{}"); } catch { return json(res, 400, { error: "bad_json", message: "Body must be JSON." }); }
      if (shieldOn && u.pathname === `${SHIELD_ROUTE_PREFIX}/challenge`) return await shieldRoute(res, "challenge", body);
      if (attest) return await shieldRoute(res, "attest", body);
      switch (u.pathname) {
        case "/v2/custody/challenge": return json(res, 200, custodian.challenge({ client }));
        case "/v2/custody/release": return json(res, 200, await custodian.release(body));
        case "/v2/custody/evidence": return json(res, 200, await member.evidence(String(body.nonce || "")));
        case "/v2/custody/join": return json(res, 200, await member.join(body, servedCommittee()));
        case "/v2/custody/approve": return json(res, 200, await member.approve({ ...body, next: body.next || [] }));
        case "/v2/custody/host-binding": return json(res, 200, await member.setHostSig(String(body.sig || "")));
        case "/v2/custody/independent-genesis": return json(res, 200, await runIndependent(body));
        case "/v2/custody/code-approve": return json(res, 200, await member.approveCode({ committeeId: String(body.committeeId || servedCommittee() || ""),
                                                                                         measurement: String(body.measurement || ""), add: body.add, permit: body.permit }));
        default: return json(res, 404, { error: "not_found", message: "Unknown custody route." });
      }
    } catch (e) {
      if (res.headersSent) return;
      if (e instanceof Refusal) return json(res, e.status, { error: e.code, message: e.message });
      return json(res, 422, { error: "refused", message: String(e.message).slice(0, 300) });
    } finally { if (held) attesting--; }
  };
}
