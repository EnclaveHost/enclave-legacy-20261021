// Authoritative Enclave DNS. Application A/AAAA and raw-port SRV answers come
// only from unexpired, operator-signed Enclave-network routes joined to live leases
// and host admission in the configured validating directory. There is no wildcard or legacy relay fallback.
// DNS-01 TXT challenges and the box control namespace remain available.
//
// IP_ZONE, APP_ZONE and NS_NAME are required. Optional TCP_ZONE preserves its
// authority and DNS-01 records. BOX_ZONE and BOX_A/BOX_AAAA serve control names.
// ROUTE_MAP_URL defaults to https://api.enclave.host/v1/network/routes.
// NET_POLL_SEC controls refresh (default 15). DNS_PORT defaults to 53,
// DNS_API_PORT to 8153; DNS_API_BIND restricts the challenge API listener.
// DNS_BIND is a comma-separated IP list; unset preserves the dual-stack wildcard.
// DNS_READ_ONLY=1 serves route answers without fleet discovery or challenge writes;
// it requires an explicit ROUTE_MAP_URL and cannot serve the box control zone.
// DNS_TXT_KEY is HMAC-SHA256(fleet SECRET, 'enclave dns-txt v1') as hex, never
// the raw fleet secret. TXT_TTL_SEC caps challenges (default 600).
// Fleet discovery (REGISTRY_ADDRESS or ENCLAVES, BASE_RPC) authenticates DNS-01
// pushes. DNS_RL_CAP/DNS_RL_PER_SEC bound per-source response rates.
// DNS_CHALLENGE_AUTH=attested runs an independent DNS-01 responder for direct
// guests' owner-committed names instead (relay/dns-challenge-attested.mjs): it
// serves only CHALLENGE_ZONE (plus NS_NAME/NS_NAMES), and writes a TXT value only
// for a push signed by a measured guest's attested key. It needs no fleet,
// registry, HMAC key, route map or eligibility API, and refuses to start with any
// of them configured, so nothing can fall back to them. ATTESTED_MEASUREMENTS
// pins the launch measurements it accepts; ATTESTED_MIN_TCB requires a firmware
// floor; ATTESTED_KDS=0 never contacts AMD KDS (the guest must carry its VCEK);
// ATTESTED_JUDGE_MODE=lab-unsigned is an explicit lab diagnostic without the AMD
// chain, stated on /health. ATTESTED_SHIELD_POLICY separately admits Enclave
// Shield (T0-hv) guests; it needs ATTESTED_SHIELD_PROFILE (+ _DIGEST, the
// reviewed authority profile whose registry pin binds code and schema) and
// ATTESTED_SHIELD_RPCS (two or more distinct hosts, one agreed block).
// ATTESTED_PUSH_READ_MS bounds a push body's arrival (default 10 s).
// This is an authoritative server, not a recursive resolver.

import dgram from "node:dgram";
import net from "node:net";
import http from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
import { createFleet, fleetConfig, fetchJson, installProcessGuards } from "./fleet.mjs";
import { isBoxHost } from "./boxhost.js";
import { authorizePush, parseMeasurements } from "./dns-challenge-attested.mjs";
import { createShieldChallengeAuth, isShieldPush, shieldRegistryBinding, shieldRegistryEntry } from "./dns-challenge-shield.mjs";
installProcessGuards("dns-relay");

const need = (k) => { const v = (process.env[k] || "").trim(); if (!v) { console.error(`fatal: ${k} is required`); process.exit(1); } return v; };
const fqdn = (s) => s.trim().toLowerCase().replace(/\.+$/, "");
const READ_ONLY = process.env.DNS_READ_ONLY === "1";
if (READ_ONLY && (!(process.env.ROUTE_MAP_URL || "").trim() || process.env.BOX_ZONE)) {
  console.error("fatal: DNS_READ_ONLY requires explicit ROUTE_MAP_URL and no BOX_ZONE");
  process.exit(1);
}
const ATTESTED = process.env.DNS_CHALLENGE_AUTH === "attested";
const NO_FALLBACK = ["DNS_READ_ONLY", "IP_ZONE", "APP_ZONE", "TCP_ZONE", "BOX_ZONE", "APP_STATIC", "ROUTE_MAP_URL", "DNS_TXT_KEY",
  "SECRET", "REGISTRY_ADDRESS", "ENCLAVES", "ENCLAVE_URL", "ELIGIBILITY_API", "DOMAINS_API", "ADDRESS_BOOK_ADDRESS", "BASE_RPC"];
if ((process.env.DNS_CHALLENGE_AUTH && !ATTESTED) || (ATTESTED && NO_FALLBACK.some((k) => (process.env[k] || "").trim()))) {
  console.error(`fatal: DNS_CHALLENGE_AUTH=attested serves only CHALLENGE_ZONE; unset ${NO_FALLBACK.join(", ")}`);
  process.exit(1);
}

const CFG = fleetConfig();
if (!READ_ONLY && !ATTESTED && !CFG.registryAddress && !CFG.staticList.length) {
  console.error("fatal: set REGISTRY_ADDRESS (on-chain discovery) or ENCLAVES (static list)");
  process.exit(1);
}
const fleet     = READ_ONLY || ATTESTED ? null : createFleet(CFG, (m) => console.log("[dns-relay]", m));
const IP_ZONE   = ATTESTED ? null : fqdn(need("IP_ZONE"));
const APP_ZONE  = ATTESTED ? null : fqdn(need("APP_ZONE"));
const CHALLENGE_ZONE = ATTESTED ? fqdn(need("CHALLENGE_ZONE")) : null;
let ATTEST = null;
if (ATTESTED) {
  const mode = process.env.ATTESTED_JUDGE_MODE || "trusted";
  const minTcb = (process.env.ATTESTED_MIN_TCB || "").trim();
  try {
    if (!["trusted", "lab-unsigned"].includes(mode)) throw new Error("ATTESTED_JUDGE_MODE must be trusted or lab-unsigned");
    if (CHALLENGE_ZONE.length > 204 || CHALLENGE_ZONE.split(".").length < 2 ||
        CHALLENGE_ZONE.split(".").some((l) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) throw new Error("CHALLENGE_ZONE must be a DNS zone of at most 204 bytes");
    // ATTESTED_SHIELD_POLICY (dns-challenge-shield.mjs): an explicit, separate opt-in for Enclave Shield (T0-hv) guests,
    // with its own TPM roots, platforms and image pairs, and a chain reader for host identity. Without it nothing but
    // SEV-SNP evidence is accepted, and ATTESTED_MEASUREMENTS stays required.
    const shieldFile = (process.env.ATTESTED_SHIELD_POLICY || "").trim();
    ATTEST = { mode, measurements: process.env.ATTESTED_MEASUREMENTS || !shieldFile ? parseMeasurements(process.env.ATTESTED_MEASUREMENTS) : new Set(),
               kds: process.env.ATTESTED_KDS !== "0",
               ...(minTcb ? { minTcb: JSON.parse(minTcb) } : {}), judge: (await import("../isolation/m2/judge.mjs")).judge };
    if (shieldFile) Object.assign(ATTEST, await shieldAuthFromEnv(shieldFile));
    const pushRead = Number(process.env.ATTESTED_PUSH_READ_MS || 10_000);
    if (!Number.isSafeInteger(pushRead) || pushRead < 1000 || pushRead > 60_000) throw new Error("ATTESTED_PUSH_READ_MS must be an integer in 1000..60000");
    ATTEST.pushReadMs = pushRead;
  } catch (e) { console.error(`fatal: ${e.message}`); process.exit(1); }
  if (mode !== "trusted") console.error("[dns-relay] ATTESTED_JUDGE_MODE=lab-unsigned: the AMD chain is NOT verified; lab diagnostic only");
}
// The Shield opt-in's inputs: the policy file, the reviewed authority profile the operator pins by digest
// (ATTESTED_SHIELD_PROFILE + ATTESTED_SHIELD_PROFILE_DIGEST; network/authority-profile.mjs refuses any other bytes) whose
// registry pin - address, runtime code hash and length, registrySchema - every host-identity read is judged against at
// its own agreed block, and ATTESTED_SHIELD_RPCS (two or more RPCs on distinct hosts; windows/node/host-identity.mjs
// quorumReader). ATTESTED_SHIELD_PINS, the strict contract-pin document, is optional; given, it must name the same
// registry. No address book, fleet, relay or default RPC is consulted.
async function shieldAuthFromEnv(file) {
  const fs = await import("node:fs");
  const { validateContractPins } = await import("../network/contract-pins.mjs");
  const { parseProfile } = await import("../network/authority-profile.mjs");
  const { quorumReader, rpcClients } = await import("../windows/node/host-identity.mjs");
  const { recoverMessageAddress } = await import("viem");
  const policy = JSON.parse(fs.readFileSync(file, "utf8"));
  const profileFile = (process.env.ATTESTED_SHIELD_PROFILE || "").trim(), digest = (process.env.ATTESTED_SHIELD_PROFILE_DIGEST || "").trim();
  if (!profileFile || !digest) throw new Error("ATTESTED_SHIELD_POLICY needs ATTESTED_SHIELD_PROFILE and ATTESTED_SHIELD_PROFILE_DIGEST (the reviewed registry pin)");
  const { profile, digest: profileDigest } = parseProfile(fs.readFileSync(profileFile), { expectedDigest: digest });
  const binding = shieldRegistryBinding(profile);
  if ((process.env.ATTESTED_SHIELD_PINS || "").trim()) {
    const pins = validateContractPins(JSON.parse(fs.readFileSync(process.env.ATTESTED_SHIELD_PINS, "utf8").replace(/^\uFEFF/, "")));
    if (pins.registry !== binding.address) throw new Error("ATTESTED_SHIELD_PINS names another registry than the reviewed profile");
  }
  const reader = quorumReader({ clients: await rpcClients(String(process.env.ATTESTED_SHIELD_RPCS || "").split(",").map((x) => x.trim()).filter(Boolean)) });
  const shield = createShieldChallengeAuth({ policy, zone: CHALLENGE_ZONE, registryEntry: shieldRegistryEntry({ reader, binding }),
    recoverSigner: (message, signature) => recoverMessageAddress({ message, signature }), log: (m) => console.log(m) });
  return { shield, shieldRegistry: { address: binding.address, schema: binding.schema, codeHash: binding.codeHash, profileDigest } };
}
// zone 3 (optional): the SNI relay's TLS namespace — same wildcard-to-one-box
// shape as the app zone, delegated here so in-enclave ACME can answer dns-01
// for <label>.tcp.* names too. Unset = zone off (Cloudflare keeps serving it).
const TCP_ZONE  = process.env.TCP_ZONE ? fqdn(process.env.TCP_ZONE.trim()) : null;
// zone 4 (optional): self-hosted ENCLAVES, one wildcard name per box
// (e<16hex>.box.enclave.host — relay/boxhost.js). Delegated here for the same
// reason as the app zone: the box answers dns-01 itself and holds its own
// certificate, which is what lets a client's TLS terminate AT the box instead
// of at the relay. Without that the quote's reportData binds a key the client
// never saw and attestation cannot complete. Unset = zone off.
const BOX_ZONE  = process.env.BOX_ZONE ? fqdn(process.env.BOX_ZONE.trim()) : null;
const NS_NAME   = fqdn(need("NS_NAME"));
// Every replica publishes the same complete delegation, so resolvers do not
// cache only the one server that happened to answer their last query.
const NS_NAMES = [...new Set(process.env.NS_NAMES?.trim()
  ? process.env.NS_NAMES.split(",").map(fqdn) : [NS_NAME])];
if (!NS_NAMES.length || NS_NAMES.length > 8 || NS_NAMES.some(n => !n || n.length > 253 ||
    n.split(".").some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)))) {
  console.error("fatal: NS_NAMES must name 1..8 valid DNS names");
  process.exit(1);
}
// hostmaster at the NS name's parent (ns1.enclave.host -> hostmaster.enclave.host)
const RNAME     = "hostmaster." + (NS_NAME.includes(".") ? NS_NAME.slice(NS_NAME.indexOf(".") + 1) : NS_NAME);
const DNS_PORT  = parseInt(process.env.DNS_PORT || "53", 10);
const DNS_BINDS = process.env.DNS_BIND
  ? [...new Set(process.env.DNS_BIND.split(",").map((v) => v.trim()).filter(Boolean))]
  : ["::"];
if (!DNS_BINDS.length || DNS_BINDS.some((address) => !net.isIP(address))) {
  console.error("fatal: DNS_BIND must contain IP addresses");
  process.exit(1);
}
const API_PORT  = parseInt(process.env.DNS_API_PORT || "8153", 10);
const API_BIND  = process.env.DNS_API_BIND || undefined;
// The enclave signs TXT pushes with a DERIVED key, NOT the raw fleet SECRET:
//   DNS_TXT_KEY = HMAC-SHA256(fleet SECRET, "enclave dns-txt v1")  (hex, 64 chars)
// (see supervisor.js's DNS_TXT_KEY). Set DNS_TXT_KEY to that derived hex.
// `SECRET` stays as a DEPRECATED fallback (it was mislabeled "the fleet secret"
// but always had to hold the derived key for a push to verify).
let TXT_KEY = READ_ONLY || ATTESTED ? "" : (process.env.DNS_TXT_KEY || "").trim();
if (!READ_ONLY && !TXT_KEY && (process.env.SECRET || "").trim()) {
  TXT_KEY = process.env.SECRET.trim();
  console.error("[dns-relay] SECRET is DEPRECATED — rename it to DNS_TXT_KEY. Its value must be the DERIVED key HMAC(fleet SECRET,'enclave dns-txt v1') hex, never the raw fleet SECRET.");
}
if (TXT_KEY && !/^[0-9a-f]{64}$/i.test(TXT_KEY)) {
  // A raw fleet SECRET (the JWT signing secret) would never verify a push — the
  // enclave signs with the 64-hex derived key — so fail CLOSED rather than 401
  // every push and look like an auth bug.
  console.error("[dns-relay] DNS_TXT_KEY is not a 64-hex derived key (looks like a raw fleet secret) — DISABLING the challenge-push API. Set DNS_TXT_KEY = HMAC(SECRET,'enclave dns-txt v1') hex.");
  TXT_KEY = "";
}
const TXT_TTL_S = parseInt(process.env.TXT_TTL_SEC || "600", 10);
// Per-source DNS response rate limit (fix 11): an authoritative server is a
// reflection/amplification vector, so cap responses per client IP. Generous —
// real resolvers burst but stay well under this.
const DNS_RL_CAP = parseInt(process.env.DNS_RL_CAP || "200", 10);
const DNS_RL_PER_SEC = parseInt(process.env.DNS_RL_PER_SEC || "50", 10);
function makeRateLimiter(cap, perSec) {
  const buckets = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (now - b.at > 300_000) buckets.delete(k); }, 60_000).unref?.();
  return (key) => {
    const now = Date.now();
    let b = buckets.get(key);
    if (!b) { b = { tokens: cap, at: now }; buckets.set(key, b); }
    b.tokens = Math.min(cap, b.tokens + ((now - b.at) / 1000) * perSec); b.at = now;
    if (b.tokens < 1) return false; b.tokens -= 1; return true;
  };
}
const dnsRate = makeRateLimiter(DNS_RL_CAP, DNS_RL_PER_SEC);
const POLL_MS   = parseInt(process.env.NET_POLL_SEC || "15", 10) * 1000;
const SERIAL    = Math.floor(Date.now() / 1000);   // SOA serial: process start
const NEG_TTL   = 60;      // SOA MINIMUM = negative-cache TTL (RFC 2308)
const UDP_MAX   = 1232;    // the EDNS-era safe UDP payload; beyond it -> TC

// ---- address parsing (text -> RDATA bytes) ---------------------------------

function ipv4Bytes(s) {
  const p = s.split(".");
  if (p.length !== 4) return null;
  const b = Buffer.alloc(4);
  for (let i = 0; i < 4; i++) {
    if (!/^\d{1,3}$/.test(p[i]) || +p[i] > 255) return null;
    b[i] = +p[i];
  }
  return b;
}

function ipv6Bytes(s) {
  s = s.split("%")[0];
  // embedded v4 tail (::ffff:1.2.3.4) -> two trailing hex groups
  const m = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (m) {
    const v4 = ipv4Bytes(m[2]);
    if (!v4) return null;
    s = m[1] + ((v4[0] << 8) | v4[1]).toString(16) + ":" + ((v4[2] << 8) | v4[3]).toString(16);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let groups = head;
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = [...head, ...Array(fill).fill("0"), ...tail];
  }
  if (groups.length !== 8) return null;
  const b = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i])) return null;
    b.writeUInt16BE(parseInt(groups[i], 16), i * 2);
  }
  return b;
}

const BOX_A = process.env.BOX_A ? ipv4Bytes(process.env.BOX_A.trim()) : null;
const BOX_AAAA = process.env.BOX_AAAA ? ipv6Bytes(process.env.BOX_AAAA.trim()) : null;

// Unexpired per-app routes. Failed refreshes retain the last map only until
// each record's signed expiry; queries never revive an expired address.
let deployments = [];

const ROUTE_MAP_URL = (process.env.ROUTE_MAP_URL || "https://api.enclave.host/v1/network/routes").trim();
const ROUTE_TTL = 15;
let appRoutes = new Map();   // label -> { a: Buffer|null, aaaa: Buffer|null, relay: string }
const SHRINK_CONFIRM_MS = Number(process.env.ROUTE_SHRINK_CONFIRM_MS || 12_000);
let shrinkSince = null;

async function pollRouteMap() {
  if (!ROUTE_MAP_URL) return;
  const j = await fetchJson(ROUTE_MAP_URL);
  if (!j || !j.labels || typeof j.labels !== "object") {
    console.error(`[dns-relay] route map poll failed: ${ROUTE_MAP_URL} (keeping ${appRoutes.size} label(s))`);
    return;
  }
  const next = new Map();
  for (const [label, v] of Object.entries(j.labels)) {
    if (!/^[0-9a-z]{1,63}$/.test(label) || !v || typeof v !== "object") continue;
    const addresses=Array.isArray(v.addresses)?v.addresses.slice(0,2):[v.a,v.aaaa].filter(Boolean);
    const a=addresses.map(value=>ipv4Bytes(String(value))).filter(Boolean);
    const aaaa=addresses.map(value=>ipv6Bytes(String(value))).filter(Boolean);
    if (!a.length && !aaaa.length) continue;                 // no current provider address
    if (!Number.isSafeInteger(v.expiresAt) || v.expiresAt <= Date.now()) continue;
    next.set(label, { a, aaaa, expiresAt: v.expiresAt, relay: "enclave-network" });
  }
  // A map that suddenly loses most labels is the relay restarting, not the apps going away (2026-10-14: a relay deploy
  // served 0, then 5, then 9 labels within 9 s; then 1, 7, 9): from that drop, every label it dropped is kept for
  // SHRINK_CONFIRM_MS while the relay fills its map again; whatever is still missing after that is dropped. A held
  // label keeps its own signed expiry, so nothing is served past what the relay signed.
  if (shrinkSince === null && appRoutes.size >= 2 && next.size * 2 < appRoutes.size) {
    shrinkSince = Date.now();
    console.warn(`[dns-relay] route map dropped to ${next.size} label(s); keeping the previous ${appRoutes.size} for ${SHRINK_CONFIRM_MS / 1000} s`);
  }
  if (shrinkSince !== null) {
    if (Date.now() - shrinkSince < SHRINK_CONFIRM_MS) {
      for (const [label, v] of appRoutes) if (!next.has(label) && v.expiresAt > Date.now()) next.set(label, v);
    } else shrinkSince = null;
  }
  if (next.size !== appRoutes.size) console.log(`[dns-relay] route map: ${next.size} routed label(s)`);
  deployments = Object.entries(j.deployments || {}).filter(([id, d]) => /^0x[0-9a-f]{64}$/.test(id)
    && d.address && Number.isSafeInteger(d.expiresAt) && d.expiresAt > Date.now())
    .map(([id, d]) => ({hex: id.slice(2), address: d.address, expiresAt: d.expiresAt, tcp: (d.tcp || []).map(p => p.publicPort)}));
  appRoutes = next;
}

async function poll() { await pollRouteMap(); }

// ---- challenge store (zone 2's TXT) ----------------------------------------

// Bounded on both axes. A TXT set is authorized (fleet HMAC, or an operator's
// on-chain lease) but authorization is not a quantity: an authorized pusher can
// mint one entry per distinct VALUE, and every value under a name is answered
// in the same response. Unbounded, that is both a memory sink and a first-class
// amplification vector — one 50-byte TCP query returning megabytes of TXT. Two
// concurrent orders per name is the real ACME shape; 8 leaves room to spare,
// and the name cap covers the ~57 distinct id-prefix labels one deployment can
// legitimately produce, times a fleet's worth of deployments.
const MAX_TXT_NAMES = 2048, MAX_TXT_VALUES = 8;
const txtStore = new Map();   // name -> Map(value -> expiresAtMs); several values = concurrent orders

function txtValues(name) {
  const vals = txtStore.get(name);
  if (!vals) return [];
  const now = Date.now();
  for (const [v, exp] of vals) if (exp <= now) vals.delete(v);
  if (!vals.size) { txtStore.delete(name); return []; }
  return [...vals.keys()];
}

setInterval(() => { for (const name of [...txtStore.keys()]) txtValues(name); }, 30_000);

// ---- DNS wire encoding ------------------------------------------------------

const T  = { A: 1, NS: 2, SOA: 6, TXT: 16, AAAA: 28, SRV: 33, OPT: 41, ANY: 255 };
const RC = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n & 0xffff); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };

function encodeName(name) {
  const out = [];
  for (const label of name.split(".").filter(Boolean)) {
    const b = Buffer.from(label, "latin1");
    if (b.length > 63) throw new Error("label too long");
    out.push(Buffer.from([b.length]), b);
  }
  out.push(Buffer.from([0]));
  return Buffer.concat(out);
}

const rr = (name, type, ttl, rdata) =>
  Buffer.concat([encodeName(name), u16(type), u16(1 /* IN */), u32(ttl), u16(rdata.length), rdata]);

const soaRR = (zone) => rr(zone, T.SOA, NEG_TTL, Buffer.concat([
  encodeName(NS_NAME), encodeName(RNAME),
  u32(SERIAL), u32(3600), u32(600), u32(604800), u32(NEG_TTL)]));
const nsRR  = (zone, name) => rr(zone, T.NS, 300, encodeName(name));
const srvRR = (name, port, target) =>
  rr(name, T.SRV, 60, Buffer.concat([u16(0), u16(0), u16(port), encodeName(target)]));

function txtRR(name, value) {
  const data = Buffer.from(value, "utf8");
  const parts = [];   // TXT rdata = character-strings, each <= 255 bytes
  for (let i = 0; i === 0 || i < data.length; i += 255) {
    const chunk = data.subarray(i, i + 255);
    parts.push(Buffer.from([chunk.length]), chunk);
  }
  return rr(name, T.TXT, 30, Buffer.concat(parts));
}

// minimal EDNS echo: root name, type OPT, class = our max UDP payload
const OPT_RR = Buffer.concat([Buffer.from([0]), u16(T.OPT), u16(UDP_MAX), u32(0), u16(0)]);

// ---- resolution -------------------------------------------------------------

// answer shape: { rcode, aa, an, au, ad } — arrays of pre-encoded RRs. NODATA
// and NXDOMAIN carry the zone SOA in AUTHORITY so resolvers can cache negatives.
const HIT    = (an, ad = []) => ({ rcode: RC.NOERROR,  aa: true, an, au: [], ad });
const NODATA = (zone) => ({ rcode: RC.NOERROR,  aa: true, an: [], au: [soaRR(zone)], ad: [] });
const NXDOM  = (zone) => ({ rcode: RC.NXDOMAIN, aa: true, an: [], au: [soaRR(zone)], ad: [] });
const EMPTY  = (rcode) => ({ rcode, aa: false, an: [], au: [], ad: [] });

function apex(zone, qtype) {
  const an = [];
  if (qtype === T.SOA || qtype === T.ANY) an.push(soaRR(zone));
  if (qtype === T.NS  || qtype === T.ANY) an.push(...NS_NAMES.map(name => nsRR(zone, name)));
  return an.length ? HIT(an) : NODATA(zone);
}

function resolveIp(qname, qtype) {
  if (qname === IP_ZONE) return apex(IP_ZONE, qtype);
  const sub = qname.slice(0, -(IP_ZONE.length + 1));
  const m = /^(?:_minecraft\._tcp\.)?([^.]+)$/.exec(sub);
  if (!m) return NXDOM(IP_ZONE);
  const wantSrv = sub !== m[1];
  const hex = m[1].replace(/^dep[-_]/, "");
  if (!/^[0-9a-f]{8,64}$/.test(hex)) return NXDOM(IP_ZONE);
  const hits = deployments.filter((d) => d.expiresAt > Date.now() && d.hex.startsWith(hex));
  if (hits.length !== 1) return NXDOM(IP_ZONE);   // unknown or ambiguous prefix
  const d = hits[0];
  const v6 = ipv6Bytes(d.address), v4 = ipv4Bytes(d.address);
  if (wantSrv) {
    if ((qtype !== T.SRV && qtype !== T.ANY) || !d.tcp.length) return NODATA(IP_ZONE);
    const target = m[1] + "." + IP_ZONE;
    return HIT([srvRR(qname, d.tcp[0], target)], v6 ? [rr(target, T.AAAA, 15, v6)] : v4 ? [rr(target, T.A, 15, v4)] : []);
  }
  const an = [];
  if ((qtype === T.A || qtype === T.ANY) && v4) an.push(rr(qname, T.A, 15, v4));
  if ((qtype === T.AAAA || qtype === T.ANY) && v6) an.push(rr(qname, T.AAAA, 15, v6));
  return an.length ? HIT(an) : NODATA(IP_ZONE);
}

function resolveWildcard(qname, qtype, zone, a4, a6) {
  if (qname === zone) return apex(zone, qtype);
  const an = [];
  if ((qtype === T.A    || qtype === T.ANY) && a4) an.push(rr(qname, T.A,    300, a4));
  if ((qtype === T.AAAA || qtype === T.ANY) && a6) an.push(rr(qname, T.AAAA, 300, a6));
  if ((qtype === T.TXT  || qtype === T.ANY) && qname.startsWith("_acme-challenge."))
    for (const value of txtValues(qname)) an.push(txtRR(qname, value));
  return an.length ? HIT(an) : NODATA(zone);   // wildcard zone: every name exists
}

// Zone 2. One deployment label deep (<label>.APP_ZONE) MAY have chosen its own
// relay; everything else in the zone — the apex, _acme-challenge TXT, any
// deeper name — is the wildcard exactly as before.
//
// A chosen label answers ONLY from that relay's own addresses. If the relay
// declares no IPv6 the AAAA is NODATA rather than the zone-wide one: falling
// back per family would hand every v6-preferring client to the DEFAULT relay
// while v4 clients used the chosen one, which is not a fallback but a silent
// half-undo of the choice, and the hardest kind of routing bug to see.
// APP_STATIC="label=1.2.3.4,label2=5.6.7.8": fixed A records for platform services that share the zone (the secret
// custodians, docs/security/secret-custody.md). A label must contain a non-hex character, so it can never be a deployment
// label (those are hex), and it answers before the route map.
const APP_STATIC = new Map(String(process.env.APP_STATIC || "").split(",").map((x) => x.trim()).filter(Boolean)
  .map((x) => x.split("=").map((y) => y.trim().toLowerCase()))
  .filter(([l, a]) => /^[a-z0-9-]{1,63}$/.test(l || "") && /[g-z-]/.test(l) && ipv4Bytes(a || ""))
  .map(([l, a]) => [l, ipv4Bytes(a)]));
function resolveApp(qname, qtype) {
  if (qname === APP_ZONE) return apex(APP_ZONE, qtype);
  if (qname.startsWith("_acme-challenge.")) return resolveWildcard(qname, qtype, APP_ZONE, null, null);
  const sub = qname.slice(0, -(APP_ZONE.length + 1));
  const fixed = sub.includes(".") ? null : APP_STATIC.get(sub);
  if (fixed) return (qtype === T.A || qtype === T.ANY) ? HIT([rr(qname, T.A, 300, fixed)]) : NODATA(APP_ZONE);
  // Routes govern addresses only. In particular, CAA must answer NODATA so
  // the CA can check the parent policy before a guest has a serving route.
  // SERVFAIL here creates a cycle: no certificate -> no route -> no certificate.
  if (qtype !== T.A && qtype !== T.AAAA && qtype !== T.ANY) return NODATA(APP_ZONE);
  const pick = sub.includes(".") ? null : appRoutes.get(sub);
  // A replica without a current verified deployment route cannot assert that
  // the name has no address. SERVFAIL lets recursive resolvers try another
  // authority instead of caching a transient verification gap as NODATA.
  if (!pick || pick.expiresAt <= Date.now()) return (pick || /^[0-9a-f]{8}$/.test(sub)) ? EMPTY(RC.SERVFAIL) : NODATA(APP_ZONE);
  const an = [];
  const ttl=Math.min(ROUTE_TTL,Math.max(0,Math.floor((pick.expiresAt-Date.now())/1000)));
  if (qtype === T.A || qtype === T.ANY) for(const address of pick.a) an.push(rr(qname,T.A,ttl,address));
  if (qtype === T.AAAA || qtype === T.ANY) for(const address of pick.aaaa) an.push(rr(qname,T.AAAA,ttl,address));
  return an.length ? HIT(an) : NODATA(APP_ZONE);
}

function answer(q) {
  if (q.opcode !== 0) return EMPTY(RC.NOTIMP);
  if (q.qclass !== 1 && q.qclass !== T.ANY) return EMPTY(RC.REFUSED);
  if (ATTESTED) return q.qname === CHALLENGE_ZONE || q.qname.endsWith("." + CHALLENGE_ZONE)
    ? resolveWildcard(q.qname, q.qtype, CHALLENGE_ZONE, null, null) : EMPTY(RC.REFUSED);
  if (q.qname === IP_ZONE  || q.qname.endsWith("." + IP_ZONE))  return resolveIp(q.qname, q.qtype);
  if (q.qname === APP_ZONE || q.qname.endsWith("." + APP_ZONE)) return resolveApp(q.qname, q.qtype);
  if (TCP_ZONE && (q.qname === TCP_ZONE || q.qname.endsWith("." + TCP_ZONE)))
    return resolveWildcard(q.qname, q.qtype, TCP_ZONE, null, null);
  if (BOX_ZONE && (q.qname === BOX_ZONE || q.qname.endsWith("." + BOX_ZONE)))
    return resolveWildcard(q.qname, q.qtype, BOX_ZONE, BOX_A, BOX_AAAA);
  return EMPTY(RC.REFUSED);   // not our zone — we're authoritative, not a resolver
}

// ---- DNS wire parsing / response assembly -----------------------------------

// -> { id, opcode, rd, qname, qtype, qclass, questionRaw, hadOpt } or null.
// questionRaw is the question section verbatim, echoed back so the client's
// case survives; qname is lowercased for matching.
function parseQuery(msg) {
  if (msg.length < 12) return null;
  const flags = msg.readUInt16BE(2);
  if (flags & 0x8000) return null;                   // a response, not a query
  if (msg.readUInt16BE(4) !== 1) return null;        // exactly one question
  const counts = msg.readUInt16BE(6) + msg.readUInt16BE(8) + msg.readUInt16BE(10);
  let off = 12;
  const labels = [];
  for (;;) {                                          // QNAME: plain labels only
    if (off >= msg.length) return null;
    const len = msg[off];
    if (len === 0) { off++; break; }
    if (len & 0xc0) return null;                     // no compression in a question
    if (off + 1 + len > msg.length || labels.length > 63) return null;
    labels.push(msg.toString("latin1", off + 1, off + 1 + len));
    off += 1 + len;
  }
  if (off + 4 > msg.length) return null;
  const qtype = msg.readUInt16BE(off);
  const qclass = msg.readUInt16BE(off + 2);
  off += 4;
  const questionRaw = msg.subarray(12, off);
  // walk the remaining records only to spot an EDNS OPT (its content is ignored)
  let hadOpt = false, p = off;
  for (let i = 0; i < counts && p < msg.length; i++) {
    for (;;) {                                        // skip the owner name
      if (p >= msg.length) break;
      const l = msg[p];
      if (l === 0) { p++; break; }
      if (l & 0xc0) { p += 2; break; }
      p += 1 + l;
    }
    if (p + 10 > msg.length) break;
    if (msg.readUInt16BE(p) === T.OPT) hadOpt = true;
    p += 10 + msg.readUInt16BE(p + 8);
  }
  return { id: msg.readUInt16BE(0), opcode: (flags >> 11) & 0xf, rd: !!(flags & 0x100),
           qname: labels.join(".").toLowerCase(), qtype, qclass, questionRaw, hadOpt };
}

function header(q, r, tc, an, au, ad) {
  const b = Buffer.alloc(12);
  b.writeUInt16BE(q.id, 0);
  b.writeUInt16BE(0x8000 | ((q.opcode & 0xf) << 11) | (r.aa ? 0x0400 : 0)
    | (tc ? 0x0200 : 0) | (q.rd ? 0x0100 : 0) | (r.rcode & 0xf), 2);
  b.writeUInt16BE(1, 4);                              // the echoed question
  b.writeUInt16BE(an, 6); b.writeUInt16BE(au, 8); b.writeUInt16BE(ad, 10);
  return b;
}

// build the response; `limit` (UDP only) trips TC: records are dropped, the
// client retries over TCP and gets the whole thing there.
function buildResponse(q, r, limit) {
  const ad = q.hadOpt ? [...r.ad, OPT_RR] : r.ad;
  const msg = Buffer.concat([header(q, r, false, r.an.length, r.au.length, ad.length),
                             q.questionRaw, ...r.an, ...r.au, ...ad]);
  if (!limit || msg.length <= limit) return msg;
  const keep = q.hadOpt ? [OPT_RR] : [];
  return Buffer.concat([header(q, r, true, 0, 0, keep.length), q.questionRaw, ...keep]);
}

// one query in, one response (or null to stay silent) — never throws.
function handle(msg, limit) {
  let q;
  try { q = parseQuery(msg); } catch { return null; }
  if (!q) return null;
  let r;
  try { r = answer(q); } catch { r = EMPTY(RC.SERVFAIL); }
  try { return buildResponse(q, r, limit); } catch { return null; }
}

// ---- transports: UDP + TCP on DNS_PORT ---------------------------------------

for (const address of DNS_BINDS) {
const ipv6Only = net.isIP(address) === 6 && address !== "::";
const udp = dgram.createSocket({ type: net.isIP(address) === 4 ? "udp4" : "udp6", ipv6Only });
let udpUp = false;
udp.on("error", (e) => { console.error("[dns-relay] udp:", e.message); if (!udpUp) process.exit(1); });
udp.on("message", (msg, rinfo) => {
  if (!dnsRate(rinfo.address)) return;                 // per-source RL (fix 11): drop, don't reflect
  const out = handle(msg, UDP_MAX);
  if (out) udp.send(out, rinfo.port, rinfo.address, () => {});
});
udp.bind(DNS_PORT, address, () => { udpUp = true; console.log(`[dns-relay] udp ${address}:${DNS_PORT}`); });

const tcp = net.createServer((sock) => {
  sock.setTimeout(15_000, () => sock.destroy());
  sock.on("error", () => sock.destroy());
  const peer = sock.remoteAddress || "unknown";
  let buf = Buffer.alloc(0);
  sock.on("data", (d) => {
    buf = buf.length ? Buffer.concat([buf, d]) : d;
    for (;;) {                                        // 2-byte length framing; may carry several queries
      if (buf.length < 2) return;
      const len = buf.readUInt16BE(0);
      if (buf.length < 2 + len) return;
      const query = buf.subarray(2, 2 + len);
      buf = buf.subarray(2 + len);
      if (!dnsRate(peer)) continue;                   // per-source RL (fix 11)
      const out = handle(query, 0);
      if (out) sock.write(Buffer.concat([u16(out.length), out]));
    }
  });
});
tcp.on("error", (e) => { console.error("[dns-relay] tcp:", e.message); process.exit(1); });
tcp.listen({ port: DNS_PORT, host: address, ipv6Only }, () => console.log(`[dns-relay] tcp ${address}:${DNS_PORT}`));
}

// ---- challenge-push HTTP API --------------------------------------------------

if (!TXT_KEY && !ATTESTED) console.error("[dns-relay] DNS_TXT_KEY unset — fleet-HMAC pushes answer 503 (operator-signed pushes still verify on-chain)");

// hex HMAC-SHA256 over the RAW body with the DERIVED DNS_TXT_KEY (NOT the raw
// fleet SECRET — the enclave derives HMAC(SECRET,'enclave dns-txt v1')), constant-time
function checkSig(sig, raw) {
  if (typeof sig !== "string" || !/^[0-9a-fA-F]{64}$/.test(sig)) return false;
  const want = createHmac("sha256", TXT_KEY).update(raw).digest();
  const got = Buffer.from(sig, "hex");
  return got.length === want.length && timingSafeEqual(want, got);
}

// Permissionless auth (metal/PROTOCOL.md): a SELLER box holds no fleet secret,
// so instead it signs the raw body (EIP-191) with its on-chain operator key and
// the push authorizes exactly the subdomain of a deployment that operator
// PROVABLY leases right now — verified against the EnclaveDeployments ledger,
// never against another relay's word (a relay box must not be able to mint
// certs). Strictly narrower than the fleet HMAC (which authorizes any name):
// per-deployment authority, anchored on chain, replay-bounded by the mandatory
// ts. Returns null when authorized, else a reason string.
// This path is UNAUTHENTICATED until the recover+ledger check completes, and
// the check is expensive: a cache-busting re-read pages the whole ledger over
// RPC. The generic DNS bucket (50/s) would let anyone with a well-formed
// signature turn the relay into an RPC hammer, so operator pushes get their own
// tight bucket, and the fresh re-read a global cooldown on top — a just-claimed
// lease needs ONE re-read, not one per attempt.
// Sized for the work, not for suspicion: an ACME push is rare per seller (one
// per issuance/renewal) and behind a fronting proxy every seller shares this
// bucket, so it must not be the thing that breaks a renewal wave. The real
// protection against the expensive path is the cooldown below.
const rlOperator = makeRateLimiter(30, 1);
const FRESH_COOLDOWN_MS = 5000;
let _lastFresh = 0;

let _recover = null;
async function operatorAuth(sig, raw, body, name) {
  if (!/^0x[0-9a-fA-F]{130}$/.test(String(sig))) return "malformed x-operator-sig";
  if (body?.ts == null) return "ts is required for operator-signed pushes";   // ±300s window enforced above
  const rest = name.slice("_acme-challenge.".length);

  // BOX ZONE: the name IS an enclave's own hostname, so authority is simply
  // "the operator that registered this endpoint" — no deployment involved.
  // Deliberately narrow: the signer must own THIS host, so a box can renew its
  // own certificate and no other box's, and a registry row for some unrelated
  // endpoint grants nothing here.
  if (BOX_ZONE && rest.endsWith("." + BOX_ZONE)) {
    const host = rest.slice(0, -(BOX_ZONE.length + 1)) + "." + BOX_ZONE;
    if (!isBoxHost(host, BOX_ZONE)) return "label is not a minted box name";
    // Registry lookup BEFORE the ECDSA recover: it is an in-memory map hit, and
    // it means an unauthenticated caller cannot make us do public-key crypto for
    // a name nobody has registered. What it reveals (whether a box is
    // registered) is already public on chain.
    const op = fleet.operatorForEndpoint(`https://${host}`);
    if (!op) return "no live registry entry for this box name";
    if (!_recover) _recover = (await import("viem")).recoverMessageAddress;
    let signer;
    try { signer = (await _recover({ message: raw.toString("utf8"), signature: sig })).toLowerCase(); }
    catch { return "signature does not recover"; }
    if (op !== signer) return "signer is not the operator registered for this box";
    return null;
  }

  const depId = String(body.deploymentId || "").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(depId)) return "deploymentId (bytes32) is required";
  // name is _acme-challenge.<label>.<zone>; the label must be a single hex
  // label that prefixes deploymentId — operator authority extends to the
  // subdomains of deployments it leases, nothing else (no apex, no nesting)
  const zone = rest.endsWith("." + APP_ZONE) ? APP_ZONE
             : (TCP_ZONE && rest.endsWith("." + TCP_ZONE) ? TCP_ZONE : null);
  if (!zone) return "name is outside the app/tcp zones";
  const label = rest.slice(0, -(zone.length + 1));
  if (!/^[0-9a-f]{8,64}$/.test(label)) return "label is not a deployment id hex prefix";
  if (!depId.slice(2).startsWith(label)) return "label is not a prefix of deploymentId";
  if (!_recover) _recover = (await import("viem")).recoverMessageAddress;
  let signer;
  try { signer = (await _recover({ message: raw.toString("utf8"), signature: sig })).toLowerCase(); }
  catch { return "signature does not recover"; }
  const ok = (l) => !!(l && l.id === depId && l.leaseLive && l.runnerOperator === signer);
  let lease = await fleet.leaseFor(depId);
  // a just-claimed lease can be behind the 10s row cache — one fresh re-read
  // before denying, at most once per cooldown across all callers
  if (!ok(lease) && Date.now() - _lastFresh > FRESH_COOLDOWN_MS) {
    _lastFresh = Date.now();
    lease = await fleet.leaseFor(depId, { fresh: true });
  }
  if (!ok(lease)) return "signer does not hold the live lease for this deployment";
  // U7: a dns-01 answer is a certificate for a tenant's name, so it is given only to a lease holder the api-relay holds
  // ELIGIBLE (fleet.eligibleId: its /enclaves verdict, fresh). The chain names the holder; it never makes it eligible.
  // (B) ...or an OWNER-ONLY hv-node the api relay lists as carrying THIS deployment (its owner consented to that host)
  if (!fleet.eligibleId(lease.runner) && !(typeof fleet.servesDeploymentId === "function" && fleet.servesDeploymentId(lease.runner, lease.id)))
    return "the lease holder is not an eligible host (U7): no dns-01 answer for its names";
  // the label must name ONLY this deployment: a prefix shared with another
  // ledger row authorizes neither holder (leaseFor is null on ambiguity)
  if (!(await fleet.leaseFor("0x" + label))) return "label does not uniquely name this deployment";
  return null;
}

// U7 on the fleet-HMAC path. The HMAC proves only "a holder of the fleet secret", never WHICH box (and on a metal box
// that secret sits in an operator-readable file), so for a name that belongs to an on-ledger deployment it authorizes a
// dns-01 answer only while that deployment has a live lease whose holder the api-relay holds ELIGIBLE, the bar the
// operator-signed path sets. A deployment name is read the way the api-relay routes it (depFromHost): one label under the
// app or tcp zone, "dep-"/"dep_" and "0x" stripped, 8-64 hex. Other names under those zones, and box-zone names (a box's
// own hostname), are not a tenant's and keep the HMAC's authority. Returns why not, or null.
async function hmacTenantRefusal(name) {
  const rest = name.slice("_acme-challenge.".length);
  const zone = rest.endsWith("." + APP_ZONE) ? APP_ZONE : (TCP_ZONE && rest.endsWith("." + TCP_ZONE) ? TCP_ZONE : null);
  if (!zone) return null;
  const label = rest.slice(0, -(zone.length + 1)).replace(/^dep[-_]/, "");
  const hex = label.startsWith("0x") ? label.slice(2) : label;
  if (!/^[0-9a-f]{8,64}$/.test(hex)) return null;
  let lease = await fleet.leaseFor("0x" + hex);
  if (!(lease && lease.leaseLive) && Date.now() - _lastFresh > FRESH_COOLDOWN_MS) {
    _lastFresh = Date.now();
    lease = await fleet.leaseFor("0x" + hex, { fresh: true });
  }
  if (!lease) return "the name is a deployment's, and no single on-ledger deployment (or no readable ledger) answers for it";
  if (!lease.leaseLive) return "the name's deployment has no live lease";
  // (B) an owner-only hv-node the api relay lists as carrying this deployment answers too (the platform's certificate for the
  // owner's own app on the host the owner chose); any other ineligible holder does not
  if (!fleet.eligibleId(lease.runner) && !(typeof fleet.servesDeploymentId === "function" && fleet.servesDeploymentId(lease.runner, lease.id)))
    return "the lease holder is not an eligible host (U7): no dns-01 answer for its names";
  return null;
}

// One guard around the whole handler. installProcessGuards turns any
// synchronous throw in a request listener into exit(1), and this daemon is the
// AUTHORITATIVE DNS for the app and ip zones — a single malformed request
// taking it down darkens every app hostname on the platform and stalls every
// in-flight ACME order until systemd restarts it. Answer 500 and stay up.
// (api-relay.js carries the same guard, for the same reason.)
const api = http.createServer((req, res) => {
  try { apiHandler(req, res); }
  catch (e) {
    console.error("[dns-relay] api handler threw:", (e && e.stack) || e);
    try { if (!res.headersSent) res.writeHead(500, { "content-type": "application/json" }); } catch {}
    try { res.end(JSON.stringify({ error: "internal_error" })); } catch {}
  }
});

function apiHandler(req, res) {
  const json = (code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
  // origin-form only, and appended to a base rather than resolved against one:
  // an absolute-form target would otherwise parse to a pathname this handler
  // routes on while naming somewhere else entirely
  if (!String(req.url || "").startsWith("/")) return json(400, { error: "bad_request_target" });
  const u = new URL("http://x" + req.url);

  if (req.method === "GET" && u.pathname === "/health") {
    let txtRecords = 0;
    for (const name of [...txtStore.keys()]) txtRecords += txtValues(name).length;
    if (ATTESTED) return json(200, { ok: true, mode: "attested", readOnly: false, zones: { challenge: CHALLENGE_ZONE },
      judgeMode: ATTEST.mode, minTcb: ATTEST.minTcb !== undefined, kds: ATTEST.kds, measurements: ATTEST.measurements.size, txtRecords,
      shield: ATTEST.shield ? { tier: "hv-node", hostExcluded: false, liveHostSessions: ATTEST.shield.sessions(), registry: ATTEST.shieldRegistry } : null });
    return json(200, { ok: true, readOnly: READ_ONLY, zones: { ip: IP_ZONE, app: APP_ZONE, tcp: TCP_ZONE, box: BOX_ZONE },
                       deployments: deployments.length, txtRecords,
                       routeLabels: appRoutes.size, routeMap: ROUTE_MAP_URL || null });
  }
  if (READ_ONLY) { req.resume(); return json(405, { error: "read_only", routes: ["GET /health"] }); }
  if (ATTESTED) return attestedPush(req, res, u, json);
  if (u.pathname !== "/v1/txt" || (req.method !== "POST" && req.method !== "DELETE"))
    return json(404, { error: "not_found", routes: ["GET /health", "POST /v1/txt", "DELETE /v1/txt"] });
  if (!dnsRate(req.socket?.remoteAddress || "unknown")) return json(429, { error: "rate_limited" });   // fix 11

  const chunks = []; let size = 0;
  req.on("data", (d) => { size += d.length; if (size > 65536) req.destroy(); else chunks.push(d); });
  req.on("error", () => {});
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    let body; try { body = JSON.parse(raw.toString("utf8")); } catch { return json(400, { error: "bad_json" }); }
    // replay protection (fix 11): if the SIGNED payload carries a timestamp,
    // reject stale/future pushes. Backward-compatible for the HMAC path —
    // pushes without `ts` are still accepted; operator-signed pushes REQUIRE it.
    if (body && body.ts != null) {
      const ts = Number(body.ts);
      if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 300)
        return json(401, { error: "stale", message: "push timestamp outside the ±300s window" });
    }
    const name = typeof body?.name === "string" ? fqdn(body.name) : "";
    const value = typeof body?.value === "string" ? body.value : "";
    const zoneOk = name.endsWith("." + APP_ZONE) || (TCP_ZONE && name.endsWith("." + TCP_ZONE))
                || (BOX_ZONE && name.endsWith("." + BOX_ZONE));
    if (!name.startsWith("_acme-challenge.") || !zoneOk || name.length > 253)
      return json(400, { error: "bad_name", message: "name must be _acme-challenge.<name> under the app, tcp or box zone" });
    if (!value || value.length > 1024) return json(400, { error: "bad_value" });
    // U7: never a challenge at a zone APEX. "_acme-challenge.<zone>" is the name a CA checks for a WILDCARD certificate over
    // the zone, i.e. for every deployment at once, eligible or not; nothing on the platform issues one (enclave-5d, round 6)
    if ([APP_ZONE, TCP_ZONE, BOX_ZONE].some((z) => z && name === "_acme-challenge." + z))
      return json(403, { error: "apex_refused", message: "no dns-01 answer at a zone apex: that would certify a wildcard over every name in the zone" });

    // auth: the fleet HMAC (any name), else an operator signature whose
    // authority is the on-chain lease for THIS deployment's subdomain only
    let authed = !!TXT_KEY && checkSig(req.headers["x-relay-sig"], raw);
    // U7: a new challenge value under the HMAC, for a deployment's name, needs that deployment's live, ELIGIBLE lease
    // holder (removing a value is not issuance and keeps the HMAC's authority)
    if (authed && req.method === "POST") {
      let why;
      try { why = await hmacTenantRefusal(name); } catch (e) { console.error(`[dns-relay] hmac tenant check error: ${e.message}`); why = "verification error"; }
      if (why) { console.log(`[dns-relay] txt POST ${name} under the fleet HMAC REFUSED: ${why}`); return json(403, { error: "hmac_auth_refused", message: why }); }
    }
    if (!authed && typeof req.headers["x-operator-sig"] === "string") {
      if (!rlOperator(req.socket?.remoteAddress || "unknown"))
        return json(429, { error: "rate_limited", message: "Too many operator-signed pushes; retry shortly." });
      let why;
      try { why = await operatorAuth(req.headers["x-operator-sig"], raw, body, name); }
      catch (e) { console.error(`[dns-relay] operator auth error: ${e.message}`); why = "verification error"; }
      if (why) return json(403, { error: "operator_auth_failed", message: why });
      authed = true;
      console.log(`[dns-relay] txt ${req.method} ${name} authorized by operator signature (lease ${String(body.deploymentId).slice(0, 10)}…)`);
    }
    if (!authed) return json(TXT_KEY ? 401 : 503, TXT_KEY ? { error: "bad_signature" }
      : { error: "no_key", message: "DNS_TXT_KEY is not configured on this relay (and no operator signature was presented)." });

    if (req.method === "POST") {
      let ttl = TXT_TTL_S;   // body ttlSec can only SHORTEN the cap, never extend it
      if (Number.isFinite(body.ttlSec) && body.ttlSec > 0) ttl = Math.min(ttl, body.ttlSec);
      const fresh = !txtStore.has(name);
      if (fresh && txtStore.size >= MAX_TXT_NAMES) {
        for (const n of [...txtStore.keys()]) txtValues(n);          // expire first, then refuse
        if (txtStore.size >= MAX_TXT_NAMES) {
          console.error(`[dns-relay] challenge store full (${txtStore.size} names) — refused ${name}`);
          return json(503, { error: "store_full", message: "Too many live challenges on this relay; retry shortly." });
        }
      }
      const vals = txtStore.get(name) || new Map();
      vals.set(value, Date.now() + ttl * 1000);
      // over the per-name cap, the value closest to expiry goes: the newest
      // challenge is the one being validated right now
      while (vals.size > MAX_TXT_VALUES) {
        let oldest = null, at = Infinity;
        for (const [v, exp] of vals) if (exp < at) { at = exp; oldest = v; }
        vals.delete(oldest);
      }
      txtStore.set(name, vals);
      console.log(`[dns-relay] txt set ${name} (${vals.size} value${vals.size === 1 ? "" : "s"}, ttl ${ttl}s)`);
      return json(200, { ok: true, name, values: vals.size, ttlSec: ttl });
    }
    const vals = txtStore.get(name);
    if (vals) { vals.delete(value); if (!vals.size) txtStore.delete(name); }
    return json(200, { ok: true, name, values: vals ? vals.size : 0 });
  });
}
// DNS_CHALLENGE_AUTH=attested: the only write path. Every push, set or delete, carries the full proof
// (dns-challenge-attested.mjs); a value is stored under the zone's per-name caps exactly like any other.
// Bounds: a per-peer rate, a 64 KiB body (declared or streamed: 413), a read deadline (408), and at most
// PUSH_MAX_INFLIGHT verifications at once across all peers (503 + retry-after). Every request is answered once.
const rlAttested = makeRateLimiter(30, 1);
const PUSH_MAX_BYTES = 65536, PUSH_MAX_INFLIGHT = 16;
let pushInflight = 0;
function attestedPush(req, res, u, json) {
  const send = (code, body, headers = {}) => {
    if (res.headersSent || res.destroyed) return;
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    json(code, body);
  };
  if (ATTEST.shield && u.pathname.startsWith("/v1/shield-session/")) {
    if (!rlAttested(req.socket?.remoteAddress || "unknown")) { req.resume(); return send(429, { error: "rate_limited" }); }
    ATTEST.shield.handle(req, res, json).then((handled) => {
      if (!handled) { req.resume(); send(404, { error: "not_found", routes: ["POST /v1/shield-session/challenge", "POST /v1/shield-session/attest"] }); }
    }, (e) => { console.error(`[dns-relay] shield session handler: ${e?.message || e}`); send(500, { error: "internal_error" }); });
    return;
  }
  if (u.pathname !== "/v1/txt" || (req.method !== "POST" && req.method !== "DELETE")) {
    req.resume();
    return send(404, { error: "not_found", routes: ["GET /health", "POST /v1/txt", "DELETE /v1/txt"] });
  }
  if (!rlAttested(req.socket?.remoteAddress || "unknown")) { req.resume(); return send(429, { error: "rate_limited" }); }
  const declared = req.headers["content-length"];
  if (declared !== undefined && !(Number(declared) <= PUSH_MAX_BYTES)) return send(413, { error: "body_too_large" }, { connection: "close" });
  if (pushInflight >= PUSH_MAX_INFLIGHT) return send(503, { error: "busy" }, { "retry-after": "1", connection: "close" });
  pushInflight++;
  let released = false, done = false;
  const release = () => { if (!released) { released = true; pushInflight--; } };
  const stop = () => { done = true; clearTimeout(timer); };
  const chunks = []; let size = 0;
  const timer = setTimeout(() => { if (done) return; stop(); release(); send(408, { error: "the push body did not arrive in time" }, { connection: "close" }); }, ATTEST.pushReadMs);
  req.on("data", (d) => {
    if (done) return;
    size += d.length;
    if (size > PUSH_MAX_BYTES) { stop(); release(); chunks.length = 0; return send(413, { error: "body_too_large" }, { connection: "close" }); }
    chunks.push(d);
  });
  req.on("error", () => { if (!done) { stop(); release(); } });
  req.on("close", () => { if (!done) { stop(); release(); } });     // the client went away before the body ended
  req.on("end", () => {
    if (done) return;
    stop();
    storePush(Buffer.concat(chunks), req, send)
      .catch((e) => { console.error(`[dns-relay] attested push: ${e?.message || e}`); send(500, { error: "internal_error" }); })
      .finally(release);
  });
}
async function storePush(raw, req, send) {
  // a Shield document is judged only by the operator's Shield opt-in; everything else only by the SNP path (each refuses the other's)
  const v = ATTEST.shield && isShieldPush(raw)
    ? await ATTEST.shield.authorize({ raw, sig: req.headers["x-attested-sig"], method: req.method })
    : await authorizePush({ raw, sig: req.headers["x-attested-sig"], method: req.method, zone: CHALLENGE_ZONE, ...ATTEST });
  if (!v.ok) { console.log(`[dns-relay] attested txt ${req.method} REFUSED: ${v.why}`); return send(v.status, { error: "attested_auth_refused", message: v.why }); }
  const name = v.name;
  if (v.op === "delete") {
    const vals = txtStore.get(name);
    if (vals) { vals.delete(v.value); if (!vals.size) txtStore.delete(name); }
    return send(200, { ok: true, name, values: vals ? vals.size : 0 });
  }
  if (!txtStore.has(name) && txtStore.size >= MAX_TXT_NAMES) {
    for (const n of [...txtStore.keys()]) txtValues(n);
    if (txtStore.size >= MAX_TXT_NAMES) return send(503, { error: "store_full", message: "Too many live challenges on this responder; retry shortly." });
  }
  const vals = txtStore.get(name) || new Map();
  vals.set(v.value, Date.now() + TXT_TTL_S * 1000);
  while (vals.size > MAX_TXT_VALUES) {
    let oldest = null, at = Infinity;
    for (const [x, exp] of vals) if (exp < at) { at = exp; oldest = x; }
    vals.delete(oldest);
  }
  txtStore.set(name, vals);
  console.log(`[dns-relay] attested txt set ${name} for ${v.deploymentId.slice(0, 10)}… (${v.verdict})`);
  return send(200, { ok: true, name, values: vals.size, ttlSec: TXT_TTL_S });
}

api.on("error", (e) => { console.error("[dns-relay] api:", e.message); process.exit(1); });
api.listen(API_PORT, API_BIND, () => console.log(`[dns-relay] challenge-push api :${API_PORT}`));

// ---- boot ---------------------------------------------------------------------

if (!READ_ONLY && !ATTESTED) { await fleet.start(); await fleet.startEligibility(); }
if (ATTESTED) console.log(`[dns-relay] attested DNS-01 responder for ${CHALLENGE_ZONE} (ns ${NS_NAME}); judge ${ATTEST.mode}, ${ATTEST.measurements.size} pinned measurement(s)`
  + (ATTEST.shield ? "; Enclave Shield (T0-hv, hostExcluded=false) guests accepted under ATTESTED_SHIELD_POLICY" : ""));
else {
await poll();
setInterval(poll, POLL_MS);
console.log(`[dns-relay] authoritative for ${IP_ZONE} + ${APP_ZONE}${TCP_ZONE ? " + " + TCP_ZONE : ""} (ns ${NS_NAME}, serial ${SERIAL}); ` +
            `refreshing allocations every ${POLL_MS / 1000}s` +
            (ROUTE_MAP_URL ? ` + per-app routes from ${ROUTE_MAP_URL}`
                           : "; route map unavailable"));
}
