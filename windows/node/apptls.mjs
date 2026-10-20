// windows/node/apptls.mjs -- the app's OWN hostname, with a real certificate.
//
// Application HTTPS arrives through an Enclave-network provider and the circuit's ingress worker,
// which routes its SNI to /x/<id>/https without terminating the TLS session.
// The lease holder answers with the application certificate.
//
// This module is the certificate half: a P-256 key, a PKCS#10 request for it, and the relay's
// issuance route (relay/certs.js), which issues for the platform's own zones to whichever box
// holds the deployment's live lease, authorized by the operator signature that the registry entry
// names. No certificate authority account, no DNS credentials and no fleet secret on this box.
//
// WHERE THE KEY LIVES, stated because it is the one thing here that is weaker than the platform's
// own boxes: in this process, in VTL0, not in the enclave. A confidential VM mints its app-zone
// key inside the measured guest, so the machine's operator cannot read the app's TLS session. Here
// the operator can, and so can anything with administrator rights on this PC. That matches what
// this box already publishes about app traffic (`apps.traffic: "carried by the host"`) - the /x/
// path is carried in the clear by this same process - and it is reported in /availability as
// appTls.keyIn so nobody has to infer it. Moving it into VTL1 needs a TLS server inside the
// enclave and is the next piece of work, not a line of copy.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/** The label the platform gives a deployment's origin: the first 8 hex of its id (domains.js). */
export const labelFor = (id) => {
  const s = String(id).toLowerCase();
  return s.startsWith("0x") ? s.slice(2, 10) : s.replace(/^dep[-_]/, "");
};
export const appHostFor = (id, zone = "app.enclave.host") => `${labelFor(id)}.${zone}`;

// ---- just enough DER to ask for a certificate ------------------------------------------------
// Node can generate a key and sign, but it cannot build a PKCS#10 request, and the relay's route
// refuses anything that is not exactly {CN == name, SAN == [name]} on a P-256 or RSA-2048 key. So
// the request is assembled here, byte by byte. It is a few dozen lines of tag-length-value and it
// only has to produce ONE shape, which is why it is written out rather than pulled from a library.
const tlv = (tag, body) => {
  const b = Buffer.isBuffer(body) ? body : Buffer.from(body);
  if (b.length < 0x80) return Buffer.concat([Buffer.from([tag, b.length]), b]);
  const len = [];
  for (let n = b.length; n > 0; n = Math.floor(n / 256)) len.unshift(n % 256);
  return Buffer.concat([Buffer.from([tag, 0x80 | len.length]), Buffer.from(len), b]);
};
const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
const set = (...parts) => tlv(0x31, Buffer.concat(parts));
const int = (n) => tlv(0x02, Buffer.from([n]));
/** A positive INTEGER from bytes, minimally encoded: leading zeros stripped, and ONE added back
 *  only when the high bit would otherwise make it negative. DER requires exactly that, and a
 *  spare zero byte is rejected as "asn1 encoding routines::illegal padding" - intermittently,
 *  since whether it happens depends on the first byte of a random serial. */
const intBytes = (buf) => {
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0) i++;
  const b = buf.subarray(i);
  return tlv(0x02, b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b);
};
const utf8 = (s) => tlv(0x0c, Buffer.from(s, "utf8"));
const ia5 = (s) => tlv(0x16, Buffer.from(s, "ascii"));
const octets = (b) => tlv(0x04, b);
/** A BIT STRING. `unused` is the number of trailing bits in the last byte that are NOT part of the
 *  value: zero for an opaque blob like a signature, but five for a KeyUsage whose highest bit set
 *  is bit 2 - and getting that wrong is rejected as "asn1 encoding routines::illegal padding" by
 *  the TLS stack that later tries to load the certificate. */
const bits = (b, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), b]));
const ctx0 = (b) => tlv(0xa0, b);
/** An OID from dotted form: the first two arcs pack into one byte, the rest are base-128. */
const oid = (dotted) => {
  const a = dotted.split(".").map(Number);
  const out = [40 * a[0] + a[1]];
  for (const v of a.slice(2)) {
    const chunk = [v & 0x7f];
    for (let n = v >> 7; n > 0; n >>= 7) chunk.unshift((n & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
};
const OID_CN = "2.5.4.3", OID_SAN = "2.5.29.17", OID_EXT_REQ = "1.2.840.113549.1.9.14";
const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";

/**
 * A P-256 key and a PKCS#10 request for `name`, with the SAN the route demands.
 *
 * Returns the request in PEM (what the route parses), the key in PEM (what the TLS server needs)
 * and the sha256 of the key's SubjectPublicKeyInfo, which is what BOTH the signature and the
 * relay's own parse bind the name to: a captured signature cannot be re-presented with a different
 * key, because the relay derives that hash from the request it parsed.
 */
export function makeCsr(name) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  const subject = seq(set(seq(oid(OID_CN), utf8(name))));
  // attributes [0]: one extensionRequest carrying one subjectAltName with one dNSName
  const san = seq(tlv(0x82, Buffer.from(name, "ascii")));
  const extensions = seq(seq(oid(OID_SAN), octets(san)));
  const attributes = ctx0(seq(oid(OID_EXT_REQ), set(extensions)));
  const info = seq(int(0), subject, spki, attributes);
  const signature = crypto.sign("sha256", info, privateKey);      // DER ECDSA, as X.509 wants
  const csr = seq(info, seq(oid(OID_ECDSA_SHA256)), bits(signature));
  const pem = (label, der) =>
    `-----BEGIN ${label}-----\n${der.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "")}\n-----END ${label}-----\n`;
  return {
    csrPem: pem("CERTIFICATE REQUEST", csr),
    keyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    spkiHash: crypto.createHash("sha256").update(spki).digest("hex"),
  };
}

/**
 * Ask the relay to issue for `name`, holding this box's lease on `id`.
 *
 * 202 is not a failure: the route answers it while an order is in flight or paced, with the
 * seconds to wait, and the caller comes back. Every other non-200 is reported with the relay's own
 * words, because they name the thing to fix on this box (an unregistered endpoint, a lease that is
 * not ours, a clock outside ±600s).
 */
export async function requestCert({ name, csrPem, spkiHash, endpoint, sign, base = "https://api.enclave.host" }) {
  // "" is a host with no certificate service (independent mode without RELAY_BASE): say so, sign nothing, ask nobody.
  if (!String(base || "").trim()) return { ok: false, error: "no_certificate_service", why: "no certificate service is configured on this host" };
  const ts = Math.floor(Date.now() / 1000);
  const ep = String(endpoint).replace(/\/+$/, "");
  // The relay builds this message from what IT parsed, so the pieces are signed in the spelling it
  // will use: the name lowercased, the endpoint without a trailing slash, the hash of the key in
  // the request.
  const message = `enclave-certs-issue:${name}:${ep}:${spkiHash}:${ts}`;
  const opSig = await sign(message);
  const r = await fetch(`${base.replace(/\/+$/, "")}/v1/certs/issue`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ name, csr: csrPem, endpoint: ep, ts, opSig }),
    signal: AbortSignal.timeout(60_000),
  });
  const text = await r.text();
  let body = {}; try { body = JSON.parse(text || "{}"); } catch {}
  if (r.status === 200 && body.certPem) return { ok: true, certPem: body.certPem, notAfter: body.notAfter, ca: body.ca, cached: !!body.cached };
  if (r.status === 202) return { ok: false, retryAfterSec: Number(body.retryAfterSec) || 60, why: "the relay is still getting it" };
  return { ok: false, error: body.error || `http_${r.status}`, why: body.message || text.slice(0, 200) };
}

const RENEW_BEFORE_MS = 21 * 24 * 3600 * 1000;      // a 90-day certificate, renewed with a third left

/**
 * The certificate for this deployment's origin, from disk or from the relay.
 *
 * On disk beside the agent, because it must survive a restart: re-asking on every boot would burn
 * the CA's rate limit for the same name and leave the app unreachable in the meantime. The key is
 * written with the file, which is the exposure this module's header is about.
 */
export async function ensureCert({ id, endpoint, sign, base, dir, zone = "app.enclave.host",
                                  hostname = null, log = () => {} }) {
  // `hostname` is a CUSTOM DOMAIN the deployment's owner attached and the relay has proven for it
  // (relay/domains.js). Everything below is identical for either kind of name - the certificate
  // service authorizes both, one because the platform owns the zone and the other because the
  // owner proved the DNS - so the only thing that changes is which name is asked for and where the
  // key is filed. Absent, this is the app's own subdomain exactly as before.
  const name = hostname ? String(hostname).toLowerCase().replace(/\.+$/, "") : appHostFor(id, zone);
  // An explicit "" is a host with no certificate service: refused before a key is minted or a file written for an order
  // that can never be placed. (undefined is the legacy default service, as before.)
  if (base !== undefined && !String(base || "").trim()) throw new Error(`no_certificate_service: no certificate service is configured on this host, so ${name} keeps its fallback certificate`);
  // One file per NAME, not per deployment: a deployment with three hostnames has three keys and
  // three orders in flight, and filing them together would have each one overwrite the last -
  // which is the orphaned-order failure this function's next comment exists to prevent.
  const slug = hostname ? `${labelFor(id)}-${name.replace(/[^a-z0-9.-]/g, "_")}` : labelFor(id);
  const file = path.join(dir, `apptls-${slug}.json`);
  let have = null;
  try { have = JSON.parse(fs.readFileSync(file, "utf8")); } catch {}
  if (have && have.name === name && have.certPem && have.keyPem
      && new Date(have.notAfter).getTime() - Date.now() > RENEW_BEFORE_MS) {
    return { name, key: have.keyPem, cert: have.certPem, notAfter: have.notAfter, source: "disk" };
  }
  // ONE KEY, kept until the certificate for it exists. This is not an optimisation: the relay
  // caches and de-duplicates an order by (name, key), so asking again with a FRESH key starts
  // another ACME order and orphans the one already running. Retrying that way never finishes -
  // every attempt answers "order in flight" for an order whose result is filed under a key this
  // side has already thrown away. So the request is made once and re-presented verbatim.
  let pending = have && have.name === name && have.keyPem && have.csrPem && have.spkiHash ? have : null;
  if (!pending) {
    const made = makeCsr(name);
    pending = { name, keyPem: made.keyPem, csrPem: made.csrPem, spkiHash: made.spkiHash, asked: new Date().toISOString() };
    try { fs.writeFileSync(file, JSON.stringify(pending, null, 1), { mode: 0o600 }); } catch (e) { log(`certificate: could not save the key: ${e.message}`); }
    log(`certificate: asking the relay for ${name}`);
  } else {
    log(`certificate: asking again for ${name} with the same key`);
  }
  const r = await requestCert({ name, csrPem: pending.csrPem, spkiHash: pending.spkiHash, endpoint, sign, base });
  if (!r.ok) {
    const e = new Error(r.error ? `${r.error}: ${r.why}` : r.why);
    e.retryAfterSec = r.retryAfterSec;
    throw e;
  }
  const rec = { ...pending, certPem: r.certPem, notAfter: r.notAfter, ca: r.ca, at: new Date().toISOString() };
  try { fs.writeFileSync(file, JSON.stringify(rec, null, 1), { mode: 0o600 }); } catch (e) { log(`certificate: could not save it: ${e.message}`); }
  log(`certificate: ${name} issued by ${r.ca || "the relay"}, valid to ${r.notAfter}`);
  return { name, key: pending.keyPem, cert: r.certPem, notAfter: r.notAfter, source: "relay" };
}

// ---- the fallback pair -----------------------------------------------------------------------
// Until the real certificate exists there has to be SOMETHING to answer the handshake with, or a
// connection dies at the first byte and the failure looks like a broken box rather than a
// certificate that has not arrived. The platform's own boxes do the same ("the origin serves the
// self-signed fallback pair" - site/components/deployments): a browser shows a warning, the
// console's padlock stays amber, and the operator can still prove the path end to end with a
// client that is told to skip verification.
//
// It is a real X.509, built the same way as the request above, because there is no other way to
// make one with only node's crypto: no library, no openssl on the box.
const OID_SHA256_ECDSA = "1.2.840.10045.4.3.2";
const OID_BASIC = "2.5.29.19", OID_KU = "2.5.29.15", OID_EKU = "2.5.29.37", OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

/** DER time: UTCTime while the year fits two digits, which it will for any validity we set. */
const utcTime = (d) => {
  const p = (n) => String(n).padStart(2, "0");
  const s = `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(s, "ascii"));
};
const bool = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
const ctx3 = (b) => tlv(0xa3, b);

/** A self-signed P-256 certificate for `name`, valid for a week: long enough to be useful, short
 *  enough that one left behind is not a liability. */
export function selfSigned(name, days = 7) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  const dn = seq(set(seq(oid(OID_CN), utf8(name))));
  const now = new Date(Date.now() - 60_000);                  // a minute of slack for clock skew
  const extensions = ctx3(seq(
    seq(oid(OID_BASIC), octets(seq())),                       // basicConstraints: not a CA
    // digitalSignature (bit 0) | keyEncipherment (bit 2): 1010_0000, so the last five bits of the
    // byte are padding and must be declared as such.
    seq(oid(OID_KU), bool(true), octets(bits(Buffer.from([0xa0]), 5))),
    seq(oid(OID_EKU), octets(seq(oid(OID_SERVER_AUTH)))),
    seq(oid(OID_SAN), octets(seq(tlv(0x82, Buffer.from(name, "ascii"))))),
  ));
  const serial = intBytes(crypto.randomBytes(8));
  const tbs = seq(
    tlv(0xa0, int(2)),                                        // version v3
    serial,
    seq(oid(OID_SHA256_ECDSA)),
    dn, seq(utcTime(now), utcTime(new Date(now.getTime() + days * 86400_000))), dn,
    spki, extensions,
  );
  const sig = crypto.sign("sha256", tbs, privateKey);
  const der = seq(tbs, seq(oid(OID_SHA256_ECDSA)), bits(sig));
  const pem = (label, d) =>
    `-----BEGIN ${label}-----\n${d.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "")}\n-----END ${label}-----\n`;
  return { name, key: privateKey.export({ type: "pkcs8", format: "pem" }), cert: pem("CERTIFICATE", der),
           notAfter: new Date(now.getTime() + days * 86400_000).toISOString(), selfSigned: true };
}
