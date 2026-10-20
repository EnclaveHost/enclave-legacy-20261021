// windows/node/release-channel.mjs -- the SIGNED Windows host release channel: an operator-selected release key (or keys,
// with a threshold) and operator-selected mirrors, both pinned on the host in a release policy.
//
// WHY. latest.json names each artifact with its sha256, but it comes from the same place as the artifacts: whoever can
// write that place writes both, and the hashes then prove only that the bytes are the ones the publisher (or the attacker)
// put there. A host that follows an unsigned latest.json runs whatever its download origin says within the minute. Here
// the hashes are trusted ONLY because they are inside a statement signed by a key the host's operator pinned; the
// manifest (and through it every delta file) is trusted only because its sha256 is in that statement. A mirror is a
// transport: it can withhold, delay or corrupt, and each of those is detected and routed around, never trusted.
//
// WHY ECDSA P-256 AND NOT Ed25519. Three programs check these signatures: this module (Node, the agent and the updater),
// EnclaveSetup.exe (C# on .NET Framework 4.8) and cli/host.ps1 (Windows PowerShell 5.1). .NET Framework has no Ed25519,
// and shipping our own curve arithmetic inside an installer is the kind of crypto that should not be written twice. P-256
// ECDSA over SHA-256 with a raw r||s signature is what CNG verifies natively (ECDsaCng, BCRYPT ECCPUBLICBLOB), and what
// Node verifies with dsaEncoding "ieee-p1363". One algorithm, three native verifiers, no bundled crypto.
//
// THE FILES (every name is relative to a mirror, which is a directory URL ending in "/"):
//   latest.signed.json             the envelope: {format, statement: base64(exact statement bytes), signatures: [{keyId, sig}]}
//   enclave-host-<v>.zip           the release, as before         EnclaveSetup-<v>.exe   its setup program
//   manifest-<v>.json              every file's sha256 (deltas)    files/<sha256>         one file of the release
//   latest.json                    the LEGACY unsigned pointer: read only by hosts without a policy; ignored here
// The signature covers SIGNING_CONTEXT followed by the statement's exact bytes: nothing is re-serialised before checking,
// and a key used for something else cannot be replayed as a Windows release.
//
// THE POLICY (ProgramData\Enclave\node\release-policy.json, SYSTEM and Administrators only; updates never write it):
//   {format, channel, keys: ["ecdsa-p256:<base64 SPKI DER>"...], threshold, mirrors: ["https://.../windows/"...]}
// Its presence switches the host to signed-only. There is no fallback: a host with a policy that cannot resolve a signed
// release does not update, and says why. No key in this file is Enclave's unless its operator chose to pin it.
//
// CLI (run by update-host.ps1 with the INSTALLED release's node and this INSTALLED file - never the download's):
//   node release-channel.mjs check-policy <policy.json>
//   node release-channel.mjs install-policy --policy <file> --dest <ProgramData\Enclave\node\release-policy.json> [--replace]
//   node release-channel.mjs resolve --policy <file> --installed <version> [--force] --out <result.json>
//   node release-channel.mjs download --policy <file> --list <items.json> [--deadline-sec N]   items: [{name, sha256, bytes, out}]
//   node release-channel.mjs statement --channel <c> --version <v> --zip <f> --setup <f> --manifest <f> [--valid-days N] --out <f>
//   node release-channel.mjs sign --statement <f> --key <pem> [--key <pem>...] --out <envelope>
//   node release-channel.mjs cosign --envelope <f> --key <pem> --out <envelope>
//   node release-channel.mjs pubkey --key <pem>                                 (the policy spec of a key the operator holds)
//   node release-channel.mjs verify --envelope <f> --channel <c> --key <pem|spec> [--key ...]   (all given keys must have signed)
// No command here creates a key: release keys are made and kept offline by whoever publishes (docs/network/independent-windows.md).
import fs from "node:fs";
import path from "node:path";
import { createHash, createPublicKey, createPrivateKey, randomBytes, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import { fileURLToPath } from "node:url";
import { newer } from "./update-watch.mjs";

export const POLICY_FORMAT = "enclave-windows-release-policy/v1";
export const STATEMENT_FORMAT = "enclave-windows-release/v1";
export const ENVELOPE_FORMAT = "enclave-windows-release-envelope/v1";
export const ENVELOPE_NAME = "latest.signed.json";
export const SIGNING_CONTEXT = Buffer.from("enclave-windows-release-signature/v1\n", "ascii");
// A P-256 public key in SubjectPublicKeyInfo DER is always these 27 bytes (ecPublicKey, prime256v1, BIT STRING, 0x04
// uncompressed) followed by X and Y: EnclaveSetup.cs and cli/host.ps1 slice X and Y at the same offsets.
export const P256_SPKI_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d03010703420004", "hex");
const KEY_PREFIX = "ecdsa-p256:";
const HEX64 = /^[0-9a-f]{64}$/;
const VERSION = /^\d{1,9}(\.\d{1,9}){1,3}$/;          // [System.Version]: 2 to 4 parts, which update-host.ps1 compares
const CHANNEL = /^[a-z0-9][a-z0-9._-]{0,31}$/;
export const LIMITS = Object.freeze({ envelope: 64 * 1024, statement: 16 * 1024, zip: 2 * 1024 ** 3, setup: 64 * 1024 ** 2,
                                      manifest: 16 * 1024 ** 2, file: 1024 ** 3, keys: 8, mirrors: 8 });
// Clock skew a statement's issuedAt may be ahead of this host by, before it is refused as not yet issued.
const FUTURE_SKEW_MS = 24 * 3600 * 1000;
// A download that trickles is cut off: each mirror gets 60 s plus the signed size at this rate (capped by timeoutMs), and
// the whole call (every mirror) ends at deadlineMs. EnclaveSetup.cs and cli/host.ps1 use the same floor.
export const MIN_RATE = 128 * 1024;
const attemptMs = (bytes, capMs) => Math.min(capMs, 60_000 + Math.ceil((bytes * 1000) / MIN_RATE));

const strictB64 = (s, what) => {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) throw new Error(`${what} is not base64`);
  const b = Buffer.from(s, "base64");
  if (b.toString("base64") !== s) throw new Error(`${what} is not canonical base64`);
  return b;
};
const sha256 = (b) => createHash("sha256").update(b).digest("hex");
/**
 * Refuse a JSON number written with a fraction or an exponent. JSON.parse reads 1.0 and 1e0 as the integer 1, but
 * .NET's JavaScriptSerializer (EnclaveSetup.cs) and PowerShell's ConvertFrom-Json (cli/host.ps1) read them as decimals and
 * refuse them as sizes or thresholds; refusing them here too keeps the three verifiers' verdicts the same.
 */
function integerNumbersOnly(text, what) {
  let str = false, esc = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (str) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === '"') str = false; continue; }
    if (c === '"') str = true;
    else if (c === "." || ((c === "e" || c === "E") && /[0-9]/.test(text[i - 1] || ""))) throw new Error(`${what} may hold only whole numbers`);
  }
}
const exactKeys = (o, allowed, what) => {
  if (!o || typeof o !== "object" || Array.isArray(o)) throw new Error(`${what} must be an object`);
  const extra = Object.keys(o).filter((k) => !allowed.includes(k));
  if (extra.length) throw new Error(`${what} has unknown field(s): ${extra.join(", ")}`);
};

/** "ecdsa-p256:<base64 SPKI>" -> { spec, keyId (sha256 of the SPKI DER), der, key }; throws on anything else. */
export function parseReleaseKey(spec) {
  if (typeof spec !== "string" || !spec.startsWith(KEY_PREFIX)) throw new Error(`release key must be "${KEY_PREFIX}<base64 SPKI>"`);
  const der = strictB64(spec.slice(KEY_PREFIX.length), "release key");
  if (der.length !== 91 || !der.subarray(0, 27).equals(P256_SPKI_PREFIX)) throw new Error("release key is not an uncompressed P-256 public key");
  let key;
  try { key = createPublicKey({ key: der, format: "der", type: "spki" }); } catch (e) { throw new Error(`release key is not a usable public key (${e.message})`); }
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error("release key is not P-256");
  return { spec, keyId: sha256(der), der, key };
}

/** The policy spec of a private (or public) key the operator holds: what goes into release-policy.json's keys. */
export function releaseKeySpec(pem) {
  const pub = pem && typeof pem === "object" && pem.type === "public" ? pem : createPublicKey(pem);
  const der = pub.export({ type: "spki", format: "der" });
  return parseReleaseKey(KEY_PREFIX + der.toString("base64")).spec;
}

// A mirror's host is judged as WRITTEN, before WHATWG URL (here) or .NET's Uri (EnclaveSetup.cs, cli/host.ps1) reads it,
// because the two read some spellings differently: WHATWG takes 127.1, 2130706433 and 0x7f000001 as IPv4, and .NET's
// Uri.Host spells IPv6 its own way. The same three rules hold in all three verifiers:
//   * a name is a strict DNS name; if its last label looks numeric, it must be a canonical dotted quad;
//   * an IPv6 literal must be ::1 (compressed or written in full), and becomes [::1];
//   * plain http is allowed only for localhost, 127.0.0.1 or [::1] exactly (a local test mirror).
const RAW_HOST = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/(\[[^\]]*\]|[^/:]*)(:[0-9]{1,5})?(\/|$)/;   // the whole authority: host[:digits]
const DNS_HOST = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;
const NUMERIC_LAST_LABEL = /(^|\.)([0-9]+|0x[0-9a-f]*)$/i;
const DOTTED_QUAD = /^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$/;
/**
 * A mirror: an https directory URL (http only on loopback, for a local test mirror), no credentials, query or fragment.
 * Written in printable ASCII without \ ? # @ %, so that no spelling is normalised one way by WHATWG URL here and another by
 * .NET's Uri in EnclaveSetup.cs and cli/host.ps1: the three accept, and de-duplicate, the same mirror lists.
 */
export function normalizeMirror(value) {
  let u;
  if (typeof value !== "string" || !/^[!-~]+$/.test(value) || /[\\?#@%]/.test(value)) throw new Error(`mirror ${JSON.stringify(value)} is not a plain URL`);
  try { u = new URL(value); } catch { throw new Error(`mirror ${JSON.stringify(value)} is not a URL`); }
  const raw = RAW_HOST.exec(value)?.[1] ?? "", v6 = raw.startsWith("[");
  if (v6 ? u.hostname !== "[::1]" : !DNS_HOST.test(raw) || (NUMERIC_LAST_LABEL.test(raw) && !DOTTED_QUAD.test(raw)) || u.hostname !== raw.toLowerCase())
    throw new Error(`mirror ${JSON.stringify(value)} must name a DNS host, a dotted quad or [::1], written plainly`);
  const loopback = v6 || u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (!(u.protocol === "https:" || (u.protocol === "http:" && loopback))) throw new Error(`mirror ${u.href} must be https`);
  if (u.username || u.password || u.search || u.hash) throw new Error(`mirror ${u.href} must not carry credentials, a query or a fragment`);
  if (!u.pathname.endsWith("/")) u.pathname += "/";
  return u.href;
}

/** Validate a release policy -> { format, channel, keys: [{spec, keyId, key}], threshold, mirrors }. Strict: unknown fields refuse. */
export function validateReleasePolicy(p) {
  exactKeys(p, ["format", "channel", "keys", "threshold", "mirrors"], "release policy");
  if (p.format !== POLICY_FORMAT) throw new Error(`release policy format must be ${POLICY_FORMAT}`);
  if (typeof p.channel !== "string" || !CHANNEL.test(p.channel)) throw new Error("release policy channel must be 1-32 of a-z 0-9 . _ -");
  if (!Array.isArray(p.keys) || !p.keys.length || p.keys.length > LIMITS.keys) throw new Error(`release policy needs 1 to ${LIMITS.keys} keys`);
  const keys = p.keys.map(parseReleaseKey);
  if (new Set(keys.map((k) => k.keyId)).size !== keys.length) throw new Error("release policy lists a key twice");
  if (!Number.isSafeInteger(p.threshold) || p.threshold < 1 || p.threshold > keys.length) throw new Error("release policy threshold must be 1 to the number of keys");
  if (!Array.isArray(p.mirrors) || !p.mirrors.length || p.mirrors.length > LIMITS.mirrors) throw new Error(`release policy needs 1 to ${LIMITS.mirrors} mirrors`);
  const mirrors = p.mirrors.map(normalizeMirror);
  if (new Set(mirrors).size !== mirrors.length) throw new Error("release policy lists a mirror twice");
  return Object.freeze({ format: POLICY_FORMAT, channel: p.channel, keys: Object.freeze(keys), threshold: p.threshold, mirrors: Object.freeze(mirrors) });
}
/** The policy as stored on the host: exactly the validated fields, in one order, so two spellings of one policy compare equal. */
export const policyDocument = (policy) => ({ format: policy.format, channel: policy.channel, keys: policy.keys.map((k) => k.spec),
                                            threshold: policy.threshold, mirrors: [...policy.mirrors] });
/** A JSON file's text, refused by its size BEFORE it is read: no file makes this allocate more than `max`. */
const readJsonText = (file, max = LIMITS.statement * 4) => {
  const fd = fs.openSync(file, "r");
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > max) throw new Error(`${file} is ${st.isFile() ? "too large" : "not a file"}`);
    const b = Buffer.alloc(st.size);
    let n = 0;
    while (n < b.length) { const r = fs.readSync(fd, b, n, b.length - n, n); if (!r) break; n += r; }
    return b.subarray(0, n).toString("utf8").replace(/^\uFEFF/, "");   // PowerShell writes UTF-8 with a byte-order mark
  } finally { fs.closeSync(fd); }
};
const readJsonFile = (file, max) => JSON.parse(readJsonText(file, max));
/** A policy file's text -> the validated policy (as EnclaveSetup.cs ReleaseChannel.ParsePolicy reads the same text). */
export const parseReleasePolicy = (text) => {
  text = String(text).replace(/^﻿/, "");
  integerNumbersOnly(text, "release policy");
  return validateReleasePolicy(JSON.parse(text));
};
export const loadReleasePolicy = (file) => parseReleasePolicy(readJsonText(file));

const ARTIFACTS = [["file", "sha256", "bytes", "zip", (v) => `enclave-host-${v}.zip`],
                   ["setup", "setupSha256", "setupBytes", "setup", (v) => `EnclaveSetup-${v}.exe`],
                   ["manifest", "manifestSha256", "manifestBytes", "manifest", (v) => `manifest-${v}.json`]];
export const STATEMENT_FIELDS = ["format", "channel", "version", "issuedAt", "expiresAt", ...ARTIFACTS.flatMap(([n, h, b]) => [n, h, b])];
const isoTime = (s, what) => {
  const t = typeof s === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z$/.test(s) ? Date.parse(s) : NaN;
  // Date.parse rolls 02-30 over to 03-02 and reads 24:00 as midnight; .NET's DateTime.TryParse refuses both, and so does this
  if (Number.isNaN(t) || new Date(t).toISOString().slice(0, 19) !== s.slice(0, 19)) throw new Error(`${what} must be an ISO-8601 UTC time`);
  return t;
};
/**
 * Validate a release statement against the policy it is read under. Artifact names are FIXED by the version, so a signed
 * statement cannot point a host at an arbitrary path on a mirror, and every artifact carries its size, so no download is
 * unbounded.
 */
export function validateStatement(s, { channel, now = Date.now() } = {}) {
  exactKeys(s, STATEMENT_FIELDS, "release statement");
  if (s.format !== STATEMENT_FORMAT) throw new Error(`release statement format must be ${STATEMENT_FORMAT}`);
  if (s.channel !== channel) throw new Error(`release statement is for channel ${JSON.stringify(s.channel)}, not ${JSON.stringify(channel)}`);
  if (typeof s.version !== "string" || !VERSION.test(s.version)) throw new Error("release statement version must be 2-4 dotted numbers");
  const issued = isoTime(s.issuedAt, "issuedAt");
  if (issued > now + FUTURE_SKEW_MS) throw new Error("release statement is issued in the future");
  if (s.expiresAt !== undefined && isoTime(s.expiresAt, "expiresAt") <= now) throw new Error(`release statement expired at ${s.expiresAt}`);
  for (const [n, h, b, kind, name] of ARTIFACTS) {
    if (s[n] !== name(s.version)) throw new Error(`release statement ${n} must be ${name(s.version)}`);
    if (typeof s[h] !== "string" || !HEX64.test(s[h])) throw new Error(`release statement ${h} must be 64 lowercase hex`);
    if (!Number.isSafeInteger(s[b]) || s[b] < 1 || s[b] > LIMITS[kind]) throw new Error(`release statement ${b} is out of range`);
  }
  return Object.freeze({ ...s });
}

/**
 * Verify an envelope's bytes under a policy -> { statement, statementSha256, signers: [keyId] }.
 * Counts DISTINCT pinned keys whose signature verifies over SIGNING_CONTEXT || the statement's exact bytes. Signatures by
 * keys the policy does not pin are ignored (a co-signer this host does not trust adds nothing and costs nothing).
 */
export function verifyEnvelope(bytes, policy, { now = Date.now() } = {}) {
  const raw = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes));
  if (raw.length > LIMITS.envelope) throw new Error("release envelope is too large");
  let env;
  try { env = JSON.parse(raw.toString("utf8").replace(/^\uFEFF/, "")); } catch { throw new Error("release envelope is not JSON"); }
  exactKeys(env, ["format", "statement", "signatures"], "release envelope");
  if (env.format !== ENVELOPE_FORMAT) throw new Error(`release envelope format must be ${ENVELOPE_FORMAT}`);
  const statementBytes = strictB64(env.statement, "release statement");
  if (statementBytes.length > LIMITS.statement) throw new Error("release statement is too large");
  if (!Array.isArray(env.signatures) || env.signatures.length > 16) throw new Error("release envelope signatures must be a list of at most 16");
  const message = Buffer.concat([SIGNING_CONTEXT, statementBytes]);
  const byId = new Map(policy.keys.map((k) => [k.keyId, k]));
  const signers = new Set();
  for (const s of env.signatures) {
    exactKeys(s, ["keyId", "sig"], "release signature");
    const k = byId.get(s.keyId);
    if (!k || signers.has(k.keyId)) continue;
    const sig = strictB64(s.sig, "release signature");
    if (sig.length !== 64) continue;
    if (cryptoVerify("sha256", message, { key: k.key, dsaEncoding: "ieee-p1363" }, sig)) signers.add(k.keyId);
  }
  if (signers.size < policy.threshold)
    throw new Error(`release statement has ${signers.size} valid signature(s) by pinned keys; the policy requires ${policy.threshold}`);
  let statement;
  const statementText = statementBytes.toString("utf8");
  try { statement = JSON.parse(statementText); } catch { throw new Error("signed release statement is not JSON"); }
  integerNumbersOnly(statementText, "signed release statement");
  return { statement: validateStatement(statement, { channel: policy.channel, now }), statementSha256: sha256(statementBytes), signers: [...signers] };
}

/** The announced Content-Length, or NaN when there is none (a chunked answer): Number(null) would be 0. */
const contentLength = (r) => { const h = r.headers?.get?.("content-length"); return h === null || h === undefined || h === "" ? NaN : Number(h); };
/** 1.2 and 1.2.0 are one version to [System.Version] comparisons too: two statements for it are equivocation. */
const versionKey = (v) => { const p = v.split(".").map(Number); while (p.length < 4) p.push(0); return p.join("."); };
/** The caller's cancellation and this call's own hard deadline, as one signal. */
const deadlineSignal = (ms, signal) => (signal ? AbortSignal.any([signal, AbortSignal.timeout(ms)]) : AbortSignal.timeout(ms));
/** Read at most `max` bytes of a response body; more is an error, not a truncation. */
async function boundedBody(r, max) {
  const len = contentLength(r);
  if (Number.isFinite(len) && len > max) throw new Error(`answer is ${len} bytes, more than ${max}`);
  if (!r.body?.getReader) { const b = Buffer.from(await r.arrayBuffer()); if (b.length > max) throw new Error(`answer is more than ${max} bytes`); return b; }
  const reader = r.body.getReader(), parts = []; let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > max) { try { await reader.cancel(); } catch {} throw new Error(`answer is more than ${max} bytes`); }
    parts.push(Buffer.from(value));
  }
  return Buffer.concat(parts);
}

/**
 * Ask EVERY mirror for its signed pointer and take the highest version any of them can prove. A mirror that withholds
 * a newer release (freeze), serves an older one (rollback), serves garbage or a statement nobody pinned signed, is
 * rejected or outvoted; it is never trusted. Two DIFFERENT signed statements for one version mean the release key signed
 * twice - a compromise or a publishing accident - and nothing is installed until the operator looks.
 * -> { statement, statementSha256, signers, servedBy: [mirror], rejected: [{mirror, reason}], newer }
 */
export async function resolveRelease({ policy, installed = null, force = false, fetchImpl = globalThis.fetch, now = Date.now,
                                       timeoutMs = 15000, signal, log = () => {} }) {
  const answers = await Promise.all(policy.mirrors.map(async (mirror) => {
    const stop = new AbortController();
    try {
      // timeoutMs bounds the whole answer, headers and body: a mirror that trickles its envelope is cut off with it
      const r = await fetchImpl(new URL(ENVELOPE_NAME, mirror).href, { cache: "no-store", signal: AbortSignal.any([deadlineSignal(timeoutMs, signal), stop.signal]) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return { mirror, ...verifyEnvelope(await boundedBody(r, LIMITS.envelope), policy, { now: now() }) };
    } catch (e) { stop.abort(); return { mirror, error: e.message || String(e) }; }   // a refused answer's connection is closed, not left open
  }));
  if (signal?.aborted) throw new Error("release resolution cancelled");
  const rejected = answers.filter((a) => a.error).map(({ mirror, error }) => ({ mirror, reason: error }));
  for (const x of rejected) log(`release: ${x.mirror} refused: ${x.reason}`);
  const valid = answers.filter((a) => !a.error);
  if (!valid.length) throw new Error(`no mirror served a release signed by the pinned key(s): ${rejected.map((x) => `${x.mirror} (${x.reason})`).join("; ")}`);
  const byVersion = new Map();
  for (const a of valid) {
    const key = versionKey(a.statement.version), seen = byVersion.get(key);
    if (seen && seen.statementSha256 !== a.statementSha256)
      throw new Error(`two different signed statements for version ${a.statement.version} (${seen.mirror} and ${a.mirror}): refusing to install until the publisher explains`);
    if (!seen) byVersion.set(key, { ...a, servedBy: [a.mirror] }); else seen.servedBy.push(a.mirror);
  }
  const best = [...byVersion.values()].reduce((x, y) => (newer(y.statement.version, x.statement.version) ? y : x));
  return { statement: best.statement, statementSha256: best.statementSha256, signers: best.signers, servedBy: best.servedBy, rejected,
           newer: !!force || !installed || newer(best.statement.version, installed) };
}

const ITEM_NAME = /^(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127}|files\/[0-9a-f]{64})$/;
/**
 * Download one artifact whose sha256 and size come from a VERIFIED statement (or a manifest a verified statement hashes),
 * trying each mirror in turn. A wrong size or hash on one mirror is that mirror's failure: the partial file is removed
 * and the next mirror is asked. An already-present file with the right hash is kept (a resumed update).
 *
 * Bounded in memory, bytes and time, whatever is on disk or on the wire:
 *   * a file already at `out` is judged by its size first (lstat: a regular file, not a link), then hashed as a stream; it
 *     is never read whole, so a cache file of any size costs one 1 MiB buffer;
 *   * a mirror may send at most the signed size: an announced longer body is refused before it is read, a longer stream
 *     at the first byte past it; the body is written as it arrives, never held;
 *   * each mirror has a hard deadline for headers AND body (60 s plus the size at MIN_RATE, at most timeoutMs), and the
 *     call has one over every mirror (deadlineMs), so a trickling mirror cannot hold the update; `signal` cancels it all;
 *   * the part file has a random name and is created exclusively (never through something already there), and only a
 *     part whose size and sha256 are the signed ones is renamed to `out`. Nothing else ever replaces `out`.
 */
export async function downloadVerified({ mirrors, name, sha256: want, bytes, out, fetchImpl = globalThis.fetch, timeoutMs = 3600_000,
                                         deadlineMs = 4 * 3600_000, signal, log = () => {} }) {
  if (!ITEM_NAME.test(String(name || ""))) throw new Error(`refusing to download ${JSON.stringify(name)}: not a release file name`);
  if (!HEX64.test(String(want || ""))) throw new Error(`${name}: no verified sha256`);
  if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > LIMITS.zip) throw new Error(`${name}: no verified size`);
  if (await hasSignedBytes(out, bytes, want, signal)) return { out, mirror: null, cached: true };
  const overall = deadlineSignal(deadlineMs, signal), errors = [];
  for (const mirror of mirrors) {
    if (overall.aborted) { errors.push(signal?.aborted ? "cancelled" : `the ${deadlineMs / 1000} s deadline passed`); break; }
    const part = `${out}.partial-${randomBytes(8).toString("hex")}`;
    let fd = null;
    const stop = new AbortController();
    try {
      const attempt = AbortSignal.any([overall, AbortSignal.timeout(attemptMs(bytes, timeoutMs)), stop.signal]);
      const r = await fetchImpl(new URL(name, mirror).href, { signal: attempt });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const len = contentLength(r);
      if (Number.isFinite(len) && len !== bytes) throw new Error(`announces ${len} bytes, the signed size is ${bytes}`);
      const h = createHash("sha256"); let n = 0;
      fd = fs.openSync(part, "wx");
      const reader = r.body.getReader();
      for (;;) {
        // a body that stalls past the deadline errors here (the signal aborts the stream); this check is for one that does not
        if (attempt.aborted) { try { await reader.cancel(); } catch {} throw new Error("the download deadline passed"); }
        const { done, value } = await reader.read();
        if (done) break;
        n += value.length;
        if (n > bytes) { try { await reader.cancel(); } catch {} throw new Error(`sent more than the signed ${bytes} bytes`); }
        h.update(value); fs.writeSync(fd, value);
      }
      fs.closeSync(fd); fd = null;
      if (n !== bytes) throw new Error(`sent ${n} bytes, the signed size is ${bytes}`);
      const got = h.digest("hex");
      if (got !== want) throw new Error(`hashes ${got.slice(0, 16)}…, the signed sha256 is ${want.slice(0, 16)}…`);
      fs.renameSync(part, out);
      return { out, mirror, cached: false };
    } catch (e) {
      stop.abort();   // a refused mirror's connection is closed, not left holding an unread body
      if (fd !== null) try { fs.closeSync(fd); } catch {}
      try { fs.rmSync(part, { force: true }); } catch {}
      const why = e.name === "TimeoutError" || e.cause?.name === "TimeoutError" ? "the download deadline passed" : e.message;
      errors.push(`${mirror}: ${why}`); log(`release: ${name} from ${mirror} refused: ${why}`);
    }
  }
  throw new Error(`${name}: no mirror served the signed bytes (${errors.join("; ")})`);
}
/** Is `file` a regular file of exactly `bytes` whose sha256 is `want`? Size first; then hashed 1 MiB at a time. */
async function hasSignedBytes(file, bytes, want, signal) {
  let st;
  try { st = fs.lstatSync(file); } catch { return false; }
  if (!st.isFile() || st.size !== bytes) return false;
  const h = createHash("sha256"), buf = Buffer.allocUnsafe(1024 * 1024);
  let fd;
  try { fd = fs.openSync(file, "r"); } catch { return false; }
  try {
    for (let pos = 0; pos < bytes;) {
      if (signal?.aborted) throw new Error("cancelled");
      const n = await new Promise((ok, no) => fs.read(fd, buf, 0, Math.min(buf.length, bytes - pos), pos, (e, r) => (e ? no(e) : ok(r))));
      if (!n) return false;
      h.update(buf.subarray(0, n)); pos += n;
    }
    // a file that grew while it was read is not the signed bytes either
    return fs.fstatSync(fd).size === bytes && h.digest("hex") === want;
  } catch (e) {
    if (signal?.aborted) throw new Error("release download cancelled");
    return false;
  } finally { fs.closeSync(fd); }
}

/**
 * The agent's minute check (update-watch.mjs fetchLatest) for a host with a release policy: the highest version the
 * pinned keys signed, or a throw. It only TRIGGERS \Enclave\Update; update-host.ps1 resolves and verifies again itself.
 * A policy file that exists but does not load is an error every minute, never a quiet fall back to latest.json.
 */
export function createSignedLatest({ policyFile, fetchImpl = globalThis.fetch, log = () => {} }) {
  return async () => {
    const policy = loadReleasePolicy(policyFile);
    const r = await resolveRelease({ policy, fetchImpl, log });
    return { version: r.statement.version, signers: r.signers, servedBy: r.servedBy };
  };
}

/** A statement for a built release: the hashes and sizes of the three artifacts, read from the files themselves. */
export function buildStatement({ channel, version, zip, setup, manifest, issuedAt = new Date(), validDays = 0 }) {
  const file = (f) => { const b = fs.readFileSync(f); return { sha256: sha256(b), bytes: b.length }; };
  const z = file(zip), s = file(setup), m = file(manifest);
  const st = { format: STATEMENT_FORMAT, channel, version, issuedAt: new Date(issuedAt).toISOString(),
    ...(validDays > 0 ? { expiresAt: new Date(new Date(issuedAt).getTime() + validDays * 86400_000).toISOString() } : {}),
    file: `enclave-host-${version}.zip`, sha256: z.sha256, bytes: z.bytes,
    setup: `EnclaveSetup-${version}.exe`, setupSha256: s.sha256, setupBytes: s.bytes,
    manifest: `manifest-${version}.json`, manifestSha256: m.sha256, manifestBytes: m.bytes };
  return validateStatement(st, { channel, now: new Date(issuedAt).getTime() });
}
/** Sign a statement with private keys the publisher holds (PEM text or KeyObjects) -> the envelope's JSON text. */
export function signEnvelope(statement, privateKeys) {
  const statementBytes = Buffer.from(JSON.stringify(statement), "utf8");
  return addSignatures(JSON.stringify({ format: ENVELOPE_FORMAT, statement: statementBytes.toString("base64"), signatures: [] }), privateKeys);
}
/** Add signatures to an existing envelope (a second signer for a threshold policy); the statement bytes never change. */
export function addSignatures(envelopeText, privateKeys) {
  const env = JSON.parse(String(envelopeText));
  exactKeys(env, ["format", "statement", "signatures"], "release envelope");
  const message = Buffer.concat([SIGNING_CONTEXT, strictB64(env.statement, "release statement")]);
  for (const pk of privateKeys) {
    const key = typeof pk === "string" || Buffer.isBuffer(pk) ? createPrivateKey(pk) : pk;
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error("release signing key must be a P-256 private key");
    const keyId = parseReleaseKey(releaseKeySpec(key)).keyId;
    env.signatures = env.signatures.filter((s) => s.keyId !== keyId);
    env.signatures.push({ keyId, sig: cryptoSign("sha256", message, { key, dsaEncoding: "ieee-p1363" }).toString("base64") });
  }
  return JSON.stringify(env, null, 1) + "\n";
}

/**
 * Put a policy on a host, refusing to replace a DIFFERENT one unless asked: a re-run of setup or an update never moves a
 * host to another key or mirror set by accident. Written beside its final name and renamed, so a reader never sees half.
 * -> "written" | "unchanged" | "replaced"
 */
export function installPolicy({ policy, dest, replace = false }) {
  const text = JSON.stringify(policyDocument(policy), null, 1) + "\n";
  let existing = null;
  try { existing = JSON.stringify(policyDocument(loadReleasePolicy(dest)), null, 1) + "\n"; }
  catch (e) { if (e.code !== "ENOENT") { if (!replace) throw new Error(`${dest} exists but is not a valid release policy (${e.message}); pass --replace to overwrite it`); existing = ""; } }
  if (existing === text) return "unchanged";
  if (existing !== null && !replace) throw new Error(`${dest} already pins a different release policy; pass --replace to change this host's release keys or mirrors`);
  const tmp = `${dest}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, text, { flag: "wx" });
  fs.renameSync(tmp, dest);
  return existing === null ? "written" : "replaced";
}

// ---- CLI ---------------------------------------------------------------------------------------------------------------
function args(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) { o._.push(a); continue; }
    const k = a.slice(2);
    if (["force", "replace"].includes(k)) { o[k] = true; continue; }
    const v = argv[++i];
    if (v === undefined) throw new Error(`--${k} needs a value`);
    if (k === "key") (o.key ||= []).push(v); else o[k] = v;
  }
  return o;
}
const need = (o, ...ks) => { for (const k of ks) if (!o[k] || (Array.isArray(o[k]) && !o[k].length)) throw new Error(`--${k} is required`); };
const writeNew = (file, text) => { const tmp = `${file}.tmp-${process.pid}`; fs.writeFileSync(tmp, text); fs.renameSync(tmp, file); };

export async function main(argv = process.argv.slice(2), { fetchImpl = globalThis.fetch, stdout = (s) => process.stdout.write(s), stderr = (s) => process.stderr.write(s) } = {}) {
  const [cmd, ...rest] = argv;
  const o = args(rest);
  const log = (m) => stderr(m + "\n");
  if (cmd === "check-policy") {
    const p = loadReleasePolicy(o._[0] || o.policy);
    stdout(JSON.stringify({ ...policyDocument(p), keyIds: p.keys.map((k) => k.keyId) }) + "\n");
  } else if (cmd === "install-policy") {
    need(o, "policy", "dest");
    stdout(installPolicy({ policy: loadReleasePolicy(o.policy), dest: o.dest, replace: !!o.replace }) + "\n");
  } else if (cmd === "resolve") {
    need(o, "policy", "out");
    const r = await resolveRelease({ policy: loadReleasePolicy(o.policy), installed: o.installed || null, force: !!o.force, fetchImpl, log });
    writeNew(o.out, JSON.stringify({ version: r.statement.version, newer: r.newer, statement: r.statement, statementSha256: r.statementSha256,
                                     signers: r.signers, servedBy: r.servedBy, rejected: r.rejected }) + "\n");
  } else if (cmd === "download") {
    need(o, "policy", "list");
    const policy = loadReleasePolicy(o.policy);
    const items = readJsonFile(o.list, 64 * 1024 ** 2);
    if (!Array.isArray(items)) throw new Error("--list must be a JSON array");
    // one hard deadline for the whole list, so the hourly task can never be held by mirrors that trickle
    const deadlineSec = Number(o["deadline-sec"] || 4 * 3600);
    if (!Number.isSafeInteger(deadlineSec) || deadlineSec < 1) throw new Error("--deadline-sec must be a whole number of seconds");
    const signal = AbortSignal.timeout(deadlineSec * 1000);
    for (const it of items) {
      const r = await downloadVerified({ mirrors: policy.mirrors, name: it.name, sha256: it.sha256, bytes: Number(it.bytes), out: it.out, fetchImpl, signal, log });
      if (!r.cached) log(`release: ${it.name} checked (sha256 ${it.sha256.slice(0, 12)}…) from ${r.mirror}`);
    }
  } else if (cmd === "statement") {
    need(o, "channel", "version", "zip", "setup", "manifest", "out");
    const st = buildStatement({ channel: o.channel, version: o.version, zip: o.zip, setup: o.setup, manifest: o.manifest, validDays: Number(o["valid-days"] || 0) });
    fs.writeFileSync(o.out, JSON.stringify(st, null, 1) + "\n", { flag: "wx" });
  } else if (cmd === "sign") {
    need(o, "statement", "key", "out");
    const st = readJsonFile(o.statement);
    validateStatement(st, { channel: st.channel });
    writeNew(o.out, signEnvelope(st, o.key.map((f) => fs.readFileSync(f, "utf8"))));
  } else if (cmd === "cosign") {
    need(o, "envelope", "key", "out");
    writeNew(o.out, addSignatures(fs.readFileSync(o.envelope, "utf8"), o.key.map((f) => fs.readFileSync(f, "utf8"))));
  } else if (cmd === "verify") {
    need(o, "envelope", "channel", "key");
    const keys = o.key.map((k) => (k.startsWith("ecdsa-p256:") ? k : releaseKeySpec(fs.readFileSync(k, "utf8"))));
    const policy = validateReleasePolicy({ format: POLICY_FORMAT, channel: o.channel, keys, threshold: keys.length, mirrors: ["https://unused.invalid/"] });
    const r = verifyEnvelope(fs.readFileSync(o.envelope), policy);
    stdout(JSON.stringify({ version: r.statement.version, signers: r.signers, statementSha256: r.statementSha256 }) + "\n");
  } else if (cmd === "pubkey") {
    need(o, "key");
    const spec = releaseKeySpec(fs.readFileSync(o.key[0], "utf8"));
    stdout(JSON.stringify({ key: spec, keyId: parseReleaseKey(spec).keyId }) + "\n");
  } else {
    throw new Error("commands: check-policy | install-policy | resolve | download | statement | sign | cosign | verify | pubkey");
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch((e) => { process.stderr.write(`release: ${e.message}\n`); process.exit(1); });
