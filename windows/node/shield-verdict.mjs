// windows/node/shield-verdict.mjs - Shield MARKET admission from verifiers the host's OPERATOR selected, instead of the one
// Enclave relay's verdict (relay/shield-marketplace.mjs over the fleet tunnel).
//
// WHAT A VERDICT MEANS, exactly the relay's market window and nothing more: a verifier ran, for THIS host and THIS round,
//   1. the hv-node attach (relay/hvnode-verify.mjs, unchanged): EK chain to the verifier's pinned TPM roots, a credential the
//      verifier minted for that EK and AK name, a quote over the verifier's nonce bound to this host's transport key, the
//      replayed boot log (Secure Boot on, production signing, VBS/HVCI), and possession of the transport key;
//   2. the host's on-chain identity: the registry entry for keccak256(endpoint) names this endpoint, and its registered
//      operator signed this exact exchange (verifier, host, nonce, transport key, EK, and the host's own challenge);
//   3. the policy's pinned readiness witness (relay/shield-market-evidence.mjs, the relay's own rule): a guest report over
//      the verifier's second nonce, signed under the IDKS of THAT authenticated boot, for the witness AppID and RuntimeID on
//      an image and platform the verifier's policy admits (verifyShieldAppPolicy). That is the monitor binding and the
//      enforced-isolation proof; the host's statements are carried, never read.
// It never says "TEE", never says the host is excluded (tier hv-node, hostExcluded false, as the relay says), and never
// admits an app: per-app evidence is still each client's to check.
//
// TRUST AND FAILURE SEMANTICS.
//   - The operator pins the verifier set (ENCLAVE_SHIELD_VERIFIERS_FILE, enclave-shield-verifier-set/v1): keys, URLs and a
//     threshold. There is NO built-in key, Enclave's included; a relay is one only if the operator lists it.
//   - The market opens only with `threshold` valid verdicts from DISTINCT pinned keys, each bound to this host id, this
//     endpoint, this transport key and this round's fresh host challenge, and unexpired. The window is the earliest expiry
//     of those, never more than five minutes, and is never extended: each round must earn its own.
//   - Anything else - a verifier down, a forged or replayed verdict, one for another host or key, a stale one, a refusal -
//     counts for nothing. Below threshold the market stays closed (owner-only scope), exactly as without a relay verdict.
//   - Verdicts are public statements (a client may check them); they grant nothing to anyone but this host's own claim
//     gate, and a verifier cannot be made mandatory for any host that does not pin it.
import fs from "node:fs";
import { createHash, createPublicKey, verify as cryptoVerify, sign as cryptoSign, randomBytes } from "node:crypto";
import { buildHvNodeFrame } from "./hvnode-evidence.mjs";

export const VERDICT_FORMAT = "enclave-shield-market-verdict/v1";
export const VERDICT_DOMAIN = "enclave-shield-market-verdict/v1\n";
export const VERIFIER_SET_FORMAT = "enclave-shield-verifier-set/v1";
export const ATTACH_DOMAIN = "enclave-shield-verifier-attach/v1";
export const MAX_VERDICT_TTL_MS = 300_000;          // the relay's market TTL (shield-marketplace.mjs), and no longer
export const CLOCK_SKEW_MS = 30_000;
const HEX32 = /^[0-9a-f]{64}$/, ID32 = /^0x[0-9a-f]{64}$/, ADDR = /^0x[0-9a-f]{40}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const sha256hex = (b) => createHash("sha256").update(b).digest("hex");

/** Canonical JSON: sorted keys, no whitespace; integers, strings, booleans, null, arrays and objects only. */
export function canonicalJson(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw new Error("canonical JSON carries integers only"); return String(v); }
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  throw new Error("canonical JSON cannot carry this value");
}
/** "ed25519:<base64 SPKI>" -> the 44-byte SPKI, or throws. */
export function verifierKeyBytes(spec) {
  const m = /^ed25519:([A-Za-z0-9+/]+={0,2})$/.exec(String(spec || ""));
  const der = m ? Buffer.from(m[1], "base64") : null;
  if (!der || der.length !== 44 || !der.subarray(0, 12).equals(ED25519_SPKI_PREFIX) || der.toString("base64") !== m[1])
    throw new Error("a verifier key must be ed25519:<base64 of its 44-byte SPKI>");
  return der;
}
export const keyIdOf = (spec) => sha256hex(verifierKeyBytes(spec));
export const keySpecOf = (publicKey) => `ed25519:${createPublicKey(publicKey).export({ type: "spki", format: "der" }).toString("base64")}`;

/** The operator's verifier set, validated. No defaults: an absent file means no verifier market at all. */
export function validateVerifierSet(o) {
  if (!o || typeof o !== "object" || Array.isArray(o) || o.format !== VERIFIER_SET_FORMAT || Object.keys(o).some((k) => !["format", "threshold", "verifiers"].includes(k)))
    throw new Error(`a verifier set is {"format":"${VERIFIER_SET_FORMAT}","threshold":n,"verifiers":[{"key":"ed25519:...","url":"https://..."}]}`);
  if (!Array.isArray(o.verifiers) || !o.verifiers.length || o.verifiers.length > 8) throw new Error("a verifier set names 1 to 8 verifiers");
  const ids = new Set();
  const verifiers = o.verifiers.map((v) => {
    if (!v || typeof v !== "object" || Object.keys(v).some((k) => !["key", "url"].includes(k))) throw new Error("a verifier is { key, url }");
    const id = keyIdOf(v.key);
    if (ids.has(id)) throw new Error("a verifier key is listed twice");
    ids.add(id);
    const u = new URL(String(v.url));
    if (u.protocol !== "https:" && !(u.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(u.hostname)) || u.username || u.password || u.search || u.hash)
      throw new Error("a verifier URL is https (or loopback http) without credentials, query or fragment");
    return { key: v.key, keyId: id, url: u.href.replace(/\/$/, "") };
  });
  if (!Number.isSafeInteger(o.threshold) || o.threshold < 1 || o.threshold > verifiers.length) throw new Error("the threshold must be 1..(number of verifiers)");
  return { threshold: o.threshold, verifiers };
}
export function loadVerifierSet(file) {
  const bytes = fs.readFileSync(file);
  if (bytes.length > 16384) throw new Error("verifier set too large");
  return validateVerifierSet(JSON.parse(bytes.toString("utf8").replace(/^﻿/, "")));
}

/** The message the host's REGISTERED OPERATOR signs (personal_sign) for one verifier exchange: its consent to this TPM,
 *  this transport key and this round, for this verifier only. */
export function attachMessage({ verifier, hostId, endpoint, nonce, transportKeySha256, ekCertSha256, hostChallenge }) {
  for (const [k, v] of Object.entries({ verifier, nonce, transportKeySha256, ekCertSha256, hostChallenge }))
    if (!HEX32.test(String(v || ""))) throw new Error(`attach message: ${k} must be 32 bytes of hex`);
  if (!ID32.test(String(hostId || ""))) throw new Error("attach message: hostId must be a bytes32");
  if (!/^https?:\/\/\S+$/.test(String(endpoint || "")) || /\s|:$/.test(endpoint)) throw new Error("attach message: endpoint must be the registered URL");
  return `${ATTACH_DOMAIN}:${verifier}:${hostId}:${endpoint}:${nonce}:${transportKeySha256}:${ekCertSha256}:${hostChallenge}`;
}

/** A verifier signs a statement: { statement (base64 of canonical bytes), signature (base64 Ed25519), key }. */
export function signVerdict(statement, privateKey) {
  const key = keySpecOf(privateKey);
  const bytes = Buffer.from(canonicalJson({ ...statement, format: VERDICT_FORMAT, verifier: keyIdOf(key) }));
  return { statement: bytes.toString("base64"), signature: cryptoSign(null, Buffer.concat([Buffer.from(VERDICT_DOMAIN), bytes]), privateKey).toString("base64"), key };
}

/** One envelope against a pinned key set -> the statement, or throws with the reason. */
export function openVerdict(env, pinned) {
  if (!env || typeof env !== "object" || typeof env.statement !== "string" || typeof env.signature !== "string" || typeof env.key !== "string"
      || env.statement.length > 8192 || env.signature.length > 128) throw new Error("not a bounded verdict envelope");
  const id = keyIdOf(env.key);
  if (!pinned.has(id)) throw new Error(`verifier ${id.slice(0, 16)} is not in this host's verifier set`);
  const bytes = Buffer.from(env.statement, "base64"), sig = Buffer.from(env.signature, "base64");
  if (bytes.toString("base64") !== env.statement || sig.length !== 64) throw new Error("noncanonical verdict encoding");
  const pub = createPublicKey({ key: verifierKeyBytes(env.key), format: "der", type: "spki" });
  if (!cryptoVerify(null, Buffer.concat([Buffer.from(VERDICT_DOMAIN), bytes]), pub, sig)) throw new Error("verdict signature does not verify");
  let s; try { s = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("verdict statement is not JSON"); }
  if (canonicalJson(s) !== bytes.toString("utf8")) throw new Error("verdict statement is not canonical");
  if (s.format !== VERDICT_FORMAT || s.verifier !== id) throw new Error("verdict format or signer mismatch");
  return s;
}

/**
 * verifyVerdicts(envelopes, { set, hostId, endpoint, transportKeySpki, hostChallenge, now })
 *   -> { ok: true, until, keyIds } once `set.threshold` distinct pinned verifiers each bound this round, or
 *   -> { ok: false, reasons: [...] }.
 */
export function verifyVerdicts(envelopes, { set, hostId, endpoint, transportKeySpki, hostChallenge, now = Date.now() }) {
  const pinned = new Set(set.verifiers.map((v) => v.keyId)), reasons = [], good = new Map();
  const tk = sha256hex(transportKeySpki), t = now;
  for (const env of Array.isArray(envelopes) ? envelopes.slice(0, 16) : []) {
    try {
      const s = openVerdict(env, pinned);
      if (s.hostId !== String(hostId).toLowerCase() || s.endpoint !== endpoint) throw new Error("the verdict names another host");
      if (s.transportKeySha256 !== tk) throw new Error("the verdict names another transport key");
      if (s.hostChallenge !== hostChallenge) throw new Error("the verdict answers another round (replayed or stale)");
      if (s.tier !== "hv-node" || s.technology !== "windows-tpm-host" || s.hostExcluded !== false || s.market !== "shield-capacity")
        throw new Error("the verdict does not state this tier's market admission");
      if (!Number.isSafeInteger(s.issuedAt) || !Number.isSafeInteger(s.expiresAt) || s.issuedAt > t + CLOCK_SKEW_MS
          || s.expiresAt <= t || s.expiresAt - s.issuedAt > MAX_VERDICT_TTL_MS) throw new Error("the verdict is expired or outside its window");
      if (!s.readiness || !HEX32.test(s.readiness.appSha256 || "") || !HEX32.test(s.readiness.runtimeId || ""))
        throw new Error("the verdict carries no verified readiness witness");
      if (!good.has(s.verifier)) good.set(s.verifier, s);
    } catch (e) { reasons.push(e.message); }
  }
  if (good.size < set.threshold) return { ok: false, reasons: [...reasons, `${good.size} of the required ${set.threshold} verifier verdict(s)`] };
  const chosen = [...good.values()].sort((a, b) => b.expiresAt - a.expiresAt).slice(0, set.threshold);
  return { ok: true, until: Math.min(...chosen.map((s) => s.expiresAt)), keyIds: chosen.map((s) => s.verifier), reasons };
}

/** An owner-selected DNS-01 responder's party id in a host's attach signature (relay/dns-challenge-shield.mjs): bound to its
 *  challenge zone, so a session a host made for one responder cannot be presented at another. */
export const shieldResponderId = (zone) => createHash("sha256").update(`enclave-shield-responder-v1\n${zone}`).digest("hex");

export async function postJson(fetchImpl, url, body, timeoutMs) {
  const r = await fetchImpl(url, { method: "POST", redirect: "error", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
                                   signal: AbortSignal.timeout(timeoutMs) });
  const text = await r.text();
  if (text.length > 65536) throw new Error("verifier answer too large");
  let j; try { j = JSON.parse(text); } catch { throw new Error(`verifier HTTP ${r.status}: not JSON`); }
  if (!r.ok) throw new Error(`verifier HTTP ${r.status}: ${String(j?.error || "").slice(0, 200)}`);
  return j;
}

/**
 * The host's side: one round asks every pinned verifier in turn (one TPM operation at a time) and opens the market only on
 * a threshold of verdicts for this round.
 *   set            validateVerifierSet(...)
 *   hostId, endpoint   this host's registry id and its registered endpoint
 *   nodeKey        { spki, privateKey }: the agent's transport key (hvnode-evidence.mjs loadOrCreateNodeKey)
 *   tpm, keysFrame the agent's TPM line protocol and its vbs-keys frame (agent.mjs tpmCmd, keysFrame)
 *   managerHealth, platform   as for the relay attach
 *   readiness(nonceHex) -> { doc, handshakeSpki } from the pinned witness (shield-witness.mjs evidence)
 *   sign(message) -> personal_sign by the registered operator key
 *   open(until, keyIds)        the host's window (host.mjs openVerifierMarket)
 */
export function createVerifierMarketClient({ set, hostId, endpoint, nodeKey, tpm, keysFrame, managerHealth = async () => null, platform = async () => ({}),
                                             readiness, sign, open, fetchImpl = globalThis.fetch, timeoutMs = 60_000, now = Date.now, log = () => {} }) {
  if (!set?.verifiers?.length) throw new Error("no verifier set");
  let running = false;
  async function askOne(v, keys, hostChallenge) {
    const ch = await postJson(fetchImpl, `${v.url}/v1/shield-verifier/challenge`, { hostId, endpoint, hostChallenge, keys }, timeoutMs);
    if (typeof ch?.session !== "string" || !HEX32.test(ch.appNonce || "")) throw new Error("malformed verifier challenge");
    const nonce = Buffer.from(String(ch.nonce || ""), "base64");
    if (nonce.length !== 32) throw new Error("verifier nonce must be 32 bytes");
    const frame = await buildHvNodeFrame({ nonce, credentialBlob: Buffer.from(String(ch.credentialBlob || ""), "base64"),
      secret: Buffer.from(String(ch.secret || ""), "base64"), spki: nodeKey.spki, privateKey: nodeKey.privateKey, tpm,
      managerHealth: await managerHealth(), platform: await platform() });
    const proof = await readiness(ch.appNonce);
    const operatorSig = await sign(attachMessage({ verifier: v.keyId, hostId, endpoint, nonce: nonce.toString("hex"),
      transportKeySha256: sha256hex(nodeKey.spki), ekCertSha256: sha256hex(Buffer.from(keys.ek, "base64")), hostChallenge }));
    const r = await postJson(fetchImpl, `${v.url}/v1/shield-verifier/attest`,
      { session: ch.session, rad: frame.rad, readiness: { doc: proof.doc, handshakeSpki: proof.handshakeSpki }, operatorSig }, timeoutMs);
    return r.verdict;
  }
  return {
    async round() {
      if (running) return { ok: false, reasons: ["a round is already running"] };
      running = true;
      try {
        const hostChallenge = randomBytes(32).toString("hex"), keys = await keysFrame(), got = [], fails = [];
        for (const v of set.verifiers) {
          try { got.push(await askOne(v, keys, hostChallenge)); }
          catch (e) { fails.push(`${v.url}: ${e.message}`); }
        }
        const r = verifyVerdicts(got, { set, hostId, endpoint, transportKeySpki: nodeKey.spki, hostChallenge, now: now() });
        if (r.ok) open(r.until, r.keyIds);
        else log(`shield market (selected verifiers): closed: ${[...fails, ...r.reasons].join("; ")}`);
        return { ...r, failures: fails };
      } finally { running = false; }
    },
  };
}
