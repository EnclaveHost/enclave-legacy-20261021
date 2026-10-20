// Enclave Shield evidence for the attested DNS-01 responder (relay/dns-relay.js, DNS_CHALLENGE_AUTH=attested): an owner who
// committed a deployment to an Enclave Shield partition (isolation.require "hyperv-partition-per-app", enforced by the
// measured Shield-direct front: isolation/m2/front/shield_direct.go) can name a responder that accepts its guest's
// in-guest ACME pushes. OFF unless the responder's operator pins a Shield policy (ATTESTED_SHIELD_POLICY): a responder
// configured for SEV-SNP measurements never accepts this evidence, and this adapter never accepts an SNP document.
//
// What a Shield push must prove, in addition to everything an SNP push must (dns-challenge-attested.mjs pushPreconditions:
// fields, window, value, the deployment and owner's alias in this zone, possession of the named key, a document whose
// nonce is this very push):
//   1. the document is the m3 monitor's Hyper-V format (hyperv-partition-domain/v1, tier T0-hv) and carries the guest's
//      own OpenHCL VBS report;
//   2. that report verifies under the IDKS of a HOST SESSION THIS RESPONDER CHALLENGED ITSELF (shield-host-session.mjs:
//      its own nonce, its own EK/AK credential, the host's TPM quote and replayed production boot log, the registry
//      endpoint and its operator's signature), and binds Bind2(the named key, the push nonce, the stated RuntimeID) ||
//      the stated AppID;
//   3. the report's VBS launch digest and RuntimeID are an image pair, and the TPM/platform a pair, the operator's Shield
//      policy admits (relay/shield-app-policy.mjs verifyShieldAppPolicy, the relay's own rule; debug off, VTL2 guest).
// Like the SNP path, it does not read the chain: the pinned measured image's front verified the owner, lease, exact
// package and the Shield tier against its own RPC quorum before it pushed. Every verdict says tier hv-node / T0-hv,
// hostExcluded false: this is not SEV-SNP operator exclusion.
//
// Host sessions: POST /v1/shield-session/challenge then /v1/shield-session/attest (the node's operator drives them with its
// TPM; windows/node/shield-sessions.mjs). A session is kept for sessionLifeMs (10 min) and re-made, one per host, at most
// maxSessions in all and at most maxLivePerEk per TPM endorsement key (so filling the responder takes that many distinct
// genuine TPMs, not one TPM registering many endpoints); a host re-attesting replaces only its own session.
// A push is tried against EVERY live session, newest first (bounded by maxSessions): the guest's IDKS-signed report is
// the only authenticator the unchanged wire format carries, and each session verifies only reports under its own boot's
// IDKS, so no session's position can make another host's push pass or fail. The search is exact and cheap: each session
// keeps the IDKS its authenticated boot log names (read at attest, as vbs-app-verify.mjs reads it), the report is checked
// against it with the very function and inputs the full verification uses (vbs-vm-report.mjs), and only a session whose
// IDKS signed the report runs the full host + app verification (verifyShieldAppPolicy). Every report check but the
// signature is the same for every session, so a report that fails one of those is refused once, not per session. The matched host's registry entry is
// re-read (one agreed read, shared by concurrent pushes) once it is older than registryRecheckMs: an agreed entry that
// no longer names this endpoint and operator, or is inactive, ends the session (403); no quorum is 503 and the session
// stands until its own expiry - an outage is not a revocation.
//
// Request bounds (handle): each route's body may be as large as the verifier itself accepts and no larger - challenge
// SHIELD_CHALLENGE_MAX_BYTES (an EK and a full chain of the TPM verifier's maximum certificates), attest
// SHIELD_ATTEST_MAX_BYTES (the session module's own rad.body ceiling) - refused by Content-Length before reading and
// counted while streaming; at most maxConcurrentChallenges / maxConcurrentAttests are held (arrival through verification),
// the next is 503 before anything is read; a body must arrive within its read deadline. Every slot is given back on every
// outcome: refused, malformed, oversized, slow, disconnected, failed or answered.
import { pushPreconditions } from "./dns-challenge-attested.mjs";
import { createHostSessions, fail, sha256hex } from "./shield-host-session.mjs";
import { keccak256 } from "viem";
import { verifyShieldAppPolicy, platformsValid } from "./shield-app-policy.mjs";
import { runtimeId, validateRuntimeIdentity, bind2 } from "./vbs-runtime.mjs";
import { parseTcgLog, vsmKey } from "./vbs-tcglog.mjs";
import { rsaKeyFromModulus } from "./vbs-verify.mjs";
import { verifyVbsVmReport } from "./vbs-vm-report.mjs";
import { vbsAppReportEnvelope, vbsAppUserData } from "./vbs-app-core.mjs";
import { VBS_MAX_CERT_BYTES, VBS_MAX_CHAIN_CERTS, VBS_MAX_TPMT_PUBLIC_BYTES } from "./vbs-tpm.mjs";

export const SHIELD_DOC_FORMAT = "hyperv-partition-domain/v1";
export const SHIELD_DOC_TIER = "T0-hv";
const HEX = /^[0-9a-f]{64}$/;
const deny = (status, why) => ({ ok: false, status, why });
// the base64 length the session module accepts for a `cap`-byte field (shield-host-session.mjs b64)
const b64Chars = (cap) => 4 * Math.ceil(cap / 3) + 4;
const ENVELOPE_BYTES = 8 * 1024;                            // JSON keys, quoting, hostId, endpoint, hostChallenge, session, signature
/** challenge: { hostId, endpoint, hostChallenge, keys: { ek, ekChain[<= VBS_MAX_CHAIN_CERTS], aikPub, aikName } } at the verifier's maxima */
export const SHIELD_CHALLENGE_MAX_BYTES = b64Chars(VBS_MAX_CERT_BYTES) * (1 + VBS_MAX_CHAIN_CERTS) + b64Chars(VBS_MAX_TPMT_PUBLIC_BYTES) + b64Chars(34) + ENVELOPE_BYTES;
/** attest: { session, rad: { format, body (<= 12 MiB of base64: shield-host-session.mjs verify), transportKey }, operatorSig } */
export const HVNODE_RAD_BODY_MAX_CHARS = 12 * 1024 * 1024;
export const SHIELD_ATTEST_MAX_BYTES = HVNODE_RAD_BODY_MAX_CHARS + ENVELOPE_BYTES;
export const MAX_LIVE_PER_EK = 4;
const LIMITS = { maxConcurrentChallenges: [1, 64], maxConcurrentAttests: [1, 16], challengeReadMs: [1000, 120_000], attestReadMs: [1000, 600_000],
                 maxSessions: [1, 256], maxLivePerEk: [1, 256], registryRecheckMs: [5000, 600_000], sessionLifeMs: [60_000, 3_600_000] };

// ---- the host-identity chain read (dns-relay.js ATTESTED_SHIELD_PROFILE) -------------------------------------------------
// The registry's get() layouts this responder decodes, by registrySchema (contracts/EnclaveRegistry.sol: every revision
// APPENDS fields, so endpoint/operator/active keep their offsets; 4 is the deployed Base registry, 5 is source HEAD).
const V4 = [["endpoint", "string"], ["repo", "string"], ["measurement", "bytes32"], ["operator", "address"], ["registeredAt", "uint64"], ["lastSeen", "uint64"],
  ["active", "bool"], ["cpuPricePerSec6", "uint64"], ["gpuPricePerSec6", "uint64"], ["proofKey", "address"], ["payoutWallet", "address"]];
export const REGISTRY_GET_LAYOUTS = Object.freeze({ 4: V4, 5: [...V4, ["caps", "uint64"], ["region", "string"]] });
const getAbi = (fields) => [{ type: "function", name: "get", stateMutability: "view", inputs: [{ type: "bytes32" }],
  outputs: [{ type: "tuple", components: fields.map(([name, type]) => ({ name, type })) }] }];
const SCHEMA_ABI = [{ type: "function", name: "registrySchema", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] }];
const reverted = (e) => { for (let x = e, i = 0; x && i < 8; x = x.cause, i++) if (["ContractFunctionRevertedError", "ContractFunctionZeroDataError"].includes(x.name)) return true; return false; };

/** The registry pin of a reviewed authority profile (network/authority-profile.mjs parseProfile): address, runtime and schema. */
export function shieldRegistryBinding(profile) {
  const r = profile?.contracts?.registry;
  if (!r || !/^0x[0-9a-f]{40}$/.test(r.address || "") || !/^0x[0-9a-f]{64}$/.test(r.codeHash || "") || !Number.isSafeInteger(r.runtimeBytes) || r.runtimeBytes < 1)
    throw new Error("the authority profile has no registry pin");
  const schema = String(r.immutable?.registrySchema ?? "");
  if (!Object.hasOwn(REGISTRY_GET_LAYOUTS, schema)) throw new Error(`the profile's registry schema ${schema} is not one this responder decodes (${Object.keys(REGISTRY_GET_LAYOUTS).join(", ")})`);
  return Object.freeze({ address: r.address, codeHash: r.codeHash, runtimeBytes: r.runtimeBytes, schema });
}

/**
 * registryEntry for createShieldChallengeAuth from a quorum reader (windows/node/host-identity.mjs quorumReader): at ONE
 * block two distinct RPCs must report the same raw facts - the registry's runtime code hash and length, registrySchema()
 * and get(hostId) - and only then are they judged against the reviewed binding. -> { endpoint, operator, active } |
 * { refused } (an agreed fact the binding forbids: other code, another schema) ; throws when no quorum forms (an outage).
 */
export function shieldRegistryEntry({ reader, binding }) {
  if (typeof reader?.agreed !== "function" || !binding?.address) throw new Error("the Shield registry read needs a quorum reader and a reviewed binding");
  return async (hostId) => {
    if (!/^0x[0-9a-f]{64}$/.test(String(hostId))) throw new Error("exact host id required");
    const facts = await reader.agreed(async (c, blockNumber) => {
      const code = await c.getCode({ address: binding.address, blockNumber });
      if (code !== undefined && code !== null && (typeof code !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(code) || code.length > 2 + 2 * 24576)) throw new Error("malformed registry code from RPC");
      const codeHash = code && code !== "0x" ? keccak256(code) : null, runtimeBytes = code ? (code.length - 2) / 2 : 0;
      let schema;
      try { schema = String(await c.readContract({ address: binding.address, abi: SCHEMA_ABI, functionName: "registrySchema", blockNumber })); }
      catch (e) { if (!reverted(e)) throw e; schema = "!reverted"; }
      let entry = null;
      if (codeHash === binding.codeHash && schema === binding.schema) {
        const x = await c.readContract({ address: binding.address, abi: getAbi(REGISTRY_GET_LAYOUTS[schema]), functionName: "get", args: [hostId], blockNumber });
        entry = { endpoint: String(x.endpoint), operator: String(x.operator).toLowerCase(), active: x.active === true };
      }
      return { codeHash, runtimeBytes, schema, entry };
    });
    if (facts.codeHash !== binding.codeHash || facts.runtimeBytes !== binding.runtimeBytes)
      return { refused: `the registry's runtime (${facts.codeHash}, ${facts.runtimeBytes} bytes) is not the reviewed profile's ${binding.codeHash}` };
    if (facts.schema !== binding.schema) return { refused: `the registry reports schema ${facts.schema}, not the reviewed ${binding.schema}` };
    return facts.entry;
  };
}

// -> Buffer | null (null: already answered 413/408 and the connection is closing). Settles exactly once on end, error,
// close (the client went away), the cap or the deadline.
function readBody(req, res, json, cap, deadlineMs) {
  return new Promise((resolve) => {
    const chunks = []; let n = 0, done = false;
    const finish = (v) => { if (done) return; done = true; clearTimeout(timer); resolve(v); };
    const refuse = (code, body) => { chunks.length = 0; if (!res.headersSent && !res.destroyed) { res.setHeader("connection", "close"); json(code, body); } finish(null); };
    const timer = setTimeout(() => refuse(408, { error: "the request body did not arrive in time" }), deadlineMs);
    req.on("data", (c) => { if (done) return; n += c.length; if (n > cap) return refuse(413, { error: "body too large" }); chunks.push(c); });
    req.on("end", () => finish(Buffer.concat(chunks)));
    req.on("error", () => finish(null));
    req.on("close", () => finish(null));
  });
}

/** This responder's party id in a host's attach signature: bound to its zone, so a session cannot be replayed to another. */
export { shieldResponderId } from "../windows/node/shield-verdict.mjs";
import { shieldResponderId } from "../windows/node/shield-verdict.mjs";

/** The operator's Shield pins, validated: the relay's enclave-shield-app-policy/1 rules for TPM roots, platforms and images. */
export function validateShieldResponderPolicy(policy) {
  if (!policy || policy.schema !== "enclave-shield-app-policy/1") throw new Error("ATTESTED_SHIELD_POLICY must be an enclave-shield-app-policy/1 document");
  if (!policy.ekRoots || typeof policy.ekRoots !== "string") throw new Error("the Shield policy needs pinned TPM EK roots (ekRoots)");
  if (!platformsValid(policy.platforms)) throw new Error('the Shield policy needs explicit TPM/firmware platform pins, or "attested"');
  if (!Array.isArray(policy.images) || !policy.images.length || policy.images.some((i) => !HEX.test(i?.measurement || "") || !HEX.test(i?.runtimeId || "")))
    throw new Error("the Shield policy needs explicit (VBS launch digest, RuntimeID) image pairs");
  return policy;
}

/** Is this push body a Shield push? (Only the format decides which adapter judges it; each refuses the other's.) */
export function isShieldPush(raw) {
  try { return JSON.parse(Buffer.from(raw).toString("utf8"))?.attestation?.format === SHIELD_DOC_FORMAT; } catch { return false; }
}

/**
 * createShieldChallengeAuth({ policy, zone, registryEntry, recoverSigner, now, sessionLifeMs, maxSessions,
 *                             maxConcurrentChallenges, maxConcurrentAttests, challengeReadMs, attestReadMs })
 *   -> { party, challenge, attest, authorize, handle, sessions(), inflight() }
 */
export function createShieldChallengeAuth({ policy, zone, registryEntry, recoverSigner, now = Date.now, sessionLifeMs = 10 * 60_000, maxSessions = 128,
                                            maxLivePerEk = MAX_LIVE_PER_EK, registryRecheckMs = 60_000,
                                            maxConcurrentChallenges = 8, maxConcurrentAttests = 2, challengeReadMs = 30_000, attestReadMs = 120_000,
                                            log = () => {} }) {
  validateShieldResponderPolicy(policy);
  const opts = { maxConcurrentChallenges, maxConcurrentAttests, challengeReadMs, attestReadMs, maxSessions, maxLivePerEk, registryRecheckMs, sessionLifeMs };
  for (const [k, [min, max]] of Object.entries(LIMITS))
    if (!Number.isSafeInteger(opts[k]) || opts[k] < min || opts[k] > max) throw new Error(`${k} must be an integer in ${min}..${max}`);
  if (typeof registryEntry !== "function") throw new Error("a Shield responder needs its own registry read (registryEntry)");
  const party = shieldResponderId(zone);
  // an entry admits a host only while it is active and names this endpoint for this operator; anything the chain read
  // refused (other registry code, another schema) admits nothing and is logged
  const entry = async (hostId) => {
    const e = await registryEntry(hostId);
    if (e?.refused) { log(`[dns-relay] shield registry read refused: ${String(e.refused).slice(0, 200)}`); return null; }
    return e && e.active === true && typeof e.endpoint === "string" ? e : null;
  };
  const hosts = createHostSessions({ party, ekRoots: policy.ekRoots, ekRootPins: policy.ekRootPins, registryEntry: entry, recoverSigner, now });
  const live = new Map();                                   // hostId -> { hostSession, until, endpoint, operator, ek, checkedAt, rechecking }
  const sweep = () => { const t = now(); for (const [k, s] of live) if (s.until <= t) live.delete(k); };

  async function attest(body) {
    const s = await hosts.verify(body);
    sweep();
    if (!live.has(s.hostId) && live.size >= maxSessions) throw fail(429, "too many live Shield host sessions on this responder");
    const ek = sha256hex(s.ekCert);
    let onEk = 0;
    for (const [k, x] of live) if (k !== s.hostId && x.ek === ek) onEk++;
    if (onEk >= maxLivePerEk) throw fail(429, `this TPM already holds ${maxLivePerEk} live host sessions on this responder`);
    const until = now() + sessionLifeMs;
    live.delete(s.hostId);                                  // newest last: a re-made session replaces only the host's own previous boot
    // the IDKS this boot's TPM-authenticated log names (null: unknown, so this session is always fully verified)
    let idksKey = null;
    try { const k = vsmKey(parseTcgLog(Buffer.from(s.hostSession.evidence.log, "base64")).events, "IDKS"); if (k) idksKey = rsaKeyFromModulus(k.modulus, k.exponent); }
    catch { idksKey = null; }
    live.set(s.hostId, { hostSession: s.hostSession, until, endpoint: s.endpoint, operator: s.signer, ek, checkedAt: now(), rechecking: null, idksKey,
                         idks: s.host.boot?.idksModulusSha256 || null });
    log(`[dns-relay] shield host session ${s.endpoint} until ${new Date(until).toISOString()}`);
    return { ok: true, party, until, tier: "hv-node", hostExcluded: false, idksModulusSha256: s.host.boot?.idksModulusSha256 || null };
  }

  /** -> { ok: true, name, value, deploymentId, op, verdict } | deny. Never throws. */
  async function authorize({ raw, sig, method }) {
    try {
      const pre = pushPreconditions({ raw, sig, method, zone, now });
      if (!pre.ok) return pre;
      const { p, spki, doc, nonce } = pre;
      if (doc.format !== SHIELD_DOC_FORMAT || doc.tier !== SHIELD_DOC_TIER) return deny(403, "the attestation is not an Enclave Shield (T0-hv) document");
      const fault = validateRuntimeIdentity(doc.runtime);
      if (fault) return deny(403, `the attestation states no admissible runtime: ${String(fault).slice(0, 120)}`);
      const ridBytes = runtimeId(doc.runtime), rid = ridBytes.toString("hex");
      sweep();
      const sessions = [...live.entries()].reverse();      // every admitted session (<= maxSessions), newest first
      if (!sessions.length) return deny(403, "no live Shield host session on this responder: the host must attest its TPM boot here first");
      // the report check verifyShieldAppPolicy -> verifyVbsAppEvidence runs, with its inputs: the admitted images for this
      // runtime, this push's binding and app, the policy's minimum SVN
      const measurements = policy.images.filter((i) => i.runtimeId === rid).map((i) => i.measurement);
      if (!measurements.length) return deny(403, "Shield attestation refused: runtime has no admitted image");
      let envelope;
      try { const e = vbsAppReportEnvelope(doc); if (e.reason) return deny(403, `Shield attestation refused: ${e.reason}`); envelope = e.envelope; }
      catch (e) { return deny(403, `Shield attestation refused: ${String(e?.message || e).slice(0, 160)}`); }
      const reportCheck = { envelope, expectedUserData: vbsAppUserData(bind2(spki, nonce, ridBytes), doc.appSha256),
                            allowedMeasurements: measurements, minimumGuestSvn: policy.minimumGuestSvn ?? 0 };
      let why = "VBS report signature failed: no live host session's IDKS signed this report";
      for (const [hostId, s] of sessions) {
        if (s.idksKey) {
          const r = verifyVbsVmReport({ ...reportCheck, idksPublicKey: s.idksKey });
          if (!r.ok && !/signature/i.test(r.reason || "")) return deny(403, `Shield attestation refused: ${String(r.reason).slice(0, 200)}`);   // the same for every session
          if (!r.ok) continue;                               // not this boot's IDKS
        }
        // the relay's own Shield rule: the report under THIS session's IDKS, Bind2(key, push nonce, RuntimeID) || AppID,
        // an admitted (launch digest, RuntimeID) pair and platform; app and runtime are the document's own, as the SNP
        // path takes the report's app half (the pinned image's front authorized them)
        const v = verifyShieldAppPolicy({ doc, handshakeSpki: spki, nonce, expectedAppSha256: doc.appSha256, expectedRuntimeId: rid,
          hostSession: s.hostSession }, policy);
        if (!v.ok) { why = v.reason || why; continue; }
        const fresh = await current(hostId, s);
        if (fresh === "revoked") return deny(403, "the host's registry entry no longer names this endpoint and operator as active: its session ended");
        if (fresh === "unavailable") return deny(503, "the host's registry entry could not be re-read (no chain quorum); retry");
        return { ok: true, name: p.name, value: p.value, deploymentId: p.deploymentId, op: p.op,
                 verdict: "shield-attested", tier: "hv-node", hostExcluded: false, measurement: v.measurement };
      }
      return deny(403, `Shield attestation refused: ${String(why).slice(0, 200)}`);
    } catch {
      return deny(500, "verification error");
    }
  }

  // the matched host's registry entry, re-read when older than registryRecheckMs -> "ok" | "revoked" | "unavailable"
  async function current(hostId, s) {
    if (now() - s.checkedAt < registryRecheckMs) return "ok";
    s.rechecking ||= (async () => {
      let e;
      try { e = await entry(hostId); } catch { return "unavailable"; }
      if (!e || e.endpoint !== s.endpoint || String(e.operator).toLowerCase() !== s.operator) {
        if (live.get(hostId) === s) live.delete(hostId);
        log(`[dns-relay] shield host session ${s.endpoint} ended: the registry no longer names it for its operator`);
        return "revoked";
      }
      s.checkedAt = now();
      return "ok";
    })().finally(() => { s.rechecking = null; });
    return s.rechecking;
  }

  // the routes, each with its body bound, its admission count and its read deadline
  const routes = {
    "/v1/shield-session/challenge": { run: (b) => hosts.challenge(b), cap: SHIELD_CHALLENGE_MAX_BYTES, max: maxConcurrentChallenges, readMs: challengeReadMs, held: 0 },
    "/v1/shield-session/attest": { run: attest, cap: SHIELD_ATTEST_MAX_BYTES, max: maxConcurrentAttests, readMs: attestReadMs, held: 0 },
  };
  const answer = (res, json, code, body) => { if (!res.headersSent && !res.destroyed) json(code, body); };

  /** POST /v1/shield-session/{challenge,attest} for node:http; true when it handled the request. */
  async function handle(req, res, json) {
    const path = new URL("http://x" + req.url).pathname;
    const route = Object.prototype.hasOwnProperty.call(routes, path) ? routes[path] : null;
    if (!route) return false;
    if (req.method !== "POST") { req.resume(); json(405, { error: "POST only" }); return true; }
    const declared = req.headers["content-length"];
    if (declared !== undefined && !(Number(declared) <= route.cap)) { res.setHeader("connection", "close"); json(413, { error: "body too large" }); return true; }
    // admission: decided now, before a byte is read; the slot is held until the answer, whatever it is
    if (route.held >= route.max) { res.setHeader("retry-after", "1"); res.setHeader("connection", "close"); json(503, { error: "busy" }); return true; }
    route.held++;
    try {
      const raw = await readBody(req, res, json, route.cap, route.readMs);
      if (raw === null) return true;
      let body; try { body = JSON.parse(raw.toString("utf8") || "{}"); } catch { answer(res, json, 400, { error: "body is not JSON" }); return true; }
      try { answer(res, json, 200, await route.run(body)); }
      catch (e) { answer(res, json, Number.isInteger(e?.status) ? e.status : 500, { error: String(e?.message || e).slice(0, 800) }); }
      return true;
    } finally { route.held--; }
  }
  return { party, challenge: (b) => hosts.challenge(b), attest, authorize, handle, sessions: () => { sweep(); return live.size; },
           inflight: () => ({ challenge: routes["/v1/shield-session/challenge"].held, attest: routes["/v1/shield-session/attest"].held }) };
}
