// A Shield host session that THIS party challenged itself: the two-round exchange the Enclave relay runs at an hv-node
// attach (relay/tunnel.js vbs-keys / attest), over plain HTTPS, for any party that must later verify a Shield guest's VBS
// report - an independent market verifier (shield-independent-verifier.mjs), an owner-selected DNS-01 responder
// (dns-challenge-shield.mjs), a custodian. What comes out is the same `hostSession` object the relay's tunnel keeps, and
// verifyVbsAppEvidence accepts only that: the guest report's signer (IDKS) is read from THIS session's TPM-authenticated
// log, never from the report or the host's word.
//
//   challenge(body)  { hostId, endpoint, hostChallenge, keys: { ek, ekChain?, aikPub, aikName } }
//                 -> { session, nonce (b64), appNonce (hex), credentialBlob, secret, party }
//                    a credential minted for that EK and AK name (vbs-credential.mjs makeCredential); single use, 60 s.
//                    ONLY for an EK certificate that chains to one of THIS party's pinned roots (the same anchors attest
//                    uses; keys.ekChain supplies intermediates only, never an anchor), that is a leaf (not a CA) naming an
//                    on-die TPM manufacturer (attest's own two EK checks): a self-signed, other-CA, CA-as-leaf or
//                    non-TPM certificate is refused (403) before any pending entry or credential exists, and one EK holds
//                    at most MAX_PENDING_PER_EK pending challenges
//   verify(body)     { session, rad: windows-hv-node/v1 frame, operatorSig }
//                 -> { hostSession, host (verifyHvNodeEvidence's verdict), hostId, endpoint, spki, ekCert, hostChallenge,
//                      nonce, appNonce }
//                    the attach (EK chain to the pinned TPM roots, credential, quote over this nonce bound to the transport
//                    key, replayed log, production boot policy, possession), then identity: the registry entry for
//                    keccak256(endpoint) names this endpoint and its registered operator signed this exchange
//                    (windows/node/shield-verdict.mjs attachMessage, with `party` in the verifier field).
// Failures throw an Error with `status` (HTTP). Nothing here is a verdict about any app.
import { randomBytes, createHash, X509Certificate } from "node:crypto";
import { keccak256, toBytes } from "viem";
import { ekPublicFrom, makeCredential } from "./vbs-credential.mjs";
import { tpmNameOf, loadTpmRoots, verifyEkChain, VBS_MAX_CERT_BYTES, VBS_MAX_CHAIN_CERTS, VBS_MAX_TPMT_PUBLIC_BYTES } from "./vbs-verify.mjs";
import { verifyHvNodeEvidence, HVNODE_FORMAT } from "./hvnode-verify.mjs";
import { tpmManufacturerOf, TPM_MANUFACTURERS_ON_DIE } from "./vbs-tpm.mjs";
import { attachMessage } from "../windows/node/shield-verdict.mjs";

const HEX32 = /^[0-9a-f]{64}$/;
// at most this many live pending challenges per EK certificate: a genuine certificate replayed by someone without its TPM
// holds no more than this, so filling maxSessions takes that many distinct genuine on-die EKs
export const MAX_PENDING_PER_EK = 2;
export const sha256hex = (b) => createHash("sha256").update(b).digest("hex");
export const b64 = (v, cap) => { if (typeof v !== "string" || !v.length || v.length > 4 * Math.ceil(cap / 3) + 4) return null; const b = Buffer.from(v, "base64"); return b.length && b.length <= cap ? b : null; };
export const fail = (status, message) => Object.assign(new Error(message), { status });

/**
 * createHostSessions({ party, ekRoots, ekRootPins, registryEntry, recoverSigner, now, sessionTtlMs, maxSessions })
 *   party          32-byte hex identity of the verifying party (its key id); the operator's attach signature names it
 *   ekRoots        PEM bundle of the TPM roots THIS party pins (ekRootPins: optional sha256 pins). Construction fails
 *                  when no pinned root remains: the same anchors relay/hvnode-verify.mjs derives at attest
 *   registryEntry  async (hostId) -> { endpoint, operator } (an agreeing chain read the party trusts), or null to DEFER
 *                  identity: verify() then returns the recovered `signer`, and the caller must bind it to the registry
 *                  operator of that endpoint from its own agreed read before trusting the session (custody/v2/shield-evidence.mjs
 *                  does, at each release, from the release's own chain state)
 *   recoverSigner  async (message, signature) -> address
 */
export function createHostSessions({ party, ekRoots, ekRootPins, registryEntry, recoverSigner, now = Date.now, sessionTtlMs = 60_000, maxSessions = 64 }) {
  if (!HEX32.test(String(party || ""))) throw new Error("a host session needs the verifying party's 32-byte id");
  if (!ekRoots) throw new Error("a host session needs pinned TPM EK roots");
  if ((registryEntry !== null && typeof registryEntry !== "function") || typeof recoverSigner !== "function") throw new Error("a host session needs chain identity checks");
  // the anchors, derived once exactly as attest derives them (hvnode-verify.mjs normalizePolicy): the bundle's self-signed
  // roots, narrowed to ekRootPins when given; intermediates from the bundle may complete a path, never anchor one
  const trust = loadTpmRoots(ekRoots);
  if (Array.isArray(ekRootPins) && ekRootPins.length) {
    const pins = new Set(ekRootPins.map((p) => String(p).toLowerCase()));
    trust.pins = trust.pins.filter((p) => pins.has(p));
  }
  if (!trust.pins.length) throw new Error("a host session needs at least one pinned TPM EK root");
  const sessions = new Map();
  const sweep = () => { const t = now(); for (const [k, s] of sessions) if (s.expires <= t) sessions.delete(k); };

  async function challenge(body = {}) {
    sweep();
    const endpoint = String(body.endpoint || ""), hostId = String(body.hostId || "").toLowerCase(), hostChallenge = String(body.hostChallenge || "");
    if (!/^https:\/\/[^\s]+$/.test(endpoint) || endpoint.endsWith("/")) throw fail(422, "endpoint must be the host's registered https URL");
    if (hostId !== keccak256(toBytes(endpoint))) throw fail(422, "hostId is not keccak256(endpoint)");
    if (!HEX32.test(hostChallenge)) throw fail(422, "hostChallenge must be 32 bytes of hex");
    const k = body.keys || {};
    const ekCert = b64(k.ek, VBS_MAX_CERT_BYTES), aikPub = b64(k.aikPub, VBS_MAX_TPMT_PUBLIC_BYTES), aikName = b64(k.aikName, 34);
    if (!ekCert || !aikPub || !aikName) throw fail(422, "keys need ek, aikPub and aikName (bounded base64)");
    const chain = Array.isArray(k.ekChain) ? k.ekChain : [];
    if (chain.length > VBS_MAX_CHAIN_CERTS || !chain.every((c) => b64(c, VBS_MAX_CERT_BYTES))) throw fail(422, "ekChain malformed");
    const wantName = tpmNameOf(aikPub);
    if (!wantName.equals(aikName)) throw fail(422, "aikName is not 0x000B || sha256(aikPub)");
    // the EK must be a genuine TPM's under THIS party's pinned roots BEFORE it may hold a pending slot or get a credential
    let leaf, extra;
    try { leaf = new X509Certificate(ekCert); extra = chain.map((c) => new X509Certificate(b64(c, VBS_MAX_CERT_BYTES))); }
    catch { throw fail(422, "ek or ekChain is not a certificate"); }
    let path;
    try { path = verifyEkChain(leaf, extra, trust, now()); } catch (e) { path = { ok: false, reason: e.message }; }
    if (!path.ok) throw fail(403, `EK certificate does not chain to a pinned TPM root: ${String(path.reason).slice(0, 200)}`);
    let mfr = null;
    try { mfr = tpmManufacturerOf(ekCert); } catch { mfr = null; }
    if (leaf.ca || !mfr || !TPM_MANUFACTURERS_ON_DIE[mfr]) throw fail(403, "the EK certificate is not an on-die TPM's endorsement certificate (a CA certificate, or no tcg tpmManufacturer AMD/Intel in its SAN)");
    const ekSha256 = sha256hex(ekCert);
    let mine = 0;
    for (const p of sessions.values()) if (p.ekSha256 === ekSha256) mine++;
    if (mine >= MAX_PENDING_PER_EK) throw fail(429, "this EK already holds its pending challenges: answer or let them expire");
    if (sessions.size >= maxSessions) throw fail(429, "verifier busy");
    const credential = randomBytes(32);
    let made;
    try { made = makeCredential(ekPublicFrom(ekCert), wantName, credential); } catch (e) { throw fail(422, `keys: ${e.message}`); }
    const session = randomBytes(24).toString("hex"), nonce = randomBytes(32), appNonce = randomBytes(32);
    sessions.set(session, { nonce, appNonce, ekCert, ekSha256, aikName: wantName, credential, hostId, endpoint, hostChallenge, expires: now() + sessionTtlMs });
    return { session, nonce: nonce.toString("base64"), appNonce: appNonce.toString("hex"),
             credentialBlob: made.credentialBlob.toString("base64"), secret: made.secret.toString("base64"), party };
  }

  async function verify(body = {}) {
    const s = sessions.get(String(body.session || ""));
    sessions.delete(String(body.session || ""));          // single use, whatever follows
    if (!s || s.expires <= now()) throw fail(409, "no live verifier session (expired, consumed or never issued)");
    const rad = body.rad || {};
    if (rad.format !== HVNODE_FORMAT) throw fail(422, `rad.format must be ${HVNODE_FORMAT}`);
    if (typeof rad.body !== "string" || !rad.body || rad.body.length > 12 * 1024 * 1024) throw fail(422, "hv-node body missing or oversized");
    const spki = b64(rad.transportKey, 64);
    if (!spki) throw fail(422, "rad.transportKey missing");
    let ev; try { ev = JSON.parse(Buffer.from(rad.body, "base64").toString("utf8")); } catch { throw fail(422, "hv-node body is not JSON"); }
    const hostSession = { evidence: ev, nonce: s.nonce, transportKeySpki: spki, expectedCredential: s.credential,
                          mintedFor: { ekCert: s.ekCert, aikName: s.aikName } };
    const host = verifyHvNodeEvidence(hostSession, { ekRoots, ...(ekRootPins ? { ekRootPins } : {}) });
    if (!host.ok || !host.admissible) throw fail(403, `hv-node evidence refused: ${host.reasons.join("; ").slice(0, 600)}`);
    let reg = null;
    if (registryEntry) {
      try { reg = await registryEntry(s.hostId); } catch (e) { throw fail(503, `registry read failed: ${e.message}`); }
      if (!reg || reg.endpoint !== s.endpoint || !/^0x[0-9a-fA-F]{40}$/.test(String(reg.operator || "")) || /^0x0{40}$/i.test(reg.operator))
        throw fail(403, "the registry does not name this endpoint for this host id");
    }
    const message = attachMessage({ verifier: party, hostId: s.hostId, endpoint: s.endpoint, nonce: s.nonce.toString("hex"),
      transportKeySha256: sha256hex(spki), ekCertSha256: sha256hex(s.ekCert), hostChallenge: s.hostChallenge });
    let signer = null;
    try { signer = await recoverSigner(message, String(body.operatorSig || "")); } catch { signer = null; }
    if (!signer || !/^0x[0-9a-fA-F]{40}$/.test(String(signer))) throw fail(403, "the attach carries no operator signature");
    if (reg && String(signer).toLowerCase() !== String(reg.operator).toLowerCase()) throw fail(403, "the host's registered operator did not sign this exchange");
    return { hostSession, host, signer: String(signer).toLowerCase(), identity: reg ? "registry" : "deferred", hostId: s.hostId, endpoint: s.endpoint, spki, ekCert: s.ekCert, hostChallenge: s.hostChallenge,
             nonce: s.nonce, appNonce: s.appNonce };
  }
  return { challenge, verify, pending: () => { sweep(); return sessions.size; } };
}
