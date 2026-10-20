// A custodian OPERATOR's opt-in to Enclave Shield release recipients (custody/v2/shield-evidence.mjs), as MEASURED
// configuration: scripts/build-custodian-v2.mjs --shield-recipients <file> validates it here and bakes it into the
// bundle's MEASURED constant (custody/v2/build-config.mjs), and the daemon validates it again here before it installs the
// adapter (custody/v2/daemon.mjs). Absent by default, and then the custodian is SNP-only exactly as before.
//
// It is never read from the host: not from the fw_cfg host config, the environment, the host's /state or /receipts, or
// any fetched document. A host that could choose the TPM roots could vouch for a host session of its own making.
//
//   {
//     "format":     "enclave-custody-shield-operator/1",
//     "acceptTier": "windows-tpm-host/hv-node/T0-hv/hostExcluded:false",   the OPERATOR's explicit acknowledgement of the
//                                                                           tier (each owner still commits its own, in
//                                                                           its Shield rules: custody/v2/shield-rules.mjs)
//     "ekRoots":    "<PEM text>",   self-signed TPM EK roots and optional CA intermediates; PEM TEXT, never a path
//     "ekRootPins": ["<sha256 hex of each root's DER>"],   exactly the self-signed roots in ekRoots: no more, no fewer
//     "limits": { "sessionLifeSec", "maxSessions", "maxPendingChallenges", "maxAttestBytes", "maxConcurrentAttests" }
//   }
// Every limit is required and bounded (SHIELD_LIMITS). maxAttestBytes bounds ONLY the attest body: an hv-node frame
// carries the host's raw TCG boot log, base64 inside base64 JSON (about 1.8x the log), and the verifier itself refuses a
// log over 4 MiB (relay/vbs-tpm.mjs VBS_MAX_LOG_BYTES). 8 MiB, the hard ceiling, carries a log of about 4.4 MiB; the default
// 4 MiB carries a log of about 2.2 MiB. Every other custody route keeps its 256 KiB bound.
import { X509Certificate, createHash } from "node:crypto";
import { createShieldCustody } from "./shield-evidence.mjs";
import { SHIELD_TIER_ACK } from "./shield-rules.mjs";

export const SHIELD_OPERATOR_FORMAT = "enclave-custody-shield-operator/1";
export const SHIELD_OPERATOR_TIER_ACK = SHIELD_TIER_ACK;
export const SHIELD_ROUTE_PREFIX = "/v2/custody/shield-session";
// [min, max, default]
export const SHIELD_LIMITS = Object.freeze({
  sessionLifeSec: Object.freeze([60, 3600, 600]),
  maxSessions: Object.freeze([1, 1024, 256]),
  maxPendingChallenges: Object.freeze([1, 256, 64]),
  maxAttestBytes: Object.freeze([65536, 8 * 1024 * 1024, 4 * 1024 * 1024]),
  maxConcurrentAttests: Object.freeze([1, 4, 2]),
});
export const defaultShieldLimits = () => Object.fromEntries(Object.entries(SHIELD_LIMITS).map(([k, v]) => [k, v[2]]));
const MAX_PEM_CHARS = 256 * 1024, MAX_CERTS = 16;
const PEM_BLOCK = /-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+?)-----END CERTIFICATE-----/g;
const PEM_ONLY = /^\s*(?:-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+?-----END CERTIFICATE-----\s*)+$/;
const HEX64 = /^[0-9a-f]{64}$/;

function exactKeys(o, keys, what) {
  if (!o || typeof o !== "object" || Array.isArray(o)) throw new Error(`${what} must be an object`);
  for (const k of Object.keys(o)) if (!keys.includes(k)) throw new Error(`${what}: unknown key "${k}"`);
  for (const k of keys) if (!(k in o)) throw new Error(`${what}: "${k}" is required`);
}

/** -> the same object, normalized and frozen (throws on anything else). Shared by the build and the daemon. */
export function validateShieldOperator(cfg) {
  exactKeys(cfg, ["format", "acceptTier", "ekRoots", "ekRootPins", "limits"], "Shield recipients");
  if (cfg.format !== SHIELD_OPERATOR_FORMAT) throw new Error(`Shield recipients: format must be ${SHIELD_OPERATOR_FORMAT}`);
  if (cfg.acceptTier !== SHIELD_OPERATOR_TIER_ACK)
    throw new Error(`Shield recipients: acceptTier must be exactly "${SHIELD_OPERATOR_TIER_ACK}" (the operator's acknowledgement of this tier)`);
  const pem = cfg.ekRoots;
  // PEM TEXT ONLY: relay/vbs-verify.mjs loadTpmRoots reads a string without "-----BEGIN" as a FILE PATH
  if (typeof pem !== "string" || !pem.length || pem.length > MAX_PEM_CHARS || !PEM_ONLY.test(pem))
    throw new Error(`Shield recipients: ekRoots must be PEM text of CERTIFICATE blocks only (at most ${MAX_PEM_CHARS} characters), never a path`);
  const blocks = [...pem.matchAll(PEM_BLOCK)].map((m) => m[0]);
  if (!blocks.length || blocks.length > MAX_CERTS) throw new Error(`Shield recipients: ekRoots: 1..${MAX_CERTS} certificates`);
  const roots = new Set(), seen = new Set();
  for (const [i, b] of blocks.entries()) {
    let c;
    try { c = new X509Certificate(b); } catch (e) { throw new Error(`Shield recipients: ekRoots certificate ${i} does not parse (${e.message})`); }
    const fp = createHash("sha256").update(c.raw).digest("hex");
    if (seen.has(fp)) throw new Error(`Shield recipients: ekRoots certificate ${i} repeats another`);
    seen.add(fp);
    if (!c.ca) throw new Error(`Shield recipients: ekRoots certificate ${i} is not a CA certificate`);
    if (c.checkIssued(c) && c.verify(c.publicKey)) roots.add(fp);
  }
  if (!roots.size) throw new Error("Shield recipients: ekRoots contains no self-signed root");
  const pins = cfg.ekRootPins;
  if (!Array.isArray(pins) || !pins.length || pins.length > MAX_CERTS || !pins.every((p) => typeof p === "string" && HEX64.test(p)))
    throw new Error("Shield recipients: ekRootPins must be 64 lowercase hex sha256 pins of the roots' DER");
  if (new Set(pins).size !== pins.length) throw new Error("Shield recipients: ekRootPins repeats a pin");
  for (const p of pins) if (!roots.has(p)) throw new Error(`Shield recipients: ekRootPins ${p} pins no self-signed root in ekRoots`);
  for (const r of roots) if (!pins.includes(r)) throw new Error(`Shield recipients: the root ${r} in ekRoots is not pinned`);
  exactKeys(cfg.limits, Object.keys(SHIELD_LIMITS), "Shield recipients limits");
  for (const [k, [min, max]] of Object.entries(SHIELD_LIMITS)) {
    const v = cfg.limits[k];
    if (!Number.isSafeInteger(v) || v < min || v > max) throw new Error(`Shield recipients limits.${k} must be an integer in ${min}..${max}`);
  }
  return Object.freeze({ format: cfg.format, acceptTier: cfg.acceptTier, ekRoots: pem, ekRootPins: Object.freeze([...pins]),
                         limits: Object.freeze(Object.fromEntries(Object.keys(SHIELD_LIMITS).map((k) => [k, cfg.limits[k]]))) });
}

/**
 * The daemon's adapter for THIS custodian: `party` is its own committee encryption key (hex), derived from its sealed
 * state, never configured. -> null when the measured config has no Shield recipients (the default: SNP only).
 */
export function shieldCustodyFor(measuredShield, { party, now } = {}) {
  if (measuredShield === undefined || measuredShield === null) return null;
  const cfg = validateShieldOperator(measuredShield);
  const adapter = createShieldCustody({ party, ekRoots: cfg.ekRoots, ekRootPins: [...cfg.ekRootPins], ...(now ? { now } : {}),
    sessionLifeMs: cfg.limits.sessionLifeSec * 1000, maxSessions: cfg.limits.maxSessions, maxPending: cfg.limits.maxPendingChallenges });
  return Object.freeze({ ...adapter, limits: cfg.limits });
}
