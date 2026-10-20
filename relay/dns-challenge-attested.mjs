// Attested DNS-01 challenge authorization: what relay/dns-relay.js checks in DNS_CHALLENGE_AUTH=attested mode before it
// sets (or removes) a TXT value for a measured direct guest's in-guest ACME (isolation/m2/front/acme.go).
//
// Anyone may run this responder for any zone; an owner selects it in their startup package and points
// _acme-challenge.<host> at the alias it serves. It needs no fleet, registry, HMAC key, eligibility API, route map or
// Enclave service. A push is authorized only when ALL of these hold:
//   1. it is signed (ECDSA P-256, SHA-256, DER) over a domain-separated hash of the exact body by the key it names;
//   2. its attestation document's report binds that key and a nonce derived from this very push (judge.mjs), comes from
//      a launch measurement this responder's operator pinned, and its HOST_DATA is the deployment the push names;
//   3. the name is exactly _acme-challenge.<label>.<zone>, where label commits to that deployment AND its owner
//      (sdk/bootstrap/package.mjs challengeLabel), so an ownership change moves the alias;
//   4. the value has the dns-01 shape, and the timestamp is within 300 s.
// The guest's report says its own measured code verified the owner, lease and startup commitment against its chain
// quorum before asking; this responder does not re-read the chain. Its trust is the pinned measurements' code.
import { createHash, createPublicKey, verify as verifySig } from "node:crypto";

export const PUSH_NONCE_PREFIX = "enclave-acme-push-v1\n";
export const PUSH_SIG_PREFIX = "enclave-acme-push-sig-v1\n";
const FIELDS = ["v", "op", "name", "value", "deploymentId", "owner", "ts", "spki", "attestation"];
const ACCEPT = { trusted: ["attested", "no-tcb-policy"], "lab-unsigned": ["attested", "no-tcb-policy", "unauthenticated"] };

// Identical to sdk/bootstrap/package.mjs challengeLabel and isolation/m2/bootstrap ChallengeLabel (the relay ships
// without the SDK tree, so it is restated here and cross-checked by test/dns-relay-attested.test.mjs).
export function challengeLabel(deploymentId, owner) {
  if (!/^0x[0-9a-f]{64}$/.test(deploymentId) || /^0x0{64}$/.test(deploymentId) ||
      !/^0x[0-9a-fA-F]{40}$/.test(owner) || /^0x0{40}$/.test(owner)) throw new Error("challenge label needs a deployment and owner");
  return createHash("sha256").update(Buffer.concat([Buffer.from("enclave-acme-alias-v1\0"), Buffer.from(deploymentId.slice(2), "hex"),
    Buffer.from(owner.slice(2).toLowerCase(), "hex")])).digest("hex").slice(0, 32);
}

export function pushNonce(p) {
  return createHash("sha256").update(PUSH_NONCE_PREFIX + [p.v, p.op, p.name, p.value, p.deploymentId, p.owner, p.ts, p.spki].join("\n")).digest();
}

// parseMeasurements: the operator's explicit pin list (96-hex SNP launch digests, comma separated). Empty = fatal.
export function parseMeasurements(text) {
  const list = String(text || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (!list.length || list.length > 64 || list.some((m) => !/^[0-9a-f]{96}$/.test(m))) throw new Error("ATTESTED_MEASUREMENTS must list 1..64 96-hex launch measurements");
  return new Set(list);
}

const deny = (status, why) => ({ ok: false, status, why });

// pushPreconditions -> { ok: true, p, spki, doc, nonce } | deny(...). Never throws. Everything a push must satisfy whatever
// hardware attests it: exact fields, version/op/method, the ±300 s window, the dns-01 value, the deployment and owner's
// alias in this zone, possession of the named canonical P-256 key, and an attestation document for that key whose nonce
// is this very push. Shared by the SNP path below and the Enclave Shield adapter (dns-challenge-shield.mjs).
export function pushPreconditions({ raw, sig, method, zone, now = Date.now }) {
  try {
    let p;
    try { p = JSON.parse(raw.toString("utf8")); } catch { return deny(400, "bad_json"); }
    if (!p || typeof p !== "object" || Array.isArray(p) || Object.keys(p).length !== FIELDS.length || !FIELDS.every((k) => Object.hasOwn(p, k)))
      return deny(400, "the push must carry exactly the attested push fields");
    if (p.v !== 1 || (p.op === "set") !== (method === "POST") || !["set", "delete"].includes(p.op) || !["POST", "DELETE"].includes(method))
      return deny(400, "version, op and HTTP method must agree");
    if (!Number.isSafeInteger(p.ts) || Math.abs(now() / 1000 - p.ts) > 300) return deny(401, "push timestamp outside the ±300s window");
    if (typeof p.value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(p.value)) return deny(400, "value is not a dns-01 digest");
    if (typeof p.deploymentId !== "string" || typeof p.owner !== "string") return deny(400, "deployment and owner required");
    let label;
    try { label = challengeLabel(p.deploymentId, p.owner); } catch (e) { return deny(400, e.message); }
    if (p.name !== `_acme-challenge.${label}.${zone}`) return deny(403, "the name is not this deployment and owner's alias in this zone");
    // 1. proof of possession of the named key
    if (typeof p.spki !== "string" || typeof sig !== "string" || p.spki.length > 512 || sig.length > 256) return deny(401, "key and signature required");
    const spki = Buffer.from(p.spki, "base64");
    let key;
    try { key = createPublicKey({ key: spki, format: "der", type: "spki" }); } catch { return deny(401, "the named key does not parse"); }
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1" || spki.toString("base64") !== p.spki)
      return deny(401, "the named key is not a canonical P-256 SPKI");
    const signed = Buffer.concat([Buffer.from(PUSH_SIG_PREFIX), raw]);
    if (!verifySig("sha256", signed, { key, dsaEncoding: "der" }, Buffer.from(sig, "base64"))) return deny(401, "the push is not signed by the named key");
    // 2. an attestation document for the named key, whose nonce is this very push
    const doc = p.attestation;
    if (!doc || typeof doc !== "object" || typeof doc.report !== "string" || doc.transportKey !== p.spki) return deny(403, "no hardware attestation for the named key");
    const nonce = pushNonce(p);
    if (doc.nonce !== nonce.toString("hex")) return deny(403, "the attestation does not bind this push");
    if (typeof doc.appSha256 !== "string" || !/^[0-9a-f]{64}$/.test(doc.appSha256)) return deny(403, "the attestation names no app");
    return { ok: true, p, spki, doc, nonce };
  } catch {
    return deny(500, "verification error");
  }
}

// authorizePush -> { ok: true, name, value, deploymentId } | { ok: false, status, why }. Never throws.
//   raw        the exact request body (Buffer); sig the x-attested-sig header; method POST | DELETE
//   zone       this responder's challenge zone; measurements a Set from parseMeasurements
//   mode       judge mode: "trusted" (production) or "lab-unsigned" (explicit lab diagnostic: no AMD chain)
//   judge      isolation/m2/judge.mjs judge (injected so the relay loads it only in this mode)
export async function authorizePush({ raw, sig, method, zone, measurements, mode = "trusted", minTcb, kds = true, judge, now = Date.now }) {
  try {
    if (!ACCEPT[mode]) return deny(500, "unknown judge mode");
    const pre = pushPreconditions({ raw, sig, method, zone, now });
    if (!pre.ok) return pre;
    const { p, spki, doc, nonce } = pre;
    const report = Buffer.from(doc.report, "base64");
    const measurement = report.length >= 0xc0 ? report.subarray(0x90, 0xc0).toString("hex") : "";
    if (!measurements.has(measurement)) return deny(403, "the launch measurement is not pinned by this responder");
    // the app half is the report's own (any owner-authorized app the measured front runs); host_data must be THIS deployment
    const v = await judge(doc, spki, nonce, { measurement, appSha: doc.appSha256, mode, kds, hostData: p.deploymentId,
      ...(minTcb !== undefined ? { minTcb } : {}) });
    if (!ACCEPT[mode].includes(v.verdict) || (minTcb !== undefined && v.verdict !== "attested"))
      return deny(403, `attestation ${v.verdict}: ${String(v.reasons?.at(-1) || "").slice(0, 160)}`);
    return { ok: true, name: p.name, value: p.value, deploymentId: p.deploymentId, op: p.op, verdict: v.verdict };
  } catch (e) {
    return deny(500, "verification error");
  }
}
