// windows/node/shield-sessions.mjs - this host's TPM sessions at the DNS-01 responders its owner-committed deployments name.
//
// A Shield guest's in-guest ACME push (isolation/m2/front/acme.go, shield_direct.go) carries the guest's own VBS report;
// the owner-selected responder (relay/dns-challenge-shield.mjs) verifies it only under the IDKS of a host boot IT
// challenged: its nonce, its credential for this TPM's EK and AK, the quote and replayed log, and this host's registered
// operator's signature over the exchange. This module is the host's half of that: for each responder named by a running
// package's names.acme.challenge, keep one live session (the responder keeps it 10 minutes; this renews after 6).
//
// What it hands the responder is public evidence and a signature over a hash; the guest's push is still the guest's (the
// host cannot read or alter it: TLS to the responder ends in the guest). A responder that answers for a zone other than
// the one the package committed (its party id is bound to the zone) is refused before the TPM is asked anything.
import { createHash, randomBytes } from "node:crypto";
import { buildHvNodeFrame } from "./hvnode-evidence.mjs";
import { attachMessage, postJson, shieldResponderId } from "./shield-verdict.mjs";

const sha256hex = (b) => createHash("sha256").update(b).digest("hex");
export const RENEW_AFTER_MS = 6 * 60_000;

/** Custody v2 committee machines ({ endpoint, encKey }) -> session targets: each custodian's party id is its encryption
 *  key, and it serves the same exchange under /v2/custody/shield-session (custody/v2/shield-evidence.mjs). */
export function custodianTargets(machines) {
  const out = new Map();
  for (const m of Array.isArray(machines) ? machines : []) {
    const url = String(m?.endpoint || "").replace(/\/+$/, ""), party = String(m?.encKey || "").toLowerCase().replace(/^0x/, "");
    if (!/^https:\/\/[^\s]+$/.test(url) || !/^[0-9a-f]{64}$/.test(party)) continue;
    out.set(`${url} ${party}`, { url, party, path: "/v2/custody/shield-session" });
  }
  return [...out.values()].slice(0, 96);
}

/** The responders the running owner-committed records name: [{ url, zone }], de-duplicated, at most 16. */
export function responderTargets(records) {
  const out = new Map();
  for (const r of records) {
    const a = r?.startup?.direct ? r.startup.acme : null;
    if (!a || typeof a.challenge !== "string" || typeof a.zone !== "string" || !["running", "provisioning"].includes(r.status)) continue;
    const url = a.challenge.replace(/\/+$/, "");
    if (!/^https:\/\/[^\s]+$/.test(url)) continue;
    out.set(`${url} ${a.zone}`, { url, zone: a.zone });
  }
  return [...out.values()].slice(0, 16);
}

/** The custodians the live direct custody records' owner-committed packages name (shield-startup.mjs startup.custody
 *  .machines): each challenges this node itself before it judges that guest's release. At most 96. */
export function custodianSessionTargets(records) {
  const machines = [];
  for (const r of records) {
    const s = r?.startup;
    if (!s?.direct || s.secretsMode !== "custody-v2" || !Array.isArray(s.custody?.machines) || !["running", "provisioning", "starting"].includes(r.status)) continue;
    machines.push(...s.custody.machines);
  }
  return custodianTargets(machines);
}
/** Every session this node keeps: the responders' and the custodians', in ONE refresh (which forgets what it is not given). */
export function sessionTargets(records) {
  const all = [...records];
  return [...responderTargets(all), ...custodianSessionTargets(all)];
}

export function createResponderSessions({ hostId, endpoint, nodeKey, tpm, keysFrame, managerHealth = async () => null, platform = async () => ({}),
                                          sign, fetchImpl = globalThis.fetch, timeoutMs = 60_000, now = Date.now, log = () => {} }) {
  const live = new Map();                                    // `${url} ${zone}` -> until
  let running = false;
  // a target: { url, zone } (a DNS-01 responder: its party is bound to the committed zone) or { url, party, path } (a custodian)
  async function one({ url, zone, party: given, path = "/v1/shield-session" }) {
    const party = given ?? shieldResponderId(zone), hostChallenge = randomBytes(32).toString("hex"), keys = await keysFrame();
    const ch = await postJson(fetchImpl, `${url}${path}/challenge`, { hostId, endpoint, hostChallenge, keys }, timeoutMs);
    if (ch?.party !== party) throw new Error(given ? "the custodian answers as another party than its committee key" : `the responder answers for another zone than the committed ${zone}`);
    if (typeof ch.session !== "string") throw new Error("malformed responder challenge");
    const nonce = Buffer.from(String(ch.nonce || ""), "base64");
    if (nonce.length !== 32) throw new Error("responder nonce must be 32 bytes");
    const frame = await buildHvNodeFrame({ nonce, credentialBlob: Buffer.from(String(ch.credentialBlob || ""), "base64"),
      secret: Buffer.from(String(ch.secret || ""), "base64"), spki: nodeKey.spki, privateKey: nodeKey.privateKey, tpm,
      managerHealth: await managerHealth(), platform: await platform() });
    const operatorSig = await sign(attachMessage({ verifier: party, hostId, endpoint, nonce: nonce.toString("hex"),
      transportKeySha256: sha256hex(nodeKey.spki), ekCertSha256: sha256hex(Buffer.from(keys.ek, "base64")), hostChallenge }));
    const r = await postJson(fetchImpl, `${url}${path}/attest`, { session: ch.session, rad: frame.rad, operatorSig }, timeoutMs);
    if (r?.ok !== true || r.tier !== "hv-node" || r.hostExcluded !== false) throw new Error("the responder did not state this tier's session");
    return Number(r.until) || 0;
  }
  return {
    /** one pass over the given responders: renew what is older than RENEW_AFTER_MS; one TPM operation at a time */
    async refresh(targets) {
      if (running) return { skipped: true };
      running = true;
      const done = [], failed = [];
      try {
        const keyOf = (t) => `${t.url} ${t.zone ?? t.party}`;
        const want = new Set(targets.map(keyOf));
        for (const k of live.keys()) if (!want.has(k)) live.delete(k);
        for (const t of targets) {
          const k = keyOf(t);
          if ((live.get(k) || 0) - now() > 10 * 60_000 - RENEW_AFTER_MS) continue;
          try { live.set(k, await one(t)); done.push(t.url); }
          catch (e) { failed.push(`${t.url}: ${e.message}`); log(`shield responder session ${t.url}: ${e.message}`); }
        }
        return { done, failed };
      } finally { running = false; }
    },
    live: () => new Map(live),
  };
}
