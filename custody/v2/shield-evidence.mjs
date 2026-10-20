// Enclave Shield release evidence for a custody v2 custodian (custody/v2/custodian.mjs `shield`). OFF unless the
// custodian's operator installs it, and then used only for a Shield-format document under owner-committed Shield rules
// (custody/v2/shield-rules.mjs). Nothing here changes the SEV-SNP path, the shares, the HPKE sealing or the committee.
//
// THE RECIPIENT EVIDENCE. The guest's front generates the recipient key R inside the guest (as on SNP) and asks the m3
// monitor for its VBS report over 64 bytes of guest input:
//     input[0:32]  = shieldReleaseInput = sha256("enclave-custody-shield-v1\n" || v2 releaseBinding (32) || owner (20))
//     input[32:64] = the AppID, written by the monitor from the code it loaded (never by the front or the host)
// v2.releaseBinding already commits chain, vault, deployment, policy and secret revisions, committee and epoch, every
// custodian's challenge, the RuntimeID, sha256(transport SPKI) and R; this adds the ledger owner the custodian read. So the
// report binds exactly: vault, deployment, owner, AppID, runtime, transport key, challenges and recipient key.
//
// THE SIGNER. The report is signed by the secure kernel's IDKS of the host's boot. A custodian trusts it only from a host
// session IT challenged (relay/shield-host-session.mjs: its own nonce, its own credential for the host's EK and AK, the
// TPM quote, the replayed production boot log, possession of the transport key), made by the host operator's signature,
// kept for sessionLifeMs, and bound at each release to the operator the release's OWN agreed chain read names for the
// lease-holding endpoint. No relay verdict, no session made for another party, and no host statement stands in.
//
// What a verdict says, always: tier hv-node / T0-hv, hostExcluded false. The host's operator and hypervisor are trusted on
// this tier; the owner accepted that by committing Shield rules. The host carries only public evidence and the sealed
// partials (HPKE to R): it never sees a share or a value.
import { createHash } from "node:crypto";
import { keccak256, toBytes } from "viem";
import { createHostSessions } from "../../relay/shield-host-session.mjs";
import { parseTcgLog, vsmKey } from "../../relay/vbs-tcglog.mjs";
import { rsaKeyFromModulus } from "../../relay/vbs-verify.mjs";
import { verifyVbsVmReport } from "../../relay/vbs-vm-report.mjs";
import { vbsAppReportEnvelope, vbsAppUserData, platformAdmitted } from "../../relay/vbs-app-core.mjs";
import { recoverOperator } from "../chain.mjs";

export const SHIELD_EVIDENCE_FORMAT = "hyperv-partition-domain/v1";
export const SHIELD_EVIDENCE_TIER = "T0-hv";
export const SHIELD_CUSTODY_DOMAIN = "enclave-custody-shield-v1\n";
export const MAX_SESSIONS_PER_EK = 4;
const ABI2 = "enclave-domain-abi/2";
const HEX64 = /^[0-9a-f]{64}$/, ADDR = /^0x[0-9a-f]{40}$/;

/** input[0:32] of a Shield custody release report (isolation/m2/custody shield.go computes the same bytes). */
export function shieldReleaseInput({ binding, owner }) {
  const b = Buffer.from(binding || []), o = String(owner || "").toLowerCase();
  if (b.length !== 32) throw new Error("the release binding is 32 bytes");
  if (!ADDR.test(o) || /^0x0{40}$/.test(o)) throw new Error("the owner is a nonzero address");
  return createHash("sha256").update(Buffer.concat([Buffer.from(SHIELD_CUSTODY_DOMAIN), b, Buffer.from(o.slice(2), "hex")])).digest();
}

/**
 * createShieldCustody({ party, ekRoots, ekRootPins, now, sessionLifeMs, maxSessions, maxPending })
 *   party       this custodian's 32-byte id (its encryption key, hex): what the host operator's attach signature names
 *   ekRoots     the TPM EK roots THIS custodian's operator pins (the measured daemon: custody/v2/shield-operator.mjs)
 *   maxPending  issued, unanswered credential challenges (each single use, 60 s)
 * -> { challenge(body), attest(body), verify(args), sessions() }
 */
export function createShieldCustody({ party, ekRoots, ekRootPins, now = Date.now, sessionLifeMs = 10 * 60_000, maxSessions = 256, maxPending = 64 }) {
  const hosts = createHostSessions({ party, ekRoots, ekRootPins, registryEntry: null, now, maxSessions: maxPending,
    recoverSigner: (message, sig) => recoverOperator(message, sig) });
  // `${hostId} ${signer}` -> { hostSession, boot, signer, endpoint, ek, until }. Identity is DEFERRED at attest (any signer
  // is accepted then, and bound to the registry only at a release), so a session is kept per (endpoint, signer): another
  // party's attest for the same endpoint, under its own TPM and key, adds its own entry and never replaces the lease
  // holder's. A release looks up only the entry made by the operator its own agreed chain read names.
  const live = new Map();
  const keyOf = (hostId, signer) => `${hostId} ${signer}`;
  const sweep = () => { const t = now(); for (const [k, s] of live) if (s.until <= t) live.delete(k); };

  async function attest(body) {
    const s = await hosts.verify(body);
    sweep();
    // The endpoint (so the hostId) is the host's claim, checked against the registry only at a release. So that one TPM
    // cannot fill the table with sessions for endpoints it does not hold, each EK keeps at most MAX_SESSIONS_PER_EK live
    // sessions: a further one evicts that EK's oldest, never another TPM's.
    const ek = createHash("sha256").update(s.ekCert).digest("hex");
    const key = keyOf(s.hostId, s.signer);
    if (!live.has(key)) {
      const mine = [...live].filter(([, v]) => v.ek === ek).sort((a, b) => a[1].until - b[1].until);
      if (mine.length >= MAX_SESSIONS_PER_EK) live.delete(mine[0][0]);
    }
    if (!live.has(key) && live.size >= maxSessions) throw Object.assign(new Error("too many live Shield host sessions"), { status: 429 });
    const until = now() + sessionLifeMs;
    live.delete(key);
    live.set(key, { hostSession: s.hostSession, boot: s.host.boot, signer: s.signer, endpoint: s.endpoint, ek, until });
    return { ok: true, party, until, tier: "hv-node", hostExcluded: false };
  }

  /** the custodian's step 9 for a Shield document -> { ok, reason?, measurement, tier, hostExcluded } */
  async function verify({ doc, allowedMeasurements, binding, appId, owner, endpoint, endpointOperator, rules }) {
    const no = (reason) => ({ ok: false, reason });
    try {
      if (!doc || doc.format !== SHIELD_EVIDENCE_FORMAT || doc.tier !== SHIELD_EVIDENCE_TIER || doc.abi !== ABI2 || typeof doc.transportKey !== "string")
        return no(`evidence must be a ${SHIELD_EVIDENCE_FORMAT} (${SHIELD_EVIDENCE_TIER}) document stating ${ABI2} and its transport key`);
      if (doc.nonce !== undefined) return no("a custody release document must not state a nonce (the challenges are bound in the report's input)");
      const app = Buffer.from(appId).toString("hex");
      if (doc.appSha256 !== app) return no("the document names another app than the rules admit");
      if (!Array.isArray(allowedMeasurements) || !allowedMeasurements.length) return no("no admitted Shield image for this runtime");
      // the host: a live session THIS custodian challenged, made by the operator the release's own chain read names
      const hostId = String(keccak256(toBytes(String(endpoint || "")))).toLowerCase();
      if (!ADDR.test(String(endpointOperator || ""))) return no("the lease holder's endpoint has no registered operator to bind a host session to");
      sweep();
      // only the session the lease holder's registered operator made (the release's own agreed chain read names it)
      const operatorL = String(endpointOperator).toLowerCase();
      const s = live.get(keyOf(hostId, operatorL));
      if (!s || s.endpoint !== endpoint || s.signer !== operatorL)
        return no("no live Shield host session from this custodian made by the lease holder's registered operator for its endpoint");
      if (!platformAdmitted(rules.platforms, s.boot)) return no("the host's TPM/platform pair is not one the owner admitted");
      // the report: under THIS boot's IDKS (from the session's TPM-authenticated log), binding exactly this release
      const key = vsmKey(parseTcgLog(Buffer.from(s.hostSession.evidence.log, "base64")).events, "IDKS");
      if (!key) return no("the host session's authenticated boot log contains no IDKS");
      const env = vbsAppReportEnvelope(doc);
      if (env.reason) return no(env.reason);
      const input = shieldReleaseInput({ binding, owner });
      const r = verifyVbsVmReport({ envelope: env.envelope, idksPublicKey: rsaKeyFromModulus(key.modulus, key.exponent),
        expectedUserData: vbsAppUserData(input, app), allowedMeasurements, minimumGuestSvn: rules.minimumGuestSvn ?? 0 });
      if (!r.ok) return no(r.reason);
      return { ok: true, measurement: r.measurement, tier: "hv-node", hostExcluded: false };
    } catch (e) { return no(String(e.message || e)); }
  }
  return { party, challenge: (b) => hosts.challenge(b), attest, verify, sessions: () => { sweep(); return live.size; } };
}
