// A v2 custodian's RELEASE path (docs/security/secret-custody-v2.md §7, spec §2). It runs inside the custodian's own
// SEV-SNP guest and holds shares of the COMMITTEE key; it answers an attested guest with partial decryptions of that
// deployment's bundle, never with a share.
//
// Release decision, in order (each failure is a refusal; none is skipped, none downgrades):
//   1. well formed;  2. carries a challenge THIS custodian issued, unexpired and unused (consumed now);
//   3. chain state at one agreed block, not older than any this custodian has seen for the deployment;
//   4. a policy, not paused; policyRev / secretRev are current; committeeId / epoch are the committee's CURRENT ones, the
//      policy and the bundle name that committee, and THIS custodian holds shares in that epoch;
//   5. the bundle's label proof verifies for (chain, vault, id, secretRev, committee) - the anti-copy check (TDH2's role);
//   6. the ledger's (beneficial) owner is the policy's pinned owner;
//   7. the endpoint holds the LIVE lease, and its registered operator signed this exact release (v2 operator message);
//   8. rules parse, evidence format verified here, runtime admitted;
//   9. the platform verifier accepts the evidence for the admitted (measurement, runtime), TCB floor, VMPL,
//      report_data = v2 binding ‖ appId, HOST_DATA = the deployment id;
//  then one DLEQ-proved partial per index it holds, HPKE-sealed to the recipient key in the binding.
// Logged: deployment, endpoint, decision, reason. Never logged: shares, keys, nonces, plaintext.
import { randomBytes, timingSafeEqual } from "node:crypto";
import * as v2 from "./protocol.mjs";
import * as hpke from "../hpke.mjs";
import { id32 } from "../protocol.mjs";
import { parseRules, admittedMeasurements } from "../rules.mjs";
import { recoverOperator } from "../chain.mjs";
import { Refusal, memoryHighWater } from "../custodian.mjs";
import { runtimeId as runtimeIdOf } from "../../isolation/contract/runtime.mjs";
import { parseShieldRules, shieldAdmittedMeasurements } from "./shield-rules.mjs";
import { SHIELD_EVIDENCE_FORMAT } from "./shield-evidence.mjs";

export { Refusal, memoryHighWater };
const refuse = (status, code, message) => { throw new Refusal(status, code, message); };
const HEX32 = /^(0x)?[0-9a-f]{64}$/;
const toBytes32 = (h, what) => { if (typeof h !== "string" || !HEX32.test(h)) refuse(422, "bad_request", `${what} must be 32 bytes of lowercase hex`); return Buffer.from(h.replace(/^0x/, ""), "hex"); };
const asRev = (x, what) => { const s = String(x); if (!/^(0|[1-9][0-9]{0,18})$/.test(s)) refuse(422, "bad_request", `${what} must be a non-negative integer`); return BigInt(s); };
const ENDPOINT_RE = /^https:\/\/[a-z0-9.-]{1,253}(\/[A-Za-z0-9._~-]+){0,4}$/;
export const OPERATOR_SIG_TTL_SEC = 600;

// keys: { encPrivateKey (32 bytes) }; shares: { get(committeeId, epoch) -> [{ k, x }] | null } (the sealed state's view)
// shield: OPTIONAL (custody/v2/shield-evidence.mjs createShieldCustody), installed only by an operator who chooses to serve
// Enclave Shield recipients. It is consulted only for a Shield-format document under owner-committed Shield rules; every
// other request takes exactly the path below, unchanged.
export function createCustodianV2({ chainId, vault, encPrivateKey, shares, chain, verifiers, shield = null, highWater = memoryHighWater(),
                                    nonceTtlSec = 120, maxNonces = 10_000, maxNoncesPerClient = 64, now = () => Date.now(), log = console.log }) {
  if (!(encPrivateKey instanceof Uint8Array) || encPrivateKey.length !== 32) throw new Error("custodian: the encryption key is 32 bytes");
  if (!verifiers || typeof verifiers !== "object") throw new Error("custodian: a verifier table is required");
  const encKey = hpke.publicKeyOf(encPrivateKey);
  const encKeyHex = Buffer.from(encKey).toString("hex");
  // the host operator's attach signature names the custodian's party: it must be THIS custodian's committee key, never
  // one the host or a configuration chose (the node targets each custodian by its encKey: windows/node/shield-sessions.mjs)
  if (shield && shield.party !== encKeyHex) throw new Error("custodian: the Shield adapter's party must be this custodian's own encryption key");
  const vaultL = String(vault).toLowerCase();
  const nonces = new Map(), perClient = new Map();

  function challenge({ client = "-" } = {}) {
    const t = now();
    for (const [n, e] of nonces) if (e.exp <= t) { nonces.delete(n); perClient.set(e.client, (perClient.get(e.client) || 1) - 1); }
    if ((perClient.get(client) || 0) >= maxNoncesPerClient) refuse(429, "rate_limited", "Too many outstanding challenges from this client.");
    if (nonces.size >= maxNonces) refuse(503, "busy", "Too many outstanding challenges; retry shortly.");
    const nonce = randomBytes(32).toString("hex");
    nonces.set(nonce, { exp: t + nonceTtlSec * 1000, client });
    perClient.set(client, (perClient.get(client) || 0) + 1);
    return { encKey: encKeyHex, nonce, expiresAt: Math.floor((t + nonceTtlSec * 1000) / 1000) };
  }
  function consumeNonce(n) {
    const e = nonces.get(n);
    nonces.delete(n);
    if (e) perClient.set(e.client, Math.max(0, (perClient.get(e.client) || 1) - 1));
    if (!e || e.exp <= now()) refuse(403, "bad_challenge", "Unknown, expired or already-used challenge.");
  }

  async function decide(req) {
    // 1. shape
    if (!req || typeof req !== "object" || req.v !== 2) refuse(422, "bad_request", "A v2 custody release request is {v:2, ...}.");
    const id = String(req.id || "");
    if (!/^0x[0-9a-f]{64}$/.test(id)) refuse(422, "bad_request", "id must be a lowercase bytes32 deployment id.");
    const endpoint = String(req.endpoint || "");
    if (!/^https?:\/\/[^\s]{1,190}$/.test(endpoint)) refuse(422, "bad_request", "endpoint must be the lease holder's registered origin.");
    const committeeId = String(req.committeeId || "").toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(committeeId)) refuse(422, "bad_request", "committeeId must be bytes32.");
    const policyRev = asRev(req.policyRev, "policyRev"), secretRev = asRev(req.secretRev, "secretRev");
    const epoch = Number(req.epoch);
    if (!Number.isInteger(epoch) || epoch < 1 || epoch > 0xffffffff) refuse(422, "bad_request", "epoch must be a committee epoch.");
    const recipientKey = toBytes32(req.recipientKey, "recipientKey");
    if (!Array.isArray(req.challenges) || !req.challenges.length || req.challenges.length > v2.MAX_MACHINES) refuse(422, "bad_request", "challenges: 1..96 entries.");
    const challenges = req.challenges.map((c) => ({ encKey: toBytes32(c && c.encKey, "challenge encKey"), nonce: toBytes32(c && c.nonce, "challenge nonce") }));
    const mine = challenges.filter((c) => c.encKey.toString("hex") === encKeyHex);
    if (mine.length !== 1) refuse(403, "not_challenged", "The request carries no challenge from this custodian.");
    const op = req.operator || {};
    const opExpiry = Number(op.expiry);
    if (!req.evidence || typeof req.evidence !== "object") refuse(422, "bad_request", "evidence is required.");
    // 2. this custodian's challenge, consumed
    consumeNonce(mine[0].nonce.toString("hex"));
    // 3. agreed chain state, never older than seen
    let s;
    try { s = await chain.readRelease({ id, endpoint }); }
    catch (e) { refuse(503, e.code || "chain_unreadable", `Chain state could not be confirmed (${e.message}); retry.`); }
    const hw = highWater.get(id);
    if (hw && (s.blockNumber < BigInt(hw.block) || s.policy.policyRev < BigInt(hw.policyRev) || s.policy.secretRev < BigInt(hw.secretRev)))
      refuse(503, "chain_rollback", "The chain state read is older than state this custodian has already seen; retry.");
    // 4. policy, revisions, committee, membership
    const pol = s.policy;
    if (pol.policyRev === 0n) refuse(404, "no_policy", "This deployment has no custody policy.");
    highWater.set(id, { block: String(s.blockNumber), policyRev: String(pol.policyRev), secretRev: String(pol.secretRev) });
    if (pol.paused) refuse(403, "paused", "The owner has paused releases for this deployment.");
    if (policyRev !== pol.policyRev || secretRev !== pol.secretRev)
      refuse(409, "stale_revision", `The request names policy ${policyRev} / secrets ${secretRev}; current is ${pol.policyRev} / ${pol.secretRev}.`);
    const com = s.committee;
    if (!com || pol.committeeId !== committeeId || s.bundle.committeeId !== committeeId) refuse(409, "wrong_committee", "The request's committee is not the policy's and bundle's committee.");
    if (com.epoch !== epoch) refuse(409, "stale_epoch", `The request names epoch ${epoch}; the committee is at ${com.epoch}.`);
    if (s.bundle.secretRev !== pol.secretRev || !s.bundle.data.length) refuse(404, "no_bundle", "No bundle at this revision.");
    if (!com.machines.some((m) => m.encKey === "0x" + encKeyHex)) refuse(403, "not_member", "This custodian is not a machine of the committee's current epoch.");
    const held = shares.get(committeeId, epoch);
    if (!held || !held.length) refuse(503, "no_share", "This custodian holds no share for this epoch (a handover may be in progress).");
    // 5. the label proof: this R was made for THIS deployment
    const label = v2.labelOf({ chainId, vault: vaultL, id, secretRev, committeeId });
    let labelOk = false;
    try { labelOk = v2.verifyLabelProof(s.bundle.data, label); } catch { labelOk = false; }
    if (!labelOk) refuse(403, "bad_label_proof", "The bundle was not made for this deployment (its label proof does not verify).");
    // 6. ownership
    if (!s.lease || s.beneficialOwner !== pol.owner) refuse(403, "owner_mismatch", "The ledger no longer names the policy's owner for this deployment.");
    // 7. live lease + operator authorization of THIS release
    if (s.lease.runner !== s.endpointId || !(s.lease.leaseUntil > s.blockTimestamp)) refuse(403, "not_lease_holder", `${endpoint} does not hold a live lease for ${id}.`);
    if (!s.endpointOperator) refuse(403, "not_registered", `${endpoint} has no active registry entry.`);
    const nowSec = Math.floor(now() / 1000);
    if (!Number.isInteger(opExpiry) || opExpiry <= nowSec || opExpiry > nowSec + OPERATOR_SIG_TTL_SEC) refuse(422, "bad_operator_expiry", `operator.expiry must be within the next ${OPERATOR_SIG_TTL_SEC} s.`);
    // 8. rules, format, runtime (a Shield document: only under the operator's Shield adapter AND the owner's Shield rules)
    const isShield = req.evidence.format === SHIELD_EVIDENCE_FORMAT && !!shield;
    let rules;
    if (isShield) {
      try { rules = parseShieldRules(pol.rules); } catch (e) { refuse(403, "bad_rules", `The deployment's rules do not admit an Enclave Shield recipient: ${e.message}.`); }
    } else {
      try { rules = parseRules(pol.rules); } catch (e) { refuse(403, "bad_rules", `The deployment's rules do not parse: ${e.message}.`); }
    }
    const verify = isShield ? shield.verify : Object.prototype.hasOwnProperty.call(verifiers, req.evidence.format) ? verifiers[req.evidence.format] : null;
    if (!verify) refuse(403, "unsupported_evidence", `Evidence format ${JSON.stringify(String(req.evidence.format)).slice(0, 80)} is not one this custodian verifies.`);
    let rid;
    try { rid = runtimeIdOf(req.evidence.runtime); } catch (e) { refuse(403, "bad_runtime", e.message); }
    const allowed = isShield ? shieldAdmittedMeasurements(rules, rid.toString("hex")) : admittedMeasurements(rules, rid.toString("hex"));
    if (!allowed.length) refuse(403, "runtime_not_admitted", "The guest's runtime is not one the owner admitted.");
    let transportSpki;
    try { transportSpki = new Uint8Array(Buffer.from(String(req.evidence.transportKey || ""), "base64")); } catch { transportSpki = new Uint8Array(0); }
    let binding;
    try { binding = v2.releaseBinding({ chainId, vault: vaultL, id, policyRev, secretRev, committeeId, epoch, challenges, runtimeId: new Uint8Array(rid), transportSpki, recipientKey }); }
    catch (e) { refuse(422, "bad_request", e.message); }
    const signer = await recoverOperator(v2.operatorMessage({ chainId, vault: vaultL, id, endpoint, binding, expiry: opExpiry }), op.sig);
    if (!signer || signer !== s.endpointOperator) refuse(403, "operator_sig", "The release is not signed by the lease holder's registered operator.");
    // 9. hardware evidence
    const v = await verify({ doc: req.evidence, allowedMeasurements: allowed, minTcb: rules.minTcb, vmpl: rules.vmpl, binding,
                             appId: Buffer.from(rules.appId, "hex"), hostData: id32(id),
                             // A Shield report binds the LEDGER owner, the one the guest's own quorum reads (the row's owner: a
                             // session vault's contract for a vault-owned deployment). Authorization by the policy's owner is
                             // step 6 above, unchanged: beneficialOwnerOf(id) must still be pol.owner.
                             ...(isShield ? { owner: s.lease.owner, endpoint, endpointOperator: s.endpointOperator, rules } : {}) });
    if (!v || v.ok !== true) refuse(403, "evidence_refused", (v && v.reason) || "The evidence did not verify.");
    // the partials
    const commitments = [];
    for (let i = 0; i < com.commitments.length; i += 33) commitments.push(com.commitments.subarray(i, i + 33));
    const R = v2.parseBundle(s.bundle.data).R;
    const records = held.map(({ k, x }) => v2.partial({ k, x, R, binding, commitments }));
    const sealed = v2.sealPartials({ recipientKey, binding, encKey, records });
    return { id, endpoint, count: records.length, indices: held.map((h) => h.k), sealed, synthetic: v.synthetic === true, measurement: v.measurement };
  }

  async function release(req) {
    const id = req && typeof req.id === "string" ? req.id.slice(0, 66) : "?";
    const ep = req && typeof req.endpoint === "string" ? req.endpoint.slice(0, 120) : "?";
    try {
      const r = await decide(req);
      log(`[custodian-v2 ${encKeyHex.slice(0, 12)}] release ${id} to ${ep}: OK (indices ${r.indices.join(",")}, measurement ${String(r.measurement).slice(0, 16)}...${r.synthetic ? ", SYNTHETIC roots" : ""})`);
      return { v: 2, encKey: encKeyHex, count: r.count, sealed: Buffer.from(r.sealed).toString("base64") };
    } catch (e) {
      if (!(e instanceof Refusal)) { log(`[custodian-v2 ${encKeyHex.slice(0, 12)}] release ${id} to ${ep}: ERROR ${e.message}`); throw new Refusal(500, "internal", "Internal error."); }
      log(`[custodian-v2 ${encKeyHex.slice(0, 12)}] release ${id} to ${ep}: REFUSED ${e.code}: ${e.message}`);
      throw e;
    }
  }
  return { encKey, encKeyHex, challenge, release, _nonces: nonces,
           // the Shield host-session routes, when the operator installed the adapter (POST bodies as in shield-host-session.mjs)
           ...(shield ? { shieldChallenge: (b) => shield.challenge(b), shieldAttest: (b) => shield.attest(b), shieldLimits: shield.limits || null } : {}) };
}
export { ENDPOINT_RE };
