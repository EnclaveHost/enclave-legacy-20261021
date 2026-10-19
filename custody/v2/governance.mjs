// Owner authorization for INDEPENDENT committees (no Enclave seat). A measured custodian checks these signatures itself;
// the vault never sees them. Each one names the exact chain, vault, committee and object it authorizes and expires by
// CHAIN time (the agreed block), never by the host-controlled guest clock.
//
//   plan permit   = independentPlanDigest(plan)                 signed by every founder machine's operator AND owner
//   admission     = admissionDigest(committee, machine, exp)     signed by the candidate's owner AND >= t governance voters
//   code permit   = codePermitDigest(committee, code, add, exp)  signed by ONE voter; its canonical seat then signs the
//                                                                vault's codeDigest
//
// The authorization point. Every decision is judged against ONE agreed block (chain.mjs readAuthorization): the committee,
// each host's operator and accepted owner, code activation and ERC-1271 answers together. Separate reads could combine
// an owner who consented at one block with a different owner or operator at another. The decision is the machine's
// signature (founder result, handover approval, code approval); what happens on chain afterwards is checked by the
// vault, which re-checks host bindings, code activation and seat counts but never owner consent. Ownership that changes
// after the signature is therefore not reflected in that signature; the next decision reads it again.
//
// Expiry gates only the ISSUE of a machine signature. A code approval already signed is bounded by the vault: it names
// the committee's epoch and its digest is single-use (_usedCodeDigest), not by the owner permit's expiry.
//
// Governance voters. The vault weighs approvals by SEAT. If seats come to share one owner (a transfer), that owner must
// not gain several votes: in an independent committee a voter is a distinct, accepted, non-Enclave current owner, and
// it votes only through its lowest-index current seat (its canonical seat). Seats sharing an owner keep SERVING releases
// and dealing in handovers - shares are in TEEs and the release path does not ask who owns a host - but they add no
// governance weight. Fewer than t voters freezes owner governance (admission, code) without stopping service; the
// remedy is a new committee. None of this proves operators are different organizations: it is current owner consent.
import { keccak256, encodeAbiParameters, hashMessage } from "viem";
import * as D from "./digests.mjs";
import { independentOwners } from "./admission.mjs";

export const MAX_PERMIT_SEC = 30 * 24 * 3600;
export const MAX_PERMIT_SIGNATURES = 64;
const T = (type) => ({ type });
const lc = (s) => String(s).toLowerCase();
const ZERO = /^0x0{40}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const SIG = /^0x(?:[0-9a-fA-F]{2}){65,2048}$/;
const owned = (o) => ADDRESS.test(lc(o)) && !ZERO.test(lc(o));

export const admissionDigest = ({ chainId, vault, committeeId, machine, expiresAt }) =>
  keccak256(encodeAbiParameters([T("string"), T("uint256"), T("address"), T("bytes32"), T("bytes32"), T("uint64")],
    ["enclave-custody-v2 independent admission", BigInt(chainId), lc(vault), lc(committeeId), D.machineHash(machine), BigInt(expiresAt)]));
export const codePermitDigest = ({ chainId, vault, committeeId, measurement, add, expiresAt }) =>
  keccak256(encodeAbiParameters([T("string"), T("uint256"), T("address"), T("bytes32"), T("bytes32"), T("bool"), T("uint64")],
    ["enclave-custody-v2 independent code permit", BigInt(chainId), lc(vault), lc(committeeId), lc(measurement), !!add, BigInt(expiresAt)]));
export const admissionClaims = (admission) => (Array.isArray(admission?.signatures) ? admission.signatures : []).map((x) => ({ account: x?.owner, signature: x?.signature }));

// A permit's expiry against the agreed block's timestamp: in the future, and not further than MAX_PERMIT_SEC.
export function permitLive(expiresAt, blockTimestamp) {
  return Number.isSafeInteger(expiresAt) && Number.isSafeInteger(blockTimestamp) && expiresAt > blockTimestamp && expiresAt <= blockTimestamp + MAX_PERMIT_SEC;
}

// Signatures for one snapshot. add() recovers EOA signers offline and queues an ERC-1271 check (for the claimed
// account, or for a host's owner AT THE SNAPSHOT BLOCK) only where needed; signers() answers after the read.
export function signatureBatch() {
  const checks = [], groups = [];
  return {
    checks,
    async add(digest, claims) {
      const hash = hashMessage({ raw: digest }), group = [];
      for (const c of (claims || []).slice(0, MAX_PERMIT_SIGNATURES)) {
        const signature = String(c?.signature ?? "");
        if (!SIG.test(signature)) continue;
        const account = c.account && owned(c.account) ? lc(c.account) : null, registryId = c.registryId ? lc(c.registryId) : null;
        if (!account && !registryId) continue;
        const row = { recovered: await D.recoverDigest(digest, signature), account, registryId, check: -1 };
        if (!account || row.recovered !== account) { row.check = checks.length; checks.push(account ? { account, hash, signature } : { registryId, hash, signature }); }
        group.push(row);
      }
      groups.push(group);
      return groups.length - 1;
    },
    signers(handle, snapshot) {
      const out = new Set();
      for (const r of groups[handle] || []) {
        if (r.recovered) out.add(r.recovered);
        const account = r.account || (r.registryId ? snapshot.entries?.[r.registryId]?.owner : null);
        if (r.check >= 0 && snapshot.valid?.[r.check] === true && owned(account)) out.add(lc(account));
      }
      return out;
    },
  };
}

// -> async ({ owner, digest, signature }) -> bool, outside a snapshot (CLI preflight only). EOA first, then ERC-1271.
export function ownerSignatureVerifier(chain) {
  return async ({ owner, digest, signature }) => {
    if (!owned(owner) || typeof signature !== "string" || !SIG.test(signature)) return false;
    if (await D.recoverDigest(digest, signature) === lc(owner)) return true;
    if (!chain || typeof chain.readIsValidSignature !== "function") return false;
    try { return (await chain.readIsValidSignature({ account: lc(owner), hash: hashMessage({ raw: digest }), signature })).valid === true; }
    catch { return false; }
  };
}

// The committee's current governance voters at the snapshot: owner -> canonical machine index, and the seats that add
// no vote (shared owner, unowned or inactive host, or - in an independent committee - the Enclave wallet).
export function governanceVoters(snapshot, enclaveOwner) {
  const com = snapshot.committee, voters = new Map(), silent = [];
  const independent = !com.machines.some((m) => m.enclave);
  // A legacy committee's Enclave seat already is the Enclave wallet's vote (the vault weighs it as one seat): an ordinary
  // seat later transferred to that wallet must not give it a second one.
  const firstEnclave = com.machines.findIndex((m) => m.enclave);
  if (firstEnclave >= 0) voters.set(lc(enclaveOwner), firstEnclave);
  com.machines.forEach((m, i) => {
    const e = snapshot.entries[lc(m.registryId)], o = lc(e?.owner);
    if (m.enclave) return;                                   // the legacy Enclave seat is weighed by the vault as one seat
    if (!e?.active || !owned(o) || (independent && o === lc(enclaveOwner)) || voters.has(o)) { silent.push(i); return; }
    voters.set(o, i);
  });
  return { voters, silent, independent };
}

// Candidate admission (owner-permits policy) judged at one snapshot: the candidate's current owner signed this exact
// record, and at least t current governance voters did.
export function judgeAdmission({ snapshot, machine, admission, signers, enclaveOwner }) {
  const com = snapshot.committee;
  if (!com) return { ok: false, reason: "committee not found" };
  if (com.machines.some((m) => m.enclave)) return { ok: false, reason: "owner-permit admission applies only to independent committees" };
  const e = snapshot.entries[lc(machine.registryId)], owner = lc(e?.owner);
  if (!e?.active || !owned(owner) || owner === lc(enclaveOwner)) return { ok: false, reason: "candidate has no accepted non-Enclave owner" };
  if (!Array.isArray(admission?.signatures) || !admission.signatures.length || admission.signatures.length > MAX_PERMIT_SIGNATURES) return { ok: false, reason: "owner admission signatures are required" };
  if (!permitLive(admission.expiresAt, snapshot.blockTimestamp)) return { ok: false, reason: "owner admission is expired or too long-lived" };
  if (!signers.has(owner)) return { ok: false, reason: "the candidate's own owner did not sign this admission" };
  const { voters } = governanceVoters(snapshot, enclaveOwner);
  const weight = [...voters.keys()].filter((o) => signers.has(o)).length;
  if (weight < com.t) return { ok: false, reason: `owner admission has ${weight} of ${com.t} required governance voters` };
  return { ok: true, owner, weight };
}
export function ownerPermitAdmission({ enclaveOwner }) {
  return async ({ machine, admission, snapshot, signers }) => (snapshot && signers ? judgeAdmission({ snapshot, machine, admission, signers, enclaveOwner })
    : { ok: false, reason: "no authorization snapshot" });
}

// A founder plan judged at one snapshot. ownerSigners(i): the owner-permit signers for machine i (owner-permits policy).
// -> the list of problems; empty means every operator (and owner) of this exact roster consents at this block.
export async function judgePlan({ plan, snapshot, policy, enclaveOwner, ownerSigners }) {
  const problems = [], owners = new Set(), digest = D.independentPlanDigest(plan);
  const permits = policy?.mode === "owner-permits";
  if (!permits && policy?.mode !== "owner-list") return ["no independent admission policy"];
  for (let i = 0; i < plan.machines.length; i++) {
    const e = snapshot.entries[lc(plan.machines[i].registryId)], o = lc(e?.owner);
    if (!e?.active) { problems.push(`machine ${i}: host registry entry is not active`); continue; }
    if (!owned(o) || o === lc(enclaveOwner) || (!permits && !policy.owners.includes(o))) problems.push(`machine ${i}: owner ${o} is outside the measured policy`);
    else if (owners.has(o)) problems.push(`machine ${i}: owner ${o} already holds a founder seat`);
    owners.add(o);
    if (await D.recoverDigest(digest, plan.operatorPermits?.[i] || "0x") !== lc(e.operator)) problems.push(`machine ${i}: operator ${lc(e.operator)} permit missing or invalid`);
    if (permits && !ownerSigners(i).has(o)) problems.push(`machine ${i}: owner ${o} permit missing or invalid`);
  }
  return problems;
}
// The plan's owner-permit signatures, each checked against that host's owner AT the snapshot block.
export async function planOwnerChecks(batch, plan) {
  const digest = D.independentPlanDigest(plan), handles = [];
  for (let i = 0; i < plan.machines.length; i++) handles.push(await batch.add(digest, [{ registryId: plan.machines[i].registryId, signature: plan.ownerPermits?.[i] }]));
  return handles;
}

// A code permit judged at one snapshot for machine `index`: it must be its owner's canonical seat, and that owner signed.
export function judgeCodePermit({ snapshot, index, permit, signers, enclaveOwner }) {
  const com = snapshot.committee, m = com.machines[index];
  const { voters, independent } = governanceVoters(snapshot, enclaveOwner);
  const owner = lc(snapshot.entries[lc(m.registryId)]?.owner);
  if (!permitLive(permit?.expiresAt, snapshot.blockTimestamp)) return { ok: false, reason: "the owner permit is expired or too long-lived" };
  if (m.enclave && !independent) {
    if (owner !== lc(enclaveOwner)) return { ok: false, reason: "the Enclave seat's machine is not owned by the Enclave wallet" };
  } else if (voters.get(owner) !== index) {
    return { ok: false, reason: owned(owner) && voters.has(owner) ? `this seat shares its owner with seat ${voters.get(owner) + 1}; an owner votes once, through its first seat`
                                                                   : "this seat's owner is not a governance voter" };
  }
  if (!signers.has(owner)) return { ok: false, reason: "not authorized by this seat's owner" };
  return { ok: true, owner };
}

// The measured independent admission policy: an explicit owner list, owner permits, or none (legacy Enclave admission).
export function independentPolicy(measured) {
  const mode = measured.independentAdmission ?? null;
  if (measured.independentOwners) {
    if (mode !== null && mode !== "owner-list") throw Error("measured owner list conflicts with the admission mode");
    return Object.freeze({ mode: "owner-list", owners: independentOwners(measured.independentOwners, measured.enclaveOwner), enclaveOwner: lc(measured.enclaveOwner) });
  }
  if (mode === "owner-permits") return Object.freeze({ mode, owners: null, enclaveOwner: lc(measured.enclaveOwner) });
  if (mode !== null) throw Error("unknown measured independent admission mode");
  return null;
}
