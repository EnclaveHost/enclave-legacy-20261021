// The operator-run independent custody workflow behind scripts/independent-custody.mjs. Every input is an explicit pin
// (chain id, vault, custodian measurement, HTTPS custodian origins, agreeing RPCs). It moves only public records, owner
// or operator signatures and member signatures; secret shares never leave the measured custodians. Nothing here is an
// authority: members re-verify everything, and the vault re-checks every signature.
import { randomBytes } from 'node:crypto';
import { encodeFunctionData } from 'viem';
import * as D from './digests.mjs';
import * as v2 from './protocol.mjs';
import { VAULT_V2_ABI } from './chain.mjs';
import { admissionDigest, admissionClaims, codePermitDigest, signatureBatch, judgePlan, planOwnerChecks, judgeAdmission, governanceVoters, MAX_PERMIT_SEC } from './governance.mjs';

const lc = s => String(s).toLowerCase();
const ADDRESS = /^0x[0-9a-f]{40}$/, BYTES32 = /^0x[0-9a-f]{64}$/, SIG = /^0x(?:[0-9a-fA-F]{2}){65,2048}$/;

export function custodianOrigin(endpoint) {
  const u = new URL(endpoint);
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || (u.port && u.port !== '443') ||
      u.pathname.split('/').some(s => s === '.' || s === '..')) throw Error(`invalid custodian HTTPS endpoint: ${endpoint}`);
  return endpoint.replace(/\/$/, '');
}
export function pins({ chainId, vault, measurement }) {
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw Error('explicit chain id required');
  if (!ADDRESS.test(lc(vault)) || /^0x0{40}$/.test(vault)) throw Error('explicit vault address required');
  if (measurement !== undefined && (!BYTES32.test(lc(measurement)) || /^0x0{64}$/.test(measurement))) throw Error('explicit custodian measurement (sha256, bytes32) required');
  return { chainId, vault: lc(vault), ...(measurement !== undefined ? { measurement: lc(measurement) } : {}) };
}
// Each custodian reports its own record; the plan pins it to the expected chain, vault, endpoint and measured code.
export async function custodianInfo(endpoint, { chainId, vault, measurement }, get) {
  const origin = custodianOrigin(endpoint), info = await get(origin + '/v2/custody/info');
  const m = info?.machine;
  if (info?.v !== 2 || !m || info.chainId !== chainId || lc(info.vault) !== vault) throw Error(`${origin} serves another chain or vault`);
  if (m.endpoint !== endpoint || lc(m.identity) !== lc(info.identity) || lc(m.encKey) !== lc(info.encKey)) throw Error(`${origin} reports an inconsistent machine record`);
  if (measurement && lc(m.measurement) !== measurement) throw Error(`${origin} runs another custodian measurement`);
  const machine = { identity: lc(m.identity), encKey: lc(m.encKey), endpoint: m.endpoint, chipId: lc(m.chipId), registryId: lc(m.registryId), measurement: lc(m.measurement) };
  return { machine, hostSig: SIG.test(String(info.hostSig)) ? info.hostSig : null, epochs: Array.isArray(info.epochs) ? info.epochs : [], admission: info.independentAdmission || null };
}

// ---- formation ----
export async function buildPlan({ endpoints, chainId, vault, measurement, salt = '0x' + randomBytes(32).toString('hex'), get }) {
  const p = pins({ chainId, vault, measurement });
  if (!Array.isArray(endpoints) || endpoints.length < 3 || endpoints.length > 64) throw Error('3..64 custodian endpoints required');
  if (!BYTES32.test(salt)) throw Error('salt must be a fresh bytes32');
  const machines = [];
  for (const e of endpoints) {
    const info = await custodianInfo(e, p, get);
    if (!info.hostSig) throw Error(`${e} is not yet bound by its host operator`);
    machines.push(info.machine);
  }
  for (const field of ['identity', 'encKey', 'chipId', 'registryId'])
    if (new Set(machines.map(m => m[field])).size !== machines.length) throw Error(`duplicate machine ${field} in the roster`);
  const n = machines.length;
  return { chainId: p.chainId, vault: p.vault, salt, machines, codeSet: [p.measurement], operatorPermits: Array(n).fill(null), ownerPermits: Array(n).fill(null) };
}
export const planDigest = plan => D.independentPlanDigest(plan);
export function addPlanSignature(plan, { role, index, signature }) {
  const field = role === 'operator' ? 'operatorPermits' : role === 'owner' ? 'ownerPermits' : null;
  if (!field) throw Error('role must be operator or owner');
  if (!Number.isInteger(index) || index < 0 || index >= plan.machines.length) throw Error('machine index out of range');
  if (!SIG.test(String(signature))) throw Error('signature must be hex');
  const list = Array.isArray(plan[field]) && plan[field].length === plan.machines.length ? [...plan[field]] : Array(plan.machines.length).fill(null);
  list[index] = signature;
  return { ...plan, [field]: list };
}
// Which permits are still missing or wrong, judged exactly as members judge them: at ONE agreed block (operators: EOA;
// owners: EOA or ERC-1271 for the host's owner at that block). An owner-list image's measured list is the image's
// business; without owner permits only operators, ownership and distinctness are checked here.
export async function checkPlan(plan, { chain, ownerPermits = true }) {
  const batch = signatureBatch(), handles = ownerPermits ? await planOwnerChecks(batch, plan) : [];
  const snapshot = await chain.readAuthorization({ registryIds: plan.machines.map(m => m.registryId), checks: batch.checks });
  const owners = plan.machines.map(m => lc(snapshot.entries[lc(m.registryId)]?.owner));
  const policy = ownerPermits ? { mode: 'owner-permits' } : { mode: 'owner-list', owners };
  const problems = await judgePlan({ plan, snapshot, policy, enclaveOwner: snapshot.enclaveOwner, ownerSigners: i => batch.signers(handles[i], snapshot) });
  return { digest: planDigest(plan), blockNumber: String(snapshot.blockNumber), ready: problems.length === 0, problems };
}
// The members' signed founder results checked against the agreed chain after activation.
export function committeeMatches(c, plan, commitments) {
  return !!c && c.epoch === 1 && c.t === Math.ceil(2 * plan.machines.length / 3) && c.W === plan.machines.length && c.machines.length === plan.machines.length &&
    !c.machines.some((m, i) => m.enclave || D.machineHash(m) !== D.machineHash(plan.machines[i])) && '0x' + Buffer.from(c.commitments).toString('hex') === commitments;
}

// ---- membership: admission of a new or replacement member ----
export async function chainExpiry(chain, committeeId, seconds) {
  if (!Number.isSafeInteger(seconds) || seconds < 60 || seconds > MAX_PERMIT_SEC) throw Error(`expiry must be 60..${MAX_PERMIT_SEC} seconds`);
  const { committee, blockTimestamp } = await chain.readCommittee({ committeeId });
  if (!committee) throw Error('committee not found on the agreed chain');
  return { committee, expiresAt: blockTimestamp + seconds };
}
export function admissionRequest({ chainId, vault, committeeId, machine, hostSig, expiresAt }) {
  const p = pins({ chainId, vault });
  if (!BYTES32.test(lc(committeeId))) throw Error('committee id required');
  return { chainId: p.chainId, vault: p.vault, committeeId: lc(committeeId), machine, hostSig, expiresAt, signatures: [],
           digest: admissionDigest({ ...p, committeeId: lc(committeeId), machine, expiresAt }) };
}
export function addAdmissionSignature(request, { owner, signature }) {
  if (!ADDRESS.test(lc(owner)) || !SIG.test(String(signature))) throw Error('owner address and signature required');
  if (admissionDigest(request) !== request.digest) throw Error('admission request was altered');
  return { ...request, signatures: [...request.signatures.filter(s => lc(s.owner) !== lc(owner)), { owner: lc(owner), signature }] };
}
// Check an admission before contacting members, exactly as members judge it at one block.
export async function checkAdmission(request, { chain }) {
  const batch = signatureBatch(), handle = await batch.add(request.digest, admissionClaims(request));
  const snapshot = await chain.readAuthorization({ committeeId: request.committeeId, registryIds: [request.machine.registryId], checks: batch.checks });
  if (!snapshot.committee) return { ready: false, problems: ['committee not found'] };
  if (admissionDigest(request) !== request.digest) return { ready: false, problems: ['admission request was altered'] };
  const r = judgeAdmission({ snapshot, machine: request.machine, admission: request, signers: batch.signers(handle, snapshot), enclaveOwner: snapshot.enclaveOwner });
  return { ready: r.ok, t: snapshot.committee.t, blockNumber: String(snapshot.blockNumber), ...(r.ok ? { weight: r.weight, problems: [] } : { problems: [r.reason] }) };
}
// Post the join to every current member. Each member verifies the candidate itself; one acceptance lets the coordinator
// propose, and any approver that did not see the join re-verifies the candidate (with this admission) on approval.
export async function joinCommittee({ request, committee, post }) {
  const body = { machine: request.machine, hostSig: request.hostSig, admission: { expiresAt: request.expiresAt, signatures: request.signatures } };
  const out = [];
  for (const m of committee.machines) {
    try { const r = await post(custodianOrigin(m.endpoint) + '/v2/custody/join', body); out.push({ endpoint: m.endpoint, ok: r?.ok === true }); }
    catch (e) { out.push({ endpoint: m.endpoint, ok: false, reason: String(e?.message || 'refused').slice(0, 200) }); }
  }
  return { accepted: out.filter(x => x.ok).length, members: out };
}

// ---- code governance: each seat's owner permits its member to sign the vault's code approval ----
export function codePermitRequest({ chainId, vault, committeeId, measurement, add, expiresAt }) {
  const p = pins({ chainId, vault, measurement });
  if (typeof add !== 'boolean') throw Error('add or remove must be explicit');
  return { chainId: p.chainId, vault: p.vault, committeeId: lc(committeeId), measurement: p.measurement, add, expiresAt,
           digest: codePermitDigest({ ...p, committeeId: lc(committeeId), add, expiresAt }) };
}
// permits: { [member identity]: signature by that seat's owner }. -> approvals and, at weight >= t, neutral calldata.
export async function collectCodeApprovals({ request, committee, permits, post }) {
  const approvals = [], refused = [];
  for (const m of committee.machines) {
    const signature = permits[m.identity];
    if (!signature) { refused.push({ identity: m.identity, reason: 'no owner permit supplied' }); continue; }
    try {
      const a = await post(custodianOrigin(m.endpoint) + '/v2/custody/code-approve',
        { committeeId: request.committeeId, measurement: request.measurement, add: request.add, permit: { expiresAt: request.expiresAt, signature } });
      if (lc(a?.approver) !== m.identity || a.epoch !== committee.epoch) throw Error('approval names another member or epoch');
      if (await D.recoverDigest(D.codeDigest({ ...request, epoch: committee.epoch }), a.sig) !== m.identity) throw Error('approval signature invalid');
      approvals.push(a);
    } catch (e) { refused.push({ identity: m.identity, reason: String(e?.message || 'refused').slice(0, 200) }); }
  }
  const lay = v2.seatLayout(committee.machines), seats = new Set();
  for (const a of approvals) seats.add(lay.seats.findIndex(s => s.machines.some(i => committee.machines[i].identity === a.approver)));
  const weight = [...seats].reduce((w, i) => w + lay.seats[i].weight, 0);
  const transaction = weight >= lay.t ? { to: request.vault, value: '0', data: encodeFunctionData({ abi: VAULT_V2_ABI, functionName: request.add ? 'proposeCode' : 'removeCode',
    args: [request.committeeId, request.measurement, approvals.map(a => a.approver), approvals.map(a => a.sig)] }) } : null;
  return { weight, t: lay.t, approvals, refused, transaction };
}

// ---- status: can this committee serve a release now, and what is it waiting for ----
export async function committeeStatus({ chain, committeeId, chainId, vault, get }) {
  const p = pins({ chainId, vault });
  const { committee: com, pending, blockNumber } = await chain.readCommittee({ committeeId });
  if (!com) throw Error('committee not found on the agreed chain');
  const snapshot = await chain.readAuthorization({ committeeId });
  const lay = v2.seatLayout(com.machines), owners = com.machines.map(m => { const e = snapshot.entries[lc(m.registryId)]; return e?.active && ADDRESS.test(lc(e.owner)) && !/^0x0{40}$/.test(e.owner) ? lc(e.owner) : null; });
  const { voters, silent } = governanceVoters({ ...snapshot, committee: com }, snapshot.enclaveOwner);
  const members = [];
  for (let i = 0; i < com.machines.length; i++) {
    const m = com.machines[i];
    let holds = false, reachable = false, reason = null;
    try {
      const info = await custodianInfo(m.endpoint, p, get);
      reachable = info.machine.identity === m.identity;
      holds = reachable && info.epochs.some(e => lc(e.committee) === lc(committeeId) && e.epoch === com.epoch && e.indices?.length);
      if (!reachable) reason = 'endpoint serves another machine';
    } catch (e) { reason = String(e?.message || 'unreachable').slice(0, 200); }
    members.push({ identity: m.identity, endpoint: m.endpoint, enclave: m.enclave, owner: owners[i], reachable, holdsCurrentEpoch: holds, ...(reason ? { reason } : {}) });
  }
  const serving = lay.seats.filter(s => s.machines.some(i => members[i].holdsCurrentEpoch)).reduce((w, s) => w + s.weight, 0);
  const named = owners.filter(Boolean);
  return { committeeId: lc(committeeId), blockNumber: String(blockNumber), epoch: com.epoch, t: com.t, W: com.W,
           independent: !com.machines.some(m => m.enclave), distinctOwners: new Set(named).size === named.length && named.length === com.machines.length,
           // service vs governance: seats sharing an owner (or unowned) still serve; they add no owner-governance vote
           governanceVoters: voters.size, nonVotingSeats: silent.map(i => com.machines[i].identity), governanceAvailable: voters.size >= com.t,
           servingWeight: serving, releaseAvailable: serving >= com.t, pending: pending ? { toEpoch: pending.toEpoch, acks: pending.acks, expires: pending.expires } : null, members };
}
