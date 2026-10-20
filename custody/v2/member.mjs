// A v2 custodian's MEMBERSHIP engine (docs/security/secret-custody-v2.md §4.4, §5, §6; spec §1.3): genesis, admission,
// handovers on membership change, and the sealed share state. Runs inside the custodian's SEV-SNP guest beside the release
// path (custodian.mjs). It signs; a host-side submitter (funded, untrusted: it can only drop what it is handed) sends the
// transactions.
//
// Coordination (no clock-driven resharing):
//   - every member polls the others' /info every HEARTBEAT_MS; a machine silent for SILENT_MS is "gone";
//   - candidates POST /join to any member; each member verifies a candidate itself (§5) with a fresh nonce;
//   - the COORDINATOR (the current machine with the lowest identity among those this member sees alive) proposes a
//     handover when the desired set (alive members + verified candidates) has differed from the current one for
//     BATCH_MS, or at once when the reachable shares fall to t + 1 (the safety trigger);
//   - approvers re-check the proposal against THEIR OWN view and sign; weight >= t_old submits it;
//   - dealers post deals; new machines verify, persist, then ack; the contract activates the epoch on the last ack;
//   - old shares are erased once the next epoch is active.
import { keccak256, toBytes, bytesToHex, hexToBytes } from "viem";
import { createHash, randomBytes } from "node:crypto";
import * as v2 from "./protocol.mjs";
import * as D from "./digests.mjs";
import { DEFAULT_MIN_TCB } from "../rules.mjs";
import { admissionDigest, admissionClaims, codePermitDigest, signatureBatch, judgePlan, planOwnerChecks, judgeCodePermit } from "./governance.mjs";

export const HEARTBEAT_MS = 60_000, SILENT_MS = 30 * 60_000, BATCH_MS = 10 * 60_000;
const MAX_APPROVALS = 32;
const sha256 = (...p) => createHash("sha256").update(Buffer.concat(p.map((x) => Buffer.from(x)))).digest();
const hex0x = (b) => "0x" + Buffer.from(b).toString("hex");
const lc = (s) => String(s).toLowerCase();
const splitPoints = (b) => { const out = []; for (let i = 0; i < b.length; i += 33) out.push(b.subarray(i, i + 33)); return out; };
// what a machine's own report binds: its whole record, and the verifier's fresh nonce
export const machineBinding = (machine, nonce) => sha256(Buffer.from("enclave-custody-v2 machine\n"), hexToBytes(D.machineHash(machine)), Buffer.from(nonce));

// state store: { load() -> obj|null, save(obj) } - the daemon seals it to the chip and this code (snpkey)
// state shape: { epochs: { "<cid>:<epoch>": [{k, x (hex)}] }, pending: { "<cid>:<toEpoch>": [{k,x}] }, hostSig, candidates }
export function createMember({ chainId, vault, identity, encPrivateKey, machine, chain, store, submit, fetchJson, attestSelf,
                               verifyPeerQuote, capacityCheck = async () => ({ ok: false, reason: "no proof-of-capacity verifier configured" }),
                               enclaveOwner, now = () => Date.now(), log = console.log, minTcb = DEFAULT_MIN_TCB, capacityReceipts = null, admissionCheck = null }) {
  const vaultL = lc(vault);
  const me = { ...machine, identity: lc(machine.identity) };
  let st = store.load() || { epochs: {}, pending: {}, hostSig: null, candidates: {} };
  const save = () => store.save(st);
  const lastSeen = new Map();             // identity -> ms
  let desiredSince = null, desiredKey = null;

  // ---- shares view for the release path ----
  const shares = { get: (cid, epoch) => (st.epochs[`${lc(cid)}:${epoch}`] || []).map((s) => ({ k: s.k, x: BigInt("0x" + s.x) })) };
  const putShares = (bucket, cid, epoch, list) => { st[bucket][`${lc(cid)}:${epoch}`] = list.map((s) => ({ k: s.k, x: s.x.toString(16).padStart(64, "0") })); };

  // ---- self ----
  async function evidence(nonceHex) {
    if (!/^[0-9a-f]{64}$/.test(String(nonceHex))) throw new Error("nonce: 32 bytes hex");
    const { report, auxblob } = await attestSelf(machineBinding(me, Buffer.from(nonceHex, "hex")));
    return { machine: me, hostSig: st.hostSig, report: Buffer.from(report).toString("base64"), auxblob: auxblob ? Buffer.from(auxblob).toString("base64") : null,
             receipts: typeof capacityReceipts === "function" ? await capacityReceipts().catch(() => []) : [] };
  }
  function info(committeeId) {
    const cur = Object.keys(st.epochs).filter((k) => !committeeId || k.startsWith(lc(committeeId) + ":"));
    return { v: 2, identity: me.identity, encKey: me.encKey, machine: me, hostSig: st.hostSig,
             epochs: cur.map((k) => ({ committee: k.split(":")[0], epoch: Number(k.split(":")[1]), indices: st.epochs[k].map((s) => s.k) })) };
  }
  // the host binds this machine to its registry entry; checked against the chain before it is kept
  async function setHostSig(sig) {
    const r = await chain.readRegistryEntry({ registryId: me.registryId });
    if (!r.entry || !r.entry.active) throw new Error("the host's registry entry is not active");
    const who = await D.recoverDigest(D.hostDigest({ chainId, vault: vaultL, machine: me }), sig);
    if (!who || who !== r.entry.operator) throw new Error("the host binding is not signed by the host's registry operator");
    if (!r.entry.owner || /^0x0{40}$/.test(r.entry.owner)) throw new Error("host wallet ownership has not been accepted");
    st.hostSig = sig; save();
    return { enclave: r.entry.owner === lc(enclaveOwner) };
  }

  // ---- genesis (§10: the Enclave seat creates the committee) ----
  async function genesis({ salt, codeSet }) {
    if (!st.hostSig) throw new Error("genesis: no host binding yet");
    const g = v2.genesis();
    const Y = g.Y;
    const committeeId = D.committeeIdOf({ chainId, vault: vaultL, salt, Y });
    // persist the share BEFORE the transaction: a crash after it lands must not lose x
    putShares("epochs", committeeId, 1, g.shares); save();
    const sig = await D.signDigest(identity, D.genesisDigest({ chainId, vault: vaultL, committeeId, Y, machine: me, codeSet }));
    const tx = await submit("createCommittee", [salt, me, hex0x(Y), codeSet, sig, st.hostSig]);
    log(`[member] genesis committee ${committeeId} (Y ${bytesToHex(Y).slice(0, 18)}...) tx ${tx}`);
    return { committeeId, Y: hex0x(Y), tx };
  }

  // ---- authorization snapshot: ONE agreed block for every owner/operator/code fact a decision uses ----
  // newcomers: [{ machine, admission }] whose admission signatures are checked at that block; extra.digests: other
  // signatures by key (claims name an account or a host whose owner at that block is asked).
  async function readSnapshot(committeeId, newcomers = [], extra = {}) {
    const batch = signatureBatch(), handles = new Map();
    for (const n of newcomers) if (committeeId && Number.isSafeInteger(n.admission?.expiresAt))
      handles.set(lc(n.machine.identity), await batch.add(admissionDigest({ chainId, vault: vaultL, committeeId, machine: n.machine, expiresAt: n.admission.expiresAt }), admissionClaims(n.admission)));
    for (const [key, { digest, claims }] of Object.entries(extra.digests || {})) handles.set(key, await batch.add(digest, claims));
    const planHandles = extra.plan ? await planOwnerChecks(batch, extra.plan) : [];
    const snap = await chain.readAuthorization({ committeeId: committeeId || null,
      registryIds: [...newcomers.map((n) => n.machine.registryId), ...(extra.registryIds || [])],
      measurements: committeeId ? newcomers.map((n) => n.machine.measurement) : [], checks: batch.checks });
    return { ...snap, signersOf: (key) => (handles.has(key) ? batch.signers(handles.get(key), snap) : new Set()),
             planSigners: (i) => (planHandles[i] === undefined ? new Set() : batch.signers(planHandles[i], snap)) };
  }

  // ---- candidate verification (§5): run by EVERY member for itself ----
  // attest: fresh evidence for this EXACT record (a different record under the same identity fails the machine hash).
  async function attest(m) {
    const nonce = randomBytes(32).toString("hex");
    const ev = await fetchJson(`${m.endpoint}/v2/custody/evidence`, { nonce });
    if (!ev || lc(D.machineHash(ev.machine)) !== lc(D.machineHash(m))) return { ok: false, reason: "evidence names another machine" };
    const report = Buffer.from(String(ev.report || ""), "base64");
    const v = await verifyPeerQuote(report, { binding: machineBinding(m, Buffer.from(nonce, "hex")), auxblob: ev.auxblob ? Buffer.from(ev.auxblob, "base64") : null, minTcb });
    if (!v.ok) return { ok: false, reason: `attestation: ${v.reason}` };
    if (hex0x(sha256(Buffer.from(v.measurement, "hex"))) !== lc(m.measurement)) return { ok: false, reason: "measurement does not match the machine record" };
    if (hex0x(sha256(Buffer.from(v.chipId, "hex"))) !== lc(m.chipId)) return { ok: false, reason: "chip id does not match the machine record" };
    return { ok: true, ev, v };
  }
  // genesisAllows: the founder owner rule (a predicate, or a measured owner list); null for a join to a live committee.
  // snap: the decision's authorization snapshot; without one (a join), one is read for this candidate alone.
  async function verifyCandidate({ machine: m, hostSig, endpoint, admission }, committeeId, genesisAllows = null, snap = null) {
    const allows = !genesisAllows ? null : typeof genesisAllows === "function" ? genesisAllows : (o) => genesisAllows.includes(o);
    if (allows) {
      // Before contacting a proposed endpoint, bind its host to a wallet this
      // image explicitly admits. Genesis peers must run this same measured code.
      snap ||= await readSnapshot(null, [], { registryIds: [m.registryId] });
      const e = snap.entries[lc(m.registryId)];
      if (!e?.active || !allows(lc(e.owner)) || m.measurement !== me.measurement) return {ok:false,reason:'genesis owner or measured code is outside policy'};
    }
    const a = await attest(m);
    if (!a.ok) return a;
    snap ||= await readSnapshot(committeeId, [{ machine: m, admission }], { registryIds: [m.registryId] });
    if (!allows) {
      const at = snap.codeActiveAt?.[lc(m.measurement)];
      if (!at || at > snap.blockTimestamp) return { ok: false, reason: "custodian code not active in the committee's code set" };
    }
    const entry = snap.entries[lc(m.registryId)];
    if (!entry || !entry.active) return { ok: false, reason: "host registry entry not active" };
    const sig = hostSig || a.ev.hostSig;
    const who = await D.recoverDigest(D.hostDigest({ chainId, vault: vaultL, machine: m }), sig);
    if (!who || who !== entry.operator) return { ok: false, reason: "host binding not signed by the host's registry operator" };
    if (!entry.owner || /^0x0{40}$/.test(entry.owner)) return { ok: false, reason: "host wallet ownership has not been accepted" };
    const enclave = entry.owner === lc(enclaveOwner);
    if (!allows && (admissionCheck || !enclave)) {
      const c = await (admissionCheck || capacityCheck)({ machine: m, chipIdRaw: a.v.chipId, registry: entry, receipts: Array.isArray(a.ev.receipts) ? a.ev.receipts : [],
                                                          committeeId, admission, snapshot: snap, signers: snap.signersOf(lc(m.identity)) });
      if (!c || !c.ok) return { ok: false, reason: `${admissionCheck ? "membership policy" : "proof of capacity"}: ${(c && c.reason) || "refused"}` };
    }
    return { ok: true, enclave, hostSig: sig, owner: entry.owner };
  }
  // policy: the measured independent policy ({ mode: "owner-list", owners } | { mode: "owner-permits" }), or an owner list.
  // owner-permits: every founder's accepted owner wallet also signs the exact plan; any distinct non-Enclave owners may form.
  // Every operator permit, owner permit, owner rule and owner distinctness is judged at ONE block: the same operators and
  // owners authorize the same roster. Then each founder is attested; its host binding is checked against that block.
  async function verifyGenesisRoster(plan, policy) {
    if (Array.isArray(policy)) policy = { mode: "owner-list", owners: policy };
    const permits = policy?.mode === "owner-permits";
    if (!permits && policy?.mode !== "owner-list") return false;
    const allows = (o) => /^0x[0-9a-f]{40}$/.test(o) && !/^0x0{40}$/.test(o) && o !== lc(enclaveOwner) && (permits || policy.owners.includes(o));
    if (plan.chainId !== chainId || lc(plan.vault) !== vaultL || plan.machines.length < 3 || plan.machines.length > 64 ||
        plan.codeSet.length !== 1 || plan.codeSet[0] !== me.measurement ||
        !Array.isArray(plan.operatorPermits)||plan.operatorPermits.length!==plan.machines.length||
        (permits && (!Array.isArray(plan.ownerPermits)||plan.ownerPermits.length!==plan.machines.length))) return false;
    if (!plan.machines.some(m=>lc(D.machineHash(m))===lc(D.machineHash(me)))) return false;
    // All operators (and, with owner permits, all owners) consent before any remote evidence call or sealed session
    // allocation. A public caller cannot consume a machine with a chosen salt.
    const snap = await readSnapshot(null, [], { registryIds: plan.machines.map((m) => m.registryId), ...(permits ? { plan } : {}) });
    if ((await judgePlan({ plan, snapshot: snap, policy, enclaveOwner, ownerSigners: snap.planSigners })).length) return false;
    const chips = new Set();
    for (const m of plan.machines) {
      const r = await verifyCandidate({ machine: m }, null, allows, snap);
      if (!r.ok || r.enclave || chips.has(m.chipId)) return false;
      chips.add(m.chipId);
    }
    return true;
  }
  async function adoptIndependentGenesis({committeeId,commitments,share}) {
    const {committee:com}=await chain.readCommittee({committeeId});
    if(!com||com.epoch!==1||com.machines.some(m=>m.enclave)||com.machines.length<3||
       hex0x(com.commitments)!==commitments)throw Error('independent genesis not confirmed');
    const pos=com.machines.findIndex(m=>lc(D.machineHash(m))===lc(D.machineHash(me)));
    const lay=v2.seatLayout(com.machines);
    if(pos<0||com.t!==lay.t||com.W!==lay.W)throw Error('independent genesis roster mismatch');
    const k=pos+1,x=v2.bytesToScalar(Buffer.from(share,'hex'));
    v2.verifySubShare({newIndex:k,y:x,dealCommitments:splitPoints(com.commitments)});
    putShares('epochs',lc(committeeId),1,[{k,x}]);save();
    return {committeeId,epoch:1};
  }
  // the committees this machine holds shares for (the daemon serves the adopted one when the host names none)
  const committees = () => [...new Set(Object.keys(st.epochs).map((k) => k.split(":")[0]))];
  async function join(body, committeeId) {
    const m = body && body.machine;
    if (!m || !/^0x[0-9a-f]{40}$/.test(lc(m.identity))) throw new Error("join: a machine record is required");
    if (committeeId) {
      const { committee: com } = await chain.readCommittee({ committeeId });
      if (com?.machines.some((c) => c.identity === lc(m.identity))) throw new Error("join: this identity already holds a seat; a changed record needs a new identity");
    }
    const r = await verifyCandidate(body, committeeId);
    if (!r.ok) throw new Error(`join refused: ${r.reason}`);
    st.candidates[lc(m.identity)] = { machine: { ...m, identity: lc(m.identity) }, hostSig: r.hostSig, enclave: r.enclave, owner: lc(r.owner), verifiedAt: now(),
                                       ...(Array.isArray(body.admission?.signatures) ? { admission: { expiresAt: body.admission.expiresAt,
                                         signatures: body.admission.signatures.slice(0, 64).map((x) => ({ owner: String(x?.owner), signature: String(x?.signature) })) } } : {}) };
    save();
    log(`[member] candidate ${lc(m.identity).slice(0, 10)} verified (${r.enclave ? "Enclave-owned" : admissionCheck ? "admitted by measured policy" : "capacity-proven"})`);
    return { ok: true, enclave: r.enclave };
  }

  // ---- the desired next set (this member's own view) ----
  function desired(com) {
    const t = now();
    const alive = com.machines.filter((m) => m.identity === me.identity || (lastSeen.get(m.identity) || 0) > t - SILENT_MS);
    const known = new Set(com.machines.map((m) => m.identity));
    const fresh = Object.values(st.candidates).filter((c) => !known.has(c.machine.identity) && c.verifiedAt > t - SILENT_MS);
    // one seat per chip among non-Enclave machines: a second candidate on a chip already seated is left out
    const chips = new Set(alive.filter((m) => !m.enclave).map((m) => m.chipId));
    const add = [];
    for (const c of fresh) { if (!c.enclave && chips.has(c.machine.chipId)) continue; if (!c.enclave) chips.add(c.machine.chipId); add.push({ ...c.machine, enclave: c.enclave, hostSig: c.hostSig, admission: c.admission }); }
    return [...alive, ...add];
  }
  // ---- what a next set may be (every approver and every dealer judges it at one snapshot) ----
  // CONTINUING means the same identity with the SAME machine record (machineHash: identity, encKey, endpoint, chip, host,
  // code). The vault accepts any record under an old identity if the host operator signs it, so a changed record is
  // refused here: a new encryption key, endpoint, chip, host or measurement needs a new identity, attested and admitted.
  // The Enclave flag of every next machine is the vault's own classification at that block (_admit: the accepted owner
  // is the Enclave wallet); a proposal's flag that differs is refused, so an approver never judges another seat layout
  // than the vault will activate. A continuing seat whose host is inactive or unowned (the vault would revert) - or, in
  // an INDEPENDENT committee, now owned by the Enclave wallet - is no longer eligible and may be removed although alive.
  // An independent committee stays independent: no Enclave-owned seat, and each newcomer's owner differs from every
  // continuing seat's and every other newcomer's. Continuing seats whose owners converged by transfer keep serving;
  // governance.mjs counts their owner once.
  const isIndependent = (com) => !com.machines.some((m) => m.enclave);
  const ownerAt = (snap, m) => { const e = snap.entries[lc(m.registryId)], o = lc(e?.owner); return e?.active && /^0x[0-9a-f]{40}$/.test(o) && !/^0x0{40}$/.test(o) ? o : null; };
  const sameRecord = (a, b) => lc(D.machineHash(strip(a))) === lc(D.machineHash(strip(b)));
  const ineligible = (snap, m) => { const o = ownerAt(snap, m); return !o || (isIndependent(snap.committee) && o === lc(enclaveOwner)); };
  // -> { next (vault flags), newcomers } or { reason }; `drop` leaves out ineligible seats and newcomers instead of refusing
  function checkNext(snap, next, { drop = false } = {}) {
    const com = snap.committee, indep = isIndependent(com), ids = new Set(), owners = new Set(), out = [];
    const why = (m, r) => ({ reason: `${lc(m.identity).slice(0, 10)} ${r}` });
    for (const m of next) {
      const id = lc(m.identity);
      if (ids.has(id)) return why(m, "appears twice in the next set");
      ids.add(id);
      const cur = com.machines.find((c) => c.identity === id);
      if (cur && !sameRecord(cur, m)) return why(m, "changes the machine record of a current identity; a new key, endpoint, chip, host or code needs a new identity");
      if (cur && indep && !ineligible(snap, m)) owners.add(ownerAt(snap, m));
    }
    const newcomers = [];
    for (const m of next) {
      const cur = com.machines.some((c) => c.identity === lc(m.identity)), o = ownerAt(snap, m);
      let reason = null;
      if (cur && ineligible(snap, m)) reason = "is no longer an eligible seat (inactive or unowned host, or Enclave-owned in an independent committee)";
      else if (!cur && indep && (!o || o === lc(enclaveOwner))) reason = "would add an Enclave-owned or unowned newcomer to an independent committee";
      else if (!cur && indep && owners.has(o)) reason = "would add a second seat for one owner to an independent committee";
      else if (!cur && !o) reason = "is an unowned newcomer";
      if (reason && !drop) return why(m, reason);
      if (reason) continue;
      if (!cur && indep) owners.add(o);
      const flag = o === lc(enclaveOwner);
      if (!drop && !!m.enclave !== flag) return why(m, "carries an Enclave flag the vault would not assign");
      out.push({ ...m, enclave: flag });
      if (!cur) newcomers.push(m);
    }
    return { next: out, newcomers };
  }
  const setKey = (ms) => ms.map((m) => m.identity).sort().join(",");
  function dealersFor(com, aliveIds, keep = null) {
    // exactly t_old indices from ALIVE machines; the Enclave seat's indices from one Enclave machine. Seats that stay in
    // the next set deal first: a seat leaving because it became ineligible may not cooperate.
    const lay = v2.seatLayout(com.machines);
    const out = [];
    const stays = (seat) => (keep && seat.machines.some((mi) => keep.has(com.machines[mi].identity)) ? 0 : 1);
    for (const seat of [...lay.seats].sort((a, b) => stays(a) - stays(b))) {
      if (!seat.machines.some((mi) => aliveIds.has(com.machines[mi].identity))) continue;
      for (const k of seat.indices) { if (out.length < lay.t) out.push(k); }
    }
    return out.length === lay.t ? out : null;
  }

  // ---- approvals: another member asks this one to sign a proposal ----
  // The authorization point for a handover is this signature, judged at one snapshot taken now: continuing machines
  // keep their exact records, vault flags match, and EVERY newcomer - including one verified at join - is re-attested
  // for the proposal's exact record and re-authorized (code, operator binding, owner, admission permit and its expiry,
  // owner distinctness). The approval is remembered: this machine deals only for a pending set it approved.
  async function approve({ committeeId, fromEpoch, next, dealerIndices }) {
    const cid = lc(committeeId);
    const { committee: com, pending } = await chain.readCommittee({ committeeId: cid });
    if (!com || com.epoch !== fromEpoch) throw new Error("approve: not the current epoch");
    if (pending && pending.expires * 1000 > now()) throw new Error("approve: a handover is already pending");
    if (!com.machines.some((m) => m.identity === me.identity)) throw new Error("approve: this machine is not a current member");
    if (!Array.isArray(next) || !next.length || next.length > v2.MAX_MACHINES) throw new Error("approve: a next set is required");
    const known = new Set(com.machines.map((m) => m.identity));
    const fresh = next.filter((m) => !known.has(lc(m.identity)));
    const snap = await readSnapshot(cid, fresh.map((m) => ({ machine: strip(m), admission: m.admission })), { registryIds: next.map((m) => m.registryId) });
    if (!snap.committee || snap.committee.epoch !== fromEpoch) throw new Error("approve: the committee changed while authorizing");
    const chk = checkNext(snap, next);
    if (chk.reason) throw new Error(`approve: ${chk.reason}`);
    for (const m of com.machines) {                 // a removal this member does not see as gone or ineligible
      if (next.some((n) => lc(n.identity) === m.identity) || ineligible(snap, m)) continue;
      if (m.identity === me.identity) throw new Error("approve: the proposal removes this machine, which is alive");
      if ((lastSeen.get(m.identity) || 0) > now() - SILENT_MS) throw new Error(`approve: ${m.identity.slice(0, 10)} is alive from here`);
    }
    for (const m of chk.newcomers) {
      const r = await verifyCandidate({ machine: strip(m), hostSig: m.hostSig, admission: m.admission }, cid, null, snap);
      if (!r.ok) throw new Error(`approve: candidate ${lc(m.identity).slice(0, 10)} refused: ${r.reason}`);
    }
    v2.seatLayout(chk.next);                        // the vault's layout; throws on an invalid seat set (e.g. < 3 seats, no Enclave)
    const digest = D.handoverDigest({ chainId, vault: vaultL, committeeId: cid, fromEpoch, next: next.map(strip), dealerIndices });
    st.approved ||= {};
    st.approved[digest] = { committeeId: cid, fromEpoch, at: now(),
                            admissions: Object.fromEntries(chk.newcomers.filter((m) => m.admission).map((m) => [lc(m.identity), m.admission])) };
    for (const k of Object.keys(st.approved).slice(0, -MAX_APPROVALS)) delete st.approved[k];
    save();
    return { approver: me.identity, sig: await D.signDigest(identity, digest) };
  }
  // A dealer re-checks the ON-CHAIN pending set before encrypting any share to it: it must be exactly a set this machine
  // approved for the current epoch (the handover digest binds committee, epoch, every machine record and the dealers),
  // still valid at a fresh snapshot (vault flags, continuing records, eligibility), and every newcomer is re-attested
  // for its exact record (encryption key included) and re-authorized now. Anything else, including an unreachable
  // recipient, withholds the deal: no share leaves, current shares stay, and the pending handover expires (HANDOVER_TTL).
  async function verifyPending(com, pending, cid) {
    const digest = D.handoverDigest({ chainId, vault: vaultL, committeeId: cid, fromEpoch: com.epoch, next: pending.next.map(strip), dealerIndices: pending.dealers });
    const rec = st.approved?.[digest];
    if (!rec || rec.committeeId !== cid || rec.fromEpoch !== com.epoch) return { ok: false, reason: "this dealer did not approve this exact pending set for the current epoch" };
    const known = new Set(com.machines.map((m) => m.identity));
    const next = pending.next.map((m) => ({ ...m, ...(rec.admissions[m.identity] ? { admission: rec.admissions[m.identity] } : {}) }));
    try {
      const snap = await readSnapshot(cid, next.filter((m) => !known.has(m.identity)).map((m) => ({ machine: strip(m), admission: m.admission })), { registryIds: next.map((m) => m.registryId) });
      if (!snap.committee || snap.committee.epoch !== com.epoch) return { ok: false, reason: "the committee changed" };
      const chk = checkNext(snap, next);
      if (chk.reason) return { ok: false, reason: chk.reason };
      for (const m of chk.newcomers) {
        const r = await verifyCandidate({ machine: strip(m), admission: m.admission }, cid, null, snap);
        if (!r.ok) return { ok: false, reason: `recipient ${m.identity.slice(0, 10)}: ${r.reason}` };
      }
    } catch (e) { return { ok: false, reason: `recipient check failed: ${String(e.message).slice(0, 200)}` }; }
    return { ok: true };
  }
  const strip = (m) => ({ identity: lc(m.identity), encKey: lc(m.encKey), endpoint: m.endpoint, chipId: lc(m.chipId), registryId: lc(m.registryId), measurement: lc(m.measurement) });

  // ---- one step of the engine ----
  async function tick(committeeId) {
    const { committee: com, pending } = await chain.readCommittee({ committeeId });
    if (!com) return { state: "no_committee" };
    const cid = lc(committeeId);
    // heartbeats
    await Promise.all(com.machines.filter((m) => m.identity !== me.identity).map(async (m) => {
      try { const i = await fetchJson(`${m.endpoint}/v2/custody/info`); if (i && lc(i.identity) === m.identity) lastSeen.set(m.identity, now()); } catch {}
    }));
    // activation: a pending epoch of ours became current
    const pkey = `${cid}:${com.epoch}`;
    if (st.pending[pkey]) { st.epochs[pkey] = st.pending[pkey]; delete st.pending[pkey]; }
    for (const k of Object.keys(st.epochs)) if (k.startsWith(cid + ":") && Number(k.split(":")[1]) < com.epoch) delete st.epochs[k];   // erase old shares
    save();
    if (pending && pending.expires * 1000 > now()) return await handoverStep(com, pending, cid);
    return await coordinate(com, cid);
  }

  async function handoverStep(com, pending, cid) {
    const lay = v2.seatLayout(pending.next);
    const newIdx = Array.from({ length: lay.W }, (_, i) => i + 1);
    // dealer: post my deal(s), only after verifying the exact pending set (verifyPending)
    const mine = shares.get(cid, com.epoch);
    let checked = null;
    for (const k of pending.dealers) {
      const s = mine.find((x) => x.k === k);
      if (!s) continue;
      const have = await chain.readDeal({ committeeId: cid, toEpoch: pending.toEpoch, dealerIndex: k });
      if (have.dealCommitments.length) continue;
      checked ||= await verifyPending(com, pending, cid);
      if (!checked.ok) {
        log(`[member] deal for index ${k} -> epoch ${pending.toEpoch} withheld: ${checked.reason}`);
        return { state: "deal_withheld", toEpoch: pending.toEpoch, reason: checked.reason };
      }
      const dl = v2.deal({ x: s.x, tNew: lay.t, newIndices: newIdx });
      const aadBase = { chainId, vault: vaultL, committeeId: cid, fromEpoch: com.epoch, toEpoch: pending.toEpoch, dealerIndex: k, dealCommitments: dl.commitments };
      const sealed = pending.next.map((m, mi) => hex0x(v2.sealDeal({ encKey: hexToBytes(m.encKey), aadFields: aadBase, entries: lay.indicesOf(mi).map((kk) => [kk, dl.sub.get(kk)]) })));
      const dc = hex0x(Buffer.concat(dl.commitments.map((c) => Buffer.from(c))));
      const sig = await D.signDigest(identity, D.dealDigest({ chainId, vault: vaultL, committeeId: cid, toEpoch: pending.toEpoch, dealerIndex: k, dealCommitments: dc, sealed }));
      await submit("postDeal", [cid, pending.toEpoch, k, dc, sealed, me.identity, sig]);
      log(`[member] posted deal for index ${k} -> epoch ${pending.toEpoch}`);
    }
    // recipient: when every dealer has posted, verify, persist, ack
    const myI = pending.next.findIndex((m) => m.identity === me.identity);
    const pkey = `${cid}:${pending.toEpoch}`;
    if (myI < 0 || st.pending[pkey]) return { state: "handover", toEpoch: pending.toEpoch };
    const deals = [];
    for (const k of pending.dealers) {
      const d = await chain.readDeal({ committeeId: cid, toEpoch: pending.toEpoch, dealerIndex: k });
      if (!d.dealCommitments.length) return { state: "waiting_deals", toEpoch: pending.toEpoch };
      const dealCommitments = splitPoints(d.dealCommitments);
      const sub = v2.openDeal({ encPrivate: encPrivateKey, encKey: hexToBytes(me.encKey),
        aadFields: { chainId, vault: vaultL, committeeId: cid, fromEpoch: com.epoch, toEpoch: pending.toEpoch, dealerIndex: k, dealCommitments }, sealed: d.sealed[myI] });
      deals.push({ dealerIndex: k, dealCommitments, sub });
    }
    const oldLay = v2.seatLayout(com.machines);
    const r = v2.receiveHandover({ deals, oldCommitments: splitPoints(com.commitments), tOld: oldLay.t, tNew: lay.t, myIndices: lay.indicesOf(myI) });
    putShares("pending", cid, pending.toEpoch, r.shares); save();         // persisted BEFORE the ack
    const nc = hex0x(Buffer.concat(r.commitments.map((c) => Buffer.from(c))));
    const sig = await D.signDigest(identity, D.ackDigest({ chainId, vault: vaultL, committeeId: cid, toEpoch: pending.toEpoch, newCommitments: nc }));
    await submit("ackHandover", [cid, pending.toEpoch, nc, me.identity, sig]);
    log(`[member] acked epoch ${pending.toEpoch} (indices ${r.shares.map((s) => s.k).join(",")})`);
    return { state: "acked", toEpoch: pending.toEpoch };
  }

  async function coordinate(com, cid) {
    const t = now();
    const aliveIds = new Set(com.machines.filter((m) => m.identity === me.identity || (lastSeen.get(m.identity) || 0) > t - SILENT_MS).map((m) => m.identity));
    const coordinator = [...aliveIds].sort()[0];
    if (coordinator !== me.identity) return { state: "idle" };
    let next = desired(com);
    const newcomersOf = (ms) => ms.filter((m) => !com.machines.some((c) => c.identity === m.identity));
    const snap = await readSnapshot(cid, newcomersOf(next).map((m) => ({ machine: strip(m), admission: m.admission })), { registryIds: next.map((m) => m.registryId) });
    if (!snap.committee || snap.committee.epoch !== com.epoch) return { state: "committee_changed" };
    const chk = checkNext(snap, next, { drop: true });
    if (chk.reason) return { state: "invalid_next", reason: chk.reason };
    next = chk.next;
    let key = setKey(next);
    if (key === setKey(com.machines)) { desiredSince = null; desiredKey = null; return { state: "steady" }; }
    try { v2.seatLayout(next); } catch (e) { return { state: "invalid_next", reason: e.message }; }
    if (desiredKey !== key) { desiredKey = key; desiredSince = t; }
    const lay = v2.seatLayout(com.machines);
    const reachable = lay.seats.filter((s) => s.machines.some((mi) => aliveIds.has(com.machines[mi].identity))).reduce((a, s) => a + s.weight, 0);
    const urgent = reachable <= lay.t + 1 && reachable < lay.W;
    if (!urgent && t - desiredSince < BATCH_MS) return { state: "batching", since: desiredSince };
    const dealerIndices = dealersFor(com, aliveIds, new Set(next.map((m) => m.identity)));
    if (!dealerIndices) return { state: "stuck", reason: "fewer than t shares are reachable; waiting for members to return" };
    // Re-verify cached candidates now, as every approver will: one whose permit expired, whose owner changed or whose
    // evidence fails is forgotten (it may join again) instead of blocking the rest of the change.
    for (const m of newcomersOf(next)) {
      const r = await verifyCandidate({ machine: strip(m), hostSig: m.hostSig, admission: m.admission }, cid, null, snap);
      if (r.ok && !!r.enclave === !!m.enclave) continue;
      log(`[member] candidate ${m.identity.slice(0, 10)} dropped: ${r.reason || "Enclave flag changed"}`);
      delete st.candidates[m.identity]; save();
      next = next.filter((x) => x.identity !== m.identity);
    }
    key = setKey(next);
    if (key === setKey(com.machines)) { desiredSince = null; desiredKey = null; return { state: "steady" }; }
    try { v2.seatLayout(next); } catch (e) { return { state: "invalid_next", reason: e.message }; }
    const proposal = { committeeId: cid, fromEpoch: com.epoch, next: next.map((m) => ({ ...strip(m), enclave: !!m.enclave, hostSig: m.hostSig, ...(m.admission ? { admission: m.admission } : {}) })), dealerIndices };
    const approvals = [];
    let weight = 0;
    const seatOf = (id) => lay.seats.find((s) => s.machines.some((mi) => com.machines[mi].identity === id));
    const counted = new Set();
    const credit = (id) => { const s = seatOf(id); if (s && !counted.has(s)) { counted.add(s); weight += s.weight; } };
    approvals.push(await approve(proposal)); credit(me.identity);
    // Every dealer seat must approve (a dealer deals only for a set it approved), then others until weight t.
    const dealerSeats = new Set(lay.seats.filter((seat) => seat.indices.some((k) => dealerIndices.includes(k))));
    const ask = [...com.machines].sort((a, b) => (dealerSeats.has(seatOf(b.identity)) ? 1 : 0) - (dealerSeats.has(seatOf(a.identity)) ? 1 : 0));
    for (const m of ask) {
      const seat = seatOf(m.identity);
      if (counted.has(seat) || m.identity === me.identity || !aliveIds.has(m.identity) || (weight >= lay.t && !dealerSeats.has(seat))) continue;
      try { const a = await fetchJson(`${m.endpoint}/v2/custody/approve`, proposal); if (a && lc(a.approver) === m.identity) { approvals.push(a); credit(m.identity); } } catch (e) { log(`[member] ${m.identity.slice(0, 10)} did not approve: ${e.message}`); }
    }
    if (weight < lay.t) return { state: "unapproved", weight, t: lay.t };
    if ([...dealerSeats].some((seat) => !counted.has(seat))) return { state: "unapproved", reason: "a dealer did not approve" };
    const hostSigs = await Promise.all(next.map(async (m) => {
      if (m.hostSig) return m.hostSig;
      if (m.identity === me.identity) return st.hostSig;
      const i = await fetchJson(`${m.endpoint}/v2/custody/info`); return i.hostSig;
    }));
    const tx = await submit("proposeHandover", [cid, next.map(strip), hostSigs, dealerIndices, approvals.map((a) => a.approver), approvals.map((a) => a.sig)]);
    log(`[member] proposed epoch ${com.epoch + 1}: ${next.length} machine(s), dealers ${dealerIndices.join(",")} (tx ${tx})`);
    desiredSince = null; desiredKey = null;
    return { state: "proposed", tx };
  }

  // ---- code governance: this seat's OWNER authorizes, this machine signs the vault's codeDigest ----
  // Judged at one snapshot: this machine must be its owner's canonical seat (an owner votes once however many seats it
  // holds; governance.mjs), the owner must have signed the exact permit, and the permit must be live at that block. The
  // permit's expiry gates only THIS signature; once signed, the vault bounds it by epoch and single-use digest.
  async function approveCode({ committeeId, measurement, add, permit }) {
    const cid = lc(committeeId), meas = lc(measurement);
    if (!/^0x[0-9a-f]{64}$/.test(cid) || !/^0x[0-9a-f]{64}$/.test(meas) || /^0x0{64}$/.test(meas) || typeof add !== "boolean") throw new Error("code: committeeId, measurement and add are required");
    if (!Number.isSafeInteger(permit?.expiresAt)) throw new Error("code: the owner permit is expired or too long-lived");
    const digest = codePermitDigest({ chainId, vault: vaultL, committeeId: cid, measurement: meas, add, expiresAt: permit.expiresAt });
    const snap = await readSnapshot(cid, [], { digests: { code: { digest, claims: [{ registryId: me.registryId, signature: permit.signature }] } } });
    const com = snap.committee, index = com ? com.machines.findIndex((m) => m.identity === me.identity) : -1;
    if (index < 0) throw new Error("code: this machine is not a current member");
    const r = judgeCodePermit({ snapshot: snap, index, permit, signers: snap.signersOf("code"), enclaveOwner });
    if (!r.ok) throw new Error(`code: ${r.reason}`);
    log(`[member] ${add ? "approved" : "approved removal of"} custodian code ${meas.slice(0, 18)}... at epoch ${com.epoch}`);
    return { approver: me.identity, epoch: com.epoch, sig: await D.signDigest(identity, D.codeDigest({ chainId, vault: vaultL, committeeId: cid, epoch: com.epoch, measurement: meas, add })) };
  }

  return { me, shares, info, evidence, setHostSig, genesis, verifyGenesisRoster, adoptIndependentGenesis, committees, join, approve, approveCode, tick, _state: () => st, _lastSeen: lastSeen };
}
