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

export const HEARTBEAT_MS = 60_000, SILENT_MS = 30 * 60_000, BATCH_MS = 10 * 60_000;
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

  // ---- candidate verification (§5): run by EVERY member for itself ----
  async function verifyCandidate({ machine: m, hostSig, endpoint }, committeeId, genesisOwners = null) {
    if (genesisOwners) {
      // Before contacting a proposed endpoint, bind its host to a wallet this
      // image explicitly admits. Genesis peers must run this same measured code.
      const reg = await chain.readRegistryEntry({registryId:m.registryId});
      if (!reg.entry?.active || !genesisOwners.includes(reg.entry.owner) || m.measurement !== me.measurement)
        return {ok:false,reason:'genesis owner or measured code is outside policy'};
    }
    const nonce = randomBytes(32).toString("hex");
    const ev = await fetchJson(`${m.endpoint}/v2/custody/evidence`, { nonce });
    if (!ev || lc(D.machineHash(ev.machine)) !== lc(D.machineHash(m))) return { ok: false, reason: "evidence names another machine" };
    const report = Buffer.from(String(ev.report || ""), "base64");
    const v = await verifyPeerQuote(report, { binding: machineBinding(m, Buffer.from(nonce, "hex")), auxblob: ev.auxblob ? Buffer.from(ev.auxblob, "base64") : null, minTcb });
    if (!v.ok) return { ok: false, reason: `attestation: ${v.reason}` };
    if (hex0x(sha256(Buffer.from(v.measurement, "hex"))) !== lc(m.measurement)) return { ok: false, reason: "measurement does not match the machine record" };
    if (hex0x(sha256(Buffer.from(v.chipId, "hex"))) !== lc(m.chipId)) return { ok: false, reason: "chip id does not match the machine record" };
    if (!genesisOwners) {
      const code = await chain.readCodeActiveAt({ committeeId, measurement: m.measurement });
      if (!code.activeAt || code.activeAt * 1000 > now()) return { ok: false, reason: "custodian code not active in the committee's code set" };
    }
    const reg = await chain.readRegistryEntry({ registryId: m.registryId });
    if (!reg.entry || !reg.entry.active) return { ok: false, reason: "host registry entry not active" };
    const who = await D.recoverDigest(D.hostDigest({ chainId, vault: vaultL, machine: m }), hostSig || ev.hostSig);
    if (!who || who !== reg.entry.operator) return { ok: false, reason: "host binding not signed by the host's registry operator" };
    if (!reg.entry.owner || /^0x0{40}$/.test(reg.entry.owner)) return { ok: false, reason: "host wallet ownership has not been accepted" };
    const enclave = reg.entry.owner === lc(enclaveOwner);
    if (!genesisOwners && (admissionCheck || !enclave)) {
      const c = await (admissionCheck || capacityCheck)({ machine: m, chipIdRaw: v.chipId, registry: reg.entry, receipts: Array.isArray(ev.receipts) ? ev.receipts : [] });
      if (!c || !c.ok) return { ok: false, reason: `${admissionCheck ? "membership policy" : "proof of capacity"}: ${(c && c.reason) || "refused"}` };
    }
    return { ok: true, enclave, hostSig: hostSig || ev.hostSig };
  }
  async function verifyGenesisRoster(plan, owners) {
    if (plan.chainId !== chainId || lc(plan.vault) !== vaultL || plan.machines.length < 3 || plan.machines.length > 64 ||
        plan.codeSet.length !== 1 || plan.codeSet[0] !== me.measurement ||
        !Array.isArray(plan.operatorPermits)||plan.operatorPermits.length!==plan.machines.length) return false;
    if (!plan.machines.some(m=>lc(D.machineHash(m))===lc(D.machineHash(me)))) return false;
    const accepted=new Set(), chips=new Set();
    const permitDigest=D.independentPlanDigest(plan);
    // All operators consent before any remote evidence call or sealed session
    // allocation. A public caller cannot consume a machine with a chosen salt.
    for(let i=0;i<plan.machines.length;i++){
      const reg=await chain.readRegistryEntry({registryId:plan.machines[i].registryId});
      if(!reg.entry?.active||!owners.includes(reg.entry.owner)||
         await D.recoverDigest(permitDigest,plan.operatorPermits[i])!==reg.entry.operator)return false;
    }
    for (const m of plan.machines) {
      const r=await verifyCandidate({machine:m},null,owners);
      if(!r.ok||r.enclave||chips.has(m.chipId))return false;
      const reg=await chain.readRegistryEntry({registryId:m.registryId});
      if(!reg.entry?.active||!owners.includes(reg.entry.owner)||accepted.has(reg.entry.owner))return false;
      accepted.add(reg.entry.owner);chips.add(m.chipId);
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
  async function join(body, committeeId) {
    const m = body && body.machine;
    if (!m || !/^0x[0-9a-f]{40}$/.test(lc(m.identity))) throw new Error("join: a machine record is required");
    const r = await verifyCandidate(body, committeeId);
    if (!r.ok) throw new Error(`join refused: ${r.reason}`);
    st.candidates[lc(m.identity)] = { machine: { ...m, identity: lc(m.identity) }, hostSig: r.hostSig, enclave: r.enclave, verifiedAt: now() };
    save();
    log(`[member] candidate ${lc(m.identity).slice(0, 10)} verified (${r.enclave ? "Enclave-owned" : "capacity-proven"})`);
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
    for (const c of fresh) { if (!c.enclave && chips.has(c.machine.chipId)) continue; if (!c.enclave) chips.add(c.machine.chipId); add.push({ ...c.machine, enclave: c.enclave, hostSig: c.hostSig }); }
    return [...alive, ...add];
  }
  const setKey = (ms) => ms.map((m) => m.identity).sort().join(",");
  function dealersFor(com, aliveIds) {
    // exactly t_old indices from ALIVE machines; the Enclave seat's indices from one Enclave machine
    const lay = v2.seatLayout(com.machines);
    const out = [];
    for (const seat of lay.seats) {
      if (!seat.machines.some((mi) => aliveIds.has(com.machines[mi].identity))) continue;
      for (const k of seat.indices) { if (out.length < lay.t) out.push(k); }
    }
    return out.length === lay.t ? out : null;
  }

  // ---- approvals: another member asks this one to sign a proposal ----
  async function approve({ committeeId, fromEpoch, next, dealerIndices }) {
    const { committee: com, pending } = await chain.readCommittee({ committeeId });
    if (!com || com.epoch !== fromEpoch) throw new Error("approve: not the current epoch");
    if (pending && pending.expires * 1000 > now()) throw new Error("approve: a handover is already pending");
    if (!com.machines.some((m) => m.identity === me.identity)) throw new Error("approve: this machine is not a current member");
    const mineIds = new Set(desired(com).map((m) => m.identity));
    const known = new Set(com.machines.map((m) => m.identity));
    for (const m of next) {
      if (known.has(lc(m.identity))) continue;
      if (!mineIds.has(lc(m.identity))) {           // a newcomer this member has not verified: verify it now
        const r = await verifyCandidate({ machine: m, hostSig: m.hostSig }, committeeId);
        if (!r.ok) throw new Error(`approve: candidate ${lc(m.identity).slice(0, 10)} refused: ${r.reason}`);
      }
    }
    for (const m of com.machines) {                 // a removal this member does not see as gone
      if (next.some((n) => lc(n.identity) === m.identity)) continue;
      if (m.identity === me.identity) throw new Error("approve: the proposal removes this machine, which is alive");
      if ((lastSeen.get(m.identity) || 0) > now() - SILENT_MS) throw new Error(`approve: ${m.identity.slice(0, 10)} is alive from here`);
    }
    v2.seatLayout(next.map((m) => ({ enclave: !!m.enclave })));   // throws on an invalid seat set (e.g. < 3 seats, no Enclave)
    const digest = D.handoverDigest({ chainId, vault: vaultL, committeeId, fromEpoch, next: next.map(strip), dealerIndices });
    return { approver: me.identity, sig: await D.signDigest(identity, digest) };
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
    // dealer: post my deal(s)
    const mine = shares.get(cid, com.epoch);
    for (const k of pending.dealers) {
      const s = mine.find((x) => x.k === k);
      if (!s) continue;
      const have = await chain.readDeal({ committeeId: cid, toEpoch: pending.toEpoch, dealerIndex: k });
      if (have.dealCommitments.length) continue;
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
    const next = desired(com);
    const key = setKey(next);
    if (key === setKey(com.machines)) { desiredSince = null; desiredKey = null; return { state: "steady" }; }
    try { v2.seatLayout(next); } catch (e) { return { state: "invalid_next", reason: e.message }; }
    if (desiredKey !== key) { desiredKey = key; desiredSince = t; }
    const lay = v2.seatLayout(com.machines);
    const reachable = lay.seats.filter((s) => s.machines.some((mi) => aliveIds.has(com.machines[mi].identity))).reduce((a, s) => a + s.weight, 0);
    const urgent = reachable <= lay.t + 1 && reachable < lay.W;
    if (!urgent && t - desiredSince < BATCH_MS) return { state: "batching", since: desiredSince };
    const dealerIndices = dealersFor(com, aliveIds);
    if (!dealerIndices) return { state: "stuck", reason: "fewer than t shares are reachable; waiting for members to return" };
    const proposal = { committeeId: cid, fromEpoch: com.epoch, next: next.map((m) => ({ ...strip(m), enclave: !!m.enclave, hostSig: m.hostSig })), dealerIndices };
    const approvals = [];
    let weight = 0;
    const seatOf = (id) => lay.seats.find((s) => s.machines.some((mi) => com.machines[mi].identity === id));
    const counted = new Set();
    const credit = (id) => { const s = seatOf(id); if (s && !counted.has(s)) { counted.add(s); weight += s.weight; } };
    approvals.push(await approve(proposal)); credit(me.identity);
    for (const m of com.machines) {
      if (weight >= lay.t || m.identity === me.identity || !aliveIds.has(m.identity)) continue;
      try { const a = await fetchJson(`${m.endpoint}/v2/custody/approve`, proposal); if (a && lc(a.approver) === m.identity) { approvals.push(a); credit(m.identity); } } catch (e) { log(`[member] ${m.identity.slice(0, 10)} did not approve: ${e.message}`); }
    }
    if (weight < lay.t) return { state: "unapproved", weight, t: lay.t };
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

  return { me, shares, info, evidence, setHostSig, genesis, verifyGenesisRoster, adoptIndependentGenesis, join, approve, tick, _state: () => st, _lastSeen: lastSeen };
}
