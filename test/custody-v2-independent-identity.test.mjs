// Machine-record integrity across handovers, on a REAL chain (anvil, real EnclaveSecretVaultV2 / EnclaveHostOwnership,
// real FROST DKG), exercising the actual member approve() and dealer (tick -> handoverStep) paths:
//   - a current identity with ANY altered record field (encKey, endpoint, chipId, registryId, measurement), a duplicate
//     identity or an Enclave flag the vault would not assign is refused by approvers;
//   - the vault itself accepts a pending set that substitutes a current member's encryption key when t approval
//     signatures exist (simulated here with the identity keys: old-code or compromised approvers); honest dealers did
//     not approve it, so they withhold their deals - no share is encrypted to the substituted key, current shares
//     stay and releases continue;
//   - a dealer deals only for a pending set it approved itself, after re-attesting each recipient: an unreachable
//     recipient withholds the deal safely until it is reachable;
//   - a seat transferred to the Enclave wallet keeps serving, is never carried into the next epoch of an independent
//     committee (no Enclave seat, no Enclave veto), and a full owner-admitted rotation then succeeds.
// Custodian self-attestation is stubbed and app-guest attestation simulated (helpers/independent-custody-rig.mjs).
import test, { before } from "node:test";
import assert from "node:assert/strict";
import { anvilAvailable } from "./helpers/custody-rig.mjs";
import { independentRig, buildDkgHelper, sha } from "./helpers/independent-custody-rig.mjs";
import * as D from "../custody/v2/digests.mjs";
import * as W from "../custody/v2/workflow.mjs";
import { VAULT_V2_ABI } from "../custody/v2/chain.mjs";
import { BATCH_MS } from "../custody/v2/member.mjs";

const skip = anvilAvailable() ? false : "anvil not installed";
before(() => { if (!skip) buildDkgHelper(); });
const strip = (m) => ({ identity: m.identity, encKey: m.encKey, endpoint: m.endpoint, chipId: m.chipId, registryId: m.registryId, measurement: m.measurement });
const entry = (m, extra = {}) => ({ ...m.machine, enclave: false, hostSig: m.info().hostSig, ...extra });
async function founders(r, names) {
  const o = {};
  for (const k of names) o[k] = await r.owner();
  const ms = [];
  for (const [i, k] of ["a", "b", "c"].entries()) ms.push(await r.makeMachine(`m${i}`, await r.host(`h${i}`, o[k])));
  const { cid } = await r.form(ms);
  return { o, ms, cid };
}

test("altered records under a current identity are refused; a substituted encryption key receives no share", { skip, timeout: 300_000 }, async () => {
  const r = await independentRig();
  try {
    const { o, ms: [M0, M1, M2], cid } = await founders(r, ["a", "b", "c", "d"]);
    const env = { KEY: "identity-bound" };
    await r.publish(cid, env, 1, 0);
    const h3 = await r.host("h3", o.d);
    const { committee: com } = await r.chain.readCommittee({ committeeId: cid });
    const base = { committeeId: cid, fromEpoch: com.epoch, dealerIndices: [1, 2] };
    const altered = {
      encKey: { encKey: "0x" + "ab".repeat(32) },
      endpoint: { endpoint: "https://attacker.example" },
      chipId: { chipId: sha(Buffer.from("other chip")) },
      registryId: { registryId: h3.registryId },
      measurement: { measurement: sha(Buffer.alloc(48, 0x99)) },
    };
    for (const [field, change] of Object.entries(altered)) {
      const rec = { ...M2.machine, ...change }, op = field === "registryId" ? h3.op : M2.host.op;
      const forged = { ...rec, enclave: false, hostSig: await D.signDigest(op, D.hostDigest({ chainId: r.chainId, vault: r.vault, machine: rec })) };
      for (const approver of [M0, M1])
        await assert.rejects(approver.member.approve({ ...base, next: [entry(M0), entry(M1), forged] }), /changes the machine record of a current identity/, field);
    }
    await assert.rejects(M0.member.approve({ ...base, next: [entry(M0), entry(M1), entry(M2, { enclave: true })] }), /Enclave flag the vault would not assign/);
    await assert.rejects(M0.member.approve({ ...base, next: [entry(M0), entry(M1), entry(M2), entry(M2)] }), /appears twice/);
    await assert.rejects(M0.member.join({ machine: { ...M2.machine, encKey: "0x" + "ab".repeat(32) } }, cid), /already holds a seat/);

    // The vault alone accepts a substituted key under M2's identity once t approval signatures exist.
    const attackerKey = "0x" + "cd".repeat(32), sub = { ...M2.machine, encKey: attackerKey };
    const next = [M0.machine, M1.machine, sub].map(strip);
    const digest = D.handoverDigest({ chainId: r.chainId, vault: r.vault, committeeId: cid, fromEpoch: 1, next, dealerIndices: [1, 2] });
    const hostSigs = [M0.info().hostSig, M1.info().hostSig, await D.signDigest(M2.host.op, D.hostDigest({ chainId: r.chainId, vault: r.vault, machine: sub }))];
    await r.send(await r.acct(), r.vault, VAULT_V2_ABI, "proposeHandover",
      [cid, next, hostSigs, [1, 2], [M0.machine.identity, M1.machine.identity], [await D.signDigest(M0.identity, digest), await D.signDigest(M1.identity, digest)]]);
    const { pending } = await r.chain.readCommittee({ committeeId: cid });
    assert.equal(pending.next[2].encKey, attackerKey, "the vault accepted the substituted key");
    for (const dealer of [M0, M1]) {
      const res = await dealer.member.tick(cid);
      assert.equal(res.state, "deal_withheld", JSON.stringify(res));
      assert.match(res.reason, /did not approve this exact pending set/);
    }
    for (const k of [1, 2]) assert.equal((await r.chain.readDeal({ committeeId: cid, toEpoch: pending.toEpoch, dealerIndex: k })).dealCommitments.length, 0, "no share was encrypted");
    assert.equal(M0.member.shares.get(cid, 1).length, 1, "current shares stay");
    assert.deepEqual(await r.unlock(cid, [M0, M2]), env, "releases continue at the current epoch");
  } finally { r.stop(); }
});

test("a dealer deals only for a pending set it approved, after re-attesting reachable recipients", { skip, timeout: 300_000 }, async () => {
  const r = await independentRig();
  try {
    const { o, ms: [M0, M1, M2], cid } = await founders(r, ["a", "b", "c", "d"]);
    const env = { KEY: "dealer-bound" };
    await r.publish(cid, env, 1, 0);
    const N3 = await r.makeMachine("n3", await r.host("h3", o.d));
    const adm = await r.admission(cid, N3, [o.d, o.a, o.b]);
    const admission = { expiresAt: adm.expiresAt, signatures: adm.signatures };
    for (const m of [M0, M1, M2]) await m.member.join({ machine: N3.machine, admission }, cid);
    const proposal = { committeeId: cid, fromEpoch: 1, dealerIndices: [1, 3], next: [entry(M0), entry(M1), entry(M2), entry(N3, { admission })] };
    // M0 (a dealer) and M1 approve with the actual method; M2 (the other dealer) never does
    const approvals = [await M0.member.approve(proposal), await M1.member.approve(proposal)];
    const hostSigs = proposal.next.map((m) => m.hostSig);
    await r.send(await r.acct(), r.vault, VAULT_V2_ABI, "proposeHandover",
      [cid, proposal.next.map(strip), hostSigs, [1, 3], approvals.map((a) => a.approver), approvals.map((a) => a.sig)]);
    const { pending } = await r.chain.readCommittee({ committeeId: cid });
    const dealt = async (k) => (await r.chain.readDeal({ committeeId: cid, toEpoch: pending.toEpoch, dealerIndex: k })).dealCommitments.length > 0;

    r.down.add("n3");
    let res = await M0.member.tick(cid);
    assert.equal(res.state, "deal_withheld");
    assert.match(res.reason, /recipient .*unreachable/);
    assert.equal(await dealt(1), false, "nothing is dealt to an unattested recipient");
    assert.equal(M0.member.shares.get(cid, 1).length, 1);
    res = await M2.member.tick(cid);
    assert.equal(res.state, "deal_withheld");
    assert.match(res.reason, /did not approve/);
    r.down.delete("n3");
    await M0.member.tick(cid);
    assert.equal(await dealt(1), true, "the approving dealer deals once its recipient re-attests");
    assert.equal(await dealt(3), false);
    assert.equal((await r.chain.readCommittee({ committeeId: cid })).committee.epoch, 1, "no rotation without every dealer's own approval");
    assert.deepEqual(await r.unlock(cid, [M1, M2]), env, "releases continue while the handover is withheld");
  } finally { r.stop(); }
});

test("a seat moved to the Enclave wallet keeps serving, never becomes an Enclave seat, and is rotated out", { skip, timeout: 300_000 }, async () => {
  const r = await independentRig();
  try {
    const { o, ms: [M0, M1, M2], cid } = await founders(r, ["a", "b", "c", "d"]);
    const env = { KEY: "independent-after-transfer" };
    await r.publish(cid, env, 1, 0);
    const enclave = { address: r.enclaveWallet.address.toLowerCase(), account: r.enclaveWallet };
    await r.transfer(M1.host, enclave);
    let status = await W.committeeStatus({ chain: r.chain, committeeId: cid, chainId: r.chainId, vault: r.vault, get: r.get });
    assert.deepEqual([status.releaseAvailable, status.governanceVoters, status.nonVotingSeats], [true, 2, [M1.machine.identity]]);
    assert.deepEqual(await r.unlock(cid, [M0, M1]), env, "service: the transferred seat still releases");
    const base = { committeeId: cid, fromEpoch: 1, dealerIndices: [1, 3] };
    for (const flag of [true, false])
      await assert.rejects(M0.member.approve({ ...base, next: [entry(M0), entry(M1, { enclave: flag }), entry(M2)] }), /no longer an eligible seat/);

    for (const m of [M0, M1, M2]) await m.member.tick(cid);         // heartbeats; without a newcomer only 2 eligible seats remain
    const [coordinator] = [M0, M1, M2].sort((x, y) => (x.machine.identity < y.machine.identity ? -1 : 1));
    assert.equal((await coordinator.member.tick(cid)).state, "invalid_next", "no 2-seat set (which would need an Enclave seat)");
    assert.deepEqual(await r.unlock(cid, [M0, M2]), env);

    const N3 = await r.makeMachine("n3", await r.host("h3", o.d));
    const adm = await r.admission(cid, N3, [o.d, o.a, o.c]);
    for (const m of [M0, M1, M2]) await m.member.join({ machine: N3.machine, admission: { expiresAt: adm.expiresAt, signatures: adm.signatures } }, cid);
    for (const m of [M0, M1, M2]) await m.member.tick(cid);
    r.clock.skew = BATCH_MS + 1000;
    const proposed = await coordinator.member.tick(cid);
    assert.equal(proposed.state, "proposed", JSON.stringify(proposed));
    const { pending } = await r.chain.readCommittee({ committeeId: cid });
    assert.deepEqual(pending.next.map((m) => [m.identity, m.enclave]), [[M0.machine.identity, false], [M2.machine.identity, false], [N3.machine.identity, false]]);
    assert.deepEqual(pending.dealers, [1, 3], "the staying seats deal");
    for (let i = 0; i < 4; i++) for (const m of [M0, M1, M2, N3]) await m.member.tick(cid);
    const { committee } = await r.chain.readCommittee({ committeeId: cid });
    assert.deepEqual([committee.epoch, committee.t, committee.W, committee.machines.some((m) => m.enclave)], [2, 2, 3, false]);
    for (const m of [M0, M2, N3]) await m.member.tick(cid);
    assert.deepEqual(await r.unlock(cid, [M2, N3]), env, "the rotated independent committee releases the existing bundle");
    assert.deepEqual(M1.member.shares.get(cid, 2), []);
    status = await W.committeeStatus({ chain: r.chain, committeeId: cid, chainId: r.chainId, vault: r.vault, get: r.get });
    assert.deepEqual([status.independent, status.distinctOwners, status.releaseAvailable], [true, true, true]);
  } finally { r.stop(); }
});
