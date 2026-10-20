// Owner governance of an independent committee on a REAL chain (anvil, real EnclaveSecretVaultV2 and EnclaveHostOwnership,
// real FROST DKG), each fact judged at the decision's own agreed block:
//   - a candidate verified at join is re-authorized when a handover is signed: an admission that expired, or a host
//     whose owner changed after the join, is refused by approvers and dropped by the coordinator; a different record
//     under a cached identity fails attestation;
//   - existing seats transferred to one owner keep serving releases but give that owner ONE governance vote: it cannot
//     reach t code approvals alone, although the vault itself would count both machine signatures.
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const proposalOf = (cid, com, members, extra) => ({ committeeId: cid, fromEpoch: com.epoch, dealerIndices: [1, 2],
  next: [...members.map((m) => ({ ...m.machine, enclave: false, hostSig: m.info().hostSig })), ...extra] });

test("a cached candidate is re-authorized at signing: expired admission, changed owner and substituted record are refused", { skip, timeout: 300_000 }, async () => {
  const r = await independentRig();
  try {
    const o = {};
    for (const k of ["a", "b", "c", "d", "e", "f"]) o[k] = await r.owner();
    const [M0, M1, M2] = [await r.makeMachine("m0", await r.host("h0", o.a)), await r.makeMachine("m1", await r.host("h1", o.b)), await r.makeMachine("m2", await r.host("h2", o.c))];
    const { cid } = await r.form([M0, M1, M2]);
    let { committee: com } = await r.chain.readCommittee({ committeeId: cid });
    const N3 = await r.makeMachine("n3", await r.host("h3", o.d)), N4 = await r.makeMachine("n4", await r.host("h4", o.e));

    // N3: an admission that is live at join but expires before any handover is signed
    const short = await r.admission(cid, N3, [o.d, o.a, o.b], { seconds: 4 });
    for (const m of [M0, M1, M2]) assert.ok((await m.member.join({ machine: N3.machine, admission: { expiresAt: short.expiresAt, signatures: short.signatures } }, cid)).ok);
    // N4: a long admission; then N4's host is handed to a wallet that never consented
    const long = await r.admission(cid, N4, [o.e, o.a, o.b]);
    for (const m of [M0, M1, M2]) assert.ok((await m.member.join({ machine: N4.machine, admission: { expiresAt: long.expiresAt, signatures: long.signatures } }, cid)).ok);
    await r.transfer(N4.host, o.f);
    while (Number((await r.pub.getBlock()).timestamp) <= short.expiresAt) { await sleep(1000); await r.mine(); }

    const n3 = { ...N3.machine, enclave: false, hostSig: N3.info().hostSig, admission: { expiresAt: short.expiresAt, signatures: short.signatures } };
    const n4 = { ...N4.machine, enclave: false, hostSig: N4.info().hostSig, admission: { expiresAt: long.expiresAt, signatures: long.signatures } };
    assert.ok(M2.member._state().candidates[N3.machine.identity] && M2.member._state().candidates[N4.machine.identity], "both are cached candidates");
    await assert.rejects(M2.member.approve(proposalOf(cid, com, [M0, M1, M2], [n3])), /expired/);
    await assert.rejects(M2.member.approve(proposalOf(cid, com, [M0, M1, M2], [n4])), /own owner did not sign/);
    // the same identity with another record (here: another encryption key) cannot ride on the cached verification
    await assert.rejects(M2.member.approve(proposalOf(cid, com, [M0, M1, M2], [{ ...n4, encKey: "0x" + "11".repeat(32) }])), /evidence names another machine/);

    // the coordinator re-verifies its cached candidates before proposing, forgets both, and proposes nothing
    const [coordinator] = [M0, M1, M2].sort((x, y) => (x.machine.identity < y.machine.identity ? -1 : 1));
    for (const m of [M0, M1, M2]) await m.member.tick(cid);            // heartbeats; the coordinator starts its batching window
    assert.deepEqual(Object.keys(coordinator.member._state().candidates).sort(), [N3.machine.identity, N4.machine.identity].sort());
    r.clock.skew = BATCH_MS + 1000;
    const res = await coordinator.member.tick(cid);
    assert.equal(res.state, "steady", JSON.stringify(res));
    assert.equal(coordinator.member._state().candidates[N4.machine.identity], undefined, "the changed-owner candidate is forgotten");
    assert.equal(coordinator.member._state().candidates[N3.machine.identity], undefined, "the expired candidate is forgotten");
    ({ committee: com } = await r.chain.readCommittee({ committeeId: cid }));
    assert.equal(com.epoch, 1, "no handover was proposed");

    // re-consent by the CURRENT owner at a fresh expiry is admitted again
    const again = await r.admission(cid, N4, [o.f, o.a, o.b]);
    assert.ok((await M1.member.join({ machine: N4.machine, admission: { expiresAt: again.expiresAt, signatures: again.signatures } }, cid)).ok);
  } finally { r.stop(); }
});

test("seats transferred to one owner keep serving but count once in owner governance", { skip, timeout: 300_000 }, async () => {
  const r = await independentRig();
  try {
    const o = {};
    for (const k of ["a", "b", "c", "d"]) o[k] = await r.owner();
    const [M0, M1, M2] = [await r.makeMachine("m0", await r.host("h0", o.a)), await r.makeMachine("m1", await r.host("h1", o.b)), await r.makeMachine("m2", await r.host("h2", o.c))];
    const { cid } = await r.form([M0, M1, M2]);
    const env = { KEY: "served-after-transfer" };
    await r.publish(cid, env, 1, 0);

    // seat 2's host is handed to seat 1's owner
    await r.transfer(M1.host, o.a);
    const status = await W.committeeStatus({ chain: r.chain, committeeId: cid, chainId: r.chainId, vault: r.vault, get: r.get });
    assert.deepEqual([status.distinctOwners, status.governanceVoters, status.nonVotingSeats, status.governanceAvailable, status.releaseAvailable],
                     [false, 2, [M1.machine.identity], true, true]);
    assert.deepEqual(await r.unlock(cid, [M0, M1]), env, "service: the shared-owner seat still releases");

    const { committee } = await r.chain.readCommittee({ committeeId: cid });
    const newCode = sha(Buffer.alloc(48, 0x71));
    const { expiresAt } = await W.chainExpiry(r.chain, cid, 3600);
    const req = W.codePermitRequest({ chainId: r.chainId, vault: r.vault, committeeId: cid, measurement: newCode, add: true, expiresAt });
    const sigA = await o.a.sign(req.digest);
    const alone = await W.collectCodeApprovals({ request: req, committee, post: r.post, permits: { [M0.machine.identity]: sigA, [M1.machine.identity]: sigA } });
    assert.deepEqual([alone.weight, alone.transaction], [1, null], "one owner of two seats cannot reach t");
    assert.match(alone.refused.find((x) => x.identity === M1.machine.identity).reason, /shares its owner with seat 1/);

    // the vault by itself WOULD count both machines: the member-side voter rule is what prevents it
    const other = sha(Buffer.alloc(48, 0x72)), cd = D.codeDigest({ chainId: r.chainId, vault: r.vault, committeeId: cid, epoch: committee.epoch, measurement: other, add: true });
    const raw = [await D.signDigest(M0.identity, cd), await D.signDigest(M1.identity, cd)];
    await r.send(await r.acct(), r.vault, VAULT_V2_ABI, "proposeCode", [cid, other, [M0.machine.identity, M1.machine.identity], raw]);
    assert.ok((await r.chain.readCodeActiveAt({ committeeId: cid, measurement: other })).activeAt > 0);

    // with the other distinct owner the change is authorized; any wallet submits it
    const both = await W.collectCodeApprovals({ request: req, committee, post: r.post,
      permits: { [M0.machine.identity]: sigA, [M1.machine.identity]: sigA, [M2.machine.identity]: await o.c.sign(req.digest) } });
    assert.equal(both.weight, 2);
    await r.mined(await r.wallet(await r.acct()).sendTransaction({ to: both.transaction.to, data: both.transaction.data }), "proposeCode");
    assert.ok((await r.chain.readCodeActiveAt({ committeeId: cid, measurement: newCode })).activeAt > 0);

    // admission weight counts the merged owner once as well
    const N3 = await r.makeMachine("n3", await r.host("h3", o.d));
    const weak = await r.admission(cid, N3, [o.d, o.a]);
    await assert.rejects(M2.member.join({ machine: N3.machine, admission: { expiresAt: weak.expiresAt, signatures: weak.signatures } }, cid), /1 of 2 required governance voters/);
    const strong = await r.admission(cid, N3, [o.d, o.a, o.c]);
    assert.ok((await M2.member.join({ machine: N3.machine, admission: { expiresAt: strong.expiresAt, signatures: strong.signatures } }, cid)).ok);
  } finally { r.stop(); }
});
