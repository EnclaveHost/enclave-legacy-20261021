// The custodian's independent genesis service (custody/v2/independent-runtime.mjs) with the REAL FROST helper, and the
// owner-permit policy edges (custody/v2/governance.mjs). Chain, roster verification and attestation are stubs here;
// custody-v2-independent-lifecycle.test.mjs runs the same service against the real vault.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import * as hpke from '../custody/hpke.mjs';
import * as D from '../custody/v2/digests.mjs';
import { dkgHelper, independentSession } from '../custody/v2/independent-genesis.mjs';
import { createIndependentService, MAX_ABANDONED } from '../custody/v2/independent-runtime.mjs';
import { coordinateIndependentGenesis } from '../custody/v2/coordinate-genesis.mjs';
import { independentPolicy, ownerPermitAdmission, admissionDigest, codePermitDigest, permitLive, signatureBatch, governanceVoters, judgeCodePermit, admissionClaims, MAX_PERMIT_SEC } from '../custody/v2/governance.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const invoke = dkgHelper(root + 'custody/dkg/target/debug/enclave-custody-dkg');
before(() => execFileSync('cargo', ['build', '--locked', '--manifest-path', root + 'custody/dkg/Cargo.toml'], { stdio: 'pipe', timeout: 300000 }));
const hex = (n, bytes = 32) => '0x' + n.toString(16).padStart(bytes * 2, '0');

function node(i) {
  const identity = privateKeyToAccount(generatePrivateKey()), keys = hpke.generateKeyPair();
  const machine = { identity: identity.address.toLowerCase(), encKey: '0x' + Buffer.from(keys.publicKey).toString('hex'), endpoint: `https://custodian-${i}.example`,
                    chipId: hex(i + 1), registryId: hex(i + 10), measurement: hex(99) };
  const state = {}, approved = new Set();
  const member = { verifyGenesisRoster: async p => approved.has(independentSession(p)), committees: () => [] };
  const genesis = createIndependentService({ policy: { mode: 'owner-permits' }, member, chain: null, identity, encPrivateKey: keys.privateKey, invoke, state,
    persist: async () => {}, fetchJson: async () => { throw Error('no peer calls'); }, submit: async () => { throw Error('no transactions'); } });
  return { machine, state, approved, genesis };
}
const planOf = (nodes, salt) => ({ chainId: 8453, vault: hex(44, 20), salt: hex(salt), machines: nodes.map(n => n.machine), codeSet: [hex(99)] });
const approve = (nodes, plan) => { for (const n of nodes) n.approved.add(independentSession(plan)); };

test('one founder refusing does not strand the others: an unfinished session is replaced only by a permitted plan, never resumed', async () => {
  const [a, b, c, d] = [0, 1, 2, 3].map(node);
  const A = planOf([a, b, c], 1);
  approve([a, b, c], A);
  const one = await Promise.all([a, b, c].map(n => n.genesis({ action: 'start', plan: A })));
  const acks = await Promise.all([a, b, c].map(n => n.genesis({ action: 'agree', round1: one })));
  await Promise.all([a, b].map(n => n.genesis({ action: 'exchange', acks })));   // c refuses from here on
  assert.equal(a.state.independentDkg.phase, 2);

  const B = planOf([a, b, d], 2);
  await assert.rejects(a.genesis({ action: 'start', plan: B }), /replacement roster not verified/);
  assert.equal(independentSession(a.state.independentPlan), independentSession(A), 'an unpermitted plan changes nothing');
  approve([a, b, d], B);
  await a.genesis({ action: 'agree', plan: B, round1: one });
  assert.equal(independentSession(a.state.independentPlan), independentSession(A), 'only start may replace a plan');
  const posts = { [a.machine.endpoint]: a, [b.machine.endpoint]: b, [d.machine.endpoint]: d };
  const post = async (url, body) => posts[url.replace('/v2/custody/independent-genesis', '')].genesis(body);
  const get = async () => { throw Error('offline'); };
  const result = await coordinateIndependentGenesis(B, { post, get });
  assert.equal(result.results.length, 3);
  assert.deepEqual(a.state.abandonedSessions, [independentSession(A)]);
  for (const n of [a, b]) {
    await assert.rejects(n.genesis({ action: 'start', plan: A }), /finished DKG session/);
  }
  // before finishing, a node that abandoned A still refuses to go back to it
  const e = node(4), f = node(5), g = node(6);
  const P = planOf([e, f, g], 7), Q = planOf([e, f, g], 8);
  approve([e, f, g], P); approve([e, f, g], Q);
  await e.genesis({ action: 'start', plan: P });
  await e.genesis({ action: 'start', plan: Q });
  await assert.rejects(e.genesis({ action: 'start', plan: P }), /abandoned/);
  assert.equal(independentSession(e.state.independentPlan), independentSession(Q));
  assert.equal(e.state.independentDkg.phase, 1, 'the replacement session starts from fresh randomness');
});

test(`abandoned sessions are tombstones: after ${MAX_ABANDONED} replans the identity refuses more instead of forgetting the oldest`, async () => {
  const peers = [node(10), node(11)], n = node(12);
  const plans = Array.from({ length: MAX_ABANDONED + 2 }, (_, i) => planOf([n, ...peers], 100 + i));
  for (const p of plans) approve([n], p);
  await n.genesis({ action: 'start', plan: plans[0] });
  for (let i = 1; i <= MAX_ABANDONED; i++) await n.genesis({ action: 'start', plan: plans[i] });
  assert.equal(n.state.abandonedSessions.length, MAX_ABANDONED);
  assert.equal(independentSession(n.state.independentPlan), independentSession(plans[MAX_ABANDONED]));
  // the limit fails closed: no further replan, and the oldest and every other tombstone stays refused
  await assert.rejects(n.genesis({ action: 'start', plan: plans[MAX_ABANDONED + 1] }), /replan limit reached/);
  for (const i of [0, 1, MAX_ABANDONED - 1]) await assert.rejects(n.genesis({ action: 'start', plan: plans[i] }), /abandoned/);
  assert.deepEqual(n.state.abandonedSessions, plans.slice(0, MAX_ABANDONED).map(independentSession));
  assert.equal(independentSession(n.state.independentPlan), independentSession(plans[MAX_ABANDONED]), 'the current session still serves');
});

// A snapshot as chain.mjs readAuthorization returns it: one block for committee, owners, operators and ERC-1271 answers.
function snapshotOf({ machines, owners, t, enclaveFlags = [], extra = {}, valid = [], blockTimestamp = 5000 }) {
  const entries = {};
  machines.forEach((m, i) => { entries[m.registryId] = { active: true, owner: owners[i], operator: hex(900 + i, 20) }; });
  Object.assign(entries, extra);
  return { committee: { machines: machines.map((m, i) => ({ ...m, enclave: !!enclaveFlags[i] })), t, epoch: 3 }, entries, valid, blockTimestamp, blockNumber: 77n };
}

test('measured policy selection and owner-permit admission judged at one snapshot', async () => {
  const enclave = hex(999, 20), owners = [hex(1, 20), hex(2, 20), hex(3, 20)];
  assert.equal(independentPolicy({ enclaveOwner: enclave, independentOwners: null }), null);
  assert.equal(independentPolicy({ enclaveOwner: enclave, independentOwners: null, independentAdmission: 'owner-permits' }).mode, 'owner-permits');
  assert.deepEqual(independentPolicy({ enclaveOwner: enclave, independentOwners: owners }).owners, owners);
  assert.throws(() => independentPolicy({ enclaveOwner: enclave, independentOwners: owners, independentAdmission: 'owner-permits' }), /conflicts/);
  assert.throws(() => independentPolicy({ enclaveOwner: enclave, independentAdmission: 'anyone' }), /unknown/);
  assert.equal(permitLive(1000 + MAX_PERMIT_SEC, 1000), true);
  assert.equal(permitLive(1001 + MAX_PERMIT_SEC, 1000), false);
  assert.equal(permitLive(1000, 1000), false);

  const keys = [0, 1, 2, 3, 4].map(() => privateKeyToAccount(generatePrivateKey()));
  const seat = keys.slice(0, 3).map(k => k.address.toLowerCase()), candidateOwner = keys[3], later = keys[4];
  const machines = seat.map((_, i) => ({ identity: hex(100 + i, 20), encKey: hex(200 + i), endpoint: `https://m${i}.example`, chipId: hex(300 + i), registryId: hex(400 + i), measurement: hex(99) }));
  const cand = { identity: hex(110, 20), encKey: hex(210), endpoint: 'https://new.example', chipId: hex(310), registryId: hex(410), measurement: hex(99) };
  const cid = hex(55), expiresAt = 6000, check = ownerPermitAdmission({ enclaveOwner: enclave });
  const digest = admissionDigest({ chainId: 8453, vault: hex(44, 20), committeeId: cid, machine: cand, expiresAt });
  const sign = (k, d = digest) => D.signDigest(k, d).then(signature => ({ owner: k.address, signature }));
  const judge = async ({ signatures, candOwner = candidateOwner.address.toLowerCase(), seatOwners = seat, enclaveFlags, exp = expiresAt, machine = cand, ts }) => {
    const batch = signatureBatch(), admission = { expiresAt: exp, signatures };
    const handle = await batch.add(admissionDigest({ chainId: 8453, vault: hex(44, 20), committeeId: cid, machine, expiresAt: exp }), admissionClaims(admission));
    const snapshot = snapshotOf({ machines, owners: seatOwners, t: 2, enclaveFlags, extra: { [cand.registryId]: { active: true, owner: candOwner, operator: hex(950, 20) } }, valid: batch.checks.map(() => false), blockTimestamp: ts });
    return check({ machine: cand, admission, snapshot, signers: batch.signers(handle, snapshot) });
  };
  const signatures = await Promise.all([candidateOwner, keys[0], keys[1]].map(k => sign(k)));
  assert.equal((await judge({ signatures })).ok, true);
  assert.match((await judge({ signatures: [signatures[0], signatures[1], { ...signatures[1] }] })).reason, /1 of 2/);
  assert.match((await judge({ signatures, candOwner: enclave })).reason, /non-Enclave owner/);
  assert.match((await judge({ signatures, exp: 5000 + MAX_PERMIT_SEC + 1 })).reason, /expired or too long/);
  assert.match((await judge({ signatures, machine: { ...cand, chipId: hex(311) } })).reason, /own owner did not sign/);
  assert.match((await judge({ signatures, enclaveFlags: [true] })).reason, /only to independent committees/);
  // the admission's authorization point: at the judged block the candidate's owner is LATER, who never signed
  assert.match((await judge({ signatures, candOwner: later.address.toLowerCase() })).reason, /own owner did not sign/);
  // expired at the judged block although live when it was signed
  assert.match((await judge({ signatures, ts: expiresAt })).reason, /expired/);
  // two seats transferred to one owner count once
  assert.match((await judge({ signatures, seatOwners: [seat[0], seat[0], seat[2]] })).reason, /1 of 2 required governance voters/);
  assert.equal((await check({ machine: cand, admission: { expiresAt, signatures } })).ok, false, 'no decision without a snapshot');
});

test('code permits: one vote per current owner through its canonical seat, never through a shared or Enclave-owned seat', async () => {
  const enclave = hex(999, 20), keys = [0, 1, 2].map(() => privateKeyToAccount(generatePrivateKey()));
  const owners = keys.map(k => k.address.toLowerCase());
  const machines = owners.map((_, i) => ({ identity: hex(100 + i, 20), encKey: hex(200 + i), endpoint: `https://m${i}.example`, chipId: hex(300 + i), registryId: hex(400 + i), measurement: hex(99) }));
  const permit = { expiresAt: 6000 };
  const d = codePermitDigest({ chainId: 8453, vault: hex(44, 20), committeeId: hex(55), measurement: hex(98), add: true, expiresAt: 6000 });
  const judge = async (seatOwners, index, signer, ts = 5000) => {
    const batch = signatureBatch(), handle = await batch.add(d, [{ registryId: machines[index].registryId, signature: await D.signDigest(signer, d) }]);
    const snapshot = snapshotOf({ machines, owners: seatOwners, t: 2, valid: batch.checks.map(() => false), blockTimestamp: ts });
    return judgeCodePermit({ snapshot, index, permit, signers: batch.signers(handle, snapshot), enclaveOwner: enclave });
  };
  for (const i of [0, 1, 2]) assert.equal((await judge(owners, i, keys[i])).ok, true);
  assert.match((await judge(owners, 1, keys[0])).reason, /not authorized by this seat's owner/);
  // seat 2 (index 1) transferred to owner 0: seat 1 votes for that owner, seat 2 no longer votes, seat 3 is unaffected
  const merged = [owners[0], owners[0], owners[2]];
  assert.equal((await judge(merged, 0, keys[0])).ok, true);
  assert.match((await judge(merged, 1, keys[0])).reason, /shares its owner with seat 1/);
  assert.equal((await judge(merged, 2, keys[2])).ok, true);
  const voters = governanceVoters(snapshotOf({ machines, owners: merged, t: 2 }), enclave);
  assert.deepEqual([voters.voters.size, voters.silent], [2, [1]]);
  // a seat transferred to the Enclave wallet keeps serving but has no vote in an independent committee
  assert.match((await judge([owners[0], enclave, owners[2]], 1, keys[1])).reason, /not a governance voter/);
  assert.match((await judge(owners, 0, keys[0], 6000)).reason, /expired/);
  // legacy committee: the Enclave seat is the Enclave wallet's one vote; an ordinary seat later transferred to that
  // wallet adds no second vote (the vault would still weigh it as its own seat until the next handover)
  const legacy = async (index) => {
    const batch = signatureBatch(), handle = await batch.add(d, [{ registryId: machines[index].registryId, signature: await D.signDigest(keys[0], d) }]);
    const snapshot = snapshotOf({ machines, owners: [enclave, enclave, owners[2]], t: 2, enclaveFlags: [true], valid: batch.checks.map(() => false) });
    return judgeCodePermit({ snapshot, index, permit, signers: new Set([enclave]), enclaveOwner: enclave });
  };
  assert.equal((await legacy(0)).ok, true);
  assert.match((await legacy(1)).reason, /shares its owner with seat 1/);
});
