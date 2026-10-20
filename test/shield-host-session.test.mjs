// relay/shield-host-session.mjs, the host-session exchange shared by the custodian (custody/v2/shield-evidence.mjs), the
// independent market verifier and the DNS-01 responder: the EK is checked against THIS party's pinned roots at the
// CHALLENGE, before any pending entry or credential exists - chain to a pinned root, a leaf (not a CA), an on-die TPM
// manufacturer, at most MAX_PENDING_PER_EK pending per EK - so malicious certificates cannot use up pending capacity; the
// genuine host still challenges, attests (the full hv-node verification, unchanged), and a replayed or expired session is
// refused.   Needs openssl.   run: node --test test/shield-host-session.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, createHash, generateKeyPairSync } from "node:crypto";
import { keccak256, toBytes, recoverMessageAddress } from "viem";
import { buildHvNodeFrame } from "../windows/node/hvnode-evidence.mjs";
import { attachMessage } from "../windows/node/shield-verdict.mjs";
import { createHostSessions, MAX_PENDING_PER_EK } from "../relay/shield-host-session.mjs";
import { issueEk } from "./fixtures/vbs-synthetic.mjs";
import { maliciousEks } from "./helpers/malicious-ek.mjs";
import { options, world, other, hex, b64, ENDPOINT, operator, stranger, fakeTpm } from "./helpers/shield-custody-rig.mjs";

const PARTY = "ab".repeat(32), HOST_ID = keccak256(toBytes(ENDPOINT));
const sha = (b) => createHash("sha256").update(b).digest();
const genuineKeys = (w = world) => ({ ek: b64(w.ek.cert), ekChain: [], aikPub: b64(w.aik.tpmtPublic), aikName: b64(w.aik.name) });
const sessionsFor = ({ roots = world, maxSessions = 64, now = Date.now, ekRootPins } = {}) => createHostSessions({ party: PARTY, ekRoots: roots.ca.bundlePem, ekRootPins,
  registryEntry: async (id) => (id === HOST_ID ? { endpoint: ENDPOINT, operator: operator.address } : null),
  recoverSigner: (message, signature) => recoverMessageAddress({ message, signature }), now, maxSessions });
const ask = (h, keys) => h.challenge({ hostId: HOST_ID, endpoint: ENDPOINT, hostChallenge: randomBytes(32).toString("hex"), keys });
async function answer(h, ch, hostChallenge, w = world, signer = operator) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }), nonce = Buffer.from(ch.nonce, "base64");
  const frame = await buildHvNodeFrame({ nonce, credentialBlob: Buffer.from(ch.credentialBlob, "base64"), secret: Buffer.from(ch.secret, "base64"), spki, privateKey, tpm: fakeTpm(w) });
  const operatorSig = await signer.signMessage({ message: attachMessage({ verifier: PARTY, hostId: HOST_ID, endpoint: ENDPOINT, nonce: hex(nonce),
    transportKeySha256: hex(sha(spki)), ekCertSha256: hex(sha(w.ek.cert)), hostChallenge }) });
  return { session: ch.session, rad: frame.rad, operatorSig };
}

test("every malicious EK is refused at the challenge with no pending entry and no credential; the genuine EK is not", options, async () => {
  const h = sessionsFor();
  for (const [name, m] of Object.entries(maliciousEks(world, other)))
    await assert.rejects(ask(h, m.keys), (e) => { assert.equal(e.status, 403, `${name}: ${e.message}`); assert.match(e.message, m.why, name); return true; });
  assert.equal(h.pending(), 0, "nothing was allocated");
  const ch = await ask(h, genuineKeys());
  assert.ok(ch.session && ch.credentialBlob && ch.secret);
  assert.equal(h.pending(), 1);
});

test("pending capacity: a flood of malicious EKs takes none of it; one genuine EK holds at most MAX_PENDING_PER_EK", options, async () => {
  const h = sessionsFor({ maxSessions: 3 });
  const bad = Object.values(maliciousEks(world, other));
  for (let i = 0; i < 100; i++) await assert.rejects(ask(h, bad[i % bad.length].keys), (e) => e.status === 403);
  assert.equal(h.pending(), 0);
  // the genuine host's certificate replayed by someone without its TPM: at most MAX_PENDING_PER_EK slots
  for (let i = 0; i < MAX_PENDING_PER_EK; i++) await ask(h, genuineKeys());
  await assert.rejects(ask(h, genuineKeys()), (e) => e.status === 429 && /already holds its pending challenges/.test(e.message));
  // another genuine TPM under the same pinned CA still gets the remaining slot; then the table is full
  const second = { ...world, ek: issueEk(world.dir) }, third = { ...world, ek: issueEk(world.dir) };
  await ask(h, genuineKeys(second));
  await assert.rejects(ask(h, genuineKeys(third)), (e) => e.status === 429 && /busy/.test(e.message));
  assert.equal(h.pending(), 3);
});

test("the genuine host attests (full hv-node verification, unchanged); replayed and expired sessions are refused; the anchors are the caller's", options, async () => {
  let t = Date.now();
  const h = sessionsFor({ now: () => t });
  const hostChallenge = randomBytes(32).toString("hex");
  const ch = await h.challenge({ hostId: HOST_ID, endpoint: ENDPOINT, hostChallenge, keys: genuineKeys() });
  const body = await answer(h, ch, hostChallenge);
  const s = await h.verify(body);
  assert.deepEqual([s.identity, s.signer, s.host.admissible], ["registry", operator.address.toLowerCase(), true]);
  await assert.rejects(h.verify(body), (e) => e.status === 409);                          // single use
  const ch2 = await h.challenge({ hostId: HOST_ID, endpoint: ENDPOINT, hostChallenge, keys: genuineKeys() });
  const body2 = await answer(h, ch2, hostChallenge);
  t += 61_000;
  await assert.rejects(h.verify(body2), (e) => e.status === 409 && /expired/.test(e.message));
  assert.equal(h.pending(), 0, "expired entries are swept");
  // attest still checks everything after a passed challenge: a genuine TPM round signed by another key than the
  // registered operator, and a frame that is not the TPM's, are refused there
  t = Date.now();
  const ch3 = await h.challenge({ hostId: HOST_ID, endpoint: ENDPOINT, hostChallenge, keys: genuineKeys() });
  await assert.rejects(h.verify(await answer(h, ch3, hostChallenge, world, stranger)), (e) => e.status === 403 && /registered operator did not sign/.test(e.message));
  const ch4 = await h.challenge({ hostId: HOST_ID, endpoint: ENDPOINT, hostChallenge, keys: genuineKeys() });
  const forged = await answer(h, ch4, hostChallenge);
  await assert.rejects(h.verify({ ...forged, rad: { ...forged.rad, body: Buffer.from("{}").toString("base64") } }), (e) => e.status === 403 && /hv-node evidence refused/.test(e.message));
  // the anchors come only from the constructor's policy: none pinned is refused at construction
  assert.throws(() => sessionsFor({ ekRootPins: ["00".repeat(32)] }), /at least one pinned TPM EK root/);
  assert.throws(() => createHostSessions({ party: PARTY, ekRoots: world.ca.interPem, registryEntry: null, recoverSigner: async () => null }), /at least one pinned TPM EK root/);
  // ...and the request's own ekChain never anchors: another CA's root supplied by the caller is refused
  const m = maliciousEks(world, other).otherCa;
  await assert.rejects(ask(sessionsFor(), m.keys), (e) => e.status === 403);
});
