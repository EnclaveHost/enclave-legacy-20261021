// The Shield market from verifiers a host's operator selected (windows/node/shield-verdict.mjs, relay/shield-independent-
// verifier.mjs): a synthetic TPM world drives the node's REAL frame builder (hvnode-evidence.mjs buildHvNodeFrame) through the
// credential round, and the verifier runs the relay's REAL checks (verifyHvNodeEvidence, the marketplace's readiness rule,
// verifyShieldAppPolicy) over HTTP. Then every way a verdict could be wrong: forged, replayed, for another node or key,
// stale, unpinned, below threshold, or a host statement standing in for evidence. Needs openssl (synthetic EK chain).
//   run: node --test test/windows-shield-verifier.test.mjs
import { test, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { randomBytes, createHash, sign, constants, generateKeyPairSync } from "node:crypto";
import { keccak256, toBytes, recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { haveOpenssl, tmpdir, makeVbsWorld, buildLog, buildQuote } from "./fixtures/vbs-synthetic.mjs";
import { activateCredential } from "../relay/vbs-credential.mjs";
import { ABI2, bind2, runtimeId } from "../isolation/contract/runtime.mjs";
import { createIndependentShieldVerifier } from "../relay/shield-independent-verifier.mjs";
import { validateVerifierSet, verifyVerdicts, createVerifierMarketClient, signVerdict, keySpecOf, keyIdOf, canonicalJson,
         attachMessage, MAX_VERDICT_TTL_MS } from "../windows/node/shield-verdict.mjs";

const options = { skip: !haveOpenssl && "openssl absent" };
const world = haveOpenssl ? makeVbsWorld(tmpdir("shield-verifier-")) : null;
const other = haveOpenssl ? makeVbsWorld(tmpdir("shield-verifier-other-")) : null;
const sha = (b) => createHash("sha256").update(b).digest(), hex = (b) => Buffer.from(b).toString("hex"), b64 = (b) => Buffer.from(b).toString("base64");
const IMAGE = "ab".repeat(32), APP = "cd".repeat(32);
const RUNTIME = { name: "wasmtime", version: "48.0.1", execution: "jit", targetIsa: "x86_64", hostIsa: "x86_64", cpuFeatures: "host-detected", wx: "enforced", cache: "none" };
const RID = runtimeId(RUNTIME);
const ENDPOINT = "https://box.example.org", HOST_ID = keccak256(toBytes(ENDPOINT));
const operator = privateKeyToAccount("0x" + "42".repeat(32)), stranger = privateKeyToAccount("0x" + "43".repeat(32));
const policy = (w) => ({ schema: "enclave-shield-app-policy/1", marketEnabled: true, hosts: "*", ekRoots: w.ca.bundlePem, platforms: "attested",
  images: [{ measurement: IMAGE, runtimeId: hex(RID) }], cpu: { runtimeId: hex(RID) }, witness: { appSha256: APP, runtimeId: hex(RID) } });

// ---- the node: a fake TPM over the synthetic world, and the readiness witness's guest -----------------------------------
function fakeTpm(w, { log = {}, idksOf = w } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shield-tpm-"));
  const L = buildLog({ idksPub: idksOf.idks.publicKey, ...log });
  fs.writeFileSync(path.join(dir, "boot.log"), L.log);
  const cmds = [];
  const tpm = async (cmd) => {
    cmds.push(cmd.split(" ")[0]);
    const [op, a, b] = cmd.split(" ");
    if (op === "log") return { log: path.join(dir, "boot.log") };
    if (op === "activate") return { credential: hex(activateCredential(w.ek.privateKey, w.aik.name, Buffer.from(a, "hex"), Buffer.from(b, "hex"))) };
    if (op === "quote") { const Q = buildQuote({ aikPriv: w.aik.privateKey, aikName: w.aik.name, pcrs: L.pcrs, pcr0: w.pcr0, extraData: Buffer.from(a, "hex") });
                          return { attest: hex(Q.attest), sig: hex(Q.sig), "aik-pub": hex(w.aik.tpmtPublic) }; }
    if (op === "pcr") return { pcr: "sha256 " + hex(w.pcr0) };
    if (op === "keys") return { "ek-cert": hex(w.ek.cert), "aik-pub": hex(w.aik.tpmtPublic), "aik-name": hex(w.aik.name) };
    throw new Error("tpm: " + cmd);
  };
  const keysFrame = async () => ({ ek: b64(w.ek.cert), ekChain: [], aikPub: b64(w.aik.tpmtPublic), aikName: b64(w.aik.name) });
  return { tpm, keysFrame, cmds };
}
function vbsReport(input, { signer, image = IMAGE }) {
  const claims = Buffer.from(JSON.stringify({ "user-data": input.toString("hex") })), env = Buffer.alloc(1236 + claims.length);
  const w32 = (o, n) => env.writeUInt32LE(n, o);
  w32(0, 0x414c4348); w32(4, 2); w32(8, env.length); w32(12, 2); w32(1216, 20 + claims.length); w32(1220, 1); w32(1224, 1); w32(1228, 1); w32(1232, claims.length); claims.copy(env, 1236);
  const r = env.subarray(32, 592); [560, 1, 1, 256, 0, 2].forEach((n, i) => r.writeUInt32LE(n, i * 4)); sha(claims).copy(r, 24); Buffer.from(image, "hex").copy(r, 120);
  r.writeUInt32LE(5, 216); r.writeUInt32LE(0, 220); r.writeUInt32LE(2, 224); r.writeUInt32LE(0, 228);
  sign("sha256", r.subarray(0, 304), { key: signer, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).copy(r, 304);
  return env;
}
// the witness guest's answer to a verifier's nonce: a report under `signer` (the boot's IDKS) binding its TLS key, the nonce and the app
function witness(w, { app = APP, signer = w.idks.privateKey, image = IMAGE } = {}) {
  return async (nonceHex) => {
    const handshakeSpki = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ type: "spki", format: "der" });
    const nonce = Buffer.from(nonceHex, "hex");
    const input = Buffer.concat([bind2(handshakeSpki, nonce, RID), Buffer.from(app, "hex")]);
    return { doc: { abi: ABI2, nonce: nonceHex, transportKey: b64(handshakeSpki), appSha256: app, runtime: RUNTIME,
                    report: b64(Buffer.from(JSON.stringify({ vbsVmReport: b64(vbsReport(input, { signer, image })) }))) },
             handshakeSpki: b64(handshakeSpki) };
  };
}

// ---- verifiers, each an HTTP service with its own key and the operator-independent chain identity ------------------------
const servers = [];
after(() => { for (const s of servers) { s.closeAllConnections?.(); s.close(); } });
async function verifierService(w, { registry = { endpoint: ENDPOINT, operator: operator.address }, now = Date.now, pol = policy(w) } = {}) {
  const { privateKey } = generateKeyPairSync("ed25519");
  const v = createIndependentShieldVerifier({ policy: pol, signingKey: privateKey, now,
    registryEntry: async (id) => (id === HOST_ID ? registry : null),
    recoverSigner: (message, signature) => recoverMessageAddress({ message, signature }) });
  const server = http.createServer((req, res) => v.handle(req, res));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  return { v, privateKey, entry: { key: v.key, url: `http://127.0.0.1:${server.address().port}` } };
}
const nodeKey = () => { const { privateKey, publicKey } = generateKeyPairSync("ed25519"); return { privateKey, spki: publicKey.export({ type: "spki", format: "der" }) }; };
function client(w, set, { nk = nodeKey(), tpmOpts = {}, readiness = witness(w), signer = operator, opened = [], hostId = HOST_ID, endpoint = ENDPOINT, logs = [] } = {}) {
  const t = fakeTpm(w, tpmOpts);
  const c = createVerifierMarketClient({ set, hostId, endpoint, nodeKey: nk, tpm: t.tpm, keysFrame: t.keysFrame,
    managerHealth: async () => ({ backend: "hyperv-partition-per-app", boundary: { tier: "t0-hv", hostExcluded: false } }),
    readiness, sign: (message) => signer.signMessage({ message }), open: (until, keyIds) => opened.push({ until, keyIds }), log: (m) => logs.push(m) });
  return { c, opened, nk, logs, t };
}

test("a pinned verifier runs the relay's own attach and readiness checks and opens a bounded window for this round only", options, async () => {
  const a = await verifierService(world);
  const set = validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 1, verifiers: [a.entry] });
  const { c, opened, t } = client(world, set);
  const r = await c.round();
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(opened.length, 1);
  assert.ok(opened[0].until > Date.now() && opened[0].until <= Date.now() + MAX_VERDICT_TTL_MS);
  assert.deepEqual(opened[0].keyIds, [keyIdOf(a.entry.key)]);
  assert.deepEqual(t.cmds.filter((x) => x !== "keys"), ["log", "activate", "quote", "pcr"], "the node's real frame builder ran the TPM round");
  // the real Host takes the window exactly as the relay's, and only as the relay's would be taken
  process.env.BASE_RPCS ||= "http://127.0.0.1:9";
  const { Host } = await import("../windows/node/host.mjs");
  const h = new Host({ dir: fs.mkdtempSync(path.join(os.tmpdir(), "ee-vm-")), endpoint: ENDPOINT, name: "box", appsEnabled: true, cpuPricePerSec6: 12,
                       log: () => {}, engineRetired: true, claimScope: "market", isolationManager: "http://127.0.0.1:1" });
  assert.equal(h.meetsIsolationContract(), false);
  assert.equal(h.scope(), "owner-only");
  h.openVerifierMarket(opened[0].until, opened[0].keyIds);
  assert.equal(h.meetsIsolationContract(), true);
  assert.equal(h.scope(), "market");
  assert.equal(h.availability().attach.verifiers.tier, "hv-node");
  assert.equal(h.availability().attach.verifiers.hostExcluded, false);
  assert.equal(h.availability().apps.hostExcluded, false, "never a host-exclusion or TEE label");
  h.openVerifierMarket(Date.now() + 3_600_000, []);
  assert.ok(h.verifierMarket.until <= Date.now() + 300_000, "a window is never longer than five minutes, whatever is passed");
  h.verifierMarket = { tier: "hv-node", until: Date.now() - 1, seenUntil: Date.now() - 1 };
  assert.equal(h.meetsIsolationContract(), false, "an expired window closes the market");
  assert.equal(h.servingScope(), "market", "...and the serving grace applies as for a relay window");
  const legacy = new Host({ dir: fs.mkdtempSync(path.join(os.tmpdir(), "ee-vm-")), endpoint: ENDPOINT, name: "box", appsEnabled: true, cpuPricePerSec6: 12,
                            log: () => {}, engineRetired: false, claimScope: "market", isolationManager: "http://127.0.0.1:1" });
  legacy.openVerifierMarket(Date.now() + 60_000, ["x"]);
  assert.equal(legacy.meetsIsolationContract(), false, "a node that still runs the legacy engine is never admitted this way");
});

test("threshold: distinct pinned verifiers must each agree; one down or refusing keeps the market closed", options, async () => {
  const a = await verifierService(world), b = await verifierService(world);
  const down = { key: keySpecOf(generateKeyPairSync("ed25519").privateKey), url: "http://127.0.0.1:9" };
  let set = validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 2, verifiers: [a.entry, b.entry] });
  let x = client(world, set);
  assert.equal((await x.c.round()).ok, true);
  assert.deepEqual(new Set(x.opened[0].keyIds), new Set([keyIdOf(a.entry.key), keyIdOf(b.entry.key)]));
  set = validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 2, verifiers: [a.entry, down] });
  x = client(world, set);
  const r = await x.c.round();
  assert.equal(r.ok, false); assert.equal(x.opened.length, 0);
  assert.match(r.reasons.at(-1), /1 of the required 2/);
  assert.throws(() => validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 2, verifiers: [a.entry, a.entry] }), /listed twice/);
  assert.throws(() => validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 0, verifiers: [a.entry] }), /threshold/);
  assert.throws(() => validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 1, verifiers: [{ key: a.entry.key, url: "http://verifier.example" }] }), /https/);
});

test("verifier-side refusals: wrong operator, another endpoint, a reused session, a bad boot, another boot's witness, another app", options, async () => {
  const a = await verifierService(world);
  const set = validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 1, verifiers: [a.entry] });
  const expectRefused = async (opts, re) => { const x = client(world, set, opts); const r = await x.c.round(); assert.equal(r.ok, false); assert.match(r.failures.join(" | "), re); assert.equal(x.opened.length, 0); };
  await expectRefused({ signer: stranger }, /registered operator did not sign/);
  await expectRefused({ endpoint: "https://not-the-box.example" }, /hostId is not keccak256\(endpoint\)/);
  await expectRefused({ hostId: keccak256(toBytes("https://not-the-box.example")) }, /hostId is not keccak256\(endpoint\)/);
  await expectRefused({ readiness: witness(world, { signer: other.idks.privateKey }) }, /readiness witness refused/);
  await expectRefused({ readiness: witness(world, { app: "ee".repeat(32) }) }, /readiness witness refused/);
  await expectRefused({ readiness: witness(world, { image: "ef".repeat(32) }) }, /readiness witness refused/);
  await expectRefused({ tpmOpts: { idksOf: other } }, /readiness witness refused/);           // the log names another boot's IDKS
  // a boot the node itself would never attest (Secure Boot off) is refused before it is sent
  const x = client(world, set, { tpmOpts: { log: { secureBoot: 0 } } });
  assert.match((await x.c.round()).failures.join(" "), /refusing to attest this node: Secure Boot is not on/);
  // the registry names another endpoint for this id
  const moved = await verifierService(world, { registry: { endpoint: "https://elsewhere.example", operator: operator.address } });
  const y = client(world, validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 1, verifiers: [moved.entry] }));
  assert.match((await y.c.round()).failures.join(" "), /registry does not name this endpoint/);
  // a session is single use, and the verifier's TPM roots decide: another CA's EK is refused
  const ch = await a.v.challenge({ hostId: HOST_ID, endpoint: ENDPOINT, hostChallenge: "11".repeat(32), keys: await fakeTpm(world).keysFrame() });
  await assert.rejects(a.v.attest({ session: ch.session, rad: { format: "windows-hv-node/v1", body: "e30=", transportKey: b64(nodeKey().spki) } }), /hv-node evidence refused/);
  await assert.rejects(a.v.attest({ session: ch.session }), /no live verifier session/);
  const otherCa = await verifierService(other);
  const z = client(world, validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 1, verifiers: [otherCa.entry] }));
  assert.match((await z.c.round()).failures.join(" "), /does not chain to a pinned TPM root/);          // refused at the challenge
  assert.throws(() => createIndependentShieldVerifier({ policy: { ...policy(world), marketEnabled: false }, signingKey: a.privateKey, registryEntry: async () => null, recoverSigner: async () => null }), /market-enabled/);
  assert.throws(() => createIndependentShieldVerifier({ policy: { ...policy(world), witness: undefined }, signingKey: a.privateKey, registryEntry: async () => null, recoverSigner: async () => null }), /readiness witness/);
});

test("host-side verdict rules: forged, unpinned, replayed, wrong node, wrong key, stale and over-long verdicts count for nothing", options, async () => {
  const a = await verifierService(world);
  const set = validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 1, verifiers: [a.entry] });
  const nk = nodeKey(), hostChallenge = "22".repeat(32), now = Date.now();
  const base = { hostId: HOST_ID, endpoint: ENDPOINT, transportKeySha256: hex(sha(nk.spki)), ekCertSha256: "33".repeat(32), hostChallenge, nonce: "44".repeat(32),
                 tier: "hv-node", technology: "windows-tpm-host", hostExcluded: false, market: "shield-capacity", omissions: [],
                 readiness: { appSha256: APP, runtimeId: hex(RID), measurement: IMAGE }, boot: {}, policySha256: "55".repeat(32), issuedAt: now, expiresAt: now + 60_000 };
  const check = (env, o = {}) => verifyVerdicts([env], { set, hostId: HOST_ID, endpoint: ENDPOINT, transportKeySpki: nk.spki, hostChallenge, now, ...o });
  assert.equal(check(signVerdict(base, a.privateKey)).ok, true);
  const rogue = generateKeyPairSync("ed25519").privateKey;
  assert.match(check(signVerdict(base, rogue)).reasons[0], /not in this host's verifier set/);
  const env = signVerdict(base, a.privateKey);
  const tampered = { ...env, statement: Buffer.from(canonicalJson({ ...JSON.parse(Buffer.from(env.statement, "base64")), expiresAt: now + 299_000 })).toString("base64") };
  assert.match(check(tampered).reasons[0], /signature does not verify/);
  assert.match(check({ ...env, key: keySpecOf(rogue) }).reasons[0], /not in this host's verifier set|signature/);
  assert.match(check(env, { hostChallenge: "66".repeat(32) }).reasons[0], /another round \(replayed or stale\)/);
  assert.match(check(signVerdict({ ...base, hostId: keccak256(toBytes("https://other.example")) }, a.privateKey)).reasons[0], /another host/);
  assert.match(check(signVerdict({ ...base, transportKeySha256: "77".repeat(32) }, a.privateKey)).reasons[0], /another transport key/);
  assert.match(check(signVerdict({ ...base, expiresAt: now - 1 }, a.privateKey)).reasons[0], /expired/);
  assert.match(check(signVerdict({ ...base, expiresAt: now + MAX_VERDICT_TTL_MS + 1 }, a.privateKey)).reasons[0], /outside its window/);
  assert.match(check(signVerdict({ ...base, issuedAt: now + 120_000, expiresAt: now + 130_000 }, a.privateKey)).reasons[0], /outside its window/);
  for (const bend of [{ hostExcluded: true }, { tier: "snp" }, { technology: "sev-snp" }, { market: "app" }])
    assert.match(check(signVerdict({ ...base, ...bend }, a.privateKey)).reasons[0], /does not state this tier's market admission/, JSON.stringify(bend));
  assert.match(check(signVerdict({ ...base, readiness: null }, a.privateKey)).reasons[0], /no verified readiness witness/);
  // two verdicts from ONE key are one verifier, not two
  const two = validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 2, verifiers: [a.entry, (await verifierService(world)).entry] });
  assert.equal(verifyVerdicts([env, signVerdict(base, a.privateKey)], { set: two, hostId: HOST_ID, endpoint: ENDPOINT, transportKeySpki: nk.spki, hostChallenge, now }).ok, false);
  // a real verdict from an earlier round, replayed into a later one, is refused
  const x = client(world, set, { nk });
  const captured = [];
  const realFetch = globalThis.fetch;
  const tap = async (url, opts) => { const r = await realFetch(url, opts); if (String(url).endsWith("/attest")) { const j = await r.clone().json(); captured.push(j.verdict); } return r; };
  const c2 = createVerifierMarketClient({ set, hostId: HOST_ID, endpoint: ENDPOINT, nodeKey: nk, tpm: x.t.tpm, keysFrame: x.t.keysFrame, readiness: witness(world),
    sign: (m) => operator.signMessage({ message: m }), open: () => {}, fetchImpl: tap });
  assert.equal((await c2.round()).ok, true);
  assert.equal(captured.length, 1);
  assert.match(verifyVerdicts(captured, { set, hostId: HOST_ID, endpoint: ENDPOINT, transportKeySpki: nk.spki, hostChallenge: "88".repeat(32) }).reasons[0], /another round/);
  // the operator's attach message is bound to every field
  assert.throws(() => attachMessage({ verifier: "x", hostId: HOST_ID, endpoint: ENDPOINT, nonce: "1".repeat(64), transportKeySha256: "1".repeat(64), ekCertSha256: "1".repeat(64), hostChallenge: "1".repeat(64) }), /verifier/);
});

test("no self-assertion opens the market: relay tier alone, a manager's statement, or a stale relay window", options, async () => {
  process.env.BASE_RPCS ||= "http://127.0.0.1:9";
  const { Host } = await import("../windows/node/host.mjs");
  const h = new Host({ dir: fs.mkdtempSync(path.join(os.tmpdir(), "ee-vm-")), endpoint: ENDPOINT, name: "box", appsEnabled: true, cpuPricePerSec6: 12,
                       log: () => {}, engineRetired: true, claimScope: "market", isolationManager: "http://127.0.0.1:1" });
  h.relayTier = "hv-node";
  assert.equal(h.meetsIsolationContract(), false, "a tier without a live window");
  h.verifierMarket = { tier: "T0-hv", until: Date.now() + 60_000 };
  assert.equal(h.meetsIsolationContract(), false, "only the verifiers' hv-node verdict, set through openVerifierMarket");
  h.shieldMarketUntil = Date.now() + 60_000;
  assert.equal(h.meetsIsolationContract(), true, "the relay path is unchanged");
});

test("over HTTP: malicious EKs at a market verifier's challenge take no pending capacity; the genuine host's round still opens the market", options, async () => {
  const { maliciousEks } = await import("./helpers/malicious-ek.mjs");
  const { privateKey } = generateKeyPairSync("ed25519");
  const v = createIndependentShieldVerifier({ policy: policy(world), signingKey: privateKey, maxSessions: 2,
    registryEntry: async (id) => (id === HOST_ID ? { endpoint: ENDPOINT, operator: operator.address } : null),
    recoverSigner: (message, signature) => recoverMessageAddress({ message, signature }) });
  const server = http.createServer((req, res) => v.handle(req, res));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  const url = `http://127.0.0.1:${server.address().port}`;
  const bad = Object.values(maliciousEks(world, other));
  for (let i = 0; i < 20; i++) {
    const r = await fetch(`${url}/v1/shield-verifier/challenge`, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ hostId: HOST_ID, endpoint: ENDPOINT, hostChallenge: randomBytes(32).toString("hex"), keys: bad[i % bad.length].keys }) });
    assert.equal(r.status, 403, await r.text());
  }
  const { c, opened } = client(world, validateVerifierSet({ format: "enclave-shield-verifier-set/v1", threshold: 1, verifiers: [{ key: v.key, url }] }));
  const r = await c.round();
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(opened.length, 1);
});
