// Owner-name certificates on Enclave Shield, the responder's half (relay/dns-challenge-shield.mjs): an owner-selected
// DNS-01 responder accepts a Shield guest's in-guest ACME push only under a Shield policy its operator pinned, with a host
// TPM session it challenged itself, for a guest VBS report binding the pushing key, this push and the stated app and
// runtime. A synthetic TPM world drives the node's REAL frame builder (hvnode-evidence.mjs) and the relay's REAL checks.
// Then every refusal the brief requires: forged or changed binding, wrong owner, wrong runtime or image, no explicit
// Shield policy, app A's evidence for app B, sessions replayed or moved between responders - and the SNP path unchanged.
// Needs openssl (synthetic EK chain).   run: node --test test/shield-dns-challenge.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes, createHash, sign, constants, generateKeyPairSync } from "node:crypto";
import { keccak256, toBytes, recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { haveOpenssl, tmpdir, makeVbsWorld, buildLog, buildQuote } from "./fixtures/vbs-synthetic.mjs";
import { activateCredential } from "../relay/vbs-credential.mjs";
import { ABI2, bind2, runtimeId } from "../isolation/contract/runtime.mjs";
import { buildHvNodeFrame } from "../windows/node/hvnode-evidence.mjs";
import { attachMessage } from "../windows/node/shield-verdict.mjs";
import { createShieldChallengeAuth, isShieldPush, shieldResponderId, SHIELD_DOC_FORMAT, validateShieldResponderPolicy,
         SHIELD_CHALLENGE_MAX_BYTES, SHIELD_ATTEST_MAX_BYTES, HVNODE_RAD_BODY_MAX_CHARS, MAX_LIVE_PER_EK,
         REGISTRY_GET_LAYOUTS, shieldRegistryBinding, shieldRegistryEntry } from "../relay/dns-challenge-shield.mjs";
import { authorizePush, pushNonce, challengeLabel, PUSH_SIG_PREFIX } from "../relay/dns-challenge-attested.mjs";

const options = { skip: !haveOpenssl && "openssl absent" };
// the reviewed live Base authority profile and its documented digest (docs/network/authority-profile.md)
const PROFILE_FILE = new URL("../contracts/deployments/network-profile-base.json", import.meta.url).pathname;
const PROFILE_DIGEST = "sha256:ee957827032cf7208434e4c73f9e859a27e4fc5c6cab5f4a2153308c09eb4cb8";
const REAL_REGISTRY = "0x868eb7fc5b5a84b2ff082eafc9bf40b7aac5ccac", REAL_CODE_HASH = "0x39911d6f53959c610b9108bb906fc36ea8f57016c4b2571b5cd52c9c32a6f518";
const world = haveOpenssl ? makeVbsWorld(tmpdir("shield-dns-")) : null;
const other = haveOpenssl ? makeVbsWorld(tmpdir("shield-dns-other-")) : null;
const sha = (b) => createHash("sha256").update(b).digest(), hex = (b) => Buffer.from(b).toString("hex"), b64 = (b) => Buffer.from(b).toString("base64");
const IMAGE = "ab".repeat(32), APP = "cd".repeat(32), APP_B = "ce".repeat(32);
const RUNTIME = { name: "wasmtime", version: "48.0.1", execution: "jit", targetIsa: "x86_64", hostIsa: "x86_64", cpuFeatures: "host-detected", wx: "enforced", cache: "none" };
const RID = runtimeId(RUNTIME);
const ZONE = "acme.owner.example", ENDPOINT = "https://box.example.org", HOST_ID = keccak256(toBytes(ENDPOINT));
const DEP = "0x" + "e7".repeat(32), OWNER = "0x" + "33".repeat(20), OTHER_OWNER = "0x" + "44".repeat(20);
const operator = privateKeyToAccount("0x" + "42".repeat(32)), stranger = privateKeyToAccount("0x" + "43".repeat(32));
const policy = (w) => ({ schema: "enclave-shield-app-policy/1", ekRoots: w.ca.bundlePem, platforms: "attested", images: [{ measurement: IMAGE, runtimeId: hex(RID) }] });
const responder = (w = world, zone = ZONE, pol = policy(w), extra = {}) => createShieldChallengeAuth({ policy: pol, zone,
  registryEntry: async (id) => (id === HOST_ID ? { endpoint: ENDPOINT, operator: operator.address, active: true } : null),
  recoverSigner: (message, signature) => recoverMessageAddress({ message, signature }), ...extra });

// the node: a fake TPM over the synthetic world (the node's real buildHvNodeFrame drives it)
function fakeTpm(w, { idksOf = w } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shield-dns-tpm-"));
  const L = buildLog({ idksPub: idksOf.idks.publicKey });
  fs.writeFileSync(path.join(dir, "boot.log"), L.log);
  return async (cmd) => {
    const [op, a, b] = cmd.split(" ");
    if (op === "log") return { log: path.join(dir, "boot.log") };
    if (op === "activate") return { credential: hex(activateCredential(w.ek.privateKey, w.aik.name, Buffer.from(a, "hex"), Buffer.from(b, "hex"))) };
    if (op === "quote") { const Q = buildQuote({ aikPriv: w.aik.privateKey, aikName: w.aik.name, pcrs: L.pcrs, pcr0: w.pcr0, extraData: Buffer.from(a, "hex") });
                          return { attest: hex(Q.attest), sig: hex(Q.sig), "aik-pub": hex(w.aik.tpmtPublic) }; }
    if (op === "pcr") return { pcr: "sha256 " + hex(w.pcr0) };
    if (op === "keys") return { "ek-cert": hex(w.ek.cert), "aik-pub": hex(w.aik.tpmtPublic), "aik-name": hex(w.aik.name) };
    throw new Error("tpm: " + cmd);
  };
}
const keysOf = (w) => ({ ek: b64(w.ek.cert), ekChain: [], aikPub: b64(w.aik.tpmtPublic), aikName: b64(w.aik.name) });
async function hostSession(auth, w = world, { signer = operator, idksOf = w, endpoint = ENDPOINT } = {}) {
  const HOST_ID = keccak256(toBytes(endpoint)), ENDPOINT = endpoint;
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }), hostChallenge = randomBytes(32).toString("hex");
  const ch = await auth.challenge({ hostId: HOST_ID, endpoint: ENDPOINT, hostChallenge, keys: keysOf(w) });
  const nonce = Buffer.from(ch.nonce, "base64");
  const frame = await buildHvNodeFrame({ nonce, credentialBlob: Buffer.from(ch.credentialBlob, "base64"), secret: Buffer.from(ch.secret, "base64"),
    spki, privateKey, tpm: fakeTpm(w, { idksOf }) });
  const operatorSig = await signer.signMessage({ message: attachMessage({ verifier: ch.party, hostId: HOST_ID, endpoint: ENDPOINT, nonce: hex(nonce),
    transportKeySha256: hex(sha(spki)), ekCertSha256: hex(sha(w.ek.cert)), hostChallenge }) });
  return { ch, rad: frame.rad, operatorSig, attest: () => auth.attest({ session: ch.session, rad: frame.rad, operatorSig }) };
}

// the guest: its P-256 TLS key, its push, and the m3 monitor's document (launcher envelope + the guest's VBS report)
function vbsReport(input, { signer, image = IMAGE }) {
  const claims = Buffer.from(JSON.stringify({ "user-data": input.toString("hex") })), env = Buffer.alloc(1236 + claims.length);
  const w32 = (o, n) => env.writeUInt32LE(n, o);
  w32(0, 0x414c4348); w32(4, 2); w32(8, env.length); w32(12, 2); w32(1216, 20 + claims.length); w32(1220, 1); w32(1224, 1); w32(1228, 1); w32(1232, claims.length); claims.copy(env, 1236);
  const r = env.subarray(32, 592); [560, 1, 1, 256, 0, 2].forEach((n, i) => r.writeUInt32LE(n, i * 4)); sha(claims).copy(r, 24); Buffer.from(image, "hex").copy(r, 120);
  r.writeUInt32LE(5, 216); r.writeUInt32LE(0, 220); r.writeUInt32LE(2, 224); r.writeUInt32LE(0, 228);
  sign("sha256", r.subarray(0, 304), { key: signer, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).copy(r, 304);
  return env;
}
const guestKey = () => { const k = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); return { ...k, spki: k.publicKey.export({ type: "spki", format: "der" }) }; };
function push({ key = guestKey(), owner = OWNER, deploymentId = DEP, op = "set", app = APP, runtime = RUNTIME, docApp = app, bindNonce, bindKey, image = IMAGE,
                signer = world.idks.privateKey, format = SHIELD_DOC_FORMAT, tier = "T0-hv", method = "POST", nonceOwner = owner, docRuntime = runtime } = {}) {
  const p = { v: 1, op, name: `_acme-challenge.${challengeLabel(deploymentId, owner)}.${ZONE}`, value: "A".repeat(43), deploymentId, owner,
              ts: Math.floor(Date.now() / 1000), spki: b64(key.spki) };
  const nonce = pushNonce({ ...p, owner: nonceOwner });
  const rid = runtimeId(runtime);
  const input = Buffer.concat([bind2(bindKey || key.spki, bindNonce || nonce, rid), Buffer.from(app, "hex")]);
  const launcher = { format: "hyperv-partition-domain/v1", signed: "launcher" };
  p.attestation = { abi: ABI2, format, tier, nonce: hex(nonce), transportKey: p.spki, appSha256: docApp, runtime: docRuntime,
                    report: b64(Buffer.from(JSON.stringify({ ...launcher, vbsVmReport: b64(vbsReport(input, { signer, image })) }))) };
  const raw = Buffer.from(JSON.stringify(p));
  const sig = sign("sha256", Buffer.concat([Buffer.from(PUSH_SIG_PREFIX), raw]), { key: key.privateKey, dsaEncoding: "der" }).toString("base64");
  return { raw, sig, method, p, key };
}

test("a Shield guest's push is accepted only under the operator's Shield policy and a host session this responder challenged", options, async () => {
  const auth = responder();
  const x = push();
  assert.equal(isShieldPush(x.raw), true);
  assert.match((await auth.authorize(x)).why, /no live Shield host session/, "no session yet: refused");
  const s = await hostSession(auth);
  const a = await s.attest();
  assert.equal(a.tier, "hv-node"); assert.equal(a.hostExcluded, false);
  const v = await auth.authorize(push());
  assert.equal(v.ok, true, v.why);
  assert.equal(v.verdict, "shield-attested"); assert.equal(v.tier, "hv-node"); assert.equal(v.hostExcluded, false);
  assert.equal(v.deploymentId, DEP); assert.equal(v.measurement, IMAGE);
  // delete takes the same proof
  assert.equal((await auth.authorize(push({ op: "delete", method: "DELETE" }))).ok, true);
  await assert.rejects(s.attest(), /no live verifier session/, "a host session is single use");
});

test("forged or changed bindings, wrong owner, runtime or image, and another boot's report are refused", options, async () => {
  const auth = responder();
  await (await hostSession(auth)).attest();
  const refused = async (x, re) => { const v = await auth.authorize(x); assert.equal(v.ok, false, `accepted: ${re}`); assert.match(v.why, re); };
  await refused(push({ bindNonce: randomBytes(32) }), /Shield attestation refused: guest binding differs/);
  await refused(push({ bindKey: guestKey().spki }), /Shield attestation refused: guest binding differs/);
  await refused(push({ signer: other.idks.privateKey }), /Shield attestation refused/);                 // a report no session's IDKS signed
  await refused(push({ image: "ef".repeat(32) }), /Shield attestation refused/);
  await refused(push({ runtime: { ...RUNTIME, version: "49.0.0" } }), /Shield attestation refused: runtime has no admitted image/);
  await refused(push({ docRuntime: { ...RUNTIME, wx: "off" } }), /no admissible runtime/);
  // wrong owner: the alias commits to the owner, and so does the push nonce the report binds
  await refused(push({ nonceOwner: OTHER_OWNER }), /the attestation does not bind this push/);
  const wrongAlias = push(); wrongAlias.p.owner = OTHER_OWNER;
  const raw2 = Buffer.from(JSON.stringify(wrongAlias.p));
  await refused({ raw: raw2, method: "POST", sig: sign("sha256", Buffer.concat([Buffer.from(PUSH_SIG_PREFIX), raw2]), { key: wrongAlias.key.privateKey, dsaEncoding: "der" }).toString("base64") },
    /not this deployment and owner's alias/);
  // a tampered body breaks the guest key's signature
  const t = push(); const tampered = Buffer.from(t.raw.toString().replace(`"value":"${"A".repeat(43)}"`, `"value":"${"B".repeat(43)}"`));
  await refused({ ...t, raw: tampered }, /not signed by the named key/);
  // the document must be the Hyper-V tier's: an SNP-shaped or relabelled document is not judged as Shield
  await refused(push({ tier: "T1" }), /not an Enclave Shield \(T0-hv\) document/);
});

test("two apps never interchange: one app's evidence cannot certify, or be carried by, another", options, async () => {
  const auth = responder();
  await (await hostSession(auth)).attest();
  const v = await auth.authorize(push({ app: APP_B, docApp: APP_B, runtime: RUNTIME }));
  assert.equal(v.ok, true, "app B on its own evidence is fine (the policy pins the image, not the app)");
  const crossed = await auth.authorize(push({ app: APP, docApp: APP_B }));                         // A's report, a document naming B
  assert.equal(crossed.ok, false); assert.match(crossed.why, /guest binding differs|document differs/);
  // B's key carrying A's document (another key in the push than the one the document attests)
  const a = push(), b = guestKey();
  const p = { ...a.p, spki: b64(b.spki) };
  const raw = Buffer.from(JSON.stringify(p));
  const carried = await auth.authorize({ raw, method: "POST", sig: sign("sha256", Buffer.concat([Buffer.from(PUSH_SIG_PREFIX), raw]), { key: b.privateKey, dsaEncoding: "der" }).toString("base64") });
  assert.equal(carried.ok, false); assert.match(carried.why, /no hardware attestation for the named key|does not bind this push/);
  // another deployment's alias with this guest's evidence: the push nonce (which the report binds) names the deployment
  const moved = push(); const mp = { ...moved.p, deploymentId: "0x" + "e8".repeat(32), name: `_acme-challenge.${challengeLabel("0x" + "e8".repeat(32), OWNER)}.${ZONE}` };
  const mraw = Buffer.from(JSON.stringify(mp));
  const m = await auth.authorize({ raw: mraw, method: "POST", sig: sign("sha256", Buffer.concat([Buffer.from(PUSH_SIG_PREFIX), mraw]), { key: moved.key.privateKey, dsaEncoding: "der" }).toString("base64") });
  assert.equal(m.ok, false); assert.match(m.why, /does not bind this push/);
});

test("host sessions: only the registered operator's, only this responder's, only a TPM chaining to the pinned roots", options, async () => {
  const auth = responder();
  await assert.rejects((await hostSession(auth, world, { signer: stranger })).attest(), /registered operator did not sign/);
  // a session signed for ANOTHER responder's zone cannot be presented here: the attach message names the responder
  const elsewhere = responder(world, "acme.elsewhere.example");
  const s = await hostSession(elsewhere);
  await assert.rejects(auth.attest({ session: s.ch.session, rad: s.rad, operatorSig: s.operatorSig }), /no live verifier session/);
  assert.notEqual(shieldResponderId(ZONE), shieldResponderId("acme.elsewhere.example"));
  // the TPM's EK chains only to the policy's pinned roots: another CA's EK is refused at the challenge, before any
  // pending slot or credential exists
  const otherRoots = responder(other);
  await assert.rejects(hostSession(otherRoots, world), (e) => e.status === 403 && /does not chain to a pinned TPM root/.test(e.message));
  // a boot whose log names another IDKS: the session verifies, but a report signed by this world's IDKS does not
  const idksSwap = responder();
  await (await hostSession(idksSwap, world, { idksOf: other })).attest();
  assert.equal((await idksSwap.authorize(push())).ok, false);
});

test("no weaker tier without explicit opt-in: invalid Shield policies refuse to start, and the SNP path refuses Shield evidence", options, async () => {
  for (const bad of [{}, { ...policy(world), schema: "x" }, { ...policy(world), ekRoots: "" }, { ...policy(world), platforms: "any" }, { ...policy(world), images: [] },
                     { ...policy(world), images: [{ measurement: IMAGE }] }])
    assert.throws(() => validateShieldResponderPolicy(bad));
  assert.throws(() => responder(world, ZONE, { ...policy(world), platforms: undefined }));
  // the SEV-SNP responder judges this push with its own rules: its measurement pins never match a Shield document
  const x = push();
  const snp = await authorizePush({ raw: x.raw, sig: x.sig, method: "POST", zone: ZONE, measurements: new Set(["11".repeat(48)]),
    judge: async () => { throw new Error("the SNP judge must not even be reached for a Shield document"); } });
  assert.equal(snp.ok, false); assert.match(snp.why, /launch measurement is not pinned/);
  // and the Shield adapter refuses an SNP-format document
  const auth = responder();
  await (await hostSession(auth)).attest();
  const s = await auth.authorize(push({ format: "sev-snp-guest-domain-v1" }));
  assert.equal(s.ok, false); assert.match(s.why, /not an Enclave Shield/);
  assert.equal(isShieldPush(push({ format: "sev-snp-guest-domain-v1" }).raw), false, "dispatch sends an SNP document to the SNP path only");
});

test("end to end over HTTP: the node's session client (shield-sessions.mjs) attests its TPM boot at the committed responder, then the guest's push passes", options, async () => {
  const http = await import("node:http");
  const { createResponderSessions, responderTargets } = await import("../windows/node/shield-sessions.mjs");
  const auth = responder();
  const json = (res) => (status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
  const server = http.createServer((req, res) => { auth.handle(req, res, json(res)).then((h) => { if (!h) json(res)(404, { error: "not_found" }); }); });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const node = (zone) => createResponderSessions({ hostId: HOST_ID, endpoint: ENDPOINT, nodeKey: { privateKey, spki: publicKey.export({ type: "spki", format: "der" }) },
      tpm: fakeTpm(world), keysFrame: async () => keysOf(world), sign: (message) => operator.signMessage({ message }) });
    // only running owner-committed records on a Shield-direct image name a responder; each once
    const R = "https://challenge.owner.example";
    const recs = [{ status: "running", startup: { direct: true, acme: { challenge: R + "/", zone: ZONE } } },
                  { status: "running", startup: { direct: true, acme: { challenge: R, zone: ZONE } } },
                  { status: "running", startup: { direct: true, acme: { challenge: url, zone: ZONE } } },
                  { status: "running", startup: { direct: false, acme: { challenge: "https://legacy.example", zone: ZONE } } },
                  { status: "stopped", startup: { direct: true, acme: { challenge: "https://gone.example", zone: ZONE } } },
                  { status: "running", startup: null }];
    assert.deepEqual(responderTargets(recs).map((t) => t.url), [R], "https only, as packages commit it; each responder once");
    // a responder answering for another zone than the package committed is refused before any TPM use
    const wrong = await node("acme.other.example").refresh([{ url, zone: "acme.other.example" }]);
    assert.match(wrong.failed[0], /another zone than the committed/);
    assert.match((await auth.authorize(push())).why, /no live Shield host session/);
    const ok = await node(ZONE).refresh([{ url, zone: ZONE }]);
    assert.deepEqual(ok.done, [url], ok.failed.join("; "));
    assert.equal((await auth.authorize(push())).ok, true);
  } finally { server.close(); }
});

test("the responder process: ATTESTED_SHIELD_POLICY is a separate opt-in with its own pins; without it, or without its chain pins, Shield is not served", options, async (t) => {
  const { spawn } = await import("node:child_process");
  const { once } = await import("node:events");
  const net = await import("node:net");
  const port = () => new Promise((r) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shield-dns-proc-"));
  fs.writeFileSync(path.join(dir, "policy.json"), JSON.stringify(policy(world)));
  fs.writeFileSync(path.join(dir, "pins.json"), JSON.stringify({ version: 1, chainId: 8453, contracts: { registry: REAL_REGISTRY,
    deployments: "0x" + "22".repeat(20), appCatalog: "0x" + "33".repeat(20), proofOfTime: "0x" + "44".repeat(20),
    ...Object.fromEntries(["enclavePay", "verificationFees", "sessionVaultFactory", "secretVaultV2"].map((k) => [k, "0x" + "00".repeat(20)])) } }));
  const blank = Object.fromEntries(["DNS_READ_ONLY", "IP_ZONE", "APP_ZONE", "TCP_ZONE", "BOX_ZONE", "APP_STATIC", "ROUTE_MAP_URL", "DNS_TXT_KEY", "SECRET",
    "REGISTRY_ADDRESS", "ENCLAVES", "ENCLAVE_URL", "ELIGIBILITY_API", "DOMAINS_API", "ADDRESS_BOOK_ADDRESS", "ATTESTED_MEASUREMENTS"].map((k) => [k, ""]));
  const base = { ...process.env, ...blank, DNS_CHALLENGE_AUTH: "attested", CHALLENGE_ZONE: ZONE, NS_NAME: "ns1.owner.example", DNS_BIND: "127.0.0.1", DNS_API_BIND: "127.0.0.1",
                 ATTESTED_SHIELD_POLICY: path.join(dir, "policy.json"), ATTESTED_SHIELD_PINS: path.join(dir, "pins.json"),
                 ATTESTED_SHIELD_PROFILE: PROFILE_FILE, ATTESTED_SHIELD_PROFILE_DIGEST: PROFILE_DIGEST,
                 ATTESTED_SHIELD_RPCS: "https://rpc-a.example,https://rpc-b.example" };
  fs.writeFileSync(path.join(dir, "other-pins.json"), fs.readFileSync(path.join(dir, "pins.json"), "utf8").replace(REAL_REGISTRY, "0x" + "12".repeat(20)));
  for (const extra of [{ ATTESTED_SHIELD_PROFILE: "" }, { ATTESTED_SHIELD_PROFILE_DIGEST: "" }, { ATTESTED_SHIELD_PROFILE_DIGEST: "sha256:" + "00".repeat(32) },
                       { ATTESTED_SHIELD_PINS: path.join(dir, "other-pins.json") }, { ATTESTED_SHIELD_RPCS: "https://rpc-a.example" },
                       { ATTESTED_SHIELD_RPCS: "https://rpc-a.example,https://RPC-A.example." }, { ADDRESS_BOOK_ADDRESS: "0x" + "12".repeat(20) },
                       { ATTESTED_SHIELD_POLICY: "", ATTESTED_MEASUREMENTS: "" }]) {
    const child = spawn(process.execPath, ["relay/dns-relay.js"], { env: { ...base, DNS_PORT: "0", DNS_API_PORT: "0", ...extra }, stdio: "pipe" });
    let log = ""; child.stderr.on("data", (c) => { log += c; });
    const kill = setTimeout(() => child.kill("SIGKILL"), 8000);
    const [code] = await once(child, "close"); clearTimeout(kill);
    assert.equal(code, 1, `${JSON.stringify(extra)} started: ${log}`);
  }
  const apiPort = await port(), dnsPort = await port();
  const child = spawn(process.execPath, ["relay/dns-relay.js"], { env: { ...base, DNS_PORT: String(dnsPort), DNS_API_PORT: String(apiPort) }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; child.stdout.on("data", (c) => { log += c; }); child.stderr.on("data", (c) => { log += c; });
  t.after(() => child.kill("SIGTERM"));
  let health;
  for (let i = 0; i < 80 && !health; i++) { health = await fetch(`http://127.0.0.1:${apiPort}/health`).then((r) => r.json()).catch(() => null); if (!health) await new Promise((r) => setTimeout(r, 100)); }
  assert.ok(health, log);
  assert.equal(health.measurements, 0, "no SNP measurement is pinned: no SNP push can pass");
  assert.deepEqual(health.shield, { tier: "hv-node", hostExcluded: false, liveHostSessions: 0,
    registry: { address: REAL_REGISTRY, schema: "4", codeHash: REAL_CODE_HASH, profileDigest: PROFILE_DIGEST } });
  const bad = await fetch(`http://127.0.0.1:${apiPort}/v1/shield-session/challenge`, { method: "POST", body: "{}" });
  assert.equal(bad.status, 422);
  // every request is answered: an unknown session route is 404 at once (it used to hang), a GET is 405
  const unknown = await fetch(`http://127.0.0.1:${apiPort}/v1/shield-session/unknown`, { method: "POST", body: "{}", signal: AbortSignal.timeout(2000) });
  assert.equal(unknown.status, 404);
  const get = await fetch(`http://127.0.0.1:${apiPort}/v1/shield-session/attest`, { signal: AbortSignal.timeout(2000) });
  assert.equal(get.status, 405);
  // the request bounds hold through the real relay's dispatch (its own json responder): a genuine challenge passes, one
  // byte over the challenge bound is 413, and an attest declaring more than its bound is 413 before a byte is sent
  const genuine = await fetch(`http://127.0.0.1:${apiPort}/v1/shield-session/challenge`, { method: "POST",
    body: JSON.stringify({ hostId: HOST_ID, endpoint: ENDPOINT, hostChallenge: randomBytes(32).toString("hex"), keys: keysOf(world) }) });
  assert.equal(genuine.status, 200, await genuine.clone().text());
  assert.ok((await genuine.json()).credentialBlob);
  const over = await fetch(`http://127.0.0.1:${apiPort}/v1/shield-session/challenge`, { method: "POST", body: Buffer.alloc(SHIELD_CHALLENGE_MAX_BYTES + 1, 0x20) }).catch((e) => e);
  assert.equal(over.status, 413, String(over));
  const http = await import("node:http");
  const declared = await new Promise((resolve, reject) => {
    const q = http.request({ host: "127.0.0.1", port: apiPort, path: "/v1/shield-session/attest", method: "POST", headers: { "content-length": SHIELD_ATTEST_MAX_BYTES + 1 } },
      (res) => { res.resume(); res.on("end", () => { q.destroy(); resolve(res.statusCode); }); });
    q.on("error", (e) => (e.code === "ECONNRESET" ? null : reject(e)));
    q.flushHeaders();
    setTimeout(() => { q.destroy(); resolve("no answer before the body"); }, 5000).unref();   // a ceiling, only for a handler that waits
  });
  assert.equal(declared, 413);
  const x = push();
  const r = await fetch(`http://127.0.0.1:${apiPort}/v1/txt`, { method: "POST", body: x.raw, headers: { "content-type": "application/json", "x-attested-sig": x.sig } });
  assert.equal(r.status, 403); assert.match((await r.json()).message, /no live Shield host session/);
});

test("over HTTP: malicious EKs at the DNS responder's challenge take no pending capacity; the genuine host still attests and its guest's push is authorized", options, async () => {
  const http = await import("node:http");
  const { maliciousEks } = await import("./helpers/malicious-ek.mjs");
  const auth = responder();
  const server = http.createServer(async (req, res) => {
    const json = (code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    if (!(await auth.handle(req, res, json))) json(404, { error: "not found" });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const url = `http://127.0.0.1:${server.address().port}/v1/shield-session/challenge`;
    const bad = Object.values(maliciousEks(world, other));
    for (let i = 0; i < 70; i++) {          // more than the responder's 64 pending slots
      const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ hostId: HOST_ID, endpoint: ENDPOINT, hostChallenge: randomBytes(32).toString("hex"), keys: bad[i % bad.length].keys }) });
      assert.equal(r.status, 403, await r.text());
    }
    await (await hostSession(auth)).attest();
    const v = await auth.authorize(push());
    assert.equal(v.ok, true, v.why);
  } finally { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
});

// ---- the handler's request bounds and admission (relay/dns-challenge-shield.mjs handle) over real HTTP ------------------
// the same json(code, body) responder relay/dns-relay.js hands it
async function serveBounded(auth) {
  const http = await import("node:http");
  const server = http.createServer(async (req, res) => {
    const json = (code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    if (!(await auth.handle(req, res, json))) json(404, { error: "not found" });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  // one request, full control of framing; `hold` keeps it open after writing `first` (resolve with { req, done })
  const send = (route, { body, raw, headers = {}, chunked = false, hold = false, first } = {}) => {
    const data = raw ?? (body === undefined ? undefined : Buffer.from(JSON.stringify(body)));
    let req;
    const done = new Promise((resolve, reject) => {
      req = http.request({ host: "127.0.0.1", port, path: route, method: "POST", agent: false,
        headers: { "content-type": "application/json", ...(data && !chunked ? { "content-length": data.length } : {}), ...headers } }, (res) => {
        const c = []; res.on("data", (d) => c.push(d)); res.on("end", () => { let j = null; try { j = JSON.parse(Buffer.concat(c)); } catch {} resolve({ status: res.statusCode, body: j, headers: res.headers }); });
      });
      req.on("error", (e) => (["ECONNRESET", "EPIPE"].includes(e.code) ? resolve({ status: "reset" }) : reject(e)));
      if (hold) { req.write(first ?? "{"); return; }
      if (data) req.write(data);
      req.end();
    });
    return hold ? { req, done } : done;
  };
  const arrived = () => new Promise((ok) => server.once("request", ok));
  return { server, port, send, arrived, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }) };
}
const challengeBody = (keys = keysOf(world)) => ({ hostId: HOST_ID, endpoint: ENDPOINT, hostChallenge: randomBytes(32).toString("hex"), keys });
// the host's exchange over HTTP: its challenge, its TPM round (the node's real frame builder), its operator's signature
async function httpSession(s, w = world, { signer = operator } = {}) {
  const body = challengeBody(keysOf(w));
  const ch = await s.send("/v1/shield-session/challenge", { body });
  assert.equal(ch.status, 200, JSON.stringify(ch.body));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }), nonce = Buffer.from(ch.body.nonce, "base64");
  const frame = await buildHvNodeFrame({ nonce, credentialBlob: Buffer.from(ch.body.credentialBlob, "base64"), secret: Buffer.from(ch.body.secret, "base64"),
    spki, privateKey, tpm: fakeTpm(w) });
  const operatorSig = await signer.signMessage({ message: attachMessage({ verifier: ch.body.party, hostId: HOST_ID, endpoint: ENDPOINT, nonce: hex(nonce),
    transportKeySha256: hex(sha(spki)), ekCertSha256: hex(sha(w.ek.cert)), hostChallenge: body.hostChallenge }) });
  return { session: ch.body.session, rad: frame.rad, operatorSig };
}
const idle = (auth) => assert.deepEqual(auth.inflight(), { challenge: 0, attest: 0 });
const settle = () => new Promise((r) => setImmediate(r));
// a ceiling for a wait that only a broken handler would never answer
const within = (p, ms = 5000) => Promise.race([p, new Promise((r) => setTimeout(() => r({ status: "no answer" }), ms).unref())]);

test("bounds are the verifier's own maxima: a genuine exchange passes, bodies up to what the session module accepts reach it, one byte more is 413", { ...options, timeout: 60000 }, async () => {
  // challenge: an EK plus a full chain of maximum-size certificates (VBS_MAX_CHAIN_CERTS of 64 KiB each)
  assert.ok(SHIELD_CHALLENGE_MAX_BYTES > 9 * 87384 && SHIELD_CHALLENGE_MAX_BYTES < 800 * 1024, String(SHIELD_CHALLENGE_MAX_BYTES));
  assert.equal(SHIELD_ATTEST_MAX_BYTES, HVNODE_RAD_BODY_MAX_CHARS + 8192);
  const auth = responder();
  const s = await serveBounded(auth);
  try {
    // the genuine host: challenge, attest, and its guest's push, all through the bounded handler
    const genuine = await httpSession(s);
    const at = await s.send("/v1/shield-session/attest", { body: genuine });
    assert.equal(at.status, 200, JSON.stringify(at.body));
    assert.equal((await auth.authorize(push())).ok, true);
    // a maximal challenge envelope is read and judged by the session module (here: not certificates), not cut off
    const maxCert = "A".repeat(4 * Math.ceil(65536 / 3));
    const big = challengeBody({ ...keysOf(world), ekChain: Array(8).fill(maxCert) });
    const bigBytes = Buffer.byteLength(JSON.stringify(big));
    assert.ok(bigBytes > 690_000 && bigBytes <= SHIELD_CHALLENGE_MAX_BYTES, String(bigBytes));
    const judged = await s.send("/v1/shield-session/challenge", { body: big });
    assert.equal(judged.status, 422, JSON.stringify(judged.body));
    assert.equal((await s.send("/v1/shield-session/challenge", { raw: Buffer.alloc(SHIELD_CHALLENGE_MAX_BYTES + 1, 0x20) })).status, 413);
    assert.equal((await s.send("/v1/shield-session/challenge", { raw: Buffer.alloc(SHIELD_CHALLENGE_MAX_BYTES + 1, 0x20), chunked: true })).status, 413);
    // attest: a rad.body at the session module's ceiling reaches it (its own 422s decide), one char over is ITS refusal,
    // and only a request over the handler's bound is the handler's 413
    for (const [len, re] of [[HVNODE_RAD_BODY_MAX_CHARS, /not JSON/], [HVNODE_RAD_BODY_MAX_CHARS + 1, /missing or oversized/]]) {
      const live = (await s.send("/v1/shield-session/challenge", { body: challengeBody() })).body;
      const r = await s.send("/v1/shield-session/attest", { body: { session: live.session, rad: { format: "windows-hv-node/v1", body: "A".repeat(len), transportKey: genuine.rad.transportKey }, operatorSig: "0x" } });
      assert.equal(r.status, 422, JSON.stringify(r.body));
      assert.match(r.body.error, re);
    }
    assert.equal((await s.send("/v1/shield-session/attest", { raw: Buffer.alloc(SHIELD_ATTEST_MAX_BYTES + 1, 0x20), chunked: true })).status, 413);
    await settle(); idle(auth);
  } finally { await s.close(); }
});

test("admission: overload is refused at once with 503 + retry-after, per route; every outcome gives its slot back, and the genuine host recovers", { ...options, timeout: 60000 }, async () => {
  const auth = responder(world, ZONE, policy(world), { maxConcurrentChallenges: 2, maxConcurrentAttests: 1, challengeReadMs: 1000, attestReadMs: 1000 });
  const s = await serveBounded(auth);
  try {
    // one attest held mid-body: the next is 503 before it is read, deterministically; challenges are admitted separately
    let seen = s.arrived();
    const held = s.send("/v1/shield-session/attest", { hold: true, headers: { "content-length": 100 } });
    const heldOnServer = await seen;
    assert.deepEqual(auth.inflight(), { challenge: 0, attest: 1 });
    for (let i = 0; i < 3; i++) {
      const busy = await s.send("/v1/shield-session/attest", { body: { session: "x" } });
      assert.deepEqual([busy.status, busy.body.error, busy.headers["retry-after"]], [503, "busy", "1"]);
    }
    assert.equal((await s.send("/v1/shield-session/challenge", { body: challengeBody() })).status, 200);
    // the client goes away: its slot is back
    const gone = new Promise((ok) => heldOnServer.once("close", ok));
    held.req.destroy();
    await held.done; await gone; await settle();
    assert.deepEqual(auth.inflight(), { challenge: 0, attest: 0 });
    // two challenges held: a third is 503; then the read deadline (408) frees both
    seen = s.arrived();
    const c1 = s.send("/v1/shield-session/challenge", { hold: true, headers: { "content-length": 100 } }); await seen;
    seen = s.arrived();
    const c2 = s.send("/v1/shield-session/challenge", { hold: true, headers: { "content-length": 100 } }); await seen;
    assert.equal((await s.send("/v1/shield-session/challenge", { body: challengeBody() })).status, 503);
    assert.deepEqual([(await within(c1.done)).status, (await within(c2.done)).status], [408, 408]);
    await settle(); idle(auth);
    // malformed, declared-oversized and refused requests all release
    assert.equal((await s.send("/v1/shield-session/attest", { raw: Buffer.from("{nope") })).status, 400);
    assert.equal((await s.send("/v1/shield-session/attest", { raw: Buffer.from("{}"), headers: { "content-length": SHIELD_ATTEST_MAX_BYTES + 1 } }).catch(() => ({ status: 413 }))).status, 413);
    const replayed = await s.send("/v1/shield-session/attest", { body: { session: "never-issued" } });
    assert.equal(replayed.status, 409);
    const wrongCa = await s.send("/v1/shield-session/challenge", { body: challengeBody(keysOf(other)) });
    assert.equal(wrongCa.status, 403);
    // an expired challenge, then a failed verification (another key signed the attach), each release
    let t = Date.now();
    const timed = responder(world, ZONE, policy(world), { maxConcurrentAttests: 1, now: () => t });
    const ts = await serveBounded(timed);
    try {
      const g = await httpSession(ts);
      t += 61_000;
      assert.equal((await ts.send("/v1/shield-session/attest", { body: g })).status, 409);
      t = Date.now();
      const g2 = await httpSession(ts, world, { signer: stranger });
      assert.equal((await ts.send("/v1/shield-session/attest", { body: g2 })).status, 403);
      await settle(); idle(timed);
      // recovery: the genuine host's exchange passes on the same responder, with its single attest slot
      assert.equal((await ts.send("/v1/shield-session/attest", { body: await httpSession(ts) })).status, 200);
      assert.equal((await timed.authorize(push())).ok, true);
      await settle(); idle(timed);
    } finally { await ts.close(); }
    await settle(); idle(auth);
    // options are bounded at construction
    for (const bad of [{ maxConcurrentAttests: 0 }, { maxConcurrentAttests: 17 }, { maxConcurrentChallenges: 1.5 }, { attestReadMs: 10 }, { challengeReadMs: "30000" }])
      assert.throws(() => responder(world, ZONE, policy(world), bad), /must be an integer/, JSON.stringify(bad));
  } finally { await s.close(); }
});

// ---- every admitted host is searched; capacity per TPM; registry freshness; the profile-bound registry read -------------
const hostAuth = (registry, extra = {}) => createShieldChallengeAuth({ policy: { ...policy(world), ekRoots: world.ca.bundlePem + other.ca.bundlePem }, zone: ZONE,
  registryEntry: async (id) => { const e = registry.get(id); if (e instanceof Error) throw e; return e ?? null; },
  recoverSigner: (message, signature) => recoverMessageAddress({ message, signature }), ...extra });
const register = (registry, i, fields = {}) => {
  const endpoint = `https://box${i}.example.org`;
  registry.set(keccak256(toBytes(endpoint)), { endpoint, operator: operator.address, active: true, ...fields });
  return endpoint;
};

test("every admitted host session is searched: with 128 live hosts the OLDEST host's guest still passes; newer or later sessions neither shadow nor evict it", { ...options, timeout: 240000 }, async () => {
  const registry = new Map(), auth = hostAuth(registry, { maxLivePerEk: 128 });
  const boots = [];
  for (let i = 0; i < 128; i++) {
    const idks = generateKeyPairSync("rsa", { modulusLength: 2048 });          // each host: its own boot, its own IDKS
    await (await hostSession(auth, world, { endpoint: register(registry, i), idksOf: { idks } })).attest();
    boots.push(idks);
  }
  assert.equal(auth.sessions(), 128);
  const ms = [];
  for (const i of [0, 1, 31, 32, 33, 64, 96, 127]) {                           // 0..95 were outside the old newest-32 cut
    const t0 = performance.now();
    const v = await auth.authorize(push({ signer: boots[i].privateKey }));
    ms.push(performance.now() - t0);
    assert.equal(v.ok, true, `host ${i}: ${v.why}`);
  }
  // a report no admitted boot signed scans all 128 and is refused - bounded work, no wrong acceptance
  const t0 = performance.now();
  assert.match((await auth.authorize(push({ signer: other.idks.privateKey }))).why, /Shield attestation refused/);
  const full = performance.now() - t0;
  // a newer host re-attesting replaces only its own session; a 129th host is refused capacity and evicts nobody
  await (await hostSession(auth, world, { endpoint: `https://box127.example.org`, idksOf: { idks: boots[127] } })).attest();
  assert.equal(auth.sessions(), 128);
  await assert.rejects((await hostSession(auth, world, { endpoint: register(registry, 128) })).attest(), (e) => e.status === 429);
  assert.equal(auth.sessions(), 128);
  assert.equal((await auth.authorize(push({ signer: boots[0].privateKey }))).ok, true, "the oldest host is still served");
  console.log(`# 128 live sessions: authorize ${ms.map((x) => x.toFixed(1)).join("/")} ms; a full scan (refused) ${full.toFixed(1)} ms`);
});

test("live capacity per TPM: one endorsement key holds at most MAX_LIVE_PER_EK sessions; its hosts are served, the next is refused", options, async () => {
  const registry = new Map(), auth = hostAuth(registry);
  const boots = [];
  for (let i = 0; i < MAX_LIVE_PER_EK; i++) {
    const idks = generateKeyPairSync("rsa", { modulusLength: 2048 });
    await (await hostSession(auth, world, { endpoint: register(registry, i), idksOf: { idks } })).attest();
    boots.push(idks);
  }
  await assert.rejects((await hostSession(auth, world, { endpoint: register(registry, MAX_LIVE_PER_EK) })).attest(),
    (e) => e.status === 429 && /already holds 4 live host sessions/.test(e.message));
  await (await hostSession(auth, world, { endpoint: `https://box0.example.org`, idksOf: { idks: boots[0] } })).attest();   // re-attesting is not a new slot
  for (const b of boots) assert.equal((await auth.authorize(push({ signer: b.privateKey }))).ok, true);
  // another TPM is not counted against this one
  await (await hostSession(auth, other, { endpoint: register(registry, 99), idksOf: other })).attest();
  assert.equal(auth.sessions(), MAX_LIVE_PER_EK + 1);
});

test("registry freshness: inactive hosts never attest; an operator transfer or deactivation ends the session at the next push; an outage keeps it", options, async () => {
  let t = Date.now();
  const registry = new Map(), reads = new Map();
  const auth = createShieldChallengeAuth({ policy: policy(world), zone: ZONE, now: () => t, registryRecheckMs: 60_000,
    registryEntry: async (id) => { reads.set(id, (reads.get(id) || 0) + 1); const e = registry.get(id); if (e instanceof Error) throw e; return e ?? null; },
    recoverSigner: (message, signature) => recoverMessageAddress({ message, signature }) });
  const inactive = register(registry, 1, { active: false });
  await assert.rejects((await hostSession(auth, world, { endpoint: inactive })).attest(), (e) => e.status === 403 && /does not name this endpoint/.test(e.message));
  const refused = register(registry, 2);
  registry.set(keccak256(toBytes(refused)), { refused: "the registry's runtime is not the reviewed profile's" });
  await assert.rejects((await hostSession(auth, world, { endpoint: refused })).attest(), (e) => e.status === 403);

  const a = register(registry, 3), idA = keccak256(toBytes(a)), bootA = generateKeyPairSync("rsa", { modulusLength: 2048 });
  await (await hostSession(auth, world, { endpoint: a, idksOf: { idks: bootA } })).attest();
  assert.equal((await auth.authorize(push({ signer: bootA.privateKey }))).ok, true);
  const before = reads.get(idA);
  assert.equal((await auth.authorize(push({ signer: bootA.privateKey }))).ok, true);
  assert.equal(reads.get(idA), before, "within registryRecheckMs no chain read");
  // an outage at recheck: 503, the session stands; concurrent pushes share one read
  t += 61_000;
  registry.set(idA, new Error("no fresh agreeing chain quorum"));
  const [x, y] = await Promise.all([auth.authorize(push({ signer: bootA.privateKey })), auth.authorize(push({ signer: bootA.privateKey }))]);
  assert.equal(x.status, 503); assert.equal(y.status, 503);
  assert.equal(reads.get(idA), before + 1, "concurrent pushes share one recheck");
  assert.equal(auth.sessions(), 1);
  // the registry answers again: served, and re-checked
  register(registry, 3);
  assert.equal((await auth.authorize(push({ signer: bootA.privateKey }))).ok, true);
  // an operator transfer: the next recheck ends the session, and it stays ended
  t += 61_000;
  register(registry, 3, { operator: stranger.address });
  const moved = await auth.authorize(push({ signer: bootA.privateKey }));
  assert.equal(moved.status, 403); assert.match(moved.why, /session ended/);
  assert.equal(auth.sessions(), 0);
  register(registry, 3);
  assert.match((await auth.authorize(push({ signer: bootA.privateKey }))).why, /no live Shield host session/, "a revoked session never returns by itself");
  // deactivation and an agreed refused read end a session the same way
  for (const change of [{ active: false }, { refused: "schema 3" }]) {
    const e = register(registry, 3), boot = generateKeyPairSync("rsa", { modulusLength: 2048 });
    await (await hostSession(auth, world, { endpoint: e, idksOf: { idks: boot } })).attest();
    t += 61_000;
    registry.set(idA, change.refused ? change : { ...registry.get(idA), ...change });
    assert.equal((await auth.authorize(push({ signer: boot.privateKey }))).status, 403);
    assert.equal(auth.sessions(), 0);
    register(registry, 3);
  }
  assert.throws(() => hostAuth(registry, { registryRecheckMs: 1000 }), /registryRecheckMs/);
  assert.throws(() => hostAuth(registry, { maxSessions: 0 }), /maxSessions/);
  assert.throws(() => createShieldChallengeAuth({ policy: policy(world), zone: ZONE, recoverSigner: () => null }), /registry read/);
});

// A JSON-RPC registry chain for fixtures: chain id, head, blocks with one fixed timestamp, the registry's code,
// registrySchema() and get(). state(peer) -> { code, schema (null: reverts), layout?, entry } decides each answer.
async function jsonRpcHandler(state, peer, blockTime) {
  const { encodeFunctionResult, toFunctionSelector } = await import("viem");
  const SCHEMA_SEL = toFunctionSelector("registrySchema()"), GET_SEL = toFunctionSelector("get(bytes32)");
  const zero = { string: "", bytes32: "0x" + "00".repeat(32), address: "0x" + "00".repeat(20), uint64: 0n, bool: false };
  const one = (m) => {
    const s = state(peer), head = 1000, r = (result) => ({ jsonrpc: "2.0", id: m.id, result });
    if (m.method === "eth_chainId") return r("0x2105");
    if (m.method === "eth_blockNumber") return r("0x" + head.toString(16));
    if (m.method === "eth_getBlockByNumber") {
      const n = Number(BigInt(m.params[0])), z32 = "0x" + "00".repeat(32);
      return r({ number: "0x" + n.toString(16), hash: "0x" + n.toString(16).padStart(64, "0"), parentHash: z32, timestamp: "0x" + blockTime.toString(16),
        nonce: "0x0000000000000000", difficulty: "0x0", gasLimit: "0x1", gasUsed: "0x0", miner: "0x" + "00".repeat(20), extraData: "0x", size: "0x1",
        logsBloom: "0x" + "00".repeat(256), transactionsRoot: z32, stateRoot: z32, receiptsRoot: z32, sha3Uncles: z32, mixHash: z32, totalDifficulty: "0x0",
        baseFeePerGas: "0x1", transactions: [], uncles: [] });
    }
    if (m.method === "eth_getCode") return r(s.code);
    if (m.method === "eth_call") {
      const data = m.params[0].data;
      if (data.startsWith(SCHEMA_SEL)) return s.schema === null ? { jsonrpc: "2.0", id: m.id, error: { code: 3, message: "execution reverted", data: "0x" } }
        : r(encodeFunctionResult({ abi: [{ type: "function", name: "registrySchema", inputs: [], outputs: [{ type: "uint256" }] }], functionName: "registrySchema", result: BigInt(s.schema) }));
      if (data.startsWith(GET_SEL)) {
        const fields = REGISTRY_GET_LAYOUTS[s.layout || s.schema];
        const abi = [{ type: "function", name: "get", inputs: [{ type: "bytes32" }], outputs: [{ type: "tuple", components: fields.map(([name, type]) => ({ name, type })) }] }];
        return r(encodeFunctionResult({ abi, functionName: "get", result: { ...Object.fromEntries(fields.map(([name, type]) => [name, zero[type]])), ...s.entry } }));
      }
    }
    return { jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "method not found" } };
  };
  return (req, res) => {
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
      const m = JSON.parse(b);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(Array.isArray(m) ? m.map(one) : one(m)));
    });
  };
}

// Two real local JSON-RPC servers (viem clients, the committed quorum reader with localFixture): the binding is judged
// only on facts both agree on at one block.
async function rpcPair(t, state) {
  const http = await import("node:http");
  const { createPublicClient, http: transport } = await import("viem");
  const { base } = await import("viem/chains");
  const { quorumReader } = await import("../windows/node/host-identity.mjs");
  const servers = [], blockTime = Math.floor(Date.now() / 1000);   // one chain: a block's timestamp never changes
  for (const peer of [0, 1]) {
    const server = http.createServer(await jsonRpcHandler(state, peer, blockTime));
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    servers.push(server);
  }
  t.after(() => Promise.all(servers.map((s) => { s.closeAllConnections(); return new Promise((r) => s.close(r)); })));
  const clients = servers.map((s) => createPublicClient({ chain: base, transport: transport(`http://127.0.0.1:${s.address().port}`, { retryCount: 0, timeout: 5000 }) }));
  return quorumReader({ clients, localFixture: true, deadlineMs: 5000 });
}

test("the profile-bound registry read: the reviewed live Base pin, agreed raw facts, other code or schema refused, a single spoofing RPC is an outage", options, async (t) => {
  const { parseProfile } = await import("../network/authority-profile.mjs");
  const real = shieldRegistryBinding(parseProfile(fs.readFileSync(PROFILE_FILE), { expectedDigest: PROFILE_DIGEST }).profile);
  assert.deepEqual({ ...real }, { address: REAL_REGISTRY, codeHash: REAL_CODE_HASH, runtimeBytes: 5892, schema: "4" });
  assert.throws(() => shieldRegistryBinding({ contracts: { registry: { address: REAL_REGISTRY, codeHash: REAL_CODE_HASH, runtimeBytes: 5892, immutable: { registrySchema: "3" } } } }), /schema 3/);

  const code = "0x" + randomBytes(5892).toString("hex"), otherCode = "0x" + randomBytes(5892).toString("hex");
  const binding = shieldRegistryBinding({ contracts: { registry: { address: "0x" + "11".repeat(20), codeHash: keccak256(code), runtimeBytes: 5892, immutable: { registrySchema: "4" } } } });
  const honest = { code, schema: "4", entry: { endpoint: ENDPOINT, operator: operator.address, active: true } };
  let peers = [honest, honest];
  const entry = shieldRegistryEntry({ reader: await rpcPair(t, (i) => peers[i]), binding });
  assert.deepEqual(await entry(HOST_ID), { endpoint: ENDPOINT, operator: operator.address.toLowerCase(), active: true });
  // one RPC spoofs get(): no agreement, an outage (throws), never a decision
  peers = [honest, { ...honest, entry: { ...honest.entry, operator: stranger.address } }];
  await assert.rejects(entry(HOST_ID), /no fresh agreeing|disagree/);
  // agreed facts the binding forbids: other runtime code, another schema (also when its layout decodes), no schema getter
  for (const [state, re] of [[{ ...honest, code: otherCode }, /runtime/], [{ ...honest, schema: "5" }, /schema 5/], [{ ...honest, schema: null }, /schema !reverted/]]) {
    peers = [state, state];
    assert.match((await entry(HOST_ID)).refused, re);
  }
  // an inactive host is a fact the session layer refuses
  peers = [{ ...honest, entry: { ...honest.entry, active: false } }, { ...honest, entry: { ...honest.entry, active: false } }];
  assert.equal((await entry(HOST_ID)).active, false);

  // end to end through the responder: the genuine host attests over this chain read; once the RPCs agree the registry
  // code differs, the next push after the recheck window ends its session
  peers = [honest, honest];
  let now = Date.now();
  const auth = createShieldChallengeAuth({ policy: policy(world), zone: ZONE, registryEntry: entry, now: () => now,
    recoverSigner: (message, signature) => recoverMessageAddress({ message, signature }) });
  await (await hostSession(auth)).attest();
  assert.equal((await auth.authorize(push())).ok, true);
  peers = [{ ...honest, code: otherCode }, { ...honest, code: otherCode }];
  now += 61_000;
  const v = await auth.authorize(push());
  assert.equal(v.status, 403); assert.match(v.why, /session ended/);
  // and a host whose registry entry is inactive cannot attest at all
  peers = [{ ...honest, entry: { ...honest.entry, active: false } }, { ...honest, entry: { ...honest.entry, active: false } }];
  await assert.rejects((await hostSession(auth)).attest(), (e) => e.status === 403);
});

// The REAL responder process end to end, entirely on this machine's loopback interface. Clearly a fixture: the TPM, the
// Shield guest report, the registry contract (its code, schema-4 get()) and the chain are synthetic; the authority profile
// is the reviewed live Base profile with ONLY the registry's code hash and length replaced by the fixture's, re-encoded
// and pinned by its own digest exactly as an operator pins theirs. The two RPCs are HTTPS on 127.0.0.2 and 127.0.0.3
// (distinct hosts to the quorum, never "loopback"), trusted by the child only through NODE_EXTRA_CA_CERTS.
function dnsQuery(name, type = 16) {
  const h = Buffer.alloc(12); h.writeUInt16BE(0x4242, 0); h.writeUInt16BE(0x100, 2); h.writeUInt16BE(1, 4);
  return Buffer.concat([h, ...name.split(".").map((v) => Buffer.concat([Buffer.from([v.length]), Buffer.from(v)])), Buffer.from([0, type >> 8, type & 255, 0, 1])]);
}
async function dnsAsk(port, name, tcp) {
  const q = dnsQuery(name);
  if (!tcp) {
    const dgram = await import("node:dgram"); const s = dgram.createSocket("udp4");
    try { return await new Promise((resolve, reject) => { s.once("message", resolve); s.send(q, port, "127.0.0.1"); setTimeout(() => reject(new Error("UDP timeout")), 2000).unref(); }); }
    finally { s.close(); }
  }
  const net = await import("node:net");
  return new Promise((resolve, reject) => {
    const s = net.connect(port, "127.0.0.1", () => { const n = Buffer.alloc(2); n.writeUInt16BE(q.length); s.write(Buffer.concat([n, q])); });
    let d = Buffer.alloc(0);
    s.on("data", (c) => { d = Buffer.concat([d, c]); if (d.length >= 2 && d.length >= 2 + d.readUInt16BE(0)) { s.destroy(); resolve(d.subarray(2)); } });
    s.on("error", reject); s.setTimeout(2000, () => { s.destroy(); reject(new Error("TCP timeout")); });
  });
}

test("the real responder process end to end (synthetic TPM, guest and chain on loopback): host attest over HTTPS RPCs, guest push, DNS over UDP and TCP, refusals", { ...options, timeout: 120000 }, async (t) => {
  const https = await import("node:https"), net = await import("node:net"), { execFileSync, spawn } = await import("node:child_process");
  const { encodeProfile, profileDigest } = await import("../network/authority-profile.mjs");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shield-dns-e2e-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  // the RPCs' TLS: a test CA and one certificate for both loopback addresses
  const run = (args) => execFileSync("openssl", args, { stdio: "ignore" });
  run(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=e2e rpc ca", "-days", "1", "-keyout", path.join(dir, "ca.key"), "-out", path.join(dir, "ca.pem"),
       "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign"]);
  run(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=rpc", "-keyout", path.join(dir, "rpc.key"), "-out", path.join(dir, "rpc.csr")]);
  fs.writeFileSync(path.join(dir, "ext"), "subjectAltName=IP:127.0.0.2,IP:127.0.0.3\nextendedKeyUsage=serverAuth\n");
  run(["x509", "-req", "-in", path.join(dir, "rpc.csr"), "-CA", path.join(dir, "ca.pem"), "-CAkey", path.join(dir, "ca.key"), "-set_serial", "7", "-days", "1", "-extfile", path.join(dir, "ext"), "-out", path.join(dir, "rpc.pem")]);
  // the fixture registry and its "reviewed" profile
  const code = "0x" + randomBytes(5892).toString("hex");
  const real = JSON.parse(fs.readFileSync(PROFILE_FILE, "utf8"));
  real.contracts.registry = { ...real.contracts.registry, codeHash: keccak256(code), runtimeBytes: 5892 };
  const profileBytes = encodeProfile(real), digest = profileDigest(profileBytes);
  fs.writeFileSync(path.join(dir, "profile.json"), profileBytes);
  fs.writeFileSync(path.join(dir, "policy.json"), JSON.stringify(policy(world)));
  const chain = { code, schema: "4", entry: { endpoint: ENDPOINT, operator: operator.address, active: true } };
  const blockTime = Math.floor(Date.now() / 1000), rpcs = [];
  for (const [peer, host] of [[0, "127.0.0.2"], [1, "127.0.0.3"]]) {
    const server = https.createServer({ key: fs.readFileSync(path.join(dir, "rpc.key")), cert: fs.readFileSync(path.join(dir, "rpc.pem")) }, await jsonRpcHandler(() => chain, peer, blockTime));
    await new Promise((r) => server.listen(0, host, r));
    t.after(() => { server.closeAllConnections(); return new Promise((r) => server.close(r)); });
    rpcs.push(`https://${host}:${server.address().port}`);
  }
  const port = () => new Promise((r) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });
  const apiPort = await port(), dnsPort = await port();
  const blank = Object.fromEntries(["DNS_READ_ONLY", "IP_ZONE", "APP_ZONE", "TCP_ZONE", "BOX_ZONE", "APP_STATIC", "ROUTE_MAP_URL", "DNS_TXT_KEY", "SECRET",
    "REGISTRY_ADDRESS", "ENCLAVES", "ENCLAVE_URL", "ELIGIBILITY_API", "DOMAINS_API", "ADDRESS_BOOK_ADDRESS", "BASE_RPC", "ATTESTED_MEASUREMENTS", "ATTESTED_SHIELD_PINS"].map((k) => [k, ""]));
  const child = spawn(process.execPath, ["relay/dns-relay.js"], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...blank,
    DNS_CHALLENGE_AUTH: "attested", CHALLENGE_ZONE: ZONE, NS_NAME: "ns1.owner.example", DNS_BIND: "127.0.0.1", DNS_API_BIND: "127.0.0.1",
    DNS_PORT: String(dnsPort), DNS_API_PORT: String(apiPort), NODE_EXTRA_CA_CERTS: path.join(dir, "ca.pem"),
    ATTESTED_SHIELD_POLICY: path.join(dir, "policy.json"), ATTESTED_SHIELD_PROFILE: path.join(dir, "profile.json"), ATTESTED_SHIELD_PROFILE_DIGEST: digest,
    ATTESTED_SHIELD_RPCS: rpcs.join(",") } });
  let log = ""; child.stdout.on("data", (c) => { log += c; }); child.stderr.on("data", (c) => { log += c; });
  t.after(() => child.kill("SIGTERM"));
  const api = `http://127.0.0.1:${apiPort}`;
  let health;
  for (let i = 0; i < 80 && !health; i++) { health = await fetch(api + "/health").then((r) => r.json()).catch(() => null); if (!health) await new Promise((r) => setTimeout(r, 100)); }
  assert.ok(health, log);
  assert.equal(health.shield.registry.profileDigest, digest);
  // the node's operator drives the host session against the process over HTTP (the same exchange shield-sessions.mjs makes)
  const post = async (p, body) => { const r = await fetch(api + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json(); if (r.status !== 200) throw Object.assign(new Error(j.error || r.status), { status: r.status }); return j; };
  const viaHttp = { challenge: (b) => post("/v1/shield-session/challenge", b), attest: (b) => post("/v1/shield-session/attest", b) };
  await assert.rejects((await hostSession(viaHttp, world, { signer: stranger })).attest(), (e) => e.status === 403, "another operator's signature");
  const a = await (await hostSession(viaHttp)).attest();
  assert.equal(a.tier, "hv-node"); assert.equal(a.hostExcluded, false);
  // the guest's push, then the CA's view of it: TXT over UDP and TCP
  const txt = (x) => fetch(api + "/v1/txt", { method: x.method, body: x.raw, headers: { "content-type": "application/json", "x-attested-sig": x.sig } });
  const x = push();
  const ok = await txt(x);
  assert.equal(ok.status, 200, (await ok.clone().text()) + log);
  for (const tcp of [false, true]) {
    const answer = await dnsAsk(dnsPort, x.p.name, tcp);
    assert.equal(answer.readUInt16BE(6), 1, "one TXT answer"); assert.ok(answer.includes(Buffer.from(x.p.value)));
  }
  // negative attestations through the process: another boot's report, a forged binding, a SNP document (no SNP pins here)
  for (const [bad, re] of [[push({ signer: other.idks.privateKey }), /Shield attestation refused/], [push({ bindNonce: randomBytes(32) }), /guest binding differs/]]) {
    const r = await txt(bad); assert.equal(r.status, 403); assert.match((await r.json()).message, re);
  }
  const snp = push({ format: "sev-snp-guest-domain-v1" });
  assert.equal((await txt(snp)).status, 403);
  // delete takes the same proof; then nothing is answered
  assert.equal((await txt(push({ op: "delete", method: "DELETE" }))).status, 200);
  assert.equal((await dnsAsk(dnsPort, x.p.name, false)).readUInt16BE(6), 0);
  // the old legacy zones are not served by this responder
  assert.equal((await dnsAsk(dnsPort, "_acme-challenge.abcd1234.app.enclave.host", true)).readUInt16BE(2) & 15, 5);
  assert.doesNotMatch(log, /unhandledRejection|uncaughtException/);
});
