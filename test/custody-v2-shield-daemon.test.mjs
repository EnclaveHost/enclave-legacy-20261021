// The custody v2 daemon's HTTP router (custody/v2/http.mjs, the handler custody/v2/daemon.mjs serves) with the OPTIONAL
// measured Shield recipient opt-in (custody/v2/shield-operator.mjs), over real HTTP on loopback:
//   - default off: the Shield routes are an unknown route, /info is unchanged, a Shield document is unsupported;
//   - on: the opt-in goes through the build's own measured module (custodianMeasured -> measuredModule -> MEASURED) into the
//     adapter for THIS custodian's encKey; the node's real session client attests over HTTP, then a release over HTTP opens
//     only for the guest's R; replays, wrong party, default/SNP rules, wrong ledger owner are refused;
//   - bounds: attest's measured body bound (Content-Length and streamed), concurrency, the 256 KiB bound everywhere else,
//     the rate limiter; every pre-existing route still dispatched exactly as before;
//   - the host config cannot carry the opt-in, and the daemon builds it from MEASURED only.
// The custodian is the real createCustodianV2 (test/helpers/shield-custody-rig.mjs); only the member/DKG engine behind the
// unchanged routes is a recording stub.   Needs openssl.   run: node --test test/custody-v2-shield-daemon.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import { randomBytes, createHash, generateKeyPairSync, X509Certificate } from "node:crypto";
import { keccak256, toBytes } from "viem";
import { buildHvNodeFrame } from "../windows/node/hvnode-evidence.mjs";
import { issueEk } from "./fixtures/vbs-synthetic.mjs";
import { MAX_SESSIONS_PER_EK } from "../custody/v2/shield-evidence.mjs";
import { attachMessage } from "../windows/node/shield-verdict.mjs";
import { createResponderSessions } from "../windows/node/shield-sessions.mjs";
import * as v2 from "../custody/v2/protocol.mjs";
import * as hpke from "../custody/hpke.mjs";
import { createCustodyRouter, validateTrustedProxies, MAX_BODY } from "../custody/v2/http.mjs";
import { custodianMeasured, measuredModule } from "../custody/v2/build-config.mjs";
import { shieldCustodyFor, defaultShieldLimits, SHIELD_OPERATOR_FORMAT, SHIELD_OPERATOR_TIER_ACK, SHIELD_ROUTE_PREFIX } from "../custody/v2/shield-operator.mjs";
import { parseHostConfig } from "../custody/v2/host-config.mjs";
import { canonicalRules } from "../custody/rules.mjs";
import { maliciousEks } from "./helpers/malicious-ek.mjs";
import { options, world, other, hex, b64, CHAIN, VAULT, COMMITTEE, ENDPOINT, OWNER, NEW_OWNER, operator, stranger, SECRETS, snpRules, rig, fakeTpm, request }
  from "./helpers/shield-custody-rig.mjs";

const HOST_OWNERSHIP = "0x" + "f5".repeat(20);
const sha = (b) => createHash("sha256").update(b).digest();
const operatorConfig = (limits = {}) => ({ format: SHIELD_OPERATOR_FORMAT, acceptTier: SHIELD_OPERATOR_TIER_ACK, ekRoots: world.ca.bundlePem,
                                           ekRootPins: [world.ca.rootPin], limits: { ...defaultShieldLimits(), ...limits } });
// the opt-in exactly as an image carries it: validated by the build, written into the measured module, imported back
async function baked(limits) {
  const { measured } = custodianMeasured({ vault: VAULT, hostOwnership: HOST_OWNERSHIP, shieldRecipients: operatorConfig(limits) });
  return (await import("data:text/javascript," + encodeURIComponent(measuredModule(measured)))).MEASURED;
}
const measuredRig = async (opts = {}, limits) => { const M = await baked(limits); return rig({ ...opts, shieldFor: (party) => shieldCustodyFor(M.shieldRecipients, { party }) }); };

// the daemon's router over a real loopback server; the member engine behind the unchanged routes records its calls
// as an image measured with --trusted-proxy for its forwarder (here the loopback the test clients connect from), so each
// test client's x-forwarded-for is its own bucket; trustedProxies: [] is the default image
async function serve(r, { memberThrows = false, attestReadMs, trustedProxies = ["127.0.0.1"] } = {}) {
  const calls = [];
  const rec = (name) => async (...a) => { calls.push([name, ...a]); if (memberThrows) throw new Error(`${name} engine says no`); return { ok: name }; };
  const member = { info: (c) => ({ v: 2, encKey: "0x" + r.encKeyHex, committeeId: c }), evidence: rec("evidence"), join: rec("join"), approve: rec("approve"),
                   setHostSig: rec("setHostSig"), approveCode: rec("approveCode") };
  const srv = http.createServer(createCustodyRouter({ custodian: r.custodian, member, runIndependent: rec("independent"), servedCommittee: () => COMMITTEE,
                                                      policyMode: null, chainId: CHAIN, vault: VAULT, trustedProxies, ...(attestReadMs ? { attestReadMs } : {}) }));
  await new Promise((ok) => srv.listen(0, "127.0.0.1", ok));
  return { url: `http://127.0.0.1:${srv.address().port}`, port: srv.address().port, srv, calls, close: () => new Promise((ok) => { srv.closeAllConnections(); srv.close(ok); }) };
}
let ip = 0;
const freshClient = () => `10.9.${(++ip >> 8) & 255}.${ip & 255}`;
// one request with full control of headers and body framing -> { status, body, headers }
function call(s, path, { method = "POST", body, raw, headers = {}, client = freshClient(), chunked = false } = {}) {
  return new Promise((resolve, reject) => {
    const data = raw !== undefined ? raw : body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request({ host: "127.0.0.1", port: s.port, path, method, headers: { "x-forwarded-for": client, ...(data ? { "content-type": "application/json", ...(chunked ? {} : { "content-length": data.length }) } : {}), ...headers } },
      (res) => { const c = []; res.on("data", (d) => c.push(d)); res.on("end", () => { const t = Buffer.concat(c).toString(); let j = null; try { j = JSON.parse(t); } catch {} resolve({ status: res.statusCode, body: j, headers: res.headers }); }); });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}
// the host's side of a session, over HTTP, keeping the attest body so a test can replay it
async function hostSessionHttp(s, { w = world, signer = operator, endpoint = ENDPOINT, party } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }), hostChallenge = randomBytes(32).toString("hex"), hostId = keccak256(toBytes(endpoint));
  const ch = await call(s, `${SHIELD_ROUTE_PREFIX}/challenge`, { body: { hostId, endpoint, hostChallenge, keys: { ek: b64(w.ek.cert), ekChain: [], aikPub: b64(w.aik.tpmtPublic), aikName: b64(w.aik.name) } } });
  assert.equal(ch.status, 200, JSON.stringify(ch.body));
  const nonce = Buffer.from(ch.body.nonce, "base64");
  const frame = await buildHvNodeFrame({ nonce, credentialBlob: Buffer.from(ch.body.credentialBlob, "base64"), secret: Buffer.from(ch.body.secret, "base64"), spki, privateKey, tpm: fakeTpm(w) });
  const operatorSig = await signer.signMessage({ message: attachMessage({ verifier: party ?? ch.body.party, hostId, endpoint, nonce: hex(nonce),
    transportKeySha256: hex(sha(spki)), ekCertSha256: hex(sha(w.ek.cert)), hostChallenge }) });
  const body = { session: ch.body.session, rad: frame.rad, operatorSig };
  return { challenge: ch.body, body, attest: await call(s, `${SHIELD_ROUTE_PREFIX}/attest`, { body }) };
}
// a guest release over HTTP: its custodian challenge from /v2/custody/challenge, the request to /v2/custody/release
async function releaseHttp(s, r, opts = {}) {
  const ch = await call(s, "/v2/custody/challenge", { body: {} });
  assert.equal(ch.status, 200);
  const built = await request({ custodian: { challenge: () => ch.body } }, opts);
  return { ...built, res: await call(s, "/v2/custody/release", { body: built.req }) };
}
const opens = (r, { recipient, binding }, out) => {
  const recs = v2.openPartials({ recipientPrivate: recipient.privateKey, binding, encKey: Buffer.from(r.encKeyHex, "hex"), count: out.count, sealed: Buffer.from(out.sealed, "base64") });
  const S = v2.combine(recs.map((record) => v2.verifyPartial({ record, R: v2.parseBundle(r.bundle).R, binding, commitments: [Buffer.from(r.g.commitments[0])] })), 1);
  return v2.decryptBundle({ S, label: r.label, bundle: r.bundle }).env;
};

test("default off: the measured module has no opt-in, the Shield routes are an unknown route, /info is unchanged, a Shield document is unsupported", options, async () => {
  const { measured } = custodianMeasured({ vault: VAULT, hostOwnership: HOST_OWNERSHIP });
  assert.equal("shieldRecipients" in measured, false);
  assert.equal(shieldCustodyFor(measured.shieldRecipients, { party: "11".repeat(32) }), null);
  const r = rig({ withShield: false, rules: canonicalRules(snpRules()) });
  const s = await serve(r);
  try {
    const unknown = await call(s, "/v2/custody/nope", { body: {} });
    assert.deepEqual([unknown.status, unknown.body], [404, { error: "not_found", message: "Unknown custody route." }]);
    for (const p of ["challenge", "attest"]) assert.deepEqual(await call(s, `${SHIELD_ROUTE_PREFIX}/${p}`, { body: { hostId: "0x" } }).then((x) => [x.status, x.body]), [unknown.status, unknown.body]);
    const info = await call(s, "/v2/custody/info", { method: "GET" });
    assert.deepEqual(info.body, { v: 2, encKey: "0x" + r.encKeyHex, committeeId: COMMITTEE, chainId: CHAIN, vault: VAULT, independentAdmission: null });
    const { res } = await releaseHttp(s, r);
    assert.deepEqual([res.status, res.body.error], [403, "unsupported_evidence"], JSON.stringify(res.body));
  } finally { await s.close(); }
});

test("every pre-existing route, method, bound and error mapping is the router's, unchanged", options, async () => {
  const r = rig({ withShield: false });
  const s = await serve(r);
  try {
    assert.deepEqual((await call(s, "/health", { method: "GET" })).body, { ok: true, role: "custodian-v2" });
    assert.deepEqual((await call(s, "/", { method: "GET" })).body, { ok: true, role: "custodian-v2" });
    assert.equal((await call(s, "/v2/custody/release", { method: "GET" })).status, 405);
    assert.deepEqual((await call(s, "/v2/custody/release", { raw: Buffer.from("{nope") })).body.error, "bad_json");
    const big = await call(s, "/v2/custody/release", { raw: Buffer.alloc(MAX_BODY + 1, 0x20) });
    assert.deepEqual([big.status, big.body.error], [413, "too_large"]);
    assert.equal(MAX_BODY, 262144);
    const ch = await call(s, "/v2/custody/challenge", { body: {} });
    assert.equal(ch.body.encKey, r.encKeyHex);
    // a Refusal keeps its status and code; any other error is 422 "refused"
    const bad = await call(s, "/v2/custody/release", { body: { v: 1 } });
    assert.deepEqual([bad.status, bad.body.error], [422, "bad_request"]);
    await call(s, "/v2/custody/evidence", { body: { nonce: "ab" } });
    await call(s, "/v2/custody/join", { body: { x: 1 } });
    await call(s, "/v2/custody/approve", { body: { y: 2 } });
    await call(s, "/v2/custody/host-binding", { body: { sig: "0xsig" } });
    await call(s, "/v2/custody/independent-genesis", { body: { z: 3 } });
    await call(s, "/v2/custody/code-approve", { body: { measurement: "0xm", add: true, permit: "p" } });
    assert.deepEqual(s.calls, [["evidence", "ab"], ["join", { x: 1 }, COMMITTEE], ["approve", { y: 2, next: [] }], ["setHostSig", "0xsig"], ["independent", { z: 3 }],
                               ["approveCode", { committeeId: COMMITTEE, measurement: "0xm", add: true, permit: "p" }]]);
  } finally { await s.close(); }
  const t = await serve(r, { memberThrows: true });
  try {
    const e = await call(t, "/v2/custody/join", { body: {} });
    assert.deepEqual([e.status, e.body], [422, { error: "refused", message: "join engine says no" }]);
    // the rate limiter (30 per client, then refill) covers every POST, the Shield routes included when on
    const client = freshClient();
    const codes = [];
    for (let i = 0; i < 35; i++) codes.push((await call(t, "/v2/custody/challenge", { body: {}, client })).status);
    assert.deepEqual([codes.slice(0, 30).every((c) => c === 200), codes[34]], [true, 429]);
  } finally { await t.close(); }
});

test("on: the node's session client attests over HTTP to THIS custodian's key, and a release over HTTP opens only for the guest's R", options, async () => {
  const r = await measuredRig();
  const s = await serve(r);
  try {
    const info = await call(s, "/v2/custody/info", { method: "GET" });
    assert.deepEqual(info.body.shieldRecipients, { tier: "hv-node/T0-hv", hostExcluded: false, party: r.encKeyHex, path: SHIELD_ROUTE_PREFIX });
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const client = createResponderSessions({ hostId: keccak256(toBytes(ENDPOINT)), endpoint: ENDPOINT, nodeKey: { privateKey, spki: publicKey.export({ type: "spki", format: "der" }) },
      tpm: fakeTpm(world), keysFrame: async () => ({ ek: b64(world.ek.cert), ekChain: [], aikPub: b64(world.aik.tpmtPublic), aikName: b64(world.aik.name) }),
      sign: (message) => operator.signMessage({ message }) });
    const ok = await client.refresh([{ url: s.url, party: r.encKeyHex, path: SHIELD_ROUTE_PREFIX }]);
    assert.deepEqual(ok.done, [s.url], ok.failed.join("; "));
    const rel = await releaseHttp(s, r);
    assert.equal(rel.res.status, 200, JSON.stringify(rel.res.body));
    assert.deepEqual(opens(r, rel, rel.res.body), SECRETS);
    assert.throws(() => opens(r, { ...rel, recipient: hpke.generateKeyPair() }, rel.res.body), "the host holds only ciphertext");
    // the same release request again: its custodian challenge is spent
    const again = await call(s, "/v2/custody/release", { body: rel.req });
    assert.deepEqual([again.status, again.body.error], [403, "bad_challenge"]);
  } finally { await s.close(); }
});

test("on: attest replay, another party, default/SNP rules and a wrong ledger owner are each refused over HTTP", options, async () => {
  const r = await measuredRig();
  const s = await serve(r);
  try {
    const h = await hostSessionHttp(s);
    assert.deepEqual([h.attest.status, h.attest.body.party, h.attest.body.tier, h.attest.body.hostExcluded], [200, r.encKeyHex, "hv-node", false]);
    const replay = await call(s, `${SHIELD_ROUTE_PREFIX}/attest`, { body: h.body });
    assert.deepEqual([replay.status, replay.body.error], [409, "shield_session"]);
    assert.match(replay.body.message, /expired, consumed or never issued/);
    const first = await releaseHttp(s, r);
    assert.equal(first.res.status, 200, JSON.stringify(first.res.body));
    // the host's operator signed an exchange naming another party than this custodian's encKey: the signature recovers to
    // no registered operator. The session is kept under that signer alone (B1), so it neither displaces this host's
    // session nor releases anything by itself.
    const foreign = await hostSessionHttp(s, { party: "11".repeat(32) });
    assert.equal(foreign.attest.status, 200);
    assert.equal(r.shield.sessions(), 2, "kept beside this host's session, not in its place");
    const after = (await releaseHttp(s, r)).res;
    assert.equal(after.status, 200, `the lease holder's own session still releases: ${JSON.stringify(after.body)}`);
    const lone = await measuredRig(), ls = await serve(lone);
    try {
      assert.equal((await hostSessionHttp(ls, { party: "11".repeat(32) })).attest.status, 200);
      const only = (await releaseHttp(ls, lone)).res;
      assert.deepEqual([only.status, only.body.error], [403, "evidence_refused"], "a foreign-party session alone releases nothing");
      assert.match(only.body.message, /registered operator/);
    } finally { await ls.close(); }
    // a report binding the policy owner where the ledger names a session vault (F2): refused at the binding
    const SESSION_VAULT = "0x" + "5e".repeat(20);
    const v = await measuredRig({ ledgerOwner: SESSION_VAULT });
    const sv = await serve(v);
    try {
      await hostSessionHttp(sv);
      const wrong = await releaseHttp(sv, v, { owner: OWNER });
      assert.deepEqual([wrong.res.status, wrong.res.body.error], [403, "evidence_refused"]);
      assert.match(wrong.res.body.message, /guest binding differs/);
      const right = await releaseHttp(sv, v, { owner: SESSION_VAULT });
      assert.equal(right.res.status, 200, JSON.stringify(right.res.body));
      assert.deepEqual(opens(v, right, right.res.body), SECRETS);
    } finally { await sv.close(); }
    // the measured adapter changes nothing for an owner without Shield rules: default/SNP rules refuse a Shield document
    const snp = await measuredRig({ rules: canonicalRules(snpRules()) });
    const ss = await serve(snp);
    try {
      await hostSessionHttp(ss);
      const res = (await releaseHttp(ss, snp)).res;
      assert.deepEqual([res.status, res.body.error], [403, "bad_rules"]);
    } finally { await ss.close(); }
    // the beneficial owner moved: refused before evidence
    const moved = await measuredRig({ beneficialOwner: NEW_OWNER });
    const sm = await serve(moved);
    try { await hostSessionHttp(sm); assert.equal((await releaseHttp(sm, moved)).res.body.error, "owner_mismatch"); } finally { await sm.close(); }
  } finally { await s.close(); }
});

test("the adapter's party is this custodian's own encKey, never a configured one", options, async () => {
  const M = await baked();
  assert.throws(() => rig({ shieldFor: () => shieldCustodyFor(M.shieldRecipients, { party: "11".repeat(32) }) }), /party must be this custodian's own encryption key/);
  assert.throws(() => shieldCustodyFor(M.shieldRecipients, {}), /verifying party's 32-byte id/);
  assert.throws(() => shieldCustodyFor(M.shieldRecipients, { party: "0x" + "11".repeat(32) }), /verifying party's 32-byte id/);
  const r = rig({ shieldFor: (party) => shieldCustodyFor(M.shieldRecipients, { party }) });
  assert.equal(r.shield.party, r.encKeyHex);
});

test("attest's measured body bound (declared and streamed), its concurrency bound, and 256 KiB on the challenge route", { ...options, timeout: 30000 }, async () => {
  const r = await measuredRig({}, { maxAttestBytes: 65536, maxConcurrentAttests: 1 });
  const s = await serve(r);
  try {
    // declared too large: refused before a byte of the body is read (none is sent)
    const declared = await new Promise((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port: s.port, path: `${SHIELD_ROUTE_PREFIX}/attest`, method: "POST",
        headers: { "content-type": "application/json", "content-length": 65537, "x-forwarded-for": freshClient() } },
        (res) => { res.resume(); res.on("end", () => { req.destroy(); resolve(res.statusCode); }); });
      req.on("error", (e) => (e.code === "ECONNRESET" ? null : reject(e)));
      req.flushHeaders();
      // a router that waited for the body would never answer: report that instead of hanging (a ceiling, not a timing)
      setTimeout(() => { req.destroy(); resolve("no answer before the body"); }, 5000).unref();
    });
    assert.equal(declared, 413);
    // streamed (chunked, no length) past the bound
    const streamed = await call(s, `${SHIELD_ROUTE_PREFIX}/attest`, { raw: Buffer.alloc(65537, 0x20), chunked: true });
    assert.deepEqual([streamed.status, streamed.body.error], [413, "too_large"]);
    // the challenge route keeps the ordinary bound, whatever attest's is
    const r2 = await measuredRig({}, { maxAttestBytes: 1 << 20 });
    const s2 = await serve(r2);
    try {
      assert.equal((await call(s2, `${SHIELD_ROUTE_PREFIX}/challenge`, { raw: Buffer.alloc(MAX_BODY + 1, 0x20) })).status, 413);
      const within = await call(s2, `${SHIELD_ROUTE_PREFIX}/attest`, { raw: Buffer.from(JSON.stringify({ session: "x", pad: "a".repeat(MAX_BODY) })) });
      assert.deepEqual([within.status, within.body.error], [409, "shield_session"], "a body over 256 KiB but under attest's bound reaches the session check");
    } finally { await s2.close(); }
    // concurrency: one attest in flight (its body still arriving) -> the next is 503 before it is read
    const arrived = new Promise((ok) => s.srv.once("request", ok));
    const slowBody = Buffer.from(JSON.stringify({ session: "nope", pad: "b".repeat(1000) }));
    let slowRes;
    const slow = http.request({ host: "127.0.0.1", port: s.port, path: `${SHIELD_ROUTE_PREFIX}/attest`, method: "POST",
      headers: { "content-type": "application/json", "content-length": slowBody.length, "x-forwarded-for": freshClient() } });
    const slowDone = new Promise((ok, no) => { slow.on("response", (res) => { const c = []; res.on("data", (d) => c.push(d)); res.on("end", () => { slowRes = { status: res.statusCode, body: JSON.parse(Buffer.concat(c)) }; ok(); }); }); slow.on("error", no); });
    slow.write(slowBody.subarray(0, 10));
    await arrived;
    const busy = await call(s, `${SHIELD_ROUTE_PREFIX}/attest`, { body: { session: "x" } });
    assert.deepEqual([busy.status, busy.body.error], [503, "busy"]);
    slow.end(slowBody.subarray(10));
    await slowDone;
    assert.deepEqual([slowRes.status, slowRes.body.error], [409, "shield_session"]);
    // a client that goes away mid-body gives its slot back (an aborted attest never holds the bound)
    const gone = http.request({ host: "127.0.0.1", port: s.port, path: `${SHIELD_ROUTE_PREFIX}/attest`, method: "POST",
      headers: { "content-type": "application/json", "content-length": 1000, "x-forwarded-for": freshClient() } });
    gone.on("error", () => {});
    const goneArrived = new Promise((ok) => s.srv.once("request", ok));
    gone.write("{");
    const seen = await goneArrived;                              // the router holds the slot from here
    const closed = new Promise((ok) => seen.once("close", ok));
    gone.destroy();
    await closed;
    await new Promise((ok) => setImmediate(ok));
    // released: a real session now attests
    const h = await hostSessionHttp(s);
    assert.equal(h.attest.status, 200, JSON.stringify(h.attest.body));
  } finally { await s.close(); }
  // a body trickling past the read deadline is cut off (408) and its slot given back
  const t = await serve(r, { attestReadMs: 300 });
  try {
    const slowest = await new Promise((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port: t.port, path: `${SHIELD_ROUTE_PREFIX}/attest`, method: "POST",
        headers: { "content-type": "application/json", "content-length": 1000, "x-forwarded-for": freshClient() } },
        (res) => { const c = []; res.on("data", (d) => c.push(d)); res.on("end", () => { req.destroy(); resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(c)) }); }); });
      req.on("error", (e) => (e.code === "ECONNRESET" || e.code === "EPIPE" ? null : reject(e)));
      req.write("{");
      setTimeout(() => { req.destroy(); resolve({ status: "no answer" }); }, 5000).unref();     // a ceiling for a router without the deadline
    });
    assert.deepEqual([slowest.status, slowest.body?.error], [408, "too_slow"]);
    const h = await hostSessionHttp(t);
    assert.equal(h.attest.status, 200, JSON.stringify(h.attest.body));
  } finally { await t.close(); }
});

test("the host config cannot carry the opt-in, and the daemon builds the adapter from MEASURED only and serves the shared router", () => {
  const hc = parseHostConfig(JSON.stringify({ endpoint: "https://c1.example.org", registryId: "0x" + "ab".repeat(32), shieldRecipients: { format: SHIELD_OPERATOR_FORMAT },
                                              ekRoots: "-----BEGIN CERTIFICATE-----", ekRootPins: ["00".repeat(32)], shield: true }));
  assert.deepEqual(Object.keys(hc).sort(), ["committeeId", "endpoint", "genesis", "hostUrl", "port", "registryId", "vcek"]);
  const src = fs.readFileSync(new URL("../custody/v2/daemon.mjs", import.meta.url), "utf8");
  const code = src.split("\n").filter((l) => !/^\s*\/\//.test(l)).join("\n");
  assert.equal((code.match(/shieldCustodyFor\(/g) || []).length, 1);
  assert.match(code, /shieldCustodyFor\(MEASURED\.shieldRecipients, \{ party: encKey\.slice\(2\) \}\)/);
  assert.match(code, /createCustodianV2\(\{[^]*?\bshield, log \}\)/);
  assert.match(code, /http\.createServer\(createCustodyRouter\(\{ custodian, member, runIndependent, servedCommittee,/);
  assert.match(code, /const trustedProxies = validateTrustedProxies\(MEASURED\.trustedProxies \?\? \[\]\);/);
  assert.match(code, /vault: MEASURED\.vault, trustedProxies \}\)\)/);
  assert.doesNotMatch(code, /switch \(u\.pathname\)|"\/v2\/custody\/release"/, "the daemon has no route table of its own");
  assert.deepEqual([...new Set(code.match(/process\.env\.[A-Z_]+/g))], ["process.env.CUSTODY_HOST_CONFIG"], "no environment input but the host config path");
  assert.doesNotMatch(code, /hc\.shield|hc\.ekRoots/);
});

test("one TPM cannot fill the live session table with endpoints it does not hold: each EK keeps at most 4 sessions", options, async () => {
  const r = await measuredRig({}, { maxSessions: MAX_SESSIONS_PER_EK + 1 });
  const s = await serve(r);
  try {
    // one TPM claims six endpoints (its sessions are accepted: identity is checked at a release, against the registry)
    for (let i = 0; i < 6; i++) assert.equal((await hostSessionHttp(s, { endpoint: `https://squat-${i}.example.org` })).attest.status, 200);
    assert.equal(r.shield.sessions(), MAX_SESSIONS_PER_EK, "its oldest sessions were evicted, not stacked");
    // another TPM under the same pinned CA (the genuine lease holder) still gets its session, and its release passes
    const genuine = { ...world, ek: issueEk(world.dir) };
    assert.equal((await hostSessionHttp(s, { w: genuine })).attest.status, 200);
    assert.equal((await releaseHttp(s, r)).res.status, 200);
    // the squatter's next claim evicts only its own oldest: the genuine session stays
    assert.equal((await hostSessionHttp(s, { endpoint: "https://squat-6.example.org" })).attest.status, 200);
    assert.equal(r.shield.sessions(), MAX_SESSIONS_PER_EK + 1);
    assert.equal((await releaseHttp(s, r)).res.status, 200);
  } finally { await s.close(); }
});

// B1 (work/custody-peer-review-interface.txt): identity is deferred at attest, so ANY genuine TPM under the pinned roots can
// attest for any endpoint with its own key. Its session must never take the place of the lease holder's.
test("a squatter's own genuine TPM and key, attesting for the lease holder's endpoint, never displaces its session or releases", options, async () => {
  const r = await measuredRig();
  const s = await serve(r);
  try {
    assert.equal((await hostSessionHttp(s)).attest.status, 200, "the lease holder (its TPM, its registered operator)");
    assert.equal((await releaseHttp(s, r)).res.status, 200);
    // another genuine on-die TPM under the same pinned CA, signing with a key that is not the endpoint's registered operator
    const squatter = { ...world, ek: issueEk(world.dir) };
    const sq = await hostSessionHttp(s, { w: squatter, signer: stranger });
    assert.deepEqual([sq.attest.status, sq.attest.body.party], [200, r.encKeyHex], "accepted at attest: identity is checked at a release");
    assert.equal(r.shield.sessions(), 2);
    const after = (await releaseHttp(s, r)).res;
    assert.equal(after.status, 200, `the genuine release stays available: ${JSON.stringify(after.body)}`);
    // repeated squatter sessions: for the same endpoint they replace only the squatter's own entry; for many endpoints the
    // per-EK cap evicts only the squatter's own oldest, never another EK's legitimate session
    for (let i = 0; i < 3; i++) assert.equal((await hostSessionHttp(s, { w: squatter, signer: stranger })).attest.status, 200);
    assert.equal(r.shield.sessions(), 2, "the squatter's re-attest for the same endpoint replaces its own entry only");
    for (let i = 0; i < 2 * MAX_SESSIONS_PER_EK; i++)
      assert.equal((await hostSessionHttp(s, { w: squatter, signer: stranger, endpoint: `https://squat-${i}.example.org` })).attest.status, 200);
    assert.equal(r.shield.sessions(), 1 + MAX_SESSIONS_PER_EK, "the squatter's EK holds at most its cap; the lease holder's session stays");
    assert.equal((await releaseHttp(s, r)).res.status, 200, "and still releases");
    // the squatter's session alone (no lease holder session) still cannot release: release authority is the registered operator's
    const lone = await measuredRig(), ls = await serve(lone);
    try {
      assert.equal((await hostSessionHttp(ls, { w: squatter, signer: stranger })).attest.status, 200);
      const only = (await releaseHttp(ls, lone)).res;
      assert.deepEqual([only.status, only.body.error], [403, "evidence_refused"]);
      assert.match(only.body.message, /no live Shield host session .*registered operator/);
      assert.equal(lone.shield.sessions(), 1, "refusing it consumed nothing");
    } finally { await ls.close(); }
  } finally { await s.close(); }
});

test("over HTTP at the custodian: malicious EKs take no pending slot; the genuine host challenges, attests and its guest is released; replayed and expired sessions refused", options, async () => {
  // the fixtures FIRST, then the frozen clock: openssl issues the "discrete" EK now, with a whole-second notBefore that
  // a clock frozen earlier in the same second could precede (then "not yet valid" would refuse it before the on-die check)
  const bad = maliciousEks(world, other);
  let t = Date.now();
  for (const [name, m] of Object.entries(bad)) assert.ok(Date.parse(new X509Certificate(Buffer.from(m.keys.ek, "base64")).validFrom) <= t, `${name} is valid at the frozen clock`);
  const M = await baked({ maxPendingChallenges: 1 });
  const r = rig({ shieldFor: (party) => shieldCustodyFor(M.shieldRecipients, { party, now: () => t }) });
  const s = await serve(r);
  try {
    const hostId = keccak256(toBytes(ENDPOINT));
    for (const [name, m] of Object.entries(bad)) {
      const x = await call(s, `${SHIELD_ROUTE_PREFIX}/challenge`, { body: { hostId, endpoint: ENDPOINT, hostChallenge: randomBytes(32).toString("hex"), keys: m.keys } });
      assert.deepEqual([x.status, x.body.error], [403, "shield_session"], name);
      assert.match(x.body.message, m.why, name);
    }
    // the one pending slot is still free: the genuine host's whole exchange, then its guest's release
    const h = await hostSessionHttp(s);
    assert.equal(h.attest.status, 200, JSON.stringify(h.attest.body));
    const rel = await releaseHttp(s, r);
    assert.equal(rel.res.status, 200, JSON.stringify(rel.res.body));
    assert.deepEqual(opens(r, rel, rel.res.body), SECRETS);
    const replay = await call(s, `${SHIELD_ROUTE_PREFIX}/attest`, { body: h.body });
    assert.deepEqual([replay.status, replay.body.error], [409, "shield_session"]);
    // a challenge left unanswered past its 60 s is refused at attest, and frees its slot
    const late = await call(s, `${SHIELD_ROUTE_PREFIX}/challenge`, { body: { hostId, endpoint: ENDPOINT, hostChallenge: randomBytes(32).toString("hex"),
      keys: { ek: b64(world.ek.cert), ekChain: [], aikPub: b64(world.aik.tpmtPublic), aikName: b64(world.aik.name) } } });
    assert.equal(late.status, 200);
    t += 61_000;
    const expired = await call(s, `${SHIELD_ROUTE_PREFIX}/attest`, { body: { session: late.body.session, rad: h.body.rad, operatorSig: h.body.operatorSig } });
    assert.deepEqual([expired.status, expired.body.error], [409, "shield_session"]);
    assert.match(expired.body.message, /expired/);
    // the live session itself expires with the measured sessionLifeSec: no release from it afterwards
    t += 600_000;
    const after = (await releaseHttp(s, r)).res;
    assert.deepEqual([after.status, after.body.error], [403, "evidence_refused"]);
    assert.match(after.body.message, /no live Shield host session/);
  } finally { await s.close(); }
});

test("the rate key is the TCP peer by default: a client-chosen x-forwarded-for neither escapes nor splits its bucket; only a measured forwarder's rightmost entry counts", options, async () => {
  const r = rig({ withShield: false });
  const codesFor = async (s, headersFor) => { const out = []; for (let i = 0; i < 35; i++) out.push((await call(s, "/v2/custody/challenge", { body: {}, client: undefined, headers: headersFor(i) })).status); return out; };
  // default image: every request here comes from 127.0.0.1; 35 different spoofed addresses still share one bucket
  const d = await serve(r, { trustedProxies: [] });
  try {
    const codes = await codesFor(d, (i) => ({ "x-forwarded-for": `198.51.100.${i}` }));
    assert.deepEqual([codes.slice(0, 30).every((c) => c === 200), codes[34]], [true, 429]);
  } finally { await d.close(); }
  // a measured forwarder: its rightmost entry is the client; a spoofed LEFT part changes nothing
  const t = await serve(r, { trustedProxies: ["127.0.0.1"] });
  try {
    const codes = await codesFor(t, (i) => ({ "x-forwarded-for": `203.0.113.${i}, 10.77.0.1` }));
    assert.equal(codes[34], 429, "one client behind the proxy, whatever it prepends");
    assert.equal((await call(t, "/v2/custody/challenge", { body: {}, headers: { "x-forwarded-for": "10.77.0.2" } })).status, 200, "another client has its own bucket");
    // a non-address rightmost entry falls back to the peer
    const junk = await codesFor(t, () => ({ "x-forwarded-for": "10.77.0.3, not-an-ip" }));
    assert.equal(junk[34], 429);
  } finally { await t.close(); }
  // a forwarder list that does not name this peer: the header is ignored
  const u = await serve(r, { trustedProxies: ["10.0.2.2"] });
  try {
    const codes = await codesFor(u, (i) => ({ "x-forwarded-for": `10.88.0.${i}` }));
    assert.equal(codes[34], 429);
  } finally { await u.close(); }
  // what may be trusted at all: loopback or private literals, at most 4, distinct
  assert.deepEqual(validateTrustedProxies(["10.0.2.2", "::ffff:127.0.0.1", "fd12::1"]), ["10.0.2.2", "127.0.0.1", "fd12::1"]);
  for (const bad of [["8.8.8.8"], ["10.0.0.0/8"], ["localhost"], ["172.32.0.1"], ["fe80::1"], ["10.0.2.2", "10.0.2.2"], ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"], "10.0.2.2", [7]])
    assert.throws(() => validateTrustedProxies(bad), /trusted proxies/, JSON.stringify(bad));
  assert.throws(() => createCustodyRouter({ custodian: r.custodian, member: {}, runIndependent: async () => ({}), servedCommittee: () => null, chainId: CHAIN, vault: VAULT, trustedProxies: ["1.1.1.1"] }), /not a loopback or private/);
});

test("the certificate clock boundary, deterministically: one ms before an EK's notBefore it is not yet valid; at notBefore the on-die rule decides", options, async () => {
  const { discrete } = maliciousEks(world, other);
  const notBefore = Date.parse(new X509Certificate(Buffer.from(discrete.keys.ek, "base64")).validFrom);
  const M = await baked();
  const at = async (clock) => {
    const r = rig({ shieldFor: (party) => shieldCustodyFor(M.shieldRecipients, { party, now: () => clock }) });
    const s = await serve(r);
    try {
      return await call(s, `${SHIELD_ROUTE_PREFIX}/challenge`, { body: { hostId: keccak256(toBytes(ENDPOINT)), endpoint: ENDPOINT,
        hostChallenge: randomBytes(32).toString("hex"), keys: discrete.keys } });
    } finally { await s.close(); }
  };
  const before = await at(notBefore - 1), exactly = await at(notBefore);
  assert.deepEqual([before.status, exactly.status], [403, 403], "refused either way: no pending slot");
  assert.match(before.body.message, /does not chain to a pinned TPM root: EK chain cert 0 not yet valid/);
  assert.match(exactly.body.message, discrete.why);
});
