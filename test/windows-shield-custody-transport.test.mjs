// Direct Shield custody, host side (windows/vbslike/manager/custody-transport.mjs, server.mjs, wmi-launcher.mjs, main.mjs;
// windows/node/shield-custody.mjs, secrets.mjs custodyAuthorization). The guest's half is isolation/m2/front
// shield_direct_custody.go (release.WriteAuthRequestV2 / ReadAuth on vsock 9445).
//
// FIXTURE, NOT HARDWARE. Nothing here is hv_sock, Hyper-V, a partition, a TPM, a custodian or a chain. What is real:
// - the launcher (over injected PowerShell answers, fake-hyperv.mjs);
// - the Manager and its HTTP server;
// - the custody transport and its pinned-bridge lifecycle;
// - the node's pump and custodyAuthorization, with a real secp256k1 test key.
// What stands in:
// - shielded-bridge.exe is testdata/fake-custody-bridge.py, a loopback "guest" port per partition. A guest connection
//   states its partition first, where the real bridge reads the hv_sock peer's VmId.
// - The guest is a socket writing the Go guest's exact line.
// - The node's fresh startup and lease verification (shield-startup.mjs materialize, tested in
//   windows-shield-startup.test.mjs) is a stub verdict here.
//   run: node --test --test-concurrency=1 test/windows-shield-custody-transport.test.mjs
import { test, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import crypto from "node:crypto";
import { spawn as nodeSpawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { privateKeyToAccount } from "viem/accounts";
import { verifyMessage } from "viem";
import { mintBridgeCredential, bridgeAuthLine, BRIDGE_AUTH_LINE_BYTES } from "../windows/vbslike/manager/bridge-auth.mjs";
import { parseCustodyRequest, custodyAnswerLine, serveCustodyRequests, startCustodyTransport, custodyCallbackHeader,
         CUSTODY_SERVICE_GUID, CUSTODY_VSOCK_PORT, CUSTODY_CALLBACK_HEADER } from "../windows/vbslike/manager/custody-transport.mjs";
import { Manager, createServer, startManager } from "../windows/vbslike/manager/server.mjs";
import { HyperVPartitionBackend } from "../windows/vbslike/manager/backend.mjs";
import { WmiHyperVLauncher, CMD, CUSTODY_CHECK, notesFor } from "../windows/vbslike/manager/wmi-launcher.mjs";
import { ImageLauncher } from "../windows/vbslike/manager/shield-profile.mjs";
import { TYPE1, PREFLIGHT_OK, defineAnswer, keyOf, startAndReadAnswer } from "../windows/vbslike/manager/fake-hyperv.mjs";
import { derive } from "../windows/vbslike/manager/derive.mjs";
import { isolationPlan, BACKEND } from "../windows/vbslike/datapath/node-bridge.mjs";
import { preparePackage } from "../sdk/bootstrap/package.mjs";
import { createShieldCustody } from "../windows/node/shield-custody.mjs";
import { custodyOperatorMessageV2 } from "../windows/node/secrets.mjs";
import { sessionTargets, custodianSessionTargets } from "../windows/node/shield-sessions.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FAKE_BRIDGE = path.join(HERE, "../windows/vbslike/manager/testdata/fake-custody-bridge.py");
const PYTHON = process.env.PYTHON_BIN || "python3";
const VEC = JSON.parse(fs.readFileSync(path.join(HERE, "../isolation/contract/catalog/derive_vectors.json"), "utf8"));
const COMPONENT = Buffer.from(VEC.component_hex, "hex"), REC = VEC.ok[0].mapping.record;
const VM_A = "5db6d4eb-1619-4936-9d60-c7e3ca67f3a8", VM_B = "6ec7e5fc-272a-4a47-8e71-d8f4db78a4b9", VM_C = "7fd8f60d-383b-4b58-9f82-e905ec89b5ca";
const DEP_A = "0x" + "e7".repeat(32), DEP_B = "0x" + "e8".repeat(32), DEP_C = "0x" + "e9".repeat(32);
const VAULT_A = "0x" + "c1".repeat(20), VAULT_B = "0x" + "c2".repeat(20);
const IMG_SHA = "2d7353760b89b81b6f47759382bb2e83c325d73ed0825734f30fc4051183dfb3";      // the Shield-direct (custody) image
const LEGACY_SHA = "4c".repeat(32);                                                           // the legacy image beside it (F3)
const ENDPOINT = "https://box.example.org";
const CONFIG = '{"api":"https://api.example"}';
const KEY = crypto.randomBytes(32);                              // the manager/node callback key: per test run
const OPERATOR = privateKeyToAccount("0x" + "7f".repeat(32));   // a TEST key (all 0x7f), never a real operator
const sign = (message) => OPERATOR.signMessage({ message });
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms));
/** A refusal is an IMMEDIATE close with no answer, never a request held until some timeout: bounded at 1 s here. */
const within = (p, ms = 1000, what = "the refusal") => Promise.race([p, new Promise((_, no) => setTimeout(() => no(new Error(`${what} took over ${ms} ms`)), ms))]);

// ---- the pinned "bridge" and its log -------------------------------------------------------------------------------------
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "custody-transport-"));
const BRIDGE_EXE = path.join(dir, "shielded-bridge.exe");
fs.writeFileSync(BRIDGE_EXE, "shielded-bridge bytes (fixture)");
const BRIDGE = { exe: BRIDGE_EXE, sha256: sha(fs.readFileSync(BRIDGE_EXE)) };
const LOG = path.join(dir, "bridge.log");
const events = () => (fs.existsSync(LOG) ? fs.readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const spawned = [];
/** t.after(reap(t)): kill every fixture child THIS test started, so a failing test leaks none into the next. */
const reap = () => { const n = spawned.length; return () => { for (const { child } of spawned.slice(n)) if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); }; };
let bridgeMode = "ok";
const spawnBridge = (file, args, opts) => {
  const child = nodeSpawn(PYTHON, [FAKE_BRIDGE, ...args], { ...opts, env: { ...process.env, FAKE_CUSTODY_BRIDGE: bridgeMode, FAKE_CUSTODY_LOG: LOG } });
  spawned.push({ file, args, child });
  return child;
};
async function until(fn, what, ms = 5000) {
  const end = Date.now() + ms;
  for (;;) { const v = fn(); if (v) return v; if (Date.now() > end) throw new Error(`timed out waiting for ${what}`); await tick(); }
}
const guestPortOf = (vm) => until(() => events().filter((e) => e.vm === vm && e.event === "ready").pop()?.guestPort, `${vm}'s bridge`);

/** The guest: dial "9445" through THIS partition's bridge, write one line, read until the host closes. */
function guestAsk(port, { from, line }) {
  return new Promise((resolve, reject) => {
    const c = net.connect(port, "127.0.0.1", () => c.write(`VM ${from}\n${line}`));
    const parts = [];
    c.on("data", (b) => parts.push(b));
    c.on("close", () => resolve(Buffer.concat(parts).toString("latin1")));
    c.on("error", reject);
  });
}
/** release.ReadAuth, as the Go guest reads the answer. */
function readAuth(text) {
  const f = text.split(/\s+/).filter(Boolean);
  assert.ok(text.endsWith("\n") && text.length <= 512, "one bounded line");
  assert.equal(f.length, 4); assert.equal(f[0], "custody-sig-v1");
  const endpoint = Buffer.from(f[1], "base64").toString();
  assert.match(endpoint, /^https?:\/\/[!-~]{1,190}$/); assert.match(f[3], /^0x[0-9a-f]{130}$/);
  return { endpoint, expiry: Number(f[2]), sig: f[3] };
}
const requestLine = (vault, id, binding) => `custody-auth-v2 ${vault} ${id} ${binding}\n`;     // release.WriteAuthRequestV2

// ---- 1. the wire --------------------------------------------------------------------------------------------------------
test("the request and answer lines are release.WriteAuthRequestV2 / WriteAuth's; v1 and every malformed line are refused", () => {
  const b = "9a".repeat(32);
  assert.deepEqual(parseCustodyRequest(requestLine(VAULT_A, DEP_A, b)), { v: 2, vault: VAULT_A, id: DEP_A, binding: b });
  assert.equal(CUSTODY_SERVICE_GUID, `${CUSTODY_VSOCK_PORT.toString(16).padStart(8, "0")}-facb-11e6-bd58-64006a7986d3`);
  for (const bad of [`custody-auth-v1 ${DEP_A} ${b}\n`, requestLine(VAULT_A.toUpperCase().replace("0X", "0x"), DEP_A, b),
                     requestLine(VAULT_A, DEP_A.replace("e7", "E7"), b), requestLine(VAULT_A, DEP_A, b.toUpperCase()), requestLine(VAULT_A, DEP_A, "9a"),
                     requestLine(VAULT_A, "0x" + "00".repeat(32), b), requestLine(VAULT_A, DEP_A, b).trimEnd(), `${requestLine(VAULT_A, DEP_A, b).trimEnd()} extra\n`,
                     requestLine(VAULT_A, DEP_A, b).padStart(300, " ")])
    assert.throws(() => parseCustodyRequest(bad), undefined, JSON.stringify(bad));
  const sig = "0x" + "ab".repeat(65);
  assert.equal(custodyAnswerLine({ endpoint: ENDPOINT, sig, expiry: 1700000000 }),
               `custody-sig-v1 ${Buffer.from(ENDPOINT).toString("base64")} 1700000000 ${sig}\n`);
  assert.equal(custodyAnswerLine({ endpoint: ENDPOINT, sig: sig.toUpperCase().replace("0X", "0x"), expiry: 1 }).split(" ")[3].trim(), sig, "lowercased, as ReadAuth requires");
  for (const bad of [{ endpoint: "ftp://x", sig, expiry: 1 }, { endpoint: ENDPOINT, sig: "0x12", expiry: 1 }, { endpoint: ENDPOINT, sig, expiry: 0 },
                     { endpoint: ENDPOINT + "/" + "a".repeat(200), sig, expiry: 1 }, { endpoint: "https://a b", sig, expiry: 1 }])
    assert.throws(() => custodyAnswerLine(bad));
});

test("the loopback channel lists only THIS deployment's and vault's requests, answers each at most once, and is bounded", async () => {
  const credential = mintBridgeCredential();
  const s = await serveCustodyRequests({ deploymentId: DEP_A, vault: VAULT_A, credential, maxRequests: 6, answerTimeoutMs: 400 });
  // as the bridge connects: its credential line first, then the guest's bytes
  const raw = (line) => new Promise((resolve) => { const c = net.connect(s.port, "127.0.0.1", () => c.write(bridgeAuthLine(credential) + line)); const p = [];
    c.on("data", (b) => p.push(b)); c.on("close", () => resolve(Buffer.concat(p).toString())); c.on("error", () => resolve("")); });
  try {
    const b = "11".repeat(32);
    assert.equal(await within(raw(requestLine(VAULT_A, DEP_B, b))), "", "another deployment: closed, no answer");
    assert.equal(await within(raw(requestLine(VAULT_B, DEP_A, b))), "", "another vault: closed, no answer");
    assert.equal(await within(raw(`custody-auth-v1 ${DEP_A} ${b}\n`)), "", "v1: closed, no answer");
    assert.equal(s.stats().refused, 3);
    assert.deepEqual(s.pending(), [], "none of them is ever listed for the node");
    const asked = raw(requestLine(VAULT_A, DEP_A, b));
    const [p] = await until(() => s.pending().length && s.pending(), "the pending request");
    assert.equal(p.id, DEP_A); assert.equal(p.binding, b); assert.match(p.request, /^[0-9a-f]{32}$/);
    const now = Math.floor(Date.now() / 1000), auth = { binding: b, endpoint: ENDPOINT, sig: "0x" + "ab".repeat(65), expiry: now + 300 };
    assert.throws(() => s.answer(p.request, { ...auth, binding: "22".repeat(32) }), (e) => e.status === 409);
    assert.throws(() => s.answer(p.request, { ...auth, expiry: now + 3600 }), (e) => e.status === 400, "an expiry past the bound");
    assert.throws(() => s.answer(p.request, { ...auth, expiry: now - 1 }), (e) => e.status === 400);
    assert.throws(() => s.answer("ff".repeat(16), auth), (e) => e.status === 409, "an unknown request");
    s.answer(p.request, auth);
    assert.equal(await asked, custodyAnswerLine(auth));
    assert.throws(() => s.answer(p.request, auth), (e) => e.status === 409, "answered once");
    // a request nobody answers is dropped before the guest's own two-minute deadline (here: 400 ms)
    const late = raw(requestLine(VAULT_A, DEP_A, b));
    await until(() => s.pending().length, "the second request");
    assert.equal(await within(late, 2000, "dropping an unanswered request"), ""); assert.deepEqual(s.pending(), []);
    // past maxRequests (6 connections), nothing more is even read
    assert.equal(await raw(requestLine(VAULT_A, DEP_A, b)), "");
    assert.equal(s.stats().answered, 1);
  } finally { await s.close(); }
});

// ---- 2. the partitions: the real launcher and manager, fixture bridges ----------------------------------------------------
/** Injected PowerShell answers: a compliant host, one VM id per define, the services registered or not. */
function hyperv({ custodyRegistered = true, vmIds = [VM_A, VM_B, VM_C], survey = () => ({ vms: [] }) } = {}) {
  let n = 0;
  const seen = [];
  const run = async (script) => {
    const k = keyOf(script); seen.push(k);
    const a = k === "preflight" ? { ...PREFLIGHT_OK, egressService: true, packageService: true, custodyService: custodyRegistered }
      : k === "imageHash" ? { present: true, sha256: script.includes("legacy.igvm") ? LEGACY_SHA : IMG_SHA, bytes: 1 }
      : k === "define" ? defineAnswer(script, { id: vmIds[n++ % vmIds.length] })
      : k === "startAndRead" ? startAndReadAnswer(() => undefined)
      : k === "removeById" ? { found: true, removed: true }
      : k === "retire" ? { present: true, retired: true }
      : k === "survey" ? survey()
      : { ok: true };
    return { code: 0, stdout: JSON.stringify(a), stderr: "" };
  };
  return { run, seen };
}
const stopped = [];
const launcherFor = (h, over = {}) => new WmiHyperVLauncher({ run: h.run, imagePath: "C:\\enclave\\shield-custody.igvm", imageSha256: IMG_SHA, prefix: "enclave-app-t-", ...TYPE1,
  startEgress: async (vmId) => ({ exited: new Promise(() => {}), stop: async () => { stopped.push(`egress ${vmId}`); } }), egressService: "000024e3-facb-11e6-bd58-64006a7986d3",
  startPackage: async (vmId) => ({ exited: new Promise(() => {}), stop: async () => { stopped.push(`package ${vmId}`); } }), packageService: "000024e6-facb-11e6-bd58-64006a7986d3",
  startCustody: (vmId, deploymentId, { vault }) => startCustodyTransport({ bridge: BRIDGE, vmId, deploymentId, vault, spawn: spawnBridge }),
  custodyService: CUSTODY_SERVICE_GUID, custodyImageSha256: IMG_SHA, imageRole: "shield-direct", ...over });
// the legacy image's launcher on the same host: egress only, no package or custody hook (F3)
const legacyFor = (h) => new WmiHyperVLauncher({ run: h.run, imagePath: "C:\\enclave\\legacy.igvm", imageSha256: LEGACY_SHA, prefix: "enclave-app-t-", ...TYPE1,
  startEgress: async (vmId) => ({ exited: new Promise(() => {}), stop: async () => { stopped.push(`egress ${vmId}`); } }), egressService: "000024e3-facb-11e6-bd58-64006a7986d3" });

const health0 = { backend: BACKEND, catalog: { derivations: ["enclave-catalog-bundle/1", "enclave-catalog-bundle/5", "enclave-catalog-bundle/6"], runtimeId: REC.runtimeId },
                  supports: { config: true, secrets: true, ports: false, directBootstrap: true, custodyV2: true }, runtime: { configSocketServer: false } };
/** What the node would spawn for a custody-v2 package (node-bridge.mjs isolationPlan, the manager's derive). */
function custodySpawn(dep, vault, { secretsMode = "custody-v2", configText = CONFIG } = {}) {
  const plan = isolationPlan({ deploymentId: dep, deployment: { cpuMilli: 250, gpuMilli: 0, isPublic: true }, version: { appId: REC.catalog.app, index: REC.catalog.version, cid: REC.cid, memMb: 512, ports: "", config: "" },
    appConfig: CONFIG, hasSecrets: true, waf: {}, volumes: [], runtimeId: REC.runtimeId, require: BACKEND, manager: health0, appConfigCid: "", configSourceCid: "" });
  assert.equal(plan.ok, true, JSON.stringify(plan));
  const appId = derive({ record: plan.spawn.derive, component: COMPONENT }).appId;
  const pkg = preparePackage({ version: 1, chainId: 8453, ledger: "0x" + "d0".repeat(20), deployment: dep, owner: "0x" + "33".repeat(20),
    appRef: `catalog://${REC.catalog.app}/${REC.catalog.version}`, appId, runtimeId: REC.runtimeId, configText, secretsMode,
    ...(secretsMode === "custody-v2" ? { custody: { v: 2, chainId: 8453, vault, machines: [{ endpoint: "https://custodian-1.example/c", encKey: "11".repeat(32), enclave: false, indices: [1] }] } } : {}) });
  const startup = { direct: true, imageRole: "shield-direct", imageSha256: IMG_SHA, sha256: pkg.sha256, appId, runtimeId: REC.runtimeId, secretsMode, deployment: dep,
                    custody: secretsMode === "custody-v2" ? { v: 2, chainId: 8453, vault, machines: [{ endpoint: "https://custodian-1.example/c", encKey: "11".repeat(32) }] } : null };
  return { body: { ...plan.spawn, bootstrap: pkg.bytes.toString("base64") }, startup, pkg };
}
const servers = [];
// a failed assertion must never leave a fixture bridge running (it would hold this process open): every child is killed
after(() => {
  for (const s of servers) { s.closeAllConnections?.(); s.close(); }
  for (const { child } of spawned) if (child && child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  fs.rmSync(dir, { recursive: true, force: true });
});
async function managerOn(h, { custodyV2 = { imageSha256: IMG_SHA, callbackKey: KEY }, launcher = new ImageLauncher({ legacy: legacyFor(h), shieldDirect: launcherFor(h) }) } = {}) {
  const m = new Manager({ runtimeId: REC.runtimeId, fetchComponent: async () => COMPONENT, directBootstrap: true, configEnabled: true, secretsEnabled: true,
    // two images, the SAME RuntimeID (legal): only the IGVM hash and the role tell them apart
    images: { legacy: { igvmSha256: LEGACY_SHA }, shieldDirect: { runtimeId: REC.runtimeId, igvmSha256: IMG_SHA } },
    fetchConfig: async () => Buffer.from("{}"), egress: { enabled: true, mode: "socks" }, custodyV2, backend: new HyperVPartitionBackend({ launcher }),
    judgeReady: async () => { throw new Error("no relay is served in this fixture: readiness is never judged"); } });
  await startManager(m);
  const server = createServer(m);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  return { m, base: `http://127.0.0.1:${server.address().port}`, server };
}
const view = async (base, id) => (await fetch(`${base}/vms/${id}`)).json();
async function awaiting(base, id, ms = 5000) {
  const end = Date.now() + ms;
  for (;;) { const v = await view(base, id); if (v.awaitingCustodyAuth?.length) return v.awaitingCustodyAuth; if (Date.now() > end) throw new Error(`no request pending on ${id}`); await tick(); }
}
async function callback(base, vmId, body, { key = KEY, header = null, path: p = `/vms/${vmId}/custody-auth` } = {}) {
  const raw = JSON.stringify(body);
  const r = await fetch(base + p, { method: "POST", body: raw, headers: { "content-type": "application/json",
    [CUSTODY_CALLBACK_HEADER]: header ?? custodyCallbackHeader(key, { path: p, body: raw }) } });
  return { status: r.status, json: await r.json() };
}

test("preflight READS the 9445 service and never writes it; canStart stays false until an explicit activation registers it", async () => {
  const script = CMD.preflight({ custodyService: CUSTODY_SERVICE_GUID });
  assert.match(script, new RegExp(`Test-Path -LiteralPath '[^']*GuestCommunicationServices\\\\${CUSTODY_SERVICE_GUID}'`));
  assert.doesNotMatch(script, /New-Item|Set-Item|New-ItemProperty|Set-ItemProperty|Remove-Item|reg(\.exe)? add/i, "nothing is registered");
  const off = await managerOn(hyperv({ custodyRegistered: false }));
  const h = off.m.health();
  assert.equal(h.canStart, false);
  // the direct image's own checks, beside the legacy image's (ImageLauncher prefixes them)
  const row = h.preflight.checks.find((c) => c.name === `shield-direct image: ${CUSTODY_CHECK}`);
  assert.equal(row.ok, false); assert.match(row.detail, /NOT registered.*explicit activation step/);
  const on = await managerOn(hyperv());
  assert.equal(on.m.health().canStart, true);
  assert.equal(on.m.health().supports.custodyV2, true);
  assert.deepEqual(on.m.health().custody, { protocol: "custody-auth-v2", vsockPort: 9445, imageSha256: IMG_SHA,
                                            scope: ["enclave-catalog-bundle/6", "enclave-catalog-bundle/7"], callback: "hmac-sha256/v1" });
});

test("lifecycle: a V6 custody partition asks once, the node re-verifies and signs, and the guest reads exactly ReadAuth's line", async (t) => {
  t.after(reap());
  const h = hyperv();
  const { m, base } = await managerOn(h);
  const A = custodySpawn(DEP_A, VAULT_A);
  const rec = await m.spawn(A.body);
  assert.equal(rec.status, "starting", rec.reason);
  assert.deepEqual(rec.custody, { protocol: "custody-auth-v2", vault: VAULT_A, imageSha256: IMG_SHA });
  assert.deepEqual(rec.awaitingCustodyAuth, []);
  const bridgeCall = spawned.find((s) => s.args[0] === VM_A);
  assert.deepEqual(bridgeCall.args, [VM_A, "9445", bridgeCall.args[2], "0", "--worker-auth-stdin"], "THIS partition's 9445 service, to its own loopback channel, its credential on stdin");
  assert.ok(!bridgeCall.args.some((a) => /^[0-9a-f]{64}$/.test(a) || a.includes("enclave-bridge-auth")), "no credential in argv");
  assert.ok(h.seen.indexOf("startAndRead") < h.seen.length, "after the VM runs");
  const guest = await guestPortOf(VM_A);

  // the node's side: its own records and a stub of the fresh startup + lease verdict (materialize, tested elsewhere)
  const records = new Map([[DEP_A, { id: DEP_A, status: "provisioning", startup: A.startup }]]);
  const verified = [], sessions = [];
  const pump = createShieldCustody({ base, callbackKey: KEY, endpoint: ENDPOINT, sign, records: () => records,
    verify: async (id) => { verified.push(id); return { ok: true, startup: A.startup }; },
    ensureSessions: async (s) => { sessions.push(custodianSessionTargets([{ status: "provisioning", startup: s }])); } });
  assert.deepEqual(await pump.pass(), { answered: [], refused: [], waiting: [] }, "nothing asked, nothing signed");
  assert.deepEqual(verified, []);

  const binding = crypto.randomBytes(32).toString("hex");
  const asked = guestAsk(guest, { from: VM_A, line: requestLine(VAULT_A, DEP_A, binding) });
  const [p] = await awaiting(base, rec.id);
  assert.equal(p.binding, binding); assert.equal(p.id, DEP_A); assert.equal(p.vault, VAULT_A);
  const r = await pump.pass();
  assert.equal(r.answered.length, 1, JSON.stringify(r));
  assert.deepEqual(verified, [DEP_A], "re-verified at the moment it signs");
  assert.deepEqual(sessions, [[{ url: "https://custodian-1.example/c", party: "11".repeat(32), path: "/v2/custody/shield-session" }]],
                   "this package's custodians' sessions refreshed first: each challenges this node itself");
  const auth = readAuth(await asked);
  assert.equal(auth.endpoint, ENDPOINT);
  assert.ok(await verifyMessage({ address: OPERATOR.address, message: custodyOperatorMessageV2({ chainId: 8453, vault: VAULT_A, id: DEP_A, endpoint: ENDPOINT, binding, expiry: auth.expiry }), signature: auth.sig }),
            "the operator's personal_sign over custody v2's exact message, for THIS vault, deployment and binding");
  assert.ok(auth.expiry > Date.now() / 1000 && auth.expiry <= Date.now() / 1000 + 300);
  assert.deepEqual((await view(base, rec.id)).awaitingCustodyAuth, []);
  assert.deepEqual((await pump.pass()).answered, [], "never signed twice");
  // the shared session list also carries the custodians, beside any responder
  assert.deepEqual(sessionTargets([{ status: "running", startup: A.startup }]).map((t) => t.party), ["11".repeat(32)]);

  // ---- cross-deployment, cross-vault, v1 and cross-VM requests on A's channel: never listed, never answered
  for (const line of [requestLine(VAULT_A, DEP_B, binding), requestLine(VAULT_B, DEP_A, binding), `custody-auth-v1 ${DEP_A} ${binding}\n`])
    assert.equal(await within(guestAsk(guest, { from: VM_A, line })), "", line);
  assert.equal(await within(guestAsk(guest, { from: VM_B, line: requestLine(VAULT_A, DEP_A, binding) })), "", "another partition's peer (FIXTURE: the real bridge's VmId check)");
  assert.ok(events().some((e) => e.vm === VM_A && e.event === "foreign-peer"));
  assert.deepEqual((await view(base, rec.id)).awaitingCustodyAuth, []);

  // ---- a second partition (B): its request is answerable only on B, and only by a node that verified B
  const B = custodySpawn(DEP_B, VAULT_B);
  const recB = await m.spawn(B.body);
  const guestB = await guestPortOf(VM_B);
  const askedB = guestAsk(guestB, { from: VM_B, line: requestLine(VAULT_B, DEP_B, binding) });
  const [pB] = await awaiting(base, recB.id);
  const now = Math.floor(Date.now() / 1000);
  const answerB = { request: pB.request, binding, endpoint: ENDPOINT, sig: "0x" + "ab".repeat(65), expiry: now + 300 };
  assert.equal((await callback(base, rec.id, answerB)).status, 409, "B's request is not pending on A's channel");
  // A's pointer with B's record or partition: the node refuses (records holds no verified startup for B)
  const r2 = await pump.pass();
  assert.equal(r2.answered.length, 0); assert.match(r2.refused.join(" "), /holds no verified owner-committed startup/);
  // and a caller that mixes A's verified startup into B's record is refused before signing
  records.set(DEP_B, { id: DEP_B, status: "provisioning", startup: B.startup });
  const mixed = createShieldCustody({ base, callbackKey: KEY, endpoint: ENDPOINT, sign, records: () => new Map([[DEP_B, { id: DEP_B, status: "provisioning", startup: A.startup }]]),
    verify: async () => ({ ok: true, startup: A.startup }) });
  const r3 = await mixed.pass();
  assert.equal(r3.answered.length, 0); assert.match(r3.refused.join(" "), /not the package this partition was spawned with/);
  const liar = createShieldCustody({ base, callbackKey: KEY, endpoint: ENDPOINT, sign, records: () => records,
    verify: async () => ({ ok: true, startup: { ...A.startup, deployment: DEP_B, sha256: B.startup.sha256 } }) });
  const r4 = await liar.pass();
  assert.equal(r4.answered.length, 0); assert.match(r4.refused.join(" "), /another vault|does not run the verified package|committed/);
  assert.equal((await view(base, recB.id)).awaitingCustodyAuth.length, 1, "still unanswered");
  // an unknown verdict (a lease not yet visible) waits and is asked again; it is never answered meanwhile
  const waiting = createShieldCustody({ base, callbackKey: KEY, endpoint: ENDPOINT, sign, records: () => records, retryMs: 0,
    verify: async () => ({ ok: false, unknown: true, why: "this host does not hold a live lease at block 9" }) });
  const r5 = await waiting.pass();
  assert.equal(r5.waiting.length, 1); assert.equal(r5.answered.length, 0);

  // ---- the callback: forged, replayed, stale, tampered or misdirected answers are refused BEFORE any lookup
  const raw = JSON.stringify(answerB), pathB = `/vms/${recB.id}/custody-auth`;
  const good = custodyCallbackHeader(KEY, { path: pathB, body: raw });
  assert.equal((await callback(base, recB.id, answerB, { key: crypto.randomBytes(32) })).status, 401, "another key");
  assert.equal((await callback(base, recB.id, answerB, { header: "" })).status, 401, "no authentication");
  assert.equal((await callback(base, recB.id, { ...answerB, binding: "00".repeat(32) }, { header: good })).status, 401, "a body other than the one authenticated");
  assert.equal((await callback(base, recB.id, answerB, { header: custodyCallbackHeader(KEY, { path: pathB, body: raw, now: Date.now() - 120_000 }) })).status, 401, "stale");
  assert.equal((await callback(base, "hvnotthere", answerB, { header: custodyCallbackHeader(KEY, { path: pathB, body: raw }) })).status, 401, "authenticated for another path: 401, not 404");
  assert.equal((await callback(base, recB.id, answerB, { header: good })).status, 200, "the authenticated answer");
  assert.equal((await callback(base, recB.id, answerB, { header: good })).status, 401, "the same callback again: a replay");
  assert.equal(readAuth(await askedB).sig, answerB.sig);

  // ---- failure closes channels: B's partition stops by itself (the liveness sweep), and its channel closes with it
  const pendingB = guestAsk(guestB, { from: VM_B, line: requestLine(VAULT_B, DEP_B, binding) });
  await awaiting(base, recB.id);
  const surveyed = { vms: [{ vmId: VM_A, name: "a", state: "Running" }, { vmId: VM_B, name: "b", state: "Off" }] };
  m.backend.survey = async () => surveyed;
  assert.deepEqual(await m.sweepLiveness(), { checked: 2, failed: 1 });
  assert.equal(m.get(recB.id).status, "failed");
  assert.equal(await pendingB, "", "the pending request is dropped unanswered");
  await until(() => events().some((e) => e.vm === VM_B && e.event === "stdin-eof"), "B's bridge to end");
  assert.deepEqual(m.get(recB.id).awaitingCustodyAuth, []);
  assert.equal((await callback(base, recB.id, answerB)).status, 409, "a failed domain is never authorized again");

  // ---- a stop closes everything: A removed, its bridge gone, its guest port refuses
  assert.equal((await fetch(`${base}/vms/${rec.id}`, { method: "DELETE" })).status, 200);
  await until(() => events().some((e) => e.vm === VM_A && e.event === "stdin-eof"), "A's bridge to end");
  assert.ok(stopped.includes(`egress ${VM_A}`) && stopped.includes(`package ${VM_A}`));
  await assert.rejects(guestAsk(guest, { from: VM_A, line: requestLine(VAULT_A, DEP_A, binding) }), /ECONNREFUSED/);
  assert.equal((await callback(base, rec.id, answerB)).status, 404, "a removed domain has no channel");
  delete m.backend.survey;
  await fetch(`${base}/vms/${recB.id}`, { method: "DELETE" });
});

test("failure: a custody bridge that dies fails its domain at once; one that cannot start fails the start and removes the VM", async (t) => {
  t.after(reap());
  const h = hyperv({ vmIds: [VM_C] });
  const { m, base } = await managerOn(h);
  const C = custodySpawn(DEP_C, VAULT_A);
  const rec = await m.spawn(C.body);
  const guest = await guestPortOf(VM_C);
  const pending = guestAsk(guest, { from: VM_C, line: requestLine(VAULT_A, DEP_C, "33".repeat(32)) });
  await awaiting(base, rec.id);
  const reclaimed = []; m.onReclaim = (id, why) => reclaimed.push(why);
  // the bridge process ends on its own (a crash): stdin is still open, so this is NOT a stop
  spawned.filter((x) => x.args[0] === VM_C).pop().child.kill("SIGKILL");     // the bridge crashes; nothing stopped it
  await until(() => m.get(rec.id).status === "failed", "the domain to fail");
  assert.match(m.get(rec.id).reason, /custody transport exited/);
  assert.deepEqual(reclaimed, ["the custody transport exited"]);
  assert.equal(await pending, "", "nothing pending survives its channel");
  assert.deepEqual(m.get(rec.id).awaitingCustodyAuth, []);
  await fetch(`${base}/vms/${rec.id}`, { method: "DELETE" });
  // a bridge that refuses to bind (10013: the service is not registered) fails the start; the VM is removed by its Id
  bridgeMode = "exit";
  try {
    const before = h.seen.filter((k) => k === "removeById").length;
    const bad = await m.spawn(C.body);
    assert.equal(bad.status, "failed"); assert.match(bad.reason, /custody bridge exited \(2\)/);
    assert.equal(h.seen.filter((k) => k === "removeById").length, before + 1);
  } finally { bridgeMode = "ok"; }
});

test("restart: a killed manager takes its bridges with it, and a restarted one recovers the VM with no channel and no request", async (t) => {
  // the manager process dies (SIGKILL: no stop runs); its bridge child sees stdin end and exits
  const code = `import { startCustodyTransport } from ${JSON.stringify(path.join(HERE, "../windows/vbslike/manager/custody-transport.mjs"))};
    import { spawn } from "node:child_process";
    await startCustodyTransport({ bridge: ${JSON.stringify(BRIDGE)}, vmId: ${JSON.stringify(VM_A)}, deploymentId: ${JSON.stringify(DEP_A)}, vault: ${JSON.stringify(VAULT_A)},
      spawn: (f, a, o) => spawn(${JSON.stringify(PYTHON)}, [${JSON.stringify(FAKE_BRIDGE)}, ...a], { ...o, env: { ...process.env, FAKE_CUSTODY_LOG: ${JSON.stringify(LOG)} } }) });
    process.stdout.write("up\\n"); setInterval(() => {}, 1 << 30);`;
  const before = events().filter((e) => e.vm === VM_A && e.event === "stdin-eof").length;
  const mgr = nodeSpawn(process.execPath, ["--input-type=module", "-e", code], { stdio: ["ignore", "pipe", "inherit"] });
  t.after(() => { if (mgr.exitCode === null && mgr.signalCode === null) mgr.kill("SIGKILL"); });
  await new Promise((r) => mgr.stdout.once("data", r));
  mgr.kill("SIGKILL");
  await until(() => events().filter((e) => e.vm === VM_A && e.event === "stdin-eof").length > before, "the orphaned bridge to exit", 8000);
  // the restarted manager: the VM is still on the host (its Notes name it), recovered, never served, with no channel
  const notes = notesFor({ id: "hv" + "a".repeat(32), name: DEP_A, instanceId: "hvaaaaaaaaaaaaaa-0feeba61", appId: "0f".repeat(32), imageRole: "shield-direct" });
  const h = hyperv({ survey: () => ({ vms: [{ vmId: VM_A, name: "enclave-app-t-hvaaaaaaaaaaaaaa-0feeba61", state: "Running", notes }] }) });
  const { m, base } = await managerOn(h);
  const v = m.list().find((r) => r.name === DEP_A);
  assert.equal(v.recovered, true); assert.equal(v.custody, undefined); assert.equal(v.awaitingCustodyAuth, undefined);
  assert.equal(v.imageRole, "shield-direct", "its image comes back from the VM's Notes");
  const now = Math.floor(Date.now() / 1000);
  assert.equal((await callback(base, v.id, { request: "ab".repeat(16), binding: "11".repeat(32), endpoint: ENDPOINT, sig: "0x" + "ab".repeat(65), expiry: now + 60 })).status, 404);
  await assert.rejects(m.spawn(custodySpawn(DEP_A, VAULT_A).body), (e) => e.status === 409, "the recovered VM blocks a second spawn; the node retires it first");
});

// ---- 3. what the gate admits, and what stays exactly as it was ----------------------------------------------------------
test("the gate: custody only on V6/V7 with a custody-v2 package naming its vault and the measured config; legacy is unchanged", async () => {
  const h = hyperv();
  const { m } = await managerOn(h, { launcher: { start: async () => { throw new Error("no start in this test"); }, preflight: async () => ({ ok: true, checks: [] }) } });
  const seen = [];
  m.backend = new HyperVPartitionBackend({ launch: async (mapping, opts) => { seen.push(opts); return { stop: async () => {},
    ...(opts.bootstrap ? { imageRole: "shield-direct", firmware: { sha256: IMG_SHA } } : { imageRole: "legacy", firmware: { sha256: LEGACY_SHA } }),
    custody: { pending: () => [], answer: () => ({}), stop: async () => {}, exited: new Promise(() => {}) } }; } });
  await m.spawn(custodySpawn(DEP_A, VAULT_A).body);
  assert.deepEqual(seen.pop().custody, { deployment: DEP_A, vault: VAULT_A }, "the launcher is told the deployment and vault");
  const refusedOn = async (mgr, b, re) => { const n = seen.length; await assert.rejects(mgr.spawn(b), re); assert.equal(seen.length, n, "nothing launched"); };
  // a public package on a secret spawn; a custody package with another config; a nameless vault
  await refusedOn(m, custodySpawn(DEP_B, VAULT_A, { secretsMode: "public" }).body, /must keep its secrets in custody-v2/);
  await refusedOn(m, custodySpawn(DEP_B, VAULT_A, { configText: '{ "api": "https://api.example" }' }).body, /another config than this spawn measures/);
  await refusedOn(m, custodySpawn(DEP_B, "0x" + "C1".repeat(20)).body, /name its vault/);
  // a secret spawn whose name is not its secret deployment
  const x = custodySpawn(DEP_B, VAULT_A);
  await refusedOn(m, { ...x.body, derive: { ...x.body.derive, secretDeployment: DEP_C } }, /secret deployment differs|custody-v2 secret deployment/);
  // a custody-v2 package on a public V1 spawn
  const v1 = { image: `ipfs://${REC.cid}`, name: DEP_C, cpuShare: 0.1, gpuShare: 0, appPort: 8080, ports: [], config: "", configCid: "", egress: "", derive: REC, isPublic: true, hasSecrets: false };
  const v1custody = preparePackage({ version: 1, chainId: 8453, ledger: "0x" + "d0".repeat(20), deployment: DEP_C, owner: "0x" + "33".repeat(20), appRef: `catalog://${REC.catalog.app}/${REC.catalog.version}`,
    appId: VEC.ok[0].mapping.appId, runtimeId: REC.runtimeId, configText: "", secretsMode: "custody-v2", custody: { v: 2, chainId: 8453, vault: VAULT_A } });
  await refusedOn(m, { ...v1, bootstrap: v1custody.bytes.toString("base64") }, /keeps secrets in custody, and this spawn is a public deployment/);
  // LEGACY: a public V1 package and a plain V1 spawn are as before: no custody opts, no channel, no new view field
  const v1public = preparePackage({ version: 1, chainId: 8453, ledger: "0x" + "d0".repeat(20), deployment: DEP_C, owner: "0x" + "33".repeat(20), appRef: `catalog://${REC.catalog.app}/${REC.catalog.version}`,
    appId: VEC.ok[0].mapping.appId, runtimeId: REC.runtimeId, configText: "", secretsMode: "public" });
  const pub = await m.spawn({ ...v1, bootstrap: v1public.bytes.toString("base64") });
  assert.equal(seen.pop().custody, undefined); assert.equal(pub.custody, undefined); assert.equal("awaitingCustodyAuth" in pub, false);
  const plain = await m.spawn({ ...v1, name: DEP_B });
  assert.equal(seen.pop().bootstrap, undefined); assert.equal("awaitingCustodyAuth" in plain, false);
  // a manager without direct custody: the old refusal, word for word, and supports.custodyV2 false
  const { m: legacy } = await managerOn(hyperv(), { custodyV2: null });
  assert.equal(legacy.health().supports.custodyV2, false); assert.equal(legacy.health().custody, null);
  await assert.rejects(legacy.spawn(custodySpawn(DEP_A, VAULT_A).body), /an owner-committed package starts only a public CPU deployment with no secrets \(enclave-catalog-bundle\/1 or \/5\)$/);
  // a half configuration is refused, never served in part
  for (const [over, re] of [[{ directBootstrap: false }, /directBootstrap/], [{ secretsEnabled: false }, /secrets/], [{ egress: null }, /egress/],
                            [{ custodyV2: { imageSha256: "x", callbackKey: KEY } }, /custody image/], [{ custodyV2: { imageSha256: IMG_SHA, callbackKey: Buffer.alloc(16) } }, /callback key/],
                            // F3: custody only on the pinned Shield-direct image, which needs its own pins and is never the legacy one relabelled
                            [{ custodyV2: { imageSha256: LEGACY_SHA, callbackKey: KEY } }, /custody image to be the pinned Shield-direct image/],
                            [{ images: null }, /its own pinned Shield-direct image/],
                            [{ images: { shieldDirect: { igvmSha256: IMG_SHA } } }, /its own pinned Shield-direct image/],
                            [{ images: { legacy: { igvmSha256: IMG_SHA }, shieldDirect: { runtimeId: REC.runtimeId, igvmSha256: IMG_SHA } } }, /distinct from the legacy image/]])
    assert.throws(() => new Manager({ directBootstrap: true, configEnabled: true, secretsEnabled: true, fetchConfig: async () => Buffer.from("{}"), egress: { enabled: true, mode: "socks" },
                                      images: { legacy: { igvmSha256: LEGACY_SHA }, shieldDirect: { runtimeId: REC.runtimeId, igvmSha256: IMG_SHA } },
                                      custodyV2: { imageSha256: IMG_SHA, callbackKey: KEY }, ...over }), re);
  // the launcher image is not the stated one: a custody spawn fails and its channel is closed
  const closed = [];
  let stated = { imageRole: "shield-direct", firmware: { sha256: "00".repeat(32) } };
  m.backend = new HyperVPartitionBackend({ launch: async () => ({ stop: async () => {}, ...stated,
    custody: { pending: () => [], answer: () => ({}), stop: async () => { closed.push("custody"); }, exited: new Promise(() => {}) } }) });
  const wrong = await m.spawn(custodySpawn("0x" + "ea".repeat(32), VAULT_A).body);
  assert.equal(wrong.status, "failed"); assert.match(wrong.reason, /not the pinned Shield-direct image/);
  await tick(); assert.deepEqual(closed, ["custody"]);
  // ...and a launcher that started it on another image (the legacy one, with the SAME RuntimeID): failed, channel closed
  stated = { imageRole: "legacy", firmware: { sha256: IMG_SHA } };
  const other = await m.spawn(custodySpawn("0x" + "eb".repeat(32), VAULT_A).body);
  assert.equal(other.status, "failed"); assert.match(other.reason, /on the legacy image, not the Shield-direct one/);
  await tick(); assert.deepEqual(closed, ["custody", "custody"]);
});

test("the launcher refuses a custody start it cannot honour before ANY PowerShell runs", async () => {
  const run = async () => { throw new Error("no PowerShell may run for a refused start"); };
  const m6 = { appId: "aa".repeat(32), record: { policy: { vcpus: 1, memMiB: 512 } } };
  const opts = { instanceId: "dep0001-aaaa", identity: { id: "hv1", name: DEP_A, appId: "aa".repeat(32) }, bootstrap: Buffer.from("{}"), custody: { deployment: DEP_A, vault: VAULT_A } };
  const base = { run, imagePath: "C:\\x.bin", imageSha256: IMG_SHA, ...TYPE1, startEgress: async () => ({}), startPackage: async () => ({}), imageRole: "shield-direct" };
  await assert.rejects(new WmiHyperVLauncher(base).start(m6, opts), /custody transport/);
  await assert.rejects(new WmiHyperVLauncher({ ...base, startCustody: async () => ({}) }).start(m6, opts), /custody build/);
  await assert.rejects(new WmiHyperVLauncher({ ...base, startCustody: async () => ({}), custodyImageSha256: "ee".repeat(32) }).start(m6, opts), /custody build/);
  await assert.rejects(new WmiHyperVLauncher({ ...base, startCustody: async () => ({}), custodyImageSha256: IMG_SHA }).start(m6, { ...opts, custody: { deployment: DEP_B, vault: VAULT_A } }), /another deployment/);
  await assert.rejects(new WmiHyperVLauncher({ ...base, startCustody: async () => ({}), custodyImageSha256: IMG_SHA }).start(m6, { ...opts, bootstrap: null }), /starts only owner-committed packages/);
  // a legacy launcher never takes a custody channel (nor a package), whatever it was given
  assert.throws(() => new WmiHyperVLauncher({ ...base, imageRole: "legacy", startCustody: async () => ({}) }), /only the Shield-direct image carries/);
  assert.throws(() => new WmiHyperVLauncher({ ...base, custodyService: "9445" }), /custodyService must be a service GUID/);
  assert.throws(() => new WmiHyperVLauncher({ ...base, startCustody: "yes" }), /startCustody must be a function/);
  // the transport itself: a wrong pin or a non-partition id starts nothing
  const n = spawned.length;
  await assert.rejects(startCustodyTransport({ bridge: { ...BRIDGE, sha256: "00".repeat(32) }, vmId: VM_A, deploymentId: DEP_A, vault: VAULT_A, spawn: spawnBridge }), /not its pin/);
  await assert.rejects(startCustodyTransport({ bridge: BRIDGE, vmId: "00000000-0000-0000-0000-000000000000", deploymentId: DEP_A, vault: VAULT_A, spawn: spawnBridge }), /not a partition id/);
  assert.equal(spawned.length, n);
});

// ---- 4. the entry point and the relay-secrets courier ---------------------------------------------------------------------
/** Run the real manager entry point (main.mjs) with an environment, bounded. */
function runMain(env, ms = 4000) {
  return new Promise((resolve) => {
    const p = nodeSpawn(process.execPath, [path.join(HERE, "../windows/vbslike/manager/main.mjs")],
      { env: { ...process.env, VMMGR_PORT: "0", ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => { out += d; }); p.stderr.on("data", (d) => { err += d; });
    const timer = setTimeout(() => { p.kill(); resolve({ code: null, out, err, timedOut: true }); }, ms);
    p.on("close", (code) => { clearTimeout(timer); resolve({ code, out, err, timedOut: false }); });
  });
}
test("main.mjs: direct custody is all-or-nothing, bound to the pinned image, with a private callback key; nothing is registered", async () => {
  const egressExe = path.join(dir, "shield-egress.exe"), identity = path.join(dir, "runtime.json"), keyFile = path.join(dir, "callback.key");
  fs.writeFileSync(egressExe, "shield-egress bytes (fixture)");
  fs.writeFileSync(identity, JSON.stringify({ name: "wasmtime", version: "48.0.1", execution: "jit", targetIsa: "x86_64", hostIsa: "x86_64", cpuFeatures: "baseline", wx: "enforced", cache: "none" }));
  fs.writeFileSync(keyFile, crypto.randomBytes(32).toString("hex"), { mode: 0o600 });
  const base = { ENCLAVE_RUNTIME_IDENTITY: identity, ENCLAVE_EGRESS_V1: "1", ENCLAVE_EGRESS_EXE: egressExe, ENCLAVE_EGRESS_EXE_SHA256: sha(fs.readFileSync(egressExe)),
                 ENCLAVE_EGRESS_BRIDGE_EXE: BRIDGE.exe, ENCLAVE_EGRESS_BRIDGE_EXE_SHA256: BRIDGE.sha256, ENCLAVE_EGRESS_SOCKS: "127.0.0.1:30489",
                 ENCLAVE_SHIELD_DIRECT: "1", ENCLAVE_CONFIG_BUNDLE_V5: "1", ENCLAVE_SECRETS_V1: "1",
                 ENCLAVE_GUEST_IGVM: "C:\\enclave\\legacy.igvm", ENCLAVE_GUEST_IGVM_SHA256: LEGACY_SHA, ENCLAVE_BOOT_FORM: "linux-direct",
                 ENCLAVE_SHIELD_DIRECT_IGVM: "C:\\enclave\\shield-custody.igvm", ENCLAVE_SHIELD_DIRECT_IGVM_SHA256: IMG_SHA, ENCLAVE_SHIELD_DIRECT_RUNTIME_IDENTITY: identity,
                 ENCLAVE_SHIELD_CUSTODY_V2: "1", ENCLAVE_SHIELD_CUSTODY_IMAGE_SHA256: IMG_SHA, ENCLAVE_CUSTODY_CALLBACK_KEY_FILE: keyFile };
  const half = await runMain({ ...base, ENCLAVE_SHIELD_DIRECT: "", ENCLAVE_SECRETS_V1: "", ENCLAVE_CUSTODY_CALLBACK_KEY_FILE: "" });
  assert.equal(half.code, 2, half.err);
  assert.match(half.err, /REFUSING TO START: ENCLAVE_SHIELD_CUSTODY_V2=1 needs ENCLAVE_SHIELD_DIRECT=1, ENCLAVE_SECRETS_V1=1, ENCLAVE_SHIELD_CUSTODY_IMAGE_SHA256 equal to the pinned ENCLAVE_SHIELD_DIRECT_IGVM_SHA256, ENCLAVE_CUSTODY_CALLBACK_KEY_FILE/);
  const otherImage = await runMain({ ...base, ENCLAVE_SHIELD_CUSTODY_IMAGE_SHA256: "ee".repeat(32) });
  assert.equal(otherImage.code, 2); assert.match(otherImage.err, /ENCLAVE_SHIELD_CUSTODY_IMAGE_SHA256 equal to the pinned ENCLAVE_SHIELD_DIRECT_IGVM_SHA256/);
  const legacyImage = await runMain({ ...base, ENCLAVE_SHIELD_CUSTODY_IMAGE_SHA256: LEGACY_SHA });
  assert.equal(legacyImage.code, 2, "custody is never stated on the legacy image"); assert.match(legacyImage.err, /equal to the pinned ENCLAVE_SHIELD_DIRECT_IGVM_SHA256/);
  fs.chmodSync(keyFile, 0o644);
  const shared = await runMain(base);
  assert.equal(shared.code, 2); assert.match(shared.err, /callback key file .* it is not private: mode 644 lets others read it/);
  fs.chmodSync(keyFile, 0o600);
  const on = await runMain(base);
  assert.ok(on.timedOut, `complete, it runs: exited ${on.code}: ${on.err.slice(0, 300)}`);
  assert.match(on.out, new RegExp(`direct Shield custody ON for image ${IMG_SHA}`));
  assert.doesNotMatch(on.out + on.err, new RegExp(fs.readFileSync(keyFile, "utf8").trim()), "the key is never printed");
  const off = await runMain({ ...base, ENCLAVE_SHIELD_CUSTODY_V2: "" });
  assert.ok(off.timedOut); assert.doesNotMatch(off.out, /direct Shield custody ON/, "off by default");
});

test("the relay-staged secrets courier never serves an owner-committed (direct) domain; other secret domains are unchanged", async () => {
  const { createShieldSecrets } = await import("../windows/node/shield-secrets.mjs");
  const relayed = [];
  const vm = (over) => ({ id: "hv" + "1".repeat(32), name: DEP_A, secretDeployment: DEP_A, status: "starting", relay: { host: "127.0.0.1", port: 9 }, ...over });
  const courier = (vms) => createShieldSecrets({ base: "http://127.0.0.1:1", endpoint: ENDPOINT, relayBase: "https://relay.example", sign, egressReady: async () => true,
    fetchImpl: async (url) => {
      if (String(url).endsWith("/vms")) return new Response(JSON.stringify({ vms }), { status: 200 });
      relayed.push(String(url)); return new Response(JSON.stringify({ ok: true, count: 1 }), { status: 200 });
    } });
  await courier([vm({ directBootstrap: true })]).pass();
  assert.deepEqual(relayed, [], "a direct custody guest opens its own secrets");
  await assert.rejects(courier([vm({ directBootstrap: true })]).install({ id: DEP_A }), /not reachable/);
  await courier([vm({ directBootstrap: false })]).pass();
  assert.deepEqual(relayed, ["https://relay.example/v1/secrets/shield-release"], "a relay-sealed secret domain is served as before");
});
