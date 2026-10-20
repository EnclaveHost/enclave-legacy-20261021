// Owner-committed startup on an independent Windows Shield host (windows/node/shield-startup.mjs, wired through
// windows/node/host.mjs): the package is fetched from the operator's own replicas, verified against a fresh agreeing
// quorum on the PINNED ledger and catalog, bound to the current owner and this host's RuntimeID, and its AppID is the one
// the manager's own rule derives - or nothing is claimed or started. The Host and the partition manager are the real ones
// (the manager over a faked Hyper-V); no Enclave endpoint is reachable, and any attempt to reach one is recorded and fails.
//   run: node --test test/windows-shield-startup.test.mjs
import { test, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { fakeBaseRpc, DEPLOYMENTS, CATALOG, enclaveIdOf } from "./helpers/fake-base-rpc.mjs";
import { REC, FakeHost, FakeLauncher, closeManagers } from "./helpers/hv-fake-manager.mjs";
import { servedOwner } from "./helpers/owners.mjs";

process.env.NODE_OPERATOR_KEY = "0x" + "7f".repeat(32);
const rpc = await fakeBaseRpc();
const chain = await import("../windows/node/chain.mjs");
chain.addresses.deployments = DEPLOYMENTS;
chain.addresses.appCatalog = CATALOG;
chain.loadOperator();
const { Host } = await import("../windows/node/host.mjs");
const { createShieldStartup, shieldStartupEnvelope, startupAdoptionRefusal, startupGateways } = await import("../windows/node/shield-startup.mjs");
const { quorumReader } = await import("../windows/node/host-identity.mjs");
const { preparePackage, packageCID } = await import("../sdk/bootstrap/package.mjs");
const { derive } = await import("../windows/vbslike/manager/derive.mjs");
const { Manager, createServer, startManager } = await import("../windows/vbslike/manager/server.mjs");
const { HyperVPartitionBackend } = await import("../windows/vbslike/manager/backend.mjs");
const { ImageLauncher } = await import("../windows/vbslike/manager/shield-profile.mjs");
const { ownerCommittedDomains } = await import("../windows/node/domains.mjs");
const { custodyAuthorization, custodyOperatorMessageV2 } = await import("../windows/node/secrets.mjs");

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VEC = JSON.parse(fs.readFileSync(path.join(HERE, "../isolation/contract/catalog/derive_vectors.json"), "utf8"));
const COMPONENT = Buffer.from(VEC.component_hex, "hex");
const ENDPOINT = "https://box.example.org";
const HOST_ID = enclaveIdOf(ENDPOINT);
const OPERATOR = chain.operatorAddress().toLowerCase();
const OTHER = "0x" + "5a".repeat(20);
const DEP = "0x" + "e7".repeat(32);
const APPREF = `catalog://${REC.catalog.app}/${REC.catalog.version}`;
const GATEWAY = "https://replica-a.example/ipfs";
const ZERO32 = "0x" + "00".repeat(32);
const OTHER_DEP = "0x" + "e8".repeat(32);
// this node's own pins for the Shield-direct image (F3): the RuntimeID equals the legacy one, the IGVM hash does not
const DIRECT_IMG = "d1".repeat(32);
const DIRECT_PIN = { runtimeId: REC.runtimeId, imageSha256: DIRECT_IMG };

// ---- every outbound request goes through here: Enclave origins are blocked and recorded ---------------------------------
const enclaveHits = [], packageHits = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  const u = String(url);
  if (/(^|\.)enclave\.host(\/|:|$)/.test(new URL(u).hostname + "/")) { enclaveHits.push(u); throw new Error(`blocked Enclave endpoint ${u}`); }
  return realFetch(url, opts);
};
const packages = new Map();                       // cid -> bytes, what the operator's replica serves
const replicaFetch = async (url) => {
  const u = new URL(String(url));
  if (/enclave\.host$/.test(u.hostname)) { enclaveHits.push(String(url)); throw new Error("blocked"); }
  packageHits.push(String(url));
  const bytes = u.origin + "/ipfs" === GATEWAY ? packages.get(u.pathname.split("/").pop()) : null;
  return bytes ? new Response(bytes, { status: 200 }) : new Response("no", { status: 404 });
};

// ---- the chain as two-plus independent RPCs see it, per block ----------------------------------------------------------
const VERSION = { cid: REC.cid, version: "1.0.0", vramMb: 0, gpuGflops: 0, memMb: REC.policy.memMiB, cpuGflops: 0, createdAt: 1n,
                  verified: true, yanked: false, ports: "", approval: 1, config: "{}" };
rpc.catalog.current = VERSION;
const state = { row: null, version: VERSION, stale: false, disagree: false, head: 1000n };
function fakeClient(i) {
  return {
    transport: { url: `https://rpc-${i}.example` },                // one host per peer (host-identity.mjs counts hosts)
    getChainId: async () => 8453,
    getBlockNumber: async () => state.head,
    getBlock: async ({ blockNumber }) => ({ number: BigInt(blockNumber), hash: "0x" + BigInt(blockNumber).toString(16).padStart(64, "0"),
      timestamp: BigInt(Math.floor(Date.now() / 1000) - (state.stale ? 3600 : 2)) }),
    readContract: async ({ address, functionName, args, blockNumber }) => {
      assert.equal(typeof blockNumber, "bigint", "every startup read names its block");
      if (functionName === "get") {
        assert.equal(address, DEPLOYMENTS); assert.equal(args[0], DEP);
        return state.disagree ? { ...state.row, owner: "0x" + String(i + 1).repeat(40) } : state.row;
      }
      if (functionName === "getVersion") { assert.equal(address, CATALOG); return state.version; }
      throw new Error("unexpected read " + functionName);
    },
  };
}
const reader = () => quorumReader({ clients: [fakeClient(0), fakeClient(1), fakeClient(2)], maxBlockAgeMs: 90_000 });
const componentFetches = [];
const authority = (over = {}) => createShieldStartup({ reader: reader(), pins: { deployments: DEPLOYMENTS, appCatalog: CATALOG },
  gateways: [GATEWAY], fetchImpl: replicaFetch, fetchComponent: async (cid) => { componentFetches.push(cid); assert.equal(cid, REC.cid); return COMPONENT; },
  abis: { DEP_ABI: chain.DEP_ABI, CATALOG_ABI: chain.CATALOG_ABI }, direct: DIRECT_PIN, ...over });

// ---- the owner's side: the package and its envelope --------------------------------------------------------------------
const envelopeFor = (intent, require = "hyperv-partition-per-app", extra = {}) =>
  JSON.stringify({ isolation: { require }, guestBootstrap: intent, ...extra });
const recordFor = (configText) => configText && configText !== "{}"
  ? { ...REC, derivation: "enclave-catalog-bundle/5", config: JSON.stringify(JSON.parse(configText)) } : REC;
function ownerPackage({ configText = "", owner = OPERATOR, appId, runtimeId = REC.runtimeId, secretsMode = "public", custody, names } = {}) {
  appId ??= derive({ record: recordFor(configText), component: COMPONENT }).appId;
  const p = preparePackage({ version: 1, chainId: 8453, ledger: DEPLOYMENTS, deployment: DEP, owner, appRef: APPREF, appId, runtimeId, configText,
                             secretsMode, ...(custody ? { custody } : {}), ...(names ? { names } : {}) });
  packages.set(packageCID(p.intent.sha256), p.bytes);
  return p;
}
const ledgerRow = (envelope, over = {}) => ({ id: DEP, owner: OPERATOR, appRef: APPREF, ports: "", configCid: envelope, gpuMilli: 0, cpuMilli: 100,
  appPort: 8080, isPublic: true, active: true, createdAt: 1n, rate: 1n, balance6: 10n ** 9n, spent6: 0n, runner: HOST_ID,
  runnerOperator: OPERATOR, leaseUntil: BigInt(Math.floor(Date.now() / 1000) + 3600), ...over });
function commit(pkg, over = {}) {
  const row = ledgerRow(envelopeFor(pkg.intent), over);
  state.row = row; rpc.row.current = row;
  return row;
}

// ---- a REAL manager (config-capable), over the fake Hyper-V ----------------------------------------------------------
const servers = [];
// FIXTURE: the Shield-direct image's launcher over the same fake Hyper-V, stating its role and its pinned IGVM (F3)
class DirectFakeLauncher extends FakeLauncher {
  constructor(host, igvmSha256 = DIRECT_IMG) { super(host); this.imageRole = "shield-direct"; this.igvmSha256 = igvmSha256; }
  async start(mapping, opts = {}) {
    if (!opts.bootstrap) throw new Error("the Shield-direct image starts only owner-committed packages");
    return { ...(await super.start(mapping, opts)), imageRole: "shield-direct", image: this.igvmSha256, firmware: { sha256: this.igvmSha256 } };
  }
}
async function manager({ configEnabled = true, directBootstrap = true, directImage = DIRECT_IMG } = {}) {
  const fake = new FakeHost();
  const m = new Manager({ runtimeId: REC.runtimeId, fetchComponent: async () => COMPONENT, configEnabled, directBootstrap, fetchConfig: async () => { throw new Error("no config CID here"); },
    // the same RuntimeID on both images (legal: the image hash tells them apart)
    ...(directBootstrap ? { images: { legacy: { igvmSha256: "ab".repeat(32) }, shieldDirect: { runtimeId: REC.runtimeId, igvmSha256: directImage } } } : {}),
    judgeReady: async () => ({ status: "running", transportKeySha256: "cd".repeat(32), checks: { document: { ok: true, verdict: "monitor-signed" }, ready: { ok: true } } }),
    backend: new HyperVPartitionBackend({ launcher: directBootstrap ? new ImageLauncher({ legacy: new FakeLauncher(fake), shieldDirect: new DirectFakeLauncher(fake, directImage) })
                                                                    : new FakeLauncher(fake) }) });
  await startManager(m);
  const server = createServer(m);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  return { fake, m, base: `http://127.0.0.1:${server.address().port}` };
}
after(() => { closeManagers(); rpc.close(); for (const s of servers) { s.closeAllConnections?.(); s.close(); } globalThis.fetch = realFetch; });
async function independentHost(over = {}) {
  const mgr = await manager();
  const h = servedOwner(new Host({ dir: fs.mkdtempSync(path.join(os.tmpdir(), "ee-startup-")), endpoint: ENDPOINT, name: "box", appsEnabled: true,
    cpuPricePerSec6: 12, ramGb: 64, log: () => {}, engineRetired: true, isolationManager: mgr.base, isolationRuntimeId: REC.runtimeId,
    relayBase: "", customDomains: true, ownerStartup: authority(), ...over }), OPERATOR);
  h.chainReady = true; h.registered = { endpoint: ENDPOINT, cpuPricePerSec6: 12n, gpuPricePerSec6: 0n };
  return { h, mgr };
}

// ---- 1. the envelope ---------------------------------------------------------------------------------------------------
test("the envelope: legacy envelopes are untouched; a commitment must name THIS backend and carry no legacy config", () => {
  assert.equal(shieldStartupEnvelope(""), null);
  assert.equal(shieldStartupEnvelope(JSON.stringify({ isolation: { require: "hyperv-partition-per-app" }, config: { a: 1 } })), null);
  const intent = { version: 1, sha256: "ab".repeat(32) };
  const s = shieldStartupEnvelope(envelopeFor(intent, "hyperv-partition-per-app", { waf: {} }));
  assert.deepEqual(s.intent, intent);
  assert.deepEqual(JSON.parse(s.projected), { isolation: { require: "hyperv-partition-per-app" }, waf: {} });
  assert.throws(() => shieldStartupEnvelope(envelopeFor(intent, "snp-guest-per-app")), /this host starts packages only for "hyperv-partition-per-app"/);
  assert.throws(() => shieldStartupEnvelope(JSON.stringify({ isolation: { require: "hyperv-partition-per-app" }, guestBootstrap: intent, config: {} })), /no legacy config/);
  assert.throws(() => shieldStartupEnvelope(envelopeFor({ version: 1, sha256: "00".repeat(32) })), /nonzero sha256/);
  assert.throws(() => startupGateways({ ENCLAVE_STARTUP_GATEWAYS: GATEWAY, ENCLAVE_STARTUP_STORAGE_PLAN_FILE: "/x" }), /not both/);
  assert.deepEqual(startupGateways({}), [], "no default replica: an operator names its own");
});

// ---- 2. materialize: the exact app ------------------------------------------------------------------------------------
test("a fresh public package with no config derives the shared vector's AppID, from the pinned ledger at one agreed block", async () => {
  const pkg = ownerPackage();
  commit(pkg);
  const before = packageHits.length;
  const mgr = await manager();
  const health = await (await realFetch(`${mgr.base}/health`)).json();
  const r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId, needLease: true, enclaveId: HOST_ID });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.startup.appId, VEC.ok[0].mapping.appId, "the AppID is the cross-implementation vector's, not one this test computed");
  assert.equal(r.startup.sha256, pkg.intent.sha256);
  assert.equal(r.startup.secretsMode, "public");
  assert.equal(r.spawn.derive.derivation, "enclave-catalog-bundle/1");
  assert.equal(r.spawn.hasSecrets, false);
  assert.ok(packageHits.slice(before).length >= 1 && packageHits.slice(before).every((u) => u.startsWith(GATEWAY)), "only the operator's replica was asked");
});

test("the package's configText replaces every other config, is measured (V5), and a wrong committed AppID is refused", async () => {
  const mgr = await manager(), health = await (await realFetch(`${mgr.base}/health`)).json();
  const pkg = ownerPackage({ configText: '{"greeting":"hi"}' });
  commit(pkg);
  rpc.catalog.current = state.version = { ...VERSION, config: '{"greeting":"the version says otherwise"}' };
  try {
    const r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.spawn.derive.derivation, "enclave-catalog-bundle/5");
    assert.equal(r.spawn.derive.config, '{"greeting":"hi"}', "the package's config, not the version's");
    assert.notEqual(r.startup.appId, VEC.ok[0].mapping.appId);
    const wrong = ownerPackage({ configText: '{"greeting":"hi"}', appId: VEC.ok[0].mapping.appId });
    commit(wrong);
    const w = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
    assert.equal(w.ok, false); assert.equal(w.unknown, false); assert.equal(w.input, "package.appId");
    assert.match(w.why, /derives [0-9a-f]{64} \(enclave-catalog-bundle\/5\)/);
  } finally { rpc.catalog.current = state.version = VERSION; }
});

// ---- 3. the chain: pinned, fresh, agreed, current ---------------------------------------------------------------------
test("stale or disagreeing RPCs decide nothing: unknown, never a start", async () => {
  const mgr = await manager(), health = await (await realFetch(`${mgr.base}/health`)).json();
  commit(ownerPackage());
  state.stale = true;
  try {
    const r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
    assert.equal(r.ok, false); assert.equal(r.unknown, true); assert.match(r.why, /no fresh agreeing chain quorum.*stale chain block/);
  } finally { state.stale = false; }
  state.disagree = true;
  try {
    const r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
    assert.equal(r.ok, false); assert.equal(r.unknown, true); assert.match(r.why, /the RPCs disagree|no fresh agreeing/);
  } finally { state.disagree = false; }
  assert.throws(() => quorumReader({ clients: [fakeClient(0)] }), /at least two RPCs/);
});

test("an owner transfer, a moved commitment, a revoked wallet policy, another runtime and custody-v2 are each refused by name", async () => {
  const mgr = await manager(), health = await (await realFetch(`${mgr.base}/health`)).json();
  const pkg = ownerPackage();
  // the ledger's owner changed: the package (bound to the old owner) no longer authorizes anything
  commit(pkg, { owner: OTHER });
  let r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.ok, false); assert.equal(r.unknown, false); assert.match(r.why, /startup owner mismatch/);
  // the caller's own read saw another commitment than the quorum: wait, never start the one in between
  const row = commit(pkg);
  r = await authority().materialize(DEP, { observed: { ...row, configCid: envelopeFor({ version: 1, sha256: "ee".repeat(32) }) }, manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.unknown, true); assert.match(r.why, /startup commitment changed during verification/);
  // the host-wallet policy (host-admission) revoked this deployment
  r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId, walletRefusal: async (d) => (assert.equal(d.id, DEP), "the owner's wallet policy revoked this deployment") });
  assert.equal(r.ok, false); assert.equal(r.input, "walletPolicy"); assert.match(r.why, /revoked/);
  // a package for another runtime (the CLI's SNP default, say)
  commit(ownerPackage({ runtimeId: "ef".repeat(32), appId: "aa".repeat(32) }));
  r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.ok, false); assert.equal(r.input, "package.runtimeId"); assert.match(r.why, /commits to RuntimeID (ef){32}, and this host's Shield-direct image runs/);
  // custody-v2: never started without its values; nothing fetched from any relay
  const custody = { v: 2, chainId: 8453, vault: "0x" + "c1".repeat(20), policyRev: "1", secretRev: "1", epoch: 1 };
  commit(ownerPackage({ secretsMode: "custody-v2", custody }));
  r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.ok, false); assert.equal(r.unknown, false); assert.equal(r.input, "secretsMode");
  assert.match(r.why, /states no direct custody.*no plaintext secret is fetched into this host/);
  // not this host's lease at the quorum block: a launch waits
  commit(pkg, { runner: ZERO32, leaseUntil: 0n });
  r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId, needLease: true, enclaveId: HOST_ID });
  assert.equal(r.unknown, true); assert.match(r.why, /does not hold a live lease/);
  // a replica that serves nothing: unknown (availability), not a refusal
  commit(ownerPackage({ configText: '{"x":1}', appId: "bb".repeat(32) }));
  packages.clear();
  r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.unknown, true); assert.equal(r.input, "package");
  assert.deepEqual(enclaveHits, []);
});

test("adoption: a partition serves an owner-committed deployment only as the committed AppID on the committed runtime", () => {
  const s = { appId: "aa".repeat(32), runtimeId: "bb".repeat(32) };
  assert.equal(startupAdoptionRefusal({ appId: s.appId, runtimeId: s.runtimeId }, s), null);
  assert.equal(startupAdoptionRefusal({ appId: s.appId, runtimeId: null }, s), null, "a view that omits the runtime is judged on the AppID");
  assert.match(startupAdoptionRefusal({ appId: "cc".repeat(32), runtimeId: s.runtimeId }, s), /not the committed/);
  assert.match(startupAdoptionRefusal({ appId: s.appId, runtimeId: "dd".repeat(32) }, s), /RuntimeID/);
  assert.match(startupAdoptionRefusal(null, s), /no manager view/);
  assert.equal(startupAdoptionRefusal({ appId: "anything" }, null), null, "legacy records are not judged here");
});

// ---- 4. the real Host and manager: claim, launch, restart, transfer --------------------------------------------------
test("an independent host launches the committed partition from its own replicas: no relay secret, name or verdict service is asked", async () => {
  const { h, mgr } = await independentHost();
  const pkg = ownerPackage({ configText: '{"greeting":"hi"}', names: { hosts: ["app.owner.example"] } });
  commit(pkg);
  const hits = enclaveHits.length;
  const out = await h.consider(DEP);
  assert.equal(out.accepted, true, JSON.stringify(out));
  const rec = h.records.get(DEP);
  assert.equal(rec.status, "running", rec.reason);
  assert.equal(rec.startup.sha256, pkg.intent.sha256);
  assert.equal(rec.isolation.appId, rec.startup.appId, "the manager's own derivation is the package's AppID");
  const view = (await (await realFetch(`${mgr.base}/vms`)).json()).vms.find((x) => x.name === DEP);
  assert.equal(view.appId, pkg.manifest.appId);
  assert.equal(enclaveHits.length, hits, `Enclave endpoints were contacted: ${enclaveHits.slice(hits).join(", ")}`);
  // the legacy relay secrets path was never consulted (relayBase "" would answer unknown and hold; it was not asked)
  assert.equal(h.secrets.has(DEP), false);
  // names: only the package's, and only with a proof; an unproven name is not routed
  h.cfg.proveOwnerName = async (_id, name) => { throw new Error(`no certificate for ${name} on the partition key`); };
  await h.refreshDomains(DEP);
  assert.deepEqual(h.domains.get(DEP), []); assert.match(h.records.get(DEP).domainWhy, /not proven: app\.owner\.example/);
  const t0 = Date.now();
  h.cfg.proveOwnerName = async (id, name) => ({ name, spkiSha256: "cd".repeat(32), notBefore: t0 - 1000, notAfter: t0 + 86_400_000 });
  await h.refreshDomains(DEP);
  assert.deepEqual(h.domains.get(DEP), ["app.owner.example"]);
  const target = await h.appZoneTarget(DEP);
  assert.deepEqual(target.isolation.allowedNames, ["app.owner.example"], "the proven name may reach this partition, still ending TLS in the guest");
});

test("a new commitment restarts, and a partition running an older package's AppID is retired rather than adopted", async () => {
  const { h, mgr } = await independentHost();
  const first = ownerPackage({ configText: '{"v":1}' });
  commit(first);
  assert.equal((await h.consider(DEP)).accepted, true);
  const was = h.records.get(DEP);
  assert.equal(was.status, "running", was.reason);
  // the owner commits another package: the envelope edit is a restart, never "only protection rules"
  const second = ownerPackage({ configText: '{"v":2}' });
  const row = commit(second);
  assert.equal(h.envelopeVerdict(was, row.configCid), "restart");
  // a node restart: a fresh Host finds the OLD partition by name and must not adopt it
  const { h: h2 } = { h: servedOwner(new Host({ ...h.cfg, dir: fs.mkdtempSync(path.join(os.tmpdir(), "ee-startup2-")), ownerStartup: authority() }), OPERATOR) };
  h2.chainReady = true; h2.registered = h.registered;
  await h2.ensureApp(DEP, await chain.readDeployment(DEP));
  const rec = h2.records.get(DEP);
  assert.equal(rec.status, "running", rec.reason);
  assert.equal(rec.startup.sha256, second.intent.sha256);
  const vms = (await (await realFetch(`${mgr.base}/vms`)).json()).vms.filter((x) => x.name === DEP);
  assert.equal(vms.length, 1, "never two partitions for one deployment");
  assert.equal(vms[0].appId, second.manifest.appId, "the old package's partition was replaced");
  assert.notEqual(vms[0].appId, first.manifest.appId);
});

test("an owner transfer under a live lease, or a revoked wallet policy, stops serving the package; nothing reaches a relay", async () => {
  const revoked = { on: false };
  const { h, mgr } = await independentHost({ hostAdmission: { hostId: HOST_ID, refusal: async () => (revoked.on ? "revoked by the owner's wallet policy" : null) } });
  commit(ownerPackage());
  assert.equal((await h.consider(DEP)).accepted, true);
  assert.equal(h.records.get(DEP).status, "running");
  // transfer: the package (bound to the previous owner) authorizes nothing now; the partition is retired
  h.ownerSet = () => new Set([OPERATOR, OTHER]);          // a served owner, so the owner rule is not what decides here
  commit(ownerPackage(), { owner: OTHER });
  await h.ensureApp(DEP, await chain.readDeployment(DEP));
  let rec = h.records.get(DEP);
  assert.notEqual(rec.status, "running");
  assert.match(String(rec.reason || [...h.blocked.values()].join(" ")), /startup owner mismatch/);
  const live = (await (await realFetch(`${mgr.base}/vms`)).json()).vms.filter((x) => x.name === DEP && ["running", "starting"].includes(x.status));
  assert.equal(live.length, 0, "the transferred deployment's partition is gone");
  // revoked wallet policy
  const { h: h3 } = await independentHost({ hostAdmission: { hostId: HOST_ID, refusal: async () => "revoked by the owner's wallet policy" } });
  commit(ownerPackage());
  const out = await h3.consider(DEP);
  assert.equal(out.accepted, false); assert.match(out.reason, /revoked/);
  assert.deepEqual(enclaveHits, []);
});

test("before any claim: an unverifiable package is never claimed, and a host without a startup authority refuses by name", async () => {
  const { h } = await independentHost();
  commit(ownerPackage({ appId: "aa".repeat(32) }), { runner: ZERO32, leaseUntil: 0n });
  const from = rpc.calls.length;
  const out = await h.consider(DEP);
  assert.equal(out.accepted, false);
  assert.match(out.reason, /before any claim: package\.appId/);
  assert.deepEqual(rpc.calls.slice(from).filter((m) => /^eth_(sendRawTransaction|estimateGas)$/.test(m)), [], "no claim was prepared");
  const { h: none } = await independentHost({ ownerStartup: null });
  none.startupConfigError = "no startup package replicas (ENCLAVE_STARTUP_STORAGE_PLAN_FILE or ENCLAVE_STARTUP_GATEWAYS)";
  const d = { ...ledgerRow(envelopeFor(ownerPackage().intent)), createdAt: 1n };
  assert.match(none.claimRefusal(d, { appsEnabled: true }), /cannot verify one: no startup package replicas/);
  // and an SNP-targeted package is refused for its backend, not silently re-derived
  assert.match(h.claimRefusal({ ...d, configCid: envelopeFor(ownerPackage().intent, "snp-guest-per-app") }, { appsEnabled: true }), /starts packages only for "hyperv-partition-per-app"/);
});

// ---- 5. names and the custody boundary (units) ------------------------------------------------------------------------
test("owner names: only the package's, each needs a live proof, proofs lapse and are re-made, a failure drops the name", async () => {
  const startup = { sha256: "ab".repeat(32), names: ["a.owner.example", "b.owner.example", "Not A Name", "x.enclave.host"] };
  let t = 1_000_000;
  const asked = [];
  const prove = async (name) => { asked.push(name); if (name === "b.owner.example") throw new Error("certificate is not on the attested guest key"); return { name, notBefore: t - 1, notAfter: t + 10 * 60_000 }; };
  let r = await ownerCommittedDomains({ startup, prove, now: () => t });
  assert.deepEqual(r.hosts, ["a.owner.example"]);
  assert.deepEqual(r.refused.map((x) => x.hostname), ["b.owner.example"]);
  assert.ok(!asked.includes("Not A Name"));
  asked.length = 0; t += 60_000;
  r = await ownerCommittedDomains({ startup, prove, proofs: r.proofs, now: () => t });
  assert.deepEqual(asked, ["b.owner.example"], "a standing proof is reused inside its TTL");
  t += 5 * 60_000;
  asked.length = 0;
  r = await ownerCommittedDomains({ startup, prove: async (name) => { asked.push(name); throw new Error("gone"); }, proofs: r.proofs, now: () => t });
  assert.deepEqual(r.hosts, [], "a lapsed proof is re-made, never extended");
  await assert.rejects(ownerCommittedDomains({ startup: null, prove }), /verified startup package/);
});

test("custody-v2 boundary: the host signs only the guest's binding for the committed vault, with custody v2's exact message", async () => {
  const { operatorMessage } = await import("../custody/v2/protocol.mjs");
  const vault = "0x" + "c1".repeat(20), binding = "9a".repeat(32);
  const msg = custodyOperatorMessageV2({ chainId: 8453, vault, id: DEP, endpoint: ENDPOINT, binding, expiry: 123 });
  assert.equal(msg, operatorMessage({ chainId: 8453, vault, id: DEP, endpoint: ENDPOINT, binding: Buffer.from(binding, "hex"), expiry: 123 }));
  const startup = { secretsMode: "custody-v2", custody: { v: 2, chainId: 8453, vault }, deployment: DEP, sha256: "5e".repeat(32), appId: "a1".repeat(32), runtimeId: REC.runtimeId,
                    imageRole: "shield-direct", imageSha256: DIRECT_IMG };
  const record = { id: DEP, status: "starting", isolationHeld: "vm1" };
  // the manager's view of the exact partition asking (custody-transport.mjs)
  const instance = { id: "vm1", name: DEP, secretDeployment: DEP, status: "starting", bootstrapSha256: startup.sha256, appId: startup.appId,
                     runtimeId: REC.runtimeId, custody: { vault }, imageRole: "shield-direct", igvmSha256: DIRECT_IMG };
  const signed = [];
  const sign = async (m) => { signed.push(m); return "0x" + "11".repeat(65); };
  const ok = await custodyAuthorization({ startup, record, instance, request: { v: 2, vault, binding }, endpoint: ENDPOINT, sign, now: () => 1_000_000 });
  assert.equal(ok.binding, binding); assert.equal(signed[0], custodyOperatorMessageV2({ chainId: 8453, vault, id: DEP, endpoint: ENDPOINT, binding, expiry: 1300 }));
  for (const [patch, re] of [[{ request: { v: 2, vault: "0x" + "c2".repeat(20), binding } }, /did not commit/], [{ request: { v: 2, vault, binding: "zz" } }, /32 bytes/],
                             [{ startup: { ...startup, secretsMode: "public" } }, /does not keep secrets/], [{ record: { id: DEP, status: "stopped" } }, /no partition/],
                             // ONE deployment: the record, the asking partition and the guest's request are all the verified startup's
                             [{ record: { ...record, id: OTHER_DEP } }, /another deployment's than the verified startup's/],
                             [{ record: { ...record, id: DEP.toUpperCase().replace("0X", "0x") } }, /another deployment's/],
                             [{ startup: { ...startup, deployment: undefined } }, /names no deployment/],
                             [{ startup: { ...startup, deployment: OTHER_DEP } }, /another deployment's than the verified startup's/],
                             [{ instance: undefined }, /not this deployment's live secret domain/],
                             [{ instance: { ...instance, name: OTHER_DEP } }, /not this deployment's live secret domain/],
                             [{ instance: { ...instance, secretDeployment: OTHER_DEP } }, /not this deployment's live secret domain/],
                             [{ instance: { ...instance, recovered: true } }, /not this deployment's live secret domain/],
                             [{ instance: { ...instance, bootstrapSha256: "00".repeat(32) } }, /does not run the verified package/],
                             [{ instance: { ...instance, appId: "00".repeat(32) } }, /does not run the verified package/],
                             [{ instance: { ...instance, custody: { vault: "0x" + "c2".repeat(20) } } }, /another vault/],
                             [{ instance: { ...instance, id: "vm2" } }, /holds another partition/],
                             // F3: the same RuntimeID on another image is not the pinned Shield-direct image
                             [{ instance: { ...instance, imageRole: "legacy" } }, /not on this host's pinned Shield-direct image/],
                             [{ instance: { ...instance, igvmSha256: "ab".repeat(32) } }, /not on this host's pinned Shield-direct image/],
                             [{ startup: { ...startup, imageSha256: null } }, /not on this host's pinned Shield-direct image/],
                             [{ request: { v: 2, vault, id: OTHER_DEP, binding } }, /another deployment/]])
    await assert.rejects(custodyAuthorization({ startup, record, instance, request: { v: 2, vault, binding }, endpoint: ENDPOINT, sign, ...patch }), re);
  assert.equal(signed.length, 1, "nothing refused was signed");
});

// Review finding (2026-10-20): the Shield-direct front (isolation/m2/front shield_direct_custody.go prepareShieldDirect, and
// shield_egress.go startDirect) starts only when the monitor's measured /app.config IS the committed configText, byte for
// byte; the bundle measures the manager's canonical rendering (appConfigText: JSON.stringify without _media; no file at all
// for a public deployment with no effective config; "{}" for a secrets-only one). A package spelled any other way derives
// the right AppID here and then dies in the guest, after a claim. The host refuses it before any claim instead.
test("a Shield-direct partition is started only for a configText that IS the bytes it measures; others are refused before any claim", async () => {
  const mgr = await manager(), health = await (await realFetch(`${mgr.base}/health`)).json();
  const v5 = (config) => derive({ record: { ...REC, derivation: "enclave-catalog-bundle/5", config }, component: COMPONENT }).appId;
  const spelled = [
    { configText: "{}", appId: VEC.ok[0].mapping.appId },                                      // public, no effective config: measures NO file
    { configText: '{ "greeting": "hi" }', appId: v5('{"greeting":"hi"}') },                     // whitespace
    { configText: '{"greeting":"hi","_media":{"icon":"x"}}', appId: v5('{"greeting":"hi"}') },  // display metadata the bundle drops
  ];
  for (const s of spelled) {
    commit(ownerPackage(s));
    const r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
    assert.equal(r.ok, false, `${s.configText} was accepted for a Shield-direct partition that would refuse it`);
    assert.equal(r.input, "package.configText"); assert.equal(r.unknown, false);
    assert.match(r.why, /exact bytes the partition measures/);
  }
  for (const configText of ["", '{"greeting":"hi"}']) {
    commit(ownerPackage({ configText }));
    const r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.spawn.derive.config ?? "", configText, "the committed text is what /app.config will hold");
  }
  // a manager without a Shield-direct image (F3): a direct node refuses (never a silent legacy start); only an explicitly
  // legacy-public node starts it host-verified, with no guest authority and no package carried
  const legacy = await manager({ directBootstrap: false }), lh = await (await realFetch(`${legacy.base}/health`)).json();
  commit(ownerPackage(spelled[0]));
  const refusedHere = await authority().materialize(DEP, { manager: lh, runtimeId: REC.runtimeId });
  assert.equal(refusedHere.ok, false); assert.equal(refusedHere.input, "manager"); assert.equal(refusedHere.unknown, false);
  const lp = await authority({ direct: null, legacyPublic: true }).materialize(DEP, { manager: lh, runtimeId: REC.runtimeId });
  assert.equal(lp.ok, true, JSON.stringify(lp)); assert.equal(lp.startup.direct, false); assert.equal(lp.startup.guestAuthority, false);
  assert.equal(lp.spawn.bootstrap, undefined);
});

// Direct Shield custody (windows/vbslike/manager/custody-transport.mjs, windows/node/shield-custody.mjs): a custody-v2
// package starts only as a V6/V7 direct custody domain on a manager stating supports.custodyV2, and its startup carries the
// committed pointer's PUBLIC part (vault, machines) for the custodians' TPM sessions. Anywhere else it is refused by name.
test("custody-v2 starts only as a direct custody domain (V6 on a manager stating custodyV2), with its committed machines", async () => {
  const mgr = await manager(), real = await (await realFetch(`${mgr.base}/health`)).json();
  const health = { ...real, supports: { ...real.supports, secrets: true, custodyV2: true },
                   catalog: { ...real.catalog, derivations: [...real.catalog.derivations, "enclave-catalog-bundle/6"] } };
  const configText = '{"api":"https://api.example"}';
  const machines = [{ endpoint: "https://custodian-1.example/c", encKey: "11".repeat(32), enclave: false, indices: [1] }];
  const custody = { v: 2, chainId: 8453, vault: "0x" + "c1".repeat(20), machines };
  const appId = derive({ record: { ...REC, derivation: "enclave-catalog-bundle/6", config: configText, secretDeployment: DEP }, component: COMPONENT }).appId;
  commit(ownerPackage({ configText, secretsMode: "custody-v2", custody, appId }));
  let r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.derivation, "enclave-catalog-bundle/6"); assert.equal(r.startup.direct, true); assert.equal(r.startup.deployment, DEP);
  assert.equal(typeof r.spawn.bootstrap, "string", "the exact package bytes go to the partition"); assert.equal(r.spawn.hasSecrets, true);
  assert.equal(r.spawn.derive.secretDeployment, DEP);
  assert.deepEqual(r.startup.custody, { v: 2, chainId: 8453, vault: custody.vault, machines: [{ endpoint: machines[0].endpoint, encKey: machines[0].encKey }] });
  // the same package where direct custody is not stated, or the image is not Shield-direct: refused, never relay secrets
  for (const [supports, input] of [[{ custodyV2: false }, "secretsMode"], [{ directBootstrap: false }, "manager"]]) {
    r = await authority().materialize(DEP, { manager: { ...health, supports: { ...health.supports, ...supports } }, runtimeId: REC.runtimeId });
    assert.equal(r.ok, false, JSON.stringify(supports)); assert.equal(r.unknown, false); assert.equal(r.input, input);
  }
  // a public package on the custody manager is exactly as before
  commit(ownerPackage());
  r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.ok, true, JSON.stringify(r)); assert.equal(r.startup.direct, true); assert.equal(r.startup.custody, null);
  assert.deepEqual(enclaveHits, []);
});

// F3 (work/shield-image-selection-interface.txt "F3 FINAL"): the node routes an owner-committed package by its OWN pins for
// the Shield-direct image (RuntimeID AND IGVM hash), compared with the manager's statement and never adopted from it. There
// is no silent legacy fallback: only explicit legacy-public operation starts a names-free public package, host-verified,
// with guestAuthority=false.
test("F3 node routing: own pins decide; a mismatch refuses; legacy-public is explicit, names-free, custody-free and without guest authority", async () => {
  const mgr = await manager(), health = await (await realFetch(`${mgr.base}/health`)).json();
  assert.deepEqual(health.images.shieldDirect, { igvmSha256: DIRECT_IMG, runtimeId: REC.runtimeId, starts: ["public enclave-catalog-bundle/1 or /5"] });
  commit(ownerPackage());
  // direct, on equal RuntimeIDs: the package goes to the Shield-direct image with its bytes and full guest authority
  let r = await authority().materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual([r.startup.direct, r.startup.guestAuthority, r.startup.imageRole, r.startup.imageSha256], [true, true, "shield-direct", DIRECT_IMG]);
  assert.equal(typeof r.spawn.bootstrap, "string");
  // the manager states another IGVM, or another RuntimeID, or no direct image: refused by name, never started on legacy
  for (const sd of [{ ...health.images.shieldDirect, igvmSha256: "d2".repeat(32) }, { ...health.images.shieldDirect, runtimeId: "ee".repeat(32) }, null]) {
    r = await authority().materialize(DEP, { manager: { ...health, images: { ...health.images, shieldDirect: sd } }, runtimeId: REC.runtimeId });
    assert.equal(r.ok, false); assert.equal(r.unknown, false); assert.equal(r.input, "manager"); assert.match(r.why, /starts on no other image/);
  }
  // a distinct direct RuntimeID: a package committing the LEGACY RuntimeID is refused, not routed to legacy
  r = await authority({ direct: { runtimeId: "ee".repeat(32), imageSha256: DIRECT_IMG } })
    .materialize(DEP, { manager: { ...health, images: { ...health.images, shieldDirect: { ...health.images.shieldDirect, runtimeId: "ee".repeat(32) } } }, runtimeId: REC.runtimeId });
  assert.equal(r.ok, false); assert.equal(r.input, "package.runtimeId"); assert.match(r.why, /Shield-direct image runs e/);
  // neither a direct image nor explicit legacy-public: nothing is started
  r = await authority({ direct: null }).materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.ok, false); assert.equal(r.input, "guestBootstrap"); assert.match(r.why, /needs this host's pinned Shield-direct image.*or explicit legacy-public operation/);
  // explicit legacy-public: host-verified, NO package carried, no guest authority, on the legacy image
  const lp = authority({ direct: null, legacyPublic: true });
  r = await lp.materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual([r.startup.direct, r.startup.guestAuthority, r.startup.imageRole, r.startup.imageSha256], [false, false, "legacy", null]);
  assert.equal(r.spawn.bootstrap, undefined, "without a package the manager routes it to the legacy image");
  // ...but never owner names or custody: those need the guest's own authority
  commit(ownerPackage({ configText: '{"greeting":"hi"}', names: { hosts: ["app.owner.example"] } }));
  r = await lp.materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.ok, false); assert.equal(r.input, "names");
  commit(ownerPackage({ secretsMode: "custody-v2", custody: { v: 2, chainId: 8453, vault: "0x" + "c1".repeat(20) } }));
  r = await lp.materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.ok, false); assert.equal(r.input, "secretsMode");
  // ...and a legacy-public package committing another runtime than the legacy pin is refused
  commit(ownerPackage({ runtimeId: "ef".repeat(32), appId: "aa".repeat(32) }));
  r = await lp.materialize(DEP, { manager: health, runtimeId: REC.runtimeId });
  assert.equal(r.ok, false); assert.equal(r.input, "package.runtimeId");
  assert.deepEqual(enclaveHits, []);
});
