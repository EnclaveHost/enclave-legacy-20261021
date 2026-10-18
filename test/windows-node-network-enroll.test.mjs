// windows/node/network-enroll.mjs: an open-market Windows host enrolls its own privacy agent on the Enclave network - the
// config, then each leased app - with no wallets and no funding; a box with retired TUNA settings is cleaned and switched.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createNetworkEnroll, RETIRED_KEYS } from "../windows/node/network-enroll.mjs";
import { rawDigest } from "../network/shield-expectation.mjs";

const RID = "ab".repeat(32), APP = "0x" + "5a".repeat(32), RUNNER = "0x" + "22".repeat(32), D = "0x" + "11".repeat(32);
const CID = "bafkreibjbefi32gvjrd54lhdizq6zlywym6urcuztzvi455xfv23tyjnza";
const CHECKER = "0x" + "57".repeat(20);

function world({ checkers = [CHECKER] } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "network-enroll-")), agentDir = path.join(dir, "agent"), policyFile = path.join(dir, "policy.json");
  fs.mkdirSync(agentDir);
  fs.writeFileSync(policyFile, JSON.stringify({ cpu: { runtimeId: RID }, gpu: {} }));
  const logs = [], fetched = [];
  const rows = [{ id: D, appRef: `catalog://${APP}/4`, configCid: "{}", runner: RUNNER, active: true, isPublic: true, leaseUntil: 9999999999n }];
  const vm = { name: D, status: "running", appReady: true, catalog: { app: APP, version: 4 }, cid: CID, appId: "ef".repeat(32), runtimeId: RID,
               componentSha256: rawDigest(CID), derivation: "enclave-catalog-bundle/1", gpuMilli: 0, startedAt: 1 };
  const fetchFn = async (url) => {
    fetched.push(url);
    if (url.endsWith("/v1/domains/map")) return { ok: true, json: async () => ({ domains: { "shop.example": D } }) };
    throw new Error("unexpected fetch " + url);
  };
  let restarts = 0;
  const config = { agentDir, binDir: path.join(dir, "bin"), nodeBinary: "node.exe", operatorKeyFile: "op.key", runner: RUNNER, endpoint: "https://api.enclave.host/t/box",
                   relayBase: "https://api.enclave.host", policyFile, tpmBinary: "tpmattest.exe", tpmSha256: "aa".repeat(32), addressBook: "0x" + "44".repeat(20), chainRpc: ["https://rpc"],
                   enclaveNetwork: { checkers } };
  const enroll = createNetworkEnroll({ agentDir, binDir: path.join(dir, "bin"), runner: RUNNER, relayBase: "https://api.enclave.host", fetch: fetchFn,
    log: (m) => logs.push(m), restartAgent: async () => { restarts++; }, config, rows: async () => rows, version: async () => ({ cid: CID }), vms: async () => [vm] });
  const read = () => JSON.parse(fs.readFileSync(path.join(agentDir, "privacy-config.json"), "utf8"));
  return { enroll, agentDir, logs, vm, fetched, read, config, restarts: () => restarts };
}

test("TUNA is retired: enrollment needs the Enclave network configuration and its trusted checkers", async () => {
  assert.throws(() => createNetworkEnroll({ agentDir: "/x", binDir: "/y", runner: RUNNER, relayBase: "https://api.enclave.host", config: {} }), /Enclave network configuration/);
  await assert.rejects(world({ checkers: [] }).enroll.pass(), /trusted checker addresses required/);
});

test("apps enroll at once with no wallets or funding; the config names the Enclave network and the box's control circuits", async () => {
  const w = world();
  const r = await w.enroll.pass();
  assert.equal(r.ready, true); assert.equal(r.apps, 1);
  assert.deepEqual(w.fetched, ["https://api.enclave.host/v1/domains/map"], "the relay is asked only for the domain map");
  assert.equal(fs.existsSync(path.join(w.agentDir, "control-wallets.json")), false, "no NKN wallets made");
  const cfg = w.read();
  for (const k of RETIRED_KEYS) assert.equal(cfg[k], undefined, k);
  assert.equal(cfg.version, 2); assert.equal(cfg.runner, RUNNER); assert.equal(cfg.shield.tpmSha256, "aa".repeat(32));
  assert.deepEqual({ apps: cfg.enclaveNetwork.apps, control: cfg.enclaveNetwork.control, checkers: cfg.enclaveNetwork.checkers }, { apps: "all", control: true, checkers: [CHECKER] });
  assert.equal(path.basename(cfg.enclaveNetwork.wgBinary), "enclave-wg.exe"); assert.equal(path.basename(cfg.enclaveNetwork.firewallBinary), "enclave-circuit-firewall.exe");
  assert.equal(path.basename(cfg.enclaveNetwork.workerModule), "windows-circuit-worker.mjs");
  assert.equal(cfg.apps[0].internetMode, "enclave-network"); assert.equal(cfg.apps[0].walletsFile, undefined);
  assert.deepEqual(cfg.apps[0].names, [D.slice(2, 10) + ".app.enclave.host", "shop.example"]);
  const exp = JSON.parse(fs.readFileSync(cfg.apps[0].expectedFile, "utf8"));
  assert.equal(exp.appSha256, "ef".repeat(32)); assert.equal(exp.runtimeId, RID);
  assert.equal(w.restarts(), 0, "a fresh config needs no restart");
  assert.equal((await w.enroll.pass()).changed, false, "steady state: nothing rewritten");
  w.vm.appId = "cd".repeat(32);
  assert.equal((await w.enroll.pass()).changed, true, "an upgraded partition rewrites the expectation and touches the config");
  assert.equal(JSON.parse(fs.readFileSync(cfg.apps[0].expectedFile, "utf8")).appSha256, "cd".repeat(32));
});

test("a partition outside the admitted policy is never enrolled", async () => {
  const w = world();
  w.vm.runtimeId = "00".repeat(32);
  const r = await w.enroll.pass();
  assert.equal(r.apps, 0); assert.equal(fs.existsSync(path.join(w.agentDir, "privacy-config.json")), false, "no config with no app: the agent refuses an empty list");
  assert.ok(w.logs.some((l) => /outside the admitted Shield policy/.test(l)));
});

test("enrollment preserves the operator's independent directory origins across app updates", async () => {
  const w=world();await w.enroll.pass();const cfg=w.read();
  cfg.enclaveNetwork.directories=['http://8.8.4.4:8188','https://directory.example'];
  fs.writeFileSync(path.join(w.agentDir,'privacy-config.json'),JSON.stringify(cfg));
  await w.enroll.pass();
  assert.deepEqual(w.read().enclaveNetwork.directories,cfg.enclaveNetwork.directories);
  w.vm.appId='cd'.repeat(32);await w.enroll.pass();
  assert.deepEqual(w.read().enclaveNetwork.directories,cfg.enclaveNetwork.directories);
});

test("a box still configured for TUNA is cleaned and switched once, and its agent restarted once", async () => {
  const w = world();
  const tuna = { version: 2, directory: path.join(w.agentDir, "state"), operatorKeyFile: "op.key", runner: RUNNER, endpoint: "https://api.enclave.host/t/box",
    nknRpc: ["http://seed.nkn.org:30003"], chain: { addressBook: "0x" + "44".repeat(20), rpc: ["https://rpc"] },
    inventory: { binary: "enclave-provider-inventory.exe" }, control: { binary: "enclave-tuna.exe", walletsFile: "control-wallets.json" },
    runtime: { binary: "enclave-tuna.exe" }, upstream: "http://127.0.0.1:9600", mirror: "https://api.enclave.host", defaults: { budgetNkn: "1.5" },
    apps: [{ deploymentId: D, names: [D.slice(2, 10) + ".app.enclave.host"], walletsFile: "wallets.json", expectedFile: path.join(w.agentDir, D, "expected.json"), internetMode: "tuna", publishToMirror: true }] };
  fs.writeFileSync(path.join(w.agentDir, "privacy-config.json"), JSON.stringify(tuna));
  await w.enroll.pass();
  const after = w.read();
  for (const k of RETIRED_KEYS) assert.equal(after[k], undefined, k);
  assert.equal(after.enclaveNetwork.apps, "all"); assert.equal(after.apps[0].internetMode, "enclave-network"); assert.equal(after.apps[0].walletsFile, undefined);
  assert.deepEqual(after.apps[0].names, [D.slice(2, 10) + ".app.enclave.host", "shop.example"]);
  assert.equal(w.restarts(), 1);
  await w.enroll.pass(); assert.equal(w.restarts(), 1, "switched once, not on every pass");
});

test("a box already on the Enclave network has leftover TUNA settings dropped without a restart", async () => {
  const w = world();
  await w.enroll.pass();
  const cfg = w.read();
  fs.writeFileSync(path.join(w.agentDir, "privacy-config.json"), JSON.stringify({ ...cfg, nknRpc: ["http://seed.nkn.org:30003"], inventory: {}, runtime: {}, defaults: { budgetNkn: "1.5" } }));
  assert.equal((await w.enroll.pass()).changed, true);
  const after = w.read();
  for (const k of RETIRED_KEYS) assert.equal(after[k], undefined, k);
  assert.deepEqual(after.enclaveNetwork, cfg.enclaveNetwork);
  assert.equal(w.restarts(), 0, "the agent ignores retired settings: nothing to restart for");
  assert.ok(w.logs.some((l) => /retired TUNA settings dropped/.test(l)));
});

test('the network config carries the box\'s paid-provider settlement keys when it has them, and nothing otherwise',async()=>{
 const {networkConfig}=await import('../windows/node/network-enroll.mjs');
 const base={binDir:'C:\\bin',nodeBinary:'node.exe',relayBase:'https://api.enclave.host',checkers:['0x'+'12'.repeat(20)]};
 assert.equal(networkConfig(base).paid,undefined);
 assert.deepEqual(networkConfig({...base,paid:{proofKeyFile:'p.key',gasKeyFile:'o.key'}}).paid,{proofKeyFile:'p.key',gasKeyFile:'o.key',rpc:'https://base-rpc.publicnode.com',maxPending6:'10000'});
});

test("an app whose new version has no ready partition yet is counted as waiting, so the node looks again soon", async () => {
  const w = world();
  assert.equal((await w.enroll.pass()).waiting, 0);
  w.vm.appReady = false;                                   // the owner switched versions; the new partition is still starting
  const r = await w.enroll.pass();
  assert.equal(r.waiting, 1);
  assert.ok(w.logs.some((l) => /no ready partition runs/.test(l)));
  w.vm.appReady = true;
  assert.equal((await w.enroll.pass()).waiting, 0);
});

test("a box whose agent directory moved (tuna -> network) has its paths repointed and its agent restarted once", async () => {
  const w = world();
  await w.enroll.pass();
  const cfg = w.read(), old = path.join(path.dirname(w.agentDir), "tuna");
  // the config as the installer moved it: every path still names the old directory
  const moved = { ...cfg, directory: path.join(old, "state"), shield: { ...cfg.shield, policyFile: path.join(old, "policy.json") },
    apps: cfg.apps.map((a) => ({ ...a, expectedFile: path.join(old, a.deploymentId, "expected.json") })) };
  fs.writeFileSync(path.join(w.agentDir, "privacy-config.json"), JSON.stringify(moved));
  assert.equal((await w.enroll.pass()).changed, true);
  const after = w.read();
  assert.equal(after.directory, path.join(w.agentDir, "state"));
  assert.equal(after.shield.policyFile, w.config.policyFile);
  assert.equal(after.apps[0].expectedFile, path.join(w.agentDir, D, "expected.json"));
  assert.equal(w.restarts(), 1, "the state directory changed: one restart");
  assert.equal((await w.enroll.pass()).changed, false, "settled");
  assert.equal(w.restarts(), 1);
});

test("an operator's hostEgress block is kept across passes (not replaced, no restart); a malformed one is dropped", async () => {
  const w = world();
  await w.enroll.pass();
  const cfg = w.read(), he = { apps: [D], own: ["203.0.113.7"] };
  fs.writeFileSync(path.join(w.agentDir, "privacy-config.json"), JSON.stringify({ ...cfg, enclaveNetwork: { ...cfg.enclaveNetwork, hostEgress: he } }));
  assert.equal((await w.enroll.pass()).changed, false, "nothing to change");
  assert.deepEqual(w.read().enclaveNetwork.hostEgress, he);
  assert.equal(w.restarts(), 0);
  fs.writeFileSync(path.join(w.agentDir, "privacy-config.json"), JSON.stringify({ ...cfg, enclaveNetwork: { ...cfg.enclaveNetwork, hostEgress: { apps: ["not-an-id"] } } }));
  await w.enroll.pass();
  assert.equal(w.read().enclaveNetwork.hostEgress, undefined, "a malformed block is not carried");
  const all = { apps: "all", own: ["203.0.113.7"] };
  fs.writeFileSync(path.join(w.agentDir, "privacy-config.json"), JSON.stringify({ ...w.read(), enclaveNetwork: { ...w.read().enclaveNetwork, hostEgress: all } }));
  await w.enroll.pass();
  assert.deepEqual(w.read().enclaveNetwork.hostEgress, all, "apps: \"all\" is the agent's shape too");
});

test("an operator's paceMbps is kept across passes (no restart); a bad value is dropped", async () => {
  const w = world();
  await w.enroll.pass();
  const cfg = w.read();
  fs.writeFileSync(path.join(w.agentDir, "privacy-config.json"), JSON.stringify({ ...cfg, enclaveNetwork: { ...cfg.enclaveNetwork, paceMbps: 90 } }));
  assert.equal((await w.enroll.pass()).changed, false, "nothing to change");
  assert.equal(w.read().enclaveNetwork.paceMbps, 90);
  assert.equal(w.restarts(), 0);
  for (const bad of [-1, 0, 200000, "90", null]) {
    fs.writeFileSync(path.join(w.agentDir, "privacy-config.json"), JSON.stringify({ ...cfg, enclaveNetwork: { ...cfg.enclaveNetwork, paceMbps: bad } }));
    await w.enroll.pass();
    assert.equal(w.read().enclaveNetwork.paceMbps, undefined, `${JSON.stringify(bad)} is not carried`);
  }
});

test("the agent's chain RPCs follow the node's list: a changed list is written once and restarts the agent once", async () => {
  const w = world();
  await w.enroll.pass();
  assert.deepEqual(w.read().chain.rpc, ["https://rpc"], "a fresh config takes the node's list");
  const before = w.restarts();
  w.config.chainRpc = ["https://base-rpc.publicnode.com", "https://base.gateway.tenderly.co", "https://base-public.nodies.app"];
  await w.enroll.pass();
  assert.deepEqual(w.read().chain.rpc, w.config.chainRpc);
  assert.equal(w.restarts(), before + 1, "one restart for the new list");
  assert.ok(w.logs.some((m) => /chain RPCs now base-rpc\.publicnode\.com, base\.gateway\.tenderly\.co, base-public\.nodies\.app/.test(m)));
  await w.enroll.pass();
  assert.equal(w.restarts(), before + 1, "settled: no more restarts");
  w.config.chainRpc = ["https://only-one"];
  await w.enroll.pass();
  assert.deepEqual(w.read().chain.rpc, ["https://base-rpc.publicnode.com", "https://base.gateway.tenderly.co", "https://base-public.nodies.app"],
    "a list too short for a 2-agreeing quorum is not applied");
});
