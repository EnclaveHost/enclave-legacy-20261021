// F3: per-spawn pinned Shield image selection (windows/vbslike/manager/shield-profile.mjs ImageLauncher, wmi-launcher.mjs
// imageRole, server.mjs images and role, main.mjs pins; windows/node/shield-startup.mjs startupImages and adoption).
// Interface: work/shield-image-selection-interface.txt ("F3 FINAL").
//
// FIXTURE, NOT HARDWARE. The launchers are the real WmiHyperVLauncher over injected PowerShell answers
// (fake-hyperv.mjs), which answer each image's hash by its path. No IGVM is loaded, no partition runs, and the candidate
// image named in the interface is not used or pinned here.
//   run: node --test --test-concurrency=1 test/windows-shield-image-selection.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import { spawn as nodeSpawn } from "node:child_process";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { Manager, startManager } from "../windows/vbslike/manager/server.mjs";
import { HyperVPartitionBackend } from "../windows/vbslike/manager/backend.mjs";
import { WmiHyperVLauncher, notesFor, parseNotes, MANAGER_NOTES_PREFIX } from "../windows/vbslike/manager/wmi-launcher.mjs";
import { ImageLauncher } from "../windows/vbslike/manager/shield-profile.mjs";
import { TYPE1, PREFLIGHT_OK, defineAnswer, keyOf, startAndReadAnswer } from "../windows/vbslike/manager/fake-hyperv.mjs";
import { derive } from "../windows/vbslike/manager/derive.mjs";
import { isolationPlan, BACKEND } from "../windows/vbslike/datapath/node-bridge.mjs";
import { preparePackage } from "../sdk/bootstrap/package.mjs";
import { runtimeId as runtimeIdOf } from "../isolation/contract/runtime.mjs";
import { startupAdoptionRefusal, startupImages, createShieldStartup } from "../windows/node/shield-startup.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VEC = JSON.parse(fs.readFileSync(path.join(HERE, "../isolation/contract/catalog/derive_vectors.json"), "utf8"));
const COMPONENT = Buffer.from(VEC.component_hex, "hex"), REC = VEC.ok[0].mapping.record;
const LEGACY = "4c".repeat(32), DIRECT = "d1".repeat(32), DIRECT2 = "d2".repeat(32);
const LEGACY_PATH = "C:\\enclave\\legacy.igvm", DIRECT_PATH = "C:\\enclave\\shield-direct.igvm";
const DEP = (n) => "0x" + n.toString(16).padStart(2, "0").repeat(32);
const RT = (version) => ({ name: "wasmtime", version, execution: "jit", targetIsa: "x86_64", hostIsa: "x86_64", cpuFeatures: "baseline", wx: "enforced", cache: "none" });
const hex = (rt) => Buffer.from(runtimeIdOf(rt)).toString("hex");

/** Injected PowerShell answers: each image's hash by its path (`disk` overrides), one fresh VM id per define. */
function hyperv({ disk = {}, survey = () => ({ vms: [] }) } = {}) {
  const seen = [];
  const run = async (script) => {
    const k = keyOf(script); seen.push({ k, script });
    const sha = script.includes(DIRECT_PATH) ? (disk.direct ?? DIRECT) : (disk.legacy ?? LEGACY);
    const a = k === "preflight" ? { ...PREFLIGHT_OK, egressService: true, packageService: true }
      : k === "imageHash" ? { present: true, sha256: sha, bytes: 1 }
      : k === "define" ? defineAnswer(script, { id: crypto.randomUUID() })
      : k === "startAndRead" ? startAndReadAnswer(() => undefined)
      : k === "removeById" ? { found: true, removed: true }
      : k === "retire" ? { present: true, retired: true }
      : k === "survey" ? survey()
      : { ok: true };
    return { code: 0, stdout: JSON.stringify(a), stderr: "" };
  };
  return { run, seen, defines: () => seen.filter((x) => x.k === "define").map((x) => x.script), count: (k) => seen.filter((x) => x.k === k).length };
}
function launchers(h, { packageHook = null, directSha = DIRECT } = {}) {
  const events = [];
  const egress = (role) => async (vmId, dep, mapping, { bootstrap = false } = {}) => {
    if (!bootstrap && !["enclave-catalog-bundle/6", "enclave-catalog-bundle/7"].includes(mapping?.record?.derivation)) return null;
    events.push(`${role} egress`); return { exited: new Promise(() => {}), stop: async () => { events.push(`${role} egress stop`); } };
  };
  const legacy = new WmiHyperVLauncher({ run: h.run, imagePath: LEGACY_PATH, imageSha256: LEGACY, prefix: "enclave-app-t-", ...TYPE1,
    startEgress: egress("legacy"), egressService: "000024e3-facb-11e6-bd58-64006a7986d3" });
  const shieldDirect = new WmiHyperVLauncher({ run: h.run, imagePath: DIRECT_PATH, imageSha256: directSha, prefix: "enclave-app-t-", ...TYPE1, imageRole: "shield-direct",
    startEgress: egress("direct"), egressService: "000024e3-facb-11e6-bd58-64006a7986d3", packageService: "000024e6-facb-11e6-bd58-64006a7986d3",
    startPackage: packageHook || (async (vmId) => { events.push("direct package"); return { exited: new Promise(() => {}), stop: async () => { events.push("direct package stop"); } }; }) });
  return { launcher: new ImageLauncher({ legacy, shieldDirect }), legacy, shieldDirect, events };
}
async function managerOver(launcher, { legacyRid = REC.runtimeId, directRid = REC.runtimeId, directSha = DIRECT, judgeReady = null, runtime = null, directRuntime = null } = {}) {
  const m = new Manager({ runtimeId: runtime ? "" : legacyRid, runtime, fetchComponent: async () => COMPONENT, directBootstrap: true, configEnabled: true, secretsEnabled: true,
    fetchConfig: async () => Buffer.from("{}"), egress: { enabled: true, mode: "socks" },
    images: { legacy: { igvmSha256: LEGACY }, shieldDirect: directRuntime ? { runtime: directRuntime, igvmSha256: directSha } : { runtimeId: directRid, igvmSha256: directSha } },
    backend: new HyperVPartitionBackend(typeof launcher === "function" ? { launch: launcher } : { launcher }), judgeReady });
  await startManager(m);
  return m;
}
/** Spawn bodies the node would send: a plain V1, a relay-secret V6 (no package), a public V1 package. */
const v1 = (name, rid = REC.runtimeId) => ({ image: `ipfs://${REC.cid}`, name, cpuShare: 0.1, gpuShare: 0, appPort: 8080, ports: [], config: "", configCid: "", egress: "",
  derive: { ...REC, runtimeId: rid }, isPublic: true, hasSecrets: false });
function v6(name) {
  const plan = isolationPlan({ deploymentId: name, deployment: { cpuMilli: 250, gpuMilli: 0, isPublic: true }, version: { appId: REC.catalog.app, index: REC.catalog.version, cid: REC.cid, memMb: 512, ports: "", config: "" },
    appConfig: '{"api":"https://api.example"}', hasSecrets: true, waf: {}, volumes: [], runtimeId: REC.runtimeId, require: BACKEND,
    manager: { backend: BACKEND, catalog: { derivations: ["enclave-catalog-bundle/6"] }, supports: { config: true, secrets: true }, runtime: {} }, appConfigCid: "", configSourceCid: "" });
  assert.equal(plan.ok, true, JSON.stringify(plan));
  return plan.spawn;
}
function v1package(name, rid = REC.runtimeId) {
  const body = v1(name, rid);
  const appId = derive({ record: body.derive, component: COMPONENT }).appId;
  const p = preparePackage({ version: 1, chainId: 8453, ledger: "0x" + "d0".repeat(20), deployment: name, owner: "0x" + "33".repeat(20),
    appRef: `catalog://${REC.catalog.app}/${REC.catalog.version}`, appId, runtimeId: rid, configText: "", secretsMode: "public" });
  return { ...body, bootstrap: p.bytes.toString("base64"), sha256: p.sha256 };
}
const strip = ({ sha256, ...b }) => b;

// ---- 1. the router and the launchers' own refusals -------------------------------------------------------------------------
test("ImageLauncher: a package -> Shield-direct, inference -> GPU, everything else (witness, public, relay secrets) -> legacy; never another", async () => {
  const calls = [];
  const spy = (role) => ({ imageRole: role, start: async (mapping, opts) => { calls.push([role, opts.name ?? opts.identity?.name]); return { imageRole: role }; },
                           preflight: async () => ({ ok: role !== "shield-direct" || spy.directOk !== false, checks: [{ name: "x", ok: true }, ...(role === "shield-direct" ? [{ name: "hv_sock 9446", ok: spy.directOk !== false }] : [])] }),
                           survey: async () => ({ vms: [role] }), stop: async () => role, teardown: async () => role });
  const L = new ImageLauncher({ legacy: spy("legacy"), shieldDirect: spy("shield-direct"), gpu: spy("gpu") });
  const plain = { record: { derivation: "enclave-catalog-bundle/1" } };
  await L.start(plain, { identity: { name: "shield-readiness-v1" } });                        // the readiness witness
  await L.start(plain, { identity: { name: "public" } });
  await L.start({ record: { derivation: "enclave-catalog-bundle/6" } }, { identity: { name: "relay-secret" } });
  await L.start(plain, { identity: { name: "package" }, bootstrap: Buffer.from("{}") });
  await L.start({ record: { derivation: "enclave-catalog-bundle/6" } }, { identity: { name: "custody" }, bootstrap: Buffer.from("{}"), custody: {} });
  await L.start({ record: { inference: { model: "m" } } }, { identity: { name: "gpu" } });
  assert.deepEqual(calls, [["legacy", "shield-readiness-v1"], ["legacy", "public"], ["legacy", "relay-secret"], ["shield-direct", "package"], ["shield-direct", "custody"], ["gpu", "gpu"]]);
  await assert.rejects(L.start({ record: { inference: {} } }, { bootstrap: Buffer.from("{}") }), /does not start a GPU inference domain/);
  // a missing image only ever refuses: never a fallback to another image
  const legacyOnly = new ImageLauncher({ legacy: spy("legacy") });
  await assert.rejects(legacyOnly.start(plain, { bootstrap: Buffer.from("{}") }), /no Shield-direct image: an owner-committed package is refused, never started on another image/);
  await assert.rejects(legacyOnly.start({ record: { inference: {} } }, {}), /no GPU image/);
  assert.equal(calls.length, 6, "nothing started for a refusal");
  assert.equal(await L.stop({}), "legacy", "stop is by VM id, image-independent"); assert.deepEqual(await L.survey(), { vms: ["legacy"] });
  // preflight carries the direct image's own facts, and a failing one stops canStart
  spy.directOk = false;
  const pre = await L.preflight();
  assert.equal(pre.ok, false); assert.ok(pre.checks.some((c) => c.name === "shield-direct image: hv_sock 9446" && c.ok === false));
  assert.throws(() => new ImageLauncher({ legacy: spy("legacy"), shieldDirect: spy("legacy") }), /must be pinned as imageRole shield-direct/);
  assert.throws(() => new ImageLauncher({ legacy: spy("shield-direct") }), /must be pinned as imageRole legacy/);
});

test("the launchers: Shield-direct starts only packages and legacy never does, before any PowerShell; Notes carry the role", async () => {
  const run = async () => { throw new Error("no PowerShell may run for a refused start"); };
  const m = { appId: "aa".repeat(32), record: { policy: { vcpus: 1, memMiB: 512 } } };
  const base = { run, imagePath: "C:\\x.bin", imageSha256: DIRECT, ...TYPE1 };
  const direct = new WmiHyperVLauncher({ ...base, imageRole: "shield-direct", startEgress: async () => ({}), startPackage: async () => ({}) });
  await assert.rejects(direct.start(m, { instanceId: "dep0001-aaaa" }), /starts only owner-committed packages/);
  await assert.rejects(new WmiHyperVLauncher(base).start(m, { instanceId: "dep0001-aaaa", bootstrap: Buffer.from("{}") }), /starts only on the Shield-direct image, and this launcher's image is legacy/);
  await assert.rejects(new WmiHyperVLauncher({ ...base, imageRole: "gpu" }).start(m, { instanceId: "dep0001-aaaa", bootstrap: Buffer.from("{}") }), /this launcher's image is gpu/);
  assert.throws(() => new WmiHyperVLauncher({ ...base, startPackage: async () => ({}) }), /only the Shield-direct image carries/);
  assert.throws(() => new WmiHyperVLauncher({ ...base, imageRole: "direct" }), /imageRole must be one of/);
  // a legacy VM's Notes are byte-for-byte what they were; a direct one's carry its role; absent means legacy
  const id = { id: "hv" + "1".repeat(32), name: DEP(0xa1), instanceId: "hv1111-deadbeef", appId: "ab".repeat(32) };
  assert.equal(notesFor(id), MANAGER_NOTES_PREFIX + Buffer.from(JSON.stringify({ v: 1, ...id })).toString("base64url"));
  assert.equal(notesFor({ ...id, imageRole: "legacy" }), notesFor(id));
  assert.equal(parseNotes(notesFor({ ...id, imageRole: "shield-direct" })).identity.imageRole, "shield-direct");
  assert.throws(() => notesFor({ ...id, imageRole: "other" }), /imageRole/);
});

// ---- 2. the manager, over both real launchers -------------------------------------------------------------------------------
test("routing: legacy public and relay-secret V6 on the legacy image, a package on the Shield-direct image, with EQUAL RuntimeIDs", async () => {
  const h = hyperv(), { launcher, events } = launchers(h);
  const m = await managerOver(launcher);                                                       // both images pin REC.runtimeId
  const a = await m.spawn(v1(DEP(0xa1)));
  const b = await m.spawn(v6(DEP(0xa2)));
  const pkg = v1package(DEP(0xa3));
  const c = await m.spawn(strip(pkg));
  for (const r of [a, b, c]) assert.equal(r.status, "starting", r.reason);
  assert.deepEqual([a.imageRole, b.imageRole, c.imageRole], ["legacy", "legacy", "shield-direct"]);
  assert.deepEqual([a.igvmSha256, b.igvmSha256, c.igvmSha256], [LEGACY, LEGACY, DIRECT], "each launcher's own hash at this start");
  const defs = h.defines();
  assert.ok(defs[0].includes(LEGACY_PATH) && defs[1].includes(LEGACY_PATH) && defs[2].includes(DIRECT_PATH), "each VM is defined on its own image");
  assert.ok(!defs[0].includes(DIRECT_PATH) && !defs[2].includes(LEGACY_PATH));
  assert.deepEqual(events, ["legacy egress", "direct egress", "direct package"], "relay secrets keep the legacy egress path; only the package spawn gets a package");
  assert.equal(c.bootstrapSha256, pkg.sha256);
  const h1 = m.health();
  assert.deepEqual(h1.images, { legacy: { igvmSha256: LEGACY, runtimeId: REC.runtimeId },
    shieldDirect: { igvmSha256: DIRECT, runtimeId: REC.runtimeId, starts: ["public enclave-catalog-bundle/1 or /5"] }, gpu: null });
  assert.equal(h1.catalog.runtimeId, REC.runtimeId, "the top-level runtime stays the legacy image's");
  assert.equal(h1.supports.directBootstrap, true);
});

test("the RuntimeID pin is per image: a package must commit the Shield-direct one, a legacy spawn the legacy one", async () => {
  const OTHER = "ee".repeat(32);
  const h = hyperv(), { launcher } = launchers(h);
  const m = await managerOver(launcher, { directRid: OTHER });
  await assert.rejects(m.spawn(strip(v1package(DEP(0xb1)))), /this host's Shield-direct image runs e/, "a package on the legacy RuntimeID is refused");
  await assert.rejects(m.spawn(v1(DEP(0xb2), OTHER)), /this host runs cdcd/, "a legacy spawn on the direct RuntimeID is refused");
  assert.equal(h.count("define"), 0, "nothing was defined for either");
  const ok = await m.spawn(strip(v1package(DEP(0xb3), OTHER)));
  assert.equal(ok.imageRole, "shield-direct"); assert.equal(ok.status, "starting", ok.reason);
  assert.equal((await m.spawn(v1(DEP(0xb4)))).imageRole, "legacy");
});

test("wrong image, wrong config, wrong hash: refused or failed, and nothing is left running", async () => {
  // the direct IGVM on disk is not its pin: the launcher refuses before any VM is defined
  let h = hyperv({ disk: { direct: DIRECT2 } }), L = launchers(h);
  let m = await managerOver(L.launcher);
  const bad = await m.spawn(strip(v1package(DEP(0xc1))));
  assert.equal(bad.status, "failed"); assert.match(bad.reason, /guest image sha256 is d2.*expected d1/);
  assert.equal(h.count("define"), 0);
  // the launcher is pinned to another image than the manager's Shield-direct pin: the VM is started, then failed at once and
  // left for DELETE, which removes it; the package path is stopped with it
  h = hyperv({ disk: { direct: DIRECT2 } }); L = launchers(h, { directSha: DIRECT2 });
  m = await managerOver(L.launcher);
  const wrong = await m.spawn(strip(v1package(DEP(0xc2))));
  assert.equal(wrong.status, "failed"); assert.match(wrong.reason, /runs IGVM d2.*not the pinned Shield-direct image d1/);
  assert.equal(wrong.igvmSha256, DIRECT2);
  assert.deepEqual(await m.remove(wrong.id), { removed: true, absent: false });
  assert.equal(h.count("removeById"), 1); assert.ok(L.events.includes("direct package stop") && L.events.includes("direct egress stop"));
  // a Shield-direct launcher configured without its package path: refused before any VM
  h = hyperv();
  const direct = new WmiHyperVLauncher({ run: h.run, imagePath: DIRECT_PATH, imageSha256: DIRECT, prefix: "enclave-app-t-", ...TYPE1, imageRole: "shield-direct" });
  m = await managerOver(new ImageLauncher({ legacy: launchers(h).legacy, shieldDirect: direct }));
  const noHook = await m.spawn(strip(v1package(DEP(0xc3))));
  assert.equal(noHook.status, "failed"); assert.match(noHook.reason, /needs this launcher's package transport and egress/);
  assert.equal(h.count("define"), 0);
  // the manager's own pins: distinct from the legacy image, both present
  assert.throws(() => new Manager({ directBootstrap: true, images: { legacy: { igvmSha256: DIRECT }, shieldDirect: { runtimeId: REC.runtimeId, igvmSha256: DIRECT } } }), /distinct from the legacy image/);
  assert.throws(() => new Manager({ directBootstrap: true, images: { shieldDirect: { igvmSha256: DIRECT } } }), /its own pinned Shield-direct image/);
  assert.throws(() => new Manager({ directBootstrap: true }), /its own pinned Shield-direct image/);
});

test("failure cleanup: a package path that cannot start fails the start and removes the VM by its Id; legacy is untouched", async () => {
  const h = hyperv();
  const L = launchers(h, { packageHook: async () => { throw new Error("the package bridge exited (2): Os { code: 10013 }"); } });
  const m = await managerOver(L.launcher);
  const r = await m.spawn(strip(v1package(DEP(0xd1))));
  assert.equal(r.status, "failed"); assert.match(r.reason, /10013/);
  assert.equal(h.count("removeById"), 1, "the direct VM is removed");
  assert.ok(L.events.includes("direct egress stop"), "and its egress path stopped");
  const ok = await m.spawn(v1(DEP(0xd2)));
  assert.equal(ok.status, "starting"); assert.equal(ok.imageRole, "legacy");
});

test("readiness is judged against the selected image's runtime identity, never the other's", async () => {
  const RT_L = RT("48.0.1"), RT_D = RT("48.0.1-direct");
  const asked = [];
  const launch = async (mapping, opts) => ({ stop: async () => {}, tcpPort: 19001, launcherKey: "K", launcherVmId: crypto.randomUUID(), appReady: false,
    ...(opts.bootstrap ? { imageRole: "shield-direct", firmware: { sha256: DIRECT } } : { imageRole: "legacy", firmware: { sha256: LEGACY } }) });
  const m = await managerOver(launch, { runtime: RT_L, directRuntime: RT_D,
    judgeReady: async (a) => { asked.push(a.expectRuntime); return { status: "running", transportKeySha256: "cd".repeat(32), checks: {} }; } });
  const l = await m.spawn(v1(DEP(0xe1), hex(RT_L))); await m.judging.get(l.id);
  const d = await m.spawn(strip(v1package(DEP(0xe2), hex(RT_D)))); await m.judging.get(d.id);
  assert.deepEqual(asked, [RT_L, RT_D]);
  assert.equal(m.get(d.id).status, "running");
  assert.equal(m.health().images.shieldDirect.runtimeId, hex(RT_D), "derived from the identity, never configured");
});

test("a launcher that states another image than the one admitted is a contract break: the domain fails, the VM is left for DELETE", async () => {
  let stated = "shield-direct";
  const stops = [];
  const m = await managerOver(async () => ({ imageRole: stated, firmware: { sha256: stated === "shield-direct" ? DIRECT : LEGACY }, vmId: crypto.randomUUID(),
                                             stop: async () => { stops.push(stated); } }));
  const r = await m.spawn(v1(DEP(0xe5)));                        // a legacy spawn, started on the Shield-direct image
  assert.equal(r.status, "failed"); assert.match(r.reason, /started a legacy spawn on the shield-direct image/);
  assert.deepEqual(await m.remove(r.id), { removed: true, absent: false }); assert.equal(stops.length, 1, "DELETE stops what was started");
  stated = "gpu";
  const g = await m.spawn(strip(v1package(DEP(0xe6))));           // a package on any other image
  assert.equal(g.status, "failed"); assert.match(g.reason, /on the gpu image, not the Shield-direct one/);
  stated = "legacy";
  assert.equal((await m.spawn(v1(DEP(0xe7)))).status, "starting", "the honest statement is served as before");
});

test("recovery: a restarted manager attributes each VM to its image from the Notes (absent = legacy); neither serves", async () => {
  const idL = { id: "hv" + "1".repeat(32), name: DEP(0xf1), instanceId: "hv1111-aaaa", appId: "ab".repeat(32) };
  const idD = { id: "hv" + "2".repeat(32), name: DEP(0xf2), instanceId: "hv2222-bbbb", appId: "ab".repeat(32) };
  const h = hyperv({ survey: () => ({ vms: [{ vmId: crypto.randomUUID(), name: "enclave-app-t-hv1111-aaaa", state: "Running", notes: notesFor(idL) },
                                           { vmId: crypto.randomUUID(), name: "enclave-app-t-hv2222-bbbb", state: "Off", notes: notesFor({ ...idD, imageRole: "shield-direct" }) }] }) });
  const m = await managerOver(launchers(h).launcher);
  const byName = Object.fromEntries(m.list().map((r) => [r.name, r]));
  assert.equal(byName[DEP(0xf1)].imageRole, "legacy"); assert.equal(byName[DEP(0xf2)].imageRole, "shield-direct");
  for (const r of Object.values(byName)) { assert.equal(r.recovered, true); assert.equal(r.status, "starting"); assert.equal(r.appReady, false); }
  await assert.rejects(m.spawn(strip(v1package(DEP(0xf2)))), (e) => e.status === 409, "the recovered VM blocks a second spawn; the node retires it first");
  assert.equal(h.count("define"), 0);
});

// ---- 3. the node: its own pins, adoption across images -----------------------------------------------------------------------
test("node pins: both or neither; explicit legacy-public excludes the direct pins and independent mode", () => {
  assert.deepEqual(startupImages({}), { direct: null, legacyPublic: false });
  assert.deepEqual(startupImages({ ENCLAVE_ISOLATION_DIRECT_RUNTIME_ID: "CD".repeat(32), ENCLAVE_ISOLATION_DIRECT_IMAGE_SHA256: DIRECT }),
                   { direct: { runtimeId: "cd".repeat(32), imageSha256: DIRECT }, legacyPublic: false });
  assert.deepEqual(startupImages({ ENCLAVE_STARTUP_LEGACY_PUBLIC: "1" }), { direct: null, legacyPublic: true });
  assert.throws(() => startupImages({ ENCLAVE_ISOLATION_DIRECT_RUNTIME_ID: "cd".repeat(32) }), /together/, "a RuntimeID alone does not tell equal-RuntimeID images apart");
  assert.throws(() => startupImages({ ENCLAVE_ISOLATION_DIRECT_IMAGE_SHA256: DIRECT }), /together/);
  assert.throws(() => startupImages({ ENCLAVE_STARTUP_LEGACY_PUBLIC: "1", ENCLAVE_ISOLATION_DIRECT_RUNTIME_ID: "cd".repeat(32), ENCLAVE_ISOLATION_DIRECT_IMAGE_SHA256: DIRECT }), /never has a legacy fallback/);
  assert.throws(() => startupImages({ ENCLAVE_STARTUP_LEGACY_PUBLIC: "1", ENCLAVE_IDENTITY_MODE: "independent" }), /independent host/);
  assert.throws(() => startupImages({ ENCLAVE_STARTUP_LEGACY_PUBLIC: "yes" }), /1 or unset/);
  const base = { reader: { agreed: async () => ({}) }, pins: { deployments: "0x" + "d0".repeat(20), appCatalog: "0x" + "c0".repeat(20) }, gateways: ["https://r.example"],
                 fetchComponent: async () => COMPONENT, abis: { DEP_ABI: [], CATALOG_ABI: [] } };
  assert.throws(() => createShieldStartup({ ...base, legacyPublic: true, direct: { runtimeId: "cd".repeat(32), imageSha256: DIRECT } }), /exclusive/);
  assert.throws(() => createShieldStartup({ ...base, direct: { runtimeId: "cd".repeat(32) } }), /both or neither/);
});

test("adoption is role + package hash + this node's image pin: nothing is adopted across images", () => {
  const s = { appId: "aa".repeat(32), runtimeId: "bb".repeat(32), sha256: "5e".repeat(32) };
  const direct = { ...s, direct: true, imageRole: "shield-direct", imageSha256: DIRECT };
  const legacyPublic = { ...s, direct: false, imageRole: "legacy", imageSha256: null };
  const v = { appId: s.appId, runtimeId: s.runtimeId, bootstrapSha256: s.sha256 };
  assert.equal(startupAdoptionRefusal({ ...v, imageRole: "shield-direct", igvmSha256: DIRECT }, direct), null);
  assert.match(startupAdoptionRefusal({ ...v, imageRole: "legacy", igvmSha256: LEGACY }, direct), /on the legacy image, not the Shield-direct image/);
  assert.match(startupAdoptionRefusal({ ...v }, direct), /on the legacy image/, "a view stating no role is legacy");
  assert.match(startupAdoptionRefusal({ ...v, imageRole: "shield-direct", igvmSha256: DIRECT2 }, direct), /not this host's pinned Shield-direct image/, "the manager's hash is compared, never adopted");
  assert.match(startupAdoptionRefusal({ ...v, imageRole: "shield-direct", igvmSha256: DIRECT, bootstrapSha256: "00".repeat(32) }, direct), /holds startup package/);
  assert.equal(startupAdoptionRefusal({ appId: s.appId, runtimeId: s.runtimeId, imageRole: "legacy" }, legacyPublic), null);
  assert.match(startupAdoptionRefusal({ ...v, imageRole: "shield-direct", igvmSha256: DIRECT }, legacyPublic), /legacy-public/);
});

// ---- 4. the entry point: distinct explicit direct pins or nothing ------------------------------------------------------------
function runMain(env, ms = 4000) {
  return new Promise((resolve) => {
    const p = nodeSpawn(process.execPath, [path.join(HERE, "../windows/vbslike/manager/main.mjs")], { env: { ...process.env, VMMGR_PORT: "0", ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => { out += d; }); p.stderr.on("data", (d) => { err += d; });
    const timer = setTimeout(() => { p.kill(); resolve({ code: null, out, err, timedOut: true }); }, ms);
    p.on("close", (code) => { clearTimeout(timer); resolve({ code, out, err, timedOut: false }); });
  });
}
test("main.mjs: ENCLAVE_SHIELD_DIRECT=1 needs its own distinct image, hash and runtime identity; the legacy image is never relabelled", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "image-selection-")); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const exe = path.join(dir, "egress.exe"), bridge = path.join(dir, "bridge.exe"), idL = path.join(dir, "legacy.json"), idD = path.join(dir, "direct.json");
  fs.writeFileSync(exe, "egress (fixture)"); fs.writeFileSync(bridge, "bridge (fixture)");
  fs.writeFileSync(idL, JSON.stringify(RT("48.0.1"))); fs.writeFileSync(idD, JSON.stringify(RT("48.0.1")));     // equal identities: legal
  const sha = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
  const env = { ENCLAVE_RUNTIME_IDENTITY: idL, ENCLAVE_EGRESS_V1: "1", ENCLAVE_EGRESS_EXE: exe, ENCLAVE_EGRESS_EXE_SHA256: sha(exe), ENCLAVE_EGRESS_BRIDGE_EXE: bridge,
                ENCLAVE_EGRESS_BRIDGE_EXE_SHA256: sha(bridge), ENCLAVE_EGRESS_SOCKS: "127.0.0.1:30489", ENCLAVE_BOOT_FORM: "linux-direct",
                ENCLAVE_GUEST_IGVM: LEGACY_PATH, ENCLAVE_GUEST_IGVM_SHA256: LEGACY, ENCLAVE_SHIELD_DIRECT: "1",
                ENCLAVE_SHIELD_DIRECT_IGVM: DIRECT_PATH, ENCLAVE_SHIELD_DIRECT_IGVM_SHA256: DIRECT, ENCLAVE_SHIELD_DIRECT_RUNTIME_IDENTITY: idD };
  for (const [over, re] of [
    [{ ENCLAVE_SHIELD_DIRECT_IGVM: "", ENCLAVE_SHIELD_DIRECT_IGVM_SHA256: "", ENCLAVE_SHIELD_DIRECT_RUNTIME_IDENTITY: "" }, /needs ENCLAVE_SHIELD_DIRECT_IGVM, ENCLAVE_SHIELD_DIRECT_IGVM_SHA256 \(64 hex\), ENCLAVE_SHIELD_DIRECT_RUNTIME_IDENTITY/],
    [{ ENCLAVE_SHIELD_DIRECT_IGVM_SHA256: LEGACY }, /hash distinct from ENCLAVE_GUEST_IGVM_SHA256 \(the legacy image is never relabelled\)/],
    [{ ENCLAVE_SHIELD_DIRECT_IGVM: LEGACY_PATH }, /path distinct from ENCLAVE_GUEST_IGVM/],
    [{ ENCLAVE_GUEST_IGVM: "", ENCLAVE_GUEST_IGVM_SHA256: "" }, /the legacy image ENCLAVE_GUEST_IGVM and _SHA256/],
    [{ ENCLAVE_EGRESS_V1: "" }, /ENCLAVE_EGRESS_V1=1/],
    [{ ENCLAVE_SHIELD_DIRECT_RUNTIME_IDENTITY: path.join(dir, "absent.json") }, /Shield-direct runtime identity/]]) {
    const r = await runMain({ ...env, ...over });
    assert.equal(r.code, 2, `${JSON.stringify(over)}: ${r.err.slice(0, 200)}`); assert.match(r.err, re);
  }
  const on = await runMain(env);
  assert.ok(on.timedOut, `complete, it runs: ${on.err.slice(0, 300)}`);
  assert.match(on.out, new RegExp(`owner-committed startup ON, on its own image ${DIRECT} \\(RuntimeID ${hex(RT("48.0.1"))}.*the legacy image ${LEGACY} keeps every other spawn`));
  const off = await runMain({ ...env, ENCLAVE_SHIELD_DIRECT: "" });
  assert.ok(off.timedOut); assert.doesNotMatch(off.out, /owner-committed startup ON/);
});
