// The owner-committed startup package, carried into one Enclave Shield partition (windows/vbslike/manager/package-
// transport.mjs, server.mjs, wmi-launcher.mjs): the frame is the Linux guestd's byte for byte (the Go side pins the same
// hex: isolation/m2/front/shield_direct_test.go), the bytes reach only a partition whose spawn they commit (the manager's
// OWN AppID and RuntimeID, this deployment, no secrets, a public CPU app), only on a manager stating a Shield-direct image,
// and only through the pinned bridge for THIS partition's vsock 9446.   run: node --test test/windows-shield-package-transport.test.mjs
import { test, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import crypto from "node:crypto";
import { spawn as nodeSpawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { packageFrame, servePackage, startPackageTransport, PACKAGE_SERVICE_GUID, PACKAGE_VSOCK_PORT } from "../windows/vbslike/manager/package-transport.mjs";
import { bridgeAuthLine, mintBridgeCredential, BRIDGE_AUTH_FLAG } from "../windows/vbslike/manager/bridge-auth.mjs";
import { Manager, startManager } from "../windows/vbslike/manager/server.mjs";
import { HyperVPartitionBackend } from "../windows/vbslike/manager/backend.mjs";
import { WmiHyperVLauncher } from "../windows/vbslike/manager/wmi-launcher.mjs";
import { preparePackage } from "../sdk/bootstrap/package.mjs";
import { derive } from "../windows/vbslike/manager/derive.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FAKE = path.join(HERE, "../windows/vbslike/manager/testdata/fake-egress-child.mjs");
const VEC = JSON.parse(fs.readFileSync(path.join(HERE, "../isolation/contract/catalog/derive_vectors.json"), "utf8"));
const COMPONENT = Buffer.from(VEC.component_hex, "hex"), REC = VEC.ok[0].mapping.record;
const VM = "5db6d4eb-1619-4936-9d60-c7e3ca67f3a8", DEP = "0x" + "e7".repeat(32), DIRECT_IMG = "d1".repeat(32);
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
// the Go guest pins this exact hex for WritePackage(0xab.., `{"version":1}`)
const FRAME_VECTOR = "656e636c6230310aabababababababababababababababababababababababababababababababab0000000d7b2276657273696f6e223a317d";

// as the bridge connects (its per-start credential first: bridge-auth.mjs), or with no credential at all (any other local process)
const read = (port, credential = null) => new Promise((resolve, reject) => {
  const c = net.connect(port, "127.0.0.1", () => { if (credential) c.write(bridgeAuthLine(credential)); }), parts = [];
  c.on("data", (b) => parts.push(b)); c.on("close", () => resolve(Buffer.concat(parts))); c.on("error", () => {});
});

test("the frame is bootstrap.WritePackage's, byte for byte, and bounded like it", () => {
  assert.equal(packageFrame("0x" + "ab".repeat(32), Buffer.from('{"version":1}')).toString("hex"), FRAME_VECTOR);
  assert.equal(PACKAGE_SERVICE_GUID, `${PACKAGE_VSOCK_PORT.toString(16).padStart(8, "0")}-facb-11e6-bd58-64006a7986d3`);
  assert.throws(() => packageFrame("0x" + "00".repeat(32), Buffer.from("x")), /deployment id/);
  assert.throws(() => packageFrame("0xAB" + "ab".repeat(31), Buffer.from("x")), /deployment id/);
  assert.throws(() => packageFrame(DEP, Buffer.alloc(0)), /1\.\.131072/);
  assert.throws(() => packageFrame(DEP, Buffer.alloc(128 * 1024 + 1)), /1\.\.131072/);
});

test("the loopback server answers each connection with exactly the one frame, a bounded number of times", async () => {
  const frame = packageFrame(DEP, Buffer.from('{"version":1}'));
  const credential = mintBridgeCredential();
  const s = await servePackage(frame, { credential, maxServes: 2, authTimeoutMs: 300 });
  try {
    assert.equal((await read(s.port)).length, 0, "no credential: nothing, and no serve spent");
    assert.deepEqual(await read(s.port, credential), frame);
    assert.deepEqual(await read(s.port, credential), frame, "a guest restart reads it again");
    assert.equal((await read(s.port, credential)).length, 0, "past the bound: nothing");
  } finally { await s.close(); }
});

test("the pinned bridge for THIS partition's 9446, readiness and stop; a wrong pin starts nothing", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkg-transport-")), exe = path.join(dir, "shielded-bridge.exe");
  fs.writeFileSync(exe, "shielded-bridge bytes");
  const spawned = [];
  const spawn = (file, args, opts) => { spawned.push({ file, args }); return nodeSpawn(process.execPath, [FAKE, ...args], opts); };
  const bytes = Buffer.from('{"version":1}');
  const t = await startPackageTransport({ bridge: { exe, sha256: sha("shielded-bridge bytes") }, vmId: VM, deploymentId: DEP, bytes, spawn });
  try {
    assert.deepEqual(spawned[0].args, [VM, "9446", String(t.port), "0", BRIDGE_AUTH_FLAG], "the credential goes to stdin, never argv");
    assert.equal((await read(t.port)).length, 0, "a direct loopback reader (not the bridge) gets nothing");
    // the frame through the bridge, credential and all: test/windows-shield-local-auth.test.mjs (fixture relay bridge)
  } finally { await t.stop(); }
  await assert.rejects(startPackageTransport({ bridge: { exe, sha256: "00".repeat(32) }, vmId: VM, deploymentId: DEP, bytes, spawn }), /not its pin/);
  await assert.rejects(startPackageTransport({ bridge: { exe, sha256: sha("shielded-bridge bytes") }, vmId: "00000000-0000-0000-0000-000000000000", deploymentId: DEP, bytes, spawn }), /not a partition id/);
  assert.equal(spawned.length, 1, "a refused start spawned nothing");
});

// ---- the manager's gate -----------------------------------------------------------------------------------------------
const managers = [];
after(() => { for (const m of managers) m.close?.(); });
async function manager({ directBootstrap = true } = {}) {
  const seen = [];
  // a package spawn lands on the Shield-direct image (F3), which states its role and pinned IGVM; the rest on legacy
  const launch = async (mapping, opts) => { seen.push({ appId: mapping.appId, opts }); return { instanceId: opts.instanceId, appId: mapping.appId, stop: async () => {},
    ...(opts.bootstrap ? { imageRole: "shield-direct", firmware: { sha256: DIRECT_IMG } } : { imageRole: "legacy" }) }; };
  const m = new Manager({ runtimeId: REC.runtimeId, fetchComponent: async () => COMPONENT, directBootstrap, backend: new HyperVPartitionBackend({ launch }),
    ...(directBootstrap ? { images: { shieldDirect: { runtimeId: REC.runtimeId, igvmSha256: DIRECT_IMG } } } : {}),
    judgeReady: async () => ({ status: "running", transportKeySha256: "cd".repeat(32), checks: { document: { ok: true, verdict: "monitor-signed" }, ready: { ok: true } } }) });
  await startManager(m);
  return { m, seen };
}
const pkg = (over = {}) => preparePackage({ version: 1, chainId: 8453, ledger: "0x" + "d0".repeat(20), deployment: DEP, owner: "0x" + "33".repeat(20),
  appRef: `catalog://${REC.catalog.app}/${REC.catalog.version}`, appId: VEC.ok[0].mapping.appId, runtimeId: REC.runtimeId, configText: "", secretsMode: "public", ...over });
const body = (over = {}) => ({ image: `ipfs://${REC.cid}`, name: DEP, cpuShare: 0.1, gpuShare: 0, appPort: 8080, ports: [], config: "", configCid: "", egress: "",
  derive: REC, isPublic: true, hasSecrets: false, ...over });

test("a Shield-direct manager carries a package only when it commits THIS spawn's own derivation", async () => {
  const { m, seen } = await manager();
  assert.equal(m.health().supports.directBootstrap, true, "/health says so, for the node's choice");
  const p = pkg();
  await m.spawn(body({ bootstrap: p.bytes.toString("base64") }));
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0].opts.bootstrap, p.bytes, "the launcher gets the exact bytes");
  const rec = m.list().find((r) => r.name === DEP);
  assert.equal(rec.bootstrapSha256, p.sha256); assert.equal(rec.directBootstrap, true);
  assert.equal(JSON.stringify(m.list()).includes(p.bytes.toString("base64")), false, "the bytes are never listed");
  // each refusal before any launch
  const refused = async (b, re) => { const { m: x, seen: s } = await manager(); await assert.rejects(x.spawn(b), re); assert.equal(s.length, 0); };
  await refused(body({ bootstrap: pkg({ appId: "aa".repeat(32) }).bytes.toString("base64") }), /does not commit this spawn: startup appId mismatch/);
  await refused(body({ bootstrap: pkg({ runtimeId: "bb".repeat(32) }).bytes.toString("base64") }), /startup runtimeId mismatch/);
  await refused(body({ bootstrap: pkg({ deployment: "0x" + "e8".repeat(32) }).bytes.toString("base64") }), /startup deployment mismatch/);
  await refused(body({ hasSecrets: true, bootstrap: pkg().bytes.toString("base64") }), /no secrets|staged secrets/);
  await refused(body({ bootstrap: "not base64!" }), /canonical base64/);
  const { m: legacy, seen: s2 } = await manager({ directBootstrap: false });
  assert.equal(legacy.health().supports.directBootstrap, false);
  await assert.rejects(legacy.spawn(body({ bootstrap: pkg().bytes.toString("base64") })), /not a Shield-direct build/);
  assert.equal(s2.length, 0);
  // a spawn without a package is exactly as before, on either manager
  await legacy.spawn(body());
  assert.equal(s2[0].opts.bootstrap, undefined);
});

test("the launcher never starts a partition with a package it cannot carry, or without egress", async () => {
  const run = async () => { throw new Error("no PowerShell may run for a refused start"); };
  const l = new WmiHyperVLauncher({ run, imagePath: "C:\\x.bin", imageSha256: "ab".repeat(32), boot: "linux-direct" });
  await assert.rejects(l.start({ appId: "aa".repeat(32), record: { policy: { vcpus: 1, memMiB: 512 } } }, { instanceId: "dep0001-aaaa", bootstrap: Buffer.from("{}") }),
    /starts only on the Shield-direct image, and this launcher's image is legacy/);
  // the Shield-direct image without its hooks refuses the package too, before any PowerShell
  await assert.rejects(new WmiHyperVLauncher({ run, imagePath: "C:\\x.bin", imageSha256: "ab".repeat(32), boot: "linux-direct", imageRole: "shield-direct" })
    .start({ appId: "aa".repeat(32), record: { policy: { vcpus: 1, memMiB: 512 } } }, { instanceId: "dep0001-aaaa", bootstrap: Buffer.from("{}") }), /needs this launcher's package transport and egress/);
  assert.throws(() => new WmiHyperVLauncher({ run, imagePath: "C:\\x.bin", imageSha256: "ab".repeat(32), startPackage: "x" }), /startPackage must be a function/);
  assert.throws(() => new WmiHyperVLauncher({ run, imagePath: "C:\\x.bin", imageSha256: "ab".repeat(32), packageService: "nope" }), /service GUID/);
});
