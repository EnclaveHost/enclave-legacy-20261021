// Namespace separation between the production manager and a second, scoped manager instance on the same host (the
// hardware canary, work/shield-hardware-canary). A scoped instance (ENCLAVE_VM_PREFIX) has its own VM name prefix AND its
// own Notes marker (wmi-launcher.mjs markerFor). Checked in both directions:
//   - the INSTALLED production manager (release 2026.10.12.47 = commit c2bc3cc6, whose wmi-launcher.mjs hashes to the
//     installed file) does not survey, parse or own a canary VM;
//   - the new default manager behaves the same, and its default Notes and scripts are byte-identical to the installed ones;
//   - the canary instance does not survey, recover or own a production VM.
// Survey and ownership filters are evaluated from each version's own generated PowerShell. Fixture-only: no VM is touched.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as NEW from "../windows/vbslike/manager/wmi-launcher.mjs";
import { Manager } from "../windows/vbslike/manager/server.mjs";
import { HyperVPartitionBackend } from "../windows/vbslike/manager/backend.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url)), ROOT = path.join(HERE, "..");
const MAIN = path.join(ROOT, "windows/vbslike/manager/main.mjs");
const INSTALLED_COMMIT = "c2bc3cc6";
const INSTALLED_LAUNCHER_SHA256 = "33ef5f0e57755e596a50a11a256d8a4b831a90dfd4cda6a9699f8761be4a4592";
const CANARY = "enclave-canary-";
const CANARY_MARKER = NEW.markerFor(CANARY);
const S = (x) => (typeof x === "string" ? x : JSON.stringify(x));

/** The installed production launcher module: its files from git at c2bc3cc6, with its hash checked. Null if unavailable. */
async function loadInstalled() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "installed-manager-"));
  try {
    for (const f of ["manager/wmi-launcher.mjs", "manager/wmiserve-run.mjs", "manager/egress.mjs", "verify/boot-statements.mjs"]) {
      const out = path.join(dir, "windows/vbslike", f);
      fs.mkdirSync(path.dirname(out), { recursive: true });
      fs.writeFileSync(out, execFileSync("git", ["show", `${INSTALLED_COMMIT}:windows/vbslike/${f}`], { cwd: ROOT, maxBuffer: 16 << 20 }));
    }
  } catch { fs.rmSync(dir, { recursive: true, force: true }); return null; }
  const file = path.join(dir, "windows/vbslike/manager/wmi-launcher.mjs");
  const sha = crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  const mod = await import(pathToFileURL(file).href);
  return { mod, sha, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

/** Translate the filter of a generated Where-Object / ownership expression into a JS predicate over { name, notes }. */
function predicateOf(expr) {
  let js = expr
    .replace(/\(\[string\]\$(?:_|v)\.Notes\)\.StartsWith\('((?:[^']|'')*)'\)/g, (_, x) => `String(vm.notes).startsWith(${JSON.stringify(x.replace(/''/g, "'"))})`)
    .replace(/\$(?:_|v)\.Name\.StartsWith\('((?:[^']|'')*)'\)/g, (_, x) => `String(vm.name).startsWith(${JSON.stringify(x.replace(/''/g, "'"))})`)
    .replace(/\$(?:_|v)\.Notes -eq '((?:[^']|'')*)'/g, (_, x) => `(vm.notes === ${JSON.stringify(x.replace(/''/g, "'"))})`)
    .replace(/ -or /g, " || ").replace(/ -and /g, " && ");
  assert.doesNotMatch(js, /\$|-eq|-or|-and/, `untranslated PowerShell in: ${expr}`);
  return new Function("vm", `return (${js});`);
}
const surveyFilter = (script) => predicateOf(/Where-Object \{ (.*?) \}\);/s.exec(S(script))[1]);
const ownedFilter = (script) => predicateOf(/if \(-not (\(\$v\.Notes -eq .*?\))\) \{/s.exec(S(script))[1]);

const identity = (n) => ({ id: "hv" + String(n).repeat(32), name: "0x" + ("e" + n).repeat(32), instanceId: `hv${n}-x`, appId: "ab".repeat(32) });
const prodVm = (n) => ({ vmId: `${n}${n}${n}${n}${n}${n}${n}${n}-1111-4111-8111-111111111111`, name: `enclave-app-hv${n}-x`, state: "Running", notes: NEW.notesFor(identity(n)) });
const canaryVm = (n) => ({ vmId: `${n}${n}${n}${n}${n}${n}${n}${n}-2222-4222-8222-222222222222`, name: `${CANARY}hv${n}-x`, state: "Running",
                           notes: NEW.notesFor(identity(n), { marker: CANARY_MARKER }) });

test("markerFor: the default prefix keeps the production marker; a scoped prefix gets a marker outside production's namespace", () => {
  assert.equal(NEW.markerFor(NEW.DEFAULT_VM_PREFIX), NEW.OWNER_MARKER);
  assert.equal(CANARY_MARKER, "enclave-canary-vbslike-domain");
  assert.ok(!CANARY_MARKER.startsWith(NEW.OWNER_MARKER) && !NEW.notesPrefixFor(CANARY_MARKER).startsWith(NEW.MANAGER_NOTES_PREFIX));
  // a non-scoped constructor prefix keeps the production marker (main.mjs refuses such a prefix as ENCLAVE_VM_PREFIX)
  for (const other of ["enclave-app-t-", "canary-", "enclave-Canary-", "x"]) assert.equal(NEW.markerFor(other), NEW.OWNER_MARKER);
});

test("the INSTALLED production manager (c2bc3cc6) does not survey, parse or own a canary VM; default Notes and scripts are byte-identical", async (t) => {
  const old = await loadInstalled();
  if (!old) { t.skip(`git object ${INSTALLED_COMMIT} unavailable here`); return; }
  try {
    assert.equal(old.sha, INSTALLED_LAUNCHER_SHA256, "these are the installed release's exact rules");
    const O = old.mod;
    // byte compatibility of the default (production) instance with what is installed
    assert.equal(S(NEW.CMD.survey({ prefix: NEW.DEFAULT_VM_PREFIX })), S(O.CMD.survey({ prefix: NEW.DEFAULT_VM_PREFIX })));
    assert.equal(S(NEW.CMD.removeById({ vmId: "5db6d4eb-1619-4936-9d60-c7e3ca67f3a8" })), S(O.CMD.removeById({ vmId: "5db6d4eb-1619-4936-9d60-c7e3ca67f3a8" })));
    const id = identity(1);
    assert.equal(NEW.notesFor(id), O.notesFor(id), "legacy-role Notes unchanged");
    assert.deepEqual(NEW.parseNotes(O.notesFor(id)), O.parseNotes(O.notesFor(id)));
    // the installed rules against canary VMs: not surveyed, not parsed, not owned
    const survey = surveyFilter(O.CMD.survey({ prefix: NEW.DEFAULT_VM_PREFIX }));
    const owned = ownedFilter(O.CMD.removeById({ vmId: "5db6d4eb-1619-4936-9d60-c7e3ca67f3a8" }));
    for (const vm of [canaryVm(4), { ...canaryVm(5), name: "renamed-by-hand" }, { ...canaryVm(6), notes: CANARY_MARKER }]) {
      assert.equal(survey(vm), false, `installed survey must not match ${vm.name}`);
      assert.equal(owned(vm), false, `installed ownership must not hold for ${vm.name}`);
      assert.deepEqual(O.parseNotes(vm.notes), { owned: false, identity: null });
    }
    // ...while it still recognises production VMs as before
    assert.equal(survey(prodVm(1)), true); assert.equal(owned(prodVm(1)), true);
  } finally { old.cleanup(); }
});

test("both directions with the new code: default and canary surveys, ownership and parsing never cross", () => {
  const defSurvey = surveyFilter(NEW.CMD.survey({ prefix: NEW.DEFAULT_VM_PREFIX }));
  const defOwned = ownedFilter(NEW.CMD.removeById({ vmId: "x" }));
  const canSurvey = surveyFilter(NEW.CMD.survey({ prefix: CANARY, marker: CANARY_MARKER }));
  const canOwned = ownedFilter(NEW.CMD.removeById({ vmId: "x", marker: CANARY_MARKER }));
  const prods = [prodVm(1), { ...prodVm(2), name: "renamed-by-hand" }, { ...prodVm(3), notes: NEW.OWNER_MARKER }];
  const cans = [canaryVm(4), { ...canaryVm(5), name: "renamed-by-hand" }, { ...canaryVm(6), notes: CANARY_MARKER }];
  for (const vm of cans) {
    assert.equal(defSurvey(vm), false); assert.equal(defOwned(vm), false);
    assert.deepEqual(NEW.parseNotes(vm.notes), { owned: false, identity: null });
    assert.equal(canSurvey(vm), true); assert.equal(canOwned(vm), true);
  }
  for (const vm of prods) {
    assert.equal(canSurvey(vm), false, `canary survey must not match ${vm.name}`); assert.equal(canOwned(vm), false);
    assert.deepEqual(NEW.parseNotes(vm.notes, { marker: CANARY_MARKER }), { owned: false, identity: null });
    assert.equal(defSurvey(vm), true); assert.equal(defOwned(vm), true);
  }
  // every ownership-checking command of a canary launcher carries the canary marker only
  for (const s of [NEW.CMD.removeExact({ name: "n", marker: CANARY_MARKER }), NEW.CMD.teardown({ prefix: CANARY, requireMarker: true, marker: CANARY_MARKER }),
                   NEW.CMD.startAndRead({ vmId: "5db6d4eb-1619-4936-9d60-c7e3ca67f3a8", pipe: "\\\\.\\pipe\\canary-test", marker: CANARY_MARKER })])
    assert.ok(!S(s).includes(NEW.MANAGER_NOTES_PREFIX) && !S(s).includes(`'${NEW.OWNER_MARKER}'`), "no production marker in a canary script");
});

test("recovery: each manager recovers only its own VMs from a mixed host; a canary launcher stops only names in its scope", async () => {
  const vms = [prodVm(1), prodVm(2), { ...prodVm(3), name: "renamed-by-hand" }, canaryVm(4), { ...canaryVm(5), name: "renamed-by-hand-2" }];
  // a fake Hyper-V that evaluates each survey script's own filter
  const run = async (script) => {
    if (!/Get-VM \| Where-Object/.test(script)) return { code: 0, stdout: JSON.stringify({ ok: true }), stderr: "" };
    const f = surveyFilter(script);
    return { code: 0, stdout: JSON.stringify({ vms: vms.filter((v) => f(v)) }), stderr: "" };
  };
  const recovered = async (prefix) => {
    const launcher = new NEW.WmiHyperVLauncher({ run, imagePath: "C:\\img\\guest.igvm", imageSha256: "ab".repeat(32), prefix });
    const m = new Manager({ backend: new HyperVPartitionBackend({ launcher }), judgeReady: async () => ({ ok: false }), fetchComponent: async () => Buffer.alloc(0) });
    const inv = await m.recover();
    return { inv, launcher, ids: m.list().map((r) => r.id).sort() };
  };
  const prod = await recovered(NEW.DEFAULT_VM_PREFIX);
  assert.deepEqual([prod.inv.state, prod.inv.recovered, prod.inv.unattributed], ["ready", 3, 0]);
  assert.deepEqual(prod.ids, [identity(1).id, identity(2).id, identity(3).id].sort());
  const can = await recovered(CANARY);
  assert.deepEqual([can.inv.state, can.inv.recovered, can.inv.unattributed], ["ready", 2, 0]);
  assert.deepEqual(can.ids, [identity(4).id, identity(5).id].sort());
  assert.equal(can.launcher.marker, CANARY_MARKER);
  await assert.rejects(can.launcher.stop({ name: "enclave-app-hv1-x" }), /not in this instance's scope/);
});

function runMain(env, ms = 8000) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [MAIN], { env: { ...process.env, VMMGR_PORT: "0", ENCLAVE_MANAGER_PORT: "0", ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => { out += d; }); p.stderr.on("data", (d) => { err += d; });
    const t = setTimeout(() => { p.kill(); resolve({ code: null, out, err }); }, ms);
    p.on("close", (code) => { clearTimeout(t); resolve({ code, out, err }); });
  });
}
test("main.mjs: a malformed ENCLAVE_VM_PREFIX refuses to start; a valid one is stated", async () => {
  for (const bad of ["enclave-app", "x-", "enclave-UP-"]) {
    const r = await runMain({ ENCLAVE_VM_PREFIX: bad });
    assert.equal(r.code, 2, `${bad}: ${r.err}`); assert.match(r.err, /REFUSING TO START: ENCLAVE_VM_PREFIX must be/);
  }
  const ok = await runMain({ ENCLAVE_VM_PREFIX: CANARY }, 4000);
  assert.match(ok.out, /VM scope enclave-canary-: a separately scoped instance/);
});
