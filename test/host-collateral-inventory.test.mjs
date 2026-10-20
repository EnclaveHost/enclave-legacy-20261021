// isolation/m2/sev-inventory.c (read-only SEV firmware inventory) and its host-collateral wrapper. The real helper is
// COMPILED here (gcc, and clang when present) but NEVER run: these tests issue no /dev/sev ioctl. Behaviour is exercised
// through test/sev-inventory-mock.c, a firmware stand-in emulating Linux 7.2 sev-dev.c semantics, linked in place of
// open/ioctl. The chip IDs and TCBs the mock returns are the real Genoa/Turin chips whose KDS VCEKs are in
// test/fixtures/verifier, so a statement from it is carried through prepare against real AMD collateral. Nothing here
// is hardware evidence.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as H from "../isolation/m2/host-collateral.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const SRC = path.join(root, "isolation/m2/sev-inventory.c"), MOCK = path.join(root, "test/sev-inventory-mock.c");
const HEADER = "/usr/include/linux/psp-sev.h";
const CC = ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"];
const have = (bin) => spawnSync(bin, ["--version"], { stdio: "ignore" }).status === 0;
const skip = have("gcc") && fs.existsSync(HEADER) ? false : "gcc and Linux UAPI headers required";
let dir, mock;
before(() => {
  if (skip) return;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "sev-inventory-"));
  mock = path.join(dir, "sev-inventory-mock");
  const r = spawnSync(CC[0], [...CC.slice(1), "-DSEV_INVENTORY_MOCK", "-o", mock, SRC, MOCK], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
});
after(() => { if (dir) fs.rmSync(dir, { recursive: true, force: true }); });
const runMock = (scenario, args = []) => {
  const r = spawnSync(mock, args, { encoding: "utf8", env: { PATH: process.env.PATH, SEV_MOCK: scenario }, timeout: 10000 });
  assert.notEqual(r.status, 99, `${scenario}: the helper sent a forbidden request: ${r.stderr}`);
  return { status: r.status, json: JSON.parse(r.stdout) };
};
const fx = (p) => fs.readFileSync(path.join(root, "test/fixtures", p));
const GENOA_URL = JSON.parse(fx("verifier/SOURCES.json"))["genoa-2026-09/vcek-kds-amd.der"].url;
const cpuinfo = (fam, mod, vendor = "AuthenticAMD", n = 2) => Array.from({ length: n }, (_, i) => `processor\t: ${i}\nvendor_id\t: ${vendor}\ncpu family\t: ${fam}\nmodel\t\t: ${mod}\n`).join("\n");
const GENOA_INV = H.inventoryFrom({ cpuinfo: cpuinfo(25, 17) }), TURIN_INV = H.inventoryFrom({ cpuinfo: cpuinfo(26, 2) });

test("the real helper compiles against the reviewed UAPI and refuses to compile against a drifted one", { skip }, () => {
  const out = path.join(dir, "sev-inventory");
  let r = spawnSync(CC[0], [...CC.slice(1), "-static", "-o", out, SRC], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(fs.statSync(out).size > 0, "built, and deliberately never executed");
  if (have("clang")) { r = spawnSync("clang", ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fsyntax-only", SRC], { encoding: "utf8" }); assert.equal(r.status, 0, r.stderr); }
  // a header whose command numbering moved must not compile into a program that sends another command
  const shim = path.join(dir, "shim/linux");
  fs.mkdirSync(shim, { recursive: true });
  fs.writeFileSync(path.join(shim, "psp-sev.h"), fs.readFileSync(HEADER, "utf8").replace("\tSEV_GET_ID2,\n", "\tSEV_SHIFTED_FOR_TEST,\n\tSEV_GET_ID2,\n"));
  r = spawnSync(CC[0], [...CC.slice(1), "-I", path.join(dir, "shim"), "-fsyntax-only", SRC], { encoding: "utf8" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /SEV_GET_ID2 differs from the reviewed UAPI/);
  assert.match(r.stderr, /SNP_PLATFORM_STATUS differs from the reviewed UAPI/);
});

test("source audit: only the two read commands, one ioctl site, read-only open, fixed device", { skip }, () => {
  // every SEV/SNP platform command the primary UAPI header defines, read from the header itself
  const hdr = fs.readFileSync(HEADER, "utf8");
  const commands = /enum\s*\{([^}]*SEV_FACTORY_RESET[^}]*)\}/.exec(hdr)[1].replace(/\/\*[\s\S]*?\*\//g, "").split(",").map((s) => s.trim().split(/\s|=/)[0]).filter(Boolean);
  assert.ok(commands.includes("SNP_COMMIT") && commands.includes("SNP_SET_CONFIG") && commands.includes("SEV_FACTORY_RESET"));
  const code = fs.readFileSync(SRC, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  for (const c of commands) {
    const used = new RegExp(`\\b${c}\\b`).test(code);
    assert.equal(used, ["SEV_GET_ID2", "SNP_PLATFORM_STATUS"].includes(c), `${c} ${used ? "appears" : "is absent"}`);
  }
  assert.equal(code.match(/\bioctl\s*\(/g).length, 1, "one ioctl call site");
  assert.match(code, /open\(SEV_DEVICE, O_RDONLY \| O_CLOEXEC \| O_NOCTTY\)/);
  assert.doesNotMatch(code, /O_RDWR|O_WRONLY|O_CREAT|argv\[1\]\s*\)|getenv|system\(|exec[lv]/);
  assert.match(code, /if \(command != SNP_PLATFORM_STATUS && command != SEV_GET_ID2\) abort\(\);/);
});

test("mock firmware: success, length probe, truncation, bounds, busy, errors, permissions and usage", { skip }, () => {
  let r = runMock("ok-genoa");
  assert.equal(r.status, 0);
  assert.deepEqual([r.json.id_length, r.json.id.length, r.json.snp_status.reported_tcb, r.json.open], [64, 128, "0a00000000001754", "O_RDONLY"]);
  // the real Turin host (2026-10-19, firmware 1.58) answered the GET_ID2 probe with length 8; the earlier helper
  // refused that. The Turin hardware ID is accepted exactly as the firmware gives it.
  r = runMock("ok-turin");
  assert.equal(r.status, 0, JSON.stringify(r.json));
  assert.deepEqual([r.json.id_length, r.json.id, r.json.snp_status.reported_tcb], [8, "fa11afcf54ae9c53", "0103020500000075"]);
  assert.equal(runMock("eintr-once").status, 0, "one EINTR is retried");
  for (const [s, code, stage, re] of [
    ["truncated", 70, "get_id2", /different CHIP_ID length/],
    ["turin-truncated", 70, "get_id2", /different CHIP_ID length/],
    ["two-sockets", 69, "get_id2_length", /unsupported ID length.*multi-socket answers, are refused/],
    ["odd-length", 69, "get_id2_length", /unsupported ID length/],
    ["huge-length", 69, "get_id2_length", /unsupported ID length/],
    ["probe-success", 69, "get_id2_length", /unsupported ID length/],
    ["busy", 75, "snp_platform_status", /busy or unresponsive/],
    ["id-busy", 75, "get_id2_length", /busy/],
    ["not-snp", 69, "snp_platform_status", /Linux 6\.11/],
    ["no-psp", 69, "snp_platform_status", /not available/],
    ["fw-error", 70, "snp_platform_status", /refused/],
    ["status-success-error", 70, "snp_platform_status", /error with a successful ioctl/],
    ["probe-success-error", 70, "get_id2_length", /error with a successful ioctl/],
    ["old-api", 69, "get_id2_length", /too old/],
    ["open-enoent", 69, "open", /not an AMD SEV host/],
    ["open-eacces", 77, "open", /needs root/],
  ]) {
    r = runMock(s);
    assert.equal(r.status, code, s);
    assert.equal(r.json.error.stage, stage, s);
    assert.match(r.json.error.message, re, s);
    assert.throws(() => H.parseFirmwareInventory(JSON.stringify(r.json)), new RegExp(`failed at ${stage}`), s);
  }
  assert.equal(runMock("fw-error").json.error.fw_error_name, "INVALID_COMMAND");
  assert.equal(runMock("ok-genoa", ["--device", "/dev/mem"]).status, 64, "no argument selects a device or command");
  const help = spawnSync(mock, ["--help"], { encoding: "utf8", env: { SEV_MOCK: "ok-genoa" } });
  assert.equal(help.status, 0);
});

test("statement: strict parsing, per-product ID formats, unsupported platforms, masked chip, mismatched product", { skip }, () => {
  const ok = runMock("ok-genoa").json, text = JSON.stringify(ok);
  const g = H.firmwareStatement({ firmware: H.parseFirmwareInventory(text), inventory: GENOA_INV });
  assert.deepEqual([g.product, g.chipId, g.reportedTcbRaw, g.reportedTcb, g.firmware.idFormat], ["Genoa", ok.id, "0a00000000001754", { bootloader: 10, tee: 0, snp: 23, microcode: 84 }, "chip-id-64"]);
  assert.equal(g.kdsUrl, GENOA_URL, "the statement requests exactly the VCEK AMD issued for this chip");
  assert.match(g.notes[0], /verified only when prepare checks the AMD VCEK chain/);
  // Turin: the 8-byte hardware ID is the statement's chip ID and exactly the KDS path component
  const turinFw = runMock("ok-turin").json;
  const t = H.firmwareStatement({ firmware: H.parseFirmwareInventory(JSON.stringify(turinFw)), inventory: TURIN_INV });
  assert.deepEqual([t.chipId, t.firmware.idFormat, t.firmware.idLength], ["fa11afcf54ae9c53", "turin-hardware-id-8", 8]);
  assert.equal(t.kdsUrl, "https://kdsintf.amd.com/vcek/v1/Turin/fa11afcf54ae9c53?fmcSPL=01&blSPL=03&teeSPL=02&snpSPL=05&ucodeSPL=117");
  // the values the real Turin host reported (API 1.58, 4 guests, reported TCB 0103020500000075, ID length 8)
  const real = structuredClone(turinFw); real.snp_status.api_minor = 58; real.snp_status.guest_count = 4;
  const rt = H.firmwareStatement({ firmware: H.parseFirmwareInventory(JSON.stringify(real)), inventory: TURIN_INV });
  assert.deepEqual([rt.firmware.api, rt.firmware.guestCount, rt.reportedTcb], ["1.58", 4, { fmc: 1, bootloader: 3, tee: 2, snp: 5, microcode: 117 }]);
  // strict parsing
  const bad = (f, base = ok) => { const j = structuredClone(base); f(j); return JSON.stringify(j); };
  for (const [mut, re, base] of [
    [(j) => { j.extra = 1; }, /unexpected fields/], [(j) => { delete j.snp_status.vlek_en; }, /unexpected fields/],
    [(j) => { j.chip_ids = [j.id]; delete j.id; }, /unexpected fields/, ok],
    [(j) => { j.snp_status.reported_tcb = "0a0000000000175"; }, /8 bytes of hex/], [(j) => { j.id = j.id.slice(0, 64); }, /malformed or truncated/],
    [(j) => { j.id_length = 128; j.id = j.id + j.id; }, /must be 8 \(Turin hardware ID\) or 64/], [(j) => { j.id_length = 16; }, /must be 8/],
    [(j) => { j.id = j.id + "00"; }, /malformed or truncated/, turinFw], [(j) => { j.id_length = 64; }, /malformed or truncated/, turinFw],
    [(j) => { j.open = "O_RDWR"; }, /reviewed read-only helper/],
    [(j) => { j.commands.push("SNP_COMMIT"); }, /reviewed read-only helper/], [(j) => { j.snp_status.mask_chip_id = 2; }, /0 or 1/],
    [(j) => { j.tool = "snphost"; }, /enclave-sev-inventory v1/],
  ]) assert.throws(() => H.parseFirmwareInventory(bad(mut, base)), re);
  assert.throws(() => H.parseFirmwareInventory("x".repeat(H.MAX_HELPER_OUTPUT + 1)), /bytes/);
  assert.throws(() => H.parseFirmwareInventory("{"), /not JSON/);
  // platforms and firmware states this path does not support, each refused with its reason
  const st = (s, inv = GENOA_INV, o = {}) => () => H.firmwareStatement({ firmware: H.parseFirmwareInventory(JSON.stringify(runMock(s).json)), inventory: inv, ...o });
  assert.throws(st("masked-chip"), /MASK_CHIP_ID/);
  assert.throws(st("masked-key"), /MASK_CHIP_KEY/);
  assert.throws(st("vlek"), /VLEK/);
  assert.throws(st("zero-id"), /zero \(masked\) chip ID/);
  assert.throws(st("turin-zero-id", TURIN_INV), /zero \(masked\) chip ID/);
  assert.throws(st("zero-tcb"), /all-zero TCB/);
  // ID format against the product line: never reinterpreted, including a Turin ID padded to 64 bytes
  assert.throws(st("ok-turin", GENOA_INV), /ID format mismatch: Genoa firmware answers GET_ID2 with 64 bytes, this answer has 8/);
  assert.throws(st("ok-genoa", TURIN_INV), /ID format mismatch: Turin firmware answers GET_ID2 with 8 bytes, this answer has 64/);
  assert.throws(st("turin-64", TURIN_INV), /ID format mismatch: Turin .* has 64/);
  // TCB layout against the product line, independently of the ID format
  assert.throws(st("genoa-8", TURIN_INV), /nonzero reserved byte\(s\) 6 for the Turin layout/);
  assert.throws(st("turin-64", GENOA_INV), /nonzero reserved byte\(s\) 2,3 for the Genoa layout/);
  assert.throws(st("ok-genoa", H.inventoryFrom({ cpuinfo: cpuinfo(6, 143, "GenuineIntel") })), /unsupported platform/);
  assert.throws(st("ok-genoa", H.inventoryFrom({ cpuinfo: cpuinfo(25, 17) + "\n" + cpuinfo(26, 2, "AuthenticAMD", 1).replace("processor\t: 0", "processor\t: 9") })), /unsupported platform: processors disagree/);
  assert.throws(() => H.firmwareStatement({ firmware: { ...ok, id_length: 128, id: ok.id + ok.id }, inventory: GENOA_INV }), /ID format mismatch/, "no socket is ever chosen");
  const uninit = structuredClone(ok); uninit.snp_status.state = 0;
  assert.throws(() => H.firmwareStatement({ firmware: uninit, inventory: GENOA_INV }), /not INIT/);
  assert.match(H.firmwareStatement({ firmware: uninit, inventory: GENOA_INV, allowUninitialized: true }).notes.join(), /not initialized/);
  assert.match(st("lagging-tcb")().notes.join(), /differs from the current TCB/);
});

test("end to end: firmware inventory -> statement file -> prepare against real AMD collateral; filesystem inventory unchanged", { skip, timeout: 60000 }, () => {
  const cli = (args, scenario = "ok-genoa") => spawnSync(process.execPath, [path.join(root, "isolation/m2/host-collateral.mjs"), ...args],
    { encoding: "utf8", env: { PATH: process.env.PATH, SEV_MOCK: scenario }, timeout: 30000 });
  const w = fs.mkdtempSync(path.join(dir, "e2e-"));
  for (const [name, fam, mod] of [["genoa", 25, 17], ["turin", 26, 2]]) fs.writeFileSync(path.join(w, `${name}.cpuinfo`), cpuinfo(fam, mod));
  // without --firmware the inventory output is the filesystem inventory exactly as before
  let r = cli(["inventory", "--cpuinfo", path.join(w, "genoa.cpuinfo")]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(Object.keys(JSON.parse(r.stdout)).sort(), Object.keys(H.inventoryFrom({ cpuinfo: "" })).sort());
  // the helper's saved output (as root would produce it) and the helper run directly give the same statement
  fs.writeFileSync(path.join(w, "fw.json"), spawnSync(mock, [], { encoding: "utf8", env: { SEV_MOCK: "ok-genoa" } }).stdout);
  r = cli(["inventory", "--firmware", "--cpuinfo", path.join(w, "genoa.cpuinfo"), "--helper-output", path.join(w, "fw.json"), "--statement-out", path.join(w, "genoa.statement.json")]);
  assert.equal(r.status, 0, r.stderr);
  r = cli(["inventory", "--firmware", "--cpuinfo", path.join(w, "genoa.cpuinfo"), "--helper", mock]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout).statement, JSON.parse(fs.readFileSync(path.join(w, "genoa.statement.json"))));
  r = cli(["inventory", "--firmware", "--cpuinfo", path.join(w, "genoa.cpuinfo"), "--helper-output", path.join(w, "fw.json"), "--statement-out", path.join(w, "genoa.statement.json")]);
  assert.match(r.stderr, /EEXIST/, "a statement file is written once");
  r = cli(["inventory", "--firmware", "--cpuinfo", path.join(w, "genoa.cpuinfo"), "--helper", mock], "busy");
  assert.equal(r.status, 1); assert.match(r.stderr, /busy or unresponsive.*EBUSY/);
  r = cli(["inventory", "--firmware", "--cpuinfo", path.join(w, "genoa.cpuinfo"), "--helper", "relative/sev-inventory"]);
  assert.match(r.stderr, /absolute path/);
  r = cli(["inventory", "--firmware", "--cpuinfo", path.join(w, "genoa.cpuinfo")]);
  assert.match(r.stderr, /--helper-output FILE/);
  // the statement drives prepare; the AMD chain, CRL and the separately supplied floor still decide
  fs.writeFileSync(path.join(w, "vcek.der"), fx("verifier/genoa-2026-09/vcek-kds-amd.der"));
  fs.writeFileSync(path.join(w, "crl.der"), fx("verifier/amd/Genoa-crl.der"));
  fs.writeFileSync(path.join(w, "floor.json"), JSON.stringify({ Genoa: { bootloader: 9, tee: 0, snp: 22, microcode: 84 } }));
  const prep = (out, extra = []) => cli(["prepare", "--statement", path.join(w, "genoa.statement.json"), "--min-tcb", path.join(w, "floor.json"), "--vcek", path.join(w, "vcek.der"),
                                         "--crl", path.join(w, "crl.der"), "--at", "2026-09-30T00:00:00Z", "--out", path.join(w, out), ...extra]);
  r = prep("collateral");
  assert.equal(r.status, 0, r.stderr);
  const meta = JSON.parse(fs.readFileSync(path.join(w, "collateral/collateral.json")));
  assert.deepEqual([meta.product, meta.kdsUrl, meta.reportedTcbRaw], ["Genoa", GENOA_URL, "0a00000000001754"]);
  r = prep("other", ["--product", "Genoa"]);
  assert.match(r.stderr, /--statement replaces/);
  r = cli(["prepare", "--statement", path.join(w, "genoa.statement.json"), "--vcek", path.join(w, "vcek.der"), "--crl", path.join(w, "crl.der"), "--out", path.join(w, "nofloor")]);
  assert.match(r.stderr, /--min-tcb policy.json is required/, "the floor is never taken from the statement");
  fs.writeFileSync(path.join(w, "turin-vcek.der"), fx("verifier/turin-m4a-app-2026-10-17/vcek-kds-amd.der"));
  r = cli(["prepare", "--statement", path.join(w, "genoa.statement.json"), "--min-tcb", path.join(w, "floor.json"), "--vcek", path.join(w, "turin-vcek.der"),
           "--crl-policy", "none", "--at", "2026-10-19T00:00:00Z", "--out", path.join(w, "wrong")]);
  assert.match(r.stderr, /collateral refused/, "a statement never vouches for another chip's VCEK");
  assert.equal(fs.existsSync(path.join(w, "wrong")), false);
  // a Turin statement from the mock carries the real Turin VCEK through prepare as well
  fs.writeFileSync(path.join(w, "fw-turin.json"), spawnSync(mock, [], { encoding: "utf8", env: { SEV_MOCK: "ok-turin" } }).stdout);
  r = cli(["inventory", "--firmware", "--cpuinfo", path.join(w, "turin.cpuinfo"), "--helper-output", path.join(w, "fw-turin.json"), "--statement-out", path.join(w, "turin.statement.json")]);
  assert.equal(r.status, 0, r.stderr);
  fs.writeFileSync(path.join(w, "turin-crl.der"), fx("verifier/turin-m4a-app-2026-10-17/Turin-crl.der"));
  fs.writeFileSync(path.join(w, "turin-floor.json"), JSON.stringify({ Turin: { fmc: 1, bootloader: 3, tee: 2, snp: 5, microcode: 117 } }));
  r = cli(["prepare", "--statement", path.join(w, "turin.statement.json"), "--min-tcb", path.join(w, "turin-floor.json"), "--vcek", path.join(w, "turin-vcek.der"),
           "--crl", path.join(w, "turin-crl.der"), "--at", "2026-10-19T00:00:00Z", "--out", path.join(w, "turin")]);
  assert.equal(r.status, 0, r.stderr);
  // the 8-byte Turin hardware ID from GET_ID2 is carried exactly: statement, KDS URL and installed metadata
  const tstate = JSON.parse(fs.readFileSync(path.join(w, "turin.statement.json")));
  const tmeta = JSON.parse(fs.readFileSync(path.join(w, "turin/collateral.json")));
  assert.deepEqual([tstate.chipId, tmeta.hwId, tmeta.chipId, tmeta.kdsUrl],
                   ["fa11afcf54ae9c53", "fa11afcf54ae9c53", null, "https://kdsintf.amd.com/vcek/v1/Turin/fa11afcf54ae9c53?fmcSPL=01&blSPL=03&teeSPL=02&snpSPL=05&ucodeSPL=117"]);
  // a Turin statement never vouches for the Genoa VCEK; a Genoa firmware answer never yields a Turin statement
  r = cli(["prepare", "--statement", path.join(w, "turin.statement.json"), "--min-tcb", path.join(w, "turin-floor.json"), "--vcek", path.join(w, "vcek.der"),
           "--crl-policy", "none", "--at", "2026-10-19T00:00:00Z", "--out", path.join(w, "turin-wrong")]);
  assert.match(r.stderr, /collateral refused/);
  assert.equal(fs.existsSync(path.join(w, "turin-wrong")), false);
  r = cli(["inventory", "--firmware", "--cpuinfo", path.join(w, "turin.cpuinfo"), "--helper-output", path.join(w, "fw.json")]);
  assert.match(r.stderr, /ID format mismatch: Turin/);
  r = cli(["inventory", "--firmware", "--cpuinfo", path.join(w, "genoa.cpuinfo"), "--helper-output", path.join(w, "fw.json"), "--socket", "1"]);
  assert.match(r.stderr, /--socket is not supported/);
});
