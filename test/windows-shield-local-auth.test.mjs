// Local transport admission (work/shield-local-auth-interface.txt, peer review P1/P2): the package (9446) and custody (9445)
// loopback servers admit ONLY their own bridge, by a per-start credential handed to it on stdin; other local callers'
// connections consume no request budget, no pending slot and no package serve, and are cleaned up; the credential is
// never in argv or output; the real Rust bridge, the fixture bridge and the manager agree on the protocol; and the
// custody callback key file is read only when private (POSIX mode, win32 owner + DACL), never altered.
// The fixture bridge's "VM <guid>" peer line is a SYNTHETIC stand-in for the hv_sock VmId: fixture-only, not hardware.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import crypto from "node:crypto";
import { spawn as nodeSpawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { BRIDGE_AUTH_FLAG, BRIDGE_AUTH_PREFIX, BRIDGE_AUTH_LINE_BYTES, bridgeAuthLine, mintBridgeCredential, createBridgeGate } from "../windows/vbslike/manager/bridge-auth.mjs";
import { serveCustodyRequests, custodyAnswerLine } from "../windows/vbslike/manager/custody-transport.mjs";
import { packageFrame, servePackage, startPackageTransport } from "../windows/vbslike/manager/package-transport.mjs";
import { readCustodyCallbackKey, windowsAclRefusal, windowsAclOf, ACL_SCRIPT, SID_SYSTEM, SID_ADMINISTRATORS } from "../windows/vbslike/manager/custody-key-file.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..");
const FAKE_BRIDGE = path.join(ROOT, "windows/vbslike/manager/testdata/fake-custody-bridge.py");
const PYTHON = process.env.PYTHON_BIN || "python3";
const VM = "5db6d4eb-1619-4936-9d60-c7e3ca67f3a8";
const DEP = "0x" + "e7".repeat(32), VAULT = "0x" + "c1".repeat(20), B = "11".repeat(32);
const requestLine = (vault, id, binding) => `custody-auth-v2 ${vault} ${id} ${binding}\n`;
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms));
const until = async (f, what, ms = 3000) => { const t = Date.now() + ms; for (;;) { const v = f(); if (v) return v; if (Date.now() > t) throw new Error(`timed out: ${what}`); await tick(10); } };
const children = [];
after(() => { for (const c of children) try { c.kill("SIGKILL"); } catch {} });

/** A loopback client: writes `bytes` (or nothing), resolves { got, closed } when the server closes or after `holdMs`. */
function client(port, bytes, { holdMs = 1500 } = {}) {
  return new Promise((resolve) => {
    const got = [];
    const c = net.connect(port, "127.0.0.1", () => { if (bytes) c.write(bytes); });
    const done = (closed) => { resolve({ got: Buffer.concat(got), closed, c }); };
    const t = setTimeout(() => done(false), holdMs);
    c.on("data", (d) => got.push(d));
    c.on("close", () => { clearTimeout(t); done(true); });
    c.on("error", () => {});
  });
}

// ---- 1. custody: unauthenticated connections consume nothing --------------------------------------------------------------
test("custody: unauthenticated, empty, wrong-credential and guest-shaped connections are closed and consume NO budget; the bridge's request is still served", async () => {
  const credential = mintBridgeCredential();
  const s = await serveCustodyRequests({ deploymentId: DEP, vault: VAULT, credential, maxRequests: 3, authTimeoutMs: 300 });
  try {
    const hostile = [
      requestLine(VAULT, DEP, B),                                          // a perfectly formed request, public ids only
      bridgeAuthLine(mintBridgeCredential()) + requestLine(VAULT, DEP, B), // another credential
      BRIDGE_AUTH_PREFIX + "0".repeat(64) + "\n",                         // a well-formed but wrong line
      bridgeAuthLine(credential).slice(0, 40),                            // a prefix of the right line, then silence
      "",                                                                 // nothing at all
    ];
    for (let round = 0; round < 8; round++)                               // 40 connections, far past maxRequests (3)
      for (const h of hostile) { const r = await client(s.port, h || null); assert.equal(r.got.length, 0); assert.equal(r.closed, true, `closed: ${JSON.stringify(h.slice(0, 30))}`); }
    const st = s.stats();
    assert.deepEqual([st.requests, st.refused, st.pending, s.pending().length], [0, 0, 0, 0], "no budget, refusal or pending slot was spent");
    assert.equal(st.gate.unauthenticated, 40); assert.equal(st.gate.waiting, 0);
    // the bridge's connection: credential, then the guest's line -> pending, and answered
    const asked = client(s.port, bridgeAuthLine(credential) + requestLine(VAULT, DEP, B), { holdMs: 3000 });
    const [p] = await until(() => s.pending().length && s.pending(), "the genuine request");
    const auth = { binding: B, endpoint: "https://box.example.org", sig: "0x" + "ab".repeat(65), expiry: Math.floor(Date.now() / 1000) + 300 };
    s.answer(p.request, auth);
    assert.equal(String((await asked).got), custodyAnswerLine(auth));
    assert.equal(s.stats().requests, 1, "only the authenticated connection counted");
    // the credential AND the request may arrive in pieces
    const c = net.connect(s.port, "127.0.0.1");
    await new Promise((r) => c.once("connect", r));
    const whole = Buffer.from(bridgeAuthLine(credential) + requestLine(VAULT, DEP, B));
    for (const cut of [10, 87, 88, 100]) { c.write(whole.subarray(cut === 10 ? 0 : [10, 87, 88, 100][[10, 87, 88, 100].indexOf(cut) - 1], cut)); await tick(5); }
    c.write(whole.subarray(100));
    await until(() => s.pending().length, "a request delivered in pieces");
    assert.equal(s.stats().requests, 2);
    c.destroy();
  } finally { await s.close(); }
});

test("the gate is bounded: a flood evicts its own idle connections, never the bridge's, and every timer and socket is cleaned up", async () => {
  const credential = mintBridgeCredential();
  const s = await serveCustodyRequests({ deploymentId: DEP, vault: VAULT, credential, maxUnauthenticated: 4, authTimeoutMs: 400 });
  try {
    const flood = [];
    for (let i = 0; i < 12; i++) { const c = net.connect(s.port, "127.0.0.1"); c.on("error", () => {}); flood.push(c); await tick(5); }
    await until(() => s.stats().gate.evicted >= 8, "evictions");
    assert.ok(s.stats().gate.waiting <= 4, "at most maxUnauthenticated wait");
    // the bridge's connection writes its line at once: admitted despite the flood
    const asked = client(s.port, bridgeAuthLine(credential) + requestLine(VAULT, DEP, B), { holdMs: 2000 });
    await until(() => s.pending().length, "the bridge's request under a flood");
    // the rest time out: nothing is left waiting
    await until(() => s.stats().gate.waiting === 0, "the gate drained");
    assert.equal(s.stats().requests, 1);
    for (const c of flood) c.destroy();
    asked.then((r) => r.c.destroy());
  } finally { await s.close(); }
  // createBridgeGate refuses to exist without a credential
  assert.throws(() => createBridgeGate({}), /32 bytes of lowercase hex/);
  assert.throws(() => serveCustodyRequests({ deploymentId: DEP, vault: VAULT }), /32 bytes of lowercase hex/);
});

// ---- 2. package: unauthenticated readers get nothing and spend no serve -------------------------------------------------
test("package: an unauthenticated reader gets no frame and spends no serve; the bridge's connections get the frame up to maxServes", async () => {
  const credential = mintBridgeCredential(), frame = packageFrame(DEP, Buffer.from('{"version":1}'));
  const s = await servePackage(frame, { credential, maxServes: 2, authTimeoutMs: 300 });
  try {
    for (let i = 0; i < 20; i++) {
      const r = await client(s.port, i % 2 ? bridgeAuthLine(mintBridgeCredential()) : null);
      assert.deepEqual([r.got.length, r.closed], [0, true]);
    }
    assert.equal(s.served(), 0, "no serve spent");
    assert.deepEqual((await client(s.port, bridgeAuthLine(credential))).got, frame);
    assert.deepEqual((await client(s.port, bridgeAuthLine(credential))).got, frame, "a guest restart reads it again");
    assert.equal((await client(s.port, bridgeAuthLine(credential))).got.length, 0, "past maxServes: nothing");
    assert.equal(s.gate().unauthenticated, 20);
  } finally { await s.close(); }
  assert.throws(() => servePackage(frame, {}), /32 bytes of lowercase hex/);
});

// ---- 3. the genuine path through the (fixture) bridge, with the credential on stdin only -----------------------------------
test("package through the bridge: the guest reads the frame, a direct loopback reader does not; the credential is on stdin, never in argv or output", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "local-auth-"));
  try {
    const exe = path.join(dir, "shielded-bridge.exe"); fs.writeFileSync(exe, "shielded-bridge bytes (fixture)");
    const log = path.join(dir, "bridge.log"), spawned = [];
    let stdout = "", stderr = "";
    const spawn = (file, args, opts) => {
      const ch = nodeSpawn(PYTHON, [FAKE_BRIDGE, ...args], { ...opts, env: { ...process.env, FAKE_CUSTODY_LOG: log } });
      ch.stdout.on("data", (b) => { stdout += b; }); ch.stderr.on("data", (b) => { stderr += b; });
      children.push(ch); spawned.push(args); return ch;
    };
    const bytes = Buffer.from('{"version":1,"pkg":"x"}');
    const t = await startPackageTransport({ bridge: { exe, sha256: sha(fs.readFileSync(exe)) }, vmId: VM, deploymentId: DEP, bytes, spawn });
    try {
      assert.deepEqual(spawned[0], [VM, "9446", String(t.port), "0", BRIDGE_AUTH_FLAG]);
      const guestPort = await until(() => fs.existsSync(log) && fs.readFileSync(log, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((e) => e.event === "ready")?.guestPort, "the bridge");
      // the guest (fixture: its partition id stands in for the hv_sock VmId) reads exactly the frame
      assert.deepEqual((await client(guestPort, `VM ${VM}\n`)).got, packageFrame(DEP, bytes));
      // a local process dialling the loopback server directly gets nothing
      assert.equal((await client(t.port, null)).got.length, 0);
      assert.equal((await client(t.port, `VM ${VM}\n`)).got.length, 0);
      assert.equal(t.served(), 1);
      assert.match(stdout, /shielded bridge ready .* auth=stdin/);
      for (const text of [JSON.stringify(spawned), stdout, stderr, fs.readFileSync(log, "utf8")])
        assert.doesNotMatch(text, /enclave-bridge-auth-v1|[0-9a-f]{64}/, "no credential in argv, output or log");
    } finally { await t.stop(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---- 4. one protocol: manager, fixture bridge, real Rust bridge -----------------------------------------------------------
test("the real Rust bridge, the fixture and the manager speak the same credential protocol; legacy invocations are unchanged", () => {
  const rs = fs.readFileSync(path.join(ROOT, "windows/vbslike/host/src/bin/shielded-bridge.rs"), "utf8");
  assert.ok(rs.includes(`const AUTH_FLAG: &str = "${BRIDGE_AUTH_FLAG}";`));
  assert.ok(rs.includes(`const AUTH_PREFIX: &[u8] = b"${BRIDGE_AUTH_PREFIX}";`));
  assert.match(rs, /const AUTH_LINE_BYTES: usize = 23 \+ 64 \+ 1;/);
  assert.equal(BRIDGE_AUTH_LINE_BYTES, 23 + 64 + 1); assert.equal(BRIDGE_AUTH_PREFIX.length, 23);
  // the credential is read from stdin BEFORE the hv_sock bind, written BEFORE the relay, and never formatted into output
  const read = rs.indexOf("valid_auth_line(&line)"), bind = rs.indexOf("hvsock::Listener::bind(&vm, port)");
  assert.ok(read > 0 && bind > read, "credential read before bind");
  assert.ok(rs.indexOf("worker.write_all(line)") < rs.indexOf("let mut gr = guest.try_clone()"), "credential written before any guest byte is relayed");
  // no output macro is handed the credential (the `line` buffer, or the `auth` value) as an argument
  assert.doesNotMatch(rs, /(println|eprintln|format|write|writeln)!\([^;]*[,(]\s*&?\*?(line|auth|l)(\.as_slice\(\))?\s*[,)]/, "the credential is never formatted into output");
  assert.match(rs, /a\.len\(\) != 5 && !auth_flag/, "5-argument (egress, GPU) invocations unchanged");
  assert.match(rs, /auth_flag && seconds != 0/, "the flag only with supervised lifetime 0");
  // the fixture refuses a bad first line without echoing it, and a good line is relayed first
  const bad = spawnSync(PYTHON, [FAKE_BRIDGE, VM, "9445", "1", "0", BRIDGE_AUTH_FLAG], { input: "enclave-bridge-auth-v1 SECRETSECRET\n", encoding: "utf8", timeout: 10000 });
  assert.equal(bad.status, 2); assert.match(bad.stderr, /not a worker credential/); assert.doesNotMatch(bad.stderr + bad.stdout, /SECRETSECRET/);
});

// ---- 5. the callback key file ------------------------------------------------------------------------------------------
test("the callback key file: missing, world-readable and malformed are refused; a private one is read; nothing is changed", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "local-auth-key-"));
  try {
    const f = path.join(dir, "custody-callback.key"), hex = crypto.randomBytes(32).toString("hex");
    assert.throws(() => readCustodyCallbackKey(path.join(dir, "absent.key"), { platform: "linux" }), /cannot be read \(ENOENT\)/);
    assert.throws(() => readCustodyCallbackKey(dir, { platform: "linux" }), /regular file/);
    fs.writeFileSync(f, hex + "\n", { mode: 0o644 }); fs.chmodSync(f, 0o644);
    assert.throws(() => readCustodyCallbackKey(f, { platform: "linux" }), /not private: mode 644/);
    assert.equal(fs.statSync(f).mode & 0o777, 0o644, "never chmodded");
    fs.chmodSync(f, 0o640); assert.throws(() => readCustodyCallbackKey(f, { platform: "linux" }), /not private: mode 640/);
    fs.chmodSync(f, 0o600);
    assert.equal(readCustodyCallbackKey(f, { platform: "linux" }).toString("hex"), hex);
    fs.writeFileSync(f, "not hex\n"); assert.throws(() => readCustodyCallbackKey(f, { platform: "linux" }), /32-64 bytes of hex/);
    // win32: the DACL and owner decide (as Get-Acl states them), and the file's POSIX mode is not consulted
    fs.writeFileSync(f, hex); fs.chmodSync(f, 0o644);
    const priv = { owner: SID_ADMINISTRATORS, sddl: "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)",
                   aces: [{ sid: SID_SYSTEM, type: "Allow", rights: 2032127, inherited: false }, { sid: SID_ADMINISTRATORS, type: "Allow", rights: 2032127, inherited: false }] };
    assert.equal(readCustodyCallbackKey(f, { platform: "win32", aclOf: () => priv }).toString("hex"), hex);
    assert.equal(windowsAclRefusal(priv), null);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("win32 ACL rule: other identities, a user owner, a null DACL or SYSTEM without read are refused; Get-Acl output is parsed as it comes", () => {
  const sys = { sid: SID_SYSTEM, type: "Allow", rights: 2032127, inherited: false }, adm = { sid: SID_ADMINISTRATORS, type: "Allow", rights: 2032127, inherited: false };
  const base = { owner: SID_SYSTEM, sddl: "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)", aces: [sys, adm] };
  assert.equal(windowsAclRefusal(base), null);
  for (const [extra, re] of [
    [{ sid: "S-1-5-32-545", type: "Allow", rights: 1179817, inherited: true }, /an inherited entry allows S-1-5-32-545/],      // BUILTIN\Users read, inherited
    [{ sid: "S-1-1-0", type: "Allow", rights: 1179817, inherited: false }, /allows S-1-1-0/],                                 // Everyone
    [{ sid: "S-1-5-11", type: "Allow", rights: 1179817, inherited: false }, /allows S-1-5-11/],                               // Authenticated Users
    [{ sid: "S-1-5-21-1-2-3-1001", type: "Allow", rights: 2032127, inherited: false }, /allows S-1-5-21-1-2-3-1001/],         // a local user
  ]) assert.match(windowsAclRefusal({ ...base, aces: [...base.aces, extra] }), re);
  assert.equal(windowsAclRefusal({ ...base, aces: [...base.aces, { sid: "S-1-1-0", type: "Deny", rights: 2032127, inherited: false }] }), null, "deny entries do not open it");
  assert.match(windowsAclRefusal({ ...base, owner: "S-1-5-21-1-2-3-1001" }), /owner is S-1-5-21-1-2-3-1001/);
  assert.match(windowsAclRefusal({ ...base, sddl: "D:NO_ACCESS_CONTROL", aces: [] }), /no DACL/);
  assert.match(windowsAclRefusal({ ...base, sddl: "", aces: [] }), /no DACL/);
  assert.match(windowsAclRefusal({ ...base, aces: [adm] }), /SYSTEM, .* may not read it/);
  assert.match(windowsAclRefusal({ ...base, aces: [{ ...sys, rights: 0x40000 }, adm] }), /SYSTEM, .* may not read it/);      // WRITE_DAC only
  // windowsAclOf: the path travels in the environment, never in the script; a single entry unwrapped by ConvertTo-Json is still a list
  let seen;
  const out = windowsAclOf("C:\\ProgramData\\Enclave\\shield\\custody-callback.key", { run: (file, args, opts) => {
    seen = { file, args, env: opts.env };
    return { status: 0, stdout: JSON.stringify({ owner: SID_SYSTEM, sddl: "D:PAI(A;;FA;;;SY)", aces: { sid: SID_SYSTEM, type: "Allow", rights: 2032127, inherited: false } }) };
  } });
  assert.equal(seen.file, "powershell.exe"); assert.ok(!seen.args.join(" ").includes("custody-callback.key"));
  assert.equal(seen.env.ENCLAVE_KEY_ACL_PATH, "C:\\ProgramData\\Enclave\\shield\\custody-callback.key");
  assert.ok(ACL_SCRIPT.includes("$env:ENCLAVE_KEY_ACL_PATH") && ACL_SCRIPT.includes("-LiteralPath"));
  assert.deepEqual(out.aces.length, 1);
  assert.throws(() => windowsAclOf("x", { run: () => ({ status: 1, stderr: "Get-Acl : Cannot find path" }) }), /ACL could not be read: Get-Acl : Cannot find path/);
  assert.throws(() => windowsAclOf("x", { run: () => ({ status: 0, stdout: "garbage" }) }), /no JSON/);
});

// ---- 6. no credential oracle: a partial line is never judged ----------------------------------------------------------------
/** Opens a connection, writes `bytes`, and resolves { ms, got } when the SERVER closes it (or `capMs`, then "open"). */
function closeTiming(port, bytes, capMs) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint(), got = [];
    const c = net.connect(port, "127.0.0.1", () => c.write(bytes));
    const done = (how) => { clearTimeout(cap); resolve({ how, ms: Number(process.hrtime.bigint() - t0) / 1e6, got: Buffer.concat(got) }); };
    const cap = setTimeout(() => { c.destroy(); done("open"); }, capMs);
    c.on("data", (d) => got.push(d)); c.on("close", () => done("closed")); c.on("error", () => {});
  });
}
test("no oracle: a correct and a wrong partial credential are held alike until the deadline, both spend nothing; only a whole line is judged", async () => {
  const credential = mintBridgeCredential(), deadline = 400;
  const wrongHex = [...credential].map((ch) => ch === "0" ? "1" : "0").join("");      // differs in every digit
  const line = bridgeAuthLine(credential), wrongLine = bridgeAuthLine(wrongHex);
  const s = await serveCustodyRequests({ deploymentId: DEP, vault: VAULT, credential, authTimeoutMs: deadline, maxUnauthenticated: 64 });
  try {
    // the attacker's probes: the public prefix plus 1..63 hex digits of a guess, right or wrong, in parallel
    for (const digits of [1, 8, 32, 63]) {
      const [right, wrong] = await Promise.all([closeTiming(s.port, line.slice(0, 23 + digits), 3000), closeTiming(s.port, wrongLine.slice(0, 23 + digits), 3000)]);
      for (const [name, r] of [["right", right], ["wrong", wrong]]) {
        assert.equal(r.how, "closed", `${name} ${digits}: closed by the server`);
        assert.ok(r.ms >= deadline * 0.9, `${name} ${digits} digits: held until the deadline (${r.ms.toFixed(0)} ms), never closed early`);
        assert.equal(r.got.length, 0);
      }
      assert.ok(Math.abs(right.ms - wrong.ms) < deadline / 2, `${digits} digits: right ${right.ms.toFixed(0)} ms vs wrong ${wrong.ms.toFixed(0)} ms`);
    }
    // the whole line minus its newline (87 bytes, all 64 digits right) is still only partial
    const almost = await closeTiming(s.port, line.slice(0, 87), 3000);
    assert.ok(almost.ms >= deadline * 0.9, "87 correct bytes are not judged either");
    // a WHOLE wrong line is judged at once (it tells nothing short of the full 256-bit guess)
    const full = await closeTiming(s.port, wrongLine, 3000);
    assert.equal(full.how, "closed"); assert.ok(full.ms < deadline * 0.5, `a whole wrong line is refused promptly (${full.ms.toFixed(0)} ms)`);
    // EOF before the line: refused at once, alike for right and wrong prefixes
    for (const p of [line.slice(0, 40), wrongLine.slice(0, 40)]) {
      const r = await new Promise((resolve) => { const t0 = Date.now(); const c = net.connect(s.port, "127.0.0.1", () => c.end(p)); c.on("close", () => resolve(Date.now() - t0)); c.on("error", () => {}); });
      assert.ok(r < deadline * 0.5, "EOF ends it promptly, whatever the prefix");
    }
    assert.deepEqual([s.stats().requests, s.stats().pending, s.pending().length], [0, 0, 0], "no probe spent budget or a pending slot");
    // the whole right line still works
    const asked = client(s.port, line + requestLine(VAULT, DEP, B), { holdMs: 3000 });
    await until(() => s.pending().length, "the genuine request");
    assert.equal(s.stats().requests, 1);
    asked.then((r) => r.c.destroy());
  } finally { await s.close(); }
});

test("no oracle under a flood: correct-prefix partial lines cannot hold the gate against the bridge (oldest evicted, content-blind)", async () => {
  const credential = mintBridgeCredential(), line = bridgeAuthLine(credential);
  const s = await serveCustodyRequests({ deploymentId: DEP, vault: VAULT, credential, maxUnauthenticated: 4, authTimeoutMs: 1500 });
  const flood = [];
  try {
    for (let i = 0; i < 8; i++) { const c = net.connect(s.port, "127.0.0.1", () => c.write(line.slice(0, 60))); c.on("error", () => {}); flood.push(c); await tick(10); }
    await until(() => s.stats().gate.evicted >= 4, "content-blind eviction");
    const asked = client(s.port, line + requestLine(VAULT, DEP, B), { holdMs: 2000 });
    await until(() => s.pending().length, "the bridge's request past partial-line holders");
    asked.then((r) => r.c.destroy());
  } finally { for (const c of flood) c.destroy(); await s.close(); }
});
