// The signed Windows release channel (windows/node/release-channel.mjs): real P-256 keys made here for the test only,
// real loopback mirrors, the real CLI update-host.ps1 runs. What it must hold:
//   * only a statement signed by the pinned key(s), to the threshold, is a release; hashes from an unsigned latest.json
//     (or an envelope with no valid signature) are never trusted, however consistent they are with the files;
//   * a mirror that corrupts, truncates, withholds or serves an older release is refused or outvoted, never followed;
//   * two different signed statements for one version stop the update;
//   * a policy on the host is never replaced by accident.
//   run: node --test test/windows-release-channel.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { fileURLToPath } from "node:url";
import * as rc from "../windows/node/release-channel.mjs";
import { createUpdateWatch } from "../windows/node/update-watch.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLI = path.join(ROOT, "windows", "node", "release-channel.mjs");
const run = promisify(execFile);
const sha = (b) => createHash("sha256").update(b).digest("hex");
const p256 = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const pem = (k) => k.privateKey.export({ type: "pkcs8", format: "pem" });
const spec = (k) => rc.releaseKeySpec(k.publicKey);
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "enclave-release-"));
const A = p256(), B = p256(), C = p256(), STRANGER = p256();

function release(version, { channel = "stable", issuedAt = "2026-10-19T00:00:00.000Z", expiresAt, tweak = {} } = {}) {
  const zip = Buffer.from(`zip of ${version} `.repeat(40)), setup = Buffer.from(`setup ${version} `.repeat(20)),
        manifest = Buffer.from(JSON.stringify({ version, files: [] }));
  const statement = { format: rc.STATEMENT_FORMAT, channel, version, issuedAt, ...(expiresAt ? { expiresAt } : {}),
    file: `enclave-host-${version}.zip`, sha256: sha(zip), bytes: zip.length,
    setup: `EnclaveSetup-${version}.exe`, setupSha256: sha(setup), setupBytes: setup.length,
    manifest: `manifest-${version}.json`, manifestSha256: sha(manifest), manifestBytes: manifest.length, ...tweak };
  return { statement, files: { [statement.file]: zip, [statement.setup]: setup, [statement.manifest]: manifest } };
}
const policyOf = (over = {}) => rc.validateReleasePolicy({ format: rc.POLICY_FORMAT, channel: "stable", keys: [spec(A)], threshold: 1,
                                                          mirrors: ["https://mirror-a.example/windows/"], ...over });
const NOW = Date.parse("2026-10-19T12:00:00Z");

/** A loopback mirror: path -> Buffer | (req,res)=>void. */
async function mirror(routes) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    seen.push(req.url);
    const r = routes[req.url];
    if (typeof r === "function") return r(req, res);
    if (!r) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { "content-length": r.length }); res.end(r);
  });
  await new Promise((ok) => srv.listen(0, "127.0.0.1", ok));
  const base = `http://127.0.0.1:${srv.address().port}/windows/`;
  return { base, seen, close: () => new Promise((ok) => { srv.close(ok); srv.closeAllConnections(); }) };
}
const routesOf = (rel, envelope) => Object.fromEntries([["/windows/latest.signed.json", Buffer.from(envelope)],
  ...Object.entries(rel.files).map(([n, b]) => [`/windows/${n}`, b])]);

test("a release key is exactly an uncompressed P-256 SPKI, and its id is the sha256 of that DER", () => {
  const k = rc.parseReleaseKey(spec(A));
  const der = A.publicKey.export({ type: "spki", format: "der" });
  assert.equal(k.keyId, sha(der));
  assert.equal(der.length, 91); assert.ok(der.subarray(0, 27).equals(rc.P256_SPKI_PREFIX), "the prefix EnclaveSetup.cs and host.ps1 slice at");
  const jwk = A.publicKey.export({ format: "jwk" });
  assert.ok(der.subarray(27, 59).equals(Buffer.from(jwk.x, "base64url")) && der.subarray(59, 91).equals(Buffer.from(jwk.y, "base64url")), "X at 27, Y at 59");
  const ed = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const p384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey.export({ type: "spki", format: "der" }).toString("base64");
  for (const bad of [`ecdsa-p256:${ed}`, `ecdsa-p256:${p384}`, `ed25519:${ed}`, "ecdsa-p256:not base64!", spec(A) + "=", spec(A).replace("ecdsa-p256:", "")])
    assert.throws(() => rc.parseReleaseKey(bad), undefined, bad.slice(0, 30));
});

test("a policy is strict: keys, threshold, https mirrors, nothing unknown", () => {
  const p = policyOf({ mirrors: ["https://m.example/w"] });
  assert.deepEqual(p.mirrors, ["https://m.example/w/"], "a mirror is a directory");
  assert.equal(policyOf({ mirrors: ["http://127.0.0.1:9/x/"] }).mirrors.length, 1, "http only for a loopback test mirror");
  const bad = [{ mirrors: ["http://mirror.example/"] }, { mirrors: ["https://u:p@m.example/"] }, { mirrors: ["https://m.example/?x=1"] },
    { mirrors: [] }, { keys: [] }, { keys: [spec(A), spec(A)] }, { threshold: 2 }, { threshold: 0 }, { channel: "Stable!" },
    { format: "other" }, { requireSigned: false }, { mirrors: ["https://a.example/", "https://a.example"] }];
  for (const b of bad) assert.throws(() => policyOf(b), undefined, JSON.stringify(b));
});

test("only a statement signed by pinned keys, to the threshold, verifies; hashes alone are never trust", () => {
  const { statement } = release("2026.10.19.1");
  const env = rc.signEnvelope(statement, [pem(A)]);
  const r = rc.verifyEnvelope(env, policyOf(), { now: NOW });
  assert.equal(r.statement.version, "2026.10.19.1"); assert.deepEqual(r.signers, [rc.parseReleaseKey(spec(A)).keyId]);
  // the legacy unsigned pointer, with perfectly consistent hashes, is not a release
  const legacy = JSON.stringify({ version: statement.version, file: statement.file, sha256: statement.sha256, bytes: statement.bytes,
                                  setup: statement.setup, setupSha256: statement.setupSha256, manifest: statement.manifest, manifestSha256: statement.manifestSha256 });
  assert.throws(() => rc.verifyEnvelope(legacy, policyOf(), { now: NOW }), /unknown field|format/);
  // the same statement with no signatures, or signed by a key nobody pinned, is not one either
  const unsigned = JSON.stringify({ ...JSON.parse(env), signatures: [] });
  assert.throws(() => rc.verifyEnvelope(unsigned, policyOf(), { now: NOW }), /0 valid signature/);
  assert.throws(() => rc.verifyEnvelope(rc.signEnvelope(statement, [pem(STRANGER)]), policyOf(), { now: NOW }), /0 valid signature/);
  // substituted bytes: the signature was over the original statement
  const e = JSON.parse(env);
  const swapped = { ...statement, sha256: sha(Buffer.from("evil")) };
  assert.throws(() => rc.verifyEnvelope(JSON.stringify({ ...e, statement: Buffer.from(JSON.stringify(swapped)).toString("base64") }), policyOf(), { now: NOW }), /0 valid signature/);
  // a signature by the right key over the bare statement (no domain separation) is not a release signature
  const bare = cryptoSign("sha256", Buffer.from(e.statement, "base64"), { key: A.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64");
  assert.throws(() => rc.verifyEnvelope(JSON.stringify({ ...e, signatures: [{ keyId: e.signatures[0].keyId, sig: bare }] }), policyOf(), { now: NOW }), /0 valid signature/);
});

test("a threshold counts distinct pinned keys; a repeated or unpinned signature adds nothing", () => {
  const { statement } = release("2026.10.19.2");
  const policy = policyOf({ keys: [spec(A), spec(B), spec(C)], threshold: 2 });
  assert.throws(() => rc.verifyEnvelope(rc.signEnvelope(statement, [pem(A)]), policy, { now: NOW }), /1 valid signature.*requires 2/);
  const one = JSON.parse(rc.signEnvelope(statement, [pem(A)]));
  const dup = JSON.stringify({ ...one, signatures: [one.signatures[0], one.signatures[0]] });
  assert.throws(() => rc.verifyEnvelope(dup, policy, { now: NOW }), /1 valid signature/);
  assert.throws(() => rc.verifyEnvelope(rc.signEnvelope(statement, [pem(A), pem(STRANGER)]), policy, { now: NOW }), /1 valid signature/);
  // a second signer adds their signature to the same bytes (cosign)
  const two = rc.addSignatures(rc.signEnvelope(statement, [pem(A)]), [pem(C)]);
  assert.equal(JSON.parse(two).statement, one.statement, "cosigning never changes the statement");
  assert.equal(rc.verifyEnvelope(two, policy, { now: NOW }).signers.length, 2);
});

test("a signed statement is still checked: channel, version-bound names, sizes, expiry, issue time", () => {
  const ok = (s, now = NOW) => rc.verifyEnvelope(rc.signEnvelope(s, [pem(A)]), policyOf(), { now });
  assert.throws(() => ok(release("1.2.3", { channel: "beta" }).statement), /channel/);
  assert.throws(() => ok(release("1.2.3", { tweak: { file: "../../evil.zip" } }).statement), /file must be enclave-host-1.2.3.zip/);
  assert.throws(() => ok(release("1.2.3", { tweak: { setup: "EnclaveSetup-1.2.4.exe" } }).statement), /setup must be/);
  assert.throws(() => ok(release("1.2.3", { tweak: { bytes: 3 * 1024 ** 3 } }).statement), /bytes is out of range/);
  assert.throws(() => ok(release("1.2.3.4.5").statement), /version/);
  assert.throws(() => ok(release("1.2.3", { tweak: { extra: 1 } }).statement), /unknown field/);
  assert.throws(() => ok(release("1.2.3", { expiresAt: "2026-10-19T06:00:00Z" }).statement), /expired/);
  assert.throws(() => ok(release("1.2.3", { issuedAt: "2026-10-25T00:00:00Z" }).statement), /future/);
  assert.equal(ok(release("1.2.3", { expiresAt: "2026-11-19T00:00:00Z" }).statement).statement.version, "1.2.3");
});

test("mirrors: the highest signed version wins; stale, corrupt and unsigned mirrors are refused, never followed", async () => {
  const v1 = release("2026.10.19.1"), v2 = release("2026.10.19.2");
  const fresh = await mirror(routesOf(v2, rc.signEnvelope(v2.statement, [pem(A)])));
  const stale = await mirror(routesOf(v1, rc.signEnvelope(v1.statement, [pem(A)])));
  const garbage = await mirror({ "/windows/latest.signed.json": Buffer.from("{\"format\":\"nope\"}"), "/windows/latest.json": Buffer.from(JSON.stringify({ version: "2099.1.1.1" })) });
  const forged = await mirror(routesOf(release("2099.1.1.1"), rc.signEnvelope(release("2099.1.1.1").statement, [pem(STRANGER)])));
  try {
    const policy = policyOf({ mirrors: [stale.base, garbage.base, forged.base, fresh.base] });
    const r = await rc.resolveRelease({ policy, installed: "2026.10.19.1", now: () => NOW });
    assert.equal(r.statement.version, "2026.10.19.2", "a stale mirror cannot hold the host back while another serves newer");
    assert.equal(r.newer, true); assert.deepEqual(r.servedBy, [fresh.base]);
    assert.equal(r.rejected.length, 2, "the garbage and the forged mirror");
    assert.ok(r.rejected.some((x) => x.mirror === forged.base && /0 valid signature/.test(x.reason)));
    for (const m of [stale, garbage, forged, fresh]) assert.ok(!m.seen.includes("/windows/latest.json"), "the unsigned pointer is never read");
    assert.equal((await rc.resolveRelease({ policy, installed: "2026.10.19.2", now: () => NOW })).newer, false);
    await assert.rejects(rc.resolveRelease({ policy: policyOf({ mirrors: [garbage.base, forged.base] }), now: () => NOW }), /no mirror served a release signed/);
  } finally { for (const m of [fresh, stale, garbage, forged]) await m.close(); }
});

test("two different signed statements for one version stop the update", async () => {
  const a = release("2026.10.19.3"), b = release("2026.10.19.3", { tweak: { sha256: sha(Buffer.from("other build")) } });
  const m1 = await mirror(routesOf(a, rc.signEnvelope(a.statement, [pem(A)]))), m2 = await mirror(routesOf(b, rc.signEnvelope(b.statement, [pem(A)])));
  try { await assert.rejects(rc.resolveRelease({ policy: policyOf({ mirrors: [m1.base, m2.base] }), now: () => NOW }), /two different signed statements/); }
  finally { await m1.close(); await m2.close(); }
});

test("downloads: a corrupt, truncated or oversized mirror is skipped; only the signed bytes are kept", async () => {
  const rel = release("2026.10.19.4"), name = rel.statement.file, good = rel.files[name];
  const flipped = Buffer.from(good); flipped[5] ^= 1;
  const corrupt = await mirror({ [`/windows/${name}`]: flipped });
  const short = await mirror({ [`/windows/${name}`]: good.subarray(0, good.length - 1) });
  const lying = await mirror({ [`/windows/${name}`]: (_q, res) => { res.writeHead(200); res.write(good); res.end(Buffer.from("more")); } });
  const right = await mirror({ [`/windows/${name}`]: good });
  const dir = tmp(), out = path.join(dir, name), logs = [];
  try {
    const r = await rc.downloadVerified({ mirrors: [corrupt.base, short.base, lying.base, right.base], name, sha256: rel.statement.sha256, bytes: rel.statement.bytes, out, log: (m) => logs.push(m) });
    assert.equal(r.mirror, right.base); assert.ok(fs.readFileSync(out).equals(good));
    assert.equal(logs.length, 3, logs.join("\n"));
    assert.match(logs[0], /hashes .* the signed sha256/); assert.match(logs[1], /signed size/); assert.match(logs[2], /more than the signed/);
    assert.deepEqual(fs.readdirSync(dir), [name], "no partial file is left behind");
    assert.equal((await rc.downloadVerified({ mirrors: [corrupt.base], name, sha256: rel.statement.sha256, bytes: rel.statement.bytes, out })).cached, true, "a resumed update keeps a checked file");
    const out2 = path.join(dir, "again.zip");
    await assert.rejects(rc.downloadVerified({ mirrors: [corrupt.base, short.base], name, sha256: rel.statement.sha256, bytes: rel.statement.bytes, out: out2 }), /no mirror served the signed bytes/);
    assert.ok(!fs.existsSync(out2));
    await assert.rejects(rc.downloadVerified({ mirrors: [right.base], name: "../escape.zip", sha256: rel.statement.sha256, bytes: 1, out: out2 }), /not a release file name/);
  } finally { for (const m of [corrupt, short, lying, right]) await m.close(); }
});

test("a policy on a host is never replaced by accident", () => {
  const dir = tmp(), dest = path.join(dir, "release-policy.json");
  assert.equal(rc.installPolicy({ policy: policyOf(), dest }), "written");
  assert.equal(rc.installPolicy({ policy: policyOf({ mirrors: ["https://mirror-a.example/windows"] }), dest }), "unchanged", "the same policy, spelled differently");
  assert.throws(() => rc.installPolicy({ policy: policyOf({ keys: [spec(B)] }), dest }), /different release policy/);
  assert.equal(rc.loadReleasePolicy(dest).keys[0].spec, spec(A), "the refused attempt changed nothing");
  assert.equal(rc.installPolicy({ policy: policyOf({ keys: [spec(B)] }), dest, replace: true }), "replaced");
  fs.writeFileSync(dest, "{broken");
  assert.throws(() => rc.installPolicy({ policy: policyOf(), dest }), /not a valid release policy/);
  assert.equal(rc.installPolicy({ policy: policyOf(), dest, replace: true }), "replaced");
  fs.writeFileSync(dest, "﻿" + fs.readFileSync(dest, "utf8"));
  assert.equal(rc.loadReleasePolicy(dest).channel, "stable", "PowerShell's byte-order mark is accepted");
});

test("the CLI update-host.ps1 runs: statement, sign, resolve and download over real mirrors", async () => {
  const dir = tmp(), v = "2026.10.19.5";
  const zip = path.join(dir, `enclave-host-${v}.zip`), setup = path.join(dir, `EnclaveSetup-${v}.exe`), manifest = path.join(dir, `manifest-${v}.json`);
  fs.writeFileSync(zip, "zip bytes ".repeat(500)); fs.writeFileSync(setup, "setup bytes"); fs.writeFileSync(manifest, JSON.stringify({ version: v, files: [] }));
  const keyFile = path.join(dir, "test-only-release-key.pem"); fs.writeFileSync(keyFile, pem(A), { mode: 0o600 });
  await run(process.execPath, [CLI, "statement", "--channel", "stable", "--version", v, "--zip", zip, "--setup", setup, "--manifest", manifest, "--valid-days", "30", "--out", path.join(dir, "st.json")]);
  await run(process.execPath, [CLI, "sign", "--statement", path.join(dir, "st.json"), "--key", keyFile, "--out", path.join(dir, "latest.signed.json")]);
  const pub = JSON.parse((await run(process.execPath, [CLI, "pubkey", "--key", keyFile])).stdout);
  assert.equal(pub.key, spec(A), "the operator derives the policy spec from the key they hold");
  const m = await mirror(Object.fromEntries(["latest.signed.json", path.basename(zip), path.basename(setup), path.basename(manifest)]
    .map((n) => [`/windows/${n}`, fs.readFileSync(path.join(dir, n))])));
  try {
    const policyFile = path.join(dir, "policy.json");
    fs.writeFileSync(policyFile, "﻿" + JSON.stringify({ format: rc.POLICY_FORMAT, channel: "stable", keys: [pub.key], threshold: 1, mirrors: [m.base] }));
    const out = path.join(dir, "resolved.json");
    await run(process.execPath, [CLI, "resolve", "--policy", policyFile, "--installed", "2026.10.19.4", "--out", out]);
    const r = JSON.parse(fs.readFileSync(out, "utf8"));
    assert.equal(r.version, v); assert.equal(r.newer, true); assert.equal(r.statement.sha256, sha(fs.readFileSync(zip)));
    const list = path.join(dir, "list.json"), got = path.join(dir, "got");
    fs.mkdirSync(got);
    fs.writeFileSync(list, "﻿" + JSON.stringify([{ name: r.statement.file, sha256: r.statement.sha256, bytes: r.statement.bytes, out: path.join(got, "z.zip") },
                                                      { name: r.statement.setup, sha256: r.statement.setupSha256, bytes: r.statement.setupBytes, out: path.join(got, "s.exe") }]));
    await run(process.execPath, [CLI, "download", "--policy", policyFile, "--list", list]);
    assert.ok(fs.readFileSync(path.join(got, "z.zip")).equals(fs.readFileSync(zip)));
    // a substituted setup on the mirror: the CLI exits non-zero and leaves nothing
    fs.rmSync(path.join(got, "s.exe"));
    const bad = await mirror({ [`/windows/${r.statement.setup}`]: Buffer.from("setup byteS"), "/windows/latest.signed.json": fs.readFileSync(path.join(dir, "latest.signed.json")) });
    fs.writeFileSync(policyFile, JSON.stringify({ format: rc.POLICY_FORMAT, channel: "stable", keys: [pub.key], threshold: 1, mirrors: [bad.base] }));
    await assert.rejects(run(process.execPath, [CLI, "download", "--policy", policyFile, "--list", list]), /no mirror served the signed bytes/);
    assert.ok(!fs.existsSync(path.join(got, "s.exe")));
    await bad.close();
    // no pinned key signed it: resolve exits non-zero and writes nothing
    fs.writeFileSync(policyFile, JSON.stringify({ format: rc.POLICY_FORMAT, channel: "stable", keys: [spec(B)], threshold: 1, mirrors: [m.base] }));
    fs.rmSync(out);
    await assert.rejects(run(process.execPath, [CLI, "resolve", "--policy", policyFile, "--installed", "1.0", "--out", out]), /no mirror served a release signed/);
    assert.ok(!fs.existsSync(out));
  } finally { await m.close(); }
});

test("the agent's minute watch: signed newer versions trigger; an unsigned newer one, or a broken policy, never does", async () => {
  const v2 = release("2026.10.19.7"), dir = tmp(), policyFile = path.join(dir, "release-policy.json");
  const m = await mirror({ ...routesOf(v2, rc.signEnvelope(v2.statement, [pem(B)])), "/windows/latest.json": Buffer.from(JSON.stringify({ version: "2099.1.1.1" })) });
  try {
    fs.writeFileSync(policyFile, JSON.stringify({ format: rc.POLICY_FORMAT, channel: "stable", keys: [spec(A)], threshold: 1, mirrors: [m.base] }));
    const runs = [], logs = [];
    const w = createUpdateWatch({ installed: "2026.10.19.6", fetchLatest: rc.createSignedLatest({ policyFile }), trigger: async () => runs.push(1), log: (x) => logs.push(x) });
    assert.equal(await w.check(), null, "signed by a key this host does not pin"); assert.equal(runs.length, 0);
    assert.match(logs.at(-1), /no mirror served a release signed/);
    fs.writeFileSync(policyFile, JSON.stringify({ format: rc.POLICY_FORMAT, channel: "stable", keys: [spec(B)], threshold: 1, mirrors: [m.base] }));
    assert.equal(await w.check(), "2026.10.19.7"); assert.equal(runs.length, 1);
    fs.writeFileSync(policyFile, "{not json");
    const w2 = createUpdateWatch({ installed: "2026.10.19.6", fetchLatest: rc.createSignedLatest({ policyFile }), trigger: async () => runs.push(2), log: (x) => logs.push(x) });
    assert.equal(await w2.check(), null, "a broken policy is an error, not a fall back to latest.json"); assert.equal(runs.length, 1);
    assert.ok(!m.seen.includes("/windows/latest.json"));
  } finally { await m.close(); }
});

// ---- bounds: memory, bytes and time, whatever is on disk or on the wire ----------------------------------------------
/** A route that answers the headers and then one byte every `everyMs`, never finishing (a mirror that trickles). */
const trickle = (len, everyMs = 100) => (req, res) => {
  res.writeHead(200, { "content-length": len }); res.flushHeaders();
  const t = setInterval(() => res.write("x"), everyMs);
  res.on("close", () => clearInterval(t));
};
/** A route that streams 64 KiB chunks for as long as anyone reads (no content-length: chunked). */
const endless = (sent) => (req, res) => {
  res.writeHead(200); const chunk = Buffer.alloc(64 * 1024, 7); let open = true;
  res.on("close", () => { open = false; });
  const pump = () => { while (open && res.write(chunk)) sent.n += chunk.length; if (open) res.once("drain", pump); };
  pump();
};
const heapish = () => { const m = process.memoryUsage(); return m.rss; };

test("a cached file is judged by its size first and hashed as a stream: a 2 GiB sparse mismatch costs no 2 GiB", async () => {
  const dir = tmp(), name = "enclave-host-9.9.zip", out = path.join(dir, name);
  const gone = await mirror({});   // every file: 404
  try {
    // the signed size, the wrong content: hashed 1 MiB at a time, refused, then each mirror asked; nothing replaces `out`
    fs.closeSync(fs.openSync(out, "w")); fs.truncateSync(out, rc.LIMITS.zip);
    const before = heapish(), t0 = Date.now();
    await assert.rejects(rc.downloadVerified({ mirrors: [gone.base], name, sha256: "ab".repeat(32), bytes: rc.LIMITS.zip, out }), /no mirror served the signed bytes.*HTTP 404/);
    assert.ok(heapish() - before < 256 * 1024 ** 2, `resident memory grew ${((heapish() - before) / 1024 ** 2).toFixed(0)} MiB hashing a 2 GiB cache file`);
    assert.equal(fs.statSync(out).size, rc.LIMITS.zip, "a failed verification never replaces or removes the file at out");
    assert.deepEqual(fs.readdirSync(dir), [name], "no part file left");
    // the sparse file of the right length but all zeros does hash to the sha256 of 2 GiB of zeros: that one is kept
    const zeros = createHash("sha256"); const mib = Buffer.alloc(1024 * 1024); for (let i = 0; i < 2048; i++) zeros.update(mib);
    assert.equal((await rc.downloadVerified({ mirrors: [gone.base], name, sha256: zeros.digest("hex"), bytes: rc.LIMITS.zip, out })).cached, true);
    // a different size is not even opened: one byte longer than the signed limit, refused at once
    fs.truncateSync(out, rc.LIMITS.zip + 1);
    const t1 = Date.now();
    await assert.rejects(rc.downloadVerified({ mirrors: [gone.base], name, sha256: "ab".repeat(32), bytes: 10, out }), /HTTP 404/);
    assert.ok(Date.now() - t1 < 2000, "judged by its size, not read");
    assert.ok(Date.now() - t0 < 60_000);
    // a directory, or a link, at out is never "the cached file"
    const linkOut = path.join(dir, "link.zip"); fs.writeFileSync(path.join(dir, "real"), "x"); fs.symlinkSync(path.join(dir, "real"), linkOut);
    await assert.rejects(rc.downloadVerified({ mirrors: [gone.base], name, sha256: sha(Buffer.from("x")), bytes: 1, out: linkOut }), /HTTP 404/);
  } finally { await gone.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("a mirror that announces too much, streams without end, or trickles is cut off; the next mirror is used", async () => {
  const rel = release("2026.10.19.8"), name = rel.statement.file, good = rel.files[name], bytes = good.length;
  const sent = { n: 0 };
  const announces = await mirror({ [`/windows/${name}`]: (_q, res) => { res.writeHead(200, { "content-length": 50 * 1024 ** 3 }); res.write("x"); } });
  const flood = await mirror({ [`/windows/${name}`]: endless(sent) });
  const slow = await mirror({ [`/windows/${name}`]: trickle(bytes) });
  const right = await mirror({ [`/windows/${name}`]: good });
  const dir = tmp(), out = path.join(dir, name), logs = [];
  try {
    const before = heapish(), t0 = Date.now();
    const r = await rc.downloadVerified({ mirrors: [announces.base, flood.base, slow.base, right.base], name, sha256: rel.statement.sha256, bytes, out,
                                          timeoutMs: 800, log: (m) => logs.push(m) });
    assert.equal(r.mirror, right.base); assert.ok(fs.readFileSync(out).equals(good));
    assert.match(logs[0], /announces 53687091200 bytes, the signed size is/);
    assert.match(logs[1], /sent more than the signed/);
    assert.match(logs[2], /deadline passed/);
    assert.ok(Date.now() - t0 < 5000, "the trickling mirror held the download for its deadline, not forever");
    assert.ok(sent.n < 64 * 1024 ** 2, `the endless mirror was cut off early (${sent.n} bytes sent)`);
    assert.ok(heapish() - before < 128 * 1024 ** 2);
    assert.deepEqual(fs.readdirSync(dir), [name], "no part file left by any refused mirror");
    // one hard deadline over every mirror: two trickling mirrors cannot each take their own
    const t1 = Date.now();
    await assert.rejects(rc.downloadVerified({ mirrors: [slow.base, slow.base, slow.base], name, sha256: rel.statement.sha256, bytes, out: path.join(dir, "x"),
                                               timeoutMs: 600, deadlineMs: 900 }), /deadline/);
    assert.ok(Date.now() - t1 < 2500, `${Date.now() - t1} ms`);
    // cancellation: the caller's signal stops it, and leaves nothing
    const ac = new AbortController(); setTimeout(() => ac.abort(), 200);
    await assert.rejects(rc.downloadVerified({ mirrors: [slow.base, right.base], name, sha256: rel.statement.sha256, bytes, out: path.join(dir, "y"), signal: ac.signal }), /cancelled|abort/i);
    assert.deepEqual(fs.readdirSync(dir), [name]);
  } finally { for (const m of [announces, flood, slow, right]) await m.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("resolve: a mirror that trickles its envelope, or sends more than 64 KiB, is refused within its deadline", async () => {
  const v = release("2026.10.19.9"), env = rc.signEnvelope(v.statement, [pem(A)]);
  const sent = { n: 0 };
  const slow = await mirror({ "/windows/latest.signed.json": trickle(1000) });
  const flood = await mirror({ "/windows/latest.signed.json": endless(sent) });
  const right = await mirror(routesOf(v, env));
  try {
    const t0 = Date.now();
    const r = await rc.resolveRelease({ policy: policyOf({ mirrors: [slow.base, flood.base, right.base] }), now: () => NOW, timeoutMs: 700 });
    assert.equal(r.statement.version, "2026.10.19.9"); assert.ok(Date.now() - t0 < 3000);
    assert.equal(r.rejected.length, 2); assert.match(r.rejected.map((x) => x.reason).join("|"), /more than 65536/);
    assert.ok(sent.n < 8 * 1024 ** 2);
  } finally { for (const m of [slow, flood, right]) await m.close(); }
});

test("refusals EnclaveSetup.cs and cli/host.ps1 make too: rolled-over times, 1.0 sizes, odd mirror spellings, 1.2 vs 1.2.0", async () => {
  const ok = (s) => rc.verifyEnvelope(rc.signEnvelope(s, [pem(A)]), policyOf(), { now: NOW });
  // .NET's DateTime.TryParse refuses 02-30 and 24:00; Date.parse rolls them over. Refused here too.
  for (const t of ["2026-02-30T00:00:00Z", "2026-10-18T24:00:00Z", "2026-10-18T12:00:00+00:00", "2026-10-18 12:00:00Z", "2026-10-18T12:00:00.1234Z"])
    assert.throws(() => ok(release("1.2.3", { issuedAt: t }).statement), /issuedAt must be/, t);
  assert.throws(() => ok(release("1.2.3", { tweak: { expiresAt: null } }).statement), /expiresAt must be/, "a null expiry is not no expiry");
  // a size written 1.0 or 1e3 is a decimal to JavaScriptSerializer: refused here, though JSON.parse reads an integer
  const st = release("1.2.3").statement, text = JSON.stringify(st);
  for (const sub of [`"bytes":${st.bytes}.0`, `"bytes":${st.bytes}e0`, `"bytes":${st.bytes}E0`]) {
    const e = JSON.parse(rc.signEnvelope(st, [pem(A)]));
    const bytes = Buffer.from(text.replace(`"bytes":${st.bytes}`, sub));
    const env = JSON.stringify({ ...e, statement: bytes.toString("base64"), signatures: [{ keyId: e.signatures[0].keyId,
      sig: cryptoSign("sha256", Buffer.concat([rc.SIGNING_CONTEXT, bytes]), { key: A.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64") }] });
    assert.throws(() => rc.verifyEnvelope(env, policyOf(), { now: NOW }), /whole numbers/, sub);
  }
  assert.equal(ok({ ...st, version: "1.2.3", sha256: "e".repeat(64) }).statement.sha256, "e".repeat(64), "an e inside a string is not an exponent");
  // a policy's threshold written 1.0 is refused the same way
  const dir = tmp(), f = path.join(dir, "p.json");
  fs.writeFileSync(f, JSON.stringify(rc.policyDocument(policyOf())).replace('"threshold":1', '"threshold":1.0'));
  assert.throws(() => rc.loadReleasePolicy(f), /whole numbers/);
  // a policy file is refused by its size before it is read
  fs.closeSync(fs.openSync(f, "w")); fs.truncateSync(f, 1024 ** 3);
  assert.throws(() => rc.loadReleasePolicy(f), /too large/);
  fs.rmSync(dir, { recursive: true, force: true });
  // mirrors: printable ASCII, no \ ? # @ %: nothing .NET's Uri and WHATWG URL would spell differently
  for (const m of ["https://m.example/a b/", " https://m.example/", "https://m.example\\w/", "https://m.example/w/?", "https://m.example/w/#",
                   "https://m.example/%77/", "https://u@m.example/", "https://bücher.example/", "http://127.0.0.2/", "http://localhost.example/"])
    assert.throws(() => policyOf({ mirrors: [m] }), /plain URL|https/, m);
  assert.deepEqual(policyOf({ mirrors: ["HTTPS://M.Example:443/W", "https://m.example/a/../b"] }).mirrors, ["https://m.example/W/", "https://m.example/b/"]);
  // the host as written: IPv6 only ::1 (compressed or in full, written back [::1]); numbers only as a plain dotted quad;
  // http only for localhost, 127.0.0.1 and [::1] exactly (EnclaveSetup.cs refused [::1] by comparing Uri.Host: case 29)
  assert.deepEqual(policyOf({ mirrors: ["http://[::1]:9/w/", "http://[0000:0000:0000:0000:0000:0000:0000:0001]/x", "https://[0:0:0:0:0:0:0:1]:443/y"] }).mirrors,
                   ["http://[::1]:9/w/", "http://[::1]/x/", "https://[::1]/y/"]);
  assert.throws(() => policyOf({ mirrors: ["http://[::1]/", "http://[0:0:0:0:0:0:0:1]:80/"] }), /twice/, "two spellings of one loopback mirror");
  for (const m of ["http://[::2]/", "http://[::]/", "http://[::ffff:127.0.0.1]/", "http://[fe80::1]/", "https://[2001:db8::1]/", "http://[::1/",
                   "http://127.1/", "http://2130706433/", "http://0x7f000001/", "http://127.0.0.01/", "http://localhost./", "http://sub.localhost/",
                   "http://localhost:/", "https://m.example./", "https://m_x.example/", "https://256.0.0.1/"])
    assert.throws(() => policyOf({ mirrors: [m] }), /written plainly|https|not a URL/, m);
  assert.deepEqual(policyOf({ mirrors: ["HTTP://LOCALHOST/w", "http://127.0.0.1:65535/"] }).mirrors, ["http://localhost/w/", "http://127.0.0.1:65535/"]);
  assert.throws(() => policyOf({ mirrors: ["https://m.example/w", "HTTPS://M.EXAMPLE:443/w/"] }), /twice/);
  // 1.2 and 1.2.0 are one [System.Version]: two statements for it are equivocation, as setup and host.ps1 judge it
  const a = release("2026.10"), b = release("2026.10.0");
  const m1 = await mirror(routesOf(a, rc.signEnvelope(a.statement, [pem(A)]))), m2 = await mirror(routesOf(b, rc.signEnvelope(b.statement, [pem(A)])));
  try { await assert.rejects(rc.resolveRelease({ policy: policyOf({ mirrors: [m1.base, m2.base] }), now: () => NOW }), /two different signed statements/); }
  finally { await m1.close(); await m2.close(); }
});
