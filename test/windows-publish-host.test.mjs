// scripts/publish-windows-host.sh, retargeted off Nan: it stages a signed release channel and copies it only to the
// mirrors named on its command line. Run here end to end on a small fake release (a real zip with a real manifest),
// signed with keys made for this test only, mirrored to local directories, then resolved and downloaded by the host's
// own verifier (release-channel.mjs) from those mirrors over loopback HTTP.
//   run: node --test test/windows-publish-host.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { createHash, generateKeyPairSync } from "node:crypto";
import { fileURLToPath } from "node:url";
import * as rc from "../windows/node/release-channel.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = path.join(ROOT, "scripts", "publish-windows-host.sh");
const run = promisify(execFile);
const sha = (b) => createHash("sha256").update(b).digest("hex");
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "enclave-publish-"));
const keyFile = (dir, name) => { const f = path.join(dir, name); fs.writeFileSync(f, generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 }); return f; };

/** A built release as build-bundle.ps1 leaves it: enclave-host-<v>.zip (manifest.json + files) and EnclaveSetup.exe. */
function built(dir, version, files = { "control/a.mjs": "export const a = 1;\n", "bin/b.exe": "MZ fake" }) {
  const out = path.join(dir, `out-${version}`); fs.mkdirSync(out);
  const manifest = { version, files: Object.entries(files).map(([p, c]) => ({ path: p, sha256: sha(Buffer.from(c)), bytes: Buffer.byteLength(c) })) };
  execFileSync("python3", ["-c", `
import json, sys, zipfile
z = zipfile.ZipFile(sys.argv[1], "w")
z.writestr("manifest.json", "\\ufeff" + sys.argv[2])
for p, c in json.loads(sys.argv[3]).items(): z.writestr(p, c)
z.close()`, path.join(out, `enclave-host-${version}.zip`), JSON.stringify(manifest), JSON.stringify(files)]);
  fs.writeFileSync(path.join(out, "EnclaveSetup.exe"), `setup for ${version}`);
  return out;
}
const publish = (args) => run("bash", [SCRIPT, ...args], { cwd: ROOT });

test("the publisher has no built-in destination and never reaches for Nan", () => {
  const src = fs.readFileSync(SCRIPT, "utf8").split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
  assert.doesNotMatch(src, /\bssh\b|\bscp\b|\bnan\b|enclave-get|get\.enclave\.host/);
});

test("stage, sign and mirror a release; the host verifies it from those mirrors", async () => {
  const dir = tmp(), stage = path.join(dir, "channel"), m1 = path.join(dir, "mirror-1"), m2 = path.join(dir, "mirror-2");
  const k1 = keyFile(dir, "test-only-1.pem"), k2 = keyFile(dir, "test-only-2.pem");
  const v = "2026.10.19.11", out = built(dir, v);
  const { stdout } = await publish([out, "--stage", stage, "--sign-key", k1, "--dest", m1, "--dest", m2, "--require-signed", "--valid-days", "90"]);
  assert.match(stdout, /signed pointer: \{"version":"2026\.10\.19\.11"/);
  for (const d of [stage, m1, m2])
    for (const f of ["latest.signed.json", `release-${v}.signed.json`, `enclave-host-${v}.zip`, `EnclaveSetup-${v}.exe`, `manifest-${v}.json`, `SHA256SUMS-${v}`, "latest.json", "host.ps1"])
      assert.ok(fs.existsSync(path.join(d, f)), `${d}/${f}`);
  assert.ok(fs.existsSync(path.join(m1, "files", sha(Buffer.from("MZ fake")))), "every release file under files/<sha256>");
  // the signed pointer names exactly the published bytes
  const policy = rc.validateReleasePolicy({ format: rc.POLICY_FORMAT, channel: "stable", keys: [rc.releaseKeySpec(fs.readFileSync(k1, "utf8"))], threshold: 1, mirrors: ["https://unused.example/"] });
  const { statement } = rc.verifyEnvelope(fs.readFileSync(path.join(m2, "latest.signed.json")), policy);
  assert.equal(statement.sha256, sha(fs.readFileSync(path.join(out, `enclave-host-${v}.zip`))));
  assert.equal(statement.setupSha256, sha(fs.readFileSync(path.join(out, "EnclaveSetup.exe"))));
  assert.equal(statement.manifestSha256, sha(fs.readFileSync(path.join(m1, `manifest-${v}.json`))));
  assert.ok(statement.expiresAt, "--valid-days sets an expiry");

  // the host side: serve mirror-1 over loopback; corrupt mirror-2's zip; resolve and download only the signed bytes
  const flipped = fs.readFileSync(path.join(m2, `enclave-host-${v}.zip`)); flipped[10] ^= 1; fs.writeFileSync(path.join(m2, `enclave-host-${v}.zip`), flipped);
  const serve = (root) => new Promise((ok) => { const s = http.createServer((q, r) => {
    const f = path.join(root, decodeURIComponent(q.url.replace(/^\/windows\//, "")));
    if (!f.startsWith(root) || !fs.existsSync(f)) { r.writeHead(404); return r.end(); }
    r.end(fs.readFileSync(f)); }); s.listen(0, "127.0.0.1", () => ok(s)); });
  const s1 = await serve(m1), s2 = await serve(m2);
  try {
    const live = rc.validateReleasePolicy({ format: rc.POLICY_FORMAT, channel: "stable", keys: [rc.releaseKeySpec(fs.readFileSync(k1, "utf8"))], threshold: 1,
      mirrors: [`http://127.0.0.1:${s2.address().port}/windows/`, `http://127.0.0.1:${s1.address().port}/windows/`] });
    const r = await rc.resolveRelease({ policy: live, installed: "2026.10.19.10" });
    assert.equal(r.statement.version, v); assert.equal(r.servedBy.length, 2);
    const got = path.join(dir, "got.zip");
    const d = await rc.downloadVerified({ mirrors: live.mirrors, name: r.statement.file, sha256: r.statement.sha256, bytes: r.statement.bytes, out: got });
    assert.equal(d.mirror, live.mirrors[1], "the corrupted mirror was skipped");
  } finally { s1.close(); s2.close(); }

  // a re-run (another mirror, a second signer) keeps ONE statement for the version: no equivocation, one more signature
  const before = JSON.parse(fs.readFileSync(path.join(stage, "latest.signed.json"), "utf8"));
  await publish([out, "--stage", stage, "--sign-key", k2, "--dest", m1]);
  const after = JSON.parse(fs.readFileSync(path.join(m1, "latest.signed.json"), "utf8"));
  assert.equal(after.statement, before.statement, "the same statement bytes");
  assert.equal(after.signatures.length, 2);
  const both = rc.validateReleasePolicy({ format: rc.POLICY_FORMAT, channel: "stable", threshold: 2, mirrors: ["https://unused.example/"],
    keys: [k1, k2].map((k) => rc.releaseKeySpec(fs.readFileSync(k, "utf8"))) });
  assert.equal(rc.verifyEnvelope(JSON.stringify(after), both).signers.length, 2, "now meets a 2-of-2 policy");
});

test("a published file is immutable, and an unsigned publish is refused when signatures are required", async () => {
  const dir = tmp(), stage = path.join(dir, "channel"), m = path.join(dir, "mirror");
  const k = keyFile(dir, "test-only.pem"), v = "2026.10.19.12";
  const out = built(dir, v);
  await publish([out, "--stage", stage, "--sign-key", k, "--dest", m]);
  fs.writeFileSync(path.join(m, `SHA256SUMS-${v}`), "tampered\n");
  await assert.rejects(publish([out, "--stage", stage, "--sign-key", k, "--dest", m]), /differs from the release: not overwritten/);
  const other = built(fs.mkdtempSync(path.join(dir, "x-")), v, { "control/a.mjs": "export const a = 2;\n" });
  await assert.rejects(publish([other, "--stage", stage, "--sign-key", k]), /already in .* with different content: a published version is immutable/);
  await assert.rejects(publish([out, "--stage", path.join(dir, "c2"), "--require-signed"]), /--require-signed: no --sign-key/);
  await assert.rejects(publish([out]), /--stage <channel-dir> is required/);
  const { stderr } = await publish([built(fs.mkdtempSync(path.join(dir, "y-")), "2026.10.19.13"), "--stage", path.join(dir, "c3")]);
  assert.match(stderr, /published UNSIGNED/);
  assert.ok(!fs.existsSync(path.join(dir, "c3", "latest.signed.json")) && fs.existsSync(path.join(dir, "c3", "latest.json")));
});
