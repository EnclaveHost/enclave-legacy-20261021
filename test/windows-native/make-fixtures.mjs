// test/windows-native/make-fixtures.mjs -- the cross-language fixtures for the signed Windows release channel.
//
// One fixture set, three verifiers: windows/node/release-channel.mjs (Node), EnclaveSetup.cs ReleaseChannel (C#, .NET
// Framework) and cli/host.ps1 (Windows PowerShell 5.1). Each case is a policy (as its exact JSON text for Node and C#, and
// as the ENCLAVE_RELEASE_* parts cli/host.ps1 takes) and, for envelope cases, an envelope's exact bytes and the time to
// judge it at. Each case also names the verdict it must get ("accept" or "refuse"). This script judges every case with Node
// and refuses to write fixtures Node disagrees with. test/windows-native/run.ps1 then holds C# and PowerShell to the same
// verdicts on Windows.
//
// Only public keys and signatures are written: the private keys are made here, used, and dropped.
//   node test/windows-native/make-fixtures.mjs [out.json]           (default test/windows-native/fixtures.json)
//   node test/windows-native/make-fixtures.mjs --check [in.json]     re-judge existing fixtures with this checkout's Node code
//                                                                   (writes test/windows-native/node-verdicts.json for run.ps1)
import fs from "node:fs";
import path from "node:path";
import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { fileURLToPath } from "node:url";
import * as rc from "../../windows/node/release-channel.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const NOW = "2026-10-19T12:00:00.000Z", NOW_MS = Date.parse(NOW);
const iso = (ms) => new Date(ms).toISOString();
const HOUR = 3600_000, DAY = 24 * HOUR;

/** Judge one case with this checkout's release-channel.mjs. */
export function judgeNode(c) {
  try {
    const p = rc.parseReleasePolicy(c.policyJson);
    if (c.envelope === undefined) return { verdict: "accept", mirrors: [...p.mirrors] };
    const r = rc.verifyEnvelope(Buffer.from(c.envelope, "base64"), p, { now: Date.parse(c.now) });
    return { verdict: "accept", version: r.statement.version, signers: r.signers.length, statementSha256: r.statementSha256 };
  } catch (e) { return { verdict: "refuse", why: e.message }; }
}

function build() {
  const p256 = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spec = (k) => rc.releaseKeySpec(k.publicKey);
  const A = p256(), B = p256(), C = p256(), S = p256();
  const keyId = (k) => rc.parseReleaseKey(spec(k)).keyId;
  const sigOver = (bytes, k) => cryptoSign("sha256", Buffer.concat([rc.SIGNING_CONTEXT, bytes]), { key: k.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64");
  const sigsFor = (bytes, keys) => keys.map((k) => ({ keyId: keyId(k), sig: sigOver(bytes, k) }));

  // ---- policies -----------------------------------------------------------------------------------------------------
  // ps: the parts cli/host.ps1 takes ({keys, mirrors, threshold, channel}); policyJson: the file Node and C# read
  const base = { keys: [spec(A), spec(B)], mirrors: ["https://mirror.invalid/windows/"], threshold: "2", channel: "test" };
  const policyJsonOf = (ps, { thresholdRaw, extra = "" } = {}) =>
    `{"format":"${rc.POLICY_FORMAT}","channel":${JSON.stringify(ps.channel)},"keys":${JSON.stringify(ps.keys)},` +
    `"threshold":${thresholdRaw ?? (/^[0-9]+$/.test(ps.threshold) ? String(Number(ps.threshold)) : JSON.stringify(ps.threshold))},` +
    `"mirrors":${JSON.stringify(ps.mirrors)}${extra}}`;
  const BASE_POLICY = policyJsonOf(base);

  const cases = [];
  const policyCase = (name, over, expect, opts = {}) => {
    const ps = { ...base, ...over };
    cases.push({ name: `policy: ${name}`, kind: "policy", ps: opts.psSkip ? null : ps, psSkip: opts.psSkip, policyJson: opts.policyJson ?? policyJsonOf(ps, opts), expect, mirrors: opts.mirrors });
  };
  policyCase("the base policy", {}, "accept", { mirrors: ["https://mirror.invalid/windows/"] });
  policyCase("no keys", { keys: [] }, "refuse");
  const nine = Array.from({ length: 9 }, () => spec(p256()));
  policyCase("eight keys", { keys: nine.slice(0, 8) }, "accept");
  policyCase("nine keys", { keys: nine }, "refuse");
  policyCase("one key listed twice", { keys: [spec(A), spec(A)] }, "refuse");
  const b64 = spec(A).slice(11);
  policyCase("a key in non-canonical base64 (a trailing newline)", { keys: [spec(A) + "\n", spec(B)] }, "refuse");
  policyCase("a key without its prefix", { keys: [b64, spec(B)] }, "refuse");
  policyCase("a P-384 key", { keys: [`ecdsa-p256:${generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey.export({ type: "spki", format: "der" }).toString("base64")}`, spec(B)] }, "refuse");
  const offCurve = Buffer.from(b64, "base64"); offCurve[90] ^= 1;
  policyCase("a key whose point is not on the curve", { keys: [`ecdsa-p256:${offCurve.toString("base64")}`, spec(B)] }, "refuse");
  for (const [t, v] of [["0", "refuse"], ["3", "refuse"], ["1", "accept"], ["01", "accept"], ["x", "refuse"], ["-1", "refuse"], ["99999999999", "refuse"]])
    policyCase(`threshold ${JSON.stringify(t)}`, { threshold: t }, v);
  policyCase("threshold written 1.0", { threshold: "1.0" }, "refuse", { thresholdRaw: "1.0" });
  policyCase("threshold written 1e0", { threshold: "1e0" }, "refuse", { thresholdRaw: "1e0" });
  for (const [ch, v] of [["Stable", "refuse"], ["stable\n", "refuse"], ["", "refuse"], ["a".repeat(32), "accept"], ["a".repeat(33), "refuse"], ["release-1.x_y", "accept"]])
    policyCase(`channel ${JSON.stringify(ch)}`, { channel: ch }, v);
  for (const [m, v, norm] of [
    ["HTTPS://M.Example:443/W", "accept", ["https://m.example/W/"]], ["https://m.example/a/../b", "accept", ["https://m.example/b/"]],
    ["https://m.example", "accept", ["https://m.example/"]], ["http://localhost:8080/x", "accept", ["http://localhost:8080/x/"]],
    ["http://127.0.0.1/", "accept", ["http://127.0.0.1/"]], ["http://[::1]:9/w/", "accept", ["http://[::1]:9/w/"]],
    ["http://127.0.0.2/", "refuse"], ["http://m.example/", "refuse"], ["ftp://m.example/", "refuse"], ["https://u:p@m.example/", "refuse"],
    ["https://m.example/w/?x=1", "refuse"], ["https://m.example/w/?", "refuse"], ["https://m.example/w/#", "refuse"], ["https://m.example/%77/", "refuse"],
    ["https://m.example/a b/", "refuse"], [" https://m.example/", "refuse"], ["https://m.example\\w/", "refuse"], ["https://bücher.example/", "refuse"],
    ["https://m.example/w/\n", "refuse"], ["m.example/w/", "refuse"],
    // IPv6: only ::1, however it is written; .NET's Uri.Host spells IPv6 its own way (native run 2026-10-20, case 29)
    ["http://[::1]/", "accept", ["http://[::1]/"]], ["http://[0:0:0:0:0:0:0:1]:9/w/", "accept", ["http://[::1]:9/w/"]],
    ["http://[0000:0000:0000:0000:0000:0000:0000:0001]/w", "accept", ["http://[::1]/w/"]], ["HTTP://[::1]:8080/A/../w", "accept", ["http://[::1]:8080/w/"]],
    ["https://[::1]:443/w/", "accept", ["https://[::1]/w/"]], ["http://[::1]:80/", "accept", ["http://[::1]/"]],
    ["http://[::2]/", "refuse"], ["http://[::]/", "refuse"], ["http://[::ffff:127.0.0.1]/", "refuse"], ["http://[::ffff:7f00:1]/", "refuse"],
    ["http://[fe80::1]/", "refuse"], ["https://[2001:db8::1]/", "refuse"], ["http://[0:0:0:0:0:0:0:2]/", "refuse"], ["http://[::1/", "refuse"],
    // IPv4 and names: only plainly written ones; http only for 127.0.0.1 and localhost exactly
    ["http://127.1/", "refuse"], ["http://2130706433/", "refuse"], ["http://0x7f000001/", "refuse"], ["http://0x7f.0.0.1/", "refuse"],
    ["http://127.0.0.01/", "refuse"], ["http://127.000.000.001/", "refuse"], ["http://127.0.0.2/w/", "refuse"], ["http://127.255.255.255/", "refuse"],
    ["http://localhost.localdomain/", "refuse"], ["http://localhost./", "refuse"], ["http://sub.localhost/", "refuse"],
    ["HTTP://LOCALHOST/w", "accept", ["http://localhost/w/"]], ["http://localhost:80/w/", "accept", ["http://localhost/w/"]],
    ["http://127.0.0.1:65535/", "accept", ["http://127.0.0.1:65535/"]], ["http://127.0.0.1:65536/", "refuse"], ["http://localhost:/", "refuse"],
    ["https://192.0.2.1/w/", "accept", ["https://192.0.2.1/w/"]], ["https://256.0.0.1/", "refuse"], ["https://m.example./", "refuse"],
    ["https://m..example/", "refuse"], ["https://-m.example/", "refuse"], ["https://m_x.example/", "refuse"], ["https://m.example.123/", "refuse"]])
    policyCase(`mirror ${JSON.stringify(m)}`, { mirrors: [m] }, v, { mirrors: norm });
  policyCase("one mirror spelled twice", { mirrors: ["https://m.example/w", "HTTPS://M.EXAMPLE:443/w/"] }, "refuse");
  policyCase("nine mirrors", { mirrors: Array.from({ length: 9 }, (_, i) => `https://m${i}.example/`) }, "refuse");
  policyCase("eight mirrors", { mirrors: Array.from({ length: 8 }, (_, i) => `https://m${i}.example/`) }, "accept",
             { mirrors: Array.from({ length: 8 }, (_, i) => `https://m${i}.example/`) });
  // what only a policy FILE can say (cli/host.ps1 builds its policy from parts, so it cannot be handed these)
  const fileOnly = (name, json) => policyCase(name, {}, "refuse", { psSkip: "a policy file only", policyJson: json });
  fileOnly("an unknown field", policyJsonOf(base, { extra: ',"requireSigned":false' }));
  fileOnly("another format", BASE_POLICY.replace(rc.POLICY_FORMAT, "enclave-windows-release-policy/v2"));
  fileOnly("keys not a list", BASE_POLICY.replace(/"keys":\[[^\]]*\]/, `"keys":${JSON.stringify(spec(A))}`));
  fileOnly("threshold as a string", BASE_POLICY.replace('"threshold":2', '"threshold":"2"'));
  fileOnly("threshold as true", BASE_POLICY.replace('"threshold":2', '"threshold":true'));
  fileOnly("not an object", "[]");
  cases.push({ name: "policy: with a byte-order mark (PowerShell's Set-Content -Encoding UTF8)", kind: "policy", ps: null, psSkip: "a policy file only",
               policyJson: "﻿" + BASE_POLICY, expect: "accept", mirrors: ["https://mirror.invalid/windows/"] });

  // ---- envelopes ----------------------------------------------------------------------------------------------------
  const statement = (v = "1.2.3", over = {}) => ({ format: rc.STATEMENT_FORMAT, channel: "test", version: v, issuedAt: iso(NOW_MS - HOUR),
    expiresAt: iso(NOW_MS + 30 * DAY), file: `enclave-host-${v}.zip`, sha256: "a".repeat(64), bytes: 1000,
    setup: `EnclaveSetup-${v}.exe`, setupSha256: "b".repeat(64), setupBytes: 1000, manifest: `manifest-${v}.json`, manifestSha256: "c".repeat(64), manifestBytes: 100, ...over });
  const envelopeOf = ({ text, keys = [A, B], sigs, extra = {}, raw }) => {
    const bytes = Buffer.from(text, "utf8");
    if (raw) return Buffer.from(raw(bytes));
    return Buffer.from(JSON.stringify({ format: rc.ENVELOPE_FORMAT, statement: bytes.toString("base64"), signatures: sigs ? sigs(bytes) : sigsFor(bytes, keys), ...extra }));
  };
  const envCase = (name, expect, env, { now = NOW, policyJson = BASE_POLICY, version, agreeOnly = false } = {}) =>
    cases.push({ name: `envelope: ${name}`, kind: "envelope", ps: { ...base, ...(policyJson === BASE_POLICY ? {} : JSON.parse(policyJson.replace(/^﻿/, ""))), threshold: policyJson === BASE_POLICY ? "2" : String(JSON.parse(policyJson).threshold) },
                 policyJson, envelope: env.toString("base64"), now, expect, version, agreeOnly });
  const st = (v, over) => JSON.stringify(statement(v, over));

  envCase("2 of 2 pinned keys", "accept", envelopeOf({ text: st() }), { version: "1.2.3" });
  envCase("1 of 2 (threshold not met)", "refuse", envelopeOf({ text: st(), keys: [A] }));
  envCase("signed by an unpinned key and one pinned", "refuse", envelopeOf({ text: st(), keys: [A, S] }));
  envCase("no signatures", "refuse", envelopeOf({ text: st(), keys: [] }));
  envCase("the statement changed after signing", "refuse", envelopeOf({ text: st(), sigs: () => sigsFor(Buffer.from(st("1.2.3", { sha256: "d".repeat(64) })), [A, B]) }));
  envCase("signed without the signing context", "refuse", envelopeOf({ text: st(), sigs: (b) => [A, B].map((k) => ({ keyId: keyId(k),
    sig: cryptoSign("sha256", b, { key: k.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64") })) }));
  envCase("expired", "refuse", envelopeOf({ text: st("1.2.3", { expiresAt: iso(NOW_MS - 1000) }) }));
  envCase("expiring exactly now", "refuse", envelopeOf({ text: st("1.2.3", { expiresAt: NOW }) }));
  envCase("expiring in a second", "accept", envelopeOf({ text: st("1.2.3", { expiresAt: iso(NOW_MS + 1000) }) }), { version: "1.2.3" });
  envCase("no expiry", "accept", envelopeOf({ text: JSON.stringify((({ expiresAt, ...s }) => s)(statement())) }), { version: "1.2.3" });
  envCase("expiresAt null", "refuse", envelopeOf({ text: st("1.2.3", { expiresAt: null }) }));
  envCase("issued 25 hours ahead", "refuse", envelopeOf({ text: st("1.2.3", { issuedAt: iso(NOW_MS + 25 * HOUR) }) }));
  envCase("issued 23 hours ahead (clock skew)", "accept", envelopeOf({ text: st("1.2.3", { issuedAt: iso(NOW_MS + 23 * HOUR) }) }), { version: "1.2.3" });
  for (const t of ["2026-02-30T00:00:00Z", "2026-10-18T24:00:00Z", "2026-10-18T12:00:00+00:00", "2026-10-18T12:00:00", "2026-10-18T12:00:00.1234Z", "2026-10-18T12:00:00Z\n"])
    envCase(`issuedAt ${JSON.stringify(t)}`, "refuse", envelopeOf({ text: st("1.2.3", { issuedAt: t }) }));
  envCase("issuedAt with milliseconds", "accept", envelopeOf({ text: st("1.2.3", { issuedAt: "2026-10-18T12:00:00.5Z" }) }), { version: "1.2.3" });
  envCase("another channel", "refuse", envelopeOf({ text: st("1.2.3", { channel: "other" }) }));
  envCase("the channel in another case", "refuse", envelopeOf({ text: st("1.2.3", { channel: "TEST" }) }));
  envCase("the statement format in another case", "refuse", envelopeOf({ text: st("1.2.3", { format: rc.STATEMENT_FORMAT.toUpperCase() }) }));
  envCase("version 1.2.3.4", "accept", envelopeOf({ text: st("1.2.3.4") }), { version: "1.2.3.4" });
  envCase("version 1.2.3.4.5", "refuse", envelopeOf({ text: st("1.2.3.4.5") }));
  envCase("version with a final newline", "refuse", envelopeOf({ text: st("1.2.3\n") }));
  envCase("version in Arabic-Indic digits", "refuse", envelopeOf({ text: st("١.٢") }));
  envCase("version as a number", "refuse", envelopeOf({ text: st("1.2.3").replace('"version":"1.2.3"', '"version":1.2') }));
  envCase("a zip name not bound to the version", "refuse", envelopeOf({ text: st("1.2.3", { file: "../evil.zip" }) }));
  envCase("a sha256 in capitals", "refuse", envelopeOf({ text: st("1.2.3", { setupSha256: "B".repeat(64) }) }));
  envCase("a size written 1000.0", "refuse", envelopeOf({ text: st().replace('"bytes":1000', '"bytes":1000.0') }));
  envCase("a size written 1e3", "refuse", envelopeOf({ text: st().replace('"bytes":1000', '"bytes":1e3') }));
  envCase("a size as a string", "refuse", envelopeOf({ text: st().replace('"bytes":1000', '"bytes":"1000"') }));
  envCase("a size of 0", "refuse", envelopeOf({ text: st("1.2.3", { bytes: 0 }) }));
  envCase("a zip of exactly 2 GiB", "accept", envelopeOf({ text: st("1.2.3", { bytes: 2 ** 31 }) }), { version: "1.2.3" });
  envCase("a zip over 2 GiB", "refuse", envelopeOf({ text: st("1.2.3", { bytes: 2 ** 31 + 1 }) }));
  envCase("a setup over 64 MiB", "refuse", envelopeOf({ text: st("1.2.3", { setupBytes: 64 * 1024 ** 2 + 1 }) }));
  envCase("a manifest over 16 MiB", "refuse", envelopeOf({ text: st("1.2.3", { manifestBytes: 16 * 1024 ** 2 + 1 }) }));
  envCase("an unknown statement field", "refuse", envelopeOf({ text: st("1.2.3", { extra: 1 }) }));
  envCase("a statement field in another case", "refuse", envelopeOf({ text: st().replace('"version"', '"Version"') }));
  envCase("a statement that is a list", "refuse", envelopeOf({ text: "[1]" }));
  envCase("a statement field given twice (last one valid)", null, envelopeOf({ text: st().replace('"sha256":"', `"sha256":"${"d".repeat(64)}","sha256":"`) }), { agreeOnly: true });
  envCase("a statement padded past 16 KiB with whitespace", "refuse", envelopeOf({ text: st().replace("{", "{" + " ".repeat(16 * 1024)) }));
  envCase("a statement padded to exactly 16 KiB", "accept", envelopeOf({ text: ((s) => s.replace("{", "{" + " ".repeat(16 * 1024 - Buffer.byteLength(s))))(st()) }), { version: "1.2.3" });
  envCase("an unknown envelope field", "refuse", envelopeOf({ text: st(), extra: { note: "x" } }));
  envCase("signatures not a list", "refuse", envelopeOf({ text: st(), sigs: (b) => sigsFor(b, [A])[0] }));
  const junk = (n) => Array.from({ length: n }, (_, i) => ({ keyId: createHash("sha256").update(String(i)).digest("hex"), sig: "AAAA" }));
  envCase("16 signatures (2 good, 14 by unpinned keys)", "accept", envelopeOf({ text: st(), sigs: (b) => [...junk(14), ...sigsFor(b, [A, B])] }), { version: "1.2.3" });
  envCase("17 signatures (2 good, 15 by unpinned keys)", "refuse", envelopeOf({ text: st(), sigs: (b) => [...junk(15), ...sigsFor(b, [A, B])] }));
  envCase("a signature with an extra field", "refuse", envelopeOf({ text: st(), sigs: (b) => sigsFor(b, [A, B]).map((s, i) => (i ? s : { ...s, alg: "es256" })) }));
  envCase("a signature that is a string", "refuse", envelopeOf({ text: st(), sigs: (b) => ["x", ...sigsFor(b, [A, B])] }));
  envCase("a pinned key's signature in non-canonical base64", "refuse", envelopeOf({ text: st(), sigs: (b) => sigsFor(b, [A, B]).map((s, i) => (i ? s : { ...s, sig: s.sig + "\n" })) }));
  envCase("an unpinned key's signature that is not base64 (ignored)", "accept", envelopeOf({ text: st(), sigs: (b) => [{ keyId: keyId(S), sig: "not base64!" }, ...sigsFor(b, [A, B])] }), { version: "1.2.3" });
  envCase("a pinned keyId in capitals (not that key)", "refuse", envelopeOf({ text: st(), sigs: (b) => sigsFor(b, [A, B]).map((s, i) => (i ? s : { ...s, keyId: s.keyId.toUpperCase() })) }));
  envCase("a keyId that is a number", "refuse", envelopeOf({ text: st(), sigs: (b) => sigsFor(b, [A, B]).map((s, i) => (i ? s : { ...s, keyId: 1 })) }));
  envCase("one key's signature twice", "refuse", envelopeOf({ text: st(), sigs: (b) => [...sigsFor(b, [A]), ...sigsFor(b, [A])] }));
  envCase("a bad signature, then a good one, by the same key", "accept", envelopeOf({ text: st(), sigs: (b) => {
    const [a] = sigsFor(b, [A]); const bad = Buffer.from(a.sig, "base64"); bad[10] ^= 1;
    return [{ keyId: a.keyId, sig: bad.toString("base64") }, a, ...sigsFor(b, [B])]; } }), { version: "1.2.3" });
  envCase("a 63-byte signature", "refuse", envelopeOf({ text: st(), sigs: (b) => sigsFor(b, [A, B]).map((s, i) => (i ? s : { ...s, sig: Buffer.from(s.sig, "base64").subarray(0, 63).toString("base64") })) }));
  envCase("a DER (not r||s) signature", "refuse", envelopeOf({ text: st(), sigs: (b) => [{ keyId: keyId(A), sig: cryptoSign("sha256", Buffer.concat([rc.SIGNING_CONTEXT, b]), A.privateKey).toString("base64") }, ...sigsFor(b, [B])] }));
  const padTo = (total) => envelopeOf({ text: st(), raw: (b) => { const j = JSON.stringify({ format: rc.ENVELOPE_FORMAT, statement: b.toString("base64"), signatures: sigsFor(b, [A, B]) });
    return j.replace("{", "{" + " ".repeat(total - Buffer.byteLength(j))); } });
  envCase("an envelope of exactly 64 KiB", "accept", padTo(64 * 1024), { version: "1.2.3" });
  envCase("an envelope of 64 KiB + 1", "refuse", padTo(64 * 1024 + 1));
  envCase("an envelope with a byte-order mark", "accept", envelopeOf({ text: st(), raw: (b) => "﻿" + JSON.stringify({ format: rc.ENVELOPE_FORMAT, statement: b.toString("base64"), signatures: sigsFor(b, [A, B]) }) }), { version: "1.2.3" });
  envCase("an envelope that is not JSON", "refuse", Buffer.from("<html>not found</html>"));
  envCase("the statement in non-canonical base64", "refuse", envelopeOf({ text: st(), raw: (b) => JSON.stringify({ format: rc.ENVELOPE_FORMAT, statement: b.toString("base64").replace(/=+$/, ""), signatures: sigsFor(b, [A, B]) }) }));
  envCase("the legacy unsigned latest.json", "refuse", Buffer.from(JSON.stringify({ version: "9.9.9", file: "enclave-host-9.9.9.zip", sha256: "a".repeat(64) })));
  // a threshold-1 policy over three keys, and the same envelope judged at another time
  const one = policyJsonOf({ ...base, keys: [spec(A), spec(B), spec(C)], threshold: "1" });
  envCase("threshold 1 of 3, signed by the third", "accept", envelopeOf({ text: st(), keys: [C] }), { policyJson: one, version: "1.2.3" });
  envCase("judged 31 days later (expired by then)", "refuse", envelopeOf({ text: st() }), { now: iso(NOW_MS + 31 * DAY) });

  // the live release run.ps1's loopback mirror serves for the resolve and download tests: no expiry, so valid whenever run
  const liveSetup = Buffer.alloc(300 * 1024); for (let i = 0; i < liveSetup.length; i++) liveSetup[i] = (i * 31 + 7) & 0xff;
  const liveSt = (({ expiresAt, ...s }) => s)(statement("7.7.7", { issuedAt: "2026-10-19T00:00:00.000Z", setupSha256: createHash("sha256").update(liveSetup).digest("hex"), setupBytes: liveSetup.length }));
  const live = { policyJson: BASE_POLICY, ps: base, envelope: envelopeOf({ text: JSON.stringify(liveSt) }).toString("base64"), version: "7.7.7",
                 setupName: liveSt.setup, setupBytes: liveSt.setupBytes, setupSha256: liveSt.setupSha256, pattern: "byte i = (i * 31 + 7) & 0xff" };
  return { format: "enclave-windows-release-fixtures/v1", now: NOW, cases, live };
}

function check(fx) {
  const wrong = [], verdicts = [];   // in case order (names may differ only in case, which ConvertFrom-Json refuses as keys)
  for (const c of fx.cases) {
    const got = judgeNode(c); verdicts.push({ name: c.name, ...got });
    if (c.expect && got.verdict !== c.expect) wrong.push(`${c.name}: Node says ${got.verdict}${got.why ? ` (${got.why})` : ""}, the case expects ${c.expect}`);
    if (c.expect === "accept" && c.version && got.version !== c.version) wrong.push(`${c.name}: version ${got.version}`);
    if (c.mirrors && JSON.stringify(got.mirrors) !== JSON.stringify(c.mirrors)) wrong.push(`${c.name}: mirrors ${JSON.stringify(got.mirrors)}`);
  }
  const live = judgeNode({ policyJson: fx.live.policyJson, envelope: fx.live.envelope, now: new Date().toISOString() });
  if (live.verdict !== "accept") wrong.push(`live release: ${live.why}`);
  return { wrong, verdicts };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2), checking = args[0] === "--check";
  const file = (checking ? args[1] : args[0]) || path.join(HERE, "fixtures.json");
  const fx = checking ? JSON.parse(fs.readFileSync(file, "utf8")) : build();
  const { wrong, verdicts } = check(fx);
  for (const w of wrong) console.error(`NODE MISMATCH ${w}`);
  if (wrong.length) process.exit(1);
  if (checking) {
    fs.writeFileSync(path.join(path.dirname(file), "node-verdicts.json"), JSON.stringify(verdicts, null, 1) + "\n");
    console.log(`Node agrees with all ${fx.cases.length} cases; verdicts in node-verdicts.json`);
  } else {
    fs.writeFileSync(file, JSON.stringify(fx, null, 1) + "\n");
    fs.writeFileSync(path.join(path.dirname(file), "node-verdicts.json"), JSON.stringify(verdicts, null, 1) + "\n");
    console.log(`wrote ${fx.cases.length} cases to ${file}; Node gives every expected verdict`);
  }
}
