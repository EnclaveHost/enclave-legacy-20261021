// isolation/m2/host-collateral.mjs: cold-host VCEK preparation from an explicit chip statement, against REAL AMD collateral
// in the repository (test/fixtures/verifier: KDS-issued Genoa and Turin VCEKs and ARK-signed CRLs with their recorded KDS
// URLs; test/fixtures/amd: the pinned ASK/ARK chains). The chip statements are read out of the real reports those VCEKs
// belong to and then supplied as explicit input, as an operator would from SEV_GET_ID2. KDS is SIMULATED here; nothing in
// these tests certifies live hardware.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseSnpReport } from "../relay/snp-verify.mjs";
import * as H from "../isolation/m2/host-collateral.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const fx = (p) => fs.readFileSync(path.join(root, "test/fixtures", p));
const SOURCES = JSON.parse(fx("verifier/SOURCES.json"));
const chainOf = (product) => fx(`amd/${product}-cert_chain.pem`).toString("utf8");
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "host-collateral-"));

// Genoa: a Tinfoil production chip (report.bin) and its KDS VCEK; Turin: warden-host's chip and its KDS VCEK.
const genoaReport = parseSnpReport(fx("verifier/genoa-2026-09/report.bin"));
const turinReport = parseSnpReport(Buffer.from(JSON.parse(fx("verifier/turin-m4a-app-2026-10-17/capture.json")).doc.report, "base64"));
const GENOA = { product: "Genoa", chipId: genoaReport.chipId.toString("hex"), tcb: { bootloader: 10, tee: 0, snp: 23, microcode: 84 },
                vcek: fx("verifier/genoa-2026-09/vcek-kds-amd.der"), crl: fx("verifier/amd/Genoa-crl.der"), now: new Date("2026-09-30T00:00:00Z"),
                url: SOURCES["genoa-2026-09/vcek-kds-amd.der"].url };
const TURIN = { product: "Turin", chipId: turinReport.chipId.toString("hex"), tcb: { fmc: 1, bootloader: 3, tee: 2, snp: 5, microcode: 117 },
                vcek: fx("verifier/turin-m4a-app-2026-10-17/vcek-kds-amd.der"), crl: fx("verifier/turin-m4a-app-2026-10-17/Turin-crl.der"),
                now: new Date("2026-10-19T00:00:00Z"), url: "https://kdsintf.amd.com/vcek/v1/Turin/fa11afcf54ae9c53?fmcSPL=01&blSPL=03&teeSPL=02&snpSPL=05&ucodeSPL=117" };
const floor = (c, delta = {}) => ({ [c.product]: Object.fromEntries(Object.entries(c.tcb).map(([k, v]) => [k, Math.max(0, v - 1) + (delta[k] || 0)])) });
const verify = (c, over = {}) => H.verifyCollateral({ product: c.product, chipId: c.chipId, tcb: c.tcb, vcekDer: c.vcek, chainPem: chainOf(c.product),
                                                       minTcb: floor(c), crlDer: c.crl, now: c.now, ...over });

test("the chip statement: exact product, chip ID and TCB forms; KDS URLs reproduce the recorded AMD requests", () => {
  assert.equal(H.kdsUrlFor(GENOA), GENOA.url, "the Genoa KDS request recorded in SOURCES.json");
  assert.equal(H.kdsUrlFor(TURIN), TURIN.url);
  assert.equal(H.kdsUrlFor({ ...TURIN, chipId: TURIN.chipId.slice(0, 16) }), TURIN.url, "Turin: the 8-byte hardware ID alone suffices");
  for (const c of [GENOA, TURIN]) {
    const p = H.parseKdsUrl(c.url);
    assert.deepEqual([p.product, p.tcb, p.kdsBase], [c.product, H.tcbOf(c.product, c.tcb).fields, "https://kdsintf.amd.com"]);
    assert.equal(H.tcbOf(c.product, H.tcbOf(c.product, c.tcb).raw.toString("hex")).fields.snp, c.tcb.snp, "raw TCB bytes round-trip");
  }
  assert.deepEqual(H.tcbOf("Genoa", genoaReport.reportedTcb.toString("hex")).fields, GENOA.tcb, "raw TCB in report byte order");
  for (const bad of [GENOA.url.replace("https:", "http:"), GENOA.url.replace("blSPL=10&teeSPL=0", "teeSPL=0&blSPL=10"), GENOA.url + "&x=1",
                     GENOA.url.replace("snpSPL=23", "snpSPL=023"), TURIN.url.replace("fmcSPL=01", "fmcSPL=1"), GENOA.url.replace("/Genoa/", "/Milan/").slice(0, 60)])
    assert.throws(() => H.parseKdsUrl(bad), /KDS URL|canonical|parameter|not a|TCB needs exactly/, bad);
  assert.throws(() => H.chipIdentity({ product: "Genoa", chipId: GENOA.chipId.slice(0, 16) }), /128 hex/);
  assert.throws(() => H.chipIdentity({ product: "Genoa", chipId: "00".repeat(64) }), /all zero/);
  assert.throws(() => H.chipIdentity({ product: "Naples", chipId: GENOA.chipId }), /unknown product/);
  assert.throws(() => H.tcbOf("Turin", GENOA.tcb), /exactly fmc/);
  assert.throws(() => H.tcbOf("Genoa", { ...GENOA.tcb, snp: 256 }), /0-255/);
  assert.throws(() => H.parseTcbArg("snp=1,snp=2"), /--tcb/);
});

test("real AMD collateral verifies; every wrong chip, TCB, product, root, form, size, floor, CRL and time is refused", () => {
  for (const c of [GENOA, TURIN]) {
    const r = verify(c);
    assert.equal(r.ok, true, r.why);
    assert.ok(r.checks.some((x) => /ARK pinned by sha256/.test(x)) && r.checks.some((x) => /not revoked/.test(x)) && r.checks.some((x) => /caller's policy/.test(x)));
  }
  const flip = (h, i) => h.slice(0, i) + (h[i] === "0" ? "1" : "0") + h.slice(i + 1);
  assert.match(verify(GENOA, { chipId: flip(GENOA.chipId, 5) }).why, /hardware ID does not match/);
  assert.match(verify(TURIN, { chipId: flip(TURIN.chipId, 3) }).why, /hardware ID does not match/);
  assert.equal(verify(TURIN, { chipId: flip(TURIN.chipId, 40) }).ok, true, "Turin's VCEK binds only the first 8 bytes of CHIP_ID");
  assert.match(verify(GENOA, { tcb: { ...GENOA.tcb, snp: 24 }, minTcb: floor(GENOA) }).why, /snp SPL 23 does not match/);
  assert.match(verify(TURIN, { tcb: { ...TURIN.tcb, microcode: 116 } }).why, /microcode SPL/);
  // product: a Genoa VCEK stated as Turin, and a Genoa VCEK against another product's (pinned) chain
  assert.match(verify(GENOA, { product: "Turin", chipId: GENOA.chipId, tcb: TURIN.tcb, minTcb: floor(TURIN), chainPem: chainOf("Turin"), crlDer: TURIN.crl }).why, /issuer CN is SEV-Genoa|not signed/);
  assert.match(verify(GENOA, { chainPem: chainOf("Milan") }).why, /not AMD's pinned Genoa root/);
  // root: the real ASK under a self-made "ARK-Genoa"
  const fake = fakeRoot("ARK-Genoa");
  if (fake) assert.match(verify(GENOA, { chainPem: chainOf("Genoa").split(/(?=-----BEGIN CERTIFICATE-----)/)[0] + fake }).why, /not AMD's pinned Genoa root/);
  assert.match(verify(GENOA, { chainPem: chainOf("Genoa").split(/(?=-----BEGIN CERTIFICATE-----)/)[0] }).why, /exactly ASK then ARK/);
  // form and size
  assert.match(verify(GENOA, { vcekDer: Buffer.from("not a certificate") }).why, /VCEK unparseable/);
  assert.match(verify(GENOA, { vcekDer: GENOA.vcek.subarray(0, 700) }).why, /VCEK unparseable/);
  assert.match(verify(GENOA, { vcekDer: Buffer.alloc(H.LIMITS.vcek + 1, 0x30) }).why, /1\.\.16384 bytes/);
  assert.match(verify(GENOA, { chainPem: "x".repeat(H.LIMITS.chain + 1) }).why, /AMD chain must be/);
  assert.match(verify(GENOA, { chainPem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" }).why, /unparseable|exactly/);
  // the caller's floor, never the chip's own TCB
  assert.equal(verify(GENOA, { minTcb: { Genoa: GENOA.tcb } }).ok, true, "a floor equal to the stated TCB is met");
  assert.match(verify(GENOA, { minTcb: floor(GENOA, { snp: 2 }) }).why, /below policy: Genoa snp 23 < 24/);
  assert.match(verify(GENOA, { minTcb: { Turin: TURIN.tcb } }).why, /no floor for Genoa/);
  assert.match(verify(GENOA, { minTcb: { Genoa: { snp: 1 } } }).why, /malformed/);
  assert.match(verify(GENOA, { minTcb: undefined }).why, /policy must be an object/);
  // CRL: stale under "required", accepted only within an explicit stale-ok window, wrong issuer, or skipped explicitly
  const late = new Date("2026-10-19T00:00:00Z");
  assert.match(verify(GENOA, { now: late }).why, /CRL is stale/);
  assert.equal(verify(GENOA, { now: late, crlPolicy: "stale-ok", maxStaleDays: 30 }).ok, true);
  assert.match(verify(GENOA, { crlDer: TURIN.crl }).why, /CRL issuer is not the pinned ARK/);
  assert.match(verify(GENOA, { crlDer: null }).why, /required by policy but none/);
  assert.equal(verify(GENOA, { crlDer: null, crlPolicy: "none" }).ok, true);
  assert.match(verify(GENOA, { crlDer: Buffer.from([0x30, 0x03, 0x02, 0x01]) }).why, /CRL unparseable/);
  // time: before the VCEK was issued; and an implicit clock is refused
  assert.match(verify(GENOA, { now: new Date("2026-09-01T00:00:00Z") }).why, /VCEK certificate is not valid/);
  assert.throws(() => verify(GENOA, { now: undefined }), /explicit verification time/);
  // a downloaded chain must equal the repository's ASK unless rotation is explicitly allowed; a fake one never passes
  assert.equal(verify(GENOA, { pinnedChainPem: chainOf("Genoa") }).ok, true);
  if (fake) assert.match(verify(GENOA, { pinnedChainPem: chainOf("Genoa"), chainPem: chainOf("Genoa").split(/(?=-----BEGIN CERTIFICATE-----)/)[0] + fake, allowAskRotation: true }).why, /not AMD's pinned/);
});

function fakeRoot(cn) {
  const dir = tmp();
  try {
    const r = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:4096", "-nodes", "-keyout", path.join(dir, "k"), "-subj", `/CN=${cn}`, "-days", "3650", "-out", path.join(dir, "c")], { stdio: "pipe", timeout: 60000 });
    return r.status === 0 ? fs.readFileSync(path.join(dir, "c"), "utf8") : null;
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

// A simulated KDS: answers by exact URL with REAL WHATWG Response objects (real Headers: an absent header is null, as
// with undici), and records every request.
function kds(routes) {
  const seen = [];
  const fetchImpl = async (url, { signal } = {}) => {
    seen.push(url);
    const r = routes[url];
    const step = Array.isArray(r) ? r.shift() : r;
    if (!step) return new Response(null, { status: 404 });
    if (step === "hang") return new Promise((_, reject) => signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" }))));
    if (step.status) return new Response(step.body ?? null, { status: step.status, headers: step.headers || {} });
    const bytes = Buffer.from(step);
    return new Response(bytes, { status: 200, headers: { "content-length": String(bytes.length) } });
  };
  return { fetchImpl, seen };
}
// A body that never finishes; it records when it is cancelled, so a test can see the release happen before a retry.
function hangingBody(events, label, first = null) {
  return new ReadableStream({
    start(c) { if (first) c.enqueue(first); },
    pull() { return new Promise(() => {}); },
    cancel() { events.push(`cancel ${label}`); },
  });
}

test("bounded KDS fetch: retries 429/5xx with capped backoff, stops on 404, times out, caps bytes", async () => {
  const sleeps = [], sleep = async (ms) => { sleeps.push(ms); };
  let k = kds({ [GENOA.url]: [{ status: 429, headers: { "retry-after": "7" } }, { status: 503 }, GENOA.vcek] });
  assert.ok((await H.fetchKds(GENOA.url, { fetchImpl: k.fetchImpl, maxBytes: H.LIMITS.vcek, sleep, baseDelayMs: 1000 })).equals(GENOA.vcek));
  assert.deepEqual(sleeps, [7000, 2000], "a present Retry-After is honored; a missing one (Headers.get -> null) uses the backoff");
  k = kds({ [GENOA.url]: [{ status: 503 }, { status: 500 }, GENOA.vcek] }); sleeps.length = 0;
  await H.fetchKds(GENOA.url, { fetchImpl: k.fetchImpl, maxBytes: H.LIMITS.vcek, sleep, baseDelayMs: 1000 });
  assert.deepEqual(sleeps, [1000, 2000], "no Retry-After: exponential backoff, never an immediate retry");
  for (const bad of ["soon", "-5", "1.5", "", "  ", "1e3", "Tue, 99 Oct 2026 00:00:00 GMT"]) {
    k = kds({ [GENOA.url]: [{ status: 429, headers: { "retry-after": bad } }, GENOA.vcek] }); sleeps.length = 0;
    await H.fetchKds(GENOA.url, { fetchImpl: k.fetchImpl, maxBytes: H.LIMITS.vcek, sleep, baseDelayMs: 1000 });
    assert.deepEqual(sleeps, [1000], `invalid Retry-After ${JSON.stringify(bad)} falls back to the backoff`);
  }
  const at = Date.parse("2026-10-20T00:00:00Z");
  k = kds({ [GENOA.url]: [{ status: 429, headers: { "retry-after": "Tue, 20 Oct 2026 00:00:12 GMT" } }, GENOA.vcek] }); sleeps.length = 0;
  await H.fetchKds(GENOA.url, { fetchImpl: k.fetchImpl, maxBytes: H.LIMITS.vcek, sleep, now: () => at });
  assert.deepEqual(sleeps, [12000], "an HTTP-date Retry-After is honored");
  assert.equal(H.retryAfterMs(null), null);
  assert.equal(H.retryAfterMs("0"), 0);
  k = kds({ [GENOA.url]: [{ status: 429, headers: { "retry-after": "3600" } }, GENOA.vcek] }); sleeps.length = 0;
  await H.fetchKds(GENOA.url, { fetchImpl: k.fetchImpl, maxBytes: H.LIMITS.vcek, sleep, maxDelayMs: 30000 });
  assert.deepEqual(sleeps, [30000], "Retry-After is capped");
  k = kds({}); sleeps.length = 0;
  await assert.rejects(H.fetchKds(GENOA.url, { fetchImpl: k.fetchImpl, maxBytes: H.LIMITS.vcek, sleep }), /404 \(KDS has no VCEK/);
  assert.equal(k.seen.length, 1, "a 404 is final");
  k = kds({ [GENOA.url]: ["hang", "hang"] });
  await assert.rejects(H.fetchKds(GENOA.url, { fetchImpl: k.fetchImpl, maxBytes: H.LIMITS.vcek, sleep, timeoutMs: 30, attempts: 2 }), /no answer within 30 ms/);
  assert.equal(k.seen.length, 2, "attempts are bounded");
  k = kds({ [GENOA.url]: [Buffer.alloc(H.LIMITS.vcek + 1)] });
  await assert.rejects(H.fetchKds(GENOA.url, { fetchImpl: k.fetchImpl, maxBytes: H.LIMITS.vcek, sleep }), /exceeds the 16384-byte cap/);
  assert.equal(k.seen.length, 1, "an oversize answer is final");
  const streamed = new Response(new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(1024)); } }), { status: 200 });
  await assert.rejects(H.fetchKds(GENOA.url, { fetchImpl: async () => streamed, maxBytes: H.LIMITS.vcek, sleep }), /exceeds the 16384-byte cap/, "an absent length is counted as it streams");
  k = kds({ [GENOA.url]: [{ status: 503 }, { status: 503 }, { status: 503 }] });
  await assert.rejects(H.fetchKds(GENOA.url, { fetchImpl: k.fetchImpl, maxBytes: H.LIMITS.vcek, sleep, attempts: 3 }), /HTTP 503/);
  await assert.rejects(H.fetchKds(GENOA.url, { fetchImpl: k.fetchImpl, sleep }), /byte cap is required/);
});

test("every failed or retried KDS answer is released (aborted and body cancelled) before the next attempt", async () => {
  const events = [];
  // a scripted sequence of answers whose bodies never end; each records its cancellation and whether the request
  // signal was already aborted at that moment
  const script = (answers) => {
    let n = 0;
    return async (_url, { signal }) => {
      const a = answers[n++]; events.push(`fetch ${n}`);
      if (a === "ok") return new Response(GENOA.vcek, { status: 200, headers: { "content-length": String(GENOA.vcek.length) } });
      const label = String(n);
      signal.addEventListener("abort", () => events.push(`abort ${label}`));
      return new Response(hangingBody(events, label, a.first), { status: a.status, headers: a.headers || {} });
    };
  };
  const sleep = async (ms) => { events.push(`sleep ${ms}`); };
  // 429 and 500 with bodies that never end: each is aborted and cancelled before the backoff sleep and the next fetch
  const got = await H.fetchKds(GENOA.url, { fetchImpl: script([{ status: 429 }, { status: 500, first: new Uint8Array([1]) }, "ok"]), maxBytes: H.LIMITS.vcek, sleep, baseDelayMs: 1000 });
  assert.ok(got.equals(GENOA.vcek));
  assert.deepEqual(events, ["fetch 1", "abort 1", "cancel 1", "sleep 1000", "fetch 2", "abort 2", "cancel 2", "sleep 2000", "fetch 3"]);
  // a final 404 with a hanging body, an oversize declared length, an oversize stream: released, then refused
  for (const [answer, re] of [
    [{ status: 404 }, /HTTP 404/],
    [{ status: 200, headers: { "content-length": String(H.LIMITS.vcek + 1) } }, /exceeds the 16384-byte cap/],
    [{ status: 200, first: new Uint8Array(H.LIMITS.vcek + 1) }, /exceeds the 16384-byte cap/],
  ]) {
    events.length = 0;
    await assert.rejects(H.fetchKds(GENOA.url, { fetchImpl: script([answer]), maxBytes: H.LIMITS.vcek, sleep }), re);
    assert.deepEqual(events, ["fetch 1", "abort 1", "cancel 1"], JSON.stringify(answer.headers || answer.status));
  }
  // a 200 whose body stalls past the deadline: cancelled by the deadline, counted as a timeout, never as a short answer
  events.length = 0;
  await assert.rejects(H.fetchKds(GENOA.url, { fetchImpl: script([{ status: 200, first: new Uint8Array(10) }, { status: 200 }]), maxBytes: H.LIMITS.vcek, sleep, timeoutMs: 40, attempts: 2 }),
    /no answer within 40 ms/);
  assert.deepEqual(events.filter((e) => !e.startsWith("abort")), ["fetch 1", "cancel 1", "sleep 2000", "fetch 2", "cancel 2"]);
  assert.ok(events.indexOf("cancel 1") < events.indexOf("fetch 2"), "the stalled body is closed before the next attempt");
});

test("bounded file reads: one descriptor, regular files only, never more than max + 1 bytes, always closed", () => {
  const dir = tmp();
  try {
    const f = path.join(dir, "v.der");
    fs.writeFileSync(f, Buffer.alloc(100, 7));
    assert.equal(H.readBounded(f, 100, "VCEK").length, 100, "exactly the limit is accepted");
    assert.throws(() => H.readBounded(f, 99, "VCEK"), /100 bytes, above the 99-byte limit/);
    assert.throws(() => H.readBounded(dir, 100, "VCEK"), /not a regular file/);
    const fifo = path.join(dir, "fifo");
    if (spawnSync("mkfifo", [fifo]).status === 0) assert.throws(() => H.readBounded(fifo, 100, "VCEK"), /not a regular file/, "a FIFO is refused without blocking");
    assert.throws(() => H.readBounded(path.join(dir, "missing"), 100, "VCEK"), /ENOENT/);
    // the file grows after the size check (simulated by a stale fstat): at most max + 1 bytes are read, then refused
    fs.writeFileSync(f, Buffer.alloc(5000, 7));
    const { fstatSync, readSync, closeSync } = fs;
    let read = 0, opened = 0, closed = 0;
    fs.fstatSync = (fd) => { opened++; const st = fstatSync(fd); return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { size: 10 }); };
    fs.readSync = (fd, buf, off, len, pos) => { const n = readSync(fd, buf, off, len, pos); read += n; return n; };
    fs.closeSync = (fd) => { closed++; return closeSync(fd); };
    try { assert.throws(() => H.readBounded(f, 100, "VCEK"), /grew above the 100-byte limit while being read/); }
    finally { Object.assign(fs, { fstatSync, readSync, closeSync }); }
    assert.deepEqual([read, opened, closed], [101, 1, 1], "101 bytes read through the one checked descriptor, which is closed");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("prepare: offline and simulated-KDS installs are complete, reproducible and never overwrite; failures leave nothing", async () => {
  const dir = tmp();
  try {
    const base = (c, over = {}) => ({ product: c.product, chipId: c.chipId, tcb: c.tcb, minTcb: floor(c), now: c.now, ...over });
    // offline: operator VCEK and CRL files, the repository's pinned chain
    fs.writeFileSync(path.join(dir, "turin.der"), TURIN.vcek); fs.writeFileSync(path.join(dir, "turin-crl.der"), TURIN.crl);
    const a = path.join(dir, "a"), b = path.join(dir, "b");
    const meta = await H.prepareCollateral({ ...base(TURIN), out: a, vcek: { file: path.join(dir, "turin.der") }, crl: { file: path.join(dir, "turin-crl.der") } });
    assert.deepEqual(fs.readdirSync(a).sort(), ["cert_chain.pem", "collateral.json", "crl.der", "min-tcb.json", "vcek.der"]);
    assert.ok(fs.readFileSync(path.join(a, "vcek.der")).equals(TURIN.vcek));
    assert.equal(fs.readFileSync(path.join(a, "cert_chain.pem"), "utf8"), chainOf("Turin"));
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(a, "min-tcb.json"))), floor(TURIN));
    assert.deepEqual([meta.product, meta.hwId, meta.kdsUrl, meta.vcek.source, meta.chain.source, meta.crl.policy, meta.reportedTcb],
                     ["Turin", "fa11afcf54ae9c53", TURIN.url, "operator-file", "repository-pinned", "required", TURIN.tcb]);
    assert.equal(meta.chain.arkSha256, "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a", "the pinned Turin ARK");
    await H.prepareCollateral({ ...base(TURIN), out: b, vcek: { file: path.join(dir, "turin.der") }, crl: { file: path.join(dir, "turin-crl.der") } });
    for (const f of fs.readdirSync(a)) assert.ok(fs.readFileSync(path.join(a, f)).equals(fs.readFileSync(path.join(b, f))), `${f} is reproducible`);

    // simulated KDS: exactly the recorded VCEK request, the chain and CRL, all verified before install
    let k = kds({ [GENOA.url]: [GENOA.vcek], "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain": [chainOf("Genoa")], "https://kdsintf.amd.com/vcek/v1/Genoa/crl": [GENOA.crl] });
    const g = path.join(dir, "g");
    const gm = await H.prepareCollateral({ ...base(GENOA), out: g, vcek: { fetch: true }, chain: { fetch: true }, crl: { fetch: true }, fetch: { fetchImpl: k.fetchImpl } });
    assert.deepEqual(k.seen, [GENOA.url, "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain", "https://kdsintf.amd.com/vcek/v1/Genoa/crl"]);
    assert.deepEqual([gm.vcek.source, gm.chain.source, gm.crl.source], ["amd-kds", "amd-kds", "amd-kds"]);

    // an existing destination is refused before any request and left untouched
    fs.mkdirSync(path.join(dir, "taken")); fs.writeFileSync(path.join(dir, "taken", "keep"), "x");
    k = kds({ [GENOA.url]: [GENOA.vcek] });
    await assert.rejects(H.prepareCollateral({ ...base(GENOA), out: path.join(dir, "taken"), vcek: { fetch: true }, crlPolicy: "none", fetch: { fetchImpl: k.fetchImpl } }), /exists/);
    assert.deepEqual([k.seen.length, fs.readdirSync(path.join(dir, "taken"))], [0, ["keep"]]);
    await assert.rejects(H.prepareCollateral({ ...base(GENOA), out: "relative/dir", vcek: { der: GENOA.vcek }, crlPolicy: "none" }), /absolute/);

    // refused collateral, a KDS miss and missing offline inputs never create the destination
    const none = path.join(dir, "none");
    k = kds({ [GENOA.url]: [TURIN.vcek] });
    await assert.rejects(H.prepareCollateral({ ...base(GENOA), out: none, vcek: { fetch: true }, crlPolicy: "none", fetch: { fetchImpl: k.fetchImpl } }), /collateral refused/);
    k = kds({});
    await assert.rejects(H.prepareCollateral({ ...base(GENOA), out: none, vcek: { fetch: true }, crlPolicy: "none", fetch: { fetchImpl: k.fetchImpl, sleep: async () => {} } }), /404/);
    await assert.rejects(H.prepareCollateral({ ...base(GENOA), out: none, vcek: { der: GENOA.vcek } }), /CRL: required by policy but none/, "offline without a CRL");
    await assert.rejects(H.prepareCollateral({ ...base(GENOA), out: none, vcek: { file: path.join(dir, "missing.der") }, crlPolicy: "none" }), /ENOENT/);
    await assert.rejects(H.prepareCollateral({ ...base(GENOA), out: none, vcek: { der: GENOA.vcek }, chain: { file: path.join(dir, "missing.pem") }, crlPolicy: "none" }), /ENOENT/);
    fs.writeFileSync(path.join(dir, "huge.der"), Buffer.alloc(H.LIMITS.vcek + 1));
    await assert.rejects(H.prepareCollateral({ ...base(GENOA), out: none, vcek: { file: path.join(dir, "huge.der") }, crlPolicy: "none" }), /above the 16384-byte limit/);
    const fakeChain = fakeRoot("ARK-Genoa");
    if (fakeChain) {
      k = kds({ [GENOA.url]: [GENOA.vcek], "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain": [chainOf("Genoa").split(/(?=-----BEGIN CERTIFICATE-----)/)[0] + fakeChain] });
      await assert.rejects(H.prepareCollateral({ ...base(GENOA), out: none, vcek: { fetch: true }, chain: { fetch: true }, crlPolicy: "none", fetch: { fetchImpl: k.fetchImpl } }), /not AMD's pinned/);
    }
    assert.equal(fs.existsSync(none), false);

    // a failure while moving files into place removes everything this run created
    const rename = fs.renameSync; let calls = 0;
    fs.renameSync = (...x) => { if (++calls === 3) throw new Error("simulated disk failure"); return rename(...x); };
    try { await assert.rejects(H.prepareCollateral({ ...base(GENOA), out: none, vcek: { der: GENOA.vcek }, crl: { der: GENOA.crl } }), /simulated disk failure/); }
    finally { fs.renameSync = rename; }
    assert.equal(fs.existsSync(none), false, "partial install cleaned up");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("CLI: offline prepare from explicit chip or KDS URL, refusals before work, read-only inventory parsing", () => {
  const dir = tmp();
  try {
    const run = (args) => spawnSync(process.execPath, [path.join(root, "isolation/m2/host-collateral.mjs"), ...args], { encoding: "utf8", timeout: 60000 });
    fs.writeFileSync(path.join(dir, "v.der"), GENOA.vcek); fs.writeFileSync(path.join(dir, "crl.der"), GENOA.crl);
    fs.writeFileSync(path.join(dir, "floor.json"), JSON.stringify(floor(GENOA)));
    const common = ["--min-tcb", path.join(dir, "floor.json"), "--vcek", path.join(dir, "v.der"), "--crl", path.join(dir, "crl.der"), "--at", "2026-09-30T00:00:00Z"];
    let r = run(["prepare", "--product", "Genoa", "--chip-id", GENOA.chipId, "--tcb", "bootloader=10,tee=0,snp=23,microcode=84", ...common, "--out", path.join(dir, "c1")]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).kdsUrl, GENOA.url);
    r = run(["prepare", "--kds-url", GENOA.url, ...common, "--out", path.join(dir, "c2")]);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(fs.readFileSync(path.join(dir, "c1/collateral.json")).equals(fs.readFileSync(path.join(dir, "c2/collateral.json"))), "the same statement, the same metadata");
    for (const [args, msg] of [
      [["prepare", "--kds-url", GENOA.url, "--vcek", path.join(dir, "v.der"), "--crl", path.join(dir, "crl.der"), "--out", path.join(dir, "c3")], /--min-tcb policy.json is required/],
      [["prepare", "--kds-url", GENOA.url, ...common, "--fetch-vcek", "--out", path.join(dir, "c3")], /exactly one of --vcek/],
      [["prepare", "--kds-url", GENOA.url, "--product", "Genoa", ...common, "--out", path.join(dir, "c3")], /replaces/],
      [["prepare", "--kds-url", GENOA.url, "--min-tcb", path.join(dir, "floor.json"), "--vcek", path.join(dir, "v.der"), "--out", path.join(dir, "c3")], /--crl FILE or --fetch-crl/],
      [["prepare", "--kds-url", GENOA.url, ...common, "--out", path.join(dir, "c1")], /exists/],
      [["install"], /usage/],
    ]) { r = run(args); assert.equal(r.status, 1, args.join(" ")); assert.match(r.stderr, msg); }
    assert.equal(fs.existsSync(path.join(dir, "c3")), false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  const cpu = (fam, mod, n = 2, vendor = "AuthenticAMD") => Array.from({ length: n }, (_, i) => `processor\t: ${i}\nvendor_id\t: ${vendor}\ncpu family\t: ${fam}\nmodel\t\t: ${mod}\n`).join("\n");
  assert.deepEqual(H.inventoryFrom({ cpuinfo: cpu(26, 2), sevSnpParam: "Y\n", devSev: true }).product, "Turin");
  assert.equal(H.inventoryFrom({ cpuinfo: cpu(25, 17) }).product, "Genoa");
  assert.equal(H.inventoryFrom({ cpuinfo: cpu(25, 1) }).product, "Milan");
  const intel = H.inventoryFrom({ cpuinfo: cpu(6, 143, 1, "GenuineIntel"), sevSnpParam: "N" });
  assert.deepEqual([intel.product, intel.snpEnabled, intel.devSev], [null, false, false]);
  assert.equal(H.inventoryFrom({ cpuinfo: cpu(25, 17, 1) + "\n" + cpu(26, 2, 1).replace("processor\t: 0", "processor\t: 1") }).product, null, "disagreeing processors");
  assert.match(H.inventoryFrom({ cpuinfo: cpu(26, 2) }).remainingStep, /SEV_GET_ID2/);
});
