// The launch measurement an attested release admits, PREDICTED by the relay from inputs neither the lease holder nor
// its guest supplies (docs/security/attested-release.md, "Measurements: predicted"). Nothing the host or the guest
// states is ever its own allowlist: the report's measurement is compared against this prediction, never added to it.
//
//   the deployment's catalog version, read from the chain here (cid, memMb, ports, approval, yanked, active)
//   -> the derivation record, by the supervisor's own rule (isolationPolicyFor / isolationHttpPortOf /
//      isolationDerivation), its runtimeId the PINNED release's own runtime.json
//   -> the component, fetched by CID and verified against it (guestd's fetcher: the platform's CAR verifier)
//   -> the bundle, by the catalog contract's reference implementation (derive_reference.py); AppID = sha256(bundle)
//   -> per ADMITTED domain release: expected-measurement.sh --pin <release id>, which verifies the release against
//      that id and reconstructs the guest image and its measurement
//
// The toolchain is ONE git commit, extracted from the object store into a private directory (git archive), so no
// working tree, untracked file or later edit is ever executed. The host tools it drives (python3, node, go, cpio,
// gzip, sev-snp-measure) are checked by a KNOWN-ANSWER test - the measurements of real M4a guests, VCEK-signed - before
// the first prediction and again every katEveryMs; a failing test disables prediction (every release refused) until a
// later test passes. A prediction that cannot be made is a refusal ({ ok: false }), never a pass.
import { spawn, execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";

const sha256hex = (b) => createHash("sha256").update(b).digest("hex");
const HEX = (n) => new RegExp(`^[0-9a-f]{${n}}$`);
export const CATALOG_REF_RE = /^catalog:\/\/(0x[0-9a-fA-F]{64})\/(\d{1,9})$/;   // supervisor.js CATALOG_REF_RE

// ---- the supervisor's rule, at the toolchain commit (supervisor.js isolationPolicyFor / isolationHttpPortOf /
// isolationDerivation). Kept byte-compatible: a different policy or port is a different AppID and measurement. ----
export function isolationPolicyFor(version) {
  const mem = Math.max(128, Math.ceil(Number(version && version.memMb) || 0));
  return { cpuPercent: 100, memMiB: mem, vcpus: 1 };
}
export function isolationPortsOf(ports) {
  const list = (Array.isArray(ports) ? ports : String(ports || "").split(","))
    .map(p => String(p).trim().toLowerCase()).filter(Boolean);
  if (!list.length) return { http: 0, ports: [] };
  let http = 0; const dests = [];
  for (const p of list) {
    const m = /^(http|tcp|udp):([1-9][0-9]{0,4})$/.exec(p);
    if (!m || +m[2] > 49999) throw new Error(`invalid declared port ${p}`);
    if (m[1] === "http") { if (http) throw new Error("only one HTTP port is supported"); http = +m[2]; }
    else dests.push(p);
  }
  if (!http || dests.length > 32 || new Set(dests).size !== dests.length || dests.includes(`tcp:${http}`))
    throw new Error("tunnel destinations need one HTTP port, no duplicates or HTTP collision, and at most 32 ports");
  return { http, ports: dests.sort() };
}
export function isolationHttpPortOf(ports) { return isolationPortsOf(ports).http; }
export function derivationRecord(catalogRef, version, runtimeId, inference = null) {
  const m = CATALOG_REF_RE.exec(String(catalogRef || ""));
  if (!m) throw new Error("not a catalog://<app>/<index> reference");
  if (!/^[A-Za-z0-9]+$/.test(String(version.cid || ""))) throw new Error("the catalog version names no CID");
  if (!HEX(64).test(String(runtimeId || ""))) throw new Error("no runtime identity");
  const { http, ports } = isolationPortsOf(version.ports);
  return { ...(inference ? { inference } : {}), derivation: inference ? "enclave-catalog-bundle/4" : ports.length ? "enclave-catalog-bundle/3" : http ? "enclave-catalog-bundle/2" : "enclave-catalog-bundle/1",
           catalog: { app: m[1].toLowerCase(), version: Number(m[2]) }, cid: String(version.cid),
           policy: inference?.model === "qwen3.8-27b-mtp-q4-vl-gguf" ? {...isolationPolicyFor(version),cpuPercent:1600,vcpus:16,memMiB:Math.max(isolationPolicyFor(version).memMiB,51200-384)}
             : inference?.model === "z-image-turbo-q4km-sd" ? {...isolationPolicyFor(version),cpuPercent:800,vcpus:8,memMiB:Math.max(isolationPolicyFor(version).memMiB,6144-384)}
             : isolationPolicyFor(version), runtimeId, ...(http ? { http } : {}), ...(ports.length ? { ports } : {}) };
}
// the supervisor's approvalVerdict: an approved, unyanked version of a listed app; a PENDING one only for a private
// deployment (forPrivate = !isPublic, as the supervisor runs it); a rejected one never
export function versionRefusal(app, v, forPrivate = false) {
  if (!app || !app.active) return "the app is not listed in the catalog";
  if (!v) return "the catalog has no such version";
  if (v.yanked) return "the version was yanked by its publisher";
  if (Number(v.approval) === 2) return "the version was rejected by the catalog owner";
  if (Number(v.approval) !== 1 && forPrivate !== true) return "the version is not approved (a pending version is released only to a private deployment)";
  return null;
}
// sha256 of the supervisor's three rule functions' source (isolationPolicyFor, isolationHttpPortOf, isolationDerivation),
// identical at 0181bce3 and c42612c0. test/measurement-predict.test.mjs fails when a supervisor this repository holds (or
// the working tree's) carries another rule, so the predictor is changed with it.
export const SHIELD_SUPERVISOR_COMMIT = "caa47a0c8";
export const SHIELD_SUPERVISOR_RULE_SHA256 = "0c05967041f871e641720f29658a5ffd85fcddef0719ab4e649ee5eb2c163dcf";
export const SUPERVISOR_RULE_SHA256 = "2ad995d42e42988151b95f0c1dd70c57130ed9f245d49da7167b6a076664796a";
export function supervisorRuleSha256(src) {
  const parts = ["isolationPolicyFor", "isolationHttpPortOf", "isolationDerivation"].map((n) => {
    const i = src.indexOf(`function ${n}(`);
    if (i < 0) return null;
    return src.slice(i, src.indexOf("\n}\n", i) + 2);
  });
  return parts.some((p) => p === null) ? null : sha256hex(parts.join("\n"));
}
// canonical JSON (keys sorted at every level, no whitespace): contract.Canonical / the record digest
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}
// RuntimeID = sha256(canonical JSON of the runtime identity) (isolation/contract/runtime.go RuntimeID)
export const runtimeIdOfJson = (text) => sha256hex(canonical(JSON.parse(text)));

// ---- KNOWN ANSWERS: real M4a guests on the isolation host, their measurement and AppID read from chip-signed reports
// (docs/security/measurement-prediction/). Each names the release it was built from and the full derivation record. ----
export const KNOWN_ANSWERS = Object.freeze([
  { what: "guest gdb677d751, deployment 0x0ddbd824…2e76 (VCEK-signed report 2026-09-24)",
    release: "5c3561f91bc76a7aab5830071d1093162c5833872884c938574673f491dd87f2",
    record: { derivation: "enclave-catalog-bundle/2", catalog: { app: "0xf7e65a8fdae1dd9f8c2a897f2f372cdb7f6150d1e20526fa06d10a682cc2e9e3", version: 4 },
              cid: "bafkreidocbixnql7lroykdtwx4r2fmi5n6sra4lj7b7vhscsfqn4gctlee", http: 8000,
              policy: { cpuPercent: 100, memMiB: 256, vcpus: 1 }, runtimeId: "ccadb38a6779615597f0614311a631c70810916c1bbeb9f5706ee3a637fd90c8" },
    appId: "d2c4dfc0ec475910aa509d1045ae4f2997346c1cd666a167cd5fc959c036aa24",
    measurement: "be6b8644384eee12396881e3e4cbca4259ae1a16a1e198d2c48d577ff7b3c6d355971eccebe8353749439adca718da4d" },
  { what: "guests gd6e734a97 and gdebc9c709, deployments 0x395bed3e…1595 and 0x4e62e60d…6c1e (VCEK-signed reports 2026-09-24)",
    release: "6f14ce7537082bd2a68d96ead6a133af4a5134e97e9b43ebc210a3cb957c1adb",
    record: { derivation: "enclave-catalog-bundle/1", catalog: { app: "0x5356e8bd197d682d87f1be0acb6db84ff9acc5a129f48103659f208bcca016ed", version: 4 },
              cid: "bafkreibjbefi32gvjrd54lhdizq6zlywym6urcuztzvi455xfv23tyjnza",
              policy: { cpuPercent: 100, memMiB: 128, vcpus: 1 }, runtimeId: "ccadb38a6779615597f0614311a631c70810916c1bbeb9f5706ee3a637fd90c8" },
    appId: "9c3d10f1450e17bc6a21478723193ef7e3da409afe353e264714cb801d180d45",
    measurement: "c068f423578cda6316fd9462db6b5e9047bd34d6e2c0ae3b0819828e8db78831bd76bdb27092efefe380713662815f9e" },
]);

// the sha256 a raw-codec CIDv1 (bafkrei…) names, or null for any other CID (those are fetched and CAR-verified every time)
export function rawCidDigest(cid) {
  const m = /^b([a-z2-7]+)$/.exec(String(cid || ""));
  if (!m) return null;
  const A = "abcdefghijklmnopqrstuvwxyz234567"; let bits = 0, v = 0; const out = [];
  for (const ch of m[1]) { v = (v << 5) | A.indexOf(ch); bits += 5; if (bits >= 8) { out.push((v >>> (bits - 8)) & 0xff); bits -= 8; } }
  const b = Buffer.from(out);
  return b.length === 36 && b[0] === 0x01 && b[1] === 0x55 && b[2] === 0x12 && b[3] === 0x20 ? b.subarray(4).toString("hex") : null;
}

// the toolchain paths a prediction executes or imports, extracted from the pinned commit and nothing else
export const TOOLCHAIN_PATHS = ["isolation/m4/expected-measurement.sh", "isolation/m4/release-manifest.py",
  "isolation/m4/verifying-firmware.txt", "isolation/m4/assemble-app-image.sh", "isolation/m4/pack-initrd.sh",
  "isolation/m4/guestd/fetch-cid.py", "isolation/contract", "wasm/ipfs_fetch.py"];

// the digest a pinned sev-snp-measure is checked against: its entry script and every file of the sevsnpmeasure package
// it imports (found by the entry script's own interpreter), as sha256 over "relpath NUL sha256 LF" lines, sorted
export async function sevSnpMeasureDigest(exe, run = runBounded) {
  const entry = fs.realpathSync(exe), text = fs.readFileSync(entry);
  const m = /^#!\s*(\S+)/.exec(text.toString("utf8", 0, 512));
  if (!m) throw new Error(`${exe} is not a script with an interpreter line`);
  const r = await run(m[1], ["-c", "import os, sevsnpmeasure; print(os.path.dirname(os.path.realpath(sevsnpmeasure.__file__)))"],
    { env: { PATH: process.env.PATH || "/usr/bin:/bin" }, timeoutMs: 30_000 });
  const dir = r.out.trim();
  if (r.code !== 0 || !dir) throw new Error(`the sevsnpmeasure package of ${exe} is not importable`);
  const lines = [`entry\0${sha256hex(text)}\n`];
  const walk = (d, rel) => { for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (e.name === "__pycache__") continue;
    const p = path.join(d, e.name), q = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) walk(p, q); else if (e.isFile()) lines.push(`${q}\0${sha256hex(fs.readFileSync(p))}\n`);
  } };
  walk(dir, "");
  return sha256hex(lines.join(""));
}

// one child process: bounded time (the whole process group is killed), bounded output, a minimal environment
export function runBounded(cmd, args, { env, cwd, timeoutMs, input }) {
  return new Promise((resolve) => {
    let out = "", err = "", done = false;
    const cap = 1 << 16;
    const p = spawn(cmd, args, { env, cwd, detached: true, stdio: [input ? "pipe" : "ignore", "pipe", "pipe"] });
    const kill = () => { try { process.kill(-p.pid, "SIGKILL"); } catch {} };
    const timer = setTimeout(() => { if (!done) { err += `\n[timed out after ${timeoutMs} ms]`; kill(); } }, timeoutMs);
    p.stdout.on("data", (d) => { if (out.length < cap) out += d; });
    p.stderr.on("data", (d) => { if (err.length < cap) err += d; });
    if (input) p.stdin.end(input);
    p.on("error", (e) => { err += String(e.message); });
    p.on("close", (code) => { done = true; clearTimeout(timer); kill(); resolve({ code: code ?? -1, out, err }); });
  });
}

// makePredictor: the relay's side. Every option is explicit except the bounds.
//   repo, commit         the toolchain: a git repository holding the 40-hex `commit`
//   releases             [{ id, dir }]: every installed domain release (the known answers' included)
//   admit                [id]: the releases whose images a release admits (a subset of `releases`)
//   certReleases         [id] (optional): the releases a guest CERTIFICATE may be judged against; default every installed
//                        one. Must hold every admitted release; a KAT-only release left out stays measurable, not certifiable
//   readCatalog          async (app, index) -> { app: { active }, version: { cid, memMb, ports, approval, yanked } }
//   gateway              the trustless gateway the CAR is fetched from (availability only: every block is verified)
//   sevSnpMeasure        the pinned sev-snp-measure executable (expected-measurement.sh runs ~/.local/bin/sev-snp-measure)
//   sevSnpMeasureSha256  its sevSnpMeasureDigest, checked before the toolchain is used
//   work                 a private directory (created 0700)
//   components           (optional) where verified raw-CID components are kept; each is re-verified against its CID on read
// Work a predictor left when it was killed mid-job (a relay restart: its `finally` never ran and its scripts' own
// cleanup died with them): every job's directories under `tmp`, a toolchain extraction or a component write stopped before
// its rename. Each job leaves gigabytes; on 2026-10-04 restarts filled nan's disk with 21 GB of them and a new app version
// could not be predicted. Swept once, before the sweeping process starts a job; an entry a live process still names (another
// predictor sharing `work`, e.g. an operator's preflight) is left alone. What to remove is decided at once; the removal
// (gigabytes) runs in the background, and a job started meanwhile gets a fresh name that is never in the list.
export function sweepStaleWork(work, { live = liveWorkRefs } = {}) {
  work = path.resolve(work);
  const refs = live(work), stale = [];
  const consider = (p) => { if (!refs.has(p)) stale.push(p); };
  const list = (d) => { try { return fs.readdirSync(d); } catch { return []; } };
  for (const name of list(path.join(work, "tmp"))) consider(path.join(work, "tmp", name));
  for (const name of list(work)) if (/^toolchain-[0-9a-f]{40}\.[0-9a-f]{12}$/.test(name)) consider(path.join(work, name));
  for (const name of list(path.join(work, "components"))) if (/\.[0-9a-f]{12}$/.test(name)) consider(path.join(work, "components", name));
  return Promise.all(stale.map((p) => fs.promises.rm(p, { recursive: true, force: true }))).then(() => stale);
}
// The `work` entries other processes name in their command lines or working directories (Linux /proc; none elsewhere).
function liveWorkRefs(work) {
  const refs = new Set(), root = path.resolve(work) + "/";
  const note = (s) => { for (let i = s.indexOf(root); i >= 0; i = s.indexOf(root, i + 1)) {
    const parts = s.slice(i + root.length).split(/[\s/]/);
    refs.add(root + parts[0]); if (parts[1]) refs.add(root + parts[0] + "/" + parts[1]);
  } };
  let pids = [];
  try { pids = fs.readdirSync("/proc").filter((p) => /^\d+$/.test(p) && p !== String(process.pid)); } catch { return refs; }
  for (const pid of pids) {
    try { note(fs.readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").join(" ")); } catch {}
    try { note(fs.readlinkSync(`/proc/${pid}/cwd`) + "/"); } catch {}
  }
  return refs;
}

export function makePredictor(o) {
  const { repo, commit, readCatalog, gateway, sevSnpMeasure, sevSnpMeasureSha256 } = o;
  // An explicit replica set replaces the legacy gateway, including its fallback.
  // Transport availability never changes the pinned toolchain's CID verification.
  const gateways = [...new Set((o.gateways?.length ? o.gateways : [gateway]).filter(Boolean))];
  // Newly pinned configs may not yet be reachable through a public gateway.
  // Each source still goes through the same pinned CAR/CID verifier.
  const configGateways = [...new Set([o.configGateway, ...gateways].filter(Boolean))];
  const digestTool = o.digestTool || ((exe) => sevSnpMeasureDigest(exe, run));
  const work = o.work ? path.resolve(o.work) : "";
  // Only the predictor that owns `work` sweeps it (the relay passes sweepStale); a preflight sharing it never does.
  const swept = work && o.sweepStale
    ? sweepStaleWork(work).then((gone) => { if (gone.length) console.log(`[measurement-predict] removed ${gone.length} work entr${gone.length === 1 ? "y" : "ies"} an interrupted predictor left`); return gone; },
                                (e) => { console.error(`[measurement-predict] stale work sweep failed: ${e.message}`); return []; })
    : Promise.resolve([]);
  const run = o.run || runBounded, now = o.now || Date.now;
  const knownAnswers = o.knownAnswers || KNOWN_ANSWERS;
  const concurrency = o.concurrency ?? 1, maxQueue = o.maxQueue ?? 4, timeoutMs = o.timeoutMs ?? 240_000;
  const cacheMax = o.cacheMax ?? 256, negativeTtlMs = o.negativeTtlMs ?? 60_000, katEveryMs = o.katEveryMs ?? 6 * 3600_000;
  const inconclusiveMaxMs = o.inconclusiveMaxMs ?? 24 * 3600_000;   // how long a pass survives inconclusive re-tests
  const maxComponentBytes = o.maxComponentBytes ?? 256 << 20;
  const components = o.components || (work && path.join(work, "components"));
  // read-only directories of pre-seeded raw-CID components (the known answers', staged with the toolchain), each re-verified
  // against its CID on read; a hit is copied into `components`
  const seeds = (o.seedComponents || []).filter(Boolean);
  // directories prepended to the children's PATH (the staged Go: the relay's own PATH need not carry a toolchain)
  const toolPath = (o.toolPath || []).filter(Boolean);
  const releases = new Map((o.releases || []).map((r) => [String(r.id).toLowerCase(), r.dir]));
  const admit = [...new Set((o.admit || []).map((s) => String(s).toLowerCase()))];
  // the releases a guest CERTIFICATE may be judged against (GET /v1/expected-guest): by default every INSTALLED release
  // (installing one is itself the reviewed act, enclave-d1: no second allowlist); or, when `certReleases` names them, exactly
  // those (enclave-87, 2026-09-26): so a release installed only for the known-answer test (the 09-24 canary images) stays
  // measurable by the KAT without making its guests certifiable. The release itself uses only `admit`.
  const certNamed = [...new Set((o.certReleases || []).map((s) => String(s).toLowerCase()))];
  const certAdmit = certNamed.length ? certNamed : [...releases.keys()];
  const problems = [
    !HEX(40).test(String(commit || "")) && "the toolchain commit (40 hex)",
    !repo && "the toolchain repository", typeof readCatalog !== "function" && "the catalog reader",
    (!gateways.length || gateways.some(g => !/^https:\/\//.test(String(g)))) && "an https gateway", !sevSnpMeasure && "sev-snp-measure",
    o.configGateway && !/^https:\/\//.test(String(o.configGateway)) && "an https config gateway",
    !HEX(64).test(String(sevSnpMeasureSha256 || "")) && "sev-snp-measure's pinned digest", !work && "a work directory",
    !admit.length && "at least one admitted release",
    ...[...(o.toolPath || []), ...(o.seedComponents || [])].filter((d) => d && !path.isAbsolute(d)).map((d) => `an absolute tool/seed directory (not ${d})`),
    ...admit.filter((id) => !HEX(64).test(id) || !releases.has(id)).map((id) => `admitted release ${id.slice(0, 12)} installed`),
    // a named certificate set: every entry installed, and every ADMITTED release in it (a guest that gets its secrets must be
    // able to get its certificate: a set that drops one is a misconfiguration, refused, not a silent outage)
    ...certNamed.filter((id) => !HEX(64).test(id) || !releases.has(id)).map((id) => `certificate release ${id.slice(0, 12)} installed`),
    ...(certNamed.length ? admit.filter((id) => !certNamed.includes(id)).map((id) => `admitted release ${id.slice(0, 12)} in the certificate set`) : []),
  ].filter(Boolean);

  const cache = new Map();          // key -> { at, value } (LRU by insertion order)
  // A version's prediction is one UNIT per (record, release), measured one at a time and cached as each finishes, so a guest
  // is judged as soon as ITS release is measured, not after every admitted release (eyesoff 1.0.74, 2026-10-06: 33 minutes
  // down while 14 releases were measured one after another, its own last). Units are shared by every set that names them.
  const units = new Map();          // unit key -> { at, value } (LRU): { ok, image } or a refusal
  const unitRuns = new Map();       // unit key -> Promise of its value, while it is being measured
  const jobs = new Map();           // set key -> { promise, bump, partial }: a version's units being measured
  const unitMax = o.unitMax ?? cacheMax * 16;
  let active = 0; const queue = [];
  let toolchain = null;             // { dir, env } once extracted
  let kat = { ok: false, at: 0, tried: 0, reason: "the known-answer test has not run", running: null };
  const stats = { predictions: 0, cacheHits: 0, refusals: 0, busy: 0 };

  // a slot: `concurrency` reconstructions at once, at most `maxQueue` waiting; the known-answer test always queues
  const slot = (always = false) => new Promise((resolve, reject) => {
    if (active < concurrency) { active++; return resolve(); }
    if (!always && queue.length >= maxQueue) return reject(Object.assign(new Error("the predictor is busy"), { busy: true }));
    queue.push(resolve);
  });
  const unslot = () => { const next = queue.shift(); if (next) next(); else active--; };

  async function prepare() {
    // the pinned sev-snp-measure, every time the toolchain MEASURES: the known-answer test catches a broken tool, this a changed one
    let got;
    try { got = await digestTool(sevSnpMeasure); } catch (e) { throw new Error(`sev-snp-measure: ${e.message}`); }
    if (got !== sevSnpMeasureSha256) throw new Error(`sev-snp-measure's digest ${String(got).slice(0, 12)} is not the pinned ${String(sevSnpMeasureSha256).slice(0, 12)}`);
    return extract();
  }
  async function extract() {
    if (toolchain) return toolchain;
    fs.mkdirSync(work, { recursive: true, mode: 0o700 });
    fs.chmodSync(work, 0o700);
    const dir = path.join(work, `toolchain-${commit}`), tmp = `${dir}.${randomBytes(6).toString("hex")}`;
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(tmp, { mode: 0o700 });
      // the commit's own objects, never the working tree: `git archive <commit> <paths>` | tar -x
      // safe.directory for THIS repository only: the relay runs as its own (dynamic) user and the staged repository is
      // root-owned and read-only, which git >= 2.35.2 otherwise refuses as "dubious ownership"
      const got = await new Promise((resolve) => execFile("git", ["-c", `safe.directory=${path.resolve(repo)}`, "-C", repo, "archive", "--format=tar", commit, "--", ...TOOLCHAIN_PATHS],
        { encoding: "buffer", maxBuffer: 64 << 20, timeout: 60_000 }, (e, stdout, stderr) => resolve(e ? { e, stderr } : { tar: stdout })));
      if (got.e) throw new Error(`the toolchain commit ${commit.slice(0, 12)} is not extractable from ${repo}: ${lastLine(String(got.stderr || "")) || String(got.e.message).split("\n")[0]}`);
      const x = await run("tar", ["-x", "-C", tmp], { env: { PATH: process.env.PATH }, timeoutMs: 60_000, input: got.tar });
      if (x.code !== 0) throw new Error(`extracting the toolchain: ${x.err.trim().slice(-200)}`);
      fs.renameSync(tmp, dir);
    }
    const home = path.join(work, "home");
    fs.mkdirSync(path.join(home, ".local", "bin"), { recursive: true, mode: 0o700 });
    const link = path.join(home, ".local", "bin", "sev-snp-measure");
    try { fs.unlinkSync(link); } catch {}
    fs.symlinkSync(path.resolve(sevSnpMeasure), link);
    for (const d of ["tmp", "gocache", "gopath"]) fs.mkdirSync(path.join(work, d), { recursive: true, mode: 0o700 });
    const env = { PATH: [...toolPath, path.dirname(process.execPath), process.env.PATH || "/usr/bin:/bin"].join(":"), HOME: home,
                  TMPDIR: path.join(work, "tmp"), GOCACHE: path.join(work, "gocache"), GOPATH: path.join(work, "gopath"),
                  GOTOOLCHAIN: "local", GOPROXY: "off", GOFLAGS: "-mod=readonly", LC_ALL: "C" };
    toolchain = { dir, env };
    return toolchain;
  }

  // a raw-CID component already held (the writable `components`, then each read-only seed), re-verified against its CID
  function heldComponent(cid, digest, max) {
    for (const dir of [components, ...seeds]) {
      if (!dir) continue;
      let b; try { b = fs.readFileSync(path.join(dir, cid)); } catch { continue; }
      if (b.length > max || sha256hex(b) !== digest) continue;
      if (dir !== components) {
        try { fs.mkdirSync(components, { recursive: true, mode: 0o700 }); const k = path.join(components, cid), tmp = `${k}.${randomBytes(6).toString("hex")}`; fs.writeFileSync(tmp, b, { mode: 0o600 }); fs.renameSync(tmp, k); } catch {}
      }
      return b;
    }
    return null;
  }

  // one reconstruction: the component (fetched ONCE, verified by its CID) -> per record, the bundle -> per release, the
  // measurement. `records` are one catalog version's, one per admitted runtime: [{ record, ids: [release id] }].
  // the component, fetched (or a held raw-CID copy) into `job`, and one bundle per record:
  // { ok, appId, bundles: [path per record] } or a refusal
  async function deriveInto(tc, job, records) {
    const cid = records[0].record.cid, comp = path.join(job, "component");
    if (records.some((r) => r.record.cid !== cid)) return { ok: false, code: "prediction_failed", reason: "records of one version name two CIDs" };
    // a raw-CID component already held is used only if it still hashes to its CID; anything else is fetched and verified
    const digest = rawCidDigest(cid), kept = digest && path.join(components, cid);
    const held = digest ? heldComponent(cid, digest, maxComponentBytes) : null;
    if (held) fs.writeFileSync(comp, held);
    else {
      let f = { code: 1, err: "no configured gateway" };
      const deadline = Date.now() + timeoutMs;
      for (const source of gateways) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) break;
        fs.rmSync(comp, { force: true });
        f = await run("python3", [path.join(tc.dir, "isolation/m4/guestd/fetch-cid.py"), tc.dir, cid, comp, String(maxComponentBytes), source],
          { env: tc.env, cwd: job, timeoutMs: Math.min(remaining, Math.max(1, Math.floor(timeoutMs / gateways.length))) });
        if (f.code === 0) break;
      }
      if (f.code !== 0) return { ok: false, code: "component_unavailable", reason: `the component ${cid} did not fetch and verify: ${lastLine(f.err)}` };
      if (digest) {
        try {
          const b = fs.readFileSync(comp);
          if (sha256hex(b) === digest) {
            fs.mkdirSync(components, { recursive: true, mode: 0o700 });
            const tmp = `${kept}.${randomBytes(6).toString("hex")}`; fs.writeFileSync(tmp, b, { mode: 0o600 }); fs.renameSync(tmp, kept);
          }
        } catch {}
      }
    }
    const bundles = []; let appId = null;
    for (const [n, { record }] of records.entries()) {
      const recFile = path.join(job, `record-${n}.json`), bundle = path.join(job, `app-${n}.bundle`);
      fs.writeFileSync(recFile, JSON.stringify(record));
      const d = await run("python3", [path.join(tc.dir, "isolation/contract/catalog/derive_reference.py"), "bundle", recFile, comp, bundle],
        { env: tc.env, cwd: job, timeoutMs });
      if (d.code !== 0) return { ok: false, code: "underivable", reason: `the catalog version derives no bundle: ${lastLine(d.err)}` };
      const got = sha256hex(fs.readFileSync(bundle));
      let stated = null; try { stated = JSON.parse(d.out).appId; } catch {}
      if (stated !== got) return { ok: false, code: "prediction_failed", reason: "the derivation's stated AppID is not sha256(bundle)" };
      if (appId && appId !== got) return { ok: false, code: "prediction_failed", reason: "two runtimes derived two AppIDs" };
      appId = got;
      bundles.push(bundle);
    }
    return { ok: true, appId, bundles };
  }
  // the whole reconstruction at once, for a caller that already holds a slot (the known-answer test)
  async function reconstruct(records) {
    const tc = await prepare();
    const job = fs.mkdtempSync(path.join(work, "tmp", "job-"));
    try {
      const d = await deriveInto(tc, job, records);
      if (!d.ok) return d;
      const images = [];
      for (const [n, { record, ids }] of records.entries()) {
        for (const id of ids) {
          const r = await measureOne(tc, job, record, d.bundles[n], d.appId, id);
          if (!r.ok) return r;
          if (r.image) images.push(r.image);
        }
      }
      if (!images.length) return { ok: false, code: "version_not_admitted", reason: "no admitted release implements this version’s protected ports" };
      return { ok: true, appId: d.appId, images };
    } finally { fs.rmSync(job, { recursive: true, force: true }); }
  }
  // one release measured with one record's bundle: { ok, image } (image null: the release does not implement the version's
  // protected ports) or a refusal
  async function measureOne(tc, job, record, bundle, appId, id) {
    // an owner-writable snapshot of the release in the private job directory: an installed release may be read-only, and
    // expected-measurement.sh copies it with `cp -a` and removes its copy on exit (a read-only copy fails that and the
    // run). The manifest pins contents, not modes, and the script verifies the snapshot against the pinned id.
    const snap = path.join(job, `release-${id.slice(0, 16)}`);
    try { snapshotRelease(releases.get(id), snap); }
    catch (e) { return { ok: false, code: "prediction_unavailable", reason: `release ${id.slice(0, 12)} could not be read: ${e.message}` }; }
    try {
      const e = await run("sh", [path.join(tc.dir, "isolation/m4/expected-measurement.sh"), "--pin", id, snap, bundle, String(record.policy.vcpus)],
        { env: tc.env, cwd: job, timeoutMs });
      const kv = Object.fromEntries(e.out.split("\n").map((l) => [l.slice(0, l.indexOf(" ")), l.slice(l.indexOf(" ") + 1).trim()]));
      if (e.code !== 0 || kv.release !== id || !HEX(96).test(kv.measurement || "")) {
        return { ok: false, code: "prediction_failed", reason: `release ${id.slice(0, 12)}: ${lastLine(e.err) || "no measurement"}` };
      }
      if (kv.app_id !== appId) return { ok: false, code: "prediction_failed", reason: `release ${id.slice(0, 12)} assembled another AppID` };
      // the VERIFIED release's runtime is the one the record was derived for (read before the release was verified)
      if (kv.runtime_id !== record.runtimeId) return { ok: false, code: "prediction_failed", reason: `release ${id.slice(0, 12)}'s verified runtime is not the record's` };
      if (record.derivation === "enclave-catalog-bundle/3") {
        let marker = "";
        try { marker = fs.readFileSync(path.join(snap, "template/rt/protected-ports.enabled"), "utf8"); } catch {}
        // This snapshot has just passed the pinned manifest check. A marker
        // added to an old release cannot pass that check under its old ID.
        if (marker !== "1\n") return { ok: true, image: null };
      }
      return { ok: true, image: { release: id, runtimeId: kv.runtime_id, measurement: kv.measurement } };
    } finally { fs.rmSync(snap, { recursive: true, force: true }); }
  }

  // the known-answer test: every vector whose release is installed must reproduce exactly, and at least one must run.
  // A component the gateway cannot serve makes the test INCONCLUSIVE: the previous verdict stands (never a first pass).
  async function selfTest() {
    if (kat.running) return kat.running;
    kat.running = (async () => {
      let ran = 0, why = null, inconclusive = null;
      try {
        await slot(true);
        try {
          for (const k of knownAnswers) {
            if (!releases.has(k.release)) continue;
            ran++;
            const r = await reconstruct([{ record: k.record, ids: [k.release] }]);
            if (!r.ok && r.code === "component_unavailable") { inconclusive = r.reason; break; }
            if (!r.ok) { why = `known answer (${k.what}): ${r.reason}`; break; }
            if (r.appId !== k.appId) { why = `known answer (${k.what}): AppID ${r.appId.slice(0, 12)} is not ${k.appId.slice(0, 12)}`; break; }
            if (r.images[0].measurement !== k.measurement) { why = `known answer (${k.what}): measurement ${r.images[0].measurement.slice(0, 12)} is not ${k.measurement.slice(0, 12)}`; break; }
          }
        } finally { unslot(); }
        if (!why && !inconclusive && !ran) why = "no known answer's release is installed, so the toolchain is unchecked";
      } catch (e) { why = `the known-answer test did not run: ${e.message}`; }
      if (inconclusive && !why) {
        if (!kat.ok || now() - kat.at <= inconclusiveMaxMs) {
          kat = { ...kat, at: kat.ok ? kat.at : now(), tried: now(), reason: kat.ok ? kat.reason : `the known-answer test was inconclusive: ${inconclusive}`, running: null };
          return kat;
        }
        why = `the last passing known-answer test is older than ${Math.round(inconclusiveMaxMs / 3600_000)} h and re-tests are inconclusive: ${inconclusive}`;
      }
      kat = { ok: !why, at: now(), tried: now(), reason: why || `${ran} known answer(s) reproduced exactly`, running: null };
      if (!kat.ok) { cache.clear(); units.clear(); console.error(`[measurement-predict] DISABLED: ${kat.reason}`); }
      return kat;
    })();
    return kat.running;
  }

  function cacheGet(key) {
    const e = cache.get(key);
    if (!e) return null;
    if (!e.value.ok && now() - e.at > negativeTtlMs) { cache.delete(key); return null; }
    cache.delete(key); cache.set(key, e);   // refresh LRU position
    return e.value;
  }
  function cachePut(key, value) {
    if (value.code === "busy") return;       // availability, not an answer
    cache.set(key, { at: now(), value });
    while (cache.size > cacheMax) cache.delete(cache.keys().next().value);
  }
  const unitKey = (record, id) => sha256hex(canonical({ commit, record, release: id }));
  function unitGet(k) {
    const e = units.get(k);
    if (!e) return null;
    if (!e.value.ok && now() - e.at > negativeTtlMs) { units.delete(k); return null; }
    units.delete(k); units.set(k, e);
    return e.value;
  }
  function unitPut(k, value) {
    units.set(k, { at: now(), value });
    while (units.size > unitMax) units.delete(units.keys().next().value);
  }

  // Measure a version's units in `order` ([{ n, id }]: records[n] under release id), each in a slot of its own so other
  // versions' work interleaves. A unit already cached, or being measured by another set's job, is not measured twice.
  // Resolves to the version's answer, exactly what one reconstruction gives: every image, or the first refusal in listing
  // order. Meanwhile partial() is the images measured so far, and bump(ids) moves those releases to the front.
  function startJob(records, order) {
    const pending = [...order], got = new Map();
    let appId = null;
    const job = {
      bump(ids) {
        const want = new Set((ids || []).map((x) => String(x).toLowerCase()));
        const front = pending.filter((u) => want.has(u.id));
        if (front.length) pending.splice(0, pending.length, ...front, ...pending.filter((u) => !want.has(u.id)));
      },
      partial() {
        if (!appId) return null;
        const images = [];
        for (const { record, ids } of records) for (const id of ids) {
          const k = unitKey(record, id), v = got.get(k) || unitGet(k);
          if (v && v.ok && v.image) images.push(v.image);
        }
        return { appId, images };
      },
    };
    job.promise = (async () => {
      try { await slot(); } catch { stats.busy++; return { ok: false, code: "busy", reason: "the measurement predictor is busy; retry shortly" }; }
      let tc = null, dir = null, d;
      try {
        tc = await prepare();
        dir = fs.mkdtempSync(path.join(work, "tmp", "job-"));
        d = await deriveInto(tc, dir, records);
      } catch (e) { d = { ok: false, code: "prediction_failed", reason: e.message }; }
      finally { unslot(); }
      try {
        if (!d.ok) return d;
        appId = d.appId;
        while (pending.length) {
          const { n, id } = pending.shift(), k = unitKey(records[n].record, id);
          let v = unitGet(k);
          if (!v && unitRuns.has(k)) v = await unitRuns.get(k);
          if (!v) {
            const measuring = (async () => {
              await slot(true);
              try { return await measureOne(tc, dir, records[n].record, d.bundles[n], d.appId, id); }
              catch (e) { return { ok: false, code: "prediction_failed", reason: e.message }; }
              finally { unslot(); }
            })().then((value) => { unitPut(k, value); return value; }).finally(() => unitRuns.delete(k));
            unitRuns.set(k, measuring);
            v = await measuring;
          }
          got.set(k, v);
        }
        const images = [];
        for (const { record, ids } of records) for (const id of ids) {
          const v = got.get(unitKey(record, id));
          if (!v.ok) return v;
          if (v.image) images.push(v.image);
        }
        if (!images.length) return { ok: false, code: "version_not_admitted", reason: "no admitted release implements this version’s protected ports" };
        return { ok: true, appId: d.appId, images };
      } finally { if (dir) fs.rmSync(dir, { recursive: true, force: true }); }
    })();
    return job;
  }

  // the expected guest for a deployment's catalog reference: { ok, appId, images: [{ release, runtimeId, measurement }] }
  // or { ok: false, code, reason }. Never throws. `forPrivate`: the deployment is private (a pending version is allowed).
  // `waitMs`: rather than wait longer, answer the images measured so far ({ ok: true, partial: true, ... }: every one a full
  // prediction of its release, the rest still being measured), or { ok: false, code: "warming" } when there are none yet;
  // the prediction continues and is cached. `prefer`: releases to measure first (the one this deployment's guest last ran);
  // after them the newest admitted first (each set is listed oldest first, as releases are appended).
  async function expectedFor(catalogRef, { forPrivate = false, waitMs, set = "release", inference = null, prefer = [] } = {}) {
    const ids = set === "cert" ? certAdmit : set === "release" ? admit : null;
    if (!ids) return { ok: false, code: "predictor_unconfigured", reason: `no admitted set named ${set}` };
    let job = null;
    const p = predict(catalogRef, forPrivate, ids, inference, prefer, (j) => { job = j; });
    if (!(waitMs >= 0)) return p;
    let timer;
    const late = new Promise((resolve) => { timer = setTimeout(() => {
      const part = job && job.partial();
      resolve(part && part.images.length
        ? { ok: true, partial: true, appId: part.appId, images: part.images, catalogRef: String(catalogRef).toLowerCase() }
        : { ok: false, code: "warming", reason: "the prediction is still being computed; retry shortly" });
    }, waitMs); });
    try { return await Promise.race([p, late]); } finally { clearTimeout(timer); }
  }
  async function predict(catalogRef, forPrivate, admitIds, inference = null, prefer = [], onJob = null) {
    const refuse = (code, reason) => { stats.refusals++; return { ok: false, code, reason }; };
    if (problems.length) return refuse("predictor_unconfigured", `measurement prediction is not configured (missing: ${problems.join(", ")})`);
    const m = CATALOG_REF_RE.exec(String(catalogRef || ""));
    if (!m) return refuse("not_catalog", "the deployment does not run a catalog://<app>/<index> version");
    // a passing test that has aged re-runs in the background; a failing one re-runs at most every negativeTtlMs
    if (kat.ok && now() - kat.at > katEveryMs && now() - (kat.tried || 0) > negativeTtlMs) selfTest();
    else if (!kat.ok && (!kat.tried || now() - kat.tried > negativeTtlMs)) await selfTest();
    if (!kat.ok) return refuse("prediction_unavailable", `measurement prediction is disabled: ${kat.reason}`);
    let cat;
    try { cat = await readCatalog(m[1].toLowerCase(), Number(m[2])); }
    catch (e) { return refuse("catalog_unreachable", `the catalog version could not be read: ${e.shortMessage || e.message}`); }
    const vr = versionRefusal(cat && cat.app, cat && cat.version, forPrivate);
    if (vr) return refuse("version_not_admitted", vr);
    // one record per distinct runtime among the admitted releases (the AppID excludes the runtime; the record does not)
    if (inference && (!["qwen2.5-0.5b-q8-gguf","qwen3.8-27b-mtp-q4-vl-gguf","z-image-turbo-q4km-sd"].includes(inference.model) || !Number.isInteger(inference.gpuMilli) || inference.gpuMilli < (inference.model === "qwen3.8-27b-mtp-q4-vl-gguf" ? 500 : inference.model === "z-image-turbo-q4km-sd" ? 100 : 65) || inference.gpuMilli > 1000))
      return refuse("unsupported_inference", "unsupported isolated model or GPU allocation");
    const byRuntime = new Map();
    for (const id of admitIds) {
      const marker=path.join(releases.get(id),"template/rt/shield-model");
      let model=null; try { model=fs.readFileSync(marker,"utf8").trim(); } catch(e) { if(e.code!=="ENOENT") return refuse("prediction_unavailable","unreadable inference profile"); }
      if (inference ? !model?.split(/\s+/).includes(inference.model) : model!==null) continue;
      let rid;
      try { rid = runtimeIdOfJson(fs.readFileSync(path.join(releases.get(id), "template/rt/runtime.json"), "utf8")); }
      catch (e) { return refuse("prediction_unavailable", `release ${id.slice(0, 12)} states no readable runtime identity`); }
      if (!byRuntime.has(rid)) byRuntime.set(rid, []);
      byRuntime.get(rid).push(id);
    }
    if (!byRuntime.size) return refuse("unsupported_inference", "no admitted release for the selected model profile");
    let records;
    try { records = [...byRuntime].map(([rid, ids]) => ({ record: derivationRecord(catalogRef, cat.version, rid, inference), ids })); }
    catch (e) { return refuse("version_not_admitted", `the version is not derivable for a per-app guest: ${e.message}`); }
    const key = sha256hex(canonical({ commit, records: records.map((r) => ({ record: r.record, releases: [...r.ids].sort() })) }));
    const hit = cacheGet(key);
    if (hit) { stats.cacheHits++; return hit.ok ? hit : refuse(hit.code, hit.reason); }
    let job = jobs.get(key);
    if (!job) {
      // the measuring order: `prefer` first, then the newest listed release first
      const want = (Array.isArray(prefer) ? prefer : []).map((x) => String(x).toLowerCase());
      const rank = (id) => { const i = want.indexOf(id); return i >= 0 ? i - want.length - admitIds.length : -admitIds.indexOf(id); };
      const order = records.flatMap(({ ids }, n) => ids.map((id) => ({ n, id }))).sort((a, b) => rank(a.id) - rank(b.id));
      job = startJob(records, order);
      const settled = job.promise.then((got) => {
        const value = got.ok ? { ok: true, appId: got.appId, images: got.images, catalogRef: catalogRef.toLowerCase() } : got;
        if (value.code !== "busy") stats.predictions++;
        cachePut(key, value);
        return value;
      }, (e) => ({ ok: false, code: "prediction_failed", reason: e.message })).finally(() => jobs.delete(key));
      job = { ...job, promise: settled };
      jobs.set(key, job);
    } else job.bump(prefer);
    if (onJob) onJob(job);
    const value = await job.promise;
    return value.ok ? value : refuse(value.code, value.reason);
  }

  // the bytes a CID names, fetched and VERIFIED against it by the platform's own fetcher (guestd's fetch-cid.py ->
  // wasm/ipfs_fetch.py, from the pinned toolchain), or a refusal. For a config CID (the release's resolveConfigCid); raw-CID
  // answers are kept like components (re-verified on every read). Not gated on the known-answer test: it measures nothing.
  async function fetchVerified(cid, maxBytes = 1 << 20) {
    if (!/^[A-Za-z0-9]{10,100}$/.test(String(cid || ""))) return { ok: false, code: "bad_cid", reason: "not a CID" };
    const digest = rawCidDigest(cid), kept = digest && components && path.join(components, cid);
    const held = digest ? heldComponent(cid, digest, maxBytes) : null;
    if (held) return { ok: true, bytes: held };
    let tc;
    try { tc = await extract(); } catch (e) { return { ok: false, code: "unavailable", reason: e.message }; }
    fs.mkdirSync(path.join(work, "tmp"), { recursive: true, mode: 0o700 });
    const job = fs.mkdtempSync(path.join(work, "tmp", "cid-"));
    try {
      const out = path.join(job, "bytes");
      let b, reason = "no configured gateway";
      const deadline = Date.now() + timeoutMs;
      for (const source of configGateways) {
        if (!/^https:\/\//.test(String(source))) { reason = "config gateway must use https"; continue; }
        const remaining = deadline - Date.now();
        if (remaining <= 0) { reason = "gateway deadline exceeded"; break; }
        fs.rmSync(out, { force: true });
        const f = await run("python3", [path.join(tc.dir, "isolation/m4/guestd/fetch-cid.py"), tc.dir, cid, out, String(maxBytes), source],
          { env: tc.env, cwd: job, timeoutMs: Math.min(remaining, Math.max(1, Math.floor(timeoutMs / configGateways.length))) });
        if (f.code !== 0) { reason = lastLine(f.err); continue; }
        const candidate = fs.readFileSync(out);
        if (candidate.length > maxBytes || (digest && sha256hex(candidate) !== digest)) { reason = "verified output size or CID mismatch"; continue; }
        b = candidate; break;
      }
      if (!b) return { ok: false, code: "unavailable", reason: `${cid} did not fetch and verify: ${reason}` };
      if (digest && sha256hex(b) === digest) {
        try { fs.mkdirSync(components, { recursive: true, mode: 0o700 }); const tmp = `${kept}.${randomBytes(6).toString("hex")}`; fs.writeFileSync(tmp, b, { mode: 0o600 }); fs.renameSync(tmp, kept); } catch {}
      }
      return { ok: true, bytes: b };
    } finally { fs.rmSync(job, { recursive: true, force: true }); }
  }

  return { expectedFor, selfTest, fetchVerified, problems, swept, sets: { release: admit, cert: certAdmit }, state: () => ({ kat: { ok: kat.ok, at: kat.at, reason: kat.reason }, toolchain: toolchain && toolchain.dir,
                                                         active, queued: queue.length, cached: cache.size, units: units.size, jobs: jobs.size, ...stats }) };
}

// copy a release directory tree (regular files and directories only; anything else is left for the manifest check to refuse)
// with the owner's write bit added, so every copy made from it can be removed again
function snapshotRelease(src, dst) {
  const st = fs.lstatSync(src);
  if (st.isDirectory()) {
    fs.mkdirSync(dst, { mode: (st.mode & 0o777) | 0o700 });
    for (const e of fs.readdirSync(src)) snapshotRelease(path.join(src, e), path.join(dst, e));
  } else if (st.isFile()) {
    fs.copyFileSync(src, dst);
    fs.chmodSync(dst, (st.mode & 0o777) | 0o200);
  } else if (st.isSymbolicLink()) {
    fs.symlinkSync(fs.readlinkSync(src), dst);   // copied as a link: release-manifest.py refuses it, as for the original
  }
}

const lastLine = (s) => String(s || "").trim().split("\n").filter(Boolean).slice(-1)[0] || "";

// the catalog reader over a viem public client: the address book's appCatalog, getApp + getVersion (supervisor.js
// CATALOG_ABI). A version record is immutable except approval / yanked / the app's listing, which are read live.
const APP_T = [["appId", "bytes32"], ["publisher", "address"], ["slug", "string"], ["name", "string"], ["description", "string"],
  ["versionCount", "uint32"], ["createdAt", "uint64"], ["updatedAt", "uint64"], ["active", "bool"]];
const VER_T = [["cid", "string"], ["version", "string"], ["vramMb", "uint32"], ["gpuGflops", "uint32"], ["memMb", "uint32"],
  ["cpuGflops", "uint32"], ["createdAt", "uint64"], ["verified", "bool"], ["yanked", "bool"], ["ports", "string"],
  ["approval", "uint8"], ["config", "string"]];
const tuple = (t) => ({ type: "tuple", components: t.map(([name, type]) => ({ name, type })) });
export const CATALOG_READ_ABI = [
  { type: "function", name: "getApp", stateMutability: "view", inputs: [{ name: "appId", type: "bytes32" }], outputs: [tuple(APP_T)] },
  { type: "function", name: "getVersion", stateMutability: "view", inputs: [{ name: "appId", type: "bytes32" }, { name: "index", type: "uint256" }], outputs: [tuple(VER_T)] },
];
// `clients`: one client, or several INDEPENDENT ones (enclave-d1): every one is read and all must agree, so one lying RPC
// cannot make the relay predict another app; a disagreement is an unreachable catalog (503), never a pick.
// THE AGREEMENT RULE for a read through several independent RPCs (the custody reader's, relay/custody-state.mjs): at least
// `min` of them must answer (default 2, or all when fewer are configured) and every answer must agree; one that fails drops
// out, one that disagrees fails the read closed. With two RPCs configured both must answer, as before; a third makes one
// flaky provider harmless (2026-10-17 05:09-05:13Z: one public RPC failed, every Shield app's check on nan failed with
// it, and sia-s3 was unroutable for a minute). -> the agreed answer.
export async function agreeingRead(list, readOne, { min = Math.min(2, list.length), key = canonical, what = "the read" } = {}) {
  const settled = await Promise.allSettled(list.map((c) => readOne(c)));
  const got = settled.filter((r) => r.status === "fulfilled").map((r) => r.value);
  if (got.length < min) {
    const why = settled.find((r) => r.status === "rejected")?.reason;
    throw new Error(`only ${got.length} of ${list.length} RPCs answered ${what}${why ? ` (${why.shortMessage || why.message})` : ""}`);
  }
  if (got.some((g) => key(g) !== key(got[0]))) throw Object.assign(new Error(`the ${list.length} RPCs disagree about ${what}`), { code: "disagree" });
  return got[0];
}

export function catalogReader(clients, catalogAddress) {
  const list = Array.isArray(clients) ? clients : [clients];
  const readOne = async (client, address, app, index) => {
    const a = await client.readContract({ address, abi: CATALOG_READ_ABI, functionName: "getApp", args: [app] });
    if (!a || /^0x0{64}$/.test(a.appId) || index >= Number(a.versionCount)) return { app: a && { active: !!a.active }, version: null };
    const v = await client.readContract({ address, abi: CATALOG_READ_ABI, functionName: "getVersion", args: [app, BigInt(index)] });
    return { app: { active: !!a.active }, version: { cid: v.cid, memMb: Number(v.memMb), ports: v.ports, approval: Number(v.approval), yanked: !!v.yanked } };
  };
  const read = async (app, index) => {
    const address = typeof catalogAddress === "function" ? await catalogAddress() : catalogAddress;
    // each provider gets one retry for a transient failure; then the agreement rule (agreeingRead) decides
    const once = async (c) => { try { return await readOne(c, address, app, index); } catch { await new Promise((r) => setTimeout(r, 500)); return readOne(c, address, app, index); } };
    return agreeingRead(list, once, { what: `${app}/${index}` });
  };
  read.sources = list.length;
  return read;
}

// the catalog VERSION's config as the chain states it, through the same agreeing clients: the inline `config` field and, on
// catalog rev >= 7, versionConfigCid (a revert there means "no such field on this catalog", i.e. ""). { config, configCid }.
const CONFIG_CID_ABI = [{ type: "function", name: "versionConfigCid", stateMutability: "view", inputs: [{ type: "bytes32" }, { type: "uint256" }], outputs: [{ type: "string" }] }];
export function versionConfigReader(clients, catalogAddress) {
  const list = Array.isArray(clients) ? clients : [clients];
  const readOne = async (client, address, app, index) => {
    const v = await client.readContract({ address, abi: CATALOG_READ_ABI, functionName: "getVersion", args: [app, BigInt(index)] });
    let configCid = "";
    try { configCid = await client.readContract({ address, abi: CONFIG_CID_ABI, functionName: "versionConfigCid", args: [app, BigInt(index)] }) || ""; }
    catch (e) { if (!/revert/i.test(e && (e.shortMessage || e.message) || "")) throw e; }
    return { config: String(v.config || ""), configCid: String(configCid) };
  };
  return async (app, index) => {
    const address = typeof catalogAddress === "function" ? await catalogAddress() : catalogAddress;
    return agreeingRead(list, (c) => readOne(c, address, app, index), { what: `${app}/${index}'s config` });
  };
}

// configuration from the environment (all required when attested release is on; see attested-release.md)
//   SECRETS_RELEASE_PREDICT_REPO       a git repository holding the toolchain commit (a clone of the public repo)
//   SECRETS_RELEASE_PREDICT_COMMIT     the toolchain commit, 40 hex
//   SECRETS_RELEASE_PREDICT_RELEASES   id=dir,id=dir: every installed domain release (the known answers' included)
//   SECRETS_RELEASE_DOMAIN_RELEASES    id,id: the releases whose images a release admits
//   SECRETS_RELEASE_CERT_RELEASES      id,id (optional): the releases a guest certificate may be judged against; unset = every
//                                      installed release. Must include every admitted release. A release installed only for
//                                      the known-answer test is left out, so its guests are not certifiable.
//   SECRETS_RELEASE_PREDICT_GATEWAY    https trustless gateway
//   SECRETS_RELEASE_PREDICT_GATEWAYS   comma-separated https replicas, replacing the legacy gateway
//   SECRETS_RELEASE_CONFIG_GATEWAY     optional preferred config gateway; same CID verification, public gateway fallback
//   SECRETS_RELEASE_SEV_SNP_MEASURE    the pinned sev-snp-measure executable
//   SECRETS_RELEASE_SEV_SNP_MEASURE_SHA256  its sevSnpMeasureDigest (node relay/measurement-predict.mjs digest <exe> prints it)
//   SECRETS_RELEASE_CATALOG_RPCS       two or more independent Base RPC URLs for the catalog read (api-relay.js)
//   SECRETS_RELEASE_PREDICT_WORK       private work directory (writable by the relay: under its StateDirectory)
//   SECRETS_RELEASE_PREDICT_PATH       dir:dir prepended to the tools' PATH (the staged Go's bin)
//   SECRETS_RELEASE_PREDICT_SEED       dir:dir of read-only pre-seeded components (the known answers'), CID-verified on read
export function predictorEnv(env = process.env) {
  const releases = String(env.SECRETS_RELEASE_PREDICT_RELEASES || "").split(",").map((s) => s.trim()).filter(Boolean)
    .map((s) => { const i = s.indexOf("="); return { id: s.slice(0, i).toLowerCase(), dir: s.slice(i + 1) }; })
    .filter((r) => HEX(64).test(r.id) && r.dir);
  return { repo: env.SECRETS_RELEASE_PREDICT_REPO || "", commit: String(env.SECRETS_RELEASE_PREDICT_COMMIT || "").toLowerCase(),
           releases, admit: String(env.SECRETS_RELEASE_DOMAIN_RELEASES || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean),
           certReleases: String(env.SECRETS_RELEASE_CERT_RELEASES || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean),
           gateway: env.SECRETS_RELEASE_PREDICT_GATEWAY || "", sevSnpMeasure: env.SECRETS_RELEASE_SEV_SNP_MEASURE || "",
           gateways: String(env.SECRETS_RELEASE_PREDICT_GATEWAYS || "").split(",").map(s => s.trim()).filter(Boolean),
           configGateway: env.SECRETS_RELEASE_CONFIG_GATEWAY || "",
           sevSnpMeasureSha256: String(env.SECRETS_RELEASE_SEV_SNP_MEASURE_SHA256 || "").toLowerCase(),
           toolPath: String(env.SECRETS_RELEASE_PREDICT_PATH || "").split(":").filter(Boolean),
           seedComponents: String(env.SECRETS_RELEASE_PREDICT_SEED || "").split(":").filter(Boolean),
           work: env.SECRETS_RELEASE_PREDICT_WORK || "" };
}

// node relay/measurement-predict.mjs digest <sev-snp-measure>: the value SECRETS_RELEASE_SEV_SNP_MEASURE_SHA256 pins
if (process.argv[1] && path.resolve(process.argv[1]) === new URL(import.meta.url).pathname && process.argv[2] === "digest") {
  sevSnpMeasureDigest(process.argv[3]).then((d) => console.log(d), (e) => { console.error(e.message); process.exit(1); });
}
