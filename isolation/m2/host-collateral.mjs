#!/usr/bin/env node
// isolation/m2/host-collateral.mjs: SEV-SNP chip collateral for a host that has NEVER run a guest (docs/network/cold-host-collateral.md).
//
// vcek-prep.mjs reads the chip ID and reported TCB out of a guest report, so a cold host could not get its VCEK before
// its first guest - and guestd will not start a guest without one. Here the operator states the chip instead: product
// line, CHIP_ID (from SEV_GET_ID2 on /dev/sev) and the REPORTED TCB its guests will carry, or the equivalent KDS VCEK URL.
// The VCEK then comes from an operator file or a bounded AMD KDS fetch, and NOTHING is installed until it verifies:
//   - VCEK -> ASK -> ARK through verifier/snp.mjs checkChain (ARK pinned by sha256 in relay/snp-verify.mjs, AMD subject
//     names, RSA-4096 ASK/ARK, every certificate inside its validity window at the stated time);
//   - the ASK/ARK chain is the repository's pinned copy by default; a downloaded chain is used only when asked for,
//     verifies the same way, and must carry the same ASK unless an ASK rotation is explicitly allowed;
//   - the ASK is not revoked by AMD's ARK-signed CRL (verifier/snp.mjs checkCrl), required unless policy says otherwise;
//   - the VCEK names exactly this chip and this TCB (relay/snp-verify.mjs vcekMatchesReport) and has a P-384 key;
//   - the stated TCB meets the CALLER's minimum-TCB policy (checkMinTcb). The floor is never derived from the hardware:
//     an observed TCB proves what the chip runs, not what is acceptable.
// A statement the operator gets wrong fails closed: a VCEK for another chip or TCB does not verify, and a guest whose
// report carries another TCB is refused by the verifier later. Nothing here talks to Enclave, a relay or a proxy.
//
//   node isolation/m2/host-collateral.mjs prepare --product Genoa --chip-id <128 hex> --tcb bootloader=10,tee=0,snp=23,microcode=84
//        --min-tcb policy.json (--vcek vcek.der | --fetch-vcek) [--chain file.pem | --fetch-chain] (--crl crl.der | --fetch-crl |
//        --crl-policy none) --out /srv/enclave/collateral [--at 2026-10-19T00:00:00Z]
//   node isolation/m2/host-collateral.mjs prepare --kds-url '<url printed by the host tool>' ...   (instead of chip/TCB)
//   node isolation/m2/host-collateral.mjs prepare --statement statement.json ...   (a firmware inventory statement, below)
//   node isolation/m2/host-collateral.mjs inventory        (read-only: product line from /proc/cpuinfo, SNP enablement)
//   node isolation/m2/host-collateral.mjs inventory --firmware (--helper-output fw.json | --helper /abs/sev-inventory)
//        [--statement-out statement.json] [--allow-uninitialized] [--cpuinfo FILE]
//      adds the CHIP_ID and REPORTED TCB that isolation/m2/sev-inventory.c read from the SEV firmware (run it as root,
//      separately) and emits a chip statement for prepare. The statement stays the operator's claim until the AMD chain
//      verifies it; the minimum-TCB floor is still supplied separately.
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { TCB_FIELDS, decodeTcb, kdsVcekUrl, vcekMatchesReport, checkMinTcb, snpProductHint } from "../../relay/snp-verify.mjs";
import { checkChain, checkCrl, parseAmdChain } from "../../verifier/snp.mjs";
import { parseCrl } from "../../verifier/der.mjs";

export const KDS = "https://kdsintf.amd.com";
export const LIMITS = Object.freeze({ vcek: 16 * 1024, chain: 32 * 1024, crl: 256 * 1024, policy: 16 * 1024 });
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const pinnedChainFile = (product) => path.join(ROOT, "test/fixtures/amd", `${product}-cert_chain.pem`);
const sha = (b) => createHash("sha256").update(b).digest("hex");
const HEX = /^[0-9a-f]+$/;
const hwLen = (product) => (product === "Turin" ? 8 : 64);

// ---- the operator's statement: product, chip, reported TCB ----
export function chipIdentity({ product, chipId }) {
  if (!TCB_FIELDS[product]) throw new Error(`unknown product line ${JSON.stringify(product)} (Milan, Genoa or Turin)`);
  const h = String(chipId || "").toLowerCase().replace(/^0x/, "");
  if (!HEX.test(h) || (h.length !== 128 && !(product === "Turin" && h.length === 16)))
    throw new Error(`${product} chip ID must be the 64-byte CHIP_ID as 128 hex${product === "Turin" ? " (or its 8-byte KDS hardware ID, 16 hex)" : ""}`);
  const id = Buffer.from(h, "hex"), hw = id.subarray(0, hwLen(product));
  if (!hw.some((b) => b !== 0)) throw new Error("chip ID is all zero (a masked CHIP_ID identifies no chip)");
  // vcekMatchesReport and kdsVcekUrl read a report's CHIP_ID; Turin uses only its first 8 bytes
  return { product, hwId: hw.toString("hex"), chipId: h.length === 128 ? h : null, chipField: Buffer.concat([id, Buffer.alloc(64 - id.length)]) };
}
// TCB as named fields (exactly the product's) or as the 8 raw TCB_VERSION bytes in report byte order (16 hex).
export function tcbOf(product, tcb) {
  const fields = TCB_FIELDS[product];
  if (!fields) throw new Error(`unknown product line ${JSON.stringify(product)}`);
  let raw;
  if (typeof tcb === "string") {
    const h = tcb.toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]{16}$/.test(h)) throw new Error("raw TCB must be 8 bytes in report byte order (16 hex)");
    raw = Buffer.from(h, "hex");
  } else {
    if (!tcb || typeof tcb !== "object" || Array.isArray(tcb)) throw new Error("TCB must be an object of SPL fields or 16 hex");
    const keys = Object.keys(tcb).sort(), want = [...fields].sort();
    if (keys.join() !== want.join()) throw new Error(`${product} TCB needs exactly ${fields.join(", ")} (got ${keys.join(", ") || "none"})`);
    for (const k of fields) if (!Number.isInteger(tcb[k]) || tcb[k] < 0 || tcb[k] > 255) throw new Error(`TCB ${k} must be an integer 0-255`);
    raw = Buffer.alloc(8);
    if (product === "Turin") { raw[0] = tcb.fmc; raw[1] = tcb.bootloader; raw[2] = tcb.tee; raw[3] = tcb.snp; raw[7] = tcb.microcode; }
    else { raw[0] = tcb.bootloader; raw[1] = tcb.tee; raw[6] = tcb.snp; raw[7] = tcb.microcode; }
  }
  return { fields: decodeTcb(product, raw), raw };
}
export function parseTcbArg(s) {
  if (/^(0x)?[0-9a-fA-F]{16}$/.test(s)) return s;
  const out = {};
  for (const part of String(s).split(",")) {
    const m = /^([a-z]+)=(\d{1,3})$/.exec(part.trim());
    if (!m || m[1] in out) throw new Error(`--tcb must be name=value,... or 16 hex (bad part ${JSON.stringify(part)})`);
    out[m[1]] = Number(m[2]);
  }
  return out;
}
// What relay/snp-verify.mjs reads from a report, built from the statement: the same matching and floor code then runs.
const statedReport = (id, tcb) => ({ version: 3, chipId: id.chipField, reportedTcb: tcb.raw });

export function kdsUrlFor({ product, chipId, tcb, kdsBase = KDS }) {
  const id = chipIdentity({ product, chipId }), t = tcbOf(product, tcb);
  return kdsVcekUrl(product, statedReport(id, t)).replace(KDS, kdsBase);
}
// A KDS VCEK URL (as host tools print it) -> the same statement, accepted only in its exact canonical form.
export function parseKdsUrl(url) {
  let u;
  try { u = new URL(url); } catch { throw new Error("KDS URL is not a URL"); }
  const m = /^\/vcek\/v1\/(Milan|Genoa|Turin)\/([0-9a-f]+)$/.exec(u.pathname);
  if (u.protocol !== "https:" || !m || u.hash || u.username || u.password) throw new Error("not a KDS VCEK URL (https://<host>/vcek/v1/<product>/<hwid>?...)");
  const product = m[1], names = product === "Turin"
    ? { fmcSPL: "fmc", blSPL: "bootloader", teeSPL: "tee", snpSPL: "snp", ucodeSPL: "microcode" }
    : { blSPL: "bootloader", teeSPL: "tee", snpSPL: "snp", ucodeSPL: "microcode" };
  const tcb = {};
  for (const [k, v] of u.searchParams) {
    if (!(k in names) || names[k] in tcb || !/^\d{1,3}$/.test(v)) throw new Error(`unexpected KDS URL parameter ${k}`);
    tcb[names[k]] = Number(v);
  }
  const t = tcbOf(product, tcb), id = chipIdentity({ product, chipId: m[2] });
  if (kdsVcekUrl(product, statedReport(id, t)).replace(KDS, u.origin) !== url) throw new Error("KDS URL is not in canonical form (would request another chip or TCB)");
  return { product, chipId: m[2], tcb: t.fields, kdsBase: u.origin };
}

// ---- the caller's minimum-TCB policy (never derived here) ----
export function minTcbPolicy(policy, product) {
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) throw new Error("minimum-TCB policy must be an object keyed by product line");
  const r = checkMinTcb(policy, product, { reportedTcb: Buffer.alloc(8) });       // shape only: the probe TCB is all zero
  if (!r.ok && /malformed|no floor/.test(r.reason)) throw new Error(r.reason);
  const canonical = {};
  for (const line of Object.keys(policy).sort()) canonical[line] = Object.fromEntries(TCB_FIELDS[line].map((k) => [k, policy[line][k]]));
  return canonical;
}

// ---- verification: nothing is installed unless all of this passes ----
export function verifyCollateral({ product, chipId, tcb, vcekDer, chainPem, minTcb, crlDer = null, crlPolicy = "required", maxStaleDays = 0, now,
                                   pinnedChainPem = null, allowAskRotation = false }) {
  if (!(now instanceof Date) || isNaN(now)) throw new Error("an explicit verification time is required");
  const id = chipIdentity({ product, chipId }), t = tcbOf(product, tcb), checks = [];
  const fail = (why) => ({ ok: false, why, checks });
  if (!Buffer.isBuffer(vcekDer) || !vcekDer.length || vcekDer.length > LIMITS.vcek) return fail(`VCEK must be 1..${LIMITS.vcek} bytes of DER`);
  if (typeof chainPem !== "string" || !chainPem.length || chainPem.length > LIMITS.chain) return fail(`AMD chain must be 1..${LIMITS.chain} bytes of PEM`);
  if (crlDer !== null && (!Buffer.isBuffer(crlDer) || !crlDer.length || crlDer.length > LIMITS.crl)) return fail(`CRL must be 1..${LIMITS.crl} bytes of DER`);
  if (!["required", "stale-ok", "none"].includes(crlPolicy)) return fail("CRL policy must be required, stale-ok or none");
  let policy;
  try { policy = minTcbPolicy(minTcb, product); } catch (e) { return fail(e.message); }
  if (pinnedChainPem !== null) {                       // a downloaded chain: same pinned ARK, and by default the same ASK
    const pin = parseAmdChain({ chainPem: pinnedChainPem, product, now }), got = parseAmdChain({ chainPem, product, now });
    if (!pin.ok) return fail(`repository chain: ${pin.why}`);
    if (!got.ok) return fail(got.why);
    if (got.ask.fingerprint256 !== pin.ask.fingerprint256 && !allowAskRotation) return fail("the downloaded ASK differs from the repository's pinned chain (allow an ASK rotation explicitly after review)");
  }
  const c = checkChain({ vcekDer, chainPem, product, now });
  if (!c.ok) return fail(c.why);
  checks.push(...c.reasons);
  const k = c.vcek.publicKey;
  if (k.asymmetricKeyType !== "ec" || k.asymmetricKeyDetails?.namedCurve !== "secp384r1") return fail("VCEK public key is not EC P-384");
  const mismatch = vcekMatchesReport(c.vcek.raw, product, statedReport(id, t));
  if (mismatch) return fail(`${mismatch} (as stated by the operator)`);
  checks.push(`VCEK names chip ${id.hwId.slice(0, 16)}... and TCB ${JSON.stringify(t.fields)}`);
  const crl = checkCrl({ crlDer, ark: c.ark, ask: c.ask, now, mode: crlPolicy, maxStaleDays });
  if (!crl.ok) return fail(crl.reasons.join("; "));
  checks.push(...crl.reasons);
  const floor = checkMinTcb(policy, product, statedReport(id, t));
  if (!floor.ok) return fail(floor.reason);
  checks.push(`${floor.reason}; the floor is the caller's policy, not derived from this chip`);
  return { ok: true, why: null, checks, id, tcb: t, policy, vcek: c.vcek, ask: c.ask, ark: c.ark, crlChecked: crl.checked };
}

// ---- bounded AMD KDS fetch: timeout, byte cap, bounded retries with backoff ----
// Retry-After, only when present and valid: delta-seconds or an HTTP-date. Real Headers.get() answers null for an
// absent header (Number(null) would be 0 and skip the backoff), so absence and anything malformed -> null.
export function retryAfterMs(value, now = Date.now()) {
  if (typeof value !== "string") return null;
  const v = value.trim();
  if (/^\d{1,9}$/.test(v)) return Number(v) * 1000;
  if (!/^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(v)) return null;
  const at = Date.parse(v);
  return Number.isFinite(at) ? Math.max(0, at - now) : null;
}
// Release a response that will not be read to the end: abort the request and cancel the body stream, waiting at most
// a moment for the cancel to settle. Every failed or retried attempt goes through here BEFORE its timer is cleared,
// so no answer (a 429/5xx body, an oversize one, a final 404) is left streaming into the next attempt.
async function discard(ctrl, res, reader) {
  ctrl.abort();
  const body = res?.body;
  if (!body) return;
  const cancel = reader ? reader.cancel() : typeof body.cancel === "function" && !body.locked ? body.cancel()
               : typeof body.return === "function" ? body.return() : null;
  if (!cancel || typeof cancel.then !== "function") return;
  let t;
  await Promise.race([Promise.resolve(cancel).catch(() => {}), new Promise((r) => { t = setTimeout(r, 1000); t.unref?.(); })]);
  clearTimeout(t);
}
export async function fetchKds(url, { fetchImpl = globalThis.fetch, maxBytes, timeoutMs = 10_000, attempts = 4, baseDelayMs = 2_000, maxDelayMs = 30_000,
                                     sleep = (ms) => new Promise((r) => setTimeout(r, ms)), log = () => {}, now = () => Date.now() } = {}) {
  if (!Number.isInteger(maxBytes) || maxBytes < 1) throw new Error("fetchKds: a byte cap is required");
  let last = "no attempt";
  for (let i = 1; i <= attempts; i++) {
    let res = null, reader = null, done = false, retryAfter = null, retry = true, final = null;
    // the deadline covers the whole answer: it aborts the request AND cancels a body still being read
    const ctrl = new AbortController(), timer = setTimeout(() => { ctrl.abort(); reader?.cancel().catch(() => {}); }, timeoutMs);
    try {
      res = await fetchImpl(url, { signal: ctrl.signal, redirect: "error" });
      if (res.status === 200) {
        const declared = res.headers?.get?.("content-length");
        if (declared !== null && declared !== undefined && /^\d+$/.test(String(declared)) && Number(declared) > maxBytes)
          final = `answer of ${declared} bytes exceeds the ${maxBytes}-byte cap`;
        else {
          const chunks = []; let seen = 0;
          const take = (c) => { seen += c.length; if (seen > maxBytes) { final = `answer exceeds the ${maxBytes}-byte cap`; return false; } chunks.push(Buffer.from(c)); return true; };
          if (typeof res.body?.getReader === "function") {
            reader = res.body.getReader();
            for (;;) { const { value, done: end } = await reader.read(); if (end || !take(value)) break; }
          } else for await (const c of res.body ?? []) if (!take(c)) break;
          // a read ended by the deadline is a timeout, never a short answer
          if (ctrl.signal.aborted) throw new Error("deadline");
          if (!final) { done = true; return Buffer.concat(chunks); }
        }
      } else {
        retry = res.status === 429 || res.status >= 500;
        retryAfter = retry ? retryAfterMs(res.headers?.get?.("retry-after"), now()) : null;
        last = `HTTP ${res.status}${res.status === 404 ? " (KDS has no VCEK for this chip and TCB)" : ""}`;
      }
    } catch (e) {
      last = ctrl.signal.aborted ? `no answer within ${timeoutMs} ms` : String(e?.message || e).slice(0, 200);
    } finally {
      if (!done) await discard(ctrl, res, reader);
      clearTimeout(timer);
    }
    if (final) throw new Error(`KDS ${final}`);
    if (!retry || i === attempts) break;
    const wait = Math.min(retryAfter !== null ? retryAfter : baseDelayMs * 2 ** (i - 1), maxDelayMs);
    log(`KDS ${last} (attempt ${i}/${attempts}); retrying in ${wait} ms`);
    await sleep(wait);
  }
  throw new Error(`KDS: ${last}`);
}

// ---- install: reserve the destination, stage, verify, move into place; never overwrite, clean up what we created ----
// One open descriptor for the type check, the size check and the read: a file swapped or grown after the check cannot
// be read past the limit, because at most max + 1 bytes are ever read (the extra byte proves it is too large).
// O_NONBLOCK keeps a FIFO from blocking the open; it is then refused as not a regular file.
export function readBounded(file, max, what) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOCTTY | fs.constants.O_NONBLOCK);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new Error(`${what} ${file} is not a regular file`);
    if (st.size > max) throw new Error(`${what} ${file} is ${st.size} bytes, above the ${max}-byte limit`);
    const buf = Buffer.alloc(max + 1);
    let n = 0, r;
    while (n < buf.length && (r = fs.readSync(fd, buf, n, buf.length - n, n)) > 0) n += r;
    if (n > max) throw new Error(`${what} ${file} grew above the ${max}-byte limit while being read`);
    return buf.subarray(0, n);
  } finally { fs.closeSync(fd); }
}
function writeDurable(file, bytes) {
  const fd = fs.openSync(file, "wx", 0o644);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function syncDir(dir) { const fd = fs.openSync(dir, "r"); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
const canonicalJson = (v) => JSON.stringify(v, null, 2) + "\n";

// sources: vcek { file | der | fetch }, chain { file | pem | fetch } (default: the repository's pinned chain),
//          crl { file | der | fetch } or crlPolicy "none". Inputs are gathered and verified before the destination exists.
export async function prepareCollateral({ out, product, chipId, tcb, minTcb, vcek, chain = {}, crl = {}, crlPolicy = "required", maxStaleDays = 0,
                                          allowAskRotation = false, now, kdsBase = KDS, fetch: fetchOpts = {}, log = () => {} }) {
  if (typeof out !== "string" || !path.isAbsolute(out)) throw new Error("--out must be an absolute path");
  if (fs.existsSync(out)) throw new Error(`${out} exists: collateral is installed once into a new directory`);
  if (!fs.statSync(path.dirname(out), { throwIfNoEntry: false })?.isDirectory()) throw new Error(`the parent of ${out} is not a directory`);
  const id = chipIdentity({ product, chipId }), t = tcbOf(product, tcb);
  const kdsUrl = kdsVcekUrl(product, statedReport(id, t)).replace(KDS, kdsBase);
  const fetchFrom = async (url, max) => fetchKds(url, { ...fetchOpts, maxBytes: max, log });
  const pinnedPem = fs.readFileSync(pinnedChainFile(product), "utf8");
  let vcekDer, vcekSource, chainPem, chainSource, crlDer = null, crlSource = null;
  if (vcek?.file) { vcekDer = readBounded(vcek.file, LIMITS.vcek, "VCEK"); vcekSource = "operator-file"; }
  else if (vcek?.der) { vcekDer = Buffer.from(vcek.der); vcekSource = "operator-supplied"; }
  else if (vcek?.fetch) { vcekDer = await fetchFrom(kdsUrl, LIMITS.vcek); vcekSource = "amd-kds"; }
  else throw new Error("a VCEK source is required: an operator file or an explicit KDS fetch");
  if (chain.file) { chainPem = readBounded(chain.file, LIMITS.chain, "AMD chain").toString("utf8"); chainSource = "operator-file"; }
  else if (chain.pem) { chainPem = String(chain.pem); chainSource = "operator-supplied"; }
  else if (chain.fetch) { chainPem = (await fetchFrom(`${kdsBase}/vcek/v1/${product}/cert_chain`, LIMITS.chain)).toString("utf8"); chainSource = "amd-kds"; }
  else { chainPem = pinnedPem; chainSource = "repository-pinned"; }
  if (crlPolicy !== "none") {
    if (crl.file) { crlDer = readBounded(crl.file, LIMITS.crl, "CRL"); crlSource = "operator-file"; }
    else if (crl.der) { crlDer = Buffer.from(crl.der); crlSource = "operator-supplied"; }
    else if (crl.fetch) { crlDer = await fetchFrom(`${kdsBase}/vcek/v1/${product}/crl`, LIMITS.crl); crlSource = "amd-kds"; }
  }
  const v = verifyCollateral({ product, chipId, tcb, vcekDer, chainPem, minTcb, crlDer, crlPolicy, maxStaleDays, now,
                               pinnedChainPem: chainSource === "repository-pinned" ? null : pinnedPem, allowAskRotation });
  if (!v.ok) throw new Error(`collateral refused: ${v.why}`);
  const crlInfo = crlDer ? (() => { const c = parseCrl(crlDer); return { sha256: sha(crlDer), source: crlSource, thisUpdate: c.thisUpdate.toISOString(), nextUpdate: c.nextUpdate ? c.nextUpdate.toISOString() : null }; })() : null;
  const files = { "vcek.der": vcekDer, "cert_chain.pem": Buffer.from(chainPem), "min-tcb.json": Buffer.from(canonicalJson(v.policy)), ...(crlDer ? { "crl.der": crlDer } : {}) };
  const metadata = {
    v: 1, kind: "sev-snp-host-collateral", product, hwId: v.id.hwId, chipId: v.id.chipId, reportedTcb: v.tcb.fields, reportedTcbRaw: v.tcb.raw.toString("hex"),
    kdsUrl, checkedAt: now.toISOString(),
    minTcb: { policy: v.policy, sha256: sha(files["min-tcb.json"]), note: "caller-selected floor; not derived from this chip" },
    vcek: { file: "vcek.der", sha256: sha(vcekDer), source: vcekSource, serial: v.vcek.serialNumber, validFrom: new Date(v.vcek.validFrom).toISOString(), validTo: new Date(v.vcek.validTo).toISOString() },
    chain: { file: "cert_chain.pem", sha256: sha(files["cert_chain.pem"]), source: chainSource, askSha256: sha(v.ask.raw), arkSha256: sha(v.ark.raw) },
    crl: crlDer ? { file: "crl.der", policy: crlPolicy, ...crlInfo } : { policy: crlPolicy, note: "revocation of the ASK was NOT checked" },
    checks: v.checks,
  };
  files["collateral.json"] = Buffer.from(canonicalJson(metadata));

  fs.mkdirSync(out, { mode: 0o755 });                  // the reservation: fails if anything took the name meanwhile
  const staging = path.join(out, ".staging"), placed = [];
  try {
    fs.mkdirSync(staging, { mode: 0o700 });
    for (const [name, bytes] of Object.entries(files)) writeDurable(path.join(staging, name), bytes);
    syncDir(staging);
    for (const name of Object.keys(files)) {           // collateral.json moves last: its presence marks a complete set
      if (fs.existsSync(path.join(out, name))) throw new Error(`${name} appeared in ${out} during installation`);
      fs.renameSync(path.join(staging, name), path.join(out, name)); placed.push(name);
    }
    fs.rmdirSync(staging); syncDir(out);
  } catch (e) {
    for (const name of placed) fs.rmSync(path.join(out, name), { force: true });
    fs.rmSync(staging, { recursive: true, force: true });
    try { fs.rmdirSync(out); } catch {}
    throw e;
  }
  return metadata;
}

// ---- read-only inventory from known kernel interfaces (no root, no /dev/sev ioctl) ----
// /proc/cpuinfo gives the product line (CPUID family/model, read with relay/snp-verify.mjs snpProductHint); the kvm_amd
// sev_snp parameter says whether the kernel enabled SNP. CHIP_ID and the reported TCB come from the SEV firmware
// (SEV_GET_ID2 and SNP_PLATFORM_STATUS / SNP_CONFIG on /dev/sev), which needs privileged host tooling and stays a
// separate, labeled operator step.
export function inventoryFrom({ cpuinfo = "", sevSnpParam = null, devSev = false }) {
  const procs = String(cpuinfo).split(/\n\s*\n/).filter((b) => /^processor\s*:/m.test(b));
  const lines = new Set();
  let vendor = null;
  for (const b of procs) {
    const get = (k) => (new RegExp(`^${k}\\s*:\\s*(.+)$`, "m").exec(b) || [])[1]?.trim();
    vendor ||= get("vendor_id");
    const fam = Number(get("cpu family")), mod = Number(get("model"));
    lines.add(Number.isInteger(fam) && Number.isInteger(mod) ? snpProductHint({ version: 3, cpuidFam: fam, cpuidMod: mod }) : null);
  }
  const products = [...lines];
  const product = products.length === 1 ? products[0] : null;
  return {
    vendor, processors: procs.length, product,
    productNote: product ? "from CPUID family/model; the verified VCEK chain proves it" : products.length > 1 ? "processors disagree" : "not an SNP product line this verifier knows",
    snpEnabled: sevSnpParam === null ? null : /^(y|1)$/i.test(String(sevSnpParam).trim()), devSev: !!devSev,
    remainingStep: "CHIP_ID and the reported TCB need the SEV firmware (SEV_GET_ID2, SNP_PLATFORM_STATUS) via /dev/sev as root; see docs/network/cold-host-collateral.md",
  };
}

// ---- firmware inventory (isolation/m2/sev-inventory.c output) -> chip statement ----
// The helper's JSON is parsed strictly: a field that is missing, extra, out of range or of another form is refused.
export const MAX_HELPER_OUTPUT = 64 * 1024;
const STATUS_FIELDS = ["api_major", "api_minor", "state", "rmp_initialized", "build_id", "mask_chip_id", "mask_chip_key", "vlek_en", "guest_count", "current_tcb", "reported_tcb"];
export function parseFirmwareInventory(text) {
  if (typeof text !== "string" || !text.length || text.length > MAX_HELPER_OUTPUT) throw new Error(`firmware inventory must be 1..${MAX_HELPER_OUTPUT} bytes`);
  let j;
  try { j = JSON.parse(text); } catch { throw new Error("firmware inventory is not JSON"); }
  if (!j || j.v !== 1 || j.tool !== "enclave-sev-inventory") throw new Error("not an enclave-sev-inventory v1 result");
  if (j.error) {
    const e = j.error;
    throw new Error(`firmware inventory failed at ${String(e.stage).slice(0, 40)}: ${String(e.message).slice(0, 200)} (errno ${e.errno_name}, firmware ${e.fw_error_name})`);
  }
  const keys = Object.keys(j).sort().join();
  if (keys !== "commands,device,id,id_length,open,snp_status,tool,uapi,v") throw new Error("firmware inventory has unexpected fields");
  if (j.uapi !== "linux/psp-sev.h" || j.device !== "/dev/sev" || j.open !== "O_RDONLY" || JSON.stringify(j.commands) !== '["SNP_PLATFORM_STATUS","SEV_GET_ID2"]')
    throw new Error("firmware inventory does not come from the reviewed read-only helper");
  const st = j.snp_status;
  if (!st || Object.keys(st).sort().join() !== [...STATUS_FIELDS].sort().join()) throw new Error("firmware SNP status has unexpected fields");
  for (const k of ["api_major", "api_minor", "state"]) if (!Number.isInteger(st[k]) || st[k] < 0 || st[k] > 255) throw new Error(`firmware ${k} out of range`);
  for (const k of ["rmp_initialized", "mask_chip_id", "mask_chip_key", "vlek_en"]) if (st[k] !== 0 && st[k] !== 1) throw new Error(`firmware ${k} must be 0 or 1`);
  for (const k of ["build_id", "guest_count"]) if (!Number.isInteger(st[k]) || st[k] < 0 || st[k] > 0xffffffff) throw new Error(`firmware ${k} out of range`);
  for (const k of ["current_tcb", "reported_tcb"]) if (!/^[0-9a-f]{16}$/.test(st[k])) throw new Error(`firmware ${k} must be 8 bytes of hex`);
  if (j.id_length !== 8 && j.id_length !== 64) throw new Error("firmware ID length must be 8 (Turin hardware ID) or 64 (Milan/Genoa CHIP_ID)");
  if (typeof j.id !== "string" || !new RegExp(`^[0-9a-f]{${2 * j.id_length}}$`).test(j.id)) throw new Error("firmware ID malformed or truncated");
  return j;
}
// TCB_VERSION bytes a product's layout leaves reserved (zero): Milan/Genoa bytes 2..5, Turin bytes 4..6.
const RESERVED_TCB = { Milan: [2, 3, 4, 5], Genoa: [2, 3, 4, 5], Turin: [4, 5, 6] };
// The GET_ID2 answer each product line gives (primary sources in isolation/m2/sev-inventory.c): Turin's is its 8-byte
// KDS hardware ID (real Turin firmware 1.58 answered length 8; virtee/snphost uses these bytes in the KDS URL; Turin
// reports carry them as CHIP_ID[0:8] with the rest zero); Milan's and Genoa's is the 64-byte CHIP_ID. Any other
// combination - including an 8-byte ID padded to 64 - is a format mismatch and is refused, never reinterpreted.
export const ID_FORMAT = Object.freeze({ Milan: 64, Genoa: 64, Turin: 8 });
export function firmwareStatement({ firmware, inventory, allowUninitialized = false }) {
  const st = firmware.snp_status, product = inventory?.product;
  if (!product || !TCB_FIELDS[product]) throw new Error(`unsupported platform: ${inventory?.productNote || "no SNP product line"} (Milan, Genoa or Turin required)`);
  if (inventory.vendor && inventory.vendor !== "AuthenticAMD") throw new Error(`unsupported platform: CPU vendor ${inventory.vendor}`);
  if (st.mask_chip_key) throw new Error("unsupported platform: MASK_CHIP_KEY is set, so guest reports are unsigned and no VCEK applies");
  if (st.mask_chip_id) throw new Error("unsupported platform: MASK_CHIP_ID is set, so guest reports carry a zero CHIP_ID that no VCEK can be matched to");
  if (st.vlek_en) throw new Error("unsupported platform: a VLEK is loaded; this verifier requires VCEK-signed reports");
  if (st.state !== 1 && !allowUninitialized) throw new Error(`SNP firmware state is ${st.state}, not INIT (1): initialize SNP on the host first, or pass --allow-uninitialized knowing the reported TCB may change at SNP_INIT/SNP_CONFIG`);
  if (firmware.id_length !== ID_FORMAT[product])
    throw new Error(`ID format mismatch: ${product} firmware answers GET_ID2 with ${ID_FORMAT[product]} bytes, this answer has ${firmware.id_length}; refused rather than reinterpreted`);
  const chipId = firmware.id;
  if (!/[1-9a-f]/.test(chipId)) throw new Error("the firmware returned a zero (masked) chip ID");
  const raw = Buffer.from(st.reported_tcb, "hex");
  if (!raw.some((b) => b !== 0)) throw new Error("the firmware reported an all-zero TCB");
  const bad = RESERVED_TCB[product].filter((i) => raw[i] !== 0);
  if (bad.length) throw new Error(`reported TCB ${st.reported_tcb} has nonzero reserved byte(s) ${bad.join(",")} for the ${product} layout: the product line does not match this firmware`);
  const reported = decodeTcb(product, raw), current = decodeTcb(product, Buffer.from(st.current_tcb, "hex"));
  chipIdentity({ product, chipId });
  return {
    v: 1, kind: "sev-snp-host-statement", product, chipId, reportedTcbRaw: st.reported_tcb, reportedTcb: reported, currentTcbRaw: st.current_tcb,
    kdsUrl: kdsVcekUrl(product, statedReport(chipIdentity({ product, chipId }), { raw })),
    firmware: { api: `${st.api_major}.${st.api_minor}`, buildId: st.build_id, state: st.state, rmpInitialized: !!st.rmp_initialized, guestCount: st.guest_count,
                idLength: firmware.id_length, idFormat: product === "Turin" ? "turin-hardware-id-8" : "chip-id-64" },
    productSource: "cpuinfo CPUID family/model",
    notes: [
      "operator statement: verified only when prepare checks the AMD VCEK chain against it; the minimum-TCB floor is supplied separately",
      ...(st.reported_tcb !== st.current_tcb ? [`reported TCB ${JSON.stringify(reported)} differs from the current TCB ${JSON.stringify(current)}; guests report, and the VCEK must match, the REPORTED one`] : []),
      ...(st.state !== 1 ? ["SNP was not initialized when read (--allow-uninitialized)"] : []),
    ],
  };
}
export function readStatement(text) {
  let j;
  try { j = JSON.parse(text); } catch { throw new Error("statement is not JSON"); }
  if (!j || j.v !== 1 || j.kind !== "sev-snp-host-statement" || !TCB_FIELDS[j.product] || !/^[0-9a-f]{16}$/.test(String(j.reportedTcbRaw)))
    throw new Error("not a v1 sev-snp-host-statement");
  const id = chipIdentity({ product: j.product, chipId: j.chipId }), t = tcbOf(j.product, j.reportedTcbRaw);
  return { product: j.product, chipId: id.chipId || id.hwId, tcb: j.reportedTcbRaw, fields: t.fields };
}

// ---- CLI ----
async function main(argv) {
  const cmd = argv[0], arg = (n) => { const i = argv.indexOf(n); return i < 0 ? null : argv[i + 1]; }, has = (n) => argv.includes(n);
  if (cmd === "inventory") {
    const read = (f) => { try { return fs.readFileSync(f, "utf8"); } catch { return null; } };
    const inv = inventoryFrom({ cpuinfo: read(arg("--cpuinfo") || "/proc/cpuinfo") || "", sevSnpParam: read("/sys/module/kvm_amd/parameters/sev_snp"), devSev: fs.existsSync("/dev/sev") });
    if (!has("--firmware")) { console.log(JSON.stringify(inv, null, 2)); return; }
    let text;
    if (arg("--helper-output")) text = readBounded(arg("--helper-output"), MAX_HELPER_OUTPUT, "firmware inventory").toString("utf8");
    else if (arg("--helper")) {
      const helper = arg("--helper");
      if (!path.isAbsolute(helper) || !fs.statSync(helper, { throwIfNoEntry: false })?.isFile()) throw new Error("--helper must be the absolute path of the built sev-inventory");
      const r = spawnSync(helper, [], { encoding: "utf8", timeout: 15_000, maxBuffer: MAX_HELPER_OUTPUT, stdio: ["ignore", "pipe", "pipe"] });
      if (r.error) throw new Error(`sev-inventory did not run: ${r.error.message}`);
      text = r.stdout;
    } else throw new Error("--firmware needs --helper-output FILE (the JSON sev-inventory printed as root) or --helper /abs/path");
    if (has("--socket")) throw new Error("--socket is not supported: multi-socket ID formats are refused, not chosen");
    const statement = firmwareStatement({ firmware: parseFirmwareInventory(text), inventory: inv, allowUninitialized: has("--allow-uninitialized") });
    if (arg("--statement-out")) writeDurable(path.resolve(arg("--statement-out")), Buffer.from(canonicalJson(statement)));
    console.log(JSON.stringify({ ...inv, statement }, null, 2));
    return;
  }
  if (cmd !== "prepare") throw new Error("usage: host-collateral.mjs prepare ... | inventory (see the header)");
  let product = arg("--product"), chipId = arg("--chip-id"), tcb = arg("--tcb") ? parseTcbArg(arg("--tcb")) : null, kdsBase = KDS;
  if (arg("--kds-url") && arg("--statement")) throw new Error("--kds-url and --statement are alternatives");
  if (arg("--kds-url") || arg("--statement")) {
    if (product || chipId || tcb) throw new Error(`${arg("--kds-url") ? "--kds-url" : "--statement"} replaces --product, --chip-id and --tcb`);
    if (arg("--kds-url")) ({ product, chipId, tcb, kdsBase } = parseKdsUrl(arg("--kds-url")));
    else ({ product, chipId, tcb } = readStatement(readBounded(arg("--statement"), LIMITS.policy, "statement").toString("utf8")));
  }
  if (!product || !chipId || !tcb) throw new Error("state the chip: --product, --chip-id and --tcb (or --kds-url)");
  const policyFile = arg("--min-tcb");
  if (!policyFile) throw new Error("--min-tcb policy.json is required: the acceptable floor is the operator's choice");
  const minTcb = JSON.parse(readBounded(policyFile, LIMITS.policy, "minimum-TCB policy").toString("utf8"));
  if (has("--vcek") === has("--fetch-vcek")) throw new Error("exactly one of --vcek FILE or --fetch-vcek");
  if (has("--chain") && has("--fetch-chain")) throw new Error("at most one of --chain FILE or --fetch-chain");
  const crlPolicy = arg("--crl-policy") || "required";
  if (crlPolicy !== "none" && has("--crl") === has("--fetch-crl")) throw new Error("exactly one of --crl FILE or --fetch-crl (or --crl-policy none)");
  const now = arg("--at") ? new Date(arg("--at")) : new Date();
  const meta = await prepareCollateral({ out: path.resolve(arg("--out") || ""), product, chipId, tcb, minTcb, now, kdsBase, crlPolicy,
    maxStaleDays: Number(arg("--max-stale-days") || 0), allowAskRotation: has("--allow-ask-rotation"),
    vcek: has("--vcek") ? { file: arg("--vcek") } : { fetch: true },
    chain: has("--chain") ? { file: arg("--chain") } : has("--fetch-chain") ? { fetch: true } : {},
    crl: has("--crl") ? { file: arg("--crl") } : has("--fetch-crl") ? { fetch: true } : {},
    log: (m) => console.error(m) });
  console.log(JSON.stringify({ out: path.resolve(arg("--out")), product: meta.product, hwId: meta.hwId, vcekSha256: meta.vcek.sha256, kdsUrl: meta.kdsUrl, crl: meta.crl.policy }, null, 2));
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((e) => { console.error(`host-collateral: ${e.message}`); process.exitCode = 1; });
}
