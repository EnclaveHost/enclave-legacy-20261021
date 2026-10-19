#!/usr/bin/env node
// The custody v2 CUSTODIAN image (docs/security/secret-custody-v2.md §8.1): a measured SEV-SNP guest made from a
// digest-checked metal control image (its kernel, PID 1, Node, guest modules and the fleet-tunnel agent), with:
//   - /opt/metal/gsup.mjs replaced by bundled custody/v2/cvm-gsup.mjs (direct custodian by default; explicit tunnel mode available);
//   - /opt/custodian/custodian.mjs: custody/v2/daemon.mjs bundled, with the MEASURED chain config (vault, RPCs) baked in;
//   - /opt/custodian/snpkey: the derived-key helper (isolation/m2/cmd/snpkey), static.
// Every other cpio entry is copied byte for byte. The launch measurement is printed (sev-snp-measure, 2 vCPUs).
//
//   node scripts/build-custodian-v2.mjs --base <metal dist dir> --out <new dir> --vault 0x… --host-ownership 0x… [--vcpus 2] [--transport direct|tunnel]
//        [--independent-owners owners.json | --independent-admission owner-permits]   (independent committees; see
//        docs/security/independent-custody-activation.md; either one bundles the static DKG helper)
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { build } from "esbuild";
import { custodianMeasured, measuredModule, readGzipFile, gzipPartsToFile } from "../custody/v2/build-config.mjs";

const ROOT = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), "..");
const arg = (n, d) => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : d; };
const BASE = path.resolve(arg("base", "")), OUT = path.resolve(arg("out", ""));
const VCPUS = String(arg("vcpus", "2"));
const ownerFile=arg("independent-owners",null);
// Every measured pin is validated (and interpreted by the daemon's own policy code) before any build work.
const { measured: MEASURED, policy: POLICY, needsDkg: NEEDS_DKG } = custodianMeasured({ vault: arg("vault", ""), hostOwnership: arg("host-ownership", ""),
  transport: arg('transport','direct'), ownerList: ownerFile ? JSON.parse(fs.readFileSync(ownerFile,'utf8')) : null, admission: arg("independent-admission", null) });
const { vault: VAULT, hostOwnership: HOST_OWNERSHIP, transport: TRANSPORT, independentOwners: INDEPENDENT_OWNERS } = MEASURED;
const INDEPENDENT_ADMISSION = MEASURED.independentAdmission || null;
const sha = (b) => createHash("sha256").update(b).digest("hex");
if (!fs.existsSync(path.join(BASE, "manifest.json"))) throw new Error("--base must be a metal dist dir");
if (fs.existsSync(OUT)) throw new Error(`${OUT} exists: an image is built once`);
const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
const dirty = execFileSync("git", ["status", "--porcelain", "--", "custody", "isolation/m2/cmd/snpkey", "relay/snp-verify.mjs", "verifier", "scripts/build-custodian-v2.mjs"], { cwd: ROOT, encoding: "utf8" }).trim();
if (dirty && !process.argv.includes("--allow-dirty")) throw new Error(`uncommitted changes in the image's sources:\n${dirty}`);

// 1. base, checked against its manifest
const m = JSON.parse(fs.readFileSync(path.join(BASE, "manifest.json"), "utf8"));
const { raw, sha256: baseInitramfsSha256 } = await readGzipFile(path.join(BASE, "initramfs.cpio.gz"));
if (m.initramfs && baseInitramfsSha256 !== m.initramfs.sha256) throw new Error("base initramfs hash mismatch");
if (sha(fs.readFileSync(path.join(BASE, "vmlinuz"))) !== m.kernel.sha256) throw new Error("base kernel hash mismatch");

// 2. the custodian bundle with the measured config
const measured = measuredModule(MEASURED);
const bundleOptions={ bundle: true, platform: "node", format: "esm", target: "node22",
  write: false, legalComments: "none", banner: { js: 'import { createRequire as __cr } from "node:module"; const require = __cr(import.meta.url);' },
  plugins: [{ name: "measured", setup(b) { b.onLoad({ filter: /custody[\\/]v2[\\/]measured\.mjs$/ }, () => ({ contents: measured, loader: "js" })); } }] };
const bundled = await build({...bundleOptions,entryPoints:[path.join(ROOT,'custody/v2/daemon.mjs')]});
const custodianJs = Buffer.from(bundled.outputFiles[0].contents);
const tmpKey = path.join(OUT + ".snpkey");
execFileSync("go", ["build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", tmpKey, "./cmd/snpkey"],
  { cwd: path.join(ROOT, "isolation/m2"), env: { ...process.env, GOFLAGS: "", CGO_ENABLED: "0", GOEXPERIMENT: "nodwarf5", GOTOOLCHAIN: "go1.27.0" }, stdio: "inherit" });
const snpkey = fs.readFileSync(tmpKey); fs.unlinkSync(tmpKey);
let dkg=null,dkgBuild=null;
if(NEEDS_DKG){
  execFileSync('cargo',['build','--locked','--release','--target','x86_64-unknown-linux-musl','--manifest-path',path.join(ROOT,'custody/dkg/Cargo.toml')],{cwd:ROOT,stdio:'inherit'});
  const binary=path.join(ROOT,'custody/dkg/target/x86_64-unknown-linux-musl/release/enclave-custody-dkg');
  if(/INTERP/.test(execFileSync('readelf',['-lW',binary],{encoding:'utf8'}))||/\(NEEDED\)/.test(execFileSync('readelf',['-dW',binary],{encoding:'utf8'})))throw Error('DKG helper must be static');
  dkg=fs.readFileSync(binary);
  dkgBuild={rustc:execFileSync('rustc',['--version'],{encoding:'utf8'}).trim(),cargo:execFileSync('cargo',['--version'],{encoding:'utf8'}).trim(),target:'x86_64-unknown-linux-musl',lockSha256:sha(fs.readFileSync(path.join(ROOT,'custody/dkg/Cargo.lock')))};
}
const gsup=Buffer.from((await build({...bundleOptions,entryPoints:[path.join(ROOT,'custody/v2/cvm-gsup.mjs')]})).outputFiles[0].contents);

// 3. rewrite the newc cpio: replace gsup, append the custodian dir + files before the trailer
const parts = []; let off = 0, maxino = 0, prefix = null, replaced = false;
const entry = (fields, name, data) => {
  const nm = Buffer.from(name + "\0");
  const h = Buffer.from("070701" + fields.map((n) => n.toString(16).padStart(8, "0")).join(""));
  const head = Buffer.concat([h, nm]); const pad1 = Buffer.alloc((4 - (head.length % 4)) % 4);
  return Buffer.concat([head, pad1, data, Buffer.alloc((4 - (data.length % 4)) % 4)]);
};
while (off < raw.length) {
  const start = off, h = raw.subarray(off, off + 110); off += 110;
  if (h.subarray(0, 6).toString() !== "070701") throw new Error("only newc cpio is supported");
  const f = Array.from({ length: 13 }, (_, i) => parseInt(h.subarray(6 + i * 8, 14 + i * 8).toString(), 16));
  const size = f[6], ns = f[11];
  const name = raw.subarray(off, off + ns - 1).toString(); off = (off + ns + 3) & ~3;
  const data = raw.subarray(off, off + size); off = (off + size + 3) & ~3;
  const key = name.replace(/^\.\//, "");
  maxino = Math.max(maxino, f[0]);
  if (key === "opt/metal/gsup.mjs") prefix = name.slice(0, name.length - key.length);
  if (name === "TRAILER!!!") {
    const add = (mode, k, d) => { maxino++; parts.push(entry([maxino, mode, 0, 0, mode >> 12 === 4 ? 2 : 1, 0, d.length, 0, 0, 0, 0, (prefix + k).length + 1, 0], prefix + k, d)); };
    add(0o040755, "opt/custodian", Buffer.alloc(0));
    add(0o100644, "opt/custodian/custodian.mjs", custodianJs);
    add(0o100755, "opt/custodian/snpkey", snpkey);
    if(dkg)add(0o100755,"opt/custodian/dkg",dkg);
    parts.push(raw.subarray(start, off));
    break;
  }
  if (key === "opt/metal/gsup.mjs") {
    if (f[4] !== 1) throw new Error("gsup.mjs is hardlinked");
    f[6] = gsup.length; parts.push(entry(f, name, gsup)); replaced = true;
  } else parts.push(raw.subarray(start, off));
}
if (!replaced || prefix === null) throw new Error("the base image has no /opt/metal/gsup.mjs");
fs.mkdirSync(OUT);
const out = await gzipPartsToFile(parts, path.join(OUT, "initramfs.cpio.gz"));
fs.copyFileSync(path.join(BASE, "vmlinuz"), path.join(OUT, "vmlinuz"));
const cmdline = fs.readFileSync(path.join(BASE, "cmdline"), "utf8").trim().replace("${MODE}", "snp");
fs.writeFileSync(path.join(OUT, "cmdline"), cmdline + "\n");
const manifest = { role: "enclave-custodian-v2", commit, vault: VAULT, hostOwnership: HOST_OWNERSHIP, base: { dir: path.basename(BASE), initramfsSha256: baseInitramfsSha256, kernelSha256: m.kernel.sha256 },
  independentOwners: INDEPENDENT_OWNERS,
  ...(INDEPENDENT_ADMISSION ? { independentAdmission: INDEPENDENT_ADMISSION } : {}),
  independentPolicy: POLICY,
  transport:TRANSPORT,
  dkgBuild,
  files: { "/opt/metal/gsup.mjs": sha(gsup), "/opt/custodian/custodian.mjs": sha(custodianJs), "/opt/custodian/snpkey": sha(snpkey), ...(dkg?{'/opt/custodian/dkg':sha(dkg)}:{}) },
  kernel: { sha256: m.kernel.sha256 }, initramfs: { sha256: out.sha256, bytes: out.bytes }, cmdline, vcpus: Number(VCPUS) };
// 4. the launch measurement this image produces on this host's firmware (the verifying OVMF), Turin
const OVMF = process.env.OVMF || path.join(process.env.HOME, ".cache/enclave-isolation/fwbuild/OVMF.amdsev.fd");
try {
  const meas = execFileSync(process.env.SEV_SNP_MEASURE || "sev-snp-measure", ["--mode", "snp", "--vcpus", VCPUS, "--vcpu-family", "26", "--vcpu-model", "2", "--vcpu-stepping", "1",
    "--ovmf", OVMF, "--kernel", path.join(OUT, "vmlinuz"), "--initrd", path.join(OUT, "initramfs.cpio.gz"), "--append", cmdline], { encoding: "utf8" }).trim().split("\n").pop();
  manifest.measurement = meas; manifest.measurementSha256 = "0x" + sha(Buffer.from(meas, "hex")); manifest.ovmfSha256 = sha(fs.readFileSync(OVMF));
} catch (e) { manifest.measurementError = e.message; }
fs.writeFileSync(path.join(OUT, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(JSON.stringify({ out: OUT, initramfs: manifest.initramfs, measurement: manifest.measurement, measurementSha256: manifest.measurementSha256 }, null, 1));
