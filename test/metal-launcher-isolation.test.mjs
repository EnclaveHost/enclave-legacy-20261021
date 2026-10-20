// The launcher's per-app isolation runtime config: what a metal node's host hands its guest over fw_cfg as
// `isolation`. The attested-release opt-in is the operator's `isolation.release: true` in the host config
// (isolation/restore/ENABLEMENT.md step 3); gsup reads it from fw_cfg and only then passes ISOLATION_RELEASE=1 to the
// supervisor. 4c-c-b (2026-09-25) booted the gsup half with the host half missing: the launcher built fw_cfg's
// `isolation` from three named keys and dropped `release`, so gsup logged "attested release off".
//
// Three layers, because a text-sliced helper alone is the kind of check that missed it (enclave-d1):
//   1. isoRuntimeOf, sliced out by text (enclave-metal.mjs launches QEMU at import; the certsCfg pattern);
//   2. the REAL launcher, run with a fake QEMU that copies out the fw_cfg file it is handed: the bytes the guest reads;
//   3. the contract across the boundary: gsup still reads fw_cfg `isolation` and gates on `release === true`.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const LAUNCHER = join(repo, "metal", "enclave-metal.mjs");
const src = fs.readFileSync(LAUNCHER, "utf8");
const gsup = fs.readFileSync(join(repo, "metal", "guest", "gsup.mjs"), "utf8");
const start = src.indexOf("function isoRuntimeOf(");
const end = src.indexOf("const ISO = (cfg.isolation");
assert.ok(start > 0 && end > start, "isoRuntimeOf must stay a self-contained block in enclave-metal.mjs");
const isoRuntimeOf = new Function(src.slice(start, end) + "\nreturn isoRuntimeOf;")();

const KEY = "ab".repeat(32);
const BASE = { backend: "snp-guest-per-app", managerUrl: "http://10.0.2.2:8095", dataAddr: "10.0.2.2:8096",
               pairingKeyFile: "/home/op/enclave-prod/guestd-pair.key" };

// ---- 1. the decision ----------------------------------------------------------------------------------------------
test("release: true is forwarded, with the endpoints and the key, and nothing else", () => {
  assert.deepEqual(isoRuntimeOf({ ...BASE, release: true }, KEY),
    { managerUrl: "http://10.0.2.2:8095", dataAddr: "10.0.2.2:8096", pairingKey: KEY, release: true });
});

test("absent or false forwards NO release key; any other value refuses (a typo must not pass for an opt-in)", () => {
  for (const release of [undefined, false])
    assert.deepEqual(Object.keys(isoRuntimeOf({ ...BASE, release }, KEY)).sort(), ["dataAddr", "managerUrl", "pairingKey"],
      `release=${JSON.stringify(release)}`);
  for (const release of ["true", "false", 1, 0, "yes", null, {}, [true]])
    assert.throws(() => isoRuntimeOf({ ...BASE, release }, KEY), /isolation\.release must be the boolean true or false/,
      `release=${JSON.stringify(release)} must refuse`);
});

test("no other isolation key crosses to the guest (backend, the key FILE path, anything added later)", () => {
  const out = isoRuntimeOf({ ...BASE, release: true, extra: "x", legacyImage: true, minTcb: {} }, KEY);
  assert.deepEqual(Object.keys(out).sort(), ["dataAddr", "managerUrl", "pairingKey", "release"]);
  assert.ok(!JSON.stringify(out).includes("guestd-pair.key"), "the key file path stays on the host");
});

test("the endpoints default as before and must be IPv4 literals", () => {
  assert.deepEqual(isoRuntimeOf({ backend: "snp-guest-per-app" }, KEY),
    { managerUrl: "http://10.0.2.2:8095", dataAddr: "10.0.2.2:8096", pairingKey: KEY });
  assert.throws(() => isoRuntimeOf({ ...BASE, managerUrl: "http://guestd.local:8095" }, KEY), /IPv4 literals/);
  assert.throws(() => isoRuntimeOf({ ...BASE, dataAddr: "[::1]:8096" }, KEY), /IPv4 literals/);
});

// ---- 2. the real launcher, a fake QEMU ------------------------------------------------------------------------------
// The fake QEMU copies the file named by `-fw_cfg name=opt/org.enclave.metal,file=…` (what the guest reads at
// /sys/firmware/qemu_fw_cfg/by_name/opt/org.enclave.metal/raw) to $FAKE_QEMU_OUT, then sleeps until the launcher
// stops it. TMPDIR is private, so the launcher's stale-fw_cfg sweep never looks at the real /tmp.
function launchWith(isolation, extras = {}) {
  const t = fs.mkdtempSync(join(os.tmpdir(), "metal-iso-test-"));
  fs.mkdirSync(join(t, "dist")); fs.mkdirSync(join(t, "tmp"));
  fs.writeFileSync(join(t, "dist", "vmlinuz"), "not a kernel");
  fs.writeFileSync(join(t, "dist", "initramfs.cpio.gz"), "not an initrd");
  fs.writeFileSync(join(t, "pair.key"), KEY + "\n", { mode: 0o600 });
  fs.writeFileSync(join(t, "fake-qemu"), [
    "#!/bin/sh",
    "while [ $# -gt 0 ]; do",
    '  if [ "$1" = -fw_cfg ]; then case "$2" in name=opt/org.enclave.metal,file=*)',
    '    cp "${2#name=opt/org.enclave.metal,file=}" "$FAKE_QEMU_OUT.tmp" && mv "$FAKE_QEMU_OUT.tmp" "$FAKE_QEMU_OUT";; esac; fi',
    "  shift",
    "done",
    "exec sleep 30",
  ].join("\n") + "\n", { mode: 0o755 });
  const cfg = { ...extras, mode: "snp", name: "iso-test", cpus: 1, memMiB: 512, dist: join(t, "dist"), ovmf: join(t, "ovmf.fd"),
                qemu: join(t, "fake-qemu"), relayUrl: "wss://relay.example.test/v1/fleet-tunnel",
                isolation: { ...BASE, pairingKeyFile: join(t, "pair.key"), ...isolation } };
  fs.writeFileSync(join(t, "config.json"), JSON.stringify(cfg));
  const out = join(t, "fwcfg.json");
  const p = spawn(process.execPath, [LAUNCHER, "--config", join(t, "config.json")],
    { env: { ...process.env, TMPDIR: join(t, "tmp"), FAKE_QEMU_OUT: out }, stdio: ["ignore", "pipe", "pipe"] });
  let log = "";
  p.stdout.on("data", (d) => { log += d; }); p.stderr.on("data", (d) => { log += d; });
  const exited = new Promise((r) => p.on("exit", (code, sig) => r({ code, sig })));
  return { t, p, out, exited, log: () => log };
}
async function fwCfgOf(isolation, extras = {}) {
  const run = launchWith(isolation, extras);
  try {
    const first = await Promise.race([
      (async () => { for (let i = 0; i < 200; i++) { if (fs.existsSync(run.out)) return "file"; await new Promise((r) => setTimeout(r, 50)); } return "timeout"; })(),
      run.exited.then(() => "exited"),
    ]);
    assert.equal(first, "file", `the fake QEMU never received the fw_cfg file (${first}); launcher output:\n${run.log()}`);
    return { fw: JSON.parse(fs.readFileSync(run.out, "utf8")), log: run.log() };
  } finally {
    run.p.kill("SIGTERM");                  // this exact child; its handler stops the fake QEMU
    await run.exited;
    fs.rmSync(run.t, { recursive: true, force: true });
  }
}

test("the real launcher hands the guest isolation.release === true for release: true", async () => {
  const { fw, log } = await fwCfgOf({ release: true });
  assert.deepEqual(fw.isolation, { managerUrl: "http://10.0.2.2:8095", dataAddr: "10.0.2.2:8096", pairingKey: KEY, release: true });
  assert.match(log, /attested release OPTED IN/);
});

test("the real launcher hands the guest NO release key when it is absent or false", async () => {
  for (const isolation of [{}, { release: false }]) {
    const { fw, log } = await fwCfgOf(isolation);
    assert.deepEqual(Object.keys(fw.isolation).sort(), ["dataAddr", "managerUrl", "pairingKey"], JSON.stringify(isolation));
    assert.match(log, /attested release off/);
  }
});

test("the real launcher REFUSES release: \"true\" (a string) and never starts QEMU", async () => {
  const run = launchWith({ release: "true" });
  try {
    // it must EXIT, before any QEMU: a launcher that reads the typo as "off" starts QEMU instead (and never exits)
    const first = await Promise.race([
      run.exited.then(({ code }) => ({ what: "exited", code })),
      (async () => { for (let i = 0; i < 200; i++) { if (fs.existsSync(run.out)) return { what: "qemu started" }; await new Promise((r) => setTimeout(r, 50)); } return { what: "timeout" }; })(),
    ]);
    assert.equal(first.what, "exited", `a non-boolean release must fail the launch, not run it (${first.what}); output:\n${run.log()}`);
    assert.notEqual(first.code, 0, "a non-boolean release must fail the launch");
    assert.match(run.log(), /isolation\.release must be the boolean true or false/);
    assert.equal(fs.existsSync(run.out), false, "QEMU must not have been started");
  } finally {
    if (run.p.exitCode === null && run.p.signalCode === null) { run.p.kill("SIGTERM"); await run.exited; }
    fs.rmSync(run.t, { recursive: true, force: true });
  }
});

// ---- 3. the contract across the boundary ----------------------------------------------------------------------------
test("the host half and the guest half name the same thing", () => {
  // the launcher puts isoRuntimeOf's result into fw_cfg as `isolation`...
  assert.match(src, /ISO_RUNTIME = isoRuntimeOf\(ISO, key\);/);
  assert.match(src, /\.\.\.\(ISO_RUNTIME \? \{ isolation: ISO_RUNTIME \} : \{\}\)/);
  // ...and gsup reads fw_cfg's `isolation` and opts in on exactly `release === true`
  assert.match(gsup, /const ISO_CFG = \(fw\.isolation && typeof fw\.isolation === 'object'\) \? fw\.isolation : \{\};/);
  assert.match(gsup, /\.\.\.\(ISO_CFG\.release === true \? \{ ISOLATION_RELEASE: '1' \} : \{\}\)/);
});

// The real launcher passes only public, validated policy data into the guest.
test("wallet policy crosses real fw_cfg and installs from the standalone guest bundle", async () => {
  const {pathToFileURL}=await import('node:url');
  const {spawnSync}=await import('node:child_process');
  const dir=fs.mkdtempSync(join(os.tmpdir(),'metal-policy-boundary-'));
  const hostId='0x'+'ab'.repeat(32),ownershipContract='0x'+'11'.repeat(20);
  const policy={version:1,chainId:8453,hostId,ownershipContract,requireCatalogApproval:false,denyDeployments:[],denyAppRefs:[]};
  const contracts=Object.fromEntries(['registry','deployments','appCatalog','proofOfTime','enclavePay','verificationFees','sessionVaultFactory','secretVaultV2'].map((k,i)=>[k,'0x'+String(i+1).repeat(40)]));
  try {
    fs.writeFileSync(join(dir,'pins.json'),JSON.stringify({version:1,chainId:8453,contracts}));
    fs.writeFileSync(join(dir,'policy.json'),JSON.stringify(policy));
    const hostAdmission={hostId,ownershipContract,pinsFile:join(dir,'pins.json'),policyFiles:[join(dir,'policy.json')],policyOrigins:['https://policy.example.test']};
    const {fw}=await fwCfgOf({}, {hostAdmission});
    assert.equal(JSON.stringify(fw.hostAdmission).includes(dir),false);
    assert.deepEqual(fw.hostAdmission.policies,[policy]);
    assert.deepEqual(Object.keys(fw.hostAdmission).sort(),['hostId','ownershipContract','pins','policies','policyOrigins','version']);
    const bundle=join(dir,'host-policy.bundle.mjs');
    fs.copyFileSync(join(repo,'metal/guest/host-policy.bundle.mjs'),bundle);
    // Separate cwd without node_modules proves the exact shipped artifact is usable.
    const script=`import {installMetalHostPolicy} from ${JSON.stringify(pathToFileURL(bundle).href)};console.log(JSON.stringify(installMetalHostPolicy(${JSON.stringify(fw.hostAdmission)},{directory:${JSON.stringify(join(dir,'guest'))}})));`;
    const installed=spawnSync(process.execPath,['--input-type=module','-e',script],{cwd:dir,encoding:'utf8'});
    assert.equal(installed.status,0,installed.stderr);
    const env=JSON.parse(installed.stdout);
    assert.equal(env.ENCLAVE_HOST_ID,hostId);
    assert.equal(env.ENCLAVE_HOST_OWNERSHIP,ownershipContract);
    assert.equal(env.ENCLAVE_HOST_REGISTRY_PIN,contracts.registry);
    assert.equal(env.ENCLAVE_HOST_CATALOG_PIN,contracts.appCatalog);
    assert.deepEqual(JSON.parse(fs.readFileSync(env.ENCLAVE_CONTRACT_PINS_FILE)),fw.hostAdmission.pins);
    const docs=fs.readdirSync(env.ENCLAVE_HOST_POLICY_DIR);assert.equal(docs.length,1);
    assert.deepEqual(JSON.parse(fs.readFileSync(join(env.ENCLAVE_HOST_POLICY_DIR,docs[0]))),policy);
    assert.match(gsup,/const HOST_POLICY_ENV=installMetalHostPolicy\(fw.hostAdmission\)/);
    assert.match(gsup,/\.\.\.flavorEnv,[^]*?\.\.\.HOST_POLICY_ENV/);
    const {hostAdmissionFromEnv}=await import('../network/host-admission-runtime.mjs');
    assert.throws(()=>hostAdmissionFromEnv({hostId:'0x'+'cd'.repeat(32),env}),/another host/);
    assert.ok(hostAdmissionFromEnv({hostId,env,addressBook:ownershipContract,rpc:['https://rpc-a.example','https://rpc-b.example']}));
    // A foreign policy must fail in the launcher, before QEMU is invoked.
    fs.writeFileSync(join(dir,'policy.json'),JSON.stringify({...policy,hostId:'0x'+'cd'.repeat(32)}));
    const run=launchWith({}, {hostAdmission});
    try{const result=await run.exited;assert.notEqual(result.code,0);assert.equal(fs.existsSync(run.out),false);assert.match(run.log(),/another host/);}
    finally{fs.rmSync(run.t,{recursive:true,force:true});}
  } finally {fs.rmSync(dir,{recursive:true,force:true});}
});

test('measured image and supervisor overlay include wallet policy and its local import closure',()=>{
 const builder=fs.readFileSync(join(repo,'metal/build-image.mjs'),'utf8');
 assert.match(builder,/\['gsup.mjs', 'host-policy.bundle.mjs'/);
 const list=builder.match(/const files = (\[[\s\S]*?\]);/)[1];
 const files=new Function('return '+list)();
 assert.ok(files.includes('windows/node/host-admission.bundle.mjs'));
 const visit=(file,seen=new Set())=>{
  if(seen.has(file))return;seen.add(file);
  assert.ok(files.includes(file),`overlay missing ${file}`);
  const code=fs.readFileSync(join(repo,file),'utf8');
  for(const m of code.matchAll(/(?:from\s*|import\s*\()(['"])(\.\.?\/[^'"]+)\1/g)){
   const target=join(dirname(file),m[2]);visit(target,seen);
  }
 };
 for(const file of ['sdk/bootstrap/storage.mjs','sdk/bootstrap/package.mjs','sdk/storage/gateways.mjs','windows/node/host-admission.bundle.mjs'])visit(file);
});
