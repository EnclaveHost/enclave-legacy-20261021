#!/usr/bin/env node
/* Loopback entry point, wired for real. The supervisor reaches this over guestd-control/1.

   Everything the manager needs is constructed here and nowhere else: the bounded PowerShell
   runner, the WMI launcher with the guest image pinned BY HASH, and a CID-verified component
   fetcher. The manager then asks the host what it can actually do (probe) before it answers
   /health, so "canStart" is the host's answer rather than a configuration detail. */
import { profile, probeWorker, startBridge, ImageLauncher } from "./shield-profile.mjs";
import fs from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Manager, createServer, startManager } from "./server.mjs";
import { judgeRunning, checkAnswer } from "./ready.mjs";
import { runtimeId as runtimeIdOf } from "../../../isolation/contract/runtime.mjs";
import { HyperVPartitionBackend } from "./backend.mjs";
import { WmiHyperVLauncher, HYPERV_MODULE_SHA256, DEFAULT_VM_PREFIX, VM_PREFIX_RE } from "./wmi-launcher.mjs";
import { powershellRunner } from "./psrun.mjs";
import { cidFetcher } from "./fetchcid.mjs";
import { egressConfigFromEnv, checkPin, startEgress, EGRESS_SERVICE_GUID } from "./egress.mjs";
import { startPackageTransport, PACKAGE_SERVICE_GUID } from "./package-transport.mjs";
import { startCustodyTransport, CUSTODY_SERVICE_GUID } from "./custody-transport.mjs";
import { readCustodyCallbackKey } from "./custody-key-file.mjs";
import { DERIVATION_V6, DERIVATION_V7 } from "./derive.mjs";
import { PartitionConsoleLogs, consoleTargets, partitionLogDir } from "./console-log.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const env = (k, d = "") => (process.env[k] || d).trim();

const port        = Number(env("VMMGR_PORT", "8091"));
// THE VM NAME SCOPE of this instance. Unset: the production prefix, exactly as before. Set (e.g. a hardware canary beside
// production): its own name prefix and Notes marker (wmi-launcher.mjs markerFor), so neither instance surveys, recovers,
// sweeps or removes the other's VMs. Validated first: a malformed scope never starts.
const vmPrefix = env("ENCLAVE_VM_PREFIX") || DEFAULT_VM_PREFIX;
if (vmPrefix !== DEFAULT_VM_PREFIX && !VM_PREFIX_RE.test(vmPrefix)) {
  console.error(`[winmgr] REFUSING TO START: ENCLAVE_VM_PREFIX must be "enclave-" + 1-16 lowercase letters or digits + "-" (got ${JSON.stringify(vmPrefix).slice(0, 60)})`);
  process.exit(2);
}
if (vmPrefix !== DEFAULT_VM_PREFIX) console.log(`[winmgr] VM scope ${vmPrefix}: a separately scoped instance; it sees only its own VM names or Notes marker`);
const imagePath   = env("ENCLAVE_GUEST_IGVM");          // e.g. C:\Users\claude\vbs-like\openhcl-ownguest.bin
const imageSha256 = env("ENCLAVE_GUEST_IGVM_SHA256");   // the bytes it must be; a path is not an identity
const runtimeId   = env("ENCLAVE_RUNTIME_ID");
// fetch-cid.py lives with the node, NOT in this directory, and it imports ipfs_fetch.py from beside
// itself - so the path must point at that copy rather than anywhere convenient.
const fetcherPath = env("ENCLAVE_CID_FETCHER", path.resolve(HERE, "../../node/fetch-cid.py"));

const fetchComponent = cidFetcher({
  script: fetcherPath,
  python: env("PYTHON_BIN", "python"),
  gateway: env("IPFS_GATEWAYS") || env("IPFS_GATEWAY"),
  timeoutMs: Number(env("ENCLAVE_FETCH_TIMEOUT_MS", "240000")),
});

// THE TYPE-1 DEFINITION (wmi-launcher.mjs, ported from uefi-dev-boot.ps1). The boot form is STATED
// here or not at all - "uefi-medium" (ENCLAVE_GUEST_MEDIUM + its sha256) or "linux-direct" (no
// medium; the IGVM is the identity) - and never inferred from which variables happen to be set. A
// launcher without it still surveys, stops and removes VMs, but refuses to start one, and /health
// says why. AllowFirmwareLoadFromFile is NOT configured here: the manager only reports it.
// THE APP AND ITS RELAY (enclave-5d's wmiserve-run.mjs): the Rust launcher's `wmiserve`, run per domain with
// `--hold stdin`, loads the bundle over hv_sock 9000, signs reports on 9001 and relays TCP to the domain. Without these
// three variables the manager boots VMs and serves nothing (the domain stays `starting`). The executable is PINNED BY
// HASH like every other input: a path is not an identity. It is checked here, and the manager refuses to start on a
// mismatch or a partial configuration rather than guessing which half was meant.
const wmiserveExe = env("ENCLAVE_WMISERVE_EXE"), wmiserveSha = env("ENCLAVE_WMISERVE_EXE_SHA256").toLowerCase();
const bundleDir = env("ENCLAVE_BUNDLE_DIR");
let serve = null;
if (wmiserveExe || wmiserveSha || bundleDir) {
  const miss = [!wmiserveExe && "ENCLAVE_WMISERVE_EXE", !/^[0-9a-f]{64}$/.test(wmiserveSha) && "ENCLAVE_WMISERVE_EXE_SHA256 (64 hex)",
                !bundleDir && "ENCLAVE_BUNDLE_DIR"].filter(Boolean);
  if (miss.length) {
    console.error(`[winmgr] REFUSING TO START: serving through wmiserve needs all three settings; missing ${miss.join(", ")}`);
    process.exit(2);
  }
  let got = null;
  try { got = createHash("sha256").update(fs.readFileSync(wmiserveExe)).digest("hex"); }
  catch (e) { console.error(`[winmgr] REFUSING TO START: cannot read the wmiserve executable ${wmiserveExe}: ${e.message}`); process.exit(2); }
  if (got !== wmiserveSha) {
    console.error(`[winmgr] REFUSING TO START: the wmiserve executable ${wmiserveExe} hashes ${got}, not the pinned ${wmiserveSha}`);
    process.exit(2);
  }
  serve = { exe: wmiserveExe, bundleDir };
  console.log(`[winmgr] serving through wmiserve ${wmiserveExe} (sha256 ${got}); bundles in ${bundleDir}`);
}

// OUTBOUND HTTPS for secret domains (egress.mjs), OFF unless ENCLAVE_EGRESS_V1=1. Then every setting must be present and
// both executables must be their pinned bytes, or the manager refuses to start rather than run half of it:
//   ENCLAVE_EGRESS_EXE / _SHA256                 shield-egress.exe (isolation/m2/cmd/shield-egress)
//   ENCLAVE_EGRESS_BRIDGE_EXE / _SHA256          shielded-bridge.exe (the Shield GPU path's bridge, unchanged)
//   ENCLAVE_EGRESS_SOCKS=127.0.0.1:30489         the host's loopback SOCKS entry (an Enclave-network circuit), or instead
//   ENCLAVE_EGRESS_APP_ROUTES=<routes.json>      the per-app routes file (egress.ReadAppRoute)
//   ENCLAVE_EGRESS_ALLOW (optional)              comma-separated https origins: a host-side narrowing for every partition
// The hv_sock service for vsock 9443 must be registered under GuestCommunicationServices: preflight reads it, and
// canStart is false until it is (this manager never writes the registry).
let egress = null;
try { egress = egressConfigFromEnv(process.env); }
catch (e) { console.error(`[winmgr] REFUSING TO START: ${e.message}`); process.exit(2); }
if (egress) {
  try {
    const a = checkPin(egress.exe, egress.sha256, "the shield-egress executable");
    const b = checkPin(egress.bridgeExe, egress.bridgeSha256, "the shielded-bridge executable (egress)");
    console.log(`[winmgr] egress ON (${egress.mode}): shield-egress ${egress.exe} (sha256 ${a}), bridge ${egress.bridgeExe} (sha256 ${b}); `
      + "secret deployments only");
  } catch (e) { console.error(`[winmgr] REFUSING TO START: ${e.message}`); process.exit(2); }
}
// OWNER-COMMITTED STARTUP (package-transport.mjs, isolation/m2/front/shield_direct.go) ON ITS OWN PINNED IMAGE (F3):
// ENCLAVE_SHIELD_DIRECT=1 needs a SEPARATE Shield-direct image, by path, hash and runtime identity:
//   ENCLAVE_SHIELD_DIRECT_IGVM / _IGVM_SHA256 / _RUNTIME_IDENTITY (runtime.json; the RuntimeID is derived, never configured)
// distinct from the legacy ENCLAVE_GUEST_IGVM, which keeps running the readiness witness, public and relay-secret apps
// exactly as before. A Shield-direct front ends every domain that receives no package, so the legacy image is never
// relabelled as direct, and there is no grace mode. Such a partition reads its package on vsock 9446 and its own RPC
// quorum, CA and responder through egress, so egress is required; the package bridge is the egress bridge's pinned
// executable. OFF by default, and then a spawn carrying a package is refused (server.mjs).
const shieldDirect = env("ENCLAVE_SHIELD_DIRECT") === "1";
let direct = null;            // { imagePath, imageSha256, runtime, runtimeId }
if (shieldDirect) {
  const dPath = env("ENCLAVE_SHIELD_DIRECT_IGVM"), dSha = env("ENCLAVE_SHIELD_DIRECT_IGVM_SHA256").toLowerCase(), dIdentity = env("ENCLAVE_SHIELD_DIRECT_RUNTIME_IDENTITY");
  const miss = [!egress && "ENCLAVE_EGRESS_V1=1 (the guest reads its own chain quorum through egress)",
                !(imagePath && imageSha256) && "the legacy image ENCLAVE_GUEST_IGVM and _SHA256 (the witness and every legacy spawn run there)",
                !dPath && "ENCLAVE_SHIELD_DIRECT_IGVM", !/^[0-9a-f]{64}$/.test(dSha) && "ENCLAVE_SHIELD_DIRECT_IGVM_SHA256 (64 hex)",
                !dIdentity && "ENCLAVE_SHIELD_DIRECT_RUNTIME_IDENTITY",
                dPath && dPath === imagePath && "a Shield-direct image path distinct from ENCLAVE_GUEST_IGVM",
                dSha && dSha === imageSha256.toLowerCase() && "a Shield-direct image hash distinct from ENCLAVE_GUEST_IGVM_SHA256 (the legacy image is never relabelled)"].filter(Boolean);
  if (miss.length) { console.error(`[winmgr] REFUSING TO START: ENCLAVE_SHIELD_DIRECT=1 needs ${miss.join(", ")}`); process.exit(2); }
  let runtime;
  try { runtime = JSON.parse(fs.readFileSync(dIdentity, "utf8")); }
  catch (e) { console.error(`[winmgr] REFUSING TO START: the Shield-direct runtime identity ${dIdentity}: ${e.message}`); process.exit(2); }
  direct = { imagePath: dPath, imageSha256: dSha, runtime, runtimeId: Buffer.from(runtimeIdOf(runtime)).toString("hex") };
  console.log(`[winmgr] owner-committed startup ON, on its own image ${dSha} (RuntimeID ${direct.runtimeId}; tier T0-hv, hostExcluded=false); the legacy image ${imageSha256} keeps every other spawn`);
}
// the launcher's hook: a secret deployment's partition, or an owner-committed one, gets its egress path; every other mapping gets none
const egressHook = egress
  ? (vmId, deploymentId, mapping, { bootstrap = false } = {}) =>
      [DERIVATION_V6,DERIVATION_V7].includes(mapping?.record?.derivation) || (shieldDirect && bootstrap) ? startEgress({ cfg: egress, vmId, deploymentId }) : null
  : null;
const packageHook = shieldDirect
  ? (vmId, deploymentId, bytes) => startPackageTransport({ bridge: { exe: egress.bridgeExe, sha256: egress.bridgeSha256 }, vmId, deploymentId, bytes })
  : null;
// DIRECT SHIELD CUSTODY (custody-transport.mjs, isolation/m2/front/shield_direct_custody.go): ENCLAVE_SHIELD_CUSTODY_V2=1
// states that the pinned Shield-direct image is the custody build, by its hash: ENCLAVE_SHIELD_CUSTODY_IMAGE_SHA256 must be
// ENCLAVE_SHIELD_DIRECT_IGVM_SHA256, so changing the image turns custody off until it is stated again. Such a guest needs the
// Shield-direct package path, egress and secret (V6) delivery, and the node answers its requests with the key in
// ENCLAVE_CUSTODY_CALLBACK_KEY_FILE (a private file of 64-128 hex, the node's copy beside it). OFF by default. The 9445
// hv_sock service is registered by an explicit activation step, never here: preflight reports it, canStart follows.
let custodyV2 = null;
if (env("ENCLAVE_SHIELD_CUSTODY_V2") === "1") {
  const stated = env("ENCLAVE_SHIELD_CUSTODY_IMAGE_SHA256").toLowerCase(), keyFile = env("ENCLAVE_CUSTODY_CALLBACK_KEY_FILE");
  const miss = [!shieldDirect && "ENCLAVE_SHIELD_DIRECT=1", env("ENCLAVE_CONFIG_BUNDLE_V5") !== "1" && "ENCLAVE_CONFIG_BUNDLE_V5=1",
                env("ENCLAVE_SECRETS_V1") !== "1" && "ENCLAVE_SECRETS_V1=1",
                !(/^[0-9a-f]{64}$/.test(stated) && stated === direct?.imageSha256) && "ENCLAVE_SHIELD_CUSTODY_IMAGE_SHA256 equal to the pinned ENCLAVE_SHIELD_DIRECT_IGVM_SHA256",
                !keyFile && "ENCLAVE_CUSTODY_CALLBACK_KEY_FILE"].filter(Boolean);
  if (miss.length) { console.error(`[winmgr] REFUSING TO START: ENCLAVE_SHIELD_CUSTODY_V2=1 needs ${miss.join(", ")}`); process.exit(2); }
  let key = null;
  // private to SYSTEM and Administrators on win32 (its DACL and owner), owner-only on POSIX; checked, never altered
  try { key = readCustodyCallbackKey(keyFile); }
  catch (e) { console.error(`[winmgr] REFUSING TO START: the custody callback key file ${keyFile}: ${e.message}`); process.exit(2); }
  custodyV2 = { imageSha256: stated, callbackKey: key };
  console.log(`[winmgr] direct Shield custody ON for image ${stated}: V6/V7 custody-v2 packages only; the guest opens its own shares`);
}
const custodyHook = custodyV2
  ? (vmId, deploymentId, { vault }) => startCustodyTransport({ bridge: { exe: egress.bridgeExe, sha256: egress.bridgeSha256 }, vmId, deploymentId, vault })
  : null;

let launcher = null, directLauncher = null;
let launcherOptions = null;
if (imagePath && imageSha256) {
  try {
    launcherOptions = {
      run: powershellRunner(), imagePath, imageSha256, prefix: vmPrefix,
      boot: env("ENCLAVE_BOOT_FORM") || null,
      medium: env("ENCLAVE_GUEST_MEDIUM") || null,
      mediumSha256: env("ENCLAVE_GUEST_MEDIUM_SHA256") || null,
      guestStateMaster: env("ENCLAVE_GUEST_STATE_MASTER") || null,
      guestStateMasterSha256: env("ENCLAVE_GUEST_STATE_MASTER_SHA256") || null,
      guestStateRunDir: env("ENCLAVE_GUEST_STATE_RUN_DIR") || null,
      guestStateArchiveDir: env("ENCLAVE_GUEST_STATE_ARCHIVE_DIR") || null,
      hypervModule: env("ENCLAVE_HYPERV_MODULE") || null,
      hypervModuleSha256: env("ENCLAVE_HYPERV_MODULE_SHA256", HYPERV_MODULE_SHA256),
      hypervUtilitiesSha256: env("ENCLAVE_HYPERV_UTILITIES_SHA256") || null,
      serve,
      ...(egress ? { startEgress: egressHook, egressService: EGRESS_SERVICE_GUID } : {}),
    };
    // the legacy image: no package and no custody hook, exactly the launcher it always was
    launcher = new WmiHyperVLauncher(launcherOptions);
    // the Shield-direct image (F3): the same host options, its own pinned IGVM, and the package and custody hooks
    if (direct) directLauncher = new WmiHyperVLauncher({ ...launcherOptions, imagePath: direct.imagePath, imageSha256: direct.imageSha256, imageRole: "shield-direct",
      startPackage: packageHook, packageService: PACKAGE_SERVICE_GUID,
      ...(custodyHook ? { startCustody: custodyHook, custodyService: CUSTODY_SERVICE_GUID, custodyImageSha256: custodyV2.imageSha256 } : {}) });
  } catch (e) {
    // A contradictory launcher configuration (a medium with linux-direct, an unknown boot form, a
    // medium with no boot form) is refused at startup rather than guessed at.
    console.error(`[winmgr] REFUSING TO START: the launcher configuration is invalid: ${e.message}`);
    process.exit(2);
  }
}
// THE RUNTIME IDENTITY, read from the image's own runtime.json rather than configured as a hash.
//
// enclave-53 found that the defect-11 fix was not REACHED from here: this entry point passed only
// runtimeId, so this.runtime was null, #judgeReadiness passed expectRuntime: undefined, and
// checkRuntime pinned nothing. Two consequences, and the second is worse than the first: any
// admissible runtime a domain stated was accepted, AND an ABI/1 document was not refused as a
// downgrade, because judge.mjs refuses that only when want.runtime is given. So a manager started
// the normal way silently accepted exactly what the ABI/2 binding exists to prevent - while the
// record-to-route case was green, because it constructs the Manager directly.
//
// A path, not a hash: the hash is derived from the identity so the two cannot disagree.
const runtimeIdentityPath = env("ENCLAVE_RUNTIME_IDENTITY");
let runtime = null;
if (runtimeIdentityPath) {
  runtime = JSON.parse(fs.readFileSync(runtimeIdentityPath, "utf8"));
  const derived = Buffer.from(runtimeIdOf(runtime)).toString("hex");
  // If a RuntimeID was ALSO configured, they must agree. Two independently supplied values that
  // must match are two values that will eventually not, and the one that silently wins decides
  // what every domain is judged against.
  // A stale ENCLAVE_RUNTIME_ID must not take the manager down, and it must not silently win either.
  // The identity is the input; the hash is derived from it, and DERIVED WINS - but a disagreement
  // is said loudly, because an operator who set that variable believed they were pinning something
  // and a silent no-op is the failure family this whole lane has been about. (enclave-99's spec:
  // ENCLAVE_RUNTIME_ID stops being an input. Agreed - with the warning, not without it.)
  if (runtimeId && runtimeId.toLowerCase() !== derived) {
    console.error(`[winmgr] WARNING: ENCLAVE_RUNTIME_ID is ${runtimeId}, which is NOT what the identity at `
      + `${runtimeIdentityPath} derives (${derived}). The identity wins and that variable is ignored; `
      + "remove it, because it pins nothing.");
  }
  console.log(`[winmgr] runtime identity ${runtime.name}/${runtime.version} ${runtime.execution} `
    + `${runtime.targetIsa} -> RuntimeID ${derived}`);
} else if (runtimeId) {
  // A hash alone cannot pin an identity: checkRuntime diffs the identity field by field, so a hash
  // here would reject every real document. Refusing beats judging nothing while looking configured.
  console.error("[winmgr] REFUSING TO START: ENCLAVE_RUNTIME_ID is set but ENCLAVE_RUNTIME_IDENTITY is not. "
    + "A RuntimeID hash cannot pin a runtime - the verifier compares the identity field by field - so this "
    + "manager would accept any admissible runtime and would not refuse an ABI/1 downgrade. "
    + "Set ENCLAVE_RUNTIME_IDENTITY to the image's runtime.json.");
  process.exit(2);
}

let shield = null, gpu = null;
const shieldConfig = env("ENCLAVE_SHIELD_PROFILE");
if (shieldConfig) {
  if (!launcherOptions) throw new Error("Shield requires an existing CPU launcher");
  const cfg = JSON.parse(fs.readFileSync(shieldConfig,"utf8"));
  shield = { ...profile(cfg.runtime), ready:false, imageSha256:cfg.imageSha256 };
  const gpuLauncher = new WmiHyperVLauncher({ ...launcherOptions, startEgress:null, egressService:null, startPackage:null, packageService:null, startCustody:null, custodyService:null, custodyImageSha256:null,   // no secret or owner-committed domain runs on the GPU image
    imageRole:"gpu", imagePath:cfg.imagePath, imageSha256:cfg.imageSha256,
    startTransport:vmId => startBridge({ exe:cfg.bridgeExe, sha256:cfg.bridgeSha256, vmId, port:cfg.workerPort || 19595 }) });
  await gpuLauncher.verifyImage();
  if (createHash("sha256").update(fs.readFileSync(cfg.bridgeExe)).digest("hex") !== cfg.bridgeSha256) throw new Error("Shield bridge differs from its pin");
  gpu = gpuLauncher;
  const refresh = async () => {
    try { shield.card=await probeWorker(cfg.workerPort || 19595); shield.ready=true; shield.checkedAt=Date.now(); shield.error=null; }
    catch(e) { shield.ready=false; shield.card=null; shield.error=e.message; shield.checkedAt=Date.now(); }
  };
  await refresh();
  setInterval(refresh,15000).unref();
}

// PER-SPAWN IMAGE SELECTION (F3, shield-profile.mjs ImageLauncher): a package -> the Shield-direct image, inference -> the
// GPU image, everything else -> the legacy image. With neither extra image, the legacy launcher alone, exactly as before.
const routed = launcher && (directLauncher || gpu) ? new ImageLauncher({ legacy: launcher, shieldDirect: directLauncher, gpu }) : launcher;
const manager = new Manager({ judgeReady: judgeRunning, answerCheck: checkAnswer, directBootstrap: !!directLauncher,
  images: { legacy: { igvmSha256: imageSha256.toLowerCase() || null },
            ...(direct ? { shieldDirect: { runtime: direct.runtime, igvmSha256: direct.imageSha256 } } : {}) },
  // only with a launcher whose own pinned image is the stated one (above); without a launcher nothing can start anyway
  custodyV2: custodyV2 && launcherOptions ? custodyV2 : null,
  // Match the node agent's advertised hosting RAM, not physical machine RAM.
  ramPoolMiB: env("NODE_APP_RAM_GB") ? Number(env("NODE_APP_RAM_GB")) * 1024 : null,
  runtime,
  shield,
  runtimeId,
  fetchComponent,
  // Enable only with the CPU guest image whose monitor delivers V5 config.
  configEnabled: env("ENCLAVE_CONFIG_BUNDLE_V5") === "1",
  secretsEnabled: env("ENCLAVE_SECRETS_V1") === "1",
  configSocketServer: env("ENCLAVE_CONFIG_SOCKET_SERVER_V1") === "1",
  protectedPorts: env("ENCLAVE_PROTECTED_PORTS_V1") === "1",
  wasmSet: env("ENCLAVE_WASM_SET") === "1", memory64: env("ENCLAVE_WASM_MEMORY64") === "1",
  egress: egress && launcherOptions ? { enabled: true, mode: egress.mode } : null,
  fetchConfig: cidFetcher({ script: fetcherPath, python: env("PYTHON_BIN", "python"),
    gateway: env("IPFS_GATEWAY"), maxBytes: 1 << 20,
    timeoutMs: Number(env("ENCLAVE_FETCH_TIMEOUT_MS", "240000")) }),
  backend: new HyperVPartitionBackend({ launcher: routed }),
});

// THE DATA PLANE. Without it a domain can be started and judged running and still have nothing to
// carry its traffic: the record names a relay port and nobody listens on the other side. It admits
// only a record that is `running` with appId, image, runtimeId, transportKeySha256 and relay all
// present, which is why those had to be real before this was worth starting (enclave-5d's
// createDataPlane, via dataPlaneFor).
const dataPort = Number(env("ENCLAVE_DATAPLANE_PORT", "0"));
let dp = null;
if (dataPort > 0) {
  const { dataPlaneFor } = await import("../datapath/node-bridge.mjs");
  dp = dataPlaneFor(manager);
  dp.server.listen(dataPort, "127.0.0.1", () => console.log(`[winmgr] data plane on 127.0.0.1:${dataPort}`));
  // A reclaimed domain's sessions must not outlive it: closeInstance is what makes a stop actually
  // stop carrying traffic, rather than leaving established connections to a partition that is gone.
  manager.onReclaim = (id, why) => { try { dp.closeInstance(id, why); } catch {} };
} else {
  console.log("[winmgr] no ENCLAVE_DATAPLANE_PORT: no data plane, so a running domain carries no traffic");
}

// Ask the host BEFORE answering anything about what it can do, then THE INVENTORY, before any /vms
// answer means anything (63's P1): the VMs a previous manager left running are recovered from their
// Notes, so "not in my memory" is never answered as "absent". Until this completes every /vms request
// is 503; a failed survey keeps it that way and is retried. (server.mjs startManager: shared with tests.)
const inv = await startManager(manager);
// LIVENESS (server.mjs sweepLiveness): a type-1 partition whose monitor dies goes OFF by itself (G4, run 082856), and
// only a survey sees it. Every ENCLAVE_LIVENESS_MS (default 15 s; 0 disables), a domain whose VM is not Running fails.
const livenessMs = Number(env("ENCLAVE_LIVENESS_MS", "15000"));
if (livenessMs > 0) {
  const t = setInterval(async () => {
    const r = await manager.sweepLiveness().catch((e) => ({ error: e.message }));
    if (r && r.failed) console.log(`[winmgr] liveness: ${r.failed} domain(s) failed because their partition stopped`);
    if (r && r.error) console.error(`[winmgr] liveness survey failed (nothing changed): ${r.error}`);
  }, livenessMs);
  t.unref?.();
}
// ANSWERS (server.mjs sweepAnswers): a Running partition whose domain wedged, or answers on another key, is invisible to
// the VM-state sweep. Every ENCLAVE_ANSWER_CHECK_MS (default 30 s; 0 disables), each running domain is asked on one TLS
// session: the verified key, and enclave-ready. 3 failures in a row, or one key change, fail it.
const answerMs = Number(env("ENCLAVE_ANSWER_CHECK_MS", "30000"));
if (answerMs > 0) {
  let busy = false;                                    // one sweep at a time: a slow domain must not stack them up
  const t = setInterval(async () => {
    if (busy) return; busy = true;
    const r = await manager.sweepAnswers().catch((e) => ({ error: e.message }));
    busy = false;
    if (r && r.failed) console.log(`[winmgr] answers: ${r.failed} domain(s) failed because they stopped answering on their verified key`);
    if (r && r.error) console.error(`[winmgr] answer check could not run: ${r.error}`);
  }, answerMs);
  t.unref?.();
}
// EVERY PARTITION'S CONSOLE, KEPT (console-log.mjs): once a domain's record carries its VM handle (after the launcher's
// boot read is over), its COM1 pipe is read into <logs>\partitions\<vmName>.log, so a later panic, OOM kill or poweroff
// leaves a trace. ENCLAVE_PARTITION_LOG_DIR overrides the directory ("off" disables). Never fatal: errors are one line.
const partitionLogs = launcher ? partitionLogDir(process.env) : null;
if (partitionLogs) {
  const consoles = new PartitionConsoleLogs({ dir: partitionLogs });
  const t = setInterval(() => { try { consoles.sync(consoleTargets(manager)); } catch (e) { console.error(`[winmgr] console sync: ${e.message}`); } }, 2_000);
  t.unref?.();
  console.log(`[winmgr] partition consoles are kept in ${partitionLogs}`);
}
console.log(`[winmgr] inventory ${inv.state}` + (inv.state === "ready" ? `: recovered ${inv.recovered}, unattributed ${inv.unattributed}` : inv.error ? `: ${inv.error}` : ""));
if (inv.state === "failed") {
  const retry = setInterval(async () => { const r = await manager.recover(); if (r.state !== "failed") { clearInterval(retry); console.log(`[winmgr] inventory ${r.state} on retry`); } }, 30_000);
  retry.unref?.();
}
const h = manager.health();
createServer(manager).listen(port, "127.0.0.1", () => {
  console.log(`[winmgr] ${h.backend} on 127.0.0.1:${port} · canStart=${h.canStart}`
    + (h.canStart ? "" : " · " + (h.preflight?.checks || []).filter((c) => !c.ok).map((c) => c.name).join(", ")));
  console.log(`[winmgr] fetcher ${fetcherPath}`);
  if (!imagePath || !imageSha256)
    console.log("[winmgr] no ENCLAVE_GUEST_IGVM / ENCLAVE_GUEST_IGVM_SHA256: no launcher, so no domain can start");
});
// Re-ask periodically: the role can be enabled under a running manager, and canStart must follow.
setInterval(() => { manager.probe().catch(() => {}); }, 60_000).unref?.();
