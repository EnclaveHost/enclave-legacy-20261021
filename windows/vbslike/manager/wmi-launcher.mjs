/* ============================================================
   The supported launcher: WMI on the Hyper-V role, defining a TYPE-1 (VBS) partition.

   THE REFERENCE IS THE RECIPE THAT BOOTED AND SERVED on nucbox-k11 (2026-09-25):
   windows/vbslike/ops/uefi-dev-boot.ps1 at e0de58cf on windows/custom-vbs-like-hyperv, its
   `if ($IsolationType -eq 1)` branch, with the reason for every step in
   windows/vbslike/evidence/type1-isolation-2026-09-25.md. It defines the VM with petri's
   `New-CustomVM` (Microsoft's own OpenHCL test harness, openvmm petri/src/vm/hyperv/hyperv.psm1,
   PINNED BY HASH) in ONE DefineSystem call that carries GuestStateIsolationType 1,
   GuestFeatureSet 0x201 and FirmwareFile together, then removes the NICs, opts the GUEST out of its
   own VBS, attaches a medium or none, sends COM1 to a named pipe and reads every one of those back.

   WHAT IT REPLACES, AND WHY. This file used to follow openhcl/Set-OpenHCL-HyperV-VM.ps1: New-VM,
   then GuestFeatureSet + FirmwareFile written on afterwards through ModifySystemSettings. On this
   host a VM made that way never started as type 1 ("A New-VM VM patched afterwards through
   ModifySystemSettings is NOT the same thing, and it never started" - the evidence doc). So there is
   no New-VM here and no ModifySystemSettings firmware pin: the definition is the recipe's, whole.

   Every PowerShell fragment is produced by a pure function so it can be read and tested without a
   host. `run` is injected: production passes a real PowerShell runner, tests pass recorded answers.
   Nothing in this file executes anything by itself, and NONE OF IT HAS RUN ON HYPER-V: the recipe
   ran on the box; this port of it has only run against the fakes in the tests.

   THREE RULES IT KEEPS.

   Preflight refuses rather than improvises. If the Hyper-V role is absent, the namespace is missing,
   the module has no Get-VM, the pinned hyperv.psm1 or the guest-state master is not there, or the
   host's AllowFirmwareLoadFromFile opt-in is not set, `start` fails before it creates anything. The
   opt-in is REPORTED, never touched: see FIRMWARE_OPT_IN.

   Ownership is scoped by construction. Every VM this creates is named with the instance prefix and
   carries a Notes marker (with the deployment's identity), and teardown filters on BOTH. It never
   enumerates VMs for action by any other criterion, so a machine that also runs somebody else's VMs
   is not at risk from this code. A failure after the VM exists removes it BY ITS ID.

   The image is pinned by hash, checked on the host immediately before it is handed to the VM, and
   hashed AGAIN inside the script that defines the VM. A path is not an identity; two runs must be
   able to prove they booted the same bytes.
   ============================================================ */
import path from "node:path";
import { BOOT_STATEMENTS, bootFormOfStatement } from "../verify/boot-statements.mjs";
import fs from "node:fs";
import { runWmiserve, writeBundle, freePort, CERT_NAME } from "./wmiserve-run.mjs";
import { GCS_KEY, EGRESS_VSOCK_PORT } from "./egress.mjs";

/** The preflight check egress adds (egress.mjs): its hv_sock service is registered, read and never written. */
export const EGRESS_CHECK = "hv_sock egress service (vsock 9443) registered";
/** ...and the startup-package service (package-transport.mjs), read the same way when owner-committed startup is on. */
export const PACKAGE_CHECK = "hv_sock startup-package service (vsock 9446) registered";
/** ...and the custody-authorization service (custody-transport.mjs), read the same way when direct custody is on. */
export const CUSTODY_CHECK = "hv_sock custody-authorization service (vsock 9445) registered";
/** The name a deployment's domain may be certified for (M4): the first 8 hex of its id in the app zone, or null for a
 *  name that is not a deployment id (a lab label): such a domain gets no certificate endpoints at all. */
export function certNameFor(name) {
  const m = /^0x([0-9a-fA-F]{64})$/.exec(String(name ?? ""));
  if (!m) return null;
  const n = `${m[1].slice(0, 8).toLowerCase()}.app.enclave.host`;
  return CERT_NAME.test(n) ? n : null;
}

/*  THE VM MUST BE CREATED WITH A GUEST-STATE ISOLATION TYPE, or FirmwareFile is inert.
 *
 *  Measured on nucbox-k11 2026-09-24: a Generation 2 VM created WITHOUT a guest-state isolation type
 *  accepts a firmware file, reads it back, starts, and boots nothing - no paravisor, so nothing
 *  consumes the field. Created WITH one, the worker actually tries, and says what it wants
 *  (Worker-Admin event 5142):
 *      failed to load custom IGVM file because AllowFirmwareLoadFromFile registry key is not set
 *
 *  So the two are independent: the VM definition decides whether our image is CONSIDERED, the host
 *  registry value decides whether it is ALLOWED. New-CustomVM carries the type in the definition
 *  itself (GuestStateIsolationType 1); the registry value is the host's, and this file only reads it.
 */
/**
 * THE PARTITION KIND IS THE LAUNCHER'S TO STATE, NOT THE GUEST'S.
 *
 * The monitor stopped printing a fixed `partition=hcs-child` (enclave-5d, 4127789d) for the right
 * reason: a guest cannot know what kind of partition it is in. So whichever launcher started the
 * domain says so, and the two launchers must NOT say the same thing (enclave-99).
 *
 * TYPE 1 IS A CONFIGURATION, NOT A MEASUREMENT. The hypervisor is configured to keep VTL0 RAM
 * host-private on a VBS partition, and the guest reports `hv_isolation=vbs` - but no host-side read
 * has been shown to be refused (E3 NOT RUN) and no report chain is verified (E2 NOT complete). So
 * `hostExcluded` and `attested` stay false, exactly as the recipe's own boot prints them, and
 * nothing this launcher produces may be advertised as verified or host-excluded capacity.
 */
export const BOUNDARY = Object.freeze({
  tier: "T0-hv",
  partition: "wmi-openhcl-gen2",   // NOT "hcs-child": a different launcher, a different kind
  guestStateIsolationType: 1,      // VBS, as DEFINED and read back - a configuration, not a measurement
  hostExcluded: false,
  attested: false,
  note: "a Gen2 OpenHCL partition with GuestStateIsolationType 1 (VBS), defined through WMI. The hypervisor "
      + "is CONFIGURED to keep VTL0 RAM host-private; that is not a measurement. The host is NOT shown to be "
      + "excluded and no chain is verified: never advertise this as verified or host-excluded capacity.",
});

/**
 * THE BOOT FORM'S NAME: ONE per form, the SIGNED report's (enclave-99's contract, "Launcher statements" in
 * docs/security/nucbox-custom-vm-verifier.md, main ae6e9147). The Rust wmiserve signs `platform.partition` with these
 * names, so the manager states the same ones; `guestImageKind` rides beside it through this FIXED pairing, and a judge
 * compares BOTH for exact equality and refuses any other pairing or any unknown value (bootFormOfStatement).
 *
 * Neither is identity. Both are launcher statements (T0-hv, host_excluded=no): what a partition RAN is established only
 * by the paravisor report's launch digest against the pinned allowlist, never by a name, a kind or an argument. And a
 * uefi-medium partition never carries an isolation claim, because the medium is not measured.
 *
 * Keyed by the boot-form strings themselves (BOOT_UEFI, BOOT_LINUX_DIRECT below), so no forward reference is needed.
 */
// The table itself lives in verify/boot-statements.mjs, shared with judge-hv and the data plane; re-exported here so
// this module's API is unchanged.
export { BOOT_STATEMENTS, bootFormOfStatement };
/** The boundary word for one boot form: BOUNDARY with that form's canonical partition name. */
export function boundaryFor(boot) {
  const st = BOOT_STATEMENTS[boot];
  if (!st) throw new Error(`boundaryFor: unknown boot form ${JSON.stringify(boot)}`);
  return Object.freeze({ ...BOUNDARY, partition: st.partition });
}

/**
 * The image identity for a UEFI boot: the sha256 of the MEDIUM the launcher attached, hashed AT
 * ATTACH TIME.
 *
 * Not the UKI's hash, and this is a security property rather than a preference. With Secure Boot
 * off the pinned stub reads addons, credentials and extensions from the ESP, so TWO MEDIA CARRYING
 * THE SAME UKI CAN BOOT DIFFERENT COMMAND LINES. Only the medium hash separates them, so only the
 * medium hash can honestly answer "what booted". The UKI hash and the composition are published
 * BESIDE it, never in place of it.
 *
 * The HCS-only fields are deliberately absent: on this path there is no host-supplied kernel or
 * initrd file, and filling `kernelSha256`/`initrdSha256` would state an identity the boot never
 * used. (enclave-99's review; adopted in 5d's UEFI-BOOT.md.)
 */
export function uefiImageIdentity({ mediumSha256, mediumPath, ukiSha256 = null, composition = null }) {
  if (!/^[0-9a-f]{64}$/.test(String(mediumSha256 || "").toLowerCase()))
    throw new Error("the medium's sha256 is required, hashed at attach time: without it nothing says WHAT booted");
  const id = {
    partition: BOOT_STATEMENTS["uefi-medium"].partition,
    guestImageSha256: String(mediumSha256).toLowerCase(),
    guestImageKind: BOOT_STATEMENTS["uefi-medium"].guestImageKind,
    guestImagePath: mediumPath ?? null,
  };
  if (ukiSha256) id.ukiSha256 = String(ukiSha256).toLowerCase();   // beside, never instead
  if (composition) id.composition = composition;
  return Object.freeze(id);
}

/**
 * The identity for a LINUX-DIRECT boot: the IGVM's own pinned sha256, because there is no medium.
 *
 * The paravisor loads our kernel, initrd and VTL0 command line from INSIDE the IGVM, where they are
 * measured (the recipe's -LinuxDirect mode). So the IGVM is everything that booted - and it is NOT
 * a medium. Its hash is the handle's `image` (the same value wmiserve's signed report puts in
 * partition.guestImageSha256 under platform.partition "wmi-openhcl-gen2-igvm-linux"), and it is only ever
 * compared TOGETHER with the (partition, guestImageKind) statement (verify/boot-statements.mjs): judge-hv
 * and the data plane refuse the same 64 hex under the other partition or kind, and never compare an
 * image alone (enclave-d1 + enclave-99). A launcher statement, not identity: what ran is only the
 * paravisor report's launch digest against the pinned allowlist.
 */
export function linuxDirectIdentity({ igvmSha256, igvmPath = null }) {
  if (!/^[0-9a-f]{64}$/.test(String(igvmSha256 || "").toLowerCase()))
    throw new Error("the IGVM's sha256 is required: with no medium it is the only identity a linux-direct boot has");
  return Object.freeze({
    partition: BOOT_STATEMENTS["linux-direct"].partition,
    guestImageKind: BOOT_STATEMENTS["linux-direct"].guestImageKind,
    igvmSha256: String(igvmSha256).toLowerCase(),
    igvmPath: igvmPath ?? null,
  });
}

/** How the guest boots. STATED by whoever constructs the launcher, never inferred from what else is set. */
export const BOOT_UEFI = "uefi-medium";
/**
 * THE VM'S RAM, from the catalog policy's memMiB (the APP's share, fixed per version: DERIVE.md "enclave-isolation-policy/1").
 *
 * The policy is what the domain gets, not what the partition needs. The ported launcher gave the VM exactly the
 * policy's memMiB, so a real hello-world spawn (memMiB 128) would have defined a 128 MiB type-1 VM. The canaries never
 * hit that because they passed 2048 themselves.
 * The rule: guestd's (policy + 384 for the guest kernel and runtime) plus 256 for VTL2 and the paravisor, with a floor
 * of 2048 for general apps. At 2048 on nucbox-k11 the guest saw 1833 MiB, so VTL2 and the firmware took about
 * 215. Like memMiB on every backend, this is an availability property the host controls, never an attested one.
 */
export const TYPE1_VM_MEM_FLOOR_MIB = 2048;
export const TYPE1_VM_MEM_OVERHEAD_MIB = 384 + 256;
// Qualified separately on NucBox: fixed diagnostic bundle, no models/customer data.
// New witness identities keep the normal floor until independently qualified.
export const READINESS_WITNESS_APP_ID = 'a79db30fdf40b37499c8dbf955728c74541fa140201059158694c841736f5030';
export function type1VmMemMiB(policyMemMiB, {name, appId} = {}) {
  const p = policyMemMiB;   // a JSON number from the derivation record; a string is refused, never coerced
  if (typeof p !== "number" || !Number.isInteger(p) || p <= 0) throw new Error(`the policy's memMiB must be a positive integer, not ${JSON.stringify(policyMemMiB)}`);
  if (name === 'shield-readiness-v1' && appId === READINESS_WITNESS_APP_ID && p === 256) return 512;
  // Hyper-V rejects odd MiB quantities. Round only the physical partition up;
  // the app keeps its exact purchased allocation and immutable catalog policy.
  return Math.ceil(Math.max(TYPE1_VM_MEM_FLOOR_MIB, p + TYPE1_VM_MEM_OVERHEAD_MIB) / 2) * 2;
}

/** Our monitor's ready line on COM1 (what uefi-dev-boot.ps1 watches for). The console reader may stop there. */
export const GUEST_READY_LINE = "MON ready";
export const BOOT_LINUX_DIRECT = "linux-direct";
export const BOOT_FORMS = Object.freeze([BOOT_UEFI, BOOT_LINUX_DIRECT]);

export const GUEST_FEATURE_SET = 0x00000201;   // what New-CustomVM writes with a FirmwareFile; read back, never written here
/** petri's hyperv.psm1 as the recipe pinned it: the module that DEFINES the VM has more say than any file it loads. */
export const HYPERV_MODULE_SHA256 = "17ca4352c500d3498f71be420ddfa418c7ed1d1b5f455856c24e633a4635e49c";

/**
 * THE HOST'S OPT-IN TO CUSTOM FIRMWARE: REPORTED, NEVER SET, CHANGED OR REMOVED.
 *
 * Hyper-V refuses a custom IGVM unless HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
 * Virtualization\AllowFirmwareLoadFromFile is set (measured: Worker-Admin 5142, and the recipe's
 * inverse control a891dfae). The dev recipe applies it for one run and restores it. A production
 * manager must not do that: the value is host-wide and permits UNSIGNED guest firmware for every VM
 * on the host, and whether a production host keeps it set permanently is an OPEN OWNER DECISION.
 * So preflight reads it, `start` refuses without it and names it, and no script in this file writes
 * to that key (a test scans every generated script for exactly that).
 */
export const FIRMWARE_OPT_IN = Object.freeze({
  key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization",
  psPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization",
  value: "AllowFirmwareLoadFromFile",
  check: "AllowFirmwareLoadFromFile",
});

export const OWNER_MARKER = "enclave-vbslike-app-domain";
/** The production instance's VM name prefix; any other (ENCLAVE_VM_PREFIX) is a separately scoped second instance. */
export const DEFAULT_VM_PREFIX = "enclave-app-";
/** A second instance's prefix: "enclave-" + 1-16 lowercase letters/digits + "-", never the default. */
export const VM_PREFIX_RE = /^enclave-[a-z0-9]{1,16}-$/;
/*
 * THE VM CARRIES ITS OWN IDENTITY (63's P1). The manager used to hold every record in memory only,
 * so a restarted manager answered "absent" for a VM that was still running: the node then released
 * the lease and spawned a second VM for the same deployment. Hyper-V outlives this process, so the
 * identity is written where Hyper-V keeps it - the VM's Notes - and a restarted manager rebuilds its
 * inventory from there before it answers anything (server.mjs recover()).
 *
 *   Notes = "enclave-vbslike-app-domain/manager|" + base64url(JSON {v:1, id, name, instanceId, appId})
 *
 * The recipe sets the bare OWNER_MARKER; this sets notesFor(identity) in its place, so the marker
 * teardown filters on is still the prefix of what is written.
 *
 * A VM whose Notes are exactly OWNER_MARKER (older managers, the dev canary) is still OURS for
 * removal, but carries no identity: it is recovered as UNATTRIBUTED, and the manager refuses to
 * spawn while one exists rather than guess which deployment it belonged to.
 */
export const MANAGER_NOTES_PREFIX = OWNER_MARKER + "/manager|";
/**
 * THE OWNERSHIP MARKER OF AN INSTANCE, from its VM name prefix. The production (default) prefix keeps OWNER_MARKER, byte for
 * byte. Any other prefix (ENCLAVE_VM_PREFIX: a second, separately scoped instance such as a hardware canary) gets
 * "<prefix>vbslike-domain", which neither equals OWNER_MARKER nor starts with MANAGER_NOTES_PREFIX - so the production
 * manager, the installed one included (its survey, ownership check and parseNotes key on exactly those), never surveys,
 * adopts, starts or removes such a VM, and this instance never does any of that to production's.
 */
export function markerFor(prefix = DEFAULT_VM_PREFIX) {
  // only a valid SCOPED prefix (the only kind main.mjs starts with, besides the default) gets its own marker; any other
  // constructor prefix (test fixtures) keeps the production marker, exactly as before
  return prefix !== DEFAULT_VM_PREFIX && VM_PREFIX_RE.test(String(prefix)) ? `${prefix}vbslike-domain` : OWNER_MARKER;
}
export const notesPrefixFor = (marker = OWNER_MARKER) => marker + "/manager|";
export function notesFor({ id, name, instanceId, appId, imageRole = "legacy" }, { marker = OWNER_MARKER } = {}) {
  for (const [k, val] of Object.entries({ id, name, instanceId }))
    if (typeof val !== "string" || !val) throw new Error(`notesFor: ${k} must be a non-empty string`);
  if (!IMAGE_ROLES.includes(imageRole)) throw new Error(`notesFor: imageRole must be one of ${IMAGE_ROLES.join(", ")}`);
  // the image a VM was started from (F3): written for a non-legacy image only, so a legacy VM's Notes stay exactly as
  // before, and Notes without it mean "legacy" (every VM from before this change)
  return notesPrefixFor(marker) + Buffer.from(JSON.stringify({ v: 1, id, name, instanceId, appId: appId ?? null,
    ...(imageRole !== "legacy" ? { imageRole } : {}) })).toString("base64url");
}
/** The pinned images a partition may start from (F3, shield-profile.mjs ImageLauncher). */
export const IMAGE_ROLES = Object.freeze(["legacy", "shield-direct", "gpu"]);
/** -> { owned, identity }: owned means the ownership marker is present; identity only when it parses completely. */
export function parseNotes(notes, { marker = OWNER_MARKER } = {}) {
  const MANAGER_NOTES_PREFIX = notesPrefixFor(marker), OWNER_MARKER_ = marker;
  const t = String(notes ?? "");
  if (t.startsWith(MANAGER_NOTES_PREFIX)) {
    try {
      const o = JSON.parse(Buffer.from(t.slice(MANAGER_NOTES_PREFIX.length), "base64url").toString("utf8"));
      if (o && o.v === 1 && typeof o.id === "string" && o.id && typeof o.name === "string" && o.name
          && typeof o.instanceId === "string" && o.instanceId) return { owned: true, identity: o };
    } catch { /* owned, but the identity is unreadable: unattributed */ }
    return { owned: true, identity: null };
  }
  return { owned: t === OWNER_MARKER_, identity: null };
}
const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;

const ps = (s) => s.replace(/\r?\n\s*/g, " ").trim();
/** PowerShell: is VM expression `v` ours? The bare marker OR the manager's identity notes. */
const OWNED = (v, marker = OWNER_MARKER) => `(${v}.Notes -eq ${q(marker)} -or ([string]${v}.Notes).StartsWith(${q(notesPrefixFor(marker))}))`;
/**
 * Enumeration is only meaningful where `Get-VM` EXISTS. `Get-VM -ErrorAction SilentlyContinue` on a
 * host without the Hyper-V module yields nothing, which is indistinguishable from a host that owns
 * no VMs - so a survey read "no VMs" and a teardown read "found 0, removed 0, failed []", a CLEAN
 * teardown, on a host that cannot enumerate at all. Measured on nucbox-k11 before the role existed.
 * Reading a missing capability as an empty result is the same fail-open shape as a hash table that
 * verifies nothing and boots anyway; both say PASS while covering no mechanism. So the scripts
 * that enumerate for action REFUSE rather than report an empty success.
 */
const ENUMERABLE = ps(`if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { throw 'Get-VM is absent: the Hyper-V PowerShell module is not installed, so VMs cannot be enumerated - this host is UNENUMERABLE, not empty' };`);

/** PowerShell single-quoted literal: the only escape inside one is a doubled quote. */
export function q(v) { return "'" + String(v).replace(/'/g, "''") + "'"; }

/**
 * One sha256 helper per script that hashes several files: the define script is the longest this
 * manager sends, and -EncodedCommand must fit Windows' 32,767-char command line (a test holds it
 * under 28,000). Not named `H`: that is Get-History's alias, and an alias outranks a function.
 */
const SHA_OF = "function ShaOf($p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() };";

/**
 * Archive the per-run guest-state copy held in `$gsf`, verify the archive, then remove the copy.
 * ONLY ever emitted after the script has established that the VM which used it is gone: OpenHCL
 * writes the store during boot, and copying it while the worker holds it risks a torn read
 * (enclave-5d). Sets $rsha and $dest.
 */
const RETIRE = (archiveDir) => `
    $rsha = (ShaOf $gsf);
    $arch = ${q(archiveDir)};
    if (-not (Test-Path -LiteralPath $arch)) { New-Item -ItemType Directory -Path $arch -Force | Out-Null };
    $dest = Join-Path $arch ([System.IO.Path]::GetFileNameWithoutExtension($gsf) + '-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss-fff') + '.vmgs');
    Copy-Item -LiteralPath $gsf -Destination $dest;
    if ((ShaOf $dest) -ne $rsha) { throw ('the archived guest state at ' + $dest + ' does not hash to the run copy''s ' + $rsha + ': the run copy is kept') };
    Remove-Item -LiteralPath $gsf -Force;
    if (Test-Path -LiteralPath $gsf) { throw ('the run copy ' + $gsf + ' is still present after its removal') };`;

/* ---- the commands, as pure functions so a test can read them ---------------------------------- */

export const CMD = {
  /**
   * Is the role actually here, and is everything the type-1 definition needs on this host? Each
   * answer is a fact, not an inference. The firmware opt-in is READ with .NET's RegistryKey getters
   * and nothing else: this script never writes the registry.
   */
  preflight: ({ hypervModule = null, guestStateMaster = null, egressService = null, packageService = null, custodyService = null } = {}) => ps(`
    $r = [ordered]@{};
    $r.vmms = [bool](Get-Service vmms -ErrorAction SilentlyContinue);
    $r.namespace = [bool](Get-CimClass -Namespace 'root\\virtualization\\v2' -ClassName Msvm_VirtualSystemManagementService -ErrorAction SilentlyContinue);
    $r.module = [bool](Get-Command Get-VM -ErrorAction SilentlyContinue);
    $r.firmwareField = [bool]((Get-CimClass -Namespace 'root\\virtualization\\v2' -ClassName Msvm_VirtualSystemSettingData -ErrorAction SilentlyContinue).CimClassProperties.Name -contains 'FirmwareFile');
    $r.hypervisor = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent;
    $fo = @{present=$false; value=$null; kind=$null; error=$null};
    try {
      $k = Get-Item -LiteralPath ${q(FIRMWARE_OPT_IN.psPath)} -ErrorAction Stop;
      if ($k.GetValueNames() -contains ${q(FIRMWARE_OPT_IN.value)}) { $fo.present = $true; $fo.value = $k.GetValue(${q(FIRMWARE_OPT_IN.value)}); $fo.kind = [string]$k.GetValueKind(${q(FIRMWARE_OPT_IN.value)}) }
    } catch { $fo.error = [string]$_.Exception.Message };
    $r.firmwareOptIn = $fo;
    ${hypervModule ? `$hm = @{path=${q(hypervModule)}; present=[bool](Test-Path -LiteralPath ${q(hypervModule)}); sha256=$null};
    if ($hm.present) { $hm.sha256 = (Get-FileHash -LiteralPath ${q(hypervModule)} -Algorithm SHA256).Hash.ToLower() };
    $r.hypervModule = $hm;` : ""}
    ${guestStateMaster ? `$gm = @{path=${q(guestStateMaster)}; present=[bool](Test-Path -LiteralPath ${q(guestStateMaster)}); bytes=$null};
    if ($gm.present) { $gm.bytes = (Get-Item -LiteralPath ${q(guestStateMaster)}).Length };
    $r.guestStateMaster = $gm;` : ""}
    ${egressService ? `$r.egressService = [bool](Test-Path -LiteralPath ${q(`${GCS_KEY}\\${egressService}`)});` : ""}
    ${packageService ? `$r.packageService = [bool](Test-Path -LiteralPath ${q(`${GCS_KEY}\\${packageService}`)});` : ""}
    ${custodyService ? `$r.custodyService = [bool](Test-Path -LiteralPath ${q(`${GCS_KEY}\\${custodyService}`)});` : ""}
    $r | ConvertTo-Json -Compress -Depth 4`),

  /** The image, by hash, on the host that will load it. */
  imageHash: (path) => ps(`
    if (-not (Test-Path ${q(path)})) { @{present=$false} | ConvertTo-Json -Compress; exit 0 };
    @{present=$true; sha256=(Get-FileHash ${q(path)} -Algorithm SHA256).Hash.ToLower(); bytes=(Get-Item ${q(path)}).Length} | ConvertTo-Json -Compress`),

  /**
   * DEFINE THE TYPE-1 VM: uefi-dev-boot.ps1's `if ($IsolationType -eq 1)` branch, as one script
   * under a terminating-error policy that removes what it created if any step fails.
   *
   * In the recipe's order, with the reason for each:
   *  - hyperv.psm1 is hashed against its pin BEFORE it is imported: New-CustomVM has more say over
   *    what runs than any file it is handed. utilities.psm1, which that module imports from beside
   *    itself, is hashed and reported, and refused when a pin for it is configured (the recipe did
   *    not pin it).
   *  - the IGVM is hashed again here, at define time, not only by the earlier imageHash.
   *  - the guest state is a FRESH COPY of the master per run, compared to the master's hash: the
   *    store is written during boot, so a shared one makes every run start from a previous run's
   *    state. The master is never handed to a VM.
   *  - New-CustomVM with GuestStateIsolationEnabled/Type 1/Mode 0, the IGVM, the run copy,
   *    TpmEnabled, Secure Boot off, COM1, memory and vCPUs - in ONE DefineSystem, as petri does.
   *  - NO VTL2 trio (-IncreaseVtl2Memory): petri sets it only for non-isolated VMs, and the type-1
   *    image is fixed-GPA; asking it to auto-place VTL2 was the bare Worker 12030.
   *  - the Notes (our identity) go on FIRST, before anything else that can fail, so the VM is never
   *    one a marker-scoped teardown cannot see.
   *  - READ BACK: GuestStateIsolationType 1, enabled, GuestFeatureSet 0x201, VTL2 mode 0,
   *    FirmwareFile, and the guest-state file (the run copy, never the master). Any mismatch throws.
   *  - NICs removed, and the count read back as zero: this guest has no NIC.
   *  - Set-VMSecurity -VirtualizationBasedSecurityOptOut, read back. REQUIRED on this host: without it
   *    OpenHCL fails "cannot safely support VTL 1 without using the alias map". It declines Guest VSM
   *    (VTL1 INSIDE the guest), which our guest never uses; the partition's isolation is untouched.
   *  - icacls read grants for the VM's own SID on the IGVM (and the medium), exit codes checked: a VM
   *    that cannot read its firmware fails with no content at all.
   *  - uefi-medium: a SCSI controller (New-CustomVM makes none) and ONE DVD, hashed AT ATTACH TIME
   *    from the path the VM is actually pointed at, and set as the first boot device.
   *    linux-direct: nothing attached, and read back as no DVD and no disk.
   *  - COM1 to our named pipe, read back.
   *  - Secure Boot read back Off, one boot entry for uefi-medium, no LoadOptions on any entry.
   *  - the vTPM Windows makes for a VBS VM is READ and REPORTED, never refused and never called
   *    attestation: nothing on this path reads its PCRs.
   */
  defineType1: ({ name, memMiB, vcpus, notes, firmware, firmwareSha256, hypervModule, hypervModuleSha256, marker = OWNER_MARKER,
                  hypervUtilitiesSha256 = null, guestStateMaster, guestStateMasterSha256 = null, guestStateRun,
                  archiveDir, pipe, boot, medium = null, mediumSha256 = null }) => {
    if (!BOOT_FORMS.includes(boot)) throw new Error(`defineType1: boot must be one of ${BOOT_FORMS.join(", ")}, stated rather than inferred`);
    const uefi = boot === BOOT_UEFI;
    if (uefi && (!medium || !SHA256.test(String(mediumSha256 || "")))) throw new Error("defineType1: a uefi-medium boot needs the medium and its sha256");
    if (!uefi && (medium || mediumSha256)) throw new Error("defineType1: a linux-direct boot attaches no medium");
    for (const [k, val] of Object.entries({ name, notes, firmware, hypervModule, guestStateMaster, guestStateRun, archiveDir, pipe }))
      if (typeof val !== "string" || !val) throw new Error(`defineType1: ${k} is required`);
    for (const [k, val] of Object.entries({ firmwareSha256, hypervModuleSha256 }))
      if (!SHA256.test(String(val || ""))) throw new Error(`defineType1: ${k} must be a lowercase sha256`);
    const mem = Math.round(memMiB), vp = Math.max(1, Math.floor(vcpus));
    return ps(`
    ${ENUMERABLE}
    $ErrorActionPreference = 'Stop'; ${SHA_OF}
    $name = ${q(name)}; $gsf = ${q(guestStateRun)}; $fw = ${q(firmware)}; $pipe = ${q(pipe)};
    $vm = $null; $copied = $false;
    if (@(Get-VM -Name $name -EA SilentlyContinue).Count) { throw ('a VM named ' + $name + ' already exists: refusing to define a second one under the same name') };
    if (Test-Path -LiteralPath $gsf) { throw ('a guest-state run copy already exists at ' + $gsf + ': refusing to overwrite a previous run''s store') };
    try {
      $mod = ${q(hypervModule)}; $pin = ${q(hypervModuleSha256)};
      $modSha = (ShaOf $mod);
      if ($modSha -ne $pin) { throw ('the module that DEFINES the VM hashes ' + $modSha + ', not the pinned ' + $pin) };
      $utl = Join-Path (Split-Path -Parent $mod) 'utilities.psm1';
      $utlSha = $null;
      if (Test-Path -LiteralPath $utl) { $utlSha = (ShaOf $utl) };
      ${hypervUtilitiesSha256 ? `$pin = ${q(hypervUtilitiesSha256)}; if ($utlSha -ne $pin) { throw ('utilities.psm1, which New-CustomVM imports, hashes ' + [string]$utlSha + ', not the pinned ' + $pin) };` : ""}
      Import-Module $mod -Force;
      if (-not (Get-Command New-CustomVM -EA SilentlyContinue)) { throw ('New-CustomVM is not defined after importing ' + $mod) };
      $pin = ${q(firmwareSha256)};
      $fwSha = (ShaOf $fw);
      if ($fwSha -ne $pin) { throw ('the IGVM hashes ' + $fwSha + ' at define time, not the pinned ' + $pin) };
      $master = ${q(guestStateMaster)};
      $masterSha = (ShaOf $master);
      ${guestStateMasterSha256 ? `$pin = ${q(guestStateMasterSha256)}; if ($masterSha -ne $pin) { throw ('the guest-state master hashes ' + $masterSha + ', not the pinned ' + $pin) };` : ""}
      Copy-Item -LiteralPath $master -Destination $gsf; $copied = $true;
      $copySha = (ShaOf $gsf);
      if ($copySha -ne $masterSha) { throw ('the guest-state copy hashes ' + $copySha + ', not the master''s ' + $masterSha) };
      $ret = @(New-CustomVM -VMName $name -GuestStateIsolationEnabled $true -GuestStateIsolationType 1 -GuestStateIsolationMode 0 -FirmwareFile $fw -GuestStateFilePath $gsf -TpmEnabled $true -SecureBootEnabled $false -Com1 $true -Memory (${mem} * 1MB) -VpCount ${vp});
      $found = @(Get-VM -Name $name -EA SilentlyContinue);
      if ($found.Count -ne 1) { throw ('after New-CustomVM ' + $found.Count + ' VMs are named ' + $name + ', not exactly one') };
      $vm = $found[0];
      $retId = [string]($ret | Select-Object -Last 1);
      if (($retId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') -and ($retId -ne $vm.Id.Guid)) { throw ('New-CustomVM returned ' + $retId + ' but the VM named ' + $name + ' has Id ' + $vm.Id.Guid) };
      Set-VM -VM $vm -Notes ${q(notes)};
      Set-VM -VM $vm -AutomaticStartAction Nothing -AutomaticStopAction TurnOff;
      $ns = 'root\\virtualization\\v2';
      $csq = "select * from Msvm_ComputerSystem where Name = '" + $vm.Id.Guid + "'";
      $vssd = Get-CimInstance -Namespace $ns -Query $csq | Get-CimAssociatedInstance -ResultClass Msvm_VirtualSystemSettingData -Association Msvm_SettingsDefineState;
      if (-not $vssd) { throw ('no Msvm_VirtualSystemSettingData for ' + $vm.Id.Guid) };
      if ([int]$vssd.GuestStateIsolationType -ne 1) { throw ('GuestStateIsolationType reads back as ' + [string]$vssd.GuestStateIsolationType + ', not 1') };
      if (-not [bool]$vssd.GuestStateIsolationEnabled) { throw 'GuestStateIsolationEnabled reads back False' };
      if ([int64]$vssd.GuestFeatureSet -ne ${GUEST_FEATURE_SET}) { throw ('GuestFeatureSet reads back as 0x' + ('{0:x}' -f [int64]$vssd.GuestFeatureSet) + ', not 0x201') };
      if ([int]$vssd.Vtl2AddressSpaceConfigurationMode -ne 0) { throw ('Vtl2AddressSpaceConfigurationMode reads back as ' + [string]$vssd.Vtl2AddressSpaceConfigurationMode + ': VTL2 auto placement on a fixed-GPA type-1 image') };
      if ([string]$vssd.FirmwareFile -ne $fw) { throw ('FirmwareFile reads back as ' + [string]$vssd.FirmwareFile + ', not ' + $fw) };
      $gsfBack = [System.IO.Path]::GetFullPath((Join-Path ([string]$vssd.GuestStateDataRoot) ([string]$vssd.GuestStateFile)));
      if ($gsfBack -ne [System.IO.Path]::GetFullPath($gsf)) { throw ('the VM''s guest state reads back as ' + $gsfBack + ', not the per-run copy ' + $gsf) };
      $nics = @(Get-VMNetworkAdapter -VM $vm -EA SilentlyContinue);
      if ($nics.Count) { $nics | Remove-VMNetworkAdapter -Confirm:$false };
      $nicsAfter = @(Get-VMNetworkAdapter -VM $vm -EA SilentlyContinue).Count;
      if ($nicsAfter -ne 0) { throw ([string]$nicsAfter + ' network adapter(s) remain: this guest has no NIC') };
      Set-VMSecurity -VM $vm -VirtualizationBasedSecurityOptOut $true -EA Stop;
      $sec = $vssd | Get-CimAssociatedInstance -ResultClassName Msvm_SecuritySettingData;
      if (-not $sec) { throw 'no Msvm_SecuritySettingData on a type-1 VM: Windows makes a vTPM for a VBS VM, so this VM is not what it should be' };
      if (-not [bool]$sec.VirtualizationBasedSecurityOptOut) { throw 'VirtualizationBasedSecurityOptOut reads back False: the guest VBS opt-out did not take' };
      $grant = 'NT VIRTUAL MACHINE\\' + $vm.Id.Guid + ':R';
      $grants = @();
      ${uefi ? `$medium = ${q(medium)};` : ""}
      foreach ($gp in @($fw${uefi ? ", $medium" : ""})) {
        & icacls $gp /grant $grant | Out-Null;
        if ($LASTEXITCODE -ne 0) { throw ('icacls could not grant the VM read access to ' + $gp + ' (exit ' + $LASTEXITCODE + ')') };
        $grants += $gp
      };
      $mediumPath = $null; $mediumSha = $null;
      ${uefi ? `$mediumWant = ${q(mediumSha256)};
      if (-not (Get-VMScsiController -VM $vm -EA SilentlyContinue)) { Add-VMScsiController -VM $vm };
      Add-VMDvdDrive -VM $vm -Path $medium;
      $dvds = @(Get-VMDvdDrive -VM $vm);
      if ($dvds.Count -ne 1) { throw ([string]$dvds.Count + ' DVD drives after attaching the medium, not exactly one') };
      $mediumPath = [string]$dvds[0].Path;
      $mediumSha = (ShaOf $mediumPath);
      if ($mediumSha -ne $mediumWant) { throw ('the attached medium hashes ' + $mediumSha + ', not the pinned ' + $mediumWant) };
      Set-VMFirmware -VM $vm -FirstBootDevice $dvds[0];` : `if (@(Get-VMDvdDrive -VM $vm -EA SilentlyContinue).Count -ne 0) { throw 'linux-direct: a DVD drive is defined, and no medium may be attached' };`}
      $dvdCount = @(Get-VMDvdDrive -VM $vm -EA SilentlyContinue).Count;
      $diskCount = @(Get-VMHardDiskDrive -VM $vm -EA SilentlyContinue).Count;
      if ($diskCount -ne 0) { throw ([string]$diskCount + ' hard disk(s) are defined: this definition attaches none') };
      Set-VMComPort -VM $vm -Number 1 -Path $pipe;
      $com1 = [string](Get-VMComPort -VM $vm -Number 1).Path;
      if ($com1 -ne $pipe) { throw ('COM1 reads back as ' + $com1 + ', not ' + $pipe) };
      $fwc = Get-VMFirmware -VM $vm;
      if ([string]$fwc.SecureBoot -ne 'Off') { throw ('Secure Boot reads back ' + [string]$fwc.SecureBoot + ', not Off') };
      $boot = @($fwc.BootOrder);
      ${uefi ? `if ($boot.Count -ne 1) { throw ('the VM has ' + $boot.Count + ' boot entries; exactly one (the DVD) is expected') };` : ""}
      foreach ($e in $boot) { if ($e.Device) { $lo = $e.Device.PSObject.Properties['LoadOptions']; if ($lo -and $lo.Value) { throw ('a boot entry carries LoadOptions: ' + [string]$lo.Value) } } };
      $v2 = Get-VM -Id $vm.Id;
      @{id=$v2.Id.Guid; name=$v2.Name; version=[string]$v2.Version; notes=[string]$v2.Notes;
        isolationType=[int]$vssd.GuestStateIsolationType; isolationEnabled=[bool]$vssd.GuestStateIsolationEnabled;
        featureSet=[int64]$vssd.GuestFeatureSet; vtl2Mode=[int]$vssd.Vtl2AddressSpaceConfigurationMode;
        firmwareFile=[string]$vssd.FirmwareFile; firmwareSha256=$fwSha; hypervModuleSha256=$modSha; hypervUtilitiesSha256=$utlSha;
        guestStateFile=$gsfBack; guestStateMasterSha256=$masterSha;
        vbsOptOut=[bool]$sec.VirtualizationBasedSecurityOptOut; tpmEnabled=[bool]$sec.TpmEnabled;
        nics=$nicsAfter; dvds=$dvdCount; disks=$diskCount; mediumPath=$mediumPath; mediumSha256=$mediumSha;
        bootEntries=$boot.Count; secureBoot=[string]$fwc.SecureBoot; com1=$com1;
        vcpus=[int]$v2.ProcessorCount; memBytes=[int64]$v2.MemoryStartup; dynamicMemory=[bool]$v2.DynamicMemoryEnabled;
        automaticStartAction=[string]$v2.AutomaticStartAction; automaticStopAction=[string]$v2.AutomaticStopAction;
        grants=@($grants)} | ConvertTo-Json -Compress -Depth 4
    } catch {
      $err = $_;
      $victims = @();
      if ($vm) { $victims = @($vm) } else { $victims = @(Get-VM -Name $name -EA SilentlyContinue | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.Notes) -or ${OWNED("$_", marker)} }) };
      foreach ($v in $victims) { try { Stop-VM -VM $v -TurnOff -Force -EA SilentlyContinue; Remove-VM -VM $v -Force -EA Stop } catch {} };
      if ($copied -and (@(Get-VM -Name $name -EA SilentlyContinue).Count -eq 0) -and (Test-Path -LiteralPath $gsf)) { try { ${RETIRE(archiveDir)} } catch {} };
      throw $err
    }`);
  },

  /**
   * Start ONE VM, by its Id, only if it carries our marker. A refusal carries the Worker-Admin events
   * from the moment it was asked, because on this host that is where the reason is (5142 for a missing
   * firmware opt-in, 12030 for a definition the worker will not start): the recipe's FIRST OBSERVABLE.
   */
  start: ({ vmId, marker = OWNER_MARKER }) => {
    if (!GUID.test(String(vmId))) throw new Error(`start: not a VM Id: ${vmId}`);
    return ps(`
    $ErrorActionPreference = 'Stop';
    $v = Get-VM -Id ${q(vmId)};
    if (-not ${OWNED("$v", marker)}) { throw 'not ours: the ownership marker is absent, so this VM is not started' };
    $t0 = Get-Date;
    try { Start-VM -VM $v -ErrorAction Stop } catch {
      $msg = 'Start-VM refused: ' + [string]$_.Exception.Message;
      $ev = @(Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Worker-Admin' -MaxEvents 20 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $t0.AddSeconds(-5) } | Sort-Object TimeCreated | ForEach-Object { '[' + $_.Id + '] ' + ([string]$_.Message -replace '\\r?\\n', ' ') });
      if ($ev.Count) { $msg += ' | Worker-Admin: ' + ($ev -join ' | ') };
      throw $msg
    };
    @{state=[string](Get-VM -Id ${q(vmId)}).State} | ConvertTo-Json -Compress`);
  },

  /**
   * Did the GUEST say anything, within a bound this function itself keeps?
   *
   * The first version opened the pipe with [IO.File]::Open and called a SYNCHRONOUS Read in a loop,
   * which blocks past any deadline on an idle pipe. The second connected with a timeout and read with
   * ReadAsync - but on a pipe opened WITHOUT PipeOptions.Asynchronous, .NET Framework turns ReadAsync
   * into a blocking read on a thread that ignores the token, and the loop issued a NEW ReadAsync after
   * every 500 ms wait, overlapping reads on one stream (enclave-53 found this in the recipe's reader,
   * which this one shared). So: Asynchronous, and at most ONE read pending, carried across waits.
   *
   * It reports BYTES, and says nothing about what they mean. Firmware banners are bytes.
   *
   * `until`: a line the reader may STOP at, so a start does not always wait the whole window (it took 46 s at
   * 40 s on nucbox-k11, runs 070935/071140, though the guest spoke within ~3 s). Seeing it only shortens the wait
   * and is reported as `sawUntil`; it is not a readiness judgement, and bytes > 0 is still all "booted" means.
   */
  /**
   * START THE VM AND READ ITS CONSOLE IN ONE PROCESS (the manager's start path).
   *
   * The monitor prints its boot lines ONCE, about 3 s after Start-VM. A reader started afterwards in a NEW PowerShell
   * process can attach after they are gone, and a silent partition is refused. That happened to every manager spawn
   * on nucbox-k11 (runs 075126 and 075544: "no output ... within 25s", although the guest had written its guest
   * state). A canary whose reader was delayed 4 s failed the same way (ca265b7d). So the reader begins connecting
   * BEFORE Start-VM, on a thread-pool task (ConnectAsync), and attaches as soon as the worker creates the pipe. If that
   * early attach is not possible, it retries in this same process straight after Start-VM (uefi-dev-boot.ps1's
   * order). Everything after that is readConsole's loop: one pending read, bounded, stopping at `until`.
   */
  startAndRead: ({ vmId, pipe, seconds = 25, connectMs = 15000, until = null, marker = OWNER_MARKER }) => {
    if (!GUID.test(String(vmId))) throw new Error(`startAndRead: not a VM Id: ${vmId}`);
    return ps(`
    $ErrorActionPreference = 'Stop';
    $v = Get-VM -Id ${q(vmId)};
    if (-not ${OWNED("$v", marker)}) { throw 'not ours: the ownership marker is absent, so this VM is not started' };
    $until = ${until ? q(until) : "$null"}; $tail = ''; $sawUntil = $false;
    $name = ${q(pipe)} -replace '^\\\\\\\\\.\\\\pipe\\\\', '';
    $total = 0; $head = ''; $connected = $false; $why = ''; $early = $false; $earlyNote = ''; $attachMs = -1;
    $pd = [System.IO.Pipes.PipeDirection]::In; $po = [System.IO.Pipes.PipeOptions]::Asynchronous;
    $cli = New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, $pd, $po);
    $pre = $null; try { $pre = $cli.ConnectAsync(${Math.max(1000, Math.floor(connectMs))}) } catch { $earlyNote = [string]$_.Exception.Message };
    $t0 = Get-Date;
    try { Start-VM -VM $v -ErrorAction Stop } catch {
      if ($cli) { try { $cli.Dispose() } catch {} };
      $msg = 'Start-VM refused: ' + [string]$_.Exception.Message;
      $ev = @(Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Worker-Admin' -MaxEvents 20 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $t0.AddSeconds(-5) } | Sort-Object TimeCreated | ForEach-Object { '[' + $_.Id + '] ' + ([string]$_.Message -replace '\\r?\\n', ' ') });
      if ($ev.Count) { $msg += ' | Worker-Admin: ' + ($ev -join ' | ') };
      throw $msg
    };
    $state = [string](Get-VM -Id ${q(vmId)}).State;
    try { if ($pre -and $pre.Wait(${Math.max(1000, Math.floor(connectMs))}) -and $cli.IsConnected) { $connected = $true; $early = $true } } catch { $earlyNote = [string]$_.Exception.Message };
    if (-not $connected) {
      try { $cli.Dispose() } catch {};
      $cli = New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, $pd, $po);
      $dl = (Get-Date).AddMilliseconds(${Math.max(1000, Math.floor(connectMs))});
      while (-not $connected -and (Get-Date) -lt $dl) { try { $cli.Connect(100); $connected = $true } catch { Start-Sleep -Milliseconds 20 } }
    };
    $attachMs = [int]((Get-Date) - $t0).TotalMilliseconds;
    $cts = New-Object System.Threading.CancellationTokenSource;
    $cts.CancelAfter(${Math.max(1, Math.floor(seconds))} * 1000);
    $pending = $null;
    try {
      if ($connected) {
        $buf = New-Object byte[] 4096;
        while (-not $cts.IsCancellationRequested) {
          if ($null -eq $pending) { $pending = $cli.ReadAsync($buf, 0, $buf.Length) };
          if (-not $pending.Wait(500)) { continue };
          $n = $pending.Result; $pending = $null;
          if ($n -le 0) { break };
          $total += $n;
          if ($head.Length -lt 400) { $head += [Text.Encoding]::ASCII.GetString($buf, 0, [Math]::Min($n, 400)) };
          if ($until) {
            $tail += [Text.Encoding]::ASCII.GetString($buf, 0, $n);
            if ($tail.Length -gt 4096) { $tail = $tail.Substring($tail.Length - 4096) };
            if ($tail.Contains($until)) { $sawUntil = $true; break }
          }
        }
      } else { $why = 'the console pipe could not be attached' }
    } catch { $why = [string]$_.Exception.Message } finally {
      if ($cli) { try { $cli.Dispose() } catch {} };
      $cts.Dispose()
    };
    @{state=$state; console=@{connected=$connected; early=$early; earlyNote=$earlyNote; attachMs=$attachMs; bytes=$total; head=$head; sawUntil=$sawUntil; note=$why}} | ConvertTo-Json -Compress -Depth 4`);
  },

  readConsole: ({ pipe, seconds = 20, connectMs = 5000, until = null }) => ps(`
    $ErrorActionPreference = 'Stop';
    $until = ${until ? q(until) : "$null"}; $tail = ''; $sawUntil = $false;
    $name = ${q(pipe)} -replace '^\\\\\\\\\.\\\\pipe\\\\', '';
    $total = 0; $head = ''; $connected = $false; $why = '';
    $cts = New-Object System.Threading.CancellationTokenSource;
    $cts.CancelAfter(${Math.max(1, Math.floor(seconds))} * 1000);
    $cli = $null; $pending = $null;
    try {
      $cli = New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, [System.IO.Pipes.PipeDirection]::In, [System.IO.Pipes.PipeOptions]::Asynchronous);
      $cli.Connect(${Math.max(250, Math.floor(connectMs))});
      $connected = $true;
      $buf = New-Object byte[] 4096;
      while (-not $cts.IsCancellationRequested) {
        if ($null -eq $pending) { $pending = $cli.ReadAsync($buf, 0, $buf.Length) };
        if (-not $pending.Wait(500)) { continue };
        $n = $pending.Result; $pending = $null;
        if ($n -le 0) { break };
        $total += $n;
        if ($head.Length -lt 400) { $head += [Text.Encoding]::ASCII.GetString($buf, 0, [Math]::Min($n, 400)) };
        if ($until) {
          $tail += [Text.Encoding]::ASCII.GetString($buf, 0, $n);
          if ($tail.Length -gt 4096) { $tail = $tail.Substring($tail.Length - 4096) };
          if ($tail.Contains($until)) { $sawUntil = $true; break }
        }
      }
    } catch { $why = [string]$_.Exception.Message } finally {
      if ($cli) { try { $cli.Dispose() } catch {} };
      $cts.Dispose()
    };
    @{connected=$connected; bytes=$total; head=$head; sawUntil=$sawUntil; note=$why} | ConvertTo-Json -Compress`),

  state: ({ name }) => ps(`$v = Get-VM -Name ${q(name)} -ErrorAction SilentlyContinue; if ($v) { @{found=$true; state=[string]$v.State; uptime=[string]$v.Uptime} | ConvertTo-Json -Compress } else { @{found=$false} | ConvertTo-Json -Compress }`),

  /** Stop, and report a failure AS one: SilentlyContinue used to answer ok whatever happened. */
  stop: ({ name }) => ps(`
    try { Stop-VM -Name ${q(name)} -TurnOff -Force -ErrorAction Stop; @{ok=$true} | ConvertTo-Json -Compress }
    catch {
      $v = Get-VM -Name ${q(name)} -ErrorAction SilentlyContinue;
      if (-not $v) { @{ok=$true; note='already gone'} | ConvertTo-Json -Compress }
      else { @{ok=$false; state=[string]$v.State; error=[string]$_.Exception.Message} | ConvertTo-Json -Compress }
    }`),

  /** Remove ONE VM by EXACT name. The failure path must never match by prefix. */
  removeExact: ({ name, requireMarker = true, marker = OWNER_MARKER }) => ps(`
    $v = Get-VM -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq ${q(name)}${requireMarker ? ` -and ${OWNED("$_", marker)}` : ""} };
    if (-not $v) { @{found=$false; removed=$false} | ConvertTo-Json -Compress; exit 0 };
    try {
      Stop-VM -VM $v -TurnOff -Force -ErrorAction SilentlyContinue;
      Remove-VM -VM $v -Force -ErrorAction Stop;
      @{found=$true; removed=$true} | ConvertTo-Json -Compress
    } catch { @{found=$true; removed=$false; error=[string]$_.Exception.Message} | ConvertTo-Json -Compress }`),

  /**
   * Remove ONLY what this owns. Scoped by the instance prefix, and by the marker when it is there -
   * a VM that failed before its Notes were set still starts with the prefix, and leaving it behind
   * because the marker is missing is how an orphan becomes permanent. Failures are REPORTED, not
   * swallowed: a teardown that could not remove something must not read as a clean one.
   */
  teardown: ({ prefix, requireMarker = false, marker = OWNER_MARKER }) => ps(`
    ${ENUMERABLE}
    $vms = @(Get-VM | Where-Object { $_.Name.StartsWith(${q(prefix)})${requireMarker ? ` -and ${OWNED("$_", marker)}` : ""} });
    $removed = @(); $failed = @();
    foreach ($v in $vms) {
      try {
        Stop-VM -VM $v -TurnOff -Force -ErrorAction SilentlyContinue;
        Remove-VM -VM $v -Force -ErrorAction Stop;
        $removed += $v.Name
      } catch { $failed += @{name=$v.Name; error=[string]$_.Exception.Message} }
    };
    @{found=$vms.Count; removed=@($removed); failed=@($failed)} | ConvertTo-Json -Compress -Depth 4`),

  /**
   * Everything this instance owns, whether or not we think we started it: the reconciliation read. Its own name prefix,
   * or its own manager Notes (a VM renamed by hand). Both are the instance's: the default (production) instance's script is
   * byte for byte what it always was, and a scoped instance (ENCLAVE_VM_PREFIX, its own marker: markerFor) never matches
   * production's names or Notes - nor production its.
   */
  survey: ({ prefix, marker = OWNER_MARKER }) => ps(`
    ${ENUMERABLE}
    $vms = @(Get-VM | Where-Object { $_.Name.StartsWith(${q(prefix)}) -or ([string]$_.Notes).StartsWith(${q(notesPrefixFor(marker))}) });
    @{vms=@($vms | ForEach-Object { @{vmId=$_.Id.Guid; name=$_.Name; state=[string]$_.State; notes=[string]$_.Notes} })} | ConvertTo-Json -Compress -Depth 4`),

  /**
   * Stop and REMOVE one VM by its Id (63's P2). Names are not unique in Hyper-V, so acting by name
   * could stop somebody else's VM of the same name. The ownership marker is checked on the VM the Id
   * resolves to before anything is done to it. Waits for Off before Remove-VM, because removing a VM
   * that is still stopping throws InvalidState (measured on nucbox-k11 in uefi-dev-boot.ps1).
   */
  removeById: ({ vmId, marker = OWNER_MARKER }) => ps(`
    ${ENUMERABLE}
    $v = $null; try { $v = Get-VM -Id ${q(vmId)} -ErrorAction Stop } catch { $v = $null };
    if (-not $v) { @{found=$false; removed=$false} | ConvertTo-Json -Compress; exit 0 };
    if (-not ${OWNED("$v", marker)}) { @{found=$true; removed=$false; error='not ours: the ownership marker is absent'} | ConvertTo-Json -Compress; exit 0 };
    try {
      Stop-VM -VM $v -TurnOff -Force -ErrorAction SilentlyContinue;
      $dl = (Get-Date).AddSeconds(20);
      while ((Get-Date) -lt $dl -and [string](Get-VM -Id ${q(vmId)} -ErrorAction SilentlyContinue).State -ne 'Off') { Start-Sleep -Milliseconds 500 };
      $last = '';
      for ($a = 0; $a -lt 5; $a++) {
        $now = Get-VM -Id ${q(vmId)} -ErrorAction SilentlyContinue;
        if (-not $now) { break };
        try { Remove-VM -VM $now -Force -ErrorAction Stop } catch { $last = [string]$_.Exception.Message; Start-Sleep -Seconds 2 }
      };
      if (Get-VM -Id ${q(vmId)} -ErrorAction SilentlyContinue) { @{found=$true; removed=$false; error=('still present after removal: ' + $last)} | ConvertTo-Json -Compress }
      else { @{found=$true; removed=$true} | ConvertTo-Json -Compress }
    } catch { @{found=$true; removed=$false; error=[string]$_.Exception.Message} | ConvertTo-Json -Compress }`),

  /**
   * ARCHIVE AND REMOVE a per-run guest-state copy, once the VM that used it is GONE.
   *
   * Refuses anything that is not a .vmgs under the run directory, refuses the MASTER by name, and
   * refuses while a VM of that Id (or that name) still exists - the worker may be holding the file.
   * The archive is hashed against the copy before the copy is deleted.
   */
  retireGuestState: ({ path: gsPath, runDir, master = null, archiveDir, vmId = null, name = null }) => {
    if (vmId && !GUID.test(String(vmId))) throw new Error(`retireGuestState: not a VM Id: ${vmId}`);
    if (!vmId && !name) throw new Error("retireGuestState: a VM Id or name is required, to establish that its VM is gone");
    for (const [k, val] of Object.entries({ gsPath, runDir, archiveDir }))
      if (typeof val !== "string" || !val) throw new Error(`retireGuestState: ${k} is required`);
    return ps(`
    ${ENUMERABLE}
    $ErrorActionPreference = 'Stop'; ${SHA_OF}
    $gsf = [System.IO.Path]::GetFullPath(${q(gsPath)});
    $dir = [System.IO.Path]::GetFullPath(${q(runDir)}).TrimEnd('\\') + '\\';
    if (-not $gsf.StartsWith($dir, [System.StringComparison]::OrdinalIgnoreCase)) { throw ('refusing to retire ' + $gsf + ': it is not under the run directory ' + $dir) };
    if (-not $gsf.EndsWith('.vmgs', [System.StringComparison]::OrdinalIgnoreCase)) { throw ('refusing to retire ' + $gsf + ': it is not a .vmgs') };
    ${master ? `if ($gsf -eq [System.IO.Path]::GetFullPath(${q(master)})) { throw ('refusing to retire ' + $gsf + ': it is the MASTER, an input that is never handed to a VM') };` : ""}
    ${vmId ? `$still = $null; try { $still = Get-VM -Id ${q(vmId)} -EA Stop } catch { $still = $null };
    if ($still) { throw ('VM ' + ${q(vmId)} + ' is still present: its guest state is not retired while the worker may hold it') };` : ""}
    ${name ? `if (@(Get-VM -Name ${q(name)} -EA SilentlyContinue).Count) { throw ('a VM named ' + ${q(name)} + ' is still present: its guest state is not retired while the worker may hold it') };` : ""}
    if (-not (Test-Path -LiteralPath $gsf)) { @{present=$false; retired=$false; path=$gsf} | ConvertTo-Json -Compress; exit 0 };
    ${RETIRE(archiveDir)}
    @{present=$true; retired=$true; path=$gsf; sha256=$rsha; archive=$dest} | ConvertTo-Json -Compress`);
  },
};

function parse(out) {
  const t = String(out ?? "").trim();
  if (!t) throw new Error("no output from PowerShell");
  try { return JSON.parse(t); } catch { throw new Error(`PowerShell output is not JSON: ${t.slice(0, 160)}`); }
}
const lc = (s) => String(s ?? "").toLowerCase();

/**
 * THE READ-BACK, asserted again on this side of the process boundary. The define script throws on
 * each of these itself; this is the second statement of the same contract, over the values it
 * returned, so a script that returned without checking (or a host that answered oddly) is still
 * refused - and so the contract can be tested without a host.
 */
export function checkDefinition(d, want) {
  const fail = (m) => { throw new Error(`the type-1 definition does not read back as asked: ${m}`); };
  if (!d || !GUID.test(String(d.id || ""))) fail(`no VM Id came back (${JSON.stringify(d ? d.id ?? null : null)})`);
  if (d.notes !== want.notes) fail("the Notes do not carry this domain's identity marker");
  if (Number(d.isolationType) !== 1) fail(`GuestStateIsolationType is ${JSON.stringify(d.isolationType ?? null)}, not 1`);
  if (d.isolationEnabled !== true) fail("GuestStateIsolationEnabled is not True");
  if (Number(d.featureSet) !== GUEST_FEATURE_SET) fail(`GuestFeatureSet is ${JSON.stringify(d.featureSet ?? null)}, not ${GUEST_FEATURE_SET} (0x201)`);
  if (Number(d.vtl2Mode) !== 0) fail(`Vtl2AddressSpaceConfigurationMode is ${JSON.stringify(d.vtl2Mode ?? null)}: VTL2 auto placement must not be set on type 1`);
  if (lc(d.firmwareFile) !== lc(want.firmware)) fail(`FirmwareFile is ${JSON.stringify(d.firmwareFile ?? null)}, not the pinned IGVM`);
  if (lc(d.firmwareSha256) !== lc(want.firmwareSha256)) fail(`the IGVM hashed ${JSON.stringify(d.firmwareSha256 ?? null)} at define time`);
  if (lc(d.hypervModuleSha256) !== lc(want.hypervModuleSha256)) fail("hyperv.psm1 did not hash to its pin");
  if (want.hypervUtilitiesSha256 && lc(d.hypervUtilitiesSha256) !== lc(want.hypervUtilitiesSha256)) fail("utilities.psm1 did not hash to its pin");
  if (lc(d.guestStateFile) !== lc(want.guestStateRun)) fail(`the guest state is ${JSON.stringify(d.guestStateFile ?? null)}, not this run's copy`);
  if (lc(d.guestStateFile) === lc(want.guestStateMaster)) fail("the VM was handed the MASTER guest state");
  if (d.vbsOptOut !== true) fail("VirtualizationBasedSecurityOptOut is not True");
  if (Number(d.nics) !== 0) fail(`${d.nics} network adapter(s) remain`);
  if (lc(d.com1) !== lc(want.pipe)) fail(`COM1 is ${JSON.stringify(d.com1 ?? null)}, not ${want.pipe}`);
  if (d.secureBoot !== "Off") fail(`Secure Boot is ${JSON.stringify(d.secureBoot ?? null)}, not Off`);
  if (Number(d.disks) !== 0) fail(`${d.disks} hard disk(s) are defined`);
  if (want.boot === BOOT_UEFI) {
    if (Number(d.dvds) !== 1) fail(`${d.dvds} DVD drive(s), not exactly the one medium`);
    if (Number(d.bootEntries) !== 1) fail(`${d.bootEntries} boot entries, not exactly the one medium`);
    if (lc(d.mediumSha256) !== lc(want.mediumSha256)) fail(`the attached medium hashed ${JSON.stringify(d.mediumSha256 ?? null)} at attach time`);
  } else {
    if (Number(d.dvds) !== 0) fail(`linux-direct, and ${d.dvds} DVD drive(s) are defined`);
    if (d.mediumSha256 != null || d.mediumPath != null) fail("linux-direct, and a medium came back");
  }
  if (Number(d.vcpus) !== want.vcpus) fail(`${d.vcpus} vCPUs, not ${want.vcpus}`);
  if (Number(d.memBytes) !== want.memMiB * 1048576) fail(`${d.memBytes} bytes of memory, not ${want.memMiB} MiB`);
  if (d.dynamicMemory !== false) fail("dynamic memory is on: a pinned share is not a dynamic one");
  if (d.automaticStartAction !== "Nothing") fail(`AutomaticStartAction is ${JSON.stringify(d.automaticStartAction ?? null)}: it must not come back by itself after a reboot`);
  if (d.automaticStopAction !== "TurnOff") fail(`AutomaticStopAction is ${JSON.stringify(d.automaticStopAction ?? null)}, not TurnOff`);
  return true;
}

const VTPM_NOTE = "Windows makes a vTPM for a VBS VM and the guest-state key protector lives there. NOTHING ON THIS "
  + "PATH READS ITS PCRs: its presence is not attestation and must never be reported as any.";

export class WmiHyperVLauncher {
  /**
   * @param run  async (script) => { code, stdout, stderr }   injected; nothing here spawns anything
   * @param imagePath / imageSha256  the IGVM the worker loads, and the hash it must have, checked on the host
   * @param boot  BOOT_UEFI ("uefi-medium") or BOOT_LINUX_DIRECT ("linux-direct"). STATED, never inferred:
   *              a launcher without it can still survey, stop and tear down, but refuses to start.
   * @param medium / mediumSha256  the boot medium, for uefi-medium only (and refused with linux-direct)
   * @param guestStateMaster  the master VMGS this host requires for type 1; copied per run, never handed to a VM
   * @param guestStateArchiveDir  where each run's copy is archived after its VM is removed
   * @param guestStateRunDir  where the per-run copies live (default: beside the master, as the recipe does)
   * @param hypervModule / hypervModuleSha256  petri's hyperv.psm1, pinned (default: the recipe's pin)
   * @param hypervUtilitiesSha256  optional pin for the utilities.psm1 hyperv.psm1 imports (always reported)
   * @param prefix  every VM this instance creates starts with it, and teardown filters on it
   */
  constructor({ run, imagePath, imageSha256, boot = null, medium = null, mediumSha256 = null,
                guestStateMaster = null, guestStateMasterSha256 = null, guestStateRunDir = null, guestStateArchiveDir = null,
                hypervModule = null, hypervModuleSha256 = HYPERV_MODULE_SHA256, hypervUtilitiesSha256 = null,
                prefix = DEFAULT_VM_PREFIX, pipeFor = null, serve = null, startTransport = null,
                startEgress = null, egressService = null, startPackage = null, packageService = null,
                startCustody = null, custodyService = null, custodyImageSha256 = null, imageRole = "legacy" }) {
    if (typeof run !== "function") throw new Error("a PowerShell runner must be injected");
    // THE BOOT FORM IS STATED. Inferring it from whether a medium happens to be set would let a
    // missing variable silently turn a medium boot into a linux-direct one, and the identity with it.
    if (boot !== null && !BOOT_FORMS.includes(boot))
      throw new Error(`boot must be one of ${BOOT_FORMS.join(", ")}; got ${JSON.stringify(boot)}`);
    if (boot === null && (medium || mediumSha256))
      throw new Error("a medium was given but no boot form: the boot form is stated, never inferred from a medium being set");
    if (boot === BOOT_LINUX_DIRECT && (medium || mediumSha256))
      throw new Error("linux-direct boots the kernel INSIDE the measured IGVM: no medium may be attached");
    if (boot === BOOT_UEFI && (!medium || !SHA256.test(String(mediumSha256 || "").toLowerCase())))
      throw new Error("a uefi-medium boot needs the medium's path and its sha256: a path is not an identity");
    for (const [k, val] of Object.entries({ hypervModuleSha256, hypervUtilitiesSha256, guestStateMasterSha256 }))
      if (val != null && !SHA256.test(String(val).toLowerCase())) throw new Error(`${k} must be a sha256`);
    this.run = run; this.imagePath = imagePath; this.imageSha256 = (imageSha256 || "").toLowerCase();
    this.boot = boot;
    // The boot medium, beside the firmware and never confused with it. The firmware is the
    // paravisor image the worker loads; the medium is what the guest BOOTS, and only the medium's
    // hash can answer "what ran" - with Secure Boot off the ESP can differ under one UKI.
    this.medium = medium;
    this.mediumSha256 = mediumSha256 ? String(mediumSha256).toLowerCase() : null;
    this.guestStateMaster = guestStateMaster;
    this.guestStateMasterSha256 = guestStateMasterSha256 ? String(guestStateMasterSha256).toLowerCase() : null;
    this.guestStateRunDir = guestStateRunDir || (guestStateMaster ? path.win32.dirname(guestStateMaster) : null);
    this.guestStateArchiveDir = guestStateArchiveDir;
    this.hypervModule = hypervModule;
    this.hypervModuleSha256 = String(hypervModuleSha256).toLowerCase();
    this.hypervUtilitiesSha256 = hypervUtilitiesSha256 ? String(hypervUtilitiesSha256).toLowerCase() : null;
    // A STABLE prefix, not one keyed to a pid: a restarted manager must still recognise, and be
    // able to reconcile, the VMs its predecessor left behind.
    this.prefix = prefix;
    // its ownership marker follows its prefix (markerFor): production's for the default prefix, its own otherwise
    this.marker = markerFor(prefix);
    // The names THIS launcher created. Cleanup and reconciliation work from this, not from a
    // prefix match, so a duplicate name or a neighbour sharing the prefix is never removed by us.
    this.created = new Set();
    this.pipeFor = pipeFor || ((name) => `\\\\.\\pipe\\${name}-com1`);
    // THE APP AND ITS RELAY (wmiserve-run.mjs, enclave-5d), opt-in: { exe, bundleDir, portFor?, readyTimeoutMs?, run? }.
    // Without it this launcher boots the VM and stops there, exactly as before (no relay, and the domain stays starting).
    this.serve = serve;
    this.startTransport = startTransport;
    // OUTBOUND HTTPS (egress.mjs), opt-in: (vmId, deploymentId, mapping) -> { exited, stop } | null, run after the VM
    // starts and before the app is served; null when this mapping gets none. egressService is the hv_sock service GUID
    // its bridge binds, which preflight READS from the registry (a WMI partition's bind fails 10013 without it).
    if (egressService !== null && !GUID.test(String(egressService))) throw new Error("egressService must be a service GUID");
    if (startEgress !== null && typeof startEgress !== "function") throw new Error("startEgress must be a function");
    this.startEgress = startEgress;
    this.egressService = egressService ? String(egressService).toLowerCase() : null;
    // THE OWNER-COMMITTED STARTUP PACKAGE (package-transport.mjs), opt-in: (vmId, deploymentId, bytes) -> { exited, stop },
    // run with egress for a spawn that carries one; packageService is its hv_sock service GUID (vsock 9446), READ by
    // preflight like egress's. Without the hook a spawn carrying a package is refused, never started without it.
    if (packageService !== null && !GUID.test(String(packageService))) throw new Error("packageService must be a service GUID");
    if (startPackage !== null && typeof startPackage !== "function") throw new Error("startPackage must be a function");
    this.startPackage = startPackage;
    this.packageService = packageService ? String(packageService).toLowerCase() : null;
    // DIRECT CUSTODY (custody-transport.mjs), opt-in: (vmId, deploymentId, { vault }) -> { exited, stop, pending, answer },
    // run for a spawn whose package keeps its secrets in custody-v2, and ONLY on the image the operator stated is the
    // custody build (custodyImageSha256 must be this launcher's own pinned image). custodyService is its hv_sock service
    // GUID (vsock 9445), READ by preflight like the others. Without all three such a spawn is refused before anything runs.
    if (custodyService !== null && !GUID.test(String(custodyService))) throw new Error("custodyService must be a service GUID");
    if (startCustody !== null && typeof startCustody !== "function") throw new Error("startCustody must be a function");
    if (custodyImageSha256 !== null && !SHA256.test(String(custodyImageSha256))) throw new Error("custodyImageSha256 must be a sha256");
    this.startCustody = startCustody;
    this.custodyService = custodyService ? String(custodyService).toLowerCase() : null;
    this.custodyImageSha256 = custodyImageSha256 ? String(custodyImageSha256) : null;
    // WHICH PINNED IMAGE THIS LAUNCHER STARTS (F3): "legacy" (every existing path), "shield-direct" (owner-committed
    // packages only: its front ends any domain that receives none) or "gpu". It is stated on every handle and in the VM's
    // Notes, and a launcher never starts a spawn of the other kind.
    if (!IMAGE_ROLES.includes(imageRole)) throw new Error(`imageRole must be one of ${IMAGE_ROLES.join(", ")}`);
    if (imageRole !== "shield-direct" && (startPackage || startCustody))
      throw new Error("only the Shield-direct image carries owner-committed packages or custody: this launcher's image is " + imageRole);
    this.imageRole = imageRole;
  }

  async #ps(script) {
    const r = await this.run(script);
    if (!r || r.code !== 0) {
      const e = new Error((r && (r.stderr || "").trim()) || `PowerShell exited ${r ? r.code : "?"}`);
      e.code = "powershell_failed";
      throw e;
    }
    return parse(r.stdout);
  }

  /** What is missing from this launcher's own configuration for a type-1 start. Empty when nothing is. */
  unconfigured() {
    const miss = [];
    if (!this.boot) miss.push(`no boot form: it must be stated as ${BOOT_FORMS.map((b) => JSON.stringify(b)).join(" or ")}, never inferred`);
    if (!this.hypervModule) miss.push("no hyperv.psm1 path: petri's New-CustomVM is what defines the VM");
    if (!this.guestStateMaster) miss.push("no guest-state master: this host refuses a type-1 VM without a VMGS, and New-CustomVM supplies none");
    if (!this.guestStateArchiveDir) miss.push("no guest-state archive directory: each run's VMGS copy is archived after its VM is removed");
    if (this.serve && !this.serve.exe) miss.push("serve is set with no wmiserve executable: nothing could load the app");
    if (this.serve && !this.serve.bundleDir) miss.push("serve is set with no bundle directory: the manager writes each instance's bundle there");
    return miss;
  }
  /** Retirement needs a run directory and an archive; without both, nothing is retired (and nothing was made). */
  #retires() { return !!(this.guestStateRunDir && this.guestStateArchiveDir); }
  /** The per-run copy for one VM name, or null when the name is not a plain file name. */
  guestStateRunFor(name) {
    const n = String(name ?? "");
    if (!this.guestStateRunDir || !/^[A-Za-z0-9._-]+$/.test(n) || n === "." || n === "..") return null;
    return path.win32.join(this.guestStateRunDir, `${n}.vmgs`);
  }
  async #retire({ vmId = null, name }) {
    const p = this.guestStateRunFor(name);
    if (!p) return { retired: false, note: `no per-run guest-state path for ${JSON.stringify(name ?? null)}` };
    return await this.#ps(CMD.retireGuestState({ path: p, runDir: this.guestStateRunDir, master: this.guestStateMaster,
                                                 archiveDir: this.guestStateArchiveDir, vmId, name }));
  }

  /** Every prerequisite, each answered rather than assumed. Never throws: it reports. */
  async preflight() {
    let got;
    try { got = await this.#ps(CMD.preflight({ hypervModule: this.hypervModule, guestStateMaster: this.guestStateMaster, egressService: this.egressService,
                                               packageService: this.packageService, custodyService: this.custodyService })); }
    catch (e) { return { ok: false, checks: [{ name: "preflight", ok: false, detail: e.message }] }; }
    const fo = got.firmwareOptIn || {};
    const optInOk = fo.present === true && Number(fo.value) === 1 && fo.kind === "DWord";
    const hm = got.hypervModule || null, gm = got.guestStateMaster || null;
    const checks = [
      { name: "vmms service", ok: got.vmms === true, detail: "the Hyper-V Virtual Machine Management service" },
      { name: "root\\virtualization\\v2", ok: got.namespace === true, detail: "the WMI namespace New-CustomVM defines the VM through" },
      { name: "Hyper-V PowerShell module", ok: got.module === true, detail: "Get-VM, which owns, starts and removes the VM" },
      { name: "Msvm_VirtualSystemSettingData.FirmwareFile", ok: got.firmwareField === true, detail: "the field that carries a custom IGVM" },
      { name: "hypervisor present", ok: got.hypervisor === true, detail: "already true here: VBS runs on it" },
      { name: FIRMWARE_OPT_IN.check, ok: optInOk,
        detail: (optInOk ? `${FIRMWARE_OPT_IN.key}\\${FIRMWARE_OPT_IN.value} is DWORD 1`
          : fo.present === true
            ? `${FIRMWARE_OPT_IN.key}\\${FIRMWARE_OPT_IN.value} is present as ${fo.kind} ${JSON.stringify(fo.value)}, not DWORD 1`
            : `${FIRMWARE_OPT_IN.key}\\${FIRMWARE_OPT_IN.value} is ABSENT`)
          + ". Hyper-V refuses a custom IGVM without it (measured: Worker-Admin event 5142). REPORTED ONLY: this "
          + "manager never sets, changes or removes it; permanent production use of it is an open owner decision." },
      { name: "hyperv.psm1 (New-CustomVM), pinned",
        ok: !!(hm && hm.present === true && lc(hm.sha256) === this.hypervModuleSha256),
        detail: !this.hypervModule ? "not configured"
          : !hm || hm.present !== true ? `not found at ${this.hypervModule}`
          : lc(hm.sha256) === this.hypervModuleSha256 ? `sha256 ${hm.sha256}`
          : `hashes ${hm.sha256}, not the pinned ${this.hypervModuleSha256}` },
      { name: "type-1 guest-state master (VMGS)", ok: !!(gm && gm.present === true),
        detail: !this.guestStateMaster ? "not configured: this host refuses a type-1 VM without guest state"
          : gm && gm.present === true ? `${this.guestStateMaster} (${gm.bytes} bytes); each run gets a fresh copy`
          : `not found at ${this.guestStateMaster}` },
      { name: "boot form", ok: BOOT_FORMS.includes(this.boot),
        detail: this.boot ? `${this.boot}${this.boot === BOOT_UEFI ? ` (medium ${this.medium})` : " (no medium; the IGVM is the identity)"}`
                          : `not stated: ${BOOT_FORMS.join(" or ")}` },
      // Only when egress is on: without the registration every egress bridge's bind fails with 10013. REPORTED ONLY:
      // this manager never registers, changes or removes a service.
      ...(this.egressService ? [{ name: EGRESS_CHECK, ok: got.egressService === true,
        detail: `${GCS_KEY}\\${this.egressService} (vsock port ${EGRESS_VSOCK_PORT}) is ${got.egressService === true ? "registered" : "NOT registered"}`
              + ": the egress bridge binds this partition's service there. Reported only; this manager never writes the registry." }] : []),
      ...(this.packageService ? [{ name: PACKAGE_CHECK, ok: got.packageService === true,
        detail: `${GCS_KEY}\\${this.packageService} (vsock port 9446) is ${got.packageService === true ? "registered" : "NOT registered"}`
              + ": the startup-package bridge binds this partition's service there. Reported only; this manager never writes the registry." }] : []),
      ...(this.custodyService ? [{ name: CUSTODY_CHECK, ok: got.custodyService === true,
        detail: `${GCS_KEY}\\${this.custodyService} (vsock port 9445) is ${got.custodyService === true ? "registered" : "NOT registered"}`
              + ": the custody-authorization bridge binds this partition's service there. Reported only; registering it is an explicit activation step, and this manager never writes the registry." }] : []),
    ];
    return { ok: checks.every((c) => c.ok), checks };
  }

  /** The image must be the bytes we expect, on the host, at the moment we pin it. */
  async verifyImage() {
    const got = await this.#ps(CMD.imageHash(this.imagePath));
    if (got.present !== true) throw new Error(`guest image not present at ${this.imagePath}`);
    if (!this.imageSha256) throw new Error("no expected image sha256 was configured; a path is not an identity");
    if (String(got.sha256).toLowerCase() !== this.imageSha256)
      throw new Error(`guest image sha256 is ${got.sha256}, expected ${this.imageSha256}`);
    return { sha256: this.imageSha256, bytes: got.bytes };
  }
  /** The boot medium, likewise, before anything is created; it is hashed AGAIN at attach time. */
  async verifyMedium() {
    const got = await this.#ps(CMD.imageHash(this.medium));
    if (got.present !== true) throw new Error(`boot medium not present at ${this.medium}`);
    if (String(got.sha256).toLowerCase() !== this.mediumSha256)
      throw new Error(`boot medium sha256 is ${got.sha256}, expected ${this.mediumSha256}`);
    return { sha256: this.mediumSha256, bytes: got.bytes };
  }

  /**
   * Define (the type-1 recipe, read back), start, and require the guest to say something.
   *
   * `instanceId` is the caller's unique handle for THIS domain and is what the VM is named after.
   * Naming by AppID alone meant two deployments of the same app collided on one VM name: the second
   * definition fails, or worse, adopts the first. The AppID is carried in the notes, not in the name.
   *
   * Any failure after the VM exists removes it BY THE ID IT WAS DEFINED WITH before rethrowing, and
   * the define script removes it itself if it fails before returning - both, because a leak here is a
   * VM nobody owns.
   */
  async start(mapping, { instanceId, identity = null, guestReadySec = 25, appMemoryMiB = null, bootstrap = null, custody = null } = {}) {
    if (this.imageRole === "shield-direct" && !bootstrap)
      throw new Error("the Shield-direct image starts only owner-committed packages: its front ends a domain that receives none");
    if (this.imageRole !== "shield-direct" && (bootstrap || custody))
      throw new Error(`an owner-committed package starts only on the Shield-direct image, and this launcher's image is ${this.imageRole}`);
    if (bootstrap && (!this.startPackage || !this.startEgress))
      throw new Error("an owner-committed startup package needs this launcher's package transport and egress (the guest verifies the package against its own RPC quorum through it)");
    if (custody) {
      if (!bootstrap) throw new Error("a custody channel is only for an owner-committed startup package");
      if (!this.startCustody) throw new Error("a custody-v2 package needs this launcher's custody transport (vsock 9445), and it has none");
      if (!this.custodyImageSha256 || this.custodyImageSha256 !== this.imageSha256)
        throw new Error("a custody-v2 package starts only on the image the operator stated is the custody build, and this launcher's pinned image is not it");
      if (!identity || String(identity.name || "") !== String(custody.deployment || ""))
        throw new Error("the custody channel names another deployment than this partition's");
    }
    if (!instanceId || !/^[A-Za-z0-9._-]{4,64}$/.test(String(instanceId)))
      throw new Error("a unique instanceId is required: naming a domain by its AppID alone collides when the same app is deployed twice");
    const miss = this.unconfigured();
    if (miss.length) {
      const e = new Error(`this launcher cannot define a type-1 VM: ${miss.join("; ")}`);
      e.code = "launcher_unconfigured"; throw e;
    }
    const pre = await this.preflight();
    if (!pre.ok) {
      const failing = pre.checks.filter((c) => !c.ok);
      const optIn = failing.find((c) => c.name === FIRMWARE_OPT_IN.check);
      if (failing.some((c) => c !== optIn)) {
        const e = new Error(`the Hyper-V role is not usable on this host: missing ${failing.map((c) => c.name).join(", ")}`);
        e.code = "prerequisites_absent"; e.checks = pre.checks;
        throw e;
      }
      // Only the host's firmware opt-in is missing. Refused BEFORE anything is created, and named,
      // because the alternative is a VM that Hyper-V refuses at Start-VM with the reason in an event log.
      const e = new Error(`refusing to start: ${optIn.detail}`);
      e.code = "firmware_opt_in_absent"; e.checks = pre.checks;
      throw e;
    }
    // THE FIRMWARE's hash, and it is NOT the image identity (enclave-53: an object in handle.image
    // made the datapath refuse every route as "identity").
    const firmware = await this.verifyImage();
    if (this.boot === BOOT_UEFI) await this.verifyMedium();
    const name = `${this.prefix}${instanceId}`;
    const pipe = this.pipeFor(name);
    const notes = identity ? notesFor({ ...identity, instanceId, imageRole: this.imageRole }, { marker: this.marker }) : this.marker;
    const guestStateRun = this.guestStateRunFor(name);
    if (!guestStateRun) throw new Error(`no per-run guest-state path can be made for ${name}`);
    const vcpus = Math.max(1, Math.floor(mapping.record.policy.vcpus));
    const appMiB = appMemoryMiB ?? mapping.record.policy.memMiB;
    if (!Number.isSafeInteger(appMiB) || appMiB < mapping.record.policy.memMiB)
      throw new Error("allocated app RAM is below its catalog minimum");
    const memMiB = type1VmMemMiB(appMiB, {name:identity?.name, appId:mapping.appId});
    let created = null, served = null, transport = null, egress = null, pkg = null, cust = null;
    try {
      created = await this.#ps(CMD.defineType1({ marker: this.marker,
        name, memMiB, vcpus, notes, pipe, boot: this.boot,
        firmware: this.imagePath, firmwareSha256: this.imageSha256,
        hypervModule: this.hypervModule, hypervModuleSha256: this.hypervModuleSha256, hypervUtilitiesSha256: this.hypervUtilitiesSha256,
        guestStateMaster: this.guestStateMaster, guestStateMasterSha256: this.guestStateMasterSha256, guestStateRun,
        archiveDir: this.guestStateArchiveDir,
        ...(this.boot === BOOT_UEFI ? { medium: this.medium, mediumSha256: this.mediumSha256 } : {}) }));
      this.created.add(name);
      checkDefinition(created, { notes, pipe, boot: this.boot, vcpus, memMiB, firmware: this.imagePath, firmwareSha256: this.imageSha256,
                                 hypervModuleSha256: this.hypervModuleSha256, hypervUtilitiesSha256: this.hypervUtilitiesSha256,
                                 guestStateRun, guestStateMaster: this.guestStateMaster, mediumSha256: this.mediumSha256 });

      // ONE process starts the VM and reads its console, the reader attaching before the guest can speak (startAndRead)
      const started = await this.#ps(CMD.startAndRead({ vmId: created.id, pipe, seconds: guestReadySec, until: GUEST_READY_LINE, marker: this.marker }));
      if (started.state !== "Running")
        throw new Error(`the VM is ${JSON.stringify(started.state ?? null)} after Start-VM, not Running`);

      // THE GUEST BOOTED - and that is ALL this establishes. Bytes on a serial port are bytes: a
      // firmware banner is bytes, a kernel panic is bytes. It says something inside the partition
      // executed, which is more than "Running" says, and it is NOT evidence that the component was
      // delivered, compiled or served. There is no app-readiness handshake on this backend yet, so
      // there is no state here that means "the app is up", and the launcher does not invent one.
      const con = started.console || {};
      if (con.connected !== true)
        throw new Error(`could not attach to the guest console at ${pipe}: ${con.note || "no connection"}`);
      const booted = Number(con.bytes) > 0;
      if (!booted)
        throw new Error(`the VM is Running but the guest produced no output on ${pipe} within ${guestReadySec}s: a silent partition is not a booted one`);

      // `image` is a 64-hex STRING, never an object and never the firmware's hash on a medium boot: the
      // medium's hash as hashed AT ATTACH TIME (uefiImageIdentity), or for linux-direct the IGVM's pinned
      // sha256 (linuxDirectIdentity), because the IGVM is what booted. Either way it travels with
      // guestIdentity's (partition, guestImageKind) statement, and judge-hv and the data plane compare the
      // pair first and the image second, never the image alone.
      const uefi = this.boot === BOOT_UEFI;
      // THE APP AND ITS RELAY, when this launcher was given wmiserve to run (enclave-5d, wmiserve-run.mjs): the bundle
      // into the guest over hv_sock 9000, the report service for THIS VM, and a loopback TCP relay to the domain.
      if (this.startTransport) transport = await this.startTransport(created.id);
      // OUTBOUND HTTPS (egress.mjs): the partition's bridge and egress endpoint, now that the VM runs and before its app is
      // served; the hook decides which mappings get one (main.mjs: secret deployments) and answers null for the rest
      if (this.startEgress) egress = (await this.startEgress(created.id, identity?.name ?? null, mapping, { bootstrap: !!bootstrap })) || null;
      // ...and the exact package bytes the node verified, for the Shield-direct front to verify again itself (vsock 9446)
      if (bootstrap) {
        if (!egress) throw new Error("an owner-committed startup package needs egress, and the egress hook started none");
        // the custody channel (vsock 9445) is up BEFORE the package that tells the guest to ask on it
        if (custody) cust = await this.startCustody(created.id, identity.name, { vault: custody.vault });
        pkg = await this.startPackage(created.id, identity?.name ?? null, bootstrap);
      }
      if (this.serve) served = await this.#serveApp({ mapping, instanceId, vmId: created.id, uefi, created, vcpus, memMiB, appMemoryMiB, certName: certNameFor(identity && identity.name) });
      const guestIdentity = uefi
        ? uefiImageIdentity({ mediumSha256: created.mediumSha256, mediumPath: created.mediumPath ?? this.medium })
        : linuxDirectIdentity({ igvmSha256: created.firmwareSha256, igvmPath: this.imagePath });
      return { imageRole: this.imageRole, transport, egress, package: pkg, custody: cust, instanceId, name, vmId: created.id, pipe, state: started.state,
               boot: this.boot, isolationType: 1,
               image: uefi ? guestIdentity.guestImageSha256 : guestIdentity.igvmSha256,
               guestIdentity, firmware, boundary: boundaryFor(this.boot), appId: mapping.appId,
               vtpm: { enabled: created.tpmEnabled === true, pcrsRead: false, note: VTPM_NOTE },
               memory: { policyMiB: mapping.record.policy.memMiB, appMiB, vmMiB: memMiB,
                         rule: memMiB === 512 ? "qualified pinned readiness witness: 512 MiB" : `align2(max(${TYPE1_VM_MEM_FLOOR_MIB}, app + ${TYPE1_VM_MEM_OVERHEAD_MIB}))` },
               definition: { recipe: "petri New-CustomVM, GuestStateIsolationType 1 (uefi-dev-boot.ps1 e0de58cf)",
                             hypervModuleSha256: created.hypervModuleSha256, hypervUtilitiesSha256: created.hypervUtilitiesSha256 ?? null,
                             featureSet: created.featureSet, vtl2Mode: created.vtl2Mode, vbsOptOut: created.vbsOptOut,
                             guestState: { path: created.guestStateFile, masterSha256: created.guestStateMasterSha256 },
                             grants: created.grants ?? [] },
               // guestBooted: something executed. appReady: NOT established - no handshake exists.
               guest: { booted, bytes: con.bytes, head: String(con.head || "").slice(0, 400), readyLine: con.sawUntil === true,
                        attach: { early: con.early === true, ms: con.attachMs ?? null } },
               appReady: false,
               // THE RELAY, when served: the manager judges readiness through tcpPort with launcherKey (the report is
               // judged against guestIdentity's pair and `image`), and routes to it. Without `serve` there is none, the
               // domain stays `starting`, and nothing is routed, exactly as before.
               // launcherVmId: the partition that launcher key signs for, in the launcher's own words; the manager judges the
               // report's partition.vmId against it, so a report from another partition's launcher never reads as this one
               ...(served ? { tcpPort: served.tcpPort, launcherKey: served.launcherKey, launcherVmId: served.vm, domainId: served.domainId,
                              guestPort: served.guestPort, boot: served.boot, relayNote: served.note, wmiserve: served } : {}),
               stop: async () => await this.stop({ name, vmId: created.id, wmiserve: served, transport, egress, package: pkg, custody: cust }) };
    } catch (e) {
      if (transport) await transport.stop();
      if (egress) await egress.stop().catch(() => {});
      if (cust) await cust.stop().catch(() => {});
      if (pkg) await pkg.stop().catch(() => {});
      if (served) { e.relay = await this.#closeServed(served); }       // before its VM goes
      const vmId = created && GUID.test(String(created.id || "")) ? String(created.id) : null;
      let swept;
      if (vmId) {
        // BY THE ID THIS ATTEMPT DEFINED. A name is not unique in Hyper-V; the Id is the VM we made.
        // removeById still checks the ownership marker on it - which the define script put on first.
        swept = await this.#ps(CMD.removeById({ vmId, marker: this.marker }))
          .catch((x) => ({ found: null, removed: false, error: x.message }));
      } else {
        // No Id came back, so the define script has already removed what it made (or never made
        // anything). EXACT name, never a prefix, and the ownership marker unless THIS attempt made it.
        const mine = this.created.has(name);
        swept = await this.#ps(CMD.removeExact({ name, requireMarker: !mine, marker: this.marker }))
          .catch((x) => ({ found: null, removed: false, error: x.message }));
      }
      this.created.delete(name);
      e.cleanup = swept;
      if (swept && swept.found === true && swept.removed !== true) {
        e.message += ` (cleanup could NOT remove ${name}${vmId ? ` (${vmId})` : ""}: ${swept.error || "unknown"} - it is still on this host)`;
      } else if (created && swept && swept.found === null) {
        // The removal itself did not run: unknown is not absent, so it is said, and nothing is retired.
        e.message += ` (cleanup of ${name}${vmId ? ` (${vmId})` : ""} did not run: ${swept.error || "unknown"} - it may still be on this host)`;
      } else if (created && swept && (swept.removed === true || swept.found === false)) {
        // The VM this attempt defined is gone, so its guest-state copy can be archived and removed.
        const g = await this.#retire({ vmId, name }).catch((x) => ({ retired: false, error: x.message }));
        e.guestState = g;
        if (g && g.error) e.message += ` (its guest-state copy was NOT retired: ${g.error})`;
      }
      throw e;
    }
  }

  /** The app into the guest and a relay to it (wmiserve-run.mjs). Its bundle file is removed if this fails. */
  async #serveApp({ mapping, instanceId, vmId, uefi, created, vcpus, memMiB, appMemoryMiB, certName = null }) {
    const s = this.serve;
    const bundleFile = writeBundle({ dir: s.bundleDir, instanceId, bundle: mapping.bundle, appId: mapping.appId });
    try {
      const tcpPort = await (s.portFor ? s.portFor(instanceId) : freePort());
      const run = await (s.run || runWmiserve)({ exe: s.exe, vmId, bundleFile, appId: mapping.appId, tcpPort,
        ...(uefi ? { mediumSha256: created.mediumSha256 } : { igvmSha256: created.firmwareSha256 }),
        isolationType: 1, label: instanceId, vcpus, memMiB, appMemoryMiB, ...(certName ? { certName } : {}),
        ...(s.readyTimeoutMs ? { readyTimeoutMs: s.readyTimeoutMs } : {}), ...(s.spawn ? { spawn: s.spawn } : {}) });
      run.bundleFile = bundleFile;
      return run;
    } catch (e) { fs.rmSync(bundleFile, { force: true }); throw e; }
  }
  /** Close a relay and remove its bundle file; the outcome, never a throw. */
  async #closeServed(run) {
    const closed = await run.stop().catch((x) => ({ closed: false, how: `stop failed: ${x.message}` }));
    try { if (run.bundleFile) fs.rmSync(run.bundleFile, { force: true }); } catch (x) { closed.bundle = `not removed: ${x.message}`; }
    return closed;
  }

  /** Stop, and SAY when it did not: "ok" for a VM that is still running is how one gets orphaned. */
  async stop(handle) {
    if (handle?.transport) await handle.transport.stop();
    // its egress path has nothing to carry once the domain stops; it ends before the VM goes, and never blocks that
    if (handle?.egress) await handle.egress.stop().catch(() => {});
    if (handle?.custody) await handle.custody.stop().catch(() => {});
    if (handle?.package) await handle.package.stop().catch(() => {});
    // The relay and report service first (wmiserve closes on a stdin line), then the VM. Its outcome is REPORTED on the
    // result and never blocks the removal: a relay that will not close is killed, and the VM must go either way.
    const relay = handle && handle.wmiserve ? await this.#closeServed(handle.wmiserve) : null;
    if (handle && handle.vmId) {
      // BY ID, and removed, not just turned off: a stopped VM that keeps its identity notes would be
      // recovered as live by the next manager, and a VM left Off is one nobody owns (63's P2).
      if (!GUID.test(String(handle.vmId))) throw Object.assign(new Error(`not a VM Id: ${handle.vmId}`), { code: "stop_failed" });
      const r = await this.#ps(CMD.removeById({ vmId: handle.vmId, marker: this.marker }));
      if (r && r.found === true && r.removed !== true) {
        const e = new Error(`could not stop and remove ${handle.name || handle.vmId}: ${r.error || "unknown"}`);
        e.code = "stop_failed"; throw e;
      }
      if (handle.name) this.created.delete(handle.name);
      const out = { stopped: true, removed: r && r.removed === true, name: handle.name ?? null, vmId: handle.vmId,
                    ...(r && r.found === false ? { note: "already gone" } : {}), ...(relay ? { relay } : {}) };
      // The VM is gone: archive and remove its per-run guest state. A failure here is REPORTED on the
      // result, not thrown - the domain has stopped, and saying otherwise would be the lie in reverse.
      if (this.#retires() && handle.name)
        out.guestState = await this.#retire({ vmId: handle.vmId, name: handle.name }).catch((x) => ({ retired: false, error: x.message }));
      return out;
    }
    if (!handle || !handle.name) return { stopped: false, reason: "no handle" };
    // by NAME only for a name in THIS instance's scope (a VM-id-less handle): never another instance's VM
    if (!String(handle.name).startsWith(this.prefix)) throw Object.assign(new Error(`${handle.name} is not in this instance's scope (${this.prefix})`), { code: "stop_failed" });
    const r = await this.#ps(CMD.stop({ name: handle.name }));
    if (r && r.ok === false) {
      const e = new Error(`could not stop ${handle.name}: ${r.error || "unknown"}`);
      e.code = "stop_failed"; throw e;
    }
    return { stopped: true, name: handle.name };
  }
  /** The boundary word for THIS launcher's stated boot form (null until one is stated: nothing can start then). */
  get boundary() { return this.boot ? boundaryFor(this.boot) : null; }
  async state(name) { return await this.#ps(CMD.state({ name })); }
  /** What this prefix owns right now, including anything a previous run left behind. */
  async survey() { return await this.#ps(CMD.survey({ prefix: this.prefix, marker: this.marker })); }
  /**
   * Remove every VM under this prefix and SAY what could not be removed. It throws when anything
   * was left behind, because a teardown that reports success while an orphan survives is how a
   * host fills up with VMs nobody owns.
   */
  async teardown({ requireMarker = true } = {}) {
    // Marker-required by DEFAULT now: a prefix alone can collide with a VM this manager never made,
    // and removing somebody else's domain is worse than leaving one of ours behind. The narrow gap
    // - a VM that died between its definition and its Notes - is closed by the exact names we recorded.
    const gone = [];
    for (const name of [...this.created]) {
      const one = await this.#ps(CMD.removeExact({ name, requireMarker: false, marker: this.marker })).catch(() => null);
      if (one && one.removed) { this.created.delete(name); gone.push(name); }
    }
    const r = await this.#ps(CMD.teardown({ prefix: this.prefix, requireMarker, marker: this.marker }));
    if (Array.isArray(r.removed)) gone.push(...r.removed);
    // Each removed VM's guest-state copy, now that the VM is gone. Reported, never thrown: the VMs are gone.
    if (this.#retires() && gone.length) {
      r.guestState = [];
      for (const name of gone) r.guestState.push({ name, ...(await this.#retire({ name }).catch((x) => ({ retired: false, error: x.message }))) });
    }
    if (Array.isArray(r.failed) && r.failed.length) {
      const e = new Error(`teardown could not remove ${r.failed.length} VM(s): `
        + r.failed.map((f) => `${f.name} (${f.error})`).join("; "));
      e.code = "teardown_incomplete"; e.result = r;
      throw e;
    }
    return r;
  }
}
