# Windows host installer

Status: design, 2026-10-11. Owner decisions (Steven): open market; downloads from get.enclave.host; unsigned for now,
SignPath Foundation (free OSS signing) to follow; the host's name is chosen during setup.

## What a Windows host is

Naming: the per-app Hyper-V isolation is **Enclave Shield** in everything a host owner sees (installer, folders, tasks,
files, docs). `vbslike` survives only as a legacy internal path in the repo (`windows/vbslike`) until its own rename.

A Windows 11 Pro/Enterprise 24H2+ PC with Hyper-V, Secure Boot and an AMD fTPM, running:

| part | what it does | today's source (known-good on nucbox-k11 until its 10-11 reset) |
|---|---|---|
| node agent (`windows/node`) | attaches to the relay (TPM attestation), registers, claims, renews, the local hosting API | `releases/risc-service-20261002/control/windows/node` |
| Enclave Shield manager (repo: `windows/vbslike/manager`) | one Hyper-V partition per app | same `control/` tree |
| `shield-host.exe` (Rust; built as `vbslike-host.exe` today) | Enclave Shield's WMI/hv_sock host side | `risc-service-20261002/vbslike-host.exe` |
| guest IGVM (77 MB) | the partition's firmware + kernel | `public-web-20261005/runtime.bin` (sha256 5fbfb947…) |
| blank guest state `type1.vmgs` (~64 MB) | VBS guest-state master | minted on the box by `New-VM -GuestStateIsolationType VBS`; the installer mints it |
| `hyperv.psm1` | petri's Hyper-V helpers | `C:\Users\claude\hyperv.psm1` (17ca4352…) |
| `runtime.json` | the wasm runtime identity | wasmtime 49 |
| `ipfs_fetch.py` + Python | the manager's CID fetcher | `v44-codex-20260929/control/wasm`; `C:\Python314` |
| egress: `shield-egress.exe`, `shielded-bridge.exe` | per-app public egress | `public-web-20261005` |
| `tpmattest.exe` | TPM quote / EK / AK | built with MSVC on the box |
| TUNA privacy agent + `enclave-tuna`, `enclave-route-discovery`, `enclave-circuit-firewall`, `enclave-provider-inventory`, circuit `worker.exe` | each app's private route (the relay has no public data plane) | `tuna-privacy/agent` (bundled .mjs + Go exes) |
| Shield GPU worker (optional) | GPU inference for Shield apps | `vbs/vkw` |
| tray (`windows/tray`) | caps, on/off, earnings, payout wallet | `EnclaveTray.exe` |
| Node.js 24 | runs node, manager, privacy agent | `C:\Program Files\nodejs` |

## Install layout

- `C:\Program Files\Enclave\` — read-only program files: `runtime\node\`, `runtime\python\`, `control\` (node + manager +
  node_modules), `guest\` (IGVM, hyperv.psm1, runtime.json), `bin\` (shield-host, tpmattest, egress, bridge),
  `tuna\` (privacy agent + exes), `tray\`.
- `C:\ProgramData\Enclave\` — state, ACL SYSTEM + Administrators: `node\` (keys, records, payout, caps, delegations),
  `manager\` (vmgs master + archive, bundles), `tuna\` (circuits, config), `logs\`, `hosting\` (tray token).
- Services: scheduled tasks `\Enclave\Shield` (the per-app isolation manager, boot +30 s), `\Enclave\Node` (+90 s),
  `\Enclave\Tuna`, `\Enclave\Card` (the GPU worker, +20 s), as SYSTEM, restart
  loops, as the hand rollout did. Tray: per-user, HKCU Run + Desktop/Start Menu shortcuts.

## Setup flow (`EnclaveSetup.exe`, C# WinForms in the tray's theme, requireAdministrator)

1. Checks: edition, virtualization in firmware, Secure Boot on / test-signing off, TPM 2.0 AMD fTPM (Intel: "not yet"),
   RAM/disk, AMD SEV not needed. Each failure says how to fix it.
2. Hyper-V features (+ VirtualMachinePlatform); if a reboot is needed, a RunOnce entry resumes setup after it.
3. Host prerequisites: `AllowFirmwareLoadFromFile=1`, the hv_sock 9001 GCS GUID (host-prereq.ps1, kept as a step).
4. **Name**: the owner types it; checked live (`GET https://api.enclave.host/v1/hosts/name/<name>`: syntax, not
   registered on chain, no tunnel holds it).
5. Download the pinned bundle from get.enclave.host, verify SHA256SUMS (+ Ed25519 signature once the release key exists),
   extract; mint `type1.vmgs`; write configs from templates; generate operator/proof/transport keys.
6. Register tasks, start manager → node; wait for attach (hardware attestation) and the SPONSORED registration
   (EnclaveHostPaymaster, no ETH needed); then the TUNA agent.
7. Install the tray for the signed-in user; open it on the payout-wallet step.
8. **EnclaveDNS** (optional, ticked by default on the Name page): the bundle's pinned EnclaveDNS installer
   (github.com/EnclaveHost/enclavedns-client) runs silently (`/VERYSILENT /TASKS=enable,path`): the EnclaveDNS service,
   this PC's DNS through it (one NRPT rule for "."), and its .eth-only CA, so the owner can reach Enclave at
   EnclaveHost.eth if enclave.host is down. `install-host.ps1 -EnclaveDNS`; a failure only warns, and updates never pass
   it (an update cannot change a host's DNS). An unticked box survives the Hyper-V restart (`--no-enclavedns`).

`irm https://get.enclave.host/host.ps1 | iex` downloads and verifies `EnclaveSetup.exe` and runs it (no Mark of the
Web, so no SmartScreen prompt while unsigned). The Host page links both.

## Platform work for an open market (built 2026-10-11; nothing per-host by hand)

1. **Serving.** `RELAY_HVNODE_OPERATORS=*`: any name's on-chain owner whose v2 attach signature binds the attach to this
   TPM serves its own apps (+ its delegators') owner-only. A NEW host attaches before its sponsored registration as a
   `claimant`; the relay's once-a-minute owner re-check promotes it to operator once the registry names that key
   (`relay/tunnel.js`). Buyers' apps need per-app evidence as before.
2. **Market admission.** The Shield policy takes `hosts: "*"` (any attested hv-node with a live session) and
   `platforms: "attested"` (any EK chained to the pinned AMD roots on a production boot, any firmware) instead of
   per-box pins (`relay/shield-app-policy.mjs`, shared with the privacy agent's own TPM proof). An hv-node row's TUNA
   route is per deployment only (its owner-only rule or its own app evidence), never the row's eligibility.
3. **Readiness witness.** The platform's pinned `shield-readiness-v1` app (`windows/installer/shield-witness.json`,
   runtime 297b6c2c) ships as `guest\witness.json`; setup sets `SHIELD_WITNESS_CONFIG` and refuses a mismatched runtime.
4. **Market window grace.** A lapsed 300 s relay window (relay restart, re-attach) keeps serving the buyer apps a box
   already runs for 15 min (`Host.servingScope`); new claims still need a live window.
5. **TUNA, automatic.** The node enrolls its own privacy agent (`windows/node/tuna-enroll.mjs`): it makes the control
   and per-app NKN wallets on the box, asks `POST /v1/hosts/tuna-funding` (signed by the attested transport key; control
   once per TPM, six wallets per app leased to it; 8 apps/host/day, 60/day), writes `privacy-config.json` once funded;
   `\Enclave\Tuna` waits for it. The relay records requests in `RELAY_TUNA_FUNDING_FILE`; the platform's machine reads
   that queue over SSH and pays through the existing top-up job (`network/tuna-funding-sync.mjs`, timer
   `enclave-tuna-funding-sync`). The paymaster pays only Base gas; NKN comes from the platform's NKN funding wallet.
6. **GPU share.** Every bundle carries Enclave Shield's GPU half (`windows/vbslike/SHIELDED-GPU.md`): the Vulkan card
   worker (`bin\shielded-worker.exe`, the yield build, + `bin\shaders\`), the measured GPU image
   (`guest\runtime-shield-gpu.bin`, 7c41baaf, Qwen2.5-0.5B, same runtime 297b6c2c). Setup registers hv_sock port 19595,
   writes `shield-gpu-profile.json` (`ENCLAVE_SHIELD_PROFILE`) and runs the worker as `\Enclave\Card` on 127.0.0.1:19595
   with the profile's 12 GiB budget. The manager probes it every 15 s and offers GPU only while it answers, so the row
   carries `shielded` + `gpuShareFree` with no hand setup, and a PC whose card the worker cannot drive sells no GPU.
   Idle, the worker holds ~40 MB RAM and ~2 MB of GPU memory, and it yields to the owner's own use of the card.
7. **Name check.** `GET /v1/hosts/name/<name>` (`relay/host-names.mjs`).

## Updates (automatic)

The node checks `get.enclave.host/windows/latest.json` once a minute (`windows/node/update-watch.mjs`) and starts
`\Enclave\Update` the moment a newer version is live; the task's own triggers (5 minutes after boot, then hourly) are only
the fallback for a node that is not running. `\Enclave\Update` (SYSTEM) runs `update-host.ps1`: when
`get.enclave.host/windows/latest.json` names a newer version than Program Files' `manifest.json`, it downloads the zip and
`EnclaveSetup.exe`, checks both against the published sha256, and runs the new `install-host.ps1` over the host with the same
name and owner (keys, records, guest state and registration kept; the services restart on the new version). A failed install
reinstalls the release that was running from its kept bundle. Updates are DELTAS: a release publishes every file by its
sha256 under `windows/files/` and its manifest as `manifest-<version>.json`; the updater hard-links unchanged files from
the installed release's kept bundle, downloads only the changed ones (falling back to the zip past 400 files or 60 MB), and
`install-host.ps1 -Delta` replaces only those in Program Files. The tray in the owner's profile replaces itself from Program
Files at its next start when they differ. Publishing a release (`scripts/publish-windows-host.sh`) is all it takes.

## Bundle build

`windows/installer/build-bundle.ps1` on a Windows build box: a sources map (bundle path → file + sha256) collects the
known-good parts above, downloads Node.js, Python (embeddable) and the EnclaveDNS installer at pinned versions and sha256, drops test/probe
artefacts, writes `manifest.json` (every file's sha256) and `SHA256SUMS`, zips `enclave-host-<version>.zip`. v1 takes
binaries from the known-good runtime; making each one build from the public repo (Rust, MSVC, Go, the IGVM) is the
next step, and is what SignPath needs.

## Order

1. bundle builder + bundle v1; 2. `EnclaveSetup.exe` + `host.ps1`; 3. the platform items above;
4. publish on get.enclave.host (2026.10.12, done) + Host page link; 5. Steven's end-to-end run on the reset NucBox.
