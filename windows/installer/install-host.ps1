# install-host.ps1 -- install an Enclave host on this Windows PC (docs/design/windows-host-installer.md). EnclaveSetup.exe
# runs it elevated from the expanded bundle; it can also be run by hand:
#   powershell -ExecutionPolicy Bypass -File install-host.ps1 -Name my-box [-Owner DOMAIN\user] [-Referral code] [-EnclaveDNS] [-CheckOnly]
# An INDEPENDENT host (docs/network/independent-windows.md): no Enclave relay tunnel, no relay name reservation, and no
# Enclave default for anything it fetches or trusts:
#   ... -Name my-box -NoRelay -PublicUrl https://my-box.example.org -Gateways https://gw1.example,https://gw2.example
#       -ContractPins C:\path\contract-pins.json [-Rpcs a,b] [-Directories a,b] [-NetworkCheckers 0x..,0x..]
#       [-NameCheck chain|offline] [-ReleasePolicy C:\path\release-policy.json]
# Progress goes to stdout as one JSON object per line: {"step","state":"run|ok|warn|fail|reboot","message"}.
# Re-running is safe: every step checks what is already there. Nothing is downloaded: the bundle is this folder.
#
# WHO THIS HOST IS is recorded in node\host.json (identity, ENCLAVE-IDENTITY-RECORD-V1) and re-used by every later run,
# including the automatic updates, which pass only -Name and -Owner: an update never moves a host to another endpoint,
# relay, gateway set, pin document or release policy. Changing any of them takes explicit parameters AND -Reconfigure,
# and a new public endpoint is a new host on chain (keccak256 of the endpoint is its registry id). A host installed before
# identities were recorded is the relay host it has always been: https://api.enclave.host/t/<name>.
param(
  [string] $Name = "",
  [string] $Owner = "",                 # the Windows account that gets the tray (default: whoever runs setup)
  [switch] $CheckOnly,                  # the machine checks alone
  [switch] $NoStart,                    # install and start Enclave Shield, but not the node (a test that registers nothing)
  [string] $Relay = "https://api.enclave.host",
  [string] $SetupExe = "",              # EnclaveSetup.exe: kept in Program Files as the uninstaller Windows' Installed apps runs
  [switch] $Delta,                      # an update over this install: replace only the files whose sha256 changed (update-host.ps1)
  [string] $Referral = "",              # the referral code this machine came with (attribution only; relay/referrals.mjs)
  [switch] $EnclaveDNS,                 # also install EnclaveDNS (setup's checkbox, ticked by default; updates never pass it)
  [switch] $NoRelay,                    # independent: no Enclave fleet tunnel and no relay name reservation
  [string] $PublicUrl = "",             # independent: this host's own public endpoint, exactly as it is to be registered
  [string] $Gateways = "",              # independent: artifact gateways (comma list; every artifact is CID-verified)
  [string] $ContractPins = "",          # independent: the contract pin document (network/contract-pins.mjs format)
  [string] $Rpcs = "",                  # Base RPCs (comma list; default: the node's public list)
  [string] $Directories = "",           # public signed-record directories for the Enclave network (comma list of origins)
  [string] $NetworkCheckers = "",       # the qualification checkers this host trusts for network providers (comma list)
  [ValidateSet("", "relay", "chain", "offline")] [string] $NameCheck = "",   # default: relay for a relay host, chain otherwise
  [string] $ReleasePolicy = "",         # the signed update policy to pin (release-channel.mjs format)
  [switch] $Reconfigure                 # let explicit parameters replace this host's recorded identity or release policy
)
$ErrorActionPreference = "Stop"
$Bundle = $PSScriptRoot
$PF = Join-Path $env:ProgramFiles "Enclave"
$PD = Join-Path $env:ProgramData "Enclave"
function Emit($step, $state, $message) { [ordered]@{ step = $step; state = $state; message = $message } | ConvertTo-Json -Compress | Write-Output }
function Fail($step, $message) { Emit $step "fail" $message; exit 1 }
function Sha($p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() }
function List($s) { @(([string]$s).Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
# node.exe with its stderr kept: native stderr under "Stop" throws in Windows PowerShell 5.1, so relaxed for this call only
function NodeRun($exe, [string[]] $a) {
  $ErrorActionPreference = "Continue"
  $o = @(& $exe @a 2>&1 | ForEach-Object { "$_" }); return @{ code = $LASTEXITCODE; out = ($o -join "`n").Trim() }
}

# ---------------------------------------------------------------------------------------------------------------------
# 1. the machine
# ---------------------------------------------------------------------------------------------------------------------
Emit "checks" "run" "Checking this PC"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail "checks" "Setup needs administrator rights." }
$cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$build = [int]$cv.CurrentBuildNumber
if ($cv.EditionID -notmatch '^(Professional|ProfessionalWorkstation|Enterprise|Education|ProfessionalEducation)') {
  Fail "checks" "Windows $($cv.EditionID) cannot run Hyper-V. Enclave hosting needs Windows 11 Pro, Enterprise or Education." }
if ($build -lt 26100) { Fail "checks" "Windows build $build is too old: update to Windows 11 24H2 or later." }
$cs = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
if (-not $cs.HypervisorPresent -and -not $cpu.VirtualizationFirmwareEnabled) {
  Fail "checks" "Virtualization is turned off in this PC's firmware. Restart into the BIOS/UEFI setup and turn on AMD-V (SVM) or Intel VT-x, then run setup again." }
$sb = $false; try { $sb = Confirm-SecureBootUEFI } catch { }
if (-not $sb) { Fail "checks" "Secure Boot is off. Turn it on in the BIOS/UEFI setup: hosts must prove a measured, secure boot." }
$bcd = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control" -Name SystemStartOptions -ErrorAction SilentlyContinue).SystemStartOptions
if ($bcd -match 'TESTSIGNING|NOINTEGRITYCHECKS') { Fail "checks" "Test signing or integrity-check bypass is on (bcdedit). Turn it off: a host must boot normally." }
$tpm = $null; try { $tpm = Get-Tpm } catch { }
if (-not $tpm -or -not $tpm.TpmPresent) { Fail "checks" "No TPM 2.0 found. Turn on the firmware TPM (AMD fTPM / Intel PTT) in the BIOS/UEFI setup." }
if ($tpm.ManufacturerIdTxt -notmatch 'AMD') {
  Fail "checks" "This PC's TPM ($($tpm.ManufacturerIdTxt)) cannot be verified yet: Enclave hosting currently supports AMD processors' firmware TPM." }
$ramGb = [math]::Floor($cs.TotalPhysicalMemory / 1GB)
if ($ramGb -lt 16) { Fail "checks" "This PC has $ramGb GB of RAM; hosting needs at least 16 GB." }
$freeGb = [math]::Floor((Get-PSDrive ($env:SystemDrive.TrimEnd(':'))).Free / 1GB)
if ($freeGb -lt 20) { Fail "checks" "Only $freeGb GB free on $env:SystemDrive; hosting needs at least 20 GB." }
Emit "checks" "ok" "Windows $($cv.DisplayVersion) build $build, $($cpu.Name.Trim()), $ramGb GB RAM, Secure Boot on, AMD TPM"

# ---------------------------------------------------------------------------------------------------------------------
# 2. Hyper-V (a restart may be needed; EnclaveSetup resumes after it)
# ---------------------------------------------------------------------------------------------------------------------
Emit "hyperv" "run" "Turning on Hyper-V"
$features = "Microsoft-Hyper-V-Hypervisor", "Microsoft-Hyper-V-Services", "Microsoft-Hyper-V-Management-PowerShell", "VirtualMachinePlatform"
$restart = $false
foreach ($f in $features) {
  $s = Get-WindowsOptionalFeature -Online -FeatureName $f
  if ($s.State -ne "Enabled") {
    $r = Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart
    if ($r.RestartNeeded) { $restart = $true }
  }
}
if ($restart -or -not $cs.HypervisorPresent) {
  if ($CheckOnly) { Emit "hyperv" "warn" "Hyper-V will be turned on during setup (a restart is needed)"; exit 0 }
  Emit "hyperv" "reboot" "Hyper-V is turned on. Restart this PC to finish; setup continues by itself after the restart."
  exit 3010
}
if (-not (Get-Service vmms -ErrorAction SilentlyContinue)) { Fail "hyperv" "The Hyper-V service (vmms) is missing after enabling Hyper-V. Restart and run setup again." }
Emit "hyperv" "ok" "Hyper-V is on"
if ($CheckOnly) { Emit "done" "ok" "This PC can host"; exit 0 }

# ---------------------------------------------------------------------------------------------------------------------
# 3. the name, and who this host is (ENCLAVE-IDENTITY-RECORD-V1)
# ---------------------------------------------------------------------------------------------------------------------
if ($Name -notmatch '^[a-z0-9](?:[a-z0-9-]{1,30})[a-z0-9]$' -or $Name -match '--') { Fail "name" "Pick a name of 3 to 32 lowercase letters, digits and hyphens." }
$existing = Join-Path $PD "node\host.json"
$rec = if (Test-Path $existing) { Get-Content $existing -Raw | ConvertFrom-Json } else { $null }
$sameBox = $rec -and $rec.name -eq $Name
function RelayIdentity($relay) { [pscustomobject]@{ mode = "relay"; publicUrl = "$relay/t/$Name"; relay = $relay; gateways = @(); rpcs = @(); directories = @(); checkers = @(); contractPinsSha256 = "" } }
# what this host IS: its recorded identity; a host installed before identities were recorded is the relay host it always was
$recorded = if ($rec -and $rec.identity) { $rec.identity } elseif ($sameBox) { RelayIdentity $Relay } else { $null }
if ($recorded -and $recorded.mode -eq "relay") { $recorded = RelayIdentity $recorded.relay }   # a relay identity follows its name
$explicit = $NoRelay -or $PublicUrl -or $Gateways -or $ContractPins -or $Rpcs -or $Directories -or $NetworkCheckers
if ($explicit) {
  if (-not $NoRelay) { Fail "identity" "-PublicUrl, -Gateways, -ContractPins, -Rpcs, -Directories and -NetworkCheckers describe an independent host: add -NoRelay (the relay honours only its own /t/<name> route)." }
  if (-not $PublicUrl -or -not $Gateways -or -not $ContractPins) { Fail "identity" "An independent host needs -PublicUrl (its own public endpoint), -Gateways (artifact gateways) and -ContractPins (the contract pin document): nothing defaults to an Enclave service." }
  if ($PublicUrl -notmatch '^https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*[A-Za-z0-9._~-])?$') { Fail "identity" "-PublicUrl must be an https URL written exactly as it will be registered, with no trailing slash, query or credentials." }
  foreach ($u in @(List $Gateways) + @(List $Rpcs) + @(List $Directories)) { if ($u -notmatch '^https://[^\s?#@]+$') { Fail "identity" "'$u' is not an https URL." } }
  # the chain name check (host-identity.mjs) decides only on two agreeing RPCs, so one RPC, or two on one host, never decides
  $rpcHosts = @(@(List $Rpcs) | ForEach-Object { ([Uri]$_).Host.ToLowerInvariant() })
  if ($rpcHosts.Count -and ($rpcHosts.Count -lt 2 -or @($rpcHosts | Select-Object -Unique).Count -ne $rpcHosts.Count)) { Fail "identity" "-Rpcs must name at least two RPCs on distinct hosts: one RPC never decides what the chain says." }
  foreach ($c in @(List $NetworkCheckers)) { if ($c -notmatch '^0x[0-9a-fA-F]{40}$') { Fail "identity" "'$c' is not a checker address." } }
  if (-not (Test-Path -LiteralPath $ContractPins)) { Fail "identity" "The contract pin document $ContractPins does not exist." }
  $want = [pscustomobject]@{ mode = "independent"; publicUrl = $PublicUrl; relay = ""; gateways = @(List $Gateways); rpcs = @(List $Rpcs)
                             directories = @(List $Directories); checkers = @(List $NetworkCheckers | ForEach-Object { $_.ToLower() }); contractPinsSha256 = (Sha $ContractPins) }
} elseif ($PSBoundParameters.ContainsKey("Relay") -or -not $recorded) { $want = RelayIdentity $Relay }
else { $want = $recorded }
function IdKey($i) { if (-not $i) { return "" }; "$($i.mode)|$(if ($i.mode -eq 'relay') { $i.relay } else { $i.publicUrl })|$(@($i.gateways) -join ',')|$(@($i.rpcs) -join ',')|$(@($i.directories) -join ',')|$(@($i.checkers) -join ',')|$($i.contractPinsSha256)" }
if ($recorded -and (IdKey $recorded) -ne (IdKey $want) -and -not $Reconfigure) {
  Fail "identity" ("This host is recorded as the $($recorded.mode) host $($recorded.publicUrl). Changing its relay, endpoint, gateways, pins, RPCs, directories or checkers needs -Reconfigure" +
                   $(if ($recorded.publicUrl -ne $want.publicUrl) { " - and $($want.publicUrl) is a NEW host on chain (a new registry entry and a new ownership enrollment)." } else { "." })) }
$independent = $want.mode -eq "independent"
if (-not $NameCheck) { $NameCheck = if ($independent) { "chain" } else { "relay" } }
if (-not $independent -and $NameCheck -ne "relay") { Fail "name" "A relay host's name is its route on the relay, so the relay checks it: -NameCheck chain and offline are for independent hosts (-NoRelay)." }
if ($independent -and $NameCheck -eq "relay") { Fail "name" "An independent host has no relay route to reserve: use -NameCheck chain (the pinned registry) or offline." }
# A referral code: 1-64 letters, digits, '.', '_' or '-'. Re-running setup or an automatic update (which passes no code)
# keeps the one this machine was installed with; a new one given here replaces it, and the relay keeps the first it saw.
$Referral = $Referral.Trim()
if ($Referral -and $Referral -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') { Fail "name" "A referral code is 1 to 64 letters, digits, '.', '_' or '-'." }
if (-not $Referral -and $rec) { $Referral = [string]$rec.referral }
if ($NameCheck -eq "relay" -and -not $sameBox) {
  try { $avail = Invoke-RestMethod -UseBasicParsing -Uri "$($want.relay)/v1/hosts/name/$Name" -TimeoutSec 20 }
  catch { Fail "name" "Could not reach $($want.relay) to check the name: $($_.Exception.Message)" }
  if (-not $avail.available) { Fail "name" "The name '$Name' is not available: $($avail.reason)" }
}
# The release policy (release-channel.mjs) and the pin document are checked now, with the bundle's own node, before anything
# on this PC is stopped or replaced; they are written once the program files are in place.
$bnode = Join-Path $Bundle "runtime\node\node.exe"; $bnodeDir = Join-Path $Bundle "control\windows\node"
$policyDest = Join-Path $PD "node\release-policy.json"; $pinsDest = Join-Path $PD "node\contract-pins.json"
if ($ReleasePolicy) {
  if (-not (Test-Path -LiteralPath $ReleasePolicy)) { Fail "release" "The release policy $ReleasePolicy does not exist." }
  $chk = NodeRun $bnode @((Join-Path $bnodeDir "release-channel.mjs"), "check-policy", $ReleasePolicy)
  if ($chk.code) { Fail "release" "The release policy is not valid: $($chk.out)" }
  if (Test-Path -LiteralPath $policyDest) {
    $have = NodeRun $bnode @((Join-Path $bnodeDir "release-channel.mjs"), "check-policy", $policyDest)
    if ($have.out -ne $chk.out -and -not $Reconfigure) { Fail "release" "This host already pins a different release policy ($policyDest): changing its release keys or mirrors needs -Reconfigure." }
  }
}
if ($independent -and $ContractPins) {
  $pinsOk = NodeRun $bnode @("--input-type=module", "-e", "import fs from 'node:fs'; import { validateContractPins } from 'file:///$((Join-Path $bnodeDir 'host-admission.bundle.mjs').Replace('\','/'))'; validateContractPins(JSON.parse(fs.readFileSync(process.argv[1], 'utf8').replace(/^\uFEFF/, ''))); process.stdout.write('pins-ok')", $ContractPins)
  if ($pinsOk.out -ne "pins-ok") { Fail "identity" "The contract pin document is not valid: $($pinsOk.out)" }
}
if ($independent -and -not $ContractPins -and -not (Test-Path -LiteralPath $pinsDest)) { Fail "identity" "This independent host's contract pin document ($pinsDest) is missing: re-run with -ContractPins and -Reconfigure." }
if ($independent) {
  Emit "name" $(if ($NameCheck -eq "offline") { "warn" } else { "ok" }) ("This host will be '$Name' at $($want.publicUrl) (independent: no Enclave relay)" +
    $(if ($NameCheck -eq "offline") { "; the endpoint is NOT checked against the chain (-NameCheck offline): if another operator registered it, this host's registration fails" } else { "; the endpoint is checked on the pinned registry once this host's key exists" }))
} else { Emit "name" "ok" "This host will be '$Name'" }

# ---------------------------------------------------------------------------------------------------------------------
# 4. host prerequisites for Enclave Shield's partitions
# ---------------------------------------------------------------------------------------------------------------------
$virt = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization"
if (-not (Test-Path $virt)) { New-Item $virt -Force | Out-Null }
New-ItemProperty -Path $virt -Name AllowFirmwareLoadFromFile -PropertyType DWord -Value 1 -Force | Out-Null
$gcs = "$virt\GuestCommunicationServices\00002329-facb-11e6-bd58-64006a7986d3"
if (-not (Test-Path $gcs)) { New-Item $gcs -Force | Out-Null }
New-ItemProperty -Path $gcs -Name ElementName -PropertyType String -Value "Enclave Shield report signing (hv_sock port 9001)" -Force | Out-Null
# a GPU app's partition reaches the card worker through shielded-bridge on hv_sock port 19595 (0x4c8b)
$gcsGpu = "$virt\GuestCommunicationServices\00004c8b-facb-11e6-bd58-64006a7986d3"
if (-not (Test-Path $gcsGpu)) { New-Item $gcsGpu -Force | Out-Null }
New-ItemProperty -Path $gcsGpu -Name ElementName -PropertyType String -Value "Enclave Shield GPU transport (hv_sock port 19595)" -Force | Out-Null
Emit "prereq" "ok" "Hyper-V is set up for Enclave Shield partitions"

# ---------------------------------------------------------------------------------------------------------------------
# 5. files: the program in Program Files, state in ProgramData (SYSTEM + Administrators only)
# ---------------------------------------------------------------------------------------------------------------------
Emit "files" "run" "Installing Enclave"
# every service but \Enclave\Update: an automatic update (update-host.ps1) runs this script from that task
foreach ($t in Get-ScheduledTask -TaskPath "\Enclave\" -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -ne "Update" }) { Stop-ScheduledTask -TaskPath "\Enclave\" -TaskName $t.TaskName -ErrorAction SilentlyContinue }
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($PF, [StringComparison]::OrdinalIgnoreCase) } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep 2
$manifest = Get-Content (Join-Path $Bundle "manifest.json") -Raw | ConvertFrom-Json
$installedManifest = Join-Path $PF "manifest.json"
$inPF = { param($e) $e.path -match '^(runtime|control|network|bin|guest|tray)/' }
if ($Delta -and (Test-Path $installedManifest)) {
  # AN UPDATE: Program Files already holds the installed release, whose manifest says what each file is. Only the files
  # whose sha256 changed are copied, files the new release no longer has are removed, and only the copied ones are
  # re-hashed: a one-file release touches one file, not 14,000.
  $old = @{}; foreach ($e in (Get-Content $installedManifest -Raw | ConvertFrom-Json).files) { $old[$e.path] = $e.sha256 }
  $want = @($manifest.files | Where-Object { & $inPF $_ })
  $changed = @($want | Where-Object { $old[$_.path] -ne $_.sha256 -or -not (Test-Path -LiteralPath (Join-Path $PF ($_.path -replace '/', '\'))) })
  foreach ($e in $changed) {
    $dst = Join-Path $PF ($e.path -replace '/', '\'); New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
    Copy-Item -LiteralPath (Join-Path $Bundle ($e.path -replace '/', '\')) $dst -Force
  }
  $keep = @{}; foreach ($e in $want) { $keep[$e.path] = 1 }
  # tuna/: the network agent's directory before release .35 (now network/), removed with everything it held
  $gone = @($old.Keys | Where-Object { $_ -match '^(runtime|control|network|tuna|bin|guest|tray)/' -and -not $keep.ContainsKey($_) })
  foreach ($g in $gone) { Remove-Item -LiteralPath (Join-Path $PF ($g -replace '/', '\')) -Force -ErrorAction SilentlyContinue }
  if (Test-Path (Join-Path $PF "tuna")) { Remove-Item (Join-Path $PF "tuna") -Recurse -Force -ErrorAction SilentlyContinue }
  $check = $changed
} else {
  if (Test-Path $PF) { Remove-Item $PF -Recurse -Force }
  New-Item -ItemType Directory -Force $PF | Out-Null
  foreach ($d in "runtime", "control", "network", "bin", "guest", "tray") { Copy-Item (Join-Path $Bundle $d) (Join-Path $PF $d) -Recurse -Force }
  $changed = $null; $gone = @()
  $check = @($manifest.files | Where-Object { & $inPF $_ })
}
Copy-Item (Join-Path $Bundle "manifest.json"), (Join-Path $Bundle "uninstall-host.ps1"), (Join-Path $Bundle "update-host.ps1") $PF -Force
$bad = @($check | Where-Object { $p = Join-Path $PF ($_.path -replace '/', '\'); -not (Test-Path -LiteralPath $p) -or (Sha $p) -ne $_.sha256 })
if ($bad.Count) { Fail "files" "$($bad.Count) installed file(s) do not match the bundle's manifest (first: $($bad[0].path))." }
# Settings > Apps > Installed apps: "Enclave", with Uninstall. Written now, not at the end, so a half-finished install can be
# removed too. EnclaveSetup.exe --uninstall copies itself out of Program Files and runs uninstall-host.ps1 with progress;
# without it (a scripted install), the script itself is the uninstaller.
if ($SetupExe -and (Test-Path -LiteralPath $SetupExe)) { Copy-Item -LiteralPath $SetupExe (Join-Path $PF "EnclaveSetup.exe") -Force }
$un = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\EnclaveHost"
$script = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $PF 'uninstall-host.ps1')`""
New-Item -Path $un -Force | Out-Null
$kb = [int]((Get-ChildItem $PF -Recurse -File | Measure-Object Length -Sum).Sum / 1KB)
foreach ($v in @(@("DisplayName", "Enclave", "String"), @("DisplayVersion", "$($manifest.version)", "String"), @("Publisher", "Enclave", "String"),
                 @("DisplayIcon", "$(Join-Path $PF 'tray\EnclaveTray.exe'),0", "String"), @("InstallLocation", $PF, "String"),
                 @("URLInfoAbout", "https://enclave.host/host", "String"), @("EstimatedSize", $kb, "DWord"),
                 @("NoModify", 1, "DWord"), @("NoRepair", 1, "DWord"), @("QuietUninstallString", $script, "String"),
                 @("UninstallString", $(if (Test-Path (Join-Path $PF "EnclaveSetup.exe")) { "`"$(Join-Path $PF 'EnclaveSetup.exe')`" --uninstall" } else { $script }), "String"))) {
  New-ItemProperty -Path $un -Name $v[0] -Value $v[1] -PropertyType $v[2] -Force | Out-Null
}
# The network agent's state was in ProgramData\Enclave\tuna until release .35: moved once to network\, with the paths in its
# config. Its route state must survive (a fresh one restarts the route sequence, which the relay refuses as a rollback), so a
# move that keeps failing (a scanner holding a file) falls back to a copy.
$oldNet = Join-Path $PD "tuna"; $newNet = Join-Path $PD "network"
if ((Test-Path $oldNet) -and -not (Test-Path $newNet)) {
  $moved = $false
  for ($i = 0; $i -lt 10 -and -not $moved; $i++) { try { Move-Item -LiteralPath $oldNet -Destination $newNet -ErrorAction Stop; $moved = $true } catch { Start-Sleep 2 } }
  if (-not $moved) { Copy-Item -LiteralPath $oldNet -Destination $newNet -Recurse -Force; Remove-Item -LiteralPath $oldNet -Recurse -Force -ErrorAction SilentlyContinue }
  $pc = Join-Path $newNet "privacy-config.json"
  if (Test-Path $pc) { [IO.File]::WriteAllText($pc, ([IO.File]::ReadAllText($pc)).Replace('\\Enclave\\tuna\\', '\\Enclave\\network\\')) }
  Emit "files" "run" "The network agent's state moved to $newNet"
}
if ((Test-Path (Join-Path $PD "logs\tuna.log")) -and -not (Test-Path (Join-Path $PD "logs\network.log"))) { Move-Item (Join-Path $PD "logs\tuna.log") (Join-Path $PD "logs\network.log") }
Remove-Item (Join-Path $PD "run-tuna.cmd") -Force -ErrorAction SilentlyContinue
if (Get-ScheduledTask -TaskPath "\Enclave\" -TaskName "Tuna" -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskPath "\Enclave\" -TaskName "Tuna" -Confirm:$false }
foreach ($d in "", "node", "shield", "shield\vmgs-archive", "shield\bundles", "network", "network\state", "logs") { New-Item -ItemType Directory -Force (Join-Path $PD $d) | Out-Null }
# the root: owners full, users may only pass through (the node opens hosting\ to the tray user itself); the rest: owners only
icacls $PD /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(RX)" /q | Out-Null
foreach ($d in "node", "shield", "network", "logs") { icacls (Join-Path $PD $d) /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /q | Out-Null }
# THE CUSTODY CALLBACK KEY (windows/vbslike/manager/custody-key-file.mjs): the HMAC key the manager and the node share for
# direct Shield custody answers. Created when ABSENT, private from its first byte: a protected DACL granting only SYSTEM and
# Administrators, owner Administrators, applied by the same call that creates it. An EXISTING file is checked by the same
# rule the manager and node apply at start and reported if it is not private: never changed here. Inert until the explicit
# activation sets ENCLAVE_CUSTODY_CALLBACK_KEY_FILE (and ENCLAVE_SHIELD_CUSTODY_V2); no other file is touched.
$ckey = Join-Path $PD "shield\custody-callback.key"
if (-not (Test-Path -LiteralPath $ckey)) {
  $kb = New-Object byte[] 32; $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($kb); $rng.Dispose()
  $sec = New-Object System.Security.AccessControl.FileSecurity
  $sec.SetAccessRuleProtection($true, $false)
  foreach ($sid in "S-1-5-18", "S-1-5-32-544") {
    $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier $sid), "FullControl", "Allow")))
  }
  $sec.SetOwner((New-Object System.Security.Principal.SecurityIdentifier "S-1-5-32-544"))
  $hex = [Text.Encoding]::ASCII.GetBytes((($kb | ForEach-Object { $_.ToString("x2") }) -join ""))
  $fsk = [System.IO.File]::Create($ckey, 4096, [System.IO.FileOptions]::None, $sec)
  try { $fsk.Write($hex, 0, $hex.Length) } finally { $fsk.Dispose() }
  [Array]::Clear($kb, 0, $kb.Length); [Array]::Clear($hex, 0, $hex.Length)
  Emit "files" "run" "Created the custody callback key $ckey (SYSTEM and Administrators only; inert until activation)"
} else {
  $acl = Get-Acl -LiteralPath $ckey
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  $open = @($acl.Access | Where-Object { $_.AccessControlType -eq "Allow" -and @("S-1-5-18", "S-1-5-32-544") -notcontains $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value })
  $nullDacl = $acl.GetSecurityDescriptorSddlForm("Access") -notmatch "D:" -or $acl.GetSecurityDescriptorSddlForm("Access") -match "D:[A-Z]*NO_ACCESS_CONTROL"
  if ($open.Count -or $nullDacl -or @("S-1-5-18", "S-1-5-32-544") -notcontains $owner) {
    Emit "files" "warn" ("The custody callback key $ckey is NOT private (owner $owner" + $(if ($open.Count) { "; allowed to $($open[0].IdentityReference)" } else { "" }) +
                         "): left unchanged, and the manager and node refuse it until it is SYSTEM and Administrators only")
  }
}
Emit "files" "ok" ("Enclave $($manifest.version) installed in $PF" + $(if ($null -ne $changed) { " ($($changed.Count) file(s) changed, $($gone.Count) removed)" } else { "" }))

# the pins and the release policy, into node\ (SYSTEM and Administrators only), never replaced unless asked (step 3)
$node = Join-Path $PF "runtime\node\node.exe"
if ($independent) {
  if ($ContractPins) { Copy-Item -LiteralPath $ContractPins $pinsDest -Force }
  if ((Sha $pinsDest) -ne $want.contractPinsSha256) { Fail "identity" "$pinsDest was changed outside setup: re-run with -ContractPins and -Reconfigure to pin a new document." }
}
if ($ReleasePolicy) {
  $ip = NodeRun $node (@((Join-Path $PF "control\windows\node\release-channel.mjs"), "install-policy", "--policy", $ReleasePolicy, "--dest", $policyDest) + @(if ($Reconfigure) { "--replace" }))
  if ($ip.code) { Fail "release" "The release policy was not installed: $($ip.out)" }
}
if (Test-Path -LiteralPath $policyDest) {
  $pol = NodeRun $node @((Join-Path $PF "control\windows\node\release-channel.mjs"), "check-policy", $policyDest)
  if ($pol.code) { Fail "release" "$policyDest is not a valid release policy: $($pol.out). Updates would refuse every release; fix it or re-run with -ReleasePolicy and -Reconfigure." }
  $pj = $pol.out | ConvertFrom-Json
  Emit "release" "ok" "Updates: only releases signed by $($pj.threshold) of $(@($pj.keys).Count) pinned key(s), from $(@($pj.mirrors) -join ', ')"
} elseif ($independent) { Emit "release" "warn" "Updates: OFF. An independent host takes no unsigned Enclave release; pin a release policy (-ReleasePolicy, or release-channel.mjs install-policy) to update automatically" }
else { Emit "release" "warn" "Updates: the legacy get.enclave.host channel, which is UNSIGNED (its hashes come from the same unsigned latest.json). Pin a release policy to require signed releases (docs/network/independent-windows.md)" }

# ---------------------------------------------------------------------------------------------------------------------
# 6. this box's own: the guest-state master, the keys, the configuration
# ---------------------------------------------------------------------------------------------------------------------
$vmgs = Join-Path $PD "shield\type1.vmgs"
if (-not (Test-Path $vmgs)) {
  # a blank VBS guest state, as Hyper-V writes it for a new isolated VM (each box mints its own; only this box pins it)
  $tmpName = "enclave-shield-mint-" + [guid]::NewGuid().ToString("N").Substring(0, 8); $tmpDir = Join-Path $env:TEMP $tmpName
  try {
    New-VM -Name $tmpName -Generation 2 -NoVHD -Path $tmpDir -GuestStateIsolationType VBS | Out-Null
    $g = Get-ChildItem $tmpDir -Recurse -Filter *.vmgs | Select-Object -First 1
    if (-not $g) { Fail "shield" "Hyper-V made no guest-state file for a VBS-isolated VM." }
    Copy-Item $g.FullName $vmgs
  } finally { Get-VM -Name $tmpName -ErrorAction SilentlyContinue | Remove-VM -Force; Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
}
$vmgsSha = Sha $vmgs
# the Hyper-V module every partition launch loads, loaded once here: a module that cannot load (a file missing from the
# bundle) would otherwise only show as every app, and the readiness witness, failing to start
$probe = @(& powershell.exe -NoProfile -NonInteractive -Command "Import-Module '$(Join-Path $PF 'guest\hyperv.psm1')' -ErrorAction Stop; 'module-ok'" 2>&1)
if (($probe | Select-Object -Last 1) -ne "module-ok") { Fail "shield" "Enclave Shield's Hyper-V module does not load: $(($probe | Out-String).Trim())" }
Emit "shield" "ok" "Enclave Shield's guest-state master is ready"

$env:NODE_NAME = $Name; $env:PUBLIC_URL = $want.publicUrl
if ($independent) { $env:ENCLAVE_CONTRACT_PINS_FILE = $pinsDest; if (@($want.rpcs).Count) { $env:BASE_RPCS = @($want.rpcs) -join "," } }
$keys = NodeRun $node (@((Join-Path $PF "control\windows\node\keys.mjs"), (Join-Path $PD "node")) + @(if ($NameCheck -eq "offline") { "--offline" }))
if ($keys.code) { Fail "keys" "The node's keys could not be made: $($keys.out)" }
$operator = ([regex]::Match($keys.out, '"operator": "(0x[0-9a-fA-F]{40})"')).Groups[1].Value
if (-not $operator) { Fail "keys" "The node's keys did not report an operator address: $($keys.out)" }
Emit "keys" "ok" "Operator key $operator (created on this PC; it never leaves it)"
# the relay-free name check: keccak256(endpoint) is the registry id, so the collision that matters is another operator's
# entry for this endpoint on the PINNED registry, read through agreeing RPCs (host-identity.mjs)
# Not repeated for an unchanged identity on the same box (an automatic update): it was checked when it was recorded, and an
# update must not fail because the RPCs are slow that hour.
$unchanged = $sameBox -and $recorded -and (IdKey $recorded) -eq (IdKey $want) -and -not $PSBoundParameters.ContainsKey("NameCheck")
if ($NameCheck -eq "chain" -and $unchanged) { Emit "name" "ok" "$($want.publicUrl): this host's recorded identity, unchanged" }
elseif ($NameCheck -eq "chain") {
  $chk = NodeRun $node (@((Join-Path $PF "control\windows\node\host-identity.mjs"), "check-endpoint", "--endpoint", $want.publicUrl, "--operator", $operator, "--pins", $pinsDest) +
                        @(@($want.rpcs) | ForEach-Object { "--rpc"; $_ }))
  if ($chk.code -eq 2) { Fail "name" "$($want.publicUrl) is registered on chain to another operator ($(($chk.out | ConvertFrom-Json).operator)): choose another public endpoint." }
  if ($chk.code) { Fail "name" "Could not check $($want.publicUrl) on the pinned registry: $($chk.out). Re-run when the RPCs answer, or with -NameCheck offline to skip the check." }
  $st = ($chk.out | ConvertFrom-Json).status
  Emit "name" "ok" "$($want.publicUrl) is $(if ($st -eq 'ours') { "already this host's (operator $operator)" } else { 'free' }) on the pinned registry"
}

$appRamGb = [math]::Max(4, [math]::Floor($ramGb / 2))
# an owner who gives apps more (or less) than half sets NODE_APP_RAM_GB in node-config.local.cmd (never written by an
# update). The node reads that file itself; the Shield manager does not, so the figure is carried into shield-config.cmd
# here, or the manager refuses partitions the node admitted. It stays at least 16 GB short of the machine.
$localRam = Join-Path $PD "node-config.local.cmd"
if (Test-Path $localRam) {
  $m = Select-String -Path $localRam -Pattern '^set NODE_APP_RAM_GB=(\d+)\s*$' | Select-Object -Last 1
  if ($m) { $appRamGb = [math]::Max(4, [math]::Min($ramGb - 16, [int]$m.Matches[0].Groups[1].Value)) }
}
# one slot per 4 GB of the apps' half, up to 16: the count is only a ceiling (capacity() also holds every app to the RAM
# left), and 8 refused a 2 GB app on a 112 GB box running seven small ones and one 12 GB one (2026-10-14)
$slots = [math]::Max(1, [math]::Min(16, [math]::Floor($appRamGb / 4)))
$runtimeJson = Join-Path $PF "guest\runtime.json"
$runtimeId = & $node --input-type=module -e "import fs from 'node:fs'; import { runtimeId } from 'file:///$((Join-Path $PF 'control\isolation\contract\runtime.mjs').Replace('\','/'))'; process.stdout.write(Buffer.from(runtimeId(JSON.parse(fs.readFileSync(process.argv[1], 'utf8')))).toString('hex'))" $runtimeJson
if ($runtimeId -notmatch '^[0-9a-f]{64}$') { Fail "config" "The runtime identity could not be derived: $runtimeId" }
# the platform's readiness witness must run on this bundle's runtime, or the relay never opens the market to this host
$witnessFile = Join-Path $PF "guest\witness.json"
$witness = Get-Content -Raw $witnessFile | ConvertFrom-Json
if ($witness.derive.runtimeId -ne $runtimeId) { Fail "config" "The bundle's readiness witness is for runtime $($witness.derive.runtimeId), not this bundle's $runtimeId" }
$pin = { param($rel) ($manifest.files | Where-Object { $_.path -eq $rel }).sha256 }
# Enclave Shield's GPU profile (windows/vbslike/SHIELDED-GPU.md): the measured GPU image, the bridge, and the card worker's
# port. The manager offers a GPU share only while the worker answers with the profile's budget, so a PC whose card the
# worker cannot drive sells no GPU and nothing else changes.
$gpuProfile = Join-Path $PD "shield-gpu-profile.json"
$gpuImage = Join-Path $PF "guest\runtime-shield-gpu.bin"
if (Test-Path $gpuImage) {
  "{`"runtime`":$((Get-Content -Raw $runtimeJson).Trim()),`"imagePath`":$($gpuImage | ConvertTo-Json),`"imageSha256`":`"$(& $pin 'guest/runtime-shield-gpu.bin')`"," +
    "`"bridgeExe`":$((Join-Path $PF 'bin\shielded-bridge.exe') | ConvertTo-Json),`"bridgeSha256`":`"$(& $pin 'bin/shielded-bridge.exe')`",`"workerPort`":19595}" |
    Set-Content -Encoding ASCII $gpuProfile
} elseif (Test-Path $gpuProfile) { Remove-Item $gpuProfile -Force }
if (-not $Owner) { $Owner = (Get-CimInstance Win32_ComputerSystem).UserName }
if (-not $Owner) { $Owner = "$env:USERDOMAIN\$env:USERNAME" }

@"
@echo off
rem Enclave Shield: the per-app Hyper-V isolation manager. Written by install-host.ps1; re-run setup to change it.
set VMMGR_PORT=8091
set ENCLAVE_GUEST_IGVM=$PF\guest\runtime.bin
set ENCLAVE_GUEST_IGVM_SHA256=$(& $pin 'guest/runtime.bin')
set ENCLAVE_BOOT_FORM=linux-direct
set ENCLAVE_GUEST_STATE_MASTER=$vmgs
set ENCLAVE_GUEST_STATE_MASTER_SHA256=$vmgsSha
set ENCLAVE_GUEST_STATE_ARCHIVE_DIR=$PD\shield\vmgs-archive
set ENCLAVE_HYPERV_MODULE=$PF\guest\hyperv.psm1
set ENCLAVE_HYPERV_MODULE_SHA256=$(& $pin 'guest/hyperv.psm1')
set ENCLAVE_RUNTIME_IDENTITY=$runtimeJson
set PYTHON_BIN=$PF\runtime\python\python.exe
set PYTHONDONTWRITEBYTECODE=1
$(if ($independent) { "set IPFS_GATEWAYS=$(@($want.gateways) -join ',')`r`nset IPFS_GATEWAY=$(@($want.gateways)[0])" } else { "set IPFS_GATEWAY=https://ipfs.enclave.host" })
set ENCLAVE_WMISERVE_EXE=$PF\bin\shield-host.exe
set ENCLAVE_WMISERVE_EXE_SHA256=$(& $pin 'bin/shield-host.exe')
set ENCLAVE_BUNDLE_DIR=$PD\shield\bundles
set ENCLAVE_DATAPLANE_PORT=8092
set ENCLAVE_LIVENESS_MS=15000
set ENCLAVE_ANSWER_CHECK_MS=30000
set ENCLAVE_CONFIG_BUNDLE_V5=1
set ENCLAVE_CONFIG_SOCKET_SERVER_V1=1
rem sealed secrets; the manager also gates protected ports and app egress on this, so without it all three are off
set ENCLAVE_SECRETS_V1=1
set ENCLAVE_EGRESS_V1=1
set ENCLAVE_EGRESS_EXE=$PF\bin\shield-egress.exe
set ENCLAVE_EGRESS_EXE_SHA256=$(& $pin 'bin/shield-egress.exe')
set ENCLAVE_EGRESS_BRIDGE_EXE=$PF\bin\shielded-bridge.exe
set ENCLAVE_EGRESS_BRIDGE_EXE_SHA256=$(& $pin 'bin/shielded-bridge.exe')
set ENCLAVE_EGRESS_APP_ROUTES=$PD\network\state\egress-routes.json
rem public, pinned content an app asks blobs.enclave.internal for comes from the node's host-side cache, not its paid route
rem (docs/design/shield-blob-cache.md); the bundle's shield-egress must be the -blob-service build (build-bundle.ps1 pins it)
set ENCLAVE_EGRESS_BLOB_SERVICE=127.0.0.1:9621
set NODE_APP_RAM_GB=$appRamGb
set ENCLAVE_PROTECTED_PORTS_V1=1
set ENCLAVE_WASM_SET=1
set ENCLAVE_WASM_MEMORY64=1
$(if (Test-Path $gpuProfile) { "set ENCLAVE_SHIELD_PROFILE=$gpuProfile" })
"@ | Set-Content -Encoding ASCII (Join-Path $PD "shield-config.cmd")

# the card worker: the GPU half of a Shield GPU app, on 127.0.0.1:19595 only, holding at most the profile's 12 GiB; it sees
# only masked data (the app's partition masks, unmasks and verifies). The yield build backs off while the owner uses the card.
@"
@echo off
rem The Enclave card worker. Written by install-host.ps1; re-run setup to change it.
set SHIELDED_VK_SHADERS=$PF\bin\shaders
if not defined SHIELDED_CARD_TFLOPS set SHIELDED_CARD_TFLOPS=8
cd /d "$PF\bin"
:loop
"$PF\bin\shielded-worker.exe" --host 127.0.0.1 --port 19595 --vram-gb 12 >> "$PD\logs\card.log" 2>&1
echo %date% %time% [run] card worker exited %errorlevel%; restarting in 30 s >> "$PD\logs\card.log"
ping -n 31 127.0.0.1 >nul
goto loop
"@ | Set-Content -Encoding ASCII (Join-Path $PD "run-card.cmd")

# A box's own node settings live in node-config.local.cmd, which updates leave alone. Settings an operator set by hand in
# node-config.cmd before it existed (the apps this box respawns after a crash) are carried into it once, so an update
# does not silently drop them.
$nodeCfg = Join-Path $PD "node-config.cmd"; $nodeLocal = Join-Path $PD "node-config.local.cmd"
if ((Test-Path $nodeCfg) -and -not (Test-Path $nodeLocal)) {
  $carried = @(Get-Content $nodeCfg | Where-Object { $_ -match '^set ENCLAVE_ISOLATION_RESPAWN_IDS=0x[0-9a-fA-F]{64}(,0x[0-9a-fA-F]{64})*\s*$' })
  if ($carried.Count) {
    (@("@echo off", "rem This box's own node settings, read after node-config.cmd. Updates never write this file.") + $carried) |
      Set-Content -Encoding ASCII $nodeLocal
    Emit "config" "run" "Kept this box's own node settings in $nodeLocal"
  }
}
@"
@echo off
rem The Enclave host node. Written by install-host.ps1; re-run setup to change it.
set APPS=1
set NODE_NAME=$Name
set REFERRAL_CODE=$Referral
set PUBLIC_URL=$($want.publicUrl)
set RELAY_URL=$(if ($independent) { "none" } else { "$($want.relay -replace '^https:', 'wss:')/v1/fleet-tunnel" })
$(if ($independent) { "set ENCLAVE_IDENTITY_MODE=independent`r`nset ENCLAVE_CONTRACT_PINS_FILE=$pinsDest" })
$(if (@($want.rpcs).Count) { "set BASE_RPCS=$(@($want.rpcs) -join ',')" })
set NODE_DIR=$PD\node
set TPMATTEST_EXE=$PF\bin\tpmattest.exe
set ENCLAVE_ISOLATION_MANAGER=http://127.0.0.1:8091
set ENCLAVE_ISOLATION_RUNTIME_ID=$runtimeId
set ENCLAVE_ISOLATION_DATA_ADDR=127.0.0.1:8092
set CLAIM_SCOPE=market
set LOCAL_HTTP_PORT=9600
set HOSTING_TRAY_USER=$Owner
set PYTHON_BIN=$PF\runtime\python\python.exe
$(if ($independent) { "set IPFS_GATEWAYS=$(@($want.gateways) -join ',')" } else { "set IPFS_GATEWAY=https://ipfs.enclave.host" })
set APP_SLOTS=$slots
set NODE_APP_RAM_GB=$appRamGb
set ENCLAVE_EGRESS_APP_ROUTES=$PD\network\state\egress-routes.json
set WASMTIME_BIN=$PF\bin\wasmtime.exe
set SHIELD_WITNESS_CONFIG=$witnessFile
set ENCLAVE_NETWORK_AGENT_DIR=$PD\network
set ENCLAVE_NETWORK_BIN_DIR=$PF\network
set ENCLAVE_NETWORK_SHIELD_POLICY=$PF\network\admitted-shield-policy.json
rem an app whose config asks for startup egress gets its secrets only once its private route is up (missing file: pending)
set ENCLAVE_STARTUP_EGRESS_CONFIG=$PD\network\privacy-config.json
rem the host-side cache for public, pinned content (blob-cache.mjs): loopback only, 32 GB, least recently used out first
set BLOB_SERVICE_PORT=9621
set BLOB_CACHE_DIR=$PD\shield\blobs
rem the Enclave network (docs/design/enclave-network.md): every app's route and this box's own control traffic over
rem WireGuard providers qualified by these checkers
$(if (-not $independent) { "set ENCLAVE_NETWORK_CHECKERS=0x57144c9008cff0b3ed94f6e40964a321fbee848a,0x033bc2b92bb1bb97c7dadf2879d3048748e2257b" }
  elseif (@($want.checkers).Count) { "set ENCLAVE_NETWORK_CHECKERS=$(@($want.checkers) -join ',')" }
  else { "rem no checkers chosen (-NetworkCheckers): network enrollment refuses until this host's operator picks the ones it trusts" })
$(if (@($want.directories).Count) { "set ENCLAVE_NETWORK_DIRECTORIES=$(@($want.directories) -join ',')" })
rem this box's own settings (node-config.local.cmd: never written by an update), after and over everything above
if exist "$PD\node-config.local.cmd" call "$PD\node-config.local.cmd"
"@ | Set-Content -Encoding ASCII (Join-Path $PD "node-config.cmd")

# the network agent: every app's route on the Enclave network. The node writes its config with the first app it enrolls
# (control\windows\node\network-enroll.mjs); until then this loop waits for it.
@"
@echo off
rem The Enclave network agent. Written by install-host.ps1; re-run setup to change it.
cd /d "$PD\network"
:loop
if not exist "$PD\network\privacy-config.json" (
  ping -n 61 127.0.0.1 >nul
  goto loop
)
"$node" "$PF\network\privacy-agent.mjs" --config "$PD\network\privacy-config.json" >> "$PD\logs\network.log" 2>&1
echo %date% %time% [run] network agent exited %errorlevel%; restarting in 10 s >> "$PD\logs\network.log"
ping -n 11 127.0.0.1 >nul
goto loop
"@ | Set-Content -Encoding ASCII (Join-Path $PD "run-network.cmd")

function RunLoop($file, $config, $script, $log) {
@"
@echo off
call "$config"
cd /d "$(Split-Path $script)"
:loop
"$node" "$script" >> "$log" 2>&1
echo %date% %time% [run] exited %errorlevel%; restarting in 10 s >> "$log"
ping -n 11 127.0.0.1 >nul
goto loop
"@ | Set-Content -Encoding ASCII $file
}
RunLoop (Join-Path $PD "run-shield.cmd") (Join-Path $PD "shield-config.cmd") (Join-Path $PF "control\windows\vbslike\manager\main.mjs") (Join-Path $PD "logs\shield.log")
RunLoop (Join-Path $PD "run-node.cmd") (Join-Path $PD "node-config.cmd") (Join-Path $PF "control\windows\node\agent.mjs") (Join-Path $PD "logs\node.log")
[ordered]@{ name = $Name; operator = $operator; owner = $Owner; referral = $Referral; version = $manifest.version; installedAt = (Get-Date).ToUniversalTime().ToString("o")
            identity = [ordered]@{ format = "enclave-host-identity/v1"; mode = $want.mode; publicUrl = $want.publicUrl; relay = $want.relay
                                   gateways = @($want.gateways); rpcs = @($want.rpcs); directories = @($want.directories); checkers = @($want.checkers)
                                   contractPinsSha256 = $want.contractPinsSha256 } } |
  ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 $existing
Emit "config" "ok" "Configured '$Name': $slots app slot(s), $appRamGb GB for apps"
if ($independent) {
  Emit "config" "warn" ("Independent: owner-only scope (the Shield market opens only on an attached relay's attestation verdict); no relay-held secrets, " +
                        "relay certificates or custom domains; the operator key pays its own registration gas. See docs/network/independent-windows.md")
}

# ---------------------------------------------------------------------------------------------------------------------
# 7. the services: \Enclave\Shield, then \Enclave\Node, as SYSTEM, at every boot
# ---------------------------------------------------------------------------------------------------------------------
function Task($name, $cmd, $delay) {
  $a = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$cmd`""
  $t = New-ScheduledTaskTrigger -AtStartup; $t.Delay = $delay
  $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskPath "\Enclave\" -TaskName $name -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
}
Task "Shield" (Join-Path $PD "run-shield.cmd") "PT30S"
if (Test-Path (Join-Path $PF "bin\shielded-worker.exe")) { Task "Card" (Join-Path $PD "run-card.cmd") "PT20S" }
Task "Node" (Join-Path $PD "run-node.cmd") "PT90S"
Task "Network" (Join-Path $PD "run-network.cmd") "PT120S"
# automatic updates (update-host.ps1): 5 minutes after boot, then every hour, as SYSTEM; one run at a time. Left as it is
# while an update is the one running this script.
if ($env:ENCLAVE_UPDATING -ne "1" -or -not (Get-ScheduledTask -TaskPath "\Enclave\" -TaskName "Update" -ErrorAction SilentlyContinue)) {
  $ua = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$(Join-Path $PF 'update-host.ps1')`""
  $boot = New-ScheduledTaskTrigger -AtStartup; $boot.Delay = "PT5M"
  $hourly = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(15) -RepetitionInterval (New-TimeSpan -Hours 1)
  $us = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskPath "\Enclave\" -TaskName "Update" -Action $ua -Trigger $boot, $hourly -Settings $us `
    -Principal (New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest) -Force | Out-Null
}
if (Get-ScheduledTask -TaskPath "\Enclave\" -TaskName "Card" -ErrorAction SilentlyContinue) { Start-ScheduledTask -TaskPath "\Enclave\" -TaskName "Card" }
Start-ScheduledTask -TaskPath "\Enclave\" -TaskName "Shield"
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep 2
  try { $h = Invoke-RestMethod -UseBasicParsing -Uri "http://127.0.0.1:8091/health" -TimeoutSec 5; if ($h.canStart -or $h.ok) { $ready = $true; break } } catch { }
}
if (-not $ready) { Fail "services" "Enclave Shield did not come up (see $PD\logs\shield.log)." }
if ($NoStart) {
  Disable-ScheduledTask -TaskPath "\Enclave\" -TaskName "Node" | Out-Null
  Disable-ScheduledTask -TaskPath "\Enclave\" -TaskName "Network" | Out-Null
  Emit "services" "ok" "Enclave Shield is running; the node is installed but NOT started (-NoStart): nothing registers"
  Emit "done" "ok" "Installed without joining the network"; exit 0
}
Start-ScheduledTask -TaskPath "\Enclave\" -TaskName "Node"
Start-ScheduledTask -TaskPath "\Enclave\" -TaskName "Network"
Emit "services" "ok" "Enclave Shield, the node and the private-route agent are running, and start with Windows"

# ---------------------------------------------------------------------------------------------------------------------
# 8. join the network: hardware attestation, then the sponsored registration (no ETH needed)
# ---------------------------------------------------------------------------------------------------------------------
Emit "join" "run" $(if ($independent) { "Registering $($want.publicUrl) from the operator key (it needs a little Base ETH for gas)" } else { "Proving this PC's hardware to the network and registering '$Name'" })
$log = Join-Path $PD "logs\node.log"; $joined = $false
for ($i = 0; $i -lt 90; $i++) {
  Start-Sleep 4
  $tail = if (Test-Path $log) { Get-Content $log -Tail 200 -ErrorAction SilentlyContinue } else { @() }
  if ($tail -match 'registry: registered|listed as') { $joined = $true; break }
  $refused = $tail | Where-Object { $_ -match 'attach refused|denied|did not sponsor' } | Select-Object -Last 1
  if ($refused) { Emit "join" "warn" ($refused -replace '^.*?\] ', '') }
}
if ($joined) { Emit "join" "ok" "'$Name' is registered and attached: it takes work from the network" }
elseif ($independent) { Emit "join" "warn" "'$Name' is installed but not registered yet: send operator $operator a little Base ETH and it registers itself (see $log)" }
else { Emit "join" "warn" "'$Name' is installed but not registered yet; it keeps trying (see $log)" }

# ---------------------------------------------------------------------------------------------------------------------
# 9. the tray, for the owner
# ---------------------------------------------------------------------------------------------------------------------
Emit "tray" "run" "Installing the Enclave tray for $Owner"
$me = "$env:USERDOMAIN\$env:USERNAME"
# The tray it starts must NOT inherit this script's output: EnclaveSetup reads it through a pipe, and a running tray holding
# that pipe kept this step "running" until the tray exited (nucbox-k11-2, 2026-10-12). ShellExecute passes no standard
# handles at all, and WaitForExit waits for cmd alone (Start-Process -Wait would wait for the tray too).
if ($Owner -ieq $me) {
  $si = New-Object Diagnostics.ProcessStartInfo "cmd.exe", "/c `"$(Join-Path $PF 'tray\install-tray.cmd')`""
  $si.UseShellExecute = $true; $si.WindowStyle = "Hidden"
  $p = [Diagnostics.Process]::Start($si); if (-not $p.WaitForExit(120000)) { Emit "tray" "warn" "The tray install is taking long; it carries on by itself" }
}
elseif ($Owner) {
  # another account (an automatic update runs as SYSTEM): install it in the owner's session if they are signed in; if not,
  # the tray refreshes itself from Program Files at their next sign-in (EnclaveTray's own start-up check)
  try {
    # the running tray holds its exe open and refuses a polite close; this account (SYSTEM, elevated) can end any copy
    Get-Process EnclaveTray -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $a = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$(Join-Path $PF 'tray\install-tray.cmd')`""
    Register-ScheduledTask -TaskName "EnclaveTrayInstall" -Action $a -Principal (New-ScheduledTaskPrincipal -UserId $Owner -LogonType Interactive) -Force | Out-Null
    Start-ScheduledTask -TaskName "EnclaveTrayInstall"
    $t0 = Get-Date
    do { Start-Sleep 1 } while ((Get-ScheduledTask -TaskName "EnclaveTrayInstall").State -eq "Running" -and ((Get-Date) - $t0).TotalSeconds -lt 60)
  } catch { Emit "tray" "warn" "The tray was not refreshed for $Owner now ($($_.Exception.Message)); it updates itself at their next sign-in" }
  finally { Unregister-ScheduledTask -TaskName "EnclaveTrayInstall" -Confirm:$false -ErrorAction SilentlyContinue }
}
Emit "tray" "ok" "Open 'Enclave Hosting' from the tray, the Desktop or the Start Menu to set your payout wallet and caps"

# ---------------------------------------------------------------------------------------------------------------------
# EnclaveDNS (optional): this PC's DNS through Enclave's resolver, and .eth names in the browser, so EnclaveHost.eth
# stays reachable if enclave.host is not. Its own installer, from the bundle, silently: it installs the EnclaveDNS
# service, points DNS at it (one NRPT rule) and trusts its .eth-only CA. A failure here never fails the host install.
# ---------------------------------------------------------------------------------------------------------------------
if ($EnclaveDNS) {
  Emit "enclavedns" "run" "Installing EnclaveDNS"
  $dnsSetup = Join-Path $Bundle "enclavedns\EnclaveDNS-Setup.exe"
  if (-not (Test-Path -LiteralPath $dnsSetup)) {
    Emit "enclavedns" "warn" "This bundle has no EnclaveDNS installer; skipped (get it from github.com/EnclaveHost/enclavedns-client)"
  } else {
    try {
      $p = Start-Process -FilePath $dnsSetup -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/TASKS=enable,path" -Wait -PassThru
      $svc = Get-Service -Name EnclaveDNS -ErrorAction SilentlyContinue
      if ($p.ExitCode -eq 0 -and $svc -and $svc.Status -eq "Running") {
        Emit "enclavedns" "ok" "EnclaveDNS is this PC's DNS; .eth names such as EnclaveHost.eth open in the browser after it restarts"
      } else {
        Emit "enclavedns" "warn" "EnclaveDNS did not finish installing (exit $($p.ExitCode)); hosting is unaffected. Its installer: github.com/EnclaveHost/enclavedns-client"
      }
    } catch {
      Emit "enclavedns" "warn" "EnclaveDNS was not installed ($($_.Exception.Message)); hosting is unaffected"
    }
  }
}
Emit "done" "ok" "Enclave host '$Name' is set up"
exit 0
