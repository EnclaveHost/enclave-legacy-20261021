# update-host.ps1 -- keep this Enclave host on the latest release with no one at the keyboard. Run as SYSTEM by the
# scheduled task \Enclave\Update (5 minutes after boot, then every hour; install-host.ps1 registers it):
#   1. find the latest release; nothing newer than Program Files' manifest: done, silently (an hourly no-op leaves no log line);
#   2. download that release's zip (or only its changed files) and EnclaveSetup.exe into ProgramData\Enclave-setup and check
#      them; a mismatch installs nothing;
#   3. run the new release's install-host.ps1 over this host: the same name and owner (node\host.json), and the identity
#      recorded there, so the keys, the records, the guest state and the registration are kept and the services restart on
#      the new version;
#   4. if that install fails, reinstall the release that was running from its own bundle (kept for exactly this), so a
#      bad release leaves the host on the old one rather than on none.
#
# WHERE "LATEST" COMES FROM, and what the check in 2 is worth (ENCLAVE-RELEASE-POLICY-V1):
#   * SIGNED (ProgramData\Enclave\node\release-policy.json exists): the release is the highest version a statement signed
#     by the policy's pinned key(s) names, from the policy's own mirrors; every hash and size checked in 2 comes from that
#     signed statement (the manifest's too, so every delta file is covered). The verifier is the INSTALLED release's
#     release-channel.mjs under the INSTALLED node.exe - never code from the download it is judging. There is no fallback:
#     if no mirror serves a properly signed release, nothing is installed and the log says why.
#   * LEGACY (no policy): get.enclave.host/windows/latest.json, UNSIGNED. The hashes it publishes come from the same place
#     as the files, so they catch corruption, not substitution: whoever controls that origin controls this host's code.
#     An independent host (node\host.json identity.mode) never uses this channel.
# A release that would drop identity records or release-policy verification is not installed on a host that relies on
# them, and is not rolled back to.
# Releases older than the running one and the one before it are removed. Log: ProgramData\Enclave\logs\update.log.
#   powershell -ExecutionPolicy Bypass -File update-host.ps1 [-Force]      (-Force: reinstall the latest even if current)
param([switch] $Force, [string] $Downloads = "https://get.enclave.host/windows/")
$ErrorActionPreference = "Stop"; $ProgressPreference = "SilentlyContinue"
$PF = Join-Path $env:ProgramFiles "Enclave"; $PD = Join-Path $env:ProgramData "Enclave"; $W = Join-Path $env:ProgramData "Enclave-setup"
$log = Join-Path $PD "logs\update.log"
$policyFile = Join-Path $PD "node\release-policy.json"
$signed = Test-Path -LiteralPath $policyFile
$node = Join-Path $PF "runtime\node\node.exe"
$channelJs = Join-Path $PF "control\windows\node\release-channel.mjs"
function Log($m) { "$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) $m" | Add-Content -Encoding UTF8 $log }
# what the tray shows while an update runs (EnclaveTray.cs UpdateState): beside the tray's token, which its owner can read
function Progress($state, $from, $to) {
  try {
    $f = Join-Path $PD "hosting\update.json"
    if (Test-Path (Split-Path $f)) {
      [ordered]@{ state = $state; from = $from; to = $to; at = (Get-Date).ToUniversalTime().ToString("o") } | ConvertTo-Json -Compress |
        Set-Content -Encoding ASCII $f
    }
  } catch { }
}
function Sha($p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() }
function Ver($s) { $v = $null; if ([version]::TryParse([string]$s, [ref]$v)) { $v } else { $null } }
# The installed verifier (release-channel.mjs), its stderr into the log. Native stderr under "Stop" would throw in Windows
# PowerShell 5.1, so the preference is relaxed for this call only; the exit code is what is judged.
function Channel([string[]] $a) {
  $ErrorActionPreference = "Continue"
  $o = & $node $channelJs @a 2>&1; $c = $LASTEXITCODE
  foreach ($l in $o) { Log "  $l" }
  return $c
}
# Download release files whose sha256 and size come from the verified statement (or the manifest it hashes), from the
# policy's mirrors in turn: a mirror that corrupts or truncates one is skipped for the next.
function FetchSigned($items) {
  New-Item -ItemType Directory -Force $W | Out-Null
  $list = Join-Path $W ("fetch-" + [guid]::NewGuid().ToString("N").Substring(0, 8) + ".json")
  ConvertTo-Json -InputObject @($items) -Depth 3 -Compress | Set-Content -Encoding UTF8 -LiteralPath $list
  try {
    if ((Channel @("download", "--policy", $policyFile, "--list", $list)) -ne 0) { throw "a release file was not served with its signed sha256 by any mirror in $policyFile" }
  } finally { Remove-Item -LiteralPath $list -Force -ErrorAction SilentlyContinue }
}
function Fetch($name, $sha, $bytes) {
  $f = Join-Path $W $name
  if ($signed) {
    FetchSigned @(@{ name = $name; sha256 = $sha; bytes = [long]$bytes; out = $f })
  } elseif (-not (Test-Path -LiteralPath $f) -or (Sha $f) -ne $sha) { Invoke-WebRequest -UseBasicParsing -Uri ($Downloads + $name) -OutFile $f -TimeoutSec 3600 }
  if ((Sha $f) -ne $sha) { Remove-Item -LiteralPath $f -Force; throw "${name} hashes differently from the published ${sha}: not installing it" }
  return $f
}
# Enclave-setup holds what this script RUNS as SYSTEM: setup programs, expanded bundles and the delta base it hard-links
# from. A folder made under ProgramData inherits "Users: create files", so any local account could plant a file there that
# a later step trusts (a "cached" zip swapped after its hash check, a missing delta file "linked" unchecked). The folder is
# used only if it is SYSTEM's and Administrators' alone (as EnclaveSetup.cs SecureWorkDir makes it). Otherwise it is moved
# aside untouched and made again with exactly that access, which costs one whole (non-delta) update and that update's
# rollback copy.
function SecureWorkDir {
  $sy = "S-1-5-18"; $ba = "S-1-5-32-544"
  if (Test-Path -LiteralPath $W) {
    $item = Get-Item -LiteralPath $W -Force
    $acl = Get-Acl -LiteralPath $W
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $others = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { @($sy, $ba) -notcontains $_.IdentityReference.Value })
    if ($item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $acl.AreAccessRulesProtected -and
        @($sy, $ba) -contains $owner -and $others.Count -eq 0) { return }
    $aside = "$W.untrusted-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss") + "-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
    [IO.Directory]::Move($W, $aside)
    Log "$W was not SYSTEM's and Administrators' alone: moved aside, untouched, to $aside; made again"
  }
  $ds = New-Object Security.AccessControl.DirectorySecurity
  $ds.SetSecurityDescriptorSddlForm("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
  [void] [IO.Directory]::CreateDirectory($W, $ds)
}
# Does a release bundle keep what this host relies on: its recorded identity (install-host.ps1) and signed updates
# (this script and the verifier)? Asked of a release before it is installed and of the old one before a rollback.
function Capable($dir) {
  $i = Join-Path $dir "install-host.ps1"; $u = Join-Path $dir "update-host.ps1"
  return (Test-Path -LiteralPath $i) -and (Test-Path -LiteralPath $u) -and
    (Select-String -LiteralPath $i -SimpleMatch "ENCLAVE-IDENTITY-RECORD-V1" -Quiet) -and
    (Select-String -LiteralPath $u -SimpleMatch "ENCLAVE-RELEASE-POLICY-V1" -Quiet) -and
    (Test-Path -LiteralPath (Join-Path $dir "control\windows\node\release-channel.mjs"))
}
function Install($dir, $name, $owner, $setup, [switch] $Delta) {
  # ENCLAVE_UPDATING: install-host.ps1 leaves the \Enclave\Update task (this script's own) running and registered as is
  $env:ENCLAVE_UPDATING = "1"
  $extra = @(); if ($Delta) { $extra += "-Delta" }
  $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $dir "install-host.ps1") -Name $name -Owner $owner -SetupExe $setup @extra 2>&1
  $code = $LASTEXITCODE
  foreach ($l in $out) { Log "  $l" }
  return $code
}
# A DELTA: the new release's files, built from the installed release's bundle (kept in Enclave-setup\<version>): what did
# not change is hard-linked from it (no copy, no download), what did is downloaded by its sha256 from files/ and checked.
# -> the new release's directory, or $null when a delta is not possible or not worth it (the caller then takes the zip).
function DeltaBundle($latest, $installed) {
  if (-not $latest.manifest -or -not $latest.manifestSha256) { return $null }
  $prev = Join-Path $W $installed
  if (-not (Test-Path (Join-Path $prev "manifest.json")) -or -not (Test-Path (Join-Path $prev "install-host.ps1"))) { return $null }
  $old = @{}; foreach ($e in (Get-Content (Join-Path $PF "manifest.json") -Raw | ConvertFrom-Json).files) { $old[$e.path] = $e.sha256 }
  $mf = Fetch $latest.manifest $latest.manifestSha256.ToLower() $latest.manifestBytes
  $new = Get-Content $mf -Raw | ConvertFrom-Json
  if ($new.version -ne $latest.version) { throw "the published manifest is for $($new.version), not $($latest.version)" }
  $fetch = @($new.files | Where-Object { $old[$_.path] -ne $_.sha256 -or -not (Test-Path -LiteralPath (Join-Path $prev ($_.path -replace '/', '\'))) })
  $bytes = ($fetch | Measure-Object bytes -Sum).Sum
  if ($fetch.Count -gt 400 -or $bytes -gt 60MB) { Log "delta: $($fetch.Count) file(s), $([int]($bytes / 1MB)) MB changed: the whole release instead"; return $null }
  if (-not ("Enclave.HardLink" -as [type])) {
    Add-Type -Namespace Enclave -Name HardLink -MemberDefinition '[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern bool CreateHardLink(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);'
  }
  $dir = Join-Path $W ($latest.version + ".partial")
  if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
  $need = @{}; foreach ($e in $fetch) { $need[$e.path] = 1 }
  $items = @()
  foreach ($e in $new.files) {
    $rel = $e.path -replace '/', '\'; $dst = Join-Path $dir $rel
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dst)) | Out-Null
    if (-not $need.ContainsKey($e.path)) {
      if (-not [Enclave.HardLink]::CreateHardLink($dst, (Join-Path $prev $rel), [IntPtr]::Zero)) { Copy-Item -LiteralPath (Join-Path $prev $rel) $dst }
    } else { $items += @{ name = "files/" + $e.sha256; sha256 = [string]$e.sha256; bytes = [long]$e.bytes; out = $dst } }
  }
  if ($signed) { if ($items.Count) { FetchSigned $items } }
  else {
    $web = New-Object Net.WebClient
    foreach ($it in $items) { $web.DownloadFile($Downloads + $it.name, $it.out) }
  }
  foreach ($it in $items) { if ((Sha $it.out) -ne $it.sha256) { throw "$($it.name) hashes differently: not installing it" } }
  Copy-Item -LiteralPath $mf (Join-Path $dir "manifest.json") -Force
  $final = Join-Path $W $latest.version
  if (Test-Path $final) { Remove-Item $final -Recurse -Force }
  Rename-Item $dir $final
  Log "delta: $($fetch.Count) file(s), $([math]::Round($bytes / 1KB)) KB downloaded and checked; the other $($new.files.Count - $fetch.Count) linked from $installed"
  return $final
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
  if (-not (Test-Path (Join-Path $PF "manifest.json")) -or -not (Test-Path (Join-Path $PD "node\host.json"))) { exit 0 }   # not installed
  $installed = (Get-Content (Join-Path $PF "manifest.json") -Raw | ConvertFrom-Json).version
  $hostRec = Get-Content (Join-Path $PD "node\host.json") -Raw | ConvertFrom-Json
  if (-not $hostRec.name) { Log "node\host.json names no host: nothing to update"; exit 0 }
  SecureWorkDir
  $independent = $hostRec.identity -and $hostRec.identity.mode -eq "independent"
  $keep = $signed -or $independent
  if ($signed) {
    if (-not (Test-Path -LiteralPath $node) -or -not (Test-Path -LiteralPath $channelJs)) { throw "a release policy is installed ($policyFile) but this release has no verifier to apply it: not updating" }
    New-Item -ItemType Directory -Force $W | Out-Null
    $res = Join-Path $W "resolved.json"; Remove-Item -LiteralPath $res -Force -ErrorAction SilentlyContinue
    $a = @("resolve", "--policy", $policyFile, "--installed", [string]$installed, "--out", $res); if ($Force) { $a += "--force" }
    if ((Channel $a) -ne 0 -or -not (Test-Path -LiteralPath $res)) { throw "no release signed by the key(s) pinned in $policyFile could be resolved from its mirrors: not updating" }
    $resolved = Get-Content -LiteralPath $res -Raw | ConvertFrom-Json
    $latest = $resolved.statement
    $via = "signed by $(@($resolved.signers).Count) pinned key(s) ($((@($resolved.signers) | ForEach-Object { $_.Substring(0, 12) }) -join ', ')), statement $($resolved.statementSha256.Substring(0, 12))..., served by $(@($resolved.servedBy) -join ' ')"
    if ($PSBoundParameters.ContainsKey("Downloads")) { Log "-Downloads is ignored: this host takes releases only from the mirrors in its release policy" }
  } elseif ($independent) {
    throw "this host is independent and has no release policy: it does not take the unsigned Enclave channel (install one with release-channel.mjs install-policy, or update by hand)"
  } else {
    $latest = Invoke-RestMethod -UseBasicParsing -Uri ($Downloads + "latest.json") -TimeoutSec 30
    $via = "UNSIGNED legacy channel $Downloads (hashes from the same unsigned latest.json)"
  }
  if (-not (Ver $latest.version) -or -not (Ver $installed)) { throw "unreadable version: installed '$installed', published '$($latest.version)'" }
  if (-not $Force -and (Ver $latest.version) -le (Ver $installed)) { exit 0 }
  foreach ($k in "file", "sha256", "setup", "setupSha256") { if (-not $latest.$k) { throw "the published release names no $k" } }
  Log "update $installed -> $($latest.version) for '$($hostRec.name)': $via"
  Progress "downloading" $installed $latest.version
  New-Item -ItemType Directory -Force $W | Out-Null
  $setup = Fetch $latest.setup $latest.setupSha256.ToLower() $latest.setupBytes
  $dir = $null
  try { $dir = DeltaBundle $latest $installed } catch { Log "delta: $($_.Exception.Message): the whole release instead"; $dir = $null }
  $delta = [bool]$dir
  if (-not $delta) {
    $zip = Fetch $latest.file $latest.sha256.ToLower() $latest.bytes
    $dir = Join-Path $W $latest.version
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $dir)
    Log "downloaded and checked $($latest.file) (sha256 $($latest.sha256.Substring(0, 12))...)"
  }
  if ($keep -and -not (Capable $dir)) {
    Progress "failed" $installed $latest.version
    throw "release $($latest.version) does not keep identity records and signed updates, which this host relies on: not installing it"
  }
  Log "installing $($latest.version)$(if ($delta) { ' (only the changed files)' })"
  Progress "installing" $installed $latest.version
  $owner = if ($hostRec.owner) { [string]$hostRec.owner } else { "" }
  $code = Install $dir $hostRec.name $owner $setup -Delta:$delta
  if ($code -ne 0) {
    $old = Join-Path $W $installed
    if ($keep -and (Test-Path (Join-Path $old "install-host.ps1")) -and -not (Capable $old)) {
      Log "install of $($latest.version) FAILED (exit $code); NOT rolling back to ${installed}: its installer would rewrite this host's identity or drop signed updates"
    } elseif (Test-Path (Join-Path $old "install-host.ps1")) {
      Log "install of $($latest.version) FAILED (exit $code): reinstalling $installed"
      $oldSetup = Get-ChildItem $W -Filter "EnclaveSetup-$installed.exe" | Select-Object -First 1
      # a whole reinstall, not a delta: a failed delta may have left Program Files part old, part new
      $back = Install $old $hostRec.name $owner $(if ($oldSetup) { $oldSetup.FullName } else { "" })
      Log "rollback to ${installed}: exit $back"
    } else { Log "install of $($latest.version) FAILED (exit $code), and no bundle of $installed is kept to roll back to" }
    Progress "failed" $installed $latest.version
    exit 1
  }
  Log "updated to $($latest.version)"
  Progress "done" $installed $latest.version
  # keep the running release and the one before it (the rollback); older bundles, zips and setups go
  $keepDirs = @(Get-ChildItem $W -Directory | Where-Object { Ver $_.Name } | Sort-Object { Ver $_.Name } -Descending | Select-Object -First 2 | ForEach-Object Name)
  foreach ($d in Get-ChildItem $W -Directory | Where-Object { (Ver $_.Name) -and $keepDirs -notcontains $_.Name }) { Remove-Item $d.FullName -Recurse -Force -ErrorAction SilentlyContinue }
  foreach ($f in Get-ChildItem $W -File | Where-Object { $_.Name -match '^(enclave-host-|EnclaveSetup-|manifest-)(.+?)(\.zip|\.exe|\.json)$' -and $keepDirs -notcontains $Matches[2] }) {
    Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
  }
  exit 0
} catch { Log "update failed: $($_.Exception.Message)"; if ($latest) { Progress "failed" $installed $latest.version }; exit 1 }
