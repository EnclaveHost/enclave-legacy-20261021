# test/windows-native/run.ps1 -- the native cross-language harness for the signed Windows release channel.
#
# Holds three verifiers of one signed protocol to the same verdicts on one fixture set (make-fixtures.mjs): EnclaveSetup.cs
# ReleaseChannel (built here by Windows' own .NET Framework 4 csc), cli/host.ps1 (its functions, loaded from its syntax
# tree, so the install itself never runs) and windows/node/release-channel.mjs (node-verdicts.json; or re-judged here with
# -Node). It also runs the bounded-transfer tests of the C# and PowerShell downloaders against a loopback mirror that
# misbehaves (announces 50 GiB, floods, trickles, truncates, corrupts).
#
# It installs nothing, changes no host setting and needs no administrator rights. As Administrator it also tests
# update-host.ps1's SecureWorkDir, on a folder under %TEMP% only. Its only network use is 127.0.0.1. It never asks for
# elevation: cli/host.ps1's Start-CheckedSetup (Start-Process -Verb RunAs) is NOT called. The same lock is tested with an
# unelevated Start-Process of a copy of whoami.exe.
#
#   powershell -NoProfile -File test\windows-native\run.ps1 [-Node C:\path\node.exe] [-Fixtures <fixtures.json>]
#
# Precondition: the machine's PowerShell execution policy must already allow this script to run. This harness does not
# change, bypass or work around that policy; if the policy refuses the script, it does not run, and that is the
# operator's decision to make.
#
# Exit 0 when every check passes. Everything it wrote is left in the work folder it prints (results.json and the build).
param([string] $Fixtures = (Join-Path $PSScriptRoot "fixtures.json"), [string] $Node = "")
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Fixtures = (Resolve-Path $Fixtures).Path
$work = Join-Path $env:TEMP ("enclave-native-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
$results = New-Object System.Collections.ArrayList
function Check([string] $Area, [string] $Name, [bool] $Ok, [string] $Detail = "") {
  [void] $results.Add([pscustomobject]@{ area = $Area; name = $Name; ok = $Ok; detail = $Detail })
  Write-Host ("{0}  {1,-11} {2}{3}" -f $(if ($Ok) { "PASS" } else { "FAIL" }), $Area, $Name, $(if ($Detail) { "  ($Detail)" } else { "" }))
}
# a native program's output lines; its stderr must not become a terminating error under "Stop"
function Native([string] $Exe, [string[]] $Arguments) {
  $ErrorActionPreference = "Continue"
  $o = & $Exe @Arguments 2>&1
  return [pscustomobject]@{ code = $LASTEXITCODE; lines = @($o | ForEach-Object { "$_" }) }
}
function Elapsed([scriptblock] $Block) {
  $sw = [Diagnostics.Stopwatch]::StartNew(); $why = $null
  try { & $Block | Out-Null } catch { $why = Get-InnerMessage $_.Exception }
  return [pscustomobject]@{ ms = $sw.ElapsedMilliseconds; why = $why }
}
Write-Host "work folder: $work"

# ---- 1. the three scripts parse with Windows PowerShell's own parser ----------------------------------------------------
$asts = @{}
foreach ($s in "cli\host.ps1", "windows\installer\install-host.ps1", "windows\installer\update-host.ps1") {
  $tokens = $null; $errs = $null
  $asts[$s] = [Management.Automation.Language.Parser]::ParseFile((Join-Path $root $s), [ref]$tokens, [ref]$errs)
  Check "parse" $s ($errs.Count -eq 0) (($errs | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join "; ")
}
# cli/host.ps1's functions, from its syntax tree: the checks and transfers exactly as the one-line install runs them
foreach ($f in $asts["cli\host.ps1"].FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
  . ([scriptblock]::Create($f.Extent.Text))
}

# ---- 2. build the C# harness around EnclaveSetup.cs's ReleaseChannel, unchanged ------------------------------------------
$src = [IO.File]::ReadAllText((Join-Path $root "windows\installer\EnclaveSetup.cs"))
$a = $src.IndexOf("    static class ReleaseChannel"); $b = $src.IndexOf("    /// <summary>Setup's progress:")
if ($a -lt 0 -or $b -lt $a) { throw "ReleaseChannel was not found in EnclaveSetup.cs" }
$harnessCs = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "Harness.cs")).Replace("// @@RELEASE_CHANNEL@@", $src.Substring($a, $b - $a))
[IO.File]::WriteAllText((Join-Path $work "Harness.cs"), $harnessCs, (New-Object Text.UTF8Encoding $false))
$csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path -LiteralPath $csc)) { $csc = Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe" }
$exe = Join-Path $work "Harness.exe"
$build = Native $csc @("/nologo", "/target:exe", "/r:System.Web.Extensions.dll", "/r:System.Core.dll", "/out:$exe", (Join-Path $work "Harness.cs"))
Check "csharp" "ReleaseChannel (from EnclaveSetup.cs) and the harness compile with the in-box csc" ($build.code -eq 0) ($build.lines -join " ")
$built = $build.code -eq 0

# ---- 3. one fixture set, three verifiers, one verdict each -----------------------------------------------------------------
$fx = [IO.File]::ReadAllText($Fixtures) | ConvertFrom-Json
$cases = @($fx.cases)
$nodeFile = Join-Path (Split-Path $Fixtures) "node-verdicts.json"
if ($Node) {
  $nr = Native $Node @((Join-Path $PSScriptRoot "make-fixtures.mjs"), "--check", $Fixtures)
  Check "node" "release-channel.mjs re-judged every fixture here" ($nr.code -eq 0) ($nr.lines -join " ")
}
$nodeV = if (Test-Path -LiteralPath $nodeFile) { @([IO.File]::ReadAllText($nodeFile) | ConvertFrom-Json) } else { @() }
$csV = @{}
if ($built) {
  foreach ($l in (Native $exe @("verdicts", $Fixtures)).lines) {
    $p = $l -split "`t", 4
    if ($p[0] -eq "verdict") { $csV[[int]$p[1]] = [pscustomobject]@{ verdict = $p[2]; detail = $p[3] } }
  }
}
function PsVerdict($c) {
  if (-not $c.ps) { return $null }
  try {
    $p = New-ReleasePolicy -Keys @($c.ps.keys) -Mirrors @($c.ps.mirrors) -Threshold ([string]$c.ps.threshold) -Channel ([string]$c.ps.channel)
    if (-not $c.envelope) { return [pscustomobject]@{ verdict = "accept"; detail = (@($p.Mirrors) -join " ") } }
    $now = [DateTime]::Parse($c.now, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
    $r = Test-ReleaseEnvelope ([Convert]::FromBase64String($c.envelope)) $p $now
    return [pscustomobject]@{ verdict = "accept"; detail = "$($r.Version) $($r.Signers) $($r.StatementSha256)" }
  } catch { return [pscustomobject]@{ verdict = "refuse"; detail = (Get-InnerMessage $_.Exception) } }
}
for ($i = 0; $i -lt $cases.Count; $i++) {
  $c = $cases[$i]; $cv = $csV[$i]; $pv = PsVerdict $c
  $nv = if ($i -lt $nodeV.Count -and $nodeV[$i].name -eq $c.name) { $nodeV[$i] } else { $null }
  $all = @(@([pscustomobject]@{ who = "C#"; v = $cv }, [pscustomobject]@{ who = "PowerShell"; v = $pv }, [pscustomobject]@{ who = "Node"; v = $nv }) | Where-Object { $_.v })
  if ($c.agreeOnly) {
    $vs = @($all | ForEach-Object { "$($_.who)=$($_.v.verdict)" })
    Check "agree" $c.name (@($all | ForEach-Object { $_.v.verdict } | Select-Object -Unique).Count -eq 1) ($vs -join ", ")
    continue
  }
  if ($built) { Check "C#" $c.name ($cv -and $cv.verdict -eq $c.expect) "$($cv.verdict): $($cv.detail)" }
  if ($pv) { Check "PowerShell" $c.name ($pv.verdict -eq $c.expect) "$($pv.verdict): $($pv.detail)" }
  if ($nv) { Check "Node" $c.name ($nv.verdict -eq $c.expect) "$($nv.verdict): $($nv.why)" }
  # what an accepted case yields must be the same everywhere: the normalised mirrors, or the version, signer count and statement hash
  if ($c.expect -eq "accept") {
    $want = if ($c.envelope) { if ($nv) { "$($nv.version) $($nv.signers) $($nv.statementSha256)" } else { $null } } else { @($c.mirrors) -join " " }
    foreach ($x in $all) {
      if ($x.who -eq "Node" -or -not $want) { continue }
      Check "same result" "$($x.who): $($c.name)" ($x.v.detail -eq $want) "$($x.v.detail) / expected $want"
    }
  }
}

# ---- 4. bounded transfers: C# ---------------------------------------------------------------------------------------------
if ($built) {
  foreach ($l in (Native $exe @("transport", $Fixtures, (Join-Path $work "cs-transport"))).lines) {
    $p = $l -split "`t", 3
    if ($p[0] -eq "PASS" -or $p[0] -eq "FAIL") { Check "C# transfer" $p[1] ($p[0] -eq "PASS") $p[2] }
  }
}

# ---- 5. bounded transfers: cli/host.ps1, against the same loopback mirror ---------------------------------------------------
$server = $null
if ($built) {
  $portFile = Join-Path $work "port.txt"
  $server = Start-Process -FilePath $exe -ArgumentList @("serve", "`"$Fixtures`"", "`"$portFile`"") -NoNewWindow -PassThru
  try {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (-not ((Test-Path -LiteralPath $portFile) -and [IO.File]::ReadAllText($portFile).Trim()) -and $sw.ElapsedMilliseconds -lt 15000) { Start-Sleep -Milliseconds 100 }
    $base = "http://127.0.0.1:$([IO.File]::ReadAllText($portFile).Trim())/"
    $live = $fx.live
    $pol = New-ReleasePolicy -Keys @($live.ps.keys) -Mirrors @("${base}ok/") -Threshold "2" -Channel "test"

    $r = $null; $e = Elapsed { $script:r = Read-Bounded -Url "${base}ok/latest.signed.json" -Max 65536 -DeadlineMs 10000 }
    $v = $null; if (-not $e.why) { try { $v = (Test-ReleaseEnvelope $r.Bytes $pol ([DateTime]::UtcNow)).Version } catch { $e.why = Get-InnerMessage $_.Exception } }
    Check "PS transfer" "Read-Bounded + Test-ReleaseEnvelope: the live signed pointer" ($v -eq $live.version) "$v $($e.why)"
    $e = Elapsed { Read-Bounded -Url "${base}announce/x" -Max 65536 -DeadlineMs 10000 }
    Check "PS transfer" "an announced 50 GiB is refused before the body" ($e.why -match "announces" -and $e.ms -lt 3000) "$($e.ms) ms: $($e.why)"
    $e = Elapsed { Read-Bounded -Url "${base}flood/latest.signed.json" -Max 65536 -DeadlineMs 10000 }
    Check "PS transfer" "an endless body is refused at the first byte over 64 KiB" ($e.why -match "more than" -and $e.ms -lt 5000) "$($e.ms) ms: $($e.why)"
    $e = Elapsed { Read-Bounded -Url "${base}trickle/x" -Max 67108864 -DeadlineMs 1500 }
    Check "PS transfer" "a trickle is cut off at the hard deadline" ($e.why -and $e.ms -ge 1400 -and $e.ms -lt 4000) "$($e.ms) ms: $($e.why)"
    $part = Join-Path $work "short.part"
    $e = Elapsed { Read-Bounded -Url "${base}short/$($live.setupName)" -Max $live.setupBytes -Expect $live.setupBytes -OutFile $part -DeadlineMs 10000 }
    Check "PS transfer" "a short body is refused and its file removed" ($e.why -and -not (Test-Path -LiteralPath $part)) "$($e.why)"
    $keep = Join-Path $work "already-there.exe"; [IO.File]::WriteAllText($keep, "keep")
    $e = Elapsed { Read-Bounded -Url "${base}ok/$($live.setupName)" -Max $live.setupBytes -Expect $live.setupBytes -OutFile $keep -DeadlineMs 10000 }
    Check "PS transfer" "a file already at the path is never written through, nor removed" ($e.why -and [IO.File]::ReadAllText($keep) -eq "keep") "$($e.why)"

    $many = New-ReleasePolicy -Keys @($live.ps.keys) -Mirrors @("${base}trickle/", "${base}flood/", "${base}announce/", "${base}ok/") -Threshold "2" -Channel "test"
    $rel = $null; $e = Elapsed { $script:rel = Resolve-SignedRelease $many 1500 3>$null }
    Check "PS transfer" "Resolve-SignedRelease: past trickle, flood and announce to the good pointer" ($rel -and $rel.Version -eq $live.version -and @($rel.ServedBy).Count -eq 1 -and $e.ms -lt 8000) "$($e.ms) ms: $($e.why)"

    $dir = Join-Path $work "save"; New-Item -ItemType Directory -Path $dir | Out-Null
    $fail = New-ReleasePolicy -Keys @($live.ps.keys) -Mirrors @("${base}corrupt/", "${base}short/", "${base}nothing/", "${base}ok/") -Threshold "2" -Channel "test"
    $saved = $null; $e = Elapsed { $script:saved = Save-SignedFile $fail @{ ServedBy = @() } $live.setupName $live.setupSha256 ([long]$live.setupBytes) $dir 3>$null }
    $ok = $saved -and (Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash.ToLower() -eq $live.setupSha256 -and @(Get-ChildItem -LiteralPath $dir).Count -eq 1
    Check "PS transfer" "Save-SignedFile: past corrupt, short and 404 to the signed bytes; no part file left" $ok "$($e.ms) ms: $($e.why)"
    $e = Elapsed { Save-SignedFile $fail @{ ServedBy = @() } $live.setupName ("0" * 64) ([long]$live.setupBytes) (Join-Path $work "save") 3>$null }
    Check "PS transfer" "Save-SignedFile: no mirror with the signed sha256 is an error, never a file" ($e.why -match "no mirror" -and @(Get-ChildItem -LiteralPath $dir).Count -eq 1) "$($e.why)"
  } finally {
    [IO.File]::WriteAllText("$portFile.stop", "")
    if ($server -and -not $server.WaitForExit(5000)) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
  }
}

# ---- 6. Start-CheckedSetup's lock: held readable-only from the check until the program has started ---------------------------
# (Start-CheckedSetup itself uses -Verb RunAs and is not called: that asks for elevation. This is the same lock and an
# unelevated start; whether consent.exe/AppInfo also open the file under that lock is for a real setup run to show.)
$copy = Join-Path $work "locked-whoami.exe"
Copy-Item -LiteralPath (Join-Path $env:WINDIR "System32\whoami.exe") -Destination $copy
$lock = New-Object IO.FileStream ($copy, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
  $canWrite = $true; try { ([IO.File]::Open($copy, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)).Dispose() } catch { $canWrite = $false }
  $canDelete = $true; try { [IO.File]::Delete($copy) } catch { $canDelete = $false }
  $pr = Start-Process -FilePath $copy -NoNewWindow -Wait -PassThru -RedirectStandardOutput (Join-Path $work "whoami.txt")
  Check "lock" "while held, the checked program cannot be written or deleted, and still starts" (-not $canWrite -and -not $canDelete -and $pr.ExitCode -eq 0) "write=$canWrite delete=$canDelete exit=$($pr.ExitCode)"
} finally { $lock.Dispose() }

# ---- 7. update-host.ps1's SecureWorkDir (Administrator only; on a folder under %TEMP%) ---------------------------------------
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "SKIP  SecureWorkDir: run as Administrator to test it (it reads folders only SYSTEM and Administrators can)" }
else {
  $fn = $asts["windows\installer\update-host.ps1"].FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq "SecureWorkDir" }, $false) | Select-Object -First 1
  . ([scriptblock]::Create($fn.Extent.Text))
  function Log($m) { Write-Host "      log: $m" }
  $W = Join-Path $work "Enclave-setup"
  $secure = {
    $acl = Get-Acl -LiteralPath $W
    $acl.AreAccessRulesProtected -and -not @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { @("S-1-5-18", "S-1-5-32-544") -notcontains $_.IdentityReference.Value }).Count
  }
  SecureWorkDir
  Check "SecureWorkDir" "an absent folder is made for SYSTEM and Administrators only" (& $secure) ((Get-Acl -LiteralPath $W).Sddl)
  [IO.File]::WriteAllText((Join-Path $W "kept.txt"), "x")
  SecureWorkDir
  Check "SecureWorkDir" "a secure folder is kept as it is" ((Test-Path -LiteralPath (Join-Path $W "kept.txt")) -and @(Get-ChildItem -LiteralPath $work -Filter "Enclave-setup.untrusted-*").Count -eq 0)
  Rename-Item -LiteralPath $W -NewName "Enclave-setup.secure-done"
  New-Item -ItemType Directory -Path $W | Out-Null; [IO.File]::WriteAllText((Join-Path $W "planted.exe"), "x")   # inherits %TEMP%'s access: this user's
  SecureWorkDir
  $aside = @(Get-ChildItem -LiteralPath $work -Filter "Enclave-setup.untrusted-*")
  Check "SecureWorkDir" "a folder others can write is moved aside untouched and made again, empty and secure" ($aside.Count -eq 1 -and (Test-Path -LiteralPath (Join-Path $aside[0].FullName "planted.exe")) -and (& $secure) -and @(Get-ChildItem -LiteralPath $W).Count -eq 0)
}

# ---- summary -------------------------------------------------------------------------------------------------------------
$failed = @($results | Where-Object { -not $_.ok })
$results | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $work "results.json")
Write-Host ""
Write-Host "$($results.Count - $failed.Count) of $($results.Count) checks passed; $($failed.Count) failed. Results: $(Join-Path $work 'results.json')"
foreach ($f in $failed) { Write-Host "  FAILED $($f.area): $($f.name)  $($f.detail)" }
exit $(if ($failed.Count) { 1 } else { 0 })
