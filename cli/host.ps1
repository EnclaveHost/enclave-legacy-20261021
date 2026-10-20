# Enclave host for Windows -- the one-line install:
#
#   irm https://get.enclave.host/host.ps1 | iex
#
# With a referral code (attribution only; setup shows it, and it can be changed there):
#
#   $env:ENCLAVE_REFERRAL="code"; irm https://get.enclave.host/host.ps1 | iex
#
# Downloads EnclaveSetup.exe (named, with its sha256, by https://get.enclave.host/windows/latest.json), refuses it unless
# it hashes to the published value, and starts it (it asks for administrator rights: it turns on Hyper-V and installs
# services). Setup then downloads and checks the host bundle itself. See docs/design/windows-host-installer.md.
# That latest.json is UNSIGNED: its hash proves the download is what get.enclave.host published, not who published it.
#
# SIGNED, with release keys and mirrors YOU choose (docs/network/independent-windows.md):
#
#   $env:ENCLAVE_RELEASE_KEYS="ecdsa-p256:MFkw..."                           # comma-separated; the policy's keys
#   $env:ENCLAVE_RELEASE_MIRRORS="https://m1.example/windows/,https://m2.example/windows/"
#   $env:ENCLAVE_RELEASE_THRESHOLD="1"; $env:ENCLAVE_RELEASE_CHANNEL="stable"  # optional (these are the defaults)
#   irm <a copy of this script you trust> | iex
#
# Then setup runs only if a statement signed by those key(s), to the threshold, names it with its size and sha256, from
# whichever mirror proves the highest version; get.enclave.host is not asked. Setup is handed the same release policy
# (--release-policy), so the bundle it installs and every later update are held to it. Nothing fetched verifies THIS
# script: read it, or run a copy you have checked. The signed path needs Windows PowerShell 5.1 (powershell.exe): its JSON
# reader is the one setup uses, so the two judge a statement the same way.
#
# Every download is bounded: an announced or actual length over the limit (64 KiB for a pointer, the signed size for
# setup) is refused while it arrives, and each request has a hard deadline over the whole exchange, so a mirror that
# trickles cannot hold the install. Setup lands in a new private folder under %TEMP%, is checked by size and sha256, and is
# held open (readable, not writable) from that check until it has started. Anything that fails is removed.
#
# The functions below hold every check; the install itself starts at "# ---- main". test/windows-native/run.ps1 loads the
# functions from this file's syntax tree and runs them against the same fixtures as EnclaveSetup.cs and
# release-channel.mjs, without installing anything.

# The innermost message of an exception (a Task's AggregateException, a method call's wrapper).
function Get-InnerMessage($e) { while ($e.InnerException) { $e = $e.InnerException }; return $e.Message }

# GET $Url, bounded in bytes and time. An announced length over $Max (or other than $Expect) is refused before the body is
# read. A body that runs past the limit is refused at the first byte over it. The deadline covers connect, headers and
# body: HttpWebRequest's Timeout and ReadWriteTimeout bound single waits, not the exchange, so every wait here is a Task
# waited for at most the time left, and the request is aborted when that runs out. With $OutFile the body goes into a NEW
# file (CreateNew: never through something already there), which is removed on any failure. Without it, the body is
# returned (at most $Max bytes). -> @{ Bytes; Length; Sha256 }
function Read-Bounded([string] $Url, [long] $Max, [int] $DeadlineMs, [long] $Expect = -1, [string] $OutFile = "") {
  $clock = [Diagnostics.Stopwatch]::StartNew()
  $req = [Net.WebRequest]::Create($Url)
  if ($req -isnot [Net.HttpWebRequest]) { throw "$Url is not an http(s) URL" }
  $req.CachePolicy = New-Object Net.Cache.RequestCachePolicy ([Net.Cache.RequestCacheLevel]::NoCacheNoStore)
  $req.Timeout = $DeadlineMs; $req.ReadWriteTimeout = $DeadlineMs; $req.KeepAlive = $false   # aborted, never drained
  $resp = $null; $body = $null; $sink = $null; $created = $false; $ok = $false
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    $t = $req.GetResponseAsync()
    if (-not $t.Wait([int][math]::Max(0, $DeadlineMs - $clock.ElapsedMilliseconds))) { throw "no answer within $($DeadlineMs / 1000) s" }
    $resp = $t.Result
    $len = $resp.ContentLength
    if ($len -gt $Max) { throw "announces $len bytes, more than $Max" }
    if ($Expect -ge 0 -and $len -ge 0 -and $len -ne $Expect) { throw "announces $len bytes, the signed size is $Expect" }
    $body = $resp.GetResponseStream()
    if ($OutFile) { $sink = New-Object IO.FileStream ($OutFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None); $created = $true }
    else { $sink = New-Object IO.MemoryStream }
    $buf = New-Object byte[] 65536
    [long] $got = 0
    while ($true) {
      $r = $body.ReadAsync($buf, 0, $buf.Length)
      if (-not $r.Wait([int][math]::Max(0, $DeadlineMs - $clock.ElapsedMilliseconds))) { throw "sent $got bytes, then did not finish within $($DeadlineMs / 1000) s" }
      $n = $r.Result
      if ($n -le 0) { break }
      $got += $n
      if ($got -gt $Max) { throw "sent more than $Max bytes" }
      if ($Expect -ge 0 -and $got -gt $Expect) { throw "sent more than the signed $Expect bytes" }
      [void] $sha.TransformBlock($buf, 0, $n, $null, 0)
      $sink.Write($buf, 0, $n)
    }
    if ($Expect -ge 0 -and $got -ne $Expect) { throw "sent $got bytes, the signed size is $Expect" }
    [void] $sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
    $res = @{ Length = $got; Sha256 = ([BitConverter]::ToString($sha.Hash)).Replace("-", "").ToLowerInvariant(); Bytes = $null }
    if (-not $OutFile) { $res.Bytes = $sink.ToArray() }
    $ok = $true
    return $res
  } finally {
    if (-not $ok) { try { $req.Abort() } catch { } }
    foreach ($d in @($sink, $body, $resp)) { if ($d) { try { $d.Dispose() } catch { } } }
    $sha.Dispose()
    if (-not $ok -and $created) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
  }
}

# ---- the signed channel's checks: windows/node/release-channel.mjs and EnclaveSetup.cs ReleaseChannel, the same rules ----
# Strict base64 (the canonical spelling only) -> bytes.
function Read-StrictBase64($s, [string] $What) {
  if ($s -isnot [string] -or $s -cnotmatch '^[A-Za-z0-9+/]+={0,2}\z') { throw "$What is not base64" }
  $b = [Convert]::FromBase64String($s)
  if ([Convert]::ToBase64String($b) -cne $s) { throw "$What is not canonical base64" }
  return , $b
}
function Get-Sha256Hex([byte[]] $b) {
  $h = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($h.ComputeHash($b))).Replace("-", "").ToLowerInvariant() } finally { $h.Dispose() }
}
# "ecdsa-p256:<base64 SPKI>" -> @{ Spec; Id (sha256 of the SPKI); Blob (BCRYPT_ECCKEY_BLOB: "ECS1", 32, X, Y) }
function ConvertTo-ReleaseKey([string] $Spec) {
  if ($Spec -cnotmatch '^ecdsa-p256:(.+)\z') { throw "release key '$Spec' is not ecdsa-p256:<base64 SPKI>" }
  $der = Read-StrictBase64 $Matches[1] "release key '$Spec'"
  if ($der.Length -ne 91 -or ([BitConverter]::ToString($der, 0, 27)).Replace("-", "").ToLowerInvariant() -cne "3059301306072a8648ce3d020106082a8648ce3d03010703420004") {
    throw "release key '$Spec' is not an uncompressed P-256 public key"
  }
  $blob = New-Object byte[] 72
  [BitConverter]::GetBytes([int]0x31534345).CopyTo($blob, 0); [BitConverter]::GetBytes([int]32).CopyTo($blob, 4); [Array]::Copy($der, 27, $blob, 8, 64)
  # CNG refuses a point that is not on the curve, here and not only when a signature is checked
  $ck = [Security.Cryptography.CngKey]::Import($blob, [Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob); $ck.Dispose()
  return [pscustomobject]@{ Spec = $Spec; Id = (Get-Sha256Hex $der); Blob = $blob }
}
# A mirror: printable ASCII with no \ ? # @ % (so no spelling normalises differently in .NET and Node), an https directory
# URL (http only on localhost, 127.0.0.1 or [::1]), always ending in "/". Its host is judged as WRITTEN, by the rules
# release-channel.mjs and EnclaveSetup.cs apply: a strict DNS name (a canonical dotted quad if its last label looks
# numeric), or an IPv6 literal that parses to exactly ::1 (compressed or in full), written back as [::1]. .NET's Uri.Host
# spells IPv6 its own way, so it is never compared with "[::1]".
function ConvertTo-ReleaseMirror([string] $Value) {
  $u = $null
  if ($Value -cnotmatch '^[!-~]+\z' -or $Value -match '[\\?#@%]' -or -not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$u)) { throw "mirror '$Value' is not a plain URL" }
  $raw = [regex]::Match($Value, '^[A-Za-z][A-Za-z0-9+.-]*://(\[[^\]]*\]|[^/:]*)(:[0-9]{1,5})?(/|\z)').Groups[1].Value   # the whole authority: host[:digits]
  $v6 = $raw.StartsWith("[")
  if ($v6) {
    $a = $null
    $hostOk = $u.HostNameType -eq [UriHostNameType]::IPv6 -and [Net.IPAddress]::TryParse($raw.Substring(1, $raw.Length - 2), [ref]$a) -and $a.Equals([Net.IPAddress]::IPv6Loopback)
  } else {
    $hostOk = $raw -match '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\z' -and
              -not ($raw -match '(^|\.)([0-9]+|0[xX][0-9A-Fa-f]*)\z' -and $raw -notmatch '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\z') -and
              [string]::Equals($u.Host, $raw, [StringComparison]::OrdinalIgnoreCase)
  }
  if (-not $hostOk) { throw "mirror '$Value' must name a DNS host, a dotted quad or [::1], written plainly" }
  $h = $raw.ToLowerInvariant()
  $loop = $u.Scheme -ceq "http" -and ($v6 -or $h -ceq "localhost" -or $h -ceq "127.0.0.1")
  if ($u.Scheme -cne "https" -and -not $loop) { throw "mirror '$Value' must be https" }
  if ($u.UserInfo -or $u.Query -or $u.Fragment) { throw "mirror '$Value' must not carry credentials, a query or a fragment" }
  $s = if ($v6) { $u.Scheme + "://[::1]" + $(if ($u.IsDefaultPort) { "" } else { ":" + $u.Port }) + $u.AbsolutePath } else { $u.AbsoluteUri }
  if (-not $s.EndsWith("/")) { $s += "/" }
  return $s
}
# The release policy from its parts (as ENCLAVE_RELEASE_* gives them): the checks of release-channel.mjs validateReleasePolicy.
function New-ReleasePolicy([string[]] $Keys, [string[]] $Mirrors, [string] $Threshold, [string] $Channel) {
  if ($Channel -cnotmatch '^[a-z0-9][a-z0-9._-]{0,31}\z') { throw "the release channel '$Channel' is not 1-32 of a-z 0-9 . _ -" }
  if (@($Keys).Count -lt 1 -or @($Keys).Count -gt 8) { throw "a release policy needs 1 to 8 keys" }
  $pinned = @()
  foreach ($k in $Keys) {
    $p = ConvertTo-ReleaseKey $k
    if (@($pinned | Where-Object { $_.Id -ceq $p.Id }).Count) { throw "the release keys list one key twice" }
    $pinned += $p
  }
  if ($Threshold -cnotmatch '^[0-9]{1,9}\z' -or [int]$Threshold -lt 1 -or [int]$Threshold -gt $pinned.Count) { throw "the release threshold must be a whole number from 1 to the number of keys" }
  if (@($Mirrors).Count -lt 1 -or @($Mirrors).Count -gt 8) { throw "a release policy needs 1 to 8 mirrors" }
  $norm = @()
  foreach ($m in $Mirrors) { $n = ConvertTo-ReleaseMirror $m; if ($norm -ccontains $n) { throw "the release mirrors list $n twice" }; $norm += $n }
  return [pscustomobject]@{ Channel = $Channel; Threshold = [int]$Threshold; Keys = $pinned; Mirrors = $norm }
}
# The policy file setup and install-host.ps1 are handed: the release-channel.mjs format.
function ConvertTo-PolicyJson($Policy) {
  return [ordered]@{ format = "enclave-windows-release-policy/v1"; channel = $Policy.Channel; keys = @($Policy.Keys | ForEach-Object { $_.Spec })
                     threshold = $Policy.Threshold; mirrors = @($Policy.Mirrors) } | ConvertTo-Json -Depth 3
}
# JSON as setup reads it (JavaScriptSerializer: objects are case-sensitive dictionaries, integers int or long, a 1.0 or 1e0
# a decimal). ConvertFrom-Json is not used: it is case-insensitive, and PowerShell 7's turns times into DateTime.
function Read-Json([string] $Text) {
  Add-Type -AssemblyName System.Web.Extensions
  return , ((New-Object Web.Script.Serialization.JavaScriptSerializer).DeserializeObject($Text))
}
function Get-Field($d, [string] $k) { $v = $null; if ($d.TryGetValue($k, [ref]$v)) { return , $v }; return $null }
function Assert-Object($d, [string] $What, [string[]] $Allowed) {
  if ($d -isnot [Collections.Generic.Dictionary[string, object]]) { throw "$What is not a JSON object" }
  foreach ($k in $d.Keys) { if ($Allowed -cnotcontains $k) { throw "$What has an unknown field: $k" } }
}
function Read-UtcTime($s, [string] $What) {
  $t = [DateTime]::MinValue
  if ($s -isnot [string] -or $s -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,3})?Z\z' -or
      -not [DateTime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$t)) {
    throw "the signed statement's $What is not an ISO-8601 UTC time"
  }
  return $t
}
# One mirror's envelope under a policy: the signatures first (distinct pinned keys, to the threshold), then the statement.
# -> @{ Version; Statement (dictionary); StatementSha256; Signers }
function Test-ReleaseEnvelope([byte[]] $Raw, $Policy, [DateTime] $NowUtc) {
  if ($Raw.Length -gt 65536) { throw "the envelope is too large" }
  $envl = Read-Json ([Text.Encoding]::UTF8.GetString($Raw).TrimStart([char]0xFEFF))
  Assert-Object $envl "the envelope" @("format", "statement", "signatures")
  if ((Get-Field $envl "format") -isnot [string] -or (Get-Field $envl "format") -cne "enclave-windows-release-envelope/v1") { throw "not a signed release envelope" }
  $stBytes = Read-StrictBase64 (Get-Field $envl "statement") "the statement"
  if ($stBytes.Length -gt 16384) { throw "the statement is too large" }
  $sigs = Get-Field $envl "signatures"
  if ($sigs -isnot [Collections.IList] -or $sigs.Count -gt 16) { throw "the envelope's signatures are not a list of at most 16" }
  $ctx = [Text.Encoding]::ASCII.GetBytes("enclave-windows-release-signature/v1`n")
  $msg = New-Object byte[] ($ctx.Length + $stBytes.Length); $ctx.CopyTo($msg, 0); $stBytes.CopyTo($msg, $ctx.Length)
  $signed = @{}
  foreach ($s in $sigs) {
    Assert-Object $s "a signature" @("keyId", "sig")
    $id = Get-Field $s "keyId"
    $k = if ($id -is [string]) { $Policy.Keys | Where-Object { $_.Id -ceq $id } | Select-Object -First 1 } else { $null }
    if (-not $k -or $signed.ContainsKey($k.Id)) { continue }
    $sig = Read-StrictBase64 (Get-Field $s "sig") "a signature"
    if ($sig.Length -ne 64) { continue }
    $ck = [Security.Cryptography.CngKey]::Import($k.Blob, [Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    $ec = New-Object Security.Cryptography.ECDsaCng $ck
    try { $ec.HashAlgorithm = [Security.Cryptography.CngAlgorithm]::Sha256; if ($ec.VerifyData($msg, $sig)) { $signed[$k.Id] = 1 } } finally { $ec.Dispose(); $ck.Dispose() }
  }
  if ($signed.Count -lt $Policy.Threshold) { throw "$($signed.Count) valid signature(s) by the pinned key(s); $($Policy.Threshold) required" }
  $st = Read-Json ([Text.Encoding]::UTF8.GetString($stBytes))
  Assert-Object $st "the signed statement" @("format", "channel", "version", "issuedAt", "expiresAt", "file", "sha256", "bytes", "setup", "setupSha256", "setupBytes", "manifest", "manifestSha256", "manifestBytes")
  $f = { param($k) Get-Field $st $k }
  if ((& $f "format") -isnot [string] -or (& $f "format") -cne "enclave-windows-release/v1") { throw "the signed statement's format is not enclave-windows-release/v1" }
  if ((& $f "channel") -isnot [string] -or (& $f "channel") -cne $Policy.Channel) { throw "the signed statement is not for channel $($Policy.Channel)" }
  $v = & $f "version"
  if ($v -isnot [string] -or $v -cnotmatch '^[0-9]{1,9}(\.[0-9]{1,9}){1,3}\z') { throw "the signed statement's version is not valid" }
  if ((Read-UtcTime (& $f "issuedAt") "issuedAt") -gt $NowUtc.AddDays(1)) { throw "the signed statement is issued in the future" }
  if ($st.ContainsKey("expiresAt") -and (Read-UtcTime (& $f "expiresAt") "expiresAt") -le $NowUtc) { throw "the signed statement expired at $(& $f 'expiresAt')" }
  foreach ($a in @(@("file", "sha256", "bytes", "enclave-host-$v.zip", 2147483648), @("setup", "setupSha256", "setupBytes", "EnclaveSetup-$v.exe", 67108864),
                   @("manifest", "manifestSha256", "manifestBytes", "manifest-$v.json", 16777216))) {
    if ((& $f $a[0]) -isnot [string] -or (& $f $a[0]) -cne $a[3]) { throw "the signed statement's $($a[0]) must be $($a[3])" }
    if ((& $f $a[1]) -isnot [string] -or (& $f $a[1]) -cnotmatch '^[0-9a-f]{64}\z') { throw "the signed statement's $($a[1]) is not a sha256" }
    $n = & $f $a[2]
    if (-not ($n -is [int] -or $n -is [long]) -or $n -lt 1 -or $n -gt $a[4]) { throw "the signed statement's $($a[2]) is not a size in range" }
  }
  return @{ Version = $v; Statement = $st; StatementSha256 = (Get-Sha256Hex $stBytes); Signers = $signed.Count }
}
# 1.2 and 1.2.0 are one [version]: two statements for it are equivocation, as in release-channel.mjs
function Get-VersionKey([string] $v) { $p = @($v.Split(".") | ForEach-Object { [long]$_ }); while ($p.Count -lt 4) { $p += 0 }; return ($p -join ".") }
# Every mirror's signed pointer; the highest version any of them proves. Two different signed statements for one version
# stop everything. -> @{ Version; Statement; StatementSha256; Signers; ServedBy }
function Resolve-SignedRelease($Policy, [int] $DeadlineMs = 20000) {
  $best = $null; $seen = @{}
  foreach ($m in $Policy.Mirrors) {
    try {
      $raw = (Read-Bounded -Url ($m + "latest.signed.json") -Max 65536 -DeadlineMs $DeadlineMs).Bytes
      $r = Test-ReleaseEnvelope $raw $Policy ([DateTime]::UtcNow)
    } catch { Write-Warning "$m refused: $(Get-InnerMessage $_.Exception)"; continue }
    $key = Get-VersionKey $r.Version
    if ($seen.ContainsKey($key) -and $seen[$key].StatementSha256 -cne $r.StatementSha256) {
      throw "two different signed statements for version $($r.Version): not running anything until the publisher explains"
    }
    if ($seen.ContainsKey($key)) { $seen[$key].ServedBy += $m; continue }
    $r.ServedBy = @($m); $seen[$key] = $r
    if (-not $best -or [version]$r.Version -gt [version]$best.Version) { $best = $r }
  }
  if (-not $best) { throw "no mirror served a release signed by the pinned key(s): not running anything" }
  return $best
}
# A file the statement names, into $Dir, from the mirrors that served the statement first and then the others. Each
# mirror gets 60 s plus the signed size at 128 KiB/s (at most 30 minutes), and all of them together one hour.
function Save-SignedFile($Policy, $Release, [string] $Name, [string] $Sha256, [long] $Bytes, [string] $Dir) {
  $clock = [Diagnostics.Stopwatch]::StartNew()
  $order = @($Release.ServedBy) + @($Policy.Mirrors | Where-Object { @($Release.ServedBy) -cnotcontains $_ })
  foreach ($m in $order) {
    $left = 3600000 - $clock.ElapsedMilliseconds
    if ($left -le 0) { break }
    $part = Join-Path $Dir ("$Name.partial-" + [guid]::NewGuid().ToString("N"))
    try {
      $got = Read-Bounded -Url ($m + $Name) -Max $Bytes -Expect $Bytes -OutFile $part -DeadlineMs ([int][math]::Min($left, [math]::Min(1800000, 60000 + [math]::Ceiling($Bytes * 1000 / 131072))))
      if ($got.Sha256 -cne $Sha256) { throw "hashes $($got.Sha256.Substring(0, 16))..., the signed sha256 is $($Sha256.Substring(0, 16))..." }
      $out = Join-Path $Dir $Name
      Move-Item -LiteralPath $part -Destination $out
      return $out
    } catch {
      Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
      Write-Warning "$Name from $m refused: $(Get-InnerMessage $_.Exception)"
    }
  }
  throw "no mirror served the signed $Name within the hour: not running anything"
}
# Run setup only as the bytes that were checked: the file is held open (others may read it, not change or delete it),
# hashed again through that handle, and started while it is held.
function Start-CheckedSetup([string] $Exe, [long] $Bytes, [string] $Sha256, [string[]] $Arguments) {
  $lock = New-Object IO.FileStream ($Exe, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    $h = [Security.Cryptography.SHA256]::Create()
    try { $sha = ([BitConverter]::ToString($h.ComputeHash($lock))).Replace("-", "").ToLowerInvariant() } finally { $h.Dispose() }
    if ($lock.Length -ne $Bytes -or $sha -cne $Sha256) { throw "$Exe changed after it was checked: not running it" }
    if (@($Arguments).Count) { Start-Process -FilePath $Exe -Verb RunAs -ArgumentList $Arguments } else { Start-Process -FilePath $Exe -Verb RunAs }
  } finally { $lock.Dispose() }
}

# ---- main ----------------------------------------------------------------------------------------------------------------
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ref = "$env:ENCLAVE_REFERRAL".Trim()
if ($ref -and $ref -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') { Write-Warning "ENCLAVE_REFERRAL is not a referral code (1-64 letters, digits, '.', '_' or '-'): setup starts without it"; $ref = "" }
$keys = @("$env:ENCLAVE_RELEASE_KEYS".Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
# any release setting with no key is a mistake, never a request for the unsigned channel
if (-not $keys.Count -and "$env:ENCLAVE_RELEASE_KEYS$env:ENCLAVE_RELEASE_MIRRORS$env:ENCLAVE_RELEASE_THRESHOLD$env:ENCLAVE_RELEASE_CHANNEL".Trim()) {
  throw "ENCLAVE_RELEASE_* is set but names no key in ENCLAVE_RELEASE_KEYS: not falling back to the unsigned channel"
}
$setupArgs = @()
# a new folder of this user's own for each run: nothing already in %TEMP% is ever opened, run or overwritten
$work = Join-Path $env:TEMP ("enclave-setup-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
  if ($keys.Count) {
    # ---- the signed channel: no fallback to the unsigned one, whatever fails ----
    if ($PSVersionTable.PSEdition -eq "Core") { throw "the signed channel is checked with Windows PowerShell 5.1 (powershell.exe), whose JSON reader is setup's: run this there" }
    $mirrors = @("$env:ENCLAVE_RELEASE_MIRRORS".Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if (-not $mirrors.Count) { throw "ENCLAVE_RELEASE_KEYS is set but ENCLAVE_RELEASE_MIRRORS is not: name the mirrors to fetch the signed release from" }
    $channel = if ($env:ENCLAVE_RELEASE_CHANNEL) { "$env:ENCLAVE_RELEASE_CHANNEL".Trim() } else { "stable" }
    $threshold = if ($env:ENCLAVE_RELEASE_THRESHOLD) { "$env:ENCLAVE_RELEASE_THRESHOLD".Trim() } else { "1" }
    $policy = New-ReleasePolicy -Keys $keys -Mirrors $mirrors -Threshold $threshold -Channel $channel
    $best = Resolve-SignedRelease $policy
    $setupName = Get-Field $best.Statement "setup"; $setupSha = Get-Field $best.Statement "setupSha256"; $setupBytes = [long](Get-Field $best.Statement "setupBytes")
    $exe = Save-SignedFile $policy $best $setupName $setupSha $setupBytes $work
    # the same policy for setup (and through it, install-host.ps1 and every later update)
    $policyFile = Join-Path $work "release-policy.json"
    ConvertTo-PolicyJson $policy | Set-Content -Encoding UTF8 -LiteralPath $policyFile
    $setupArgs += "--release-policy", "`"$policyFile`""
    Write-Host "Checked Enclave setup $($best.Version): signed by $($best.Signers) pinned key(s), $setupBytes bytes, sha256 $($setupSha.Substring(0, 16))... Starting setup; Windows asks for administrator rights."
  } else {
    # ---- the legacy channel: get.enclave.host, UNSIGNED --------------------------------------------------------------------
    $base = "https://get.enclave.host/windows"
    $latest = [Text.Encoding]::UTF8.GetString((Read-Bounded -Url "$base/latest.json" -Max 65536 -DeadlineMs 30000).Bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
    if ($latest.setup -cnotmatch '^[A-Za-z0-9._-]+\.exe\z' -or $latest.setupSha256 -cnotmatch '^[0-9a-f]{64}\z') { throw "latest.json does not name a setup program" }
    $setupSha = [string]$latest.setupSha256
    $exe = Join-Path $work $latest.setup
    Write-Host "Downloading Enclave setup $($latest.version)..."
    $got = Read-Bounded -Url "$base/$($latest.setup)" -Max 67108864 -DeadlineMs 1800000 -OutFile $exe
    if ($got.Sha256 -cne $setupSha) { Remove-Item -LiteralPath $exe -Force; throw "the download hashes $($got.Sha256), not the published ${setupSha}: not running it" }
    $setupBytes = $got.Length
    Write-Host "Checked against the unsigned latest.json (sha256 $($setupSha.Substring(0, 16))...). Starting setup; Windows asks for administrator rights."
  }
  if ($ref) { $setupArgs += "--referral", $ref }
  Start-CheckedSetup $exe $setupBytes $setupSha $setupArgs
} catch {
  # nothing started: nothing kept (once setup runs, its folder stays: setup and its policy file are in it)
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  throw
}
