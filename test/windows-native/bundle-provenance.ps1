# Exercise the actual builder's source-manifest verification block without running a build or installer.
param([Parameter(Mandatory)][string]$Builder)
$ErrorActionPreference='Stop'
function Sha($p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() }
function Die($m) { throw "build-bundle: $m" }
$source=Get-Content -LiteralPath $Builder -Raw
$start=$source.IndexOf('$n = 0');$end=$source.IndexOf('"control: $n files match their manifest"',$start)
if($start -lt 0 -or $end -le $start){throw 'builder verification block not found'}
$verify=[ScriptBlock]::Create($source.Substring($start,$end-$start))
$B=Join-Path $env:TEMP ('enclave-provenance-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $B|Out-Null
try {
  $Control=Join-Path $B 'control-aaaaaaaa.tar.gz';$Manifest=Join-Path $B 'MANIFEST-control-aaaaaaaa.txt'
  $identity=Join-Path $B 'control-source.json'
  [ordered]@{format='enclave-control-source/1';commit=('a'*40)}|ConvertTo-Json|Set-Content -LiteralPath $identity
  Set-Content -LiteralPath $Manifest ((Sha $identity)+'  control-source.json')
  . $verify
  if(-not $sourceIdentityChecked -or $sourceIdentity.commit -cne ('a'*40)){throw 'full commit not verified'}
  Write-Output 'PASS builder verifies hashed full source identity'
  Set-Content -LiteralPath $Manifest '# descriptor omitted'
  $rejected=$false;try{. $verify}catch{$rejected=$true};if(-not $rejected){throw 'missing descriptor accepted'}
  Write-Output 'PASS builder refuses unhashed source descriptor'
  Set-Content -LiteralPath $Manifest (('0'*64)+'  control-source.json')
  $rejected=$false;try{. $verify}catch{$rejected=$true};if(-not $rejected){throw 'wrong descriptor hash accepted'}
  Write-Output 'PASS builder refuses changed source descriptor'
  Set-Content -LiteralPath $Manifest ((Sha $identity)+'  control-source.json');$Control=Join-Path $B 'control-bbbbbbbb.tar.gz'
  $rejected=$false;try{. $verify}catch{$rejected=$true};if(-not $rejected){throw 'different archive source accepted'}
  Write-Output 'PASS builder refuses archive/commit mismatch'
} finally {Remove-Item -LiteralPath $B -Recurse -Force}
Write-Output 'No build, installer or production changes were executed'
