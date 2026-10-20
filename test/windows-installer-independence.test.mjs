// The Windows installer side of host independence: EnclaveSetup.cs, install-host.ps1, update-host.ps1 and cli/host.ps1.
// This Linux test environment has no PowerShell and no .NET, so these checks are STRUCTURAL: they hold the C# and
// PowerShell verifiers to the same constants as release-channel.mjs (which test/windows-release-channel.test.mjs runs
// with real keys), and hold the scripts to the contracts between them - the parameters setup passes are the ones the
// installer takes, an update passes no identity, the signed path never reads the unsigned pointer, the verifier comes
// from the INSTALLED tree, and every step the installer reports is one setup knows. A Windows run is still required
// (docs/network/independent-windows.md, "What has and has not been run").
//   run: node --test test/windows-installer-independence.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as rc from "../windows/node/release-channel.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), "utf8");
const SETUP = read("windows", "installer", "EnclaveSetup.cs");
const INSTALL = read("windows", "installer", "install-host.ps1");
const UPDATE = read("windows", "installer", "update-host.ps1");
const ONELINE = read("cli", "host.ps1");
const code = (src) => src.split("\n").filter((l) => !/^\s*(#|\/\/)/.test(l)).join("\n");   // without comment lines
const csConst = (name) => { const m = SETUP.match(new RegExp(`const string ${name} = "((?:[^"\\\\]|\\\\.)*)";`)); assert.ok(m, name); return JSON.parse(`"${m[1]}"`); };

test("setup's C# verifier and host.ps1's PowerShell verifier use release-channel.mjs's exact constants", () => {
  assert.equal(csConst("PolicyFormat"), rc.POLICY_FORMAT);
  assert.equal(csConst("StatementFormat"), rc.STATEMENT_FORMAT);
  assert.equal(csConst("EnvelopeFormat"), rc.ENVELOPE_FORMAT);
  assert.equal(csConst("EnvelopeName"), rc.ENVELOPE_NAME);
  assert.equal(csConst("Context"), rc.SIGNING_CONTEXT.toString("ascii"), "the signed message's prefix, newline included");
  assert.equal(csConst("P256SpkiPrefixHex"), rc.P256_SPKI_PREFIX.toString("hex"));
  assert.match(SETUP, /BcryptEcdsaPublicP256Magic = 0x31534345/, "BCRYPT_ECDSA_PUBLIC_P256_MAGIC (\"ECS1\")");
  assert.match(SETUP, /Array\.Copy\(der, 27, blob, 8, 64\)/, "X and Y from the SPKI's offset 27 (the 27-byte prefix)");
  assert.match(SETUP, /ec\.HashAlgorithm = CngAlgorithm\.Sha256/);
  assert.match(SETUP, /if \(signed\.Count < p\.Threshold\)/);
  assert.ok(ONELINE.includes(`"${rc.P256_SPKI_PREFIX.toString("hex")}"`));
  assert.ok(ONELINE.includes('"enclave-windows-release-signature/v1`n"'), "PowerShell's `n is the same newline");
  assert.ok(ONELINE.includes(`"${rc.ENVELOPE_FORMAT}"`) && ONELINE.includes(`"${rc.POLICY_FORMAT}"`) && ONELINE.includes('"enclave-windows-release/v1"'));
  assert.match(ONELINE, /\[Array\]::Copy\(\$der, 27, \$blob, 8, 64\)/); assert.match(ONELINE, /0x31534345/);
  // the statement fields all three verifiers accept are the same set
  const csFields = SETUP.match(/StatementFields = \{([^}]*)\}/)[1].match(/"([a-zA-Z0-9]+)"/g).map((s) => s.slice(1, -1)).sort();
  const psFields = ONELINE.match(/Assert-Object \$st "the signed statement" @\(([^)]*)\)/)[1].match(/"([a-zA-Z0-9]+)"/g).map((s) => s.slice(1, -1)).sort();
  const jsFields = [...rc.STATEMENT_FIELDS].sort();
  assert.deepEqual(csFields, jsFields); assert.deepEqual(psFields, jsFields);
});

test("the arguments setup passes are the parameters install-host.ps1 takes; an update passes no identity", () => {
  const params = new Set([...INSTALL.match(/^param\(([\s\S]*?)^\)/m)[1].matchAll(/\$([A-Za-z]+)/g)].map((m) => m[1]));
  const passed = [...SETUP.matchAll(/" -([A-Z][A-Za-z]+)[ "]/g)].map((m) => m[1]);
  assert.ok(passed.length >= 12, passed.join(","));
  for (const p of passed) assert.ok(params.has(p), `EnclaveSetup passes -${p}, which install-host.ps1 does not take`);
  for (const p of ["NoRelay", "PublicUrl", "Gateways", "ContractPins", "Rpcs", "Directories", "NetworkCheckers", "NameCheck", "ReleasePolicy", "Reconfigure"])
    assert.ok(params.has(p), p);
  const updateInstall = UPDATE.match(/install-host\.ps1"\) ([^\n]*)/)[1];
  assert.match(updateInstall, /^-Name \$name -Owner \$owner -SetupExe \$setup @extra 2>&1$/, "an update re-uses the recorded identity: it passes none");
  assert.match(UPDATE, /\$extra = @\(\); if \(\$Delta\) \{ \$extra \+= "-Delta" \}/);
});

test("every step the installer reports is one setup shows", () => {
  const steps = new Set(SETUP.match(/InstallSteps = \{([^}]*)\}/)[1].match(/"([a-z]+)"/g).map((s) => s.slice(1, -1)));
  const weights = SETUP.match(/InstallWeights = \{([^}]*)\}/)[1].split(",").length;
  assert.equal(weights, steps.size);
  const emitted = new Set([...INSTALL.matchAll(/(?:Emit|Fail) "([a-z]+)"/g)].map((m) => m[1]));
  for (const s of emitted) assert.ok(steps.has(s), `install-host.ps1 reports "${s}", which EnclaveSetup does not list`);
});

test("install-host.ps1: a relay host is unchanged; nothing Enclave is defaulted for an independent one", () => {
  const c = code(INSTALL);
  assert.match(INSTALL, /ENCLAVE-IDENTITY-RECORD-V1/);
  // the relay host's lines, now each in the relay branch only
  assert.match(c, /\$\(if \(\$independent\) \{ "set IPFS_GATEWAYS=[^\n]*\} else \{ "set IPFS_GATEWAY=https:\/\/ipfs\.enclave\.host" \}\)/);
  assert.match(c, /set RELAY_URL=\$\(if \(\$independent\) \{ "none" \} else \{ "\$\(\$want\.relay -replace '\^https:', 'wss:'\)\/v1\/fleet-tunnel" \}\)/);
  assert.match(c, /\$\(if \(-not \$independent\) \{ "set ENCLAVE_NETWORK_CHECKERS=0x57144c9008cff0b3ed94f6e40964a321fbee848a,0x033bc2b92bb1bb97c7dadf2879d3048748e2257b" \}/);
  assert.match(c, /set PUBLIC_URL=\$\(\$want\.publicUrl\)/);
  assert.doesNotMatch(c, /PUBLIC_URL=\$Relay\/t\/\$Name|PUBLIC_URL = "\$Relay\/t\/\$Name"/, "the relay route is no longer forced");
  // the relay name check only for a relay host, and against that host's recorded relay
  assert.match(c, /if \(\$NameCheck -eq "relay" -and -not \$sameBox\) \{\s*\n\s*try \{ \$avail = Invoke-RestMethod -UseBasicParsing -Uri "\$\(\$want\.relay\)\/v1\/hosts\/name\/\$Name"/);
  assert.match(c, /if \(\$independent -and \$NameCheck -eq "relay"\) \{ Fail/);
  // recorded identity: explicit change needs -Reconfigure
  assert.match(c, /if \(\$recorded -and \(IdKey \$recorded\) -ne \(IdKey \$want\) -and -not \$Reconfigure\)/);
  assert.match(c, /identity = \[ordered\]@\{ format = "enclave-host-identity\/v1"/);
  // the chain check, through the installed node and module, with exit 2 = taken
  assert.match(c, /host-identity\.mjs"\), "check-endpoint", "--endpoint", \$want\.publicUrl, "--operator", \$operator, "--pins", \$pinsDest/);
  assert.match(c, /if \(\$chk\.code -eq 2\) \{ Fail "name"/);
  // the release policy is installed with refuse-to-replace semantics
  assert.match(c, /"install-policy", "--policy", \$ReleasePolicy, "--dest", \$policyDest\) \+ @\(if \(\$Reconfigure\) \{ "--replace" \}\)/);
  // node-config.local.cmd (where a wallet veto lives) is still read last, after everything the installer writes
  const nodeCfg = INSTALL.slice(INSTALL.indexOf("rem The Enclave host node."), INSTALL.indexOf('Set-Content -Encoding ASCII (Join-Path $PD "node-config.cmd")'));
  assert.match(nodeCfg.trim().split("\n").at(-2), /if exist "\$PD\\node-config\.local\.cmd" call "\$PD\\node-config\.local\.cmd"/);
});

test("update-host.ps1: signed mode never reads the unsigned pointer, and verifies with the INSTALLED code", () => {
  const c = code(UPDATE);
  assert.match(UPDATE, /ENCLAVE-RELEASE-POLICY-V1/);
  assert.match(c, /\$node = Join-Path \$PF "runtime\\node\\node\.exe"/);
  assert.match(c, /\$channelJs = Join-Path \$PF "control\\windows\\node\\release-channel\.mjs"/);
  // the unsigned latest.json is read in exactly one place: the legacy branch after the signed and independent ones
  const reads = [...c.matchAll(/\+ "latest\.json"\)/g)].length;
  assert.equal(reads, 1, "one request for latest.json");
  const signedAt = c.indexOf("if ($signed) {\n    if (-not (Test-Path -LiteralPath $node)"), indepAt = c.indexOf("} elseif ($independent) {\n    throw"),
        legacyAt = c.indexOf("} else {\n    $latest = Invoke-RestMethod -UseBasicParsing -Uri ($Downloads + \"latest.json\")");
  assert.ok(signedAt > 0 && indepAt > signedAt && legacyAt > indepAt, "signed, then independent (refuses), then legacy");
  // downloads in signed mode go through the verifier with the signed sizes; deltas too
  assert.match(c, /if \(\$signed\) \{\s*\n\s*FetchSigned @\(@\{ name = \$name; sha256 = \$sha; bytes = \[long\]\$bytes; out = \$f \}\)/);
  assert.match(c, /if \(\$signed\) \{ if \(\$items\.Count\) \{ FetchSigned \$items \} \}/);
  assert.match(c, /Fetch \$latest\.manifest \$latest\.manifestSha256\.ToLower\(\) \$latest\.manifestBytes/);
  // a release (or rollback) that would drop identity records or signed updates is refused on a host relying on them
  for (const marker of ["ENCLAVE-IDENTITY-RECORD-V1", "ENCLAVE-RELEASE-POLICY-V1"]) assert.ok(c.includes(`-SimpleMatch "${marker}"`), marker);
  assert.match(c, /if \(\$keep -and -not \(Capable \$dir\)\) \{/);
  assert.match(c, /if \(\$keep -and \(Test-Path \(Join-Path \$old "install-host\.ps1"\)\) -and -not \(Capable \$old\)\) \{/);
  // and the markers it checks for are really in the scripts that carry them
  assert.ok(INSTALL.includes("ENCLAVE-IDENTITY-RECORD-V1") && UPDATE.includes("ENCLAVE-RELEASE-POLICY-V1"));
  // the CLI it calls exists
  for (const sub of ["resolve", "download"]) assert.match(read("windows", "node", "release-channel.mjs"), new RegExp(`cmd === "${sub}"`));
});

test("setup: no relay name check and no unsigned pointer in an independent or signed install", () => {
  const signed = SETUP.slice(SETUP.indexOf("void SignedDownload()"), SETUP.indexOf("// ---- 3. checks"));
  assert.doesNotMatch(signed, /latest\.json|Downloads \+|get\.enclave\.host/);
  assert.match(SETUP, /if \(opt\.ReleasePolicy != null\) \{ SignedDownload\(\); return; \}/);
  const check = SETUP.slice(SETUP.indexOf("void CheckName(string candidate)"), SETUP.indexOf("ThreadPool.QueueUserWorkItem(delegate", SETUP.indexOf("void CheckName(string candidate)")));
  assert.match(check, /if \(opt\.NoRelay\)[\s\S]*return;/, "an independent install never asks the relay about the name");
  assert.match(SETUP, /setup-options\.json/, "independent options survive the Hyper-V restart in a file, not a >260-character RunOnce line");
  assert.match(SETUP, /matches the UNSIGNED latest\.json/, "the legacy path says what its check is worth");
});

test("cli/host.ps1: signed mode never asks get.enclave.host and hands setup the same policy", () => {
  const signed = ONELINE.slice(ONELINE.indexOf("  if ($keys.Count) {"), ONELINE.indexOf("  } else {\n    # ---- the legacy channel"));
  assert.ok(signed.length > 1000);
  assert.doesNotMatch(code(signed), /get\.enclave\.host|latest\.json"/);
  assert.match(signed, /\$setupArgs \+= "--release-policy"/);
  assert.match(ONELINE, /throw "two different signed statements for version/);
  // no fallback to the unsigned channel from inside the signed one: a failure there throws out of the whole script
  assert.doesNotMatch(signed, /\$keys = @\(\)|Remove-Variable keys/);
  assert.match(ONELINE, /if \(-not \$keys\.Count -and "\$env:ENCLAVE_RELEASE_KEYS\$env:ENCLAVE_RELEASE_MIRRORS\$env:ENCLAVE_RELEASE_THRESHOLD\$env:ENCLAVE_RELEASE_CHANNEL"\.Trim\(\)\) \{\s*\n\s*throw/,
               "release settings with no key refuse instead of taking the unsigned channel");
});

test("cli/host.ps1: every download is bounded and checked before setup runs", () => {
  const c = code(ONELINE);
  // nothing buffers a whole answer or writes a whole file before its limit is checked
  assert.doesNotMatch(c, /Invoke-WebRequest|Invoke-RestMethod|WebClient|DownloadFile|DownloadString/);
  const rb = c.slice(c.indexOf("function Read-Bounded"), c.indexOf("\n}\n", c.indexOf("function Read-Bounded")));
  assert.match(rb, /if \(\$len -gt \$Max\) \{ throw/, "an announced length over the limit is refused before the body");
  assert.match(rb, /if \(\$got -gt \$Max\) \{ throw/, "a body over the limit is refused at the first byte over");
  assert.match(rb, /\$t = \$req\.GetResponseAsync\(\)\s*\n\s*if \(-not \$t\.Wait\(/, "headers waited for at most the time left");
  assert.match(rb, /\$r = \$body\.ReadAsync\(\$buf, 0, \$buf\.Length\)\s*\n\s*if \(-not \$r\.Wait\(/, "every body read waited for at most the time left");
  assert.match(rb, /if \(-not \$ok\) \{ try \{ \$req\.Abort\(\) \}/, "aborted (not drained) on failure, before anything is disposed");
  assert.match(rb, /\[IO\.FileMode\]::CreateNew/);
  // the pointer is read with a 64 KiB limit; setup with its signed size, then held and hashed again while it starts
  assert.match(c, /Read-Bounded -Url \(\$m \+ "latest\.signed\.json"\) -Max 65536 -DeadlineMs \$DeadlineMs/);
  assert.match(c, /Read-Bounded -Url \(\$m \+ \$Name\) -Max \$Bytes -Expect \$Bytes -OutFile \$part/);
  assert.match(c, /\[IO\.FileShare\]::Read\)\s*\n\s*try \{\s*\n\s*\$h = /);
  assert.match(c, /Start-CheckedSetup \$exe \$setupBytes \$setupSha \$setupArgs/);
  assert.equal([...c.matchAll(/Start-Process/g)].length, 2, "only Start-CheckedSetup starts anything");
  // the checks release-channel.mjs and EnclaveSetup.cs make: issue time, expiry, all three artifacts, signature list size
  for (const re of [/issued in the future/, /expired at/, /\$sigs\.Count -gt 16/, /"enclave-host-\$v\.zip", 2147483648/, /"EnclaveSetup-\$v\.exe", 67108864/,
                    /"manifest-\$v\.json", 16777216/, /the release keys list one key twice/, /CngKey\]::Import\(\$blob/])
    assert.match(c, re);
});

test("the work folder setup and the SYSTEM updater run from is SYSTEM's and Administrators' alone", () => {
  for (const src of [SETUP, UPDATE]) assert.ok(src.includes('"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"'));
  assert.equal([...SETUP.matchAll(/Directory\.CreateDirectory\(WorkDir\)/g)].length, 0, "setup never makes it with inherited access");
  assert.equal([...SETUP.matchAll(/SecureWorkDir\(\);/g)].length, 2, "both downloads secure it first");
  const main = code(UPDATE).slice(code(UPDATE).indexOf("try {\n  if (-not (Test-Path (Join-Path $PF \"manifest.json\"))"));
  assert.ok(main.indexOf("SecureWorkDir") > 0 && main.indexOf("SecureWorkDir") < main.indexOf("$W"), "the updater secures it before its first use");
  // setup's C# transport: a timer aborts the request at a hard deadline; the part file is new and random
  const rcs = SETUP.slice(SETUP.indexOf("static class ReleaseChannel"), SETUP.indexOf("/// <summary>Setup's progress"));
  assert.match(rcs, /new System\.Threading\.Timer\(delegate \{ late = true; try \{ q\.Abort\(\); \}/);
  assert.match(rcs, /catch \{ try \{ q\.Abort\(\); \} catch \{ \} throw; \}/);
  assert.match(rcs, /new FileStream\(part, FileMode\.CreateNew/);
  assert.doesNotMatch(code(rcs), /\$"|\\d/, "no .NET $ (matches before a final newline) or \\d (any script's digits) in its patterns");
});
