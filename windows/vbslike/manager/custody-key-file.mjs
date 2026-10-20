/* ============================================================
   THE CUSTODY CALLBACK KEY FILE (ENCLAVE_CUSTODY_CALLBACK_KEY_FILE), read by the manager (main.mjs) and the node agent
   (windows/node/agent.mjs): the HMAC key of the node's answers to custody requests (custody-transport.mjs). A local
   reader of it can forge those callbacks, so it is read only when it is PRIVATE to the identities that run the two:
     POSIX   mode & 0o077 === 0 (owner-only), as before;
     win32   the file's owner and every ALLOW entry of its DACL (explicit or inherited) are SYSTEM (S-1-5-18) or
             BUILTIN\Administrators (S-1-5-32-544) - the \Enclave\Shield and \Enclave\Node tasks run as SYSTEM
             (install-host.ps1) - SYSTEM may read it, and the DACL is not null. Deny entries are ignored.
   A file that is not private is REFUSED, naming the entry; nothing here changes an ACL or a mode. The installer creates
   the file private (install-host.ps1); an operator who made it otherwise fixes it explicitly.
   This guards against other local users, not against an administrator of this host (trusted on tier T0-hv).
   ============================================================ */
import fs from "node:fs";
import { spawnSync } from "node:child_process";

export const SID_SYSTEM = "S-1-5-18";
export const SID_ADMINISTRATORS = "S-1-5-32-544";
const ALLOWED = new Set([SID_SYSTEM, SID_ADMINISTRATORS]);
// FileSystemRights bits that let a holder READ the contents (ReadData 0x1, GenericRead 0x80000000, GenericAll
// 0x10000000) - for "SYSTEM may read it"
const READ_BITS = 0x1 | 0x80000000 | 0x10000000;

/** The PowerShell that states a file's owner and DACL as SIDs. The path arrives in an environment variable, never in the script text. */
export const ACL_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$a = Get-Acl -LiteralPath $env:ENCLAVE_KEY_ACL_PATH",
  "$sddl = $a.GetSecurityDescriptorSddlForm('Access')",
  "$sid = { param($r) try { $r.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { [string]$r } }",
  "[pscustomobject]@{ owner = (& $sid $a.GetOwner([System.Security.Principal.NTAccount])); sddl = $sddl;",
  "  aces = @($a.Access | ForEach-Object { [pscustomobject]@{ sid = (& $sid $_.IdentityReference); type = [string]$_.AccessControlType;",
  "    rights = [int64]$_.FileSystemRights; inherited = [bool]$_.IsInherited } }) } | ConvertTo-Json -Compress -Depth 4",
].join("; ");

/** win32: Get-Acl through powershell.exe -> { owner, sddl, aces: [{ sid, type, rights, inherited }] }. Throws when it cannot say. */
export function windowsAclOf(file, { run = spawnSync } = {}) {
  const r = run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ACL_SCRIPT],
    { encoding: "utf8", windowsHide: true, timeout: 20_000, env: { ...process.env, ENCLAVE_KEY_ACL_PATH: file } });
  if (r.error || r.status !== 0) throw new Error(`its ACL could not be read: ${String(r.error?.message || r.stderr || `exit ${r.status}`).trim().slice(0, 200)}`);
  let o;
  try { o = JSON.parse(String(r.stdout || "").trim()); } catch { throw new Error("its ACL could not be read: Get-Acl returned no JSON"); }
  const aces = Array.isArray(o?.aces) ? o.aces : o?.aces ? [o.aces] : [];       // ConvertTo-Json unwraps a one-element array
  return { owner: String(o?.owner || ""), sddl: String(o?.sddl || ""), aces };
}

/** -> null when the ACL is private to SYSTEM and Administrators, else the reason (naming the offending identity). */
export function windowsAclRefusal({ owner, sddl, aces } = {}) {
  if (!ALLOWED.has(String(owner || ""))) return `its owner is ${owner || "unknown"}, not SYSTEM (${SID_SYSTEM}) or Administrators (${SID_ADMINISTRATORS})`;
  // GetSecurityDescriptorSddlForm('Access') is the DACL part alone ("D:<flags>(ace)..."): a null DACL ("D:NO_ACCESS_CONTROL")
  // grants everyone everything, and anything that is not a DACL is not a statement either
  const dacl = String(sddl || "").trim();
  if (!dacl.startsWith("D:") || /^D:[A-Z_]*NO_ACCESS_CONTROL/.test(dacl)) return "it has no DACL (everyone may read it)";
  if (!Array.isArray(aces)) return "its DACL could not be read";
  let systemReads = false;
  for (const e of aces) {
    if (String(e?.type) !== "Allow") continue;
    const sid = String(e?.sid || "");
    if (!ALLOWED.has(sid)) return `${e?.inherited ? "an inherited" : "an"} entry allows ${sid || "an unknown identity"} (rights 0x${(Number(e?.rights) >>> 0).toString(16)}): only SYSTEM and Administrators may hold it`;
    if (sid === SID_SYSTEM && ((Number(e?.rights) >>> 0) & READ_BITS) !== 0) systemReads = true;
  }
  if (!systemReads) return "SYSTEM, which runs the manager and the node, may not read it";
  return null;
}

/**
 * readCustodyCallbackKey(file, { platform, aclOf }) -> Buffer (32-64 bytes). Throws "<why>" for a missing, non-regular,
 * non-private or malformed file; never alters it.
 */
export function readCustodyCallbackKey(file, { platform = process.platform, aclOf = windowsAclOf, stat = fs.statSync, read = fs.readFileSync } = {}) {
  if (!file) throw new Error("no key file is named");
  let st;
  try { st = stat(file); } catch (e) { throw new Error(`it cannot be read (${e.code || e.message})`); }
  if (!st.isFile()) throw new Error("it must be a regular file");
  if (platform === "win32") {
    const why = windowsAclRefusal(aclOf(file));
    if (why) throw new Error(`it is not private: ${why}`);
  } else if ((st.mode & 0o077) !== 0) throw new Error(`it is not private: mode ${(st.mode & 0o777).toString(8)} lets others read it (0600 needed)`);
  const hex = String(read(file, "utf8")).trim().toLowerCase();
  if (!/^[0-9a-f]{64,128}$/.test(hex) || hex.length % 2) throw new Error("it must hold 32-64 bytes of hex");
  return Buffer.from(hex, "hex");
}
