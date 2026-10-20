// The custodian image's MEASURED configuration (scripts/build-custodian-v2.mjs bakes it into custody/v2/measured.mjs's
// place in the bundle). One function so the build, its tests and the daemon agree on the admission modes:
//   independentOwners: [3..64 wallets]  -> owner-list policy (only these owners may found or join)
//   independentAdmission: "owner-permits" -> any distinct non-Enclave owners that sign (governance.mjs)
// They are mutually exclusive; with neither, the image keeps the legacy Enclave-founded admission. Either independent
// mode needs the static DKG helper in the image.
//   shieldRecipients: {...}  -> the operator's OPTIONAL Enclave Shield recipient opt-in (custody/v2/shield-operator.mjs),
//                               validated here and again by the daemon; absent by default (SNP only, bytes unchanged)
//   trustedProxies: [ip, ...]  -> the host forwarder(s) whose X-Forwarded-For names the client for rate limiting
//                               (custody/v2/http.mjs clientKeyFor); absent by default: the TCP peer, one shared bucket
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { createHash } from "node:crypto";
import { Readable, Transform, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { independentOwners } from "./admission.mjs";
import { independentPolicy } from "./governance.mjs";
import { validateShieldOperator } from "./shield-operator.mjs";
import { validateTrustedProxies } from "./http.mjs";

export const ENCLAVE_OWNER = "0x0b2d009c0c9af05b12100d77f3c815fea822ee61";
export const MEASURED_RPCS = Object.freeze(["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org", "https://base.public.blockpi.network/v1/rpc/public"]);
const ADDRESS = /^0x[0-9a-f]{40}$/;

export function custodianMeasured({ vault, hostOwnership, transport = "direct", ownerList = null, admission = null, shieldRecipients = null, trustedProxies = null }) {
  vault = String(vault || "").toLowerCase(); hostOwnership = String(hostOwnership || "").toLowerCase();
  if (!ADDRESS.test(vault) || /^0x0{40}$/.test(vault)) throw new Error("--vault must be the deployed EnclaveSecretVaultV2");
  if (!ADDRESS.test(hostOwnership) || /^0x0{40}$/.test(hostOwnership)) throw new Error("--host-ownership must pin the accepted wallet authority for the new vault; legacy vaults require their compatible runtime");
  if (!["direct", "tunnel"].includes(transport)) throw new Error("--transport must be direct or tunnel");
  if (admission !== null && admission !== "owner-permits") throw new Error("--independent-admission must be owner-permits");
  if (admission && ownerList) throw new Error("--independent-admission owner-permits and --independent-owners are mutually exclusive");
  // Shield hosts reach the custodian's own /v2/custody/shield-session routes at its registered endpoint; the Enclave relay's
  // tunnel forwards only its fixed custody surfaces (relay/api-relay.js CUSTODY_SURFACES), so a tunnel image could never serve them
  if (shieldRecipients !== null && shieldRecipients !== undefined && transport !== "direct")
    throw new Error("--shield-recipients needs --transport direct (operator-owned ingress): the relay tunnel does not forward the Shield session routes");
  const measured = {
    chainId: 8453, transport, vault, hostOwnership, rpcs: [...MEASURED_RPCS],
    minAgree: 3, confirmations: 2, maxAgeSec: 120, enclaveOwner: ENCLAVE_OWNER,
    independentOwners: ownerList ? independentOwners(ownerList, ENCLAVE_OWNER) : null,
    // present only when set, so legacy and owner-list images stay byte-identical to their earlier builds
    ...(admission ? { independentAdmission: admission } : {}),
    capacityContract: "0x87c7266543ff5839b2c20226bd9b3cd511a23641", witnesses: { "0xd80bf435467df887f1031743c2a2125a130fe225": "enclave-bootstrap" },
    // present only when the operator opts in, so every other image's measured text is unchanged
    ...(shieldRecipients !== null && shieldRecipients !== undefined ? { shieldRecipients: shieldSection(shieldRecipients) } : {}),
    ...(trustedProxies !== null && trustedProxies !== undefined ? { trustedProxies: proxySection(trustedProxies) } : {}),
  };
  const policy = independentPolicy(measured);          // the daemon's own interpretation must accept it
  return { measured, policy: policy ? policy.mode : null, needsDkg: !!policy };
}
function shieldSection(cfg) {
  try { const v = validateShieldOperator(cfg); return { format: v.format, acceptTier: v.acceptTier, ekRoots: v.ekRoots, ekRootPins: [...v.ekRootPins], limits: { ...v.limits } }; }
  catch (e) { throw new Error(`--shield-recipients: ${e.message}`); }
}
function proxySection(list) {
  try { const v = validateTrustedProxies(list); if (!v.length) throw new Error("name at least one address, or omit the flag"); return v; }
  catch (e) { throw new Error(`--trusted-proxy: ${e.message.replace(/^trusted proxies: /, "")}`); }
}
export const measuredModule = (measured) => `export const MEASURED = Object.freeze(${JSON.stringify(measured)});\n`;

// The base initramfs, hashed while read and inflated into ONE buffer sized by its gzip trailer: the compressed file and
// a second inflated copy are never held at once (an ~800 MB control image would otherwise need well over 2 GiB).
export async function readGzipFile(file) {
  const fd = fs.openSync(file, "r");
  let isize;
  try { const tail = Buffer.alloc(4); fs.readSync(fd, tail, 0, 4, fs.fstatSync(fd).size - 4); isize = tail.readUInt32LE(0); } finally { fs.closeSync(fd); }
  const raw = Buffer.allocUnsafe(isize), hash = createHash("sha256");
  let off = 0;
  await pipeline(fs.createReadStream(file), new Transform({ transform(c, _, cb) { hash.update(c); cb(null, c); } }), zlib.createGunzip(),
    new Writable({ write(c, _, cb) { if (off + c.length > isize) return cb(new Error("initramfs is larger than its gzip trailer")); c.copy(raw, off); off += c.length; cb(); } }));
  if (off !== isize) throw new Error("initramfs size differs from its gzip trailer");
  return { raw, sha256: hash.digest("hex") };
}
// The rewritten cpio parts, deflated straight to a new file (never concatenated); byte-identical to gzipSync(concat).
export async function gzipPartsToFile(parts, file, level = 9) {
  const hash = createHash("sha256");
  let bytes = 0;
  await pipeline(Readable.from(parts), zlib.createGzip({ level }), new Transform({ transform(c, _, cb) { hash.update(c); bytes += c.length; cb(null, c); } }),
    fs.createWriteStream(file, { flags: "wx", mode: 0o644 }));
  return { sha256: hash.digest("hex"), bytes };
}

// ---- the bundle's own sources ----
// The esbuild options both bundles use (the custodian daemon and gsup), with MEASURED replaced by `measuredText`.
export const bundleOptions = (measuredText, { root }) => ({ absWorkingDir: root, bundle: true, platform: "node", format: "esm", target: "node22", metafile: true,
  write: false, legalComments: "none", banner: { js: 'import { createRequire as __cr } from "node:module"; const require = __cr(import.meta.url);' },
  plugins: [{ name: "measured", setup(b) { b.onLoad({ filter: /custody[\\/]v2[\\/]measured\.mjs$/ }, () => ({ contents: measuredText, loader: "js" })); } }] });

// The sources the build always pins besides the bundles' inputs: the Go helper, the script itself, and the npm lock that
// decides every node_modules input.
// snpkey imports only the Go standard library (go list -deps), so its directory plus the module files that set its language
// version are its whole source; the DKG helper and its Cargo.lock are under "custody".
export const STATIC_IMAGE_SOURCES = Object.freeze(["custody", "isolation/m2/cmd/snpkey", "isolation/m2/go.mod", "isolation/m2/go.sum", "relay/snp-verify.mjs", "verifier",
  "scripts/build-custodian-v2.mjs", "package.json", "package-lock.json"]);

/**
 * bundleSources(metafiles, { root }) -> { repo: [repo-relative paths], packages: [name@version] }
 * Every input esbuild actually read (metafile.inputs), split into repository files and node_modules packages.
 */
export function bundleSources(metafiles, { root }) {
  const repo = new Set(), packages = new Set();
  for (const mf of metafiles) for (const input of Object.keys(mf?.inputs || {})) {
    const abs = path.resolve(root, input), rel = path.relative(root, abs).split(path.sep).join("/");
    if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error(`bundle input ${input} is outside the repository`);
    const nm = rel.lastIndexOf("node_modules/");
    if (nm >= 0) {
      const parts = rel.slice(nm + "node_modules/".length).split("/"), name = parts[0].startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
      let version = "?";
      try { version = JSON.parse(fs.readFileSync(path.join(root, rel.slice(0, nm), "node_modules", name, "package.json"), "utf8")).version; } catch {}
      packages.add(`${name}@${version}`);
    } else repo.add(rel);
  }
  return { repo: [...repo].sort(), packages: [...packages].sort() };
}

/**
 * sourceCheck({ repo }, { git }) -> { paths, untracked: [...], dirty: "porcelain" }
 * git(args) -> stdout. Every repository input and every STATIC_IMAGE_SOURCES path must be TRACKED (an ignored or new
 * file shows nowhere in `git status`) and CLEAN.
 */
export function sourceCheck({ repo }, { git }) {
  const paths = [...new Set([...STATIC_IMAGE_SOURCES, ...repo])];
  const tracked = new Set(git(["ls-files", "--", ...repo]).split("\n").map((l) => l.trim()).filter(Boolean));
  const untracked = repo.filter((p) => !tracked.has(p));
  const dirty = git(["status", "--porcelain", "--", ...paths]).trim();
  return { paths, untracked, dirty };
}
