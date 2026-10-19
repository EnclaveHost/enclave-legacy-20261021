// The custodian image's MEASURED configuration (scripts/build-custodian-v2.mjs bakes it into custody/v2/measured.mjs's
// place in the bundle). One function so the build, its tests and the daemon agree on the admission modes:
//   independentOwners: [3..64 wallets]  -> owner-list policy (only these owners may found or join)
//   independentAdmission: "owner-permits" -> any distinct non-Enclave owners that sign (governance.mjs)
// They are mutually exclusive; with neither, the image keeps the legacy Enclave-founded admission. Either independent
// mode needs the static DKG helper in the image.
import fs from "node:fs";
import zlib from "node:zlib";
import { createHash } from "node:crypto";
import { Readable, Transform, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { independentOwners } from "./admission.mjs";
import { independentPolicy } from "./governance.mjs";

export const ENCLAVE_OWNER = "0x0b2d009c0c9af05b12100d77f3c815fea822ee61";
export const MEASURED_RPCS = Object.freeze(["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org", "https://base.public.blockpi.network/v1/rpc/public"]);
const ADDRESS = /^0x[0-9a-f]{40}$/;

export function custodianMeasured({ vault, hostOwnership, transport = "direct", ownerList = null, admission = null }) {
  vault = String(vault || "").toLowerCase(); hostOwnership = String(hostOwnership || "").toLowerCase();
  if (!ADDRESS.test(vault) || /^0x0{40}$/.test(vault)) throw new Error("--vault must be the deployed EnclaveSecretVaultV2");
  if (!ADDRESS.test(hostOwnership) || /^0x0{40}$/.test(hostOwnership)) throw new Error("--host-ownership must pin the accepted wallet authority for the new vault; legacy vaults require their compatible runtime");
  if (!["direct", "tunnel"].includes(transport)) throw new Error("--transport must be direct or tunnel");
  if (admission !== null && admission !== "owner-permits") throw new Error("--independent-admission must be owner-permits");
  if (admission && ownerList) throw new Error("--independent-admission owner-permits and --independent-owners are mutually exclusive");
  const measured = {
    chainId: 8453, transport, vault, hostOwnership, rpcs: [...MEASURED_RPCS],
    minAgree: 3, confirmations: 2, maxAgeSec: 120, enclaveOwner: ENCLAVE_OWNER,
    independentOwners: ownerList ? independentOwners(ownerList, ENCLAVE_OWNER) : null,
    // present only when set, so legacy and owner-list images stay byte-identical to their earlier builds
    ...(admission ? { independentAdmission: admission } : {}),
    capacityContract: "0x87c7266543ff5839b2c20226bd9b3cd511a23641", witnesses: { "0xd80bf435467df887f1031743c2a2125a130fe225": "enclave-bootstrap" },
  };
  const policy = independentPolicy(measured);          // the daemon's own interpretation must accept it
  return { measured, policy: policy ? policy.mode : null, needsDkg: !!policy };
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
