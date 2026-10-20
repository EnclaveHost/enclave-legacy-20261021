// Owner-committed custody rules that admit an Enclave Shield partition (Hyper-V, tier T0-hv) as a release recipient. A
// DISTINCT rule format, written by the owner into the vault policy (EnclaveSecretVault policy.rules) in place of the SNP
// rules (custody/rules.mjs). The two never stand in for each other:
//   - custody/rules.mjs (unchanged) refuses this object (its exact keys are v, appId, images, minTcb, vmpl), and refuses the
//     platform "shield" by name, so default and SEV-SNP rules never admit Shield evidence;
//   - this parser refuses SNP rules (no format, no acknowledgement), so Shield rules never admit SNP evidence by accident;
//   - the custodian uses this parser ONLY for an evidence document of the Shield format, and only when its operator
//     installed the Shield adapter (custody/v2/shield-evidence.mjs; custodian.mjs `shield`).
//
//   {
//     "format": "enclave-custody-shield-rules/1",
//     "acceptTier": "windows-tpm-host/hv-node/T0-hv/hostExcluded:false",   the owner's explicit acknowledgement, exactly
//     "appId": "<64 hex>",                                                  report user-data[32:64]: the app the monitor loaded
//     "images": [ { "measurement": "<64 hex VBS launch digest>", "runtimeId": "<64 hex>" } ],   admitted (image, runtime) PAIRS
//     "platforms": "attested" | [ { "ekCertSha256": "<64 hex>", "pcr0": "<64 hex>" } ],         TPM/firmware pairs, or any
//                                                                                              TPM chaining to the custodian's
//                                                                                              pinned roots on an accepted boot
//     "minimumGuestSvn": 0                                                  optional
//   }
// What the acknowledgement means: the host's physical operator and hypervisor are TRUSTED (no memory encryption against
// them), the evidence is the host's TPM and the secure kernel's signature over the partition's report, and the host is not
// excluded. An owner who commits these rules accepts that for these values.
import { platformsValid } from "../../relay/vbs-app-core.mjs";

export const SHIELD_RULES_FORMAT = "enclave-custody-shield-rules/1";
export const SHIELD_TIER_ACK = "windows-tpm-host/hv-node/T0-hv/hostExcluded:false";
const HEX64 = /^[0-9a-f]{64}$/;
const MAX_IMAGES = 64;

function exactKeys(o, keys, optional, what) {
  if (!o || typeof o !== "object" || Array.isArray(o)) throw new Error(`${what} must be an object`);
  for (const k of Object.keys(o)) if (!keys.includes(k) && !optional.includes(k)) throw new Error(`${what}: unknown key "${k}"`);
  for (const k of keys) if (!(k in o)) throw new Error(`${what}: "${k}" is required`);
}

export function validateShieldRules(r) {
  exactKeys(r, ["format", "acceptTier", "appId", "images", "platforms"], ["minimumGuestSvn"], "Shield rules");
  if (r.format !== SHIELD_RULES_FORMAT) throw new Error(`Shield rules: format must be ${SHIELD_RULES_FORMAT}`);
  if (r.acceptTier !== SHIELD_TIER_ACK) throw new Error(`Shield rules: acceptTier must be exactly "${SHIELD_TIER_ACK}" (the owner's acknowledgement of this tier)`);
  if (typeof r.appId !== "string" || !HEX64.test(r.appId)) throw new Error("Shield rules: appId must be 64 lowercase hex");
  if (!Array.isArray(r.images) || !r.images.length || r.images.length > MAX_IMAGES) throw new Error(`Shield rules: images: 1..${MAX_IMAGES}`);
  const seen = new Set();
  for (const [i, im] of r.images.entries()) {
    exactKeys(im, ["measurement", "runtimeId"], [], `Shield rules images[${i}]`);
    if (!HEX64.test(String(im.measurement)) || !HEX64.test(String(im.runtimeId))) throw new Error(`Shield rules images[${i}]: measurement and runtimeId must be 64 lowercase hex`);
    const k = `${im.measurement}/${im.runtimeId}`;
    if (seen.has(k)) throw new Error(`Shield rules images[${i}] repeats an image`);
    seen.add(k);
  }
  if (!platformsValid(r.platforms)) throw new Error('Shield rules: platforms must be "attested" or explicit {ekCertSha256, pcr0} pairs');
  if (r.minimumGuestSvn !== undefined && (!Number.isSafeInteger(r.minimumGuestSvn) || r.minimumGuestSvn < 0)) throw new Error("Shield rules: minimumGuestSvn must be a non-negative integer");
  return r;
}

/** the bytes on chain -> Shield rules; throws for anything else, SNP rules included */
export function parseShieldRules(bytes) {
  const s = typeof bytes === "string" ? bytes : new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  let o;
  try { o = JSON.parse(s); } catch { throw new Error("rules are not JSON"); }
  return validateShieldRules(o);
}

const sortKeys = (x) => Array.isArray(x) ? x.map(sortKeys)
  : x && typeof x === "object" ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, sortKeys(x[k])])) : x;
export const canonicalShieldRules = (rules) => new TextEncoder().encode(JSON.stringify(sortKeys(validateShieldRules(rules))));

/** the VBS launch digests a guest stating `runtimeIdHex` may run in */
export const shieldAdmittedMeasurements = (rules, runtimeIdHex) => rules.images.filter((im) => im.runtimeId === runtimeIdHex).map((im) => im.measurement);
