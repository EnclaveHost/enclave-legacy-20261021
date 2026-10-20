// windows/node/host-ownership.mjs -- prepare (never sign, never send) a Windows host's enrollment on a VERIFIED
// EnclaveHostOwnership deployment, and the node settings that switch its wallet veto to that contract once the owner
// has accepted.
//
// Why a separate step. A Windows host's local wallet veto (host-admission.bundle.mjs) is on when node-config.local.cmd
// names ENCLAVE_HOST_OWNERSHIP and its pins, and it FAILS CLOSED: pointed at a contract where this host has no accepted
// owner, it refuses every deployment. So the order is fixed and nothing here shortcuts it:
//   1. prepare: the unsigned proposeOwner (operator) / acceptOwner / setPolicy (owner) transactions, checked against the
//      verified authority record (contracts/deployments/independent-authorities-base.json: address, code hash and the
//      registry it is bound to), and the policy document to place on the host;
//   2. the operator nominates and the owner accepts and commits the policy - with their own wallets, outside this tool;
//   3. ownershipStatus reads the contract back (two agreeing RPCs) and says ready only when the owner and the policy
//      hash are set and the policy document is on the host;
//   4. only then are the generated settings added to node-config.local.cmd (which updates never write) and the node
//      restarted. Until step 4 the host keeps enforcing whatever it enforced before (for nucbox-k11-4, its existing
//      contract), so preparing never weakens a live veto.
import fs from "node:fs";
import path from "node:path";
import { keccak256, toBytes, parseAbi } from "viem";

const ADDR = /^0x[0-9a-f]{40}$/, ID = /^0x[0-9a-f]{64}$/, ZERO = "0x" + "0".repeat(40), ZERO32 = "0x" + "0".repeat(64);
const lc = (v) => String(v || "").toLowerCase();
const authorityABI = parseAbi(["function authority(bytes32) view returns (address owner,address pendingOwner,uint64 revision,bytes32 policyHash)",
                               "function registry() view returns (address)"]);

/**
 * The verified ownership authority from an independent-authorities record, cross-checked against the host's contract
 * pins: the contract the record verified, the registry its immutable binding names, and the catalog the record was made
 * for must all be the ones this host pins. -> { ownershipContract, codeHash, registry, catalog }
 */
export function verifiedOwnershipAuthority(authorities, pins) {
  if (!authorities || authorities.chainId !== 8453) throw new Error("authority record must be for Base (8453)");
  const v = authorities.verified?.contracts?.EnclaveHostOwnership;
  const ownershipContract = lc(authorities.addresses?.EnclaveHostOwnership);
  if (!ADDR.test(ownershipContract) || lc(v?.address) !== ownershipContract) throw new Error("authority record has no verified EnclaveHostOwnership");
  if (!/^0x[0-9a-f]{64}$/.test(lc(v.codeHash))) throw new Error("authority record has no verified code hash for EnclaveHostOwnership");
  const registry = lc(v.bindings?.registry);
  if (!ADDR.test(registry) || registry !== lc(authorities.inputs?.registry)) throw new Error("authority record's registry binding is inconsistent");
  if (!pins || lc(pins.registry) !== registry) throw new Error(`this host pins registry ${lc(pins?.registry) || "(none)"}, the verified ownership contract is bound to ${registry}`);
  const catalog = lc(authorities.inputs?.catalog);
  if (!ADDR.test(catalog) || lc(pins.appCatalog) !== catalog) throw new Error(`this host pins catalog ${lc(pins?.appCatalog) || "(none)"}, the authority record was made for ${catalog}`);
  return Object.freeze({ ownershipContract, codeHash: lc(v.codeHash), registry, catalog });
}

/** The settings that turn the wallet veto on for this contract, as env and as node-config.local.cmd lines. */
export function ownershipActivation({ authority, hostId, pinsFile, policyDir }) {
  if (!ID.test(lc(hostId))) throw new Error("host id must be bytes32");
  if (!pinsFile || !policyDir) throw new Error("the host's contract pin file and policy directory paths are required");
  const env = { ENCLAVE_CONTRACT_PINS_FILE: pinsFile, ENCLAVE_HOST_ID: lc(hostId), ENCLAVE_HOST_OWNERSHIP: authority.ownershipContract,
                ENCLAVE_HOST_REGISTRY_PIN: authority.registry, ENCLAVE_HOST_CATALOG_PIN: authority.catalog, ENCLAVE_HOST_POLICY_DIR: policyDir };
  const cmd = ["rem Wallet veto on the verified EnclaveHostOwnership " + authority.ownershipContract + " (host-ownership.mjs).",
               "rem Add to node-config.local.cmd ONLY after ownership-status reports ready; the veto fails closed before that.",
               ...Object.entries(env).map(([k, v]) => `set ${k}=${v}`)].join("\r\n") + "\r\n";
  return { env, cmd };
}

/**
 * Prepare the enrollment for one host: the policy must name the verified contract and this host's id (keccak256 of its
 * endpoint), and the contract on chain must have the verified code hash. -> prepareHostPolicy's result plus the checks.
 */
export async function prepareOwnershipEnrollment({ policy, owner, endpoint, authority, reader, prepareHostPolicy }) {
  const hostId = keccak256(toBytes(String(endpoint)));
  if (lc(policy?.ownershipContract) !== authority.ownershipContract) throw new Error(`the policy names ownership contract ${lc(policy?.ownershipContract)}, not the verified ${authority.ownershipContract}`);
  if (lc(policy?.hostId) !== hostId) throw new Error(`the policy is for host ${lc(policy?.hostId)}, but ${endpoint} is ${hostId}`);
  if (!ADDR.test(lc(owner)) || lc(owner) === ZERO) throw new Error("an exact nonzero owner wallet is required");
  if (!prepareHostPolicy) ({ prepareHostPolicy } = await import("../../scripts/network/prepare-host-policy.mjs"));
  const prepared = await prepareHostPolicy({ policy, owner: lc(owner), registry: authority.registry, reader });
  if (lc(prepared.observation?.ownershipCodeHash) !== authority.codeHash)
    throw new Error(`the contract at ${authority.ownershipContract} has code hash ${prepared.observation?.ownershipCodeHash}, not the verified ${authority.codeHash}`);
  return { ...prepared, hostId, endpoint, verifiedAuthority: authority };
}

/** Read the authority back -> { ready, why, owner, pendingOwner, revision, policyHash }. Ready means the switch is safe. */
export async function ownershipStatus({ authority, hostId, reader, policyDir }) {
  const a = await reader.agreed(async (c, blockNumber) => {
    const reg = lc(await c.readContract({ address: authority.ownershipContract, abi: authorityABI, functionName: "registry", blockNumber }));
    const [owner, pendingOwner, revision, policyHash] = await c.readContract({ address: authority.ownershipContract, abi: authorityABI, functionName: "authority", args: [hostId], blockNumber });
    return { registry: reg, owner: lc(owner), pendingOwner: lc(pendingOwner), revision: String(revision), policyHash: lc(policyHash) };
  });
  const out = { ...a, hostId: lc(hostId), ownershipContract: authority.ownershipContract };
  if (a.registry !== authority.registry) return { ...out, ready: false, why: "the contract's registry is not the pinned one" };
  if (a.owner === ZERO) return { ...out, ready: false, why: a.pendingOwner === ZERO ? "not nominated yet (operator: proposeOwner)" : `nominated ${a.pendingOwner}; waiting for acceptOwner` };
  if (a.policyHash === ZERO32) return { ...out, ready: true, why: "owner accepted with no committed policy: no catalog veto and no deny entries" };
  const doc = policyDir ? path.join(policyDir, `${a.policyHash}.json`) : null;
  if (doc && !fs.existsSync(doc)) return { ...out, ready: false, why: `the committed policy ${a.policyHash} is not in ${policyDir}: place it first, or the veto refuses everything` };
  return { ...out, ready: true, why: "owner accepted and the committed policy is on this host" };
}
