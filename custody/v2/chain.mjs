// Custody reads use a fresh majority-agreed block hash and immutable vault authorities.
import { createPublicClient, http, keccak256, toBytes, hexToBytes, stringToHex, encodeFunctionData, decodeFunctionResult } from "viem";
import { createQuorumReader } from "./quorum.mjs";

export const MACHINE = [
  { name: "identity", type: "address" }, { name: "encKey", type: "bytes32" }, { name: "endpoint", type: "string" },
  { name: "chipId", type: "bytes32" }, { name: "registryId", type: "bytes32" }, { name: "measurement", type: "bytes32" },
];
const M_ARR = { type: "tuple[]", components: MACHINE };
export const HOST_OWNERSHIP_ABI = [
  { type: "function", name: "authority", stateMutability: "view", inputs: [{type:"bytes32"}], outputs: [{type:"address"},{type:"address"},{type:"uint64"},{type:"bytes32"}] },
];
export const VAULT_V2_ABI = [
  { type: "function", name: "hostOwnership", stateMutability: "view", inputs: [], outputs: [{type:"address"}] },
  { type: "function", name: "hostRegistry", stateMutability: "view", inputs: [], outputs: [{type:"address"}] },
  { type: "function", name: "deploymentLedger", stateMutability: "view", inputs: [], outputs: [{type:"address"}] },
  { type: "function", name: "sessionVaultFactory", stateMutability: "view", inputs: [], outputs: [{type:"address"}] },
  { type: "function", name: "book", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "enclaveOwner", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "policyOf", stateMutability: "view", inputs: [{ name: "id", type: "bytes32" }],
    outputs: [{ name: "owner", type: "address" }, { name: "policyRev", type: "uint64" }, { name: "secretRev", type: "uint64" }, { name: "committeeId", type: "bytes32" }, { name: "paused", type: "bool" }, { name: "rules", type: "bytes" }] },
  { type: "function", name: "bundleOf", stateMutability: "view", inputs: [{ name: "id", type: "bytes32" }],
    outputs: [{ name: "committeeId", type: "bytes32" }, { name: "secretRev", type: "uint64" }, { name: "bundle", type: "bytes" }] },
  { type: "function", name: "beneficialOwnerOf", stateMutability: "view", inputs: [{ name: "id", type: "bytes32" }], outputs: [{ type: "address" }] },
  { type: "function", name: "committeeOf", stateMutability: "view", inputs: [{ name: "cid", type: "bytes32" }],
    outputs: [{ name: "Y", type: "bytes" }, { name: "epoch", type: "uint32" }, { name: "t", type: "uint8" }, { name: "W", type: "uint8" }, { name: "activatedAt", type: "uint64" }] },
  { type: "function", name: "machinesOf", stateMutability: "view", inputs: [{ name: "cid", type: "bytes32" }, { name: "epoch", type: "uint32" }],
    outputs: [{ name: "machines", ...M_ARR }, { name: "enclave", type: "bool[]" }] },
  { type: "function", name: "commitmentsOf", stateMutability: "view", inputs: [{ name: "cid", type: "bytes32" }, { name: "epoch", type: "uint32" }], outputs: [{ type: "bytes" }] },
  { type: "function", name: "pendingOf", stateMutability: "view", inputs: [{ name: "cid", type: "bytes32" }],
    outputs: [{ name: "toEpoch", type: "uint32" }, { name: "next", ...M_ARR }, { name: "enclave", type: "bool[]" }, { name: "t", type: "uint8" }, { name: "W", type: "uint8" }, { name: "dealers", type: "uint32[]" }, { name: "expires", type: "uint64" }] },
  { type: "function", name: "dealOf", stateMutability: "view", inputs: [{ name: "cid", type: "bytes32" }, { name: "toEpoch", type: "uint32" }, { name: "dealerIndex", type: "uint32" }],
    outputs: [{ name: "dealCommitments", type: "bytes" }, { name: "sealed", type: "bytes[]" }] },
  { type: "function", name: "ackCount", stateMutability: "view", inputs: [{ name: "cid", type: "bytes32" }, { name: "toEpoch", type: "uint32" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "codeActiveAt", stateMutability: "view", inputs: [{ name: "cid", type: "bytes32" }, { name: "measurement", type: "bytes32" }], outputs: [{ type: "uint64" }] },
  // writes (custodians sign; any funded account submits)
  { type: "function", name: "createIndependentCommittee", stateMutability: "nonpayable",
    inputs: [{ name: "salt", type: "bytes32" }, { name: "machines", ...M_ARR }, { name: "commitments", type: "bytes" },
      { name: "codeSet", type: "bytes32[]" }, { name: "identitySigs", type: "bytes[]" }, { name: "hostSigs", type: "bytes[]" }],
    outputs: [{ name: "committeeId", type: "bytes32" }] },
  { type: "function", name: "createCommittee", stateMutability: "nonpayable",
    inputs: [{ name: "salt", type: "bytes32" }, { name: "m", type: "tuple", components: MACHINE }, { name: "Y", type: "bytes" }, { name: "codeSet", type: "bytes32[]" }, { name: "identitySig", type: "bytes" }, { name: "hostSig", type: "bytes" }],
    outputs: [{ name: "committeeId", type: "bytes32" }] },
  { type: "function", name: "proposeHandover", stateMutability: "nonpayable",
    inputs: [{ name: "cid", type: "bytes32" }, { name: "next", ...M_ARR }, { name: "hostSigs", type: "bytes[]" }, { name: "dealerIndices", type: "uint32[]" }, { name: "approvers", type: "address[]" }, { name: "approvals", type: "bytes[]" }], outputs: [] },
  { type: "function", name: "postDeal", stateMutability: "nonpayable",
    inputs: [{ name: "cid", type: "bytes32" }, { name: "toEpoch", type: "uint32" }, { name: "dealerIndex", type: "uint32" }, { name: "dealCommitments", type: "bytes" }, { name: "sealed", type: "bytes[]" }, { name: "dealer", type: "address" }, { name: "sig", type: "bytes" }], outputs: [] },
  { type: "function", name: "ackHandover", stateMutability: "nonpayable",
    inputs: [{ name: "cid", type: "bytes32" }, { name: "toEpoch", type: "uint32" }, { name: "newCommitments", type: "bytes" }, { name: "machine", type: "address" }, { name: "sig", type: "bytes" }], outputs: [] },
  { type: "function", name: "proposeCode", stateMutability: "nonpayable",
    inputs: [{ name: "cid", type: "bytes32" }, { name: "measurement", type: "bytes32" }, { name: "approvers", type: "address[]" }, { name: "approvals", type: "bytes[]" }], outputs: [] },
  { type: "function", name: "removeCode", stateMutability: "nonpayable",
    inputs: [{ name: "cid", type: "bytes32" }, { name: "measurement", type: "bytes32" }, { name: "approvers", type: "address[]" }, { name: "approvals", type: "bytes[]" }], outputs: [] },
];
export const LEDGER_ABI = [{ type: "function", name: "get", stateMutability: "view", inputs: [{ name: "id", type: "bytes32" }], outputs: [{ type: "tuple", components: [
  { name: "id", type: "bytes32" }, { name: "owner", type: "address" }, { name: "appRef", type: "string" }, { name: "ports", type: "string" }, { name: "configCid", type: "string" },
  { name: "gpuMilli", type: "uint16" }, { name: "cpuMilli", type: "uint16" }, { name: "appPort", type: "uint32" }, { name: "isPublic", type: "bool" }, { name: "active", type: "bool" }, { name: "createdAt", type: "uint64" },
  { name: "rate", type: "uint256" }, { name: "balance6", type: "uint256" }, { name: "spent6", type: "uint256" },
  { name: "runner", type: "bytes32" }, { name: "runnerOperator", type: "address" }, { name: "leaseUntil", type: "uint64" }] }] }];
// EnclaveRegistry.get, the schema-4 PREFIX (appended fields keep offsets): operator, active and the self-set payoutWallet
export const REGISTRY_V4_ABI = [{ type: "function", name: "get", stateMutability: "view", inputs: [{ name: "id", type: "bytes32" }], outputs: [{ type: "tuple", components: [
  { name: "endpoint", type: "string" }, { name: "repo", type: "string" }, { name: "measurement", type: "bytes32" }, { name: "operator", type: "address" },
  { name: "registeredAt", type: "uint64" }, { name: "lastSeen", type: "uint64" }, { name: "active", type: "bool" },
  { name: "cpuPricePerSec6", type: "uint64" }, { name: "gpuPricePerSec6", type: "uint64" }, { name: "proofKey", type: "address" }, { name: "payoutWallet", type: "address" }] }] }];
const key = (s) => stringToHex(s, { size: 32 });
export const BOOK_KEYS = { deployments: key("deployments"), registry: key("registry") };
export const endpointIdOf = (endpoint) => keccak256(toBytes(endpoint));
const ZERO = "0x0000000000000000000000000000000000000000";
const b = (h) => hexToBytes(h === "0x" ? "0x" : h);
const err = (code, message, status = 503) => Object.assign(new Error(message), { code, status });
const lc = (a) => String(a).toLowerCase();
const machineOut = (m) => ({ identity: lc(m.identity), encKey: lc(m.encKey), endpoint: m.endpoint, chipId: lc(m.chipId), registryId: lc(m.registryId), measurement: lc(m.measurement) });

async function readCommitteeAt(rd, vault, cid) {
  const [Y, epoch, t, W, activatedAt] = await rd(vault, VAULT_V2_ABI, "committeeOf", [cid]);
  if (!epoch) return null;
  const [[machines, enclave], commitments] = await Promise.all([rd(vault, VAULT_V2_ABI, "machinesOf", [cid, epoch]), rd(vault, VAULT_V2_ABI, "commitmentsOf", [cid, epoch])]);
  return { committeeId: lc(cid), Y: b(Y), epoch: Number(epoch), t: Number(t), W: Number(W), activatedAt: Number(activatedAt),
           machines: machines.map((m, i) => ({ ...machineOut(m), enclave: enclave[i] })), commitments: b(commitments) };
}

// No number-only fallback: every eth_call must name this canonical hash.
const rdOf = (client, block) => async (address, abi, functionName, args = []) => {
  const data=encodeFunctionData({abi,functionName,args});
  const result=await client.request({method:'eth_call',params:[{to:address,data},{blockHash:block.blockHash,requireCanonical:true}]});
  return decodeFunctionResult({abi,functionName,data:result});
};

async function readReleaseAt(client, vault, { id, endpoint }, block) {
  const rd = rdOf(client,block);
  const [policy, bundle, ledgerAddr, registryAddr, beneficialOwner] = await Promise.all([
    rd(vault, VAULT_V2_ABI, "policyOf", [id]), rd(vault, VAULT_V2_ABI, "bundleOf", [id]),
    rd(vault, VAULT_V2_ABI, "deploymentLedger"), rd(vault, VAULT_V2_ABI, "hostRegistry"),
    rd(vault, VAULT_V2_ABI, "beneficialOwnerOf", [id])]);
  const [owner, policyRev, secretRev, committeeId, paused, rules] = policy;
  if (lc(ledgerAddr) === ZERO || lc(registryAddr) === ZERO) throw err("release_authority_missing", "pinned release authorities required");
  const epId = endpoint ? endpointIdOf(endpoint) : null;
  const zeroCid = /^0x0{64}$/.test(committeeId);
  const [row, reg, committee] = await Promise.all([
    ledgerAddr === ZERO ? null : rd(ledgerAddr, LEDGER_ABI, "get", [id]),
    !epId || registryAddr === ZERO ? null : rd(registryAddr, REGISTRY_V4_ABI, "get", [epId]),
    zeroCid ? null : readCommitteeAt(rd, vault, committeeId),
  ]);
  return {
    policy: { owner: lc(owner), policyRev, secretRev, committeeId: lc(committeeId), paused, rules: b(rules) },
    bundle: { committeeId: lc(bundle[0]), secretRev: bundle[1], data: b(bundle[2]) },
    committee,
    beneficialOwner: lc(beneficialOwner),
    lease: row ? { owner: lc(row.owner), runner: lc(row.runner), leaseUntil: Number(row.leaseUntil), appRef: row.appRef, envelope: row.configCid } : null,
    endpointId: epId ? lc(epId) : null,
    endpointOperator: reg && reg.active ? lc(reg.operator) : null,
  };
}
export function createChainReaderV2({ rpcs, vault, hostOwnership = null, chainId=null, minAgree, confirmations=0,
  clients: given=null, timeoutMs=10000, maxAgeSec=120, maxFutureSec=10, now=()=>Date.now(), checkpoint=null }) {
  if (!given && new Set((rpcs||[]).map(url=>new URL(url).hostname)).size !== (rpcs||[]).length)
    throw Error('chain: distinct RPC hostnames required');
  const clients = given || (rpcs || []).map(url=>createPublicClient({transport:http(url,{timeout:timeoutMs,retryCount:0})}));
  const agreed=createQuorumReader({clients,minAgree,chainId,confirmations,timeoutMs,maxAgeSec,maxFutureSec,now,checkpoint});
  return {
    vault, clients,
    readRelease: ({ id, endpoint }) => agreed((c, n) => readReleaseAt(c, vault, { id, endpoint }, n)),
    // the committee's current epoch, its machines (with on-chain Enclave flags) and commitments; plus any pending handover
    readCommittee: ({ committeeId }) => agreed(async (c, n) => {
      const rd = rdOf(c, n);
      const cur = await readCommitteeAt(rd, vault, committeeId);
      if (!cur) return { committee: null, pending: null };
      const p = await rd(vault, VAULT_V2_ABI, "pendingOf", [committeeId]);
      const pending = Number(p[0]) ? { toEpoch: Number(p[0]), next: p[1].map((m, i) => ({ ...machineOut(m), enclave: p[2][i] })), t: Number(p[3]), W: Number(p[4]),
                                       dealers: p[5].map(Number), expires: Number(p[6]), acks: Number(await rd(vault, VAULT_V2_ABI, "ackCount", [committeeId, p[0]])) } : null;
      return { committee: cur, pending };
    }),
    readDeal: ({ committeeId, toEpoch, dealerIndex }) => agreed(async (c, n) => {
      const [dc, sealed] = await rdOf(c, n)(vault, VAULT_V2_ABI, "dealOf", [committeeId, toEpoch, dealerIndex]);
      return { dealCommitments: b(dc), sealed: sealed.map(b) };
    }),
    readCodeActiveAt: ({ committeeId, measurement }) => agreed(async (c, n) => ({ activeAt: Number(await rdOf(c, n)(vault, VAULT_V2_ABI, "codeActiveAt", [committeeId, measurement])) })),
    // Membership is only supported on the wallet-authority vault release.
    // No fallback to payoutWallet or a mutable book registry. Old vaults must
    // keep their old measured membership runtime until a controlled handover.
    readRegistryEntry: ({ registryId }) => agreed(async (c, n) => {
      const rd = rdOf(c, n);
      const [reg, ownership] = await Promise.all([rd(vault, VAULT_V2_ABI, "hostRegistry"), rd(vault, VAULT_V2_ABI, "hostOwnership")]);
      if (hostOwnership && lc(ownership) !== lc(hostOwnership)) throw err("host_authority_mismatch", "vault host authority differs from the measured pin");
      if (reg === ZERO || ownership === ZERO) throw err("host_authority_missing", "wallet host authority required");
      const [e, authority] = await Promise.all([rd(reg, REGISTRY_V4_ABI, "get", [registryId]), rd(ownership, HOST_OWNERSHIP_ABI, "authority", [registryId])]);
      return { entry: { endpoint: e.endpoint, active: e.active, operator: lc(e.operator), payoutWallet: lc(e.payoutWallet), owner: lc(authority[0]) } };
    }),
  };
}
