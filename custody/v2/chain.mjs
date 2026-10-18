// Chain reads for custody v2 (EnclaveSecretVaultV2, docs/security/secret-custody-v2-spec.md §1), with v1's agreement rule:
// every read is pinned to the HIGHEST head any RPC reports, at least `minAgree` RPCs must return byte-identical state at
// that block, and (custodians, relay) the block must be fresh against this machine's clock (maxAgeSec).
import { createPublicClient, http, keccak256, toBytes, bytesToHex, hexToBytes, stringToHex } from "viem";

const BOOK_ABI = [{ type: "function", name: "addr", stateMutability: "view", inputs: [{ name: "key", type: "bytes32" }], outputs: [{ type: "address" }] }];
export const MACHINE = [
  { name: "identity", type: "address" }, { name: "encKey", type: "bytes32" }, { name: "endpoint", type: "string" },
  { name: "chipId", type: "bytes32" }, { name: "registryId", type: "bytes32" }, { name: "measurement", type: "bytes32" },
];
const M_ARR = { type: "tuple[]", components: MACHINE };
const HOST_OWNERSHIP_ABI = [
  { type: "function", name: "authority", stateMutability: "view", inputs: [{type:"bytes32"}], outputs: [{type:"address"},{type:"address"},{type:"uint64"},{type:"bytes32"}] },
];
export const VAULT_V2_ABI = [
  { type: "function", name: "hostOwnership", stateMutability: "view", inputs: [], outputs: [{type:"address"}] },
  { type: "function", name: "hostRegistry", stateMutability: "view", inputs: [], outputs: [{type:"address"}] },
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
const LEDGER_ABI = [{ type: "function", name: "get", stateMutability: "view", inputs: [{ name: "id", type: "bytes32" }], outputs: [{ type: "tuple", components: [
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

async function readReleaseAt(client, vault, { id, endpoint }, blockNumber) {
  const rd = (address, abi, functionName, args = []) => client.readContract({ address, abi, functionName, args, blockNumber });
  const [policy, bundle, bookAddr, beneficialOwner] = await Promise.all([
    rd(vault, VAULT_V2_ABI, "policyOf", [id]), rd(vault, VAULT_V2_ABI, "bundleOf", [id]), rd(vault, VAULT_V2_ABI, "book"), rd(vault, VAULT_V2_ABI, "beneficialOwnerOf", [id])]);
  const [owner, policyRev, secretRev, committeeId, paused, rules] = policy;
  const [ledgerAddr, registryAddr] = await Promise.all([rd(bookAddr, BOOK_ABI, "addr", [BOOK_KEYS.deployments]), rd(bookAddr, BOOK_ABI, "addr", [BOOK_KEYS.registry])]);
  const epId = endpoint ? endpointIdOf(endpoint) : null;
  const zeroCid = /^0x0{64}$/.test(committeeId);
  const [row, reg, committee] = await Promise.all([
    ledgerAddr === ZERO ? null : rd(ledgerAddr, LEDGER_ABI, "get", [id]),
    !epId || registryAddr === ZERO ? null : rd(registryAddr, REGISTRY_V4_ABI, "get", [epId]),
    zeroCid ? null : readCommitteeAt(rd, vault, committeeId),
  ]);
  const blk = await client.getBlock({ blockNumber });
  return {
    blockNumber: blk.number, blockTimestamp: Number(blk.timestamp),
    policy: { owner: lc(owner), policyRev, secretRev, committeeId: lc(committeeId), paused, rules: b(rules) },
    bundle: { committeeId: lc(bundle[0]), secretRev: bundle[1], data: b(bundle[2]) },
    committee,
    beneficialOwner: lc(beneficialOwner),
    lease: row ? { owner: lc(row.owner), runner: lc(row.runner), leaseUntil: Number(row.leaseUntil), appRef: row.appRef, envelope: row.configCid } : null,
    endpointId: epId ? lc(epId) : null,
    endpointOperator: reg && reg.active ? lc(reg.operator) : null,
  };
}
const digest = (o) => JSON.stringify(o, (k, v) => (typeof v === "bigint" ? `n${v}` : v instanceof Uint8Array ? `x${bytesToHex(v)}` : v));

export function createChainReaderV2({ rpcs, vault, hostOwnership = null, minAgree, confirmations = 0, clients: given = null, timeoutMs = 10_000, maxAgeSec = null, now = () => Date.now() }) {
  const clients = given || (rpcs || []).map((url) => createPublicClient({ transport: http(url, { timeout: timeoutMs, retryCount: 1 }) }));
  if (!clients.length) throw new Error("chain: no RPC configured");
  if (!Number.isInteger(minAgree) || minAgree < 1 || minAgree > clients.length) throw new Error(`chain: minAgree must be 1..${clients.length} (state it explicitly)`);
  async function agreed(fn) {
    const heads = await Promise.allSettled(clients.map((c) => c.getBlockNumber({ cacheTime: 0 })));
    const ok = heads.filter((h) => h.status === "fulfilled").map((h) => h.value);
    if (ok.length < minAgree) throw err("chain_unconfirmed", `only ${ok.length} of ${clients.length} RPCs answered (need ${minAgree})`);
    const head = ok.reduce((a, x) => (x > a ? x : a)) - BigInt(confirmations);
    const reads = await Promise.allSettled(clients.map((c) => fn(c, head)));
    const got = reads.filter((r) => r.status === "fulfilled").map((r) => r.value);
    if (got.length < minAgree) {
      const why = reads.find((r) => r.status === "rejected");
      throw err("chain_unconfirmed", `only ${got.length} RPCs could read block ${head} (need ${minAgree})${why ? `: ${String(why.reason?.shortMessage || why.reason?.message || why.reason).split("\n")[0].slice(0, 160)}` : ""}`);
    }
    const d0 = digest(got[0]);
    if (got.some((g) => digest(g) !== d0)) throw err("chain_unconfirmed", `RPCs disagree about block ${head}`);
    return got[0];
  }
  const fresh = (st) => {
    if (maxAgeSec != null && st.blockTimestamp < Math.floor(now() / 1000) - maxAgeSec)
      throw err("chain_stale", `the newest block the RPCs agree on is ${Math.floor(now() / 1000) - st.blockTimestamp} s old (limit ${maxAgeSec} s)`);
    return st;
  };
  const withBlock = (fn) => async (c, n) => { const r = await fn(c, n); const blk = await c.getBlock({ blockNumber: n }); return { ...r, blockNumber: blk.number, blockTimestamp: Number(blk.timestamp) }; };
  const rdOf = (c, n) => (address, abi, functionName, args = []) => c.readContract({ address, abi, functionName, args, blockNumber: n });
  return {
    vault, clients,
    readRelease: ({ id, endpoint }) => agreed((c, n) => readReleaseAt(c, vault, { id, endpoint }, n)).then(fresh),
    // the committee's current epoch, its machines (with on-chain Enclave flags) and commitments; plus any pending handover
    readCommittee: ({ committeeId }) => agreed(withBlock(async (c, n) => {
      const rd = rdOf(c, n);
      const cur = await readCommitteeAt(rd, vault, committeeId);
      if (!cur) return { committee: null, pending: null };
      const p = await rd(vault, VAULT_V2_ABI, "pendingOf", [committeeId]);
      const pending = Number(p[0]) ? { toEpoch: Number(p[0]), next: p[1].map((m, i) => ({ ...machineOut(m), enclave: p[2][i] })), t: Number(p[3]), W: Number(p[4]),
                                       dealers: p[5].map(Number), expires: Number(p[6]), acks: Number(await rd(vault, VAULT_V2_ABI, "ackCount", [committeeId, p[0]])) } : null;
      return { committee: cur, pending };
    })).then(fresh),
    readDeal: ({ committeeId, toEpoch, dealerIndex }) => agreed(withBlock(async (c, n) => {
      const [dc, sealed] = await rdOf(c, n)(vault, VAULT_V2_ABI, "dealOf", [committeeId, toEpoch, dealerIndex]);
      return { dealCommitments: b(dc), sealed: sealed.map(b) };
    })),
    readCodeActiveAt: ({ committeeId, measurement }) => agreed(withBlock(async (c, n) => ({ activeAt: Number(await rdOf(c, n)(vault, VAULT_V2_ABI, "codeActiveAt", [committeeId, measurement])) }))),
    // Membership is only supported on the wallet-authority vault release.
    // No fallback to payoutWallet or a mutable book registry. Old vaults must
    // keep their old measured membership runtime until a controlled handover.
    readRegistryEntry: ({ registryId }) => agreed(withBlock(async (c, n) => {
      const rd = rdOf(c, n);
      const [reg, ownership] = await Promise.all([rd(vault, VAULT_V2_ABI, "hostRegistry"), rd(vault, VAULT_V2_ABI, "hostOwnership")]);
      if (hostOwnership && lc(ownership) !== lc(hostOwnership)) throw err("host_authority_mismatch", "vault host authority differs from the measured pin");
      if (reg === ZERO || ownership === ZERO) throw err("host_authority_missing", "wallet host authority required");
      const [e, authority] = await Promise.all([rd(reg, REGISTRY_V4_ABI, "get", [registryId]), rd(ownership, HOST_OWNERSHIP_ABI, "authority", [registryId])]);
      return { entry: { endpoint: e.endpoint, active: e.active, operator: lc(e.operator), payoutWallet: lc(e.payoutWallet), owner: lc(authority[0]) } };
    })).then(fresh),
  };
}
