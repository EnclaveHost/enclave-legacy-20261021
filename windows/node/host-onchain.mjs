// windows/node/host-onchain.mjs -- the owner's side of putting a consumer node on the ledger.
//
// The node itself registers, claims, renews and proves with the operator key on the box
// (host.mjs). Three things it CANNOT do, because they belong to the owner's wallet, live here:
//
//   fund-operator   send the box's operator key a little Base ETH for gas. It is a gas tank, not
//                   a payment: earnings never touch that key.
//   declare-payout  EnclaveRegistry.setPayoutWallet(id), which records msg.sender and therefore
//                   can only come from the wallet itself. Once declared, deployments OWNED by
//                   that wallet run on this box for nothing (_hostRate returns 0 when
//                   payoutWallet == owner), and this node claims only that wallet's work.
//   deploy          EnclaveDeployments.create(...) for an app from the catalog. The CLI's `enclave
//                   deploy` is the normal route and does much more (pricing, minimum shares,
//                   secrets, waiting); it needs a SERVING enclave to quote a price from, which a
//                   fleet of owner-only nodes has none of, so this is the direct equivalent.
//
// Usage (OWNER_KEY is the owner's private key; never the box's operator key). The host is PUBLIC_URL, or the legacy relay
// route of NODE_NAME (https://api.enclave.host/t/<name>); one of them is required - there is no default host.
//   OWNER_KEY=0x… node host-onchain.mjs status                 (OWNER_KEY optional here: without it, no owner balance)
//   OWNER_KEY=0x… node host-onchain.mjs fund-operator <0xoperator> [eth]
//   OWNER_KEY=0x… node host-onchain.mjs declare-payout [endpoint]
//   OWNER_KEY=0x… node host-onchain.mjs deploy <catalog://appId/index> [cpuPercent] [maxRateUsdPerHour]
//
// HOST OWNERSHIP on a verified EnclaveHostOwnership (host-ownership.mjs). READ-ONLY, no key of any kind: they prepare
// and check, they never sign or send. ENCLAVE_CONTRACT_PINS_FILE is required (the registry and catalog the verified
// contract is bound to must be the ones this host pins); --authorities defaults to the repo's
// contracts/deployments/independent-authorities-base.json (the verified 0xF5E9E6C0… deployment).
//   node host-onchain.mjs prepare-ownership --policy <policy.json> --owner <0xwallet> --out <new-dir> --policy-dir <dir> [--authorities <file>]
//       -> <out>/<policyHash>.json (place it in the host's ENCLAVE_HOST_POLICY_DIR), transactions.json (UNSIGNED:
//          proposeOwner from the operator key, acceptOwner and setPolicy from the owner wallet), node-config.ownership.cmd
//   node host-onchain.mjs ownership-status [--policy-dir <dir>] [--authorities <file>]
//       -> whether the owner has accepted and the committed policy is on the host: only then add
//          node-config.ownership.cmd to node-config.local.cmd (the veto fails closed before that)
import { createWalletClient, createPublicClient, http, fallback, parseEther, formatEther, getAddress, keccak256, toBytes, decodeEventLog } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
import * as chain from "./chain.mjs";

const RPCS = (process.env.BASE_RPCS || "https://base-rpc.publicnode.com,https://base.drpc.org,https://mainnet.base.org").split(",").map((s) => s.trim()).filter(Boolean);
const ENDPOINT = process.env.PUBLIC_URL || (process.env.NODE_NAME ? `https://api.enclave.host/t/${process.env.NODE_NAME}` : "");
if (!ENDPOINT) { console.error("set PUBLIC_URL (this host's registered endpoint), or NODE_NAME for a relay-routed host"); process.exit(2); }
const [cmd, ...rest] = process.argv.slice(2);
const opt = (name, dflt = "") => { const i = rest.indexOf(`--${name}`); return i >= 0 && rest[i + 1] ? rest[i + 1] : dflt; };
const enclaveId = keccak256(toBytes(ENDPOINT));
const pub = createPublicClient({ chain: base, transport: fallback(RPCS.map((u) => http(u))) });

if (cmd === "prepare-ownership" || cmd === "ownership-status") {
  const fs = await import("node:fs"), path = await import("node:path"), { fileURLToPath } = await import("node:url");
  const own = await import("./host-ownership.mjs"), { quorumReader, rpcClients } = await import("./host-identity.mjs");
  if (!chain.CONTRACT_PINS) { console.error("set ENCLAVE_CONTRACT_PINS_FILE: ownership is prepared only against pinned contracts"); process.exit(2); }
  const authFile = opt("authorities", path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "contracts", "deployments", "independent-authorities-base.json"));
  const authority = own.verifiedOwnershipAuthority(JSON.parse(fs.readFileSync(authFile, "utf8")), chain.CONTRACT_PINS);
  const reader = quorumReader({ clients: await rpcClients(RPCS) });
  const policyDir = opt("policy-dir", process.env.ENCLAVE_HOST_POLICY_DIR || "");
  if (cmd === "ownership-status") {
    console.log(JSON.stringify(await own.ownershipStatus({ authority, hostId: enclaveId, reader, policyDir }), null, 1));
    process.exit(0);
  }
  const policyFile = opt("policy"), wallet = opt("owner"), out = opt("out");
  // --policy-dir is the host's ENCLAVE_HOST_POLICY_DIR as the HOST sees it (the generated settings name it); not guessed
  if (!policyFile || !wallet || !out || !policyDir) { console.error("prepare-ownership --policy <policy.json> --owner <0xwallet> --out <new-dir> --policy-dir <host's policy dir> [--authorities <file>]"); process.exit(2); }
  const prepared = await own.prepareOwnershipEnrollment({ policy: JSON.parse(fs.readFileSync(policyFile, "utf8")), owner: wallet, endpoint: ENDPOINT, authority, reader });
  const activation = own.ownershipActivation({ authority, hostId: enclaveId, pinsFile: process.env.ENCLAVE_CONTRACT_PINS_FILE, policyDir });
  fs.mkdirSync(out);                                   // a new directory: an earlier signing package is never overwritten
  fs.writeFileSync(path.join(out, `${prepared.policyHash}.json`), JSON.stringify(prepared.policy, null, 2) + "\n", { flag: "wx" });
  fs.writeFileSync(path.join(out, "transactions.json"), JSON.stringify({ ...prepared, activation: activation.env }, null, 2) + "\n", { flag: "wx" });
  fs.writeFileSync(path.join(out, "node-config.ownership.cmd"), activation.cmd, { flag: "wx" });
  console.log(JSON.stringify({ status: prepared.status, hostId: enclaveId, ownership: authority.ownershipContract, policyHash: prepared.policyHash,
                               transactions: prepared.transactions.map((t) => `${t.transaction.from} ${t.purpose}`), out }, null, 1));
  process.exit(0);
}

const key = (process.env.OWNER_KEY || "").trim();
if (key && !/^0x[0-9a-fA-F]{64}$/.test(key)) { console.error("OWNER_KEY must be the owner wallet's private key (0x + 64 hex)"); process.exit(2); }
if (!key && cmd !== "status") { console.error("set OWNER_KEY to the owner wallet's private key (0x + 64 hex)"); process.exit(2); }
const owner = key ? privateKeyToAccount(key) : null;
const wal = owner ? createWalletClient({ account: owner, chain: base, transport: fallback(RPCS.map((u) => http(u))) }) : null;
const A = await chain.resolveAddresses();

const SET_PAYOUT_ABI = [{ type: "function", name: "setPayoutWallet", stateMutability: "nonpayable", inputs: [{ name: "id", type: "bytes32" }], outputs: [] }];
const CREATE_ABI = [
  { type: "function", name: "create", stateMutability: "nonpayable", inputs: [
    { name: "appRef", type: "string" }, { name: "gpuMilli", type: "uint16" }, { name: "cpuMilli", type: "uint16" },
    { name: "appPort", type: "uint32" }, { name: "ports", type: "string" }, { name: "isPublic", type: "bool" },
    { name: "configCid", type: "string" }, { name: "feeRecipient", type: "address" }, { name: "feePerSec6", type: "uint256" },
    { name: "maxRate6", type: "uint256" }], outputs: [{ type: "bytes32" }] },
  { type: "event", name: "Created", inputs: [{ name: "id", type: "bytes32", indexed: true }, { name: "owner", type: "address", indexed: true }, { name: "appRef", type: "string", indexed: false }] },
];
const send = async (label, req) => {
  await pub.simulateContract({ ...req, account: owner });
  const hash = await wal.writeContract(req);
  const r = await pub.waitForTransactionReceipt({ hash });
  if (r.status !== "success") throw new Error(`${label} reverted (${hash})`);
  console.log(`${label}: ${hash}`);
  return r;
};

const e = await chain.readEnclave(enclaveId).catch(() => null);
if (cmd === "status") {
  console.log(JSON.stringify({ owner: owner?.address || null, ownerEth: owner ? formatEther(await pub.getBalance({ address: owner.address })) : null,
    endpoint: ENDPOINT, enclaveId, registered: !!(e && e.endpoint),
    entry: e && e.endpoint ? { operator: e.operator, active: e.active, cpuPricePerSec6: String(e.cpuPricePerSec6), proofKey: e.proofKey, payoutWallet: e.payoutWallet, measurement: e.measurement } : null,
    addresses: A }, null, 1));
} else if (cmd === "fund-operator") {
  const to = getAddress(rest[0]); const eth = rest[1] || "0.0004";
  const before = await pub.getBalance({ address: to });
  const hash = await wal.sendTransaction({ to, value: parseEther(String(eth)) });
  await pub.waitForTransactionReceipt({ hash });
  console.log(`funded ${to} with ${eth} ETH (was ${formatEther(before)}, now ${formatEther(await pub.getBalance({ address: to }))}) tx=${hash}`);
} else if (cmd === "declare-payout") {
  if (!e || !e.endpoint) throw new Error(`${ENDPOINT} is not registered yet: the box registers itself once its operator key has gas`);
  await send("setPayoutWallet", { address: A.registry, abi: SET_PAYOUT_ABI, functionName: "setPayoutWallet", args: [enclaveId] });
  const after = await chain.readEnclave(enclaveId);
  console.log(`payout wallet on chain: ${after.payoutWallet} (deployments owned by it run on this box for nothing)`);
} else if (cmd === "deploy") {
  const ref = rest[0]; const cpuPct = Number(rest[1] || 1); const maxUsdHr = Number(rest[2] || 0.36);
  const v = await chain.resolveAppRef(ref);
  if (v.yanked) throw new Error("that catalog version is yanked");
  if (Number(v.vramMb) > 0) throw new Error("that version wants a card; this node sells no GPU share");
  const httpEntry = String(v.ports || "").split(",").map((s) => s.trim()).find((s) => /^http:/i.test(s));
  const appPort = httpEntry ? Number(httpEntry.split(":")[1]) : 8080;
  const cpuMilli = Math.max(1, Math.round(cpuPct * 10));
  const maxRate6 = BigInt(Math.round(maxUsdHr * 1e6 / 3600));
  console.log(`creating: ${ref} v${v.version} cpu ${cpuPct}% appPort ${appPort} ports "${v.ports}" public, cap $${maxUsdHr}/h`);
  const r = await send("create", { address: A.deployments, abi: CREATE_ABI, functionName: "create",
    args: [ref, 0, cpuMilli, appPort, String(v.ports || ""), true, "", "0x0000000000000000000000000000000000000000", 0n, maxRate6] });
  for (const l of r.logs) {
    try { const d = decodeEventLog({ abi: CREATE_ABI, data: l.data, topics: l.topics });
      if (d.eventName === "Created") console.log(`deployment ${d.args.id} owned by ${d.args.owner}`); } catch {}
  }
} else {
  console.error("commands: status | fund-operator <0xaddr> [eth] | declare-payout | deploy <catalog://appId/index> [cpuPercent] [maxRateUsdPerHour]"
    + " | prepare-ownership --policy <f> --owner <0x> --out <dir> | ownership-status");
  process.exit(2);
}
