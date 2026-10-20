// Windows host identity without a required Enclave relay (windows/node/host-identity.mjs, agent.mjs, keys.mjs) and the
// preparation of its enrollment on the verified EnclaveHostOwnership (windows/node/host-ownership.mjs).
//   * relay mode (every installed host) resolves exactly the values it always did;
//   * independent mode takes the operator's endpoint, gateways and pins, defaults nothing to an Enclave service, and says
//     which relay-only features are off instead of reaching for api.enclave.host;
//   * the relay-free name check reads the PINNED registry through agreeing RPCs;
//   * ownership on 0xF5E9… is prepared against the verified record (address, code hash, registry binding), never signed.
//   run: node --test test/windows-host-identity.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import { spawn, execFile } from "node:child_process";
import { once } from "node:events";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { keccak256, toBytes } from "viem";
import { resolveIdentity, quorumReader, checkEndpointOnChain, relayHttpBase } from "../windows/node/host-identity.mjs";
import { verifiedOwnershipAuthority, ownershipActivation, prepareOwnershipEnrollment, ownershipStatus } from "../windows/node/host-ownership.mjs";
import { hostAdmissionPolicyHash } from "../network/host-admission-policy.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const AGENT = path.join(ROOT, "windows", "node", "agent.mjs");
const AUTH = JSON.parse(fs.readFileSync(path.join(ROOT, "contracts", "deployments", "independent-authorities-base.json"), "utf8"));
const lc = (s) => s.toLowerCase();
// Test pins: the registry and catalog the verified ownership record is bound to, and stand-ins for the rest.
const PINS = { registry: lc(AUTH.inputs.registry), deployments: lc(AUTH.inputs.ledger), appCatalog: lc(AUTH.inputs.catalog), proofOfTime: "0x" + "11".repeat(20) };
const PIN_DOC = { version: 1, chainId: 8453, contracts: { ...PINS, enclavePay: "0x" + "00".repeat(20), verificationFees: "0x" + "00".repeat(20),
                                                           sessionVaultFactory: "0x" + "00".repeat(20), secretVaultV2: "0x" + "00".repeat(20) } };
const INDEPENDENT = { ENCLAVE_IDENTITY_MODE: "independent", NODE_NAME: "box-1", PUBLIC_URL: "https://box-1.operator.example",
                      IPFS_GATEWAYS: "https://gw-a.example,https://gw-b.example/" };
const OPERATOR = "0x" + "ab".repeat(20), OTHER = "0x" + "cd".repeat(20), ZERO = "0x" + "00".repeat(20);

test("relay mode (every installed host) resolves exactly what it always did", () => {
  const id = resolveIdentity({}, { hostname: "NucBox K11" });
  assert.equal(id.mode, "relay"); assert.equal(id.name, "nucbox-k11");
  assert.equal(id.publicUrl, "https://api.enclave.host/t/nucbox-k11");
  assert.equal(id.relayUrl, "wss://api.enclave.host/v1/fleet-tunnel"); assert.equal(id.relayHttp, "https://api.enclave.host");
  assert.equal(id.relayBase, "https://api.enclave.host"); assert.equal(id.gateway, "https://ipfs.enclave.host");
  assert.equal(id.sponsor, true); assert.equal(id.prices, true); assert.deepEqual(id.unavailable, []);
  const custom = resolveIdentity({ NODE_NAME: "x", RELAY_URL: "none", RELAY_BASE: "https://r.example", IPFS_GATEWAY: "https://g.example" });
  assert.equal(custom.publicUrl, "https://api.enclave.host/t/x", "RELAY_URL=none in relay mode keeps the legacy identity (local only), as before");
  assert.equal(custom.relayBase, "https://r.example"); assert.equal(custom.gateway, "https://g.example"); assert.equal(custom.sponsor, false);
  assert.equal(relayHttpBase("wss://relay.example/v1/fleet-tunnel"), "https://relay.example"); assert.equal(relayHttpBase("none"), "");
});

test("independent mode requires the operator's endpoint, pins and gateways, and defaults nothing to Enclave", () => {
  assert.throws(() => resolveIdentity({ ...INDEPENDENT, PUBLIC_URL: "" }, { pins: PINS }), /needs PUBLIC_URL/);
  assert.throws(() => resolveIdentity(INDEPENDENT, { pins: null }), /ENCLAVE_CONTRACT_PINS_FILE/);
  assert.throws(() => resolveIdentity({ ...INDEPENDENT, IPFS_GATEWAYS: "" }, { pins: PINS }), /needs IPFS_GATEWAYS/);
  assert.throws(() => resolveIdentity({ ...INDEPENDENT, PUBLIC_URL: "https://box-1.operator.example/" }, { pins: PINS }), /exactly as registered/);
  assert.throws(() => resolveIdentity({ ...INDEPENDENT, PUBLIC_URL: "http://box-1.operator.example" }, { pins: PINS }), /must be https/);
  assert.throws(() => resolveIdentity({ ...INDEPENDENT, ENCLAVE_IDENTITY_MODE: "sovereign" }, { pins: PINS }), /relay or independent/);
  const id = resolveIdentity(INDEPENDENT, { pins: PINS });
  assert.equal(id.publicUrl, "https://box-1.operator.example"); assert.equal(id.relayUrl, "none");
  assert.equal(id.relayBase, ""); assert.equal(id.relayHttp, "");
  assert.equal(id.gateway, "https://gw-a.example,https://gw-b.example");
  assert.equal(id.sponsor, false); assert.equal(id.prices, false); assert.deepEqual(id.sessionApiHosts, []);
  assert.doesNotMatch(JSON.stringify({ ...id, unavailable: [], warnings: [] }), /enclave\.host/, "no Enclave origin in any resolved value");
  for (const off of [/relay-staged secrets/, /certificates/, /Shield market .*owner-only/, /sponsored first registration/, /network routes/])
    assert.ok(id.unavailable.some((u) => off.test(u)), `says ${off} is off`);
  const routed = resolveIdentity({ ...INDEPENDENT, PUBLIC_URL: "https://api.enclave.host/t/box-1" }, { pins: PINS });
  assert.match(routed.warnings[0], /route on Enclave's relay/, "keeping a relay-route identity is allowed, and named for what it is");
  const opted = resolveIdentity({ ...INDEPENDENT, RELAY_URL: "wss://relay.operator.example/v1/fleet-tunnel", RELAY_BASE: "https://relay.operator.example",
                                  ENCLAVE_NETWORK_DIRECTORIES: "https://dir-a.example,https://dir-b.example/" }, { pins: PINS });
  assert.equal(opted.sponsor, true); assert.equal(opted.prices, true); assert.equal(opted.relayBase, "https://relay.operator.example");
  assert.deepEqual(opted.networkDirectories, ["https://dir-a.example", "https://dir-b.example"]);
  assert.throws(() => resolveIdentity({ ...INDEPENDENT, ENCLAVE_NETWORK_DIRECTORIES: "https://dir.example/v1" }, { pins: PINS }), /must be an origin/);
});

/**
 * A fake RPC client: chain id, head, blocks (2 s apart, the head's stamped now - lag), and readContract answering from
 * `answer(functionName, args)`. `reads` records the block every read asked for.
 */
const CHAIN_T0 = Math.floor(Date.now() / 1000);
let rpcSeq = 0;   // the fake chain's blocks are all "just made" (lagS ages one RPC's view)
const client = (answer, { head = 100n, chainId = 8453, lagS = 0, dead = false, fork = "", reorg = false } = {}) => {
  const reads = [];
  let flips = 0;
  const hash = (n) => "0x" + (fork + n.toString(16)).padStart(64, "0");
  return { reads, transport: { url: `https://rpc-${++rpcSeq}.test/` },   // each fake is its own RPC host
    getChainId: async () => { if (dead) throw new Error("connection refused"); return chainId; },
    getBlockNumber: async () => head,
    getBlock: async ({ blockNumber }) => {
      if (blockNumber > head) throw new Error("block not found");
      const h = reorg && flips++ ? hash(blockNumber + 1000n) : hash(blockNumber);
      return { number: blockNumber, hash: h, timestamp: BigInt(CHAIN_T0 - lagS) };   // a block's time is the chain's, not the asker's
    },
    getCode: async () => answer("getCode"),
    readContract: async ({ functionName, args, blockNumber }) => { reads.push(blockNumber); return answer(functionName, args); } };
};
const pair = (answer) => [client(answer), client(answer)];

test("the agreeing-RPC reader: two fresh RPCs agreeing at one confirmed block decide; one RPC never does", async () => {
  const { LeaseReader } = await import("../network/lease-reader.mjs");
  const read = (c, b) => c.readContract({ functionName: "x", blockNumber: b }).then((v) => ({ v }));
  const val = (v, o) => client(() => v, o);
  // [name, clients, expected value or null for refusal]. Each runs through this reader AND network/lease-reader.mjs
  // LeaseReader.agreed on fresh clients: the two must give the same verdict.
  const cases = [
    ["three agree", () => [val("a"), val("a"), val("a")], "a"],
    ["one liar against two fresh", () => [val("lie"), val("a"), val("a")], "a"],
    ["one dead against two fresh", () => [val("a", { dead: true }), val("a"), val("a")], "a"],
    ["one wrong chain against two fresh", () => [val("a", { chainId: 1 }), val("a"), val("a")], "a"],
    ["one stale (behind, old blocks) against two fresh", () => [val("old", { head: 40n, lagS: 3600 }), val("a"), val("a")], "a"],
    ["one claiming a far-future head against two fresh", () => [val("lie", { head: 10n ** 9n }), val("a"), val("a")], "a"],
    ["one on another fork (same value, other block hash) against two fresh", () => [val("a", { fork: "f" }), val("a"), val("a")], "a"],
    ["one reorganized during its read against two fresh", () => [val("lie", { reorg: true }), val("a"), val("a")], "a"],
    ["split, two RPCs", () => [val("a"), val("b")], null],
    ["split three ways", () => [val("a"), val("b"), val("c")], null],
    ["only one answers", () => [val("a"), val("a", { dead: true })], null],
    ["one fresh, one wrong chain", () => [val("a"), val("a", { chainId: 1 })], null],
    ["two agreeing but stale", () => [val("a", { lagS: 3600 }), val("a", { lagS: 3600 })], null],
    ["two agreeing on different forks", () => [val("a"), val("a", { fork: "f" })], null],
  ];
  for (const [name, make, want] of cases) {
    const ours = await quorumReader({ clients: make() }).agreed(read).then((r) => r.v, () => null);
    const lease = await new LeaseReader({ clients: make(), addressBook: "0x" + "11".repeat(20) }).agreed(read).then((r) => r.v, () => null);
    assert.equal(ours, want, `quorumReader: ${name}`);
    assert.equal(lease, want, `LeaseReader (the reference): ${name}`);
  }
  // the block is the second-highest head minus two confirmations: the liar's far-future head did not choose it
  const honest = [val("a", { head: 500n }), val("a", { head: 501n })];
  await quorumReader({ clients: [val("a", { head: 10n ** 9n }), ...honest] }).agreed(read);
  // heads arrive 10^9, 500, 501: reads start at 500 - 2 and move to 501 - 2 when the third head raises the second-highest;
  // the liar's far-future head never chooses the block
  assert.ok(honest.flatMap((c) => c.reads).every((b) => b === 498n || b === 499n), JSON.stringify(honest.map((c) => c.reads.map(String))));
  assert.ok(honest[1].reads.includes(499n), "the higher block once the third head is in");
  // never below a block this reader already accepted (a lagging pair cannot roll an answer back)
  const fresh = [val("a", { head: 600n }), val("a", { head: 600n })], q = quorumReader({ clients: fresh });
  await q.agreed(read);
  fresh[0].reads.length = 0; for (const c of fresh) c.getBlockNumber = async () => 590n;
  await q.agreed(read).catch(() => {});
  assert.deepEqual(fresh[0].reads, [598n]);
  // the refusal says why
  await assert.rejects(quorumReader({ clients: [val("a"), val("b")] }).agreed(read), /no fresh agreeing chain quorum.*disagree/);
  await assert.rejects(quorumReader({ clients: [val("a"), val("a", { dead: true })] }).agreed(read), /quorum unavailable: 1 of 2.*connection refused/);
  assert.throws(() => quorumReader({ clients: [val("a")] }), /at least two RPCs/, "one configured RPC decides nothing");
});

test("the Shield market is named off only when neither a relay nor operator-selected verifiers can open it", () => {
  const off = (env) => resolveIdentity({ ...INDEPENDENT, ...env }, { pins: PINS }).unavailable.some((u) => /Shield market/.test(u));
  assert.equal(off({}), true, "no relay, no verifier set: owner-only, and said so");
  assert.match(resolveIdentity(INDEPENDENT, { pins: PINS }).unavailable.find((u) => /Shield market/.test(u)), /ENCLAVE_SHIELD_VERIFIERS_FILE: owner-only scope until then/);
  assert.equal(off({ ENCLAVE_SHIELD_VERIFIERS_FILE: "C:\\ProgramData\\Enclave\\node\\shield-verifiers.json" }), false,
               "operator-selected verifiers (shield-verdict.mjs) may open it: not reported as unavailable");
  assert.equal(off({ RELAY_URL: "wss://relay.operator.example/v1/fleet-tunnel" }), false);
});

test("the relay-free name check reads the pinned registry: free, ours, or taken by another operator", async () => {
  const endpoint = "https://box-1.operator.example", hostId = keccak256(toBytes(endpoint));
  const registryAnswer = (entry) => (fn, args) => { assert.equal(fn, "get"); assert.equal(args[0], hostId); return entry; };
  const entry = (operator, ep = endpoint) => ({ endpoint: ep, operator, active: true, repo: "", measurement: "0x" + "00".repeat(32) });
  const check = (e) => checkEndpointOnChain({ endpoint, operator: OPERATOR, registry: PINS.registry,
                                              reader: quorumReader({ clients: pair(registryAnswer(e)) }) });
  assert.equal((await check(entry(ZERO, ""))).status, "free");
  assert.equal((await check(entry(OPERATOR))).status, "ours", "a re-install of the same box");
  const taken = await check(entry(OTHER));
  assert.equal(taken.status, "taken"); assert.equal(taken.operator, OTHER); assert.equal(taken.hostId, hostId);
  await assert.rejects(checkEndpointOnChain({ endpoint, operator: OPERATOR, registry: PINS.registry,
    reader: quorumReader({ clients: [client(registryAnswer(entry(ZERO, ""))), client(registryAnswer(entry(OTHER)))] }) }), /disagree/,
    "one RPC saying free while another says taken decides nothing");
  // one outdated or lying RPC saying "free" neither vetoes nor overrules two fresh RPCs that see the other operator
  const liar = client(registryAnswer(entry(ZERO, ""))), stale = client(registryAnswer(entry(ZERO, "")), { head: 40n, lagS: 3600 });
  for (const odd of [liar, stale])
    assert.equal((await checkEndpointOnChain({ endpoint, operator: OPERATOR, registry: PINS.registry,
      reader: quorumReader({ clients: [odd, ...pair(registryAnswer(entry(OTHER)))] }) })).status, "taken");
});

test("ownership is prepared against the VERIFIED 0xF5E9… record only, and nothing is signed", async () => {
  const authority = verifiedOwnershipAuthority(AUTH, PINS);
  assert.equal(authority.ownershipContract, "0xf5e9e6c02449001f6e8e95e5d87413f2cb6790ea");
  assert.equal(authority.registry, PINS.registry); assert.equal(authority.catalog, PINS.appCatalog);
  assert.throws(() => verifiedOwnershipAuthority(AUTH, { ...PINS, registry: "0x" + "22".repeat(20) }), /bound to/);
  assert.throws(() => verifiedOwnershipAuthority(AUTH, { ...PINS, appCatalog: "0x" + "22".repeat(20) }), /catalog/);
  const endpoint = "https://box-1.operator.example", hostId = keccak256(toBytes(endpoint)), owner = "0x0b2d009c0c9af05b12100d77f3c815fea822ee61";
  const policy = { version: 1, chainId: 8453, ownershipContract: authority.ownershipContract, hostId, requireCatalogApproval: false, denyDeployments: [], denyAppRefs: [] };
  const code = "0x6080604052";
  const chainAnswer = (fn) => fn === "getCode" ? code : fn === "registry" ? PINS.registry
    : fn === "get" ? { endpoint, operator: OPERATOR, active: true } : fn === "authority" ? [ZERO, ZERO, 0n, "0x" + "00".repeat(32)] : assert.fail(fn);
  const reader = quorumReader({ clients: pair(chainAnswer) });
  // the deployed code must be the verified code
  await assert.rejects(prepareOwnershipEnrollment({ policy, owner, endpoint, authority, reader }), /not the verified/);
  const asVerified = { ...authority, codeHash: keccak256(code) };
  const p = await prepareOwnershipEnrollment({ policy, owner, endpoint, authority: asVerified, reader });
  assert.equal(p.status, "prepared-not-signed"); assert.equal(p.policyHash, hostAdmissionPolicyHash(policy));
  assert.deepEqual(p.transactions.map((t) => [t.transaction.from, t.purpose.split(" ").slice(0, 3).join(" ")]),
    [[OPERATOR, "Registered host operator"], [owner, "Nominated wallet accepts"], [owner, "Owning wallet commits"]]);
  for (const t of p.transactions) {
    assert.equal(t.transaction.to, authority.ownershipContract);
    assert.ok(!("signature" in t) && !("nonce" in t.transaction) && !("gas" in t.transaction), "unsigned, no nonce, no gas: prepared only");
  }
  // the previously documented contract, or another host's policy, is not this verified authority
  await assert.rejects(prepareOwnershipEnrollment({ policy: { ...policy, ownershipContract: "0xbbd885d3e9bc33609387bb9710e91c1905fe6ee7" }, owner, endpoint, authority: asVerified, reader }), /not the verified/);
  await assert.rejects(prepareOwnershipEnrollment({ policy: { ...policy, hostId: "0x" + "33".repeat(32) }, owner, endpoint, authority: asVerified, reader }), /is for host/);
  // the settings that switch the veto, for node-config.local.cmd, after acceptance only
  const act = ownershipActivation({ authority, hostId, pinsFile: "C:\\ProgramData\\Enclave\\node\\contract-pins.json", policyDir: "C:\\ProgramData\\Enclave\\node\\host-policy" });
  assert.deepEqual(Object.keys(act.env), ["ENCLAVE_CONTRACT_PINS_FILE", "ENCLAVE_HOST_ID", "ENCLAVE_HOST_OWNERSHIP", "ENCLAVE_HOST_REGISTRY_PIN", "ENCLAVE_HOST_CATALOG_PIN", "ENCLAVE_HOST_POLICY_DIR"]);
  assert.match(act.cmd, /ONLY after ownership-status reports ready/); assert.match(act.cmd, /set ENCLAVE_HOST_OWNERSHIP=0xf5e9e6c0/);
});

test("ownership status says ready only once the owner accepted and the committed policy is on the host", async () => {
  const authority = verifiedOwnershipAuthority(AUTH, PINS), hostId = "0x" + "44".repeat(32), dir = fs.mkdtempSync(path.join(os.tmpdir(), "own-"));
  const at = (registry, a) => quorumReader({ clients: pair((fn) => fn === "registry" ? registry : a) });
  const status = (a, registry = PINS.registry) => ownershipStatus({ authority, hostId, reader: at(registry, a), policyDir: dir });
  const zero32 = "0x" + "00".repeat(32), hash = "0x" + "55".repeat(32);
  assert.match((await status([ZERO, ZERO, 0n, zero32])).why, /not nominated/);
  assert.match((await status([ZERO, OTHER, 0n, zero32])).why, /waiting for acceptOwner/);
  const missing = await status([OTHER, ZERO, 1n, hash]);
  assert.equal(missing.ready, false); assert.match(missing.why, /not in .*place it first/);
  fs.writeFileSync(path.join(dir, `${hash}.json`), "{}");
  assert.equal((await status([OTHER, ZERO, 2n, hash])).ready, true);
  assert.equal((await status([OTHER, ZERO, 1n, zero32])).ready, true, "an accepted owner with no policy: no veto entries");
  assert.equal((await status([OTHER, ZERO, 2n, hash], "0x" + "22".repeat(20))).ready, false);
});

test("keys.mjs makes and prints the keys offline, with no hard-coded host", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "keys-"));
  const { stdout } = await promisify(execFile)(process.execPath, [path.join(ROOT, "windows", "node", "keys.mjs"), dir, "--offline"],
    { env: { ...process.env, PUBLIC_URL: "https://box-1.operator.example", NODE_NAME: "" } });
  const r = JSON.parse(stdout);
  assert.match(r.operator, /^0x[0-9a-fA-F]{40}$/); assert.equal(r.operatorCreated, true);
  assert.equal(r.endpoint, "https://box-1.operator.example"); assert.equal(r.enclaveId, keccak256(toBytes("https://box-1.operator.example")));
  assert.equal(r.registered, null); assert.match(r.chain, /--offline/);
  assert.ok(fs.existsSync(path.join(dir, "operator.key")) && fs.existsSync(path.join(dir, "proof.key")));
  const again = JSON.parse((await promisify(execFile)(process.execPath, [path.join(ROOT, "windows", "node", "keys.mjs"), dir, "--offline"],
    { env: { ...process.env, PUBLIC_URL: "", NODE_NAME: "" } })).stdout);
  assert.equal(again.operator, r.operator, "the same key, kept"); assert.equal(again.endpoint, null, "no endpoint is invented");
});

const freePort = async () => { const s = net.createServer(); s.listen(0, "127.0.0.1"); await once(s, "listening"); const p = s.address().port; s.close(); return p; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function agent(env) {
  const nodeDir = fs.mkdtempSync(path.join(os.tmpdir(), "ee-indep-"));
  const child = spawn(process.execPath, [AGENT], { env: { ...process.env, NODE_DIR: nodeDir, TPMATTEST_EXE: path.join(nodeDir, "no-tpm-tool"),
    HOSTING_ADMIN_PORT: "0", ENCLAVE_ENGINE: "", APPS: "", RELAY_URL: "", RELAY_BASE: "", PUBLIC_URL: "", IPFS_GATEWAY: "", IPFS_GATEWAYS: "", ...env },
    stdio: ["ignore", "pipe", "pipe"] });
  let out = ""; child.stdout.on("data", (d) => { out += d; }); child.stderr.on("data", (d) => { out += d; });
  return { child, nodeDir, out: () => out };
}

test("the agent refuses to start independent without its pins, and never falls back to the relay identity", { timeout: 30_000 }, async () => {
  const a = agent({ ...INDEPENDENT, ENCLAVE_CONTRACT_PINS_FILE: "" });
  try {
    const [code] = await once(a.child, "exit");
    assert.notEqual(code, 0); assert.match(a.out(), /ENCLAVE_CONTRACT_PINS_FILE/);
    assert.doesNotMatch(a.out(), /dialing/);
  } finally { fs.rmSync(a.nodeDir, { recursive: true, force: true }); }
});

test("the agent in independent mode serves locally with no tunnel, and names what is off", { timeout: 30_000 }, async () => {
  const pinsDir = fs.mkdtempSync(path.join(os.tmpdir(), "pins-")), pinsFile = path.join(pinsDir, "contract-pins.json");
  fs.writeFileSync(pinsFile, JSON.stringify(PIN_DOC));
  const httpPort = await freePort();
  const a = agent({ ...INDEPENDENT, ENCLAVE_CONTRACT_PINS_FILE: pinsFile, LOCAL_HTTP_PORT: String(httpPort) });
  try {
    let health = null;
    for (let i = 0; i < 50 && !health; i++) { await sleep(200); health = await fetch(`http://127.0.0.1:${httpPort}/v1/health`).then((r) => r.json()).catch(() => null); }
    assert.ok(health, `the agent did not come up: ${a.out()}`);
    assert.equal(health.name, "box-1");
    const out = a.out();
    assert.match(out, /identity: independent mode, https:\/\/box-1\.operator\.example, no fleet tunnel, no relay services, artifacts from https:\/\/gw-a\.example,https:\/\/gw-b\.example/);
    assert.match(out, /unavailable without an Enclave relay: the Shield market/);
    assert.match(out, /RELAY_URL=none: no fleet tunnel \(independent: owner-only scope/);
    assert.doesNotMatch(out, /dialing|api\.enclave\.host\/t\//, "no relay tunnel, no relay identity");
    assert.equal(a.child.exitCode, null, `the agent exited: ${out}`);
  } finally { a.child.kill(); fs.rmSync(a.nodeDir, { recursive: true, force: true }); fs.rmSync(pinsDir, { recursive: true, force: true }); }
});
