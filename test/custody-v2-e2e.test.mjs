// Custody v2 end to end on a REAL chain (anvil) with the REAL EnclaveSecretVaultV2: the Enclave seat creates the committee
// (genesis), an owner encrypts to the committee key, an attested guest unlocks at t = 1, candidates join (a second
// Enclave machine, two capacity-proven hosts), a handover runs through the contract (proposal, deals, acks, activation),
// and the guest unlocks at t = 2 with EXACTLY ONE Enclave machine's partial; the two Enclave machines alone cannot.
// Every custodian signature (genesis, approvals, deals, acks) is checked by the contract, so this also pins
// custody/v2/digests.mjs to the Solidity. Attestation of app guests is SIMULATED (synthetic AMD chain, real verifier);
// custodian self-evidence is stubbed (the hardware path is exercised on warden-host).
//   run: node --test test/custody-v2-e2e.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { createHash, randomBytes } from "node:crypto";
import { createWalletClient, http, keccak256, toBytes, parseEther, stringToHex } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { anvilAvailable, startAnvil, snpAttester, RUNTIME, MEASUREMENT, FLOOR } from "./helpers/custody-rig.mjs";
import { synthChain } from "./helpers/snp-synth.mjs";
import { memoryCollateral } from "../verifier/index.mjs";
import { snpVerifier, SNP_GUEST_FORMAT } from "../custody/verifiers.mjs";
import * as hpke from "../custody/hpke.mjs";
import * as v2 from "../custody/v2/protocol.mjs";
import * as D from "../custody/v2/digests.mjs";
import { createChainReaderV2, VAULT_V2_ABI } from "../custody/v2/chain.mjs";
import { createCustodianV2 } from "../custody/v2/custodian.mjs";
import { createMember, BATCH_MS, SILENT_MS } from "../custody/v2/member.mjs";
import { buildBundleV2, makeUpdateV2, UPDATE_V2_ABI } from "../custody/v2/owner.mjs";
import { runtimeId } from "../isolation/contract/runtime.mjs";
import { createCustodyReader } from "../relay/custody-state.mjs";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const require = createRequire(import.meta.url);
const MOCKS = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract RigBook { mapping(bytes32 => address) public addr; function set(bytes32 k, address v) external { addr[k] = v; } }
contract RigLedger {
  struct Deployment { bytes32 id; address owner; string appRef; string ports; string configCid; uint16 gpuMilli; uint16 cpuMilli; uint32 appPort;
    bool isPublic; bool active; uint64 createdAt; uint256 rate; uint256 balance6; uint256 spent6; bytes32 runner; address runnerOperator; uint64 leaseUntil; }
  mapping(bytes32 => Deployment) private d;
  function set(bytes32 id, address owner, bytes32 runner, address runnerOperator, uint64 leaseUntil) external {
    Deployment storage x = d[id]; x.id = id; x.owner = owner; x.runner = runner; x.runnerOperator = runnerOperator; x.leaseUntil = leaseUntil; x.active = true; }
  function get(bytes32 id) external view returns (Deployment memory) { return d[id]; }
}
contract RigRegistry {
  struct Enclave { string endpoint; string repo; bytes32 measurement; address operator; uint64 registeredAt; uint64 lastSeen; bool active;
    uint64 cpuPricePerSec6; uint64 gpuPricePerSec6; address proofKey; address payoutWallet; }
  mapping(bytes32 => Enclave) private e;
  function set(string calldata endpoint, address operator, bool active, address payoutWallet) external {
    Enclave storage x = e[keccak256(bytes(endpoint))]; x.endpoint = endpoint; x.operator = operator; x.active = active; x.payoutWallet = payoutWallet; }
  function get(bytes32 id) external view returns (Enclave memory) { return e[id]; }
}
`;
function compile() {
  const src = fs.readFileSync(path.join(ROOT, "contracts/EnclaveSecretVaultV2.sol"), "utf8");
  const ownershipSrc = fs.readFileSync(path.join(ROOT, "contracts/EnclaveHostOwnership.sol"), "utf8");
  const key = createHash("sha256").update(src).update(ownershipSrc).update(MOCKS).digest("hex").slice(0, 16);
  const cache = path.join(process.env.TMPDIR || "/tmp", `enclave-custody-v2-rig-${key}.json`);
  if (fs.existsSync(cache)) return JSON.parse(fs.readFileSync(cache, "utf8"));
  const solc = require("solc");
  const out = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources: { "V.sol": { content: src }, "Rig.sol": { content: MOCKS }, "Ownership.sol": {content: ownershipSrc} },
    settings: { viaIR: true, optimizer: { enabled: true, runs: 200 }, outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } } })));
  const errs = (out.errors || []).filter((e) => e.severity === "error");
  if (errs.length) throw new Error(errs.map((e) => e.formattedMessage).join("\n"));
  const pick = (f, n) => ({ abi: out.contracts[f][n].abi, bytecode: "0x" + out.contracts[f][n].evm.bytecode.object });
  const r = { ownership: pick("Ownership.sol", "EnclaveHostOwnership"), vault: pick("V.sol", "EnclaveSecretVaultV2"), book: pick("Rig.sol", "RigBook"), ledger: pick("Rig.sol", "RigLedger"), registry: pick("Rig.sol", "RigRegistry") };
  fs.writeFileSync(cache, JSON.stringify(r));
  return r;
}

const sha = (b) => "0x" + createHash("sha256").update(b).digest("hex");
const APP = Buffer.alloc(32, 0xa7);
const RULES = { v: 1, appId: APP.toString("hex"), images: [{ platform: "sev-snp", measurement: MEASUREMENT, runtimeId: runtimeId(RUNTIME).toString("hex") }], minTcb: FLOOR, vmpl: 0 };
const CUSTODIAN_MEAS = Buffer.alloc(48, 0x5c);

test("custody v2 end to end: genesis, release at t=1, join + handover through the contract, release at t=2 with exactly one Enclave partial", { skip: anvilAvailable() ? false : "anvil not installed", timeout: 300_000 }, async () => {
  const C = compile();
  const anvil = await startAnvil({ chainId: 31337 });
  try {
    const pub = anvil.client;
    const fund = (a) => pub.request({ method: "anvil_setBalance", params: [a, "0x" + parseEther("100").toString(16)] });
    const acct = async () => { const a = privateKeyToAccount(generatePrivateKey()); await fund(a.address); return a; };
    const wallet = (a) => createWalletClient({ account: a, chain: anvil.chain, transport: http(anvil.url) });
    const send = async (a, address, abi, functionName, args) => {
      const hash = await wallet(a).writeContract({ address, abi, functionName, args });
      const r = await pub.waitForTransactionReceipt({ hash });
      if (r.status !== "success") throw new Error(`${functionName} reverted`);
      return hash;
    };
    const deploy = async (a, c, args = []) => (await pub.waitForTransactionReceipt({ hash: await wallet(a).deployContract({ abi: c.abi, bytecode: c.bytecode, args }) })).contractAddress;
    const deployer = await acct(), enclaveWallet = await acct(), enclaveOwner = enclaveWallet.address;
    const book = await deploy(deployer, C.book), ledger = await deploy(deployer, C.ledger), registry = await deploy(deployer, C.registry);
    await send(deployer, book, C.book.abi, "set", [stringToHex("deployments", { size: 32 }), ledger]);
    await send(deployer, book, C.book.abi, "set", [stringToHex("registry", { size: 32 }), registry]);
    const ownership = await deploy(deployer, C.ownership, [registry]);
    const vault = (await deploy(deployer, C.vault, [book, enclaveOwner, ownership])).toLowerCase();
    const chainId = 31337;
    const nowBlock = async () => Number((await pub.getBlock()).timestamp);
    // simulated clock for the engine's batching/liveness windows
    let skew = 0; const now = () => Date.now() + skew;

    // ---- hosts: two accepted by Enclave wallet, two others, one app host ----
    const hosts = {};
    for (const [name, enclave] of [["ea", true], ["eb", true], ["nb", false], ["nc", false], ["app", false]]) {
      const op = await acct(); const endpoint = `https://${name}.host.test`;
      await send(deployer, registry, C.registry.abi, "set", [endpoint, op.address, true, enclave ? enclaveOwner : "0x" + "00".repeat(20)]);
      const registryId = keccak256(toBytes(endpoint)), owner = enclave ? enclaveWallet : op;
      await send(op, ownership, C.ownership.abi, "proposeOwner", [registryId, owner.address]);
      await send(owner, ownership, C.ownership.abi, "acceptOwner", [registryId]);
      hosts[name] = { op, endpoint, registryId };
    }

    // ---- custodian machines (in-process), routed by endpoint ----
    const submitter = await acct();
    const submit = (fn, args) => send(submitter, vault, VAULT_V2_ABI, fn, args);
    const S = synthChain();
    const collateral = memoryCollateral({ chains: { Genoa: S.chainPem }, vceks: { Genoa: S.vcekDer }, crls: { Genoa: S.crlDer } });
    const verifiers = Object.freeze({ [SNP_GUEST_FORMAT]: snpVerifier({ collateral, roots: new Map([["Genoa", S.arkFp]]) }) });
    const machines = {};
    const route = async (url, body) => {
      const m = Object.values(machines).find((x) => url.startsWith(x.endpoint + "/"));
      if (!m) throw new Error(`no machine at ${url}`);
      const p = url.slice(m.endpoint.length);
      if (p === "/v2/custody/info") return m.member.info();
      if (p === "/v2/custody/evidence") return m.member.evidence(body.nonce);
      if (p === "/v2/custody/approve") return m.member.approve(body);
      if (p === "/v2/custody/join") return m.member.join(body, m.committeeId);
      throw new Error(`no route ${p}`);
    };
    const capacityOk = new Set();
    const makeMachine = async (name, host) => {
      const identity = privateKeyToAccount(generatePrivateKey());
      const kp = hpke.generateKeyPair();
      const chip = randomBytes(64);
      const machine = { identity: identity.address.toLowerCase(), encKey: "0x" + Buffer.from(kp.publicKey).toString("hex"), endpoint: `https://custody-${name}.test`,
                        chipId: sha(chip), registryId: host.registryId, measurement: sha(CUSTODIAN_MEAS) };
      let state = null;
      const chain = createChainReaderV2({ rpcs: [anvil.url], vault, minAgree: 1 });
      const member = createMember({ chainId, vault, identity, encPrivateKey: kp.privateKey, machine, chain, store: { load: () => state, save: (s) => { state = JSON.parse(JSON.stringify(s)); } },
        submit, fetchJson: route, now, log: () => {}, enclaveOwner,
        // custodian self-evidence (stub): the binding is carried through and checked; measurement and chip from the record
        attestSelf: async (binding) => ({ report: Buffer.concat([Buffer.from(binding), CUSTODIAN_MEAS, chip]), auxblob: null }),
        verifyPeerQuote: async (report, { binding }) => (Buffer.compare(report.subarray(0, 32), Buffer.from(binding)) === 0
          ? { ok: true, measurement: report.subarray(32, 80).toString("hex"), chipId: report.subarray(80, 144).toString("hex") } : { ok: false, reason: "binding" }),
        capacityCheck: async ({ machine: m }) => (capacityOk.has(m.identity) ? { ok: true } : { ok: false, reason: "no receipts" }) });
      const custodian = createCustodianV2({ chainId, vault, encPrivateKey: kp.privateKey, shares: member.shares, chain, verifiers, log: () => {} });
      const sig = await D.signDigest(host.op, D.hostDigest({ chainId, vault, machine }));
      await member.setHostSig(sig);
      machines[name] = { name, endpoint: machine.endpoint, machine, member, custodian, committeeId: null };
      return machines[name];
    };

    // ---- 1. genesis by an Enclave machine; a non-Enclave machine cannot ----
    const E1 = await makeMachine("e1", hosts.ea);
    const N0 = await makeMachine("n0", hosts.nb);
    await assert.rejects(N0.member.genesis({ salt: "0x" + "01".repeat(32), codeSet: [N0.machine.measurement] }), "genesis by a non-Enclave host is refused by the contract");
    delete machines.n0;
    const g = await E1.member.genesis({ salt: "0x" + "02".repeat(32), codeSet: [E1.machine.measurement] });
    const cid = g.committeeId; E1.committeeId = cid;
    const reader = createChainReaderV2({ rpcs: [anvil.url], vault, minAgree: 1 });
    let { committee } = await reader.readCommittee({ committeeId: cid });
    assert.deepEqual([committee.epoch, committee.t, committee.W, committee.machines[0].enclave], [1, 1, 1, true]);

    // ---- 2. an owner publishes, and an app guest unlocks at t = 1 ----
    const owner = await acct();
    const id = "0x" + randomBytes(32).toString("hex");
    await send(deployer, ledger, C.ledger.abi, "set", [id, owner.address, hosts.app.registryId, hosts.app.op.address, BigInt((await nowBlock()) + 7200)]);
    const env = { API_KEY: "v2-secret", DB: "postgres://x" };
    const publish = async (secretRev, expectPolicyRev) => {
      const bundle = buildBundleV2({ chainId, vault, id, secretRev, committeeId: cid, Y: committee.Y, env, configText: "" });
      await send(owner, vault, UPDATE_V2_ABI, "update", [id, makeUpdateV2({ expectPolicyRev, policy: { committeeId: cid, paused: false, rules: RULES }, bundle })]);
    };
    await publish(1, 0);

    const unlock = async (useMachines, { expectEnclaveRule = true } = {}) => {
      const st = await reader.readRelease({ id, endpoint: hosts.app.endpoint });
      const com = st.committee;
      const at = snpAttester(S, { appId: APP, hostData: Buffer.from(id.slice(2), "hex") });
      const recipient = hpke.generateKeyPair();
      const challenges = [];
      for (const m of useMachines) { const c = m.custodian.challenge(); challenges.push({ m, encKey: c.encKey, nonce: c.nonce }); }
      const chs = challenges.map((c) => ({ encKey: Buffer.from(c.encKey, "hex"), nonce: Buffer.from(c.nonce, "hex") }));
      const binding = v2.releaseBinding({ chainId, vault, id, policyRev: st.policy.policyRev, secretRev: st.policy.secretRev, committeeId: cid, epoch: com.epoch,
        challenges: chs, runtimeId: new Uint8Array(runtimeId(RUNTIME)), transportSpki: at.transportSpki, recipientKey: recipient.publicKey });
      const expiry = Math.floor(Date.now() / 1000) + 300;
      const sig = await hosts.app.op.signMessage({ message: v2.operatorMessage({ chainId, vault, id, endpoint: hosts.app.endpoint, binding, expiry }) });
      const evidence = await at.evidence(binding);
      const commitments = []; for (let i = 0; i < com.commitments.length; i += 33) commitments.push(com.commitments.subarray(i, i + 33));
      const R = v2.parseBundle(st.bundle.data).R;
      const got = [];
      for (const c of challenges) {
        const r = await c.m.custodian.release({ v: 2, id, endpoint: hosts.app.endpoint, committeeId: cid, epoch: com.epoch, policyRev: String(st.policy.policyRev), secretRev: String(st.policy.secretRev),
          recipientKey: Buffer.from(recipient.publicKey).toString("hex"), challenges: challenges.map((x) => ({ encKey: x.encKey, nonce: x.nonce })), operator: { sig, expiry }, evidence });
        const recs = v2.openPartials({ recipientPrivate: recipient.privateKey, binding, encKey: Buffer.from(r.encKey, "hex"), count: r.count, sealed: Buffer.from(r.sealed, "base64") });
        const mm = com.machines.find((x) => x.encKey === "0x" + r.encKey);
        got.push({ enclave: mm.enclave, parts: recs.map((record) => v2.verifyPartial({ record, R, binding, commitments })) });
      }
      // the guest's choice: exactly ONE Enclave machine's partials (if any answered), then other seats
      const encl = got.filter((x) => x.enclave), others = got.filter((x) => !x.enclave);
      const chosen = expectEnclaveRule && encl.length ? [...encl[0].parts] : [];
      for (const o of (expectEnclaveRule ? others : got)) for (const p of o.parts) if (chosen.length < com.t && !chosen.some((c) => c.k === p.k)) chosen.push(p);
      const S2 = v2.combine(chosen.slice(0, com.t), com.t);
      return v2.decryptBundle({ S: S2, label: v2.labelOf({ chainId, vault, id, secretRev: st.policy.secretRev, committeeId: cid }), bundle: st.bundle.data }).env;
    };
    assert.deepEqual(await unlock([E1]), env, "t = 1: the Enclave seat alone unlocks");

    // A payout declaration naming Enclave must not waive an independent host's
    // proof of capacity or merge it into Enclave's seat.
    await send(deployer, registry, C.registry.abi, "set", [hosts.nb.endpoint, hosts.nb.op.address, true, enclaveOwner]);
    const nbRegistry = await reader.readRegistryEntry({registryId:hosts.nb.registryId});
    assert.equal(nbRegistry.entry.owner, hosts.nb.op.address.toLowerCase());
    assert.equal(nbRegistry.entry.payoutWallet,enclaveOwner.toLowerCase());

    // ---- 3. candidates join; E1 coordinates a handover through the contract ----
    const E2 = await makeMachine("e2", hosts.eb), NB = await makeMachine("nb", hosts.nb), NC = await makeMachine("nc", hosts.nc);
    for (const m of [E2, NB, NC]) m.committeeId = cid;
    await assert.rejects(E1.member.join({ machine: NB.machine }, cid), /proof of capacity/, "a non-Enclave candidate without capacity proof is refused");
    capacityOk.add(NB.machine.identity); capacityOk.add(NC.machine.identity);
    for (const m of [E2, NB, NC]) assert.ok((await E1.member.join({ machine: m.machine }, cid)).ok);
    let r = await E1.member.tick(cid);
    assert.equal(r.state, "batching", "changes wait for the batching window");
    skew += BATCH_MS + 1000;
    r = await E1.member.tick(cid);
    assert.equal(r.state, "proposed", JSON.stringify(r));
    // deals, then every new machine verifies, persists and acks; the last ack activates the epoch
    for (let i = 0; i < 4; i++) for (const m of [E1, E2, NB, NC]) await m.member.tick(cid).catch((e) => { throw new Error(`${m.name}: ${e.message}`); });
    ({ committee } = await reader.readCommittee({ committeeId: cid }));
    assert.equal(committee.machines.length, 4);
    assert.deepEqual([committee.t, committee.W], [2, 3], "3 seats (one Enclave seat for two Enclave machines): t = 2");
    assert.ok(committee.epoch > 1);
    assert.equal(Buffer.from(committee.Y).toString("hex"), Buffer.from(g.Y.slice(2), "hex").toString("hex"), "the committee key never changed");
    for (const m of [E1, E2, NB, NC]) await m.member.tick(cid);
    assert.deepEqual(E1.member.shares.get(cid, 1), [], "old-epoch shares are erased after activation");
    assert.deepEqual(E1.member.shares.get(cid, committee.epoch).map((s) => s.k), E2.member.shares.get(cid, committee.epoch).map((s) => s.k), "Enclave replicas hold the same index");
    assert.equal(E1.member.shares.get(cid, committee.epoch)[0].x, E2.member.shares.get(cid, committee.epoch)[0].x, "...and the same share");

    // ---- 4. t = 2: exactly one Enclave machine + one other host unlock; the old bundle is still readable ----
    assert.deepEqual(await unlock([E1, NB]), env);
    assert.deepEqual(await unlock([E2, NC]), env);
    assert.deepEqual(await unlock([E1, E2, NB, NC]), env, "all answer: one Enclave partial used");
    await assert.rejects(unlock([E1, E2], { expectEnclaveRule: false }), /exactly 2 distinct/, "two Enclave machines are ONE seat: they cannot reach t");
    assert.deepEqual(await unlock([NB, NC]), env, "no Enclave machine online: the other seats suffice");
    // ---- 5. the relay's v2 pointer for the guest's signed release (relay/custody-state.mjs) ----
    const relayReader = createCustodyReader({ vault2: vault, chainId, rpcs: [anvil.url], minAgree: 1, maxAgeSec: null });
    const ptr = await relayReader.custodyStateFor(id);
    assert.equal(ptr.v, 2); assert.equal(ptr.vault, vault); assert.equal(ptr.committeeId, cid); assert.equal(ptr.t, 2); assert.equal(ptr.epoch, committee.epoch);
    assert.equal(typeof ptr.policyRev, "string"); assert.equal(ptr.commitments.length, 2 * 33 * 2);
    assert.deepEqual(ptr.machines.map((m) => [m.enclave, m.indices]), committee.machines.map((m) => [m.enclave, m.enclave ? [1] : null]).map(([e, k], i) => [e, k || ptr.machines[i].indices]));
    assert.deepEqual(new Set(ptr.machines.filter((m) => !m.enclave).flatMap((m) => m.indices)), new Set([2, 3]));
    assert.equal(await relayReader.custodyHeld(id), true);
    assert.equal(await relayReader.custodyHeld("0x" + "ab".repeat(32)), false);
    void SILENT_MS;
  } finally { anvil.stop(); }
});
