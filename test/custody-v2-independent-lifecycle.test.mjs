// Independent custody lifecycle on a REAL chain (anvil) with the REAL EnclaveSecretVaultV2 and EnclaveHostOwnership, the
// REAL FROST DKG helper and the custodian's actual genesis service (custody/v2/independent-runtime.mjs):
//   founders plan with explicit pins, every operator AND owner signs (one owner is an ERC-1271 contract wallet); the DKG
//   runs; one founder's host refuses to pay gas and still adopts, another is offline for activation and adopts from the
//   chain when it returns; the DKG copy of each share is erased after adoption;
//   an owner provisions and updates a secret; a 2-of-3 release works with a member down; a new user's machine is
//   admitted by owner permits (refused without them, refused below t seat owners, refused as a second seat for one
//   owner) and replaces the dead member through the vault's handover; the key never changes; owners authorize a new
//   custodian measurement whose vault proposal any wallet submits.
// No Enclave founder, capacity witness, Enclave API, relay or Enclave-owned seat takes part. Custodian self-attestation
// is stubbed and app-guest attestation is simulated, as in custody-v2-e2e.test.mjs; this is not hardware evidence.
import test, { before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
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
import { createMember } from "../custody/v2/member.mjs";
import { buildBundleV2, makeUpdateV2, UPDATE_V2_ABI } from "../custody/v2/owner.mjs";
import { dkgHelper } from "../custody/v2/independent-genesis.mjs";
import { createIndependentService } from "../custody/v2/independent-runtime.mjs";
import { coordinateIndependentGenesis } from "../custody/v2/coordinate-genesis.mjs";
import { independentPolicy, ownerPermitAdmission } from "../custody/v2/governance.mjs";
import * as W from "../custody/v2/workflow.mjs";
import { runtimeId } from "../isolation/contract/runtime.mjs";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const require = createRequire(import.meta.url);
const invoke = dkgHelper(path.join(ROOT, "custody/dkg/target/debug/enclave-custody-dkg"));
before(() => { if (anvilAvailable()) execFileSync("cargo", ["build", "--locked", "--manifest-path", path.join(ROOT, "custody/dkg/Cargo.toml")], { stdio: "pipe", timeout: 300000 }); });

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
interface IRigOwnership { function acceptOwner(bytes32 hostId) external; }
contract Rig1271 {
  address public signer;
  constructor(address s) { signer = s; }
  function accept(address o, bytes32 id) external { IRigOwnership(o).acceptOwner(id); }
  function isValidSignature(bytes32 h, bytes calldata sig) external view returns (bytes4) {
    if (sig.length != 65) return 0xffffffff;
    return ecrecover(h, uint8(sig[64]), bytes32(sig[0:32]), bytes32(sig[32:64])) == signer ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
  }
}
`;
function compile() {
  const src = fs.readFileSync(path.join(ROOT, "contracts/EnclaveSecretVaultV2.sol"), "utf8");
  const ownershipSrc = fs.readFileSync(path.join(ROOT, "contracts/EnclaveHostOwnership.sol"), "utf8");
  const key = createHash("sha256").update(src).update(ownershipSrc).update(MOCKS).digest("hex").slice(0, 16);
  const cache = path.join(process.env.TMPDIR || "/tmp", `enclave-custody-v2-independent-${key}.json`);
  if (fs.existsSync(cache)) return JSON.parse(fs.readFileSync(cache, "utf8"));
  const solc = require("solc");
  const out = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources: { "V.sol": { content: src }, "Rig.sol": { content: MOCKS }, "Ownership.sol": { content: ownershipSrc } },
    settings: { viaIR: true, optimizer: { enabled: true, runs: 200 }, outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } } })));
  const errs = (out.errors || []).filter((e) => e.severity === "error");
  if (errs.length) throw new Error(errs.map((e) => e.formattedMessage).join("\n"));
  const pick = (f, n) => ({ abi: out.contracts[f][n].abi, bytecode: "0x" + out.contracts[f][n].evm.bytecode.object });
  const r = { ownership: pick("Ownership.sol", "EnclaveHostOwnership"), vault: pick("V.sol", "EnclaveSecretVaultV2"), book: pick("Rig.sol", "RigBook"),
              ledger: pick("Rig.sol", "RigLedger"), registry: pick("Rig.sol", "RigRegistry"), wallet1271: pick("Rig.sol", "Rig1271") };
  fs.writeFileSync(cache, JSON.stringify(r));
  return r;
}
const sha = (b) => "0x" + createHash("sha256").update(b).digest("hex");
const APP = Buffer.alloc(32, 0xa7);
const RULES = { v: 1, appId: APP.toString("hex"), images: [{ platform: "sev-snp", measurement: MEASUREMENT, runtimeId: runtimeId(RUNTIME).toString("hex") }], minTcb: FLOOR, vmpl: 0 };
const CUSTODIAN_MEAS = Buffer.alloc(48, 0x6d);

test("independent custody lifecycle: owner-permitted formation, refusal-tolerant activation, release, update, owner-admitted replacement and owner-governed code",
  { skip: anvilAvailable() ? false : "anvil not installed", timeout: 600_000 }, async () => {
  const C = compile();
  const anvil = await startAnvil({ chainId: 31337 });
  try {
    const pub = anvil.client, chainId = 31337;
    const fund = (a) => pub.request({ method: "anvil_setBalance", params: [a, "0x" + parseEther("100").toString(16)] });
    const acct = async () => { const a = privateKeyToAccount(generatePrivateKey()); await fund(a.address); return a; };
    const wallet = (a) => createWalletClient({ account: a, chain: anvil.chain, transport: http(anvil.url) });
    const mined = async (hash, what) => { const r = await pub.waitForTransactionReceipt({ hash }); if (r.status !== "success") throw new Error(`${what} reverted`); return r; };
    const send = async (a, address, abi, functionName, args) => (await mined(await wallet(a).writeContract({ address, abi, functionName, args }), functionName)).transactionHash;
    const deploy = async (a, c, args = []) => (await pub.waitForTransactionReceipt({ hash: await wallet(a).deployContract({ abi: c.abi, bytecode: c.bytecode, args }) })).contractAddress;
    const deployer = await acct(), enclaveWallet = await acct();
    const book = await deploy(deployer, C.book), ledger = await deploy(deployer, C.ledger), registry = await deploy(deployer, C.registry);
    await send(deployer, book, C.book.abi, "set", [stringToHex("deployments", { size: 32 }), ledger]);
    await send(deployer, book, C.book.abi, "set", [stringToHex("registry", { size: 32 }), registry]);
    const ownership = await deploy(deployer, C.ownership, [registry]);
    const vault = (await deploy(deployer, C.vault, [book, enclaveWallet.address, ownership])).toLowerCase();
    const reader = () => createChainReaderV2({ rpcs: [anvil.url], vault, hostOwnership: ownership.toLowerCase(), chainId, minAgree: 1, maxAgeSec: 86400 });
    const chain = reader();

    // ---- hosts: each with its own operator and accepted owner wallet; h2's owner is an ERC-1271 contract wallet ----
    const owners = {}, hosts = {};
    const host = async (name, owner) => {
      const op = await acct(), endpoint = `https://${name}.host.test`, registryId = keccak256(toBytes(endpoint));
      await send(deployer, registry, C.registry.abi, "set", [endpoint, op.address, true, enclaveWallet.address]);   // payout naming Enclave confers nothing
      await send(op, ownership, C.ownership.abi, "proposeOwner", [registryId, owner.address]);
      if (owner.contract) await send(owner.signer, owner.address, C.wallet1271.abi, "accept", [ownership, registryId]);
      else await send(owner.account, ownership, C.ownership.abi, "acceptOwner", [registryId]);
      return (hosts[name] = { op, endpoint, registryId });
    };
    const eoaOwner = async () => { const account = await acct(); return { address: account.address.toLowerCase(), account, sign: (d) => D.signDigest(account, d) }; };
    owners.o0 = await eoaOwner(); owners.o1 = await eoaOwner(); owners.o3 = await eoaOwner();
    { const signer = await acct(); const address = (await deploy(deployer, C.wallet1271, [signer.address])).toLowerCase();
      owners.o2 = { address, contract: true, signer, sign: (d) => D.signDigest(signer, d) }; }
    await host("h0", owners.o0); await host("h1", owners.o1); await host("h2", owners.o2);
    await host("h3", owners.o3);                 // a new user's host
    await host("h4", owners.o1);                 // a second host of an existing seat owner
    const appOp = await acct(), appEndpoint = "https://app.host.test";
    await send(deployer, registry, C.registry.abi, "set", [appEndpoint, appOp.address, true, "0x" + "00".repeat(20)]);

    // ---- custodians (in process), routed by endpoint; `down` simulates an offline or refusing machine ----
    const policy = independentPolicy({ independentAdmission: "owner-permits", enclaveOwner: enclaveWallet.address });
    const S = synthChain();
    const collateral = memoryCollateral({ chains: { Genoa: S.chainPem }, vceks: { Genoa: S.vcekDer }, crls: { Genoa: S.crlDer } });
    const verifiers = Object.freeze({ [SNP_GUEST_FORMAT]: snpVerifier({ collateral, roots: new Map([["Genoa", S.arkFp]]) }) });
    const payer = await acct();
    const machines = {}, down = new Set();
    const at = (url) => { const m = Object.values(machines).find((x) => url.startsWith(x.endpoint + "/")); if (!m || down.has(m.name)) throw new Error(`unreachable ${url}`); return [m, url.slice(m.endpoint.length)]; };
    const info = (m) => ({ ...m.member.info(m.member.committees()[0] || null), chainId, vault, independentAdmission: policy.mode });
    const get = async (url) => { const [m, p] = at(url); if (p !== "/v2/custody/info") throw new Error(`no GET ${p}`); return info(m); };
    const post = async (url, body) => {
      const [m, p] = at(url);
      body = JSON.parse(JSON.stringify(body));
      if (p === "/v2/custody/evidence") return m.member.evidence(body.nonce);
      if (p === "/v2/custody/approve") return m.member.approve(body);
      if (p === "/v2/custody/join") return m.member.join(body, m.member.committees()[0] || null);
      if (p === "/v2/custody/code-approve") return m.member.approveCode(body);
      if (p === "/v2/custody/independent-genesis") return m.genesis(body);
      throw new Error(`no route ${p}`);
    };
    const fetchJson = (url, body) => (body === undefined ? get(url) : post(url, body));
    let skew = 0; const now = () => Date.now() + skew;
    const makeMachine = async (name, h, { refuseGas = false } = {}) => {
      const identity = privateKeyToAccount(generatePrivateKey()), kp = hpke.generateKeyPair(), chip = randomBytes(64);
      const machine = { identity: identity.address.toLowerCase(), encKey: "0x" + Buffer.from(kp.publicKey).toString("hex"), endpoint: `https://custody-${name}.test`,
                        chipId: sha(chip), registryId: h.registryId, measurement: sha(CUSTODIAN_MEAS) };
      const state = { member: null }, snapshots = [];
      const persist = async () => { snapshots.push(JSON.parse(JSON.stringify(state))); };
      const mchain = reader();
      const submit = async (fn, args) => { if (refuseGas) throw new Error("submit: no submitter key configured"); return send(payer, vault, VAULT_V2_ABI, fn, args); };
      const member = createMember({ chainId, vault, identity, encPrivateKey: kp.privateKey, machine, chain: mchain, submit, fetchJson, now, log: () => {},
        enclaveOwner: enclaveWallet.address, store: { load: () => state.member, save: (s) => { state.member = s; persist(); } },
        admissionCheck: ownerPermitAdmission({ chainId, vault, chain: mchain, enclaveOwner: enclaveWallet.address }),
        capacityCheck: async () => { throw new Error("no capacity witness may be consulted"); },
        attestSelf: async (binding) => ({ report: Buffer.concat([Buffer.from(binding), CUSTODIAN_MEAS, chip]), auxblob: null }),
        verifyPeerQuote: async (report, { binding }) => (Buffer.compare(report.subarray(0, 32), Buffer.from(binding)) === 0
          ? { ok: true, measurement: report.subarray(32, 80).toString("hex"), chipId: report.subarray(80, 144).toString("hex") } : { ok: false, reason: "binding" }) });
      await member.setHostSig(await D.signDigest(h.op, D.hostDigest({ chainId, vault, machine })));
      const genesis = createIndependentService({ policy, member, chain: mchain, identity, encPrivateKey: kp.privateKey, invoke, state, persist, fetchJson, submit });
      const custodian = createCustodianV2({ chainId, vault, encPrivateKey: kp.privateKey, shares: member.shares, chain: mchain, verifiers, log: () => {} });
      return (machines[name] = { name, endpoint: machine.endpoint, machine, member, custodian, genesis, state, snapshots, host: h });
    };
    const M0 = await makeMachine("m0", hosts.h0, { refuseGas: true }), M1 = await makeMachine("m1", hosts.h1), M2 = await makeMachine("m2", hosts.h2);
    const founders = [M0, M1, M2];

    // ---- 1. plan with explicit pins; every operator and every owner signs the exact plan ----
    let plan = await W.buildPlan({ endpoints: founders.map((m) => m.endpoint), chainId, vault, measurement: sha(CUSTODIAN_MEAS), get });
    assert.equal((await W.checkPlan(plan, { chain })).ready, false);
    const digest = W.planDigest(plan);
    for (const [i, m] of founders.entries()) plan = W.addPlanSignature(plan, { role: "operator", index: i, signature: await D.signDigest(m.host.op, digest) });
    const ownerOf = { m0: owners.o0, m1: owners.o1, m2: owners.o2 };
    const partial = structuredClone(plan);
    for (const [i, m] of founders.entries()) plan = W.addPlanSignature(plan, { role: "owner", index: i, signature: await ownerOf[m.name].sign(digest) });
    const planCheck = await W.checkPlan(plan, { chain });
    assert.deepEqual({ ...planCheck, blockNumber: undefined }, { digest, ready: true, problems: [], blockNumber: undefined }, "EOA and ERC-1271 owner permits verify at the agreed block");
    // a plan lacking one owner's consent cannot allocate any member's DKG session
    const lacking = W.addPlanSignature(partial, { role: "owner", index: 0, signature: await owners.o0.sign(digest) });
    assert.equal(await M1.member.verifyGenesisRoster(lacking, policy), false);
    await assert.rejects(M1.genesis({ action: "start", plan: lacking }), /not verified/);
    assert.equal(M1.state.independentPlan, undefined);

    // ---- 2. formation; m0's host refuses to pay gas and still adopts; m2 is offline for activation and adopts later ----
    const offlineActivation = (url, body) => (body.action === "activate" && url.startsWith(M2.endpoint + "/") ? Promise.reject(new Error("m2 offline")) : post(url, body));
    const formed = await coordinateIndependentGenesis(plan, { post: offlineActivation, get, activate: true });
    assert.deepEqual(formed.unadopted.map((u) => u.id), [3]);
    assert.deepEqual(formed.activated.map((a) => a.id).sort(), [1, 2]);
    assert.equal(M2.member.committees().length, 0);
    assert.equal((await M2.genesis.adoptIfCreated()).committeeId, formed.committeeId, "a returning founder adopts from the chain by itself");
    assert.equal(await M2.genesis.adoptIfCreated(), null);
    assert.ok(formed.transaction && formed.transaction.to === vault, "neutral creation calldata for any wallet");
    const cid = formed.committeeId;
    let { committee } = await chain.readCommittee({ committeeId: cid });
    assert.ok(W.committeeMatches(committee, plan, formed.commitments));
    assert.deepEqual([committee.epoch, committee.t, committee.W], [1, 2, 3]);
    for (const m of founders) {
      assert.deepEqual(m.member.shares.get(cid, 1).map((s) => s.k), [founders.indexOf(m) + 1]);
      assert.equal(m.state.independentDkg.share, undefined, "the DKG copy of the share is erased after adoption");
      assert.equal(m.state.independentDkg.adopted, true);
      assert.equal(JSON.stringify(m.snapshots.at(-1).independentDkg).includes(m.member.shares.get(cid, 1)[0].x.toString(16)), false);
      assert.deepEqual(await m.genesis({ action: "activate", results: formed.results }), { committeeId: cid, adopted: true }, "activation is idempotent");
    }
    await assert.rejects(M1.genesis({ action: "start", plan: { ...plan, salt: "0x" + "ab".repeat(32) } }), /finished DKG session/, "a finished session cannot be replanned");

    // ---- 3. an owner provisions a secret; 2-of-3 releases, including with one member down ----
    const appOwner = await acct();
    const id = "0x" + randomBytes(32).toString("hex");
    await send(deployer, ledger, C.ledger.abi, "set", [id, appOwner.address, keccak256(toBytes(appEndpoint)), appOp.address, BigInt(Number((await pub.getBlock()).timestamp) + 7200)]);
    let env = { API_KEY: "independent-v1" };
    const publish = async (secretRev, expectPolicyRev) => {
      const bundle = buildBundleV2({ chainId, vault, id, secretRev, committeeId: cid, Y: committee.Y, env, configText: "" });
      await send(appOwner, vault, UPDATE_V2_ABI, "update", [id, makeUpdateV2({ expectPolicyRev, policy: { committeeId: cid, paused: false, rules: RULES }, bundle })]);
    };
    await publish(1, 0);
    const unlock = async (use) => {
      const st = await chain.readRelease({ id, endpoint: appEndpoint });
      const com = st.committee;
      const att = snpAttester(S, { appId: APP, hostData: Buffer.from(id.slice(2), "hex") });
      const recipient = hpke.generateKeyPair();
      const challenges = use.map((m) => ({ m, ...m.custodian.challenge() }));
      const binding = v2.releaseBinding({ chainId, vault, id, policyRev: st.policy.policyRev, secretRev: st.policy.secretRev, committeeId: cid, epoch: com.epoch,
        challenges: challenges.map((c) => ({ encKey: Buffer.from(c.encKey, "hex"), nonce: Buffer.from(c.nonce, "hex") })),
        runtimeId: new Uint8Array(runtimeId(RUNTIME)), transportSpki: att.transportSpki, recipientKey: recipient.publicKey });
      const expiry = Math.floor(Date.now() / 1000) + 300;
      const sig = await appOp.signMessage({ message: v2.operatorMessage({ chainId, vault, id, endpoint: appEndpoint, binding, expiry }) });
      const evidence = await att.evidence(binding);
      const commitments = []; for (let i = 0; i < com.commitments.length; i += 33) commitments.push(com.commitments.subarray(i, i + 33));
      const R = v2.parseBundle(st.bundle.data).R, parts = [];
      for (const c of challenges) {
        if (down.has(c.m.name)) continue;                    // a refusing or offline member is skipped, never waited for
        const r = await c.m.custodian.release({ v: 2, id, endpoint: appEndpoint, committeeId: cid, epoch: com.epoch, policyRev: String(st.policy.policyRev), secretRev: String(st.policy.secretRev),
          recipientKey: Buffer.from(recipient.publicKey).toString("hex"), challenges: challenges.map((x) => ({ encKey: x.encKey, nonce: x.nonce })), operator: { sig, expiry }, evidence });
        for (const record of v2.openPartials({ recipientPrivate: recipient.privateKey, binding, encKey: Buffer.from(r.encKey, "hex"), count: r.count, sealed: Buffer.from(r.sealed, "base64") }))
          parts.push(v2.verifyPartial({ record, R, binding, commitments }));
      }
      return v2.decryptBundle({ S: v2.combine(parts.slice(0, com.t), com.t), label: v2.labelOf({ chainId, vault, id, secretRev: st.policy.secretRev, committeeId: cid }), bundle: st.bundle.data }).env;
    };
    assert.deepEqual(await unlock([M0, M1]), env);
    down.add("m0");
    assert.deepEqual(await unlock([M0, M1, M2]), env, "one member down: the other two seats suffice");
    let status = await W.committeeStatus({ chain, committeeId: cid, chainId, vault, get });
    assert.deepEqual([status.independent, status.distinctOwners, status.servingWeight, status.releaseAvailable], [true, true, 2, true]);
    assert.equal(status.members.find((m) => m.identity === M0.machine.identity).reachable, false);
    // ---- 4. the owner updates the secret without any custodian action ----
    env = { API_KEY: "independent-v2", EXTRA: "1" };
    await publish(2, 1);
    assert.deepEqual(await unlock([M1, M2]), env);
    await assert.rejects(unlock([M1]), /exactly 2/, "one share alone cannot decrypt");

    // ---- 5. a new user's machine replaces the dead member, admitted by owner permits ----
    const M3 = await makeMachine("m3", hosts.h3), M4 = await makeMachine("m4", hosts.h4);
    await assert.rejects(M1.member.join({ machine: M3.machine }, cid), /owner admission signatures are required/);
    const { expiresAt } = await W.chainExpiry(chain, cid, 3600);
    let request = W.admissionRequest({ chainId, vault, committeeId: cid, machine: M3.machine, hostSig: info(M3).hostSig, expiresAt });
    request = W.addAdmissionSignature(request, { owner: owners.o3.address, signature: await owners.o3.sign(request.digest) });
    request = W.addAdmissionSignature(request, { owner: owners.o1.address, signature: await owners.o1.sign(request.digest) });
    assert.match((await W.checkAdmission(request, { chain })).problems.join(), /1 of 2/);
    await assert.rejects(M1.member.join({ machine: M3.machine, admission: { expiresAt, signatures: request.signatures } }, cid), /1 of 2 required governance voters/);
    request = W.addAdmissionSignature(request, { owner: owners.o2.address, signature: await owners.o2.sign(request.digest) });
    assert.equal((await W.checkAdmission(request, { chain })).ready, true);
    const forged = W.addAdmissionSignature(request, { owner: owners.o0.address, signature: await owners.o0.sign(request.digest) });
    forged.expiresAt += 1;
    await assert.rejects(M1.member.join({ machine: M3.machine, admission: { expiresAt: forged.expiresAt, signatures: forged.signatures } }, cid), /own owner did not sign/);
    const joined = await W.joinCommittee({ request, committee, post });
    assert.equal(joined.accepted, 2);
    assert.match(joined.members.find((x) => x.endpoint === M0.endpoint).reason, /unreachable/);
    // a fully permitted second machine of an existing seat owner is admitted as a candidate but never gets a seat
    let dup = W.admissionRequest({ chainId, vault, committeeId: cid, machine: M4.machine, hostSig: info(M4).hostSig, expiresAt });
    for (const o of [owners.o1, owners.o2]) dup = W.addAdmissionSignature(dup, { owner: o.address, signature: await o.sign(dup.digest) });
    assert.equal((await W.joinCommittee({ request: dup, committee, post })).accepted, 2);
    const dealers = [2, 3];
    const strip = (m, extra = {}) => ({ ...m.machine, enclave: false, hostSig: info(m).hostSig, ...extra });
    await assert.rejects(M2.member.approve({ committeeId: cid, fromEpoch: 1, next: [strip(M1), strip(M2), strip(M4, { admission: { expiresAt, signatures: dup.signatures } })], dealerIndices: dealers }),
      /second seat for one owner/);
    // the coordinator (lowest live identity) proposes at once: only t shares remain reachable
    const coordinator = [M1, M2].sort((a, b) => (a.machine.identity < b.machine.identity ? -1 : 1))[0];
    const other = coordinator === M1 ? M2 : M1;
    assert.equal((await other.member.tick(cid)).state, "idle");
    // the approver that never saw the join re-verifies the newcomer from the admission carried in the proposal
    delete other.member._state().candidates[M3.machine.identity];
    const proposed = await coordinator.member.tick(cid);
    assert.equal(proposed.state, "proposed", JSON.stringify(proposed));
    let pending = (await chain.readCommittee({ committeeId: cid })).pending;
    assert.deepEqual(pending.next.map((m) => m.identity), [M1, M2, M3].map((m) => m.machine.identity), "the duplicate-owner candidate was left out");
    for (let i = 0; i < 4; i++) for (const m of [M1, M2, M3]) await m.member.tick(cid);
    ({ committee } = await chain.readCommittee({ committeeId: cid }));
    assert.deepEqual([committee.epoch, committee.t, committee.W, committee.machines.some((m) => m.enclave)], [2, 2, 3, false]);
    assert.equal(Buffer.from(committee.Y).toString("hex"), formed.commitments.slice(2, 68), "the committee key never changed");
    for (const m of [M1, M2, M3]) await m.member.tick(cid);
    assert.deepEqual(M1.member.shares.get(cid, 1), [], "epoch-1 shares are erased after the handover");
    assert.deepEqual(await unlock([M3, M1]), env, "the new member and a continuing member unlock the existing bundle");
    assert.deepEqual(await unlock([M2, M3]), env);
    status = await W.committeeStatus({ chain, committeeId: cid, chainId, vault, get });
    assert.deepEqual([status.epoch, status.servingWeight, status.distinctOwners, status.releaseAvailable], [2, 3, true, true]);

    // ---- 6. owners govern custodian code; any wallet submits the vault proposal ----
    const newCode = sha(Buffer.alloc(48, 0x6e));
    const { expiresAt: codeExpiry } = await W.chainExpiry(chain, cid, 3600);
    const codeReq = W.codePermitRequest({ chainId, vault, committeeId: cid, measurement: newCode, add: true, expiresAt: codeExpiry });
    const seatOwner = { [M1.machine.identity]: owners.o1, [M2.machine.identity]: owners.o2, [M3.machine.identity]: owners.o3 };
    const wrong = await W.collectCodeApprovals({ request: codeReq, committee, post,
      permits: Object.fromEntries(await Promise.all(Object.keys(seatOwner).map(async (k) => [k, await owners.o0.sign(codeReq.digest)]))) });
    assert.equal(wrong.transaction, null);
    assert.ok(wrong.refused.every((r) => /not authorized by this seat's owner/.test(r.reason)));
    const one = await W.collectCodeApprovals({ request: codeReq, committee, post, permits: { [M3.machine.identity]: await owners.o3.sign(codeReq.digest) } });
    assert.deepEqual([one.weight, one.transaction], [1, null], "one owner cannot add custodian code");
    const code = await W.collectCodeApprovals({ request: codeReq, committee, post,
      permits: Object.fromEntries(await Promise.all(Object.entries(seatOwner).map(async ([k, o]) => [k, await o.sign(codeReq.digest)]))) });
    assert.equal(code.weight, 3);
    const outsider = await acct();
    await mined(await wallet(outsider).sendTransaction({ to: code.transaction.to, data: code.transaction.data }), "proposeCode");
    assert.ok((await chain.readCodeActiveAt({ committeeId: cid, measurement: newCode })).activeAt > 0);
  } finally { anvil.stop(); }
});
