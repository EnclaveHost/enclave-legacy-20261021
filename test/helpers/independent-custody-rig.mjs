// A REAL chain (anvil) with the REAL EnclaveSecretVaultV2 and EnclaveHostOwnership, minimal ledger/registry stand-ins,
// and in-process custodians running the real member engine, genesis service (real FROST helper) and release path.
// Custodian self-attestation is stubbed (binding ‖ measurement ‖ chip) and app-guest attestation is simulated: this is
// not hardware evidence. Used by the independent custody governance tests.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createWalletClient, http, keccak256, toBytes, parseEther, stringToHex } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { startAnvil, snpAttester, RUNTIME, MEASUREMENT, FLOOR } from "./custody-rig.mjs";
import { synthChain } from "./snp-synth.mjs";
import { memoryCollateral } from "../../verifier/index.mjs";
import { snpVerifier, SNP_GUEST_FORMAT } from "../../custody/verifiers.mjs";
import * as hpke from "../../custody/hpke.mjs";
import * as v2 from "../../custody/v2/protocol.mjs";
import * as D from "../../custody/v2/digests.mjs";
import { createChainReaderV2, VAULT_V2_ABI } from "../../custody/v2/chain.mjs";
import { createCustodianV2 } from "../../custody/v2/custodian.mjs";
import { createMember } from "../../custody/v2/member.mjs";
import { buildBundleV2, makeUpdateV2, UPDATE_V2_ABI } from "../../custody/v2/owner.mjs";
import { dkgHelper } from "../../custody/v2/independent-genesis.mjs";
import { createIndependentService } from "../../custody/v2/independent-runtime.mjs";
import { coordinateIndependentGenesis } from "../../custody/v2/coordinate-genesis.mjs";
import { independentPolicy, ownerPermitAdmission } from "../../custody/v2/governance.mjs";
import * as W from "../../custody/v2/workflow.mjs";
import { runtimeId } from "../../isolation/contract/runtime.mjs";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const require = createRequire(import.meta.url);
export const buildDkgHelper = () => execFileSync("cargo", ["build", "--locked", "--manifest-path", path.join(ROOT, "custody/dkg/Cargo.toml")], { stdio: "pipe", timeout: 300000 });
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
  const cache = path.join(process.env.TMPDIR || "/tmp", `enclave-custody-v2-independent-rig-${key}.json`);
  if (fs.existsSync(cache)) return JSON.parse(fs.readFileSync(cache, "utf8"));
  const out = JSON.parse(require("solc").compile(JSON.stringify({ language: "Solidity", sources: { "V.sol": { content: src }, "Rig.sol": { content: MOCKS }, "Ownership.sol": { content: ownershipSrc } },
    settings: { viaIR: true, optimizer: { enabled: true, runs: 200 }, outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } } })));
  const errs = (out.errors || []).filter((e) => e.severity === "error");
  if (errs.length) throw new Error(errs.map((e) => e.formattedMessage).join("\n"));
  const pick = (f, n) => ({ abi: out.contracts[f][n].abi, bytecode: "0x" + out.contracts[f][n].evm.bytecode.object });
  const r = { ownership: pick("Ownership.sol", "EnclaveHostOwnership"), vault: pick("V.sol", "EnclaveSecretVaultV2"), book: pick("Rig.sol", "RigBook"),
              ledger: pick("Rig.sol", "RigLedger"), registry: pick("Rig.sol", "RigRegistry") };
  fs.writeFileSync(cache, JSON.stringify(r));
  return r;
}
export const sha = (b) => "0x" + createHash("sha256").update(b).digest("hex");
const APP = Buffer.alloc(32, 0xa7);
const RULES = { v: 1, appId: APP.toString("hex"), images: [{ platform: "sev-snp", measurement: MEASUREMENT, runtimeId: runtimeId(RUNTIME).toString("hex") }], minTcb: FLOOR, vmpl: 0 };
export const CUSTODIAN_MEAS = Buffer.alloc(48, 0x6d);

export async function independentRig() {
  const C = compile(), anvil = await startAnvil({ chainId: 31337 }), invoke = dkgHelper(path.join(ROOT, "custody/dkg/target/debug/enclave-custody-dkg"));
  const pub = anvil.client, chainId = 31337;
  const acct = async () => { const a = privateKeyToAccount(generatePrivateKey()); await pub.request({ method: "anvil_setBalance", params: [a.address, "0x" + parseEther("100").toString(16)] }); return a; };
  const wallet = (a) => createWalletClient({ account: a, chain: anvil.chain, transport: http(anvil.url) });
  const mined = async (hash, what) => { const r = await pub.waitForTransactionReceipt({ hash }); if (r.status !== "success") throw new Error(`${what} reverted`); return r; };
  const send = async (a, address, abi, functionName, args) => (await mined(await wallet(a).writeContract({ address, abi, functionName, args }), functionName)).transactionHash;
  const deploy = async (a, c, args = []) => (await pub.waitForTransactionReceipt({ hash: await wallet(a).deployContract({ abi: c.abi, bytecode: c.bytecode, args }) })).contractAddress;
  const deployer = await acct(), enclaveWallet = await acct(), payer = await acct();
  const book = await deploy(deployer, C.book), ledger = await deploy(deployer, C.ledger), registry = await deploy(deployer, C.registry);
  await send(deployer, book, C.book.abi, "set", [stringToHex("deployments", { size: 32 }), ledger]);
  await send(deployer, book, C.book.abi, "set", [stringToHex("registry", { size: 32 }), registry]);
  const ownership = await deploy(deployer, C.ownership, [registry]);
  const vault = (await deploy(deployer, C.vault, [book, enclaveWallet.address, ownership])).toLowerCase();
  const reader = () => createChainReaderV2({ rpcs: [anvil.url], vault, hostOwnership: ownership.toLowerCase(), chainId, minAgree: 1, maxAgeSec: 86400 });
  const chain = reader();
  const owner = async () => { const account = await acct(); return { address: account.address.toLowerCase(), account, sign: (d) => D.signDigest(account, d) }; };
  const hosts = {};
  const host = async (name, o) => {
    const op = await acct(), endpoint = `https://${name}.host.test`, registryId = keccak256(toBytes(endpoint));
    await send(deployer, registry, C.registry.abi, "set", [endpoint, op.address, true, enclaveWallet.address]);
    await send(op, ownership, C.ownership.abi, "proposeOwner", [registryId, o.address]);
    await send(o.account, ownership, C.ownership.abi, "acceptOwner", [registryId]);
    return (hosts[name] = { op, endpoint, registryId, owner: o });
  };
  // an accepted owner hands its host to another wallet: the existing owner proposes, the new owner accepts
  const transfer = async (h, to) => {
    await send(h.owner.account, ownership, C.ownership.abi, "proposeOwner", [h.registryId, to.address]);
    await send(to.account, ownership, C.ownership.abi, "acceptOwner", [h.registryId]);
    h.owner = to;
  };
  const mine = () => pub.request({ method: "evm_mine", params: [] });

  const policy = independentPolicy({ independentAdmission: "owner-permits", enclaveOwner: enclaveWallet.address });
  const S = synthChain();
  const collateral = memoryCollateral({ chains: { Genoa: S.chainPem }, vceks: { Genoa: S.vcekDer }, crls: { Genoa: S.crlDer } });
  const verifiers = Object.freeze({ [SNP_GUEST_FORMAT]: snpVerifier({ collateral, roots: new Map([["Genoa", S.arkFp]]) }) });
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
  const clock = { skew: 0 }, now = () => Date.now() + clock.skew;
  const makeMachine = async (name, h, { endpoint = `https://custody-${name}.test` } = {}) => {
    const identity = privateKeyToAccount(generatePrivateKey()), kp = hpke.generateKeyPair(), chip = randomBytes(64);
    const machine = { identity: identity.address.toLowerCase(), encKey: "0x" + Buffer.from(kp.publicKey).toString("hex"), endpoint,
                      chipId: sha(chip), registryId: h.registryId, measurement: sha(CUSTODIAN_MEAS) };
    const state = { member: null }, mchain = reader();
    const persist = async () => {};
    const submit = (fn, args) => send(payer, vault, VAULT_V2_ABI, fn, args);
    const member = createMember({ chainId, vault, identity, encPrivateKey: kp.privateKey, machine, chain: mchain, submit, fetchJson, now, log: () => {},
      enclaveOwner: enclaveWallet.address, store: { load: () => state.member, save: (s) => { state.member = s; } },
      admissionCheck: ownerPermitAdmission({ enclaveOwner: enclaveWallet.address }),
      capacityCheck: async () => { throw new Error("no capacity witness may be consulted"); },
      attestSelf: async (binding) => ({ report: Buffer.concat([Buffer.from(binding), CUSTODIAN_MEAS, chip]), auxblob: null }),
      verifyPeerQuote: async (report, { binding }) => (Buffer.compare(report.subarray(0, 32), Buffer.from(binding)) === 0
        ? { ok: true, measurement: report.subarray(32, 80).toString("hex"), chipId: report.subarray(80, 144).toString("hex") } : { ok: false, reason: "binding" }) });
    await member.setHostSig(await D.signDigest(h.op, D.hostDigest({ chainId, vault, machine })));
    const genesis = createIndependentService({ policy, member, chain: mchain, identity, encPrivateKey: kp.privateKey, invoke, state, persist, fetchJson, submit });
    const custodian = createCustodianV2({ chainId, vault, encPrivateKey: kp.privateKey, shares: member.shares, chain: mchain, verifiers, log: () => {} });
    return (machines[name] = { name, endpoint, machine, identity, member, custodian, genesis, state, host: h, info: () => info(machines[name]) });
  };
  // every operator and owner signs the exact plan; the founders run the DKG and activate
  const form = async (founders) => {
    let plan = await W.buildPlan({ endpoints: founders.map((m) => m.endpoint), chainId, vault, measurement: sha(CUSTODIAN_MEAS), get });
    const digest = W.planDigest(plan);
    for (const [i, m] of founders.entries()) {
      plan = W.addPlanSignature(plan, { role: "operator", index: i, signature: await D.signDigest(m.host.op, digest) });
      plan = W.addPlanSignature(plan, { role: "owner", index: i, signature: await m.host.owner.sign(digest) });
    }
    const formed = await coordinateIndependentGenesis(plan, { post, get, activate: true });
    if (formed.unadopted.length) throw new Error("founders did not adopt");
    return { plan, cid: formed.committeeId, formed };
  };
  const admission = async (cid, m, signers, { seconds = 3600 } = {}) => {
    const { expiresAt } = seconds >= 60 ? await W.chainExpiry(chain, cid, seconds) : { expiresAt: Number((await pub.getBlock()).timestamp) + seconds };
    let r = W.admissionRequest({ chainId, vault, committeeId: cid, machine: m.machine, hostSig: info(m).hostSig, expiresAt });
    for (const o of signers) r = W.addAdmissionSignature(r, { owner: o.address, signature: await o.sign(r.digest) });
    return r;
  };

  // an app owner publishes a bundle to the committee; unlock(use) is the guest's release over the chosen custodians
  const appOwner = await acct(), appOp = await acct(), appEndpoint = "https://app.host.test";
  await send(deployer, registry, C.registry.abi, "set", [appEndpoint, appOp.address, true, "0x" + "00".repeat(20)]);
  const id = "0x" + randomBytes(32).toString("hex");
  const publish = async (cid, env, secretRev, expectPolicyRev) => {
    await send(deployer, ledger, C.ledger.abi, "set", [id, appOwner.address, keccak256(toBytes(appEndpoint)), appOp.address, BigInt(Number((await pub.getBlock()).timestamp) + 7200)]);
    const { committee } = await chain.readCommittee({ committeeId: cid });
    const bundle = buildBundleV2({ chainId, vault, id, secretRev, committeeId: cid, Y: committee.Y, env, configText: "" });
    await send(appOwner, vault, UPDATE_V2_ABI, "update", [id, makeUpdateV2({ expectPolicyRev, policy: { committeeId: cid, paused: false, rules: RULES }, bundle })]);
  };
  const unlock = async (cid, use) => {
    const st = await chain.readRelease({ id, endpoint: appEndpoint }), com = st.committee;
    const att = snpAttester(S, { appId: APP, hostData: Buffer.from(id.slice(2), "hex") }), recipient = hpke.generateKeyPair();
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
      const r = await c.m.custodian.release({ v: 2, id, endpoint: appEndpoint, committeeId: cid, epoch: com.epoch, policyRev: String(st.policy.policyRev), secretRev: String(st.policy.secretRev),
        recipientKey: Buffer.from(recipient.publicKey).toString("hex"), challenges: challenges.map((x) => ({ encKey: x.encKey, nonce: x.nonce })), operator: { sig, expiry }, evidence });
      for (const record of v2.openPartials({ recipientPrivate: recipient.privateKey, binding, encKey: Buffer.from(r.encKey, "hex"), count: r.count, sealed: Buffer.from(r.sealed, "base64") }))
        parts.push(v2.verifyPartial({ record, R, binding, commitments }));
    }
    return v2.decryptBundle({ S: v2.combine(parts.slice(0, com.t), com.t), label: v2.labelOf({ chainId, vault, id, secretRev: st.policy.secretRev, committeeId: cid }), bundle: st.bundle.data }).env;
  };
  return { anvil, pub, chainId, vault, chain, acct, send, mined, wallet, owner, host, hosts, transfer, mine, makeMachine, machines, down, get, post, clock,
           form, admission, publish, unlock, enclaveWallet, stop: () => anvil.stop() };
}
