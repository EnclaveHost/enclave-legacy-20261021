// The in-memory Shield custody rig shared by test/shield-custody.test.mjs and test/custody-v2-shield-daemon.test.mjs: a real
// committee key and share (v2 genesis), a real owner bundle with its label proof, the REAL custodian (createCustodianV2), a
// host TPM session through the node's real frame builder over a synthetic TPM, and a guest VBS report over
// shieldReleaseInput || AppID. Moved verbatim from shield-custody.test.mjs; `shieldFor` lets a test install the adapter the
// measured daemon builds (custody/v2/shield-operator.mjs) instead of a bare createShieldCustody.   Needs openssl.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes, createHash, sign, constants, generateKeyPairSync } from "node:crypto";
import { keccak256, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { haveOpenssl, tmpdir, makeVbsWorld, buildLog, buildQuote } from "../fixtures/vbs-synthetic.mjs";
import { activateCredential } from "../../relay/vbs-credential.mjs";
import { runtimeId } from "../../isolation/contract/runtime.mjs";
import { buildHvNodeFrame } from "../../windows/node/hvnode-evidence.mjs";
import { attachMessage } from "../../windows/node/shield-verdict.mjs";
import * as v2 from "../../custody/v2/protocol.mjs";
import * as hpke from "../../custody/hpke.mjs";
import { createCustodianV2 } from "../../custody/v2/custodian.mjs";
import { createShieldCustody, shieldReleaseInput, SHIELD_EVIDENCE_FORMAT } from "../../custody/v2/shield-evidence.mjs";
import { canonicalShieldRules, SHIELD_RULES_FORMAT, SHIELD_TIER_ACK } from "../../custody/v2/shield-rules.mjs";

export const options = { skip: !haveOpenssl && "openssl absent" };
export const world = haveOpenssl ? makeVbsWorld(tmpdir("shield-custody-")) : null;
export const other = haveOpenssl ? makeVbsWorld(tmpdir("shield-custody-other-")) : null;
export const sha = (b) => createHash("sha256").update(b).digest(), hex = (b) => Buffer.from(b).toString("hex"), b64 = (b) => Buffer.from(b).toString("base64");
export const IMAGE = "ab".repeat(32), APP = "cd".repeat(32);
export const RUNTIME = { name: "wasmtime", version: "48.0.1", execution: "jit", targetIsa: "x86_64", hostIsa: "x86_64", cpuFeatures: "host-detected", wx: "enforced", cache: "none" };
export const RID = runtimeId(RUNTIME);
export const CHAIN = 8453, VAULT = "0x" + "5a".repeat(20), DEP = "0x" + "e7".repeat(32), COMMITTEE = "0x" + "cc".repeat(32);
export const ENDPOINT = "https://box.example.org", OTHER_ENDPOINT = "https://other.example.org";
export const OWNER = "0x" + "33".repeat(20), NEW_OWNER = "0x" + "44".repeat(20);
export const operator = privateKeyToAccount("0x" + "42".repeat(32)), stranger = privateKeyToAccount("0x" + "43".repeat(32));
export const SECRETS = { API_KEY: "s3cret-value" };

export const shieldRules = (over = {}) => ({ format: SHIELD_RULES_FORMAT, acceptTier: SHIELD_TIER_ACK, appId: APP, images: [{ measurement: IMAGE, runtimeId: hex(RID) }],
                                       platforms: "attested", ...over });
export const snpRules = () => ({ v: 1, appId: APP, images: [{ platform: "sev-snp", measurement: "ab".repeat(48), runtimeId: hex(RID) }],
                          minTcb: { Genoa: { bootloader: 10, tee: 0, snp: 23, microcode: 84 } }, vmpl: 0 });

// ---- a custodian with a real committee share, a real bundle, and the chain as one agreed read ------------------------------
export function rig({ rules = canonicalShieldRules(shieldRules()), withShield = true, shieldFor = null, owner = OWNER, beneficialOwner = owner, ledgerOwner = beneficialOwner,
               endpointOperator = operator.address.toLowerCase(), runner = ENDPOINT, roots = world } = {}) {
  const g = v2.genesis();
  const label = v2.labelOf({ chainId: CHAIN, vault: VAULT, id: DEP, secretRev: 1n, committeeId: COMMITTEE });
  const bundle = v2.encryptBundle({ Y: g.Y, label, env: SECRETS, configSha256: "00".repeat(32) });
  const kp = hpke.generateKeyPair(), encKeyHex = hex(kp.publicKey);
  const shield = !withShield ? null : shieldFor ? shieldFor(encKeyHex) : createShieldCustody({ party: encKeyHex, ekRoots: roots.ca.bundlePem });
  const state = () => ({ blockNumber: 100n, blockTimestamp: Math.floor(Date.now() / 1000),
    policy: { owner, policyRev: 1n, secretRev: 1n, committeeId: COMMITTEE, paused: false, rules: Buffer.from(rules) },
    bundle: { committeeId: COMMITTEE, secretRev: 1n, data: bundle },
    committee: { epoch: 1, machines: [{ encKey: "0x" + encKeyHex }], commitments: Buffer.from(g.commitments[0]) },
    beneficialOwner, lease: { owner: ledgerOwner, runner: keccak256(toBytes(runner)).toLowerCase(), leaseUntil: Math.floor(Date.now() / 1000) + 3600 },
    endpointId: keccak256(toBytes(ENDPOINT)).toLowerCase(), endpointOperator });
  const shares = { get: () => g.shares };
  const custodian = createCustodianV2({ chainId: CHAIN, vault: VAULT, encPrivateKey: kp.privateKey, shares, chain: { readRelease: async () => state() },
    verifiers: Object.freeze({ "sev-snp-guest-domain-v1": async () => ({ ok: false, reason: "SNP verifier: not SNP evidence" }) }), shield, log: () => {} });
  return { custodian, encKeyHex, label, bundle, g, shield };
}

// the host's TPM session at this custodian (the node's real frame builder over a synthetic TPM)
export function fakeTpm(w, { idksOf = w } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shield-custody-tpm-"));
  const L = buildLog({ idksPub: idksOf.idks.publicKey });
  fs.writeFileSync(path.join(dir, "boot.log"), L.log);
  return async (cmd) => {
    const [op, a, b] = cmd.split(" ");
    if (op === "log") return { log: path.join(dir, "boot.log") };
    if (op === "activate") return { credential: hex(activateCredential(w.ek.privateKey, w.aik.name, Buffer.from(a, "hex"), Buffer.from(b, "hex"))) };
    if (op === "quote") { const Q = buildQuote({ aikPriv: w.aik.privateKey, aikName: w.aik.name, pcrs: L.pcrs, pcr0: w.pcr0, extraData: Buffer.from(a, "hex") });
                          return { attest: hex(Q.attest), sig: hex(Q.sig), "aik-pub": hex(w.aik.tpmtPublic) }; }
    if (op === "pcr") return { pcr: "sha256 " + hex(w.pcr0) };
    if (op === "keys") return { "ek-cert": hex(w.ek.cert), "aik-pub": hex(w.aik.tpmtPublic), "aik-name": hex(w.aik.name) };
    throw new Error("tpm: " + cmd);
  };
}
export async function hostSession(r, { w = world, signer = operator, endpoint = ENDPOINT, idksOf = w } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }), hostChallenge = randomBytes(32).toString("hex"), hostId = keccak256(toBytes(endpoint));
  const ch = await r.custodian.shieldChallenge({ hostId, endpoint, hostChallenge, keys: { ek: b64(w.ek.cert), ekChain: [], aikPub: b64(w.aik.tpmtPublic), aikName: b64(w.aik.name) } });
  const nonce = Buffer.from(ch.nonce, "base64");
  const frame = await buildHvNodeFrame({ nonce, credentialBlob: Buffer.from(ch.credentialBlob, "base64"), secret: Buffer.from(ch.secret, "base64"),
    spki, privateKey, tpm: fakeTpm(w, { idksOf }) });
  const operatorSig = await signer.signMessage({ message: attachMessage({ verifier: ch.party, hostId, endpoint, nonce: hex(nonce),
    transportKeySha256: hex(sha(spki)), ekCertSha256: hex(sha(w.ek.cert)), hostChallenge }) });
  return r.custodian.shieldAttest({ session: ch.session, rad: frame.rad, operatorSig });
}

// the guest: its own recipient key R, its TLS key, and the monitor's VBS report over shieldReleaseInput || AppID
export function vbsReport(input, { signer, image = IMAGE }) {
  const claims = Buffer.from(JSON.stringify({ "user-data": input.toString("hex") })), env = Buffer.alloc(1236 + claims.length);
  const w32 = (o, n) => env.writeUInt32LE(n, o);
  w32(0, 0x414c4348); w32(4, 2); w32(8, env.length); w32(12, 2); w32(1216, 20 + claims.length); w32(1220, 1); w32(1224, 1); w32(1228, 1); w32(1232, claims.length); claims.copy(env, 1236);
  const rr = env.subarray(32, 592); [560, 1, 1, 256, 0, 2].forEach((n, i) => rr.writeUInt32LE(n, i * 4)); sha(claims).copy(rr, 24); Buffer.from(image, "hex").copy(rr, 120);
  rr.writeUInt32LE(5, 216); rr.writeUInt32LE(0, 220); rr.writeUInt32LE(2, 224); rr.writeUInt32LE(0, 228);
  sign("sha256", rr.subarray(0, 304), { key: signer, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).copy(rr, 304);
  return env;
}
export async function request(r, { owner = OWNER, app = APP, docApp = app, runtime = RUNTIME, image = IMAGE, signer = world.idks.privateKey, endpoint = ENDPOINT,
                            format = SHIELD_EVIDENCE_FORMAT, tier = "T0-hv", bendBinding = false, opSigner = operator, nonceField } = {}) {
  const recipient = hpke.generateKeyPair();
  const tls = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ type: "spki", format: "der" });
  const ch = r.custodian.challenge({ client: "guest" });
  const challenges = [{ encKey: Buffer.from(ch.encKey, "hex"), nonce: Buffer.from(ch.nonce, "hex") }];
  const binding = v2.releaseBinding({ chainId: CHAIN, vault: VAULT, id: DEP, policyRev: 1n, secretRev: 1n, committeeId: COMMITTEE, epoch: 1, challenges,
    runtimeId: new Uint8Array(runtimeId(runtime)), transportSpki: new Uint8Array(tls), recipientKey: recipient.publicKey });
  const input = shieldReleaseInput({ binding: bendBinding ? randomBytes(32) : binding, owner });
  const doc = { abi: "enclave-domain-abi/2", format, tier, transportKey: b64(tls), appSha256: docApp, runtime, ...(nonceField ? { nonce: nonceField } : {}),
                report: b64(Buffer.from(JSON.stringify({ format, signed: "launcher", vbsVmReport: b64(vbsReport(Buffer.concat([input, Buffer.from(app, "hex")]), { signer, image })) }))) };
  const expiry = Math.floor(Date.now() / 1000) + 120;
  const sig = await opSigner.signMessage({ message: v2.operatorMessage({ chainId: CHAIN, vault: VAULT, id: DEP, endpoint, binding, expiry }) });
  return { req: { v: 2, id: DEP, endpoint, committeeId: COMMITTEE, policyRev: "1", secretRev: "1", epoch: 1, recipientKey: hex(recipient.publicKey),
                  challenges: [{ encKey: ch.encKey, nonce: ch.nonce }], operator: { expiry, sig }, evidence: doc }, recipient, binding };
}
