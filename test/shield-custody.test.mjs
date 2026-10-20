// custody-v2 recipient evidence for an Enclave Shield partition (custody/v2/shield-evidence.mjs, shield-rules.mjs, and the
// opt-in hooks in custody/v2/custodian.mjs): end to end in memory. A real committee key and share (v2 genesis), a real
// owner bundle with its label proof, the REAL custodian decide(), a host TPM session the custodian challenged itself
// (synthetic TPM world through the node's real frame builder), and a guest VBS report over shieldReleaseInput || AppID.
// The recipient key R is the guest's; the custodian's answer is HPKE-sealed to it and opens to the owner's values ONLY there.
// Then every refusal: no adapter, no owner-committed Shield rules (SNP or default rules), the acknowledgement missing,
// a forged or changed binding, wrong owner, runtime, image or app, another host's session, a stale or foreign session -
// and the SNP path unchanged.   Needs openssl.   run: node --test test/shield-custody.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { keccak256, toBytes } from "viem";
import * as v2 from "../custody/v2/protocol.mjs";
import * as hpke from "../custody/hpke.mjs";
import { createCustodianV2 } from "../custody/v2/custodian.mjs";
import { createShieldCustody, shieldReleaseInput } from "../custody/v2/shield-evidence.mjs";
import { parseShieldRules } from "../custody/v2/shield-rules.mjs";
import { canonicalRules, parseRules } from "../custody/rules.mjs";
import { options, world, other, hex, b64, APP, RUNTIME, RID, CHAIN, VAULT, DEP, COMMITTEE, ENDPOINT, OTHER_ENDPOINT, OWNER, NEW_OWNER,
         operator, stranger, SECRETS, shieldRules, snpRules, rig, fakeTpm, hostSession, request } from "./helpers/shield-custody-rig.mjs";

// the literal the Go guest pins (isolation/m2/custody/shield_test.go TestShieldReleaseInputMatchesTheCustodian): the two
// implementations of input[0:32] must never drift
test("shieldReleaseInput matches the Go guest's vector byte for byte", () => {
  assert.equal(hex(shieldReleaseInput({ binding: Buffer.alloc(32, 0xab), owner: "0x" + "33".repeat(20) })),
               "4e01ef1a9ae8565737835fb7577a968701ce4492461eb812164a7c2eb8eefd53");
  assert.equal(hex(shieldReleaseInput({ binding: Buffer.alloc(32, 0xab), owner: "0x" + "33".repeat(20) })),
               hex(shieldReleaseInput({ binding: Buffer.alloc(32, 0xab), owner: "0X" + "33".repeat(20) })), "the owner is case-folded, as in Go");
  assert.throws(() => shieldReleaseInput({ binding: Buffer.alloc(31), owner: "0x" + "33".repeat(20) }), /32 bytes/);
  assert.throws(() => shieldReleaseInput({ binding: Buffer.alloc(32), owner: "0x" + "00".repeat(20) }), /nonzero/);
});

test("a Shield recipient under owner-committed Shield rules: the custodian releases, and only the guest's R opens the owner's values", options, async () => {
  const r = rig();
  const s = await hostSession(r);
  assert.equal(s.tier, "hv-node"); assert.equal(s.hostExcluded, false);
  const { req, recipient, binding } = await request(r);
  const out = await r.custodian.release(req);
  assert.equal(out.count, 1);
  // the guest's side: open, verify every DLEQ proof against the committee commitments, combine, decrypt
  const recs = v2.openPartials({ recipientPrivate: recipient.privateKey, binding, encKey: Buffer.from(r.encKeyHex, "hex"), count: out.count, sealed: Buffer.from(out.sealed, "base64") });
  const R = v2.parseBundle(r.bundle).R;
  const verified = recs.map((record) => v2.verifyPartial({ record, R, binding, commitments: [Buffer.from(r.g.commitments[0])] }));
  const S = v2.combine(verified, 1);
  assert.deepEqual(v2.decryptBundle({ S, label: r.label, bundle: r.bundle }).env, SECRETS);
  // anyone else (the host included) holds only ciphertext
  assert.throws(() => v2.openPartials({ recipientPrivate: hpke.generateKeyPair().privateKey, binding, encKey: Buffer.from(r.encKeyHex, "hex"), count: 1, sealed: Buffer.from(out.sealed, "base64") }));
});

test("no weaker tier without the owner's explicit Shield rules, and none without the custodian operator's adapter", options, async () => {
  const refusedWith = async (r, opts, code, re) => {
    await assert.rejects(r.custodian.release((await request(r, opts)).req), (e) => { assert.equal(e.code, code, e.message); if (re) assert.match(e.message, re); return true; });
  };
  // default/SNP rules: the Shield parser refuses them (and the SNP parser refuses the Shield platform by name)
  const snp = rig({ rules: canonicalRules(snpRules()) });
  await hostSession(snp);
  await refusedWith(snp, {}, "bad_rules", /do not admit an Enclave Shield recipient/);
  assert.throws(() => parseRules(JSON.stringify(shieldRules())), /unknown key/);
  assert.throws(() => parseRules(JSON.stringify({ ...snpRules(), images: [{ platform: "shield", measurement: "ab".repeat(48), runtimeId: hex(RID) }] })), /not a TEE against its operator/);
  // Shield rules without the exact acknowledgement never parse
  for (const bad of [{ acceptTier: "yes" }, { acceptTier: undefined }, { format: "x" }, { platforms: "any" }, { images: [] }, { extra: 1 }])
    assert.throws(() => parseShieldRules(JSON.stringify(shieldRules(bad))));
  // no adapter: a Shield document is just an unsupported format, exactly as before
  const plain = rig({ withShield: false });
  await refusedWith(plain, {}, "bad_rules");               // Shield rules do not parse as SNP rules on a custodian without the adapter
  const plainSnp = rig({ withShield: false, rules: canonicalRules(snpRules()) });
  await refusedWith(plainSnp, {}, "unsupported_evidence", /not one this custodian verifies/); // with SNP rules: the answer it always gave
});

test("forged or changed bindings, wrong owner, runtime, image or app, another boot's report: each refused", options, async () => {
  const r = rig();
  await hostSession(r);
  const refused = async (opts, code, re) => {
    await assert.rejects(r.custodian.release((await request(r, opts)).req), (e) => { assert.equal(e.code, code, e.message); if (re) assert.match(e.message, re); return true; });
  };
  await refused({ bendBinding: true }, "evidence_refused");
  await refused({ owner: NEW_OWNER }, "evidence_refused");                         // a report binding another owner than the ledger's
  await refused({ runtime: { ...RUNTIME, version: "49.0.0" } }, "runtime_not_admitted");
  await refused({ image: "ef".repeat(32) }, "evidence_refused");
  await refused({ app: "ee".repeat(32), docApp: APP }, "evidence_refused");         // the monitor's AppID is another app's
  await refused({ docApp: "ee".repeat(32) }, "evidence_refused", /another app/);
  await refused({ signer: other.idks.privateKey }, "evidence_refused");             // a report no session's IDKS signed
  await refused({ tier: "T1" }, "evidence_refused", /T0-hv/);
  await refused({ nonceField: "00".repeat(32) }, "evidence_refused", /must not state a nonce/);
  await refused({ opSigner: stranger }, "operator_sig");
});

test("two apps never interchange, and a host session counts only for the lease holder's own operator and endpoint", options, async () => {
  // app B's release cannot use app A's report (the rules name one AppID; the report's second half is the monitor's)
  const a = rig();
  await hostSession(a);
  await assert.rejects(a.custodian.release((await request(a, { app: "ce".repeat(32), docApp: "ce".repeat(32) })).req), /another app/);
  // a session made by another key than the registered operator of the lease holder
  const s1 = rig();
  await hostSession(s1, { signer: stranger });
  await assert.rejects(s1.custodian.release((await request(s1)).req), (e) => e.code === "evidence_refused" && /registered operator/.test(e.message));
  // a session for another host's endpoint does not cover this release
  const s2 = rig();
  await hostSession(s2, { endpoint: OTHER_ENDPOINT });
  await assert.rejects(s2.custodian.release((await request(s2)).req), (e) => e.code === "evidence_refused" && /no live Shield host session/.test(e.message));
  // a TPM chaining to roots this custodian does not pin: refused at the challenge, before any pending slot or credential
  const s3 = rig({ roots: other });
  await assert.rejects(hostSession(s3), (e) => e.status === 403 && /does not chain to a pinned TPM root/.test(e.message));
  // no session at all
  const s4 = rig();
  await assert.rejects(s4.custodian.release((await request(s4)).req), (e) => e.code === "evidence_refused" && /no live Shield host session/.test(e.message));
  // the lease moved to another runner: refused before evidence, as for SNP
  const s5 = rig({ runner: OTHER_ENDPOINT });
  await hostSession(s5);
  await assert.rejects(s5.custodian.release((await request(s5)).req), (e) => e.code === "not_lease_holder");
  // the ledger owner changed: refused before evidence, as for SNP
  const s6 = rig({ beneficialOwner: NEW_OWNER });
  await hostSession(s6);
  await assert.rejects(s6.custodian.release((await request(s6)).req), (e) => e.code === "owner_mismatch");
});

test("the SNP path is untouched: an SNP document under SNP rules still reaches only the SNP verifier", options, async () => {
  const seen = [];
  const g = v2.genesis(), kp = hpke.generateKeyPair();
  const label = v2.labelOf({ chainId: CHAIN, vault: VAULT, id: DEP, secretRev: 1n, committeeId: COMMITTEE });
  const bundle = v2.encryptBundle({ Y: g.Y, label, env: SECRETS, configSha256: "00".repeat(32) });
  const custodian = createCustodianV2({ chainId: CHAIN, vault: VAULT, encPrivateKey: kp.privateKey, shares: { get: () => g.shares },
    chain: { readRelease: async () => ({ blockNumber: 1n, blockTimestamp: Math.floor(Date.now() / 1000),
      policy: { owner: OWNER, policyRev: 1n, secretRev: 1n, committeeId: COMMITTEE, paused: false, rules: canonicalRules(snpRules()) },
      bundle: { committeeId: COMMITTEE, secretRev: 1n, data: bundle }, committee: { epoch: 1, machines: [{ encKey: "0x" + hex(kp.publicKey) }], commitments: Buffer.from(g.commitments[0]) },
      beneficialOwner: OWNER, lease: { runner: keccak256(toBytes(ENDPOINT)).toLowerCase(), leaseUntil: Math.floor(Date.now() / 1000) + 3600 },
      endpointId: keccak256(toBytes(ENDPOINT)).toLowerCase(), endpointOperator: operator.address.toLowerCase() }) },
    verifiers: { "sev-snp-guest-domain-v1": async (args) => { seen.push(Object.keys(args).sort()); return { ok: true, measurement: "ab".repeat(48) }; } },
    shield: createShieldCustody({ party: hex(kp.publicKey), ekRoots: world.ca.bundlePem }), log: () => {} });
  const r = { custodian };
  const { req } = await request(r, { format: "sev-snp-guest-domain-v1" });
  const out = await custodian.release(req);
  assert.equal(out.count, 1);
  assert.deepEqual(seen, [["allowedMeasurements", "appId", "binding", "doc", "hostData", "minTcb", "vmpl"]], "the SNP verifier gets exactly its old arguments");
});

test("over HTTP: the node's session client (shield-sessions.mjs) attests its TPM boot at a custodian by its committee key, then the release passes", options, async () => {
  const http = await import("node:http");
  const { createResponderSessions, custodianTargets } = await import("../windows/node/shield-sessions.mjs");
  const r = rig();
  // a bare route table over the adapter (the measured daemon's own router: test/custody-v2-shield-daemon.test.mjs)
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const route = { "/v2/custody/shield-session/challenge": r.custodian.shieldChallenge, "/v2/custody/shield-session/attest": r.custodian.shieldAttest }[req.url];
    try { const out = await route(JSON.parse(Buffer.concat(chunks).toString() || "{}")); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(out)); }
    catch (e) { res.writeHead(e.status || 500, { "content-type": "application/json" }); res.end(JSON.stringify({ error: e.message })); }
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.deepEqual(custodianTargets([{ endpoint: "https://c1.example/", encKey: "0x" + r.encKeyHex }, { endpoint: "https://c1.example", encKey: r.encKeyHex },
                                       { endpoint: "http://c2.example", encKey: r.encKeyHex }, { endpoint: "https://c3.example", encKey: "zz" }]),
      [{ url: "https://c1.example", party: r.encKeyHex, path: "/v2/custody/shield-session" }]);
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const client = createResponderSessions({ hostId: keccak256(toBytes(ENDPOINT)), endpoint: ENDPOINT, nodeKey: { privateKey, spki: publicKey.export({ type: "spki", format: "der" }) },
      tpm: fakeTpm(world), keysFrame: async () => ({ ek: b64(world.ek.cert), ekChain: [], aikPub: b64(world.aik.tpmtPublic), aikName: b64(world.aik.name) }),
      sign: (message) => operator.signMessage({ message }) });
    const wrong = await client.refresh([{ url, party: "11".repeat(32), path: "/v2/custody/shield-session" }]);
    assert.match(wrong.failed[0], /another party than its committee key/);
    const ok = await client.refresh([{ url, party: r.encKeyHex, path: "/v2/custody/shield-session" }]);
    assert.deepEqual(ok.done, [url], ok.failed.join("; "));
    assert.equal((await r.custodian.release((await request(r)).req)).count, 1);
  } finally { server.close(); }
});

// Review finding F2 (2026-10-20), fixed: for a deployment owned through a session vault, the ledger row's owner is the vault
// contract and EnclaveSecretVaultV2.beneficialOwnerOf() (= the policy owner) is the vault's human owner. The Shield-direct
// guest binds the LEDGER owner its own quorum reads (isolation/m2/front shield_direct_custody.go: auth.NameGrant().Owner); the
// custodian now binds the same (custodian.mjs passes s.lease.owner), and still AUTHORIZES by the policy owner (step 6:
// beneficialOwnerOf(id) === pol.owner). Each of the two checks is exercised alone below.
test("session-vault owner: the report binds the ledger owner, the policy is still authorized by the beneficial owner", options, async () => {
  const SESSION_VAULT = "0x" + "5e".repeat(20), OTHER_VAULT = "0x" + "5f".repeat(20);
  // the guest's binding names the ledger owner (the vault contract): released, and only the guest's R opens the values
  const r = rig({ owner: OWNER, beneficialOwner: OWNER, ledgerOwner: SESSION_VAULT });
  await hostSession(r);
  const { req, recipient, binding } = await request(r, { owner: SESSION_VAULT });
  const out = await r.custodian.release(req);
  assert.equal(out.count, 1);
  const recs = v2.openPartials({ recipientPrivate: recipient.privateKey, binding, encKey: Buffer.from(r.encKeyHex, "hex"), count: out.count, sealed: Buffer.from(out.sealed, "base64") });
  const S = v2.combine(recs.map((record) => v2.verifyPartial({ record, R: v2.parseBundle(r.bundle).R, binding, commitments: [Buffer.from(r.g.commitments[0])] })), 1);
  assert.deepEqual(v2.decryptBundle({ S, label: r.label, bundle: r.bundle }).env, SECRETS);
  // a report binding any OTHER owner is refused at the evidence: the beneficial/policy owner, another vault, a stranger
  for (const owner of [OWNER, OTHER_VAULT, NEW_OWNER]) {
    const x = rig({ owner: OWNER, beneficialOwner: OWNER, ledgerOwner: SESSION_VAULT });
    await hostSession(x);
    await assert.rejects(x.custodian.release((await request(x, { owner })).req),
      (e) => e.code === "evidence_refused" && /guest binding differs/.test(e.message), `a report binding ${owner} was accepted`);
  }
  // the policy authorization is unchanged: a vault whose beneficial owner is no longer the policy owner is refused before
  // any evidence, even with the ledger owner bound exactly
  const moved = rig({ owner: OWNER, beneficialOwner: NEW_OWNER, ledgerOwner: SESSION_VAULT });
  await hostSession(moved);
  await assert.rejects(moved.custodian.release((await request(moved, { owner: SESSION_VAULT })).req), (e) => e.code === "owner_mismatch");
  // and an EOA owner (ledger = beneficial = policy) binds itself, as before
  const eoa = rig();
  await hostSession(eoa);
  assert.equal((await eoa.custodian.release((await request(eoa, { owner: OWNER })).req)).count, 1);
});
