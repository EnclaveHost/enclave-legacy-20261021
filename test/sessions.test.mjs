// Sessions end to end on a local chain: the SDK (sdk/sessions, built) drives the
// REAL relayer (relay/sessions.mjs) over HTTP, which submits to the REAL
// SessionVault deployed by scripts/deploy-session-vault.mjs, against the REAL
// ledger, catalog and PaymentRouter. Skips when Foundry (anvil/forge) is absent.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { createWalletClient, http as viemHttp, parseUnits, decodeFunctionData, encodeFunctionData, parseEventLogs } from "viem";
import { foundry } from "viem/chains";
import { haveFoundry, startChain, deployPlatform, KEYS } from "./helpers/sessions-chain.mjs";
import { createSessionsService, createCustodyGate, sessionRowRefusal, codeHasDelegation, delegateSlot } from "../relay/sessions.mjs";
import { JsonStore } from "../relay/store.js";
import * as sdk from "../sdk/sessions/dist/node.mjs";

const skip = !haveFoundry() || !fs.existsSync(new URL("../sdk/sessions/dist/node.mjs", import.meta.url))
  ? "needs Foundry (anvil + forge) and a built SDK (cd sdk/sessions && npm run build)" : false;

let chain, P, svc, server, relayUrl, tmp, stores = [];
const owner = privateKeyToAccount(KEYS.owner);
const ownerSigner = { address: owner.address, signTypedData: (td) => owner.signTypedData(td) };

before(async () => {
  if (skip) return;
  chain = await startChain();
  P = await deployPlatform(chain);
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sessions-relay-"));
  const relayer = privateKeyToAccount(KEYS.relayer);
  svc = createSessionsService({
    pc: chain.pc, wc: createWalletClient({ chain: foundry, account: relayer, transport: viemHttp(chain.rpc) }),
    account: relayer, chainId: 31337, factory: P.factory, book: P.book, usdc: P.usdc, router: P.router,
    startBlock: P.deployBlock, ethUsd: 3000, minFee6: 500, now: chain.now,
    // Base today: ~0.005 gwei base + 0.001 gwei tip (anvil suggests a 1 gwei tip, 1000x Base)
    feesPerGas: async () => ({ maxFeePerGas: 7_000_000n, maxPriorityFeePerGas: 1_000_000n }),
    store: (stores[0] = new JsonStore(path.join(tmp, "idx.json"), {})),
    journal: (stores[1] = new JsonStore(path.join(tmp, "j.json"), { txs: [] }, { durable: true })),
    log: (...a) => { if (process.env.SESSIONS_TEST_LOG) console.log("[relay]", ...a); }, alert: (k, d) => { alerts.push([k, d]); },
  });
  server = http.createServer((req, res) => {
    const u = new URL(req.url, "http://relay.test");
    if (u.pathname.startsWith("/v1/sessions")) return svc.handle(req, res, u, null);
    res.writeHead(404).end();
  });
  await new Promise((r) => server.listen(0, r));
  relayUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  if (process.env.SESSIONS_TEST_LOG && stores[1])
    for (const t of stores[1].data.txs) console.log("gas", t.label.replace(/ 0x[0-9a-f]+/, ""), t.gasUsed);
  for (const st of stores) clearInterval(st._timer);
  server?.close(); chain?.stop();
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});
const alerts = [];

test("relay-free session: fresh owner grant, independent gas payer, replay and scope enforcement, refund", { skip }, async () => {
  let httpCalls = 0;
  const deniedFetch = async () => { httpCalls++; throw new Error("Enclave refuses service"); };
  const signer = await sdk.signerFromKeyPair(await sdk.generateKeyPair(false));
  const grant = sdk.buildGrant({ sessionKey: signer.keyHash, label: "independent submission", preset: "staging-publish",
    policy: { apps: ["relay-free"], budget: parseUnits("3", 6) } });
  const before = await usdcBal(owner.address);
  const prepared = await sdk.prepareSessionOpen({ publicClient: chain.pc, factory: P.factory,
    owner: ownerSigner, chainId: 31337, grant, usdc: await sdk.usdcDomain(chain.pc, P.usdc, 31337) });
  const broadcast = async ({ to, data, value }) => {
    const hash = await chain.wc(KEYS.stranger).sendTransaction({ to, data, value });
    const receipt = await chain.pc.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, "success");
    return receipt;
  };
  await broadcast(prepared);
  const session = new sdk.Session({ chainId: 31337, vault: prepared.vault, sid: prepared.sid, relay: "https://refused.invalid" },
    signer, { publicClient: chain.pc, fetch: deniedFetch });
  assert.equal((await session.status()).balance6, parseUnits("3", 6));
  await assert.rejects(session.prepareCall("app.publish", {}, { lane: 1n << 192n }), /uint192/);
  await assert.rejects(session.prepareTermination({ deadlineSeconds: 0 }), /deadlineSeconds/);
  const wrongChain = new sdk.Session({ ...session.handle, chainId: 8453 }, signer, { publicClient: chain.pc, fetch: deniedFetch });
  await assert.rejects(wrongChain.prepareTermination(), /chain does not match/);
  const pub = await session.prepareCall("app.publish", { slug: "relay-free", name: "Independent", description: "",
    version: "1.0.0", cid: "bafyrelayfree", res: [0, 0, 256, 10], ports: "", config: "{}", configCid: "" }, { lane: 7n });
  // A gas payer cannot turn the zero fee into a charge or change the signed action.
  const decoded = decodeFunctionData({ abi: sdk.sessionVaultAbi, data: pub.data });
  const changed = [...decoded.args]; changed[4] = 1n;
  await assert.rejects(chain.pc.call({ to: pub.to, data: encodeFunctionData({ abi: sdk.sessionVaultAbi,
    functionName: "execute", args: changed }) }));
  const pubReceipt = await broadcast(pub);
  assert.equal(parseEventLogs({ abi: sdk.sessionVaultAbi, logs: pubReceipt.logs, eventName: "SessionOp" })[0].args.fee6, 0n);
  await assert.rejects(chain.pc.call({ to: pub.to, data: pub.data }), "replay must fail on chain");
  const appId = await chain.pc.readContract({ address: P.catalog, abi: P.abi.catalog.abi,
    functionName: "appIdOf", args: [prepared.vault, "relay-free"] });
  const args = { appRef: `catalog://${appId}/0`, gpuMilli: 0, cpuMilli: 1000, appPort: 8080, ports: "",
    isPublic: false, configCid: "", maxRate6: 1000n, env: "staging", fund6: parseUnits("1", 6) };
  const outOfScope = await session.prepareCall("deploy.create", { ...args, appRef: P.storeRef });
  await assert.rejects(chain.pc.call({ to: outOfScope.to, data: outOfScope.data }), "app policy must survive relay refusal");
  await assert.rejects(session.prepareCall("deploy.create", { ...args, fund6: parseUnits("4", 6) }), e => e.code === "budget");
  const created = await broadcast(await session.prepareCall("deploy.create", args));
  const result = parseEventLogs({ abi: sdk.sessionVaultAbi, logs: created.logs, eventName: "SessionOp" })[0].args.result;
  const row = await chain.pc.readContract({ address: P.ledger, abi: P.abi.ledger.abi,
    functionName: "get", args: [`0x${result.slice(2, 66)}`] });
  assert.equal(row.owner.toLowerCase(), prepared.vault.toLowerCase());
  assert.equal(row.balance6, parseUnits("1", 6));
  await broadcast(await session.prepareTermination());
  assert.equal((await session.status()).live, false);
  assert.equal(await usdcBal(owner.address), before - parseUnits("1", 6));
  assert.equal(httpCalls, 0, "opening, executing and refunding use no relay requests");
});

test("relay-free zero-budget grant: owner revocation invalidates already signed calldata", { skip }, async () => {
  const signer = await sdk.signerFromKeyPair(await sdk.generateKeyPair(false));
  const grant = sdk.buildGrant({ sessionKey: signer.keyHash, label: "revocable direct intent", preset: "staging-publish",
    policy: { apps: ["revocable-direct"], budget: 0n } });
  const prepared = await sdk.prepareSessionOpen({ publicClient: chain.pc, factory: P.factory,
    owner: ownerSigner, chainId: 31337, grant });
  const sent = await chain.wc(KEYS.stranger).sendTransaction({ to: prepared.to, data: prepared.data, value: prepared.value });
  assert.equal((await chain.pc.waitForTransactionReceipt({ hash: sent })).status, "success");
  const session = new sdk.Session({ chainId: 31337, vault: prepared.vault, sid: prepared.sid, relay: "https://refused.invalid" },
    signer, { publicClient: chain.pc, fetch: async () => { throw new Error("relay unavailable"); } });
  const pending = await session.prepareCall("app.publish", { slug: "revocable-direct", name: "Revocable", description: "",
    version: "1.0.0", cid: "bafyrevocable", res: [0, 0, 256, 10], ports: "", config: "{}", configCid: "" });
  await chain.pc.call({ to: pending.to, data: pending.data });
  const revoked = await chain.wc(KEYS.owner).writeContract({ address: prepared.vault, abi: sdk.sessionVaultAbi,
    functionName: "revokeAll", args: [true, `0x${"00".repeat(32)}`, 0n, "0x"] });
  assert.equal((await chain.pc.waitForTransactionReceipt({ hash: revoked })).status, "success");
  await assert.rejects(chain.pc.call({ to: pending.to, data: pending.data }));
  assert.equal((await session.status()).live, false);
});

const usdcBal = async (a) => chain.pc.readContract({ address: P.usdc, abi: P.abi.usdc.abi, functionName: "balanceOf", args: [a] });

async function openFor(preset, { apps, budget = 0n, expiresIn, label = "test" } = {}) {
  const store = new sdk.MemoryStore();
  const { signer, record } = await sdk.newSessionKey(store, { relay: relayUrl, chainId: 31337, label, extractable: true });
  const grant = sdk.buildGrant({ sessionKey: signer.keyHash, label, preset,
    policy: { ...(apps ? { apps } : {}), budget, ...(expiresIn ? { expiresIn } : {}) } });
  const relay = new sdk.RelayClient(relayUrl);
  const vault = await sdk.vaultAddress(chain.pc, P.factory, owner.address);
  const usdc = budget > 0n ? await sdk.usdcDomain(chain.pc, P.usdc, 31337) : undefined;
  const out = await sdk.openSession({ relay, owner: ownerSigner, chainId: 31337, vault, grant, usdc });
  const rec = await sdk.completeSession(store, record, { vault, owner: owner.address, grant, rpc: chain.rpc });
  const session = await sdk.sessionFromRecord(rec);
  return { session, grant, vault, sid: out.sid, store, relay, signer };
}

test("agent staging-publish flow: publish, deploy to staging, re-point, sign out with refund", { skip }, async () => {
  const before = await usdcBal(owner.address);
  const { session, vault, sid } = await openFor("staging-publish", { apps: ["mine-staging"], budget: parseUnits("10", 6), label: "Claude Code" });
  assert.equal(await usdcBal(vault), parseUnits("10", 6));
  const st = await session.status();
  assert.equal(st.live, true);
  assert.equal(st.envs, 1);

  const pub = await session.call("app.publish", { slug: "mine-staging", name: "Mine (staging)", description: "",
    version: "0.1.0", cid: "bafymine1", res: [0, 0, 256, 10], ports: "", config: "{}", configCid: "" });
  assert.match(pub.txHash, /^0x[0-9a-f]{64}$/);
  const appId = await chain.pc.readContract({ address: P.catalog, abi: P.abi.catalog.abi, functionName: "appIdOf", args: [vault, "mine-staging"] });
  const ref0 = `catalog://${appId}/0`;

  const created = await session.call("deploy.create", { appRef: ref0, gpuMilli: 0, cpuMilli: 1000, appPort: 8080, ports: "",
    isPublic: false, configCid: "", maxRate6: 1000n, env: "staging", fund6: parseUnits("2", 6) });
  const id = `0x${created.result.slice(2, 66)}`;
  const d = await chain.pc.readContract({ address: P.ledger, abi: P.abi.ledger.abi, functionName: "get", args: [id] });
  assert.equal(d.owner, vault);
  assert.equal(d.appRef, ref0);

  await session.call("app.publish", { slug: "mine-staging", name: "Mine (staging)", description: "", version: "0.1.1",
    cid: "bafymine2", res: [0, 0, 256, 10], ports: "", config: "{}", configCid: "" });
  await session.call("deploy.setAppRef", { id, appRef: `catalog://${appId}/1` });
  const d2 = await chain.pc.readContract({ address: P.ledger, abi: P.abi.ledger.abi, functionName: "get", args: [id] });
  assert.equal(d2.appRef, `catalog://${appId}/1`);

  // outside the preset: the session can't touch the store app, prod, or pay orders
  await assert.rejects(session.call("deploy.setShares", { id, gpuMilli: 0, cpuMilli: 500 }), (e) => e.code === "not_allowed");
  await assert.rejects(session.call("deploy.create", { appRef: P.storeRef, gpuMilli: 0, cpuMilli: 1000, appPort: 8080, ports: "",
    isPublic: false, configCid: "", maxRate6: 1000n, env: "staging", fund6: 0n }), (e) => e.code === "app");

  const spent = (await session.status()).spent6;
  const res = await session.terminate();
  assert.equal(res.refund6, parseUnits("10", 6) - spent);
  assert.equal(await usdcBal(owner.address), before - spent);
  assert.equal((await session.status()).live, false);
  // the index saw all of it
  await svc.indexOnce();
  const byKey = await new sdk.RelayClient(relayUrl).request("GET", `/by-key/${session.signer.keyHash}`);
  assert.equal(byKey.sessions[0].sid, sid);
  assert.equal(byKey.sessions[0].ended, true);
});

test("browser flow: zero-budget sign-in, wallet top-up, spend, promote, revoke-all", { skip }, async () => {
  const { session, vault, sid, relay } = await openFor("browser", { label: "this browser", expiresIn: 3600 });
  assert.equal((await session.status()).balance6, 0n);
  // spending with no budget fails up front with a code the UI turns into "Top up"
  const mkArgs = (fund6, env = "staging") => ({ appRef: P.storeRef, gpuMilli: 0, cpuMilli: 1000, appPort: 8080, ports: "",
    isPublic: false, configCid: "", maxRate6: 1000n, env, fund6 });
  await assert.rejects(session.call("deploy.create", mkArgs(parseUnits("1", 6))), (e) => e.code === "budget");
  const usdc = await sdk.usdcDomain(chain.pc, P.usdc, 31337);
  await sdk.topUpFromWallet({ relay, owner: ownerSigner, chainId: 31337, vault, sessionId: sid, amount: parseUnits("5", 6), usdc });
  assert.equal((await session.status()).balance6, parseUnits("5", 6));
  const t0 = await usdcBal(P.treasury);
  const made = await session.call("deploy.create", mkArgs(parseUnits("1", 6)));
  const sid0 = `0x${made.result.slice(2, 66)}`;
  const row0 = await chain.pc.readContract({ address: P.ledger, abi: P.abi.ledger.abi, functionName: "get", args: [sid0] });
  assert.equal(row0.balance6, parseUnits("1", 6), "the funding reached the deployment");
  assert.ok(await usdcBal(P.treasury) >= t0 + made.fee, "the relay fee reached the treasury");
  // a top-up and a resize of the (unleased) record, through the relay
  await session.call("deploy.fund", { id: sid0, amount6: parseUnits("0.5", 6) });
  await session.call("deploy.setShares", { id: sid0, gpuMilli: 0, cpuMilli: 500 });
  const row1 = await chain.pc.readContract({ address: P.ledger, abi: P.abi.ledger.abi, functionName: "get", args: [sid0] });
  assert.equal(row1.balance6, parseUnits("1.5", 6));
  assert.equal(row1.cpuMilli, 500);

  // a prod deployment created by the session, then promoted by the owner
  const c = await session.call("deploy.create", { appRef: P.storeRef, gpuMilli: 0, cpuMilli: 1000, appPort: 8080, ports: "",
    isPublic: true, configCid: "", maxRate6: 1000n, env: "prod", fund6: 0n });
  const id = `0x${c.result.slice(2, 66)}`;
  let held = await chain.pc.readContract({ address: vault, abi: sdk.sessionVaultAbi, functionName: "held", args: [id] });
  assert.equal(held[0], 2);
  assert.equal(held[1], "0x" + "00".repeat(32), "unpromoted until the owner says so");
  // the session cannot re-point prod
  await assert.rejects(session.call("deploy.setAppRef", { id, appRef: P.storeRef }), (e) => e.code === "env");
  // a copied slug + label under another publisher, or the wrong exposure, is refused on chain
  const promo = { op: "promote", deployment: id, app: "store", publisher: P.publisher, appRef: P.storeRef, configCid: "",
    versionLabel: "1.0.0", isPublic: true };
  await assert.rejects(sdk.ownerOperation({ relay, owner: ownerSigner, chainId: 31337, vault, op: { ...promo, publisher: owner.address } }),
    /LabelMismatch|mismatch/i);
  await assert.rejects(sdk.ownerOperation({ relay, owner: ownerSigner, chainId: 31337, vault, op: { ...promo, isPublic: false } }),
    /LabelMismatch|mismatch/i);
  await sdk.ownerOperation({ relay, owner: ownerSigner, chainId: 31337, vault, op: promo });
  held = await chain.pc.readContract({ address: vault, abi: sdk.sessionVaultAbi, functionName: "held", args: [id] });
  assert.notEqual(held[1], "0x" + "00".repeat(32));

  const before = await usdcBal(owner.address);
  const left = (await session.status()).balance6;
  await sdk.ownerOperation({ relay, owner: ownerSigner, chainId: 31337, vault, op: { op: "revokeAll", withdraw: true } });
  assert.equal((await session.status()).live, false);
  assert.ok(await usdcBal(owner.address) >= before + left);
  await assert.rejects(session.call("deploy.setActive", { id, active: false }), (e) => e.code === "not_live");
});

test("the SDK's typed-data shapes hash to the vault's typehashes", { skip }, async () => {
  const { vault } = await openFor("auth-only", { label: "pin" });
  const { keccak256, toBytes } = await import("viem");
  const NAMES = { SessionGrant: "GRANT", SessionCall: "CALL", SessionEnd: "END", TopUp: "TOPUP", Extend: "EXTEND",
    Terminate: "TERMINATE", RevokeAll: "REVOKE", Withdraw: "WITHDRAW", Promote: "PROMOTE", Adopt: "ADOPT",
    SetEnvironment: "SETENV", Release: "RELEASE" };
  assert.deepEqual(Object.keys(NAMES).sort(), Object.keys(sdk.TYPES).sort(), "every SDK type is pinned");
  for (const [t, c] of Object.entries(NAMES)) {
    const enc = `${t}(${sdk.TYPES[t].map((f) => `${f.type} ${f.name}`).join(",")})`;
    const onChain = await chain.pc.readContract({ address: vault, abi: [{ type: "function", name: `${c}_TYPEHASH`,
      stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] }], functionName: `${c}_TYPEHASH` });
    assert.equal(keccak256(toBytes(enc)), onChain, t);
  }
});

test("API request auth: valid, replayed, tampered, out of scope, signed out", { skip }, async () => {
  const { session, vault, sid, relay, signer } = await openFor("staging-publish", { apps: ["api-staging"], budget: 0n });
  const url = "https://api.enclave.host/v1/deployments/0xabc/logs?tail=10";
  const hdr = await session.apiAuthorization("GET", url);
  const ok = await svc.verifyApiRequest({ header: hdr, method: "GET", hostPath: "api.enclave.host/v1/deployments/0xabc/logs?tail=10", scope: "api.logs" });
  assert.equal(ok.owner, owner.address);
  assert.equal(ok.vault, vault);
  await assert.rejects(svc.verifyApiRequest({ header: hdr, method: "GET", hostPath: "api.enclave.host/v1/deployments/0xabc/logs?tail=10", scope: "api.logs" }),
    /replayed/);
  const h2 = await session.apiAuthorization("POST", "https://api.enclave.host/v1/upload", '{"a":1}');
  await assert.rejects(svc.verifyApiRequest({ header: h2, method: "POST", hostPath: "api.enclave.host/v1/upload", body: Buffer.from('{"a":2}'), scope: "api.upload" }),
    /bad session signature/);
  const h3 = await session.apiAuthorization("GET", "https://api.enclave.host/v1/x");
  await assert.rejects(svc.verifyApiRequest({ header: h3, method: "GET", hostPath: "api.enclave.host/v1/x", scope: "api.appAccess" }),
    /lacks api.appAccess/);
  // another key presenting this session id
  const other = await sdk.signerFromKeyPair(await sdk.generateKeyPair(false));
  const h4 = await sdk.signApiRequest(other, vault, sid, "GET", "https://api.enclave.host/v1/x");
  await assert.rejects(svc.verifyApiRequest({ header: h4, method: "GET", hostPath: "api.enclave.host/v1/x", scope: "api.status" }),
    /does not belong/);
  // sign-out revokes API access in the same flow
  await session.terminate();
  const h5 = await session.apiAuthorization("GET", "https://api.enclave.host/v1/x");
  await assert.rejects(svc.verifyApiRequest({ header: h5, method: "GET", hostPath: "api.enclave.host/v1/x", scope: "api.status" }),
    /signed out/);
  void relay; void signer;
});

test("API auth binds vault + sid, claims the replay slot first, and a revokeAll covers unindexed sessions", { skip }, async () => {
  const { session, vault, sid, relay, signer } = await openFor("staging-publish", { apps: ["bind-a"], budget: 0n });
  // a SECOND session for the same key (as an attested agent key may have)
  const grant2 = sdk.buildGrant({ sessionKey: signer.keyHash, label: "same key", preset: "staging-publish",
    policy: { apps: ["bind-b"], budget: 0n } });
  const sid2 = (await sdk.openSession({ relay, owner: ownerSigner, chainId: 31337, vault, grant: grant2 })).sid;
  const url = "https://api.enclave.host/v1/x";
  const hp = "api.enclave.host/v1/x";
  const h = await session.apiAuthorization("GET", url);
  const swapped = h.replace(`sid=${sid}`, `sid=${sid2}`);
  assert.notEqual(swapped, h);
  await assert.rejects(svc.verifyApiRequest({ header: swapped, method: "GET", hostPath: hp, scope: "api.status" }),
    /bad session signature/, "a request signed for one session never verifies under another");
  // concurrent copies of one signed request: exactly one verifies
  const h2 = await session.apiAuthorization("GET", url);
  const res = await Promise.allSettled([1, 2, 3].map(() =>
    svc.verifyApiRequest({ header: h2, method: "GET", hostPath: hp, scope: "api.status" })));
  assert.equal(res.filter((r) => r.status === "fulfilled").length, 1);
  // a revokeAll in flight refuses even a session the index has not seen; once mined, sessions
  // opened AFTER its block pass
  await svc.indexOnce();
  const r0 = svc.store.data.revokedVaults[vault];
  svc.store.data.revokedVaults[vault] = { at: Math.floor(Date.now() / 1000), block: null };
  await assert.rejects(svc.verifyApiRequest({ header: await session.apiAuthorization("GET", url), method: "GET", hostPath: hp,
    scope: "api.status" }), /revoked/);
  const opened = svc.store.data.sessions[sid].openedBlock;
  assert.ok(Number.isInteger(opened));
  svc.store.data.revokedVaults[vault] = { at: Math.floor(Date.now() / 1000), block: opened - 1 };
  const ok = await svc.verifyApiRequest({ header: await session.apiAuthorization("GET", url), method: "GET", hostPath: hp, scope: "api.status" });
  assert.equal(ok.sid, sid);
  svc.store.data.revokedVaults[vault] = { at: Math.floor(Date.now() / 1000), block: opened };
  await assert.rejects(svc.verifyApiRequest({ header: await session.apiAuthorization("GET", url), method: "GET", hostPath: hp,
    scope: "api.status" }), /revoked/);
  if (r0 === undefined) delete svc.store.data.revokedVaults[vault]; else svc.store.data.revokedVaults[vault] = r0;
  await session.terminate();
});

test("a lagging RPC node right after the open: the relay believes its own receipts and retries", { skip }, async () => {
  // what production showed on 2026-10-07: Base's public RPCs balance nodes a block or two apart, and
  // the sign-out 1.5 s after the open hit one that had no code at the new vault yet
  let behind = null, lagUntil = 0;
  const lagging = () => behind !== null && Date.now() < lagUntil;
  const pc = new Proxy(chain.pc, { get: (t, k) => {
    if (k === "readContract") return (a) => t.readContract(lagging() ? { ...a, blockNumber: behind } : a);
    if (k === "simulateContract") return (a) => t.simulateContract(lagging() ? { ...a, blockNumber: behind } : a);
    if (k === "getCode") return (a) => t.getCode(lagging() ? { ...a, blockNumber: behind } : a);
    return t[k];
  } });
  const relayer = privateKeyToAccount(KEYS.relayer);
  const st = [new JsonStore(path.join(tmp, "lag-idx.json"), {}), new JsonStore(path.join(tmp, "lag-j.json"), { txs: [] }, { durable: true })];
  const lagSvc = createSessionsService({
    pc, wc: createWalletClient({ chain: foundry, account: relayer, transport: viemHttp(chain.rpc) }),
    account: relayer, chainId: 31337, factory: P.factory, book: P.book, usdc: P.usdc, router: P.router,
    startBlock: P.deployBlock, ethUsd: 3000, minFee6: 500, now: chain.now,
    feesPerGas: async () => ({ maxFeePerGas: 7_000_000n, maxPriorityFeePerGas: 1_000_000n }),
    store: st[0], journal: st[1], log: () => {}, alert: () => {},
  });
  const srv = http.createServer((req, res) => lagSvc.handle(req, res, new URL(req.url, "http://relay.test"), null));
  await new Promise((r) => srv.listen(0, r));
  try {
    const url = `http://127.0.0.1:${srv.address().port}`;
    // a FRESH owner, so the open also creates the vault (no code anywhere before this block)
    const freshOwner = privateKeyToAccount("0x" + "5a".repeat(32));
    const signer2 = { address: freshOwner.address, signTypedData: (td) => freshOwner.signTypedData(td) };
    const store = new sdk.MemoryStore();
    const { signer, record } = await sdk.newSessionKey(store, { relay: url, chainId: 31337, label: "lag", extractable: true });
    const grant = sdk.buildGrant({ sessionKey: signer.keyHash, label: "lag", preset: "browser", policy: { budget: 0n } });
    const relay = new sdk.RelayClient(url);
    const vault = await sdk.vaultAddress(chain.pc, P.factory, freshOwner.address);
    behind = await chain.pc.getBlockNumber();
    const out = await sdk.openSession({ relay, owner: signer2, chainId: 31337, vault, grant });
    lagUntil = Date.now() + 1500;                         // every read/simulation now sees the pre-open block
    const rec = await sdk.completeSession(store, record, { vault, owner: freshOwner.address, grant, rpc: chain.rpc });
    const session = await sdk.sessionFromRecord(rec);
    const ok = await lagSvc.verifyApiRequest({ header: await session.apiAuthorization("GET", "https://api.enclave.host/v1/x"),
      method: "GET", hostPath: "api.enclave.host/v1/x", scope: "api.status", fresh: true });
    assert.equal(ok.sid, out.sid, "sign-in right after the open");
    lagUntil = Date.now() + 1500;
    await session.terminate();                            // the smoke test's failing call
    // straight after: a node still behind the sign-out must not make the relay report it live
    behind = await chain.pc.getBlockNumber() - 1n;
    lagUntil = Date.now() + 1500;
    const r = await relay.request("GET", `/session/${vault}/${out.sid}`);
    assert.equal(r.state.live, false);
    assert.equal(Number(r.state.state), 2, "the stale 'live' read was retried");
    lagUntil = 0;
    const [, live] = await chain.pc.readContract({ address: vault, abi: sdk.sessionVaultAbi, functionName: "sessionOf", args: [out.sid] });
    assert.equal(live, false);
  } finally {
    srv.close();
    for (const x of st) clearInterval(x._timer);
  }
});

test("relay maps vault reverts to typed errors and refuses unknown vaults", { skip }, async () => {
  const { session } = await openFor("staging-publish", { apps: ["e-staging"], budget: parseUnits("1", 6) });
  // bypass the SDK's pre-check: ask the relay directly to spend more than the budget
  const q = await session.relay.request("POST", "/quote", { vault: session.handle.vault, sid: session.handle.sid, action: 1, args: "0x" });
  const args = sdk.encodeArgs("deploy.fund", { id: "0x" + "12".repeat(32), amount6: parseUnits("50", 6) });
  const digest = sdk.digestOf(31337, session.handle.vault, "SessionCall", { sessionId: session.handle.sid, nonce: q.nonce, action: 1,
    argsHash: (await import("viem")).keccak256(args), fee: q.fee, deadline: q.deadline });
  const { r, s } = await session.signer.signDigest(digest);
  await assert.rejects(session.relay.request("POST", "/execute", { vault: session.handle.vault, sid: session.handle.sid, nonce: q.nonce,
    action: 1, args, fee: q.fee, deadline: q.deadline, x: session.signer.x, y: session.signer.y, r, s }),
  (e) => e instanceof sdk.SessionError && e.code === "budget");
  await assert.rejects(session.relay.request("POST", "/quote", { vault: P.ledger, sid: session.handle.sid, action: 1, args: "0x" }),
    (e) => e.code === "not_a_vault");
});

test("owner-only operations are unreachable for a session key, and the relay checks vault ownership", { skip }, async () => {
  const { vault, sid, relay } = await openFor("staging-publish", { apps: ["o-staging"], budget: 0n });
  const stranger = privateKeyToAccount(KEYS.stranger);
  const strangerSigner = { address: stranger.address, signTypedData: (td) => stranger.signTypedData(td) };
  await assert.rejects(sdk.ownerOperation({ relay, owner: strangerSigner, chainId: 31337, vault, op: { op: "withdraw", amount: 1n } }),
    (e) => e.code === "not_owner");
  // a signature from the wrong wallet presented as the owner's is refused by the vault itself
  const opNonce = "0x" + "77".repeat(32);
  const signBefore = BigInt(Math.floor(Date.now() / 1000) + 600);
  const td = sdk.typedData(31337, vault, "Terminate", { sessionId: sid, opNonce, signBefore });
  const forged = await stranger.signTypedData(td);
  await assert.rejects(relay.request("POST", "/owner", { owner: owner.address, vault, op: "terminate",
    args: { sessionId: sid, opNonce, signBefore }, sig: forged }), (e) => e.code === "signature");
});

test("secret-release custody gate: staging releases, prod only once promoted, unadopted never, wallet rows untouched", { skip }, async () => {
  const gate = createCustodyGate({ pc: chain.pc, book: P.book, ttlMs: 0 });
  const { session, vault, relay } = await openFor("browser", { budget: parseUnits("1", 6), label: "gate" });
  const mk = async (env) => {
    const c = await session.call("deploy.create", { appRef: P.storeRef, gpuMilli: 0, cpuMilli: 1000, appPort: 8080, ports: "",
      isPublic: true, configCid: "", maxRate6: 1000n, env, fund6: 0n });
    return `0x${c.result.slice(2, 66)}`;
  };
  const row = (id) => chain.pc.readContract({ address: P.ledger, abi: P.abi.ledger.abi, functionName: "get", args: [id] });
  const stg = await mk("staging");
  const prd = await mk("prod");
  assert.equal(await gate.custodyRefusal(await row(stg)), null);
  assert.match(await gate.custodyRefusal(await row(prd)), /not been promoted/);
  await sdk.ownerOperation({ relay, owner: ownerSigner, chainId: 31337, vault,
    op: { op: "promote", deployment: prd, app: "store", publisher: P.publisher, appRef: P.storeRef, configCid: "",
      versionLabel: "1.0.0", isPublic: true } });
  assert.equal(await gate.custodyRefusal(await row(prd)), null, "promoted: releases");
  const prdUnpromoted = await mk("prod");
  // a deployment gifted into the vault is inert until adopted
  const stranger = chain.wc(KEYS.stranger);
  const h = await stranger.writeContract({ address: P.ledger, abi: P.abi.ledger.abi, functionName: "create",
    args: [P.storeRef, 0, 1000, 8080, "", true, "", "0x0000000000000000000000000000000000000000", 0n, 1_000_000n] });
  const rc = await chain.pc.waitForTransactionReceipt({ hash: h });
  const gift = rc.logs.find((l) => l.address.toLowerCase() === P.ledger.toLowerCase()).topics[1];
  await chain.pc.waitForTransactionReceipt({ hash: await stranger.writeContract({ address: P.ledger, abi: P.abi.ledger.abi,
    functionName: "transferDeployment", args: [gift, vault] }) });
  assert.match(await gate.custodyRefusal(await row(gift)), /not adopted/);
  // wallet-held rows and owner resolution
  const mine = await row(gift);
  assert.equal(await gate.custodyRefusal({ ...mine, owner: owner.address }), null, "a wallet-held row passes untouched");
  assert.equal(await gate.beneficialOwner(vault), owner.address);
  assert.equal(await gate.beneficialOwner(owner.address), owner.address);
  // a relay that no longer knows the vault's factory (rotated out of the book, history unset)
  // still gates it: held() answers, so an unpromoted prod record stays refused
  const blind = createCustodyGate({ pc: chain.pc, book: null, ttlMs: 0 });
  assert.equal(await blind.vaultOwnerOf(vault), null);
  assert.match(await blind.custodyRefusal(await row(prdUnpromoted)), /not been promoted/);
  assert.match(await blind.custodyRefusal(await row(gift)), /not adopted/);
  assert.equal(await blind.custodyRefusal(await row(stg)), null);
  // a contract owner with no held() (here the USDC token) passes like a wallet
  assert.equal(await blind.custodyRefusal({ ...mine, owner: P.usdc }), null);
  // a KNOWN vault must answer: a lagging node's empty result (or any odd error) refuses, never "wallet"
  const lagging = new Proxy(chain.pc, { get: (t, k) => k === "call" ? async () => ({ data: undefined })
    : k === "readContract" ? async (a) => {
      if (a.functionName === "held") throw new Error('The contract function "held" returned no data ("0x").');
      return t.readContract(a);
    } : t[k] });
  const strict = createCustodyGate({ pc: lagging, book: P.book, ttlMs: 0 });
  await assert.rejects(strict.custodyRefusal(await row(stg)), /returned no data/);
  const revertish = new Proxy(chain.pc, { get: (t, k) => k === "readContract" ? async (a) => {
    if (a.functionName === "held") { const e = new Error("execution reverted"); e.name = "ExecutionRevertedError"; throw e; }
    return t.readContract(a);
  } : t[k] });
  await assert.rejects(createCustodyGate({ pc: revertish, book: P.book, ttlMs: 0 }).custodyRefusal(await row(stg)), /reverted/);
  // a lying node reporting NO CODE for the vault: the relay's own VaultCreated index still holds it to
  // the strict read, and nothing negative is cached (an honest answer next time refuses at once)
  const noCode = new Proxy(chain.pc, { get: (t, k) => k === "getCode" ? async () => "0x" : t[k] });
  const indexed = createCustodyGate({ pc: noCode, book: P.book, ttlMs: 60_000, knownVault: (a) => a === vault });
  assert.match(await indexed.custodyRefusal(await row(prdUnpromoted)), /not been promoted/);
  let lie = true;
  const flaky = new Proxy(chain.pc, { get: (t, k) => k === "getCode" ? async (a) => (lie ? "0x" : t.getCode(a)) : t[k] });
  const cached = createCustodyGate({ pc: flaky, book: P.book, ttlMs: 60_000 });
  await cached.custodyRefusal(await row(prdUnpromoted));               // one lie (no index here) ...
  lie = false;
  assert.match(await cached.custodyRefusal(await row(prdUnpromoted)), /not been promoted/, "... is not remembered");
  // an unreachable chain refuses (the callers fail closed on a throw)
  const dead = createCustodyGate({ pc: { getCode: async () => "0x60", call: async () => { throw new Error("fetch failed"); },
    readContract: async () => { throw new Error("fetch failed"); } }, book: null, ttlMs: 0 });
  await assert.rejects(dead.custodyRefusal({ ...mine, owner: vault }), /fetch failed/);
});

test("session-derived account token: sign-in, short SSO tokens, dies with the session", { skip }, async () => {
  // the relay's account + SSO modules in-process, wired to the sessions service exactly as api-relay.js does
  process.env.AUTH_DATA_DIR = fs.mkdtempSync(path.join(tmp, "auth-"));
  process.env.SSO_SIGNER_KEY = "0x" + "42".repeat(32);
  const auth = await import("../relay/auth.js");
  const sso = await import("../relay/sso.js");
  assert.equal((await auth.initAccounts()).enabled, true);
  assert.equal((await sso.initSso()).enabled, true);
  auth.setSessionHooks({
    verify: (req, raw) => svc.verifyApiRequest({ header: req.headers.authorization || "", method: req.method,
      hostPath: req.headers.host + new URL(req.url, "http://relay").pathname, body: raw, scope: "api.account", fresh: true }),
    state: async (vault, sid) => {
      const r = await svc.route("GET", `/session/${vault}/${sid}`, {});
      return { ...r.state, live: Boolean(r.state.live) && !r.revoked };
    },
    isRevoked: (sid) => Boolean(svc.store?.data?.revoked?.[String(sid).toLowerCase()]),
  });
  const ctx = {
    json: (res, code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); },
    cors: () => ({}), clientIp: () => "127.0.0.1",
    readBody: async (req) => { const b = []; for await (const c of req) b.push(c); return Buffer.concat(b); },
  };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, "http://relay");
    if (u.pathname.startsWith("/v1/sso")) return sso.handleSso(req, res, u, ctx);
    return auth.handleAccount(req, res, u, ctx);
  });
  await new Promise((r) => srv.listen(0, r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const post = async (p, { headers = {}, body } = {}) => {
      const r = await fetch(base + p, { method: "POST", headers: { ...headers, ...(body ? { "content-type": "application/json" } : {}) },
        body: body ? JSON.stringify(body) : undefined });
      return { status: r.status, body: await r.json().catch(() => ({})) };
    };
    // an agent's staging key has no api.account: no account token
    const agent = await openFor("staging-publish", { apps: ["acct-agent"], budget: 0n });
    const refused = await post("/v1/account/session-login",
      { headers: { Authorization: await agent.session.apiAuthorization("POST", base + "/v1/account/session-login", "") } });
    assert.equal(refused.status, 403);
    assert.match(refused.body.message, /lacks api.account/);

    const { session, sid, vault } = await openFor("browser", { budget: 0n });
    const login = await post("/v1/account/session-login",
      { headers: { Authorization: await session.apiAuthorization("POST", base + "/v1/account/session-login", "") } });
    assert.equal(login.status, 200, JSON.stringify(login.body));
    assert.equal(login.body.sid, sid);
    assert.equal(login.body.vault, vault);
    const tok = { Authorization: "Bearer " + login.body.token };
    const aud = "0x" + "ab".repeat(32);
    // an est1 can't be recalled once an app holds it: a session-derived one lives as long as the
    // session (browser preset: 12 h), never longer, and not just 10 minutes (that signed apps out)
    const est = await post("/v1/sso/token", { headers: tok, body: { aud, ttl: 604800 } });
    assert.equal(est.status, 200, JSON.stringify(est.body));
    const sessExp = Number((await session.status()).expiresAt);
    assert.ok(est.body.exp <= sessExp, `the token outlives the session (${est.body.exp} > ${sessExp})`);
    assert.ok(est.body.exp - est.body.iat > 12 * 3600 - 300, `too short: ${est.body.exp - est.body.iat}s`);
    const shortAsked = await post("/v1/sso/token", { headers: tok, body: { aud, ttl: 900 } });
    assert.equal(shortAsked.body.exp - shortAsked.body.iat, 900, "an app asking for less gets what it asked");
    // a session token can't widen the account it stands for
    const link = await post("/v1/account/link/siwe", { headers: tok, body: {} });
    assert.equal(link.status, 403);
    // sign-out: the account token is dead at once, and so is minting
    await session.terminate();
    assert.equal((await post("/v1/sso/token", { headers: tok, body: { aud } })).status, 401);
  } finally { srv.close(); }
});

test("records the WALLET holds: a session acts on them only once the owner lets its vault (ledger rev 15d delegation)", { skip }, async () => {
  const { session, vault } = await openFor("browser", { budget: parseUnits("2", 6), label: "wallet records" });
  const wallet = chain.wc(KEYS.owner);
  const ledgerGet = (id) => chain.pc.readContract({ address: P.ledger, abi: P.abi.ledger.abi, functionName: "get", args: [id] });
  const send = async (data) => {
    const rc = await chain.pc.waitForTransactionReceipt({ hash: await wallet.sendTransaction({ to: P.ledger, data }) });
    assert.equal(rc.status, "success");
    return rc;
  };
  const relayView = async () => (await new sdk.RelayClient(relayUrl).request("GET", `/owner/${owner.address}`)).delegation;

  // the owner's wallet creates a record directly on the ledger: the wallet holds it, not the vault
  const rc = await chain.pc.waitForTransactionReceipt({ hash: await wallet.writeContract({ address: P.ledger, abi: P.abi.ledger.abi,
    functionName: "create", args: [P.storeRef, 0, 1000, 8080, "", false, "", "0x0000000000000000000000000000000000000000", 0n, 1000n] }) });
  const id = rc.logs.find((l) => l.address.toLowerCase() === P.ledger.toLowerCase()).topics[1];
  assert.equal((await ledgerGet(id)).owner, owner.address);
  assert.equal((await ledgerGet(id)).active, true);

  // not granted yet: the SDK and the relay agree, and the vault's call meets the ledger's owner gate
  assert.deepEqual(await sdk.delegationStatus(chain.pc, P.ledger, owner.address, vault), { supported: true, granted: false });
  assert.deepEqual(await relayView(), { ledger: P.ledger, supported: true, granted: false });
  await assert.rejects(session.call("deploy.setActive", { id, active: false }),
    (e) => e instanceof sdk.SessionError && e.code === "delegation", "Error(\"!owner\") is a typed 'delegation' refusal");
  assert.equal((await ledgerGet(id)).active, true);

  // the owner grants it: one wallet transaction to the ledger (DelegateSet), read back from storage
  const grantRc = await send(sdk.setDelegateCall(vault, true).data);
  const ev = (await import("viem")).parseEventLogs({ abi: sdk.ledgerDelegateAbi, logs: grantRc.logs, eventName: "DelegateSet" })[0];
  assert.deepEqual([ev.args.owner, ev.args.delegate, ev.args.allowed], [owner.address, vault, true]);
  assert.equal(BigInt(await chain.pc.getStorageAt({ address: P.ledger, slot: sdk.delegateSlot(owner.address, vault) })), 1n);
  assert.equal(delegateSlot(owner.address, vault), sdk.delegateSlot(owner.address, vault), "relay and SDK read the same slot");
  assert.deepEqual(await sdk.delegationStatus(chain.pc, P.ledger, owner.address, vault), { supported: true, granted: true });
  assert.deepEqual(await relayView(), { ledger: P.ledger, supported: true, granted: true });

  // now the session suspends, resumes, resizes and lowers the cap - through the relay, no wallet
  await session.call("deploy.setActive", { id, active: false });
  assert.equal((await ledgerGet(id)).active, false);
  await session.call("deploy.setActive", { id, active: true });
  await session.call("deploy.setShares", { id, gpuMilli: 0, cpuMilli: 500 });
  assert.equal((await ledgerGet(id)).cpuMilli, 500);
  await session.call("deploy.setMaxRate", { id, maxRate6: 800n });
  assert.equal(await chain.pc.readContract({ address: P.ledger, abi: P.abi.ledger.abi, functionName: "capOf", args: [id] }), 800n);
  // ... but a wallet record is PRODUCTION: never a raised cap, never what it runs
  await assert.rejects(session.call("deploy.setMaxRate", { id, maxRate6: 900n }), (e) => e.code === "price");
  await assert.rejects(session.call("deploy.setAppRef", { id, appRef: P.storeRef }), (e) => e.code === "env");
  await assert.rejects(session.call("deploy.setConfig", { id, configCid: "{}" }), (e) => e.code === "env");
  assert.equal((await ledgerGet(id)).owner, owner.address, "still the wallet's");
  // an agent's staging-only session never reaches a wallet record, delegation or not
  const agent = await openFor("staging-publish", { apps: ["wr-staging"], budget: parseUnits("1", 6), label: "agent" });
  await assert.rejects(agent.session.call("deploy.setActive", { id, active: false }), (e) => e.code === "env");
  await agent.session.terminate();

  // off the chain (placement), the relay holds a session to the same rule
  const held = async (v, i) => (await chain.pc.readContract({ address: v, abi: sdk.sessionVaultAbi, functionName: "held", args: [i] }))[0];
  const st = await session.status();
  const me = { vault, owner: owner.address, envs: st.envs };
  assert.equal(await sessionRowRefusal(me, { id, owner: owner.address }, held), null, "a prod session may act on a wallet row");
  assert.match(await sessionRowRefusal({ ...me, envs: 1 }, { id, owner: owner.address }, held), /production \(wallet-held\)/);
  assert.match(await sessionRowRefusal(me, { id, owner: P.publisher }, held), /does not belong/);
  assert.match(await sessionRowRefusal(me, { id, owner: vault }, held), /outside this session's environments/, "unadopted in the vault");

  // the owner takes it back: refused again
  await send(sdk.setDelegateCall(vault, false).data);
  assert.deepEqual(await sdk.delegationStatus(chain.pc, P.ledger, owner.address, vault), { supported: true, granted: false });
  assert.deepEqual(await relayView(), { ledger: P.ledger, supported: true, granted: false });
  await assert.rejects(session.call("deploy.setActive", { id, active: false }), (e) => e.code === "delegation");
  assert.equal((await ledgerGet(id)).active, true);
  await session.terminate();

  // support is read off the code: main's undeployed rev 16 ledger has no setDelegate, so a client never
  // reads slot 23 there; neither does a contract without it, nor an address with no code
  const rev16 = JSON.parse(fs.readFileSync(new URL("../contracts/foundry/out/EnclaveDeployments.sol/EnclaveDeployments.json", import.meta.url)));
  assert.equal(codeHasDelegation(rev16.deployedBytecode.object), false);
  assert.equal(sdk.codeHasDelegation(rev16.deployedBytecode.object), false);
  assert.equal(codeHasDelegation(await chain.pc.getCode({ address: P.ledger })), true);
  assert.deepEqual(await sdk.delegationStatus(chain.pc, P.catalog, owner.address, vault), { supported: false, granted: false });
  assert.deepEqual(await sdk.delegationStatus(chain.pc, "0x00000000000000000000000000000000000d0d0d", owner.address, vault),
    { supported: false, granted: false });
});

test("keeper closes expired sessions and refunds the owner", { skip }, async () => {
  const { session, vault, sid } = await openFor("staging-publish", { apps: ["k-staging"], budget: parseUnits("3", 6), expiresIn: 600 });
  await svc.indexOnce();
  const before = await usdcBal(owner.address);
  await chain.warp(700);
  assert.equal((await session.status()).live, false);
  await svc.keeperOnce();
  const after = await usdcBal(owner.address);
  if (process.env.SESSIONS_TEST_LOG) console.log("keeper refund", before, after, after - before);
  assert.ok(after >= before + parseUnits("3", 6) - 100_000n, "refund landed, minus at most the close fee ($0.10 cap)");
  assert.ok(after > before, "something was refunded");
  const st = await sdk.readSession(chain.pc, vault, sid);
  assert.equal(st.state, 2);
});
