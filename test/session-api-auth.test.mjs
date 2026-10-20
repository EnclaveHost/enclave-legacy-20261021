// Wallet sessions as the OWNER'S credential on a host (windows/node/session-api-auth.mjs): the shared verifier, then the
// two hosts that use it - the Windows node's Host (restartRequest, a private deployment's proxy) and the Linux
// supervisor's real routes, booted. The on-chain parts run against anvil with the REAL SessionVault factory (deployed by
// the production script), the rev 15d ledger and sessions opened by the built SDK through the real relay service
// (test/helpers/sessions-chain.mjs, as test/sessions.test.mjs does). Skips the chain parts without Foundry.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createPublicKey, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";
import { createWalletClient, getAddress, http as viemHttp, parseUnits } from "viem";
import { foundry } from "viem/chains";
import { haveFoundry, startChain, deployPlatform, KEYS } from "./helpers/sessions-chain.mjs";
import { bootDaemon } from "./helpers/daemon.mjs";
import { createSessionsService, delegateSlot as relayDelegateSlot } from "../relay/sessions.mjs";
import { JsonStore } from "../relay/store.js";
import * as sdk from "../sdk/sessions/dist/node.mjs";
import * as A from "../windows/node/session-api-auth.mjs";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const skip = !haveFoundry() ? "needs Foundry (anvil + forge)" : false;
const API = "https://api.enclave.host";
const ID = (n) => "0x" + n.repeat(64 / n.length);

// ============================================================================================================
// Pure parts: the header, the bases, the message, the slot, the replay set
// ============================================================================================================

const b64u = (b) => Buffer.from(b).toString("base64url");
/** A header made by hand with a node key, for the shapes the SDK never produces. */
function handHeader({ vault = "0x" + "11".repeat(20), sid = ID("22"), ts = Math.floor(Date.now() / 1000), n = "AAAAAAAAAAAAAAAA",
  method = "GET", hostPath = "api.enclave.host/v1/x", body = "", key = null } = {}) {
  const kp = key || generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = kp.publicKey.export({ format: "jwk" });
  const msg = A.apiMessage(method, hostPath, A.sha256Hex(Buffer.from(body)), ts, n, vault, sid);
  const sig = nodeSign("sha256", Buffer.from(msg), { key: kp.privateKey, dsaEncoding: "ieee-p1363" });
  return { header: `EnclaveSession v1 vault=${vault},sid=${sid},ts=${ts},n=${n},x=${jwk.x},y=${jwk.y},sig=${b64u(sig)}`, kp };
}

test("isSessionHeader: the scheme, in any case, is a session; Bearer and nothing are not", () => {
  for (const h of ["EnclaveSession v1 vault=…", "enclavesession v1", "ENCLAVESESSION", "EnclaveSession"]) assert.equal(A.isSessionHeader(h), true, h);
  for (const h of ["Bearer abc", "", undefined, null, "EnclaveSessionX v1", "Basic EnclaveSession"]) assert.equal(A.isSessionHeader(h), false, String(h));
});

test("parseSessionHeader: every malformed shape is a 401, never a guess", () => {
  const { header } = handHeader();
  const p = A.parseSessionHeader(header);
  assert.equal(p.sid, ID("22"));
  assert.equal(p.x.length, 32);
  assert.equal(p.sig.length, 64);
  const bad = [
    "EnclaveSession v2 " + header.slice("EnclaveSession v1 ".length),          // another version
    "EnclaveSession v1",                                                      // nothing
    header.replace(/vault=[^,]+/, "vault=0x1234"),                            // short address
    header.replace(/sid=[^,]+/, "sid=0x22"),                                  // short sid
    header.replace(/ts=[^,]+/, "ts=-5"),                                      // not a time
    header.replace(/ts=[^,]+/, "ts=1.5"),
    header.replace(/n=[^,]+/, "n=abc"),                                       // nonce too short
    header.replace(/n=[^,]+/, "n=AAAA+AAAA/AAAA="),                           // not base64url
    header.replace(/x=[^,]+/, "x=AAAA"),                                      // key too short
    header.replace(/sig=[^,]+$/, "sig=" + b64u(Buffer.alloc(63))),            // 63-byte signature
    header.replace(/sig=[^,]+$/, "sig=" + b64u(Buffer.alloc(70))),            // DER-ish length
    header + ",n=BBBBBBBBBBBBBBBB",                                           // duplicate field
    header.replace(/,ts=/, ",=x,ts="),                                        // empty key
    header.replace(/vault=[^,]+,/, ""),                                       // missing vault
  ];
  for (const h of bad) assert.throws(() => A.parseSessionHeader(h), (e) => e instanceof A.SessionAuthError && e.status === 401, h);
});

test("apiBases: front doors as is and with /t/<name>, plus this host's own public URLs; never anything else", () => {
  assert.deepEqual(A.apiBases({}), ["api.enclave.host"]);
  assert.deepEqual(A.apiBases({ publicUrls: ["https://api.enclave.host/t/metal0"] }), ["api.enclave.host", "api.enclave.host/t/metal0"]);
  assert.deepEqual(A.apiBases({ hosts: ["API.enclave.host.", "api2.example"], tunnelNames: ["box1"], publicUrls: ["https://E1.box.example/", "not a url", null] }),
    ["api.enclave.host", "api.enclave.host/t/box1", "api2.example", "api2.example/t/box1", "e1.box.example"]);
  // a tunnel name is a plain label: anything that could smuggle a path is dropped
  assert.deepEqual(A.apiBases({ tunnelNames: ["../x", "a/b", ""] }), ["api.enclave.host"]);
});

test("the signed bytes are the SDK's and the relay's; the delegate slot and support probe match theirs", () => {
  const body = '{"a":1}';
  const vault = "0xAbCdEf0000000000000000000000000000000001", sid = ID("aB");
  assert.equal(A.apiMessage("post", "api.enclave.host/v1/x?y=1", A.sha256Hex(Buffer.from(body)), 1700000000, "nonce123", vault, sid),
    sdk.apiMessage("POST", "api.enclave.host/v1/x?y=1", body, 1700000000, "nonce123", vault, sid));
  const owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
  assert.equal(A.delegateSlot(owner, vault), relayDelegateSlot(owner, vault));
  assert.equal(A.delegateSlot(owner, vault), sdk.delegateSlot(owner, vault));
  assert.equal(A.codeHasDelegation("0x6080" + "634a994eef" + "00"), true);
  assert.equal(A.codeHasDelegation("0x6080604052"), false);
  assert.equal(A.hasScope(1n << 129n, "api.logs"), true);
  assert.equal(A.hasScope(1n << 129n, "api.restart"), false);
  assert.throws(() => A.hasScope(0n, "api.nope"), /unknown API scope/);
});

test("replayGuard: single use, expires, and stays bounded (oldest first)", () => {
  let t = 1000;
  const g = A.replayGuard({ ttlSec: 10, max: 3, now: () => t });
  assert.equal(g.claim("a"), true);
  assert.equal(g.claim("a"), false);
  t += 11;
  assert.equal(g.claim("a"), true, "an expired entry no longer blocks (the timestamp window refuses it anyway)");
  g.claim("b"); g.claim("c"); g.claim("d");
  assert.equal(g.size, 3);
  assert.equal(g.claim("b"), false, "a recent entry survives eviction");
  g.release("b");
  assert.equal(g.claim("b"), true);
});

// ============================================================================================================
// On chain: anvil + the real vault factory, ledger 15d, the relay service (to open sessions), the built SDK
// ============================================================================================================

let chain, P, svc, server, relayUrl, tmp, stores = [];
const owner = privateKeyToAccount(KEYS.owner);
const ownerSigner = { address: owner.address, signTypedData: (td) => owner.signTypedData(td) };
const S = {};       // sessions by name
const R = {};       // records by name: { id, owner }

async function openFor(preset, { apps, budget = 0n, policy = {}, label = "test" } = {}) {
  const store = new sdk.MemoryStore();
  const { signer, record } = await sdk.newSessionKey(store, { relay: relayUrl, chainId: 31337, label, extractable: true });
  const grant = sdk.buildGrant({ sessionKey: signer.keyHash, label, preset, policy: { ...(apps ? { apps } : {}), budget, ...policy } });
  const relay = new sdk.RelayClient(relayUrl);
  const vault = await sdk.vaultAddress(chain.pc, P.factory, owner.address);
  const usdc = budget > 0n ? await sdk.usdcDomain(chain.pc, P.usdc, 31337) : undefined;
  const out = await sdk.openSession({ relay, owner: ownerSigner, chainId: 31337, vault, grant, usdc });
  const rec = await sdk.completeSession(store, record, { vault, owner: owner.address, grant, rpc: chain.rpc });
  const session = await sdk.sessionFromRecord(rec);
  return { session, vault, sid: out.sid, signer: session.signer };
}
const hdr = (name, method, url, body) => S[name].session.apiAuthorization(method, url, body);
const verifier = (o = {}) => A.createSessionApiAuth({ pc: chain.pc, book: () => P.book, factories: [], bases: () => A.apiBases({}), ...o });
const createVia = async (name, env) => {
  const c = await S[name].session.call("deploy.create", { appRef: P.storeRef, gpuMilli: 0, cpuMilli: 1000, appPort: 8080, ports: "",
    isPublic: false, configCid: "", maxRate6: 1000n, env, fund6: 0n });
  return `0x${c.result.slice(2, 66)}`;
};
const wallet = () => chain.wc(KEYS.owner);
const sendToLedger = async (data) => {
  const rc = await chain.pc.waitForTransactionReceipt({ hash: await wallet().sendTransaction({ to: P.ledger, data }) });
  assert.equal(rc.status, "success");
};

before(async () => {
  if (skip) return;
  chain = await startChain();
  P = await deployPlatform(chain);
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "session-api-auth-"));
  const relayer = privateKeyToAccount(KEYS.relayer);
  svc = createSessionsService({
    pc: chain.pc, wc: createWalletClient({ chain: foundry, account: relayer, transport: viemHttp(chain.rpc) }),
    account: relayer, chainId: 31337, factory: P.factory, book: P.book, usdc: P.usdc, router: P.router,
    startBlock: P.deployBlock, ethUsd: 3000, minFee6: 500, now: chain.now,
    feesPerGas: async () => ({ maxFeePerGas: 7_000_000n, maxPriorityFeePerGas: 1_000_000n }),
    store: (stores[0] = new JsonStore(path.join(tmp, "idx.json"), {})),
    journal: (stores[1] = new JsonStore(path.join(tmp, "j.json"), { txs: [] }, { durable: true })),
    log: () => {}, alert: () => {},
  });
  server = http.createServer((req, res) => {
    const u = new URL(req.url, "http://relay.test");
    if (u.pathname.startsWith("/v1/sessions")) return svc.handle(req, res, u, null);
    res.writeHead(404).end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  relayUrl = `http://127.0.0.1:${server.address().port}`;

  // the browser's session (staging + prod, every api scope), an agent's (staging only, no appAccess), a status-only one
  S.browser = await openFor("browser", { budget: parseUnits("5", 6), label: "browser" });
  S.agent = await openFor("staging-publish", { apps: ["agent-app"], budget: 0n, label: "agent" });
  S.status = await openFor("auth-only", { policy: { environments: ["staging", "prod"] }, label: "status only" });
  // records: two the vault holds (staging, prod), one the wallet holds, one a stranger's
  R.staging = { id: await createVia("browser", "staging"), owner: S.browser.vault };
  R.prod = { id: await createVia("browser", "prod"), owner: S.browser.vault };
  const rc = await chain.pc.waitForTransactionReceipt({ hash: await wallet().writeContract({ address: P.ledger, abi: P.abi.ledger.abi,
    functionName: "create", args: [P.storeRef, 0, 1000, 8080, "", false, "", "0x0000000000000000000000000000000000000000", 0n, 1000n] }) });
  R.wallet = { id: rc.logs.find((l) => l.address.toLowerCase() === P.ledger.toLowerCase()).topics[1], owner: owner.address };
  R.stranger = { id: ID("5e"), owner: getAddress(privateKeyToAccount(KEYS.stranger).address) };
});

after(() => {
  for (const st of stores) clearInterval(st._timer);
  server?.close(); chain?.stop();
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

const logsUrl = (id, q = "?tail=5") => `${API}/v1/deployments/${id}/logs${q}`;
const logsPath = (id, q = "?tail=5") => `/v1/deployments/${id}/logs${q}`;
const rejects401 = (p, re) => assert.rejects(p, (e) => e instanceof A.SessionAuthError && e.status === 401 && (!re || re.test(e.message)));

test("pinned factory and ledger verify real sessions with the book forbidden, and zero never restores legacy factories", { skip }, async () => {
  let bookReads=0;
  const pc=new Proxy(chain.pc,{get(target,key){
    if(key==='readContract')return q=>{
      if(q.address.toLowerCase()===P.book.toLowerCase()){bookReads++;throw Error('book forbidden');}
      return target.readContract(q);
    };
    return target[key];
  }});
  const config={pc,authorityPins:{deployments:P.ledger,sessionVaultFactory:P.factory},
    book:()=>{bookReads++;throw Error('book forbidden');},ledger:()=>P.book,factories:[P.book]};
  const v=verifier(config);
  const session=await v.verify({header:await hdr('browser','GET',logsUrl(R.prod.id)),method:'GET',path:logsPath(R.prod.id),scope:'api.logs'});
  assert.equal(await v.refusal(session,R.prod),null);
  await sendToLedger(sdk.setDelegateCall(S.browser.vault,true).data);
  try{assert.equal(await v.refusal(session,R.wallet,{fresh:true}),null);}
  finally{await sendToLedger(sdk.setDelegateCall(S.browser.vault,false).data);}
  const disabled=verifier({...config,factories:[P.factory],authorityPins:{deployments:P.ledger,sessionVaultFactory:'0x'+'0'.repeat(40)}});
  await rejects401(disabled.verify({header:await hdr('browser','GET',logsUrl(R.prod.id)),method:'GET',path:logsPath(R.prod.id)}),/not a SessionVault/);
  assert.equal(bookReads,0);
});

test("a good signature verifies, names the vault, the session and the owner's wallet, and reports what it was signed for", { skip }, async () => {
  const v = verifier();
  const s = await v.verify({ header: await hdr("browser", "GET", logsUrl(R.prod.id)), method: "GET", path: logsPath(R.prod.id), scope: "api.logs" });
  assert.equal(s.vault, S.browser.vault);
  assert.equal(s.sid, S.browser.sid.toLowerCase());
  assert.equal(s.owner, owner.address);
  assert.equal(s.envs, 3);
  assert.equal(s.hostPath, `api.enclave.host${logsPath(R.prod.id)}`);
  // a JSON body is covered byte for byte
  const body = '{"seconds":1}';
  const b = await v.verify({ header: await hdr("browser", "POST", `${API}/v1/deployments/${R.prod.id}/cpu-profile`, body), method: "POST",
    path: `/v1/deployments/${R.prod.id}/cpu-profile`, body: Buffer.from(body), scope: "api.logs" });
  assert.equal(b.vault, S.browser.vault);
});

test("/t/<name> and the host's own URL: verified exactly when this host has that name", { skip }, async () => {
  const tUrl = `${API}/t/metal0/v1/deployments/${R.prod.id}/logs?tail=5`;
  const named = verifier({ bases: () => A.apiBases({ publicUrls: ["https://api.enclave.host/t/metal0"] }) });
  const s = await named.verify({ header: await hdr("browser", "GET", tUrl), method: "GET", path: logsPath(R.prod.id), scope: "api.logs" });
  assert.equal(s.hostPath, `api.enclave.host/t/metal0${logsPath(R.prod.id)}`);
  // another box's name: the relay sent it somewhere it was not meant for
  const other = verifier({ bases: () => A.apiBases({ tunnelNames: ["metal1"] }) });
  await rejects401(other.verify({ header: await hdr("browser", "GET", tUrl), method: "GET", path: logsPath(R.prod.id), scope: "api.logs" }), /bad session signature/);
  // the box's own hostname
  const own = verifier({ bases: () => A.apiBases({ publicUrls: ["https://e0123.box.example"] }) });
  assert.ok(await own.verify({ header: await hdr("browser", "GET", `https://e0123.box.example${logsPath(R.prod.id)}`), method: "GET",
    path: logsPath(R.prod.id), scope: "api.logs" }));
});

test("tampered method, path, query, body or host: the signature does not verify", { skip }, async () => {
  const v = verifier();
  const body = '{"a":1}';
  const u = `${API}/v1/deployments/${R.prod.id}/cpu-profile`, p = `/v1/deployments/${R.prod.id}/cpu-profile`;
  const cases = [
    [await hdr("browser", "POST", u, body), { method: "GET", path: p, body: Buffer.from(body) }],
    [await hdr("browser", "POST", u, body), { method: "POST", path: p.replace("cpu-profile", "restart"), body: Buffer.from(body) }],
    [await hdr("browser", "POST", u, body), { method: "POST", path: p, body: Buffer.from('{"a":2}') }],
    [await hdr("browser", "POST", u, body), { method: "POST", path: p, body: null }],
    [await hdr("browser", "GET", logsUrl(R.prod.id)), { method: "GET", path: logsPath(R.prod.id, "?tail=6") }],
    [await hdr("browser", "GET", `https://evil.example${logsPath(R.prod.id)}`), { method: "GET", path: logsPath(R.prod.id) }],
  ];
  for (const [header, req] of cases) await rejects401(v.verify({ header, scope: "api.logs", ...req }), /bad session signature/);
});

test("stale or future timestamps, and a replayed nonce (single use PER HOST)", { skip }, async () => {
  const h = await hdr("browser", "GET", logsUrl(R.prod.id));
  const req = { header: h, method: "GET", path: logsPath(R.prod.id), scope: "api.logs" };
  await rejects401(verifier({ now: () => Math.floor(Date.now() / 1000) + 61 }).verify(req), /stale or future/);
  await rejects401(verifier({ now: () => Math.floor(Date.now() / 1000) - 61 }).verify(req), /stale or future/);
  const hostA = verifier(), hostB = verifier();
  assert.ok(await hostA.verify(req));
  await rejects401(hostA.verify(req), /replayed/);
  // the relay's list fan-out sends one header to every host: each takes it once
  assert.ok(await hostB.verify(req));
  await rejects401(hostB.verify(req), /replayed/);
  // concurrent copies: exactly one passes
  const h2 = await hdr("browser", "GET", logsUrl(R.prod.id));
  const hostC = verifier();
  const rs = await Promise.allSettled([1, 2, 3].map(() => hostC.verify({ ...req, header: h2 })));
  assert.equal(rs.filter((r) => r.status === "fulfilled").length, 1);
});

test("a key that is not the session's, an ended session, a missing scope, a vault no known factory made", { skip }, async () => {
  const v = verifier();
  const u = logsUrl(R.prod.id), p = logsPath(R.prod.id);
  // another key signing for the browser session's vault + sid
  const other = await sdk.signerFromKeyPair(await sdk.generateKeyPair(false));
  await rejects401(v.verify({ header: await sdk.signApiRequest(other, S.browser.vault, S.browser.sid, "GET", u), method: "GET", path: p, scope: "api.logs" }),
    /does not belong to the session/);
  // a scope the session lacks: 403, not 401 (the credential is good)
  await assert.rejects(v.verify({ header: await hdr("agent", "POST", `${API}/v1/deployments/${R.staging.id}/app-token`, ""), method: "POST",
    path: `/v1/deployments/${R.staging.id}/app-token`, scope: "api.appAccess" }), (e) => e.status === 403 && /lacks api.appAccess/.test(e.message));
  // not a vault: an EOA, and a real vault under a verifier that knows no factory
  const eoa = handHeader({ vault: owner.address, sid: S.browser.sid, hostPath: `api.enclave.host${p}` });
  await rejects401(v.verify({ header: eoa.header, method: "GET", path: p }), /not a SessionVault of a known factory/);
  const blind = verifier({ book: () => null, factories: ["0x000000000000000000000000000000000000dEaD"] });
  await rejects401(blind.verify({ header: await hdr("browser", "GET", u), method: "GET", path: p, scope: "api.logs" }), /not a SessionVault/);
  // ...while the configured list alone (no book) recognises it
  assert.ok(await verifier({ book: () => null, factories: [P.factory] }).verify({ header: await hdr("browser", "GET", u), method: "GET", path: p }));
  // an ended session
  const gone = await openFor("auth-only", { label: "to end" });
  const early = await gone.session.apiAuthorization("GET", u);
  await gone.session.terminate();
  await rejects401(verifier().verify({ header: early, method: "GET", path: p }), /ended or expired/);
});

test("the record rule: vault-held by environment, wallet-held only with production AND the ledger delegation", { skip }, async () => {
  const v = verifier();
  const sess = async (name, scope = "api.status") => v.verify({ header: await hdr(name, "GET", `${API}/v1/deployments`), method: "GET",
    path: "/v1/deployments", scope });
  const browser = await sess("browser"), agent = await sess("agent"), status = await sess("status");
  assert.equal(await v.refusal(browser, R.staging), null);
  assert.equal(await v.refusal(browser, R.prod), null);
  assert.equal(await v.refusal(agent, R.staging), null, "a vault-held staging record, a staging session");
  assert.match(await v.refusal(agent, R.prod), /production, outside this session's environments/);
  assert.match(await v.refusal(browser, { id: R.wallet.id, owner: S.browser.vault }), /not been adopted/, "held() says 0: unadopted");
  assert.match(await v.refusal(browser, R.stranger), /does not belong to the deployment's owner/);
  // the wallet's own record: refused until the wallet grants the vault on the ledger
  assert.match(await v.refusal(browser, R.wallet, { fresh: true }), /has not let your session vault/);
  await sendToLedger(sdk.setDelegateCall(S.browser.vault, true).data);
  assert.equal(await v.refusal(browser, R.wallet, { fresh: true }), null);
  assert.equal(await v.refusal(status, R.wallet, { fresh: true }), null, "a status session covering prod reads it too");
  assert.match(await v.refusal(agent, R.wallet, { fresh: true }), /does not cover your production \(wallet-held\)/, "staging-only, delegation or not");
  // listing: what the vault holds in the session's envs + (delegated, prod) what the wallet holds; never a stranger's
  const rows = [R.staging, R.prod, R.wallet, R.stranger];
  assert.deepEqual((await v.visible(browser, rows)).map((r) => r.id), [R.staging.id, R.prod.id, R.wallet.id]);
  assert.deepEqual((await v.visible(agent, rows)).map((r) => r.id), [R.staging.id]);
  // taken back: refused again on the next fresh read (and within CACHE_MS on a cached one)
  await sendToLedger(sdk.setDelegateCall(S.browser.vault, false).data);
  assert.match(await v.refusal(browser, R.wallet, { fresh: true }), /has not let your session vault/);
  // a ledger without setDelegate: never reads the slot, refuses
  const old = verifier({ ledger: () => P.catalog });
  assert.match(await old.refusal(browser, R.wallet), /no owner-approved delegates/);
});

// ============================================================================================================
// The Windows node's Host: restartRequest and a private deployment's proxy
// ============================================================================================================

test("Windows Host: a restart and a private app take a wallet session; the box's own sign-in still works", { skip }, async () => {
  process.env.BASE_RPCS = chain.rpc;      // chain.mjs reads it at load: nothing here may reach a public RPC
  await sendToLedger(sdk.setDelegateCall(S.browser.vault, true).data);   // the wallet record is delegated (idempotent)
  const { Host } = await import("../windows/node/host.mjs");
  const { servedOwner } = await import("./helpers/owners.mjs");
  const { initSessionKey, mint, addressFor } = await import("../windows/node/session.mjs");
  const dir = fs.mkdtempSync(path.join(tmp, "win-"));
  const h = servedOwner(new Host({ dir, endpoint: "https://api.enclave.host/t/nucbox", name: "nucbox", appsEnabled: true,
    cpuPricePerSec6: 12, log: () => {}, engineRetired: true, isolationManager: "http://127.0.0.1:1" }), owner.address);
  const key = initSessionKey({ dir });
  h.cfg.sessionVerify = (headers, id) => addressFor(key, headers, id);
  h.cfg.sessionApi = verifier({ bases: () => A.apiBases({ tunnelNames: ["nucbox"], publicUrls: ["https://api.enclave.host/t/nucbox"] }) });
  const restarted = [];
  h.restart = async (id) => { restarted.push(id); return { status: "running" }; };
  const read = (id) => chain.pc.readContract({ address: P.ledger, abi: P.abi.ledger.abi, functionName: "get", args: [id] });
  const restart = async (name, rec, { url = `${API}/v1/deployments/${rec.id}/restart`, path: p = `/v1/deployments/${rec.id}/restart`, headers } = {}) =>
    h.restartRequest(rec.id, headers ?? { authorization: await hdr(name, "POST", url, "") }, { read, request: { method: "POST", path: p, body: null } });

  let r = await restart("browser", R.prod);
  assert.equal(r.status, 200, JSON.stringify(r));
  r = await restart("browser", R.wallet, { url: `${API}/t/nucbox/v1/deployments/${R.wallet.id}/restart` });
  assert.equal(r.status, 200, "the /t/<name> route, a delegated wallet record: " + JSON.stringify(r));
  r = await restart("agent", R.prod);
  assert.equal(r.status, 403, JSON.stringify(r));
  assert.match(r.body.message, /outside this session's environments/);
  r = await restart("status", R.prod);
  assert.equal(r.status, 403, "no api.restart");
  assert.match(r.body.message, /lacks api.restart/);
  r = await restart("browser", R.prod, { headers: { authorization: "EnclaveSession v1 garbage" } });
  assert.equal(r.status, 401, "a malformed session is a 401, never the bearer path");
  r = await restart("browser", R.prod, { headers: { authorization: `Bearer ${mint(key, { subject: S.browser.vault, ttlSec: 60 })}` } });
  assert.equal(r.status, 200, "the box's own SIWE session for the record's owner, unchanged");
  r = await restart("browser", R.prod, { headers: {} });
  assert.equal(r.status, 401);
  assert.deepEqual(restarted, [R.prod.id, R.wallet.id, R.prod.id].map((x) => x.toLowerCase()));
  // a box without a verifier refuses sessions
  const bare = servedOwner(new Host({ dir: fs.mkdtempSync(path.join(tmp, "win-")), endpoint: "https://api.enclave.host/t/x", name: "x",
    appsEnabled: true, cpuPricePerSec6: 12, log: () => {}, engineRetired: true, isolationManager: "http://127.0.0.1:1" }), owner.address);
  r = await bare.restartRequest(R.prod.id, { authorization: await hdr("browser", "POST", `${API}/v1/deployments/${R.prod.id}/restart`, "") },
    { read, request: { method: "POST", path: `/v1/deployments/${R.prod.id}/restart`, body: null } });
  assert.equal(r.status, 401);

  // a PRIVATE deployment's data path, on the app's own hostname (the app zone) and through the relay's /x/<id>
  const pid = R.prod.id.toLowerCase();
  h.records.set(pid, { id: pid, owner: S.browser.vault.toLowerCase(), isPublic: false, status: "running" });
  const host = h.hostsFor(pid)[0];
  const appReq = async (name, { url = `https://${host}/hello?q=1`, target = null, method = "POST", body = '{"x":1}', headers } = {}) =>
    h.proxy(pid, { method, pathRest: "/hello?q=1", target, body: Buffer.from(body),
      headers: headers ?? { authorization: await hdr(name, method, url, body) } });
  r = await appReq("browser");
  assert.equal(r.status, 503, "past the owner check to the (absent) app: " + r.body);
  assert.match(r.body, /not_running/);
  r = await appReq("browser", { url: `${API}/x/${pid}/hello?q=1`, target: `/x/${pid}/hello?q=1` });
  assert.equal(r.status, 503, "via the relay's /x/<id>: " + r.body);
  r = await appReq("agent");
  assert.equal(r.status, 403, "the agent's session has no api.appAccess");
  // a session WITH api.appAccess, on a private deployment its owner does not hold: the record rule refuses it
  const sid2 = R.stranger.id.toLowerCase();
  h.records.set(sid2, { id: sid2, owner: R.stranger.owner.toLowerCase(), isPublic: false, status: "running" });
  const host2 = h.hostsFor(sid2)[0];
  r = await h.proxy(sid2, { method: "GET", pathRest: "/", body: null,
    headers: { authorization: await hdr("browser", "GET", `https://${host2}/`) } });
  assert.equal(r.status, 403, r.body);
  assert.match(r.body, /does not belong to the deployment's owner/);
  r = await appReq("browser", { body: '{"x":1}', headers: { authorization: await hdr("browser", "POST", `https://${host}/hello?q=1`, '{"x":2}') } });
  assert.equal(r.status, 401, "a body the session did not sign");
  r = await appReq("browser", { headers: { authorization: `Bearer ${mint(key, { subject: S.browser.vault, ttlSec: 60 })}` } });
  assert.equal(r.status, 503, "the owner's box session still opens it");
  r = await appReq("browser", { headers: {} });
  assert.equal(r.status, 401);
});

// ============================================================================================================
// The Linux supervisor, booted: its real routes with an EnclaveSession header
// ============================================================================================================

test("supervisor: logs, restart, app-token, list, get, cpu-profile and create, with wallet sessions over its real routes", { skip }, async () => {
  await sendToLedger(sdk.setDelegateCall(S.browser.vault, true).data);   // the wallet record is delegated (idempotent)
  const dir = fs.mkdtempSync(path.join(tmp, "sup-"));
  const rec = (r, extra = {}) => ({ id: r.id.toLowerCase(), owner: getAddress(r.owner), status: "terminated", public: false, firewall: [],
    image: { reference: P.storeRef }, createdAt: new Date().toISOString(), remainingMs: 0, consumedMs: 0, rate: 0, paidUsdc: 0, ...extra });
  const pub = { ...R.staging, id: ID("9b") };   // a PUBLIC record the vault "holds" (off-ledger id: unadopted)
  fs.writeFileSync(path.join(dir, "state.json"), JSON.stringify({ savedAt: Date.now(),
    deployments: [rec(R.staging), rec(R.prod), rec(R.wallet), rec(R.stranger), rec(pub, { public: true })] }));
  const { child, port } = await bootDaemon({
    start: (p) => spawn(process.execPath, [process.env.SUPERVISOR_JS || path.join(REPO, "supervisor.js")], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env,
      PORT: String(p), SECRET: "test-secret", SESSION_KEY_DIR: path.join(dir, "keys"), STATE_FILE: path.join(dir, "state.json"),
      MOCK_SPAWN: "1", BASE_RPC: chain.rpc, DEPLOYMENTS_ADDRESS: P.ledger, SESSIONS_FACTORIES: P.factory,
      SESSION_API_TUNNEL_NAMES: "metal0", PUBLIC_URL: "", ADDRESS_BOOK_ADDRESS: "", REGISTRY_ENABLED: "", CLAIM_ENABLED: "",
      ACME_SELFTEST: "", ACME_EAB_KID: "", ACME_EAB_HMAC: "", APP_CERT_DOMAIN: "", DNS_API: "", SWEEP_SELFTEST: "",
      REACH_SELFTEST: "", WAF_SELFTEST: "", APPAUTH_SELFTEST: "" } }),
    claimed: (out, p) => out.includes(`enclave supervisor on :${p}`),
  });
  // the relay's leg: path + query as the client sent them, Host rewritten to the box
  const call = async (method, p, { name = "browser", signUrl = API + p, body, auth } = {}) => {
    const a = auth ?? await hdr(name, method, signUrl, body);
    const res = await fetch(`http://127.0.0.1:${port}${p}`, { method, body,
      headers: { authorization: a, ...(body ? { "content-type": "application/json" } : {}) } });
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    return { status: res.status, text, json };
  };
  try {
    let r = await call("GET", logsPath(R.prod.id));
    assert.equal(r.status, 200, r.text);
    assert.match(r.text, /\[mock\]/);
    r = await call("GET", logsPath(R.prod.id), { signUrl: `${API}/t/metal0${logsPath(R.prod.id)}` });
    assert.equal(r.status, 200, "signed for /t/metal0/...: " + r.text);
    r = await call("GET", logsPath(R.wallet.id));
    assert.equal(r.status, 200, "the wallet's record, delegated: " + r.text);
    r = await call("GET", logsPath(R.prod.id), { name: "agent" });
    assert.equal(r.status, 403, r.text);
    assert.equal(r.json.code, "not_allowed");
    r = await call("GET", logsPath(R.stranger.id));
    assert.equal(r.status, 403, r.text);
    r = await call("GET", logsPath(R.prod.id), { name: "status" });
    assert.equal(r.status, 403, "no api.logs: " + r.text);
    // restart: past the owner check, to this backend's own answer (no vm manager here)
    r = await call("POST", `/v1/deployments/${R.prod.id}/restart`, { body: undefined });
    assert.equal(r.status, 501, r.text);
    assert.equal(r.json.code, "restart_unavailable");
    r = await call("POST", `/v1/deployments/${R.staging.id}/restart`, { name: "agent" });
    assert.equal(r.status, 501, "a staging session restarts its staging record: " + r.text);
    // a JSON body is signed byte for byte: cpu-profile POST
    r = await call("POST", `/v1/deployments/${R.prod.id}/cpu-profile`, { body: '{"seconds":1}' });
    assert.equal(r.status, 501, r.text);
    const signedOther = await hdr("browser", "POST", `${API}/v1/deployments/${R.prod.id}/cpu-profile`, '{"seconds":2}');
    r = await call("POST", `/v1/deployments/${R.prod.id}/cpu-profile`, { body: '{"seconds":1}', auth: signedOther });
    assert.equal(r.status, 401, r.text);
    // app-token: minted for the RECORD's owner (the vault here), audience-bound to this one deployment
    r = await call("POST", `/v1/deployments/${R.prod.id}/app-token`);
    assert.equal(r.status, 200, r.text);
    const claims = JSON.parse(Buffer.from(r.json.token.split(".")[1], "base64url").toString());
    assert.equal(claims.sub, S.browser.vault);
    assert.equal(claims.aud, `app:${R.prod.id.toLowerCase()}`);
    r = await call("POST", `/v1/deployments/${R.prod.id}/app-token`, { name: "agent" });
    assert.equal(r.status, 403, "no api.appAccess: " + r.text);
    // listing and a single record
    r = await call("GET", "/v1/deployments");
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(r.json.data.map((d) => d.id).sort(), [R.staging.id, R.prod.id, R.wallet.id].map((x) => x.toLowerCase()).sort());
    r = await call("GET", "/v1/deployments", { name: "agent" });
    assert.deepEqual(r.json.data.map((d) => d.id), [R.staging.id.toLowerCase()]);
    r = await call("GET", `/v1/deployments/${R.staging.id}`, { name: "agent" });
    assert.equal(r.status, 200, r.text);
    r = await call("GET", "/v1/account");
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.address, owner.address);
    assert.equal(r.json.deployments.total, 3);
    // never created through a session; a malformed or replayed header is a 401; no header is the old 401
    r = await call("POST", "/v1/deployments", { body: "{}" });
    assert.equal(r.status, 403, r.text);
    assert.equal(r.json.code, "session_not_supported");
    r = await call("GET", logsPath(R.prod.id), { auth: "EnclaveSession v1 vault=0x1" });
    assert.equal(r.status, 401, r.text);
    const once = await hdr("browser", "GET", API + logsPath(R.prod.id));
    assert.equal((await call("GET", logsPath(R.prod.id), { auth: once })).status, 200);
    r = await call("GET", logsPath(R.prod.id), { auth: once });
    assert.equal(r.status, 401, r.text);
    assert.match(r.json.message, /replayed/);
    r = await call("GET", logsPath(R.prod.id), { auth: "" });
    assert.equal(r.status, 401);
    assert.equal(r.json.message, "Missing or invalid session.");
    // attestation: a session credential that does not verify is a 401, not an anonymous read
    r = await call("GET", `/v1/deployments/${R.prod.id}/attestation`, { auth: "EnclaveSession v1 nope" });
    assert.equal(r.status, 401, r.text);
  } finally { child.kill("SIGKILL"); }
});
