// The custody v2 custodian, as it runs INSIDE its SEV-SNP guest (docs/security/secret-custody-v2.md §8). Bundled by
// scripts/build-custodian-v2.mjs into /opt/custodian/custodian.mjs of the custodian image.
//
// MEASURED (this bundle's constants, MEASURED below): the chain, the vault, the RPCs and how many must agree, the Enclave
// owner. A host must not choose the chain a custodian believes: RPCs it controls could invent a policy.
// UNMEASURED (fw_cfg opt/org.enclave.custody, written by the host launcher): the public endpoint, the host's registry id,
// the committee to serve, whether to run genesis, and where the host keeps the sealed state and submits transactions. A
// lying host can at most make this custodian useless (wrong endpoint, dropped state, unsent transactions); it cannot make
// it release anything: every release is checked against the agreed chain, and the state opens only inside this guest.
//
// State: sealed with an SNP DERIVED key (snpkey: VCEK root, mixing the launch measurement and the guest policy), so only
// this exact code on this exact chip opens it. The host stores the ciphertext (GET/PUT <host>/state).
import fs from "node:fs";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { createCipheriv, createDecipheriv, randomBytes, createHash } from "node:crypto";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { bytesToHex } from "viem";
import * as hpke from "../hpke.mjs";
import { createChainReaderV2 } from "./chain.mjs";
import { createCustodianV2, Refusal } from "./custodian.mjs";
import { createMember } from "./member.mjs";
import { rateLimiter } from "../custodian.mjs";
import { productionVerifiers } from "../verifiers.mjs";
import { cachedCollateral, httpCollateral } from "../../verifier/consumer.mjs";
import { verifyQuote, parseSnpReport } from "../../relay/snp-verify.mjs";
import { MEASURED } from "./measured.mjs";
import { receiptCapacityCheck } from "./capacity.mjs";
import { independentOwners, ownerAdmissionCheck } from "./admission.mjs";
import { createIndependentGenesis, dkgHelper } from "./independent-genesis.mjs";
import * as D from "./digests.mjs";

const log = (...a) => console.log(new Date().toISOString(), ...a);
const FW = "/sys/firmware/qemu_fw_cfg/by_name/opt/org.enclave.custody/raw";
const TSM = "/sys/kernel/config/tsm/report";

function readHostConfig() {
  const c = JSON.parse(fs.readFileSync(process.env.CUSTODY_HOST_CONFIG || FW, "utf8"));
  const out = {
    endpoint: String(c.endpoint || ""), registryId: String(c.registryId || "").toLowerCase(), hostUrl: String(c.hostUrl || "http://10.0.2.2:8796"),
    committeeId: c.committeeId ? String(c.committeeId).toLowerCase() : null, genesis: c.genesis === true, port: Number(c.port || 8787),
    vcek: c.vcek ? Buffer.from(String(c.vcek), "base64") : null,
  };
  if (!/^https:\/\/[a-z0-9.-]{1,253}(\/[A-Za-z0-9._~-]+){0,4}$/.test(out.endpoint)) throw new Error("host config: endpoint must be an https URL (an optional plain path prefix)");
  if (!/^0x[0-9a-f]{64}$/.test(out.registryId)) throw new Error("host config: registryId must be bytes32");
  if (out.committeeId && !/^0x[0-9a-f]{64}$/.test(out.committeeId)) throw new Error("host config: committeeId must be bytes32");
  return out;
}

// ---- the chip: derived sealing key and reports ----
const derivedKey = () => Buffer.from(execFileSync("/opt/custodian/snpkey", ["derive"], { encoding: "utf8" }).trim(), "hex");
function vcekTable(der) {
  const hdr = Buffer.alloc(48);
  Buffer.from("63da758de6644564adc5f4b93be8accd", "hex").copy(hdr, 0);
  hdr.writeUInt32LE(48, 16); hdr.writeUInt32LE(der.length, 20);
  return Buffer.concat([hdr, der]);
}
function tsmReport(first32, vcek) {
  const dir = `${TSM}/custody-${process.pid}-${randomBytes(4).toString("hex")}`;
  fs.mkdirSync(dir);
  try {
    const rd = Buffer.alloc(64); Buffer.from(first32).copy(rd, 0);
    fs.writeFileSync(`${dir}/inblob`, rd);
    const report = fs.readFileSync(`${dir}/outblob`);
    let auxblob = null; try { auxblob = fs.readFileSync(`${dir}/auxblob`); } catch {}
    if ((!auxblob || !auxblob.length) && vcek) auxblob = vcekTable(vcek);
    return { report, auxblob };
  } finally { try { fs.rmdirSync(dir); } catch {} }
}

// ---- sealed state ----
const AAD = Buffer.from("enclave-custody-v2 state");
function seal(key, obj) {
  const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", key, iv); c.setAAD(AAD);
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(obj))), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
}
function unseal(key, blob) {
  const d = createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12)); d.setAAD(AAD); d.setAuthTag(blob.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(blob.subarray(28)), d.final()]).toString("utf8"));
}
async function hostGet(hostUrl, p) { const r = await fetch(hostUrl + p); if (r.status === 404) return null; if (!r.ok) throw new Error(`host ${p}: ${r.status}`); return Buffer.from(await r.arrayBuffer()); }
async function hostPut(hostUrl, p, body) { const r = await fetch(hostUrl + p, { method: "PUT", body }); if (!r.ok) throw new Error(`host ${p}: ${r.status}`); }

async function main() {
  const hc = readHostConfig();
  const key = derivedKey();
  // 1. the sealed state (keys + shares), or a fresh identity
  let state = null;
  const blob = await hostGet(hc.hostUrl, "/state").catch((e) => { log(`state fetch failed: ${e.message}`); return null; });
  if (blob) { try { state = unseal(key, blob); log("sealed state opened"); } catch { throw new Error("the host's sealed state does not open in this guest (another chip or another custodian build): refusing to start rather than overwrite it"); } }
  if (!state) {
    const kp = hpke.generateKeyPair();
    state = { identityKey: generatePrivateKey(), encPrivate: Buffer.from(kp.privateKey).toString("hex"), member: null };
    await hostPut(hc.hostUrl, "/state", seal(key, state));
    log("new custodian identity sealed");
  }
  const identity = privateKeyToAccount(state.identityKey);
  const encPrivateKey = new Uint8Array(Buffer.from(state.encPrivate, "hex"));
  const encKey = "0x" + Buffer.from(hpke.publicKeyOf(encPrivateKey)).toString("hex");
  // 2. this machine's record: measurement and chip id from its OWN report
  const probe = parseSnpReport(tsmReport(Buffer.alloc(32), hc.vcek).report);
  const sha = (b) => "0x" + createHash("sha256").update(b).digest("hex");
  const machine = { identity: identity.address.toLowerCase(), encKey, endpoint: hc.endpoint, chipId: sha(probe.chipId), registryId: hc.registryId, measurement: sha(probe.measurement) };
  log(`machine ${machine.identity} measurement ${probe.measurement.toString("hex").slice(0, 16)}... chip ${machine.chipId.slice(0, 12)}...`);

  if (!/^0x[0-9a-f]{40}$/.test(MEASURED.hostOwnership || "") || /^0x0{40}$/.test(MEASURED.hostOwnership)) throw new Error("measured host wallet authority is required");
  const chain = createChainReaderV2({ hostOwnership: MEASURED.hostOwnership, rpcs: MEASURED.rpcs, vault: MEASURED.vault, minAgree: MEASURED.minAgree, maxAgeSec: MEASURED.maxAgeSec });
  // Serialize snapshots so an older asynchronous member save cannot overwrite
  // a newer DKG phase. DKG awaits persistence before it emits a phase response.
  let writes=Promise.resolve();
  const saveNow = () => { const blob=seal(key,state);const next=writes.catch(()=>{}).then(()=>hostPut(hc.hostUrl,"/state",blob));writes=next;return next; };
  const store = { load: () => state.member, save: (m) => { state.member = m; saveNow().catch((e) => log(`STATE SAVE FAILED: ${e.message}`)); } };
  const submit = async (fn, args) => {
    const r = await fetch(hc.hostUrl + "/submit", { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ fn, args }, (k, v) => (typeof v === "bigint" ? v.toString() : v)) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`submit ${fn}: ${j.error || r.status}`);
    return j.tx;
  };
  const fetchJson = async (url, body) => {
    const r = await fetch(url, {signal:AbortSignal.timeout(15000),...(body === undefined ? {} : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })});
    const j = await r.json(); if (!r.ok) throw new Error(j.message || j.error || String(r.status)); return j;
  };
  const verifyPeerQuote = async (report, { binding, auxblob, minTcb }) => {
    let p; try { p = parseSnpReport(report); } catch (e) { return { ok: false, reason: e.message }; }
    const v = await verifyQuote(report, { challenge: Buffer.alloc(32, 1), transportKeySpki: Buffer.alloc(32, 1), expectedBinding: Buffer.from(binding),
                                          allowedMeasurements: [p.measurement.toString("hex")], auxblob, requireVcek: true, minTcb, expectedVmpl: 0 });
    if (!v.ok) return { ok: false, reason: v.reasons.slice(-1)[0] };
    return { ok: true, measurement: p.measurement.toString("hex"), chipId: p.chipId.toString("hex") };
  };
  const owners=MEASURED.independentOwners ? independentOwners(MEASURED.independentOwners,MEASURED.enclaveOwner) : null;
  const member = createMember({ chainId: MEASURED.chainId, vault: MEASURED.vault, identity, encPrivateKey, machine, chain, store, submit, fetchJson,
                                attestSelf: async (b) => tsmReport(b, hc.vcek), verifyPeerQuote, enclaveOwner: MEASURED.enclaveOwner, log,
                                // a non-Enclave candidate proves capacity with the audit witness's receipt for its chip (§5 item 2)
                                admissionCheck: owners ? ownerAdmissionCheck(owners) : null,
                                capacityCheck: receiptCapacityCheck({ chainId: MEASURED.chainId, contract: MEASURED.capacityContract, witnesses: MEASURED.witnesses }),
                                // this machine's own receipts, which its host fetches from the witness (unverified here: every member checks them)
                                capacityReceipts: async () => { const r = await fetch(hc.hostUrl + "/receipts"); return r.ok ? (await r.json()).slice(0, 8) : []; } });
  const custodian = createCustodianV2({ chainId: MEASURED.chainId, vault: MEASURED.vault, encPrivateKey, shares: member.shares, chain,
                                        verifiers: productionVerifiers({ collateral: cachedCollateral({ dir: "/tmp/amd-collateral", upstream: httpCollateral({ timeoutMs: 8000 }) }) }), log });

  let dkg=null;
  async function independent(body) {
    if(!owners)throw Error('independent genesis not enabled in this measured image');
    if(!dkg){
      const plan=state.independentPlan||body.plan;
      if(!plan||!await member.verifyGenesisRoster(plan,owners))throw Error('independent roster not verified');
      // One sealed session per machine; replacing its salt/transcript requires
      // an explicit new identity, not a host-controlled reset endpoint.
      const candidate=createIndependentGenesis({plan,identity,encPrivateKey,invoke:dkgHelper('/opt/custodian/dkg'),
        verifyRoster:p=>member.verifyGenesisRoster(p,owners),
        store:{load:()=>state.independentDkg,save:async s=>{state.independentDkg=s;await saveNow();}}});
      state.independentPlan=plan;await saveNow();dkg=candidate;
    }
    if(body.action==='start')return dkg.start();
    if(body.action==='agree')return dkg.agree(body.round1);
    if(body.action==='exchange')return dkg.exchange(body.acks);
    if(body.action==='finish')return dkg.finish(body.messages);
    if(body.action==='activate'){
      const s=state.independentDkg,plan=state.independentPlan;
      if(s?.phase!==3||!s.result)throw Error('independent DKG has not finished');
      if(!await member.verifyGenesisRoster(plan,owners))throw Error('independent roster changed');
      if(!Array.isArray(body.results)||body.results.length!==plan.machines.length)throw Error('all founder signatures required');
      const results=[...body.results].sort((a,b)=>a.id-b.id);
      for(let i=0;i<results.length;i++){
        const r=results[i];
        if(r.id!==i+1||r.committeeId!==s.committeeId||r.commitments!==s.commitments||
           await D.recoverDigest(D.independentGenesisDigest({...plan,committeeId:r.committeeId,commitments:r.commitments}),r.signature)!==plan.machines[i].identity.toLowerCase())throw Error('founder agreement mismatch');
      }
      const current=await chain.readCommittee({committeeId:s.committeeId});
      if(!current.committee){
        const hostSigs=[];
        for(const m of plan.machines){const ev=await fetchJson(`${m.endpoint}/v2/custody/info`);hostSigs.push(ev.hostSig);}
        await submit('createIndependentCommittee',[plan.salt,plan.machines,s.commitments,plan.codeSet,results.map(r=>r.signature),hostSigs]);
      }
      const adopted=await member.adoptIndependentGenesis(s);await saveNow();return adopted;
    }
    throw Error('unknown independent genesis action');
  }
  let independentTail=Promise.resolve();
  const runIndependent=body=>{const next=independentTail.then(()=>independent(body));independentTail=next.catch(()=>{});return next;};

  // 3. HTTP (the tunnel agent forwards the relay's /t/<name>/... here)
  const rate = rateLimiter();
  const json = (res, code, body) => { res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" }); res.end(JSON.stringify(body)); };
  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, "http://x");
    const client = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "-").split(",")[0].trim().slice(0, 64);
    try {
      if (req.method === "GET" && (u.pathname === "/health" || u.pathname === "/")) return json(res, 200, { ok: true, role: "custodian-v2" });
      if (req.method === "GET" && u.pathname === "/v2/custody/info") return json(res, 200, { ...member.info(hc.committeeId), chainId: MEASURED.chainId, vault: MEASURED.vault });
      if (req.method !== "POST") return json(res, 405, { error: "method_not_allowed", message: "POST only." });
      if (!rate(client)) return json(res, 429, { error: "rate_limited", message: "Too many requests; retry shortly." });
      const chunks = []; let n = 0;
      for await (const ch of req) { n += ch.length; if (n > 262144) return json(res, 413, { error: "too_large", message: "Body too large." }); chunks.push(ch); }
      let body; try { body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { return json(res, 400, { error: "bad_json", message: "Body must be JSON." }); }
      switch (u.pathname) {
        case "/v2/custody/challenge": return json(res, 200, custodian.challenge({ client }));
        case "/v2/custody/release": return json(res, 200, await custodian.release(body));
        case "/v2/custody/evidence": return json(res, 200, await member.evidence(String(body.nonce || "")));
        case "/v2/custody/join": return json(res, 200, await member.join(body, hc.committeeId));
        case "/v2/custody/approve": return json(res, 200, await member.approve({ ...body, next: body.next || [] }));
        case "/v2/custody/host-binding": return json(res, 200, await member.setHostSig(String(body.sig || "")));
        case "/v2/custody/independent-genesis": return json(res, 200, await runIndependent(body));
        default: return json(res, 404, { error: "not_found", message: "Unknown custody route." });
      }
    } catch (e) {
      if (e instanceof Refusal) return json(res, e.status, { error: e.code, message: e.message });
      return json(res, 422, { error: "refused", message: String(e.message).slice(0, 300) });
    }
  });
  srv.listen(hc.port, "0.0.0.0", () => log(`custodian-v2 on :${hc.port} for ${hc.endpoint}`));

  // 4. genesis, if the host asked for it and there is no committee yet; then the engine
  if (hc.genesis && !hc.committeeId && !(state.member && Object.keys(state.member.epochs || {}).length)) {
    for (;;) {
      if (state.member && state.member.hostSig) break;
      if (member._state().hostSig) break;
      log("genesis waits for the host binding (POST /v2/custody/host-binding)"); await new Promise((r) => setTimeout(r, 15000));
    }
    const g = await member.genesis({ salt: "0x" + randomBytes(32).toString("hex"), codeSet: [machine.measurement] });
    await saveNow();
    log(`GENESIS ${g.committeeId}: set committeeId in the host config`);
  }
  const loop = async () => {
    const cid = hc.committeeId || Object.keys(member._state().epochs || {}).map((k) => k.split(":")[0])[0];
    if (cid) { try { const r = await member.tick(cid); if (r.state !== "steady" && r.state !== "idle") log(`[engine] ${JSON.stringify(r)}`); } catch (e) { log(`[engine] ${e.message}`); } }
    setTimeout(loop, 60_000);
  };
  setTimeout(loop, 5_000);
}
main().catch((e) => { log(`FATAL ${e.stack || e.message}`); process.exit(1); });
