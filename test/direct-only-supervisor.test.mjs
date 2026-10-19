import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {preparePackage} from '../sdk/bootstrap/package.mjs';
const exec=promisify(execFile),tier='snp-guest-per-app';

// Pinned authorities: the only chain addresses a direct-only host may read or write.
const pins={registry:'0x'+'a1'.repeat(20),deployments:'0x'+'a2'.repeat(20),appCatalog:'0x'+'a3'.repeat(20),proofOfTime:'0x'+'a4'.repeat(20),
  enclavePay:'0x'+'00'.repeat(20),verificationFees:'0x'+'00'.repeat(20),sessionVaultFactory:'0x'+'00'.repeat(20),secretVaultV2:'0x'+'00'.repeat(20)};
const app='0x'+'ab'.repeat(32),enclaveId='0x'+'e1'.repeat(32),owner='0x'+'33'.repeat(20);
const catalog={app,publisher:'0x'+'44'.repeat(20),slug:'direct-app',version:'1.0.0',cid:'bafybeigdirectcomponent',memMb:256};
const manifest={version:1,chainId:8453,ledger:pins.deployments,deployment:'0x'+'11'.repeat(32),owner,appRef:`catalog://${app}/0`,
  appId:'45'.repeat(32),runtimeId:'55'.repeat(32),configText:'{"endpoint":"https://owner-chosen.example"}',secretsMode:'public'};
const pkg=preparePackage(manifest);
const health={backend:tier,catalog:{runtimeId:manifest.runtimeId,derivations:['enclave-catalog-bundle/1']},supports:{directBootstrap:true,gpu:false,protectedPorts:true},
  pool:{budget:{memMiB:32768,cpuPct:800},allocated:{memMiB:0,cpuPct:0},free:{memMiB:32768,cpuPct:800},guests:0,overcommitted:false,perGuest:{floorMiB:1024,runtimeMiB:384,unitOverheadMiB:768},hostAvailableMiB:65536,hostFloorMiB:16384}};
const now=Math.floor(Date.now()/1000);
const row=(o={})=>({id:manifest.deployment,owner,appRef:manifest.appRef,configCid:JSON.stringify({guestBootstrap:pkg.intent}),active:true,isPublic:true,
  gpuMilli:0,cpuMilli:100,leaseUntil:0,runner:'0x'+'00'.repeat(32),balance6:10_000_000,rate:1,spent6:0,createdAt:now-600,...o});
const A='http://192.0.2.10:8189/ipfs',B='http://192.0.2.11:8189/ipfs';

// The record guestd must be sent, written out from the pinned catalog's answer (catalog://app/0, its CID and memMb),
// not taken from the supervisor: enclave-catalog-bundle/1, the isolation policy and the manager's RuntimeID.
const expectedDerive={derivation:'enclave-catalog-bundle/1',catalog:{app,version:0},cid:catalog.cid,policy:{cpuPercent:100,memMiB:256,vcpus:1},runtimeId:manifest.runtimeId};
const canon=v=>Array.isArray(v)?`[${v.map(canon).join(',')}]`:v&&typeof v==='object'?`{${Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canon(v[k])).join(',')}}`:JSON.stringify(v);
const recordSha=createHash('sha256').update(canon(expectedDerive)).digest('hex');

function env(t,extra={}){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'direct-only-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const file=path.join(dir,'pins.json');fs.writeFileSync(file,JSON.stringify({version:1,chainId:8453,contracts:pins}));
  // A clean environment: nothing from the caller's shell (or any real host config) reaches the supervisor.
  return {PATH:process.env.PATH,SECRET:'direct-test-secret',ENABLE_MPS:'0',STATE_FILE:path.join(dir,'state.json'),
    ISOLATION_DIRECT_ONLY:'1',ISOLATION_BACKEND:tier,PROVISION_BACKEND:'vm',ENCLAVE_CONTRACT_PINS_FILE:file,ADDRESS_BOOK_ADDRESS:'',
    SECRETS_API:'',DOMAINS_API:'',CERTS_API:'',DNS_API:'',APP_CERT_DOMAIN:'',
    GUEST_BOOTSTRAP_GATEWAYS:`${A},${B}`,IPFS_GATEWAY:JSON.stringify([A,B].map(g=>new URL(g).origin)),
    REGISTRY_ENABLED:'1',REGISTRY_PRIVATE_KEY:'0x'+'01'.repeat(32),ENCLAVE_REPO:'independent/host',CLAIM_ENABLED:'1',...extra};
}
async function run(t,config,extra){
  const {stdout}=await exec(process.execPath,['supervisor.js'],{cwd:new URL('..',import.meta.url),timeout:60000,
    env:{...env(t,extra),DIRECT_CLAIM_SELFTEST:JSON.stringify(config)},maxBuffer:8<<20}).catch(e=>{throw Error(e.stderr||e.message);});
  return JSON.parse(stdout.trim().split('\n').at(-1));
}
const base={catalog,health,appId:manifest.appId,bytes:pkg.bytes.toString('base64'),enclaveId,endpoint:'https://host.independent.example',leaseUntil:now+3600};
const onlyPinned=out=>assert(out.reads.every(r=>[pins.deployments,pins.appCatalog].includes(r.address)),JSON.stringify(out.reads));
const onlyReplicas=out=>assert(out.calls.every(u=>u.startsWith(A+'/')||u.startsWith(B+'/')),JSON.stringify(out.calls));

test('a direct-only sweep claims and launches from pinned chain state and a surviving literal-IP replica',async t=>{
  const legacy=row({id:'0x'+'12'.repeat(32),configCid:''});
  const out=await run(t,{...base,rows:[row(),legacy],replicas:{[A]:'refuse',[B]:'serve'}});
  assert.equal(out.records[manifest.deployment]?.status,'running',JSON.stringify(out));
  // zero calls to anything but the operator's replicas: no relay, domain, certificate, DNS or catalog gateway
  onlyReplicas(out);assert(out.calls.some(u=>u.startsWith(A+'/'))&&out.calls.some(u=>u.startsWith(B+'/')));
  onlyPinned(out);
  assert.deepEqual(out.txs,[{address:pins.deployments,functionName:'claim',args:[manifest.deployment,enclaveId]}]);
  assert.equal(out.posted.length,1);const body=out.posted[0];
  assert.deepEqual(body.derive,expectedDerive);assert.equal(body.bootstrap,pkg.bytes.toString('base64'));
  assert.equal(body.config,'');assert.equal(body.release,undefined);assert.equal(out.prefetched[0].derive.cid,catalog.cid);
  assert.equal(out.records[manifest.deployment].config,manifest.configText);
  // the uncommitted deployment is refused, not launched by a legacy fallback
  assert.equal(out.records[legacy.id],null);assert.match(out.declines[legacy.id],/only owner-committed startup/);
});

test('hostile, redirecting and out-of-scope sources never reach a claim or a guest',async t=>{
  const other=preparePackage({...manifest,owner:'0x'+'77'.repeat(20)});
  const cases=[
    [{rows:[row()],replicas:{[A]:'corrupt',[B]:{bytes:other.bytes.toString('base64')}}},/no gateway returned/],
    [{rows:[row()],replicas:{[A]:'redirect',[B]:'throw'}},/no gateway returned/],
    // the owner transferred the deployment: its old commitment's package no longer matches the ledger owner
    [{rows:[row({owner:'0x'+'77'.repeat(20)})],replicas:{[A]:'serve',[B]:'serve'}},/no gateway returned/],
  ];
  for(const [config,why] of cases){
    const out=await run(t,{...base,hint:true,...config});
    assert.match(out.declines[manifest.deployment]||'',why,JSON.stringify(out));
    assert.deepEqual(out.txs,[]);assert.deepEqual(out.posted,[]);assert.deepEqual(out.prefetched,[]);onlyReplicas(out);
  }
  // an owner change while the component was prefetching stops the claim before any transaction
  const moved=await run(t,{...base,hint:true,rows:[row()],latest:{[manifest.deployment]:row({owner:'0x'+'77'.repeat(20)})},replicas:{[A]:'serve',[B]:'serve'}});
  assert.equal(moved.prefetched.length,1);assert.deepEqual(moved.txs,[]);assert.deepEqual(moved.posted,[]);
  // HTTP is accepted only for literal IPs: a DNS name over HTTP refuses the whole source list before any request
  const named=await run(t,{...base,hint:true,rows:[row()],replicas:{[A]:'serve'}},{GUEST_BOOTSTRAP_GATEWAYS:`http://replica.example/ipfs,${A}`});
  assert.match(named.declines[manifest.deployment],/HTTPS without credentials/);assert.deepEqual(named.calls,[]);
});

test('a restarted direct-only host adopts only the same committed guest and replaces a stale one',async t=>{
  const resumeRow=row({runner:enclaveId,leaseUntil:now+1800});
  const held={id:'gdheld0001',name:manifest.deployment,status:'running',appId:manifest.appId,runtimeId:manifest.runtimeId,recordSha256:recordSha,directBootstrap:true,bootstrapSha256:pkg.sha256,reserved:{memMiB:1792,cpuPct:100}};
  const same=await run(t,{...base,rows:[resumeRow],held,replicas:{[A]:'serve',[B]:'serve'}});
  assert.equal(same.records[manifest.deployment]?.status,'running',JSON.stringify(same));
  assert.deepEqual(same.txs,[]);assert.deepEqual(same.deleted,[]);assert.equal(same.records[manifest.deployment].vmId,held.id);
  onlyReplicas(same);onlyPinned(same);
  const stale=await run(t,{...base,rows:[resumeRow],held:{...held,bootstrapSha256:'aa'.repeat(32)},replicas:{[A]:'serve',[B]:'serve'}});
  assert.deepEqual(stale.deleted,[held.id]);assert.equal(stale.posted.length,2);assert.deepEqual(stale.txs,[]);
  assert.notEqual(stale.records[manifest.deployment].vmId,held.id);
});

test('direct-only mode refuses to start with an Enclave default or missing pin',async t=>{
  for(const [extra,why] of [[{SECRETS_API:undefined},/SECRETS_API must be empty/],[{DOMAINS_API:undefined,SECRETS_API:'https://relay.example'},/DOMAINS_API must be empty/],
    [{ENCLAVE_CONTRACT_PINS_FILE:''},/must pin the contracts/],[{GUEST_BOOTSTRAP_GATEWAYS:''},/name the package replicas/],
    [{IPFS_GATEWAY:''},/IPFS_GATEWAY must name/],[{ISOLATION_RELEASE:'1'},/ISOLATION_RELEASE must be off/]]){
    const e=env(t,extra);for(const k of Object.keys(e))if(e[k]===undefined)delete e[k];
    const r=await exec(process.execPath,['supervisor.js'],{cwd:new URL('..',import.meta.url),env:{...e,DIRECT_CLAIM_SELFTEST:'{}'},timeout:60000}).then(()=>null,x=>x);
    assert.equal(r?.code,2,why.source);assert.match(r.stderr,why);
  }
});
