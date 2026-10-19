import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {preparePackage} from '../sdk/bootstrap/package.mjs';
const exec=promisify(execFile),tier='snp-guest-per-app';
const manifest={version:1,chainId:8453,ledger:'0x'+'22'.repeat(20),deployment:'0x'+'11'.repeat(32),owner:'0x'+'33'.repeat(20),appRef:'catalog://0x'+'ab'.repeat(32)+'/0',appId:'44'.repeat(32),runtimeId:'55'.repeat(32),configText:'{ "endpoint":"https://independent.example" }',secretsMode:'public'};
const pkg=preparePackage(manifest),envelope=JSON.stringify({guestBootstrap:pkg.intent});
const pool={budget:{memMiB:32768,cpuPct:800},allocated:{memMiB:0,cpuPct:0},free:{memMiB:32768,cpuPct:800},guests:0,overcommitted:false,perGuest:{floorMiB:1024,runtimeMiB:384,unitOverheadMiB:768},hostAvailableMiB:65536,hostFloorMiB:16384};
const health={backend:tier,pool,catalog:{runtimeId:manifest.runtimeId,derivations:['enclave-catalog-bundle/1']},supports:{directBootstrap:true,gpu:false,protectedPorts:true}};
const row={id:manifest.deployment,owner:manifest.owner,appRef:manifest.appRef,configCid:envelope};
const rec={id:row.id,_onchain:true,_envelope:envelope,image:{reference:manifest.appRef},appWasm:'ipfs://bafylabcomponent',_versionMemMb:128,resources:{cpuShare:0.1,gpuShare:0},network:{port:8080},firewall:[]};
async function run(seam,config,extraEnv={}){
 const {stdout}=await exec(process.execPath,['supervisor.js'],{cwd:new URL('..',import.meta.url),env:{...process.env,SECRET:'test-secret',ENABLE_MPS:'0',ADDRESS_BOOK_ADDRESS:'',DEPLOYMENTS_ADDRESS:manifest.ledger,ISOLATION_BACKEND:tier,ISOLATION_RELEASE:'1',PROVISION_BACKEND:'vm',SECRETS_API:'https://refused.enclave.example',GUEST_BOOTSTRAP_GATEWAYS:'https://independent.example/ipfs',REGISTRY_ENABLED:'',CLAIM_ENABLED:'',ACME_EAB_KID:'',ACME_EAB_HMAC:'',APP_CERT_DOMAIN:'',DNS_API:'',[seam]:JSON.stringify(config),...extraEnv}});
 return JSON.parse(stdout.trim().split('\n').at(-1));
}
test('actual launchSpec and spawn use owner package when Enclave services refuse',async()=>{
 const out=await run('RELEASE_SELFTEST',{bootstrapLaunchSpec:{row,rec,health,appId:manifest.appId,bytes:pkg.bytes.toString('base64')}});
 assert.equal(out.error,null);assert.equal(out.config,manifest.configText);assert.equal(out.posted.length,1);
 assert.equal(out.posted[0].bootstrap,pkg.bytes.toString('base64'));assert.equal(out.posted[0].release,undefined);
 assert.equal(out.posted[0].config,'');assert.ok(out.calls.length);assert.ok(out.calls.every(u=>u.startsWith('https://independent.example/ipfs/')));
});
test('owner transfer or missing manager support prevents launch before posting a guest',async()=>{
 for(const change of [{row:{...row,owner:'0x'+'77'.repeat(20)}},{health:{...health,supports:{}}}]){
  const out=await run('RELEASE_SELFTEST',{bootstrapLaunchSpec:{row,rec,health,appId:manifest.appId,bytes:pkg.bytes.toString('base64'),...change}});
  assert.ok(out.error);assert.equal(out.posted.length,0);
 }
});
test('restart adopts only the same package; stale owner config forces replacement',async()=>{
 for(const [heldHash,replacements]of [[pkg.sha256,0],['aa'.repeat(32),1]]){
  const out=await run('RELEASE_SELFTEST',{bootstrapLaunchSpec:{row,rec,health,appId:manifest.appId,bytes:pkg.bytes.toString('base64'),heldHash}});
  assert.equal(out.error,null);assert.equal(out.deleted.length,replacements);assert.equal(out.posted.length,1+replacements);
 }
});
test('reservation credit requires the same direct package, app and runtime',async()=>{
 const g={ref:manifest.appRef,wasmRef:'ipfs://bafylabcomponent',min:{memMb:128},_bootstrap:pkg};
 const {recordOf}=await run('GUEST_POOL_SELFTEST',{recordOf:{g,runtimeId:manifest.runtimeId,ports:[]}});
 const held={recordSha256:recordOf,directBootstrap:true,bootstrapSha256:pkg.sha256,appId:manifest.appId,runtimeId:manifest.runtimeId};
 const changes=[{}, {directBootstrap:false}, {bootstrapSha256:'aa'.repeat(32)}, {appId:'aa'.repeat(32)}, {runtimeId:'aa'.repeat(32)}];
 const out=await run('GUEST_POOL_SELFTEST',{sameRecord:changes.map(change=>({held:{...held,...change},g,firewall:[],runtimeId:manifest.runtimeId}))});
 assert.deepEqual(out.sameRecord,[true,false,false,false,false]);
});
test('claim gate and envelope audit understand explicit bootstrap without a relay list',async()=>{
 const clean={require:tier,manager:health,guestBootstrap:pkg.intent,gpuMilli:0,cpuMilli:1000,config:manifest.configText,appConfigCid:'',hasSecrets:null,firewall:[],volumes:[],isPublic:true,waf:null,policy:{cpuPercent:100,memMiB:128,vcpus:1},listed:'unknown'};
 const out=await run('ISOLATION_SELFTEST',{parse:[envelope,JSON.stringify({guestBootstrap:pkg.intent,config:{}})],verdicts:[clean,{...clean,guestBootstrap:null},{...clean,manager:{...health,supports:{}}}],edits:[{rec:{_onchain:true,status:'running',_envelope:envelope},chainCid:JSON.stringify({guestBootstrap:{version:1,sha256:'ab'.repeat(32)}})}]});
 assert.equal(out.parse[0].ok,true);assert.equal(out.parse[1].ok,false);assert.equal(out.verdicts[0],null);assert.match(out.verdicts[1],/requires an owner/);assert.match(out.verdicts[2],/does not support/);assert.equal(out.edits[0],'restart');
});

test('direct custody pump signs only the committed vault and never requests a ticket',async()=>{
 const vault='0x'+'88'.repeat(20),binding='ab'.repeat(32);
 const directManifest={...manifest,secretsMode:'custody-v2',custody:{vault}};
 const cfg={id:row.id,vmId:'gd0a0b0c0d',endpoint:'https://host.independent.example',directManifest,
  script:[{status:'starting',awaitingCustodyAuth:{v:2,vault,binding}},{status:'running'}]};
 const out=await run('RELEASE_SELFTEST',cfg,{REGISTRY_PRIVATE_KEY:'0x'+'01'.repeat(32),CUSTODY_VAULT_V2:'0x'+'99'.repeat(20)});
 assert.equal(out.result,'running');assert.equal(out.posts.length,1);assert.match(out.posts[0].path,/custody-auth$/);assert.equal(out.posts[0].custody.binding,binding);
 const wrong=await run('RELEASE_SELFTEST',{...cfg,script:[{status:'starting',awaitingCustodyAuth:{v:2,vault:'0x'+'77'.repeat(20),binding}},{status:'running'}]},{REGISTRY_PRIVATE_KEY:'0x'+'01'.repeat(32)});
 assert.equal(wrong.posts.length,0);assert.ok(wrong.logs.some(x=>x.includes('differs from owner')));
});
