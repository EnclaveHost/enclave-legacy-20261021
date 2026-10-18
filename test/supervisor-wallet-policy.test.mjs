// Execute the actual supervisor gates with local chain/process adapters. No
// listener, public RPC, signing key or production self-test bypass is involved.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../supervisor.js',import.meta.url),'utf8');
function between(start,end){const a=source.indexOf(start),b=source.indexOf(end,a+start.length);assert.ok(a>=0&&b>a);return source.slice(a,b);}
const host='0x'+'ab'.repeat(32),dep='0x'+'cd'.repeat(32),app='0x'+'ef'.repeat(32),catalog='0x'+'12'.repeat(20),ref=`catalog://${app}/1`;
function fixture(){
 const state={reason:null,reads:[],requests:[],events:[],fail:false};
 const ctx=vm.createContext({console,Date,Number,BigInt,Set,Map,Error,String,
   HOST_WALLET_POLICY:true,_enclaveId:host,
   _hostWalletAdmission:{hostId:host,refusal:async q=>{state.requests.push(q);if(state.fail)throw Error('quorum unavailable');if(q.deploymentId!==dep)throw Error('exact deployment id required');return state.reason;}},
   hostCatalogAddress:()=>catalog,CATALOG_REF_RE:/^catalog:\/\/(0x[0-9a-fA-F]{64})\/(\d{1,9})$/,ZERO32:'0x'+'00'.repeat(32),CATALOG_ABI:[],
   getAddress:a=>a,catSchemaRev:async()=>7,gpuOptionalOfConfig:()=>false,cpuFallbackOfConfig:()=>null,
   approvalVerdict:()=>{throw Error('global approval must not be consulted');},
   chainClient:{readContract:async q=>{state.reads.push(q);assert.equal(q.address,catalog);
     if(q.functionName==='getApp')return {appId:app,versionCount:2,active:false,publisher:catalog,slug:'test'};
     if(q.functionName==='getVersion')return {cid:'verified-cid',version:'1',active:false,yanked:true,approval:2,config:'{}'};
     if(q.functionName==='versionFee')return 0n;if(q.functionName==='versionConfigCid')return '';throw Error('unexpected read');}},
   _reach:{tripped:false},RENEW_MARGIN_SEC:900,claimSigner:()=>({account:{address:catalog}}),tenantProvisions:new Set(),
   placementRefusal:()=>null,readLedgerContract:async()=>({appRef:ref}),
   stopContainer:async()=>{state.events.push('stop');},proveAndRelease:async()=>{state.events.push('release');},saveStateSoon:()=>{},
   sendClaimTx:()=>{throw Error('denied work must not renew');},_yankBusy:false,
 });
 vm.runInContext(between('async function hostWalletRefusal(', '\nconst hostCatalogAddress='),ctx);
 vm.runInContext(between('async function gateAppReference(', '// A paid app is servable'),ctx);
 vm.runInContext(between('async function retireForPlacement(', '\nfunction parseDepOptions('),ctx);
 vm.runInContext(between('async function renewLeases()', '\nasync function switchTenantVersion('),ctx);
 vm.runInContext(between('async function auditClaims(', '\nasync function fetchLedger('),ctx);
 vm.runInContext(between('async function yankSweep()', '\nasync function auditClaims('),ctx);
 return {state,ctx};
}
test('Linux admission permits rejected, delisted and yanked catalog metadata when the host wallet allows it',async()=>{
 const {state,ctx}=fixture();const result=await ctx.gateAppReference(ref,{deploymentId:dep});
 assert.equal(result.error,undefined);assert.equal(result.wasmRef,'ipfs://verified-cid');assert.equal(state.requests[0].deploymentId,dep);
 assert.equal(state.reads.length,4);
});
test('Linux admission rejects host denial, missing identity and unreadable authority without global fallback',async()=>{
 const {state,ctx}=fixture();state.reason='this host owner declines this deployment';
 assert.match((await ctx.gateAppReference(ref,{deploymentId:dep})).error.msg,/declines/);
 state.fail=true;assert.match((await ctx.gateAppReference(ref,{deploymentId:dep})).error.msg,/unavailable.*quorum/);
 state.fail=false;state.reason=null;assert.match((await ctx.gateAppReference(ref,{})).error.msg,/deployment id required/);
 ctx._enclaveId=null;assert.match((await ctx.gateAppReference(ref,{deploymentId:dep})).error.msg,/identity unavailable/);
});
test('Linux audit and renewal stop before releasing a denied deployment, and do not renew it',async()=>{
 for(const action of ['audit','renew']){
  const {state,ctx}=fixture();state.reason='this host owner declines this deployment';
  const rec={id:dep,status:'running',_onchain:true,_leaseUntil:Math.floor(Date.now()/1000)+100,image:{reference:ref}};
  ctx.deployments=new Map([[dep,rec]]);
  if(action==='audit')await ctx.auditClaims(new Map([[dep,{appRef:ref}]]));else await ctx.renewLeases();
  assert.deepEqual(state.events,['stop','release']);assert.equal(rec.status,'terminated');assert.match(rec.error,/declines/);
 }
});
test('wallet-mode yank sweep cannot impose a second global veto',async()=>{
 const {state,ctx}=fixture();await ctx.yankSweep();assert.equal(state.reads.length,0);assert.deepEqual(state.events,[]);
});
