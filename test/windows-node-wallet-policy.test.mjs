import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fakeBaseRpc,DEPLOYMENTS,CATALOG} from './helpers/fake-base-rpc.mjs';
process.env.NODE_OPERATOR_KEY='0x'+'7f'.repeat(32);
const rpc=await fakeBaseRpc();
const chain=await import('../windows/node/chain.mjs');
chain.addresses.deployments=DEPLOYMENTS;chain.addresses.appCatalog=CATALOG;chain.loadOperator();
const {Host}=await import('../windows/node/host.mjs');
const dirs=[];after(()=>{rpc.close();for(const dir of dirs)fs.rmSync(dir,{recursive:true,force:true});});
const id='0x'+'ab'.repeat(32),ref='catalog://0x'+'cd'.repeat(32)+'/1',endpoint='https://api.enclave.host/t/wallet-policy-test';
const version={cid:'bafy',version:'1',vramMb:0,gpuGflops:0,memMb:512,cpuGflops:0,createdAt:1n,verified:true,yanked:true,ports:'',approval:2,config:'{}'};
const box=async refusal=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'host-wallet-test-'));dirs.push(dir);
 const h=new Host({dir,endpoint,name:'test',appsEnabled:true,vcpus:8,ramGb:16,cpuPricePerSec6:0,
   hostAdmission:{hostId:chain.enclaveIdOf(endpoint),refusal}});
 h.chainReady=true;h.registered={cpuPricePerSec6:'0'};await h.refreshOwners();return h;
};
const row=h=>({id,owner:chain.operatorAddress(),appRef:ref,ports:'',configCid:'',gpuMilli:0,cpuMilli:100,appPort:8000,isPublic:true,
 active:true,createdAt:1n,rate:1n,balance6:1000000n,spent6:0n,runner:h.enclaveId,runnerOperator:chain.operatorAddress(),
 leaseUntil:BigInt(Math.floor(Date.now()/1000)+3600)});
test('a wallet denial refuses a forced claim before starting or spending',async()=>{
 const h=await box(async()=> 'this host owner declines this deployment');rpc.row.current=row(h);rpc.catalog.current=version;
 const before=rpc.chainTx.sent.length;const r=await h.consider(id,{force:true});
 assert.equal(r.accepted,false);assert.match(r.reason,/host owner declines/);assert.equal(rpc.chainTx.sent.length,before);
});
test('a permissive wallet cannot override catalog rejection or publisher yank',async()=>{
 for(const status of [{approval:2,yanked:false},{approval:1,yanked:true}]){
  const h=await box(async()=>null);rpc.row.current=row(h);rpc.catalog.current={...version,...status};
  let launched=false;h.ensureApp=async()=>{launched=true;return {status:'running'};};
  const before=rpc.chainTx.sent.length;
  const r=await h.consider(id);assert.equal(r.accepted,false);assert.equal(launched,false);
  assert.match(r.reason,/rejected|yanked/);assert.equal(rpc.chainTx.sent.length,before);
 }
});
test('policy refresh in the live tick stops and releases local work before renewal; no permanent block',async()=>{
 const h=await box(async()=> 'this host owner declines this deployment');rpc.row.current=row(h);rpc.catalog.current=version;rpc.chainTx.mine=true;
 for(const name of ['followBook','enforceOff','ensureRegistered','ensurePriced','scanLedger','retireForeignRecovered'])h[name]=async()=>{};
 let stopped=0;h.apps.set(id,{stop:async()=>{stopped++;}});h.tracked.add(id);h.records.set(id,{id,status:'running',appRef:ref,isolationRequired:false});
 const before=rpc.chainTx.sent.length;await h.tick();
 assert.equal(stopped,1);assert.equal(h.apps.has(id),false);assert.equal(h.tracked.has(id),false);assert.equal(h.blocked.has(id),false);
 assert.equal(rpc.chainTx.sent.length,before+1);assert.match(h.records.get(id).reason,/host owner declines/);
});
test('direct/forced ensure cannot bypass an unavailable authority',async()=>{
 const h=await box(async()=>{throw Error('chain quorum unavailable');});rpc.row.current={...row(h),runner:'0x'+'00'.repeat(32)};
 let stopped=0;h.apps.set(id,{stop:async()=>{stopped++;}});h.records.set(id,{id,isolationRequired:false});
 const rec=await h.ensureApp(id,row(h),{force:true,version});assert.equal(stopped,1);assert.match(rec.reason,/wallet policy unavailable.*quorum/);
});
