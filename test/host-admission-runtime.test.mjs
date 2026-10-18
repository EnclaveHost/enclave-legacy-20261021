import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createHostAdmission,fileHostPolicyLoader,hostAdmissionFromEnv} from '../network/host-admission-runtime.mjs';
import {hostAdmissionPolicyHash} from '../network/host-admission-policy.mjs';
const host='0x'+'ab'.repeat(32),deployment='0x'+'cd'.repeat(32),app='0x'+'ef'.repeat(32);
const ownership='0x'+'11'.repeat(20),registry='0x'+'22'.repeat(20),catalog='0x'+'33'.repeat(20),owner='0x'+'44'.repeat(20);
const request={deploymentId:deployment,appRef:`catalog://${app}/1`};
const document={version:1,chainId:8453,ownershipContract:ownership,hostId:host,requireCatalogApproval:false,denyDeployments:[],denyAppRefs:[]};
function setup(){
 const state={now:1000000,owner,hash:hostAdmissionPolicyHash(document),revision:1,doc:document,registry,reads:[],failure:false,
   catalog:{active:false,approval:2,yanked:true}};
 const client={readContract:async q=>{
   state.reads.push(q);assert.equal(q.blockNumber,100n);
   if(q.functionName==='registry')return state.registry;
   if(q.functionName==='authority')return [state.owner,owner,BigInt(state.revision),state.hash];
   assert.equal(q.address,catalog);
   if(q.functionName==='getApp')return {appId:app,versionCount:2,...state.catalog};
   if(q.functionName==='getVersion')return state.catalog;
   throw Error('unexpected read');
 }};
 const reader={agreed:async fn=>{if(state.failure)throw Error('chain quorum unavailable');return {timestamp:state.now,...await fn(client,100n)};}};
 const config={hostId:host,ownershipContract:ownership,registry,catalog,reader,loadPolicy:async()=>state.doc,now:()=>state.now};
 return {state,config,admission:createHostAdmission(config)};
}
test('independent owner can serve a rejected/yanked/delisted version without any catalog authority read',async()=>{
 const {state,admission}=setup();assert.equal(await admission.refusal(request),null);
 assert.deepEqual(state.reads.map(q=>q.functionName).sort(),['authority','registry']);
});
test('catalog governance becomes local policy only through the current wallet commitment',async()=>{
 const {state,admission}=setup();state.doc={...document,requireCatalogApproval:true};state.hash=hostAdmissionPolicyHash(state.doc);
 assert.match(await admission.refusal(request),/requires current catalog approval/);
 state.catalog={active:true,approval:1,yanked:false};assert.equal(await admission.refusal(request),null);
});
test('wallet denial revokes admission after bounded cache; transfer clears old policy',async()=>{
 const {state,admission}=setup();assert.equal(await admission.refusal(request),null);
 state.doc={...document,denyDeployments:[deployment]};state.hash=hostAdmissionPolicyHash(state.doc);state.revision++;
 state.now+=15001;assert.match(await admission.refusal(request),/declines/);
 state.owner='0x'+'55'.repeat(20);state.hash='0x'+'00'.repeat(32);state.revision++;state.now+=15001;
 assert.equal(await admission.refusal(request),null);
});
test('authority failure, mismatched registry, foreign documents and missing ownership fail closed',async()=>{
 for(const mutate of [s=>{s.failure=true;},s=>{s.registry=owner;},s=>{s.doc={...document,hostId:deployment};},s=>{s.owner='0x'+'00'.repeat(20);}]){
  const {state,admission}=setup();mutate(state);await assert.rejects(admission.refusal(request));
 }
 const {state,admission}=setup();await admission.refusal(request);state.now+=15001;state.failure=true;
 await assert.rejects(admission.refusal(request),/quorum/);state.failure=false;
 state.doc={...document,denyDeployments:[deployment]};state.hash=hostAdmissionPolicyHash(state.doc);
 assert.match(await admission.refusal(request),/declines/);
});
test('documents are hash-addressed, bounded, and partial activation configuration refuses startup',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'host-policy-'));
 try {
  const hash=hostAdmissionPolicyHash(document);await fs.writeFile(path.join(dir,hash+'.json'),JSON.stringify(document));
  assert.deepEqual(await fileHostPolicyLoader(dir)(hash),document);
  await assert.rejects(fileHostPolicyLoader(dir)('../anything'),/hash/);
  await fs.writeFile(path.join(dir,hash+'.json'),Buffer.alloc(2*1024*1024+1));
  await assert.rejects(fileHostPolicyLoader(dir)(hash),/too large/);
 }finally{await fs.rm(dir,{recursive:true,force:true});}
 assert.equal(hostAdmissionFromEnv({env:{}}),null);
 assert.throws(()=>hostAdmissionFromEnv({env:{ENCLAVE_HOST_OWNERSHIP:ownership}}),/incomplete/);
});
