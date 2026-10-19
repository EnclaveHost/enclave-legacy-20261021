import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {publicHostPolicyLoader,hostPolicyOrigins,createHostAdmission} from '../network/host-admission-runtime.mjs';
import {hostAdmissionPolicyHash} from '../network/host-admission-policy.mjs';
const host='0x'+'ab'.repeat(32),other='0x'+'ac'.repeat(32),deployment='0x'+'cd'.repeat(32),app='0x'+'ef'.repeat(32);
const ownership='0x'+'11'.repeat(20),registry='0x'+'22'.repeat(20),catalog='0x'+'33'.repeat(20),owner='0x'+'44'.repeat(20);
const doc={version:1,chainId:8453,ownershipContract:ownership,hostId:host,requireCatalogApproval:false,denyDeployments:[],denyAppRefs:[]};
const request={deploymentId:deployment,appRef:`catalog://${app}/1`};
async function server(handler){
 const s=http.createServer(handler);await new Promise(r=>s.listen(0,'127.0.0.1',r));
 return {origin:`http://127.0.0.1:${s.address().port}`,stop:()=>new Promise(r=>{s.close(r);s.closeAllConnections();})};
}
test('real policy mirrors cannot substitute bytes; verified local cache survives all mirrors failing',async()=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'host-mirrors-')),hash=hostAdmissionPolicyHash(doc);
 let hits=0;
 const bad=await server((q,r)=>r.end(JSON.stringify({...doc,requireCatalogApproval:true})));
 const good=await server((q,r)=>{hits++;assert.equal(q.url,`/${hash}.json`);r.end(JSON.stringify(doc));});
 try{
  const load=publicHostPolicyLoader({directory,origins:[bad.origin,good.origin]});
  assert.deepEqual(await load(hash),doc);assert.equal(hits,1);
  assert.deepEqual(JSON.parse(await fs.readFile(path.join(directory,hash+'.json'))),doc);
  await bad.stop();await good.stop();
  assert.deepEqual(await load(hash),doc);
  await fs.writeFile(path.join(directory,hash+'.json'),JSON.stringify({...doc,requireCatalogApproval:true}));
  await assert.rejects(load(hash),/no hash-matching/);
 }finally{await bad.stop();await good.stop();await fs.rm(directory,{recursive:true,force:true});}
});
test('new wallet commitment fetches a new document without reboot; refusal is scoped to the owner host',async()=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'host-policy-live-'));
 let now=1000000,revision=1,policy=doc,hash=hostAdmissionPolicyHash(policy),available=true;
 const mirror=await server((q,r)=>{if(!available){r.writeHead(404);r.end();return;}r.end(JSON.stringify(policy));});
 const reader={agreed:async fn=>({timestamp:now,...await fn({readContract:async q=>{
  if(q.functionName==='registry')return registry;
  if(q.functionName==='authority')return [owner,owner,BigInt(revision),q.args[0]===host?hash:'0x'+'00'.repeat(32)];
  throw Error('catalog authority must not be consulted');
 }},100n)})};
 try{
  const cfg={ownershipContract:ownership,registry,catalog,reader,now:()=>now,policyDirectory:directory,policyOrigins:[mirror.origin]};
  const local=createHostAdmission({...cfg,hostId:host}),independent=createHostAdmission({...cfg,hostId:other});
  assert.equal(await local.refusal(request),null);
  policy={...doc,denyDeployments:[deployment]};hash=hostAdmissionPolicyHash(policy);revision++;now+=15001;available=false;
  await assert.rejects(local.refusal(request),/no hash-matching/);
  available=true;
  assert.match(await local.refusal(request),/declines/);
  assert.equal(await independent.refusal(request),null);
  available=false;now+=15001;
  assert.match(await local.refusal(request),/declines/); // current verified document is cached
 }finally{await mirror.stop();await fs.rm(directory,{recursive:true,force:true});}
});
test('no implicit authority origin, bounded downloads, no redirects or credentials and no traversal',async()=>{
 assert.deepEqual(hostPolicyOrigins(),[]);assert.deepEqual(hostPolicyOrigins([]),[]);
 for(const origins of [['https://x.test/path'],['https://u:p@x.test'],['file:///tmp/a'],['https://x.test/#foo']])assert.throws(()=>hostPolicyOrigins(origins));
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'host-policy-invalid-'));
 try{
  const hash=hostAdmissionPolicyHash(doc);
  const noNetwork=publicHostPolicyLoader({directory,fetch:()=>{throw Error('unexpected network request');}});
  await assert.rejects(noNetwork(hash),/ENOENT/);
  await assert.rejects(noNetwork('../escape'),/hash required/);
  const load=publicHostPolicyLoader({directory,origins:['https://peer.example'],fetch:async(url,options)=>{
   assert.equal(url,`https://peer.example/${hash}.json`);assert.equal(options.credentials,'omit');assert.equal(options.redirect,'error');assert.ok(options.signal);
   return new Response(' '.repeat(2*1024*1024+1));
  }});
  await assert.rejects(load(hash),/no hash-matching/);assert.deepEqual(await fs.readdir(directory),[]);
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});

test('a withholding mirror is bounded by the deadline and cannot hold admission indefinitely',async()=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'host-policy-withholding-'));
 const mirror=await server(()=>{});
 try{
  const start=Date.now();
  await assert.rejects(publicHostPolicyLoader({directory,origins:[mirror.origin]})(hostAdmissionPolicyHash(doc)),/no hash-matching/);
  assert.ok(Date.now()-start<12000,'eight-second transport deadline was not enforced');
 }finally{await mirror.stop();await fs.rm(directory,{recursive:true,force:true});}
});
