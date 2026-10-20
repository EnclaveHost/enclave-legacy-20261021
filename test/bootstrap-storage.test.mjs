import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {privateKeyToAccount} from 'viem/accounts';
import {recoverMessageAddress} from 'viem';
import {preparePackage} from '../sdk/bootstrap/package.mjs';
import {publishPackageReplicas,verifyPackageReplicas,validateStoragePlan} from '../sdk/bootstrap/storage.mjs';
import {uploadMessage} from '../sdk/storage/upload-auth.mjs';
const pkg=preparePackage(JSON.parse(JSON.parse(fs.readFileSync(new URL('../isolation/m2/bootstrap/testdata/vectors.json',import.meta.url))).manifest));
const signer=privateKeyToAccount('0x'+'42'.repeat(32));
const plan={version:1,minimumCopies:2,replicas:[1,2,3].map(n=>({upload:`https://storage${n}.example/add-json`,gateway:`https://storage${n}.example/ipfs`,audience:'0x'+String(n).repeat(64)}))};
test('two verified adapters can publish despite one refusal; signatures bind each deployment and exact bytes',async()=>{
 const calls=[];
 const report=await publishPackageReplicas(pkg.bytes,{},plan,signer,{fetchImpl:async(url,opts)=>{
  calls.push({url,...opts});const i=plan.replicas.findIndex(r=>url.startsWith(new URL(r.upload).origin));
  if(i===0)return new Response('refused',{status:503});
  assert.equal(opts.redirect,'error');
  if(opts.method==='POST'){
   const h=opts.headers;assert.deepEqual(opts.body,pkg.bytes);
   const message=uploadMessage({audience:plan.replicas[i].audience,path:'/add-json',address:h['x-upload-address'],hash:h['x-upload-sha256'],size:opts.body.length,expiry:Number(h['x-upload-expiry'])});
   assert.equal(await recoverMessageAddress({message,signature:h['x-upload-signature']}),signer.address);
   return new Response(JSON.stringify({cid:pkg.cid}));
  }
  assert.equal(opts.cache,'no-store');return new Response(pkg.bytes);
 }});
 assert.equal(report.verifiedCopies,2);assert.equal(report.failures.length,1);assert.equal(report.independentOperatorsVerified,false);
 assert.equal(calls.filter(c=>c.method==='POST').length,3);
});
test('an upload acknowledgement without correct independent readback never counts',async()=>{
 for(const broken of ['missing','corrupt','oversize','wrong-cid','duplicate-cid']){
  await assert.rejects(()=>publishPackageReplicas(pkg.bytes,{},plan,signer,{fetchImpl:async(url,opts)=>{
   const good=url.includes('storage3.');
   if(opts.method==='POST')return new Response(!good&&broken==='duplicate-cid'?`{"cid":"bad","cid":"${pkg.cid}"}`:JSON.stringify({cid:!good&&broken==='wrong-cid'?'bad':pkg.cid}));
   return good?new Response(pkg.bytes):broken==='missing'?new Response('',{status:404}):new Response(broken==='oversize'?'x'.repeat(128*1024+1):'{}');
  }}),e=>e.report.verifiedCopies===1&&e.report.failures.length===2);
 }
});
test('activation checks current availability again and rejects loss below the required copies',async()=>{
 let refused=0;
 const fetchImpl=async url=>new Response(url.includes(`storage${refused}.`)?'{}':pkg.bytes);
 assert.equal((await verifyPackageReplicas(pkg.bytes,{},plan,{fetchImpl})).verifiedCopies,3);
 refused=1;assert.equal((await verifyPackageReplicas(pkg.bytes,{},plan,{fetchImpl})).verifiedCopies,2);
 await assert.rejects(()=>verifyPackageReplicas(pkg.bytes,{},plan,{fetchImpl:async url=>new Response(url.includes('storage3.')?pkg.bytes:'{}')}),/1\/2/);
});
test('duplicates, weak copy counts, redirecting readback origins and bad package scope fail before signing or HTTP',async()=>{
 let operations=0;const no={address:signer.address,signMessage:()=>{operations++;throw Error('must not sign');}};
 const bads=[{...plan,minimumCopies:1},{...plan,minimumCopies:4},{...plan,version:2},{...plan,extra:true},
  {...plan,replicas:[plan.replicas[0],plan.replicas[0]]},
  {...plan,replicas:plan.replicas.map((r,i)=>i?{...r,audience:plan.replicas[0].audience}:r)},
  {...plan,replicas:plan.replicas.map(r=>({...r,gateway:'https://shared.example/ipfs'}))},
  {...plan,replicas:plan.replicas.map(r=>({...r,upload:r.upload+'?token=x'}))},
  {...plan,replicas:plan.replicas.map(r=>({...r,audience:'0x'+'0'.repeat(64)}))}];
 for(const bad of bads){assert.throws(()=>validateStoragePlan(bad));await assert.rejects(()=>publishPackageReplicas(pkg.bytes,{},bad,no));}
 await assert.rejects(()=>publishPackageReplicas(pkg.bytes,{owner:'0x'+'ab'.repeat(20)},plan,no));
 assert.equal(operations,0);
});
test('one hanging adapter is bounded and does not veto two available copies',async()=>{
 const start=Date.now();
 const report=await verifyPackageReplicas(pkg.bytes,{},plan,{timeoutMs:40,fetchImpl:async(url,{signal})=>{
  if(!url.includes('storage1.'))return new Response(pkg.bytes);
  return new Promise((_,reject)=>{const hold=setTimeout(()=>reject(Error('deadline did not fire')),1000);signal.addEventListener('abort',()=>{clearTimeout(hold);reject(signal.reason);},{once:true});});
 }});
 assert.equal(report.verifiedCopies,2);assert(Date.now()-start<500);
});
