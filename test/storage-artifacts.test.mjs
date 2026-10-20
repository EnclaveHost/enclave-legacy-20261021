import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {privateKeyToAccount} from 'viem/accounts';
import {recoverMessageAddress} from 'viem';
import {artifactIdentity,CHUNK_BYTES} from '../sdk/storage/unixfs.mjs';
import {publishArtifactReplicas,verifyArtifactReplicas} from '../sdk/storage/artifacts.mjs';
import {uploadMessage} from '../sdk/storage/upload-auth.mjs';
const signer=privateKeyToAccount('0x'+'42'.repeat(32));
const plan={version:1,minimumCopies:2,replicas:[1,2,3].map(n=>({upload:`https://storage${n}.example/add-json`,gateway:`https://storage${n}.example/ipfs`,audience:'0x'+String(n).repeat(64)}))};
const data=Buffer.alloc(5*1024*1024+7,0xab);
function rangeResponse(url,opts,bytes=data){
 const match=/^bytes=(\d+)-(\d+)$/.exec(opts.headers.range),start=Number(match[1]),end=Number(match[2]);
 return new Response(bytes.subarray(start,end+1),{status:206,headers:{'content-range':`bytes ${start}-${end}/${bytes.length}`}});
}
test('canonical file identities match a fresh offline Kubo across chunk and balanced-tree boundaries',{skip:!process.env.KUBO_BIN},t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'enclave-cid-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const env={...process.env,IPFS_PATH:dir+'/repo'};execFileSync(process.env.KUBO_BIN,['init','--empty-repo'],{env,stdio:'ignore'});
 for(const size of [0,1,CHUNK_BYTES-1,CHUNK_BYTES,CHUNK_BYTES+1,CHUNK_BYTES*174,CHUNK_BYTES*174+1,CHUNK_BYTES*175+13]){
  const bytes=Buffer.alloc(size,0x5a);if(size)bytes[size-1]=0xab;
  const expected=execFileSync(process.env.KUBO_BIN,['add','--offline','--only-hash','--cid-version=1','--quieter'],{env,input:bytes,encoding:'utf8',maxBuffer:1024*1024}).trim();
  const identity=artifactIdentity(bytes);assert.equal(identity.cid,expected,`size ${size}`);assert.equal(identity.bytes,size);
  assert.equal(identity.sha256,createHash('sha256').update(bytes).digest('hex'));
 }
});
test('artifact publication streams bounded chunks, binds the local CID and verifies every range despite one refusal',async()=>{
 const expected=artifactIdentity(data),calls=[];
 const report=await publishArtifactReplicas(data,'wasm',plan,signer,{fetchImpl:async(url,opts)=>{
  calls.push({url,method:opts.method,range:opts.headers.range});
  const index=plan.replicas.findIndex(r=>url.startsWith(new URL(r.upload).origin));
  if(index===0)return new Response('refused',{status:503});
  if(opts.method==='POST'){
   assert(url.endsWith('/add-wasm'));assert.equal(opts.duplex,'half');assert.equal(opts.headers['content-length'],String(data.length));
   const hash=createHash('sha256');let size=0;
   for await(const chunk of opts.body){assert(chunk.length<=CHUNK_BYTES);size+=chunk.length;hash.update(chunk);}
   assert.equal(size,data.length);assert.equal(hash.digest('hex'),expected.sha256);
   const h=opts.headers,message=uploadMessage({audience:plan.replicas[index].audience,path:'/add-wasm',address:h['x-upload-address'],hash:h['x-upload-sha256'],size,expiry:Number(h['x-upload-expiry'])});
   assert.equal(await recoverMessageAddress({message,signature:h['x-upload-signature']}),signer.address);
   return new Response(JSON.stringify({cid:expected.cid}));
  }
  return rangeResponse(url,opts);
 }});
 assert.equal(report.verifiedCopies,2);assert.equal(report.cid,expected.cid);assert.equal(report.bytes,data.length);
 assert(report.copies.every(r=>r.upload.endsWith('/add-wasm')));assert.equal(calls.filter(c=>c.range).length,4);
});
test('changed bytes, truncated or oversized ranges, wrong totals and ignored ranges cannot satisfy retention',async()=>{
 for(const mode of ['corrupt','short','overlong','wrong-range','ignore']){
  await assert.rejects(()=>verifyArtifactReplicas(data,plan,{fetchImpl:async(url,opts)=>{
   if(url.includes('storage3.'))return rangeResponse(url,opts);
   const match=/bytes=(\d+)-(\d+)/.exec(opts.headers.range),start=Number(match[1]),end=Number(match[2]);
   const b=Buffer.from(data.subarray(start,end+1));
   if(mode==='corrupt')b[0]^=1;
   return new Response(mode==='short'?b.subarray(1):mode==='overlong'?Buffer.concat([b,Buffer.from([1])]):b,{status:mode==='ignore'?200:206,headers:{'content-range':`bytes ${start}-${end}/${mode==='wrong-range'?data.length+1:data.length}`}});
  }}),e=>e.report.verifiedCopies===1);
 }
});
test('another CID returned by an uploader is rejected before readback',async()=>{
 let gets=0;await assert.rejects(()=>publishArtifactReplicas(Buffer.from('{}'),'json',plan,signer,{fetchImpl:async(url,opts)=>{if(opts.method!=='POST')gets++;return new Response('{"cid":"bafkreiwrong"}');}}),/0\/2/);assert.equal(gets,0);
});
