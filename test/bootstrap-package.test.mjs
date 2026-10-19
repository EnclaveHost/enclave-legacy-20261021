import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {bootstrapIntent,packageCID,preparePackage,verifyPackage,fetchPackage,readBoundedResponse,parseUniqueJSON,MAX_PACKAGE_BYTES} from '../sdk/bootstrap/package.mjs';
const v=JSON.parse(fs.readFileSync(new URL('../isolation/m2/bootstrap/testdata/vectors.json',import.meta.url)));
const hash=b=>createHash('sha256').update(b).digest('hex');
const intent=b=>({version:1,sha256:hash(b)});
test('JS accepts Go public and custody vectors and names the exact raw CID',()=>{
 for(const raw of [v.manifest,v.custodyManifest])assert.equal(verifyPackage(Buffer.from(raw),intent(raw)).manifest.configText,JSON.parse(raw).configText);
 assert.equal(packageCID(hash(v.manifest)),'bafkreiflr2ulroik7wvu4kqvxhggtdm4lun7vjt62b2h2wmvyiwl5zpkvm');
 const p=preparePackage(JSON.parse(v.manifest));assert.equal(p.bytes.toString(),v.manifest);
});
test('ambiguous JSON, oversized documents, changed bytes and changed owner scope fail',()=>{
 for(const raw of ['{"a":1,"a":2}','{"a":{"x":1,"\\u0078":2}}','[ {"a":1,"a":2} ]', '['.repeat(66)+'0'+']'.repeat(66)])assert.throws(()=>parseUniqueJSON(raw));
 assert.throws(()=>verifyPackage(Buffer.from(v.manifest+' '),intent(v.manifest)),/hash/);
 assert.throws(()=>verifyPackage(Buffer.alloc(MAX_PACKAGE_BYTES+1),{}),/size/);
 for(const scope of [{owner:'0x'+'ab'.repeat(20)},{deployment:'0x'+'ab'.repeat(32)},{runtimeId:'ab'.repeat(32)},{ledger:'0x'+'ab'.repeat(20)},{chainId:1}])assert.throws(()=>verifyPackage(Buffer.from(v.manifest),intent(v.manifest),scope),/mismatch/);
 for(const changes of [{version:2},{secretsMode:'legacy'},{secretsMode:'custody-v2'},{custody:{}},{appId:'0'.repeat(64)},{configText:'{"a":1,"a":2}'},{Version:1},{configText:'false'}])assert.throws(()=>preparePackage({...JSON.parse(v.manifest),...changes}));
});
test('startup intent cannot be confused with legacy config or duplicate fields',()=>{
 const good={guestBootstrap:intent(v.manifest)};
 assert.deepEqual(bootstrapIntent(JSON.stringify(good)),good.guestBootstrap);
 for(const x of [{...good,config:{}},{...good,configCid:'bafy'},{guestBootstrap:{...good.guestBootstrap,Version:1}},{guestBootstrap:{version:1,sha256:'0'.repeat(64)}}])assert.throws(()=>bootstrapIntent(JSON.stringify(x)));
 assert.throws(()=>bootstrapIntent('{"guestBootstrap":{},"guestBootstrap":'+JSON.stringify(good.guestBootstrap)+'}'));
});
test('unavailable or malicious gateways cannot override the valid committed bytes',async()=>{
 const p=await fetchPackage(intent(v.manifest),{}, {gateways:['https://down.example/ipfs','https://liar.example/ipfs','https://independent.example/ipfs'],fetchImpl:async url=>{
  if(url.includes('down'))throw Error('refused');
  return new Response(url.includes('liar')?'{}':v.manifest);
 }});assert.equal(p.bytes.toString(),v.manifest);
 await assert.rejects(()=>fetchPackage(intent(v.manifest),{}, {gateways:['https://liar.example/ipfs'],fetchImpl:async()=>new Response('x'.repeat(MAX_PACKAGE_BYTES+1))}),/no gateway/);
 for(const gateway of ['http://insecure.example','https://user:password@example.test/ipfs','https://example.test/ipfs?token=x'])await assert.rejects(()=>fetchPackage(intent(v.manifest),{}, {gateways:[gateway]}),/HTTPS/);
});
test('upload response bounds apply with missing or dishonest length headers',async()=>{
 for(const headers of [{},{'content-length':'1'},{'content-length':'999999'}])await assert.rejects(()=>readBoundedResponse(new Response('x'.repeat(4097),{headers}),4096),/size limit/);
 assert.equal((await readBoundedResponse(new Response('{"cid":"test"}'),4096)).toString(),'{"cid":"test"}');
 const bytes=Buffer.concat([Buffer.from(v.manifest.slice(0,-1)),Buffer.from([0xff]),Buffer.from('}')]);
 assert.throws(()=>verifyPackage(bytes,intent(bytes)),/encoded data/);
});
