import test from 'node:test';
import assert from 'node:assert/strict';
import {artifactGateways,createArtifactGatewayProbe} from '../sdk/storage/gateways.mjs';
const cid='bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e';
test('artifact recovery accepts the same explicit JSON gateway list as guestd without adding an Enclave fallback',async()=>{
 const calls=[],value='["https://down.example","https://available.example"]';
 const probe=createArtifactGatewayProbe({gateways:value,fetchImpl:async(url,opts)=>{calls.push(url);assert.equal(opts.redirect,'error');return new Response('',{status:url.includes('down')?503:206});}});
 assert.equal(await probe(cid),true);assert.equal(calls.length,2);assert(calls.every(u=>!u.includes('enclave.host')));
 calls.length=0;assert.equal(await probe(cid),true);assert.deepEqual(calls,[`https://available.example/ipfs/${cid}`]);
});
test('one hung gateway cannot delay an available replica, and canceled peers are not marked as failed',async()=>{
 let now=0;const calls=[];
 const probe=createArtifactGatewayProbe({gateways:['https://slow.example','https://fast.example'],now:()=>now,timeoutMs:500,fetchImpl:async(url,{signal})=>{
  calls.push(url);if(url.includes('fast'))return new Response('',{status:200});
  return new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}));
 }});
 const before=Date.now();assert.equal(await probe(cid),true);assert(Date.now()-before<300);
 now=1;await probe(cid);assert.equal(calls.filter(u=>u.includes('slow')).length,2);
});
test('malformed gateway plans and injected CID paths are refused',async()=>{
 for(const value of ['[]','["https://x","https://x/"]','[null]','https://user:secret@x','https://x/?key=y','file:///tmp/a'])assert.throws(()=>artifactGateways(value));
 let calls=0;const probe=createArtifactGatewayProbe({gateways:'https://storage.example',fetchImpl:()=>{calls++;throw Error();}});
 for(const bad of ['../../control','bafkreifz?other=1',''])assert.equal(await probe(bad),false);assert.equal(calls,0);
});
