import test from 'node:test';
import assert from 'node:assert/strict';
import {egressProbeUrls,probeEgressUrls} from '../network/egress-probes.mjs';
import {WgControlTransport} from '../network/wg-control.mjs';
test('default egress probes come from operator RPC origins, never Enclave',()=>{
 assert.deepEqual(egressProbeUrls(undefined,['https://rpc.one.example/key','https://rpc.two.example/path']),['https://rpc.one.example/','https://rpc.two.example/']);
 assert.deepEqual(egressProbeUrls(['https://one.example/health','https://two.example/health']),['https://one.example/health','https://two.example/health']);
 for(const value of [[],['https://one.example'],['https://one.example/a','https://one.example/b'],['http://one.example','https://two.example'],['https://user:pass@one.example','https://two.example'],Array(9).fill('https://one.example')])assert.throws(()=>egressProbeUrls(value));
});
test('one probe refusal cannot take down healthy egress and a hung sibling is cancelled',async()=>{
 const calls=[];let cancelled=false;
 const fetch=async(url,{signal})=>{
  calls.push(url.hostname);
  if(url.hostname==='one.example')return new Response('',{status:503});
  if(url.hostname==='two.example')return new Response('',{status:405});
  return new Promise((_r,reject)=>signal.addEventListener('abort',()=>{cancelled=true;reject(Error('cancelled'));},{once:true}));
 };
 await probeEgressUrls(fetch,egressProbeUrls(['https://one.example','https://two.example','https://three.example']));
 assert.equal(calls.length,3);assert.equal(cancelled,true);
});
test('all unreachable or failed destinations refuse egress readiness',async()=>{
 await assert.rejects(probeEgressUrls(async()=>new Response('',{status:503}),['https://one.example','https://two.example']),AggregateError);
 await assert.rejects(probeEgressUrls(async()=>{throw Error('offline');},['https://one.example','https://two.example']),AggregateError);
 await assert.rejects(probeEgressUrls(async()=>{},[]),/configure/);
});
test('control transport has no implicit Enclave API probe',()=>{
 assert.throws(()=>new WgControlTransport({}),/probe URLs required/);
 const c=new WgControlTransport({probeUrls:['http://203.0.113.1:8188/v1/network/providers']});assert.equal(c.probeUrls.length,1);
});
