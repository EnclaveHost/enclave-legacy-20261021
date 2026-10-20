import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {catalogAdmissionRefusal} from '../site/js/core/catalog-policy.js';
const approved={active:true,yanked:false,approval:1};
const deploySource=fs.readFileSync(new URL('../site/js/pages/deploy.js',import.meta.url),'utf8');
const begin=deploySource.indexOf('  const catalogRef =',deploySource.indexOf('export async function deployOnChain(spec)'));
const end=deploySource.indexOf('  const capMsg =',begin);
assert.ok(begin>0&&end>begin);
function browserGate({app=approved,version=approved,fail=false,isPublic=true}={}){
 const state={reads:[],messages:[]};
 const ctx=vm.createContext({Promise,catalogAdmissionRefusal,parseCatalogRef:()=>({appId:'app',index:0}),
  catGetApp:async()=>{state.reads.push('app');if(fail)throw Error('RPC unavailable');return app;},
  catGetVersion:async()=>{state.reads.push('version');return version;},showToast:s=>{state.messages.push(s);return 'refused';}});
 const fn=vm.runInContext('(async function(spec){'+deploySource.slice(begin,end)+' return "admitted";})',ctx);
 return {state,run:()=>fn({reference:'catalog://app/0',isPublic})};
}
test('actual browser deployment gate reads current moderation and refuses before downstream spending',async()=>{
 for(const status of [{active:false},{yanked:true},{approval:2}])for(const isPublic of [true,false]){
  const x=browserGate({app:{...approved,...status},version:{...approved,...status},isPublic});
  assert.equal(await x.run(),'refused');assert.deepEqual(x.state.reads,['app','version']);
 }
 assert.equal(await browserGate().run(),'admitted');
 assert.equal(await browserGate({fail:true}).run(),'refused');
 assert.equal(await browserGate({version:{...approved,approval:0}}).run(),'refused');
 assert.equal(await browserGate({version:{...approved,approval:0},isPublic:false}).run(),'admitted');
});
test('actual Windows wallet gate passes only ledger-authoritative private visibility',async()=>{
 const source=fs.readFileSync(new URL('../windows/node/host.mjs',import.meta.url),'utf8');
 const start=source.indexOf('  async walletPolicyRefusal(d)'),end=source.indexOf('  claimRefusal(',start);
 const ctx=vm.createContext({String});const Class=vm.runInContext('(class Host {'+source.slice(start,end)+'})',ctx);
 const host=new Class(),seen=[];host.hostAdmission={refusal:async q=>{seen.push(q);return null;}};
 for(const isPublic of [false,true,undefined,'false']){
  await host.walletPolicyRefusal({id:'id',appRef:'ref',isPublic});assert.equal(seen.at(-1).forPrivate,isPublic===false);
 }
 host.hostAdmission.refusal=async()=>{throw Error('quorum unavailable');};
 assert.match(await host.walletPolicyRefusal({}),/unavailable/);
});
