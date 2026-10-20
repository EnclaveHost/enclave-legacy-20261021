import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';
import {catalogAdmissionRefusal,catalogAdmissionNotice} from '../site/js/core/catalog-policy.js';
const source=fs.readFileSync(new URL('../site/js/core/catalog.js',import.meta.url),'utf8');
const helpers=source.slice(source.indexOf('export const appPrivileged'),source.indexOf('export function selIdx'));
const resolver=source.slice(source.indexOf('export function resolveAppRef'),source.indexOf('// A mid-session address-book'));
const publisher='0x'+'12'.repeat(20),admin='0x'+'34'.repeat(20),id='0x'+'cd'.repeat(32);
function rig(){
 const app={active:true,publisher,appId:id,slug:'demo',versions:[{version:'1',yanked:false,approval:1},{version:'2',yanked:false,approval:2},{version:'3',yanked:true,approval:1},{version:'4',yanked:false,approval:0}]};
 const ctx=vm.createContext({Enclave:{address:''},STORE:{owner:admin,apps:[app],loaded:true},APPROVAL:{approved:1,rejected:2,pending:0},catalogAdmissionRefusal,catalogAdmissionNotice,
 REF_CACHE:{},PORTS_CACHE:{},SPECS_CACHE:{},MANIFEST_CACHE:{},CONFIG_CACHE:{},CONFIG_CID_CACHE:{},looksFriendly:s=>s.includes(':'),catalogRef:(a,i)=>`catalog://${a}/${i}`,specOf:()=>({}),minPctsOf:()=>({}),stripMedia:s=>s});
 vm.runInContext((helpers+'\n'+resolver).replaceAll('export ',''),ctx);return {app,ctx,eval:s=>vm.runInContext(s,ctx)};
}
test('public catalog hides rejected/yanked releases and delisted apps; moderation roles retain history',()=>{
 const r=rig();assert.deepEqual(Array.from(r.eval('visibleVerIdxs(STORE.apps[0])')),[0,3]);
 r.app.active=false;assert.deepEqual(Array.from(r.eval('visibleVerIdxs(STORE.apps[0])')),[]);
 for(const address of [publisher,admin]){r.ctx.Enclave.address=address;assert.deepEqual(Array.from(r.eval('visibleVerIdxs(STORE.apps[0])')),[0,1,2,3]);}
});
test('explicit private-development selection does not cache a permission to deploy publicly',()=>{
 const r=rig();assert.ok(r.ctx.resolveAppRef('demo:4').error);
 assert.equal(r.ctx.resolveAppRef('demo:4',{allowPending:true}).error,undefined);
 assert.equal(r.ctx.REF_CACHE['demo:4'],undefined);assert.ok(r.ctx.resolveAppRef('demo:4').error);
 for(const name of ['demo:2','demo:3'])assert.ok(r.ctx.resolveAppRef(name,{allowPending:true}).error);
 r.app.active=false;assert.ok(r.ctx.resolveAppRef('demo:1',{allowPending:true}).error);
});
