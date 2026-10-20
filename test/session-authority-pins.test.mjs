import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createSessionApiAuth,delegateSlot} from '../windows/node/session-api-auth.mjs';
const address=n=>'0x'+n.repeat(40),zero=address('0');
const pins={deployments:address('1'),sessionVaultFactory:address('2')};
const owner=address('3'),vault=address('4');
function setup(authorityPins=pins){
 const reads=[];
 const pc={readContract:async q=>{throw Error('unexpected authority read');},
  getCode:async q=>{reads.push(['code',q.address]);return '0x63'+ '00'.repeat(4);},
  getStorageAt:async q=>{reads.push(['storage',q.address]);assert.equal(q.slot,delegateSlot(owner,vault));return '0x01';}};
 const auth=createSessionApiAuth({pc,authorityPins,book:()=>{throw Error('book must not be consulted');},ledger:()=>address('5'),factories:[address('6')],bases:()=>[]});
 return {auth,pc,reads};
}
test('explicit factory excludes mutable book, default factories and legacy configured factories',async()=>{
 const copy={...pins};const {auth}=setup(copy);
 copy.sessionVaultFactory=address('7');copy.deployments=address('7');
 assert.deepEqual(await auth.knownFactories(),[pins.sessionVaultFactory]);
 assert.deepEqual(await auth.knownFactories(),[pins.sessionVaultFactory]);
});
test('zero explicitly disables session factories and malformed pins fail closed',async()=>{
 assert.deepEqual(await setup({...pins,sessionVaultFactory:zero}).auth.knownFactories(),[]);
 for(const bad of [{},[],{...pins,deployments:zero},{...pins,sessionVaultFactory:undefined},{...pins,sessionVaultFactory:'bad'}])assert.throws(()=>setup(bad),/invalid pinned/);
});
test('delegation uses pinned ledger even if caller supplied a different legacy ledger',async()=>{
 const {auth,reads}=setup();
 const result=await auth.delegation(owner,vault,true);
 assert.equal(result.ledger,pins.deployments);
 assert.deepEqual(reads,[['code',pins.deployments]]);
});
test('Linux and Windows host constructors pass the loaded pins to session verification',()=>{
 for(const file of ['supervisor.js','windows/node/agent.mjs']){
  const code=fs.readFileSync(new URL('../'+file,import.meta.url),'utf8');
  assert.match(code,/const sessionApi = createSessionApiAuth\(\{\s*authorityPins: CONTRACT_PINS,/);
 }
});
