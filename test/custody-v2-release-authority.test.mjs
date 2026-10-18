import test from 'node:test';
import assert from 'node:assert/strict';
import {createChainReaderV2} from '../custody/v2/chain.mjs';
const vault='0x'+'11'.repeat(20),ledger='0x'+'22'.repeat(20),registry='0x'+'33'.repeat(20),owner='0x'+'44'.repeat(20);
const id='0x'+'55'.repeat(32),zero='0x'+'00'.repeat(32),endpoint='https://host.example';
function client({legacy=false,wrongOwner=false}={}) {
 return {getBlockNumber:async()=>10n,getBlock:async({blockNumber})=>({number:blockNumber,timestamp:1000n}),readContract:async({address,functionName,blockNumber})=>{
  assert.equal(blockNumber,10n);
  if(address===vault){
   if(functionName==='policyOf')return [owner,1n,1n,zero,false,'0x'];
   if(functionName==='bundleOf')return [zero,1n,'0x'];
   if(functionName==='beneficialOwnerOf')return owner;
   if(functionName==='deploymentLedger'){if(legacy)throw Error('old vault');return ledger;}
   if(functionName==='hostRegistry')return registry;
  }
  if(address===ledger&&functionName==='get')return {owner:wrongOwner?registry:owner,runner:zero,leaseUntil:1100n,appRef:'catalog://'+id+'/0',configCid:''};
  if(address===registry&&functionName==='get')return {operator:owner,active:true};
  throw Error('unexpected authority lookup '+functionName);
 }};
}
const reader=clients=>createChainReaderV2({vault,clients,minAgree:2,maxAgeSec:120,now:()=>1000_000});
test('release reads the vault-pinned ledger and host registry without consulting the book',async()=>{
 const r=await reader([client(),client()]).readRelease({id,endpoint});
 assert.equal(r.lease.owner,owner);assert.equal(r.endpointOperator,owner);
});
test('legacy or disagreeing release authorities cannot trigger a mutable-book fallback',async()=>{
 await assert.rejects(reader([client({legacy:true}),client({legacy:true})]).readRelease({id,endpoint}),/only 0 RPCs/);
 await assert.rejects(reader([client(),client({wrongOwner:true})]).readRelease({id,endpoint}),/disagree/);
});
