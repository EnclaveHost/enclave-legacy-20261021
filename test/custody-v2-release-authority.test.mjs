import test from 'node:test';
import assert from 'node:assert/strict';
import {createChainReaderV2,VAULT_V2_ABI,LEDGER_ABI,REGISTRY_V4_ABI} from '../custody/v2/chain.mjs';
import {wireClient} from './helpers/custody-rpc.mjs';
const vault='0x'+'11'.repeat(20),ledger='0x'+'22'.repeat(20),registry='0x'+'33'.repeat(20),owner='0x'+'44'.repeat(20);
const id='0x'+'55'.repeat(32),zero='0x'+'00'.repeat(32),endpoint='https://host.example';
function client({legacy=false,wrongOwner=false}={}) {
 return wireClient({getBlockNumber:async()=>10n,getBlock:async({blockNumber})=>({number:blockNumber,timestamp:1000n,hash:'0x'+'ab'.repeat(32)}),readContract:async({address,functionName,blockNumber})=>{
  assert.equal(blockNumber,10n);
  if(address===vault){
   if(functionName==='policyOf')return [owner,1n,1n,zero,false,'0x'];
   if(functionName==='bundleOf')return [zero,1n,'0x'];
   if(functionName==='beneficialOwnerOf')return owner;
   if(functionName==='deploymentLedger'){if(legacy)throw Error('old vault');return ledger;}
   if(functionName==='hostRegistry')return registry;
  }
  if(address===ledger&&functionName==='get')return {owner:wrongOwner?registry:owner,runner:zero,leaseUntil:1100n,appRef:'catalog://'+id+'/0',configCid:'',id,ports:'',gpuMilli:0,cpuMilli:0,appPort:443,isPublic:false,active:true,createdAt:1n,rate:0n,balance6:0n,spent6:0n,runnerOperator:owner};
  if(address===registry&&functionName==='get')return {endpoint,repo:'',measurement:zero,operator:owner,registeredAt:1n,lastSeen:1n,active:true,cpuPricePerSec6:0n,gpuPricePerSec6:0n,proofKey:owner,payoutWallet:owner};
  throw Error('unexpected authority lookup '+functionName);
 }},{[vault]:VAULT_V2_ABI,[ledger]:LEDGER_ABI,[registry]:REGISTRY_V4_ABI});
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
