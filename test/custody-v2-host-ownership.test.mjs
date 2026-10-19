import test from 'node:test';
import assert from 'node:assert/strict';
import {createChainReaderV2,VAULT_V2_ABI,HOST_OWNERSHIP_ABI,REGISTRY_V4_ABI} from '../custody/v2/chain.mjs';
import {wireClient} from './helpers/custody-rpc.mjs';
const vault='0x'+'11'.repeat(20),registry='0x'+'22'.repeat(20),ownership='0x'+'33'.repeat(20),owner='0x'+'44'.repeat(20),payout='0x'+'55'.repeat(20),host='0x'+'66'.repeat(32);
function client({timestamp=1000n,accepted=owner,missing=false}={}) {
 return wireClient({getBlockNumber:async()=>10n,getBlock:async({blockNumber})=>({number:blockNumber,timestamp,hash:'0x'+'ab'.repeat(32)}),readContract:async({address,functionName,blockNumber})=>{
  assert.equal(blockNumber,10n);
  if(functionName==='hostOwnership'){if(missing)throw Error('old vault');assert.equal(address,vault);return ownership;}
  if(functionName==='hostRegistry'){assert.equal(address,vault);return registry;}
  if(functionName==='authority'){assert.equal(address,ownership);return [accepted,'0x'+'00'.repeat(20),1n,'0x'+'00'.repeat(32)];}
  if(functionName==='get'){assert.equal(address,registry);return {endpoint:'https://host.example',active:true,operator:owner,payoutWallet:payout,repo:'',measurement:host,registeredAt:1n,lastSeen:1n,cpuPricePerSec6:0n,gpuPricePerSec6:0n,proofKey:owner};}
  throw Error('unexpected mutable lookup '+functionName);
 }},{[vault]:VAULT_V2_ABI,[ownership]:HOST_OWNERSHIP_ABI,[registry]:REGISTRY_V4_ABI});
}
const reader=(clients)=>createChainReaderV2({vault,clients,minAgree:2,maxAgeSec:120,now:()=>1000_000});
test('custody reads accepted host ownership from a fresh agreeing block, separately from payout',async()=>{
 const r=await reader([client(),client()]).readRegistryEntry({registryId:host});
 assert.equal(r.entry.owner,owner);assert.equal(r.entry.payoutWallet,payout);
});
test('stale, disagreeing, or legacy ownership reads never fall back to payout',async()=>{
 await assert.rejects(reader([client({timestamp:800n}),client({timestamp:800n})]).readRegistryEntry({registryId:host}),/chain_stale/);
 await assert.rejects(reader([client(),client({accepted:payout})]).readRegistryEntry({registryId:host}),/disagree/);
 await assert.rejects(reader([client({missing:true}),client({missing:true})]).readRegistryEntry({registryId:host}),/only 0 RPCs/);
});

test('a measured authority pin cannot be replaced by a different vault authority',async()=>{
 const r=createChainReaderV2({vault,hostOwnership:owner,clients:[client(),client()],minAgree:2,maxAgeSec:120,now:()=>1000_000});
 await assert.rejects(r.readRegistryEntry({registryId:host}),/host_authority_mismatch/);
});
