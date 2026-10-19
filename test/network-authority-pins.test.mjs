import test from 'node:test';
import assert from 'node:assert/strict';
import {privateKeyToAccount} from 'viem/accounts';
import {LeaseReader} from '../network/lease-reader.mjs';
import {verifyOwnerSignature} from '../network/owner-signature.mjs';
const a=n=>'0x'+n.repeat(40),book=a('1'),registry=a('2'),deployments=a('3'),factory=a('4'),vault=a('5');
const host='0x'+'a'.repeat(64),id='0x'+'b'.repeat(64),zero=a('0'),now=()=>1700000000000;
const pins={deployments,registry,connectivity:zero,sessionVaultFactory:factory};
const owner=privateKeyToAccount('0x'+'11'.repeat(32));
const row={id,runner:host,owner:owner.address,runnerOperator:owner.address,active:true,isPublic:true,leaseUntil:1700003600n,appRef:'catalog:a:1',configCid:''};
function peer({time=1699999995n,recognizes=true}={}){return {
 getChainId:async()=>8453,getBlockNumber:async()=>1000n,getBlock:async()=>({hash:'0x'+'c'.repeat(64),timestamp:time}),
 getCode:async q=>{assert.equal(q.blockNumber,998n);return q.address===vault?'0x01':'0x';},
 readContract:async q=>{
  assert.notEqual(q.address,book,'must never follow the book');assert.equal(q.blockNumber,998n);
  if(q.functionName==='deploymentsSchema'){assert.equal(q.address,deployments);return 16n;}
  if(q.functionName==='get'&&q.address===deployments)return row;
  if(q.functionName==='get'&&q.address===registry)return {active:true,operator:owner.address,payoutWallet:owner.address,proofKey:owner.address};
  if(q.functionName==='isValidSignature')return '0xffffffff';
  if(q.functionName==='isVault'){assert.equal(q.address,factory);return recognizes;}
  if(q.functionName==='owner'){assert.equal(q.address,vault);return owner.address;}
  throw Error('unexpected call '+q.functionName);
 }
};}
const reader=clients=>new LeaseReader({addressBook:book,authorityPins:pins,includeHostPayout:true,includeConnectivity:'auto',clients,now});
test('network lease and operator reads survive an unavailable/hostile address book with explicit pins',async()=>{
 const r=reader([peer(),peer()]);
 const [lease]=await r.refresh([id]);assert.equal(lease.deployments,deployments);assert.equal(lease.runnerRegistered,true);
 assert.equal(await r.bookAddress('registry'),registry);
 assert.equal((await r.registryEntries(registry,[host]))[0].operator,owner.address.toLowerCase());
 await assert.rejects(r.bookAddress('unknown'),/not pinned/);
});
test('network pins are complete, copied and immutable, with no partial fallback',()=>{
 for(const authorityPins of [null,{}, {...pins,registry:zero},{...pins,other:factory},{...pins,connectivity:undefined}])
  assert.throws(()=>new LeaseReader({addressBook:book,authorityPins,clients:[],now}),/pin/);
 const input={...pins};const r=new LeaseReader({addressBook:book,authorityPins:input,clients:[],now});input.registry=book;
 assert.equal(r.authorityPins.registry,registry);assert.throws(()=>{r.authorityPins.registry=book;});assert.throws(()=>{r.authorityPins=null;});
});
test('pinned SessionVault signatures use one fresh agreeing block without book discovery',async()=>{
 const message='network policy test',signature=await owner.signMessage({message});
 const check=r=>verifyOwnerSignature({reader:r,owner:vault,message,signature,addressBook:book,sessionVaultFactory:factory});
 assert.equal(await check(reader([peer(),peer()])),true);
 assert.equal(await check(reader([peer({recognizes:false}),peer(),peer()])),true,'a disagreeing peer cannot override a fresh majority');
 assert.equal(await check(reader([peer({recognizes:false}),peer()])),false,'no agreeing quorum');
 assert.equal(await check(reader([peer({time:1699999800n}),peer({time:1699999800n})])),false,'stale authority');
 assert.equal(await verifyOwnerSignature({reader:reader([peer(),peer()]),owner:vault,message,signature,addressBook:book,sessionVaultFactory:zero}),false,'disabled factory cannot fall back');
 assert.equal(await verifyOwnerSignature({reader:reader([peer(),peer()]),owner:vault,message:message+' changed',signature,addressBook:book,sessionVaultFactory:factory}),false,'signature binds the exact policy');
});

// Exercise the host consumer, not only the signature helper: its policy lookup
// must pass the pinned factory and fresh quorum through to owner verification.
test('network host verifies a vault policy with pinned authorities and refuses conflicting registry settings',async t=>{
 const {createNetworkHost}=await import('../network/enclave-network-host.mjs');
 const {defaultNetworkPolicy,signNetworkPolicy}=await import('../network/network-policy.mjs');
 const {mkdtemp,rm}=await import('node:fs/promises');const {tmpdir}=await import('node:os');
 const directory=await mkdtemp(tmpdir()+'/pinned-network-host-');t.after(()=>rm(directory,{recursive:true,force:true}));
 const config={relay:'http://127.0.0.1:9',checkers:[owner.address],apps:'all',wgBinary:'/bin/true',nodeBinary:process.execPath,workerModule:'/bin/true'};
 const policy={...defaultNetworkPolicy(id),nonce:1,issuedAt:1};const envelope=await signNetworkPolicy(owner,policy);
 const args={config,directory,authorityPins:pins,addressBook:book,now,fetch:async()=>Response.json({envelope})};
 const h=await createNetworkHost({...args,leaseReader:reader([peer(),peer()])});
 assert.deepEqual(await h.policyFor({deploymentId:id},{id,owner:vault}),policy);
 const stale=await createNetworkHost({...args,leaseReader:reader([peer({time:1699999800n}),peer({time:1699999800n})])});
 await assert.rejects(stale.policyFor({deploymentId:id},{id,owner:vault}),/no valid owner policy/);
 await assert.rejects(createNetworkHost({...args,config:{...config,registry:book},leaseReader:reader([peer(),peer()])}),/conflicts/);
 await assert.rejects(createNetworkHost({...args,leaseReader:{}}),/quorum reader/);
 await assert.rejects(createNetworkHost({...args,authorityPins:{registry},leaseReader:reader([peer(),peer()])}),/pin/);
});
