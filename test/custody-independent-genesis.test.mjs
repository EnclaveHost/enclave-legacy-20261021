import {test,before} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import fs from 'node:fs';
import solc from 'solc';
import {createWalletClient,http,parseEther} from 'viem';
import {startAnvil} from './helpers/custody-rig.mjs';
import {VAULT_V2_ABI,createChainReaderV2} from '../custody/v2/chain.mjs';
import {generatePrivateKey,privateKeyToAccount} from 'viem/accounts';
import * as hpke from '../custody/hpke.mjs';
import * as v2 from '../custody/v2/protocol.mjs';
import * as D from '../custody/v2/digests.mjs';
import {createIndependentGenesis,dkgHelper} from '../custody/v2/independent-genesis.mjs';
import {coordinateIndependentGenesis} from '../custody/v2/coordinate-genesis.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const invoke=dkgHelper(root+'custody/dkg/target/debug/enclave-custody-dkg');
before(()=>execFileSync('cargo',['build','--locked','--manifest-path',root+'custody/dkg/Cargo.toml'],{stdio:'pipe',timeout:120000}));
const hex=(n,bytes=32)=>'0x'+n.toString(16).padStart(bytes*2,'0');
function rig(overrides={}){
 const identities=Array.from({length:3},()=>privateKeyToAccount(generatePrivateKey()));
 const keys=identities.map(()=>hpke.generateKeyPair());
 const machines=identities.map((a,i)=>({identity:a.address,encKey:'0x'+Buffer.from(keys[i].publicKey).toString('hex'),endpoint:`https://custodian-${i}.example`,chipId:hex(i+1),registryId:hex(i+10),measurement:hex(99),enclave:false}));
 const plan={chainId:8453,vault:hex(44,20),salt:hex(55),machines,codeSet:[hex(99)],...overrides};
 const stores=identities.map(()=>({value:null,load(){return structuredClone(this.value);},save(v){this.value=structuredClone(v);}}));
 const options=identities.map((identity,i)=>({plan,identity,encPrivateKey:keys[i].privateKey,store:stores[i],invoke,verifyRoster:async()=>true}));
 return {plan,stores,options,engines:options.map(createIndependentGenesis)};
}
async function rounds(r){
 const one=await Promise.all(r.engines.map(e=>e.start()));
 const acks=await Promise.all(r.engines.map(e=>e.agree(one)));
 const outgoing=await Promise.all(r.engines.map(e=>e.exchange(acks)));
 const incoming=r.engines.map((_,i)=>outgoing.flat().filter(m=>m.recipient===i+1));
 return {one,acks,outgoing,incoming};
}
test('real FROST DKG: independent 2-of-3 key decrypts custody without an Enclave participant',async()=>{
 const r=rig(),flow=await rounds(r);
 const results=await Promise.all(r.engines.map((e,i)=>e.finish(flow.incoming[i])));
 assert.equal(new Set(results.map(x=>x.commitments)).size,1);
 assert.equal(new Set(results.map(x=>x.committeeId)).size,1);
 const b=Buffer.from(results[0].commitments.slice(2),'hex'),commitments=[b.subarray(0,33),b.subarray(33)];
 for(let i=0;i<3;i++){
  assert.equal(await D.recoverDigest(D.independentGenesisDigest({...r.plan,...results[i]}),results[i].signature),r.plan.machines[i].identity.toLowerCase());
  assert.equal(r.stores[i].value.state,undefined);
  assert.equal(JSON.stringify([...flow.one,...flow.outgoing.flat(),...results]).includes(r.stores[i].value.share),false);
 }
 const label=Buffer.alloc(32,7),binding=Buffer.alloc(32,8);
 const bundle=v2.encryptBundle({Y:commitments[0],label,env:{KEY:'independent-secret'},configSha256:'ab'.repeat(32)});
 const R=v2.parseBundle(bundle).R;
 const partials=r.stores.map((s,i)=>v2.verifyPartial({record:v2.partial({k:i+1,x:BigInt('0x'+s.value.share),R,binding,commitments}),R,binding,commitments}));
 for(const subset of [[0,1],[0,2],[1,2]])assert.equal(v2.decryptBundle({S:v2.combine(subset.map(i=>partials[i]),2),label,bundle}).env.KEY,'independent-secret');
 assert.throws(()=>v2.combine([partials[0]],2),/exactly 2/);
 assert.throws(()=>v2.combine([partials[0],partials[0]],2),/distinct/);
});
test('broadcast agreement rejects substituted contributions, incomplete rosters and split views',async()=>{
 const r=rig(),one=await Promise.all(r.engines.map(e=>e.start()));
 const bad=structuredClone(one);bad[1].round1=bad[0].round1;
 await assert.rejects(r.engines[0].agree(bad),/unauthenticated/);
 await assert.rejects(r.engines[0].agree(one.slice(1)),/incomplete/);
 const acks=await Promise.all(r.engines.map(e=>e.agree(one)));
 const split=structuredClone(acks);split[1].root=hex(77);
 await assert.rejects(r.engines[0].exchange(split),/disagreement/);
 const other=rig(),otherOne=await Promise.all(other.engines.map(e=>e.start()));
 await assert.rejects(r.engines[0].agree(otherOne),/unauthenticated/);
});
test('confidential second round rejects tampering, wrong recipient, missing peer and invalid private state',async()=>{
 const r=rig(),flow=await rounds(r),bad=structuredClone(flow.incoming[0]);
 bad[0].sealed=(bad[0].sealed.startsWith('00')?'01':'00')+bad[0].sealed.slice(2);
 await assert.rejects(r.engines[0].finish(bad),/unauthenticated/);
 await assert.rejects(r.engines[0].finish(flow.incoming[1]),/participant|recipient/);
 await assert.rejects(r.engines[0].finish(flow.incoming[0].slice(1)),/incomplete/);
 await assert.rejects(invoke({phase:3,id:1,participants:3,state:'00',round1:{2:'00',3:'00'},round2:{2:'00',3:'00'}}),/refused/);
});
test('sealed share survives a crash before final signature; unverified roster cannot start or finish',async()=>{
 const r=rig(),flow=await rounds(r),store=r.stores[0],save=store.save.bind(store);
 let fail=true;
 store.save=v=>{save(v);if(v.phase===3&&!v.result&&fail){fail=false;throw Error('simulated power loss');}};
 await assert.rejects(r.engines[0].finish(flow.incoming[0]),/power loss/);
 assert.equal(store.value.phase,3);assert.equal(store.value.result,undefined);
 const restarted=createIndependentGenesis(r.options[0]);
 const result=await restarted.finish([]);
 assert.equal(result.committeeId,store.value.committeeId);
 const denied=createIndependentGenesis({...r.options[1],verifyRoster:async()=>false});
 await assert.rejects(denied.finish(flow.incoming[1]),/not verified/);
 await assert.rejects(denied.start(),/not verified/);
});

test('public coordinator resumes a signed transcript and requests activation sequentially',async()=>{
 const r=rig();let active=0,maxActive=0,activations=0;
 const post=async(url,body)=>{
  const i=r.plan.machines.findIndex(m=>url===m.endpoint+'/v2/custody/independent-genesis');assert.ok(i>=0);
  const e=r.engines[i];
  if(body.action==='start')return e.start();
  if(body.action==='agree')return e.agree(body.round1);
  if(body.action==='exchange')return e.exchange(body.acks);
  if(body.action==='finish')return e.finish(body.messages);
  if(body.action==='activate'){active++;maxActive=Math.max(active,maxActive);await new Promise(res=>setTimeout(res,1));active--;activations++;return {committeeId:body.results[0].committeeId,epoch:1};}
  throw Error('unexpected route');
 };
 const prepared=await coordinateIndependentGenesis(r.plan,{post});assert.equal(activations,0);
 await assert.rejects(coordinateIndependentGenesis(r.plan,{activate:true,post:async(url,body)=>{
   const value=await post(url,body);
   return body.action==='finish'&&value.id===1?{...value,signature:'0x'+'00'.repeat(65)}:value;
 }}),/founder signature/);
 assert.equal(activations,0);
 const activated=await coordinateIndependentGenesis(r.plan,{post,activate:true});
 assert.equal(activated.committeeId,prepared.committeeId);assert.equal(activations,3);assert.equal(maxActive,1);
});

test('real chain accepts the real DKG founder signatures through an unrelated gas payer', {timeout:120000}, async()=>{
 const mock=`pragma solidity ^0.8.20;
 contract Bindings {
  mapping(bytes32=>address) public addr;
  struct Entry {string endpoint;string repo;bytes32 measurement;address operator;uint64 registeredAt;uint64 lastSeen;bool active;uint64 cpuPrice;uint64 gpuPrice;address proofKey;address payoutWallet;}
  mapping(bytes32=>Entry) entries; mapping(bytes32=>address) owners;
  constructor(){addr[bytes32("deployments")]=address(this);}
  function registry() external view returns(address){return address(this);}
  function set(bytes32 id,address op,address owner) external {entries[id].operator=op;entries[id].active=true;owners[id]=owner;}
  function get(bytes32 id) external view returns(Entry memory){return entries[id];}
  function authority(bytes32 id) external view returns(address,address,uint64,bytes32){return(owners[id],address(0),1,bytes32(0));}
 }`;
 const output=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'V.sol':{content:fs.readFileSync(root+'contracts/EnclaveSecretVaultV2.sol','utf8')},'Mock.sol':{content:mock}},settings:{viaIR:true,optimizer:{enabled:true,runs:200},outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object']}}}})));
 assert.equal((output.errors||[]).filter(x=>x.severity==='error').length,0);
 const vaultArtifact=output.contracts['V.sol'].EnclaveSecretVaultV2;
 assert.ok(vaultArtifact.evm.deployedBytecode.object.length/2<=24576,'contract exceeds EIP-170');
 const a=await startAnvil({chainId:31337});
 try{
  const payer=privateKeyToAccount(generatePrivateKey());
  await a.client.request({method:'anvil_setBalance',params:[payer.address,'0x'+parseEther('10').toString(16)]});
  const w=createWalletClient({account:payer,chain:a.chain,transport:http(a.url)});
  const deploy=async(c,args=[])=>{const rc=await a.client.waitForTransactionReceipt({hash:await w.deployContract({abi:c.abi,bytecode:'0x'+c.evm.bytecode.object,args})});assert.equal(rc.status,'success');return rc.contractAddress;};
  const mockArtifact=output.contracts['Mock.sol'].Bindings;
  const bindings=await deploy(mockArtifact);
  const vault=await deploy(vaultArtifact,[bindings,hex(888,20),bindings]);
  const r=rig({chainId:31337,vault});
  const ops=r.engines.map(()=>privateKeyToAccount(generatePrivateKey()));
  const write=async(address,abi,functionName,args)=>{const rc=await a.client.waitForTransactionReceipt({hash:await w.writeContract({address,abi,functionName,args})});assert.equal(rc.status,'success');};
  for(let i=0;i<3;i++)await write(bindings,mockArtifact.abi,'set',[r.plan.machines[i].registryId,ops[i].address,hex(700+i,20)]);
  const flow=await rounds(r),results=await Promise.all(r.engines.map((e,i)=>e.finish(flow.incoming[i])));
  const hostSigs=await Promise.all(ops.map((op,i)=>D.signDigest(op,D.hostDigest({...r.plan,machine:r.plan.machines[i]}))));
  await write(vault,VAULT_V2_ABI,'createIndependentCommittee',[r.plan.salt,r.plan.machines,results[0].commitments,r.plan.codeSet,results.map(r=>r.signature),hostSigs]);
  const reader=createChainReaderV2({vault,clients:[a.client],minAgree:1});
  const {committee:c}=await reader.readCommittee({committeeId:results[0].committeeId});
  assert.equal(c.t,2);assert.equal(c.W,3);assert.equal(c.epoch,1);
  assert.equal(c.machines.some(m=>m.enclave),false);
  assert.equal('0x'+Buffer.from(c.commitments).toString('hex'),results[0].commitments);
 }finally{await a.stop();}
});
