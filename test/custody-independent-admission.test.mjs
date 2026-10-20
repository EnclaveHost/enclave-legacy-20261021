import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {generatePrivateKey,privateKeyToAccount} from 'viem/accounts';
import * as D from '../custody/v2/digests.mjs';
import * as hpke from '../custody/hpke.mjs';
import {createMember,machineBinding} from '../custody/v2/member.mjs';
import {independentOwners,ownerAdmissionCheck} from '../custody/v2/admission.mjs';
const hex=(n,len=32)=>'0x'+n.toString(16).padStart(len*2,'0');
const sha=b=>'0x'+createHash('sha256').update(b).digest('hex');
const enclave=hex(999,20),owners=[hex(1,20),hex(2,20),hex(3,20)];
test('committee-local admission uses accepted wallet ownership, never payout or an Enclave witness',async()=>{
 const accepted=independentOwners(owners,enclave),check=ownerAdmissionCheck(accepted);
 assert.equal((await check({registry:{owner:owners[0],payoutWallet:enclave}})).ok,true);
 assert.equal((await check({registry:{owner:enclave,payoutWallet:owners[0]}})).ok,false);
 assert.equal((await check({registry:{payoutWallet:owners[0]}})).ok,false);
 assert.throws(()=>independentOwners([owners[0],owners[0],owners[1]],enclave),/distinct/);
 assert.throws(()=>independentOwners([enclave,...owners.slice(1)],enclave),/distinct/);
 assert.throws(()=>independentOwners([],enclave),/3..64/);
});
test('genesis requires every operator permit, fresh peer evidence, same measured code and distinct allowed owners',async()=>{
 const ids=owners.map(()=>privateKeyToAccount(generatePrivateKey())),ops=owners.map(()=>privateKeyToAccount(generatePrivateKey())),keys=owners.map(()=>hpke.generateKeyPair());
 const meas=Buffer.alloc(48,9),chips=owners.map((_,i)=>Buffer.alloc(64,i+1));
 const machines=ids.map((id,i)=>({identity:id.address.toLowerCase(),encKey:'0x'+Buffer.from(keys[i].publicKey).toString('hex'),endpoint:`https://peer${i}.example`,registryId:hex(10+i),measurement:sha(meas),chipId:sha(chips[i])}));
 const plan={chainId:8453,vault:hex(70,20),salt:hex(80),machines,codeSet:[sha(meas)]};
 plan.operatorPermits=await Promise.all(ops.map(op=>D.signDigest(op,D.independentPlanDigest(plan))));
 const hostSigs=await Promise.all(ops.map((op,i)=>D.signDigest(op,D.hostDigest({...plan,machine:machines[i]}))));
 let requests=0,snapshots=0,badQuote=false,changedOwner=false;
 const member=createMember({chainId:plan.chainId,vault:plan.vault,identity:ids[0],encPrivateKey:keys[0].privateKey,machine:machines[0],enclaveOwner:enclave,
  store:{load:()=>null,save:()=>{}},submit:()=>{throw Error('not a transaction');},attestSelf:()=>{throw Error('not needed');},
  chain:{readAuthorization:async({committeeId,registryIds,checks})=>{assert.equal(committeeId,null);snapshots++;
    const entry=id=>{const i=machines.findIndex(m=>m.registryId===id);return {active:true,owner:changedOwner&&i===2?owners[0]:owners[i],operator:ops[i].address.toLowerCase(),payoutWallet:enclave};};
    return {committee:null,entries:Object.fromEntries(registryIds.map(id=>[id,entry(id)])),codeActiveAt:{},valid:checks.map(()=>false),blockNumber:1n,blockTimestamp:1000};},
   readRegistryEntry:()=>{throw Error('genesis must judge one snapshot');},readCodeActiveAt:()=>{throw Error('no existing committee code authority');}},
  capacityCheck:()=>{throw Error('no capacity witness allowed');},
  fetchJson:async(url,{nonce})=>{requests++;const i=machines.findIndex(m=>url.startsWith(m.endpoint+'/'));return {machine:machines[i],hostSig:hostSigs[i],report:Buffer.concat([Buffer.from([i]),machineBinding(machines[i],Buffer.from(nonce,'hex'))]).toString('base64')};},
  verifyPeerQuote:async(report,{binding})=>{assert.deepEqual(report.subarray(1),binding);return {ok:!badQuote,reason:'bad evidence',measurement:meas.toString('hex'),chipId:chips[report[0]].toString('hex')};},log:()=>{}});
 assert.equal(await member.verifyGenesisRoster(plan,owners),true);assert.equal(requests,3);assert.equal(snapshots,1,'one block authorizes the whole roster');
 requests=0;const unsigned=structuredClone(plan);unsigned.operatorPermits[1]=unsigned.operatorPermits[0];
 assert.equal(await member.verifyGenesisRoster(unsigned,owners),false);assert.equal(requests,0);
 const wrong=structuredClone(plan);wrong.salt=hex(81);
 assert.equal(await member.verifyGenesisRoster(wrong,owners),false);assert.equal(requests,0);
 badQuote=true;assert.equal(await member.verifyGenesisRoster(plan,owners),false);
 badQuote=false;changedOwner=true;assert.equal(await member.verifyGenesisRoster(plan,owners),false);
});
