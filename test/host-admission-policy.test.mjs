import test from 'node:test';import assert from 'node:assert/strict';
import {hostAdmissionPolicyHash,readHostAdmissionPolicy,hostAdmissionRefusal} from '../network/host-admission-policy.mjs';
const host='0x'+'ab'.repeat(32),other='0x'+'cd'.repeat(32),owner='0x'+'11'.repeat(20),contract='0x'+'22'.repeat(20),app='0x'+'ef'.repeat(32);
const appRef='catalog://'+app+'/1';
const policy={version:1,chainId:8453,ownershipContract:contract,hostId:host,requireCatalogApproval:true,denyDeployments:[app],denyAppRefs:[]};
test('only the exact host wallet commitment authorizes a policy',async()=>{
 const opts={hostId:host,ownershipContract:contract,readAuthority:async()=>({owner,revision:2,policyHash:hostAdmissionPolicyHash(policy)}),loadPolicy:async()=>policy};
 assert.deepEqual((await readHostAdmissionPolicy(opts)).policy,policy);
 await assert.rejects(readHostAdmissionPolicy({...opts,hostId:other}),/does not match/);
 await assert.rejects(readHostAdmissionPolicy({...opts,loadPolicy:async()=>({...policy,denyDeployments:[]})}),/does not match/);
 await assert.rejects(readHostAdmissionPolicy({...opts,readAuthority:async()=>{throw Error('chain quorum unavailable');}}),/quorum/);
 assert.throws(()=>hostAdmissionRefusal(policy,{hostId:other,deploymentId:app,appRef}),/another host/);
 assert.match(hostAdmissionRefusal(policy,{hostId:host,deploymentId:app,appRef}),/declines/);
});
test('no host wallet policy can override platform rejection, delisting or a yank',()=>{
 for(const requireCatalogApproval of [true,false]){
  const p={...policy,requireCatalogApproval,denyDeployments:[]};
  for(const change of [{active:false},{yanked:true},{approval:2}])
   for(const forPrivate of [false,true])assert.ok(hostAdmissionRefusal(p,{hostId:host,deploymentId:other,appRef,forPrivate,version:{active:true,yanked:false,approval:1,...change}}));
 }
});
test('ownership transfer clears former wallet policy and unavailable documents fail closed locally',async()=>{
 const opts={hostId:host,ownershipContract:contract,readAuthority:async()=>({owner,revision:3,policyHash:'0x'+'00'.repeat(32)}),loadPolicy:async()=>{throw Error('must not load former policy');}};
 assert.equal((await readHostAdmissionPolicy(opts)).policy.requireCatalogApproval,false);
 await assert.rejects(readHostAdmissionPolicy({...opts,readAuthority:async()=>({owner,revision:2,policyHash:hostAdmissionPolicyHash(policy)}),loadPolicy:async()=>{throw Error('document unavailable');}}),/unavailable/);
 await assert.rejects(readHostAdmissionPolicy({...opts,readAuthority:async()=>({owner:'0x'+'00'.repeat(20),revision:0,policyHash:'0x'+'00'.repeat(32)})}),/ownership unavailable/);
});

test('case and numeric aliases cannot bypass a wallet denial',()=>{
 const p={...policy,denyDeployments:[],denyAppRefs:[appRef]};
 assert.match(hostAdmissionRefusal(p,{hostId:host,deploymentId:other,appRef:'catalog://'+app.toUpperCase().replace('0X','0x')+'/0001'}),/declines/);
 assert.match(hostAdmissionRefusal(policy,{hostId:host,deploymentId:app.toUpperCase().replace('0X','0x'),appRef}),/declines/);
 assert.throws(()=>hostAdmissionRefusal(p,{hostId:host,deploymentId:other}),/reference required/);
 assert.match(hostAdmissionRefusal({...policy,denyDeployments:[]},{hostId:host,deploymentId:other,appRef,version:{approval:1}}),/catalog status/);
});
