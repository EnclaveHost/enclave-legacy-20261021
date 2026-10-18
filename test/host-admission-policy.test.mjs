import test from 'node:test';import assert from 'node:assert/strict';
import {hostAdmissionPolicyHash,readHostAdmissionPolicy,hostAdmissionRefusal} from '../network/host-admission-policy.mjs';
const host='0x'+'ab'.repeat(32),other='0x'+'cd'.repeat(32),owner='0x'+'11'.repeat(20),contract='0x'+'22'.repeat(20),app='0x'+'ef'.repeat(32);
const policy={version:1,chainId:8453,ownershipContract:contract,hostId:host,requireCatalogApproval:true,denyDeployments:[app],denyAppRefs:[]};
test('only the exact host wallet commitment authorizes a policy',async()=>{
 const opts={hostId:host,ownershipContract:contract,readAuthority:async()=>({owner,revision:2,policyHash:hostAdmissionPolicyHash(policy)}),loadPolicy:async()=>policy};
 assert.deepEqual((await readHostAdmissionPolicy(opts)).policy,policy);
 await assert.rejects(readHostAdmissionPolicy({...opts,hostId:other}),/does not match/);
 await assert.rejects(readHostAdmissionPolicy({...opts,loadPolicy:async()=>({...policy,denyDeployments:[]})}),/does not match/);
 await assert.rejects(readHostAdmissionPolicy({...opts,readAuthority:async()=>{throw Error('chain quorum unavailable');}}),/quorum/);
 assert.throws(()=>hostAdmissionRefusal(policy,{hostId:other,deploymentId:app}),/another host/);
 assert.match(hostAdmissionRefusal(policy,{hostId:host,deploymentId:app}),/declines/);
});
test('independent hosts can accept the same deployment regardless of Enclave catalog refusal',async()=>{
 const independent={...policy,hostId:other,requireCatalogApproval:false,denyDeployments:[]};
 const refused={active:true,yanked:false,approval:2};
 assert.match(hostAdmissionRefusal(policy,{hostId:host,deploymentId:other,version:refused}),/catalog approval/);
 assert.equal(hostAdmissionRefusal(independent,{hostId:other,deploymentId:app,version:refused}),null);
});
test('ownership transfer clears former wallet policy and unavailable documents fail closed locally',async()=>{
 const opts={hostId:host,ownershipContract:contract,readAuthority:async()=>({owner,revision:3,policyHash:'0x'+'00'.repeat(32)}),loadPolicy:async()=>{throw Error('must not load former policy');}};
 assert.equal((await readHostAdmissionPolicy(opts)).policy.requireCatalogApproval,false);
 await assert.rejects(readHostAdmissionPolicy({...opts,readAuthority:async()=>({owner,revision:2,policyHash:hostAdmissionPolicyHash(policy)}),loadPolicy:async()=>{throw Error('document unavailable');}}),/unavailable/);
 await assert.rejects(readHostAdmissionPolicy({...opts,readAuthority:async()=>({owner:'0x'+'00'.repeat(20),revision:0,policyHash:'0x'+'00'.repeat(32)})}),/ownership unavailable/);
});
