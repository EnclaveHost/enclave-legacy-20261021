import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeAbiParameters, keccak256, toFunctionSelector, zeroAddress } from 'viem';
import { captureGovernanceReview, configurationHash, profiles } from '../scripts/lib/governance-review.mjs';

const target='0x1111111111111111111111111111111111111111';
const dependency='0x2222222222222222222222222222222222222222';
const owner='0x3333333333333333333333333333333333333333';
function fixture(changes={}) {
  const values={deploymentsSchema:16n,retired:false,importsSealed:true,usdc:dependency,registry:dependency,
    payout:owner,ethUsdFeed:zeroAddress,leaseSec:1800n,maxGpuMilli:1000,maxFeePerSec6:1389n,
    runnerBps:8000,claimBond6:0n,bondExitDelay:86400n,prover:dependency,proofRequiredFrom:1n,
    feeRouter:dependency,bandwidthRouter:dependency,owner,pendingOwner:zeroAddress,...changes};
  const fields=[...profiles.ledger16.getters,['owner','address'],['pendingOwner','address']];
  const reads=[];
  return {reads,client:{
    async getCode({address,blockNumber}) {assert.equal(blockNumber,42n);reads.push(address);return '0x6000';},
    async call({to,data,blockNumber}) {
      assert.equal(to,target); assert.equal(blockNumber,42n);
      const [name,type]=fields.find(([n])=>toFunctionSelector(`${n}()`)==data);
      reads.push(name);return {data:encodeAbiParameters([{type}],[values[name]])};
    },
  }};
}
const options={target,profile:'ledger16',chainId:8453,blockNumber:42n};
test('full fixed-block capture commits all configured values and identifies enabled dependencies',async()=>{
  const {client,reads}=fixture();const r=await captureGovernanceReview(client,options);
  assert.equal(r.readings.length,17); assert.equal(r.dependencies.filter(d=>d.enabled).length,5);
  assert.deepEqual(r.blockers,[]);assert.match(r.status,/review-required/);
  assert(!r.selectors.includes(toFunctionSelector('owner()')));
  assert(reads.includes('pendingOwner'));assert(!('data' in r));
});
test('configuration commitment changes on code, chain, address, value or getter order',async()=>{
  const r=await captureGovernanceReview(fixture().client,options);
  const hash=(chain=8453,to=target,code=r.codeHash,rows=r.readings)=>configurationHash(chain,to,code,rows);
  assert.equal(hash(),r.configurationHash);
  for(const other of [hash(1),hash(8453,dependency),hash(8453,target,keccak256('0x6001')),
    hash(8453,target,r.codeHash,[...r.readings].reverse()),
    (await captureGovernanceReview(fixture({leaseSec:3600n}).client,options)).configurationHash])
    assert.notEqual(other,r.configurationHash);
});
test('refuses unknown revisions, profiles, absent code and latest-block ambiguity',async()=>{
  await assert.rejects(captureGovernanceReview(fixture({deploymentsSchema:17n}).client,options),/revision/);
  await assert.rejects(captureGovernanceReview(fixture().client,{...options,profile:'guessed'}),/profile/);
  await assert.rejects(captureGovernanceReview(fixture().client,{...options,blockNumber:undefined}),/fixed block/);
  const {client}=fixture();client.getCode=async()=> '0x';
  await assert.rejects(captureGovernanceReview(client,options),/target code missing/);
});
test('refuses malformed getter responses and missing dependency code',async()=>{
  const {client}=fixture();client.call=async()=>({data:'0x01'});
  await assert.rejects(captureGovernanceReview(client,options),/getter response/);
  const f=fixture();f.client.getCode=async({address})=>address===target?'0x6000':'0x';
  await assert.rejects(captureGovernanceReview(f.client,options),/dependency code missing/);
});
test('reports closed admission, disabled proofs, unsealed imports and pending transfer as blockers',async()=>{
  const {client}=fixture({retired:true,importsSealed:false,maxGpuMilli:0,runnerBps:0,
    proofRequiredFrom:0n,prover:zeroAddress,feeRouter:zeroAddress,pendingOwner:dependency});
  const r=await captureGovernanceReview(client,options);
  assert.equal(r.blockers.length,8);
});
