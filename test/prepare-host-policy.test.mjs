import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import solc from 'solc';
import {createWalletClient,http,keccak256,toHex,decodeFunctionData} from 'viem';
import {generatePrivateKey,privateKeyToAccount} from 'viem/accounts';
import {startAnvil,anvilAvailable} from './helpers/custody-rig.mjs';
import {prepareHostPolicy,ownershipABI} from '../scripts/network/prepare-host-policy.mjs';
import {readHostAdmissionPolicy} from '../network/host-admission-policy.mjs';

test('unsigned policy preparation executes on a real registry, resumes enrollment and preserves independent ownership',
  {skip:anvilAvailable()?false:'anvil not installed'},async()=>{
  const a=await startAnvil({chainId:8453});
  try {
    const sources=Object.fromEntries(['EnclaveRegistry','EnclaveHostOwnership'].map(n=>[n+'.sol',{content:fs.readFileSync(new URL('../contracts/'+n+'.sol',import.meta.url),'utf8')}]));
    const compiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources,settings:{viaIR:true,optimizer:{enabled:true,runs:200},outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
    assert.deepEqual((compiled.errors||[]).filter(e=>e.severity==='error'),[]);
    const wallets=await Promise.all(Array.from({length:3},async()=>{
      const account=privateKeyToAccount(generatePrivateKey());
      await a.client.request({method:'anvil_setBalance',params:[account.address,'0x56bc75e2d63100000']});
      return createWalletClient({account,chain:a.chain,transport:http(a.url)});
    }));
    const [operator,owner,independent]=wallets;
    const receipt=async hash=>{const r=await a.client.waitForTransactionReceipt({hash});assert.equal(r.status,'success');return r;};
    const deploy=async(name,args=[])=>{const c=compiled.contracts[name+'.sol'][name];return (await receipt(await operator.deployContract({abi:c.abi,bytecode:'0x'+c.evm.bytecode.object,args}))).contractAddress;};
    const registry=await deploy('EnclaveRegistry'),ownershipContract=await deploy('EnclaveHostOwnership',[registry]);
    const endpoint='https://host.example',hostId=keccak256(toHex(endpoint));
    await receipt(await operator.writeContract({address:registry,abi:compiled.contracts['EnclaveRegistry.sol'].EnclaveRegistry.abi,functionName:'register',args:[endpoint,'repo','0x'+'1'.repeat(64),1n,0n,operator.account.address]}));
    // The test uses one local chain; production CLI uses LeaseReader's fresh RPC quorum.
    const reader={agreed:async fn=>fn(a.client,await a.client.getBlockNumber({cacheTime:0}))};
    const policy={version:1,chainId:8453,ownershipContract,hostId,requireCatalogApproval:false,denyDeployments:[],denyAppRefs:[]};
    const opts={policy,registry,owner:owner.account.address.toLowerCase(),reader};
    const prepare=()=>prepareHostPolicy(opts);
    const first=await prepare();
    assert.deepEqual(first.transactions.map(t=>decodeFunctionData({abi:ownershipABI,data:t.transaction.data}).functionName),['proposeOwner','acceptOwner','setPolicy']);
    assert.equal(first.transactions[0].transaction.from,operator.account.address.toLowerCase());
    assert.equal(first.transactions[1].transaction.from,opts.owner);
    const send=async item=>{const tx=item.transaction;const wallet=wallets.find(w=>w.account.address.toLowerCase()===tx.from);await receipt(await wallet.sendTransaction({to:tx.to,data:tx.data,value:BigInt(tx.value)}));};
    await send(first.transactions[0]);
    const nominated=await prepare();assert.equal(nominated.transactions.length,2);
    await send(nominated.transactions[0]);
    const accepted=await prepare();assert.equal(accepted.transactions.length,1);
    await send(accepted.transactions[0]);
    assert.equal((await prepare()).transactions.length,0);
    const result=await readHostAdmissionPolicy({hostId,ownershipContract,readAuthority:async()=>{
      const [owner,,revision,policyHash]=await a.client.readContract({address:ownershipContract,abi:ownershipABI,functionName:'authority',args:[hostId]});return {owner:owner.toLowerCase(),revision:String(revision),policyHash};
    },loadPolicy:async hash=>{assert.equal(hash,first.policyHash);return policy;}});
    assert.equal(result.owner,opts.owner);assert.equal(result.policy.requireCatalogApproval,false);
    await assert.rejects(prepareHostPolicy({...opts,owner:independent.account.address.toLowerCase()}),/another wallet/);
    await assert.rejects(prepareHostPolicy({...opts,registry:independent.account.address.toLowerCase()}),/registry/);
    await assert.rejects(prepareHostPolicy({...opts,policy:{...policy,hostId:'0x'+'f'.repeat(64)}}),/active registered/);
    await receipt(await owner.writeContract({address:ownershipContract,abi:ownershipABI,functionName:'proposeOwner',args:[hostId,independent.account.address]}));
    await assert.rejects(prepare(),/conflicting ownership nomination/);
  }finally{a.stop();}
});
