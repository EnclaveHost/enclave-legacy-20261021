import {test,before} from 'node:test';
import assert from 'node:assert/strict';
import {createWalletClient,http,parseEther} from 'viem';
import {privateKeyToAccount,generatePrivateKey} from 'viem/accounts';
import {startAnvil} from './helpers/custody-rig.mjs';
import {compileIndependentAuthorities,independentAuthorityPlan,verifyIndependentAuthorities,verifyAuthorityRuntime,authorityReads} from '../scripts/independent-authorities.mjs';
const address=n=>'0x'+n.toString(16).padStart(40,'0');
const inputs={usdc:address(101),ledger:address(102),catalog:address(103),router:address(104),registry:address(105),enclaveOwner:address(106),keyAttestations:address(0),maxVault6:'250000000'};
let artifacts;before(()=>{artifacts=compileIndependentAuthorities();});
test('authority deployment plan has deterministic nested CREATE addresses and no mutable book dependency',()=>{
  const options={artifacts,inputs,deployer:address(200),nonce:4};
  const p=independentAuthorityPlan(options);
  assert.deepEqual(p,independentAuthorityPlan(options));
  assert.equal(new Set(Object.values(p.addresses)).size,6);
  assert.deepEqual(p.transactions.map(t=>t.nonce),[4,5,6,7]);
  assert.equal(p.transactions.every(t=>t.value==='0'&&/^0x[0-9a-f]+$/i.test(t.data)),true);
  assert.throws(()=>independentAuthorityPlan({...options,inputs:{...inputs,ledger:address(0)}}),/ledger/);
  assert.throws(()=>independentAuthorityPlan({...options,nonce:-1}),/nonce/);
});
test('real deployments match all compiled runtime bytes and intended authority bindings',async()=>{
  const a=await startAnvil();
  try{
    const account=privateKeyToAccount(generatePrivateKey());
    await a.client.request({method:'anvil_setBalance',params:[account.address,'0x'+parseEther('1').toString(16)]});
    // The dependency code is a stand-in; the separate Base fork rehearsal uses
    // the live ledger/catalog/registry and exercises accepted owner registration.
    for(const name of ['usdc','ledger','catalog','router','registry'])await a.client.request({method:'anvil_setCode',params:[inputs[name],'0x00']});
    const p=independentAuthorityPlan({artifacts,inputs,deployer:account.address,nonce:0});
    const w=createWalletClient({account,chain:a.chain,transport:http(a.url)});
    for(const tx of p.transactions){
      const r=await a.client.waitForTransactionReceipt({hash:await w.sendTransaction({data:tx.data,nonce:tx.nonce})});
      assert.equal(r.status,'success');assert.equal(r.contractAddress.toLowerCase(),tx.address.toLowerCase());
    }
    const b=await a.client.getBlock({blockTag:'latest'}),reads=authorityReads(a.client,b.hash);
    const results=await verifyIndependentAuthorities({artifacts,plan:p,...reads});
    assert.equal(Object.keys(results).length,6);
    assert.equal(results.EnclaveSecretVaultV2.bindings.sessionVaultFactory.toLowerCase(),p.addresses.PinnedSessionVaultFactory.toLowerCase());
    await assert.rejects(verifyIndependentAuthorities({artifacts,plan:p,...reads,read:async(address,abi,name,args)=>name==='hostRegistry'?inputs.ledger:reads.read(address,abi,name,args)}),/hostRegistry binding mismatch/);
    const code=await reads.code(p.addresses.EnclaveHostOwnership),bad=code.slice(0,-2)+(code.endsWith('00')?'01':'00');
    assert.throws(()=>verifyAuthorityRuntime({artifact:artifacts.contracts.EnclaveHostOwnership,code:bad,address:p.addresses.EnclaveHostOwnership}),/differs/);
  }finally{await a.stop();}
});
