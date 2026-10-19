// Reproducible deployment/verification primitives. All dependencies are explicit;
// no address-book writes, owner transfers, session grants or bundle migration.
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import {encodeDeployData,getContractAddress,keccak256,getAddress,encodeFunctionData,decodeFunctionResult} from 'viem';
import {compilePinnedSessionVault} from './build-pinned-session-vault.mjs';
import {compileHostOwnership,compileSecretVaultV2} from './deploy-secret-vault-v2.mjs';
import {linkBytecode} from '../site/js/lib/contract-linker.js';

export function compileIndependentAuthorities() {
  const sessions=compilePinnedSessionVault();
  const contracts={...sessions.contracts,EnclaveHostOwnership:compileHostOwnership(),EnclaveSecretVaultV2:compileSecretVaultV2()};
  const sourceSha256={...sessions.sourceSha256};
  for(const name of ['EnclaveHostOwnership','EnclaveSecretVaultV2'])sourceSha256[name+'.sol']=createHash('sha256')
    .update(fs.readFileSync(new URL('../contracts/'+name+'.sol',import.meta.url))).digest('hex');
  return {compiler:sessions.compiler,settings:{sessions:sessions.settings,custody:{viaIR:true,optimizer:{enabled:true,runs:200}}},sourceSha256,contracts};
}
export function independentAuthorityPlan({artifacts,inputs,deployer,nonce}) {
  for(const field of ['usdc','ledger','catalog','router','registry','enclaveOwner'])
    if(!/^0x[0-9a-f]{40}$/i.test(inputs[field]||'')||/^0x0{40}$/i.test(inputs[field]))throw Error(`invalid ${field} pin`);
  if(!/^0x[0-9a-f]{40}$/i.test(inputs.keyAttestations||'')||BigInt(inputs.maxVault6)<=0n)throw Error('invalid session policy');
  if(!Number.isSafeInteger(nonce)||nonce<0)throw Error('invalid deployment nonce');
  const names=['SessionVaultLib','PinnedSessionVaultFactory','EnclaveHostOwnership','EnclaveSecretVaultV2'];
  const addresses=Object.fromEntries(names.map((name,i)=>[name,getContractAddress({from:deployer,nonce:BigInt(nonce+i)})]));
  addresses.PinnedSessionAuthority=getContractAddress({from:addresses.PinnedSessionVaultFactory,nonce:1n});
  addresses.SessionVault=getContractAddress({from:addresses.PinnedSessionVaultFactory,nonce:2n});
  const libraries={'SessionVault.sol:SessionVaultLib':addresses.SessionVaultLib};
  const args={SessionVaultLib:[],PinnedSessionVaultFactory:[inputs.usdc,inputs.ledger,inputs.catalog,inputs.router,inputs.keyAttestations,BigInt(inputs.maxVault6)],
    EnclaveHostOwnership:[inputs.registry],EnclaveSecretVaultV2:[addresses.PinnedSessionAuthority,inputs.enclaveOwner,addresses.EnclaveHostOwnership]};
  const transactions=names.map((name,i)=>{
    const art=artifacts.contracts[name],code=linkBytecode('0x'+art.evm.bytecode.object,art.evm.bytecode.linkReferences||{},libraries);
    const data=encodeDeployData({abi:art.abi,bytecode:code,args:args[name]});
    return {name,nonce:nonce+i,address:addresses[name],data,dataHash:keccak256(data),value:'0'};
  });
  return {version:1,deployer:getAddress(deployer),inputs,addresses,transactions};
}

export function verifyAuthorityRuntime({artifact,code,address,libraries={}}) {
  if(!/^0x(?:[0-9a-f]{2})+$/i.test(code||''))throw Error('authority runtime missing');
  const deployed=artifact.evm.deployedBytecode;
  let expected=linkBytecode('0x'+deployed.object,deployed.linkReferences||{},libraries).slice(2).toLowerCase();
  let actual=code.slice(2).toLowerCase();
  if(actual.length!==expected.length)throw Error('authority runtime length mismatch');
  // Solidity libraries embed their own address immediately after PUSH20.
  if(expected.startsWith('73'+'00'.repeat(20))){
    expected='73'+address.slice(2).toLowerCase()+expected.slice(42);
  }
  for(const slots of Object.values(deployed.immutableReferences||{}))for(const {start,length} of slots){
    if(!Number.isSafeInteger(start)||length!==32||(start+length)*2>actual.length)throw Error('invalid immutable reference');
    actual=actual.slice(0,start*2)+'00'.repeat(length)+actual.slice((start+length)*2);
    expected=expected.slice(0,start*2)+'00'.repeat(length)+expected.slice((start+length)*2);
  }
  if(actual!==expected)throw Error('authority runtime differs from compiled source');
  return {runtimeBytes:code.slice(2).length/2,codeHash:keccak256(code)};
}

export async function verifyIndependentAuthorities({artifacts,plan,read,code}) {
  const a=plan.addresses,p=plan.inputs,libraries={'SessionVault.sol:SessionVaultLib':a.SessionVaultLib};
  const checks={};
  for(const [name,address] of Object.entries(a))checks[name]={address,...verifyAuthorityRuntime({artifact:artifacts.contracts[name],code:await code(address),address,libraries})};
  const expected={
    PinnedSessionAuthority:{deployments:p.ledger,appCatalog:p.catalog,sessionVaultFactory:a.PinnedSessionVaultFactory},
    PinnedSessionVaultFactory:{implementation:a.SessionVault},
    SessionVault:{usdc:p.usdc,book:a.PinnedSessionAuthority,router:p.router,keyAttestations:p.keyAttestations,
      maxVault6:BigInt(p.maxVault6),factory:a.PinnedSessionVaultFactory,owner:'0x0000000000000000000000000000000000000001'},
    EnclaveHostOwnership:{registry:p.registry},
    EnclaveSecretVaultV2:{book:a.PinnedSessionAuthority,enclaveOwner:p.enclaveOwner,hostOwnership:a.EnclaveHostOwnership,
      hostRegistry:p.registry,deploymentLedger:p.ledger,sessionVaultFactory:a.PinnedSessionVaultFactory},
  };
  for(const [name,getters] of Object.entries(expected)){
    checks[name].bindings={};
    for(const [getter,want] of Object.entries(getters)){
      const got=await read(a[name],artifacts.contracts[name].abi,getter,[]);
      if(String(got).toLowerCase()!==String(want).toLowerCase())throw Error(`${name}.${getter} binding mismatch`);
      checks[name].bindings[getter]=String(got);
    }
  }
  return checks;
}

export function authorityReads(client,blockHash){
  const block={blockHash,requireCanonical:true};
  return {
    code:address=>client.request({method:'eth_getCode',params:[address,block]}),
    read:async(address,abi,functionName,args=[])=>decodeFunctionResult({abi,functionName,data:await client.request({method:'eth_call',
      params:[{to:address,data:encodeFunctionData({abi,functionName,args})},block]})}),
  };
}
