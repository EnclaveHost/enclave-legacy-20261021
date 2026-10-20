// A wallet commits this document through EnclaveHostOwnership.setPolicy.
// Consumers pin that contract and registry; payoutWallet is not an authority.
import {keccak256,toHex,parseAbi} from 'viem';
import {canonical} from './route-record.mjs';
import {catalogAdmissionRefusal} from '../site/js/core/catalog-policy.js';
const id=/^0x[0-9a-f]{64}$/,address=/^0x[0-9a-f]{40}$/;
const zero='0x'+'00'.repeat(32);
const authorityABI=parseAbi(['function authority(bytes32) view returns (address owner,address pendingOwner,uint64 revision,bytes32 policyHash)']);
export const hostAuthorityReader=reader=>async(ownershipContract,hostId)=>reader.agreed(async(client,blockNumber)=>{
 const [owner,,revision,policyHash]=await client.readContract({address:ownershipContract,abi:authorityABI,functionName:'authority',args:[hostId],blockNumber});
 return {owner:owner.toLowerCase(),revision:revision.toString(),policyHash:policyHash.toLowerCase()};
});
export function validateHostAdmissionPolicy(p){
 if(!p||p.version!==1||p.chainId!==8453||!address.test(p.ownershipContract)||!id.test(p.hostId)||
    typeof p.requireCatalogApproval!=='boolean'||Object.keys(p).some(k=>!['version','chainId','ownershipContract','hostId','requireCatalogApproval','denyDeployments','denyAppRefs'].includes(k)))throw Error('invalid host policy');
 for(const k of ['denyDeployments','denyAppRefs']){
  if(!Array.isArray(p[k])||p[k].length>4096||new Set(p[k]).size!==p[k].length)throw Error('invalid host deny list');
  for(const v of p[k])if(typeof v!=='string'||(k==='denyDeployments'?!id.test(v):!/^catalog:\/\/0x[0-9a-f]{64}\/(?:0|[1-9][0-9]{0,8})$/.test(v)))throw Error('invalid host deny entry');
 }
 return structuredClone(p);
}
export const hostAdmissionPolicyHash=p=>keccak256(toHex('enclave-host-admission:v1\n'+canonical(validateHostAdmissionPolicy(p))));
export async function readHostAdmissionPolicy({hostId,ownershipContract,readAuthority,loadPolicy}){
 if(!id.test(hostId)||!address.test(ownershipContract))throw Error('exact host authority required');
 // readAuthority MUST use an agreeing, fresh chain quorum (LeaseReader.agreed).
 const a=await readAuthority(ownershipContract,hostId);
 if(!a||!address.test(a.owner)||/^0x0{40}$/.test(a.owner)||!id.test(a.policyHash))throw Error('host ownership unavailable');
 if(a.policyHash===zero)return {owner:a.owner,revision:a.revision,policy:{version:1,chainId:8453,ownershipContract,hostId,requireCatalogApproval:false,denyDeployments:[],denyAppRefs:[]}};
 const p=validateHostAdmissionPolicy(await loadPolicy(a.policyHash));
 if(p.hostId!==hostId||p.ownershipContract!==ownershipContract||hostAdmissionPolicyHash(p)!==a.policyHash)throw Error('host policy does not match the current wallet commitment');
 return {owner:a.owner,revision:a.revision,policy:p};
}
export function hostAdmissionRefusal(p,{hostId,deploymentId,appRef,version,forPrivate=false}){
 p=validateHostAdmissionPolicy(p);
 if(p.hostId!==hostId)throw Error('host policy cannot apply to another host');
 if(typeof deploymentId!=='string'||!/^0x[0-9a-f]{64}$/i.test(deploymentId))throw Error('deployment id required');
 const ref=typeof appRef==='string'&&appRef.match(/^catalog:\/\/(0x[0-9a-fA-F]{64})\/([0-9]{1,9})$/);
 if(!ref)throw Error('catalog app reference required');
 const canonicalRef=`catalog://${ref[1].toLowerCase()}/${Number(ref[2])}`;
 if(p.denyDeployments.includes(deploymentId.toLowerCase())||p.denyAppRefs.includes(canonicalRef))return 'this host owner declines this deployment';
 const platformRefusal=catalogAdmissionRefusal(version,version,{forPrivate});
 if(platformRefusal)return platformRefusal;
 // The legacy commitment field can tighten private development admission, never bypass platform policy.
 if(p.requireCatalogApproval&&Number(version.approval)!==1)return 'this host owner requires current catalog approval';
 return null;
}
