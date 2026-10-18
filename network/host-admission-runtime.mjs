import fs from 'node:fs/promises';
import path from 'node:path';
import {parseAbi} from 'viem';
import {LeaseReader} from './lease-reader.mjs';
import {readHostAdmissionPolicy,hostAdmissionRefusal} from './host-admission-policy.mjs';
import {loadContractPins} from './contract-pins.mjs';
export {loadContractPins,validateContractPins} from './contract-pins.mjs';

const address=/^0x[0-9a-f]{40}$/,id=/^0x[0-9a-f]{64}$/;
const ownershipABI=parseAbi([
  'function registry() view returns (address)',
  'function authority(bytes32) view returns (address owner,address pendingOwner,uint64 revision,bytes32 policyHash)',
]);
const catalogABI=parseAbi([
  'function getApp(bytes32) view returns ((bytes32 appId,address publisher,string slug,string name,string description,uint32 versionCount,uint64 createdAt,uint64 updatedAt,bool active))',
  'function getVersion(bytes32,uint256) view returns ((string cid,string version,uint32 vramMb,uint32 gpuGflops,uint32 memMb,uint32 cpuGflops,uint64 createdAt,bool verified,bool yanked,string ports,uint8 approval,string config))',
]);
const nonzero=a=>address.test(a||'')&&!/^0x0{40}$/.test(a);

// Documents are public, addressed by their on-chain commitment, and may be
// distributed by any peer. A local verified cache makes admission independent
// of a particular document server. Never interpret a missing document as allow.
export const fileHostPolicyLoader=directory=>async hash=>{
  if(!id.test(hash))throw Error('policy hash required');
  const f=await fs.open(path.join(directory,hash+'.json'),'r');
  try {
    if((await f.stat()).size>2*1024*1024)throw Error('host policy document too large');
    const bytes=Buffer.alloc(2*1024*1024+1);let size=0;
    while(size<bytes.length){const r=await f.read(bytes,size,bytes.length-size,null);if(!r.bytesRead)break;size+=r.bytesRead;}
    if(size>2*1024*1024)throw Error('host policy document too large');
    return JSON.parse(bytes.subarray(0,size).toString('utf8'));
  } finally {await f.close();}
};

export function createHostAdmission({hostId,ownershipContract,registry,catalog,rpc,addressBook,policyDirectory,
  reader,loadPolicy,now=Date.now,cacheMs=15000}) {
  if(!id.test(hostId)||![ownershipContract,registry,catalog].every(nonzero))throw Error('explicit host, ownership, registry and catalog pins required');
  if(!Number.isSafeInteger(cacheMs)||cacheMs<0||cacheMs>15000)throw Error('invalid host policy cache lifetime');
  reader ||= new LeaseReader({rpc,addressBook,now});
  loadPolicy ||= fileHostPolicyLoader(policyDirectory||'');
  let cached=null,pending=null;
  const policy=async()=>{
    if(cached&&cached.reuseUntil>now())return cached;
    if(pending)return pending;
    pending=(async()=>{
      const at=now();
      const snapshot=await reader.agreed(async(client,blockNumber)=>{
        const [bound,a]=await Promise.all([
          client.readContract({address:ownershipContract,abi:ownershipABI,functionName:'registry',blockNumber}),
          client.readContract({address:ownershipContract,abi:ownershipABI,functionName:'authority',args:[hostId],blockNumber}),
        ]);
        if(String(bound).toLowerCase()!==registry)throw Error('host authority registry pin mismatch');
        return {owner:String(a[0]).toLowerCase(),revision:String(a[2]),policyHash:String(a[3]).toLowerCase()};
      });
      const resolved=await readHostAdmissionPolicy({hostId,ownershipContract,loadPolicy,readAuthority:async()=>snapshot});
      const validUntil=snapshot.timestamp+90000,reuseUntil=Math.min(at+cacheMs,validUntil);
      if(!Number.isSafeInteger(snapshot.timestamp)||snapshot.timestamp>now()+5000||snapshot.timestamp+90000<=now())throw Error('host authority snapshot expired');
      cached={...resolved,validUntil,reuseUntil};return cached;
    })().catch(e=>{cached=null;throw e;}).finally(()=>{pending=null;});
    return pending;
  };
  return {hostId,ownershipContract,registry,catalog,
    async refusal({deploymentId,appRef}) {
      const a=await policy();
      let version;
      // Only this host owner's policy can give catalog governance veto power.
      if(a.policy.requireCatalogApproval){
        const m=String(appRef||'').match(/^catalog:\/\/(0x[0-9a-fA-F]{64})\/([0-9]{1,9})$/);
        if(!m)throw Error('catalog app reference required');
        version=await reader.agreed(async(client,blockNumber)=>{
          const [app,v]=await Promise.all([
            client.readContract({address:catalog,abi:catalogABI,functionName:'getApp',args:[m[1]],blockNumber}),
            client.readContract({address:catalog,abi:catalogABI,functionName:'getVersion',args:[m[1],BigInt(m[2])],blockNumber}),
          ]);
          return {active:app.appId.toLowerCase()===m[1].toLowerCase()&&BigInt(app.versionCount)>BigInt(m[2])&&app.active===true,
            yanked:v.yanked,approval:Number(v.approval)};
        });
      }
      if(a.validUntil<=now())throw Error('host policy expired during admission');
      return hostAdmissionRefusal(a.policy,{hostId,deploymentId,appRef,version});
    },
  };
}

const names=['ENCLAVE_HOST_OWNERSHIP','ENCLAVE_HOST_REGISTRY_PIN','ENCLAVE_HOST_CATALOG_PIN','ENCLAVE_HOST_POLICY_DIR'];
export const hostAdmissionConfigured=(env=process.env)=>names.some(k=>env[k]);
export function hostAdmissionFromEnv({hostId,rpc,addressBook,env=process.env}) {
  if(!hostAdmissionConfigured(env))return null;
  if(names.some(k=>!env[k]))throw Error('incomplete wallet host admission configuration');
  const pins=loadContractPins(env);
  if(!pins||pins.registry!==env.ENCLAVE_HOST_REGISTRY_PIN.toLowerCase()||pins.appCatalog!==env.ENCLAVE_HOST_CATALOG_PIN.toLowerCase())
    throw Error('wallet host admission requires matching immutable contract pins');
  return createHostAdmission({hostId,ownershipContract:env.ENCLAVE_HOST_OWNERSHIP.toLowerCase(),
    registry:env.ENCLAVE_HOST_REGISTRY_PIN.toLowerCase(),catalog:env.ENCLAVE_HOST_CATALOG_PIN.toLowerCase(),
    policyDirectory:env.ENCLAVE_HOST_POLICY_DIR,rpc,addressBook});
}
