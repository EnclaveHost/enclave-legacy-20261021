// Public wallet-policy delivery across the host -> control-VM boundary. fw_cfg
// does not authorize a policy: the supervisor rechecks its on-chain commitment.
import fs from 'node:fs';
import path from 'node:path';
import {validateContractPins} from './contract-pins.mjs';
import {validateHostAdmissionPolicy,hostAdmissionPolicyHash} from './host-admission-policy.mjs';
import {hostPolicyOrigins} from './host-admission-runtime.mjs';
const address=/^0x[0-9a-f]{40}$/,id=/^0x[0-9a-f]{64}$/;
const nonzero=value=>address.test(value||'')&&!/^0x0{40}$/.test(value);
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(k=>keys.includes(k));
const maxBytes=4*1024*1024;
function read(file,limit){
 if(typeof file!=='string'||!path.isAbsolute(file))throw Error('absolute host policy input path required');
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);
 try{if(!fs.fstatSync(fd).isFile())throw Error('host policy input must be a regular file');
  const bytes=Buffer.alloc(limit+1);let size=0;
  while(size<bytes.length){const n=fs.readSync(fd,bytes,size,bytes.length-size,null);if(!n)break;size+=n;}
  if(size>limit)throw Error('host policy input too large');try{return JSON.parse(bytes.subarray(0,size).toString('utf8'));}catch{throw Error('invalid host policy JSON');}
 }finally{fs.closeSync(fd);}
}
export function validateMetalHostPolicy(wire){
 if(!exact(wire,['version','hostId','ownershipContract','pins','policies','policyOrigins'])||wire.version!==1||!id.test(wire.hostId)||!nonzero(wire.ownershipContract)||
   !Array.isArray(wire.policies)||wire.policies.length>8||Buffer.byteLength(JSON.stringify(wire))>maxBytes)throw Error('invalid metal host policy configuration');
 const contracts=validateContractPins(wire.pins),policyOrigins=hostPolicyOrigins(wire.policyOrigins);
 const policies=wire.policies.map(value=>{
  const policy=validateHostAdmissionPolicy(value);
  if(policy.hostId!==wire.hostId||policy.ownershipContract!==wire.ownershipContract)throw Error('metal policy belongs to another host or ownership contract');
  return policy;
 });
 return {version:1,hostId:wire.hostId,ownershipContract:wire.ownershipContract,pins:{version:1,chainId:8453,contracts},policies,policyOrigins};
}
export function prepareMetalHostPolicy(config){
 if(config===undefined)return null;
 if(!exact(config,['hostId','ownershipContract','pinsFile','policyFiles','policyOrigins'])||
   !Array.isArray(config.policyFiles)||config.policyFiles.length>8)throw Error('explicit metal host policy files required');
 return validateMetalHostPolicy({version:1,hostId:config.hostId,ownershipContract:config.ownershipContract,
  pins:read(config.pinsFile,16384),policies:config.policyFiles.map(file=>read(file,2*1024*1024)),policyOrigins:config.policyOrigins});
}
export function installMetalHostPolicy(wire,{directory='/run/enclave-host-admission'}={}){
 if(wire===undefined)return {};
 wire=validateMetalHostPolicy(wire);
 if(!path.isAbsolute(directory))throw Error('absolute guest policy directory required');
 const policies=path.join(directory,'policies'),pins=path.join(directory,'contract-pins.json');
 fs.mkdirSync(policies,{recursive:true,mode:0o700});
 const write=(file,value)=>{const temporary=file+'.new';fs.writeFileSync(temporary,JSON.stringify(value)+'\n',{mode:0o600,flag:'wx'});fs.renameSync(temporary,file);};
 write(pins,wire.pins);
 for(const policy of wire.policies)write(path.join(policies,hostAdmissionPolicyHash(policy)+'.json'),policy);
 return {ENCLAVE_CONTRACT_PINS_FILE:pins,ENCLAVE_HOST_ID:wire.hostId,ENCLAVE_HOST_OWNERSHIP:wire.ownershipContract,
  ENCLAVE_HOST_REGISTRY_PIN:wire.pins.contracts.registry,ENCLAVE_HOST_CATALOG_PIN:wire.pins.contracts.appCatalog,
  ENCLAVE_HOST_POLICY_DIR:policies,ENCLAVE_HOST_POLICY_ORIGINS:JSON.stringify(wire.policyOrigins)};
}
