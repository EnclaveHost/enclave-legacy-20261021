// Read-only enrollment/policy preparation. No wallet, key, nonce or broadcast.
import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import {parseAbi,encodeFunctionData,keccak256} from 'viem';
import {LeaseReader} from '../../network/lease-reader.mjs';
import {hostABI} from '../../network/registry-abi.mjs';
import {validateHostAdmissionPolicy,hostAdmissionPolicyHash} from '../../network/host-admission-policy.mjs';
export const ownershipABI=parseAbi([
  'function registry() view returns (address)',
  'function authority(bytes32) view returns (address owner,address pendingOwner,uint64 revision,bytes32 policyHash)',
  'function proposeOwner(bytes32 hostId,address next)',
  'function acceptOwner(bytes32 hostId)',
  'function setPolicy(bytes32 hostId,bytes32 policyHash)',
]);
const zero='0x'+'0'.repeat(40);
const address=value=>typeof value==='string'&&/^0x[0-9a-f]{40}$/.test(value)&&value!==zero;

export async function prepareHostPolicy({policy,owner,registry,reader}) {
  policy=validateHostAdmissionPolicy(policy);
  if(!address(owner)||!address(registry)||!address(policy.ownershipContract))throw Error('exact nonzero owner, registry and ownership contract required');
  const observation=await reader.agreed(async(client,blockNumber)=>{
    const code=await client.getCode({address:policy.ownershipContract,blockNumber});
    if(!code||code==='0x')throw Error('ownership contract must be deployed before preparing enrollment');
    const pinnedRegistry=(await client.readContract({address:policy.ownershipContract,abi:ownershipABI,functionName:'registry',blockNumber})).toLowerCase();
    if(pinnedRegistry!==registry)throw Error('ownership registry does not match the selected pin');
    const [entry,a]=await Promise.all([
      client.readContract({address:registry,abi:hostABI,functionName:'get',args:[policy.hostId],blockNumber}),
      client.readContract({address:policy.ownershipContract,abi:ownershipABI,functionName:'authority',args:[policy.hostId],blockNumber}),
    ]);
    if(!entry.active||!address(entry.operator.toLowerCase()))throw Error('host must have an active registered operator');
    return {ownershipCodeHash:keccak256(code),registry,hostId:policy.hostId,endpoint:entry.endpoint,
      operator:entry.operator.toLowerCase(),owner:a[0].toLowerCase(),pendingOwner:a[1].toLowerCase(),revision:String(a[2]),policyHash:a[3].toLowerCase()};
  });
  // This tool cannot silently seize or transfer an already owned host, or
  // replace a nomination made by another workflow.
  if(observation.owner!==zero&&observation.owner!==owner)throw Error('host already belongs to another wallet; explicit ownership transfer required');
  if(observation.pendingOwner!==zero&&observation.pendingOwner!==owner)throw Error('conflicting ownership nomination; resolve it before preparing enrollment');
  const policyHash=hostAdmissionPolicyHash(policy),transactions=[];
  const add=(from,functionName,args,purpose)=>transactions.push({purpose,transaction:{chainId:8453,from,to:policy.ownershipContract,value:'0x0',data:encodeFunctionData({abi:ownershipABI,functionName,args})}});
  if(observation.owner===zero){
    if(observation.pendingOwner===zero)add(observation.operator,'proposeOwner',[policy.hostId,owner],'Registered host operator nominates the owning wallet');
    add(owner,'acceptOwner',[policy.hostId],'Nominated wallet accepts ownership of this host only');
  }
  if(observation.owner===zero||observation.policyHash!==policyHash)add(owner,'setPolicy',[policy.hostId,policyHash],'Owning wallet commits this host-local admission policy');
  return {status:'prepared-not-signed',policyHash,policy,observation,transactions,
    instructions:['Place the policy document on the host before committing its hash.',
      'Execute in order; re-read authority and simulate each transaction after its prerequisite confirms.',
      'Refresh nonce and fees at signing time. No gas estimate or signature is included.',
      'Activate the pinned host runtime only after ownership and policy read-back succeed.',
      'These transactions affect only this host; independent hosts retain their own policies.']};
}

async function main(){
  const {values}=parseArgs({options:{policy:{type:'string'},owner:{type:'string'},registry:{type:'string'},book:{type:'string'},out:{type:'string'},rpc:{type:'string',multiple:true}}});
  if(!values.policy||!values.owner||!values.registry||!values.book||!values.out)throw Error('usage: --policy <json> --owner <wallet> --registry <pin> --book <address> --out <new-directory> [--rpc <https-origin> ...]');
  const file=await fs.open(values.policy,'r');let policy;
  try {const bytes=Buffer.alloc(2*1024*1024+1);let size=0;while(size<bytes.length){const {bytesRead}=await file.read(bytes,size,bytes.length-size,null);if(!bytesRead)break;size+=bytesRead;}if(size===bytes.length)throw Error('policy file too large');policy=JSON.parse(bytes.subarray(0,size).toString('utf8'));}finally{await file.close();}
  const reader=new LeaseReader({addressBook:values.book,rpc:values.rpc||['https://base-rpc.publicnode.com','https://base.drpc.org','https://mainnet.base.org']});
  const prepared=await prepareHostPolicy({policy,owner:values.owner.toLowerCase(),registry:values.registry.toLowerCase(),reader});
  await fs.mkdir(values.out); // Never overwrite an earlier signing package.
  await fs.writeFile(path.join(values.out,prepared.policyHash+'.json'),JSON.stringify(prepared.policy,null,2)+'\n',{flag:'wx'});
  await fs.writeFile(path.join(values.out,'transactions.json'),JSON.stringify(prepared,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify({status:prepared.status,hostId:policy.hostId,policyHash:prepared.policyHash,transactions:prepared.transactions.length}));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(e=>{console.error(e.shortMessage||e.message);process.exitCode=1;});
