#!/usr/bin/env node
// Does not need Enclave API authentication, session issuance or release tickets.
// The signed plan must already contain all host-operator permits.
import fs from 'node:fs';
import {coordinateIndependentGenesis} from '../custody/v2/coordinate-genesis.mjs';
import {parseUniqueJSON} from '../sdk/bootstrap/package.mjs';
import {createChainReaderV2} from '../custody/v2/chain.mjs';
import {machineHash} from '../custody/v2/digests.mjs';
const argv=process.argv.slice(2);
const arg=n=>{const i=argv.indexOf(n);return i<0?null:argv[i+1];};
try{
 const file=arg('--plan'),out=arg('--out');
 if(!file||!out)throw Error('usage: node scripts/independent-custody.mjs --plan signed-plan.json --out result.json [--activate --rpcs HTTPS,HTTPS]');
 const raw=fs.readFileSync(file);if(raw.length>262144)throw Error('genesis plan too large');
 const plan=parseUniqueJSON(raw.toString('utf8'));
 let reader=null;
 if(argv.includes('--activate')){
   const rpcs=String(arg('--rpcs')||'').split(',').filter(Boolean);
   if(rpcs.length<2||new Set(rpcs.map(r=>new URL(r).hostname)).size!==rpcs.length||rpcs.some(r=>new URL(r).protocol!=='https:'))throw Error('two distinct explicit HTTPS RPCs required');
   reader=createChainReaderV2({rpcs,vault:plan.vault,chainId:plan.chainId,minAgree:Math.floor(rpcs.length/2)+1,maxAgeSec:120});
   // Preflight the pinned vault/ownership surface through the same quorum.
   // Requiring every RPC to answer here would reintroduce a single-peer veto.
   await reader.readRegistryEntry({registryId:plan.machines[0].registryId});
 }
 const result=await coordinateIndependentGenesis(plan,{activate:argv.includes('--activate')});
 if(reader){
   const {committee:c}=await reader.readCommittee({committeeId:result.committeeId});
   if(!c||c.epoch!==1||c.t!==Math.ceil(2*plan.machines.length/3)||c.W!==plan.machines.length||c.machines.length!==plan.machines.length||
      c.machines.some((m,i)=>m.enclave||machineHash(m)!==machineHash(plan.machines[i]))||'0x'+Buffer.from(c.commitments).toString('hex')!==result.commitments)throw Error('on-chain committee differs from founder agreement');
   result.chainVerified=true;
 }
 fs.writeFileSync(out,JSON.stringify(result,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({committeeId:result.committeeId,chainVerified:result.chainVerified,activatedMembers:result.activated.length,output:out}));
}catch{console.error('Independent custody formation failed; check the signed plan, member availability and on-chain state. No secret material was printed.');process.exitCode=1;}
