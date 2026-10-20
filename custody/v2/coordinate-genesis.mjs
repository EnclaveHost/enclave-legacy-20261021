// Public, untrusted coordination only. Secret packages stay inside the measured
// custodians. Every broadcast/HPKE message is authenticated by those custodians.
import { encodeFunctionData } from 'viem';
import * as D from './digests.mjs';
import * as v2 from './protocol.mjs';
import { VAULT_V2_ABI } from './chain.mjs';
const SIG=/^0x[0-9a-fA-F]{130}$/;
async function boundedJson(r,what){
  const chunks=[];let size=0;
  for await(const c of r.body){size+=c.length;if(size>1048576)throw Error('oversized custodian response');chunks.push(c);}
  if(!r.ok)throw Error(`custodian refused ${what}: HTTP ${r.status}`);
  return JSON.parse(Buffer.concat(chunks));
}
export async function coordinateIndependentGenesis(plan,{post,get,activate=false}={}) {
  if(!Array.isArray(plan?.machines)||plan.machines.length<3||plan.machines.length>64)throw Error('3..64 genesis machines required');
  const urls=plan.machines.map(m=>{
    const u=new URL(m.endpoint);
    if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||(u.port&&u.port!=='443')||u.pathname.split('/').some(s=>s==='.'||s==='..'))throw Error('invalid custodian HTTPS endpoint');
    return m.endpoint.replace(/\/$/,'')+'/v2/custody/independent-genesis';
  });
  post ||= async(url,body)=>boundedJson(await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(120000),redirect:'error'}),body.action);
  get ||= async url=>boundedJson(await fetch(url,{signal:AbortSignal.timeout(30000),redirect:'error'}),'info');
  const stage=body=>Promise.all(urls.map((url,i)=>post(url,typeof body==='function'?body(i):body)));
  const round1=await stage({action:'start',plan});
  const acks=await stage({action:'agree',round1});
  const outgoing=await stage({action:'exchange',acks});
  const results=await stage(i=>({action:'finish',messages:outgoing.flat().filter(m=>m.recipient===i+1)}));
  if(new Set(results.map(r=>r.committeeId)).size!==1||new Set(results.map(r=>r.commitments)).size!==1)throw Error('founder results disagree');
  const packed=results[0].commitments,t=Math.ceil(2*plan.machines.length/3);
  if(!new RegExp(`^0x[0-9a-f]{${t*66}}$`).test(packed))throw Error('invalid founder commitments');
  const raw=Buffer.from(packed.slice(2),'hex');
  for(let i=0;i<t;i++)v2.pointOf(raw.subarray(i*33,(i+1)*33));
  const expected=D.committeeIdOf({...plan,Y:raw.subarray(0,33)});
  for(let i=0;i<results.length;i++){
    const r=results[i];
    if(r.id!==i+1||r.committeeId!==expected||await D.recoverDigest(D.independentGenesisDigest({...plan,committeeId:r.committeeId,commitments:packed}),r.signature)!==plan.machines[i].identity.toLowerCase())throw Error('invalid founder signature or committee scope');
  }
  // Public host bindings let ANY wallet submit the creation (the vault checks every signature) and spare the paying
  // host from reaching every peer. A peer that does not answer only removes this convenience.
  const hostSigs=await Promise.all(plan.machines.map(async m=>{
    try{const info=await get(m.endpoint.replace(/\/$/,'')+'/v2/custody/info');return SIG.test(String(info?.hostSig))?info.hostSig:null;}catch{return null;}
  }));
  const complete=hostSigs.every(Boolean);
  const transaction=complete?{to:plan.vault,value:'0',data:encodeFunctionData({abi:VAULT_V2_ABI,functionName:'createIndependentCommittee',
    args:[plan.salt,plan.machines.map(({identity,encKey,endpoint,chipId,registryId,measurement})=>({identity,encKey,endpoint,chipId,registryId,measurement})),
      packed,plan.codeSet,results.map(r=>r.signature),hostSigs]})}:null;
  const activated=[],unadopted=[];
  // One gas payer creates the committee. Later members observe it and adopt;
  // concurrent creation would needlessly spend gas on duplicate transactions.
  // A member whose host refuses to pay or is down does not stop the others; it is retried once after another
  // member's activation, when it only has to adopt from the chain.
  if(activate){
    const body={action:'activate',results,...(complete?{hostSigs}:{})};
    let pending=urls.map((_,i)=>i);const reasons={};
    for(let round=0;round<2&&pending.length;round++){
      const left=[];
      for(const i of pending){
        try{activated.push({id:i+1,...await post(urls[i],body)});}
        catch(e){left.push(i);reasons[i]=String(e?.message||'refused').slice(0,200);}
      }
      if(left.length===pending.length&&!activated.length)break;
      pending=left;
    }
    for(const i of pending)unadopted.push({id:i+1,reason:reasons[i]});
  }
  return {committeeId:results[0].committeeId,commitments:results[0].commitments,results,hostSigs,transaction,activated,unadopted,chainVerified:false};
}
