// Transitional consumers (the legacy DNS/API) pull public signed records from
// the independent directories. Providers/checkers never need to publish to nan.
// The destination verifies signatures, registry ownership and replay ordering;
// this process holds no signing key and never changes a verdict.
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {DirectoryClient,boundedJSON,directoryOrigins} from '../../network/directory-client.mjs';
import {validateNetworkPolicy} from '../../network/network-policy.mjs';
import {qualificationMessage} from '../../network/provider-qualification.mjs';

const only=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(k=>keys.includes(k));
function publicRouteOnly(p){
  validateNetworkPolicy(p.policy);
  const b=p.bundle,d=b?.authorization?.delegation,r=b?.record;
  if(!only(b,['authorization','record','signature'])||!only(b.authorization,['delegation','signature'])||
    !only(d,['version','deploymentId','runner','chainId','deployments','policyHash','epoch','notBefore','expiresAt','publicKey','ipns'])||
    !only(r,['version','deploymentId','delegationHash','sequence','issuedAt','expiresAt','routes','qualification'])||
    !Array.isArray(r.routes)||r.routes.some(route=>!only(route,['circuit','address','port','transport'])))throw Error('non-public route fields');
  if(r.qualification){
    if(!only(r.qualification,['report','signature']))throw Error('non-public qualification fields');
    qualificationMessage(r.qualification.report);
  }
  return {version:p.version,endpoint:p.endpoint,policy:p.policy,bundle:p.bundle};
}

export async function mirrorProviderPass({sources,destination,fetch=globalThis.fetch,sent=new Map(),now=Date.now}) {
  const [origin]=directoryOrigins([destination]);
  for(const [key,expiry] of sent)if(expiry<=now())sent.delete(key);
  const answers=await sources.read('/v1/network/providers');
  const counts={accepted:0,unchanged:0,rejected:0};
  const put=async(path,envelope,expiry)=>{
    if(!Number.isSafeInteger(expiry)||expiry<=now())return;
    const body=JSON.stringify(envelope);
    if(Buffer.byteLength(body)>65536){counts.rejected++;return;}
    const key=createHash('sha256').update(path+'\n'+body).digest('hex');
    if(sent.has(key)){counts.unchanged++;return;}
    try {
      const r=await fetch(origin+path,{method:'POST',redirect:'error',credentials:'omit',
        headers:{'content-type':'application/json'},body,signal:AbortSignal.timeout(8000)});
      const reply=await boundedJSON(new Response(r.body,{headers:r.headers}),4096);
      // A mismatch is NOT a replay: retry it after a matching provider arrives.
      const stale=r.status===409&&['stale provider record','stale qualification','stale on-chain attestation'].includes(reply.error);
      if(r.ok||stale){if(sent.size<32768)sent.set(key,expiry);counts[r.ok?'accepted':'unchanged']++;}
      else counts.rejected++;
    }catch{counts.rejected++;}
  };
  for(const {value} of answers)for(const p of (Array.isArray(value?.providers)?value.providers:[]).slice(0,4096)){
    // Export only the public envelopes, never the source's arbitrary extra data.
    if(p?.record?.record)await put('/v1/network/providers',{record:p.record.record,signature:p.record.signature},p.record.record.expiresAt);
    const qualifications=Array.isArray(p?.qualifications)?p.qualifications:[p?.qualification];
    for(const q of qualifications.filter(Boolean).slice(0,16)){
      await put('/v1/network/qualifications',{qualification:q.qualification,signature:q.signature,...(q.onchain?{onchain:q.onchain}:{})},q.qualification?.expiresAt);
    }
  }
  return counts;
}

// Optional compatibility consumer of public route publications. It has no host
// key, cannot extend expiry, and must never copy diagnostic status or secrets.
// The destination performs the full policy/lease/provider/signature admission.
export async function mirrorRoutePass({sources,destination,fetch=globalThis.fetch,sent=new Map(),now=Date.now}){
  const [origin]=directoryOrigins([destination]);
  for(const [key,expiry] of sent)if(expiry<=now())sent.delete(key);
  const answers=await sources.read('/v1/network/records');
  const counts={accepted:0,unchanged:0,rejected:0},seen=new Set();
  for(const {value} of answers)for(const p of (Array.isArray(value?.publications)?value.publications:[]).slice(0,4096)){
    const expiry=p?.bundle?.record?.expiresAt;
    if(p?.version!==2||!Number.isSafeInteger(expiry)||expiry<=now())continue;
    // Shape-check public fields here; full signature and current-state admission
    // belongs to the destination. No diagnostic host status is mirrored.
    let publication;try{publication=publicRouteOnly(p);}catch{counts.rejected++;continue;}
    const body=JSON.stringify({publication});
    if(Buffer.byteLength(body)>65536){counts.rejected++;continue;}
    const key=createHash('sha256').update(body).digest('hex');
    if(seen.has(key)||sent.has(key)){counts.unchanged++;continue;}seen.add(key);
    try{
      const r=await fetch(origin+'/v1/network/routes',{method:'POST',redirect:'error',credentials:'omit',headers:{'content-type':'application/json'},body,signal:AbortSignal.timeout(8000)});
      const reply=await boundedJSON(new Response(r.body,{headers:r.headers}),4096);
      if(!r.ok||reply.ok!==true){counts.rejected++;continue;}
      if(sent.size<32768)sent.set(key,expiry);counts.accepted++;
    }catch{counts.rejected++;}
  }
  return counts;
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const config=JSON.parse(await fs.readFile(process.argv[2],'utf8'));
  if(config.routes!==undefined&&typeof config.routes!=='boolean')throw Error('routes must be boolean');
  const sources=new DirectoryClient({origins:config.directories}),sent=new Map(),routesSent=new Map();let busy=false;
  const sync=async()=>{
    if(busy)return;busy=true;
    try{
      const r=await mirrorProviderPass({sources,destination:config.destination,sent});if(r.accepted||r.rejected)console.log(JSON.stringify({providers:r}));
      if(config.routes){const routes=await mirrorRoutePass({sources,destination:config.destination,sent:routesSent});if(routes.accepted||routes.rejected)console.log(JSON.stringify({routes}));}
    }
    catch(e){console.error('public provider mirror: '+String(e.message).slice(0,300));}finally{busy=false;}
  };
  await sync();const timer=setInterval(sync,config.routes?10000:30000);
  for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{clearInterval(timer);process.exit(0);});
}
