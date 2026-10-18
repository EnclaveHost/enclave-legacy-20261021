// Transitional consumers (the legacy DNS/API) pull public signed records from
// the independent directories. Providers/checkers never need to publish to nan.
// The destination verifies signatures, registry ownership and replay ordering;
// this process holds no signing key and never changes a verdict.
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {DirectoryClient,boundedJSON,directoryOrigins} from '../../network/directory-client.mjs';

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

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const config=JSON.parse(await fs.readFile(process.argv[2],'utf8'));
  const sources=new DirectoryClient({origins:config.directories}),sent=new Map();let busy=false;
  const sync=async()=>{
    if(busy)return;busy=true;
    try{const r=await mirrorProviderPass({sources,destination:config.destination,sent});if(r.accepted||r.rejected)console.log(JSON.stringify(r));}
    catch(e){console.error('public provider mirror: '+String(e.message).slice(0,300));}finally{busy=false;}
  };
  await sync();const timer=setInterval(sync,30000);
  for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{clearInterval(timer);process.exit(0);});
}
