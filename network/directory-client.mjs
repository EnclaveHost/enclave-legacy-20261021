import {recoverMessageAddress} from 'viem';
import {verifyProviderRecord,validateQualification,qualificationMessage} from './provider-directory.mjs';
import {verifyNetworkPolicy} from './network-policy.mjs';
import {recordHash} from './route-record.mjs';
// Public-record transport only. Never send credentials, BYO configs or control
// requests here. HTTP IP endpoints are allowed because callers verify signatures;
// transport supplies availability, never authority. Redirects are forbidden.
export function directoryOrigins(values){
  if(!Array.isArray(values)||values.length<1||values.length>8)throw Error('1..8 directory origins required');
  return [...new Set(values.map(v=>{
    const u=new URL(v);if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.search||u.hash||u.pathname!=='/')throw Error('directory origin required');
    return u.origin;
  }))];
}
export async function boundedJSON(response,maxBytes=4*1024*1024){
  if(!response.ok)throw Error('directory HTTP '+response.status);
  if(Number(response.headers.get('content-length'))>maxBytes)throw Error('directory response too large');
  const reader=response.body.getReader();let size=0;const chunks=[];
  try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes)throw Error('directory response too large');chunks.push(Buffer.from(value));}}
  catch(e){await reader.cancel().catch(()=>{});throw e;}
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
export class DirectoryClient {
  constructor({origins,fetch=globalThis.fetch,timeoutMs=8000,retryCooldownMs=30000}){this.origins=directoryOrigins(origins);Object.assign(this,{fetch,timeoutMs,retryCooldownMs});this.failedUntil=new Map();}
  async read(path){
    this.checkPath(path);
    // A circuit cannot reach its own providers' public IPs. Do not repeat those
    // timeouts for every app and exhaust the lease lifetime during cold startup.
    const ready=this.origins.filter(origin=>(this.failedUntil.get(origin)||0)<=Date.now());
    const origins=ready.length?ready:this.origins;
    const results=await Promise.allSettled(origins.map(async origin=>{try{
      const response=await this.fetch(origin+path,{redirect:'error',credentials:'omit',signal:AbortSignal.timeout(this.timeoutMs)});
      // Legacy relays report an unset policy as 404; new replicas use a null envelope.
      if(response.status===404&&path.startsWith('/v1/network/policy/')){await response.body?.cancel();this.failedUntil.delete(origin);return {origin,value:{envelope:null}};}
      const value=await boundedJSON(response);this.failedUntil.delete(origin);return {origin,value};
    }catch(e){this.failedUntil.set(origin,Date.now()+this.retryCooldownMs);throw e;}
    }));
    const answers=results.filter(r=>r.status==='fulfilled').map(r=>r.value);
    if(!answers.length)throw Error('all public directories unavailable: '+results.map(r=>String(r.reason?.message||'unavailable').slice(0,200)).join('; '));
    return answers;
  }
  async publish(path,value){
    this.checkPath(path);
    const body=JSON.stringify(value);if(Buffer.byteLength(body)>65536)throw Error('public record too large');
    const results=await Promise.allSettled(this.origins.map(async origin=>{
      const r=await this.fetch(origin+path,{method:'POST',redirect:'error',credentials:'omit',headers:{'content-type':'application/json'},body,signal:AbortSignal.timeout(this.timeoutMs)});
      if(!r.ok){const detail=await boundedJSON(new Response(r.body,{headers:r.headers}),4096).then(b=>String(b.error||'').slice(0,200)).catch(()=>'');throw Error('directory HTTP '+r.status+' '+detail);}await r.body?.cancel();return origin;
    }));
    const accepted=results.filter(r=>r.status==='fulfilled').map(r=>r.value);
    if(!accepted.length)throw Error('all public directory publications failed: '+results.map(r=>String(r.reason?.message||'unavailable').slice(0,200)).join('; '));
    return accepted;
  }
  async providers({hostOperator,now=Date.now()}={}){
    const answers=await this.read('/v1/network/providers'),records=new Map(),conflicts=new Set(),entries=[];
    for(const {value} of answers)for(const entry of (Array.isArray(value?.providers)?value.providers:[]).slice(0,4096)){
      try{
        const r=await verifyProviderRecord(entry.record,{hostOperator,now}),old=records.get(r.providerId);
        entries.push(entry);
        if(!old||r.issuedAt>old.record.issuedAt){records.set(r.providerId,entry.record);conflicts.delete(r.providerId);}
        else if(r.issuedAt===old.record.issuedAt&&recordHash(r)!==recordHash(old.record))conflicts.add(r.providerId);
      }catch{/* An invalid copy must not hide a valid independently signed one. */}
    }
    const out=[];
    for(const [id,envelope] of records){
      if(conflicts.has(id))continue;
      const r=envelope.record,byChecker=new Map();
      for(const e of entries.filter(e=>e.record.record.providerId===id))for(const env of (e.qualifications||[e.qualification]).filter(Boolean).slice(0,16)){
        try{
          const q=validateQualification(env.qualification);
          if(q.expiresAt<=now||q.issuedAt>now+60000||!['providerId','operator','address','wgExitKey','wgGuardKey'].every(k=>q[k]===r[k]))continue;
          const signer=(await recoverMessageAddress({message:qualificationMessage(q),signature:env.signature})).toLowerCase();
          const old=byChecker.get(signer);
          // Keep signed negative verdicts as well as positive ones. A stale
          // mirror cannot hide a newer security failure seen by another.
          if(!old||q.issuedAt>old.qualification.issuedAt||(q.issuedAt===old.qualification.issuedAt&&(env.onchain?.expires||0)>(old.onchain?.expires||0)))byChecker.set(signer,env);
        }catch{}
      }
      out.push({record:envelope,qualifications:[...byChecker.values()]});
    }
    return {providers:out};
  }
  async policy(id,{owner,verify}={}){
    const answers=await this.read('/v1/network/policy/'+id),valid=[];let invalid=false;
    for(const {value} of answers){if(!value?.envelope)continue;try{
      await verifyNetworkPolicy(value.envelope,{owner,deploymentId:id,verify});valid.push(value.envelope);
    }catch{invalid=true;}}
    valid.sort((a,b)=>b.policy.nonce-a.policy.nonce);
    if(valid.some(e=>e.policy.nonce===valid[0].policy.nonce&&recordHash(e.policy)!==recordHash(valid[0].policy)))throw Error('owner policy equivocation');
    if(!valid.length&&invalid)throw Error('no valid owner policy available');
    return valid[0]||null;
  }
  checkPath(p){if(!/^\/v1\/network\/(?:providers|qualifications|routes|records|policy\/0x[0-9a-f]{64})$/.test(p))throw Error('not a public-record path');}
}
