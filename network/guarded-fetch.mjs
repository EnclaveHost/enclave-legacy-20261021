import https from 'node:https';
import http from 'node:http';
import net from 'node:net';
import {SocksHttpsAgent,SocksPublicHttpAgent} from './socks-connect.mjs';

export function withGuardedFailover(proxy,fetchForProxy){
    const failedUntil=new Map();let preferred;
    return async(input,init={})=>{
      const entries=await proxy();if(!Array.isArray(entries)||!entries.length||entries.length>2||entries.some(p=>typeof p!=='string'||!p))throw new Error('guarded control transport unavailable');
      const now=Date.now(),ordered=[...entries].sort((a,b)=>Number((failedUntil.get(a)||0)>now)-Number((failedUntil.get(b)||0)>now)||Number(b===preferred)-Number(a===preferred));
      let error;
      for(const entry of ordered){
        if(init.signal?.aborted)throw init.signal.reason;
        try{
          const result=await fetchForProxy(entry)(input,init);
          if(result.status>=500||result.status===429||result.status===403){failedUntil.set(entry,Date.now()+60000);if(entry!==ordered.at(-1))continue;}
          else{preferred=entry;failedUntil.delete(entry);}
          return result;
        }catch(e){failedUntil.set(entry,Date.now()+60000);error=e;}
      }
      throw error;
    };
}

// Fetch-compatible bounded HTTPS for chain RPC and discovery. Names are resolved
// by the guard; redirects and implicit direct/host-DNS fallbacks are forbidden.
export function guardedFetch(proxy,{maxBytes=2097152,timeoutMs=15000,publicRecords=false}={}){
  if(typeof proxy!=='function'&&(typeof proxy!=='string'||!proxy))throw new Error('explicit SOCKS proxy required');
  if(typeof proxy==='function')return withGuardedFailover(proxy,entry=>guardedFetch(entry,{maxBytes,timeoutMs,publicRecords}));
  return async(input,init={})=>{
    const url=new URL(typeof input==='string'||input instanceof URL?input:input.url);
    const publicHTTP=publicRecords&&url.protocol==='http:'&&net.isIP(url.hostname.replace(/^\[|\]$/g,''))&&
      !url.search&&/^\/v1\/network\/(?:providers|qualifications|routes|records|policy\/0x[0-9a-f]{64})$/.test(url.pathname);
    if((url.protocol!=='https:'&&!publicHTTP)||url.username||url.password||url.hash)throw new Error('guarded HTTPS URL required');
    const agent=publicHTTP?new SocksPublicHttpAgent(proxy):new SocksHttpsAgent(proxy);
    try{
      return await new Promise((resolve,reject)=>{
        const headers=Object.fromEntries(new Headers(init.headers||input.headers||{}));
        if(publicHTTP&&Object.keys(headers).some(k=>!['content-type','accept'].includes(k)))throw Error('public records cannot carry credential headers');
        const req=(publicHTTP?http:https).request(url,{method:init.method||input.method||'GET',headers,agent,signal:init.signal,timeout:timeoutMs},res=>{
          const chunks=[];let length=0;
          res.on('data',b=>{length+=b.length;if(length>maxBytes)res.destroy(new Error('guarded response too large'));else chunks.push(b);});
          res.once('error',reject);res.once('end',()=>{
            const responseHeaders=new Headers();for(const[key,value]of Object.entries(res.headers)){if(Array.isArray(value))for(const item of value)responseHeaders.append(key,item);else if(value!==undefined)responseHeaders.set(key,value);}
            resolve(new Response([204,205,304].includes(res.statusCode)?null:Buffer.concat(chunks),{status:res.statusCode,headers:responseHeaders}));
          });
        });
        req.once('error',reject);req.once('timeout',()=>req.destroy(new Error('guarded HTTPS timeout')));
        const timer=setTimeout(()=>req.destroy(new Error('guarded request deadline')),timeoutMs);req.once('close',()=>clearTimeout(timer));
        if(init.body!==undefined&&init.body!==null){if(typeof init.body!=='string'&&!Buffer.isBuffer(init.body)&&!(init.body instanceof Uint8Array)){req.destroy(new Error('bounded request body required'));return;}req.end(init.body);}else req.end();
      });
    }finally{agent.destroy();}
  };
}
