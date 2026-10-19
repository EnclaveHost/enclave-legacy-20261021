// Advisory prefetch-recovery probe only. Serving still requires full CID
// verification by the manager; an HTTP success is never content authority.
export function artifactGateways(value) {
 if(typeof value==='string'&&value.trimStart().startsWith('['))value=JSON.parse(value);
 const rows=Array.isArray(value)?value:[value];
 if(!rows.length||rows.length>8)throw Error('one to eight artifact gateways required');
 const result=rows.map(raw=>{
  if(typeof raw!=='string')throw Error('invalid artifact gateway');
  const url=new URL(raw);
  if(!['https:','http:'].includes(url.protocol)||url.username||url.password||url.search||url.hash)throw Error('invalid artifact gateway');
  return url.href.replace(/\/$/,'');
 });
 if(new Set(result).size!==result.length)throw Error('distinct artifact gateways required');return result;
}
export function createArtifactGatewayProbe({gateways,fetchImpl=fetch,now=Date.now,timeoutMs=10000,backoffMs=60000}) {
 const downUntil=new Map();
 return async cid=>{
  if(!/^(?:b[a-z2-7]{10,120}|Qm[1-9A-HJ-NP-Za-km-z]{44})$/.test(cid))return false;
  const origins=artifactGateways(typeof gateways==='function'?gateways():gateways).filter(url=>(downUntil.get(url)||0)<=now());
  if(!origins.length)return false;
  const controller=new AbortController();
  try{
   await Promise.any(origins.map(async url=>{
    try{
     const r=await fetchImpl(`${url}/ipfs/${cid}`,{headers:{range:'bytes=0-0'},redirect:'error',signal:AbortSignal.any([controller.signal,AbortSignal.timeout(timeoutMs)])});
     await r.body?.cancel();
     if(r.status!==200&&r.status!==206)throw Error('artifact gateway refused');
     downUntil.delete(url);
    }catch(e){if(!controller.signal.aborted)downUntil.set(url,now()+backoffMs);throw e;}
   }));return true;
  }catch{return false;}finally{controller.abort();}
 };
}
