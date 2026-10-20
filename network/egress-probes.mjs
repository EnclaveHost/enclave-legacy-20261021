// Connectivity observations are not an authority over leases or app identity.
// An operator chooses probes; otherwise use the configured independent RPC
// origins. A single unavailable website must not retire a working circuit.
export function egressProbeUrls(configured,rpc=[]) {
  const values=configured===undefined?[...new Set(rpc.map(value=>new URL(value).origin+'/'))]:configured;
  if(!Array.isArray(values)||values.length>8)throw Error('egress probe URLs must be a bounded list');
  const urls=values.map(value=>{
    const u=new URL(value);
    if(u.protocol!=='https:'||u.username||u.password||u.hash)throw Error('egress probes require HTTPS without credentials or fragments');
    return u.href;
  });
  if(urls.length&&new Set(urls.map(value=>new URL(value).hostname)).size<2)throw Error('egress probes require at least two independent hostnames');
  if(configured!==undefined&&!urls.length)throw Error('explicit egress probes must not be empty');
  return urls;
}
export async function probeEgressUrls(fetch,urls) {
  if(!urls.length)throw Error('configure independent egress probe URLs or chain RPCs');
  const abort=new AbortController();
  try {
    await Promise.any(urls.map(async url=>{
      const response=await fetch(new URL(url),{signal:abort.signal});
      // An authenticated HTTP refusal (including an RPC GET returning 405)
      // still proves transport connectivity. Server failures do not.
      if(response.status<200||response.status>=500)throw Error('egress probe HTTP '+response.status);
    }));
  } finally {abort.abort();}
}
