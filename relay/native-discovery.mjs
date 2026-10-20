// Public routing metadata only. Application traffic never crosses this process.
import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {X509Certificate,createHash} from 'node:crypto';
export const ROOT='enclavehost.eth';
const SERVICES=new Set(['api','mcp']);
export function routeFor(name, map, now=Date.now()) {
 if(typeof name!=='string'||name!==name.toLowerCase()||name.length>253)return null;
 if(name.endsWith('.'+ROOT) && SERVICES.has(name.slice(0,-ROOT.length-1)))
  return {name, addresses:['134.199.235.187','134.209.248.172','165.245.191.129','146.190.246.39'],port:443,kind:'control'};
 const m=name.match(/^([0-9a-f]{8})\.app\.enclavehost\.eth$/);
 if(!m)return null;
 const row=map?.labels?.[m[1]];
 if(!row||!(row.expiresAt>now)||!row.addresses?.length)return null;
 return {name,addresses:row.addresses,port:443,kind:'application',expiresAt:row.expiresAt};
}
export function createDiscovery({getRoutes,caPem}){
 const fingerprint=createHash('sha256').update(new X509Certificate(caPem).raw).digest('hex');
 return http.createServer(async(req,res)=>{
  const json=(status,obj)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(obj));};
  let u; try { u=new URL(req.url,'http://localhost'); } catch { return json(400,{error:'invalid_url'}); }
  if(req.method!=='GET')return json(405,{error:'method_not_allowed'});
  if(u.pathname==='/native/ca.pem') {res.writeHead(200,{'content-type':'application/x-pem-file','cache-control':'public,max-age=3600'});return res.end(caPem);}
  if(u.pathname==='/native/status')return json(200,{service:'enclave-native-discovery',root:ROOT,caSha256:fingerprint});
  if(u.pathname!=='/native/resolve')return json(404,{error:'not_found'});
  try {
   const name=u.searchParams.get('name');
   const route=routeFor(name,name?.endsWith('.app.'+ROOT)?await getRoutes():null);
   if(!route)return json(404,{error:'no_current_route'});
   return json(200,{...route,caSha256:fingerprint});
  }catch{return json(503,{error:'route_discovery_unavailable'});}
 });
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 const caPem=await readFile(process.env.NATIVE_CA_CERT||'/var/lib/enclave-native-ca/ca.pem','utf8');
 const server=createDiscovery({caPem,getRoutes:async()=>{
  const r=await fetch('http://127.0.0.1:8100/v1/network/routes',{signal:AbortSignal.timeout(5000)});
  if(!r.ok)throw new Error('route map unavailable');return r.json();
 }});
 server.listen(8187,'127.0.0.1');
}
