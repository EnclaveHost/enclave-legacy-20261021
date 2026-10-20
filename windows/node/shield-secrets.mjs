import {startupEgressReady} from './startup-egress.mjs';
// This host-side courier can forward only public evidence and signed ciphertext.
import https from 'node:https';
const ID=/^0x[0-9a-f]{64}$/;
const message=(id,endpoint,ts)=>`enclave-shield-secrets:${id}:${endpoint}:${ts}`;
export function createShieldSecrets({base,endpoint,relayBase,sign,fetchImpl=fetch,log=()=>{},exchangeTimeoutMs=20000,egressReady=id=>startupEgressReady(id,{configFile:process.env.ENCLAVE_STARTUP_EGRESS_CONFIG,routeFile:process.env.ENCLAVE_EGRESS_APP_ROUTES})}){
 const done=new Set(),retry=new Map();let active=false;
 const inventory=async()=>{const r=await fetchImpl(base+'/vms',{signal:AbortSignal.timeout(10000)});if(!r.ok)throw Error('manager inventory unavailable');return (await r.json()).vms;};
 async function target(id){
  if(!ID.test(id||''))throw Error('exact deployment required');
  const v=(await inventory()).find(v=>v.name===id&&v.secretDeployment===id&&!v.recovered&&v.directBootstrap!==true&&['starting','running'].includes(v.status));
  if(!v||v.relay?.host!=='127.0.0.1'||!Number.isInteger(v.relay.port)||v.relay.port<1||v.relay.port>65535)throw Error('secret guest is not reachable');
  return v;
 }
 const exchange=(v,path,body)=>new Promise((resolve,reject)=>{
  let spki;
  const q=https.request({host:'127.0.0.1',port:v.relay.port,rejectUnauthorized:false,agent:false,path,method:body?'POST':'GET',headers:{'content-type':'application/json'},signal:AbortSignal.timeout(exchangeTimeoutMs)},r=>{
   let n=0,parts=[];r.on('data',b=>{n+=b.length;if(n>65536)q.destroy(Error('guest response too large'));else parts.push(b);});
   r.on('end',()=>{if(r.statusCode!==200)return reject(Error(`guest release HTTP ${r.statusCode}`));try{resolve({body:JSON.parse(Buffer.concat(parts)),spki});}catch{reject(Error('invalid guest release response'));}});r.on('error',reject);
  });
  q.on('socket',s=>s.on('secureConnect',()=>{spki=s.getPeerX509Certificate()?.publicKey.export({type:'spki',format:'der'});}));
  q.on('error',reject);q.setTimeout(20000,()=>q.destroy(Error('guest release timeout')));q.end(body?JSON.stringify(body):undefined);
 });
 return {
  async evidence(id,nonce){
   if(!/^[0-9a-f]{64}$/.test(nonce||''))throw Error('nonce required');
   const v=await target(id),r=await exchange(v,'/.well-known/enclave-secrets?nonce='+nonce);
   if(!r.spki||r.body.doc?.transportKey!==r.spki.toString('base64')||r.body.doc.appSha256!==v.appId||r.body.doc.nonce!==nonce)throw Error('secret evidence differs from TLS guest');
   return {...r.body,handshakeSpki:r.spki.toString('base64')};
  },
  async install(b){
   const {id,...envelope}=b||{};
   if(Buffer.byteLength(JSON.stringify(envelope))>65536)throw Error('sealed release too large');
   const r=await exchange(await target(id),'/.well-known/enclave-secrets',envelope);return r.body;
  },
  async pass(){
   if(active||typeof sign!=='function')return;active=true;
   try{
    const all=await inventory(),live=new Set(all.map(v=>v.id));for(const id of done)if(!live.has(id))done.delete(id);for(const id of retry.keys())if(!live.has(id))retry.delete(id);
    for(const v of all){
     // an owner-committed (direct) domain never gets relay-staged secrets: a custody guest opens its own (shield-custody.mjs)
     if(v.directBootstrap===true)continue;
     if(v.recovered||v.status!=='starting'||v.secretDeployment!==v.name||!ID.test(v.name||'')||!v.relay||done.has(v.id)||Date.now()<(retry.get(v.id)||0))continue;
     retry.set(v.id,Date.now()+15000);
     const ts=Math.floor(Date.now()/1000),ep=endpoint.replace(/\/+$/,''),opSig=await sign(message(v.name,ep,ts));
     try{
      if(!await egressReady(v.name)){log(`sealed secrets for ${v.name.slice(0,10)} waiting for its startup egress route`);continue;}
      const r=await fetchImpl(relayBase.replace(/\/+$/,'')+'/v1/secrets/shield-release',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id:v.name,endpoint:ep,ts,opSig}),signal:AbortSignal.timeout(90000)});
      const b=await r.json();if(!r.ok||b.ok!==true)throw Error(`relay HTTP ${r.status}`);
      done.add(v.id);retry.delete(v.id);log(`sealed secrets delivered to ${v.name.slice(0,10)} (${b.count} names)`);
     }catch(e){log(`sealed secrets for ${v.name.slice(0,10)} pending: ${e.message}`);}
    }
   }finally{active=false;}
  }
 };
}
