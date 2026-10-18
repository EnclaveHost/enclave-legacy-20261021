// The host's own control traffic over the Enclave network (docs/design/enclave-network.md): chain reads, relay calls and
// route publication leave through two guarded, egress-only circuits, so RPC providers and the relay see an exit's
// address, never the host's. Replaces TUNA's control guards; same shape (proxies(), close()).
import {selectNetworkCircuits} from './wg-manager.mjs';
import {guardedFetch} from './guarded-fetch.mjs';
const ZERO='0x'+'0'.repeat(64),COOLDOWN_MAX_MS=30*60000;

export class WgControlTransport {
 constructor({runtime,providers,routes=2,probeUrl='https://api.enclave.host/v1/network/providers',probeUrls,now=Date.now,log=()=>{}}){
  Object.assign(this,{runtime,providers,routes,probeUrl,now,log});this.probeUrls=probeUrls||[probeUrl];
  if(!Array.isArray(this.probeUrls)||!this.probeUrls.length||this.probeUrls.length>8)throw Error('control probe URLs required');
  this.circuits=[];this.cooldown=new Map();this.strikes=new Map();this.closed=false;this.busy=false;
 }
 async probe(c,timeoutMs){
  const transport=guardedFetch(c.egress,{timeoutMs,maxBytes:4194304,publicRecords:true});
  await Promise.any(this.probeUrls.map(async url=>{const r=await transport(new URL(url));if(r.status!==200)throw Error('control probe HTTP '+r.status);}));
 }
 // loopback SOCKS entries of the live control circuits (guardedFetch / LeaseReader `proxy`)
 proxies=async()=>{const live=this.circuits.filter(c=>!c.closed&&c.healthy).map(c=>c.egress);if(!live.length)throw new Error('Enclave-network control transport unavailable');return live;};
 async start(){await this.reconcile();this.timer=setInterval(()=>void this.reconcile().catch(e=>this.log('control circuits: '+e.message)),15000);this.timer.unref?.();return this;}
 async reconcile(){
  if(this.busy||this.closed)return;this.busy=true;
  try{
   const providers=await this.providers();
   const byId=new Map(providers.map(p=>[p.providerId,p]));
   // a provider that lost qualification (or changed keys/address) loses the control circuit through it, now
   for(const c of [...this.circuits]){
    const g=byId.get(c.providers.guard.providerId),x=byId.get(c.providers.exit.providerId);
    const ok=g&&x&&g.address===c.providers.guard.address&&x.address===c.providers.exit.address&&g.wgGuardKey===c.providers.guard.wgGuardKey&&x.wgExitKey===c.providers.exit.wgExitKey&&g.eligibleRoles.includes('guard')&&x.eligibleRoles.includes('egress');
    if(!ok||c.closed){this.drop(c,ok?'closed':'provider no longer qualified');}
   }
   // a live circuit must still carry traffic: a provider that lost this peer (or whose egress refuses it) can leave the
   // tunnel handshaking while nothing passes. Two failed probes in a row and the circuit is replaced.
   await Promise.all(this.circuits.map(async c=>{
    try{await this.probe(c,10000);c.misses=0;}
    catch(e){c.misses=(c.misses||0)+1;if(c.misses>=2)this.drop(c,'control probe failed twice: '+e.message);}
   }));
   const keep=this.circuits.map(c=>({guard:c.providers.guard,exit:c.providers.exit}));
   if(keep.length>=this.routes)return;
   const choice=selectNetworkCircuits(providers,{routes:this.routes,ingress:false,egress:true,maxPricePerGiB6:0,keep,cooldown:this.cooldown,now:this.now()});
   for(const {guard,exit} of choice.slice(keep.length)){
    if(this.closed)return;
    let c;
    try{
     c=await this.runtime.start({deploymentId:ZERO,names:[],kind:'network',guard,exit,egress:true,exitRole:'control',gate:()=>!this.closed});
     c.on('down',reason=>this.drop(c,reason));
     await this.probe(c,15000);
     c.healthy=true;this.circuits.push(c);this.strikes.delete(guard.providerId);this.strikes.delete(exit.providerId);
     this.log(`control circuit up: guard ${guard.region} -> exit ${exit.region}`);
    }catch(e){
     await c?.close(e.message);
     const p=e.providerRole==='guard'?guard:exit;
     if((this.cooldown.get(p.providerId)||0)<=this.now()){const n=(this.strikes.get(p.providerId)||0)+1;this.strikes.set(p.providerId,n);this.cooldown.set(p.providerId,this.now()+Math.min(60000*2**(n-1),COOLDOWN_MAX_MS));}
     this.log('control circuit: '+e.message);
    }
   }
  }finally{this.busy=false;}
 }
 drop(c,reason){if(!this.circuits.includes(c))return;this.circuits=this.circuits.filter(x=>x!==c);c.healthy=false;void c.close(reason);this.log('control circuit down: '+reason);}
 async close(){this.closed=true;clearInterval(this.timer);await Promise.all(this.circuits.map(c=>c.close('stopped')));this.circuits=[];}
}
