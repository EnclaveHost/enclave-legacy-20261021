import http from 'node:http';
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {PublicDirectory} from './public-directory.mjs';
import {DirectoryClient} from './directory-client.mjs';
import {LeaseReader} from './lease-reader.mjs';
import {verifyOwnerSignature} from './owner-signature.mjs';

export function createDirectoryServer(directory,{maxInFlight=32,log=()=>{}}={}){
  let inFlight=0,tokens=100,last=Date.now(),localInFlight=0,localTokens=20;
  return http.createServer({requestTimeout:15000,headersTimeout:10000,maxHeaderSize:8192},async(req,res)=>{
    const send=(status,value)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'no-store','access-control-allow-origin':'*','x-content-type-options':'nosniff'});res.end(JSON.stringify(value));};
    if(req.method==='OPTIONS'){res.writeHead(204,{'access-control-allow-origin':'*','access-control-allow-methods':'GET, POST, OPTIONS','access-control-allow-headers':'content-type','access-control-max-age':'600'});res.end();return;}
    const now=Date.now();tokens=Math.min(100,tokens+(now-last)/100);localTokens=Math.min(20,localTokens+(now-last)/1000);last=now;
    // Reserve bounded capacity for this machine's DNS consumer. Public traffic
    // must not starve local verified-route refreshes. Forwarded headers confer
    // no privilege; only a loopback socket and these read endpoints qualify.
    const local=req.method==='GET'&&['/health','/v1/network/routes'].includes(req.url)&&['127.0.0.1','::1','::ffff:127.0.0.1'].includes(req.socket.remoteAddress);
    if(local?(localInFlight>=4||localTokens<1):(inFlight>=maxInFlight||tokens<1)){send(429,{error:'directory busy'});req.resume();return;}
    if(local){localTokens--;localInFlight++;}else{tokens--;inFlight++;}
    try{
      const u=new URL(req.url,'http://directory.local'),p=u.pathname;
      if(u.search)throw Error('query parameters are not supported');
      if(req.method==='GET'){
        if(p==='/health')return send(200,{ok:true,service:'enclave-public-directory',version:1});
        if(p==='/v1/network/providers')return send(200,{providers:await directory.providers(),checkers:directory.checkers});
        if(p==='/v1/network/records')return send(200,await directory.snapshot());
        if(p==='/v1/network/routes')return send(200,await directory.routes());
        const m=p.match(/^\/v1\/network\/policy\/(0x[0-9a-f]{64})$/);if(m)return send(200,await directory.policy(m[1]));
        return send(404,{error:'public record not found'});
      }
      if(req.method!=='POST')return send(405,{error:'GET or POST required'});
      const policy=p.match(/^\/v1\/network\/policy\/(0x[0-9a-f]{64})$/);
      const kind=({'/v1/network/providers':'provider','/v1/network/qualifications':'qualification','/v1/network/routes':'route'})[p]||(policy?'policy':null);
      if(!kind){req.resume();return send(404,{error:'not a public record endpoint'});}
      let size=0;const chunks=[];
      for await(const chunk of req){size+=chunk.length;if(size>65536){send(413,{error:'record too large'});req.destroy();return;}chunks.push(chunk);}
      const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const envelope=kind==='policy'?body.envelope:kind==='route'?body.publication:body;
      if(policy&&envelope?.policy?.deploymentId!==policy[1])throw Error('policy path mismatch');
      const changed=await directory.accept(kind,envelope);send(200,{ok:true,changed});
    }catch(e){log('directory refusal '+String(req.url).slice(0,120)+': '+String(e.message).slice(0,200));if(!res.headersSent)send(400,{error:String(e.message).slice(0,200)});}
    finally{if(local)localInFlight--;else inFlight--;if(Date.now()-now>4000)log('slow public request '+String(req.url).slice(0,120)+' '+(Date.now()-now)+'ms');}
  });
}

export async function runDirectory(config){
  const log=m=>console.log(new Date().toISOString(),m);
  const reader=new LeaseReader({rpc:config.rpc,addressBook:config.addressBook,authorityPins:config.authorityPins,includeHostPayout:true});
  const leases=new Map(),operators=new Map();let registry=null,registryAt=0,refreshLeases=null;
  const leaseOf=async id=>{
    const cached=leases.get(id);if(cached&&cached.at+15000>Date.now())return cached.row;
    // Admission is serialized, so refreshing one app at a time defeats the
    // reader's multicall batching. Refresh known publications at one block.
    if(refreshLeases){await refreshLeases;return leaseOf(id);}
    refreshLeases=(async()=>{
      const s=await directory.read();
      const ids=[id,...Object.keys(s.publications).filter(x=>x!==id)].slice(0,256);
      const rows=await reader.refresh(ids),at=Date.now(),byId=new Map(rows.map(row=>[row.id,row]));
      for(const key of ids)leases.set(key,{at,row:byId.get(key)});
    })();
    try{await refreshLeases;}finally{refreshLeases=null;}
    return leases.get(id)?.row;
  };
  const hostOperator=async id=>{
    if(!registry||registryAt+30000<Date.now()){registry=await reader.bookAddress('registry');registryAt=Date.now();}
    const cached=operators.get(id);if(cached&&cached.at+15000>Date.now())return cached.operator;
    const [h]=await reader.registryEntries(registry,[id]);const operator=h?.active?h.operator:null;
    operators.set(id,{at:Date.now(),operator});return operator;
  };
  const directory=new PublicDirectory({directory:config.stateDir,checkers:config.checkers,leaseOf,hostOperator,
    verifyOwner:(owner,message,signature)=>verifyOwnerSignature({reader,owner,message,signature,addressBook:config.addressBook,
      sessionVaultFactory:reader.authorityPins?.sessionVaultFactory})});
  await directory.read(); // corruption must refuse startup, not forget replay floors
  const server=createDirectoryServer(directory,{log});
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(config.port||8188,config.bind||'127.0.0.1',resolve);});
  let busy=false;
  const peers=config.peers?.length?new DirectoryClient({origins:config.peers}):null;
  const sync=async()=>{
    if(!peers||busy)return;busy=true;
    try{for(const {value} of await peers.read('/v1/network/records'))await directory.import(value);}
    catch(e){log('peer sync: '+e.message);}finally{busy=false;}
  };
  const timer=setInterval(()=>void sync(),10000);timer.unref();void sync();
  log('public signed-record directory listening on '+JSON.stringify(server.address()));
  return {server,directory,close:()=>{clearInterval(timer);server.close();}};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const config=JSON.parse(await fs.readFile(process.argv[2],'utf8'));
  const running=await runDirectory(config);
  for(const sig of ['SIGTERM','SIGINT'])process.on(sig,()=>{running.close();setTimeout(()=>process.exit(0),1000).unref();});
}
