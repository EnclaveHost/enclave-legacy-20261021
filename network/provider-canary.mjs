// A separate, bounded qualification endpoint. Its TLS certificate is unrelated
// to app certificates: guest TLS still passes through unchanged.
import tls from 'node:tls';import net from 'node:net';import dgram from 'node:dgram';import fs from 'node:fs/promises';
import {createHash,timingSafeEqual} from 'node:crypto';
import {createDirectEgress} from './direct-egress.mjs';
// The canary's NAME. Legacy (the default, unchanged): probe-<label>.enclave.host. Independent (`independent: true`): the
// host operator names `probeZone`, the reviewed public zone its chosen checkers probe in, and the hostname must be
// probe-<label>.<probeZone>. The zone is explicit configuration - never derived from the hostname, never an Enclave
// zone, never anything a checker learns from this host: the checker holds its own copy and refuses a manifest outside it
// (provider-probes.mjs probeTargets). Probes reach the canary at the host's public address by SNI/Host, so the name
// decides only what this runtime reserves for the canary; an app can never claim it (direct-runtime.mjs).
const ZONE=/^(?=.{1,240}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;
export function canaryHostname(config){
 const h=config?.hostname;
 if(config?.independent!==true){
  if(config&&config.probeZone!==undefined)throw Error('provider canary: probeZone is for an independent canary (independent: true)');
  if(typeof h!=='string'||!/^probe-[a-z0-9-]+\.enclave\.host$/.test(h))throw Error('invalid provider canary configuration');
  return h;
 }
 const zone=config.probeZone;
 if(typeof zone!=='string'||!ZONE.test(zone))throw Error('independent provider canary needs its reviewed probe zone (probeZone)');
 if(zone==='enclave.host'||zone.endsWith('.enclave.host'))throw Error('independent provider canary: the probe zone must not be an Enclave zone');
 if(typeof h!=='string'||h.length>253||!h.endsWith('.'+zone))throw Error('independent provider canary: hostname must be in its probe zone');
 const label=h.slice(0,-zone.length-1);
 if(!/^probe-[a-z0-9-]{1,57}$/.test(label)||label.endsWith('-'))throw Error('independent provider canary: hostname must be probe-<label>.<probeZone>');
 return h;
}
export async function createProviderCanary(config,{address,ownAddresses=[]}) {
 canaryHostname(config);   // the name is judged before any key, certificate or token is read
 const [key,cert,tokenRaw]=await Promise.all([fs.readFile(config.keyFile),fs.readFile(config.certFile),fs.readFile(config.tokenFile,'utf8')]);
 const token=tokenRaw.trim();if(!/^[0-9a-f]{64}$/.test(token)||!Number.isInteger(config.udpPort)||config.udpPort<1024||config.udpPort>65535)throw Error('invalid provider canary configuration');
 const sockets=new Set();let closed=false;
 const server=tls.createServer({key,cert,minVersion:'TLSv1.2'},socket=>{
  if(sockets.size>=16)return socket.destroy();sockets.add(socket);socket.on('error',()=>{});socket.once('close',()=>sockets.delete(socket));
  const timer=setTimeout(()=>socket.destroy(),30000);socket.once('close',()=>clearTimeout(timer));
  let pending=Buffer.alloc(0),authenticated=false,total=0;
  socket.on('data',chunk=>{
   if(!authenticated){pending=Buffer.concat([pending,chunk]);if(pending.length<65)return;
    if(pending[64]!==10||!timingSafeEqual(pending.subarray(0,64),Buffer.from(token)))return socket.destroy();
    authenticated=true;chunk=pending.subarray(65);pending=null;socket.write('OK\n');}
   total+=chunk.length;if(total>48*1024*1024)return socket.destroy();
   if(chunk.length&&!socket.write(chunk)){socket.pause();socket.once('drain',()=>socket.resume());}
  });
 });server.on('tlsClientError',()=>{});
 // Every resource is released if a later step fails (a busy UDP port, the egress proxy, the manifest write): a canary
 // that cannot start leaves nothing bound behind it.
 let udp=null,proxy=null,manifest,closing=null;
 try{
  await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
  udp=dgram.createSocket(address.includes(':')?'udp6':'udp4');let count=0,second=0;
  udp.on('message',(b,peer)=>{const now=Math.floor(Date.now()/1000);if(second!==now){second=now;count=0;}
   if(++count>32||b.length!==97||!timingSafeEqual(b.subarray(0,64),Buffer.from(token))||b[64]!==46)return;
   udp.send(b,peer.port,peer.address,()=>{});});
  await new Promise((r,j)=>{udp.once('error',j);udp.bind(config.udpPort,config.bindHost||'0.0.0.0',r);});
  proxy=await createDirectEgress({authorize:()=>!closed,meter:{consume:async()=>{}},ownAddresses:[address,...ownAddresses]});
  const {X509Certificate}=await import('node:crypto');const certificate=new X509Certificate(cert);
  manifest={address,hostname:config.hostname,token,udpPort:config.udpPort,certificateSha256:createHash('sha256').update(certificate.raw).digest('hex'),proxy:proxy.proxy};
  await fs.writeFile(config.manifestFile,JSON.stringify(manifest),{mode:0o600});await fs.chmod(config.manifestFile,0o600);
 }catch(e){
  closed=true;await proxy?.close().catch(()=>{});try{udp?.close();}catch{}server.close();throw e;
 }
 return {hostname:config.hostname,manifest,
  accept(socket){if(closed)return socket.destroy();const upstream=net.connect(server.address().port,'127.0.0.1');upstream.on('error',()=>socket.destroy());socket.on('error',()=>upstream.destroy());socket.once('close',()=>upstream.destroy());upstream.once('close',()=>socket.destroy());socket.pipe(upstream).pipe(socket);},
  http(req,res){if(req.method!=='GET'||req.url!=='/__provider_probe/'+token){res.writeHead(404);res.end();return;}res.writeHead(200,{'cache-control':'no-store'});res.end(token);},
  // idempotent: a second close (the runtime's, after the agent's) returns the first one's promise
  close(){return closing||=(async()=>{closed=true;for(const s of sockets)s.destroy();try{udp.close();}catch{}server.close();await proxy.close();})();}};
}
