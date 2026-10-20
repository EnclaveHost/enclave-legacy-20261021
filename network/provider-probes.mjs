import net from 'node:net';import tls from 'node:tls';import http from 'node:http';import https from 'node:https';import dgram from 'node:dgram';
import {randomBytes,createHash} from 'node:crypto';import {once} from 'node:events';
import {connectSOCKS,SocksHttpsAgent} from './socks-connect.mjs';
import {publicProviderAddress} from './provider-qualification.mjs';
// Run on the independent verifier. proxy is an SSH loopback forward to the
// host's private per-probe SOCKS endpoint; public ingress is tested directly.
// Targets. With `independent: true` the CHECKER names both: `probeZone` (the zone the canary hostname must be
// probe-<label>.<zone> in) and `outbound` (the HTTPS egress canary); neither defaults to an Enclave name, and neither
// comes from the host's manifest. Without it, the compatibility defaults stay: probe-*.enclave.host and
// https://enclave.host/ (callers that already pass `outbound` keep it).
const ZONE=/^(?=.{1,240}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;
export function probeTargets({independent=false,probeZone,outbound}={}){
 if(!independent)return {probeZone:'enclave.host',outbound:outbound??'https://enclave.host/'};
 if(typeof probeZone!=='string'||!ZONE.test(probeZone))throw Error('independent probes need the checker\'s probe zone');
 if(probeZone==='enclave.host'||probeZone.endsWith('.enclave.host'))throw Error('independent probes: the probe zone must not be an Enclave zone');
 let u;try{u=new URL(String(outbound));}catch{throw Error('independent probes need an https outbound canary');}
 if(u.protocol!=='https:'||u.username||u.password)throw Error('independent probes need an https outbound canary');
 return {probeZone,outbound:u.href};
}
export function providerProbes(manifest,{proxy=manifest.proxy,outbound,independent=false,probeZone,timeout=20000,testPorts}={}) {
 const targets=probeTargets({independent,probeZone,outbound});outbound=targets.outbound;
 const {address,hostname,token,certificateSha256,udpPort}=manifest;
 if(!Number.isInteger(udpPort)||udpPort<1||udpPort>65535)throw Error('invalid UDP canary port');
 if(!testPorts&&!publicProviderAddress(address))throw Error('public provider IP required');
 const label=String(hostname).endsWith('.'+targets.probeZone)?String(hostname).slice(0,-targets.probeZone.length-1):'';
 // the same name rule as provider-canary.mjs canaryHostname: legacy as before; independent bounded to one DNS label
 const labelOk=independent?/^probe-[a-z0-9-]{1,57}$/.test(label)&&!label.endsWith('-'):/^probe-[a-z0-9-]+$/.test(label);
 if(!/^[0-9a-f]{64}$/.test(token)||!labelOk||!/^([0-9a-f]{64})$/.test(certificateSha256))throw Error('invalid independent probe manifest');
 const request=(url,options={})=>new Promise((resolve,reject)=>{
  const u=new URL(url);const req=(u.protocol==='https:'?https:http).get(u,options,res=>{let body='';res.on('data',b=>{body+=b;if(body.length>1048576)req.destroy(Error('probe response too large'));});res.once('end',()=>resolve({status:res.statusCode,body}));res.once('error',reject);});
  req.setTimeout(timeout,()=>req.destroy(Error('probe timed out')));req.once('error',reject);
 });
 async function echo(size){
  const socket=tls.connect({host:address,port:testPorts?.https||443,servername:hostname,rejectUnauthorized:false,minVersion:'TLSv1.2'});socket.on('error',()=>{});
  const timer=setTimeout(()=>socket.destroy(Error('provider TLS probe timed out')),timeout);
  try{
   await once(socket,'secureConnect');const fingerprint=createHash('sha256').update(socket.getPeerCertificate().raw).digest('hex');
   if(fingerprint!==certificateSha256)throw Error('canary TLS key mismatch');
   const chunks=socket[Symbol.asyncIterator]();let pending=Buffer.alloc(0);
   const read=async length=>{while(pending.length<length){const next=await chunks.next();if(next.done)throw Error('canary stream closed');pending=Buffer.concat([pending,next.value]);}const result=pending.subarray(0,length);pending=pending.subarray(length);return result;};
   socket.write(token+'\n');if((await read(3)).toString()!=='OK\n')throw Error('canary authentication failed');
   const sent=createHash('sha256'),received=createHash('sha256');
   for(let offset=0;offset<size;offset+=262144){const data=randomBytes(Math.min(262144,size-offset));sent.update(data);socket.write(data);received.update(await read(data.length));}
   return sent.digest('hex')===received.digest('hex');
  }finally{clearTimeout(timer);socket.destroy();}
 }
 async function denied(host,port){try{const socket=await connectSOCKS(proxy,host,port,{signal:AbortSignal.timeout(timeout)});socket.destroy();return false;}catch(e){return e.socksReply===2;}}
 return {
  tcp80:async()=>{const r=await request(`http://${net.isIP(address)===6?'['+address+']':address}:${testPorts?.http||80}/__provider_probe/${token}`,{headers:{host:hostname}});return r.status===200&&r.body===token;},
  tcp443:()=>echo(1),payloadIntegrity:()=>echo(40*1024*1024),
  udpEcho:async()=>{const socket=dgram.createSocket(net.isIP(address)===6?'udp6':'udp4');try{for(let i=0;i<5;i++){
    const data=Buffer.from(token+'.'+randomBytes(16).toString('hex'));
    const reply=new Promise((resolve,reject)=>{const timer=setTimeout(()=>{socket.off('message',message);reject(Error('UDP probe timed out'));},timeout);const message=(b,peer)=>{if(peer.address!==address||peer.port!==udpPort)return;clearTimeout(timer);socket.off('message',message);resolve(b);};socket.on('message',message);});
    socket.send(data,udpPort,address);if(!(await reply).equals(data))return false;}return true;
   }finally{socket.close();}},
  outboundHttps:async()=>{const u=new URL(outbound);if(u.protocol!=='https:'||u.username||u.password)throw Error('HTTPS canary required');const agent=new SocksHttpsAgent(proxy);try{const r=await request(outbound,{agent});return r.status>=200&&r.status<400;}finally{agent.destroy();}},
  blocksPrivateDestinations:async()=>{for(const host of ['127.0.0.1','10.0.0.1','172.16.0.1','192.168.0.1','169.254.169.254','::1','fd00::1'])if(!await denied(host,443))return false;return true;},
  blocksOwnAddresses:async()=>{for(const host of [address,...(manifest.ownAddresses||[])])if(!await denied(host,443))return false;return true;},
  blocksSmtp:()=>denied('1.1.1.1',25),
  rejectsUnauthorizedProxy:async()=>{const without=proxy.replace(/^[^@]+@/,'');try{const socket=await connectSOCKS(without,'1.1.1.1',443,{signal:AbortSignal.timeout(timeout)});socket.destroy();return false;}catch(e){return e.message==='SOCKS authentication refused';}},
 };
}
