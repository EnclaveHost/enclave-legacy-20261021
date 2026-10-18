// Local app-to-app routing (docs/design/enclave-network.md): when an app on this host connects to the website of another
// app this same host serves, the connection is handed to that app here, the way its own ingress hands a visitor's,
// instead of leaving through the caller's egress and coming back through the target's circuits. TLS still runs end to
// end into the target enclave; this only shortens the path (sia-s3 and the apps storing on it share the NucBox: their
// traffic crossed two providers each way and an upload-bound userspace TCP, ~0.9 MiB/s, 2026-10-15).
//
// Each app's egress address in the egress map becomes a front: the same loopback SOCKS5 contract as enclave-wg's
// (no authentication, CONNECT only). A CONNECT to port 443 whose TLS ClientHello names a local app's website (an app with
// public ingress, currently authorized) goes to that app; everything else is replayed to the real egress unchanged.
import net from 'node:net';
import {reader} from './host-egress.mjs';

const PEEK_MS=5000,HELLO_MAX=16384+5,MAX_SOCKETS=1024,HOST=/^(?=.{1,253}$)[a-z0-9-]+(\.[a-z0-9-]+)+$/;

// The server name of a TLS ClientHello, or null when the bytes are not one (or carry no SNI); undefined = need more bytes.
export function clientHelloSNI(b){
 if(b.length<5)return undefined;
 if(b[0]!==0x16||b[1]!==3)return null;
 const len=b.readUInt16BE(3);if(len<4||len>16384)return null;if(b.length<5+len)return undefined;
 const h=b.subarray(5,5+len);if(h[0]!==1)return null;
 const hl=(h[1]<<16)|(h[2]<<8)|h[3];if(hl+4>h.length)return null; // a ClientHello spanning records: not handled, replayed upstream
 let p=4+2+32;if(p>=h.length)return null;
 p+=1+h[p];if(p+2>h.length)return null;
 p+=2+h.readUInt16BE(p);if(p+1>h.length)return null;
 p+=1+h[p];if(p+2>h.length)return null;
 const end=p+2+h.readUInt16BE(p);p+=2;if(end>h.length)return null;
 while(p+4<=end){
  const type=h.readUInt16BE(p),l=h.readUInt16BE(p+2);p+=4;if(p+l>end)return null;
  if(type===0){
   let q=p+2;const listEnd=p+l;
   while(q+3<=listEnd){const nt=h[q],nl=h.readUInt16BE(q+1);q+=3;if(q+nl>listEnd)return null;if(nt===0)return h.subarray(q,q+nl).toString('latin1').toLowerCase();q+=nl;}
   return null;
  }
  p+=l;
 }
 return null;
}

export class LocalAppRouter {
 // target(name) -> deploymentId of a local app whose website may be reached now, or null; forward(stream, id) hands a
 // raw connection to that app (the host's ingress forwarder)
 constructor({target,forward,connect=net.connect,log=()=>{}}){
  Object.assign(this,{target,forward,connect,log});this.fronts=new Map();this.closed=false;this.seen=new Set();
 }
 // the front for one upstream egress address (created once, kept while the address is in use)
 async front(source,upstream){
  const key=source+' '+upstream;let f=this.fronts.get(key);
  if(f)return f.address;
  const sockets=new Set();
  const server=net.createServer(c=>{
   if(this.closed||sockets.size>=MAX_SOCKETS){c.destroy();return;}
   sockets.add(c);c.once('close',()=>sockets.delete(c));c.on('error',()=>{});
   void this.handle(c,source,upstream).catch(()=>c.destroy());
  });
  await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
  f={address:'127.0.0.1:'+server.address().port,server,sockets};this.fronts.set(key,f);return f.address;
 }
 // fronts whose upstream is no longer in use close (their open connections with them)
 prune(keep){for(const [k,f] of this.fronts)if(!keep.has(k)){this.fronts.delete(k);for(const s of f.sockets)s.destroy();f.server.close();}}
 close(){this.closed=true;this.prune(new Set());}
 async handle(c,source,upstream){
  c.setTimeout(20000,()=>c.destroy());
  const rd=reader(c);
  const [ver,n]=await rd(2);if(ver!==5||!n)return c.destroy();
  const methods=await rd(n);if(!methods.includes(0)){c.end(Buffer.from([5,0xff]));return;}
  c.write(Buffer.from([5,0]));
  const head=await rd(4);const [v,cmd,,atyp]=head;if(v!==5)return c.destroy();
  let addr;
  if(atyp===1)addr=await rd(4);else if(atyp===4)addr=await rd(16);
  else if(atyp===3){const l=await rd(1);addr=Buffer.concat([l,await rd(l[0])]);}
  else{c.end(Buffer.from([5,8,0,1,0,0,0,0,0,0]));return;}
  const portB=await rd(2),port=portB.readUInt16BE(0);
  const request=Buffer.concat([head,addr,portB]);
  const name=atyp===3?addr.subarray(1).toString('latin1').toLowerCase():null;
  if(cmd!==1||port!==443)return this.replay(c,rd,upstream,request,null);
  // a name that is a local app: straight to it; otherwise read the ClientHello (callers resolve names themselves and
  // connect to an exit's address, which many apps share: only the server name says which app is meant)
  let local=name?this.target(name):null,hello=Buffer.alloc(0);
  if(!local){
   c.write(Buffer.from([5,0,0,1,0,0,0,0,0,0]));
   const deadline=Date.now()+PEEK_MS;let sni;
   while((sni=clientHelloSNI(hello))===undefined&&hello.length<HELLO_MAX&&Date.now()<deadline){
    const more=await rd.some(Math.max(1,deadline-Date.now()));
    if(!more)break;hello=Buffer.concat([hello,more]);
   }
   local=sni?this.target(sni):null;
   if(!local)return this.replay(c,rd,upstream,request,hello,sni);
  }else c.write(Buffer.from([5,0,0,1,0,0,0,0,0,0]));
  const rest=Buffer.concat([hello,rd.rest()]);
  if(!this.seen.has(source+local)){this.seen.add(source+local);this.log(`local route: app ${source.slice(0,10)} -> app ${local.slice(0,10)} on this host`);}
  // the forwarder starts reading: resuming here first would let the first bytes go by unread
  c.setTimeout(0);if(rest.length)c.unshift(rest);
  await this.forward(c,local);
 }
 // the connection goes to the real egress as it came: the same SOCKS request; an already answered one (after a peek)
 // swallows the upstream's reply and fails closed if the upstream refuses - except that a refused address is first
 // retried once by the server name its ClientHello carries. TLS verifies that name end to end, and the egress, given the
 // name, picks an address it may reach: a circuit refuses its own providers' addresses, and an exit is often also the
 // ingress of the app the caller wants (eyesoff -> a69dcbba and 38f368d6, both served through eyesoff's exit
 // 146.190.246.39: every MCP call that resolved to it ended in a TlsProtocolError, 2026-10-18)
 async replay(c,rd,upstream,request,sent,sni=null){
  let u=await this.open(upstream,request);
  if(u&&u.rh[1]!==0&&sent!==null&&request[3]!==3&&sni&&HOST.test(sni)){
   u.up.destroy();
   u=await this.open(upstream,Buffer.concat([Buffer.from([5,1,0,3,sni.length]),Buffer.from(sni,'latin1'),request.subarray(-2)]));
  }
  if(!u)return c.destroy();
  const {up,ur,rh,skip,tail}=u;
  const close=()=>{c.destroy();up.destroy();};up.on('error',close);c.on('error',close);
  if(sent===null)c.write(Buffer.concat([rh,rh[3]===3?Buffer.from([skip]):Buffer.alloc(0),tail]));
  else if(rh[1]!==0)return close();
  if(rh[1]!==0){c.end();up.destroy();return;}
  const fromClient=Buffer.concat([sent||Buffer.alloc(0),rd.rest()]),fromUp=ur.rest();
  c.setTimeout(0);
  if(fromClient.length)up.write(fromClient);if(fromUp.length)c.write(fromUp);
  c.once('close',close);up.once('close',close);c.pipe(up);up.pipe(c);c.resume();up.resume();
 }
 // one SOCKS CONNECT to the real egress: the open upstream and its reply (refusals included), or null when it never answered
 async open(upstream,request){
  const i=upstream.lastIndexOf(':');
  const up=this.connect({host:upstream.slice(0,i),port:+upstream.slice(i+1)});up.on('error',()=>{});
  try{
   await new Promise((r,j)=>{up.once('connect',r);up.once('error',j);});
   const ur=reader(up);
   up.write(Buffer.from([5,1,0]));const g=await ur(2);if(g[0]!==5||g[1]!==0){up.destroy();return null;}
   up.write(request);
   const rh=await ur(4);const skip=rh[3]===1?4:rh[3]===4?16:(await ur(1))[0];const tail=await ur(skip+2);
   return {up,ur,rh,skip,tail};
  }catch{up.destroy();return null;}
 }
}
