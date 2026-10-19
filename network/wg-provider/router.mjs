// Public ingress: TCP 443 routed by TLS SNI and TCP 80 by Host header to the tunnel address of the peer that holds the
// name. Raw bytes only: TLS terminates inside the enclave; this never holds a certificate. An unknown or missing name
// is closed, so this is not an open proxy.
import net from 'node:net';
import {clientHelloName} from '../client-hello.mjs';

function hostHeader(buf){
 const end=buf.indexOf('\r\n\r\n');if(end<0)return buf.length>16384?'':null;
 const m=/\r\nhost:[ \t]*([^\r\n:]+)(?::\d+)?[ \t]*\r\n/i.exec(buf.subarray(0,end+2).toString('latin1'));return m?m[1].trim().toLowerCase():'';
}

export async function createRouter({port,host='0.0.0.0',route,tls=true,noSniRoute=null,count=()=>{},maxConnections=8192,log=()=>{}}){
 // Explicit IP-certificate recovery ingress only. Unknown SNI and malformed TLS still fail closed.
 if(noSniRoute!==null&&(!tls||!noSniRoute||!/^127\.\d+\.\d+\.\d+$/.test(noSniRoute.host)||
   !Number.isInteger(noSniRoute.tls)||noSniRoute.tls<1||noSniRoute.tls>65535))throw Error('no-SNI recovery route must be a loopback TLS service');
 const sockets=new Set();
 const server=net.createServer(socket=>{
  if(sockets.size>=maxConnections)return socket.destroy();
  sockets.add(socket);socket.once('close',()=>sockets.delete(socket));socket.on('error',()=>{});
  socket.setTimeout(10000,()=>socket.destroy());
  let head=Buffer.alloc(0);
  const read=chunk=>{
   head=Buffer.concat([head,chunk]);if(head.length>65536)return socket.destroy();
   const name=tls?clientHelloName(head):hostHeader(head);if(name===null)return;
   socket.removeListener('data',read);socket.pause();
   const to=tls&&name===''?noSniRoute:name&&route(name.toLowerCase());if(!to)return socket.destroy();
   // `to` is a peer's tunnel address (port 443/80 there), or a LOCAL route {host,tls,http} (main.mjs localRoutes: a
   // service on this box, e.g. a secret custodian, that shares the public ports by name)
   const local=typeof to==='object';
   const up=local?net.connect({host:to.host,port:tls?to.tls:to.http}):net.connect({host:to,port:tls?443:80});sockets.add(up);up.once('close',()=>sockets.delete(up));
   const close=()=>{socket.destroy();up.destroy();};up.on('error',close);socket.once('close',close);up.once('close',close);
   up.setTimeout(15000,()=>up.destroy());
   const meter=local?()=>{}:count;   // a local service is not a metered peer
   up.once('connect',()=>{up.setTimeout(0);socket.setTimeout(0);up.write(head);meter(to,head.length,0);
    socket.on('data',b=>meter(to,b.length,0));up.on('data',b=>meter(to,0,b.length));socket.pipe(up);up.pipe(socket);socket.resume();});
  };
  socket.on('data',read);
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,resolve);});
 return {port:server.address().port,close(){server.close();for(const s of sockets)s.destroy();}};
}
