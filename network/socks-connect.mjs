import net from 'node:net';
import tls from 'node:tls';
import https from 'node:https';
import http from 'node:http';
import {once} from 'node:events';

export async function connectSOCKS(proxy,host,port,{signal=AbortSignal.timeout(10000)}={}) {
  let u;try{u=new URL('socks5://'+proxy);}catch{throw new Error('invalid SOCKS proxy');}
  const ip=u.hostname.replace(/^\[|\]$/g,'');
  if(!net.isIP(ip)||!u.port||u.pathname||!Number.isInteger(port)||port<1||port>65535)throw new Error('literal SOCKS proxy and destination port required');
  const auth=!!(u.username||u.password);
  if(auth&&(ip!=='127.0.0.1'||!/^([a-f0-9]{32})$/.test(u.username)||!/^([a-f0-9]{32})$/.test(u.password)))throw new Error('invalid local proxy credentials');
  if(typeof host!=='string'||!host.length||Buffer.byteLength(host)>255||/[\x00-\x20\x7f]/.test(host))throw new Error('invalid SOCKS destination');
  const socket=net.connect({host:ip,port:Number(u.port)});
  const abort=()=>socket.destroy(new Error('SOCKS connection aborted'));
  signal.addEventListener('abort',abort,{once:true});socket.on('error',()=>{});
  const read=async n=>{
    while(true){const b=socket.read(n);if(b)return b;if(socket.destroyed||signal.aborted)throw new Error('SOCKS connection closed');
      await new Promise((resolve,reject)=>{
        const cleanup=()=>{socket.off('readable',readable);socket.off('error',error);socket.off('end',end);socket.off('close',end)};
        const readable=()=>{cleanup();resolve()},error=e=>{cleanup();reject(e)},end=()=>error(new Error('SOCKS closed during handshake'));
        socket.once('readable',readable);socket.once('error',error);socket.once('end',end);socket.once('close',end);
      });
    }
  };
  try{
    if(signal.aborted)throw new Error('SOCKS connection aborted');
    await once(socket,'connect',{signal});socket.write(Buffer.from([5,1,auth?2:0]));
    if(!(await read(2)).equals(Buffer.from([5,auth?2:0])))throw new Error('SOCKS authentication refused');
    if(auth){socket.write(Buffer.concat([Buffer.from([1,32]),Buffer.from(u.username),Buffer.from([32]),Buffer.from(u.password)]));
      if(!(await read(2)).equals(Buffer.from([1,0])))throw new Error('SOCKS authentication refused');}

    // Names remain names all the way to the remote SOCKS service. Even literal
    // IPs may use ATYP=DOMAIN without making a local DNS call.
    const name=Buffer.from(host),request=Buffer.alloc(7+name.length);request.set([5,1,0,3,name.length]);request.set(name,5);request.writeUInt16BE(port,5+name.length);socket.write(request);
    const reply=await read(4);if(reply[0]!==5||reply[1]!==0||reply[2]!==0){const error=new Error('SOCKS connect refused');error.socksReply=reply[0]===5&&reply[2]===0?reply[1]:undefined;throw error;}
    const length=reply[3]===1?4:reply[3]===4?16:reply[3]===3?(await read(1))[0]:-1;
    if(length<0)throw new Error('invalid SOCKS reply');await read(length+2);
    return socket;
  }catch(e){socket.destroy();throw e;}finally{signal.removeEventListener('abort',abort);}
}
export class SocksHttpsAgent extends https.Agent {
  constructor(proxy,{tlsOptions={},verifyPeer}={}){super({keepAlive:false,maxSockets:16});this.proxy=proxy;this.tlsOptions=tlsOptions;this.verifyPeer=verifyPeer;}
  createConnection(options,callback){
    connectSOCKS(this.proxy,options.host,Number(options.port||443)).then(socket=>{
      const connection=tls.connect({...options,...this.tlsOptions,socket});let settled=false;
      const done=(error)=>{if(settled)return;settled=true;clearTimeout(timer);if(error){connection.destroy();callback(error);}else callback(null,connection)};
      const timer=setTimeout(()=>done(new Error('TLS handshake timeout')),15000);
      connection.once('secureConnect',()=>{try{this.verifyPeer?.(connection);done();}catch(e){done(e);}});connection.once('error',done);
    },callback);
  }
}

// Only used for independently signed PUBLIC directory records, through the same
// explicit guard as HTTPS. It must never carry account or app control traffic.
export class SocksPublicHttpAgent extends http.Agent {
  constructor(proxy){super({keepAlive:false,maxSockets:16});this.proxy=proxy;}
  createConnection(options,callback){connectSOCKS(this.proxy,options.host,Number(options.port||80)).then(s=>callback(null,s),callback);}
}

// Explicit direct mode retains the same pre-request peer verification used by
// guarded probes. Merely omitting a SOCKS proxy never enables this transport.
export class DirectHttpsAgent extends https.Agent {
  constructor({tlsOptions={},verifyPeer}={}){super({keepAlive:false,maxSockets:16});this.tlsOptions=tlsOptions;this.verifyPeer=verifyPeer;}
  createConnection(options,callback){
    const connection=tls.connect({...options,...this.tlsOptions});let settled=false;
    const done=error=>{if(settled)return;settled=true;clearTimeout(timer);if(error){connection.destroy();callback(error);}else callback(null,connection);};
    const timer=setTimeout(()=>done(new Error('TLS handshake timeout')),15000);
    connection.once('secureConnect',()=>{try{this.verifyPeer?.(connection);done();}catch(e){done(e);}});connection.once('error',done);
  }
}
