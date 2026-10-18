// Local app-to-app routing (network/local-app-router.mjs): the SNI parser on a real ClientHello, and a front that hands
// connections to apps this host serves to the host's forwarder while everything else is replayed to the real egress.
import test from 'node:test';import assert from 'node:assert/strict';import net from 'node:net';import tls from 'node:tls';
import {clientHelloSNI,LocalAppRouter} from '../network/local-app-router.mjs';
import {HostEgress} from '../network/host-egress.mjs';

// the first bytes a real TLS client sends for servername
async function clientHello(servername){
 const srv=net.createServer();await new Promise(r=>srv.listen(0,'127.0.0.1',r));
 const got=new Promise(r=>srv.once('connection',s=>{let b=Buffer.alloc(0);s.on('data',d=>{b=Buffer.concat([b,d]);if(b.length>=5&&b.length>=5+b.readUInt16BE(3)){r(b);s.destroy();}});}));
 const c=tls.connect({host:'127.0.0.1',port:srv.address().port,servername,rejectUnauthorized:false});c.on('error',()=>{});
 const b=await got;c.destroy();srv.close();return b;
}

test('SNI from a real ClientHello; partial and non-TLS input',async()=>{
 const h=await clientHello('ABCD1234.app.enclave.host');
 assert.equal(clientHelloSNI(h),'abcd1234.app.enclave.host');
 assert.equal(clientHelloSNI(h.subarray(0,20)),undefined,'needs more bytes');
 assert.equal(clientHelloSNI(Buffer.from('GET / HTTP/1.1\r\nHost: x\r\n\r\n')),null);
 const noSni=await clientHello('');assert.equal(clientHelloSNI(noSni),null);
});

// SOCKS5 CONNECT through a front, then send bytes and collect the reply
function via(port,{ip,host,dport},send){
 return new Promise((resolve,reject)=>{
  const s=net.connect({host:'127.0.0.1',port});let buf=Buffer.alloc(0),stage=0;s.on('error',reject);
  const p=Buffer.alloc(2);p.writeUInt16BE(dport);
  s.on('data',d=>{buf=Buffer.concat([buf,d]);
   if(stage===0&&buf.length>=2){buf=buf.subarray(2);stage=1;s.write(Buffer.concat([Buffer.from([5,1,0]),ip?Buffer.from([1,...ip.split('.').map(Number)]):Buffer.concat([Buffer.from([3,host.length]),Buffer.from(host)]),p]));}
   if(stage===1&&buf.length>=10){stage=2;const code=buf[1];buf=buf.subarray(10);if(code!==0){resolve({code});s.destroy();return;}s.write(send);}
  });
  s.on('end',()=>resolve({code:0,reply:buf.toString()}));
  s.write(Buffer.from([5,1,0]));
 });
}

test('a front: local websites stay on the host, everything else goes out unchanged',async()=>{
 const id='0x'+'ee'.repeat(32);let websiteOn=true;
 // "the internet" behind the real egress: answers what it was sent
 const internet=net.createServer(c=>c.once('data',d=>c.end('internet got '+(d[0]===0x16?'tls':String(d)))));await new Promise(r=>internet.listen(0,'127.0.0.1',r));
 const dialed=[];
 const egress=new HostEgress({authorize:()=>true,lookup:async name=>name==='inside.example'?['10.1.2.3']:['93.184.216.34'],connect:({host,port,timeout})=>{dialed.push(`${host}:${port}`);return net.connect({host:'127.0.0.1',port:internet.address().port,timeout});}});
 const circuit=await egress.start({deploymentId:'0x'+'aa'.repeat(32)});
 const forwarded=[];
 const router=new LocalAppRouter({target:n=>n==='eeee.app.enclave.host'&&websiteOn?id:null,
  forward:async(stream,to)=>{forwarded.push(to);stream.once('data',d=>stream.end('app '+to.slice(0,6)+' got '+(d[0]===0x16?'tls':'?')));stream.resume();}}); // like localAppForwarder: attach, then resume
 const front=+(await router.front('0x'+'aa'.repeat(32),circuit.egress)).split(':')[1];
 const hello=await clientHello('eeee.app.enclave.host'),other=await clientHello('example.com');

 let r=await via(front,{ip:'134.199.235.187',dport:443},hello);
 assert.equal(r.reply,'app 0xeeee got tls','an exit address + a local SNI: handed to the local app');
 r=await via(front,{host:'eeee.app.enclave.host',dport:443},hello);
 assert.equal(r.reply,'app 0xeeee got tls','a local name: straight to the app');
 assert.equal(dialed.length,0,'nothing left the host for either');
 r=await via(front,{ip:'93.184.216.34',dport:443},other);
 assert.equal(r.reply,'internet got tls','another SNI: replayed to the real egress, ClientHello intact');
 r=await via(front,{host:'example.com',dport:80},Buffer.from('GET'));
 assert.equal(r.reply,'internet got GET','other ports pass straight through');
 r=await via(front,{ip:'10.0.0.1',dport:443},other);
 assert.equal(r.reply,'internet got tls','a refused address after the peek is retried once by the ClientHello\'s name');
 assert.equal(dialed.at(-1),'93.184.216.34:443','the retry went where the name resolves, never to the refused address');
 const inside=await clientHello('inside.example');
 r=await via(front,{ip:'10.0.0.1',dport:443},inside);
 assert.notEqual(r.reply,'internet got tls','the egress still refuses what it refuses (after the peek: closed, never sent)');
 websiteOn=false;
 r=await via(front,{ip:'134.199.235.187',dport:443},hello);
 assert.equal(r.reply,'internet got tls','a target without a public website is not reached locally');
 assert.deepEqual(forwarded,[id,id]);
 router.prune(new Set());await circuit.close('t');await egress.close();internet.close();
});

// eyesoff's MCP calls to a69dcbba and 38f368d6 (2026-10-18): the guest resolves the name itself and connects to one of its
// addresses; the one that is this circuit's own exit is refused by the egress, so the front retries by the server name
// and the egress dials the name's other address
test('a front: a refused exit address is retried by the server name, which reaches the other address',async()=>{
 const internet=net.createServer(c=>c.once('data',d=>c.end('internet got '+(d[0]===0x16?'tls':String(d)))));await new Promise(r=>internet.listen(0,'127.0.0.1',r));
 const dialed=[];
 const egress=new HostEgress({authorize:()=>true,own:['146.190.246.39'],lookup:async()=>['146.190.246.39','134.199.235.187'],
  connect:({host,port,timeout})=>{dialed.push(`${host}:${port}`);return net.connect({host:'127.0.0.1',port:internet.address().port,timeout});}});
 const circuit=await egress.start({deploymentId:'0x'+'aa'.repeat(32)});
 const router=new LocalAppRouter({target:()=>null,forward:async()=>assert.fail('nothing is local')});
 const front=+(await router.front('0x'+'aa'.repeat(32),circuit.egress)).split(':')[1];
 const hello=await clientHello('a69dcbba.app.enclave.host');
 let r=await via(front,{ip:'146.190.246.39',dport:443},hello);
 assert.equal(r.reply,'internet got tls');
 assert.deepEqual(dialed,['134.199.235.187:443'],'the own address was never dialed');
 r=await via(front,{ip:'146.190.246.39',dport:443},Buffer.from('GET / HTTP/1.1\r\n\r\n'));
 assert.notEqual(r.reply?.startsWith('internet got'),true,'no ClientHello, no name: the refusal stands');
 r=await via(front,{ip:'146.190.246.39',dport:80},Buffer.from('GET'));
 assert.equal(r.code,2,'an unanswered CONNECT gets the refusal itself (the caller tries its next address)');
 router.prune(new Set());await circuit.close('t');await egress.close();internet.close();
});
