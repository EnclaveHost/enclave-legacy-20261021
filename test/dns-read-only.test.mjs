import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import dgram from 'node:dgram';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
const delay=ms=>new Promise(r=>setTimeout(r,ms));
const port=()=>new Promise(resolve=>{const s=net.createServer().listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
function query(name,type=1){const h=Buffer.alloc(12);h.writeUInt16BE(0x4242,0);h.writeUInt16BE(0x100,2);h.writeUInt16BE(1,4);return Buffer.concat([h,...name.split('.').map(v=>Buffer.concat([Buffer.from([v.length]),Buffer.from(v)])),Buffer.from([0,type>>>8,type&255,0,1])]);}
async function ask(dnsPort,tcp=false,name='abcd.app.test',type=1){
 const q=query(name,type);
 if(!tcp){const socket=dgram.createSocket('udp4');try{const answer=once(socket,'message');socket.send(q,dnsPort,'127.0.0.1');return (await Promise.race([answer,delay(2000).then(()=>{throw Error('UDP timeout');})]))[0];}finally{socket.close();}}
 return new Promise((resolve,reject)=>{const socket=net.connect(dnsPort,'127.0.0.1',()=>{const n=Buffer.alloc(2);n.writeUInt16BE(q.length);socket.write(Buffer.concat([n,q]));});let data=Buffer.alloc(0);socket.on('data',chunk=>{data=Buffer.concat([data,chunk]);if(data.length>=2&&data.length>=2+data.readUInt16BE(0)){socket.destroy();resolve(data.subarray(2));}});socket.on('error',reject);socket.setTimeout(2000,()=>{socket.destroy();reject(Error('TCP timeout'));});});
}
test('read-only DNS needs no fleet or signing key, serves UDP/TCP and expires routes while its directory is down',async t=>{
 let expires=Date.now()+30000,offline=false,hits=0;
 const origin=http.createServer((_req,res)=>{hits++;res.setHeader('content-type','application/json');res.statusCode=offline?503:200;res.end(JSON.stringify({labels:{abcd:{addresses:['198.51.100.7'],expiresAt:expires}}}));});origin.listen(0,'127.0.0.1');await once(origin,'listening');t.after(()=>origin.close());
 const dnsPort=await port(),apiPort=await port();
 const env={...process.env,DNS_READ_ONLY:'1',DNS_BIND:'127.0.0.1',DNS_PORT:String(dnsPort),DNS_API_BIND:'127.0.0.1',DNS_API_PORT:String(apiPort),IP_ZONE:'ip.test',APP_ZONE:'app.test',NS_NAME:'ns.test',NET_POLL_SEC:'1',ROUTE_MAP_URL:'http://127.0.0.1:'+origin.address().port+'/v1/network/routes',ENCLAVES:'',ENCLAVE_URL:'',REGISTRY_ADDRESS:'',ADDRESS_BOOK_ADDRESS:'',BOX_ZONE:'',TCP_ZONE:'',DNS_TXT_KEY:'',SECRET:''};
 const child=spawn(process.execPath,[process.env.ENCLAVE_DNS_BIN||'relay/dns-relay.js'],{env,stdio:['ignore','pipe','pipe']});let log='';child.stdout.on('data',c=>log+=c);child.stderr.on('data',c=>log+=c);t.after(()=>child.kill('SIGTERM'));
 let health;
 for(let i=0;i<60;i++){health=await fetch('http://127.0.0.1:'+apiPort+'/health').then(r=>r.json()).catch(()=>null);if(health?.routeLabels===1)break;await delay(100);}
 assert.equal(health?.readOnly,true,log);assert.equal(health?.routeLabels,1,log);
 for(const tcp of [false,true]){const answer=await ask(dnsPort,tcp);assert.equal(answer.readUInt16BE(6),1);assert.deepEqual(answer.subarray(-4),Buffer.from([198,51,100,7]));}
 for(const method of ['POST','DELETE']){const r=await fetch('http://127.0.0.1:'+apiPort+'/v1/txt',{method,body:'{}'});assert.equal(r.status,405);assert.equal((await r.json()).error,'read_only');}
 expires=Date.now()+1800;const seen=hits;while(hits<=seen)await delay(100);offline=true;await delay(Math.max(0,expires-Date.now()+100));
 for(const tcp of [false,true]){const answer=await ask(dnsPort,tcp);assert.equal(answer.readUInt16BE(6),0,'expired answers cannot survive origin failure');assert.equal(answer.readUInt16BE(2)&15,2,'verification outage must allow resolver failover');assert.equal(answer.readUInt16BE(8),0,'no cacheable negative SOA');}
 for(const tcp of [false,true])assert.equal((await ask(dnsPort,tcp,'1234abcd.app.test')).readUInt16BE(2)&15,2,'a cold replica cannot assert absence of an unknown deployment');
 for(const tcp of [false,true])for(const name of ['abcd.app.test','1234abcd.app.test']){
  for(const type of [257,5,16]){
   const answer=await ask(dnsPort,tcp,name,type);
   assert.equal(answer.readUInt16BE(2)&15,0,'CAA/CNAME/TXT absence does not depend on an address route');
   assert.equal(answer.readUInt16BE(6),0);
   assert.equal(answer.readUInt16BE(8),1,'NODATA carries the zone SOA so CAA can ascend to the parent');
  }
  for(const type of [1,28,255])assert.equal((await ask(dnsPort,tcp,name,type)).readUInt16BE(2)&15,2,'address queries still fail closed without a verified route');
 }
 assert.doesNotMatch(log,/api\.enclave\.host|eligibility/);
});
test('read-only mode refuses implicit legacy route fallback and the box control namespace',async()=>{
 for(const config of [{ROUTE_MAP_URL:'',BOX_ZONE:''},{ROUTE_MAP_URL:'http://127.0.0.1:1/routes',BOX_ZONE:'box.test'}]){
  const child=spawn(process.execPath,[process.env.ENCLAVE_DNS_BIN||'relay/dns-relay.js'],{env:{...process.env,DNS_READ_ONLY:'1',...config},stdio:'pipe'});let log='';child.stderr.on('data',c=>log+=c);const [code]=await once(child,'close');assert.equal(code,1);assert.match(log,/requires explicit ROUTE_MAP_URL and no BOX_ZONE/);
 }
});

test('all replicas publish a complete explicit NS set over UDP and TCP',async t=>{
 const origin=http.createServer((_q,r)=>r.end(JSON.stringify({labels:{}})));origin.listen(0,'127.0.0.1');await once(origin,'listening');t.after(()=>origin.close());
 const dnsPort=await port(),apiPort=await port(),names=['ns-a.test','ns-b.test','ns-c.test','ns-d.test'];
 const child=spawn(process.execPath,[process.env.ENCLAVE_DNS_BIN||'relay/dns-relay.js'],{env:{...process.env,DNS_READ_ONLY:'1',DNS_BIND:'127.0.0.1',DNS_PORT:String(dnsPort),DNS_API_BIND:'127.0.0.1',DNS_API_PORT:String(apiPort),IP_ZONE:'ip.test',APP_ZONE:'app.test',NS_NAME:names[0],NS_NAMES:names.join(','),ROUTE_MAP_URL:'http://127.0.0.1:'+origin.address().port,BOX_ZONE:'',TCP_ZONE:''},stdio:'pipe'});let log='';child.stderr.on('data',c=>log+=c);t.after(()=>child.kill('SIGTERM'));
 let ready=false;for(let i=0;i<60;i++){ready=await fetch('http://127.0.0.1:'+apiPort+'/health').then(r=>r.ok).catch(()=>false);if(ready)break;await delay(100);}assert.equal(ready,true,log);
 for(const tcp of [false,true])for(const zone of ['app.test','ip.test']){
  const answer=await ask(dnsPort,tcp,zone,2);assert.equal(answer.readUInt16BE(6),4);
  for(const name of names){const wire=Buffer.concat([...name.split('.').map(s=>Buffer.concat([Buffer.from([s.length]),Buffer.from(s)])),Buffer.from([0])]);assert.ok(answer.includes(wire),'missing nameserver '+name);}
 }
 const soa=await ask(dnsPort,false,'app.test',6);assert.equal(soa.readUInt16BE(6),1);
});
test('malformed or oversized NS sets refuse startup',async()=>{
 for(const NS_NAMES of ['ns.test,,other.test','-bad.test','bad..test',Array.from({length:9},(_,i)=>'ns'+i+'.test').join(',')]){
  const child=spawn(process.execPath,[process.env.ENCLAVE_DNS_BIN||'relay/dns-relay.js'],{env:{...process.env,DNS_READ_ONLY:'1',ROUTE_MAP_URL:'http://127.0.0.1:1',IP_ZONE:'ip.test',APP_ZONE:'app.test',BOX_ZONE:'',NS_NAME:'ns.test',NS_NAMES},stdio:'pipe'});let log='';child.stderr.on('data',c=>log+=c);const [code]=await once(child,'close');assert.equal(code,1);assert.match(log,/NS_NAMES must name/);
 }
});
