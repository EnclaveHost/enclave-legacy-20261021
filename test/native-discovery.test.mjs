import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash,X509Certificate} from 'node:crypto';
import {createDiscovery,routeFor} from '../relay/native-discovery.mjs';

test('native control recovery names use the four provider addresses',()=>{
 for(const service of ['api','mcp']){
  const r=routeFor(service+'.enclavehost.eth',null);
  assert.equal(r.kind,'control');assert.equal(r.port,443);
  assert.deepEqual(r.addresses,['134.199.235.187','134.209.248.172','165.245.191.129','146.190.246.39']);
 }
 for(const name of ['api.enclavehost.eth.attacker.test','API.enclavehost.eth','other.enclavehost.eth','api.enclave.host',null])assert.equal(routeFor(name,null),null);
});

test('native application discovery never returns an expired or absent route',()=>{
 const now=Date.now(),name='1234abcd.app.enclavehost.eth';
 const map={labels:{'1234abcd':{addresses:['8.8.4.4'],expiresAt:now+1000}}};
 assert.deepEqual(routeFor(name,map,now).addresses,['8.8.4.4']);
 assert.equal(routeFor(name,map,now+1000),null);assert.equal(routeFor(name,{},now),null);
 assert.equal(routeFor('nested.'+name,map,now),null);
});

test('native discovery publishes only public CA and routing metadata and refuses missing authority',async t=>{
 const caPem=await readFile(new URL('./fixtures/amd/Genoa-cert_chain.pem',import.meta.url),'utf8');
 let reads=0;const server=createDiscovery({caPem,getRoutes:async()=>{reads++;throw Error('offline');}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>{server.closeAllConnections();server.close();});
 const origin='http://127.0.0.1:'+server.address().port;
 const status=await(await fetch(origin+'/native/status')).json();assert.equal(status.caSha256,createHash('sha256').update(new X509Certificate(caPem).raw).digest('hex'));
 assert.equal((await fetch(origin+'/native/resolve?name=api.enclavehost.eth')).status,200);assert.equal(reads,0);
 assert.equal((await fetch(origin+'/native/resolve?name=1234abcd.app.enclavehost.eth')).status,503);assert.equal(reads,1);
 assert.equal((await fetch(origin+'/native/private.key')).status,404);
 assert.equal((await fetch(origin+'/native/status',{method:'POST'})).status,405);
});
