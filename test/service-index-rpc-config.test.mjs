import test from 'node:test';
import assert from 'node:assert/strict';
import {peersFor} from '../scripts/network/service-index.mjs';
test('service-index CLI cannot turn one public RPC host into multiple votes',()=>{
 for(const urls of [
  ['https://a.example','https://a.example'],
  ['https://a.example/key1','https://a.example/key2'],
  ['https://a.example/?key=secret1','https://a.example/?key=secret2'],
  ['https://a.example:443','https://a.example:8443'],
  ['https://a.example.','https://a.example'],
 ]) assert.throws(()=>peersFor(urls,8453),/distinct/);
 const peers=peersFor(['https://a.example/key1','https://b.example/key2','https://c.example'],8453);
 assert.equal(peers.length,3);assert.deepEqual(peers.map(p=>p.label),['https://a.example','https://b.example','https://c.example']);
});
test('loopback test peers require different ports and public transports are validated without secret echo',()=>{
 assert.equal(peersFor(['http://127.0.0.1:8545','http://127.0.0.1:8546'],8453).length,2);
 assert.throws(()=>peersFor(['http://127.0.0.1:8545','http://localhost:8545'],8453),/distinct/);
 for(const bad of ['http://a.example','ftp://a.example','https://u:secret@a.example','https://a.example/#secret','not-a-url']){
  assert.throws(()=>peersFor([bad,'https://b.example'],8453),e=>!e.message.includes('secret')&&/RPC/.test(e.message));
 }
 assert.throws(()=>peersFor(['https://a.example'],8453),/two to sixteen/);
});
