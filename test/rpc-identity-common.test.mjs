import test from 'node:test';
import assert from 'node:assert/strict';
import {rpcEndpoint, rpcLabel, redactUrls} from '../network/rpc-identity.mjs';
import {rpcIdentity as leaseIdentity} from '../network/lease-reader.mjs';
import {rpcIdentity as custodyIdentity, checkRpcUrls} from '../custody/v2/quorum.mjs';
import {rpcIdentity as indexIdentity, peerList, resolveProviderBootstrap, resolveCheckerBootstrap} from '../network/service-index.mjs';
import {peersFor} from '../scripts/network/service-index.mjs';
import {rpcPeerHost, quorumReader} from '../windows/node/host-identity.mjs';
const client=url=>({transport:{url},getChainId(){},getBlockNumber(){},getBlock(){}});

test('all reader boundaries refuse two votes for one IPv4 host, including translated address spellings',()=>{
 const aliases=['https://[::ffff:8.8.8.8]','https://[::ffff:808:808]','https://[64:ff9b::808:808]','https://134744072','https://0x08080808'];
 for(const alias of aliases){
  for(const identify of [leaseIdentity,custodyIdentity,indexIdentity])assert.equal(identify(alias),identify('https://8.8.8.8'));
  assert.equal(rpcPeerHost(alias),rpcPeerHost('https://8.8.8.8'));
  assert.throws(()=>checkRpcUrls(['https://8.8.8.8',alias]),/distinct/);
  assert.throws(()=>peerList({clients:[client('https://8.8.8.8'),client(alias)]}),/distinct/);
  assert.throws(()=>peersFor(['https://8.8.8.8',alias],8453),/distinct/);
  assert.throws(()=>quorumReader({clients:[client('https://8.8.8.8'),client(alias)]}),/one host/);
 }
 assert.equal(peerList({clients:[client('https://8.8.8.8'),client('https://8.8.4.4')]}).length,2);
});

test('loopback aliases preserve local fixtures while Windows production never counts local ports as separate hosts',()=>{
 const a='http://127.0.0.1:8545',b='http://[::ffff:127.0.0.1]:8545';
 assert.equal(rpcEndpoint(a).identity,rpcEndpoint(b).identity);
 assert.throws(()=>peersFor([a,b],31337),/distinct/);
 assert.throws(()=>quorumReader({clients:[client(a),client('http://localhost:8546')]}),/one host/);
 assert.doesNotThrow(()=>quorumReader({clients:[client(a),client('http://localhost:8546')],localFixture:true}));
 assert.throws(()=>quorumReader({clients:[client(a),client(b)],localFixture:true}),/one host/);
 assert.throws(()=>rpcEndpoint('http://[64:ff9b::7f00:1]'),/HTTPS/);
});

test('malformed and credential-bearing transports are refused without echoing their secrets',()=>{
 for(const url of ['https://name:privatepass@rpc.example/privatekey?api=privatequery','http://rpc.example/privatekey','https://rpc.example/privatekey#privatefragment','not-a-url-privatekey','https://rpc..example/privatekey']){
  for(const action of [()=>leaseIdentity(url),()=>custodyIdentity(url),()=>peersFor([url,'https://other.example'],8453),()=>peerList({clients:[client(url),client('https://other.example')]}),()=>rpcPeerHost(url)]){
   assert.throws(action,e=>!e.message.includes('private'));
  }
  assert.equal(indexIdentity(url),null);
 }
 const raw='request failed https://name:privatepass@rpc.example/privatekey?api=privatequery, retry refused';
 assert.equal(redactUrls(raw),'request failed https://rpc.example, retry refused');
 assert.equal(rpcLabel('https://name:privatepass@rpc.example/privatekey?api=privatequery'),'https://rpc.example');
});


test('provider and checker configuration cannot bypass the shared vote identity rule',()=>{
 const zero='0x'+'0'.repeat(40),pins={deployments:'0x'+'1'.repeat(40),registry:'0x'+'2'.repeat(40),connectivity:zero,sessionVaultFactory:zero};
 for(const alias of ['https://[::ffff:8.8.8.8]','https://8.8.8.8:8443/path?api=privatekey']){
  const rpc=['https://8.8.8.8',alias];
  assert.throws(()=>resolveProviderBootstrap({bootstrap:'explicit',rpc}),/distinct hosts/);
  assert.throws(()=>resolveCheckerBootstrap({directories:['https://directory.example'],pins,rpc}),/distinct origins/);
 }
 assert.throws(()=>resolveProviderBootstrap({bootstrap:'explicit',rpc:['https://u:privatepass@rpc.example/privatekey','https://other.example']}),e=>!e.message.includes('private'));
});
