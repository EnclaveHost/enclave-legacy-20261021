import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import net from 'node:net';
import {privateKeyToAccount} from 'viem/accounts';
import {createProviderBootstrap,providerRegistryReader,createNetworkFetch} from '../network/provider-bootstrap.mjs';
import {LeaseReader} from '../network/lease-reader.mjs';
import {createNetworkHost} from '../network/enclave-network-host.mjs';
import {signProviderRecord,signQualification,providerIdFor,CHECKS} from '../network/provider-directory.mjs';

const address=n=>'0x'+n.repeat(40),book=address('1'),registry=address('2');
const pins={deployments:address('3'),registry,connectivity:address('0'),sessionVaultFactory:address('0')};
const operator=privateKeyToAccount('0x'+'11'.repeat(32)),checker=privateKeyToAccount('0x'+'22'.repeat(32));
const runner='0x'+'ab'.repeat(32);
const hostConfig={directories:['https://refusing.example','https://records.example'],apps:'all',checkers:[checker.address],wgBinary:'/bin/true',nodeBinary:process.execPath,workerModule:'/bin/true'};
class CaptureReader{constructor(config){this.config=config;}}

test('bootstrap is explicit for guarded hosts and never silently enables direct traffic',async()=>{
 const make=network=>createProviderBootstrap({network,chain:{authorityPins:pins},Reader:CaptureReader});
 assert.equal(make({control:true}),null);
 assert.equal(make({control:true,controlRequired:true}),null);
 assert.equal(make({}).reader.config.proxy,undefined);
 assert.equal(make({control:true,bootstrap:{mode:'direct'}}).reader.config.authorityPins,pins);
 assert.throws(()=>make({control:true,controlRequired:true,bootstrap:{mode:'direct'}}),/conflicts/);
 assert.throws(()=>make({controlRequired:true}),/control enabled/);
 for(const bootstrap of [null,{},[],{mode:'magic'},{mode:'direct',proxies:[]},{mode:'proxy',proxies:[]},
  {mode:'proxy',proxies:['localhost:9']},{mode:'proxy',proxies:['127.0.0.1:9/path']},
  {mode:'proxy',proxies:['127.0.0.1:0']},{mode:'proxy',proxies:['127.0.0.1:9?bad']},{mode:'proxy',proxies:['127.0.0.1:9#bad']},
  {mode:'proxy',proxies:['user:pass@8.8.8.8:9']}])assert.throws(()=>make({control:true,bootstrap}));
 const config={mode:'proxy',proxies:['127.0.0.1:9000','[::1]:9001']};
 const privateBootstrap=make({control:true,controlRequired:true,bootstrap:config});
 config.proxies[0]='127.0.0.1:9999';
 assert.deepEqual(await privateBootstrap.reader.config.proxy(),['127.0.0.1:9000','[::1]:9001']);
});

test('real guarded bootstrap cannot escape a refusing SOCKS service through direct fetch',async t=>{
 const sockets=new Set();const server=net.createServer(socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.on('data',()=>socket.end(Buffer.from([5,255])));});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(()=>{for(const socket of sockets)socket.destroy();server.close();});
 let direct=0;
 const bootstrap=createProviderBootstrap({chain:{},network:{control:true,controlRequired:true,bootstrap:{mode:'proxy',proxies:['127.0.0.1:'+server.address().port]}},
  Reader:CaptureReader,fetch:async()=>{direct++;assert.fail('direct fallback');}});
 const fetch=createNetworkFetch({bootstrap,control:()=>null,controlRequired:true,fetch:async()=>{direct++;assert.fail('direct fallback');}});
 await assert.rejects(fetch('http://8.8.8.8/v1/network/providers'),/SOCKS authentication refused/);
 assert.equal(direct,0);
});

test('strict discovery uses only the selected private bootstrap during startup or circuit loss',async()=>{
 let live=false,direct=0,privateCalls=0,guardCalls=0;
 const transport={proxies:async()=>{if(!live)throw Error('circuits down');return ['127.0.0.1:9000'];}};
 const bootstrap={fetch:async()=>{privateCalls++;return Response.json({source:'bootstrap'});}};
 const fetch=createNetworkFetch({bootstrap,control:()=>transport,controlRequired:true,
  fetch:async()=>{direct++;throw Error('direct forbidden');},guard:()=>async()=>{guardCalls++;return Response.json({source:'control'});}});
 assert.equal((await (await fetch('https://records.example')).json()).source,'bootstrap');
 live=true;assert.equal((await (await fetch('https://records.example')).json()).source,'control');
 live=false;assert.equal((await (await fetch('https://records.example')).json()).source,'bootstrap');
 assert.deepEqual([direct,privateCalls,guardCalls],[0,2,1]);
 const closed=createNetworkFetch({control:()=>transport,controlRequired:true,fetch:()=>{direct++;}});
 await assert.rejects(closed('https://records.example'),/circuits down/);assert.equal(direct,0);
 bootstrap.fetch=async()=>{throw Error('private bootstrap down');};
 await assert.rejects(fetch('https://records.example'),/private bootstrap down/);assert.equal(direct,0);
});

test('fresh directory-only host admits a signed registered provider before control startup, then follows live registry changes',async t=>{
 const directory=await mkdtemp(tmpdir()+'/bootstrap-provider-');t.after(()=>rm(directory,{recursive:true,force:true}));
 let now=Date.now(),reads=0,live=false;
 const peer=op=>({getChainId:async()=>8453,getBlockNumber:async()=>100n,
  getBlock:async()=>({hash:'0x'+'cd'.repeat(32),timestamp:BigInt(Math.floor(now/1000))}),
  readContract:async q=>{reads++;assert.equal(q.address,registry,'pinned registry only');assert.equal(q.blockNumber,98n);return {active:true,operator:op};}});
 const chain={addressBook:book,authorityPins:pins,clients:[peer(operator.address),peer(operator.address),peer(checker.address)],now:()=>now};
 const bootstrap=createProviderBootstrap({chain,network:{control:true,bootstrap:{mode:'direct'}}});
 const liveReader=new LeaseReader({...chain,clients:[peer(checker.address),peer(checker.address)]});
 const providerReader=providerRegistryReader({bootstrap,liveReader,control:()=>({proxies:async()=>{if(!live)throw Error('not started');return ['127.0.0.1:9'];}}),controlEnabled:true});
 const r={version:1,providerId:providerIdFor(operator.address,'8.8.4.4'),operator:operator.address.toLowerCase(),address:'8.8.4.4',
  wgExitKey:Buffer.alloc(32,1).toString('base64'),wgGuardKey:Buffer.alloc(32,2).toString('base64'),ports:{exit:51820,guard:51821,control:51822},
  roles:['guard','ingress','egress'],pricePerGiB6:0,region:'independent-test',kind:'community',hostId:runner,issuedAt:now,expiresAt:now+1800000};
 const record=await signProviderRecord(operator,r),qualification=await signQualification(checker,{version:1,providerId:r.providerId,
  operator:r.operator,address:r.address,wgExitKey:r.wgExitKey,wgGuardKey:r.wgGuardKey,roles:r.roles,
  checks:Object.fromEntries(CHECKS.map(k=>[k,true])),issuedAt:now,expiresAt:now+600000});
 const calls=[];const fetch=async url=>{calls.push(String(url));if(new URL(url).hostname==='refusing.example')throw Error('operator refusal');
  assert.equal(new URL(url).hostname,'records.example');return Response.json({providers:[{record,qualifications:[qualification]},
   {record:{...record,record:{...r,address:'9.9.9.9'}},qualifications:[qualification]}]});};
 const network=await createNetworkHost({config:hostConfig,directory,authorityPins:pins,leaseReader:liveReader,providerReader,fetch,now:()=>now});
 const providers=await network.providers();assert.equal(providers.length,1);assert.equal(providers[0].providerId,r.providerId);assert.ok(reads>=4);
 assert.ok(calls.every(url=>!url.includes('enclave.host')));
 live=true;now+=31000;
 assert.deepEqual(await network.providers(),[],'a changed live registry operator cannot retain the provider via bootstrap');
 const absent=providerRegistryReader({bootstrap:null,liveReader,control:()=>null,controlEnabled:true});
 await assert.rejects(absent.registryEntries(registry,[runner]),/explicit enclaveNetwork.bootstrap/);
});

test('missing discovery origins and malformed explicit relays are refused',async()=>{
 for(const config of [{...hostConfig,directories:undefined},{...hostConfig,relay:'http://127.0.0.1.evil.example'},
  {...hostConfig,relay:'https://user:pass@records.example'},{...hostConfig,relay:'https://records.example/path'}])
  await assert.rejects(createNetworkHost({config,directory:'/unused'}));
});
