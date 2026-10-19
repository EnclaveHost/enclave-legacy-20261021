import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import {execFileSync} from 'node:child_process';
import {generateKeyPairSync,X509Certificate,createHash} from 'node:crypto';
import {privateKeyToAccount} from 'viem/accounts';
import {NativeClient} from '../network/native-client.mjs';
import {signProviderRecord,signQualification,providerIdFor,CHECKS} from '../network/provider-directory.mjs';
import {defaultNetworkPolicy} from '../network/network-policy.mjs';
import {signDelegation,signRoute,recordHash} from '../network/route-record.mjs';
import {preparePackage} from '../sdk/bootstrap/package.mjs';
import {runtimeId} from '../isolation/contract/runtime.mjs';

// Real signed directory records and TLS. Hardware verdict and chain reads are
// test doubles here; guest-probe-bootstrap covers the proof transport, and the
// live proof uses real SNP hardware and independent RPC reads.
const account=n=>privateKeyToAccount('0x'+n.repeat(64));
const owner=account('1'),operator=account('2'),checker=account('3');
const id='0x'+'ab'.repeat(32),runner='0x'+'cd'.repeat(32),address='8.8.4.4';
const runtime={name:'wasmtime',version:'test',execution:'jit',hostIsa:'x86_64',targetIsa:'x86_64',cpuFeatures:'baseline',wx:'enforced',cache:'none'};
async function rig(t,scenario='valid',handler=null,clientOptions={}){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'native-client-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  execFileSync('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=not-a-trusted-ca','-days','1','-keyout',dir+'/key','-out',dir+'/cert'],{stdio:'ignore'});
  const cert=fs.readFileSync(dir+'/cert'),key=fs.readFileSync(dir+'/key'),spkiSha256=createHash('sha256').update(new X509Certificate(cert).publicKey.export({format:'der',type:'spki'})).digest('hex');
  let now=Date.now(),reads=0,probes=0,requests=0,appBytes=0;const policy=defaultNetworkPolicy(id);
  const expected={appRef:'test-app',configCid:'test-config',appSha256:'ef'.repeat(32),runtimeId:runtimeId(runtime).toString('hex')};
  const pins={deployments:'0x'+'05'.repeat(20),registry:'0x'+'06'.repeat(20),connectivity:'0x'+'00'.repeat(20),sessionVaultFactory:'0x'+'00'.repeat(20)};
  const lease={id,owner:owner.address,runner,chainId:8453,deployments:pins.deployments,runnerOperator:operator.address,active:true,isPublic:true,leaseUntil:now+600000,validUntil:now+90000,appRef:expected.appRef,configCid:expected.configCid,blockNumber:'1234'};
  const startup=scenario.startsWith('startup'),pkg=preparePackage({version:1,chainId:8453,ledger:pins.deployments,deployment:id,owner:owner.address,appRef:expected.appRef,appId:expected.appSha256,runtimeId:expected.runtimeId,configText:'{}',secretsMode:'public'});
  if(startup)lease.configCid=JSON.stringify({guestBootstrap:pkg.intent});
  const record={version:1,providerId:providerIdFor(operator.address,address),operator:operator.address.toLowerCase(),address,
    wgExitKey:Buffer.alloc(32,1).toString('base64'),wgGuardKey:Buffer.alloc(32,2).toString('base64'),ports:{exit:51820,guard:51821,control:51822},
    roles:['guard','ingress','egress'],pricePerGiB6:0,region:'test',kind:'community',hostId:runner,issuedAt:now,expiresAt:now+1800000};
  const pr=await signProviderRecord(operator,record),q={version:1,providerId:record.providerId,operator:record.operator,address,wgExitKey:record.wgExitKey,wgGuardKey:record.wgGuardKey,roles:record.roles,
    checks:Object.fromEntries(CHECKS.map(k=>[k,true])),issuedAt:now,expiresAt:now+600000};
  const qualification=await signQualification(checker,q),keys=generateKeyPairSync('ed25519');
  const delegation={version:2,deploymentId:id,runner,chainId:8453,deployments:pins.deployments,policyHash:recordHash(policy),epoch:now,notBefore:now,expiresAt:now+3600000,
    publicKey:keys.publicKey.export({format:'der',type:'spki'}).toString('base64'),ipns:'k51'+'a'.repeat(50)};
  const authorization=await signDelegation(operator,delegation,now);
  const publication=(sequence,withdraw=false)=>({version:2,policy,bundle:{authorization,...signRoute(keys.privateKey,{version:2,deploymentId:id,delegationHash:recordHash(delegation),sequence,issuedAt:now,expiresAt:now+60000,
    routes:withdraw?[]:[{circuit:'f'.repeat(32),address,port:443,transport:'enclave-network'}]})}});
  let snapshot={version:1,providers:[{record:pr,qualifications:[qualification]}],policies:[],publications:[publication(1)]};
  const profile={version:1,deploymentId:id,hostname:'never-resolve.invalid',stateDir:dir+'/state',chainId:8453,expected,linux:{},authorityPins:pins,checkers:[checker.address],directories:['http://192.0.2.1:8188','http://192.0.2.2:8188']};
  if(startup){delete profile.expected;profile.linux={runtime};profile.startup={gateways:['http://198.51.100.1:8189/ipfs','http://198.51.100.2:8189/ipfs']};}
  const reader={refresh:async()=>{reads++;if(reads>1&&scenario==='lease changed')lease.configCid='other';if(reads>1&&scenario==='lease revoked')lease.active=false;
    if(reads>1&&scenario==='startup owner changed')lease.owner=operator.address;
    if(reads>1&&scenario==='startup commitment changed')lease.configCid=JSON.stringify({guestBootstrap:{version:1,sha256:'ab'.repeat(32)}});
  },
    get:()=>structuredClone(lease),registryEntries:async()=>[{active:true,operator:operator.address}]};
  const fetch=async (url,options)=>{
    if(url.startsWith('http://198.51.100.')){
      assert.equal(options.credentials,'omit');assert.equal(options.redirect,'error');
      if(url.startsWith('http://198.51.100.1:'))throw Error('storage refused');
      return new Response(scenario==='startup forged bytes'?'forged':pkg.bytes);
    }
    assert.ok(url.endsWith('/v1/network/records'));assert.equal(new URL(url).protocol,'http:');
    if(url.startsWith('http://192.0.2.1:')){
      if(scenario==='malformed replica')return Response.json({version:1,providers:[null,{record:{},qualifications:{}}],policies:[],publications:[]});
      throw Error('directory refused');
    }
    if(scenario==='withdrawal'&&reads>1)snapshot={...snapshot,publications:[publication(2,true)]};
    return Response.json(snapshot);
  };
  const probe=async options=>{
    probes++;assert.equal(options.address,address);assert.equal(options.attestationBootstrap,true);assert.equal(options.hostname,profile.hostname);
    if(startup){assert.equal(options.expected.appSha256,pkg.manifest.appId);assert.equal(options.expected.configCid,lease.configCid);assert.equal(options.expected.runtimeId,runtimeId(runtime).toString('hex'));}
    if(scenario==='bad proof')throw Error('hardware refused');
    return {verified:true,ready:true,deploymentId:id,appSha256:expected.appSha256,runtimeId:expected.runtimeId,spkiSha256:scenario==='wrong TLS key'?'00'.repeat(32):spkiSha256};
  };
  const server=https.createServer({key,cert},(req,res)=>{
    requests++;if(handler)return handler(req,res);assert.equal(req.socket.servername,profile.hostname);assert.equal(req.headers.host,profile.hostname);assert.equal(req.headers.authorization,'Bearer private-test-only');
    if(scenario==='redirect'){res.writeHead(302,{location:'https://must-not-follow.invalid'});res.end();}
    else res.end('pong');
  });
  // Decrypted bytes the guest stand-in received on any connection: a refused send must leave this at zero.
  server.on('secureConnection',socket=>socket.on('data',b=>{appBytes+=b.length;}));
  await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>{server.closeAllConnections();return new Promise(r=>server.close(r));});
  const realRequest=https.request;
  t.mock.method(https,'request',(options,callback)=>{
    assert.equal(options.host,address,'production transport must select a signed literal IP');assert.equal(options.port,443);
    return realRequest({...options,host:'127.0.0.1',port:server.address().port},callback);
  });
  const client=new NativeClient(profile,{reader,fetch,probe,now:()=>now,...clientOptions});
  const request=()=>client.request({path:'/ping',headers:{Authorization:'Bearer private-test-only'}});
  return {client,request,lease,snapshot,profile,reader,fetch,probe,publication,counts:()=>({requests,probes,appBytes}),advance:n=>now+=n};
}

for(const scenario of ['valid','malformed replica','bad proof','wrong TLS key','lease changed','lease revoked','withdrawal','redirect','startup valid','startup forged bytes','startup owner changed','startup commitment changed'])test('native client: '+scenario,async t=>{
  const r=await rig(t,scenario);
  if(['valid','malformed replica','redirect','startup valid'].includes(scenario)){
    const response=await r.request();assert.equal(response.status,scenario==='redirect'?302:200);assert.equal(r.counts().requests,1);
    if(scenario!=='redirect')assert.equal(response.body.toString(),'pong');
    if(scenario==='startup valid'){assert.equal(response.expectation.source,'owner-committed-startup');assert.equal(response.expectation.owner,owner.address);}
  }else{
    await assert.rejects(r.request(),/hardware refused|TLS key changed|matching the pinned|verified route|changed during|committed startup package|startup owner mismatch/);
    assert.equal(r.counts().requests,0,'no application bytes or credentials reach a refused or unverified destination');
  }
});
test('expired lease is refused before attestation; corrupt replay state is not reset',async t=>{
  const r=await rig(t);r.lease.validUntil=0;await assert.rejects(r.request(),/current lease/);assert.equal(r.counts().probes,0);
  r.lease.validUntil=Date.now()+90000;await r.client.resolve();
  fs.writeFileSync(r.client.directory.state.filename('public-records'),'{broken');
  await assert.rejects(r.request(),SyntaxError);assert.equal(r.counts().requests,0);
});
test('route withdrawal survives a client restart and stale directory replay',async t=>{
  const r=await rig(t);await r.client.resolve();await r.client.directory.accept('route',r.publication(2,true));
  const restarted=new NativeClient(r.profile,{reader:r.reader,fetch:r.fetch,probe:r.probe});
  await assert.rejects(restarted.request(),/no current verified route/);assert.equal(r.counts().probes,0);assert.equal(r.counts().requests,0);
});

// ---- writes and streaming (real TLS server; hardware verdict and chain reads remain test doubles) ----
const readBody=req=>new Promise((resolve,reject)=>{const c=[];req.on('data',b=>c.push(b));req.once('end',()=>resolve(Buffer.concat(c)));req.once('error',reject);});
const AUTH={Authorization:'Bearer private-test-only'};

test('native POST sends one bounded body snapshot after the proof and returns the guest answer',async t=>{
  let seen;
  const r=await rig(t,'startup valid',async(req,res)=>{seen={method:req.method,length:req.headers['content-length'],type:req.headers['content-type'],auth:req.headers.authorization,body:await readBody(req)};
    res.writeHead(201,{'content-type':'application/json'});res.end(JSON.stringify({stored:seen.body.length}));});
  const upload=Buffer.from(JSON.stringify({messages:[{role:'user',content:'hello'}]}));
  const pending=r.client.request({method:'POST',path:'/v1/chat',headers:{...AUTH,'Content-Type':'application/json'},body:upload});
  upload.fill(0x78);   // the caller's later mutation must not change what is sent
  const response=await pending;
  assert.equal(response.status,201);assert.deepEqual(JSON.parse(response.body),{stored:upload.length});
  assert.equal(seen.method,'POST');assert.equal(seen.length,String(upload.length));assert.equal(seen.type,'application/json');assert.equal(seen.auth,AUTH.Authorization);
  assert.equal(JSON.parse(seen.body).messages[0].content,'hello');assert(r.counts().appBytes>upload.length,'the TLS-layer counter sees an accepted send');assert.equal(response.expectation.source,'owner-committed-startup');
  for(const method of ['PUT','PATCH','DELETE']){
    const x=await r.client.request({method,path:'/v1/files/a',headers:AUTH,body:new Uint8Array([1,2,3])});assert.equal(x.status,201);assert.equal(seen.method,method);assert.deepEqual([...seen.body],[1,2,3]);
  }
});

test('a streamed response is delivered incrementally, before the guest ends it',async t=>{
  let firstSeen;const delivered=new Promise(r=>firstSeen=r);
  const r=await rig(t,'valid',async(req,res)=>{
    res.writeHead(200,{'content-type':'text/event-stream'});res.write('data: one\n\n');
    await delivered;   // the guest continues only once the client has consumed the first event
    res.write('data: two\n\n');res.end();
  });
  const s=await r.client.stream({method:'POST',path:'/v1/chat/stream',headers:AUTH,body:'{"stream":true}'});
  assert.equal(s.status,200);assert.equal(s.headers['content-type'],'text/event-stream');
  const events=[];
  for await(const chunk of s.body){events.push(chunk.toString());if(events.length===1){assert.equal(chunk.toString(),'data: one\n\n');firstSeen();}}
  assert.equal(events.join(''),'data: one\n\ndata: two\n\n');
  assert.deepEqual(await s.closed,{bytes:22,error:null});assert.equal(r.client.open,0);
});

test('cancellation, response limits and idle limits end the stream and close the guest connection',async t=>{
  const serverClosed=[];
  const r=await rig(t,'valid',(req,res)=>{res.writeHead(200);res.write('x'.repeat(1024));const iv=setInterval(()=>res.write('y'),20);
    res.on('close',()=>{clearInterval(iv);serverClosed.push(req.url);});if(req.url==='/idle')clearInterval(iv);});
  const a=await r.client.stream({path:'/cancel',headers:AUTH});
  for await(const _ of a.body){a.cancel('user stopped');break;}
  assert.match((await a.closed).error,/user stopped|cancel|premature/i);
  const b=await r.client.stream({path:'/limit',headers:AUTH,maxBytes:2048});
  await assert.rejects((async()=>{for await(const _ of b.body);})(),/native response too large/);
  const c=await r.client.stream({path:'/idle',headers:AUTH,idleTimeoutMs:1000});
  await assert.rejects((async()=>{for await(const _ of c.body);})(),/idle timeout/);
  const controller=new AbortController(),d=await r.client.stream({path:'/signal',headers:AUTH,signal:controller.signal});
  controller.abort();await assert.rejects((async()=>{for await(const _ of d.body);})(),/cancel/);
  for(let i=0;i<50&&serverClosed.length<4;i++)await new Promise(x=>setTimeout(x,20));
  assert.deepEqual(serverClosed.sort(),['/cancel','/idle','/limit','/signal']);assert.equal(r.client.open,0);
  // a buffered request is bounded too, and cancellation before sending sends nothing
  await assert.rejects(r.client.request({path:'/limit',headers:AUTH,maxBytes:512}),/too large/);
  const before=r.counts().requests,early=new AbortController();early.abort();
  await assert.rejects(r.client.request({method:'POST',path:'/x',headers:AUTH,body:'secret',signal:early.signal}),/cancelled before sending/);
  assert.equal(r.counts().requests,before);
});

test('a wrong guest key or changed owner refuses a write before the guest receives any application byte',async t=>{
  for(const scenario of ['wrong TLS key','startup owner changed','lease changed','withdrawal'])await t.test(scenario,async t=>{
    const r=await rig(t,scenario,()=>assert.fail('application request reached the guest'));
    await assert.rejects(r.client.request({method:'POST',path:'/v1/upload',headers:AUTH,body:Buffer.alloc(4096,7)}),/TLS key changed|matching the pinned|verified route|changed during|startup owner mismatch/);
    await r.client.stream({method:'POST',path:'/v1/chat/stream',headers:AUTH,body:'x'}).then(()=>assert.fail('stream opened'),()=>{});
    assert.equal(r.counts().requests,0);assert.equal(r.counts().appBytes,0,scenario);assert.equal(r.client.open,0);
  });
});

test('a write is never redirected or retried after a partial transport failure',async t=>{
  const r=await rig(t,'valid',async(req,res)=>{
    await readBody(req);
    if(req.url==='/redirect'){res.writeHead(307,{location:'https://must-not-follow.invalid/again'});return res.end();}
    if(req.url==='/reset'){res.writeHead(200);res.write('partial');setTimeout(()=>req.socket.destroy(),20);return;}
    req.socket.destroy();   // the guest received the whole request, then the connection failed
  });
  const redirected=await r.client.request({method:'POST',path:'/redirect',headers:AUTH,body:'a'});
  assert.equal(redirected.status,307);assert.equal(redirected.headers.location,'https://must-not-follow.invalid/again');assert.equal(r.counts().requests,1);
  await assert.rejects(r.client.request({method:'POST',path:'/drop',headers:AUTH,body:'b'}));
  assert.equal(r.counts().requests,2,'no second application attempt');
  const s=await r.client.stream({method:'POST',path:'/reset',headers:AUTH,body:'c'});
  await assert.rejects((async()=>{for await(const _ of s.body);})());
  await new Promise(x=>setTimeout(x,100));
  assert.equal(r.counts().requests,3);assert.equal(r.counts().probes,3,'each request attested once; none re-attested to resend');
});

test('an open stream ends when the chain no longer shows the same current deployment',async t=>{
  const r=await rig(t,'valid',(req,res)=>{res.writeHead(200);res.write('data: open\n\n');});
  const s=await r.client.stream({path:'/events',headers:AUTH,recheckMs:1000});
  const it=s.body[Symbol.asyncIterator]();assert.equal((await it.next()).value.toString(),'data: open\n\n');
  r.lease.owner=account('9').address;   // ownership transferred while the stream is open
  await assert.rejects(it.next(),/authorization ended/);assert.match((await s.closed).error,/not confirmed current/);
});

test('per-client concurrency and request validation fail before discovery or proof',async t=>{
  const r=await rig(t,'valid',(req,res)=>{res.writeHead(200);if(req.method==='HEAD')res.end();else res.write('open');},{maxConcurrent:2});
  const a=await r.client.stream({path:'/a',headers:AUTH}),b=await r.client.stream({path:'/b',headers:AUTH});
  await assert.rejects(r.client.stream({path:'/c',headers:AUTH}),/too many open/);
  a.cancel();await a.closed;const c=await r.client.stream({path:'/c',headers:AUTH});c.cancel();b.cancel();await Promise.all([b.closed,c.closed]);
  const probes=r.counts().probes;
  for(const bad of [{method:'CONNECT'},{method:'TRACE'},{method:'GET',body:'x'},{method:'POST',body:'x'.repeat(11),maxRequestBytes:10},
    {headers:{'Transfer-Encoding':'chunked'}},{headers:{Expect:'100-continue'}},{headers:{'X-A':'1\r\nX-Injected: 1'}},{headers:{'x-a':'1','X-A':'2'}},
    {method:'POST',body:{not:'bytes'}},{signal:{aborted:false}},{path:'//elsewhere'},{timeoutMs:10},{unknown:true}])
    await assert.rejects(r.client.request({path:'/x',...bad}),/native|GET and HEAD|signal/);
  assert.equal(r.counts().probes,probes);
  const head=await r.client.request({method:'HEAD',path:'/h',headers:AUTH});assert.equal(head.status,200);assert.deepEqual(head.body,Buffer.alloc(0));
});
