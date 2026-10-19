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
async function rig(t,scenario='valid'){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'native-client-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  execFileSync('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=not-a-trusted-ca','-days','1','-keyout',dir+'/key','-out',dir+'/cert'],{stdio:'ignore'});
  const cert=fs.readFileSync(dir+'/cert'),key=fs.readFileSync(dir+'/key'),spkiSha256=createHash('sha256').update(new X509Certificate(cert).publicKey.export({format:'der',type:'spki'})).digest('hex');
  let now=Date.now(),reads=0,probes=0,requests=0;const policy=defaultNetworkPolicy(id);
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
    requests++;assert.equal(req.socket.servername,profile.hostname);assert.equal(req.headers.host,profile.hostname);assert.equal(req.headers.authorization,'Bearer private-test-only');
    if(scenario==='redirect'){res.writeHead(302,{location:'https://must-not-follow.invalid'});res.end();}
    else res.end('pong');
  });await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
  const realRequest=https.request;
  t.mock.method(https,'request',(options,callback)=>{
    assert.equal(options.host,address,'production transport must select a signed literal IP');assert.equal(options.port,443);
    return realRequest({...options,host:'127.0.0.1',port:server.address().port},callback);
  });
  const client=new NativeClient(profile,{reader,fetch,probe,now:()=>now});
  const request=()=>client.request({path:'/ping',headers:{Authorization:'Bearer private-test-only'}});
  return {client,request,lease,snapshot,profile,reader,fetch,probe,publication,counts:()=>({requests,probes}),advance:n=>now+=n};
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
