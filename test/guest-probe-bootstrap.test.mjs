import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {X509Certificate,createHash} from 'node:crypto';
import {probeGuest} from '../network/guest-probe.mjs';
import {runtimeId} from '../isolation/contract/runtime.mjs';

const runtime={name:'wasmtime',version:'test',execution:'jit',hostIsa:'x86_64',targetIsa:'x86_64',cpuFeatures:'baseline',wx:'enforced',cache:'none'};
const deploymentId='0x'+'ab'.repeat(32),expected={appSha256:'cd'.repeat(32),runtimeId:runtimeId(runtime).toString('hex')};
for(const scenario of ['valid','bad proof','wrong nonce','wrong app','wrong key binding','key changes before readiness'])test('hardware bootstrap: '+scenario,async t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'native-proof-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const pair=n=>{
    execFileSync('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=untrusted.invalid','-days','1','-keyout',dir+'/key'+n,'-out',dir+'/cert'+n],{stdio:'ignore'});
    return {key:fs.readFileSync(dir+'/key'+n),cert:fs.readFileSync(dir+'/cert'+n)};
  };
  const first=pair(1),second=pair(2),spki=new X509Certificate(first.cert).publicKey.export({format:'der',type:'spki'}),requests=[];
  const server=https.createServer(first,(req,res)=>{
    requests.push(req.url);assert.equal(req.socket.servername,'never-resolve.invalid');
    assert.equal(req.headers.authorization,undefined);assert.equal(req.headers.cookie,undefined);
    if(req.url==='/.well-known/enclave-ready'){res.end('ready');return;}
    const doc={format:'sev-snp-guest-domain-v1',nonce:new URL(req.url,'https://local').searchParams.get('nonce'),transportKey:spki.toString('base64'),appSha256:expected.appSha256};
    if(scenario==='wrong nonce')doc.nonce='00'.repeat(32);
    if(scenario==='wrong app')doc.appSha256='00'.repeat(32);
    if(scenario==='wrong key binding')doc.transportKey=Buffer.alloc(32).toString('base64');
    res.end(JSON.stringify(doc));
    if(scenario==='key changes before readiness')server.setSecureContext(second);
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
  let verified=0;
  const options={deploymentId,expected,linux:{runtime},hostname:'never-resolve.invalid',address:'127.0.0.1',port:server.address().port,direct:true,attestationBootstrap:true,
    verifySnp:async(doc,key,nonce,want)=>{
      verified++;assert.deepEqual(key,spki);assert.equal(doc.nonce,nonce.toString('hex'));assert.equal(want.mode,'trusted');assert.equal(want.hostData,deploymentId);
      return {gateOpen:scenario!=='bad proof',verdict:scenario==='bad proof'?'reject':'attested'};
    }};
  if(scenario==='valid'){
    const proof=await probeGuest(options);assert.equal(proof.ready,true);assert.equal(proof.spkiSha256,createHash('sha256').update(spki).digest('hex'));assert.equal(verified,1);assert.equal(requests.length,2);
  }else{await assert.rejects(probeGuest(options),/binding mismatch|proof refused|TLS key changed/);assert.equal(requests.length,1,'no readiness or application request after failed proof or changed TLS key');}
  await assert.rejects(probeGuest({...options,attestationBootstrap:false}),/require an attested key/);
  await assert.rejects(probeGuest({...options,address:'untrusted.invalid'}),/literal direct route/);
});
