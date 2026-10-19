import https from 'node:https';
import {isIP} from 'node:net';
import {randomBytes,createHash} from 'node:crypto';
import {SocksHttpsAgent,DirectHttpsAgent} from './socks-connect.mjs';
import {LocalAppHttpsAgent} from './local-app-transport.mjs';
import {judge} from '../isolation/m2/judge.mjs';
import {runtimeId} from '../isolation/contract/runtime.mjs';
import {verifyShieldAppPolicy} from '../relay/shield-app-policy.mjs';
import {verifyPvmAppEvidence} from '../relay/pvm-app-attest.mjs';

const observedPeerKeys=new WeakMap();
function get(hostname,address,path,agent,pin,port=443){return new Promise((resolve,reject)=>{
 const req=https.get({host:address,port,servername:hostname,headers:{host:hostname},path,agent,timeout:15000},res=>{
  const spki=observedPeerKeys.get(res.socket)||res.socket.getPeerX509Certificate()?.publicKey.export({format:'der',type:'spki'});
  if(!spki||(pin&&!pin.equals(spki))){res.destroy();reject(new Error('guest TLS key changed'));return;}
  const chunks=[];let size=0;res.on('data',b=>{size+=b.length;if(size>2097152)res.destroy(new Error('guest proof too large'));else chunks.push(b)});
  res.once('error',reject);res.once('end',()=>resolve({status:res.statusCode,spki,bytes:Buffer.concat(chunks)}));
 });
 const deadline=setTimeout(()=>req.destroy(new Error('guest probe timeout')),30000);
 req.once('close',()=>clearTimeout(deadline));req.once('timeout',()=>req.destroy(new Error('guest probe timeout')));req.once('error',reject);
});}
const GUEST_BUSY=/attestation busy; retry|too many concurrent report requests/,GUEST_BUSY_RETRIES=5;
export async function probeGuest({deploymentId,hostname,address,port=443,proxy,direct=false,expected,linux,shield,hostSession,pvm,localUpstream,openApp,domainIndependent=false,verifySnp=judge,pinnedSpkiSha256=null,startupEgress=false,attestationBootstrap=false}){
 if(startupEgress&&(!openApp||proxy||pinnedSpkiSha256||expected.requiresConfigSocketServer!==true||expected.requiresSecretsV1!==true))throw new Error('startup egress requires a local configured secret command proof');
 if([proxy,localUpstream,openApp,direct].filter(Boolean).length!==1)throw new Error('guest probes require exactly one explicit app transport');
 if(attestationBootstrap&&(!direct||!isIP(address)||pinnedSpkiSha256||domainIndependent||startupEgress||
   !hostname||!/^0x[0-9a-f]{64}$/.test(deploymentId)||!expected||
   !/^[0-9a-f]{64}$/.test(expected.appSha256)||!/^[0-9a-f]{64}$/.test(expected.runtimeId)||
   !(linux||shield&&hostSession||pvm)))throw new Error('attestation bootstrap requires a literal direct route and explicit guest policy');
 if(direct&&(!pinnedSpkiSha256&&!attestationBootstrap||domainIndependent))throw new Error('direct route probes require an attested key and SNI');
 // The locally attested key authenticates a route even before its WebPKI
 // certificate is installed. SNI remains present for shared public listeners;
 // only a dedicated native port uses domainIndependent transport.
 let verifiedKey=pinnedSpkiSha256;
 const routeTls={tlsOptions:{...(domainIndependent||pinnedSpkiSha256||attestationBootstrap?{rejectUnauthorized:false}:{}),...(domainIndependent?{servername:''}:{})},
   ...((pinnedSpkiSha256||attestationBootstrap)?{verifyPeer:connection=>{
     const key=connection.getPeerX509Certificate()?.publicKey.export({format:'der',type:'spki'});
     // Bootstrap sends only a nonce proof request until hardware verifies this
     // key. Every later connection is checked BEFORE any HTTP bytes are sent.
     if(!key||verifiedKey&&createHash('sha256').update(key).digest('hex')!==verifiedKey)throw new Error('guest TLS key changed');
     observedPeerKeys.set(connection,key);
   }}:{})};
 const agent=(localUpstream||openApp)?new LocalAppHttpsAgent(localUpstream,deploymentId,{openApp,attestationOnly:startupEgress}):direct?new DirectHttpsAgent(routeTls):new SocksHttpsAgent(proxy,routeTls),nonce=randomBytes(32);
 address=(localUpstream||openApp)?'127.0.0.1':address;
 try{
  // A route probe for a guest whose current proof bound TLS key K needs no new
  // report: a TLS session that completes with K reaches that guest (only it
  // holds K's private key), and its readiness answer says it is serving. A
  // changed key is rejected; only a fresh local attestation may replace K.
  if(pinnedSpkiSha256){
    const ready=await get(hostname,address,'/.well-known/enclave-ready',agent,undefined,port);
    const spkiSha256=createHash('sha256').update(ready.spki).digest('hex');
    if(spkiSha256===pinnedSpkiSha256){
      if(ready.status!==200)throw new Error('guest readiness HTTP '+ready.status);
      return {verified:true,deploymentId,appSha256:expected.appSha256,runtimeId:expected.runtimeId,spkiSha256,pinned:true};
    }
    throw new Error('guest TLS key changed');
  }
  // A Shield guest makes one TPM report at a time (~3 s) and answers any other
  // request meanwhile with HTTP 500 "busy; retry"; Nan and clients ask too, so
  // that answer is waited out rather than counted against the route.
  let response;
  for(let attempt=0;;attempt++){
    response=await get(hostname,address,'/.well-known/enclave-attestation?nonce='+nonce.toString('hex'),agent,undefined,port);
    if(response.status!==500||attempt>=GUEST_BUSY_RETRIES||!GUEST_BUSY.test(response.bytes.subarray(0,512).toString('utf8')))break;
    await new Promise(r=>setTimeout(r,1000+Math.floor(Math.random()*2500)));
  }
  if(response.status!==200)throw new Error('guest attestation HTTP '+response.status);
  const doc=JSON.parse(response.bytes);
  if(doc.nonce!==nonce.toString('hex')||doc.transportKey!==response.spki.toString('base64')||doc.appSha256!==expected.appSha256)throw new Error('app, nonce or TLS binding mismatch');
  let verified=false;
  if(doc.format==='sev-snp-guest-domain-v1'&&linux){
    if(runtimeId(linux.runtime).toString('hex')!==expected.runtimeId)throw new Error('SNP runtime policy does not match expected runtime');
    const verdict=await verifySnp(doc,response.spki,nonce,{...linux,appSha:expected.appSha256,hostData:deploymentId,mode:'trusted'});
    verified=verdict.gateOpen===true&&verdict.verdict==='attested';if(!verified)throw new Error('SNP guest proof refused: '+JSON.stringify(verdict));
  }else if(shield&&hostSession){
    const verdict=verifyShieldAppPolicy({doc,handshakeSpki:response.spki,nonce,expectedAppSha256:expected.appSha256,expectedRuntimeId:expected.runtimeId,hostSession,requiresConfigBundleV5:expected.requiresConfigBundleV5,requiresSecretsV1:expected.requiresSecretsV1,requiresConfigSocketServer:expected.requiresConfigSocketServer},shield);
    verified=verdict.ok===true;if(!verified)throw new Error('Shield guest proof refused: '+verdict.reason);
  }else if(pvm&&String(doc.format||'').startsWith('enclave-pvm-app-evidence/')){
    // a pVM host's app: a fresh AVF certificate over OUR nonce, rooted at Google's attestation roots, for the pinned build and
    // runtime, binding this app and -- signed by the attested transport key -- the TLS key this very connection presented
    const verdict=verifyPvmAppEvidence(doc,{nonce,appId:expected.appSha256,requireTls:true,allowedRuntimeIds:pvm.runtimeIds,
      allowedCodeHashes:pvm.codeHashes,allowedAuthorityHashes:pvm.authorityHashes,...(pvm.rootPins?{rootPins:pvm.rootPins}:{})});
    if(!verdict.ok)throw new Error('pVM guest proof refused: '+verdict.reasons.at(-1));
    if(verdict.tlsSpki!==response.spki.toString('hex'))throw new Error('pVM guest proof refused: the evidence binds another TLS key');
    if(verdict.runtimeId!==expected.runtimeId)throw new Error('pVM guest proof refused: another runtime');
    verified=true;
  }else throw new Error('no independently trusted guest verification policy');
  verifiedKey=createHash('sha256').update(response.spki).digest('hex');
  const ready=await get(hostname,address,'/.well-known/enclave-ready',agent,response.spki,port);
  if(ready.status!==200&&!(startupEgress&&ready.status===503))throw new Error('guest readiness HTTP '+ready.status);
  return {ready:ready.status===200,verified,deploymentId,appSha256:expected.appSha256,runtimeId:expected.runtimeId,spkiSha256:createHash('sha256').update(response.spki).digest('hex')};
 }finally{agent.destroy();}
}
