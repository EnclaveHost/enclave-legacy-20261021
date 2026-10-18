import https from 'node:https';
import {randomBytes,timingSafeEqual} from 'node:crypto';
import {verifyShieldAppPolicy} from '../relay/shield-app-policy.mjs';
import {verifyEvidence} from '../verifier/index.mjs';
import {runtimeId,bind2} from '../isolation/contract/runtime.mjs';
import {appLookup} from './public-dns.mjs';

function exchange(url,{method='GET',headers={},body,timeoutMs,maxBytes=131072,pinnedSpki}={}) {
 return new Promise((resolve,reject)=>{
  if(url.protocol!=='https:')return reject(new Error('HTTPS required'));
  const bytes=body===undefined?null:Buffer.from(JSON.stringify(body));
  const req=https.request(url,{method,agent:false,lookup:appLookup,headers:{...headers,...(bytes?{'content-type':'application/json','content-length':String(bytes.length)}:{})}},res=>{
   const cert=res.socket.getPeerX509Certificate();if(!cert){req.destroy(new Error('no peer certificate'));return;}
   const spki=cert.publicKey.export({format:'der',type:'spki'});
   if(pinnedSpki&&(pinnedSpki.length!==spki.length||!timingSafeEqual(pinnedSpki,spki))){req.destroy(new Error('guest key changed'));return;}
   const chunks=[];let size=0;
   res.on('data',b=>{size+=b.length;if(size>maxBytes)req.destroy(new Error('response too large'));else chunks.push(b);});
   res.on('error',reject);res.on('end',()=>{
    try{if(res.statusCode!==200)throw Object.assign(new Error(`HTTP ${res.statusCode}`),{status:res.statusCode,text:Buffer.concat(chunks).subarray(0,512).toString('utf8')});
     resolve({body:JSON.parse(Buffer.concat(chunks)),spki});}catch(e){reject(e);}
   });
  });
  const timer=setTimeout(()=>req.destroy(new Error('request deadline exceeded')),timeoutMs);
  req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end(bytes);
 });
}

// A Shield guest makes one TPM report at a time (~3 s) and answers any other
// request meanwhile with HTTP 500 "attestation busy; retry" (network/guest-probe.mjs);
// that answer is waited out with the SAME nonce, never counted as evidence.
const GUEST_BUSY=/attestation busy; retry|too many concurrent report requests/,GUEST_BUSY_RETRIES=5;

/** Expectations MUST be independently derived from the current ledger/catalog,
 * pinned runtime release and authenticated current host session. No values
 * learned from the report are promoted to trusted expectations here.
 *
 * request.prepare(job) loads the expectations ahead of the request (the workload
 * calls it before its timer starts: verifier-side work, such as a Shield host's
 * TPM session, is not charged to the host); the request then uses them once.
 * transport and verifyShield are for tests only.
 */
export function verifiedAppRequest({loadExpectations,collateral,now=Date.now,transport=exchange,verifyShield=verifyShieldAppPolicy,
                                    sleep=ms=>new Promise(r=>setTimeout(r,ms))}) {
 if(typeof loadExpectations!=='function')throw new Error('independent expectation loader required');
 const prepared=new Map();
 const call=async(job,request)=>{
  const exp=prepared.get(job.deployment.id)||await loadExpectations(job);prepared.delete(job.deployment.id);
  if(exp.deploymentId!==job.deployment.id||exp.hostId!==job.offer.hostId
    || !/^[0-9a-f]{64}$/.test(exp.appId||''))throw new Error('wrong expected deployment, host or artifact');
  const origin=new URL(exp.origin);
  if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)
   throw new Error('invalid attested origin');
  const nonce=randomBytes(32),at=now();
  let capture;
  for(let attempt=0;;attempt++) {
   try{capture=await transport(new URL('/.well-known/enclave-attestation?nonce='+nonce.toString('hex'),origin),{timeoutMs:request.timeoutMs-(now()-at)});break;}
   catch(e){if(e.status!==500||attempt>=GUEST_BUSY_RETRIES||!GUEST_BUSY.test(e.text||'')||now()-at>=request.timeoutMs)throw e;}
   await sleep(1000+Math.floor(Math.random()*2500));
  }
  let verdict;
  if(exp.kind==='shield') {
   if(!Number.isSafeInteger(exp.hostSessionAtMs)||exp.hostSessionAtMs>at||at-exp.hostSessionAtMs>30000)
    throw new Error('current authenticated host session required');
   // the image must support what this app's derivation needs (a config bundle, sealed secrets, the config socket):
   // an image without secrets support is not admitted for an app that has them
   verdict=verifyShield({doc:capture.body,handshakeSpki:capture.spki,nonce,
    expectedAppSha256:exp.appId,expectedRuntimeId:exp.runtimeId,hostSession:exp.hostSession,
    requiresConfigBundleV5:exp.requiresConfigBundleV5===true,requiresSecretsV1:exp.requiresSecretsV1===true,
    requiresConfigSocketServer:exp.requiresConfigSocketServer===true},exp.policy);
   if(!verdict.ok)throw new Error('Shield app evidence rejected: '+String(verdict.reason||'no reason given').slice(0,400));
  } else if(exp.kind==='snp') {
   // Each expected image is its OWN expectation: a launch measurement together with the runtime identity that image
   // binds (one per admitted release). Allowing every measurement but binding one runtime refuses every guest of the
   // other releases (production job 0xb11f432d, 2026-10-16). Trying each trusted pair promotes nothing from the report.
   const images=exp.images||[{measurements:exp.policy?.snp?.allowedMeasurements,runtimeIdentity:exp.runtimeIdentity}];
   if(!images.length)throw new Error('no expected image');
   const reasons=[];
   for(const image of images) {
    const rid=runtimeId(image.runtimeIdentity);
    const policy={...exp.policy,snp:{...exp.policy.snp,allowedMeasurements:image.measurements}};
    verdict=await verifyEvidence(capture.body,{policy,collateral,
     context:{transportKeySpki:capture.spki,nonce,expectedBinding:bind2(capture.spki,nonce,rid),
      expectedAppId:Buffer.from(exp.appId,'hex'),expectedHostData:Buffer.from(job.deployment.id.slice(2),'hex'),
      auxblob:capture.body.certs?Buffer.from(capture.body.certs,'base64'):undefined,now:new Date(at).toISOString()}});
    if(verdict.status==='verified'&&verdict.admissionSafe===true)break;
    reasons.push(...(verdict.reasons||[]).filter(r=>/^REJECT/.test(r)));
   }
   if(verdict.status!=='verified'||verdict.admissionSafe!==true)
    throw new Error('SNP app evidence rejected: '+([...new Set(reasons)].join('; ').slice(0,400)||'no reason given'));
  } else throw new Error('unsupported isolation verifier');
  const target=new URL(request.path,origin);if(target.origin!==origin.origin)throw new Error('cross-origin workload');
  const remainingMs=request.timeoutMs-(now()-at);
  if(remainingMs<=0)throw new Error('request deadline exceeded');
  const response=await transport(target,{...request,timeoutMs:remainingMs,pinnedSpki:capture.spki});
  return {body:response.body,attestationVerified:true,hostId:exp.hostId,deploymentId:exp.deploymentId,
   evidence:{nonce:nonce.toString('hex'),document:capture.body,spki:capture.spki.toString('base64'),verdict}};
 };
 call.prepare=async job=>{prepared.set(job.deployment.id,await loadExpectations(job));};
 call.discard=job=>{prepared.delete(job.deployment.id);};
 return call;
}
