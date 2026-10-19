// Verified publication to distinct adapter deployments. Current availability
// is not proof of operator independence or a future retention promise.
import {createHash} from 'node:crypto';
import {directUploadHeaders} from '../storage/upload-auth.mjs';
import {verifyPackage,readBoundedResponse,parseUniqueJSON,MAX_PACKAGE_BYTES} from './package.mjs';
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).every(k=>keys.includes(k));
export function validateStoragePlan(plan) {
  if(!exact(plan,['version','minimumCopies','replicas'])||plan.version!==1||!Array.isArray(plan.replicas)||
    plan.replicas.length<2||plan.replicas.length>8||!Number.isInteger(plan.minimumCopies)||
    plan.minimumCopies<2||plan.minimumCopies>plan.replicas.length)throw Error('storage plan needs 2–8 adapters and a minimum of 2 verified copies');
  const hosts=new Set(),audiences=new Set();
  const replicas=plan.replicas.map(r=>{
    if(!exact(r,['upload','audience','gateway'])||typeof r.upload!=='string'||typeof r.gateway!=='string'||
      !/^0x[0-9a-f]{64}$/.test(r.audience||'')||/^0x0{64}$/.test(r.audience))throw Error('invalid storage adapter');
    const u=new URL(r.upload),g=new URL(r.gateway);
    for(const x of [u,g])if(x.protocol!=='https:'||x.username||x.password||x.search||x.hash)throw Error('storage adapters require HTTPS without credentials, query or fragment');
    if(u.pathname!=='/add-json'||g.pathname.replace(/\/$/,'')!=='/ipfs'||u.origin!==g.origin)throw Error('upload and readback must address the same adapter origin');
    // Distinct hostnames and deployments are necessary but do not prove
    // different operators. Aliases for one adapter cannot count twice.
    if(hosts.has(u.hostname)||audiences.has(r.audience))throw Error('storage adapters need distinct hostnames and deployment audiences');
    hosts.add(u.hostname);audiences.add(r.audience);
    return {upload:u.href,audience:r.audience,gateway:g.href.replace(/\/$/,'')};
  });
  return {version:1,minimumCopies:plan.minimumCopies,replicas};
}
const checkedPackage=(bytes,scope)=>verifyPackage(bytes,{version:1,sha256:createHash('sha256').update(bytes).digest('hex')},scope);
function options({timeoutMs=240000,fetchImpl=fetch}={}) {
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>260000)throw Error('invalid storage deadline');
  return {timeoutMs,fetchImpl};
}
async function readback(pkg,replica,fetchImpl,signal) {
  const res=await fetchImpl(`${replica.gateway}/${pkg.cid}`,{redirect:'error',signal,cache:'no-store',headers:{'cache-control':'no-cache'}});
  if(!res.ok){await res.body?.cancel();throw Error('adapter readback refused');}
  verifyPackage(await readBoundedResponse(res,MAX_PACKAGE_BYTES),{version:1,sha256:pkg.sha256});
}
async function collect(plan,pkg,operation) {
  const results=await Promise.all(plan.replicas.map(async(replica,index)=>{
    try {await operation(replica,index);return {index,...replica,verified:true};}
    catch(e){return {index,...replica,verified:false,reason:e.name==='TimeoutError'?'deadline exceeded':'upload or exact-byte readback failed'};}
  }));
  const copies=results.filter(r=>r.verified),failures=results.filter(r=>!r.verified);
  const report={version:1,cid:pkg.cid,sha256:pkg.sha256,minimumCopies:plan.minimumCopies,
    verifiedCopies:copies.length,copies,failures,checkedAt:new Date().toISOString(),independentOperatorsVerified:false};
  if(copies.length<plan.minimumCopies){const e=Error(`storage availability requirement not met (${copies.length}/${plan.minimumCopies} verified copies)`);e.report=report;throw e;}
  return report;
}
export async function publishPackageReplicas(bytes,scope,plan,signer,opts={}) {
  plan=validateStoragePlan(plan);const pkg=checkedPackage(bytes,scope),{timeoutMs,fetchImpl}=options(opts);
  // Serialize wallet requests. No remote upload occurs until every endpoint
  // and the package have passed validation and the caller has signed the plan.
  const headers=[];
  for(const replica of plan.replicas)headers.push(await directUploadHeaders({audience:replica.audience,url:replica.upload,
    address:signer.address,bytes:pkg.bytes,signMessage:args=>signer.signMessage(args)}));
  return collect(plan,pkg,async(replica,index)=>{
    const signal=AbortSignal.timeout(timeoutMs);
    const res=await fetchImpl(replica.upload,{method:'POST',redirect:'error',signal,
      headers:{'content-type':'application/json',...headers[index]},body:pkg.bytes});
    if(!res.ok){await res.body?.cancel();throw Error('adapter upload refused');}
    const body=parseUniqueJSON(new TextDecoder('utf-8',{fatal:true}).decode(await readBoundedResponse(res,4096)));
    if(body?.cid!==pkg.cid)throw Error('adapter returned another CID');
    await readback(pkg,replica,fetchImpl,signal);
  });
}
export async function verifyPackageReplicas(bytes,scope,plan,opts={}) {
  plan=validateStoragePlan(plan);const pkg=checkedPackage(bytes,scope),{timeoutMs,fetchImpl}=options(opts);
  return collect(plan,pkg,(replica)=>readback(pkg,replica,fetchImpl,AbortSignal.timeout(timeoutMs)));
}
