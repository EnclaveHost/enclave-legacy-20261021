// Verified publication to distinct adapter deployments. Current availability
// is not proof of operator independence or a future retention promise.
import {createHash} from 'node:crypto';
import {directUploadHeaders} from '../storage/upload-auth.mjs';
import {verifyPackage,readBoundedResponse,parseUniqueJSON,MAX_PACKAGE_BYTES} from './package.mjs';
import {validateStoragePlan,replicaOptions,collectReplicas} from '../storage/replicas.mjs';
export {validateStoragePlan} from '../storage/replicas.mjs';
const checkedPackage=(bytes,scope)=>verifyPackage(bytes,{version:1,sha256:createHash('sha256').update(bytes).digest('hex')},scope);
async function readback(pkg,replica,fetchImpl,signal) {
  const res=await fetchImpl(`${replica.gateway}/${pkg.cid}`,{redirect:'error',signal,cache:'no-store',headers:{'cache-control':'no-cache'}});
  if(!res.ok){await res.body?.cancel();throw Error('adapter readback refused');}
  verifyPackage(await readBoundedResponse(res,MAX_PACKAGE_BYTES),{version:1,sha256:pkg.sha256});
}
export async function publishPackageReplicas(bytes,scope,plan,signer,opts={}) {
  plan=validateStoragePlan(plan);const pkg=checkedPackage(bytes,scope),{timeoutMs,fetchImpl}=replicaOptions(opts);
  // Serialize wallet requests. No remote upload occurs until every endpoint
  // and the package have passed validation and the caller has signed the plan.
  const headers=[];
  for(const replica of plan.replicas)headers.push(await directUploadHeaders({audience:replica.audience,url:replica.upload,
    address:signer.address,bytes:pkg.bytes,signMessage:args=>signer.signMessage(args)}));
  return collectReplicas(plan,pkg,async(replica,index)=>{
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
  plan=validateStoragePlan(plan);const pkg=checkedPackage(bytes,scope),{timeoutMs,fetchImpl}=replicaOptions(opts);
  return collectReplicas(plan,pkg,(replica)=>readback(pkg,replica,fetchImpl,AbortSignal.timeout(timeoutMs)));
}
