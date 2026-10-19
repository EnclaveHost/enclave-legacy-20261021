import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {artifactIdentity,CHUNK_BYTES} from './unixfs.mjs';
import {directUploadDigestHeaders} from './upload-auth.mjs';
import {validateStoragePlan,replicaOptions,collectReplicas} from './replicas.mjs';
import {readBoundedResponse,parseUniqueJSON} from '../bootstrap/package.mjs';
const WINDOW=4*1024*1024;
const kinds={wasm:{path:'/add-wasm',type:'application/wasm',max:2*1024*1024*1024},json:{path:'/add-json',type:'application/json',max:1024*1024},image:{path:'/add-image',type:'application/octet-stream',max:4*1024*1024}};
async function readback(identity,replica,fetchImpl,signal) {
 const hash=createHash('sha256');
 for(let start=0;start<identity.bytes||start===0;start+=WINDOW){
  const size=Math.min(WINDOW,identity.bytes-start),end=start+size-1;
  const headers={'cache-control':'no-cache','accept-encoding':'identity',...(size?{range:`bytes=${start}-${end}`}:{})};
  const res=await fetchImpl(`${replica.gateway}/${identity.cid}`,{redirect:'error',signal,cache:'no-store',headers});
  const whole=res.status===200&&start===0&&size===identity.bytes;
  const partial=res.status===206&&res.headers.get('content-range')===`bytes ${start}-${end}/${identity.bytes}`;
  if(!whole&&!partial){await res.body?.cancel();throw Error('artifact range refused or changed');}
  const bytes=await readBoundedResponse(res,size);
  if(bytes.length!==size)throw Error('truncated artifact readback');hash.update(bytes);
 }
 if(hash.digest('hex')!==identity.sha256)throw Error('artifact readback digest mismatch');
}
export async function publishArtifactReplicas(bytes,kind,plan,signer,opts={}) {
 plan=validateStoragePlan(plan);const format=kinds[kind];
 if(!format||!(bytes instanceof Uint8Array)||bytes.length>format.max)throw Error('invalid artifact kind or size');
 const identity=artifactIdentity(bytes),{timeoutMs,fetchImpl}=replicaOptions(opts),headers=[];
 for(const replica of plan.replicas)headers.push(await directUploadDigestHeaders({audience:replica.audience,
  url:new URL(format.path,replica.upload).href,address:signer.address,hash:identity.sha256,size:identity.bytes,
  signMessage:args=>signer.signMessage(args)}));
 const artifactPlan={...plan,replicas:plan.replicas.map(r=>({...r,upload:new URL(format.path,r.upload).href}))};
 const report=await collectReplicas(artifactPlan,identity,async(replica,index)=>{
  const signal=AbortSignal.timeout(timeoutMs);
  // A separate bounded stream for each adapter avoids fetch cloning the full
  // potentially multi-gigabyte Buffer for every replica.
  const body=Readable.from((async function*(){for(let offset=0;offset<bytes.length;offset+=CHUNK_BYTES)yield bytes.subarray(offset,offset+CHUNK_BYTES);})());
  try {
   const res=await fetchImpl(new URL(format.path,replica.upload).href,{method:'POST',redirect:'error',signal,duplex:'half',
    headers:{'content-type':format.type,'content-length':String(bytes.length),...headers[index]},body});
   if(!res.ok){await res.body?.cancel();throw Error('artifact upload refused');}
   const answer=parseUniqueJSON(new TextDecoder('utf-8',{fatal:true}).decode(await readBoundedResponse(res,4096)));
   if(answer?.cid!==identity.cid)throw Error('artifact CID differs from local import');
   await readback(identity,replica,fetchImpl,signal);
  } finally {body.destroy();}
 });
 return {...report,kind,bytes:identity.bytes};
}
export async function verifyArtifactReplicas(bytes,plan,opts={}) {
 plan=validateStoragePlan(plan);const identity=artifactIdentity(bytes),{timeoutMs,fetchImpl}=replicaOptions(opts);
 return collectReplicas(plan,identity,(replica)=>readback(identity,replica,fetchImpl,AbortSignal.timeout(timeoutMs)));
}
