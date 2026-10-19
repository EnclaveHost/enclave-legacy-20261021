// Digest-addressed PUBLIC artifacts. A gateway is only a byte supplier; every
// accepted byte is covered by a caller/owner pin before it reaches a consumer.
import fs from 'node:fs/promises';
import path from 'node:path';
import {isIP} from 'node:net';
import {createHash,randomBytes} from 'node:crypto';
import {packageCID,parseUniqueJSON} from '../bootstrap/package.mjs';

const HEX=/^[0-9a-f]{64}$/;
export class RawArtifacts {
  constructor({gateways,fetchImpl=fetch,timeoutMs=60000}={}){
    if(!Array.isArray(gateways)||!gateways.length||gateways.length>8||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>120000)throw Error('explicit bounded artifact sources required');
    this.gateways=[...new Set(gateways.map(raw=>{
      const u=new URL(raw);
      if(!['http:','https:'].includes(u.protocol)||!isIP(u.hostname.replace(/^\[|\]$/g,''))||u.username||u.password||u.search||u.hash)throw Error('literal public artifact gateways required');
      return u.href.replace(/\/$/,'');
    }))];
    Object.assign(this,{fetchImpl,timeoutMs});this.failedUntil=new Map();this.receipts=[];
  }
  async get(sha256,target,{size,maxBytes=512*1024*1024}={}){
    if(!HEX.test(sha256)||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>1024*1024*1024||size!==undefined&&(!Number.isSafeInteger(size)||size<0||size>maxBytes))throw Error('bounded artifact digest and size required');
    const cid=packageCID(sha256),available=this.gateways.filter(g=>(this.failedUntil.get(g)||0)<=Date.now());
    // Prefer responsive peers, but a replica missing object A may still be the
    // only source of B. Backoff must never hide it after other peers refuse B.
    const origins=[...available,...this.gateways.filter(g=>!available.includes(g))];
    for(const origin of origins){
      const temporary=target+'.'+randomBytes(8).toString('hex');let handle,response,reader;
      try{
        response=await this.fetchImpl(origin+'/'+cid,{redirect:'error',credentials:'omit',headers:{'accept-encoding':'identity'},signal:AbortSignal.timeout(this.timeoutMs)});
        if(response.status!==200)throw Error('artifact HTTP '+response.status);
        const declared=response.headers.get('content-length');
        if(declared!==null&&(!/^\d+$/.test(declared)||Number(declared)>maxBytes||size!==undefined&&Number(declared)!==size))throw Error('artifact length mismatch');
        if(!response.body)throw Error('missing artifact body');
        handle=await fs.open(temporary,'wx',0o600);reader=response.body.getReader();const hash=createHash('sha256');let bytes=0;
        for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.length;
          if(bytes>maxBytes||size!==undefined&&bytes>size)throw Error('artifact size limit');hash.update(value);await handle.writeFile(value);
        }
        if(size!==undefined&&bytes!==size||hash.digest('hex')!==sha256)throw Error('artifact digest or size mismatch');
        await handle.sync();await handle.close();handle=null;
        // Link rather than replace: a concurrent writer or existing path is an
        // error, never permission to overwrite a user's file or follow a link.
        await fs.link(temporary,target);await fs.unlink(temporary);
        const receipt={cid,sha256,bytes,origin};this.receipts.push(receipt);this.failedUntil.delete(origin);return receipt;
      }catch(e){
        if(['EEXIST','EACCES','ENOSPC','EROFS','ENOENT','ENOTDIR','EPERM'].includes(e.code))throw e;
        this.failedUntil.set(origin,Date.now()+30000);
      }finally{
        if(reader)await reader.cancel().catch(()=>{});else await response?.body?.cancel().catch(()=>{});
        await handle?.close().catch(()=>{});await fs.rm(temporary,{force:true}).catch(()=>{});
      }
    }
    throw Error('no artifact source returned verified bytes for '+sha256);
  }
}

const canonical=value=>JSON.stringify(value,(_key,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const safeName=name=>typeof name==='string'&&name.length<=240&&name.split('/').every(s=>s!=='.'&&s!=='..'&&/^[a-zA-Z0-9_.-]+$/.test(s));
const PARAMETERS={mode:'snp',vcpuFamily:26,vcpuModel:2,vcpuStepping:1,vmmType:'QEMU'};
export function verifiedReleaseManifest(bytes,releaseId){
  if(!HEX.test(releaseId)||bytes.length>1024*1024||createHash('sha256').update(bytes).digest('hex')!==releaseId)throw Error('release manifest digest mismatch');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),m=parseUniqueJSON(text);
  if(canonical(m)!==text||!exact(m,['format','cmdline','measure','dirs','files'])||m.format!=='enclave-m4a-domain-release/1'||canonical(m.measure)!==canonical(PARAMETERS)||
    typeof m.cmdline!=='string'||m.cmdline.length>8192||!Array.isArray(m.dirs)||m.dirs.length>256||!m.files||typeof m.files!=='object'||Array.isArray(m.files)||Object.keys(m.files).length>256)throw Error('unsupported or noncanonical release manifest');
  const dirs=new Set(m.dirs),files=Object.keys(m.files);let total=0;
  if(dirs.size!==m.dirs.length||JSON.stringify([...dirs].sort())!==JSON.stringify(m.dirs)||m.dirs.some(d=>!safeName(d)||d==='release.json'))throw Error('invalid release directories');
  for(const name of [...m.dirs,...files]){
    if(!safeName(name)||name==='release.json'||files.includes(name)&&dirs.has(name))throw Error('unsafe release path');
    const parent=path.posix.dirname(name);if(parent!=='.'&&!dirs.has(parent))throw Error('missing release parent directory');
  }
  for(const entry of Object.values(m.files)){
    if(!exact(entry,['sha256','size'])||!HEX.test(entry.sha256)||!Number.isSafeInteger(entry.size)||entry.size<0||entry.size>512*1024*1024)throw Error('invalid release file');
    total+=entry.size;if(total>1024*1024*1024)throw Error('release size limit');
  }
  for(const need of ['kernel','firmware.fd','template/init','template/front','template/rt/wasmtime','template/rt/runtime.json'])if(!Object.hasOwn(m.files,need))throw Error('missing required release file');
  return m;
}

export async function fetchRelease(artifacts,releaseId,destination){
  // Own a new directory, never merge into an existing release or retain partial
  // material as an accepted cache. The image verifier independently checks it.
  await fs.mkdir(destination,{mode:0o700});
  try{
    const file=path.join(destination,'release.json');await artifacts.get(releaseId,file,{maxBytes:1024*1024});
    const manifest=verifiedReleaseManifest(await fs.readFile(file),releaseId);
    for(const d of manifest.dirs)await fs.mkdir(path.join(destination,d),{mode:0o700});
    const entries=Object.entries(manifest.files);let next=0,failure;
    await Promise.allSettled(Array.from({length:Math.min(3,entries.length)},async()=>{
      while(!failure&&next<entries.length){const [name,entry]=entries[next++];
        try{await artifacts.get(entry.sha256,path.join(destination,name),{size:entry.size});}catch(e){failure=e;throw e;}
      }
    }));
    if(failure)throw failure;
    return {releaseId,files:entries.length,bytes:entries.reduce((n,[,e])=>n+e.size,0)};
  }catch(e){await fs.rm(destination,{recursive:true,force:true});throw e;}
}
