// Public startup packages: only the guest's fresh chain verification authorizes
// startup. This module checks bytes and scope before a host spends a lease.
import {createHash} from 'node:crypto';
import {isIP} from 'node:net';
export const MAX_PACKAGE_BYTES=128*1024;
const hex32=/^[0-9a-f]{64}$/, addr=/^0x[0-9a-fA-F]{40}$/, id32=/^0x[0-9a-f]{64}$/;
const nonzero=s=>!/^0x?0*$/.test(s)&&!/^0+$/.test(s);
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function keys(o,allowed){if(!object(o)||Object.keys(o).some(k=>!allowed.includes(k)))throw Error('unknown or invalid startup fields');}
export function parseUniqueJSON(text){
  // JSON.parse supplies syntax validation; this second walk rejects duplicate
  // decoded keys (including escaped aliases) at any depth.
  const result=JSON.parse(text);let i=0;
  const ws=()=>{while(/\s/.test(text[i]||'')&&i<text.length)i++;};
  const str=()=>{const start=i++;while(i<text.length){if(text[i++]==='"')break;if(text[i-1]==='\\')i++;}return JSON.parse(text.slice(start,i));};
  const walk=depth=>{if(depth>64)throw Error('startup JSON nesting limit');ws();const c=text[i++];
    if(c==='{'){const seen=new Set();ws();if(text[i]==='}'){i++;return;}for(;;){ws();const k=str();if(seen.has(k))throw Error('duplicate startup JSON key');seen.add(k);ws();i++;walk(depth+1);ws();if(text[i++]==='}')return;}}
    else if(c==='['){ws();if(text[i]===']'){i++;return;}for(;;){walk(depth+1);ws();if(text[i++]===']')return;}}
    else if(c==='"'){i--;str();}else{while(i<text.length&&!/[\s,}\]]/.test(text[i]))i++;}};
  walk(0);return result;
}
export function bootstrapIntent(envelope){
  if(!envelope)return null;
  const o=parseUniqueJSON(String(envelope));
  if(!object(o))throw Error('startup envelope must be an object');
  if(!Object.hasOwn(o,'guestBootstrap'))return null;
  keys(o.guestBootstrap,['version','sha256']);
  if(o.guestBootstrap.version!==1||!hex32.test(o.guestBootstrap.sha256)||!nonzero(o.guestBootstrap.sha256)||'config' in o||'configCid' in o)
    throw Error('guestBootstrap needs version 1, a nonzero sha256, and no legacy config');
  return {...o.guestBootstrap};
}
export function packageCID(hash){
  if(!hex32.test(hash))throw Error('invalid package hash');
  const b=Buffer.concat([Buffer.from([1,0x55,0x12,0x20]),Buffer.from(hash,'hex')]);
  const alphabet='abcdefghijklmnopqrstuvwxyz234567';let bits=0,value=0,out='b';
  for(const x of b){value=(value<<8)|x;bits+=8;while(bits>=5){bits-=5;out+=alphabet[(value>>>bits)&31];}}
  if(bits)out+=alphabet[(value<<(5-bits))&31];return out;
}
export function verifyPackage(bytes,intent,scope={}){
  bytes=Buffer.from(bytes);if(!bytes.length||bytes.length>MAX_PACKAGE_BYTES)throw Error('startup package size limit');
  const hash=createHash('sha256').update(bytes).digest('hex');
  if(intent?.version!==1||intent.sha256!==hash)throw Error('startup package hash mismatch');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),m=parseUniqueJSON(text);
  keys(m,['version','chainId','ledger','deployment','owner','appRef','appId','runtimeId','configText','secretsMode','custody']);
  if(m.version!==1||!Number.isSafeInteger(m.chainId)||m.chainId<=0||!addr.test(m.ledger)||!nonzero(m.ledger)||!addr.test(m.owner)||!nonzero(m.owner)||!id32.test(m.deployment)||!nonzero(m.deployment)||!hex32.test(m.appId)||!nonzero(m.appId)||!hex32.test(m.runtimeId)||!nonzero(m.runtimeId)||typeof m.appRef!=='string'||!m.appRef||typeof m.configText!=='string'||Buffer.byteLength(m.configText)>32768)throw Error('invalid startup package');
  if(m.configText){const c=parseUniqueJSON(m.configText);if(!c||typeof c!=='object')throw Error('startup config must be an object or array');}
  if(m.secretsMode==='public'){if(m.custody!=null)throw Error('public package cannot carry custody');}
  else if(m.secretsMode==='custody-v2'){if(!object(m.custody)||m.custody.v!==2||m.custody.chainId!==m.chainId)throw Error('custody-v2 pointer required');}
  else throw Error('explicit startup secrets mode required');
  for(const [k,v]of Object.entries(scope)){if(v==null)continue;const fold=['ledger','owner'].includes(k);if((fold?m[k]?.toLowerCase():m[k])!==(fold?String(v).toLowerCase():v))throw Error(`startup ${k} mismatch`);}
  return {manifest:m,bytes,sha256:hash,cid:packageCID(hash)};
}
export function preparePackage(manifest){const bytes=Buffer.from(JSON.stringify(manifest));const intent={version:1,sha256:createHash('sha256').update(bytes).digest('hex')};return {...verifyPackage(bytes,intent),intent};}
export async function readBoundedResponse(res,limit){
  if(Number(res.headers.get('content-length'))>limit){await res.body?.cancel();throw Error('startup response size limit');}
  const reader=res.body?.getReader();if(!reader)throw Error('startup response empty body');const parts=[];let size=0;
  try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>limit)throw Error('startup response size limit');parts.push(value);}}
  finally{await reader.cancel().catch(()=>{});}
  return Buffer.concat(parts,size);
}
export async function fetchPackage(intent,scope,{gateways,fetchImpl=fetch,timeoutMs=8000,allowHttpIPs=false}={}){
  if(!Array.isArray(gateways)||!gateways.length||gateways.length>8)throw Error('startup package gateways required (1–8)');
  // Public bytes may travel over an explicitly selected literal HTTP origin:
  // the caller's chain commitment authenticates them, never the gateway. This
  // option does not permit uploads, credentials or uncommitted configuration.
  const bases=gateways.map(raw=>{const u=new URL(raw);if(!(u.protocol==='https:'||allowHttpIPs&&u.protocol==='http:'&&isIP(u.hostname.replace(/^\[|\]$/g,'')))||u.username||u.password||u.search||u.hash)throw Error('startup gateways must be HTTPS without credentials/query (or explicitly allowed HTTP IPs)');return u.href.replace(/\/$/,'');});
  const cid=packageCID(intent.sha256),controller=new AbortController();
  try{return await Promise.any(bases.map(async base=>{
    const res=await fetchImpl(`${base}/${cid}`,{redirect:'error',credentials:'omit',signal:AbortSignal.any([controller.signal,AbortSignal.timeout(timeoutMs)])});
    if(!res.ok){await res.body?.cancel();throw Error('startup gateway refused');}
    return verifyPackage(await readBoundedResponse(res,MAX_PACKAGE_BYTES),intent,scope);
  }));}catch{throw Error('no gateway returned the committed startup package');}finally{controller.abort();}
}
