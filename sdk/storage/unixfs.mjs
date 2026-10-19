// The adapter's fixed import profile: CIDv1, SHA-256, 256 KiB raw leaves,
// balanced UnixFS with 174 links per node. No remote hash or importer needed.
import {createHash} from 'node:crypto';
export const CHUNK_BYTES=262144;
export const MAX_ARTIFACT_BYTES=2*1024*1024*1024;
const FANOUT=174,sha=b=>createHash('sha256').update(b).digest();
const vi=n=>{const out=[];do{out.push(n%128+(n>=128?128:0));n=Math.floor(n/128);}while(n);return Buffer.from(out);};
const uint=(field,n)=>Buffer.concat([vi(field*8),vi(n)]);
const field=(n,b)=>Buffer.concat([vi(n*8+2),vi(b.length),b]);
const cid=(codec,digest)=>Buffer.concat([Buffer.from([1,codec,0x12,32]),digest]);
function base32(bytes){const alphabet='abcdefghijklmnopqrstuvwxyz234567';let out='b',acc=0,bits=0;
 for(const b of bytes){acc=(acc<<8)|b;bits+=8;while(bits>=5){bits-=5;out+=alphabet[(acc>>>bits)&31];}}
 if(bits)out+=alphabet[(acc<<(5-bits))&31];return out;
}
export function artifactIdentity(bytes) {
 if(!(bytes instanceof Uint8Array)||bytes.byteLength>MAX_ARTIFACT_BYTES)throw Error('artifact must be bytes, at most 2 GiB');
 const leaves=[],sizes=[],whole=createHash('sha256');
 for(let offset=0;offset<bytes.length||offset===0;offset+=CHUNK_BYTES){const b=bytes.subarray(offset,offset+CHUNK_BYTES);leaves.push(cid(0x55,sha(b)));sizes.push(b.length);whole.update(b);}
 function level(start,end,depth){
  if(!depth)return {cid:leaves[start],content:sizes[start],total:sizes[start]};
  const children=[],group=FANOUT**(depth-1);
  for(let i=start;i<end;i+=group)children.push(level(i,Math.min(end,i+group),depth-1));
  const content=children.reduce((n,c)=>n+c.content,0);
  const data=Buffer.concat([uint(1,2),uint(3,content),...children.map(c=>uint(4,c.content))]);
  // dag-pb links precede Data; empty link names are explicitly encoded.
  const block=Buffer.concat([...children.map(c=>field(2,Buffer.concat([field(1,c.cid),field(2,Buffer.alloc(0)),uint(3,c.total)]))),field(1,data)]);
  return {cid:cid(0x70,sha(block)),content,total:block.length+children.reduce((n,c)=>n+c.total,0)};
 }
 let depth=0,capacity=1;while(capacity<leaves.length){depth++;capacity*=FANOUT;}
 return {cid:base32(level(0,leaves.length,depth).cid),sha256:whole.digest('hex'),bytes:bytes.length};
}
