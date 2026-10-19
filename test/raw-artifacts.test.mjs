import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {RawArtifacts,fetchRelease,verifiedReleaseManifest} from '../sdk/storage/raw-artifacts.mjs';
import {packageCID} from '../sdk/bootstrap/package.mjs';

const hash=b=>createHash('sha256').update(b).digest('hex');
const canonical=value=>JSON.stringify(value,(_k,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
function fixture(){
  const objects=new Map(),files={};
  for(const name of ['kernel','firmware.fd','template/init','template/front','template/rt/wasmtime','template/rt/runtime.json']){
    const b=Buffer.from('test public file '+name),sha256=hash(b);objects.set(sha256,b);files[name]={sha256,size:b.length};
  }
  const manifest={format:'enclave-m4a-domain-release/1',cmdline:'console=ttyS0',measure:{mode:'snp',vcpuFamily:26,vcpuModel:2,vcpuStepping:1,vmmType:'QEMU'},dirs:['template','template/rt'],files};
  const bytes=Buffer.from(canonical(manifest)),releaseId=hash(bytes);objects.set(releaseId,bytes);return {objects,manifest,bytes,releaseId};
}
async function temp(t){const d=await fs.mkdtemp(path.join(os.tmpdir(),'raw-artifacts-'));t.after(()=>fs.rm(d,{recursive:true,force:true}));return d;}
test('real HTTP raw replicas reject refusal and substitution, with no credentials or redirects',async t=>{
  const dir=await temp(t),data=Buffer.alloc(3*1024*1024,5),sha=hash(data),seen=[];
  const server=http.createServer((req,res)=>{
    seen.push(req.url);assert.equal(req.headers.authorization,undefined);assert.equal(req.headers.cookie,undefined);
    if(req.url.startsWith('/bad/'))res.end('wrong');
    else if(req.url.startsWith('/redirect/')){res.writeHead(302,{location:'/good/'+packageCID(sha)});res.end();}
    else if(req.url.startsWith('/good/')){for(let n=0;n<data.length;n+=65536)res.write(data.subarray(n,n+65536));res.end();}
    else{res.writeHead(503);res.end();}
  });await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>{server.closeAllConnections();server.close();});
  const origin='http://127.0.0.1:'+server.address().port;
  const client=new RawArtifacts({gateways:['/down','/redirect','/bad','/good'].map(p=>origin+p)});
  const receipt=await client.get(sha,path.join(dir,'good'),{size:data.length});assert.equal(receipt.bytes,data.length);assert.equal(hash(await fs.readFile(path.join(dir,'good'))),sha);assert.equal(seen.length,4);
  assert.deepEqual(await fs.readdir(dir),['good']);
  await assert.rejects(client.get(sha,path.join(dir,'good'),{size:data.length}),{code:'EEXIST'});assert.equal(hash(await fs.readFile(path.join(dir,'good'))),sha);
});
test('dishonest length, oversized and truncated data leave no accepted or temporary file',async t=>{
  const dir=await temp(t),data=Buffer.from('correct'),sha=hash(data);
  for(const [body,headers] of [['wrong',{}],['correctX',{'content-length':'7'}],['cor',{}],['correct',{'content-length':'99999999'}]]){
    const client=new RawArtifacts({gateways:['http://192.0.2.1/ipfs'],fetchImpl:async()=>new Response(body,{headers})});
    await assert.rejects(client.get(sha,path.join(dir,'target'),{size:7,maxBytes:7}),/no artifact source/);assert.deepEqual(await fs.readdir(dir),[]);
  }
  for(const gateway of ['https://not-literal.invalid/ipfs','http://user:pass@192.0.2.1/ipfs','http://192.0.2.1/ipfs?token=1'])assert.throws(()=>new RawArtifacts({gateways:[gateway]}));
});
test('a replica missing one object remains a fallback for a different object',async t=>{
  const dir=await temp(t),a=Buffer.from('object A'),b=Buffer.from('object B'),aCID=packageCID(hash(a)),bCID=packageCID(hash(b)),calls=[];
  const client=new RawArtifacts({gateways:['http://192.0.2.1/ipfs','http://192.0.2.2/ipfs'],fetchImpl:async url=>{
    const u=new URL(url),cid=u.pathname.split('/').at(-1);calls.push(u.hostname+':'+cid);
    if(u.hostname==='192.0.2.2'&&cid===aCID)return new Response(a);
    if(u.hostname==='192.0.2.1'&&cid===bCID)return new Response(b);
    return new Response('not held',{status:404});
  }});
  await client.get(hash(a),path.join(dir,'a'));await client.get(hash(b),path.join(dir,'b'));
  assert.equal((await fs.readFile(path.join(dir,'b'))).toString(),'object B');
  assert.deepEqual(calls.map(x=>x.split(':')[0]),['192.0.2.1','192.0.2.2','192.0.2.2','192.0.2.1']);
});
test('release paths and work bounds are validated before materializing files',()=>{
  const f=fixture();assert.deepEqual(verifiedReleaseManifest(f.bytes,f.releaseId),f.manifest);
  for(const mutate of [m=>m.dirs.push('../escape'),m=>m.files['template/../escape']=m.files.kernel,m=>m.files['/absolute']=m.files.kernel,m=>m.files['template']=m.files.kernel,
    m=>m.files['release.json']=m.files.kernel,m=>m.dirs.push('template'),m=>m.files.kernel.size=2**40,m=>delete m.files.kernel,m=>m.files.kernel.extra=true,m=>m.measure.vcpuFamily=0]){
    const m=structuredClone(f.manifest);mutate(m);const bytes=Buffer.from(canonical(m));assert.throws(()=>verifiedReleaseManifest(bytes,hash(bytes)));
  }
  assert.throws(()=>verifiedReleaseManifest(Buffer.concat([f.bytes,Buffer.from(' ')]),hash(Buffer.concat([f.bytes,Buffer.from(' ')]))),/noncanonical/);
  assert.throws(()=>verifiedReleaseManifest(f.bytes,'00'.repeat(32)),/digest/);
});
test('fetches a complete release into a new directory; existing content is preserved',async t=>{
  const dir=await temp(t),f=fixture(),byCID=new Map([...f.objects].map(([sha,b])=>[packageCID(sha),b]));
  const client=new RawArtifacts({gateways:['http://192.0.2.1/ipfs'],fetchImpl:async url=>new Response(byCID.get(url.split('/').at(-1)))});
  const target=path.join(dir,'release'),result=await fetchRelease(client,f.releaseId,target);assert.equal(result.files,6);
  for(const [name,e] of Object.entries(f.manifest.files))assert.equal(hash(await fs.readFile(path.join(target,name))),e.sha256);
  await assert.rejects(fetchRelease(client,f.releaseId,target),{code:'EEXIST'});assert.equal(hash(await fs.readFile(path.join(target,'release.json'))),f.releaseId);
});
test('a failed release waits for in-flight writers before removing its partial directory',async t=>{
  const dir=await temp(t),f=fixture();let releaseSlow,entered,done=false;
  const started=new Promise(r=>entered=r),gate=new Promise(r=>releaseSlow=r);
  const artifacts={get:async(sha,file)=>{
    if(sha===f.releaseId){await fs.writeFile(file,f.bytes);return;}
    if(sha===f.manifest.files['firmware.fd'].sha256){entered();await gate;await fs.writeFile(file,'late writer');return;}
    throw Error('source refused');
  }};
  const target=path.join(dir,'release'),run=fetchRelease(artifacts,f.releaseId,target);run.then(()=>done=true,()=>done=true);
  await started;await new Promise(r=>setImmediate(r));assert.equal(done,false);releaseSlow();
  await assert.rejects(run,/source refused/);assert.deepEqual(await fs.readdir(dir),[]);
});
