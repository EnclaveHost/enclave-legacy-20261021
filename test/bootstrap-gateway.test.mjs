import test from 'node:test';import assert from 'node:assert/strict';import {mkdtemp,writeFile,rm} from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {createHash} from 'node:crypto';import {createBootstrapGateway} from '../network/bootstrap-gateway.mjs';
const digest=b=>createHash('sha256').update(b).digest('hex');
test('only manifest artifacts are served and corrupt stored bytes refuse startup',async t=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'bootstrap-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const cid='bafkreiaxjgrgo4w23lgn5kx5nyrz6utj45vjmhzitdlryxtwhzj4qglwsq';
 // Transport fixtures: consumer CAR verification is tested by ipfs_fetch.
 await writeFile(path.join(directory,cid+'.bin'),'artifact');await writeFile(path.join(directory,cid+'.car'),'car');
 const manifest={verifiedObjects:[{cid,sha256:digest('artifact'),carSha256:digest('car')}]};
 const server=await createBootstrapGateway({directory,manifest});await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>{server.closeAllConnections();server.close();});const base='http://127.0.0.1:'+server.address().port;
 assert.equal(await (await fetch(base+'/ipfs/'+cid)).text(),'artifact');
 assert.equal(await (await fetch(base+'/ipfs/'+cid+'?format=car&dag-scope=all')).text(),'car');
 assert.equal((await fetch(base+'/ipfs/'+cid,{method:'POST',body:'replace'})).status,405);
 assert.equal((await fetch(base+'/config.json')).status,404);
 await writeFile(path.join(directory,cid+'.bin'),'tampered');await assert.rejects(createBootstrapGateway({directory,manifest}),/digest mismatch/);
});

test('replica object-size limits remain explicit and bounded',async()=>{
 const manifest={verifiedObjects:[]};
 for(const maxObjectBytes of [0,-1,1.5,1024*1024*1024+1])await assert.rejects(createBootstrapGateway({directory:'.',manifest,maxObjectBytes}),/size limit/);
 const server=await createBootstrapGateway({directory:'.',manifest,maxObjectBytes:1024*1024*1024});server.close();
});

test('image responses are typed from bytes while CAR and non-images retain safe types',async t=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'bootstrap-media-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const cases=[
  [Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><rect width="2" height="2"/></svg>'),'image/svg+xml'],
  [Buffer.from('<?xml version="1.0"?>\n<!-- logo --><svg xmlns="http://www.w3.org/2000/svg"/>'),'image/svg+xml'],
  [Buffer.from([137,80,78,71,13,10,26,10]),'image/png'],
  [Buffer.from([255,216,255,224]),'image/jpeg'],
  [Buffer.from('GIF89a'),'image/gif'],
  [Buffer.from('RIFF0000WEBP'),'image/webp'],
  [Buffer.from('<html><svg></svg></html>'),'application/octet-stream'],
  [Buffer.from('arbitrary artifact'),'application/octet-stream'],
 ];
 const verifiedObjects=[];
 for(let i=0;i<cases.length;i++){
  const cid='bafkrei'+String.fromCharCode(97+i).repeat(40);cases[i].push(cid);
  await writeFile(path.join(directory,cid+'.bin'),cases[i][0]);await writeFile(path.join(directory,cid+'.car'),'car');
  verifiedObjects.push({cid,sha256:digest(cases[i][0]),carSha256:digest('car')});
 }
 const server=await createBootstrapGateway({directory,manifest:{verifiedObjects}});await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>{server.closeAllConnections();server.close();});
 const base='http://127.0.0.1:'+server.address().port;
 for(const [body,type,cid] of cases){
  for(const suffix of ['', '?filename=i.svg', '?filename=x.html']){
   const r=await fetch(base+'/ipfs/'+cid+suffix);assert.equal(r.headers.get('content-type'),type);assert.deepEqual(Buffer.from(await r.arrayBuffer()),body);
   assert.equal(r.headers.get('content-security-policy'),"default-src 'none'; sandbox");assert.equal(r.headers.get('x-content-type-options'),'nosniff');
  }
  const head=await fetch(base+'/ipfs/'+cid,{method:'HEAD'});assert.equal(head.headers.get('content-type'),type);assert.equal((await head.text()).length,0);
  const car=await fetch(base+'/ipfs/'+cid+'?filename=i.svg&format=car');assert.equal(car.headers.get('content-type'),'application/vnd.ipld.car');assert.equal(await car.text(),'car');
 }
});
