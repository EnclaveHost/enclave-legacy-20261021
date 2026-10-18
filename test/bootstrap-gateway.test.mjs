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
