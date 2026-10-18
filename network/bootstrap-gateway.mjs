// Static, CID-addressed bootstrap replicas. These hold public artifacts only;
// clients still verify CAR blocks. No upload/control/secret endpoints.
import http from 'node:http';
import {createReadStream} from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const CID=/^b[a-z2-7]{10,100}$/;
export async function createBootstrapGateway({directory,manifest}){
 const entries=new Map();
 if(!Array.isArray(manifest.verifiedObjects)||manifest.verifiedObjects.length>4096)throw Error('verified bootstrap manifest required');
 for(const entry of manifest.verifiedObjects){
  if(!CID.test(entry.cid)||entries.has(entry.cid))throw Error('invalid or duplicate bootstrap CID');
  const files={};
  for(const [extension,expected] of [['bin',entry.sha256],['car',entry.carSha256]]){
   if(!/^[0-9a-f]{64}$/.test(expected||''))throw Error('bootstrap digest required');
   const file=path.join(directory,entry.cid+'.'+extension),stat=await fs.stat(file),hash=createHash('sha256');
   if(!stat.isFile()||stat.size>256*1024*1024)throw Error('invalid bootstrap file');
   for await(const chunk of createReadStream(file))hash.update(chunk);
   if(hash.digest('hex')!==expected)throw Error('bootstrap file digest mismatch');
   files[extension]={file,size:stat.size};
  }
  entries.set(entry.cid,files);
 }
 let active=0;
 const server=http.createServer({requestTimeout:30000,headersTimeout:10000,maxHeaderSize:8192},(req,res)=>{
  if(!['GET','HEAD'].includes(req.method)){req.resume();res.writeHead(405);res.end();return;}
  if(active>=64){res.writeHead(503);res.end();return;}
  let u;try{u=new URL(req.url,'http://bootstrap.local');}catch{res.writeHead(400);res.end();return;}
  const m=u.pathname.match(/^\/ipfs\/(b[a-z2-7]{10,100})$/),files=m&&entries.get(m[1]);
  if(!files){res.writeHead(404);res.end();return;}
  const car=u.searchParams.get('format')==='car'||String(req.headers.accept||'').includes('application/vnd.ipld.car');
  const f=files[car?'car':'bin'];
  res.writeHead(200,{'content-type':car?'application/vnd.ipld.car':'application/octet-stream','content-length':f.size,'cache-control':'public, max-age=31536000, immutable','access-control-allow-origin':'*','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'; sandbox"});
  if(req.method==='HEAD'){res.end();return;}
  active++;const stream=createReadStream(f.file);let settled=false;
  const done=()=>{if(!settled){settled=true;active--;stream.destroy();}};
  res.once('close',done);res.once('finish',done);stream.once('error',()=>res.destroy());stream.pipe(res);
 });
 return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const config=JSON.parse(await fs.readFile(process.argv[2],'utf8'));
 const manifest=JSON.parse(await fs.readFile(config.manifest,'utf8'));
 const server=await createBootstrapGateway({...config,manifest});
 server.listen(config.port||8189,config.bind||'127.0.0.1',()=>console.log('verified bootstrap replica ready'));
 for(const sig of ['SIGTERM','SIGINT'])process.on(sig,()=>server.close(()=>process.exit(0)));
}
