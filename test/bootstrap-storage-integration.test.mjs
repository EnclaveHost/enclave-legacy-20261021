// Real Rust adapters and independent disk-backed MinIO instances, with verified
// loopback TLS fronts. No production credentials, chain writes or enclave APIs.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import {spawn,execFileSync,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {once} from 'node:events';
import {createHash} from 'node:crypto';
import {directUploadHeaders} from '../sdk/storage/upload-auth.mjs';
import {privateKeyToAccount} from 'viem/accounts';
import {preparePackage,fetchPackage} from '../sdk/bootstrap/package.mjs';
import {publishArtifactReplicas,verifyArtifactReplicas} from '../sdk/storage/artifacts.mjs';
import {publishPackageReplicas,verifyPackageReplicas} from '../sdk/bootstrap/storage.mjs';
const adapter=process.env.S3_ADAPTER_BIN,minio=process.env.MINIO_BIN;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function port(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
async function stop(p){if(!p||p.exitCode!==null||p.signalCode!==null)return;const ended=once(p,'exit');p.kill('SIGTERM');const timer=setTimeout(()=>p.kill('SIGKILL'),3000);try{await ended;}finally{clearTimeout(timer);}}
async function ready(url,p){for(let i=0;i<150;i++){if(p.exitCode!==null)throw Error('test service exited');try{if((await fetch(url,{signal:AbortSignal.timeout(500)})).ok)return;}catch{}await pause(100);}throw Error('test service startup timeout');}
test('packages, multipart WASM and runtime files survive real S3 loss and cold recovery', {skip:!adapter||!minio,timeout:180000},async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'enclave-storage-')),children=[],fronts=[];
 t.after(async()=>{for(const s of fronts){s.closeAllConnections();await new Promise(r=>s.close(r));}await Promise.all(children.map(stop));fs.rmSync(dir,{recursive:true,force:true});});
 const start=(bin,args,env,log)=>{const fd=fs.openSync(path.join(dir,log),'a');const p=spawn(bin,args,{env:{...process.env,...env},stdio:['ignore',fd,fd]});fs.closeSync(fd);children.push(p);return p;};
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',dir+'/key.pem','-out',dir+'/cert.pem','-days','1','-subj','/CN=storage-test','-addext','subjectAltName=IP:127.0.0.1,IP:127.0.0.2,IP:127.0.0.3'],{stdio:'ignore'});
 const cert=fs.readFileSync(dir+'/cert.pem'),key=fs.readFileSync(dir+'/key.pem'),rows=[];
 const credentials={accessKeyId:'localtest',secretAccessKey:'localtest-secret-no-production'};
 for(let i=0;i<3;i++){
  const s3port=await port(),appport=await port(),consoleport=await port(),disk=path.join(dir,'store'+i);fs.mkdirSync(disk);
  const row={s3port,appport,consoleport,disk,fileLimit:i===0?0:64*1024*1024,audience:'0x'+String(i+1).repeat(64)};rows.push(row);
  row.startS3=()=>start(minio,['server','--address',`127.0.0.1:${s3port}`,'--console-address',`127.0.0.1:${consoleport}`,disk],{MINIO_ROOT_USER:credentials.accessKeyId,MINIO_ROOT_PASSWORD:credentials.secretAccessKey,MINIO_BROWSER:'off'},`minio${i}.log`);
  row.s3=row.startS3();await ready(`http://127.0.0.1:${s3port}/minio/health/ready`,row.s3);
  execFileSync('curl',['--fail','--silent','--show-error','--aws-sigv4','aws:amz:us-east-1:s3','--user',credentials.accessKeyId+':'+credentials.secretAccessKey,'-X','PUT',`http://127.0.0.1:${s3port}/artifacts/`]);
  row.startAdapter=()=>start(adapter,[],{ENCLAVE_PORTS:`http:8000=${appport}`,S3IPFS_CONFIG:JSON.stringify({endpoint:`http://127.0.0.1:${s3port}`,region:'us-east-1',bucket:'artifacts',credentials,refreshSecs:3600,upload:{walletAudience:row.audience,maxFileBytes:row.fileLimit,allowOrigins:[]}})},`adapter${i}.log`);
  row.app=row.startAdapter();await ready(`http://127.0.0.1:${appport}/healthz`,row.app);
  const front=https.createServer({key,cert},(req,res)=>{
   const upstream=http.request({host:'127.0.0.1',port:appport,path:req.url,method:req.method,headers:req.headers},r=>{res.writeHead(r.statusCode,r.headers);r.once('aborted',()=>res.destroy());r.on('error',()=>res.destroy());r.pipe(res);});
   upstream.on('error',()=>{if(!res.headersSent)res.writeHead(503);res.end();});req.pipe(upstream);res.on('close',()=>upstream.destroy());
  });
  await new Promise(r=>front.listen(0,`127.0.0.${i+1}`,r));fronts.push(front);row.origin=`https://127.0.0.${i+1}:${front.address().port}`;
 }
 const fetchTLS=(url,opts={})=>new Promise((resolve,reject)=>{
  const req=https.request(url,{ca:cert,method:opts.method||'GET',headers:opts.headers,signal:opts.signal},res=>{
   const parts=[];let size=0;res.on('data',b=>{size+=b.length;if(size>5*1024*1024)res.destroy(Error('test HTTP body limit'));else parts.push(b);});
   res.on('error',reject);res.on('end',()=>resolve(new Response(Buffer.concat(parts),{status:res.statusCode,headers:res.headers})));
  });req.on('error',reject);if(opts.body?.pipe){opts.body.on('error',e=>req.destroy(e));opts.body.pipe(req);}else req.end(opts.body);
 });
 const plan={version:1,minimumCopies:2,replicas:rows.map(r=>({upload:r.origin+'/add-json',gateway:r.origin+'/ipfs',audience:r.audience}))};
 const signer=privateKeyToAccount('0x'+'42'.repeat(32));
 // Generic artifacts are opt-in, require route-bound wallet authorization,
 // and must not weaken WASM validation or browser gateway protections.
 const sample=Buffer.from('this is a kernel fixture, not a WASM component');
 const headersFor=(row,route)=>directUploadHeaders({audience:row.audience,url:row.origin+route,address:signer.address,bytes:sample,signMessage:args=>signer.signMessage(args)});
 const post=async(row,route,headers)=>fetchTLS(row.origin+route,{method:'POST',headers:{'content-length':String(sample.length),...headers},body:sample});
 assert.equal((await post(rows[0],'/add-file',await headersFor(rows[0],'/add-file'))).status,503);
 await stop(rows[0].app);rows[0].fileLimit=64*1024*1024;rows[0].app=rows[0].startAdapter();await ready(`http://127.0.0.1:${rows[0].appport}/healthz`,rows[0].app);
 assert.equal((await post(rows[0],'/add-file',{})).status,401);
 assert.equal((await post(rows[0],'/add-file',await headersFor(rows[0],'/add-json'))).status,403);
 assert.equal((await post(rows[0],'/add-wasm',await headersFor(rows[0],'/add-wasm'))).status,415);
 // Oversized declared bodies are refused before a byte has to be sent.
 const oversized=await new Promise((resolve,reject)=>{
  const req=http.request(`http://127.0.0.1:${rows[0].appport}/add-file`,{method:'POST',headers:{'content-length':String(rows[0].fileLimit+1)},signal:AbortSignal.timeout(3000)},res=>{res.resume();resolve(res.statusCode);req.destroy();});
  req.on('error',reject);req.flushHeaders();
 });assert.equal(oversized,413);
 const runtime=process.env.RUNTIME_ARTIFACT_FILE?fs.readFileSync(process.env.RUNTIME_ARTIFACT_FILE):Buffer.alloc(17*1024*1024+7,0xa7);
 const runtimeHash=createHash('sha256').update(runtime).digest('hex');
 if(process.env.RUNTIME_ARTIFACT_SHA256)assert.equal(runtimeHash,process.env.RUNTIME_ARTIFACT_SHA256);
 const manifest=JSON.parse(JSON.parse(fs.readFileSync(new URL('../isolation/m2/bootstrap/testdata/vectors.json',import.meta.url))).manifest);
 const pkg=preparePackage({...manifest,configText:JSON.stringify({independentStorageTest:Date.now()})});
 const opts={fetchImpl:fetchTLS,timeoutMs:15000};
 const initial=await publishPackageReplicas(pkg.bytes,{},plan,signer,opts);assert.equal(initial.verifiedCopies,3);
 const vi=n=>{const out=[];do{out.push((n%128)+(n>=128?128:0));n=Math.floor(n/128);}while(n);return Buffer.from(out);};
 // A valid component with a large custom section crosses both multipart
 // (8 MiB) and balanced UnixFS (174 x 256 KiB) boundaries.
 const payload=Buffer.alloc(50*1024*1024+13,0x5a);
 const wasm=Buffer.concat([Buffer.from([0,97,115,109,13,0,1,0,0]),vi(payload.length+1),Buffer.from([0]),payload]);
 const artifactOpts={...opts,timeoutMs:90000};
 const firstRuntime=await publishArtifactReplicas(runtime,'file',plan,signer,artifactOpts);assert.equal(firstRuntime.verifiedCopies,3);
 const gatewayResponse=await fetchTLS(rows[0].origin+'/ipfs/'+firstRuntime.cid,{headers:{range:'bytes=0-31'}});assert.match(gatewayResponse.headers.get('content-security-policy'),/(?:^|;\s*)sandbox(?:;|$)/);assert.equal(gatewayResponse.headers.get('x-content-type-options'),'nosniff');
 const firstArtifact=await publishArtifactReplicas(wasm,'wasm',plan,signer,artifactOpts);assert.equal(firstArtifact.verifiedCopies,3);

 // Stop only the first S3 backend, leaving its adapter reachable. The other
 // copies cannot use its credentials, metadata, cache or object store.
 await stop(rows[0].s3);
 assert.equal((await fetchTLS(rows[0].origin+'/healthz')).status,200);
 const next=preparePackage({...manifest,configText:JSON.stringify({secondPublication:true})});
 const degraded=await publishPackageReplicas(next.bytes,{},plan,signer,opts);assert.equal(degraded.verifiedCopies,2);
 const nextWasm=Buffer.from(wasm);nextWasm[nextWasm.length-1]^=1;
 const degradedArtifact=await publishArtifactReplicas(nextWasm,'wasm',plan,signer,artifactOpts);
 assert.equal(degradedArtifact.verifiedCopies,2);assert.notEqual(degradedArtifact.cid,firstArtifact.cid);
 const nextRuntime=Buffer.alloc(10*1024*1024+3,0xb8);
 const degradedRuntime=await publishArtifactReplicas(nextRuntime,'file',plan,signer,artifactOpts);assert.equal(degradedRuntime.verifiedCopies,2);assert.notEqual(degradedRuntime.cid,firstRuntime.cid);

 // Clear every surviving process's memory by restarting its S3 and adapter.
 for(const row of rows.slice(1)){
  await stop(row.app);await stop(row.s3);row.s3=row.startS3();await ready(`http://127.0.0.1:${row.s3port}/minio/health/ready`,row.s3);
  row.app=row.startAdapter();await ready(`http://127.0.0.1:${row.appport}/healthz`,row.app);
 }
 let recovered;
 for(let i=0;i<60;i++){
  try{recovered=await verifyPackageReplicas(next.bytes,{},plan,opts);break;}catch{await pause(100);}
 }
 assert.equal(recovered?.verifiedCopies,2);
 for(const artifact of [wasm,nextWasm,runtime,nextRuntime])assert.equal((await verifyArtifactReplicas(artifact,plan,artifactOpts)).verifiedCopies,2);
 const repo=fileURLToPath(new URL('..',import.meta.url)),coldWasm=dir+'/cold.wasm';
 const fetched=await promisify(execFile)('python3',[repo+'/isolation/m4/guestd/fetch-cid.py',repo,degradedArtifact.cid,coldWasm,String(nextWasm.length),JSON.stringify(rows.map(r=>r.origin))],{env:{...process.env,SSL_CERT_FILE:dir+'/cert.pem',NO_PROXY:'127.0.0.1,127.0.0.2,127.0.0.3'},timeout:45000});
 assert.match(fetched.stdout,/^ok /);assert.deepEqual(fs.readFileSync(coldWasm),nextWasm);
 const coldKernel=dir+'/cold-kernel';
 const kernelFetch=await promisify(execFile)('python3',[repo+'/isolation/m4/guestd/fetch-cid.py',repo,firstRuntime.cid,coldKernel,String(runtime.length),JSON.stringify(rows.map(r=>r.origin))],{env:{...process.env,SSL_CERT_FILE:dir+'/cert.pem',NO_PROXY:'127.0.0.1,127.0.0.2,127.0.0.3'},timeout:45000});
 assert.match(kernelFetch.stdout,/^ok /);assert.deepEqual(fs.readFileSync(coldKernel),runtime);
 t.diagnostic(JSON.stringify({runtime:{bytes:runtime.length,sha256:runtimeHash,cid:firstRuntime.cid,source:process.env.RUNTIME_ARTIFACT_FILE?'operator-pinned-kernel':'synthetic-fixture'},initialCopies:3,degradedCopies:2,coldKernelRecovered:true,independentOperatorsVerified:false}));


 const cold=await fetchPackage({version:1,sha256:next.sha256},{},{gateways:plan.replicas.map(r=>r.gateway),fetchImpl:fetchTLS,timeoutMs:3000});assert.deepEqual(cold.bytes,next.bytes);
 // Every remaining replica independently recovers the exact old and new CID.
 for(const row of rows.slice(1))for(const p of [pkg,next])assert.deepEqual(Buffer.from(await (await fetchTLS(row.origin+'/ipfs/'+p.cid)).arrayBuffer()),p.bytes);
 await stop(rows[1].app);await stop(rows[1].s3);
 await assert.rejects(()=>verifyPackageReplicas(next.bytes,{},plan,opts),e=>e.report.verifiedCopies===1);
});
