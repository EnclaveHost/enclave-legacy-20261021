import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {preparePackage,MAX_PACKAGE_BYTES} from '../sdk/bootstrap/package.mjs';
import {startupExpectation,inlineStartupBytes} from '../network/startup-expectation.mjs';
import {runtimeId} from '../isolation/contract/runtime.mjs';

const runtime={name:'wasmtime',version:'test',execution:'jit',hostIsa:'x86_64',targetIsa:'x86_64',cpuFeatures:'baseline',wx:'enforced',cache:'none'};
const lease={id:'0x'+'01'.repeat(32),owner:'0x'+'02'.repeat(20),chainId:8453,deployments:'0x'+'03'.repeat(20),appRef:'catalog://example/1'};
const manifest={version:1,deployment:lease.id,owner:lease.owner,chainId:lease.chainId,ledger:lease.deployments,appRef:lease.appRef,appId:'04'.repeat(32),runtimeId:runtimeId(runtime).toString('hex'),configText:'{"public":true}',secretsMode:'public'};
const pkg=preparePackage(manifest),row={...lease,configCid:JSON.stringify({guestBootstrap:pkg.intent})};

test('derives app identity from owner commitment and independently selected runtime',async()=>{
  const r=await startupExpectation(row,{runtime,bytes:pkg.bytes});
  assert.equal(r.expected.appSha256,manifest.appId);assert.equal(r.expected.configCid,row.configCid);assert.equal(r.provenance.owner,row.owner);assert.equal(r.provenance.cid,pkg.cid);
  for(const mutation of [{owner:'0x'+'05'.repeat(20)},{id:'0x'+'06'.repeat(32)},{appRef:'changed'},{deployments:'0x'+'07'.repeat(20)},{chainId:1}])
    await assert.rejects(startupExpectation({...row,...mutation},{runtime,bytes:pkg.bytes}),/mismatch/);
  await assert.rejects(startupExpectation(row,{runtime:{...runtime,version:'another'},bytes:pkg.bytes}),/runtimeId mismatch/);
  await assert.rejects(startupExpectation(row,{runtime:{},bytes:pkg.bytes}),/runtime policy required/);
});
test('no legacy, malformed commitment, changed bytes or duplicate fields fallback',async()=>{
  for(const configCid of ['',JSON.stringify({config:{}}),'{"guestBootstrap":{},"guestBootstrap":{}}',JSON.stringify({guestBootstrap:pkg.intent,configCid:'legacy'})])
    await assert.rejects(startupExpectation({...row,configCid},{runtime,bytes:pkg.bytes}));
  await assert.rejects(startupExpectation(row,{runtime,bytes:Buffer.concat([pkg.bytes,Buffer.from(' ')])}),/hash mismatch/);
  assert.deepEqual(inlineStartupBytes(pkg.bytes.toString('base64')),pkg.bytes);
  for(const v of ['?',Buffer.alloc(MAX_PACKAGE_BYTES+1).toString('base64'),'Zh==',5])assert.throws(()=>inlineStartupBytes(v));
});
test('real public HTTP replicas: refusal and substitution cannot hide committed bytes',async t=>{
  let requests=0;
  const server=http.createServer((req,res)=>{
    requests++;assert.equal(req.headers.authorization,undefined);assert.equal(req.headers.cookie,undefined);
    if(req.url==='/good/'+pkg.cid)res.end(pkg.bytes);else if(req.url.startsWith('/bad/'))res.end('{}');else{res.writeHead(503);res.end();}
  });await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>{server.closeAllConnections();server.close();});
  const origin='http://127.0.0.1:'+server.address().port;
  const r=await startupExpectation(row,{runtime,gateways:[origin+'/down',origin+'/bad',origin+'/good']});
  assert.equal(r.expected.appSha256,manifest.appId);assert.equal(requests,3);
  await assert.rejects(startupExpectation(row,{runtime,gateways:[origin+'/down',origin+'/bad']}),/no gateway/);
  await assert.rejects(startupExpectation(row,{runtime,gateways:['http://name.invalid/ipfs']}),/HTTPS/);
});
