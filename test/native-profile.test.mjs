import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {prepareNativeProfile,parseMeasurement} from '../scripts/network/native-profile.mjs';
import {preparePackage,packageCID} from '../sdk/bootstrap/package.mjs';
import {runtimeId} from '../isolation/contract/runtime.mjs';

const runtime={name:'wasmtime',version:'test',execution:'jit',hostIsa:'x86_64',targetIsa:'x86_64',cpuFeatures:'baseline',wx:'enforced',cache:'none'};
const rid=runtimeId(runtime).toString('hex'),releaseId='02'.repeat(32),measurement='03'.repeat(48),bytes=Buffer.from('unit-test bundle transport; the image tool is mocked in these tests');
const appId=createHash('sha256').update(bytes).digest('hex');
const output=()=>`release ${releaseId}\napp_id ${appId}\nruntime_id ${rid}\nruntime_identity_json ${JSON.stringify(runtime)}\nmeasurement ${measurement}\n`;
test('measurement output cannot substitute a release, app, runtime or inspection result',()=>{
  const want={releaseId,appId,runtimeId:rid};assert.equal(parseMeasurement(output(),want).measurement,measurement);
  for(const text of [output().replace(appId,'ab'.repeat(32)),output().replace(releaseId,'cd'.repeat(32)),output().replace(rid,'ef'.repeat(32)),output()+'measurement '+measurement,'INSPECTION-ONLY '+output(),output().replace(measurement,'short')])assert.throws(()=>parseMeasurement(text,want));
});
for(const scenario of ['valid','wrong bundle','owner changes','runtime document changes','remote','remote wrong file','remote wrong bundle'])test('profile reproduction: '+scenario,async t=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'native-profile-test-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const bundleFile=path.join(dir,'bundle');await fs.writeFile(bundleFile,scenario==='wrong bundle'?'bad':bytes);
  const pins={deployments:'0x'+'04'.repeat(20),registry:'0x'+'05'.repeat(20),connectivity:'0x'+'00'.repeat(20),sessionVaultFactory:'0x'+'00'.repeat(20)};
  const row={id:'0x'+'06'.repeat(32),chainId:8453,deployments:pins.deployments,owner:'0x'+'07'.repeat(20),appRef:'catalog://test/1',active:false,blockNumber:'1234'};
  const pkg=preparePackage({version:1,chainId:8453,ledger:row.deployments,deployment:row.id,owner:row.owner,appRef:row.appRef,appId,runtimeId:rid,configText:'{}',secretsMode:'public'});row.configCid=JSON.stringify({guestBootstrap:pkg.intent});
  const profile={version:1,deploymentId:row.id,chainId:8453,hostname:'never-resolve.invalid',stateDir:dir+'/state',authorityPins:pins,rpc:['https://rpc1.invalid','https://rpc2.invalid'],directories:['http://192.0.2.1:8188'],checkers:['0x'+'08'.repeat(20)],linux:{minTcb:{Turin:{snp:5}}},startup:{packageBase64:pkg.bytes.toString('base64')}};
  let reads=0,measures=0;
  const reader={refresh:async()=>[{...row,...(++reads>1&&scenario==='owner changes'?{owner:'0x'+'09'.repeat(20)}:{})}]};
  const remote=scenario.startsWith('remote'),objects=new Map();let pin=releaseId;
  if(remote){
    const files={};for(const name of ['kernel','firmware.fd','template/init','template/front','template/rt/wasmtime','template/rt/runtime.json']){
      const b=Buffer.from(name),sha256=createHash('sha256').update(b).digest('hex');files[name]={sha256,size:b.length};objects.set(packageCID(sha256),scenario==='remote wrong file'&&name==='kernel'?Buffer.from('bad'):b);
    }
    const manifest={format:'enclave-m4a-domain-release/1',cmdline:'test',dirs:['template','template/rt'],files,measure:{mode:'snp',vcpuFamily:26,vcpuModel:2,vcpuStepping:1,vmmType:'QEMU'}};
    const m=Buffer.from(JSON.stringify(manifest,(_k,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v));pin=createHash('sha256').update(m).digest('hex');objects.set(packageCID(pin),m);objects.set(packageCID(appId),scenario==='remote wrong bundle'?Buffer.from('bad'):bytes);
  }
  const measure=async({bundleFile:copy,releaseDir:release})=>{measures++;assert.deepEqual(await fs.readFile(copy),bytes);
    if(remote)assert.equal((await fs.readFile(path.join(release,'kernel'))).toString(),'kernel');
    return {stdout:(scenario==='runtime document changes'?output().replace('"version":"test"','"version":"different"'):output()).replace(releaseId,pin)};
  };
  const result=prepareNativeProfile(profile,{...(remote?{artifactGateways:['http://192.0.2.1/ipfs'],fetchImpl:async url=>new Response(objects.get(url.split('/').at(-1)))}:{releaseDir:dir,bundleFile}),releaseId:pin,vcpus:1,reader,measure});
  if(scenario==='valid'||scenario==='remote'){
    const r=await result;assert.equal(r.profile.expected,undefined);assert.equal(r.profile.linux.measurement,measurement);assert.deepEqual(r.profile.linux.runtime,runtime);
    assert.equal(r.evidence.admissionVerified,false);assert.equal(r.evidence.active,false);assert.equal(r.evidence.source,'owner-committed-startup');assert.equal(reads,2);
    if(remote){assert.equal(r.evidence.artifacts.emptyInputCache,true);assert.equal(r.evidence.artifacts.receipts.length,8);}
  }else await assert.rejects(result,/AppID|commitment changed|runtimeId mismatch|no artifact source/);
  if(scenario==='wrong bundle'||scenario.startsWith('remote wrong'))assert.equal(measures,0,'do not build images from substituted bytes');
});
