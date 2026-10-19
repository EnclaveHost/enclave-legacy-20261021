import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {prepareNativeProfile,parseMeasurement} from '../scripts/network/native-profile.mjs';
import {preparePackage} from '../sdk/bootstrap/package.mjs';
import {runtimeId} from '../isolation/contract/runtime.mjs';

const runtime={name:'wasmtime',version:'test',execution:'jit',hostIsa:'x86_64',targetIsa:'x86_64',cpuFeatures:'baseline',wx:'enforced',cache:'none'};
const rid=runtimeId(runtime).toString('hex'),releaseId='02'.repeat(32),measurement='03'.repeat(48),bytes=Buffer.from('unit-test bundle transport; the image tool is mocked in these tests');
const appId=createHash('sha256').update(bytes).digest('hex');
const output=()=>`release ${releaseId}\napp_id ${appId}\nruntime_id ${rid}\nruntime_identity_json ${JSON.stringify(runtime)}\nmeasurement ${measurement}\n`;
test('measurement output cannot substitute a release, app, runtime or inspection result',()=>{
  const want={releaseId,appId,runtimeId:rid};assert.equal(parseMeasurement(output(),want).measurement,measurement);
  for(const text of [output().replace(appId,'ab'.repeat(32)),output().replace(releaseId,'cd'.repeat(32)),output().replace(rid,'ef'.repeat(32)),output()+'measurement '+measurement,'INSPECTION-ONLY '+output(),output().replace(measurement,'short')])assert.throws(()=>parseMeasurement(text,want));
});
for(const scenario of ['valid','wrong bundle','owner changes','runtime document changes'])test('profile reproduction: '+scenario,async t=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'native-profile-test-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const bundleFile=path.join(dir,'bundle');await fs.writeFile(bundleFile,scenario==='wrong bundle'?'bad':bytes);
  const pins={deployments:'0x'+'04'.repeat(20),registry:'0x'+'05'.repeat(20),connectivity:'0x'+'00'.repeat(20),sessionVaultFactory:'0x'+'00'.repeat(20)};
  const row={id:'0x'+'06'.repeat(32),chainId:8453,deployments:pins.deployments,owner:'0x'+'07'.repeat(20),appRef:'catalog://test/1',active:false,blockNumber:'1234'};
  const pkg=preparePackage({version:1,chainId:8453,ledger:row.deployments,deployment:row.id,owner:row.owner,appRef:row.appRef,appId,runtimeId:rid,configText:'{}',secretsMode:'public'});row.configCid=JSON.stringify({guestBootstrap:pkg.intent});
  const profile={version:1,deploymentId:row.id,chainId:8453,hostname:'never-resolve.invalid',stateDir:dir+'/state',authorityPins:pins,rpc:['https://rpc1.invalid','https://rpc2.invalid'],directories:['http://192.0.2.1:8188'],checkers:['0x'+'08'.repeat(20)],linux:{minTcb:{Turin:{snp:5}}},startup:{packageBase64:pkg.bytes.toString('base64')}};
  let reads=0,measures=0;
  const reader={refresh:async()=>[{...row,...(++reads>1&&scenario==='owner changes'?{owner:'0x'+'09'.repeat(20)}:{})}]};
  const measure=async({bundleFile:copy})=>{measures++;assert.deepEqual(await fs.readFile(copy),bytes);return {stdout:scenario==='runtime document changes'?output().replace('"version":"test"','"version":"different"'):output()};};
  const result=prepareNativeProfile(profile,{releaseDir:dir,releaseId,bundleFile,vcpus:1,reader,measure});
  if(scenario==='valid'){
    const r=await result;assert.equal(r.profile.expected,undefined);assert.equal(r.profile.linux.measurement,measurement);assert.deepEqual(r.profile.linux.runtime,runtime);
    assert.equal(r.evidence.admissionVerified,false);assert.equal(r.evidence.active,false);assert.equal(r.evidence.source,'owner-committed-startup');assert.equal(reads,2);
  }else await assert.rejects(result,/AppID|commitment changed|runtimeId mismatch/);
  if(scenario==='wrong bundle')assert.equal(measures,0,'do not build images from substituted bytes');
});
