#!/usr/bin/env node
// Build a client profile from a caller-pinned runtime release and owner-committed
// app bundle. No host's predicted measurement or app expectation is an input.
import fs from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {LeaseReader} from '../../network/lease-reader.mjs';
import {validateNetworkAuthorities} from '../../network/network-authorities.mjs';
import {bootstrapIntent,fetchPackage,verifyPackage} from '../../sdk/bootstrap/package.mjs';
import {inlineStartupBytes,startupExpectation} from '../../network/startup-expectation.mjs';
import {NativeClient} from '../../network/native-client.mjs';
import {RawArtifacts,fetchRelease} from '../../sdk/storage/raw-artifacts.mjs';

const exec=promisify(execFile),script=fileURLToPath(new URL('../../isolation/m4/expected-measurement.sh',import.meta.url));
const scope=row=>({chainId:row.chainId,ledger:row.deployments,deployment:row.id,owner:row.owner,appRef:row.appRef});
export function parseMeasurement(text,{releaseId,appId,runtimeId}){
  const fields={};
  for(const line of text.trim().split('\n')){
    const i=line.indexOf(' '),key=line.slice(0,i),value=line.slice(i+1);
    if(i<1||Object.hasOwn(fields,key)||!['release','app_id','runtime_id','runtime_identity_json','measurement'].includes(key))throw Error('unexpected measurement output');
    fields[key]=value;
  }
  if(fields.release!==releaseId||fields.app_id!==appId||fields.runtime_id!==runtimeId||!/^[0-9a-f]{96}$/.test(fields.measurement||''))throw Error('reproduced image does not match committed app/runtime and pinned release');
  return {measurement:fields.measurement,release:releaseId,runtime:JSON.parse(fields.runtime_identity_json)};
}

export async function prepareNativeProfile(input,{releaseDir,releaseId,bundleFile,artifactGateways,vcpus,reader,fetchImpl=fetch,measure}={}){
  const profile=structuredClone(input);
  if(profile.expected!==undefined||!profile.startup||!profile.linux||!/^0x[0-9a-f]{64}$/.test(profile.deploymentId||'')||
    !/^[0-9a-f]{64}$/.test(releaseId||'')||!Number.isSafeInteger(vcpus)||vcpus<1||vcpus>256||
    (artifactGateways?(releaseDir!==undefined||bundleFile!==undefined):(!releaseDir||!bundleFile)))throw Error('owner startup profile, release pin, vCPU count and exactly one local/remote artifact source required');
  new NativeClient(profile); // validate literal discovery origins before any I/O
  const artifacts=artifactGateways?new RawArtifacts({gateways:artifactGateways,fetchImpl}):null;
  const pins=validateNetworkAuthorities(profile.authorityPins);
  reader||=new LeaseReader({rpc:profile.rpc,chainId:profile.chainId,addressBook:'0x'+'0'.repeat(40),authorityPins:pins});
  const [row]=await reader.refresh([profile.deploymentId]);
  if(!row||row.id!==profile.deploymentId||row.chainId!==(profile.chainId??8453)||row.deployments.toLowerCase()!==pins.deployments)throw Error('deployment scope not available');
  const intent=bootstrapIntent(row.configCid);if(!intent)throw Error('owner startup commitment required');
  const inline=inlineStartupBytes(profile.startup.packageBase64);
  const pkg=inline?verifyPackage(inline,intent,scope(row)):await fetchPackage(intent,scope(row),{gateways:profile.startup.gateways,fetchImpl,allowHttpIPs:true});
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'enclave-native-profile-'));
  try{
    const snapshot=path.join(dir,'app.bundle');
    let artifactEvidence={source:'local'};
    if(artifacts){
      releaseDir=path.join(dir,'release');
      const release=await fetchRelease(artifacts,releaseId,releaseDir);
      await artifacts.get(pkg.manifest.appId,snapshot);
      artifactEvidence={source:'public-digest-replicas',emptyInputCache:true,...release,receipts:artifacts.receipts};
    }else{
      const stat=await fs.stat(bundleFile);if(!stat.isFile()||stat.size>512*1024*1024)throw Error('bounded regular app bundle required');
      await fs.copyFile(bundleFile,snapshot);
    }
    const hash=createHash('sha256');let size=0;
    for await(const b of createReadStream(snapshot)){size+=b.length;if(size>512*1024*1024)throw Error('app bundle grew beyond limit');hash.update(b);}
    if(hash.digest('hex')!==pkg.manifest.appId)throw Error('bundle is not the owner-committed AppID');
    // The existing tool snapshots and verifies every release file against the
    // explicit pin, validates the bundle, and assembles the measured image.
    const result=measure?await measure({releaseDir,releaseId,bundleFile:snapshot,vcpus}):await exec('sh',[script,'--pin',releaseId,path.resolve(releaseDir),snapshot,String(vcpus)],{timeout:240000,maxBuffer:1024*1024,env:{...process.env,EM_TEST_AFTER_SNAPSHOT:'',BUNDLETOOL:''}});
    const measured=parseMeasurement(result.stdout,{releaseId,appId:pkg.manifest.appId,runtimeId:pkg.manifest.runtimeId});
    const derived=await startupExpectation(row,{runtime:measured.runtime,bytes:pkg.bytes});
    profile.linux={...profile.linux,...measured};
    // A second independent snapshot must still authorize exactly this package.
    const [current]=await reader.refresh([profile.deploymentId]);
    if(!current||current.configCid!==row.configCid||JSON.stringify(scope(current))!==JSON.stringify(scope(row)))throw Error('owner commitment changed during image reproduction');
    new NativeClient(profile); // fail before emitting an unusable/ambiguous profile
    return {profile,evidence:{...derived.provenance,appId:pkg.manifest.appId,runtimeId:pkg.manifest.runtimeId,release:releaseId,measurement:measured.measurement,vcpus,blockNumber:current.blockNumber,active:current.active,admissionVerified:false,artifacts:artifactEvidence}};
  }finally{await fs.rm(dir,{recursive:true,force:true});}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{
    const args=process.argv.slice(2),opts={};
    for(let i=0;i<args.length;i+=2){if(!['--profile','--release','--release-id','--bundle','--artifact-gateways','--vcpus','--out'].includes(args[i])||opts[args[i]]!==undefined||!args[i+1])throw Error('usage: native-profile.mjs --profile BASE.json --release-id HEX --vcpus N --out NEW.json (--release DIR --bundle FILE | --artifact-gateways HTTP-IP/ipfs,…)');opts[args[i]]=args[i+1];}
    if(!['--profile','--release-id','--vcpus','--out'].every(k=>opts[k]))throw Error('profile, release-id, vcpus and out are required');
    const input=JSON.parse(await fs.readFile(opts['--profile'],'utf8'));
    const result=await prepareNativeProfile(input,{releaseDir:opts['--release'],releaseId:opts['--release-id'],bundleFile:opts['--bundle'],artifactGateways:opts['--artifact-gateways']?.split(','),vcpus:Number(opts['--vcpus'])});
    await fs.writeFile(opts['--out'],JSON.stringify(result.profile,null,2)+'\n',{flag:'wx',mode:0o600});
    console.log(JSON.stringify({profile:path.resolve(opts['--out']),...result.evidence}));
  }catch(e){console.error(e.message);process.exitCode=1;}
}
