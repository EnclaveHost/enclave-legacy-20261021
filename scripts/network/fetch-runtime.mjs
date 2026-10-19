#!/usr/bin/env node
// Install a caller-pinned public CPU release into a NEW directory. This neither
// registers a host nor authorizes a deployment; guest and client checks still apply.
import fs from 'node:fs/promises';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {RawArtifacts,fetchRelease,verifiedReleaseManifest} from '../../sdk/storage/raw-artifacts.mjs';

// The trusted local tree: its firmware pin list and the release verifier every
// pinned build and launch runs (isolation/m4/pinned-domain-env.sh).
const ISOLATION=fileURLToPath(new URL('../../isolation/',import.meta.url));

export async function fetchRuntime({releaseId,destination,gateways,fetchImpl=fetch,isolation=ISOLATION}){
  const artifacts=new RawArtifacts({gateways,fetchImpl});
  destination=path.resolve(destination);
  // fetchRelease creates the directory exclusively: an existing path is refused
  // before any download and is never removed here.
  const release=await fetchRelease(artifacts,releaseId,destination);
  try{
    const manifest=verifiedReleaseManifest(await fs.readFile(path.join(destination,'release.json')),releaseId);
    const pins=await fs.readFile(path.join(isolation,'m4/verifying-firmware.txt'),'utf8');
    if(!new RegExp('^'+manifest.files['firmware.fd'].sha256+'\\s','m').test(pins))throw Error('release firmware is not pinned as verifying');
    await promisify(execFile)('python3',[path.join(isolation,'m4/release-manifest.py'),'verify',destination,'--expect',releaseId],{timeout:120000})
      .catch(e=>{throw Error('installed release does not verify: '+String(e.stderr||e.message).trim());});
    return {directory:destination,...release,receipts:artifacts.receipts};
  }catch(e){await fs.rm(destination,{recursive:true,force:true});throw e;}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{
    const args=process.argv.slice(2),o={};
    for(let i=0;i<args.length;i+=2){
      if(!['--release-id','--out','--artifact-gateways'].includes(args[i])||o[args[i]]!==undefined||!args[i+1])throw Error('usage: fetch-runtime.mjs --release-id HEX --out NEW-DIR --artifact-gateways HTTP-IP/ipfs,…');
      o[args[i]]=args[i+1];
    }
    if(Object.keys(o).length!==3)throw Error('release-id, out and artifact-gateways are required');
    console.log(JSON.stringify(await fetchRuntime({releaseId:o['--release-id'],destination:o['--out'],gateways:o['--artifact-gateways'].split(',')})));
  }catch(e){console.error(e.message);process.exitCode=1;}
}
