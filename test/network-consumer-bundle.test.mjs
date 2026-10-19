import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const run=promisify(execFile);
test('standalone network bundles load outside the repository without npm dependencies',async t=>{
 const dir=await mkdtemp(path.join(tmpdir(),'enclave-network-bundles-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 await run(process.execPath,[new URL('../scripts/network/build-consumers.mjs',import.meta.url).pathname,dir]);
 for(const [name,exported] of [['privacy-agent.mjs','PrivacyAgent']]){
  const url=pathToFileURL(path.join(dir,name)).href;
  const {stdout}=await run(process.execPath,['--input-type=module','-e',`const m=await import(${JSON.stringify(url)}); ${exported?`if(typeof m.${exported}!=="function")throw Error("missing export");`:''} console.log("imported");`],{cwd:dir,env:{...process.env,NODE_PATH:''}});
  assert.equal(stdout.trim(),'imported');
 }
 // The provider is an executable entry point, so stop at its first config read.
 // A missing config must be the failure, rather than a dependency/import error.
 const absent=path.join(dir,'deliberately-absent.json');
 await assert.rejects(run(process.execPath,[path.join(dir,'provider.mjs'),absent],{cwd:dir,env:{...process.env,NODE_PATH:''}}),e=>e.code===1&&e.stderr.includes('ENOENT')&&e.stderr.includes(absent)&&!e.stderr.includes('Dynamic require'));
});
