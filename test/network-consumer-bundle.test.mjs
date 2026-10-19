import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
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
 await assert.rejects(run(process.execPath,[path.join(dir,'dns.mjs')],{cwd:dir,env:{...process.env,NODE_PATH:'',DNS_READ_ONLY:'1',ROUTE_MAP_URL:'',BOX_ZONE:''}}),e=>e.code===1&&e.stderr.includes('requires explicit ROUTE_MAP_URL')&&!e.stderr.includes('Dynamic require'));
 const key=path.join(dir,'test-only.key');await writeFile(key,'0x'+'01'.repeat(32),{mode:0o600});
 const {stdout}=await run(process.execPath,[path.join(dir,'checker.mjs'),'--key-file',key,'--print-address'],{cwd:dir,env:{...process.env,NODE_PATH:''}});
 assert.equal(stdout.trim(),'0x1a642f0e3c3af545e7acbd38b07251b3990914f1');
 const records=path.join(dir,'records.json'),directories=path.join(dir,'directories.json'),out=path.join(dir,'verdicts.json');
 await writeFile(records,'[]');await writeFile(directories,'["http://127.0.0.1:8188"]');
 // Empty fixtures exercise native file arguments without any probe, RPC or publication.
 await run(process.execPath,[path.join(dir,'checker.mjs'),'--key-file',key,'--records',records,'--directories-file',directories,'--out',out],{cwd:dir});
 await assert.rejects(run(process.execPath,[path.join(dir,'checker.mjs'),'--key-file',key,'--directories-file',directories,'--directories','[]']),e=>e.stderr.includes('choose directories or directories-file'));
 await writeFile(directories,'null');
 await assert.rejects(run(process.execPath,[path.join(dir,'checker.mjs'),'--key-file',key,'--directories-file',directories,'--records',records]),e=>e.stderr.includes('1..8 directory origins required'));
});
