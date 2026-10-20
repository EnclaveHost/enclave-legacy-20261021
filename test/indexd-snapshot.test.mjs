import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const run=promisify(execFile),script=new URL('../scripts/storage/snapshot-indexd.sh',import.meta.url).pathname;
async function rig(t){
 const dir=await mkdtemp(tmpdir()+'/indexd-snapshot-');t.after(()=>rm(dir,{recursive:true,force:true}));await mkdir(dir+'/bin');
 for(const [name,body] of Object.entries({
  id:'echo 0',
  systemctl:'echo "$*" >> "$SNAPSHOT_TEST_LOG"\ncase "$*" in "show indexd --property=MainPID --value") echo "${SNAPSHOT_TEST_PID:-0}";; esac',
  pg_dump:'exit 0',
  runuser:'if [ "$4" = pg_dump ]; then [ "$SNAPSHOT_TEST_FAIL" != 1 ] || exit 42; echo fixture-dump; else echo \'{"objects":2,"slabs":3,"contracts":4,"accounts":1}\'; fi'
 }))await writeFile(dir+'/bin/'+name,'#!/bin/sh\n'+body+'\n',{mode:0o755});
 for(const f of ['consensus.db','indexd.yml','indexd'])await writeFile(dir+'/'+f,'fixture-'+f);
 const env={...process.env,PATH:dir+'/bin:'+process.env.PATH,SNAPSHOT_INDEXD_CONFIG:dir+'/indexd.yml',SNAPSHOT_INDEXD_DATA:dir,SNAPSHOT_INDEXD_BINARY:dir+'/indexd',SNAPSHOT_TEST_LOG:dir+'/service.log'};
 return {dir,env};
}
test('snapshot stops the writer, captures both databases, restarts before hashing, and preserves source files',async t=>{
 const {dir,env}=await rig(t);const {stdout}=await run('bash',[script,dir+'/snapshot'],{env});const report=JSON.parse(stdout);
 assert.equal(report.quiesced,true);assert.equal(report.sourceResumed,true);assert.equal(report.counts.objects,2);
 assert.equal(Object.keys(report.files).length,5);assert.equal(await readFile(dir+'/snapshot/indexd.pgdump','utf8'),'fixture-dump\n');assert.equal(await readFile(dir+'/snapshot/consensus.db','utf8'),'fixture-consensus.db');
 assert.equal(await readFile(dir+'/consensus.db','utf8'),'fixture-consensus.db');
 assert.equal((await stat(dir+'/snapshot')).mode&0o777,0o700);
 const calls=(await readFile(dir+'/service.log','utf8')).trim().split('\n');
 assert.deepEqual(calls,['is-active --quiet indexd','stop indexd','show indexd --property=MainPID --value','start indexd','is-active --quiet indexd']);
});
test('a failed database dump restarts the source and never reports a successful snapshot',async t=>{
 const {dir,env}=await rig(t);await assert.rejects(run('bash',[script,dir+'/snapshot'],{env:{...env,SNAPSHOT_TEST_FAIL:'1'}}),e=>e.code===42&&e.stdout==='');
 assert.match(await readFile(dir+'/service.log','utf8'),/start indexd\n$/);
 await assert.rejects(readFile(dir+'/snapshot/manifest.json'),{code:'ENOENT'});
});
test('an existing output is refused before the source service is touched',async t=>{
 const {dir,env}=await rig(t);await assert.rejects(run('bash',[script,dir],{env}),e=>e.code===2);
 await assert.rejects(readFile(dir+'/service.log'),{code:'ENOENT'});
});
test('the optional GeoIP database is included so offline startup needs no download',async t=>{
 const {dir,env}=await rig(t);await writeFile(dir+'/GeoLite2-City.mmdb','fixture-geoip');
 const {stdout}=await run('bash',[script,dir+'/snapshot'],{env});const report=JSON.parse(stdout);
 assert.equal(report.files['GeoLite2-City.mmdb'].bytes,13);
 assert.equal(await readFile(dir+'/snapshot/GeoLite2-City.mmdb','utf8'),'fixture-geoip');
});
test('a writer that remains alive prevents any database capture and resumes service',async t=>{
 const {dir,env}=await rig(t);await assert.rejects(run('bash',[script,dir+'/snapshot'],{env:{...env,SNAPSHOT_TEST_PID:'123'}}));
 await assert.rejects(readFile(dir+'/snapshot/indexd.pgdump'),{code:'ENOENT'});
 assert.match(await readFile(dir+'/service.log','utf8'),/start indexd\n$/);
});
