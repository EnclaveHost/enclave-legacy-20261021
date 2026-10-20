import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fetchRuntime} from '../scripts/network/fetch-runtime.mjs';
import {packageCID} from '../sdk/bootstrap/package.mjs';
const exec=promisify(execFile),repo=new URL('../',import.meta.url);
const hash=b=>createHash('sha256').update(b).digest('hex');

async function fixture(t){
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'pinned-host-'));
  t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const iso=path.join(dir,'isolation'),release=path.join(dir,'release'),bin=path.join(dir,'bin');
  for(const p of ['m1','m2','m4'])await fs.mkdir(path.join(iso,p),{recursive:true});
  await fs.mkdir(path.join(release,'template','rt'),{recursive:true});await fs.mkdir(bin);
  for(const f of ['m4/release-manifest.py','m4/pinned-domain-env.sh','m4/build-app-guest.sh','m2/run-domain.sh'])await fs.copyFile(new URL('isolation/'+f,repo),path.join(iso,f));
  await fs.writeFile(path.join(iso,'m1/domain.env'),'echo "HOST DEFAULTS WERE USED" >&2; exit 99\n');
  for(const f of ['kernel','firmware.fd','template/init','template/front','template/rt/wasmtime','template/rt/runtime.json'])await fs.writeFile(path.join(release,f),'fixture '+f);
  const pins=path.join(iso,'m4/verifying-firmware.txt');
  await fs.writeFile(pins,hash(Buffer.from('fixture firmware.fd'))+' test-only firmware\n');
  const cmdline='console=ttyS0 literal=$(touch SHOULD_NOT_EXIST)';
  await exec('python3',[path.join(iso,'m4/release-manifest.py'),'write',release,'--cmdline',cmdline]);
  const id=hash(await fs.readFile(path.join(release,'release.json')));
  await fs.writeFile(path.join(bin,'systemd-run'),'#!/usr/bin/python3\nimport json,os,sys\nopen(os.environ["CAPTURE"],"w").write(json.dumps(sys.argv[1:]))\n',{mode:0o700});
  await fs.writeFile(path.join(bin,'systemctl'),'#!/bin/sh\nexit 1\n',{mode:0o700});
  const image=path.join(dir,'guest.cpio.gz');await fs.writeFile(image,'image');
  const env={...process.env,PATH:bin+':'+process.env.PATH,DOMAIN_RELEASE_DIR:release,DOMAIN_RELEASE_ID:id,OVMF_OVERRIDE:'',KERNEL_HASHES:'on',GUEST_CID:'131074',HOST_DATA:'',SHIELDED_IMAGE_TEMPLATE:'',CAPTURE:path.join(dir,'argv.json')};
  const launch=(extra={},mode='snp')=>exec('sh',[path.join(iso,'m2/run-domain.sh'),'start',image,mode,'coldtest',dir,'1','1024','100'],{cwd:dir,env:{...env,...extra}});
  const build=(extra={})=>exec('sh',[path.join(iso,'m4/build-app-guest.sh'),path.join(dir,'missing.bundle'),path.join(dir,'out.cpio.gz')],{cwd:dir,env:{...env,...extra}});
  return {dir,iso,release,id,cmdline,env,pins,image,launch,build};
}

test('actual launcher uses the pinned kernel, firmware and literal cmdline without host defaults',async t=>{
  const f=await fixture(t);await f.launch();const args=JSON.parse(await fs.readFile(f.env.CAPTURE));
  for(const [flag,value]of [['-kernel',path.join(f.release,'kernel')],['-bios',path.join(f.release,'firmware.fd')],['-append',f.cmdline]])assert.equal(args[args.indexOf(flag)+1],value);
  assert(args.some(a=>a.includes('kernel-hashes=on')));
  await assert.rejects(fs.stat(path.join(f.dir,'SHOULD_NOT_EXIST')),{code:'ENOENT'});
});
test('tampered releases, mismatched pins and boot overrides refuse before launching',async t=>{
  const f=await fixture(t);
  for(const env of [{DOMAIN_RELEASE_ID:'00'.repeat(32)},{DOMAIN_RELEASE_ID:''},{DOMAIN_RELEASE_DIR:''},{DOMAIN_RELEASE_DIR:'release'},{OVMF_OVERRIDE:'/other/firmware'},{KERNEL_HASHES:'off'}])await assert.rejects(f.launch(env));
  await assert.rejects(f.launch({},'plain'));
  await fs.writeFile(f.image+'.shield','qwen2.5-0.5b-q8-gguf');await assert.rejects(f.launch(),/cannot launch a Shield image/);await fs.rm(f.image+'.shield');
  const pins=await fs.readFile(f.pins);await fs.writeFile(f.pins,'# no verifying firmware\n');
  await assert.rejects(f.launch(),/not approved as verifying/);await fs.writeFile(f.pins,pins);
  await fs.writeFile(path.join(f.release,'kernel'),'tampered');await assert.rejects(f.launch());
  await assert.rejects(fs.stat(f.env.CAPTURE),{code:'ENOENT'});
});
test('the image builder takes the same pin and refuses before building',async t=>{
  const f=await fixture(t);
  await assert.rejects(f.build({SHIELDED_IMAGE_TEMPLATE:'/some/shield/template'}),/cannot select a Shield template/);
  await assert.rejects(f.build({OVMF_OVERRIDE:'/other/firmware'}),/refuses firmware or kernel-hash overrides/);
  await fs.writeFile(path.join(f.release,'template/front'),'tampered');
  await assert.rejects(f.build(),/template\/front does not match its manifest entry/);
  await assert.rejects(fs.stat(path.join(f.dir,'out.cpio.gz')),{code:'ENOENT'});
});
test('stopping a guest does not require the release to remain readable',async t=>{
  const f=await fixture(t);await fs.rm(f.release,{recursive:true});
  await fs.writeFile(path.join(f.dir,'coldtest.host'),'HOST unit=already-stopped\n');
  const out=await exec('sh',[path.join(f.iso,'m2/run-domain.sh'),'stop','coldtest',f.dir],{env:f.env});
  assert.match(out.stdout,/was not running/);
});

// A replica serving the fixture release's objects by raw CID, counting requests.
async function replica(f){
  const objects=new Map([[f.id,await fs.readFile(path.join(f.release,'release.json'))]]);
  for(const [name,{sha256}] of Object.entries(JSON.parse(objects.get(f.id)).files))objects.set(packageCID(sha256),await fs.readFile(path.join(f.release,name)));
  objects.set(packageCID(f.id),objects.get(f.id));objects.delete(f.id);
  const r={requests:0,fetchImpl:async url=>{r.requests++;const b=objects.get(new URL(url).pathname.split('/').at(-1));return b?new Response(b):new Response('',{status:404});}};
  return r;
}
const gateways=['http://192.0.2.1/ipfs'];
test('fetch-runtime installs a release the boot verifier accepts, and removes one whose firmware is not pinned',async t=>{
  const f=await fixture(t),r=await replica(f),out=path.join(f.dir,'fetched');
  const got=await fetchRuntime({releaseId:f.id,destination:out,gateways,fetchImpl:r.fetchImpl,isolation:f.iso});
  assert.equal(got.directory,out);assert.equal(got.files,6);
  await f.launch({DOMAIN_RELEASE_DIR:out});
  assert.equal(JSON.parse(await fs.readFile(f.env.CAPTURE)).includes(path.join(out,'firmware.fd')),true);
  await fs.writeFile(f.pins,'# no verifying firmware\n');
  const second=path.join(f.dir,'unpinned');
  await assert.rejects(fetchRuntime({releaseId:f.id,destination:second,gateways,fetchImpl:r.fetchImpl,isolation:f.iso}),/not pinned as verifying/);
  await assert.rejects(fs.stat(second),{code:'ENOENT'});
});
test('fetch-runtime never merges into or removes an existing directory',async t=>{
  const f=await fixture(t),r=await replica(f),out=path.join(f.dir,'existing');
  await fs.mkdir(out);await fs.writeFile(path.join(out,'keep'),'operator data');
  await assert.rejects(fetchRuntime({releaseId:f.id,destination:out,gateways,fetchImpl:r.fetchImpl,isolation:f.iso}),{code:'EEXIST'});
  assert.deepEqual(await fs.readdir(out),['keep']);assert.equal(await fs.readFile(path.join(out,'keep'),'utf8'),'operator data');
  assert.equal(r.requests,0);
});
