// Owner-committed names in the public startup package: the JS check must accept and refuse exactly what the
// measured guest's Go check does (isolation/m2/bootstrap/names_test.go reads the same vectors), existing exact v1
// bytes must keep their hash and meaning, and the package must never carry credential material.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {verifyPackage,preparePackage,validateNames,challengeLabel,challengeAlias,dnsName,ownerHost,MAX_OWNER_NAMES} from '../sdk/bootstrap/package.mjs';
const v=JSON.parse(fs.readFileSync(new URL('../isolation/m2/bootstrap/testdata/vectors.json',import.meta.url)));
const nv=JSON.parse(fs.readFileSync(new URL('../isolation/m2/bootstrap/testdata/names-vectors.json',import.meta.url)));
const intent=b=>({version:1,sha256:createHash('sha256').update(b).digest('hex')});

test('JS and Go agree on every owner-names vector',()=>{
  assert.ok(nv.cases.length>=30&&nv.cases.some(c=>c.valid)&&nv.cases.some(c=>!c.valid));
  for(const c of nv.cases){
    let err=null;try{verifyPackage(Buffer.from(c.manifest),intent(c.manifest));}catch(e){err=e;}
    assert.equal(err===null,c.valid,`${c.name}: ${err?.message??'accepted'}`);
  }
});

test('the challenge alias commits to deployment and owner, identically to Go',()=>{
  for(const a of nv.aliases){
    assert.equal(challengeLabel(a.deployment,a.owner),a.label);
    assert.equal(challengeAlias(a.deployment,a.owner,a.zone),a.alias);
    assert.equal(challengeLabel(a.deployment,a.owner.toUpperCase().replace('0X','0x')),a.label,'owner case does not matter');
  }
  assert.notEqual(nv.aliases[0].label,nv.aliases[1].label,'a changed owner changes the alias');
  for(const [d,o] of [[v.id,'0x'+'00'.repeat(20)],['0x'+'00'.repeat(32),v.owner],[v.id.slice(2),v.owner],[v.id,v.owner.slice(2)]])
    assert.throws(()=>challengeLabel(d,o));
  assert.throws(()=>challengeAlias(v.id,v.owner,'not a zone'));
});

test('existing exact v1 packages keep their bytes, hash and meaning',()=>{
  for(const raw of [v.manifest,v.custodyManifest]){
    const p=verifyPackage(Buffer.from(raw),intent(raw));
    assert.equal(Object.hasOwn(p.manifest,'names'),false);
    assert.equal(preparePackage(JSON.parse(raw)).bytes.toString(),raw);
  }
});

test('prepared named packages are exact, bounded and credential-free',()=>{
  const names={hosts:['a.example.org','shop.example.com'],acme:{directory:'https://acme-v02.api.letsencrypt.org/directory',challenge:'https://challenge.example.net',zone:'acme.example.net',eab:{kid:'ACME_EAB_KID',hmac:'ACME_EAB_HMAC'}}};
  const p=preparePackage({...JSON.parse(v.custodyManifest),names});
  assert.deepEqual(p.manifest.names,names);
  assert.doesNotMatch(p.bytes.toString(),/"(?:value|key|secret|token|password)"/i,'EAB is named, never carried');
  assert.throws(()=>preparePackage({...JSON.parse(v.manifest),names}),/custody-v2/);
  assert.throws(()=>validateNames({hosts:Array.from({length:MAX_OWNER_NAMES+1},(_,i)=>`h${String(i).padStart(2,'0')}.example`)},'public'),/1 to 10/);
  for(const h of ['shop.example.com','xn--bcher-kva.example','a-b.c-d.example'])assert.ok(ownerHost(h),h);
  for(const h of ['x.enclave.host','enclave.host','1.2.3.4','a..b','a.b.','*.a.b','A.example',`${'a'.repeat(64)}.example`,'.example'])assert.equal(ownerHost(h),false,h);
  assert.equal(dnsName('acme.enclave.host'),true,'a responder zone may be any explicitly selected zone');
});
