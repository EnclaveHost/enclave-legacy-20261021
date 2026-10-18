import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import os from 'node:os';import path from 'node:path';
import {generateKeyPairSync} from 'node:crypto';
import {privateKeyToAccount} from 'viem/accounts';
import {PublicDirectory} from '../network/public-directory.mjs';
import {DirectoryClient} from '../network/directory-client.mjs';
import {createDirectoryServer} from '../network/directory-server.mjs';
import {signProviderRecord,signQualification,providerIdFor,CHECKS} from '../network/provider-directory.mjs';
import {defaultNetworkPolicy,signNetworkPolicy} from '../network/network-policy.mjs';
import {signDelegation,signRoute,recordHash} from '../network/route-record.mjs';
const account=n=>privateKeyToAccount('0x'+n.repeat(64));
const owner=account('1'),operator=account('2'),checker=account('3'),stranger=account('4');
const id='0x'+'ab'.repeat(32),runner='0x'+'cd'.repeat(32);
async function rig(t){
  const dir=await mkdtemp(path.join(os.tmpdir(),'public-directory-'));t.after(()=>rm(dir,{recursive:true,force:true}));
  let now=Date.now();const policy=defaultNetworkPolicy(id);
  const lease={id,owner:owner.address,runner,chainId:8453,deployments:'0x'+'05'.repeat(20),runnerOperator:operator.address,active:true,isPublic:true,leaseUntil:now+600000,validUntil:now+90000};
  const opts={directory:dir,checkers:[checker.address],now:()=>now,hostOperator:async()=>operator.address,leaseOf:async()=>({...lease})};
  const d=new PublicDirectory(opts),address='8.8.4.4';
  const record={version:1,providerId:providerIdFor(operator.address,address),operator:operator.address.toLowerCase(),address,
    wgExitKey:Buffer.alloc(32,1).toString('base64'),wgGuardKey:Buffer.alloc(32,2).toString('base64'),ports:{exit:51820,guard:51821,control:51822},
    roles:['guard','ingress','egress'],pricePerGiB6:0,region:'test',kind:'community',hostId:runner,issuedAt:now,expiresAt:now+1800000};
  const pr=await signProviderRecord(operator,record),q={version:1,providerId:record.providerId,operator:record.operator,address,wgExitKey:record.wgExitKey,wgGuardKey:record.wgGuardKey,roles:record.roles,
    checks:Object.fromEntries(CHECKS.map(k=>[k,true])),issuedAt:now,expiresAt:now+600000};
  const qualification=await signQualification(checker,q);
  const keys=generateKeyPairSync('ed25519');
  async function publication(p=policy,sequence=1){
    const delegation={version:2,deploymentId:id,runner,chainId:8453,deployments:lease.deployments,policyHash:recordHash(p),epoch:now,notBefore:now,expiresAt:now+3600000,
      publicKey:keys.publicKey.export({format:'der',type:'spki'}).toString('base64'),ipns:'k51'+'a'.repeat(50)};
    const authorization=await signDelegation(operator,delegation,now);
    const record={version:2,deploymentId:id,delegationHash:recordHash(delegation),sequence,issuedAt:now,expiresAt:now+60000,
      routes:[{circuit:'f'.repeat(32),address,port:443,transport:'enclave-network'}]};
    return {version:2,endpoint:'https://old-control.example/t/host',policy:p,bundle:{authorization,...signRoute(keys.privateKey,record)}};
  }
  return {d,opts,dir,pr,q,qualification,lease,policy,publication,advance:n=>{now+=n;}};
}
test('accepts independent signed providers; rejects forgery and an untrusted checker',async t=>{
  const r=await rig(t);await r.d.accept('provider',r.pr);await r.d.accept('qualification',r.qualification);
  assert.equal((await r.d.providers()).length,1);
  await assert.rejects(r.d.accept('provider',{...r.pr,record:{...r.pr.record,address:'9.9.9.9'}}));
  await assert.rejects(r.d.accept('qualification',await signQualification(stranger,r.q)),/untrusted/);
});
test('policies require owner authorization; higher nonce survives restart and conflicting equal nonce is refused',async t=>{
  const r=await rig(t),p={...r.policy,nonce:1,issuedAt:1};
  await assert.rejects(r.d.accept('policy',await signNetworkPolicy(stranger,p)),/owner signature/);
  await r.d.accept('policy',await signNetworkPolicy(owner,p));
  const restarted=new PublicDirectory(r.opts);
  await assert.rejects(restarted.accept('policy',await signNetworkPolicy(owner,r.policy)),/stale/);
  await assert.rejects(restarted.accept('policy',await signNetworkPolicy(owner,{...p,issuedAt:2})),/equivocation/);
  assert.equal((await restarted.policy(id)).envelope.policy.nonce,1);
  r.lease.owner=stranger.address;
  await assert.rejects(restarted.policy(id),/owner signature/);
});
test('routes require qualified providers, current owner policy and current lease; stale route cannot resurrect after restart',async t=>{
  const r=await rig(t),p=await r.publication();
  await assert.rejects(r.d.accept('route',p),/qualified/);
  await r.d.accept('provider',r.pr);await r.d.accept('qualification',r.qualification);await r.d.accept('route',p);
  assert.deepEqual((await r.d.routes()).labels[id.slice(2,10)].addresses,['8.8.4.4']);
  await r.d.accept('route',await r.publication(r.policy,2));
  await assert.rejects(new PublicDirectory(r.opts).accept('route',p),/rollback/);
  r.lease.runner='0x'+'ef'.repeat(32);assert.equal(Object.keys((await r.d.routes()).labels).length,0);
});
test('expired records disappear and negative checker verdict is retained across replicas',async t=>{
  const r=await rig(t);await r.d.accept('provider',r.pr);await r.d.accept('qualification',r.qualification);await r.d.accept('route',await r.publication());
  r.advance(1000);await r.d.accept('qualification',await signQualification(checker,{...r.q,issuedAt:r.q.issuedAt+1000,checks:{...r.q.checks,blocksPrivateDestinations:false}}));
  assert.equal(Object.keys((await r.d.routes()).labels).length,0);
  const other=new PublicDirectory({...r.opts,directory:r.dir+'/second'});await other.import(await r.d.snapshot());
  assert.equal((await other.providers())[0].qualifications[0].qualification.checks.blocksPrivateDestinations,false);
  r.advance(1800001);assert.equal((await other.providers()).length,0);
});
test('directory has no credential/control endpoints; reads survive loss of one origin',async t=>{
  const r=await rig(t),server=createDirectoryServer(r.d);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>{server.closeAllConnections();server.close();});const origin='http://127.0.0.1:'+server.address().port;
  const client=new DirectoryClient({origins:['http://127.0.0.1:1',origin],timeoutMs:500});
  assert.equal((await client.publish('/v1/network/providers',r.pr)).length,1);
  assert.equal((await client.read('/v1/network/providers'))[0].value.providers.length,1);
  await assert.rejects(client.publish('/v1/network/byo/'+id+'/release',{secret:'must not send'}),/not a public/);
  assert.equal((await fetch(origin+'/v1/secrets/'+id)).status,404);
});
test('corrupted persisted state never becomes a fresh empty directory',async t=>{
  const r=await rig(t);await writeFile(path.join(r.dir,'public-records.json'),'{broken');
  await assert.rejects(new PublicDirectory(r.opts).read(),SyntaxError);
});
test('client verifies copies independently and refuses hidden or equivocal owner policies',async t=>{
  const r=await rig(t),p={...r.policy,nonce:1,issuedAt:1};
  const good=await signNetworkPolicy(owner,p),bad=await signNetworkPolicy(stranger,p);
  let values=[{envelope:bad},{envelope:good},{envelope:good}];
  const client=new DirectoryClient({origins:['http://127.0.0.1:1','http://127.0.0.1:2','http://127.0.0.1:3'],
    fetch:async url=>Response.json(values[Number(new URL(url).port)-1])});
  assert.deepEqual(await client.policy(id,{owner:owner.address}),good);
  values=[{envelope:bad},{envelope:null},{envelope:null}];
  await assert.rejects(client.policy(id,{owner:owner.address}),/no valid owner policy/);
  values=[{envelope:good},{envelope:good},{envelope:await signNetworkPolicy(owner,{...p,issuedAt:2})}];
  await assert.rejects(client.policy(id,{owner:owner.address}),/equivocation/);
  values=[{providers:[{record:{...r.pr,signature:bad.signature}}]},{providers:[{record:r.pr,qualifications:[r.qualification]}]},{providers:[]}];
  assert.equal((await client.providers({hostOperator:r.opts.hostOperator})).providers.length,1);
});
test('one unreachable mirror is backed off across apps; total outage still tries every origin',async()=>{
  const calls=[];let allDown=false;
  const client=new DirectoryClient({origins:['http://127.0.0.1:1','http://127.0.0.1:2'],fetch:async url=>{
    const port=new URL(url).port;calls.push(port);if(port==='1'||allDown)throw Error('unreachable');return Response.json({envelope:null});
  }});
  await client.policy(id,{owner:owner.address});await client.policy(id,{owner:owner.address});
  assert.deepEqual(calls,['1','2','2']);allDown=true;
  await assert.rejects(client.read('/v1/network/providers'),/unavailable/);
  calls.length=0;await assert.rejects(client.read('/v1/network/providers'),/unavailable/);assert.deepEqual(calls,['1','2']);
});
