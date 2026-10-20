import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,writeFile,chmod,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createNetworkHost} from '../network/enclave-network-host.mjs';
import {parseWireGuardConfig,wireGuardConfigDigest} from '../network/wg-config.mjs';
import {privateKeyToAccount} from 'viem/accounts';
import {signNetworkPolicy} from '../network/network-policy.mjs';

const id='0x'+'ab'.repeat(32),salt='cd'.repeat(32);
const config=`[Interface]
PrivateKey = ${Buffer.alloc(32,1).toString('base64')}
Address = 10.1.2.3/32
DNS = 1.1.1.1
[Peer]
PublicKey = ${Buffer.alloc(32,2).toString('base64')}
Endpoint = 8.8.8.8:51820
AllowedIPs = 0.0.0.0/0
`;
async function rig(t){
 const directory=await mkdtemp(tmpdir()+'/local-byo-');t.after(()=>rm(directory,{recursive:true,force:true}));
 const file=path.join(directory,id+'.json');
 const host=await createNetworkHost({directory,config:{directories:['https://records.example'],relay:'https://refusing.example',byoConfigDirectory:directory,
  apps:'all',checkers:['0x'+'11'.repeat(20)],wgBinary:'/bin/true',nodeBinary:process.execPath,workerModule:'/bin/true'},
  fetch:async()=>{assert.fail('local BYO must not contact any relay');},account:{signMessage:async()=>{assert.fail('no relay release signature');}}});
 const app={deploymentId:id,policy:{mode:'byo-wireguard',byo:{configDigest:await wireGuardConfigDigest(salt,parseWireGuardConfig(config).config)}}};
 const write=body=>writeFile(file,JSON.stringify(body),{mode:0o600});
 return {host,app,file,write,directory};
}
test('owner-committed local BYO survives relay refusal and refuses changed secrets or unsafe endpoints',async t=>{
 const r=await rig(t);await r.write({config,salt});
 assert.deepEqual((await r.host.byoConfig(r.app)).endpoint,{address:'8.8.8.8',port:51820});
 await r.write({config,salt:'ef'.repeat(32)});await assert.rejects(r.host.byoConfig(r.app),/current policy/);
 await r.write({config:config.replace('8.8.8.8','9.9.9.9'),salt});await assert.rejects(r.host.byoConfig(r.app),/current policy/);
 await r.write({config:config.replace('8.8.8.8','127.0.0.1'),salt});await assert.rejects(r.host.byoConfig(r.app),/public address/);
 await rm(r.file);await assert.rejects(r.host.byoConfig(r.app),/ENOENT/);
 await assert.rejects(r.host.byoConfig({...r.app,deploymentId:'../outside'}),/exact BYO deployment/);
});
test('local BYO requires a bounded private regular file; parse errors never echo secret contents',async t=>{
 const r=await rig(t);await r.write({config,salt});
 if(process.platform!=='win32'){
  await chmod(r.file,0o644);await assert.rejects(r.host.byoConfig(r.app),/private regular/);await chmod(r.file,0o600);
  const target=r.file+'.real';await writeFile(target,JSON.stringify({config,salt}),{mode:0o600});
  await rm(r.file);await symlink(target,r.file);await assert.rejects(r.host.byoConfig(r.app),/ELOOP/);await rm(r.file);
 }
 await writeFile(r.file,'x'.repeat(16385),{mode:0o600});await assert.rejects(r.host.byoConfig(r.app),/16 KiB/);
 await writeFile(r.file,'{"private-secret-marker"', {mode:0o600});
 await assert.rejects(r.host.byoConfig(r.app),e=>e.message==='invalid BYO config document');
});

test('directory-only BYO accepts the owner signature and refuses another wallet before config use',async t=>{
 const r=await rig(t);await r.write({config,salt});
 const owner=privateKeyToAccount('0x'+'33'.repeat(32)),stranger=privateKeyToAccount('0x'+'44'.repeat(32));
 const policy={version:5,deploymentId:id,nonce:1,issuedAt:1,mode:'byo-wireguard',fallback:'none',byo:{...r.app.policy.byo,ingress:'none'}};
 let envelope=await signNetworkPolicy(owner,policy);
 const make=()=>createNetworkHost({directory:r.directory,config:{directories:['https://records.example'],byoConfigDirectory:r.directory,
  apps:'all',checkers:[owner.address],wgBinary:'/bin/true',nodeBinary:process.execPath,workerModule:'/bin/true'},fetch:async url=>{
   assert.equal(String(url),'https://records.example/v1/network/policy/'+id);return Response.json({envelope});
  }});
 const host=await make(),verified=await host.policyFor({deploymentId:id},{id,owner:owner.address});
 assert.equal((await host.byoConfig({deploymentId:id,policy:verified})).endpoint.address,'8.8.8.8');
 envelope=await signNetworkPolicy(stranger,policy);
 await assert.rejects((await make()).policyFor({deploymentId:id},{id,owner:owner.address}),/no valid owner policy/);
});
