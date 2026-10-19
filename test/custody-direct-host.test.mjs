import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {build} from 'esbuild';
import {EventEmitter} from 'node:events';
import {generatePrivateKey,privateKeyToAccount} from 'viem/accounts';
import {prepareHostBinding} from '../custody/v2/host-binding.mjs';
import {directCustodyIngress} from '../custody/v2/ingress.mjs';
import * as D from '../custody/v2/digests.mjs';
const hex=(n,size=32)=>'0x'+n.toString(16).padStart(size*2,'0');

test('actual bundled startup uses only the custodian in measured direct mode despite hostile host transport config',async()=>{
  for(const transport of ['direct','tunnel','invalid']){
    const {outputFiles}=await build({entryPoints:['custody/v2/cvm-gsup.mjs'],bundle:true,platform:'node',format:'cjs',write:false,
      plugins:[{name:'test-measured',setup(b){b.onLoad({filter:/custody[\\/]v2[\\/]measured\.mjs$/},()=>({contents:`export const MEASURED={transport:${JSON.stringify(transport)}};`,loader:'js'}));}}]});
    const spawned=[];
    const config={transport:'tunnel',relayUrl:'wss://api.enclave.host/forced',endpoint:'https://custody.operator.example',tunnelName:'test'};
    const run=()=>vm.runInNewContext(outputFiles[0].text,{setTimeout:()=>{},console:{log:()=>{}},require:name=>{
      if(name==='node:fs')return {readFileSync:()=>JSON.stringify(config),writeFileSync:()=>{}};
      if(name==='node:child_process')return {spawn:(command,args,options)=>{spawned.push({command,args,options});return new EventEmitter();}};
      throw Error('unexpected dependency '+name);
    }});
    if(transport==='invalid'){assert.throws(run,/unknown measured/);assert.equal(spawned.length,0);continue;}
    run();assert.equal(spawned.length,transport==='direct'?1:2);
    assert.deepEqual(Array.from(spawned[0].args),['/opt/custodian/custodian.mjs']);
    if(transport==='direct')assert.equal(JSON.stringify(spawned).includes('enclave.host'),false);
    else assert.equal(spawned[1].options.env.METAL_RELAY_URL,config.relayUrl);
  }
});

function bindingRig(){
  const operator=privateKeyToAccount(generatePrivateKey());const identity=privateKeyToAccount(generatePrivateKey());
  const machine={identity:identity.address,encKey:hex(3),registryId:hex(4),chipId:hex(5),measurement:hex(6),endpoint:'https://custody.operator.example'};
  const entry={active:true,endpoint:'https://host.operator.example',operator:operator.address.toLowerCase(),owner:hex(7,20)};
  const chain={readRegistryEntry:async({registryId})=>{assert.equal(registryId,machine.registryId);return {entry};}};
  return {entry,options:{chain,operator,chainId:8453,vault:hex(8,20),registryId:machine.registryId,registryEndpoint:entry.endpoint,endpoint:machine.endpoint,
    info:{v:2,identity:identity.address,encKey:machine.encKey,machine,hostSig:null}}};
}
test('host signs the exact configured machine through pinned registry authority, and verifies existing binding',async()=>{
  const {options}=bindingRig();const binding=await prepareHostBinding(options);
  assert.equal(binding.alreadyBound,false);
  assert.equal(await D.recoverDigest(D.hostDigest({...options,machine:options.info.machine}),binding.signature),options.operator.address.toLowerCase());
  options.info.hostSig=binding.signature;assert.equal((await prepareHostBinding(options)).alreadyBound,true);
  options.vault=hex(9,20);assert.equal((await prepareHostBinding(options)).alreadyBound,false);
});
test('host refuses foreign machine records, inactive operators and unaccepted owners before signing',async()=>{
  for(const alter of [r=>r.options.info.machine.registryId=hex(99),r=>r.options.info.machine.endpoint='https://other.example',
    r=>r.options.info.identity=hex(99,20),r=>r.entry.active=false,r=>r.entry.operator=hex(99,20),
    r=>r.entry.owner=hex(0,20),r=>r.entry.endpoint='https://other-host.example']){
    const r=bindingRig();alter(r);let signed=false;
    r.options.operator={...r.options.operator,signMessage:async()=>{signed=true;throw Error('must not sign');}};
    await assert.rejects(prepareHostBinding(r.options),/differs|authorized/);assert.equal(signed,false);
  }
});
test('direct ingress refuses ambiguous origins and injection into server configuration',()=>{
  for(const endpoint of ['http://custody.example','https://user:pass@custody.example','https://custody.example/path','https://custody.example?x','https://custody.example\n{','https://-bad.example','https://custody.example:8443'])
    assert.throws(()=>directCustodyIngress({endpoint,mgmtPort:8788}));
  for(const mgmtPort of [0,65536,1.5,'8788\nrespond 200'])assert.throws(()=>directCustodyIngress({endpoint:'https://custody.example',mgmtPort}));
});
