import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {keccak256} from 'viem';
import {PROFILE_LAYOUT,CONTRACT_PIN_KEYS,MAX_PROFILE_BYTES,encodeProfile,profileDigest,parseProfile,validateProfile,contractPinsFromProfile,
  verifyProfileOnChain,rpcClients,boundedFetch} from '../network/authority-profile.mjs';
import {validateContractPins} from '../network/contract-pins.mjs';
import {draftSkeleton,buildProfile} from '../scripts/network/verify-profile.mjs';
const run=promisify(execFile);
const root=new URL('..',import.meta.url);
const read=p=>fs.readFileSync(new URL(p,root));
// The reviewed digest is held here, out of band of the file it names.
const DIGEST='sha256:ee957827032cf7208434e4c73f9e859a27e4fc5c6cab5f4a2153308c09eb4cb8';
const PROFILE_FILE='contracts/deployments/network-profile-base.json';
// The public host pin document the profile's host pins came from (metal-host-policy-staging/51a568c6), verbatim.
const PUBLIC_PINS='{"version":1,"chainId":8453,"contracts":{"registry":"0x868eb7fc5b5a84b2ff082eafc9bf40b7aac5ccac","deployments":"0xb1783b61e1fdee6a6163dc3cdac27bf32e7d117b","appCatalog":"0x18419ca2b502d423a8de6269aeee171a378626e3","proofOfTime":"0x6f462d77727f10f05a3e660650e7dcc9cc60e6b2","enclavePay":"0x580270e88e5df35dad59e7fe3d907ebea96673a6","verificationFees":"0x87c7266543ff5839b2c20226bd9b3cd511a23641","sessionVaultFactory":"0x0000000000000000000000000000000000000000","secretVaultV2":"0x0000000000000000000000000000000000000000"}}\n';
const LEGACY_FACTORY='0x1f5c887c0cdf491b16ab6c449abafdf9b2ec9c9c',ADDRESS_BOOK='0xab214342d5a490150a4a977063a2f88e21f80907';
const sha256=b=>createHash('sha256').update(b).digest('hex');
const committed=()=>JSON.parse(read(PROFILE_FILE));
const reparse=value=>{const bytes=encodeProfile(value);return parseProfile(bytes,{expectedDigest:profileDigest(bytes)});};

test('the committed profile is canonical, matches the reviewed digest and exports the strict host pin document',()=>{
  const bytes=read(PROFILE_FILE);
  assert.equal('sha256:'+sha256(bytes),DIGEST);
  const {digest,profile}=parseProfile(bytes,{expectedDigest:DIGEST});
  assert.equal(digest,DIGEST);
  const pins=contractPinsFromProfile(profile);
  assert.deepEqual(Object.keys(pins.contracts),CONTRACT_PIN_KEYS);
  assert.deepEqual(validateContractPins(pins),pins.contracts);
  assert.deepEqual(JSON.parse(read('contracts/deployments/contract-pins-base.json')),pins);
  // New path: the pinned factory and V2 vault, never the legacy book-following factory.
  assert.equal(pins.contracts.sessionVaultFactory,'0xec9277a32f98ad3108747fe3da78c35e1bee097b');
  assert.equal(pins.contracts.secretVaultV2,'0x56b81b3970a8ac2c52f9874bd2758ede30758228');
  assert.equal(profile.contracts.hostOwnership.address,'0xf5e9e6c02449001f6e8e95e5d87413f2cb6790ea');
  assert.equal(profile.contracts.connectivity.address,'0x5f8b636e0768e84bd47b736652030b65db615111');
  assert.ok(!Object.values(pins.contracts).includes(LEGACY_FACTORY));
  // The compatibility difference is on the record: legacy vaults resolve the ledger through the mutable book.
  assert.equal(profile.contracts.legacySessionVaultFactory.address,LEGACY_FACTORY);
  assert.equal(profile.contracts.legacySessionVaultImplementation.immutable.book,ADDRESS_BOOK);
  assert.equal(profile.contracts.sessionVaultImplementation.immutable.book,profile.contracts.pinnedSessionAuthority.address);
});

test('the profile repeats the recorded compiled-runtime verification and the public host pins exactly',()=>{
  const recordBytes=read('contracts/deployments/independent-authorities-base.json'),record=JSON.parse(recordBytes),profile=committed();
  assert.equal(profile.review.inputs.deploymentRecord.sha256,sha256(recordBytes));
  assert.equal(profile.review.inputs.publicHostPins.sha256,sha256(PUBLIC_PINS));
  const names={sessionVaultFactory:'PinnedSessionVaultFactory',pinnedSessionAuthority:'PinnedSessionAuthority',sessionVaultImplementation:'SessionVault',
    sessionVaultLib:'SessionVaultLib',hostOwnership:'EnclaveHostOwnership',secretVaultV2:'EnclaveSecretVaultV2'};
  for(const [name,c] of Object.entries(profile.contracts)){
    if(c.codeProvenance!=='compiled-runtime'){assert.equal(Object.hasOwn(names,name),false);continue;}
    const r=record.verified.contracts[names[name]];
    assert.equal(c.address,r.address.toLowerCase());assert.equal(c.codeHash,r.codeHash);assert.equal(c.runtimeBytes,r.runtimeBytes);
    for(const [getter,want] of Object.entries(r.bindings||{}))
      assert.equal(String(c.immutable[getter]??c.reviewedState[getter]).toLowerCase(),String(want).toLowerCase(),name+'.'+getter);
  }
  assert.deepEqual(profile.builds['independent-authorities'].sourceSha256,record.sourceSha256);
  assert.equal(profile.builds['independent-authorities'].compiler,record.compiler);
  for(const [k,v] of Object.entries(JSON.parse(PUBLIC_PINS).contracts))if(!/^0x0{40}$/.test(v))assert.equal(profile.contracts[k].address,v);
  for(const [k,v] of [['usdc','usdc'],['paymentRouter','router'],['keyAttestations','keyAttestations']])assert.equal(profile.contracts[k].address,record.inputs[v].toLowerCase());
  assert.equal(profile.contracts.secretVaultV2.immutable.enclaveOwner,record.inputs.enclaveOwner.toLowerCase());
});

test('a reviewer re-derives the identical bytes from the explicit inputs; a recorded hash is never replaced by an observed one',()=>{
  const record=JSON.parse(read('contracts/deployments/independent-authorities-base.json')),profile=committed();
  const addresses=draftSkeleton({record,publicPins:JSON.parse(PUBLIC_PINS),connectivity:'0x5F8b636E0768e84bD47B736652030b65dB615111',
    legacyFactory:LEGACY_FACTORY,legacyImplementation:profile.contracts.legacySessionVaultImplementation.address});
  const observation={contracts:Object.fromEntries(Object.entries(profile.contracts).map(([n,c])=>[n,{codeHash:c.codeHash,runtimeBytes:c.runtimeBytes,
    immutable:structuredClone(c.immutable),reviewedState:structuredClone(c.reviewedState)}]))};
  assert.equal(profileDigest(encodeProfile(buildProfile({record,addresses,observation,review:profile.review}))),DIGEST);
  const swapped=structuredClone(observation);swapped.contracts.sessionVaultFactory.codeHash='0x'+'ab'.repeat(32);
  assert.throws(()=>buildProfile({record,addresses,observation:swapped,review:profile.review}),/differs from the verified compiled runtime/);
  const rebound=structuredClone(observation);rebound.contracts.secretVaultV2.immutable.sessionVaultFactory=LEGACY_FACTORY;
  assert.throws(()=>buildProfile({record,addresses,observation:rebound,review:profile.review}),/differs from the verified record/);
  const silent=structuredClone(observation);silent.contracts.registry.immutable.registrySchema='!reverted';
  assert.throws(()=>buildProfile({record,addresses,observation:silent,review:profile.review}),/did not answer/);
  assert.throws(()=>draftSkeleton({record,publicPins:{...JSON.parse(PUBLIC_PINS),contracts:{...JSON.parse(PUBLIC_PINS).contracts,deployments:'0x'+'1'.repeat(40)}},
    connectivity:'0x'+'2'.repeat(40),legacyFactory:LEGACY_FACTORY,legacyImplementation:'0x'+'3'.repeat(40)}),/disagree with the public host pins/);
  assert.throws(()=>draftSkeleton({record,publicPins:{...JSON.parse(PUBLIC_PINS),contracts:{...JSON.parse(PUBLIC_PINS).contracts,sessionVaultFactory:LEGACY_FACTORY}},
    connectivity:'0x'+'2'.repeat(40),legacyFactory:LEGACY_FACTORY,legacyImplementation:'0x'+'3'.repeat(40)}),/different sessionVaultFactory/);
});

test('the digest is required and decides first; non-canonical, duplicate, oversized and malformed bytes refuse',()=>{
  const bytes=read(PROFILE_FILE);
  assert.throws(()=>parseProfile(bytes),/expected profile digest/);
  assert.throws(()=>parseProfile(bytes,{expectedDigest:'ee957827032cf7208434e4c73f9e859a27e4fc5c6cab5f4a2153308c09eb4cb8'}),/expected profile digest/);
  assert.throws(()=>parseProfile(bytes,{expectedDigest:'sha256:'+'0'.repeat(64)}),/digest mismatch/);
  const tampered=Buffer.from(bytes.toString().replace('"retired": false','"retired": true '));
  assert.throws(()=>parseProfile(tampered,{expectedDigest:DIGEST}),/digest mismatch/);
  const withDigest=b=>()=>parseProfile(b,{expectedDigest:profileDigest(b)});
  assert.throws(withDigest(Buffer.from(JSON.stringify(JSON.parse(bytes)))),/not canonically encoded/);
  assert.throws(withDigest(Buffer.from(bytes.toString().replace('{\n  "builds"','{\n  "chainId": 1,\n  "builds"'))),/not canonically encoded/);
  assert.throws(withDigest(Buffer.from(bytes.toString().replace('"chainId": 8453','"chainId": 8453.0'))),/not canonically encoded/);
  assert.throws(withDigest(Buffer.concat([bytes.subarray(0,10),Buffer.from([0xff]),bytes.subarray(10)])),/malformed/);
  assert.throws(withDigest(bytes.subarray(0,bytes.length-3)),/malformed/);
  assert.throws(withDigest(Buffer.alloc(MAX_PROFILE_BYTES+1,32)),/too large/);
  assert.throws(()=>encodeProfile({n:1.5}),/safe integers/);
});

test('unknown, missing, duplicate and miswired fields refuse even with a matching digest',()=>{
  const cases=[
    [p=>{p.extra=1;},/unknown field: profile.extra/],
    [p=>{p.chainId=1;},/not for Base mainnet/],
    [p=>{p.version=2;},/unsupported/],
    [p=>{p.contracts.addressBook=p.contracts.usdc;},/unknown field: contracts.addressBook/],
    [p=>{delete p.contracts.connectivity;},/missing field: contracts.connectivity/],
    [p=>{p.contracts.deployments.immutable.owner=p.contracts.deployments.reviewedState.owner;},/unknown field: contracts.deployments.immutable.owner/],
    [p=>{delete p.contracts.deployments.reviewedState.owner;},/missing field/],
    [p=>{p.contracts.usdc.role='host-pin';},/wrong role/],
    [p=>{p.contracts.enclavePay.address=p.contracts.verificationFees.address;},/duplicate contract address/],
    [p=>{p.contracts.proofOfTime.address='0x'+'0'.repeat(40);},/invalid address/],
    [p=>{p.contracts.registry.address=p.contracts.registry.address.toUpperCase().replace('0X','0x');},/invalid address/],
    [p=>{p.contracts.registry.codeHash='0x1234';},/invalid code pin/],
    [p=>{p.contracts.registry.runtimeBytes=24577;},/invalid code pin/],
    [p=>{p.contracts.sessionVaultFactory.codeProvenance='observed';},/wrong code provenance/],
    [p=>{p.contracts.registry.codeProvenance='compiled-runtime';},/wrong code provenance/],
    [p=>{p.contracts.sessionVaultFactory.build='other';},/wrong build reference/],
    [p=>{p.contracts.secretVaultV2.immutable.sessionVaultFactory=LEGACY_FACTORY;},/inconsistent binding: secretVaultV2.sessionVaultFactory/],
    [p=>{p.contracts.sessionVaultFactory.immutable.authorityPins=p.contracts.sessionVaultFactory.immutable.authorityPins.slice(0,2);},/invalid tuple binding/],
    [p=>{p.contracts.sessionVaultImplementation.immutable.book=ADDRESS_BOOK;},/inconsistent binding: sessionVaultImplementation.book/],
    [p=>{p.contracts.deployments.reviewedState.bandwidthRouter='0x'+'0'.repeat(40);},/inconsistent binding: deployments.bandwidthRouter/],
    [p=>{p.contracts.deployments.reviewedState.retired='false';},/invalid boolean binding/],
    [p=>{p.contracts.registry.immutable.registrySchema=4;},/invalid integer binding/],
    [p=>{p.contracts.usdc.ownerPowers=[];},/invalid owner powers/],
    [p=>{p.review.rpcHosts=['one.example'];},/invalid review RPC hosts/],
    [p=>{p.review.inputs.x={description:'d',sha256:'0'.repeat(64),url:'u'};},/unknown field/],
  ];
  for(const [mutate,error] of cases){const p=committed();mutate(p);assert.throws(()=>reparse(p),error,String(error));}
});

// ---- scripted peers ----
const CHAIN=8453,HEAD=1000n,NOW=1_800_000_000_000;
function syntheticProfile(){
  // The real layout and bindings with synthetic bytecode: a scripted peer can serve bytes whose hash it knows.
  const p=committed(),codes={};
  for(const [name,c] of Object.entries(p.contracts)){
    codes[c.address]='0x'+createHash('sha256').update(name).digest('hex').repeat(4);
    c.codeHash=keccak256(codes[c.address]);c.runtimeBytes=(codes[c.address].length-2)/2;
  }
  return {profile:reparse(p).profile,codes};
}
class RevertError extends Error{constructor(){super('execution reverted');this.name='ContractFunctionExecutionError';this.cause={name:'ContractFunctionRevertedError'};}}
function peer(profile,codes,{chainId=CHAIN,head=HEAD,age=10_000,hash='0x'+'aa'.repeat(32),edit,fail,log}={}){
  const byAddress=new Map(Object.entries(profile.contracts).map(([n,c])=>[c.address,{name:n,...structuredClone(c),code:codes[c.address]}]));
  if(edit)edit(byAddress);
  const value=(c,getter)=>{
    for(const [section,layout] of [['immutable',PROFILE_LAYOUT[c.name].immutable],['reviewedState',PROFILE_LAYOUT[c.name].reviewedState]])
      if(Object.hasOwn(c[section],getter)&&c[section][getter]!=='!reverted'){
        const v=c[section][getter],type=layout[getter];
        return type==='uint256'?BigInt(v):type==='address'?v.toUpperCase().replace('0X','0x'):v;
      }
    throw new RevertError();
  };
  return {
    async getChainId(){if(fail)throw Error(fail);return chainId;},
    async getBlockNumber(){return head;},
    async getBlock({blockNumber}){return {hash,number:blockNumber,timestamp:BigInt(Math.floor((NOW-age)/1000))};},
    async getCode({address}){log?.push(['code',address]);return byAddress.get(address.toLowerCase())?.code;},
    async readContract({address,functionName}){
      log?.push([functionName,address]);
      if(functionName==='addr')throw Error('the mutable address book must never be read');
      const c=byAddress.get(address.toLowerCase());if(!c?.code)throw Object.assign(new RevertError(),{cause:{name:'ContractFunctionZeroDataError'}});
      return value(c,functionName);
    },
  };
}
const verify=(profile,clients,extra={})=>verifyProfileOnChain({profile,clients,now:()=>NOW,pacing:{minIntervalMs:0,concurrency:8},...extra});
const setCode=(name,code)=>m=>{for(const c of m.values())if(c.name===name)c.code=code;};
const setValue=(name,section,getter,v)=>m=>{for(const c of m.values())if(c.name===name)c[section][getter]=v;};

test('two agreeing fresh peers verify every pinned code hash and binding at one block, without the address book',async()=>{
  const {profile,codes}=syntheticProfile(),log=[];
  const result=await verify(profile,[peer(profile,codes,{log}),peer(profile,codes)]);
  assert.equal(result.blockNumber,String(HEAD-2n));
  assert.equal(result.blockHash,'0x'+'aa'.repeat(32));
  const addresses=new Set(Object.values(profile.contracts).map(c=>c.address));
  assert.ok(log.length>=Object.keys(PROFILE_LAYOUT).length);
  assert.ok(log.every(([,a])=>addresses.has(a)));
});

test('failover: one dead, wrong-chain, stale, oversized or lying peer cannot block or sway two honest peers',async()=>{
  const {profile,codes}=syntheticProfile();
  const honest=()=>peer(profile,codes);
  for(const bad of [peer(profile,codes,{fail:'connect ECONNREFUSED'}),peer(profile,codes,{chainId:1}),peer(profile,codes,{age:600_000,head:HEAD}),
    peer(profile,codes,{edit:setCode('registry','0x'+'00'.repeat(24577))}),peer(profile,codes,{edit:setCode('secretVaultV2','0x60016001')}),
    peer(profile,codes,{edit:setValue('appCatalog','reviewedState','owner','0x'+'9'.repeat(40))})]){
    const result=await verify(profile,[bad,honest(),honest()]);
    assert.equal(result.blockNumber,String(HEAD-2n));
  }
});

test('refusals: no quorum, disagreement, stale chain, wrong chain and two agreeing liars',async()=>{
  const {profile,codes}=syntheticProfile();
  const honest=()=>peer(profile,codes);
  await assert.rejects(verify(profile,[honest()]),/two to eight RPC clients/);
  await assert.rejects(verify(profile,[honest(),peer(profile,codes,{fail:'timeout'})]),/chain quorum unavailable/);
  await assert.rejects(verify(profile,[honest(),peer(profile,codes,{chainId:84532})]),/chain quorum unavailable/);
  await assert.rejects(verify(profile,[honest(),peer(profile,codes,{edit:setCode('sessionVaultFactory','0x6001')})]),/no fresh agreeing chain quorum/);
  await assert.rejects(verify(profile,[honest(),peer(profile,codes,{hash:'0x'+'bb'.repeat(32)})]),/no fresh agreeing chain quorum/);
  await assert.rejects(verify(profile,[peer(profile,codes,{age:600_000}),peer(profile,codes,{age:600_000})]),/stale chain block/);
  const liars=edit=>[peer(profile,codes,{edit}),peer(profile,codes,{edit})];
  await assert.rejects(verify(profile,liars(setCode('sessionVaultFactory','0x6001'))),/sessionVaultFactory: code hash mismatch/);
  await assert.rejects(verify(profile,liars(setCode('secretVaultV2',undefined))),/secretVaultV2: no deployed code/);
  await assert.rejects(verify(profile,liars(setCode('hostOwnership','0x'))),/hostOwnership: no deployed code/);
  await assert.rejects(verify(profile,liars(setValue('sessionVaultImplementation','immutable','book',ADDRESS_BOOK))),/sessionVaultImplementation.book: binding mismatch/);
  await assert.rejects(verify(profile,liars(setValue('sessionVaultFactory','immutable','authorityPins','!reverted'))),/sessionVaultFactory.authorityPins: binding mismatch/);
  await assert.rejects(verify(profile,liars(setValue('deployments','reviewedState','owner','0x'+'9'.repeat(40)))),/deployments.owner: reviewed mutable state changed/);
  await assert.rejects(verify(profile,liars(setValue('deployments','reviewedState','retired',true))),/deployments.retired: reviewed mutable state changed/);
  const changed=structuredClone(profile);changed.contracts.extra={};
  await assert.rejects(verify(changed,[honest(),honest()]),/unknown field/);
});

test('RPC origins are explicit, distinct HTTPS hosts and responses are size bounded',async()=>{
  assert.throws(()=>rpcClients(['https://a.example']),/two to eight/);
  assert.throws(()=>rpcClients(['https://a.example','http://b.example']),/distinct HTTPS/);
  assert.throws(()=>rpcClients(['https://a.example/x','https://a.example/y']),/distinct HTTPS/);
  assert.throws(()=>rpcClients(['https://u:p@a.example','https://b.example']),/without credentials/);
  assert.equal(rpcClients(['https://a.example','https://b.example']).length,2);
  const big=boundedFetch({maxBytes:1024,fetch:async()=>new Response('x'.repeat(4096))});
  await assert.rejects(big('https://a.example',{}),/too large/);
  const declared=boundedFetch({maxBytes:1024,fetch:async()=>new Response('{}',{headers:{'content-length':'99999'}})});
  await assert.rejects(declared('https://a.example',{}),/too large/);
  const ok=boundedFetch({maxBytes:1024,fetch:async(_u,init)=>{assert.equal(init.redirect,'error');return new Response('{"ok":1}');}});
  assert.deepEqual(await (await ok('https://a.example',{})).json(),{ok:1});
});

test('the verifier command requires the user digest and refuses before any RPC on a mismatch',async()=>{
  const script=new URL('../scripts/network/verify-profile.mjs',import.meta.url).pathname,cwd=root.pathname;
  const fails=async(args,pattern)=>{
    await assert.rejects(run(process.execPath,[script,...args],{cwd,timeout:20000}),e=>{assert.match(e.stderr,pattern);return true;});
  };
  await fails(['--profile',PROFILE_FILE],/--expect sha256:<digest> is required/);
  await fails(['--profile',PROFILE_FILE,'--expect','sha256:'+'1'.repeat(64)],/digest mismatch/);
  await fails(['--profile',PROFILE_FILE,'--expect',DIGEST],/two to eight independent HTTPS RPC origins/);
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'authority-profile-'));
  try{
    const wrong=JSON.parse(read('contracts/deployments/contract-pins-base.json'));wrong.contracts.sessionVaultFactory=LEGACY_FACTORY;
    fs.writeFileSync(path.join(dir,'pins.json'),JSON.stringify(wrong));
    await fails(['--profile',PROFILE_FILE,'--expect',DIGEST,'--check-pins',path.join(dir,'pins.json'),'--rpc','https://a.invalid','--rpc','https://b.invalid'],/differs from the verified profile/);
    await fails(['draft','--record','contracts/deployments/independent-authorities-base.json'],/draft requires --public-pins/);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});

test('every pinned contract documents its owner powers and the scope disclaims migration and independence',()=>{
  const profile=committed();
  assert.match(profile.scope,/not evidence that production migrated/);
  assert.match(profile.scope,/governance is sealed/);
  assert.match(profile.contracts.appCatalog.ownerPowers.join(' '),/transferApp/);
  assert.match(profile.contracts.deployments.ownerPowers.join(' '),/slashBond/);
  assert.match(profile.contracts.usdc.ownerPowers.join(' '),/implementation can change/);
  for(const [name,c] of Object.entries(profile.contracts))if(c.codeProvenance==='observed'&&!['usdc','legacySessionVaultFactory','legacySessionVaultImplementation'].includes(name))
    assert.match(c.ownerPowers.join(' '),/observed hash/,name);
  assert.doesNotThrow(()=>validateProfile(profile));
});
