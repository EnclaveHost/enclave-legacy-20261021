import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {execFileSync,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {keccak256} from 'viem';
import {MANIFEST_KIND,validateManifest,ipfsMetadataHash,cborMetadata,compareRuntime,readBuildSources,loadCompiler,compileBuild,readLive,
  verifyDeployedSources} from '../scripts/network/verify-deployed-sources.mjs';
import {parseProfile} from '../network/authority-profile.mjs';
const run=promisify(execFile);
const root=new URL('..',import.meta.url).pathname;
const read=p=>fs.readFileSync(path.join(root,p));
const MANIFEST=JSON.parse(read('contracts/deployments/source-verification-base.json'));
const PROFILE_DIGEST='sha256:ee957827032cf7208434e4c73f9e859a27e4fc5c6cab5f4a2153308c09eb4cb8';
const solc=createRequire(path.join(root,'package.json'))('solc');
const sha256=b=>createHash('sha256').update(b).digest('hex');
const clone=v=>structuredClone(v);
const word=a=>'0x'+a.slice(2).padStart(64,'0');

// A deployed source that is byte-identical at this checkout's HEAD, read from git so a working-tree edit does not count.
function headSource(build){
  const [unit,s]=Object.entries(MANIFEST.builds[build].sources)[0];
  try{
    const blob=execFileSync('git',['-C',root,'rev-parse','HEAD:'+s.path],{encoding:'utf8'}).trim();
    if(blob!==s.gitBlob)return null;
    return {unit,content:execFileSync('git',['-C',root,'cat-file','blob',blob],{encoding:'utf8'})};
  }catch{return null;}
}
const compile=(sources,settings,wanted)=>compileBuild(solc,{settings},sources,wanted);
// The live runtime rebuilt offline: compiler output with each declared slot holding the manifest's value.
function rebuild(k,entry){
  let code=k.object;
  for(const [id,refs] of Object.entries(k.immutableReferences||{})){
    const v=entry.immutables[k.slotNames[id]??id].slice(2);
    for(const {start,length} of refs)code=code.slice(0,start*2)+v.slice(64-2*length)+code.slice((start+length)*2);
  }
  for(const [unit,libs] of Object.entries(k.linkReferences||{}))for(const [lib,refs] of Object.entries(libs))
    for(const {start} of refs)code=code.slice(0,start*2)+entry.links[unit+':'+lib].slice(2)+code.slice((start+20)*2);
  return '0x'+code;
}
const routerSource=headSource('payment-router');
const router=routerSource&&compile({[routerSource.unit]:routerSource.content},MANIFEST.builds['payment-router'].settings,[{unit:'PaymentRouter.sol',contract:'PaymentRouter'}])['PaymentRouter.sol:PaymentRouter'];
const routerEntry=MANIFEST.contracts.paymentRouter;
const routerLive=router&&rebuild(router,routerEntry);
const cmp=(liveCode,entry=routerEntry,k=router)=>compareRuntime({compiled:k,liveCode,address:entry.address,kind:entry.kind,expectedImmutables:entry.immutables,expectedLinks:entry.links});
const inSlot=(k,i)=>Object.values(k.immutableReferences||{}).flat().some(({start,length})=>i>=start&&i<start+length);
const executableByte=k=>{let i=100;while(inSlot(k,i))i++;return i;};
const flip=(hex,byte)=>{const i=2+byte*2;return hex.slice(0,i)+(hex.slice(i,i+2)==='00'?'01':'00')+hex.slice(i+2);};

test('the committed manifest is strict, complete for the profile\'s observed runtimes and agrees with independent records',()=>{
  const m=validateManifest(clone(MANIFEST));
  const {profile}=parseProfile(read('contracts/deployments/network-profile-base.json'),{expectedDigest:PROFILE_DIGEST});
  const covered=new Set([...Object.values(m.contracts),...Object.values(m.external)].map(c=>c.profileName).filter(Boolean));
  for(const [name,c] of Object.entries(profile.contracts))if(c.codeProvenance==='observed')assert.ok(covered.has(name),name+' has no source verification entry');
  for(const c of [...Object.values(m.contracts),...Object.values(m.external)])if(c.profileName){
    assert.equal(profile.contracts[c.profileName].codeHash,c.codeHash,c.profileName);
    assert.equal(profile.contracts[c.profileName].address,c.address,c.profileName);
  }
  // Address immutables repeat the profile's getter bindings; the legacy vault repeats the ledger-15d deployment record.
  let checked=0;
  for(const c of Object.values(m.contracts))for(const [k,v] of Object.entries(c.immutables)){
    const g=k.split('.')[1],p=c.profileName&&profile.contracts[c.profileName].immutable[g];
    if(typeof p==='string'&&/^0x[0-9a-f]{40}$/.test(p)){assert.equal(v,word(p),k);checked++;}
  }
  assert.ok(checked>=15);
  const rec=JSON.parse(read('contracts/deployments/ledger-15d-base.json')).sessionVaultV2,impl=m.contracts.legacySessionVaultImplementation;
  assert.equal(impl.immutables['SessionVault.book'],word(rec.SessionVaultFactory.args.book.toLowerCase()));
  assert.equal(BigInt(impl.immutables['SessionVault.maxVault6']),BigInt(rec.SessionVaultFactory.args.maxVault6));
  assert.equal(impl.links['SessionVault.sol:SessionVaultLib'],rec.SessionVaultLib.address.toLowerCase());
  assert.equal(m.contracts.legacySessionVaultLib.immutables.library_deploy_address,word(rec.SessionVaultLib.address.toLowerCase()));
  assert.equal(m.contracts.deployments.links['EnclaveDeployments.sol:EnclaveLedgerBandwidth'],m.contracts.ledgerBandwidthLibrary.address);
  // The registry finding: schema 4 is deployed, not the schema-5 source at HEAD.
  assert.notEqual(m.builds['registry-schema4'].sources['EnclaveRegistry.sol'].sha256,sha256(read('contracts/EnclaveRegistry.sol')));
  assert.match(m.contracts.registry.basis,/registerRelay/);
  assert.equal(m.external.usdc.kind,'upgradeable-proxy');
  for(const b of Object.values(m.builds))assert.match(b.commit,/^[0-9a-f]{40}$/);
});

test('manifest refusals: unknown, missing and unsafe fields',()=>{
  const cases=[
    [m=>{m.extra=1;},/unknown field: manifest.extra/],
    [m=>{m.chainId=1;},/unsupported/],
    [m=>{m.builds.pay.settings.libraries={};},/unknown field/],
    [m=>{m.builds.pay.settings.optimizer.runs=0;},/invalid settings/],
    [m=>{m.builds.pay.commit='cf6022cce3';},/invalid build commit/],
    [m=>{m.builds.pay.sources['EnclavePay.sol'].path='../x.sol';},/invalid source pin/],
    [m=>{m.contracts.enclavePay.address=m.contracts.paymentRouter.address;},/duplicate address/],
    [m=>{m.contracts.enclavePay.build='nope';},/unknown build/],
    [m=>{m.contracts.enclavePay.immutables['EnclavePay.usdc']='0x1234';},/invalid immutable/],
    [m=>{m.contracts.enclavePay.metadataIpfs='0x00';},/invalid code pin/],
    [m=>{delete m.contracts.enclavePay.basis;},/missing field/],
    [m=>{m.external.usdc.kind='contract';},/invalid external/],
    [m=>{delete m.external.usdc.slots.admin;},/missing field/],
  ];
  for(const [mutate,error] of cases){const m=clone(MANIFEST);mutate(m);assert.throws(()=>validateManifest(m),error,String(error));}
});

test('metadata: the IPFS hash solc embeds is reproduced, and its CBOR trailer is parsed',()=>{
  const out=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'A.sol':{content:'// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract A { function f() external pure returns (uint) { return 7; } }'}},
    settings:{optimizer:{enabled:true,runs:200},outputSelection:{'*':{'*':['metadata','evm.deployedBytecode.object']}}}})));
  const a=out.contracts['A.sol'].A,meta=cborMetadata(a.evm.deployedBytecode.object);
  assert.equal(meta.ipfs,ipfsMetadataHash(a.metadata));
  assert.equal(meta.solc,'0.8.35');
  assert.equal(cborMetadata('0x00'),null);
});

test('offline: deployed sources at HEAD rebuild exactly to the live code hashes the manifest records',{skip:!router&&'PaymentRouter.sol at HEAD differs from the deployed source'},()=>{
  assert.equal(keccak256(routerLive),routerEntry.codeHash);
  assert.equal(ipfsMetadataHash(router.metadata),routerEntry.metadataIpfs);
  assert.equal(cmp(routerLive).status,'full-match');
  for(const [build,name] of [['pay','enclavePay'],['key-attestations','keyAttestations']]){
    const s=headSource(build);if(!s)continue;
    const e=MANIFEST.contracts[name],k=compile({[s.unit]:s.content},MANIFEST.builds[build].settings,[{unit:e.unit,contract:e.contract}])[e.unit+':'+e.contract];
    const live=rebuild(k,e);
    assert.equal(keccak256(live),e.codeHash,name);
    assert.equal(cmp(live,e,k).status,'full-match',name);
  }
});

test('mismatches: executable bytes, metadata only, slot values, lengths and empty code are each refused precisely',{skip:!router&&'PaymentRouter.sol at HEAD differs'},()=>{
  const at=executableByte(router),exec=cmp(flip(routerLive,at));
  assert.equal(exec.status,'mismatch');assert.equal(exec.reason,'executable bytes differ');assert.equal(exec.firstDifference,at);assert.equal(exec.differingBytes,1);
  const metaAt=cborMetadata(routerLive).start+10,meta=cmp(flip(routerLive,metaAt));
  assert.equal(meta.status,'mismatch');assert.match(meta.reason,/partial match only/);
  const wrongTreasury=cmp(routerLive,{...routerEntry,immutables:{...routerEntry.immutables,'PaymentRouter.treasury':word('0x'+'9'.repeat(40))}});
  assert.equal(wrongTreasury.status,'mismatch');assert.match(wrongTreasury.problems.join(';'),/PaymentRouter.treasury/);
  const undeclared=cmp(routerLive,{...routerEntry,immutables:{...routerEntry.immutables,'PaymentRouter.extra':word('0x'+'1'.repeat(40))}});
  assert.match(undeclared.problems.join(';'),/PaymentRouter.extra: live absent/);
  const missing=cmp(routerLive,{...routerEntry,immutables:{'PaymentRouter.usdc':routerEntry.immutables['PaymentRouter.usdc']}});
  assert.match(missing.problems.join(';'),/PaymentRouter.treasury: live .* expected undeclared/);
  // One occurrence of an immutable changed: the occurrences no longer agree.
  const ref=router.immutableReferences[Object.keys(router.immutableReferences)[0]];
  if(ref.length>1){const s=ref[1].start;const bad=routerLive.slice(0,2+s*2)+'ff'+routerLive.slice(2+s*2+2);assert.match(cmp(bad).problems.join(';'),/disagree/);}
  assert.equal(cmp(routerLive+'00').reason,'runtime length differs');
  assert.equal(cmp('0x').status,'no-code');
  assert.equal(cmp(undefined).status,'no-code');
});

test('a comment-only source change, or different settings, is not a full match',{skip:!router&&'PaymentRouter.sol at HEAD differs'},()=>{
  const commented=compile({'PaymentRouter.sol':routerSource.content+'\n// reviewed\n'},MANIFEST.builds['payment-router'].settings,[{unit:'PaymentRouter.sol',contract:'PaymentRouter'}])['PaymentRouter.sol:PaymentRouter'];
  const r=cmp(routerLive,routerEntry,commented);
  assert.equal(r.status,'mismatch');assert.match(r.reason,/partial match only/);
  const otherRuns=compile({'PaymentRouter.sol':routerSource.content},{optimizer:{enabled:true,runs:1}},[{unit:'PaymentRouter.sol',contract:'PaymentRouter'}])['PaymentRouter.sol:PaymentRouter'];
  assert.equal(cmp(routerLive,routerEntry,otherRuns).status,'mismatch');
  const renamed=compile({'contracts/PaymentRouter.sol':routerSource.content},MANIFEST.builds['payment-router'].settings,[{unit:'contracts/PaymentRouter.sol',contract:'PaymentRouter'}])['contracts/PaymentRouter.sol:PaymentRouter'];
  assert.match(cmp(routerLive,routerEntry,renamed).reason,/partial match only/);
});

test('libraries and links: linked addresses and a library\'s own-address guard are checked, legacy and viaIR',()=>{
  const src='// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\nlibrary L { event E(uint x); function f(uint x) external returns (uint) { emit E(x); return x + 1; } }\n'+
    'contract C { uint public immutable k; constructor(uint a) { k = a; } function g(uint x) external returns (uint) { return L.f(x) + k; } }';
  const lib='0x'+'ab'.repeat(20),other='0x'+'cd'.repeat(20);
  for(const settings of [{optimizer:{enabled:true,runs:200}},{optimizer:{enabled:true,runs:200},viaIR:true}]){
    const k=compile({'L.sol':src},settings,[{unit:'L.sol',contract:'C'},{unit:'L.sol',contract:'L'}]);
    const c=k['L.sol:C'],l=k['L.sol:L'];
    const cEntry={address:'0x'+'11'.repeat(20),kind:'contract',immutables:{'C.k':word('0x'+'2a')},links:{'L.sol:L':lib}};
    const cLive=rebuild(c,cEntry);
    const ok=compareRuntime({compiled:c,liveCode:cLive,address:cEntry.address,kind:'contract',expectedImmutables:cEntry.immutables,expectedLinks:cEntry.links});
    assert.equal(ok.status,'full-match');assert.equal(ok.links['L.sol:L'],lib);
    const relinked=compareRuntime({compiled:c,liveCode:cLive,address:cEntry.address,kind:'contract',expectedImmutables:cEntry.immutables,expectedLinks:{'L.sol:L':other}});
    assert.match(relinked.problems.join(';'),/link L.sol:L/);
    // The library's guard: legacy codegen writes PUSH20 <self>; viaIR keeps library_deploy_address as an immutable.
    const slot=settings.viaIR?'library_deploy_address':'library_self_address';
    let lLive=l.object;
    if(settings.viaIR)for(const {start,length} of l.immutableReferences.library_deploy_address)lLive=lLive.slice(0,start*2)+word(lib).slice(66-2*length)+lLive.slice((start+length)*2);
    else lLive='73'+lib.slice(2)+lLive.slice(42);
    const lr=compareRuntime({compiled:l,liveCode:'0x'+lLive,address:lib,kind:'library',expectedImmutables:{[slot]:word(lib)},expectedLinks:{}});
    assert.equal(lr.status,'full-match',JSON.stringify(lr));
    const elsewhere=compareRuntime({compiled:l,liveCode:'0x'+lLive,address:other,kind:'library',expectedImmutables:{[slot]:word(lib)},expectedLinks:{}});
    assert.match(elsewhere.problems.join(';'),/own address/);
  }
});

function tempRepo(files){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'deployed-sources-'));
  const git=(...a)=>execFileSync('git',['-C',dir,...a],{encoding:'utf8',env:{...process.env,GIT_AUTHOR_NAME:'t',GIT_AUTHOR_EMAIL:'t@t',GIT_COMMITTER_NAME:'t',GIT_COMMITTER_EMAIL:'t@t'}});
  git('init','-q');
  for(const [p,c] of Object.entries(files)){fs.mkdirSync(path.dirname(path.join(dir,p)),{recursive:true});fs.writeFileSync(path.join(dir,p),c);}
  git('add','.');git('commit','-qm','fixture');
  return {dir,gitDir:path.join(dir,'.git'),commit:git('rev-parse','HEAD').trim(),blob:p=>git('rev-parse','HEAD:'+p).trim()};
}

test('sources come only from the pinned commit, blob and digest',async()=>{
  const content='// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract A {}\n';
  const r=tempRepo({'contracts/A.sol':content});
  try{
    const build={commit:r.commit,sources:{'A.sol':{path:'contracts/A.sol',gitBlob:r.blob('contracts/A.sol'),sha256:sha256(content)}},settings:{optimizer:{enabled:true,runs:200}}};
    assert.deepEqual(await readBuildSources(build,['/nonexistent/.git',r.gitDir]),{'A.sol':content});
    await assert.rejects(readBuildSources({...build,sources:{'A.sol':{...build.sources['A.sol'],gitBlob:'0'.repeat(40)}}},[r.gitDir]),/manifest says/);
    await assert.rejects(readBuildSources({...build,sources:{'A.sol':{...build.sources['A.sol'],sha256:'0'.repeat(64)}}},[r.gitDir]),/source digest mismatch/);
    await assert.rejects(readBuildSources({...build,commit:'1'.repeat(40)},[r.gitDir]),/source unavailable/);
    await assert.rejects(readBuildSources({...build,sources:{'A.sol':{...build.sources['A.sol'],path:'contracts/B.sol'}}},[r.gitDir]),/source unavailable/);
    // An import outside the pinned units is refused rather than resolved from disk.
    assert.throws(()=>compileBuild(solc,build,{'A.sol':'import "./B.sol";\n'+content},[{unit:'A.sol',contract:'A'}]),/compile failed/);
  }finally{fs.rmSync(r.dir,{recursive:true,force:true});}
});

test('the compiler binary is pinned by version, package and soljson digest',()=>{
  assert.equal(typeof loadCompiler(MANIFEST).compile,'function');
  assert.throws(()=>loadCompiler({...MANIFEST,compiler:{...MANIFEST.compiler,version:'0.8.34+commit.x'}}),/compiler/);
  assert.throws(()=>loadCompiler({...MANIFEST,compiler:{...MANIFEST.compiler,soljsonSha256:'0'.repeat(64)}}),/soljson.js digest/);
  assert.throws(()=>loadCompiler({...MANIFEST,compiler:{...MANIFEST.compiler,package:'solc@0.0.1'}}),/solc package/);
});

// ---- end to end with scripted peers ----
const NOW=1_800_000_000_000,HEAD=500n;
function peer({codes,slots={},chainId=8453,hash='0x'+'aa'.repeat(32),age=5000}){
  return {
    async getChainId(){return chainId;},async getBlockNumber(){return HEAD;},
    async getBlock({blockNumber}){return {hash,number:blockNumber,timestamp:BigInt(Math.floor((NOW-age)/1000))};},
    async getCode({address}){return codes[address];},
    async getStorageAt({address,slot}){return slots[address+slot]??'0x'+'0'.repeat(64);},
  };
}
test('end to end: agreeing peers, a full match, a proxy whose implementation is observed but never pinned, and refusals',{skip:!router&&'PaymentRouter.sol at HEAD differs'},async()=>{
  const r=tempRepo({'contracts/PaymentRouter.sol':routerSource.content});
  try{
    const usdcCode='0x6080604052'+'00'.repeat(40)+'a2646970667358221220'+'11'.repeat(32)+'64736f6c634300060c0033';
    const e=MANIFEST.external.usdc;
    const manifest={...clone(MANIFEST),builds:{'payment-router':{commit:r.commit,sources:{'PaymentRouter.sol':{path:'contracts/PaymentRouter.sol',gitBlob:r.blob('contracts/PaymentRouter.sol'),sha256:sha256(routerSource.content)}},settings:MANIFEST.builds['payment-router'].settings}},
      contracts:{paymentRouter:clone(routerEntry)},external:{usdc:{...clone(e),codeHash:keccak256(usdcCode),runtimeBytes:(usdcCode.length-2)/2}}};
    const impl=a=>({[e.address+e.slots.implementation]:word(a),[e.address+e.slots.admin]:word('0x'+'4'.repeat(40))});
    const honest=(implementation='0x'+'2'.repeat(40))=>peer({codes:{[routerEntry.address]:routerLive,[e.address]:usdcCode},slots:impl(implementation)});
    const opts={now:()=>NOW,minIntervalMs:0};
    const live=await readLive(manifest,[honest(),honest()],opts);
    const report=await verifyDeployedSources({manifest,gitDirs:[r.gitDir],live,solc});
    assert.equal(report.ok,true);assert.equal(report.results.paymentRouter.status,'full-match');
    assert.equal(report.external.usdc.status,'proxy-runtime-pinned-source-not-verified');assert.equal(report.external.usdc.implementationPinned,false);
    // Identical runtime at another address does not establish the authority profile's address binding.
    const matchingProfile={contracts:{paymentRouter:{address:routerEntry.address,codeHash:routerEntry.codeHash},usdc:{address:e.address,codeHash:keccak256(usdcCode)}}};
    assert.equal((await verifyDeployedSources({manifest,gitDirs:[r.gitDir],live,solc,profile:matchingProfile})).ok,true);
    const wrongAddresses=clone(matchingProfile);
    wrongAddresses.contracts.paymentRouter.address='0x'+'a'.repeat(40);
    wrongAddresses.contracts.usdc.address='0x'+'b'.repeat(40);
    const mismatchedProfile=await verifyDeployedSources({manifest,gitDirs:[r.gitDir],live,solc,profile:wrongAddresses});
    assert.equal(mismatchedProfile.ok,false);
    assert.match(mismatchedProfile.results.paymentRouter.problems.join(';'),/different contract address/);
    assert.match(mismatchedProfile.external.usdc.problems.join(';'),/different proxy address/);
    // A different implementation behind the same proxy still verifies: the proxy pin says nothing about it.
    const upgraded=await verifyDeployedSources({manifest,gitDirs:[r.gitDir],live:await readLive(manifest,[honest('0x'+'3'.repeat(40)),honest('0x'+'3'.repeat(40))],opts),solc});
    assert.equal(upgraded.ok,true);assert.equal(upgraded.external.usdc.observedImplementation,'0x'+'3'.repeat(40));
    // Two agreeing peers serving altered router bytes are refused at comparison; one liar cannot form a quorum.
    const liar=()=>peer({codes:{[routerEntry.address]:flip(routerLive,executableByte(router)),[e.address]:usdcCode},slots:impl('0x'+'2'.repeat(40))});
    const altered=await verifyDeployedSources({manifest,gitDirs:[r.gitDir],live:await readLive(manifest,[liar(),liar()],opts),solc});
    assert.equal(altered.ok,false);assert.equal(altered.results.paymentRouter.reason,'executable bytes differ');
    assert.match(altered.results.paymentRouter.problems.join(';'),/live code hash differs/);
    await assert.rejects(readLive(manifest,[honest(),liar()],opts),/no fresh agreeing chain quorum/);
    await assert.rejects(readLive(manifest,[honest(),peer({codes:{},chainId:1})],opts),/chain quorum unavailable/);
    await assert.rejects(readLive(manifest,[peer({codes:{},age:600_000}),peer({codes:{},age:600_000})],opts),/stale chain block/);
    const gone=await verifyDeployedSources({manifest,gitDirs:[r.gitDir],live:{codes:{paymentRouter:null,usdc:usdcCode},slots:{usdc:{implementation:'0x0',admin:'0x0'}}},solc});
    assert.equal(gone.results.paymentRouter.status,'no-code');assert.equal(gone.ok,false);
    const swapped=await verifyDeployedSources({manifest,gitDirs:[r.gitDir],live:{codes:{paymentRouter:routerLive,usdc:usdcCode.replace('6080','6081')},slots:{usdc:{implementation:'0x0',admin:'0x0'}}},solc});
    assert.equal(swapped.ok,false);assert.match(swapped.external.usdc.problems.join(';'),/proxy code hash differs/);
  }finally{fs.rmSync(r.dir,{recursive:true,force:true});}
});

test('the command requires the manifest, a git history source and RPCs',async()=>{
  const script=path.join(root,'scripts/network/verify-deployed-sources.mjs');
  const fails=async(args,pattern)=>assert.rejects(run(process.execPath,[script,...args],{cwd:root,timeout:30000}),e=>{assert.match(e.stderr,pattern);return true;});
  await fails([],/usage/);
  await fails(['--manifest','contracts/deployments/source-verification-base.json'],/--git-dir is required/);
  await fails(['--manifest','contracts/deployments/source-verification-base.json','--git-dir','.git'],/two to eight independent HTTPS RPC origins/);
  await fails(['--manifest','contracts/deployments/source-verification-base.json','--git-dir','.git','--profile','contracts/deployments/network-profile-base.json'],/--profile-digest/);
  assert.equal(MANIFEST.kind,MANIFEST_KIND);
});
