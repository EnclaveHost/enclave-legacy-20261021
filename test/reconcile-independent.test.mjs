import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {readReconciliationSnapshot,bundleComponentIdentity,validateReconciliationNames,reconciliationNames} from '../network/reconcile-core.mjs';
import {reconcileApps} from '../network/reconcile-apps.mjs';
import {artifactIdentity} from '../sdk/storage/unixfs.mjs';
const id='0x'+'ab'.repeat(32),runner='0x'+'cd'.repeat(32),app='0x'+'12'.repeat(32),ref=`catalog://${app}/3`,now=()=>1700000000000;
const keys=['registry','deployments','appCatalog','proofOfTime','enclavePay','verificationFees','sessionVaultFactory','secretVaultV2'];
const pinDocument={version:1,chainId:8453,contracts:Object.fromEntries(keys.map((k,i)=>[k,'0x'+String(i+1).repeat(40)]))};
const row={id,runner,active:true,isPublic:true,leaseUntil:1700003600n,appRef:ref,configCid:''};
const bytes=Buffer.alloc(700000,0x53),identity=artifactIdentity(bytes);
function bundle(data=bytes,sha=identity.sha256){
 const frame=b=>{const n=Buffer.alloc(4);n.writeUInt32LE(b.length);return Buffer.concat([n,b]);};
 return Buffer.concat([Buffer.from('ENCLAVE-BUNDLE/1\n'),frame(Buffer.from(JSON.stringify({artifact:{sha256:sha}}))),frame(data)]);
}
function client({rows=[row],cid=identity.cid,timestamp=1699999995n,chainId=8453,reorg=false}={}){
 let reads=0;return {
  getChainId:async()=>chainId,getBlockNumber:async()=>1000n,
  getBlock:async()=>({hash:'0x'+(reorg&&reads++?'bb':'aa').repeat(32),timestamp}),
  readContract:async({address,functionName,args,blockNumber})=>{
   assert.equal(blockNumber,998n);assert.notEqual(functionName,'addr','must never read the address book');
   if(functionName==='getVersion'){assert.equal(address,pinDocument.contracts.appCatalog);assert.deepEqual(args,[app,3n]);return {cid};}
   assert.equal(address,pinDocument.contracts.deployments);
   if(functionName==='count')return BigInt(rows.length);
   if(functionName==='getPage')return rows.slice(Number(args[0]),Number(args[0])+Number(args[1]));
   throw Error('unexpected chain call '+functionName);
  }
 };
}
const snapshot=clients=>readReconciliationSnapshot({chain:{addressBook:'0x'+'ff'.repeat(20)},runner,pinDocument,clients,now});
test('fresh agreeing pinned snapshot survives a hostile book and conflicting RPC',async()=>{
 const s=await snapshot([client({cid:'hostile'}),client(),client()]);
 assert.equal(s.rows[0].id,id);assert.equal(s.versions[ref].cid,identity.cid);assert.equal(s.blockNumber,'998');
});
test('no quorum, stale chain, reorg and conflicting catalog data fail closed',async()=>{
 for(const peers of [[client(),client({cid:'wrong'})],[client(),client({chainId:1})],[client({timestamp:1n}),client({timestamp:1n})],[client({reorg:true}),client({reorg:true})]])
  await assert.rejects(snapshot(peers),/quorum/);
});
test('missing, malformed and conflicting pins never fall back to address-book resolution',async()=>{
 await assert.rejects(readReconciliationSnapshot({chain:{},runner,clients:[client(),client()],now}),/pin document/);
 await assert.rejects(readReconciliationSnapshot({chain:{chainId:1},runner,pinDocument,clients:[client(),client()],now}),/chain differs/);
 await assert.rejects(readReconciliationSnapshot({chain:{authorityPins:{deployments:'0x'+'ff'.repeat(20)}},runner,pinDocument,clients:[client(),client()],now}),/conflicts/);
});
test('duplicates and incomplete pages are not accepted as an inventory',async()=>{
 await assert.rejects(snapshot([client({rows:[row,row]}),client({rows:[row,row]})]),/quorum/);
 const peers=[client(),client()];for(const c of peers){const read=c.readContract;c.readContract=a=>a.functionName==='count'?2n:read(a);}
 await assert.rejects(snapshot(peers),/quorum/);
});
test('component identity is computed from bytes without trusting a cached digest or requiring Kubo',()=>{
 assert.deepEqual(bundleComponentIdentity(bundle()),identity);
 assert.throws(()=>bundleComponentIdentity(bundle(Buffer.alloc(bytes.length,0x54))),/digest mismatch/);
 assert.throws(()=>bundleComponentIdentity(bundle().subarray(0,-1)),/truncated/);
 assert.throws(()=>bundleComponentIdentity(Buffer.from('not a bundle')),/invalid/);
});
test('local names support independent domains and preserve existing names without an API',()=>{
 const names=validateReconciliationNames({version:1,deployments:{[id]:['App.Independent.example']}});
 assert.deepEqual(reconciliationNames(id,null,names),['app.independent.example']);
 assert.deepEqual(reconciliationNames(id,{names:['existing.example']}),['existing.example']);
 assert.throws(()=>validateReconciliationNames({version:1,deployments:{[id]:['https://bad.example/']}}));
});
test('new host enrolls, reconciles an upgrade and rejects changed bytes with every HTTP API refused',async t=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'reconcile-independent-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));
 const configFile=path.join(dir,'config.json'),pinFile=path.join(dir,'pins.json'),namesFile=path.join(dir,'names.json'),guestdRoot=path.join(dir,'guests');
 const guest=path.join(guestdRoot,'gd123abc');await fs.mkdir(guest,{recursive:true});
 await fs.writeFile(configFile,JSON.stringify({version:2,runner,chain:{},apps:[],enclaveNetwork:{}}));
 await fs.writeFile(pinFile,JSON.stringify(pinDocument));
 await fs.writeFile(namesFile,JSON.stringify({version:1,deployments:{[id]:['independent.example']}}));
 const instance={ID:'gd123abc',Name:id,Verdict:'attested',Created:'2026-10-19T00:00:00Z',AppID:'11'.repeat(32),RuntimeID:'22'.repeat(32),Releases:['33'.repeat(32)],Measurement:'44'.repeat(48)};
 await fs.writeFile(path.join(guest,'instance.json'),JSON.stringify(instance));await fs.writeFile(path.join(guest,'app.bundle'),bundle());
 let reloaded=0;const original=globalThis.fetch;globalThis.fetch=async()=>{throw Error('Enclave APIs refused');};t.after(()=>{globalThis.fetch=original;});
 const opts={configFile,pinFile,namesFile,guestdRoot,snapshotReader:()=>snapshot([client(),client()]),reloadAgent:async()=>{reloaded++;},log(){}};
 const dry=await reconcileApps({...opts,dryRun:true});assert(dry.changed);assert.equal(reloaded,0);assert.deepEqual(JSON.parse(await fs.readFile(configFile)).apps,[]);
 assert((await reconcileApps(opts)).changed);assert.equal(reloaded,1);
 const cfg=JSON.parse(await fs.readFile(configFile));assert.equal(cfg.apps.length,1);assert.deepEqual(cfg.apps[0].names,['independent.example']);
 let expected=JSON.parse(await fs.readFile(cfg.apps[0].expectedFile));assert.equal(expected.measurement,instance.Measurement);
 instance.Measurement='55'.repeat(48);await fs.writeFile(path.join(guest,'instance.json'),JSON.stringify(instance));
 assert((await reconcileApps({...opts,namesFile:undefined})).changed);assert.equal(reloaded,2);
 expected=JSON.parse(await fs.readFile(cfg.apps[0].expectedFile));assert.equal(expected.measurement,instance.Measurement);
 await fs.writeFile(path.join(guest,'app.bundle'),bundle(Buffer.alloc(bytes.length,0x54)));
 instance.Measurement='66'.repeat(48);await fs.writeFile(path.join(guest,'instance.json'),JSON.stringify(instance));
 assert.equal((await reconcileApps(opts)).changed,false);assert.equal(reloaded,2);
 assert.equal(JSON.parse(await fs.readFile(cfg.apps[0].expectedFile)).measurement,expected.measurement);
});
