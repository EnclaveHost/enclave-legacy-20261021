import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {prepareMetalHostPolicy,validateMetalHostPolicy,installMetalHostPolicy} from '../network/metal-host-policy.mjs';
const hostId='0x'+'ab'.repeat(32),ownershipContract='0x'+'11'.repeat(20);
const contracts=Object.fromEntries(['registry','deployments','appCatalog','proofOfTime','enclavePay','verificationFees','sessionVaultFactory','secretVaultV2'].map((k,i)=>[k,'0x'+String(i+1).repeat(40)]));
const wire={version:1,hostId,ownershipContract,pins:{version:1,chainId:8453,contracts},policies:[],policyOrigins:[]};
test('absence preserves legacy mode; malformed or privately extended wire fails closed',()=>{
 assert.equal(prepareMetalHostPolicy(undefined),null);assert.deepEqual(installMetalHostPolicy(undefined),{});
 for(const w of [null,{}, {...wire,registryKey:'private'}, {...wire,ownershipContract:'0x'+'0'.repeat(40)}, {...wire,policies:Array(9).fill({})}, {...wire,pins:{...wire.pins,chainId:1}}])assert.throws(()=>validateMetalHostPolicy(w));
 assert.throws(()=>prepareMetalHostPolicy({hostId,ownershipContract,pinsFile:'/x',policyFiles:[],registryKey:'private'}),/explicit/);
});
test('operator input paths are bounded regular JSON files and parse errors do not expose file content',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'metal-policy-input-'));
 const cfg={hostId,ownershipContract,pinsFile:path.join(dir,'pins'),policyFiles:[]};
 try{
  fs.writeFileSync(cfg.pinsFile,'private-unexpected-data');
  assert.throws(()=>prepareMetalHostPolicy(cfg),e=>e.message==='invalid host policy JSON');
  fs.writeFileSync(cfg.pinsFile,' '.repeat(16385));assert.throws(()=>prepareMetalHostPolicy(cfg),/too large/);
  assert.throws(()=>prepareMetalHostPolicy({...cfg,pinsFile:dir}),/regular file/);
  assert.throws(()=>prepareMetalHostPolicy({...cfg,pinsFile:'relative'}),/absolute/);
  fs.writeFileSync(cfg.pinsFile,JSON.stringify(wire.pins));
  assert.deepEqual(prepareMetalHostPolicy(cfg),wire);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
