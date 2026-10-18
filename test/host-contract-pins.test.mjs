import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {validateContractPins} from '../network/contract-pins.mjs';
const run=promisify(execFile),keys=['registry','deployments','appCatalog','proofOfTime','enclavePay','verificationFees','sessionVaultFactory','secretVaultV2'];
const document={version:1,chainId:8453,contracts:Object.fromEntries(keys.map((k,i)=>[k,'0x'+String(i+1).repeat(40)]))};
test('pins require complete explicit known bindings and a fixed chain',()=>{
 assert.deepEqual(validateContractPins(document),document.contracts);
 for(const value of [{...document,chainId:1},{...document,contracts:{...document.contracts,registry:undefined}},
   {...document,contracts:{...document.contracts,deployments:'0x'+'0'.repeat(40)}},
   {...document,contracts:{...document.contracts,unexpected:document.contracts.registry}}])assert.throws(()=>validateContractPins(value));
});
test('both runtimes start with a hostile/unreachable book and keep exact pins across subsequent resolves',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'contract-pins-'));const file=path.join(dir,'pins.json');await fs.writeFile(file,JSON.stringify(document));
 try {
  const script=`
    import assert from 'node:assert/strict';
    globalThis.fetch=async()=>{throw Error('a pinned host must not fetch the book');};
    const pins=JSON.parse(process.env.TEST_PINS).contracts;
    const book=await import('./addressbook.js');
    assert.equal(await book.initAddressBook({log(){},warn(){throw Error('book failure must not be hidden');}}),false);
    assert.equal(book.REGISTRY_ADDRESS,pins.registry);assert.equal(book.DEPLOYMENTS_ADDRESS,pins.deployments);
    assert.equal(book.APP_CATALOG_ADDRESS,pins.appCatalog);assert.equal(book.PROOF_OF_TIME_ADDRESS,pins.proofOfTime);
    const chain=await import('./windows/node/chain.mjs');
    for(let i=0;i<2;i++){
      chain.addresses.registry='0x'+'f'.repeat(40);
      const resolved=await chain.resolveAddresses();
      for(const k of ['registry','deployments','appCatalog','proofOfTime','verificationFees'])assert.equal(resolved[k],pins[k]);
    }
    console.log('both pinned runtimes passed');
  `;
  const result=await run(process.execPath,['--input-type=module','-e',script],{cwd:new URL('..',import.meta.url),timeout:10000,
    env:{...process.env,ENCLAVE_CONTRACT_PINS_FILE:file,ADDRESS_BOOK_ADDRESS:'0x'+'f'.repeat(40),REGISTRY_ADDRESS:'0x'+'e'.repeat(40),TEST_PINS:JSON.stringify(document)}});
  assert.match(result.stdout,/both pinned runtimes passed/);
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});
