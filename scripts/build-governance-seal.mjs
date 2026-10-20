#!/usr/bin/env node
// Offline compilation only. No deployment, owner nomination or signing.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import solc from 'solc';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const directory=process.argv[2];
if(!directory)throw Error('usage: node scripts/build-governance-seal.mjs NEW_OUTPUT_DIRECTORY');
const source=fs.readFileSync(path.join(root,'contracts/GovernanceSeal.sol'),'utf8');
const settings={optimizer:{enabled:true,runs:200},viaIR:true,outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object','evm.deployedBytecode.immutableReferences']}}};
const result=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'GovernanceSeal.sol':{content:source}},settings})));
const errors=(result.errors||[]).filter(e=>e.severity==='error');
if(errors.length)throw Error(errors.map(e=>e.formattedMessage).join('\n'));
const artifact=result.contracts['GovernanceSeal.sol'].GovernanceSeal;
const runtimeBytes=artifact.evm.deployedBytecode.object.length/2;
if(runtimeBytes>24576||artifact.evm.bytecode.object.length/2>49152)throw Error('contract exceeds deployment size limit');
fs.mkdirSync(directory,{recursive:false});
fs.writeFileSync(path.join(directory,'artifacts.json'),JSON.stringify({compiler:solc.version(),settings,
  sourceSha256:createHash('sha256').update(source).digest('hex'),runtimeBytes,artifact},null,2)+'\n');
console.log(JSON.stringify({compiler:solc.version(),runtimeBytes,transactionsSent:0}));
