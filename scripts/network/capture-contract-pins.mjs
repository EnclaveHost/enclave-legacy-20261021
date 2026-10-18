// Read-only preparation. Capture explicit bindings and bytecode hashes from
// agreeing RPCs before a release; never make a runtime follow the book again.
import {parseArgs} from 'node:util';
import fs from 'node:fs/promises';
import path from 'node:path';
import {parseAbi,stringToHex,keccak256} from 'viem';
import {LeaseReader} from '../../network/lease-reader.mjs';
import {validateContractPins} from '../../network/contract-pins.mjs';
const {values}=parseArgs({options:{book:{type:'string'},out:{type:'string'},rpc:{type:'string',multiple:true}}});
if(!values.book||!values.out)throw Error('usage: --book <address> --out <directory> [--rpc <https-origin> ...]');
const reader=new LeaseReader({addressBook:values.book,rpc:values.rpc||['https://base-rpc.publicnode.com','https://base.drpc.org','https://mainnet.base.org']});
const names=['registry','deployments','appCatalog','proofOfTime','enclavePay','verificationFees','sessionVaultFactory','secretVaultV2'];
const abi=parseAbi(['function addr(bytes32) view returns (address)']);
const observation=await reader.agreed(async(client,blockNumber)=>{
  const rows=await Promise.all(names.map(async name=>{
    const address=(await client.readContract({address:values.book,abi,functionName:'addr',args:[stringToHex(name,{size:32})],blockNumber})).toLowerCase();
    let codeHash=null;
    if(!/^0x0{40}$/.test(address)){
      const code=await client.getCode({address,blockNumber});if(!code||code==='0x')throw Error(name+' has no deployed code');codeHash=keccak256(code);
    }
    return {name,address,codeHash};
  }));
  const contracts=Object.fromEntries(rows.map(r=>[r.name,r.address]));validateContractPins({version:1,chainId:8453,contracts});
  return {contracts,codeHashes:Object.fromEntries(rows.map(r=>[r.name,r.codeHash]))};
});
await fs.mkdir(values.out,{recursive:true});
await fs.writeFile(path.join(values.out,'contract-pins.json'),JSON.stringify({version:1,chainId:8453,contracts:observation.contracts},null,2)+'\n');
await fs.writeFile(path.join(values.out,'contract-pin-observation.json'),JSON.stringify({preparedAt:new Date().toISOString(),book:values.book,
  status:'read-only snapshot, not activated',...observation},null,2)+'\n');
console.log(JSON.stringify({status:'captured-not-activated',block:observation.blockNumber,contracts:observation.contracts}));
