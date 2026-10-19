// Read-only capture of the contracts a directory will use instead of the book.
import fs from 'node:fs/promises';
import {parseArgs} from 'node:util';
import {parseAbi,stringToHex,keccak256} from 'viem';
import {LeaseReader} from '../../network/lease-reader.mjs';
import {validateNetworkAuthorities} from '../../network/network-authorities.mjs';
const {values}=parseArgs({options:{book:{type:'string'},out:{type:'string'},'session-factory':{type:'string'},rpc:{type:'string',multiple:true}}});
if(!values.book||!values.out)throw Error('usage: --book <address> --out <new-json-file> [--session-factory <verified-legacy-address>] [--rpc <https-origin> ...]');
const reader=new LeaseReader({addressBook:values.book,rpc:values.rpc||['https://base-rpc.publicnode.com','https://base.drpc.org','https://mainnet.base.org']});
const names=['deployments','registry','connectivity','sessionVaultFactory'],abi=parseAbi(['function addr(bytes32) view returns (address)']);
const observation=await reader.agreed(async(c,blockNumber)=>{
 const bookBindings=Object.fromEntries(await Promise.all(names.map(async name=>[name,(await c.readContract({address:values.book,abi,functionName:'addr',args:[stringToHex(name,{size:32})],blockNumber})).toLowerCase()])));
 const selected={...bookBindings};
 if(values['session-factory']){
  const explicit=values['session-factory'].toLowerCase();
  if(!/^0x0{40}$/.test(selected.sessionVaultFactory)&&selected.sessionVaultFactory!==explicit)throw Error('explicit session factory conflicts with nonempty book binding');
  selected.sessionVaultFactory=explicit;
 }
 const authorityPins=validateNetworkAuthorities(selected),codeHashes={};
 for(const [name,address] of Object.entries(authorityPins)){
  if(/^0x0{40}$/.test(address)){codeHashes[name]=null;continue;}
  const code=await c.getCode({address,blockNumber});if(!code||code==='0x')throw Error(name+' has no deployed code');codeHashes[name]=keccak256(code);
 }
 return {bookBindings,authorityPins,codeHashes};
});
await fs.writeFile(values.out,JSON.stringify({preparedAt:new Date().toISOString(),chainId:8453,book:values.book,
 explicitSessionFactory:values['session-factory']||null,...observation},null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({status:'captured-not-activated',blockNumber:observation.blockNumber,authorityPins:observation.authorityPins}));
