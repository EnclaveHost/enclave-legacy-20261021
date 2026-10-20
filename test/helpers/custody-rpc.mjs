import assert from 'node:assert/strict';
import {decodeFunctionData,encodeFunctionResult} from 'viem';
// Exercise the actual ABI/hash-addressed eth_call wire shape in reader tests.
export function wireClient(client,abis) {
  client.request=async({method,params})=>{
    assert.equal(method,'eth_call');
    const [{to,data},block]=params;
    assert.deepEqual(block,{blockHash:'0x'+'ab'.repeat(32),requireCanonical:true});
    const abi=abis[to],{functionName,args}=decodeFunctionData({abi,data});
    const result=await client.readContract({address:to,abi,functionName,args,blockNumber:10n});
    return encodeFunctionResult({abi,functionName,result});
  };
  return client;
}
