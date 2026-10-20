#!/usr/bin/env node
// Independent direct-host qualification, with the exact same acceptance list
// required of TUNA providers. Never consumes host-supplied pass/fail booleans.
// Independent targets (config.independent === true): the CHECKER's own config names `probeZone` (the reviewed public zone
// the host's canary must be named in) and `outbound` (the HTTPS egress canary). Both are required, neither defaults to an
// Enclave name, and neither is taken from the host's manifest: a manifest whose hostname is outside this checker's zone
// is refused before any probe runs. Without it, the compatibility targets stay (probe-*.enclave.host,
// config.outbound or https://enclave.host/).
import fs from 'node:fs/promises';import path from 'node:path';
import {createPublicClient,createWalletClient,http,parseAbi,keccak256,stringToHex,encodeAbiParameters} from 'viem';
import {privateKeyToAccount} from 'viem/accounts';import {base} from 'viem/chains';
import {providerProbes,probeTargets} from '../../network/provider-probes.mjs';
import {qualifyProvider} from '../../network/provider-qualification.mjs';
const arg=k=>{const i=process.argv.indexOf(k);return i<0?undefined:process.argv[i+1];};
const file=arg('--config');if(!file)throw Error('usage: qualify-provider.mjs --config PRIVATE_CONFIG [--publish]');
const config=JSON.parse(await fs.readFile(file,'utf8'));
const independent=config.independent===true;
if(!independent&&config.probeZone!==undefined)throw Error('probeZone is for independent qualification (independent: true)');
const targets=independent?{independent:true,...probeTargets({independent:true,probeZone:config.probeZone,outbound:config.outbound})}:{outbound:config.outbound};
const signer=privateKeyToAccount((await fs.readFile(config.probeKeyFile,'utf8')).trim());
const manifest=JSON.parse(await fs.readFile(config.manifestFile,'utf8'));
const envelope=await qualifyProvider({hostId:config.hostId,operator:config.operator,address:manifest.address,
 signer,probe:providerProbes(manifest,{proxy:config.proxy,...targets}),validForMs:300000});
// A fresh on-chain signature binds the report to Base, its deployed verifier,
// the registry operator and the exact tested public IP.
const issuedAt=BigInt(Math.floor(envelope.report.issuedAt/1000)),expires=BigInt(Math.floor(envelope.report.expiresAt/1000));
const addressHash=keccak256(stringToHex(manifest.address));
if(!/^0x[0-9a-f]{40}$/i.test(config.connectivity||''))throw Error('deployed connectivity contract required');
const digest=keccak256(encodeAbiParameters([{type:'string'},{type:'uint256'},{type:'address'},{type:'bytes32'},{type:'address'},{type:'bytes32'},{type:'uint64'},{type:'uint64'},{type:'uint16'}],
 ['EnclaveConnectivity.qualification.v1',8453n,config.connectivity,config.hostId,config.operator,addressHash,issuedAt,expires,511]));
const signature=await signer.signMessage({message:{raw:digest}});
if(process.argv.includes('--publish')){
 if(!config.rpc?.startsWith('https://'))throw Error('HTTPS Base RPC required');
 const client=createPublicClient({chain:base,transport:http(config.rpc)}),wallet=createWalletClient({account:signer,chain:base,transport:http(config.rpc)});
 if(await client.getChainId()!==8453)throw Error('wrong qualification chain');
 const abi=parseAbi(['function qualify(bytes32,bytes32,uint64,uint64,uint16,bytes)']);const args=[config.hostId,addressHash,issuedAt,expires,511,signature];
 const gas=await client.estimateContractGas({account:signer,address:config.connectivity,abi,functionName:'qualify',args});
 const hash=await wallet.writeContract({address:config.connectivity,abi,functionName:'qualify',args,gas:gas*125n/100n+10000n});
 const receipt=await client.waitForTransactionReceipt({hash,confirmations:2});if(receipt.status!=='success')throw Error('qualification rejected by chain');
 if(envelope.report.expiresAt<=Date.now())throw Error('qualification expired before publication');
}
if(!path.isAbsolute(config.outputFile||''))throw Error('absolute qualification output path required');
const temp=config.outputFile+'.tmp';await fs.writeFile(temp,JSON.stringify(envelope),{mode:0o600});await fs.rename(temp,config.outputFile);
console.log(JSON.stringify({qualified:true,address:manifest.address,expiresAt:envelope.report.expiresAt,onChain:process.argv.includes('--publish')}));
