// Reproducible cross-language vectors: viem's ABI encoder is independent of
// the measured Go guest's bounded tuple decoder. No network or wallet calls.
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {encodeFunctionResult,toFunctionSelector} from 'viem';
const abi=JSON.parse(fs.readFileSync(new URL('../contracts/EnclaveDeployments.abi.json',import.meta.url)));
const hex=(b,n)=>b.repeat(n);
const id='0x'+hex('11',32),ledger='0x'+hex('22',20),owner='0x'+hex('33',20);
const manifest={version:1,chainId:8453,ledger,deployment:id,owner,appRef:'catalog://explicit/1',appId:hex('44',32),runtimeId:hex('55',32),configText:'{ "endpoint": "https://independent.example" }',secretsMode:'public'};
const raw=JSON.stringify(manifest),commit=s=>JSON.stringify({guestBootstrap:{version:1,sha256:createHash('sha256').update(s).digest('hex')}});
const row={id,owner,appRef:manifest.appRef,ports:'',configCid:commit(raw),gpuMilli:0,cpuMilli:100,appPort:8080,isPublic:true,active:true,createdAt:1700000000n,rate:100n,balance6:10000000n,spent6:0n,runner:'0x'+hex('66',32),runnerOperator:'0x'+hex('77',20),leaseUntil:1800001800n};
const encode=changes=>encodeFunctionResult({abi,functionName:'get',result:{...row,...changes}});
const custody={v:2,chainId:8453,vault:'0x'+hex('88',20),policyRev:'1',secretRev:'1',epoch:1,committeeId:'0x'+hex('99',32),t:2,bundle:hex('ab',125),commitments:hex('02'+'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',2),machines:[1,2,3].map((n)=>({encKey:hex('0'+n,32),endpoint:`https://custodian${n}.example`,enclave:false,indices:[n]}))};
const custodyManifest=JSON.stringify({...manifest,secretsMode:'custody-v2',custody});
const out={id,ledger,owner,now:1800000000,manifest:raw,custodyManifest,appId:manifest.appId,runtimeId:manifest.runtimeId,getSelector:toFunctionSelector('get(bytes32)'),schemaSelector:toFunctionSelector('deploymentsSchema()'),schema:encodeFunctionResult({abi,functionName:'deploymentsSchema',result:16n}),row:encode({}),variants:{
 owner:encode({owner:'0x'+hex('aa',20)}),appRef:encode({appRef:'catalog://other/0'}),runner:encode({runner:'0x'+hex('bb',32)}),operator:encode({runnerOperator:'0x'+hex('bb',20)}),inactive:encode({active:false}),expired:encode({leaseUntil:1799999999n}),noCommitment:encode({configCid:'{}'}),mixedConfig:encode({configCid:JSON.stringify({...JSON.parse(commit(raw)),config:{}})}),mixedConfigCid:encode({configCid:JSON.stringify({...JSON.parse(commit(raw)),configCid:'bafy-legacy'})}),custody:encode({configCid:commit(custodyManifest)}),renewed:encode({leaseUntil:1800003600n}),duplicate:encode({configCid:'{"guestBootstrap":{},"guestBootstrap":'+JSON.stringify(JSON.parse(commit(raw)).guestBootstrap)+'}'})}};
const dest=new URL('../isolation/m2/bootstrap/testdata/vectors.json',import.meta.url);fs.mkdirSync(new URL('.',dest),{recursive:true});fs.writeFileSync(dest,JSON.stringify(out,null,2)+'\n');
console.log('Wrote guest bootstrap ABI vectors; no transactions.');
