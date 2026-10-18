#!/usr/bin/env node
// The Enclave-network qualification checker (docs/design/enclave-network.md, Qualification).
//   node scripts/network/wg-qualify.mjs --key-file checker.key --wg /path/enclave-wg --relay https://api.enclave.host [--loop 240]
//        [--rpc https://… --book 0x…]   (a community provider that passes also gets an on-chain attestation, for paid service)
//   node scripts/network/wg-qualify.mjs --key-file k --wg w --records records.json --out results.json      (tests)
// For every provider record: ask it for this checker's own probe peers (exit, and guard when it offers guard), run every
// check through the real WireGuard path (enclave-wg check), sign the verdict (valid 10 minutes) and publish it. A provider
// that cannot be checked, or fails any check, gets a verdict that says so: hosts treat it as not eligible.
import fs from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import dns from 'node:dns';
import {privateKeyToAccount} from 'viem/accounts';
import {recoverMessageAddress} from 'viem';
import {peerRequestMessage,grantMessage} from '../../network/wg-provider/provider.mjs';
import {wireGuardKeypair} from '../../network/wg-grants.mjs';
import {verifyProviderRecord,signQualification,CHECKS,QUALIFICATION_MAX_MS} from '../../network/provider-directory.mjs';
import {signOnchainQualification,connectivityAddress} from '../../network/onchain-qualification.mjs';
import {createPublicClient,http,parseAbi,stringToHex} from 'viem';
import {hostABI} from '../../network/registry-abi.mjs';
import {base} from 'viem/chains';
import {DirectoryClient} from '../../network/directory-client.mjs';

const arg=(n,d)=>{const i=process.argv.indexOf('--'+n);return i>0?process.argv[i+1]:d;};
const account=privateKeyToAccount((await fs.readFile(arg('key-file'),'utf8')).trim());
if(process.argv.includes('--print-address')){console.log(account.address.toLowerCase());process.exit(0);}
const wgBinary=arg('wg'),relay=arg('relay'),log=m=>console.log(new Date().toISOString(),m);
const directories=arg('directories')||relay?new DirectoryClient({origins:arg('directories')?JSON.parse(arg('directories')):[relay],timeoutMs:15000}):null;
const zero='0x'+'0'.repeat(64);
const chain=arg('rpc')?createPublicClient({chain:base,transport:http(arg('rpc'),{timeout:15000})}):null;
const book=arg('book','0xab214342d5A490150A4A977063A2f88E21F80907');
// a community provider must be the operator of an active registry host (the registry the address book publishes)
let registry=null;
const hostOperator=async hostId=>{if(!chain)return null;
 registry||=await chain.readContract({address:book,abi:parseAbi(['function addr(bytes32) view returns (address)']),functionName:'addr',args:[stringToHex('registry',{size:32})]});
 const h=await chain.readContract({address:registry,abi:hostABI,functionName:'get',args:[hostId]});return h.active?h.operator:null;};

async function probeGrant(rec,role){
 const keys=wireGuardKeypair(),now=Date.now();
 const request={version:1,providerId:rec.providerId,role:'probe',deploymentId:zero,runner:zero,wgPublicKey:keys.publicKey,policy:null,
  ingress:role==='exit',egress:role==='exit',issuedAt:now,nonce:randomBytes(16).toString('hex'),expiresAt:now+5*60000};
 const r=await fetch(`http://${rec.address}:${rec.ports.control}/v1/peer`,{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({request,signature:await account.signMessage({message:peerRequestMessage(request)})}),signal:AbortSignal.timeout(15000)});
 const b=await r.json().catch(()=>({}));if(!r.ok)throw new Error(`${role} probe grant: ${b.error||r.status}`);
 const g=b.grant,signer=(await recoverMessageAddress({message:grantMessage(g),signature:b.signature})).toLowerCase();
 const key=role==='exit'?rec.wgExitKey:rec.wgGuardKey,port=role==='exit'?rec.ports.exit:rec.ports.guard;
 if(signer!==rec.operator||g.providerPublicKey!==key||g.endpoint!==`${rec.address}:${port}`||g.clientPublicKey!==keys.publicKey)throw new Error(`${role} probe grant does not match the provider record`);
 return {keys,grant:g};
}
function runCheck(input){
 return new Promise((resolve,reject)=>{const c=spawn(wgBinary,['check'],{stdio:['pipe','pipe','inherit']});let out='';
  c.stdout.on('data',d=>out+=d);c.on('error',reject);c.on('exit',code=>{try{resolve(JSON.parse(out));}catch{reject(new Error('check exited '+code));}});
  const t=setTimeout(()=>c.kill(),180000);c.on('exit',()=>clearTimeout(t));c.stdin.end(JSON.stringify(input));});
}
// a public mail exchanger that accepts on 25 (resolved by this checker, outside any tunnel), or --smtp ip:port
async function smtpTarget(){
 if(arg('smtp'))return arg('smtp');
 const mx=(await dns.promises.resolveMx(arg('smtp-domain','gmail.com'))).sort((a,b)=>a.priority-b.priority)[0];
 const [a]=await dns.promises.resolve4(mx.exchange);return `${a}:25`;
}
async function qualify(rec,all){
 const failed=why=>({checks:Object.fromEntries(CHECKS.map(c=>[c,false])),details:{error:why}});
 let result;
 try{
  if(!rec.roles.length)throw new Error('the provider offers no roles');
  const exit=rec.roles.some(r=>r!=='guard')?await probeGrant(rec,'exit'):null;
  const guard=rec.roles.includes('guard')?await probeGrant(rec,'guard'):null;
  if(!exit)throw new Error('a guard-only provider is checked through an exit role too; none offered');
  const other=all.find(p=>p.providerId!==rec.providerId&&p.address!==rec.address&&p.roles.some(r=>r!=='guard'));
  result=await runCheck({
   exit:{peer:{privateKey:exit.keys.privateKey,publicKey:exit.grant.providerPublicKey,endpoint:exit.grant.endpoint,addresses:[exit.grant.clientAddress],dns:(arg('dns')||'1.1.1.1,9.9.9.9').split(','),mtu:1340,keepalive:5},probeName:exit.grant.names[0]},
   ...(guard?{guard:{peer:{privateKey:guard.keys.privateKey,publicKey:guard.grant.providerPublicKey,endpoint:guard.grant.endpoint,addresses:[guard.grant.clientAddress],mtu:1420,keepalive:5},allowed:other?`${other.address}:${other.ports.control}`:''}}:{}),
   publicAddress:rec.address,exitPort:rec.ports.exit,outboundURL:arg('outbound','https://example.com/'),payloadBytes:Number(arg('payload',4<<20)),smtpTarget:await smtpTarget()});
 }catch(e){result=failed(e.message);}
 const now=Date.now();
 const q={version:1,providerId:rec.providerId,operator:rec.operator,address:rec.address,wgExitKey:rec.wgExitKey,wgGuardKey:rec.wgGuardKey,roles:rec.roles,
  checks:Object.fromEntries(CHECKS.map(c=>[c,result.checks?.[c]===true])),issuedAt:now,expiresAt:now+QUALIFICATION_MAX_MS};
 return {env:await signQualification(account,q),details:result.details||{}};
}
async function round(){
 let recs;
 if(arg('records'))recs=JSON.parse(await fs.readFile(arg('records'),'utf8'));
 else{const d=await directories.providers({hostOperator});
  recs=[];for(const e of d.providers||[]){try{recs.push(await verifyProviderRecord(e.record,{hostOperator}));}catch(err){log(`skip ${e.record?.record?.providerId?.slice(0,8)}: ${err.message}`);}}}
 const out=[];
 // paid (community) providers also need this checker's attestation on chain; none while no connectivity contract is published
 let connectivity=null;if(chain&&recs.some(r=>r.kind==='community'))connectivity=await connectivityAddress(chain,book).catch(e=>{log('connectivity: '+e.message);return null;});
 for(const rec of recs){
  const {env,details}=await qualify(rec,recs);
  const passed=Object.values(env.qualification.checks).every(Boolean);
  if(passed&&connectivity){try{const onchain=await signOnchainQualification({account,client:chain,connectivity,record:rec});if(onchain){env.onchain=onchain;passed_.set(rec.providerId,{rec,env:{qualification:env.qualification,signature:env.signature}});}}catch(e){log(`on-chain attestation ${rec.address}: ${e.message}`);}}
  else passed_.delete(rec.providerId);
  out.push({...env,details});
  log(`${rec.address} ${rec.region||''}: ${passed?'QUALIFIED':'NOT qualified'} ${passed?'':JSON.stringify(details).slice(0,600)}`);
  if(directories)await directories.publish('/v1/network/qualifications',env).catch(e=>log(`publish ${rec.address}: ${e.message}`));
 }
 if(arg('out'))await fs.writeFile(arg('out'),JSON.stringify(out,null,1));
}
// Paid (community) providers: their on-chain attestation lasts at most 5 minutes, a verdict 10. Between full checks,
// re-sign the attestation every minute for each community provider this checker passed and whose verdict is current.
const passed_=new Map(),passed=passed_;
async function refreshOnchain(){
 if(!chain||!directories||!passed.size)return;
 const connectivity=await connectivityAddress(chain,book);if(!connectivity)return;
 for(const [pid,{rec,env}] of passed){
  if(env.qualification.expiresAt<=Date.now()+60000){passed.delete(pid);continue;}
  const onchain=await signOnchainQualification({account,client:chain,connectivity,record:rec});
  await directories.publish('/v1/network/qualifications',{qualification:env.qualification,signature:env.signature,onchain});
 }
}
const loop=Number(arg('loop',0));
await round();
if(loop>0){setInterval(()=>round().catch(e=>log('round: '+e.message)),loop*1000);setInterval(()=>refreshOnchain().catch(e=>log('on-chain refresh: '+e.message)),60000);}
