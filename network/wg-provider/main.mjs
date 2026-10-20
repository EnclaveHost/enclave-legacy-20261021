// enclave-wg-provider: runs an Enclave-network provider on a Linux server with a public IPv4 address.
//   node wg-provider.mjs /etc/enclave-network/provider.json
//   node wg-provider.mjs --check-config <provider.json>     (validate the bootstrap and exit; install.sh runs it)
// config: {operatorKeyFile, publicAddress, uplink, roles, pricePerGiB6, region, kind, hostId, ports:{exit,guard,control},
//          bootstrap: "explicit" | "legacy" (default), authorityPins, directories:[...],
//          rpc:[two or more https], addressBook, relay, checkers:[...], zone, probeZone, stateDir,
//          budget:{monthlyBytes, stopAt},   (budget: outbound bytes this month; at stopAt the provider stops accepting)
//          proofKeyFile}                    (a paid provider, pricePerGiB6 > 0: a community provider, i.e. a registry host
//                                            [kind community, hostId], co-signs receipts with that host's proof key)
import fs from 'node:fs/promises';
import path from 'node:path';
import {privateKeyToAccount} from 'viem/accounts';
import {createPublicClient,http} from 'viem';
import {base} from 'viem/chains';
import {DirectoryClient} from '../directory-client.mjs';
import {LeaseReader} from '../lease-reader.mjs';
import {WgProvider} from './provider.mjs';
import {Kernel} from './kernel.mjs';
import {createRouter} from './router.mjs';
import {createControl} from './control.mjs';
import {providerIdFor,signProviderRecord,verifyProviderRecord} from '../provider-directory.mjs';
import {verifyOwnerSignature} from '../owner-signature.mjs';
import {PeerMeter,createReceiptCosigner} from './paid.mjs';
import {connectivityAddress,submitAttestations,ensureHost} from '../onchain-qualification.mjs';
import {createWalletClient} from 'viem';
import {resolveProviderBootstrap} from '../service-index.mjs';

const log=m=>console.log(new Date().toISOString(),m);
const checkOnly=process.argv[2]==='--check-config';
const cfg=JSON.parse(await fs.readFile((checkOnly?process.argv[3]:process.argv[2])||'/etc/enclave-network/provider.json','utf8'));
// WHO THIS PROVIDER TRUSTS AND ASKS (network/service-index.mjs resolveProviderBootstrap). "explicit": the operator's own
// pins, RPCs, directories, checkers and zones; no address book, no relay fallback, no enclave.host default. "legacy" (an
// installed provider's config, unchanged): Enclave's defaults exactly as before.
const boot=resolveProviderBootstrap(cfg);
if(checkOnly){
 if(!Array.isArray(cfg.rpc)||cfg.rpc.length<2)throw new Error('two or more RPC endpoints required');
 console.log(JSON.stringify({ok:true,mode:boot.mode,directories:boot.directories,zone:boot.zone,probeZone:boot.probeZone,relay:boot.relay,
  pinned:!!boot.authorityPins,checkers:(cfg.checkers||[]).length,notes:boot.notes}));process.exit(0);
}
const account=privateKeyToAccount((await fs.readFile(cfg.operatorKeyFile,'utf8')).trim());
log(`bootstrap: ${boot.mode}; directories ${boot.directories.join(',')}; ${boot.authorityPins?'pinned contracts':'address book '+boot.addressBook}`);
for(const n of boot.notes)log('bootstrap: '+n);
const directories=new DirectoryClient({origins:boot.directories});
const ports={exit:51820,guard:51821,control:51822,...cfg.ports};
const providerId=providerIdFor(account.address,cfg.publicAddress);
const stateDir=cfg.stateDir||'/var/lib/enclave-network';await fs.mkdir(stateDir,{recursive:true,mode:0o700});
if(!Array.isArray(cfg.rpc)||cfg.rpc.length<2)throw new Error('two or more RPC endpoints required');

// A paid provider charges through the on-chain connectivity contract: it must be a registry host that can sign receipts.
const paid=(cfg.pricePerGiB6||0)>0;
if(paid&&(cfg.kind!=='community'||!/^0x[0-9a-f]{64}$/.test(cfg.hostId||'')||!cfg.proofKeyFile))throw new Error('a paid provider is a community provider (kind community, hostId) with its host\'s proofKeyFile');
const leases=new LeaseReader({rpc:cfg.rpc,addressBook:boot.addressBook,authorityPins:boot.authorityPins,includeHostPayout:true,...(paid?{includeConnectivity:'auto'}:{})});
const clients=cfg.rpc.map(url=>createPublicClient({chain:base,transport:http(url,{timeout:10000})}));
// Owner signatures use the same fresh chain quorum and explicit factory binding.
const verifyOwner=(owner,message,signature)=>verifyOwnerSignature({reader:leases,owner,message,signature,addressBook:boot.addressBook,sessionVaultFactory:leases.authorityPins?.sessionVaultFactory});
const kernel=new Kernel({publicAddress:cfg.publicAddress,uplink:cfg.uplink||'eth0',ports,log});
const keys=await kernel.ensure();
const policyFile=path.join(stateDir,'policy-nonces.json');
let nonces={};try{nonces=JSON.parse(await fs.readFile(policyFile,'utf8'));}catch{}
const policyMemory={get:async id=>nonces[id],set:async(id,n)=>{nonces[id]=n;await fs.writeFile(policyFile+'.tmp',JSON.stringify(nonces),{mode:0o600});await fs.rename(policyFile+'.tmp',policyFile);}};
const relayJSON=async p=>{const r=await fetch(boot.relay+p,{signal:AbortSignal.timeout(10000)});if(r.status===404)return null;if(!r.ok)throw new Error(`relay ${p}: HTTP ${r.status}`);return r.json();};
let domainMap={at:0,map:{}};
// Custom-domain names come only from a relay the configuration names; without one only app-zone names are served.
const domains=async id=>{if(!boot.relay)return [];if(Date.now()-domainMap.at>60000){try{const m=await relayJSON('/v1/domains/map');domainMap={at:Date.now(),map:m||{}};}catch(e){log(e.message);}}
 return Object.entries(domainMap.map?.domains||domainMap.map||{}).filter(([,v])=>(v?.deploymentId||v)===id).map(([k])=>k.toLowerCase());};
let targetCache={at:0,list:[]};
const targets=async()=>{
 if(Date.now()-targetCache.at<60000)return targetCache.list;
 try{const d=await directories.providers({hostOperator:async id=>{const h=await hosts(id);return h?.active?h.operator:null;}});
  // A guard may forward to any provider with a current, operator-signed record that offers an exit role - qualified
  // or not, so qualification itself can test guard paths. Which exits a host USES is decided by qualification, on the host.
  const ok=[];for(const e of d?.providers||[]){try{ok.push(await verifyProviderRecord(e.record,{hostOperator:async id=>{const h=await hosts(id);return h?.active?h.operator:null;}}));}catch{}}
  targetCache={at:Date.now(),list:ok.filter(p=>p.providerId!==providerId&&p.roles.some(r=>r!=='guard')).map(p=>({address:p.address,ports:p.ports}))};
 }catch(e){log('provider directory: '+e.message);}
 return targetCache.list;
};
const config={providerId,hostId:cfg.hostId||null,roles:cfg.roles,pricePerGiB6:cfg.pricePerGiB6||0,publicAddress:cfg.publicAddress,exitKey:keys['wg-exit'],guardKey:keys['wg-guard'],
 ports,zone:boot.zone,probeZone:boot.probeZone,checkers:cfg.checkers||[]};
// a host's own (control) peers: an active registry entry whose operator signed, read with the same two-RPC agreement
const registryAddress=()=>leases.bookAddress('registry');
let registry;const hosts=async id=>{registry||=await registryAddress();const [h]=await leases.registryEntries(registry,[id]);return h||null;};
// the peer table on disk: a restart (an update) keeps every peer at its tunnel address
const peerFile=path.join(stateDir,'peers.json');
// saves are queued (concurrent grants each persist) and each writes its own temporary file before the atomic rename
let saving=Promise.resolve(),seq=0;
const store={load:async()=>{try{return JSON.parse(await fs.readFile(peerFile,'utf8'));}catch{return null;}},
 save:v=>(saving=saving.catch(()=>{}).then(async()=>{const tmp=`${peerFile}.${process.pid}.${++seq}.tmp`;await fs.writeFile(tmp,JSON.stringify(v),{mode:0o600});await fs.rename(tmp,peerFile);}))};
const lastLease=new Map();
const provider=new WgProvider({config,signer:account,kernel,log,policyMemory,verifyOwner,domains,targets,hosts,store,
 leases:async(id,{renewal=false}={})=>{
  try{const l=(await leases.readSnapshot([id]))[0]||null;if(l)lastLease.set(id,{l,at:Date.now()});return l;}
  catch(e){
   // the public RPCs failing to agree for a moment must not end a peer this provider already holds: a renewal (or a
   // sweep) may use the last agreeing read for up to 10 minutes, while that lease still runs; a NEW peer never does
   const c=lastLease.get(id);
   if(renewal&&c&&Date.now()-c.at<10*60000&&Number(c.l.leaseUntil)>Date.now()){log(`lease ${id.slice(0,10)}: ${e.message}; using the agreeing read from ${Math.round((Date.now()-c.at)/1000)} s ago`);return {...c.l,validUntil:Date.now()+30000};}
   throw e;
  }},
 currentPolicy:(id,owner)=>directories.policy(id,{owner,verify:verifyOwner})});
log(`restored ${await provider.restore()} peer(s) from the last run`);
let receipt=null;
if(paid){
 const meter=await new PeerMeter({file:path.join(stateDir,'meter.json'),kernel,log}).load();
 provider.meterSample=()=>meter.sample([...provider.peers.values()]);provider.meterForget=key=>meter.forget(key);
 const proofAccount=privateKeyToAccount((await fs.readFile(cfg.proofKeyFile,'utf8')).trim());
 receipt=createReceiptCosigner({hostId:cfg.hostId,proofAccount,leaseReader:leases,meter,sample:provider.meterSample});
 setInterval(()=>void provider.meterSample().catch(e=>log('meter: '+e.message)),15000).unref?.();
 // On chain, this host offers network service at its record's price, and the checkers' current attestations of it are
 // submitted while it serves (each lasts at most 5 minutes); the operator key pays the gas.
 const wallet=createWalletClient({account,chain:base,transport:http(cfg.rpc[0],{timeout:15000})}),[client]=clients;
 const onchain=async()=>{
  const connectivity=leases.authorityPins?.connectivity??await connectivityAddress(client,boot.addressBook);if(!connectivity||/^0x0{40}$/i.test(connectivity))return;
  if(await ensureHost({wallet,client,connectivity,hostId:cfg.hostId,pricePerGiB6:cfg.pricePerGiB6}))log(`on chain: offering network service at ${cfg.pricePerGiB6} per GiB`);
  const d=await directories.providers({hostOperator:async id=>{const h=await hosts(id);return h?.active?h.operator:null;}});const mine=d?.providers?.find(e=>e.record?.record?.providerId===providerId);
  const sent=await submitAttestations({wallet,client,connectivity,hostId:cfg.hostId,address:cfg.publicAddress,attestations:(mine?.qualifications||[]).map(x=>x.onchain).filter(Boolean)});
  if(sent)log(`on chain: ${sent} checker attestation(s) submitted`);
 };
 setInterval(()=>void onchain().catch(e=>log('on-chain qualification: '+e.message)),30000).unref?.();void onchain().catch(e=>log('on-chain qualification: '+e.message));
}
const meter=new Map();
const count=(to,up,down)=>{const m=meter.get(to)||{up:0,down:0};m.up+=up;m.down+=down;meter.set(to,m);};
// localRoutes: {"<name>": {"host":"127.0.0.1","tls":8443,"http":8080}} - a service on THIS box reached by name on the public
// ports (a secret custodian, docs/security/secret-custody.md). Loopback targets only; a name a peer also claims still
// answers locally, so only names no app can hold belong here.
const localRoutes=new Map(Object.entries(cfg.localRoutes||{}).filter(([n,r])=>/^[a-z0-9.-]{1,253}$/.test(n)&&r&&/^127\.\d+\.\d+\.\d+$/.test(r.host)
 &&Number.isInteger(r.tls)&&Number.isInteger(r.http)).map(([n,r])=>[n,{host:r.host,tls:r.tls,http:r.http}]));
const routeOf=n=>localRoutes.get(n)||provider.route(n);
const routes=[await createRouter({port:443,route:routeOf,tls:true,noSniRoute:cfg.noSniRoute??null,count,log}),await createRouter({port:80,route:routeOf,tls:false,count,log})];
const control=await createControl({provider,receipt,port:ports.control,log,info:()=>({providerId,operator:account.address.toLowerCase(),address:cfg.publicAddress,roles:cfg.roles,
 pricePerGiB6:config.pricePerGiB6,keys:{exit:keys['wg-exit'],guard:keys['wg-guard']},ports,region:cfg.region,kind:cfg.kind||'enclave'})});

// The transfer budget: outbound bytes this calendar month (UTC), kept across restarts and counter resets.
const budgetFile=path.join(stateDir,'transfer.json');
let budget;try{budget=JSON.parse(await fs.readFile(budgetFile,'utf8'));}catch{budget={month:'',used:0,last:null};}
async function checkBudget(){
 const month=new Date().toISOString().slice(0,7),{tx}=await kernel.uplinkBytes();
 if(budget.month!==month)budget={month,used:0,last:tx};
 budget.used+=budget.last===null||tx<budget.last?0:tx-budget.last;budget.last=tx;
 await fs.writeFile(budgetFile+'.tmp',JSON.stringify(budget));await fs.rename(budgetFile+'.tmp',budgetFile);
 const stop=cfg.budget?.stopAt??cfg.budget?.monthlyBytes;
 const over=Number.isFinite(stop)&&budget.used>=stop;
 if(over!==!provider.accepting){provider.accepting=!over;log(over?`transfer budget reached (${budget.used} B this month): not accepting peers`:'transfer budget available: accepting peers');}
}
// The opt-in: this provider's signed record, re-published while it runs. Over budget it publishes no roles.
async function publish(){
 const now=Date.now();
 const record={version:1,providerId,operator:account.address.toLowerCase(),address:cfg.publicAddress,wgExitKey:keys['wg-exit'],wgGuardKey:keys['wg-guard'],ports,
  roles:provider.accepting?cfg.roles:[],pricePerGiB6:config.pricePerGiB6,region:cfg.region||'unknown',kind:cfg.kind||'enclave',hostId:cfg.hostId||null,issuedAt:now,expiresAt:now+30*60000};
 const env=await signProviderRecord(account,record);
 await directories.publish('/v1/network/providers',env);
}
const every=(ms,f,name)=>{const go=()=>f().catch(e=>log(`${name}: ${e.message}`));setInterval(go,ms).unref?.();return go();};
await every(60000,checkBudget,'budget');
every(30000,()=>provider.sweep(),'sweep');
every(10*60000,publish,'publish');
log(`provider ${providerId} up: ${cfg.publicAddress} roles ${cfg.roles.join(',')} exit ${keys['wg-exit']} guard ${keys['wg-guard']}`);
const stop=()=>{for(const r of routes)r.close();control.close();process.exit(0);};
process.on('SIGTERM',stop);process.on('SIGINT',stop);
