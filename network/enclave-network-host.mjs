// A host's connection to the Enclave network (docs/design/enclave-network.md): which apps use it, each app's owner-
// signed policy, the verified provider directory, BYO WireGuard configs, and the runtime that builds circuits.
// host config (cfg.enclaveNetwork): {relay, checkers:[...], apps:'all'|[ids], wgBinary, nodeBinary, workerModule,
//   firewallBinary (Windows), registry (registry address, for community providers),
//   hostEgress {apps:'all'|[ids], own:[this host's public addresses]} (optional: the operator lets apps whose owners chose
//   'host' send their outbound traffic through this host's own connection)}
import path from 'node:path';
import dns from 'node:dns';
import {randomBytes} from 'node:crypto';
import {createPublicClient,http} from 'viem';
import {base} from 'viem/chains';
import {WgCircuitRuntime} from './wg-circuit-runtime.mjs';
import {WgGrants} from './wg-grants.mjs';
import {eligibleProviders} from './provider-directory.mjs';
import {admitNetworkPolicy,defaultNetworkPolicy,validateNetworkPolicy,byoReleaseMessage} from './network-policy.mjs';
import {parseWireGuardConfig,wireGuardConfigDigest,privateAddress,ipKind} from './wg-config.mjs';
import {DurableState} from './durable-state.mjs';
import {verifyOwnerSignature} from './owner-signature.mjs';
import {canonical} from './route-record.mjs';
import {guardedFetch} from './guarded-fetch.mjs';
import {DirectRuntime} from './direct-runtime.mjs';
import {createProviderCanary,canaryHostname} from './provider-canary.mjs';
import {ownerNameSource,leaseNameScope} from './owner-names.mjs';
import {verifyQualification} from './provider-qualification.mjs';
import {HostEgress} from './host-egress.mjs';
import fs from 'node:fs/promises';
import {DirectoryClient} from './directory-client.mjs';
import {validateNetworkAuthorities} from './network-authorities.mjs';
import {egressProbeUrls,probeEgressUrls} from './egress-probes.mjs';


// cfg.enclaveNetwork.direct.probe -> the provider canary's configuration (provider-canary.mjs), checked before anything is
// bound or read: {hostname, keyFile, certFile, tokenFile, udpPort, manifestFile, bindHost?, independent?, probeZone?}.
// independent:true names the operator's reviewed probe zone (probe-<label>.<probeZone>); otherwise probe-*.enclave.host.
const PROBE_KEYS=['hostname','keyFile','certFile','tokenFile','udpPort','manifestFile','bindHost','independent','probeZone'];
export function directProbeConfig(p){
 if(!p||typeof p!=='object'||Array.isArray(p))throw new Error('Enclave network: direct.probe must be an object');
 const extra=Object.keys(p).filter(k=>!PROBE_KEYS.includes(k));
 if(extra.length)throw new Error('Enclave network: direct.probe has unknown field(s): '+extra.join(', '));
 for(const k of ['keyFile','certFile','tokenFile','manifestFile'])if(typeof p[k]!=='string'||!path.isAbsolute(p[k]))throw new Error(`Enclave network: direct.probe.${k} must be an absolute path`);
 if(!Number.isInteger(p.udpPort)||p.udpPort<1024||p.udpPort>65535)throw new Error('Enclave network: direct.probe.udpPort must be 1024-65535');
 if(p.bindHost!==undefined&&!ipKind(p.bindHost))throw new Error('Enclave network: direct.probe.bindHost must be an IP address');
 if(p.independent!==undefined&&typeof p.independent!=='boolean')throw new Error('Enclave network: direct.probe.independent must be true or false');
 try{canaryHostname(p);}catch(e){throw new Error('Enclave network: direct.probe: '+e.message);}
 return {...p};
}

// cfg.enclaveNetwork.hostEgress -> {apps, own} or null (absent); a malformed block throws
export function hostEgressOffer(h){
 if(h==null)return null;
 if(h.apps!=='all'&&!(Array.isArray(h.apps)&&h.apps.every(id=>/^0x[0-9a-f]{64}$/.test(id))))throw new Error('Enclave network: hostEgress.apps must be "all" or a list of deployment ids');
 if(h.own!==undefined&&!(Array.isArray(h.own)&&h.own.every(a=>ipKind(a))))throw new Error('Enclave network: hostEgress.own must list IP addresses');
 return {apps:h.apps==='all'?'all':[...h.apps],own:[...(h.own||[])]};
}

// attestedKey(id) -> sha256 hex of the TLS key the host's CURRENT attested guest proof bound (or null): required for
// owner-committed custom names on direct hosting (c.direct.ownerNames), never consulted otherwise. ownerNameRoots is a
// code-level override of the public root store for embedders and tests; no configuration file can set it.
export async function createNetworkHost({config:c,account,runner,rpc,addressBook,authorityPins,leaseReader,providerReader=leaseReader,directory,authorize,forward,attestedKey=null,ownerNameRoots,fetch=globalThis.fetch,now=Date.now,log=()=>{}}){
 if(!c||typeof c!=='object')throw new Error('Enclave network configuration required');
 if(c.relay!==undefined){
  const u=new URL(c.relay);
  if((u.protocol!=='https:'&&!(u.protocol==='http:'&&u.hostname==='127.0.0.1'))||u.username||u.password||u.search||u.hash||u.pathname!=='/')throw new Error('Enclave network: relay HTTPS origin required');
 }
 if(c.byoConfigDirectory!==undefined&&!path.isAbsolute(c.byoConfigDirectory))throw new Error('Enclave network: absolute BYO config directory required');
 if(!Array.isArray(c.checkers)||!c.checkers.length)throw new Error('Enclave network: trusted checker addresses required');
 if(c.apps!=='all'&&!Array.isArray(c.apps))throw new Error('Enclave network: apps must be "all" or a list');
 const pins=authorityPins===undefined?null:validateNetworkAuthorities(authorityPins);
 if(pins&&c.registry&&c.registry.toLowerCase()!==pins.registry)throw Error('Enclave network: registry conflicts with authority pin');
 if(pins&&typeof leaseReader?.agreed!=='function')throw Error('Enclave network: pinned authority requires a quorum reader');
 const probeUrls=egressProbeUrls(c.egressProbeUrls,rpc);
 const onNetwork=id=>c.apps==='all'||c.apps.includes(id);
 const relay=async(p,init)=>{if(!c.relay)throw new Error('BYO requires an operator-local config directory or an explicit relay');const r=await fetch(new URL(p,c.relay),{...init,signal:AbortSignal.timeout(10000)});if(r.status===404)return null;const b=await r.json().catch(()=>null);if(!r.ok)throw new Error(`relay ${p.split('/').slice(0,4).join('/')}: ${b?.error||r.status}`);return b;};
 const directories=new DirectoryClient({origins:c.directories||(c.relay?[c.relay]:[]),fetch});
 const clients=(rpc||[]).map(url=>createPublicClient({chain:base,transport:http(url,{timeout:10000})}));
 // Pinned mode verifies contract owners at the same fresh agreeing chain block.
 const verify=async(owner,message,signature)=>verifyOwnerSignature({clients,reader:pins?leaseReader:undefined,owner,message,signature,addressBook,sessionVaultFactory:pins?.sessionVaultFactory});
 const state=new DurableState(path.join(directory,'enclave-network'));
 const memory={get:async id=>(await state.get('policy-nonces'))?.[id],set:async(id,n)=>state.update('policy-nonces',async old=>({...(old||{}),[id]:n}))};
 const policyCache=new Map();
 // The app's network policy: the owner's newest signed one from the relay, or the default if the owner never set one.
 // Once a nonce has been seen, "none" is refused (a relay that loses or withholds a policy does not reset an app).
 async function policyFor(app,lease){
  if(!lease||lease.id!==app.deploymentId)throw new Error('policy requires the current lease');
  let env=policyCache.get(app.deploymentId);
  if(!env||now()-env.at>15000){
   // an unreachable relay is not an answer: the last policy it gave stays in force for up to 10 minutes (a refresh that
   // throws must not revoke the app; 2026-10-13 15:21Z), while a definite answer (an envelope, or none) replaces it
   try{env={at:now(),value:await directories.policy(app.deploymentId,{owner:lease.owner,verify})};policyCache.set(app.deploymentId,env);}
   catch(e){if(!env||now()-env.at>10*60_000)throw e;}
  }
  if(env.value)return admitNetworkPolicy(env.value,{owner:lease.owner,deploymentId:app.deploymentId,verify,memory});
  const seen=await memory.get(app.deploymentId);
  if(seen!==undefined&&seen>0)throw new Error('the owner\'s network policy is unavailable');
  return validateNetworkPolicy(defaultNetworkPolicy(app.deploymentId));
 }
 let directory_={at:0,list:[]},registryAddress=null;
 async function providers(){
  if(now()-directory_.at<30000)return directory_.list;
  // a community provider must be the operator of its registry host (the registry the address book publishes, unless configured)
  const hostOperator=async hostId=>{const registry=pins?.registry||c.registry||(registryAddress||=await providerReader.bookAddress?.('registry'));if(!registry)return null;
   const [h]=await providerReader.registryEntries(registry,[hostId]);return h?.active?h.operator:null;};
  const d=await directories.providers({hostOperator,now:now()});
  directory_={at:now(),list:await eligibleProviders(d?.providers||[],{checkers:c.checkers,now:now(),hostOperator,log})};
  return directory_.list;
 }
 // An operator-local BYO document, or the legacy relay release to the current
 // runner. Either source must match the owner's signed policy commitment.
 async function byoConfig(app){
  const policy=app.policy;if(policy.mode!=='byo-wireguard')throw new Error('not a BYO app');
  let body;
  if(c.byoConfigDirectory){
   if(!/^0x[0-9a-f]{64}$/.test(app.deploymentId))throw Error('exact BYO deployment id required');
   const file=await fs.open(path.join(c.byoConfigDirectory,app.deploymentId+'.json'),fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0)|(fs.constants.O_NONBLOCK||0));
   try{
    const st=await file.stat();
    if(!st.isFile()||st.size>16384||(process.platform!=='win32'&&((st.mode&0o077)!==0||st.uid!==process.getuid())))throw Error('BYO config must be a private regular file up to 16 KiB owned by this operator');
    const bytes=Buffer.alloc(16385);let size=0;
    while(size<bytes.length){const {bytesRead}=await file.read(bytes,size,bytes.length-size,null);if(!bytesRead)break;size+=bytesRead;}
    if(size>16384)throw Error('BYO config exceeds 16 KiB');
    try{body=JSON.parse(bytes.subarray(0,size).toString('utf8'));}catch{throw Error('invalid BYO config document');}
   }finally{await file.close();}
  }else{
   if(!c.relay)throw new Error('BYO requires an operator-local config directory or an explicit relay');
   const request={version:1,deploymentId:app.deploymentId,runner,issuedAt:now(),nonce:randomBytes(16).toString('hex')};
   body=await relay(`/v1/network/byo/${app.deploymentId}/release`,{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({request,signature:await account.signMessage({message:byoReleaseMessage(request)})})});
  }
  if(!body?.config||!/^[0-9a-f]{64}$/.test(body.salt||''))throw new Error('no BYO WireGuard config on record');
  const {config}=parseWireGuardConfig(body.config);
  if(await wireGuardConfigDigest(body.salt,config)!==policy.byo.configDigest)throw new Error('the stored BYO config is not the one the current policy names');
  let address=config.endpoint.host;
  if(!ipKind(address)){const all=await dns.promises.lookup(address,{all:true});const v4=all.find(a=>a.family===4);if(!v4)throw new Error('BYO endpoint has no IPv4 address');address=v4.address;}
  if(ipKind(address)!==4||privateAddress(address))throw new Error('BYO endpoint must be a public IPv4 address');
  return {...config,endpoint:{address,port:config.endpoint.port}};
 }
 const grants=new WgGrants({account,runner,policy:async id=>{const v=policyCache.get(id)?.value;return v||null;}});
 // paceMbps (optional): the host's uplink in Mbps; circuits pace their UDP to it so a small home-router buffer never drops
 // their bursts (docs/design/enclave-network.md, "Circuit TCP")
 const runtime=new WgCircuitRuntime({directory:path.join(directory,'network-circuits'),wgBinary:c.wgBinary,nodeBinary:c.nodeBinary,workerModule:c.workerModule,firewallBinary:c.firewallBinary,grants,authorize,forward,paceMbps:c.paceMbps||0,log});
 // An egress-only circuit's health: one HTTPS request through it.
 async function probeEgress(app,circuit){
  const f=guardedFetch(circuit.egress,{timeoutMs:15000,maxBytes:65536});
  await probeEgressUrls(f,probeUrls);
 }
 // Direct hosting (c.direct = {address, bindHost?, qualificationFile}): this host opted in to serve apps whose owners
 // chose direct on its own public address. It serves only while a trusted checker's current qualification of exactly
 // this runner, operator and address is on file; free (the host's own connection, no metering to settle).
 let direct=null;
 if(c.direct){
  if(!c.direct.address||!path.isAbsolute(c.direct.qualificationFile||''))throw new Error('Enclave network: direct hosting needs an address and a qualification file');
  // the qualification canary: judged now, started last (below), so a malformed probe is never ignored and nothing is
  // bound while any other part of this configuration can still be refused
  const probe=c.direct.probe===undefined?null:directProbeConfig(c.direct.probe);
  const envelope=async()=>JSON.parse(await fs.readFile(c.direct.qualificationFile,'utf8'));
  const qualification=async()=>{const env=await envelope();const q=await verifyQualification(env,{hostId:runner,operator:account.address,address:c.direct.address,probeSigners:c.checkers,now:now()});return {...q,envelope:env};};
  // Owner-committed custom names (c.direct.ownerNames = {gateways:[...]}, docs/network/independent-name-routing.md): the
  // committed package from the operator's explicit gateways, scoped by the lease this host reads, each name routed only
  // while the guest proves a public certificate for it on its attested key. Absent: platform labels only, as before.
  let ownerNames=null;
  if(c.direct.ownerNames!==undefined){
   const o=c.direct.ownerNames;
   if(!o||typeof o!=='object'||Object.keys(o).some(k=>k!=='gateways'))throw new Error('Enclave network: direct.ownerNames takes only explicit gateways');
   if(typeof attestedKey!=='function'||typeof leaseReader?.get!=='function')throw new Error('Enclave network: owner names need the attested guest key and the lease reader');
   const lease=id=>{const l=leaseReader.get(id);return l&&l.runner===runner?l:null;};
   ownerNames={hosts:ownerNameSource({lease,gateways:o.gateways,fetchImpl:fetch}),scope:id=>leaseNameScope(lease(id)),attestedKey:id=>attestedKey(id)||null,ca:ownerNameRoots};
  }
  const runtimeOptions={address:c.direct.address,bindHost:c.direct.bindHost||'0.0.0.0',httpsPort:c.direct.httpsPort||443,httpPort:c.direct.httpPort||80,authorize,forward,log,ownerNames,
   terms:async()=>{const q=await qualification();return {pricePerGiB6:0,selfHosted:false,expiresAt:q.expiresAt};},
   meter:async()=>({consume(){}})};
  direct={runtime:null,runtimeOptions,probe,qualification,envelope};
 }
 // Host egress: the operator's opt-in to let named apps (or all) leave through this host's own connection. Their
 // destinations see this host's address; the entry refuses private and reserved ranges, SMTP and the host's own addresses.
 // The offer can change while the agent runs (update(), from a config reload): an app no longer offered loses its host
 // circuit on the next reconcile (wg-manager.mjs), and a newly offered one gets it then.
 let offer=hostEgressOffer(c.hostEgress),egress=null;
 const hostEgress={
  allows:id=>!!offer&&(offer.apps==='all'||offer.apps.includes(id)),
  start:a=>{if(!offer)return Promise.reject(new Error('this host does not offer its own connection'));
   egress||=new HostEgress({authorize,own:offer.own,log});egress.own=offer.own;return egress.start(a);},
  close:()=>egress?.close(),
  // -> true when the offer changed; a malformed block throws and leaves the current offer in force
  update(h){const next=hostEgressOffer(h);if(JSON.stringify(next)===JSON.stringify(offer))return false;offer=next;if(egress&&next)egress.own=next.own;return true;},
  get offered(){return offer?{apps:offer.apps,own:[...offer.own]}:null;},
 };
 // Direct hosting starts LAST, after every check above has passed. With a canary (direct.probe) the runtime listens on
 // its public ports now: a checker must reach the canary before any app can be qualified to run here. Without one the
 // runtime listens on the first direct app, as before. Anything already bound is closed if a step fails.
 let closing=null;
 if(direct){
  const {runtimeOptions,probe}=direct;let canary=null,runtimeD=null;
  try{
   if(probe)canary=await createProviderCanary(probe,{address:c.direct.address,ownAddresses:hostEgressOffer(c.hostEgress)?.own||[]});
   runtimeD=new DirectRuntime(canary?{...runtimeOptions,canary}:runtimeOptions);
   if(canary){await runtimeD.listen();log(`direct hosting: qualification canary ${canary.hostname} on ${c.direct.address}`);}
  }catch(e){
   if(runtimeD)await runtimeD.close().catch(()=>{});else await canary?.close().catch(()=>{});
   throw e;
  }
  direct={runtime:runtimeD,qualification:direct.qualification,envelope:direct.envelope};
 }
 // localRoutes: apps on this host reach each other's websites here (local-app-router.mjs); false turns it off
 return {onNetwork,policyFor,providers,byoConfig,runtime,probeEgress,grants,direct,hostEgress,localRoutes:c.localRoutes!==false,
  // releases what this host bound itself: the direct runtime's listeners and its canary (the circuit runtime and host
  // egress keep their own lifecycles)
  // (idempotent: the agent's shutdown and a failed start may both ask)
  close(){return closing||=Promise.resolve(direct?.runtime?.close());}};
}
