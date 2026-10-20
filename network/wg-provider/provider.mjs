// An Enclave-network provider: decides who may hold a WireGuard peer here, in which role, for how long, and keeps
// the kernel (wg + nftables) and the SNI table matching that decision (docs/design/enclave-network.md).
// Everything outside this file is injected: the kernel, the chain, the owner-signature check, the domain map.
import {randomBytes} from 'node:crypto';
import {recoverMessageAddress} from 'viem';
import {canonical} from '../route-record.mjs';
import {defaultNetworkPolicy,admitNetworkPolicy,networkUse} from '../network-policy.mjs';
import {paidGate} from './paid.mjs';

export const REQUEST_MAX_AGE_MS=60000,PEER_TTL_MS=10*60000,MAX_PEERS=2048;
const app=/^0x[0-9a-f]{64}$/,hex32=/^[0-9a-f]{32}$/,wgKey=/^[A-Za-z0-9+/]{43}=$/,address=/^0x[0-9a-fA-F]{40}$/;
export const peerRequestMessage=r=>`enclave-network:peer-request:v1\n${canonical(r)}`;
export const grantMessage=g=>`enclave-network:peer-grant:v1\n${canonical(g)}`;
export const appLabel=id=>id.slice(2,10);

export function validatePeerRequest(r,now=Date.now()){
 const k=r&&typeof r==='object'?Object.keys(r).sort().join(','):'';
 if(k!=='deploymentId,egress,expiresAt,ingress,issuedAt,nonce,policy,providerId,role,runner,version,wgPublicKey'||r.version!==1||
    !app.test(r.deploymentId)||!app.test(r.runner)||!['guard','exit','probe','control'].includes(r.role)||typeof r.providerId!=='string'||!/^[0-9a-f]{16,64}$/.test(r.providerId)||
    !wgKey.test(r.wgPublicKey)||typeof r.egress!=='boolean'||typeof r.ingress!=='boolean'||!hex32.test(r.nonce)||
    !Number.isSafeInteger(r.issuedAt)||!Number.isSafeInteger(r.expiresAt))throw new Error('invalid peer request');
 if(r.role==='guard'&&(r.egress||r.ingress))throw new Error('a guard carries no app traffic of its own');
 if(r.role==='exit'&&!r.egress&&!r.ingress)throw new Error('an exit peer needs ingress or egress');
 // a host's own traffic (chain reads, relay calls): no app, egress only, any active registered host
 if(r.role==='control'&&(!/^0x0{64}$/.test(r.deploymentId)||r.policy!==null||r.ingress||!r.egress))throw new Error('a control peer is egress-only and belongs to no app');
 if(r.role==='probe'&&(r.policy!==null||!/^0x0{64}$/.test(r.runner)||!/^0x0{64}$/.test(r.deploymentId)))throw new Error('a probe peer has no app, runner or policy');
 if(Math.abs(now-r.issuedAt)>REQUEST_MAX_AGE_MS||r.expiresAt<=now||r.expiresAt-r.issuedAt>PEER_TTL_MS+REQUEST_MAX_AGE_MS)throw new Error('stale or overlong peer request');
 if(r.policy!==null&&(typeof r.policy!=='object'||!r.policy.policy||typeof r.policy.signature!=='string'))throw new Error('invalid policy envelope');
 return r;
}

export class WgProvider {
 // config: {providerId, roles:[...], pricePerGiB6, publicAddress, exitKey, guardKey, ports:{exit,guard,control}, zone}
 constructor({config,signer,kernel,leases,hosts=async()=>null,verifyOwner,policyMemory,currentPolicy=async()=>null,domains,targets=async()=>[],store=null,now=Date.now,log=()=>{}}){
  Object.assign(this,{config,signer,kernel,leases,hosts,verifyOwner,policyMemory,currentPolicy,domains,targets,store,now,log});
  this.peers=new Map();          // wg public key -> peer
  this.nonces=new Map();         // request nonce -> expiry (replay)
  this.used=new Set();this.next={exit:2,guard:2};
  this.accepting=true;           // false when over the transfer budget or unqualified: no new peers
 }
 // Restore the peers a previous run granted and that have not expired (a restart keeps every peer at its address);
 // the kernel is brought back to exactly that set.
 async restore(){
  const saved=this.store?await this.store.load():null,now=this.now();
  for(const p of saved?.peers||[]){
   if(!p||p.expiresAt<=now||!/^10\.7[78]\./.test(p.address||''))continue;
   this.peers.set(p.key,p);this.used.add(p.address);
   try{await this.kernel.setPeer({...p,role:p.role==='guard'||p.onGuard?'guard':'exit'});}catch(e){this.log('restore peer: '+e.message);}
  }
  if(saved?.next)this.next={...this.next,...saved.next};
  await this.prune();
  await this.sync();
  return this.peers.size;
 }
 // a failed save is logged, never a refused grant: the kernel already holds the peer
 // The kernel holds exactly the peers in the table: anything else (left by an older run) is removed.
 async prune(){
  if(!this.kernel.listPeers)return;
  for(const iface of ['wg-exit','wg-guard']){
   const want=new Set([...this.peers.values()].filter(p=>(p.role==='guard'||p.onGuard?'wg-guard':'wg-exit')===iface).map(p=>p.key));
   for(const key of await this.kernel.listPeers(iface).catch(()=>[]))if(!want.has(key)){await this.kernel.removePeer({key,role:iface==='wg-guard'?'guard':'exit'}).catch(()=>{});this.log('removed a kernel peer this provider never granted (or no longer holds)');}
  }
 }
 async persist(){if(this.store)await this.store.save({version:1,peers:[...this.peers.values()],next:this.next}).catch(e=>this.log('saving the peer table: '+e.message));}
 allocate(role){
  // 10.77/16 exit, 10.78/16 guard; .0.1 is this side
  const base=role==='exit'?[10,77]:[10,78];
  for(let i=0;i<65000;i++){const n=this.next[role]++;if(this.next[role]>65533)this.next[role]=2;
   const a=`${base[0]}.${base[1]}.${n>>8}.${n&255}`;if(!this.used.has(a)&&(n&255)!==0&&(n&255)!==255){this.used.add(a);return a;}}
  throw new Error('no tunnel addresses left');
 }
 async handle(envelope){
  const now=this.now();
  if(!this.accepting)throw new Error('provider is not accepting peers');
  const r=validatePeerRequest(envelope?.request,now);
  if(r.providerId!==this.config.providerId)throw new Error('request is for another provider');
  const roles=this.config.roles;
  if(r.role==='guard'&&!roles.includes('guard'))throw new Error('this provider is not a guard');
  if(r.role==='exit'&&((r.ingress&&!roles.includes('ingress'))||(r.egress&&!roles.includes('egress'))))throw new Error('this provider does not offer that role');
  for(const [n,exp] of this.nonces)if(exp<now)this.nonces.delete(n);
  if(this.nonces.has(r.nonce))throw new Error('replayed peer request');
  if(typeof envelope.signature!=='string'||!/^0x[0-9a-fA-F]{130}$/.test(envelope.signature))throw new Error('runner signature required');
  const signer=(await recoverMessageAddress({message:peerRequestMessage(r),signature:envelope.signature})).toLowerCase();
  if(r.role==='probe')return this.probe(r,signer,now);
  if(/^0x0{64}$/.test(r.deploymentId))return this.control(r,signer,now);
  // the lease, read with two agreeing RPCs: active, held by this runner, whose registry operator signed
  // a renewal of a peer this provider already holds may lean on the last agreeing lease read while the RPCs disagree
  const lease=await this.leases(r.deploymentId,{renewal:this.peers.get(r.wgPublicKey)?.deploymentId===r.deploymentId});
  if(!lease||!lease.active||lease.runner!==r.runner||String(lease.runnerOperator).toLowerCase()!==signer||!(lease.validUntil>now)||!(lease.leaseUntil>now))
   throw new Error('the request is not from the deployment\'s current runner');
  if(r.ingress&&!lease.isPublic)throw new Error('only public apps get public ingress');
  const policy=await this.policyFor(r.deploymentId,lease.owner,r.policy);
  const use=networkUse(policy);
  const network=use.egress==='enclave-network'||use.ingress==='enclave-network'||use.fallback==='enclave-network';
  if(!network)throw new Error('the app\'s network policy does not use the Enclave network');
  if(r.egress&&use.egress!=='enclave-network'&&use.fallback!=='enclave-network')throw new Error('the policy does not authorize Enclave-network egress');
  if(r.ingress&&use.ingress!=='enclave-network')throw new Error('the policy does not authorize Enclave-network ingress');
  if(this.config.pricePerGiB6>(use.enclaveNetwork?.maxPricePerGiB6??0))throw new Error('provider price is above the policy\'s limit');
  // a paid provider carries an app only under the owner's current on-chain authorization of it (and meters it)
  const paidNonce=this.config.pricePerGiB6>0?paidGate({lease,hostId:this.config.hostId,pricePerGiB6:this.config.pricePerGiB6,now}):null;
  this.nonces.set(r.nonce,now+2*REQUEST_MAX_AGE_MS);
  const names=r.ingress?await this.names(r.deploymentId):[];
  // renewal keeps the address; a new key is a new peer; at most two peers per app and role (circuit handover)
  let peer=this.peers.get(r.wgPublicKey);
  if(peer&&(peer.deploymentId!==r.deploymentId||peer.role!==r.role))throw new Error('key is held by another peer');
  if(!peer){
   if(this.peers.size>=MAX_PEERS)throw new Error('provider is full');
   const same=[...this.peers.values()].filter(p=>p.deploymentId===r.deploymentId&&p.role===r.role).sort((a,b)=>a.createdAt-b.createdAt);
   while(same.length>=2)await this.remove(same.shift(),'replaced');
   peer={key:r.wgPublicKey,role:r.role,deploymentId:r.deploymentId,runner:r.runner,address:this.allocate(r.role),createdAt:now};
  }
  if(peer.paidNonce&&paidNonce!==peer.paidNonce){await this.meterSample?.();}   // a new on-chain policy: new meter
  Object.assign(peer,{egress:r.egress,ingress:r.ingress,names,expiresAt:Math.min(r.expiresAt,now+PEER_TTL_MS),policyNonce:policy.nonce,paidNonce});
  this.peers.set(peer.key,peer);
  await this.kernel.setPeer(peer);
  await this.sync();await this.persist();
  const grant={version:1,providerId:this.config.providerId,role:r.role,deploymentId:r.deploymentId,clientPublicKey:r.wgPublicKey,
   providerPublicKey:r.role==='guard'?this.config.guardKey:this.config.exitKey,
   endpoint:`${this.config.publicAddress}:${r.role==='guard'?this.config.ports.guard:this.config.ports.exit}`,
   clientAddress:peer.address,serverAddress:r.role==='guard'?'10.78.0.1':'10.77.0.1',names,issuedAt:now,expiresAt:peer.expiresAt};
  return {grant,signature:await this.signer.signMessage({message:grantMessage(grant)})};
 }
 // The owner's policy: the newest of the one the runner sent and the one the relay publishes, both owner-signed. A
 // request carrying an older nonce than either this provider has seen is refused, and so is "no policy" once one exists.
 async policyFor(id,owner,sent){
  const opts={owner,deploymentId:id,verify:this.verifyOwner,memory:this.policyMemory};
  const published=await this.currentPolicy(id,owner).catch(()=>null);
  let best=null;
  for(const env of [published,sent])if(env){const p=await admitNetworkPolicy(env,opts);if(!best||p.nonce>best.nonce)best=p;}
  if(sent&&best&&sent.policy.nonce<best.nonce)throw new Error('stale network policy');
  if(!best){const seen=await this.policyMemory.get(id);if(seen!==undefined&&seen>0)throw new Error('the owner\'s network policy is unavailable');return defaultNetworkPolicy(id);}
  return best;
 }
 // A host's own control traffic (two-RPC registry check: an active host whose operator signed): a guard peer, or an
 // egress-only exit peer, at most two of each per host. Never an app's route, never ingress.
 async control(r,signer,now){
  if(r.role!=='guard'&&r.role!=='control')throw new Error('only guard and control peers carry a host\'s own traffic');
  if(r.role==='control'&&!this.config.roles.includes('egress'))throw new Error('this provider does not offer egress');
  const host=await this.hosts(r.runner);
  if(!host||!host.active||String(host.operator).toLowerCase()!==signer)throw new Error('the request is not from an active registered host');
  this.nonces.set(r.nonce,now+2*REQUEST_MAX_AGE_MS);
  let peer=this.peers.get(r.wgPublicKey);
  if(peer&&(peer.role!==r.role||peer.runner!==r.runner||peer.deploymentId!==r.deploymentId))throw new Error('key is held by another peer');
  if(!peer){
   if(this.peers.size>=MAX_PEERS)throw new Error('provider is full');
   const same=[...this.peers.values()].filter(p=>p.runner===r.runner&&p.role===r.role&&p.deploymentId===r.deploymentId).sort((a,b)=>a.createdAt-b.createdAt);
   while(same.length>=2)await this.remove(same.shift(),'replaced');
   peer={key:r.wgPublicKey,role:r.role,deploymentId:r.deploymentId,runner:r.runner,address:this.allocate(r.role==='guard'?'guard':'exit'),createdAt:now,control:true};
  }
  Object.assign(peer,{egress:r.role==='control',ingress:false,names:[],expiresAt:Math.min(r.expiresAt,now+PEER_TTL_MS)});
  this.peers.set(peer.key,peer);await this.kernel.setPeer({...peer,role:r.role==='guard'?'guard':'exit'});await this.sync();await this.persist();
  const guard=r.role==='guard';
  const grant={version:1,providerId:this.config.providerId,role:r.role,deploymentId:r.deploymentId,clientPublicKey:r.wgPublicKey,
   providerPublicKey:guard?this.config.guardKey:this.config.exitKey,endpoint:`${this.config.publicAddress}:${guard?this.config.ports.guard:this.config.ports.exit}`,
   clientAddress:peer.address,serverAddress:guard?'10.78.0.1':'10.77.0.1',names:[],issuedAt:now,expiresAt:peer.expiresAt};
  return {grant,signature:await this.signer.signMessage({message:grantMessage(grant)})};
 }
 // A qualification checker's own peer: exit ingress for one random probe name and/or egress, 5 minutes, through
 // exactly the data path apps use. Only keys in config.checkers (never this provider's operator) may ask.
 async probe(r,signer,now){
  const checkers=(this.config.checkers||[]).map(a=>a.toLowerCase());
  if(!checkers.includes(signer)||signer===String(this.signer.address).toLowerCase())throw new Error('not a trusted checker');
  this.nonces.set(r.nonce,now+2*REQUEST_MAX_AGE_MS);
  // neither ingress nor egress: a probe of the guard path (a peer on wg-guard)
  const onGuard=!r.ingress&&!r.egress;
  if(onGuard&&!this.config.roles.includes('guard'))throw new Error('this provider is not a guard');
  for(const p of [...this.peers.values()])if(p.role==='probe'&&p.checker===signer&&p.onGuard===onGuard)await this.remove(p,'replaced');
  const names=r.ingress?[`probe-${r.nonce}.${this.config.probeZone||'probe.enclave.host'}`]:[];
  const peer={key:r.wgPublicKey,role:'probe',onGuard,deploymentId:r.deploymentId,runner:r.runner,checker:signer,address:this.allocate(onGuard?'guard':'exit'),createdAt:now,
   egress:r.egress,ingress:r.ingress,names,expiresAt:Math.min(r.expiresAt,now+5*60000)};
  if(this.peers.has(peer.key))throw new Error('key is held by another peer');
  this.peers.set(peer.key,peer);await this.kernel.setPeer({...peer,role:onGuard?'guard':'exit'});await this.sync();await this.persist();
  const grant={version:1,providerId:this.config.providerId,role:'probe',deploymentId:r.deploymentId,clientPublicKey:r.wgPublicKey,providerPublicKey:onGuard?this.config.guardKey:this.config.exitKey,
   endpoint:`${this.config.publicAddress}:${onGuard?this.config.ports.guard:this.config.ports.exit}`,clientAddress:peer.address,serverAddress:onGuard?'10.78.0.1':'10.77.0.1',names,issuedAt:now,expiresAt:peer.expiresAt};
  return {grant,signature:await this.signer.signMessage({message:grantMessage(grant)})};
 }
 async names(id){
  const zone=this.config.zone||'app.enclave.host';
  const custom=(await this.domains(id).catch(()=>[])).filter(n=>typeof n==='string'&&n.length<=253&&/^[a-z0-9.-]+$/.test(n)&&!n.endsWith('.'+zone));
  return [`${appLabel(id)}.${zone}`,...custom.slice(0,32)];
 }
 async remove(peer,why){
  if(peer.paidNonce)await this.meterSample?.().catch(e=>this.log('meter: '+e.message));
  this.peers.delete(peer.key);this.used.delete(peer.address);if(peer.paidNonce)await this.meterForget?.(peer.key);
  await this.kernel.removePeer({...peer,role:peer.role==='guard'||peer.onGuard?'guard':'exit'}).catch(e=>this.log(`remove ${peer.role} peer: ${e.message}`));
  this.log(`${peer.role} peer for ${peer.deploymentId.slice(0,10)} removed (${why})`);
  await this.persist();
 }
 // Remove what expired or lost its lease; re-sync firewall sets and the SNI table.
 async sweep(){
  const now=this.now();
  for(const p of [...this.peers.values()]){
   if(p.expiresAt<=now){await this.remove(p,'expired');continue;}
   if(p.role==='probe')continue;
   // a peer goes only on a definite answer: a read that FAILS (the public RPCs disagree for a moment) keeps it until the
   // next sweep - removing on a failed read tore down every circuit through this provider at once
   if(p.control){let host;try{host=await this.hosts(p.runner);}catch{continue;}if(!host||!host.active)await this.remove(p,'host no longer registered');continue;}
   let lease;try{lease=await this.leases(p.deploymentId,{renewal:true});}catch{continue;}
   if(!lease||!lease.active||lease.runner!==p.runner||!(lease.leaseUntil>now)){await this.remove(p,'lease ended');continue;}
   // the owner revoked or replaced the on-chain authorization, or the budget is spent: no more paid traffic
   if(p.paidNonce){let ok=false;try{ok=paidGate({lease,hostId:this.config.hostId,pricePerGiB6:this.config.pricePerGiB6,now})===p.paidNonce;}catch{}if(!ok)await this.remove(p,'paid authorization ended');}
  }
  await this.prune();
  await this.sync();
 }
 async sync(){
  const peers=[...this.peers.values()];
  await this.kernel.sync({
   egress:peers.filter(p=>p.role!=='guard'&&p.egress).map(p=>p.address),
   targets:await this.targets(),     // [{address, ports:{exit,control}}] of qualified providers a guard may reach
  });
 }
 // name -> tunnel address of the newest ingress peer holding it
 route(name){
  name=String(name||'').toLowerCase();let best=null;
  for(const p of this.peers.values())if(p.role!=='guard'&&p.ingress&&p.expiresAt>this.now()&&p.names.includes(name)&&(!best||p.createdAt>best.createdAt))best=p;
  return best?.address||null;
 }
 status(){return {providerId:this.config.providerId,accepting:this.accepting,peers:{guard:[...this.peers.values()].filter(p=>p.role==='guard').length,exit:[...this.peers.values()].filter(p=>p.role==='exit').length}};}
}

export function nonce(){return randomBytes(16).toString('hex');}
