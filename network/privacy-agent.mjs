#!/usr/bin/env node
// The host's privacy agent: every app this host serves reaches the internet, and is reached, only through the Enclave
// network (docs/design/enclave-network.md) - two WireGuard circuits through qualified providers, the owner's bring-your-own
// WireGuard peer, or (on a host that opted in) direct hosting on its own qualified public address, as the owner's signed
// v5 network policy says. TUNA (NKN) is retired: a configuration without enclaveNetwork is refused, and the retired TUNA
// settings an older configuration may still carry are ignored.
import {startingShieldTransport} from './shield-starting-transport.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {privateKeyToAccount} from 'viem/accounts';
import {LeaseReader,AdmissionGate} from './lease-reader.mjs';
import {EnclaveNetworkManager} from './wg-manager.mjs';
import {createNetworkHost} from './enclave-network-host.mjs';
import {WgControlTransport} from './wg-control.mjs';
import {createPaidNetwork} from './paid-network.mjs';
import {ShieldHostProof} from './shield-host-proof.mjs';
import {RoutePublisher} from './route-publisher.mjs';
import {EgressMap} from './egress-map.mjs';
import {LocalAppRouter} from './local-app-router.mjs';
import {networkUse} from './network-policy.mjs';
// how long a lease still running on chain is believed from its last agreeing read when a chain read fails outright
const LEASE_GRACE_MS=10*60_000;
// how long one round waits for the chain before it goes on with the held leases (a slow read through a failing control
// circuit must not hold up the round past the 60-s proofs: 2026-10-16 01:41:42Z every k11-4 app lapsed at once)
// 45 s, not 20: reads through the control circuits (two WireGuard hops, several calls) often took longer, so every other
// round logged a failure while the read finished in the background and refreshed the leases anyway (k11-4, 2026-10-18:
// 554 "no chain answer within 20 s" from 11:04Z, no lapse). A lease is good for 90 s from its block (lease-reader.mjs),
// and the guest proofs renew on their own (refreshProofs), so a longer wait holds nothing else up.
export const CHAIN_DEADLINE_MS=45_000;
import {DurableState} from './durable-state.mjs';
import {localAppForwarder} from './local-app-transport.mjs';
import {pvmAppPort,openPvmApp,pvmForwarder} from './pvm-app-transport.mjs';
import {probeGuest} from './guest-probe.mjs';
import {createProbeScheduler} from './probe-scheduler.mjs';
import {GuestdIngress} from './guestd-ingress.mjs';
import {ShieldIngress} from './shield-ingress.mjs';
import {guardedFetch} from './guarded-fetch.mjs';
import {delegatedIPNS} from './discovery-http.mjs';
import {validateAppNames} from './app-ingress.mjs';

// Settings of the retired TUNA transport (and of the TUNA-era direct hosting it carried) that an older configuration may
// still hold. They are ignored, never acted on: no NKN wallet, provider inventory, control guard or currency conversion runs.
export const RETIRED_SETTINGS=['nknRpc','inventory','control','runtime','defaults','tunaUSDC','currencyManagement','connectivity','direct'];
export const NETWORK_REQUIRED='enclaveNetwork configuration required: TUNA is retired, and apps are served only on the Enclave network (docs/design/enclave-network.md)';

// Timely admission is independent of slow allocation and publication work. Even
// a hung RPC, allocator or distributor cannot extend an old authorization.
export class PrivacyAgent {
  constructor({apps,runner,account,leaseReader,probe,distribute,directory,dns,network,qualification,paid=null,chainDeadlineMs=CHAIN_DEADLINE_MS,now=Date.now,log=()=>{}}){
    if(!network)throw new Error(NETWORK_REQUIRED);
    Object.assign(this,{apps,leaseReader,probe,distribute,directory,now,log,network,chainDeadlineMs});this.refreshing=false;this.closed=false;this.publishing=false;this.configured=[];this.proving=new Map();this.proofFailures=new Map();this.chainRead=null;
    this.admission=new AdmissionGate({runner,expected:id=>this.apps.find(a=>a.deploymentId===id)?.expected,now});
    this.manager=new EnclaveNetworkManager({runtime:network.runtime,admission:this.admission,providers:network.providers,byoConfig:network.byoConfig,probeEgress:network.probeEgress,direct:network.direct,hostEgress:network.hostEgress||null,paid,now,log,
      probe:(app,circuit)=>probe(app.deploymentId,app.expected,circuit),publish:(id,routes)=>this.publisher.publish(id,routes)});
    this.publisher=new RoutePublisher({directory:path.join(directory,'routes'),account,lease:id=>leaseReader.get(id),
      policy:id=>this.manager.apps.get(id)?.policy,qualification,now,distribute:async(id,value)=>{
        if(distribute)await distribute(id,value).catch(e=>log('optional route mirror: '+e.message));
      }});
    // apps this host serves reach each other here, not out through one's egress and back through the other's circuits
    this.router=network.localRoutes===false||!network.runtime?.forward?null:new LocalAppRouter({log,forward:(stream,id)=>network.runtime.forward(stream,id),
      target:name=>{for(const app of this.manager.apps.values()){
        if(!app.names?.some(n=>n.toLowerCase()===name))continue;
        // only a website the owner serves publicly, to an app whose lease and guest proof are current
        if(app.isPublic===false||networkUse(app.policy).ingress==='none'||!this.admission.allows(app.id))return null;
        return app.id;
      }return null;}});
    this.egress=new EgressMap({directory,manager:this.manager,dns,router:this.router,now,log});this.status=new DurableState(directory);
  }
  async refreshAuthorization(){
    if(this.refreshing||this.closed)return;this.refreshing=true;this.authorizationRefresh={phase:"chain",startedAt:this.now()};void this.snapshot().catch(e=>this.log(e.message));
    try{
      // A chain read that fails outright (the control circuits or this host's uplink down for a minute) must not lapse
      // every app: leases still running on chain are held up to LEASE_GRACE_MS after their last agreeing read, and the
      // round goes on to the policies and guest proofs (2026-10-13 15:21Z: control circuits down ~1 min -> three apps'
      // egress OFF, their leases fine).
      let leases;
      try{
        // one read at a time: a read still running from an earlier round is not doubled, and that round's leases are held
        if(this.chainRead)throw new Error('the previous chain read has not finished');
        const began=this.now();
        const read=this.chainRead=this.leaseReader.refresh(this.apps.map(a=>a.deploymentId)).finally(()=>{if(this.chainRead===read)this.chainRead=null;
          // a read that answered after the deadline still refreshed the leases: say how long it took (once a minute at most)
          const took=this.now()-began;if(took>this.chainDeadlineMs&&this.now()-(this.lateChainSaid||0)>60_000){this.lateChainSaid=this.now();this.log(`chain read answered after ${Math.round(took/1000)} s (past the ${this.chainDeadlineMs/1000}-s deadline; its leases count)`);}});
        let timer;
        leases=await Promise.race([read,new Promise((_,j)=>{timer=setTimeout(()=>j(new Error(`no chain answer within ${this.chainDeadlineMs/1000} s`)),this.chainDeadlineMs);})]).finally(()=>clearTimeout(timer));
      }
      catch(e){
        const held=this.leaseReader.hold?this.leaseReader.hold(LEASE_GRACE_MS):[];
        this.log(`chain authorization read failed: ${e.message}; ${held.length} running lease(s) held from their last agreeing read`);
        leases=held.map(id=>this.leaseReader.get(id)).filter(Boolean);
      }
      for(const lease of leases)this.admission.observeLease(lease);
      this.authorizationRefresh.phase="policy";void this.snapshot().catch(e=>this.log(e.message));
      const policies=await Promise.allSettled(this.apps.map(async app=>{const lease=this.leaseReader.get(app.deploymentId);
        if(!this.network.onNetwork(app.deploymentId))throw new Error('not on the Enclave network (enclaveNetwork.apps), and TUNA is retired');
        return {...app,isPublic:!!lease?.isPublic,policy:await this.network.policyFor(app,lease)};}));
      const configured=[];policies.forEach((r,i)=>{if(r.status==='fulfilled')configured.push(r.value);else{this.admission.revoke(this.apps[i].deploymentId);this.log(`app policy ${this.apps[i].deploymentId.slice(0,10)}: ${r.reason.message}`);}});
      await this.manager.configure(configured);
      this.configured=configured;
      // guest proofs renew on their own (refreshProofs), so neither a slow app nor a slow round holds up the others
      void this.refreshProofs();
    }catch(e){this.authorizationRefresh.error=e.message;this.log('chain/app authorization: '+e.message);}finally{this.authorizationRefresh.completedAt=this.now();this.authorizationRefresh.phase='idle';this.refreshing=false;this.manager.enforceAdmission();}
  }
  // A proof lasts 60 s and is renewed once 40 s or less remain, every 5 s (a Shield guest makes one report at a time).
  // Each app's renewal runs on its own: one app's slow or hanging probe, or a slow chain round, never delays another
  // app's proof (2026-10-16 01:41:42Z: one round waited on its slowest step and all eight k11-4 apps lapsed together).
  // -> settles when every renewal in flight has.
  refreshProofs(){
    if(this.closed)return Promise.resolve();
    for(const app of this.configured){
      const id=app.deploymentId;
      if(this.proving.has(id)||(this.admission.allows(id)&&this.admission.proofs.get(id).validUntil-this.now()>40000))continue;
      // after a failure the app waits 4 s before it is asked again, and the same failure is logged once a minute (a guest
      // that is still starting answers the same thing for many minutes)
      const failure=this.proofFailures.get(id);
      if(failure&&this.now()-failure.at<4000)continue;
      const run=this.admission.attest(id,(i,expected)=>this.probe(i,expected,null))
        .then(()=>{this.proofFailures.delete(id);})
        .catch(e=>{const kept=this.admission.failed(id,e),line=`${e.message}${kept?' (last proof kept until it expires)':''}`,last=this.proofFailures.get(id);
          const repeat=last&&last.line===line&&this.now()-last.loggedAt<60000;
          this.proofFailures.set(id,{at:this.now(),line,loggedAt:repeat?last.loggedAt:this.now(),count:repeat?last.count+1:1});
          if(!repeat)this.log(`local guest proof ${id.slice(0,10)}: ${line}${last?.line===line&&last.count>1?` (${last.count} more since the last line)`:''}`);})
        .finally(()=>{this.proving.delete(id);this.manager.enforceAdmission();});
      this.proving.set(id,run);
    }
    return Promise.allSettled([...this.proving.values()]);
  }
  async snapshot(){await this.egress.write();await this.status.set('status',{version:2,updatedAt:this.now(),authorizationRefresh:this.authorizationRefresh,apps:this.manager.status().map(app=>({...app,leaseUntil:this.admission.leases.get(app.deploymentId)?.validUntil||0,proofUntil:this.admission.proofs.get(app.deploymentId)?.validUntil||0}))});}
  async start(){
    await this.refreshAuthorization();await this.refreshProofs();if(this.closed)throw new Error('privacy agent stopped during startup');await this.snapshot();
    this.timers=[setInterval(()=>{this.manager.enforceAdmission();void this.snapshot().catch(e=>this.log(e.message));},1000),
      setInterval(()=>void this.refreshAuthorization(),15000),
      setInterval(()=>void this.refreshProofs(),5000),
      setInterval(()=>{if(this.publishing||this.closed)return;this.publishing=true;void Promise.allSettled([...this.manager.apps.values()].map(app=>this.manager.publishApp(app))).finally(()=>{this.publishing=false;});},10000),
      setInterval(()=>void this.manager.reconcile().catch(e=>this.log('circuits: '+e.message)),5000)];
    void this.manager.reconcile().catch(e=>this.log('circuits: '+e.message));return this;
  }
  async close(){if(this.closed)return;this.closed=true;for(const timer of this.timers||[])clearInterval(timer);await this.manager.close();await this.snapshot();this.router?.close();}
}

export async function runPrivacy(configFile){
  const cfg=JSON.parse(await fs.readFile(configFile,'utf8'));
  if(cfg.version!==2||!Array.isArray(cfg.apps)||!cfg.apps.length||cfg.apps.length>256||!path.isAbsolute(cfg.directory))throw new Error('version 2 app configuration required');
  if(!cfg.enclaveNetwork||typeof cfg.enclaveNetwork!=='object')throw new Error(NETWORK_REQUIRED);
  // each line carries its UTC time: a cut stream has to be matched against circuit events, and the log had none
  const log=message=>console.error(new Date().toISOString().slice(11,19)+' [privacy] '+message);
  const retired=RETIRED_SETTINGS.filter(k=>k in cfg);
  if(retired.length)log(`ignoring retired TUNA-era settings: ${retired.join(', ')}`);
  const readJSON=async file=>JSON.parse(await fs.readFile(file,'utf8'));
  let key=cfg.operatorKeyFile?(await fs.readFile(cfg.operatorKeyFile,'utf8')).trim():(await readJSON(cfg.operatorConfigFile)).registryKey;
  const account=privateKeyToAccount(key);key=null;
  // An app's route is decided by its owner's v5 network policy (read from the relay), never by this file: per-app TUNA
  // settings (walletsFile, ownerPolicyFile, internetMode) are ignored.
  const loadApp=async item=>{
    const expected=await readJSON(item.expectedFile);
    if(!expected.appRef||typeof expected.configCid!=='string'||!/^0x[0-9a-f]{64}$/.test(item.deploymentId)||!Array.isArray(item.names)||!item.names.length)throw new Error('explicit app expectations and names required');
    validateAppNames(item.deploymentId,item.names);
    if(item.publishToMirror!==undefined&&typeof item.publishToMirror!=='boolean')throw new Error('publishToMirror must be true or false');
    if(item.startupEgress===true&&(expected.requiresConfigSocketServer!==true||expected.requiresSecretsV1!==true))throw new Error('startup egress needs a configured secret command');
    return {...item,expected};
  };
  const apps=[];
  for(const item of cfg.apps)apps.push(await loadApp(item));
  let verifySnp;
  if(cfg.verifierModule){if(!path.isAbsolute(cfg.verifierModule))throw new Error('local verifier module required');verifySnp=(await import(pathToFileURL(cfg.verifierModule).href)).judge;}
  const windows=process.platform==='win32';let linux,shield,hostProof,pvm;
  if(cfg.pvm){
    // a pVM host (a phone's protected VM): the relay's own pins for the tier, and the loopback port of the VM's TLS app port
    const hex=(xs,re)=>Array.isArray(xs)&&xs.length&&xs.every(x=>re.test(x));
    if(!hex(cfg.pvm.codeHashes,/^[0-9a-f]{64}$/)||!hex(cfg.pvm.authorityHashes,/^[0-9a-f]{128}$/)||!hex(cfg.pvm.runtimeIds,/^[0-9a-f]{64}$/))
      throw new Error('pvm needs codeHashes, authorityHashes and runtimeIds (the tier\'s pins)');
    pvm={appPort:pvmAppPort(cfg.pvm),codeHashes:cfg.pvm.codeHashes,authorityHashes:cfg.pvm.authorityHashes,runtimeIds:cfg.pvm.runtimeIds};
    if(cfg.guestd||cfg.upstream||cfg.shield||cfg.linux)throw new Error('a pVM host takes no guest manager, upstream, Shield or Linux configuration');
  }else if(windows){
    if(!cfg.shield?.policyFile||!cfg.shield?.tpmBinary||!cfg.shield?.tpmSha256)throw new Error('independent Shield platform and TPM pins required');
    shield=await readJSON(cfg.shield.policyFile);hostProof=new ShieldHostProof({binary:cfg.shield.tpmBinary,sha256:cfg.shield.tpmSha256,policy:shield});
  }else{
    if(process.platform!=='linux'||!cfg.linux)throw new Error('supported measured host configuration required');
    linux={...cfg.linux,runtime:await readJSON(cfg.linux.runtimeFile),minTcb:await readJSON(cfg.linux.minTcbFile),vcek:await fs.readFile(cfg.linux.vcekFile),kds:false};
  }
  if(linux&&cfg.linux.certChainFile){
    const seedModule=cfg.linux.snpModule?await import(pathToFileURL(cfg.linux.snpModule).href):await import('../relay/snp-verify.mjs');
    seedModule.seedCertChain(cfg.linux.product,await fs.readFile(cfg.linux.certChainFile,'utf8'));
  }
  let agent,networkHost=null;
  if(windows&&cfg.guestd)throw new Error('Linux guest manager configuration on Windows');
  if(!windows&&cfg.shield?.ingress)throw new Error('Windows partition ingress configuration on Linux');
  const guestd=cfg.guestd?new GuestdIngress({...cfg.guestd,expected:id=>apps.find(a=>a.deploymentId===id)?.expected}):
    cfg.shield?.ingress?new ShieldIngress({...cfg.shield.ingress,expected:id=>apps.find(a=>a.deploymentId===id)?.expected,key:id=>agent?.admission.proofs.get(id)?.spkiSha256}):null;
  const scheduleProbe=createProbeScheduler();
  let wgControl=null,paid=null;
  const close=()=>{hostProof?.close();void Promise.all([agent?.close(),wgControl?.close()]).then(()=>paid?.close()).catch(e=>log(e.message));};
  process.once('SIGTERM',close);process.once('SIGINT',close);
  // SIGHUP re-reads the app list: each app's expectation, names and mirror
  // flag, and any new app, and the operator's host-egress offer (enclaveNetwork.hostEgress). Everything is validated before anything changes; no
  // existing circuit is rebuilt (new names apply to circuits built later).
  // An app dropped from the file is left alone (its lease decides its fate).
  const reloadApps=async()=>{try{
    const fresh=JSON.parse(await fs.readFile(configFile,'utf8'));
    if(!Array.isArray(fresh.apps)||fresh.apps.length>256)throw new Error('version 2 app configuration required');
    const next=[];for(const item of fresh.apps)next.push(await loadApp(item));
    // the operator's uplink pace (enclaveNetwork.paceMbps): circuits built from now on use it; running ones keep theirs
    const pace=fresh.enclaveNetwork?.paceMbps??0;
    if(!(typeof pace==='number'&&Number.isFinite(pace)&&pace>=0&&pace<=100000))throw new Error('enclaveNetwork.paceMbps must be a number of Mbps');
    // the operator's host-egress offer applies without a restart (a malformed block is refused before anything changes)
    const egressChanged=!!networkHost?.hostEgress.update(fresh.enclaveNetwork?.hostEgress);
    let added=0,updated=0;
    for(const n of next){
      const cur=apps.find(a=>a.deploymentId===n.deploymentId);
      if(!cur){apps.push(n);added++;continue;}
      if(JSON.stringify(cur.expected)!==JSON.stringify(n.expected)||JSON.stringify(cur.names)!==JSON.stringify(n.names)||cur.publishToMirror!==n.publishToMirror)updated++;
      for(const k of ['expected','names','publishToMirror','expectedFile','startupEgress'])cur[k]=n[k];
    }
    log(`config reloaded: ${apps.length} apps (${added} added, ${updated} changed); mirror apps: `+(apps.filter(a=>a.publishToMirror).map(a=>a.deploymentId.slice(0,10)).join(',')||'none'));
    if(networkHost&&networkHost.runtime.paceMbps!==pace){networkHost.runtime.paceMbps=pace;log(`circuit pacing now ${pace?pace+' Mbps':'off'} (new circuits)`);}
    if(egressChanged){const o=networkHost.hostEgress.offered;
      log('host egress now offered to: '+(!o?'no apps':o.apps==='all'?'all apps':o.apps.map(id=>id.slice(0,10)).join(',')||'no apps'));
      void agent?.manager.reconcile().catch(e=>log('reconcile: '+e.message));}
  }catch(e){log('config reload refused: '+e.message);}};
  process.on('SIGHUP',()=>void reloadApps());
  // Windows has no SIGHUP: the config file's modification time is the signal
  // there (the reconciler rewrites or touches it), and works on Linux too.
  let configStamp=(await fs.stat(configFile)).mtimeMs;
  setInterval(()=>void fs.stat(configFile).then(st=>{if(st.mtimeMs!==configStamp){configStamp=st.mtimeMs;return reloadApps();}}).catch(e=>log('config watch: '+e.message)),30000).unref();
  const starting=windows&&cfg.shield?.manager?startingShieldTransport(cfg.shield.manager,id=>apps.find(a=>a.deploymentId===id)?.expected):null;
  if(apps.some(a=>a.startupEgress)&&!starting)throw new Error('startup egress needs the local Shield manager');
  // The Enclave network, before the lease reader: with enclaveNetwork.control the host's own chain reads and relay calls
  // leave through two guarded Enclave-network circuits (docs/design/enclave-network.md).
  let leaseReaderLate;
  const directFetch=globalThis.fetch;
  // through the control circuits when they are up; otherwise (or if they fail) directly, with a fresh deadline (the
  // caller's signal may already have expired on the failed attempt)
  const networkFetch=async(url,init={})=>{if(wgControl){try{await wgControl.proxies();return await guardedFetch(wgControl.proxies,{timeoutMs:15000,maxBytes:4194304})(url,init);}catch(e){if(cfg.enclaveNetwork?.controlRequired)throw e;}}
    return directFetch(url,{...init,signal:AbortSignal.timeout(15000)});};
  const network=await createNetworkHost({config:cfg.enclaveNetwork,account,runner:cfg.runner,rpc:cfg.chain?.rpc,addressBook:cfg.chain?.addressBook,
    leaseReader:{registryEntries:(...a)=>leaseReaderLate?leaseReaderLate.registryEntries(...a):Promise.reject(new Error('lease reader not ready yet')),
      bookAddress:(...a)=>leaseReaderLate?leaseReaderLate.bookAddress(...a):Promise.reject(new Error('lease reader not ready yet'))},directory:cfg.directory,log,fetch:networkFetch,
    authorize:id=>!agent?.closed&&!!agent?.admission.allows(id),forward:pvm?pvmForwarder(pvm.appPort):guestd?guestd.forward:localAppForwarder(cfg.upstream)});
  networkHost=network;
  if(cfg.enclaveNetwork.control===true){wgControl=new WgControlTransport({runtime:network.runtime,providers:network.providers,log});await wgControl.start();}
  // paid providers (enclaveNetwork.paid): the lease must carry the on-chain connectivity authorization
  const leaseReader=new LeaseReader({...cfg.chain,...(cfg.enclaveNetwork.paid?{includeConnectivity:'auto',includeHostPayout:true}:{}),...(wgControl?{proxy:wgControl.proxies}:{})});leaseReaderLate=leaseReader;
  paid=cfg.enclaveNetwork.paid?await createPaidNetwork({config:cfg.enclaveNetwork.paid,directory:path.join(cfg.directory,'paid'),leaseReader,providers:network.providers,fetchFn:networkFetch,log}):null;
  agent=new PrivacyAgent({apps,runner:cfg.runner,account,leaseReader,directory:cfg.directory,dns:cfg.dns,network,paid,log,
    // the route publisher attaches the host's direct-hosting qualification to a direct route (v5)
    qualification:network.direct?.envelope,
    distribute:async(id,value)=>{
      if(!value)return;
      const circuits=agent.manager.apps.get(id)?.circuits.filter(c=>c.healthy&&!c.closed&&c.egress)||[];
      // the paths a publication may leave by: the app's own circuits, else (an app with website-only circuits) the
      // host's Enclave-network control circuits; never the host's own address
      const paths=circuits.length?circuits.map(c=>c.transport==='direct'?fetch:guardedFetch(c.egress,{timeoutMs:5000})):wgControl?[guardedFetch(wgControl.proxies,{timeoutMs:8000})]:[];
      if(!paths.length)return;
      const tasks=[];
      // Publishing to Nan's DNS mirror moves an app off the shared route for good
      // (the mirror remembers it), so it is opted into per app, never all at once.
      if(cfg.mirror&&apps.find(a=>a.deploymentId===id)?.publishToMirror===true)tasks.push((async()=>{
        let error;for(const publishFetch of paths){try{
          const post=path=>publishFetch(new URL(path,cfg.mirror),{method:'POST',signal:AbortSignal.timeout(5000),headers:{'content-type':'application/json'},
            body:JSON.stringify({publication:{version:2,endpoint:cfg.endpoint,policy:value.policy,bundle:value.bundle,
              status:agent.manager.status().find(x=>x.deploymentId===id)}})});
          const response=await post('/v1/network/routes');
          if(!response.ok)throw new Error('DNS mirror HTTP '+response.status);return;
        }catch(e){error=e;}}throw error;
      })());
      if(circuits.length)for(const origin of cfg.ipnsRouters||[])tasks.push(delegatedIPNS(origin,circuits[0].egress).publish(value.name,value.ipns));
      const results=await Promise.allSettled(tasks);for(const r of results)if(r.status==='rejected')log('optional discovery transport: '+r.reason.message);
    },
    // Only local attestations need serialization: pinned route probes make no
    // TPM reports and must not delay the 60-second authorization renewal.
    // A route probe pins the TLS key of the app's current local proof (no new
    // guest report); the local proof itself always asks for a fresh report.
    probe:async(id,expected,circuit)=>scheduleProbe(id,!!circuit,async()=>{
      if(circuit&&!agent?.admission.allows(id))throw new Error('no current local guest proof');
      return probeGuest({deploymentId:id,hostname:apps.find(a=>a.deploymentId===id).names[0],expected,
      ...(circuit&&agent?.admission.allows(id)?{pinnedSpkiSha256:agent.admission.proofs.get(id).spkiSha256}:{}),
      ...(!circuit&&pvm?{pvm}:!circuit&&windows?{shield,hostSession:await hostProof.get()}:!circuit?{linux:{...linux,measurement:expected.measurement,release:expected.release},verifySnp}:{}),
      ...(circuit?{address:circuit.address,direct:circuit.transport==='direct',proxy:circuit.transport==='direct'?undefined:circuit.isolation.guardAddress,domainIndependent:circuit.transport!=='direct'&&apps.find(a=>a.deploymentId===id)?.startupEgress===true}:apps.find(a=>a.deploymentId===id)?.startupEgress===true?{openApp:starting,startupEgress:true}:guestd?{openApp:id=>guestd.open(id)}:pvm?{openApp:()=>openPvmApp(pvm.appPort)}:{localUpstream:cfg.upstream})});
    })});
  try{await agent.start();}catch(e){hostProof?.close();await agent.close();await wgControl?.close();throw e;}
  return agent;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
  const i=process.argv.indexOf('--config');runPrivacy(process.argv[i+1]).catch(e=>{console.error(e.message);process.exitCode=1;});
}
