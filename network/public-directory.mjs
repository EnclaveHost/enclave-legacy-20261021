// Independently runnable storage for PUBLIC, signed network records. No fleet,
// account, upload, TLS, custody or BYO secret keys belong in this service.
import {recoverMessageAddress} from 'viem';
import {DurableState} from './durable-state.mjs';
import {verifyProviderRecord,validateQualification,qualificationMessage,eligibleProviders} from './provider-directory.mjs';
import {verifyNetworkPolicy,defaultNetworkPolicy} from './network-policy.mjs';
import {recordHash,verifyRoute} from './route-record.mjs';

const ID=/^0x[0-9a-f]{64}$/;
const equal=(a,b)=>recordHash(a)===recordHash(b);
const empty=()=>({version:1,providers:{},policies:{},publications:{}});
export class PublicDirectory {
  constructor({directory,checkers,hostOperator,leaseOf,verifyOwner,now=Date.now,maxRecords=4096}) {
    if(!Array.isArray(checkers)||!checkers.length)throw Error('explicit checker trust required');
    Object.assign(this,{hostOperator,leaseOf,verifyOwner,now,maxRecords});
    this.checkers=checkers.map(x=>x.toLowerCase());
    this.state=new DurableState(directory);this.floors=new DurableState(directory+'/route-floors');
    this.tail=Promise.resolve();
  }
  async read(){const s=await this.state.get('public-records');if(s&&s.version!==1)throw Error('unsupported directory state');return s||empty();}
  // Serialize verification with acceptance so concurrent older submissions cannot
  // overwrite newer records. Damaged state fails closed rather than resetting floors.
  accept(kind,envelope){
    const run=this.tail.then(()=>this._accept(kind,structuredClone(envelope)));
    this.tail=run.catch(()=>{});return run;
  }
  async _accept(kind,envelope){
    if(Buffer.byteLength(JSON.stringify(envelope))>65536)throw Error('record too large');
    const s=await this.read(),now=this.now();
    if(kind==='provider'){
      if(Object.keys(envelope).some(k=>!['record','signature'].includes(k)))throw Error('unexpected provider data');
      const r=await verifyProviderRecord(envelope,{now,hostOperator:this.hostOperator}),old=s.providers[r.providerId];
      if(old){
        if(old.record.record.issuedAt>r.issuedAt)throw Error('stale provider record');
        if(old.record.record.issuedAt===r.issuedAt){if(!equal(old.record,envelope))throw Error('provider equivocation');return false;}
      } else if(Object.keys(s.providers).length>=this.maxRecords)throw Error('provider capacity reached');
      // Keep only verdicts bound to these exact provider keys/address/operator.
      const qualifications=(old?.qualifications||[]).filter(e=>{
        const q=e.qualification;return q.expiresAt>now&&['providerId','operator','address','wgExitKey','wgGuardKey'].every(k=>q[k]===r[k]);
      });
      s.providers[r.providerId]={record:envelope,qualifications};
    }else if(kind==='qualification'){
      const q=validateQualification(envelope?.qualification),entry=s.providers[q.providerId];
      const signer=(await recoverMessageAddress({message:qualificationMessage(q),signature:envelope.signature})).toLowerCase();
      if(!this.checkers.includes(signer)||signer===q.operator)throw Error('untrusted checker');
      if(q.expiresAt<=now||q.issuedAt>now+60000)throw Error('expired qualification');
      if(!entry||!['providerId','operator','address','wgExitKey','wgGuardKey'].every(k=>q[k]===entry.record.record[k]))throw Error('qualification does not match provider');
      // onchain attestations are distinct signatures; retain them but consumers
      // must verify their contract authorization before settlement.
      if(Object.keys(envelope).some(k=>!['qualification','signature','onchain'].includes(k)))throw Error('unexpected qualification data');
      const list=entry.qualifications||[],next=[];let duplicate=false;
      for(const e of list){
        const who=(await recoverMessageAddress({message:qualificationMessage(e.qualification),signature:e.signature})).toLowerCase();
        if(who!==signer){next.push(e);continue;}
        if(e.qualification.issuedAt>q.issuedAt)throw Error('stale qualification');
        if(e.qualification.issuedAt===q.issuedAt){
          if(!equal(e.qualification,q)||e.signature!==envelope.signature)throw Error('checker equivocation');
          if((e.onchain?.expires||0)>=(envelope.onchain?.expires||0))duplicate=true;
        }
      }
      if(duplicate)return false;
      next.push(envelope);entry.qualifications=next;
    }else if(kind==='policy'){
      if(Object.keys(envelope).some(k=>!['policy','signature'].includes(k)))throw Error('unexpected policy data');
      const id=envelope?.policy?.deploymentId;if(!ID.test(id||''))throw Error('deployment id required');
      const lease=await this.leaseOf(id);if(!lease?.owner)throw Error('deployment owner unavailable');
      const policy=await verifyNetworkPolicy(envelope,{owner:lease.owner,deploymentId:id,verify:this.verifyOwner});
      const old=s.policies[id];
      if(old&&old.owner.toLowerCase()===lease.owner.toLowerCase()){
        if(old.envelope.policy.nonce>policy.nonce)throw Error('stale policy');
        if(old.envelope.policy.nonce===policy.nonce){if(!equal(old.envelope.policy,policy))throw Error('policy equivocation');return false;}
      }else if(!old&&Object.keys(s.policies).length>=this.maxRecords)throw Error('policy capacity reached');
      s.policies[id]={owner:lease.owner,envelope};
    }else if(kind==='route'){
      if(envelope?.version!==2||Object.keys(envelope).some(k=>!['version','endpoint','policy','bundle','status'].includes(k)))throw Error('signed v2 route required');
      const id=envelope.bundle?.record?.deploymentId;if(!ID.test(id||''))throw Error('deployment id required');
      if(!s.publications[id]&&Object.keys(s.publications).length>=this.maxRecords)throw Error('route capacity reached');
      await this.checkRoute(envelope,s);
      // Diagnostic host status is deliberately not replicated; the route itself
      // has all the signed fields required for independent verification.
      const {status,...publicPart}=envelope;s.publications[id]=publicPart;
    }else throw Error('unsupported public record');
    await this.state.set('public-records',s);return true;
  }
  async providers(){return Object.values((await this.read()).providers).filter(e=>e.record.record.expiresAt>this.now());}
  async policy(id){
    if(!ID.test(id))throw Error('deployment id required');
    const e=(await this.read()).policies[id];if(!e)return {envelope:null};
    const lease=await this.leaseOf(id);
    await verifyNetworkPolicy(e.envelope,{owner:lease?.owner,deploymentId:id,verify:this.verifyOwner});
    return {envelope:e.envelope};
  }
  async checkRoute(publication,s){
    const id=publication.bundle.record.deploymentId,lease=await this.leaseOf(id);
    const stored=s.policies[id];
    let policy=defaultNetworkPolicy(id);
    if(stored){policy=await verifyNetworkPolicy(stored.envelope,{owner:lease?.owner,deploymentId:id,verify:this.verifyOwner});}
    if(!equal(policy,publication.policy))throw Error('route policy not available or not current');
    const providers=await eligibleProviders(Object.values(s.providers),{checkers:this.checkers,hostOperator:this.hostOperator,now:this.now()});
    return verifyRoute(publication.bundle,{deploymentId:id,policy,lease,memory:this.floors,networkProviders:providers,providerProbeSigners:this.checkers,now:this.now()});
  }
  async currentRoute(id,s){
    // Acceptance advances the replay floor before persisting public records. A
    // read holding the previous snapshot must wait for that write, then verify
    // the replacement. Also recheck successful reads if policy/provider state
    // changed while RPC verification was in flight. Never serve the old result
    // after a withdrawal, policy change or repeatedly changing snapshot.
    const context=state=>({publication:state.publications[id]??null,policy:state.policies[id]??null,providers:state.providers});
    for(let attempt=0;attempt<3;attempt++){
      let route,error;
      try{route=await this.checkRoute(s.publications[id],s);}catch(e){error=e;}
      await this.tail;
      const latest=await this.read();
      if(equal(context(s),context(latest))){if(error)throw error;return route;}
      s=latest;
    }
    throw Error('route state changed during verification');
  }
  async routes(){
    const s=await this.read(),labels={},deployments={},pending=[],collisions=new Set();
    for(const id of Object.keys(s.publications)){
      try{
        const r=await this.currentRoute(id,s);if(!r.routes.length)continue;
        const addresses=r.routes.map(x=>x.address),label=id.slice(2,10);
        deployments[id]={transport:r.routes[0].transport,expiresAt:r.expiresAt,httpsRoutes:r.routes,discovery:{ipns:r.ipns},version:2};
        if(labels[label]||collisions.has(label)){delete labels[label];collisions.add(label);}else labels[label]={transport:r.routes[0].transport,expiresAt:r.expiresAt,addresses};
      }catch{pending.push({id,reason:'no_current_verified_route'});}
    }
    return {transport:'enclave-network',updatedAt:new Date(this.now()).toISOString(),relays:[],labels,deployments,pending};
  }
  async snapshot(){
    const s=await this.read();
    return {version:1,providers:Object.values(s.providers).filter(e=>e.record.record.expiresAt>this.now()),
      policies:Object.values(s.policies).map(e=>e.envelope),
      publications:Object.values(s.publications).filter(e=>e.bundle.record.expiresAt>this.now())};
  }
  async import(snapshot){
    if(snapshot?.version!==1||!['providers','policies','publications'].every(k=>Array.isArray(snapshot[k])&&snapshot[k].length<=this.maxRecords))throw Error('invalid public snapshot');
    const results={accepted:0,rejected:0};
    // Gossip repeatedly includes the entire snapshot. Already stored exact
    // records need no admission work; reads still revalidate current leases,
    // policies and qualification expiry. Never skip a changed envelope.
    const current=await this.read();
    const put=async(k,e)=>{try{if(await this.accept(k,e))results.accepted++;}catch{results.rejected++;}};
    for(const p of snapshot.providers){
      const old=current.providers[p?.record?.record?.providerId];
      if(!old||!equal(old.record,p.record))await put('provider',p.record);
      for(const q of (p.qualifications||[]).slice(0,16))if(!(old?.qualifications||[]).some(e=>equal(e,q)))await put('qualification',q);
    }
    for(const p of snapshot.policies){const old=current.policies[p?.policy?.deploymentId];if(!old||!equal(old.envelope,p))await put('policy',p);}
    for(const p of snapshot.publications){const old=current.publications[p?.bundle?.record?.deploymentId];if(!old||!equal(old,p))await put('route',p);}
    return results;
  }
}
