// Serving authorization comes from two independently configured chain RPCs at
// the same recent block. Nan is neither a bootstrap nor an admission dependency.
import {createPublicClient, http, stringToHex} from 'viem';
import {base} from 'viem/chains';
import {canonical} from './route-record.mjs';
import {readConnectivity} from './connectivity-chain.mjs';
import {guardedFetch} from './guarded-fetch.mjs';
import {validateNetworkAuthorities} from './network-authorities.mjs';
const fields=[['id','bytes32'],['owner','address'],['appRef','string'],['ports','string'],['configCid','string'],['gpuMilli','uint16'],['cpuMilli','uint16'],['appPort','uint32'],['isPublic','bool'],['active','bool'],['createdAt','uint64'],['rate','uint256'],['balance6','uint256'],['spent6','uint256'],['runner','bytes32'],['runnerOperator','address'],['leaseUntil','uint64']];
const bookABI=[{type:'function',name:'addr',stateMutability:'view',inputs:[{type:'bytes32'}],outputs:[{type:'address'}]}];
const deploymentABI=[{type:'function',name:'get',stateMutability:'view',inputs:[{type:'bytes32'}],outputs:[{type:'tuple',components:fields.map(([name,type])=>({name,type}))}]}];
const schemaABI=[{type:'function',name:'deploymentsSchema',stateMutability:'view',inputs:[],outputs:[{type:'uint256'}]}];
import {hostABI} from './registry-abi.mjs';
const registryV1ABI=[{type:'function',name:'get',stateMutability:'view',inputs:[{type:'bytes32'}],outputs:[{type:'tuple',components:
  [['endpoint','string'],['repo','string'],['measurement','bytes32'],['operator','address'],['registeredAt','uint64'],['lastSeen','uint64'],['active','bool']].map(([name,type])=>({name,type}))}]}];
function jsonValue(value) {return JSON.parse(JSON.stringify(value,(_k,v)=>typeof v==='bigint'?v.toString():v));}
export class LeaseReader {
  constructor({rpc,chainId=8453,addressBook,authorityPins,maxBlockAgeMs=90000,confirmations=2,clients,proxy,includeHostPayout=false,includeConnectivity=false,now=Date.now}) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(addressBook||'') || !Number.isSafeInteger(chainId) || chainId<=0 ||
        !Number.isSafeInteger(maxBlockAgeMs) || maxBlockAgeMs<1000 || maxBlockAgeMs>120000 || !Number.isSafeInteger(confirmations) || confirmations<1) throw new Error('invalid chain policy');
    if (!clients && (!Array.isArray(rpc) || rpc.length<2 || new Set(rpc.map(s=>new URL(s).hostname)).size!==rpc.length || rpc.some(s=>new URL(s).protocol!=='https:'))) throw new Error('at least two independent HTTPS RPC origins required');
    Object.assign(this,{chainId,addressBook,maxBlockAgeMs,confirmations,includeHostPayout,includeConnectivity,now});
    Object.defineProperty(this,'authorityPins',{value:authorityPins===undefined?null:validateNetworkAuthorities(authorityPins),enumerable:true});
    // Public RPCs meter requests per second. Multicall3 folds a snapshot's
    // same-block reads into one eth_call each, however many apps it covers.
    this.clients=clients||rpc.map(url=>createPublicClient({chain:base,batch:{multicall:{wait:0}},
      transport:http(url,{timeout:14000,retryCount:0,...(proxy?{fetchFn:guardedFetch(proxy,{timeoutMs:6000})}:{})})}));
    this.lastBlock=0n;this.cache=new Map();this.retryDelayMs=400;this.headGraceMs=250;
  }
  // Requests that arrive while a snapshot is queued join it: a burst of
  // publications costs one chain read, not one per app.
  refresh(ids) {
    if(!Array.isArray(ids)||ids.length>256||ids.some(id=>!/^0x[0-9a-f]{64}$/.test(id))) return Promise.reject(new Error('exact deployment ids required'));
    if(!this.queued||this.queued.ids.size+ids.length>256){
      const queued={ids:new Set()};
      queued.run=(this.pending||Promise.resolve()).then(()=>{if(this.queued===queued)this.queued=null;return this.readSnapshot([...queued.ids]);});
      this.pending=queued.run.catch(()=>{});this.queued=queued;
    }
    for(const id of ids)this.queued.ids.add(id);
    return this.queued.run.then(rows=>{const byId=new Map(rows.map(row=>[row.id,row]));return ids.map(id=>byId.get(id)).filter(Boolean);});
  }
  // Only a rate-limit refusal is retried, briefly; a timeout or a wrong answer is not.
  async limited(read) {
    for(let attempt=0;;attempt++){
      try{return await read();}
      catch(e){
        if(attempt>=2||!/rate limit|over rate|too many requests|compute units per second|\b429\b/i.test(String(e?.message)))throw e;
        await new Promise(r=>setTimeout(r,this.retryDelayMs*(attempt+1)*(1+Math.random())));
      }
    }
  }
  // One value read from every peer at the same recent block, returned once two
  // peers agree on it. Every chain answer this class gives comes through here.
  async agreed(read, failures=[]) {
    // Two heads pick the block. A slower peer gets a short grace to join, not its
    // full request timeout: route publications wait on this snapshot.
    const available=await new Promise(resolve=>{
      const heads=[];let settled=0,grace;
      const done=()=>{clearTimeout(grace);resolve([...heads]);};
      for(const c of this.clients)this.limited(async()=>{
        const [chainId,number]=await Promise.all([c.getChainId(),c.getBlockNumber({cacheTime:0})]);
        if(chainId!==this.chainId) throw new Error('wrong chain');
        return {client:c,number};
      }).then(head=>heads.push(head),()=>{}).finally(()=>{
        if(++settled===this.clients.length)done();
        else if(heads.length>=2&&!grace)grace=setTimeout(done,this.headGraceMs);
      });
    });
    if(available.length<2) throw new Error('chain quorum unavailable');
    // A stale outlier cannot keep fresh peers from forming a quorum. Conversely,
    // no one RPC can advance or renew a cached admission on its own.
    available.sort((a,b)=>a.number>b.number?-1:a.number<b.number?1:0);
    // Peers' heads jitter by a block or two between back-to-back snapshots. Never
    // read below the block already accepted; reread it instead. The block-age
    // check below still decides whether that block is fresh enough.
    let blockNumber=available[1].number-BigInt(this.confirmations);
    if(blockNumber<0n)throw new Error('no fresh agreeing chain quorum');
    if(blockNumber<this.lastBlock)blockNumber=this.lastBlock;
    const reads=available.map(({client:c})=>this.limited(async()=>{
      const block=await c.getBlock({blockNumber});
      const timestamp=Number(block.timestamp)*1000;
      if(!Number.isSafeInteger(timestamp)||timestamp>this.now()+5000||timestamp+this.maxBlockAgeMs<=this.now()) throw new Error('stale chain block');
      const value=await read(c,blockNumber);
      // Confirm the numbered block was not replaced while eth_call ran.
      if((await c.getBlock({blockNumber})).hash!==block.hash)throw new Error('chain reorganized during read');
      return {hash:block.hash,blockNumber:String(blockNumber),timestamp,...value};
    }));
    // Read every candidate at the same block concurrently. A slow or faulty
    // third RPC cannot delay two agreeing peers, and a single peer never wins.
    const snapshot=await new Promise((resolve,reject)=>{
      const seen=new Map();let pending=reads.length;
      for(const read of reads)read.then(value=>{
        const key=canonical(value),prior=seen.get(key);if(prior)resolve(value);else seen.set(key,value);
      },e=>failures.push(String(e.shortMessage||e.message).slice(0,400))).finally(()=>{if(--pending===0)reject(new Error('no fresh agreeing chain quorum'));});
    });
    if(blockNumber>this.lastBlock)this.lastBlock=blockNumber;
    return snapshot;
  }
  async readSnapshot(ids) {
    if(!Array.isArray(ids)||ids.length>256||ids.some(id=>!/^0x[0-9a-f]{64}$/.test(id))) throw new Error('exact deployment ids required');
    this.failures=[];
    return this.agreed(async(c,blockNumber)=>{
      const deployments=await this.authorityAddress(c,'deployments',blockNumber);
      if(!/^0x[0-9a-fA-F]{40}$/.test(deployments)||/^0x0{40}$/i.test(deployments))throw new Error('no deployments contract');
      const schema=await c.readContract({address:deployments,abi:schemaABI,functionName:'deploymentsSchema',blockNumber});
      if(![15,16].includes(Number(schema))||(this.includeConnectivity===true&&Number(schema)!==16))throw new Error('unsupported deployments schema');
      let rows=await Promise.all(ids.map(id=>c.readContract({address:deployments,abi:deploymentABI,functionName:'get',args:[id],blockNumber})));
      if(this.includeHostPayout){
        const registry=await this.authorityAddress(c,'registry',blockNumber);
        await Promise.all(rows.map(async row=>{
          if(/^0x0{64}$/.test(row.runner))return;
          const host=await c.readContract({address:registry,abi:hostABI,functionName:'get',args:[row.runner],blockNumber});
          // Withhold only this app: a snapshot shared by many apps must not fail for one.
          if(!host.active||host.operator.toLowerCase()!==row.runnerOperator.toLowerCase()){row.runnerUnavailable=true;return;}
          // The runner's registry entry is active and names this lease's operator, at this block.
          row.runnerRegistered=true;row.runnerPayoutWallet=host.payoutWallet;row.runnerProofKey=host.proofKey;
        }));
      }
      const connectivityAddress=this.includeConnectivity&&Number(schema)>=16?await this.authorityAddress(c,'connectivity',blockNumber):null;
      // 'auto': a book that publishes no connectivity contract (none deployed yet) reads as schema 15 did. Without this the
      // 16d cutover (2026-10-12 16:04Z) made every RPC throw "connectivity contract required": no quorum, every TUNA route refused.
      if(connectivityAddress&&!(this.includeConnectivity==='auto'&&/^0x0{40}$/i.test(connectivityAddress))){
        const address=connectivityAddress;
        rows=await readConnectivity(c,{address,deployments,rows,blockNumber});
        await Promise.all(rows.map(async row=>{row.bandwidthBackingRequired6=await c.readContract({address:deployments,abi:[{type:'function',name:'bandwidthBackingRequired6',stateMutability:'view',inputs:[{type:'bytes32'}],outputs:[{type:'uint256'}]}],functionName:'bandwidthBackingRequired6',args:[row.id],blockNumber});}));
      }
      return {deployments:deployments.toLowerCase(),rows:jsonValue(rows)};
    },this.failures).then(snapshot=>{
      const result=snapshot.rows.map((row,index)=>{
        if(row.id.toLowerCase()!==ids[index]){this.cache.delete(ids[index]);this.failures.push('deployment not found: '+ids[index]);return null;}
        if(row.runnerUnavailable){this.cache.delete(ids[index]);this.failures.push('inactive or changed runner: '+ids[index]);return null;}
        const leaseUntil=Number(row.leaseUntil)*1000;
        if(!Number.isSafeInteger(leaseUntil))throw new Error('invalid lease expiry');
        return {...row,id:row.id.toLowerCase(),runner:row.runner.toLowerCase(),leaseUntil,chainId:this.chainId,deployments:snapshot.deployments,
          blockNumber:snapshot.blockNumber,blockHash:snapshot.hash,blockTime:snapshot.timestamp,
          validUntil:Math.min(leaseUntil,snapshot.timestamp+this.maxBlockAgeMs)};
      });
      for(const row of result)if(row)this.cache.set(row.id,row);
      return result.filter(Boolean);
    });
  }

  // Who holds registry ids, from the same agreeing peers. Only the original
  // seven-field entry prefix is decoded, so every registry revision reads alike.
  // an address the book publishes (e.g. 'registry'), read like everything else: an agreeing quorum at a confirmed block
  authorityAddress(client,name,blockNumber){
    if(this.authorityPins){
      if(!Object.hasOwn(this.authorityPins,name))throw Error('network authority is not pinned: '+name);
      return this.authorityPins[name];
    }
    return client.readContract({address:this.addressBook,abi:bookABI,functionName:'addr',args:[stringToHex(name,{size:32})],blockNumber});
  }
  async bookAddress(name) {
    if(this.authorityPins)return this.authorityAddress(null,name);
    const v=await this.agreed(async(c,blockNumber)=>({address:(await this.authorityAddress(c,name,blockNumber)).toLowerCase()}));
    return v.address;
  }
  registryEntries(registry,ids) {
    if(!/^0x[0-9a-fA-F]{40}$/.test(registry||'')||!Array.isArray(ids)||ids.length<1||ids.length>256||ids.some(id=>!/^0x[0-9a-f]{64}$/.test(id)))return Promise.reject(new Error('exact registry ids required'));
    // Not queued behind lease snapshots: a registry answer must not hold up a lease renewal.
    return this.agreed(async(c,blockNumber)=>{
      const hosts=await Promise.all(ids.map(id=>c.readContract({address:registry,abi:registryV1ABI,functionName:'get',args:[id],blockNumber})));
      return {registry:registry.toLowerCase(),hosts:hosts.map(h=>({active:!!h.active,operator:String(h.operator).toLowerCase()}))};
    }).then(snapshot=>snapshot.hosts.map((host,index)=>({id:ids[index],...host,blockTime:snapshot.timestamp})));
  }

  get(id) {const value=this.cache.get(id);return value&&value.validUntil>this.now()?structuredClone(value):null;}
  // A refresh that got NO agreeing answer (an outage of the RPCs, the control circuits or this host's uplink) says
  // nothing about the leases, so each one still running on chain stays valid until `graceMs` after its last agreeing read
  // (the providers' rule for a held peer, wg-provider/main.mjs). Never past the lease's end; never for a lease a read
  // has answered about (a definite answer deletes or replaces the cache entry). -> the ids held.
  hold(graceMs) {
    const now=this.now(),held=[];
    for(const [id,lease] of this.cache){
      if(!(lease.leaseUntil>now))continue;
      const until=Math.min(lease.leaseUntil,lease.blockTime+graceMs);
      if(until>lease.validUntil){lease.validUntil=until;}
      if(lease.validUntil>now)held.push(id);
    }
    return held;
  }
}

// Only these say nothing about the guest: the transport between this host and
// it failed. Anything else (a mismatch, a refusal, an unknown error) revokes.
const transientCodes=new Set(['ECONNRESET','ECONNREFUSED','ETIMEDOUT','EPIPE','EHOSTUNREACH','ENETUNREACH','EAI_AGAIN','ECONNABORTED']);
export function transientProofError(e) {
  return !!e&&(transientCodes.has(e.code)||e.message==='guest probe timeout'||/^guest (attestation|readiness) HTTP 5\d\d$/.test(e.message||''));
}

const leaseIdentity=l=>l?canonical({id:l.id,chainId:l.chainId??null,deployments:l.deployments??null,runner:l.runner,owner:l.owner??null,appRef:l.appRef,configCid:l.configCid}):null;

export class AdmissionGate {
  constructor({runner,expected,now=Date.now}) {
    if(!/^0x[0-9a-f]{64}$/.test(runner||''))throw new Error('runner required');
    Object.assign(this,{runner,expected,now});this.leases=new Map();this.proofs=new Map();
  }
  observeLease(lease) {
    const old=this.leases.get(lease.id);
    if(old&&(old.runner!==lease.runner||old.appRef!==lease.appRef||old.configCid!==lease.configCid||old.owner!==lease.owner))this.proofs.delete(lease.id);
    this.leases.set(lease.id,structuredClone(lease));
  }
  async attest(id,verifyGuest) {
    const lease=this.leases.get(id),expected=this.expected(id);
    if(!lease||!expected||lease.runner!==this.runner||lease.validUntil<=this.now()||expected.appRef!==lease.appRef||expected.configCid!==lease.configCid) throw new Error('no matching current app expectation');
    // bound to the lease's identity - the fields whose change drops a proof (observeLease) - not to its read freshness: a
    // chain round that re-reads the same lease while the guest is asked (block, validity, a renewed leaseUntil) does not
    // void the proof, while a changed runner, owner, app or config still does
    const fingerprint=leaseIdentity(lease),startedAt=this.now();
    const verdict=await verifyGuest(id,expected);
    if(verdict?.ready===false&&!(expected.requiresConfigSocketServer===true&&expected.requiresSecretsV1===true))throw new Error('startup proof requires a configured secret command');
    if(!verdict?.verified||verdict.deploymentId!==id||verdict.appSha256!==expected.appSha256||verdict.runtimeId!==expected.runtimeId||
      !/^[0-9a-f]{64}$/.test(verdict.spkiSha256||'')||leaseIdentity(this.leases.get(id))!==fingerprint)throw new Error('fresh bound guest proof required');
    // A proof is good for 60 s from its start, on its own: allows() still requires a valid lease, so capping it at the
    // lease's validity AT PROOF TIME added nothing - except that a lease extended later by an outage hold (hold())
    // was outlived by none of its proofs: 2026-10-14 07:28:08 the chain read failed, the leases were held, and every
    // proof still lapsed 8 s later at the old lease validity, turning off all nine k11-4 apps' egress.
    this.proofs.set(id,{...verdict,validUntil:startedAt+60000});
  }
  allows(id) {
    const lease=this.leases.get(id),proof=this.proofs.get(id),expected=this.expected(id);
    return !!(lease&&proof&&expected&&lease.active&&lease.isPublic&&lease.runner===this.runner&&lease.validUntil>this.now()&&lease.leaseUntil>this.now()&&
      proof.validUntil>this.now()&&expected.appRef===lease.appRef&&expected.configCid===lease.configCid&&proof.appSha256===expected.appSha256&&proof.runtimeId===expected.runtimeId);
  }
  revoke(id) {this.proofs.delete(id);}
  // A transient probe failure leaves the last proof to expire on its own
  // schedule (never extended); everything else revokes it now.
  failed(id,error) {const transient=transientProofError(error);if(!transient)this.revoke(id);return transient;}
}
