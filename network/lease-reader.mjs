// Serving authorization comes from two independently configured chain RPCs at
// the same recent block. Nan is neither a bootstrap nor an admission dependency.
import {createPublicClient, http, stringToHex} from 'viem';
import {base} from 'viem/chains';
import {canonical} from './route-record.mjs';
import {readConnectivity} from './connectivity-chain.mjs';
import {guardedFetch} from './guarded-fetch.mjs';
import {validateNetworkAuthorities} from './network-authorities.mjs';
import {rpcEndpoint,redactUrls} from './rpc-identity.mjs';
const fields=[['id','bytes32'],['owner','address'],['appRef','string'],['ports','string'],['configCid','string'],['gpuMilli','uint16'],['cpuMilli','uint16'],['appPort','uint32'],['isPublic','bool'],['active','bool'],['createdAt','uint64'],['rate','uint256'],['balance6','uint256'],['spent6','uint256'],['runner','bytes32'],['runnerOperator','address'],['leaseUntil','uint64']];
const bookABI=[{type:'function',name:'addr',stateMutability:'view',inputs:[{type:'bytes32'}],outputs:[{type:'address'}]}];
const deploymentABI=[{type:'function',name:'get',stateMutability:'view',inputs:[{type:'bytes32'}],outputs:[{type:'tuple',components:fields.map(([name,type])=>({name,type}))}]}];
const schemaABI=[{type:'function',name:'deploymentsSchema',stateMutability:'view',inputs:[],outputs:[{type:'uint256'}]}];
import {hostABI} from './registry-abi.mjs';
const registryV1ABI=[{type:'function',name:'get',stateMutability:'view',inputs:[{type:'bytes32'}],outputs:[{type:'tuple',components:
  [['endpoint','string'],['repo','string'],['measurement','bytes32'],['operator','address'],['registeredAt','uint64'],['lastSeen','uint64'],['active','bool']].map(([name,type])=>({name,type}))}]}];
function jsonValue(value) {return JSON.parse(JSON.stringify(value,(_k,v)=>typeof v==='bigint'?v.toString():v));}
// A request that has not answered within `ms` stops being waited for. It cannot be aborted (viem's per-call API takes
// no signal), but nothing waits on it and nothing new is sent on its behalf.
function timed(promise,ms) {
  let timer;
  return Promise.race([promise,new Promise((_r,reject)=>{timer=setTimeout(()=>reject(new Error('chain request timed out')),ms);})]).finally(()=>clearTimeout(timer));
}
// an RPC library's error can name the URL it called, API key and all: only a safe label of it is kept
const errText=e=>redactUrls(String(e?.shortMessage||e?.message||e)).slice(0,400);
// The vote identity of an RPC URL: network/rpc-identity.mjs, the rule every quorum reader shares (one public host is
// one vote however its URL is spelled; loopback by port; IPv4 written as IPv6 folded; https, plain http only on
// loopback; no credentials or fragment; no DNS, and distinct hosts are not proof of independent operators). Throws an
// error that does not echo the URL, which may hold an API key.
export function rpcIdentity(raw) {
  return rpcEndpoint(raw).identity;
}
const maxClients=16,clientMethods=['getChainId','getBlockNumber','getBlock'];
// Why a client set cannot read a quorum, or null. Two to sixteen DISTINCT objects (one object twice is one RPC counted
// twice), each with the three calls every read needs. A client that exposes its transport URL (viem's http transport
// does, as transport.url) is also counted by rpcIdentity, so two clients for one host are one vote; a malformed exposed
// URL is refused. A client with no visible URL (a test double, or a caller's own transport) is known only by its object
// identity: the caller who builds it vouches that it is a separate endpoint.
function clientProblem(clients) {
  if(!Array.isArray(clients)||clients.length<2||clients.length>maxClients)return `two to ${maxClients} chain clients are required`;
  if(new Set(clients).size!==clients.length)return 'two distinct clients are required: one client listed twice';
  if(!clients.every(c=>c&&typeof c==='object'&&clientMethods.every(m=>typeof c[m]==='function')))return 'each chain client needs getChainId, getBlockNumber and getBlock';
  const seen=new Set();
  for(const c of clients){
    const url=c.transport?.url;
    if(url===undefined||url===null)continue;
    let id;try{id=rpcIdentity(url);}catch(e){return 'a chain client exposes an unusable RPC URL: '+e.message;}
    if(seen.has(id))return 'two chain clients reach the same RPC host: one vote, not two';
    seen.add(id);
  }
  return null;
}
// Why the reader's chain policy is unusable, or null (checked at construction and again by every read, since the
// fields are plain properties).
function policyProblem(r) {
  const int=(v,lo,hi)=>Number.isSafeInteger(v)&&v>=lo&&v<=hi;
  if(!int(r.chainId,1,Number.MAX_SAFE_INTEGER)||!int(r.maxBlockAgeMs,1000,120000)||!int(r.confirmations,1,64)||!int(r.deadlineMs,100,300000)||
     !int(r.headGraceMs,0,10000)||!int(r.retryDelayMs,0,10000)||typeof r.now!=='function')return 'invalid chain policy';
  return null;
}
// A block header as an RPC returned it, checked: the block number asked for, a 32-byte hash, a whole-second timestamp.
function header(block,blockNumber) {
  const {number,hash,timestamp}=block||{};
  if(!(typeof number==='bigint'||Number.isSafeInteger(number))||BigInt(number)!==blockNumber)throw new Error('chain block number differs from the one requested');
  if(typeof hash!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(hash))throw new Error('malformed chain block hash');
  if(!((typeof timestamp==='bigint'&&timestamp>=0n)||(Number.isSafeInteger(timestamp)&&timestamp>=0)))throw new Error('malformed chain block timestamp');
  const ms=Number(timestamp)*1000;
  if(!Number.isSafeInteger(ms))throw new Error('malformed chain block timestamp');
  return {number:blockNumber,hash:hash.toLowerCase(),timestamp:ms};
}
// The fields agreed() itself puts on every answer; a read callback returning one is a bug, refused loudly.
const reservedFields=['hash','blockNumber','timestamp'];
export class LeaseReader {
  constructor({rpc,chainId=8453,addressBook,authorityPins,maxBlockAgeMs=90000,confirmations=2,deadlineMs=30000,clients,proxy,includeHostPayout=false,includeConnectivity=false,now=Date.now}) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(addressBook||'')) throw new Error('invalid chain policy');
    Object.assign(this,{chainId,addressBook,maxBlockAgeMs,confirmations,deadlineMs,includeHostPayout,includeConnectivity,now});
    this.retryDelayMs=400;this.headGraceMs=250;
    const policy=policyProblem(this);if(policy)throw new Error(policy);
    if (!clients) {
      // one vote per public host: case, a trailing dot, the port and the path do not make another one
      if (!Array.isArray(rpc) || rpc.length<2 || rpc.length>maxClients) throw new Error('at least two independent HTTPS RPC origins required');
      const ids=rpc.map(rpcIdentity);
      if (new Set(ids).size!==ids.length) throw new Error('at least two independent HTTPS RPC origins required: two URLs reach the same host');
    }
    if (clients) {const problem=clientProblem(clients);if(problem)throw new Error('invalid chain clients: '+problem);}
    Object.defineProperty(this,'authorityPins',{value:authorityPins===undefined?null:validateNetworkAuthorities(authorityPins),enumerable:true});
    // Public RPCs meter requests per second. Multicall3 folds a snapshot's
    // same-block reads into one eth_call each, however many apps it covers.
    this.clients=clients||rpc.map(url=>createPublicClient({chain:base,batch:{multicall:{wait:0}},
      transport:http(url,{timeout:14000,retryCount:0,...(proxy?{fetchFn:guardedFetch(proxy,{timeoutMs:6000})}:{})})}));
    this.lastBlock=0n;this.cache=new Map();
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
  // One value read at ONE fixed recent block, returned once two peers return it identically (the whole value,
  // block hash and timestamp included). Every chain answer this class gives comes through here.
  //  * Each peer reports chain id and head; a wrong chain or a failure leaves it out. Once two heads are in, the others
  //    get `headGraceMs` before the block is chosen: the SECOND-highest head minus `confirmations`, never below the block
  //    already accepted (`lastBlock`: a lagging pair cannot roll an answer back). One RPC claiming a far-future head
  //    cannot choose the block, and one slow RPC cannot hold the others back.
  //  * Choosing the block shuts nobody out: a head that arrives later still reads at that block, for as long as the
  //    deadline allows, so a fast liar beside one fast honest RPC cannot veto a slower honest one by disagreeing.
  //  * If every reader finished without two matching answers and later heads give a strictly NEWER block (a liar's low
  //    head made the first one stale), the read is repeated there with every RPC that reported a head.
  //  * Each header must be the block asked for (number), with a 32-byte hash and a valid timestamp; it is read again
  //    after the read and all three must be unchanged. The block must be neither in the future nor older than
  //    `maxBlockAgeMs` before the read, after it, and again at the moment two answers match.
  //  * At that moment the block must also be no older than `lastBlock`: another call on this reader (a registry read,
  //    a book address) may have accepted a newer block meanwhile. Then the read moves up to that block instead of
  //    returning an answer older than one already given.
  //  * `read(client, blockNumber)` must return a plain object without the reserved fields hash, blockNumber and
  //    timestamp (agreed() sets those from the checked header); anything else refuses the whole call at once.
  //  * ONE deadline (`deadlineMs`) bounds the whole call. Each request is waited for at most the time left, and once the
  //    outcome is decided, a round is superseded, or the deadline has passed, no further request is sent.
  //  * One RPC never wins alone; there is no fallback to a first answer.
  agreed(read, failures=[]) {
    const problem=clientProblem(this.clients);
    if(problem)return Promise.reject(new Error('invalid chain clients: '+problem));
    const policy=policyProblem(this);
    if(policy)return Promise.reject(new Error(policy));
    if(typeof read!=='function')return Promise.reject(new Error('agreed() needs a read function'));
    return new Promise((resolve,reject)=>{
      const endAt=performance.now()+this.deadlineMs,fresh=ts=>ts+this.maxBlockAgeMs>this.now();
      let closed=false,round=0,block=null,seen=new Map(),readers=new Set(),pending=0,grace=null;
      const heads=new Map(),tried=[];let headsOutstanding=this.clients.length;
      const finish=(err,out)=>{if(closed)return;closed=true;clearTimeout(grace);clearTimeout(deadline);if(err)reject(err);else resolve(out);};
      const deadline=setTimeout(()=>finish(new Error(`no fresh agreeing chain quorum within ${this.deadlineMs} ms`)),this.deadlineMs);
      deadline.unref?.();
      // Every request goes through here: refused once decided, superseded or past the deadline, and bounded by the time left.
      const gate=(r,f)=>{
        if(closed)return Promise.reject(new Error('the chain read was already decided'));
        if(r!==null&&r!==round)return Promise.reject(new Error('superseded by a newer block'));
        const left=Math.floor(endAt-performance.now());
        if(left<=0)return Promise.reject(new Error('the chain read deadline has passed'));
        return timed(Promise.resolve().then(f),left);
      };
      // `read` gets the client behind this gate, so its own requests obey it too.
      const guarded=(c,r)=>new Proxy(c,{get(target,key){const v=Reflect.get(target,key);return typeof v==='function'?(...args)=>gate(r,()=>v.apply(target,args)):v;}});
      const choose=()=>{
        if(heads.size<2)return null;
        const ns=[...heads.values()].sort((a,b)=>a>b?-1:a<b?1:0);
        let b=ns[1]-BigInt(this.confirmations);
        if(b<0n)return -1n;
        // Peers' heads jitter by a block or two between back-to-back snapshots. Never read below the block already
        // accepted; reread it instead. The block-age checks still decide whether that block is fresh enough.
        if(b<this.lastBlock)b=this.lastBlock;
        return b;
      };
      const readAt=(c,b,r)=>this.limited(async()=>{
        const g=guarded(c,r);
        const {hash,timestamp}=header(await g.getBlock({blockNumber:b}),b);
        if(timestamp>this.now()+5000||!fresh(timestamp))throw new Error('stale chain block');
        const value=await read(g,b);
        if(!value||typeof value!=='object'||Array.isArray(value))throw Object.assign(new Error('the chain read function must return an object'),{readerBug:true});
        const reserved=reservedFields.find(k=>Object.hasOwn(value,k));
        if(reserved)throw Object.assign(new Error('the chain read function returned the reserved field '+reserved),{readerBug:true});
        // Confirm the numbered block was not replaced while eth_call ran, and is still recent.
        const again=header(await g.getBlock({blockNumber:b}),b);
        if(again.hash!==hash||again.timestamp!==timestamp)throw new Error('chain reorganized during read');
        if(!fresh(timestamp))throw new Error('chain block became stale during the read');
        return {...value,hash,blockNumber:String(b),timestamp};
      });
      const addReader=c=>{
        if(closed||readers.has(c))return;
        const r=round,b=block;readers.add(c);pending++;
        readAt(c,b,r).then(snap=>{
          if(closed||r!==round)return;
          const key=canonical(snap),first=seen.get(key);
          if(first===undefined){seen.set(key,c);return;}
          if(first===c)return;                         // two distinct peers, never one twice
          if(!fresh(snap.timestamp)){failures.push('chain block became stale before two peers agreed');return;}
          if(b<this.lastBlock){
            // another call accepted a newer block while this one read: never answer from below it
            failures.push(`block ${b} is older than block ${this.lastBlock} accepted meanwhile`);
            const next=choose();
            if(next!==null&&next>b)return startRound(next);
            return finish(new Error('no fresh agreeing chain quorum'));
          }
          this.lastBlock=b;
          finish(null,snap);
        },e=>{
          if(e?.readerBug)return finish(e);               // the caller's read is wrong: say so, do not dress it as a quorum failure
          if(!closed&&r===round)failures.push(errText(e));
        }).finally(()=>{if(r===round){pending--;settle();}});
      };
      const startRound=b=>{
        round++;block=b;tried.push(b);seen=new Map();readers=new Set();pending=0;
        for(const c of heads.keys())addReader(c);
        settle();
      };
      // Nothing more can arrive for this round: try a strictly newer block if later heads give one, else refuse.
      const settle=()=>{
        if(closed||block===null||pending>0||headsOutstanding>0)return;
        const next=choose();
        if(next!==null&&next>tried[tried.length-1])return startRound(next);
        finish(new Error('no fresh agreeing chain quorum'));
      };
      const headsSettled=()=>{
        if(closed)return;
        if(block!==null)return settle();
        if(headsOutstanding>0&&!(heads.size>=2&&grace==='fired'))return;
        clearTimeout(grace);
        const b=choose();
        if(b===null)return finish(new Error('chain quorum unavailable'));
        if(b<0n)return finish(new Error('no fresh agreeing chain quorum'));
        startRound(b);
      };
      for(const c of this.clients)this.limited(async()=>{
        const g=guarded(c,null);
        const [chainId,number]=await Promise.all([g.getChainId(),g.getBlockNumber({cacheTime:0})]);
        if(chainId!==this.chainId)throw new Error('wrong chain');
        return BigInt(number);
      }).then(number=>{
        if(closed)return;
        heads.set(c,number);
        if(block!==null)addReader(c);                  // a late head still reads at the chosen block
        else if(heads.size>=2&&grace===null)grace=setTimeout(()=>{grace='fired';headsSettled();},this.headGraceMs);
      },()=>{}).finally(()=>{headsOutstanding--;headsSettled();});
    });
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
