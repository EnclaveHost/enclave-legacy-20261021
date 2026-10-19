// A configured majority must agree on the same fresh block and complete result.
// One unavailable or dissenting peer cannot veto the other three of four peers.
import { bytesToHex } from 'viem';
const fail = (code, message) => Object.assign(new Error(message), {code, status:503});
const fingerprint = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? `n${v}` : v instanceof Uint8Array ? `x${bytesToHex(v)}` : v);
const hashPattern = /^0x[0-9a-fA-F]{64}$/;

export function createQuorumReader({clients, minAgree, chainId=null, confirmations=0, timeoutMs=10000,
  maxAgeSec=120, maxFutureSec=10, now=()=>Date.now(), checkpoint=null}) {
  if (!clients.length || new Set(clients).size !== clients.length) throw Error('chain: distinct RPC clients required');
  const origins=clients.flatMap(c=>c.transport?.url?[new URL(c.transport.url).hostname]:[]);
  if(new Set(origins).size!==origins.length)throw Error('chain: distinct RPC hostnames required');
  if (!Number.isInteger(minAgree) || minAgree <= clients.length/2 || minAgree > clients.length)
    throw Error('chain: minAgree must be an explicit majority of configured RPCs');
  for (const [key,value] of Object.entries({confirmations,timeoutMs,maxAgeSec,maxFutureSec}))
    if (!Number.isSafeInteger(value) || value < 0 || (key==='timeoutMs' && value===0)) throw Error(`chain: invalid ${key}`);
  if (chainId!==null && (!Number.isSafeInteger(chainId)||chainId<=0)) throw Error('chain: invalid chain ID');
  const deadline = async fn => {
    let timer;
    try { return await Promise.race([Promise.resolve().then(fn),new Promise((_,reject)=>{
      timer=setTimeout(()=>reject(fail('chain_timeout','RPC deadline exceeded')),timeoutMs);
    })]); } finally { clearTimeout(timer); }
  };
  function blockFields(b,number=b?.number) {
    if (typeof number!=='bigint'||number<0n||b?.number!==number||!hashPattern.test(b.hash)||
        typeof b.timestamp!=='bigint'||b.timestamp<0n||b.timestamp>BigInt(Number.MAX_SAFE_INTEGER))
      throw fail('chain_unconfirmed','invalid RPC block header');
    const timestamp=Number(b.timestamp), clock=Math.floor(now()/1000);
    if (timestamp<clock-maxAgeSec) throw fail('chain_stale','RPC block is too old');
    if (timestamp>clock+maxFutureSec) throw fail('chain_future','RPC block is in the future');
    return {blockNumber:number,blockHash:b.hash.toLowerCase(),blockTimestamp:timestamp};
  }
  let highWater=null, loaded=false, commits=Promise.resolve();
  async function commit(result) {
    // The network reads may overlap; the durable high-water update may not.
    const next=commits.then(async()=>{
      if (!loaded) {
        const old=await checkpoint?.load();
        if (old) {
          if (!/^(0|[1-9][0-9]*)$/.test(old.blockNumber)||!hashPattern.test(old.blockHash)||
              !Number.isSafeInteger(old.blockTimestamp)||old.blockTimestamp<0) throw fail('chain_checkpoint','invalid sealed chain checkpoint');
          highWater={...old,blockNumber:BigInt(old.blockNumber),blockHash:old.blockHash.toLowerCase()};
        }
        loaded=true;
      }
      // Recheck after waiting for persistence, not only when the RPC replied.
      blockFields({number:result.blockNumber,hash:result.blockHash,timestamp:BigInt(result.blockTimestamp)});
      if (highWater && (result.blockNumber<highWater.blockNumber || result.blockTimestamp<highWater.blockTimestamp ||
          (result.blockNumber===highWater.blockNumber && (result.blockHash!==highWater.blockHash || result.blockTimestamp!==highWater.blockTimestamp))))
        throw fail('chain_rollback','RPC state moves behind or conflicts with the accepted block');
      if (!highWater || result.blockNumber>highWater.blockNumber) {
        const mark={blockNumber:result.blockNumber.toString(),blockHash:result.blockHash,blockTimestamp:result.blockTimestamp};
        await checkpoint?.save(mark);
        highWater={...mark,blockNumber:result.blockNumber};
      }
      return result;
    });
    commits=next.catch(()=>{});return next;
  }
  return async read => {
    const heads=await Promise.allSettled(clients.map(c=>deadline(async()=>{
      if (chainId!==null && await c.getChainId()!==chainId) throw fail('chain_wrong_network','RPC chain ID differs from the pin');
      const head=await c.getBlockNumber({cacheTime:0});
      if (typeof head!=='bigint'||head<0n) throw fail('chain_unconfirmed','invalid RPC head');
      return head;
    })));
    const ok=heads.flatMap((h,i)=>h.status==='fulfilled'?[{client:clients[i],head:h.value}]:[]);
    if (ok.length<minAgree) throw fail('chain_unconfirmed',`only ${ok.length} RPCs answered (need ${minAgree})`);
    const heights=ok.map(h=>h.head).sort((a,b)=>a>b?-1:a<b?1:0);
    // This height is supported by a quorum of advertised heads. Do not walk
    // backwards on a disagreement: that could conceal a recent owner pause.
    const number=heights[minAgree-1]-BigInt(confirmations);
    if (number<0n) throw fail('chain_unconfirmed','insufficient confirmed blocks');
    const reads=await Promise.allSettled(ok.map(({client})=>deadline(async()=>{
      const block=blockFields(await client.getBlock({blockNumber:number}),number);
      const result=await read(client,block);
      const after=blockFields(await client.getBlock({blockNumber:number}),number);
      if (fingerprint(block)!==fingerprint(after)) throw fail('chain_unconfirmed','block changed during RPC read');
      return {...result,...block};
    })));
    const groups=new Map();let count=0;
    for (const r of reads) if(r.status==='fulfilled') {
      count++;const key=fingerprint(r.value),group=groups.get(key)||{value:r.value,count:0};
      group.count++;groups.set(key,group);
    }
    const winner=[...groups.values()].find(g=>g.count>=minAgree);
    if (!winner) {
      // Diagnostics are local constants/error codes; never echo RPC bodies.
      const codes=[...new Set(reads.filter(r=>r.status==='rejected').map(r=>
        ['chain_stale','chain_future','host_authority_mismatch','host_authority_missing'].includes(r.reason?.code)?r.reason.code:'rpc_refused'))];
      throw fail('chain_unconfirmed',`RPCs disagree or only ${count} RPCs could read block ${number} (need ${minAgree}; ${codes.join(',')})`);
    }
    return commit(winner.value);
  };
}
