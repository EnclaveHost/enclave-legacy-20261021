import test from 'node:test';
import assert from 'node:assert/strict';
import {createQuorumReader,rpcIdentity} from '../custody/v2/quorum.mjs';
import {createChainReaderV2,VAULT_V2_ABI} from '../custody/v2/chain.mjs';
import {decodeFunctionData,encodeFunctionResult} from 'viem';
const hash=n=>'0x'+BigInt(n).toString(16).padStart(64,'0');
const never=()=>new Promise(()=>{});
function peer(options={}) {
  const opts={head:100n,timestamp:1000n,chainId:8453,hashOffset:0n,...options};
  const p={opts,getChainId:async()=>opts.chainId,getBlockNumber:async()=>opts.head,
    getBlock:async({blockNumber})=>({number:blockNumber,hash:hash(blockNumber+opts.hashOffset),timestamp:opts.timestamp})};
  return p;
}
const reader=(clients,extra={})=>createQuorumReader({clients,minAgree:Math.floor(clients.length/2)+1,
  chainId:8453,now:()=>1000000,timeoutMs:50,...extra});
const read=async(_,block)=>({ownerPaused:true,selected:block.blockNumber});

test('each single outlier can refuse, hang, lie about height, or return conflicting state without vetoing 3 of 4',async()=>{
  for(let at=0;at<4;at++)for(const mode of ['refuse','hang','high','state','fork','wrong-chain']){
    const peers=Array.from({length:4},()=>peer());
    if(mode==='refuse')peers[at].getBlockNumber=async()=>{throw Error('unavailable');};
    if(mode==='hang')peers[at].getBlockNumber=never;
    if(mode==='high')peers[at].opts.head=2n**200n;
    if(mode==='fork')peers[at].opts.hashOffset=1000n;
    if(mode==='wrong-chain')peers[at].opts.chainId=1;
    const result=await reader(peers)(async(c,b)=>mode==='state'&&c===peers[at]?{ownerPaused:false,selected:b.blockNumber}:read(c,b));
    assert.equal(result.blockNumber,100n,`${at}/${mode}`);assert.equal(result.ownerPaused,true);
    assert.equal(result.blockHash,hash(100));
  }
});

test('quorum-supported height applies confirmations without falling back to a stale unpaused state',async()=>{
  const peers=[peer({head:100n}),peer({head:101n}),peer({head:102n}),peer({head:99999n})];
  const selected=[];
  const r=await reader(peers,{confirmations:2})(async(_,b)=>{selected.push(b.blockNumber);return {paused:true};});
  assert.equal(r.blockNumber,99n);assert.deepEqual(selected,[99n,99n,99n,99n]);
  const divergent=[peer(),peer(),peer(),peer()];const attempted=[];
  await assert.rejects(reader(divergent)(async(c,b)=>{
    attempted.push(b.blockNumber);return {paused:divergent.indexOf(c)<2};
  }),/disagree/);
  assert.deepEqual(attempted,[100n,100n,100n,100n]);
  await assert.rejects(reader(peers,{confirmations:200})(read),/insufficient/);
});

test('rejects stale, future, malformed, moving or wrong-number block headers',async()=>{
  for(const kind of ['stale','future','hash','number','moving']){
    const peers=Array.from({length:3},()=>{
      const p=peer({timestamp:kind==='stale'?800n:kind==='future'?1011n:1000n});let count=0;
      const get=p.getBlock;
      p.getBlock=async args=>{
        const b=await get(args);count++;
        if(kind==='hash')b.hash='0x00';
        if(kind==='number')b.number--;
        if(kind==='moving'&&count>1)b.hash=hash(500);
        return b;
      };return p;
    });
    await assert.rejects(reader(peers)(read),/disagree|only/);
  }
});

test('all chain methods use canonical hash-addressed calls and freshness, including deals and code admission',async()=>{
  const vault='0x'+'12'.repeat(20),id=hash(1);
  const peers=Array.from({length:3},()=>{
    const p=peer();p.request=async({method,params})=>{
      assert.equal(method,'eth_call');assert.equal(params[0].to,vault);
      assert.deepEqual(params[1],{blockHash:hash(100),requireCanonical:true});
      const {functionName}=decodeFunctionData({abi:VAULT_V2_ABI,data:params[0].data});
      return encodeFunctionResult({abi:VAULT_V2_ABI,functionName,result:functionName==='codeActiveAt'?900n:['0x',[]]});
    };return p;
  });
  const c=createChainReaderV2({vault,clients:peers,minAgree:2,chainId:8453,now:()=>1000000});
  assert.equal((await c.readCodeActiveAt({committeeId:id,measurement:id})).activeAt,900);
  assert.equal((await c.readDeal({committeeId:id,toEpoch:2,dealerIndex:1})).blockHash,hash(100));
  for(const p of peers)p.opts.timestamp=800n;
  await assert.rejects(c.readCodeActiveAt({committeeId:id,measurement:id}),/chain_stale/);
  await assert.rejects(c.readDeal({committeeId:id,toEpoch:2,dealerIndex:1}),/chain_stale/);
});

test('a lost or unsupported canonical-hash call never downgrades to number-only eth_call',async()=>{
  const vault='0x'+'12'.repeat(20),id=hash(1);let calls=0;
  const peers=Array.from({length:3},()=>{
    const p=peer();p.request=async({params})=>{
      calls++;assert.deepEqual(params[1],{blockHash:hash(100),requireCanonical:true});
      throw Error('block hash unsupported');
    };return p;
  });
  const c=createChainReaderV2({vault,clients:peers,minAgree:2,now:()=>1000000});
  await assert.rejects(c.readCodeActiveAt({committeeId:id,measurement:id}),/only 0 RPCs/);
  assert.equal(calls,3);
});

test('checkpoint survives reader restart and rejects rollback, same-height fork and failed persistence',async()=>{
  let saved=null;const checkpoint={load:()=>saved,save:async mark=>{saved=mark;}};
  const peers=Array.from({length:3},()=>peer());
  await reader(peers,{checkpoint})(read);assert.equal(saved.blockNumber,'100');
  for(const p of peers)p.opts.head=99n;
  await assert.rejects(reader(peers,{checkpoint})(read),{code:'chain_rollback'});
  for(const p of peers){p.opts.head=100n;p.opts.hashOffset=1n;}
  await assert.rejects(reader(peers,{checkpoint})(read),{code:'chain_rollback'});
  for(const p of peers){p.opts.hashOffset=0n;p.opts.timestamp=1001n;}
  await assert.rejects(reader(peers,{checkpoint})(read),{code:'chain_rollback'});
  for(const p of peers)p.opts.timestamp=1000n;
  for(const p of peers){p.opts.head=101n;p.opts.hashOffset=0n;}
  assert.equal((await reader(peers,{checkpoint})(read)).blockNumber,101n);
  await assert.rejects(reader(peers,{checkpoint:{load:()=>null,save:async()=>{throw Error('disk unavailable');}}})(read),/disk unavailable/);
  await assert.rejects(reader(peers,{checkpoint:{load:()=>({blockNumber:'oops'}),save:async()=>{}}})(read),/checkpoint/);
});

test('concurrent reads cannot return an older snapshot after a later one was persisted',async()=>{
  const peers=Array.from({length:3},()=>peer());const r=reader(peers);let release,started;
  const entered=new Promise(resolve=>{started=resolve;});const hold=new Promise(resolve=>{release=resolve;});
  const earlier=r(async(_,b)=>{started();await hold;return {number:b.blockNumber};});
  await entered;for(const p of peers)p.opts.head=101n;
  const later=await r(read);assert.equal(later.blockNumber,101n);
  release();await assert.rejects(earlier,{code:'chain_rollback'});
});

test('configured peers and thresholds cannot silently count one peer twice or accept disjoint quorums',()=>{
  const p=peer();assert.throws(()=>reader([p,p]),/distinct/);
  assert.throws(()=>reader([Object.assign(peer(),{transport:{url:'https://rpc.example/a'}}),Object.assign(peer(),{transport:{url:'https://rpc.example/b'}})]),/distinct/);
  assert.throws(()=>reader([peer(),peer(),peer(),peer()],{minAgree:2}),/majority/);
  for(const args of [{confirmations:-1},{maxAgeSec:null},{maxFutureSec:-1},{timeoutMs:0}])
    assert.throws(()=>reader([peer()],args),/invalid/);
  assert.throws(()=>createChainReaderV2({rpcs:['https://rpc.example/a','https://rpc.example/b'],minAgree:2}),/distinct/);
});

test('one public RPC host is one vote however it is spelled; loopback test chains count by port',()=>{
  const at=url=>Object.assign(peer(),{transport:{url}});
  for(const [a,b] of [
    ['https://rpc.example.org','https://rpc.example.org.'],                  // trailing dot (the reported alias)
    ['https://rpc.example.org','https://RPC.Example.ORG'],                   // case
    ['https://rpc.example.org','https://rpc.example.org:8443'],              // port
    ['https://rpc.example.org/key-a','https://rpc.example.org./key-b?x=1'],  // path, key, query and dot together
    ['http://127.0.0.1:8545','http://localhost:8545/'],                      // loopback aliases on one port
    ['http://[::1]:8545','http://127.0.0.1:8545'],
  ]){
    assert.throws(()=>reader([at(a),at(b)]),/distinct RPC hostnames/,`${a} | ${b}`);
    assert.throws(()=>reader([at(a),at(b),at('https://third.example.net')]),/distinct RPC hostnames/,`3 peers: ${a} | ${b}`);
    assert.throws(()=>createChainReaderV2({rpcs:[a,b],minAgree:2}),/distinct RPC hostnames/,`rpcs: ${a} | ${b}`);
  }
  // with the alias, three configured clients are two hosts: a "majority of 3" would be satisfied by one host twice
  assert.throws(()=>reader([at('https://a.example.org'),at('https://a.example.org.'),at('https://b.example.org')]),/distinct/);
  assert.equal(rpcIdentity('https://RPC.example.org.:8443/k?x=1'),'host:rpc.example.org');
  assert.equal(rpcIdentity('http://localhost:8546'),'loopback:8546');
  for (const url of ['http://rpc.example.org', 'https://rpc.example.org/#secret', 'https://user:secret@rpc.example.org'])
    assert.throws(() => rpcIdentity(url), e => /HTTPS/.test(e.message) && !e.message.includes('secret'));
  // genuinely distinct hosts, and distinct loopback test ports, are separate votes
  assert.doesNotThrow(()=>reader([at('https://a.example.org'),at('https://b.example.org'),at('https://a.example.net')]));
  assert.doesNotThrow(()=>reader([at('http://127.0.0.1:8545'),at('http://127.0.0.1:8546')]));
  assert.doesNotThrow(()=>createChainReaderV2({rpcs:['https://a.example.org/x','https://b.example.org/x'],minAgree:2}));
});

test('invalid reader configuration is refused before any request; custom transports without a URL still work',async()=>{
  const at=url=>Object.assign(peer(),{transport:{url}});
  for(const [clients,re] of [
    [[],/1-16 RPC clients/], [Array.from({length:17},()=>peer()),/1-16 RPC clients/],
    [[peer(),null],/client 2 is malformed/], [[peer(),{getBlock(){}}],/client 2 is malformed/], [[peer(),'https://a.example.org'],/client 2 is malformed/],
    [[peer(),at('not a url')],/invalid RPC URL/], [[peer(),at(42)],/invalid RPC URL/], [[peer(),at('ftp://a.example.org')],/HTTPS/],
    [[peer(),at('https://user:secret@a.example.org')],/without credentials/],
  ]) assert.throws(()=>reader(clients),re,JSON.stringify(re.source));
  assert.throws(()=>createQuorumReader({clients:null,minAgree:1}),/1-16 RPC clients/);
  assert.throws(()=>createQuorumReader({clients:{length:2,0:peer(),1:peer()},minAgree:2}),/1-16 RPC clients/,'an array, not an array-like');
  const noChainId=peer();delete noChainId.getChainId;
  assert.throws(()=>reader([noChainId,peer()]),/needs getBlockNumber, getBlock, getChainId/,'a pinned chain id needs getChainId');
  assert.doesNotThrow(()=>reader([noChainId,peer(),peer()],{chainId:null}),'without a pinned chain id getChainId is not needed');
  for(const extra of [{minAgree:1},{minAgree:3},{minAgree:1.5},{minAgree:'2'}])
    assert.throws(()=>reader([peer(),peer()],extra),/majority/,JSON.stringify(extra));
  for(const extra of [{confirmations:1001},{confirmations:1.5},{timeoutMs:300001},{timeoutMs:Infinity},{maxAgeSec:7*86400+1},{maxAgeSec:NaN},
                      {maxFutureSec:3601},{maxFutureSec:'5'},{chainId:0},{chainId:2**53}])
    assert.throws(()=>reader([peer()],extra),/invalid/,JSON.stringify(extra));
  assert.throws(()=>reader([peer()],{now:1000000}),/invalid clock/);
  for(const checkpoint of [{load:()=>null},{save:async()=>{}},'file.json',{load:1,save:2}])
    assert.throws(()=>reader([peer()],{checkpoint}),/invalid checkpoint/);
  for(const rpcs of [[],['https://a.example.org','not a url'],Array.from({length:17},(_,i)=>`https://h${i}.example.org`),'https://a.example.org'])
    assert.throws(()=>createChainReaderV2({rpcs,minAgree:1}),/RPC/,JSON.stringify(rpcs));
  // the existing custom-transport fixtures (no exposed URL) are known by object identity and still read
  const plain=[peer(),peer(),peer()];
  assert.equal((await reader(plain)(read)).blockNumber,100n);
});

test('a snapshot that goes stale while its checkpoint is being persisted is refused; the mark still advances',async()=>{
  let clock=1000000,saved=null;
  const checkpoint={load:()=>saved,save:async mark=>{clock+=200000;saved=mark;}};   // a 200 s durable write
  const peers=Array.from({length:3},()=>peer());
  const r=createQuorumReader({clients:peers,minAgree:2,chainId:8453,now:()=>clock,timeoutMs:50,checkpoint});
  await assert.rejects(r(read),{code:'chain_stale'});
  assert.equal(saved.blockNumber,'100','the genuine agreed block is still the persisted floor');
  for(const p of peers){p.opts.head=99n;p.opts.timestamp=BigInt(clock/1000);}
  await assert.rejects(r(read),{code:'chain_rollback'},'the floor is never lowered after the refused answer');
});
