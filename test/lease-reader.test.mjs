import test from 'node:test';
import assert from 'node:assert/strict';
import {LeaseReader,AdmissionGate,transientProofError} from '../network/lease-reader.mjs';
const id='0x'+'ab'.repeat(32),runner='0x'+'cd'.repeat(32),book='0x'+'01'.repeat(20),contract='0x'+'02'.repeat(20);
const now=()=>1700000000000;
const row={id,runner,owner:book,runnerOperator:book,active:true,isPublic:true,leaseUntil:1700003600n,appRef:'catalog:a:1',configCid:''};
function client({time=1699999995n,hash='0x'+'aa'.repeat(32),value=row,fail=false}={}) {return {
 getChainId:async()=>{if(fail)throw Error('offline');return 8453},getBlockNumber:async()=>1000n,
 getBlock:async({blockNumber})=>({number:blockNumber,hash,timestamp:time}),readContract:async({functionName})=>functionName==='addr'?contract:functionName==='deploymentsSchema'?15n:value,
};}
test('only an agreeing recent chain quorum can renew authorization',async()=>{
 const reader=new LeaseReader({addressBook:book,clients:[client(),client()],now});
 const [lease]=await reader.refresh([id]);assert.equal(lease.validUntil,1699999995000+90000);
 reader.clients=[client(),client({value:{...row,runner:'0x'+'de'.repeat(32)}})];
 await assert.rejects(reader.refresh([id]),/agreeing chain quorum/);
 assert.equal(reader.get(id).validUntil,lease.validUntil);
 reader.clients=[client({time:1699999800n}),client({time:1699999800n})];
 await assert.rejects(reader.refresh([id]),/fresh agreeing/);
 reader.clients=[client(),client({fail:true})];await assert.rejects(reader.refresh([id]),/quorum unavailable/);
 reader.now=()=>lease.validUntil;assert.equal(reader.get(id),null);
});
test('a stale outlier cannot prevent two fresh peers from agreeing',async()=>{
 const reader=new LeaseReader({addressBook:book,clients:[client({time:1699999800n}),client(),client()],now});
 assert.equal((await reader.refresh([id]))[0].runner,runner);
});
test('guest proof expires without self-extension and lease changes invalidate it',async()=>{
 let clock=now();const expected={appRef:row.appRef,configCid:'',appSha256:'ab'.repeat(32),runtimeId:'cd'.repeat(32)};
 const gate=new AdmissionGate({runner,expected:()=>expected,now:()=>clock});
 const lease={...row,leaseUntil:clock+300000,validUntil:clock+90000};gate.observeLease(lease);
 const verify=async()=>({verified:true,deploymentId:id,appSha256:expected.appSha256,runtimeId:expected.runtimeId,spkiSha256:'ef'.repeat(32)});
 await gate.attest(id,verify);assert.equal(gate.allows(id),true);
 clock+=60000;gate.observeLease({...lease,validUntil:clock+90000});assert.equal(gate.allows(id),false);
 await gate.attest(id,verify);assert.equal(gate.allows(id),true);
 gate.observeLease({...lease,appRef:'catalog:a:2',validUntil:clock+90000});assert.equal(gate.allows(id),false);
 await assert.rejects(gate.attest(id,verify),/expectation/);
});

test('a missing deployment is revoked without withholding another app lease',async()=>{
 const missing='0x'+'ef'.repeat(32),readers=[client(),client()];
 for(const c of readers){const original=c.readContract;c.readContract=async args=>args.functionName==='get'&&args.args[0]===missing?{...row,id:'0x'+'00'.repeat(32)}:original(args);}
 const reader=new LeaseReader({addressBook:book,clients:readers,now});reader.cache.set(missing,{...row,id:missing,validUntil:now()+60000});
 assert.deepEqual((await reader.refresh([missing,id])).map(x=>x.id),[id]);assert.equal(reader.get(missing),null);assert.ok(reader.get(id));
});
test('a stalled snapshot cannot withhold an already agreeing quorum',async()=>{
 const slow=client();let release;const gate=new Promise(r=>release=r);slow.getBlock=async()=>{await gate;throw Error('late peer failure');};
 const reader=new LeaseReader({addressBook:book,clients:[slow,client(),client()],now});
 try{const result=await Promise.race([reader.refresh([id]),new Promise((_r,j)=>setTimeout(()=>j(Error('quorum stalled')),100))]);assert.equal(result.length,1);}finally{release();}
});
test('a transport failure keeps the last guest proof only until it expires; a mismatch revokes it now',async()=>{
 let clock=now();const expected={appRef:row.appRef,configCid:'',appSha256:'ab'.repeat(32),runtimeId:'cd'.repeat(32)};
 const gate=new AdmissionGate({runner,expected:()=>expected,now:()=>clock});
 gate.observeLease({...row,leaseUntil:clock+300000,validUntil:clock+300000});
 const verify=async()=>({verified:true,deploymentId:id,appSha256:expected.appSha256,runtimeId:expected.runtimeId,spkiSha256:'ef'.repeat(32)});
 await gate.attest(id,verify);assert.equal(gate.allows(id),true);
 const reset=Object.assign(new Error('Client network socket disconnected before secure TLS connection was established'),{code:'ECONNRESET'});
 for(const e of [reset,new Error('guest probe timeout'),new Error('guest attestation HTTP 503')]){assert.equal(transientProofError(e),true);assert.equal(gate.failed(id,e),true);assert.equal(gate.allows(id),true);}
 clock+=60001;assert.equal(gate.allows(id),false); // never extended by a failed refresh
 await gate.attest(id,verify);assert.equal(gate.allows(id),true);
 for(const e of [new Error('app, nonce or TLS binding mismatch'),new Error('guest attestation HTTP 403'),new Error('something unexpected'),undefined])assert.equal(transientProofError(e),false);
 assert.equal(gate.failed(id,new Error('app, nonce or TLS binding mismatch')),false);assert.equal(gate.allows(id),false);
});

test('publications arriving during a snapshot share the next one',async()=>{
 const other='0x'+'ef'.repeat(32);let heads=0;const peers=[client(),client()];
 for(const c of peers){const original=c.getBlockNumber;c.getBlockNumber=async()=>{heads++;return original();};
  const read=c.readContract;c.readContract=async args=>args.functionName==='get'?{...row,id:args.args[0]}:read(args);}
 const reader=new LeaseReader({addressBook:book,clients:peers,now});
 // Requested together: one snapshot answers both.
 const [x,y]=[reader.refresh([id]),reader.refresh([other])];
 assert.deepEqual((await x).map(r=>r.id),[id]);assert.deepEqual((await y).map(r=>r.id),[other]);assert.equal(heads,2);
 // Requested while a snapshot is in flight: all of them share the next one.
 let started;const inFlight=new Promise(r=>started=r);
 for(const c of peers){const original=c.getBlock;c.getBlock=async args=>{started();return original(args);};}
 const first=reader.refresh([id]);await inFlight;
 const [a,b,c]=[reader.refresh([other]),reader.refresh([id]),reader.refresh([other,id])];
 assert.deepEqual((await first).map(r=>r.id),[id]);
 assert.deepEqual((await a).map(r=>r.id),[other]);assert.deepEqual((await b).map(r=>r.id),[id]);assert.deepEqual((await c).map(r=>r.id),[other,id]);
 assert.equal(heads,6); // three snapshots on two peers, not five
 await assert.rejects(reader.refresh(['0xBAD']),/exact deployment ids/);
 assert.equal((await reader.refresh([id])).length,1);
});
test('a peer head lagging behind the accepted block rereads that block instead of refusing',async()=>{
 let head=1000n;const peers=[client(),client()];const asked=[];
 for(const c of peers){c.getBlockNumber=async()=>head;const original=c.getBlock;c.getBlock=async args=>{asked.push(args.blockNumber);return original(args);};}
 const reader=new LeaseReader({addressBook:book,clients:peers,now});
 await reader.refresh([id]);assert.equal(reader.lastBlock,998n);
 head=999n;assert.equal((await reader.refresh([id])).length,1);
 assert.equal(reader.lastBlock,998n);assert.ok(asked.slice(-4).every(n=>n===998n));
 // Reading the accepted block again still needs it to be recent.
 for(const c of peers)c.getBlock=async({blockNumber})=>({number:blockNumber,hash:'0x'+'aa'.repeat(32),timestamp:1699999800n});
 await assert.rejects(reader.refresh([id]),/agreeing chain quorum/);
});
test('only a rate-limit refusal is retried',async()=>{
 const limited=client(),broken=client();let limitedCalls=0,brokenCalls=0;
 limited.getChainId=async()=>{if(limitedCalls++<2)throw Error('RPC Request failed.\n\nDetails: You reached Public endpoint rate limit, please upgrade to paid plan');return 8453;};
 broken.getChainId=async()=>{brokenCalls++;throw Error('wrong answer');};
 const reader=new LeaseReader({addressBook:book,clients:[limited,client()],now});reader.retryDelayMs=1;
 assert.equal((await reader.refresh([id])).length,1);assert.equal(limitedCalls,3);
 const strict=new LeaseReader({addressBook:book,clients:[broken,client()],now});strict.retryDelayMs=1;
 await assert.rejects(strict.refresh([id]),/quorum unavailable/);assert.equal(brokenCalls,1);
});
test('an app whose host left the registry is withheld without failing the apps sharing its snapshot',async()=>{
 const moved='0x'+'ef'.repeat(32),gone='0x'+'99'.repeat(32);
 const peers=[client(),client()];
 for(const c of peers)c.readContract=async({functionName,args})=>functionName==='addr'?contract:functionName==='deploymentsSchema'?15n:
  args[0]===runner||args[0]===gone?{active:args[0]===runner,operator:book,payoutWallet:book,proofKey:book}:{...row,id:args[0],runner:args[0]===moved?gone:runner};
 const reader=new LeaseReader({addressBook:book,clients:peers,includeHostPayout:true,now});
 reader.cache.set(moved,{...row,id:moved,validUntil:now()+60000});
 assert.deepEqual((await reader.refresh([moved,id])).map(x=>x.id),[id]);
 assert.equal(reader.get(moved),null);assert.equal(reader.get(id).runnerPayoutWallet,book);assert.equal(reader.get(id).runnerRegistered,true);
 assert.ok(reader.failures.some(f=>f.includes('inactive or changed runner')));
});
test('a peer that never answers its head cannot hold the snapshot for its request timeout',async()=>{
 const hung=client();let release;hung.getBlockNumber=()=>new Promise(r=>release=r);
 const reader=new LeaseReader({addressBook:book,clients:[hung,client(),client()],now});reader.headGraceMs=20;
 const started=Date.now();
 try{assert.equal((await Promise.race([reader.refresh([id]),new Promise((_r,j)=>setTimeout(()=>j(Error('head phase stalled')),500))])).length,1);}
 finally{release?.(1000n);}
 assert.ok(Date.now()-started<500);
});
test('registry entries come from agreeing peers and decode only the original entry prefix',async()=>{
 const registry='0x'+'03'.repeat(20),host='0x'+'cd'.repeat(32),other='0x'+'ce'.repeat(32);
 const entry=(op,active)=>({endpoint:'https://x',repo:'',measurement:'0x'+'00'.repeat(32),operator:op,registeredAt:1n,lastSeen:1n,active});
 const peer=(op=book)=>{const c=client();c.readContract=async({address,functionName,args,abi})=>{
  assert.equal(address,registry);assert.equal(functionName,'get');assert.equal(abi[0].outputs[0].components.length,7);
  return args[0]===host?entry(op,true):entry('0x'+'00'.repeat(20),false);};return c;};
 const reader=new LeaseReader({addressBook:book,clients:[peer(),peer()],now});
 assert.deepEqual((await reader.registryEntries(registry,[host,other])).map(({id,active,operator})=>({id,active,operator})),
  [{id:host,active:true,operator:book.toLowerCase()},{id:other,active:false,operator:'0x'+'00'.repeat(20)}]);
 reader.clients=[peer(),peer('0x'+'09'.repeat(20))];
 await assert.rejects(reader.registryEntries(registry,[host]),/agreeing chain quorum/);
 await assert.rejects(reader.registryEntries('0xnope',[host]),/exact registry ids/);
 await assert.rejects(reader.registryEntries(registry,[]),/exact registry ids/);
});
test('a registry read does not wait behind a stalled lease snapshot',async()=>{
 const registry='0x'+'03'.repeat(20),host='0x'+'cd'.repeat(32);let stall=true,release;
 const gate=new Promise(r=>release=r);
 const peer=()=>{const c=client();const read=c.readContract;c.readContract=async args=>{
  if(args.address===registry)return {endpoint:'',repo:'',measurement:'0x'+'00'.repeat(32),operator:book,registeredAt:1n,lastSeen:1n,active:true};
  if(stall&&args.functionName==='get')await gate;return read(args);};return c;};
 const reader=new LeaseReader({addressBook:book,clients:[peer(),peer()],now});
 const lease=reader.refresh([id]);
 try{const [entry]=await Promise.race([reader.registryEntries(registry,[host]),new Promise((_r,j)=>setTimeout(()=>j(Error('registry read queued behind the lease snapshot')),300))]);
  assert.equal(entry.active,true);}
 finally{stall=false;release();}
 assert.equal((await lease).length,1);
});
test("schema 16 with no connectivity contract in the book reads as 15 under 'auto' (the 16d cutover outage)",async()=>{
 const zero='0x'+'00'.repeat(20);
 const c16=()=>{const c=client();c.readContract=async({functionName,args})=>functionName==='addr'?(String(args[0]).startsWith('0x636f6e6e')?zero:contract):functionName==='deploymentsSchema'?16n:row;return c;};
 const auto=new LeaseReader({addressBook:book,clients:[c16(),c16()],includeConnectivity:'auto',now});
 assert.equal((await auto.refresh([id]))[0].runner,runner);   // 'connectivity' is 0x636f6e6e... as bytes32
 const required=new LeaseReader({addressBook:book,clients:[c16(),c16()],includeConnectivity:true,now});
 await assert.rejects(required.refresh([id]),/agreeing chain quorum/);   // demanded explicitly: still refused without one
});

test('a refresh with NO agreeing answer holds a running lease up to the grace after its last agreeing read, never past its end',async()=>{
 let clock=now();
 const reader=new LeaseReader({addressBook:book,clients:[client(),client()],now:()=>clock});
 const [lease]=await reader.refresh([id]);
 assert.equal(lease.validUntil,1699999995000+90000);
 clock=lease.validUntil+1000;                                   // the read window passed: nothing is current
 assert.equal(reader.get(id),null);
 assert.deepEqual(reader.hold(10*60_000),[id]);
 assert.equal(reader.get(id).validUntil,1699999995000+600000,'held to ten minutes after the last agreeing read');
 clock=1699999995000+600000;assert.equal(reader.get(id),null,'and no longer');
 assert.deepEqual(reader.hold(10*60_000),[],'a second hold does not extend it again');
 const short=new LeaseReader({addressBook:book,clients:[client({value:{...row,leaseUntil:1700000060n}}),client({value:{...row,leaseUntil:1700000060n}})],now});
 await short.refresh([id]);short.now=()=>1700000050000;short.hold(10*60_000);
 assert.equal(short.get(id).validUntil,1700000060000,'never past the lease itself');
 short.now=()=>1700000061000;assert.deepEqual(short.hold(10*60_000),[],'an ended lease is not held');
});

test('a lease extended by an outage hold keeps the proofs made before it: a proof lasts its own 60 s (2026-10-14 07:28)',async()=>{
 let clock=now();const expected={appRef:row.appRef,configCid:'',appSha256:'ab'.repeat(32),runtimeId:'cd'.repeat(32)};
 const gate=new AdmissionGate({runner,expected:()=>expected,now:()=>clock});
 const lease={...row,leaseUntil:clock+300000,validUntil:clock+10000};gate.observeLease(lease);   // the last read: valid 10 s more
 const verify=async()=>({verified:true,deploymentId:id,appSha256:expected.appSha256,runtimeId:expected.runtimeId,spkiSha256:'ef'.repeat(32)});
 await gate.attest(id,verify);
 gate.observeLease({...lease,validUntil:clock+600000});                                   // the chain read failed: the lease is held
 clock+=20000;assert.equal(gate.allows(id),true,'the proof is not cut to the lease validity it was made under');
 clock+=40001;assert.equal(gate.allows(id),false,'and still lasts only its own 60 s');
});

// ---- late honest heads, one deadline, freshness at acceptance (2026-10-19 review) ----------------------------------
// A peer whose head arrives `delay` ms late and whose blocks age 2 s per block below 1000.
function peer({value=row,head=1000n,delay=0,hang=null}={}) {
 const p={reads:[],calls:0,
  getChainId:async()=>8453,
  getBlockNumber:async()=>{if(delay)await new Promise(r=>setTimeout(r,delay));return head;},
  getBlock:async({blockNumber})=>{p.calls++;if(hang)await hang;p.reads.push(blockNumber);return {number:blockNumber,hash:'0x'+(blockNumber%256n).toString(16).padStart(2,'0').repeat(32),timestamp:1699999995n-(1000n-blockNumber)*2n};},
  readContract:async({functionName})=>{p.calls++;return functionName==='addr'?contract:functionName==='deploymentsSchema'?15n:value;}};
 return p;
}
const liarRow={...row,runner:'0x'+'de'.repeat(32)};
test('a fast liar beside a fast honest RPC cannot shut out a slower honest head',async()=>{
 const reader=new LeaseReader({addressBook:book,clients:[peer({value:liarRow}),peer(),peer({delay:80})],now});reader.headGraceMs=10;
 const [lease]=await reader.refresh([id]);
 assert.equal(lease.runner,runner,'the two honest RPCs agree; the liar neither vetoes nor wins');
});
test('a liar whose low head makes the first block stale is outvoted at a newer block once the late honest head is in',async()=>{
 const slow=peer({delay:80}),fast=peer();
 const reader=new LeaseReader({addressBook:book,clients:[peer({value:liarRow,head:900n}),fast,slow],now});reader.headGraceMs=10;
 const [lease]=await reader.refresh([id]);
 assert.equal(lease.runner,runner);assert.equal(lease.blockNumber,'998');
 assert.ok(fast.reads.includes(898n)&&fast.reads.includes(998n),'block 898 was tried first and found stale');
 assert.equal(reader.lastBlock,998n);
});
test('a block that ages past the freshness bound during the read is not accepted',async()=>{
 let clock=now();
 // the clock passes the bound only once each peer has checked the block and read: at its recheck of the block hash
 const ager=()=>{const p=peer();const get=p.getBlock;let n=0;p.getBlock=async args=>{if(++n===2)clock=1699999995000+90000;return get(args);};return p;};
 const reader=new LeaseReader({addressBook:book,clients:[ager(),ager()],now:()=>clock});
 await assert.rejects(reader.refresh([id]),/fresh agreeing chain quorum/);
 assert.equal(reader.lastBlock,0n,'a refused read does not raise the accepted block');
});
test('one deadline bounds the whole read, and no request starts after it',async()=>{
 let release;const hang=new Promise(r=>release=r);
 const peers=[peer({hang}),peer({hang})];
 const reader=new LeaseReader({addressBook:book,clients:peers,now,deadlineMs:150});
 reader.cache.set(id,{...row,id,leaseUntil:now()+300000,blockTime:now()-1000,validUntil:now()+60000});
 const started=Date.now();
 await assert.rejects(reader.refresh([id]),/agreeing chain quorum/);
 assert.ok(Date.now()-started<1000,'refused at the deadline, not after the request timeouts');
 assert.ok(reader.get(id),'a read that got no answer leaves the cached lease to its own validity (and hold())');
 const before=peers.map(p=>p.calls);release();await new Promise(r=>setTimeout(r,50));
 assert.deepEqual(peers.map(p=>p.calls),before,'the hung reads, once released, issue nothing more');
 // a later refresh is not stuck behind the expired one
 const fresh=new LeaseReader({addressBook:book,clients:[peer(),peer()],now,deadlineMs:150});
 assert.equal((await fresh.refresh([id])).length,1);
});
test('an agreed inactive lease replaces the cache at once, and no hold revives it',async()=>{
 let clock=now();const expected={appRef:row.appRef,configCid:'',appSha256:'ab'.repeat(32),runtimeId:'cd'.repeat(32)};
 const reader=new LeaseReader({addressBook:book,clients:[peer(),peer()],now:()=>clock});
 const gate=new AdmissionGate({runner,expected:()=>expected,now:()=>clock});
 gate.observeLease((await reader.refresh([id]))[0]);
 await gate.attest(id,async()=>({verified:true,deploymentId:id,appSha256:expected.appSha256,runtimeId:expected.runtimeId,spkiSha256:'ef'.repeat(32)}));
 assert.equal(gate.allows(id),true);
 reader.clients=[peer({value:{...row,active:false}}),peer({value:{...row,active:false}})];
 const [off]=await reader.refresh([id]);gate.observeLease(off);
 assert.equal(off.active,false);assert.equal(gate.allows(id),false,'revoked with the proof still fresh');
 reader.clients=[peer({hang:new Promise(()=>{})}),peer({hang:new Promise(()=>{})})];reader.deadlineMs=100;
 await assert.rejects(reader.refresh([id]),/agreeing chain quorum/);
 reader.hold(600000);gate.observeLease(reader.get(id));assert.equal(gate.allows(id),false,'an outage hold keeps the inactive fact');
});

// ---- coordinator final review: high-water at decision, checked headers, clients, reserved fields ------------------
test('an answer is never older than a block another call on the same reader accepted meanwhile',async()=>{
 // call A chooses block 998 and stalls in its read; call B, on newer heads, accepts block 1008; A must move up to 1008
 let head=1000n,releaseA;const stalled=new Promise(r=>releaseA=r);
 const mk=()=>({getChainId:async()=>8453,getBlockNumber:async()=>head,
  getBlock:async({blockNumber})=>({number:blockNumber,hash:'0x'+blockNumber.toString(16).padStart(64,'0'),timestamp:1699999995n}),
  readContract:async()=>{throw Error('unused');}});
 const reader=new LeaseReader({addressBook:book,clients:[mk(),mk()],now});reader.headGraceMs=0;
 const asked=[];
 const a=reader.agreed(async(_c,b)=>{asked.push(b);if(b===998n)await stalled;return {v:'a'};});
 await new Promise(r=>setTimeout(r,20));                    // A has chosen 998 and is stalled there
 head=1010n;
 const b=await reader.agreed(async()=>({v:'b'}));
 assert.equal(b.blockNumber,'1008');assert.equal(reader.lastBlock,1008n);
 releaseA();
 const late=await a;
 assert.equal(late.blockNumber,'1008','A re-read at the newer accepted block, not 998');
 assert.ok(asked.includes(998n)&&asked.includes(1008n));
 assert.equal(reader.lastBlock,1008n);
 // and a refresh() after both still never goes below it
 assert.ok(BigInt((await reader.agreed(async()=>({v:'c'}))).blockNumber)>=1008n);
});
test('a header for another block, a malformed hash or timestamp, or a header that changes under the read is refused',async()=>{
 const run=async patch=>{const peers=[peer(),peer()];for(const p of peers){const get=p.getBlock;p.getBlock=async args=>patch(await get(args),args);}
  return new LeaseReader({addressBook:book,clients:peers,now}).refresh([id]);};
 assert.equal((await run(h=>h)).length,1);
 await assert.rejects(run(h=>({...h,number:h.number+1n})),/agreeing chain quorum/,'the header of another block');
 await assert.rejects(run(h=>({...h,number:undefined})),/agreeing chain quorum/,'no block number');
 await assert.rejects(run(h=>({...h,hash:'0x'+'ab'.repeat(31)})),/agreeing chain quorum/,'a 31-byte hash');
 await assert.rejects(run(h=>({...h,hash:'0xzz'+'ab'.repeat(31)})),/agreeing chain quorum/,'a non-hex hash');
 await assert.rejects(run(h=>({...h,timestamp:-1n})),/agreeing chain quorum/,'a negative timestamp');
 await assert.rejects(run(h=>({...h,timestamp:'soon'})),/agreeing chain quorum/,'a timestamp that is not a number');
 let n=0;await assert.rejects(run(h=>++n>2?{...h,timestamp:h.timestamp-1n}:h),/agreeing chain quorum/,'the timestamp changed between header reads');
 const failures=[];const peers=[peer(),peer()];for(const p of peers){const get=p.getBlock;p.getBlock=async a=>({...(await get(a)),number:a.blockNumber+1n});}
 await assert.rejects(new LeaseReader({addressBook:book,clients:peers,now}).agreed(async()=>({v:1}),failures));
 assert.ok(failures.some(f=>/number differs/.test(f)),'and the failures say why');
});
test('one client twice, or a client without the read calls, is refused',async()=>{
 const c=peer();
 assert.throws(()=>new LeaseReader({addressBook:book,clients:[c,c],now}),/two distinct clients/);
 assert.throws(()=>new LeaseReader({addressBook:book,clients:[peer(),{getChainId:async()=>8453}],now}),/invalid chain clients/);
 assert.throws(()=>new LeaseReader({addressBook:book,clients:[peer(),null],now}),/invalid chain clients/);
 const reader=new LeaseReader({addressBook:book,clients:[peer(),peer()],now});
 reader.clients=[c,c];await assert.rejects(reader.refresh([id]),/two distinct clients/);
 reader.clients=[c,peer(),c];await assert.rejects(reader.agreed(async()=>({v:1})),/two distinct clients/);
});
test('a read function cannot shadow the checked header, and its mistakes are reported as such',async()=>{
 const reader=new LeaseReader({addressBook:book,clients:[peer(),peer()],now});
 for(const field of ['timestamp','hash','blockNumber'])
  await assert.rejects(reader.agreed(async()=>({[field]:1,v:1})),new RegExp('reserved field '+field));
 await assert.rejects(reader.agreed(async()=>null),/must return an object/);
 await assert.rejects(reader.agreed(async()=>[1]),/must return an object/);
 await assert.rejects(reader.agreed('nope'),/read function/);
 const ok=await reader.agreed(async()=>({v:1}));
 assert.equal(ok.v,1);assert.equal(ok.timestamp,(1699999995-4)*1000);assert.match(ok.hash,/^0x[0-9a-f]{64}$/);assert.equal(ok.blockNumber,'998');
});

// ---- RPC identity and policy bounds (coordinator round 3) ------------------------------------------------------------
test('one public host is one vote, however its URL is written',async()=>{
 const {rpcIdentity}=await import('../network/lease-reader.mjs');
 const mk=rpc=>new LeaseReader({rpc,addressBook:book});
 assert.equal(mk(['https://rpc-a.example','https://rpc-b.example/key']).clients.length,2);
 for(const alias of ['https://RPC-A.example','https://rpc-a.example.','https://rpc-a.example:8443','https://rpc-a.example/v2/other-key','https://rpc-a.example/?apikey=2'])
  assert.throws(()=>mk(['https://rpc-a.example',alias]),/same host/,alias);
 // a local test chain is one vote per loopback port, whichever loopback name reaches it
 assert.equal(mk(['https://127.0.0.1:8545','https://localhost:8546']).clients.length,2);
 assert.throws(()=>mk(['https://127.0.0.1:8545','https://localhost:8545']),/same host/);
 assert.equal(rpcIdentity('https://Node.Example.:443/x?k=1'),'host:node.example');
});
test('a malformed RPC configuration is refused without echoing the URL',async()=>{
 const mk=rpc=>new LeaseReader({rpc,addressBook:book});
 for(const [bad,why] of [[['http://rpc-a.example','https://rpc-b.example'],/HTTPS/],[['https://user:secret@rpc-a.example','https://rpc-b.example'],/credentials/],
   [['https://rpc-a.example/#frag','https://rpc-b.example'],/fragment/],[['not a url','https://rpc-b.example'],/invalid RPC URL/],
   [['https://rpc-a.example'],/two independent/],['https://rpc-a.example',/two independent/],[Array.from({length:17},(_,i)=>`https://rpc-${i}.example`),/two independent/]]){
  let err;try{mk(bad);}catch(e){err=e;}
  assert.ok(err,'refused: '+JSON.stringify(bad).slice(0,60));assert.match(err.message,why);assert.ok(!/secret/.test(err.message),'no URL secret in the error');
 }
});
test('injected clients count by the URL they expose; URL-less test clients count by identity',async()=>{
 const {createPublicClient,http}=await import('viem');const {base}=await import('viem/chains');
 const viemClient=u=>createPublicClient({chain:base,transport:http(u)});
 assert.throws(()=>new LeaseReader({addressBook:book,clients:[viemClient('https://rpc-a.example/k1'),viemClient('https://RPC-A.example./k2')],now}),/same RPC host/);
 assert.equal(new LeaseReader({addressBook:book,clients:[viemClient('https://rpc-a.example'),viemClient('https://rpc-b.example')],now}).clients.length,2);
 const exposing=url=>({...peer(),transport:{url}});
 assert.throws(()=>new LeaseReader({addressBook:book,clients:[exposing('http://rpc-a.example'),peer()],now}),/unusable RPC URL/);
 assert.throws(()=>new LeaseReader({addressBook:book,clients:[exposing('::'),peer()],now}),/unusable RPC URL/);
 // the test seam stays: clients without a visible URL are distinct objects, vouched for by whoever built them
 const reader=new LeaseReader({addressBook:book,clients:[peer(),peer()],now});
 assert.equal((await reader.refresh([id])).length,1);
 // and a set reassigned later is checked again at the read
 reader.clients=[exposing('https://rpc-a.example/x'),exposing('https://rpc-a.example./y')];
 await assert.rejects(reader.refresh([id]),/same RPC host/);
 reader.clients=Array.from({length:17},()=>peer());await assert.rejects(reader.refresh([id]),/two to 16 chain clients/);
});
test('chain policy is bounded at construction and again at every read',async()=>{
 for(const p of [{chainId:0},{chainId:1.5},{maxBlockAgeMs:999},{maxBlockAgeMs:Infinity},{confirmations:0},{confirmations:65},{deadlineMs:99},{deadlineMs:NaN},{now:'soon'}])
  assert.throws(()=>new LeaseReader({addressBook:book,clients:[peer(),peer()],now,...p}),/invalid chain policy/,JSON.stringify(p));
 assert.throws(()=>new LeaseReader({addressBook:'0x12',clients:[peer(),peer()],now}),/invalid chain policy/);
 for(const [k,v] of [['headGraceMs',-1],['headGraceMs',Infinity],['retryDelayMs',NaN],['deadlineMs',10],['confirmations',0]]){
  const reader=new LeaseReader({addressBook:book,clients:[peer(),peer()],now});reader[k]=v;
  await assert.rejects(reader.refresh([id]),/invalid chain policy/,k+'='+v);
 }
});
test('a local chain over plain loopback HTTP is accepted with real viem clients; public HTTP is not',async()=>{
 const {createServer}=await import('node:http');const {createPublicClient,http}=await import('viem');const {base}=await import('viem/chains');
 const {rpcIdentity}=await import('../network/lease-reader.mjs');
 // two tiny JSON-RPC servers on loopback, answering only what agreed() asks: chain id, head, block headers
 const serve=()=>new Promise(ok=>{const srv=createServer((req,res)=>{let body='';req.on('data',d=>body+=d);req.on('end',()=>{
  const reply=q=>{const n=q.params?.[0];const result=q.method==='eth_chainId'?'0x2105':q.method==='eth_blockNumber'?'0x3e8':
   q.method==='eth_getBlockByNumber'?{number:n,hash:'0x'+BigInt(n).toString(16).padStart(64,'0'),timestamp:'0x'+(1699999995).toString(16),parentHash:'0x'+'00'.repeat(32),transactions:[]}:null;
   return {jsonrpc:'2.0',id:q.id,result};};
  const q=JSON.parse(body);res.setHeader('content-type','application/json');res.end(JSON.stringify(Array.isArray(q)?q.map(reply):reply(q)));});});
  srv.listen(0,'127.0.0.1',()=>ok(srv));});
 const [a,b]=await Promise.all([serve(),serve()]);
 try{
  const urls=[`http://127.0.0.1:${a.address().port}`,`http://localhost:${b.address().port}`];
  const viemClient=u=>createPublicClient({chain:base,transport:http(u,{retryCount:0})});
  const reader=new LeaseReader({addressBook:book,clients:urls.map(viemClient),now,deadlineMs:5000});
  const got=await reader.agreed(async()=>({v:'local'}));
  assert.equal(got.v,'local');assert.equal(got.blockNumber,'998');
  // the rpc option takes the same URLs (it builds its own viem clients)
  assert.equal(new LeaseReader({rpc:urls,addressBook:book}).clients.length,2);
  // one loopback port is one vote whichever loopback name or scheme reaches it
  const same=`http://localhost:${a.address().port}`;
  assert.throws(()=>new LeaseReader({addressBook:book,clients:[viemClient(urls[0]),viemClient(same)],now}),/same RPC host/);
  assert.throws(()=>new LeaseReader({rpc:[urls[0],same],addressBook:book}),/same host/);
  assert.equal(rpcIdentity('http://127.0.0.1'),'loopback:80');assert.equal(rpcIdentity('https://127.0.0.1'),'loopback:443');
  assert.equal(rpcIdentity('http://[::1]:8545'),'loopback:8545');
  // plain HTTP stays refused for every public host, however the client was built
  for(const u of ['http://rpc-a.example','http://127.0.0.2:8545','http://8.8.8.8:8545'])assert.throws(()=>rpcIdentity(u),/HTTPS \(plain HTTP only on loopback\)/,u);
  assert.throws(()=>new LeaseReader({addressBook:book,clients:[viemClient('http://rpc-a.example'),viemClient(urls[1])],now}),/unusable RPC URL/);
  assert.throws(()=>new LeaseReader({rpc:['http://rpc-a.example','https://rpc-b.example'],addressBook:book}),/HTTPS/);
 }finally{a.close();b.close();}
});
test('an address literal is one vote however it is spelled, including IPv4 written as IPv6; distinct addresses stay distinct',async()=>{
 const {rpcIdentity}=await import('../network/lease-reader.mjs');
 const mk=rpc=>new LeaseReader({rpc,addressBook:book});
 // the same IPv4 host: dotted, hex, integer, IPv4-mapped (any IPv6 spelling of it), NAT64 well-known prefix
 for(const alias of ['https://8.8.8.8/other','https://0x8.8.8.8','https://134744072','https://[::ffff:8.8.8.8]','https://[::FFFF:808:808]:8443',
   'https://[0:0:0:0:0:ffff:808:808]/k','https://[64:ff9b::8.8.8.8]']){
  assert.equal(rpcIdentity(alias),'host:8.8.8.8',alias);
  assert.throws(()=>mk(['https://8.8.8.8',alias]),/same host/,alias);
 }
 // the same IPv6 host however compressed or cased; and the same URL twice
 assert.throws(()=>mk(['https://[2001:db8::1]','https://[2001:DB8:0:0:0:0:0:1]:8443']),/same host/);
 assert.throws(()=>mk(['https://rpc-a.example/k','https://rpc-a.example/k']),/same host/);
 // distinct addresses are distinct votes
 assert.equal(mk(['https://8.8.8.8','https://8.8.4.4']).clients.length,2);
 assert.equal(mk(['https://[::ffff:8.8.8.8]','https://[::ffff:8.8.4.4]']).clients.length,2);
 assert.equal(mk(['https://[2001:db8::1]','https://[2001:db8::2]']).clients.length,2);
 assert.equal(mk(['https://8.8.8.8','https://[2001:4860:4860::8888]']).clients.length,2,'an IPv6 address is not folded onto an IPv4 one unless it embeds it');
 assert.equal(rpcIdentity('https://[::ffff:0:1]'),'host:0.0.0.1');assert.equal(rpcIdentity('https://[64:ff9b::1]'),'host:0.0.0.1');
 // a mapped loopback address is the loopback listener on that port, plain HTTP included, one vote with its other names
 assert.equal(rpcIdentity('http://[::ffff:127.0.0.1]:8545'),'loopback:8545');
 assert.throws(()=>mk(['http://127.0.0.1:8545','http://[::ffff:7f00:1]:8545']),/same host/);
 assert.throws(()=>mk(['http://localhost:8545','https://[::ffff:127.0.0.1]:8545']),/same host/);
 assert.equal(mk(['http://[::ffff:127.0.0.1]:8545','http://localhost:8546']).clients.length,2);
 // folding never opens plain HTTP to a public host, or to anything reached through a NAT64 translator
 for(const u of ['http://[::ffff:8.8.8.8]','http://[64:ff9b::8.8.8.8]','http://[64:ff9b::7f00:1]:8545'])assert.throws(()=>rpcIdentity(u),/plain HTTP only on loopback/,u);
});
