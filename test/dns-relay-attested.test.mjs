// The independent DNS-01 responder for direct guests' owner-committed names (relay/dns-relay.js
// DNS_CHALLENGE_AUTH=attested, relay/dns-challenge-attested.mjs): run as anyone's process with no fleet, registry,
// HMAC key, route map, eligibility API or Enclave origin, it writes a TXT value only for a push signed by a measured
// guest's attested key, for the alias that commits to that guest's deployment and current owner.
//
// The reports here are synthetic, so the responder runs the judge's explicit lab-unsigned mode (no AMD chain); every
// other check - signature, key binding, push-bound nonce, pinned measurement, HOST_DATA, runtime binding, alias - is
// the production code path. Real hardware evidence is a separate activation gate.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import dgram from 'node:dgram';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {generateKeyPairSync, sign, createHash, randomBytes} from 'node:crypto';
import {ABI2, bind2, runtimeId} from '../isolation/contract/runtime.mjs';
import {authorizePush, challengeLabel, pushNonce, PUSH_SIG_PREFIX} from '../relay/dns-challenge-attested.mjs';
import {challengeLabel as sdkLabel} from '../sdk/bootstrap/package.mjs';
import {judge} from '../isolation/m2/judge.mjs';

const delay=ms=>new Promise(r=>setTimeout(r,ms));
const port=()=>new Promise(resolve=>{const s=net.createServer().listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
const ZONE='acme.zone-b.example', MEAS='44'.repeat(48), APP='55'.repeat(32);
const DEP='0x'+'11'.repeat(32), OWNER='0x'+'33'.repeat(20), NEW_OWNER='0x'+'aa'.repeat(20);
const JIT={name:'wasmtime',version:'48.0.1',execution:'jit',targetIsa:'x86_64',hostIsa:'x86_64',cpuFeatures:'baseline',wx:'enforced',cache:'none'};
const ST=`exec_pages=allowed wx=clean maps=3 runtime=1 front=1 init=1 seccomp=${'d4'.repeat(32)} scope=cgroup:/dom1`;
const guestKey=()=>{const k=generateKeyPairSync('ec',{namedCurve:'P-256'});return {priv:k.privateKey,spki:k.publicKey.export({type:'spki',format:'der'})};};

function report(binding,{measurement=MEAS,hostData=DEP}={}){
  const r=Buffer.alloc(0x4a0);
  r.writeUInt32LE(5,0x00);r.writeBigUInt64LE(0x30000n,0x08);
  binding.copy(r,0x50);Buffer.from(APP,'hex').copy(r,0x70);Buffer.from(measurement,'hex').copy(r,0x90);
  Buffer.from(hostData.slice(2),'hex').copy(r,0xc0);
  Buffer.from('0103020500000075','hex').copy(r,0x180);r[0x188]=0x1a;r[0x189]=0x02;
  return r;
}
// push builds exactly what isolation/m2/front/acme.go sends (field order, nonce, signature domain).
function push(key,{op='set',value=createHash('sha256').update(randomBytes(8)).digest('base64url'),owner=OWNER,deploymentId=DEP,
  name=`_acme-challenge.${challengeLabel(deploymentId,owner)}.${ZONE}`,ts=Math.floor(Date.now()/1000),reportOpts={},signer=key,docKey=key,
  nonceOverride,extra}={}){
  const p={v:1,op,name,value,deploymentId,owner,ts,spki:key.spki.toString('base64')};
  const nonce=nonceOverride??pushNonce(p);
  const doc={tier:'T1',format:'sev-snp-guest-domain-v1',report:report(bind2(docKey.spki,nonce,runtimeId(JIT)),reportOpts).toString('base64'),
    transportKey:docKey.spki.toString('base64'),appSha256:APP,nonce:nonce.toString('hex'),abi:ABI2,runtime:JIT,runtimeSelfTest:ST};
  const body=Buffer.from(JSON.stringify({...p,attestation:doc,...extra}));
  return {body,sig:sign('sha256',Buffer.concat([Buffer.from(PUSH_SIG_PREFIX),body]),{key:signer.priv,dsaEncoding:'der'}).toString('base64'),name,value};
}

function query(name,type=16){const h=Buffer.alloc(12);h.writeUInt16BE(0x4242,0);h.writeUInt16BE(0x100,2);h.writeUInt16BE(1,4);return Buffer.concat([h,...name.split('.').map(v=>Buffer.concat([Buffer.from([v.length]),Buffer.from(v)])),Buffer.from([0,type>>>8,type&255,0,1])]);}
async function ask(dnsPort,name,tcp=false){
  const q=query(name);
  if(!tcp){const s=dgram.createSocket('udp4');try{const a=once(s,'message');s.send(q,dnsPort,'127.0.0.1');return (await Promise.race([a,delay(2000).then(()=>{throw Error('UDP timeout');})]))[0];}finally{s.close();}}
  return new Promise((resolve,reject)=>{const s=net.connect(dnsPort,'127.0.0.1',()=>{const n=Buffer.alloc(2);n.writeUInt16BE(q.length);s.write(Buffer.concat([n,q]));});let d=Buffer.alloc(0);s.on('data',c=>{d=Buffer.concat([d,c]);if(d.length>=2&&d.length>=2+d.readUInt16BE(0)){s.destroy();resolve(d.subarray(2));}});s.on('error',reject);s.setTimeout(2000,()=>{s.destroy();reject(Error('TCP timeout'));});});
}
const blank=Object.fromEntries(['DNS_READ_ONLY','IP_ZONE','APP_ZONE','TCP_ZONE','BOX_ZONE','APP_STATIC','ROUTE_MAP_URL','DNS_TXT_KEY','SECRET',
  'REGISTRY_ADDRESS','ENCLAVES','ENCLAVE_URL','ELIGIBILITY_API','DOMAINS_API','ADDRESS_BOOK_ADDRESS','BASE_RPC','ATTESTED_SHIELD_POLICY','ATTESTED_PUSH_READ_MS'].map(k=>[k,'']));

async function responder(t,extra={}){
  const dnsPort=await port(),apiPort=await port();
  const env={...process.env,...blank,DNS_CHALLENGE_AUTH:'attested',CHALLENGE_ZONE:ZONE,NS_NAME:'ns1.zone-b.example',DNS_BIND:'127.0.0.1',
    DNS_PORT:String(dnsPort),DNS_API_BIND:'127.0.0.1',DNS_API_PORT:String(apiPort),ATTESTED_MEASUREMENTS:MEAS,ATTESTED_JUDGE_MODE:'lab-unsigned',
    ATTESTED_KDS:'0',...extra};
  const child=spawn(process.execPath,['relay/dns-relay.js'],{env,stdio:['ignore','pipe','pipe']});
  let log='';child.stdout.on('data',c=>log+=c);child.stderr.on('data',c=>log+=c);t.after(()=>child.kill('SIGTERM'));
  let health;
  for(let i=0;i<80&&!health;i++){health=await fetch(`http://127.0.0.1:${apiPort}/health`).then(r=>r.json()).catch(()=>null);if(!health)await delay(100);}
  assert.ok(health,log);
  const post=(p,method='POST')=>fetch(`http://127.0.0.1:${apiPort}/v1/txt`,{method,body:p.body,headers:{'content-type':'application/json','x-attested-sig':p.sig}})
    .then(async r=>({status:r.status,body:await r.json()}));
  return {dnsPort,apiPort,health,post,log:()=>log};
}

test('an attested guest push is answered over DNS with no fleet, HMAC, route map or Enclave origin',async t=>{
  const r=await responder(t),key=guestKey();
  assert.deepEqual({mode:r.health.mode,zones:r.health.zones,judge:r.health.judgeMode,pins:r.health.measurements},
    {mode:'attested',zones:{challenge:ZONE},judge:'lab-unsigned',pins:1});
  const p=push(key),ok=await r.post(p);
  assert.equal(ok.status,200,JSON.stringify(ok.body)+r.log());
  for(const tcp of [false,true]){
    const a=await ask(r.dnsPort,p.name,tcp);
    assert.equal(a.readUInt16BE(6),1,'one TXT answer');assert.ok(a.includes(Buffer.from(p.value)),'the pushed dns-01 value');
  }
  // other zones are not this responder's; names without a value are NODATA, never NXDOMAIN (no RFC 8020 cut)
  assert.equal((await ask(r.dnsPort,'_acme-challenge.x.app.enclave.host')).readUInt16BE(2)&15,5);
  const none=await ask(r.dnsPort,`_acme-challenge.${'0'.repeat(32)}.${ZONE}`);assert.equal(none.readUInt16BE(2)&15,0);assert.equal(none.readUInt16BE(6),0);
  // delete needs the same proof, then the value is gone
  const del=await r.post(push(key,{op:'delete',value:p.value}),'DELETE');assert.equal(del.status,200,JSON.stringify(del.body));
  assert.equal((await ask(r.dnsPort,p.name)).readUInt16BE(6),0);
  assert.doesNotMatch(r.log(),/api\.enclave\.host|eligib|fleet|registry/i);
});

test('the responder refuses every push that is not the attested guest for this deployment and owner',async t=>{
  const r=await responder(t),key=guestKey(),other=guestKey();
  const cases={
    'signed by another key (TLS-key mismatch)':[push(key,{signer:other}),401],
    'attested key differs from the named key':[push(key,{docKey:other}),403],
    'previous owner\'s alias under the new owner':[push(key,{owner:NEW_OWNER,name:`_acme-challenge.${challengeLabel(DEP,OWNER)}.${ZONE}`}),403],
    'another deployment\'s HOST_DATA':[push(key,{reportOpts:{hostData:'0x'+'22'.repeat(32)}}),403],
    'unpinned launch measurement':[push(key,{reportOpts:{measurement:'66'.repeat(48)}}),403],
    'attestation for a different push':[push(key,{nonceOverride:randomBytes(32)}),403],
    'stale timestamp':[push(key,{ts:Math.floor(Date.now()/1000)-900}),401],
    'name outside the zone':[push(key,{name:`_acme-challenge.${challengeLabel(DEP,OWNER)}.zone-a.example`}),403],
    'not a dns-01 value':[push(key,{value:'x'.repeat(44)}),400],
    'extra field':[push(key,{extra:{note:1}}),400],
  };
  for(const [what,[p,status]] of Object.entries(cases)){
    const res=await r.post(p);assert.equal(res.status,status,`${what}: ${JSON.stringify(res.body)}`);
    assert.equal((await ask(r.dnsPort,p.name)).readUInt16BE(6),0,`${what} set a value`);
  }
  const mismatch=await r.post(push(key,{op:'delete'}));assert.equal(mismatch.status,400,'a delete body cannot be replayed as a set');
  // the NEW owner's guest may write - but only at its own alias, which the previous owner's DNS delegation does not name
  const moved=push(key,{owner:NEW_OWNER});assert.equal((await r.post(moved)).status,200);
  assert.notEqual(moved.name,`_acme-challenge.${challengeLabel(DEP,OWNER)}.${ZONE}`);
});

test('attested mode refuses to start with any central fallback or without explicit pins',async()=>{
  for(const extra of [{DNS_TXT_KEY:'ab'.repeat(32)},{ROUTE_MAP_URL:'https://api.enclave.host/v1/network/routes'},{REGISTRY_ADDRESS:'0x'+'12'.repeat(20)},
    {ELIGIBILITY_API:'https://api.enclave.host'},{IP_ZONE:'ip.test'},{DNS_READ_ONLY:'1'},{ATTESTED_MEASUREMENTS:''},{ATTESTED_MEASUREMENTS:'44'},
    {ATTESTED_JUDGE_MODE:'t0-diagnostic'},{CHALLENGE_ZONE:''},{DNS_CHALLENGE_AUTH:'hmac'},
    {ADDRESS_BOOK_ADDRESS:'0x'+'12'.repeat(20)},{BASE_RPC:'https://mainnet.base.org'},{ATTESTED_PUSH_READ_MS:'500'},{ATTESTED_PUSH_READ_MS:'abc'}]){
    const child=spawn(process.execPath,['relay/dns-relay.js'],{env:{...process.env,...blank,DNS_CHALLENGE_AUTH:'attested',CHALLENGE_ZONE:ZONE,NS_NAME:'ns.test',
      ATTESTED_MEASUREMENTS:MEAS,DNS_PORT:'0',DNS_API_PORT:'0',...extra},stdio:'pipe'});
    let log='';child.stderr.on('data',c=>log+=c);const kill=setTimeout(()=>child.kill('SIGKILL'),5000);
    const [code]=await once(child,'close');clearTimeout(kill);assert.equal(code,1,`${JSON.stringify(extra)} started: ${log}`);
  }
});

test('the Go guest and this responder agree on the push wire format; a T0 document is never enough',async()=>{
  const v=JSON.parse(fs.readFileSync(new URL('../isolation/m2/front/testdata/attested-push.json',import.meta.url)));
  const p=JSON.parse(v.Body);
  assert.equal(pushNonce(p).toString('hex'),v.Nonce,'nonce derivation');
  assert.equal(p.attestation.nonce,v.Nonce);
  assert.equal(p.name,`_acme-challenge.${challengeLabel(p.deploymentId,p.owner)}.acme.example.net`);
  assert.equal(challengeLabel(p.deploymentId,p.owner),sdkLabel(p.deploymentId,p.owner),'relay and SDK labels agree');
  const now=()=>p.ts*1000;
  const res=await authorizePush({raw:Buffer.from(v.Body),sig:v.Sig,method:'POST',zone:'acme.example.net',measurements:new Set([MEAS]),mode:'lab-unsigned',judge,now});
  assert.equal(res.ok,false);assert.match(res.why,/no hardware attestation/,'the signature verified; only the missing report refused it');
  const forged=await authorizePush({raw:Buffer.from(v.Body),sig:Buffer.alloc(70).toString('base64'),method:'POST',zone:'acme.example.net',measurements:new Set([MEAS]),mode:'lab-unsigned',judge,now});
  assert.match(forged.why,/not signed by the named key/);
});

test('in trusted mode a synthetic report never authorizes a write',async()=>{
  const key=guestKey(),p=push(key);
  const res=await authorizePush({raw:p.body,sig:p.sig,method:'POST',zone:ZONE,measurements:new Set([MEAS]),mode:'trusted',kds:false,judge});
  assert.equal(res.ok,false);assert.match(res.why,/attestation (reject|unauthenticated)/);
});

// The push endpoint's own bounds, through the real relay process: every request gets exactly one answer.
test('push bounds: unknown routes answer at once; oversized, slow and excess concurrent bodies are refused; slots come back',async t=>{
  const http=await import('node:http');
  const r=await responder(t,{ATTESTED_PUSH_READ_MS:'1000'});
  const base=`http://127.0.0.1:${r.apiPort}`;
  // unknown and wrong-method routes: a JSON 404 within a second (nothing is left hanging)
  for(const [method,path] of [['POST','/v1/shield-session/challenge'],['POST','/v1/shield-session/unknown'],['GET','/v1/txt'],['POST','/v1/nope']]){
    const res=await fetch(base+path,{method,body:method==='GET'?undefined:'{}',signal:AbortSignal.timeout(1000)});
    assert.equal(res.status,404,`${method} ${path}`);assert.equal((await res.json()).error,'not_found');
  }
  // a declared length over 64 KiB: 413 before any body byte; a streamed one: 413 at the bound
  const raw=(headers,write)=>new Promise((resolve,reject)=>{
    const q=http.request({host:'127.0.0.1',port:r.apiPort,path:'/v1/txt',method:'POST',headers},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});
    q.on('error',e=>e.code==='ECONNRESET'||e.code==='EPIPE'?null:reject(e));q.flushHeaders();write?.(q);
    setTimeout(()=>{q.destroy();resolve('no answer');},4000).unref();
  });
  assert.equal(await raw({'content-length':65537}),413);
  assert.equal(await raw({'transfer-encoding':'chunked'},q=>q.write(Buffer.alloc(70000,0x20))),413);
  // a body that does not arrive within ATTESTED_PUSH_READ_MS: 408
  const t0=Date.now();
  assert.equal(await raw({'content-length':100},q=>q.write('{"v":1')),408);
  assert.ok(Date.now()-t0<3000,'the read deadline holds');
  // 16 verifications at most: 16 held bodies, the 17th is 503 busy with retry-after, from other peers' sockets too
  const held=[];
  for(let i=0;i<16;i++){const q=http.request({host:'127.0.0.1',port:r.apiPort,path:'/v1/txt',method:'POST',headers:{'content-length':100}});q.on('error',()=>{});q.on('response',x=>x.resume());q.flushHeaders();q.write('{');held.push(q);}
  await delay(200);
  const busy=await fetch(base+'/v1/txt',{method:'POST',body:'{}',signal:AbortSignal.timeout(1000)});
  assert.equal(busy.status,503);assert.equal(busy.headers.get('retry-after'),'1');
  for(const q of held)q.destroy();
  await delay(300);
  // every slot came back: a genuine push passes
  const key=guestKey(),p=push(key),ok=await r.post(p);
  assert.equal(ok.status,200,JSON.stringify(ok.body)+r.log());
  assert.doesNotMatch(r.log(),/unhandledRejection|uncaughtException/);
});
