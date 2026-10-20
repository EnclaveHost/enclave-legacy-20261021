import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import {execFileSync} from 'node:child_process';
import {generateKeyPairSync,createPublicKey} from 'node:crypto';
import {getAddress} from 'viem';
import {privateKeyToAccount} from 'viem/accounts';
import {PublicDirectory} from '../network/public-directory.mjs';
import {createDirectoryServer} from '../network/directory-server.mjs';
import {managementBase,signManagementRecord,validateManagementRecord,managementFor} from '../network/management-record.mjs';
import {managementRoute,managementTarget} from '../network/management-routes.mjs';
import {createManagementGateway,managementUpstream} from '../network/management-gateway.mjs';
import {ManagementClient,sessionRequestSigner} from '../network/management-client.mjs';
import {managementRecord,publishManagementRecord} from '../network/management-host.mjs';
import {createSessionApiAuth,apiBases,sessionKeyHash,API_SCOPES} from '../windows/node/session-api-auth.mjs';
import {LeaseReader} from '../network/lease-reader.mjs';

// Real: TLS (gateway key pinned by a real secp256k1 operator signature), the public directory server over HTTP,
// EnclaveSession P-256 request signatures, the gateway's quorum authorization through the real LeaseReader.agreed() over
// three RPC clients (each scriptable to lie, lag or fail), and the HTTP hops. Test doubles: the RPC endpoints' chain
// state, and in most tests the supervisor, a stand-in running the SAME session verifier with the base construction
// supervisor.js uses. The last tests run the actual supervisor.js with test-only local fixtures behind the gateway.
const operator=privateKeyToAccount('0x'+'2'.repeat(64)),stranger=privateKeyToAccount('0x'+'4'.repeat(64));
const id='0x'+'ab'.repeat(32),runner='0x'+'cd'.repeat(32),otherRunner='0x'+'ce'.repeat(32);
const pins={deployments:'0x'+'05'.repeat(20),registry:'0x'+'06'.repeat(20),connectivity:'0x'+'00'.repeat(20),sessionVaultFactory:'0x'+'07'.repeat(20)};
const vault=getAddress('0x'+'88'.repeat(20)),sid='0x'+'99'.repeat(32),wallet=getAddress('0x'+'77'.repeat(20));
const PUBLIC={address:'8.8.4.4',port:8443};
const cert=dir=>{execFileSync('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=host-management','-days','1','-keyout',dir+'/key','-out',dir+'/cert'],{stdio:'ignore'});
  return {key:fs.readFileSync(dir+'/key'),cert:fs.readFileSync(dir+'/cert')};};
const collect=async s=>{const c=[];for await(const x of s)c.push(x);return Buffer.concat(c);};
// a later record of the same operator: sequence and issue time move together (a sequence never runs ahead of its issue time)
const later=(r,n)=>({sequence:r.sequence+n,issuedAt:r.issuedAt+n});
const assertIdle=s=>assert.deepEqual([s.inFlight,s.mutating,s.preAuth,s.authorizing],[0,0,0,0],JSON.stringify(s));

// ---- the chain the RPCs report ----
const sleepMs=ms=>new Promise(r=>setTimeout(r,ms));
const ZERO20='0x'+'00'.repeat(20),ZERO32='0x'+'00'.repeat(32);
function chainWorld({runner,keyHash,actions}){
  const now=Math.floor(Date.now()/1000);
  return {block:1000n,blockTime:now,down:new Set(),delayMs:0,delays:new Map(),liars:new Map(),reads:0,
    state:{row:{owner:vault.toLowerCase(),runner,runnerOperator:operator.address.toLowerCase(),active:true,leaseUntil:now+600},
      host:{active:true,operator:operator.address.toLowerCase()},
      vaults:{[vault.toLowerCase()]:{owner:wallet.toLowerCase(),held:{[id]:2},sessions:{[sid]:{keyHash,actions,envs:2,expiresAt:now+3600,live:true}}}},
      ledgerCode:'0x',delegated:new Set()}};
}
// One RPC endpoint over the world; liars.get(i) rewrites what endpoint i reports.
function fakeClient(world,i){
  const view=()=>{const s=world.state,lie=world.liars.get(i);return lie?lie(structuredClone({...s,delegated:[...s.delegated]})):{...s,delegated:[...s.delegated]};};
  const up=()=>{if(world.down.has(i))throw Error('rpc '+i+' unavailable');};
  return {
    getChainId:async()=>{up();return 8453;},
    getBlockNumber:async()=>{up();return world.block;},
    getBlock:async({blockNumber})=>{up();return {number:blockNumber,timestamp:BigInt(world.blockTime),hash:'0x'+blockNumber.toString(16).padStart(64,'0')};},
    getCode:async()=>{up();return view().ledgerCode;},
    getStorageAt:async({slot})=>{up();return view().delegated.includes(slot)?'0x'+'0'.repeat(63)+'1':'0x'+'0'.repeat(64);},
    readContract:async({address,functionName,args})=>{
      up();world.reads++;if(world.delayMs)await sleepMs(world.delayMs);if(world.delays.get(i))await sleepMs(world.delays.get(i));
      const s=view(),a=address.toLowerCase();
      if(functionName==='deploymentsSchema')return 16n;
      if(functionName==='get'&&a===pins.deployments)return {id:args[0],owner:getAddress(s.row.owner),appRef:'',ports:'',configCid:'',gpuMilli:0,cpuMilli:100,appPort:8080,
        isPublic:false,active:s.row.active,createdAt:0n,rate:0n,balance6:0n,spent6:0n,runner:s.row.runner,runnerOperator:getAddress(s.row.runnerOperator),leaseUntil:BigInt(s.row.leaseUntil)};
      if(functionName==='get'&&a===pins.registry)return {endpoint:'',repo:'',measurement:ZERO32,operator:getAddress(s.host.operator),registeredAt:0n,lastSeen:0n,active:s.host.active,
        cpuPricePerSec6:0n,gpuPricePerSec6:0n,proofKey:ZERO20,payoutWallet:ZERO20};
      if(functionName==='isVault')return a===pins.sessionVaultFactory&&!!s.vaults[String(args[0]).toLowerCase()];
      const v=s.vaults[a];if(!v)throw Error('no contract at '+a);
      if(functionName==='owner')return getAddress(v.owner);
      if(functionName==='held')return [v.held[String(args[0]).toLowerCase()]||0,ZERO32,ZERO32];
      if(functionName==='sessionOf'){const x=v.sessions[String(args[0]).toLowerCase()];
        return x?[{keyHash:x.keyHash,actions:x.actions,envs:x.envs,expiresAt:BigInt(x.expiresAt)},x.live,[]]:[{keyHash:ZERO32,actions:0n,envs:0,expiresAt:0n},false,[]];}
      throw Error('unexpected chain read '+functionName);
    }};
}
const honestClient=world=>{const c=fakeClient(world,-1);return {readContract:c.readContract,getCode:c.getCode,getStorageAt:c.getStorageAt};};

async function rig(t,{scope=['api.status','api.logs','api.restart','api.appAccess'],gateway:gatewayOptions={},runner:hostRunner=runner,upstream=null,session:fixedSession=null,browser=null}={}){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'management-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  fs.mkdirSync(dir+'/a');fs.mkdirSync(dir+'/b');const tls=cert(dir+'/a'),wrongTls=cert(dir+'/b');
  const session=fixedSession||generateKeyPairSync('ec',{namedCurve:'P-256'}),jwk=createPublicKey(session.privateKey).export({format:'jwk'});
  const keyHash=sessionKeyHash(Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url'));
  const actions=scope.reduce((a,s)=>a|(1n<<API_SCOPES[s]),0n);
  // The chain the RPCs report: one vault, one live session holding the deployment in production, this runner leased.
  const world=chainWorld({runner:hostRunner,keyHash,actions});
  const chain={set live(v){world.state.vaults[vault.toLowerCase()].sessions[sid].live=v;}};
  const pc=honestClient(world);   // the supervisor stand-in's own (legacy, single-RPC) verifier
  const gatewayReader=new LeaseReader({clients:[0,1,2].map(i=>fakeClient(world,i)),chainId:8453,addressBook:'0x'+'00'.repeat(20),authorityPins:pins});
  const leaseOf=()=>({id,owner:vault,runner:hostRunner,runnerOperator:operator.address,chainId:8453,deployments:pins.deployments,active:true,isPublic:false,
    leaseUntil:Date.now()+600000,validUntil:Date.now()+90000,appRef:'catalog://app/0',configCid:'',blockNumber:'1'});
  const clientLease=leaseOf();
  // the host's view of the lease IS the chain world (what the RPCs report)
  const row=world.state.row;
  const hostLease={get owner(){return row.owner;},set owner(v){row.owner=v.toLowerCase();},get runner(){return row.runner;},set runner(v){row.runner=v;},
    set validUntil(ms){row.leaseUntil=Math.ceil(ms/1000);}};
  const reader=lease=>({refresh:async()=>{},get:()=>structuredClone(lease)});
  // the supervisor stand-in, on loopback
  const hits=[],mode={},profileEffects=[];let restarts=0,release;
  const supervisorAuth=createSessionApiAuth({pc,authorityPins:{deployments:pins.deployments,sessionVaultFactory:pins.sessionVaultFactory},
    bases:()=>apiBases({hosts:[managementBase(hostRunner)],publicUrls:['https://host.independent.example']})});
  const supervisor=http.createServer(async(req,res)=>{
    hits.push(req.method+' '+req.url);const body=await collect(req);
    const route=managementRoute(req.method,req.url);
    if(!route){res.writeHead(200);return res.end('ADMIN SURFACE');}
    try{const s=await supervisorAuth.verify({header:req.headers.authorization,method:req.method,path:req.url,body,scope:route.scope,fresh:true});
      const why=await supervisorAuth.refusal(s,{id,owner:vault});if(why)throw Object.assign(Error(why),{status:403});}
    catch(e){res.writeHead(e.status||401,{'content-type':'application/json'});return res.end(JSON.stringify({code:'unauthorized',message:e.message}));}
    if(route.op==='status'){res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({id,status:'running'}));}
    if(route.op==='attestation'){res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({deploymentId:id,cpu:{format:'fixture-not-snp'}}));}
    if(route.op==='appToken'){res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({token:'app-origin-token',tokenType:'Cookie',deployment:id,expiresAt:new Date(Date.now()+3600e3).toISOString()}));}
    if(route.op==='cpuProfile'){res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({state:'complete',seconds:5,format:'gperftools',bytes:4,data:Buffer.from('prof').toString('base64')}));}
    if(route.op==='cpuProfileControl'){
      if(mode.profile==='422'){res.writeHead(422,{'content-type':'application/json'});return res.end(JSON.stringify({error:'seconds must be an integer from 1 to 60'}));}
      profileEffects.push(JSON.parse(body));
      if(mode.profile==='409'){res.writeHead(409,{'content-type':'application/json'});return res.end(JSON.stringify({error:'CPU profiler did not acknowledge the signal'}));}
      if(mode.profile==='malformed'){res.writeHead(200,{'content-type':'application/json'});return res.end('{"state":');}
      res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({state:'active',seconds:5,format:'gperftools',oneCapturePerProcess:true}));
    }
    if(route.op==='logs'&&mode.logs==='trickle'){res.writeHead(200,{'content-type':'text/plain'});const iv=setInterval(()=>res.write('.'),30);res.once('close',()=>clearInterval(iv));return;}
    if(route.op==='logs'){res.writeHead(200,{'content-type':'text/plain'});res.write('# status=running\n');await new Promise(r=>release=r);res.end('line two\n');return;}
    if(mode.restart==='not_running'){res.writeHead(409,{'content-type':'application/json'});return res.end(JSON.stringify({code:'not_running',message:'Only a running deployment restarts in place'}));}
    restarts++;   // from here on the restart has a side effect, whatever the answer says
    if(mode.restart==='malformed'){res.writeHead(200,{'content-type':'application/json'});return res.end('{"id":');}
    if(mode.restart==='500'){res.writeHead(500,{'content-type':'application/json'});return res.end(JSON.stringify({code:'internal',message:'boom'}));}
    if(mode.restart==='wrong-shape'){res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({ok:true}));}
    if(mode.restart==='drop')return req.socket.destroy();
    if(mode.restart==='cut'){res.writeHead(200,{'content-type':'application/json'});res.write('{"id":');return setTimeout(()=>req.socket.destroy(),20);}
    res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({id,status:'running',note:'Restarted in place'}));
  });
  await new Promise(r=>supervisor.listen(0,'127.0.0.1',r));
  const gateway=createManagementGateway({tls,runner:hostRunner,pins,reader:gatewayReader,
    ...(browser?{browserTls:{hostname:new URL(browser.origin).hostname,key:browser.tls.key,cert:browser.tls.cert},dashboards:browser.dashboards}:{}),
    upstream:upstream||`http://127.0.0.1:${supervisor.address().port}`,...gatewayOptions});
  let gatewayRequests=0,gatewayBytes=0;
  gateway.on('request',()=>gatewayRequests++);gateway.on('secureConnection',s=>s.on('data',b=>{gatewayBytes+=b.length;}));
  await new Promise(r=>gateway.listen(0,'127.0.0.1',r));
  // the public directory, over real HTTP; the host operator is the registry's active operator for this runner
  const directory=new PublicDirectory({directory:dir+'/directory',checkers:['0x'+'03'.repeat(20)],hostOperator:async r=>r===hostRunner?operator.address:null,
    leaseOf:async()=>null,verifyOwner:async()=>false,importManagement:true});
  const directoryServer=createDirectoryServer(directory);await new Promise(r=>directoryServer.listen(0,'127.0.0.1',r));
  const dirOrigin=`http://127.0.0.1:${directoryServer.address().port}`;
  t.after(()=>{for(const s of [supervisor,gateway,directoryServer]){s.closeAllConnections?.();s.close();}});
  const publish=async(over={},account=operator)=>{const record={...managementRecord({operator:operator.address,runner:hostRunner,deployments:pins.deployments,...PUBLIC,cert:tls.cert,now:Date.now(),
    browser:browser?{origin:browser.origin,dashboards:browser.dashboards}:null}),...over};
    const env=await signManagementRecord(account,record);await directory.accept('management',env);return env;};
  // The production transport dials the record's public literal address; only this test maps it to the local listener.
  const realRequest=https.request;
  t.mock.method(https,'request',(options,callback)=>{
    if(options.host!==PUBLIC.address)return realRequest(options,callback);
    assert.equal(options.port,PUBLIC.port);return realRequest({...options,host:'127.0.0.1',port:gateway.address().port},callback);
  });
  // every fetch the owner client makes; only the operator-selected directory answers (no Enclave API, relay or tunnel)
  const calls=[];let serve=null;
  const fetchImpl=async(url,init)=>{calls.push(String(url));if(!String(url).startsWith(dirOrigin+'/'))throw TypeError('refused: not an operator-selected directory');
    return serve?serve(url,init):fetch(url,init);};
  const signer=sessionRequestSigner({vault,sid,privateKey:session.privateKey});
  const client=(over={})=>new ManagementClient({deploymentId:id,authorityPins:pins,directories:[dirOrigin],stateDir:dir+'/client',signer,
    reader:reader(clientLease),fetch:fetchImpl,...over});
  const raw=(method,target,{header,base=managementBase(hostRunner),body=''}={})=>new Promise((resolve,reject)=>{
    const req=realRequest({host:'127.0.0.1',port:gateway.address().port,method,path:target,rejectUnauthorized:false,agent:false,
      headers:{authorization:header??signer({method,hostPath:base+target,body:Buffer.from(body)}),...(body?{'content-length':Buffer.byteLength(body)}:{})}},async res=>{
      const b=(await collect(res)).toString();let json=null;try{json=JSON.parse(b);}catch{}resolve({status:res.statusCode,body:b,json});});
    req.on('error',reject);req.end(body||undefined);});
  return {client,publish,raw,signer,directory,dirOrigin,calls,hits,mode,profileEffects,clientLease,hostLease,wrongTls,tls,chain,session,reader,fetchImpl,world,
    stats:()=>gateway.managementStats(),gatewayPort:()=>gateway.address().port,
    setServe:f=>{serve=f;},release:()=>release?.(),counts:()=>({restarts,gatewayRequests,gatewayBytes})};
}

test('owner status, streamed logs and attestation reach the current runner with no Enclave service',async t=>{
  const r=await rig(t);await r.publish();const c=r.client();
  const status=await c.status();
  assert.deepEqual(status.json,{id,status:'running'});assert.equal(status.authenticated,'host-management-record');assert.equal(status.runner,runner);
  const logs=await c.logs({tail:50});const it=logs.body[Symbol.asyncIterator]();
  assert.equal((await it.next()).value.toString(),'# status=running\n','the first chunk arrives before the host finishes');
  r.release();assert.equal(Buffer.concat([...(await (async()=>{const x=[];for(let n=await it.next();!n.done;n=await it.next())x.push(n.value);return x;})())]).toString(),'line two\n');
  const att=await c.attestation({nonce:'ab'.repeat(32)});assert.equal(att.json.cpu.format,'fixture-not-snp');
  assert(r.calls.length>0&&r.calls.every(u=>u.startsWith(r.dirOrigin+'/v1/network/records')),JSON.stringify(r.calls));
  assert.deepEqual(r.hits,[`GET /v1/deployments/${id}`,`GET /v1/deployments/${id}/logs?tail=50`,`GET /v1/deployments/${id}/attestation?nonce=${'ab'.repeat(32)}`]);
});

test('restart is attempted exactly once, and a possibly delivered restart is never resent',async t=>{
  const r=await rig(t);await r.publish();const c=r.client();
  assert.equal((await c.restart()).json.status,'running');assert.equal(r.counts().restarts,1);
  r.mode.restart='drop';   // the supervisor received it, then the connection died
  await assert.rejects(c.restart(),e=>e.outcomeUnknown===true&&e.code==='restart_outcome_unknown');
  assert.equal(r.counts().restarts,2);
  r.mode.restart='cut';    // the answer started and was cut off
  await assert.rejects(c.restart(),e=>e.outcomeUnknown===true&&e.sent===true);
  await new Promise(x=>setTimeout(x,100));
  assert.equal(r.counts().restarts,3,'each call reached the host once; nothing retried');
  // a replayed copy of a signed restart is refused by the gateway before the supervisor sees it
  const target=managementTarget('restart',id),header=r.signer({method:'POST',hostPath:managementBase(runner)+target,body:Buffer.alloc(0)});
  r.mode.restart=undefined;
  assert.equal((await r.raw('POST',target,{header})).status,200);
  assert.equal((await r.raw('POST',target,{header})).status,401);assert.equal(r.counts().restarts,4);
});

test('a wrong owner or a host that is not the current runner gets nothing',async t=>{
  const r=await rig(t);await r.publish();
  r.hostLease.owner=getAddress('0x'+'66'.repeat(20));   // the ledger owner changed: this session belongs to someone else now
  await assert.rejects(r.client().status(),e=>e.status===403);
  r.hostLease.owner=vault;r.hostLease.runner=otherRunner;  // the gateway's host no longer holds the lease
  await assert.rejects(r.client().restart(),e=>e.status===409&&e.outcomeUnknown===false);
  r.hostLease.runner=runner;r.clientLease.runner=otherRunner;   // the chain names another runner: its endpoint is unknown
  const before=r.counts().gatewayRequests;
  await assert.rejects(r.client().restart(),/no current management record/);
  assert.equal(r.counts().gatewayRequests,before);assert.equal(r.counts().restarts,0);assert.deepEqual(r.hits,[]);
});

test('stale, withdrawn, foreign-signed and equivocating records refuse before any connection',async t=>{
  const r=await rig(t);const first=await r.publish();
  // a record signed by a key the lease does not name is not this runner's endpoint
  await assert.rejects(r.directory.accept('management',await signManagementRecord(stranger,{...first.record,operator:stranger.address.toLowerCase(),...later(first.record,1)})),/registry operator/);
  const c=r.client();assert.equal((await c.status()).status,200);
  // withdrawal: newer, endpoint null
  const w=await r.publish({address:null,port:null,spkiSha256:null,...later(first.record,5)});
  await assert.rejects(c.status(),/withdrew/);
  // a stale directory copy replays the older endpoint: the client's floor refuses it
  const stale={version:1,providers:[],policies:[],publications:[],management:[first]};
  r.setServe(async()=>Response.json(stale));
  await assert.rejects(c.status(),/stale management record/);
  // two different records at one sequence
  const twin=await signManagementRecord(operator,{...w.record,expiresAt:w.record.expiresAt-1});
  r.setServe(async()=>Response.json({...stale,management:[w,twin]}));
  await assert.rejects(c.status(),/equivocation/);
  // directory side: rollback and equivocation are refused there too
  await assert.rejects(r.directory.accept('management',first),/stale/);
  await assert.rejects(r.directory.accept('management',twin),/equivocation/);
  // an expired record is never current
  r.setServe(null);
  const fresh=r.client({stateDir:fs.mkdtempSync(path.join(os.tmpdir(),'management-fresh-')),now:()=>Date.now()+7*3600*1000});
  await assert.rejects(fresh.status(),/no current lease|no current management record/);
  assert.equal(r.counts().gatewayRequests,1);assert.equal(r.counts().restarts,0);
});

test('a gateway presenting a key other than the signed one receives no application byte',async t=>{
  const r=await rig(t);
  await r.publish({spkiSha256:managementRecord({operator:operator.address,runner,deployments:pins.deployments,...PUBLIC,cert:r.wrongTls.cert}).spkiSha256});
  await assert.rejects(r.client().restart(),e=>/does not match the signed host record/.test(e.message)&&e.sent===false&&e.outcomeUnknown===false);
  assert.equal(r.counts().gatewayRequests,0);assert.equal(r.counts().gatewayBytes,0);assert.equal(r.counts().restarts,0);
});

test('admin, listing, deletion and rebinding attempts never reach the supervisor',async t=>{
  const r=await rig(t);await r.publish();
  for(const [method,target] of [['POST',`/v1/admin/deployments/${id}/provision`],['GET','/v1/admin/gpu'],['GET','/v1/deployments'],['DELETE',`/v1/deployments/${id}`],
    ['PUT',`/v1/deployments/${id}/cpu-profile`],['POST',`/v1/deployments/${id}/app-token?x=1`],['GET',`/v1/deployments/${id.slice(0,10)}`],['GET',`/v1/deployments/${id}/logs?tail=5&x=1`],
    ['GET',`/v1/deployments/${id}/../${id}/logs`],['GET',`/v1/deployments/${id}%2Flogs`],['GET',`/x/${id}/`],['GET',`/v1/deployments/${id}/restart`]])
    assert.equal((await r.raw(method,target)).status,404,method+' '+target);
  const target=managementTarget('status',id);
  assert.equal((await r.raw('GET',target,{header:'Bearer host-wide-siwe-token'})).status,401,'a host-wide bearer is not a management credential');
  assert.equal((await r.raw('GET',target,{base:managementBase(otherRunner)})).status,401,'a signature for another runner does not verify here');
  assert.equal((await r.raw('GET',target,{base:'api.enclave.host'})).status,401,'a signature for the relay base does not verify here');
  const other='0x'+'ac'.repeat(32);
  assert.equal((await r.raw('GET',target,{header:r.signer({method:'GET',hostPath:managementBase(runner)+managementTarget('status',other),body:Buffer.alloc(0)})})).status,401,'cross-deployment signature');
  assert.equal((await r.raw('POST',managementTarget('restart',id),{body:'{"x":1}'})).status,413);
  assert.deepEqual(r.hits,[],'nothing reached the supervisor');
  assert.throws(()=>managementTarget('admin',id));assert.throws(()=>managementTarget('logs',id,{tail:5000}));
});

test('endpoint records and the gateway refuse private targets and non-loopback upstreams',async t=>{
  const base={version:1,runner,operator:operator.address.toLowerCase(),chainId:8453,deployments:pins.deployments,port:443,spkiSha256:'ab'.repeat(32),sequence:1,issuedAt:Date.now(),expiresAt:Date.now()+60000};
  for(const address of ['10.0.0.1','127.0.0.1','169.254.169.254','192.168.1.1','::1','fd00::1','host.example'])
    assert.throws(()=>validateManagementRecord({...base,address}),/public literal/,address);
  assert.throws(()=>validateManagementRecord({...base,address:'8.8.4.4',expiresAt:base.issuedAt+25*3600*1000}),/invalid or expired/);
  assert.throws(()=>validateManagementRecord({...base,address:'8.8.4.4',extra:1}),/invalid/);
  for(const u of ['http://10.0.0.5:8080','https://127.0.0.1:8080','http://localhost:8080','http://127.0.0.1:8080/v1','http://user@127.0.0.1:8080'])
    assert.throws(()=>managementUpstream(u),/loopback/,u);
  assert.deepEqual(managementUpstream('http://127.0.0.1:8080'),{host:'127.0.0.1',port:8080});
  // a lease must name the signer: the right runner signed by another key is not accepted by the client either
  const env=await signManagementRecord(stranger,{...base,address:'8.8.4.4',operator:stranger.address.toLowerCase()});
  await assert.rejects(managementFor([env],{runner,runnerOperator:operator.address},{chainId:8453,deployments:pins.deployments}),/no current management record/);
});

test('the host publishes its record to operator directories only, as public data',async t=>{
  const posts=[];
  const env=await signManagementRecord(operator,managementRecord({operator:operator.address,runner,deployments:pins.deployments,...PUBLIC,cert:cert(fs.mkdtempSync(path.join(os.tmpdir(),'mgmt-pub-'))).cert}));
  const accepted=await publishManagementRecord(env,{directories:['http://192.0.2.10:8188','http://192.0.2.11:8188'],fetch:async(url,init)=>{
    posts.push({url,redirect:init.redirect,credentials:init.credentials,body:JSON.parse(init.body)});
    if(url.startsWith('http://192.0.2.10'))return new Response('',{status:404});return new Response('{"ok":true}');}});
  assert.deepEqual(accepted,['http://192.0.2.11:8188']);
  assert(posts.every(p=>p.url.endsWith('/v1/network/management')&&p.redirect==='error'&&p.credentials==='omit'&&p.body.signature===env.signature));
});

// ---- hardening ----
import net from 'node:net';
import tlsModule from 'node:tls';
import {runDirectory} from '../network/directory-server.mjs';
import {startManagementHost} from '../network/management-host.mjs';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const until=async(f,ms=5000)=>{for(const t0=Date.now();Date.now()-t0<ms;await sleep(20))if(await f())return true;return false;};
const freePort=()=>new Promise(r=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>r(p));});});

test('async SDK signers are awaited, their answer is checked, and expiry during signing sends nothing',async t=>{
  const r=await rig(t);await r.publish();
  const slow=async a=>{await sleep(30);return r.signer(a);};
  assert.equal((await r.client({signer:slow}).status()).status,200);
  const other='0x'+'ac'.repeat(32);
  const bad=[
    [async a=>r.signer({...a,hostPath:managementBase(runner)+managementTarget('status',other)}),/did not sign exactly this request/],
    [async()=>'Bearer host-wide',/no EnclaveSession authorization/],
    [async a=>r.signer(a)+'\r\nX-Injected: 1',/no EnclaveSession authorization/],
    [async()=>'EnclaveSession v1 vault=nope',/malformed authorization/],
    [async()=>{throw Error('wallet locked');},/signer failed/],
    [async a=>sessionRequestSigner({vault,sid,privateKey:r.session.privateKey,now:()=>Date.now()-120000})(a),/clock window/],
  ];
  for(const [signer,why] of bad)await assert.rejects(r.client({signer}).status(),why);
  // the record expires while the wallet deliberates: refused before any connection
  let skew=0;const clock=()=>Date.now()+skew;
  const deliberate=async a=>{skew=7*3600*1000;return sessionRequestSigner({vault,sid,privateKey:r.session.privateKey,now:clock})(a);};
  r.clientLease.validUntil=Date.now()+9*3600*1000;r.clientLease.leaseUntil=Date.now()+9*3600*1000;
  await assert.rejects(r.client({signer:deliberate,now:clock}).restart(),e=>/expired while the request was being signed/.test(e.message)&&e.sent===false);
  assert.equal(r.counts().gatewayRequests,1);assert.equal(r.counts().restarts,0);
});

test('rollback floors are per network: the same runner on another pinned ledger cannot poison them',async t=>{
  const r=await rig(t);const first=await r.publish();
  const stateDir=fs.mkdtempSync(path.join(os.tmpdir(),'management-shared-'));
  const a=r.client({stateDir});assert.equal((await a.status()).status,200);
  await r.publish({address:null,port:null,spkiSha256:null,...later(first.record,1000)});
  await assert.rejects(a.status(),/withdrew/);   // network A's floor is now far above
  // an unrelated network B: same runner id, another ledger, its own older-sequence record
  const pinsB={...pins,deployments:'0x'+'0b'.repeat(20)},leaseB={...r.clientLease,deployments:pinsB.deployments};
  const recordB=await signManagementRecord(operator,{...first.record,deployments:pinsB.deployments,...later(first.record,1)});
  const b=r.client({stateDir,authorityPins:pinsB,reader:r.reader(leaseB),
    fetch:async()=>Response.json({version:1,providers:[],policies:[],publications:[],management:[recordB]})});
  assert.equal((await b.resolve()).record.deployments,pinsB.deployments,'B is judged against its own floor');
  // and B's floor never lowers A's: a fresh A client sharing the state still refuses the stale endpoint
  r.setServe(async()=>Response.json({version:1,providers:[],policies:[],publications:[],management:[first]}));
  await assert.rejects(r.client({stateDir}).status(),/stale management record/);
  assert.notEqual(a.floorKey(runner,operator.address),b.floorKey(runner,operator.address));
});

test('a restart that may have run is never reported as success or as a clean refusal',async t=>{
  const r=await rig(t);await r.publish();const c=r.client();
  for(const mode of ['malformed','500','wrong-shape']){
    r.mode.restart=mode;const before=r.counts().restarts;
    await assert.rejects(c.restart(),e=>e.outcomeUnknown===true&&e.sent===true&&/may have run/.test(e.message),mode);
    assert.equal(r.counts().restarts,before+1,mode+': the side effect happened exactly once');
  }
  r.mode.restart='not_running';   // the supervisor's own refusal before any side effect
  await assert.rejects(c.restart(),e=>e.outcomeUnknown===false&&e.code==='not_running');
  r.mode.restart=undefined;r.hostLease.owner=getAddress('0x'+'66'.repeat(20));   // refused by the gateway, never forwarded
  await assert.rejects(c.restart(),e=>e.outcomeUnknown===false&&e.status===403);
  assert.equal(r.counts().restarts,3);assertIdle(r.stats());
});

test('the gateway bounds trickling answers and slow bodies by total time, and frees every slot',async t=>{
  const r=await rig(t,{gateway:{maxRequestMs:400,bodyReadMs:200}});await r.publish();
  r.mode.logs='trickle';
  const logs=await r.client().logs();const t0=Date.now();
  await assert.rejects(collect(logs.body));assert(Date.now()-t0<3000,'a trickle cannot hold the request past its bound');
  assert(await until(()=>r.stats().inFlight===0),'slot released');
  const rawSend=async text=>{
    const socket=tlsModule.connect({host:'127.0.0.1',port:r.gatewayPort(),rejectUnauthorized:false});
    await new Promise(x=>socket.once('secureConnect',x));socket.write(text);
    const t1=Date.now(),answer=await new Promise(x=>{let b='';socket.on('data',d=>{b+=d;});socket.once('close',()=>x(b));});
    return {answer,ms:Date.now()-t1};
  };
  // a chunked body is refused at once: there is nothing to wait for
  const target=managementTarget('restart',id),header=r.signer({method:'POST',hostPath:managementBase(runner)+target,body:Buffer.alloc(0)});
  const chunked=await rawSend(`POST ${target} HTTP/1.1\r\nhost: x\r\nauthorization: ${header}\r\ntransfer-encoding: chunked\r\n\r\n`);
  assert.match(chunked.answer,/^HTTP\/1\.1 400/);assert(chunked.ms<1000);
  // the one operation with a body: its declared bytes never arrive, and the short body bound refuses it
  const ctl=managementTarget('cpuProfileControl',id),ctlHeader=r.signer({method:'POST',hostPath:managementBase(runner)+ctl,body:Buffer.from('{"action":"stop"}')});
  const stalled=await rawSend(`POST ${ctl} HTTP/1.1\r\nhost: x\r\nauthorization: ${ctlHeader}\r\ncontent-length: 17\r\n\r\n`);
  assert.match(stalled.answer,/^HTTP\/1\.1 408/);assert(stalled.ms<3000,'the gateway body bound, not the server request timeout');
  assert(await until(()=>r.stats().preAuth===0&&r.stats().inFlight===0));assertIdle(r.stats());
  assert.equal(r.counts().restarts,0);assert.deepEqual(r.hits.filter(h=>h.startsWith('POST')),[]);
});

test('an open log stream stops when the owner, runner, session or lease freshness changes',async t=>{
  for(const change of ['owner','runner','session','freshness'])await t.test(change,async t=>{
    const r=await rig(t,{gateway:{recheckMs:change==='freshness'?300000:100}});await r.publish();
    if(change==='freshness')r.hostLease.validUntil=Date.now()+500;
    const logs=await r.client().logs();const it=logs.body[Symbol.asyncIterator]();
    assert.equal((await it.next()).value.toString(),'# status=running\n');
    if(change==='owner')r.hostLease.owner=getAddress('0x'+'66'.repeat(20));
    if(change==='runner')r.hostLease.runner=otherRunner;
    if(change==='session')r.chain.live=false;
    const t0=Date.now();
    await assert.rejects((async()=>{for(let n=await it.next();!n.done;n=await it.next());})());
    assert(Date.now()-t0<3000,'cut by revalidation, not by the 60 s operation bound');
    assert(await until(()=>r.stats().inFlight===0),'slot released');r.release();
  });
});

test('the real runDirectory accepts, serves and replicates management records from peers',async t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'management-run-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const reader={authorityPins:pins,bookAddress:async name=>name==='registry'?pins.registry:null,refresh:async()=>[],
    registryEntries:async(_registry,ids)=>ids.map(x=>({active:true,operator:x===runner?operator.address:'0x'+'00'.repeat(20)}))};
  const [portA,portB]=[await freePort(),await freePort()];
  const base={checkers:['0x'+'03'.repeat(20)],bind:'127.0.0.1',rpc:[],authorityPins:pins};
  const a=await runDirectory({...base,stateDir:dir+'/a',port:portA},{reader});t.after(()=>a.close());
  const env=await signManagementRecord(operator,managementRecord({operator:operator.address,runner,deployments:pins.deployments,...PUBLIC,cert:cert(fs.mkdtempSync(path.join(dir,'c'))).cert}));
  assert.deepEqual(await publishManagementRecord(env,{directories:[`http://127.0.0.1:${portA}`]}),[`http://127.0.0.1:${portA}`]);
  const foreign=await signManagementRecord(stranger,{...env.record,operator:stranger.address.toLowerCase(),...later(env.record,1)});
  await assert.rejects(publishManagementRecord(foreign,{directories:[`http://127.0.0.1:${portA}`]}),/HTTP 400/);
  const snapshot=await (await fetch(`http://127.0.0.1:${portA}/v1/network/records`)).json();
  assert.deepEqual(snapshot.management,[env]);
  const b=await runDirectory({...base,stateDir:dir+'/b',port:portB,peers:[`http://127.0.0.1:${portA}`]},{reader});t.after(()=>b.close());
  assert(await until(async()=>(await (await fetch(`http://127.0.0.1:${portB}/v1/network/records`)).json()).management?.length===1),'peer copy replicated');
});

test('the management host cleans up a failed start and only moves its sequence forward',async t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'management-host-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const keys=cert(dir);fs.writeFileSync(dir+'/k',keys.key);fs.writeFileSync(dir+'/c',keys.cert);
  const posted=[];const fetchImpl=async(url,init)=>{posted.push(JSON.parse(init.body));return new Response('{"ok":true}');};
  const port=await freePort();
  const config={runner,chainId:8453,authorityPins:pins,rpc:[],directories:['http://192.0.2.20:8188'],listen:{host:'127.0.0.1',port},public:PUBLIC,
    tlsKeyFile:dir+'/k',tlsCertFile:dir+'/c',upstream:'http://127.0.0.1:9',stateDir:dir+'/state',ttlMs:60000};
  const deps={reader:{agreed:async()=>{throw Error('unused');},chainId:8453},fetch:fetchImpl,log:()=>{}};
  const broken={address:operator.address,signMessage:async()=>{throw Error('signer unavailable');}};
  await assert.rejects(startManagementHost(config,{...deps,account:broken}),/signer unavailable/);
  const probe=net.createServer();await new Promise((ok,no)=>{probe.once('error',no);probe.listen(port,'127.0.0.1',ok);});probe.close();   // the port was released
  let clock=2_000_000_000_000;
  const host=await startManagementHost(config,{...deps,account:operator,now:()=>clock});t.after(()=>host.close());
  await host.refresh();await host.refresh();   // same instant: still strictly increasing
  clock-=5000;await host.refresh();             // clock stepped back
  const w=await host.withdraw();
  const seqs=posted.map(p=>p.record.sequence);
  assert(seqs.every((x,i)=>i===0||x>seqs[i-1]),JSON.stringify(seqs));assert.equal(w.record.address,null);
  await assert.rejects(host.refresh(),/withdrawn/);host.close();
  // a restart with a slower clock still continues above the persisted sequence
  clock-=60000;const again=await startManagementHost(config,{...deps,account:operator,now:()=>clock});t.after(()=>again.close());
  assert(again.record.record.sequence>w.record.sequence);
});

// ---- quorum authorization, freshness, parity, and the actual supervisor ----
import {spawn} from 'node:child_process';
import {keccak256,stringToBytes,toFunctionSelector} from 'viem';
import {delegateSlot} from '../windows/node/session-api-auth.mjs';
const otherVault=getAddress('0x'+'55'.repeat(20)),otherSid='0x'+'44'.repeat(32);

test('one lying RPC cannot forge an authorization, and without agreement nothing is forwarded',async t=>{
  const r=await rig(t);await r.publish();
  // an attacker's own session, which the liar (RPC 2) reports as owning the deployment with every scope
  const attacker=generateKeyPairSync('ec',{namedCurve:'P-256'}),aj=createPublicKey(attacker.privateKey).export({format:'jwk'});
  const attackerHash=sessionKeyHash(Buffer.from(aj.x,'base64url'),Buffer.from(aj.y,'base64url'));
  r.world.liars.set(2,s=>({...s,row:{...s.row,owner:otherVault.toLowerCase()},vaults:{...s.vaults,[otherVault.toLowerCase()]:{owner:wallet.toLowerCase(),held:{[id]:2},
    sessions:{[otherSid]:{keyHash:attackerHash,actions:(1n<<200n)-1n,envs:3,expiresAt:Math.floor(Date.now()/1000)+3600,live:true}}}}}));
  const attackerSigner=sessionRequestSigner({vault:otherVault,sid:otherSid,privateKey:attacker.privateKey});
  r.world.delays.set(0,25);r.world.delays.set(1,25);   // the liar always answers first: only agreement can refuse it
  const target=managementTarget('logs',id);
  const forged=await r.raw('GET',target,{header:attackerSigner({method:'GET',hostPath:managementBase(runner)+target,body:Buffer.alloc(0)})});
  assert(forged.status===401||forged.status===403,JSON.stringify(forged));
  assert.equal((await r.client().status()).status,200,'the two honest RPCs still authorize the real owner');
  r.world.delays.clear();
  // honest, liar and an unavailable RPC: no two agree
  r.world.down.add(0);
  const split=await r.raw('GET',managementTarget('status',id));
  assert.equal(split.status,503);assert.equal(split.json.error,'chain_unavailable');
  assert.deepEqual(r.hits,[`GET /v1/deployments/${id}`],'only the honestly authorized request reached the supervisor');
  assertIdle(r.stats());
});

test('a slow chain read is bounded, and authority that expires during it forwards nothing',async t=>{
  const r=await rig(t,{gateway:{maxRequestMs:500}});await r.publish();
  r.world.delayMs=400;const t0=Date.now();
  const slow=await r.raw('POST',managementTarget('restart',id));
  assert.equal(slow.status,504);assert.equal(slow.json.error,'authorization_timeout');assert(Date.now()-t0<2000);
  assert(await until(()=>r.stats().authorizing===0));assertIdle(r.stats());
  // (refuse-only refusal memory off here: each case below must reach the chain read it is about)
  const s=await rig(t,{gateway:{limits:{negativeTtlMs:0}}});await s.publish();
  const session=s.world.state.vaults[vault.toLowerCase()].sessions[sid];session.expiresAt=Math.floor(Date.now()/1000)+1;
  s.world.delayMs=300;   // five sequential reads: the session has expired by the time the snapshot is complete
  const expired=await s.raw('POST',managementTarget('restart',id));
  assert.equal(expired.status,401);assert.equal(expired.json.error,'session_ended');
  s.world.delayMs=0;session.expiresAt=Math.floor(Date.now()/1000)+3600;s.world.state.row.leaseUntil=Math.floor(Date.now()/1000)+1;s.world.delayMs=300;   // ends within 1 s; the read takes 1.5 s
  assert.equal((await s.raw('POST',managementTarget('restart',id))).status,409,'a lease that ends during the read');
  // every rule holds, but the agreed block itself ages out while the reads run: refused before any upstream request.
  // LeaseReader.agreed now refuses such a block itself (503); the gateway's own freshUntil check (504) is the second line.
  s.world.delayMs=0;s.hostLease.validUntil=Date.now()+600000;s.world.blockTime=Math.floor(Date.now()/1000)-88;s.world.delayMs=600;   // 88-89 s old at the read's start, 91+ s old once five reads finish
  const stale=await s.raw('POST',managementTarget('restart',id));
  assert(stale.status===503&&stale.json.error==='chain_unavailable'||stale.status===504&&stale.json.error==='authorization_expired',JSON.stringify(stale));
  assert.equal(r.counts().restarts+s.counts().restarts,0);assert.deepEqual([...r.hits,...s.hits],[]);
});

test('scope, revocation, transfer and owner delegation are decided from the agreed snapshot',async t=>{
  const r=await rig(t,{scope:['api.status']});await r.publish();const c=r.client();
  await assert.rejects(c.logs(),e=>e.status===403&&/lacks api.logs/.test(e.message));
  assert.equal((await c.status()).status,200);
  r.chain.live=false;await assert.rejects(c.status(),e=>e.status===401&&e.code==='session_ended');r.chain.live=true;
  // a wallet-held deployment: production session, but only with the owner's ledger delegation
  r.hostLease.owner=wallet;
  await assert.rejects(c.status(),e=>e.status===403&&/delegated/.test(e.message));
  r.world.state.ledgerCode='0x63'+toFunctionSelector('setDelegate(address,bool)').slice(2);
  await assert.rejects(c.status(),e=>e.status===403&&/delegated/.test(e.message),'supported but not granted');
  r.world.state.delegated.add(delegateSlot(wallet,vault));
  assert.equal((await c.status()).status,200,'delegated');
  r.hostLease.owner=otherVault;await assert.rejects(c.status(),e=>e.status===403&&/current owner/.test(e.message));
  assert.equal(r.hits.length,2);
});

test('cpu-profile bodies are exact and typed; replays, wrong methods and admin paths never reach the supervisor',async t=>{
  const r=await rig(t);await r.publish();
  const target=managementTarget('cpuProfileControl',id);
  for(const body of ['{"action":"start","seconds":61}','{"action":"start","seconds":5,"x":1}','{"seconds":5,"action":"start"}','{"action":"start"}','{"action":"stop" }','[]'])
    assert.equal((await r.raw('POST',target,{body})).status,body.length>64?413:400,body);
  assert.equal((await r.raw('GET',managementTarget('cpuProfile',id),{body:'x'})).status,413);
  const body='{"action":"start","seconds":5}',header=r.signer({method:'POST',hostPath:managementBase(runner)+target,body:Buffer.from(body)});
  assert.equal((await r.raw('POST',target,{header,body})).status,200);
  assert.equal((await r.raw('POST',target,{header,body})).status,401,'replay');
  assert.equal((await r.raw('POST',target,{header,body:'{"action":"stop"}'})).status,401,'the signature covers the exact body');
  assert.equal(r.profileEffects.length,1);
  assert.deepEqual(r.hits,[`POST ${target}`],'the gateway itself refused the replay and the rebinding; the supervisor saw one request');
  assert.throws(()=>managementTarget('admin',id));
});

test('app tokens and CPU profiles have exact parity, with honest outcomes for profile controls',async t=>{
  const r=await rig(t);await r.publish();const c=r.client();
  const token=await c.appToken();assert.equal(token.deployment,id);assert.equal(token.tokenType,'Cookie');
  const p=await c.cpuProfile();assert.equal(p.data.toString(),'prof');assert.equal(p.profile.state,'complete');assert.equal(p.profile.data,undefined);
  assert.equal((await c.startCpuProfile({seconds:5})).outcome,'succeeded');
  await assert.rejects(c.startCpuProfile({seconds:0}),/start", seconds:1..60/);
  r.mode.profile='422';await assert.rejects(c.startCpuProfile({seconds:5}),e=>e.outcomeUnknown===false&&e.status===422);
  r.mode.profile='409';await assert.rejects(c.startCpuProfile({seconds:5}),e=>e.outcomeUnknown===true,'the capture may be in an uncertain state');
  r.mode.profile='malformed';await assert.rejects(c.stopCpuProfile(),e=>e.outcomeUnknown===true);
  assert.deepEqual(r.profileEffects,[{action:'start',seconds:5},{action:'start',seconds:5},{action:'stop'}]);
});

// The actual supervisor.js, unmodified, as a child process (test/helpers/management-supervisor.mjs): its real ownerAuth,
// sessionApi bases, mayAct and route handlers. Its chain, app manager and network are local test fixtures.
import {startActualSupervisor} from './helpers/management-supervisor.mjs';
import {MANAGEMENT_GATEWAY_HEADER} from '../network/management-gateway.mjs';
const SUPERVISOR_URL='https://host.independent.example',supervisorRunner=keccak256(stringToBytes(SUPERVISOR_URL));
const TOKEN='5a'.repeat(32);
const supervisorPins={registry:pins.registry,deployments:pins.deployments,appCatalog:'0x'+'08'.repeat(20),proofOfTime:'0x'+'09'.repeat(20),
  enclavePay:ZERO20,verificationFees:ZERO20,sessionVaultFactory:pins.sessionVaultFactory,secretVaultV2:ZERO20};
const supervisorChain=(keyHash,actions)=>({factory:pins.sessionVaultFactory,vaults:{[vault.toLowerCase()]:{owner:wallet,held:{[id]:2},
  sessions:{[sid]:{keyHash,actions:String(actions),envs:2,expiresAt:Math.floor(Date.now()/1000)+3600,live:true}}}}});
const ALL_SCOPES=(1n<<128n)|(1n<<129n)|(1n<<130n)|(1n<<132n);
// A request straight to the supervisor (not through the gateway), from `localAddress`, optionally with the gateway token.
const direct=(port,signer,{base,token,localAddress='127.0.0.1',host='127.0.0.1'})=>new Promise((resolve,reject)=>{const target=managementTarget('status',id);
  const req=http.request({host,port,path:target,localAddress,agent:false,headers:{authorization:signer({method:'GET',hostPath:base+target,body:Buffer.alloc(0)}),
    ...(token?{[MANAGEMENT_GATEWAY_HEADER]:token}:{})}},res=>{res.resume();resolve(res.statusCode);});req.on('error',reject);req.end();});

test('the actual supervisor serves every management operation behind the gateway, exactly once',async t=>{
  const probe=await rig(t,{runner:supervisorRunner});
  const keyHash=probe.world.state.vaults[vault.toLowerCase()].sessions[sid].keyHash;
  const sup=await startActualSupervisor(t,{chain:supervisorChain(keyHash,ALL_SCOPES),deployment:{id,owner:vault},pins:supervisorPins,publicUrl:SUPERVISOR_URL,
    env:{MANAGEMENT_GATEWAY:'1',MANAGEMENT_GATEWAY_TOKEN:TOKEN}});
  const r=await rig(t,{runner:supervisorRunner,upstream:`http://127.0.0.1:${sup.port}`,session:probe.session,gateway:{upstreamToken:TOKEN}});
  await r.publish();const c=r.client();
  const status=await c.status();assert.equal(status.json.id,id);assert.equal(status.json.status,'running');
  const logs=(await collect((await c.logs({tail:20})).body)).toString();assert.match(logs,/booted\nserving/);
  const token=await c.appToken();assert.equal(token.deployment,id);assert.match(token.token,/^[A-Za-z0-9._-]+$/);
  assert.equal((await c.cpuProfile()).data.toString(),'prof');
  assert.equal((await c.startCpuProfile({seconds:5})).json.state,'active');
  assert.equal((await c.restart()).json.status,'running');
  assert.deepEqual(sup.effects,[{cpuProfile:{action:'start',seconds:5}},{deleted:'vm-management-1'},{launched:id}],sup.stdout().slice(-1500));
  // The management base is the gateway's alone: straight to the supervisor it verifies only from loopback WITH the token.
  assert.equal(await direct(sup.port,r.signer,{base:managementBase(supervisorRunner),token:TOKEN}),200);
  assert.equal(await direct(sup.port,r.signer,{base:managementBase(supervisorRunner)}),401,'no token: another ingress cannot use the management base');
  assert.equal(await direct(sup.port,r.signer,{base:managementBase(supervisorRunner),token:'6b'.repeat(32)}),401,'a wrong token');
  assert.equal(await direct(sup.port,r.signer,{base:managementBase(otherRunner),token:TOKEN}),401,'another runner\'s base');
  const lan=Object.values(os.networkInterfaces()).flat().find(i=>i&&i.family==='IPv4'&&!i.internal);
  if(lan)assert.equal(await direct(sup.port,r.signer,{base:managementBase(supervisorRunner),token:TOKEN,localAddress:lan.address,host:lan.address}),401,'the token from a non-loopback peer');
  assert(!/enclave\.host/.test(sup.stdout().match(/fetch failed: test process is loopback-only \(([^)]*)\)/g)?.join(' ')||''),'no Enclave domain was even attempted');
});

test('without MANAGEMENT_GATEWAY the actual supervisor keeps its legacy bases only',async t=>{
  const probe=await rig(t,{runner:supervisorRunner});
  const keyHash=probe.world.state.vaults[vault.toLowerCase()].sessions[sid].keyHash;
  const sup=await startActualSupervisor(t,{chain:supervisorChain(keyHash,1n<<128n),deployment:{id,owner:vault},pins:supervisorPins,publicUrl:SUPERVISOR_URL,
    env:{MANAGEMENT_GATEWAY_TOKEN:TOKEN}});
  assert.equal(await direct(sup.port,probe.signer,{base:managementBase(supervisorRunner),token:TOKEN}),401);
  assert.equal(await direct(sup.port,probe.signer,{base:'host.independent.example'}),200,'the PUBLIC_URL base works as before');
});

// ---- browser transport (record v2): WebPKI origin, explicit dashboards, the same owner authorization ----
import {browserManagementEndpoint,browserManagementRequest,managementFloorKey} from '../network/management-browser.mjs';
import {webcrypto} from 'node:crypto';
const MGMT_HOST='mgmt.host-operator.net',MGMT_ORIGIN='https://'+MGMT_HOST,DASHBOARD='https://dashboard.owner-tools.net';
// A test CA and a leaf for the browser origin's name: Node's TLS checks the chain and the name, as a browser's WebPKI would.
function webpki(dir){
  const run=args=>execFileSync('openssl',args,{cwd:dir,stdio:'ignore'});
  run(['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=management-test-ca','-days','1','-keyout','ca.key','-out','ca.crt',
    '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign']);
  run(['req','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN='+MGMT_HOST,'-keyout','leaf.key','-out','leaf.csr']);
  fs.writeFileSync(path.join(dir,'ext'),`subjectAltName=DNS:${MGMT_HOST}\nextendedKeyUsage=serverAuth\n`);
  run(['x509','-req','-in','leaf.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-days','1','-out','leaf.crt','-extfile','ext']);
  return {ca:fs.readFileSync(path.join(dir,'ca.crt')),tls:{key:fs.readFileSync(path.join(dir,'leaf.key')),cert:fs.readFileSync(path.join(dir,'leaf.crt'))}};
}
// What a page's fetch does for this request: TLS validated against the trusted CAs for the URL's name, a CORS preflight
// (Authorization is not a simple header), the Origin header, Access-Control-Allow-Origin checks, only exposed headers
// readable, redirect:'error' and no credentials. Names resolve only through `hosts`; everything else fails like a
// network error and is recorded.
function pageFetch({ca,hosts,pageOrigin,log}){
  const send=(method,url,headers,body)=>new Promise((resolve,reject)=>{
    const u=new URL(url);log.push(method+' '+url);const port=hosts[u.hostname];
    if(!port)return reject(TypeError('Failed to fetch'));
    const req=https.request({host:'127.0.0.1',port,servername:u.hostname,ca,path:u.pathname+u.search,method,agent:false,headers:{...headers,origin:pageOrigin}},async res=>{
      resolve({status:res.statusCode,headers:res.headers,body:await collect(res)});});
    req.on('error',()=>reject(TypeError('Failed to fetch')));req.end(body?Buffer.from(body):undefined);
  });
  return async(url,init)=>{
    assert.equal(init.credentials,'omit');assert.equal(init.redirect,'error');assert.equal(init.mode,'cors');
    const pre=await send('OPTIONS',url,{'access-control-request-method':init.method,'access-control-request-headers':Object.keys(init.headers).join(',').toLowerCase()});
    if(pre.status!==204||pre.headers['access-control-allow-origin']!==pageOrigin||!String(pre.headers['access-control-allow-methods']).includes(init.method))
      throw TypeError('CORS preflight refused');
    const res=await send(init.method,url,init.headers,init.body);
    if(res.headers['access-control-allow-origin']!==pageOrigin)throw TypeError('CORS refused');
    if(res.status>=300&&res.status<400)throw TypeError('redirect refused');
    const exposed=new Set(String(res.headers['access-control-expose-headers']||'').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean));
    const headers=new Headers();for(const [k,v] of Object.entries(res.headers))if(k==='content-type'||exposed.has(k))headers.set(k,v);
    return new Response(res.body,{status:res.status,headers});
  };
}
// A WebCrypto session signer, as a browser holds it.
async function webSigner(privateKey){
  const pkcs8=privateKey.export({format:'der',type:'pkcs8'});
  const key=await webcrypto.subtle.importKey('pkcs8',pkcs8,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  const {x,y}=createPublicKey(privateKey).export({format:'jwk'});
  return async({method,hostPath,body})=>{
    const ts=Math.floor(Date.now()/1000),n=Buffer.from(webcrypto.getRandomValues(new Uint8Array(12))).toString('base64url');
    const bodyHash=Buffer.from(await webcrypto.subtle.digest('SHA-256',body)).toString('hex');
    const msg=`enclave-api-v1\n${method}\n${hostPath}\n${bodyHash}\n${ts}\n${n}\n${vault.toLowerCase()}\n${sid}`;
    const sig=Buffer.from(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,new TextEncoder().encode(msg))).toString('base64url');
    return `EnclaveSession v1 vault=${vault},sid=${sid},ts=${ts},n=${n},x=${x},y=${y},sig=${sig}`;
  };
}
async function browserRig(t,over={}){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'management-webpki-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const pki=webpki(dir);
  const r=await rig(t,{browser:{origin:MGMT_ORIGIN,dashboards:[DASHBOARD],tls:pki.tls},...over});
  const log=[];
  const lease={...r.clientLease,runner:over.runner||runner};
  return {...r,pki,log,lease,fetchFor:(pageOrigin=DASHBOARD,hosts={[MGMT_HOST]:r.gatewayPort()})=>pageFetch({ca:pki.ca,hosts,pageOrigin,log}),
    signerWeb:await webSigner(r.session.privateKey),
    snapshot:async()=>(await (await fetch(r.dirOrigin+'/v1/network/records')).json()).management};
}

test('a dashboard reaches the operator-signed WebPKI origin with per-request owner signatures and no Enclave domain',async t=>{
  const r=await browserRig(t);const env=await r.publish();
  assert.equal(env.record.version,2);
  const endpoint=await browserManagementEndpoint(await r.snapshot(),r.lease,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD});
  assert.equal(endpoint.origin,MGMT_ORIGIN);
  const call=(op,extra={})=>browserManagementRequest({op,deploymentId:id,endpoint,lease:r.lease,signer:r.signerWeb,fetch:r.fetchFor(),...extra});
  const status=await call('status');assert.equal(status.transport,'browser-webpki');assert.equal(status.json.status,'running');assert.equal(status.forwarded,true);
  const logs=call('logs',{tail:5});await sleepMs(50);r.release();assert.match((await logs).text,/status=running/);
  assert.equal((await call('appToken')).json.deployment,id);
  assert.equal((await call('cpuProfile')).json.format,'gperftools');
  assert.equal((await call('cpuProfileControl',{action:'start',seconds:5})).outcome,'succeeded');
  assert.equal((await call('restart')).outcome,'succeeded');
  assert(r.log.every(l=>new URL(l.split(' ')[1]).origin===MGMT_ORIGIN),JSON.stringify(r.log));
  assert(!r.log.some(l=>/enclave\.host/.test(l)));
  assert.equal(r.counts().restarts,1);assert.equal(r.profileEffects.length,1);
  // the same gateway still serves the native exact-SPKI path
  assert.equal((await r.client().status()).transport,'native-spki');
  assert.match(managementFloorKey({chainId:8453,deployments:pins.deployments,registry:pins.registry,runner}),/^[0-9a-f]{64}$/);
  assert.deepEqual(endpoint.floor.operators[operator.address.toLowerCase()],{sequence:env.record.sequence,hash:endpoint.hash},'the floor is kept per operator');
});

test('unlisted page origins, swapped or stale records, a changed owner and no quorum all fail without reaching the supervisor',async t=>{
  const r=await browserRig(t);const v2=await r.publish();
  // an unlisted dashboard: the helper refuses, and the gateway refuses the page itself before authorization
  await assert.rejects(browserManagementEndpoint(await r.snapshot(),r.lease,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:'https://evil.example'}),/not one the runner operator allowed/);
  const endpoint=await browserManagementEndpoint(await r.snapshot(),r.lease,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD});
  await assert.rejects(browserManagementRequest({op:'restart',deploymentId:id,endpoint,lease:r.lease,signer:r.signerWeb,fetch:r.fetchFor('https://evil.example')}),
    e=>e.outcomeUnknown===true,'a page that cannot read the answer learns nothing; as a mutation it is reported outcome-unknown');
  const evil=await r.raw('POST',managementTarget('restart',id));   // a signed request carrying a foreign Origin
  assert.equal(evil.status,200,'no Origin header: the native path is unaffected');
  const foreign=await new Promise((resolve,reject)=>{const target=managementTarget('status',id);
    const req=https.request({host:'127.0.0.1',port:r.gatewayPort(),path:target,rejectUnauthorized:false,agent:false,headers:{origin:'https://evil.example',
      authorization:r.signer({method:'GET',hostPath:managementBase(runner)+target,body:Buffer.alloc(0)})}},res=>{res.resume();resolve({status:res.statusCode,acao:res.headers['access-control-allow-origin']});});
    req.on('error',reject);req.end();});
  assert.deepEqual(foreign,{status:403,acao:undefined});
  // a directory swaps in another origin: unsigned by the runner operator it is ignored; replaying the older record after a newer one is stale
  const swapped=await signManagementRecord(stranger,{...v2.record,operator:stranger.address.toLowerCase(),...later(v2.record,1),browser:{origin:'https://attacker.net',dashboards:[DASHBOARD]}});
  assert.equal((await browserManagementEndpoint([v2,swapped],r.lease,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD})).origin,MGMT_ORIGIN);
  const moved=await signManagementRecord(operator,{...v2.record,...later(v2.record,2),browser:{origin:'https://mgmt2.host-operator.net',dashboards:[DASHBOARD]}});
  const after=await browserManagementEndpoint([moved],r.lease,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD});
  await assert.rejects(browserManagementEndpoint([v2],r.lease,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD,floor:after.floor}),/stale/);
  // a native-only (v1) record newer than the browser one: no browser transport, never a guessed origin
  const nativeOnly=await signManagementRecord(operator,managementRecord({operator:operator.address,runner,deployments:pins.deployments,...PUBLIC,cert:r.tls.cert,now:v2.record.sequence+3}));
  await assert.rejects(browserManagementEndpoint([v2,nativeOnly],r.lease,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD}),/no browser transport/);
  // the ledger owner changed: the gateway's agreed snapshot refuses before forwarding
  const hitsBefore=r.hits.length;
  r.hostLease.owner=otherVault;
  await assert.rejects(browserManagementRequest({op:'status',deploymentId:id,endpoint,lease:r.lease,signer:r.signerWeb,fetch:r.fetchFor()}),e=>e.status===403&&e.outcomeUnknown===false);
  r.hostLease.owner=vault;
  // no agreeing quorum
  r.world.down.add(0);r.world.liars.set(1,s=>({...s,row:{...s.row,owner:otherVault.toLowerCase()}}));
  await assert.rejects(browserManagementRequest({op:'restart',deploymentId:id,endpoint,lease:r.lease,signer:r.signerWeb,fetch:r.fetchFor()}),e=>e.status===503&&e.outcomeUnknown===false);
  assert.equal(r.hits.length,hitsBefore,'nothing after the owner change reached the supervisor');
});

test('a certificate the page cannot trust fails closed, and the native SPKI path still works without DNS or a CA',async t=>{
  const r=await browserRig(t);await r.publish();
  const endpoint=await browserManagementEndpoint(await r.snapshot(),r.lease,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD});
  const untrusted=pageFetch({ca:r.tls.cert,hosts:{[MGMT_HOST]:r.gatewayPort()},pageOrigin:DASHBOARD,log:r.log});   // the page does not trust this CA
  await assert.rejects(browserManagementRequest({op:'status',deploymentId:id,endpoint,lease:r.lease,signer:r.signerWeb,fetch:untrusted}),e=>e.sent===null);
  const noDns=pageFetch({ca:r.pki.ca,hosts:{},pageOrigin:DASHBOARD,log:r.log});   // the name does not resolve
  await assert.rejects(browserManagementRequest({op:'restart',deploymentId:id,endpoint,lease:r.lease,signer:r.signerWeb,fetch:noDns}),e=>e.outcomeUnknown===true);
  assert.equal(r.counts().restarts,0);
  assert.equal((await r.client().status()).status,200,'native: literal IP and exact SPKI, no DNS or CA involved');
  // a signer answer for another request is refused before any fetch
  const before=r.log.length;
  await assert.rejects(browserManagementRequest({op:'status',deploymentId:id,endpoint,lease:r.lease,fetch:r.fetchFor(),
    signer:a=>r.signerWeb({...a,hostPath:managementBase(otherRunner)+managementTarget('status',id)})}),/did not sign exactly this request/);
  assert.equal(r.log.length,before);
});

test('browser origins in records are strict',()=>{
  const base={version:2,runner,operator:operator.address.toLowerCase(),chainId:8453,deployments:pins.deployments,address:'8.8.4.4',port:443,spkiSha256:'ab'.repeat(32),
    sequence:1,issuedAt:Date.now(),expiresAt:Date.now()+60000};
  assert.equal(validateManagementRecord({...base,browser:null}).browser,null);
  assert.equal(validateManagementRecord({...base,browser:{origin:MGMT_ORIGIN,dashboards:[DASHBOARD]}}).browser.origin,MGMT_ORIGIN);
  for(const browser of [{origin:'https://8.8.4.4',dashboards:[DASHBOARD]},{origin:'http://'+MGMT_HOST,dashboards:[DASHBOARD]},{origin:MGMT_ORIGIN+'/',dashboards:[DASHBOARD]},
    {origin:MGMT_ORIGIN+'/path',dashboards:[DASHBOARD]},{origin:'https://user@'+MGMT_HOST,dashboards:[DASHBOARD]},{origin:'https://mgmt.localhost',dashboards:[DASHBOARD]},
    {origin:'https://x.invalid',dashboards:[DASHBOARD]},{origin:'https://host',dashboards:[DASHBOARD]},{origin:MGMT_ORIGIN,dashboards:[]},
    {origin:MGMT_ORIGIN,dashboards:['https://*.owner-tools.net']},{origin:MGMT_ORIGIN,dashboards:['http://dashboard.owner-tools.net']},
    {origin:MGMT_ORIGIN,dashboards:[DASHBOARD,DASHBOARD]},{origin:MGMT_ORIGIN,dashboards:Array.from({length:9},(_,i)=>`https://d${i}.owner-tools.net`)},
    {origin:MGMT_ORIGIN,dashboards:[DASHBOARD],extra:1}])
    assert.throws(()=>validateManagementRecord({...base,browser}),undefined,JSON.stringify(browser));
  assert.throws(()=>validateManagementRecord({...base,address:null,port:null,spkiSha256:null,browser:{origin:MGMT_ORIGIN,dashboards:[DASHBOARD]}}),/withdrawal/);
});

// ---- independent review fixes: admission (F1), operator floors (F2), browser origin (F4), replay capacity (F5) ----
import {strictReplayGuard,sourceOf} from '../network/management-gateway.mjs';
import {operatorFloor,withOperatorFloor,MANAGEMENT_FLOOR_OPERATORS} from '../network/management-record.mjs';
// A raw connection from `localAddress` (any 127.0.0.x is a distinct source on Linux loopback), written by hand.
const rawFrom=(port,localAddress,text,{wait=true}={})=>new Promise((resolve,reject)=>{
  const socket=tlsModule.connect({host:'127.0.0.1',port,localAddress,rejectUnauthorized:false},()=>{socket.write(text);if(!wait)resolve(socket);});
  let b='';socket.on('data',d=>{b+=d;});socket.once('close',()=>wait&&resolve(b));socket.once('error',e=>wait?resolve(b||String(e)):null);
});
const stallText=(target,header)=>`POST ${target} HTTP/1.1\r\nhost: x\r\nauthorization: ${header}\r\ncontent-length: 17\r\n\r\n`;
const junkHeader='EnclaveSession v1 vault=0x'+'77'.repeat(20)+',sid=0x'+'88'.repeat(32)+',ts=1,n=abcdefgh,x='+'A'.repeat(43)+',y='+'A'.repeat(43)+',sig='+'A'.repeat(86);
const forgedSigner=()=>{const k=generateKeyPairSync('ec',{namedCurve:'P-256'});
  return sessionRequestSigner({vault:'0x'+webcrypto.getRandomValues(new Uint8Array(20)).reduce((h,b)=>h+b.toString(16).padStart(2,'0'),''),sid:'0x'+'12'.repeat(32),privateKey:k.privateKey});};

test('F1: stalled unauthenticated bodies cannot lock owners out, and one source cannot take the pool',async t=>{
  const r=await rig(t,{gateway:{bodyReadMs:3000}});await r.publish();
  const ctl=managementTarget('cpuProfileControl',id),sockets=[];
  t.after(()=>{for(const s of sockets)s.destroy();});
  // the reviewer's attack, bigger: 16 stalled bodies from ONE source and one each from 16 more sources, no signature at all
  const burst=[];for(let i=0;i<16;i++)burst.push(rawFrom(r.gatewayPort(),'127.0.0.2',stallText(ctl,junkHeader),{wait:false}));
  for(let i=0;i<16;i++)burst.push(rawFrom(r.gatewayPort(),`127.0.1.${i+1}`,stallText(ctl,junkHeader),{wait:false}));
  sockets.push(...await Promise.all(burst));
  assert(await until(()=>r.stats().preAuth===20),JSON.stringify(r.stats()));   // 4 from the noisy source, 16 from the others
  // the owner's own request (another source) is served while they stall
  const t0=Date.now();assert.equal((await r.client().status()).status,200);assert(Date.now()-t0<2000);
  // a 5th concurrent unauthenticated request from the noisy source is refused at once; another source is unaffected
  assert.match(await rawFrom(r.gatewayPort(),'127.0.0.2',stallText(ctl,junkHeader)),/^HTTP\/1\.1 429/);
  assert.equal(r.stats().preAuth,20);
  for(const s of sockets)s.destroy();
  assert(await until(()=>r.stats().preAuth===0),'every pre-authorization slot comes back');assertIdle(r.stats());
});

test('F1: throwaway keys get a bounded number of chain authorizations, and a known owner keeps a reserve',async t=>{
  const r=await rig(t,{gateway:{limits:{authorizing:2,knownReserve:2,authorizingPerSource:2,authBurst:5,authPerMinute:1}}});await r.publish();
  const c=r.client();assert.equal((await c.status()).status,200);   // this session key is now known here
  const target=managementTarget('status',id);
  const flood=async(localAddress,signer)=>new Promise((resolve,reject)=>{const req=https.request({host:'127.0.0.1',port:r.gatewayPort(),path:target,localAddress,
    rejectUnauthorized:false,agent:false,headers:{authorization:signer({method:'GET',hostPath:managementBase(runner)+target,body:Buffer.alloc(0)})}},
    res=>{res.resume();resolve(res.statusCode);});req.on('error',reject);req.end();});
  // one source, fresh random vaults: at most the burst reaches the chain
  const before=r.world.reads;
  const statuses=await Promise.all(Array.from({length:20},()=>flood('127.0.0.2',forgedSigner())));
  const authorized=statuses.filter(x=>x===401).length;
  assert(authorized<=5,JSON.stringify(statuses));assert(statuses.every(x=>x===401||x===429),JSON.stringify(statuses));
  const perSnapshot=4;   // reads one refused snapshot costs per RPC answer here (schema, row, registry, isVault) x 3 RPCs at most
  assert(r.world.reads-before<=authorized*perSnapshot*3,`${r.world.reads-before} reads for ${authorized} authorizations`);
  // a repeat from a signer the chain already showed is not a vault costs no chain read at all
  const repeat=forgedSigner();await flood('127.0.0.3',repeat);const mid=r.world.reads;
  assert.equal(await flood('127.0.0.3',repeat),401);assert.equal(r.world.reads,mid,'refused from the refuse-only cache');
  // the general pool held by slow strangers from two sources; the known owner is admitted through the reserve
  r.world.delayMs=400;
  const strangers=[flood('127.0.0.4',forgedSigner()),flood('127.0.0.5',forgedSigner())];
  await sleepMs(50);assert.equal(r.stats().authorizing,2);
  const owner=c.status();
  assert.equal((await owner).status,200,'the owner is served while strangers hold the general pool');
  await Promise.all(strangers);r.world.delayMs=0;assertIdle(r.stats());
});

test('F1: a deployment this runner does not hold is refused from memory after one agreed read',async t=>{
  const r=await rig(t);await r.publish();
  r.hostLease.runner=otherRunner;
  const target=managementTarget('status',id);
  assert.equal((await r.raw('GET',target)).status,409);const after=r.world.reads;
  assert.equal((await r.raw('GET',target)).status,409);assert.equal(r.world.reads,after,'no second chain read within the memory window');
});

test('F2: a sequence cannot run ahead of its issue time, and floors are kept per operator',async t=>{
  const base={version:1,runner,operator:operator.address.toLowerCase(),chainId:8453,deployments:pins.deployments,address:'8.8.4.4',port:443,spkiSha256:'ab'.repeat(32),
    issuedAt:Date.now(),expiresAt:Date.now()+60000};
  assert.throws(()=>validateManagementRecord({...base,sequence:base.issuedAt+1}),/invalid/);
  assert.throws(()=>validateManagementRecord({...base,sequence:2**53-1}),/invalid/);
  assert.equal(validateManagementRecord({...base,sequence:base.issuedAt}).sequence,base.issuedAt);
  // the composite floor: raised, never lowered, one entry per operator, bounded without forgetting
  let f=withOperatorFloor(null,operator.address,{sequence:10,hash:'aa'.repeat(32)});
  f=withOperatorFloor(f,operator.address,{sequence:5,hash:'bb'.repeat(32)});
  assert.deepEqual(operatorFloor(f,operator.address),{sequence:10,hash:'aa'.repeat(32)});
  assert.equal(operatorFloor(f,stranger.address),null);
  for(let i=1;i<MANAGEMENT_FLOOR_OPERATORS;i++)f=withOperatorFloor(f,'0x'+i.toString(16).padStart(40,'0'),{sequence:1,hash:'cc'.repeat(32)});
  assert.throws(()=>withOperatorFloor(f,'0x'+'ff'.repeat(20),{sequence:1,hash:'cc'.repeat(32)}),/refusing rather than forgetting/);
});

test('F2: a former operator\'s highest record cannot block the next operator, natively or in the browser',async t=>{
  const r=await browserRig(t);
  // operator A publishes the highest sequence it can (issue time ~59 s ahead); every client that sees it records it
  const poison=await signManagementRecord(operator,{...managementRecord({operator:operator.address,runner,deployments:pins.deployments,...PUBLIC,cert:r.tls.cert,
    now:Date.now()+59000,browser:{origin:MGMT_ORIGIN,dashboards:[DASHBOARD]}})});
  const snap=list=>async()=>Response.json({version:1,providers:[],policies:[],publications:[],management:list});
  r.setServe(snap([poison]));
  const stateDir=fs.mkdtempSync(path.join(os.tmpdir(),'management-rotation-'));t.after(()=>fs.rmSync(stateDir,{recursive:true,force:true}));
  assert.equal((await r.client({stateDir}).resolve()).record.sequence,poison.record.sequence);
  const ep=await browserManagementEndpoint([poison],r.lease,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD});
  // the runner's operator rotates to B, whose honest record is issued now (far below A's floor)
  const fresh=await signManagementRecord(stranger,managementRecord({operator:stranger.address,runner,deployments:pins.deployments,...PUBLIC,cert:r.tls.cert,
    browser:{origin:MGMT_ORIGIN,dashboards:[DASHBOARD]}}));
  r.clientLease.runnerOperator=stranger.address;const leaseB={...r.lease,runnerOperator:stranger.address};
  r.setServe(snap([poison,fresh]));
  assert.equal((await r.client({stateDir}).resolve()).record.operator,stranger.address.toLowerCase(),'native: B is judged against its own floor');
  const epB=await browserManagementEndpoint([poison,fresh],leaseB,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD,floor:ep.floor});
  assert.equal(epB.record.operator,stranger.address.toLowerCase(),'browser: the same');
  // within B, rollback is still refused; and A, should it return, keeps its own historical floor
  const older=await signManagementRecord(stranger,{...fresh.record,sequence:fresh.record.sequence-5,issuedAt:fresh.record.issuedAt-5});
  await assert.rejects(browserManagementEndpoint([older],leaseB,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD,floor:epB.floor}),/stale/);
  const aOlder=await signManagementRecord(operator,{...poison.record,sequence:poison.record.sequence-1000,issuedAt:poison.record.issuedAt-1000});
  await assert.rejects(browserManagementEndpoint([aOlder],r.lease,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD,floor:epB.floor}),/stale/,'A\'s floor survived B');
  r.clientLease.runnerOperator=operator.address;r.setServe(snap([aOlder]));
  await assert.rejects(r.client({stateDir}).resolve(),/stale/,'natively too');
});

test('F4: a substituted browser origin or record never receives an owner signature',async t=>{
  const r=await browserRig(t);await r.publish();
  const endpoint=await browserManagementEndpoint(await r.snapshot(),r.lease,{deployments:pins.deployments,registry:pins.registry,dashboardOrigin:DASHBOARD});
  let signed=0,fetched=0;
  const signer=async a=>{signed++;return r.signerWeb(a);},fetchSpy=async(...a)=>{fetched++;return r.fetchFor()(...a);};
  for(const bad of [{...endpoint,origin:'https://evil.example'},{...endpoint,record:{...endpoint.record,browser:{origin:'https://evil.example',dashboards:[DASHBOARD]}},origin:'https://evil.example'},
    {...endpoint,envelope:{...endpoint.envelope,record:{...endpoint.envelope.record,browser:{origin:'https://evil.example',dashboards:[DASHBOARD]}}},origin:'https://evil.example'},
    {...endpoint,envelope:undefined}])
    await assert.rejects(browserManagementRequest({op:'appToken',deploymentId:id,endpoint:bad,lease:r.lease,signer,fetch:fetchSpy}));
  assert.equal(signed,0);assert.equal(fetched,0);
  const withdrawn=await signManagementRecord(operator,{...managementRecord({operator:operator.address,runner,deployments:pins.deployments,...PUBLIC,cert:r.tls.cert,
    browser:{origin:MGMT_ORIGIN,dashboards:[DASHBOARD]},withdrawn:true})});
  await assert.rejects(browserManagementRequest({op:'status',deploymentId:id,endpoint:{...endpoint,envelope:withdrawn,record:withdrawn.record},lease:r.lease,signer,fetch:fetchSpy}),/no current browser transport/);
  assert.equal(signed,0);assert.equal((await browserManagementRequest({op:'status',deploymentId:id,endpoint,lease:r.lease,signer,fetch:fetchSpy})).status,200);
});

test('F5: a full replay guard refuses new nonces and never forgets a live one',async t=>{
  let now=1000;const g=strictReplayGuard({max:3,ttlMs:100,now:()=>now});
  assert.deepEqual(['a','b','c','d'].map(k=>g.claim(k)),['ok','ok','ok','full']);
  assert.equal(g.claim('a'),'replayed','a live nonce is still remembered when full');
  now+=101;assert.equal(g.claim('d'),'ok','expired entries make room');assert.equal(g.claim('a'),'ok');
  const r=await rig(t,{gateway:{limits:{nonces:2}}});await r.publish();
  const target=managementTarget('status',id),h=()=>r.signer({method:'GET',hostPath:managementBase(runner)+target,body:Buffer.alloc(0)});
  const first=h();assert.equal((await r.raw('GET',target,{header:first})).status,200);assert.equal((await r.raw('GET',target)).status,200);
  const full=await r.raw('GET',target);assert.equal(full.status,503);assert.equal(full.json.error,'replay_capacity');
  assert.equal((await r.raw('GET',target,{header:first})).status,401,'the first nonce is still spent');
  assert.equal(sourceOf('::ffff:10.1.2.3'),'10.1.2.3');assert.equal(sourceOf('2001:db8:1:2:3:4:5:6'),'2001:db8:1:2::/64');assert.equal(sourceOf('2001:db8::1'),'2001:db8:0:0::/64');
});
