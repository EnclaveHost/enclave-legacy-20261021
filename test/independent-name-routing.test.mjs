// Owner-committed custom names routed by INDEPENDENT direct hosts (network/owner-names.mjs, direct-runtime.mjs,
// enclave-network-host.mjs direct.ownerNames), end to end over real TLS/SNI:
//   - the exact committed startup package (from untrusted gateways, one of them lying) names the hosts;
//   - a name routes only while the deployment's own guest presents a public-root certificate for it on the attested key;
//   - Enclave services refuse every request (none is made), and platform labels keep working;
//   - an attacker deployment listing the victim's name can neither take nor veto it; ties fail closed for that name only;
//   - owner/commitment/runner changes retire routes at once; a client fails over to the host that holds the lease, found
//     through a signed, checker-qualified route record (rollback-protected).
// Fixtures stand in for hardware: the guests are Node TLS servers holding one key each, the CA is a local test root, and
// the "attested key" is what a host's admission proof would bind. No real CA, chain, SNP report or public DNS is used.
import test from 'node:test';import assert from 'node:assert/strict';
import net from 'node:net';import https from 'node:https';import http from 'node:http';import tls from 'node:tls';
import fs from 'node:fs/promises';import os from 'node:os';import path from 'node:path';
import {execFileSync} from 'node:child_process';import {createHash,createPublicKey} from 'node:crypto';
import {privateKeyToAccount} from 'viem/accounts';
import {createNetworkHost} from '../network/enclave-network-host.mjs';
import {OwnerNameTable,ownerPackageNames,leaseNameScope,NAME_PROOF_TTL_MS} from '../network/owner-names.mjs';
import {createAppIngress} from '../network/app-ingress.mjs';
import {preparePackage,packageCID} from '../sdk/bootstrap/package.mjs';
import {qualifyProvider,PROVIDER_CHECKS} from '../network/provider-qualification.mjs';
import {RoutePublisher} from '../network/route-publisher.mjs';
import {verifyRoute} from '../network/route-record.mjs';
import {DurableState} from '../network/durable-state.mjs';
import {validateNetworkPolicy} from '../network/network-policy.mjs';

const A='0x'+'a1'.repeat(32),B='0x'+'b2'.repeat(32),R1='0x'+'01'.repeat(32),R2='0x'+'02'.repeat(32),ledger='0x'+'11'.repeat(20);
const acct=n=>privateKeyToAccount('0x'+n.repeat(32));
const op1=acct('0a'),op2=acct('0b'),checker=acct('0c'),ownerA=acct('0d'),ownerB=acct('0e'),newOwner=acct('0f');
const label=id=>id.slice(2,10)+'.apps.independent.example';
const free=()=>new Promise(r=>{const s=net.createServer().listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>r(p));});});

// ---- PKI fixtures (openssl) ----
async function pki(dir){
  const run=args=>execFileSync('openssl',args,{stdio:'ignore'});
  const key=name=>{const f=path.join(dir,name+'.key');run(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',f]);return f;};
  const root=(name,cn)=>{const k=key(name);const f=path.join(dir,name+'.pem');
    run(['req','-x509','-new','-key',k,'-subj','/CN='+cn,'-days','3','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-out',f]);return {key:k,cert:f};};
  const stamp=ms=>new Date(ms).toISOString().replace(/[-:T]/g,'').slice(0,14)+'Z';
  let serial=1;
  const issue=async(ca,keyFile,name,notBefore,days=30)=>{
    const csr=path.join(dir,`c${serial}.csr`),ext=path.join(dir,`c${serial}.ext`),out=path.join(dir,`c${serial}.pem`);
    await fs.writeFile(ext,`subjectAltName=DNS:${name}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n`);
    run(['req','-new','-key',keyFile,'-subj','/CN='+name,'-out',csr]);
    run(['x509','-req','-in',csr,'-CA',ca.cert,'-CAkey',ca.key,'-set_serial',String(serial++),'-not_before',stamp(notBefore),'-not_after',stamp(notBefore+days*86400000),'-extfile',ext,'-out',out]);
    return fs.readFile(out,'utf8');
  };
  const selfSigned=async(keyFile,name)=>{const out=path.join(dir,`s${serial++}.pem`);
    run(['req','-x509','-new','-key',keyFile,'-subj','/CN='+name,'-days','2','-addext','subjectAltName=DNS:'+name,'-out',out]);return fs.readFile(out,'utf8');};
  return {key,root,issue,selfSigned};
}
const spkiSha=async keyFile=>createHash('sha256').update(createPublicKey(await fs.readFile(keyFile)).export({type:'spki',format:'der'})).digest('hex');

// A guest front: one TLS key, a self-signed carrier by default, and CA certificates per name (SNI), as certs.go serves.
async function guest(t,{keyFile,tag,selfName}){
  const key=await fs.readFile(keyFile),fallback={key,cert:null},contexts=new Map();
  const g={tag,contexts,key,keyFile,serve(name,cert,otherKey){contexts.set(name,tls.createSecureContext({key:otherKey||key,cert}));},
    revoke(){contexts.clear();}};
  fallback.cert=selfName;
  const server=https.createServer({key,cert:fallback.cert,SNICallback:(name,cb)=>cb(null,contexts.get(name)||tls.createSecureContext(fallback))},
    (req,res)=>res.end(`${tag} ${req.headers.host}`));
  await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>{server.closeAllConnections();server.close(r);}));
  g.port=server.address().port;g.open=()=>new Promise((r,j)=>server.getConnections((e,n)=>e?j(e):r(n)));return g;
}

// A client: resolve nothing, connect to an ingress address with SNI, trust only the given roots, read the body.
function fetchName(port,name,ca){
  return new Promise((resolve,reject)=>{
    const req=https.get({host:'127.0.0.1',port,servername:name,headers:{host:name},ca,agent:false,timeout:5000},res=>{let b='';res.on('data',d=>b+=d);res.on('end',()=>resolve(b));});
    req.on('error',reject);req.on('timeout',()=>req.destroy(Error('timeout')));
  });
}
const refused=(port,name,ca)=>assert.rejects(fetchName(port,name,ca),undefined,`${name} must not route`);

test('owner-committed names route through independent direct hosts only with proof of name control',async t=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'owner-names-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const P=await pki(dir),root=P.root('root','Test WebPKI Root'),rogue=P.root('rogue','Rogue Root');
  const rootPem=await fs.readFile(root.cert,'utf8'),now=Date.now(),day=86400000;
  const kA1=P.key('a1'),kA2=P.key('a2'),kB=P.key('b'),kOther=P.key('other');

  // ---- owner packages, committed on the (fixture) ledger ----
  const pkg=(id,owner,hosts)=>preparePackage({version:1,chainId:8453,ledger,deployment:id,owner,appRef:'catalog://explicit/1',
    appId:'44'.repeat(32),runtimeId:'55'.repeat(32),configText:'',secretsMode:'public',names:{hosts:[...hosts].sort()}});
  const pkgA=pkg(A,ownerA.address,['shop.example.com','www.example.com','wrongkey.example.com','unproven.example.org']);
  const pkgB=pkg(B,ownerB.address,['shop.example.com','b.example.net']);
  const pkgA2=pkg(A,newOwner.address,['shop.example.com','www.example.com']);
  const envelope=p=>JSON.stringify({guestBootstrap:p.intent});
  const leases={
    [A]:{id:A,chainId:8453,deployments:ledger,owner:ownerA.address,appRef:'catalog://explicit/1',configCid:envelope(pkgA),runner:R1,runnerOperator:op1.address,active:true,isPublic:true,validUntil:now+day,leaseUntil:now+day},
    [B]:{id:B,chainId:8453,deployments:ledger,owner:ownerB.address,appRef:'catalog://explicit/1',configCid:envelope(pkgB),runner:R1,runnerOperator:op1.address,active:true,isPublic:true,validUntil:now+day,leaseUntil:now+day}};
  const leaseReader={get:id=>leases[id]?structuredClone(leases[id]):null};

  // ---- public package gateways: one lies (serves B's bytes for every CID), one is honest ----
  const byCid=new Map([pkgA,pkgB,pkgA2].map(p=>[p.cid,p.bytes]));
  const serve=handler=>new Promise(r=>{const s=http.createServer(handler).listen(0,'127.0.0.1',()=>{t.after(()=>new Promise(q=>{s.closeAllConnections();s.close(q);}));r('http://127.0.0.1:'+s.address().port+'/ipfs');});});
  const liar=await serve((_q,res)=>res.end(pkgB.bytes)),honest=await serve((q,res)=>{const b=byCid.get(q.url.split('/').pop());res.statusCode=b?200:404;res.end(b||'');});
  const central=[];
  const refusingFetch=(url,init)=>{if(new URL(url).hostname.endsWith('enclave.host')){central.push(String(url));return Promise.reject(Error('Enclave refuses'));}return fetch(url,init);};

  // ---- guests (fixtures for attested SNP guests) ----
  const gA1=await guest(t,{keyFile:kA1,tag:'guest-A@host1',selfName:await P.selfSigned(kA1,label(A))});
  const gB=await guest(t,{keyFile:kB,tag:'guest-B@host1',selfName:await P.selfSigned(kB,label(B))});
  const issuedA=now-2*day;
  gA1.serve('shop.example.com',await P.issue(root,kA1,'shop.example.com',issuedA));
  gA1.serve('www.example.com',await P.issue(root,kA1,'www.example.com',issuedA));
  gA1.serve('wrongkey.example.com',await P.issue(root,kOther,'wrongkey.example.com',issuedA),await fs.readFile(kOther));   // another key
  gA1.serve('notlisted.example.org',await P.issue(root,kA1,'notlisted.example.org',issuedA));                            // not committed
  gB.serve('b.example.net',await P.issue(root,kB,'b.example.net',issuedA));

  // ---- two independent hosts, each with a checker-signed direct-hosting qualification ----
  async function host(name,runner,operator,address,guests){
    const qualification=await qualifyProvider({hostId:runner,operator:operator.address,address,signer:checker,validForMs:300000,
      probe:Object.fromEntries(PROVIDER_CHECKS.map(k=>[k,async()=>true]))});
    const qfile=path.join(dir,name+'-qualification.json');await fs.writeFile(qfile,JSON.stringify(qualification));
    const admitted=new Map();   // id -> attested key: what the host's admission proof of the local guest binds
    const [httpsPort,httpPort]=[await free(),await free()];
    const h=await createNetworkHost({config:{directories:['http://127.0.0.1:9/'],checkers:[checker.address],apps:'all',wgBinary:'/bin/true',nodeBinary:process.execPath,workerModule:'/bin/true',
      direct:{address,bindHost:'127.0.0.1',httpsPort,httpPort,qualificationFile:qfile,ownerNames:{gateways:[liar,honest]}}},
      directory:path.join(dir,name),account:operator,runner,leaseReader,fetch:refusingFetch,ownerNameRoots:[rootPem],
      authorize:id=>!!leases[id]&&leases[id].runner===runner&&admitted.has(id),attestedKey:id=>admitted.get(id)||null,
      forward:(socket,id)=>{const g=guests()[id];if(!g)return socket.destroy();const up=net.connect(g.port,'127.0.0.1');
        const close=()=>{socket.destroy();up.destroy();};up.on('error',close);socket.on('error',close);up.once('close',close);socket.once('close',close);socket.pipe(up).pipe(socket);}});
    t.after(()=>h.direct.runtime.close());
    return {h,rt:h.direct.runtime,admitted,qualification,address};
  }
  const guests1={[A]:gA1,[B]:gB};
  const H1=await host('host1',R1,op1,'8.8.4.4',()=>guests1);
  const start=async(H,id,g)=>{H.admitted.set(id,await spkiSha(g.keyFile));const app=await H.rt.start({deploymentId:id,names:[label(id)],policy:{}});app.admit(Date.now()+day);await H.rt.proveOwnerNames(app);return app;};
  const appA=await start(H1,A,gA1),appB=await start(H1,B,gB);
  const port1=H1.rt.httpsPort;
  await new Promise(r=>setTimeout(r,50));
  assert.equal(await gA1.open()+await gB.open(),0,'a proof leaves no connection to the guest open');

  // valid custom names route to the owner's guest; platform labels keep working (self-signed carrier: pinned by clients)
  assert.equal(await fetchName(port1,'shop.example.com',rootPem),'guest-A@host1 shop.example.com');
  assert.equal(await fetchName(port1,'www.example.com',rootPem),'guest-A@host1 www.example.com');
  assert.equal(await fetchName(port1,'b.example.net',rootPem),'guest-B@host1 b.example.net');
  assert.equal(await fetchName(port1,label(A),undefined).catch(()=>null),null,'a label cert is not publicly trusted');
  assert.equal(await new Promise((res,rej)=>{const s=tls.connect({host:'127.0.0.1',port:port1,servername:label(A),rejectUnauthorized:false},()=>{res(s.getPeerX509Certificate().subject);s.destroy();});s.on('error',rej);}),'CN='+label(A));
  // a name the package does not list, a listed name without a certificate, and a certificate on another key: refused
  await refused(port1,'notlisted.example.org',rootPem);
  await refused(port1,'unproven.example.org',rootPem);
  await refused(port1,'wrongkey.example.com',rootPem);
  const st=H1.rt.ownerStatus(A);
  assert.deepEqual(st.routed.sort(),['shop.example.com','www.example.com']);
  assert.match(st.names['wrongkey.example.com'],/not on the attested guest key/);
  assert.match(st.names['unproven.example.org'],/does not chain|not for/);
  // port 80 only redirects a routed owner name to HTTPS
  const redirect=await new Promise(r=>http.get({host:'127.0.0.1',port:H1.rt.httpPort,headers:{host:'shop.example.com'},path:'/x'},res=>{res.resume();r([res.statusCode,res.headers.location]);}));
  assert.deepEqual(redirect,[308,'https://shop.example.com/x']);
  const no80=await new Promise(r=>http.get({host:'127.0.0.1',port:H1.rt.httpPort,headers:{host:'notlisted.example.org'},path:'/'},res=>{res.resume();r(res.statusCode);}));
  assert.equal(no80,421);

  // ---- an attacker deployment B lists the victim's name ----
  const reproveB=async cert=>{if(cert)gB.serve('shop.example.com',cert,cert.key);else gB.contexts.delete('shop.example.com');await H1.rt.proveOwnerNames(appB);};
  for(const [what,cert] of [['no certificate',null],['a self-signed certificate',await P.selfSigned(kB,'shop.example.com')],
    ['a certificate from an untrusted root',await P.issue(rogue,kB,'shop.example.com',now-day)],
    ['an older public certificate (a previous DNS owner)',await P.issue(root,kB,'shop.example.com',issuedA-day)]]){
    await reproveB(cert);
    assert.equal(await fetchName(port1,'shop.example.com',rootPem),'guest-A@host1 shop.example.com',`B with ${what} took the name`);
    assert.equal(await fetchName(port1,'b.example.net',rootPem),'guest-B@host1 b.example.net','B keeps its own name');
  }
  // an exact tie selects neither for THAT name only: the victim's other names and the attacker's own keep routing
  await reproveB(await P.issue(root,kB,'shop.example.com',issuedA));
  await refused(port1,'shop.example.com',rootPem);
  assert.equal(await fetchName(port1,'www.example.com',rootPem),'guest-A@host1 www.example.com','a tie cannot veto unrelated names');
  // the name's DNS controller issuing later to B is the controller moving the name: B wins, and only that name
  await reproveB(await P.issue(root,kB,'shop.example.com',issuedA+day));
  assert.equal(await fetchName(port1,'shop.example.com',rootPem),'guest-B@host1 shop.example.com');
  await reproveB(null);
  assert.equal(await fetchName(port1,'shop.example.com',rootPem),'guest-A@host1 shop.example.com','without its proof B is no candidate again');

  // ---- a changed key (guest relaunch) retires routes until re-proven ----
  H1.admitted.set(A,'00'.repeat(32));
  await refused(port1,'shop.example.com',rootPem);
  H1.admitted.set(A,await spkiSha(kA1));
  assert.equal(await fetchName(port1,'shop.example.com',rootPem),'guest-A@host1 shop.example.com');

  // ---- substitution: the package for another owner or deployment never yields names ----
  assert.throws(()=>ownerPackageNames(leases[A],pkgB.bytes),/hash mismatch/);
  assert.throws(()=>ownerPackageNames({...leases[A],configCid:envelope(pkgA2)},pkgA.bytes),/hash mismatch/);
  assert.throws(()=>ownerPackageNames({...leases[A],owner:newOwner.address},pkgA.bytes),/owner mismatch/);

  // ---- ownership transfer: retired at once (scope), and the revoked guest no longer proves ----
  leases[A]={...leases[A],owner:newOwner.address,configCid:envelope(pkgA2)};
  await refused(port1,'shop.example.com',rootPem);
  gA1.revoke();await H1.rt.proveOwnerNames(appA);
  await refused(port1,'shop.example.com',rootPem);
  assert.equal(H1.rt.ownerStatus(A).routed.length,0);
  // the new owner's guest (same host, relaunched with a new key and a fresh certificate) proves again
  const gA1b=await guest(t,{keyFile:kA2,tag:'guest-A(new owner)@host1',selfName:await P.selfSigned(kA2,label(A))});
  gA1b.serve('shop.example.com',await P.issue(root,kA2,'shop.example.com',now-60000));guests1[A]=gA1b;
  H1.admitted.set(A,await spkiSha(kA2));await H1.rt.proveOwnerNames(appA);
  assert.equal(await fetchName(port1,'shop.example.com',rootPem),'guest-A(new owner)@host1 shop.example.com');

  // ---- runner transfer and provider failover, found through signed, qualified route records ----
  const policy=validateNetworkPolicy({version:5,deploymentId:A,nonce:1,issuedAt:1,mode:'direct',fallback:'none',direct:{maxPricePerGiB6:0}});
  const route=address=>[{circuit:'ab'.repeat(16),address,port:443,transport:'direct'}];
  const publisher=(H,op,name)=>new RoutePublisher({directory:path.join(dir,name+'-routes'),account:op,lease:id=>({...leases[id],validUntil:Date.now()+60000}),policy:()=>policy,qualification:async()=>H.qualification,distribute:async()=>{}});
  const memory=new DurableState(path.join(dir,'client-route-memory'));
  const clientVerify=bundle=>verifyRoute(JSON.parse(JSON.stringify(bundle)),{deploymentId:A,policy,lease:{...leases[A],validUntil:Date.now()+60000},memory,providerProbeSigners:[checker.address]});
  const portOf={'8.8.4.4':port1};   // fixture network: a public route address -> the local listener standing in for it
  const via=async(bundle,name)=>{const r=await clientVerify(bundle);return fetchName(portOf[r.routes[0].address],name,rootPem);};
  const record1=await publisher(H1,op1,'host1').publish(A,route('8.8.4.4'));
  assert.equal(await via(record1,'shop.example.com'),'guest-A(new owner)@host1 shop.example.com');

  const guests2={},H2=await host('host2',R2,op2,'8.8.8.8',()=>guests2);portOf['8.8.8.8']=H2.rt.httpsPort;
  const gA2=await guest(t,{keyFile:kA1,tag:'guest-A@host2',selfName:await P.selfSigned(kA1,label(A))});
  gA2.serve('shop.example.com',await P.issue(root,kA1,'shop.example.com',now-30000));guests2[A]=gA2;
  leases[A]={...leases[A],runner:R2,runnerOperator:op2.address};
  // the old host retires the name at once; its record no longer verifies for the current lease
  await refused(port1,'shop.example.com',rootPem);
  await assert.rejects(clientVerify(record1),/fresh matching lease|not signed by current runner/);
  const appA2=await start(H2,A,gA2);assert.ok(appA2);
  const record2=await publisher(H2,op2,'host2').publish(A,route('8.8.8.8'));
  assert.equal(await via(record2,'shop.example.com'),'guest-A@host2 shop.example.com');
  const record3=await publisher(H2,op2,'host2').publish(A,route('8.8.8.8'));await clientVerify(record3);
  await assert.rejects(clientVerify(record2),/rollback/,'an older record is refused by the client\'s floor');
  // DNS-style failover across both providers' addresses: the first is down, the second serves
  await H1.rt.close();
  let served=null;for(const port of [port1,H2.rt.httpsPort]){try{served=await fetchName(port,'shop.example.com',rootPem);break;}catch{}}
  assert.equal(served,'guest-A@host2 shop.example.com');

  assert.deepEqual(central,[],'no Enclave service was asked');
});

test('the name table: ties fail closed per name, unproven claims cannot veto, proofs lapse and are bound to scope',()=>{
  let t=1_000_000;const table=new OwnerNameTable({now:()=>t});
  const proof=(name,notBefore,extra={})=>({name,notBefore,notAfter:t+86400000,spkiSha256:'aa'.repeat(32),scope:'s',...extra});
  table.set(A,[proof('shop.example.com',10),proof('www.example.com',10)]);
  const live=()=>true;
  assert.equal(table.select('shop.example.com',live),A);
  table.set(B,[proof('shop.example.com',5)]);assert.equal(table.select('shop.example.com',live),A,'older loses');
  table.set(B,[proof('shop.example.com',10)]);assert.equal(table.select('shop.example.com',live),null,'tie: neither');
  assert.equal(table.select('www.example.com',live),A,'a tie on one name leaves the others');
  assert.equal(table.select('shop.example.com',id=>id===A),A,'a claim that is not live is no candidate');
  table.set(B,[]);assert.equal(table.select('shop.example.com',live),A,'replacing B\'s set never removes A\'s');
  t+=NAME_PROOF_TTL_MS;assert.equal(table.select('shop.example.com',live),null,'a proof lapses unless re-made');
  assert.equal(leaseNameScope({id:A,runner:R1,owner:'0xAB',configCid:'x'})===leaseNameScope({id:A,runner:R2,owner:'0xAB',configCid:'x'}),false);
});

test('a per-app ingress admits a dynamic owner name only for its own app',async t=>{
  const seen=[];let proven=new Set(['shop.example.com']);
  const ing=await createAppIngress({deploymentId:A,names:[label(A)],authorize:()=>true,admitName:n=>proven.has(n),forward:s=>{seen.push(s);s.destroy();}});
  t.after(()=>ing.close());
  const hello=name=>new Promise(r=>{const s=tls.connect({host:'127.0.0.1',port:ing.port,servername:name,rejectUnauthorized:false});s.on('error',()=>r());s.on('close',()=>r());});
  await hello('shop.example.com');await hello('other.example.com');proven=new Set();await hello('shop.example.com');await hello(label(A));
  assert.equal(seen.length,2,'the proven owner name and the label were forwarded; the unproven and revoked ones were not');
  await assert.rejects(createAppIngress({deploymentId:A,names:[label(A)],authorize:()=>true,forward:()=>{},admitName:'yes'}),/function/);
});

test('direct owner names need explicit gateways and the attested key; nothing else configures them',async t=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'owner-names-cfg-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const base={directories:['http://127.0.0.1:9/'],checkers:[checker.address],apps:'all',wgBinary:'/bin/true',nodeBinary:process.execPath,workerModule:'/bin/true'};
  const direct=o=>({...base,direct:{address:'8.8.4.4',qualificationFile:path.join(dir,'q.json'),httpsPort:1,httpPort:2,...o}});
  const make=(config,extra={})=>createNetworkHost({config,directory:dir,account:op1,runner:R1,leaseReader:{get:()=>null},authorize:()=>true,forward:()=>{},...extra});
  await assert.rejects(make(direct({ownerNames:{gateways:['http://127.0.0.1:1/ipfs']}})),/attested guest key/);
  await assert.rejects(make(direct({ownerNames:{gateways:['http://127.0.0.1:1/ipfs'],relay:'https://api.enclave.host'}}),{attestedKey:()=>null}),/only explicit gateways/);
  await assert.rejects(make(direct({ownerNames:{gateways:['http://gateway.example/ipfs']}}),{attestedKey:()=>null}),/HTTPS or literal-IP/);
  await assert.rejects(make(direct({ownerNames:{gateways:[]}}),{attestedKey:()=>null}),/1-8 explicit/);
  const plain=await make(direct({}));assert.equal(plain.direct.runtime.ownerNames,null,'without the block: platform labels only');
});
