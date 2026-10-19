// A client-owned trust profile, signed public records and hardware evidence are
// sufficient to reach an app. No Enclave API, DNS resolution of the app name,
// address-book authority or operator CA participates in this path.
import https from 'node:https';
import {isIP} from 'node:net';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {PassThrough,Transform,pipeline} from 'node:stream';
import {LeaseReader} from './lease-reader.mjs';
import {PublicDirectory} from './public-directory.mjs';
import {DirectoryClient} from './directory-client.mjs';
import {validateNetworkAuthorities} from './network-authorities.mjs';
import {verifyOwnerSignature} from './owner-signature.mjs';
import {recordHash} from './route-record.mjs';
import {probeGuest} from './guest-probe.mjs';
import {DirectHttpsAgent} from './socks-connect.mjs';
import {seedCertChain} from '../relay/snp-verify.mjs';
import {startupExpectation,inlineStartupBytes} from './startup-expectation.mjs';
import {bootstrapIntent} from '../sdk/bootstrap/package.mjs';

const ZERO='0x'+'0'.repeat(40);
const identity=l=>recordHash(Object.fromEntries(['id','chainId','deployments','owner','runner','runnerOperator','appRef','configCid'].map(k=>[k,l[k]])));

export class NativeClient {
  constructor(profile,{reader,fetch=globalThis.fetch,probe=probeGuest,now=Date.now,maxConcurrent=4}={}){
    if(!Number.isSafeInteger(maxConcurrent)||maxConcurrent<1||maxConcurrent>32)throw Error('native client concurrency must be 1..32');
    // Snapshot all caller inputs: asynchronous proof work must not permit a
    // caller's later mutation to change the expected app or verification policy.
    this.profile=structuredClone(profile);const p=this.profile;
    if(!p||p.version!==1||!/^0x[0-9a-f]{64}$/.test(p.deploymentId||'')||
      !/^(?=.{1,253}$)[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(p.hostname||'')||
      typeof p.stateDir!=='string'||!path.isAbsolute(p.stateDir)||
      !(p.linux||p.shield&&p.hostSession||p.pvm))throw Error('explicit native client profile required');
    if(p.startup!==undefined){
      if(!p.startup||typeof p.startup!=='object'||Array.isArray(p.startup)||p.expected!==undefined||!p.linux||p.shield||p.pvm||p.hostSession||
        Object.keys(p.startup).some(k=>!['gateways','packageBase64'].includes(k)))throw Error('owner startup requires an unambiguous SNP runtime policy');
      this.startupBytes=inlineStartupBytes(p.startup.packageBase64);this.startupCache=null;
      if(this.startupBytes===undefined&&(!Array.isArray(p.startup.gateways)||!p.startup.gateways.length||p.startup.gateways.length>8))throw Error('explicit startup package sources required');
      // Keep first-use artifact discovery independent of any DNS authority too.
      if(p.startup.gateways?.some(raw=>!isIP(new URL(raw).hostname.replace(/^\[|\]$/g,''))))throw Error('native startup requires literal gateway addresses');
    }else if(!p.expected||typeof p.expected.appRef!=='string'||typeof p.expected.configCid!=='string'||
      !/^[0-9a-f]{64}$/.test(p.expected.appSha256||'')||!/^[0-9a-f]{64}$/.test(p.expected.runtimeId||''))throw Error('explicit app expectations or owner startup required');
    this.pins=validateNetworkAuthorities(p.authorityPins);
    if(p.linux?.vcekBase64)p.linux.vcek=Buffer.from(p.linux.vcekBase64,'base64');
    if(p.linux?.certChainPem)seedCertChain(p.linux.product,p.linux.certChainPem);
    this.reader=reader||new LeaseReader({rpc:p.rpc,chainId:p.chainId,addressBook:ZERO,authorityPins:this.pins,includeHostPayout:true,now});
    this.transport=new DirectoryClient({origins:p.directories,fetch});
    // Literal directory origins make the DNS-independent claim enforceable.
    if(this.transport.origins.some(o=>!isIP(new URL(o).hostname.replace(/^\[|\]$/g,''))))throw Error('native discovery requires literal directory addresses');
    this.now=now;this.probe=probe;this.fetch=fetch;this.operators=new Map();this.tail=Promise.resolve();this.maxConcurrent=maxConcurrent;this.open=0;
    this.directory=new PublicDirectory({directory:path.join(p.stateDir,recordHash({chainId:p.chainId??8453,pins:this.pins,id:p.deploymentId,checkers:p.checkers})),checkers:p.checkers,now,
      leaseOf:async id=>id===p.deploymentId?this.reader.get(id):null,
      hostOperator:async id=>{
        if(!this.operators.has(id))this.operators.set(id,this.reader.registryEntries(this.pins.registry,[id]).then(([h])=>h?.active?h.operator:null));
        return this.operators.get(id);
      },
      verifyOwner:(owner,message,signature)=>verifyOwnerSignature({reader:this.reader,owner,message,signature,sessionVaultFactory:this.pins.sessionVaultFactory})});
  }
  currentLease(){
    const p=this.profile,l=this.reader.get(p.deploymentId);
    if(!l||!l.active||!l.isPublic||l.validUntil<=this.now()||l.leaseUntil<=this.now()||
      l.chainId!==(p.chainId??8453)||l.deployments.toLowerCase()!==this.pins.deployments||
      p.expected&&(l.appRef!==p.expected.appRef||l.configCid!==p.expected.configCid))throw Error('no current lease matching the pinned application');
    return l;
  }
  async resolve(){
    const p=this.profile;
    await this.reader.refresh([p.deploymentId]);const startLease=this.currentLease();this.operators.clear();
    let expected=p.expected,provenance={source:'caller-pinned'};
    if(p.startup){
      const intent=bootstrapIntent(startLease.configCid);
      const cached=this.startupCache?.sha256===intent?.sha256?this.startupCache.bytes:undefined;
      const derived=await startupExpectation(startLease,{runtime:p.linux.runtime,gateways:p.startup.gateways,bytes:this.startupBytes??cached,fetchImpl:this.fetch});
      expected=derived.expected;provenance=derived.provenance;this.startupCache={sha256:provenance.sha256,bytes:derived.bytes};
    }
    const answers=await this.transport.read('/v1/network/records');
    let validSnapshots=0;
    for(const {value} of answers){
      if(value?.version!==1||!['providers','policies','publications'].every(k=>Array.isArray(value[k])&&value[k].length<=4096))continue;
      // Full deployment IDs prevent short-label collisions. Do not import any
      // other deployment's policy, route, owner or application expectation.
      await this.directory.import({...value,
        providers:value.providers.filter(e=>e&&typeof e==='object'&&e.record).map(e=>({record:e.record,qualifications:Array.isArray(e.qualifications)?e.qualifications:[]})),
        policies:value.policies.filter(e=>e?.policy?.deploymentId===p.deploymentId),
        publications:value.publications.filter(e=>e?.bundle?.record?.deploymentId===p.deploymentId)});
      validSnapshots++;
    }
    if(!validSnapshots)throw Error('no public record snapshot available');
    const routes=(await this.directory.routes()).deployments[p.deploymentId],lease=this.currentLease();
    if(!routes?.httpsRoutes?.length||routes.expiresAt<=this.now())throw Error('no current verified route');
    if(identity(startLease)!==identity(lease))throw Error('deployment changed during expectation verification');
    return {routes,lease,expected,provenance};
  }
  // One application request: discovery, fresh proof, revalidation, then ONE send.
  // Buffered; resolves after the whole bounded response (the GET/HEAD result shape).
  request(options={}){
    return this._enqueue(options,false).then(async handle=>{
      if(!handle.body)return {...handle.result,body:Buffer.alloc(0)};
      const chunks=[];
      try{for await(const chunk of handle.body)chunks.push(chunk);}
      catch(e){throw Error(e.message);}
      return {...handle.result,body:Buffer.concat(chunks)};
    });
  }
  // The same authorization and single send, resolving as soon as response headers
  // arrive. `body` is a Readable delivering bytes as they come (SSE, incremental
  // chat): async-iterate or pipe it; it applies backpressure to the guest.
  stream(options={}){
    return this._enqueue(options,true).then(handle=>({...handle.result,body:handle.body,cancel:handle.cancel,closed:handle.closed}));
  }
  // Discovery, proof and connection setup are serialized per client, so a second
  // request cannot replace the lease context while the first attests. The queue is
  // released once response headers arrive; open responses are bounded separately.
  _enqueue(options,streaming){
    let input;
    try{input=snapshotRequest(options,streaming);}catch(e){return Promise.reject(e);}
    if(this.open>=this.maxConcurrent)return Promise.reject(Error('too many open native requests'));
    this.open++;let released=false;const release=()=>{if(!released){released=true;this.open--;}};
    const run=this.tail.then(()=>this._open(input,release));
    this.tail=run.then(()=>{},()=>{});
    return run.catch(e=>{release();throw e;});
  }
  async _open({path:requestPath,method,headers,body,signal,maxBytes,timeoutMs,idleTimeoutMs,maxDurationMs,recheckMs,streaming},release){
    const cancelled=()=>{if(signal?.aborted)throw Error('native request cancelled before sending');};
    cancelled();
    const p=this.profile,initial=await this.resolve(),fingerprint=identity(initial.lease);
    let chosen,proof,proofStarted;const failures=[];
    for(const route of initial.routes.httpsRoutes){
      cancelled();
      if(!isIP(route.address)||route.port!==443)continue;
      try{
        proofStarted=this.now();
        proof=await this.probe({deploymentId:p.deploymentId,hostname:p.hostname,address:route.address,port:route.port,
          direct:true,attestationBootstrap:true,expected:initial.expected,linux:p.linux,shield:p.shield,hostSession:p.hostSession,pvm:p.pvm});
        if(proof?.verified!==true||proof.ready!==true||proof.deploymentId!==p.deploymentId||proof.appSha256!==initial.expected.appSha256||proof.runtimeId!==initial.expected.runtimeId||
          !/^[0-9a-f]{64}$/.test(proof.spkiSha256||''))throw Error('fresh bound guest proof required');
        chosen=route;break;
      }catch(e){failures.push(String(e.message).slice(0,200));}
    }
    if(!chosen)throw Error('all attestation routes refused: '+failures.join('; '));
    // Attestation may take seconds. Read signed records and chain state again;
    // a withdrawal, reassignment or app change must prevent application bytes.
    const current=await this.resolve();
    if(identity(current.lease)!==fingerprint||!current.routes.httpsRoutes.some(r=>recordHash(r)===recordHash(chosen)))throw Error('deployment changed during attestation');
    cancelled();
    // A deadline for STARTING a send, never a claim about later ownership.
    const validUntil=Math.min(current.routes.expiresAt,current.lease.validUntil,proofStarted+60000);
    // Checked on the handshake, before Node may write the request line, headers,
    // credentials or body: the agent hands over the socket only after this returns.
    const agent=new DirectHttpsAgent({tlsOptions:{rejectUnauthorized:false},verifyPeer:connection=>{
      if(signal?.aborted)throw Error('native request cancelled before sending');
      if(validUntil<=this.now()||identity(this.currentLease())!==fingerprint)throw Error('native authorization expired');
      const key=connection.getPeerX509Certificate()?.publicKey.export({format:'der',type:'spki'});
      if(!key||createHash('sha256').update(key).digest('hex')!==proof.spkiSha256)throw Error('guest TLS key changed');
    }});
    const result={route:chosen,proof,expectation:current.provenance,leaseBlock:current.lease.blockNumber,validUntil};
    return new Promise((resolve,reject)=>{
      let settled=false,out=null,idle=null,recheck=null,finished=false,closedResolve;
      const closed=new Promise(r=>closedResolve=r),timers=[];
      const finish=error=>{
        if(finished)return;finished=true;
        for(const t of timers)clearTimeout(t);clearTimeout(idle);clearInterval(recheck);
        signal?.removeEventListener('abort',onAbort);req.destroy();agent.destroy();release();
        closedResolve({bytes:size,error:error?error.message:null});
      };
      const fail=error=>{
        if(!settled){settled=true;finish(error);reject(error);}
        else if(out&&!out.destroyed)out.destroy(error);
        else finish(error);
      };
      const onAbort=()=>fail(Error(settled?'native stream cancelled':'native request cancelled'));
      let size=0;
      // host is a literal address. servername/Host only select a virtual app;
      // they are never resolved and are never accepted as proof of identity.
      const req=https.request({host:chosen.address,port:chosen.port,servername:p.hostname,path:requestPath,method,
        headers:{...headers,host:p.hostname,...(body?{'content-length':String(body.length)}:{})},agent},res=>{
        if(!streaming)timers.push(setTimeout(()=>fail(Error('native request timeout')),Math.max(0,deadline-Date.now())));
        clearTimeout(timers.shift());
        const empty=method==='HEAD'||res.statusCode===204||res.statusCode===304;
        const limiter=new Transform({transform(chunk,_encoding,callback){
          size+=chunk.length;if(size>maxBytes)return callback(Error('native response too large'));
          if(streaming)armIdle();callback(null,chunk);
        }});
        out=new PassThrough({highWaterMark:64*1024});
        // A consumer that never listens for errors must not crash the process;
        // iterators and pipes still receive the error.
        out.on('error',()=>{});
        const armIdle=()=>{clearTimeout(idle);idle=setTimeout(()=>out.destroy(Error('native stream idle timeout')),idleTimeoutMs);};
        if(streaming){
          armIdle();timers.push(setTimeout(()=>out.destroy(Error('native stream duration limit')),maxDurationMs));
          // An open stream is cut once the chain no longer shows the same current
          // deployment (owner, runner, app, configuration, lease), or once that can
          // no longer be confirmed. It never extends the send authorization.
          recheck=setInterval(async()=>{
            await this.reader.refresh([p.deploymentId]).catch(()=>{});
            try{if(identity(this.currentLease())!==fingerprint)throw Error();}
            catch{out.destroy(Error('native authorization ended: deployment is not confirmed current'));}
          },recheckMs);
        }
        pipeline(res,limiter,out,error=>finish(error));
        if(empty&&!streaming)out.resume();
        settled=true;
        resolve({result:{...result,status:res.statusCode,headers:res.headers},body:empty&&!streaming?null:out,
          cancel:reason=>{if(!out.destroyed)out.destroy(Error(typeof reason==='string'?reason.slice(0,200):'native stream cancelled'));},closed});
      });
      const deadline=Date.now()+timeoutMs;
      timers.push(setTimeout(()=>fail(Error('native request timeout')),timeoutMs));
      req.once('error',error=>fail(error));
      signal?.addEventListener('abort',onAbort,{once:true});
      // One send. A transport failure after this point is reported, never retried:
      // the guest may already have acted on the request.
      req.end(body||undefined);
    });
  }
}

const METHODS=['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'];
const FORBIDDEN=['host','connection','upgrade','content-length','transfer-encoding','proxy-authorization','proxy-connection','keep-alive','te','trailer','expect'];
const TOKEN=/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const bounded=(v,fallback,min,max)=>{const x=v===undefined?fallback:v;if(!Number.isSafeInteger(x)||x<min||x>max)throw Error('native request limit out of range');return x;};
// Copy everything the caller supplied, synchronously: later mutation of their
// headers or body buffer cannot change what is sent. The signal is kept by
// reference on purpose; it is the caller's live cancellation channel.
function snapshotRequest(options,streaming){
  if(!options||typeof options!=='object'||Array.isArray(options))throw Error('native request options required');
  const {body:rawBody,signal,...plain}=options;
  if(signal!==undefined&&!(signal instanceof AbortSignal))throw Error('signal must be an AbortSignal');
  const o=structuredClone(plain);
  const known=['path','method','headers','maxBytes','maxRequestBytes','timeoutMs','idleTimeoutMs','maxDurationMs','recheckMs'];
  if(Object.keys(o).some(k=>!known.includes(k)))throw Error('unknown native request option');
  const method=o.method===undefined?'GET':o.method,requestPath=o.path===undefined?'/':o.path;
  if(!METHODS.includes(method))throw Error('unsupported native request method');
  if(typeof requestPath!=='string'||requestPath.length>8192||!requestPath.startsWith('/')||requestPath.startsWith('//')||/[\x00-\x20\x7f#]/.test(requestPath))throw Error('invalid native request path');
  const headers=o.headers===undefined?{}:o.headers;
  if(!headers||Array.isArray(headers)||typeof headers!=='object'||Object.keys(headers).length>100)throw Error('invalid native request headers');
  const seen=new Set();let headerBytes=0;
  for(const [name,value]of Object.entries(headers)){
    const lower=name.toLowerCase();
    if(!TOKEN.test(name)||FORBIDDEN.includes(lower)||seen.has(lower))throw Error('forbidden or duplicate native request header');
    seen.add(lower);
    for(const v of Array.isArray(value)?value:[value]){
      if(typeof v!=='string'||/[\x00\r\n]/.test(v))throw Error('invalid native request header value');
      headerBytes+=name.length+v.length;
    }
  }
  if(headerBytes>64*1024)throw Error('native request headers too large');
  const maxRequestBytes=bounded(o.maxRequestBytes,8*1024*1024,0,64*1024*1024);
  let body=null;
  if(rawBody!==undefined&&rawBody!==null){
    if(method==='GET'||method==='HEAD')throw Error('GET and HEAD carry no native request body');
    if(typeof rawBody==='string')body=Buffer.from(rawBody,'utf8');
    else if(rawBody instanceof ArrayBuffer)body=Buffer.from(new Uint8Array(rawBody.slice(0)));
    else if(ArrayBuffer.isView(rawBody))body=Buffer.from(new Uint8Array(rawBody.buffer,rawBody.byteOffset,rawBody.byteLength));
    else throw Error('native request body must be bytes or a string (streamed uploads are not supported)');
    if(body.length>maxRequestBytes)throw Error('native request body too large');
  }
  return {path:requestPath,method,headers,body,signal,streaming,
    maxBytes:bounded(o.maxBytes,streaming?64*1024*1024:8*1024*1024,1,streaming?1024*1024*1024:64*1024*1024),
    timeoutMs:bounded(o.timeoutMs,30000,1000,120000),
    idleTimeoutMs:bounded(o.idleTimeoutMs,60000,1000,600000),
    maxDurationMs:bounded(o.maxDurationMs,600000,1000,3600000),
    recheckMs:bounded(o.recheckMs,30000,1000,300000)};
}
