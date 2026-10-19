// A client-owned trust profile, signed public records and hardware evidence are
// sufficient to reach an app. No Enclave API, DNS resolution of the app name,
// address-book authority or operator CA participates in this path.
import https from 'node:https';
import {isIP} from 'node:net';
import {createHash} from 'node:crypto';
import path from 'node:path';
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
  constructor(profile,{reader,fetch=globalThis.fetch,probe=probeGuest,now=Date.now}={}){
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
    this.now=now;this.probe=probe;this.fetch=fetch;this.operators=new Map();this.tail=Promise.resolve();
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
  // Serialize each client's discovery/proof/send operation. In particular a
  // second request cannot replace its lease context while the first attests.
  request(options={}){
    const input=structuredClone(options);
    const run=this.tail.then(()=>this._request(input));this.tail=run.catch(()=>{});return run;
  }
  async _request({path:requestPath='/',method='GET',headers={},maxBytes=8*1024*1024}={}){
    if(!['GET','HEAD'].includes(method)||typeof requestPath!=='string'||!requestPath.startsWith('/')||requestPath.startsWith('//')||/[\x00-\x20\x7f#]/.test(requestPath)||
      !Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>64*1024*1024||!headers||Array.isArray(headers)||typeof headers!=='object'||
      Object.keys(headers).some(k=>['host','connection','upgrade','content-length','transfer-encoding','proxy-authorization'].includes(k.toLowerCase())))throw Error('bounded native GET or HEAD required');
    const p=this.profile,initial=await this.resolve(),fingerprint=identity(initial.lease);
    let chosen,proof,proofStarted;const failures=[];
    for(const route of initial.routes.httpsRoutes){
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
    const validUntil=Math.min(current.routes.expiresAt,current.lease.validUntil,proofStarted+60000);
    const agent=new DirectHttpsAgent({tlsOptions:{rejectUnauthorized:false},verifyPeer:connection=>{
      if(validUntil<=this.now()||identity(this.currentLease())!==fingerprint)throw Error('native authorization expired');
      const key=connection.getPeerX509Certificate()?.publicKey.export({format:'der',type:'spki'});
      if(!key||createHash('sha256').update(key).digest('hex')!==proof.spkiSha256)throw Error('guest TLS key changed');
    }});
    try{
      const response=await new Promise((resolve,reject)=>{
        // host is a literal address. servername/Host only select a virtual app;
        // they are never resolved and are never accepted as proof of identity.
        const req=https.request({host:chosen.address,port:chosen.port,servername:p.hostname,path:requestPath,method,
          headers:{...headers,host:p.hostname},agent},res=>{
          const chunks=[];let size=0;
          res.on('data',b=>{size+=b.length;if(size>maxBytes)res.destroy(Error('native response too large'));else chunks.push(b);});
          res.once('error',reject);res.once('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks)}));
        });
        const timer=setTimeout(()=>req.destroy(Error('native request timeout')),30000);
        req.once('close',()=>clearTimeout(timer));req.once('error',reject);req.end();
      });
      // Never follow redirects and never retry an application request elsewhere.
      return {...response,route:chosen,proof,expectation:current.provenance,leaseBlock:current.lease.blockNumber,validUntil};
    }finally{agent.destroy();}
  }
}
