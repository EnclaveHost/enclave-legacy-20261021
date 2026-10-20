// Owner-committed custom names on an independent ingress (docs/network/independent-name-routing.md).
//
// Three questions, answered separately, and all three must hold before a custom name selects a deployment:
//   1. Did the deployment's CURRENT owner commit to the name? Only the exact startup package the ledger envelope
//      commits to, verified against the current lease's chain, ledger, deployment, owner and appRef, says so
//      (sdk/bootstrap/package.mjs). No relay domain map, unsigned alias or host configuration is consulted.
//   2. Does whoever controls the name's DNS agree? A package proves owner intent, not DNS ownership. The proof is a
//      WebPKI certificate for the name, chaining to the public roots, presented by the deployment's own guest over the
//      host's ordinary forward path, on exactly the TLS key the host's current attested proof bound
//      (isolation/m2/front certs.go installs only such a certificate). A CA issued it only after DNS validation.
//   3. Is it still current? A proof is bound to the lease fields whose change retires a route (owner, envelope,
//      runner, app reference) and to the attested key; it lapses after NAME_PROOF_TTL_MS and is re-made, never extended.
// Two deployments that both prove a name: the certificate issued LATER wins (a later DNS-validated issuance is the
// fresher statement of the name controller); an exact tie selects neither. A claim that cannot prove anything is not a
// candidate at all, so it can neither take nor veto a name.
import tls from 'node:tls';
import {duplexPair} from 'node:stream';
import {createHash} from 'node:crypto';
import {bootstrapIntent,verifyPackage,fetchPackage,ownerHost,MAX_OWNER_NAMES} from '../sdk/bootstrap/package.mjs';

export const NAME_PROOF_TTL_MS=5*60_000;
export const NAME_PROOF_TIMEOUT_MS=5000;

// The lease fields whose change retires every owner-name route of a deployment.
export function leaseNameScope(l){
  if(!l||!/^0x[0-9a-f]{64}$/.test(l.id||''))return null;
  return JSON.stringify([l.id,l.chainId??null,String(l.deployments||'').toLowerCase(),l.runner,String(l.owner||'').toLowerCase(),l.appRef,l.configCid]);
}

// -> {hosts, sha256, scope}: the names the exact committed package lists (none for a legacy envelope or a package
// without names). Throws when the bytes are not the committed package for this lease's owner and deployment.
export function ownerPackageNames(lease,bytes){
  const scope=leaseNameScope(lease);
  if(!scope||!Number.isSafeInteger(lease.chainId)||!/^0x[0-9a-fA-F]{40}$/.test(lease.deployments||'')||!/^0x[0-9a-fA-F]{40}$/.test(lease.owner||''))
    throw Error('owner names need a current lease scope');
  const intent=bootstrapIntent(lease.configCid);
  if(!intent)return {hosts:[],sha256:null,scope};
  const pkg=verifyPackage(bytes,intent,{chainId:lease.chainId,ledger:lease.deployments,deployment:lease.id,owner:lease.owner,appRef:lease.appRef});
  return {hosts:[...(pkg.manifest.names?.hosts||[])],sha256:pkg.sha256,scope};
}

// A host's source of owner names: the lease the host already reads, and the committed package bytes from the
// operator's explicit gateways (public bytes, authenticated by the chain commitment, never by the gateway). Packages
// are cached by hash (immutable); a lease change is a new lookup. No gateway configured -> no owner names at all.
export function ownerNameSource({lease,gateways,fetchImpl=globalThis.fetch,timeoutMs=8000}){
  if(!Array.isArray(gateways)||!gateways.length||gateways.length>8)throw Error('owner names need 1-8 explicit startup package gateways');
  for(const g of gateways){const u=new URL(g);if(!(u.protocol==='https:'||u.protocol==='http:'&&/^(\d+\.){3}\d+$|^\[[0-9a-f:]+\]$/i.test(u.hostname))||u.username||u.password||u.search||u.hash)
    throw Error('owner-name package gateways must be HTTPS or literal-IP HTTP without credentials or query');}
  const cache=new Map();
  return async id=>{
    const l=lease(id);if(!l)throw Error('no current lease');
    const intent=bootstrapIntent(l.configCid);
    if(!intent)return ownerPackageNames(l,null);
    let bytes=cache.get(intent.sha256);
    if(!bytes){
      bytes=(await fetchPackage(intent,{chainId:l.chainId,ledger:l.deployments,deployment:l.id,owner:l.owner,appRef:l.appRef},
        {gateways,fetchImpl,timeoutMs,allowHttpIPs:true})).bytes;
      cache.set(intent.sha256,bytes);while(cache.size>256)cache.delete(cache.keys().next().value);
    }
    return ownerPackageNames(l,bytes);
  };
}

// One TLS handshake to the deployment's own guest, through `open` (a duplex the host's forward path serves), naming
// `name`. Nothing is sent after the handshake: this proves a certificate, it is not a client of the app.
// -> {name, spkiSha256, notBefore, notAfter, fingerprint256, issuer}
export function proveNameControl({name,open,spkiSha256,ca=tls.rootCertificates,timeoutMs=NAME_PROOF_TIMEOUT_MS,now=Date.now}){
  return new Promise((resolve,reject)=>{
    if(!ownerHost(name)||!/^[0-9a-f]{64}$/.test(spkiSha256||''))return reject(Error('a proof needs an owner host and the attested key'));
    let socket,raw,done=false;
    // both layers end with the proof: a TLS socket over a JS stream does not end that stream on its own
    const finish=(err,value)=>{if(done)return;done=true;clearTimeout(timer);socket?.destroy();raw?.destroy();err?reject(err):resolve(value);};
    const timer=setTimeout(()=>finish(Error('name proof timed out')),timeoutMs);
    try{
      raw=open();socket=tls.connect({socket:raw,servername:name,ca,rejectUnauthorized:false,minVersion:'TLSv1.2'});
    }catch(e){return finish(e);}
    socket.once('error',e=>finish(Error('name proof handshake failed: '+e.message)));
    socket.once('secureConnect',()=>{
      const leaf=socket.getPeerX509Certificate();
      if(!leaf)return finish(Error('the guest presented no certificate'));
      if(!socket.authorized)return finish(Error('the certificate for '+name+' does not chain to the public roots: '+socket.authorizationError));
      if(leaf.checkHost(name,{subject:'never'})!==name)return finish(Error('the certificate is not for '+name));
      const key=createHash('sha256').update(leaf.publicKey.export({type:'spki',format:'der'})).digest('hex');
      if(key!==spkiSha256)return finish(Error('the certificate for '+name+' is not on the attested guest key'));
      const notBefore=Date.parse(leaf.validFrom),notAfter=Date.parse(leaf.validTo),t=now();
      if(!(notBefore<=t&&t<notAfter))return finish(Error('the certificate is not valid now'));
      finish(null,{name,spkiSha256,notBefore,notAfter,fingerprint256:leaf.fingerprint256,issuer:leaf.issuer.split('\n').find(l=>l.startsWith('CN='))?.slice(3)||''});
    });
  });
}

// A duplex the forward path can serve: the proof's TLS client writes into one end, `forward` gets the other.
export function forwardDuplex(forward,deploymentId,log=()=>{}){
  const [mine,theirs]=duplexPair();
  mine.once('close',()=>theirs.destroy());theirs.once('close',()=>mine.destroy());
  Promise.resolve().then(()=>forward(theirs,deploymentId)).catch(e=>{log('name proof forward: '+e.message);theirs.destroy();mine.destroy();});
  return mine;
}

// name -> deploymentId -> proof. Each deployment's set is replaced as a whole; one deployment never removes another's.
export class OwnerNameTable {
  constructor({now=Date.now}={}){this.now=now;this.claims=new Map();}
  set(deploymentId,proofs){
    this.drop(deploymentId);
    for(const p of proofs.slice(0,MAX_OWNER_NAMES)){
      if(!this.claims.has(p.name))this.claims.set(p.name,new Map());
      this.claims.get(p.name).set(deploymentId,{...p,provedAt:p.provedAt??this.now()});
    }
  }
  drop(deploymentId){for(const [name,m] of this.claims){m.delete(deploymentId);if(!m.size)this.claims.delete(name);}}
  // live(deploymentId, claim) -> boolean: the caller's current-authorization check for that claim
  select(name,live){
    const m=this.claims.get(String(name||'').toLowerCase());if(!m)return null;
    const t=this.now();let best=null,tie=false;
    for(const [id,c] of m){
      if(!(c.notAfter>t)||!(c.provedAt+NAME_PROOF_TTL_MS>t)||!live(id,c))continue;
      if(!best||c.notBefore>best.c.notBefore){best={id,c};tie=false;}
      else if(c.notBefore===best.c.notBefore)tie=true;
    }
    return best&&!tie?best.id:null;
  }
  names(deploymentId){return [...this.claims].filter(([,m])=>m.has(deploymentId)).map(([n])=>n);}
}
