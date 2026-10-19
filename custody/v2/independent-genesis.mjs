// Measured-guest DKG coordinator. All secret state belongs in the existing
// chip/code-sealed store. Only signed public broadcasts or HPKE envelopes leave
// this module. A host is a transport and gas payer, never a key dealer.
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from 'viem';
import * as D from './digests.mjs';
import * as v2 from './protocol.mjs';
import * as hpke from '../hpke.mjs';
const hash = x => createHash('sha256').update(x).digest('hex');
const digest = (...parts) => '0x' + hash(JSON.stringify(parts));
const hx = b => Buffer.from(b).toString('hex');
const bytes = (s, max=16384) => {
  if (typeof s !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(s) || s.length > max*2) throw Error('invalid DKG bytes');
  return Buffer.from(s,'hex');
};
const info = Buffer.from('enclave-custody independent DKG round2 v1');

// Keep this helper path pinned in the measured image. Input/output include
// secret material: never add command tracing, HTTP proxying or stderr details.
export function dkgHelper(path) {
  return input => new Promise((resolve,reject) => {
    const b=Buffer.from(JSON.stringify(input));
    if(b.length>1048576)return reject(Error('DKG request too large'));
    const p=spawn(path,[],{stdio:['pipe','pipe','ignore']});
    let chunks=[],size=0,settled=false;
    const fail=()=>{if(!settled){settled=true;reject(Error('DKG helper refused'));}p.kill();};
    const timer=setTimeout(fail,15000);
    p.on('error',fail); p.stdin.on('error',fail);
    p.stdout.on('data',c=>{size+=c.length;if(size>1048576)fail();else chunks.push(c);});
    p.on('close',code=>{clearTimeout(timer);if(settled)return;settled=true;
      if(code!==0)return reject(Error('DKG helper refused'));
      try{resolve(JSON.parse(Buffer.concat(chunks)));}catch{reject(Error('DKG helper invalid output'));}
    });
    p.stdin.end(b);
  });
}

export function createIndependentGenesis({ plan, identity, encPrivateKey, store, invoke, verifyRoster }) {
  // Freeze exact scope; caller must verify every peer's fresh quote, accepted
  // host ownership and local admission policy. There is no permissive default.
  plan=JSON.parse(JSON.stringify(plan));
  const {chainId,vault,salt,machines,codeSet}=plan;
  if(!Number.isSafeInteger(chainId)||chainId<=0||!/^0x[0-9a-fA-F]{40}$/.test(vault)||!/^0x[0-9a-f]{64}$/.test(salt)||
     !Array.isArray(machines)||machines.length<3||machines.length>64||!Array.isArray(codeSet)||!codeSet.length||codeSet.length>64||
     codeSet.some(c=>!/^0x[0-9a-f]{64}$/.test(c))||typeof verifyRoster!=='function')throw Error('invalid independent genesis plan');
  for(const field of ['identity','encKey','chipId','registryId']){
    if(new Set(machines.map(m=>String(m[field]).toLowerCase())).size!==machines.length)throw Error('duplicate genesis machine');
  }
  if(machines.some(m=>m.enclave||!codeSet.includes(m.measurement)))throw Error('independent genesis requires admitted non-Enclave machines');
  const at=machines.findIndex(m=>m.identity.toLowerCase()===identity.address.toLowerCase()),id=at+1,n=machines.length,t=Math.ceil(2*n/3);
  if(at<0||hx(hpke.publicKeyOf(encPrivateKey))!==machines[at].encKey.slice(2).toLowerCase())throw Error('genesis identity/key mismatch');
  const session=digest('enclave-custody independent DKG v1',chainId,vault.toLowerCase(),salt,machines.map(D.machineHash),codeSet);
  let st=store.load()||{session,phase:0};
  if(st.session!==session)throw Error('sealed DKG state belongs to another session');
  const save=async next=>{await store.save(next);st=next;};
  const sign=(kind,...args)=>D.signDigest(identity,digest(session,kind,...args));
  async function signed(kind,row,args) {
    const who=machines[row?.id-1];
    if(!who||await D.recoverDigest(digest(session,kind,...args),row.signature)!==who.identity.toLowerCase())throw Error('unauthenticated DKG message');
  }
  function ordered(rows,others=false){
    if(!Array.isArray(rows)||rows.length!==n-(others?1:0))throw Error('incomplete DKG participant set');
    const sorted=[...rows].sort((a,b)=>a.id-b.id);
    const expected=machines.map((_,i)=>i+1).filter(i=>!others||i!==id);
    if(sorted.some((r,i)=>r.id!==expected[i]))throw Error('duplicate or wrong DKG participant');
    return sorted;
  }
  async function roster(){if(await verifyRoster(plan)!==true)throw Error('genesis roster not verified');}
  async function start(){
    await roster();
    if(st.phase===0){const r=await invoke({phase:1,id,participants:n});bytes(r.round1);bytes(r.state,1048576);
      await save({...st,phase:1,state:r.state,round1:r.round1});}
    return {id,round1:st.round1,signature:await sign('round1',id,st.round1)};
  }
  async function agree(rows){
    if(st.phase<1)throw Error('start DKG first');
    rows=ordered(rows);
    for(const r of rows){bytes(r.round1);await signed('round1',r,[r.id,r.round1]);}
    if(rows[at].round1!==st.round1)throw Error('own DKG contribution replaced');
    const root=digest(session,'broadcast',rows.map(r=>[r.id,r.round1]));
    if(st.root&&st.root!==root)throw Error('DKG broadcast equivocation');
    if(!st.root){await save({...st,root,rows});}
    return {id,root,signature:await sign('broadcast',id,root)};
  }
  async function exchange(acks){
    if(!st.root)throw Error('agree on DKG broadcast first');
    for(const a of ordered(acks)){if(a.root!==st.root)throw Error('DKG broadcast disagreement');await signed('broadcast',a,[a.id,a.root]);}
    if(st.phase===1){
      const round1=Object.fromEntries(st.rows.filter(r=>r.id!==id).map(r=>[r.id,r.round1]));
      const r=await invoke({phase:2,id,participants:n,state:st.state,round1});
      const messages=[];
      for(let recipient=1;recipient<=n;recipient++)if(recipient!==id){
        const aad=Buffer.from(digest(session,'round2',st.root,id,recipient).slice(2),'hex');
        const sealed=hx(hpke.seal(hexToBytes(machines[recipient-1].encKey),info,aad,bytes(r.round2[recipient])));
        messages.push({id,recipient,root:st.root,sealed,signature:await sign('round2',id,recipient,st.root,sealed)});
      }
      bytes(r.state,1048576);await save({...st,phase:2,state:r.state,messages});
    }
    return st.messages;
  }
  async function finish(messages){
    await roster();
    if(st.phase===3)return completeResult();
    if(st.phase!==2)throw Error('exchange DKG messages first');
    const round2={};
    for(const m of ordered(messages,true)){
      if(m.recipient!==id||m.root!==st.root)throw Error('DKG recipient/transcript mismatch');
      bytes(m.sealed);await signed('round2',m,[m.id,m.recipient,m.root,m.sealed]);
      const aad=Buffer.from(digest(session,'round2',st.root,m.id,id).slice(2),'hex');
      round2[m.id]=hx(hpke.open(encPrivateKey,info,aad,bytes(m.sealed)));
    }
    const round1=Object.fromEntries(st.rows.filter(r=>r.id!==id).map(r=>[r.id,r.round1]));
    const r=await invoke({phase:3,id,participants:n,state:st.state,round1,round2});
    if(!Array.isArray(r.coefficients)||r.coefficients.length!==n)throw Error('wrong DKG commitment set');
    const vectors=r.coefficients.map(raw=>{const b=bytes(raw);if(b.length!==t*33)throw Error('wrong DKG threshold');return Array.from({length:t},(_,i)=>v2.pointOf(b.subarray(i*33,(i+1)*33)));});
    const commitments=Array.from({length:t},(_,j)=>v2.pointBytes(vectors.reduce((s,v)=>s.add(v[j]),secp256k1.ProjectivePoint.ZERO)));
    const share=v2.bytesToScalar(bytes(r.share));
    if(share===0n||hx(commitments[0])!==r.Y||hx(v2.pointBytes(v2.publicShare(id,commitments)))!==r.verifyingShare||
       hx(v2.pointBytes(secp256k1.ProjectivePoint.BASE.multiply(share)))!==r.verifyingShare)throw Error('DKG result binding mismatch');
    const packed=bytesToHex(Buffer.concat(commitments));
    const committeeId=D.committeeIdOf({chainId,vault,salt,Y:commitments[0]});
    // Persist the share before signing. On restart, return exactly this result;
    // do not regenerate a key or sign a different transcript under this salt.
    await save({session,phase:3,root:st.root,round1:st.round1,rows:st.rows,messages:st.messages,share:share.toString(16).padStart(64,'0'),committeeId,commitments:packed});
    return completeResult();
  }
  async function completeResult(){
    if(st.result)return st.result;
    const signature=await D.signDigest(identity,D.independentGenesisDigest({chainId,vault,committeeId:st.committeeId,commitments:st.commitments,machines,codeSet}));
    await save({...st,result:{id,committeeId:st.committeeId,commitments:st.commitments,signature}});return st.result;
  }
  // HTTP handlers can overlap. Serialize transitions through the sealed state.
  let tail=Promise.resolve();
  const serial=fn=>(...args)=>{const next=tail.then(()=>fn(...args));tail=next.catch(()=>{});return next;};
  return {session,start:serial(start),agree:serial(agree),exchange:serial(exchange),finish:serial(finish)};
}
