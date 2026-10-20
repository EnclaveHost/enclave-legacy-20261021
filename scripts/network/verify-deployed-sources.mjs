#!/usr/bin/env node
// Read-only. Rebuild each deployed Base contract from an exact git commit with the pinned solc-js binary and compare
// the live runtime, read at one block from two or more agreeing RPCs, byte for byte. Only the compiler-declared
// immutable and library-link slots may differ from the compiler output, and their live values must equal the
// manifest. Metadata (CBOR) is compared too, so a match here is a full match, not a metadata-stripped one.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {keccak256} from 'viem';
import {LeaseReader} from '../../network/lease-reader.mjs';
import {rpcClients,parseProfile} from '../../network/authority-profile.mjs';

const run=promisify(execFile);
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
export const MANIFEST_KIND='enclave.deployed-source-verification';
const MAX_MANIFEST_BYTES=262144,MAX_SOURCE_BYTES=1<<20,MAX_RUNTIME_BYTES=24576;
const address=/^0x[0-9a-f]{40}$/,hash32=/^0x[0-9a-f]{64}$/,word=/^0x[0-9a-f]{64}$/,zero='0x'+'0'.repeat(40);
const plain=v=>!!v&&typeof v==='object'&&Object.getPrototypeOf(v)===Object.prototype;
function exactKeys(value,required,optional,what){
  if(!plain(value))throw Error(what+' must be an object');
  for(const k of Object.keys(value))if(!required.includes(k)&&!optional.includes(k))throw Error('unknown field: '+what+'.'+k);
  for(const k of required)if(!Object.hasOwn(value,k))throw Error('missing field: '+what+'.'+k);
}
const text=(v,max,what)=>{if(typeof v!=='string'||!v.length||v.length>max)throw Error('invalid '+what);return v;};

// ---- manifest ----
export function validateManifest(m){
  exactKeys(m,['kind','version','chainId','repository','compiler','review','builds','contracts','external'],[],'manifest');
  if(m.kind!==MANIFEST_KIND||m.version!==1||m.chainId!==8453)throw Error('unsupported source verification manifest');
  if(typeof m.repository!=='string'||!/^https:\/\/[a-z0-9.-]+\/[\w.-]+\/[\w.-]+\.git$/.test(m.repository))throw Error('invalid repository');
  exactKeys(m.compiler,['version','package','soljsonSha256'],[],'compiler');
  text(m.compiler.version,128,'compiler version');text(m.compiler.package,64,'compiler package');
  if(!/^[0-9a-f]{64}$/.test(m.compiler.soljsonSha256))throw Error('invalid compiler digest');
  exactKeys(m.review,['blockNumber','blockHash','rpcHosts'],[],'review');
  if(!/^[1-9][0-9]{0,15}$/.test(m.review.blockNumber)||!hash32.test(m.review.blockHash)||!Array.isArray(m.review.rpcHosts)||m.review.rpcHosts.length<2)throw Error('invalid review');
  if(!plain(m.builds)||!Object.keys(m.builds).length||Object.keys(m.builds).length>32)throw Error('invalid builds');
  for(const [id,b] of Object.entries(m.builds)){
    if(!/^[a-z][a-z0-9-]{0,63}$/.test(id))throw Error('invalid build id');
    exactKeys(b,['commit','sources','settings'],['note'],'builds.'+id);
    if(!/^[0-9a-f]{40}$/.test(b.commit))throw Error('invalid build commit: '+id);
    if(b.note!==undefined)text(b.note,600,'build note');
    if(!plain(b.sources)||!Object.keys(b.sources).length||Object.keys(b.sources).length>16)throw Error('invalid build sources: '+id);
    for(const [unit,s] of Object.entries(b.sources)){
      if(!/^[A-Za-z0-9_./-]{1,128}\.sol$/.test(unit)||unit.includes('..'))throw Error('invalid source unit: '+unit);
      exactKeys(s,['path','gitBlob','sha256'],[],'builds.'+id+'.sources.'+unit);
      if(!/^[A-Za-z0-9_./-]{1,200}\.sol$/.test(s.path)||s.path.includes('..')||!/^[0-9a-f]{40}$/.test(s.gitBlob)||!/^[0-9a-f]{64}$/.test(s.sha256))throw Error('invalid source pin: '+unit);
    }
    // Only settings that enter the metadata are allowed, and only in the shapes these builds used.
    exactKeys(b.settings,['optimizer'],['viaIR','evmVersion'],'builds.'+id+'.settings');
    exactKeys(b.settings.optimizer,['enabled','runs'],[],'builds.'+id+'.settings.optimizer');
    if(b.settings.optimizer.enabled!==true||!Number.isSafeInteger(b.settings.optimizer.runs)||b.settings.optimizer.runs<1||
      b.settings.viaIR!==undefined&&b.settings.viaIR!==true||b.settings.evmVersion!==undefined&&!/^[a-z]{3,16}$/.test(b.settings.evmVersion))throw Error('invalid settings: '+id);
  }
  if(!plain(m.contracts)||!Object.keys(m.contracts).length||Object.keys(m.contracts).length>32)throw Error('invalid contracts');
  const seen=new Set();
  for(const [name,c] of Object.entries(m.contracts)){
    if(!/^[a-zA-Z][a-zA-Z0-9]{0,63}$/.test(name))throw Error('invalid contract name');
    exactKeys(c,['address','kind','build','unit','contract','runtimeBytes','codeHash','metadataIpfs','immutables','links','profileName','basis'],[],'contracts.'+name);
    if(!address.test(c.address)||c.address===zero||seen.has(c.address))throw Error('invalid or duplicate address: '+name);seen.add(c.address);
    if(!['contract','library'].includes(c.kind))throw Error('invalid kind: '+name);
    if(!Object.hasOwn(m.builds,c.build)||!Object.hasOwn(m.builds[c.build].sources,c.unit))throw Error('unknown build or unit: '+name);
    if(!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(c.contract))throw Error('invalid contract identifier: '+name);
    if(!Number.isSafeInteger(c.runtimeBytes)||c.runtimeBytes<1||c.runtimeBytes>MAX_RUNTIME_BYTES||!hash32.test(c.codeHash)||!/^1220[0-9a-f]{64}$/.test(c.metadataIpfs))throw Error('invalid code pin: '+name);
    if(!plain(c.immutables)||Object.keys(c.immutables).length>32)throw Error('invalid immutables: '+name);
    for(const [k,v] of Object.entries(c.immutables))if(!/^([A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*|library_deploy_address|library_self_address)$/.test(k)||!word.test(v))throw Error('invalid immutable: '+name+'.'+k);
    if(!plain(c.links)||Object.keys(c.links).length>8)throw Error('invalid links: '+name);
    for(const [k,v] of Object.entries(c.links))if(!/^[A-Za-z0-9_./-]+\.sol:[A-Za-z_][A-Za-z0-9_]*$/.test(k)||!address.test(v))throw Error('invalid link: '+name+'.'+k);
    if(c.profileName!==null&&!/^[a-zA-Z][a-zA-Z0-9]{0,63}$/.test(c.profileName))throw Error('invalid profile name: '+name);
    text(c.basis,1200,'basis');
  }
  if(!plain(m.external)||Object.keys(m.external).length>8)throw Error('invalid external');
  for(const [name,e] of Object.entries(m.external)){
    exactKeys(e,['address','kind','codeHash','runtimeBytes','metadataSolc','slots','profileName','basis'],[],'external.'+name);
    if(!address.test(e.address)||seen.has(e.address)||e.kind!=='upgradeable-proxy'||!hash32.test(e.codeHash)||!Number.isSafeInteger(e.runtimeBytes)||e.runtimeBytes<1||
      !/^\d+\.\d+\.\d+$/.test(e.metadataSolc))throw Error('invalid external contract: '+name);
    seen.add(e.address);
    exactKeys(e.slots,['implementation','admin'],[],'external.'+name+'.slots');
    if(!word.test(e.slots.implementation)||!word.test(e.slots.admin))throw Error('invalid proxy slots: '+name);
    if(e.profileName!==null&&typeof e.profileName!=='string')throw Error('invalid profile name: '+name);
    text(e.basis,1200,'basis');
  }
  return m;
}

// ---- metadata ----
const varint=n=>{const o=[];while(n>=0x80){o.push((n&0x7f)|0x80);n>>>=7;}o.push(n);return Buffer.from(o);};
const field=(tag,b)=>Buffer.concat([Buffer.from([tag]),varint(b.length),b]);
// The CIDv0 multihash solc embeds: SHA-256 of the single-block UnixFS file node holding the metadata JSON.
export function ipfsMetadataHash(metadata){
  const d=Buffer.from(metadata,'utf8');
  if(d.length>262144)throw Error('metadata exceeds one IPFS chunk');
  const unixfs=Buffer.concat([Buffer.from([0x08,0x02]),d.length?field(0x12,d):Buffer.alloc(0),Buffer.from([0x18]),varint(d.length)]);
  return '1220'+createHash('sha256').update(field(0x0a,unixfs)).digest('hex');
}
// solc's trailer: CBOR {"ipfs": bytes(34), "solc": bytes(3)} then its 2-byte length. Anything else is reported, not parsed.
export function cborMetadata(hex){
  const b=Buffer.from(hex.replace(/^0x/,''),'hex');
  if(b.length<4)return null;
  const length=b.readUInt16BE(b.length-2);
  if(length+2>b.length)return null;
  const cbor=b.subarray(b.length-2-length,b.length-2),start=b.length-2-length;
  const m=cbor.toString('hex').match(/^a2646970667358221220([0-9a-f]{64})64736f6c6343([0-9a-f]{6})$/);
  return {start,length,raw:cbor.toString('hex'),ipfs:m?'1220'+m[1]:null,solc:m?[0,2,4].map(i=>parseInt(m[2].slice(i,i+2),16)).join('.'):null};
}

// ---- comparison ----
// compiled: {object, immutableReferences, linkReferences}, as solc's deployedBytecode, plus slotNames (AST id -> name).
export function compareRuntime({compiled,liveCode,address:self,kind,expectedImmutables,expectedLinks}){
  const live=String(liveCode||'').replace(/^0x/,'').toLowerCase();
  if(!live)return {status:'no-code'};
  if(!/^(?:[0-9a-f]{2})+$/.test(live)||live.length>2*MAX_RUNTIME_BYTES)return {status:'mismatch',reason:'malformed or oversized live code'};
  const object=compiled.object.toLowerCase();
  if(object.length!==live.length)return {status:'mismatch',reason:'runtime length differs',compiledBytes:object.length/2,liveBytes:live.length/2};
  const slots=[];
  for(const [id,refs] of Object.entries(compiled.immutableReferences||{})){
    const name=compiled.slotNames?.[id]??id;
    for(const {start,length} of refs)slots.push({kind:'immutable',name,start,length});
  }
  for(const [unit,libs] of Object.entries(compiled.linkReferences||{}))for(const [lib,refs] of Object.entries(libs))
    for(const {start,length} of refs)slots.push({kind:'link',name:unit+':'+lib,start,length});
  // Legacy-codegen libraries guard calls with PUSH20 <own address>, written at deployment in place of zeros.
  if(kind==='library'&&!Object.values(compiled.slotNames||{}).includes('library_deploy_address')&&!compiled.immutableReferences?.library_deploy_address&&
    object.startsWith('73'+'00'.repeat(20)))slots.push({kind:'immutable',name:'library_self_address',start:1,length:20});
  slots.sort((a,b)=>a.start-b.start);
  for(let i=0;i<slots.length;i++){
    const s=slots[i];
    if(!Number.isSafeInteger(s.start)||s.start<0||(s.start+s.length)*2>live.length||i&&slots[i-1].start+slots[i-1].length>s.start)return {status:'mismatch',reason:'invalid slot layout'};
    const placeholder=object.slice(s.start*2,(s.start+s.length)*2);
    if(s.kind==='immutable'?placeholder!=='00'.repeat(s.length):!/^__\$[0-9a-f]{34}\$__$/.test(placeholder))return {status:'mismatch',reason:'compiler slot is not a placeholder: '+s.name};
  }
  const values={},links={},problems=[];
  for(const s of slots){
    const v='0x'+live.slice(s.start*2,(s.start+s.length)*2);
    const bag=s.kind==='immutable'?values:links,shown=s.kind==='immutable'?'0x'+v.slice(2).padStart(64,'0'):v;
    if(Object.hasOwn(bag,s.name)&&bag[s.name]!==shown)problems.push('occurrences of '+s.name+' disagree');
    bag[s.name]=shown;
  }
  const want=(expected,got,what)=>{
    for(const k of new Set([...Object.keys(expected||{}),...Object.keys(got)]))
      if(expected?.[k]!==got[k])problems.push(`${what} ${k}: live ${got[k]??'absent'}, expected ${expected?.[k]??'undeclared'}`);
  };
  want(expectedImmutables,values,'immutable');want(expectedLinks,links,'link');
  if(Object.hasOwn(values,'library_deploy_address')||Object.hasOwn(values,'library_self_address')){
    const own='0x'+(values.library_deploy_address??values.library_self_address).slice(-40);
    if(own!==self)problems.push('library slot does not hold its own address');
  }
  let patched=object;
  for(const s of slots)patched=patched.slice(0,s.start*2)+live.slice(s.start*2,(s.start+s.length)*2)+patched.slice((s.start+s.length)*2);
  const meta=cborMetadata(live),compiledMeta=cborMetadata(patched);
  const result={immutables:values,links,slots:slots.length,metadata:{live:meta?.ipfs??null,compiled:compiledMeta?.ipfs??null,solc:meta?.solc??null}};
  if(patched!==live){
    let i=0;while(patched[i]===live[i])i++;
    const offset=Math.floor(i/2),metaStart=meta?meta.start:live.length/2;
    let differing=0;for(let j=0;j<live.length;j+=2)if(patched.slice(j,j+2)!==live.slice(j,j+2))differing++;
    const executableEqual=meta&&compiledMeta&&patched.slice(0,metaStart*2)===live.slice(0,metaStart*2);
    return {...result,status:'mismatch',reason:executableEqual?'executable bytes equal but metadata differs (partial match only)':'executable bytes differ',
      firstDifference:offset,differingBytes:differing,problems};
  }
  if(problems.length)return {...result,status:'mismatch',reason:'slot values differ from the manifest',problems};
  return {...result,status:'full-match'};
}

// ---- sources and compilation ----
export async function readBuildSources(build,gitDirs){
  const sources={};
  for(const [unit,s] of Object.entries(build.sources)){
    let content=null,errors=[];
    for(const dir of gitDirs){
      try{
        const blob=(await run('git',['--git-dir='+dir,'rev-parse','--verify',`${build.commit}:${s.path}`],{timeout:60000})).stdout.trim();
        if(blob!==s.gitBlob)throw Error(`commit ${build.commit.slice(0,10)} has blob ${blob} at ${s.path}, manifest says ${s.gitBlob}`);
        content=(await run('git',['--git-dir='+dir,'cat-file','blob',blob],{timeout:120000,maxBuffer:MAX_SOURCE_BYTES,encoding:'buffer'})).stdout;
        break;
      }catch(e){errors.push(String(e.message).split('\n')[0]);}
    }
    if(!content)throw Error('source unavailable: '+unit+' ('+errors.join('; ')+')');
    const sha=createHash('sha256').update(content).digest('hex');
    if(sha!==s.sha256)throw Error('source digest mismatch: '+unit);
    sources[unit]=content.toString('utf8');
  }
  return sources;
}
export function loadCompiler(manifest){
  const require=createRequire(path.join(root,'package.json'));
  const solc=require('solc'),soljson=require.resolve('solc/soljson.js');
  const digest=createHash('sha256').update(fs.readFileSync(soljson)).digest('hex');
  const pkg=JSON.parse(fs.readFileSync(path.join(path.dirname(require.resolve('solc/package.json')),'package.json'),'utf8'));
  if(solc.version()!==manifest.compiler.version)throw Error('compiler '+solc.version()+' is not '+manifest.compiler.version);
  if(digest!==manifest.compiler.soljsonSha256)throw Error('soljson.js digest '+digest+' differs from the manifest');
  if('solc@'+pkg.version!==manifest.compiler.package)throw Error('solc package '+pkg.version+' differs from the manifest');
  return solc;
}
function immutableNames(ast){
  const names={};
  const walk=(node,contract)=>{
    if(!node||typeof node!=='object')return;
    if(Array.isArray(node)){for(const n of node)walk(n,contract);return;}
    if(node.nodeType==='ContractDefinition')contract=node.name;
    if(node.nodeType==='VariableDeclaration'&&node.mutability==='immutable')names[String(node.id)]=contract+'.'+node.name;
    for(const v of Object.values(node))if(v&&typeof v==='object')walk(v,contract);
  };
  walk(ast);return names;
}
// One build, one solc job. No import callback: every unit is pinned in the manifest, so a missing one fails.
export function compileBuild(solc,build,sources,wanted){
  const outputSelection={'*':{'':['ast'],'*':[]}};
  for(const {unit,contract} of wanted)outputSelection[unit]={...(outputSelection[unit]||{'':['ast']}),[contract]:['metadata','evm.deployedBytecode.object','evm.deployedBytecode.immutableReferences','evm.deployedBytecode.linkReferences']};
  const input={language:'Solidity',sources:Object.fromEntries(Object.entries(sources).map(([u,content])=>[u,{content}])),settings:{...build.settings,outputSelection}};
  const out=JSON.parse(solc.compile(JSON.stringify(input),{import:p=>({error:'unpinned import: '+p})}));
  const errors=(out.errors||[]).filter(e=>e.severity==='error');
  if(errors.length)throw Error('compile failed: '+errors.map(e=>e.formattedMessage).join('\n').slice(0,2000));
  const slotNames={};for(const s of Object.values(out.sources||{}))Object.assign(slotNames,immutableNames(s.ast));
  const result={};
  for(const {unit,contract} of wanted){
    const c=out.contracts?.[unit]?.[contract];
    if(!c?.evm?.deployedBytecode?.object)throw Error('no runtime for '+unit+':'+contract);
    result[unit+':'+contract]={...c.evm.deployedBytecode,metadata:c.metadata,slotNames};
  }
  return result;
}

// ---- chain ----
export async function readLive(manifest,clients,{maxBlockAgeMs=90000,now=Date.now,minIntervalMs=100}={}){
  const reader=new LeaseReader({clients,chainId:manifest.chainId,addressBook:zero,maxBlockAgeMs,now,
    authorityPins:{deployments:zero.slice(0,-1)+'1',registry:zero.slice(0,-1)+'2',connectivity:zero,sessionVaultFactory:zero}});
  const failures=[];
  const targets=[...Object.entries(manifest.contracts),...Object.entries(manifest.external)];
  const snapshot=await reader.agreed(async(client,blockNumber)=>{
    const codes={},slots={};
    for(const [name,c] of targets){
      const code=await client.getCode({address:c.address,blockNumber});
      if(code&&code.length>2+2*MAX_RUNTIME_BYTES)throw Error('oversized code from RPC');
      codes[name]=code&&code!=='0x'?code.toLowerCase():null;
      await new Promise(r=>setTimeout(r,minIntervalMs));
    }
    for(const [name,e] of Object.entries(manifest.external)){
      slots[name]={};
      for(const k of ['implementation','admin']){slots[name][k]=String(await client.getStorageAt({address:e.address,slot:e.slots[k],blockNumber})).toLowerCase();await new Promise(r=>setTimeout(r,minIntervalMs));}
    }
    return {codes,slots};
  },failures).catch(e=>{throw Error(e.message+(failures.length?': '+failures.slice(0,6).join('; '):''));});
  return {...snapshot,failures};
}

export async function verifyDeployedSources({manifest,gitDirs,live,solc,profile=null}){
  validateManifest(manifest);
  const results={},byBuild={};
  for(const [name,c] of Object.entries(manifest.contracts))(byBuild[c.build]||=[]).push([name,c]);
  for(const [id,entries] of Object.entries(byBuild)){
    const build=manifest.builds[id];
    const sources=await readBuildSources(build,gitDirs);
    const compiled=compileBuild(solc,build,sources,entries.map(([,c])=>({unit:c.unit,contract:c.contract})));
    for(const [name,c] of entries){
      const k=compiled[c.unit+':'+c.contract],code=live.codes[name];
      const r=compareRuntime({compiled:k,liveCode:code,address:c.address,kind:c.kind,expectedImmutables:c.immutables,expectedLinks:c.links});
      const metadataIpfs=ipfsMetadataHash(k.metadata);
      const problems=[...(r.problems||[])];
      if(metadataIpfs!==c.metadataIpfs)problems.push('compiled metadata hash differs from the manifest');
      if(code&&(keccak256(code)!==c.codeHash||(code.length-2)/2!==c.runtimeBytes))problems.push('live code hash differs from the manifest');
      if(profile&&c.profileName){
        const pin=profile.contracts[c.profileName];
        if(pin?.address!==c.address)problems.push('authority profile pins a different contract address');
        if(pin?.codeHash!==c.codeHash)problems.push('authority profile pins a different code hash');
      }
      const status=r.status==='full-match'&&!problems.length?'full-match':r.status==='full-match'?'mismatch':r.status;
      results[name]={status,address:c.address,build:id,commit:build.commit,unit:c.unit,contract:c.contract,codeHash:code?keccak256(code):null,
        metadataIpfs,immutables:r.immutables??{},links:r.links??{},...(r.reason?{reason:r.reason}:{}),...(r.firstDifference!==undefined?{firstDifference:r.firstDifference,differingBytes:r.differingBytes}:{}),
        ...(problems.length?{problems}:{})};
    }
  }
  const external={};
  for(const [name,e] of Object.entries(manifest.external)){
    const code=live.codes[name],problems=[];
    if(!code)problems.push('no code');
    else if(keccak256(code)!==e.codeHash||(code.length-2)/2!==e.runtimeBytes)problems.push('proxy code hash differs from the manifest');
    if(code&&cborMetadata(code)?.solc!==e.metadataSolc)problems.push('proxy compiler differs from the manifest');
    if(profile&&e.profileName){
      const pin=profile.contracts[e.profileName];
      if(pin?.address!==e.address)problems.push('authority profile pins a different proxy address');
      if(pin?.codeHash!==e.codeHash)problems.push('authority profile pins a different proxy code hash');
    }
    const slot=v=>'0x'+String(v).replace(/^0x/,'').padStart(64,'0').slice(-40);
    // The proxy's own bytes are pinned. Its implementation and admin are observed values only: the admin can
    // replace the implementation at any time without changing the proxy code hash.
    external[name]={status:problems.length?'mismatch':'proxy-runtime-pinned-source-not-verified',address:e.address,codeHash:code?keccak256(code):null,
      observedImplementation:slot(live.slots[name].implementation),observedAdmin:slot(live.slots[name].admin),implementationPinned:false,...(problems.length?{problems}:{})};
  }
  const ok=Object.values(results).every(r=>r.status==='full-match')&&Object.values(external).every(r=>!r.problems);
  return {ok,results,external};
}

async function main(){
  const {values}=parseArgs({options:{manifest:{type:'string'},'git-dir':{type:'string',multiple:true},rpc:{type:'string',multiple:true},
    profile:{type:'string'},'profile-digest':{type:'string'},out:{type:'string'}}});
  if(!values.manifest)throw Error('usage: verify-deployed-sources.mjs --manifest FILE --git-dir <clone with history> --rpc URL --rpc URL [...] [--profile FILE --profile-digest sha256:…] [--out NEW_FILE]');
  const bytes=fs.readFileSync(values.manifest);if(bytes.length>MAX_MANIFEST_BYTES)throw Error('manifest too large');
  const manifest=validateManifest(JSON.parse(bytes));
  if(!values['git-dir']?.length)throw Error('--git-dir is required: a clone holding the manifest commits (a blobless clone of '+manifest.repository+' works)');
  let profile=null;
  if(values.profile){
    if(!values['profile-digest'])throw Error('--profile needs --profile-digest');
    profile=parseProfile(fs.readFileSync(values.profile),{expectedDigest:values['profile-digest']}).profile;
  }
  const solc=loadCompiler(manifest);
  const clients=rpcClients(values.rpc||[]);
  const live=await readLive(manifest,clients);
  const report=await verifyDeployedSources({manifest,gitDirs:values['git-dir'],live,solc,profile});
  const hwm=Number((fs.readFileSync('/proc/self/status','utf8').match(/VmHWM:\s+(\d+)/)||[])[1]||0);
  const out={kind:MANIFEST_KIND+'.result',status:report.ok?'verified':'refused',checkedAt:new Date().toISOString(),manifestSha256:createHash('sha256').update(bytes).digest('hex'),
    blockNumber:live.blockNumber,blockHash:live.hash,blockTimestamp:Math.floor(live.timestamp/1000),rpcHosts:values.rpc.map(u=>new URL(u).hostname),peerFailures:live.failures,
    compiler:manifest.compiler,peakRssMiB:Math.round(hwm/1024),profileChecked:!!profile,results:report.results,external:report.external};
  if(values.out)fs.writeFileSync(values.out,JSON.stringify(out,null,2)+'\n',{flag:'wx'});
  const summary=Object.fromEntries([...Object.entries(report.results),...Object.entries(report.external)].map(([k,r])=>[k,r.status]));
  console.log(JSON.stringify({status:out.status,blockNumber:out.blockNumber,blockHash:out.blockHash,summary},null,1));
  if(!report.ok)process.exitCode=1;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{console.error(String(e.message||e));process.exit(1);});
