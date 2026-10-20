// A reviewed, hash-identified set of Base authorities for the owner-committed
// path. The user supplies the expected digest; nothing here asks the mutable
// address book, and a verification never rewrites a pin from what it observed.
import {createHash} from 'node:crypto';
import {createPublicClient,http,keccak256} from 'viem';
import {base} from 'viem/chains';
import {LeaseReader} from './lease-reader.mjs';
import {validateContractPins} from './contract-pins.mjs';

export const PROFILE_KIND='enclave.authority-profile';
export const MAX_PROFILE_BYTES=65536;
const MAX_RUNTIME_BYTES=24576,MAX_RPC_RESPONSE_BYTES=1<<20;
const A='address',B='bool',U='uint256',T3='address,address,address';
const owned={owner:A,pendingOwner:A};
// The v1 layout: every contract, its role and exactly which getters are pinned. `immutable` getters read code-embedded
// values (constructor immutables, constants); `reviewedState` getters read storage that was correct at review and must
// still be: a changed owner, payout or one-shot binding is a different trust decision and refuses until re-reviewed.
// Owner-tunable economic parameters (lease length, caps, bonds, fees) are deliberately not pinned.
export const PROFILE_LAYOUT=Object.freeze({
  registry:{role:'host-pin',immutable:{registrySchema:U},reviewedState:{}},
  deployments:{role:'host-pin',immutable:{usdc:A,registry:A,deploymentsSchema:U},
    reviewedState:{...owned,payout:A,ethUsdFeed:A,bandwidthRouter:A,feeRouter:A,prover:A,importsSealed:B,retired:B}},
  appCatalog:{role:'host-pin',immutable:{},reviewedState:{...owned,importsSealed:B}},
  proofOfTime:{role:'host-pin',immutable:{deployments:A,registry:A},reviewedState:owned},
  enclavePay:{role:'host-pin',immutable:{usdc:A},reviewedState:{...owned,payout:A}},
  verificationFees:{role:'host-pin',immutable:{ledger:A,proof:A,token:A},reviewedState:{}},
  connectivity:{role:'network',immutable:{ledger:A,registry:A},reviewedState:{}},
  sessionVaultFactory:{role:'new-path',artifact:'PinnedSessionVaultFactory',immutable:{implementation:A,authorityPins:T3},reviewedState:{}},
  pinnedSessionAuthority:{role:'new-path',artifact:'PinnedSessionAuthority',immutable:{deployments:A,appCatalog:A,sessionVaultFactory:A},reviewedState:{}},
  sessionVaultImplementation:{role:'new-path',artifact:'SessionVault',immutable:{usdc:A,book:A,router:A,keyAttestations:A,maxVault6:U,factory:A},reviewedState:{owner:A}},
  sessionVaultLib:{role:'new-path',artifact:'SessionVaultLib',immutable:{},reviewedState:{}},
  hostOwnership:{role:'new-path',artifact:'EnclaveHostOwnership',immutable:{registry:A},reviewedState:{}},
  secretVaultV2:{role:'new-path',artifact:'EnclaveSecretVaultV2',
    immutable:{book:A,enclaveOwner:A,hostOwnership:A,hostRegistry:A,deploymentLedger:A,sessionVaultFactory:A},reviewedState:{}},
  usdc:{role:'external',immutable:{},reviewedState:{}},
  paymentRouter:{role:'dependency',immutable:{usdc:A,treasury:A},reviewedState:{}},
  keyAttestations:{role:'dependency',immutable:{},reviewedState:owned},
  legacySessionVaultFactory:{role:'legacy-compatibility',immutable:{implementation:A},reviewedState:{}},
  legacySessionVaultImplementation:{role:'legacy-compatibility',immutable:{usdc:A,book:A,router:A,keyAttestations:A,factory:A},reviewedState:{owner:A}},
});
// Bindings that must name another profile contract, checked on the document and again on chain.
const LINKS=[
  ['deployments','immutable','usdc','usdc'],['deployments','immutable','registry','registry'],
  ['deployments','reviewedState','bandwidthRouter','connectivity'],['deployments','reviewedState','feeRouter','verificationFees'],
  ['deployments','reviewedState','prover','proofOfTime'],
  ['proofOfTime','immutable','deployments','deployments'],['proofOfTime','immutable','registry','registry'],
  ['enclavePay','immutable','usdc','usdc'],
  ['verificationFees','immutable','ledger','deployments'],['verificationFees','immutable','proof','proofOfTime'],['verificationFees','immutable','token','usdc'],
  ['connectivity','immutable','ledger','deployments'],['connectivity','immutable','registry','registry'],
  ['sessionVaultFactory','immutable','implementation','sessionVaultImplementation'],
  ['sessionVaultFactory','immutable','authorityPins',['deployments','appCatalog','pinnedSessionAuthority']],
  ['pinnedSessionAuthority','immutable','deployments','deployments'],['pinnedSessionAuthority','immutable','appCatalog','appCatalog'],
  ['pinnedSessionAuthority','immutable','sessionVaultFactory','sessionVaultFactory'],
  ['sessionVaultImplementation','immutable','usdc','usdc'],['sessionVaultImplementation','immutable','book','pinnedSessionAuthority'],
  ['sessionVaultImplementation','immutable','router','paymentRouter'],['sessionVaultImplementation','immutable','keyAttestations','keyAttestations'],
  ['sessionVaultImplementation','immutable','factory','sessionVaultFactory'],
  ['hostOwnership','immutable','registry','registry'],
  ['secretVaultV2','immutable','book','pinnedSessionAuthority'],['secretVaultV2','immutable','hostOwnership','hostOwnership'],
  ['secretVaultV2','immutable','hostRegistry','registry'],['secretVaultV2','immutable','deploymentLedger','deployments'],
  ['secretVaultV2','immutable','sessionVaultFactory','sessionVaultFactory'],
  ['paymentRouter','immutable','usdc','usdc'],
  ['legacySessionVaultFactory','immutable','implementation','legacySessionVaultImplementation'],
  ['legacySessionVaultImplementation','immutable','factory','legacySessionVaultFactory'],
  ['legacySessionVaultImplementation','immutable','usdc','usdc'],['legacySessionVaultImplementation','immutable','router','paymentRouter'],
  ['legacySessionVaultImplementation','immutable','keyAttestations','keyAttestations'],
];
// The strict contract pin document hosts and the CLI already consume (network/contract-pins.mjs).
export const CONTRACT_PIN_KEYS=Object.freeze(['registry','deployments','appCatalog','proofOfTime','enclavePay','verificationFees','sessionVaultFactory','secretVaultV2']);

const plain=v=>!!v&&typeof v==='object'&&Object.getPrototypeOf(v)===Object.prototype;
const address=/^0x[0-9a-f]{40}$/,hash32=/^0x[0-9a-f]{64}$/,zero='0x'+'0'.repeat(40);
function exactKeys(value,required,optional,what){
  if(!plain(value))throw Error(what+' must be an object');
  for(const k of Object.keys(value))if(!required.includes(k)&&!optional.includes(k))throw Error('unknown field: '+what+'.'+k);
  for(const k of required)if(!Object.hasOwn(value,k))throw Error('missing field: '+what+'.'+k);
}
const text=(v,max,what)=>{if(typeof v!=='string'||!v.length||v.length>max||/[\u0000-\u001f\u007f]/.test(v))throw Error('invalid '+what);return v;};

// Sorted keys, two-space indentation, one trailing newline. The digest is SHA-256 of exactly these bytes, so
// `sha256sum` reproduces it and a duplicate key, reordering or reformatting cannot hide behind the same digest.
export function encodeProfile(value){
  const sort=v=>{
    if(v===null||typeof v==='boolean'||typeof v==='string')return v;
    if(typeof v==='number'){if(!Number.isSafeInteger(v))throw Error('profile numbers must be safe integers');return v;}
    if(Array.isArray(v))return v.map(sort);
    if(plain(v))return Object.fromEntries(Object.keys(v).sort().map(k=>[k,sort(v[k])]));
    throw Error('profile must contain only JSON values');
  };
  return Buffer.from(JSON.stringify(sort(value),null,2)+'\n','utf8');
}
export function profileDigest(bytes){return 'sha256:'+createHash('sha256').update(bytes).digest('hex');}

function checkValue(type,value,what){
  if(type===A){if(typeof value!=='string'||!address.test(value))throw Error('invalid address binding: '+what);return;}
  if(type===B){if(typeof value!=='boolean')throw Error('invalid boolean binding: '+what);return;}
  if(type===U){if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,77})$/.test(value))throw Error('invalid integer binding: '+what);return;}
  if(type===T3){if(!Array.isArray(value)||value.length!==3||value.some(v=>typeof v!=='string'||!address.test(v)))throw Error('invalid tuple binding: '+what);return;}
  throw Error('unsupported binding type');
}

export function validateProfile(profile){
  exactKeys(profile,['kind','version','chainId','scope','review','builds','contracts'],[],'profile');
  if(profile.kind!==PROFILE_KIND||profile.version!==1)throw Error('unsupported authority profile');
  if(profile.chainId!==8453)throw Error('authority profile is not for Base mainnet');
  text(profile.scope,2048,'scope');
  exactKeys(profile.review,['blockNumber','blockHash','blockTimestamp','capturedAt','rpcHosts','inputs'],[],'review');
  const r=profile.review;
  if(!/^[1-9][0-9]{0,15}$/.test(r.blockNumber)||!hash32.test(r.blockHash)||!Number.isSafeInteger(r.blockTimestamp)||r.blockTimestamp<=0||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z$/.test(r.capturedAt))throw Error('invalid review snapshot');
  if(!Array.isArray(r.rpcHosts)||r.rpcHosts.length<2||r.rpcHosts.length>8||new Set(r.rpcHosts).size!==r.rpcHosts.length||
    r.rpcHosts.some(h=>typeof h!=='string'||!/^[a-z0-9.-]{1,253}$/.test(h)))throw Error('invalid review RPC hosts');
  if(!plain(r.inputs)||Object.keys(r.inputs).length<1||Object.keys(r.inputs).length>8)throw Error('invalid review inputs');
  for(const [k,v] of Object.entries(r.inputs)){
    if(!/^[a-zA-Z][a-zA-Z0-9]{0,63}$/.test(k))throw Error('invalid review input name');
    exactKeys(v,['description','sha256'],[],'review.inputs.'+k);text(v.description,512,'input description');
    if(!/^[0-9a-f]{64}$/.test(v.sha256))throw Error('invalid input digest');
  }
  if(!plain(profile.builds)||Object.keys(profile.builds).length>4)throw Error('invalid builds');
  for(const [name,b] of Object.entries(profile.builds)){
    if(!/^[a-z][a-z0-9-]{0,63}$/.test(name))throw Error('invalid build name');
    exactKeys(b,['compiler','sourceCommit','sourceSha256','record'],[],'builds.'+name);
    text(b.compiler,128,'compiler');text(b.record,256,'build record');
    if(!/^[0-9a-f]{40}$/.test(b.sourceCommit))throw Error('invalid build commit');
    if(!plain(b.sourceSha256)||!Object.keys(b.sourceSha256).length||Object.keys(b.sourceSha256).length>16||
      Object.entries(b.sourceSha256).some(([f,h])=>!/^[A-Za-z0-9]{1,64}\.sol$/.test(f)||!/^[0-9a-f]{64}$/.test(h)))throw Error('invalid build sources');
  }
  const names=Object.keys(PROFILE_LAYOUT);
  exactKeys(profile.contracts,names,[],'contracts');
  const seen=new Map();
  for(const name of names){
    const c=profile.contracts[name],layout=PROFILE_LAYOUT[name],what='contracts.'+name;
    const compiled=!!layout.artifact;
    exactKeys(c,['role','address','codeHash','runtimeBytes','codeProvenance','immutable','reviewedState','ownerPowers'],compiled?['artifact','build']:[],what);
    if(c.role!==layout.role)throw Error('wrong role: '+name);
    if(!address.test(c.address)||c.address===zero)throw Error('invalid address: '+name);
    if(seen.has(c.address))throw Error('duplicate contract address: '+name+' and '+seen.get(c.address));
    seen.set(c.address,name);
    if(!hash32.test(c.codeHash)||!Number.isSafeInteger(c.runtimeBytes)||c.runtimeBytes<1||c.runtimeBytes>MAX_RUNTIME_BYTES)throw Error('invalid code pin: '+name);
    // Compiled-runtime pins name the build whose recorded runtime hash they repeat; observed pins say only that two
    // agreeing RPCs served these bytes at review, not that they derive from any reviewed source.
    if(c.codeProvenance!==(compiled?'compiled-runtime':'observed'))throw Error('wrong code provenance: '+name);
    if(compiled&&(c.artifact!==layout.artifact||typeof c.build!=='string'||!Object.hasOwn(profile.builds,c.build)))throw Error('wrong build reference: '+name);
    for(const section of ['immutable','reviewedState']){
      exactKeys(c[section],Object.keys(layout[section]),[],what+'.'+section);
      for(const [getter,type] of Object.entries(layout[section]))checkValue(type,c[section][getter],name+'.'+getter);
    }
    if(!Array.isArray(c.ownerPowers)||c.ownerPowers.length<1||c.ownerPowers.length>16)throw Error('invalid owner powers: '+name);
    c.ownerPowers.forEach(p=>text(p,400,'owner power'));
  }
  for(const [from,section,getter,to] of LINKS){
    const got=profile.contracts[from][section][getter];
    const want=Array.isArray(to)?to.map(n=>profile.contracts[n].address):profile.contracts[to].address;
    if(JSON.stringify(got)!==JSON.stringify(want))throw Error(`inconsistent binding: ${from}.${getter} must name ${[to].flat().join(',')}`);
  }
  return profile;
}

// Bytes in, validated profile out, but only for the digest the caller already holds. A profile never vouches for itself.
export function parseProfile(bytes,{expectedDigest}={}){
  if(typeof expectedDigest!=='string'||!/^sha256:[0-9a-f]{64}$/.test(expectedDigest))throw Error('an expected profile digest (sha256:<64 hex>) is required');
  if(!(bytes instanceof Uint8Array))throw Error('profile bytes required');
  if(bytes.length>MAX_PROFILE_BYTES)throw Error('authority profile too large');
  const digest=profileDigest(bytes);
  if(digest!==expectedDigest)throw Error('authority profile digest mismatch: got '+digest);
  let value;
  try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw Error('malformed authority profile');}
  if(!Buffer.from(bytes).equals(encodeProfile(value)))throw Error('authority profile is not canonically encoded');
  return {digest,profile:validateProfile(value)};
}

export function contractPinsFromProfile(profile){
  const document={version:1,chainId:profile.chainId,contracts:Object.fromEntries(CONTRACT_PIN_KEYS.map(k=>[k,profile.contracts[k].address]))};
  validateContractPins(document);
  return document;
}

// ---- chain reads ----

// One JSON-RPC origin with a bounded response, no redirects and a deadline.
export function boundedFetch({maxBytes=MAX_RPC_RESPONSE_BYTES,timeoutMs=15000,fetch:inner=globalThis.fetch}={}){
  return async(url,init={})=>{
    const response=await inner(url,{...init,redirect:'error',signal:AbortSignal.timeout(timeoutMs)});
    const length=Number(response.headers.get('content-length'));
    if(Number.isFinite(length)&&length>maxBytes)throw Error('RPC response too large');
    const chunks=[];let size=0;
    if(response.body)for await(const chunk of response.body){
      size+=chunk.length;if(size>maxBytes)throw Error('RPC response too large');chunks.push(chunk);
    }
    return new Response(Buffer.concat(chunks),{status:response.status,statusText:response.statusText,headers:response.headers});
  };
}
export function rpcClients(rpc,{fetchFn=boundedFetch()}={}){
  if(!Array.isArray(rpc)||rpc.length<2||rpc.length>8)throw Error('two to eight independent HTTPS RPC origins required');
  const urls=rpc.map(s=>new URL(s));
  if(urls.some(u=>u.protocol!=='https:'||u.username||u.password)||new Set(urls.map(u=>u.hostname)).size!==urls.length)
    throw Error('RPC origins must be distinct HTTPS hosts without credentials');
  return rpc.map(url=>createPublicClient({chain:base,transport:http(url,{timeout:15000,retryCount:2,retryDelay:600,fetchFn})}));
}

function reverted(e){for(let x=e,i=0;x&&i<8;x=x.cause,i++)if(['ContractFunctionRevertedError','ContractFunctionZeroDataError'].includes(x.name))return true;return false;}
const abiFor=(getter,type)=>[{type:'function',name:getter,stateMutability:'view',inputs:[],outputs:type.split(',').map(t=>({type:t}))}];
function normalize(type,value){
  if(type===A)return String(value).toLowerCase();
  if(type===B)return value===true?true:value===false?false:'!invalid';
  if(type===U)return typeof value==='bigint'?value.toString():'!invalid';
  return Array.isArray(value)?value.map(v=>String(v).toLowerCase()):'!invalid';
}
// Everything the profile pins, read by one peer at one block. Facts (empty code, a reverting getter) are returned so
// two peers can agree on them; transport errors and oversized code fail this peer only. Reads are paced per peer:
// public RPCs meter each request, and about 75 of them make one snapshot.
export function profileRead(profile,{includeCode=false,concurrency=3,minIntervalMs=80}={}){
  return async(client,blockNumber)=>{
    let next=0;
    const paced=async read=>{const wait=next-Date.now();next=Math.max(next,Date.now())+minIntervalMs;if(wait>0)await new Promise(r=>setTimeout(r,wait));return read();};
    const tasks=[],contracts={};
    for(const [name,layout] of Object.entries(PROFILE_LAYOUT)){
      const target=profile.contracts[name].address,row=contracts[name]={codeHash:null,runtimeBytes:0,immutable:{},reviewedState:{}};
      tasks.push(async()=>{
        const code=await paced(()=>client.getCode({address:target,blockNumber}));
        if(code!==undefined&&code!==null&&(typeof code!=='string'||!/^0x(?:[0-9a-fA-F]{2})*$/.test(code)))throw Error('malformed code from RPC');
        if(code&&code.length>2+2*MAX_RUNTIME_BYTES)throw Error('oversized code from RPC');
        if(code&&code!=='0x'){row.codeHash=keccak256(code);row.runtimeBytes=(code.length-2)/2;if(includeCode)row.code=code.toLowerCase();}
      });
      for(const section of ['immutable','reviewedState'])for(const [getter,type] of Object.entries(layout[section]))tasks.push(async()=>{
        try{row[section][getter]=normalize(type,await paced(()=>client.readContract({address:target,abi:abiFor(getter,type),functionName:getter,blockNumber})));}
        catch(e){if(!reverted(e))throw e;row[section][getter]='!reverted';}
      });
    }
    let index=0;
    await Promise.all(Array.from({length:Math.max(1,Math.min(concurrency,8))},async()=>{while(index<tasks.length)await tasks[index++]();}));
    return {contracts};
  };
}

// Compare an agreed snapshot with the profile. Every difference is a refusal; nothing observed is adopted.
export function checkObservation(profile,observation){
  const problems=[];
  for(const [name,layout] of Object.entries(PROFILE_LAYOUT)){
    const want=profile.contracts[name],got=observation.contracts?.[name];
    if(!got){problems.push(name+': not observed');continue;}
    if(!got.codeHash){problems.push(name+': no deployed code at '+want.address);continue;}
    if(got.codeHash!==want.codeHash||got.runtimeBytes!==want.runtimeBytes)problems.push(name+': code hash mismatch ('+got.codeHash+')');
    for(const getter of Object.keys(layout.immutable))
      if(JSON.stringify(got.immutable[getter])!==JSON.stringify(want.immutable[getter]))problems.push(`${name}.${getter}: binding mismatch (${JSON.stringify(got.immutable[getter])})`);
    for(const getter of Object.keys(layout.reviewedState))
      if(JSON.stringify(got.reviewedState[getter])!==JSON.stringify(want.reviewedState[getter]))problems.push(`${name}.${getter}: reviewed mutable state changed (${JSON.stringify(got.reviewedState[getter])})`);
  }
  if(problems.length)throw Object.assign(Error('authority profile refused: '+problems.join('; ')),{problems});
}

// Two or more peers must agree on every pinned fact at the same recent block (LeaseReader.agreed: same chain id,
// confirmed, fresh, unchanged block hash), and the agreed facts must equal the reviewed profile.
export async function verifyProfileOnChain({profile,clients,maxBlockAgeMs=90000,confirmations=2,now=Date.now,includeCode=false,pacing}){
  validateProfile(profile);
  if(!Array.isArray(clients)||clients.length<2||clients.length>8)throw Error('two to eight RPC clients required');
  // The reader's book is unused: agreed() reads only what profileRead asks for, and these pins make any book read throw.
  const reader=new LeaseReader({clients,chainId:profile.chainId,addressBook:zero,maxBlockAgeMs,confirmations,now,
    authorityPins:{deployments:profile.contracts.deployments.address,registry:profile.contracts.registry.address,connectivity:zero,sessionVaultFactory:zero}});
  const failures=[];
  let observation;
  try{observation=await reader.agreed(profileRead(profile,{includeCode,...pacing}),failures);}
  catch(e){throw Object.assign(Error(e.message+(failures.length?': '+failures.slice(0,8).join('; '):'')),{failures});}
  checkObservation(profile,observation);
  return {blockNumber:observation.blockNumber,blockHash:observation.hash,blockTimestamp:Math.floor(observation.timestamp/1000),
    failures,observation};
}
