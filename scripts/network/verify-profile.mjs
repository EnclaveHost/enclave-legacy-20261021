#!/usr/bin/env node
// Read-only. `verify` checks a reviewed authority profile against agreeing Base RPCs for a digest the user supplies;
// `draft` re-derives a profile from explicit, previously verified inputs. Neither reads the mutable address book,
// signs, sends a transaction or changes any service.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {PROFILE_KIND,PROFILE_LAYOUT,MAX_PROFILE_BYTES,encodeProfile,profileDigest,parseProfile,validateProfile,contractPinsFromProfile,
  rpcClients,verifyProfileOnChain} from '../../network/authority-profile.mjs';
import {validateContractPins} from '../../network/contract-pins.mjs';
import {canonical} from '../../network/canonical.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');

export const SCOPE='New-path trust choice for owner-committed deployments on Base: the pinned session factory and authority, '+
  'SecretVaultV2 and EnclaveHostOwnership from the independent-authorities deployment, plus the existing host contract pins. '+
  'It is not evidence that production migrated, that governance is sealed, that an independent custody committee is active, '+
  'or that any service is independently operated. Base, its sequencer, USDC (Circle) and the chosen RPCs remain trusted. '+
  'Code hashes do not remove owner powers inside or behind the pinned contracts; see ownerPowers.';
const LEGACY_NOTE='Not part of the new path. Production network sessions use this factory; its vaults resolve deployments '+
  'through the mutable EnclaveAddressBook (book binding), and pinned-mode CLI refuses it. Pinned only to make the difference reviewable.';
// From contract source at the profile's source revision. Runtimes marked `observed` are not source-verified here.
export const OWNER_POWERS={
  registry:['No owner or admin in EnclaveRegistry source; register and registerRelay are permissionless.',
    'The deployed registry reports registrySchema 4 while source HEAD declares 5; its runtime is pinned by observed hash, not source-verified.'],
  deployments:['owner (two-step setOwner/acceptOwnership) can slashBond an operator bond (up to its amount) to payout, and sweepEscrow a lapsed, unfundable deployment\'s escrow to payout.',
    'owner can setClaimBond, setMaxGpuMilli, setMaxFee, setRunnerBps, setLeaseSec, setProofRequiredFrom and setEthUsdFeed (0 disables ETH funding); these future-create parameters are not pinned here.',
    'owner can setPayout and retire the ledger (one-way: closes claims, renewals and funding and opens refund to every record owner).',
    'One-shot owner bindings bandwidthRouter, feeRouter and prover are already set and pinned; importsSealed=true closes owner record imports.',
    'Runtime pinned by observed hash; owner powers are as written in contracts/EnclaveDeployments.sol, not proven for these bytes.'],
  appCatalog:['owner can setApproval and setVerified on any version, grantCid (bind any CID to an app id), transferApp (move a publisher lineage to another address) and setMaxFee.',
    'Versions the owner publishes start Approved; everyone else\'s start Pending. importsSealed=true closes owner imports.',
    'Runtime pinned by observed hash; powers per contracts/EnclaveAppCatalog.sol.'],
  proofOfTime:['owner can setProofWindow within [60 s, ledger leaseSec); two-step ownership transfer.','Runtime pinned by observed hash; powers per contracts/EnclaveProofOfTime.sol.'],
  enclavePay:['owner can setPayout (where USDC and ETH payments are forwarded); two-step ownership transfer.','Runtime pinned by observed hash; powers per contracts/EnclavePay.sol.'],
  verificationFees:['No owner, rescue or treasury function in source; fee wallets are controller-only per source deployment and payer.','Runtime pinned by observed hash.'],
  connectivity:['No global owner in source; per-app bootstrap trust and payment policy are set by that deployment\'s ledger owner.','Runtime pinned by observed hash.'],
  sessionVaultFactory:['No owner, setter, proxy or delegatecall; compiled-runtime verified. Acts on the deployments ledger and appCatalog, whose owner powers apply.'],
  pinnedSessionAuthority:['No owner or setter; addr() answers only deployments, appCatalog and sessionVaultFactory.'],
  sessionVaultImplementation:['No admin; the implementation is initialized to owner 0x…01. Each clone has only its own wallet owner and sessions. Calls the ledger, catalog, PaymentRouter and KeyAttestations, whose powers apply.'],
  sessionVaultLib:['Linked library; no state or owner.'],
  hostOwnership:['No global admin. Per host: the registry\'s active operator nominates the first owner, that wallet accepts, and only the current owner sets policy or nominates a successor.'],
  secretVaultV2:['No setter. The immutable enclaveOwner decides which hosts count as Enclave-owned seats (hosts whose hostOwnership owner equals it).'],
  usdc:['External: Circle-administered upgradeable proxy with pause and blacklist roles. Only the proxy bytes are pinned; the implementation can change without changing this hash.'],
  paymentRouter:['No owner, setter, pause, rescue or upgrade; every payment lands at the immutable treasury (per contracts/PaymentRouter.sol). Runtime pinned by observed hash.'],
  keyAttestations:['owner can setAttestor (removal voids that attestor\'s bindings) and revoke any key binding; two-step ownership. Measurement-bound session grants depend on it.',
    'Runtime pinned by observed hash; powers per contracts/EnclaveKeyAttestations.sol.'],
  legacySessionVaultFactory:[LEGACY_NOTE],
  legacySessionVaultImplementation:[LEGACY_NOTE,'Its immutable book is the mutable EnclaveAddressBook; whoever controls the book chooses which ledger these vaults act on.'],
};
// Profile name -> deployment-record contract name, for the compiled-runtime authorities.
const RECORD_NAMES={sessionVaultFactory:'PinnedSessionVaultFactory',pinnedSessionAuthority:'PinnedSessionAuthority',sessionVaultImplementation:'SessionVault',
  sessionVaultLib:'SessionVaultLib',hostOwnership:'EnclaveHostOwnership',secretVaultV2:'EnclaveSecretVaultV2'};
const BUILD='independent-authorities',RECORD='contracts/deployments/independent-authorities-base.json';
const addr=(v,what)=>{if(typeof v!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(v)||/^0x0{40}$/i.test(v))throw Error('invalid '+what);return v.toLowerCase();};
const sha256=b=>createHash('sha256').update(b).digest('hex');
async function readBounded(file,max){
  const h=await fs.open(file,'r');
  try{const b=Buffer.alloc(max+1);let n=0;for(;;){const {bytesRead}=await h.read(b,n,b.length-n,null);if(!bytesRead)break;n+=bytesRead;if(n>max)throw Error(file+' is too large');}return b.subarray(0,n);}
  finally{await h.close();}
}

// The skeleton a reviewer can re-derive: addresses only from the explicit inputs, never from chain discovery.
export function draftSkeleton({record,publicPins,connectivity,legacyFactory,legacyImplementation}){
  if(record?.chainId!==8453||!record.verified?.contracts||!record.inputs)throw Error('invalid independent-authorities record');
  const pins=validateContractPins(publicPins);
  for(const k of ['sessionVaultFactory','secretVaultV2'])if(!/^0x0{40}$/.test(pins[k])&&pins[k]!==addr(record.addresses[RECORD_NAMES[k]],k))
    throw Error('public pins name a different '+k+' than the verified record');
  const v=record.verified.contracts,i=record.inputs;
  if(addr(i.ledger,'ledger')!==pins.deployments||addr(i.catalog,'catalog')!==pins.appCatalog||addr(i.registry,'registry')!==pins.registry)
    throw Error('verified record inputs disagree with the public host pins');
  const addresses={registry:pins.registry,deployments:pins.deployments,appCatalog:pins.appCatalog,proofOfTime:pins.proofOfTime,
    enclavePay:addr(pins.enclavePay,'enclavePay'),verificationFees:addr(pins.verificationFees,'verificationFees'),connectivity:addr(connectivity,'connectivity'),
    usdc:addr(i.usdc,'usdc'),paymentRouter:addr(i.router,'router'),keyAttestations:addr(i.keyAttestations,'keyAttestations'),
    legacySessionVaultFactory:addr(legacyFactory,'legacy factory'),legacySessionVaultImplementation:addr(legacyImplementation,'legacy implementation')};
  for(const [name,recordName] of Object.entries(RECORD_NAMES)){
    const c=v[recordName];
    if(!c||addr(c.address,recordName)!==addr(record.addresses[recordName],recordName))throw Error('record verification is missing '+recordName);
    addresses[name]=c.address.toLowerCase();
  }
  return addresses;
}

// Fill observed values into the skeleton. Compiled-runtime contracts must match the record's previously verified
// hash and bindings exactly; an observed difference refuses instead of replacing the recorded value.
export function buildProfile({record,addresses,observation,review}){
  const contracts={};
  for(const [name,layout] of Object.entries(PROFILE_LAYOUT)){
    const got=observation.contracts[name];
    if(!got?.codeHash)throw Error(name+' has no deployed code');
    const entry={role:layout.role,address:addresses[name],codeHash:got.codeHash,runtimeBytes:got.runtimeBytes,
      codeProvenance:layout.artifact?'compiled-runtime':'observed',immutable:{},reviewedState:{},ownerPowers:OWNER_POWERS[name]};
    for(const section of ['immutable','reviewedState'])for(const getter of Object.keys(layout[section])){
      if(typeof got[section][getter]==='string'&&got[section][getter].startsWith('!'))throw Error(`${name}.${getter} did not answer (${got[section][getter]})`);
      entry[section][getter]=got[section][getter];
    }
    if(layout.artifact){
      const c=record.verified.contracts[RECORD_NAMES[name]];
      if(c.codeHash.toLowerCase()!==got.codeHash||c.runtimeBytes!==got.runtimeBytes)throw Error(name+' code differs from the verified compiled runtime');
      for(const [getter,want] of Object.entries(c.bindings||{})){
        const section=Object.hasOwn(layout.immutable,getter)?'immutable':'reviewedState';
        if(String(entry[section][getter]).toLowerCase()!==String(want).toLowerCase())throw Error(`${name}.${getter} differs from the verified record`);
      }
      Object.assign(entry,{artifact:layout.artifact,build:BUILD,codeHash:c.codeHash.toLowerCase()});
    }
    contracts[name]=entry;
  }
  return validateProfile({kind:PROFILE_KIND,version:1,chainId:8453,scope:SCOPE,review,
    builds:{[BUILD]:{compiler:record.compiler,sourceCommit:record.sourceCommit,sourceSha256:record.sourceSha256,record:RECORD}},contracts});
}

// Optional: rebuild the recorded sources and compare every compiled-runtime contract's live bytes with the compiler
// output (immutables masked, library address substituted), so the recorded hash is not taken on faith either.
export async function verifyCompiledRuntimes(profile,observation){
  const {compileIndependentAuthorities,verifyAuthorityRuntime}=await import('../independent-authorities.mjs');
  const build=profile.builds[BUILD];
  if(!build)throw Error('profile has no '+BUILD+' build');
  const artifacts=compileIndependentAuthorities();
  if(artifacts.compiler!==build.compiler)throw Error('local compiler '+artifacts.compiler+' differs from '+build.compiler);
  if(canonical(artifacts.sourceSha256)!==canonical(build.sourceSha256))throw Error('local contract sources differ from the profile build');
  const libraries={'SessionVault.sol:SessionVaultLib':profile.contracts.sessionVaultLib.address};
  const checked=[];
  for(const [name,c] of Object.entries(profile.contracts)){
    if(c.codeProvenance!=='compiled-runtime')continue;
    const code=observation.contracts[name]?.code;
    if(!code)throw Error(name+' runtime bytes were not captured');
    verifyAuthorityRuntime({artifact:artifacts.contracts[c.artifact],code,address:c.address,libraries});
    checked.push(name);
  }
  return checked;
}

function slimObservation(observation){
  return Object.fromEntries(Object.entries(observation.contracts).map(([n,c])=>[n,{codeHash:c.codeHash,runtimeBytes:c.runtimeBytes}]));
}

async function verify(values){
  if(!values.expect)throw Error('--expect sha256:<digest> is required: obtain the reviewed digest out of band; the profile file cannot vouch for itself');
  if(!values.profile)throw Error('--profile <file> is required');
  const {digest,profile}=parseProfile(await readBounded(values.profile,MAX_PROFILE_BYTES),{expectedDigest:values.expect});
  const pins=contractPinsFromProfile(profile);
  if(values['check-pins']){
    const supplied=validateContractPins(JSON.parse(await readBounded(values['check-pins'],16384)));
    if(canonical(supplied)!==canonical(Object.fromEntries(Object.entries(pins.contracts))))throw Error('contract pin document differs from the verified profile');
  }
  const maxBlockAgeMs=values['max-block-age-ms']?Number(values['max-block-age-ms']):90000;
  const result=await verifyProfileOnChain({profile,clients:rpcClients(values.rpc||[]),maxBlockAgeMs,includeCode:!!values.recompile});
  const recompiled=values.recompile?await verifyCompiledRuntimes(profile,result.observation):[];
  const report={status:'verified',kind:'enclave.authority-profile.verification',profile:path.relative(root,path.resolve(values.profile)),digest,
    chainId:profile.chainId,blockNumber:result.blockNumber,blockHash:result.blockHash,blockTimestamp:result.blockTimestamp,checkedAt:new Date().toISOString(),
    rpcHosts:values.rpc.map(u=>new URL(u).hostname),peerFailures:result.failures,recompiledRuntimes:recompiled,
    checkedPins:values['check-pins']?path.relative(root,path.resolve(values['check-pins'])):null,contractPins:pins,contracts:slimObservation(result.observation),
    meaning:'The pinned code hashes, immutable bindings and reviewed owner state matched at this block on two or more agreeing RPCs. '+
      'This is not evidence of production migration, governance seal, independent operation, or the absence of the documented owner powers.'};
  if(values['export-pins'])await fs.writeFile(values['export-pins'],JSON.stringify(pins,null,2)+'\n',{flag:'wx'});
  if(values.out)await fs.writeFile(values.out,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify({status:report.status,digest,blockNumber:report.blockNumber,blockHash:report.blockHash,recompiledRuntimes:recompiled,peerFailures:result.failures.length}));
}

async function draft(values){
  for(const k of ['record','public-pins','connectivity','legacy-factory','legacy-implementation','out'])if(!values[k])throw Error('draft requires --'+k);
  const recordBytes=await readBounded(values.record,262144),pinBytes=await readBounded(values['public-pins'],16384);
  const record=JSON.parse(recordBytes),publicPins=JSON.parse(pinBytes);
  const addresses=draftSkeleton({record,publicPins,connectivity:values.connectivity,legacyFactory:values['legacy-factory'],legacyImplementation:values['legacy-implementation']});
  // A provisional profile for reading only: the same addresses, any value types. The real one is built from the read.
  const {LeaseReader}=await import('../../network/lease-reader.mjs');
  const {profileRead}=await import('../../network/authority-profile.mjs');
  const zero='0x'+'0'.repeat(40);
  const reader=new LeaseReader({clients:rpcClients(values.rpc||[]),addressBook:zero,
    authorityPins:{deployments:addresses.deployments,registry:addresses.registry,connectivity:zero,sessionVaultFactory:zero}});
  const failures=[];
  const observation=await reader.agreed(profileRead({contracts:Object.fromEntries(Object.entries(addresses).map(([n,a])=>[n,{address:a}]))},{includeCode:!!values.recompile}),failures)
    .catch(e=>{throw Error(e.message+(failures.length?': '+failures.slice(0,8).join('; '):''));});
  const review={blockNumber:observation.blockNumber,blockHash:observation.hash,blockTimestamp:Math.floor(observation.timestamp/1000),
    capturedAt:new Date().toISOString().replace(/\.\d+Z$/,'Z'),rpcHosts:values.rpc.map(u=>new URL(u).hostname),
    inputs:{deploymentRecord:{description:RECORD+' (compiled-runtime verification of the independent authorities)',sha256:sha256(recordBytes)},
      publicHostPins:{description:'Public host contract-pins.json (registry, deployments, appCatalog, proofOfTime, enclavePay, verificationFees)',sha256:sha256(pinBytes)}}};
  const profile=buildProfile({record,addresses,observation,review});
  if(values.recompile)await verifyCompiledRuntimes(profile,observation);
  const bytes=encodeProfile(profile);
  await fs.writeFile(values.out,bytes,{flag:'wx'});
  console.log(JSON.stringify({status:'drafted-for-review',digest:profileDigest(bytes),blockNumber:review.blockNumber,peerFailures:failures.length}));
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const {positionals,values}=parseArgs({allowPositionals:true,options:{profile:{type:'string'},expect:{type:'string'},rpc:{type:'string',multiple:true},
    recompile:{type:'boolean'},'export-pins':{type:'string'},'check-pins':{type:'string'},out:{type:'string'},'max-block-age-ms':{type:'string'},
    record:{type:'string'},'public-pins':{type:'string'},connectivity:{type:'string'},'legacy-factory':{type:'string'},'legacy-implementation':{type:'string'}}});
  const mode=positionals[0]||'verify';
  if(positionals.length>1||!['verify','draft'].includes(mode))throw Error('usage: verify-profile.mjs [verify|draft] ...; see docs/network/authority-profile.md');
  await (mode==='draft'?draft(values):verify(values)).catch(e=>{console.error(String(e.message||e));process.exit(1);});
}
