// Keep a Linux host's privacy-agent app list current, then SIGHUP the agent.
//
//   node reconcile-apps.mjs --config FILE --guestd-root DIR --contract-pins FILE [--names-file FILE] [--agent-unit UNIT] [--dry-run]
//
// For every public, active deployment leased to this runner it derives the expectation the agent pins:
// appRef and configCid from the lease, and appSha256/runtimeId/release/measurement from guestd's record of
// the attested guest it launched. A record is used only when its CID is the catalog CID of the lease's
// CURRENT version, so a guest from before an upgrade is never pinned. Without this an owner's version
// change leaves the agent refusing the new guest, and a privacy-routed app has no fallback route.
// A deployment not yet in the config is enrolled on the Enclave network (docs/design/enclave-network.md): its
// expectation, locally configured names (existing names are preserved) and
// publishes directly to configured directories. API mirroring is opt-in via
// mirrorNewApps: true. Its route is still decided by the owner's signed policy.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readReconciliationSnapshot,bundleComponentIdentity,validateReconciliationNames,reconciliationNames} from './reconcile-core.mjs';
const run=promisify(execFile);

const readJSON=async f=>JSON.parse(await fs.readFile(f,'utf8'));
const writeAtomic=async(f,text,mode=0o600)=>{const t=f+'.tmp-'+process.pid;await fs.writeFile(t,text,{mode});await fs.rename(t,f);};
export async function reconcileApps({configFile,guestdRoot,pinFile,namesFile,dryRun:DRY=false,agentUnit='enclave-network-agent.service',
  snapshotReader=readReconciliationSnapshot,reloadAgent=unit=>run('systemctl',['--user','reload',unit]),log=m=>console.log(`[reconcile] ${m}`)}) {
if(!configFile||!guestdRoot||!pinFile)throw new Error('usage: --config FILE --guestd-root DIR --contract-pins FILE [--names-file FILE] [--dry-run]');
const cfg=await readJSON(configFile);
if(!cfg.enclaveNetwork)throw new Error('the privacy agent config has no enclaveNetwork section: TUNA is retired, and apps are enrolled only on the Enclave network');
if(cfg.mirrorNewApps!==undefined&&typeof cfg.mirrorNewApps!=='boolean')throw Error('mirrorNewApps must be boolean');
if(cfg.mirrorNewApps===true&&!cfg.mirror)throw Error('mirrorNewApps requires an explicit mirror origin');
const runner=String(cfg.runner).toLowerCase(),appsDir=path.dirname(configFile);
const pinDocument=await readJSON(pinFile);
const configuredNames=namesFile?validateReconciliationNames(await readJSON(namesFile)):{};
const snapshot=await snapshotReader({chain:cfg.chain,runner,pinDocument});
const mine=snapshot.rows;
log(`pinned snapshot block ${snapshot.blockNumber} (${snapshot.hash})`);

// guestd's attested guests, newest first per deployment
const instances=new Map();
for(const d of await fs.readdir(guestdRoot)){
  if(!/^gd[0-9a-f]+$/.test(d))continue;
  let i;try{i=await readJSON(path.join(guestdRoot,d,'instance.json'));}catch{continue;}
  if(i.ID!==d||i.Verdict!=='attested'||!/^0x[0-9a-f]{64}$/.test(String(i.Name).toLowerCase()))continue;
  const k=String(i.Name).toLowerCase(),prev=instances.get(k);
  if(!Number.isFinite(Date.parse(i.Created)))continue;
  if(!prev||Date.parse(i.Created)>Date.parse(prev.Created))instances.set(k,i);
}

async function componentCid(inst){
  try{return bundleComponentIdentity(await fs.readFile(path.join(guestdRoot,inst.ID,'app.bundle'))).cid;}
  catch(e){log(`${inst.Name.slice(0,10)}: guest component refused: ${e.message}`);return null;}
}

let changed=false;
for(const row of mine){
  const id=String(row.id).toLowerCase(),inst=instances.get(id),appRef=String(row.appRef),m=appRef.match(/^catalog:\/\/(0x[0-9a-f]{64})\/(\d+)$/i);
  if(!m){log(`${id.slice(0,10)}: appRef ${appRef} is not a catalog reference; skipped`);continue;}
  if(!inst){log(`${id.slice(0,10)}: no attested guest yet; skipped`);continue;}
  const version=snapshot.versions[appRef];
  const guestCid=await componentCid(inst);
  if(!guestCid||String(version?.cid)!==guestCid){log(`${id.slice(0,10)}: the attested guest's component is not ${appRef}'s yet; waiting`);continue;}
  const expected={appRef,configCid:String(row.configCid),appSha256:inst.AppID,runtimeId:inst.RuntimeID,release:inst.Releases?.[0]??inst.Release,measurement:inst.Measurement};
  if(!/^[0-9a-f]{64}$/.test(expected.appSha256||'')||!/^[0-9a-f]{64}$/.test(expected.runtimeId||'')||!/^[0-9a-f]{64}$/.test(expected.release||'')||!/^[0-9a-f]{96}$/.test(expected.measurement||'')){log(`${id.slice(0,10)}: incomplete guest record; skipped`);continue;}
  const existing=cfg.apps.find(a=>a.deploymentId===id);
  if(existing){
    if(existing.internetMode!=='enclave-network'){existing.internetMode='enclave-network';changed=true;}
    // a TUNA-era entry's wallets are no longer used by anything
    if('walletsFile' in existing){delete existing.walletsFile;changed=true;}
    const cur=await readJSON(existing.expectedFile).catch(()=>null);
    if(JSON.stringify(cur)!==JSON.stringify(expected)){
      log(`${id.slice(0,10)}: expectation ${cur?.appRef?.split('/').pop()}->${appRef.split('/').pop()} app ${String(cur?.appSha256).slice(0,8)}->${expected.appSha256.slice(0,8)}`);
      if(!DRY){if(cur)await fs.copyFile(existing.expectedFile,existing.expectedFile+'.'+new Date().toISOString().replace(/[:.]/g,''));await writeAtomic(existing.expectedFile,JSON.stringify(expected,null,2));}
      changed=true;
    }
    {const names=reconciliationNames(id,existing,configuredNames);if(JSON.stringify(names)!==JSON.stringify(existing.names)){log(`${id.slice(0,10)}: names ${existing.names} -> ${names}`);existing.names=names;changed=true;}}
    continue;
  }
  // enrollment
  const names=reconciliationNames(id,null,configuredNames);
  const dir=path.join(appsDir,id);log(`${id.slice(0,10)}: enrolling (${names.join(', ')})`);
  changed=true;
  if(DRY)continue;
  await fs.mkdir(dir,{recursive:true,mode:0o700});
  await writeAtomic(path.join(dir,'expected.json'),JSON.stringify(expected,null,2));
  cfg.apps.push({deploymentId:id,names,expectedFile:path.join(dir,'expected.json'),internetMode:'enclave-network',publishToMirror:cfg.mirrorNewApps===true});
  changed=true;log(`${id.slice(0,10)}: enrolled on the Enclave network`);
}
if(changed&&!DRY){
  await writeAtomic(configFile,JSON.stringify(cfg,null,2));
  await reloadAgent(agentUnit);
  log('agent reloaded');
}
log(`${mine.length} leased apps checked; ${changed?(DRY?'changes proposed':'changes applied'):'no changes'}${DRY?' (dry run)':''}`);

return {checked:mine.length,changed,dryRun:DRY,blockNumber:snapshot.blockNumber,blockHash:snapshot.hash};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const arg=(k,d)=>{const i=process.argv.indexOf(k);return i>0?process.argv[i+1]:d;};
  await reconcileApps({configFile:arg('--config'),guestdRoot:arg('--guestd-root'),pinFile:arg('--contract-pins',process.env.ENCLAVE_CONTRACT_PINS_FILE),
    namesFile:arg('--names-file'),agentUnit:arg('--agent-unit','enclave-network-agent.service'),dryRun:process.argv.includes('--dry-run')});
}
