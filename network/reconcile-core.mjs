// Host-local enrollment: fixed contract bindings, a fresh agreeing chain snapshot,
// and bytes from an already attested local guest. No control API or Kubo process.
import {LeaseReader} from './lease-reader.mjs';
import {validateContractPins} from './contract-pins.mjs';
import {validateAppNames} from './app-ingress.mjs';
import {artifactIdentity} from '../sdk/storage/unixfs.mjs';
import deploymentABI from '../contracts/EnclaveDeployments.abi.json' with {type:'json'};
import catalogABI from '../contracts/EnclaveAppCatalog.abi.json' with {type:'json'};
const zero='0x'+'0'.repeat(40);
const jsonValue=value=>JSON.parse(JSON.stringify(value,(_k,v)=>typeof v==='bigint'?v.toString():v));
export async function readReconciliationSnapshot({chain,runner,pinDocument,clients,now=Date.now}) {
  const pins=validateContractPins(pinDocument);
  if(!/^0x[0-9a-f]{64}$/.test(runner||''))throw Error('exact runner identity required');
  if(chain?.chainId!==undefined&&chain.chainId!==pinDocument.chainId)throw Error('reconciliation chain differs from contract pins');
  for(const key of ['deployments','registry','sessionVaultFactory'])
    if(chain?.authorityPins?.[key]!==undefined&&chain.authorityPins[key].toLowerCase()!==pins[key])throw Error('reconciliation pin conflicts with network authority: '+key);
  const reader=new LeaseReader({...chain,addressBook:chain?.addressBook||zero,chainId:pinDocument.chainId,clients,now,
    authorityPins:{deployments:pins.deployments,registry:pins.registry,connectivity:zero,sessionVaultFactory:pins.sessionVaultFactory}});
  return reader.agreed(async(client,blockNumber)=>{
    const read=(address,abi,functionName,args)=>client.readContract({address,abi,functionName,args,blockNumber});
    const total=Number(await read(pins.deployments,deploymentABI,'count'));
    if(!Number.isSafeInteger(total)||total<0||total>10000)throw Error('deployment enumeration limit exceeded');
    const rows=[],seen=new Set();
    for(let offset=0;offset<total;offset+=50){
      const page=await read(pins.deployments,deploymentABI,'getPage',[BigInt(offset),50n]);
      if(!Array.isArray(page)||page.length!==Math.min(50,total-offset))throw Error('incomplete deployment page');
      for(const row of page){
        const id=String(row.id).toLowerCase();
        if(!/^0x[0-9a-f]{64}$/.test(id)||seen.has(id))throw Error('invalid or duplicate deployment');
        seen.add(id);
        if(String(row.runner).toLowerCase()===runner&&row.active===true&&row.isPublic===true&&Number(row.leaseUntil)*1000>now())rows.push(row);
      }
    }
    if(rows.length>256)throw Error('host app limit exceeded');
    const versions={};
    for(const row of rows){
      const ref=String(row.appRef),m=ref.match(/^catalog:\/\/(0x[0-9a-f]{64})\/(\d+)$/i);
      if(m&&!Object.hasOwn(versions,ref))versions[ref]=await read(pins.appCatalog,catalogABI,'getVersion',[m[1],BigInt(m[2])]);
    }
    return {deployments:pins.deployments,catalog:pins.appCatalog,rows:jsonValue(rows),versions:jsonValue(versions)};
  });
}
export function bundleComponentIdentity(bundle) {
  const magic=Buffer.from('ENCLAVE-BUNDLE/1\n');
  if(!Buffer.isBuffer(bundle)||!bundle.subarray(0,magic.length).equals(magic))throw Error('invalid guest bundle');
  let offset=magic.length;
  const frame=()=>{if(offset+4>bundle.length)throw Error('truncated guest bundle');const n=bundle.readUInt32LE(offset);offset+=4;
    if(n>bundle.length-offset)throw Error('truncated guest bundle');const bytes=bundle.subarray(offset,offset+n);offset+=n;return bytes;};
  const manifest=JSON.parse(frame().toString('utf8')),component=frame();
  const identity=artifactIdentity(component);
  if(!/^[0-9a-f]{64}$/.test(manifest?.artifact?.sha256||'')||manifest.artifact.sha256!==identity.sha256)throw Error('guest component digest mismatch');
  return identity;
}
export function validateReconciliationNames(document) {
  if(!document||document.version!==1||!document.deployments||typeof document.deployments!=='object'||Array.isArray(document.deployments)||
    Object.keys(document).some(k=>!['version','deployments'].includes(k))||Object.keys(document.deployments).length>256)throw Error('invalid local names document');
  const names={};
  for(const [id,value] of Object.entries(document.deployments))names[id]=[...new Set(validateAppNames(id,value).map(n=>n.toLowerCase()))];
  return names;
}
export function reconciliationNames(id,existing,configured={}) {
  return [...validateAppNames(id,configured[id]??existing?.names??[id.slice(2,10)+'.app.enclave.host'])];
}
