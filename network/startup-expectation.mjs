import {bootstrapIntent,verifyPackage,fetchPackage,MAX_PACKAGE_BYTES} from '../sdk/bootstrap/package.mjs';
import {runtimeId,validateRuntimeIdentity} from '../isolation/contract/runtime.mjs';

// The ledger owner selects app bytes; the client selects trusted runtime code.
// No host record, catalog approval or control API supplies either expectation.
// This helper also supports inspecting inactive records. Admission must separately
// require a current active lease (NativeClient does so before calling it).
export async function startupExpectation(lease,{runtime,gateways,bytes,fetchImpl=fetch}={}){
  const fault=validateRuntimeIdentity(runtime);if(fault)throw Error('explicit trusted runtime policy required: '+fault);
  if(!lease||!/^0x[0-9a-f]{64}$/.test(lease.id||'')||!Number.isSafeInteger(lease.chainId)||lease.chainId<=0||
    !/^0x[0-9a-fA-F]{40}$/.test(lease.deployments||'')||!/^0x[0-9a-fA-F]{40}$/.test(lease.owner||'')||typeof lease.appRef!=='string')throw Error('chain deployment scope required');
  const intent=bootstrapIntent(lease.configCid);
  if(!intent)throw Error('owner-committed startup package required; no host expectation fallback');
  const scope={chainId:lease.chainId,ledger:lease.deployments,deployment:lease.id,owner:lease.owner,appRef:lease.appRef,runtimeId:runtimeId(runtime).toString('hex')};
  const pkg=bytes===undefined?await fetchPackage(intent,scope,{gateways,fetchImpl,allowHttpIPs:true}):verifyPackage(bytes,intent,scope);
  return {expected:{appRef:lease.appRef,configCid:lease.configCid,appSha256:pkg.manifest.appId,runtimeId:pkg.manifest.runtimeId},
    provenance:{source:'owner-committed-startup',chainId:lease.chainId,ledger:lease.deployments,owner:lease.owner,deploymentId:lease.id,sha256:pkg.sha256,cid:pkg.cid,secretsMode:pkg.manifest.secretsMode},bytes:pkg.bytes};
}

export function inlineStartupBytes(value){
  if(value===undefined)return undefined;
  if(typeof value!=='string'||value.length>4*Math.ceil(MAX_PACKAGE_BYTES/3)||!value.length||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))throw Error('invalid inline public startup package');
  const bytes=Buffer.from(value,'base64');if(bytes.length>MAX_PACKAGE_BYTES||bytes.toString('base64')!==value)throw Error('oversized or noncanonical inline startup package');return bytes;
}
