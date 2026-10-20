import * as D from './digests.mjs';
const lc=value=>String(value).toLowerCase();
// The private operator key is used only after the guest's requested machine
// record matches this host's configured registry and endpoint. The reader uses
// the vault's immutable registry/ownership bindings, never the address book.
export async function prepareHostBinding({chain,operator,chainId,vault,registryId,registryEndpoint,endpoint,info}) {
  const m=info?.machine;
  if(info?.v!==2||!m||lc(m.registryId)!==lc(registryId)||m.endpoint!==endpoint||
     lc(m.identity)!==lc(info.identity)||lc(m.encKey)!==lc(info.encKey))throw Error('guest machine differs from configured host binding');
  const {entry}=await chain.readRegistryEntry({registryId});
  if(!entry?.active||entry.endpoint!==registryEndpoint||lc(entry.operator)!==lc(operator.address)||
     !/^0x[0-9a-f]{40}$/.test(lc(entry.owner))||/^0x0{40}$/i.test(entry.owner))
    throw Error('host operator or accepted owner is not authorized');
  const digest=D.hostDigest({chainId,vault:lc(vault),machine:m});
  if(info.hostSig&&await D.recoverDigest(digest,info.hostSig)===lc(operator.address))return {signature:info.hostSig,alreadyBound:true};
  return {signature:await D.signDigest(operator,digest),alreadyBound:false};
}
