// Provider discovery precedes control circuits. Its chain reads need an explicit
// bootstrap path; app admission always uses the final (control-proxied) reader.
import {LeaseReader} from './lease-reader.mjs';
import {guardedFetch} from './guarded-fetch.mjs';
import {socksProxyAddress} from './socks-connect.mjs';

export function createProviderBootstrap({chain,network,Reader=LeaseReader,fetch=globalThis.fetch}){
 const b=network.bootstrap;
 if(network.controlRequired===true&&network.control!==true)throw Error('controlRequired needs control enabled');
 if(b===undefined&&network.control===true)return null;
 const config=b===undefined?{mode:'direct'}:b;
 if(!config||typeof config!=='object'||Array.isArray(config)||!['direct','proxy'].includes(config.mode))throw Error('network bootstrap mode must be direct or proxy');
 if(Object.keys(config).some(k=>!['mode',...(config.mode==='proxy'?['proxies']:[])].includes(k)))throw Error('unknown network bootstrap setting');
 let proxy;
 if(config.mode==='direct'){
  if(network.controlRequired===true)throw Error('direct bootstrap conflicts with controlRequired');
 }else{
  if(!Array.isArray(config.proxies)||config.proxies.length<1||config.proxies.length>2)throw Error('bootstrap requires 1..2 SOCKS proxies');
  for(const p of config.proxies)socksProxyAddress(p);
  const entries=[...config.proxies];proxy=async()=>[...entries];
 }
 return {reader:new Reader({...chain,proxy}),
  fetch:proxy?guardedFetch(proxy,{timeoutMs:15000,maxBytes:4194304,publicRecords:true}):fetch};
}

// Only provider registration uses bootstrap. Policy signatures and app leases
// cannot borrow this path when the required live control transport is down.
export function providerRegistryReader({bootstrap,liveReader,control,controlEnabled}){
 const reader=async()=>{
  if(!controlEnabled)return liveReader;
  const transport=control();
  try{if(transport){await transport.proxies();return liveReader;}}catch{}
  if(bootstrap)return bootstrap.reader;
  throw Error('registered provider discovery needs explicit enclaveNetwork.bootstrap before control circuits are available');
 };
 return {
  registryEntries:async(...a)=>(await reader()).registryEntries(...a),
  bookAddress:async(...a)=>(await reader()).bookAddress(...a),
 };
}

export function createNetworkFetch({bootstrap,control,controlRequired=false,fetch=globalThis.fetch,guard=guardedFetch}){
 return async(url,init={})=>{
  const transport=control();
  if(transport){try{
   await transport.proxies();
   return await guard(transport.proxies,{timeoutMs:15000,maxBytes:4194304,publicRecords:true})(url,init);
  }catch(e){if(controlRequired&&!bootstrap)throw e;}}
  if(controlRequired&&!bootstrap)throw Error('control transport unavailable without an explicit private bootstrap');
  return (bootstrap?.fetch||fetch)(url,{...init,signal:AbortSignal.timeout(15000)});
 };
}
