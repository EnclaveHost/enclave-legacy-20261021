// Transitional publisher for clients that still submit owner-signed policies to
// the legacy API. Only the public policy/signature pair is exported, never BYO
// ciphertext, tokens, status, account records or signing keys. Remove this bridge
// once all policy writers publish to independent directories themselves.
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {DirectoryClient} from '../../network/directory-client.mjs';
import {validateNetworkPolicy} from '../../network/network-policy.mjs';

export function publicPolicies(state){
  return Object.entries(state.policies||{}).map(([id,e])=>{
    const policy=validateNetworkPolicy(e.policy);
    if(policy.deploymentId!==id||typeof e.signature!=='string'||!/^0x[0-9a-fA-F]{2,8192}$/.test(e.signature))throw Error('invalid stored policy');
    return {policy,signature:e.signature};
  });
}
export async function mirrorPolicies({file,directories,log=console.log}){
  const client=new DirectoryClient({origins:directories}),sent=new Map();let busy=false;
  const sync=async()=>{
    if(busy)return;busy=true;
    try{
      for(const envelope of publicPolicies(JSON.parse(await fs.readFile(file,'utf8')))){
        const id=envelope.policy.deploymentId,bytes=JSON.stringify(envelope);if(sent.get(id)===bytes)continue;
        await client.publish('/v1/network/policy/'+id,{envelope});sent.set(id,bytes);
        log('public policy replicated '+id+' nonce '+envelope.policy.nonce);
      }
    }catch(e){log('policy replication: '+e.message);}finally{busy=false;}
  };
  await sync();const timer=setInterval(sync,5000);return ()=>clearInterval(timer);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const config=JSON.parse(await fs.readFile(process.argv[2],'utf8'));
  const close=await mirrorPolicies(config);for(const sig of ['SIGTERM','SIGINT'])process.on(sig,()=>{close();process.exit(0);});
}
