// The transport selection is part of the measured image. Unmeasured host
// configuration supplies addresses, but cannot enable a relay in direct mode.
export function custodianProcessPlan(config,transport) {
  const processes=[{name:'custodian',args:['/opt/custodian/custodian.mjs'],env:{}}];
  if(transport==='direct')return processes;
  if(transport!=='tunnel')throw Error('unknown measured custody transport');
  const name=/^[a-z0-9][a-z0-9-]{0,40}$/.test(String(config.tunnelName||''))?config.tunnelName:'custody-unnamed';
  processes.push({name:'agent',args:['/opt/metal/agent.mjs'],env:{
    METAL_MODE:'snp',METAL_NAME:name,METAL_SUP_URL:'http://127.0.0.1:8787',
    METAL_RELAY_URL:String(config.relayUrl||'wss://api.enclave.host/v1/fleet-tunnel'),
    METAL_PUBLIC_URL:String(config.endpoint||''),METAL_VCEK_B64:typeof config.vcek==='string'?config.vcek:'',
    METAL_RAD_PORT:'8443',METAL_TUNNEL_TOKEN:'',
  }});
  return processes;
}
