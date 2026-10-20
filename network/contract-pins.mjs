import fs from 'node:fs';
const required=['registry','deployments','appCatalog','proofOfTime'];
const optional=['enclavePay','verificationFees','sessionVaultFactory','secretVaultV2'];
export function validateContractPins(value){
  if(!value||value.version!==1||value.chainId!==8453||!value.contracts||Array.isArray(value.contracts)||
    Object.keys(value).some(k=>!['version','chainId','contracts'].includes(k)))throw Error('invalid contract pin document');
  const contracts=value.contracts;
  if(Object.keys(contracts).some(k=>![...required,...optional].includes(k)))throw Error('unknown contract pin');
  for(const key of [...required,...optional]){
    const a=contracts[key];
    if(typeof a!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(a)||required.includes(key)&&/^0x0{40}$/i.test(a))throw Error('missing or invalid contract pin: '+key);
  }
  return Object.freeze(Object.fromEntries(Object.entries(contracts).map(([k,v])=>[k,v.toLowerCase()])));
}
export function loadContractPins(env=process.env){
  if(!env.ENCLAVE_CONTRACT_PINS_FILE)return null;
  const fd=fs.openSync(env.ENCLAVE_CONTRACT_PINS_FILE,'r');
  try{
    const bytes=Buffer.alloc(16385);let size=0;
    while(size<bytes.length){const n=fs.readSync(fd,bytes,size,bytes.length-size,null);if(!n)break;size+=n;}
    if(size>16384)throw Error('contract pin document too large');
    return validateContractPins(JSON.parse(bytes.subarray(0,size).toString('utf8')));
  }finally{fs.closeSync(fd);}
}
