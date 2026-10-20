// Explicit authority bindings for a network reader. Zero disables optional
// authorities; it never asks the address book for a replacement.
export function validateNetworkAuthorities(value){
  const required=['deployments','registry'],optional=['connectivity','sessionVaultFactory'];
  if(!value||typeof value!=='object'||Array.isArray(value)||
    Object.keys(value).some(k=>![...required,...optional].includes(k)))throw Error('invalid network authority pins');
  for(const key of [...required,...optional]){
    const address=value[key];
    if(typeof address!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(address)||
      required.includes(key)&&/^0x0{40}$/i.test(address))throw Error('missing or invalid network authority pin: '+key);
  }
  return Object.freeze(Object.fromEntries(Object.entries(value).map(([key,address])=>[key,address.toLowerCase()])));
}
