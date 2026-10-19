// The adapter verifies this deployment-bound EIP-191 message inside the guest.
export function uploadMessage({audience,path,address,hash,size,expiry}) {
  if(!/^0x[0-9a-f]{64}$/.test(audience)||!/^0x[0-9a-f]{40}$/.test(address)||! /^[0-9a-f]{64}$/.test(hash)||
     !['/add-wasm','/add-json','/add-image','/add-file'].includes(path)||!Number.isSafeInteger(size)||size<0||!Number.isSafeInteger(expiry)||expiry<0)
    throw Error('Invalid direct upload scope');
  return `enclave-storage-upload:v1\nchainId:8453\nservice:${audience}\nmethod:POST\npath:${path}\naddress:${address}\nsha256:${hash}\nbytes:${size}\nexpiry:${expiry}`;
}
// A caller that streams a large file can compute its digest without buffering
// a second copy. The adapter still verifies the actual request body against it.
export async function directUploadDigestHeaders({audience,url,address,hash,size,signMessage,now=Date.now}) {
  const target=new URL(url);
  if(target.username||target.password||target.search||target.hash||target.protocol!=='https:')throw Error('Direct upload requires an HTTPS endpoint without credentials or query');
  address=address.toLowerCase();audience=audience.toLowerCase();
  const expiry=Math.floor(now()/1000)+300;
  const message=uploadMessage({audience,path:target.pathname,address,hash,size,expiry});
  const signature=await signMessage({message});
  return {'x-upload-address':address,'x-upload-expiry':String(expiry),'x-upload-sha256':hash,'x-upload-signature':signature};
}
export async function directUploadHeaders({bytes,...args}) {
  const hash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
  return directUploadDigestHeaders({...args,hash,size:bytes.byteLength});
}
