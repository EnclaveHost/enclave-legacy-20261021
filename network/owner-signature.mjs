// Is `signature` over `message` the deployment owner's? The owner on the ledger may be a wallet (EOA), a passkey vault
// (ERC-1271), or a SessionVault from the address book's sessionVaultFactory, whose own owner (a wallet or passkey
// vault) answers for it, as the relay's beneficialOwner does. Every client must agree; any read failure is "no".
import {recoverMessageAddress,hashMessage,parseAbi,stringToHex} from 'viem';
const ERC1271=parseAbi(['function isValidSignature(bytes32 hash, bytes signature) view returns (bytes4)']);
const BOOK=parseAbi(['function addr(bytes32) view returns (address)']);
const FACTORY=parseAbi(['function isVault(address) view returns (bool)']);
const VAULT=parseAbi(['function owner() view returns (address)']);
const addr=/^0x[0-9a-fA-F]{40}$/;

async function signedBy(client,owner,message,signature,eoa,blockNumber){
 if(eoa&&eoa.toLowerCase()===owner.toLowerCase())return true;
 const code=await client.getCode({address:owner,blockNumber});if(!code||code==='0x')return false;
 return (await client.readContract({address:owner,abi:ERC1271,functionName:'isValidSignature',args:[hashMessage(message),signature],blockNumber}).catch(()=>null))==='0x1626ba7e';
}
async function oneClient(client,{owner,message,signature,addressBook,eoa,sessionVaultFactory,blockNumber}){
 if(await signedBy(client,owner,message,signature,eoa,blockNumber))return true;
 if(sessionVaultFactory===undefined&&!addressBook)return false;
 const factory=sessionVaultFactory===undefined?await client.readContract({address:addressBook,abi:BOOK,functionName:'addr',args:[stringToHex('sessionVaultFactory',{size:32})],blockNumber}):sessionVaultFactory;
 if(!addr.test(factory)||/^0x0{40}$/i.test(factory))return false;
 if(!await client.readContract({address:factory,abi:FACTORY,functionName:'isVault',args:[owner],blockNumber}))return false;
 const controller=await client.readContract({address:owner,abi:VAULT,functionName:'owner',blockNumber});
 return addr.test(controller)&&await signedBy(client,controller,message,signature,eoa,blockNumber);
}
export async function verifyOwnerSignature({clients,reader,owner,message,signature,addressBook,sessionVaultFactory}){
 if(!addr.test(owner||'')||!/^0x(?:[0-9a-fA-F]{2}){1,4096}$/.test(signature||''))return false;
 if(sessionVaultFactory!==undefined&&!addr.test(sessionVaultFactory))return false;
 let eoa=null;if(signature.length===132){try{eoa=await recoverMessageAddress({message,signature});}catch{}}
 if(eoa&&eoa.toLowerCase()===owner.toLowerCase())return true;
 if(reader){
   try{return (await reader.agreed(async(client,blockNumber)=>({valid:await oneClient(client,{owner,message,signature,addressBook,eoa,sessionVaultFactory,blockNumber})}))).valid;}
   catch{return false;}
 }
 if(!clients?.length)return !!eoa&&eoa.toLowerCase()===owner.toLowerCase();
 const r=await Promise.all(clients.map(c=>oneClient(c,{owner,message,signature,addressBook,eoa,sessionVaultFactory}).catch(()=>false)));
 return r.every(Boolean);
}
