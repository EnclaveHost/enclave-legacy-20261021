import test from 'node:test';
import assert from 'node:assert/strict';
import {privateKeyToAccount} from 'viem/accounts';
import {recoverMessageAddress} from 'viem';
import {directUploadHeaders,uploadMessage} from '../sdk/storage/upload-auth.mjs';
const account=privateKeyToAccount('0x'+'42'.repeat(32)),audience='0x'+'ab'.repeat(32);
test('direct upload signs the Rust protocol without calling a token issuer',async()=>{
 const headers=await directUploadHeaders({audience,url:'https://adapter.example/add-json',address:account.address,bytes:new TextEncoder().encode('{}'),signMessage:args=>account.signMessage(args),now:()=>1792345700000});
 assert.equal(headers['x-upload-expiry'],'1792346000');
 assert.equal(headers['x-upload-sha256'],'44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a');
 const message=uploadMessage({audience,path:'/add-json',address:account.address.toLowerCase(),hash:headers['x-upload-sha256'],size:2,expiry:1792346000});
 assert.equal(await recoverMessageAddress({message,signature:headers['x-upload-signature']}),account.address);
 assert.equal(headers['x-upload-token'],undefined);
});
test('refuses ambiguous service and transport scope before asking the wallet',async()=>{
 let calls=0;const opts={audience,url:'https://adapter.example/add-json',address:account.address,bytes:new Uint8Array(),signMessage:async()=>{calls++;throw Error('must not sign');}};
 for(const url of ['http://adapter.example/add-json','https://a:b@adapter.example/add-json','https://adapter.example/add-json?a=b','https://adapter.example/add-json#x','https://adapter.example/other'])await assert.rejects(directUploadHeaders({...opts,url}));
 await assert.rejects(directUploadHeaders({...opts,audience:'0x00'}));assert.equal(calls,0);
});
