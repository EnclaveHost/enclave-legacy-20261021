import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {privateKeyToAccount} from 'viem/accounts';
import {PublicDirectory} from '../network/public-directory.mjs';
import {signManagementRecord} from '../network/management-record.mjs';

test('directory operator rotation accepts the new owner immediately and preserves returning operators rollback floors',async t=>{
 const dir=await mkdtemp(path.join(os.tmpdir(),'management-directory-rotation-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 const a=privateKeyToAccount('0x'+'11'.repeat(32)),b=privateKeyToAccount('0x'+'22'.repeat(32));
 let current=a.address;
 const now=Date.now(),runner='0x'+'ab'.repeat(32);
 const open=()=>new PublicDirectory({directory:dir,checkers:[a.address],hostOperator:async()=>current,leaseOf:async()=>null,verifyOwner:async()=>false,now:()=>now,importManagement:true});
 const signed=(who,offset)=>signManagementRecord(who,{version:1,runner,operator:who.address.toLowerCase(),chainId:8453,deployments:'0x'+'33'.repeat(20),address:'8.8.8.8',port:443,spkiSha256:'44'.repeat(32),sequence:now+offset,issuedAt:now+offset,expiresAt:now+120000});
 let d=open();const ahead=await signed(a,30000),newOwner=await signed(b,0);
 assert.equal(await d.accept('management',ahead),true);
 current=b.address;
 assert.equal(await d.accept('management',newOwner),true,'former operator sequence cannot veto the new operator');
 assert.equal((await d.snapshot()).management[0].record.operator,b.address.toLowerCase());
 await assert.rejects(d.accept('management',ahead),/registry operator/);
 d=open();current=a.address;
 await assert.rejects(d.accept('management',await signed(a,0)),/stale/,'restart and rotation never forget the first operator floor');
 assert.equal(await d.accept('management',ahead),true,'a returning operator can republish its last accepted record');
 assert.equal((await d.snapshot()).management[0].record.operator,a.address.toLowerCase());
 assert.equal(await d.accept('management',ahead),false);
});
