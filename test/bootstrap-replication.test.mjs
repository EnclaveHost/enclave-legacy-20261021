import test from 'node:test';import assert from 'node:assert/strict';import {mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import path from 'node:path';import {createHash} from 'node:crypto';import {spawnSync} from 'node:child_process';
const base32={encode(bytes){let out='b',acc=0,bits=0;for(const b of bytes){acc=(acc<<8)|b;bits+=8;while(bits>=5){bits-=5;out+='abcdefghijklmnopqrstuvwxyz234567'[(acc>>>bits)&31];}}if(bits)out+='abcdefghijklmnopqrstuvwxyz234567'[(acc<<(5-bits))&31];return out;}};
const sha=b=>createHash('sha256').update(b).digest();
const vi=n=>{const b=[];do{b.push((n&127)|(n>127?128:0));n>>>=7;}while(n);return Buffer.from(b);};
test('replication verifies the requested CID as well as the transport manifest',t=>{
 const dir=mkdtempSync(path.join(tmpdir(),'replica-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const bytes=Buffer.from('public artifact'),cidBytes=Buffer.concat([Buffer.from([1,0x55,0x12,32]),sha(bytes)]),cid=base32.encode(cidBytes);
 const header=Buffer.concat([Buffer.from('a265726f6f747381d82a582500','hex'),cidBytes,Buffer.from('6776657273696f6e01','hex')]);
 const car=Buffer.concat([vi(header.length),header,vi(cidBytes.length+bytes.length),cidBytes,bytes]);
 const row={cid,bytes:bytes.length,sha256:sha(bytes).toString('hex'),carSha256:sha(car).toString('hex')},manifest=path.join(dir,'manifest.json');
 writeFileSync(path.join(dir,cid+'.car'),car);writeFileSync(manifest,JSON.stringify({verifiedObjects:[row]}));
 const run=()=>spawnSync('python3',['network/replicate-artifacts.py',manifest,dir],{encoding:'utf8'});
 assert.equal(run().status,0);assert.deepEqual(readFileSync(path.join(dir,cid+'.bin')),bytes);
 car[car.length-1]^=1;writeFileSync(path.join(dir,cid+'.car'),car);assert.notEqual(run().status,0);
 row.carSha256=sha(car).toString('hex');writeFileSync(manifest,JSON.stringify({verifiedObjects:[row]}));const forged=run();assert.notEqual(forged.status,0);assert.match(forged.stderr,/block hash mismatch/);
 assert.deepEqual(readFileSync(path.join(dir,cid+'.bin')),bytes);
});
