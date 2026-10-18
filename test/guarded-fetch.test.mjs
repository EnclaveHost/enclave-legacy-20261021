import test from 'node:test';import assert from 'node:assert/strict';
import {withGuardedFailover,guardedFetch} from '../network/guarded-fetch.mjs';
import net from 'node:net';
test('control RPC remembers a usable guard after an aborted attempt',async()=>{
 const calls=[],abort=new AbortController();let entries=['127.0.0.1:1','127.0.0.1:2'];
 const fetch=withGuardedFailover(()=>entries,p=>async()=>{calls.push(p);if(p.endsWith(':1')){abort.abort(new Error('deadline'));throw Error('guard timeout');}return new Response('{}');});
 await assert.rejects(fetch('https://rpc.example',{signal:abort.signal}),/deadline/);
 assert.equal((await fetch('https://rpc.example')).status,200);assert.deepEqual(calls,['127.0.0.1:1','127.0.0.1:2']);
 entries=[];await assert.rejects(fetch('https://rpc.example'),/unavailable/);assert.equal(calls.length,2);
});
test('public HTTP metadata uses SOCKS; credentials and other HTTP paths never leave',async t=>{
 let connections=0,destination;
 const sockets=new Set();
 const proxy=net.createServer(s=>{connections++;sockets.add(s);s.on('close',()=>sockets.delete(s));let stage=0,buffer=Buffer.alloc(0);
  s.on('data',chunk=>{buffer=Buffer.concat([buffer,chunk]);
   if(stage===0&&buffer.length>=3){assert.deepEqual([...buffer.subarray(0,3)],[5,1,0]);buffer=buffer.subarray(3);stage=1;s.write(Buffer.from([5,0]));}
   if(stage===1&&buffer.length>=5&&buffer.length>=7+buffer[4]){const n=buffer[4];destination=buffer.subarray(5,5+n).toString()+':'+buffer.readUInt16BE(5+n);buffer=buffer.subarray(7+n);stage=2;s.write(Buffer.from([5,0,0,1,0,0,0,0,0,0]));}
   if(stage===2&&buffer.includes('\r\n\r\n')){stage=3;s.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}');}
  });
 });
 await new Promise(resolve=>proxy.listen(0,'127.0.0.1',resolve));t.after(()=>{for(const s of sockets)s.destroy();proxy.close();});
 const address='127.0.0.1:'+proxy.address().port,url='http://198.51.100.7:8188/v1/network/providers';
 await assert.rejects(guardedFetch(address)(url),/HTTPS/);
 const fetch=guardedFetch(address,{publicRecords:true});
 await assert.rejects(fetch(url,{headers:{Authorization:'must-not-leave'}}),/credential/);
 await assert.rejects(fetch('http://198.51.100.7:8188/v1/secrets/test'),/HTTPS/);
 await assert.rejects(fetch('http://example.test/v1/network/providers'),/HTTPS/);
 assert.equal(connections,0);
 assert.equal((await fetch(url)).status,200);assert.equal(destination,'198.51.100.7:8188');assert.equal(connections,1);
});
test('blocked and rate-limited guard responses try only the explicit sibling',async()=>{
 const calls=[];const fetch=withGuardedFailover(()=>['127.0.0.1:1','127.0.0.1:2'],p=>async()=>{calls.push(p);return new Response('{}',{status:p.endsWith(':1')?403:200});});
 assert.equal((await fetch('https://rpc.example')).status,200);assert.equal((await fetch('https://rpc.example')).status,200);
 assert.deepEqual(calls,['127.0.0.1:1','127.0.0.1:2','127.0.0.1:2']);
});
