import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import {execFileSync,spawn} from 'node:child_process';
import {once} from 'node:events';
import {mintLocalCa} from './helpers/local-tls.mjs';
import {directCustodyIngress} from '../custody/v2/ingress.mjs';
import * as hpke from '../custody/hpke.mjs';
const caddy=process.env.CADDY_BIN;
test('operator HTTPS ingress forwards public custody ciphertext but never private host routes',
  {skip:!caddy?'set CADDY_BIN to run the real Caddy/TLS integration':false,timeout:20000},async()=>{
  const ca=mintLocalCa(),seen=[],keys=hpke.generateKeyPair(),info=Buffer.from('transport test'),aad=Buffer.from('bound request');
  const sealed=hpke.seal(keys.publicKey,info,aad,Buffer.from('recipient-only test value'));
  let child,backend;let diagnostics='';
  const request=(port,route,method='GET',body=null)=>new Promise((resolve,reject)=>{
    const req=https.request({hostname:'127.0.0.1',servername:'localhost',port,path:route,method,ca:ca.caPem,
      headers:{host:'localhost','content-type':'application/json','content-length':Buffer.byteLength(body||'')},timeout:2000},res=>{
      const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(chunks).toString()}));
    });req.on('error',reject);req.on('timeout',()=>req.destroy(Error('timeout')));req.end(body);
  });
  try{
    backend=http.createServer(async(req,res)=>{
      const chunks=[];for await(const c of req)chunks.push(c);seen.push({path:req.url,method:req.method,body:Buffer.concat(chunks).toString()});
      res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({ok:true,sealed:Buffer.from(sealed).toString('base64')}));
    });backend.listen(0,'127.0.0.1');await once(backend,'listening');
    const reservation=net.createServer();reservation.listen(0,'127.0.0.1');await once(reservation,'listening');
    const port=reservation.address().port;await new Promise(r=>reservation.close(r));
    const site=directCustodyIngress({endpoint:'https://localhost',mgmtPort:backend.address().port});
    const config='{\n admin off\n auto_https off\n}\n'+site.replace('https://localhost {',`https://localhost:${port} {\n bind 127.0.0.1\n tls ${ca.dir}/leaf.pem ${ca.dir}/leaf.key`);
    const configPath=path.join(ca.dir,'Caddyfile');fs.writeFileSync(configPath,config,{mode:0o600});
    // Validate the real generated syntax before starting the isolated server.
    execFileSync(caddy,['adapt','--config',configPath,'--adapter','caddyfile'],{stdio:'pipe'});
    child=spawn(caddy,['run','--config',configPath,'--adapter','caddyfile'],{
      env:{...process.env,XDG_CONFIG_HOME:ca.dir,XDG_DATA_HOME:ca.dir},stdio:['ignore','ignore','pipe']});
    child.stderr.on('data',c=>{diagnostics=(diagnostics+c.toString()).slice(-3000);});
    let ready=false;
    for(let i=0;i<60;i++){
      if(child.exitCode!==null)throw Error('Caddy exited: '+diagnostics);
      try{ready=(await request(port,'/v2/custody/info')).status===200;}catch{}
      if(ready)break;await new Promise(r=>setTimeout(r,50));
    }
    assert.ok(ready,'direct TLS ingress becomes ready');seen.length=0;
    const body=JSON.stringify({recipientKey:Buffer.from(keys.publicKey).toString('hex'),nonce:'test'});
    for(const route of ['evidence','challenge','release','join','approve','independent-genesis','code-approve']){
      const response=await request(port,'/v2/custody/'+route,'POST',body);assert.equal(response.status,200);
      const value=hpke.open(keys.privateKey,info,aad,Buffer.from(JSON.parse(response.body).sealed,'base64'));
      assert.equal(Buffer.from(value).toString(),'recipient-only test value');
      assert.equal(seen.at(-1).body,body);
    }
    const forwarded=seen.length;
    for(const [route,method] of [['/state','GET'],['/state','PUT'],['/submit','POST'],['/receipts','GET'],
      ['/v2/custody/host-binding','POST'],['/v2/custody/%68ost-binding','POST'],['/v2/custody/release','GET'],['/v2/custody/info','POST']]){
      assert.equal((await request(port,route,method,'{}')).status,404,route+' '+method);
    }
    assert.equal(seen.length,forwarded,'private requests never reach the guest forwarding port');
  }finally{
    if(child&&child.exitCode===null){const done=once(child,'exit');child.kill('SIGTERM');await done;}
    if(backend){backend.closeAllConnections();await new Promise(r=>backend.close(r));}
    ca.cleanup();
  }
});
