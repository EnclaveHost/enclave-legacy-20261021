#!/usr/bin/env node
import fs from 'node:fs/promises';
import {NativeClient} from '../../network/native-client.mjs';

const [profileFile,requestPath='/']=process.argv.slice(2);
if(!profileFile||process.argv.length>4){console.error('Usage: node scripts/network/native-get.mjs TRUST-PROFILE.json [/path]');process.exitCode=2;}
else try{
  const client=new NativeClient(JSON.parse(await fs.readFile(profileFile,'utf8')));
  const result=await client.request({path:requestPath});
  console.error(JSON.stringify({status:result.status,route:result.route,proof:result.proof,expectation:result.expectation,leaseBlock:result.leaseBlock,validUntil:result.validUntil}));
  process.stdout.write(result.body);if(result.status<200||result.status>=300)process.exitCode=1;
}catch(e){console.error(e.message);process.exitCode=1;}
