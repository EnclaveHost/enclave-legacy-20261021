import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mirrorProviderPass} from '../scripts/network/mirror-public-providers.mjs';
const record={providerId:'provider',expiresAt:2000};
const negative={qualification:{expiresAt:1800,checks:{security:false}},signature:'negative'};
const positive={qualification:{expiresAt:1900,checks:{security:true}},signature:'positive',onchain:{expires:1900}};
const sources={read:async()=>[{value:{providers:[{record:{record,signature:'provider'},qualifications:[positive,negative],privateData:'never copied'}]}}]};
test('legacy mirror preserves signed negative and positive verdicts and suppresses exact repeats',async()=>{
 const sent=new Map(),calls=[];
 const fetch=async(url,o)=>{calls.push({url,body:JSON.parse(o.body),redirect:o.redirect,credentials:o.credentials});return Response.json({ok:true});};
 const options={sources,destination:'https://legacy.example',sent,fetch,now:()=>1000};
 assert.equal((await mirrorProviderPass(options)).accepted,3);
 assert.equal((await mirrorProviderPass(options)).unchanged,3);
 assert.equal(calls.length,3);assert.deepEqual(calls[2].body,negative);assert.deepEqual(calls[1].body,positive);
 assert.equal(JSON.stringify(calls).includes('never copied'),false);
 assert.ok(calls.every(c=>c.redirect==='error'&&c.credentials==='omit'));
});
test('destination mismatch is retried; only exact stale-record refusals are remembered',async()=>{
 const sent=new Map();let mismatch=true,calls=0;
 const fetch=async(url)=>{calls++;return url.endsWith('/qualifications')&&mismatch?Response.json({error:'qualification does not match the current provider record'},{status:409}):Response.json({error:'stale provider record'},{status:409});};
 const options={sources,destination:'https://legacy.example',sent,fetch,now:()=>1000};
 assert.equal((await mirrorProviderPass(options)).rejected,2);assert.equal(sent.size,1);
 mismatch=false;assert.equal((await mirrorProviderPass(options)).rejected,0);assert.equal(calls,5);
});
test('expired records are not republished and a failed source read does not become an empty success',async()=>{
 let calls=0;
 assert.deepEqual(await mirrorProviderPass({sources,destination:'https://legacy.example',now:()=>3000,fetch:async()=>{calls++;}}),{accepted:0,unchanged:0,rejected:0});
 assert.equal(calls,0);
 await assert.rejects(mirrorProviderPass({sources:{read:async()=>{throw Error('unavailable');}},destination:'https://legacy.example'}),/unavailable/);
});
