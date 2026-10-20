#!/usr/bin/env node
// Read-only: explicit addresses, agreeing RPC snapshots, no wallet or API.
import { parseArgs } from 'node:util';
import fs from 'node:fs/promises';
import { zeroAddress } from 'viem';
import { LeaseReader } from '../network/lease-reader.mjs';
import { captureGovernanceReview } from './lib/governance-review.mjs';
const {values:v} = parseArgs({options:{ledger:{type:'string'},catalog:{type:'string'},out:{type:'string'},rpc:{type:'string',multiple:true}}});
if (!v.ledger || !v.out) throw Error('usage: --ledger ADDRESS [--catalog ADDRESS] --out NEW_FILE [--rpc HTTPS_ORIGIN ...]');
const reader = new LeaseReader({addressBook:zeroAddress,rpc:v.rpc || ['https://base-rpc.publicnode.com','https://base.drpc.org','https://mainnet.base.org']});
const failures=[];
let snapshot;
try {
  snapshot = await reader.agreed(async(client,blockNumber)=>{
    const ledger = await captureGovernanceReview(client,{target:v.ledger,profile:'ledger16',chainId:8453,blockNumber});
    const targets = [ledger];
    const prover = ledger.dependencies.find(d=>d.name==='prover');
    if (prover.enabled) {
      const proof = await captureGovernanceReview(client,{target:prover.address,profile:'proof2',chainId:8453,blockNumber});
      const get = (t,n) => t.readings.find(r=>r.name===n).value.toLowerCase();
      if (get(proof,'deployments') !== v.ledger.toLowerCase() || get(proof,'registry') !== get(ledger,'registry')) throw Error('proof dependency mismatch');
      targets.push(proof);
    }
    if(v.catalog) targets.push(await captureGovernanceReview(client,{target:v.catalog,profile:'catalog9',chainId:8453,blockNumber}));
    return {targets};
  },failures);
} catch(e) { throw Error(`${e.message}: ${[...new Set(failures)].join('; ')}`); }
await fs.writeFile(v.out,JSON.stringify({preparedAt:new Date().toISOString(),transactionsSent:0,...snapshot},null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({out:v.out,block:snapshot.blockNumber,targets:snapshot.targets.map(t=>({profile:t.profile,target:t.target,blockers:t.blockers})),transactionsSent:0}));
