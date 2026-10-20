#!/usr/bin/env node
// Prepare a reviewable Caddy site. Does not contact Enclave, install a service,
// change DNS, issue a certificate or reload an existing server.
import fs from 'node:fs';
import {directCustodyIngress} from '../custody/v2/ingress.mjs';
const [configFile,output]=process.argv.slice(2);
if(!configFile||!output)throw Error('usage: node scripts/prepare-custodian-ingress.mjs HOST_CONFIG.json NEW_CADDYFILE');
const config=JSON.parse(fs.readFileSync(configFile,'utf8'));
fs.writeFileSync(output,directCustodyIngress(config),{flag:'wx',mode:0o600});
console.log(JSON.stringify({output,upstream:`127.0.0.1:${config.mgmtPort}`,activated:false}));
