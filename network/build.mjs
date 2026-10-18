import {build} from 'esbuild';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(process.argv[2] || path.join(root, 'dist'));
fs.mkdirSync(out, {recursive:true});
const bundle = (entry, file) => build({entryPoints:[path.join(root,entry)], outfile:path.join(out,file), bundle:true, platform:'node', format:'esm', target:'node22',
  banner:{js:'import {createRequire as bundleRequire} from "node:module"; const require=bundleRequire(import.meta.url);'}});
// the host's privacy agent and its circuits' ingress worker (the SNI gate each Enclave-network circuit runs; the name is
// historical: Linux hosts run the same worker)
await bundle('privacy-agent.mjs', 'privacy-agent.mjs');
await bundle('windows-circuit-worker.mjs', 'windows-circuit-worker.mjs');
// the Enclave network (docs/design/enclave-network.md): the provider daemon and the checker, one file each
await bundle('wg-provider/main.mjs', 'wg-provider.mjs');
await bundle('../scripts/network/wg-qualify.mjs', 'wg-qualify.mjs');
await bundle('directory-server.mjs', 'enclave-directory.mjs');
// enclave-wg: one WireGuard-in-WireGuard circuit, in-process (no OS interface)
for (const goos of ['linux','windows'])
  execFileSync('go',['build','-trimpath','-o',path.join(out,'enclave-wg'+(goos==='windows'?'.exe':'')),'./cmd/enclave-wg'],{cwd:path.join(root,'wg'),stdio:'inherit',env:{...process.env,GOOS:goos,GOARCH:'amd64',CGO_ENABLED:'0'}});
// the Windows circuits' sandbox: AppContainer + exact WFP rules (tunnel mode for enclave-wg)
execFileSync('go',['build','-trimpath','-o',path.join(out,'enclave-circuit-firewall.exe'),'.'],{cwd:path.join(root,'windows-firewall'),stdio:'inherit',env:{...process.env,GOOS:'windows',GOARCH:'amd64',CGO_ENABLED:'0'}});
console.log(out);
