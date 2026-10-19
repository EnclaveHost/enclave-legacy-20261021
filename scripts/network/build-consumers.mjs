// Standalone host/provider artifacts need CommonJS built-ins used by bundled ws.
import {build} from 'esbuild';
import {mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../../',import.meta.url));
const output=process.argv[2];
if(!output)throw Error('usage: node scripts/network/build-consumers.mjs OUTPUT_DIRECTORY');
await mkdir(output,{recursive:true});
const files={};
for(const [name,entry] of Object.entries({'provider.mjs':'network/wg-provider/main.mjs','privacy-agent.mjs':'network/privacy-agent.mjs','checker.mjs':'scripts/network/wg-qualify.mjs','dns.mjs':'relay/dns-relay.js'})){
 const result=await build({absWorkingDir:root,entryPoints:[entry],outfile:name,write:false,bundle:true,platform:'node',format:'esm',target:'node20',minify:true,metafile:true,
  banner:{js:'import {createRequire as bundleRequire} from "node:module"; const require=bundleRequire(import.meta.url);'}});
 const bytes=result.outputFiles[0].contents;
 await writeFile(path.join(output,name),bytes);
 files[name]={bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),inputs:Object.keys(result.metafile.inputs).sort()};
}
await writeFile(path.join(output,'build-manifest.json'),JSON.stringify({files},null,2)+'\n');
console.log(JSON.stringify({output,files:Object.fromEntries(Object.entries(files).map(([k,v])=>[k,{sha256:v.sha256,bytes:v.bytes}]))}));
