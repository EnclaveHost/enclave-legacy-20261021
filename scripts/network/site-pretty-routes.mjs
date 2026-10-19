#!/usr/bin/env node
// Render the site's IPFS _redirects as Caddy rules for the static mirror.
// Include inside the site's handle, after root and before file_server.
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

export function sitePrettyRoutes(redirects) {
  const out = ['# BEGIN generated site pretty routes'];
  let index = 0;
  for (const line of redirects.split('\n')) {
    const value = line.replace(/#.*/, '').trim();
    if (!value) continue;
    const [from, to, status, extra] = value.split(/\s+/);
    if (from === '/*' && to === '/404.html' && status === '404' && !extra) continue;
    if (extra || !/^\/[A-Za-z0-9/._-]*$/.test(from) || !/^\/[A-Za-z0-9/._-]*$/.test(to) ||
        !['200', '301', '302'].includes(status)) throw Error('unsupported site redirect: ' + value);
    const matcher = '@sitePretty' + index++;
    out.push(`${matcher} {`, `    path ${from}`, '    not file {path} {path}/index.html', '}');
    // Rewrites retain the original query; redirects carry it explicitly.
    out.push(status === '200' ? `rewrite ${matcher} ${to}` :
      `redir ${matcher} ${to}?{http.request.uri.query} ${status}`);
  }
  out.push('# END generated site pretty routes');
  return out.join('\n') + '\n';
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const input = process.argv[2] || fileURLToPath(new URL('../../site/_redirects', import.meta.url));
  process.stdout.write(sitePrettyRoutes(fs.readFileSync(input, 'utf8')));
}
