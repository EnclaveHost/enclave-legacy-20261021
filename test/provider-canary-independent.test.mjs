// The provider canary and its independent qualification in an operator-chosen probe zone, end to end, as real child
// processes with every *.enclave.host lookup and connection refused (and logged):
//   host:    network/provider-canary.mjs createProviderCanary(direct.probe) -> network/direct-runtime.mjs DirectRuntime({canary}),
//            exactly the startup wiring docs/network/open-participation.md proposes for enclave-network-host.mjs;
//   checker: scripts/network/qualify-provider.mjs --config (independent: true, its own probeZone and outbound canary).
// Public test addresses stand in for the host (44.0.0.7) and the outbound canary site (44.0.0.9); a preload maps them to
// loopback in each child, so all nine checks - TCP 80/443, UDP echo, the 40 MiB echo, the HTTPS canary through the
// host's egress proxy (validated against a test CA) and the four refusals - run for real. Also: every malformed or
// unconfigured zone refused on both sides, a manifest outside the checker's zone refused, and the canary's token,
// path, port and SNI protections held in the independent mode.
//   run: node --test test/provider-canary-independent.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import https from 'node:https';
import nodeHttp from 'node:http';
import path from 'node:path';
import { spawn, execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { canaryHostname } from '../network/provider-canary.mjs';
import { probeTargets, providerProbes } from '../network/provider-probes.mjs';
import { verifyQualification } from '../network/provider-qualification.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const run = promisify(execFile);
const QUALIFY = path.join(ROOT, 'scripts', 'network', 'qualify-provider.mjs');
const ZONE = 'probe.alice-net.org', NAME = `probe-node1.${ZONE}`, HOST = '44.0.0.7', SITE = '44.0.0.9', OUTBOUND = 'https://canary.alice-net.org/';
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-independent-'));
const f = (n) => path.join(dir, n);
const TOKEN = 'ab'.repeat(32);

// A preload for both children: refuse and log Enclave names; map the public test addresses (TCP host:port, UDP host, DNS
// name) to loopback, and give UDP replies back their public source address.
const PRELOAD = `import net from 'node:net'; import dns from 'node:dns'; import dgram from 'node:dgram'; import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
const LOG = process.env.BLOCK_LOG, TCP = JSON.parse(process.env.MAP_TCP || '{}'), UDP = JSON.parse(process.env.MAP_UDP || '{}'), NAMES = JSON.parse(process.env.MAP_DNS || '{}');
const back = Object.fromEntries(Object.entries(UDP).map(([k, v]) => [v, k]));
const enclave = (h) => /(^|\\.)enclave\\.host\\.?$/i.test(String(h || ''));
const refuse = (h) => { fs.appendFileSync(LOG, String(h) + '\\n'); return Object.assign(new Error('blocked ' + h), { code: 'ENOTFOUND' }); };
const lookup = dns.lookup, plookup = dns.promises.lookup;
dns.lookup = function (h, o, cb) { cb = typeof o === 'function' ? o : cb; o = typeof o === 'object' ? o : {};
  if (enclave(h)) return process.nextTick(cb, refuse(h));
  if (NAMES[h]) return process.nextTick(() => o.all ? cb(null, [{ address: NAMES[h], family: 4 }]) : cb(null, NAMES[h], 4));
  return lookup.call(this, h, o, cb); };
dns.promises.lookup = async function (h, o = {}) { if (enclave(h)) throw refuse(h); if (NAMES[h]) return o.all ? [{ address: NAMES[h], family: 4 }] : { address: NAMES[h], family: 4 }; return plookup.call(this, h, o); };
syncBuiltinESMExports();
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...a) {
  const o = Array.isArray(a[0]) ? a[0][0] : (a[0] && typeof a[0] === 'object' ? a[0] : null);
  if (o) { if (enclave(o.host)) { const e = refuse(o.host); process.nextTick(() => this.destroy(e)); return this; }
           const to = TCP[o.host + ':' + o.port]; if (to) { const [h, p] = to.split(':'); o.host = h; o.port = Number(p); } }
  return connect.apply(this, a);
};
const send = dgram.Socket.prototype.send;
dgram.Socket.prototype.send = function (...a) { const i = a.findIndex((x, j) => j > 0 && typeof x === 'string' && UDP[x]); if (i > 0) a[i] = UDP[a[i]]; return send.apply(this, a); };
const emit = dgram.Socket.prototype.emit;
dgram.Socket.prototype.emit = function (ev, msg, rinfo) { if (ev === 'message' && rinfo && back[rinfo.address]) rinfo = { ...rinfo, address: back[rinfo.address] }; return emit.call(this, ev, msg, rinfo); };`;

// The host: the SHIPPING startup path. network/enclave-network-host.mjs createNetworkHost, called as
// network/privacy-agent.mjs runPrivacy calls it, from a daemon configuration file (privacy-config.json's shape) whose
// enclaveNetwork.direct.probe names the canary. Faked here are only what lies outside the wiring under test: the chain
// quorum reader (an object whose reads throw: startup must not need the chain), the app forwarder and authorizer.
const HOST_MAIN = `import fs from 'node:fs'; import { privateKeyToAccount } from ${JSON.stringify(import.meta.resolve('viem/accounts'))};
import { createNetworkHost } from ${JSON.stringify(pathToFileURL(path.join(ROOT, 'network', 'enclave-network-host.mjs')).href)};
const cfg = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const account = privateKeyToAccount(fs.readFileSync(cfg.operatorKeyFile, 'utf8').trim());
const leaseReader = { agreed: async () => { throw new Error('the chain is not read at startup'); }, get: () => null };
let network = null;
const stop = async (code) => { try { await network?.close(); } finally { process.exit(code); } };
process.on('SIGTERM', () => void stop(0));
try {
  network = await createNetworkHost({ config: cfg.enclaveNetwork, account, runner: cfg.runner, rpc: cfg.chain?.rpc, addressBook: cfg.chain?.addressBook,
    authorityPins: cfg.chain?.authorityPins, leaseReader, providerReader: leaseReader, directory: cfg.directory, log: (m) => process.stderr.write(m + '\\n'),
    authorize: () => false, attestedKey: () => null, forward: (socket) => socket.destroy() });
} catch (e) { process.stderr.write(e.message + '\\n'); process.exit(3); }
const r = network.direct.runtime;
process.stdout.write(JSON.stringify({ httpsPort: r.httpsPort, httpPort: r.httpPort, hostname: r.canary?.hostname ?? null, listening: !!r.listening }) + '\\n');`;

// A daemon configuration with no Enclave authority anywhere: pinned contracts, the operator's RPCs, directories and
// checkers, no relay, and the canary in the operator's reviewed probe zone.
const PINS = { deployments: '0x' + '11'.repeat(20), registry: '0x' + '22'.repeat(20), connectivity: '0x' + '00'.repeat(20), sessionVaultFactory: '0x' + '00'.repeat(20) };
let ports = null;
const daemonConfig = (probe) => ({ runner: '0x' + '42'.repeat(32), operatorKeyFile: f('operator.key'), directory: f('state'),
  chain: { rpc: ['https://rpc-one.example-rpc.org', 'https://rpc-two.other-rpc.net'], authorityPins: PINS },
  enclaveNetwork: { directories: ['https://dir.alice-net.org'], checkers: ['0x' + '45'.repeat(20)], apps: 'all',
    wgBinary: process.execPath, nodeBinary: process.execPath, workerModule: path.join(ROOT, 'network', 'windows-circuit-worker.mjs'),
    direct: { address: HOST, bindHost: '127.0.0.1', httpsPort: ports.https, httpPort: ports.http, qualificationFile: f('qualification.json'), ...(probe ? { probe } : {}) } } });
const writeDaemon = (probe) => { const file = f(`privacy-config-${Math.random().toString(16).slice(2)}.json`); fs.writeFileSync(file, JSON.stringify(daemonConfig(probe)), { mode: 0o600 }); return file; };
const freePort = () => new Promise((ok) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => ok(p)); }); });

let host = null, hostInfo = null, site = null, siteHits = 0, udpPort = 0, checker = null;
const probeConfig = (over = {}) => ({ independent: true, probeZone: ZONE, hostname: NAME, keyFile: f('canary.key'), certFile: f('canary.pem'), tokenFile: f('token'),
                                      udpPort, bindHost: '127.0.0.1', manifestFile: f('manifest.json'), ...over });
const childEnv = (extra) => ({ ...process.env, BLOCK_LOG: f('blocked.log'), ...extra });

before(async () => {
  const ossl = (...a) => execFileSync('openssl', a, { stdio: 'ignore' });
  // the canary's own certificate (unrelated to any app certificate), in the operator's zone
  ossl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', `/CN=${NAME}`, '-days', '1', '-keyout', f('canary.key'), '-out', f('canary.pem'));
  // a test CA and the outbound canary site's certificate (the checker trusts the CA through NODE_EXTRA_CA_CERTS)
  ossl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=test-ca', '-days', '1', '-keyout', f('ca.key'), '-out', f('ca.pem'),
       '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign');
  ossl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=canary.alice-net.org', '-keyout', f('site.key'), '-out', f('site.csr'));
  fs.writeFileSync(f('site.ext'), 'subjectAltName=DNS:canary.alice-net.org\n');
  ossl('x509', '-req', '-in', f('site.csr'), '-CA', f('ca.pem'), '-CAkey', f('ca.key'), '-CAcreateserial', '-days', '1', '-out', f('site.pem'), '-extfile', f('site.ext'));
  fs.writeFileSync(f('token'), TOKEN, { mode: 0o600 });
  fs.writeFileSync(f('preload.mjs'), PRELOAD); fs.writeFileSync(f('host.mjs'), HOST_MAIN); fs.writeFileSync(f('blocked.log'), '');
  site = https.createServer({ key: fs.readFileSync(f('site.key')), cert: fs.readFileSync(f('site.pem')) }, (q, s) => { siteHits++; s.end('canary ok'); });
  site.listen(0, '127.0.0.1'); await once(site, 'listening');
  const u = dgram.createSocket('udp4'); await new Promise((r) => u.bind(0, '127.0.0.1', r)); udpPort = u.address().port; await new Promise((r) => u.close(r));
  fs.writeFileSync(f('checker.key'), generatePrivateKey(), { mode: 0o600 });
  checker = privateKeyToAccount(fs.readFileSync(f('checker.key'), 'utf8'));
  fs.writeFileSync(f('operator.key'), generatePrivateKey(), { mode: 0o600 }); fs.mkdirSync(f('state'));
  ports = { https: await freePort(), http: await freePort() };
  try {
    host = spawn(process.execPath, ['--import', pathToFileURL(f('preload.mjs')).href, f('host.mjs'), writeDaemon(probeConfig())],
      { env: childEnv({ MAP_DNS: JSON.stringify({ 'canary.alice-net.org': SITE }), MAP_TCP: JSON.stringify({ [`${SITE}:443`]: `127.0.0.1:${site.address().port}` }) }), stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = ''; host.stderr.on('data', (d) => { err += d; });
    hostInfo = await new Promise((ok, no) => {
      const t = setTimeout(() => no(new Error(`host did not start: ${err}`)), 30_000);
      host.stdout.on('data', (d) => { out += d; if (out.includes('\n')) { clearTimeout(t); ok(JSON.parse(out)); } });
      host.once('exit', (c) => { clearTimeout(t); no(new Error(`host exited ${c}: ${err}`)); });
    });
  } catch (e) { host?.kill('SIGKILL'); site?.close(); throw e; }   // a failed setup leaves no child behind
});
after(() => { try { host?.kill('SIGTERM'); } finally { site?.close(); } });

const checkerConfig = (over = {}) => ({ independent: true, probeZone: ZONE, outbound: OUTBOUND, hostId: '0x' + '42'.repeat(32), operator: '0x' + '43'.repeat(20),
  probeKeyFile: f('checker.key'), manifestFile: f('manifest.json'), outputFile: f(`qualification-${Math.random().toString(16).slice(2)}.json`),
  proxy: JSON.parse(fs.readFileSync(f('manifest.json'), 'utf8')).proxy, connectivity: '0x' + '44'.repeat(20), ...over });
const qualify = (cfg) => {
  const file = f(`checker-${Math.random().toString(16).slice(2)}.json`); fs.writeFileSync(file, JSON.stringify(cfg), { mode: 0o600 });
  return run(process.execPath, ['--import', pathToFileURL(f('preload.mjs')).href, QUALIFY, '--config', file], { timeout: 120_000, env: childEnv({
    NODE_EXTRA_CA_CERTS: f('ca.pem'), MAP_UDP: JSON.stringify({ [HOST]: '127.0.0.1' }),
    MAP_TCP: JSON.stringify({ [`${HOST}:443`]: `127.0.0.1:${hostInfo.httpsPort}`, [`${HOST}:80`]: `127.0.0.1:${hostInfo.httpPort}` }) }) });
};

test('the host starts its canary in the operator\'s zone; an independent checker qualifies it, with Enclave blocked', { timeout: 180_000 }, async () => {
  assert.equal(hostInfo.hostname, NAME); assert.equal(hostInfo.listening, true, 'the direct runtime listens from startup when a canary is configured');
  assert.deepEqual([hostInfo.httpsPort, hostInfo.httpPort], [ports.https, ports.http], 'on the ports the daemon config names');
  const manifest = JSON.parse(fs.readFileSync(f('manifest.json'), 'utf8'));
  assert.equal(manifest.hostname, NAME); assert.equal(manifest.address, HOST); assert.ok(!('probeZone' in manifest), 'the manifest carries no zone a checker could take');
  assert.equal((fs.statSync(f('manifest.json')).mode & 0o777), 0o600);
  const cfg = checkerConfig(), { stdout } = await qualify(cfg);
  assert.equal(JSON.parse(stdout).qualified, true);
  const envelope = JSON.parse(fs.readFileSync(cfg.outputFile, 'utf8'));
  const q = await verifyQualification(envelope, { hostId: cfg.hostId, operator: cfg.operator, address: HOST, probeSigners: [checker.address] });
  assert.ok(Object.values(q.checks).every(Boolean)); assert.equal(q.signer, checker.address.toLowerCase());
  assert.ok(siteHits >= 1, 'the outbound check reached the operator\'s canary site through the host\'s egress proxy');
  assert.equal(fs.readFileSync(f('blocked.log'), 'utf8'), '', 'no enclave.host name was looked up or connected to, by either process');
  // the blocker is live (a positive control in a separate log): a child that does reach for Enclave is refused and logged
  const control = f('control.log'); fs.writeFileSync(control, '');
  const e = await run(process.execPath, ['--import', pathToFileURL(f('preload.mjs')).href, '-e', "await fetch('https://api.enclave.host/v1/health')"],
    { env: { ...process.env, BLOCK_LOG: control }, timeout: 20_000 }).then(() => null, (x) => x);
  assert.ok(e, 'the Enclave request was refused'); assert.match(fs.readFileSync(control, 'utf8'), /api\.enclave\.host/);
});

test('the checker refuses an unconfigured, malformed or Enclave zone, and any manifest outside its own zone', { timeout: 120_000 }, async () => {
  const refused = async (cfg, why) => { const e = await qualify(cfg).then(() => null, (x) => x); assert.ok(e, `accepted: ${JSON.stringify(cfg).slice(0, 120)}`); assert.match(e.stderr, why); };
  await refused(checkerConfig({ probeZone: undefined }), /probe zone/);
  for (const zone of ['Probe.Alice-Net.org', 'alice', 'probe.alice-net.org.', '-x.alice-net.org', 'probe..alice-net.org', 'probe alice.org', 'a'.repeat(64) + '.org'])
    await refused(checkerConfig({ probeZone: zone }), /probe zone/);
  for (const zone of ['enclave.host', 'probe.enclave.host']) await refused(checkerConfig({ probeZone: zone }), /must not be an Enclave zone/);
  await refused(checkerConfig({ outbound: undefined }), /https outbound canary/);
  await refused(checkerConfig({ outbound: 'http://canary.alice-net.org/' }), /https outbound canary/);
  await refused(checkerConfig({ independent: undefined }), /probeZone is for independent/);
  // the host's manifest cannot move the probe zone: a name outside the checker's zone, or the compatibility zone, is refused
  const manifest = JSON.parse(fs.readFileSync(f('manifest.json'), 'utf8'));
  for (const hostname of ['probe-node1.probe.evil-net.org', 'probe-node1.enclave.host', `probe-.${ZONE}`, `probe-${'x'.repeat(58)}.${ZONE}`, `x.probe-node1.${ZONE}`]) {
    const file = f(`manifest-${hostname.length}-${Math.random().toString(16).slice(2)}.json`); fs.writeFileSync(file, JSON.stringify({ ...manifest, hostname }));
    await refused(checkerConfig({ manifestFile: file }), /invalid independent probe manifest/);
  }
  // the compatibility checker does not accept the operator's zone either
  const legacy = checkerConfig(); delete legacy.independent; delete legacy.probeZone;
  await refused(legacy, /invalid independent probe manifest/);
  assert.equal(fs.readFileSync(f('blocked.log'), 'utf8'), '');
});

test('the canary refuses an unconfigured, malformed or Enclave zone before reading any key', async () => {
  const startHost = (probe) => run(process.execPath, [f('host.mjs'), writeDaemon(probe)], { timeout: 30_000, env: childEnv({}) }).then(() => null, (x) => x);
  const missing = { keyFile: f('no-such.key'), certFile: f('no-such.pem'), tokenFile: f('no-such-token') };
  for (const [probe, why] of [
    [probeConfig({ probeZone: undefined, ...missing }), /needs its reviewed probe zone/],
    [probeConfig({ probeZone: 'Probe.alice-net.org', ...missing }), /needs its reviewed probe zone/],
    [probeConfig({ probeZone: 'probe.enclave.host', hostname: 'probe-node1.probe.enclave.host', ...missing }), /must not be an Enclave zone/],
    [probeConfig({ hostname: 'probe-node1.probe.evil-net.org', ...missing }), /must be in its probe zone/],
    [probeConfig({ hostname: `node1.${ZONE}`, ...missing }), /probe-<label>/],
    [probeConfig({ hostname: `probe-${'x'.repeat(58)}.${ZONE}`, ...missing }), /probe-<label>/],
    [probeConfig({ hostname: `probe-node1-.${ZONE}`, ...missing }), /probe-<label>/],
    [probeConfig({ independent: undefined, ...missing }), /probeZone is for an independent canary/],
    [{ ...probeConfig({ independent: undefined, ...missing }), probeZone: undefined }, /invalid provider canary configuration/],
  ]) {
    const e = await startHost(probe);
    assert.ok(e, JSON.stringify(probe)); assert.match(e.stderr, why); assert.doesNotMatch(e.stderr, /ENOENT/, 'the name is judged before any file is read');
  }
  // and the token and port rules still hold in independent mode
  fs.writeFileSync(f('bad-token'), 'not-hex', { mode: 0o600 });
  assert.match((await startHost(probeConfig({ tokenFile: f('bad-token') }))).stderr, /invalid provider canary configuration/);
  assert.match((await startHost(probeConfig({ udpPort: 80 }))).stderr, /udpPort must be 1024-65535/);
  assert.match((await startHost(probeConfig({ zone: ZONE }))).stderr, /unknown field\(s\): zone/);
  assert.match((await startHost(probeConfig({ keyFile: 'canary.key' }))).stderr, /keyFile must be an absolute path/);
  assert.match((await startHost(probeConfig({ independent: 'yes' }))).stderr, /independent must be true or false/);
  // (that a refused or failed start leaves nothing bound is test/enclave-network-host-canary.test.mjs's, on ports of its own)
  // the legacy name rule is exactly as before
  assert.equal(canaryHostname({ hostname: 'probe-node1.enclave.host' }), 'probe-node1.enclave.host');
  assert.throws(() => canaryHostname({ hostname: NAME }), /invalid provider canary configuration/);
});

test('in the operator\'s zone the canary keeps its token, path and name protections', { timeout: 60_000 }, async () => {
  // TLS: the canary's name with a wrong token is closed without "OK"; another name reaches nothing
  const tlsTry = (servername, line) => new Promise((ok) => {
    const s = tls.connect({ host: '127.0.0.1', port: hostInfo.httpsPort, servername, rejectUnauthorized: false });
    let got = ''; s.on('data', (d) => { got += d; }); s.on('error', () => {}); s.once('close', () => ok(got));
    s.once('secureConnect', () => s.write(line)); setTimeout(() => s.destroy(), 3000);
  });
  assert.equal(await tlsTry(NAME, 'cd'.repeat(32) + '\n'), '');
  assert.equal(await tlsTry(NAME, TOKEN + '\n'), 'OK\n');
  assert.equal(await tlsTry('probe-other.' + ZONE, TOKEN + '\n'), '');
  // HTTP: only GET of the exact path with the canary's Host header
  const get = (hostHeader, p, method = 'GET') => new Promise((ok, no) => nodeHttp.request({ host: '127.0.0.1', port: hostInfo.httpPort, path: p, method, headers: { host: hostHeader } },
    (r) => { let b = ''; r.on('data', (d) => { b += d; }); r.on('end', () => ok({ status: r.statusCode, body: b })); }).on('error', no).end());
  assert.deepEqual(await get(NAME, `/__provider_probe/${TOKEN}`), { status: 200, body: TOKEN });
  assert.equal((await get(NAME, `/__provider_probe/${'cd'.repeat(32)}`)).status, 404);
  assert.equal((await get(NAME, `/__provider_probe/${TOKEN}`, 'POST')).status, 404);
  assert.equal((await get(NAME, `/__provider_probe/${TOKEN}/x`)).status, 404);
  assert.equal((await get('probe-node1.enclave.host', `/__provider_probe/${TOKEN}`)).status, 421, 'the compatibility name is not this canary');
  // UDP: only the token-prefixed 97-byte datagram is echoed
  const udp = dgram.createSocket('udp4'); await new Promise((r) => udp.bind(0, '127.0.0.1', r));
  const echo = (b) => new Promise((ok) => { const t = setTimeout(() => { udp.off('message', m); ok(null); }, 700); const m = (x) => { clearTimeout(t); udp.off('message', m); ok(x); }; udp.on('message', m); udp.send(b, udpPort, '127.0.0.1'); });
  const good = Buffer.from(TOKEN + '.' + 'ef'.repeat(16));
  assert.ok((await echo(good)).equals(good));
  assert.equal(await echo(Buffer.from('cd'.repeat(32) + '.' + 'ef'.repeat(16))), null);
  assert.equal(await echo(Buffer.from(TOKEN + '.' + 'ef'.repeat(15))), null);
  udp.close();
});

test('probe targets agree with the canary\'s name rule', () => {
  assert.throws(() => probeTargets({ independent: true, probeZone: 'probe.enclave.host', outbound: OUTBOUND }), /must not be an Enclave zone/);
  const manifest = { address: '127.0.0.1', hostname: NAME, token: TOKEN, certificateSha256: 'cd'.repeat(32), udpPort: 4444, proxy: 'u:p@127.0.0.1:1' };
  assert.ok(providerProbes(manifest, { independent: true, probeZone: ZONE, outbound: OUTBOUND, testPorts: {} }));
  for (const hostname of [`probe-${'x'.repeat(58)}.${ZONE}`, `probe-node1-.${ZONE}`])
    assert.throws(() => providerProbes({ ...manifest, hostname }, { independent: true, probeZone: ZONE, outbound: OUTBOUND, testPorts: {} }), /invalid independent probe manifest/);
  // the compatibility rule is unchanged
  assert.ok(providerProbes({ ...manifest, hostname: 'probe-local.enclave.host' }, { testPorts: {} }));
});
