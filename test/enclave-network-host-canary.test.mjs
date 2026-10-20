// network/enclave-network-host.mjs createNetworkHost wires direct.probe (the provider canary, provider-canary.mjs) into the
// direct runtime: judged before anything is read or bound, started after every other check, listening from startup so a
// checker can reach it, and released completely - by close(), or when any step of the start fails. Bound sockets are
// counted with process.getActiveResourcesInfo() before and after each case: nothing may be left behind.
//   run: node --test test/enclave-network-host-canary.test.mjs
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import dgram from 'node:dgram';
import path from 'node:path';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { createNetworkHost, directProbeConfig } from '../network/enclave-network-host.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'network-host-canary-'));
const f = (n) => path.join(dir, n);
const ZONE = 'probe.alice-net.org', NAME = `probe-node1.${ZONE}`, ADDRESS = '44.0.0.7';
const account = privateKeyToAccount(generatePrivateKey());
const freeTcp = () => new Promise((ok) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => ok(p)); }); });
const freeUdp = async () => { const u = dgram.createSocket('udp4'); await new Promise((r) => u.bind(0, '127.0.0.1', r)); const p = u.address().port; await new Promise((r) => u.close(r)); return p; };
const tcpFree = (port) => new Promise((ok) => { const s = net.createServer().once('error', () => ok(false)).listen(port, '127.0.0.1', () => s.close(() => ok(true))); });
const udpFree = (port) => new Promise((ok) => { const u = dgram.createSocket('udp4'); u.once('error', () => { u.close(); ok(false); }); u.bind(port, '127.0.0.1', () => u.close(() => ok(true))); });
// the sockets this process holds open, by kind
const held = () => { const n = { tcp: 0, udp: 0 }; for (const r of process.getActiveResourcesInfo()) { if (r === 'TCPServerWrap' || r === 'TCPSocketWrap') n.tcp++; if (r === 'UDPWrap') n.udp++; } return n; };
const settle = () => new Promise((r) => setTimeout(r, 50));
// the baseline after earlier cases' closed handles are gone
const baseline = async () => { await settle(); return held(); };

let ports;
const probe = (over = {}) => ({ independent: true, probeZone: ZONE, hostname: NAME, keyFile: f('canary.key'), certFile: f('canary.pem'), tokenFile: f('token'),
                                udpPort: ports.udp, bindHost: '127.0.0.1', manifestFile: f(`manifest-${Math.random().toString(16).slice(2)}.json`), ...over });
const config = (p, over = {}, direct = {}) => ({ directories: ['https://dir.alice-net.org'], checkers: ['0x' + '45'.repeat(20)], apps: 'all',
  wgBinary: process.execPath, nodeBinary: process.execPath, workerModule: path.join(ROOT, 'network', 'windows-circuit-worker.mjs'),
  direct: { address: ADDRESS, bindHost: '127.0.0.1', httpsPort: ports.https, httpPort: ports.http, qualificationFile: f('qualification.json'), ...(p !== undefined ? { probe: p } : {}), ...direct }, ...over });
const start = (c, extra = {}) => createNetworkHost({ config: c, account, runner: '0x' + '42'.repeat(32), rpc: [], leaseReader: { get: () => null }, directory: dir,
  authorize: () => false, forward: (s) => s.destroy(), ...extra });

before(async () => {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', `/CN=${NAME}`, '-days', '1',
    '-keyout', f('canary.key'), '-out', f('canary.pem')], { stdio: 'ignore' });
  fs.writeFileSync(f('token'), 'ab'.repeat(32), { mode: 0o600 });
  ports = { https: await freeTcp(), http: await freeTcp(), udp: await freeUdp() };
});

const get = (hostHeader) => new Promise((ok, no) => http.get({ host: '127.0.0.1', port: ports.http, path: `/__provider_probe/${'ab'.repeat(32)}`, headers: { host: hostHeader }, agent: false },
  (r) => { let b = ''; r.on('data', (d) => { b += d; }); r.on('end', () => ok({ status: r.statusCode, body: b })); }).on('error', no));

test('with direct.probe the host listens from startup, serves the canary, and close() releases everything', async () => {
  const before_ = await baseline(), p = probe(), host = await start(config(p));
  try {
  const r = host.direct.runtime;
  assert.equal(r.canary.hostname, NAME); assert.deepEqual([r.httpsPort, r.httpPort], [ports.https, ports.http]);
  assert.equal(await tcpFree(ports.https), false); assert.equal(await tcpFree(ports.http), false); assert.equal(await udpFree(ports.udp), false);
  assert.equal(JSON.parse(fs.readFileSync(p.manifestFile, 'utf8')).hostname, NAME);
  // the canary answers its challenge through the runtime's public HTTP port, with its own Host header only
  assert.deepEqual(await get(NAME), { status: 200, body: 'ab'.repeat(32) });
  assert.equal((await get('probe-node1.enclave.host')).status, 421);
  } finally { await host.close(); }
  await host.close();   // idempotent
  await settle();
  assert.deepEqual(held(), before_, 'no socket left open');   // counted before the port probes below open their own
  assert.ok(await tcpFree(ports.https) && await tcpFree(ports.http) && await udpFree(ports.udp), 'every port is free again');
});

test('without direct.probe the direct runtime starts exactly as before: nothing listens until the first direct app', async () => {
  const before_ = await baseline(), host = await start(config(undefined));
  try {
  assert.ok(host.direct.runtime); assert.equal(host.direct.runtime.canary, undefined); assert.equal(host.direct.runtime.listening, undefined);
  assert.ok(await tcpFree(ports.https) && await tcpFree(ports.http));
  } finally { await host.close(); }
  await settle(); assert.deepEqual(held(), before_);
  // and a host without direct hosting has nothing to close
  const plain = await start({ ...config(undefined), direct: undefined }); assert.equal(plain.direct, null); await plain.close();
});

test('a malformed direct.probe is refused before any file is read or anything is bound', async () => {
  const before_ = await baseline(), missing = { keyFile: f('none.key'), certFile: f('none.pem'), tokenFile: f('none-token') };
  for (const [bad, why] of [
    [null, /direct.probe must be an object/], [[], /direct.probe must be an object/],
    [probe({ zone: ZONE }), /unknown field\(s\): zone/],
    [probe({ keyFile: 'canary.key' }), /keyFile must be an absolute path/],
    [probe({ manifestFile: undefined }), /manifestFile must be an absolute path/],
    [probe({ udpPort: 80 }), /udpPort must be 1024-65535/], [probe({ udpPort: '9000' }), /udpPort must be 1024-65535/],
    [probe({ bindHost: 'localhost' }), /bindHost must be an IP address/],
    [probe({ independent: 'yes' }), /independent must be true or false/],
    [probe({ probeZone: undefined, ...missing }), /needs its reviewed probe zone/],
    [probe({ probeZone: 'probe.enclave.host', hostname: 'probe-node1.probe.enclave.host', ...missing }), /must not be an Enclave zone/],
    [probe({ hostname: 'probe-node1.probe.evil-net.org', ...missing }), /must be in its probe zone/],
    [probe({ independent: undefined, ...missing }), /probeZone is for an independent canary/],
    [probe({ independent: false, probeZone: undefined, hostname: NAME, ...missing }), /invalid provider canary configuration/],
  ]) {
    const e = await start(config(bad)).then(() => null, (x) => x);
    assert.ok(e, JSON.stringify(bad)); assert.match(e.message, why); assert.doesNotMatch(e.message, /ENOENT/);
  }
  assert.deepEqual(held(), before_); assert.ok(await tcpFree(ports.https) && await udpFree(ports.udp));
});

test('a start that fails at any step leaves nothing bound', async () => {
  const before_ = await baseline();
  // the canary cannot read its certificate
  let p = probe({ certFile: f('missing.pem') });
  await assert.rejects(start(config(p)), /ENOENT/);
  // its UDP port is taken: the canary closes the TLS endpoint it had already opened (provider-canary.mjs)
  const squat = dgram.createSocket('udp4'); await new Promise((r) => squat.bind(ports.udp, '127.0.0.1', r));
  p = probe(); await assert.rejects(start(config(p)), /EADDRINUSE/); assert.ok(!fs.existsSync(p.manifestFile));
  await new Promise((r) => squat.close(r));
  // the runtime's public port is taken: the canary that had started is closed with it
  const blocker = net.createServer().listen(ports.https, '127.0.0.1'); await new Promise((r) => blocker.once('listening', r));
  p = probe(); await assert.rejects(start(config(p)), /EADDRINUSE/);
  await new Promise((r) => blocker.close(r));
  // a check after the direct block refuses the configuration: the canary is never started at all
  p = probe(); await assert.rejects(start(config(p, { hostEgress: { apps: 'some' } })), /hostEgress\.apps/); assert.ok(!fs.existsSync(p.manifestFile));
  await settle();
  assert.deepEqual(held(), before_, 'no socket left open by any failed start');
  assert.ok(await tcpFree(ports.https) && await tcpFree(ports.http) && await udpFree(ports.udp));
});

test('owner-committed names and the canary coexist; the legacy canary name still starts', async () => {
  const before_ = await baseline();
  const host = await start(config(probe(), {}, { ownerNames: { gateways: ['https://gateway.alice-net.org'] } }), { attestedKey: () => null });
  try { assert.ok(host.direct.runtime.ownerNames, 'the owner-name source is kept'); assert.equal(host.direct.runtime.canary.hostname, NAME); }
  finally { await host.close(); }
  const legacy = await start(config(probe({ independent: undefined, probeZone: undefined, hostname: 'probe-node1.enclave.host' })));
  try { assert.equal(legacy.direct.runtime.canary.hostname, 'probe-node1.enclave.host'); } finally { await legacy.close(); }
  await settle(); assert.deepEqual(held(), before_);
  const p = probe(); assert.deepEqual(directProbeConfig(p), p, 'a valid probe passes through unchanged');
});
