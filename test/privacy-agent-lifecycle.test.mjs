// The REAL daemon (node network/privacy-agent.mjs --config FILE) with a qualification canary configured
// (enclaveNetwork.direct.probe, enclave-network-host.mjs): its listeners exist from startup, so the daemon must release
// them itself. This runs the daemon as a child process and checks, from outside, that
//   * after a normal start, SIGTERM makes the process EXIT on its own and frees the canary's UDP port and the direct
//     runtime's public ports;
//   * a start that fails (agent.start() cannot write its status) exits with an error and frees them too;
//   * a malformed probe is refused before anything is bound.
// The configuration has no Enclave authority (pinned contracts, unreachable operator RPCs, a non-Enclave probe zone) and
// every *.enclave.host lookup or connection is refused and logged. Each child is killed in `finally` with a hard
// deadline, so a regression shows as a failure, never as a hung test.
//   run: node --test --test-concurrency=1 test/privacy-agent-lifecycle.test.mjs
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import dgram from 'node:dgram';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { generatePrivateKey } from 'viem/accounts';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const AGENT = path.join(ROOT, 'network', 'privacy-agent.mjs');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-lifecycle-'));
const f = (n) => path.join(dir, n);
const ZONE = 'probe.alice-net.org', NAME = `probe-node1.${ZONE}`;
const freeTcp = () => new Promise((ok) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => ok(p)); }); });
const freeUdp = async () => { const u = dgram.createSocket('udp4'); await new Promise((r) => u.bind(0, '127.0.0.1', r)); const p = u.address().port; await new Promise((r) => u.close(r)); return p; };
const tcpFree = (port) => new Promise((ok) => { const s = net.createServer().once('error', () => ok(false)).listen(port, '127.0.0.1', () => s.close(() => ok(true))); });
const udpFree = (port) => new Promise((ok) => { const u = dgram.createSocket('udp4'); u.once('error', () => { u.close(); ok(false); }); u.bind(port, '127.0.0.1', () => u.close(() => ok(true))); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PRELOAD = `import net from 'node:net'; import dns from 'node:dns'; import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
const enclave = (h) => /(^|\\.)enclave\\.host\\.?$/i.test(String(h || ''));
const refuse = (h) => { fs.appendFileSync(process.env.BLOCK_LOG, String(h) + '\\n'); return Object.assign(new Error('blocked ' + h), { code: 'ENOTFOUND' }); };
const lookup = dns.lookup, plookup = dns.promises.lookup;
dns.lookup = function (h, ...a) { if (enclave(h)) return process.nextTick(a.at(-1), refuse(h)); return lookup.call(this, h, ...a); };
dns.promises.lookup = async function (h, ...a) { if (enclave(h)) throw refuse(h); return plookup.call(this, h, ...a); };
syncBuiltinESMExports();
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...a) { const o = Array.isArray(a[0]) ? a[0][0] : (a[0] && typeof a[0] === 'object' ? a[0] : null);
  if (o && enclave(o.host)) { const e = refuse(o.host); process.nextTick(() => this.destroy(e)); return this; } return connect.apply(this, a); };`;

let ports;
before(async () => {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', `/CN=${NAME}`, '-days', '1',
    '-keyout', f('canary.key'), '-out', f('canary.pem')], { stdio: 'ignore' });
  fs.writeFileSync(f('token'), 'ab'.repeat(32), { mode: 0o600 });
  fs.writeFileSync(f('operator.key'), generatePrivateKey(), { mode: 0o600 });
  fs.writeFileSync(f('expected.json'), JSON.stringify({ appRef: 'catalog://0x' + '12'.repeat(32) + '/1', configCid: '' }));
  for (const n of ['runtime.json', 'min-tcb.json']) fs.writeFileSync(f(n), '{}');
  fs.writeFileSync(f('vcek.der'), 'not used before an app is probed');
  fs.writeFileSync(f('preload.mjs'), PRELOAD);
  ports = { https: await freeTcp(), http: await freeTcp(), udp: await freeUdp(), upstream: await freeTcp() };
});

/** A daemon configuration (privacy-config.json) with no Enclave authority and the canary in the operator's zone. */
function daemonConfig(name, { probe = {}, state = f(`state-${name}`) } = {}) {
  fs.mkdirSync(state, { recursive: true });
  const file = f(`privacy-config-${name}.json`);
  fs.writeFileSync(file, JSON.stringify({ version: 2, directory: state, operatorKeyFile: f('operator.key'), runner: '0x' + '42'.repeat(32),
    apps: [{ deploymentId: '0x' + 'ab'.repeat(32), names: ['app1.alice-net.org'], expectedFile: f('expected.json') }],
    dns: ['9.9.9.9'], upstream: `http://127.0.0.1:${ports.upstream}`,
    // the operator's RPCs (unreachable here: startup must not need the chain) and pinned contracts, no address book read
    chain: { rpc: ['https://127.0.0.2:1', 'https://127.0.0.3:1'], addressBook: '0x' + '00'.repeat(20),
             authorityPins: { deployments: '0x' + '11'.repeat(20), registry: '0x' + '22'.repeat(20), connectivity: '0x' + '00'.repeat(20), sessionVaultFactory: '0x' + '00'.repeat(20) } },
    linux: { runtimeFile: f('runtime.json'), minTcbFile: f('min-tcb.json'), vcekFile: f('vcek.der') },
    enclaveNetwork: { directories: ['https://dir.alice-net.org'], checkers: ['0x' + '45'.repeat(20)], apps: 'all',
      wgBinary: process.execPath, nodeBinary: process.execPath, workerModule: path.join(ROOT, 'network', 'windows-circuit-worker.mjs'),
      direct: { address: '44.0.0.7', bindHost: '127.0.0.1', httpsPort: ports.https, httpPort: ports.http, qualificationFile: f('qualification.json'),
        probe: { independent: true, probeZone: ZONE, hostname: NAME, keyFile: f('canary.key'), certFile: f('canary.pem'), tokenFile: f('token'),
                 udpPort: ports.udp, bindHost: '127.0.0.1', manifestFile: f(`manifest-${name}.json`), ...probe } } } }), { mode: 0o600 });
  return { file, state };
}

/** Start the real daemon; -> { child, output(), exited: Promise<{code, signal}> }. */
function daemon(file, blockLog) {
  const child = spawn(process.execPath, ['--import', pathToFileURL(f('preload.mjs')).href, AGENT, '--config', file],
    { env: { ...process.env, BLOCK_LOG: blockLog }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; child.stdout.on('data', (d) => { out += d; }); child.stderr.on('data', (d) => { out += d; });
  const exited = new Promise((ok) => child.once('exit', (code, signal) => ok({ code, signal })));
  return { child, output: () => out, exited };
}
const until = async (what, cond, ms) => { const t0 = Date.now(); while (!(await cond())) { if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(100); } };
const within = (p, ms) => Promise.race([p, sleep(ms).then(() => null)]);
const released = async () => ({ https: await tcpFree(ports.https), http: await tcpFree(ports.http), udp: await udpFree(ports.udp) });

test('the daemon serves its canary from startup, and on SIGTERM exits by itself and releases every listener', { timeout: 90_000 }, async () => {
  const { file, state } = daemonConfig('sigterm'), blockLog = f('blocked-sigterm.log'); fs.writeFileSync(blockLog, '');
  const d = daemon(file, blockLog);
  try {
    await until('the canary', () => d.output().includes(`qualification canary ${NAME}`) || d.child.exitCode !== null, 30_000);
    assert.equal(d.child.exitCode, null, d.output());
    // started: the agent wrote its status, after the chain refresh failed against the unreachable RPCs (no chain needed)
    await until('the agent status', () => fs.existsSync(path.join(state, 'status.json')), 30_000); await sleep(1500);
    assert.deepEqual(await released(), { https: false, http: false, udp: false }, 'the canary and the direct runtime listen');
    d.child.kill('SIGTERM');
    const exit = await within(d.exited, 20_000);
    assert.ok(exit, `the daemon did not exit after SIGTERM:\n${d.output().slice(-2000)}`);
    assert.equal(exit.signal, null, 'it exited by itself, not by a signal default');
    assert.equal(exit.code, 0, d.output().slice(-2000));
    assert.deepEqual(await released(), { https: true, http: true, udp: true }, 'every port is free again');
    assert.equal(fs.readFileSync(blockLog, 'utf8'), '', 'no enclave.host name was looked up or connected to');
  } finally { if (d.child.exitCode === null && d.child.signalCode === null) d.child.kill('SIGKILL'); await within(d.exited, 5000); }
});

test('a failed agent start exits with an error and releases every listener', { timeout: 90_000 }, async () => {
  // the agent cannot write its status (the path is a directory), so agent.start() fails after the network host started
  const { file, state } = daemonConfig('failed-start'); fs.mkdirSync(path.join(state, 'status.json'));
  const blockLog = f('blocked-failed.log'); fs.writeFileSync(blockLog, '');
  const d = daemon(file, blockLog);
  try {
    const exit = await within(d.exited, 45_000);
    assert.ok(exit, `the daemon did not exit after its start failed:\n${d.output().slice(-2000)}`);
    assert.equal(exit.code, 1); assert.match(d.output(), /EISDIR/);
    assert.match(d.output(), new RegExp(`qualification canary ${NAME.replace(/\./g, '\\.')}`), 'the host had started its canary before the failure');
    assert.deepEqual(await released(), { https: true, http: true, udp: true });
    assert.equal(fs.readFileSync(blockLog, 'utf8'), '');
  } finally { if (d.child.exitCode === null && d.child.signalCode === null) d.child.kill('SIGKILL'); await within(d.exited, 5000); }
});

test('a malformed probe stops the daemon before anything is bound', { timeout: 60_000 }, async () => {
  const { file } = daemonConfig('malformed', { probe: { probeZone: 'probe.enclave.host', hostname: 'probe-node1.probe.enclave.host' } });
  const blockLog = f('blocked-malformed.log'); fs.writeFileSync(blockLog, '');
  const d = daemon(file, blockLog);
  try {
    const exit = await within(d.exited, 30_000);
    assert.ok(exit, 'the daemon did not exit'); assert.equal(exit.code, 1);
    assert.match(d.output(), /direct\.probe: .*must not be an Enclave zone/);
    assert.ok(!fs.existsSync(f('manifest-malformed.json')), 'no canary was started');
    assert.deepEqual(await released(), { https: true, http: true, udp: true });
  } finally { if (d.child.exitCode === null && d.child.signalCode === null) d.child.kill('SIGKILL'); await within(d.exited, 5000); }
});
