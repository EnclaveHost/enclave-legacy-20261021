// Test-only process fixture: the ACTUAL supervisor.js, unmodified and without any self-test seam, started as a child
// process whose world is local:
//   - chain reads: BASE_RPC is a local JSON-RPC server answering the session vault and factory calls from `chain`;
//   - the app manager: VMMGR_URL is a local HTTP server answering logs, CPU profile, delete and relaunch, and recording
//     each side effect;
//   - the deployment: a seeded STATE_FILE, loaded by the supervisor's own loadState;
//   - the network: a preload (loopback-only-fetch.mjs) refuses every non-loopback fetch, so the public RPC fallbacks and
//     any Enclave domain are unreachable.
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import {decodeFunctionData, encodeFunctionResult, getAddress} from 'viem';
import {VAULT_ABI, FACTORY_ABI} from '../../windows/node/session-api-auth.mjs';

const ABI = [...VAULT_ABI, ...FACTORY_ABI];
const freePort = () => new Promise(r => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const readJson = req => new Promise((resolve, reject) => { const c = []; req.on('data', d => c.push(d)); req.once('end', () => { try { resolve(c.length ? JSON.parse(Buffer.concat(c)) : null); } catch (e) { reject(e); } }); });
const ZERO32 = '0x' + '00'.repeat(32);

// chain: {factory, vaults: {<vault lc>: {owner, held: {<id>: env}, sessions: {<sid>: {keyHash, actions, envs, expiresAt, live}}}}}
function rpcServer(chain) {
  const call = ({to, data}) => {
    const {functionName, args} = decodeFunctionData({abi: ABI, data});
    const at = String(to).toLowerCase(), v = chain.vaults[at];
    let result;
    if (functionName === 'isVault') { if (at !== chain.factory.toLowerCase()) throw Error('not the factory'); result = !!chain.vaults[String(args[0]).toLowerCase()]; }
    else if (!v) throw Error('no contract');
    else if (functionName === 'owner') result = getAddress(v.owner);
    else if (functionName === 'held') result = [v.held[String(args[0]).toLowerCase()] || 0, ZERO32, ZERO32];
    else if (functionName === 'sessionOf') {
      const x = v.sessions[String(args[0]).toLowerCase()];
      const s = x || {keyHash: ZERO32, actions: '0', envs: 0, expiresAt: 0, live: false};
      result = [{keyHash: s.keyHash, measurement: ZERO32, actions: BigInt(s.actions), expiresAt: BigInt(s.expiresAt), epoch: 0n, envs: s.envs, state: 0, anyApp: false,
        balance6: 0n, spent6: 0n, perPeriod6: 0n, maxFee6: 0n, maxAppFeeHour6: 0n, maxRateHour6: 0n, periodStart: 0n, period: 0, opsPerPeriod: 0, periodSpent6: 0n, periodOps: 0},
        !!(x && x.live), []];
    } else throw Error('unscripted');
    return encodeFunctionResult({abi: ABI, functionName, result});
  };
  const one = m => {
    try {
      if (m.method === 'eth_chainId') return {result: '0x2105'};
      if (m.method === 'eth_blockNumber') return {result: '0x100'};
      if (m.method === 'eth_getLogs') return {result: []};
      if (m.method === 'eth_call') return {result: call(m.params[0])};
      return {error: {code: -32601, message: 'not available in this fixture'}};
    } catch (e) { return {error: {code: 3, message: 'execution reverted: ' + e.message, data: '0x'}}; }
  };
  return http.createServer(async (req, res) => {
    const body = await readJson(req).catch(() => null);
    const answer = Array.isArray(body) ? body.map(m => ({jsonrpc: '2.0', id: m.id, ...one(m)})) : {jsonrpc: '2.0', id: body?.id, ...one(body || {})};
    res.writeHead(200, {'content-type': 'application/json'}); res.end(JSON.stringify(answer));
  });
}

function managerServer({vmId, logs, effects}) {
  return http.createServer(async (req, res) => {
    const body = await readJson(req).catch(() => null);
    const json = (status, value) => { res.writeHead(status, {'content-type': 'application/json'}); res.end(JSON.stringify(value)); };
    const u = new URL(req.url, 'http://manager.local');
    if (req.method === 'GET' && u.pathname === `/vms/${vmId}/logs`) return json(200, {id: vmId, status: 'running', lines: logs, exited: false});
    if (u.pathname === `/vms/${vmId}/cpu-profile`) {
      if (req.method === 'GET') return json(200, {state: 'complete', seconds: 5, frequencyHz: 49, error: null, format: 'gperftools', oneCapturePerProcess: true,
        bytes: 4, data: Buffer.from('prof').toString('base64')});
      effects.push({cpuProfile: body});
      return json(200, {state: body?.action === 'start' ? 'active' : 'complete', seconds: body?.seconds ?? null, frequencyHz: 49, error: null, format: 'gperftools', oneCapturePerProcess: true});
    }
    if (req.method === 'DELETE' && u.pathname.startsWith('/vms/')) { effects.push({deleted: u.pathname.slice(5)}); return json(200, {}); }
    if (req.method === 'POST' && u.pathname === '/vms') { effects.push({launched: body?.name}); return json(201, {id: vmId, hostPort: 0, status: 'running'}); }
    if (req.method === 'GET' && u.pathname.startsWith('/vms/')) return json(200, {id: vmId, status: 'running'});
    if (req.method === 'GET' && u.pathname === '/vms') return json(200, []);
    return json(200, {ok: true});
  });
}

/**
 * -> {port, effects, stdout()} once the supervisor listens. `env` adds or overrides supervisor environment.
 * deployment: {id, owner} - restored as a running, private, vm-backed record with an app instance.
 */
export async function startActualSupervisor(t, {chain, deployment, pins, publicUrl, env = {}, logs = ['booted', 'serving']}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'management-supervisor-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const effects = [], vmId = 'vm-management-1';
  const rpc = rpcServer(chain), manager = managerServer({vmId, logs, effects});
  await Promise.all([rpc, manager].map(s => new Promise(r => s.listen(0, '127.0.0.1', r))));
  t.after(() => { for (const s of [rpc, manager]) { s.closeAllConnections?.(); s.close(); } });
  const pinFile = path.join(dir, 'pins.json');
  fs.writeFileSync(pinFile, JSON.stringify({version: 1, chainId: 8453, contracts: pins}));
  const stateFile = path.join(dir, 'state.json');
  fs.writeFileSync(stateFile, JSON.stringify({savedAt: Date.now(), deployments: [{id: deployment.id, owner: getAddress(deployment.owner), status: 'running', public: false,
    firewall: [], image: {reference: 'catalog://0x' + '00'.repeat(32) + '/0'}, command: [], config: '', resources: {cpuShare: 0.1, gpuShare: 0},
    network: {port: 8080, protocol: 'https'}, remainingMs: null, _vmId: vmId, _port: 0, startedAt: Date.now(), createdAt: new Date().toISOString()}]}));
  const port = await freePort();
  const child = spawn(process.execPath, ['--import', new URL('./loopback-only-fetch.mjs', import.meta.url).pathname, 'supervisor.js'], {
    cwd: new URL('../..', import.meta.url).pathname,
    env: {PATH: process.env.PATH, HOME: dir, SECRET: 'management-fixture-secret', PORT: String(port), ENABLE_MPS: '0', STATE_FILE: stateFile,
      PROVISION_BACKEND: 'vm', VMMGR_URL: `http://127.0.0.1:${manager.address().port}`, BASE_RPC: `http://127.0.0.1:${rpc.address().port}`,
      ENCLAVE_CONTRACT_PINS_FILE: pinFile, ADDRESS_BOOK_ADDRESS: '', PUBLIC_URL: publicUrl, SECRETS_API: '', DOMAINS_API: '', CERTS_API: '', DNS_API: '',
      APP_CERT_DOMAIN: '', CLAIM_ENABLED: '', REGISTRY_ENABLED: '', ...env},
  });
  t.after(() => child.kill('SIGKILL'));
  let out = '';
  child.stdout.on('data', d => { out += d; }); child.stderr.on('data', d => { out += d; });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('the supervisor did not start:\n' + out.slice(-2000))), 30000);
    const check = () => { if (out.includes(`enclave supervisor on :${port}`)) { clearTimeout(timer); resolve(); } };
    child.stdout.on('data', check);
    child.once('exit', code => { clearTimeout(timer); reject(Error(`the supervisor exited ${code}:\n` + out.slice(-2000))); });
  });
  return {port, effects, stdout: () => out};
}
