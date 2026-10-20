// The host's independent management service (docs/network/independent-management.md): the gateway listener plus its
// operator-signed management record, renewed before expiry and published to operator-selected public directories.
//
//   node network/management-host.mjs /etc/enclave/management.json
//
// config: {runner, chainId, authorityPins, rpc:[…], directories:[…], listen:{host, port}, public:{address, port},
//          tlsKeyFile, tlsCertFile, operatorKeyFile, upstream:"http://127.0.0.1:8080", ttlMs?, stateDir?,
//          upstreamTokenFile? (the supervisor's MANAGEMENT_GATEWAY_TOKEN), limits? (gateway admission), browser?}
// The operator key is this host's registry/runner operator key (the one the ledger names as runnerOperator). It signs
// only the public management record here; it is never sent anywhere.
import fs from 'node:fs/promises';
import {X509Certificate, createHash} from 'node:crypto';
import {isIP} from 'node:net';
import {pathToFileURL} from 'node:url';
import {privateKeyToAccount} from 'viem/accounts';
import {LeaseReader} from './lease-reader.mjs';
import {DurableState} from './durable-state.mjs';
import {directoryOrigins} from './directory-client.mjs';
import {validateNetworkAuthorities} from './network-authorities.mjs';
import {signManagementRecord, validateManagementRecord, MANAGEMENT_RECORD_MAX_MS} from './management-record.mjs';
import {createManagementGateway} from './management-gateway.mjs';

export const spkiSha256 = cert => createHash('sha256').update(new X509Certificate(cert).publicKey.export({format: 'der', type: 'spki'})).digest('hex');

/** The record for this host now. Sequence is the issue time in ms, so it only moves forward across restarts. */
// browser: optional {origin, dashboards} - the operator's explicit choice to also serve a WebPKI HTTPS origin to those
// dashboards (record v2). Without it the record stays v1: native exact-SPKI transport only.
export function managementRecord({operator, runner, chainId = 8453, deployments, address, port, cert, now = Date.now(), ttlMs = 6 * 3600 * 1000, withdrawn = false, browser = null}) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 60000 || ttlMs > MANAGEMENT_RECORD_MAX_MS) throw Error('management record lifetime must be 1 min..24 h');
  return {version: browser ? 2 : 1, runner, operator: operator.toLowerCase(), chainId, deployments: deployments.toLowerCase(),
    address: withdrawn ? null : address, port: withdrawn ? null : port, spkiSha256: withdrawn ? null : spkiSha256(cert),
    ...(browser ? {browser: withdrawn ? null : {origin: browser.origin, dashboards: [...browser.dashboards]}} : {}),
    sequence: now, issuedAt: now, expiresAt: now + ttlMs};
}

/** POST a signed record to every directory; -> the origins that accepted it. Public data only; no credentials. */
export async function publishManagementRecord(envelope, {directories, fetch = globalThis.fetch, timeoutMs = 8000}) {
  const body = JSON.stringify(envelope);
  const results = await Promise.allSettled(directoryOrigins(directories).map(async origin => {
    const r = await fetch(origin + '/v1/network/management', {method: 'POST', redirect: 'error', credentials: 'omit',
      headers: {'content-type': 'application/json'}, body, signal: AbortSignal.timeout(timeoutMs)});
    await r.body?.cancel().catch(() => {});
    if (!r.ok) throw Error(`${origin}: HTTP ${r.status}`);
    return origin;
  }));
  const accepted = results.filter(r => r.status === 'fulfilled').map(r => r.value);
  if (!accepted.length) throw Error('no directory accepted the management record: ' + results.map(r => String(r.reason?.message).slice(0, 120)).join('; '));
  return accepted;
}

// Sequences are issue times in ms, but never repeat or go backwards: within one process (two signings in one ms, a clock
// step back) and, with config.stateDir, across restarts (the last sequence is persisted before it is published).
async function readPrivateHex(file) {
  const handle = await fs.open(file, 'r');
  try {
    const st = await handle.stat();
    if (!st.isFile() || (process.platform !== 'win32' && (st.mode & 0o077) !== 0)) throw Error(`${file} must be a private regular file`);
    return (await handle.readFile('utf8')).trim().toLowerCase();
  } finally { await handle.close(); }
}

// reader: an agreeing chain reader (LeaseReader over config.rpc, at least two independent HTTPS RPCs, by default). Every
// authorization comes from one snapshot those RPCs agree on; there is no first-answer chain client anywhere here.
export async function startManagementHost(config, {account, reader, fetch = globalThis.fetch, now = Date.now, log = console.log} = {}) {
  const pins = validateNetworkAuthorities(config.authorityPins);
  if (!/^0x[0-9a-f]{64}$/.test(config.runner || '') || !isIP(config.public?.address || '')) throw Error('management host needs its runner id and public literal address');
  if (typeof account?.signMessage !== 'function' || !/^0x[0-9a-fA-F]{40}$/.test(account?.address || '')) throw Error('management host needs its operator account');
  directoryOrigins(config.directories);
  const [key, cert] = await Promise.all([fs.readFile(config.tlsKeyFile), fs.readFile(config.tlsCertFile)]);
  // Optional browser transport: its WebPKI certificate for the origin's name, served by SNI on the same listener.
  const browser = config.browser ? {origin: config.browser.origin, dashboards: config.browser.dashboards} : null;
  const browserTls = config.browser ? {hostname: new URL(config.browser.origin).hostname,
    key: await fs.readFile(config.browser.tlsKeyFile), cert: await fs.readFile(config.browser.tlsCertFile)} : null;
  const chainId = config.chainId ?? 8453, ttlMs = config.ttlMs ?? 6 * 3600 * 1000;
  const probe = managementRecord({operator: account.address, runner: config.runner, chainId, deployments: pins.deployments, ...config.public, cert, ttlMs, browser});
  validateManagementRecord(probe, probe.issuedAt);   // the record (and browser origin) must be valid before listening
  const state = config.stateDir ? new DurableState(config.stateDir) : null;
  let last = Number((await state?.get('management-sequence'))?.sequence || 0);
  reader ||= new LeaseReader({rpc: config.rpc, chainId, addressBook: '0x' + '0'.repeat(40), authorityPins: pins, includeHostPayout: true});
  if (typeof reader?.agreed !== 'function' || reader.chainId !== chainId) throw Error('management host needs an agreeing chain reader for its chain');
  // The secret the supervisor requires (MANAGEMENT_GATEWAY_TOKEN) before it accepts this runner's management base.
  const upstreamToken = config.upstreamTokenFile ? await readPrivateHex(config.upstreamTokenFile) : null;
  if (upstreamToken !== null && !/^[0-9a-f]{64,128}$/.test(upstreamToken)) throw Error('the upstream token file must hold 32-64 bytes of hex');
  const server = createManagementGateway({tls: {key, cert}, browserTls, dashboards: browser?.dashboards, runner: config.runner, pins, reader, upstream: config.upstream,
    upstreamToken, limits: config.limits, log});
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(config.listen?.port ?? config.public.port, config.listen?.host ?? '0.0.0.0', resolve); });
  let current = null, withdrawn = false, closed = false, timer = null, tail = Promise.resolve();
  const schedule = ms => { clearTimeout(timer); if (!closed && !withdrawn) { timer = setTimeout(() => void refresh().catch(() => {}), ms); timer.unref(); } };
  const sign = async asWithdrawal => {
    const sequence = Math.max(now(), last + 1);
    const record = {...managementRecord({operator: account.address, runner: config.runner, chainId, deployments: pins.deployments,
      ...config.public, cert, now: sequence, ttlMs, withdrawn: asWithdrawal, browser})};
    const envelope = await signManagementRecord(account, record, sequence);
    await state?.set('management-sequence', {sequence});   // persisted BEFORE anything can see it
    last = sequence;
    return envelope;
  };
  // Serialized: a refresh and a withdrawal never interleave, and nothing republishes an endpoint after a withdrawal.
  const serial = fn => { const run = tail.then(fn); tail = run.catch(() => {}); return run; };
  const refresh = () => serial(async () => {
    if (withdrawn || closed) throw Error('the management endpoint was withdrawn or closed');
    current = await sign(false);
    try {
      log(`[management] record ${current.record.sequence} published to ${(await publishManagementRecord(current, {directories: config.directories, fetch})).join(', ')}`);
      schedule(Math.floor(ttlMs / 2));
    } catch (e) { log(`[management] publication failed: ${e.message}`); schedule(Math.min(60000, Math.floor(ttlMs / 4))); }
    return current;
  });
  const close = () => { closed = true; clearTimeout(timer); server.closeAllConnections?.(); server.close(); };
  try { await refresh(); }
  catch (e) { close(); throw e; }   // a host that cannot sign its record does not keep an unannounced listener open
  return {server, get record() { return current; }, refresh, close,
    withdraw: () => serial(async () => {
      withdrawn = true; clearTimeout(timer);
      current = await sign(true);
      await publishManagementRecord(current, {directories: config.directories, fetch});
      return current;
    })};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const config = JSON.parse(await fs.readFile(process.argv[2], 'utf8'));
  const keyFile = await fs.open(config.operatorKeyFile, 'r');
  let hex;
  try {
    const st = await keyFile.stat();
    if (!st.isFile() || (process.platform !== 'win32' && (st.mode & 0o077) !== 0)) throw Error('the operator key file must be a private regular file');
    hex = (await keyFile.readFile('utf8')).trim();
  } finally { await keyFile.close(); }
  await startManagementHost(config, {account: privateKeyToAccount(hex.startsWith('0x') ? hex : '0x' + hex)});
}
