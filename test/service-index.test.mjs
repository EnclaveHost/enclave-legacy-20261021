// Open participation on a REAL local chain (anvil): the ownerless EnclaveServiceIndex compiled from the reviewed source
// with the repo's solc-js, the reader in network/service-index.mjs, the operator command scripts/network/service-index.mjs,
// and the provider's explicit bootstrap (network/wg-provider/main.mjs --check-config, install.sh --config-only).
// The keys used here are anvil's published test keys and keys made in the test; nothing touches a public network.
//   run: node --test test/service-index.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import nodeHttp from 'node:http';
import { createRequire } from 'node:module';
import path from 'node:path';
import { spawn, spawnSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createPublicClient, createWalletClient, http, keccak256, defineChain } from 'viem';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import * as si from '../network/service-index.mjs';
import { providerIdFor, signProviderRecord, qualificationMessage, CHECKS } from '../network/provider-directory.mjs';
import { grantMessage } from '../network/wg-provider/provider.mjs';
import { wireGuardKeypair } from '../network/wg-grants.mjs';
import { probeTargets, providerProbes } from '../network/provider-probes.mjs';
import { recoverMessageAddress, encodeFunctionData, keccak256 as k256, toBytes, parseAbi } from 'viem';
import { compileServiceIndex, main as cli } from '../scripts/network/service-index.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const run = promisify(execFile);
const HAVE_ANVIL = spawnSync('anvil', ['--version'], { stdio: 'ignore' }).status === 0;
const KEYS = { governor: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', alice: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
               bob: '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a', payer: '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6' };
const acct = Object.fromEntries(Object.entries(KEYS).map(([k, v]) => [k, privateKeyToAccount(v)]));
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'service-index-'));
const freePort = () => new Promise((ok) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => ok(p)); }); });

async function anvil() {
  const port = await freePort(), p = spawn('anvil', ['--port', String(port), '--silent', '--chain-id', '31337'], { stdio: 'ignore' });
  const url = `http://127.0.0.1:${port}`, chain = defineChain({ id: 31337, name: 'anvil', nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [url] } } });
  const pub = createPublicClient({ chain, transport: http(url) });
  for (let i = 0; i < 100; i++) { try { await pub.getBlockNumber(); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
  const wallet = (k) => createWalletClient({ account: acct[k] || privateKeyToAccount(k), chain, transport: http(url) });
  const mine = (n = 3) => pub.request({ method: 'anvil_mine', params: [`0x${n.toString(16)}`] });
  return { url, pub, wallet, mine, chain, stop: () => p.kill() };
}
let A, B, A2, built, index, pin;   // A2: an honest proxy in front of chain A on its own loopback port (a second distinct vote)
let skewMs = 0;   // how far evm_increaseTime (and back-to-back mining) has moved chain A's clock ahead of this one
/** A reader whose clock follows chain A (auto-mined blocks run ahead of the wall clock); freshness itself is tested with explicit clocks. */
const syncClock = async () => { const ts = Number((await A.pub.getBlock()).timestamp) * 1000; skewMs = Math.max(skewMs, ts - Date.now() + 1000); };
const reader = async (clients = [A.pub, A2.pub], over = {}) => { await syncClock(); return si.readServiceIndex({ clients, pin, now: () => Date.now() + skewMs, ...over })
  .catch((e) => { if (e.evidence) e.message += ' ' + JSON.stringify(e.evidence); throw e; }); };
const write = async (who, functionName, args) => {
  const { request } = await A.pub.simulateContract({ address: index, abi: si.SERVICE_INDEX_ABI, account: acct[who] || privateKeyToAccount(who), functionName, args });
  const r = await A.pub.waitForTransactionReceipt({ hash: await A.wallet(who).writeContract(request) });
  assert.equal(r.status, 'success'); await A.mine();
};
const later = async (sec) => Number((await A.pub.getBlock()).timestamp) + sec;

before(async () => {
  if (!HAVE_ANVIL) return;
  built = compileServiceIndex();
  [A, B] = await Promise.all([anvil(), anvil()]);
  // the "former governor" deploys it - and, as the tests show, gains nothing by having done so
  for (const chain of [A, B]) {
    const hash = await chain.wallet('governor').deployContract({ abi: built.abi, bytecode: built.bytecode });
    const r = await chain.pub.waitForTransactionReceipt({ hash }); await chain.mine();
    index = r.contractAddress;   // the same deployer and nonce on both chains: the same address
  }
  pin = si.validateIndexPin({ chainId: 31337, address: index, codeHash: built.codeHash });
  // one RPC endpoint is one vote: a second view of chain A needs its own endpoint (a loopback test port here)
  A2 = await rpcProxy('honest'); A2.pub = createPublicClient({ chain: A.chain, transport: http(A2.url) });
});
after(async () => { await A2?.close(); A?.stop(); B?.stop(); });
const skip = HAVE_ANVIL ? false : 'anvil not installed';

test('the pin is reproducible from the reviewed source and the chain; other code is refused', { skip }, async () => {
  const lines = []; await cli(['pin', '--index', index, '--chain-id', '31337', '--rpc', A.url, '--rpc', A2.url], (s) => lines.push(s));
  const p = JSON.parse(lines[0]);
  assert.equal(p.codeHash, keccak256(await A.pub.getCode({ address: index })));
  assert.equal(p.address, index.toLowerCase());
  await assert.rejects(cli(['pin', '--index', acct.alice.address, '--chain-id', '31337', '--rpc', A.url, '--rpc', A2.url], () => {}), /is not the reviewed source/);
  await assert.rejects(cli(['pin', '--index', index, '--chain-id', '8453', '--rpc', A.url, '--rpc', A2.url], () => {}), /fewer than two RPCs on chain 8453 reported a head/);
  await assert.rejects(reader([A.pub, A2.pub], { pin: { ...pin, codeHash: '0x' + '11'.repeat(32) } }), /not the pinned/);
});

test('two operators register independently: directly, and signed with a separate gas payer; both are untrusted candidates', { skip }, async () => {
  const dir = tmp(), aliceKey = path.join(dir, 'alice.key'), bobKey = path.join(dir, 'bob.key'), payerKey = path.join(dir, 'payer.key'), pinFile = path.join(dir, 'pin.json');
  fs.writeFileSync(aliceKey, KEYS.alice); fs.writeFileSync(bobKey, KEYS.bob); fs.writeFileSync(payerKey, KEYS.payer); fs.writeFileSync(pinFile, JSON.stringify(pin));
  const say = []; const o = (s) => say.push(s);
  // alice: a directory, with a content-addressed descriptor, published directly from her key
  await cli(['descriptor', '--kind', 'directory', '--operator', acct.alice.address, '--endpoint', 'https://dir.alice-net.org', '--key', 'recordKey=0xabc', '--out', path.join(dir, 'alice-desc.json')], o);
  const descHash = JSON.parse(say.at(-1)).descriptor;
  await cli(['prepare-publish', '--pin', pinFile, '--rpc', A.url, '--rpc', A2.url, '--operator', acct.alice.address, '--slot', '0', '--kind', 'directory',
             '--endpoint', 'https://dir.alice-net.org', '--endpoint', 'http://8.8.4.4:8080/', '--descriptor', path.join(dir, 'alice-desc.json'), '--ttl-days', '7', '--out', path.join(dir, 'alice.json')], o);
  await assert.rejects(cli(['send', '--prepared', path.join(dir, 'alice.json'), '--rpc', A.url, '--rpc', A2.url, '--key-file', aliceKey], o), /--yes/, 'nothing is sent without --yes');
  await cli(['send', '--prepared', path.join(dir, 'alice.json'), '--rpc', A.url, '--rpc', A2.url, '--key-file', aliceKey, '--yes'], o); await A.mine();
  // bob: a checker, signed offline by bob, submitted by a gas payer
  await cli(['prepare-publish', '--pin', pinFile, '--rpc', A.url, '--rpc', A2.url, '--operator', acct.bob.address, '--slot', '2', '--kind', 'checker',
             '--endpoint', 'https://check.bob-ops.net', '--out', path.join(dir, 'bob.json')], o);
  await assert.rejects(cli(['sign', '--prepared', path.join(dir, 'bob.json'), '--key-file', aliceKey], o), /not the ad's operator/, 'the wrong signer is refused before signing');
  const sig = []; await cli(['sign', '--prepared', path.join(dir, 'bob.json'), '--key-file', bobKey], (s) => sig.push(s));
  await assert.rejects(cli(['send', '--prepared', path.join(dir, 'bob.json'), '--rpc', A.url, '--rpc', A2.url, '--key-file', payerKey, '--yes'], o), /must be the operator/);
  await cli(['send', '--prepared', path.join(dir, 'bob.json'), '--rpc', A.url, '--rpc', A2.url, '--key-file', payerKey, '--yes', '--signature', sig[0]], o); await A.mine();

  const r = await reader();
  const alice = r.candidates.find((c) => c.operator === acct.alice.address.toLowerCase()), bob = r.candidates.find((c) => c.operator === acct.bob.address.toLowerCase());
  assert.deepEqual(alice.endpoints, ['https://dir.alice-net.org/', 'http://8.8.4.4:8080/']); assert.equal(alice.kindName, 'directory'); assert.equal(alice.descriptor, descHash);
  assert.equal(bob.kindName, 'checker'); assert.equal(bob.slot, 2);
  for (const c of r.candidates) assert.equal(c.trust, 'untrusted-candidate');
  assert.match(r.notice, /does not prove honest content, organizational independence \(distinct keys are not distinct organizations\), an accepted host owner or checker authority/);
  assert.match(r.notice, /Nothing here is admitted automatically/);
  // the descriptor is checked against the ad that committed to it, and is still only the operator's statement
  const d = si.verifyDescriptor(fs.readFileSync(path.join(dir, 'alice-desc.json')), alice);
  assert.equal(d.keys.recordKey, '0xabc');
  assert.throws(() => si.verifyDescriptor(Buffer.from('{"format":"enclave-service-descriptor/v1"}'), alice), /does not match/);
  // the list command prints the same
  const listed = []; await cli(['list', '--pin', pinFile, '--rpc', A.url, '--rpc', A2.url, '--kind', 'checker'], (s) => listed.push(s));
  assert.equal(JSON.parse(listed[0]).candidates.length, 1);
});

test('replacement needs a higher sequence; withdrawal removes the ad and revokes older signatures', { skip }, async () => {
  const exp = BigInt(await later(86400)), zero = '0x' + '0'.repeat(64);
  await write('alice', 'publish', [5, 3, 1, 1n, exp, zero, ['https://store-a.alice-net.org']]);
  const old = await acct.alice.signTypedData(si.publishTypedData({ chainId: 31337, index, operator: acct.alice.address, slot: 5, kind: 3, sequence: 2n, expiresAt: exp, descriptor: zero, endpoints: ['https://old.alice-net.org'] }));
  await write('alice', 'publish', [5, 3, 1, 3n, exp, zero, ['https://store-b.alice-net.org']]);
  let c = (await reader()).candidates.filter((x) => x.operator === acct.alice.address.toLowerCase() && x.slot === 5);
  assert.deepEqual(c.map((x) => x.endpoints[0]), ['https://store-b.alice-net.org/']);
  await assert.rejects(write('payer', 'publishFor', [acct.alice.address, 5, 3, 1, 2n, exp, zero, ['https://old.alice-net.org'], old]), /stale sequence/, 'an older signed ad cannot come back');
  await write('alice', 'withdraw', [5, 4n]);
  c = (await reader()).candidates.filter((x) => x.operator === acct.alice.address.toLowerCase() && x.slot === 5);
  assert.equal(c.length, 0);
});

test('the former governor (the deployer) cannot take anything down; a wrong signer cannot publish', { skip }, async () => {
  const exp = BigInt(await later(86400)), zero = '0x' + '0'.repeat(64);
  await write('bob', 'publish', [6, 1, 1, 1n, exp, zero, ['https://dir.bob-ops.net']]);
  const forged = await acct.governor.signTypedData(si.withdrawTypedData({ chainId: 31337, index, operator: acct.bob.address, slot: 6, sequence: 2n }));
  await assert.rejects(write('governor', 'withdrawFor', [acct.bob.address, 6, 2n, forged]), /not signed by operator/);
  await assert.rejects(write('governor', 'prune', [acct.bob.address, 6]), /ad is live/);
  const wrong = await acct.alice.signTypedData(si.publishTypedData({ chainId: 31337, index, operator: acct.bob.address, slot: 6, kind: 1, sequence: 9n, expiresAt: exp, descriptor: zero, endpoints: ['https://evil.example-attacker.org'] }));
  await assert.rejects(write('governor', 'publishFor', [acct.bob.address, 6, 1, 1, 9n, exp, zero, ['https://evil.example-attacker.org'], wrong]), /not signed by operator/);
  // a signature for another chain id is not valid here
  const otherChain = await acct.bob.signTypedData(si.publishTypedData({ chainId: 8453, index, operator: acct.bob.address, slot: 6, kind: 1, sequence: 9n, expiresAt: exp, descriptor: zero, endpoints: ['https://x.bob-ops.net'] }));
  await assert.rejects(write('governor', 'publishFor', [acct.bob.address, 6, 1, 1, 9n, exp, zero, ['https://x.bob-ops.net'], otherChain]), /not signed by operator/);
  for (const sig of ['owner()', 'pause()', 'upgradeTo(address)'])
    await assert.rejects(A.pub.call({ to: index, data: keccak256(Buffer.from(sig)).slice(0, 10) + '0'.repeat(64) }), undefined, `${sig} does not exist`);
  assert.ok((await reader()).candidates.some((x) => x.operator === acct.bob.address.toLowerCase() && x.slot === 6), 'still listed');
});

test('expired ads are not candidates, and only then may anyone prune them', { skip }, async () => {
  const zero = '0x' + '0'.repeat(64);
  await write('alice', 'publish', [7, 5, 1, 1n, BigInt(await later(120)), zero, ['https://mirror.alice-net.org/windows/']]);
  assert.ok((await reader()).candidates.some((x) => x.slot === 7 && x.kindName === 'replica'));
  await A.pub.request({ method: 'evm_increaseTime', params: [600] }); skewMs += 600_000; await A.mine();
  const r = await reader();
  assert.ok(!r.candidates.some((x) => x.operator === acct.alice.address.toLowerCase() && x.slot === 7)); assert.ok(r.expired >= 1);
  await write('governor', 'prune', [acct.alice.address, 7]);
  assert.equal((await A.pub.readContract({ address: index, abi: si.SERVICE_INDEX_ABI, functionName: 'sequenceOf', args: [acct.alice.address, 7] })), 1n, 'the sequence outlives the ad');
});

test('RPCs that disagree, a single RPC, or the wrong chain yield no candidates at all', { skip }, async () => {
  // chain B: the same contract at the same address, with a different ad
  const exp = BigInt(Number((await B.pub.getBlock()).timestamp) + 86400), zero = '0x' + '0'.repeat(64);
  const { request } = await B.pub.simulateContract({ address: index, abi: si.SERVICE_INDEX_ABI, account: acct.alice, functionName: 'publish', args: [0, 1, 1, 1n, exp, zero, ['https://other.alice-net.org']] });
  await B.pub.waitForTransactionReceipt({ hash: await B.wallet('alice').writeContract(request) }); await B.mine(20);
  // 1 honest + 1 that answers differently: no quorum, refused with evidence (never an empty list)
  const split = await reader([A.pub, B.pub], { now: () => Date.now() + skewMs }).then(() => null, (e) => e);
  assert.ok(split instanceof si.QuorumError, String(split)); assert.equal(split.evidence.peers.length, 2);
  await assert.rejects(reader([A.pub]), /two or more/);
  await assert.rejects(reader([A.pub, A2.pub], { pin: { ...pin, chainId: 8453 } }), /fewer than two RPCs on chain 8453 reported a head/);
  const stale = await reader([A.pub, A2.pub], { now: () => Date.now() + skewMs + 3600_000 * 24 }).then(() => null, (e) => e);
  assert.ok(stale instanceof si.QuorumError); assert.ok(stale.evidence.peers.every((x) => /older than/.test(x.reason)), 'old data is refused, peer by peer');
});

test('enumeration is bounded, and unsafe advertised targets are dropped with a reason', { skip }, async () => {
  const exp = BigInt(await later(86400)), zero = '0x' + '0'.repeat(64);
  const bad = ['https://10.0.0.5/', 'http://127.0.0.1:8545/', 'http://169.254.169.254/latest/', 'https://db.internal/', 'http://[::1]/', 'https://localhost./', 'http://100.64.1.1/', 'http://2130706433/'];
  for (let i = 0; i < 70; i++) {
    const k = generatePrivateKey(), op = privateKeyToAccount(k), endpoints = [i < bad.length ? bad[i] : `https://dir-${i}.open-ops.org`];
    const sig = await op.signTypedData(si.publishTypedData({ chainId: 31337, index, operator: op.address, slot: 0, kind: 1, sequence: 1n, expiresAt: exp, descriptor: zero, endpoints }));
    const { request } = await A.pub.simulateContract({ address: index, abi: si.SERVICE_INDEX_ABI, account: acct.payer, functionName: 'publishFor', args: [op.address, 0, 1, 1, 1n, exp, zero, endpoints, sig] });
    await A.wallet('payer').writeContract(request);
  }
  await A.mine();
  const total = await A.pub.readContract({ address: index, abi: si.SERVICE_INDEX_ABI, functionName: 'count', args: [1] });
  assert.ok(total >= 70n);
  const r = await reader([A.pub, A2.pub], { kinds: ['directory'], window: 50 });
  assert.equal(r.status, 'incomplete'); assert.equal(r.windows.directory.complete, false); assert.ok(r.next);
  assert.ok(r.candidates.length + r.rejected.length + r.expired <= 50, 'never more than asked for');
  const all = await reader([A.pub, A2.pub], { kinds: ['directory'], window: 1024 });
  assert.equal(all.status, 'complete');
  for (const b of bad) assert.ok(!all.candidates.some((c) => c.endpoints.some((e) => e.startsWith(b.replace(/\/$/, '')))), b);
  assert.equal(all.rejected.filter((x) => /non-public|IPv6|special-use|two or more labels/.test(x.reason)).length, bad.length);
  await assert.rejects(si.readServiceIndex({ clients: [A.pub, A2.pub], pin, window: 5000 }), /window/);
});

// ---- the provider's bootstrap ------------------------------------------------------------------------------------------
const PINS = { deployments: '0x' + '11'.repeat(20), registry: '0x' + '22'.repeat(20), connectivity: '0x' + '00'.repeat(20), sessionVaultFactory: '0x' + '33'.repeat(20) };
const EXPLICIT = { bootstrap: 'explicit', rpc: ['https://rpc-one.example-rpc.org', 'https://rpc-two.other-rpc.net'], authorityPins: PINS,
                   directories: ['https://dir.alice-net.org'], checkers: ['0x' + '44'.repeat(20)], zone: 'apps.alice-net.org', probeZone: 'probe.alice-net.org' };

test('provider bootstrap: legacy is unchanged; explicit names every authority and defaults nothing to Enclave', () => {
  const legacy = si.resolveProviderBootstrap({ relay: 'https://api.enclave.host', addressBook: '0xab214342d5A490150A4A977063A2f88E21F80907' });
  assert.deepEqual([legacy.mode, legacy.directories, legacy.zone, legacy.probeZone], ['legacy', ['https://api.enclave.host'], 'app.enclave.host', 'probe.enclave.host']);
  const b = si.resolveProviderBootstrap(EXPLICIT);
  assert.equal(b.addressBook, '0x' + '0'.repeat(40)); assert.equal(b.relay, null);
  assert.doesNotMatch(JSON.stringify({ ...b, notes: [] }), /enclave\.host|0xab214342/);
  assert.ok(b.notes.some((n) => /custom-domain/.test(n)) && b.notes.some((n) => /paid service disabled/.test(n)));
  for (const [what, cfg] of [['address book', { ...EXPLICIT, addressBook: '0xab214342d5A490150A4A977063A2f88E21F80907' }], ['directories', { ...EXPLICIT, directories: [] }],
    ['one RPC', { ...EXPLICIT, rpc: ['https://rpc-one.example-rpc.org'] }], ['same RPC host', { ...EXPLICIT, rpc: ['https://a.rpc.org', 'https://a.rpc.org/x'] }],
    ['pins', { ...EXPLICIT, authorityPins: { deployments: PINS.deployments, registry: PINS.registry } }], ['checkers', { ...EXPLICIT, checkers: [] }],
    ['zone', { ...EXPLICIT, zone: undefined }], ['probe zone', { ...EXPLICIT, probeZone: 'x' }], ['http relay', { ...EXPLICIT, relay: 'http://domains.alice-net.org' }]])
    assert.throws(() => si.resolveProviderBootstrap(cfg), undefined, what);
});

test('main.mjs --check-config and install.sh --config-only: explicit authorities, legacy only by opt-in, operator fields kept', async () => {
  const root = tmp(), rel = tmp();
  // the release directory install.sh runs from: wg-provider.mjs (here the source entry, instead of the bundle)
  fs.writeFileSync(path.join(rel, 'wg-provider.mjs'), `import ${JSON.stringify(pathToFileURL(path.join(ROOT, 'network', 'wg-provider', 'main.mjs')).href)};\n`);
  fs.copyFileSync(path.join(ROOT, 'network', 'wg-provider', 'install.sh'), path.join(rel, 'install.sh'));
  const pinsFile = path.join(rel, 'pins.json'); fs.writeFileSync(pinsFile, JSON.stringify(PINS));
  const env = { ...process.env, ENCLAVE_NETWORK_ROOT: root };
  const install = (args) => run('bash', [path.join(rel, 'install.sh'), ...args], { env });
  const cfgFile = path.join(root, 'etc', 'enclave-network', 'provider.json');

  await assert.rejects(install(['r1', 'nyc', '0x' + '44'.repeat(20), '--config-only', '--public-address', '203.0.114.7']), /add --legacy-enclave-defaults/);
  await assert.rejects(install(['r1', 'nyc', '--checkers', '0x' + '44'.repeat(20), '--rpc', 'https://a.rpc.org', '--config-only', '--public-address', '203.0.114.7']), /name your own authorities/);
  const explicitArgs = ['r1', 'nyc', '--checkers', '0x' + '44'.repeat(20), '--rpc', 'https://rpc-one.example-rpc.org', '--rpc', 'https://rpc-two.other-rpc.net',
    '--directory', 'https://dir.alice-net.org', '--pins', pinsFile, '--zone', 'apps.alice-net.org', '--probe-zone', 'probe.alice-net.org', '--public-address', '203.0.114.7', '--config-only'];
  const { stdout } = await install(explicitArgs);
  assert.match(stdout, /"mode":"explicit"/); assert.match(stdout, /--config-only/);
  const cfg = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
  assert.equal(cfg.bootstrap, 'explicit'); assert.doesNotMatch(JSON.stringify(cfg), /enclave\.host|addressBook/);
  assert.match(fs.readFileSync(path.join(root, 'etc', 'enclave-network', 'operator.key'), 'utf8'), /^0x[0-9a-f]{64}\n$/, 'the operator key is made on the server');
  // the operator's own fields survive an update
  fs.writeFileSync(cfgFile, JSON.stringify({ ...cfg, kind: 'community', hostId: '0x' + '55'.repeat(32), pricePerGiB6: 7, proofKeyFile: '/x/proof.key', localRoutes: { 'custodian.alice-net.org': { host: '127.0.0.1', tls: 8443, http: 8080 } } }));
  await install(explicitArgs);
  const kept = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
  assert.deepEqual([kept.kind, kept.pricePerGiB6, Object.keys(kept.localRoutes)], ['community', 7, ['custodian.alice-net.org']]);
  // a rejected configuration changes nothing
  fs.writeFileSync(pinsFile, JSON.stringify({ deployments: PINS.deployments, registry: PINS.registry }));
  await assert.rejects(install(explicitArgs), /rejected; nothing changed/);
  assert.equal(JSON.parse(fs.readFileSync(cfgFile, 'utf8')).pricePerGiB6, 7);
  // Enclave's fleet: the old form, by explicit opt-in, still writes Enclave's defaults
  const root2 = tmp();
  await run('bash', [path.join(rel, 'install.sh'), 'r1', 'nyc', '0x' + '44'.repeat(20), 'guard', '--legacy-enclave-defaults', '--config-only', '--public-address', '203.0.114.7'], { env: { ...process.env, ENCLAVE_NETWORK_ROOT: root2 } });
  const legacy = JSON.parse(fs.readFileSync(path.join(root2, 'etc', 'enclave-network', 'provider.json'), 'utf8'));
  assert.equal(legacy.relay, 'https://api.enclave.host'); assert.deepEqual(legacy.roles, ['guard']); assert.equal(legacy.bootstrap, undefined);
});

// ---- quorum hardening: a lying, hanging, wrong-chain, future-head or reorganizing RPC ---------------------------------
/** A JSON-RPC proxy in front of anvil A. honest | liar (answers calls from chain B) | flip (alters every eth_call result)
 *  | wrongchain | hang | future (claims a far-future head) | reorg (a different block hash on every second block read). */
async function rpcProxy(mode, { target = A.url, other = B?.url } = {}) {
  const log = [], blockReads = new Map(), port = await freePort();
  const srv = nodeHttp.createServer(async (req, res) => {
    let body = ''; for await (const c of req) body += c;
    const msg = JSON.parse(body), batch = Array.isArray(msg) ? msg : [msg];
    for (const m of batch) log.push(m);
    if (mode === 'hang') return;
    const answer = async (m) => {
      if (mode === 'wrongchain' && m.method === 'eth_chainId') return { jsonrpc: '2.0', id: m.id, result: '0x1' };
      if (mode === 'future' && m.method === 'eth_blockNumber') return { jsonrpc: '2.0', id: m.id, result: '0xffffffffff' };
      let url = target, fwd = m;
      if (mode === 'liar' && ['eth_call', 'eth_getCode'].includes(m.method)) { url = other; fwd = { ...m, params: [m.params[0], 'latest'] }; }
      const r = await (await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(fwd) })).json();
      if (mode === 'flip' && m.method === 'eth_call' && /^0x[0-9a-f]{2,}$/.test(r.result || '')) r.result = r.result.slice(0, -1) + (r.result.endsWith('0') ? '1' : '0');
      if (mode === 'reorg' && m.method === 'eth_getBlockByNumber' && r.result) {
        const n = (blockReads.get(m.params[0]) || 0) + 1; blockReads.set(m.params[0], n);
        if (n % 2 === 0) r.result = { ...r.result, hash: '0x' + 'ee'.repeat(32) };
      }
      return r;
    };
    const out = await Promise.all(batch.map(answer));
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(Array.isArray(msg) ? out : out[0]));
  });
  await new Promise((ok) => srv.listen(port, '127.0.0.1', ok));
  const url = `http://127.0.0.1:${port}`;
  return { url, log, peer: (label) => ({ label, client: createPublicClient({ chain: A.chain, transport: http(url, { timeout: 4000, retryCount: 0 }) }) }),
           close: () => { srv.closeAllConnections?.(); return new Promise((ok) => srv.close(ok)); } };
}
const quick = { requestTimeoutMs: 1500, deadlineMs: 6000 };
const read = async (peers, over = {}) => { await syncClock(); return si.readServiceIndex({ peers, pin, kinds: ['directory', 'checker'], now: () => Date.now() + skewMs, ...quick, ...over }); };
const statusOf = (r, label) => r.evidence.peers.find((p) => p.label === label);

test('2 honest + 1 liar, + 1 wrong chain, + 1 hanging, + 1 future head, + 1 reorganizing: the honest pair decides', { skip }, async () => {
  const [h1, h2, liar, wrong, hang, future, reorg] = await Promise.all(['honest', 'honest', 'liar', 'wrongchain', 'hang', 'future', 'reorg'].map((m) => rpcProxy(m)));
  try {
    const truth = await read([h1.peer('h1'), h2.peer('h2')]);
    const same = (r) => assert.deepEqual(r.candidates.map((c) => c.operator + c.slot).sort(), truth.candidates.map((c) => c.operator + c.slot).sort());
    // a liar cannot veto two honest RPCs (the earlier rule - every answer must agree - gave it that veto)
    const withLiar = await read([liar.peer('liar'), h1.peer('h1'), h2.peer('h2')]);
    same(withLiar); assert.equal(withLiar.status, truth.status);
    assert.deepEqual(['h1', 'h2'].map((l) => statusOf(withLiar, l).status), ['agreed', 'agreed']);
    assert.ok(['disagreed', 'pending'].includes(statusOf(withLiar, 'liar').status), JSON.stringify(statusOf(withLiar, 'liar')));
    // another chain is excluded at the head
    const withWrong = await read([wrong.peer('wrong'), h1.peer('h1'), h2.peer('h2')]);
    same(withWrong); assert.match(statusOf(withWrong, 'wrong').reason, /reports chain 1, not 31337/);
    // a hanging RPC delays nothing past the head grace
    const t0 = Date.now(), withHang = await read([hang.peer('hang'), h1.peer('h1'), h2.peer('h2')]);
    assert.ok(Date.now() - t0 < 1500, `took ${Date.now() - t0} ms`); same(withHang);
    assert.ok(['pending', 'failed'].includes(statusOf(withHang, 'hang').status));
    // a far-future head cannot choose the block: it is the honest second-highest head minus 2
    const head = await A.pub.getBlockNumber(), withFuture = await read([future.peer('future'), h1.peer('h1'), h2.peer('h2')]);
    assert.equal(BigInt(withFuture.blockNumber), head - 2n); same(withFuture);
    // a block replaced while it was read is that RPC's failure: beside two honest RPCs it changes nothing; beside one it
    // leaves no quorum, and the evidence says why
    same(await read([reorg.peer('reorg'), h1.peer('h1'), h2.peer('h2')]));
    const lone = await read([reorg.peer('reorg'), h1.peer('h1')]).then(() => null, (x) => x);
    assert.ok(lone instanceof si.QuorumError); assert.match(statusOf({ evidence: lone.evidence }, 'reorg').reason, /reorganized during the read/);
  } finally { await Promise.all([h1, h2, liar, wrong, hang, future, reorg].map((p) => p.close())); }
});

test('1 honest + 1 liar, or + 1 hanging, fails closed with evidence; it is never an empty directory', { skip }, async () => {
  const [h1, liar, hang] = await Promise.all(['honest', 'liar', 'hang'].map((m) => rpcProxy(m)));
  await write('alice', 'publish', [4, 1, 1, 1n, BigInt(await later(86400)), '0x' + '0'.repeat(64), ['https://dir4.alice-net.org']]);   // A now differs from B
  try {
    for (const bad of [liar.peer('liar')]) {
      const e = await read([h1.peer('h1'), bad]).then((r) => ({ ok: r.evidence }), (x) => x);
      assert.ok(e instanceof si.QuorumError, JSON.stringify(e)); assert.match(e.message, /no two RPCs returned the same snapshot/);
      assert.equal(e.evidence.peers.length, 2); assert.ok(!('candidates' in e));
    }
    const t0 = Date.now(), e = await read([h1.peer('h1'), hang.peer('hang')]).then(() => null, (x) => x);
    assert.ok(e instanceof si.QuorumError); assert.ok(Date.now() - t0 < 6500, 'bounded by the request timeout and the deadline');
    assert.match(statusOf({ evidence: e.evidence }, 'hang').reason || '', /timed out/);
    // the command prints the evidence and exits 2
    const pinFile = path.join(tmp(), 'pin.json'); fs.writeFileSync(pinFile, JSON.stringify(pin));
    const r = await run(process.execPath, [path.join(ROOT, 'scripts', 'network', 'service-index.mjs'), 'list', '--pin', pinFile, '--rpc', h1.url, '--rpc', liar.url, '--timeout-ms', '1500', '--deadline-ms', '6000'])
      .then(() => null, (x) => x);
    assert.equal(r.code, 2); const printed = JSON.parse(r.stdout);
    assert.match(printed.refused, /no two RPCs/); assert.equal(printed.evidence.peers.length, 2); assert.ok(!('candidates' in printed));
  } finally { await Promise.all([h1, liar, hang].map((p) => p.close())); }
});

test('pagination resumes at the same block; a known operator is found past any window; a forged cursor is refused', { skip }, async () => {
  const [h1, h2] = await Promise.all([rpcProxy('honest'), rpcProxy('honest')]);
  const peers = [h1.peer('h1'), h2.peer('h2')];
  try {
    const first = await read(peers, { kinds: ['directory'], window: 50 });
    assert.equal(first.status, 'incomplete'); assert.equal(first.windows.directory.end, 50); assert.equal(first.next.positions.directory, 50);
    await A.mine(2);   // the chain moves on; the resumed read stays at the first block
    const rest = await read(peers, { kinds: ['directory'], window: 1024, cursor: first.next });
    assert.equal(rest.blockHash, first.blockHash); assert.equal(rest.windows.directory.start, 50);
    assert.equal(rest.status, 'complete'); assert.equal(rest.windows.directory.end, first.windows.directory.total);
    const seen = (r) => r.candidates.length + r.rejected.length + r.expired;
    assert.equal(seen(first) + seen(rest), first.windows.directory.total, 'every listed ad examined exactly once across the two windows');
    // an operator beyond a 5-ad window: invisible in the listing, found by lookup in the same snapshot
    const knownAd = rest.candidates.at(-1), known = knownAd.operator, same = (c) => c.operator === known && c.slot === knownAd.slot;
    const small = await read(peers, { kinds: ['directory'], window: 5, lookups: [{ operator: known }, { operator: '0x' + '77'.repeat(20), slot: 0 }] });
    assert.equal(small.status, 'incomplete'); assert.ok(!small.candidates.some(same), 'outside the window');
    const hit = small.lookups.find((l) => same(l) && l.state === 'listed');
    assert.ok(hit && hit.candidate.trust === 'untrusted-candidate'); assert.equal(small.lookups.filter((l) => l.operator === known).length, 8, 'all 8 slots asked');
    assert.equal(small.lookups.find((l) => l.operator === '0x' + '77'.repeat(20)).state, 'absent');
    // a cursor naming a block the RPCs do not have, or another index, is refused
    const forged = await read(peers, { kinds: ['directory'], cursor: { ...first.next, blockHash: '0x' + '12'.repeat(32) } }).then(() => null, (x) => x);
    assert.ok(forged instanceof si.QuorumError); assert.ok(forged.evidence.peers.every((p) => /differs from the resume point/.test(p.reason)));
    await assert.rejects(read(peers, { cursor: { ...first.next, index: '0x' + '99'.repeat(20) } }), /another index/);
  } finally { await h1.close(); await h2.close(); }
});

// ---- smart-contract wallet operators -----------------------------------------------------------------------------------
const WALLET_SOURCE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;
contract TestWallet {
  address public owner; constructor(address o) { owner = o; }
  function execute(address to, bytes calldata data) external { require(msg.sender == owner, "not owner"); (bool ok, bytes memory r) = to.call(data); if (!ok) assembly { revert(add(r, 0x20), mload(r)) } }
  function isValidSignature(bytes32 d, bytes calldata sig) external view returns (bytes4) {
    if (sig.length != 65) return 0xffffffff;
    return ecrecover(d, uint8(sig[64]), bytes32(sig[0:32]), bytes32(sig[32:64])) == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
  }
}`;
const t_after = []; after(() => { for (const f of t_after) f(); });
const compileOne = (name, source, settings = {}) => {
  const solc = createRequire(import.meta.url)('solc');
  const out = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources: { [`${name}.sol`]: { content: source } },
    settings: { optimizer: { enabled: true, runs: 200 }, ...settings, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })));
  const err = (out.errors || []).filter((e) => e.severity === 'error'); if (err.length) throw new Error(err[0].formattedMessage);
  const c = out.contracts[`${name}.sol`][name]; return { abi: c.abi, bytecode: '0x' + c.evm.bytecode.object };
};
const deploy = async (who, { abi, bytecode }, args = []) => {
  const r = await A.pub.waitForTransactionReceipt({ hash: await A.wallet(who).deployContract({ abi, bytecode, args }) }); await A.mine(); return r.contractAddress;
};

test('a smart-contract wallet publishes by direct call, and by an ERC-1271 signature a gas payer submits', { skip }, async () => {
  // a fresh chain: the command reads with the wall clock, and chain A's clock now runs ahead of it; its own second endpoint
  const A = await anvil(), A2 = await rpcProxy('honest', { target: A.url });
  A2.pub = createPublicClient({ chain: A.chain, transport: http(A2.url) });
  const deploy = async (who, { abi, bytecode }, args = []) => {
    const r = await A.pub.waitForTransactionReceipt({ hash: await A.wallet(who).deployContract({ abi, bytecode, args }) }); await A.mine(); return r.contractAddress; };
  const index = await deploy('governor', built), pin = si.validateIndexPin({ chainId: 31337, address: index, codeHash: built.codeHash });
  const reader = (clients, over) => si.readServiceIndex({ clients: [A.pub, A2.pub], pin, ...over });
  const later = async (sec) => Number((await A.pub.getBlock()).timestamp) + sec;
  const write = async (who, functionName, args) => {
    const { request } = await A.pub.simulateContract({ address: index, abi: si.SERVICE_INDEX_ABI, account: acct[who], functionName, args });
    await A.pub.waitForTransactionReceipt({ hash: await A.wallet(who).writeContract(request) }); await A.mine(); };
  t_after.push(() => A2.close(), () => A.stop());
  const W = compileOne('TestWallet', WALLET_SOURCE), wallet = await deploy('alice', W, [acct.alice.address]);
  const exp = BigInt(await later(86400)), zero = '0x' + '0'.repeat(64);
  const data = encodeFunctionData({ abi: si.SERVICE_INDEX_ABI, functionName: 'publish', args: [0, 3, 1, 1n, exp, zero, ['https://store.wallet-ops.org']] });
  const { request } = await A.pub.simulateContract({ address: wallet, abi: W.abi, account: acct.alice, functionName: 'execute', args: [index, data] });
  await A.pub.waitForTransactionReceipt({ hash: await A.wallet('alice').writeContract(request) }); await A.mine();
  let r = await reader([A.pub, A2.pub], { kinds: ['storage'], lookups: [{ operator: wallet, slot: 0 }] });
  assert.equal(r.lookups[0].state, 'listed'); assert.equal(r.lookups[0].candidate.operator, wallet.toLowerCase());
  // slot 1, signed by the wallet's owner (ERC-1271), submitted by a separate gas payer through the command
  const dir = tmp(), pinFile = path.join(dir, 'pin.json'), payerKey = path.join(dir, 'payer.key');
  fs.writeFileSync(pinFile, JSON.stringify(pin)); fs.writeFileSync(payerKey, KEYS.payer);
  await cli(['prepare-publish', '--pin', pinFile, '--rpc', A.url, '--rpc', A2.url, '--operator', wallet, '--slot', '1', '--kind', 'storage',
             '--endpoint', 'https://store2.wallet-ops.org', '--out', path.join(dir, 'w.json')], () => {});
  const prepared = JSON.parse(fs.readFileSync(path.join(dir, 'w.json'), 'utf8'));
  await assert.rejects(cli(['sign', '--prepared', path.join(dir, 'w.json'), '--key-file', payerKey], () => {}), /not the ad's operator/);
  const typed = { ...prepared.typedData, message: { ...prepared.typedData.message, sequence: BigInt(prepared.typedData.message.sequence), expiresAt: BigInt(prepared.typedData.message.expiresAt) } };
  const sig = await acct.alice.signTypedData(typed);
  await cli(['send', '--prepared', path.join(dir, 'w.json'), '--rpc', A.url, '--rpc', A2.url, '--key-file', payerKey, '--yes', '--signature', sig], () => {}); await A.mine();
  r = await reader([A.pub, A2.pub], { kinds: [], lookups: [{ operator: wallet, slot: 1 }] });
  assert.equal(r.lookups[0].state, 'listed');
  // the owner's signature does not make the owner's EOA the operator, nor work for another wallet
  const other = await deploy('bob', W, [acct.bob.address]);
  const wrong = await acct.alice.signTypedData(si.publishTypedData({ chainId: 31337, index, operator: other, slot: 0, kind: 3, sequence: 1n, expiresAt: exp, descriptor: zero, endpoints: ['https://x.wallet-ops.org'] }));
  await assert.rejects(write('payer', 'publishFor', [other, 0, 3, 1, 1n, exp, zero, ['https://x.wallet-ops.org'], wrong]), /not signed by operator/);
});

// ---- the checker, with Enclave blocked ----------------------------------------------------------------------------------
const PRELOAD = `import net from 'node:net'; import dns from 'node:dns'; import fs from 'node:fs';
const LOG = process.env.BLOCK_LOG, REDIRECT = JSON.parse(process.env.REDIRECT || '{}');
const blocked = (h) => /(^|\\.)enclave\\.host\\.?$/i.test(String(h || ''));
const note = (h) => fs.appendFileSync(LOG, String(h) + '\\n');
const lookup = dns.lookup;
dns.lookup = function (host, ...a) { if (blocked(host)) { note(host); return process.nextTick(a.at(-1), Object.assign(new Error('blocked ' + host), { code: 'ENOTFOUND' })); } return lookup.call(this, host, ...a); };
const plookup = dns.promises.lookup;
dns.promises.lookup = function (host, ...a) { if (blocked(host)) { note(host); return Promise.reject(Object.assign(new Error('blocked ' + host), { code: 'ENOTFOUND' })); } return plookup.call(this, host, ...a); };
const connect = net.connect;
net.connect = net.createConnection = function (...a) {
  const o = a[0] && typeof a[0] === 'object' ? a[0] : { port: a[0], host: a[1] };
  if (blocked(o.host)) note(o.host);
  if (o.host && REDIRECT[o.host]) { if (a[0] && typeof a[0] === 'object') a[0] = { ...a[0], host: REDIRECT[o.host] }; else a[1] = REDIRECT[o.host]; }
  return connect.apply(this, a);
};`;

test('the independent checker qualifies a community provider on the deployed schema-4 registry, with Enclave blocked', { skip, timeout: 120_000 }, async () => {
  const dir = tmp(), env = { ...process.env };
  const Cn = await anvil();   // a fresh chain whose clock matches this one's (the checker uses the wall clock)
  const deploy = async (who, { abi, bytecode }, args = []) => {
    const r = await Cn.pub.waitForTransactionReceipt({ hash: await Cn.wallet(who).deployContract({ abi, bytecode, args }) }); await Cn.mine(); return r.contractAddress; };
  const A = Cn;
  // the registry exactly as deployed on Base (b17db9a3, schema 4: register(), no registerRelay or capability bits)
  const registrySource = spawnSync('git', ['show', 'b17db9a3:contracts/EnclaveRegistry.sol'], { cwd: ROOT, encoding: 'utf8' }).stdout;
  const R = compileOne('EnclaveRegistry', registrySource), registry = await deploy('governor', R);
  assert.equal(await A.pub.readContract({ address: registry, abi: parseAbi(['function registrySchema() view returns (uint256)']), functionName: 'registrySchema' }), 4n);
  const C = compileOne('MockConnectivity', `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;
contract MockConnectivity { function qualificationDigest(bytes32 h, bytes32 a, uint64 i, uint64 e, uint16 c) external view returns (bytes32) {
  return keccak256(abi.encode("mock-qualification", block.chainid, address(this), h, a, i, e, c)); } }`), connectivity = await deploy('governor', C);
  // the provider: its own key, a registry host it registered itself (open, first come by endpoint), a signed record
  const provider = privateKeyToAccount(generatePrivateKey()), endpoint = 'https://host.provider-ops.org';
  await A.pub.request({ method: 'anvil_setBalance', params: [provider.address, '0x56bc75e2d63100000'] });
  const reg = await A.pub.simulateContract({ address: registry, abi: R.abi, account: provider, functionName: 'register', args: [endpoint, 'provider-ops/host', '0x' + '00'.repeat(32), 10n, 0n, '0x' + '00'.repeat(20)] });
  await A.pub.waitForTransactionReceipt({ hash: await createWalletClient({ account: provider, chain: A.chain, transport: http(A.url) }).writeContract(reg.request) });
  await A.mine();
  const control = await freePort(), exit = wireGuardKeypair(), guard = wireGuardKeypair(), address = '44.0.0.7', now = Date.now();
  const record = { version: 1, providerId: providerIdFor(provider.address.toLowerCase(), address), operator: provider.address.toLowerCase(), address,
    wgExitKey: exit.publicKey, wgGuardKey: guard.publicKey, ports: { exit: 51820, guard: 51821, control }, roles: ['ingress', 'egress'], pricePerGiB6: 5,
    region: 'fra', kind: 'community', hostId: k256(toBytes(endpoint)), issuedAt: now, expiresAt: now + 20 * 60000 };
  const signed = await signProviderRecord(provider, record);
  // its control port: grants the checker a probe peer (names in the operator's probe zone)
  const grants = nodeHttp.createServer(async (req, res) => {
    let b = ''; for await (const c of req) b += c; const { request } = JSON.parse(b);
    const g = { providerPublicKey: exit.publicKey, endpoint: `${address}:51820`, clientPublicKey: request.wgPublicKey, clientAddress: '10.77.0.2', names: [`probe-${request.nonce}.probe.alice-net.org`], expiresAt: request.expiresAt };
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ grant: g, signature: await provider.signMessage({ message: grantMessage(g) }) }));
  }).listen(control, '127.0.0.1');
  // a public directory the checker operator chose
  const published = [], dport = await freePort();
  const directory = nodeHttp.createServer(async (req, res) => {
    let b = ''; for await (const c of req) b += c;
    if (req.method === 'POST') { published.push(JSON.parse(b)); res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{}'); }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ providers: [{ record: signed }] }));
  }).listen(dport, '127.0.0.1');
  // the WireGuard checks (enclave-wg check needs root and a tunnel): a stand-in that records the targets it was given
  const capture = path.join(dir, 'check-input.json'), wg = path.join(dir, 'fake-wg');
  fs.writeFileSync(wg, `#!/usr/bin/env node\nlet s='';process.stdin.on('data',d=>s+=d).on('end',()=>{require('fs').writeFileSync(${JSON.stringify(capture)},s);`
    + `console.log(JSON.stringify({checks:Object.fromEntries(${JSON.stringify(CHECKS)}.map(c=>[c,true])),details:{standIn:true}}));});\n`, { mode: 0o755 });
  const checker = privateKeyToAccount(generatePrivateKey()), keyFile = path.join(dir, 'checker.key'); fs.writeFileSync(keyFile, checker.privateKey ?? '');
  fs.writeFileSync(keyFile, (await import('viem/accounts')).generatePrivateKey());
  const checkerAddress = privateKeyToAccount(fs.readFileSync(keyFile, 'utf8').trim()).address.toLowerCase();
  const pinsFile = path.join(dir, 'pins.json'), dirsFile = path.join(dir, 'dirs.json'), blockLog = path.join(dir, 'blocked.log'), preload = path.join(dir, 'preload.mjs');
  fs.writeFileSync(pinsFile, JSON.stringify({ deployments: '0x' + '11'.repeat(20), registry, connectivity, sessionVaultFactory: '0x' + '00'.repeat(20) }));
  fs.writeFileSync(dirsFile, JSON.stringify([`http://127.0.0.1:${dport}`])); fs.writeFileSync(blockLog, ''); fs.writeFileSync(preload, PRELOAD);
  const [h1, h2, flip] = await Promise.all(['honest', 'honest', 'flip'].map((m) => rpcProxy(m, { target: Cn.url })));
  const childEnv = { ...env, BLOCK_LOG: blockLog, REDIRECT: JSON.stringify({ [address]: '127.0.0.1' }) };
  const QUALIFY = path.join(ROOT, 'scripts', 'network', 'wg-qualify.mjs');
  try {
    const out = path.join(dir, 'results.json');
    await run(process.execPath, ['--import', pathToFileURL(preload).href, QUALIFY, '--independent', '--key-file', keyFile, '--wg', wg,
      '--directories-file', dirsFile, '--pins', pinsFile, '--rpc', flip.url, '--rpc', h1.url, '--rpc', h2.url, '--chain-id', '31337',
      '--outbound', 'https://canary.alice-net.org/', '--dns', '9.9.9.9', '--smtp', '44.0.0.9:25', '--out', out], { env: childEnv, timeout: 90_000 })
      .then((x) => { process.env.DEBUG_CHECKER && console.log(x.stdout, x.stderr); return x; });
    const [res] = JSON.parse(fs.readFileSync(out, 'utf8'));
    assert.ok(res, 'the checker produced a verdict');
    assert.ok(Object.values(res.qualification.checks).every(Boolean), JSON.stringify(res.details));
    assert.equal((await recoverMessageAddress({ message: qualificationMessage(res.qualification), signature: res.signature })).toLowerCase(), checkerAddress);
    // the on-chain attestation signs the digest the HONEST pair returned, though one RPC altered every call
    const o = res.onchain;
    const honest = await A.pub.readContract({ address: connectivity, abi: C.abi, functionName: 'qualificationDigest', args: [o.hostId, o.addressHash, BigInt(o.issuedAt), BigInt(o.expires), o.checks] });
    assert.equal((await recoverMessageAddress({ message: { raw: honest }, signature: o.signature })).toLowerCase(), checkerAddress);
    // the probe targets were the checker operator's own, and the probe name is in the provider's own zone
    const given = JSON.parse(fs.readFileSync(capture, 'utf8'));
    assert.equal(given.outboundURL, 'https://canary.alice-net.org/'); assert.deepEqual(given.exit.peer.dns, ['9.9.9.9']); assert.equal(given.smtpTarget, '44.0.0.9:25');
    assert.match(given.exit.probeName, /\.probe\.alice-net\.org$/);
    assert.equal(published.length, 1, 'the verdict went to the chosen directory');
    // nothing Enclave was asked: no enclave.host name, no address-book read
    assert.equal(fs.readFileSync(blockLog, 'utf8'), '');
    const book = '0xab214342d5a490150a4a977063a2f88e21f80907';
    for (const p of [h1, h2, flip]) assert.ok(!p.log.some((m) => m.method === 'eth_call' && String(m.params?.[0]?.to).toLowerCase() === book));
    // the legacy form does reach for the relay (and the blocker sees it): compatibility is opt-in by its flags
    await run(process.execPath, ['--import', pathToFileURL(preload).href, QUALIFY, '--key-file', keyFile, '--wg', wg, '--relay', 'https://api.enclave.host'],
      { env: childEnv, timeout: 30_000 }).catch(() => {});
    assert.match(fs.readFileSync(blockLog, 'utf8'), /api\.enclave\.host/);
    // independent mode refuses Enclave fallbacks and missing targets
    for (const [why, extra] of [['--relay', ['--relay', 'https://api.enclave.host']], ['--book', ['--book', book]]]) {
      const e = await run(process.execPath, [QUALIFY, '--independent', '--key-file', keyFile, '--wg', wg, '--directories-file', dirsFile, '--pins', pinsFile,
        '--rpc', h1.url, '--rpc', h2.url, '--outbound', 'https://canary.alice-net.org/', '--dns', '9.9.9.9', '--smtp', '44.0.0.9:25', ...extra], { env: childEnv }).then(() => null, (x) => x);
      assert.ok(e && new RegExp(why).test(e.stderr), why);
    }
    const noTargets = await run(process.execPath, [QUALIFY, '--independent', '--key-file', keyFile, '--wg', wg, '--directories-file', dirsFile, '--pins', pinsFile,
      '--rpc', h1.url, '--rpc', h2.url], { env: childEnv }).then(() => null, (x) => x);
    assert.match(noTargets.stderr, /--outbound https URL required/);
  } finally { grants.close(); directory.close(); await Promise.all([h1, h2, flip].map((p) => p.close())); Cn.stop(); }
});

test('probe targets: explicit zone and canary in independent mode; the compatibility defaults otherwise', async () => {
  assert.deepEqual(probeTargets(), { probeZone: 'enclave.host', outbound: 'https://enclave.host/' });
  assert.deepEqual(probeTargets({ outbound: 'https://x.example-canary.org/' }).outbound, 'https://x.example-canary.org/');
  assert.throws(() => probeTargets({ independent: true, outbound: 'https://c.alice-net.org/' }), /probe zone/);
  assert.throws(() => probeTargets({ independent: true, probeZone: 'probe.alice-net.org' }), /outbound canary/);
  assert.throws(() => probeTargets({ independent: true, probeZone: 'probe.alice-net.org', outbound: 'http://c.alice-net.org/' }), /outbound canary/);
  // a live probe entry in the operator's zone: the tcp80 check against a local stand-in for the provider's port 80
  const token = 'ab'.repeat(32), port = await freePort(), hostname = 'probe-local.probe.alice-net.org';
  const srv = nodeHttp.createServer((q, s) => { s.end(q.headers.host === hostname && q.url === `/__provider_probe/${token}` ? token : 'no'); }).listen(port, '127.0.0.1');
  try {
    const manifest = { address: '127.0.0.1', hostname, token, certificateSha256: 'cd'.repeat(32), udpPort: 4444, proxy: 'socks5://u:p@127.0.0.1:1' };
    const probes = providerProbes(manifest, { independent: true, probeZone: 'probe.alice-net.org', outbound: 'https://canary.alice-net.org/', testPorts: { http: port } });
    assert.equal(await probes.tcp80(), true);
    assert.throws(() => providerProbes(manifest, { testPorts: { http: port } }), /invalid independent probe manifest/, 'the compatibility zone does not accept another zone');
    assert.throws(() => providerProbes({ ...manifest, hostname: 'probe-local.enclave.host' }, { independent: true, probeZone: 'probe.alice-net.org', outbound: 'https://c.alice-net.org/', testPorts: {} }), /invalid independent probe manifest/);
  } finally { srv.close(); }
});
