// scripts/build-custodian-v2.mjs preparation: the measured admission pins (owner list XOR owner permits), byte
// compatibility of legacy measured config, the actual daemon bundle interpreting the pin, the bounded-memory initramfs
// path (streamed inflate/deflate, byte-identical to the one-shot path) and refusals before any build work. Then the
// OPTIONAL measured Shield recipient opt-in (default off, validated, tamper-refused by the daemon's own validator) and the
// bundle's committed-source check over every input esbuild actually reads.   The Shield tests need openssl.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { spawnSync, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { custodianMeasured, measuredModule, readGzipFile, gzipPartsToFile, bundleOptions, bundleSources, sourceCheck, STATIC_IMAGE_SOURCES } from '../custody/v2/build-config.mjs';
import { independentPolicy } from '../custody/v2/governance.mjs';
import { validateShieldOperator, shieldCustodyFor, defaultShieldLimits, SHIELD_LIMITS, SHIELD_OPERATOR_FORMAT, SHIELD_OPERATOR_TIER_ACK, SHIELD_ROUTE_PREFIX } from '../custody/v2/shield-operator.mjs';
import { haveOpenssl, makeVbsWorld, tmpdir, fp } from './fixtures/vbs-synthetic.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const vault = '0x' + '56'.repeat(20), hostOwnership = '0x' + 'f5'.repeat(20);
const owners = ['0x' + '01'.repeat(20), '0x' + '02'.repeat(20), '0x' + '03'.repeat(20)];

test('measured admission pins: owner permits, owner list, legacy; mutually exclusive; legacy bytes unchanged', () => {
  const permits = custodianMeasured({ vault, hostOwnership, admission: 'owner-permits' });
  assert.deepEqual([permits.policy, permits.needsDkg, permits.measured.independentAdmission, permits.measured.independentOwners], ['owner-permits', true, 'owner-permits', null]);
  const list = custodianMeasured({ vault, hostOwnership, ownerList: owners });
  assert.deepEqual([list.policy, list.needsDkg, 'independentAdmission' in list.measured], ['owner-list', true, false]);
  const legacy = custodianMeasured({ vault, hostOwnership });
  assert.deepEqual([legacy.policy, legacy.needsDkg], [null, false]);
  assert.throws(() => custodianMeasured({ vault, hostOwnership, ownerList: owners, admission: 'owner-permits' }), /mutually exclusive/);
  assert.throws(() => custodianMeasured({ vault, hostOwnership, admission: 'anyone' }), /must be owner-permits/);
  assert.throws(() => custodianMeasured({ vault, hostOwnership, transport: 'relay' }), /direct or tunnel/);
  assert.throws(() => custodianMeasured({ vault: '0x' + '00'.repeat(20), hostOwnership }), /--vault/);
  assert.throws(() => custodianMeasured({ vault, hostOwnership, ownerList: [owners[0], owners[0], owners[1]] }), /distinct/);
  // the measured text earlier builds produced (the inline template this module replaced), byte for byte
  const old = (independentOwners) => `export const MEASURED = Object.freeze(${JSON.stringify({
    chainId: 8453, transport: 'direct', vault, hostOwnership,
    rpcs: ['https://mainnet.base.org', 'https://base-rpc.publicnode.com', 'https://base.drpc.org', 'https://base.public.blockpi.network/v1/rpc/public'],
    minAgree: 3, confirmations: 2, maxAgeSec: 120, enclaveOwner: '0x0b2d009c0c9af05b12100d77f3c815fea822ee61', independentOwners,
    capacityContract: '0x87c7266543ff5839b2c20226bd9b3cd511a23641', witnesses: { '0xd80bf435467df887f1031743c2a2125a130fe225': 'enclave-bootstrap' } })});\n`;
  assert.equal(measuredModule(legacy.measured), old(null));
  assert.equal(measuredModule(list.measured), old(owners));
  assert.notEqual(measuredModule(permits.measured), old(null));
});

test('the actual daemon bundle carries and interprets the owner-permits pin', { timeout: 120000 }, async () => {
  const { measured } = custodianMeasured({ vault, hostOwnership, admission: 'owner-permits' });
  const text = measuredModule(measured);
  const out = await build({ entryPoints: [path.join(root, 'custody/v2/daemon.mjs')], bundle: true, platform: 'node', format: 'esm', target: 'node22', write: false, legalComments: 'none',
    plugins: [{ name: 'measured', setup(b) { b.onLoad({ filter: /custody[\\/]v2[\\/]measured\.mjs$/ }, () => ({ contents: text, loader: 'js' })); } }] });
  const js = out.outputFiles[0].text;
  assert.match(js, /independentAdmission"?:\s*"owner-permits"/);
  for (const s of ['/v2/custody/code-approve', 'adoptIfCreated', 'readAuthorization']) assert.ok(js.includes(s), s);
  const { MEASURED } = await import('data:text/javascript,' + encodeURIComponent(text));
  assert.equal(independentPolicy(MEASURED).mode, 'owner-permits');
});

test('initramfs streaming: hash-while-inflate into one buffer, deflate parts byte-identical to gzipSync', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custodian-build-'));
  try {
    const parts = [randomBytes(70000), Buffer.alloc(300000, 7), randomBytes(5), Buffer.from('TRAILER!!!'), Buffer.alloc(1 << 20, 1)];
    const whole = Buffer.concat(parts), oneShot = zlib.gzipSync(whole, { level: 9 });
    const r = await gzipPartsToFile(parts, path.join(dir, 'out.gz'));
    const written = fs.readFileSync(path.join(dir, 'out.gz'));
    assert.equal(Buffer.compare(written, oneShot), 0, 'streamed deflate equals the one-shot output');
    assert.deepEqual(r, { sha256: createHash('sha256').update(oneShot).digest('hex'), bytes: oneShot.length });
    await assert.rejects(gzipPartsToFile(parts, path.join(dir, 'out.gz')), /EEXIST/, 'an image file is written once');
    const back = await readGzipFile(path.join(dir, 'out.gz'));
    assert.equal(Buffer.compare(back.raw, whole), 0);
    assert.equal(back.sha256, r.sha256);
    fs.writeFileSync(path.join(dir, 'lying.gz'), Buffer.concat([oneShot.subarray(0, -4), Buffer.from([1, 0, 0, 0])]));
    await assert.rejects(readGzipFile(path.join(dir, 'lying.gz')), /gzip trailer|incorrect|check/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the build refuses conflicting or invalid admission before any build work', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custodian-build-'));
  try {
    fs.writeFileSync(path.join(dir, 'owners.json'), JSON.stringify(owners));
    const run = (extra) => spawnSync(process.execPath, [path.join(root, 'scripts/build-custodian-v2.mjs'), '--base', path.join(dir, 'missing'), '--out', path.join(dir, 'out'),
      '--vault', vault, '--host-ownership', hostOwnership, ...extra], { encoding: 'utf8', timeout: 30000 });
    let r = run(['--independent-owners', path.join(dir, 'owners.json'), '--independent-admission', 'owner-permits']);
    assert.notEqual(r.status, 0); assert.match(r.stderr, /mutually exclusive/);
    r = run(['--independent-admission', 'open']);
    assert.notEqual(r.status, 0); assert.match(r.stderr, /must be owner-permits/);
    r = run(['--independent-admission', 'owner-permits']);
    assert.notEqual(r.status, 0); assert.match(r.stderr, /--base must be a metal dist dir/, 'valid pins proceed to the base check');
    assert.equal(fs.existsSync(path.join(dir, 'out')), false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('legacy tunnel images expose code-approve as a public custody route, POST only', () => {
  const src = fs.readFileSync(path.join(root, 'relay/api-relay.js'), 'utf8');
  const list = src.slice(src.indexOf('const CUSTODY_SURFACES'), src.indexOf(']);', src.indexOf('const CUSTODY_SURFACES')));
  assert.match(list, /\["\/v2\/custody\/code-approve", "POST"\]/);
  assert.doesNotMatch(list, /host-binding/);
});

// ---- the OPTIONAL measured Shield recipient opt-in (custody/v2/shield-operator.mjs) and the bundle's own sources ----------

const ssl = { skip: !haveOpenssl && 'openssl absent' };
const W = haveOpenssl ? makeVbsWorld(tmpdir('custodian-shield-build-')) : null, W2 = haveOpenssl ? makeVbsWorld(tmpdir('custodian-shield-build-2-')) : null;
const pemOf = (der) => new X509Certificate(der).toString();
const shieldCfg = (over = {}) => ({ format: SHIELD_OPERATOR_FORMAT, acceptTier: SHIELD_OPERATOR_TIER_ACK, ekRoots: W.ca.bundlePem, ekRootPins: [W.ca.rootPin],
                                    limits: defaultShieldLimits(), ...over });

test('Shield recipients: default off and byte-identical; a valid opt-in is baked in and read back by the daemon\'s own validator', ssl, async () => {
  const off = custodianMeasured({ vault, hostOwnership });
  assert.equal('shieldRecipients' in off.measured, false);
  assert.doesNotMatch(measuredModule(off.measured), /shield/i);
  const on = custodianMeasured({ vault, hostOwnership, shieldRecipients: shieldCfg() });
  assert.deepEqual(on.measured.shieldRecipients, shieldCfg());
  assert.deepEqual([on.policy, on.needsDkg], [null, false], 'the opt-in changes no admission or formation mode');
  const { MEASURED } = await import('data:text/javascript,' + encodeURIComponent(measuredModule(on.measured)));
  assert.deepEqual(validateShieldOperator(MEASURED.shieldRecipients), shieldCfg());
  assert.equal(shieldCustodyFor(MEASURED.shieldRecipients, { party: 'ab'.repeat(32) }).party, 'ab'.repeat(32));
  // with owner permits too: independent formation is unchanged by it
  const both = custodianMeasured({ vault, hostOwnership, admission: 'owner-permits', shieldRecipients: shieldCfg() });
  assert.deepEqual([both.policy, both.needsDkg], ['owner-permits', true]);
  assert.throws(() => custodianMeasured({ vault, hostOwnership, transport: 'tunnel', shieldRecipients: shieldCfg() }), /needs --transport direct/);
});

test('Shield recipients: malformed or weakened opt-ins are refused at build time', ssl, () => {
  const refused = (cfg, re) => assert.throws(() => custodianMeasured({ vault, hostOwnership, shieldRecipients: cfg }), (e) => /^--shield-recipients: /.test(e.message) && re.test(e.message), String(re));
  refused(shieldCfg({ ekRoots: '/etc/ssl/certs/ca-certificates.crt' }), /PEM text .* never a path/);
  refused(shieldCfg({ ekRoots: W.ca.rootPem + '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n' }), /CERTIFICATE blocks only/);
  refused(shieldCfg({ ekRoots: 'x'.repeat(10) + W.ca.rootPem }), /CERTIFICATE blocks only/);
  refused(shieldCfg({ ekRoots: W.ca.bundlePem + W2.ca.rootPem }), /is not pinned/);                       // a root without a pin
  refused(shieldCfg({ ekRootPins: [W.ca.rootPin, W2.ca.rootPin] }), /pins no self-signed root/);          // a pin without a root
  refused(shieldCfg({ ekRootPins: [fp(new X509Certificate(W.ca.inter))] }), /pins no self-signed root/);                       // an intermediate is not a root
  refused(shieldCfg({ ekRootPins: [W.ca.rootPin, W.ca.rootPin] }), /repeats a pin/);
  refused(shieldCfg({ ekRootPins: [W.ca.rootPin.toUpperCase()] }), /lowercase hex/);
  refused(shieldCfg({ ekRootPins: [] }), /ekRootPins/);
  refused(shieldCfg({ ekRoots: W.ca.interPem }), /no self-signed root/);
  refused(shieldCfg({ ekRoots: W.ca.bundlePem + pemOf(W.ek.cert) }), /not a CA certificate/);              // a leaf (an EK) is never a trust anchor
  refused(shieldCfg({ ekRoots: W.ca.rootPem + W.ca.rootPem }), /repeats another/);
  refused(shieldCfg({ acceptTier: 'hv-node' }), /acceptTier must be exactly/);
  const { acceptTier: _ack, ...noAck } = shieldCfg();
  refused(noAck, /"acceptTier" is required/);
  refused(shieldCfg({ format: 'enclave-custody-shield-operator/2' }), /format must be/);
  refused({ ...shieldCfg(), registry: 'https://api.enclave.host' }, /unknown key "registry"/);
  refused(shieldCfg({ limits: { ...defaultShieldLimits(), extra: 1 } }), /unknown key "extra"/);
  const { maxAttestBytes, ...noBytes } = defaultShieldLimits();
  refused(shieldCfg({ limits: noBytes }), /"maxAttestBytes" is required/);
  for (const [k, [min, max]] of Object.entries(SHIELD_LIMITS))
    for (const v of [min - 1, max + 1, 1.5, String(min)]) refused(shieldCfg({ limits: { ...defaultShieldLimits(), [k]: v } }), new RegExp(`limits\\.${k} must be an integer`));
  assert.equal(SHIELD_LIMITS.maxAttestBytes[1], 8 * 1024 * 1024, 'the attest body never exceeds 8 MiB');
});

test('Shield recipients: a tampered measured module is refused by the daemon\'s own validator, never repaired or dropped to SNP-only', ssl, async () => {
  const text = measuredModule(custodianMeasured({ vault, hostOwnership, shieldRecipients: shieldCfg() }).measured);
  const load = async (t) => (await import('data:text/javascript,' + encodeURIComponent(t))).MEASURED.shieldRecipients;
  const bent = [
    text.replace(W.ca.rootPin, W2.ca.rootPin),                                                          // a pin swapped
    text.replace(JSON.stringify(W.ca.bundlePem).slice(1, -1), JSON.stringify(W.ca.bundlePem + W2.ca.rootPem).slice(1, -1)),   // a root added
    text.replace('"maxAttestBytes":4194304', '"maxAttestBytes":67108864'),                               // a bound widened
    text.replace(`"acceptTier":"${SHIELD_OPERATOR_TIER_ACK}"`, '"acceptTier":"hv-node"'),
  ];
  for (const t of bent) {
    assert.notEqual(t, text);
    const cfg = await load(t);
    assert.throws(() => shieldCustodyFor(cfg, { party: 'ab'.repeat(32) }), /Shield recipients/);
  }
});

test('the actual daemon bundle with Shield recipients: routes and pins inside, and every source it reads is in the build\'s committed-source check', { ...ssl, timeout: 120000 }, async () => {
  const { measured } = custodianMeasured({ vault, hostOwnership, shieldRecipients: shieldCfg() });
  const opts = bundleOptions(measuredModule(measured), { root });
  const daemon = await build({ ...opts, entryPoints: [path.join(root, 'custody/v2/daemon.mjs')] });
  const gsup = await build({ ...opts, entryPoints: [path.join(root, 'custody/v2/cvm-gsup.mjs')] });
  const js = daemon.outputFiles[0].text;
  for (const s of [SHIELD_ROUTE_PREFIX, W.ca.rootPin, 'shieldRecipients', SHIELD_OPERATOR_TIER_ACK, '/v2/custody/code-approve']) assert.ok(js.includes(s), s);
  const src = bundleSources([daemon.metafile, gsup.metafile], { root });
  // the modules the old fixed list (custody, snpkey, relay/snp-verify.mjs, verifier, the script) missed
  for (const f of ['relay/shield-host-session.mjs', 'relay/hvnode-verify.mjs', 'relay/vbs-verify.mjs', 'relay/vbs-tcglog.mjs', 'relay/vbs-credential.mjs',
                   'relay/vbs-vm-report.mjs', 'relay/vbs-app-core.mjs', 'windows/node/shield-verdict.mjs', 'windows/node/hvnode-evidence.mjs',
                   'isolation/contract/runtime.mjs', 'custody/v2/shield-operator.mjs', 'custody/v2/http.mjs', 'custody/v2/cvm-gsup.mjs'])
    assert.ok(src.repo.includes(f), f);
  assert.ok(src.repo.every((f) => !f.includes('node_modules')) && src.packages.some((p) => p.startsWith('viem@')));
  // the check: every input and STATIC_IMAGE_SOURCES are asked of git; an untracked or modified one is reported
  const asked = [];
  const git = (status, tracked) => (args) => { asked.push(args); return args[0] === 'ls-files' ? tracked.join('\n') : status; };
  let r = sourceCheck(src, { git: git('', src.repo) });
  assert.deepEqual([r.untracked, r.dirty], [[], '']);
  assert.deepEqual(asked[1].slice(3).sort(), [...new Set([...STATIC_IMAGE_SOURCES, ...src.repo])].sort());
  for (const f of ['package-lock.json', 'relay/snp-verify.mjs', 'scripts/build-custodian-v2.mjs']) assert.ok(STATIC_IMAGE_SOURCES.includes(f), f);
  r = sourceCheck(src, { git: git(' M relay/vbs-verify.mjs', src.repo.filter((f) => f !== 'windows/node/shield-verdict.mjs')) });
  assert.deepEqual([r.untracked, r.dirty], [['windows/node/shield-verdict.mjs'], 'M relay/vbs-verify.mjs']);
  // the real repository answers too (whatever its state): the script refuses exactly when this is non-empty
  // read-only against the shared tree: GIT_OPTIONAL_LOCKS=0, so `git status` never rewrites .git/index under another session
  r = sourceCheck(src, { git: (args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 16 << 20, env: { ...process.env, GIT_OPTIONAL_LOCKS: '0' } }) });
  assert.ok(Array.isArray(r.untracked) && typeof r.dirty === 'string');
  assert.throws(() => bundleSources([{ inputs: { '../outside.mjs': {} } }], { root }), /outside the repository/);
});

test('the build refuses a malformed --shield-recipients file before any build work', ssl, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custodian-build-'));
  try {
    const run = (cfg, extra = []) => {
      fs.writeFileSync(path.join(dir, 'shield.json'), typeof cfg === 'string' ? cfg : JSON.stringify(cfg));
      return spawnSync(process.execPath, [path.join(root, 'scripts/build-custodian-v2.mjs'), '--base', path.join(dir, 'missing'), '--out', path.join(dir, 'out'),
        '--vault', vault, '--host-ownership', hostOwnership, '--shield-recipients', path.join(dir, 'shield.json'), ...extra], { encoding: 'utf8', timeout: 30000 });
    };
    let r = run(shieldCfg({ ekRootPins: [W2.ca.rootPin] }));
    assert.notEqual(r.status, 0); assert.match(r.stderr, /--shield-recipients: .*pins no self-signed root/);
    r = run('{"format":');
    assert.notEqual(r.status, 0); assert.match(r.stderr, /JSON/);
    r = run(shieldCfg(), ['--transport', 'tunnel']);
    assert.notEqual(r.status, 0); assert.match(r.stderr, /needs --transport direct/);
    r = run(shieldCfg());
    assert.notEqual(r.status, 0); assert.match(r.stderr, /--base must be a metal dist dir/, 'a valid opt-in proceeds to the base check');
    assert.equal(fs.existsSync(path.join(dir, 'out')), false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('trusted proxies: absent by default (bytes unchanged); a measured forwarder list is validated and baked; the script refuses a public one early', () => {
  const off = custodianMeasured({ vault, hostOwnership });
  assert.equal('trustedProxies' in off.measured, false);
  assert.doesNotMatch(measuredModule(off.measured), /trustedProxies/);
  assert.deepEqual(custodianMeasured({ vault, hostOwnership, trustedProxies: ['10.0.2.2'] }).measured.trustedProxies, ['10.0.2.2']);
  for (const [bad, re] of [[['8.8.8.8'], /not a loopback or private/], [['10.0.0.0/8'], /not an IP literal/], [[], /at least one address/],
                           [['10.0.2.2', '10.0.2.2'], /repeated/], [['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5'], /at most 4/]])
    assert.throws(() => custodianMeasured({ vault, hostOwnership, trustedProxies: bad }), (e) => /^--trusted-proxy: /.test(e.message) && re.test(e.message), JSON.stringify(bad));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custodian-build-'));
  try {
    const run = (v) => spawnSync(process.execPath, [path.join(root, 'scripts/build-custodian-v2.mjs'), '--base', path.join(dir, 'missing'), '--out', path.join(dir, 'out'),
      '--vault', vault, '--host-ownership', hostOwnership, '--trusted-proxy', v], { encoding: 'utf8', timeout: 30000 });
    let r = run('203.0.113.7');
    assert.notEqual(r.status, 0); assert.match(r.stderr, /--trusted-proxy: 203\.0\.113\.7 is not a loopback or private address/);
    r = run('10.0.2.2,127.0.0.1');
    assert.notEqual(r.status, 0); assert.match(r.stderr, /--base must be a metal dist dir/, 'a valid list proceeds to the base check');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
