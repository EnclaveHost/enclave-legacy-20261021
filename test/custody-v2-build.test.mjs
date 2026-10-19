// scripts/build-custodian-v2.mjs preparation: the measured admission pins (owner list XOR owner permits), byte
// compatibility of legacy measured config, the actual daemon bundle interpreting the pin, the bounded-memory initramfs
// path (streamed inflate/deflate, byte-identical to the one-shot path) and refusals before any build work.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { custodianMeasured, measuredModule, readGzipFile, gzipPartsToFile } from '../custody/v2/build-config.mjs';
import { independentPolicy } from '../custody/v2/governance.mjs';

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
