// scripts/independent-custody.mjs offline commands: digest, operator/owner signing (key only from a named environment
// variable, never printed), admission signing, and the explicit-pin refusals that run before any network access.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import * as D from '../custody/v2/digests.mjs';
import * as W from '../custody/v2/workflow.mjs';

const script = fileURLToPath(new URL('../scripts/independent-custody.mjs', import.meta.url));
const hex = (n, bytes = 32) => '0x' + n.toString(16).padStart(bytes * 2, '0');
const run = (args, env = {}) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH, ...env }, timeout: 30000 });

test('operator and owner sign the exact plan offline; keys come only from a named variable and never reach output', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'independent-custody-'));
  try {
    const machines = [0, 1, 2].map(i => ({ identity: hex(100 + i, 20), encKey: hex(200 + i), endpoint: `https://m${i}.example`, chipId: hex(300 + i), registryId: hex(400 + i), measurement: hex(99) }));
    const plan = { chainId: 8453, vault: hex(44, 20), salt: hex(5), machines, codeSet: [hex(99)], operatorPermits: [null, null, null], ownerPermits: [null, null, null] };
    const file = path.join(dir, 'plan.json');
    fs.writeFileSync(file, JSON.stringify(plan));
    const digest = JSON.parse(run(['digest', '--plan', file]).stdout).digest;
    assert.equal(digest, D.independentPlanDigest(plan));

    const key = generatePrivateKey(), account = privateKeyToAccount(key);
    let r = run(['sign', '--plan', file, '--index', '1', '--role', 'owner', '--key-env', 'OWNER_KEY', '--out', file], { OWNER_KEY: key });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.includes(key.slice(2)), false);
    assert.equal(JSON.parse(r.stdout).signer, account.address.toLowerCase());
    const signed = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.equal(await D.recoverDigest(digest, signed.ownerPermits[1]), account.address.toLowerCase());
    assert.equal(signed.operatorPermits[1], null);
    assert.equal((fs.statSync(file).mode & 0o777), 0o600);

    const secret = 'not-a-key-but-sensitive-1234';
    r = run(['sign', '--plan', file, '--index', '0', '--role', 'operator', '--key-env', 'OP_KEY', '--out', file], { OP_KEY: secret });
    assert.equal(r.status, 1);
    assert.equal((r.stdout + r.stderr).includes(secret), false);
    assert.match(r.stderr, /does not hold a private key/);
    r = run(['sign', '--plan', file, '--index', '3', '--role', 'operator', '--signature', '0x' + '11'.repeat(65), '--out', file]);
    assert.match(r.stderr, /index out of range/);

    for (const [args, message] of [
      [['check', '--plan', file, '--rpcs', 'https://one.example'], /two distinct explicit HTTPS RPCs/],
      [['check', '--plan', file, '--rpcs', 'https://one.example,http://two.example'], /two distinct explicit HTTPS RPCs/],
      [['form', '--plan', file], /--out is required/],
      [['status', '--chain-id', '8453', '--vault', hex(44, 20)], /--committee is required/],
      [['launch'], /unknown command/],
    ]) { r = run(args); assert.equal(r.status, 1); assert.match(r.stderr, message); }

    const owner = privateKeyToAccount(generatePrivateKey()), ownerKey = generatePrivateKey();
    const admission = W.admissionRequest({ chainId: 8453, vault: hex(44, 20), committeeId: hex(77), machine: machines[0], hostSig: '0x' + '22'.repeat(65), expiresAt: 123456 });
    const afile = path.join(dir, 'adm.json');
    fs.writeFileSync(afile, JSON.stringify(admission));
    r = run(['admit', '--admission', afile, '--key-env', 'K', '--out', afile, '--owner', owner.address], { K: ownerKey });
    assert.match(r.stderr, /differs from the signing key/);
    r = run(['admit', '--admission', afile, '--key-env', 'K', '--out', afile], { K: ownerKey });
    assert.equal(r.status, 0, r.stderr);
    const adm = JSON.parse(fs.readFileSync(afile, 'utf8'));
    assert.equal(adm.signatures.length, 1);
    assert.equal(await D.recoverDigest(adm.digest, adm.signatures[0].signature), privateKeyToAccount(ownerKey).address.toLowerCase());
    fs.writeFileSync(afile, JSON.stringify({ ...adm, expiresAt: 999999 }));
    r = run(['admit', '--admission', afile, '--signature', '0x' + '33'.repeat(65), '--owner', owner.address, '--out', afile]);
    assert.match(r.stderr, /altered/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
