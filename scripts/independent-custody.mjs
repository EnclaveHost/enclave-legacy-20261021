#!/usr/bin/env node
// Operator-run independent custody workflow (docs/security/independent-custody-activation.md). Does not need Enclave API
// authentication, session issuance, release tickets, an Enclave founder or a capacity witness. Every network input is an
// explicit pin; chain reads need >= 2 distinct HTTPS RPCs and an agreeing majority. Keys are read only from an
// environment variable the operator names (--key-env) or replaced by an externally produced --signature; they are
// never printed. Nothing here holds a secret share or can release a secret.
//
//   plan      --endpoints A,B,C --chain-id N --vault 0x.. --measurement 0x.. --out plan.json [--salt 0x..]
//   digest    --plan plan.json                                    (the 32-byte digest operators and owners sign)
//   sign      --plan plan.json --index I --role operator|owner (--key-env VAR | --signature 0x..) --out plan.json
//   check     --plan plan.json --rpcs R1,R2[,..] [--owner-permits false] [--host-ownership 0x..]
//   form      --plan plan.json --out result.json [--activate --rpcs R1,R2[,..]]   (also the legacy form with no command)
//   status    --chain-id N --vault 0x.. --committee 0x.. --rpcs R1,R2[,..] [--out status.json]
//   admission --chain-id N --vault 0x.. --committee 0x.. --candidate https://.. --expires-in SEC --rpcs .. --out adm.json
//   admit     --admission adm.json --owner 0x.. (--key-env VAR | --signature 0x..) --out adm.json
//   join      --admission adm.json --rpcs R1,R2[,..]                (checks the admission, then posts it to every member)
//   code-permit --chain-id N --vault 0x.. --committee 0x.. --measurement 0x.. (--add|--remove) --expires-in SEC --rpcs .. --out code.json
//   code      --request code.json --permits permits.json --rpcs .. --out tx.json   (permits: {memberIdentity: ownerSignature})
import fs from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { coordinateIndependentGenesis } from '../custody/v2/coordinate-genesis.mjs';
import { parseUniqueJSON } from '../sdk/bootstrap/package.mjs';
import { createChainReaderV2 } from '../custody/v2/chain.mjs';
import * as D from '../custody/v2/digests.mjs';
import * as W from '../custody/v2/workflow.mjs';

const argv = process.argv.slice(2);
const command = argv[0] && !argv[0].startsWith('--') ? argv[0] : 'form';
const arg = n => { const i = argv.indexOf(n); return i < 0 ? null : argv[i + 1]; };
const need = n => { const v = arg(n); if (!v) throw Error(`${n} is required for ${command}`); return v; };
const readJson = (file, max = 262144) => { const raw = fs.readFileSync(file); if (raw.length > max) throw Error(`${file} is too large`); return parseUniqueJSON(raw.toString('utf8')); };
const writeJson = (file, value) => { fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 }); fs.chmodSync(file, 0o600); };
const int = n => { const v = Number(need(n)); if (!Number.isSafeInteger(v)) throw Error(`${n} must be an integer`); return v; };
const limited = async (r, what) => {
  const chunks = []; let size = 0;
  for await (const c of r.body) { size += c.length; if (size > 1048576) throw Error(`oversized ${what} response`); chunks.push(c); }
  const body = Buffer.concat(chunks).toString('utf8');
  if (!r.ok) { let m = ''; try { m = JSON.parse(body).message || ''; } catch {} throw Error(`${what}: HTTP ${r.status} ${String(m).slice(0, 200)}`); }
  return JSON.parse(body);
};
const get = async url => limited(await fetch(url, { signal: AbortSignal.timeout(30000), redirect: 'error' }), url);
const post = async (url, body) => limited(await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  signal: AbortSignal.timeout(120000), redirect: 'error' }), url);
function reader({ chainId, vault }) {
  const rpcs = String(need('--rpcs')).split(',').filter(Boolean);
  if (rpcs.length < 2 || new Set(rpcs.map(r => new URL(r).hostname)).size !== rpcs.length || rpcs.some(r => new URL(r).protocol !== 'https:'))
    throw Error('two distinct explicit HTTPS RPCs required');
  const hostOwnership = arg('--host-ownership');
  return createChainReaderV2({ rpcs, vault, chainId, minAgree: Math.floor(rpcs.length / 2) + 1, maxAgeSec: 120, ...(hostOwnership ? { hostOwnership: hostOwnership.toLowerCase() } : {}) });
}
async function signature(digest) {
  const given = arg('--signature');
  if (given) return given;
  const name = need('--key-env');
  let account;
  try { account = privateKeyToAccount(process.env[name]); } catch { throw Error(`environment variable ${name} does not hold a private key`); }
  return { signature: await D.signDigest(account, digest), signer: account.address.toLowerCase() };
}
const out = value => console.log(JSON.stringify(value, null, 2));

const commands = {
  async plan() {
    const plan = await W.buildPlan({ endpoints: need('--endpoints').split(',').filter(Boolean), chainId: int('--chain-id'), vault: need('--vault'),
      measurement: need('--measurement'), ...(arg('--salt') ? { salt: arg('--salt') } : {}), get });
    writeJson(need('--out'), plan);
    out({ digest: W.planDigest(plan), machines: plan.machines.length, output: arg('--out') });
  },
  async digest() { out({ digest: W.planDigest(readJson(need('--plan'))) }); },
  async sign() {
    const plan = readJson(need('--plan')), s = await signature(W.planDigest(plan));
    const sig = typeof s === 'string' ? s : s.signature;
    writeJson(need('--out'), W.addPlanSignature(plan, { role: need('--role'), index: int('--index'), signature: sig }));
    out({ role: arg('--role'), index: Number(arg('--index')), ...(typeof s === 'string' ? {} : { signer: s.signer }), output: arg('--out') });
  },
  async check() {
    const plan = readJson(need('--plan'));
    out(await W.checkPlan(plan, { chain: reader(plan), ownerPermits: arg('--owner-permits') !== 'false' }));
  },
  async form() {
    const file = need('--plan'), result = need('--out');
    const plan = readJson(file);
    let chain = null;
    if (argv.includes('--activate')) {
      chain = reader(plan);
      // Preflight the pinned vault/ownership surface through the same quorum.
      // Requiring every RPC to answer here would reintroduce a single-peer veto.
      await chain.readRegistryEntry({ registryId: plan.machines[0].registryId });
    }
    const r = await coordinateIndependentGenesis(plan, { activate: argv.includes('--activate'), post, get });
    if (chain) {
      const { committee: c } = await chain.readCommittee({ committeeId: r.committeeId });
      if (!W.committeeMatches(c, plan, r.commitments)) throw Error('on-chain committee differs from founder agreement');
      r.chainVerified = true;
    }
    writeJson(result, r);
    out({ committeeId: r.committeeId, chainVerified: r.chainVerified, activatedMembers: r.activated.length, unadopted: r.unadopted,
          neutralTransaction: !!r.transaction, output: result });
    if (r.unadopted.length) process.exitCode = 2;
  },
  async status() {
    const p = { chainId: int('--chain-id'), vault: need('--vault') }, committeeId = need('--committee');
    const s = await W.committeeStatus({ chain: reader(p), committeeId, ...p, get });
    if (arg('--out')) writeJson(arg('--out'), s);
    out(s);
    if (!s.releaseAvailable) process.exitCode = 3;
  },
  async admission() {
    const p = { chainId: int('--chain-id'), vault: need('--vault') }, chain = reader(p), committeeId = need('--committee').toLowerCase();
    const info = await W.custodianInfo(need('--candidate'), W.pins(p), get);
    if (!info.hostSig) throw Error('the candidate is not yet bound by its host operator');
    const { expiresAt } = await W.chainExpiry(chain, committeeId, int('--expires-in'));
    const request = W.admissionRequest({ ...p, committeeId, machine: info.machine, hostSig: info.hostSig, expiresAt });
    writeJson(need('--out'), request);
    out({ digest: request.digest, expiresAt, candidate: info.machine.identity, output: arg('--out') });
  },
  async admit() {
    const request = readJson(need('--admission')), s = await signature(request.digest);
    const owner = typeof s === 'string' ? need('--owner').toLowerCase() : s.signer;
    if (arg('--owner') && arg('--owner').toLowerCase() !== owner) throw Error('--owner differs from the signing key');
    const next = W.addAdmissionSignature(request, { owner, signature: typeof s === 'string' ? s : s.signature });
    writeJson(need('--out'), next);
    out({ owner, signatures: next.signatures.length, output: arg('--out') });
  },
  async join() {
    const request = readJson(need('--admission')), chain = reader(request);
    const check = await W.checkAdmission(request, { chain });
    if (!check.ready) { out(check); throw Error('admission is not ready'); }
    const { committee } = await chain.readCommittee({ committeeId: request.committeeId });
    const r = await W.joinCommittee({ request, committee, post });
    out(r);
    if (!r.accepted) process.exitCode = 2;
  },
  async ['code-permit']() {
    const p = { chainId: int('--chain-id'), vault: need('--vault') }, committeeId = need('--committee').toLowerCase();
    if (argv.includes('--add') === argv.includes('--remove')) throw Error('exactly one of --add or --remove');
    const { expiresAt } = await W.chainExpiry(reader(p), committeeId, int('--expires-in'));
    const request = W.codePermitRequest({ ...p, committeeId, measurement: need('--measurement'), add: argv.includes('--add'), expiresAt });
    writeJson(need('--out'), request);
    out({ digest: request.digest, expiresAt, output: arg('--out') });
  },
  async code() {
    const request = readJson(need('--request')), permits = readJson(need('--permits')), chain = reader(request);
    const { committee } = await chain.readCommittee({ committeeId: request.committeeId });
    if (!committee) throw Error('committee not found on the agreed chain');
    const r = await W.collectCodeApprovals({ request, committee, permits, post });
    writeJson(need('--out'), r);
    out({ weight: r.weight, t: r.t, refused: r.refused, transaction: !!r.transaction, output: arg('--out') });
    if (!r.transaction) process.exitCode = 2;
  },
};

try {
  if (!commands[command]) throw Error(`unknown command ${command}`);
  await commands[command]();
} catch (e) {
  // Workflow errors carry only public records; key parsing errors are replaced above.
  console.error(`independent-custody ${command} failed: ${String(e?.message || e).slice(0, 400)}. No secret material was printed.`);
  process.exitCode = 1;
}
