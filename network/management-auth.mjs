// Authorization for the independent management gateway (docs/network/independent-management.md), decided from ONE
// chain snapshot that at least two RPCs agree on at the same fixed, fresh, reorg-checked block (LeaseReader.agreed).
// Every fact the decision uses is read at that block: the ledger row (owner, runner, runnerOperator, active, lease),
// the runner's registry entry, the vault factory's verdict, the session (key, scope, liveness, expiry, environments), the
// vault's owner, and either the vault's environment for the deployment or the owner's ledger delegation. Nothing is
// cached between requests and nothing is combined across blocks, so one lying or lagging RPC can neither forge nor
// replay an authorization; without agreement the request is refused before anything reaches the supervisor.
//
// The request signature itself (EnclaveSession v1 over this runner's management base, the 60 s window) is checked
// locally first; its nonce is spent once it verifies and is never released, so a refused request cannot be replayed
// later into an authorization.
import {createPublicKey, verify as verifyBytes} from 'node:crypto';
import {getAddress} from 'viem';
import {apiMessage, sha256Hex, parseSessionHeader, WINDOW_SEC, VAULT_ABI, FACTORY_ABI, sessionKeyHash, hasScope,
  delegateSlot, codeHasDelegation, ENV_PROD} from '../windows/node/session-api-auth.mjs';
import {hostABI} from './registry-abi.mjs';
import {managementBase} from './management-record.mjs';

const ID = /^0x[0-9a-f]{64}$/, ZERO_ADDRESS = /^0x0{40}$/i, ZERO_ID = /^0x0{64}$/i;
const ROW = [['id','bytes32'],['owner','address'],['appRef','string'],['ports','string'],['configCid','string'],['gpuMilli','uint16'],
  ['cpuMilli','uint16'],['appPort','uint32'],['isPublic','bool'],['active','bool'],['createdAt','uint64'],['rate','uint256'],['balance6','uint256'],
  ['spent6','uint256'],['runner','bytes32'],['runnerOperator','address'],['leaseUntil','uint64']];
const LEDGER_ABI = [
  {type: 'function', name: 'get', stateMutability: 'view', inputs: [{type: 'bytes32'}], outputs: [{type: 'tuple', components: ROW.map(([name, type]) => ({name, type}))}]},
  {type: 'function', name: 'deploymentsSchema', stateMutability: 'view', inputs: [], outputs: [{type: 'uint256'}]},
];

export class ManagementAuthError extends Error {
  constructor(status, code, message) { super(message); this.name = 'ManagementAuthError'; Object.assign(this, {status, code}); }
}

/** The request's own signature, checked without the chain. -> {vault, sid, x, y, ts, n} or throws a 401. */
export function verifyRequestSignature({header, method, path, body, runner, now = Date.now()}) {
  let p;
  try { p = parseSessionHeader(header); } catch (e) { throw new ManagementAuthError(401, 'unauthorized', String(e.message).slice(0, 200)); }
  if (Math.abs(Math.floor(now / 1000) - p.ts) > WINDOW_SEC) throw new ManagementAuthError(401, 'unauthorized', 'stale or future request timestamp');
  let ok = false;
  try {
    const key = createPublicKey({key: {kty: 'EC', crv: 'P-256', x: p.x.toString('base64url'), y: p.y.toString('base64url')}, format: 'jwk'});
    ok = verifyBytes('sha256', Buffer.from(apiMessage(method, managementBase(runner) + path, sha256Hex(body), p.ts, p.n, p.vault, p.sid)),
      {key, dsaEncoding: 'ieee-p1363'}, p.sig);
  } catch {}
  if (!ok) throw new ManagementAuthError(401, 'unauthorized', 'bad session signature: it does not cover this runner, method, path and body');
  return p;
}

const str = v => typeof v === 'bigint' ? v.toString() : v;
/**
 * Every authorization fact, from one agreed snapshot. `reader` is a LeaseReader (its agreed() picks the block, checks its
 * age and hash, and requires two peers to return identical values). -> {blockNumber, hash, timestamp, schema, row, host,
 * isVault, session, vaultOwner, held, delegation}
 */
export function readAuthorization(reader, {pins, deploymentId, vault, sid}) {
  if (typeof reader?.agreed !== 'function') throw Error('management authorization needs an agreeing chain reader');
  const ledger = getAddress(pins.deployments), registry = getAddress(pins.registry), factory = pins.sessionVaultFactory;
  const v = getAddress(vault);
  return reader.agreed(async (c, blockNumber) => {
    const read = (address, abi, functionName, args) => c.readContract({address, abi, functionName, args, blockNumber});
    const [schema, row] = await Promise.all([read(ledger, LEDGER_ABI, 'deploymentsSchema'), read(ledger, LEDGER_ABI, 'get', [deploymentId])]);
    const runner = String(row.runner).toLowerCase();
    const host = ZERO_ID.test(runner) ? null : await read(registry, hostABI, 'get', [runner]);
    const isVault = !factory || ZERO_ADDRESS.test(factory) ? false : await read(getAddress(factory), FACTORY_ABI, 'isVault', [v]) === true;
    let session = null, vaultOwner = null, held = 0, delegation = {supported: false, granted: false};
    if (isVault) {
      const [[s, live], owner] = await Promise.all([read(v, VAULT_ABI, 'sessionOf', [sid]), read(v, VAULT_ABI, 'owner')]);
      session = {keyHash: String(s.keyHash).toLowerCase(), actions: str(s.actions), envs: Number(s.envs), expiresAt: str(s.expiresAt), live: live === true};
      vaultOwner = String(owner).toLowerCase();
      const holder = String(row.owner).toLowerCase();
      if (holder === v.toLowerCase()) held = Number((await read(v, VAULT_ABI, 'held', [deploymentId]))[0]);
      else if (holder === vaultOwner) {
        const code = await c.getCode({address: ledger, blockNumber});
        const supported = !!code && code !== '0x' && codeHasDelegation(code);
        const word = supported ? await c.getStorageAt({address: ledger, slot: delegateSlot(getAddress(owner), v), blockNumber}) : null;
        delegation = {supported, granted: supported && !!word && word !== '0x' && BigInt(word) === 1n};
      }
    }
    return {schema: Number(schema), row: {id: String(row.id).toLowerCase(), owner: String(row.owner).toLowerCase(), runner,
      runnerOperator: String(row.runnerOperator).toLowerCase(), active: row.active === true, leaseUntil: str(row.leaseUntil)},
      host: host ? {active: host.active === true, operator: String(host.operator).toLowerCase()} : null,
      isVault, session, vaultOwner, held, delegation};
  });
}

/**
 * The decision, pure. -> {ok: true, owner, freshUntil} or {ok: false, status, code, reason}. freshUntil is the earliest of
 * lease end, the snapshot's freshness and session expiry: the gateway forwards nothing at or after it.
 */
export function decideAuthorization(f, {deploymentId, runner, scope, parsed, now = Date.now(), maxBlockAgeMs = 90000}) {
  // `cacheable` names a refusal a gateway may remember briefly to refuse repeats cheaply (never to authorize anything).
  const deny = (status, code, reason, cacheable = null) => ({ok: false, status, code, reason, cacheable});
  if (![15, 16].includes(f.schema)) return deny(503, 'chain_unavailable', 'unsupported deployments ledger');
  const leaseUntil = Number(f.row.leaseUntil) * 1000;
  if (f.row.id !== deploymentId || !f.row.active || f.row.runner !== runner || !(leaseUntil > now) ||
      !f.host?.active || f.host.operator !== f.row.runnerOperator)
    return deny(409, 'not_current_runner', 'this host does not hold a current lease for that deployment', 'deployment');
  const s = f.session;
  if (!f.isVault || !s) return deny(401, 'unauthorized', 'the signer is not a session vault of the pinned factory', 'vault');
  if (s.keyHash !== sessionKeyHash(parsed.x, parsed.y).toLowerCase()) return deny(401, 'unauthorized', 'this key does not belong to the session');
  const expiresAt = Number(s.expiresAt) * 1000;
  if (!s.live || !(expiresAt > now)) return deny(401, 'session_ended', 'this session has ended or expired');
  if (!hasScope(BigInt(s.actions), scope)) return deny(403, 'not_allowed', `this session lacks ${scope}`);
  const holder = f.row.owner, vault = parsed.vault.toLowerCase();
  if (holder === vault) {
    if (!f.held) return deny(403, 'not_allowed', 'this deployment is not adopted into one of the vault\'s environments');
    if ((s.envs & f.held) === 0) return deny(403, 'not_allowed', 'this deployment is outside the session\'s environments');
  } else if (holder === f.vaultOwner) {
    if ((s.envs & ENV_PROD) === 0) return deny(403, 'not_allowed', 'this session does not cover the owner\'s production deployments');
    if (!f.delegation.supported || !f.delegation.granted) return deny(403, 'not_allowed', 'the owner has not delegated this deployment to the session vault');
  } else return deny(403, 'not_allowed', 'this session does not belong to the deployment\'s current owner');
  return {ok: true, owner: holder, freshUntil: Math.min(leaseUntil, f.timestamp + maxBlockAgeMs, expiresAt)};
}

/** readAuthorization + decideAuthorization under a hard deadline: a hung or slow chain read is a refusal, and a snapshot
 *  that is no longer fresh when it arrives is a refusal too. */
export async function authorizeManagement(reader, {pins, deploymentId, runner, scope, parsed, deadline, now = Date.now, maxBlockAgeMs}) {
  if (!ID.test(deploymentId) || !ID.test(runner)) throw Error('exact deployment and runner required');
  let timer;
  const facts = await Promise.race([
    readAuthorization(reader, {pins, deploymentId, vault: parsed.vault, sid: parsed.sid}),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new ManagementAuthError(504, 'authorization_timeout', 'the chain authorization did not complete in time')), Math.max(0, deadline - now())); }),
  ]).catch(e => { if (e instanceof ManagementAuthError) throw e; throw new ManagementAuthError(503, 'chain_unavailable', 'no agreeing chain quorum for the authorization'); })
    .finally(() => clearTimeout(timer));
  const d = decideAuthorization(facts, {deploymentId, runner, scope, parsed, now: now(), maxBlockAgeMs: maxBlockAgeMs ?? reader.maxBlockAgeMs ?? 90000});
  if (d.ok && Math.min(d.freshUntil, deadline) <= now()) return {ok: false, status: 504, code: 'authorization_expired', reason: 'the authorization expired before the request could be forwarded'};
  return d.ok ? {...d, freshUntil: Math.min(d.freshUntil, deadline), blockNumber: facts.blockNumber} : d;
}
