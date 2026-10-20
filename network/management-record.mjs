// Host-management endpoint records (docs/network/independent-management.md). Browser-safe: viem, canonical JSON and
// the dependency-free address guard only, so the dashboard verifies records with exactly this code.
//
// A host's management gateway is a DIFFERENT principal from any tenant app: its TLS key is the host's, not a guest's,
// and nothing in a tenant's SNP proof speaks for it. What authorizes the endpoint is the chain: the record must be
// signed by the operator EOA that the pinned deployments ledger names as the deployment's CURRENT runnerOperator
// (clients check that against a fresh lease), and directories additionally require it to be the registry's active
// operator for that runner.
//
// v1 binds one literal public address and one TLS key digest (the native path: exact SPKI pinning, no DNS or CA).
// v2 adds an optional browser transport: an HTTPS origin the gateway serves with a WebPKI certificate, and the exact
// dashboard origins allowed to read its answers. That is an explicit, weaker trust choice (DNS plus a public CA) made by
// the same operator signature; it never replaces or relaxes the native path, which every record keeps.
//
// A withdrawal is a newer record with every endpoint field null. Sequences only move forward per runner and network,
// across both versions.
import {recoverMessageAddress, sha256, stringToBytes} from 'viem';
import {canonical} from './canonical.mjs';
import {isBlockedHost, parseIp} from '../relay/net-guard.mjs';

export const MANAGEMENT_RECORD_MAX_MS = 24 * 3600 * 1000;
const ID = /^0x[0-9a-f]{64}$/, ADDRESS = /^0x[0-9a-f]{40}$/, HEX32 = /^[0-9a-f]{64}$/;
const KEYS_V1 = ['version','runner','operator','chainId','deployments','address','port','spkiSha256','sequence','issuedAt','expiresAt'];
const KEYS = {1: KEYS_V1, 2: [...KEYS_V1, 'browser']};
const DNS_NAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const RESERVED = /(^|\.)(localhost|local|invalid|test|example|internal|home\.arpa)$/;

export const managementRecordHash = r => sha256(stringToBytes(canonical(r))).slice(2);

/** The session-signature base for one runner's management plane. Derived, never chosen by the operator: a signature an
 *  owner makes for this host's management gateway verifies nowhere else (not at the relay, not at another runner). */
export function managementBase(runner) {
  if (!ID.test(runner || '')) throw Error('management base needs a runner id');
  return `enclave-management.invalid/${runner}`;
}
export const managementRecordMessage = r => `enclave-network:management:v${r.version}\n${canonical(r)}`;

/** An exact https origin. `dns`: a public DNS name is required (a WebPKI-certified gateway origin). */
export function httpsOrigin(value, {dns = false} = {}) {
  let u;
  try { u = new URL(value); } catch { throw Error('an https origin is required'); }
  if (u.protocol !== 'https:' || u.username || u.password || u.pathname !== '/' || u.search || u.hash || u.origin !== value)
    throw Error('an exact https origin is required (no path, query, credentials or trailing slash)');
  // exact names only: no wildcard or other pattern characters (WHATWG URL parsing keeps a literal "*")
  if (!/^[a-z0-9.-]+$/.test(u.hostname) && !parseIp(u.hostname.replace(/^\[|\]$/g, ''))) throw Error('an exact https origin is required (no wildcards)');
  if (dns && (parseIp(u.hostname.replace(/^\[|\]$/g, '')) || !DNS_NAME.test(u.hostname) || RESERVED.test(u.hostname)))
    throw Error('the browser origin must be a public DNS name');
  return value;
}
function validateBrowser(b) {
  if (b === null) return null;
  if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).length !== 2 || !('origin' in b) || !Array.isArray(b.dashboards))
    throw Error('browser transport needs exactly an origin and its dashboards');
  httpsOrigin(b.origin, {dns: true});
  if (b.dashboards.length < 1 || b.dashboards.length > 8 || new Set(b.dashboards).size !== b.dashboards.length)
    throw Error('browser transport needs 1..8 distinct dashboard origins');
  for (const d of b.dashboards) httpsOrigin(d);
  return b;
}

/** Structure and bounds; `now` checks lifetime. -> the record (withdrawn records have address null). */
export function validateManagementRecord(r, now = Date.now()) {
  const keys = KEYS[r?.version];
  if (!keys || typeof r !== 'object' || Array.isArray(r) || Object.keys(r).length !== keys.length || keys.some(k => !(k in r)) ||
      !ID.test(r.runner) || !ADDRESS.test(r.operator) || !Number.isSafeInteger(r.chainId) || r.chainId <= 0 ||
      !ADDRESS.test(r.deployments) || !Number.isSafeInteger(r.sequence) || r.sequence < 1 ||
      !Number.isSafeInteger(r.issuedAt) || !Number.isSafeInteger(r.expiresAt) || r.issuedAt > now + 60000 ||
      r.expiresAt <= now || r.expiresAt - r.issuedAt > MANAGEMENT_RECORD_MAX_MS || r.expiresAt <= r.issuedAt ||
      // a sequence never runs ahead of its own issue time (itself at most 60 s ahead of now): no record can raise a
      // rollback floor beyond what honest later records will pass
      r.sequence > r.issuedAt)
    throw Error('invalid or expired management record');
  const withdrawn = r.address === null;
  if (withdrawn) {
    if (r.port !== null || r.spkiSha256 !== null || (r.version === 2 && r.browser !== null)) throw Error('a withdrawal carries no endpoint');
  } else {
    if (typeof r.address !== 'string' || !parseIp(r.address) || isBlockedHost(r.address) ||
        !Number.isSafeInteger(r.port) || r.port < 1 || r.port > 65535 || !HEX32.test(r.spkiSha256 || ''))
      throw Error('management endpoint must be a public literal address, a port and a TLS key digest');
    if (r.version === 2) validateBrowser(r.browser);
  }
  return r;
}

export async function signManagementRecord(account, record, now = Date.now()) {
  validateManagementRecord(record, now);
  if (account.address.toLowerCase() !== record.operator) throw Error('a management record is signed by its own operator');
  return {record, signature: await account.signMessage({message: managementRecordMessage(record)})};
}

/** Signature and structure. Authority (who that operator must be) is the caller's: see managementFor. */
export async function verifyManagementRecord(envelope, {now = Date.now()} = {}) {
  if (!envelope || typeof envelope !== 'object' || Object.keys(envelope).some(k => !['record','signature'].includes(k)) ||
      typeof envelope.signature !== 'string' || JSON.stringify(envelope).length > 4096) throw Error('management record envelope required');
  const r = validateManagementRecord(envelope.record, now);
  const signer = (await recoverMessageAddress({message: managementRecordMessage(r), signature: envelope.signature})).toLowerCase();
  if (signer !== r.operator) throw Error('management record is not signed by its operator');
  return r;
}

// Rollback floors are kept PER OPERATOR of a runner: a key that was once the runner's operator can never raise the floor
// that a later operator's records are judged against, and an operator that returns keeps its own earlier floor. A
// composite floor {version: 1, operators: {<operator>: {sequence, hash}}} holds them under one storage key per runner and
// network (managementFloorKey). It is bounded; past the bound it refuses rather than forgetting an operator's floor.
export const MANAGEMENT_FLOOR_OPERATORS = 64;
const FLOOR = f => f && typeof f === 'object' && Number.isSafeInteger(f.sequence) && f.sequence >= 1 && HEX32.test(f.hash || '');
/** The floor for `operator` in a composite floor (or null). Anything that is not a composite floor holds nothing. */
export function operatorFloor(composite, operator) {
  const e = composite?.version === 1 && composite.operators && typeof composite.operators === 'object' ? composite.operators[String(operator).toLowerCase()] : null;
  return FLOOR(e) ? {sequence: e.sequence, hash: e.hash} : null;
}
/** A composite floor with `operator`'s entry raised to `entry` (never lowered). Throws past MANAGEMENT_FLOOR_OPERATORS. */
export function withOperatorFloor(composite, operator, entry) {
  const operators = {};
  if (composite?.version === 1 && composite.operators && typeof composite.operators === 'object')
    for (const [k, v] of Object.entries(composite.operators)) if (ADDRESS.test(k) && FLOOR(v)) operators[k] = {sequence: v.sequence, hash: v.hash};
  const key = String(operator).toLowerCase(), old = operators[key];
  if (!ADDRESS.test(key) || !FLOOR(entry)) throw Error('an operator and a floor entry are required');
  if (!old && Object.keys(operators).length >= MANAGEMENT_FLOOR_OPERATORS) throw Error('too many operators recorded for this runner: refusing rather than forgetting a rollback floor');
  if (!old || entry.sequence > old.sequence) operators[key] = {sequence: entry.sequence, hash: entry.hash};
  return {version: 1, operators};
}

/**
 * The current management record for a deployment's lease, from any number of untrusted copies. Only records for the
 * lease's runner, signed by the lease's runnerOperator, on the pinned ledger and chain count. The newest sequence wins;
 * two different records at that sequence are equivocation; `floor` ({sequence, hash} last accepted for this runner,
 * network and the lease's CURRENT operator: see operatorFloor) refuses rollback to an older record (a replayed copy cannot undo a withdrawal). -> {record, hash} (record.address
 * null = withdrawn) or throws.
 */
export async function managementFor(envelopes, lease, {chainId, deployments, floor = null, now = Date.now()} = {}) {
  if (!lease || !ID.test(lease.runner || '') || !/^0x[0-9a-fA-F]{40}$/.test(lease.runnerOperator || ''))
    throw Error('a current runner is required');
  const operator = lease.runnerOperator.toLowerCase();
  let best = null, conflict = false;
  for (const e of (Array.isArray(envelopes) ? envelopes : []).slice(0, 4096)) {
    if (e?.record?.runner !== lease.runner) continue;
    let r;
    try { r = await verifyManagementRecord(e, {now}); } catch { continue; }
    if (r.operator !== operator || r.chainId !== chainId || r.deployments !== String(deployments).toLowerCase()) continue;
    const hash = managementRecordHash(r);
    if (!best || r.sequence > best.record.sequence) { best = {record: r, hash, envelope: e}; conflict = false; }
    else if (r.sequence === best.record.sequence && hash !== best.hash) conflict = true;
  }
  if (conflict) throw Error('management record equivocation');
  if (floor && (!best || best.record.sequence < floor.sequence)) throw Error('stale management record (a newer one was seen)');
  if (floor && best.record.sequence === floor.sequence && best.hash !== floor.hash) throw Error('management record equivocation');
  if (!best) throw Error('no current management record for this runner');
  return best;
}
