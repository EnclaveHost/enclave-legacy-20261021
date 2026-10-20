// Browser transport for independent management (docs/network/independent-management.md, work/management-interface.txt).
// Browser-safe: viem, WebCrypto, TextEncoder and fetch only; no Node modules, no Buffer.
//
// TRUST, stated exactly: the browser reaches an HTTPS origin that the deployment's CURRENT runner operator signed into
// its management record (v2 browser.origin), and the browser's own WebPKI validation of that origin's certificate is the
// transport check. The page cannot see the peer's key, so nothing here claims an SPKI check; this path depends on DNS
// and a public CA, which the native path (management-client.mjs, exact SPKI over a literal IP) does not. Owner
// authorization is identical on both paths: one EnclaveSession signature per request over this runner's management base,
// a single-use nonce at the gateway, and the gateway's own agreeing-RPC chain authorization. No relay, no bearer, no
// cookie, no retry, no redirect.
import {sha256} from 'viem';
import {managementFor, managementBase, operatorFloor, withOperatorFloor, verifyManagementRecord} from './management-record.mjs';
import {MANAGEMENT_OPERATIONS, managementTarget} from './management-routes.mjs';
import {classifyManagementAnswer, checkAppToken, MAX_PROFILE_BYTES} from './management-outcome.mjs';
import {canonical} from './canonical.mjs';

export {MANAGEMENT_OPERATIONS};
const ID = /^0x[0-9a-f]{64}$/, WINDOW_SEC = 60, FORWARDED = 'x-enclave-management-forwarded';
const enc = new TextEncoder();
const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
const b64urlBytes = s => { const t = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)); return Uint8Array.from(t, c => c.charCodeAt(0)); };

export class ManagementBrowserError extends Error {
  constructor(message, {status = null, code = null, sent = false, outcomeUnknown = false} = {}) {
    super(message); this.name = 'ManagementBrowserError'; Object.assign(this, {status, code, sent, outcomeUnknown});
  }
}

/** The storage key for one runner's composite rollback floor on one pinned network. The value stored under it (the
 *  `floor` this module returns) holds a separate floor per operator of that runner (management-record operatorFloor). */
export const managementFloorKey = ({chainId, deployments, registry, runner}) =>
  sha256(enc.encode(canonical({chainId, deployments: deployments.toLowerCase(), registry: registry.toLowerCase(), runner}))).slice(2);

/**
 * The current runner's browser endpoint. `lease` must come from the caller's own agreeing-RPC read (never one RPC and
 * never a directory). -> {record, hash, origin, floor}; persist `floor` before using the endpoint. Throws (with
 * error.floor set when the floor advanced) on a withdrawal, a record without browser transport, or an unlisted dashboard.
 */
export async function browserManagementEndpoint(envelopes, lease, {chainId = 8453, deployments, registry, dashboardOrigin, floor = null, now = Date.now()} = {}) {
  if (!lease || !lease.active || !(lease.leaseUntil > now) || !(lease.validUntil > now) || lease.chainId !== chainId ||
      String(lease.deployments).toLowerCase() !== String(deployments).toLowerCase())
    throw new ManagementBrowserError('no current lease for this deployment on the pinned ledger');
  // Judged against the CURRENT operator's own floor only; the returned composite keeps every other operator's floor.
  const best = await managementFor(envelopes, lease, {chainId, deployments, floor: operatorFloor(floor, lease.runnerOperator), now});
  const next = withOperatorFloor(floor, lease.runnerOperator, {sequence: best.record.sequence, hash: best.hash});
  const refuse = m => Object.assign(new ManagementBrowserError(m), {floor: next});
  if (best.record.address === null) throw refuse('the current runner withdrew its management endpoint');
  if (best.record.version !== 2 || !best.record.browser) throw refuse('this runner publishes no browser transport (use the native client)');
  if (!best.record.browser.dashboards.includes(dashboardOrigin)) throw refuse('this dashboard origin is not one the runner operator allowed');
  return {record: best.record, hash: best.hash, envelope: best.envelope, origin: best.record.browser.origin, floor: next};
}

/** The exact body bytes (identical to management-routes.managementBody). */
function bodyFor(op, {action, seconds} = {}) {
  if (op !== 'cpuProfileControl') {
    if (action !== undefined || seconds !== undefined) throw new ManagementBrowserError('this management operation carries no body');
    return new Uint8Array(0);
  }
  if (action === 'stop' && seconds === undefined) return enc.encode('{"action":"stop"}');
  if (action === 'start' && Number.isSafeInteger(seconds) && seconds >= 1 && seconds <= 60) return enc.encode(`{"action":"start","seconds":${seconds}}`);
  throw new ManagementBrowserError('a CPU profile control is {action:"start", seconds:1..60} or {action:"stop"}');
}

/** A signer's answer must be one EnclaveSession v1 header, current, whose signature covers exactly this request. */
export async function checkAuthorizationWeb(header, {method, hostPath, body, now = Date.now()}) {
  const m = typeof header === 'string' && header.length <= 2048 && !/[\r\n\0]/.test(header) && /^EnclaveSession v1 (\S.*)$/.exec(header);
  if (!m) throw new ManagementBrowserError('the session signer returned no EnclaveSession authorization');
  const f = Object.create(null);
  for (const kv of m[1].split(',')) { const i = kv.indexOf('='); if (i <= 0 || kv.slice(0, i) in f) throw new ManagementBrowserError('malformed session authorization'); f[kv.slice(0, i)] = kv.slice(i + 1); }
  if (!/^0x[0-9a-fA-F]{40}$/.test(f.vault || '') || !/^0x[0-9a-fA-F]{64}$/.test(f.sid || '') || !/^\d{1,12}$/.test(f.ts || '') ||
      !/^[A-Za-z0-9_-]{8,64}$/.test(f.n || '') || !/^[A-Za-z0-9_-]{43}$/.test(f.x || '') || !/^[A-Za-z0-9_-]{43}$/.test(f.y || '') || !/^[A-Za-z0-9_-]{86}$/.test(f.sig || ''))
    throw new ManagementBrowserError('malformed session authorization');
  if (Math.abs(Math.floor(now / 1000) - Number(f.ts)) > WINDOW_SEC) throw new ManagementBrowserError('the session signature is outside the host clock window');
  const bodyHash = hex(await crypto.subtle.digest('SHA-256', body));
  const message = `enclave-api-v1\n${method}\n${hostPath}\n${bodyHash}\n${f.ts}\n${f.n}\n${f.vault.toLowerCase()}\n${f.sid.toLowerCase()}`;
  let ok = false;
  try {
    const key = await crypto.subtle.importKey('jwk', {kty: 'EC', crv: 'P-256', x: f.x, y: f.y, ext: true}, {name: 'ECDSA', namedCurve: 'P-256'}, false, ['verify']);
    ok = await crypto.subtle.verify({name: 'ECDSA', hash: 'SHA-256'}, key, b64urlBytes(f.sig), enc.encode(message));
  } catch {}
  if (!ok) throw new ManagementBrowserError('the session signer did not sign exactly this request');
}

async function readBounded(response, max) {
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array(0);
  const parts = []; let size = 0;
  try {
    for (;;) { const {done, value} = await reader.read(); if (done) break; size += value.length;
      if (size > max) throw new ManagementBrowserError('management response too large'); parts.push(value); }
  } finally { reader.cancel().catch(() => {}); }
  const out = new Uint8Array(size); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/**
 * One management operation over the browser transport. -> {status, json? | text?, outcome?, transport: 'browser-webpki',
 * forwarded, runner}. Throws ManagementBrowserError {status, code, sent, outcomeUnknown}.
 */
export async function browserManagementRequest({op, deploymentId, endpoint, lease, signer, tail, nonce, action, seconds,
  fetch: fetchImpl = globalThis.fetch, now = Date.now, signal}) {
  const o = MANAGEMENT_OPERATIONS[op];
  if (!o || !ID.test(deploymentId || '') || !endpoint?.envelope || typeof signer !== 'function') throw new ManagementBrowserError('unsupported management request');
  // The origin is taken ONLY from the operator-signed record, verified again here: an endpoint object whose origin (or
  // record) was substituted after browserManagementEndpoint - from storage, a URL or a stale object - never receives an
  // owner signature. Nothing is signed for a withdrawn, native-only or expired record.
  let record;
  try { record = await verifyManagementRecord(endpoint.envelope, {now: now()}); }
  catch (e) { throw new ManagementBrowserError('the endpoint\'s management record does not verify: ' + String(e.message).slice(0, 120)); }
  if (record.address === null || record.version !== 2 || !record.browser) throw new ManagementBrowserError('this endpoint has no current browser transport');
  if (endpoint.origin !== record.browser.origin || canonical(endpoint.record ?? null) !== canonical(record))
    throw new ManagementBrowserError('the endpoint was altered after it was verified');
  if (lease?.runner !== record.runner || lease.runnerOperator?.toLowerCase() !== record.operator)
    throw new ManagementBrowserError('the endpoint does not belong to the deployment\'s current runner');
  const origin = record.browser.origin;
  const target = managementTarget(op, deploymentId, {tail, nonce}), body = bodyFor(op, {action, seconds});
  const hostPath = managementBase(lease.runner) + target;
  const deadline = Math.min(record.expiresAt, lease.validUntil, lease.leaseUntil);
  let authorization;
  try { authorization = await signer({method: o.method, hostPath, body}); }
  catch (e) { throw new ManagementBrowserError('the session signer failed: ' + String(e?.message || e).slice(0, 120)); }
  await checkAuthorizationWeb(authorization, {method: o.method, hostPath, body, now: now()});
  if (deadline <= now()) throw new ManagementBrowserError('the lease or management record expired while the request was being signed');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(0, Math.min(deadline - now(), o.timeoutMs)));
  const onAbort = () => controller.abort();
  signal?.addEventListener('abort', onAbort, {once: true});
  try {
    let response;
    try {
      response = await fetchImpl(origin + target, {method: o.method, redirect: 'error', credentials: 'omit', mode: 'cors',
        cache: 'no-store', referrerPolicy: 'no-referrer', signal: controller.signal,
        headers: {authorization, ...(body.length ? {'content-type': 'application/json'} : {})}, ...(body.length ? {body} : {})});
    } catch (e) {
      // A browser cannot tell a refused connection from one that failed after the request was written.
      throw new ManagementBrowserError(o.mutation ? 'the request may have been delivered; its outcome is unknown: check status before asking again'
        : 'the management origin could not be reached', {sent: null, outcomeUnknown: o.mutation});
    }
    if (response.type === 'opaqueredirect' || response.redirected) throw new ManagementBrowserError('management answers are never redirected', {status: response.status, sent: true, outcomeUnknown: o.mutation});
    const forwarded = response.headers.get(FORWARDED) !== '0';   // unreadable = may have been forwarded (conservative)
    let bytes = null, readError = null;
    try { bytes = await readBounded(response, o.maxResponseBytes); } catch (e) { readError = e; }
    if (op === 'logs' && !readError && response.status === 200)
      return {status: 200, text: new TextDecoder().decode(bytes), transport: 'browser-webpki', forwarded, runner: lease.runner};
    let json = null;
    if (!readError) try { json = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)); } catch {}
    const v = classifyManagementAnswer(op, {status: response.status, forwarded, readError, json, deploymentId});
    if (v.kind !== 'ok') throw new ManagementBrowserError(v.message, {status: response.status, code: v.code, sent: true, outcomeUnknown: v.kind === 'unknown'});
    if (op === 'appToken' && !checkAppToken(v.json, deploymentId)) throw new ManagementBrowserError('the host answered with a malformed app token', {status: response.status, sent: true});
    if (op === 'cpuProfile' && v.json.data != null) {
      const d = v.json.data;
      if (typeof d !== 'string' || d.length > Math.ceil(MAX_PROFILE_BYTES / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(d))
        throw new ManagementBrowserError('the host answered with a malformed CPU profile capture', {status: response.status, sent: true});
    }
    return {status: response.status, json: v.json, ...(o.mutation ? {outcome: 'succeeded'} : {}), transport: 'browser-webpki', forwarded, runner: lease.runner};
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', onAbort); }
}
