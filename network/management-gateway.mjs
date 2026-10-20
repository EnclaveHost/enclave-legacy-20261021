// The host side of independent management (docs/network/independent-management.md): an HTTPS listener with the
// host's own management key (published in a runnerOperator-signed management record) that forwards exactly the
// operations in management-routes.mjs to the supervisor on loopback.
//
// Order, for every request, before anything reaches the supervisor:
//   1. a target from the fixed table, an EnclaveSession header (never a bearer or cookie) and exactly the operation's
//      body bytes, read under a body deadline;
//   2. the request signature over THIS runner's management base, in the 60 s window; its nonce is then spent for good;
//   3. ONE chain snapshot two RPCs agree on at a fixed fresh block (management-auth.mjs): the deployment's lease names
//      this runner and its registry entry, and the session is live, holds the key and scope, and may act for the
//      deployment's current ledger owner - all under the operation's hard total deadline;
//   4. nothing is forwarded at or after the earliest of that deadline, lease end, snapshot freshness and session expiry.
// The supervisor then verifies the same signature again under its own rules; it accepts this runner's management base
// only on a request carrying the gateway's upstream token (MANAGEMENT_GATEWAY_TOKEN), so no other ingress can use it.
// While an answer flows the authorization is re-read periodically (never two rechecks at once) and the answer is cut if
// it no longer holds. Each request is forwarded at most once; a mutation whose exchange fails is outcome-unknown. Every
// answer says whether it was forwarded (x-enclave-management-forwarded).
//
// ADMISSION. Separate bounded stages limit how stalled requests affect authorized traffic:
//   - before authorization (headers and body): a global pool and a per-source cap; a declared or chunked body that the
//     operation cannot carry is refused at once, and the one small body (a CPU profile control) has a short deadline;
//   - chain authorization (the RPC-costly stage): a global pool, per-source and per-deployment concurrency caps, a
//     per-source rate, refuse-only negative caches (a deployment not leased to this runner, a signer that is not a
//     vault), and a reserve that only session keys which authorized here recently can use;
//   - forwarding: separate pools for long answers (logs, restart, attestation, CPU profile) and short ones, and a
//     per-deployment cap.
// Sources are the connection's address (IPv6 by /64). This bounds what one source, key or deployment can take; it does
// NOT make the gateway immune to a distributed flood from many addresses, which can still fill the shared pools.
import https from 'node:https';
import nodeTls from 'node:tls';
import http from 'node:http';
import {Transform, pipeline} from 'node:stream';
import {isSessionHeader} from '../windows/node/session-api-auth.mjs';
import {managementRoute, managementBodyAllowed} from './management-routes.mjs';
import {validateNetworkAuthorities} from './network-authorities.mjs';
import {verifyRequestSignature, authorizeManagement, ManagementAuthError} from './management-auth.mjs';
import {httpsOrigin} from './management-record.mjs';

const LOOPBACK = new Set(['127.0.0.1', '[::1]']);
const ID = /^0x[0-9a-f]{64}$/;
const FORWARDED = 'x-enclave-management-forwarded';
/** The header carrying the gateway's upstream token to the supervisor (supervisor.js MANAGEMENT_GATEWAY_TOKEN). */
export const MANAGEMENT_GATEWAY_HEADER = 'x-enclave-management-gateway';
const LONG = new Set(['logs', 'restart', 'attestation', 'cpuProfile']);

export function managementUpstream(raw) {
  const u = new URL(raw);
  if (u.protocol !== 'http:' || !LOOPBACK.has(u.hostname) || u.username || u.password || u.search || u.hash || u.pathname !== '/')
    throw Error('the management upstream must be the supervisor on a loopback http origin');
  return {host: u.hostname.replace(/^\[|\]$/g, ''), port: Number(u.port || 80)};
}

const bounded = (v, fallback, min, max, what) => {
  const x = v ?? fallback;
  if (!Number.isSafeInteger(x) || x < min || x > max) throw Error(`management gateway ${what} out of range`);
  return x;
};

/** The admission source of a connection: its address, IPv6 grouped by /64 (one host's addresses are one source). */
export function sourceOf(address) {
  let a = String(address || '').toLowerCase().replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/, '');
  if (!a.includes(':')) return a;
  const [head, tail] = a.split('::');
  const left = head ? head.split(':') : [], right = tail !== undefined && tail ? tail.split(':') : [];
  const groups = tail === undefined ? left : [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right];
  return groups.slice(0, 4).map(g => g.replace(/^0+(?=.)/, '')).join(':') + '::/64';
}

// Counts per key, removed at zero (bounded by the concurrency they count).
function counter() {
  const m = new Map();
  return {get: k => m.get(k) || 0, inc: k => m.set(k, (m.get(k) || 0) + 1), dec: k => { const n = (m.get(k) || 1) - 1; if (n) m.set(k, n); else m.delete(k); }, get size() { return m.size; }};
}
// A bounded expiring set. Over capacity the OLDEST entry goes: use only where forgetting can never grant anything.
function expiring(max, now) {
  const m = new Map();
  return {
    has(k) { const e = m.get(k); if (e === undefined) return false; if (e <= now()) { m.delete(k); return false; } return true; },
    add(k, ttl) { m.delete(k); m.set(k, now() + ttl); while (m.size > max) m.delete(m.keys().next().value); },
    get size() { return m.size; },
  };
}
// Single-use nonces. Live entries are NEVER evicted: when full of unexpired nonces it refuses new ones (fail closed).
export function strictReplayGuard({ttlMs = 130000, max = 100000, now = Date.now} = {}) {
  const m = new Map();
  const purge = () => { const t = now(); for (const [k, e] of m) { if (e > t) break; m.delete(k); } };
  return {
    claim(key) {
      const t = now(), e = m.get(key);
      if (e !== undefined && e > t) return 'replayed';
      if (m.size >= max) purge();
      if (m.size >= max) return 'full';
      m.delete(key); m.set(key, t + ttlMs);   // insertion order = expiry order (one fixed ttl)
      return 'ok';
    },
    get size() { return m.size; },
  };
}
// A per-source token bucket for chain authorizations; sources beyond `max` start fresh (only limits are forgotten).
function rateLimiter({perMinute, burst, max = 10000, now}) {
  const m = new Map();
  return k => {
    const t = now(), b = m.get(k) || {tokens: burst, at: t};
    b.tokens = Math.min(burst, b.tokens + (t - b.at) * perMinute / 60000); b.at = t;
    m.delete(k); m.set(k, b); while (m.size > max) m.delete(m.keys().next().value);
    if (b.tokens < 1) return false;
    b.tokens -= 1; return true;
  };
}

/**
 * reader: a LeaseReader (or anything with its agreed(read) contract) over at least two independent RPCs.
 * pins: the host's network authority pins (deployments, registry, sessionVaultFactory).
 * dashboards: the exact https origins (record v2 browser.dashboards) whose pages may read answers (CORS). A request that
 *   carries any other Origin is refused before authorization; one with no Origin (the native client) is unaffected.
 * upstreamToken: the secret the supervisor requires before it accepts this runner's management base (hex, >= 32 bytes).
 * limits: admission capacities (see the defaults below).
 */
export function createManagementHandler({runner, pins, reader, upstream, upstreamToken = null, dashboards = [], now = Date.now, maxRequestMs, bodyReadMs,
  recheckMs, limits = {}, log = () => {}}) {
  if (!Array.isArray(dashboards) || dashboards.length > 8) throw Error('management gateway dashboards must be a list of at most 8 origins');
  for (const d of dashboards) httpsOrigin(d);
  if (!ID.test(runner || '')) throw Error('management gateway needs its runner id');
  if (upstreamToken !== null && !/^[0-9a-f]{64,128}$/.test(upstreamToken)) throw Error('the management upstream token must be 32-64 bytes of lower-case hex');
  pins = validateNetworkAuthorities(pins);
  if (typeof reader?.agreed !== 'function') throw Error('management gateway needs an agreeing chain reader (LeaseReader)');
  const target = managementUpstream(upstream);
  const totalCap = bounded(maxRequestMs, 360000, 100, 360000, 'request bound');
  const bodyMs = bounded(bodyReadMs, 2000, 50, 30000, 'body bound');
  const recheckEvery = bounded(recheckMs, 15000, 50, 300000, 'recheck interval');
  const L = {
    preAuth: bounded(limits.preAuth, 64, 1, 4096, 'pre-authorization pool'),
    preAuthPerSource: bounded(limits.preAuthPerSource, 4, 1, 256, 'per-source pre-authorization cap'),
    authorizing: bounded(limits.authorizing, 8, 1, 256, 'authorization pool'),
    knownReserve: bounded(limits.knownReserve, 4, 0, 256, 'known-key reserve'),
    authorizingPerSource: bounded(limits.authorizingPerSource, 2, 1, 256, 'per-source authorization cap'),
    authorizingPerDeployment: bounded(limits.authorizingPerDeployment, 4, 1, 256, 'per-deployment authorization cap'),
    authorizingPerKey: bounded(limits.authorizingPerKey, 2, 1, 256, 'per-key authorization cap'),
    authPerMinute: bounded(limits.authPerMinute, 30, 1, 100000, 'per-source authorization rate'),
    authBurst: bounded(limits.authBurst, 10, 1, 100000, 'per-source authorization burst'),
    long: bounded(limits.long, 8, 1, 1024, 'long-answer pool'),
    short: bounded(limits.short, 8, 1, 1024, 'short-answer pool'),
    forwardPerDeployment: bounded(limits.forwardPerDeployment, 4, 1, 256, 'per-deployment forwarding cap'),
    nonces: bounded(limits.nonces, 100000, 1, 10000000, 'nonce capacity'),
    knownTtlMs: bounded(limits.knownTtlMs, 15 * 60000, 1000, 86400000, 'known-key lifetime'),
    negativeTtlMs: bounded(limits.negativeTtlMs, 15000, 0, 600000, 'negative-cache lifetime'),
  };
  const replay = strictReplayGuard({max: L.nonces, now});
  const rate = rateLimiter({perMinute: L.authPerMinute, burst: L.authBurst, now});
  const known = expiring(4096, now), notOurs = expiring(4096, now), notVault = expiring(4096, now);
  let preAuth = 0, authorizing = 0, authorizingKnown = 0;
  const pool = {long: 0, short: 0};
  const preBySource = counter(), authBySource = counter(), authByDeployment = counter(), authByKey = counter(), fwdByDeployment = counter();
  const mutating = new Set();

  async function handle(req, res) {
    const timers = [], held = [];
    const cleanup = () => { for (const t of timers) { clearTimeout(t); clearInterval(t); } timers.length = 0; };
    const release = () => { while (held.length) held.pop()(); };
    const origin = req.headers.origin;
    const cors = origin === undefined ? {} : dashboards.includes(origin) ? {'access-control-allow-origin': origin, vary: 'Origin', 'access-control-expose-headers': FORWARDED} : null;
    const send = (status, error, message, forwarded = false) => {
      if (res.headersSent) return res.destroy();
      res.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', [FORWARDED]: forwarded ? '1' : '0', ...(cors || {})});
      res.end(JSON.stringify({error, message}));
    };
    const refuseNow = (status, error, message) => { res.once('finish', () => req.destroy()); return send(status, error, message); };
    if (cors === null) { req.resume(); return send(403, 'origin_not_allowed', 'this page origin is not one the runner operator allowed'); }
    if (req.method === 'OPTIONS') {
      req.resume();
      if (origin === undefined || !managementRoute(String(req.headers['access-control-request-method'] || ''), req.url)) return send(404, 'not_found', 'not a management operation');
      res.writeHead(204, {...cors, 'access-control-allow-methods': 'GET, POST', 'access-control-allow-headers': 'authorization, content-type',
        'access-control-max-age': '600', 'cache-control': 'no-store'});
      return res.end();
    }
    const source = sourceOf(req.socket.remoteAddress);
    let mutationKey = null;
    try {
      // ---- stage 1: before authorization (cheap checks, then the body under the pre-authorization pool)
      const route = managementRoute(req.method, req.url);
      if (!route) { req.resume(); return send(404, 'not_found', 'not a management operation'); }
      const header = req.headers.authorization;
      if (!isSessionHeader(header)) { req.resume(); return send(401, 'unauthorized', 'an EnclaveSession request signature is required'); }
      if (req.headers.cookie || req.headers['proxy-authorization']) { req.resume(); return send(400, 'bad_request', 'management requests carry no cookies or proxy credentials'); }
      // A body is accepted only with an exact declared length the operation can carry: nothing to wait for otherwise.
      if (req.headers['transfer-encoding']) return refuseNow(400, 'bad_request', 'management bodies need an exact content-length');
      const declared = req.headers['content-length'] === undefined ? 0 : Number(req.headers['content-length']);
      if (!Number.isSafeInteger(declared) || declared < 0) return refuseNow(400, 'bad_request', 'invalid content-length');
      if (declared > route.maxBodyBytes) return refuseNow(413, 'too_large', 'this operation\'s body is larger than allowed');
      if (preAuth >= L.preAuth || preBySource.get(source) >= L.preAuthPerSource) return refuseNow(429, 'busy', 'too many unauthenticated management requests from this source or in total');
      preAuth++; preBySource.inc(source);
      let preHeld = true;
      const endPre = () => { if (preHeld) { preHeld = false; preAuth--; preBySource.dec(source); } };
      held.push(endPre);
      const hardUntil = now() + Math.min(route.timeoutMs, totalCap);
      const body = declared === 0 ? {bytes: Buffer.alloc(0)} : await new Promise(resolve => {
        let size = 0; const chunks = [];
        const stop = result => { cleanup(); req.removeListener('data', onData); req.removeListener('end', onEnd); req.removeListener('error', onEnd); resolve(result); };
        const onData = chunk => { size += chunk.length; if (size > declared) { req.pause(); stop({error: 413}); } else chunks.push(chunk); };
        const onEnd = e => stop(e instanceof Error ? {error: 400} : {bytes: Buffer.concat(chunks)});
        timers.push(setTimeout(() => { req.pause(); stop({error: 408}); }, bodyMs));
        req.on('data', onData); req.once('end', onEnd); req.once('error', onEnd);
      });
      endPre();
      // Refuse, then drop the connection once the refusal is written: the rest of that body is never read.
      if (body.error) return refuseNow(body.error, body.error === 413 ? 'too_large' : body.error === 408 ? 'body_timeout' : 'bad_request',
        body.error === 413 ? 'this operation\'s body is larger than allowed' : 'the request body did not arrive in time');
      if (!managementBodyAllowed(route.op, body.bytes)) return send(400, 'bad_body', 'this operation accepts only its exact body');
      // ---- stage 2: the signature (local), then the nonce, spent for good
      let parsed;
      try { parsed = verifyRequestSignature({header, method: req.method, path: req.url, body: body.bytes, runner, now: now()}); }
      catch (e) { return send(e.status || 401, e.code || 'unauthorized', String(e.message).slice(0, 200)); }
      const vault = parsed.vault.toLowerCase(), keyId = `${vault}:${parsed.sid}:${parsed.x.toString('base64url')}:${parsed.y.toString('base64url')}`;
      // Refuse-only memory of agreed refusals: a repeat for a deployment this runner does not hold, or from a signer that
      // is not a vault, costs no chain read. It never authorizes anything.
      if (notOurs.has(route.deploymentId)) return send(409, 'not_current_runner', 'this host does not hold a current lease for that deployment');
      if (notVault.has(vault)) return send(401, 'unauthorized', 'the signer is not a session vault of the pinned factory');
      const claim = replay.claim(`${vault}:${parsed.sid}:${parsed.n}`);
      if (claim === 'replayed') return send(401, 'unauthorized', 'replayed request: this nonce was already used here');
      if (claim === 'full') return send(503, 'replay_capacity', 'this gateway cannot record more single-use nonces right now; try again shortly');
      // ---- stage 3: chain authorization, under its own bounded admission
      const recent = known.has(keyId);
      const general = authorizing - authorizingKnown < L.authorizing;
      const reserve = recent && authorizingKnown < L.knownReserve;
      if (authByDeployment.get(route.deploymentId) >= L.authorizingPerDeployment || authByKey.get(keyId) >= L.authorizingPerKey ||
          (!recent && (authBySource.get(source) >= L.authorizingPerSource || !general)) || (recent && !general && !reserve))
        return send(429, 'busy', 'too many management authorizations in flight for this source, key, deployment or in total');
      if (!recent && !rate(source)) return send(429, 'rate_limited', 'too many management authorizations from this source; try again shortly');
      const asKnown = recent && !general;
      authorizing++; if (asKnown) authorizingKnown++;
      authBySource.inc(source); authByDeployment.inc(route.deploymentId); authByKey.inc(keyId);
      let authHeld = true;
      const endAuth = () => { if (authHeld) { authHeld = false; authorizing--; if (asKnown) authorizingKnown--; authBySource.dec(source); authByDeployment.dec(route.deploymentId); authByKey.dec(keyId); } };
      held.push(endAuth);
      const authorize = () => authorizeManagement(reader, {pins, deploymentId: route.deploymentId, runner, scope: route.scope, parsed,
        deadline: hardUntil, now});
      let auth;
      try { auth = await authorize(); }
      catch (e) { return send(e instanceof ManagementAuthError ? e.status : 503, e.code || 'chain_unavailable', String(e.message).slice(0, 200)); }
      finally { endAuth(); }
      if (!auth.ok) {
        if (auth.cacheable === 'deployment' && L.negativeTtlMs) notOurs.add(route.deploymentId, L.negativeTtlMs);
        if (auth.cacheable === 'vault' && L.negativeTtlMs) notVault.add(vault, L.negativeTtlMs);
        return send(auth.status, auth.code, auth.reason);
      }
      known.add(keyId, L.knownTtlMs);
      // ---- stage 4: forwarding, under its own pools
      const kind = LONG.has(route.op) ? 'long' : 'short';
      if (pool[kind] >= L[kind] || fwdByDeployment.get(route.deploymentId) >= L.forwardPerDeployment)
        return send(429, 'busy', 'too many management answers in flight for this deployment or in total');
      if (route.mutation) {
        if (mutating.has(`${route.op}:${route.deploymentId}`)) return send(409, `${route.op === 'restart' ? 'restart' : 'operation'}_in_progress`, 'this operation is already in progress for that deployment');
        mutating.add(mutationKey = `${route.op}:${route.deploymentId}`);
      }
      // Fail closed BEFORE an upstream request exists: no zero-length timer race with a stale authorization.
      if (auth.freshUntil <= now()) return send(504, 'authorization_expired', 'the authorization expired before the request could be forwarded');
      pool[kind]++; fwdByDeployment.inc(route.deploymentId);
      held.push(() => { pool[kind]--; fwdByDeployment.dec(route.deploymentId); });
      await new Promise(done => {
        let finished = false, answered = false, up = null, rechecking = false, cut = null;
        const end = () => { if (finished) return; finished = true; cleanup(); res.removeListener('close', onClose); done(); };
        const abort = (why, status = 504, code = 'upstream_timeout') => {
          if (finished) return;
          log(`[management] ${route.op} ${route.deploymentId.slice(0, 10)}: ${why}`);
          up?.destroy(Error(why));
          if (!answered) {
            if (route.mutation) send(502, `${route.op === 'restart' ? 'restart' : 'operation'}_outcome_unknown`, 'the request was forwarded once and its outcome is unknown: check status before asking again', true);
            else send(status, code, why, true);
          } else res.destroy();
          end();
        };
        const onClose = () => { if (!res.writableFinished) { up?.destroy(Error('client went away')); end(); } };
        res.once('close', onClose);
        const arm = until => { clearTimeout(cut); cut = setTimeout(() => abort('management authorization or time bound reached'), Math.max(0, until - now())); timers.push(cut); };
        arm(auth.freshUntil);
        // Revalidation while an answer flows: one recheck at a time, each a fresh agreed snapshot that may extend the cut
        // (never past the hard bound) or end the answer.
        timers.push(setInterval(async () => {
          if (rechecking || finished) return;
          rechecking = true;
          try {
            const next = await authorize();
            if (finished) return;
            if (!next.ok) return abort(`authorization no longer holds: ${next.reason}`, next.status, 'authority_changed');
            arm(next.freshUntil);
          } catch { abort('the authorization could not be revalidated', 503, 'chain_unavailable'); }
          finally { rechecking = false; }
        }, recheckEvery));
        up = http.request({host: target.host, port: target.port, method: req.method, path: req.url,
          headers: {authorization: header, accept: req.headers.accept || '*/*', ...(upstreamToken ? {[MANAGEMENT_GATEWAY_HEADER]: upstreamToken} : {}),
            ...(body.bytes.length ? {'content-type': 'application/json', 'content-length': body.bytes.length} : {})}});
        up.once('response', ur => {
          if (finished) return ur.destroy();
          answered = true;
          res.writeHead(ur.statusCode, {'content-type': ur.headers['content-type'] || 'application/octet-stream', 'cache-control': 'no-store',
            'x-content-type-options': 'nosniff', [FORWARDED]: '1', ...cors});
          let bytes = 0;
          const limit = new Transform({transform(chunk, _e, cb) {
            bytes += chunk.length; if (bytes > route.maxResponseBytes) return cb(Error('management response too large')); cb(null, chunk);
          }});
          pipeline(ur, limit, res, err => { if (err) { up.destroy(); res.destroy(); } end(); });
        });
        // on, not once: destroying the request in abort() emits a further error that must not go unhandled
        up.on('error', err => abort('upstream ' + String(err.message).slice(0, 120), 502, 'upstream_unavailable'));
        up.end(body.bytes.length ? body.bytes : undefined);
      });
    } catch (e) {
      log('[management] refused: ' + String(e?.message || e).slice(0, 200));
      send(400, 'bad_request', 'management request refused');
    } finally {
      cleanup();
      release();
      if (mutationKey) mutating.delete(mutationKey);
    }
  }
  handle.stats = () => ({inFlight: pool.long + pool.short, mutating: mutating.size, preAuth, authorizing, nonces: replay.size});
  return handle;
}

/** HTTPS listener with the host's management key. -> the server (call .listen); server.managementStats() for slots.
 *  browserTls {hostname, key, cert}: the WebPKI certificate for the record's browser origin, chosen by SNI. Native clients
 *  dial the literal address without SNI and always get the management key their record pins. */
export function createManagementGateway({tls, browserTls = null, ...options}) {
  if (!tls?.key || !tls?.cert) throw Error('management gateway needs its TLS key and certificate');
  if (browserTls && (!browserTls.hostname || !browserTls.key || !browserTls.cert)) throw Error('browser TLS needs a hostname, key and certificate');
  const handler = createManagementHandler(options);
  const native = nodeTls.createSecureContext({key: tls.key, cert: tls.cert});
  const web = browserTls ? nodeTls.createSecureContext({key: browserTls.key, cert: browserTls.cert}) : null;
  const server = https.createServer({key: tls.key, cert: tls.cert, minVersion: 'TLSv1.3', requestTimeout: 30000, headersTimeout: 10000,
    maxHeaderSize: 16384, ...(web ? {SNICallback: (name, cb) => cb(null, name === browserTls.hostname ? web : native)} : {})}, handler);
  server.managementStats = handler.stats;
  return server;
}
