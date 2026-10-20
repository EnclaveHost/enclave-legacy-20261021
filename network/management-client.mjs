// Owner-side independent management (docs/network/independent-management.md): status, logs, restart and attestation
// for ONE deployment, sent to the host that the pinned ledger names as its current runner, through the management
// endpoint that runner's operator key signed. No Enclave API, fleet tunnel or address book participates, and the
// endpoint itself needs no DNS name or CA (a literal IP and the signed SPKI). The lease read still needs two agreeing
// RPCs (LeaseReader: HTTPS origins, so DNS and WebPKI for their names unless they are literal IPs with IP-SAN certs).
//
// What is authenticated, and by what:
//   - which host: the deployment's CURRENT lease (pinned ledger, agreeing RPC reads) names runner and runnerOperator;
//   - which endpoint: a management record for that runner, signed by that runnerOperator, from any directory copy, with a
//     persistent sequence floor per runner AND operator (no rollback within an operator; a former operator's floor never
//     blocks the next one);
//   - which TLS peer: the handshake key must equal the record's spkiSha256 before the request line, the owner's signed
//     Authorization header or any body is written (the agent hands the socket over only after this check).
// This is the HOST's identity. It is never inferred from, and never substitutes for, a tenant app's SNP/TLS proof:
// an attestation document fetched here is host-reported data to be verified independently.
//
// Every request is signed per request (EnclaveSession v1) over this runner's management base, so the signature is useless
// at any other host or service. Requests are never retried; a restart that may have been sent reports outcomeUnknown.
import https from 'node:https';
import path from 'node:path';
import {isIP} from 'node:net';
import {createHash, createPrivateKey, createPublicKey, randomBytes, sign as signBytes, verify as verifyBytes} from 'node:crypto';
import {PassThrough, Transform, pipeline} from 'node:stream';
import {LeaseReader} from './lease-reader.mjs';
import {DirectoryClient} from './directory-client.mjs';
import {DurableState} from './durable-state.mjs';
import {validateNetworkAuthorities} from './network-authorities.mjs';
import {DirectHttpsAgent} from './socks-connect.mjs';
import {apiMessage, sha256Hex, isSessionHeader, parseSessionHeader, WINDOW_SEC} from '../windows/node/session-api-auth.mjs';
import {recordHash} from './route-record.mjs';
import {managementBase, managementFor} from './management-record.mjs';
import {MANAGEMENT_OPERATIONS, managementTarget, managementBody} from './management-routes.mjs';
import {classifyManagementAnswer, checkAppToken, MAX_PROFILE_BYTES} from './management-outcome.mjs';

const ZERO = '0x' + '0'.repeat(40);

/** A per-request EnclaveSession v1 signer (the sdk's signApiRequest format) for a session's P-256 key. */
export function sessionRequestSigner({vault, sid, privateKey, now = Date.now}) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(vault || '') || !/^0x[0-9a-fA-F]{64}$/.test(sid || '')) throw Error('session vault and sid required');
  const key = privateKey?.type === 'private' ? privateKey : createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw Error('a P-256 session key is required');
  const {x, y} = createPublicKey(key).export({format: 'jwk'});
  return ({method, hostPath, body}) => {
    const ts = Math.floor(now() / 1000), n = randomBytes(12).toString('base64url');
    const message = apiMessage(method, hostPath, sha256Hex(body), ts, n, vault, sid);
    const sig = signBytes('sha256', Buffer.from(message), {key, dsaEncoding: 'ieee-p1363'}).toString('base64url');
    return `EnclaveSession v1 vault=${vault},sid=${sid.toLowerCase()},ts=${ts},n=${n},x=${x},y=${y},sig=${sig}`;
  };
}

/** A signer's answer must be one EnclaveSession v1 header, current, whose signature covers exactly this request. */
export function checkAuthorization(header, {method, hostPath, body = Buffer.alloc(0), now = Date.now()}) {
  if (typeof header !== 'string' || header.length > 2048 || /[\r\n\0]/.test(header) || !isSessionHeader(header))
    throw new ManagementError('the session signer returned no EnclaveSession authorization');
  let p;
  try { p = parseSessionHeader(header); } catch (e) { throw new ManagementError('the session signer returned a malformed authorization: ' + String(e.message).slice(0, 120)); }
  if (Math.abs(Math.floor(now / 1000) - p.ts) > WINDOW_SEC) throw new ManagementError('the session signature is outside the host clock window');
  let ok = false;
  try {
    const key = createPublicKey({key: {kty: 'EC', crv: 'P-256', x: p.x.toString('base64url'), y: p.y.toString('base64url')}, format: 'jwk'});
    ok = verifyBytes('sha256', Buffer.from(apiMessage(method, hostPath, sha256Hex(body), p.ts, p.n, p.vault, p.sid)), {key, dsaEncoding: 'ieee-p1363'}, p.sig);
  } catch {}
  if (!ok) throw new ManagementError('the session signer did not sign exactly this request');
  return p;
}

export class ManagementError extends Error {
  constructor(message, {status = null, code = null, sent = false, outcomeUnknown = false} = {}) {
    super(message); this.name = 'ManagementError'; Object.assign(this, {status, code, sent, outcomeUnknown});
  }
}

export class ManagementClient {
  constructor({deploymentId, chainId = 8453, authorityPins, rpc, directories, stateDir, signer, reader, fetch = globalThis.fetch, now = Date.now}) {
    if (!/^0x[0-9a-f]{64}$/.test(deploymentId || '') || typeof stateDir !== 'string' || !path.isAbsolute(stateDir) || typeof signer !== 'function')
      throw Error('explicit deployment, state directory and session signer required');
    this.pins = validateNetworkAuthorities(authorityPins);
    Object.assign(this, {deploymentId, chainId, signer, now});
    this.reader = reader || new LeaseReader({rpc, chainId, addressBook: ZERO, authorityPins: this.pins, includeHostPayout: true, now});
    this.directories = new DirectoryClient({origins: directories, fetch});
    // Literal directory origins keep host discovery independent of any DNS authority.
    if (this.directories.origins.some(o => !isIP(new URL(o).hostname.replace(/^\[|\]$/g, '')))) throw Error('management discovery requires literal directory addresses');
    this.floors = new DurableState(path.join(stateDir, 'management-floors'));
    this.mutating = new Set();
  }

  // Floors are per network AND per operator: the same runner id under another chain, ledger or registry is an unrelated
  // host record, and a key that was once a runner's operator can never raise the floor a later operator is judged
  // against. An operator that returns keeps its own earlier floor (each has its own file, never overwritten by another).
  floorKey(runner, operator) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(operator || '')) throw Error('a floor belongs to one operator');
    return recordHash({chainId: this.chainId, deployments: this.pins.deployments, registry: this.pins.registry, runner, operator: operator.toLowerCase()});
  }

  /** The current runner's verified management endpoint. -> {lease, record} or throws (nothing is sent). */
  async resolve() {
    const id = this.deploymentId;
    await this.reader.refresh([id]);
    const lease = this.reader.get(id), now = this.now();
    if (!lease || lease.id !== id || !lease.active || lease.leaseUntil <= now || lease.validUntil <= now || lease.chainId !== this.chainId ||
        String(lease.deployments).toLowerCase() !== this.pins.deployments) throw new ManagementError('no current lease for this deployment on the pinned ledger');
    const answers = await this.directories.read('/v1/network/records');
    const envelopes = answers.flatMap(a => Array.isArray(a.value?.management) ? a.value.management.slice(0, 4096) : []);
    const floorKey = this.floorKey(lease.runner, lease.runnerOperator), floor = await this.floors.get(floorKey);
    const best = await managementFor(envelopes, lease, {chainId: this.chainId, deployments: this.pins.deployments, floor, now});
    // Persist the floor BEFORE using the record: a later stale copy cannot undo a withdrawal or key rotation.
    if (!floor || best.record.sequence > floor.sequence) await this.floors.set(floorKey, {sequence: best.record.sequence, hash: best.hash});
    if (best.record.address === null) throw new ManagementError('the current runner withdrew its management endpoint');
    return {lease, record: best.record};
  }

  status() { return this._json('status'); }
  /** Host-reported GPU capacity for the current lease holder; not an attestation or a capacity reservation. */
  gpu() { return this._json('gpu'); }
  attestation({nonce} = {}) { return this._json('attestation', {nonce}); }
  /** Exactly one attempt. A failure after the request may have been written carries outcomeUnknown: check status(). */
  restart() { return this._mutate('restart'); }
  /** A per-deployment app-origin token for a PRIVATE deployment (sensitive: it opens that app as its owner; never log it).
   *  -> {token, tokenType: 'Cookie', deployment, expiresAt}. It is not a host-wide or control-plane credential. */
  async appToken() {
    const r = await this._json('appToken'), j = r.json;
    if (!checkAppToken(j, this.deploymentId))
      throw new ManagementError('the host answered with a malformed app token', {status: r.status, sent: true});
    return {token: j.token, tokenType: j.tokenType, deployment: j.deployment, expiresAt: j.expiresAt};
  }
  /** The capture's state, and its gperftools bytes once complete (at most 16 MiB). -> {profile, data: Buffer|null} */
  async cpuProfile() {
    const r = await this._json('cpuProfile'), {data, ...profile} = r.json;
    if (typeof profile.state !== 'string') throw new ManagementError('the host answered with a malformed CPU profile', {status: r.status, sent: true});
    if (data === undefined || data === null) return {profile, data: null};
    const bytes = typeof data === 'string' && /^[A-Za-z0-9+/]*={0,2}$/.test(data) ? Buffer.from(data, 'base64') : null;
    if (!bytes || bytes.length > MAX_PROFILE_BYTES || bytes.toString('base64') !== data || (profile.bytes !== undefined && profile.bytes !== bytes.length))
      throw new ManagementError('the host answered with a malformed CPU profile capture', {status: r.status, sent: true});
    return {profile, data: bytes};
  }
  /** Start a capture of 1..60 s (one per app process). A lost answer is outcome-unknown: read cpuProfile() before retrying. */
  startCpuProfile({seconds} = {}) { return this._mutate('cpuProfileControl', {}, {action: 'start', seconds}); }
  stopCpuProfile() { return this._mutate('cpuProfileControl', {}, {action: 'stop'}); }
  async _mutate(op, opts, bodyOpts) {
    if (this.mutating.has(op)) throw new ManagementError('this operation is already in flight from this client');
    this.mutating.add(op);
    try { return await this._json(op, opts, bodyOpts); } finally { this.mutating.delete(op); }
  }
  /** -> {status, headers, body: Readable, cancel(), closed}: the host's log tail, delivered as it arrives. */
  async logs({tail} = {}) {
    const r = await this._open('logs', {tail});
    if (r.status !== 200) throw await this._failure(r, 'logs');
    return r;
  }

  async _json(op, opts, bodyOpts) {
    const r = await this._open(op, opts, bodyOpts);
    const forwarded = r.headers['x-enclave-management-forwarded'] !== '0';
    let bytes, readError = null;
    try { const chunks = []; for await (const c of r.body) chunks.push(c); bytes = Buffer.concat(chunks); }
    catch (e) { readError = e; }
    let json = null;
    if (!readError) try { json = JSON.parse(bytes.toString('utf8')); } catch {}
    const v = classifyManagementAnswer(op, {status: r.status, forwarded, readError, json, deploymentId: this.deploymentId});
    if (v.kind !== 'ok') throw new ManagementError(v.message, {status: r.status, code: v.code, sent: true, outcomeUnknown: v.kind === 'unknown'});
    // The authenticated principal is the HOST management endpoint, not the tenant guest.
    return {status: r.status, json: v.json, ...(MANAGEMENT_OPERATIONS[op].mutation ? {outcome: 'succeeded'} : {}),
      authenticated: 'host-management-record', transport: 'native-spki', runner: r.runner, record: r.record};
  }
  async _failure(r, op) {
    const chunks = [];
    try { for await (const c of r.body) { chunks.push(c); if (chunks.length > 16) break; } } catch {}
    let code = null, message = `management ${op} refused (HTTP ${r.status})`;
    try { const b = JSON.parse(Buffer.concat(chunks).toString('utf8')); code = String(b.error || b.code || '').slice(0, 60) || null;
      if (b.message) message += ': ' + String(b.message).slice(0, 200); } catch {}
    return new ManagementError(message, {status: r.status, code, sent: true});
  }

  async _open(op, opts = {}, bodyOpts) {
    const o = MANAGEMENT_OPERATIONS[op], target = managementTarget(op, this.deploymentId, opts), body = managementBody(op, bodyOpts);
    const {lease, record} = await this.resolve();
    const hostPath = managementBase(lease.runner) + target, deadline = Math.min(record.expiresAt, lease.validUntil);
    // SDK signers are asynchronous (a wallet, an agent key). Whatever comes back must be a session signature over
    // exactly this request, and the lease and record must still be current once it has.
    let authorization;
    try { authorization = await this.signer({method: o.method, hostPath, body: Buffer.from(body)}); }
    catch (e) { throw new ManagementError('the session signer failed: ' + String(e?.message || e).slice(0, 120)); }
    checkAuthorization(authorization, {method: o.method, hostPath, body, now: this.now()});
    if (deadline <= this.now()) throw new ManagementError('the lease or management record expired while the request was being signed');
    const agent = new DirectHttpsAgent({tlsOptions: {rejectUnauthorized: false, minVersion: 'TLSv1.3'}, verifyPeer: connection => {
      if (deadline <= this.now()) throw Error('management authorization expired');
      const key = connection.getPeerX509Certificate()?.publicKey.export({format: 'der', type: 'spki'});
      if (!key || createHash('sha256').update(key).digest('hex') !== record.spkiSha256) throw Error('management TLS key does not match the signed host record');
    }});
    return new Promise((resolve, reject) => {
      let sent = false, settled = false;
      const finish = () => { clearTimeout(timer); agent.destroy(); };
      const fail = e => {
        finish();
        if (settled) return out?.destroy(e);
        settled = true;
        const unknown = sent && o.mutation;
        reject(new ManagementError(unknown ? 'the request may have been delivered; its outcome is unknown: check status before asking again'
          : String(e?.message || 'management transport failed').slice(0, 200), {sent, outcomeUnknown: unknown}));
      };
      let out = null;
      // The literal address from the signed record; never a name, never the directory's or the app's address.
      const req = https.request({host: record.address, port: record.port, path: target, method: o.method, agent,
        headers: {authorization, accept: op === 'logs' ? 'text/plain' : 'application/json',
          ...(body.length ? {'content-type': 'application/json', 'content-length': body.length} : {})}}, res => {
        let bytes = 0;
        const limit = new Transform({transform(chunk, _e, cb) {
          bytes += chunk.length; if (bytes > o.maxResponseBytes) return cb(Error('management response too large')); cb(null, chunk);
        }});
        out = new PassThrough({highWaterMark: 64 * 1024});
        out.on('error', () => {});
        let closedResolve; const closed = new Promise(r => closedResolve = r);
        // An answer is never read past the authority it was requested under (record expiry, lease freshness).
        const stale = setTimeout(() => out.destroy(Error('management authorization expired during the response')), Math.max(0, deadline - this.now()));
        pipeline(res, limit, out, err => { clearTimeout(stale); finish(); closedResolve({bytes, error: err ? err.message : null}); });
        settled = true;
        resolve({status: res.statusCode, headers: res.headers, body: out, closed, runner: lease.runner, record,
          cancel: () => { if (!out.destroyed) out.destroy(Error('management stream cancelled')); }});
      });
      // The socket is assigned only after the TLS key check above: from here the request may have been written.
      req.once('socket', () => { sent = true; });
      const timer = setTimeout(() => req.destroy(Error('management request timeout')), o.timeoutMs);
      req.once('error', fail);
      req.end(body.length ? body : undefined);
    });
  }
}
