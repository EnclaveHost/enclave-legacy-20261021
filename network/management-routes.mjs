// The ONLY requests the independent management plane carries (client and gateway share this table). Everything else,
// including /v1/admin/*, listings, deletion, topups and the data path, is refused: an owner's per-request signature for
// one of these never becomes a credential for anything else on the host.
//
// mutation: whether a lost or malformed answer leaves the outcome unknown (the operation may have changed host state).
export const MANAGEMENT_OPERATIONS = Object.freeze({
  status:      {method: 'GET',  suffix: '',             scope: 'api.status',    maxBodyBytes: 0,  timeoutMs: 30000,  maxResponseBytes: 1 << 20, mutation: false},
  gpu:         {method: 'GET',  suffix: '/gpu',         scope: 'api.status',    maxBodyBytes: 0,  timeoutMs: 30000,  maxResponseBytes: 1 << 20, mutation: false},
  logs:        {method: 'GET',  suffix: '/logs',        scope: 'api.logs',      maxBodyBytes: 0,  timeoutMs: 60000,  maxResponseBytes: 8 << 20, mutation: false},
  attestation: {method: 'GET',  suffix: '/attestation', scope: 'api.status',    maxBodyBytes: 0,  timeoutMs: 60000,  maxResponseBytes: 4 << 20, mutation: false},
  // A restart re-provisions in place; the supervisor answers only once the relaunch finished (or failed).
  restart:     {method: 'POST', suffix: '/restart',     scope: 'api.restart',   maxBodyBytes: 0,  timeoutMs: 360000, maxResponseBytes: 1 << 16, mutation: true},
  // A per-deployment, audience-pinned app-origin token for a PRIVATE deployment (supervisor mintAppToken): never a
  // host-wide credential. Minting has no host-side effect beyond the token itself.
  appToken:    {method: 'POST', suffix: '/app-token',   scope: 'api.appAccess', maxBodyBytes: 0,  timeoutMs: 30000,  maxResponseBytes: 8192,    mutation: false},
  // The capture: metadata plus at most 16 MiB of gperftools data, base64 (wasm_manager _CpuProfile.read).
  cpuProfile:  {method: 'GET',  suffix: '/cpu-profile', scope: 'api.logs',      maxBodyBytes: 0,  timeoutMs: 60000,  maxResponseBytes: 24 << 20, mutation: false},
  // Start (1..60 s) or stop a capture. Signalling the app can leave the capture in an uncertain state.
  cpuProfileControl: {method: 'POST', suffix: '/cpu-profile', scope: 'api.logs', maxBodyBytes: 64, timeoutMs: 30000, maxResponseBytes: 1 << 16, mutation: true},
});
const TARGET = /^\/v1\/deployments\/(0x[0-9a-f]{64})(\/logs|\/attestation|\/restart|\/app-token|\/cpu-profile|\/gpu)?(?:\?([^#]*))?$/;
const BY_REQUEST = new Map(Object.entries(MANAGEMENT_OPERATIONS).map(([op, o]) => [`${o.method} ${o.suffix}`, op]));

/** The exact request target for an operation. Throws on anything outside the table. */
export function managementTarget(op, deploymentId, {tail, nonce} = {}) {
  const o = MANAGEMENT_OPERATIONS[op];
  if (!o || !/^0x[0-9a-f]{64}$/.test(deploymentId || '')) throw Error('unsupported management operation');
  let query = '';
  if (op === 'logs' && tail !== undefined) {
    if (!Number.isSafeInteger(tail) || tail < 1 || tail > 2000) throw Error('logs tail must be 1..2000 lines');
    query = '?tail=' + tail;
  } else if (op === 'attestation' && nonce !== undefined) {
    if (!/^[0-9a-f]{64}$/.test(nonce)) throw Error('attestation nonce must be 32 bytes of lower-case hex');
    query = '?nonce=' + nonce;
  } else if (tail !== undefined || nonce !== undefined) throw Error('unsupported management query');
  return `/v1/deployments/${deploymentId}${o.suffix}${query}`;
}

/** The exact body bytes an operation carries (signed and checked byte for byte; no other encoding is accepted). */
export function managementBody(op, {action, seconds} = {}) {
  if (op !== 'cpuProfileControl') {
    if (action !== undefined || seconds !== undefined) throw Error('this management operation carries no body');
    return Buffer.alloc(0);
  }
  if (action === 'stop' && seconds === undefined) return Buffer.from('{"action":"stop"}');
  if (action === 'start' && Number.isSafeInteger(seconds) && seconds >= 1 && seconds <= 60) return Buffer.from(`{"action":"start","seconds":${seconds}}`);
  throw Error('a CPU profile control is {action:"start", seconds:1..60} or {action:"stop"}');
}
/** Is `bytes` exactly a body managementBody would produce for this operation? */
export function managementBodyAllowed(op, bytes) {
  if (op !== 'cpuProfileControl') return bytes.length === 0;
  const s = bytes.toString('latin1');
  return s === '{"action":"stop"}' || /^\{"action":"start","seconds":([1-9]|[1-5][0-9]|60)\}$/.test(s);
}

/** Classify a received request. -> {op, deploymentId, ...MANAGEMENT_OPERATIONS[op]} or null (not a management request).
 *  The target must be exactly what managementTarget produces: no prefixes, encodings, extra parameters or dot segments. */
export function managementRoute(method, target) {
  if (typeof target !== 'string' || target.length > 256) return null;
  const m = TARGET.exec(target);
  if (!m) return null;
  const op = BY_REQUEST.get(`${method} ${m[2] || ''}`);
  if (!op) return null;
  const q = m[3];
  if (q !== undefined) {
    const tail = op === 'logs' && /^tail=([1-9][0-9]{0,3})$/.exec(q);
    const nonce = op === 'attestation' && /^nonce=[0-9a-f]{64}$/.test(q);
    if (!(tail && Number(tail[1]) <= 2000) && !nonce) return null;
  }
  return {op, deploymentId: m[1], ...MANAGEMENT_OPERATIONS[op]};
}
