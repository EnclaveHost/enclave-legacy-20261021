// What an answer from a management gateway means, shared by the native client and the browser helper (pure; no Node or
// browser APIs). Reads are simple: a 2xx JSON object or a refusal. Mutations (restart, CPU profile control) are not
// idempotent, so only two answers are definite: a well-formed success, and a refusal known to precede any side effect:
// a gateway refusal before forwarding (x-enclave-management-forwarded: 0), or the supervisor's own pre-mutation
// refusals; for a CPU profile control also the manager's 422 input refusal, which precedes any signal. Anything else -
// malformed, truncated, a 5xx, a 409 from the profiler (its capture may be uncertain), an unexpected status or code - is
// outcome-unknown: it may have run. Never report success for it and never invite a blind resend.
import {MANAGEMENT_OPERATIONS} from './management-routes.mjs';

const AUTH_REFUSALS = ['unauthorized', 'session_ended', 'chain_unavailable', 'session_check_failed', 'not_allowed', 'not_found'];
const NOT_STARTED = {
  restart: new Set([...AUTH_REFUSALS, 'not_running', 'restart_in_progress', 'restart_unavailable']),
  cpuProfileControl: new Set([...AUTH_REFUSALS, 'profile_unavailable', 'no_instance']),
};
const SUCCEEDED = {
  restart: (json, id) => json.id === id && typeof json.status === 'string',
  cpuProfileControl: json => typeof json.state === 'string' && json.format === 'gperftools',
};

/**
 * -> {kind: 'ok', json} | {kind: 'refused', message, status, code} | {kind: 'unknown', message, status, code}
 * `readError`: the body could not be read completely. `json`: the parsed body or null.
 */
export function classifyManagementAnswer(op, {status, forwarded, readError = null, json = null, deploymentId}) {
  const o = MANAGEMENT_OPERATIONS[op];
  const code = json && typeof json === 'object' ? String(json.error || json.code || '').slice(0, 60) || null : null;
  const detail = json && typeof json.message === 'string' ? ': ' + json.message.slice(0, 200) : '';
  const object = json && typeof json === 'object' && !Array.isArray(json);
  if (!o.mutation) {
    if (readError) return {kind: 'refused', message: String(readError.message || 'management response failed').slice(0, 200), status, code};
    if (status < 200 || status >= 300) return {kind: 'refused', message: `management ${op} refused (HTTP ${status})${detail}`, status, code};
    if (!object) return {kind: 'refused', message: 'the host answered with malformed JSON', status, code};
    return {kind: 'ok', json};
  }
  const what = op === 'restart' ? 'restart' : 'CPU profile control';
  const unknown = why => ({kind: 'unknown', message: `the ${what} may have run; its outcome is unknown (${why}): check status before asking again`, status, code});
  if (readError) return unknown('the answer was cut off');
  if (status >= 200 && status < 300) return object && SUCCEEDED[op](json, deploymentId) ? {kind: 'ok', json} : unknown('the success answer was malformed');
  if (!forwarded && status >= 400 && status < 600)
    return {kind: 'refused', message: `management ${what} refused before reaching the supervisor (HTTP ${status})${detail}`, status, code};
  if (forwarded && status >= 400 && status < 500 && (NOT_STARTED[op].has(code) || (op === 'cpuProfileControl' && status === 422)))
    return {kind: 'refused', message: `management ${what} refused (HTTP ${status})${detail}`, status, code};
  return unknown(/_outcome_unknown$/.test(code || '') ? 'the gateway lost the supervisor' : `HTTP ${status}${code ? ' ' + code.slice(0, 40) : ''}`);
}

/** Checks on typed results, shared by both clients. */
export const MAX_PROFILE_BYTES = 16 * 1024 * 1024;
export function checkAppToken(j, deploymentId) {
  return typeof j.token === 'string' && j.token.length > 0 && j.token.length <= 4096 && j.tokenType === 'Cookie' && j.deployment === deploymentId &&
    typeof j.expiresAt === 'string' && Number.isFinite(Date.parse(j.expiresAt));
}
