// Marketplace authority for a restricted Shield runtime. Capacity admission is
// connection-bound; routing and certificates additionally require the exact app.
import fs from 'node:fs';
import {randomBytes} from 'node:crypto';
import { createShieldAppVerifier } from './shield-app-verifier.mjs';
import { shieldHostAdmitted } from './shield-app-policy.mjs';
import { pinnedWitness, readinessInput } from './shield-market-evidence.mjs';

const TTL = 300000, REFRESH = 60000;
// Failures that say nothing about the app: the chain read, this verifier being
// busy, or the node not answering this round. They leave the last verification
// to expire on its own TTL (never extended); anything else revokes it now. One
// such blip used to drop a verified app from DNS until a later round passed.
const TRANSIENT = [/^RPC Request failed/, /^HTTP request failed/, /^The request took too long to respond/, /^Request timed out/, /^fetch failed/,
  /^Shield verification busy; retry shortly$/, /^no bounded app proof from the live node$/, /^catalog component could not be CID-verified$/,
  // too few RPCs ANSWERED a quorum read (measurement-predict.mjs agreeingRead): a provider blip, not an answer. RPCs that
  // answered and DISAGREE are not here: that stays a hard failure (2026-10-17 13:08:19Z: one round of "only 1 of 3"
  // dropped ipns-publisher from DNS at once)
  /^only \d+ of \d+ RPCs answered /];
export const transientAdmissionError = message => TRANSIENT.some(pattern => pattern.test(String(message || '')));
export const fingerprint = d => JSON.stringify([d.id, d.runner, d.appRef, d.configCid, d.isPublic,
  Number(d.cpuMilli), Number(d.gpuMilli), d.active, String(d.owner || "").toLowerCase()]);
export function createShieldMarketplace({ hub, policyFile = '', policy: supplied, confirmRow,
  hasSecrets, isOwnerDeployment = () => false, readCatalog, readConfig, fetchVerified, now = Date.now, log = console.warn }) {
  const policy = supplied || (policyFile ? JSON.parse(fs.readFileSync(policyFile, 'utf8')) : null);
  if (policy && (policy.schema !== 'enclave-shield-app-policy/1' ||
      !(policy.hosts === '*' || (Array.isArray(policy.hosts) && policy.hosts.length)) ||
      !policy.ekRoots || !policy.cpu?.runtimeId)) throw new Error('invalid Shield marketplace policy');
  const configured = name => shieldHostAdmitted(policy, name);
  const verify = policy ? createShieldAppVerifier({ hub, policy, readCatalog, readConfig, fetchVerified, hasSecrets }) : null;
  const witness = pinnedWitness(policy);
  const states = new Map();
  let refreshing = false;
  const session = row => row?.mode === 'hv-node' && configured(row.name) ? hub.shieldSessionId(row.name) : null;
  function stateFor(row) {
    const key = session(row), old = states.get(row?.name);
    return key && old?.session === key ? old : null;
  }
  function eligible(row) { return policy?.marketEnabled === true && !!(stateFor(row)?.until > now()); }
  function servesUntil(host, d) {
    const state = stateFor(host), app = state?.apps.get(d?.id);
    if (!app || !eligible(host) || app.until <= now() || fingerprint(d) !== app.fingerprint ||
        d.active !== true || d.isPublic !== true || (hasSecrets(d.id) && !policy?.cpu?.secretsV1) || (app.ownerException && !isOwnerDeployment(host,d)) ||
        String(d.runner).toLowerCase() !== String(host.id).toLowerCase()) return 0;
    return Math.floor(Math.min(app.until, Number(d.leaseUntil) * 1000) / 1000);
  }
  async function admit(host, candidate, csrSpkiSha256) {
    const sid = session(host);
    if (!sid) return {ok:false, reason:'no configured live Shield session'};
    let state = stateFor(host);
    if (!state) states.set(host.name, state = {session:sid, until:0, apps:new Map(), attempts:new Map(), verdicts:new Set()});
    state.attempts.set(candidate.id,now());
    try {
      const d = await confirmRow(candidate.id);
      if (d.active !== true || d.isPublic !== true || Number(d.leaseUntil)*1000 <= now() ||
          String(d.runner).toLowerCase() !== String(host.id).toLowerCase() || (hasSecrets(d.id) && !policy?.cpu?.secretsV1))
        throw new Error('deployment must be public, compatible and leased to this host');
      const ownerException = isOwnerDeployment(host,d);
      const proof = await verify(host.name, d, {csrSpkiSha256, allowPendingOwner:ownerException});
      if (!proof.ok) throw new Error(proof.reason);
      if (session(host) !== sid) throw new Error('Shield attachment changed during verification');
      // A ledger mutation during the round trip must not acquire the old app's evidence.
      const current = await confirmRow(d.id);
      if (fingerprint(current) !== fingerprint(d) || Number(current.leaseUntil)*1000 <= now() || (hasSecrets(d.id) && !policy?.cpu?.secretsV1) || (ownerException && !isOwnerDeployment(host,current)))
        throw new Error('deployment changed during verification');
      state = stateFor(host);
      const until = now() + TTL;
      state.until = until;
      state.apps.set(d.id, {until, checked:now(), fingerprint:fingerprint(d), ownerException, spkiSha256:proof.spkiSha256});
      state.verdicts.add(d.id);
      if (policy.marketEnabled === true) hub.notifyShieldMarket(host.name, sid, until);
      log(`[shield-market] verified ${host.name}/${d.id.slice(0,10)} runtime app and TLS key (market=${policy.marketEnabled === true})`);
      return proof;
    } catch(e) {
      if (!transientAdmissionError(e.message)) { stateFor(host)?.apps.delete(candidate.id); stateFor(host)?.verdicts?.add(candidate.id); }
      return {ok:false,reason:e.message};
    }
  }
  async function readiness(host) {
    if (!witness || policy.marketEnabled !== true) return;
    const sid = session(host);
    if (!sid) return;
    let state = stateFor(host);
    if (!state) states.set(host.name, state = {session:sid, until:0, apps:new Map(), attempts:new Map(), verdicts:new Set()});
    if (state.witnessAttempt !== undefined && now()-state.witnessAttempt < REFRESH) return;
    state.witnessAttempt = now();
    try {
      const nonce = randomBytes(32);
      const proof = await hub.fetchJson(`tunnel://${host.name}`, `/v1/shield/readiness?nonce=${nonce.toString('hex')}`);
      const verdict = await hub.verifyShieldApp(host.name, readinessInput(proof, nonce, witness), policy);
      if (!verdict.ok) throw Error(verdict.reason);
      if (session(host) !== sid) throw Error('Shield attachment changed during readiness verification');
      stateFor(host).until = now()+TTL;
      // Capacity only: no app entry, lease, route or certificate is granted.
      hub.notifyShieldMarket(host.name, sid, stateFor(host).until);
      if (!state.witnessVerified) log(`[shield-market] ${host.name}: dedicated readiness witness verified`);
      state.witnessVerified = true;
    } catch(e) { log(`[shield-market] ${host.name}: readiness witness: ${e.message}`); }
  }
  return {
    configured, eligible, servesUntil,
    // true until this host's current attachment has a verdict on d (relay/route-grace.mjs keeps a route meanwhile)
    pending: (host, d) => !stateFor(host)?.verdicts?.has(d?.id),
    certificate: (host, d, spki) => admit(host, d, spki),
    async refresh(hosts, rows) {
      if (!policy || refreshing) return;
      refreshing = true;
      try {
        for (const host of hosts.filter(h => session(h))) {
          await readiness(host);
          const candidates = rows.filter(d => d.active === true && d.isPublic === true &&
            String(d.runner).toLowerCase() === String(host.id).toLowerCase() && Number(d.leaseUntil)*1000 > now()).slice(0, 32);
          for (const d of candidates) {
            const state = stateFor(host);
            if (state?.attempts.has(d.id) && now()-state.attempts.get(d.id) < REFRESH) continue;
            const old = state?.apps.get(d.id);
            if (old && now()-old.checked < REFRESH && servesUntil(host,d)) continue;
            const result = await admit(host,d);
            if (!result.ok) log(`[shield-market] ${host.name}/${d.id.slice(0,10)}: ${result.reason}`);
          }
        }
      } finally {refreshing = false;}
    },
  };
}
