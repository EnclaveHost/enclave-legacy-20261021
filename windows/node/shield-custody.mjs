// windows/node/shield-custody.mjs - this host's answers to direct Shield custody requests (vsock 9445).
//
// A Shield-direct custody guest (isolation/m2/front/shield_direct_custody.go) opens its owner's custody-v2 shares itself.
// The one thing it asks this host for is the lease holder's operator signature over its release binding, for the exact
// vault its package commits. The manager holds each request on the partition's own channel and lists it on that
// partition's view (awaitingCustodyAuth; windows/vbslike/manager/custody-transport.mjs). This pump answers it, and only
// after re-establishing everything the signature stands for, at the moment it signs:
//   1. the deployment's owner-committed startup and THIS host's live lease, from a fresh agreed quorum read (verify:
//      shield-startup.mjs materialize with needLease), still the package this partition was spawned with;
//   2. this node's TPM sessions with that package's custodians, brought up to date (ensureSessions): each custodian
//      challenges this node itself, and there is no Enclave verdict anywhere in the path;
//   3. the exact partition asking: this deployment's live secret domain, on that package, app and runtime, for that
//      vault (secrets.mjs custodyAuthorization).
// The answer reaches the manager through its authenticated callback (an HMAC under the key the two share). Nothing here
// sees a share or a value, and a refusal is not answered at all: the guest's request times out and it starts nothing.
import { custodyAuthorization } from "./secrets.mjs";
import { custodyCallbackHeader, CUSTODY_CALLBACK_HEADER } from "../vbslike/manager/custody-transport.mjs";

const DEPLOYMENT = /^0x[0-9a-f]{64}$/;
const INSTANCE = /^[A-Za-z0-9-]{1,64}$/;                    // server.mjs ID_RE: safe in a path without encoding
const REQUEST = /^[0-9a-f]{32}$/;
const short = (e) => String(e?.message || e).slice(0, 200);

/**
 * createShieldCustody({ base, callbackKey, endpoint, sign, records, verify, ensureSessions, ... }) -> { pass }
 *   base            the manager's loopback origin (host.cfg.isolationManager)
 *   callbackKey     Buffer, the key the manager was started with (ENCLAVE_CUSTODY_CALLBACK_KEY_FILE)
 *   endpoint        this box's registered origin (the lease's runner is keccak256 of it)
 *   sign            the operator key's personal_sign (message) -> 0x hex
 *   records         () -> the host's records Map (id -> record with its verified `startup`)
 *   verify          async (deploymentId) -> materialize's verdict, fresh, with this host's lease required
 *   ensureSessions  async () -> refresh this node's TPM sessions at the live packages' custodians (bounded by its caller)
 */
export function createShieldCustody({ base, callbackKey, endpoint, sign, records, verify, ensureSessions = async () => {},
                                      fetchImpl = globalThis.fetch, chainId = 8453, now = Date.now, log = () => {},
                                      maxPerPass = 4, timeoutMs = 15_000, retryMs = 5_000, sessionWaitMs = 45_000 }) {
  if (!/^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(String(base || "").replace(/\/+$/, ""))) throw new Error("the custody pump talks only to a loopback manager (http://127.0.0.1:<port>)");
  if (!Buffer.isBuffer(callbackKey) || callbackKey.length < 32) throw new Error("the custody pump needs the manager's callback key (at least 32 bytes)");
  if (typeof sign !== "function" || typeof verify !== "function" || typeof records !== "function") throw new Error("the custody pump needs sign, verify and records");
  const origin = String(base).replace(/\/+$/, "");
  const done = new Set(), retry = new Map();            // `${instance} ${request}`: answered or definitely refused / next try
  let active = false;
  const post = async (path, body) => {
    const r = await fetchImpl(origin + path, { method: "POST", redirect: "error", body, signal: AbortSignal.timeout(timeoutMs),
      headers: { "content-type": "application/json", [CUSTODY_CALLBACK_HEADER]: custodyCallbackHeader(callbackKey, { path, body, now: now() }) } });
    const text = await r.text().catch(() => "");
    if (!r.ok) throw new Error(`the manager refused the answer: HTTP ${r.status}${text ? ` ${text.slice(0, 160)}` : ""}`);
  };
  return {
    /** One pass over the manager's views: at most maxPerPass requests answered or refused; one pass at a time. */
    async pass() {
      if (active) return { skipped: true };
      active = true;
      const answered = [], refused = [], waiting = [];
      try {
        const r = await fetchImpl(origin + "/vms", { redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
        if (!r.ok) throw new Error(`manager inventory unavailable (HTTP ${r.status})`);
        const vms = (await r.json())?.vms;
        if (!Array.isArray(vms)) throw new Error("manager inventory is not a list");
        const asked = (v) => (Array.isArray(v?.awaitingCustodyAuth) ? v.awaitingCustodyAuth : []).filter((q) => REQUEST.test(String(q?.request || "")));
        const live = new Set(vms.flatMap((v) => asked(v).map((q) => `${v.id} ${q.request}`)));
        for (const k of done) if (!live.has(k)) done.delete(k);
        for (const k of retry.keys()) if (!live.has(k)) retry.delete(k);
        let budget = maxPerPass;
        for (const v of vms) {
          if (budget <= 0) break;
          const todo = asked(v).filter((q) => { const k = `${v.id} ${q.request}`; return !done.has(k) && now() >= (retry.get(k) || 0); }).slice(0, budget);
          if (!todo.length) continue;
          budget -= todo.length;
          const keys = todo.map((q) => `${v.id} ${q.request}`);
          const refuse = (why, definite) => {
            for (const k of keys) { if (definite) { done.add(k); retry.delete(k); } else retry.set(k, now() + retryMs); }
            (definite ? refused : waiting).push(`${String(v.name || v.id).slice(0, 10)}: ${why}`);
            log(`custody ${String(v.name || v.id).slice(0, 10)} ${definite ? "refused" : "waiting"}: ${why}`);
          };
          if (!INSTANCE.test(String(v.id || "")) || !DEPLOYMENT.test(String(v.name || ""))) { refuse("the asking partition names no deployment", true); continue; }
          const recs = records();
          const rec = recs && typeof recs.get === "function" ? recs.get(v.name) : null;
          if (!rec?.startup) { refuse("this host holds no verified owner-committed startup for it", true); continue; }
          let fresh;
          try { fresh = await verify(v.name); }
          catch (e) { refuse(`its startup and lease could not be re-verified: ${short(e)}`, false); continue; }
          if (!fresh || fresh.ok !== true || !fresh.startup) {
            refuse(`its startup and this host's lease are not established now: ${String(fresh?.why || "no verdict").slice(0, 200)}`, fresh?.unknown === false);
            continue;
          }
          if (fresh.startup.deployment !== v.name || fresh.startup.sha256 !== rec.startup.sha256) {
            refuse("its committed startup is not the package this partition was spawned with", true); continue;
          }
          // bounded: the guest waits two minutes for its answer, and the custodians judge the sessions anyway
          let timer;
          try { await Promise.race([ensureSessions(fresh.startup), new Promise((_, no) => { timer = setTimeout(() => no(new Error("timed out")), sessionWaitMs); })]); }
          catch (e) { log(`custody ${v.name.slice(0, 10)}: custodian sessions: ${short(e)}`); }
          finally { clearTimeout(timer); }
          for (const [i, q] of todo.entries()) {
            const k = keys[i];
            let auth;
            try {
              auth = await custodyAuthorization({ startup: fresh.startup, record: rec, instance: v,
                request: { v: q.v, vault: q.vault, id: q.id, binding: q.binding }, endpoint, sign, chainId, now });
            } catch (e) { done.add(k); refused.push(`${v.name.slice(0, 10)}: ${short(e)}`); log(`custody ${v.name.slice(0, 10)} refused: ${short(e)}`); continue; }
            // sent at most once: an answer whose outcome is unknown is never signed again (the guest asks anew)
            done.add(k); retry.delete(k);
            const path = `/vms/${v.id}/custody-auth`;
            const body = JSON.stringify({ request: q.request, binding: auth.binding, endpoint: auth.endpoint, sig: auth.sig, expiry: auth.expiry });
            try { await post(path, body); answered.push(`${v.name.slice(0, 10)} ${q.request.slice(0, 8)}`); log(`custody ${v.name.slice(0, 10)}: release binding authorized (expires ${auth.expiry})`); }
            catch (e) { refused.push(`${v.name.slice(0, 10)}: ${short(e)}`); log(`custody ${v.name.slice(0, 10)}: ${short(e)}`); }
          }
        }
        return { answered, refused, waiting };
      } finally { active = false; }
    },
  };
}
