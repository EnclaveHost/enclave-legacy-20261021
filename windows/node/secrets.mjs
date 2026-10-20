// windows/node/secrets.mjs -- the relay-staged per-deployment secrets for the app this box holds
// the lease on, fetched with the only key this box has any business holding.
//
// WHAT THESE ARE. An owner stages env-var-shaped private values (S3 keys, API tokens) on the
// api-relay instead of in the deployment's config, because the catalog config and the options
// envelope are both on chain and world-readable by design; relay/secrets.js carries the whole
// trust model, including the part a buyer is owed: the relay operator CAN read them, the chain and
// other tenants cannot. The lease holder pulls the current snapshot right before it starts the app
// and hands the values in as guest env vars. This file is that pull and nothing else: it returns a
// {NAME: value} map and never starts an app, writes a file or keeps a cache.
//
// HOW THIS BOX AUTHENTICATES, and why it is deliberately not how the fleet does it. The relay's
// fetch route takes two factors and opens on EITHER one:
//   * a fleet HMAC over "<id>:<endpoint>:<ts>", derived from the fleet SECRET, which on its own
//     proves only "a holder of the fleet key" and not "this endpoint";
//   * a personal_sign over the SAME tuple by the operator key that REGISTERED this endpoint on
//     chain, which the relay checks against the registry entry and which is per-box.
// We send the second only, and this box must never be given the first: that same derived-key
// family authorizes dns-relay's _acme-challenge TXT pushes, so a holder of the fleet key can
// obtain a CA certificate for every deployment hostname on the platform. On a consumer PC that key
// would live in a file in VTL0, where the enclave boundary does not protect it -- relay/secrets.js
// says so at the line, and calls the operator factor the stronger of the two anyway. What actually
// scopes the answer is the ledger: the relay only serves a deployment whose live lease `runner`
// equals keccak256(endpoint), so `endpoint` here must be the EXACT string this box registered
// (chain.mjs enclaveIdOf), not a prettier spelling of the same URL.
//
// WHY A REFUSAL IS NOT AN EMPTY RESULT. "No secrets staged" and "this box was refused" both end
// with the app running and its $NAME placeholders unresolved, and from inside the guest the two are
// indistinguishable -- that ambiguity cost the platform a two-day investigation pointed at egress
// (supervisor.js fetchDepSecrets, relay/secrets.js log pair). So an empty snapshot returns
// {env:{}, count:0} and a refusal THROWS with the relay's own reason in it. This is the one place
// we do not mirror the platform runner: its fetch never blocks a launch because it has a warm
// per-process cache and a fleet of boxes that have run the deployment before. This box has neither,
// so host.mjs gets to decide, with the reason in hand, whether to launch or hand the lease back.
//
// Values never reach a log line or an error message here, only NAMES and byte counts: a log on this
// box is readable by whoever holds the machine, and an error string ends up on /v1/deployments.

// The relay's own bounds, spelled here so a refusal can name the suspect. FETCH_SKEW_SEC is why a
// box with a wrong clock is refused rather than served, and this is the only refusal an operator
// fixes by looking at their own machine instead of the chain.
const FETCH_SKEW_SEC = 300;
const TIMEOUT_MS = 5000;

// relay/secrets.js SECRET_KEY_RE, re-checked HERE rather than trusted, because the relay is not the
// authority for what this box puts on a command line. A name with "=" or a space in it passes
// nothing on the way in but would be split at the wrong place by wasmtime's `--env K=V` argv
// (apprun.mjs serveArgs) or by the enclave's "K=V\0K=V\0\0" env block (EnclaveApp), and a name
// carrying a NUL would truncate the block and hand the rest of it to the guest as another variable.
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
// The platform's own variables, by name. A secret that landed on one of these would not add a
// variable, it would REPLACE a channel: ENCLAVE_CONFIG is the app's whole config, ENCLAVE_MEM_MB
// its size, ENCLAVE_PORTS its port map, ENCLAVE_EGRESS its outbound. The relay refuses the entire
// ENCLAVE_ prefix on write (checkEnvMap), and so do we on read, for a reason this box has that the
// fleet does not: it adds ENCLAVE_INFERENCE_URL (apprun.mjs appEnv), the loopback address of the
// model in VTL1, which is not one of the four -- a secret with that name would silently point an
// app's inference calls somewhere off the machine.
const RESERVED = new Set(["ENCLAVE_CONFIG", "ENCLAVE_MEM_MB", "ENCLAVE_PORTS", "ENCLAVE_EGRESS"]);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Pull this deployment's secrets snapshot from the relay.
 *
 *   id        the bytes32 deployment id (lowercased before it is signed: the relay lowercases
 *             what it verifies, so the tuple has to be lowercase on this side too)
 *   endpoint  this box's publicUrl -- the string whose keccak256 is its registry/lease id
 *   sign      async (message) => 0x<130 hex>, the operator key's personal_sign. PASSED IN: this
 *             module never touches operator.key, so a bug here cannot become a key read
 *   base      relay origin; "" disables the pull entirely (the supervisor's SECRETS_API="" lever)
 *   log       names and counts only
 *
 * Returns { env, count, rev, dropped, source }, where source is one of:
 *   "relay"         the relay served this snapshot (count may legitimately be 0)
 *   "off"           no relay configured on this box: nothing to fetch
 *   "disabled"      the relay does not have the secrets plane configured (503)
 *   "not-on-ledger" the relay's ledger view has no such deployment, or no fetch route (404)
 * and throws on every other outcome.
 */
export async function fetchSecrets({ id, endpoint, sign, base = "https://api.enclave.host", log = () => {} }) {
  // Checked against the relay's own parser first, because a request it would 422 is a request we
  // should not have signed: a signature is a small commitment, but it is the box's identity, and
  // signing tuples built from junk is how a key ends up over a message nobody audited.
  const idL = String(id || "").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(idL)) throw new Error(`secrets: "${id}" is not a bytes32 deployment id`);
  // Trailing slashes off BEFORE signing, not after. The relay strips them from the endpoint it
  // verifies (`String(b.endpoint).replace(/\/+$/, "")`) and builds its message from the stripped
  // form, so a signature over the unstripped spelling recovers the RIGHT key over the WRONG
  // message and comes back 403 wrong_operator -- a refusal that reads like a stolen key.
  const ep = String(endpoint || "").replace(/\/+$/, "");
  if (!/^https?:\/\//.test(ep)) throw new Error("secrets: endpoint must be this box's registered http(s) origin");
  if (typeof sign !== "function") throw new Error("secrets: no operator sign function was passed");
  const api = String(base || "").trim().replace(/\/+$/, "");
  if (!api) { log("secrets: no relay configured; the app launches with none"); return { env: {}, count: 0, rev: 0, dropped: [], source: "off" }; }

  let last = "";
  // Three goes, the platform runner's backoff. Only the transient classes come back here: the wire,
  // a 409 (the chain has not caught up with our own claim tx yet -- we fetch seconds after it), a
  // 429 and a 5xx. A 401/403 never retries, because a wrong key and a wrong clock do not fix
  // themselves in four seconds and hammering the route only burns the relay's per-ip bucket.
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt) await sleep(attempt === 1 ? 1000 : 3000);
    // Re-signed per attempt with a fresh ts, so a backoff cannot age the tuple past the relay's
    // skew window. Free to do: this route keeps no single-use signature cache (fleet-auth.js
    // makeReplayCache is the owner routes' and certs.js's), and the tuple is bound to the id and
    // the endpoint, so a captured one is worth nothing off this box anyway.
    const ts = Math.floor(Date.now() / 1000);
    // Byte for byte what relay/fleet-auth.js recoverOp will verify: the literal prefix, the
    // lowercased id, the stripped endpoint, and the same ts that rides in the body. EIP-191
    // personal_sign, which is also why this is safe to ask of the key that sends our claims -- a
    // personal_sign can never be replayed as a transaction.
    const message = `enclave-secrets-fetch:${idL}:${ep}:${ts}`;
    let opSig;
    try { opSig = String(await sign(message) || ""); }
    catch (e) { throw new Error(`secrets: the operator key would not sign the fetch: ${e.message}`); }
    // Refuse our own malformed signature rather than spend a round trip on a 401 the relay would
    // log as "supervisor predates the check" -- that log line sends an operator hunting a rollout
    // problem that is really a broken sign function on this box.
    if (!/^0x[0-9a-fA-F]{130}$/.test(opSig))
      throw new Error("secrets: sign() did not return a 65-byte personal_sign hex; the relay would refuse it unread");

    let status = 0, text = "";
    try {
      // No `sig` field at all: this box holds no fleet key and sending an empty one would only
      // make the relay's refusal log read as a failed HMAC instead of what it is.
      const r = await fetch(`${api}/v1/secrets/fetch`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: idL, endpoint: ep, ts, opSig }),
        signal: AbortSignal.timeout(TIMEOUT_MS) });
      status = r.status;
      text = await r.text();
    } catch (e) { last = e.message || String(e); continue; }   // the wire: worth another go

    if (status === 200) {
      let b;
      try { b = JSON.parse(text); } catch { throw new Error(`secrets: the relay answered ${text.length} bytes that are not JSON`); }
      // The reply must be about the deployment we ASKED about. It always is from the real relay
      // (it echoes the id it served), so a mismatch means something in the middle answered -- a
      // captive portal, a proxy serving a cached body, a tunnel crossed with another box's. That
      // is the one way another tenant's values could reach this guest, and it costs one compare.
      if (String(b?.id || "").toLowerCase() !== idL)
        throw new Error(`secrets: the relay answered for ${String(b?.id || "(nothing)").slice(0, 66)}, not ${idL}`);
      if (!b.env || typeof b.env !== "object" || Array.isArray(b.env))
        throw new Error("secrets: the relay's reply carries no env object");
      const rev = Number(b.rev) || 0;

      const env = {}, dropped = [];
      for (const [k, v] of Object.entries(b.env)) {
        // Every drop says WHY. A silently dropped name is the same invisible failure as a refused
        // fetch: the app comes up, one variable is missing, and nothing on either side said so.
        const drop = (why) => { dropped.push(k); log(`secrets: dropping "${k}" -- ${why}`); };
        if (!NAME_RE.test(k)) { drop("not an env-var name ([A-Za-z_][A-Za-z0-9_]*, max 64), and the guest would misread it"); continue; }
        if (RESERVED.has(k)) { drop("it is one of the platform's own variables and would replace a channel, not add one"); continue; }
        if (/^ENCLAVE_/i.test(k)) { drop("the ENCLAVE_ prefix is the platform's namespace (this box also sets ENCLAVE_INFERENCE_URL)"); continue; }
        if (typeof v !== "string") { drop(`its value is ${Array.isArray(v) ? "an array" : typeof v}, not a string`); continue; }
        // A NUL would end the enclave's env block early; a newline breaks the one-line argv and
        // every log line downstream of it. Byte count only -- the value itself stays out of here.
        if (/[\0\r\n]/.test(v)) { drop(`its ${Buffer.byteLength(v, "utf8")}-byte value contains a NUL or newline`); continue; }
        env[k] = v;
      }
      const count = Object.keys(env).length;
      log(`secrets: rev ${rev}, ${count} name(s) for ${idL.slice(0, 10)}${count ? ` (${Object.keys(env).sort().join(", ")})` : ""}`
        + `${dropped.length ? `, ${dropped.length} dropped` : ""}`);
      return { env, count, rev, dropped, source: "relay" };
    }

    // The relay's own {error, message} pair, which names the signer, the endpoint or the ledger
    // row and never a value -- worth carrying verbatim into the throw, because it is the only
    // description of the refusal that exists.
    let code = "", why = "";
    try { const e = JSON.parse(text); code = String(e.error || ""); why = String(e.message || ""); } catch { why = text.slice(0, 200); }

    // Authoritative "there is nothing to inject", and not worth a retry: the relay has no secrets
    // plane at all, or its ledger view has no such row (which is also the answer if this relay is
    // old enough to have no fetch route). Neither is a refusal OF THIS BOX, so neither throws.
    // ONLY the relay's own secrets_disabled 503 says that (relay/secrets.js: the route's one 503). Any other 503 - a
    // proxy in front of a relay that is restarting, an overloaded upstream - says nothing about this deployment's
    // secrets, and used to be read as "no secrets plane", so the app launched without them and the isolation probe
    // counted "none" (enclave-b4's N3). It is transient now: retried with the 5xx, then thrown.
    if (status === 503 && code === "secrets_disabled") { log(`secrets: this relay has no secrets plane (${code}); the app launches with none`); return { env: {}, count: 0, rev: 0, dropped: [], source: "disabled" }; }
    if (status === 404) { log(`secrets: the relay has no record to serve for ${idL.slice(0, 10)} (${code || "404"}); the app launches with none`); return { env: {}, count: 0, rev: 0, dropped: [], source: "not-on-ledger" }; }

    // REFUSED. Four causes, all of them this box's to fix, and the caller needs the difference:
    // 401 no_operator_sig / bad_fetch_sig = the registry does not authorize what we sent (or the
    // entry is gone), 403 wrong_operator = the entry names a different key than the one that
    // signed, 422 bad_ts = our clock. None of them mean "no secrets", so none of them may be
    // rounded off to an empty env.
    if (status === 401 || status === 403)
      throw new Error(`secrets: the relay REFUSED this box for ${idL} (HTTP ${status} ${code || "?"}): ${why}`
        + " -- this box is not authorized to fetch them: check its registry entry is active and names the operator key that signed.");
    if (status === 422)
      throw new Error(`secrets: the relay rejected the request for ${idL} (HTTP 422 ${code || "?"}): ${why}`
        + (code === "bad_ts" ? ` -- this box's clock must be within ${FETCH_SKEW_SEC}s of real time.` : ""));
    last = `HTTP ${status}${code ? ` ${code}` : ""}${why ? `: ${why}` : ""}`;
  }
  // Out of goes. 409 (not the live lease holder), 429 and 5xx land here, and the caller is the one
  // that knows whether a lease this box believes it holds is worth waiting on.
  throw new Error(`secrets: could not fetch the secrets for ${idL} after 3 tries (${last}).`);
}

/**
 * The app's environment: the platform's own variables over the deployment's secrets.
 *
 * Layered in that order deliberately. The filter above already refuses the ENCLAVE_ namespace, so
 * this is the second of two independent reasons a secret cannot shadow ENCLAVE_CONFIG -- and the
 * cheaper one to be sure of, since it holds even if a future name ever slips the filter. A new
 * object, because the caller keeps its platform env across restarts and a merge that wrote into it
 * would leave a secret behind in it after the deployment's lease was gone.
 */
export function mergeEnv(base, secrets) {
  return { ...(secrets || {}), ...(base || {}) };
}

/**
 * secretsExist({ id, base }) -> true | false: does the relay hold staged secrets for this deployment? Throws when it
 * cannot say. The relay's /v1/secrets/exists is deliberately UNAUTHENTICATED and needs no lease (relay/secrets.js: a
 * runner asks it before claiming), and it answers only the boolean - no names, no values. The isolated backend needs
 * nothing more: a partition is never handed secrets, so all the node must know is whether there are any. Unlike the
 * lease holder's fetch it works BEFORE a claim, and for a lease holder the relay does not hold eligible - the fetch
 * refuses both (409 not_lease_holder; 403 host_ineligible since U7), which left d1's live test 1 held as "not known".
 * Anything but a 200 that names this id with a boolean is a throw (unknown): never "no". A 5xx or the wire is retried once.
 */
export async function secretsExist({ id, base = "https://api.enclave.host" } = {}) {
  const idL = String(id || "").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(idL)) throw new Error(`secrets: "${id}" is not a bytes32 deployment id`);
  const api = String(base || "").trim().replace(/\/+$/, "");
  if (!api) throw new Error("secrets: no relay configured, so whether this deployment has secrets is not known");
  let last = "";
  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt) await sleep(1000);
    let status = 0, text = "";
    try {
      const r = await fetch(`${api}/v1/secrets/exists`, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: idL }), signal: AbortSignal.timeout(TIMEOUT_MS) });
      status = r.status; text = await r.text();
    } catch (e) { last = e.message || String(e); continue; }
    if (status === 200) {
      let b; try { b = JSON.parse(text); } catch { throw new Error("secrets: the relay's exists answer is not JSON"); }
      if (String(b?.id || "").toLowerCase() !== idL) throw new Error(`secrets: the relay answered exists for ${String(b?.id || "(nothing)").slice(0, 66)}, not ${idL}`);
      if (typeof b.exists !== "boolean") throw new Error("secrets: the relay's exists answer carries no boolean");
      return b.exists;
    }
    last = `HTTP ${status}${text ? `: ${text.slice(0, 120)}` : ""}`;
    if (status < 500) break;                              // 4xx (429 included) is not fixed by asking again now
  }
  throw new Error(`secrets: whether ${idL} has staged secrets is not known (${last})`);
}

// ---- owner-committed custody-v2 (the transport boundary for a Shield guest) ------------------------------------------
//
// A deployment started from an owner-committed package (shield-startup.mjs) never uses the relay pull above. Its secrets,
// when it has any, are custody-v2's: the GUEST proves itself to the owner's committee and opens the shares with a key that
// never leaves it. This host's only part is the one the Linux host has (supervisor.js authorizeCustody, v2): as the lease
// holder's registered operator it signs the guest's release binding - a hash - for the exact vault the owner committed.
// It never sees a share, a bundle key or a value, and it signs for nothing else.
//
// ACTIVE ONLY behind the manager's supports.custodyV2 (a stated custody image, windows/vbslike/manager/custody-transport.mjs):
// shield-startup.mjs refuses a custody-v2 package otherwise. The node's pump (shield-custody.mjs) re-verifies the startup
// and this host's lease before it calls this, and each custodian challenges this node's TPM itself (shield-sessions.mjs).
// The message is custody/v2/protocol.mjs operatorMessage's, byte for byte.
export const CUSTODY_SIG_TTL_SEC = 300;
export const custodyOperatorMessageV2 = ({ chainId, vault, id, endpoint, binding, expiry }) =>
  `enclave-custody-release-v2:${chainId}:${String(vault).toLowerCase()}:${id}:${endpoint}:${binding}:${expiry}`;
const CUSTODY_ID = /^0x[0-9a-f]{64}$/;
/**
 * custodyAuthorization({ startup, record, instance, request, endpoint, sign, chainId, now }) -> { binding, endpoint, sig, expiry }
 *   startup   the FRESHLY verified startup (secretsMode custody-v2, custody: the package's pointer, deployment: its id)
 *   record    the host's record for that deployment (record.id must BE startup.deployment): starting, provisioning or running
 *   instance  the manager's view of the exact partition asking: this deployment's, on this package, app and runtime
 *   request   { v: 2, vault, id?, binding } as the guest stated it through the manager
 * Throws, naming the refusal, for anything else. One deployment's pointer can never sign for another's record or partition.
 */
export async function custodyAuthorization({ startup, record, instance, request, endpoint, sign, chainId = 8453, now = () => Date.now() }) {
  if (!startup || startup.secretsMode !== "custody-v2" || !startup.custody) throw new Error("custody: the deployment's package does not keep secrets in custody-v2");
  const vault = String(startup.custody.vault || "").toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(vault) || Number(startup.custody.chainId) !== chainId) throw new Error("custody: the package's custody pointer names no vault on this chain");
  // ONE deployment throughout: the verified startup's, exactly, with no fallback between the record and the pointer
  const id = typeof startup.deployment === "string" ? startup.deployment : "";
  if (!CUSTODY_ID.test(id)) throw new Error("custody: the verified startup names no deployment");
  if (!record || record.id !== id) throw new Error("custody: the host record is another deployment's than the verified startup's");
  if (!["starting", "provisioning", "running"].includes(record.status))
    throw new Error("custody: no partition of this deployment is starting or running here");
  const v = instance;
  if (!v || typeof v !== "object" || v.name !== id || v.secretDeployment !== id || v.recovered === true || !["starting", "running"].includes(v.status))
    throw new Error("custody: the asking partition is not this deployment's live secret domain");
  if (v.bootstrapSha256 !== startup.sha256 || v.appId !== startup.appId || v.runtimeId !== startup.runtimeId)
    throw new Error("custody: the asking partition does not run the verified package, app and runtime");
  if (String(v.custody?.vault || "") !== vault) throw new Error("custody: the asking partition's channel is for another vault");
  // on the Shield-direct image whose IGVM is THIS node's pin (F3), never on another image that happens to share the RuntimeID
  if (v.imageRole !== "shield-direct" || !startup.imageSha256 || v.igvmSha256 !== startup.imageSha256)
    throw new Error("custody: the asking partition is not on this host's pinned Shield-direct image");
  const held = record.isolation?.instance ?? record.isolationHeld ?? null;
  if (held && held !== v.id) throw new Error("custody: the host record holds another partition of this deployment");
  if (!request || request.v !== 2 || String(request.vault || "").toLowerCase() !== vault) throw new Error("custody: the guest asked for a vault its owner did not commit");
  if (request.id !== undefined && request.id !== id) throw new Error("custody: the guest asked for another deployment");
  const binding = String(request.binding || "");
  if (!/^[0-9a-f]{64}$/.test(binding)) throw new Error("custody: the guest's release binding is not 32 bytes of hex");
  const ep = String(endpoint || "").replace(/\/+$/, "");
  if (!/^https?:\/\//.test(ep)) throw new Error("custody: endpoint must be this box's registered origin");
  if (typeof sign !== "function") throw new Error("custody: no operator sign function was passed");
  const expiry = Math.floor(now() / 1000) + CUSTODY_SIG_TTL_SEC;
  const sig = String(await sign(custodyOperatorMessageV2({ chainId, vault, id, endpoint: ep, binding, expiry })) || "");
  if (!/^0x[0-9a-fA-F]{130}$/.test(sig)) throw new Error("custody: sign() did not return a 65-byte personal_sign hex");
  return { binding, endpoint: ep, sig, expiry };
}
