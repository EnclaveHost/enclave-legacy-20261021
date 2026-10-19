// windows/node/session-api-auth.mjs -- a WALLET SESSION as the owner's credential on a host.
//
// Shared by the Linux supervisor (supervisor.js, COPY'd into its image beside verification-checkpoints.mjs) and the
// Windows hv-node agent (shipped by deploy-files.mjs, which follows the agent's imports). It lives under windows/node
// because that is where code the two share already lives, and because a file outside windows/node may not import an npm
// package there (the box has node_modules only in windows/node).
//
// THE CREDENTIAL (docs/design/sessions.md; signer sdk/sessions/src/client.ts signApiRequest):
//
//   Authorization: EnclaveSession v1 vault=<0x addr>,sid=<0x bytes32>,ts=<unix s>,n=<base64url>,x=<b64url 32>,
//                  y=<b64url 32>,sig=<b64url 64-byte r||s>
//
// sig is ECDSA P-256/SHA-256 over
//   "enclave-api-v1\n" METHOD "\n" hostPath "\n" sha256hex(raw body) "\n" ts "\n" n "\n" vault(lower) "\n" sid(lower)
// where hostPath is host + pathname + search of the URL the CLIENT called.
//
// WHAT A HOST CHECKS, from the chain and never from the relay's word (the relay forwards; it does not vouch):
//   1. the signature, for a hostPath this host may be addressed under (apiBases below) and the path as received;
//   2. ts within +-60 s of this host's clock, and (vault, sid, n) never seen here before: a nonce is single-use PER HOST;
//   3. the vault was created by a known SessionVaultFactory (factory.isVault), and vault.sessionOf(sid) is live, holds
//      keccak256(abi.encode(x, y)) as its key, and has the route's scope bit;
//   4. per record (refusal below): a record the VAULT holds is acted on only inside the session's environments (its
//      vault.held(id) env); a record the owner's WALLET holds only by a session covering production AND only once the
//      wallet let its vault act for it on the ledger (setDelegate, ledger rev 15d). Anything else is someone else's.
//
// Reads are cached for at most CACHE_MS (a negative answer too); a mutation (fresh) reads the chain again.
import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { encodeAbiParameters, getAddress, keccak256, stringToHex, pad, toFunctionSelector } from "viem";

/** The off-chain API scopes, as bits of a session's `actions` (SessionVaultLib.actionBit; sdk constants.ts). */
export const API_SCOPES = Object.freeze({
  "api.status": 128n, "api.logs": 129n, "api.restart": 130n, "api.upload": 131n, "api.appAccess": 132n,
  "api.placement": 133n, "api.account": 134n,
});
export const ENV_STAGING = 1;
export const ENV_PROD = 2;
/** SessionVaultFactory v2 (delegation-aware) and v1 on Base. A vault of either is a vault. */
export const FACTORY_V2 = "0x1F5c887c0cDF491b16AB6c449abAfDF9B2ec9C9C";
export const FACTORY_V1 = "0x00bB59c40768aA56E292b4E789f9f3B5826E3a8d";
export const DEFAULT_FACTORIES = Object.freeze([FACTORY_V2, FACTORY_V1]);
/** The public API front door a client calls; the relay forwards per-deployment calls to the host that runs them. */
export const DEFAULT_API_HOSTS = Object.freeze(["api.enclave.host"]);
export const WINDOW_SEC = 60;
export const CACHE_MS = 5000;
/** isDelegate[owner][delegate] lives at slot 23 of the rev 15d ledger (sdk/sessions/src/delegate.ts). */
export const DELEGATE_SLOT = 23n;
const SET_DELEGATE_PUSH4 = "63" + toFunctionSelector("setDelegate(address,bool)").slice(2).toLowerCase();
const BOOK_KEY_FACTORY = pad(stringToHex("sessionVaultFactory"), { dir: "right", size: 32 });
const BOOK_KEY_DEPLOYMENTS = pad(stringToHex("deployments"), { dir: "right", size: 32 });
const ZERO = /^0x0{40}$/i;

const SESSION_TUPLE = [
  { name: "keyHash", type: "bytes32" }, { name: "measurement", type: "bytes32" }, { name: "actions", type: "uint256" },
  { name: "expiresAt", type: "uint64" }, { name: "epoch", type: "uint64" }, { name: "envs", type: "uint8" },
  { name: "state", type: "uint8" }, { name: "anyApp", type: "bool" }, { name: "balance6", type: "uint128" },
  { name: "spent6", type: "uint128" }, { name: "perPeriod6", type: "uint128" }, { name: "maxFee6", type: "uint128" },
  { name: "maxAppFeeHour6", type: "uint128" }, { name: "maxRateHour6", type: "uint128" }, { name: "periodStart", type: "uint64" },
  { name: "period", type: "uint32" }, { name: "opsPerPeriod", type: "uint32" }, { name: "periodSpent6", type: "uint128" },
  { name: "periodOps", type: "uint32" },
];
export const VAULT_ABI = [
  { type: "function", name: "sessionOf", stateMutability: "view", inputs: [{ name: "sid", type: "bytes32" }],
    outputs: [{ name: "s", type: "tuple", components: SESSION_TUPLE }, { name: "live", type: "bool" }, { name: "apps", type: "bytes32[]" }] },
  { type: "function", name: "owner", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "held", stateMutability: "view", inputs: [{ type: "bytes32" }],
    outputs: [{ name: "env", type: "uint8" }, { name: "promoted", type: "bytes32" }, { name: "createdBy", type: "bytes32" }] },
];
export const FACTORY_ABI = [{ type: "function", name: "isVault", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }] }];
const BOOK_ABI = [{ type: "function", name: "addr", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "address" }] }];

/** A refusal with the HTTP status it means: 401 (not a valid session credential), 403 (valid, not allowed),
 *  503 (the chain could not be read: fail closed). */
export class SessionAuthError extends Error {
  constructor(status, code, message) { super(message); this.name = "SessionAuthError"; this.status = status; this.code = code; }
}
const e401 = (m, code = "unauthorized") => new SessionAuthError(401, code, m);

/** Does this Authorization value use the EnclaveSession scheme? (Case-insensitive, as auth schemes are.) A header that
 *  does is ALWAYS judged as a session: malformed is a 401, never a fall-through to another credential or to anonymous. */
export function isSessionHeader(h) {
  return typeof h === "string" && /^\s*EnclaveSession(?:\s|$)/i.test(h);
}

const B64U = (bytes) => new RegExp(`^[A-Za-z0-9_-]{${Math.ceil(bytes * 4 / 3)}}={0,2}$`);
const X_RE = B64U(32), SIG_RE = B64U(64);

/** Parse the header -> { vault, sid, ts, n, x, y, sig } (x, y, sig as Buffers). Throws a 401 on anything off-format. */
export function parseSessionHeader(h) {
  const m = /^EnclaveSession v1 (\S.*)$/.exec(String(h ?? "").trim());
  if (!m) throw e401("malformed EnclaveSession authorization: expected `EnclaveSession v1 vault=…,sid=…,ts=…,n=…,x=…,y=…,sig=…`");
  const f = Object.create(null);
  for (const kv of m[1].split(",")) {
    const i = kv.indexOf("=");
    if (i <= 0) throw e401("malformed EnclaveSession authorization: every field is key=value");
    const k = kv.slice(0, i).trim(), v = kv.slice(i + 1).trim();
    if (k in f) throw e401(`malformed EnclaveSession authorization: ${k} appears twice`);
    f[k] = v;
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(f.vault || "")) throw e401("EnclaveSession: vault must be an address");
  if (!/^0x[0-9a-fA-F]{64}$/.test(f.sid || "")) throw e401("EnclaveSession: sid must be 32-byte hex");
  if (!/^\d{1,12}$/.test(f.ts || "")) throw e401("EnclaveSession: ts must be a unix time in seconds");
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(f.n || "")) throw e401("EnclaveSession: bad request nonce");
  if (!X_RE.test(f.x || "") || !X_RE.test(f.y || "")) throw e401("EnclaveSession: bad session public key");
  if (!SIG_RE.test(f.sig || "")) throw e401("EnclaveSession: bad signature encoding");
  const x = Buffer.from(f.x, "base64url"), y = Buffer.from(f.y, "base64url"), sig = Buffer.from(f.sig, "base64url");
  if (x.length !== 32 || y.length !== 32) throw e401("EnclaveSession: bad session public key");
  if (sig.length !== 64) throw e401("EnclaveSession: bad signature encoding");
  return { vault: getAddress(f.vault), sid: f.sid.toLowerCase(), ts: Number(f.ts), n: f.n, x, y, sig };
}

export const sha256Hex = (body) => createHash("sha256").update(body == null ? Buffer.alloc(0) : body).digest("hex");

/** The exact bytes the session key signs (sdk apiMessage, relay verifyClaimed). */
export function apiMessage(method, hostPath, bodyHashHex, ts, n, vault, sid) {
  return `enclave-api-v1\n${String(method).toUpperCase()}\n${hostPath}\n${bodyHashHex}\n${ts}\n${n}\n${String(vault).toLowerCase()}\n${String(sid).toLowerCase()}`;
}

/** keccak256(abi.encode(uint256 x, uint256 y)): what a session stores as its keyHash. */
export function sessionKeyHash(x, y) {
  return keccak256(encodeAbiParameters([{ type: "uint256" }, { type: "uint256" }],
    [BigInt("0x" + Buffer.from(x).toString("hex")), BigInt("0x" + Buffer.from(y).toString("hex"))]));
}

/** keccak256(abi.encode(delegate, keccak256(abi.encode(owner, 23)))): where the ledger keeps isDelegate[owner][delegate]. */
export function delegateSlot(owner, delegate) {
  const inner = keccak256(encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [getAddress(owner), DELEGATE_SLOT]));
  return keccak256(encodeAbiParameters([{ type: "address" }, { type: "bytes32" }], [getAddress(delegate), inner]));
}
/** Does this runtime code dispatch setDelegate(address,bool)? (Its selector pushed as PUSH4: 0x63 ++ 4a994eef.) */
export const codeHasDelegation = (code) => typeof code === "string" && code.toLowerCase().includes(SET_DELEGATE_PUSH4);

/** Is `scope`'s bit set in a session's actions mask? */
export function hasScope(actions, scope) {
  if (!(scope in API_SCOPES)) throw new SessionAuthError(500, "internal", `unknown API scope ${scope}`);
  return ((BigInt(actions) >> API_SCOPES[scope]) & 1n) === 1n;
}

const normHost = (h) => String(h || "").trim().toLowerCase().replace(/\.$/, "");
/**
 * The BASES a client may have signed a request to this host under: hostPath = base + the path as this host received it.
 *
 *   - every API front door in `hosts` as is: the relay forwards /v1/deployments/<id>/... with the path untouched
 *     (proxyTo/forward: path = req.url; the Host header is rewritten to the box for a direct https box and passed through
 *     on a tunnel, so the Host header is never what a host trusts here);
 *   - every front door with /t/<name> for each of this host's tunnel names: the relay strips /t/<name> and forwards the
 *     rest with the query (api-relay.js `tm`);
 *   - each of this host's own public URLs (PUBLIC_URL, the attested certificate SAN): host + its path, so
 *     https://api.enclave.host/t/metal0 adds "api.enclave.host/t/metal0" and https://box.example adds "box.example".
 *
 * A base never comes from the request (its Host or X-Forwarded-Host): a header the caller picks must not pick what the
 * signature is checked against, or a signature made for some other service would verify here.
 */
export function apiBases({ hosts = DEFAULT_API_HOSTS, tunnelNames = [], publicUrls = [] } = {}) {
  const out = new Set();
  const names = new Set(tunnelNames.filter((n) => /^[A-Za-z0-9_-]{1,64}$/.test(String(n || ""))));
  const own = [];
  for (const u of publicUrls) {
    if (!u) continue;
    try {
      const x = new URL(String(u));
      const path = x.pathname.replace(/\/+$/, "");
      own.push(normHost(x.host) + path);
      const t = /^\/t\/([A-Za-z0-9_-]{1,64})$/.exec(path);
      if (t) names.add(t[1]);
    } catch { /* not a URL: contributes nothing */ }
  }
  for (const h of hosts.map(normHost).filter(Boolean)) {
    out.add(h);
    for (const n of names) out.add(`${h}/t/${n}`);
  }
  for (const b of own) out.add(b);
  return [...out];
}

/** Split a comma list from the environment (empty -> []). */
export const envList = (v) => String(v || "").split(",").map((s) => s.trim()).filter(Boolean);

/**
 * Single-use nonces, per host: (vault, sid, n) -> expiry. Claimed synchronously right after the signature verifies and
 * BEFORE any chain read, so concurrent copies of one signed request cannot all pass; released again if the request
 * then fails (a self-signed request for a vault that is not one must not occupy room). Bounded: past `max` the expired
 * go first, then the oldest (which are nearest expiry anyway).
 */
export function replayGuard({ ttlSec = 2 * WINDOW_SEC + 10, max = 100_000, now = () => Math.floor(Date.now() / 1000) } = {}) {
  const seen = new Map();
  return {
    claim(key) {
      const t = now();
      const exp = seen.get(key);
      if (exp !== undefined && exp >= t) return false;
      seen.delete(key);
      seen.set(key, t + ttlSec);
      if (seen.size > max) {
        for (const [k, e] of seen) if (e < t) seen.delete(k);
        while (seen.size > max) seen.delete(seen.keys().next().value);
      }
      return true;
    },
    release(key) { seen.delete(key); },
    get size() { return seen.size; },
  };
}

/**
 * The verifier, wired to a chain. Everything it reads goes through `pc` (a viem public client: readContract, getCode,
 * getStorageAt), so a test hands it an anvil client.
 *
 *   pc         viem public client on the chain the vaults live on (Base)
 *   book       () => the EnclaveAddressBook address, or null: resolves "sessionVaultFactory" and, when `ledger` is not
 *              given, "deployments"
 *   ledger     () => the deployments ledger (the book's "deployments"), or null: where wallet-held delegation is read
 *   factories  extra SessionVaultFactory addresses (default v2 + v1); the book's factory is always added
 *   authorityPins optional host pins: exact deployments/sessionVaultFactory, overriding book, ledger and factories
 *   bases      () => apiBases(...) for this host
 *   now        () => unix seconds (this host's clock)
 */
export function createSessionApiAuth({ pc, book = () => null, ledger = null, factories = DEFAULT_FACTORIES, authorityPins, bases,
  now = () => Math.floor(Date.now() / 1000), cacheMs = CACHE_MS, log = () => {} } = {}) {
  if (!pc) throw new Error("createSessionApiAuth: a public client is required");
  if (typeof bases !== "function") throw new Error("createSessionApiAuth: bases() is required");
  // Explicit host pins replace every legacy authority source. A zero factory
  // disables session-vault credentials; it never restores the book/defaults.
  if (authorityPins != null) {
    const valid = a => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a);
    if (!authorityPins || Array.isArray(authorityPins) || !valid(authorityPins.deployments) || ZERO.test(authorityPins.deployments) ||
        !valid(authorityPins.sessionVaultFactory)) throw new Error("invalid pinned session authorities");
    const pinnedLedger = getAddress(authorityPins.deployments), pinnedFactory = getAddress(authorityPins.sessionVaultFactory);
    book = () => null;
    ledger = () => pinnedLedger;
    factories = ZERO.test(pinnedFactory) ? [] : [pinnedFactory];
  }
  const replay = replayGuard({ now });
  const fixed = factories.filter((a) => /^0x[0-9a-fA-F]{40}$/.test(String(a || ""))).map((a) => getAddress(a));
  const ms = () => Date.now();
  const caches = new Map();   // name -> Map(key -> { at, v })
  const cached = async (name, key, fresh, ttl, read) => {
    let c = caches.get(name);
    if (!c) caches.set(name, (c = new Map()));
    const hit = c.get(key);
    if (!fresh && hit && ms() - hit.at <= ttl) return hit.v;
    const v = await read();
    c.set(key, { at: ms(), v });
    if (c.size > 20_000) for (const [k, x] of c) if (ms() - x.at > ttl) c.delete(k);
    return v;
  };
  const chainRead = async (what, fn) => {
    try { return await fn(); }
    catch (e) {
      log(`session auth: ${what} unreadable: ${e?.shortMessage || e?.message || e}`);
      throw new SessionAuthError(503, "chain_unavailable", `This host could not read ${what} from the chain; try again.`);
    }
  };
  const bookAddr = (key) => cached("book", key, false, 60_000, async () => {
    const b = book();
    if (!b || !/^0x[0-9a-fA-F]{40}$/.test(String(b))) return null;
    const a = await pc.readContract({ address: getAddress(b), abi: BOOK_ABI, functionName: "addr", args: [key] });
    return a && !ZERO.test(a) ? getAddress(a) : null;
  });

  async function knownFactories() {
    const fromBook = await bookAddr(BOOK_KEY_FACTORY).catch(() => null);   // the configured list stands without the book
    return [...new Set([fromBook, ...fixed].filter(Boolean))];
  }
  const isVaultForever = new Set();
  // A factory address with no code (a list entry for another chain, a typo) answers "not mine"; any other failure
  // to read one is an unreadable chain, and unless another factory says yes the request fails closed (503).
  const noCode = (e) => { for (let x = e, i = 0; x && i < 12; x = x.cause, i++) if (x.name === "ContractFunctionZeroDataError") return true; return false; };
  async function isVault(vault, fresh) {
    if (isVaultForever.has(vault)) return true;                             // a vault never stops being one
    const ok = await cached("isVault", vault, fresh, cacheMs, async () => {
      let err = null;
      for (const f of await knownFactories()) {
        try {
          if (await pc.readContract({ address: f, abi: FACTORY_ABI, functionName: "isVault", args: [vault] })) return true;
        } catch (e) { if (!noCode(e)) err = e; }
      }
      if (err) throw err;
      return false;
    });
    if (ok) isVaultForever.add(vault);
    return ok;
  }
  const sessionOf = (vault, sid, fresh) => cached("sessionOf", `${vault}:${sid}`, fresh, cacheMs, async () => {
    const [s, live, apps] = await pc.readContract({ address: vault, abi: VAULT_ABI, functionName: "sessionOf", args: [sid] });
    return { ...s, live, apps };
  });
  const ownerOf = (vault, fresh) => cached("owner", vault, fresh, cacheMs, async () =>
    getAddress(await pc.readContract({ address: vault, abi: VAULT_ABI, functionName: "owner" })));
  const heldEnv = (vault, id, fresh) => cached("held", `${vault}:${id}`, fresh, cacheMs, async () =>
    Number((await pc.readContract({ address: vault, abi: VAULT_ABI, functionName: "held", args: [id] }))[0]));
  async function ledgerAddr() {
    const l = typeof ledger === "function" ? ledger() : null;
    if (l && /^0x[0-9a-fA-F]{40}$/.test(String(l))) return getAddress(l);
    return bookAddr(BOOK_KEY_DEPLOYMENTS);
  }
  const support = new Map();        // ledger -> bool, once its code was read (code never changes; no code is never kept)
  async function delegation(owner, vault, fresh) {
    const l = await ledgerAddr();
    if (!l) return { ledger: null, supported: false, granted: false };
    let ok = support.get(l);
    if (ok === undefined) {
      const code = await pc.getCode({ address: l });
      if (!code || code === "0x") return { ledger: l, supported: false, granted: false };
      support.set(l, (ok = codeHasDelegation(code)));
    }
    if (!ok) return { ledger: l, supported: false, granted: false };
    const granted = await cached("delegate", `${l}:${owner}:${vault}`, fresh, cacheMs, async () => {
      const w = await pc.getStorageAt({ address: l, slot: delegateSlot(owner, vault) });
      return !!w && w !== "0x" && BigInt(w) === 1n;
    });
    return { ledger: l, supported: true, granted };
  }

  /**
   * Verify one request. `path` is the request target AS RECEIVED (path + query, never decoded or normalised), `body` the
   * raw body bytes (absent = empty), `scope` the API scope the route needs (null: none beyond a live session), `fresh`
   * re-reads the chain (mutations), `bases` adds bases for this request only (an app's own hostnames on its data path).
   * -> { vault, sid, owner, actions, envs, anyApp, apps, expiresAt, hostPath } or throws a SessionAuthError.
   */
  async function verify({ header, method, path, body, scope = null, fresh = false, bases: extra = [] }) {
    const p = parseSessionHeader(header);
    if (Math.abs(now() - p.ts) > WINDOW_SEC) throw e401("stale or future request timestamp (more than 60 s from this host's clock)");
    if (typeof path !== "string" || !path.startsWith("/")) throw e401("unsupported request target");
    let key;
    try {
      key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: p.x.toString("base64url"), y: p.y.toString("base64url") }, format: "jwk" });
    } catch { throw e401("EnclaveSession: the session public key is not a P-256 point"); }
    const bodyHash = sha256Hex(body);
    const candidates = [...new Set([...bases(), ...extra.map(normHost).filter(Boolean)])].map((b) => b + path);
    const hostPath = candidates.find((hp) => {
      try {
        return nodeVerify("sha256", Buffer.from(apiMessage(method, hp, bodyHash, p.ts, p.n, p.vault, p.sid)),
          { key, dsaEncoding: "ieee-p1363" }, p.sig);
      } catch { return false; }
    });
    if (!hostPath) throw e401("bad session signature: it does not cover this method, host, path and body");
    const rkey = `${p.vault.toLowerCase()}:${p.sid}:${p.n}`;
    if (!replay.claim(rkey)) throw e401("replayed request: this nonce was already used here");
    try {
      if (!(await chainRead("the session vault factory", () => isVault(p.vault, fresh))))
        throw e401(`${p.vault} is not a SessionVault of a known factory`);
      const st = await chainRead("the session", () => sessionOf(p.vault, p.sid, fresh));
      if (String(st.keyHash).toLowerCase() !== sessionKeyHash(p.x, p.y).toLowerCase())
        throw e401("this key does not belong to the session");
      if (!st.live) throw e401("this session has ended or expired", "session_ended");
      if (scope && !hasScope(st.actions, scope))
        throw new SessionAuthError(403, "not_allowed", `this session lacks ${scope}`);
      const owner = await chainRead("the vault's owner", () => ownerOf(p.vault, fresh));
      return { vault: p.vault, sid: p.sid, owner, actions: BigInt(st.actions), envs: Number(st.envs), anyApp: Boolean(st.anyApp),
        apps: [...(st.apps || [])], expiresAt: Number(st.expiresAt), hostPath };
    } catch (e) { replay.release(rkey); throw e; }
  }

  /**
   * May verified session `s` act on ledger row `row` ({ id, owner })? null = yes, else the reason (a 403's message).
   * Throws a 503 SessionAuthError when the chain cannot answer (callers fail closed).
   */
  async function refusal(s, row, { fresh = false } = {}) {
    const holder = String(row?.owner || "").toLowerCase();
    if (holder && holder === String(s.vault).toLowerCase()) {
      if (!/^0x[0-9a-fA-F]{64}$/.test(String(row.id || ""))) return "This deployment is not on the ledger.";
      const env = await chainRead("the vault's custody record", () => heldEnv(s.vault, String(row.id).toLowerCase(), fresh));
      if (!env) return "This deployment sits in your session vault but has not been adopted into an environment.";
      if ((s.envs & env) === 0)
        return `This deployment is ${env === ENV_PROD ? "production" : env === ENV_STAGING ? "staging" : `environment ${env}`}, outside this session's environments.`;
      return null;
    }
    if (holder && holder === String(s.owner).toLowerCase()) {
      if ((s.envs & ENV_PROD) === 0) return "This session does not cover your production (wallet-held) deployments.";
      const d = await chainRead("the ledger delegation", () => delegation(s.owner, s.vault, fresh));
      if (!d.supported) return "The deployments ledger has no owner-approved delegates, so a session cannot act on the deployments your wallet holds.";
      if (!d.granted) return "Your wallet has not let your session vault manage the deployments it holds: grant it once with setDelegate from the wallet.";
      return null;
    }
    return "This session does not belong to the deployment's owner.";
  }

  /** The rows `s` may act on (listing): every row refusal() passes. */
  async function visible(s, rows, opts) {
    const ok = await Promise.all(rows.map(async (r) => (await refusal(s, r, opts)) === null));
    return rows.filter((_, i) => ok[i]);
  }

  return { verify, refusal, visible, delegation, knownFactories, replay };
}
