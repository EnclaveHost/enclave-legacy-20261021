// Open participation without anyone's approval (docs/network/open-participation.md):
//   * the EnclaveServiceIndex reader: operator-published service advertisements, read as one whole snapshot at ONE fixed
//     confirmed block that at least two RPCs return identically (agreedRead: a lying, hanging or wrong-chain RPC can
//     neither veto nor decide), from a contract whose runtime code hash the caller pinned, and returned as UNTRUSTED
//     CANDIDATES - never as admission, trust or proof of who runs them (distinct keys are not distinct organizations);
//   * the provider's explicit bootstrap: a provider whose operator chose its pins, RPCs, directories, checkers and zones
//     runs with no address book, no relay fallback and no enclave.host default.
//
// What an ad is worth. It says "the holder of this operator key claims a <kind> at these endpoints, until <expiry>". It
// does not prove the content served there is honest, that the operator is independent of anyone, that a host owner
// accepted it, or that a checker is qualified. Signed provider records, owner policies and the caller's pinned checkers
// remain the only authorities; an ad only tells you where to look. This module never fetches, probes or writes an
// advertised endpoint: what to contact, through what (network/guarded-fetch.mjs for anything automatic), is the caller's
// decision. Endpoints that name loopback, private, link-local or otherwise non-public targets are dropped here so a
// candidate list cannot steer a careless client at its own network.
import { createHash } from 'node:crypto';
import { keccak256 } from 'viem';
import { directoryOrigins } from './directory-client.mjs';
import { validateNetworkAuthorities } from './network-authorities.mjs';
import { rpcEndpoint, rpcLabel as safeRpcLabel, redactUrls } from './rpc-identity.mjs';

export const SERVICE_KINDS = Object.freeze({ directory: 1, checker: 2, storage: 3, dns: 4, replica: 5 });
export const KIND_NAMES = Object.freeze(Object.fromEntries(Object.entries(SERVICE_KINDS).map(([k, v]) => [v, k])));
export const AD_VERSION = 1;
export const LIMITS = Object.freeze({ slots: 8, endpoints: 4, endpointBytes: 256, ttlSec: 90 * 86400, page: 64, perKind: 1024, descriptor: 4096 });
export const CANDIDATE_NOTICE = 'untrusted candidates: an advertisement is a self-description by its operator key. It does not prove honest content, '
  + 'organizational independence (distinct keys are not distinct organizations), an accepted host owner or checker authority; '
  + 'signed records, owner policies and your pinned checkers still decide. Nothing here is admitted automatically.';

const adComponents = [
  { name: 'operator', type: 'address' }, { name: 'slot', type: 'uint8' }, { name: 'kind', type: 'uint16' }, { name: 'version', type: 'uint16' },
  { name: 'sequence', type: 'uint64' }, { name: 'expiresAt', type: 'uint64' }, { name: 'updatedAt', type: 'uint64' },
  { name: 'descriptor', type: 'bytes32' }, { name: 'endpoints', type: 'string[]' }];
const fn = (name, inputs, outputs, stateMutability = 'view') => ({ type: 'function', name, stateMutability, inputs, outputs });
const T = (type, name = '') => ({ type, name });
const publishInputs = [T('uint8', 'slot'), T('uint16', 'kind'), T('uint16', 'version'), T('uint64', 'sequence'), T('uint64', 'expiresAt'), T('bytes32', 'descriptor'), T('string[]', 'endpoints')];
export const SERVICE_INDEX_ABI = [
  fn('page', [T('uint16', 'kind'), T('uint256', 'start'), T('uint256', 'limit')], [{ type: 'tuple[]', name: 'out', components: adComponents }, T('uint256', 'total')]),
  fn('get', [T('address', 'operator'), T('uint8', 'slot')], [{ type: 'tuple', name: '', components: adComponents }]),
  fn('count', [T('uint16', 'kind')], [T('uint256')]),
  fn('sequenceOf', [T('address'), T('uint8')], [T('uint64')]),
  fn('publish', publishInputs, [], 'nonpayable'),
  fn('publishFor', [T('address', 'operator'), ...publishInputs, T('bytes', 'signature')], [], 'nonpayable'),
  fn('withdraw', [T('uint8', 'slot'), T('uint64', 'sequence')], [], 'nonpayable'),
  fn('withdrawFor', [T('address', 'operator'), T('uint8', 'slot'), T('uint64', 'sequence'), T('bytes', 'signature')], [], 'nonpayable'),
  fn('prune', [T('address', 'operator'), T('uint8', 'slot')], [], 'nonpayable'),
];

const ADDR = /^0x[0-9a-fA-F]{40}$/, HASH = /^0x[0-9a-f]{64}$/;
const lc = (s) => String(s).toLowerCase();

/** The caller's pin of an index: { chainId, address, codeHash } (keccak256 of the runtime code). */
export function validateIndexPin(pin) {
  if (!pin || typeof pin !== 'object' || Object.keys(pin).some((k) => !['chainId', 'address', 'codeHash'].includes(k))) throw new Error('index pin must be {chainId, address, codeHash}');
  if (!Number.isSafeInteger(pin.chainId) || pin.chainId <= 0) throw new Error('index pin chainId required');
  if (!ADDR.test(pin.address || '') || /^0x0{40}$/i.test(pin.address)) throw new Error('index pin address required');
  if (!HASH.test(lc(pin.codeHash || ''))) throw new Error('index pin codeHash (keccak256 of the runtime code) required');
  return Object.freeze({ chainId: pin.chainId, address: lc(pin.address), codeHash: lc(pin.codeHash) });
}

// ---- endpoints ---------------------------------------------------------------------------------------------------------
const v4 = (h) => { const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/); return m && m.slice(1).every((x) => Number(x) <= 255) ? m.slice(1).map(Number) : null; };
/** A public unicast IPv4 address (not private, loopback, link-local, CGNAT, multicast, documentation or reserved). */
export function publicIPv4(h) {
  const a = v4(h); if (!a) return false;
  const [x, y] = a;
  return !(x === 0 || x === 10 || x === 127 || x >= 224 || (x === 100 && y >= 64 && y <= 127) || (x === 169 && y === 254) || (x === 172 && y >= 16 && y <= 31)
    || (x === 192 && y === 168) || (x === 192 && y === 0 && (a[2] === 0 || a[2] === 2)) || (x === 198 && (y === 18 || y === 19))
    || (x === 198 && y === 51 && a[2] === 100) || (x === 203 && y === 0 && a[2] === 113));
}
const BAD_SUFFIX = /(^|\.)(localhost|local|internal|intranet|lan|home|corp|private|home\.arpa|in-addr\.arpa|ip6\.arpa|onion|test|invalid|example)$/i;
/**
 * An advertised endpoint a client may consider contacting: http(s) to a public DNS name (two or more labels, no
 * special-use suffix) or a public IPv4 literal. No IPv6 literals, credentials, query or fragment. A DNS name can still
 * resolve to a private address: whoever contacts it automatically must do so through a resolver-side guard.
 */
export function validateEndpoint(value) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > LIMITS.endpointBytes || !/^[\x21-\x7e]+$/.test(value)) throw new Error('endpoint must be 1-256 printable ASCII bytes');
  let u; try { u = new URL(value); } catch { throw new Error('endpoint is not a URL'); }
  if (!['https:', 'http:'].includes(u.protocol)) throw new Error('endpoint must be http(s)');
  if (u.username || u.password || u.search || u.hash) throw new Error('endpoint must not carry credentials, a query or a fragment');
  const h = u.hostname.toLowerCase();
  if (h.startsWith('[')) throw new Error('IPv6 literal endpoints are not accepted');
  if (v4(h)) { if (!publicIPv4(h)) throw new Error('endpoint names a non-public IPv4 address'); }
  else {
    if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/.test(h)) throw new Error('endpoint host must be a DNS name with two or more labels');
    if (BAD_SUFFIX.test(h)) throw new Error('endpoint host is a special-use or internal name');
  }
  return u.href;
}

// ---- descriptors -------------------------------------------------------------------------------------------------------
/** sha256 of a descriptor's exact bytes, as the on-chain bytes32 the ad commits to. */
export const descriptorHash = (bytes) => '0x' + createHash('sha256').update(bytes).digest('hex');
/**
 * Check a fetched descriptor against the ad that committed to it: exact hash, bounded size, and the operator and kind it
 * names. The descriptor is still the operator's own statement (e.g. a directory's record-signing key, a checker's
 * address); it inherits no more trust than the ad.
 */
export function verifyDescriptor(bytes, ad) {
  const b = Buffer.from(bytes);
  if (b.length > LIMITS.descriptor) throw new Error('descriptor too large');
  if (!ad || ad.descriptor === '0x' + '0'.repeat(64) || descriptorHash(b) !== lc(ad.descriptor)) throw new Error('descriptor does not match the advertisement');
  const d = JSON.parse(b.toString('utf8'));
  if (d?.format !== 'enclave-service-descriptor/v1' || lc(d.operator) !== lc(ad.operator) || d.kind !== ad.kindName) throw new Error('descriptor names another operator or kind');
  return d;
}

// ---- signing (for operators; nothing here holds or chooses a key) ----------------------------------------------------
const domain = (chainId, index) => ({ name: 'EnclaveServiceIndex', version: '1', chainId, verifyingContract: index });
export function publishTypedData({ chainId, index, operator, slot, kind, version = AD_VERSION, sequence, expiresAt, descriptor, endpoints }) {
  return { domain: domain(chainId, index), primaryType: 'Publish',
    types: { Publish: [{ name: 'operator', type: 'address' }, { name: 'slot', type: 'uint8' }, { name: 'kind', type: 'uint16' }, { name: 'version', type: 'uint16' },
      { name: 'sequence', type: 'uint64' }, { name: 'expiresAt', type: 'uint64' }, { name: 'descriptor', type: 'bytes32' }, { name: 'endpoints', type: 'string[]' }] },
    message: { operator, slot, kind, version, sequence: BigInt(sequence), expiresAt: BigInt(expiresAt), descriptor, endpoints } };
}
export function withdrawTypedData({ chainId, index, operator, slot, sequence }) {
  return { domain: domain(chainId, index), primaryType: 'Withdraw',
    types: { Withdraw: [{ name: 'operator', type: 'address' }, { name: 'slot', type: 'uint8' }, { name: 'sequence', type: 'uint64' }] },
    message: { operator, slot, sequence: BigInt(sequence) } };
}
/** Check an ad an operator is about to publish, with the same bounds the contract and readers apply. */
export function validateAdInput({ slot, kind, endpoints, ttlSec, descriptor = '0x' + '0'.repeat(64) }) {
  if (!Number.isInteger(slot) || slot < 0 || slot >= LIMITS.slots) throw new Error(`slot must be 0..${LIMITS.slots - 1}`);
  const k = typeof kind === 'string' ? SERVICE_KINDS[kind] : kind;
  if (!KIND_NAMES[k]) throw new Error(`kind must be one of ${Object.keys(SERVICE_KINDS).join(', ')}`);
  if (!Array.isArray(endpoints) || !endpoints.length || endpoints.length > LIMITS.endpoints) throw new Error('1 to 4 endpoints');
  const eps = endpoints.map((e) => validateEndpoint(e));
  if (!Number.isSafeInteger(ttlSec) || ttlSec < 60 || ttlSec > LIMITS.ttlSec) throw new Error('ttl must be 60 s to 90 days');
  if (!HASH.test(lc(descriptor))) throw new Error('descriptor must be a 32-byte hex hash');
  return { slot, kind: k, endpoints: eps, ttlSec, descriptor: lc(descriptor) };
}

// ---- agreeing reads ----------------------------------------------------------------------------------------------------
const stable = (v) => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x));
// an RPC library's error can name the URL it called, API key and all: evidence keeps only a safe label of it
const errText = (e) => redactUrls(String(e?.shortMessage || e?.message || e)).slice(0, 300);
const HEX32 = /^0x[0-9a-fA-F]{64}$/;
const MAX_TS_SEC = BigInt(Math.floor(Number.MAX_SAFE_INTEGER / 1000));
/** A block header an RPC returned for block `b`, checked: that exact number, a 32-byte hash, a whole-second timestamp. */
function headerOf(blk, b) {
  if (!blk || typeof blk !== 'object') throw new Error('no block header');
  const n = typeof blk.number === 'bigint' ? blk.number : Number.isSafeInteger(blk.number) ? BigInt(blk.number) : null;
  if (n === null) throw new Error('block header has no valid number');
  if (n !== b) throw new Error(`block header is for block ${n}, not the requested ${b}`);
  if (typeof blk.hash !== 'string' || !HEX32.test(blk.hash)) throw new Error('block hash is not 32 bytes of hex');
  const t = typeof blk.timestamp === 'bigint' ? blk.timestamp : Number.isSafeInteger(blk.timestamp) ? BigInt(blk.timestamp) : null;
  if (t === null || t < 0n || t > MAX_TS_SEC) throw new Error('block timestamp is not a valid number of seconds');
  if (blk.parentHash !== undefined && (typeof blk.parentHash !== 'string' || !HEX32.test(blk.parentHash))) throw new Error('block parent hash is not 32 bytes of hex');
  return { number: n, hash: lc(blk.hash), timestamp: Number(t), parentHash: blk.parentHash === undefined ? null : lc(blk.parentHash) };
}
/** A refusal that carries what each RPC did: which reported a head, answered, agreed, disagreed, failed or never answered. */
export class QuorumError extends Error {
  constructor(message, evidence) { super(message); this.name = 'QuorumError'; this.evidence = evidence; }
}
const timed = (p, ms, what) => {
  let t;
  return Promise.race([p, new Promise((_, reject) => { t = setTimeout(() => reject(new Error(`${what} timed out after ${ms} ms`)), ms); t.unref?.(); })])
    .finally(() => clearTimeout(t));
};
/**
 * The vote identity of an RPC transport URL: network/rpc-identity.mjs, the rule every quorum reader shares (and
 * scripts/network/service-index.mjs peersFor). A public host is one vote regardless of case, trailing dots, path,
 * query, key or port, and an IPv4 address written in IPv6 form is that IPv4 address. Local test chains count by
 * loopback PORT (127.0.0.1, localhost, [::1] and [::ffff:127.0.0.1] on one port are one vote). -> 'host:<host>' |
 * 'loopback:<port>', or null for a URL that is not a usable RPC URL (not https, or plain http off loopback;
 * credentials; a fragment; a malformed host). Distinct identities are distinct configured endpoints, NOT proof of
 * independent operators or organizations.
 */
export function rpcIdentity(url) {
  try { return rpcEndpoint(url).identity; } catch { return null; }
}
const CLIENT_METHODS = ['getChainId', 'getBlockNumber', 'getBlock'];
/**
 * [{label, client}] from either peers or bare clients; 2-16 of them, each a distinct vote: distinct labels (evidence
 * names them; no URL secrets), distinct client objects, and - when a client exposes its transport URL (viem's http
 * transport does) - distinct rpcIdentity()s. A client without a visible URL is only known by its object identity; the
 * caller who builds such a client is responsible for it being a separate endpoint.
 */
export function peerList({ peers, clients, methods = [] }) {
  const list = peers || (clients || []).map((client, i) => ({ label: `rpc#${i + 1}`, client }));
  if (!Array.isArray(list) || list.length < 2) throw new Error('two or more independently chosen RPCs are required');
  if (list.length > 16) throw new Error('at most 16 RPCs');
  const out = list.map((p, i) => {
    if (!p || typeof p !== 'object') throw new Error(`RPC #${i + 1} is not a {label, client} entry`);
    const c = p.client;
    if (!c || typeof c !== 'object' || [...CLIENT_METHODS, ...methods].some((m) => typeof c[m] !== 'function'))
      throw new Error(`RPC #${i + 1} has no usable client (needs ${[...CLIENT_METHODS, ...methods].join(', ')})`);
    if (p.label !== undefined && (typeof p.label !== 'string' || !p.label.trim())) throw new Error(`RPC #${i + 1} label must be a non-empty string`);
    return { label: String(p.label || `rpc#${i + 1}`).slice(0, 120), client: c };
  });
  if (new Set(out.map((p) => p.label)).size !== out.length) throw new Error('RPC labels must be distinct');
  if (new Set(out.map((p) => p.client)).size !== out.length) throw new Error('RPC peers must be distinct clients: one client cannot vote twice');
  // an exposed URL that is not a usable RPC URL is refused, never ignored as if the client had none
  const ids = out.flatMap((p, i) => {
    const url = p.client.transport?.url;
    if (url === undefined || url === null) return [];
    try { return [rpcEndpoint(url).identity]; } catch (e) { throw new Error(`RPC #${i + 1} exposes an unusable RPC URL: ${e.message}`); }
  });
  if (new Set(ids).size !== ids.length) throw new Error('RPC peers must use distinct public hosts or distinct loopback test ports: one endpoint cannot vote twice');
  return out;
}
/** An RPC URL as evidence may name it: scheme, canonical host and port only (a path or query can carry an API key). */
export const rpcLabel = (url) => safeRpcLabel(url);

/**
 * One whole snapshot read at ONE fixed block, accepted once two RPCs return it byte for byte - LeaseReader.agreed's
 * rule (network/lease-reader.mjs), with deadlines and evidence:
 *   * each peer reports chain id and head; a wrong chain or a failure excludes it. Once two heads are in, the others get
 *     `headGraceMs` before a block is chosen: the SECOND-highest head minus `confirmations` (never below `floorBlock`),
 *     so one RPC claiming a far-future head cannot choose the block, and one lagging RPC cannot hold the others back;
 *   * choosing the block excludes nobody: a head that arrives later (a slow honest RPC) joins the read at that block for
 *     as long as the deadline allows, so a fast liar beside one fast honest RPC cannot veto by disagreeing;
 *   * every reader reads at that block: the block's timestamp must be neither in the future nor older than
 *     `maxBlockAgeMs`; `read(client, blockNumber, call)` runs; the block hash is read again and must be unchanged; and
 *     the timestamp must STILL be within `maxBlockAgeMs` when the read ends and again when the snapshot is accepted;
 *   * the first two identical snapshots from two distinct RPCs win. A third RPC that lies, hangs or is on another chain
 *     neither vetoes nor delays two honest ones; one RPC never wins alone, and there is no fallback to a first answer;
 *   * if every reader finished without two matching snapshots and later heads now give a strictly NEWER block (for
 *     example a fast liar's low head made the first block stale), the read is repeated there with every RPC that
 *     reported a head; it never moves to an older block, and the same two-identical-snapshots rule decides;
 *   * ONE deadline (`deadlineMs`) bounds everything: each request gets at most `requestTimeoutMs` and never more than the
 *     time left, and once the outcome is decided (or a round is superseded) no further request is started;
 *   * `atBlock: {number, hash}` resumes at a block already agreed (pagination): no head phase, and each peer must report
 *     that exact block hash.
 * -> { blockNumber, blockHash, timestamp, value, evidence: { block, rounds, snapshot, peers: [{label, status, ...}] } },
 * where status is agreed | disagreed | failed (with stage and reason) | pending (no answer when the quorum formed) | late
 * (a head after the outcome was decided) | head (a head, but no block was ever chosen). Throws QuorumError with the same
 * evidence when no two RPCs agree.
 */
export async function agreedRead({ peers, chainId, read, confirmations = 2, maxBlockAgeMs = 90_000, futureSkewMs = 5_000, requestTimeoutMs = 8_000,
                                   deadlineMs = 30_000, headGraceMs = 250, floorBlock = 0n, atBlock = null, now = Date.now }) {
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error('chainId required');
  if (typeof read !== 'function') throw new Error('read(client, blockNumber, call) required');
  peers = peerList({ peers });                         // direct callers get the same distinct-vote rules as readServiceIndex
  if (!(maxBlockAgeMs >= 1000 && maxBlockAgeMs <= 600_000) || !(requestTimeoutMs >= 100 && deadlineMs >= requestTimeoutMs && deadlineMs <= 300_000)) throw new Error('invalid freshness or deadline policy');
  if (atBlock && !/^0x[0-9a-f]{64}$/.test(String(atBlock.hash))) throw new Error('resume block hash required');
  const ev = new Map(peers.map((p) => [p.label, { label: p.label, status: 'pending', stage: atBlock ? 'read' : 'head' }]));
  const set = (p, o) => Object.assign(ev.get(p.label), o);
  const tried = [];                                   // blocks read, in order (each strictly newer than the last)
  const evidence = (digest = null) => ({ block: tried.length ? String(tried[tried.length - 1]) : null, rounds: tried.map(String), snapshot: digest,
    peers: [...ev.values()].map((e) => ({ ...e,
      status: digest && e.snapshot === digest ? 'agreed' : e.status === 'answered' ? 'disagreed' : e.status === 'reading' ? 'pending' : e.status === 'head' && tried.length ? 'late' : e.status })) });
  const fresh = (tsMs) => tsMs + maxBlockAgeMs > now();
  const endAt = performance.now() + deadlineMs;

  return new Promise((resolve, reject) => {
    let closed = false, round = 0, block = null, seen = new Map(), readers = new Set(), pending = 0, grace = null;
    const heads = new Map();                          // label -> { p, n }
    let headsOutstanding = atBlock ? 0 : peers.length;
    const finish = (err, out) => { if (closed) return; closed = true; clearTimeout(grace); clearTimeout(deadline); if (err) reject(err); else resolve(out); };
    const deadline = setTimeout(() => finish(new QuorumError(`no two RPCs agreed within ${deadlineMs} ms`, evidence())), deadlineMs);
    deadline.unref?.();
    // every request: refused once decided or superseded, and bounded by the request timeout AND the time left
    const call = (p, r) => (what, f) => {
      if (closed || r !== round) return Promise.reject(new Error(closed ? 'the read was already decided' : 'superseded by a newer block'));
      const left = Math.floor(endAt - performance.now());
      if (left <= 0) return Promise.reject(new Error(`${p.label} ${what}: the deadline has passed`));
      return timed(Promise.resolve().then(f), Math.min(requestTimeoutMs, left), `${p.label} ${what}`);
    };
    const choose = () => {
      if (heads.size < 2) return null;
      const ns = [...heads.values()].map((h) => h.n).sort((a, b) => (a > b ? -1 : a < b ? 1 : 0));
      let b = ns[1] - BigInt(confirmations);
      if (b < 0n) return -1n;
      if (b < BigInt(floorBlock)) b = BigInt(floorBlock);
      return b;
    };
    const readAt = async (p, b, c) => {
      if (atBlock) { const id = await c('chain id', () => p.client.getChainId()); if (Number(id) !== chainId) throw new Error(`reports chain ${id}, not ${chainId}`); }
      const h = headerOf(await c('block', () => p.client.getBlock({ blockNumber: b })), b);
      if (atBlock && h.hash !== lc(atBlock.hash)) throw new Error('block hash differs from the resume point: reorganized, or another chain');
      const ts = h.timestamp * 1000;
      if (ts > now() + futureSkewMs) throw new Error('block timestamp is in the future');
      if (!fresh(ts)) throw new Error(`block ${b} is older than ${maxBlockAgeMs} ms`);
      const value = await read(p.client, b, c);
      // the whole header again, not only the hash: same number, hash, timestamp and parent
      const again = headerOf(await c('block recheck', () => p.client.getBlock({ blockNumber: b })), b);
      if (again.hash !== h.hash || again.timestamp !== h.timestamp || again.parentHash !== h.parentHash) throw new Error('reorganized during the read: the block header changed');
      if (!fresh(ts)) throw new Error(`block ${b} became older than ${maxBlockAgeMs} ms during the read`);
      return { blockNumber: String(b), blockHash: h.hash, timestamp: h.timestamp, value };
    };
    const addReader = (p) => {
      if (closed || readers.has(p.label)) return;
      const r = round, b = block;
      readers.add(p.label); pending++;
      const e = ev.get(p.label); delete e.snapshot; delete e.reason;   // a newer round starts this RPC afresh
      set(p, { stage: 'read', status: 'reading', round: r });
      readAt(p, b, call(p, r)).then((snap) => {
        if (closed || r !== round) return;
        const key = stable(snap), digest = createHash('sha256').update(key).digest('hex');
        set(p, { status: 'answered', snapshot: digest });
        const first = seen.get(key);
        if (first === undefined) { seen.set(key, p.label); return; }
        if (first === p.label) return;                // two distinct RPCs, never one twice
        // accepted only while still fresh at this very moment
        if (!fresh(snap.timestamp * 1000)) { set(p, { status: 'failed', reason: `block ${b} became older than ${maxBlockAgeMs} ms before acceptance` }); return; }
        finish(null, { ...snap, evidence: evidence(digest) });
      }, (e) => { if (r === round) set(p, { status: 'failed', reason: errText(e) }); })
        .finally(() => { if (r === round) { pending--; settle(); } });
    };
    const startRound = (b) => {
      round++; block = b; tried.push(b); seen = new Map(); readers = new Set(); pending = 0;
      for (const h of heads.values()) addReader(h.p);
      if (atBlock) for (const p of peers) addReader(p);
      settle();
    };
    // nothing more can arrive for this round: try a strictly newer block if later heads give one, else refuse
    const settle = () => {
      if (closed || block === null || pending > 0 || headsOutstanding > 0) return;
      const next = atBlock ? null : choose();
      if (next !== null && next > tried[tried.length - 1]) return startRound(next);
      finish(new QuorumError(`no two RPCs returned the same snapshot at block ${block}`, evidence()));
    };
    const headsSettled = () => {
      if (closed) return;
      if (block !== null) return settle();
      if (headsOutstanding > 0 && !(heads.size >= 2 && grace === 'fired')) return;
      clearTimeout(grace);
      const b = choose();
      if (b === null) return finish(new QuorumError(`fewer than two RPCs on chain ${chainId} reported a head`, evidence()));
      if (b < 0n) return finish(new QuorumError('no confirmed block yet', evidence()));
      startRound(b);
    };
    if (atBlock) { startRound(BigInt(atBlock.number)); return; }
    for (const p of peers) {
      (async () => {
        const c = (what, f) => {
          const left = Math.floor(endAt - performance.now());
          if (closed) return Promise.reject(new Error('the read was already decided'));
          return timed(Promise.resolve().then(f), Math.max(1, Math.min(requestTimeoutMs, left)), `${p.label} ${what}`);
        };
        const [id, n] = await Promise.all([c('chain id', () => p.client.getChainId()), c('head', () => p.client.getBlockNumber({ cacheTime: 0 }))]);
        if (Number(id) !== chainId) throw new Error(`reports chain ${id}, not ${chainId}`);
        return BigInt(n);
      })().then((n) => {
        if (closed) return;
        set(p, { status: 'head', head: String(n) }); heads.set(p.label, { p, n });
        if (block !== null) addReader(p);             // a late head still reads at the chosen block
        else if (heads.size >= 2 && grace === null) { grace = setTimeout(() => { grace = 'fired'; headsSettled(); }, headGraceMs); grace.unref?.(); }
      }, (e) => { if (!closed) set(p, { status: 'failed', reason: errText(e) }); })
        .finally(() => { headsOutstanding--; headsSettled(); });
    }
  });
}

// ---- reading the index ---------------------------------------------------------------------------------------------
const zero32 = '0x' + '0'.repeat(64);
function judge(a, ts) {
  const base = { operator: lc(a.operator), slot: Number(a.slot), kind: Number(a.kind), kindName: KIND_NAMES[Number(a.kind)] || null, sequence: String(a.sequence) };
  if (BigInt(a.expiresAt) <= ts) return { state: 'expired', ...base, expiresAt: Number(a.expiresAt) };
  if (Number(a.version) !== AD_VERSION) return { state: 'rejected', ...base, reason: `ad format version ${a.version} is not understood` };
  if (!base.kindName) return { state: 'rejected', ...base, reason: `kind ${a.kind} is not understood` };
  try {
    return { state: 'listed', candidate: { ...base, version: Number(a.version), expiresAt: Number(a.expiresAt), updatedAt: Number(a.updatedAt),
      descriptor: lc(a.descriptor), endpoints: a.endpoints.map((e) => validateEndpoint(e)), trust: 'untrusted-candidate' } };
  } catch (e) { return { state: 'rejected', ...base, reason: e.message }; }
}
function lookupList(lookups) {
  if (!Array.isArray(lookups) || lookups.length > 32) throw new Error('at most 32 operator lookups');
  const out = [];
  for (const l of lookups) {
    if (!ADDR.test(String(l?.operator || ''))) throw new Error('lookup operator must be an address');
    const slots = l.slot === undefined || l.slot === null ? [...Array(LIMITS.slots).keys()] : [Number(l.slot)];
    for (const slot of slots) { if (!Number.isInteger(slot) || slot < 0 || slot >= LIMITS.slots) throw new Error('lookup slot must be 0..7'); out.push({ operator: lc(l.operator), slot }); }
  }
  return out;
}

/**
 * Read the index -> {
 *   status: 'complete' | 'incomplete', chainId, index, blockNumber, blockHash, blockTimestamp,
 *   windows: { <kind>: { total, start, end, complete } },   every listed ad of a kind was examined iff complete
 *   next: null | cursor,                                    pass back as `cursor` to continue at the SAME block
 *   candidates, rejected, expired,                           (untrusted; from the windows read)
 *   lookups: [{ operator, slot, state: listed|absent|expired|rejected, candidate?, reason? }],
 *   evidence: { snapshot, peers }, notice }
 * `window` ads per kind are read per call (at most 1024; 64 per request). An INCOMPLETE result says nothing about the ads
 * it did not reach - not seeing an operator there proves nothing; continue with `next`, or look the operator up
 * directly: `lookups` ({operator, slot?}, up to 32 operators) read get(operator, slot) in the same agreed snapshot, so
 * any amount of spam in the listing cannot hide an operator the caller already knows of. Distinct operator keys are not
 * distinct organizations. Without an agreeing quorum this throws QuorumError (with evidence); it never returns an empty
 * list for a disagreement.
 */
export async function readServiceIndex({ peers, clients, pin, kinds = Object.keys(SERVICE_KINDS), window = 256, cursor = null, lookups = [],
                                        maxBlockAgeMs = 90_000, requestTimeoutMs = 8_000, deadlineMs = 30_000, now = Date.now, ...policy }) {
  pin = validateIndexPin(pin);
  const list = peerList({ peers, clients, methods: ['getCode', 'readContract'] });
  if (!Number.isSafeInteger(window) || window < 1 || window > LIMITS.perKind) throw new Error(`window must be 1..${LIMITS.perKind}`);
  const kindIds = kinds.map((k) => { const id = SERVICE_KINDS[k]; if (!id) throw new Error(`unknown kind ${k}`); return id; });
  const wanted = lookupList(lookups);
  let atBlock = null, positions = {};
  if (cursor) {
    if (cursor.index !== pin.address || cursor.chainId !== pin.chainId) throw new Error('the cursor is for another index');
    atBlock = { number: BigInt(cursor.blockNumber), hash: cursor.blockHash }; positions = cursor.positions || {};
  }
  const r = await agreedRead({ peers: list, chainId: pin.chainId, maxBlockAgeMs, requestTimeoutMs, deadlineMs, now, atBlock, ...policy,
    read: async (c, blockNumber, call) => {
      const code = await call('code', () => c.getCode({ address: pin.address, blockNumber }));
      const value = { codeHash: code ? keccak256(code) : null, windows: {}, lookups: [] };
      if (value.codeHash !== pin.codeHash) return value;   // agreed below, then refused: the pin is never weakened
      for (const kind of kindIds) {
        const start = BigInt(positions[KIND_NAMES[kind]] ?? 0), ads = []; let total = null;
        for (let at = start; ads.length < window; at += BigInt(LIMITS.page)) {
          const limit = BigInt(Math.min(LIMITS.page, window - ads.length));
          const [out, t] = await call(`page ${KIND_NAMES[kind]}@${at}`, () => c.readContract({ address: pin.address, abi: SERVICE_INDEX_ABI, functionName: 'page', args: [kind, at, limit], blockNumber }));
          total = t; ads.push(...out);
          if (out.length < Number(limit) || at + BigInt(out.length) >= t) break;
        }
        value.windows[kind] = { total: total ?? 0n, start, ads };
      }
      for (const w of wanted)
        value.lookups.push(await call(`get ${w.operator}/${w.slot}`, () => c.readContract({ address: pin.address, abi: SERVICE_INDEX_ABI, functionName: 'get', args: [w.operator, w.slot], blockNumber })));
      return value;
    } });
  const v = r.value;
  if (v.codeHash !== pin.codeHash) throw new QuorumError(`the agreed code at ${pin.address} is ${v.codeHash || 'absent'}, not the pinned ${pin.codeHash}`, r.evidence);
  const ts = BigInt(r.timestamp), candidates = [], rejected = [], windows = {}, next = {};
  let expired = 0;
  for (const kind of kindIds) {
    const { total, start, ads } = v.windows[kind], end = start + BigInt(ads.length), complete = end >= BigInt(total);
    windows[KIND_NAMES[kind]] = { total: Number(total), start: Number(start), end: Number(end), complete };
    if (!complete) next[KIND_NAMES[kind]] = Number(end);
    for (const a of ads) {
      const j = judge(a, ts);
      if (j.state === 'listed') candidates.push(j.candidate); else if (j.state === 'expired') expired++; else rejected.push(j);
    }
  }
  const found = wanted.map((w, i) => {
    const a = v.lookups[i];
    if (lc(a.operator) !== w.operator) return { ...w, state: 'absent' };
    const j = judge(a, ts);
    return j.state === 'listed' ? { ...w, state: 'listed', candidate: j.candidate } : { ...w, state: j.state, ...(j.reason ? { reason: j.reason } : {}) };
  });
  const incomplete = Object.keys(next).length > 0;
  return { status: incomplete ? 'incomplete' : 'complete', chainId: pin.chainId, index: pin.address, blockNumber: r.blockNumber, blockHash: r.blockHash,
           blockTimestamp: r.timestamp, windows, next: incomplete ? { chainId: pin.chainId, index: pin.address, blockNumber: r.blockNumber, blockHash: r.blockHash, positions: next } : null,
           candidates, rejected, expired, lookups: found, evidence: r.evidence, notice: CANDIDATE_NOTICE };
}

// ---- the provider's bootstrap ------------------------------------------------------------------------------------------
const ZERO = '0x' + '0'.repeat(40);
const dnsZone = (z, what) => {
  if (typeof z !== 'string' || !/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/.test(z)) throw new Error(`${what} must be a DNS zone the operator chose`);
  return z;
};
/**
 * The bootstrap a wg-provider runs with -> { mode, directories, addressBook, authorityPins, zone, probeZone, relay, notes }.
 *   legacy (no "bootstrap" field, or "legacy"): exactly what installed providers do today - directories, else the relay;
 *     the mutable address book unless authorityPins are given; app.enclave.host and probe.enclave.host zones.
 *   explicit ("bootstrap": "explicit"): every authority named by the operator - two or more https RPCs on distinct hosts,
 *     complete authorityPins (zero disables connectivity / session-vault owners; nothing is looked up), 1-8 directories,
 *     one or more checkers, the app and probe zones. No address book, no relay fallback; "relay" (optional) is used only
 *     for the custom-domain map. Nothing defaults to enclave.host.
 */
export function resolveProviderBootstrap(cfg) {
  const mode = cfg?.bootstrap ?? 'legacy';
  if (mode === 'legacy') {
    return { mode, directories: directoryOrigins(cfg.directories || [cfg.relay]), addressBook: cfg.addressBook, authorityPins: cfg.authorityPins,
             zone: cfg.zone || 'app.enclave.host', probeZone: cfg.probeZone || 'probe.enclave.host', relay: cfg.relay || null,
             notes: ['legacy bootstrap: Enclave defaults (relay fallback, address book unless pinned, enclave.host zones)'] };
  }
  if (mode !== 'explicit') throw new Error('bootstrap must be "legacy" or "explicit"');
  if ('addressBook' in cfg) throw new Error('explicit bootstrap uses authorityPins only: remove addressBook');
  if (!Array.isArray(cfg.rpc) || cfg.rpc.length < 2) throw new Error('explicit bootstrap needs two or more RPCs');
  const hosts = cfg.rpc.map((r) => { const e = rpcEndpoint(r, { loopbackPorts: false }); if (e.url.protocol !== 'https:') throw new Error('explicit bootstrap RPCs must be https'); return e.identity; });
  if (new Set(hosts).size !== hosts.length) throw new Error('explicit bootstrap RPCs must be on distinct hosts');
  const pins = validateNetworkAuthorities(cfg.authorityPins);
  for (const k of ['connectivity', 'sessionVaultFactory']) if (!(k in pins)) throw new Error(`explicit bootstrap needs authorityPins.${k} (zero to disable)`);
  if (!Array.isArray(cfg.checkers) || !cfg.checkers.length || cfg.checkers.some((c) => !ADDR.test(c))) throw new Error('explicit bootstrap needs one or more checker addresses');
  const relay = cfg.relay == null ? null : directoryOrigins([cfg.relay])[0];
  if (relay && !relay.startsWith('https:')) throw new Error('relay must be https');
  const notes = [];
  if (!relay) notes.push('no relay: custom-domain names are not served (app-zone names only)');
  if (pins.connectivity === ZERO) notes.push('connectivity pinned to zero: paid service disabled');
  if (pins.sessionVaultFactory === ZERO) notes.push('sessionVaultFactory pinned to zero: only wallet (EOA/ERC-1271) owner policies verify');
  return { mode, directories: directoryOrigins(cfg.directories || []), addressBook: ZERO, authorityPins: pins,
           zone: dnsZone(cfg.zone, 'zone'), probeZone: dnsZone(cfg.probeZone, 'probeZone'), relay, notes };
}

// ---- the checker's bootstrap ---------------------------------------------------------------------------------------
/**
 * A qualification checker (scripts/network/wg-qualify.mjs --independent) with every authority and probe target named by
 * its operator -> { directories, pins, rpc, chainId, outbound, dns, smtp, smtpDomain }:
 *   directories (1-8 origins; no relay fallback), authorityPins (registry for community hosts, connectivity for on-chain
 *   attestations; zero disables them; no address book), two or more RPCs on distinct origins (https; http only on
 *   loopback), and the probe targets: the outbound HTTPS canary, the DNS resolvers given to probe peers, and the SMTP
 *   target (ip:port) or the mail domain whose MX is used. Nothing defaults to an Enclave service or to a third party.
 */
export function resolveCheckerBootstrap({ directories, pins, rpc = [], chainId = 8453, relay, book, outbound, dns, smtp, smtpDomain }) {
  if (relay) throw new Error('independent checker: --relay is a legacy fallback; name the directories (--directories)');
  if (book) throw new Error('independent checker: --book is the mutable address book; pin the contracts (--pins)');
  const dirs = directoryOrigins(directories || []);
  const authority = validateNetworkAuthorities(pins);
  if (!('connectivity' in authority)) throw new Error('independent checker: authorityPins.connectivity required (zero to disable on-chain attestations)');
  if (!Array.isArray(rpc) || rpc.length < 2) throw new Error('independent checker: two or more --rpc required');
  const origins = rpc.map((r) => rpcEndpoint(r).identity);
  if (new Set(origins).size !== origins.length) throw new Error('independent checker: RPCs must be distinct origins');
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error('chain id required');
  const o = new URL(String(outbound || 'missing:'));
  if (!outbound || o.protocol !== 'https:' || o.username || o.password) throw new Error('independent checker: --outbound https URL required (the egress canary)');
  const resolvers = String(dns || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!resolvers.length || resolvers.some((r) => !publicIPv4(r))) throw new Error('independent checker: --dns public IPv4 resolvers required');
  if (!smtp && !smtpDomain) throw new Error('independent checker: --smtp ip:port or --smtp-domain required (the outbound-mail block check)');
  if (smtp && !/^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(smtp)) throw new Error('--smtp must be ip:port');
  return { directories: dirs, pins: authority, rpc: [...rpc], chainId, outbound: o.href, dns: resolvers, smtp: smtp || null, smtpDomain: smtpDomain || null,
           connectivity: authority.connectivity === ZERO ? null : authority.connectivity };
}
