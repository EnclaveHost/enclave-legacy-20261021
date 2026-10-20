// network/service-index.mjs agreedRead under timing and liars, with in-memory RPCs and modest real timers (no chain):
// a slow honest head is not excluded by a fast liar, a fast liar's stale low head is followed by a newer block, a
// snapshot that ages past the freshness bound during a long read is refused, wrong-chain RPCs are excluded even when
// late, a split or a lone answer never decides, and nothing new is requested once the outcome is fixed.
// Also: every peer is a distinct vote (distinct labels, client objects and transport identities, validated by
// agreedRead itself), and a block header must be exactly the requested number with a 32-byte hash and whole-second
// timestamp, unchanged (hash, timestamp, parent) when re-read after the snapshot.
//   run: node --test --test-concurrency=1 test/service-index-quorum.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { agreedRead, peerList, rpcIdentity, QuorumError } from '../network/service-index.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T0 = Math.floor(Date.now() / 1000);
// block n of a chain whose head is 100, two seconds apart: 98 is ~4 s old, 48 is ~104 s old
const tsOf = (n) => T0 - (100 - Number(n)) * 2;
const hashOf = (n) => '0x' + BigInt(n).toString(16).padStart(64, '0');
/** an RPC: its chain, the head it reports and when, how slowly it serves blocks and reads, and what value it returns;
 *  `header(blockNumber, nth)` may alter the nth (1 = first read, 2 = recheck) header it serves for a block */
function rpc({ chain = 31337, head = 100n, headDelay = 0, readDelay = 0, value = 'truth', calls = { n: 0 }, header = null, url } = {}) {
  const tick = async (ms) => { calls.n++; if (ms) await sleep(ms); };
  const served = new Map();
  return {
    calls, ...(url ? { transport: { url } } : {}),
    getChainId: async () => { await tick(headDelay); return chain; },
    getBlockNumber: async () => { await tick(headDelay); return head; },
    getBlock: async ({ blockNumber }) => {
      await tick(0);
      const nth = (served.get(blockNumber) || 0) + 1; served.set(blockNumber, nth);
      const real = { number: BigInt(blockNumber), hash: hashOf(blockNumber), parentHash: hashOf(BigInt(blockNumber) - 1n), timestamp: BigInt(tsOf(blockNumber)) };
      return header ? header(real, nth) : real;
    },
    value: async (b) => { await tick(readDelay); return `${value}@${b}`; },
  };
}
const read = async (client, b, call) => call('value', () => client.value(b));
const run = (peers, over = {}) => agreedRead({ peers: peers.map(([label, client]) => ({ label, client })), chainId: 31337, read,
  requestTimeoutMs: 2000, deadlineMs: 4000, ...over });
const peerOf = (r, label) => r.evidence.peers.find((p) => p.label === label);
const refusal = (p) => p.then((r) => assert.fail(`accepted ${JSON.stringify(r.value)}`), (e) => e);

test('a slow honest head (past the head grace) still joins: a fast liar beside one fast honest RPC cannot veto', async () => {
  const t0 = Date.now();
  const r = await run([['fast-honest', rpc()], ['fast-liar', rpc({ value: 'lie' })], ['slow-honest', rpc({ headDelay: 600 })]]);
  assert.equal(r.value, 'truth@98');
  assert.equal(r.blockNumber, '98');
  assert.ok(Date.now() - t0 >= 600, 'decided only once the slow honest RPC answered');
  assert.deepEqual(['fast-honest', 'fast-liar', 'slow-honest'].map((l) => peerOf(r, l).status), ['agreed', 'disagreed', 'agreed']);
  assert.deepEqual(r.evidence.rounds, ['98']);
  // two liars that agree with each other are still two RPCs; but one liar plus a late honest RPC never decides
  const e = await refusal(run([['fast-liar', rpc({ value: 'lie' })], ['slow-honest', rpc({ headDelay: 600 })]]));
  assert.ok(e instanceof QuorumError);
  assert.match(e.message, /no two RPCs returned the same snapshot at block 98/);
  assert.deepEqual(e.evidence.peers.map((p) => p.status).sort(), ['disagreed', 'disagreed']);
});

test('a fast liar with a stale low head: the first block is refused, later heads give a newer block and the honest pair decides', async () => {
  // the liar reports a low head AND lies about the data, so only the two honest RPCs can agree
  const r = await run([['fast-honest', rpc()], ['low-liar', rpc({ head: 50n, value: 'lie' })], ['slow-honest', rpc({ headDelay: 600 })]]);
  assert.equal(r.value, 'truth@98');
  assert.deepEqual(r.evidence.rounds, ['48', '98'], 'the first block (second-highest of 100 and 50) was stale; never an older retry');
  assert.deepEqual(['fast-honest', 'low-liar', 'slow-honest'].map((l) => peerOf(r, l).status), ['agreed', 'disagreed', 'agreed']);
  // without a later honest head there is nothing newer to try: refused with evidence, not accepted at a stale block
  const e = await refusal(run([['fast-honest', rpc()], ['low-liar', rpc({ head: 50n, value: 'lie' })]]));
  assert.ok(e instanceof QuorumError);
  assert.match(e.message, /no two RPCs returned the same snapshot at block 48/);
  assert.ok(e.evidence.peers.every((p) => p.status === 'failed' && /older than 90000 ms/.test(p.reason)), JSON.stringify(e.evidence.peers));
});

test('freshness is judged again when the read ends: a snapshot that aged past the bound during a long read is refused', async () => {
  // the block is 400 ms short of the 1 s bound when the read starts; the read takes 600 ms
  const start = Date.now(), now = () => tsOf(98) * 1000 + 1000 - 400 + (Date.now() - start);
  const e = await refusal(run([['h1', rpc({ readDelay: 600 })], ['h2', rpc({ readDelay: 600 })]], { maxBlockAgeMs: 1000, now }));
  assert.ok(e instanceof QuorumError);
  assert.ok(e.evidence.peers.every((p) => /became older than 1000 ms during the read/.test(p.reason)), JSON.stringify(e.evidence.peers));
  // the same reads finishing inside the bound are accepted
  const start2 = Date.now(), now2 = () => tsOf(98) * 1000 + 1000 - 900 + (Date.now() - start2);
  assert.equal((await run([['h1', rpc({ readDelay: 300 })], ['h2', rpc({ readDelay: 300 })]], { maxBlockAgeMs: 1000, now: now2 })).value, 'truth@98');
});

test('another chain is excluded, early or late; it never reads and never counts', async () => {
  const wrongLate = rpc({ chain: 1, headDelay: 600 }), wrongFast = rpc({ chain: 1 });
  const r = await run([['wrong-fast', wrongFast], ['h1', rpc()], ['wrong-late', wrongLate], ['h2', rpc({ headDelay: 500 })]]);
  assert.equal(r.value, 'truth@98');
  for (const l of ['wrong-fast', 'wrong-late']) { assert.equal(peerOf(r, l).status, 'failed'); assert.match(peerOf(r, l).reason, /reports chain 1, not 31337/); }
  // one honest RPC beside wrong chains: fewer than two heads, refused with evidence
  const e = await refusal(run([['wrong-fast', rpc({ chain: 1 })], ['h1', rpc()], ['wrong-late', rpc({ chain: 1, headDelay: 300 })]]));
  assert.ok(e instanceof QuorumError);
  assert.match(e.message, /fewer than two RPCs on chain 31337 reported a head/);
  assert.deepEqual(e.evidence.peers.map((p) => p.status), ['failed', 'head', 'failed'], 'a head with no block chosen is not "late"');
  assert.equal(e.evidence.block, null);
});

test('no quorum is evidence, never a weaker threshold: a split, a lone answer, and an honest RPC past the deadline', async () => {
  let e = await refusal(run([['a', rpc()], ['b', rpc({ value: 'other' })]]));
  assert.match(e.message, /no two RPCs returned the same snapshot/);
  assert.deepEqual(e.evidence.peers.map((p) => p.status), ['disagreed', 'disagreed']);
  e = await refusal(run([['a', rpc()], ['b', rpc({ value: 'other' })], ['c', rpc({ value: 'third' })]]));
  assert.deepEqual(e.evidence.peers.map((p) => p.status), ['disagreed', 'disagreed', 'disagreed'], 'three different answers: no pair');
  // one honest answer while the other honest RPC's head never arrives in time: the deadline refuses, nothing is accepted alone
  const t0 = Date.now();
  e = await refusal(run([['h1', rpc()], ['liar', rpc({ value: 'lie' })], ['too-slow', rpc({ headDelay: 3000 })]], { requestTimeoutMs: 1000, deadlineMs: 1500 }));
  assert.ok(e instanceof QuorumError);
  assert.ok(Date.now() - t0 < 2200, `bounded by the request timeout and the deadline (${Date.now() - t0} ms)`);
  assert.equal(e.evidence.peers.find((p) => p.label === 'too-slow').status, 'failed');
  assert.match(e.evidence.peers.find((p) => p.label === 'too-slow').reason, /timed out after 1000 ms/);
});

test('the deadline bounds the whole read: once decided, no further request is started', async () => {
  const calls = { n: 0 };
  // each read makes up to 40 sequential 100 ms requests; the deadline is 700 ms
  const slowRead = async (client, b, call) => { for (let i = 0; i < 40; i++) await call(`page ${i}`, () => client.value(b)); return 'x'; };
  const t0 = Date.now();
  const e = await agreedRead({ peers: [{ label: 'a', client: rpc({ readDelay: 100, calls }) }, { label: 'b', client: rpc({ readDelay: 100, calls }) }],
    chainId: 31337, read: slowRead, requestTimeoutMs: 500, deadlineMs: 700 }).then(() => null, (x) => x);
  // either the deadline timer or the deadline-capped requests end it first; both are the same refusal
  assert.ok(e instanceof QuorumError); assert.match(e.message, /no two RPCs (agreed within 700 ms|returned the same snapshot at block 98)/);
  assert.ok(e.evidence.peers.every((p) => p.status === 'pending' || /timed out|deadline has passed/.test(p.reason)), JSON.stringify(e.evidence.peers));
  assert.ok(Date.now() - t0 < 900);
  const atDecision = calls.n;
  await sleep(400);
  assert.ok(calls.n <= atDecision + 2, `at most the in-flight requests complete; ${calls.n - atDecision} started after the decision`);
  // each request gets at most the time left: a request that would outlive the deadline is cut at the deadline
  const t1 = Date.now();
  const e2 = await agreedRead({ peers: [{ label: 'a', client: rpc({ readDelay: 5000 }) }, { label: 'b', client: rpc({ readDelay: 5000 }) }],
    chainId: 31337, read, requestTimeoutMs: 5000, deadlineMs: 5000, headGraceMs: 0 }).then(() => null, (x) => x);
  assert.ok(e2 instanceof QuorumError);
  assert.ok(Date.now() - t1 < 5600, `no request outlives the deadline (${Date.now() - t1} ms)`);
});

test('after an early quorum a slow third reader starts no more requests; in-flight requests end by the deadline, not later', async () => {
  // two fast honest RPCs decide at once; the third pages slowly (40 sequential 100 ms requests)
  const slow = { n: 0 }, pagedRead = async (client, b, call) => {
    if (client === slowClient) { for (let i = 0; i < 40; i++) await call(`page ${i}`, () => client.value(b)); return 'x'; }
    return call('value', () => client.value(b));
  };
  const slowClient = rpc({ readDelay: 100, calls: slow });
  const r = await agreedRead({ peers: [{ label: 'a', client: rpc() }, { label: 'b', client: rpc() }, { label: 'slow', client: slowClient }],
    chainId: 31337, read: pagedRead, requestTimeoutMs: 2000, deadlineMs: 4000, headGraceMs: 0 });
  assert.equal(r.value, 'truth@98');
  const atDecision = slow.n;
  await sleep(500);
  assert.ok(slow.n <= atDecision + 1, `the slow reader started ${slow.n - atDecision} requests after the decision`);
  // a request in flight when the deadline passes is cut AT the deadline (the time left), not after its own longer timeout
  const t0 = Date.now(); let settled = null;
  const recordingRead = async (client, b, call) => { try { return await call('value', () => client.value(b)); } finally { settled ??= Date.now() - t0; } };
  const e = await agreedRead({ peers: [{ label: 'a', client: rpc({ headDelay: 400, readDelay: 5000 }) }, { label: 'b', client: rpc({ headDelay: 400, readDelay: 5000 }) }],
    chainId: 31337, read: recordingRead, requestTimeoutMs: 1000, deadlineMs: 1000, headGraceMs: 0 }).then(() => null, (x) => x);
  assert.ok(e instanceof QuorumError);
  await sleep(700);
  assert.ok(settled !== null && settled < 1150, `the in-flight read settled ${settled} ms after the start (deadline 1000 ms)`);
});

test('agreedRead validates its peers itself: distinct labels, client objects and transport identities; usable clients', async () => {
  const shared = rpc();
  await assert.rejects(agreedRead({ peers: [{ label: 'a', client: shared }, { label: 'b', client: shared }], chainId: 31337, read }), /one client cannot vote twice/);
  await assert.rejects(agreedRead({ peers: [{ label: 'a', client: rpc() }, { label: 'a', client: rpc() }], chainId: 31337, read }), /labels must be distinct/);
  await assert.rejects(agreedRead({ peers: [{ label: 'a', client: rpc() }], chainId: 31337, read }), /two or more/);
  for (const [bad, re] of [[{ label: 'b' }, /no usable client/], [{ label: 'b', client: { getChainId() {} } }, /no usable client/], [null, /not a \{label, client\} entry/],
                           [{ label: '', client: rpc() }, /non-empty string/], [{ label: 7, client: rpc() }, /non-empty string/]])
    await assert.rejects(agreedRead({ peers: [{ label: 'a', client: rpc() }, bad], chainId: 31337, read }), re);
  await assert.rejects(agreedRead({ peers: [{ label: 'a', client: rpc() }, { label: 'b', client: rpc() }], chainId: 31337 }), /read\(client, blockNumber, call\) required/);
  // one public host is one vote however it is addressed; local test chains are distinct by loopback port
  for (const [u1, u2] of [['https://rpc.example.org/key1', 'https://rpc.example.org/key2'], ['https://rpc.example.org', 'https://RPC.example.org.:8443/?k=1'],
                          ['http://127.0.0.1:8545', 'http://localhost:8545/'], ['http://[::1]:8545', 'http://127.0.0.1:8545']])
    await assert.rejects(agreedRead({ peers: [{ label: 'a', client: rpc({ url: u1 }) }, { label: 'b', client: rpc({ url: u2 }) }], chainId: 31337, read }), /one endpoint cannot vote twice/, `${u1} ${u2}`);
  assert.equal(rpcIdentity('https://Rpc.Example.org.:8443/path?key=secret'), 'host:rpc.example.org');
  assert.equal(rpcIdentity('http://localhost:8546'), 'loopback:8546');
  const r = await run([['a', rpc({ url: 'http://127.0.0.1:8545' })], ['b', rpc({ url: 'http://127.0.0.1:8546' })], ['c', rpc({ url: 'https://rpc.example.net/x' })]]);
  assert.equal(r.value, 'truth@98', 'distinct loopback ports and a distinct public host are three votes');
  // a client without a visible transport URL is known by its object identity only (documented)
  assert.equal(peerList({ clients: [rpc(), rpc()] }).length, 2);
});

test('block headers are checked: the requested number, a 32-byte hash, whole-second timestamp, and unchanged at the recheck', async () => {
  for (const [name, header, re] of [
    ['wrong number', (h) => ({ ...h, number: h.number + 1n }), /block header is for block 99, not the requested 98/],
    ['missing number', ({ number, ...h }) => h, /no valid number/],
    ['string number', (h) => ({ ...h, number: '98' }), /no valid number/],
    ['short hash', (h) => ({ ...h, hash: h.hash.slice(0, 40) }), /not 32 bytes of hex/],
    ['non-hex hash', (h) => ({ ...h, hash: '0x' + 'zz'.repeat(32) }), /not 32 bytes of hex/],
    ['missing hash', ({ hash, ...h }) => h, /not 32 bytes of hex/],
    ['negative timestamp', (h) => ({ ...h, timestamp: -1n }), /not a valid number of seconds/],
    ['fractional timestamp', (h) => ({ ...h, timestamp: 1.5 }), /not a valid number of seconds/],
    ['missing timestamp', ({ timestamp, ...h }) => h, /not a valid number of seconds/],
    ['bad parent', (h) => ({ ...h, parentHash: '0x12' }), /parent hash is not 32 bytes/],
    ['not an object', () => null, /no block header/],
    ['timestamp changed at recheck', (h, nth) => (nth === 2 ? { ...h, timestamp: h.timestamp + 1n } : h), /the block header changed/],
    ['parent changed at recheck', (h, nth) => (nth === 2 ? { ...h, parentHash: '0x' + 'ab'.repeat(32) } : h), /the block header changed/],
    ['number changed at recheck', (h, nth) => (nth === 2 ? { ...h, number: h.number - 1n } : h), /not the requested 98/],
  ]) {
    // two RPCs serving the same malformed header never agree on it
    const e = await refusal(run([['m1', rpc({ header })], ['m2', rpc({ header })]]));
    assert.ok(e instanceof QuorumError, name);
    assert.ok(e.evidence.peers.every((p) => p.status === 'failed' && re.test(p.reason)), `${name}: ${JSON.stringify(e.evidence.peers)}`);
    // beside two honest RPCs it changes nothing
    const r = await run([['m', rpc({ header })], ['h1', rpc()], ['h2', rpc()]]);
    assert.equal(r.value, 'truth@98', name);
    assert.ok(['failed', 'pending'].includes(peerOf(r, 'm').status), name);
  }
  // an uppercase-hex hash is the same hash: normalized, and agrees with lowercase
  const r = await run([['up', rpc({ header: (h) => ({ ...h, hash: h.hash.toUpperCase().replace('0X', '0x') }) })], ['low', rpc()]]);
  assert.equal(r.blockHash, '0x' + '0'.repeat(62) + '62');
});

test('one RPC never counts twice: not within a round, and not across rounds', async () => {
  // round 1 (block 48, from the liar's low head) is stale for everyone; round 2 (98) has one honest answer and one lie:
  // the honest RPC answered in both rounds, yet it is still one vote, so nothing is accepted
  const failing = rpc({ headDelay: 300, header: () => null });
  const e = await refusal(run([['honest', rpc()], ['low-liar', rpc({ head: 50n, value: 'lie' })], ['broken', failing]]));
  assert.ok(e instanceof QuorumError);
  assert.deepEqual(e.evidence.rounds, ['48', '98']);
  assert.deepEqual(e.evidence.peers.map((p) => [p.label, p.status]), [['honest', 'disagreed'], ['low-liar', 'disagreed'], ['broken', 'failed']]);
  // the same RPC object listed twice is refused before any request
  const twice = rpc();
  await assert.rejects(run([['a', twice], ['b', twice]]), /one client cannot vote twice/);
  assert.equal(twice.calls.n, 0);
});

