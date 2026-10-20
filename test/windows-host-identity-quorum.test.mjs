// host-identity.mjs quorumReader under timing an attacker controls: a liar that answers first must not shut out an honest
// RPC that answers later, a stale fast head must not pin an old block, and a block must still be fresh when the whole
// snapshot has been read. No early cut-off, and it still fails closed: a single RPC never decides, and no two fresh
// agreeing answers (by the deadline) is a refusal.
// This file imports only host-identity.mjs, so it can be run against an isolated, mutated copy of that module
// (QUORUM_MODULE=<file>), to check that each test fails when the property it tests is removed.
//   run: node --test --test-concurrency=1 test/windows-host-identity-quorum.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const mod = await import(pathToFileURL(process.env.QUORUM_MODULE || path.join(ROOT, "windows", "node", "host-identity.mjs")).href);
const { quorumReader } = mod;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * A fake RPC: `value` is what its snapshot read returns. headMs / readMs delay its head and its read; hang never answers;
 * lagS ages its blocks; head is its chain head. clock() is the time its block stamps are relative to.
 */
const T0 = Math.floor(Date.now() / 1000) * 1000;
let rpcSeq = 0;
/**
 * More of what an adversarial or slow RPC can do:
 *   * perBlock: its value names the block it read (honest peers then agree only at one block);
 *   * readMs: a number, or a function of the block;
 *   * blockMs: delays getBlock;
 *   * fixedHash: the same block hash for every block (a forger's);
 *   * wrongNumber: the block it returns is numbered one below the one asked for;
 *   * hash: a malformed hash;
 *   * chain: {head}, a head shared and changeable by the test.
 * `calls` records [block, signal] for each snapshot read.
 */
function rpc(value, { head = 1000n, headMs = 0, readMs = 0, blockMs = 0, hang = false, dead = false, lagS = 0, chainId = 8453, clock = () => T0,
                      perBlock = false, fixedHash, wrongNumber = false, hash, chain } = {}) {
  const reads = [], calls = [];
  const tip = () => (chain ? chain.head : head);
  // a block's time belongs to the chain: the same for every RPC that serves it, and on every read (lagS ages one RPC's view)
  const stamp = () => BigInt(Math.floor(clock() / 1000) - lagS);
  return { reads, calls, transport: { url: `https://rpc-${++rpcSeq}.test/` },   // each fake is its own RPC host
    getChainId: async () => { if (hang) await new Promise(() => {}); await sleep(headMs); if (dead) throw new Error("connection refused"); return chainId; },
    getBlockNumber: async () => tip(),
    getBlock: async ({ blockNumber }) => {
      await sleep(blockMs);
      if (blockNumber > tip()) throw new Error("block not found");
      return { number: wrongNumber ? blockNumber - 1n : blockNumber, hash: hash ?? fixedHash ?? "0x" + blockNumber.toString(16).padStart(64, "0"), timestamp: stamp(blockNumber) };
    },
    snapshot: async (blockNumber, signal) => {
      reads.push(blockNumber); calls.push([blockNumber, signal]);
      await sleep(typeof readMs === "function" ? readMs(blockNumber) : readMs);
      const v = perBlock ? `${value}@${blockNumber}` : value;
      return { owner: v, operator: v, code: v };
    } };
}
const snapshot = (c, b, signal) => c.snapshot(b, signal);
const timed = async (p) => { const t0 = Date.now(); try { return { v: await p, ms: Date.now() - t0 }; } catch (e) { return { e: e.message, ms: Date.now() - t0 }; } };

test("a fast liar and a fast honest RPC cannot shut out a second honest RPC that answers 500 ms later", async () => {
  const r = await timed(quorumReader({ clients: [rpc("lie"), rpc("honest"), rpc("honest", { headMs: 500 })] }).agreed(snapshot));
  assert.deepEqual(r.v, { owner: "honest", operator: "honest", code: "honest" }, r.e);
  assert.ok(r.ms >= 450 && r.ms < 3000, `${r.ms} ms`);
  // and in any order, including the liar arriving last, or the honest pair arriving 1 s apart
  for (const order of [[rpc("honest", { headMs: 600 }), rpc("lie"), rpc("honest")], [rpc("honest"), rpc("honest", { headMs: 1000 }), rpc("lie", { headMs: 50 })]])
    assert.equal((await quorumReader({ clients: order }).agreed(snapshot)).owner, "honest");
});

test("a liar whose snapshot read is fastest cannot make the reader give up on slower honest reads", async () => {
  const r = await timed(quorumReader({ clients: [rpc("lie"), rpc("honest", { readMs: 300 }), rpc("honest", { headMs: 500, readMs: 200 })] }).agreed(snapshot));
  assert.equal(r.v?.owner, "honest", r.e);
});

test("a fast, stale head cannot pin the block: when the late honest head raises the second-highest, everyone is read again", async () => {
  const liar = rpc("lie", { head: 40n, lagS: 3600 }), h1 = rpc("honest"), h2 = rpc("honest", { headMs: 500 });
  const r = await timed(quorumReader({ clients: [liar, h1, h2] }).agreed(snapshot));
  assert.equal(r.v?.owner, "honest", r.e);
  assert.ok(h1.reads.includes(998n) && h2.reads.includes(998n), `reads ${h1.reads} / ${h2.reads}`);
  // and a far-future head never chooses it
  const g1 = rpc("honest"), g2 = rpc("honest", { headMs: 300 });
  assert.equal((await quorumReader({ clients: [rpc("lie", { head: 10n ** 12n }), g1, g2] }).agreed(snapshot)).owner, "honest");
  assert.ok([...g1.reads, ...g2.reads].every((b) => b === 998n), `reads ${[...g1.reads, ...g2.reads]}`);
});

test("freshness is checked after the whole snapshot is read, not only before it starts", async () => {
  let skew = 0;
  const clock = () => Date.now() + skew;
  // the snapshot takes "two minutes" (the clock jumps while it is read): blocks fresh at the start are stale at the end
  const slow = (v) => { const c = rpc(v); const s = c.snapshot; c.snapshot = async (b) => { const x = await s(b); skew = 120_000; return x; }; return c; };
  const r = await timed(quorumReader({ clients: [slow("honest"), slow("honest")], now: clock, deadlineMs: 2000 }).agreed(snapshot));
  assert.match(r.e || "", /went stale during the read|no longer fresh/, JSON.stringify(r));
});

test("it still fails closed: no two fresh agreeing RPCs is a refusal, and one that never answers cannot hold it past the deadline", async () => {
  const refuse = async (clients, re, opts = {}) => {
    const r = await timed(quorumReader({ clients, ...opts }).agreed(snapshot));
    assert.ok(r.e, `decided ${JSON.stringify(r.v)}`); assert.match(r.e, re); return r;
  };
  await refuse([rpc("lie"), rpc("honest")], /no fresh agreeing chain quorum.*disagree/);
  await refuse([rpc("lie"), rpc("honest"), rpc("honest", { dead: true })], /no fresh agreeing chain quorum/);
  await refuse([rpc("honest"), rpc("honest", { dead: true }), rpc("honest", { chainId: 1 })], /quorum unavailable: 1 of 3/);
  await refuse([rpc("a"), rpc("b"), rpc("c")], /no fresh agreeing chain quorum/);
  await refuse([rpc("honest", { lagS: 3600 }), rpc("honest", { lagS: 3600 })], /stale chain block/);
  const hung = await refuse([rpc("lie"), rpc("honest"), rpc("honest", { hang: true })], /within 0\.4 s/, { deadlineMs: 400 });
  assert.ok(hung.ms >= 350 && hung.ms < 1500, `${hung.ms} ms`);
  // an honest answer after the deadline is too late: refused, not waited for
  const late = await refuse([rpc("lie"), rpc("honest"), rpc("honest", { headMs: 800 })], /within 0\.4 s/, { deadlineMs: 400 });
  assert.ok(late.ms < 800, `${late.ms} ms`);
  // a hung RPC does not delay two honest ones that agree
  const quick = await timed(quorumReader({ clients: [rpc("honest", { hang: true }), rpc("honest"), rpc("honest")], deadlineMs: 5000 }).agreed(snapshot));
  assert.equal(quick.v?.owner, "honest"); assert.ok(quick.ms < 500, `${quick.ms} ms`);
  assert.throws(() => quorumReader({ clients: [rpc("honest")] }), /at least two RPCs/);
});

test("the whole snapshot must agree: owner, operator and code each, and the block hash", async () => {
  const part = (field) => { const c = rpc("honest"); const s = c.snapshot; c.snapshot = async (b) => ({ ...(await s(b)), [field]: "other" }); return c; };
  for (const f of ["owner", "operator", "code"])
    await assert.rejects(quorumReader({ clients: [rpc("honest"), part(f)] }).agreed(snapshot), /no fresh agreeing chain quorum/, f);
  const fork = rpc("honest"); const gb = fork.getBlock; fork.getBlock = async (q) => ({ ...(await gb(q)), hash: "0x" + "f".repeat(64) });
  await assert.rejects(quorumReader({ clients: [rpc("honest"), fork] }).agreed(snapshot), /no fresh agreeing chain quorum/, "the same value on another block hash");
});

// ---- authorization: one RPC never decides, however it times or repeats its answers ---------------------------------------
test("a fast liar repeating one forged block hash and value in two rounds never counts as two votes", async () => {
  const FORGED = "0x" + "f0".repeat(32);
  // heads 1000 (liar) and 1001 put the target at 998; the late honest head 1001 makes the second-highest 1001, so the target
  // rises to 999 and every peer, the liar too, is read in a second round
  const scene = (h2value) => [rpc("forged", { fixedHash: FORGED }), rpc("h1", { perBlock: true, head: 1001n }), rpc(h2value, { perBlock: true, head: 1001n, headMs: 300 })];
  const liarScene = scene("h2");
  const r = await timed(quorumReader({ clients: liarScene, deadlineMs: 3000 }).agreed(snapshot));
  assert.ok(r.e, `decided ${JSON.stringify(r.v)}: the liar's two answers met each other`);
  assert.deepEqual(liarScene[0].reads.map(String), ["998", "999"], "the liar really was read in two rounds");
  assert.match(r.e, /no fresh agreeing chain quorum/);
  // when the honest two agree, they decide, never the liar
  assert.equal((await quorumReader({ clients: scene("h1"), deadlineMs: 3000 }).agreed(snapshot)).owner, "h1@999");
  // a liar answering fast in many rounds (heads keep raising the target) still never meets itself
  const many = [rpc("forged", { fixedHash: FORGED, head: 2000n }), rpc("a", { perBlock: true, head: 1000n }),
                rpc("b", { perBlock: true, head: 1100n, headMs: 100 }), rpc("c", { perBlock: true, head: 1200n, headMs: 200 })];
  await assert.rejects(quorumReader({ clients: many, deadlineMs: 3000 }).agreed(snapshot), /no fresh agreeing chain quorum/);
});

test("each configured peer counts once: the same client, or one RPC host, twice is refused", async () => {
  const liar = rpc("forged");
  assert.throws(() => quorumReader({ clients: [liar, liar] }), /configured twice/);
  assert.throws(() => quorumReader({ clients: [liar, rpc("h"), liar] }), /configured twice/);
  const at = (url) => Object.assign(rpc("h"), { transport: { url } });
  assert.throws(() => quorumReader({ clients: [at("https://rpc.example/a"), at("https://rpc.example/b")] }), /one host/);
  assert.ok(quorumReader({ clients: [at("https://rpc-a.example/"), at("https://rpc-b.example/")] }));
});

test("the block a peer returns is validated: its number must be the one asked for, its hash 32-byte hex", async () => {
  await assert.rejects(quorumReader({ clients: [rpc("h", { wrongNumber: true }), rpc("h", { wrongNumber: true })] }).agreed(snapshot), /asked for block 998, got block 997/);
  for (const hash of ["0xabc", "f".repeat(64), "0x" + "g".repeat(64), 7])
    await assert.rejects(quorumReader({ clients: [rpc("h", { hash }), rpc("h", { hash })] }).agreed(snapshot), /malformed chain block/, String(hash));
});

test("a superseded round's result never decides, and its reads stop before their next request", async () => {
  // round 1 (block 998) reads are slow; the late head moves the target to 999; round 1 agreeing later must not count
  const h1 = rpc("v", { perBlock: true, head: 1001n, readMs: 400 }), h2 = rpc("v", { perBlock: true, readMs: 400 }), h3 = rpc("v", { perBlock: true, head: 1001n, headMs: 100, readMs: 400 });
  const r = await timed(quorumReader({ clients: [h1, h2, h3] }).agreed(snapshot));
  assert.equal(r.v?.owner, "v@999", r.e);
  assert.ok(h1.calls.filter(([b]) => b === 998n).every(([, sig]) => sig.aborted), "round 1's signal is aborted once it is superseded");
  // with a slow getBlock, a round-1 read reaches its next step only after round 2 started: it never calls fn at 998
  const g1 = rpc("v", { perBlock: true, head: 1001n, blockMs: 300 }), g2 = rpc("v", { perBlock: true, blockMs: 300 }), g3 = rpc("v", { perBlock: true, head: 1001n, headMs: 100, blockMs: 300 });
  assert.equal((await quorumReader({ clients: [g1, g2, g3] }).agreed(snapshot)).owner, "v@999");
  assert.deepEqual([...g1.reads, ...g2.reads, ...g3.reads].map(String).sort(), ["999", "999", "999"], "no snapshot read for the superseded block");
});

test("after the deadline (or a decision) nothing starts another request", async () => {
  const s1 = rpc("v", { blockMs: 500 }), s2 = rpc("v", { blockMs: 500 });
  const r = await timed(quorumReader({ clients: [s1, s2], deadlineMs: 200 }).agreed(snapshot));
  assert.match(r.e || "", /within 0\.2 s/);
  await sleep(800);
  assert.deepEqual([...s1.reads, ...s2.reads], [], "no fn after the deadline, though getBlock answered later");
  // decided: a third, slower peer's in-flight read does not go on to fn
  const d3 = rpc("v", { blockMs: 300 });
  assert.equal((await quorumReader({ clients: [rpc("v"), rpc("v"), d3] }).agreed(snapshot)).owner, "v");
  await sleep(500);
  assert.deepEqual(d3.reads, []);
});

test("overlapping calls cannot roll an accepted block back: the high-water mark is checked at the decision", async () => {
  const chain = { head: 1000n };
  const slowAt998 = (b) => (b === 998n ? 400 : 0);
  const q = quorumReader({ clients: [rpc("v", { perBlock: true, chain, readMs: slowAt998 }), rpc("v", { perBlock: true, chain, readMs: slowAt998 })] });
  const older = q.agreed(snapshot);   // targets 998, slowly
  await sleep(50);
  chain.head = 1100n;
  assert.equal((await q.agreed(snapshot)).owner, "v@1098", "the newer call decides first, at 1098");
  assert.equal((await older).owner, "v@1098", "the older call's 998 agreement is below the accepted 1098: read again at 1098, never answered at 998");
  // and once 1098 is accepted, a later call whose peers are behind it refuses rather than answer from older blocks
  chain.head = 1000n;
  await assert.rejects(q.agreed(snapshot), /no fresh agreeing chain quorum.*block not found/);
});

// ---- configuration: one public RPC host votes once however it is spelled; nothing malformed or unbounded is accepted ----
const peerAt = (url) => Object.assign(rpc("h"), { transport: { url } });
test("one public RPC host is one peer however it is spelled: case, trailing dots and ports do not make two", async () => {
  for (const [a, b] of [["https://rpc.example/", "https://rpc.example./"], ["https://RPC.Example/a", "https://rpc.example../b"],
                        ["https://rpc.example/", "https://Rpc.Example.:443/x"], ["https://rpc.example:443/", "https://rpc.example:8443/"],
                        ["https://203.0.113.7/", "https://203.0.113.7:8545/"]])
    assert.throws(() => quorumReader({ clients: [peerAt(a), peerAt(b)] }), /one host/, `${a} + ${b}`);
  assert.throws(() => quorumReader({ clients: [peerAt("https://rpc-a.example/"), peerAt("https://rpc-b.example/"), peerAt("https://RPC-A.example./v2")] }), /one host/);
  assert.ok(quorumReader({ clients: [peerAt("https://rpc-a.example/"), peerAt("https://rpc-b.example/")] }));
  // rpcClients, which the CLI uses, applies the same canonical host before it makes any client
  await assert.rejects(mod.rpcClients(["https://rpc.example", "https://rpc.example."]), /distinct hosts/);
  await assert.rejects(mod.rpcClients(["https://rpc.example/a", "https://RPC.EXAMPLE/b"]), /distinct hosts/);
  assert.equal((await mod.rpcClients(["https://rpc-a.example", "https://rpc-b.example."])).length, 2);
  assert.equal(mod.rpcPeerHost("https://RPC.Example../x"), "rpc.example");
});

test("a peer must name a well-formed RPC and have the methods the reader calls", () => {
  const without = (m) => { const c = rpc("h"); delete c[m]; return c; };
  for (const m of ["getChainId", "getBlockNumber", "getBlock"])
    assert.throws(() => quorumReader({ clients: [rpc("h"), without(m)] }), /needs getChainId, getBlockNumber, getBlock/, m);
  assert.throws(() => quorumReader({ clients: [rpc("h"), Object.assign(rpc("h"), { getBlock: "x" })] }), /needs/);
  assert.throws(() => quorumReader({ clients: [rpc("h"), null] }), /needs/);
  const noUrl = (t) => Object.assign(rpc("h"), { transport: t });
  for (const t of [undefined, {}, { url: 5 }, { url: null }, { type: "fallback", transports: [] }])
    assert.throws(() => quorumReader({ clients: [rpc("h"), noUrl(t)] }), /must name its RPC/, JSON.stringify(t));
  for (const url of ["", "not a url", "ftp://rpc.example/", "http://rpc.example/", "https://rpc..example/", "https://./", "ws://rpc.example/"])
    assert.throws(() => quorumReader({ clients: [rpc("h"), peerAt(url)] }), /not a URL|must be https|malformed host/, url);
});

test("configuration is bounded: peers, chain id, confirmations, block age, deadline", () => {
  const two = () => [rpc("h"), rpc("h")];
  assert.ok(quorumReader({ clients: Array.from({ length: mod.MAX_PEERS }, () => rpc("h")) }));
  assert.throws(() => quorumReader({ clients: Array.from({ length: mod.MAX_PEERS + 1 }, () => rpc("h")) }), /at most 16 RPCs/);
  assert.throws(() => quorumReader({ clients: "rpc" }), /at least two/);
  for (const chainId of [0, -1, 1.5, "8453", NaN, Infinity, 8453n]) assert.throws(() => quorumReader({ clients: two(), chainId }), /chainId/, String(chainId));
  for (const confirmations of [0, -1, 1.5, "2", NaN, Infinity, 1001, 2n]) assert.throws(() => quorumReader({ clients: two(), confirmations }), /confirmations/, String(confirmations));
  for (const maxBlockAgeMs of [0, -1, 999, 1.5, NaN, Infinity, 3_600_001, "90000"]) assert.throws(() => quorumReader({ clients: two(), maxBlockAgeMs }), /maxBlockAgeMs/, String(maxBlockAgeMs));
  for (const deadlineMs of [0, -1, 99, 1.5, NaN, Infinity, 600_001, "30000"]) assert.throws(() => quorumReader({ clients: two(), deadlineMs }), /deadlineMs/, String(deadlineMs));
  assert.throws(() => quorumReader({ clients: two(), now: 5 }), /now must be a function/);
  assert.ok(quorumReader({ clients: two(), chainId: 1, confirmations: 1, maxBlockAgeMs: 1000, deadlineMs: 100 }));
});

test("local fixtures: several loopback RPCs only through the explicit seam, and never two votes for one public host", async () => {
  const local = (port) => peerAt(`http://127.0.0.1:${port}/`);
  assert.throws(() => quorumReader({ clients: [local(8545), local(8546)] }), /one host/, "by default loopback ports are one host");
  assert.ok(quorumReader({ clients: [local(8545), local(8546)], localFixture: true }));
  assert.throws(() => quorumReader({ clients: [local(8545), local(8545)], localFixture: true }), /one host/);
  assert.throws(() => quorumReader({ clients: [peerAt("https://rpc.example:443/"), peerAt("https://rpc.example:8443/")], localFixture: true }), /one host/,
                "the seam keeps ports for loopback only");
  assert.throws(() => quorumReader({ clients: [local(8545), local(8546)], localFixture: "yes" }), /localFixture a boolean/);
  // the seam is not reachable from the CLI's client list
  await assert.rejects(mod.rpcClients(["http://127.0.0.1:8545", "http://127.0.0.1:8546"]), /distinct hosts/);
});
