// windows/node/audit-jobs.mjs: a Windows host accepts the paid capacity-audit jobs created for it (offerJobRate, signed by
// its operator key on the box) through availability/host-acceptor.mjs, sent by the node's serialized sender; off unless
// the operator lists the audit workloads.
import test from "node:test";
import assert from "node:assert/strict";
import { createAuditJobs, auditAppRefsOf } from "../windows/node/audit-jobs.mjs";

const HOST = "0x" + "a1".repeat(32), OTHER = "0x" + "b2".repeat(32);
const APP = "catalog://0x962622b0284b438f58ad480b824d4fbf7fa9ce3dc84e2af97b65bd15392a5e6f/0";
const FEES = "0x" + "fe".repeat(20), LEDGER = "0x" + "dd".repeat(20);
const NOW = 1_900_000_000_000;
const id = (n) => "0x" + String(n).padStart(2, "0").repeat(32);
const WALLET = "0x14b37ee3c06b047bb3a3f7fe54d29a8e67091428", PAYER = "0x29479bf04ed889d46a7afb7f292b9bb26e12647c", SOURCE = "0x" + "0f".repeat(32);

function world({ jobs, rows, rateFor = {}, wallets = null, payers = {} }) {
  const reads = [], sent = [];
  const publicClient = {
    async readContract({ address, functionName, args }) {
      reads.push(`${functionName}:${String(args[0]).slice(0, 6)}`);
      if (functionName === "jobs") { const j = jobs[args[0]]; if (!j) throw new Error("no job"); return j; }
      if (functionName === "get") return { appRef: rows.find((r) => r.id === args[0]).appRef, cpuMilli: 19n };
      if (functionName === "rateFor") return rateFor[args[0]] ?? 0n;
      if (functionName === "isWallet") return (wallets || [WALLET]).map((w) => w.toLowerCase()).includes(String(args[0]).toLowerCase());
      if (functionName === "policies") return [payers[args[0]] ?? PAYER, "0x" + "e1".repeat(20), WALLET, 0n, 0n, 0, 0, 0n, 0n, 0n, 0n, APP, "hyperv-partition-per-app"];
      throw new Error("unexpected " + functionName + " at " + address);
    },
    async waitForTransactionReceipt() { return { status: "success" }; },
  };
  const send = async (address, abi, fn, args) => { sent.push({ address, fn, args }); return "0xhash" + sent.length; };
  const logs = [];
  return { publicClient, send, reads, sent, logs, log: (m) => logs.push(m) };
}
// (source, wallet, hostId, epoch, expires, rate6, amount6, funded, stopAfter)
const job = (host, { rate = 22n, expiresSec = BigInt(NOW / 1000 + 600), funded = false, wallet = WALLET, stopAfter = BigInt(NOW / 1000 + 900), source = SOURCE } = {}) =>
  [source, wallet, host, 1n, expiresSec, rate, 0n, funded, stopAfter];
const row = (n, extra = {}) => ({ id: id(n), active: true, appRef: APP, owner: WALLET, runner: "0x" + "00".repeat(32), leaseUntil: 0n, ...extra });

test("off unless the operator lists audit workloads: nothing is read or sent", async () => {
  const w = world({ jobs: { [id(1)]: job(HOST) }, rows: [row(1)] });
  const a = createAuditJobs({ appRefs: auditAppRefsOf(""), enclaveId: HOST, ledger: LEDGER, fees: FEES, publicClient: w.publicClient, send: w.send, now: () => NOW });
  assert.equal(a.enabled, false);
  const r0 = await a.pass([row(1)]); assert.equal(r0.pool.size + r0.admitted.size, 0);
  assert.deepEqual(w.reads, []); assert.deepEqual(w.sent, []);
  assert.deepEqual(auditAppRefsOf(` ${APP.toUpperCase()}, nonsense, catalog://0x12/1`), [APP], "only well-formed refs, lower-cased");
});

test("a job created for this host is accepted once, at its own rate and expiry, through the serialized sender", async () => {
  const rows = [row(1), row(2), row(3, { appRef: "catalog://0x" + "77".repeat(32) + "/0" })];
  const w = world({ jobs: { [id(1)]: job(HOST), [id(2)]: job(OTHER) }, rows });
  const a = createAuditJobs({ appRefs: [APP], enclaveId: HOST, ledger: LEDGER, fees: FEES, publicClient: w.publicClient, send: w.send, log: w.log, now: () => NOW });
  const { pool: mine } = await a.pass(rows);
  assert.deepEqual([...mine], [id(1)], "only this host's job joins the pool");
  assert.equal(w.sent.length, 1);
  assert.equal(w.sent[0].fn, "offerJobRate");
  assert.equal(w.sent[0].address, LEDGER);
  assert.deepEqual(w.sent[0].args, [id(1), HOST, 22n, BigInt(NOW / 1000 + 600)]);
  assert.ok(!w.reads.some((r) => r.endsWith(id(3).slice(0, 6))), "a workload not on the list is never read");
  const before = w.reads.length;
  await a.pass(rows);
  assert.equal(w.sent.length, 1, "accepted once");
  assert.equal(w.reads.filter((r) => r === `jobs:${id(2).slice(0, 6)}`).length, 1, "another host's job is read once, ever");
  assert.ok(w.reads.length - before <= 2, "the second pass reads only this host's job and its policy (isWallet is cached)");
});

test("an expired, funded or below-floor job is not accepted; a refusal is logged once", async () => {
  const rows = [row(1), row(2), row(3)];
  const w = world({ jobs: { [id(1)]: job(HOST, { expiresSec: BigInt(NOW / 1000 - 1) }), [id(2)]: job(HOST, { funded: true }), [id(3)]: job(HOST, { rate: 10n }) }, rows });
  const a = createAuditJobs({ appRefs: [APP], minRatePerShareMilli6: 1n, enclaveId: HOST, ledger: LEDGER, fees: FEES, publicClient: w.publicClient,
    send: w.send, log: w.log, now: () => NOW });
  const { pool: mine } = await a.pass(rows);
  assert.equal(mine.size, 3, "they are still this host's jobs");
  assert.deepEqual(w.sent, [], "nothing signed: expired, funded, and 10/s < 1 x 19 milli");
  await a.pass(rows);
  const floor = w.logs.filter((m) => /not accepted: acceptor: below this host's floor/.test(m));
  assert.equal(floor.length, 1, w.logs.join("\n"));
});

test("a row somebody else holds a live lease on is not a job waiting for this host", async () => {
  const rows = [row(1, { runner: OTHER, leaseUntil: BigInt(NOW / 1000 + 300) })];
  const w = world({ jobs: { [id(1)]: job(HOST) }, rows });
  const a = createAuditJobs({ appRefs: [APP], enclaveId: HOST, ledger: LEDGER, fees: FEES, publicClient: w.publicClient, send: w.send, now: () => NOW });
  assert.equal((await a.pass(rows)).pool.size, 0);
  assert.deepEqual(w.reads, []);
});

test("owner-only: a job is admitted only if a fee wallet owns it, it names this host, and a served owner's policy paid for it", async () => {
  const STRANGER = "0x" + "99".repeat(20);
  const rows = [row(1), row(2, { owner: "0x" + "ab".repeat(20) }), row(3), row(4), row(5)];
  const w = world({ rows, payers: { ["0x" + "03".repeat(32)]: STRANGER },
    jobs: { [id(1)]: job(HOST), [id(2)]: job(HOST, { wallet: "0x" + "ab".repeat(20) }), [id(3)]: job(HOST, { source: "0x" + "03".repeat(32) }),
            [id(4)]: job(HOST, { stopAfter: BigInt(NOW / 1000 - 1) }), [id(5)]: job(HOST, { wallet: "0x" + "cd".repeat(20) }) } });
  const a = createAuditJobs({ appRefs: [APP], enclaveId: HOST, ledger: LEDGER, fees: FEES, publicClient: w.publicClient, send: w.send, log: w.log,
    now: () => NOW, servedOwners: () => new Set([PAYER.toUpperCase().replace("0X", "0x")]), ownerOnly: () => true });
  const { pool, admitted } = await a.pass(rows);
  assert.equal(pool.size, 5, "all five were created for this host");
  assert.deepEqual([...admitted], [id(1)], "only the fee wallet's job paid by a served owner");
  assert.equal(w.sent.length, 1, "only the admitted job is accepted");
  assert.equal(w.sent[0].args[0], id(1));
  for (const why of ["is not a fee-contract wallet", "is not an owner this box serves", "past its stopAfter", "is not the job's fee wallet"])
    assert.ok(w.logs.some((m) => m.includes(why)), `said: ${why}\n` + w.logs.join("\n"));
});

test("market scope: an unadmitted job is still accepted (scope admits it), and admission is still reported", async () => {
  const rows = [row(1)];
  const w = world({ rows, jobs: { [id(1)]: job(HOST) }, payers: { [SOURCE]: "0x" + "99".repeat(20) } });
  const a = createAuditJobs({ appRefs: [APP], enclaveId: HOST, ledger: LEDGER, fees: FEES, publicClient: w.publicClient, send: w.send,
    now: () => NOW, servedOwners: () => new Set(), ownerOnly: () => false });
  const { admitted } = await a.pass(rows);
  assert.equal(admitted.size, 0);
  assert.equal(w.sent.length, 1);
});

test("a job owned by its own fee wallet is marked one-quantum (fee); a job owned by anyone else is not", async () => {
  const rows = [row(1), row(2, { owner: "0x" + "ab".repeat(20) })];
  const w = world({ rows, jobs: { [id(1)]: job(HOST), [id(2)]: job(HOST) } });
  const a = createAuditJobs({ appRefs: [APP], enclaveId: HOST, ledger: LEDGER, fees: FEES, publicClient: w.publicClient, send: w.send, now: () => NOW });
  const { pool, fee } = await a.pass(rows);
  assert.equal(pool.size, 2);
  assert.deepEqual([...fee], [id(1)]);
});
