// PAID CAPACITY AUDITS on a Windows host (docs/design/paid-capacity-verification.md). The audit coordinator creates a job
// deployment through EnclaveVerificationFees for ONE host at a negotiated rate, and that host accepts the rate with
// EnclaveDeployments.offerJobRate, signed by its registry OPERATOR. Here the operator key never leaves the box, so the
// node accepts by itself: a PULL in the ledger scan, finding the jobs created for it. The coordinator only waits for the
// acceptance on chain (rateFor) before it funds the job; the node then claims it like any other work.
//
// What is accepted is availability/host-acceptor.mjs's decision, unchanged: a fee-contract job for THIS enclave, unfunded
// and unexpired, running an approved audit workload, at the job's own rate and expiry and at or above the operator's
// floor. Its transaction goes out through the node's one serialized sender (chain.mjs send), never beside a claim or a
// renewal with its own nonce. OFF unless the operator lists the workloads (ENCLAVE_AUDIT_APPREFS).

const lc = (s) => String(s || "").toLowerCase();
const ZERO_RUNNER = /^0x0*$/;
const FEES_ABI = [
  { type: "function", name: "jobs", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ name: "source", type: "bytes32" },
    { name: "wallet", type: "address" }, { name: "hostId", type: "bytes32" }, { name: "epoch", type: "uint64" }, { name: "expires", type: "uint64" },
    { name: "rate6", type: "uint256" }, { name: "amount6", type: "uint256" }, { name: "funded", type: "bool" }, { name: "stopAfter", type: "uint64" }] },
  { type: "function", name: "policies", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ name: "payer", type: "address" },
    { name: "executor", type: "address" }, { name: "wallet", type: "address" }, { name: "expires", type: "uint64" }, { name: "epoch", type: "uint64" },
    { name: "revenueBps", type: "uint16" }, { name: "maxCpuMilli", type: "uint16" }, { name: "dailyCap6", type: "uint256" }, { name: "jobCap6", type: "uint256" },
    { name: "maxRate6", type: "uint256" }, { name: "available6", type: "uint256" }, { name: "appRef", type: "string" }, { name: "backend", type: "string" }] },
  { type: "function", name: "isWallet", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
];

/** ENCLAVE_AUDIT_APPREFS -> the catalog refs this host runs audits for (catalog://0x<64 hex>/<version>). */
export function auditAppRefsOf(raw) {
  return String(raw || "").split(",").map((x) => x.trim().toLowerCase()).filter((x) => /^catalog:\/\/0x[0-9a-f]{64}\/\d+$/.test(x));
}

/**
 * -> { enabled, pass(rows) -> { pool, admitted, fee } }, Sets of deployment ids:
 *   fee       the jobs whose ledger owner is the job's own fee wallet: one quantum by design (the coordinator stops each
 *             after its challenge, stopAfter bounds it), so the node never renews them;
 *   pool      the active jobs created for this host (accepted now or before): the scan includes them whatever its scope;
 *   admitted  those an OWNER-ONLY box serves although their ledger owner is a fee wallet with no key (it can never sign a
 *             delegation): the owner is a fee-contract wallet (isWallet), the job names that wallet and THIS enclave, the
 *             job's payer policy belongs to an owner this box already serves (servedOwners: its operator and delegated
 *             owners - only someone it serves can direct audits here), the workload is on the operator's list, and the job
 *             has not reached stopAfter (enclave-d4's rule, 2026-10-16). A market box admits by scope and does not need it.
 * A job is accepted (offerJobRate) only if it would be admitted, or the box is in market scope. Never throws: a failure is
 * logged once per job and reason. opts: appRefs, minRatePerShareMilli6 (bigint), enclaveId, ledger, fees (address or null),
 * publicClient, send(address, abi, fn, args) -> hash, servedOwners() -> Set, ownerOnly() -> bool, log, now; loadAcceptor (tests).
 */
export function createAuditJobs({ appRefs = [], minRatePerShareMilli6 = 0n, enclaveId, ledger, fees, publicClient, send, log = () => {},
                                  servedOwners = () => new Set(), ownerOnly = () => false,
                                  now = () => Date.now(), loadAcceptor = () => import("../../availability/host-acceptor.mjs") }) {
  const allowed = new Set(appRefs.map(lc));
  const enabled = allowed.size > 0 && !!fees && !!ledger;
  const notOurs = new Set();                 // a job's host never changes: a job for another host is read once
  const accepted = new Map();               // id -> rate accepted (string)
  const said = new Map();                   // id -> last logged failure (once per reason)
  const wallets = new Map();                // owner -> isWallet (a fee wallet stays one)
  const say = (id, m) => { if (said.get(id) !== m) { said.set(id, m); log(m); } };
  const read = (functionName, args) => publicClient.readContract({ address: fees, abi: FEES_ABI, functionName, args });
  let acceptor = null;
  async function accept(o) {
    if (!acceptor) {
      const { createHostAcceptor } = await loadAcceptor();
      acceptor = createHostAcceptor({ publicClient, ledger, fees, enclaveId, appRefs: [...allowed], minRatePerShareMilli6, log,
        // through the node's serialized sender: one transaction at a time from this key, with its nonce bookkeeping
        operatorWallet: { writeContract: ({ address, abi, functionName, args }) => send(address, abi, functionName, args) } });
    }
    return acceptor(o);
  }
  async function pass(rows) {
    const pool = new Set(), admitted = new Set(), fee = new Set();
    if (!enabled) return { pool, admitted, fee };
    const served = new Set([...servedOwners()].map(lc)), onlyOwners = ownerOnly();
    for (const d of rows) {
      const id = lc(d.id);
      if (!d.active || !allowed.has(lc(d.appRef)) || notOurs.has(id)) continue;
      // somebody else holds a live lease on it: not a job waiting for this host
      const live = Number(d.leaseUntil) * 1000 > now();
      if (live && !ZERO_RUNNER.test(String(d.runner || "")) && lc(d.runner) !== lc(enclaveId)) continue;
      let j;
      try { j = await read("jobs", [id]); }
      catch (e) { say(id, `audit job ${id.slice(0, 10)}: the fee contract could not be read (${e.shortMessage || e.message})`); continue; }
      if (/^0x0{40}$/i.test(String(j[1])) || lc(j[2]) !== lc(enclaveId)) { notOurs.add(id); continue; }
      pool.add(id);
      // a fee-contract job proper (its ledger owner is the job's own fee wallet): one quantum by design, never renewed
      if (lc(j[1]) === lc(d.owner)) fee.add(id);
      // the owner-only admission (see above): every input read from the chain
      let why = null;
      try {
        if (lc(j[1]) !== lc(d.owner)) why = "its ledger owner is not the job's fee wallet";
        else {
          if (!wallets.has(lc(d.owner))) wallets.set(lc(d.owner), !!(await read("isWallet", [d.owner])));
          if (!wallets.get(lc(d.owner))) why = "its owner is not a fee-contract wallet";
          else if (BigInt(j[8]) * 1000n <= BigInt(now())) why = "the job is past its stopAfter";
          else {
            const p = await read("policies", [j[0]]);
            if (!served.has(lc(p[0]))) why = `its payer ${p[0]} is not an owner this box serves`;
          }
        }
      } catch (e) { why = `the fee contract could not be read (${e.shortMessage || e.message})`; }
      if (!why) admitted.add(id);
      else if (onlyOwners) { say(id, `audit job ${id.slice(0, 10)} not served here: ${why}`); continue; }
      if (j[7] || accepted.get(id) === String(j[5])) continue;                    // funded, or already accepted at this rate
      if (BigInt(j[4]) * 1000n <= BigInt(now())) continue;                          // its offer expired: nothing to accept
      try {
        await accept({ id, hostId: enclaveId, rate6: j[5], expiresSec: j[4] });
        accepted.set(id, String(j[5])); said.delete(id);
      } catch (e) { say(id, `audit job ${id.slice(0, 10)} not accepted: ${e.shortMessage || e.message}`); }
    }
    return { pool, admitted, fee };
  }
  return { enabled, pass };
}
